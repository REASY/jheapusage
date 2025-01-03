use crate::errors;
use crate::errors::AppError;
use libc::pid_t;
use nix::fcntl::OFlag;
use nix::sched::{setns, CloneFlags};
use nix::sys::stat::Mode;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, pipe, read, write, ForkResult};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::{fs, io, process};
use tracing::{debug, error};

pub struct NamespaceIsolation {
    pid: pid_t,
}

impl NamespaceIsolation {
    pub fn new(pid: pid_t) -> Self {
        NamespaceIsolation { pid }
    }

    fn enter_namespaces(&self) -> errors::Result<()> {
        // The order is important!
        // https://github.com/util-linux/util-linux/blob/4e14b5731efcd703ad13e24362448c87cecb5424/sys-utils/nsenter.c#L63-L80
        let namespaces = ["user", "cgroup", "ipc", "uts", "net", "pid", "mnt", "time"];
        for ns in namespaces {
            if Self::can_enter_namespace(self.pid, ns) {
                self.enter_namespace(ns)?;
            }
        }
        Ok(())
    }

    fn enter_namespace(&self, ns: &str) -> errors::Result<()> {
        let ns_path = PathBuf::from(format!("/proc/{}/ns/{ns}", self.pid));
        let raw_fd = nix::fcntl::open(&ns_path, OFlag::O_RDONLY, Mode::empty())?;
        let fd = unsafe { BorrowedFd::borrow_raw(raw_fd) };
        setns(fd, CloneFlags::empty())?;
        Ok(())
    }

    pub fn execute<F, T: Debug + Serialize + DeserializeOwned>(&self, func: F) -> errors::Result<T>
    where
        F: Fn() -> T,
    {
        // Use pipe for IPC between parent and child processes.
        // More https://pubs.opengroup.org/onlinepubs/9799919799/functions/pipe.html
        let (reader, writer) = pipe()?;
        let f = unsafe { fork() };
        match f {
            Ok(ForkResult::Parent { child }) => {
                // Immediate close write end of the pipe in parent process, parent will only read.
                nix::unistd::close(writer.as_raw_fd())?;
                debug!(
                    "Parent process PID: {}, spawned child PID: {}",
                    process::id(),
                    child
                );
                let wait_status = waitpid(child, None)?;
                debug!("wait_status: {:?}", wait_status);

                match wait_status {
                    WaitStatus::Exited(_, exit_code) => {
                        if exit_code != 0 {
                            error!("Spawned child process {} didn't complete successfully, exit code: {}", child, exit_code);
                            panic!("Spawned child process {} didn't complete successfully, exit code: {}", child, exit_code);
                        }
                    }
                    x => panic!("do not know what to do with {:?}", x),
                }

                let buffer = Self::read_all(&reader)?;
                let data: T = serde_json::from_slice(&buffer)?;
                debug!("data: {:?}", data);

                Ok(data)
            }
            Ok(ForkResult::Child) => {
                // Immediate close read end of the pipe in child process, child will only write.
                nix::unistd::close(reader.as_raw_fd())?;
                match self.run_inside_namespace(func, writer) {
                    Ok(_) => {
                        process::exit(0);
                    }
                    Err(err) => {
                        error!("Failed to run: {}", err);
                        Err(err)
                    }
                }
            }
            Err(err) => {
                error!("Fork failed: {}", err);
                Err(AppError::from(err))
            }
        }
    }

    fn read_all(fd: &OwnedFd) -> errors::Result<Vec<u8>> {
        let mut buffer = Vec::new();
        let mut temp = [0u8; 4096];
        loop {
            let bytes_read = read(fd.as_raw_fd(), &mut temp)?;
            // Is EOF?
            if bytes_read == 0 {
                break;
            }
            buffer.extend_from_slice(&temp[..bytes_read]);
        }
        Ok(buffer)
    }

    fn run_inside_namespace<F, T: Debug + Serialize + DeserializeOwned>(
        &self,
        func: F,
        writer: OwnedFd,
    ) -> errors::Result<()>
    where
        F: Fn() -> T,
    {
        self.enter_namespaces()?;
        let r = func();
        let serialized = serde_json::to_vec(&r)?;
        write(writer, &serialized)?;
        Ok(())
    }

    fn get_inode(path: &PathBuf) -> io::Result<u64> {
        let metadata = fs::metadata(path)?;
        Ok(metadata.ino())
    }

    fn can_enter_namespace(target_pid: pid_t, ns: &str) -> bool {
        // Namespace check is inspired by https://github.com/util-linux/util-linux/blob/4e14b5731efcd703ad13e24362448c87cecb5424/sys-utils/nsenter.c#L368
        let my_ns_path = PathBuf::from(format!("/proc/{}/ns/{ns}", process::id()));
        let my_inode = match Self::get_inode(&my_ns_path) {
            Ok(ino) => ino,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return false, // Unsupported NS
            Err(_) => panic!("Failed to get inode for {:?}", my_ns_path),
        };
        // It is not permitted to use setns to reenter the caller's
        // current user namespace; see setns man page for more details.
        if ns == "user" {
            let target_ns_path = PathBuf::from(format!("/proc/{}/ns/{ns}", target_pid));
            let target_inode = match Self::get_inode(&target_ns_path) {
                Ok(ino) => ino,
                Err(_) => panic!("Failed to stat {:?}", target_ns_path),
            };

            if my_inode == target_inode {
                return false;
            }
        }
        true
    }
}
