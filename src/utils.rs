use crate::errors::ErrorKind::FuncNotFoundError;
use crate::errors::{AppError, ErrorKind, Result};
use chrono::{DateTime, Utc};
use libc::{pid_t, timespec, uid_t};
use nix::sys::time::{TimeSpec, TimeValLike};
use nix::time::{clock_gettime, ClockId};
use nix::unistd::User;
use object::elf;
use object::elf::STT_FUNC;
use object::read::elf::{FileHeader, Sym};
use serde::{Deserialize, Serialize};
use std::ffi::CStr;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::num::ParseIntError;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::{fs, io};
use tracing::{debug, warn};

#[derive(Debug, Copy, Clone)]
pub enum UserId {
    #[allow(unused)]
    Real(uid_t),
    #[allow(unused)]
    Effective(uid_t),
    #[allow(unused)]
    SavedSet(uid_t),
    #[allow(unused)]
    Filesystem(uid_t),
}

#[derive(Debug)]
pub struct ProcessStatus {
    pub uid: [UserId; 4],
    pub tgid: pid_t,
    pub ns_tgid: Vec<pid_t>,
    pub ns_pid: Vec<pid_t>,
    pub ns_pgid: Vec<pid_t>,
    pub ns_sid: Vec<pid_t>,
}

impl ProcessStatus {
    pub fn get_effective_uid(&self) -> uid_t {
        self.uid
            .iter()
            .find_map(|d| match d {
                UserId::Effective(pid) => Some(pid.clone()),
                _ => None,
            })
            .unwrap()
    }
    pub fn of_process(pid: pid_t) -> Result<Self> {
        let path = PathBuf::from(format!("/proc/{pid}/status"));
        let f = File::open(path)?;
        let mut rdr = BufReader::new(f);
        let mut tgid: pid_t = 0;
        let mut uid = [UserId::Real(0); 4];
        let mut ns_tgid: Vec<pid_t> = Vec::new();
        let mut ns_pid: Vec<pid_t> = Vec::new();
        let mut ns_pgid: Vec<pid_t> = Vec::new();
        let mut ns_sid: Vec<pid_t> = Vec::new();
        loop {
            let mut s: String = String::new();
            let read = rdr.read_line(&mut s)?;
            if read == 0 {
                break;
            }
            let split: Vec<&str> = s.split(":\t").collect();
            assert!(!split.is_empty());

            fn get_values(value: &str) -> Vec<String> {
                // `read_line` will read newline as well if it is there, remove if it was read
                let value_no_new_line = value.replace('\n', "");
                value_no_new_line
                    .split('\t')
                    .map(|s| s.to_owned())
                    .collect()
            }
            fn get_as<T: FromStr>(value: &str) -> Result<Vec<T>>
            where
                ErrorKind: From<<T as FromStr>::Err>,
            {
                let xs = get_values(value);
                let mut pids: Vec<T> = Vec::new();
                assert!(!xs.is_empty());
                for s in xs {
                    let v = T::from_str(s.as_str())?;
                    pids.push(v);
                }
                Ok(pids)
            }

            let key = split[0];
            match key {
                "Uid" => {
                    let uids = get_as::<uid_t>(split[1])?;
                    // https://man7.org/linux/man-pages/man5/proc_pid_status.5.html
                    uid = [
                        UserId::Real(uids[0]),
                        UserId::Effective(uids[1]),
                        UserId::SavedSet(uids[2]),
                        UserId::Filesystem(uids[3]),
                    ]
                }
                "Tgid" => {
                    let v = get_values(split[1]);
                    assert_eq!(1, v.len());
                    tgid = pid_t::from_str(v[0].as_str())?;
                }
                "NStgid" => {
                    ns_tgid = get_as(split[1])?;
                }
                "NSpid" => {
                    ns_pid = get_as(split[1])?;
                }
                "NSpgid" => {
                    ns_pgid = get_as(split[1])?;
                }
                "NSsid" => {
                    ns_sid = get_as(split[1])?;
                }
                _ => {}
            }
        }

        Ok(ProcessStatus {
            uid,
            tgid,
            ns_tgid,
            ns_pid,
            ns_pgid,
            ns_sid,
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PasswdStruct {
    pub name: String,
    pub passwd: String,
    pub uid: uid_t,
    pub gid: uid_t,
    pub gecos: String,
    pub dir: String,
    pub shell: String,
}

impl PasswdStruct {
    pub fn from(user: User) -> PasswdStruct {
        PasswdStruct {
            name: user.name,
            passwd: user.passwd.into_string().unwrap(),
            uid: user.uid.as_raw(),
            gid: user.gid.as_raw(),
            gecos: user.gecos.into_string().unwrap(),
            dir: user.dir.to_str().unwrap().to_owned(),
            shell: user.shell.to_str().unwrap().to_owned(),
        }
    }
}

pub fn increase_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        return Err(AppError::from(ErrorKind::SetMemLockLimitError(
            io::Error::last_os_error(),
        )));
    }
    Ok(())
}

pub fn find_loaded_library(pid: pid_t, library_name: &str) -> Result<Option<String>> {
    let maps_path = format!("/proc/{}/maps", pid);
    println!("maps_path: {}", maps_path);
    let file = fs::File::open(&maps_path)?;
    let reader = io::BufReader::new(file);
    for line in reader.lines() {
        let line = line?;
        if line.contains(library_name) {
            let path_to_lib = line
                .find('/')
                .map(|path_start_idx| line[path_start_idx..].to_string());
            return Ok(path_to_lib);
        }
    }
    Ok(None)
}

pub fn find_func_symbol(library_name: &str, name: &str) -> Result<String> {
    let data = fs::read(library_name)?;
    let elf = elf::FileHeader64::<object::Endianness>::parse(&*data)?;
    let endian = elf.endian()?;
    let sections = elf.sections(endian, &*data)?;
    let symbols = sections.symbols(endian, &*data, elf::SHT_SYMTAB)?;
    for symbol in symbols.iter() {
        if symbol.st_info() != STT_FUNC {
            continue;
        }
        let name_bytes = symbol.name(endian, symbols.strings())?;
        let read_name = String::from_utf8_lossy(name_bytes);
        if read_name.contains(name) {
            return Ok(read_name.to_string());
        }
    }
    Err(AppError::from(FuncNotFoundError(name.to_string())))
}

#[allow(dead_code)]
pub fn get_java_processes_as_jps(hs_perf_data_folder: &str) -> Vec<u32> {
    fn parse_as_pid(str: &str) -> std::result::Result<u32, ParseIntError> {
        str.parse::<u32>()
    }
    let mut java_processes: Vec<u32> = vec![];
    match fs::read_dir(hs_perf_data_folder) {
        Ok(read_dir) => {
            for maybe_entry in read_dir {
                match maybe_entry {
                    Ok(entry) => match entry.file_name().to_str() {
                        None => {
                            warn!("Entry {:?} does not have file name", entry);
                        }
                        Some(file_name) => match parse_as_pid(file_name) {
                            Ok(pid) => {
                                java_processes.push(pid);
                            }
                            Err(err) => {
                                warn!("Could not parse {} as u32 processed id: {}", file_name, err);
                            }
                        },
                    },
                    Err(err) => {
                        warn!(
                            "Failed to read entry from `hs_perf_data_folder` {}: {}",
                            hs_perf_data_folder, err
                        );
                    }
                }
            }
        }
        Err(err) => {
            warn!(
                "Failed to read `hs_perf_data_folder` {}: {}",
                hs_perf_data_folder, err
            );
        }
    }
    java_processes
}

/// Check whether the provided process id is a Java process.
pub fn check_java_process(
    pid: pid_t,
    ns_tgid: Option<&pid_t>,
    pwd_struct: PasswdStruct,
) -> Result<()> {
    // Inspired by https://github.com/openjdk/jdk/blob/62a4544bb76aa339a8129f81d2527405a1b1e7e3/src/jdk.internal.jvmstat/share/classes/sun/jvmstat/perfdata/monitor/protocol/local/LocalVmManager.java#L77-L116
    let hs_perf_path = if let Some(ns_tgid) = ns_tgid {
        format!(
            "/proc/{}/root/tmp/hsperfdata_{}/{}",
            pid, pwd_struct.name, ns_tgid
        )
    } else {
        format!("/tmp/hsperfdata_{}/{}", pwd_struct.name, pid)
    };

    let hs_perf_path = Path::new(hs_perf_path.as_str());
    debug!(
        "Checking the existence of PerfDataFile at {:?} and enough permissions to read from it",
        hs_perf_path
    );
    let mut f = File::open(hs_perf_path)?;
    let mut buf: [u8; 64] = [0; 64];
    f.read(&mut buf)?;
    debug!("PerfDataFile at {:?} is readable", hs_perf_path);
    Ok(())
}

/// Estimates the system start-time (boot time) in Unix-epoch nanoseconds
///
/// Credits to https://milek.blogspot.com/2023/03/bpf-unix-timestamp.html, this is just a Rust version with some comments
pub fn estimate_system_boot_time<const ITERATIONS: usize>() -> Result<u64> {
    // On high level, the code below tries to estimate the relationship/offset between two clocks on a Linux System
    // - CLOCK_REALTIME — The "wall clock" time
    // - CLOCK_BOOTTIME — The system’s uptime clock, which starts at zero when the kernel boots and increases steadily (even during system sleep).
    // to estimate the system's boot time with the least noise in Unix-epoch nanoseconds

    // Prepare arrays to store timespec for each iteration
    let mut ts1 = [TimeSpec::from(timespec {
        tv_sec: 0,
        tv_nsec: 0,
    }); ITERATIONS];
    let mut ts2 = [TimeSpec::from(timespec {
        tv_sec: 0,
        tv_nsec: 0,
    }); ITERATIONS];
    let mut ts3 = [TimeSpec::from(timespec {
        tv_sec: 0,
        tv_nsec: 0,
    }); ITERATIONS];

    // In a tight loop capture timestamps from both clocks to analyze it later
    for i in 0..ITERATIONS {
        ts1[i] = clock_gettime(ClockId::CLOCK_REALTIME)?;
        ts2[i] = clock_gettime(ClockId::CLOCK_BOOTTIME)?;
        ts3[i] = clock_gettime(ClockId::CLOCK_REALTIME)?;
    }

    // Find the smallest difference between two `CLOCK_REALTIME` readings.
    // That reading happened with the least overhead/noise so we can get a cleaner midpoint t4
    // that best represents the actual real time of the middle call to CLOCK_BOOTTIME.
    let mut smallest_dt: i64 = 0;
    let mut smallest_dt_i: usize = 0;
    for i in 0..ITERATIONS {
        let t1 = ts1[i].num_nanoseconds();
        let t3 = ts3[i].num_nanoseconds();
        let dt = t3.saturating_sub(t1);
        if smallest_dt == 0 || dt < smallest_dt {
            smallest_dt = dt;
            smallest_dt_i = i;
        }
    }
    // Least noisy readings
    let t1 = &ts1[smallest_dt_i].num_nanoseconds();
    // Note that t2 is CLOCK_BOOTTIME that starts at zero when the kernel boots and increases steadily
    let t2 = &ts2[smallest_dt_i].num_nanoseconds();
    let t3 = &ts3[smallest_dt_i].num_nanoseconds();
    // Compute t4, that represents the best guess of the real time of the middle call to CLOCK_BOOTTIME.
    let t4 = (t1 + t3) / 2;
    // Subtract t2 from t4 to get an approximation of when the system started (i.e., the boot time) in Unix-epoch nanoseconds
    let estimated_boot_time_in_ns = t4.saturating_sub(*t2);
    Ok(estimated_boot_time_in_ns as u64)
}

#[allow(unused)]
pub fn str_from_null_terminated_utf8_safe(s: &[u8]) -> &str {
    if s.iter().any(|&x| x == 0) {
        unsafe { str_from_null_terminated_utf8(s) }
    } else {
        std::str::from_utf8(s).unwrap()
    }
}

#[allow(unused)]
unsafe fn str_from_null_terminated_utf8(s: &[u8]) -> &str {
    CStr::from_ptr(s.as_ptr() as *const _).to_str().unwrap()
}

pub fn unix_timestamp_ns_to_datetime(timestamp: i64) -> DateTime<Utc> {
    // Convert nanoseconds -> (seconds, subsecond nanos)
    let secs = (timestamp / 1_000_000_000) as i64;
    let nanos = (timestamp % 1_000_000_000) as u32;

    // Construct a DateTime
    let dt = DateTime::from_timestamp(secs, nanos).expect("t5 is out of range for NaiveDateTime");
    dt
}
