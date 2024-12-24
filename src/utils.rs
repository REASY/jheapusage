use crate::errors::{AppError, ErrorKind, Result};
use std::fs::File;
use std::io::{BufRead, Read};
use std::num::ParseIntError;
use std::path::Path;
use std::{fs, io};
use tracing::{debug, warn};

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

pub fn find_loaded_library(pid: u32, library_name: &str) -> Result<Option<String>> {
    let maps_path = format!("/proc/{}/maps", pid);
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

/// Check whether provided process id is Java process.
pub fn check_java_process(hs_perf_data_folder: &str, pid: u32) -> Result<()> {
    // Inspired by https://github.com/openjdk/jdk/blob/62a4544bb76aa339a8129f81d2527405a1b1e7e3/src/jdk.internal.jvmstat/share/classes/sun/jvmstat/perfdata/monitor/protocol/local/LocalVmManager.java#L77-L116
    let hs_perf_path = Path::new(hs_perf_data_folder).join(pid.to_string());
    debug!(
        "Checking the existence of PerfDataFile at {:?} and enough permissions to read from it",
        hs_perf_path.as_path()
    );
    let mut f = File::open(hs_perf_path.clone())?;
    let mut buf: [u8; 64] = [0; 64];
    f.read(&mut buf)?;
    debug!("PerfDataFile at {:?} is readable", hs_perf_path.as_path());
    Ok(())
}
