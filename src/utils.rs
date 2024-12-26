use crate::errors::{AppError, ErrorKind, Result};
use chrono::{DateTime, Utc};
use libc::{clock_gettime, timespec, CLOCK_BOOTTIME, CLOCK_REALTIME};
use std::ffi::CStr;
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

/// Check whether the provided process id is a Java process.
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

/// Estimates the system start-time (boot time) in Unix-epoch nanoseconds
///
/// Credits to https://milek.blogspot.com/2023/03/bpf-unix-timestamp.html, this is just a Rust version with some comments
pub fn estimate_system_boot_time<const ITERATIONS: usize>() -> Result<u64> {
    // On high level, the code below tries to estimate the relationship/offset between two clocks on a Linux System
    // - CLOCK_REALTIME — The "wall clock" time
    // - CLOCK_BOOTTIME — The system’s uptime clock, which starts at zero when the kernel boots and increases steadily (even during system sleep).
    // to estimate the system's boot time with the least noise in Unix-epoch nanoseconds

    // Prepare arrays to store timespec for each iteration
    let mut ts1 = [timespec {
        tv_sec: 0,
        tv_nsec: 0,
    }; ITERATIONS];
    let mut ts2 = [timespec {
        tv_sec: 0,
        tv_nsec: 0,
    }; ITERATIONS];
    let mut ts3 = [timespec {
        tv_sec: 0,
        tv_nsec: 0,
    }; ITERATIONS];

    // In a tight loop capture timestamps from both clocks to analyze it later
    for i in 0..ITERATIONS {
        unsafe {
            clock_gettime(CLOCK_REALTIME, &mut ts1[i]);
            clock_gettime(CLOCK_BOOTTIME, &mut ts2[i]);
            clock_gettime(CLOCK_REALTIME, &mut ts3[i]);
        }
    }

    // Find the smallest difference between two `CLOCK_REALTIME` readings.
    // That reading happened with the least overhead/noise so we can get a cleaner midpoint t4
    // that best represents the actual real time of the middle call to CLOCK_BOOTTIME.
    let mut smallest_dt: u64 = 0;
    let mut smallest_dt_i: usize = 0;
    for i in 0..ITERATIONS {
        let t1 = timespec_to_ns(&ts1[i]);
        let t3 = timespec_to_ns(&ts3[i]);
        let dt = t3.saturating_sub(t1);
        if smallest_dt == 0 || dt < smallest_dt {
            smallest_dt = dt;
            smallest_dt_i = i;
        }
    }
    // Least noisy readings
    let t1 = timespec_to_ns(&ts1[smallest_dt_i]);
    // Note that t2 is CLOCK_BOOTTIME that starts at zero when the kernel boots and increases steadily
    let t2 = timespec_to_ns(&ts2[smallest_dt_i]);
    let t3 = timespec_to_ns(&ts3[smallest_dt_i]);
    // Compute t4, that represents the best guess of the real time of the middle call to CLOCK_BOOTTIME.
    let t4 = (t1 + t3) / 2;
    // Subtract t2 from t4 to get an approximation of when the system started (i.e., the boot time) in Unix-epoch nanoseconds
    let estimated_boot_time_in_ns = t4.saturating_sub(t2);
    Ok(estimated_boot_time_in_ns)
}

/// Convert a `timespec` to nanoseconds as a `u64`.
fn timespec_to_ns(ts: &timespec) -> u64 {
    // tv_sec can be negative in theory if the timespec was derived from e.g. CLOCK_REALTIME way in the past,
    // but typically for real-time and boottime, tv_sec >= 0. We'll cast safely to u64.
    (ts.tv_sec as u64).saturating_mul(1_000_000_000) + (ts.tv_nsec as u64)
}

pub fn str_from_null_terminated_utf8_safe(s: &[u8]) -> &str {
    if s.iter().any(|&x| x == 0) {
        unsafe { str_from_null_terminated_utf8(s) }
    } else {
        std::str::from_utf8(s).unwrap()
    }
}

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
