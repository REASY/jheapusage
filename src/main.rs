// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

mod errors;
mod logger;
mod utils;

use std::mem::MaybeUninit;
use std::time::Duration;

use clap::Parser;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use plain::Plain;

use errors::Result;

mod hotspot_usdt {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/ebpf/hotspot_usdt.skel.rs"
    ));
}

use crate::hotspot_usdt::types::mem_pool_gc_end_event;
use crate::utils::{check_java_process, find_loaded_library, increase_memlock_rlimit};
use hotspot_usdt::*;
use tracing::{debug, info, warn};

#[derive(Parser, Debug, Clone)]
#[clap()]
/// Prints heap usage of a running Java program
struct AppArgs {
    /// Java process PID
    #[clap(long)]
    pid: u32,
    /// Verbose debug output
    #[arg(short, long)]
    verbose: bool,
}

unsafe impl Plain for mem_pool_gc_end_event {}

impl std::fmt::Display for mem_pool_gc_end_event {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        // FIXME
        let manager = std::str::from_utf8(self.manager.as_ref()).unwrap();
        // FIXME
        let pool = std::str::from_utf8(self.pool.as_ref()).unwrap();
        let max_size = if self.max_size == u64::MAX {
            None
        } else {
            Some(self.max_size)
        };
        write!(
            f,
            "ts: {}, pid: {}, manager: {}, pool: {}, used: {}, committed: {}, max_size: {:?}",
            self.ts, self.pid, manager, pool, self.used, self.committed, max_size
        )?;

        Ok(())
    }
}

const LIBJVM_NAME: &'static str = "libjvm.so";
const USDT_PROVIDER: &'static str = "hotspot";
const USDT_NAME: &'static str = "mem__pool__gc__end";

fn main() -> Result<()> {
    let args = AppArgs::parse();
    if args.verbose {
        logger::setup("jheapusage", "DEBUG");
    } else {
        logger::setup("jheapusage", "INFO");
    }
    info!("Received args: {:?}", args);

    check_java_process("/tmp/hsperfdata_user/", args.pid).map_err(|err| {
        warn!("Could not check whether provided process id {} is a Java process. Is it still running? Make sure it does not run with `-XX:-UsePerfData` JVM arguments. The error: {}", args.pid, err);
        err
    })?;

    let Some(libjvm_path) = find_loaded_library(args.pid, LIBJVM_NAME)? else {
        warn!(
            "Could not find {} in process {}. Is it Java process?",
            LIBJVM_NAME, args.pid
        );
        return Ok(());
    };

    increase_memlock_rlimit()?;
    debug!("Increased memlock rlimit");

    let mut hotspot_usdt_builder = HotspotUsdtSkelBuilder::default();
    if args.verbose {
        hotspot_usdt_builder.obj_builder.debug(true);
    }
    let mut open_object = MaybeUninit::uninit();
    let open_skel = hotspot_usdt_builder.open(&mut open_object)?;
    open_skel.maps.rodata_data.target_userspace_pid = args.pid as i32;

    let mut skel: HotspotUsdtSkel = open_skel.load()?;
    debug!("Loaded `HotspotUsdtSkel`");

    // Begin tracing
    skel.attach()?;
    debug!("Attached");

    let link = skel.progs.handle_gc_end.attach_usdt(
        args.pid as i32,
        libjvm_path,
        USDT_PROVIDER,
        USDT_NAME,
    )?;
    info!(
        "Attached USDT {}:{} to the process {}. Link is {:?}",
        USDT_PROVIDER, USDT_NAME, args.pid, link
    );
    let callback = |data: &[u8]| {
        let event =
            plain::from_bytes::<mem_pool_gc_end_event>(data).expect("failed to convert bytes");
        println!(
            "Received {} bytes, the payload: {{ {} }}",
            data.len(),
            event
        );
        0
    };

    let mut builder = libbpf_rs::RingBufferBuilder::new();
    builder
        .add(&skel.maps.ringbuf, callback)
        .expect("failed to add ringbuf");
    let ringbuf = builder.build().expect("failed to build");
    info!("Built RingBuffer {:?}", ringbuf);

    loop {
        ringbuf.poll(Duration::from_millis(100))?;
        if skel.maps.bss_data.has_exited {
            info!(
                "The process {} has exited with exit code {}",
                args.pid, skel.maps.bss_data.exit_code
            );
            break;
        }
    }

    Ok(())
}
