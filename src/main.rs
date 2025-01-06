// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

mod ebpf;
mod errors;
mod events;
mod handlers;
mod isolation;
mod logger;
mod otlp;
mod utils;

use crate::ebpf::jvm::types::{gc_heap_summary_event, mem_pool_gc_event};
use crate::ebpf::jvm::JvmMaps;
use crate::ebpf::Ebpf;
use crate::handlers::{GenericEventHandler, RingBufferCallbackHandler};
use crate::isolation::NamespaceIsolation;
use crate::otlp::{
    init_metrics, process_as_otlp_gc_heap_summary_event, process_as_otlp_mem_pool_gc_event,
};
use crate::utils::{
    check_java_process, estimate_system_boot_time, find_func_symbol, find_loaded_library,
    increase_memlock_rlimit, unix_timestamp_ns_to_datetime, PasswdStruct, ProcessStatus,
};
use clap::Parser;
use errors::Result;
use lazy_static::lazy_static;
use libc::pid_t;
use nix::unistd::{Uid, User};
use opentelemetry::global;
use opentelemetry_otlp::Protocol;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::Duration;
use tracing::{debug, info, warn};

#[derive(Parser, Debug, Clone)]
#[clap()]
/// Prints heap usage of a running Java program
struct AppArgs {
    /// Java process PID
    #[clap(long)]
    pid: pid_t,
    /// Verbose debug output
    #[arg(short, long)]
    verbose: bool,
}

lazy_static! {
    static ref BOOT_DATE_TIME: u64 = estimate_system_boot_time::<25>().unwrap();
}

const LIBJVM_NAME: &'static str = "libjvm.so";

/// `GCTracer::report_gc_heap_summary` method is available since Java 11, however it is am internal (HIDDEN) C++ function so the name is mangled
/// https://github.com/openjdk/jdk/blob/jdk-11%2B28/src/hotspot/share/gc/shared/gcTraceSend.cpp#L392
/*
➜ readelf -Ws --dyn-syms /home/user/.sdkman/candidates/java/11.0.25-zulu/lib/server/libjvm.so | grep -i report_gc_heap_summary
 34411: 00000000007e26d0     5 FUNC    LOCAL  HIDDEN    13 _ZNK8GCTracer22report_gc_heap_summaryEN6GCWhen4TypeERK13GCHeapSummary

➜ readelf -Ws --dyn-syms /home/user/.sdkman/candidates/java/21.0.5-zulu/lib/server/libjvm.so | grep -i report_gc_heap_summary
 38234: 00000000008662f0     5 FUNC    LOCAL  HIDDEN    12 _ZNK8GCTracer22report_gc_heap_summaryEN6GCWhen4TypeERK13GCHeapSummary
*/
const REPORT_GC_HEAP_SUMMARY_FUNC: &'static str = "report_gc_heap_summary";

struct JobQueue<T> {
    elements: Arc<Mutex<VecDeque<T>>>,
}

impl<T> JobQueue<T> {
    /// Creates a new, empty `JobQueue`.
    fn new() -> Self {
        JobQueue {
            elements: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    /// Pushes an event into the queue.
    fn push(&self, event: T) {
        let mut queue = self.elements.lock().unwrap(); // Lock the mutex
        queue.push_back(event);
    }

    /// Pops an event from the queue.
    /// Returns `Some(event)` if the queue is not empty, or `None` otherwise.
    fn pop(&self) -> Option<T> {
        let mut queue = self.elements.lock().unwrap(); // Lock the mutex
        queue.pop_front()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = AppArgs::parse();
    if args.verbose {
        logger::setup("jheapusage", "DEBUG");
    } else {
        logger::setup("jheapusage", "INFO");
    }
    info!("Received args: {:?}", args);

    let proc_status = ProcessStatus::of_process(args.pid)?;
    let effective_uid = proc_status.get_effective_uid();
    info!("Process status is: {:?}", proc_status);

    let pwd_struct = if proc_status.ns_tgid.len() >= 2 {
        let ns = NamespaceIsolation::new(args.pid);
        ns.execute(|| {
            // FIXME
            let user = User::from_uid(Uid::from(effective_uid)).unwrap();
            user.map(|x| PasswdStruct::from(x))
        })?
    } else {
        let user = User::from_uid(Uid::from(effective_uid))?;
        user.map(|x| PasswdStruct::from(x))
    }
    .unwrap();
    info!("Password db is: {:?}", pwd_struct);
    let ns_tgid: Option<&pid_t> = if proc_status.ns_tgid.len() > 1 {
        proc_status.ns_tgid.last()
    } else {
        None
    };
    if ns_tgid.is_some() {
        info!(
            "Target process is running in isolated namespace (container?). Process ids in all namespaces: {:?}, namespace ids: {:?}",
            proc_status.ns_tgid,
            proc_status.ns_sid
        );
    }

    let stat = nix::sys::stat::stat(&PathBuf::from(format!("/proc/{}/ns/pid", args.pid)))?;
    info!("st_dev: {}, st_ino: {}", stat.st_dev, stat.st_ino);

    info!(
        "System boot time in ns: {}, as datetime: {}",
        *BOOT_DATE_TIME,
        unix_timestamp_ns_to_datetime(*BOOT_DATE_TIME as i64)
    );

    check_java_process(args.pid, ns_tgid, pwd_struct).map_err(|err| {
        warn!("Could not check whether provided process id {} is a Java process. Is it still running? Make sure it does not run with `-XX:-UsePerfData` JVM arguments. The error: {}", args.pid, err);
        err
    })?;

    let libjvm_path = match find_loaded_library(args.pid, LIBJVM_NAME)? {
        None => {
            warn!(
                "Could not find {} in process {}. Is it Java process?",
                LIBJVM_NAME, args.pid
            );
            return Ok(());
        }
        Some(path) => ns_tgid.map_or(path.clone(), |_| format!("/proc/{}/root{}", args.pid, path)),
    };
    debug!("Path to libjvm: {}", libjvm_path);

    let report_gc_heap_summary_name =
        find_func_symbol(libjvm_path.as_str(), REPORT_GC_HEAP_SUMMARY_FUNC)?;
    info!(
        "report_gc_heap_summary_name: {}",
        report_gc_heap_summary_name
    );

    increase_memlock_rlimit()?;
    debug!("Increased memlock rlimit");

    let mut epbf = Ebpf::new(args.verbose, |skel| {
        skel.maps.rodata_data.st_dev = stat.st_dev;
        skel.maps.rodata_data.st_ino = stat.st_ino;
        skel.maps.rodata_data.target_userspace_pid = args.pid;
        skel.maps.rodata_data.boot_time_ns = *BOOT_DATE_TIME;
    });
    epbf.setup(args.pid, libjvm_path.clone(), report_gc_heap_summary_name)?;
    let jvm_maps = epbf.maps();

    // Setup OpenTelementry
    let meter_provider = init_metrics(Protocol::HttpJson)?;
    global::set_meter_provider(meter_provider.clone());

    let should_stop = Arc::new(AtomicBool::new(false));
    let queue_gc_heap_summary_event: Arc<JobQueue<gc_heap_summary_event>> =
        Arc::new(JobQueue::new());
    let queue_mem_pool_gc_event: Arc<JobQueue<mem_pool_gc_event>> = Arc::new(JobQueue::new());

    let mut gc_heap_summary_event_handler =
        GenericEventHandler::new(queue_gc_heap_summary_event.clone());
    tokio::spawn({
        let should_stop = should_stop.clone();
        async move {
            process_as_otlp_gc_heap_summary_event(queue_gc_heap_summary_event, should_stop).await;
        }
    });

    let mut mem_pool_gc_end_event_handler =
        GenericEventHandler::new(queue_mem_pool_gc_event.clone());
    tokio::spawn({
        let should_stop = should_stop.clone();
        async move {
            process_as_otlp_mem_pool_gc_event(queue_mem_pool_gc_event, should_stop).await;
        }
    });

    let mut rg0 = libbpf_rs::RingBufferBuilder::new();
    rg0.add(&jvm_maps.rg_send_gc_heap_summary_event, move |data| {
        gc_heap_summary_event_handler.callback(data)
    })?;
    let rg_send_gc_heap_summary_event = rg0
        .build()
        .expect("failed to build ring buffer for rg_send_gc_heap_summary_event");
    info!(
        "Built rg_send_gc_heap_summary_event {:?}",
        rg_send_gc_heap_summary_event
    );

    let mut rg1 = libbpf_rs::RingBufferBuilder::new();
    rg1.add(&jvm_maps.rg_hotspot_mem_pool_gc, move |data| {
        mem_pool_gc_end_event_handler.callback(data)
    })?;
    let rg_hotspot_mem_pool_gc = rg1
        .build()
        .expect("failed to build ring buffer for rg_hotspot_mem_pool_gc");
    info!("Built rg_hotspot_mem_pool_gc {:?}", rg_hotspot_mem_pool_gc);

    let t1 = tokio::spawn({
        let should_stop = should_stop.clone();
        async move {
            while !should_stop.load(std::sync::atomic::Ordering::Relaxed) {
                rg_send_gc_heap_summary_event
                    .poll(Duration::from_millis(100))
                    .unwrap();
            }
        }
    });

    let t2 = tokio::spawn({
        let should_stop = should_stop.clone();
        async move {
            while !should_stop.load(std::sync::atomic::Ordering::Relaxed) {
                rg_hotspot_mem_pool_gc
                    .poll(Duration::from_millis(100))
                    .unwrap();
            }
        }
    });

    wait_for_target_process_to_exit(args.pid, jvm_maps, should_stop);

    info!("Waiting for tasks to complete...");
    t1.await?;
    t2.await?;
    info!("Done");
    Ok(())
}

fn wait_for_target_process_to_exit(pid: pid_t, jvm_maps: &JvmMaps, should_stop: Arc<AtomicBool>) {
    loop {
        if jvm_maps.bss_data.has_exited {
            info!(
                "The process {} has exited with exit code {}",
                pid, jvm_maps.bss_data.exit_code
            );
            should_stop.store(true, std::sync::atomic::Ordering::SeqCst);
            break;
        }
        sleep(Duration::from_millis(100));
    }
}
