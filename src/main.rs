// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

mod errors;
mod logger;
mod otlp;
mod utils;

use clap::Parser;
use errors::Result;
use lazy_static::lazy_static;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::UprobeOpts;
use opentelemetry::{global, KeyValue};
use opentelemetry_otlp::{MetricExporter, Protocol, WithExportConfig};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::resource::{
    EnvResourceDetector, ResourceDetector, SdkProvidedResourceDetector, TelemetryResourceDetector,
};
use opentelemetry_sdk::{runtime, Resource};
use plain::Plain;
use std::collections::VecDeque;
use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

mod hotspot_usdt {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/ebpf/hotspot_usdt.skel.rs"
    ));
}

use crate::hotspot_usdt::types::gc_heap_summary_event;
use crate::otlp::process_as_otlp;
use crate::utils::{
    check_java_process, estimate_system_boot_time, find_func_symbol, find_loaded_library,
    increase_memlock_rlimit, unix_timestamp_ns_to_datetime,
};
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

unsafe impl Plain for gc_heap_summary_event {}

lazy_static! {
    static ref BOOT_DATE_TIME: u64 = estimate_system_boot_time::<25>().unwrap();
}

impl std::fmt::Display for gc_heap_summary_event {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let t = unsafe { self.gc_when_type.assume_init() };
        write!(
            f,
            "ts: {}, pid: {}, tid: {}, type: {:?}, used: {}",
            unix_timestamp_ns_to_datetime(self.ts as i64),
            self.pid,
            self.tid,
            t,
            self.used,
        )?;

        Ok(())
    }
}

const LIBJVM_NAME: &'static str = "libjvm.so";

/// `report_gc_heap_summary` method is available since Java 11, however it is am internal (HIDDEN) C++ function so the name is mangled
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

    info!(
        "System boot time in ns: {}, as datetime: {}",
        *BOOT_DATE_TIME,
        unix_timestamp_ns_to_datetime(*BOOT_DATE_TIME as i64)
    );

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
    let report_gc_heap_summary_name =
        find_func_symbol(libjvm_path.as_str(), REPORT_GC_HEAP_SUMMARY_FUNC)?;
    info!(
        "report_gc_heap_summary_name: {}",
        report_gc_heap_summary_name
    );

    increase_memlock_rlimit()?;
    debug!("Increased memlock rlimit");

    let mut hotspot_usdt_builder = HotspotUsdtSkelBuilder::default();
    if args.verbose {
        hotspot_usdt_builder.obj_builder.debug(true);
    }
    let mut open_object = MaybeUninit::uninit();
    let open_skel = hotspot_usdt_builder.open(&mut open_object)?;
    open_skel.maps.rodata_data.target_userspace_pid = args.pid as i32;
    open_skel.maps.rodata_data.boot_time_ns = *BOOT_DATE_TIME;

    let mut skel: HotspotUsdtSkel = open_skel.load()?;
    debug!("Loaded `HotspotUsdtSkel`");

    // Begin tracing
    skel.attach()?;
    debug!("Attached");

    let link = skel
        .progs
        .send_gc_heap_summary_event
        .attach_uprobe_with_opts(
            args.pid as i32,
            libjvm_path,
            0,
            UprobeOpts {
                func_name: report_gc_heap_summary_name,
                ..Default::default()
            },
        )?;
    info!(
        "Attached UProbe to the process {}. Link is {:?}",
        args.pid, link
    );

    // Setup OpenTelementry
    let meter_provider = init_metrics()?;
    global::set_meter_provider(meter_provider.clone());

    let should_stop = Arc::new(AtomicBool::new(false));
    let queue: JobQueue<gc_heap_summary_event> = JobQueue::new();

    let arc_queue = Arc::new(queue);
    let arc_queue_2 = arc_queue.clone();
    let should_stop_cloned = should_stop.clone();
    tokio::spawn(async move {
        process_as_otlp(arc_queue, should_stop_cloned).await;
    });

    let mut processed: usize = 0;
    let callback = |data: &[u8]| {
        let event =
            plain::from_bytes::<gc_heap_summary_event>(data).expect("failed to convert bytes");
        debug!(
            "Received {} bytes, the payload: {{ {} }}",
            data.len(),
            event
        );
        arc_queue_2.push(*event);

        if processed % 50 == 0 {
            info!("Events {} was processed", processed);
        }
        processed += 1;
        0
    };
    let mut builder = libbpf_rs::RingBufferBuilder::new();
    builder
        .add(&skel.maps.ringbuf, callback)
        .expect("failed to add ringbuf");
    let ringbuf = builder.build().expect("failed to build");
    info!("Built RingBuffer {:?}", ringbuf);

    loop {
        ringbuf.poll(Duration::from_millis(10))?;
        if skel.maps.bss_data.has_exited {
            info!(
                "The process {} has exited with exit code {}",
                args.pid, skel.maps.bss_data.exit_code
            );
            should_stop.store(true, std::sync::atomic::Ordering::SeqCst);
            break;
        }
    }

    Ok(())
}

fn init_metrics() -> Result<SdkMeterProvider> {
    let exporter = MetricExporter::builder()
        .with_tonic()
        .with_protocol(Protocol::Grpc) //can be changed to `Protocol::HttpJson` to export in JSON format
        .build()?;
    const SERVICE_NAME: &str = "service.name";
    let reader = opentelemetry_sdk::metrics::PeriodicReader::builder(exporter, runtime::Tokio)
        .with_interval(Duration::from_millis(500))
        .build();

    let detectors: Vec<Box<dyn ResourceDetector>> = vec![
        Box::new(SdkProvidedResourceDetector),
        Box::new(TelemetryResourceDetector),
        Box::new(EnvResourceDetector::new()),
    ];
    let resource = Resource::from_detectors(Duration::from_secs(5), detectors).merge(
        &Resource::new_with_defaults([KeyValue::new(SERVICE_NAME, "jheapusage")]),
    );
    Ok(SdkMeterProvider::builder()
        .with_resource(resource)
        .with_reader(reader)
        .build())
}
