use crate::ebpf::jvm::types::gc_when_type_enum::GCWhenEndSentinel;
use crate::ebpf::jvm::types::{gc_heap_summary_event, gc_when_type_enum, mem_pool_gc_event};
use crate::utils::str_from_null_terminated_utf8_safe;
use crate::JobQueue;
use opentelemetry::{global, InstrumentationScope, KeyValue};
use opentelemetry_otlp::{MetricExporter, Protocol, WithExportConfig};
use opentelemetry_sdk::metrics::{SdkMeterProvider, Temporality};
use opentelemetry_sdk::resource::{
    EnvResourceDetector, ResourceDetector, SdkProvidedResourceDetector, TelemetryResourceDetector,
};
use opentelemetry_sdk::{runtime, Resource};
use opentelemetry_semantic_conventions::attribute::{HOST_ARCH, JVM_MEMORY_POOL_NAME, OS_NAME};
use opentelemetry_semantic_conventions::metric::{
    JVM_MEMORY_COMMITTED, JVM_MEMORY_INIT, JVM_MEMORY_LIMIT, JVM_MEMORY_USED,
};
use opentelemetry_semantic_conventions::resource;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, info};

const JVM_MEMORY_STATE: &'static str = "jvm.memory.state";
const JVM_MEMORY_MANAGER_NAME: &'static str = "jvm.memory.manager.name";

fn get_scope() -> InstrumentationScope {
    InstrumentationScope::builder("jheapusage")
        .with_version(env!("CARGO_PKG_VERSION"))
        .with_schema_url("1.0")
        .with_attributes(vec![
            KeyValue::new(OS_NAME, std::env::consts::OS),
            KeyValue::new(HOST_ARCH, std::env::consts::ARCH),
        ])
        .build()
}

fn as_runtime(name: &str) -> String {
    format!("runtime.{}", name)
}

pub async fn process_as_otlp_gc_heap_summary_event(
    queue: Arc<JobQueue<gc_heap_summary_event>>,
    should_stop: Arc<AtomicBool>,
) {
    let mut processed: usize = 0;
    let scope = get_scope();
    let meter = global::meter_with_scope(scope);
    let used_gauge = meter
        .u64_gauge(as_runtime("jvm.memory.total.used"))
        .with_unit("By")
        .with_description("The total amount of Heap memory currently used by JVM")
        .build();
    while !should_stop.load(std::sync::atomic::Ordering::Relaxed) {
        match queue.pop() {
            None => {}
            Some(event) => {
                let gc_when = unsafe { event.gc_when_type.assume_init() };
                let state = match gc_when {
                    gc_when_type_enum::BeforeGC => "BeforeGC",
                    gc_when_type_enum::AfterGC => "AfterGC",
                    GCWhenEndSentinel => "GCWhenEndSentinel",
                };
                let tags = [KeyValue::new(JVM_MEMORY_STATE, state)];
                used_gauge.record(event.used, &tags);
                debug!("Handled `gc_heap_summary_event` {}", event);
                if processed > 0 && processed % 50 == 0 {
                    info!("{} events were recorded to OTLP", processed);
                }
                processed += 1;
            }
        }
        sleep(Duration::from_millis(10)).await;
    }
}

pub async fn process_as_otlp_mem_pool_gc_event(
    queue: Arc<JobQueue<mem_pool_gc_event>>,
    should_stop: Arc<AtomicBool>,
) {
    let mut processed: usize = 0;
    let scope = get_scope();
    let meter = global::meter_with_scope(scope);
    // https://github.com/openjdk/jdk/blob/6c59185475eeca83153f085eba27cc0b3acf9bb4/src/hotspot/share/services/memoryUsage.hpp#L30-L46
    let init_size_gauge = meter
        .u64_gauge(as_runtime(JVM_MEMORY_INIT))
        .with_unit("By")
        .with_description("The initial amount of memory the JVM requests from the OS")
        .build();
    let used_gauge = meter
        .u64_gauge(as_runtime(JVM_MEMORY_USED))
        .with_unit("By")
        .with_description("The amount of memory currently used")
        .build();
    let committed_gauge = meter
        .u64_gauge(as_runtime(JVM_MEMORY_COMMITTED))
        .with_unit("By")
        .with_description(
            "The amount of memory that is guaranteed to be available for use by the JVM",
        )
        .build();
    let max_size_gauge = meter
        .u64_gauge(as_runtime(JVM_MEMORY_LIMIT))
        .with_unit("By")
        .with_description("The maximum amount of memory that can be used for memory management")
        .build();

    while !should_stop.load(std::sync::atomic::Ordering::Relaxed) {
        match queue.pop() {
            None => {}
            Some(event) => {
                let manager = str_from_null_terminated_utf8_safe(event.manager.as_ref()).to_owned();
                let pool = str_from_null_terminated_utf8_safe(event.pool.as_ref()).to_owned();
                let state = if event.is_begin == 1 {
                    "BeforeGC"
                } else {
                    "AfterGC"
                };
                let tags = [
                    KeyValue::new(JVM_MEMORY_MANAGER_NAME, manager),
                    KeyValue::new(JVM_MEMORY_POOL_NAME, pool),
                    KeyValue::new(JVM_MEMORY_STATE, state),
                ];
                used_gauge.record(event.used, &tags);
                init_size_gauge.record(event.init_size, &tags);
                committed_gauge.record(event.committed, &tags);
                if event.max_size != u64::MAX {
                    max_size_gauge.record(event.max_size, &tags);
                }
                debug!("Handled `mem_pool_gc_event` {}", event);
                if processed > 0 && processed % 50 == 0 {
                    info!("{} events were recorded to OTLP", processed);
                }
                processed += 1;
            }
        }
        sleep(Duration::from_millis(10)).await;
    }
}

pub fn init_metrics(
    protocol: Protocol,
    service_name: String,
) -> crate::errors::Result<SdkMeterProvider> {
    let exporter = MetricExporter::builder()
        .with_http()
        .with_protocol(protocol)
        .with_temporality(Temporality::default())
        .build()?;
    let reader = opentelemetry_sdk::metrics::PeriodicReader::builder(exporter, runtime::Tokio)
        .with_interval(Duration::from_millis(1000))
        .build();

    let detectors: Vec<Box<dyn ResourceDetector>> = vec![
        Box::new(SdkProvidedResourceDetector),
        Box::new(TelemetryResourceDetector),
        Box::new(EnvResourceDetector::new()),
    ];
    let resource = Resource::from_detectors(Duration::from_secs(5), detectors).merge(
        &Resource::new_with_defaults([KeyValue::new(resource::SERVICE_NAME, service_name)]),
    );
    Ok(SdkMeterProvider::builder()
        .with_resource(resource)
        .with_reader(reader)
        .build())
}
