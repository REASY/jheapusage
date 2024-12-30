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
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, info};

pub async fn process_as_otlp_gc_heap_summary_event(
    queue: Arc<JobQueue<gc_heap_summary_event>>,
    should_stop: Arc<AtomicBool>,
) {
    let mut processed: usize = 0;
    let common_scope_attributes = vec![KeyValue::new("scope-key", "scope-value")];
    let scope = InstrumentationScope::builder("basic")
        .with_version("1.0")
        .with_attributes(common_scope_attributes)
        .build();
    let meter = global::meter_with_scope(scope);
    let used_gauge = meter
        .u64_gauge("runtime.java.total.memory.used")
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
                let tags = [KeyValue::new("state", state)];
                used_gauge.record(event.used, &tags);
                debug!("Handled `gc_heap_summary_event` {}", event);
                if processed % 50 == 0 {
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
    let common_scope_attributes = vec![KeyValue::new("scope-key", "scope-value")];
    let scope = InstrumentationScope::builder("basic")
        .with_version("1.0")
        .with_attributes(common_scope_attributes)
        .build();
    let meter = global::meter_with_scope(scope);

    // https://github.com/openjdk/jdk/blob/6c59185475eeca83153f085eba27cc0b3acf9bb4/src/hotspot/share/services/memoryUsage.hpp#L30-L46
    let init_size_gauge = meter
        .u64_gauge("runtime.java.memory.init_size")
        .with_unit("By")
        .with_description("The initial amount of memory the JVM requests from the OS")
        .build();
    let used_gauge = meter
        .u64_gauge("runtime.java.memory.used")
        .with_unit("By")
        .with_description("The amount of memory currently used")
        .build();
    let committed_gauge = meter
        .u64_gauge("runtime.java.memory.committed")
        .with_unit("By")
        .with_description(
            "The amount of memory that is guaranteed to be available for use by the JVM",
        )
        .build();
    let max_size_gauge = meter
        .u64_gauge("runtime.java.memory.max_size")
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
                    KeyValue::new("manager", manager),
                    KeyValue::new("pool", pool),
                    KeyValue::new("state", state),
                ];
                used_gauge.record(event.used, &tags);
                init_size_gauge.record(event.init_size, &tags);
                committed_gauge.record(event.committed, &tags);
                if event.max_size != u64::MAX {
                    max_size_gauge.record(event.max_size, &tags);
                }
                debug!("Handled `mem_pool_gc_event` {}", event);
                if processed % 50 == 0 {
                    info!("{} events were recorded to OTLP", processed);
                }
                processed += 1;
            }
        }
        sleep(Duration::from_millis(10)).await;
    }
}

pub fn init_metrics(protocol: Protocol) -> crate::errors::Result<SdkMeterProvider> {
    let exporter = MetricExporter::builder()
        .with_http()
        .with_protocol(protocol)
        .with_temporality(Temporality::default())
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
