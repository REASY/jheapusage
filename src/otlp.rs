use crate::hotspot_usdt::types::gc_heap_summary_event;
use crate::JobQueue;
use opentelemetry::{global, InstrumentationScope, KeyValue};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, info};

pub async fn process_as_otlp(
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

    // https://github.com/openjdk/jdk/blob/6c59185475eeca83153f085eba27cc0b3acf9bb4/src/hotspot/share/services/memoryUsage.hpp#L30-L46
    // let init_size_gauge = meter
    //     .u64_gauge("runtime.java.memory.init_size")
    //     .with_unit("By")
    //     .with_description("The initial amount of memory the JVM requests from the OS")
    //     .build();
    // let used_gauge = meter
    //     .u64_gauge("runtime.java.memory.used")
    //     .with_unit("By")
    //     .with_description("The amount of memory currently used")
    //     .build();
    // let committed_gauge = meter
    //     .u64_gauge("runtime.java.memory.committed")
    //     .with_unit("By")
    //     .with_description(
    //         "The amount of memory that is guaranteed to be available for use by the JVM",
    //     )
    //     .build();
    // let max_size_gauge = meter
    //     .u64_gauge("runtime.java.memory.max_size")
    //     .with_unit("By")
    //     .with_description("The maximum amount of memory that can be used for memory management")
    //     .build();

    let used_gauge = meter
        .u64_gauge("runtime.java.total.memory.used")
        .with_unit("By")
        .with_description("The total amount of Heap memory currently used by JVM")
        .build();
    while !should_stop.load(std::sync::atomic::Ordering::Relaxed) {
        match queue.pop() {
            None => {}
            Some(event) => {
                used_gauge.record(event.used, &[]);
                debug!("Recorded metrics for {}", event);
                if processed % 50 == 0 {
                    info!("Events {} was recorded to OTLP", processed);
                }
                processed += 1;
            }
        }
        sleep(Duration::from_millis(10)).await;
    }
}
