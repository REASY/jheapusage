use crate::JobQueue;
use plain::Plain;
use std::sync::Arc;
use tracing::{debug, info};

pub trait RingBufferCallbackHandler {
    fn callback(&mut self, data: &[u8]) -> i32;
}

pub struct GenericEventHandler<T> {
    job_queue: Arc<JobQueue<T>>,
    processed: usize,
}

impl<T> GenericEventHandler<T> {
    pub fn new(job_queue: Arc<JobQueue<T>>) -> Self {
        Self {
            job_queue,
            processed: 0,
        }
    }
}
impl<T: Plain + std::fmt::Display + Clone> RingBufferCallbackHandler for GenericEventHandler<T> {
    fn callback(&mut self, data: &[u8]) -> i32 {
        let event = plain::from_bytes::<T>(data).expect("failed to convert bytes");
        debug!(
            "Received {} bytes, the payload as `{}`: {{ {} }}",
            data.len(),
            std::any::type_name::<T>(),
            event
        );
        self.job_queue.push(event.clone());

        if self.processed > 0 && self.processed % 50 == 0 {
            info!(
                "Processed {} events of type {}",
                self.processed,
                std::any::type_name::<T>()
            );
        }
        self.processed += 1;
        0
    }
}
