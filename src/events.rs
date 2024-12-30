use crate::ebpf::jvm::types::{gc_heap_summary_event, mem_pool_gc_event};
use crate::utils::{str_from_null_terminated_utf8_safe, unix_timestamp_ns_to_datetime};
use plain::Plain;

unsafe impl Plain for mem_pool_gc_event {}
unsafe impl Plain for gc_heap_summary_event {}

impl std::fmt::Display for mem_pool_gc_event {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        // FIXME
        let manager = str_from_null_terminated_utf8_safe(self.manager.as_ref());
        // FIXME
        let pool = str_from_null_terminated_utf8_safe(self.pool.as_ref());
        let max_size = if self.max_size == u64::MAX {
            None
        } else {
            Some(self.max_size)
        };
        let state = if self.is_begin == 1 {
            "BeforeGC"
        } else {
            "AfterGC"
        };
        write!(
            f,
            "[{}] ts: {}, pid: {}, manager: {}, pool: {}, used: {}, committed: {}, max_size: {:?}",
            state,
            unix_timestamp_ns_to_datetime(self.ts as i64),
            self.pid,
            manager,
            pool,
            self.used,
            self.committed,
            max_size,
        )?;

        Ok(())
    }
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
