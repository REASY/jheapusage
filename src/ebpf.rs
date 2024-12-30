use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{Link, OpenObject, UprobeOpts};
use std::mem::{ManuallyDrop, MaybeUninit};
use tracing::{debug, info};

pub mod jvm {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/ebpf/jvm.skel.rs"));
}

use crate::ebpf::jvm::{JvmMaps, JvmSkel, JvmSkelBuilder, OpenJvmSkel};
use crate::errors;

const USDT_PROVIDER: &'static str = "hotspot";
const USDT_MEM_POOL_GC_BEGIN: &'static str = "mem__pool__gc__begin";
const USDT_MEM_POOL_GC_END: &'static str = "mem__pool__gc__end";

pub struct Ebpf {
    _links: Vec<Link>,
    jvm: ManuallyDrop<JvmSkel<'static>>,
    storage: ManuallyDrop<Box<MaybeUninit<OpenObject>>>,
}

impl Drop for Ebpf {
    fn drop(&mut self) {
        while !self._links.is_empty() {
            let link = self._links.remove(self._links.len() - 1);
            drop(link)
        }
        unsafe { ManuallyDrop::drop(&mut self.jvm) };
        unsafe { ManuallyDrop::drop(&mut self.storage) };
    }
}

impl Ebpf {
    pub fn new<F>(verbose: bool, mut init: F) -> Self
    where
        F: FnMut(&mut OpenJvmSkel) -> (),
    {
        let mut builder = JvmSkelBuilder::default();
        builder.obj_builder.debug(verbose);

        // Read https://github.com/libbpf/libbpf-rs/issues/1017 to understand why we need Rust type-system dancing here.
        let mut storage = Box::new(MaybeUninit::uninit());
        // https://github.com/atenart/libbpf-rs-skel-embed/blob/10d1a44b39399f9018f5824eb4624d3ee06a28d1/src/workaround.rs
        // To allow embedding an open skeleton in an internal structure we need a little dance
        // as Rust does not allow self. The lifetime of the skeleton must be faked to
        // being 'static for self-referencing to work.
        let storage_static = unsafe {
            std::mem::transmute::<&mut MaybeUninit<_>, &'static mut MaybeUninit<_>>(
                storage.as_mut(),
            )
        };

        let mut open_skel = builder.open(storage_static).expect("Unable to open");
        init(&mut open_skel);
        let jvm_skel = ManuallyDrop::new(open_skel.load().expect("Unable to load"));
        debug!("Loaded `JvmSkel`");
        Self {
            _links: Vec::new(),
            jvm: jvm_skel,
            storage: ManuallyDrop::new(storage),
        }
    }

    pub fn setup(
        &mut self,
        pid: u32,
        libjvm_path: String,
        report_gc_heap_summary_name: String,
    ) -> errors::Result<()> {
        self.jvm.attach()?;
        info!("Attach BPF object");

        let link = self.jvm.progs.hotspot_mem_pool_gc_begin.attach_usdt(
            pid as i32,
            libjvm_path.clone(),
            USDT_PROVIDER,
            USDT_MEM_POOL_GC_BEGIN,
        )?;
        info!(
            "Attached USDT {}:{} to the process {}. Link is {:?}",
            USDT_PROVIDER, USDT_MEM_POOL_GC_BEGIN, pid, link
        );
        self._links.push(link);

        let link = self.jvm.progs.hotspot_mem_pool_gc_end.attach_usdt(
            pid as i32,
            libjvm_path.clone(),
            USDT_PROVIDER,
            USDT_MEM_POOL_GC_END,
        )?;
        info!(
            "Attached USDT {}:{} to the process {}. Link is {:?}",
            USDT_PROVIDER, USDT_MEM_POOL_GC_END, pid, link
        );
        self._links.push(link);

        let link = self
            .jvm
            .progs
            .send_gc_heap_summary_event
            .attach_uprobe_with_opts(
                pid as i32,
                libjvm_path,
                0,
                UprobeOpts {
                    func_name: report_gc_heap_summary_name,
                    ..Default::default()
                },
            )?;
        info!("Attached UProbe to the process {}. Link is {:?}", pid, link);
        self._links.push(link);

        Ok(())
    }

    pub fn maps(&self) -> &JvmMaps {
        &self.jvm.maps
    }
}
