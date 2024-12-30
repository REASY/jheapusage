use std::env;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/ebpf/jvm.bpf.c";

fn main() {
    let out = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script"),
    )
    .join("src")
    .join("ebpf")
    .join("jvm.skel.rs");

    let arch = env::var("CARGO_CFG_TARGET_ARCH")
        .expect("CARGO_CFG_TARGET_ARCH must be set in build script");

    SkeletonBuilder::new()
        .source(SRC)
        .clang_args([
            OsStr::new("-I"),
            vmlinux::include_path_root().join(arch).as_os_str(),
            // FIXME: Without adding `/usr/include/x86_64-linux-gnu` to include I'm getting on Ubuntu 24.10 with kernel 6.11.0-13-generic
            /*
            Caused by:
              process didn't exit successfully: `/home/user/github/REASY/jheapusage/target/debug/build/jheapusage-f45cdd62dad4e982/build-script-build` (exit status: 101)
              --- stderr
              thread 'main' panicked at build.rs:33:10:
              called `Result::unwrap()` on an `Err` value: failed to build `src/ebpf/jvm.bpf.c`

              Caused by:
                  0: Failed to compile /tmp/.tmp8IxaCK/hotspot_usdt.o from src/ebpf/jvm.bpf.c
                  1: Command `clang -I /home/user/.cargo/git/checkouts/vmlinux.h-ec81e0afb9d5f7e2/83a228c/include/x86_64 -I /tmp/.tmpPwZDSl/bpf/src -fno-stack-protector -D__TARGET_ARCH_x86 -g -O2 -target bpf -c src/ebpf/jvm.bpf.c -o /tmp/.tmp8IxaCK/hotspot_usdt.o` failed (exit status: 1)
                  2: In file included from src/ebpf/jvm.bpf.c:6:
                     In file included from /tmp/.tmpPwZDSl/bpf/src/bpf/usdt.bpf.h:6:
                     /usr/include/linux/errno.h:1:10: fatal error: 'asm/errno.h' file not found
                         1 | #include <asm/errno.h>
                           |          ^~~~~~~~~~~~~
                     1 error generated.
            */
            OsStr::new("-I"),
            Path::new("/usr/include/x86_64-linux-gnu").as_os_str(),
        ])
        .build_and_generate(&out)
        .unwrap();
    println!("cargo:rerun-if-changed={SRC}");
    println!("cargo:rerun-if-changed=src/ebpf/jvm.h");
}
