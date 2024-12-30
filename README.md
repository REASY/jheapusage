jheapusage
-----

![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)

## Development

The project requires the following tools configured on your developer machine:

- Rust compiler and Cargo, check https://www.rust-lang.org/tools/install on how to install both
- Installed Java, you can use [SDKMAN!](https://sdkman.io/) to get Java 21

### Install Dependencies
On Ubuntu/Debian, you need:
```shell
sudo apt update
sudo apt-get install -y --no-install-recommends clang-format build-essential make llvm clang libelf1 libelf-dev zlib1g-dev
```

### Build the project

To build the project, run the following command:

```
cargo build --release
```

### Known issues

I had to add [build.rs](build.rs) extra include path `/usr/include/x86_64-linux-gnu` on my Ubuntu 24.10 with kernel 6.11.0-13-generic otherwise I was getting the error
```
Caused by:
  process didn't exit successfully: `/home/user/github/REASY/jheapusage/target/debug/build/jheapusage-f45cdd62dad4e982/build-script-build` (exit status: 101)
  --- stderr
  thread 'main' panicked at build.rs:33:10:
  called `Result::unwrap()` on an `Err` value: failed to build `src/ebpf/hotspot_usdt.bpf.c`

  Caused by:
      0: Failed to compile /tmp/.tmp8IxaCK/hotspot_usdt.o from src/ebpf/hotspot_usdt.bpf.c
      1: Command `clang -I /home/user/.cargo/git/checkouts/vmlinux.h-ec81e0afb9d5f7e2/83a228c/include/x86_64 -I /tmp/.tmpPwZDSl/bpf/src -fno-stack-protector -D__TARGET_ARCH_x86 -g -O2 -target bpf -c src/ebpf/hotspot_usdt.bpf.c -o /tmp/.tmp8IxaCK/hotspot_usdt.o` failed (exit status: 1)
      2: In file included from src/ebpf/hotspot_usdt.bpf.c:6:
         In file included from /tmp/.tmpPwZDSl/bpf/src/bpf/usdt.bpf.h:6:
         /usr/include/linux/errno.h:1:10: fatal error: 'asm/errno.h' file not found
             1 | #include <asm/errno.h>
               |          ^~~~~~~~~~~~~
         1 error generated.
```

This will compile your code and create the necessary binaries.

## How to run `jheapusage`
Note: you need to use `sudo`, provide `--help` to get help on how to run it.
```shell
sudo target/release/jheapusage --help
Prints heap usage of a running Java program

Usage: jheapusage [OPTIONS] --pid <PID>

Options:
      --pid <PID>  Java process PID
  -v, --verbose    Verbose debug output
  -h, --help       Print help
```

### Example of run with [InfiniteApp.java](InfiniteApp.java)
1. Compile and run `javac InfiniteApp.java && java -Xmx400M InfiniteApp`
   ```shell
   javac InfiniteApp.java && java -Xmx500M InfiniteApp
   Runtime is: 21.0.5+11-LTS
   The application is running. Press Ctrl+C to stop. Process Id: 37885
   ```
2. Use the process id from above with `jheapusage`: `sudo target/release/jheapusage --pid 58842`
   ```shell
   sudo OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318 target/release/jheapusage --pid 37885           
   2025-01-02T03:53:28.138179Z  INFO main ThreadId(01) jheapusage: src/main.rs:97: Received args: AppArgs { pid: 37885, verbose: false }
   2025-01-02T03:53:28.138193Z  INFO main ThreadId(01) jheapusage: src/main.rs:99: System boot time in ns: 1735782997823610000, as datetime: 2025-01-02 01:56:37.823610 UTC
   2025-01-02T03:53:28.145177Z  INFO main ThreadId(01) jheapusage: src/main.rs:119: report_gc_heap_summary_name: _ZNK8GCTracer22report_gc_heap_summaryEN6GCWhen4TypeERK13GCHeapSummary
   2025-01-02T03:53:28.155553Z  INFO main ThreadId(01) jheapusage::ebpf: src/ebpf.rs:72: Attach BPF object
   2025-01-02T03:53:28.175666Z  INFO main ThreadId(01) jheapusage::ebpf: src/ebpf.rs:80: Attached USDT hotspot:mem__pool__gc__begin to the process 37885. Link is Link { ptr: 0x57573a805bc0 }
   2025-01-02T03:53:28.175726Z  INFO main ThreadId(01) jheapusage::ebpf: src/ebpf.rs:92: Attached USDT hotspot:mem__pool__gc__end to the process 37885. Link is Link { ptr: 0x57573a7f9610 }
   2025-01-02T03:53:28.198632Z  INFO main ThreadId(01) jheapusage::ebpf: src/ebpf.rs:111: Attached UProbe to the process 37885. Link is Link { ptr: 0x57573a7f6890 }
   2025-01-02T03:53:28.199042Z  INFO main ThreadId(01) jheapusage: src/main.rs:168: Built rg_send_gc_heap_summary_event RingBuffer { ptr: 0x57573a7f63f0, _cbs: [RingBufferCallback { cb: 0x57573a7faac0 }] }
   2025-01-02T03:53:28.199463Z  INFO main ThreadId(01) jheapusage: src/main.rs:180: Built rg_hotspot_mem_pool_gc RingBuffer { ptr: 0x57573a803970, _cbs: [RingBufferCallback { cb: 0x57573a7eb2c0 }] }
   2025-01-02T03:53:29.284641Z  INFO tokio-runtime-worker ThreadId(32) jheapusage::handlers: src/handlers.rs:35: Processed 0 events of type jheapusage::ebpf::jvm::imp::types::gc_heap_summary_event
   2025-01-02T03:53:29.284660Z  INFO tokio-runtime-worker ThreadId(26) jheapusage::handlers: src/handlers.rs:35: Processed 0 events of type jheapusage::ebpf::jvm::imp::types::mem_pool_gc_event
   2025-01-02T03:53:29.285917Z  INFO tokio-runtime-worker ThreadId(33) jheapusage::otlp: src/otlp.rs:48: 0 events were recorded to OTLP
   2025-01-02T03:53:29.285920Z  INFO tokio-runtime-worker ThreadId(02) jheapusage::otlp: src/otlp.rs:117: 0 events were recorded to OTLP
   2025-01-02T03:53:35.298938Z  INFO tokio-runtime-worker ThreadId(26) jheapusage::handlers: src/handlers.rs:35: Processed 50 events of type jheapusage::ebpf::jvm::imp::types::mem_pool_gc_event
   2025-01-02T03:53:35.324006Z  INFO tokio-runtime-worker ThreadId(33) jheapusage::otlp: src/otlp.rs:117: 50 events were recorded to OTLP
   2025-01-02T03:53:41.310079Z  INFO tokio-runtime-worker ThreadId(26) jheapusage::handlers: src/handlers.rs:35: Processed 100 events of type jheapusage::ebpf::jvm::imp::types::mem_pool_gc_event
   2025-01-02T03:53:41.361932Z  INFO tokio-runtime-worker ThreadId(02) jheapusage::otlp: src/otlp.rs:117: 100 events were recorded to OTLP
   2025-01-02T03:53:55.022270Z  INFO                 main ThreadId(01) jheapusage: src/main.rs:216: The process 37885 has exited with exit code 130
   2025-01-02T03:53:55.022285Z  INFO                 main ThreadId(01) jheapusage: src/main.rs:206: Waiting for tasks to complete...
   2025-01-02T03:53:55.035924Z  INFO                 main ThreadId(01) jheapusage: src/main.rs:209: Done
   ```

### Run under valgrind
1. Install valgrind , `sudo apt-get install valgrind`
2. Run it on `jheapusage`
   ```shell
   OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318 G_SLICE=always-malloc G_DEBUG=gc-friendly valgrind -v \
     --tool=memcheck \
     --track-origins=yes \
     --leak-check=full \
     --num-callers=100 \
     --log-file=valgrind.log \
     target/release/jheapusage --pid 59258#PID#
   ```
3. Analyze `valgrind.log`, the following errors **should not be in the log**, more [Understanding Valgrind Error Messages](https://cs3157.github.io/www/2022-9/guides/valgrind.html)
   - Invalid reads
   - Invalid writes
   - Conditional jumps and moves that depend on uninitialized value(s)
   - Segmentation faults (colloquially, “segfaults”)

### Format C code
```shell
clang-format --style=file:src/ebpf/.clang-format -i src/ebpf/*
```
## **License**

This project is licensed under the MIT License. See the **[LICENSE](LICENSE)** file for more information.
