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
sudo apt-get install -y --no-install-recommends clang-format build-essential make libelf1 libelf-dev zlib1g-dev pkg-config
```

Then install Clang version >= 15. One can
use [Automatic installation script](https://apt.llvm.org/#:~:text=flang%20packages%20added-,Automatic%20installation%20script,-For%20convenience%20there)
for that.

### Build the project

To build the project, run the following command:

```
cargo build --release
```

### Docker

Run `docker build --build-arg BUILD_DATE="$(date --rfc-3339=seconds)" -t jheapusage:dev docker/dev ` in the root folder
to build dev docker image

```shell
docker build --build-arg BUILD_DATE="$(date --rfc-3339=seconds)" -t jheapusage:dev docker/dev 
[+] Building 64.0s (8/8) FINISHED                                                                                                                                                             docker:default
 => [internal] load build definition from Dockerfile                                                                                                                                                    0.0s
 => => transferring dockerfile: 1.68kB                                                                                                                                                                  0.0s
 => [internal] load metadata for docker.io/library/ubuntu:22.04                                                                                                                                         0.8s
 => [internal] load .dockerignore                                                                                                                                                                       0.0s
 => => transferring context: 2B                                                                                                                                                                         0.0s
 => CACHED [1/4] FROM docker.io/library/ubuntu:22.04@sha256:0e5e4a57c2499249aafc3b40fcd541e9a456aab7296681a3994d631587203f97                                                                            0.0s
 => [2/4] RUN apt-get update -y &&     apt-get install -y --no-install-recommends       curl ca-certificates lsb-release wget software-properties-common gnupg clang-format       build-essential mak  29.5s
 => [3/4] RUN curl -O https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && ./llvm.sh 17 && rm -rf llvm.sh                                                                                               23.7s 
 => [4/4] RUN curl https://sh.rustup.rs -sSf | sh -s -- -y  && rustup --version                           && cargo --version                            && rustc --version                              8.1s 
 => exporting to image                                                                                                                                                                                  1.9s 
 => => exporting layers                                                                                                                                                                                 1.9s 
 => => writing image sha256:d60298440dad99fdc0ec86a9b81c876e469d7c55d0bdaf2bbc25a78dc6e577eb                                                                                                            0.0s 
 => => naming to docker.io/library/jheapusage:dev 
```

### Known issues

I had to add [build.rs](build.rs) extra include path `/usr/include/x86_64-linux-gnu` on my Ubuntu 24.10 with kernel
6.11.0-13-generic otherwise I was getting the error

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
      --pid <PID>
          Java process PID
      --sampling-interval-ms <SAMPLING_INTERVAL_MS>
          Sampling interval in milliseconds [default: 1000]
  -v, --verbose
          Verbose debug output
  -h, --help
```

### Example of run with [InfiniteApp.java](InfiniteApp.java)

1. Compile and run `javac InfiniteApp.java && java -Xmx500M InfiniteApp`
   ```shell
   javac InfiniteApp.java && java -Xmx500M InfiniteApp
   Runtime is: 21.0.5+11-LTS
   The application is running. Press Ctrl+C to stop. Process Id: 37885
   ```
2. Use the process id from above with `jheapusage`: `sudo target/release/jheapusage --pid 37885`
   ```shell
   sudo OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318 target/release/jheapusage --pid 37885           
   2025-01-02T07:55:24.780259Z  INFO main ThreadId(01) jheapusage: src/main.rs:97: Received args: AppArgs { pid: 103680, verbose: false }
   2025-01-02T07:55:24.780275Z  INFO main ThreadId(01) jheapusage: src/main.rs:99: System boot time in ns: 1735782997823610000, as datetime: 2025-01-02 01:56:37.823610 UTC
   2025-01-02T07:55:24.787120Z  INFO main ThreadId(01) jheapusage: src/main.rs:119: report_gc_heap_summary_name: _ZNK8GCTracer22report_gc_heap_summaryEN6GCWhen4TypeERK13GCHeapSummary
   2025-01-02T07:55:24.797382Z  INFO main ThreadId(01) jheapusage::ebpf: src/ebpf.rs:72: Attach BPF object
   2025-01-02T07:55:24.814656Z  INFO main ThreadId(01) jheapusage::ebpf: src/ebpf.rs:80: Attached USDT hotspot:mem__pool__gc__begin to the process 103680. Link is Link { ptr: 0x5ee97b3edba0 }
   2025-01-02T07:55:24.814712Z  INFO main ThreadId(01) jheapusage::ebpf: src/ebpf.rs:92: Attached USDT hotspot:mem__pool__gc__end to the process 103680. Link is Link { ptr: 0x5ee97b378a40 }
   2025-01-02T07:55:24.815503Z  INFO main ThreadId(01) jheapusage::ebpf: src/ebpf.rs:111: Attached UProbe to the process 103680. Link is Link { ptr: 0x5ee97b3e75f0 }
   2025-01-02T07:55:24.815988Z  INFO main ThreadId(01) jheapusage: src/main.rs:168: Built rg_send_gc_heap_summary_event RingBuffer { ptr: 0x5ee97b3eb720, _cbs: [RingBufferCallback { cb: 0x5ee97b3ebb10 }] }
   2025-01-02T07:55:24.816704Z  INFO main ThreadId(01) jheapusage: src/main.rs:180: Built rg_hotspot_mem_pool_gc RingBuffer { ptr: 0x5ee97b3ebe60, _cbs: [RingBufferCallback { cb: 0x5ee97b3ebe20 }] }
   ...
   2025-01-02T07:56:15.910340Z  INFO tokio-runtime-worker ThreadId(31) jheapusage::handlers: src/handlers.rs:35: Processed 50 events of type jheapusage::ebpf::jvm::imp::types::gc_heap_summary_event
   2025-01-02T07:56:15.913705Z  INFO tokio-runtime-worker ThreadId(30) jheapusage::otlp: src/otlp.rs:67: 50 events were recorded to OTLP
   2025-01-02T07:56:15.913714Z  INFO tokio-runtime-worker ThreadId(25) jheapusage::otlp: src/otlp.rs:131: 400 events were recorded to OTLP
   2025-01-02T07:56:21.922315Z  INFO tokio-runtime-worker ThreadId(03) jheapusage::handlers: src/handlers.rs:35: Processed 450 events of type jheapusage::ebpf::jvm::imp::types::mem_pool_gc_event
   2025-01-02T07:56:21.950469Z  INFO tokio-runtime-worker ThreadId(22) jheapusage::otlp: src/otlp.rs:131: 450 events were recorded to OTLP
   2025-01-02T07:56:27.932491Z  INFO tokio-runtime-worker ThreadId(03) jheapusage::handlers: src/handlers.rs:35: Processed 500 events of type jheapusage::ebpf::jvm::imp::types::mem_pool_gc_event
   2025-01-02T07:56:27.977579Z  INFO tokio-runtime-worker ThreadId(22) jheapusage::otlp: src/otlp.rs:131: 500 events were recorded to OTLP
   2025-01-02T07:56:33.945204Z  INFO tokio-runtime-worker ThreadId(03) jheapusage::handlers: src/handlers.rs:35: Processed 550 events of type jheapusage::ebpf::jvm::imp::types::mem_pool_gc_event
   2025-01-02T07:56:34.018606Z  INFO tokio-runtime-worker ThreadId(30) jheapusage::otlp: src/otlp.rs:131: 550 events were recorded to OTLP
   2025-01-02T07:56:37.167495Z  INFO                 main ThreadId(01) jheapusage: src/main.rs:216: The process 103680 has exited with exit code 130
   2025-01-02T07:56:37.167509Z  INFO                 main ThreadId(01) jheapusage: src/main.rs:206: Waiting for tasks to complete...
   2025-01-02T07:56:37.253469Z  INFO                 main ThreadId(01) jheapusage: src/main.rs:209: Done
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
     target/release/jheapusage --pid #PID#
   ```
3. Analyze `valgrind.log`, the following errors **should not be in the log**,
   more [Understanding Valgrind Error Messages](https://cs3157.github.io/www/2022-9/guides/valgrind.html)
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
