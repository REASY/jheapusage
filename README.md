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
sudo apt-get install -y --no-install-recommends make llvm clang libelf1 libelf-dev zlib1g-dev
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
javac InfiniteApp.java && java -Xmx400M InfiniteApp
The application is running. Press Ctrl+C to stop. Process Id: 58842
buffer is 17964196
buffer is 19107073
buffer is 15320567
buffer is 15074673
buffer is 13406603
buffer is 14874387
buffer is 10877020
```
2. Use the process id from above with `jheapusage`: `sudo target/release/jheapusage --pid 58842`
```shell
sudo target/release/jheapusage --pid 58842
2024-12-24T15:20:53.720855Z  INFO main ThreadId(01) jheapusage: src/main.rs:76: Received args: AppArgs { pid: 58842, verbose: false }
2024-12-24T15:20:53.738050Z  INFO main ThreadId(01) jheapusage: src/main.rs:115: Attached USDT hotspot:mem__pool__gc__end to the process 58842. Link is Link { ptr: 0x62ddcbe099e0 }
2024-12-24T15:20:53.738325Z  INFO main ThreadId(01) jheapusage: src/main.rs:135: Built RingBuffer RingBuffer { ptr: 0x62ddcbe19160, _cbs: [RingBufferCallback { cb: 0x1 }] }
Received 176 bytes, the payload: { ts: 6936494667278, pid: 58842, manager: G1 Young Generation, pool: CodeHeap 'non-nmethods', used: 1375488, committed: 2555904, max_size: Some(8196096) }
Received 176 bytes, the payload: { ts: 6936494672508, pid: 58842, manager: G1 Young Generation, pool: CodeHeap 'profiled nmethods', used: 201344, committed: 2555904, max_size: Some(121729024) }
Received 176 bytes, the payload: { ts: 6936494672868, pid: 58842, manager: G1 Young Generation, pool: CodeHeap 'non-profiled nmethods', used: 68864, committed: 2555904, max_size: Some(121733120) }
Received 176 bytes, the payload: { ts: 6936494673248, pid: 58842, manager: G1 Young Generation, pool: Metaspace, used: 459376, committed: 655360, max_size: None }
Received 176 bytes, the payload: { ts: 6936494673568, pid: 58842, manager: G1 Young Generation, pool: Compressed Class Space, used: 29872, committed: 131072, max_size: Some(1073741824) }
Received 176 bytes, the payload: { ts: 6936494673938, pid: 58842, manager: G1 Young Generation, pool: G1 Eden Space, used: 0, committed: 123731968, max_size: None }
Received 176 bytes, the payload: { ts: 6936494674248, pid: 58842, manager: G1 Young Generation, pool: G1 Survivor Space, used: 0, committed: 0, max_size: None }
Received 176 bytes, the payload: { ts: 6936494674528, pid: 58842, manager: G1 Young Generation, pool: G1 Old Gen, used: 285458216, committed: 295698432, max_size: Some(419430400) }
Received 176 bytes, the payload: { ts: 6936494773859, pid: 58842, manager: G1 Young Generation, pool: CodeHeap 'non-nmethods', used: 1375488, committed: 2555904, max_size: Some(8196096) }
Received 176 bytes, the payload: { ts: 6936494775049, pid: 58842, manager: G1 Young Generation, pool: CodeHeap 'profiled nmethods', used: 201344, committed: 2555904, max_size: Some(121729024) }
Received 176 bytes, the payload: { ts: 6936494775369, pid: 58842, manager: G1 Young Generation, pool: CodeHeap 'non-profiled nmethods', used: 68864, committed: 2555904, max_size: Some(121733120) }
Received 176 bytes, the payload: { ts: 6936494775669, pid: 58842, manager: G1 Young Generation, pool: Metaspace, used: 459376, committed: 655360, max_size: None }
Received 176 bytes, the payload: { ts: 6936494775929, pid: 58842, manager: G1 Young Generation, pool: Compressed Class Space, used: 29872, committed: 131072, max_size: Some(1073741824) }
Received 176 bytes, the payload: { ts: 6936494776199, pid: 58842, manager: G1 Young Generation, pool: G1 Eden Space, used: 0, committed: 117440512, max_size: None }
Received 176 bytes, the payload: { ts: 6936494776479, pid: 58842, manager: G1 Young Generation, pool: G1 Survivor Space, used: 0, committed: 0, max_size: None }
...
Received 176 bytes, the payload: { ts: 7037902916377, pid: 58842, manager: G1 Young Generation, pool: G1 Survivor Space, used: 0, committed: 0, max_size: None }
Received 176 bytes, the payload: { ts: 7037902916667, pid: 58842, manager: G1 Young Generation, pool: G1 Old Gen, used: 96715248, committed: 155189248, max_size: Some(419430400) }
2024-12-24T15:22:36.388054Z  INFO main ThreadId(01) jheapusage: src/main.rs:140: The process 58842 has exited with exit code 130
```
## **License**

This project is licensed under the MIT License. See the **[LICENSE](LICENSE)** file for more information.
