// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/usdt.bpf.h>
#include "hotspot_usdt.h"

const volatile pid_t targ_pid = 0;
const u64 dev = 0x60;
const u64 ino = 912591;

// Dummy instance to get skeleton to generate definition for `struct mem_pool_gc_end_event`
struct mem_pool_gc_end_event _mem_pool_gc_end_event = {0};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB ring buffer
} ringbuf SEC(".maps");

SEC("tracepoint/sched/sched_process_exit")
int sched_process_exit(struct trace_event_raw_sched_process_template* ctx) {
    // FIXME properly handle the exit of Java app that we care `targ_pid`
    u64 id = bpf_get_current_pid_tgid();
    pid_t pid = id >> 32;
    pid_t tgid = id & 0xffffffff;
    /* ignore thread exits */
//    if (pid != tid)
//        return 0;

    char command[128];
    __builtin_memset(command, 0, sizeof(command));
    bpf_get_current_comm(command, sizeof(command));
    struct task_struct* task = (struct task_struct*)bpf_get_current_task();

    bpf_printk("sched_process_exit: Kernel id %d, pid %d, tid %d, command: %s", id, pid, tgid, command);

    if (targ_pid && pid != targ_pid)
        return 0;
}


// Attach to the USDT probe mem__pool__gc__end
SEC("usdt")
int BPF_USDT(handle_gc_end, uintptr_t* manager, int manager_len, uintptr_t* pool, int pool_len, __u64 init_size, __u64 used, __u64 committed,  __u64 max_size)
{
    // https://github.com/openjdk/jdk/blob/master/src/hotspot/share/services/memoryManager.cpp#L274
    // Inspired by https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/progs/test_usdt.c
    struct mem_pool_gc_end_event *e;
    e = bpf_ringbuf_reserve(&ringbuf, sizeof(*e), 0);
    if (!e)
        return 0;

    e->ts  = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    __builtin_memset(e->manager, 0, sizeof(e->manager));
    __builtin_memset(e->pool, 0, sizeof(e->pool));

    if (manager && manager_len > 0) {
        if (bpf_probe_read_str(e->manager, sizeof(e->manager), (void*)manager) < 0) {
            bpf_printk("handle_gc_end: bpf_probe_read_str failed to copy from `manager` %d chars into buffer e->manager with the size %d", manager_len, sizeof(e->manager));
        }
    }

    if (pool && pool_len > 0) {
        if (bpf_probe_read_str(e->pool, sizeof(e->pool), (void*)pool) < 0) {
            bpf_printk("handle_gc_end: bpf_probe_read_str failed to copy from `pool` %d chars into buffer e->pool with the size %d", pool_len, sizeof(e->pool));
        }
    }

    e->init_size = init_size;
    e->used = used;
    e->committed = committed;
    e->max_size = max_size;

    bpf_ringbuf_submit(e, 0);
//    bpf_printk("handle_gc_end: submitted ringbuf value");
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
