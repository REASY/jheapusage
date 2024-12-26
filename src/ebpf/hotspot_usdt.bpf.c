// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/usdt.bpf.h>
#include "hotspot_usdt.h"

const volatile __u64 boot_time_ns = 0;
const volatile pid_t target_userspace_pid = 0;
volatile _Bool has_exited = false;
volatile __s32 exit_code = 0;

// Dummy instance to get skeleton to generate definition for `struct mem_pool_gc_end_event`
struct mem_pool_gc_end_event _mem_pool_gc_end_event = {0};

#define MAX_COMMAND_SIZE 128

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB ring buffer
} ringbuf SEC(".maps");

SEC("tracepoint/sched/sched_process_exit")
int sched_process_exit(struct trace_event_raw_sched_process_template* ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    // Thread or Task Group ID
    pid_t tgid = pid_tgid >> 32;
    pid_t pid = pid_tgid & 0xffffffff;
    // ignore thread exits
    if (pid != tgid)
        return 0;

    // That's right, Userspace process id is tgid in kernel-space!
    // https://utcc.utoronto.ca/~cks/space/blog/linux/PidsTgidsAndTasks
    pid_t userspace_pid = tgid;
    if (target_userspace_pid && userspace_pid != target_userspace_pid)
        return 0;

    char command[TASK_COMM_LEN];
    __builtin_memset(command, 0, sizeof(command));
    bpf_get_current_comm(command, sizeof(command));

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    exit_code = BPF_CORE_READ(task, exit_code)  >> 8;
    has_exited = true;
    bpf_printk("sched_process_exit: Kernel (pid_tgid %ld, tgid %d, pid %d), Userspace PID %d, command: %s, exit_code: %d", pid_tgid, tgid, pid, userspace_pid, command, exit_code);
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

    e->ts  = bpf_ktime_get_ns() + boot_time_ns;
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
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
