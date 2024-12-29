// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/usdt.bpf.h>
#include "hotspot_usdt.h"

const volatile __u64 boot_time_ns = 0;
const volatile pid_t target_userspace_pid = 0;
volatile _Bool has_exited = false;
volatile __s32 exit_code = 0;

// Dummy instance to get skeleton to generate definition for `struct gc_heap_summary_event`
struct gc_heap_summary_event _gc_heap_summary_event = {0};

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

SEC("uprobe")
int BPF_UPROBE(send_gc_heap_summary_event, void* clazz, enum gc_when_type_enum when, struct gc_heap_summary* hs)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    // Thread or Task Group ID
    pid_t tgid = pid_tgid >> 32;
    pid_t pid = (u32)pid_tgid;// & 0xffffffff;

    pid_t userspace_pid = tgid;
    pid_t userspace_tid = pid;

    struct gc_heap_summary_event *e;
    e = bpf_ringbuf_reserve(&ringbuf, sizeof(*e), 0);
    if (!e)
        return 0;

    e->ts  = bpf_ktime_get_ns() + boot_time_ns;
    e->pid = userspace_pid;
    e->tid = userspace_tid;

    __u64 used = 0;
    int ret = bpf_probe_read_user(&used, sizeof(used), &hs->used);
    if (ret != 0) {
        bpf_printk("send_gc_heap_summary_event: bpf_probe_read_user hs failed: %d", ret);
    };
    char command[TASK_COMM_LEN];
    __builtin_memset(command, 0, sizeof(command));
    bpf_get_current_comm(command, sizeof(command));

    if (when == BeforeGC) {
        bpf_printk("send_gc_heap_summary_event: Userspace (PID %d, TID %d), cmd: %s, type BeforeGC [%d], used %d", userspace_pid, userspace_tid, command, when, used);
    }
    else if (when == AfterGC) {
        bpf_printk("send_gc_heap_summary_event: Userspace (PID %d, TID %d), cmd: %s, type AfterGC [%d], used %d", userspace_pid, userspace_tid, command, when, used);
    }
    else if (when == GCWhenEndSentinel) {
         bpf_printk("send_gc_heap_summary_event: Userspace (PID %d, TID %d), cmd: %s, type GCWhenEndSentinel [%d], used %d", userspace_pid, userspace_tid, command, when, used);
    }

    e->gc_when_type = when;
    e->used = used;

    bpf_ringbuf_submit(e, 0);

    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
