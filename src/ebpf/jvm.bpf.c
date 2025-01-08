// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/usdt.bpf.h>
#include "jvm.h"

// Input parameters to eBPF programs
const volatile __u64 st_dev = 0;
const volatile __u64 st_ino = 0;
const volatile __u64 boot_time_ns = 0;
const volatile pid_t target_userspace_pid = 0;

volatile _Bool has_exited = false;
volatile __s32 exit_code = 0;

// Dummy instance to get skeleton to generate definition for exported C structs
// to Rust
struct mem_pool_gc_event _mem_pool_gc_event = { 0 };
struct gc_heap_summary_event _gc_heap_summary_event = { 0 };

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 * 1024 * 1024); // 4MB ring buffer
} rg_hotspot_mem_pool_gc SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 * 1024 * 1024); // 4MB ring buffer
} rg_send_gc_heap_summary_event SEC(".maps");

SEC("tracepoint/sched/sched_process_exit")
int sched_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	pid_t userspace_pid, userspace_tid;
	extract_userspace_ids(pid_tgid, &userspace_pid, &userspace_tid);
	// ignore thread exits
	if (userspace_pid != userspace_tid)
		return 0;
	// ignore exits of processes that we're not interested in
	if (target_userspace_pid && userspace_pid != target_userspace_pid)
		return 0;

	char command[TASK_COMM_LEN];
	__builtin_memset(command, 0, sizeof(command));
	bpf_get_current_comm(command, sizeof(command));

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	exit_code = BPF_CORE_READ(task, exit_code) >> 8;
	has_exited = true;
	bpf_printk(
		"sched_process_exit: Userspace (PID %d, TID %d), command: %s, "
		"exit_code: %d",
		userspace_pid, userspace_tid, command, exit_code);
}

SEC("uprobe")
int BPF_UPROBE(report_gc_heap_summary, void *clazz, enum gc_when_type_enum when,
	       struct gc_heap_summary *hs)
{
	char command[TASK_COMM_LEN];
	__builtin_memset(command, 0, sizeof(command));
	bpf_get_current_comm(command, sizeof(command));

	// Ignore event from `G1 Main Marker`, it is not true GC event
	// https://github.com/openjdk/jdk/blob/jdk-11%2B28/src/hotspot/share/gc/g1/g1ConcurrentMarkThread.cpp#L87
	const char g1_main_maker_thread_name[] = "G1 Main Marker";
	if (__builtin_memcmp(command, g1_main_maker_thread_name,
			     sizeof(g1_main_maker_thread_name)) == 0) {
		bpf_printk("report_gc_heap_summary: Skipping event from %s",
			   command);
		return 0;
	}

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	pid_t userspace_pid, userspace_tid;
	extract_userspace_ids(pid_tgid, &userspace_pid, &userspace_tid);

	struct gc_heap_summary_event *e;
	e = bpf_ringbuf_reserve(&rg_send_gc_heap_summary_event, sizeof(*e), 0);
	if (!e)
		return 0;

	struct bpf_pidns_info ns = {};
	bpf_get_ns_current_pid_tgid(st_dev, st_ino, &ns,
				    sizeof(struct bpf_pidns_info));

	e->ts = bpf_ktime_get_ns() + boot_time_ns;
	e->global_pid = userspace_pid;
	e->global_tid = userspace_tid;
	e->ns_pid = ns.tgid;
	e->ns_tid = ns.pid;

	__u64 used = 0;
	int ret = bpf_probe_read_user(&used, sizeof(used), &hs->used);
	if (ret != 0) {
		bpf_printk(
			"report_gc_heap_summary: bpf_probe_read_user hs failed: %d",
			ret);
	};

	if (when == BeforeGC) {
		bpf_printk(
			"report_gc_heap_summary: Userspace (PID %d, TID %d), cmd: "
			"%s, type BeforeGC [%d], used %d",
			userspace_pid, userspace_tid, command, when, used);
	} else if (when == AfterGC) {
		bpf_printk(
			"report_gc_heap_summary: Userspace (PID %d, TID %d), cmd: "
			"%s, type AfterGC [%d], used %d",
			userspace_pid, userspace_tid, command, when, used);
	} else if (when == GCWhenEndSentinel) {
		bpf_printk(
			"report_gc_heap_summary: Userspace (PID %d, TID %d), cmd: "
			"%s, type GCWhenEndSentinel [%d], used %d",
			userspace_pid, userspace_tid, command, when, used);
	}

	e->gc_when_type = when;
	e->used = used;

	bpf_ringbuf_submit(e, 0);

	return 0;
}

SEC("usdt")
int BPF_USDT(hotspot_mem_pool_gc_begin, uintptr_t *manager, int manager_len,
	     uintptr_t *pool, int pool_len, __u64 init_size, __u64 used,
	     __u64 committed, __u64 max_size)
{
	// https://github.com/openjdk/jdk/blob/jdk-21%2B35/src/hotspot/share/services/memoryManager.cpp#L230

	struct mem_pool_gc_event *e;
	e = bpf_ringbuf_reserve(&rg_hotspot_mem_pool_gc, sizeof(*e), 0);
	if (!e)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	pid_t userspace_pid, userspace_tid;
	extract_userspace_ids(pid_tgid, &userspace_pid, &userspace_tid);

	struct bpf_pidns_info ns = {};
	bpf_get_ns_current_pid_tgid(st_dev, st_ino, &ns,
				    sizeof(struct bpf_pidns_info));

	e->ts = bpf_ktime_get_ns() + boot_time_ns;
	e->global_pid = userspace_pid;
	e->global_tid = userspace_tid;
	e->ns_pid = ns.tgid;
	e->ns_tid = ns.pid;

	__builtin_memset(e->manager, 0, sizeof(e->manager));
	__builtin_memset(e->pool, 0, sizeof(e->pool));
	if (manager && manager_len > 0) {
		if (bpf_probe_read_str(e->manager, sizeof(e->manager),
				       (void *)manager) < 0) {
			bpf_printk(
				"hotspot_mem_pool_gc_begin: bpf_probe_read_str failed to copy from "
				"`manager` %d chars into buffer e->manager with the size %d",
				manager_len, sizeof(e->manager));
		}
	}
	if (pool && pool_len > 0) {
		if (bpf_probe_read_str(e->pool, sizeof(e->pool), (void *)pool) <
		    0) {
			bpf_printk(
				"hotspot_mem_pool_gc_begin: bpf_probe_read_str failed to copy "
				"from `pool` %d chars into buffer e->pool with the size %d",
				pool_len, sizeof(e->pool));
		}
	}

	e->init_size = init_size;
	e->used = used;
	e->committed = committed;
	e->max_size = max_size;
	e->is_begin = 1;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("usdt")
int BPF_USDT(hotspot_mem_pool_gc_end, uintptr_t *manager, int manager_len,
	     uintptr_t *pool, int pool_len, __u64 init_size, __u64 used,
	     __u64 committed, __u64 max_size)
{
	// https://github.com/openjdk/jdk/blob/jdk-21%2B35/src/hotspot/share/services/memoryManager.cpp#L263

	struct mem_pool_gc_event *e;
	e = bpf_ringbuf_reserve(&rg_hotspot_mem_pool_gc, sizeof(*e), 0);
	if (!e)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	pid_t userspace_pid, userspace_tid;
	extract_userspace_ids(pid_tgid, &userspace_pid, &userspace_tid);

	struct bpf_pidns_info ns = {};
	bpf_get_ns_current_pid_tgid(st_dev, st_ino, &ns,
				    sizeof(struct bpf_pidns_info));

	e->ts = bpf_ktime_get_ns() + boot_time_ns;
	e->global_pid = userspace_pid;
	e->global_tid = userspace_tid;
	e->ns_pid = ns.tgid;
	e->ns_tid = ns.pid;

	__builtin_memset(e->manager, 0, sizeof(e->manager));
	__builtin_memset(e->pool, 0, sizeof(e->pool));
	if (manager && manager_len > 0) {
		if (bpf_probe_read_str(e->manager, sizeof(e->manager),
				       (void *)manager) < 0) {
			bpf_printk(
				"hotspot_mem_pool_gc_end: bpf_probe_read_str failed to copy from "
				"`manager` %d chars into buffer e->manager with the size %d",
				manager_len, sizeof(e->manager));
		}
	}
	if (pool && pool_len > 0) {
		if (bpf_probe_read_str(e->pool, sizeof(e->pool), (void *)pool) <
		    0) {
			bpf_printk(
				"hotspot_mem_pool_gc_end: bpf_probe_read_str failed to copy "
				"from `pool` %d chars into buffer e->pool with the size %d",
				pool_len, sizeof(e->pool));
		}
	}

	e->init_size = init_size;
	e->used = used;
	e->committed = committed;
	e->max_size = max_size;
	e->is_begin = 0;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
