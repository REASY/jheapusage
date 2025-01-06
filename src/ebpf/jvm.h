/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __JVM_H
#define __JVM_H

#define MAX_STR_LEN 64

static __always_inline __u32 extract_tgid(__u64 pid_tgid)
{
	return (__u32)(pid_tgid >> 32);
}
static __always_inline __u32 extract_pid(__u64 pid_tgid)
{
	return (__u32)pid_tgid;
}
static __always_inline __u32 extract_userspace_pid(__u64 pid_tgid)
{
	// That's right, Userspace process id is tgid in kernel-space!
	// https://utcc.utoronto.ca/~cks/space/blog/linux/PidsTgidsAndTasks
	return extract_tgid(pid_tgid);
}
static __always_inline __u32 extract_userspace_tid(__u64 pid_tgid)
{
	return extract_pid(pid_tgid);
}
static __always_inline void extract_userspace_ids(__u64 pid_tgid,
						  pid_t *userspace_pid,
						  pid_t *userspace_tid)
{
	*userspace_pid = extract_tgid(pid_tgid);
	*userspace_tid = extract_pid(pid_tgid);
}

struct mem_pool_gc_event {
	__u64 ts; // Timestamp
	pid_t global_pid; // Global userspace process id that hit the probe
	pid_t global_tid; // Global userspace thread id that hit the probe
	pid_t ns_pid; // Namespaced userspace process id that hit the probe
	pid_t ns_tid; // Namespaced userspace thread id that hit the probe
	__u64 init_size; // Initial size of the memory pool
	__u64 used; // Used memory size
	__u64 committed; // Committed memory size
	__u64 max_size; // Maximum memory size
	unsigned char manager[MAX_STR_LEN]; // Manager identifier
	unsigned char pool[MAX_STR_LEN]; // Pool identifier
	__u8 is_begin; // Indicates whether it is begin GC or end GC event
};

// https://github.com/openjdk/jdk/blob/jdk-21%2B35/src/hotspot/share/gc/shared/gcWhen.hpp#L32-L37
enum gc_when_type_enum { BeforeGC, AfterGC, GCWhenEndSentinel };

// Use https://godbolt.org/z/YcodaPhvY to help to understand memory layout of `GCHeapSummary` C++ class
// https://github.com/openjdk/jdk/blob/jdk-21%2B35/src/hotspot/share/gc/shared/gcHeapSummary.hpp#L76
struct gc_heap_summary {
	__u64 _s1;
	__u64 _s2;
	__u64 _s4;
	__u64 _s5;
	__u64 used;
};

struct gc_heap_summary_event {
	__u64 ts; // Timestamp
	pid_t global_pid; // Global userspace process id that hit the probe
	pid_t global_tid; // Global userspace thread id that hit the probe
	pid_t ns_pid; // Namespaced userspace process id that hit the probe
	pid_t ns_tid; // Namespaced userspace thread id that hit the probe
	enum gc_when_type_enum gc_when_type;
	__u64 used;
};

#endif /* __JVM_H */
