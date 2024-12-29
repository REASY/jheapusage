/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __HOTSPOT_USDT_H
#define __HOTSPOT_USDT_H

// https://github.com/openjdk/jdk/blob/jdk-21%2B35/src/hotspot/share/gc/shared/gcWhen.hpp#L32-L37
enum gc_when_type_enum {
    BeforeGC,
    AfterGC,
    GCWhenEndSentinel
};

// Use https://godbolt.org/z/dbq9cv7G9 to help to understand the alignment
// https://github.com/openjdk/jdk/blob/jdk-21%2B35/src/hotspot/share/gc/shared/gcHeapSummary.hpp#L76
struct gc_heap_summary {
    __u64 _s1;
    __u64 _s2;
    __u64 _s4;
    __u64 _s5;
    __u64 used;
};

struct gc_heap_summary_event {
    __u64 ts;           // Timestamp
    __u64 pid;          // Userspace process id that hit the probe
    __u64 tid;          // Userspace thread id that hit the probe
    enum gc_when_type_enum gc_when_type;
    __u64 used;
};

#endif /* __HOTSPOT_USDT_H */
