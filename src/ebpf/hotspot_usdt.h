/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __HOTSPOT_USDT_H
#define __HOTSPOT_USDT_H

#define MAX_STR_LEN 64

struct mem_pool_gc_end_event {
    __u64 ts;           // Timestamp
    __u64 pid;          // PID that hit the probe
    __u64 init_size;    // Initial size of the memory pool
    __u64 used;         // Used memory size
    __u64 committed;    // Committed memory size
    __u64 max_size;     // Maximum memory size
    unsigned char manager[MAX_STR_LEN];   // Manager identifier
    unsigned char pool[MAX_STR_LEN];      // Pool identifier
};

#endif /* __HOTSPOT_USDT_H */
