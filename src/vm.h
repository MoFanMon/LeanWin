/* SPDX-License-Identifier: MIT */
#ifndef LEANWIN_VM_H
#define LEANWIN_VM_H
#include "pe.h"
typedef struct {
    uint32_t guest_exit_code;
    uint64_t instructions, api_calls;
    double elapsed_ms;
    size_t guest_memory_bytes;
    uint64_t host_peak_rss_bytes;
} lw_result;
int lw_run(const lw_pe *, const char *, uint64_t, lw_result *, char *, size_t);
void lw_capabilities(FILE *);
#endif
