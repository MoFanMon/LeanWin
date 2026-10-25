/* SPDX-License-Identifier: MIT */
#ifndef LEANWIN_PE_H
#define LEANWIN_PE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define LW_MAX_SECTIONS 96
typedef struct { uint32_t rva, virtual_size, raw, raw_size, flags; } lw_section;
typedef struct {
    const uint8_t *data;
    size_t size;
    uint16_t machine, subsystem, characteristics;
    unsigned bits, section_count;
    uint64_t image_base;
    uint32_t image_size, headers_size, entry, directories[16][2];
    lw_section sections[LW_MAX_SECTIONS];
} lw_pe;
typedef struct {
    char dll[260], name[260];
    uint16_t ordinal;
    uint32_t iat;
    bool delayed, by_ordinal;
} lw_import;
typedef int (*lw_import_fn)(const lw_import *, void *, char *, size_t);

int lw_pe_parse(lw_pe *, const uint8_t *, size_t, char *, size_t);
const uint8_t *lw_pe_span(const lw_pe *, uint32_t, size_t);
int lw_pe_imports(const lw_pe *, lw_import_fn, void *, char *, size_t);
void lw_json_string(FILE *, const char *);
const char *lw_pe_arch(const lw_pe *);
int lw_pe_report(const lw_pe *, FILE *, char *, size_t);
#endif
