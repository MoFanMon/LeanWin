/* SPDX-License-Identifier: MIT. Original implementation; no Wine code included. */
#include "pe.h"
#include <inttypes.h>
#include <string.h>

static uint16_t u16(const uint8_t *p) { return (uint16_t)(p[0] | (uint16_t)p[1] << 8); }
static uint32_t u32(const uint8_t *p) { return (uint32_t)u16(p) | (uint32_t)u16(p + 2) << 16; }
static uint64_t u64(const uint8_t *p) { return u32(p) | (uint64_t)u32(p + 4) << 32; }
static bool range(size_t size, size_t off, size_t n) { return off <= size && n <= size - off; }
static int fail(char *e, size_t n, const char *s) { if (n) snprintf(e, n, "%s", s); return -1; }

int lw_pe_parse(lw_pe *p, const uint8_t *data, size_t size, char *e, size_t en)
{
    memset(p, 0, sizeof(*p));
    if (size < 64 || memcmp(data, "MZ", 2)) return fail(e, en, "missing DOS header");
    size_t nt = u32(data + 60);
    if (!range(size, nt, 24) || memcmp(data + nt, "PE\0\0", 4)) return fail(e, en, "invalid PE header");
    p->machine = u16(data + nt + 4);
    p->section_count = u16(data + nt + 6);
    p->characteristics = u16(data + nt + 22);
    size_t optional_size = u16(data + nt + 20), opt = nt + 24;
    if (!range(size, opt, optional_size) || optional_size < 96) return fail(e, en, "truncated optional header");
    uint16_t magic = u16(data + opt);
    p->bits = magic == 0x20b ? 64 : magic == 0x10b ? 32 : 0;
    if (!p->bits || optional_size < (p->bits == 64 ? 112U : 96U)) return fail(e, en, "unsupported optional header");
    if ((p->machine == 0x14c && p->bits != 32) ||
        ((p->machine == 0x8664 || p->machine == 0xaa64) && p->bits != 64)) return fail(e, en, "machine and PE format disagree");
    p->entry = u32(data + opt + 16);
    p->image_base = p->bits == 64 ? u64(data + opt + 24) : u32(data + opt + 28);
    p->image_size = u32(data + opt + 56);
    p->headers_size = u32(data + opt + 60);
    p->subsystem = u16(data + opt + 68);
    if (!p->image_size || p->headers_size > size || p->headers_size > p->image_size ||
        p->entry >= p->image_size) return fail(e, en, "invalid image layout");
    unsigned dir_count = u32(data + opt + (p->bits == 64 ? 108 : 92));
    size_t dir_start = p->bits == 64 ? 112 : 96;
    if (dir_count > 16 || dir_count > (optional_size - dir_start) / 8) return fail(e, en, "invalid directory table");
    for (unsigned i = 0; i < dir_count; i++) {
        p->directories[i][0] = u32(data + opt + dir_start + i * 8);
        p->directories[i][1] = u32(data + opt + dir_start + i * 8 + 4);
    }
    size_t table = opt + optional_size;
    if (!p->section_count || p->section_count > LW_MAX_SECTIONS ||
        !range(size, table, p->section_count * 40)) return fail(e, en, "invalid section table");
    for (unsigned i = 0; i < p->section_count; i++) {
        const uint8_t *s = data + table + i * 40;
        lw_section *out = &p->sections[i];
        out->virtual_size = u32(s + 8); out->rva = u32(s + 12);
        out->raw_size = u32(s + 16); out->raw = u32(s + 20); out->flags = u32(s + 36);
        uint64_t extent = out->virtual_size > out->raw_size ? out->virtual_size : out->raw_size;
        if (!range(size, out->raw, out->raw_size) || (uint64_t)out->rva + extent > p->image_size)
            return fail(e, en, "section lies outside file or image");
        if (out->rva < p->headers_size) return fail(e, en, "section overlaps headers");
        for (unsigned j = 0; j < i; j++) {
            const lw_section *other = &p->sections[j];
            uint64_t other_end = (uint64_t)other->rva + (other->virtual_size > other->raw_size ? other->virtual_size : other->raw_size);
            if (extent && other_end > out->rva && (uint64_t)out->rva + extent > other->rva)
                return fail(e, en, "overlapping sections");
        }
    }
    p->data = data; p->size = size;
    return 0;
}

const uint8_t *lw_pe_span(const lw_pe *p, uint32_t rva, size_t n)
{
    if (rva < p->headers_size && n <= p->headers_size - rva && range(p->size, rva, n)) return p->data + rva;
    for (unsigned i = 0; i < p->section_count; i++) {
        const lw_section *s = &p->sections[i];
        if (rva >= s->rva && (uint64_t)rva - s->rva <= s->raw_size) {
            size_t offset = rva - s->rva;
            if (n <= s->raw_size - offset && range(p->size, (size_t)s->raw + offset, n)) return p->data + s->raw + offset;
        }
    }
    return NULL;
}

static int string_at(const lw_pe *p, uint32_t rva, char *s, size_t cap)
{
    for (size_t i = 0; i < cap; i++) {
        if ((uint64_t)rva + i > UINT32_MAX) return -1;
        const uint8_t *b = lw_pe_span(p, rva + (uint32_t)i, 1);
        if (!b) return -1;
        s[i] = (char)*b;
        if (!*b) return i ? 0 : -1;
    }
    return -1;
}

static int walk_table(const lw_pe *p, unsigned index, bool delayed, lw_import_fn callback, void *ctx, char *e, size_t en)
{
    uint32_t rva = p->directories[index][0], size = p->directories[index][1];
    if (!rva && !size) return 0;
    unsigned stride = delayed ? 32 : 20, word = p->bits / 8;
    if (!rva || size < stride || (uint64_t)rva + size > UINT32_MAX) return fail(e, en, "invalid import directory RVA");
    for (unsigned row = 0; row < 512 && (uint64_t)(row + 1) * stride <= size; row++) {
        const uint8_t *d = lw_pe_span(p, rva + row * stride, stride);
        if (!d) return fail(e, en, "unmapped import descriptor RVA");
        bool zero = true;
        for (unsigned k = 0; k < stride; k++) if (d[k]) zero = false;
        if (zero) return 0;
        lw_import item = {0}; item.delayed = delayed;
        uint32_t name = u32(d + (delayed ? 4 : 12));
        uint32_t thunk = u32(d + (delayed ? 16 : 0));
        uint32_t iat = u32(d + (delayed ? 12 : 16));
        if (delayed && !(u32(d) & 1)) {
            if (name < p->image_base || thunk < p->image_base || iat < p->image_base) return fail(e, en, "invalid delay import VA");
            name -= (uint32_t)p->image_base; thunk -= (uint32_t)p->image_base; iat -= (uint32_t)p->image_base;
        }
        if (!thunk) thunk = iat;
        if (!thunk || !iat || string_at(p, name, item.dll, sizeof(item.dll))) return fail(e, en, "invalid import name RVA");
        bool terminated = false;
        for (unsigned symbol = 0; symbol < 8192; symbol++) {
            uint64_t address = (uint64_t)thunk + (uint64_t)symbol * word;
            uint64_t slot = (uint64_t)iat + (uint64_t)symbol * word;
            if (address > UINT32_MAX || slot > UINT32_MAX) return fail(e, en, "overflow in import RVA");
            const uint8_t *t = lw_pe_span(p, (uint32_t)address, word);
            if (!t || !lw_pe_span(p, (uint32_t)slot, word)) return fail(e, en, "invalid import thunk RVA");
            uint64_t value = word == 8 ? u64(t) : u32(t);
            if (!value) { terminated = true; break; }
            item.iat = (uint32_t)slot;
            item.by_ordinal = (value & (UINT64_C(1) << (p->bits - 1))) != 0;
            item.ordinal = (uint16_t)value;
            if (item.by_ordinal) item.name[0] = '\0';
            else if (value > UINT32_MAX - 2 || string_at(p, (uint32_t)value + 2, item.name, sizeof(item.name)))
                return fail(e, en, "invalid imported symbol RVA");
            if (callback(&item, ctx, e, en)) return -1;
        }
        if (!terminated) return fail(e, en, "unterminated import thunk table");
    }
    return fail(e, en, "unterminated import descriptors");
}

int lw_pe_imports(const lw_pe *p, lw_import_fn callback, void *ctx, char *e, size_t en)
{
    return walk_table(p, 1, false, callback, ctx, e, en) || walk_table(p, 13, true, callback, ctx, e, en) ? -1 : 0;
}

void lw_json_string(FILE *out, const char *s)
{
    fputc('"', out);
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p == '"' || *p == '\\') { fputc('\\', out); fputc(*p, out); }
        else if (*p < 32 || *p >= 127) fprintf(out, "\\u%04x", *p);
        else fputc(*p, out);
    }
    fputc('"', out);
}

const char *lw_pe_arch(const lw_pe *p)
{
    switch (p->machine) { case 0x14c: return "x86"; case 0x8664: return "x86_64"; case 0xaa64: return "arm64"; default: return "unknown"; }
}
typedef struct { FILE *out; char previous[260]; bool delayed, started; } json_context;
static int report_import(const lw_import *item, void *opaque, char *e, size_t en)
{
    (void)e; (void)en;
    json_context *ctx = opaque;
    if (!ctx->started || strcmp(ctx->previous, item->dll) || ctx->delayed != item->delayed) {
        if (ctx->started) fputs("]},", ctx->out);
        fputs("{\"dll\":", ctx->out); lw_json_string(ctx->out, item->dll);
        fprintf(ctx->out, ",\"delayed\":%s,\"symbols\":[", item->delayed ? "true" : "false");
        memcpy(ctx->previous, item->dll, sizeof(ctx->previous)); ctx->delayed = item->delayed; ctx->started = true;
    } else fputc(',', ctx->out);
    if (item->by_ordinal) fprintf(ctx->out, "\"#%u\"", item->ordinal);
    else lw_json_string(ctx->out, item->name);
    return 0;
}
static int validate_import(const lw_import *item, void *ctx, char *e, size_t en)
{
    (void)item; (void)ctx; (void)e; (void)en; return 0;
}
int lw_pe_report(const lw_pe *p, FILE *out, char *e, size_t en)
{
    /* Two bounded in-memory passes avoid temporary files and partial success reports. */
    if (lw_pe_imports(p, validate_import, NULL, e, en)) return -1;
    json_context ctx = {.out = out};
    fprintf(out, "{\"format\":\"%s\",\"architecture\":\"%s\",\"subsystem\":\"%s\",\"managed\":%s,\"imports\":[",
            p->bits == 64 ? "PE32+" : "PE32", lw_pe_arch(p),
            p->subsystem == 2 ? "windows-gui" : p->subsystem == 3 ? "windows-console" : "other",
            p->directories[14][0] ? "true" : "false");
    if (lw_pe_imports(p, report_import, &ctx, e, en)) return -1;
    if (ctx.started) fputs("]}", out);
    fputs("]}\n", out);
    return 0;
}
