/* SPDX-License-Identifier: MIT. Original bounded UTF-8 / UTF-16 conversions. */
#include "nls.h"
#include <string.h>

static uint16_t u16(const uint8_t *p) { return (uint16_t)(p[0] | (uint16_t)p[1] << 8); }
static void put16(uint8_t *p, uint32_t c) { p[0] = (uint8_t)c; p[1] = (uint8_t)(c >> 8); }

static uint32_t next_utf8(const uint8_t *p, size_t n, size_t *consumed, bool *valid)
{
    uint32_t c = p[0]; unsigned width;
    *consumed = 1; *valid = true;
    if (c < 0x80) return c;
    if (c >= 0xc2 && c <= 0xdf) { width = 2; c &= 0x1f; }
    else if (c >= 0xe0 && c <= 0xef) { width = 3; c &= 0x0f; }
    else if (c >= 0xf0 && c <= 0xf4) { width = 4; c &= 7; }
    else { *valid = false; return 0xfffd; }
    for (unsigned i = 1; i < width; i++) {
        if (i >= n || p[i] < 0x80 || p[i] > 0xbf ||
            (i == 1 && ((p[0] == 0xe0 && p[i] < 0xa0) || (p[0] == 0xed && p[i] > 0x9f) ||
                        (p[0] == 0xf0 && p[i] < 0x90) || (p[0] == 0xf4 && p[i] > 0x8f)))) {
            /* Replace the maximal valid prefix, leaving the first byte that
               cannot continue it for the next decoding step. */
            *consumed = i; *valid = false; return 0xfffd;
        }
        c = (c << 6) | (p[i] & 63);
    }
    *consumed = width;
    return c;
}
static uint32_t next_utf16(const uint8_t *p, size_t n, size_t *consumed, bool *valid)
{
    uint32_t c = u16(p);
    *consumed = 1; *valid = true;
    if (c < 0xd800 || c > 0xdfff) return c;
    if (c <= 0xdbff && n > 1) {
        uint32_t low = u16(p + 2);
        if (low >= 0xdc00 && low <= 0xdfff) {
            *consumed = 2; return 0x10000 + ((c - 0xd800) << 10) + low - 0xdc00;
        }
    }
    *valid = false; return 0xfffd;
}
uint32_t lw_utf8_to_utf16(const uint8_t *source, size_t size, uint8_t *out,
                        size_t capacity, bool strict, size_t *count)
{
    size_t required = 0;
    for (size_t i = 0; i < size; ) {
        size_t used; bool valid;
        uint32_t c = next_utf8(source + i, size - i, &used, &valid);
        if (!valid && strict) return 1113;
        i += used; required += c > 0xffff ? 2 : 1;
    }
    *count = required;
    if (!out) return 0;
    if (capacity < required) return 122;
    size_t written = 0;
    for (size_t i = 0; i < size; ) {
        size_t used; bool valid;
        uint32_t c = next_utf8(source + i, size - i, &used, &valid);
        i += used;
        if (c > 0xffff) {
            c -= 0x10000;
            put16(out + written++ * 2, 0xd800 + (c >> 10));
            put16(out + written++ * 2, 0xdc00 + (c & 1023));
        } else put16(out + written++ * 2, c);
    }
    return 0;
}
uint32_t lw_utf16_to_utf8(const uint8_t *source, size_t size, uint8_t *out,
                        size_t capacity, bool strict, size_t *count)
{
    size_t required = 0;
    for (size_t i = 0; i < size; ) {
        size_t used; bool valid;
        uint32_t c = next_utf16(source + i * 2, size - i, &used, &valid);
        if (!valid && strict) return 1113;
        i += used; required += c < 0x80 ? 1 : c < 0x800 ? 2 : c < 0x10000 ? 3 : 4;
    }
    *count = required;
    if (!out) return 0;
    if (capacity < required) return 122;
    size_t written = 0;
    for (size_t i = 0; i < size; ) {
        size_t used; bool valid;
        uint32_t c = next_utf16(source + i * 2, size - i, &used, &valid);
        i += used;
        unsigned width = c < 0x80 ? 1 : c < 0x800 ? 2 : c < 0x10000 ? 3 : 4;
        if (width == 1) out[written++] = (uint8_t)c;
        else {
            out[written++] = (uint8_t)((width == 2 ? 0xc0 : width == 3 ? 0xe0 : 0xf0) | (c >> (6 * (width - 1))));
            for (unsigned j = width - 1; j; j--) out[written++] = (uint8_t)(0x80 | ((c >> (j * 6 - 6)) & 63));
        }
    }
    return 0;
}
void lw_utf8_cpinfo(uint8_t *out, bool extended)
{
    memset(out, 0, extended ? 544 : 20);
    out[0] = 4; out[4] = '?';
    if (extended) {
        put16(out + 18, 0xfffd);
        out[20] = (uint8_t)LW_ANSI_CODE_PAGE; out[21] = (uint8_t)(LW_ANSI_CODE_PAGE >> 8);
        const char *name = "Unicode (UTF-8)";
        for (size_t i = 0; name[i]; i++) put16(out + 24 + i * 2, (unsigned char)name[i]);
    }
}
