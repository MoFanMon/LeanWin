/* SPDX-License-Identifier: MIT. Bounded three-level PE resource tree lookup. */
#include "resource.h"
static uint16_t u16(const uint8_t *p) { return (uint16_t)(p[0] | (uint16_t)p[1] << 8); }
static uint32_t u32(const uint8_t *p) { return u16(p) | (uint32_t)u16(p+2) << 16; }
static bool span(uint32_t size, uint32_t offset, uint64_t length) { return offset <= size && length <= size-offset; }
static uint32_t lookup(const uint8_t *root, uint32_t size, uint32_t offset, const lw_resource_key *key,
                       bool language, uint32_t *target)
{
    if (!span(size, offset, 16)) return 193;
    unsigned count = u16(root+offset+12) + u16(root+offset+14);
    if (count > 4096 || !span(size, offset+16, (uint64_t)count*8)) return 193;
    uint32_t fallback = 0; bool found = false;
    for (unsigned i = 0; i < count; i++) {
        const uint8_t *entry = root+offset+16+i*8;
        uint32_t name = u32(entry), data = u32(entry+4);
        if (language) {
            if (name & 0x80000000U) continue;
            if (!found || name == 0) { fallback = data; found = true; }
            if (name == 0x409) { *target = data; return 0; }
            continue;
        }
        bool matches = false;
        if (!(name & 0x80000000U)) matches = !key->named && name == key->id;
        else if (key->named) {
            uint32_t string = name & 0x7fffffff;
            if (!span(size, string, 2)) return 193;
            unsigned length = u16(root+string);
            if (!span(size, string+2, (uint64_t)length*2)) return 193;
            matches = length == key->length;
            for (unsigned j = 0; matches && j < length; j++) if (u16(root+string+2+j*2) != key->text[j]) matches = false;
        }
        if (matches) { *target = data; return 0; }
    }
    if (language && found) { *target = fallback; return 0; }
    return 1814;
}
uint32_t lw_resource_find(const lw_pe *pe, const uint8_t *image, const lw_resource_key *type,
                           const lw_resource_key *name, lw_resource *out)
{
    uint32_t rva = pe->directories[2][0], size = pe->directories[2][1];
    if (!rva || !size) return 1812;
    if (!span(pe->image_size, rva, size)) return 193;
    const uint8_t *root = image+rva;
    uint32_t type_entry, name_entry, language_entry;
    uint32_t error = lookup(root, size, 0, type, false, &type_entry);
    if (error) return error == 1814 ? 1813 : error;
    if (!(type_entry & 0x80000000U)) return 193;
    error = lookup(root, size, type_entry & 0x7fffffff, name, false, &name_entry);
    if (error) return error;
    if (!(name_entry & 0x80000000U)) return 193;
    error = lookup(root, size, name_entry & 0x7fffffff, NULL, true, &language_entry);
    if (error) return error == 1814 ? 1815 : error;
    if ((language_entry & 0x80000000U) || !span(size, language_entry, 16)) return 193;
    uint32_t data = u32(root+language_entry), length = u32(root+language_entry+4);
    if (!span(pe->image_size, data, length)) return 193;
    *out = (lw_resource){.entry=rva+language_entry,.data=data,.size=length}; return 0;
}
