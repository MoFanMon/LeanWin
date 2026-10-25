/* SPDX-License-Identifier: MIT. Guest pages and heaps never expose host pointers. */
#include "memory.h"
#include <stdlib.h>
#include <string.h>

#define PAGE 4096U
#define REGIONS 256U
#define BLOCKS 4096U
#define LIMIT (64U * 1024U * 1024U)
#define ARENA_START UINT64_C(0x10000000)
#define ARENA_END UINT64_C(0x60000000)
typedef struct {
    uint64_t base; size_t size;
    uint8_t *data; uint32_t *protection;
    uint32_t initial, type;
    unsigned heap; bool owned, used;
} region;
typedef struct { uint64_t base; size_t size; unsigned heap; bool used, busy; } block;
typedef struct { bool used; size_t maximum, allocated; } heap;
struct lw_memory { region regions[REGIONS]; block blocks[BLOCKS]; heap heaps[16]; size_t private_size; };
static bool protection_valid(uint32_t p) { return p == 1 || p == 2 || p == 4 || p == 0x10 || p == 0x20 || p == 0x40; }
static unsigned permissions(uint32_t p)
{
    switch (p) { case 2: return LW_READ; case 4: return LW_READ | LW_WRITE;
        case 0x10: return LW_EXECUTE; case 0x20: return LW_READ | LW_EXECUTE;
        case 0x40: return LW_READ | LW_WRITE | LW_EXECUTE; default: return 0; }
}
static region *containing(lw_memory *m, uint64_t base, uint64_t size)
{
    for (unsigned i = 0; i < REGIONS; i++) {
        region *r = &m->regions[i];
        if (r->used && base >= r->base && base - r->base < r->size && size <= r->size - (base - r->base)) return r;
    }
    return NULL;
}
static region *add_region(lw_memory *m, uint64_t base, size_t size, uint8_t *data,
                          bool owned, uint32_t protect, uint32_t type)
{
    if (!size || base > UINT64_MAX - size) return NULL;
    region *slot = NULL;
    for (unsigned i = 0; i < REGIONS; i++) {
        region *r = &m->regions[i];
        if (!r->used) { if (!slot) slot = r; continue; }
        if (base < r->base + r->size && r->base < base + size) return NULL;
    }
    if (!slot) return NULL;
    size_t pages = (size + PAGE - 1) / PAGE;
    uint32_t *p = calloc(pages, sizeof(*p));
    if (!p) return NULL;
    for (size_t i = 0; i < pages; i++) p[i] = protect;
    *slot = (region){.base=base,.size=size,.data=data,.protection=p,.initial=protect,.type=type,.owned=owned,.used=true};
    return slot;
}
static void release(lw_memory *m, region *r)
{
    if (r->owned) { free(r->data); m->private_size -= r->size; }
    free(r->protection); memset(r, 0, sizeof(*r));
}
static uint64_t free_address(lw_memory *m, size_t size)
{
    uint64_t base = ARENA_START;
    while (base + size <= ARENA_END) {
        uint64_t next = base;
        for (unsigned i = 0; i < REGIONS; i++) {
            region *r = &m->regions[i];
            if (r->used && base < r->base + r->size && r->base < base + size)
                if (r->base + r->size > next) next = r->base + r->size;
        }
        if (next == base) return base;
        base = (next + 65535) & ~UINT64_C(65535);
    }
    return 0;
}
lw_memory *lw_memory_create(void)
{
    lw_memory *m = calloc(1, sizeof(*m));
    if (m) m->heaps[0].used = true;
    return m;
}
void lw_memory_destroy(lw_memory *m)
{
    if (!m) return;
    for (unsigned i = 0; i < REGIONS; i++) if (m->regions[i].used) release(m, &m->regions[i]);
    free(m);
}
bool lw_memory_map(lw_memory *m, uint64_t base, size_t size, uint8_t *data, uint32_t protect, uint32_t type)
{
    return add_region(m, base, size, data, false, protect, type) != NULL;
}
void lw_memory_unmap_borrowed(lw_memory *m, uint64_t base)
{
    for (unsigned i = 0; i < REGIONS; i++) if (m->regions[i].used && !m->regions[i].owned && m->regions[i].base == base) {
        release(m, &m->regions[i]); return;
    }
}
uint8_t *lw_memory_access(lw_memory *m, uint64_t address, size_t size, unsigned access)
{
    region *r = containing(m, address, size);
    if (!r) return NULL;
    size_t offset = (size_t)(address - r->base);
    if (size) for (size_t page = offset / PAGE; page <= (offset + size - 1) / PAGE; page++)
        if ((permissions(r->protection[page]) & access) != access) return NULL;
    return r->data + offset;
}
uint64_t lw_virtual_alloc(lw_memory *m, uint64_t address, uint64_t size, uint32_t flags,
                          uint32_t protect, uint32_t *error)
{
    if (!size || size > LIMIT || !protection_valid(protect) ||
        (flags != 0x1000 && flags != 0x2000 && flags != 0x3000)) { *error = 87; return 0; }
    uint64_t base = address & ~(uint64_t)((flags & 0x2000) ? 65535 : PAGE - 1);
    uint64_t length = (size + (address - base) + PAGE - 1) & ~(uint64_t)(PAGE - 1);
    if (length > LIMIT || (address && base > UINT64_MAX - length)) { *error = 87; return 0; }
    if (address && !(flags & 0x2000)) {
        region *r = containing(m, base, length);
        if (!r || !r->owned || r->heap) { *error = 487; return 0; }
        for (size_t i = (size_t)(base - r->base) / PAGE; i < (base - r->base + length) / PAGE; i++) r->protection[i] = protect;
        return base;
    }
    if (m->private_size + length > LIMIT) { *error = 8; return 0; }
    if (!address) base = free_address(m, (size_t)length);
    if (!base) { *error = 8; return 0; }
    uint8_t *data = calloc(1, (size_t)length);
    if (!data) { *error = 8; return 0; }
    region *r = add_region(m, base, (size_t)length, data, true, flags & 0x1000 ? protect : 0, 0x20000);
    if (!r) { free(data); *error = 487; return 0; }
    r->initial = protect; m->private_size += (size_t)length;
    return base;
}
bool lw_virtual_free(lw_memory *m, uint64_t address, uint64_t size, uint32_t flags, uint32_t *error)
{
    region *r = containing(m, address, 1);
    if (!r || !r->owned || r->heap) { *error = 487; return false; }
    if (flags == 0x8000) {
        if (size || address != r->base) { *error = 87; return false; }
        release(m, r); return true;
    }
    if (flags != 0x4000 || size > LIMIT) { *error = 87; return false; }
    uint64_t start = address & ~(uint64_t)(PAGE - 1);
    if (!size) { if (address != r->base) { *error = 87; return false; } size = r->size; }
    uint64_t length = (size + address - start + PAGE - 1) & ~(uint64_t)(PAGE - 1);
    if (start < r->base || length > r->size - (start - r->base)) { *error = 487; return false; }
    memset(r->data + (start - r->base), 0, (size_t)length);
    for (size_t i = (start - r->base) / PAGE; i < (start - r->base + length) / PAGE; i++) r->protection[i] = 0;
    return true;
}
bool lw_virtual_protect(lw_memory *m, uint64_t address, uint64_t size, uint32_t protect, uint32_t *old, uint32_t *error)
{
    if (!size || size > LIMIT || !protection_valid(protect)) { *error = 87; return false; }
    uint64_t base = address & ~(uint64_t)(PAGE - 1), length = (size + address - base + PAGE - 1) & ~(uint64_t)(PAGE - 1);
    region *r = containing(m, base, length);
    if (!r) { *error = 487; return false; }
    size_t first = (size_t)(base - r->base) / PAGE, last = first + (size_t)length / PAGE;
    for (size_t i = first; i < last; i++) if (!r->protection[i]) { *error = 487; return false; }
    *old = r->protection[first];
    for (size_t i = first; i < last; i++) r->protection[i] = protect;
    return true;
}
bool lw_virtual_query(lw_memory *m, uint64_t address, lw_memory_info *info)
{
    uint64_t base = address & ~(uint64_t)(PAGE - 1);
    region *r = containing(m, address, 1);
    if (!r) {
        uint64_t end = UINT64_C(0x800000000000);
        if (base >= end) return false;
        for (unsigned i = 0; i < REGIONS; i++) if (m->regions[i].used && m->regions[i].base > base && m->regions[i].base < end) end = m->regions[i].base;
        *info = (lw_memory_info){.base=base,.size=end-base,.state=0x10000}; return true;
    }
    size_t page = (size_t)(address - r->base) / PAGE, first = page, last = page + 1;
    uint32_t protect = r->protection[page];
    while (first && r->protection[first-1] == protect) first--;
    while (last * PAGE < r->size && r->protection[last] == protect) last++;
    *info = (lw_memory_info){.base=r->base+first*PAGE,.allocation_base=r->base,.size=last*PAGE-first*PAGE,
                            .allocation_protect=r->initial,.state=protect?0x1000:0x2000,.protect=protect,.type=r->type};
    return true;
}
static heap *get_heap(lw_memory *m, uint64_t handle)
{
    if (handle < LW_PROCESS_HEAP || handle >= LW_PROCESS_HEAP + 16) return NULL;
    heap *h = &m->heaps[handle - LW_PROCESS_HEAP]; return h->used ? h : NULL;
}
uint64_t lw_heap_create(lw_memory *m, uint64_t initial, uint64_t maximum, uint32_t *error)
{
    if (initial > LIMIT || maximum > LIMIT || (maximum && initial > maximum)) { *error = 87; return 0; }
    for (unsigned i = 1; i < 16; i++) if (!m->heaps[i].used) {
        m->heaps[i] = (heap){.used=true,.maximum=(size_t)maximum}; return LW_PROCESS_HEAP + i;
    }
    *error = 8; return 0;
}
bool lw_heap_destroy(lw_memory *m, uint64_t handle, uint32_t *error)
{
    heap *h = get_heap(m, handle);
    if (!h || handle == LW_PROCESS_HEAP) { *error = 6; return false; }
    unsigned index = (unsigned)(handle - LW_PROCESS_HEAP) + 1;
    for (unsigned i = 0; i < REGIONS; i++) if (m->regions[i].used && m->regions[i].heap == index) release(m, &m->regions[i]);
    for (unsigned i = 0; i < BLOCKS; i++) if (m->blocks[i].used && m->blocks[i].heap == index) m->blocks[i].used = false;
    memset(h, 0, sizeof(*h)); return true;
}
uint64_t lw_heap_alloc(lw_memory *m, uint64_t handle, uint64_t size, uint32_t flags, uint32_t *error)
{
    heap *h = get_heap(m, handle);
    if (!h) { *error = 6; return 0; }
    if (flags & ~9U) { *error = 50; return 0; }
    if (size > LIMIT) { *error = 8; return 0; }
    size_t amount = ((size_t)(size ? size : 1) + 15) & ~(size_t)15;
    if (h->maximum && amount > h->maximum - h->allocated) { *error = 8; return 0; }
    unsigned index = (unsigned)(handle - LW_PROCESS_HEAP) + 1;
    block *free_slot = NULL, *candidate = NULL;
    for (unsigned i = 0; i < BLOCKS; i++) {
        block *b = &m->blocks[i];
        if (!b->used) { if (!free_slot) free_slot = b; }
        else if (!b->busy && b->heap == index && b->size >= amount && !candidate) candidate = b;
    }
    if (!free_slot) { *error = 8; return 0; }
    if (!candidate) {
        size_t chunk = (amount + 65535) & ~(size_t)65535;
        uint64_t base = lw_virtual_alloc(m, 0, chunk, 0x3000, 4, error);
        if (!base) return 0;
        containing(m, base, chunk)->heap = index;
        *free_slot = (block){.base=base,.size=chunk,.heap=index,.used=true};
        candidate = free_slot; free_slot = NULL;
        for (unsigned i = 0; i < BLOCKS; i++) if (!m->blocks[i].used) { free_slot = &m->blocks[i]; break; }
    }
    if (candidate->size > amount && free_slot) {
        *free_slot = (block){.base=candidate->base+amount,.size=candidate->size-amount,.heap=index,.used=true};
        candidate->size = amount;
    }
    uint8_t *data = lw_memory_access(m, candidate->base, candidate->size, LW_WRITE);
    if (!data) { *error = 998; return 0; }
    if (h->maximum && candidate->size > h->maximum - h->allocated) { *error = 8; return 0; }
    candidate->busy = true; h->allocated += candidate->size;
    if (flags & 8) memset(data, 0, candidate->size);
    return candidate->base;
}
bool lw_heap_free(lw_memory *m, uint64_t handle, uint64_t address, uint32_t *error)
{
    heap *h = get_heap(m, handle);
    if (!h) { *error = 6; return false; }
    if (!address) return true;
    unsigned index = (unsigned)(handle - LW_PROCESS_HEAP) + 1;
    for (unsigned i = 0; i < BLOCKS; i++) {
        block *b = &m->blocks[i];
        if (!b->used || !b->busy || b->heap != index || b->base != address) continue;
        h->allocated -= b->size; b->busy = false;
        /* Coalesce only inside the same 64 KiB allocation; VirtualQuery retains
           the allocation base even when adjacent heap chunks happen to touch. */
        region *owner = containing(m, b->base, b->size);
        bool changed;
        do {
            changed = false;
            for (unsigned j = 0; j < BLOCKS; j++) {
                block *other = &m->blocks[j];
                if (other == b || !other->used || other->busy || other->heap != index || containing(m, other->base, other->size) != owner) continue;
                if (b->base + b->size == other->base) { b->size += other->size; other->used = false; changed = true; }
                else if (other->base + other->size == b->base) { b->base = other->base; b->size += other->size; other->used = false; changed = true; }
            }
        } while (changed);
        return true;
    }
    *error = 87; return false;
}
size_t lw_memory_size(const lw_memory *m)
{
    size_t total = 0;
    if (m) for (unsigned i = 0; i < REGIONS; i++) if (m->regions[i].used) total += m->regions[i].size;
    return total;
}
