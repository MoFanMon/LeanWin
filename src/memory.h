/* SPDX-License-Identifier: MIT */
#ifndef LEANWIN_MEMORY_H
#define LEANWIN_MEMORY_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef struct lw_memory lw_memory;
typedef struct {
    uint64_t base, allocation_base, size;
    uint32_t allocation_protect, state, protect, type;
} lw_memory_info;
enum { LW_READ = 1, LW_WRITE = 2, LW_EXECUTE = 4 };
#define LW_PROCESS_HEAP UINT64_C(0x8000)
lw_memory *lw_memory_create(void);
void lw_memory_destroy(lw_memory *);
bool lw_memory_map(lw_memory *, uint64_t, size_t, uint8_t *, uint32_t, uint32_t);
void lw_memory_unmap_borrowed(lw_memory *, uint64_t);
uint8_t *lw_memory_access(lw_memory *, uint64_t, size_t, unsigned);
uint64_t lw_virtual_alloc(lw_memory *, uint64_t, uint64_t, uint32_t, uint32_t, uint32_t *);
bool lw_virtual_free(lw_memory *, uint64_t, uint64_t, uint32_t, uint32_t *);
bool lw_virtual_protect(lw_memory *, uint64_t, uint64_t, uint32_t, uint32_t *, uint32_t *);
bool lw_virtual_query(lw_memory *, uint64_t, lw_memory_info *);
uint64_t lw_heap_create(lw_memory *, uint64_t, uint64_t, uint32_t *);
bool lw_heap_destroy(lw_memory *, uint64_t, uint32_t *);
uint64_t lw_heap_alloc(lw_memory *, uint64_t, uint64_t, uint32_t, uint32_t *);
bool lw_heap_free(lw_memory *, uint64_t, uint64_t, uint32_t *);
size_t lw_memory_size(const lw_memory *);
#endif
