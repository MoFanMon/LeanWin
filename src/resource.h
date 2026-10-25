/* SPDX-License-Identifier: MIT */
#ifndef LEANWIN_RESOURCE_H
#define LEANWIN_RESOURCE_H
#include "pe.h"
typedef struct { uint16_t id; const uint16_t *text; size_t length; bool named; } lw_resource_key;
typedef struct { uint32_t entry, data, size; } lw_resource;
uint32_t lw_resource_find(const lw_pe *, const uint8_t *, const lw_resource_key *, const lw_resource_key *, lw_resource *);
#endif
