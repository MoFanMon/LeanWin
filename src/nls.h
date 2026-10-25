/* SPDX-License-Identifier: MIT */
#ifndef LEANWIN_NLS_H
#define LEANWIN_NLS_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The guest has one explicit UTF-8 ANSI profile, independent of host locale.
   UTF-16 buffers are Windows little-endian bytes. Inputs and outputs must not
   overlap. NULL output queries size; insufficient output is never modified.
   Return values are Windows error codes, zero on success. */
#define LW_ANSI_CODE_PAGE 65001U
uint32_t lw_utf8_to_utf16(const uint8_t *, size_t, uint8_t *, size_t, bool, size_t *);
uint32_t lw_utf16_to_utf8(const uint8_t *, size_t, uint8_t *, size_t, bool, size_t *);
void lw_utf8_cpinfo(uint8_t *, bool);
#endif
