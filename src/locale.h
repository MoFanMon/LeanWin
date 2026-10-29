/* SPDX-License-Identifier: MIT */
#ifndef LEANWIN_LOCALE_H
#define LEANWIN_LOCALE_H
#include <stdint.h>
#define LW_DEFAULT_LOCALE 0x409U
/* Explicit supported locale data, independent of the host's locale database. */
uint32_t lw_locale_resolve(uint32_t);
uint32_t lw_locale_info(uint32_t id, uint32_t type, const char **text, uint32_t *number);
#endif
