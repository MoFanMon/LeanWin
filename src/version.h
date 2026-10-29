/* SPDX-License-Identifier: MIT */
#ifndef LEANWIN_VERSION_H
#define LEANWIN_VERSION_H
#include <stddef.h>
#include <stdint.h>
/* Explicit guest compatibility profile, independent of the host OS. Manifest
   version lies and feature completeness are not modeled by this prototype. */
#define LW_VERSION_MAJOR 10U
#define LW_VERSION_MINOR 0U
#define LW_VERSION_BUILD 19045U
void lw_version_info(uint8_t *, size_t);
uint32_t lw_version_verify(const uint8_t *, uint32_t types, uint64_t conditions);
#endif
