/* SPDX-License-Identifier: MIT */
#ifndef LEANWIN_FPU_H
#define LEANWIN_FPU_H
#include <stdbool.h>
#include <stdint.h>
typedef struct {
    uint16_t control,status,tags,code_selector,data_selector,opcode;
    uint32_t instruction_pointer,data_pointer;
} lw_fpu;
void lw_fpu_init(lw_fpu *);
void lw_fpu_control(lw_fpu *, uint16_t);
void lw_fpu_clear(lw_fpu *);
void lw_fpu_load_environment(lw_fpu *, const uint8_t *, bool short_format);
void lw_fpu_store_environment(lw_fpu *, uint8_t *, bool short_format);
#endif
