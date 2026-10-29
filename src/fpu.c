/* SPDX-License-Identifier: MIT. Guest state never changes the host FPU mode. */
#include "fpu.h"
#include <string.h>
static uint16_t u16(const uint8_t *p) { return (uint16_t)(p[0]|(uint16_t)p[1]<<8); }
static uint32_t u32(const uint8_t *p) { return u16(p)|(uint32_t)u16(p+2)<<16; }
static void put16(uint8_t *p, uint16_t n) { p[0]=(uint8_t)n; p[1]=(uint8_t)(n>>8); }
static void put32(uint8_t *p, uint32_t n) { put16(p,(uint16_t)n); put16(p+2,(uint16_t)(n>>16)); }
void lw_fpu_init(lw_fpu *f) { memset(f,0,sizeof(*f)); f->control=0x037f; f->tags=0xffff; }
void lw_fpu_control(lw_fpu *f, uint16_t word)
{
    f->control=(word&0x1f3f)|0x40;
    if (f->status & (uint16_t)(~f->control) & 0x3f) f->status|=0x8080;
    else f->status&=0x7f7f;
}
void lw_fpu_clear(lw_fpu *f) { f->status&=0x7f00; }
void lw_fpu_load_environment(lw_fpu *f, const uint8_t *p, bool small)
{
    f->status=u16(p+(small?2:4)); f->tags=u16(p+(small?4:8));
    f->instruction_pointer=small ? u16(p+6) : u32(p+12);
    f->code_selector=u16(p+(small?8:16));
    f->data_pointer=small ? u16(p+10) : u32(p+20);
    f->data_selector=u16(p+(small?12:24));
    if (!small) f->opcode=u16(p+18)&0x7ff;
    lw_fpu_control(f,u16(p));
}
void lw_fpu_store_environment(lw_fpu *f, uint8_t *p, bool small)
{
    memset(p,0xff,small?14:28);
    put16(p,f->control); put16(p+(small?2:4),f->status); put16(p+(small?4:8),f->tags);
    if (small) { put16(p+6,(uint16_t)f->instruction_pointer); put16(p+10,(uint16_t)f->data_pointer); }
    else { put32(p+12,f->instruction_pointer); put32(p+20,f->data_pointer); put16(p+18,f->opcode); }
    put16(p+(small?8:16),f->code_selector); put16(p+(small?12:24),f->data_selector);
    lw_fpu_control(f,f->control|0x3f);
}
