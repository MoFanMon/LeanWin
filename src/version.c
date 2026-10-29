/* SPDX-License-Identifier: MIT */
#include "version.h"
#include <string.h>
static uint32_t u32(const uint8_t *p) { return p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24; }
static uint32_t u16(const uint8_t *p) { return p[0] | (uint32_t)p[1]<<8; }
static void put32(uint8_t *p, uint32_t n) { for (unsigned i=0;i<4;i++) p[i]=(uint8_t)(n>>(i*8)); }
void lw_version_info(uint8_t *p, size_t size)
{
    memset(p,0,size); put32(p,(uint32_t)size);
    put32(p+4,LW_VERSION_MAJOR); put32(p+8,LW_VERSION_MINOR); put32(p+12,LW_VERSION_BUILD); put32(p+16,2);
    if (size==284) { p[281]=1; p[282]=1; } /* VER_SUITE_SINGLEUSERTS, workstation. */
}
uint32_t lw_version_verify(const uint8_t *p, uint32_t types, uint64_t conditions)
{
    if (u32(p)!=284 || !types || (types & ~255U)) return 87;
    /* Only the version tuple is implemented. Other fields and mixed relational
       operators return ERROR_NOT_SUPPORTED, never an invented positive match. */
    if (types & ~0x33U) return 50;
    const unsigned fields[]={1,0,5,4}, offsets[]={4,8,276,278};
    const uint32_t current[]={LW_VERSION_MAJOR,LW_VERSION_MINOR,0,0};
    unsigned condition=0; int relation=0;
    for (unsigned i=0;i<4;i++) if (types & (1U<<fields[i])) {
        unsigned op=(unsigned)(conditions>>(fields[i]*3))&7;
        if (!op || op>5) return 87;
        if (condition && condition!=op) return 50;
        condition=op;
        uint32_t requested=i<2 ? u32(p+offsets[i]) : u16(p+offsets[i]);
        if (!relation && current[i]!=requested) relation=current[i]>requested ? 1 : -1;
    }
    int matches=condition==1 ? relation==0 : condition==2 ? relation>0 : condition==3 ? relation>=0 : condition==4 ? relation<0 : relation<=0;
    return matches ? 0 : 1150;
}
