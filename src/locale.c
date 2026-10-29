/* SPDX-License-Identifier: MIT */
#include "locale.h"
#include <stdlib.h>
uint32_t lw_locale_resolve(uint32_t id)
{
    if (!id || id==0x400 || id==0x800) return LW_DEFAULT_LOCALE;
    return id==0x409 || id==0x804 || id==0x7f ? id : 0;
}
uint32_t lw_locale_info(uint32_t id, uint32_t type, const char **text, uint32_t *number)
{
    id=lw_locale_resolve(id);
    if (!id) return 87;
    if (type & ~UINT32_C(0xa000ffff)) return 1004;
    struct entry { unsigned key,base; const char *en,*zh,*invariant; };
    static const struct entry entries[]={
        {1,16,"0409","0804","007f"}, {5,10,"1","86","1"},
        {9,16,"0409","0804","007f"}, {0xb,10,"437","936","437"},
        {0x1004,10,"1252","936","1252"},
        {0x59,0,"en","zh","iv"}, {0x5a,0,"US","CN","IV"}, {0x5c,0,"en-US","zh-CN",""},
        {0xc,0,",",",",","}, {0xe,0,".",".","."}, {0xf,0,",",",",","},
        {0x10,0,"3;0","3;0","3;0"}, {0x11,10,"2","2","2"},
        {0x14,0,"$","¥","¤"}, {0x15,0,"USD","CNY","XDR"},
        {0x16,0,".",".","."}, {0x17,0,",",",",","}, {0x18,0,"3;0","3;0","3;0"},
        {0x19,10,"2","2","2"}, {0x1d,0,"/","/","/"}, {0x1e,0,":",":",":"},
        {0x1f,0,"M/d/yyyy","yyyy/M/d","MM/dd/yyyy"},
        {0x20,0,"dddd, MMMM d, yyyy","yyyy'年'M'月'd'日'","dddd, dd MMMM yyyy"},
        {0x28,0,"AM","上午","AM"}, {0x29,0,"PM","下午","PM"},
        {0x1003,0,"h:mm:ss tt","H:mm:ss","HH:mm:ss"}
    };
    for (unsigned i=0;i<sizeof(entries)/sizeof(entries[0]);i++) if (entries[i].key==(type&0xffff)) {
        const struct entry *e=&entries[i];
        *text=id==0x409 ? e->en : id==0x804 ? e->zh : e->invariant;
        if (type & 0x20000000U) {
            if (!e->base) return 1004;
            *number=(uint32_t)strtoul(*text,NULL,(int)e->base);
        }
        return 0;
    }
    return 50;
}
