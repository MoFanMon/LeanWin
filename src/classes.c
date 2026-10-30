/* SPDX-License-Identifier: MIT. Original bounded window-class registry. */
#include "classes.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>

struct lw_classes {
    lw_window_class values[LW_CLASS_LIMIT];
    uint8_t strings[LW_CLASS_BYTES];
};
typedef struct { const char *name; uint32_t flags; } builtin_class;
static const builtin_class builtins[] = {
    {"Button",0x4000}, {"Edit",0x4000}, {"Static",0x4000}, {"ListBox",0x4000},
    {"ComboBox",0x4000}, {"ScrollBar",0x4000}, {"#32770",0x4000},
    {"SysListView32",1}, {"SysHeader32",1}, {"SysTreeView32",2},
    {"ToolbarWindow32",4}, {"msctls_statusbar32",4}, {"msctls_trackbar32",4},
    {"tooltips_class32",4|8|2}, {"SysTabControl32",8}, {"msctls_updown32",0x10},
    {"msctls_progress32",0x20}, {"msctls_hotkey32",0x40}, {"SysAnimate32",0x80},
    {"SysDateTimePick32",0x100}, {"SysMonthCal32",0x100}, {"ComboBoxEx32",0x200},
    {"ReBarWindow32",0x400}, {"SysIPAddress32",0x800}, {"SysPager",0x1000}
};

static void store(lw_classes *classes, unsigned slot, const lw_window_class *value,
                  const uint8_t *menu, size_t menu_bytes)
{
    lw_window_class *out = &classes->values[slot];
    *out = *value; out->atom = (uint16_t)(0xc000 + slot);
    uint8_t *strings = classes->strings + slot*1024;
    memset(strings, 0, 1024);
    for (unsigned i=0; value->name[i]; i++) strings[i*2] = (uint8_t)value->name[i];
    out->name_address = LW_CLASS_BASE + slot*1024;
    if (menu_bytes) { memcpy(strings+512, menu, menu_bytes); out->menu = out->name_address+512; }
}

lw_classes *lw_classes_create(void)
{
    lw_classes *classes = calloc(1, sizeof(*classes));
    uint32_t error = 0;
    if (classes && !lw_classes_common(classes, 0x4000, &error)) { free(classes); return NULL; }
    return classes;
}
void lw_classes_destroy(lw_classes *classes) { free(classes); }
uint8_t *lw_classes_strings(lw_classes *classes) { return classes->strings; }

bool lw_classes_common(lw_classes *classes, uint32_t flags, uint32_t *error)
{
    /* NativeFontCtl, SysLink, activation contexts and v6 manifests are absent. */
    if (flags & ~0x5fffU) { *error=50; return false; }
    unsigned needed=0, free_slots=0;
    for (unsigned i=0; i<LW_CLASS_LIMIT; i++) if (!classes->values[i].atom) free_slots++;
    for (unsigned i=0; i<sizeof(builtins)/sizeof(*builtins); i++)
        if ((builtins[i].flags & flags) && !lw_classes_find(classes, 0, builtins[i].name, 0)) needed++;
    if (needed>free_slots) { *error=8; return false; }
    for (unsigned i=0; i<sizeof(builtins)/sizeof(*builtins); i++) {
        if (!(builtins[i].flags & flags) || lw_classes_find(classes, 0, builtins[i].name, 0)) continue;
        lw_window_class value = {.builtin=true, .procedure=LW_CLASS_PROC_BASE+(i+1)*16};
        strcpy(value.name, builtins[i].name);
        for (unsigned slot=0; slot<LW_CLASS_LIMIT; slot++) if (!classes->values[slot].atom) {
            store(classes, slot, &value, NULL, 0); break;
        }
    }
    return true;
}

const lw_window_class *lw_classes_find(const lw_classes *classes, uint64_t instance,
                                     const char *name, uint16_t atom)
{
    const lw_window_class *fallback = NULL;
    for (unsigned i=0; i<LW_CLASS_LIMIT; i++) {
        const lw_window_class *value = &classes->values[i];
        if (!value->atom || (atom ? value->atom!=atom : strcasecmp(value->name, name))) continue;
        if (!value->builtin && value->instance==instance) return value;
        if (value->builtin) fallback=value;
    }
    return fallback;
}

uint16_t lw_classes_register(lw_classes *classes, const lw_window_class *value,
                            const uint8_t *menu, size_t menu_bytes, uint32_t *error)
{
    const lw_window_class *existing = lw_classes_find(classes, value->instance, value->name, 0);
    if (existing && !existing->builtin) { *error=1410; return 0; }
    for (unsigned i=0; i<LW_CLASS_LIMIT; i++) if (!classes->values[i].atom) {
        store(classes, i, value, menu, menu_bytes); return classes->values[i].atom;
    }
    *error=8; return 0;
}
bool lw_classes_unregister(lw_classes *classes, const lw_window_class *value, uint32_t *error)
{
    if (value->builtin) { *error=50; return false; }
    unsigned slot = value->atom-0xc000;
    memset(&classes->values[slot], 0, sizeof(classes->values[slot]));
    memset(classes->strings+slot*1024, 0, 1024);
    return true;
}
