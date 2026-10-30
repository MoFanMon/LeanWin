/* SPDX-License-Identifier: MIT. Window-class metadata, independent of a GUI backend. */
#ifndef LW_CLASSES_H
#define LW_CLASSES_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define LW_CLASS_BASE UINT64_C(0x76000000)
#define LW_CLASS_LIMIT 128U
#define LW_CLASS_BYTES (LW_CLASS_LIMIT * 1024U)
#define LW_CLASS_PROC_BASE UINT64_C(0xf1000000)

typedef struct {
    char name[256];
    uint64_t procedure, instance, icon, cursor, background, menu, small_icon, name_address;
    uint32_t style;
    int32_t class_extra, window_extra;
    uint16_t atom;
    bool builtin;
} lw_window_class;
typedef struct lw_classes lw_classes;

lw_classes *lw_classes_create(void);
void lw_classes_destroy(lw_classes *classes);
uint8_t *lw_classes_strings(lw_classes *classes);
bool lw_classes_common(lw_classes *classes, uint32_t flags, uint32_t *error);
const lw_window_class *lw_classes_find(const lw_classes *classes, uint64_t instance,
                                     const char *name, uint16_t atom);
uint16_t lw_classes_register(lw_classes *classes, const lw_window_class *value,
                            const uint8_t *menu, size_t menu_bytes, uint32_t *error);
bool lw_classes_unregister(lw_classes *classes, const lw_window_class *value, uint32_t *error);
#endif
