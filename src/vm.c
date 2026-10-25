/* SPDX-License-Identifier: MIT. Original, deliberately limited x86 interpreter. */
#include "vm.h"
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

#define STACK_SIZE (1024U * 1024U)
#define STACK_BASE UINT64_C(0x70000000)
#define API_BASE UINT64_C(0xf0000000)
#define RETURN_ADDRESS UINT64_C(0xfffffff0)
#define TLS_BASE UINT64_C(0x71000000)
#define TLS_FIXED_SIZE 8192U
#define TLS_MAX_SIZE (1024U * 1024U)
#define TLS_MAX_CALLBACKS 64U
#define CF 1U
#define PF 4U
#define ZF 64U
#define SF 128U
#define OF 2048U

typedef struct {
    const lw_pe *pe;
    uint8_t *image, *stack, *tls;
    size_t tls_size;
    uint64_t tls_callbacks[TLS_MAX_CALLBACKS], segment;
    unsigned tls_callback_count;
    uint64_t r[16], ip, origin, instructions, calls;
    unsigned flags, word;
    bool failed, done;
    uint32_t last_error, exit_code;
    int root, files[64];
    char *error; size_t error_size;
} vm;
typedef struct { bool reg, relative; unsigned index; uint64_t address; } operand;
typedef struct { const char *name; unsigned argc; bool user; } api;
enum { EXIT_PROCESS, GET_STD_HANDLE, WRITE_FILE, READ_FILE, CREATE_FILE, CLOSE_HANDLE,
       GET_LAST_ERROR, SET_LAST_ERROR, GET_TICK_COUNT64, GET_PROCESS_ID, GET_FILE_SIZE,
       GET_MODULE_HANDLE, LOAD_LIBRARY, GET_PROC_ADDRESS, MESSAGE_BOX, API_COUNT };
static const api apis[] = {
    {"ExitProcess",1,false}, {"GetStdHandle",1,false}, {"WriteFile",5,false},
    {"ReadFile",5,false}, {"CreateFileW",7,false}, {"CloseHandle",1,false},
    {"GetLastError",0,false}, {"SetLastError",1,false}, {"GetTickCount64",0,false},
    {"GetCurrentProcessId",0,false}, {"GetFileSizeEx",2,false},
    {"GetModuleHandleW",1,false}, {"LoadLibraryW",1,false},
    {"GetProcAddress",2,false}, {"MessageBoxW",4,true}
};

static void fault(vm *v, const char *format, ...)
{
    if (v->failed) return;
    v->failed = true;
    va_list args; va_start(args, format);
    vsnprintf(v->error, v->error_size, format, args);
    va_end(args);
}
static uint64_t mask(unsigned bits) { return bits == 64 ? UINT64_MAX : (UINT64_C(1) << bits) - 1; }
static uint64_t pointer(vm *v, uint64_t value) { return value & mask(v->pe->bits); }
static uint8_t *memory(vm *v, uint64_t address, size_t size)
{
    if (address >= v->pe->image_base && address - v->pe->image_base <= v->pe->image_size &&
        size <= v->pe->image_size - (address - v->pe->image_base)) return v->image + (address - v->pe->image_base);
    if (address >= STACK_BASE && address - STACK_BASE <= STACK_SIZE && size <= STACK_SIZE - (address - STACK_BASE))
        return v->stack + (address - STACK_BASE);
    if (v->tls && address >= TLS_BASE && address - TLS_BASE <= v->tls_size && size <= v->tls_size - (address - TLS_BASE))
        return v->tls + (address - TLS_BASE);
    fault(v, "unmapped guest address 0x%" PRIx64 " (%zu bytes), IP=0x%" PRIx64, address, size, v->origin);
    return NULL;
}
static uint64_t read_mem(vm *v, uint64_t address, unsigned size)
{
    uint8_t *p = memory(v, address, size); uint64_t value = 0;
    if (p) for (unsigned i = 0; i < size; i++) value |= (uint64_t)p[i] << (i * 8);
    return value;
}
static void write_mem(vm *v, uint64_t address, uint64_t value, unsigned size)
{
    uint8_t *p = memory(v, address, size);
    if (p) for (unsigned i = 0; i < size; i++) p[i] = (uint8_t)(value >> (i * 8));
}
static uint64_t fetch(vm *v, unsigned n) { uint64_t value = read_mem(v, v->ip, n); v->ip = pointer(v, v->ip + n); return value; }
static void push(vm *v, uint64_t value) { v->r[4] = pointer(v, v->r[4] - v->word); write_mem(v, v->r[4], value, v->word); }
static uint64_t pop(vm *v) { uint64_t value = read_mem(v, v->r[4], v->word); v->r[4] = pointer(v, v->r[4] + v->word); return value; }
static uint64_t get_reg(vm *v, unsigned r, unsigned bits) { return v->r[r] & mask(bits); }
static void set_reg(vm *v, unsigned r, uint64_t value, unsigned bits)
{
    value &= mask(bits);
    if (bits >= 32) v->r[r] = value;
    else v->r[r] = (v->r[r] & ~mask(bits)) | value;
}
static operand modrm(vm *v, unsigned rex, unsigned *reg)
{
    unsigned byte = (unsigned)fetch(v, 1), mode = byte >> 6, rm = byte & 7;
    *reg = ((byte >> 3) & 7) + ((rex & 4) ? 8 : 0);
    operand op = {.reg = mode == 3, .index = rm + ((rex & 1) ? 8 : 0)};
    if (op.reg) return op;
    if (rm == 4) {
        unsigned sib = (unsigned)fetch(v, 1), base = sib & 7, index = (sib >> 3) & 7;
        if (base == 5 && mode == 0) op.address = (uint32_t)fetch(v, 4);
        else op.address = v->r[base + ((rex & 1) ? 8 : 0)];
        if (index != 4 || (rex & 2)) op.address += v->r[index + ((rex & 2) ? 8 : 0)] << (sib >> 6);
    } else if (rm == 5 && mode == 0) {
        op.address = v->word == 8 ? (uint64_t)(int64_t)(int32_t)fetch(v, 4) : (uint32_t)fetch(v, 4);
        op.relative = v->word == 8;
    } else op.address = v->r[op.index];
    if (mode == 1) op.address += (int8_t)fetch(v, 1);
    if (mode == 2) op.address += (int32_t)fetch(v, 4);
    return op;
}
static uint64_t effective(vm *v, operand op) { return pointer(v, op.address + (op.relative ? v->ip : 0)); }
static uint64_t get_operand(vm *v, operand op, unsigned bits) { return op.reg ? get_reg(v, op.index, bits) : read_mem(v, pointer(v, effective(v, op) + v->segment), bits / 8); }
static void set_operand(vm *v, operand op, uint64_t value, unsigned bits)
{
    if (op.reg) set_reg(v, op.index, value, bits); else write_mem(v, pointer(v, effective(v, op) + v->segment), value, bits / 8);
}
static uint64_t alu(vm *v, uint64_t a, uint64_t b, unsigned bits, unsigned kind)
{
    uint64_t m = mask(bits), sign = UINT64_C(1) << (bits - 1), result;
    a &= m; b &= m;
    switch (kind) { case 0: result = a + b; break; case 1: result = a | b; break;
        case 4: result = a & b; break; case 5: case 7: result = a - b; break;
        case 6: result = a ^ b; break; default: fault(v, "unsupported arithmetic operation"); return 0; }
    result &= m; v->flags = 0;
    if (!result) v->flags |= ZF;
    if (result & sign) v->flags |= SF;
    unsigned parity = (unsigned)result & 255; parity ^= parity >> 4; parity &= 15;
    if ((0x9669U >> parity) & 1) v->flags |= PF;
    if (kind == 0) {
        if (result < a) v->flags |= CF;
        if ((~(a ^ b) & (a ^ result)) & sign) v->flags |= OF;
    } else if (kind == 5 || kind == 7) {
        if (a < b) v->flags |= CF;
        if (((a ^ b) & (a ^ result)) & sign) v->flags |= OF;
    }
    return result;
}
static bool condition(vm *v, unsigned code)
{
    bool c = (v->flags & CF) != 0, z = (v->flags & ZF) != 0,
         s = (v->flags & SF) != 0, o = (v->flags & OF) != 0, p = (v->flags & PF) != 0;
    bool result;
    switch (code >> 1) { case 0: result = o; break; case 1: result = c; break;
        case 2: result = z; break; case 3: result = c || z; break;
        case 4: result = s; break; case 5: result = p; break;
        case 6: result = s != o; break; default: result = z || (s != o); break; }
    return result != ((code & 1) != 0);
}

static void instruction(vm *v)
{
    v->origin = v->ip;
    v->segment = 0;
    unsigned rex = 0, bits = 32, byte = (unsigned)fetch(v, 1), prefixes = 0;
    bool wide16 = false;
    while (byte == 0x66 || byte == 0x64 || byte == 0x65 || (v->word == 8 && byte >= 0x40 && byte <= 0x4f)) {
        if (++prefixes > 8) { fault(v, "too many instruction prefixes"); return; }
        if (byte == 0x66) wide16 = true;
        else if (byte == 0x64 || byte == 0x65) {
            if ((byte == 0x64) != (v->word == 4)) { fault(v, "unsupported FS/GS segment for this architecture"); return; }
            v->segment = TLS_BASE;
        } else rex = byte & 15;
        byte = (unsigned)fetch(v, 1);
    }
    bits = (rex & 8) ? 64 : wide16 ? 16 : 32;
    if (v->failed) return;
    if (byte >= 0xb8 && byte <= 0xbf) {
        uint64_t value = fetch(v, bits / 8); set_reg(v, (byte & 7) + ((rex & 1) ? 8 : 0), value, bits); return;
    }
    if (byte >= 0x50 && byte <= 0x57) { push(v, v->r[(byte & 7) + ((rex & 1) ? 8 : 0)]); return; }
    if (byte >= 0x58 && byte <= 0x5f) { uint64_t x = pop(v); v->r[(byte & 7) + ((rex & 1) ? 8 : 0)] = x; return; }
    if (byte >= 0x70 && byte <= 0x7f) { int8_t delta = (int8_t)fetch(v, 1); if (condition(v, byte & 15)) v->ip = pointer(v, v->ip + delta); return; }
    if (v->word == 4 && byte >= 0x40 && byte <= 0x4f) {
        unsigned reg = byte & 7, carry = v->flags & CF;
        v->r[reg] = alu(v, v->r[reg], 1, 32, (byte & 8) ? 5 : 0);
        v->flags = (v->flags & ~CF) | carry; return;
    }
    switch (byte) {
    case 0x90: return;
    case 0xa1: {
        uint64_t address = pointer(v, fetch(v, v->word) + v->segment);
        set_reg(v, 0, read_mem(v, address, bits / 8), bits);
        return;
    }
    case 0x68: { int64_t x = (int32_t)fetch(v, 4); push(v, (uint64_t)x); return; }
    case 0x6a: { int64_t x = (int8_t)fetch(v, 1); push(v, (uint64_t)x); return; }
    case 0xc3: v->ip = pop(v); return;
    case 0xc2: { unsigned adjustment = (unsigned)fetch(v, 2); v->ip = pop(v); v->r[4] = pointer(v, v->r[4] + adjustment); return; }
    case 0xc9: v->r[4] = v->r[5]; v->r[5] = pop(v); return;
    case 0xe8: { int32_t delta = (int32_t)fetch(v, 4); uint64_t next = v->ip; push(v, next); v->ip = pointer(v, next + delta); return; }
    case 0xe9: { int32_t delta = (int32_t)fetch(v, 4); v->ip = pointer(v, v->ip + delta); return; }
    case 0xeb: { int8_t delta = (int8_t)fetch(v, 1); v->ip = pointer(v, v->ip + delta); return; }
    case 0x0f: {
        unsigned second = (unsigned)fetch(v, 1);
        if (second >= 0x80 && second <= 0x8f) {
            int32_t delta = (int32_t)fetch(v, 4);
            if (condition(v, second & 15)) v->ip = pointer(v, v->ip + delta);
            return;
        }
        if (second == 0xb6 || second == 0xb7 || second == 0xbe || second == 0xbf) {
            unsigned reg, width = (second & 1) ? 16 : 8; operand op = modrm(v, rex, &reg);
            if (width == 8 && op.reg && op.index >= 4 && !rex) { fault(v, "legacy high-byte registers are not implemented"); return; }
            uint64_t value = get_operand(v, op, width);
            if (second & 8) value = width == 8 ? (uint64_t)(int64_t)(int8_t)value : (uint64_t)(int64_t)(int16_t)value;
            set_reg(v, reg, value, bits); return;
        }
        break;
    }
    case 0x89: case 0x8b: case 0x8d: case 0xc7: case 0xc6: case 0x63:
    case 0x01: case 0x03: case 0x09: case 0x0b: case 0x21: case 0x23:
    case 0x29: case 0x2b: case 0x31: case 0x33: case 0x39: case 0x3b: case 0x85:
    case 0x81: case 0x83: case 0xff: {
        unsigned reg; operand op = modrm(v, rex, &reg);
        if (v->failed) return;
        if (byte == 0x8d) {
            if (op.reg) { fault(v, "LEA requires memory addressing"); return; }
            set_reg(v, reg, effective(v, op), bits); return;
        }
        if (byte == 0x89) { set_operand(v, op, get_reg(v, reg, bits), bits); return; }
        if (byte == 0x8b) { set_reg(v, reg, get_operand(v, op, bits), bits); return; }
        if (byte == 0x63 && v->word == 8) { set_reg(v, reg, (uint64_t)(int64_t)(int32_t)get_operand(v, op, 32), bits); return; }
        if (byte == 0x63) break; /* In 32-bit mode this opcode is ARPL, not MOVSXD. */
        if (byte == 0xc7 || byte == 0xc6) {
            if ((reg & 7) != 0) break;
            unsigned width = byte == 0xc6 ? 8 : bits;
            if (width == 8 && op.reg && op.index >= 4 && !rex) { fault(v, "legacy high-byte registers are not implemented"); return; }
            uint64_t x = fetch(v, width == 64 ? 4 : width / 8);
            if (width == 64) x = (uint64_t)(int64_t)(int32_t)x;
            set_operand(v, op, x, width); return;
        }
        if (byte == 0xff) {
            unsigned operation = reg & 7;
            if (operation == 2 || operation == 4 || operation == 6) {
                uint64_t target = get_operand(v, op, v->pe->bits);
                if (operation == 6) push(v, target);
                else { if (operation == 2) push(v, v->ip); v->ip = target; }
                return;
            }
            if (operation < 2) {
                unsigned carry = v->flags & CF;
                uint64_t x = alu(v, get_operand(v, op, bits), 1, bits, operation ? 5 : 0);
                set_operand(v, op, x, bits); v->flags = (v->flags & ~CF) | carry; return;
            }
            break;
        }
        if (byte == 0x81 || byte == 0x83) {
            uint64_t b = byte == 0x83 ? (uint64_t)(int64_t)(int8_t)fetch(v, 1) : fetch(v, bits == 16 ? 2 : 4);
            if (bits == 64 && byte == 0x81) b = (uint64_t)(int64_t)(int32_t)b;
            unsigned kind = reg & 7;
            uint64_t x = alu(v, get_operand(v, op, bits), b, bits, kind);
            if (kind != 7) set_operand(v, op, x, bits);
            return;
        }
        unsigned kind = (byte >> 3) & 7;
        bool reverse = (byte & 2) != 0;
        uint64_t a = reverse ? get_reg(v, reg, bits) : get_operand(v, op, bits);
        uint64_t b = reverse ? get_operand(v, op, bits) : get_reg(v, reg, bits);
        if (byte == 0x85) { (void)alu(v, a, b, bits, 4); return; }
        uint64_t x = alu(v, a, b, bits, kind);
        if (kind != 7) { if (reverse) set_reg(v, reg, x, bits); else set_operand(v, op, x, bits); }
        return;
    }
    default: break;
    }
    fault(v, "unsupported instruction 0x%02x at guest IP 0x%" PRIx64, byte, v->origin);
}

static int module(const char *name)
{
    if (!strcasecmp(name, "kernel32.dll") || !strcasecmp(name, "kernelbase.dll")) return 0x200;
    if (!strcasecmp(name, "user32.dll")) return 0x201;
    return 0;
}
static int api_index(int mod, const char *name)
{
    for (int i = 0; i < API_COUNT; i++) if ((mod == 0x201) == apis[i].user && !strcmp(name, apis[i].name)) return i;
    return -1;
}
static int bind_import(const lw_import *item, void *opaque, char *e, size_t en)
{
    vm *v = opaque; int mod = module(item->dll);
    int index = mod && !item->by_ordinal ? api_index(mod, item->name) : -1;
    if (index < 0) {
        if (item->by_ordinal) snprintf(e, en, "unimplemented import %s!#%u", item->dll, item->ordinal);
        else snprintf(e, en, "unimplemented import %s!%s", item->dll, item->name);
        return -1;
    }
    write_mem(v, v->pe->image_base + item->iat, API_BASE + (uint64_t)(index + 1) * 16, v->word);
    return v->failed ? -1 : 0;
}
static bool wide_string(vm *v, uint64_t addr, char *out, size_t cap)
{
    size_t n = 0;
    for (unsigned i = 0; i < 4096; i++) {
        uint32_t c = (uint32_t)read_mem(v, addr + (uint64_t)i * 2, 2);
        if (v->failed) return false;
        if (!c) { if (n >= cap) return false; out[n] = '\0'; return true; }
        if (c >= 0xd800 && c <= 0xdbff) {
            uint32_t low = (uint32_t)read_mem(v, addr + (uint64_t)++i * 2, 2);
            if (v->failed || low < 0xdc00 || low > 0xdfff) return false;
            c = 0x10000 + ((c - 0xd800) << 10) + low - 0xdc00;
        } else if (c >= 0xdc00 && c <= 0xdfff) return false;
        unsigned count = c < 0x80 ? 1 : c < 0x800 ? 2 : c < 0x10000 ? 3 : 4;
        if (n + count >= cap) return false;
        if (count == 1) out[n++] = (char)c;
        else {
            out[n++] = (char)((count == 2 ? 0xc0 : count == 3 ? 0xe0 : 0xf0) | (c >> (6 * (count - 1))));
            for (unsigned j = count - 1; j; j--) out[n++] = (char)(0x80 | ((c >> (6 * (j - 1))) & 63));
        }
    }
    return false;
}
static uint32_t os_error(void) { return errno == ENOENT ? 2 : errno == EEXIST ? 80 : errno == EBADF ? 6 : 5; }
static uint64_t create_file(vm *v, uint64_t *a)
{
    char path[4096]; uint64_t invalid = mask(v->pe->bits);
    if (!wide_string(v, a[0], path, sizeof(path))) { v->last_error = 87; return invalid; }
    if (a[2] || a[3] || a[6] || (a[5] && a[5] != 0x80)) { v->last_error = 50; return invalid; }
    char *relative = path;
    if (isalpha((unsigned char)relative[0]) && relative[1] == ':') {
        if (tolower((unsigned char)relative[0]) != 'c') { v->last_error = 15; return invalid; }
        relative += 2;
    }
    for (char *p = relative; *p; p++) if (*p == '\\') *p = '/';
    if (*relative == '/') relative++;
    int parent = dup(v->root);
    if (parent < 0) { v->last_error = 5; return invalid; }
    char *component = relative;
    while (true) {
        char *slash = strchr(component, '/');
        if (slash) *slash = '\0';
        if (!*component || !strcmp(component, ".") || !strcmp(component, "..") || strchr(component, ':')) {
            close(parent); v->last_error = 5; return invalid;
        }
        if (!slash) break;
        int next = openat(parent, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        close(parent);
        if (next < 0) { v->last_error = 5; return invalid; }
        parent = next; component = slash + 1;
    }
    unsigned access = (unsigned)a[1]; int flags;
    if (access == 0x80000000U) flags = O_RDONLY;
    else if (access == 0x40000000U) flags = O_WRONLY;
    else if (access == 0xc0000000U) flags = O_RDWR;
    else { close(parent); v->last_error = 87; return invalid; }
    switch (a[4]) { case 1: flags |= O_CREAT | O_EXCL; break; case 2: flags |= O_CREAT | O_TRUNC; break;
        case 3: break; case 4: flags |= O_CREAT; break; case 5: flags |= O_TRUNC; break;
        default: close(parent); v->last_error = 87; return invalid; }
    struct stat before;
    bool existed = fstatat(parent, component, &before, AT_SYMLINK_NOFOLLOW) == 0;
    if (existed && !S_ISREG(before.st_mode)) { close(parent); v->last_error = 5; return invalid; }
    if (existed) {
        for (unsigned i = 0; i < 64; i++) if (v->files[i] >= 0) {
            struct stat opened;
            if (!fstat(v->files[i], &opened) && opened.st_dev == before.st_dev && opened.st_ino == before.st_ino) {
                close(parent); v->last_error = 32; return invalid;
            }
        }
    }
    /* NONBLOCK also prevents a concurrently replaced FIFO from blocking the host. */
    int fd = openat(parent, component, flags | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600);
    close(parent);
    if (fd < 0) { v->last_error = os_error(); return invalid; }
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode)) { close(fd); v->last_error = 5; return invalid; }
    for (unsigned i = 0; i < 64; i++) if (v->files[i] < 0) {
        v->files[i] = fd; v->last_error = existed && (a[4] == 2 || a[4] == 4) ? 183 : 0; return 0x1000 + i;
    }
    close(fd); v->last_error = 4; return invalid;
}
static int handle_fd(vm *v, uint64_t handle)
{
    if (handle == 0x100) return STDOUT_FILENO;
    if (handle == 0x101) return STDERR_FILENO;
    if (handle >= 0x1000 && handle < 0x1040) return v->files[handle - 0x1000];
    return -1;
}
static int show_dialog(vm *v, const char *text, const char *title)
{
#ifdef __APPLE__
    char executable[4096]; uint32_t length = sizeof(executable);
    if (_NSGetExecutablePath(executable, &length)) { fault(v, "GUI module path is too long"); return 0; }
    char *slash = strrchr(executable, '/');
    if (!slash) { fault(v, "cannot locate GUI module"); return 0; }
    *slash = '\0';
    char path[8192]; snprintf(path, sizeof(path), "%s/liblwgui.dylib", executable);
    void *library = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!library) { fault(v, "GUI module unavailable: %s", dlerror()); return 0; }
    void *symbol = dlsym(library, "lw_native_message_box");
    int (*function)(const char *, const char *) = NULL;
    _Static_assert(sizeof(function) == sizeof(symbol), "function pointer size");
    memcpy(&function, &symbol, sizeof(function));
    if (!function) { fault(v, "GUI module interface unavailable"); return 0; }
    /* AppKit owns process-global state; keep the module loaded until process exit. */
    return function(text, title);
#else
    (void)text; (void)title; fault(v, "MessageBoxW backend requires macOS"); return 0;
#endif
}
static uint64_t dispatch(vm *v, int id, uint64_t *a)
{
    switch (id) {
    case EXIT_PROCESS: v->done = true; v->exit_code = (uint32_t)a[0]; return 0;
    case GET_STD_HANDLE:
        if ((uint32_t)a[0] == (uint32_t)-11) return 0x100;
        if ((uint32_t)a[0] == (uint32_t)-12) return 0x101;
        v->last_error = 6; return 0;
    case WRITE_FILE: case READ_FILE: {
        int fd = handle_fd(v, a[0]);
        if (fd < 0) { v->last_error = 6; return 0; }
        if (a[4]) { v->last_error = 50; return 0; }
        if (a[2] > 16 * 1024 * 1024) { v->last_error = 87; return 0; }
        uint8_t *buffer = memory(v, a[1], (size_t)(uint32_t)a[2]);
        if (a[3] && !memory(v, a[3], 4)) return 0;
        if (!buffer || v->failed) return 0;
        ssize_t n;
        do { n = id == WRITE_FILE ? write(fd, buffer, (size_t)(uint32_t)a[2]) : read(fd, buffer, (size_t)(uint32_t)a[2]); } while (n < 0 && errno == EINTR);
        if (n < 0) { v->last_error = os_error(); return 0; }
        if (a[3]) write_mem(v, a[3], (uint32_t)n, 4);
        return 1;
    }
    case CREATE_FILE: return create_file(v, a);
    case CLOSE_HANDLE:
        if (a[0] >= 0x1000 && a[0] < 0x1040 && v->files[a[0] - 0x1000] >= 0) {
            close(v->files[a[0] - 0x1000]); v->files[a[0] - 0x1000] = -1; return 1;
        }
        v->last_error = 6; return 0;
    case GET_LAST_ERROR: return v->last_error;
    case SET_LAST_ERROR: v->last_error = (uint32_t)a[0]; return 0;
    case GET_TICK_COUNT64: {
        struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
        return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
    }
    case GET_PROCESS_ID: return (uint32_t)getpid();
    case GET_FILE_SIZE: {
        int fd = handle_fd(v, a[0]); struct stat st;
        if (fd < 0 || fstat(fd, &st)) { v->last_error = 6; return 0; }
        write_mem(v, a[1], (uint64_t)st.st_size, 8); return v->failed ? 0 : 1;
    }
    case GET_MODULE_HANDLE: case LOAD_LIBRARY: {
        if (!a[0] && id == GET_MODULE_HANDLE) return v->pe->image_base;
        char name[1024];
        if (!wide_string(v, a[0], name, sizeof(name))) { v->last_error = 87; return 0; }
        int mod = module(name);
        if (!mod) v->last_error = 126;
        return (uint64_t)mod;
    }
    case GET_PROC_ADDRESS: {
        if ((a[0] != 0x200 && a[0] != 0x201) || a[1] <= 0xffff) { v->last_error = 127; return 0; }
        char name[260]; bool ended = false;
        for (unsigned i = 0; i < sizeof(name); i++) {
            name[i] = (char)read_mem(v, a[1] + i, 1);
            if (!name[i]) { ended = true; break; }
        }
        if (v->failed || !ended) { v->last_error = 127; return 0; }
        int index = api_index((int)a[0], name);
        if (index < 0) { v->last_error = 127; return 0; }
        return API_BASE + (uint64_t)(index + 1) * 16;
    }
    case MESSAGE_BOX: {
        if (a[0] || a[3]) { v->last_error = 50; return 0; }
        char text[16384] = "", title[16384] = "";
        if ((a[1] && !wide_string(v, a[1], text, sizeof(text))) ||
            (a[2] && !wide_string(v, a[2], title, sizeof(title)))) { v->last_error = 87; return 0; }
        return (uint64_t)show_dialog(v, text, title);
    }
    default: fault(v, "invalid interface dispatch"); return 0;
    }
}
static void call_api(vm *v, int index)
{
    uint64_t a[8] = {0};
    for (unsigned i = 0; i < apis[index].argc; i++) {
        if (v->word == 8 && i < 4) a[i] = v->r[(unsigned[]){1, 2, 8, 9}[i]];
        else a[i] = read_mem(v, v->r[4] + (v->word == 8 ? 40 + (uint64_t)(i - 4) * 8 : (uint64_t)(i + 1) * 4), v->word);
    }
    if (v->failed) return;
    v->calls++;
    uint64_t result = dispatch(v, index, a);
    if (v->failed || v->done) return;
    set_reg(v, 0, result, v->pe->bits);
    if (v->word == 4 && index == GET_TICK_COUNT64) v->r[2] = result >> 32;
    v->ip = pop(v);
    if (v->word == 4) v->r[4] = pointer(v, v->r[4] + apis[index].argc * 4);
}

static bool image_span(vm *v, uint64_t address, uint64_t size)
{
    return address >= v->pe->image_base && address - v->pe->image_base <= v->pe->image_size &&
        size <= v->pe->image_size - (address - v->pe->image_base);
}
static bool executable_address(vm *v, uint64_t address)
{
    if (!image_span(v, address, 1)) return false;
    uint64_t rva = address - v->pe->image_base;
    for (unsigned i = 0; i < v->pe->section_count; i++) {
        const lw_section *s = &v->pe->sections[i];
        uint32_t size = s->virtual_size > s->raw_size ? s->virtual_size : s->raw_size;
        if ((s->flags & 0x20000000U) && rva >= s->rva && rva - s->rva < size) return true;
    }
    return false;
}
static void prepare_tls(vm *v)
{
    uint32_t rva = v->pe->directories[9][0], size = v->pe->directories[9][1];
    if (!rva && !size) return;
    unsigned header_size = v->word * 4 + 8;
    uint64_t directory = v->pe->image_base + rva;
    if (!rva || size < header_size || !image_span(v, directory, size)) {
        fault(v, "invalid TLS directory"); return;
    }
    uint64_t start = read_mem(v, directory, v->word), end = read_mem(v, directory + v->word, v->word);
    uint64_t index = read_mem(v, directory + v->word * 2, v->word);
    uint64_t callbacks = read_mem(v, directory + v->word * 3, v->word);
    uint64_t zero_fill = read_mem(v, directory + v->word * 4, 4);
    uint32_t characteristics = (uint32_t)read_mem(v, directory + v->word * 4 + 4, 4);
    if (end < start || ((start || end) && !image_span(v, start, end - start)) || !image_span(v, index, 4)) {
        fault(v, "invalid TLS template or index address"); return;
    }
    uint64_t initialized = end - start;
    if (initialized > TLS_MAX_SIZE || zero_fill > TLS_MAX_SIZE - initialized) {
        fault(v, "TLS data exceeds the 1 MiB prototype limit"); return;
    }
    if ((characteristics & ~0x00f00000U) || ((characteristics >> 20) & 15) == 15) {
        fault(v, "unsupported TLS characteristics or alignment"); return;
    }
    /* Validate and snapshot the whole callback table before executing any code. */
    if (callbacks) {
        for (unsigned i = 0; ; i++) {
            if (!image_span(v, callbacks, v->word)) { fault(v, "invalid TLS callback table address"); return; }
            uint64_t target = read_mem(v, callbacks, v->word);
            if (!target) break;
            if (i == TLS_MAX_CALLBACKS) { fault(v, "TLS callback list exceeds the 64 callback limit"); return; }
            if (!executable_address(v, target)) { fault(v, "TLS callback is outside executable image sections"); return; }
            v->tls_callbacks[v->tls_callback_count++] = target;
            callbacks += v->word;
        }
    }
    /* One image, one main thread, one static TLS slot. The block base is 8 KiB
       aligned in guest address space, covering every PE TLS alignment value. */
    v->tls_size = TLS_FIXED_SIZE + (size_t)(initialized + zero_fill);
    v->tls = calloc(1, v->tls_size);
    if (!v->tls) { fault(v, "cannot allocate TLS memory"); return; }
    if (initialized) memcpy(v->tls + TLS_FIXED_SIZE, v->image + (start - v->pe->image_base), (size_t)initialized);
    write_mem(v, TLS_BASE + (v->word == 8 ? 0x30 : 0x18), TLS_BASE, v->word);
    write_mem(v, TLS_BASE + (v->word == 8 ? 0x58 : 0x2c), TLS_BASE + 4096, v->word);
    write_mem(v, TLS_BASE + 4096, TLS_BASE + TLS_FIXED_SIZE, v->word);
    write_mem(v, index, 0, 4);
}
static void execute(vm *v, uint64_t budget)
{
    while (!v->failed && !v->done && v->ip != RETURN_ADDRESS) {
        if (v->instructions >= budget) { fault(v, "instruction budget exhausted at guest IP 0x%" PRIx64, v->ip); break; }
        if (v->ip > API_BASE && v->ip <= API_BASE + API_COUNT * 16 && (v->ip - API_BASE) % 16 == 0)
            call_api(v, (int)((v->ip - API_BASE) / 16) - 1);
        else { v->instructions++; instruction(v); }
    }
}
static void enter(vm *v, uint64_t address, bool callback)
{
    memset(v->r, 0, sizeof(v->r)); v->flags = 0;
    v->ip = address;
    v->r[4] = STACK_BASE + STACK_SIZE - 0x100;
    if (v->word == 8) {
        v->r[4] -= 32; /* Windows x64 shadow space; callee RSP is 8 mod 16. */
        if (callback) { v->r[1] = v->pe->image_base; v->r[2] = 1; }
    } else if (callback) {
        push(v, 0); push(v, 1); push(v, v->pe->image_base);
    }
    push(v, RETURN_ADDRESS);
}

int lw_run(const lw_pe *pe, const char *root, uint64_t budget, lw_result *out, char *e, size_t en)
{
    memset(out, 0, sizeof(*out));
    vm v = {.pe = pe, .word = pe->bits / 8, .error = e, .error_size = en, .root = -1};
    struct timespec start, end; clock_gettime(CLOCK_MONOTONIC, &start);
    for (unsigned i = 0; i < 64; i++) v.files[i] = -1;
    if ((pe->machine != 0x8664 && pe->machine != 0x14c) || (pe->characteristics & 0x2000) ||
        pe->directories[14][0]) {
        fault(&v, "this prototype supports x86/x64 EXEs without CLR; DLL entry points are not supported"); goto cleanup;
    }
    if (pe->image_size > 64 * 1024 * 1024 || pe->image_base > UINT64_MAX - pe->image_size ||
        pe->image_base + pe->image_size > mask(pe->bits) ||
        (pe->image_base < STACK_BASE + STACK_SIZE && pe->image_base + pe->image_size > STACK_BASE) ||
        (pe->image_base < TLS_BASE + TLS_FIXED_SIZE + TLS_MAX_SIZE && pe->image_base + pe->image_size > TLS_BASE) ||
        (pe->image_base < RETURN_ADDRESS + 16 && pe->image_base + pe->image_size > API_BASE)) {
        fault(&v, "guest image size or address conflicts with prototype limits"); goto cleanup;
    }
    v.image = calloc(1, pe->image_size); v.stack = calloc(1, STACK_SIZE);
    if (!v.image || !v.stack) { fault(&v, "cannot allocate guest memory"); goto cleanup; }
    memcpy(v.image, pe->data, pe->headers_size);
    for (unsigned i = 0; i < pe->section_count; i++) memcpy(v.image + pe->sections[i].rva, pe->data + pe->sections[i].raw, pe->sections[i].raw_size);
    if (lw_pe_imports(pe, bind_import, &v, e, en)) { v.failed = true; goto cleanup; }
    prepare_tls(&v);
    if (v.failed) goto cleanup;
    if (mkdir(root, 0700) && errno != EEXIST) { fault(&v, "cannot create guest drive: %s", strerror(errno)); goto cleanup; }
    v.root = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (v.root < 0) { fault(&v, "cannot open guest drive: %s", strerror(errno)); goto cleanup; }
    for (unsigned i = 0; i < v.tls_callback_count && !v.failed && !v.done; i++) {
        enter(&v, v.tls_callbacks[i], true);
        execute(&v, budget);
    }
    if (!v.failed && !v.done) {
        enter(&v, pe->image_base + pe->entry, false);
        execute(&v, budget);
        if (!v.failed && !v.done) { v.exit_code = (uint32_t)v.r[0]; v.done = true; }
    }
cleanup:
    for (unsigned i = 0; i < 64; i++) if (v.files[i] >= 0) close(v.files[i]);
    if (v.root >= 0) close(v.root);
    free(v.image); free(v.stack); free(v.tls);
    clock_gettime(CLOCK_MONOTONIC, &end);
    out->guest_exit_code = v.exit_code; out->instructions = v.instructions; out->api_calls = v.calls;
    out->elapsed_ms = (double)(end.tv_sec - start.tv_sec) * 1000 + (double)(end.tv_nsec - start.tv_nsec) / 1000000;
    out->guest_memory_bytes = (size_t)pe->image_size + STACK_SIZE + v.tls_size;
    struct rusage usage;
    if (!getrusage(RUSAGE_SELF, &usage)) {
#ifdef __APPLE__
        out->host_peak_rss_bytes = (uint64_t)usage.ru_maxrss;
#else
        out->host_peak_rss_bytes = (uint64_t)usage.ru_maxrss * 1024;
#endif
    }
    return v.failed ? -1 : 0;
}
void lw_capabilities(FILE *out)
{
    fputs("{\"backend\":\"original-x86-interpreter\",\"architectures\":[\"x86\",\"x86_64\"],\"interfaces\":[", out);
    for (unsigned i = 0; i < API_COUNT; i++) {
        if (i) fputc(',', out);
        fprintf(out, "{\"dll\":\"%s\",\"name\":\"%s\",\"arguments\":%u}", apis[i].user ? "USER32.dll" : "KERNEL32.dll", apis[i].name, apis[i].argc);
    }
    fputs("]}\n", out);
}
