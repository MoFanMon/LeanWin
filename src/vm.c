/* SPDX-License-Identifier: MIT. Original, deliberately limited x86 interpreter. */
#include "vm.h"
#include "nls.h"
#include "memory.h"
#include "resource.h"
#include "process.h"
#include "version.h"
#include "locale.h"
#include "fpu.h"
#include "classes.h"
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
#define TRAP_BASE UINT64_C(0xe0000000)
#define RETURN_ADDRESS UINT64_C(0xfffffff0)
#define TLS_BASE UINT64_C(0x71000000)
#define TLS_FIXED_SIZE 8192U
#define TLS_MAX_SIZE (1024U * 1024U)
#define TLS_MAX_CALLBACKS 64U
#define MAX_THREADS 16U
#define TLS_STRIDE UINT64_C(0x200000)
#define PARAMETERS_BASE UINT64_C(0x75000000)
#define PARAMETERS_SIZE 65536U
#define CF 1U
#define PF 4U
#define AF 16U
#define ZF 64U
#define SF 128U
#define DF 1024U
#define OF 2048U
#define ID_FLAG 0x200000U
#define ARITHMETIC_FLAGS (CF | PF | AF | ZF | SF | OF)

enum { THREAD_ATTACH, THREAD_BODY, THREAD_DETACH, THREAD_ENDED };
enum { READY, WAIT_OBJECT, SLEEPING, WAIT_CRITICAL };
typedef struct {
    uint64_t r[16], ip, start, parameter, deadline, wait_handle;
    uint8_t xmm[16][16];
    lw_fpu fpu;
    unsigned flags, last_error, id, suspend, phase, callback, state;
    uint32_t exit_code;
    uint8_t *stack, *tls;
    bool open, entered;
} guest_thread;
typedef struct { bool used, manual, signaled; } guest_event;
typedef struct { uint64_t address; unsigned owner, recursion; bool used; } guest_critical;

typedef struct {
    const lw_pe *pe;
    const lw_run_options *options;
    lw_import *traps;
    unsigned trap_count, trap_capacity;
    lw_memory *memory;
    lw_processes *processes;
    lw_classes *classes;
    uint8_t *parameters;
    uint64_t command_line, module_path;
    size_t module_length;
    char module_utf8[4096];
    guest_thread threads[MAX_THREADS];
    guest_event events[64];
    guest_critical critical[64];
    unsigned thread_count, current;
    bool tls_indices[64], yielded, thread_exit;
    uint32_t thread_exit_code;
    uint64_t tls_template;
    size_t tls_initialized;
    lw_resource resources[64];
    unsigned resource_count;
    bool resource_loaded[64];
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
enum { DLL_KERNEL=0x200, DLL_USER, DLL_COMMON };
static const char *const module_names[] = {"KERNEL32.dll", "USER32.dll", "COMCTL32.dll"};
typedef struct { const char *name; unsigned argc, module; } api;
enum { EXIT_PROCESS, GET_STD_HANDLE, WRITE_FILE, READ_FILE, CREATE_FILE, CLOSE_HANDLE,
       GET_LAST_ERROR, SET_LAST_ERROR, GET_TICK_COUNT64, GET_PROCESS_ID, GET_FILE_SIZE,
       GET_MODULE_HANDLE, LOAD_LIBRARY, GET_PROC_ADDRESS, MESSAGE_BOX,
       GET_ACP, GET_CP_INFO, GET_CP_INFO_EX, MULTIBYTE_TO_WIDE, WIDE_TO_MULTIBYTE,
       GET_HEAP, HEAP_CREATE, HEAP_DESTROY, HEAP_ALLOC, HEAP_FREE, LOCAL_ALLOC, LOCAL_FREE,
       VIRTUAL_ALLOC, VIRTUAL_FREE, VIRTUAL_PROTECT, VIRTUAL_QUERY, VIRTUAL_QUERY_EX,
       FIND_RESOURCE, SIZEOF_RESOURCE, LOAD_RESOURCE, LOCK_RESOURCE,
       CURRENT_PROCESS, EXIT_CODE_PROCESS, CURRENT_THREAD, CURRENT_THREAD_ID, CREATE_THREAD,
       EXIT_THREAD, EXIT_CODE_THREAD, RESUME_THREAD, SUSPEND_THREAD, WAIT_SINGLE,
       CREATE_EVENT, SET_EVENT, RESET_EVENT, SLEEP_THREAD, SWITCH_THREAD,
       TLS_ALLOC, TLS_FREE, TLS_GET, TLS_SET,
       CRITICAL_INIT, CRITICAL_ENTER, CRITICAL_LEAVE, CRITICAL_DELETE,
       CREATE_PROCESS, GET_COMMAND_LINE, GET_MODULE_FILENAME, GET_STARTUP_INFO,
       PERFORMANCE_FREQUENCY, PERFORMANCE_COUNTER, VERSION_CONDITION, VERIFY_VERSION,
       GET_VERSION, GET_VERSION_EX, SET_THREAD_LOCALE, GET_THREAD_LOCALE, VALID_LOCALE,
       USER_LCID, SYSTEM_LCID, USER_LANG, SYSTEM_LANG, USER_UI_LANG, SYSTEM_UI_LANG,
       LOCALE_INFO, COMPARE_ORDINAL, MAP_STRING, SYSTEM_INFO, COMMON_INIT, COMMON_INIT_EX,
       CLASS_REGISTER, CLASS_REGISTER_EX, CLASS_INFO, CLASS_INFO_EX, CLASS_UNREGISTER, API_COUNT };
static const api apis[] = {
    {"ExitProcess",1,DLL_KERNEL}, {"GetStdHandle",1,DLL_KERNEL}, {"WriteFile",5,DLL_KERNEL},
    {"ReadFile",5,DLL_KERNEL}, {"CreateFileW",7,DLL_KERNEL}, {"CloseHandle",1,DLL_KERNEL},
    {"GetLastError",0,DLL_KERNEL}, {"SetLastError",1,DLL_KERNEL}, {"GetTickCount64",0,DLL_KERNEL},
    {"GetCurrentProcessId",0,DLL_KERNEL}, {"GetFileSizeEx",2,DLL_KERNEL},
    {"GetModuleHandleW",1,DLL_KERNEL}, {"LoadLibraryW",1,DLL_KERNEL},
    {"GetProcAddress",2,DLL_KERNEL}, {"MessageBoxW",4,DLL_USER},
    {"GetACP",0,DLL_KERNEL}, {"GetCPInfo",2,DLL_KERNEL}, {"GetCPInfoExW",3,DLL_KERNEL},
    {"MultiByteToWideChar",6,DLL_KERNEL}, {"WideCharToMultiByte",8,DLL_KERNEL},
    {"GetProcessHeap",0,DLL_KERNEL}, {"HeapCreate",3,DLL_KERNEL}, {"HeapDestroy",1,DLL_KERNEL},
    {"HeapAlloc",3,DLL_KERNEL}, {"HeapFree",3,DLL_KERNEL}, {"LocalAlloc",2,DLL_KERNEL}, {"LocalFree",1,DLL_KERNEL},
    {"VirtualAlloc",4,DLL_KERNEL}, {"VirtualFree",3,DLL_KERNEL}, {"VirtualProtect",4,DLL_KERNEL},
    {"VirtualQuery",3,DLL_KERNEL}, {"VirtualQueryEx",4,DLL_KERNEL}, {"FindResourceW",3,DLL_KERNEL},
    {"SizeofResource",2,DLL_KERNEL}, {"LoadResource",2,DLL_KERNEL}, {"LockResource",1,DLL_KERNEL},
    {"GetCurrentProcess",0,DLL_KERNEL}, {"GetExitCodeProcess",2,DLL_KERNEL}, {"GetCurrentThread",0,DLL_KERNEL},
    {"GetCurrentThreadId",0,DLL_KERNEL}, {"CreateThread",6,DLL_KERNEL}, {"ExitThread",1,DLL_KERNEL},
    {"GetExitCodeThread",2,DLL_KERNEL}, {"ResumeThread",1,DLL_KERNEL}, {"SuspendThread",1,DLL_KERNEL},
    {"WaitForSingleObject",2,DLL_KERNEL}, {"CreateEventW",4,DLL_KERNEL}, {"SetEvent",1,DLL_KERNEL},
    {"ResetEvent",1,DLL_KERNEL}, {"Sleep",1,DLL_KERNEL}, {"SwitchToThread",0,DLL_KERNEL},
    {"TlsAlloc",0,DLL_KERNEL}, {"TlsFree",1,DLL_KERNEL}, {"TlsGetValue",1,DLL_KERNEL}, {"TlsSetValue",2,DLL_KERNEL},
    {"InitializeCriticalSection",1,DLL_KERNEL}, {"EnterCriticalSection",1,DLL_KERNEL},
    {"LeaveCriticalSection",1,DLL_KERNEL}, {"DeleteCriticalSection",1,DLL_KERNEL},
    {"CreateProcessW",10,DLL_KERNEL}, {"GetCommandLineW",0,DLL_KERNEL}, {"GetModuleFileNameW",3,DLL_KERNEL},
    {"GetStartupInfoW",1,DLL_KERNEL}, {"QueryPerformanceFrequency",1,DLL_KERNEL}, {"QueryPerformanceCounter",1,DLL_KERNEL},
    {"VerSetConditionMask",3,DLL_KERNEL}, {"VerifyVersionInfoW",3,DLL_KERNEL}, {"GetVersion",0,DLL_KERNEL}, {"GetVersionExW",1,DLL_KERNEL},
    {"SetThreadLocale",1,DLL_KERNEL}, {"GetThreadLocale",0,DLL_KERNEL}, {"IsValidLocale",2,DLL_KERNEL},
    {"GetUserDefaultLCID",0,DLL_KERNEL}, {"GetSystemDefaultLCID",0,DLL_KERNEL},
    {"GetUserDefaultLangID",0,DLL_KERNEL}, {"GetSystemDefaultLangID",0,DLL_KERNEL},
    {"GetUserDefaultUILanguage",0,DLL_KERNEL}, {"GetSystemDefaultUILanguage",0,DLL_KERNEL},
    {"GetLocaleInfoW",4,DLL_KERNEL}, {"CompareStringOrdinal",5,DLL_KERNEL}, {"LCMapStringW",6,DLL_KERNEL}, {"GetSystemInfo",1,DLL_KERNEL},
    {"InitCommonControls",0,DLL_COMMON}, {"InitCommonControlsEx",1,DLL_COMMON},
    {"RegisterClassW",1,DLL_USER}, {"RegisterClassExW",1,DLL_USER},
    {"GetClassInfoW",3,DLL_USER}, {"GetClassInfoExW",3,DLL_USER}, {"UnregisterClassW",2,DLL_USER}
};
static uint64_t create_thread(vm *, uint64_t *);
static bool executable_address(vm *, uint64_t);
static uint64_t pointer(vm *, uint64_t);
static uint64_t now_ms(void)
{
    struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec*1000 + (uint64_t)now.tv_nsec/1000000;
}
static uint64_t thread_tls_base(vm *v) { return TLS_BASE + v->current*TLS_STRIDE; }
static guest_thread *thread_handle(vm *v, uint64_t handle)
{
    if (handle == pointer(v, (uint64_t)-2)) return &v->threads[v->current];
    if (handle >= 0x2000 && handle-0x2000 < v->thread_count && v->threads[handle-0x2000].open) return &v->threads[handle-0x2000];
    return NULL;
}

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
static uint8_t *access_memory(vm *v, uint64_t address, size_t size, unsigned access)
{
    uint8_t *p = lw_memory_access(v->memory, address, size, access);
    if (p) return p;
    fault(v, "unmapped guest address or protection violation at 0x%" PRIx64 " (%zu bytes), IP=0x%" PRIx64, address, size, v->origin);
    return NULL;
}
static uint8_t *memory(vm *v, uint64_t address, size_t size) { return access_memory(v, address, size, LW_READ | LW_WRITE); }
static uint64_t read_mem(vm *v, uint64_t address, unsigned size)
{
    uint8_t *p = access_memory(v, address, size, LW_READ); uint64_t value = 0;
    if (p) for (unsigned i = 0; i < size; i++) value |= (uint64_t)p[i] << (i * 8);
    return value;
}
static void write_mem(vm *v, uint64_t address, uint64_t value, unsigned size)
{
    uint8_t *p = memory(v, address, size);
    if (p) for (unsigned i = 0; i < size; i++) p[i] = (uint8_t)(value >> (i * 8));
}
static uint64_t fetch(vm *v, unsigned n)
{
    uint8_t *p = access_memory(v, v->ip, n, LW_EXECUTE); uint64_t value = 0;
    if (p) for (unsigned i = 0; i < n; i++) value |= (uint64_t)p[i] << (i * 8);
    v->ip = pointer(v, v->ip + n); return value;
}
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
    unsigned carry = (kind==2 || kind==3) && (v->flags & CF) ? 1U : 0U;
    a &= m; b &= m;
    switch (kind) { case 0: case 2: result = a + b + carry; break; case 1: result = a | b; break;
        case 4: result = a & b; break; case 3: case 5: case 7: result = a - b - carry; break;
        case 6: result = a ^ b; break; default: fault(v, "unsupported arithmetic operation"); return 0; }
    result &= m; v->flags &= ~ARITHMETIC_FLAGS;
    if (!result) v->flags |= ZF;
    if (result & sign) v->flags |= SF;
    unsigned parity = (unsigned)result & 255; parity ^= parity >> 4; parity &= 15;
    if ((0x9669U >> parity) & 1) v->flags |= PF;
    if (kind == 0 || kind == 2) {
        if ((a ^ b ^ result) & 16) v->flags |= AF;
        if (result < a || (carry && result==a)) v->flags |= CF;
        if ((~(a ^ b) & (a ^ result)) & sign) v->flags |= OF;
    } else if (kind == 3 || kind == 5 || kind == 7) {
        if ((a ^ b ^ result) & 16) v->flags |= AF;
        if (a < b || (carry && a==b)) v->flags |= CF;
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
static uint64_t multiply(vm *v, uint64_t a, uint64_t b, unsigned bits)
{
    uint64_t sign = UINT64_C(1) << (bits-1), m = mask(bits);
    a &= m; b &= m;
    bool negative = ((a ^ b) & sign) != 0;
    uint64_t left = (a & sign) ? (0-a)&m : a, right = (b & sign) ? (0-b)&m : b;
    uint64_t limit = negative ? sign : sign-1;
    v->flags &= ~(CF | OF);
    if (right && left > limit/right) v->flags |= CF | OF;
    return (a*b)&m;
}

/* Legacy SSE data movement only. Each thread owns its XMM bytes; there is no
   host SIMD state, floating-point arithmetic, or CPUID feature promotion. */
static bool simd_instruction(vm *v, unsigned opcode, unsigned rex, bool prefix66, bool prefixf3)
{
    if (prefix66 && prefixf3) return false;
    bool scalar = prefix66 && (opcode == 0x6e || opcode == 0x7e);
    bool shuffle = prefix66 && opcode == 0x70;
    bool packed = !prefix66 && !prefixf3 && (opcode == 0x10 || opcode == 0x11 || opcode == 0x28 || opcode == 0x29);
    if (!scalar && !shuffle && !packed) return false;
    unsigned reg; operand op = modrm(v, rex, &reg);
    if (v->failed) return true;
    uint8_t (*xmm)[16] = v->threads[v->current].xmm;
    if (scalar) {
        unsigned bits = (rex & 8) ? 64 : 32;
        if (opcode == 0x6e) {
            uint64_t value = get_operand(v, op, bits);
            if (!v->failed) {
                memset(xmm[reg], 0, 16);
                for (unsigned i = 0; i < bits/8; i++) xmm[reg][i] = (uint8_t)(value >> (i*8));
            }
        } else {
            uint64_t value = 0;
            for (unsigned i = 0; i < bits/8; i++) value |= (uint64_t)xmm[reg][i] << (i*8);
            set_operand(v, op, value, bits);
        }
        return true;
    }
    unsigned control = shuffle ? (unsigned)fetch(v, 1) : 0;
    bool store = packed && (opcode == 0x11 || opcode == 0x29);
    uint8_t *data;
    if (op.reg) data = xmm[op.index];
    else {
        uint64_t address = pointer(v, effective(v, op)+v->segment);
        if ((shuffle || opcode == 0x28 || opcode == 0x29) && (address & 15)) {
            fault(v, "unaligned SIMD operand at 0x%" PRIx64 ", IP=0x%" PRIx64, address, v->origin); return true;
        }
        data = access_memory(v, address, 16, store ? LW_WRITE : LW_READ);
    }
    if (!data || v->failed) return true;
    if (shuffle) {
        uint8_t result[16];
        for (unsigned i = 0; i < 4; i++) memcpy(result+i*4, data+((control >> (i*2)) & 3)*4, 4);
        memcpy(xmm[reg], result, 16);
    } else if (store) memmove(data, xmm[reg], 16);
    else memmove(xmm[reg], data, 16);
    return true;
}
static bool fpu_wait(vm *v)
{
    if (v->threads[v->current].fpu.status & 0x80) {
        fault(v,"unmasked guest x87 exception at IP 0x%" PRIx64,v->origin); return false;
    }
    return true;
}
static bool fpu_instruction(vm *v, unsigned opcode, unsigned rex, bool short_format)
{
    unsigned reg; operand op=modrm(v,rex,&reg); reg&=7;
    lw_fpu *f=&v->threads[v->current].fpu;
    if (v->failed) return true;
    if (op.reg) {
        unsigned second=0xc0|(reg<<3)|(op.index&7);
        if (opcode==0xdb && second==0xe3) { lw_fpu_init(f); return true; }
        if (opcode==0xdb && second==0xe2) { lw_fpu_clear(f); return true; }
        if (opcode==0xdf && second==0xe0) { set_reg(v,0,f->status,16); return true; }
        return false;
    }
    uint64_t address=pointer(v,effective(v,op)+v->segment);
    if (opcode==0xd9 && (reg==4 || reg==6)) {
        bool store=reg==6;
        if (!store && !fpu_wait(v)) return true;
        uint8_t *data=access_memory(v,address,short_format?14:28,store?LW_WRITE:LW_READ);
        if (data) {
            if (store) lw_fpu_store_environment(f,data,short_format);
            else lw_fpu_load_environment(f,data,short_format);
        }
        return true;
    }
    if (opcode==0xd9 && reg==5) {
        if (!fpu_wait(v)) return true;
        uint16_t word=(uint16_t)read_mem(v,address,2);
        if (!v->failed) lw_fpu_control(f,word);
        return true;
    }
    if (opcode==0xd9 && reg==7) { write_mem(v,address,f->control,2); return true; }
    if (opcode==0xdd && reg==7) { write_mem(v,address,f->status,2); return true; }
    return false;
}

/* Atomicity is with respect to this process's cooperative guest scheduler:
   validation, read/modify/write and register updates happen in one VM step.
   There are no host threads or shared-memory mappings in this execution model. */
static uint64_t atomic_reg(vm *v, unsigned reg, unsigned bits, bool rex)
{
    if (bits==8 && !rex && reg>=4 && reg<8) return (v->r[reg-4]>>8)&255;
    return get_reg(v,reg,bits);
}
static void atomic_set_reg(vm *v, unsigned reg, uint64_t value, unsigned bits, bool rex)
{
    if (bits==8 && !rex && reg>=4 && reg<8)
        v->r[reg-4]=(v->r[reg-4]&~UINT64_C(0xff00))|((value&255)<<8);
    else set_reg(v,reg,value,bits);
}
static bool atomic_instruction(vm *v, unsigned opcode, unsigned rex, unsigned bits, bool locked, bool has_rex)
{
    enum { BINARY, IMMEDIATE, UNARY, EXCHANGE, EXCHANGE_ADD, COMPARE_EXCHANGE } kind;
    if (opcode<=0x31 && (opcode&7)<=1) kind=BINARY;
    else if (opcode==0x80 || opcode==0x81 || opcode==0x83) kind=IMMEDIATE;
    else if (opcode==0xfe || opcode==0xff || opcode==0xf6 || opcode==0xf7) kind=UNARY;
    else if (opcode==0x86 || opcode==0x87) kind=EXCHANGE;
    else if (opcode==0x1c0 || opcode==0x1c1) kind=EXCHANGE_ADD;
    else if (opcode==0x1b0 || opcode==0x1b1) kind=COMPARE_EXCHANGE;
    else return false;
    if (!(opcode&1)) bits=8;
    unsigned reg; operand op=modrm(v,rex,&reg);
    if (v->failed) return true;
    unsigned operation=reg&7;
    if ((locked && op.reg) || (kind==IMMEDIATE && operation==7) ||
        (kind==UNARY && ((opcode>=0xfe && operation>1) || (opcode<=0xf7 && operation!=2 && operation!=3)))) {
        fault(v,"invalid LOCK operand or operation at guest IP 0x%" PRIx64,v->origin); return true;
    }
    uint64_t source=0;
    if (kind==IMMEDIATE) {
        source=fetch(v,opcode==0x81 ? (bits==16 ? 2 : 4) : 1);
        if (opcode==0x83) source=(uint64_t)(int64_t)(int8_t)source;
        else if (bits==64 && opcode==0x81) source=(uint64_t)(int64_t)(int32_t)source;
    } else if (kind!=UNARY) source=atomic_reg(v,reg,bits,has_rex);
    if (v->failed) return true;
    uint64_t address=0, old;
    if (op.reg) old=atomic_reg(v,op.index,bits,has_rex);
    else {
        address=pointer(v,effective(v,op)+v->segment);
        /* CMPXCHG has a write cycle even when the comparison fails. */
        if (!access_memory(v,address,bits/8,LW_READ|LW_WRITE)) return true;
        old=read_mem(v,address,bits/8);
    }
    uint64_t result=old;
    if (kind==BINARY) result=alu(v,old,source,bits,(opcode>>3)&7);
    else if (kind==IMMEDIATE) result=alu(v,old,source,bits,operation);
    else if (kind==UNARY) {
        if (opcode>=0xfe) {
            unsigned carry=v->flags&CF;
            result=alu(v,old,1,bits,operation ? 5 : 0);
            v->flags=(v->flags&~CF)|carry;
        } else if (operation==2) result=~old;
        else result=alu(v,0,old,bits,5);
    } else if (kind==EXCHANGE) {
        result=source; atomic_set_reg(v,reg,old,bits,has_rex);
    } else if (kind==EXCHANGE_ADD) {
        result=alu(v,old,source,bits,0); atomic_set_reg(v,reg,old,bits,has_rex);
    } else {
        uint64_t accumulator=get_reg(v,0,bits);
        (void)alu(v,accumulator,old,bits,7);
        if (accumulator==old) result=source;
        else set_reg(v,0,old,bits);
    }
    if (op.reg) atomic_set_reg(v,op.index,result,bits,has_rex);
    else write_mem(v,address,result,bits/8);
    return true;
}

static void instruction(vm *v)
{
    v->origin = v->ip;
    v->segment = 0;
    unsigned rex = 0, last_rex = 0, bits = 32, byte = (unsigned)fetch(v, 1), prefixes = 0;
    bool wide16 = false, repeat = false, repeat_not_equal = false, locked = false;
    while (byte == 0xf0 || byte == 0x66 || byte == 0xf2 || byte == 0xf3 || byte == 0x64 || byte == 0x65 || (v->word == 8 && byte >= 0x40 && byte <= 0x4f)) {
        if (++prefixes > 8) { fault(v, "too many instruction prefixes"); return; }
        last_rex = byte>=0x40 && byte<=0x4f ? byte : 0;
        if (byte == 0xf0) locked = true;
        else if (byte == 0x66) wide16 = true;
        else if (byte == 0xf2 || byte == 0xf3) { repeat = true; repeat_not_equal = byte==0xf2; }
        else if (byte == 0x64 || byte == 0x65) {
            if ((byte == 0x64) != (v->word == 4)) { fault(v, "unsupported FS/GS segment for this architecture"); return; }
            v->segment = thread_tls_base(v);
        }
        byte = (unsigned)fetch(v, 1);
    }
    /* REX must immediately precede the opcode; legacy prefixes cancel it. */
    rex=last_rex&15;
    bits = (rex & 8) ? 64 : wide16 ? 16 : 32;
    if (v->failed) return;
    if (locked) {
        unsigned opcode=byte==0x0f ? 0x100+(unsigned)fetch(v,1) : byte;
        if (!v->failed && (repeat || !atomic_instruction(v,opcode,rex,bits,true,last_rex!=0)))
            fault(v,"unsupported LOCK instruction at guest IP 0x%" PRIx64,v->origin);
        return;
    }
    if (repeat && byte!=0xae && byte!=0xaf &&
        (repeat_not_equal || (byte!=0x0f && byte!=0xa4 && byte!=0xa5 && byte!=0xaa && byte!=0xab && byte!=0xc3))) {
        fault(v, "unsupported REP instruction at guest IP 0x%" PRIx64, v->origin); return;
    }
    if (byte>=0x90 && byte<=0x97) {
        unsigned reg=(byte&7)+((rex&1) ? 8 : 0);
        if (reg) {
            uint64_t old=get_reg(v,0,bits), other=get_reg(v,reg,bits);
            set_reg(v,0,other,bits); set_reg(v,reg,old,bits);
        }
        return;
    }
    if (byte < 0x40 && ((byte & 7) == 4 || (byte & 7) == 5)) {
        unsigned width = (byte & 1) ? bits : 8, kind = (byte >> 3) & 7;
        uint64_t value = fetch(v, width == 64 ? 4 : width/8);
        if (width == 64) value = (uint64_t)(int64_t)(int32_t)value;
        uint64_t result = alu(v, get_reg(v, 0, width), value, width, kind);
        if (kind != 7) set_reg(v, 0, result, width);
        return;
    }
    if (byte >= 0xb0 && byte <= 0xb7) {
        unsigned code=byte & 7;
        uint64_t value=fetch(v,1);
        if (v->failed) return;
        if (code>=4 && !last_rex) {
            unsigned reg=code-4;
            v->r[reg]=(v->r[reg] & ~UINT64_C(0xff00)) | (value<<8);
        } else set_reg(v,code+((last_rex & 1) ? 8 : 0),value,8);
        return;
    }
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
    case 0x86: case 0x87:
        (void)atomic_instruction(v,byte,rex,bits,false,last_rex!=0); return;
    case 0x9b: (void)fpu_wait(v); return;
    case 0xd9: case 0xdb: case 0xdd: case 0xdf:
        if (fpu_instruction(v,byte,rex,wide16)) return;
        break;
    case 0xfc: v->flags &= ~DF; return;
    case 0x9c: case 0x9d: {
        unsigned width = wide16 ? 2 : v->word;
        if (byte == 0x9c) {
            v->r[4] = pointer(v, v->r[4]-width);
            write_mem(v, v->r[4], v->flags | 0x202U, width);
        } else {
            uint64_t value = read_mem(v, v->r[4], width); v->r[4] = pointer(v, v->r[4]+width);
            unsigned allowed = ARITHMETIC_FLAGS | DF | (wide16 ? 0U : ID_FLAG);
            v->flags = (v->flags & ~allowed) | ((unsigned)value & allowed);
        }
        return;
    }
    case 0xa4: case 0xa5: case 0xaa: case 0xab: {
        if (repeat && !pointer(v, v->r[1])) return;
        bool store = byte == 0xaa || byte == 0xab;
        unsigned width = (byte & 1) ? bits/8 : 1;
        uint64_t value = store ? get_reg(v, 0, width*8) : read_mem(v, pointer(v, v->r[6]+v->segment), width);
        write_mem(v, pointer(v, v->r[7]), value, width);
        int64_t step = (v->flags & DF) ? -(int64_t)width : width;
        if (!store) v->r[6] = pointer(v, v->r[6]+(uint64_t)step);
        v->r[7] = pointer(v, v->r[7]+(uint64_t)step);
        if (repeat) { v->r[1] = pointer(v, v->r[1]-1); if (v->r[1]) v->ip = v->origin; }
        return;
    }
    case 0xae: case 0xaf: {
        if (repeat && !pointer(v,v->r[1])) return;
        unsigned width=byte==0xae ? 1 : bits/8;
        uint64_t value=read_mem(v,pointer(v,v->r[7]),width);
        if (v->failed) return;
        (void)alu(v,get_reg(v,0,width*8),value,width*8,7);
        int64_t step=(v->flags & DF) ? -(int64_t)width : width;
        v->r[7]=pointer(v,v->r[7]+(uint64_t)step);
        if (repeat) {
            v->r[1]=pointer(v,v->r[1]-1);
            if (v->r[1] && (((v->flags & ZF)!=0)!=repeat_not_equal)) v->ip=v->origin;
        }
        return;
    }
    case 0xa0: case 0xa1: case 0xa2: case 0xa3: {
        uint64_t address = pointer(v, fetch(v, v->word) + v->segment);
        unsigned width = (byte & 1) ? bits : 8;
        if (!(byte & 2)) set_reg(v, 0, read_mem(v, address, width / 8), width);
        else write_mem(v, address, get_reg(v, 0, width), width / 8);
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
        if (!repeat && (second==0xb0 || second==0xb1 || second==0xc0 || second==0xc1)) {
            (void)atomic_instruction(v,0x100+second,rex,bits,false,last_rex!=0); return;
        }
        if (simd_instruction(v, second, rex, wide16, repeat)) return;
        if (repeat) break;
        if (second == 0xa2) {
            uint32_t leaf = (uint32_t)v->r[0];
            v->r[0] = v->r[1] = v->r[2] = v->r[3] = 0;
            if (!leaf) { v->r[0] = 1; v->r[3] = 0x6e61654c; v->r[2] = 0x436e6957; v->r[1] = 0x20205550; }
            else if (leaf == 1) v->r[0] = 0x300; /* Integer interpreter: no x87/SIMD advertised. */
            return;
        }
        if (second == 0xaf) {
            unsigned reg; operand op = modrm(v, rex, &reg);
            set_reg(v, reg, multiply(v, get_reg(v, reg, bits), get_operand(v, op, bits), bits), bits); return;
        }
        if (second >= 0x80 && second <= 0x8f) {
            int32_t delta = (int32_t)fetch(v, 4);
            if (condition(v, second & 15)) v->ip = pointer(v, v->ip + delta);
            return;
        }
        if (second >= 0x90 && second <= 0x9f) {
            unsigned ignored; operand op = modrm(v, rex, &ignored);
            if (op.reg && op.index >= 4 && !rex) { fault(v, "legacy high-byte registers are not implemented"); return; }
            set_operand(v, op, condition(v, second & 15), 8); return;
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
    case 0x69: case 0x6b: case 0xc1: case 0xd1: case 0xd3:
    case 0x88: case 0x8a: case 0x84:
    case 0x89: case 0x8b: case 0x8d: case 0xc7: case 0xc6: case 0x63:
    case 0x01: case 0x03: case 0x09: case 0x0b: case 0x21: case 0x23:
    case 0x11: case 0x13: case 0x19: case 0x1b:
    case 0x29: case 0x2b: case 0x31: case 0x33: case 0x39: case 0x3b: case 0x85:
    case 0x80: case 0x81: case 0x83: case 0xf6: case 0xf7: case 0xff: {
        unsigned reg; operand op = modrm(v, rex, &reg);
        if (v->failed) return;
        if (byte == 0x69 || byte == 0x6b) {
            uint64_t factor = byte == 0x6b ? (uint64_t)(int64_t)(int8_t)fetch(v, 1) : fetch(v, bits == 16 ? 2 : 4);
            if (bits == 64 && byte == 0x69) factor = (uint64_t)(int64_t)(int32_t)factor;
            set_reg(v, reg, multiply(v, get_operand(v, op, bits), factor, bits), bits); return;
        }
        if (byte == 0xc1 || byte == 0xd1 || byte == 0xd3) {
            unsigned operation = reg & 7;
            unsigned count = byte == 0xc1 ? (unsigned)fetch(v, 1) : byte == 0xd1 ? 1U : (unsigned)v->r[1];
            count &= bits == 64 ? 63 : 31;
            if (operation != 4 && operation != 5 && operation != 7) break;
            if (!count) return;
            uint64_t value = get_operand(v, op, bits), result;
            unsigned carry = 0;
            if (operation == 4) {
                if (count <= bits) carry = (unsigned)((value >> (bits-count)) & 1);
                result = count >= bits ? 0 : (value << count) & mask(bits);
            } else {
                if (count <= bits) carry = (unsigned)((value >> (count-1)) & 1);
                result = count >= bits ? 0 : value >> count;
                if (operation == 7 && (value & (UINT64_C(1) << (bits-1))))
                    result |= count >= bits ? mask(bits) : mask(bits) ^ (mask(bits) >> count);
            }
            (void)alu(v, result, 0, bits, 1);
            if (carry) v->flags |= CF;
            if (count == 1 && ((operation == 4 && ((result >> (bits-1)) ^ carry)) ||
                              (operation == 5 && (value >> (bits-1))))) v->flags |= OF;
            set_operand(v, op, result, bits); return;
        }
        if (byte == 0x88 || byte == 0x8a || byte == 0x84) {
            if (!rex && (reg >= 4 || (op.reg && op.index >= 4))) { fault(v, "legacy high-byte registers are not implemented"); return; }
            if (byte == 0x88) set_operand(v, op, get_reg(v, reg, 8), 8);
            else if (byte == 0x8a) set_reg(v, reg, get_operand(v, op, 8), 8);
            else (void)alu(v, get_operand(v, op, 8), get_reg(v, reg, 8), 8, 4);
            return;
        }
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
        if (byte == 0xf6 || byte == 0xf7) {
            if ((reg & 7)==2) {
                unsigned width=byte==0xf6 ? 8 : bits;
                if (width==8 && op.reg && op.index>=4 && !rex) {
                    fault(v,"legacy high-byte registers are not implemented for NOT"); return;
                }
                uint64_t value=get_operand(v,op,width);
                if (!v->failed) set_operand(v,op,~value,width);
                return;
            }
            if (byte==0xf7 && (reg & 7)==6) {
                uint64_t divisor=get_operand(v,op,bits), high=get_reg(v,2,bits), low=get_reg(v,0,bits);
                if (v->failed) return;
                if (!divisor || high>=divisor) { fault(v,"guest divide error (zero divisor or quotient overflow) at IP 0x%" PRIx64,v->origin); return; }
                uint64_t quotient=0, remainder=high;
                if (bits<64) {
                    uint64_t dividend=(high<<bits)|low;
                    quotient=dividend/divisor; remainder=dividend%divisor;
                } else for (unsigned i=64;i;i--) {
                    bool carry=(remainder>>63)!=0;
                    remainder=(remainder<<1)|((low>>(i-1))&1);
                    if (carry || remainder>=divisor) { remainder-=divisor; quotient|=UINT64_C(1)<<(i-1); }
                }
                set_reg(v,0,quotient,bits); set_reg(v,2,remainder,bits); return;
            }
            if ((reg & 7) != 0) break;
            if (byte == 0xf6) {
                bits = 8;
                if (op.reg && op.index >= 4 && !rex) { fault(v, "legacy high-byte registers are not implemented"); return; }
            }
            uint64_t value = fetch(v, bits == 8 ? 1 : bits == 16 ? 2 : 4);
            if (bits == 64) value = (uint64_t)(int64_t)(int32_t)value;
            (void)alu(v, get_operand(v, op, bits), value, bits, 4); return;
        }
        if (byte == 0x80 || byte == 0x81 || byte == 0x83) {
            if (byte == 0x80) {
                bits = 8;
                if (op.reg && op.index >= 4 && !rex) { fault(v, "legacy high-byte registers are not implemented"); return; }
            }
            uint64_t b = byte == 0x83 ? (uint64_t)(int64_t)(int8_t)fetch(v, 1) : fetch(v, bits == 8 ? 1 : bits == 16 ? 2 : 4);
            /* Byte immediates occupy one byte, unlike the 81 group. */
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
    if (!strcasecmp(name, "kernel32.dll") || !strcasecmp(name, "kernelbase.dll")) return DLL_KERNEL;
    if (!strcasecmp(name, "user32.dll")) return DLL_USER;
    if (!strcasecmp(name, "comctl32.dll")) return DLL_COMMON;
    return 0;
}
static int api_index(int mod, const char *name)
{
    for (int i = 0; i < API_COUNT; i++) if ((unsigned)mod == apis[i].module && !strcmp(name, apis[i].name)) return i;
    return -1;
}
static int bind_import(const lw_import *item, void *opaque, char *e, size_t en)
{
    vm *v = opaque; int mod = module(item->dll);
    int index = mod && !item->by_ordinal ? api_index(mod, item->name) : -1;
    if (index < 0) {
        if (v->options->defer_imports) {
            if (v->trap_count == 1024) { snprintf(e, en, "deferred import limit exceeded"); return -1; }
            if (v->trap_count == v->trap_capacity) {
                unsigned capacity = v->trap_capacity ? v->trap_capacity*2 : 16;
                lw_import *items = realloc(v->traps, capacity*sizeof(*items));
                if (!items) { snprintf(e, en, "cannot allocate deferred imports"); return -1; }
                v->traps = items; v->trap_capacity = capacity;
            }
            v->traps[v->trap_count++] = *item;
            write_mem(v, v->pe->image_base+item->iat, TRAP_BASE+v->trap_count*16, v->word);
            return v->failed ? -1 : 0;
        }
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
    if (a[3] || a[6] || (a[5] && a[5] != 0x80)) { v->last_error = 50; return invalid; }
    char *relative = path;
    if (isalpha((unsigned char)relative[0]) && relative[1] == ':') {
        if (tolower((unsigned char)relative[0]) != 'c') { v->last_error = 15; return invalid; }
        relative += 2;
    }
    for (char *p = relative; *p; p++) if (*p == '\\') *p = '/';
    if (*relative == '/') relative++;
    char self[4096]; snprintf(self, sizeof(self), "%s", v->module_utf8);
    for (char *s = self; *s; s++) if (*s == '\\') *s = '/';
    if (!strcasecmp(relative, self+3)) {
        if (a[1] != UINT64_C(0x80000000) || a[4] != 3) { v->last_error = 5; return invalid; }
        if (a[2] & ~1U) { v->last_error = 50; return invalid; }
        int fd = open(v->options->image_path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        if (fd < 0) { v->last_error = os_error(); return invalid; }
        for (unsigned i = 0; i < 64; i++) if (v->files[i] < 0) { v->files[i] = fd; return 0x1000+i; }
        close(fd); v->last_error = 4; return invalid;
    }
    if (a[2]) { v->last_error = 50; return invalid; }
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
    uint32_t error = fd < 0 ? os_error() : 0;
    close(parent);
    if (fd < 0) { v->last_error = error; return invalid; }
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
static uint64_t convert_string(vm *v, uint64_t *a, bool to_wide)
{
    uint32_t cp = (uint32_t)a[0], flags = (uint32_t)a[1];
    int32_t input_count = (int32_t)a[3], capacity = (int32_t)a[5];
    unsigned source_width = to_wide ? 1 : 2, dest_width = to_wide ? 2 : 1;
    const size_t limit = 16U * 1024U * 1024U;
    if ((cp && cp != LW_ANSI_CODE_PAGE) || !a[2] || input_count == 0 || input_count < -1 ||
        capacity < 0 || (capacity && !a[4]) || (uint64_t)capacity > limit / dest_width ||
        (!to_wide && (a[6] || a[7]))) { v->last_error = 87; return 0; }
    if (flags && flags != (to_wide ? 8U : 128U)) { v->last_error = 1004; return 0; }
    size_t count = 0;
    if (input_count == -1) {
        bool terminated = false;
        while (count < limit / source_width) {
            uint64_t value = read_mem(v, a[2] + count++ * source_width, source_width);
            if (v->failed) return 0;
            if (!value) { terminated = true; break; }
        }
        if (!terminated) { v->last_error = 87; return 0; }
    } else count = (size_t)input_count;
    if (count > limit / source_width) { v->last_error = 87; return 0; }
    size_t input_bytes = count * source_width, output_bytes = (size_t)capacity * dest_width;
    uint8_t *source = access_memory(v, a[2], input_bytes, LW_READ), *destination = NULL;
    if (capacity) {
        if (a[2] < a[4] + output_bytes && a[4] < a[2] + input_bytes) { v->last_error = 87; return 0; }
        destination = memory(v, a[4], output_bytes);
    }
    if (v->failed) return 0;
    size_t required = 0;
    uint32_t error = to_wide ? lw_utf8_to_utf16(source, count, destination, (size_t)capacity, flags != 0, &required)
                             : lw_utf16_to_utf8(source, count, destination, (size_t)capacity, flags != 0, &required);
    if (error) { v->last_error = error; return 0; }
    return required;
}
static bool resource_key(vm *v, uint64_t address, uint16_t *text, lw_resource_key *key)
{
    if (address <= 0xffff) { *key = (lw_resource_key){.id=(uint16_t)address}; return true; }
    for (unsigned i = 0; i < 512; i++) {
        text[i] = (uint16_t)read_mem(v, address+i*2, 2);
        if (v->failed) return false;
        if (text[i] >= 'a' && text[i] <= 'z') text[i] -= 'a'-'A';
        if (!text[i]) { *key = (lw_resource_key){.text=text,.length=i,.named=true}; return true; }
    }
    v->last_error = 87; return false;
}
static guest_critical *critical_at(vm *v, uint64_t address)
{
    for (unsigned i = 0; i < 64; i++) if (v->critical[i].used && v->critical[i].address == address) return &v->critical[i];
    return NULL;
}
static void critical_fields(vm *v, guest_critical *c)
{
    unsigned waiters = 0;
    for (unsigned i = 0; i < v->thread_count; i++) if (v->threads[i].state == WAIT_CRITICAL && v->threads[i].wait_handle == c->address) waiters++;
    write_mem(v, c->address+v->word, c->recursion+waiters-1, 4);
    write_mem(v, c->address+v->word+4, c->recursion, 4);
    write_mem(v, c->address+(v->word == 8 ? 16 : 12), c->owner ? v->threads[c->owner-1].id : 0, v->word);
}
static int object_signaled(vm *v, uint64_t handle, bool consume, unsigned owner)
{
    if (handle >= 0x4000 && handle < 0x4010) return lw_process_signaled(v->processes, handle);
    guest_thread *t = handle == pointer(v, (uint64_t)-2) ? &v->threads[owner] : thread_handle(v, handle);
    if (t) return t->phase == THREAD_ENDED;
    if (handle == mask(v->pe->bits)) return 0;
    if (handle >= 0x3000 && handle < 0x3040 && v->events[handle-0x3000].used) {
        guest_event *event = &v->events[handle-0x3000];
        if (!event->signaled) return 0;
        if (consume && !event->manual) event->signaled = false;
        return 1;
    }
    return -1;
}
static const uint8_t *utf16_span(vm *v, uint64_t address, int32_t length, size_t *units, bool terminator)
{
    if (!address || length < -1 || length>1048576) { v->last_error=87; return NULL; }
    size_t n;
    if (length==-1) {
        for (n=0;n<1048576;n++) {
            uint64_t c=read_mem(v,address+n*2,2);
            if (v->failed) return NULL;
            if (!c) break;
        }
        if (n==1048576) { v->last_error=87; return NULL; }
        if (terminator) n++;
    } else n=(size_t)length;
    *units=n;
    return access_memory(v,address,n*2,LW_READ);
}
static uint16_t utf16_unit(const uint8_t *p, size_t index) { return (uint16_t)(p[index*2] | (uint16_t)p[index*2+1]<<8); }
static uint16_t ascii_case(uint16_t c, bool upper)
{
    if (upper && c>='a' && c<='z') return c-32;
    if (!upper && c>='A' && c<='Z') return c+32;
    return c;
}
/* Class names use a bounded ASCII profile; never apply the host locale. */
static bool class_name(vm *v, uint64_t address, char name[256], uint16_t *atom)
{
    *atom=0; name[0]='\0';
    if (address<=0xffff) {
        if (!address) { v->last_error=87; return false; }
        *atom=(uint16_t)address; return true;
    }
    for (unsigned i=0; i<256; i++) {
        uint16_t c=(uint16_t)read_mem(v,address+i*2,2);
        if (v->failed) return false;
        if (c>=128) { v->last_error=50; return false; }
        name[i]=(char)c;
        if (!c) { if (!i) { v->last_error=87; return false; } return true; }
    }
    v->last_error=87; return false;
}
static bool prepare_classes(vm *v)
{
    if (v->classes) return true;
    v->classes=lw_classes_create();
    if (!v->classes) { fault(v,"cannot allocate window-class registry"); return false; }
    if (!lw_memory_map(v->memory,LW_CLASS_BASE,LW_CLASS_BYTES,lw_classes_strings(v->classes),2,0x20000)) {
        fault(v,"cannot map window-class strings"); return false;
    }
    return true;
}
static uint64_t class_api(vm *v, int id, uint64_t *a)
{
    if (!prepare_classes(v)) return 0;
    if (id==COMMON_INIT || id==COMMON_INIT_EX) {
        uint32_t flags=0xff;
        if (id==COMMON_INIT_EX) {
            if (!a[0]) { v->last_error=87; return 0; }
            if (!access_memory(v,a[0],8,LW_READ)) return 0;
            if (read_mem(v,a[0],4)!=8) { v->last_error=87; return 0; }
            flags=(uint32_t)read_mem(v,a[0]+4,4);
        }
        return lw_classes_common(v->classes,flags,&v->last_error);
    }
    bool registering=id==CLASS_REGISTER || id==CLASS_REGISTER_EX;
    bool extended=id==CLASS_REGISTER_EX || id==CLASS_INFO_EX;
    unsigned size=extended ? (v->word==8 ? 80 : 48) : (v->word==8 ? 72 : 40);
    unsigned proc_offset=extended || v->word==8 ? 8 : 4;
    unsigned extra_offset=proc_offset+v->word, instance_offset=extra_offset+8;
    if (registering) {
        if (!a[0]) { v->last_error=87; return 0; }
        if (!access_memory(v,a[0],size,LW_READ)) return 0;
        if (extended && read_mem(v,a[0],4)!=size) { v->last_error=87; return 0; }
        lw_window_class value={0}; uint16_t atom;
        value.style=(uint32_t)read_mem(v,a[0]+(extended ? 4 : 0),4);
        value.procedure=read_mem(v,a[0]+proc_offset,v->word);
        value.class_extra=(int32_t)read_mem(v,a[0]+extra_offset,4);
        value.window_extra=(int32_t)read_mem(v,a[0]+extra_offset+4,4);
        value.instance=read_mem(v,a[0]+instance_offset,v->word);
        value.icon=read_mem(v,a[0]+instance_offset+v->word,v->word);
        value.cursor=read_mem(v,a[0]+instance_offset+2*v->word,v->word);
        value.background=read_mem(v,a[0]+instance_offset+3*v->word,v->word);
        value.menu=read_mem(v,a[0]+instance_offset+4*v->word,v->word);
        uint64_t name=read_mem(v,a[0]+instance_offset+5*v->word,v->word);
        if (extended) value.small_icon=read_mem(v,a[0]+instance_offset+6*v->word,v->word);
        if (!class_name(v,name,value.name,&atom)) return 0;
        if (atom || value.class_extra<0 || value.window_extra<0 || !executable_address(v,value.procedure)) {
            v->last_error=87; return 0;
        }
        if (value.instance!=v->pe->image_base || (value.style & 0x4000) ||
            value.class_extra>4096 || value.window_extra>4096 || value.icon || value.cursor || value.small_icon || value.background>31) {
            v->last_error=50; return 0;
        }
        uint8_t menu[512]; size_t menu_bytes=0;
        if (value.menu>0xffff) {
            for (unsigned i=0; i<256; i++) {
                uint16_t c=(uint16_t)read_mem(v,value.menu+i*2,2);
                if (v->failed) return 0;
                menu[i*2]=(uint8_t)c; menu[i*2+1]=(uint8_t)(c>>8);
                if (!c) { menu_bytes=(i+1)*2; break; }
            }
            if (!menu_bytes) { v->last_error=50; return 0; }
        }
        return lw_classes_register(v->classes,&value,menu,menu_bytes,&v->last_error);
    }
    char name[256]; uint16_t atom;
    uint64_t instance=id==CLASS_UNREGISTER ? a[1] : a[0];
    if (!class_name(v,a[id==CLASS_UNREGISTER ? 0 : 1],name,&atom)) return 0;
    const lw_window_class *value=lw_classes_find(v->classes,instance,name,atom);
    if (!value) { v->last_error=1411; return 0; }
    if (id==CLASS_UNREGISTER) return lw_classes_unregister(v->classes,value,&v->last_error);
    if (!a[2]) { v->last_error=87; return 0; }
    if (extended && read_mem(v,a[2],4)!=size) { v->last_error=87; return 0; }
    uint8_t *out=memory(v,a[2],size);
    if (!out) return 0;
    memset(out,0,size);
    if (extended) write_mem(v,a[2],size,4);
    write_mem(v,a[2]+(extended ? 4 : 0),value->style,4);
    write_mem(v,a[2]+proc_offset,value->procedure,v->word);
    write_mem(v,a[2]+extra_offset,(uint32_t)value->class_extra,4);
    write_mem(v,a[2]+extra_offset+4,(uint32_t)value->window_extra,4);
    const uint64_t fields[]={value->instance,value->icon,value->cursor,value->background,value->menu,value->name_address,value->small_icon};
    for (unsigned i=0; i<(extended ? 7U : 6U); i++) write_mem(v,a[2]+instance_offset+i*v->word,fields[i],v->word);
    return 1;
}

static uint64_t dispatch(vm *v, int id, uint64_t *a)
{
    switch (id) {
    case SYSTEM_INFO: {
        unsigned size=v->word==8 ? 48 : 36;
        uint8_t *out=memory(v,a[0],size);
        if (!out) return 0;
        memset(out,0,size);
        write_mem(v,a[0],v->word==8 ? 9 : 0,2);
        write_mem(v,a[0]+4,4096,4);
        write_mem(v,a[0]+8,0x10000,v->word);
        write_mem(v,a[0]+8+v->word,v->word==8 ? UINT64_C(0x7ffffffeffff) : 0x7ffeffff,v->word);
        write_mem(v,a[0]+8+v->word*2,1,v->word);
        write_mem(v,a[0]+8+v->word*3,1,4);
        write_mem(v,a[0]+12+v->word*3,v->word==8 ? 8664 : 386,4);
        write_mem(v,a[0]+16+v->word*3,65536,4);
        write_mem(v,a[0]+20+v->word*3,3,2);
        return 0;
    }
    case LOCALE_INFO: {
        int32_t capacity=(int32_t)a[3];
        if (capacity<0 || capacity>1048576 || (capacity && !a[2])) { v->last_error=87; return 0; }
        const char *text=NULL; uint32_t number=0;
        uint32_t error=lw_locale_info((uint32_t)a[0],(uint32_t)a[1],&text,&number);
        if (error) { v->last_error=error; return 0; }
        if (a[1]&0x20000000U) {
            if (!capacity) return 2;
            if (capacity<2) { v->last_error=122; return 0; }
            write_mem(v,a[2],number,4); return v->failed ? 0 : 2;
        }
        size_t units=0;
        lw_utf8_to_utf16((const uint8_t *)text,strlen(text)+1,NULL,0,true,&units);
        if (!capacity) return units;
        if ((size_t)capacity<units) { v->last_error=122; return 0; }
        uint8_t *out=memory(v,a[2],units*2);
        if (!out) return 0;
        error=lw_utf8_to_utf16((const uint8_t *)text,strlen(text)+1,out,units,true,&units);
        if (error) { v->last_error=error; return 0; }
        return units;
    }
    case COMPARE_ORDINAL: {
        unsigned ignore_case=(uint32_t)a[4];
        if (ignore_case>1) { v->last_error=87; return 0; }
        size_t left_count,right_count;
        const uint8_t *left=utf16_span(v,a[0],(int32_t)a[1],&left_count,false);
        const uint8_t *right=utf16_span(v,a[2],(int32_t)a[3],&right_count,false);
        if (!left || !right) return 0;
        if (ignore_case) {
            for (size_t i=0;i<left_count;i++) if (utf16_unit(left,i)>127) { v->last_error=50; return 0; }
            for (size_t i=0;i<right_count;i++) if (utf16_unit(right,i)>127) { v->last_error=50; return 0; }
        }
        for (size_t i=0;i<left_count && i<right_count;i++) {
            uint16_t l=utf16_unit(left,i),r=utf16_unit(right,i);
            if (ignore_case) { l=ascii_case(l,true); r=ascii_case(r,true); }
            if (l!=r) return l<r ? 1 : 3;
        }
        return left_count==right_count ? 2 : left_count<right_count ? 1 : 3;
    }
    case MAP_STRING: {
        uint32_t flags=(uint32_t)a[1];
        if (!lw_locale_resolve((uint32_t)a[0])) { v->last_error=87; return 0; }
        if (flags!=0x100 && flags!=0x200) { v->last_error=1004; return 0; }
        int32_t capacity=(int32_t)a[5]; size_t count;
        if (!(int32_t)a[3] || capacity<0 || capacity>1048576 || (capacity && !a[4])) { v->last_error=87; return 0; }
        const uint8_t *source=utf16_span(v,a[2],(int32_t)a[3],&count,true);
        if (!source) return 0;
        for (size_t i=0;i<count;i++) if (utf16_unit(source,i)>127) { v->last_error=50; return 0; }
        if (!capacity) return count;
        if ((size_t)capacity<count) { v->last_error=122; return 0; }
        if (a[2]!=a[4] && a[2]<a[4]+count*2 && a[4]<a[2]+count*2) { v->last_error=87; return 0; }
        uint8_t *out=memory(v,a[4],count*2);
        if (!out) return 0;
        for (size_t i=0;i<count;i++) { uint16_t c=ascii_case(utf16_unit(source,i),flags==0x200); out[i*2]=(uint8_t)c; out[i*2+1]=0; }
        return count;
    }
    case SET_THREAD_LOCALE: {
        uint32_t locale=lw_locale_resolve((uint32_t)a[0]);
        if (!locale) { v->last_error=87; return 0; }
        write_mem(v,thread_tls_base(v)+(v->word==8 ? 0x108 : 0xc4),locale,4); return !v->failed;
    }
    case GET_THREAD_LOCALE: return read_mem(v,thread_tls_base(v)+(v->word==8 ? 0x108 : 0xc4),4);
    case VALID_LOCALE:
        if ((uint32_t)a[1]!=1 && (uint32_t)a[1]!=2) { v->last_error=1004; return 0; }
        return (uint32_t)a[0]==0x409 || (uint32_t)a[0]==0x804 || (uint32_t)a[0]==0x7f;
    case USER_LCID: case SYSTEM_LCID: case USER_LANG: case SYSTEM_LANG: case USER_UI_LANG: case SYSTEM_UI_LANG:
        return LW_DEFAULT_LOCALE;
    case VERSION_CONDITION: {
        unsigned types=(uint32_t)a[1], condition=(uint8_t)a[2]&7;
        for (unsigned i=0;i<8;i++) if (types & (1U<<i)) return a[0] | UINT64_C(0x8000000000000000) | (uint64_t)condition<<(i*3);
        return a[0];
    }
    case VERIFY_VERSION: {
        if (!a[0]) { v->last_error=87; return 0; }
        uint8_t *info=access_memory(v,a[0],284,LW_READ);
        if (!info) return 0;
        uint32_t error=lw_version_verify(info,(uint32_t)a[1],a[2]);
        if (error) { v->last_error=error; return 0; }
        return 1;
    }
    case GET_VERSION: return (LW_VERSION_BUILD<<16)|(LW_VERSION_MINOR<<8)|LW_VERSION_MAJOR;
    case GET_VERSION_EX: {
        if (!a[0]) { v->last_error=87; return 0; }
        uint32_t size=(uint32_t)read_mem(v,a[0],4);
        if (size!=276 && size!=284) { v->last_error=87; return 0; }
        uint8_t *info=memory(v,a[0],size);
        if (!info) return 0;
        lw_version_info(info,size); return 1;
    }
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
        uint8_t *buffer = access_memory(v, a[1], (size_t)(uint32_t)a[2], id == WRITE_FILE ? LW_READ : LW_WRITE);
        if (a[3] && !memory(v, a[3], 4)) return 0;
        if (!buffer || v->failed) return 0;
        ssize_t n;
        do { n = id == WRITE_FILE ? write(fd, buffer, (size_t)(uint32_t)a[2]) : read(fd, buffer, (size_t)(uint32_t)a[2]); } while (n < 0 && errno == EINTR);
        if (n < 0) { v->last_error = os_error(); return 0; }
        if (a[3]) write_mem(v, a[3], (uint32_t)n, 4);
        return 1;
    }
    case CREATE_FILE: return create_file(v, a);
    case CREATE_PROCESS: {
        if (a[2] || a[3] || a[4] || (a[5] & ~UINT64_C(0x08000000)) || a[6] || a[7]) { v->last_error = 50; return 0; }
        unsigned startup_size = v->word == 8 ? 104 : 68;
        if (!a[8] || !a[9] || read_mem(v, a[8], 4) < startup_size) { v->last_error = 87; return 0; }
        if (!access_memory(v, a[8], startup_size, LW_READ) || !memory(v, a[9], v->word*2+8)) return 0;
        if (read_mem(v, a[8]+(v->word == 8 ? 60 : 44), 4)) { v->last_error = 50; return 0; }
        char app[4096], command[16384];
        if (a[1]) {
            if (!wide_string(v, a[1], command, sizeof(command))) { v->last_error = 87; return 0; }
        } else command[0] = 0;
        if (a[0]) {
            if (!wide_string(v, a[0], app, sizeof(app))) { v->last_error = 87; return 0; }
        } else {
            const char *s = command; while (*s == ' ' || *s == '\t') s++;
            bool quoted = *s == '"'; if (quoted) s++;
            size_t n = 0;
            while (*s && (quoted ? *s != '"' : *s != ' ' && *s != '\t')) {
                if (n+1 == sizeof(app)) { v->last_error = 87; return 0; }
                app[n++] = *s++;
            }
            if (!n || (quoted && *s != '"')) { v->last_error = 87; return 0; }
            app[n] = 0;
        }
        if (!a[1]) snprintf(command, sizeof(command), "\"%s\"", app);
        uint32_t pid;
        uint64_t handle = lw_process_spawn(v->processes, app, command, &pid, &v->last_error);
        if (!handle) return 0;
        write_mem(v, a[9], handle, v->word); write_mem(v, a[9]+v->word, handle+1, v->word);
        write_mem(v, a[9]+v->word*2, pid, 4); write_mem(v, a[9]+v->word*2+4, pid, 4);
        return !v->failed;
    }
    case GET_COMMAND_LINE: return v->command_line;
    case GET_MODULE_FILENAME: {
        if (a[0] && a[0] != v->pe->image_base) { v->last_error = 126; return 0; }
        uint32_t capacity = (uint32_t)a[2];
        if (!a[1] || !capacity) { v->last_error = 122; return 0; }
        size_t units = v->module_length+1;
        if (units > capacity) units = capacity;
        uint8_t *out = memory(v, a[1], units*2);
        const uint8_t *source = access_memory(v, v->module_path, units*2, LW_READ);
        if (!out || !source) return 0;
        memmove(out, source, units*2); out[units*2-2] = out[units*2-1] = 0;
        if (capacity <= v->module_length) { v->last_error = 122; return capacity; }
        return v->module_length;
    }
    case GET_STARTUP_INFO: {
        unsigned size = v->word == 8 ? 104 : 68;
        uint8_t *out = memory(v, a[0], size);
        if (out) { memset(out, 0, size); write_mem(v, a[0], size, 4); }
        return 0;
    }
    case PERFORMANCE_COUNTER: case PERFORMANCE_FREQUENCY: {
        struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
        uint64_t value = id == PERFORMANCE_FREQUENCY ? UINT64_C(1000000000) : (uint64_t)now.tv_sec*1000000000+(uint64_t)now.tv_nsec;
        write_mem(v, a[0], value, 8); return !v->failed;
    }
    case CLOSE_HANDLE: {
        if (lw_process_close(v->processes, a[0])) return 1;
        guest_thread *t = thread_handle(v, a[0]);
        if (t && a[0] >= 0x2000 && a[0] < 0x2000+MAX_THREADS) { t->open = false; return 1; }
        if (a[0] >= 0x3000 && a[0] < 0x3040 && v->events[a[0]-0x3000].used) { v->events[a[0]-0x3000].used = false; return 1; }
        if (a[0] >= 0x1000 && a[0] < 0x1040 && v->files[a[0] - 0x1000] >= 0) {
            close(v->files[a[0] - 0x1000]); v->files[a[0] - 0x1000] = -1; return 1;
        }
        v->last_error = 6; return 0;
    }
    case GET_LAST_ERROR: return v->last_error;
    case SET_LAST_ERROR: v->last_error = (uint32_t)a[0]; return 0;
    case CURRENT_PROCESS: return mask(v->pe->bits);
    case EXIT_CODE_PROCESS: {
        uint32_t code = 259;
        if (a[0] != mask(v->pe->bits) && !lw_process_exit(v->processes, a[0], false, &code)) { v->last_error = 6; return 0; }
        write_mem(v, a[1], code, 4); return !v->failed;
    }
    case CURRENT_THREAD: return pointer(v, (uint64_t)-2);
    case CURRENT_THREAD_ID: return v->threads[v->current].id;
    case CREATE_THREAD: return create_thread(v, a);
    case EXIT_THREAD:
        v->thread_exit = true; v->thread_exit_code = (uint32_t)a[0]; return 0;
    case EXIT_CODE_THREAD: {
        guest_thread *t = thread_handle(v, a[0]);
        uint32_t code;
        if (t) code = t->phase == THREAD_ENDED ? t->exit_code : 259;
        else if (!lw_process_exit(v->processes, a[0], true, &code)) { v->last_error = 6; return 0; }
        write_mem(v, a[1], code, 4); return !v->failed;
    }
    case RESUME_THREAD: case SUSPEND_THREAD: {
        guest_thread *t = thread_handle(v, a[0]);
        if (!t || t->phase == THREAD_ENDED) { v->last_error = 6; return UINT32_MAX; }
        unsigned previous = t->suspend;
        if (id == RESUME_THREAD) { if (t->suspend) t->suspend--; }
        else if (t->suspend == 127) { v->last_error = 87; return UINT32_MAX; }
        else t->suspend++;
        if (t == &v->threads[v->current]) v->yielded = true;
        return previous;
    }
    case WAIT_SINGLE: {
        int signaled = object_signaled(v, a[0], true, v->current);
        if (signaled < 0) { v->last_error = 6; return UINT32_MAX; }
        if (signaled) return 0;
        uint32_t timeout = (uint32_t)a[1];
        if (!timeout) return 258;
        guest_thread *t = &v->threads[v->current];
        t->state = WAIT_OBJECT; t->wait_handle = a[0];
        t->deadline = timeout == UINT32_MAX ? UINT64_MAX : now_ms()+timeout;
        return 0;
    }
    case CREATE_EVENT:
        if (a[0] || a[3]) { v->last_error = 50; return 0; }
        for (unsigned i = 0; i < 64; i++) if (!v->events[i].used) {
            v->events[i] = (guest_event){.used=true,.manual=a[1]!=0,.signaled=a[2]!=0}; return 0x3000+i;
        }
        v->last_error = 8; return 0;
    case SET_EVENT: case RESET_EVENT:
        if (a[0] < 0x3000 || a[0] >= 0x3040 || !v->events[a[0]-0x3000].used) { v->last_error = 6; return 0; }
        v->events[a[0]-0x3000].signaled = id == SET_EVENT; return 1;
    case SLEEP_THREAD: {
        if ((uint32_t)a[0] == UINT32_MAX) { v->last_error = 50; return 0; }
        guest_thread *t = &v->threads[v->current];
        if ((uint32_t)a[0]) { t->state = SLEEPING; t->deadline = now_ms()+(uint32_t)a[0]; }
        v->yielded = true; return 0;
    }
    case SWITCH_THREAD:
        v->yielded = true;
        for (unsigned i = 0; i < v->thread_count; i++) if (i != v->current && v->threads[i].phase != THREAD_ENDED &&
            v->threads[i].state == READY && !v->threads[i].suspend) return 1;
        return 0;
    case TLS_ALLOC:
        for (unsigned i = 0; i < 64; i++) if (!v->tls_indices[i]) { v->tls_indices[i] = true; return i; }
        v->last_error = 8; return UINT32_MAX;
    case TLS_FREE: case TLS_GET: case TLS_SET: {
        unsigned index = (unsigned)a[0];
        if (a[0] >= 64 || !v->tls_indices[index]) { v->last_error = 87; return 0; }
        if (id == TLS_FREE) {
            v->tls_indices[index] = false;
            for (unsigned i = 0; i < v->thread_count; i++) {
                write_mem(v, TLS_BASE+i*TLS_STRIDE+(v->word == 8 ? 0x1480 : 0xe10)+index*v->word, 0, v->word);
            }
            return !v->failed;
        }
        if (id == TLS_GET) { v->last_error = 0; return read_mem(v, thread_tls_base(v)+(v->word == 8 ? 0x1480 : 0xe10)+index*v->word, v->word); }
        write_mem(v, thread_tls_base(v)+(v->word == 8 ? 0x1480 : 0xe10)+index*v->word, a[1], v->word);
        return !v->failed;
    }
    case CRITICAL_INIT: {
        uint8_t *data = memory(v, a[0], v->word == 8 ? 40 : 24);
        if (!data) return 0;
        if (critical_at(v, a[0])) { fault(v, "critical section is already initialized"); return 0; }
        for (unsigned i = 0; i < 64; i++) if (!v->critical[i].used) {
            v->critical[i] = (guest_critical){.used=true,.address=a[0]};
            memset(data, 0, v->word == 8 ? 40 : 24); critical_fields(v, &v->critical[i]); return 0;
        }
        fault(v, "critical section limit exceeded"); return 0;
    }
    case CRITICAL_ENTER: case CRITICAL_LEAVE: case CRITICAL_DELETE: {
        guest_critical *c = critical_at(v, a[0]);
        if (!c) { fault(v, "uninitialized critical section"); return 0; }
        if (id == CRITICAL_ENTER) {
            if (!c->owner || c->owner == v->current+1) { c->owner = v->current+1; c->recursion++; }
            else {
                guest_thread *t = &v->threads[v->current];
                t->state = WAIT_CRITICAL; t->wait_handle = a[0]; t->deadline = UINT64_MAX;
            }
        } else if (id == CRITICAL_LEAVE) {
            if (c->owner != v->current+1 || !c->recursion) { fault(v, "critical section is not owned by the current thread"); return 0; }
            if (!--c->recursion) c->owner = 0;
        } else {
            if (c->owner) { fault(v, "cannot delete an owned critical section"); return 0; }
            c->used = false;
        }
        critical_fields(v, c); return 0;
    }
    case FIND_RESOURCE: {
        if (a[0] && a[0] != v->pe->image_base) { v->last_error = 126; return 0; }
        uint16_t names[512], types[512]; lw_resource_key name, type; lw_resource result;
        if (!resource_key(v, a[1], names, &name) || !resource_key(v, a[2], types, &type)) return 0;
        uint32_t error = lw_resource_find(v->pe, v->image, &type, &name, &result);
        if (error) { v->last_error = error; return 0; }
        for (unsigned i = 0; i < v->resource_count; i++) if (v->resources[i].entry == result.entry) return 0x9000+i;
        if (v->resource_count == 64) { v->last_error = 8; return 0; }
        unsigned i = v->resource_count++; v->resources[i] = result; return 0x9000+i;
    }
    case SIZEOF_RESOURCE: case LOAD_RESOURCE: {
        if (a[0] && a[0] != v->pe->image_base) { v->last_error = 126; return 0; }
        if (a[1] < 0x9000 || a[1]-0x9000 >= v->resource_count) { v->last_error = 6; return 0; }
        unsigned i = (unsigned)(a[1]-0x9000);
        if (id == SIZEOF_RESOURCE) return v->resources[i].size;
        v->resource_loaded[i] = true; return 0xa000+i;
    }
    case LOCK_RESOURCE: {
        if (a[0] < 0xa000 || a[0]-0xa000 >= v->resource_count || !v->resource_loaded[a[0]-0xa000]) { v->last_error = 6; return 0; }
        return v->pe->image_base + v->resources[a[0]-0xa000].data;
    }
    case GET_HEAP: return LW_PROCESS_HEAP;
    case HEAP_CREATE:
        if (a[0] & ~1U) { v->last_error = 50; return 0; }
        return lw_heap_create(v->memory, a[1], a[2], &v->last_error);
    case HEAP_DESTROY: return lw_heap_destroy(v->memory, a[0], &v->last_error);
    case HEAP_ALLOC: return lw_heap_alloc(v->memory, a[0], a[2], (uint32_t)a[1], &v->last_error);
    case HEAP_FREE:
        if (a[1] & ~1U) { v->last_error = 50; return 0; }
        return lw_heap_free(v->memory, a[0], a[2], &v->last_error);
    case LOCAL_ALLOC:
        if (a[0] & ~0x40U) { v->last_error = 50; return 0; }
        return lw_heap_alloc(v->memory, LW_PROCESS_HEAP, a[1], a[0] & 0x40 ? 8 : 0, &v->last_error);
    case LOCAL_FREE: return lw_heap_free(v->memory, LW_PROCESS_HEAP, a[0], &v->last_error) ? 0 : a[0];
    case VIRTUAL_ALLOC:
        if (a[1] > mask(v->pe->bits)-a[0]) { v->last_error = 87; return 0; }
        return lw_virtual_alloc(v->memory, a[0], a[1], (uint32_t)a[2], (uint32_t)a[3], &v->last_error);
    case VIRTUAL_FREE: return lw_virtual_free(v->memory, a[0], a[1], (uint32_t)a[2], &v->last_error);
    case VIRTUAL_PROTECT: {
        if (!a[3]) { v->last_error = 87; return 0; }
        if (!memory(v, a[3], 4)) return 0;
        uint32_t old;
        if (!lw_virtual_protect(v->memory, a[0], a[1], (uint32_t)a[2], &old, &v->last_error)) return 0;
        write_mem(v, a[3], old, 4); return !v->failed;
    }
    case VIRTUAL_QUERY: case VIRTUAL_QUERY_EX: {
        if (id == VIRTUAL_QUERY_EX) {
            if (a[0] != mask(v->pe->bits)) { v->last_error = 6; return 0; }
            a++;
        }
        unsigned size = v->word == 8 ? 48 : 28;
        if (!a[1] || a[2] < size) { v->last_error = 24; return 0; }
        uint8_t *data = memory(v, a[1], size);
        if (!data) return 0;
        lw_memory_info info;
        if (!lw_virtual_query(v->memory, a[0], &info)) { v->last_error = 87; return 0; }
        memset(data, 0, size);
        write_mem(v, a[1], info.base, v->word); write_mem(v, a[1]+v->word, info.allocation_base, v->word);
        write_mem(v, a[1]+v->word*2, info.allocation_protect, 4);
        unsigned offset = v->word == 8 ? 24 : 12;
        write_mem(v, a[1]+offset, info.size, v->word); offset += v->word;
        write_mem(v, a[1]+offset, info.state, 4); write_mem(v, a[1]+offset+4, info.protect, 4); write_mem(v, a[1]+offset+8, info.type, 4);
        return size;
    }
    case GET_ACP: return LW_ANSI_CODE_PAGE;
    case GET_CP_INFO: case GET_CP_INFO_EX: {
        bool extended = id == GET_CP_INFO_EX;
        uint32_t cp = (uint32_t)a[0]; uint64_t address = a[extended ? 2 : 1];
        if ((cp && cp != LW_ANSI_CODE_PAGE) || !address) { v->last_error = 87; return 0; }
        if (extended && (uint32_t)a[1]) { v->last_error = 1004; return 0; }
        uint8_t *out = memory(v, address, extended ? 544 : 20);
        if (!out) return 0;
        lw_utf8_cpinfo(out, extended); return 1;
    }
    case MULTIBYTE_TO_WIDE: return convert_string(v, a, true);
    case WIDE_TO_MULTIBYTE: return convert_string(v, a, false);
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
        if ((a[0] < DLL_KERNEL || a[0] > DLL_COMMON) || a[1] <= 0xffff) { v->last_error = 127; return 0; }
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
    case COMMON_INIT: case COMMON_INIT_EX: case CLASS_REGISTER: case CLASS_REGISTER_EX:
    case CLASS_INFO: case CLASS_INFO_EX: case CLASS_UNREGISTER: return class_api(v,id,a);
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
    uint64_t a[12] = {0};
    unsigned argc=apis[index].argc + (v->word==4 && (index==VERSION_CONDITION || index==VERIFY_VERSION) ? 1U : 0U);
    for (unsigned i = 0; i < argc; i++) {
        if (v->word == 8 && i < 4) a[i] = v->r[(unsigned[]){1, 2, 8, 9}[i]];
        else a[i] = read_mem(v, v->r[4] + (v->word == 8 ? 40 + (uint64_t)(i - 4) * 8 : (uint64_t)(i + 1) * 4), v->word);
    }
    if (v->failed) return;
    if (v->word==4 && index==VERSION_CONDITION) { a[0] |= a[1]<<32; a[1]=a[2]; a[2]=a[3]; }
    if (v->word==4 && index==VERIFY_VERSION) a[2] |= a[3]<<32;
    v->calls++;
    uint64_t result = dispatch(v, index, a);
    if (v->failed || v->done || v->thread_exit) return;
    set_reg(v, 0, result, v->pe->bits);
    if (v->word == 4 && (index == GET_TICK_COUNT64 || index == VERSION_CONDITION)) v->r[2] = result >> 32;
    v->ip = pop(v);
    if (v->word == 4) v->r[4] = pointer(v, v->r[4] + argc * 4);
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
static uint8_t *allocate_tls(vm *v, unsigned index)
{
    uint8_t *data = calloc(1, v->tls_size);
    uint64_t base = TLS_BASE+index*TLS_STRIDE;
    if (!data) return NULL;
    if (!lw_memory_map(v->memory, base, v->tls_size, data, 4, 0x20000)) { free(data); return NULL; }
    if (v->tls_initialized) memcpy(data+TLS_FIXED_SIZE, v->image+(v->tls_template-v->pe->image_base), v->tls_initialized);
    write_mem(v, base+(v->word == 8 ? 0x30 : 0x18), base, v->word);
    write_mem(v, base+(v->word == 8 ? 0x58 : 0x2c), base+4096, v->word);
    write_mem(v, base+4096, base+TLS_FIXED_SIZE, v->word);
    write_mem(v, base+(v->word==8 ? 0x108 : 0xc4), LW_DEFAULT_LOCALE, 4);
    return data;
}
static void prepare_tls(vm *v)
{
    uint32_t rva = v->pe->directories[9][0], size = v->pe->directories[9][1];
    if (!rva && !size) {
        v->tls_size = TLS_FIXED_SIZE; v->tls = allocate_tls(v, 0);
        if (!v->tls) fault(v, "cannot allocate thread environment");
        return;
    }
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
    v->tls_initialized = (size_t)initialized; v->tls_template = start;
    v->tls = allocate_tls(v, 0);
    if (!v->tls) { fault(v, "cannot allocate TLS memory"); return; }
    write_mem(v, index, 0, 4);
}
static uint64_t create_thread(vm *v, uint64_t *a)
{
    if (a[0] || (a[4] & ~4U)) { v->last_error = 50; return 0; }
    if (a[1] > STACK_SIZE || !lw_memory_access(v->memory, a[2], 1, LW_EXECUTE)) { v->last_error = 87; return 0; }
    if (a[5] && !memory(v, a[5], 4)) return 0;
    if (v->thread_count == MAX_THREADS) { v->last_error = 8; return 0; }
    unsigned i = v->thread_count;
    uint64_t stack_base = STACK_BASE+i*(uint64_t)STACK_SIZE;
    uint8_t *stack = calloc(1, STACK_SIZE);
    if (!stack || !lw_memory_map(v->memory, stack_base, STACK_SIZE, stack, 4, 0x20000)) { free(stack); v->last_error = 8; return 0; }
    uint8_t *tls = allocate_tls(v, i);
    if (!tls) { lw_memory_unmap_borrowed(v->memory, stack_base); free(stack); v->last_error = 8; return 0; }
    v->threads[i] = (guest_thread){.stack=stack,.tls=tls,.start=a[2],.parameter=a[3],
        .id=0x40000000U+i,.suspend=a[4] ? 1U : 0U,.open=true};
    lw_fpu_init(&v->threads[i].fpu);
    v->thread_count++;
    if (a[5]) write_mem(v, a[5], v->threads[i].id, 4);
    return 0x2000+i;
}
static void execute(vm *v, uint64_t budget)
{
    guest_thread *t = &v->threads[v->current];
    for (unsigned quantum = 0; quantum < 256 && !v->failed && !v->done && !v->thread_exit && !v->yielded &&
            t->state == READY && !t->suspend && v->ip != RETURN_ADDRESS; quantum++) {
        if (v->instructions >= budget) { fault(v, "instruction budget exhausted at guest IP 0x%" PRIx64, v->ip); break; }
        if (v->ip > TRAP_BASE && v->ip <= TRAP_BASE+v->trap_count*16 && (v->ip-TRAP_BASE)%16 == 0) {
            const lw_import *item = &v->traps[(v->ip-TRAP_BASE)/16-1];
            if (item->by_ordinal) fault(v, "called unimplemented import %s!#%u at guest IP 0x%" PRIx64, item->dll, item->ordinal, v->origin);
            else fault(v, "called unimplemented import %s!%s at guest IP 0x%" PRIx64, item->dll, item->name, v->origin);
        } else if (v->ip > API_BASE && v->ip <= API_BASE + API_COUNT * 16 && (v->ip - API_BASE) % 16 == 0)
            call_api(v, (int)((v->ip - API_BASE) / 16) - 1);
        else if (v->ip > LW_CLASS_PROC_BASE && v->ip <= LW_CLASS_PROC_BASE+LW_CLASS_LIMIT*16)
            fault(v, "built-in control window procedure is not implemented at guest IP 0x%" PRIx64, v->origin);
        else { v->instructions++; instruction(v); }
    }
}
static void enter(vm *v, uint64_t address, unsigned reason, bool child)
{
    memset(v->r, 0, sizeof(v->r)); v->flags = 0;
    v->ip = address;
    v->r[4] = STACK_BASE + (v->current+1)*(uint64_t)STACK_SIZE - 0x100;
    if (v->word == 8) {
        v->r[4] -= 32; /* Windows x64 shadow space; callee RSP is 8 mod 16. */
        if (reason) { v->r[1] = v->pe->image_base; v->r[2] = reason; }
        else if (child) v->r[1] = v->threads[v->current].parameter;
    } else if (reason) {
        push(v, 0); push(v, reason); push(v, v->pe->image_base);
    } else if (child) {
        push(v, v->threads[v->current].parameter);
    }
    push(v, RETURN_ADDRESS);
}
static void schedule(vm *v, uint64_t budget)
{
    unsigned next = 0;
    while (!v->failed && !v->done) {
        uint64_t now = now_ms(), earliest = UINT64_MAX;
        bool living = false; int chosen = -1;
        for (unsigned n = 0; n < v->thread_count; n++) {
            unsigned i = (next+n)%v->thread_count;
            guest_thread *t = &v->threads[i];
            if (t->phase == THREAD_ENDED) continue;
            living = true;
            if (t->state == WAIT_OBJECT) {
                int signaled = object_signaled(v, t->wait_handle, true, i);
                if (signaled || now >= t->deadline) {
                    t->r[0] = signaled < 0 ? UINT32_MAX : signaled ? 0 : 258;
                    if (signaled < 0) t->last_error = 6;
                    t->state = READY;
                }
                if (!signaled && t->wait_handle >= 0x4000 && t->wait_handle < 0x4010 && now+1 < earliest) earliest = now+1;
            } else if (t->state == WAIT_CRITICAL) {
                guest_critical *c = critical_at(v, t->wait_handle);
                if (!c) { fault(v, "critical section deleted while a thread was waiting"); break; }
                if (!c->owner) { c->owner = i+1; c->recursion = 1; t->state = READY; critical_fields(v, c); }
            } else if (t->state == SLEEPING && now >= t->deadline) t->state = READY;
            if (t->state != READY && t->deadline < earliest) earliest = t->deadline;
            if (t->state == READY && !t->suspend && chosen < 0 &&
                (!i || v->threads[0].phase != THREAD_ATTACH)) chosen = (int)i;
        }
        if (!living) { v->done = true; break; }
        if (chosen < 0) {
            if (earliest == UINT64_MAX) { fault(v, "guest threads are deadlocked or all suspended"); break; }
            uint64_t delay = earliest > now ? earliest-now : 0;
            if (delay > 10) delay = 10;
            struct timespec sleep = {.tv_sec=0,.tv_nsec=(long)delay*1000000};
            nanosleep(&sleep, NULL); continue;
        }
        v->current = (unsigned)chosen; guest_thread *t = &v->threads[v->current];
        memcpy(v->r, t->r, sizeof(v->r)); v->ip = t->ip; v->flags = t->flags; v->last_error = t->last_error;
        v->yielded = v->thread_exit = false;
        if (!t->entered) {
            if (t->phase == THREAD_ATTACH || t->phase == THREAD_DETACH) {
                if (t->callback == v->tls_callback_count) {
                    t->phase = t->phase == THREAD_ATTACH ? THREAD_BODY : THREAD_ENDED;
                    t->callback = 0;
                    if (t->phase == THREAD_ENDED) { v->exit_code = t->exit_code; continue; }
                } else {
                    enter(v, v->tls_callbacks[t->callback], t->phase == THREAD_DETACH ? 3 : v->current ? 2 : 1, false);
                    t->entered = true;
                }
            }
            if (!t->entered && t->phase == THREAD_BODY) { enter(v, t->start, 0, v->current != 0); t->entered = true; }
        }
        execute(v, budget);
        if (v->thread_exit) {
            t->exit_code = v->thread_exit_code;
            t->phase = t->phase == THREAD_DETACH ? THREAD_ENDED : THREAD_DETACH;
            if (t->phase == THREAD_ENDED) v->exit_code = t->exit_code;
            t->callback = 0; t->entered = false; t->state = READY;
        } else if (v->ip == RETURN_ADDRESS && !v->failed && !v->done) {
            if (t->phase == THREAD_BODY) {
                t->exit_code = (uint32_t)v->r[0];
                if (!v->current) { v->exit_code = t->exit_code; v->done = true; }
                else { t->phase = THREAD_DETACH; t->callback = 0; t->entered = false; }
            } else { t->callback++; t->entered = false; }
        }
        memcpy(t->r, v->r, sizeof(v->r)); t->ip = v->ip; t->flags = v->flags; t->last_error = v->last_error;
        next = (v->current+1)%v->thread_count;
    }
}

int lw_run(const lw_pe *pe, const lw_run_options *options, lw_result *out, char *e, size_t en)
{
    memset(out, 0, sizeof(*out));
    vm v = {.pe = pe, .options=options, .word = pe->bits / 8, .error = e, .error_size = en, .root = -1};
    const char *root = options->root;
    struct timespec start, end; clock_gettime(CLOCK_MONOTONIC, &start);
    for (unsigned i = 0; i < 64; i++) v.files[i] = -1;
    if ((pe->machine != 0x8664 && pe->machine != 0x14c) || (pe->characteristics & 0x2000) ||
        pe->directories[14][0]) {
        fault(&v, "this prototype supports x86/x64 EXEs without CLR; DLL entry points are not supported"); goto cleanup;
    }
    if (pe->image_size > 64 * 1024 * 1024 || pe->image_base > UINT64_MAX - pe->image_size ||
        pe->image_base + pe->image_size > mask(pe->bits) ||
        (pe->image_base < LW_CLASS_BASE + LW_CLASS_BYTES && pe->image_base + pe->image_size > STACK_BASE) ||
        (pe->image_base < RETURN_ADDRESS + 16 && pe->image_base + pe->image_size > TRAP_BASE)) {
        fault(&v, "guest image size or address conflicts with prototype limits"); goto cleanup;
    }
    v.image = calloc(1, pe->image_size); v.stack = calloc(1, STACK_SIZE); v.memory = lw_memory_create();
    if (!v.image || !v.stack || !v.memory) { fault(&v, "cannot allocate guest memory"); goto cleanup; }
    if (!lw_memory_map(v.memory, pe->image_base, pe->image_size, v.image, 0x40, 0x1000000) ||
        !lw_memory_map(v.memory, STACK_BASE, STACK_SIZE, v.stack, 4, 0x20000)) { fault(&v, "cannot map guest image and stack"); goto cleanup; }
    memcpy(v.image, pe->data, pe->headers_size);
    for (unsigned i = 0; i < pe->section_count; i++) memcpy(v.image + pe->sections[i].rva, pe->data + pe->sections[i].raw, pe->sections[i].raw_size);
    if (lw_pe_imports(pe, bind_import, &v, e, en)) { v.failed = true; goto cleanup; }
    prepare_tls(&v);
    if (v.failed) goto cleanup;
    v.thread_count = 1;
    v.threads[0] = (guest_thread){.stack=v.stack,.tls=v.tls,.start=pe->image_base+pe->entry,.id=(unsigned)getpid()};
    lw_fpu_init(&v.threads[0].fpu);
    if (mkdir(root, 0700) && errno != EEXIST) { fault(&v, "cannot create guest drive: %s", strerror(errno)); goto cleanup; }
    v.root = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (v.root < 0) { fault(&v, "cannot open guest drive: %s", strerror(errno)); goto cleanup; }
    v.processes = lw_processes_create(v.root, options->host_executable, root, options->defer_imports, options->budget, options->process_depth);
    if (!v.processes) { fault(&v, "cannot initialize guest process launcher"); goto cleanup; }
    v.parameters = calloc(1, PARAMETERS_SIZE);
    if (!v.parameters || !lw_memory_map(v.memory, PARAMETERS_BASE, PARAMETERS_SIZE, v.parameters, 4, 0x20000)) {
        fault(&v, "cannot allocate process parameters"); goto cleanup;
    }
    char image_path[4096], command[8192];
    const char *basename = strrchr(options->image_path, '/');
    snprintf(image_path, sizeof(image_path), "C:\\%s", basename ? basename+1 : options->image_path);
    const char *image_name = options->guest_image ? options->guest_image : image_path;
    if (strlen(image_name) >= sizeof(v.module_utf8) || strncmp(image_name, "C:\\", 3)) {
        fault(&v, "guest module path must be an absolute C: path"); goto cleanup;
    }
    strcpy(v.module_utf8, image_name);
    snprintf(command, sizeof(command), "\"%s\"", image_name);
    const char *command_text = options->command_line ? options->command_line : command;
    size_t module_units, command_units;
    if (lw_utf8_to_utf16((const uint8_t *)image_name, strlen(image_name)+1, v.parameters, 8192, true, &module_units) ||
        lw_utf8_to_utf16((const uint8_t *)command_text, strlen(command_text)+1, v.parameters+16384, 16384, true, &command_units)) {
        fault(&v, "process path or command line exceeds prototype limits"); goto cleanup;
    }
    v.module_path = PARAMETERS_BASE; v.module_length = module_units-1; v.command_line = PARAMETERS_BASE+16384;
    schedule(&v, options->budget);
cleanup:
    lw_processes_destroy(v.processes);
    lw_classes_destroy(v.classes);
    for (unsigned i = 0; i < 64; i++) if (v.files[i] >= 0) close(v.files[i]);
    if (v.root >= 0) close(v.root);
    out->guest_memory_bytes = lw_memory_size(v.memory);
    lw_memory_destroy(v.memory); free(v.image); free(v.stack); free(v.tls);
    free(v.traps); free(v.parameters);
    for (unsigned i = 1; i < v.thread_count; i++) { free(v.threads[i].stack); free(v.threads[i].tls); }
    clock_gettime(CLOCK_MONOTONIC, &end);
    out->guest_exit_code = v.exit_code; out->instructions = v.instructions; out->api_calls = v.calls;
    out->elapsed_ms = (double)(end.tv_sec - start.tv_sec) * 1000 + (double)(end.tv_nsec - start.tv_nsec) / 1000000;
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
        fprintf(out, "{\"dll\":\"%s\",\"name\":\"%s\",\"arguments\":%u}", module_names[apis[i].module-DLL_KERNEL], apis[i].name, apis[i].argc);
    }
    fprintf(out, "],\"ansi_code_page\":%u}\n", LW_ANSI_CODE_PAGE);
}
