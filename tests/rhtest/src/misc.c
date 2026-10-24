/* misc: what the other programs leave out. Thread-local storage, both kinds: __declspec(thread)
 * variables (the image's TLS directory, reached through fs:[0x2c] and _tls_index) and the TlsAlloc
 * API. Compiler intrinsics that become single instructions (rol/ror, bswap, bsf/bsr, bt, popcnt,
 * lock xadd and cmpxchg, mul's high half). Bitfields, signed and unsigned, across a word. alloca
 * (`sub esp` by a run-time size, through __alloca_probe_16). setjmp and longjmp (the CRT's
 * _setjmp3, a longjmp out of a nested call). */
#include "rhtest.h"

#include <intrin.h>
#include <malloc.h>
#include <setjmp.h>
#include <stdint.h>
#include <string.h>

__declspec(dllimport) unsigned long __stdcall TlsAlloc(void);
__declspec(dllimport) int __stdcall TlsFree(unsigned long index);
__declspec(dllimport) void *__stdcall TlsGetValue(unsigned long index);
__declspec(dllimport) int __stdcall TlsSetValue(unsigned long index, void *value);
typedef struct { unsigned int MaxCharSize; unsigned char DefaultChar[2]; unsigned char LeadByte[12]; } CpInfo;
__declspec(dllimport) int __stdcall GetCPInfo(unsigned int codepage, CpInfo *info);
/* (a window class: user32, its x86 WNDCLASSEXA) */
#pragma comment(lib, "user32.lib")
typedef long(__stdcall *WndProc32)(void *, unsigned int, unsigned int, long);
typedef struct {
    unsigned int cbSize, style;
    WndProc32 proc;
    int cbClsExtra, cbWndExtra;
    void *hInstance, *hIcon, *hCursor, *hbrBackground;
    const char *menu, *name;
    void *hIconSm;
} WndClassExA32;
__declspec(dllimport) unsigned short __stdcall RegisterClassExA(const WndClassExA32 *wc);
__declspec(dllimport) void *__stdcall CreateWindowExA(unsigned long ex, const char *cls, const char *title,
                                                      unsigned long style, int x, int y, int w, int h, void *parent,
                                                      void *menu, void *inst, void *param);
__declspec(dllimport) long __stdcall SendMessageA(void *hwnd, unsigned int msg, unsigned int wp, long lp);
__declspec(dllimport) long __stdcall DefWindowProcA(void *hwnd, unsigned int msg, unsigned int wp, long lp);
__declspec(dllimport) int __stdcall DestroyWindow(void *hwnd);
__declspec(dllimport) void *__stdcall GetModuleHandleA(const char *name);

/* ---- thread-local storage ---- */
static __declspec(thread) u32 t_count = 5;
static __declspec(thread) u32 t_table[4] = {1, 2, 3, 4};

NOINLINE void tls_bump(u32 k) {
    t_count += k;
    t_table[k & 3] ^= t_count;
}
NOINLINE u32 tls_static(u32 s) {
    for (u32 k = 0; k < s; k++) tls_bump(k);
    return t_count * 1000 + t_table[0] + t_table[1] * 3 + t_table[2] * 5 + t_table[3] * 7;
}
NOINLINE u32 tls_api(u32 s) {
    unsigned long slot = TlsAlloc();
    if (slot == 0xFFFFFFFFu) return 0xDEAD;
    TlsSetValue(slot, (void *)(uintptr_t)(s * 3 + 1));
    u32 v = (u32)(uintptr_t)TlsGetValue(slot);
    TlsFree(slot);
    return v;
}

/* ---- intrinsics ---- */
NOINLINE u32 rotates(u32 a, int n) { return _rotl(a, n) ^ _rotr(a, n + 3) ^ (u32)_rotl8((u8)a, (u8)n) << 8; }
NOINLINE u32 swaps(u32 a) { return _byteswap_ulong(a) ^ _byteswap_ushort((u16)a); }
NOINLINE u64 swap64(u64 a) { return _byteswap_uint64(a); }
NOINLINE u32 scans(u32 a) {
    unsigned long lo = 99, hi = 99;
    unsigned char f = _BitScanForward(&lo, a);
    unsigned char r = _BitScanReverse(&hi, a);
    return lo | hi << 8 | (u32)f << 16 | (u32)r << 17;
}
NOINLINE u32 bits(u32 a, u32 b) {
    long v = (long)a;
    u32 t = (u32)_bittest(&v, (long)(b & 31));
    u32 c = (u32)_bittestandcomplement(&v, (long)((b + 1) & 31));
    return t | c << 1 | (u32)v << 2;
}
NOINLINE u32 popcount(u32 a) { return __popcnt(a) | __popcnt16((u16)a) << 8; }
NOINLINE u64 mulhi(u32 a, u32 b) { return __emulu(a, b); }
NOINLINE u32 atomics(u32 s) {
    volatile long n = (long)s;
    long r = _InterlockedIncrement(&n);
    r += _InterlockedExchangeAdd(&n, 10);
    long old = _InterlockedCompareExchange(&n, 100, (long)s + 11);
    long miss = _InterlockedCompareExchange(&n, 5, 1);
    r = r * 31 + old * 7 + miss + _InterlockedExchange(&n, 3);
    return (u32)(r ^ n);
}

/* ---- bitfields ---- */
struct Packed {
    u32 a : 3;
    u32 b : 7;
    i32 c : 5;        /* (signed: read back sign-extended) */
    u32 d : 1;
    u32 e : 16;       /* (ends the first word) */
    u16 f : 4;
    u16 g : 12;
};
NOINLINE void pack(struct Packed *p, u32 s) {
    p->a = s;
    p->b = s * 9;
    p->c = -(i32)s;
    p->d = s & 1;
    p->e = s * 1000;
    p->f = (u16)(s + 3);
    p->g = (u16)(s * 77);
}
NOINLINE u32 unpack(const struct Packed *p) {
    return p->a + p->b * 10 + (u32)(p->c * 100) + p->d * 7 + p->e * 3 + p->f * 11 + p->g * 13;
}
NOINLINE u32 bitfields(u32 s) {
    struct Packed p;
    memset(&p, 0, sizeof p);
    pack(&p, s);
    p.c += 3;
    p.b ^= 0x55;
    u32 raw[2];
    memcpy(raw, &p, sizeof raw);
    return unpack(&p) ^ raw[0] ^ raw[1] << 3;
}

/* ---- alloca ---- */
NOINLINE u32 fill_sum(u8 *buf, u32 n) {
    u32 h = 0;
    for (u32 k = 0; k < n; k++) {
        buf[k] = (u8)(k * 7 + n);
        h = h * 33 + buf[k];
    }
    return h;
}
NOINLINE u32 stack_alloc(u32 s) {
    u32 n = s * 37 + 5;                /* (a size known only at run time) */
    u8 *buf = (u8 *)_alloca(n);
    u32 h = fill_sum(buf, n);
    u32 *words = (u32 *)_alloca(s * sizeof(u32));
    for (u32 k = 0; k < s; k++) words[k] = buf[k * 3] + k;
    for (u32 k = 0; k < s; k++) h ^= words[k] << (k & 7);
    return h;
}

/* ---- setjmp / longjmp ---- */
static jmp_buf g_jump;
static u32 g_depth;
NOINLINE void dive(u32 n) {
    g_depth++;
    if (n == 0) longjmp(g_jump, (int)g_depth);
    dive(n - 1);
    g_depth += 100;                    /* (never reached) */
}
NOINLINE u32 jumps(u32 s) {
    volatile u32 tries = 0;
    g_depth = 0;
    int r = setjmp(g_jump);
    tries++;
    if (tries < 3) dive(s + tries);
    return (u32)r * 1000 + tries * 10 + g_depth;
}

/* an 8-byte value a callee fills, returned whole in edx:eax: QueryPerformanceCounter's
 * LARGE_INTEGER. Taken for an object's fields, it was a byte array and the function's return a
 * `byte [8]`, no C (CrystalCore) */
NOINLINE void fill64(u64 *p, u32 s) { *p = ((u64)(s * 3) << 32) | (s ^ 0x55u); }
NOINLINE u64 filled(u32 s) {
    u64 v;
    fill64(&v, s);
    if (s & 1) return v;
    return 0;
}

/* a switch in a function with a frame pointer (_alloca keeps ebp at /O2): its cases, reached only
 * through the jump table, read the parameters through ebp. Taken for ebp read unset, it made the
 * function take ebp as an input, and its callers stubs (memcpy's tails, CrystalCore) */
NOINLINE u32 framed_switch(u32 k, u32 a, u32 b) {
    volatile u8 *p = (volatile u8 *)_alloca(16 + (k & 7));
    p[0] = (u8)k;
    switch (k % 7) {
    case 0: return a + p[0];
    case 1: return a * b;
    case 2: return a - b;
    case 3: return b << 3;
    case 4: return a ^ b ^ p[0];
    case 5: return a | b;
    default: return b - a;
    }
}
/* a Windows structure on the stack that a kernel32 call fills, as __setmbcp_nolock's CPINFO: the
 * decompiler, knowing GetCPInfo's type, names such a local `_Stack_1c`, which the translator took
 * for one of its unnamed pieces (CrystalCore) */
NOINLINE u32 code_page(u32 s) {
    CpInfo ci;
    u32 r, k;
    if (!GetCPInfo(1252, &ci)) return 0;
    r = ci.MaxCharSize * 1000 + ci.DefaultChar[0] + s;
    for (k = 0; k < 12 && ci.LeadByte[k]; k++) r = r * 7 + ci.LeadByte[k];
    return r;
}
/* a window class and its procedure: x86's WNDCLASSEXA is 48 bytes of 4-byte pointers, and the
 * procedure Windows calls is a reference address. Handed to x64's RegisterClassExA as it was, the
 * class was never made and CrystalCore's WinMain had no window. A negative result comes back as one */
static u32 g_msgs;
static long __stdcall test_proc(void *hwnd, unsigned int msg, unsigned int wp, long lp) {
    if (msg == 0x8001) {
        g_msgs += wp;
        return -5;
    }
    if (msg == 1) g_msgs += 1000;   /* WM_CREATE */
    return DefWindowProcA(hwnd, msg, wp, lp);
}
NOINLINE u32 window_class(u32 s) {
    WndClassExA32 wc = {sizeof wc, 0, test_proc, 0, 0, 0, 0, 0, 0, 0, "rhtest_class", 0};
    void *hwnd;
    long r;
    wc.hInstance = GetModuleHandleA(0);
    if (!RegisterClassExA(&wc)) return 1;
    hwnd = CreateWindowExA(0, "rhtest_class", "rhtest", 0, 0, 0, 10, 10, 0, 0, wc.hInstance, 0);
    if (!hwnd) return 2;
    r = SendMessageA(hwnd, 0x8001, s, 0);
    DestroyWindow(hwnd);
    return g_msgs * 10 + (u32)(r + 5);
}
/* a byte-order mark read into a 4-byte local, written from its address plus an offset and
 * compared whole: where a function happens to sit at the mark's value (UTF-8's EF BB BF, 0xbfbbef
 * in CrystalCore's image), Ghidra types the local `code *`, and the write through `&mark + k` is
 * no arithmetic on the pointer (the CRT's _tsopen_nolock was a stub for it) */
NOINLINE u32 bom_kind(const u8 *text, u32 n) {
    u32 mark = 0, k;
    for (k = 0; k < 3 && k < n; k++) *((u8 *)&mark + k) = text[k];
    if (mark == 0xbfbbef) return 8;
    if ((mark & 0xffff) == 0xfeff) return 16;
    return 0;
}
NOINLINE u32 framed_calls(u32 s) {
    u32 r = 0, k;
    for (k = 0; k < 7; k++) r = r * 33 + framed_switch(s + k, s * 5 + k, k * 11);
    return r;
}

void rhtest_run(void) {
    u32 s = seed();   /* 7 */
    check("tls_static", tls_static(s));
    check("tls_api", tls_api(s));
    check("rotates", rotates(0x12345678u * s, (int)s));
    check("swaps", swaps(0xA1B2C3D4u ^ s));
    check64("swap64", swap64(0x0102030405060708ull * s));
    check("scans", scans(0x00F0F000u >> (s & 3)));
    check("bits", bits(0x5A5A5A5Au ^ s, s));
    check("popcount", popcount(0xF0F0F0F1u * s));
    check64("mulhi", mulhi(0xFFFFFFF0u + s, 0x80000001u));
    check("atomics", atomics(s));
    check("bitfields", bitfields(s));
    check("stack_alloc", stack_alloc(s));
    check("jumps", jumps(s));
    check64("filled", filled(s));
    check("framed_switch", framed_calls(s));
    check("code_page", code_page(s));
    check("window_class", window_class(s));
    {
        static const u8 utf8[] = {0xef, 0xbb, 0xbf, 'x'}, utf16[] = {0xff, 0xfe, 'x', 0};
        check("bom_kind", bom_kind(utf8, 4) * 100 + bom_kind(utf16, s & 3) * 10 + bom_kind(utf8 + 3, 1));
    }
}
