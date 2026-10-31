/* The types and helpers Ghidra's decompilation of a 32-bit reference program uses, for building
   it as C in an x64 port (translate32.py writes against this header and copies it into the
   project's gen directory: edit it here, in Rhipper's runtime32/).

   The memory model. The reference's image is mapped at its own addresses, and everything it
   allocates, its heap and the stack its code runs on, sits below 2 GB (the runtime in
   runtime32/). So every address the reference stores fits its 4-byte slots, and widens to a
   host pointer exactly, by sign or zero extension alike. A pointer in a register or local is the
   host's own (8 bytes); a pointer stored in memory is 4 bytes: translate32.py spells every
   pointer that sits in memory as __ptr32 (`int **` -> `int * PTR32 *`), which MSVC reads and
   writes as 4 bytes and widens on use. Windows' pointer typedefs below are __ptr32 for the same
   reason: the reference's structures hold them in 4 bytes.

   Parameters cross every translated function as 32-bit integers or pointers the callee narrows
   itself (translate32.py), as the reference's own code passed them: a caller that hands over an
   `int` holding an address and one that hands over a pointer read the same. */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>             /* (a variadic function's argument block, translate32.py) */
/* The host. An x86 one under MSVC's dialect (the x64 port, clang's x86_64-pc-windows-msvc too, and
   bytes32.py's x86 fidelity build): this header calls its intrinsics, each the reference's own
   instruction. Any other (aarch64 Linux/Android under clang): each helper is C computing the x86
   instruction's result, and Windows' spellings are C11's. Its clang flags: -std=gnu17 (C23's `()` is `(void)`, and `code` is unprototyped) -fms-extensions
   (__ptr32) -fshort-wchar -fsigned-char -fno-strict-aliasing -fwrapv -ffp-contract=off
   -fno-delete-null-pointer-checks -U_FORTIFY_SOURCE */
#if defined(_M_IX86) || defined(_M_X64)
#define GEN_HOST_X86 1
#endif
#ifdef _WIN32
#define GEN_THREAD __declspec(thread)
#define GEN_ALIGN16 __declspec(align(16))
#elif defined(__cplusplus)
#define GEN_THREAD thread_local
#define GEN_ALIGN16 alignas(16)
#else
#define GEN_THREAD _Thread_local
#define GEN_ALIGN16 _Alignas(16)
#endif
/* this header's helpers: inlined always in the x86 fidelity build, where each is the reference's
   own instruction or none (a 64-bit argument pushed for an address's truncation, GEN_TOP, was a
   call the reference never made); a hint in the port */
#ifdef GEN_FIDELITY
#define GEN_INLINE __forceinline
#else
#define GEN_INLINE __inline
#endif

#define PTR32 __ptr32 __uptr

/* ---- Ghidra's integer types, at the reference's widths ------------------------------------- */
typedef unsigned char undefined;
typedef unsigned char undefined1;
typedef unsigned short undefined2;
typedef unsigned int undefined3;
typedef unsigned int undefined4;
typedef unsigned long long undefined5;
typedef unsigned long long undefined6;
typedef unsigned long long undefined7;
typedef unsigned long long undefined8;
typedef unsigned char byte;
typedef unsigned char uchar;
typedef unsigned char uint1;
typedef signed char sbyte;
typedef signed char int1;
typedef unsigned short ushort;
typedef unsigned short word;
typedef unsigned short wchar16;
typedef unsigned short uint2;
typedef short int2;
typedef unsigned int uint;
typedef unsigned int uint3;
typedef unsigned int uint4;
typedef unsigned int dword;
typedef int int3;
typedef int int4;
/* the reference's `long`, 4 bytes on x86 as on Win64: C's own on Windows, int where the host's long
   is 8 (LP64, aarch64 Linux/Android). translate32.py spells every long of the translation so
   (port_longs), and Windows' LONG and DWORD are these */
#if defined(__LP64__) || defined(_LP64)
typedef int gen_long;
typedef unsigned int gen_ulong;
#else
typedef long gen_long;
typedef unsigned long gen_ulong;
#endif
typedef gen_ulong ulong;                /* 4 bytes, as in the reference */
typedef long long longlong;
typedef unsigned long long ulonglong;
typedef unsigned long long qword;
typedef unsigned long long uint5;
typedef unsigned long long uint6;
typedef unsigned long long uint7;
typedef unsigned long long uint8;
typedef long long int5;
typedef long long int6;
typedef long long int7;
typedef long long int8;
typedef float float4;
typedef double float8;
typedef double float10;                 /* x87 extended: MSVC has no wider double */
typedef unsigned int gen_size32;        /* the reference's size_t (translate32.py spells it so) */
typedef unsigned int gen_ptrdiff32;
typedef long long __time64_t;

/* `code`: what Ghidra calls through. A function returning the reference's 32-bit register, its
   parameters unprototyped: each caller passes what Ghidra wrote, and the callee (a translated
   function) narrows every parameter to its 32 bits */
typedef unsigned int code();
/* a function pointer as the reference stores it: 4 bytes, an integer. MSVC drops __ptr32 from a
   pointer to a function (an 8-byte load of the slot), so translate32.py loads one as this and
   converts it to `code *` to call it */
typedef unsigned int gen_code32;
/* a function called through a pointer for its x87 result: every translated function returning one
   is entered as one returning a double (jumps.c's W_ entries) */
typedef double gen_fcode();
/* and for its edx:eax result: a translated function returning 8 bytes returns them in rax whole */
typedef unsigned long long gen_lcode();

/* The shadow trace (shadow32.py): every translated function records its entry and first four
   arguments while the runtime has tracing on (<ENV>_TRACE), to be compared call by call with the
   reference's own run. Off, the cost is a flag test */
extern int gen_trace_on;
void gen_trace_enter(unsigned int addr, unsigned int a0, unsigned int a1, unsigned int a2, unsigned int a3);
/* the reference's calling conventions, in bytes32.py's x86 build (GEN_FIDELITY) only: x64 has one
   convention, and the port's calls through pointers and the runtime's entry jumps assume the
   plain one. __thiscall, which C cannot declare, as __fastcall with edx a dummy after `this`:
   ecx `this`, the rest on the stack, the callee popping them, the same code (ret N) */
#ifdef GEN_FIDELITY
/* (and a virtual call's pointer, translate32's vcalls: __thiscall's code, unprototyped) */
typedef unsigned int __fastcall gen_tcode();
#define GEN_TCODE gen_tcode
#define GEN_STDCALL __stdcall
#define GEN_FASTCALL __fastcall
#define GEN_THISCALL __fastcall
#define GEN_EDX_PARAM , unsigned int gen_edx
#define GEN_EDX_ARG , 0
/* (a __thiscall function's own dummy handed on: edx as it came, nothing to set) */
#define GEN_EDX_FWD , gen_edx
/* (and each function's frame as the reference's: `push ebp; mov ebp, esp` or none, which
   VS2010's libraries mixed, per function as translate32 reads it off the reference) */
/* (and never inlined into another: each translation is a function the reference kept apart, its
   callers call it. Inlined, a test program's main was its callees' loops, 2.5 times the
   reference's size, rhtest core-O2's 0x4024d0) */
#define GEN_FRAME __pragma(optimize("y", off)) __declspec(noinline)
#define GEN_NOFRAME __pragma(optimize("y", on)) __declspec(noinline)
#else
#define GEN_EDX_FWD
#define GEN_FRAME
#define GEN_NOFRAME
#define GEN_TCODE code
#define GEN_STDCALL
#define GEN_FASTCALL
#define GEN_THISCALL
#define GEN_EDX_PARAM
#define GEN_EDX_ARG
#endif
/* a parameter, translate32.py's: in the x86 fidelity build the typed parameter itself, as the
   reference's source had it (a /Od build keeps every local in a stack slot, and the port's copy of
   each word into its type was a store and a load more); in the port its 32-bit word, and the copy
   into Ghidra's type a local (GEN_PIN) */
/* (a function's code generation in the x86 fidelity build: the program's own, as its command line
   gives it, GEN_OWN; or a static library's, the C runtime's, which its vendor built optimized
   whatever the program's options, GEN_LIB. The port: nothing) */
/* (and no security cookie of the compiler's: the reference's own is in the translation, its
   store of __security_cookie ^ esp and its __security_check_cookie call, and /GS put a second
   around every frame buffer, gen_frame) */
#ifdef GEN_FIDELITY
#define GEN_OWN __pragma(optimize("", on)) __declspec(safebuffers)
#define GEN_LIB __pragma(optimize("gt", on)) __declspec(safebuffers)
#define GEN_OWN_GS __pragma(optimize("", on))
#define GEN_LIB_GS __pragma(optimize("gt", on))
#else
#define GEN_OWN
#define GEN_LIB
#define GEN_OWN_GS
#define GEN_LIB_GS
#endif
/* (a function that never returns, so declared where the reference's compiler knew it: the x86
   fidelity build's code after the call as the reference's, none) */
#ifdef GEN_FIDELITY
#define GEN_NORETURN __declspec(noreturn)
#else
#define GEN_NORETURN
#endif
/* (an import in the x86 fidelity build: called through its import table slot as the reference's
   code calls it, translated.h; the port's is its adapter, imports.c) */
#ifdef GEN_FIDELITY
#define GEN_DLLIMPORT __declspec(dllimport)
#else
#define GEN_DLLIMPORT
#endif
#ifdef GEN_FIDELITY
#define GEN_P(typed, abi) typed
#define GEN_PIN(...)
#else
#define GEN_P(typed, abi) abi
#define GEN_PIN(...) __VA_ARGS__
#endif
/* the reference's frame as one buffer of n bytes, translate32's frame_locals: in the port 16-byte
   aligned, pad bytes in front rounding it to 16; in the x86 fidelity build the frame alone, as the
   reference's, its locals 4-byte aligned under esp, where align(16) made every one `and esp, -16`
   in an ebp frame of its own and the rounding `sub esp, 0x10` for a one-DWORD `push ecx` (rhtest
   core-O2 0x402970) */
/* (and a frame whose top word is the reference's /GS cookie, translate32's frame_cookie: in the x86
   build the compiler's own /GS lays it, GEN_OWN_GS without safebuffers, so the frame without the
   word and GEN_COOKIE's store nothing. The port stores it as the reference does) */
/* (_TOP: an ebp frame's, its top bytes the saved ebp, none of the x86 build's frame) */
#ifdef GEN_FIDELITY
#define GEN_FRAME_DECL(n, pad) undefined1 gen_frame[n]
#define GEN_FRAME_DECL_TOP(n, pad, top) undefined1 gen_frame[(n) - (top)]
#define GEN_FRAME_DECL_GS(n, pad, top) undefined1 gen_frame[(n) - (top) - 4]
#define GEN_COOKIE(...) ((void)0)
#else
#define GEN_FRAME_DECL(n, pad) GEN_ALIGN16 undefined1 gen_frame_[(pad) + (n)]; \
    undefined1 *const gen_frame = gen_frame_ + (pad)
#define GEN_FRAME_DECL_TOP(n, pad, top) GEN_FRAME_DECL(n, pad)
#define GEN_FRAME_DECL_GS(n, pad, top) GEN_FRAME_DECL(n, pad)
#define GEN_COOKIE(...) __VA_ARGS__
#endif
/* a 32-bit shift's count, translate32's shift_counts: the decompiler's `n & 0x1f` for `shr r32,
   cl`, which masks it itself. The port keeps the mask; the x86 fidelity build shifts by the count
   bare, the instruction's own masking, as the reference's code has no `and ecx, 0x1f` */
#ifdef GEN_FIDELITY
#define GEN_SHC(masked, bare) (bare)
#else
#define GEN_SHC(masked, bare) ((masked) & 0x1f)
#endif
/* (GEN_FIDELITY: nothing, bytes32.py's x86 build, compared byte for byte with the reference) */
#ifdef GEN_FIDELITY
#define GEN_ENTER(addr, a0, a1, a2, a3) ((void)0)
#else
#define GEN_ENTER(addr, a0, a1, a2, a3) \
    do { if (gen_trace_on) gen_trace_enter((addr), (a0), (a1), (a2), (a3)); } while (0)
#endif
/* (a function translate32 found reading a local it never assigns, a register the decompiler lost and
   named like a variable: its first call logged, by name, `<name>: suspect F_x ran (this_00)` -- what
   would be a silent miscompile, a UI hit test handed its node a code address, 2026-10-28) */
void gen_suspect(unsigned int addr, const char *names);
#ifdef GEN_FIDELITY
#define GEN_SUSPECT(addr, names) ((void)0)
#else
#define GEN_SUSPECT(addr, names) \
    do { static volatile int gen_s_; if (!gen_s_) { gen_s_ = 1; gen_suspect((addr), (names)); } } while (0)
#endif
/* (a float or 8-byte argument's stack words, as the reference's record holds them: its bits, not
   its value converted, pi/4 recorded as 0 parted a client's runs at a sincos, 2026-10-26) */
static GEN_INLINE unsigned int gen_trace_f(float f) { union { float f; unsigned int u; } v; v.f = f; return v.u; }
static GEN_INLINE unsigned long long gen_trace_d(double d) { union { double d; unsigned long long u; } v; v.d = d; return v.u; }
/* the x87 unit's control word, per thread as the hardware's is: what `fnstcw` reads and `fldcw`
   writes in the translation (MSVC's default 0x27f; Direct3D's CreateDevice sets 24-bit
   precision, Com32.cpp). The port computes in SSE whatever it says: the code that reads it, the
   CRT's math choosing its paths by the precision, takes the reference's way */
extern GEN_THREAD unsigned short gen_x87_cw;
/* (`fldcw`'s write: the word, and its rounding control applied to the host's SSE rounding) */
void gen_set_x87_cw(unsigned short cw);
/* an x87 result under the control word's precision control, translate32's x87_precision: at 24
   bits (PC 00, _PC_24, what Direct3D's CreateDevice sets) the reference's unit rounds each result's
   mantissa to a float's, in the rounding mode (the host's SSE has it too, gen_set_x87_cw), so
   `1.0 / 3.0` is 0x3fd5555560000000. 53 bits and 64 are the double's (the host has no wider).
   Outside a float's range the value as it is: the x87 keeps its own exponent there */
#ifdef GEN_FIDELITY
#define GEN_X87(x) (x)
#else
static GEN_INLINE double gen_x87_pc24(double v) {
    double a = v < 0 ? -v : v;
    return a <= 3.4028234663852886e38 && a >= 1.1754943508222875e-38 ? (double)(float)v : v;
}
static GEN_INLINE double gen_x87(double v) { return (gen_x87_cw & 0x300) ? v : gen_x87_pc24(v); }
#define GEN_X87(x) gen_x87(x)
#endif
/* and its status word, `fnstsw`: the host's floating-point exception flags as x87 bits (IE 1,
   DE 2, ZE 4, OE 8, UE 0x10, PE 0x20), cleared after the read when `clear` (fnclex) */
unsigned short gen_fpusw(int clear);
/* `cdq; idiv r32`: a 32-bit signed division, as the reference's, faulting where it faults (a zero
   divisor, EXCEPTION_INT_DIVIDE_BY_ZERO; INT_MIN / -1, EXCEPTION_INT_OVERFLOW), the divisor read
   through a volatile so the host compiler neither folds nor reorders the instruction away */
#ifdef GEN_HOST_X86
static GEN_INLINE int gen_idiv32(int a, int b) { volatile int d = b; return a / d; }
static GEN_INLINE int gen_irem32(int a, int b) { volatile int d = b; return a % d; }
#else
/* (aarch64's sdiv faults on neither, 0 for a zero divisor and INT_MIN for the overflow: the fault
   raised as the reference's exception by the runtime, gen_int_fault, which returns only if a
   handler continues; then 0, x86 having no result to give) */
void gen_int_fault(unsigned int code);
static GEN_INLINE int gen_idiv_ok(int a, int b) {
    if (b == 0) { gen_int_fault(0xc0000094u); return 0; }                     /* INT_DIVIDE_BY_ZERO */
    if (b == -1 && a == (int)0x80000000) { gen_int_fault(0xc0000095u); return 0; }   /* INT_OVERFLOW */
    return 1;
}
static GEN_INLINE int gen_idiv32(int a, int b) { return gen_idiv_ok(a, b) ? a / b : 0; }
static GEN_INLINE int gen_irem32(int a, int b) { return gen_idiv_ok(a, b) ? a % b : 0; }
#endif
/* an SSE register's 16 bytes, as Ghidra writes one (`undefined1 [16]`): an array, so a pointer
   to one steps 16 and indexes its bytes as the reference does. An array is not assignable: a
   value stored into one (`*p = (undefined1 [16])0x0`) is GEN_V16_SET's, zero-extended */
typedef unsigned char gen_v16[16];
/* (and the other sizes Ghidra points to as `undefined1 (*p) [n]`: a vector of three floats, 12) */
typedef unsigned char gen_v8[8];
typedef unsigned char gen_v12[12];
typedef unsigned char gen_v24[24];
typedef unsigned char gen_v32[32];
typedef unsigned char gen_v48[48];
typedef unsigned char gen_v64[64];
#define GEN_V16_SET(lhs, v) do { unsigned long long gen_v16_lo_ = (unsigned long long)(v); \
    memset((lhs), 0, 16); memcpy((lhs), &gen_v16_lo_, 8); } while (0)

/* Ghidra's SSE pseudo-ops (`auVar9 = rsqrtps(in_XMM3, auVar1)`: the instruction's destination
   register first, then its source), each through the same instruction's intrinsic, so a result
   is the reference's to the bit (rsqrtps and rcpps are the hardware's approximations). Operands
   and results are 16 bytes anywhere: translate32.py passes their addresses, the result first */
#include <math.h>
#ifdef GEN_HOST_X86
#include <emmintrin.h>
static GEN_INLINE __m128 gen_ldps(const void *p) { return _mm_loadu_ps((const float *)p); }
static GEN_INLINE __m128i gen_ldi(const void *p) { return _mm_loadu_si128((const __m128i *)p); }
static GEN_INLINE void gen_stps(void *p, __m128 v) { _mm_storeu_ps((float *)p, v); }
static GEN_INLINE void gen_sti(void *p, __m128i v) { _mm_storeu_si128((__m128i *)p, v); }
/* (a function's 16-byte result, protos32.py's "v16", Ghidra's `undefined1 [16]` in xmm0: an __m128,
   which C returns where it cannot an array, and in xmm0 as the reference's code does under x86's
   convention. translate32's v16_forms returns the body's 16 bytes through GEN_R16 and stores a
   call's into its local through GEN_R16_SET. 0x666280's rsqrtps, 2026-10-30) */
typedef __m128 gen_r16;
#define GEN_R16(a) gen_ldps(a)
#define GEN_R16_SET(lhs, v) gen_stps(&(lhs), (v))
/* (a stub's: its lanes 0, as C converts no 0 to an __m128, 2026-10-30) */
#define GEN_R16_ZERO _mm_setzero_ps()
static GEN_INLINE void gen_minps(void *r, const void *a, const void *b) { gen_stps(r, _mm_min_ps(gen_ldps(a), gen_ldps(b))); }
static GEN_INLINE void gen_maxps(void *r, const void *a, const void *b) { gen_stps(r, _mm_max_ps(gen_ldps(a), gen_ldps(b))); }
static GEN_INLINE void gen_divps(void *r, const void *a, const void *b) { gen_stps(r, _mm_div_ps(gen_ldps(a), gen_ldps(b))); }
static GEN_INLINE void gen_rsqrtps(void *r, const void *d, const void *s) { (void)d; gen_stps(r, _mm_rsqrt_ps(gen_ldps(s))); }
static GEN_INLINE void gen_rcpps(void *r, const void *d, const void *s) { (void)d; gen_stps(r, _mm_rcp_ps(gen_ldps(s))); }
static GEN_INLINE void gen_sqrtps(void *r, const void *d, const void *s) { (void)d; gen_stps(r, _mm_sqrt_ps(gen_ldps(s))); }
static GEN_INLINE void gen_packssdw(void *r, const void *a, const void *b) { gen_sti(r, _mm_packs_epi32(gen_ldi(a), gen_ldi(b))); }
static GEN_INLINE void gen_psllw(void *r, const void *a, const void *n) { gen_sti(r, _mm_sll_epi16(gen_ldi(a), gen_ldi(n))); }
/* (SSE4.1: MSVC's /O2 vectorizes an integer multiply loop with it, behind __isa_available) */
#include <smmintrin.h>
static GEN_INLINE void gen_pmulld(void *r, const void *a, const void *b) { gen_sti(r, _mm_mullo_epi32(gen_ldi(a), gen_ldi(b))); }
static GEN_INLINE void gen_v16_or(void *r, const void *a, const void *b) { gen_sti(r, _mm_or_si128(gen_ldi(a), gen_ldi(b))); }
static GEN_INLINE void gen_v16_and(void *r, const void *a, const void *b) { gen_sti(r, _mm_and_si128(gen_ldi(a), gen_ldi(b))); }
static GEN_INLINE void gen_v16_xor(void *r, const void *a, const void *b) { gen_sti(r, _mm_xor_si128(gen_ldi(a), gen_ldi(b))); }
/* movmskps(dst, src): the sign bits of src's four floats */
static GEN_INLINE int gen_movmskps(const void *s) { return _mm_movemask_ps(gen_ldps(s)); }
#else
/* (another host: each op in C over the 16 bytes, lane by lane as the instruction. A NaN is x86's:
   an operand's that is one, the first, quieted; else the one an invalid operation makes, x86's
   negative "indefinite" 0xffc00000, where aarch64 makes 0x7fc00000. MINPS and MAXPS by their
   compare, the second operand for a NaN or two zeros, where aarch64's fmin and fmax differ) */
typedef float gen_r16 __attribute__((vector_size(16)));        /* in v0, as __m128 in xmm0 */
static GEN_INLINE gen_r16 gen_ldps(const void *p) { gen_r16 v; memcpy(&v, p, 16); return v; }
static GEN_INLINE void gen_stps(void *p, gen_r16 v) { memcpy(p, &v, 16); }
#define GEN_R16(a) gen_ldps(a)
#define GEN_R16_SET(lhs, v) gen_stps(&(lhs), (v))
#define GEN_R16_ZERO ((gen_r16){0.0f, 0.0f, 0.0f, 0.0f})
static GEN_INLINE unsigned int gen_fbits_(float f) { unsigned int u; memcpy(&u, &f, 4); return u; }
static GEN_INLINE float gen_bitsf_(unsigned int u) { float f; memcpy(&f, &u, 4); return f; }
static GEN_INLINE int gen_fnan_(unsigned int u) { return (u & 0x7fffffffu) > 0x7f800000u; }
#define GEN_SSE_INDEFINITE 0xffc00000u
static GEN_INLINE float gen_divss_(float a, float b) {
    unsigned int ua = gen_fbits_(a), ub = gen_fbits_(b);
    float q;
    if (gen_fnan_(ua)) return gen_bitsf_(ua | 0x400000u);
    if (gen_fnan_(ub)) return gen_bitsf_(ub | 0x400000u);
    q = a / b;
    return q != q ? gen_bitsf_(GEN_SSE_INDEFINITE) : q;
}
static GEN_INLINE float gen_sqrtss_(float s) {
    unsigned int u = gen_fbits_(s);
    if (gen_fnan_(u)) return gen_bitsf_(u | 0x400000u);
    return s < 0.0f ? gen_bitsf_(GEN_SSE_INDEFINITE) : sqrtf(s);
}
/* (rcpps and rsqrtps are the hardware's approximations, |relative error| <= 1.5 * 2^-12, Intel's
   and AMD's tables apart: here the value itself rounded to a float, which matches neither in the
   low 11 or so bits of the mantissa. Their edges are the SDM's: a denormal source is 0, so an
   infinity of its sign; a result below a float's normal range is 0; a negative square root the
   indefinite NaN) */
static GEN_INLINE float gen_rcpss_(float s) {
    unsigned int u = gen_fbits_(s), sign = u & 0x80000000u;
    float q;
    if (gen_fnan_(u)) return gen_bitsf_(u | 0x400000u);
    if (!(u & 0x7f800000u)) return gen_bitsf_(sign | 0x7f800000u);
    q = 1.0f / s;
    return (gen_fbits_(q) & 0x7f800000u) ? q : gen_bitsf_(sign);
}
static GEN_INLINE float gen_rsqrtss_(float s) {
    unsigned int u = gen_fbits_(s), sign = u & 0x80000000u;
    if (gen_fnan_(u)) return gen_bitsf_(u | 0x400000u);
    if (!(u & 0x7f800000u)) return gen_bitsf_(sign | 0x7f800000u);
    if (sign) return gen_bitsf_(GEN_SSE_INDEFINITE);
    return (float)(1.0 / sqrt((double)s));
}
#define GEN_PS2(name, expr) \
    static GEN_INLINE void name(void *r, const void *a_, const void *b_) { \
        float a[4], b[4]; memcpy(a, a_, 16); memcpy(b, b_, 16); \
        for (int k = 0; k < 4; k++) a[k] = (expr); memcpy(r, a, 16); }
#define GEN_PS1(name, expr) \
    static GEN_INLINE void name(void *r, const void *d_, const void *s_) { \
        float s[4]; (void)d_; memcpy(s, s_, 16); \
        for (int k = 0; k < 4; k++) s[k] = (expr); memcpy(r, s, 16); }
GEN_PS2(gen_minps, a[k] < b[k] ? a[k] : b[k])
GEN_PS2(gen_maxps, a[k] > b[k] ? a[k] : b[k])
GEN_PS2(gen_divps, gen_divss_(a[k], b[k]))
GEN_PS1(gen_rsqrtps, gen_rsqrtss_(s[k]))
GEN_PS1(gen_rcpps, gen_rcpss_(s[k]))
GEN_PS1(gen_sqrtps, gen_sqrtss_(s[k]))
/* (a's four dwords then b's, each saturated to a signed word) */
static GEN_INLINE void gen_packssdw(void *r, const void *a, const void *b) {
    int x[8]; short t[8];
    memcpy(x, a, 16); memcpy(x + 4, b, 16);
    for (int k = 0; k < 8; k++) t[k] = (short)(x[k] > 32767 ? 32767 : x[k] < -32768 ? -32768 : x[k]);
    memcpy(r, t, 16);
}
/* (each word by the count's whole low qword, 0 past 15) */
static GEN_INLINE void gen_psllw(void *r, const void *a, const void *n) {
    unsigned short x[8]; unsigned long long c;
    memcpy(x, a, 16); memcpy(&c, n, 8);
    for (int k = 0; k < 8; k++) x[k] = c > 15 ? 0 : (unsigned short)(x[k] << c);
    memcpy(r, x, 16);
}
static GEN_INLINE void gen_pmulld(void *r, const void *a, const void *b) {
    unsigned int x[4], y[4];
    memcpy(x, a, 16); memcpy(y, b, 16);
    for (int k = 0; k < 4; k++) x[k] *= y[k];
    memcpy(r, x, 16);
}
#define GEN_V16_BIN(name, op) \
    static GEN_INLINE void name(void *r, const void *a, const void *b) { \
        unsigned long long x[2], y[2]; memcpy(x, a, 16); memcpy(y, b, 16); \
        x[0] = x[0] op y[0]; x[1] = x[1] op y[1]; memcpy(r, x, 16); }
GEN_V16_BIN(gen_v16_or, |)
GEN_V16_BIN(gen_v16_and, &)
GEN_V16_BIN(gen_v16_xor, ^)
/* movmskps(dst, src): the sign bits of src's four floats */
static GEN_INLINE int gen_movmskps(const void *s) {
    unsigned int x[4];
    memcpy(x, s, 16);
    return (int)(x[0] >> 31 | (x[1] >> 31) << 1 | (x[2] >> 31) << 2 | (x[3] >> 31) << 3);
}
#endif
/* (AVX2's per-lane shift, the 128-bit form, behind __isa_available as /O2 vectorizes `w << (k & 7)`:
   in C, each lane by its own count, 0 past 31, so the port needs no AVX2 of its own) */
static GEN_INLINE void gen_vpsllvd_avx2(void *r, const void *a, const void *n) {
    unsigned int x[4], c[4];
    memcpy(x, a, 16); memcpy(c, n, 16);
    for (int k = 0; k < 4; k++) x[k] = c[k] > 31 ? 0 : x[k] << c[k];
    memcpy(r, x, 16);
}
/* (AVX-512VL's float to 64-bit integer conversion, truncating, the 128-bit form: its two low
   floats, behind __isa_available as MSVC 14.51 converts a float to u64. In C, the hardware's
   0x8000000000000000 for a NaN or one out of range, so the port needs no AVX-512 of its own) */
static GEN_INLINE void gen_vcvttps2qq_avx512vl(void *r, const void *a) {
    float f[4]; long long q[2];
    memcpy(f, a, 16);
    for (int k = 0; k < 2; k++)
        q[k] = (f[k] != f[k] || f[k] >= 9223372036854775808.0f || f[k] < -9223372036854775808.0f)
            ? (long long)0x8000000000000000ull : (long long)f[k];
    memcpy(r, q, 16);
}

/* ---- vectors of any width, as vec32.py writes Ghidra's (the static C runtime's and C++ library's
   AVX2 and SSE4.2 string and search routines, behind __isa_available, rhtest stl /MT). A value is
   its bytes somewhere, little-endian; each helper writes its result to r (n bytes) after reading
   all of its operands, so r may be one of them. In C, so the port needs none of the instructions */
static const unsigned char gen_vzero[64] = {0};
/* (a scalar's m bytes zero-extended to 64) */
static GEN_INLINE void gen_vzext(void *r, unsigned long long v, int m) {
    unsigned char t[64] = {0};
    memcpy(t, &v, (size_t)m); memcpy(r, t, 64);
}
/* (n bytes of a w-byte vector's value shifted right by `bit` bits, 0 past its end: Ghidra's
   SUBwn(v >> bit, 0)) */
static GEN_INLINE unsigned long long gen_vbits(const void *p, int w, int bit, int n) {
    const unsigned char *b = (const unsigned char *)p;
    unsigned long long v = 0;
    for (int k = 0; k < 8 * n; k++) {
        int at = bit + k;
        if (at >= 0 && at < 8 * w && (b[at >> 3] >> (at & 7) & 1)) v |= 1ull << k;
    }
    return v;
}
/* (a copy: the destination's w bytes from the value's m, zero beyond) */
static GEN_INLINE void gen_vset(void *r, int w, const void *a, int m) {
    unsigned char t[64] = {0};
    memcpy(t, a, (size_t)(m < w ? m : w)); memcpy(r, t, (size_t)w);
}
static GEN_INLINE void gen_vcat(void *r, const void *hi, int mh, const void *lo, int ml) {
    unsigned char t[64] = {0};
    memcpy(t, lo, (size_t)ml); memcpy(t + ml, hi, (size_t)mh); memcpy(r, t, 64);
}
static GEN_INLINE void gen_vbin(void *r, const void *a, const void *b, int n, char op) {
    unsigned char t[64];
    const unsigned char *x = (const unsigned char *)a, *y = (const unsigned char *)b;
    for (int k = 0; k < n; k++) t[k] = op == '&' ? x[k] & y[k] : op == '|' ? x[k] | y[k] : x[k] ^ y[k];
    memcpy(r, t, (size_t)n);
}
static GEN_INLINE void gen_vnot(void *r, const void *a, int n) {
    unsigned char t[64];
    for (int k = 0; k < n; k++) t[k] = (unsigned char)~((const unsigned char *)a)[k];
    memcpy(r, t, (size_t)n);
}
/* (an n-byte value shifted by k bits, right or left, zeros in) */
static GEN_INLINE void gen_vshift(void *r, const void *a, int n, int k, int right) {
    unsigned char t[64] = {0};
    const unsigned char *b = (const unsigned char *)a;
    for (int i = 0; i < 8 * n; i++) {
        int from = right ? i + k : i - k;
        if (from >= 0 && from < 8 * n && (b[from >> 3] >> (from & 7) & 1)) t[i >> 3] |= (unsigned char)(1 << (i & 7));
    }
    memcpy(r, t, (size_t)n);
}
static GEN_INLINE int gen_vcmp(const void *a, const void *b, int n) { return memcmp(a, b, (size_t)n) != 0; }
/* (the lanes, each op as the instruction: a byte, word or dword lane of a and b) */
#define GEN_VLANES(name, T, expr) \
    static GEN_INLINE void name(void *r, const void *a, const void *b, int n) { \
        T x[64 / sizeof(T)], y[64 / sizeof(T)]; memcpy(x, a, (size_t)n); memcpy(y, b, (size_t)n); \
        for (int k = 0; k < n / (int)sizeof(T); k++) x[k] = (T)(expr); memcpy(r, x, (size_t)n); }
GEN_VLANES(gen_vpcmpeqb, unsigned char, x[k] == y[k] ? 0xff : 0)
GEN_VLANES(gen_vpcmpeqw, unsigned short, x[k] == y[k] ? 0xffff : 0)
GEN_VLANES(gen_vpcmpeqd, unsigned int, x[k] == y[k] ? 0xffffffffu : 0)
GEN_VLANES(gen_vpcmpgtd, unsigned int, (int)x[k] > (int)y[k] ? 0xffffffffu : 0)
GEN_VLANES(gen_vpminsd, unsigned int, (int)x[k] < (int)y[k] ? x[k] : y[k])
GEN_VLANES(gen_vpmaxsd, unsigned int, (int)x[k] > (int)y[k] ? x[k] : y[k])
GEN_VLANES(gen_vpminud, unsigned int, x[k] < y[k] ? x[k] : y[k])
GEN_VLANES(gen_vpsubd, unsigned int, x[k] - y[k])
GEN_VLANES(gen_vpand, unsigned char, x[k] & y[k])
/* (vpblendvb(a, b, mask), pblendvb's too: each byte b's where the mask byte's top bit is set) */
static GEN_INLINE void gen_vpblendvb(void *r, const void *a, const void *b, const void *m, int n) {
    unsigned char t[64];
    for (int k = 0; k < n; k++)
        t[k] = (((const unsigned char *)m)[k] & 0x80) ? ((const unsigned char *)b)[k] : ((const unsigned char *)a)[k];
    memcpy(r, t, (size_t)n);
}
/* (pshufb(data, control): within each 16-byte lane, the data byte the control's low 4 bits name,
   0 where its top bit is set) */
static GEN_INLINE void gen_vpshufb(void *r, const void *a, const void *c, int n) {
    unsigned char t[64];
    const unsigned char *x = (const unsigned char *)a, *s = (const unsigned char *)c;
    for (int k = 0; k < n; k++) t[k] = (s[k] & 0x80) ? 0 : x[(k & ~15) + (s[k] & 15)];
    memcpy(r, t, (size_t)n);
}
/* (vpshufd(src, imm): within each 16-byte lane, dword i the one imm's bits 2i..2i+1 name) */
static GEN_INLINE void gen_vpshufd(void *r, const void *a, int imm, int n) {
    unsigned int x[16], t[16];
    memcpy(x, a, (size_t)n);
    for (int k = 0; k < n / 4; k++) t[k] = x[(k & ~3) + (imm >> (2 * (k & 3)) & 3)];
    memcpy(r, t, (size_t)n);
}
/* (vpermq(src, imm): qword i the one imm's bits 2i..2i+1 name, across the 32 bytes) */
static GEN_INLINE void gen_vpermq(void *r, const void *a, int imm, int n) {
    unsigned long long x[4], t[4];
    (void)n; memcpy(x, a, 32);
    for (int k = 0; k < 4; k++) t[k] = x[imm >> (2 * k) & 3];
    memcpy(r, t, 32);
}
/* (vpermd(indices, src): dword i the source's dword the index dword's low three bits name) */
static GEN_INLINE void gen_vpermd(void *r, const void *idx, const void *a, int n) {
    unsigned int x[8], ix[8], t[8];
    (void)n; memcpy(ix, idx, 32); memcpy(x, a, 32);
    for (int k = 0; k < 8; k++) t[k] = x[ix[k] & 7];
    memcpy(r, t, 32);
}
/* (vpmaskmovd(mask, mem): each dword of mem where the mask dword's top bit is set, else 0; the
   others are not read, as the instruction does not fault on them) */
static GEN_INLINE void gen_vpmaskmovd(void *r, const void *m, const void *p, int n) {
    unsigned int t[16], mk[16];
    memcpy(mk, m, (size_t)n);
    for (int k = 0; k < n / 4; k++) {
        t[k] = 0;
        if (mk[k] & 0x80000000u) memcpy(&t[k], (const unsigned char *)p + 4 * k, 4);
    }
    memcpy(r, t, (size_t)n);
}
/* (pshuflw(dst, src, imm): the low four words src's by imm, the high eight bytes src's) */
static GEN_INLINE void gen_pshuflw(void *r, const void *d, const void *a, int imm, int n) {
    unsigned short x[8], t[8];
    (void)d; (void)n; memcpy(x, a, 16); memcpy(t, x, 16);
    for (int k = 0; k < 4; k++) t[k] = x[imm >> (2 * k) & 3];
    memcpy(r, t, 16);
}
/* (roundsd(dst, src, imm): src's low double rounded by imm's mode, or the current one where imm
   has bit 2; the high eight bytes dst's) */
#include <math.h>
static GEN_INLINE void gen_roundsd(void *r, const void *d, const void *a, int imm, int n) {
    double x, y; unsigned char t[16];
    (void)n; memcpy(t, d, 16); memcpy(&x, a, 8);
    switch ((imm & 4) ? 4 : (imm & 3)) {
    case 0: y = floor(x + 0.5); if (y - x == 0.5 && fmod(y, 2.0) != 0.0) y -= 1.0;
            if (x != x || fabs(x) >= 4503599627370496.0) y = x; break;
    case 1: y = floor(x); break;
    case 2: y = ceil(x); break;
    case 3: y = trunc(x); break;
    default: y = nearbyint(x); break;
    }
    memcpy(t, &y, 8); memcpy(r, t, 16);
}
/* (SSE4.2's string compares, PCMPESTRI and PCMPISTRI: the instruction's IntRes2 for imm, a and b
   of la and lb elements (explicit), or up to each one's first 0 (implicit); the index in ecx and
   the flags, CF 1, ZF 2, SF 4, OF 8, as the decompiler's pcmpestri_flags reads them) */
static GEN_INLINE unsigned gen_pcmpstr(const void *a, int la, const void *b, int lb, int imm, int implicit,
                                       unsigned *flags) {
    int words = imm & 1, sgn = imm & 2, n = words ? 8 : 16, agg = imm >> 2 & 3, pol = imm >> 4 & 3;
    int ea[16], eb[16];
    for (int k = 0; k < n; k++) {
        ea[k] = words ? (sgn ? (int)((const short *)a)[k] : (int)((const unsigned short *)a)[k])
                      : (sgn ? (int)((const signed char *)a)[k] : (int)((const unsigned char *)a)[k]);
        eb[k] = words ? (sgn ? (int)((const short *)b)[k] : (int)((const unsigned short *)b)[k])
                      : (sgn ? (int)((const signed char *)b)[k] : (int)((const unsigned char *)b)[k]);
    }
    if (implicit) {
        la = n; lb = n;
        for (int k = 0; k < n; k++) if (ea[k] == 0) { la = k; break; }
        for (int k = 0; k < n; k++) if (eb[k] == 0) { lb = k; break; }
    } else {
        la = la < 0 ? (la < -n ? n : -la) : (la > n ? n : la);
        lb = lb < 0 ? (lb < -n ? n : -lb) : (lb > n ? n : lb);
    }
    unsigned res = 0;
    for (int j = 0; j < n; j++) {
        int bit = 0;
        if (agg == 0) {                                   /* equal any */
            for (int i = 0; i < la && j < lb; i++) if (ea[i] == eb[j]) bit = 1;
        } else if (agg == 1) {                            /* ranges */
            for (int i = 0; i + 1 < la && j < lb; i += 2) if (ea[i] <= eb[j] && eb[j] <= ea[i + 1]) bit = 1;
        } else if (agg == 2) {                            /* equal each */
            bit = (j >= la && j >= lb) ? 1 : (j >= la || j >= lb) ? 0 : ea[j] == eb[j];
        } else {                                          /* equal ordered */
            /* (an element of a past its length matches; one of b past its, against a valid one of
               a, does not) */
            bit = 1;
            for (int i = 0; i < n - j; i++) {
                int ok = i >= la ? 1 : (j + i >= lb ? 0 : ea[i] == eb[j + i]);
                if (!ok) { bit = 0; break; }
            }
        }
        res |= (unsigned)bit << j;
    }
    unsigned mask = (1u << n) - 1, r2 = res;
    if (pol == 1) r2 = ~res & mask;
    else if (pol == 3) for (int j = 0; j < lb && j < n; j++) r2 ^= 1u << j;
    r2 &= mask;
    unsigned idx = (unsigned)n;
    if (r2) {
        if (imm & 0x40) { idx = 0; for (int j = n - 1; j >= 0; j--) if (r2 >> j & 1) { idx = (unsigned)j; break; } }
        else { for (int j = 0; j < n; j++) if (r2 >> j & 1) { idx = (unsigned)j; break; } }
    }
    *flags = (r2 != 0 ? 1u : 0u) | (lb < n ? 2u : 0u) | (la < n ? 4u : 0u) | ((r2 & 1) ? 8u : 0u);
    return idx;
}
static GEN_INLINE unsigned gen_pcmpestri(const void *a, const void *b, int imm, int la, int lb) {
    unsigned f; return gen_pcmpstr(a, la, b, lb, imm, 0, &f);
}
static GEN_INLINE unsigned gen_pcmpestri_flags(const void *a, const void *b, int imm, int la, int lb) {
    unsigned f; gen_pcmpstr(a, la, b, lb, imm, 0, &f); return f;
}
static GEN_INLINE unsigned gen_pcmpistri(const void *a, const void *b, int imm) {
    unsigned f; return gen_pcmpstr(a, 0, b, 0, imm, 1, &f);
}
static GEN_INLINE unsigned gen_pcmpistri_flags(const void *a, const void *b, int imm) {
    unsigned f; gen_pcmpstr(a, 0, b, 0, imm, 1, &f); return f;
}
/* (Ghidra's LZCOUNT of a 4-byte value: lzcnt's, 32 for 0) */
static GEN_INLINE unsigned gen_lzcount(unsigned int x) {
    unsigned n = 0;
    if (!x) return 32;
    while (!(x & 0x80000000u)) { x <<= 1; n++; }
    return n;
}
#define LZCOUNT(x) gen_lzcount((unsigned int)(x))
typedef void *pointer;                  /* a value; translate32.py makes a stored one __ptr32 */

/* ---- Windows' pointer-sized types, 4 bytes as the reference stores them --------------------- */
typedef void * PTR32 HANDLE;
typedef void * PTR32 HMODULE;
typedef void * PTR32 HINSTANCE;
typedef void * PTR32 HWND;
typedef void * PTR32 HDC;
typedef void * PTR32 HKEY;
typedef void * PTR32 HICON;
typedef void * PTR32 HCURSOR;
typedef void * PTR32 HMENU;
typedef void * PTR32 HBRUSH;
typedef void * PTR32 HGLOBAL;
typedef void * PTR32 HLOCAL;
typedef void * PTR32 HKL;
typedef void * PTR32 HGDIOBJ;
typedef void * PTR32 HIMC;
/* (no const on the LPC* ones: the reference writes through what Ghidra typed LPCWSTR, `*lpFilename
   = L'/'`, and C refuses that through a const pointer) */
typedef void * PTR32 LPVOID;
typedef void * PTR32 PVOID;
typedef void * PTR32 LPCVOID;
typedef char * PTR32 LPSTR;
typedef char * PTR32 LPCSTR;
typedef unsigned short * PTR32 LPWSTR;
typedef unsigned short * PTR32 LPCWSTR;
/* any other Windows pointer typedef Ghidra spells (translate32.py maps them here): bytes */
typedef unsigned char * PTR32 GEN_LPANY;
/* the x86 CRITICAL_SECTION, 24 bytes: `lpCriticalSection + 1` steps over one */
typedef struct { unsigned char gen_cs[24]; } GEN_CRITICAL_SECTION32;
typedef GEN_CRITICAL_SECTION32 * PTR32 LPCRITICAL_SECTION;
typedef GEN_CRITICAL_SECTION32 * PTR32 PRTL_CRITICAL_SECTION;
typedef unsigned short * PTR32 BSTR;
typedef gen_ulong * PTR32 LPDWORD;
typedef gen_long * PTR32 LPLONG;
typedef unsigned char * PTR32 LPBYTE;
typedef int * PTR32 LPBOOL;
typedef unsigned short * PTR32 LPWORD;
typedef gen_code32 FARPROC;             /* (a function pointer, stored: gen_code32) */
typedef int BOOL;
typedef unsigned char BOOLEAN;
typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef gen_ulong DWORD;               /* (gen_long and gen_ulong: 4 bytes on an LP64 host too) */
typedef unsigned long long DWORD64;
typedef unsigned long long DWORDLONG;
typedef unsigned int UINT;
typedef int INT;
typedef gen_long LONG;
typedef gen_ulong ULONG;
typedef short SHORT;
typedef unsigned short USHORT;
typedef char CHAR;
typedef unsigned short WCHAR;
typedef long long LONGLONG;
typedef unsigned long long ULONGLONG;
typedef gen_long HRESULT;
typedef gen_long LSTATUS;
typedef gen_ulong LCID;
typedef unsigned short ATOM;
typedef unsigned int SIZE_T;            /* 32-bit, as stored */
typedef unsigned int ULONG_PTR;
typedef unsigned int DWORD_PTR;
typedef unsigned int UINT_PTR;
typedef int LONG_PTR;
typedef int INT_PTR;
typedef int LPARAM;
typedef unsigned int WPARAM;
typedef int LRESULT;
typedef unsigned int SOCKET;

/* ---- Windows' structures, at their x86 layouts (pointer fields 4 bytes) ------------------- */
typedef struct _FILETIME { DWORD dwLowDateTime; DWORD dwHighDateTime; } _FILETIME, FILETIME;
typedef union _LARGE_INTEGER {
    struct { DWORD LowPart; LONG HighPart; } s;
    struct { DWORD LowPart; LONG HighPart; } u;
    LONGLONG QuadPart;
} _LARGE_INTEGER, LARGE_INTEGER;
typedef union _ULARGE_INTEGER {
    struct { DWORD LowPart; DWORD HighPart; } s;
    struct { DWORD LowPart; DWORD HighPart; } u;
    ULONGLONG QuadPart;
} _ULARGE_INTEGER, ULARGE_INTEGER;
typedef struct _STARTUPINFOW {
    DWORD cb; LPWSTR lpReserved; LPWSTR lpDesktop; LPWSTR lpTitle;
    DWORD dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
    WORD wShowWindow; WORD cbReserved2; LPBYTE lpReserved2; HANDLE hStdInput, hStdOutput, hStdError;
} _STARTUPINFOW, STARTUPINFOW;
typedef struct _STARTUPINFOA {
    DWORD cb; LPSTR lpReserved; LPSTR lpDesktop; LPSTR lpTitle;
    DWORD dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
    WORD wShowWindow; WORD cbReserved2; LPBYTE lpReserved2; HANDLE hStdInput, hStdOutput, hStdError;
} _STARTUPINFOA, STARTUPINFOA;
typedef struct _SYSTEMTIME {
    WORD wYear, wMonth, wDayOfWeek, wDay, wHour, wMinute, wSecond, wMilliseconds;
} _SYSTEMTIME, SYSTEMTIME;
typedef struct _OSVERSIONINFOA {
    DWORD dwOSVersionInfoSize, dwMajorVersion, dwMinorVersion, dwBuildNumber, dwPlatformId;
    CHAR szCSDVersion[128];
} _OSVERSIONINFOA, OSVERSIONINFOA;
typedef struct _OSVERSIONINFOW {
    DWORD dwOSVersionInfoSize, dwMajorVersion, dwMinorVersion, dwBuildNumber, dwPlatformId;
    WCHAR szCSDVersion[128];
} _OSVERSIONINFOW, OSVERSIONINFOW;
typedef struct _SYSTEM_INFO {
    union { DWORD dwOemId; struct { WORD wProcessorArchitecture; WORD wReserved; } s; } u;
    DWORD dwPageSize; LPVOID lpMinimumApplicationAddress; LPVOID lpMaximumApplicationAddress;
    DWORD_PTR dwActiveProcessorMask; DWORD dwNumberOfProcessors; DWORD dwProcessorType;
    DWORD dwAllocationGranularity; WORD wProcessorLevel; WORD wProcessorRevision;
} _SYSTEM_INFO, SYSTEM_INFO;
typedef struct tagPOINT { LONG x, y; } tagPOINT, POINT;
typedef struct tagRECT { LONG left, top, right, bottom; } tagRECT, RECT;
typedef POINT * PTR32 LPPOINT;
typedef RECT * PTR32 LPRECT;
#ifndef __cplusplus
_Static_assert(sizeof(STARTUPINFOW) == 68, "STARTUPINFOW, x86");
_Static_assert(sizeof(SYSTEM_INFO) == 36, "SYSTEM_INFO, x86");
_Static_assert(sizeof(OSVERSIONINFOA) == 148, "OSVERSIONINFOA, x86");
#endif

/* ---- Ghidra's piecewise helpers ------------------------------------------------------------- */
/* (the x86 fidelity build's bit copies through a pointer: a /Od reference's union read is its
   slot's word, where memcpy was a call to it, the helper inlined or not, bytes32.py's /Ob1) */
#ifdef GEN_FIDELITY
static GEN_INLINE unsigned long long gen_d2bits_(double x) { return *(unsigned long long *)&x; }
static GEN_INLINE unsigned long long gen_fl2bits_(float x) { return *(unsigned int *)&x; }
#else
static GEN_INLINE unsigned long long gen_d2bits_(double x) { unsigned long long r; memcpy(&r, &x, 8); return r; }
static GEN_INLINE unsigned long long gen_fl2bits_(float x) { unsigned int r; memcpy(&r, &x, 4); return r; }
#endif
static GEN_INLINE unsigned long long gen_u2bits64(unsigned long long x) { return x; }
static GEN_INLINE unsigned long long gen_u2bits32(unsigned long long x) { return (unsigned int)x; }
/* (by the operand's type: an integer is bits already. Ghidra prints a view of a value it holds as
   floating point; translate32.py may hold the same place as an integer, an untyped global or
   local, and as `(float)` of it the bits were converted by value) */
#define gen_d2bits(x) _Generic((x), double: gen_d2bits_, long double: gen_d2bits_, float: gen_d2bits_, \
    default: gen_u2bits64)(x)
#define gen_fl2bits(x) _Generic((x), float: gen_fl2bits_, double: gen_fl2bits_, long double: gen_fl2bits_, \
    default: gen_u2bits32)(x)
#define GEN_BITS(x) _Generic((x), double: gen_d2bits_, float: gen_fl2bits_, default: gen_u2bits64)(x)
/* an 8-byte value as the reference's two argument words, low first (a variadic call's double:
   translate32.py's calls to a variadic translation) */
#define GEN_LO32(x) ((unsigned int)(unsigned long long)GEN_BITS(x))
#define GEN_HI32(x) ((unsigned int)((unsigned long long)GEN_BITS(x) >> 32))
#ifdef GEN_FIDELITY
static GEN_INLINE double gen_bits2d_(unsigned long long u) { return *(double *)&u; }
static GEN_INLINE float gen_bits2f_(unsigned int u) { return *(float *)&u; }
#else
static GEN_INLINE double gen_bits2d_(unsigned long long u) { double d; memcpy(&d, &u, 8); return d; }
static GEN_INLINE float gen_bits2f_(unsigned int u) { float f; memcpy(&f, &u, 4); return f; }
#endif
static GEN_INLINE double gen_d_same(double d) { return d; }
static GEN_INLINE float gen_f_same(float f) { return f; }
/* (and the other way: a floating-point operand is the value already. Ghidra viewed u2d's table of
   2^32 adjustments as bits, floatdata.py types it double from its `addsd`, and gen_bits2d of the
   double converted it to an integer first, rhtest float-O2 u2d) */
#define gen_bits2d(x) _Generic((x), double: gen_d_same, long double: gen_d_same, float: gen_d_same, \
    default: gen_bits2d_)(x)
#define gen_bits2f(x) _Generic((x), float: gen_f_same, double: gen_f_same, long double: gen_f_same, \
    default: gen_bits2f_)(x)

/* A cast between floating point and a pointer is Ghidra moving a register's bits (movd, or a value
   through the x87 stack): `(float)*ppvVar4`, `(int *)fVar2`. C converts between float and integer
   by value and refuses float and pointer outright. Where translate32.py cannot tell an operand's
   type, these pick by it: a pointer's bits to a float, a float's bits to a pointer, any integer or
   float by value as C would. */
static GEN_INLINE float gen_tof_f(float x) { return x; }
static GEN_INLINE float gen_tof_d(double x) { return (float)x; }
static GEN_INLINE float gen_tof_i(long long x) { return (float)x; }
static GEN_INLINE float gen_tof_u(unsigned long long x) { return (float)x; }
static GEN_INLINE float gen_tof_p(const volatile void *p) { return gen_bits2f((unsigned int)(uintptr_t)p); }
static GEN_INLINE double gen_tod_f(float x) { return x; }
static GEN_INLINE double gen_tod_d(double x) { return x; }
static GEN_INLINE double gen_tod_i(long long x) { return (double)x; }
static GEN_INLINE double gen_tod_u(unsigned long long x) { return (double)x; }
static GEN_INLINE double gen_tod_p(const volatile void *p) { return gen_bits2f((unsigned int)(uintptr_t)p); }
static GEN_INLINE uintptr_t gen_top_f(float x) { return gen_fl2bits(x); }
static GEN_INLINE uintptr_t gen_top_d(double x) { return (unsigned int)gen_d2bits(x); }
/* (an address the reference computes is 32 bits, and wraps so: `p + (i - 4)` of an unsigned i
   below 4 is p - 16 there, 16 GB on here, and a negative int sign-extended is no address at all.
   Truncated, as every address in the port's low 2 GB is) */
static GEN_INLINE uintptr_t gen_top_i(long long x) { return (uintptr_t)(unsigned int)x; }
static GEN_INLINE uintptr_t gen_top_u(unsigned long long x) { return (uintptr_t)(unsigned int)x; }
static GEN_INLINE uintptr_t gen_top_p(const volatile void *p) { return (uintptr_t)(unsigned int)(uintptr_t)p; }
#define GEN_BYTYPE(x, f, d, i, u, p) _Generic((x), float: f, double: d, long double: d, \
    char: i, signed char: i, short: i, int: i, long: i, long long: i, \
    unsigned char: u, unsigned short: u, unsigned int: u, unsigned long: u, unsigned long long: u, _Bool: u, \
    default: p)(x)
#define GEN_TOF(x) GEN_BYTYPE(x, gen_tof_f, gen_tof_d, gen_tof_i, gen_tof_u, gen_tof_p)
#define GEN_TOD(x) GEN_BYTYPE(x, gen_tod_f, gen_tod_d, gen_tod_i, gen_tod_u, gen_tod_p)
#define GEN_TOP(x) GEN_BYTYPE(x, gen_top_f, gen_top_d, gen_top_i, gen_top_u, gen_top_p)
/* A float parameter's argument, by its type: a call converts nothing on x86, the callee takes the 4
   bytes its caller pushed, so an integer or a pointer is its bits (a float or double is the value).
   By GEN_TOF, an integer converted by value: a client's `this` Ghidra typed float, passed as
   `*(undefined4 *)(p + 0x25f8)`, came in as the float 2.58e8 and its bits were written through,
   0x4e8640, 2026-10-30 */
static GEN_INLINE float gen_argf_i(long long x) { return gen_bits2f_((unsigned int)x); }
static GEN_INLINE float gen_argf_u(unsigned long long x) { return gen_bits2f_((unsigned int)x); }
#define GEN_ARGF(x) GEN_BYTYPE(x, gen_tof_f, gen_tof_d, gen_argf_i, gen_argf_u, gen_tof_p)
/* a float copied whole into an lvalue Ghidra typed otherwise (a mov of its 4 bytes into a pointer
   slot): its value into a float or double, its bits into anything else */
#define GEN_FLT_TO(lhs, v) _Generic((lhs), float: (v), double: (v), long double: (v), \
    default: (void *)(uintptr_t)gen_fl2bits((float)(v)))

#define CONCAT11(a, b) ((uint16_t)(((uint16_t)(uint8_t)GEN_BITS(a) << 8) | (uint8_t)GEN_BITS(b)))
#define CONCAT12(a, b) ((uint32_t)(((uint32_t)(uint8_t)GEN_BITS(a) << 16) | (uint16_t)GEN_BITS(b)))
#define CONCAT13(a, b) ((uint32_t)(((uint32_t)(uint8_t)GEN_BITS(a) << 24) | ((uint32_t)GEN_BITS(b) & 0xffffff)))
#define CONCAT14(a, b) ((uint64_t)(((uint64_t)(uint8_t)GEN_BITS(a) << 32) | (uint32_t)GEN_BITS(b)))
#define CONCAT15(a, b) ((uint64_t)(((uint64_t)(uint8_t)GEN_BITS(a) << 40) | ((uint64_t)GEN_BITS(b) & 0xffffffffffULL)))
#define CONCAT16(a, b) ((uint64_t)(((uint64_t)(uint8_t)GEN_BITS(a) << 48) | ((uint64_t)GEN_BITS(b) & 0xffffffffffffULL)))
#define CONCAT17(a, b) ((uint64_t)(((uint64_t)(uint8_t)GEN_BITS(a) << 56) | ((uint64_t)GEN_BITS(b) & 0xffffffffffffffULL)))
#define CONCAT21(a, b) ((uint32_t)(((uint32_t)(uint16_t)GEN_BITS(a) << 8) | (uint8_t)GEN_BITS(b)))
#define CONCAT22(a, b) ((uint32_t)(((uint32_t)(uint16_t)GEN_BITS(a) << 16) | (uint16_t)GEN_BITS(b)))
#define CONCAT24(a, b) ((uint64_t)(((uint64_t)(uint16_t)GEN_BITS(a) << 32) | (uint32_t)GEN_BITS(b)))
#define CONCAT26(a, b) ((uint64_t)(((uint64_t)(uint16_t)GEN_BITS(a) << 48) | ((uint64_t)GEN_BITS(b) & 0xffffffffffffULL)))
#define CONCAT31(a, b) ((uint32_t)((((uint32_t)GEN_BITS(a) & 0xffffff) << 8) | (uint8_t)GEN_BITS(b)))
#define CONCAT32(a, b) ((uint64_t)((((uint64_t)GEN_BITS(a) & 0xffffff) << 16) | (uint16_t)GEN_BITS(b)))
#define CONCAT35(a, b) ((uint64_t)((((uint64_t)GEN_BITS(a) & 0xffffff) << 40) | ((uint64_t)GEN_BITS(b) & 0xffffffffffULL)))
#define CONCAT41(a, b) ((uint64_t)(((uint64_t)(uint32_t)GEN_BITS(a) << 8) | (uint8_t)GEN_BITS(b)))
#define CONCAT42(a, b) ((uint64_t)(((uint64_t)(uint32_t)GEN_BITS(a) << 16) | (uint16_t)GEN_BITS(b)))
#define CONCAT44(a, b) ((uint64_t)(((uint64_t)(uint32_t)GEN_BITS(a) << 32) | (uint32_t)GEN_BITS(b)))
#define CONCAT53(a, b) ((uint64_t)((((uint64_t)GEN_BITS(a) & 0xffffffffffULL) << 24) | ((uint32_t)GEN_BITS(b) & 0xffffff)))
#define CONCAT62(a, b) ((uint64_t)((((uint64_t)GEN_BITS(a) & 0xffffffffffffULL) << 16) | (uint16_t)GEN_BITS(b)))
#define CONCAT71(a, b) ((uint64_t)((((uint64_t)GEN_BITS(a) & 0xffffffffffffffULL) << 8) | (uint8_t)GEN_BITS(b)))
#define SUB21(x, n) ((uint8_t)((uint16_t)GEN_BITS(x) >> ((n) * 8)))
#define SUB41(x, n) ((uint8_t)((uint32_t)GEN_BITS(x) >> ((n) * 8)))
#define SUB42(x, n) ((uint16_t)((uint32_t)GEN_BITS(x) >> ((n) * 8)))
#define SUB43(x, n) ((uint32_t)(((uint32_t)GEN_BITS(x) >> ((n) * 8)) & 0xffffffu))
#define SUB81(x, n) ((uint8_t)((uint64_t)GEN_BITS(x) >> ((n) * 8)))
#define SUB82(x, n) ((uint16_t)((uint64_t)GEN_BITS(x) >> ((n) * 8)))
#define SUB83(x, n) ((uint32_t)(((uint64_t)GEN_BITS(x) >> ((n) * 8)) & 0xffffffu))
#define SUB84(x, n) ((uint32_t)((uint64_t)GEN_BITS(x) >> ((n) * 8)))
#define SUB85(x, n) ((uint64_t)(((uint64_t)GEN_BITS(x) >> ((n) * 8)) & 0xffffffffffull))
#define SUB86(x, n) ((uint64_t)(((uint64_t)GEN_BITS(x) >> ((n) * 8)) & 0xffffffffffffull))
#define SUB87(x, n) ((uint64_t)(((uint64_t)GEN_BITS(x) >> ((n) * 8)) & 0xffffffffffffffull))
#define SUB101(x, n) ((uint8_t)((uint64_t)GEN_BITS(x) >> ((n) * 8)))
#define SUB104(x, n) ((uint32_t)((uint64_t)GEN_BITS(x) >> ((n) * 8)))
#define SUB108(x, n) ((uint64_t)GEN_BITS(x))
#define ZEXT14(x) ((uint32_t)(uint8_t)(x))
#define ZEXT18(x) ((uint64_t)(uint8_t)(x))
#define ZEXT24(x) ((uint32_t)(uint16_t)(x))
#define ZEXT28(x) ((uint64_t)(uint16_t)(x))
#define ZEXT48(x) ((uint64_t)(uint32_t)(x))
#define ZEXT38(x) ((uint64_t)(x) & 0xffffffull)
#define ZEXT58(x) ((uint64_t)(x) & 0xffffffffffull)
#define ZEXT68(x) ((uint64_t)(x) & 0xffffffffffffull)
#define ZEXT78(x) ((uint64_t)(x) & 0xffffffffffffffull)
#define ZEXT34(x) ((uint32_t)(x) & 0xffffffu)
/* a 4-byte piece of a 12-byte value, a float vector's x, y or z (`SUB124(*v, 8) * f`): the float
   its bytes hold, the 12 bytes an array in memory (gen_v12), the piece read from them. Only ever a
   float's in the decompiler's output: an integer's would read its bits as one */
#define SUB124(x, n) (*(float *)((unsigned char *)(x) + (n)))
#define SEXT14(x) ((int32_t)(int8_t)(x))
#define SEXT18(x) ((int64_t)(int8_t)(x))
#define SEXT24(x) ((int32_t)(int16_t)(x))
#define SEXT28(x) ((int64_t)(int16_t)(x))
#define SEXT48(x) ((int64_t)(int32_t)(x))
#define CARRY1(a, b) ((uint8_t)((uint8_t)(a) + (uint8_t)(b)) < (uint8_t)(a))
#define CARRY2(a, b) ((uint16_t)((uint16_t)(a) + (uint16_t)(b)) < (uint16_t)(a))
#define CARRY4(a, b) ((uint32_t)((uint32_t)(a) + (uint32_t)(b)) < (uint32_t)(a))
#define CARRY8(a, b) ((uint64_t)((uint64_t)(a) + (uint64_t)(b)) < (uint64_t)(a))
#define SCARRY1(a, b) ((((int8_t)(a) ^ (int8_t)((uint8_t)(a) + (uint8_t)(b))) & ((int8_t)(b) ^ (int8_t)((uint8_t)(a) + (uint8_t)(b)))) < 0)
#define SCARRY2(a, b) ((((int16_t)(a) ^ (int16_t)((uint16_t)(a) + (uint16_t)(b))) & ((int16_t)(b) ^ (int16_t)((uint16_t)(a) + (uint16_t)(b)))) < 0)
#define SCARRY4(a, b) ((((int32_t)(a) ^ (int32_t)((uint32_t)(a) + (uint32_t)(b))) & ((int32_t)(b) ^ (int32_t)((uint32_t)(a) + (uint32_t)(b)))) < 0)
#define SCARRY8(a, b) ((((int64_t)(a) ^ (int64_t)((uint64_t)(a) + (uint64_t)(b))) & ((int64_t)(b) ^ (int64_t)((uint64_t)(a) + (uint64_t)(b)))) < 0)
#define SBORROW1(a, b) ((((int8_t)(a) ^ (int8_t)(b)) & ((int8_t)(a) ^ (int8_t)((uint8_t)(a) - (uint8_t)(b)))) < 0)
#define SBORROW2(a, b) ((((int16_t)(a) ^ (int16_t)(b)) & ((int16_t)(a) ^ (int16_t)((uint16_t)(a) - (uint16_t)(b)))) < 0)
#define SBORROW4(a, b) ((((int32_t)(a) ^ (int32_t)(b)) & ((int32_t)(a) ^ (int32_t)((uint32_t)(a) - (uint32_t)(b)))) < 0)
#define SBORROW8(a, b) ((((int64_t)(a) ^ (int64_t)(b)) & ((int64_t)(a) ^ (int64_t)((uint64_t)(a) - (uint64_t)(b)))) < 0)
/* a piece of a variable 3, 5, 6 or 7 bytes wide (`local_1e4._0_3_`), read in place */
static GEN_INLINE unsigned long long GEN_PIECE(const void *p, int off, int n) {
    unsigned long long x = 0;
    memcpy(&x, (const char *)p + off, n);
    return x;
}
/* the same written: the low n bytes of v at offset off */
static GEN_INLINE unsigned long long gen_piece_set(void *p, int off, int n, unsigned long long v) {
    memcpy((char *)p + off, &v, n);
    return v;
}
#ifdef GEN_HOST_X86
#include <intrin.h>
#define rdtsc() __rdtsc()
#define GEN_POPCNT64(x) __popcnt64(x)
#else
/* (another host's counter for the time stamp: aarch64's virtual count, at its own rate
   (CNTFRQ_EL0, tens of MHz, where a TSC counts GHz), as rdtsc's increasing; the reference only
   differences it, or calibrates it against QueryPerformanceCounter) */
static GEN_INLINE unsigned long long gen_rdtsc(void) {
#if defined(__aarch64__)
    unsigned long long v;
    __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(v));
    return v;
#else
    return __builtin_readcyclecounter();
#endif
}
#define rdtsc() gen_rdtsc()
#define GEN_POPCNT64(x) __builtin_popcountll(x)
#endif
/* (of the value at its own size: `POPCOUNT((short)x)` counts 16 bits, not the sign extension's 64,
   rhtest misc-O2's __popcnt16 2026-10-24) */
#define POPCOUNT(x) ((int)GEN_POPCNT64((uint64_t)(x) & (sizeof(x) >= 8 ? ~0ull : (1ull << (8 * sizeof(x))) - 1)))
#define GEN_ISNAN(x) ((x) != (x))
#define ABS(x) ((x) < 0 ? -(x) : (x))
#include <math.h>
#define SQRT(x) sqrt(x)
/* the C runtime's x87 math as ApplyFacts' call fixups write it, `fpatan(from_bcd(x), K)`: K the
   function, helpers32.py's MATH_CODES (exp, log, log10, tan, atan, asin, acos, sinh, cosh, tanh,
   sin, cos, floor, ceil) */
static GEN_INLINE double gen_x87math(double x, int k) {
    switch (k) {
    case 1: return exp(x);   case 2: return log(x);   case 3: return log10(x); case 4: return tan(x);
    case 5: return atan(x);  case 6: return asin(x);  case 7: return acos(x);  case 8: return sinh(x);
    case 9: return cosh(x);  case 10: return tanh(x); case 11: return sin(x);  case 12: return cos(x);
    case 13: return floor(x); case 14: return ceil(x);
    default: return x;
    }
}
#define GEN_X87MATH(x, k) gen_x87math((double)(x), (int)(k))
#define ROUND(x) nearbyint(x)
#define TRUNC(x) trunc(x)
#define FLOOR(x) floor(x)
#define CEIL(x) ceil(x)
/* the copies the decompiler folds into a call of its own name: an inlined strcpy of a literal,
   `builtin_strncpy(p, ".exh", 5)` (a file name's extension), stubbed as an undeclared name */
/* the x87's sine and cosine, as the decompiler names the language's operations (FSIN, FCOS, and
   ApplyFacts' __CIsin / __CIcos fixups) */
#define fsin(x) sin(x)
#define fcos(x) cos(x)
/* and the x87's scale and power of two, as the decompiler names them in the C runtime's own math
   (`fscale(st0, st1)`: st0 * 2^trunc(st1); `f2xm1(x)`: 2^x - 1) */
#define fscale(a, b) ldexp((double)(a), (int)(double)(b))
#define f2xm1(x) (exp2((double)(x)) - 1.0)
/* (and its partial tangent, `fptan(st0)`: the tangent it leaves under the 1.0 it pushes, the C
   runtime's tan 0xc4d5e8) */
#define fptan(x) tan((double)(x))
#define builtin_strncpy(d, s, n) ((void)strncpy((char *)(d), (const char *)(s), (n)))
#define builtin_memcpy(d, s, n) ((void)memcpy((void *)(d), (const void *)(s), (n)))
#define builtin_memset(d, c, n) ((void)memset((void *)(d), (c), (n)))

/* Ghidra's `(code *)swi(n)`, called: the trap the instruction raises. `int3` (swi(3)) breaks
   into a debugger; `int 0x29` (swi(0x29)) is __fastfail, which ends the process (Ghidra drops the
   code in ecx: a generic one, 7). MSVC's /GS range checks end in one (Ghidra64.h's, 2026-10-23) */
/* (said where first, by the runtime, Adapters.cpp: a fail-fast ends the process with no report of
   its own, rhtest stl's vector section 2026-10-29) */
void gen_fastfail_report(void);
#ifdef GEN_HOST_X86
static unsigned int gen_swi_break(void) { __debugbreak(); return 0; }
static unsigned int gen_swi_fastfail(void) { gen_fastfail_report(); __fastfail(7); return 0; }
/* `hlt`, a privileged instruction in user mode: it faults as the reference's does (translate32.py
   hlt_loops) */
static void gen_hlt(void) { __halt(); }
/* `ud2`, which Ghidra spells `(code *)invalidInstructionException()` and calls */
static unsigned int gen_ud2(void) { __ud2(); return 0; }
#else
/* (another host: a trap of its own, which the runtime's signal handler raises as the reference's
   exception. int3 a breakpoint, SIGTRAP (`brk #0xf000`); ud2 and hlt SIGILL at an `udf` whose
   immediate, the instruction word's low 16 bits, tells them apart: 0 ud2
   (ILLEGAL_INSTRUCTION), 1 hlt (PRIV_INSTRUCTION). A fail-fast ends the process, as __fastfail,
   after the runtime's report) */
#if defined(__aarch64__)
#define GEN_UDF(k) __asm__ __volatile__("udf #" #k)
#else
#define GEN_UDF(k) __builtin_trap()
#endif
static GEN_INLINE unsigned int gen_swi_break(void) { __builtin_debugtrap(); return 0; }
static GEN_INLINE unsigned int gen_swi_fastfail(void) { gen_fastfail_report(); __builtin_trap(); return 0; }
static GEN_INLINE void gen_hlt(void) { GEN_UDF(1); }
static GEN_INLINE unsigned int gen_ud2(void) { GEN_UDF(0); return 0; }
/* (and MSVC's intrinsics of these that the translation may call by name, translate32's
   HEADER_NAMES) */
#define __debugbreak() __builtin_debugtrap()
static GEN_INLINE unsigned int gen_rotl32_(unsigned int x, int n) { n &= 31; return n ? x << n | x >> (32 - n) : x; }
static GEN_INLINE unsigned long long gen_rotl64_(unsigned long long x, int n) { n &= 63; return n ? x << n | x >> (64 - n) : x; }
#define _rotl(x, n) gen_rotl32_((unsigned int)(x), (int)(n))
#define _rotr(x, n) gen_rotl32_((unsigned int)(x), -(int)(n))
#define _rotl64(x, n) gen_rotl64_((unsigned long long)(x), (int)(n))
#define _rotr64(x, n) gen_rotl64_((unsigned long long)(x), -(int)(n))
#endif
#define swi(n) ((n) == 0x29 ? gen_swi_fastfail : gen_swi_break)
#define invalidInstructionException() gen_ud2

/* Ghidra's `cpuid` pseudo-functions: the leaf's registers as Ghidra's x86 spec reads them back,
   EAX, EBX, EDX, ECX, each call its own slot of a small ring (Ghidra64.h's). The CRT's
   __isa_available_init reads them, and its result picks /O2's vector paths. AVX-512 is never
   reported (leaf 7's bits and XCR0's opmask/ZMM state, GEN_XCR0): the CRT's AVX-512 paths are
   ones Ghidra decompiles lossily (__ultod3's `vmovd; vpinsrd; vcvtuqq2pd` as the low word alone,
   a stub), and on a machine that has it the port would run them where the others are exact */
#ifdef GEN_HOST_X86
#define GEN_CPUIDEX(r, leaf) __cpuidex((r), (leaf), 0)
/* `xinuse(0)`: xgetbv with ecx = 1, the state components in use (in_XCR0, ecx = 0, is
   translate32.py's _xgetbv(0)) */
#define xinuse(x) (_xgetbv(1) & ~0xE0ull)
/* XCR0 without AVX-512's state components (opmask, ZMM_Hi256, Hi16_ZMM), as gen_cpuid */
#define GEN_XCR0() ((unsigned int)(_xgetbv(0) & ~0xE0ull))
#else
/* (another host has no x86 to ask: an Intel family 6 of the instructions the translation computes
   exactly, SSE to SSE4.2 and POPCNT, so the CRT's __isa_available_init and the program's own
   checks take paths the port has. -DGEN_CPU_AVX2 adds AVX, AVX2, BMI1/2 and LZCNT with XCR0's
   AVX state, as a modern x64 host reports them to the x64 port: vec32.py's helpers compute those
   paths too, so a run compares with the x64 port's path for path) */
#ifdef GEN_CPU_AVX2
#define GEN_CPU_XCR0 7u
#define GEN_CPU_ECX1 0x1c982201u        /* SSE3 SSSE3 CX16 SSE4.1 SSE4.2 POPCNT XSAVE OSXSAVE AVX */
#define GEN_CPU_EBX7 0x128u             /* BMI1 AVX2 BMI2 */
#define GEN_CPU_LZCNT 0x20u
#define GEN_CPU_MAXLEAF 0xd
#else
#define GEN_CPU_XCR0 3u
#define GEN_CPU_ECX1 0x00982201u        /* SSE3 SSSE3 CX16 SSE4.1 SSE4.2 POPCNT */
#define GEN_CPU_EBX7 0u
#define GEN_CPU_LZCNT 0u
#define GEN_CPU_MAXLEAF 7
#endif
/* (r as __cpuidex's: EAX, EBX, ECX, EDX) */
static GEN_INLINE void gen_cpuid_x86_(int leaf, int r[4]) {
    static const char brand[48] = "Rhipper x86 (portable host)";
    r[0] = r[1] = r[2] = r[3] = 0;
    switch ((unsigned int)leaf) {
    case 0:                                          /* "GenuineIntel" */
        r[0] = GEN_CPU_MAXLEAF; r[1] = 0x756e6547; r[3] = 0x49656e69; r[2] = 0x6c65746e; break;
    case 1:                                          /* family 6 model 0x3c; CLFLUSH 64 bytes */
        r[0] = 0x000306c3; r[1] = 0x00100800; r[2] = (int)GEN_CPU_ECX1;
        r[3] = 0x078bfbff; break;                    /* FPU TSC CX8 CMOV CLFSH MMX FXSR SSE SSE2 */
    case 7: r[1] = (int)GEN_CPU_EBX7; break;
    case 0xd: if (GEN_CPU_XCR0 & 4) { r[0] = 7; r[1] = r[2] = 0x340; } break;
    case 0x80000000u: r[0] = (int)0x80000004u; break;
    case 0x80000001u: r[2] = (int)(1u | GEN_CPU_LZCNT); r[3] = 0x20100800; break;   /* LAHF; SYSCALL NX LM */
    case 0x80000002u: case 0x80000003u: case 0x80000004u:
        memcpy(r, brand + 16 * ((unsigned int)leaf - 0x80000002u), 16); break;
    default: break;
    }
}
#define GEN_CPUIDEX(r, leaf) gen_cpuid_x86_((leaf), (r))
#define xinuse(x) ((unsigned long long)GEN_CPU_XCR0)
#define GEN_XCR0() GEN_CPU_XCR0
#endif
static GEN_INLINE unsigned int *gen_cpuid(int leaf) {
    static GEN_THREAD int regs[8][4];
    static GEN_THREAD unsigned int next;
    int *slot = regs[next++ & 7];
    int r[4];
    GEN_CPUIDEX(r, leaf);
    if (leaf == 7) {
        r[1] &= ~(int)0xDC230000u;     /* EBX: AVX512F, DQ, IFMA, PF, ER, CD, BW, VL */
        r[2] &= ~(int)0x00005842u;     /* ECX: VBMI, VBMI2, VNNI, BITALG, VPOPCNTDQ */
        r[3] &= ~(int)0x0080010Cu;     /* EDX: 4VNNIW, 4FMAPS, VP2INTERSECT, FP16 */
    }
    slot[0] = r[0];
    slot[1] = r[1];
    slot[2] = r[3];
    slot[3] = r[2];
    return (unsigned int *)slot;
}
#define cpuid(x) gen_cpuid((int)(x))
#define cpuid_basic_info(x) gen_cpuid(0)
#define cpuid_Version_info(x) gen_cpuid(1)
#define cpuid_cache_tlb_info(x) gen_cpuid(2)
#define cpuid_serial_info(x) gen_cpuid(3)
#define cpuid_Deterministic_Cache_Parameters_info(x) gen_cpuid(4)
#define cpuid_MONITOR_MWAIT_Features_info(x) gen_cpuid(5)
#define cpuid_Thermal_Power_Management_info(x) gen_cpuid(6)
#define cpuid_Extended_Feature_Enumeration_info(x) gen_cpuid(7)
#define cpuid_Direct_Cache_Access_info(x) gen_cpuid(9)
#define cpuid_Architectural_Performance_Monitoring_info(x) gen_cpuid(10)
#define cpuid_Extended_Topology_info(x) gen_cpuid(11)
#define cpuid_Processor_Extended_States_info(x) gen_cpuid(13)
#define cpuid_Quality_of_Service_info(x) gen_cpuid(15)
#define cpuid_brand_part1_info(x) gen_cpuid((int)0x80000002)
#define cpuid_brand_part2_info(x) gen_cpuid((int)0x80000003)
#define cpuid_brand_part3_info(x) gen_cpuid((int)0x80000004)

/* ---- the reference's own memory ----------------------------------------------------------- */
/* a global of the image, at its address: REFG(type, addr) is the lvalue, REFP(addr) the address */
#define REFG(type, addr) (*(type *)(uintptr_t)(addr))
#define REFP(addr) ((void *)(uintptr_t)(addr))
/* a 32-bit address (an int Ghidra computed) as a host pointer */
#define GP(x) ((void *)(uintptr_t)(uint32_t)(x))

/* The reference's fs segment, its x86 TEB: Ghidra maps it at 0xffdff000 (its "tdb" block:
   ExceptionList, Self, ThreadLocalStoragePointer, ProcessEnvironmentBlock, ...), and
   translate32.py reads and writes there through this thread's own (src/runtime: a block below
   2 GB, its fields set as x86 Windows would). fs:[0], the SEH chain head, is linked and unlinked
   by the translated code and walked by nothing (an exception the reference raises is the
   runtime's) */
unsigned int gen_teb32(void);
#define ExceptionList (*(unsigned int *)(uintptr_t)gen_teb32())

/* setjmp and longjmp (the reference's _setjmp3, longjmp): the port's own, on a native jmp_buf that
   stands for the reference's (by its address, per thread). The reference's buffer holds its x86
   registers and is no use to the port; a setjmp has to be the translated function's own call, its
   frame the one a longjmp comes back to (translate32.py: GEN_SETJMP(buf) for gen_imp__setjmp3) */
#include <setjmp.h>
jmp_buf *gen_jmpbuf(unsigned int ref);
#ifdef _WIN32
#define GEN_SETJMP(b) setjmp(*gen_jmpbuf((unsigned int)(uintptr_t)(b)))
#define GEN_LONGJMP(b, v) longjmp(*gen_jmpbuf((unsigned int)(uintptr_t)(b)), (int)(v))
#else
/* (POSIX's _setjmp: the reference's _setjmp3 keeps no signal mask, and setjmp's is a system call
   each time. bionic's longjmp and _longjmp are one function, which reads from the buffer whether
   it holds a mask; eh_landing's setjmp below keeps one) */
#define GEN_SETJMP(b) _setjmp(*gen_jmpbuf((unsigned int)(uintptr_t)(b)))
#define GEN_LONGJMP(b, v) _longjmp(*gen_jmpbuf((unsigned int)(uintptr_t)(b)), (int)(v))
#endif

/* The reference's exceptions (Adapters.cpp: _CxxThrowException, RaiseException): the runtime walks
   the fs:[0] chain the translated code links, as x86 Windows and vcruntime would, over the
   reference's own tables (FuncInfo, the EH4 scope table), and calls its funclets, translated, on
   their frame's ebp. A function that links a frame sets its landing after the link
   (translate32.py eh_landing): a catch done, the dispatcher comes back there, and the function
   returns what the reference's continuation (a function on the same ebp) returns */
jmp_buf *gen_eh_landing(unsigned int node);
unsigned long long gen_eh_resume(void);

/* the reference's TLS (__declspec(thread) data, fs:[0x2c] on x86): this thread's array of block
   addresses, indexed by the image's TLS index, each block a copy of the image's TLS template
   (src/runtime) */
unsigned int gen_tls_array(void);
#define GEN_TLS_ARRAY (gen_tls_array())

/* a `lock`-prefixed instruction (Ghidra's LOCK(); ... UNLOCK(); around its read-modify-write):
   one process-wide lock (src/runtime), so the operation is atomic among the translated threads */
void gen_lock_enter(void);
void gen_lock_leave(void);
#define LOCK() gen_lock_enter()
#define UNLOCK() gen_lock_leave()
/* the interlocked intrinsics translate32.py writes for `xchg`, `lock xadd` and `lock cmpxchg`
   (`_InterlockedExchange((volatile gen_long *)p, v)`): MSVC's on Windows; on another host the
   compiler's atomics on the reference's 4 bytes, sequentially consistent as a locked x86
   instruction is (where aarch64 faults on a misaligned one, which x86 does not) */
#ifndef _WIN32
static GEN_INLINE gen_long gen_ilk_xchg_(volatile void *p, gen_long v) {
    return __atomic_exchange_n((volatile int *)p, (int)v, __ATOMIC_SEQ_CST);
}
static GEN_INLINE gen_long gen_ilk_add_(volatile void *p, gen_long v) {
    return __atomic_fetch_add((volatile int *)p, (int)v, __ATOMIC_SEQ_CST);
}
static GEN_INLINE gen_long gen_ilk_cas_(volatile void *p, gen_long x, gen_long c) {
    int e = (int)c;
    __atomic_compare_exchange_n((volatile int *)p, &e, (int)x, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    return e;
}
static GEN_INLINE gen_long gen_ilk_or_(volatile void *p, gen_long v) { return __atomic_fetch_or((volatile int *)p, (int)v, __ATOMIC_SEQ_CST); }
static GEN_INLINE gen_long gen_ilk_and_(volatile void *p, gen_long v) { return __atomic_fetch_and((volatile int *)p, (int)v, __ATOMIC_SEQ_CST); }
static GEN_INLINE gen_long gen_ilk_xor_(volatile void *p, gen_long v) { return __atomic_fetch_xor((volatile int *)p, (int)v, __ATOMIC_SEQ_CST); }
#define _InterlockedExchange(p, v) gen_ilk_xchg_((p), (gen_long)(v))
#define _InterlockedExchangeAdd(p, v) gen_ilk_add_((p), (gen_long)(v))
#define _InterlockedCompareExchange(p, x, c) gen_ilk_cas_((p), (gen_long)(x), (gen_long)(c))
#define _InterlockedIncrement(p) ((gen_long)((unsigned int)gen_ilk_add_((p), 1) + 1u))
#define _InterlockedDecrement(p) ((gen_long)((unsigned int)gen_ilk_add_((p), -1) - 1u))
#define _InterlockedOr(p, v) gen_ilk_or_((p), (gen_long)(v))
#define _InterlockedAnd(p, v) gen_ilk_and_((p), (gen_long)(v))
#define _InterlockedXor(p, v) gen_ilk_xor_((p), (gen_long)(v))
#endif

/* SSE's control register, which Ghidra writes as a variable (ldmxcsr / stmxcsr) */
#define MXCSR gen_MXCSR
extern GEN_THREAD unsigned int gen_MXCSR;
/* enumerators Ghidra spells by name from its Windows type library */
#define HeapCompatibilityInformation 0
#define HeapEnableTerminationOnCorruption 1
#define HeapOptimizeResources 3
/* (FindFirstFileExW's, the CRT's __wstat64: undeclared, it was a stub and a client's thread
   12 got 0 for its stat, 2026-10-25) */
#define FindExInfoStandard 0
#define FindExInfoBasic 1
#define FindExSearchNameMatch 0
#define FindExSearchLimitToDirectories 1
#define FindExSearchLimitToDevices 2

/* a function no translation covers: the runtime logs the address once */
void GenUnimplemented(unsigned int address);
