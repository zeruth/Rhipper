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
typedef unsigned long ulong;            /* 4 bytes on Windows, as in the reference */
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
#define GEN_ENTER(addr, a0, a1, a2, a3) \
    do { if (gen_trace_on) gen_trace_enter((addr), (a0), (a1), (a2), (a3)); } while (0)
/* (a float or 8-byte argument's stack words, as the reference's record holds them: its bits, not
   its value converted, pi/4 recorded as 0 parted a client's runs at a sincos, 2026-10-26) */
static __inline unsigned int gen_trace_f(float f) { union { float f; unsigned int u; } v; v.f = f; return v.u; }
static __inline unsigned long long gen_trace_d(double d) { union { double d; unsigned long long u; } v; v.d = d; return v.u; }
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
#include <emmintrin.h>
static __inline __m128 gen_ldps(const void *p) { return _mm_loadu_ps((const float *)p); }
static __inline __m128i gen_ldi(const void *p) { return _mm_loadu_si128((const __m128i *)p); }
static __inline void gen_stps(void *p, __m128 v) { _mm_storeu_ps((float *)p, v); }
static __inline void gen_sti(void *p, __m128i v) { _mm_storeu_si128((__m128i *)p, v); }
static __inline void gen_minps(void *r, const void *a, const void *b) { gen_stps(r, _mm_min_ps(gen_ldps(a), gen_ldps(b))); }
static __inline void gen_maxps(void *r, const void *a, const void *b) { gen_stps(r, _mm_max_ps(gen_ldps(a), gen_ldps(b))); }
static __inline void gen_divps(void *r, const void *a, const void *b) { gen_stps(r, _mm_div_ps(gen_ldps(a), gen_ldps(b))); }
static __inline void gen_rsqrtps(void *r, const void *d, const void *s) { (void)d; gen_stps(r, _mm_rsqrt_ps(gen_ldps(s))); }
static __inline void gen_rcpps(void *r, const void *d, const void *s) { (void)d; gen_stps(r, _mm_rcp_ps(gen_ldps(s))); }
static __inline void gen_sqrtps(void *r, const void *d, const void *s) { (void)d; gen_stps(r, _mm_sqrt_ps(gen_ldps(s))); }
static __inline void gen_packssdw(void *r, const void *a, const void *b) { gen_sti(r, _mm_packs_epi32(gen_ldi(a), gen_ldi(b))); }
static __inline void gen_psllw(void *r, const void *a, const void *n) { gen_sti(r, _mm_sll_epi16(gen_ldi(a), gen_ldi(n))); }
/* (SSE4.1: MSVC's /O2 vectorizes an integer multiply loop with it, behind __isa_available) */
#include <smmintrin.h>
static __inline void gen_pmulld(void *r, const void *a, const void *b) { gen_sti(r, _mm_mullo_epi32(gen_ldi(a), gen_ldi(b))); }
/* (AVX2's per-lane shift, the 128-bit form, behind __isa_available as /O2 vectorizes `w << (k & 7)`:
   in C, each lane by its own count, 0 past 31, so the port needs no AVX2 of its own) */
static __inline void gen_vpsllvd_avx2(void *r, const void *a, const void *n) {
    unsigned int x[4], c[4];
    memcpy(x, a, 16); memcpy(c, n, 16);
    for (int k = 0; k < 4; k++) x[k] = c[k] > 31 ? 0 : x[k] << c[k];
    memcpy(r, x, 16);
}
static __inline void gen_v16_or(void *r, const void *a, const void *b) { gen_sti(r, _mm_or_si128(gen_ldi(a), gen_ldi(b))); }
static __inline void gen_v16_and(void *r, const void *a, const void *b) { gen_sti(r, _mm_and_si128(gen_ldi(a), gen_ldi(b))); }
static __inline void gen_v16_xor(void *r, const void *a, const void *b) { gen_sti(r, _mm_xor_si128(gen_ldi(a), gen_ldi(b))); }
/* movmskps(dst, src): the sign bits of src's four floats */
static __inline int gen_movmskps(const void *s) { return _mm_movemask_ps(gen_ldps(s)); }
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
typedef unsigned long * PTR32 LPDWORD;
typedef long * PTR32 LPLONG;
typedef unsigned char * PTR32 LPBYTE;
typedef int * PTR32 LPBOOL;
typedef unsigned short * PTR32 LPWORD;
typedef gen_code32 FARPROC;             /* (a function pointer, stored: gen_code32) */
typedef int BOOL;
typedef unsigned char BOOLEAN;
typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned long DWORD;
typedef unsigned long long DWORD64;
typedef unsigned long long DWORDLONG;
typedef unsigned int UINT;
typedef int INT;
typedef long LONG;
typedef unsigned long ULONG;
typedef short SHORT;
typedef unsigned short USHORT;
typedef char CHAR;
typedef unsigned short WCHAR;
typedef long long LONGLONG;
typedef unsigned long long ULONGLONG;
typedef long HRESULT;
typedef long LSTATUS;
typedef unsigned long LCID;
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
static __inline unsigned long long gen_d2bits_(double x) { unsigned long long r; memcpy(&r, &x, 8); return r; }
static __inline unsigned long long gen_fl2bits_(float x) { unsigned int r; memcpy(&r, &x, 4); return r; }
static __inline unsigned long long gen_u2bits64(unsigned long long x) { return x; }
static __inline unsigned long long gen_u2bits32(unsigned long long x) { return (unsigned int)x; }
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
static __inline double gen_bits2d_(unsigned long long u) { double d; memcpy(&d, &u, 8); return d; }
static __inline float gen_bits2f_(unsigned int u) { float f; memcpy(&f, &u, 4); return f; }
static __inline double gen_d_same(double d) { return d; }
static __inline float gen_f_same(float f) { return f; }
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
static __inline float gen_tof_f(float x) { return x; }
static __inline float gen_tof_d(double x) { return (float)x; }
static __inline float gen_tof_i(long long x) { return (float)x; }
static __inline float gen_tof_u(unsigned long long x) { return (float)x; }
static __inline float gen_tof_p(const volatile void *p) { return gen_bits2f((unsigned int)(uintptr_t)p); }
static __inline double gen_tod_f(float x) { return x; }
static __inline double gen_tod_d(double x) { return x; }
static __inline double gen_tod_i(long long x) { return (double)x; }
static __inline double gen_tod_u(unsigned long long x) { return (double)x; }
static __inline double gen_tod_p(const volatile void *p) { return gen_bits2f((unsigned int)(uintptr_t)p); }
static __inline uintptr_t gen_top_f(float x) { return gen_fl2bits(x); }
static __inline uintptr_t gen_top_d(double x) { return (unsigned int)gen_d2bits(x); }
/* (an address the reference computes is 32 bits, and wraps so: `p + (i - 4)` of an unsigned i
   below 4 is p - 16 there, 16 GB on here, and a negative int sign-extended is no address at all.
   Truncated, as every address in the port's low 2 GB is) */
static __inline uintptr_t gen_top_i(long long x) { return (uintptr_t)(unsigned int)x; }
static __inline uintptr_t gen_top_u(unsigned long long x) { return (uintptr_t)(unsigned int)x; }
static __inline uintptr_t gen_top_p(const volatile void *p) { return (uintptr_t)(unsigned int)(uintptr_t)p; }
#define GEN_BYTYPE(x, f, d, i, u, p) _Generic((x), float: f, double: d, long double: d, \
    char: i, signed char: i, short: i, int: i, long: i, long long: i, \
    unsigned char: u, unsigned short: u, unsigned int: u, unsigned long: u, unsigned long long: u, _Bool: u, \
    default: p)(x)
#define GEN_TOF(x) GEN_BYTYPE(x, gen_tof_f, gen_tof_d, gen_tof_i, gen_tof_u, gen_tof_p)
#define GEN_TOD(x) GEN_BYTYPE(x, gen_tod_f, gen_tod_d, gen_tod_i, gen_tod_u, gen_tod_p)
#define GEN_TOP(x) GEN_BYTYPE(x, gen_top_f, gen_top_d, gen_top_i, gen_top_u, gen_top_p)
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
static __inline unsigned long long GEN_PIECE(const void *p, int off, int n) {
    unsigned long long x = 0;
    memcpy(&x, (const char *)p + off, n);
    return x;
}
/* the same written: the low n bytes of v at offset off */
static __inline unsigned long long gen_piece_set(void *p, int off, int n, unsigned long long v) {
    memcpy((char *)p + off, &v, n);
    return v;
}
#include <intrin.h>
#define rdtsc() __rdtsc()
/* (of the value at its own size: `POPCOUNT((short)x)` counts 16 bits, not the sign extension's 64,
   rhtest misc-O2's __popcnt16 2026-10-24) */
#define POPCOUNT(x) ((int)__popcnt64((uint64_t)(x) & (sizeof(x) >= 8 ? ~0ull : (1ull << (8 * sizeof(x))) - 1)))
#define GEN_ISNAN(x) ((x) != (x))
#define ABS(x) ((x) < 0 ? -(x) : (x))
#include <math.h>
#define SQRT(x) sqrt(x)
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
#define builtin_strncpy(d, s, n) ((void)strncpy((char *)(d), (const char *)(s), (n)))
#define builtin_memcpy(d, s, n) ((void)memcpy((void *)(d), (const void *)(s), (n)))
#define builtin_memset(d, c, n) ((void)memset((void *)(d), (c), (n)))

/* Ghidra's `(code *)swi(n)`, called: the trap the instruction raises. `int3` (swi(3)) breaks
   into a debugger; `int 0x29` (swi(0x29)) is __fastfail, which ends the process (Ghidra drops the
   code in ecx: a generic one, 7). MSVC's /GS range checks end in one (Ghidra64.h's, 2026-10-23) */
static unsigned int gen_swi_break(void) { __debugbreak(); return 0; }
static unsigned int gen_swi_fastfail(void) { __fastfail(7); return 0; }
#define swi(n) ((n) == 0x29 ? gen_swi_fastfail : gen_swi_break)
/* `ud2`, which Ghidra spells `(code *)invalidInstructionException()` and calls */
static unsigned int gen_ud2(void) { __ud2(); return 0; }
#define invalidInstructionException() gen_ud2

/* Ghidra's `cpuid` pseudo-functions: the leaf's registers as Ghidra's x86 spec reads them back,
   EAX, EBX, EDX, ECX, each call its own slot of a small ring (Ghidra64.h's). The CRT's
   __isa_available_init reads them, and its result picks /O2's vector paths. AVX-512 is never
   reported (leaf 7's bits and XCR0's opmask/ZMM state, GEN_XCR0): the CRT's AVX-512 paths are
   ones Ghidra decompiles lossily (__ultod3's `vmovd; vpinsrd; vcvtuqq2pd` as the low word alone,
   a stub), and on a machine that has it the port would run them where the others are exact */
static __inline unsigned int *gen_cpuid(int leaf) {
    static __declspec(thread) int regs[8][4];
    static __declspec(thread) unsigned int next;
    int *slot = regs[next++ & 7];
    int r[4];
    __cpuidex(r, leaf, 0);
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
/* `xinuse(0)`: xgetbv with ecx = 1, the state components in use (in_XCR0, ecx = 0, is
   translate32.py's _xgetbv(0)) */
#define xinuse(x) (_xgetbv(1) & ~0xE0ull)
/* XCR0 without AVX-512's state components (opmask, ZMM_Hi256, Hi16_ZMM), as gen_cpuid */
#define GEN_XCR0() ((unsigned int)(_xgetbv(0) & ~0xE0ull))
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
#define GEN_SETJMP(b) setjmp(*gen_jmpbuf((unsigned int)(uintptr_t)(b)))
#define GEN_LONGJMP(b, v) longjmp(*gen_jmpbuf((unsigned int)(uintptr_t)(b)), (int)(v))

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

/* SSE's control register, which Ghidra writes as a variable (ldmxcsr / stmxcsr) */
#define MXCSR gen_MXCSR
extern __declspec(thread) unsigned int gen_MXCSR;
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
