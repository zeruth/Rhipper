// The import adapters the generic one in src/gen/imports.c cannot be: imports whose structures
// are laid out differently on x86 and x64, and kernel32 functions x64 Windows does not export.
// Each is listed in rhipper.json "import_overrides", so translate32.py leaves it to this file.
//
// An adapter takes the reference's 32-bit arguments (an address, below 2 GB, is its own value)
// and returns its 32-bit result.
#include <windows.h>
#include <shlobj.h>

#include <csetjmp>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include <corecrt_startup.h>
#include <float.h>

#include "RefImage.hpp"

extern "C" uint32_t gen_ref_base;   // RefImage.cpp
const wchar_t* RefImagePath();       // RefImage.cpp
extern "C" unsigned int gen_teb32(void);
extern "C" int gen_teb32_made(void);
extern "C" const unsigned int g_genEhFuncInfo[];   // gen/jumps.c
extern "C" {
struct GEN_JUMP {
    unsigned int ref;
    void* port;
};
extern const GEN_JUMP g_genJumps[];
extern const unsigned int g_genJumpCount;
}

namespace {

template <typename T>
T* At(uint32_t address) {
    return reinterpret_cast<T*>(static_cast<uintptr_t>(address));
}

// The reference's CRITICAL_SECTION is 24 bytes (x86); Windows' is 40. The x86 one's first field
// (DebugInfo) holds the port's own, made when the reference initializes it.
CRITICAL_SECTION* HostSection(uint32_t refSection) {
    auto slot = At<volatile uint32_t>(refSection);
    if (*slot == 0) {
        auto cs = static_cast<CRITICAL_SECTION*>(HeapAlloc(GetProcessHeap(), 0, sizeof(CRITICAL_SECTION)));
        InitializeCriticalSection(cs);
        uint32_t mine = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(cs));
        if (InterlockedCompareExchange(reinterpret_cast<volatile LONG*>(slot), static_cast<LONG>(mine), 0) != 0) {
            DeleteCriticalSection(cs);
            HeapFree(GetProcessHeap(), 0, cs);
        }
    }
    return At<CRITICAL_SECTION>(*slot);
}

void InitSection(uint32_t refSection, DWORD spin) {
    memset(At<void>(refSection), 0, 24);
    CRITICAL_SECTION* cs = HostSection(refSection);
    SetCriticalSectionSpinCount(cs, spin);
}

#pragma pack(push, 4)
struct StartupInfo32 {
    uint32_t cb, lpReserved, lpDesktop, lpTitle;
    uint32_t dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
    uint16_t wShowWindow, cbReserved2;
    uint32_t lpReserved2, hStdInput, hStdOutput, hStdError;
};
static_assert(sizeof(StartupInfo32) == 68, "STARTUPINFO, x86");

struct SystemInfo32 {
    uint16_t wProcessorArchitecture, wReserved;
    uint32_t dwPageSize, lpMinimumApplicationAddress, lpMaximumApplicationAddress, dwActiveProcessorMask;
    uint32_t dwNumberOfProcessors, dwProcessorType, dwAllocationGranularity;
    uint16_t wProcessorLevel, wProcessorRevision;
};
static_assert(sizeof(SystemInfo32) == 36, "SYSTEM_INFO, x86");

struct MemoryInfo32 {
    uint32_t BaseAddress, AllocationBase, AllocationProtect, RegionSize, State, Protect, Type;
};
static_assert(sizeof(MemoryInfo32) == 28, "MEMORY_BASIC_INFORMATION, x86");
#pragma pack(pop)

uint32_t Low(const void* p) {
    return static_cast<uint32_t>(reinterpret_cast<uintptr_t>(p));
}

uint32_t Low(HANDLE h) {
    return static_cast<uint32_t>(reinterpret_cast<uintptr_t>(h));
}

// A reference function called by its address: the runtime's jump there reaches its translation
// (or the int3 that logs it), which takes nothing and returns its 32-bit result
int CallRef(uint32_t fn) {
    return reinterpret_cast<int (*)(void)>(static_cast<uintptr_t>(fn))();
}

// A vector of host strings as the reference's: an array of 4-byte pointers (the strings are
// below 2 GB like all the port's memory), made once, NULL-terminated
uint32_t Vector32(char** v) {
    int n = 0;
    while (v && v[n]) n++;
    auto out = static_cast<uint32_t*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (n + 1) * sizeof(uint32_t)));
    for (int k = 0; k < n; k++) out[k] = Low(v[k]);
    return Low(out);
}

// The reference's _onexit_table_t: three 4-byte pointers, first, last, end
struct OnexitTable32 {
    uint32_t first, last, end;
};

// ---- the reference's va_list as x64's ----------------------------------------------------------
// The reference's va_list points at its own arguments, 4-byte slots (a double or a 64-bit integer
// 8 bytes); x64 ucrt reads 8-byte ones. A printf or scanf format says what each is: the arguments
// are read off the reference's list by it and laid out again, one 8-byte slot each.
constexpr int kMaxArgs = 64;

struct Args64 {
    uint64_t slot[kMaxArgs + 4] = {};
    int n = 0;
    void Put(uint64_t v) {
        if (n < kMaxArgs) slot[n++] = v;
    }
    va_list List() { return reinterpret_cast<va_list>(slot); }
};

// A count the reference passed as 32 bits: its -1 ("no limit", sprintf's) as the host's
size_t Count32(uint32_t c) {
    return c == 0xffffffffu ? SIZE_MAX : c;
}

// printf: by each conversion's length and type. And the format again where x64 would print
// otherwise: `%p` is 8 hex digits on x86 and 16 on x64, so it becomes `%08X` (fmt_strings'
// `[%p]`, rhtest crt 2026-10-24); `fixed` is that copy, `f` itself when nothing changes
template <typename C>
void PrintfArgs(const C* f, uint32_t va, Args64& out, std::basic_string<C>* fixed = nullptr) {
    auto take32 = [&]() { uint32_t v = *At<uint32_t>(va); va += 4; return v; };
    auto take64 = [&]() { uint64_t v = *At<uint64_t>(va); va += 8; return v; };
    const C* start = f;
    if (fixed) fixed->clear();
    for (; f && *f; f++) {
        if (*f != '%') continue;
        const C* conv_at = f;
        f++;
        if (*f == '%') continue;
        bool plain = true;   // (no flags, width or precision: `%p` itself)
        while (*f && strchr("-+ #0'", static_cast<char>(*f)) && *f < 128) { f++; plain = false; }
        if (fixed && (*f == 'p') && plain) {
            fixed->append(start, conv_at);
            static const C x08[] = {'%', '0', '8', 'X', 0};
            fixed->append(x08);
            start = f + 1;
            out.Put(take32());
            continue;
        }
        if (*f == '*') { out.Put(static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(take32())))); f++; }
        while (*f >= '0' && *f <= '9') f++;
        if (*f == '.') {
            f++;
            if (*f == '*') { out.Put(static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(take32())))); f++; }
            while (*f >= '0' && *f <= '9') f++;
        }
        // length: 8 bytes for ll, I64, j; the rest 4 on x86 (l, h, hh, z, t, I, I32, w, L for
        // an integer; L of a float is a double to MSVC)
        bool wide = false;
        for (;;) {
            if (*f == 'l' && f[1] == 'l') { wide = true; f += 2; }
            else if (*f == 'I' && f[1] == '6' && f[2] == '4') { wide = true; f += 3; }
            else if (*f == 'I' && f[1] == '3' && f[2] == '2') { f += 3; }
            else if (*f == 'j') { wide = true; f++; }
            else if (*f && strchr("lhztIwLq", static_cast<char>(*f)) && *f < 128) { if (*f == 'q') wide = true; f++; }
            else break;
        }
        if (!*f) break;
        switch (*f) {
            case 'd': case 'i':
                out.Put(wide ? take64() : static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(take32()))));
                break;
            case 'u': case 'o': case 'x': case 'X': case 'c': case 'C': case 'b':
                out.Put(wide ? take64() : take32());
                break;
            case 'e': case 'E': case 'f': case 'F': case 'g': case 'G': case 'a': case 'A':
                out.Put(take64());
                break;
            default:      // s S p n Z: an address, below 2 GB
                out.Put(take32());
                break;
        }
    }
    if (fixed && !fixed->empty() && start) fixed->append(start);
}

// a printf call's arguments as x64's, and its format as ucrt is to read it (PrintfArgs)
template <typename C>
struct Printf {
    Args64 args;
    std::basic_string<C> fixed;
    const C* fmt;
    Printf(uint32_t f, uint32_t va) : fmt(At<C>(f)) { PrintfArgs(fmt, va, args, &fixed); }
    const C* Fmt() const { return fixed.empty() ? fmt : fixed.c_str(); }
    va_list List() { return args.List(); }
};

// scanf: every conversion an address, but a suppressed one (`%*d`); the secure forms (_s) give
// %c, %s and %[ a buffer size after it
template <typename C>
void ScanfArgs(const C* f, uint32_t va, bool secure, Args64& out) {
    auto take32 = [&]() { uint32_t v = *At<uint32_t>(va); va += 4; return v; };
    for (; f && *f; f++) {
        if (*f != '%') continue;
        f++;
        if (*f == '%') continue;
        bool suppress = *f == '*';
        if (suppress) f++;
        while (*f >= '0' && *f <= '9') f++;
        while (*f && strchr("lhztIjLwq0123456789", static_cast<char>(*f)) && *f < 128) f++;
        if (!*f) break;
        C conv = *f;
        if (conv == '[') {
            f++;
            if (*f == '^') f++;
            if (*f == ']') f++;
            while (*f && *f != ']') f++;
            if (!*f) break;
        }
        if (suppress) continue;
        out.Put(take32());
        if (secure && (conv == 'c' || conv == 's' || conv == '[' || conv == 'C' || conv == 'S')) out.Put(take32());
    }
}

FILE* File32(uint32_t f) {
    return At<FILE>(f);
}

// a conversion's end pointer, written to the reference's 4-byte slot
template <typename R, typename C, typename F>
R WithEnd32(uint32_t s, uint32_t end, F f) {
    C* e = nullptr;
    R r = f(At<C>(s), &e);
    if (end) *At<uint32_t>(end) = Low(e);
    return r;
}

template <typename Info>
void StartupInfoTo32(const Info& si, uint32_t out) {
    auto o = At<StartupInfo32>(out);
    memset(o, 0, sizeof *o);
    o->cb = sizeof *o;
    o->lpDesktop = Low(si.lpDesktop);
    o->lpTitle = Low(si.lpTitle);
    o->dwX = si.dwX; o->dwY = si.dwY; o->dwXSize = si.dwXSize; o->dwYSize = si.dwYSize;
    o->dwXCountChars = si.dwXCountChars; o->dwYCountChars = si.dwYCountChars;
    o->dwFillAttribute = si.dwFillAttribute; o->dwFlags = si.dwFlags;
    o->wShowWindow = si.wShowWindow;
    // (cbReserved2/lpReserved2 carry the C runtime's inherited handle table, in x64 layout: none)
    o->hStdInput = Low(si.hStdInput);
    o->hStdOutput = Low(si.hStdOutput);
    o->hStdError = Low(si.hStdError);
}

// ---- the reference's exceptions: x86 SEH dispatch over its fs:[0] chain (Ghidra32.h gen_eh_*) ----
//
// A frame's node is the reference's x86 one, in the translated function's frame (below 2 GB):
// { next, handler, ... }. Two handlers are known: vcruntime's C++ one, reached through a thunk
// (`mov eax, FuncInfo; jmp __CxxFrameHandler3`), its node at ebp - 0xc and the state at node + 8;
// and the CRT's _except_handler4, its node at ebp - 0x10, the scope table at node + 8 xored with
// the security cookie, the try level at node + 0xc. Funclets are the reference's addresses, and a
// call there runs their translation (RefImage's jumps), each given its frame's ebp.
namespace eh {

constexpr uint32_t kCxxCode = 0xE06D7363;        // ('msc' | 0xE0000000)
constexpr uint32_t kEndOfChain = 0xFFFFFFFF;
constexpr int32_t kTryNone = -2;

uint32_t U(uint32_t a) { return *At<uint32_t>(a); }
int32_t I(uint32_t a) { return *At<int32_t>(a); }

// a reference function's translation, by the jump table (gen/jumps.c), not through the jump
// written at its entry: a funclet can start too close to the next for one, the __finally block
// entered 3 bytes ahead of its normal path's call, rhtest eh. Its entry if it has none
void* PortOf(uint32_t ref) {
    for (unsigned int k = 0; k < g_genJumpCount; k++)
        if (g_genJumps[k].ref == ref) return g_genJumps[k].port;
    return reinterpret_cast<void*>(static_cast<uintptr_t>(ref));
}
// (RH_EHTRACE set: each funclet the dispatcher runs, on stderr)
bool Tracing() {
    static int on = -1;
    if (on < 0) on = GetEnvironmentVariableA("RH_EHTRACE", nullptr, 0) != 0;
    return on != 0;
}
uint32_t Call1(uint32_t ref, uint32_t a0) {
    if (Tracing()) fprintf(stderr, "rhipper eh: call %08X (%08X)\n", ref, a0);
    return reinterpret_cast<uint32_t (*)(uint32_t)>(PortOf(ref))(a0);
}
uint32_t Call2(uint32_t ref, uint32_t a0, uint32_t a1) {
    return reinterpret_cast<uint32_t (*)(uint32_t, uint32_t)>(PortOf(ref))(a0, a1);
}
uint32_t Call3(uint32_t ref, uint32_t a0, uint32_t a1, uint32_t a2) {
    return reinterpret_cast<uint32_t (*)(uint32_t, uint32_t, uint32_t)>(PortOf(ref))(a0, a1, a2);
}

uint32_t& Head() { return *At<uint32_t>(gen_teb32()); }

// the reference's /GS cookie, by its load configuration's SecurityCookie
uint32_t Cookie() {
    uint32_t pe = gen_ref_base + U(gen_ref_base + 0x3C);
    uint32_t dir = U(pe + 0x18 + 0x60 + 10 * 8);             // IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG
    if (dir == 0 || U(pe + 0x18 + 0x60 + 10 * 8 + 4) < 0x40) return 0;
    uint32_t va = U(gen_ref_base + dir + 0x3C);
    return va ? U(va) : 0;
}

bool InImage(uint32_t a) {
    uint32_t pe = gen_ref_base + U(gen_ref_base + 0x3C);
    return a >= gen_ref_base && a - gen_ref_base < U(pe + 0x18 + 0x38);   // SizeOfImage
}

// a C++ frame's FuncInfo, by its handler thunk (0 if it is no such thunk): translate32.py's table
// (gen/jumps.c), the thunk's `mov eax, FuncInfo`, as the reference's code is int3 here
uint32_t FuncInfoOf(uint32_t handler) {
    for (const unsigned int* p = g_genEhFuncInfo; p[0]; p += 2)
        if (p[0] == handler) return p[1];
    return 0;
}

// an EH4 frame's scope table (0 if the node is not one)
uint32_t ScopeTableOf(uint32_t node) {
    uint32_t st = U(node + 8) ^ Cookie();
    int32_t level = I(node + 0xC);
    if (!InImage(st) || level < kTryNone || level > 0x400) return 0;
    return st;
}

// and an EH3 frame's, _except_handler3's (an older compiler's library, Havok's in a client,
// whose SetThreadName raises 0x406D1388 under one, 2026-10-25): the same node at ebp - 0x10, its
// scope table at node + 8 as it is (no cookie, no header) and the try level at node + 0xC, -1
// for none. Taken only where the node is no EH4 one
constexpr int32_t kTryNone3 = -1;
uint32_t ScopeTable3Of(uint32_t node) {
    uint32_t st = U(node + 8);
    int32_t level = I(node + 0xC);
    if (!InImage(st) || level < kTryNone3 || level > 0x400) return 0;
    // (each record's filter and handler code in the image, or a __finally's 0 filter)
    for (int32_t l = level; l != kTryNone3;) {
        uint32_t rec = st + 12 * l;
        if (!InImage(rec) || (U(rec + 4) && !InImage(U(rec + 4))) || !InImage(U(rec + 8))) return 0;
        int32_t enclosing = I(rec);
        if (enclosing >= l) return 0;
        l = enclosing;
    }
    return st;
}

// an EH3 frame's __finally blocks from its try level down to `target`
void LocalUnwind3(uint32_t node, uint32_t st, int32_t target) {
    uint32_t ebp = node + 0x10;
    int32_t level = I(node + 0xC);
    while (level != kTryNone3 && level != target) {
        uint32_t rec = st + 12 * level;
        int32_t enclosing = I(rec);
        *At<int32_t>(node + 0xC) = enclosing;
        if (U(rec + 4) == 0) Call1(U(rec + 8), ebp);
        level = enclosing;
    }
}

struct Thrown {
    uint32_t code;
    uint32_t object;        // a C++ exception's object and ThrowInfo; 0 for SEH
    uint32_t info;
    uint32_t pointers;      // the reference's EXCEPTION_POINTERS, for filters' GetExceptionInformation
    bool rethrown;
};

// the catches in progress, innermost last (a rethrow's object is the innermost's)
thread_local std::vector<Thrown> g_caught;

struct Landing {
    uint32_t node;
    size_t depth;           // g_caught's size when the frame was linked: catches past it are left
    jmp_buf buf;
};
thread_local std::vector<std::unique_ptr<Landing>> g_landings;
thread_local uint32_t g_resumeAt, g_resumeEbp;

Landing* LandingOf(uint32_t node) {
    for (auto& l : g_landings)
        if (l->node == node) return l.get();
    return nullptr;
}

// the reference's EXCEPTION_RECORD and CONTEXT (x86: 0x50, 0x2cc bytes) and the pointers to them
uint32_t Pointers(uint32_t code, uint32_t flags, uint32_t n, const uint32_t* args) {
    auto p = static_cast<uint8_t*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 8 + 0x50 + 0x2CC));
    uint32_t base = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(p));
    uint32_t rec = base + 8, ctx = base + 8 + 0x50;
    *At<uint32_t>(base) = rec;
    *At<uint32_t>(base + 4) = ctx;
    *At<uint32_t>(rec) = code;
    *At<uint32_t>(rec + 4) = flags;
    *At<uint32_t>(rec + 0x10) = n > 15 ? 15 : n;
    for (uint32_t k = 0; k < n && k < 15; k++) *At<uint32_t>(rec + 0x14 + 4 * k) = args[k];
    return base;
}

// a C++ object's address as one of its bases (a CatchableType's thisDisplacement)
uint32_t Adjust(uint32_t object, uint32_t ct) {
    int32_t mdisp = I(ct + 8), pdisp = I(ct + 0xC), vdisp = I(ct + 0x10);
    uint32_t p = object + mdisp;
    if (pdisp >= 0) p += I(U(object + pdisp) + vdisp) + pdisp;
    return p;
}

const char* TypeName(uint32_t td) { return td ? At<const char>(td + 8) : ""; }

// the CatchableType of the thrown object a handler takes (0: none; 1: catch(...), no type)
uint32_t Matches(uint32_t handler, const Thrown& t) {
    uint32_t adjectives = U(handler), type = U(handler + 4);
    if (type == 0 || TypeName(type)[0] == 0 || (adjectives & 0x40)) return 1;
    if (t.code != kCxxCode || t.info == 0) return 0;
    uint32_t cta = U(t.info + 0xC);
    for (uint32_t k = 0, n = U(cta); k < n; k++) {
        uint32_t ct = U(cta + 4 + 4 * k);
        uint32_t ctType = U(ct + 4);
        if (ctType != type && strcmp(TypeName(ctType), TypeName(type)) != 0) continue;
        if ((U(ct) & 2) && !(adjectives & 8)) continue;          // (by reference only)
        return ct;
    }
    return 0;
}

// the catch's object at ebp + dispCatchObj: a reference, a copy of a simple type, or a copy made
// by the type's copy constructor
void BuildCatchObject(uint32_t handler, uint32_t ct, const Thrown& t, uint32_t ebp) {
    int32_t disp = I(handler + 8);
    if (ct <= 1 || disp == 0) return;
    uint32_t dest = ebp + disp, src = Adjust(t.object, ct);
    uint32_t props = U(ct), size = U(ct + 0x14), copy = U(ct + 0x18);
    if (U(handler) & 8)
        *At<uint32_t>(dest) = src;
    else if ((props & 1) || copy == 0)
        memcpy(At<void>(dest), At<void>(src), size);
    else if (props & 4)
        Call3(copy, dest, src, 1);
    else
        Call2(copy, dest, src);
}

// a C++ frame's state stepped back to `target`, each state's unwind action run
void UnwindToState(uint32_t node, uint32_t fi, int32_t target) {
    uint32_t ebp = node + 0xC, map = U(fi + 8);
    int32_t maxState = I(fi + 4);
    int32_t state = I(node + 8);
    while (state != target && state >= 0 && state < maxState) {
        int32_t next = I(map + 8 * state);
        uint32_t action = U(map + 8 * state + 4);
        *At<int32_t>(node + 8) = next;
        if (action) Call1(action, ebp);
        state = next;
    }
}

// an EH4 frame's termination handlers (__finally) from its try level down to `target`
void LocalUnwind4(uint32_t node, uint32_t st, int32_t target) {
    uint32_t ebp = node + 0x10;
    int32_t level = I(node + 0xC);
    while (level != kTryNone && level != target) {
        uint32_t rec = st + 0x10 + 12 * level;
        int32_t enclosing = I(rec);
        *At<int32_t>(node + 0xC) = enclosing;
        if (U(rec + 4) == 0) Call1(U(rec + 8), ebp);
        level = enclosing;
    }
}

// a frame the exception passes, left as its function would leave it
void UnwindFrame(uint32_t node) {
    uint32_t handler = U(node + 4);
    if (uint32_t fi = FuncInfoOf(handler))
        UnwindToState(node, fi, -1);
    else if (uint32_t st = ScopeTableOf(node))
        LocalUnwind4(node, st, kTryNone);
    else if (uint32_t st3 = ScopeTable3Of(node))
        LocalUnwind3(node, st3, kTryNone3);
}

[[noreturn]] void Land(uint32_t node, uint32_t at, uint32_t ebp) {
    Head() = node;
    Landing* l = LandingOf(node);
    if (l == nullptr) {
        fprintf(stderr, "rhipper: an exception caught by a frame with no landing (node %08X, at %08X)\n", node, at);
        TerminateProcess(GetCurrentProcess(), 3);
    }
    // (the catches this frame's function is in, its own and its callees', end here: their objects
    // destroyed but where a rethrow took one on)
    while (g_caught.size() > l->depth) {
        Thrown done = g_caught.back();
        g_caught.pop_back();
        if (!done.rethrown && done.object && U(done.info + 4)) Call1(U(done.info + 4), done.object);
    }
    g_resumeAt = at;
    g_resumeEbp = ebp;
    if (Tracing()) fprintf(stderr, "rhipper eh: land at node %08X, continuation %08X\n", node, at);
    longjmp(l->buf, 1);
}

// the dispatch: a search for the frame that takes the exception (a catch whose type matches, an
// __except whose filter says so), the frames above it unwound, then its catch run and the
// function landed at the continuation the catch returns, or the __except's block. Returns where
// a filter says to go on (EXCEPTION_CONTINUE_EXECUTION)
void Dispatch(Thrown t) {
    for (uint32_t node = Head(); node != kEndOfChain && node != 0; node = U(node)) {
        uint32_t handler = U(node + 4);
        if (uint32_t fi = FuncInfoOf(handler)) {
            if (t.code != kCxxCode) continue;
            int32_t state = I(node + 8);
            uint32_t tries = U(fi + 0x10);
            for (uint32_t k = 0, n = U(fi + 0xC); k < n; k++) {
                uint32_t tb = tries + 20 * k;
                int32_t low = I(tb), high = I(tb + 4);
                if (state < low || state > high) continue;
                for (uint32_t h = 0, nh = U(tb + 0xC); h < nh; h++) {
                    uint32_t ht = U(tb + 0x10) + 16 * h;
                    uint32_t ct = Matches(ht, t);
                    if (!ct) continue;
                    // (as vcruntime's CatchIt: the catch's object first, then the frames above
                    // unwound, then this one to the try block's state)
                    uint32_t ebp = node + 0xC;
                    BuildCatchObject(ht, ct, t, ebp);
                    for (uint32_t above = Head(); above != node; above = U(above)) {
                        Head() = above;
                        UnwindFrame(above);
                    }
                    Head() = node;
                    UnwindToState(node, fi, low);
                    *At<int32_t>(node + 8) = high + 1;
                    g_caught.push_back(t);
                    uint32_t at = Call1(U(ht + 0xC), ebp);
                    Land(node, at, ebp);
                }
            }
        } else if (uint32_t st = ScopeTableOf(node)) {
            uint32_t ebp = node + 0x10;
            for (int32_t level = I(node + 0xC); level != kTryNone;) {
                uint32_t rec = st + 0x10 + 12 * level;
                int32_t enclosing = I(rec);
                uint32_t filter = U(rec + 4);
                if (filter) {
                    *At<uint32_t>(ebp - 0x14) = t.pointers;
                    int32_t r = static_cast<int32_t>(Call1(filter, ebp));
                    if (r < 0) return;
                    if (r > 0) {
                        for (uint32_t above = Head(); above != node; above = U(above)) {
                            Head() = above;
                            UnwindFrame(above);
                        }
                        Head() = node;
                        LocalUnwind4(node, st, level);
                        *At<int32_t>(node + 0xC) = enclosing;
                        Land(node, U(rec + 8), ebp);
                    }
                }
                level = enclosing;
            }
        } else if (uint32_t st3 = ScopeTable3Of(node)) {
            uint32_t ebp = node + 0x10;
            for (int32_t level = I(node + 0xC); level != kTryNone3;) {
                uint32_t rec = st3 + 12 * level;
                int32_t enclosing = I(rec);
                uint32_t filter = U(rec + 4);
                if (filter) {
                    *At<uint32_t>(ebp - 0x14) = t.pointers;
                    int32_t r = static_cast<int32_t>(Call1(filter, ebp));
                    if (r < 0) return;
                    if (r > 0) {
                        for (uint32_t above = Head(); above != node; above = U(above)) {
                            Head() = above;
                            UnwindFrame(above);
                        }
                        Head() = node;
                        LocalUnwind3(node, st3, level);
                        *At<int32_t>(node + 0xC) = enclosing;
                        Land(node, U(rec + 8), ebp);
                    }
                }
                level = enclosing;
            }
        }
    }
    fprintf(stderr, "rhipper: unhandled exception %08X; the chain:\n", t.code);
    for (uint32_t node = Head(); node != kEndOfChain && node != 0; node = U(node))
        fprintf(stderr, "  node %08X handler %08X FuncInfo %08X scope table %08X state %d\n", node, U(node + 4),
                FuncInfoOf(U(node + 4)), ScopeTableOf(node), I(node + 8));
    TerminateProcess(GetCurrentProcess(), t.code == kCxxCode ? 3 : t.code);
}

}  // namespace eh

}  // namespace

extern "C" {

jmp_buf* gen_eh_landing(unsigned int node) {
    eh::Landing* l = eh::LandingOf(node);
    if (l == nullptr) {
        eh::g_landings.push_back(std::make_unique<eh::Landing>());
        l = eh::g_landings.back().get();
        l->node = node;
    }
    l->depth = eh::g_caught.size();
    if (eh::Tracing()) fprintf(stderr, "rhipper eh: frame linked at node %08X\n", node);
    return &l->buf;
}
// a landing's continuation, a function on the frame's ebp: what the frame's function returns
unsigned long long gen_eh_resume(void) {
    return eh::Call1(eh::g_resumeAt, eh::g_resumeEbp);
}
// a C++ throw: an object and its ThrowInfo, or both 0 to rethrow the innermost caught
[[noreturn]] static void CxxThrow(uint32_t magic, uint32_t object, uint32_t info) {
    eh::Thrown t{eh::kCxxCode, object, info, 0, false};
    if (object == 0 && info == 0) {
        if (eh::g_caught.empty()) {
            fprintf(stderr, "rhipper: a rethrow with no exception\n");
            TerminateProcess(GetCurrentProcess(), 3);
        }
        eh::g_caught.back().rethrown = true;
        t = eh::g_caught.back();
        t.rethrown = false;
    }
    uint32_t args[3] = {magic, t.object, t.info};
    t.pointers = eh::Pointers(eh::kCxxCode, 1, 3, args);
    eh::Dispatch(t);
    fprintf(stderr, "rhipper: a C++ exception continued\n");
    TerminateProcess(GetCurrentProcess(), 3);
    for (;;) {}
}
// throw (vcruntime's x86 __stdcall one, imported by a /MD program)
unsigned int gen_imp__CxxThrowException(uint32_t object, uint32_t info) {
    CxxThrow(0x19930520u, object, info);
}
// ---- a hardware fault in translated code, dispatched as the reference's SEH would -------------
// An access violation, a division by zero, a breakpoint or a privileged instruction inside a
// `__try`: the reference's filter and __except run, as for RaiseException. The exception handler
// cannot land there itself (Windows is mid-dispatch), so it sends the faulting thread to
// HwTrampoline, which dispatches on the thread's own stack as if the fault were a call to
// RaiseException; where a filter says to continue execution, the fault's context is restored and
// the instruction runs again (rhtest seh, 2026-10-27)
namespace {
struct HwFault {
    CONTEXT ctx;
    uint32_t code, n, a[4];
};
thread_local HwFault t_fault;

[[noreturn]] void HwTrampoline() {
    HwFault& f = t_fault;
    eh::Thrown t{f.code, 0, 0, eh::Pointers(f.code, 0, f.n, f.a), false};
    eh::Dispatch(t);
    RtlRestoreContext(&f.ctx, nullptr);
    for (;;) {}
}

bool InPortImage(uint64_t at) {
    static uint64_t lo = 0, hi = 0;
    if (!lo) {
        auto base = reinterpret_cast<const uint8_t*>(GetModuleHandleW(nullptr));
        auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + reinterpret_cast<const IMAGE_DOS_HEADER*>(base)->e_lfanew);
        lo = reinterpret_cast<uint64_t>(base);
        hi = lo + nt->OptionalHeader.SizeOfImage;
    }
    return at >= lo && at < hi;
}
}  // namespace

// (RefImage.cpp's exception handler: true where the fault is sent to the reference's handlers)
int gen_seh_hardware(EXCEPTION_POINTERS* ep) {
    auto r = ep->ExceptionRecord;
    switch (r->ExceptionCode) {
    case EXCEPTION_ACCESS_VIOLATION: case EXCEPTION_INT_DIVIDE_BY_ZERO: case EXCEPTION_INT_OVERFLOW:
    case EXCEPTION_BREAKPOINT: case EXCEPTION_PRIV_INSTRUCTION: case EXCEPTION_ILLEGAL_INSTRUCTION:
    case EXCEPTION_FLT_DIVIDE_BY_ZERO: case EXCEPTION_FLT_INVALID_OPERATION: case EXCEPTION_FLT_OVERFLOW:
    case EXCEPTION_FLT_UNDERFLOW: case EXCEPTION_FLT_INEXACT_RESULT: case EXCEPTION_FLT_STACK_CHECK:
    case EXCEPTION_FLT_DENORMAL_OPERAND: case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
        break;
    default:
        return 0;
    }
    // (only the translation's own faults, and only with a reference frame to take them: a system
    // DLL's, handled by its own frames, and one no __try covers stay the host's)
    if (!InPortImage(reinterpret_cast<uint64_t>(r->ExceptionAddress))) return 0;
    // (a thread the reference's code never ran on has no chain; asking would make its TEB, an
    // allocation in an exception handler)
    if (!gen_teb32_made()) return 0;
    uint32_t head = eh::Head();
    if (head == eh::kEndOfChain || head == 0) return 0;
    HwFault& f = t_fault;
    f.ctx = *ep->ContextRecord;
    f.code = static_cast<uint32_t>(r->ExceptionCode);
    f.n = r->NumberParameters < 4 ? r->NumberParameters : 4;
    for (uint32_t k = 0; k < f.n; k++) f.a[k] = static_cast<uint32_t>(r->ExceptionInformation[k]);
    CONTEXT* c = ep->ContextRecord;
    // (as if the faulting instruction had called it: its address the return address, just below
    // the faulting frame, so a landing's longjmp unwinds through the trampoline into that frame)
    c->Rsp -= 8;
    *reinterpret_cast<uint64_t*>(c->Rsp) = c->Rip;
    c->Rip = reinterpret_cast<uint64_t>(&HwTrampoline);
    return 1;
}

// RaiseException: dispatched as the reference's; returns where a filter continues execution.
// (a C++ throw too where the C runtime is the reference's own: VS2010's /MT _CxxThrowException is
// translated, and raises 0xE06D7363 with {magic, object, ThrowInfo}. Taken as an SEH exception,
// no typed catch matched it, catch (...) took every throw, and a rethrow had no object, rhtest
// msvc-16.00-x86 eh)
unsigned int gen_imp_RaiseException(uint32_t code, uint32_t flags, uint32_t n, uint32_t args) {
    uint32_t a[15] = {};
    for (uint32_t k = 0; k < n && k < 15; k++) a[k] = *At<uint32_t>(args + 4 * k);
    if (code == eh::kCxxCode && n >= 3 && a[0] >= 0x19930520u && a[0] <= 0x19930522u)
        CxxThrow(a[0], a[1], a[2]);
    eh::Thrown t{code, 0, 0, eh::Pointers(code, flags, n, a), false};
    eh::Dispatch(t);
    return 0;
}

// ExitProcess: the reference's program ends, on its thread (RefRun); the runtime ends the process
// once that thread has, with its trace flushed and the port's own runtime shut down in order. A
// static C runtime ends so, VS2010's _doexit, where a /MD one calls the host's exit
static void ExitReport(const char* how, uint32_t code);
unsigned int gen_imp_ExitProcess(uint32_t code) {
    ExitReport("ExitProcess", code);
    ExitThread(code);
}

// ---- critical sections ----------------------------------------------------------------------
unsigned int gen_imp_InitializeCriticalSection(uint32_t cs) {
    InitSection(cs, 0);
    return 0;
}
unsigned int gen_imp_InitializeCriticalSectionAndSpinCount(uint32_t cs, uint32_t spin) {
    InitSection(cs, spin);
    return 1;
}
unsigned int gen_imp_InitializeCriticalSectionEx(uint32_t cs, uint32_t spin, uint32_t) {
    InitSection(cs, spin);
    return 1;
}
unsigned int gen_imp_EnterCriticalSection(uint32_t cs) {
    EnterCriticalSection(HostSection(cs));
    return 0;
}
unsigned int gen_imp_LeaveCriticalSection(uint32_t cs) {
    LeaveCriticalSection(HostSection(cs));
    return 0;
}
unsigned int gen_imp_TryEnterCriticalSection(uint32_t cs) {
    return TryEnterCriticalSection(HostSection(cs));
}
unsigned int gen_imp_DeleteCriticalSection(uint32_t cs) {
    uint32_t mine = *At<uint32_t>(cs);
    if (mine) {
        DeleteCriticalSection(At<CRITICAL_SECTION>(mine));
        HeapFree(GetProcessHeap(), 0, At<void>(mine));
        *At<uint32_t>(cs) = 0;
    }
    return 0;
}
unsigned int gen_imp_SetCriticalSectionSpinCount(uint32_t cs, uint32_t spin) {
    return SetCriticalSectionSpinCount(HostSection(cs), spin);
}

// ---- structures laid out for x86 ------------------------------------------------------------
unsigned int gen_imp_GetStartupInfoW(uint32_t out) {
    STARTUPINFOW si = {sizeof si};
    GetStartupInfoW(&si);
    StartupInfoTo32(si, out);
    return 0;
}
unsigned int gen_imp_GetStartupInfoA(uint32_t out) {
    STARTUPINFOA si = {sizeof si};
    GetStartupInfoA(&si);
    StartupInfoTo32(si, out);
    return 0;
}
static void SystemInfoTo32(const SYSTEM_INFO& si, uint32_t out) {
    auto o = At<SystemInfo32>(out);
    o->wProcessorArchitecture = PROCESSOR_ARCHITECTURE_INTEL;   // (what the reference was built for)
    o->wReserved = 0;
    o->dwPageSize = si.dwPageSize;
    o->lpMinimumApplicationAddress = Low(si.lpMinimumApplicationAddress);
    o->lpMaximumApplicationAddress = 0x7ffeffff;                // the 2 GB the port lives in
    o->dwActiveProcessorMask = static_cast<uint32_t>(si.dwActiveProcessorMask);
    o->dwNumberOfProcessors = si.dwNumberOfProcessors;
    o->dwProcessorType = PROCESSOR_INTEL_PENTIUM;
    o->dwAllocationGranularity = si.dwAllocationGranularity;
    o->wProcessorLevel = si.wProcessorLevel;
    o->wProcessorRevision = si.wProcessorRevision;
}
unsigned int gen_imp_GetSystemInfo(uint32_t out) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    SystemInfoTo32(si, out);
    return 0;
}
unsigned int gen_imp_GetNativeSystemInfo(uint32_t out) {
    return gen_imp_GetSystemInfo(out);
}
unsigned int gen_imp_VirtualQuery(uint32_t address, uint32_t out, uint32_t length) {
    if (length < sizeof(MemoryInfo32)) return 0;
    MEMORY_BASIC_INFORMATION m;
    if (!VirtualQuery(At<void>(address), &m, sizeof m)) return 0;
    auto o = At<MemoryInfo32>(out);
    o->BaseAddress = Low(m.BaseAddress);
    o->AllocationBase = Low(m.AllocationBase);
    o->AllocationProtect = m.AllocationProtect;
    o->RegionSize = static_cast<uint32_t>(m.RegionSize);
    o->State = m.State;
    o->Protect = m.Protect;
    o->Type = m.Type;
    return sizeof(MemoryInfo32);
}

// ---- message boxes: what the reference says, on the console too ----------------------------
// <ENV>_NODIALOGS=1: a message box logged and answered with its default button, not shown. An
// unattended run (pipeline32.py's) that met the reference's "An unexpected error has occurred"
// waited on a dialog no one was there to close, 2026-10-26
static unsigned int Unattended(uint32_t type) {
    wchar_t v[8] = {};
    if (!RefEnv("NODIALOGS", v, 8) || v[0] == L'0') return 0;
    static const unsigned int buttons[][3] = {
        {IDOK, IDOK, IDOK}, {IDOK, IDCANCEL, IDCANCEL}, {IDABORT, IDRETRY, IDIGNORE},
        {IDYES, IDNO, IDCANCEL}, {IDYES, IDNO, IDNO}, {IDRETRY, IDCANCEL, IDCANCEL},
        {IDCANCEL, IDTRYAGAIN, IDCONTINUE}};
    unsigned kind = type & MB_TYPEMASK, def = (type & MB_DEFMASK) >> 8;
    return buttons[kind < 7 ? kind : 0][def < 3 ? def : 0];
}

unsigned int gen_imp_MessageBoxW(uint32_t hwnd, uint32_t text, uint32_t caption, uint32_t type) {
    // (narrow: stderr's first output was narrow, and a wide write to it then printed nothing)
    fprintf(stderr, "%s: MessageBox [%ls] %ls\n", RHIPPER_NAME, caption ? At<wchar_t>(caption) : L"",
            text ? At<wchar_t>(text) : L"");
    fflush(stderr);
    if (unsigned int r = Unattended(type)) return r;
    return MessageBoxW(At<HWND__>(hwnd), At<wchar_t>(text), At<wchar_t>(caption), type);
}
unsigned int gen_imp_MessageBoxA(uint32_t hwnd, uint32_t text, uint32_t caption, uint32_t type) {
    fprintf(stderr, "%s: MessageBox [%s] %s\n", RHIPPER_NAME, caption ? At<char>(caption) : "", text ? At<char>(text) : "");
    fflush(stderr);
    if (unsigned int r = Unattended(type)) return r;
    return MessageBoxA(At<HWND__>(hwnd), At<char>(text), At<char>(caption), type);
}

// ---- the process's end, said where: an exit with an exception's code (its own crash handler's
// TerminateProcess after catching one) left no report of the runtime's, 2026-10-26
extern "C++" void RefPrintStack(HANDLE thread, CONTEXT c);   // RefImage.cpp

static void ExitReport(const char* how, uint32_t code) {
    // (a clean exit says nothing: its stack pushed the run's own last lines out of the logs' tails,
    // ultrareview 2026-10-27)
    if (code == 0) return;
    fprintf(stderr, "%s: %s(%#x) on thread %lu\n", RHIPPER_NAME, how, code, GetCurrentThreadId());
    CONTEXT c = {};
    RtlCaptureContext(&c);
    RefPrintStack(GetCurrentThread(), c);
    fflush(stderr);
    RefTraceFlush();
}
unsigned int gen_imp_TerminateProcess(uint32_t process, uint32_t code) {
    HANDLE h = reinterpret_cast<HANDLE>(static_cast<intptr_t>(static_cast<int32_t>(process)));
    if (h == GetCurrentProcess() || GetProcessId(h) == GetCurrentProcessId()) ExitReport("TerminateProcess", code);
    return static_cast<unsigned int>(TerminateProcess(h, code));
}

// ---- messages: x86's MSG is 28 bytes (4-byte handle, wParam, lParam), x64's 48 -----------------
// Passed as they were, PeekMessage and GetMessage wrote x64's MSG over the 28 bytes the reference
// keeps on its stack: a client's message pump returned into the message's own words, WM_COMMAND's
// 0x111 its return address, 2026-10-26.
#pragma pack(push, 4)
struct Msg32 {
    uint32_t hwnd, message, wParam, lParam, time;
    int32_t x, y;
};
#pragma pack(pop)
static_assert(sizeof(Msg32) == 28, "MSG, x86");

static void ToMsg32(const MSG& m, uint32_t out) {
    auto o = At<Msg32>(out);
    o->hwnd = Low(m.hwnd);
    o->message = m.message;
    o->wParam = static_cast<uint32_t>(m.wParam);
    o->lParam = static_cast<uint32_t>(m.lParam);
    o->time = m.time;
    o->x = m.pt.x;
    o->y = m.pt.y;
}
static MSG FromMsg32(uint32_t in) {
    auto o = At<Msg32>(in);
    MSG m = {};
    m.hwnd = reinterpret_cast<HWND>(static_cast<uintptr_t>(o->hwnd));
    m.message = o->message;
    m.wParam = o->wParam;
    // (lParam signed, as LPARAM is: a packed coordinate's negative y stays negative)
    m.lParam = static_cast<LPARAM>(static_cast<int32_t>(o->lParam));
    m.time = o->time;
    m.pt.x = o->x;
    m.pt.y = o->y;
    return m;
}
static HWND Hwnd32(uint32_t h) {
    return reinterpret_cast<HWND>(static_cast<uintptr_t>(h));
}

unsigned int gen_imp_PeekMessageW(uint32_t msg, uint32_t hwnd, uint32_t lo, uint32_t hi, uint32_t remove) {
    MSG m = {};
    BOOL r = PeekMessageW(&m, Hwnd32(hwnd), lo, hi, remove);
    if (r && msg) ToMsg32(m, msg);
    return static_cast<unsigned int>(r);
}
unsigned int gen_imp_PeekMessageA(uint32_t msg, uint32_t hwnd, uint32_t lo, uint32_t hi, uint32_t remove) {
    MSG m = {};
    BOOL r = PeekMessageA(&m, Hwnd32(hwnd), lo, hi, remove);
    if (r && msg) ToMsg32(m, msg);
    return static_cast<unsigned int>(r);
}
unsigned int gen_imp_GetMessageW(uint32_t msg, uint32_t hwnd, uint32_t lo, uint32_t hi) {
    MSG m = {};
    BOOL r = GetMessageW(&m, Hwnd32(hwnd), lo, hi);
    if (r != -1 && msg) ToMsg32(m, msg);
    return static_cast<unsigned int>(r);
}
unsigned int gen_imp_TranslateMessage(uint32_t msg) {
    MSG m = FromMsg32(msg);
    return static_cast<unsigned int>(TranslateMessage(&m));
}
unsigned int gen_imp_DispatchMessageW(uint32_t msg) {
    MSG m = FromMsg32(msg);
    return static_cast<unsigned int>(DispatchMessageW(&m));
}
unsigned int gen_imp_DispatchMessageA(uint32_t msg) {
    MSG m = FromMsg32(msg);
    return static_cast<unsigned int>(DispatchMessageA(&m));
}
unsigned int gen_imp_TranslateAcceleratorA(uint32_t hwnd, uint32_t accel, uint32_t msg) {
    MSG m = FromMsg32(msg);
    return static_cast<unsigned int>(
        TranslateAcceleratorA(Hwnd32(hwnd), reinterpret_cast<HACCEL>(static_cast<uintptr_t>(accel)), &m));
}

// ---- window classes: x86's WNDCLASS(EX), 4-byte pointers and handles -----------------------
// Passed as they are, x64's RegisterClassExA read the 48-byte x86 structure as its 80-byte one
// and failed; CreateWindowExA then found no class, and a client's WinMain returned 0 before
// its window (2026-10-24). The class gets a window procedure of the runtime's, which calls the
// reference's (its jump reaches the translation, which takes its 4 arguments as 32-bit values)
// and widens its 32-bit result as the signed LRESULT it is.
extern "C++" {
namespace {
#pragma pack(push, 4)
struct WndClassEx32 {
    uint32_t cbSize, style, lpfnWndProc;
    int32_t cbClsExtra, cbWndExtra;
    uint32_t hInstance, hIcon, hCursor, hbrBackground, lpszMenuName, lpszClassName, hIconSm;
};
static_assert(sizeof(WndClassEx32) == 48, "WNDCLASSEX, x86");
struct WndClass32 {
    uint32_t style, lpfnWndProc;
    int32_t cbClsExtra, cbWndExtra;
    uint32_t hInstance, hIcon, hCursor, hbrBackground, lpszMenuName, lpszClassName;
};
static_assert(sizeof(WndClass32) == 40, "WNDCLASS, x86");
#pragma pack(pop)

SRWLOCK g_classLock = SRWLOCK_INIT;
std::vector<std::pair<ATOM, uint32_t>> g_classProcs;   // a class's atom, its reference procedure

uint32_t ClassProc(ATOM atom) {
    AcquireSRWLockShared(&g_classLock);
    uint32_t fn = 0;
    for (auto& [a, p] : g_classProcs) {
        if (a == atom) fn = p;
    }
    ReleaseSRWLockShared(&g_classLock);
    return fn;
}

// The messages whose lParam points to a structure holding handles or pointers, 8 bytes each on
// x64: the reference's window procedure reads x86's layout, so it gets an x86 copy, and what it
// writes back goes into Windows' own. Passed as they were, a client's WM_WINDOWPOSCHANGING read
// x64's second handle for its x and wrote its clamped size over the native y and cx: its window
// opened off the screen's bottom right and was moved and sized again on every frame (2026-10-26).
#pragma pack(push, 4)
struct WindowPos32 {
    uint32_t hwnd, hwndInsertAfter;
    int32_t x, y, cx, cy;
    uint32_t flags;
};
static_assert(sizeof(WindowPos32) == 28, "WINDOWPOS, x86");
struct NcCalcSize32 {
    RECT rgrc[3];
    uint32_t lppos;
};
static_assert(sizeof(NcCalcSize32) == 52, "NCCALCSIZE_PARAMS, x86");
struct CreateStruct32 {
    uint32_t lpCreateParams, hInstance, hMenu, hwndParent;
    int32_t cy, cx, y, x;
    int32_t style;
    uint32_t lpszName, lpszClass;
    uint32_t dwExStyle;
};
static_assert(sizeof(CreateStruct32) == 48, "CREATESTRUCT, x86");
#pragma pack(pop)

void PosTo32(const WINDOWPOS& p, WindowPos32& o) {
    o.hwnd = Low(p.hwnd);
    o.hwndInsertAfter = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(p.hwndInsertAfter));
    o.x = p.x;
    o.y = p.y;
    o.cx = p.cx;
    o.cy = p.cy;
    o.flags = p.flags;
}
void PosFrom32(const WindowPos32& o, WINDOWPOS& p) {
    // (HWND_TOP 0, HWND_BOTTOM 1, HWND_TOPMOST -1, HWND_NOTOPMOST -2: sign-extended, as handles are)
    p.hwndInsertAfter = reinterpret_cast<HWND>(static_cast<intptr_t>(static_cast<int32_t>(o.hwndInsertAfter)));
    p.x = o.x;
    p.y = o.y;
    p.cx = o.cx;
    p.cy = o.cy;
    p.flags = o.flags;
}

LRESULT CALLBACK GenWndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    uint32_t fn = ClassProc(static_cast<ATOM>(GetClassWord(hwnd, GCW_ATOM)));
    if (!fn) return IsWindowUnicode(hwnd) ? DefWindowProcW(hwnd, msg, wp, lp) : DefWindowProcA(hwnd, msg, wp, lp);
    using Proc = unsigned int (*)(uint32_t, uint32_t, uint32_t, uint32_t);
    auto call = [&](uint32_t lp32) {
        unsigned int r = reinterpret_cast<Proc>(static_cast<uintptr_t>(fn))(Low(hwnd), msg, static_cast<uint32_t>(wp), lp32);
        return static_cast<LRESULT>(static_cast<int32_t>(r));
    };
    if (lp && (msg == WM_WINDOWPOSCHANGING || msg == WM_WINDOWPOSCHANGED)) {
        auto& p = *reinterpret_cast<WINDOWPOS*>(lp);
        WindowPos32 o;
        PosTo32(p, o);
        LRESULT r = call(static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&o)));
        PosFrom32(o, p);
        return r;
    }
    if (lp && msg == WM_NCCALCSIZE && wp) {
        auto& n = *reinterpret_cast<NCCALCSIZE_PARAMS*>(lp);
        WindowPos32 o = {};
        NcCalcSize32 n32;
        memcpy(n32.rgrc, n.rgrc, sizeof n32.rgrc);
        if (n.lppos) PosTo32(*n.lppos, o);
        n32.lppos = n.lppos ? static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&o)) : 0;
        LRESULT r = call(static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&n32)));
        memcpy(n.rgrc, n32.rgrc, sizeof n32.rgrc);
        if (n.lppos) PosFrom32(o, *n.lppos);
        return r;
    }
    if (lp && (msg == WM_CREATE || msg == WM_NCCREATE)) {
        // (the A and W structures alike: the same fields, the strings' type apart)
        auto& c = *reinterpret_cast<CREATESTRUCTA*>(lp);
        CreateStruct32 c32;
        c32.lpCreateParams = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(c.lpCreateParams));
        c32.hInstance = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(c.hInstance));
        c32.hMenu = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(c.hMenu));
        c32.hwndParent = Low(c.hwndParent);
        c32.cy = c.cy;
        c32.cx = c.cx;
        c32.y = c.y;
        c32.x = c.x;
        c32.style = c.style;
        c32.lpszName = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(c.lpszName));
        c32.lpszClass = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(c.lpszClass));
        c32.dwExStyle = c.dwExStyle;
        return call(static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&c32)));
    }
    return call(static_cast<uint32_t>(lp));
}

// A native procedure (DefWindowProc, DefDlgProc, CallWindowProc's ...) from the reference's window
// procedure, handed the x86 copy GenWndProc made: a native structure for Windows again, what it
// changes copied back. `native(hwnd, lparam)` makes the call
template <typename F>
LRESULT Native32(uint32_t hwnd32, uint32_t msg, uint32_t wp, uint32_t lp, F native) {
    HWND hwnd = reinterpret_cast<HWND>(static_cast<intptr_t>(static_cast<int32_t>(hwnd32)));
    auto def = [&](LPARAM l) { return native(hwnd, l); };
    if (lp && (msg == WM_WINDOWPOSCHANGING || msg == WM_WINDOWPOSCHANGED)) {
        auto& o = *At<WindowPos32>(lp);
        WINDOWPOS p = {};
        p.hwnd = hwnd;
        PosFrom32(o, p);
        LRESULT r = def(reinterpret_cast<LPARAM>(&p));
        PosTo32(p, o);
        return r;
    }
    if (lp && msg == WM_NCCALCSIZE && wp) {
        auto& n32 = *At<NcCalcSize32>(lp);
        NCCALCSIZE_PARAMS n = {};
        WINDOWPOS p = {};
        memcpy(n.rgrc, n32.rgrc, sizeof n.rgrc);
        if (n32.lppos) {
            p.hwnd = hwnd;
            PosFrom32(*At<WindowPos32>(n32.lppos), p);
            n.lppos = &p;
        }
        LRESULT r = def(reinterpret_cast<LPARAM>(&n));
        memcpy(n32.rgrc, n.rgrc, sizeof n32.rgrc);
        if (n32.lppos) PosTo32(p, *At<WindowPos32>(n32.lppos));
        return r;
    }
    if (lp && (msg == WM_CREATE || msg == WM_NCCREATE)) {
        auto& c32 = *At<CreateStruct32>(lp);
        CREATESTRUCTA c = {};
        c.lpCreateParams = reinterpret_cast<LPVOID>(static_cast<uintptr_t>(c32.lpCreateParams));
        c.hInstance = reinterpret_cast<HINSTANCE>(static_cast<uintptr_t>(c32.hInstance));
        c.hMenu = reinterpret_cast<HMENU>(static_cast<intptr_t>(static_cast<int32_t>(c32.hMenu)));
        c.hwndParent = reinterpret_cast<HWND>(static_cast<intptr_t>(static_cast<int32_t>(c32.hwndParent)));
        c.cy = c32.cy;
        c.cx = c32.cx;
        c.y = c32.y;
        c.x = c32.x;
        c.style = c32.style;
        c.lpszName = reinterpret_cast<LPCSTR>(static_cast<uintptr_t>(c32.lpszName));
        c.lpszClass = reinterpret_cast<LPCSTR>(static_cast<uintptr_t>(c32.lpszClass));
        c.dwExStyle = c32.dwExStyle;
        return def(reinterpret_cast<LPARAM>(&c));
    }
    return def(static_cast<LPARAM>(static_cast<intptr_t>(static_cast<int32_t>(lp))));
}

LRESULT DefWindowProc32(bool wide, uint32_t hwnd32, uint32_t msg, uint32_t wp, uint32_t lp) {
    return Native32(hwnd32, msg, wp, lp, [&](HWND h, LPARAM l) {
        return wide ? DefWindowProcW(h, msg, static_cast<WPARAM>(wp), l) : DefWindowProcA(h, msg, static_cast<WPARAM>(wp), l);
    });
}

// a name or a resource number (below 0x10000, MAKEINTRESOURCE)
template <typename C>
const C* NameOrId(uint32_t p) {
    return p < 0x10000 ? reinterpret_cast<const C*>(static_cast<uintptr_t>(p)) : At<const C>(p);
}

template <typename C, typename W>
void ClassFrom32(W& wc, uint32_t style, int32_t clsExtra, int32_t wndExtra, uint32_t inst, uint32_t icon,
                 uint32_t cursor, uint32_t brush, uint32_t menu, uint32_t name) {
    wc.style = style;
    wc.lpfnWndProc = GenWndProc;
    wc.cbClsExtra = clsExtra;
    wc.cbWndExtra = wndExtra;
    wc.hInstance = reinterpret_cast<HINSTANCE>(static_cast<uintptr_t>(inst));
    wc.hIcon = reinterpret_cast<HICON>(static_cast<intptr_t>(static_cast<int32_t>(icon)));
    wc.hCursor = reinterpret_cast<HCURSOR>(static_cast<intptr_t>(static_cast<int32_t>(cursor)));
    // (a brush is a handle, or a system colour + 1)
    wc.hbrBackground = reinterpret_cast<HBRUSH>(static_cast<intptr_t>(static_cast<int32_t>(brush)));
    wc.lpszMenuName = NameOrId<C>(menu);
    wc.lpszClassName = NameOrId<C>(name);
}

unsigned int Registered(ATOM atom, uint32_t proc) {
    if (atom) {
        AcquireSRWLockExclusive(&g_classLock);
        g_classProcs.emplace_back(atom, proc);
        ReleaseSRWLockExclusive(&g_classLock);
    }
    return atom;
}
}  // namespace
}  // extern "C++"

unsigned int gen_imp_RegisterClassExA(uint32_t p) {
    auto c = At<WndClassEx32>(p);
    WNDCLASSEXA wc{sizeof wc};
    ClassFrom32<char>(wc, c->style, c->cbClsExtra, c->cbWndExtra, c->hInstance, c->hIcon, c->hCursor,
                      c->hbrBackground, c->lpszMenuName, c->lpszClassName);
    wc.hIconSm = reinterpret_cast<HICON>(static_cast<intptr_t>(static_cast<int32_t>(c->hIconSm)));
    return Registered(RegisterClassExA(&wc), c->lpfnWndProc);
}
unsigned int gen_imp_RegisterClassExW(uint32_t p) {
    auto c = At<WndClassEx32>(p);
    WNDCLASSEXW wc{sizeof wc};
    ClassFrom32<wchar_t>(wc, c->style, c->cbClsExtra, c->cbWndExtra, c->hInstance, c->hIcon, c->hCursor,
                         c->hbrBackground, c->lpszMenuName, c->lpszClassName);
    wc.hIconSm = reinterpret_cast<HICON>(static_cast<intptr_t>(static_cast<int32_t>(c->hIconSm)));
    return Registered(RegisterClassExW(&wc), c->lpfnWndProc);
}
unsigned int gen_imp_RegisterClassA(uint32_t p) {
    auto c = At<WndClass32>(p);
    WNDCLASSA wc{};
    ClassFrom32<char>(wc, c->style, c->cbClsExtra, c->cbWndExtra, c->hInstance, c->hIcon, c->hCursor,
                      c->hbrBackground, c->lpszMenuName, c->lpszClassName);
    return Registered(RegisterClassA(&wc), c->lpfnWndProc);
}
unsigned int gen_imp_RegisterClassW(uint32_t p) {
    auto c = At<WndClass32>(p);
    WNDCLASSW wc{};
    ClassFrom32<wchar_t>(wc, c->style, c->cbClsExtra, c->cbWndExtra, c->hInstance, c->hIcon, c->hCursor,
                         c->hbrBackground, c->lpszMenuName, c->lpszClassName);
    return Registered(RegisterClassW(&wc), c->lpfnWndProc);
}

// ---- pointer encoding: the reference keeps encoded pointers in 4 bytes ----------------------
// x64's EncodePointer scrambles all 64 bits, and the 4 the reference kept decoded to garbage that
// the C runtime then called (0xcc0a2740, 2026-10-23). The encoding only has to round-trip: none.
unsigned int gen_imp_EncodePointer(uint32_t p) {
    return p;
}
unsigned int gen_imp_DecodePointer(uint32_t p) {
    return p;
}

// ---- kernel32 exports that x64 Windows has only as compiler intrinsics -----------------------
unsigned int gen_imp_InterlockedIncrement(uint32_t p) {
    return static_cast<unsigned int>(InterlockedIncrement(At<volatile LONG>(p)));
}
unsigned int gen_imp_InterlockedDecrement(uint32_t p) {
    return static_cast<unsigned int>(InterlockedDecrement(At<volatile LONG>(p)));
}
unsigned int gen_imp_InterlockedExchange(uint32_t p, uint32_t v) {
    return static_cast<unsigned int>(InterlockedExchange(At<volatile LONG>(p), static_cast<LONG>(v)));
}
unsigned int gen_imp_InterlockedExchangeAdd(uint32_t p, uint32_t v) {
    return static_cast<unsigned int>(InterlockedExchangeAdd(At<volatile LONG>(p), static_cast<LONG>(v)));
}
unsigned int gen_imp_InterlockedCompareExchange(uint32_t p, uint32_t v, uint32_t cmp) {
    return static_cast<unsigned int>(
        InterlockedCompareExchange(At<volatile LONG>(p), static_cast<LONG>(v), static_cast<LONG>(cmp)));
}

// ---- the module: the reference's image, not the port's --------------------------------------
// (GetModuleHandle(NULL) is the image the code reads its own PE headers from: the CRT's
// __scrt_is_managed_app checked the port's x64 headers as PE32)
// the 64-bit name of a 32-bit library that has one of its own (a path's file name compared)
static const char* Library64(const char* name) {
    static const char* const twins[][2] = {{"nvapi.dll", "nvapi64.dll"}, {"nvapi", "nvapi64"}};
    if (name == nullptr) return name;
    const char* file = name;
    for (const char* p = name; *p; p++)
        if (*p == '\\' || *p == '/') file = p + 1;
    for (const auto& t : twins)
        if (_stricmp(file, t[0]) == 0) return t[1];
    return name;
}
unsigned int gen_imp_GetModuleHandleW(uint32_t name) {
    return name ? Low(GetModuleHandleW(At<wchar_t>(name))) : gen_ref_base;
}
unsigned int gen_imp_GetModuleHandleA(uint32_t name) {
    return name ? Low(GetModuleHandleA(Library64(At<char>(name)))) : gen_ref_base;
}
// (a 32-bit library whose 64-bit twin has another name, as the port loads it: NVIDIA's NVAPI,
// nvapi.dll on x86 and nvapi64.dll on x64. Not loaded, the 32-bit reference's driver queries took
// their no-NVAPI path, the reference its NVAPI one, and the two runs parted, 2026-10-25)
unsigned int gen_imp_LoadLibraryA(uint32_t name) {
    return Low(LoadLibraryA(name ? Library64(At<char>(name)) : nullptr));
}
// (and its file name is the reference's: a client hashes its own executable at startup,
// GetModuleFileNameW(NULL) and a read of it in 1 KB pieces, and the port's file, another size,
// read one piece more, 2026-10-25). As the API: the length copied, the name cut and
// ERROR_INSUFFICIENT_BUFFER where it does not fit with its terminator
// ---- SECURITY_ATTRIBUTES: 12 bytes on x86 (length, a 4-byte descriptor pointer, inherit), 24 on
// x64. Handed through as it was, the CRT's _sopen gave CreateFileA its x86 one and Windows read past
// it: ERROR_NOACCESS, and a client's first file open failed, 2026-10-25 ----------------------------
struct SA32 {
    uint32_t length, descriptor, inherit;
};
static SECURITY_ATTRIBUTES* Sa64(uint32_t p, SECURITY_ATTRIBUTES* out) {
    if (p == 0) return nullptr;
    const SA32* s = At<SA32>(p);
    out->nLength = sizeof *out;
    out->lpSecurityDescriptor = At<void>(s->descriptor);
    out->bInheritHandle = static_cast<BOOL>(s->inherit);
    return out;
}
unsigned int gen_imp_CreateFileA(uint32_t name, uint32_t access, uint32_t share, uint32_t sa, uint32_t disposition,
                                 uint32_t flags, uint32_t tmpl) {
    SECURITY_ATTRIBUTES s;
    return Low(CreateFileA(At<char>(name), access, share, Sa64(sa, &s), disposition, flags,
                           reinterpret_cast<HANDLE>(static_cast<uintptr_t>(tmpl))));
}
unsigned int gen_imp_CreateFileW(uint32_t name, uint32_t access, uint32_t share, uint32_t sa, uint32_t disposition,
                                 uint32_t flags, uint32_t tmpl) {
    SECURITY_ATTRIBUTES s;
    return Low(CreateFileW(At<wchar_t>(name), access, share, Sa64(sa, &s), disposition, flags,
                           reinterpret_cast<HANDLE>(static_cast<uintptr_t>(tmpl))));
}
// ---- OVERLAPPED: 20 bytes on x86 (Internal, InternalHigh, Offset, OffsetHigh, hEvent), 32 on
// x64. Handed through, Windows took the x86 Offset for InternalHigh's upper half and the event from
// past the end: every positioned ReadFile and WriteFile failed (rhtest sys, 2026-10-27). Each x86
// OVERLAPPED gets a native one of its own, kept while it may still be in flight (an asynchronous
// handle's operation finishes after the call): the offsets and event copied in at each call, the
// status and count copied back after it and at GetOverlappedResult, where the reference's
// HasOverlappedIoCompleted reads them
struct Ov32 {
    uint32_t internal, internalHigh, offset, offsetHigh, event;
};
static HANDLE H64(uint32_t h) { return reinterpret_cast<HANDLE>(static_cast<intptr_t>(static_cast<int32_t>(h))); }
static std::mutex g_ovLock;
static std::unordered_map<uint32_t, OVERLAPPED*> g_ovMade;
static std::unordered_map<const OVERLAPPED*, uint32_t> g_ovOf;     // (a completion port's, back)
static OVERLAPPED* Ov64(uint32_t p) {
    if (p == 0) return nullptr;
    OVERLAPPED* o;
    {
        std::lock_guard<std::mutex> hold(g_ovLock);
        auto& slot = g_ovMade[p];
        if (!slot) {
            slot = static_cast<OVERLAPPED*>(calloc(1, sizeof(OVERLAPPED)));
            g_ovOf[slot] = p;
        }
        o = slot;
    }
    const Ov32* s = At<Ov32>(p);
    o->Internal = s->internal;
    o->InternalHigh = s->internalHigh;
    o->Offset = s->offset;
    o->OffsetHigh = s->offsetHigh;
    o->hEvent = H64(s->event);
    return o;
}
static void OvBack(uint32_t p, const OVERLAPPED* o) {
    if (p == 0 || o == nullptr) return;
    Ov32* s = At<Ov32>(p);
    s->internal = static_cast<uint32_t>(o->Internal);
    s->internalHigh = static_cast<uint32_t>(o->InternalHigh);
}
unsigned int gen_imp_ReadFile(uint32_t h, uint32_t buf, uint32_t n, uint32_t got, uint32_t ov) {
    OVERLAPPED* o = Ov64(ov);
    BOOL r = ReadFile(H64(h), At<void>(buf), n, got ? At<DWORD>(got) : nullptr, o);
    DWORD e = GetLastError();
    OvBack(ov, o);
    SetLastError(e);
    return r;
}
unsigned int gen_imp_WriteFile(uint32_t h, uint32_t buf, uint32_t n, uint32_t put, uint32_t ov) {
    OVERLAPPED* o = Ov64(ov);
    BOOL r = WriteFile(H64(h), At<void>(buf), n, put ? At<DWORD>(put) : nullptr, o);
    DWORD e = GetLastError();
    OvBack(ov, o);
    SetLastError(e);
    return r;
}
unsigned int gen_imp_GetOverlappedResult(uint32_t h, uint32_t ov, uint32_t got, uint32_t wait) {
    OVERLAPPED* o = Ov64(ov);
    BOOL r = GetOverlappedResult(H64(h), o, At<DWORD>(got), wait);
    DWORD e = GetLastError();
    OvBack(ov, o);
    SetLastError(e);
    return r;
}
unsigned int gen_imp_DeviceIoControl(uint32_t h, uint32_t code, uint32_t in, uint32_t inSize, uint32_t out,
                                     uint32_t outSize, uint32_t got, uint32_t ov) {
    OVERLAPPED* o = Ov64(ov);
    BOOL r = DeviceIoControl(H64(h), code, in ? At<void>(in) : nullptr, inSize, out ? At<void>(out) : nullptr, outSize,
                             got ? At<DWORD>(got) : nullptr, o);
    DWORD e = GetLastError();
    OvBack(ov, o);
    SetLastError(e);
    return r;
}
unsigned int gen_imp_LockFileEx(uint32_t h, uint32_t flags, uint32_t reserved, uint32_t lo, uint32_t hi, uint32_t ov) {
    OVERLAPPED* o = Ov64(ov);
    BOOL r = LockFileEx(H64(h), flags, reserved, lo, hi, o);
    DWORD e = GetLastError();
    OvBack(ov, o);
    SetLastError(e);
    return r;
}
unsigned int gen_imp_UnlockFileEx(uint32_t h, uint32_t reserved, uint32_t lo, uint32_t hi, uint32_t ov) {
    OVERLAPPED* o = Ov64(ov);
    BOOL r = UnlockFileEx(H64(h), reserved, lo, hi, o);
    DWORD e = GetLastError();
    OvBack(ov, o);
    SetLastError(e);
    return r;
}
unsigned int gen_imp_CancelIoEx(uint32_t h, uint32_t ov) {
    return CancelIoEx(H64(h), ov ? Ov64(ov) : nullptr);
}
// a completion port hands back the native OVERLAPPED: the reference's own, its status copied in
// (and a key or an OVERLAPPED posted by PostQueuedCompletionStatus, an x86 value, as it is)
unsigned int gen_imp_GetQueuedCompletionStatus(uint32_t port, uint32_t got, uint32_t key, uint32_t ov, uint32_t ms) {
    DWORD n = 0;
    ULONG_PTR k = 0;
    OVERLAPPED* o = nullptr;
    BOOL r = GetQueuedCompletionStatus(H64(port), &n, &k, &o, ms);
    DWORD e = GetLastError();
    uint32_t back = 0;
    bool ours = false;
    if (o) {
        std::lock_guard<std::mutex> hold(g_ovLock);
        auto it = g_ovOf.find(o);
        ours = it != g_ovOf.end();
        back = ours ? it->second : static_cast<uint32_t>(reinterpret_cast<uintptr_t>(o));
    }
    if (ours) OvBack(back, o);
    if (got) *At<DWORD>(got) = n;
    if (key) *At<uint32_t>(key) = static_cast<uint32_t>(k);
    if (ov) *At<uint32_t>(ov) = back;
    SetLastError(e);
    return r;
}
unsigned int gen_imp_PostQueuedCompletionStatus(uint32_t port, uint32_t n, uint32_t key, uint32_t ov) {
    // (the reference's OVERLAPPED posted as its x86 address: handed back as it was)
    return PostQueuedCompletionStatus(H64(port), n, key, reinterpret_cast<OVERLAPPED*>(static_cast<uintptr_t>(ov)));
}
// ---- the interlocked singly linked list: x86's header is 8 bytes (the first entry, a 16-bit
// depth, a 16-bit sequence) and its entries 4, x64's 16 and 16, aligned so. Handed x64's
// functions, the reference's 8-aligned header crashed them (rhtest sys, 2026-10-27). x86's own
// algorithm: a compare-exchange of the whole header, the sequence counted up at each push against a
// pop's ABA
static volatile LONG64* SlHead(uint32_t h) { return reinterpret_cast<volatile LONG64*>(At<uint8_t>(h)); }
static LONG64 SlMake(uint32_t first, uint32_t depth, uint32_t seq) {
    return static_cast<LONG64>(static_cast<uint64_t>(first) | (static_cast<uint64_t>(depth & 0xFFFF) << 32) |
                               (static_cast<uint64_t>(seq & 0xFFFF) << 48));
}
// (the CRT's type_info list head among them)
unsigned int gen_imp_InitializeSListHead(uint32_t h) {
    *SlHead(h) = 0;
    return 0;
}

// ---- one-time initialization: x86's INIT_ONCE is one 4-byte word, its context 4 bytes, x64's 8
// and 8: Windows' wrote past the reference's static INIT_ONCE and its callback's context (rhtest
// sys, 2026-10-27). x86's state kept in the word: 0 not begun, 1 running, the context | 2 done
unsigned int gen_imp_InitOnceInitialize(uint32_t once) {
    *At<uint32_t>(once) = 0;
    return 0;
}
unsigned int gen_imp_InitOnceExecuteOnce(uint32_t once, uint32_t fn, uint32_t param, uint32_t ctx) {
    auto w = reinterpret_cast<volatile LONG*>(At<uint32_t>(once));
    for (;;) {
        LONG v = *w;
        if ((v & 3) == 2) {
            if (ctx) *At<uint32_t>(ctx) = static_cast<uint32_t>(v) & ~3u;
            return 1;
        }
        if ((v & 3) == 1 || InterlockedCompareExchange(w, 1, 0) != 0) {
            Sleep(0);
            continue;
        }
        // (the reference's callback, its context in a word of the stack: low, as the x86 code's)
        uint32_t made = 0;
        using Fn = unsigned int (*)(uint32_t, uint32_t, uint32_t);
        unsigned int ok = reinterpret_cast<Fn>(static_cast<uintptr_t>(fn))(
            once, param, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&made)));
        if (!ok) {
            InterlockedExchange(w, 0);
            return 0;
        }
        InterlockedExchange(w, static_cast<LONG>((made & ~3u) | 2));
        if (ctx) *At<uint32_t>(ctx) = made & ~3u;
        return 1;
    }
}
unsigned int gen_imp_InterlockedPushEntrySList(uint32_t h, uint32_t e) {
    for (;;) {
        LONG64 old = *SlHead(h);
        uint32_t first = static_cast<uint32_t>(old);
        *At<uint32_t>(e) = first;
        LONG64 now = SlMake(e, static_cast<uint32_t>(old >> 32) + 1, static_cast<uint32_t>(old >> 48) + 1);
        if (InterlockedCompareExchange64(SlHead(h), now, old) == old) return first;
    }
}
unsigned int gen_imp_InterlockedPopEntrySList(uint32_t h) {
    for (;;) {
        LONG64 old = *SlHead(h);
        uint32_t first = static_cast<uint32_t>(old);
        if (first == 0) return 0;
        LONG64 now = SlMake(*At<uint32_t>(first), static_cast<uint32_t>(old >> 32) - 1, static_cast<uint32_t>(old >> 48));
        if (InterlockedCompareExchange64(SlHead(h), now, old) == old) return first;
    }
}
unsigned int gen_imp_InterlockedFlushSList(uint32_t h) {
    for (;;) {
        LONG64 old = *SlHead(h);
        uint32_t first = static_cast<uint32_t>(old);
        if (first == 0) return 0;
        if (InterlockedCompareExchange64(SlHead(h), SlMake(0, 0, static_cast<uint32_t>(old >> 48)), old) == old)
            return first;
    }
}
unsigned int gen_imp_QueryDepthSList(uint32_t h) {
    return static_cast<unsigned int>((*SlHead(h) >> 32) & 0xFFFF);
}
// (a chain of entries, first to last, pushed at once: count of them)
unsigned int gen_imp_InterlockedPushListSListEx(uint32_t h, uint32_t first, uint32_t last, uint32_t count) {
    for (;;) {
        LONG64 old = *SlHead(h);
        uint32_t was = static_cast<uint32_t>(old);
        *At<uint32_t>(last) = was;
        LONG64 now = SlMake(first, static_cast<uint32_t>(old >> 32) + count, static_cast<uint32_t>(old >> 48) + 1);
        if (InterlockedCompareExchange64(SlHead(h), now, old) == old) return was;
    }
}
unsigned int gen_imp_CreateDirectoryW(uint32_t path, uint32_t sa) {
    SECURITY_ATTRIBUTES s;
    return CreateDirectoryW(At<wchar_t>(path), Sa64(sa, &s));
}
unsigned int gen_imp_CreateDirectoryA(uint32_t path, uint32_t sa) {
    SECURITY_ATTRIBUTES s;
    return CreateDirectoryA(At<char>(path), Sa64(sa, &s));
}
unsigned int gen_imp_CreateEventA(uint32_t sa, uint32_t manual, uint32_t initial, uint32_t name) {
    SECURITY_ATTRIBUTES s;
    return Low(CreateEventA(Sa64(sa, &s), manual, initial, At<char>(name)));
}
unsigned int gen_imp_CreateEventW(uint32_t sa, uint32_t manual, uint32_t initial, uint32_t name) {
    SECURITY_ATTRIBUTES s;
    return Low(CreateEventW(Sa64(sa, &s), manual, initial, At<wchar_t>(name)));
}
unsigned int gen_imp_CreateMutexA(uint32_t sa, uint32_t owner, uint32_t name) {
    SECURITY_ATTRIBUTES s;
    return Low(CreateMutexA(Sa64(sa, &s), owner, At<char>(name)));
}
unsigned int gen_imp_CreateMutexW(uint32_t sa, uint32_t owner, uint32_t name) {
    SECURITY_ATTRIBUTES s;
    return Low(CreateMutexW(Sa64(sa, &s), owner, At<wchar_t>(name)));
}
unsigned int gen_imp_CreateSemaphoreA(uint32_t sa, uint32_t initial, uint32_t maximum, uint32_t name) {
    SECURITY_ATTRIBUTES s;
    return Low(CreateSemaphoreA(Sa64(sa, &s), static_cast<LONG>(initial), static_cast<LONG>(maximum), At<char>(name)));
}
unsigned int gen_imp_CreateSemaphoreW(uint32_t sa, uint32_t initial, uint32_t maximum, uint32_t name) {
    SECURITY_ATTRIBUTES s;
    return Low(CreateSemaphoreW(Sa64(sa, &s), static_cast<LONG>(initial), static_cast<LONG>(maximum), At<wchar_t>(name)));
}
// (and its two handles into the reference's 4-byte slots)
unsigned int gen_imp_CreatePipe(uint32_t read, uint32_t write, uint32_t sa, uint32_t size) {
    SECURITY_ATTRIBUTES s;
    HANDLE r = nullptr, w = nullptr;
    BOOL ok = CreatePipe(&r, &w, Sa64(sa, &s), size);
    if (ok) {
        *At<uint32_t>(read) = Low(r);
        *At<uint32_t>(write) = Low(w);
    }
    return ok;
}

// ---- the processors: x86's SYSTEM_LOGICAL_PROCESSOR_INFORMATION is 24 bytes (a 4-byte mask), x64's
// 32, and affinity masks are 4 bytes. Handed the x64 entries, Havok's thread pool counted one core
// and started 1 job thread for the reference's 10, a VS2010 client 2026-10-25 ------------------------
#pragma pack(push, 4)
struct ProcessorInfo32 {
    uint32_t mask;
    uint32_t relationship;
    uint8_t rest[16];       // the union: a flags byte, a node number, a CACHE_DESCRIPTOR (12 bytes)
};
#pragma pack(pop)
static_assert(sizeof(ProcessorInfo32) == 24, "SYSTEM_LOGICAL_PROCESSOR_INFORMATION, x86");
unsigned int gen_imp_GetLogicalProcessorInformation(uint32_t buf, uint32_t plen) {
    uint32_t* len = At<uint32_t>(plen);
    DWORD bytes = 0;
    GetLogicalProcessorInformation(nullptr, &bytes);
    std::vector<SYSTEM_LOGICAL_PROCESSOR_INFORMATION> all(bytes / sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION) + 1);
    bytes = static_cast<DWORD>(all.size() * sizeof all[0]);
    if (!GetLogicalProcessorInformation(all.data(), &bytes)) return 0;
    size_t n = bytes / sizeof all[0];
    uint32_t need = static_cast<uint32_t>(n * sizeof(ProcessorInfo32));
    if (buf == 0 || *len < need) {
        *len = need;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    auto out = At<ProcessorInfo32>(buf);
    for (size_t k = 0; k < n; k++) {
        out[k].mask = static_cast<uint32_t>(all[k].ProcessorMask);
        out[k].relationship = static_cast<uint32_t>(all[k].Relationship);
        static_assert(sizeof(all[k].Cache) == 12, "CACHE_DESCRIPTOR");
        memset(out[k].rest, 0, sizeof out[k].rest);
        memcpy(out[k].rest, &all[k].Cache, sizeof all[k].Cache);
    }
    *len = need;
    return 1;
}
unsigned int gen_imp_GetProcessAffinityMask(uint32_t process, uint32_t pmask, uint32_t psystem) {
    DWORD_PTR mine = 0, all = 0;
    HANDLE h = reinterpret_cast<HANDLE>(static_cast<intptr_t>(static_cast<int32_t>(process)));
    if (!GetProcessAffinityMask(h, &mine, &all)) return 0;
    if (pmask) *At<uint32_t>(pmask) = static_cast<uint32_t>(mine);
    if (psystem) *At<uint32_t>(psystem) = static_cast<uint32_t>(all);
    return 1;
}

// (its LARGE_INTEGER as the two words the reference pushed, ApplyFacts' splitWideImportArgs32)
unsigned int gen_imp_SetFilePointerEx(uint32_t file, uint32_t low, uint32_t high, uint32_t out, uint32_t method) {
    LARGE_INTEGER d;
    d.LowPart = low;
    d.HighPart = static_cast<LONG>(high);
    HANDLE h = reinterpret_cast<HANDLE>(static_cast<intptr_t>(static_cast<int32_t>(file)));
    return SetFilePointerEx(h, d, At<LARGE_INTEGER>(out), method);
}

// ---- COM objects the reference is handed: an x64 object's vtable has 8-byte slots, and the
// reference's code calls a 4-byte slot at 4 * index. An object of the runtime's in their place: a
// 4-byte vtable whose slots are the runtime's methods, each taking the reference's x86 arguments
// (`this` first, as COM's __stdcall has it on the stack). The shell's IMalloc, the first on
// a client's path (FUN_00420900's My Documents lookup, 2026-10-25) ---------------------------------
struct ComObject32 {
    uint32_t vtbl;          // the reference reads its slots through this
};
static unsigned int Malloc32_QueryInterface(uint32_t, uint32_t, uint32_t out) {
    if (out) *At<uint32_t>(out) = 0;
    return static_cast<unsigned int>(E_NOINTERFACE);
}
static unsigned int Malloc32_AddRef(uint32_t) { return 1; }
static unsigned int Malloc32_Release(uint32_t) { return 1; }
static unsigned int Malloc32_Alloc(uint32_t, uint32_t cb) { return Low(CoTaskMemAlloc(cb)); }
static unsigned int Malloc32_Realloc(uint32_t, uint32_t pv, uint32_t cb) { return Low(CoTaskMemRealloc(At<void>(pv), cb)); }
static unsigned int Malloc32_Free(uint32_t, uint32_t pv) {
    CoTaskMemFree(At<void>(pv));
    return 0;
}
static unsigned int Malloc32_GetSize(uint32_t, uint32_t pv) {
    IMalloc* m = nullptr;
    unsigned int n = 0xFFFFFFFF;
    if (SUCCEEDED(CoGetMalloc(1, &m))) {
        n = static_cast<unsigned int>(m->GetSize(At<void>(pv)));
        m->Release();
    }
    return n;
}
static unsigned int Malloc32_DidAlloc(uint32_t, uint32_t pv) {
    IMalloc* m = nullptr;
    unsigned int r = static_cast<unsigned int>(-1);
    if (SUCCEEDED(CoGetMalloc(1, &m))) {
        r = static_cast<unsigned int>(m->DidAlloc(At<void>(pv)));
        m->Release();
    }
    return r;
}
static unsigned int Malloc32_HeapMinimize(uint32_t) { return 0; }

// a vtable of 4-byte slots for the runtime's functions (all below 4 GB: the port is linked at a
// fixed base under 2 GB), in memory of its own
static uint32_t Vtable32(void* const* fns, size_t n) {
    auto v = static_cast<uint32_t*>(HeapAlloc(GetProcessHeap(), 0, n * 4));
    for (size_t k = 0; k < n; k++) v[k] = Low(fns[k]);
    return Low(v);
}
static uint32_t Malloc32() {
    static uint32_t obj = 0;
    if (obj == 0) {
        void* const fns[] = {reinterpret_cast<void*>(Malloc32_QueryInterface), reinterpret_cast<void*>(Malloc32_AddRef),
                             reinterpret_cast<void*>(Malloc32_Release), reinterpret_cast<void*>(Malloc32_Alloc),
                             reinterpret_cast<void*>(Malloc32_Realloc), reinterpret_cast<void*>(Malloc32_Free),
                             reinterpret_cast<void*>(Malloc32_GetSize), reinterpret_cast<void*>(Malloc32_DidAlloc),
                             reinterpret_cast<void*>(Malloc32_HeapMinimize)};
        auto o = static_cast<ComObject32*>(HeapAlloc(GetProcessHeap(), 0, sizeof(ComObject32)));
        o->vtbl = Vtable32(fns, sizeof fns / sizeof fns[0]);
        obj = Low(o);
    }
    return obj;
}
unsigned int gen_imp_SHGetMalloc(uint32_t out) {
    *At<uint32_t>(out) = Malloc32();
    return S_OK;
}
unsigned int gen_imp_CoGetMalloc(uint32_t context, uint32_t out) {
    *At<uint32_t>(out) = Malloc32();
    return context == 1 ? S_OK : static_cast<unsigned int>(E_INVALIDARG);
}
// (an item list's address into the reference's 4-byte slot)
unsigned int gen_imp_SHGetSpecialFolderLocation(uint32_t hwnd, uint32_t folder, uint32_t out) {
    PIDLIST_ABSOLUTE pidl = nullptr;
    HRESULT hr = SHGetSpecialFolderLocation(reinterpret_cast<HWND>(static_cast<uintptr_t>(hwnd)), static_cast<int>(folder), &pidl);
    *At<uint32_t>(out) = Low(pidl);
    return static_cast<unsigned int>(hr);
}

static const wchar_t* RefFullPath(size_t* len) {
    static wchar_t full[MAX_PATH] = {};
    if (full[0] == 0) GetFullPathNameW(RefImagePath(), MAX_PATH, full, nullptr);
    *len = wcslen(full);
    return full;
}
static unsigned int RefNameCopied(size_t len, uint32_t n) {
    if (len >= n) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return n;
    }
    return static_cast<unsigned int>(len);
}
unsigned int gen_imp_GetModuleFileNameW(uint32_t module, uint32_t buf, uint32_t n) {
    if (module != 0 && module != gen_ref_base)
        return GetModuleFileNameW(reinterpret_cast<HMODULE>(static_cast<uintptr_t>(module)), At<wchar_t>(buf), n);
    size_t len;
    const wchar_t* full = RefFullPath(&len);
    if (n == 0) return 0;
    wchar_t* out = At<wchar_t>(buf);
    size_t k = len < n ? len : n - 1;
    memcpy(out, full, k * sizeof(wchar_t));
    out[k] = 0;
    return RefNameCopied(len, n);
}
unsigned int gen_imp_GetModuleFileNameA(uint32_t module, uint32_t buf, uint32_t n) {
    if (module != 0 && module != gen_ref_base)
        return GetModuleFileNameA(reinterpret_cast<HMODULE>(static_cast<uintptr_t>(module)), At<char>(buf), n);
    size_t len;
    const wchar_t* full = RefFullPath(&len);
    if (n == 0) return 0;
    char* out = At<char>(buf);
    size_t k = len < n ? len : n - 1;
    for (size_t i = 0; i < k; i++) out[i] = static_cast<char>(full[i]);   // (an ASCII path, as RefImagePath's)
    out[k] = 0;
    return RefNameCopied(len, n);
}

// An x86 filter, which Windows would call with x64 EXCEPTION_POINTERS: not installed (a crash is
// the runtime's to report)
unsigned int gen_imp_SetUnhandledExceptionFilter(uint32_t) {
    return 0;
}

// ---- the C runtime (ucrt, vcruntime) of a /MD reference: tables of 4-byte pointers -----------
// _initterm / _initterm_e: the reference's initializer tables, [first, last) of function addresses
unsigned int gen_imp__initterm(uint32_t first, uint32_t last) {
    for (uint32_t p = first; p < last; p += 4) {
        if (uint32_t fn = *At<uint32_t>(p)) CallRef(fn);
    }
    return 0;
}
unsigned int gen_imp__initterm_e(uint32_t first, uint32_t last) {
    for (uint32_t p = first; p < last; p += 4) {
        if (uint32_t fn = *At<uint32_t>(p)) {
            if (int r = CallRef(fn)) return static_cast<unsigned int>(r);
        }
    }
    return 0;
}
// a module's own atexit table (a DLL's; an exe's goes to _crt_atexit), kept in its layout
unsigned int gen_imp__initialize_onexit_table(uint32_t table) {
    if (!table) return static_cast<unsigned int>(-1);
    auto t = At<OnexitTable32>(table);
    if (t->first == 0) t->last = t->end = 0;
    return 0;
}
unsigned int gen_imp__register_onexit_function(uint32_t table, uint32_t fn) {
    if (!table) return static_cast<unsigned int>(-1);
    auto t = At<OnexitTable32>(table);
    if (t->last == t->end) {
        uint32_t n = (t->end - t->first) / 4;
        uint32_t grown = n ? n * 2 : 32;
        void* mem = t->first ? HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, At<void>(t->first), grown * 4)
                             : HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, grown * 4);
        if (!mem) return static_cast<unsigned int>(-1);
        t->first = Low(mem);
        t->last = t->first + n * 4;
        t->end = t->first + grown * 4;
    }
    *At<uint32_t>(t->last) = fn;
    t->last += 4;
    return 0;
}
unsigned int gen_imp__execute_onexit_table(uint32_t table) {
    if (!table) return static_cast<unsigned int>(-1);
    auto t = At<OnexitTable32>(table);
    uint32_t first = t->first, last = t->last;
    t->first = t->last = t->end = 0;
    while (last > first) {
        last -= 4;
        if (uint32_t fn = *At<uint32_t>(last)) CallRef(fn);
    }
    if (first) HeapFree(GetProcessHeap(), 0, At<void>(first));
    return 0;
}
// argc, argv and the environment, as the reference's 4-byte vectors
unsigned int gen_imp___p___argc(void) {
    return Low(__p___argc());
}
unsigned int gen_imp___p___argv(void) {
    static uint32_t argv = Vector32(*__p___argv());
    return Low(&argv);
}
unsigned int gen_imp___p__environ(void) {
    static uint32_t env = Vector32(*__p__environ());
    return Low(&env);
}
unsigned int gen_imp__get_initial_narrow_environment(void) {
    static uint32_t env = Vector32(_get_initial_narrow_environment());
    return env;
}
// x87 precision and infinity control have no x64 counterpart (the translation computes in
// doubles): the x86 CRT's _PC_53 at startup, without them, or the call is an invalid parameter
unsigned int gen_imp__controlfp_s(uint32_t current, uint32_t value, uint32_t mask) {
    unsigned int now = 0;
    errno_t r = _controlfp_s(&now, value, mask & ~(_MCW_PC | _MCW_IC));
    if (current) *At<uint32_t>(current) = now;
    return static_cast<unsigned int>(r);
}
// vcruntime's x86 SEH handler: x64 has none, and the reference's exceptions are the runtime's
unsigned int gen_imp__except_handler4_common(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t) {
    return ExceptionContinueSearch;
}
// vcruntime's EH4 __finally runner, called where a __try is left by a jump (`__leave`, a return,
// a goto out of it): the frame's termination handlers down to the try level given (rhtest seh)
unsigned int gen_imp__local_unwind4(uint32_t /*cookie*/, uint32_t node, uint32_t level) {
    if (uint32_t st = eh::ScopeTableOf(node)) eh::LocalUnwind4(node, st, static_cast<int32_t>(level));
    return 0;
}
// an x86 exception filter's EXCEPTION_POINTERS, which x64 ucrt would read as its own
unsigned int gen_imp__seh_filter_exe(uint32_t, uint32_t) {
    return EXCEPTION_CONTINUE_SEARCH;
}

// ---- ucrt's formatted I/O: the options (8 bytes, two of the reference's words), and the
// reference's va_list laid out again for x64 (Args64). printf's family reaches these through the
// headers' inline wrappers, a /MD program's own code
#define RH_OPTS(lo, hi) ((static_cast<uint64_t>(hi) << 32) | (lo))
unsigned int gen_imp___stdio_common_vsprintf(uint32_t lo, uint32_t hi, uint32_t buf, uint32_t count, uint32_t fmt,
                                             uint32_t loc, uint32_t va) {
    Printf<char> p(fmt, va);
    return static_cast<unsigned int>(__stdio_common_vsprintf(RH_OPTS(lo, hi), At<char>(buf), Count32(count), p.Fmt(),
                                                             At<__crt_locale_pointers>(loc), p.List()));
}
unsigned int gen_imp___stdio_common_vsprintf_s(uint32_t lo, uint32_t hi, uint32_t buf, uint32_t count, uint32_t fmt,
                                               uint32_t loc, uint32_t va) {
    Printf<char> p(fmt, va);
    return static_cast<unsigned int>(__stdio_common_vsprintf_s(RH_OPTS(lo, hi), At<char>(buf), Count32(count), p.Fmt(),
                                                               At<__crt_locale_pointers>(loc), p.List()));
}
unsigned int gen_imp___stdio_common_vsnprintf_s(uint32_t lo, uint32_t hi, uint32_t buf, uint32_t count, uint32_t max,
                                                uint32_t fmt, uint32_t loc, uint32_t va) {
    Printf<char> p(fmt, va);
    return static_cast<unsigned int>(__stdio_common_vsnprintf_s(RH_OPTS(lo, hi), At<char>(buf), Count32(count),
                                                                Count32(max), p.Fmt(),
                                                                At<__crt_locale_pointers>(loc), p.List()));
}
unsigned int gen_imp___stdio_common_vswprintf(uint32_t lo, uint32_t hi, uint32_t buf, uint32_t count, uint32_t fmt,
                                              uint32_t loc, uint32_t va) {
    Printf<wchar_t> p(fmt, va);
    return static_cast<unsigned int>(__stdio_common_vswprintf(RH_OPTS(lo, hi), At<wchar_t>(buf), Count32(count),
                                                              p.Fmt(), At<__crt_locale_pointers>(loc), p.List()));
}
unsigned int gen_imp___stdio_common_vfprintf(uint32_t lo, uint32_t hi, uint32_t file, uint32_t fmt, uint32_t loc,
                                             uint32_t va) {
    Printf<char> p(fmt, va);
    return static_cast<unsigned int>(__stdio_common_vfprintf(RH_OPTS(lo, hi), File32(file), p.Fmt(),
                                                             At<__crt_locale_pointers>(loc), p.List()));
}
unsigned int gen_imp___stdio_common_vfprintf_s(uint32_t lo, uint32_t hi, uint32_t file, uint32_t fmt, uint32_t loc,
                                               uint32_t va) {
    Printf<char> p(fmt, va);
    return static_cast<unsigned int>(__stdio_common_vfprintf_s(RH_OPTS(lo, hi), File32(file), p.Fmt(),
                                                               At<__crt_locale_pointers>(loc), p.List()));
}
unsigned int gen_imp___stdio_common_vfwprintf(uint32_t lo, uint32_t hi, uint32_t file, uint32_t fmt, uint32_t loc,
                                              uint32_t va) {
    Printf<wchar_t> p(fmt, va);
    return static_cast<unsigned int>(__stdio_common_vfwprintf(RH_OPTS(lo, hi), File32(file), p.Fmt(),
                                                              At<__crt_locale_pointers>(loc), p.List()));
}
unsigned int gen_imp___stdio_common_vsscanf(uint32_t lo, uint32_t hi, uint32_t buf, uint32_t count, uint32_t fmt,
                                            uint32_t loc, uint32_t va) {
    Args64 a;
    uint64_t opts = RH_OPTS(lo, hi);
    ScanfArgs(At<char>(fmt), va, (opts & _CRT_INTERNAL_SCANF_SECURECRT) != 0, a);
    return static_cast<unsigned int>(__stdio_common_vsscanf(opts, At<char>(buf), Count32(count), At<char>(fmt),
                                                            At<__crt_locale_pointers>(loc), a.List()));
}
unsigned int gen_imp___stdio_common_vswscanf(uint32_t lo, uint32_t hi, uint32_t buf, uint32_t count, uint32_t fmt,
                                             uint32_t loc, uint32_t va) {
    Args64 a;
    uint64_t opts = RH_OPTS(lo, hi);
    ScanfArgs(At<wchar_t>(fmt), va, (opts & _CRT_INTERNAL_SCANF_SECURECRT) != 0, a);
    return static_cast<unsigned int>(__stdio_common_vswscanf(opts, At<wchar_t>(buf), Count32(count), At<wchar_t>(fmt),
                                                             At<__crt_locale_pointers>(loc), a.List()));
}
unsigned int gen_imp___stdio_common_vfscanf(uint32_t lo, uint32_t hi, uint32_t file, uint32_t fmt, uint32_t loc,
                                            uint32_t va) {
    Args64 a;
    uint64_t opts = RH_OPTS(lo, hi);
    ScanfArgs(At<char>(fmt), va, (opts & _CRT_INTERNAL_SCANF_SECURECRT) != 0, a);
    return static_cast<unsigned int>(__stdio_common_vfscanf(opts, File32(file), At<char>(fmt),
                                                            At<__crt_locale_pointers>(loc), a.List()));
}
#undef RH_OPTS

// ---- conversions with an end pointer: the reference's is a 4-byte slot, which the x64 ucrt's
// 8-byte store would run past (convert()'s second strtoul read its own end as garbage). WithEnd32
unsigned int gen_imp_strtol(uint32_t s, uint32_t end, uint32_t base) {
    return static_cast<unsigned int>(WithEnd32<long, char>(s, end, [&](char* p, char** e) { return strtol(p, e, static_cast<int>(base)); }));
}
unsigned int gen_imp_strtoul(uint32_t s, uint32_t end, uint32_t base) {
    return static_cast<unsigned int>(WithEnd32<unsigned long, char>(s, end, [&](char* p, char** e) { return strtoul(p, e, static_cast<int>(base)); }));
}
unsigned long long gen_imp_strtoll(uint32_t s, uint32_t end, uint32_t base) {
    return static_cast<unsigned long long>(WithEnd32<long long, char>(s, end, [&](char* p, char** e) { return strtoll(p, e, static_cast<int>(base)); }));
}
unsigned long long gen_imp_strtoull(uint32_t s, uint32_t end, uint32_t base) {
    return WithEnd32<unsigned long long, char>(s, end, [&](char* p, char** e) { return strtoull(p, e, static_cast<int>(base)); });
}
double gen_imp_strtod(uint32_t s, uint32_t end) {
    return WithEnd32<double, char>(s, end, [](char* p, char** e) { return strtod(p, e); });
}
float gen_imp_strtof(uint32_t s, uint32_t end) {
    return WithEnd32<float, char>(s, end, [](char* p, char** e) { return strtof(p, e); });
}
unsigned int gen_imp_wcstol(uint32_t s, uint32_t end, uint32_t base) {
    return static_cast<unsigned int>(WithEnd32<long, wchar_t>(s, end, [&](wchar_t* p, wchar_t** e) { return wcstol(p, e, static_cast<int>(base)); }));
}
unsigned int gen_imp_wcstoul(uint32_t s, uint32_t end, uint32_t base) {
    return static_cast<unsigned int>(WithEnd32<unsigned long, wchar_t>(s, end, [&](wchar_t* p, wchar_t** e) { return wcstoul(p, e, static_cast<int>(base)); }));
}
double gen_imp_wcstod(uint32_t s, uint32_t end) {
    return WithEnd32<double, wchar_t>(s, end, [](wchar_t* p, wchar_t** e) { return wcstod(p, e); });
}
double gen_imp_atof(uint32_t s) {
    return atof(At<char>(s));
}

// ---- div and ldiv: an 8-byte structure, x86's in edx:eax (quot low, rem high), x64's whole in rax
unsigned long long gen_imp_div(uint32_t n, uint32_t d) {
    div_t q = div(static_cast<int>(n), static_cast<int>(d));
    return (static_cast<unsigned long long>(static_cast<uint32_t>(q.rem)) << 32) | static_cast<uint32_t>(q.quot);
}
unsigned long long gen_imp_ldiv(uint32_t n, uint32_t d) {
    ldiv_t q = ldiv(static_cast<long>(static_cast<int>(n)), static_cast<long>(static_cast<int>(d)));
    return (static_cast<unsigned long long>(static_cast<uint32_t>(q.rem)) << 32) | static_cast<uint32_t>(q.quot);
}

// ---- WSAStartup: x64's WSADATA has the counts and the vendor pointer before the strings, x86's
// after them (400 bytes: the strings at 4 and 261, the counts at 390, the pointer at 396)
#pragma pack(push, 2)
struct WsaData32 {
    uint16_t wVersion, wHighVersion;
    char szDescription[257];
    char szSystemStatus[129];
    uint16_t iMaxSockets, iMaxUdpDg;
    uint16_t pad;
    uint32_t lpVendorInfo;
};
#pragma pack(pop)
static_assert(sizeof(WsaData32) == 400, "x86 WSADATA");
unsigned int gen_imp_WSAStartup(uint32_t version, uint32_t out) {
    // (ws2_32 loaded for it: the runtime links no winsock of its own)
    using Startup = int(WINAPI*)(WORD, void*);
    static Startup startup = reinterpret_cast<Startup>(GetProcAddress(LoadLibraryA("ws2_32.dll"), "WSAStartup"));
    // (x64's own layout, as the SDK has it: version words, the counts, the vendor pointer, the
    // strings)
    struct {
        WORD wVersion, wHighVersion;
        unsigned short iMaxSockets, iMaxUdpDg;
        char* lpVendorInfo;
        char szDescription[257];
        char szSystemStatus[129];
    } d = {};
    int r = startup(static_cast<WORD>(version), &d);
    if (out) {
        auto o = At<WsaData32>(out);
        memset(o, 0, sizeof *o);
        o->wVersion = d.wVersion;
        o->wHighVersion = d.wHighVersion;
        memcpy(o->szDescription, d.szDescription, sizeof o->szDescription);
        memcpy(o->szSystemStatus, d.szSystemStatus, sizeof o->szSystemStatus);
        o->iMaxSockets = d.iMaxSockets;
        o->iMaxUdpDg = d.iMaxUdpDg;
    }
    return static_cast<unsigned int>(r);
}

// ---- the x87 unit's control and status words (Ghidra32.h) ----------------------------------
__declspec(thread) unsigned short gen_x87_cw = 0x27f;

// `fldcw`: the word kept for `fnstcw` to read back, and its rounding control the host's too, the
// SSE unit the port computes in (precision control has no SSE counterpart)
void gen_set_x87_cw(unsigned short cw) {
    gen_x87_cw = cw;
    static const unsigned int rc[4] = {_RC_NEAR, _RC_DOWN, _RC_UP, _RC_CHOP};
    unsigned int old;
    _controlfp_s(&old, rc[(cw >> 10) & 3], _MCW_RC);
}

unsigned short gen_fpusw(int clear) {
    unsigned int s = _statusfp();
    unsigned short w = 0;
    if (s & _SW_INVALID) w |= 0x01;
    if (s & _SW_DENORMAL) w |= 0x02;
    if (s & _SW_ZERODIVIDE) w |= 0x04;
    if (s & _SW_OVERFLOW) w |= 0x08;
    if (s & _SW_UNDERFLOW) w |= 0x10;
    if (s & _SW_INEXACT) w |= 0x20;
    if (clear) _clearfp();
    return w;
}

// ---- DefWindowProc: the x86 structures GenWndProc handed the reference's window procedure
unsigned int gen_imp_DefWindowProcA(uint32_t hwnd, uint32_t msg, uint32_t wp, uint32_t lp) {
    return static_cast<unsigned int>(DefWindowProc32(false, hwnd, msg, wp, lp));
}
unsigned int gen_imp_DefWindowProcW(uint32_t hwnd, uint32_t msg, uint32_t wp, uint32_t lp) {
    return static_cast<unsigned int>(DefWindowProc32(true, hwnd, msg, wp, lp));
}
// (and the other native procedures a window procedure passes its message on to: given the x86
// copy as it is, they read garbage and write past it, ultrareview 2026-10-27)
// (each written out: translate32 finds the adapters by their definitions)
extern "C++" {
template <typename P>
static unsigned int Native4(P proc, uint32_t hwnd, uint32_t msg, uint32_t wp, uint32_t lp) {
    return static_cast<unsigned int>(Native32(hwnd, msg, wp, lp, [&](HWND h, LPARAM l) {
        return proc(h, msg, static_cast<WPARAM>(wp), l); }));
}
}  // extern "C++"
unsigned int gen_imp_DefDlgProcA(uint32_t hwnd, uint32_t msg, uint32_t wp, uint32_t lp) {
    return Native4(DefDlgProcA, hwnd, msg, wp, lp);
}
unsigned int gen_imp_DefDlgProcW(uint32_t hwnd, uint32_t msg, uint32_t wp, uint32_t lp) {
    return Native4(DefDlgProcW, hwnd, msg, wp, lp);
}
unsigned int gen_imp_DefMDIChildProcA(uint32_t hwnd, uint32_t msg, uint32_t wp, uint32_t lp) {
    return Native4(DefMDIChildProcA, hwnd, msg, wp, lp);
}
unsigned int gen_imp_DefMDIChildProcW(uint32_t hwnd, uint32_t msg, uint32_t wp, uint32_t lp) {
    return Native4(DefMDIChildProcW, hwnd, msg, wp, lp);
}
static HWND Hwnd64(uint32_t h) { return reinterpret_cast<HWND>(static_cast<intptr_t>(static_cast<int32_t>(h))); }
unsigned int gen_imp_DefFrameProcA(uint32_t hwnd, uint32_t client, uint32_t msg, uint32_t wp, uint32_t lp) {
    return static_cast<unsigned int>(Native32(hwnd, msg, wp, lp, [&](HWND h, LPARAM l) {
        return DefFrameProcA(h, Hwnd64(client), msg, static_cast<WPARAM>(wp), l); }));
}
unsigned int gen_imp_DefFrameProcW(uint32_t hwnd, uint32_t client, uint32_t msg, uint32_t wp, uint32_t lp) {
    return static_cast<unsigned int>(Native32(hwnd, msg, wp, lp, [&](HWND h, LPARAM l) {
        return DefFrameProcW(h, Hwnd64(client), msg, static_cast<WPARAM>(wp), l); }));
}
// CallWindowProc: a reference procedure (its address in the image, as GetWindowLong handed it)
// called as it is, the x86 copy its own; a native one given a native structure
static unsigned int CallWindowProc32(bool wide, uint32_t proc, uint32_t hwnd, uint32_t msg, uint32_t wp, uint32_t lp) {
    if (eh::InImage(proc)) {
        using Proc = unsigned int (*)(uint32_t, uint32_t, uint32_t, uint32_t);
        return reinterpret_cast<Proc>(static_cast<uintptr_t>(proc))(hwnd, msg, wp, lp);
    }
    auto native = reinterpret_cast<WNDPROC>(static_cast<intptr_t>(static_cast<int32_t>(proc)));
    return static_cast<unsigned int>(Native32(hwnd, msg, wp, lp, [&](HWND h, LPARAM l) {
        return wide ? CallWindowProcW(native, h, msg, static_cast<WPARAM>(wp), l)
                    : CallWindowProcA(native, h, msg, static_cast<WPARAM>(wp), l);
    }));
}
unsigned int gen_imp_CallWindowProcA(uint32_t proc, uint32_t hwnd, uint32_t msg, uint32_t wp, uint32_t lp) {
    return CallWindowProc32(false, proc, hwnd, msg, wp, lp);
}
unsigned int gen_imp_CallWindowProcW(uint32_t proc, uint32_t hwnd, uint32_t msg, uint32_t wp, uint32_t lp) {
    return CallWindowProc32(true, proc, hwnd, msg, wp, lp);
}

}  // extern "C"
