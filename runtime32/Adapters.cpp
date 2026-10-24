// The import adapters the generic one in src/gen/imports.c cannot be: imports whose structures
// are laid out differently on x86 and x64, and kernel32 functions x64 Windows does not export.
// Each is listed in rhipper.json "import_overrides", so translate32.py leaves it to this file.
//
// An adapter takes the reference's 32-bit arguments (an address, below 2 GB, is its own value)
// and returns its 32-bit result.
#include <windows.h>

#include <csetjmp>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>
#include <corecrt_startup.h>
#include <float.h>

extern "C" uint32_t gen_ref_base;   // RefImage.cpp
extern "C" unsigned int gen_teb32(void);
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
    return &l->buf;
}
// a landing's continuation, a function on the frame's ebp: what the frame's function returns
unsigned long long gen_eh_resume(void) {
    return eh::Call1(eh::g_resumeAt, eh::g_resumeEbp);
}
// throw (vcruntime's x86 __stdcall one): an object and its ThrowInfo, or both 0 to rethrow
unsigned int gen_imp__CxxThrowException(uint32_t object, uint32_t info) {
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
    uint32_t args[3] = {0x19930520u, t.object, t.info};
    t.pointers = eh::Pointers(eh::kCxxCode, 1, 3, args);
    eh::Dispatch(t);
    fprintf(stderr, "rhipper: a C++ exception continued\n");
    TerminateProcess(GetCurrentProcess(), 3);
    return 0;
}
// RaiseException: dispatched as the reference's; returns where a filter continues execution
unsigned int gen_imp_RaiseException(uint32_t code, uint32_t flags, uint32_t n, uint32_t args) {
    uint32_t a[15] = {};
    for (uint32_t k = 0; k < n && k < 15; k++) a[k] = *At<uint32_t>(args + 4 * k);
    eh::Thrown t{code, 0, 0, eh::Pointers(code, flags, n, a), false};
    eh::Dispatch(t);
    return 0;
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
unsigned int gen_imp_MessageBoxW(uint32_t hwnd, uint32_t text, uint32_t caption, uint32_t type) {
    // (narrow: stderr's first output was narrow, and a wide write to it then printed nothing)
    fprintf(stderr, "%s: MessageBox [%ls] %ls\n", RHIPPER_NAME, caption ? At<wchar_t>(caption) : L"",
            text ? At<wchar_t>(text) : L"");
    fflush(stderr);
    return MessageBoxW(At<HWND__>(hwnd), At<wchar_t>(text), At<wchar_t>(caption), type);
}
unsigned int gen_imp_MessageBoxA(uint32_t hwnd, uint32_t text, uint32_t caption, uint32_t type) {
    fprintf(stderr, "%s: MessageBox [%s] %s\n", RHIPPER_NAME, caption ? At<char>(caption) : "", text ? At<char>(text) : "");
    fflush(stderr);
    return MessageBoxA(At<HWND__>(hwnd), At<char>(text), At<char>(caption), type);
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
unsigned int gen_imp_GetModuleHandleW(uint32_t name) {
    return name ? Low(GetModuleHandleW(At<wchar_t>(name))) : gen_ref_base;
}
unsigned int gen_imp_GetModuleHandleA(uint32_t name) {
    return name ? Low(GetModuleHandleA(At<char>(name))) : gen_ref_base;
}

// An x86 SLIST_HEADER is 8 bytes; x64's is 16 and 16-aligned (the CRT's type_info list head)
unsigned int gen_imp_InitializeSListHead(uint32_t head) {
    memset(At<void>(head), 0, 8);
    return 0;
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

}  // extern "C"
