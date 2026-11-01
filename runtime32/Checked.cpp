// The checked build (CMake GEN_CHECKED, <name>_checked.exe): every load and store of the translated
// code checked, so a run names the first bad access, its function and stack, where the normal build
// crashes later somewhere else (a heap's fail-fast at a free, an AV in a function the damage reached).
//
// The translation is built by clang-cl with its AddressSanitizer instrumentation and none of ASan's
// own runtime, which reserves terabytes the memory model (/LARGEADDRESSAWARE:NO, everything below
// 2 GB) does not have. This file is that runtime, for the low 2 GB alone:
//   - the shadow: a byte per 8 bytes of [0, 2 GB), 256 MB committed at start (its pages taken only
//     as they are touched), its address in __asan_shadow_memory_dynamic_address, which each
//     instrumented function reads. 0 is accessible, 1..7 the first k bytes of the 8, >= 0x80 not;
//   - the reports, __asan_report_*_noabort: the access, what the shadow says the address is (a heap
//     block's redzone, a freed block, a frame's redzone), the block with its allocation and free
//     stacks, the function (F_<address>) and the stack; then on, or stopped, <ENV>_CHECKED_ON;
//   - the reference's heap (its HeapAlloc, HeapFree, HeapSize, HeapReAlloc, HeapDestroy imports):
//     each block between redzones, its header in the left one, and a freed block held back poisoned
//     (the last <ENV>_CHECKED_QUARANTINE_MB, 64), so an overrun into a neighbour's header or a write
//     after a free stops at the instruction that does it;
//   - the stack: clang lays redzones around each frame (Ghidra32.h's gen_frame) and clears them
//     at the return; a longjmp past frames (__asan_handle_no_return, Adapters.cpp's landings) and
//     a thread's start and end clear the stack's shadow;
//   - the reference's read-only sections write-protected (CheckedProtect), a write reported, the
//     page made writable and the write let through; an access fault at an address no 32-bit
//     program has, 2 GB and up, named so;
//   - Ghidra32.h's GEN_TOP of a value wider than 32 bits, said once per site (<ENV>_CHECKED_WRAP=1).
// Its settings, <ENV>_CHECKED_*: ON=continue|stop|break (continue: each site reported once, at
// most MAX=40), HEAP=0 (no redzones), QUARANTINE_MB, DEPTH (stack frames kept per block, 8), EXACT=1
// (a block's bytes to its size, not its 16-byte heap granule), FRAMES=1, WRAP=1, RDATA=0.
#include "RefImage.hpp"

#include <windows.h>
#include <intrin.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// (this file's statics made before the rest of the program's: the shadow first of all)
#pragma warning(disable : 4073)
#pragma init_seg(lib)

extern "C" {
typedef intptr_t (*gen_real_fn)(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t,
                                intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t);
struct GEN_IMPORT {
    unsigned int slot;
    const char* dll;
    const char* name;
    void* adapter;
    gen_real_fn* real;
};
extern const GEN_IMPORT g_genImports[];
extern const unsigned int g_genImportCount;

// what the instrumentation reads: the shadow's base, (address >> 3) + base its byte
uintptr_t __asan_shadow_memory_dynamic_address = 0;
// Ghidra32.h's switches
int gen_checked_frames = 0;
int gen_checked_wrap_on = 0;
}
void RefPrintStack(HANDLE thread, CONTEXT c);                   // RefImage.cpp
void RefPrintFrames(void* const* frames, unsigned short n);     // RefImage.cpp

namespace {

constexpr uintptr_t kCover = 0x80000000u;               // the low 2 GB, all a 32-bit program has
constexpr size_t kShadowSize = kCover >> 3;
// the shadow's values (ASan's where it has one)
constexpr uint8_t kHeapLeft = 0xfa, kHeapRight = 0xfb, kHeapFreed = 0xfd;
constexpr uint8_t kStackLeft = 0xf1, kStackMid = 0xf2, kStackRight = 0xf3, kFrameEdge = 0xf4;
constexpr uint8_t kStackAfterReturn = 0xf5, kStackAfterScope = 0xf8;

uint8_t* g_shadow = nullptr;

inline uint8_t* Sh(uintptr_t a) { return g_shadow + (a >> 3); }
// [a, a + n) poisoned with v, a and n in whole granules
void Poison(uintptr_t a, size_t n, uint8_t v) {
    if (!g_shadow || a >= kCover || n == 0) return;
    if (n > kCover - a) n = kCover - a;
    memset(Sh(a), v, (n + 7) >> 3);
}
// [a, a + n) accessible, a granule-aligned: its last granule's first n & 7 bytes when n is not whole
void Unpoison(uintptr_t a, size_t n) {
    if (!g_shadow || a >= kCover || n == 0) return;
    if (n > kCover - a) n = kCover - a;
    memset(Sh(a), 0, n >> 3);
    if (n & 7) *Sh(a + (n & ~size_t(7))) = static_cast<uint8_t>(n & 7);
}

// The shadow, made before main in the program's process (the launcher, which runs no translated
// code, has none): bottom-up, clear of LowStub's 0x70000000 range and of the reference's, which
// the launcher reserved before this process ran
struct ShadowInit {
    ShadowInit() {
        wchar_t child[4] = {};
        if (RefEnv("CHILD", child, 4) == 0) return;
        void* s = VirtualAlloc(nullptr, kShadowSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!s) {
            fprintf(stderr, "%s: CHECKED: no room for the shadow (%zu MB, error %lu)\n", RHIPPER_NAME,
                    kShadowSize >> 20, GetLastError());
            fflush(stderr);
            TerminateProcess(GetCurrentProcess(), 1);
        }
        g_shadow = static_cast<uint8_t*>(s);
        __asan_shadow_memory_dynamic_address = reinterpret_cast<uintptr_t>(s);
    }
};
ShadowInit g_shadowInit;

// ---- settings -----------------------------------------------------------------------------------
enum class OnError { Continue, Stop, Break };
struct Settings {
    OnError on = OnError::Continue;
    long max = 40;
    bool heap = true, exact = false, rdata = true;
    size_t quarantine = 64u << 20;
    USHORT depth = 8;
} g_set;

unsigned EnvNum(const char* name, unsigned dflt) {
    wchar_t v[24] = {};
    return RefEnv(name, v, 24) ? static_cast<unsigned>(wcstoul(v, nullptr, 0)) : dflt;
}

// ---- the stacks blocks keep: each distinct one stored once, by an id ---------------------------
struct Depot {
    SRWLOCK lock = SRWLOCK_INIT;
    struct Entry {
        void* frames[16];
        USHORT n;
    };
    std::vector<Entry> all;
    std::unordered_multimap<ULONG, uint32_t> byHash;
    uint32_t Put(USHORT skip) {
        Entry e = {};
        ULONG hash = 0;
        e.n = RtlCaptureStackBackTrace(skip + 1, g_set.depth, e.frames, &hash);
        AcquireSRWLockExclusive(&lock);
        auto r = byHash.equal_range(hash);
        for (auto it = r.first; it != r.second; ++it) {
            const Entry& o = all[it->second];
            if (o.n == e.n && memcmp(o.frames, e.frames, e.n * sizeof(void*)) == 0) {
                ReleaseSRWLockExclusive(&lock);
                return it->second + 1;
            }
        }
        all.push_back(e);
        uint32_t id = static_cast<uint32_t>(all.size());
        byHash.emplace(hash, id - 1);
        ReleaseSRWLockExclusive(&lock);
        return id;
    }
    void Print(uint32_t id) {
        if (id == 0) {
            fprintf(stderr, "    (none kept)\n");
            return;
        }
        AcquireSRWLockShared(&lock);
        Entry e = all[id - 1];
        ReleaseSRWLockShared(&lock);
        RefPrintFrames(e.frames, e.n);
    }
} g_depot;

// ---- the reference's heap blocks ------------------------------------------------------------------
// raw: [header 32][the block, its bytes rounded to 16][right redzone 16]; the left redzone is the header
constexpr size_t kLeft = 32, kRight = 16;
constexpr uint32_t kMagic = 0xC4EC4ED0u;
constexpr uint8_t kRedFill = 0xab, kFreedFill = 0xdd;
enum : uint32_t { kLive = 1, kFreed = 2 };
struct Header {
    uint32_t magic;      // kMagic ^ the block's address
    uint32_t size;       // as asked
    uint32_t allocStack, freeStack;
    uint32_t allocTid, freeTid;
    uint32_t state;
    uint32_t serial;
};
static_assert(sizeof(Header) == kLeft, "the header is the left redzone");

inline size_t Granule16(size_t n) { return (std::max<size_t>(n, 1) + 15) & ~size_t(15); }
inline size_t RawSize(size_t n) { return kLeft + Granule16(n) + kRight; }
inline Header* HeaderOf(uintptr_t user) { return reinterpret_cast<Header*>(user - kLeft); }

// (whether p is a block of these hooks': its header's magic, read where any address may be passed)
bool Tracked(uintptr_t p) {
    if (p < kLeft || p >= kCover || (p & 15)) return false;
    __try {
        return HeaderOf(p)->magic == (kMagic ^ static_cast<uint32_t>(p));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

struct Held {
    intptr_t heap, flags;
    uintptr_t user;
};
struct Heap {
    gen_real_fn alloc = nullptr, free = nullptr, size = nullptr, realloc = nullptr, destroy = nullptr;
    SRWLOCK lock = SRWLOCK_INIT;
    std::deque<Held> held;
    size_t heldBytes = 0;
    volatile long serial = 0;
} g_heap;

void Report(uintptr_t a, size_t size, int write, void* pc, const char* what, const CONTEXT* at);

intptr_t Real(gen_real_fn f, intptr_t a0, intptr_t a1, intptr_t a2, intptr_t a3 = 0) {
    return f(a0, a1, a2, a3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
}

uintptr_t NewBlock(intptr_t heap, intptr_t flags, size_t n) {
    if (n >= 0x7fff0000u) return 0;
    intptr_t raw = Real(g_heap.alloc, heap, flags, static_cast<intptr_t>(RawSize(n)));
    if (!raw) return 0;
    uintptr_t user = static_cast<uintptr_t>(raw) + kLeft;
    if ((user & 15) || user + Granule16(n) + kRight > kCover) {
        // (not a 16-aligned block below 2 GB: never so from Windows' heap; handed out unchecked)
        return static_cast<uintptr_t>(raw);
    }
    Header* h = HeaderOf(user);
    h->magic = kMagic ^ static_cast<uint32_t>(user);
    h->size = static_cast<uint32_t>(n);
    h->allocStack = g_depot.Put(2);
    h->freeStack = 0;
    h->allocTid = GetCurrentThreadId();
    h->freeTid = 0;
    h->state = kLive;
    h->serial = static_cast<uint32_t>(InterlockedIncrement(&g_heap.serial));
    const size_t g = Granule16(n), open = g_set.exact ? n : g;
    memset(reinterpret_cast<void*>(user + g), kRedFill, kRight);
    if (g_set.exact && g > n) memset(reinterpret_cast<void*>(user + n), kRedFill, g - n);
    Poison(user - kLeft, kLeft, kHeapLeft);
    Poison(user, g + kRight, kHeapRight);
    Unpoison(user, open);
    return user;
}

// (a block's redzones as they were filled: what code the instrumentation does not see wrote there,
// an adapter's or a system DLL's; the first damaged byte's offset from the block, or 0)
long long RedzoneDamage(uintptr_t user, const Header* h) {
    const size_t g = Granule16(h->size);
    const size_t from = g_set.exact ? h->size : g;
    const uint8_t* b = reinterpret_cast<const uint8_t*>(user);
    for (size_t k = from; k < g + kRight; k++)
        if (b[k] != kRedFill) return static_cast<long long>(k) + 1;
    return 0;
}

bool CountReport();
void Act();
void ReportBlock(const char* what, uintptr_t user, const Header* h, bool freed) {
    if (!CountReport()) return;
    fprintf(stderr, "%s: CHECKED: %s: block %llx (size 0x%x, #%u)\n", RHIPPER_NAME, what,
            static_cast<unsigned long long>(user), h->size, h->serial);
    fprintf(stderr, "  allocated on thread %u at:\n", h->allocTid);
    g_depot.Print(h->allocStack);
    if (freed) {
        fprintf(stderr, "  freed on thread %u at:\n", h->freeTid);
        g_depot.Print(h->freeStack);
    }
    fprintf(stderr, "  now:\n");
    CONTEXT c = {};
    RtlCaptureContext(&c);
    RefPrintStack(GetCurrentThread(), c);
    fflush(stderr);
    Act();
}

void ReleaseHeld(const Held& x) {
    Header* h = HeaderOf(x.user);
    const uint8_t* b = reinterpret_cast<const uint8_t*>(x.user);
    for (size_t k = 0; k < h->size; k++)
        if (b[k] != kFreedFill) {
            char what[192];
            sprintf_s(what, "written after its free at +0x%zx (a store reported above, or code the checks do not see)", k);
            ReportBlock(what, x.user, h, true);
            break;
        }
    if (long long k = RedzoneDamage(x.user, h)) {
        char what[192];
        sprintf_s(what, "redzone written at +0x%llx (a store reported above, or code the checks do not see)", k - 1);
        ReportBlock(what, x.user, h, true);
    }
    const size_t raw = RawSize(h->size);
    h->magic = 0;
    Unpoison(x.user - kLeft, raw);
    Real(g_heap.free, x.heap, x.flags, static_cast<intptr_t>(x.user - kLeft));
}

intptr_t CheckedHeapAlloc(intptr_t heap, intptr_t flags, intptr_t n, intptr_t, intptr_t, intptr_t, intptr_t,
                          intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t) {
    return static_cast<intptr_t>(NewBlock(heap, flags, static_cast<uint32_t>(n)));
}

intptr_t CheckedHeapFree(intptr_t heap, intptr_t flags, intptr_t p, intptr_t a3, intptr_t a4, intptr_t a5,
                         intptr_t a6, intptr_t a7, intptr_t a8, intptr_t a9, intptr_t a10, intptr_t a11,
                         intptr_t a12, intptr_t a13) {
    const uintptr_t user = static_cast<uintptr_t>(static_cast<uint32_t>(p));
    if (!p || !Tracked(user)) return g_heap.free(heap, flags, p, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13);
    Header* h = HeaderOf(user);
    if (h->state != kLive) {
        ReportBlock("freed again", user, h, true);
        return 1;   // (the second free left out)
    }
    if (long long k = RedzoneDamage(user, h)) {
        char what[192];
        sprintf_s(what, "redzone written before its free at +0x%llx (a store reported above, or code the checks do not see)", k - 1);
        ReportBlock(what, user, h, false);
    }
    h->state = kFreed;
    h->freeStack = g_depot.Put(1);
    h->freeTid = GetCurrentThreadId();
    memset(reinterpret_cast<void*>(user), kFreedFill, h->size);
    Poison(user, Granule16(h->size), kHeapFreed);
    std::vector<Held> out;
    AcquireSRWLockExclusive(&g_heap.lock);
    g_heap.held.push_back({heap, flags, user});
    g_heap.heldBytes += RawSize(h->size);
    while (g_heap.heldBytes > g_set.quarantine && !g_heap.held.empty()) {
        Held x = g_heap.held.front();
        g_heap.held.pop_front();
        g_heap.heldBytes -= RawSize(HeaderOf(x.user)->size);
        out.push_back(x);
    }
    ReleaseSRWLockExclusive(&g_heap.lock);
    for (const Held& x : out) ReleaseHeld(x);
    return 1;
}

intptr_t CheckedHeapSize(intptr_t heap, intptr_t flags, intptr_t p, intptr_t a3, intptr_t a4, intptr_t a5,
                         intptr_t a6, intptr_t a7, intptr_t a8, intptr_t a9, intptr_t a10, intptr_t a11,
                         intptr_t a12, intptr_t a13) {
    const uintptr_t user = static_cast<uintptr_t>(static_cast<uint32_t>(p));
    if (p && Tracked(user)) {
        Header* h = HeaderOf(user);
        if (h->state != kLive) ReportBlock("HeapSize of a freed block", user, h, true);
        return h->size;
    }
    return g_heap.size(heap, flags, p, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13);
}

intptr_t CheckedHeapReAlloc(intptr_t heap, intptr_t flags, intptr_t p, intptr_t n, intptr_t a4, intptr_t a5,
                            intptr_t a6, intptr_t a7, intptr_t a8, intptr_t a9, intptr_t a10, intptr_t a11,
                            intptr_t a12, intptr_t a13) {
    const uintptr_t user = static_cast<uintptr_t>(static_cast<uint32_t>(p));
    const size_t want = static_cast<uint32_t>(n);
    size_t old;
    bool mine = p && Tracked(user);
    if (mine) {
        Header* h = HeaderOf(user);
        if (h->state != kLive) {
            ReportBlock("reallocated after its free", user, h, true);
            return 0;
        }
        old = h->size;
    } else {
        // (a block from before the hooks or from no allocation of theirs: its size from the heap)
        if (!p || (flags & HEAP_REALLOC_IN_PLACE_ONLY))
            return g_heap.realloc(heap, flags, p, n, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13);
        old = static_cast<size_t>(Real(g_heap.size, heap, 0, p));
        if (old == static_cast<size_t>(-1))
            return g_heap.realloc(heap, flags, p, n, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13);
    }
    if (flags & HEAP_REALLOC_IN_PLACE_ONLY) return 0;   // (a move every time; in place, refused)
    uintptr_t q = NewBlock(heap, flags & ~static_cast<intptr_t>(HEAP_ZERO_MEMORY), want);
    if (!q) return 0;
    memcpy(reinterpret_cast<void*>(q), reinterpret_cast<void*>(user), std::min(old, want));
    if ((flags & HEAP_ZERO_MEMORY) && want > old) memset(reinterpret_cast<char*>(q) + old, 0, want - old);
    if (mine)
        CheckedHeapFree(heap, flags & ~static_cast<intptr_t>(HEAP_ZERO_MEMORY), p, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    else
        Real(g_heap.free, heap, 0, p);
    return static_cast<intptr_t>(q);
}

// (a heap destroyed: its held blocks dropped, and every block's shadow cleared, the memory going
// back to Windows for anything)
intptr_t CheckedHeapDestroy(intptr_t heap, intptr_t a1, intptr_t a2, intptr_t a3, intptr_t a4, intptr_t a5,
                            intptr_t a6, intptr_t a7, intptr_t a8, intptr_t a9, intptr_t a10, intptr_t a11,
                            intptr_t a12, intptr_t a13) {
    AcquireSRWLockExclusive(&g_heap.lock);
    for (auto it = g_heap.held.begin(); it != g_heap.held.end();) {
        if (it->heap == heap) {
            g_heap.heldBytes -= RawSize(HeaderOf(it->user)->size);
            it = g_heap.held.erase(it);
        } else {
            ++it;
        }
    }
    ReleaseSRWLockExclusive(&g_heap.lock);
    HANDLE hh = reinterpret_cast<HANDLE>(heap);
    const BOOL locked = HeapLock(hh);   // (fails for a HEAP_NO_SERIALIZE heap: walked as it is)
    PROCESS_HEAP_ENTRY e = {};
    while (HeapWalk(hh, &e))
        if (e.wFlags & PROCESS_HEAP_ENTRY_BUSY)
            Unpoison(reinterpret_cast<uintptr_t>(e.lpData) & ~uintptr_t(7), e.cbData + 8);
    if (locked) HeapUnlock(hh);
    return g_heap.destroy(heap, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13);
}

// ---- the stack -----------------------------------------------------------------------------------
void UnpoisonThisStack(uintptr_t from) {
    auto tib = reinterpret_cast<NT_TIB*>(NtCurrentTeb());
    uintptr_t lo = reinterpret_cast<uintptr_t>(tib->StackLimit), hi = reinterpret_cast<uintptr_t>(tib->StackBase);
    if (from > lo) lo = from;
    lo &= ~uintptr_t(7);
    if (hi > lo) Unpoison(lo, hi - lo);
}

// (each thread's stack clear at its start and its end: a dead thread's frames left poisoned where
// another's stack comes to lie, an ExitThread from deep in the translation)
void NTAPI CheckedTls(PVOID, DWORD reason, PVOID) {
    if (g_shadow && (reason == DLL_THREAD_ATTACH || reason == DLL_THREAD_DETACH)) UnpoisonThisStack(0);
}

// ---- the reference's read-only sections ----------------------------------------------------------
struct Range {
    uint32_t lo, hi;
};
std::vector<Range> g_readonly;

// ---- reports -------------------------------------------------------------------------------------
SRWLOCK g_reportLock = SRWLOCK_INIT;
std::unordered_set<void*> g_sites;
long g_reports = 0, g_suppressed = 0;
thread_local bool t_reporting = false;

const char* Describe(uint8_t s) {
    switch (s) {
    case kHeapLeft: return "a heap block's left redzone (its header: an underrun, or an overrun of the block below)";
    case kHeapRight: return "a heap block's right redzone (an overrun)";
    case kHeapFreed: return "a freed heap block (a use after free)";
    case kStackLeft: return "a frame's left redzone (below gen_frame: an underrun)";
    case kStackMid: return "between two of a frame's locals (an overrun)";
    case kStackRight: return "a frame's right redzone (past gen_frame: an overrun)";
    case kFrameEdge: return "the frame's pad or saved-ebp bytes (CHECKED_FRAMES)";
    case kStackAfterReturn: return "a frame that returned";
    case kStackAfterScope: return "a local out of its scope";
    default: return s < 8 ? "past the end of a partly accessible granule (an overrun by a few bytes)" : "poisoned memory";
    }
}

// the heap block an address in a redzone or a freed block belongs to: the shadow walked to the block's
// first granule, its header checked
bool FindBlock(uintptr_t a, uintptr_t* user, Header** h) {
    if (!g_shadow || a >= kCover) return false;
    uintptr_t g = a & ~uintptr_t(7);
    const uint8_t s = *Sh(g);
    const uintptr_t limit = 64u << 20;
    if (s == kHeapLeft) {
        // (forward to the first granule past the header)
        uintptr_t x = g;
        while (x < kCover && *Sh(x) == kHeapLeft && x - g < kLeft) x += 8;
        if (Tracked(x)) { *user = x; *h = HeaderOf(x); return true; }
        return false;
    }
    // (back over the block's own granules to its header)
    uintptr_t x = g;
    while (x >= 8 && g - x < limit && *Sh(x - 8) != kHeapLeft) x -= 8;
    if (x >= 8 && Tracked(x)) { *user = x; *h = HeaderOf(x); return true; }
    return false;
}

void PrintAround(uintptr_t a) {
    uintptr_t user;
    Header* h;
    const uint8_t s = g_shadow && a < kCover ? *Sh(a) : 0;
    if ((s == kHeapLeft || s == kHeapRight || s == kHeapFreed || (s > 0 && s < 8)) && FindBlock(a, &user, &h)) {
        long long off = static_cast<long long>(a) - static_cast<long long>(user);
        if (s == kHeapLeft) {
            fprintf(stderr, "  %lld bytes before block %llx (size 0x%x, #%u, %s)\n", -off,
                    static_cast<unsigned long long>(user), h->size, h->serial, h->state == kLive ? "live" : "freed");
            // (and the block below, whose overrun this likely is)
            uintptr_t below;
            Header* hb;
            if (user >= kLeft + 8 && FindBlock(user - kLeft - 8, &below, &hb)) {
                fprintf(stderr, "  block below: %llx (size 0x%x, #%u), its end %lld bytes before the access; allocated at:\n",
                        static_cast<unsigned long long>(below), hb->size, hb->serial,
                        static_cast<long long>(a) - static_cast<long long>(below + hb->size));
                g_depot.Print(hb->allocStack);
            }
        } else if (off >= static_cast<long long>(h->size)) {
            fprintf(stderr, "  at +0x%llx of block %llx (size 0x%x, #%u, %s): %lld bytes past its end\n", off,
                    static_cast<unsigned long long>(user), h->size, h->serial, h->state == kLive ? "live" : "freed",
                    off - static_cast<long long>(h->size));
        } else {
            fprintf(stderr, "  at +0x%llx of block %llx (size 0x%x, #%u, %s)\n", off,
                    static_cast<unsigned long long>(user), h->size, h->serial, h->state == kLive ? "live" : "freed");
        }
        fprintf(stderr, "  allocated on thread %u at:\n", h->allocTid);
        g_depot.Print(h->allocStack);
        if (h->state != kLive) {
            fprintf(stderr, "  freed on thread %u at:\n", h->freeTid);
            g_depot.Print(h->freeStack);
        }
        return;
    }
    // (a stack address: where in this thread's stack)
    auto tib = reinterpret_cast<NT_TIB*>(NtCurrentTeb());
    if (a >= reinterpret_cast<uintptr_t>(tib->StackLimit) && a < reinterpret_cast<uintptr_t>(tib->StackBase))
        fprintf(stderr, "  this thread's stack, rsp+0x%llx\n",
                static_cast<unsigned long long>(a - reinterpret_cast<uintptr_t>(_AddressOfReturnAddress())));
}

// (a report of the heap's own, ReportBlock: counted with the others, under the same limit)
bool CountReport() {
    AcquireSRWLockExclusive(&g_reportLock);
    bool shown = g_reports < g_set.max;
    if (shown) g_reports++;
    else g_suppressed++;
    ReleaseSRWLockExclusive(&g_reportLock);
    return shown;
}

void Act() {
    if (g_set.on == OnError::Break && IsDebuggerPresent()) {
        __debugbreak();
    } else if (g_set.on != OnError::Continue) {
        fprintf(stderr, "%s: CHECKED: stopped (CHECKED_ON)\n", RHIPPER_NAME);
        fflush(stderr);
        TerminateProcess(GetCurrentProcess(), 0xC4EC0001u);
    }
}

// (the access a report call stands for: the instrumentation's cold block calls the report, then
// jumps back to the load or store, `call __asan_report_store4_noabort; jmp <access>`)
bool InPort(uintptr_t pc);
void* AccessPc(void* pc) {
    if (!InPort(reinterpret_cast<uintptr_t>(pc))) return pc;
    const uint8_t* b = static_cast<const uint8_t*>(pc);
    if (b[0] == 0xe9) return const_cast<uint8_t*>(b + 5 + *reinterpret_cast<const int32_t*>(b + 1));
    if (b[0] == 0xeb) return const_cast<uint8_t*>(b + 2 + static_cast<int8_t>(b[1]));
    return pc;
}

// one access reported: once per site, at most g_set.max
void Report(uintptr_t a, size_t size, int write, void* pc, const char* what, const CONTEXT* at) {
    if (t_reporting) return;
    t_reporting = true;
    AcquireSRWLockExclusive(&g_reportLock);
    bool first = g_sites.insert(pc).second;
    bool shown = first && g_reports < g_set.max;
    if (shown) g_reports++;
    else g_suppressed++;
    if (shown) {
        const uint8_t s = g_shadow && a < kCover ? *Sh(a) : 0;
        char kind[160];
        if (what) sprintf_s(kind, "%s", what);
        else if (a >= 0x100000000ull) sprintf_s(kind, "a 64-bit address, none of the reference's (an address computed 64 bits wide)");
        else if (a >= kCover) sprintf_s(kind, "an address above 2 GB, nothing of the port's");
        else sprintf_s(kind, "%s [shadow %02x]", Describe(s), s);
        char width[32] = "";
        if (size) sprintf_s(width, " of %zu bytes", size);
        fprintf(stderr, "%s: CHECKED #%ld: %s%s at %llx: %s\n", RHIPPER_NAME, g_reports,
                write == 1 ? "store" : write == 0 ? "load" : "access", width, static_cast<unsigned long long>(a), kind);
        fprintf(stderr, "  in:\n");
        void* f[1] = {pc};
        RefPrintFrames(f, 1);
        PrintAround(a);
        fprintf(stderr, "  stack:\n");
        if (at) {
            RefPrintStack(GetCurrentThread(), *at);
        } else {
            CONTEXT c = {};
            RtlCaptureContext(&c);
            RefPrintStack(GetCurrentThread(), c);
        }
        fflush(stderr);
    }
    ReleaseSRWLockExclusive(&g_reportLock);
    t_reporting = false;
    if (shown) Act();
}

// a range [p, p + n) of a memcpy or memset: its first poisoned byte reported
void CheckRange(uintptr_t p, size_t n, int write, void* pc) {
    if (n == 0) return;
    if (p >= kCover || n > kCover - p) {
        Report(p >= kCover ? p : kCover, n, write, pc, nullptr, nullptr);
        return;
    }
    for (uintptr_t g = p & ~uintptr_t(7); g < p + n; g += 8) {
        const uint8_t s = *Sh(g);
        if (s == 0) continue;
        const uintptr_t lo = std::max(p, g);
        if (s < 8 && lo < g + s && p + n <= g + s) continue;
        Report(s < 8 ? std::max(lo, g + s) : lo, n, write, pc, nullptr, nullptr);
        return;
    }
}

// ---- faults --------------------------------------------------------------------------------------
bool InPort(uintptr_t pc) {
    static uintptr_t lo = 0, hi = 0;
    if (!lo) {
        auto base = reinterpret_cast<const uint8_t*>(GetModuleHandleW(nullptr));
        auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + reinterpret_cast<const IMAGE_DOS_HEADER*>(base)->e_lfanew);
        lo = reinterpret_cast<uintptr_t>(base);
        hi = lo + nt->OptionalHeader.SizeOfImage;
    }
    return pc >= lo && pc < hi;
}

LONG CALLBACK CheckedFault(EXCEPTION_POINTERS* ep) {
    const EXCEPTION_RECORD* r = ep->ExceptionRecord;
    if (r->ExceptionCode != EXCEPTION_ACCESS_VIOLATION || r->NumberParameters < 2) return EXCEPTION_CONTINUE_SEARCH;
    const int kind = static_cast<int>(r->ExceptionInformation[0]);   // 0 read, 1 write, 8 execute
    const uintptr_t a = r->ExceptionInformation[1];
    void* pc = r->ExceptionAddress;
    // a write into a read-only section of the reference's: reported, then let through
    if (kind == 1 && a < kCover) {
        for (const Range& x : g_readonly)
            if (a >= x.lo && a < x.hi) {
                Report(a, 0, 1, pc, "a store into the reference's read-only data (.rdata or headers)", ep->ContextRecord);
                DWORD old;
                VirtualProtect(reinterpret_cast<void*>(a & ~uintptr_t(0xfff)), 0x1000, PAGE_READWRITE, &old);
                return EXCEPTION_CONTINUE_EXECUTION;
            }
    }
    if (!InPort(reinterpret_cast<uintptr_t>(pc))) return EXCEPTION_CONTINUE_SEARCH;
    // the instrumentation's shadow read of an address past 2 GB (its shadow past the shadow's end)
    const uintptr_t sh = reinterpret_cast<uintptr_t>(g_shadow);
    if (g_shadow && a >= sh + kShadowSize && a < sh + (uintptr_t(1) << 45))
        Report((a - sh) << 3, 0, kind == 1, pc, nullptr, ep->ContextRecord);
    else if (a >= kCover && kind != 8)
        Report(a, 0, kind == 1, pc, nullptr, ep->ContextRecord);
    return EXCEPTION_CONTINUE_SEARCH;   // (the fault is the run's as before)
}

void Hook(const char* name, gen_real_fn* keep, gen_real_fn mine) {
    for (unsigned k = 0; k < g_genImportCount; k++) {
        const GEN_IMPORT& im = g_genImports[k];
        if (im.real && *im.real && strcmp(im.name, name) == 0) {
            *keep = *im.real;
            *im.real = mine;
        }
    }
}

}  // namespace

// ---- the instrumentation's calls -------------------------------------------------------------------
extern "C" {
void __asan_init(void) {}
void __asan_version_mismatch_check_v8(void) {}

#define GEN_ASAN_REPORT(kind, n, w)                                                                  \
    __declspec(noinline) void __asan_report_##kind##n##_noabort(uintptr_t a) {                        \
        Report(a, n, w, AccessPc(_ReturnAddress()), nullptr, nullptr);                                          \
    }                                                                                                 \
    __declspec(noinline) void __asan_report_##kind##n(uintptr_t a) { Report(a, n, w, AccessPc(_ReturnAddress()), nullptr, nullptr); }
GEN_ASAN_REPORT(load, 1, 0)
GEN_ASAN_REPORT(load, 2, 0)
GEN_ASAN_REPORT(load, 4, 0)
GEN_ASAN_REPORT(load, 8, 0)
GEN_ASAN_REPORT(load, 16, 0)
GEN_ASAN_REPORT(store, 1, 1)
GEN_ASAN_REPORT(store, 2, 1)
GEN_ASAN_REPORT(store, 4, 1)
GEN_ASAN_REPORT(store, 8, 1)
GEN_ASAN_REPORT(store, 16, 1)
#undef GEN_ASAN_REPORT
// (an access of another width, or one the instrumentation checks by its first and last byte)
__declspec(noinline) void __asan_report_load_n_noabort(uintptr_t a, size_t n) {
    Report(a, n, 0, AccessPc(_ReturnAddress()), nullptr, nullptr);
}
__declspec(noinline) void __asan_report_store_n_noabort(uintptr_t a, size_t n) {
    Report(a, n, 1, AccessPc(_ReturnAddress()), nullptr, nullptr);
}
__declspec(noinline) void __asan_report_load_n(uintptr_t a, size_t n) { Report(a, n, 0, AccessPc(_ReturnAddress()), nullptr, nullptr); }
__declspec(noinline) void __asan_report_store_n(uintptr_t a, size_t n) { Report(a, n, 1, AccessPc(_ReturnAddress()), nullptr, nullptr); }

// (the translation's memcpy, memmove and memset, which the instrumentation hands here: both ranges
// checked whole)
__declspec(noinline) void* __asan_memcpy(void* d, const void* s, size_t n) {
    CheckRange(reinterpret_cast<uintptr_t>(s), n, 0, _ReturnAddress());
    CheckRange(reinterpret_cast<uintptr_t>(d), n, 1, _ReturnAddress());
    return memcpy(d, s, n);
}
__declspec(noinline) void* __asan_memmove(void* d, const void* s, size_t n) {
    CheckRange(reinterpret_cast<uintptr_t>(s), n, 0, _ReturnAddress());
    CheckRange(reinterpret_cast<uintptr_t>(d), n, 1, _ReturnAddress());
    return memmove(d, s, n);
}
__declspec(noinline) void* __asan_memset(void* d, int c, size_t n) {
    CheckRange(reinterpret_cast<uintptr_t>(d), n, 1, _ReturnAddress());
    return memset(d, c, n);
}

// (a call that does not return, a longjmp: the frames it leaves stay poisoned, so this thread's stack
// above here is cleared, its live frames' redzones with it until they return)
void __asan_handle_no_return(void) {
    UnpoisonThisStack(reinterpret_cast<uintptr_t>(_AddressOfReturnAddress()));
}

// (a large frame's redzones, set by call: the shadow's bytes at addr, size of them)
void __asan_set_shadow_00(uintptr_t addr, size_t size) { memset(reinterpret_cast<void*>(addr), 0x00, size); }
void __asan_set_shadow_01(uintptr_t addr, size_t size) { memset(reinterpret_cast<void*>(addr), 0x01, size); }
void __asan_set_shadow_02(uintptr_t addr, size_t size) { memset(reinterpret_cast<void*>(addr), 0x02, size); }
void __asan_set_shadow_03(uintptr_t addr, size_t size) { memset(reinterpret_cast<void*>(addr), 0x03, size); }
void __asan_set_shadow_04(uintptr_t addr, size_t size) { memset(reinterpret_cast<void*>(addr), 0x04, size); }
void __asan_set_shadow_05(uintptr_t addr, size_t size) { memset(reinterpret_cast<void*>(addr), 0x05, size); }
void __asan_set_shadow_06(uintptr_t addr, size_t size) { memset(reinterpret_cast<void*>(addr), 0x06, size); }
void __asan_set_shadow_07(uintptr_t addr, size_t size) { memset(reinterpret_cast<void*>(addr), 0x07, size); }
void __asan_set_shadow_f1(uintptr_t addr, size_t size) { memset(reinterpret_cast<void*>(addr), 0xf1, size); }
void __asan_set_shadow_f2(uintptr_t addr, size_t size) { memset(reinterpret_cast<void*>(addr), 0xf2, size); }
void __asan_set_shadow_f3(uintptr_t addr, size_t size) { memset(reinterpret_cast<void*>(addr), 0xf3, size); }
void __asan_set_shadow_f5(uintptr_t addr, size_t size) { memset(reinterpret_cast<void*>(addr), 0xf5, size); }
void __asan_set_shadow_f8(uintptr_t addr, size_t size) { memset(reinterpret_cast<void*>(addr), 0xf8, size); }

// Ghidra32.h's GEN_FRAME_DECL* with <ENV>_CHECKED_FRAMES=1: the pad's whole granules in front of
// gen_frame, and its top bytes (the saved ebp) to the array's end, poisoned. Cleared with the rest
// of the frame's shadow at its return
void gen_checked_frame(void* frame, unsigned int pad, unsigned int n, unsigned int top) {
    const uintptr_t f = reinterpret_cast<uintptr_t>(frame);
    if (!g_shadow || (f & 7) || f >= kCover) return;
    if (pad >= 8) Poison(f, pad & ~7u, kFrameEdge);
    if (top && top <= n) {
        const uintptr_t from = f + pad + n - top, end = f + pad + n;
        uintptr_t g = from & ~uintptr_t(7);
        *Sh(g) = (from & 7) ? static_cast<uint8_t>(from & 7) : kFrameEdge;
        for (g += 8; g < end; g += 8) *Sh(g) = kFrameEdge;
    }
}

// Ghidra32.h's GEN_TOP of a value past 32 bits (<ENV>_CHECKED_WRAP=1): once per site, no stack
__declspec(noinline) void gen_checked_wrap(unsigned long long x) {
    static SRWLOCK lock = SRWLOCK_INIT;
    static std::unordered_set<void*> seen;
    void* pc = _ReturnAddress();
    AcquireSRWLockExclusive(&lock);
    bool first = seen.size() < 200 && seen.insert(pc).second;
    ReleaseSRWLockExclusive(&lock);
    if (!first) return;
    fprintf(stderr, "%s: CHECKED: GEN_TOP of %llx, wider than 32 bits, truncated to %08x in:\n", RHIPPER_NAME, x,
            static_cast<unsigned int>(x));
    void* f[1] = {pc};
    RefPrintFrames(f, 1);
    fflush(stderr);
}

// (the thread callback, kept by the linker)
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:gen_checked_tls")
#pragma const_seg(".CRT$XLB")
extern const PIMAGE_TLS_CALLBACK gen_checked_tls = CheckedTls;
#pragma const_seg()
}

// ---- RefImage.cpp's calls ------------------------------------------------------------------------
// a read-only section of the reference's [lo, hi), write-protected (CHECKED_RDATA=0: left writable)
void CheckedProtect(uint32_t lo, uint32_t hi) {
    if (EnvNum("CHECKED_RDATA", 1) == 0 || hi <= lo) return;
    DWORD old;
    if (VirtualProtect(reinterpret_cast<void*>(static_cast<uintptr_t>(lo)), hi - lo, PAGE_READONLY, &old))
        g_readonly.push_back({lo, hi});
}

// after the imports are resolved and RefImage's exception handler is in: the settings, the heap's
// hooks, and this file's fault handler first of all
void CheckedStart() {
    wchar_t on[16] = {};
    if (RefEnv("CHECKED_ON", on, 16)) {
        if (_wcsicmp(on, L"stop") == 0) g_set.on = OnError::Stop;
        else if (_wcsicmp(on, L"break") == 0) g_set.on = OnError::Break;
    }
    g_set.max = static_cast<long>(EnvNum("CHECKED_MAX", 40));
    g_set.heap = EnvNum("CHECKED_HEAP", 1) != 0;
    g_set.exact = EnvNum("CHECKED_EXACT", 0) != 0;
    g_set.quarantine = static_cast<size_t>(EnvNum("CHECKED_QUARANTINE_MB", 64)) << 20;
    g_set.depth = static_cast<USHORT>(std::min(16u, std::max(1u, EnvNum("CHECKED_DEPTH", 8))));
    gen_checked_frames = EnvNum("CHECKED_FRAMES", 0) != 0;
    gen_checked_wrap_on = EnvNum("CHECKED_WRAP", 0) != 0;
    if (!g_shadow) {
        fprintf(stderr, "%s: CHECKED: no shadow (not the program's process?)\n", RHIPPER_NAME);
        TerminateProcess(GetCurrentProcess(), 1);
    }
    if (g_set.heap) {
        Hook("HeapAlloc", &g_heap.alloc, CheckedHeapAlloc);
        Hook("HeapFree", &g_heap.free, CheckedHeapFree);
        Hook("HeapSize", &g_heap.size, CheckedHeapSize);
        Hook("HeapReAlloc", &g_heap.realloc, CheckedHeapReAlloc);
        Hook("HeapDestroy", &g_heap.destroy, CheckedHeapDestroy);
        if (!g_heap.alloc || !g_heap.free || !g_heap.size || !g_heap.realloc || !g_heap.destroy) {
            fprintf(stderr, "%s: CHECKED: the heap imports are not all the reference's; the heap unchecked\n", RHIPPER_NAME);
            g_set.heap = false;
        }
    }
    UnpoisonThisStack(0);
    AddVectoredExceptionHandler(1, CheckedFault);
    fprintf(stderr, "%s: CHECKED on: shadow %p-%p, heap %s (quarantine %zu MB, %s), frames %s, wrap %s, "
            "%zu read-only ranges, on error %ls\n", RHIPPER_NAME, g_shadow, g_shadow + kShadowSize,
            g_set.heap ? "redzoned" : "off", g_set.quarantine >> 20, g_set.exact ? "exact" : "16-byte",
            gen_checked_frames ? "on" : "off", gen_checked_wrap_on ? "on" : "off", g_readonly.size(),
            on[0] ? on : L"continue");
    fflush(stderr);
}
