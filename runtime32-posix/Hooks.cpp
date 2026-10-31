// What the generated code and Ghidra32.h expect of the runtime, besides the imports: the x86 TEB
// (fs), the reference's TLS array, setjmp buffers, the `lock` prefix's lock, the x87 control and
// status words, MXCSR, GenUnimplemented and the reports, and the personality's registry.
#include <dlfcn.h>
#include <fenv.h>
#include <pthread.h>
#include <unistd.h>

#include <atomic>
#include <csetjmp>
#include <cstdio>
#include <memory>
#include <mutex>
#include <unordered_set>
#include <vector>

#include "Runtime.h"

namespace rh {

uint32_t g_tlsStart = 0, g_tlsEnd = 0, g_tlsZero = 0;   // the image's TLS template (RefImage.cpp)
void NamePc(uintptr_t pc, char* out, size_t n);         // RefImage.cpp
bool InPort(uintptr_t pc);
void RefTraceFlush();

ApiEntry*& ApiList() {
    static ApiEntry* list = nullptr;
    return list;
}

const ApiEntry* FindApi(const char* name) {
    for (ApiEntry* e = ApiList(); e; e = e->next)
        if (strcmp(e->name, name) == 0) return e;
    return nullptr;
}

// the frame-pointer chain from a context: AArch64 keeps x29 as the frame pointer (Android's
// default), each frame {previous x29, return address}. Every frame read checked against the
// thread's stack, so a bad chain ends the walk, not the report
thread_local uintptr_t t_stackLo = 0, t_stackHi = 0;

void NoteStack() {
    pthread_attr_t a;
    if (pthread_getattr_np(pthread_self(), &a) != 0) return;
    void* lo = nullptr;
    size_t len = 0;
    pthread_attr_getstack(&a, &lo, &len);
    pthread_attr_destroy(&a);
    t_stackLo = reinterpret_cast<uintptr_t>(lo);
    t_stackHi = t_stackLo + len;
}

void PrintBacktrace(uintptr_t fp, uintptr_t pc, uintptr_t lr) {
    if (!t_stackHi) NoteStack();
    char name[160], line[256];
    NamePc(pc, name, sizeof name);
    snprintf(line, sizeof line, "   0  %016lx  %s", static_cast<unsigned long>(pc), name);
    LogRaw(line);
    // (a leaf's caller, which no frame records yet)
    NamePc(lr, name, sizeof name);
    snprintf(line, sizeof line, "  lr  %016lx  %s", static_cast<unsigned long>(lr), name);
    LogRaw(line);
    for (int k = 1; k < 48; k++) {
        if (fp & 15 || fp < t_stackLo || fp + 16 > t_stackHi) break;
        auto frame = reinterpret_cast<const uintptr_t*>(fp);
        uintptr_t ret = frame[1];
        if (!ret) break;
        NamePc(ret, name, sizeof name);
        snprintf(line, sizeof line, "  %2d  %016lx  %s", k, static_cast<unsigned long>(ret), name);
        LogRaw(line);
        if (frame[0] <= fp) break;
        fp = frame[0];
    }
}

void PrintHere() {
    PrintBacktrace(reinterpret_cast<uintptr_t>(__builtin_frame_address(0)),
                   reinterpret_cast<uintptr_t>(&PrintHere),
                   reinterpret_cast<uintptr_t>(__builtin_return_address(0)));
}

}  // namespace rh

using namespace rh;

extern "C" {

// ---- GenUnimplemented: a function no translation covers, logged once with its caller ------------
void GenUnimplemented(unsigned int address) {
    static std::mutex lock;
    static std::unordered_set<unsigned int> seen;
    {
        std::lock_guard<std::mutex> guard(lock);
        if (!seen.insert(address).second) return;
    }
    Log("not translated: %08x", address);
    PrintHere();
    RefTraceFlush();
}

void gen_fastfail_report(void) {
    Log("__fastfail (0xc0000409) on thread %u", CurrentThreadId());
    PrintHere();
    RefTraceFlush();
    LogFlush();
}

void gen_suspect(unsigned int addr, const char* names) {
    static std::atomic<long> n{0};
    Log("suspect %08x ran, reading %s uninitialized (%ld so far)", addr, names, ++n);
}

// ---- Ghidra32.h's LOCK() / UNLOCK(): the reference's `lock`-prefixed read-modify-writes ----------
static std::mutex g_genLock;
void gen_lock_enter(void) { g_genLock.lock(); }
void gen_lock_leave(void) { g_genLock.unlock(); }

// ---- the x87 unit's words and SSE's MXCSR, per thread ------------------------------------------
thread_local unsigned short gen_x87_cw = 0x27f;
thread_local unsigned int gen_MXCSR = 0x1f80;

// `fldcw`: kept for `fnstcw`, its rounding control the host's (FPCR's RMode)
void gen_set_x87_cw(unsigned short cw) {
    gen_x87_cw = cw;
    static const int rc[4] = {FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO};
    fesetround(rc[(cw >> 10) & 3]);
}

// `fnstsw`: the host's exception flags as x87 bits (AArch64 has no denormal-operand flag)
unsigned short gen_fpusw(int clear) {
    int s = fetestexcept(FE_ALL_EXCEPT);
    unsigned short w = 0;
    if (s & FE_INVALID) w |= 0x01;
    if (s & FE_DIVBYZERO) w |= 0x04;
    if (s & FE_OVERFLOW) w |= 0x08;
    if (s & FE_UNDERFLOW) w |= 0x10;
    if (s & FE_INEXACT) w |= 0x20;
    if (clear) feclearexcept(FE_ALL_EXCEPT);
    return w;
}

// ---- the reference's TLS: this thread's array of block addresses, index 0 the image's ------------
unsigned int gen_tls_array(void) {
    static thread_local uint32_t array = 0;
    if (array == 0) {
        const uint32_t data = g_tlsEnd - g_tlsStart;
        auto block = static_cast<uint8_t*>(LowNew(data + g_tlsZero + 16));
        if (data) memcpy(block, At(g_tlsStart), data);
        auto slots = static_cast<uint32_t*>(LowNew(64 * sizeof(uint32_t)));
        slots[0] = Low(block);
        array = Low(slots);
    }
    return array;
}

// ---- setjmp: a native jmp_buf per reference buffer address, per thread ---------------------------
jmp_buf* gen_jmpbuf(unsigned int ref) {
    struct Slot {
        unsigned int ref;
        jmp_buf buf;
    };
    static thread_local std::vector<std::unique_ptr<Slot>> slots;
    for (auto& s : slots)
        if (s->ref == ref) return &s->buf;
    slots.push_back(std::make_unique<Slot>());
    slots.back()->ref = ref;
    return &slots.back()->buf;
}

// ---- the x86 TEB and PEB (Ghidra32.h gen_teb32): per thread a zeroed 4 KB block below 2 GB with
// the fields 32-bit Windows sets. The personality keeps its per-thread state there too, where x86
// Windows does: LastErrorValue (0x34), TlsSlots (0xE10), TlsExpansionSlots (0xF94)
static thread_local uint8_t* t_teb32 = nullptr;
int gen_teb32_made(void) { return t_teb32 != nullptr; }

unsigned int gen_teb32(void) {
    static uint8_t* peb = nullptr;
    static std::once_flag pebOnce;
    if (t_teb32 == nullptr) {
        std::call_once(pebOnce, [] {
            auto p = static_cast<uint8_t*>(LowNew(0x1000));
            *reinterpret_cast<uint32_t*>(p + 0x08) = gen_ref_base;    // ImageBaseAddress
            *reinterpret_cast<uint32_t*>(p + 0x18) = ProcessHeap();   // ProcessHeap
            *reinterpret_cast<uint32_t*>(p + 0x10) = Low(LowNew(0x400));   // ProcessParameters (zeroed)
            *reinterpret_cast<uint32_t*>(p + 0x64) = static_cast<uint32_t>(sysconf(_SC_NPROCESSORS_ONLN));
            *reinterpret_cast<uint32_t*>(p + 0xA4) = 6;               // OSMajorVersion (7: 6.1)
            *reinterpret_cast<uint32_t*>(p + 0xA8) = 1;
            *reinterpret_cast<uint16_t*>(p + 0xAC) = 7601;
            *reinterpret_cast<uint32_t*>(p + 0xB0) = 2;               // OSPlatformId
            peb = p;
        });
        auto t = static_cast<uint8_t*>(LowNew(0x1000));
        auto w = [t](unsigned off, uint32_t v) { *reinterpret_cast<uint32_t*>(t + off) = v; };
        NoteStack();
        w(0x00, 0xffffffffu);                            // ExceptionList
        w(0x04, static_cast<uint32_t>(t_stackHi));       // StackBase (below 2 GB on a LowThread)
        w(0x08, static_cast<uint32_t>(t_stackLo));       // StackLimit
        w(0x18, Low(t));                                 // Self
        w(0x20, static_cast<uint32_t>(getpid()));        // ClientId
        w(0x24, CurrentThreadId());
        w(0x30, Low(peb));                               // ProcessEnvironmentBlock
        t_teb32 = t;
        w(0x2c, gen_tls_array());                        // ThreadLocalStoragePointer
    }
    return Low(t_teb32);
}

}  // extern "C"

namespace rh {

// the last error: the TEB's where this thread has one, a thread_local always (an error set before
// the TEB exists, or from inside the low allocator, must not make one)
static thread_local uint32_t t_lastError = 0;
void SetLastError(uint32_t e) {
    t_lastError = e;
    if (t_teb32) *reinterpret_cast<uint32_t*>(t_teb32 + 0x34) = e;
}
uint32_t GetLastError() { return t_teb32 ? *reinterpret_cast<uint32_t*>(t_teb32 + 0x34) : t_lastError; }

}  // namespace rh

static uint32_t GetLastError_() { return rh::GetLastError(); }
RH_REG(KERNEL32, GetLastError, GetLastError_)
static uint32_t SetLastError_(uint32_t e) { return rh::SetLastError(e), 0; }
RH_REG(KERNEL32, SetLastError, SetLastError_)

// ---- TlsAlloc and friends: the TEB's 64 slots, then 1,024 expansion slots, as x86 Windows ------
namespace {
std::mutex g_tlsLock;
std::vector<bool> g_tlsUsed(64 + 1024);

uint32_t* TlsSlot(uint32_t index, bool make) {
    auto teb = At<uint8_t>(gen_teb32());
    if (index < 64) return reinterpret_cast<uint32_t*>(teb + 0xE10) + index;
    auto& exp = *reinterpret_cast<uint32_t*>(teb + 0xF94);
    if (!exp) {
        if (!make) return nullptr;
        exp = Low(LowNew(1024 * 4));
    }
    return At<uint32_t>(exp) + (index - 64);
}
}  // namespace

static uint32_t TlsAlloc_() {
    std::lock_guard<std::mutex> hold(g_tlsLock);
    for (uint32_t k = 0; k < g_tlsUsed.size(); k++)
        if (!g_tlsUsed[k]) {
            g_tlsUsed[k] = true;
            return k;
        }
    return 0xFFFFFFFFu;   // TLS_OUT_OF_INDEXES
}
RH_REG(KERNEL32, TlsAlloc, TlsAlloc_)
static uint32_t TlsFree_(uint32_t k) {
    std::lock_guard<std::mutex> hold(g_tlsLock);
    if (k >= g_tlsUsed.size() || !g_tlsUsed[k]) return 0;
    g_tlsUsed[k] = false;
    return 1;
}
RH_REG(KERNEL32, TlsFree, TlsFree_)
static uint32_t TlsGetValue_(uint32_t k) {
    if (k >= 64 + 1024) {
        SetLastError(win::ERROR_INVALID_PARAMETER);
        return 0;
    }
    uint32_t* s = TlsSlot(k, false);
    SetLastError(0);
    return s ? *s : 0;
}
RH_REG(KERNEL32, TlsGetValue, TlsGetValue_)
static uint32_t TlsSetValue_(uint32_t k, uint32_t v) {
    if (k >= 64 + 1024) {
        SetLastError(win::ERROR_INVALID_PARAMETER);
        return 0;
    }
    *TlsSlot(k, true) = v;
    return 1;
}
RH_REG(KERNEL32, TlsSetValue, TlsSetValue_)
