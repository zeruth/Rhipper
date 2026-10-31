// kernel32's threads and process: native threads whose stacks are below 2 GB (the reference takes
// the addresses of its locals into 4-byte slots), each with a TEB made on first use (Hooks.cpp), the
// process's end, and the system's description (x86 layouts).
#include <pthread.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <condition_variable>

#include "Runtime.h"

extern "C" unsigned int gen_teb32(void);

namespace rh {

void ThreadSignalStack();   // RefImage.cpp
void NoteStack();           // Hooks.cpp
void RefTraceFlush();
void PrintHere();
void RefExit(int code);

uint32_t CurrentThreadId() {
    static thread_local uint32_t tid = static_cast<uint32_t>(gettid());
    return tid;
}

struct Thread : Object {
    pthread_t thread{};
    uint32_t tid = 0;
    bool done = false, suspended = false;
    uint32_t exitCode = 259;   // STILL_ACTIVE
    void (*fn)(void*) = nullptr;
    void* arg = nullptr;
    uint32_t stackLo = 0, stackSize = 0;
    const char* Kind() const override { return "thread"; }
    bool Waitable() const override { return true; }
    bool Signalled(uint32_t) const override { return done; }
};

namespace {
std::mutex g_threadsLock;
std::condition_variable g_resumeCv;
thread_local std::shared_ptr<Thread> t_self;

void* ThreadMain(void* p) {
    auto self = *static_cast<std::shared_ptr<Thread>*>(p);
    delete static_cast<std::shared_ptr<Thread>*>(p);
    t_self = self;
    ThreadSignalStack();
    NoteStack();
    {
        std::unique_lock<std::mutex> lk(g_threadsLock);
        self->tid = CurrentThreadId();
        g_resumeCv.notify_all();   // (the creator waits for the id)
        g_resumeCv.wait(lk, [&] { return !self->suspended; });
    }
    self->fn(self->arg);
    {
        std::lock_guard<std::mutex> hold(WaitLock());
        self->done = true;
        WaitNotify();
    }
    // (the stack stays mapped: the thread runs on it through its exit. Games make few threads)
    return nullptr;
}

struct RefStart {
    uint32_t start, param;
    std::atomic<uint32_t>* code;
};
void RunRef(void* p) {
    std::unique_ptr<RefStart> s(static_cast<RefStart*>(p));
    uint32_t r = CallRef(s->start, s->param);
    if (t_self) t_self->exitCode = r;
}
}  // namespace

uint32_t StartLowThread(void (*fn)(void*), void* arg, uint32_t stack, bool suspended, uint32_t* tid) {
    auto t = std::make_shared<Thread>();
    t->fn = fn;
    t->arg = arg;
    t->suspended = suspended;
    const uint32_t guard = static_cast<uint32_t>(std::max<size_t>(PageSize(), 0x10000));
    stack = (stack + 0xFFFF) & ~0xFFFFu;
    uint32_t lo = LowAlloc(stack + guard);
    if (!lo) return 0;
    mprotect(At(lo), guard, PROT_NONE);   // (an overflow faults, reported, before it reaches anything)
    t->stackLo = lo;
    t->stackSize = stack + guard;
    pthread_attr_t a;
    pthread_attr_init(&a);
    pthread_attr_setstack(&a, At(lo + guard), stack);
    pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
    auto boxed = new std::shared_ptr<Thread>(t);
    int err = pthread_create(&t->thread, &a, ThreadMain, boxed);
    pthread_attr_destroy(&a);
    if (err) {
        delete boxed;
        Log("pthread_create failed (%d)", err);
        return 0;
    }
    {
        std::unique_lock<std::mutex> lk(g_threadsLock);
        g_resumeCv.wait(lk, [&] { return t->tid != 0; });
    }
    if (tid) *tid = t->tid;
    return NewHandle(t);
}

}  // namespace rh

using namespace rh;

// CreateThread(sa, stack, start, param, flags, tid): the reference's function on a low thread. Its
// stack the larger of 8 MB and twice what it asked (translated frames are larger than x86's)
static uint32_t CreateThread_(uint32_t, uint32_t stack, uint32_t start, uint32_t param, uint32_t flags, uint32_t tidOut) {
    uint32_t size = std::max<uint32_t>(8u << 20, std::min<uint32_t>(stack, 256u << 20) * 2);
    auto s = new RefStart{start, param, nullptr};
    uint32_t tid = 0;
    uint32_t h = StartLowThread(RunRef, s, size, (flags & 4) != 0 /* CREATE_SUSPENDED */, &tid);
    if (!h) {
        delete s;
        SetLastError(win::ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    }
    if (tidOut) *At<uint32_t>(tidOut) = tid;
    return h;
}
RH_REG(KERNEL32, CreateThread, CreateThread_)

static uint32_t ResumeThread_(uint32_t h) {
    auto t = GetAs<Thread>(h);
    if (!t) return 0xFFFFFFFFu;
    std::lock_guard<std::mutex> hold(g_threadsLock);
    uint32_t was = t->suspended ? 1 : 0;
    t->suspended = false;
    g_resumeCv.notify_all();
    return was;
}
RH_REG(KERNEL32, ResumeThread, ResumeThread_)

static uint32_t ExitThread_(uint32_t code) {
    if (t_self) {
        t_self->exitCode = code;
        std::lock_guard<std::mutex> hold(WaitLock());
        t_self->done = true;
        WaitNotify();
    }
    pthread_exit(nullptr);
}
RH_REG(KERNEL32, ExitThread, ExitThread_)

static uint32_t GetExitCodeThread_(uint32_t h, uint32_t out) {
    auto t = GetAs<Thread>(h);
    if (!t) return SetLastError(win::ERROR_INVALID_HANDLE), 0;
    std::lock_guard<std::mutex> hold(WaitLock());
    *At<uint32_t>(out) = t->done ? t->exitCode : 259;
    return 1;
}
RH_REG(KERNEL32, GetExitCodeThread, GetExitCodeThread_)

static uint32_t GetThreadPriority_(uint32_t) { return 0; }
RH_REG(KERNEL32, GetThreadPriority, GetThreadPriority_)
static uint32_t SetThreadPriority_(uint32_t, uint32_t) { return 1; }
RH_REG(KERNEL32, SetThreadPriority, SetThreadPriority_)
static uint32_t SetThreadAffinityMask_(uint32_t, uint32_t) { return 1; }   // (the old mask: one core's)
RH_REG(KERNEL32, SetThreadAffinityMask, SetThreadAffinityMask_)
static uint32_t SetThreadIdealProcessor_(uint32_t, uint32_t) { return 0; }
RH_REG(KERNEL32, SetThreadIdealProcessor, SetThreadIdealProcessor_)

static uint32_t GetCurrentThread_() { return kCurrentThread; }
RH_REG(KERNEL32, GetCurrentThread, GetCurrentThread_)
static uint32_t GetCurrentThreadId_() { return CurrentThreadId(); }
RH_REG(KERNEL32, GetCurrentThreadId, GetCurrentThreadId_)
static uint32_t GetCurrentProcess_() { return kCurrentProcess; }
RH_REG(KERNEL32, GetCurrentProcess, GetCurrentProcess_)
static uint32_t GetCurrentProcessId_() { return static_cast<uint32_t>(getpid()); }
RH_REG(KERNEL32, GetCurrentProcessId, GetCurrentProcessId_)
static uint32_t GetProcessId_(uint32_t h) { return h == kCurrentProcess ? static_cast<uint32_t>(getpid()) : 0; }
RH_REG(KERNEL32, GetProcessId, GetProcessId_)

// ---- other processes: none here (an updater, a crash reporter, a browser the game would start) --
static uint32_t CreateProcessA_(uint32_t app, uint32_t cmd, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t,
                                uint32_t, uint32_t) {
    Log("CreateProcessA(%s, %s): no other processes here", app ? At<char>(app) : "-", cmd ? At<char>(cmd) : "-");
    SetLastError(win::ERROR_FILE_NOT_FOUND);
    return 0;
}
RH_REG(KERNEL32, CreateProcessA, CreateProcessA_)
static uint32_t OpenProcess_(uint32_t, uint32_t, uint32_t pid) {
    if (pid == static_cast<uint32_t>(getpid())) return kCurrentProcess;
    SetLastError(win::ERROR_INVALID_PARAMETER);
    return 0;
}
RH_REG(KERNEL32, OpenProcess, OpenProcess_)
static uint32_t GetExitCodeProcess_(uint32_t, uint32_t out) {
    if (out) *At<uint32_t>(out) = 259;
    return 1;
}
RH_REG(KERNEL32, GetExitCodeProcess, GetExitCodeProcess_)
static uint32_t DebugActiveProcess_(uint32_t) { return SetLastError(win::ERROR_ACCESS_DENIED), 0; }
RH_REG(KERNEL32, DebugActiveProcess, DebugActiveProcess_)
static uint32_t IsDebuggerPresent_() { return 0; }
RH_REG(KERNEL32, IsDebuggerPresent, IsDebuggerPresent_)

// ---- the process's end ---------------------------------------------------------------------------
static void EndReport(const char* how, uint32_t code) {
    Log("%s(%#x) on thread %u", how, code, CurrentThreadId());
    if (code) PrintHere();
    RefTraceFlush();
    LogFlush();
}

extern "C" {
// ExitProcess: the reference's program ends. On its main thread, that thread ends and
// rhipper_host_run returns the code to the host; from another, the process ends here
unsigned int gen_imp_ExitProcess(uint32_t code) {
    EndReport("ExitProcess", code);
    RefExit(static_cast<int>(code));
    if (t_self) {
        t_self->exitCode = code;
        std::lock_guard<std::mutex> hold(WaitLock());
        t_self->done = true;
        WaitNotify();
        // (the waiting host thread returns; this one goes no further)
    }
    pthread_exit(nullptr);
}
unsigned int gen_imp_TerminateProcess(uint32_t process, uint32_t code) {
    if (process != kCurrentProcess && process != static_cast<uint32_t>(getpid())) return 0;
    EndReport("TerminateProcess", code);
    _exit(static_cast<int>(code));
}
}  // extern "C"

static uint32_t FatalAppExitA_(uint32_t, uint32_t text) {
    Log("FatalAppExit: %s", text ? At<char>(text) : "");
    EndReport("FatalAppExit", 3);
    _exit(3);
}
RH_REG(KERNEL32, FatalAppExitA, FatalAppExitA_)

// ---- the system, at x86 layouts --------------------------------------------------------------------
namespace {
#pragma pack(push, 4)
struct SystemInfo32 {
    uint16_t wProcessorArchitecture, wReserved;
    uint32_t dwPageSize, lpMinimumApplicationAddress, lpMaximumApplicationAddress, dwActiveProcessorMask;
    uint32_t dwNumberOfProcessors, dwProcessorType, dwAllocationGranularity;
    uint16_t wProcessorLevel, wProcessorRevision;
};
struct ProcessorInfo32 {
    uint32_t mask, relationship;
    uint8_t rest[16];
};
struct MemoryInfo32 {
    uint32_t BaseAddress, AllocationBase, AllocationProtect, RegionSize, State, Protect, Type;
};
struct StartupInfo32 {
    uint32_t cb, lpReserved, lpDesktop, lpTitle;
    uint32_t dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
    uint16_t wShowWindow, cbReserved2;
    uint32_t lpReserved2, hStdInput, hStdOutput, hStdError;
};
#pragma pack(pop)
static_assert(sizeof(SystemInfo32) == 36, "SYSTEM_INFO, x86");
static_assert(sizeof(ProcessorInfo32) == 24, "SYSTEM_LOGICAL_PROCESSOR_INFORMATION, x86");
static_assert(sizeof(MemoryInfo32) == 28, "MEMORY_BASIC_INFORMATION, x86");
static_assert(sizeof(StartupInfo32) == 68, "STARTUPINFO, x86");

uint32_t Cpus() {
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n < 1 ? 1 : n > 32 ? 32 : static_cast<uint32_t>(n);
}
}  // namespace

extern "C" {
unsigned int gen_imp_GetSystemInfo(uint32_t out) {
    auto o = At<SystemInfo32>(out);
    memset(o, 0, sizeof *o);
    o->wProcessorArchitecture = 0;          // PROCESSOR_ARCHITECTURE_INTEL: what the reference was built for
    o->dwPageSize = 0x1000;
    o->lpMinimumApplicationAddress = 0x10000;
    o->lpMaximumApplicationAddress = 0x7ffeffff;
    o->dwNumberOfProcessors = Cpus();
    o->dwActiveProcessorMask = Cpus() >= 32 ? 0xFFFFFFFFu : (1u << Cpus()) - 1;
    o->dwProcessorType = 586;               // PROCESSOR_INTEL_PENTIUM
    o->dwAllocationGranularity = 0x10000;
    o->wProcessorLevel = 6;
    o->wProcessorRevision = 0x3a09;
    return 0;
}

// one core per processor, no shared caches: Havok's pool counts the cores
unsigned int gen_imp_GetLogicalProcessorInformation(uint32_t buf, uint32_t plen) {
    const uint32_t n = Cpus() + 1, need = n * sizeof(ProcessorInfo32);
    uint32_t* len = At<uint32_t>(plen);
    if (buf == 0 || *len < need) {
        *len = need;
        SetLastError(win::ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    auto out = At<ProcessorInfo32>(buf);
    memset(out, 0, need);
    for (uint32_t k = 0; k + 1 < n; k++) {
        out[k].mask = 1u << k;
        out[k].relationship = 0;   // RelationProcessorCore
    }
    out[n - 1].mask = (Cpus() >= 32 ? 0xFFFFFFFFu : (1u << Cpus()) - 1);
    out[n - 1].relationship = 3;   // RelationProcessorPackage
    *len = need;
    return 1;
}

unsigned int gen_imp_GetProcessAffinityMask(uint32_t, uint32_t pmask, uint32_t psystem) {
    uint32_t all = Cpus() >= 32 ? 0xFFFFFFFFu : (1u << Cpus()) - 1;
    if (pmask) *At<uint32_t>(pmask) = all;
    if (psystem) *At<uint32_t>(psystem) = all;
    return 1;
}

unsigned int gen_imp_VirtualQuery(uint32_t address, uint32_t out, uint32_t length) {
    if (length < sizeof(MemoryInfo32)) return 0;
    Region r;
    if (!LowQuery(address, &r)) return 0;
    auto o = At<MemoryInfo32>(out);
    *o = {r.base, r.allocBase, r.allocProtect, r.size, r.state, r.protect, r.type};
    return sizeof(MemoryInfo32);
}

unsigned int gen_imp_GetStartupInfoW(uint32_t out) {
    auto o = At<StartupInfo32>(out);
    memset(o, 0, sizeof *o);
    o->cb = sizeof *o;
    o->wShowWindow = 1;   // SW_SHOWNORMAL
    return 0;
}
}  // extern "C"

// SSE, SSE2, SSE3, NX, cmpxchg8b, rdtsc: what a 2013 PC has (the port computes them portably)
static uint32_t IsProcessorFeaturePresent_(uint32_t f) {
    switch (f) {
        case 2: case 3: case 6: case 8: case 10: case 12: case 13: return 1;
        default: return 0;
    }
}
RH_REG(KERNEL32, IsProcessorFeaturePresent, IsProcessorFeaturePresent_)
