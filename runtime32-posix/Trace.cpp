// The shadow trace, the port's side of shadow32.py (runtime32/Trace.cpp's): with <ENV>_TRACE=<file>
// (a path relative to the log directory, or absolute) every translated function's entry is recorded:
// thread, reference address, first four arguments, 24 bytes each, up to <ENV>_TRACE_MAX records
// (2,000,000), from <ENV>_TRACE_FROM's function's first call when it is set. The same file format,
// so shadow_diff.py compares it with the reference's record. (The x64 runtime's DUMPAT and STACKAT
// hooks are not here.)
//
// <ENV>_WATCH=<hex addr>[:<hex len>] (from TRACE_FROM's first call when that is set, with or without a
// trace file): who writes those bytes. There are no hardware watchpoints from user space here, so
// the page is made read-only; a write fault in the range is reported (the function, its registers,
// its backtrace), the page made writable for the write to go on, and read-only again at the next
// translated function's entry, which also logs the watched words when they changed. Writes to the
// rest of the page are let through the same way, unreported. (A write the kernel makes, read() into
// the page, fails with EFAULT instead.)
#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>

#include <atomic>
#include <cstring>

#include <cstdio>
#include <cstdlib>
#include <mutex>

#include "Runtime.h"

extern "C" int gen_trace_on = 0;

namespace rh {

namespace {
struct Record {
    uint32_t tid, addr, a[4];
};
static_assert(sizeof(Record) == 24, "trace record");

FILE* g_file = nullptr;
std::mutex g_lock;
uint64_t g_left = 0;
uint32_t g_from = 0;
bool g_started = true;
Record g_buf[4096];
unsigned g_used = 0;
bool g_sync = false;

// the watch: [g_watchLo, g_watchHi) on the page at g_watchPage; armed while that page is read-only
uintptr_t g_watchLo = 0, g_watchHi = 0, g_watchPage = 0;
std::atomic<bool> g_watchArmed{false};
std::atomic<int> g_watchHits{0};
uint32_t g_watchSeen[8] = {};

void WatchArm() {
    if (g_watchArmed.load(std::memory_order_relaxed)) return;
    // (only once the page is committed: reserved, it is PROT_NONE, and reading it would fault)
    Region r;
    if (!LowQuery(static_cast<uint32_t>(g_watchPage), &r) || r.state != 0x1000 /* MEM_COMMIT */) return;
    // (the watched words as they are now, when they changed since the last look)
    uint32_t now[8] = {};
    size_t words = (g_watchHi - g_watchLo + 3) / 4;
    if (words > 8) words = 8;
    memcpy(now, reinterpret_cast<void*>(g_watchLo), words * 4);
    if (memcmp(now, g_watchSeen, words * 4) != 0) {
        char line[160];
        int n = snprintf(line, sizeof line, RHIPPER_NAME ": watch %08lx now", static_cast<unsigned long>(g_watchLo));
        for (size_t k = 0; k < words && n < 150; k++) n += snprintf(line + n, sizeof line - n, " %08x", now[k]);
        LogRaw(line);
        memcpy(g_watchSeen, now, sizeof now);
    }
    if (mprotect(reinterpret_cast<void*>(g_watchPage), 4096, PROT_READ) == 0) g_watchArmed = true;
}

void FlushLocked() {
    if (g_file && g_used) {
        fwrite(g_buf, sizeof(Record), g_used, g_file);
        fflush(g_file);
    }
    g_used = 0;
}

void* Flusher(void*) {
    for (;;) {
        usleep(250000);
        std::lock_guard<std::mutex> hold(g_lock);
        FlushLocked();
    }
    return nullptr;
}
}  // namespace

void RefTraceStart() {
    std::string watch = Env("WATCH");
    if (!watch.empty()) {
        char* end = nullptr;
        g_watchLo = strtoul(watch.c_str(), &end, 16);
        uintptr_t len = end && *end == ':' ? strtoul(end + 1, nullptr, 16) : 4;
        g_watchHi = g_watchLo + (len ? len : 4);
        g_watchPage = g_watchLo & ~uintptr_t(4095);
        Log("watching writes to %08lx-%08lx", static_cast<unsigned long>(g_watchLo),
            static_cast<unsigned long>(g_watchHi));
    }
    std::string path = Env("TRACE");
    if (path.empty() && !g_watchPage) return;
    if (!path.empty()) {
        if (path[0] != '/') path = LogDir() + "/" + path;
        g_file = fopen(path.c_str(), "wb");
        if (!g_file) {
            Log("cannot write the trace %s", path.c_str());
            if (!g_watchPage) return;
        }
    }
    std::string max = Env("TRACE_MAX"), from = Env("TRACE_FROM");
    g_left = max.empty() ? 2000000 : strtoull(max.c_str(), nullptr, 10);
    g_sync = !Env("TRACE_SYNC").empty();
    if (!from.empty()) {
        g_from = static_cast<uint32_t>(strtoul(from.c_str(), nullptr, 16));
        g_started = g_from == 0;
    }
    gen_trace_on = 1;
    if (!g_file) return;
    Log("tracing to %s (%llu calls at most%s)", path.c_str(), static_cast<unsigned long long>(g_left),
        g_started ? "" : ", from TRACE_FROM's first call");
    pthread_t t;
    pthread_create(&t, nullptr, Flusher, nullptr);
    pthread_detach(t);
}

// LowMem.cpp's Protect changed [lo, hi)'s protection (a commit, a decommit): the watch's page, if it
// is in there, is armed again at the next translated function's entry
void RefWatchProtected(uintptr_t lo, uintptr_t hi) {
    if (g_watchPage && g_watchPage + 4096 > lo && g_watchPage < hi) g_watchArmed = false;
}

// a fault at `addr`: 0 not the watch's, 1 the watched page outside the range (let through), 2 a write
// into the range (to be reported, the first 32). The page is writable again on return either way.
int RefWatchFault(uintptr_t addr) {
    if (!g_watchPage || addr < g_watchPage || addr >= g_watchPage + 4096) return 0;
    if (!g_watchArmed) return 0;   // (not ours: the page as the runtime left it, a real fault)
    mprotect(reinterpret_cast<void*>(g_watchPage), 4096, PROT_READ | PROT_WRITE);
    g_watchArmed = false;
    if (addr < g_watchLo || addr >= g_watchHi) return 1;
    return g_watchHits++ < 32 ? 2 : 1;
}

void RefTraceFlush() {
    if (!g_file) return;
    // (from a fault handler too: a lock held by the faulting thread itself is not waited for)
    std::unique_lock<std::mutex> hold(g_lock, std::try_to_lock);
    if (hold.owns_lock()) FlushLocked();
}

}  // namespace rh

using namespace rh;

extern "C" void gen_trace_enter(unsigned int addr, unsigned int a0, unsigned int a1, unsigned int a2, unsigned int a3) {
    std::lock_guard<std::mutex> hold(g_lock);
    if (!g_started) {
        if (addr != g_from) return;
        g_started = true;
    }
    if (g_watchPage) WatchArm();
    if (!g_file) return;
    if (g_left == 0) {
        gen_trace_on = 0;
        FlushLocked();
        return;
    }
    g_left--;
    g_buf[g_used++] = Record{CurrentThreadId(), addr, {a0, a1, a2, a3}};
    if (g_used == sizeof g_buf / sizeof g_buf[0] || g_sync) FlushLocked();
}
