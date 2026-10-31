// The shadow trace, the port's side of shadow32.py (runtime32/Trace.cpp's): with <ENV>_TRACE=<file>
// (a path relative to the log directory, or absolute) every translated function's entry is recorded:
// thread, reference address, first four arguments, 24 bytes each, up to <ENV>_TRACE_MAX records
// (2,000,000), from <ENV>_TRACE_FROM's function's first call when it is set. The same file format,
// so shadow_diff.py compares it with the reference's record. (The x64 runtime's DUMPAT, STACKAT and
// WATCH hooks are not here: no hardware watchpoints from user space on Android.)
#include <pthread.h>
#include <unistd.h>

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
    std::string path = Env("TRACE");
    if (path.empty()) return;
    if (path[0] != '/') path = LogDir() + "/" + path;
    g_file = fopen(path.c_str(), "wb");
    if (!g_file) {
        Log("cannot write the trace %s", path.c_str());
        return;
    }
    std::string max = Env("TRACE_MAX"), from = Env("TRACE_FROM");
    g_left = max.empty() ? 2000000 : strtoull(max.c_str(), nullptr, 10);
    g_sync = !Env("TRACE_SYNC").empty();
    if (!from.empty()) {
        g_from = static_cast<uint32_t>(strtoul(from.c_str(), nullptr, 16));
        g_started = g_from == 0;
    }
    Log("tracing to %s (%llu calls at most%s)", path.c_str(), static_cast<unsigned long long>(g_left),
        g_started ? "" : ", from TRACE_FROM's first call");
    gen_trace_on = 1;
    pthread_t t;
    pthread_create(&t, nullptr, Flusher, nullptr);
    pthread_detach(t);
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
    if (!g_file) return;
    std::lock_guard<std::mutex> hold(g_lock);
    if (!g_started) {
        if (addr != g_from) return;
        g_started = true;
    }
    if (g_left == 0) {
        gen_trace_on = 0;
        FlushLocked();
        return;
    }
    g_left--;
    g_buf[g_used++] = Record{CurrentThreadId(), addr, {a0, a1, a2, a3}};
    if (g_used == sizeof g_buf / sizeof g_buf[0] || g_sync) FlushLocked();
}
