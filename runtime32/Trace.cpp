// The shadow trace: the port's side of shadow32.py. With <ENV>_TRACE=<file> set, every translated
// function's entry (GEN_ENTER, Ghidra32.h) is recorded: the thread, the reference address, the
// first four arguments, 24 bytes each, up to <ENV>_TRACE_MAX records (2,000,000 by default),
// from <ENV>_TRACE_FROM's function's first call when it is set (shadow32.py --from, the same point).
// shadow_diff.py compares the file with shadow32.py's record of the reference.
#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cwchar>
#include <mutex>

#include "RefImage.hpp"

extern "C" int gen_trace_on = 0;

namespace {

struct Record {
    uint32_t tid, addr, a[4];
};

FILE* g_file = nullptr;
std::mutex g_lock;
uint64_t g_left = 0;
// <ENV>_TRACE_FROM=<hex address>: nothing recorded until that function is first entered, as
// shadow32.py --from starts the reference's record there
unsigned int g_from = 0;
bool g_started = true;
Record g_buf[4096];
unsigned g_used = 0;

void FlushLocked() {
    if (g_file && g_used) {
        fwrite(g_buf, sizeof(Record), g_used, g_file);
        fflush(g_file);
    }
    g_used = 0;
}

}  // namespace

void RefTraceStart() {
    wchar_t path[MAX_PATH] = {};
    if (RefEnv("TRACE", path, MAX_PATH) == 0) return;
    if (_wfopen_s(&g_file, path, L"wb") != 0 || g_file == nullptr) {
        fprintf(stderr, "%s: cannot write the trace %ls\n", RHIPPER_NAME, path);
        return;
    }
    wchar_t max[24] = {};
    g_left = RefEnv("TRACE_MAX", max, 24) ? _wcstoui64(max, nullptr, 10) : 2000000;
    wchar_t from[24] = {};
    if (RefEnv("TRACE_FROM", from, 24)) {
        g_from = static_cast<unsigned int>(wcstoul(from, nullptr, 16));
        g_started = g_from == 0;
    }
    fprintf(stderr, "%s: tracing to %ls (%llu calls at most%s)\n", RHIPPER_NAME, path, g_left,
            g_started ? "" : ", from the first call of TRACE_FROM's function");
    gen_trace_on = 1;
    // (the buffer written a few times a second too: a port that goes quiet, waiting, and is then
    // killed kept its last calls in memory, and the trace ended 250 calls before a worker thread
    // called the stub it stopped at, 2026-10-25)
    CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
        for (;;) {
            Sleep(250);
            RefTraceFlush();
        }
    }, nullptr, 0, nullptr);
}

void RefTraceFlush() {
    std::lock_guard<std::mutex> hold(g_lock);
    FlushLocked();
}

extern unsigned int g_watchFn;   // RefImage.cpp, <ENV>_WATCH=<function>+<offset>
void RefWatchEnter(unsigned int a0);
void RefWatchStart();

extern "C" void gen_trace_enter(unsigned int addr, unsigned int a0, unsigned int a1, unsigned int a2, unsigned int a3) {
    static bool first = true;
    if (first) {
        first = false;
        RefWatchStart();
    }
    if (addr == g_watchFn && addr) RefWatchEnter(a0);
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
    g_buf[g_used++] = Record{GetCurrentThreadId(), addr, {a0, a1, a2, a3}};
    if (g_used == sizeof g_buf / sizeof g_buf[0]) FlushLocked();
}
