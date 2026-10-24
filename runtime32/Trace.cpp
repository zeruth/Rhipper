// The shadow trace: the port's side of shadow32.py. With <ENV>_TRACE=<file> set, every translated
// function's entry (GEN_ENTER, Ghidra32.h) is recorded: the thread, the reference address, the
// first four arguments, 24 bytes each, up to <ENV>_TRACE_MAX records (2,000,000 by default).
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
    fprintf(stderr, "%s: tracing to %ls (%llu calls at most)\n", RHIPPER_NAME, path, g_left);
    gen_trace_on = 1;
}

void RefTraceFlush() {
    std::lock_guard<std::mutex> hold(g_lock);
    FlushLocked();
}

extern "C" void gen_trace_enter(unsigned int addr, unsigned int a0, unsigned int a1, unsigned int a2, unsigned int a3) {
    std::lock_guard<std::mutex> hold(g_lock);
    if (g_left == 0) {
        gen_trace_on = 0;
        FlushLocked();
        return;
    }
    g_left--;
    g_buf[g_used++] = Record{GetCurrentThreadId(), addr, {a0, a1, a2, a3}};
    if (g_used == sizeof g_buf / sizeof g_buf[0]) FlushLocked();
}
