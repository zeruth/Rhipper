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

void RefPrintStack(HANDLE thread, CONTEXT c);   // RefImage.cpp

// (Ghidra32.h's GEN_SUSPECT: a function reading a local it never assigns, on its first call; a
// count of them at the end, gotchas.py's)
extern "C" void gen_suspect(unsigned int addr, const char* names) {
    static volatile long n = 0;
    long k = InterlockedIncrement(&n);
    fprintf(stderr, "%s: suspect %08x ran, reading %s uninitialized (%ld so far)\n", RHIPPER_NAME, addr, names, k);
    fflush(stderr);
}

extern "C" void gen_trace_enter(unsigned int addr, unsigned int a0, unsigned int a1, unsigned int a2, unsigned int a3) {
    static bool first = true;
    // <ENV>_STACKAT=<hex address>: the stack at that function's first entry, its callers (a
    // function reached only through a pointer has no caller the trace names)
    static unsigned int stack_at = 0;
    // <ENV>_DUMPAT=<hex address>[,<calls>[,<bytes>]]: at each of that function's first calls (8),
    // its arguments and the object its first points to (0x40 bytes): the state of the third of
    // three objects a chain of calls reads, which a write watch armed at the first call cannot
    // reach (a sound filter's DynamicValue, 2026-10-28)
    static unsigned int dump_at = 0, dump_left = 0, dump_bytes = 0x40;
    static int dump_from = 0;                  // (,<start>: from a0 + start, a signed hex offset)
    static int dump_arg = 0;                   // (,<arg>: which argument points to it, 0-3)
    // (,<deref>...: hex offsets followed first, the object at *(arg + d1), then *(that + d2): a
    // renderer's this+4 object's +4 field, null in one run and stale in the next, 2026-10-28)
    static int dump_deref[4] = {};
    static int dump_nderef = 0;
    if (first) {
        first = false;
        RefWatchStart();
        wchar_t at[24] = {};
        if (RefEnv("STACKAT", at, 24)) stack_at = static_cast<unsigned int>(wcstoul(at, nullptr, 16));
        wchar_t d[48] = {};
        if (RefEnv("DUMPAT", d, 48)) {
            wchar_t* end = nullptr;
            dump_at = static_cast<unsigned int>(wcstoul(d, &end, 16));
            dump_left = 8;
            if (end && *end == L',') dump_left = static_cast<unsigned int>(wcstoul(end + 1, &end, 10));
            if (end && *end == L',') dump_bytes = static_cast<unsigned int>(wcstoul(end + 1, &end, 16));
            if (end && *end == L',') dump_from = static_cast<int>(wcstol(end + 1, &end, 16));
            if (end && *end == L',') dump_arg = static_cast<int>(wcstol(end + 1, &end, 10)) & 3;
            while (end && *end == L',' && dump_nderef < 4)
                dump_deref[dump_nderef++] = static_cast<int>(wcstol(end + 1, &end, 16));
        }
    }
    // (<ENV>_DUMPAT_IF=0: only the calls whose pointer chain ends at 0 or in memory nothing has, each
    // with its stack, the trace's own limit no matter: the one call of thousands that writes through
    // a field another run held garbage in)
    static int dump_if = -1;
    if (dump_if == -1) {
        wchar_t v[8] = {};
        dump_if = RefEnv("DUMPAT_IF", v, 8) && v[0] == L'0' ? 1 : 0;
    }
    if (dump_left && addr == dump_at) {
        MEMORY_BASIC_INFORMATION mbi;
        unsigned int base = dump_arg == 1 ? a1 : dump_arg == 2 ? a2 : dump_arg == 3 ? a3 : a0;
        unsigned int chain[4] = {};
        for (int k = 0; k < dump_nderef && base; k++) {
            auto at = reinterpret_cast<const unsigned int*>(static_cast<uintptr_t>(base) + dump_deref[k]);
            base = VirtualQuery(at, &mbi, sizeof mbi) && mbi.State == MEM_COMMIT ? *at : 0;
            chain[k] = base;
        }
        auto q = reinterpret_cast<const void*>(static_cast<uintptr_t>(base));
        const bool bad = !base || !VirtualQuery(q, &mbi, sizeof mbi) || mbi.State != MEM_COMMIT;
        if (dump_if && !bad) goto dumped;
        dump_left--;
        fprintf(stderr, "%s: DUMPAT %x(%x, %x, %x, %x) on thread %lu:\n", RHIPPER_NAME, addr, a0, a1, a2, a3,
                GetCurrentThreadId());
        for (int k = 0; k < dump_nderef; k++) fprintf(stderr, "  *(+%x) = %x\n", dump_deref[k], chain[k]);
        if (dump_if) {
            CONTEXT c = {};
            RtlCaptureContext(&c);
            RefPrintStack(GetCurrentThread(), c);
            // (and the object the chain starts at, not the bad place it ends: the node whose
            // parent pointer is garbage)
            base = dump_arg == 1 ? a1 : dump_arg == 2 ? a2 : dump_arg == 3 ? a3 : a0;
        }
        auto p = reinterpret_cast<const unsigned char*>(static_cast<uintptr_t>(base) + dump_from);
        if (base && VirtualQuery(p, &mbi, sizeof mbi) && mbi.State == MEM_COMMIT) {
            for (unsigned int k = 0; k < dump_bytes; k += 16) {
                int o = dump_from + static_cast<int>(k);
                fprintf(stderr, "  %c%03x ", o < 0 ? '-' : '+', o < 0 ? -o : o);
                for (unsigned int j = 0; j < 16; j += 4)
                    fprintf(stderr, " %08x", *reinterpret_cast<const unsigned int*>(p + k + j));
                fprintf(stderr, "\n");
            }
        }
        fflush(stderr);
    }
dumped:
    if (stack_at && addr == stack_at) {
        stack_at = 0;
        fprintf(stderr, "%s: STACKAT %x(%x, %x, %x, %x) on thread %lu:\n", RHIPPER_NAME, addr, a0, a1, a2, a3,
                GetCurrentThreadId());
        CONTEXT c = {};
        RtlCaptureContext(&c);
        RefPrintStack(GetCurrentThread(), c);
        fflush(stderr);
    }
    if (addr == g_watchFn && addr) RefWatchEnter(a0);
    std::lock_guard<std::mutex> hold(g_lock);
    if (!g_started) {
        if (addr != g_from) return;
        g_started = true;
    }
    if (g_left == 0) {
        // (the trace's file full: the entry hooks stay on for DUMPAT and STACKAT, which want them)
        if (!dump_left && !stack_at && !g_watchFn) gen_trace_on = 0;
        FlushLocked();
        return;
    }
    g_left--;
    g_buf[g_used++] = Record{GetCurrentThreadId(), addr, {a0, a1, a2, a3}};
    if (g_used == sizeof g_buf / sizeof g_buf[0]) FlushLocked();
}
