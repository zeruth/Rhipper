// shadow32.py --inproc's tracer: a 32-bit DLL loaded into the reference at its entry, recording every
// function's call in the process itself. An int3 at each function's entry, caught by a vectored
// exception handler: the record written (thread, reference address, four argument words, as
// runtime32/Trace.cpp writes the port's), and the call resumed through a trampoline holding the
// function's first instruction and a jump back past it (or that instruction emulated, where it is a
// relative branch). No debugger round trip and no single step: a call costs one exception in the
// process, where shadow32.py's debugger stopped the whole process for each.
//
// The table (SHADOW_TABLE): a header line `base size`, then a line per function:
//   `addr len kind target cc regs nargs` (hex; kind 0 copy, 1 call rel, 2 jmp rel, 3 jcc, 4 skip;
//   regs `-` or two hex digits per register, reg | width << 4, eax ecx edx ebx esi edi ebp = 0..6,
//   width 0 full, 1 low byte, 2 word)
// SHADOW_OUT the trace file; SHADOW_MAX records at most; SHADOW_PER_FUNCTION calls a function keeps
// its int3 for; SHADOW_FROM (hex): recording from that function's first call on.
#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace {

enum Kind { kCopy = 0, kCall = 1, kJmp = 2, kJcc = 3, kSkip = 4 };

struct Fn {
    uint32_t live;        // the entry, where the image is loaded
    uint32_t ref;         // the entry as the facts name it
    uint8_t len, kind, cc, nregs;
    uint8_t regs[4];
    uint8_t nargs;
    uint8_t orig;         // the first byte the int3 replaced
    uint32_t target;      // a branch's target (live)
    uint8_t* tramp;       // copy: the first instruction, then a jump back
    volatile LONG hits;
};

struct Record {
    uint32_t tid, addr, a[4];
};

std::vector<Fn> g_fn;                  // by live address, ascending
uint32_t g_base = 0, g_size = 0, g_delta = 0, g_refBase = 0;
HANDLE g_out = INVALID_HANDLE_VALUE;
CRITICAL_SECTION g_lock;
Record* g_buf = nullptr;
const unsigned kBuf = 1 << 16;
unsigned g_used = 0;
volatile LONG64 g_left = 0;
LONG g_perFunction = 0x7fffffff;
uint32_t g_from = 0;
volatile LONG g_recording = 1;
// the thread that loaded this DLL: its exit runs the image's thread-detach code, a thread the port
// never has, so it is not recorded
DWORD g_loader = 0;

void FlushLocked() {
    if (g_used && g_out != INVALID_HANDLE_VALUE) {
        DWORD wrote;
        WriteFile(g_out, g_buf, g_used * sizeof(Record), &wrote, nullptr);
    }
    g_used = 0;
}

int Find(uint32_t live) {
    size_t lo = 0, hi = g_fn.size();
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (g_fn[mid].live < live) lo = mid + 1;
        else hi = mid;
    }
    return lo < g_fn.size() && g_fn[lo].live == live ? static_cast<int>(lo) : -1;
}

uint32_t Reg(const CONTEXT* c, uint8_t code) {
    uint32_t v = 0;
    switch (code & 15) {
        case 0: v = c->Eax; break;
        case 1: v = c->Ecx; break;
        case 2: v = c->Edx; break;
        case 3: v = c->Ebx; break;
        case 4: v = c->Esi; break;
        case 5: v = c->Edi; break;
        case 6: v = c->Ebp; break;
    }
    switch (code >> 4) {
        case 1: return v & 0xff;
        case 2: return v & 0xffff;
        default: return v;
    }
}

// a jcc's condition (its low nibble, as the opcode's) on the flags
bool Taken(uint32_t f, uint8_t cc) {
    bool cf = f & 1, pf = f & 4, zf = f & 0x40, sf = f & 0x80, of = f & 0x800;
    bool r;
    switch (cc >> 1) {
        case 0: r = of; break;
        case 1: r = cf; break;
        case 2: r = zf; break;
        case 3: r = cf || zf; break;
        case 4: r = sf; break;
        case 5: r = pf; break;
        case 6: r = sf != of; break;
        default: r = zf || sf != of; break;
    }
    return (cc & 1) ? !r : r;
}

void Write(const Fn& f, const CONTEXT* c) {
    Record r;
    r.tid = GetCurrentThreadId();
    r.addr = f.ref;
    uint32_t vals[4] = {0, 0, 0, 0};
    unsigned n = 0;
    for (; n < f.nregs && n < 4; n++) vals[n] = Reg(c, f.regs[n]);
    // the stack parameters, above the return address (esp + 4 at entry)
    for (unsigned k = 0; n < f.nargs && n < 4; n++, k++) vals[n] = *reinterpret_cast<const uint32_t*>(c->Esp + 4 + 4 * k);
    // (an address inside the image as the reference's own: the loader may have moved it)
    for (unsigned k = 0; k < 4; k++) {
        if (g_delta && vals[k] >= g_base && vals[k] < g_base + g_size) vals[k] -= g_delta;
        r.a[k] = vals[k];
    }
    EnterCriticalSection(&g_lock);
    if (g_left > 0) {
        g_left--;
        g_buf[g_used++] = r;
        if (g_used == kBuf) FlushLocked();
    }
    LeaveCriticalSection(&g_lock);
}

void Disarm(Fn& f) {
    DWORD old;
    uint8_t* p = reinterpret_cast<uint8_t*>(f.live);
    VirtualProtect(p, 1, PAGE_EXECUTE_READWRITE, &old);
    *p = f.orig;
    VirtualProtect(p, 1, old, &old);
    FlushInstructionCache(GetCurrentProcess(), p, 1);
}

LONG CALLBACK OnException(EXCEPTION_POINTERS* ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT) return EXCEPTION_CONTINUE_SEARCH;
    uint32_t at = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(ep->ExceptionRecord->ExceptionAddress));
    int k = Find(at);
    if (k < 0) return EXCEPTION_CONTINUE_SEARCH;
    Fn& f = g_fn[k];
    CONTEXT* c = ep->ContextRecord;
    if (!g_recording && f.ref == g_from) InterlockedExchange(&g_recording, 1);
    if (g_recording && GetCurrentThreadId() != g_loader) {
        LONG n = InterlockedIncrement(&f.hits);
        if (n <= g_perFunction) Write(f, c);
        if (n == g_perFunction) Disarm(f);
    }
    switch (f.kind) {
        case kCall:
            c->Esp -= 4;
            *reinterpret_cast<uint32_t*>(c->Esp) = at + f.len;
            c->Eip = f.target;
            break;
        case kJmp:
            c->Eip = f.target;
            break;
        case kJcc:
            c->Eip = Taken(c->EFlags, f.cc) ? f.target : at + f.len;
            break;
        default:
            c->Eip = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(f.tramp));
            break;
    }
    return EXCEPTION_CONTINUE_EXECUTION;
}

DWORD WINAPI Flusher(LPVOID) {
    for (;;) {
        Sleep(250);
        EnterCriticalSection(&g_lock);
        FlushLocked();
        LeaveCriticalSection(&g_lock);
    }
}

bool Env(const char* name, char* buf, DWORD size) {
    DWORD n = GetEnvironmentVariableA(name, buf, size);
    return n > 0 && n < size;
}

void Start() {
    char path[MAX_PATH], v[64];
    g_loader = GetCurrentThreadId();
    if (!Env("SHADOW_TABLE", path, MAX_PATH)) return;
    FILE* t = nullptr;
    if (fopen_s(&t, path, "r") != 0 || !t) return;
    uint32_t refBase = 0, size = 0;
    if (fscanf_s(t, "%x %x", &refBase, &size) != 2) { fclose(t); return; }
    g_refBase = refBase;
    g_base = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr)));
    g_size = size;
    g_delta = g_base - refBase;
    char regs[16];
    unsigned addr, len, kind, target, cc, nargs;
    while (fscanf_s(t, "%x %x %x %x %x %15s %x", &addr, &len, &kind, &target, &cc, regs, (unsigned)sizeof regs, &nargs) == 7) {
        Fn f = {};
        f.ref = addr;
        f.live = addr + g_delta;
        f.len = static_cast<uint8_t>(len);
        f.kind = static_cast<uint8_t>(kind);
        f.cc = static_cast<uint8_t>(cc);
        f.target = target + g_delta;
        f.nargs = static_cast<uint8_t>(nargs);
        if (regs[0] != '-') {
            for (size_t i = 0; regs[i] && regs[i + 1] && f.nregs < 4; i += 2) {
                char b[3] = {regs[i], regs[i + 1], 0};
                f.regs[f.nregs++] = static_cast<uint8_t>(strtoul(b, nullptr, 16));
            }
        }
        if (f.kind != kSkip) g_fn.push_back(f);
    }
    fclose(t);

    if (!Env("SHADOW_OUT", path, MAX_PATH)) return;
    g_out = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, 0, nullptr);
    if (g_out == INVALID_HANDLE_VALUE) return;
    g_left = Env("SHADOW_MAX", v, sizeof v) ? _strtoi64(v, nullptr, 10) : 100000000;
    if (Env("SHADOW_PER_FUNCTION", v, sizeof v)) g_perFunction = static_cast<LONG>(strtol(v, nullptr, 10));
    if (Env("SHADOW_FROM", v, sizeof v)) {
        g_from = strtoul(v, nullptr, 16);
        g_recording = g_from == 0;
    }
    g_buf = static_cast<Record*>(VirtualAlloc(nullptr, kBuf * sizeof(Record), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    InitializeCriticalSection(&g_lock);

    // the trampolines: each copied first instruction, then `jmp entry + len`
    uint8_t* tramps = static_cast<uint8_t*>(VirtualAlloc(nullptr, g_fn.size() * 24, MEM_COMMIT | MEM_RESERVE,
                                                         PAGE_EXECUTE_READWRITE));
    for (size_t k = 0; k < g_fn.size(); k++) {
        Fn& f = g_fn[k];
        if (f.kind != kCopy) continue;
        uint8_t* p = tramps + k * 24;
        memcpy(p, reinterpret_cast<void*>(f.live), f.len);
        p[f.len] = 0xE9;
        int32_t rel = static_cast<int32_t>((f.live + f.len) - static_cast<uint32_t>(reinterpret_cast<uintptr_t>(p + f.len + 5)));
        memcpy(p + f.len + 1, &rel, 4);
        f.tramp = p;
    }
    AddVectoredExceptionHandler(1, OnException);
    // the int3s, the image's code made writable while they go in
    DWORD old;
    for (Fn& f : g_fn) {
        uint8_t* p = reinterpret_cast<uint8_t*>(f.live);
        VirtualProtect(p, 1, PAGE_EXECUTE_READWRITE, &old);
        f.orig = *p;
        *p = 0xCC;
        VirtualProtect(p, 1, old, &old);
    }
    FlushInstructionCache(GetCurrentProcess(), nullptr, 0);
    CreateThread(nullptr, 0, Flusher, nullptr, 0, nullptr);
}

}  // namespace

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        Start();
    } else if (reason == DLL_PROCESS_DETACH && g_buf) {
        EnterCriticalSection(&g_lock);
        FlushLocked();
        LeaveCriticalSection(&g_lock);
    }
    return TRUE;
}
