#include "RefImage.hpp"

#include <windows.h>
#include <dbghelp.h>
#include <tlhelp32.h>

#include <algorithm>
#include <csetjmp>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// The generated tables (src/gen/jumps.c, imports.c).
extern "C" {
struct GEN_JUMP {
    unsigned int ref;
    void* port;
};
extern const GEN_JUMP g_genJumps[];
extern const unsigned int g_genJumpCount;
// the code section's data the translation reads (jumps.c): [lo, hi) pairs, 0-ended
extern const unsigned int g_genTextData[];

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

unsigned int gen_tls_array(void);
// the reference's image base, once mapped (Adapters.cpp's GetModuleHandle(NULL), the PEB's)
uint32_t gen_ref_base = 0x400000;
// MXCSR as the reference reads and writes it (Ghidra32.h): its default
__declspec(thread) unsigned int gen_MXCSR = 0x1f80;
void GenUnimplemented(unsigned int address);
// a fault in translated code sent to the reference's SEH (Adapters.cpp)
int gen_seh_hardware(EXCEPTION_POINTERS* ep);
}

namespace {

uint32_t g_textLo, g_textHi;   // the reference's .text
uint32_t g_entry;
// the reference's TLS template: [start, end) of its initialized data, then zero fill
uint32_t g_tlsStart, g_tlsEnd, g_tlsZero;

// The reference's PE headers, read from the file.
struct Headers {
    IMAGE_NT_HEADERS32 nt;
    std::vector<IMAGE_SECTION_HEADER> sections;
};

bool ReadHeaders(const std::vector<uint8_t>& file, Headers* h) {
    if (file.size() < sizeof(IMAGE_DOS_HEADER)) return false;
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(file.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || file.size() < dos->e_lfanew + sizeof(IMAGE_NT_HEADERS32)) return false;
    memcpy(&h->nt, file.data() + dos->e_lfanew, sizeof h->nt);
    if (h->nt.Signature != IMAGE_NT_SIGNATURE || h->nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) return false;
    auto sec = reinterpret_cast<const IMAGE_SECTION_HEADER*>(file.data() + dos->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) +
                                                             h->nt.FileHeader.SizeOfOptionalHeader);
    h->sections.assign(sec, sec + h->nt.FileHeader.NumberOfSections);
    return true;
}

bool ReadFile(const wchar_t* path, std::vector<uint8_t>* out) {
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size;
    GetFileSizeEx(f, &size);
    out->resize(static_cast<size_t>(size.QuadPart));
    DWORD got = 0;
    BOOL ok = ::ReadFile(f, out->data(), static_cast<DWORD>(out->size()), &got, nullptr);
    CloseHandle(f);
    return ok && got == out->size();
}

void InitSymbols() {
    static bool symbols = false;
    if (!symbols) {
        symbols = true;
        SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
        // (the PDB is beside the executable, not in the working directory, the game's folder)
        char dir[MAX_PATH] = {};
        GetModuleFileNameA(nullptr, dir, MAX_PATH);
        if (char* slash = strrchr(dir, '\\')) *slash = 0;
        SymInitialize(GetCurrentProcess(), dir, TRUE);
    }
}

// a suspended thread's return addresses, by the images' unwind tables alone: no DbgHelp, no heap,
// no stdio, whose locks the thread may hold (the frames' stack memory read while it cannot move)
void UnwindLoop(CONTEXT& c, DWORD64* out, int max, int& n) {
    while (n < max && c.Rip) {
        out[n++] = c.Rip;
        DWORD64 base = 0;
        PRUNTIME_FUNCTION fn = RtlLookupFunctionEntry(c.Rip, &base, nullptr);
        if (!fn) {
            // (a leaf: its return address at rsp)
            c.Rip = *reinterpret_cast<DWORD64*>(c.Rsp);
            c.Rsp += 8;
            continue;
        }
        void* handler = nullptr;
        DWORD64 frame = 0;
        RtlVirtualUnwind(UNW_FLAG_NHANDLER, base, c.Rip, fn, &c, &handler, &frame, nullptr);
    }
}

int UnwindPcs(CONTEXT c, DWORD64* out, int max) {
    int n = 0;
    __try {
        UnwindLoop(c, out, max, n);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // (a stack it could not read further: what it had)
    }
    return n;
}

// return addresses symbolized from the port's PDB
void PrintPcs(const DWORD64* pcs, int n) {
    InitSymbols();
    for (int k = 0; k < n; k++) {
        char buf[sizeof(SYMBOL_INFO) + 256] = {};
        auto sym = reinterpret_cast<SYMBOL_INFO*>(buf);
        sym->SizeOfStruct = sizeof(SYMBOL_INFO);
        sym->MaxNameLen = 255;
        DWORD64 disp = 0;
        const char* name = SymFromAddr(GetCurrentProcess(), pcs[k], &disp, sym) ? sym->Name : "?";
        fprintf(stderr, "  %2d  %016llx  %s+0x%llx\n", k, pcs[k], name, disp);
    }
    fflush(stderr);
}

// A thread's stack from a context, symbolized from the port's PDB (F_<address> names the
// reference function)
void PrintStack(HANDLE thread, CONTEXT c) {
    HANDLE self = GetCurrentProcess();
    InitSymbols();
    STACKFRAME64 f = {};
    f.AddrPC.Offset = c.Rip;
    f.AddrPC.Mode = AddrModeFlat;
    f.AddrFrame.Offset = c.Rbp;
    f.AddrFrame.Mode = AddrModeFlat;
    f.AddrStack.Offset = c.Rsp;
    f.AddrStack.Mode = AddrModeFlat;
    for (int k = 0; k < 64 && StackWalk64(IMAGE_FILE_MACHINE_AMD64, self, thread, &f, &c, nullptr,
                                          SymFunctionTableAccess64, SymGetModuleBase64, nullptr); k++) {
        char buf[sizeof(SYMBOL_INFO) + 256] = {};
        auto sym = reinterpret_cast<SYMBOL_INFO*>(buf);
        sym->SizeOfStruct = sizeof(SYMBOL_INFO);
        sym->MaxNameLen = 255;
        DWORD64 disp = 0;
        const char* name = SymFromAddr(self, f.AddrPC.Offset, &disp, sym) ? sym->Name : "?";
        fprintf(stderr, "  %2d  %016llx  %s+0x%llx\n", k, f.AddrPC.Offset, name, disp);
    }
    fflush(stderr);
}

// <ENV>_WATCH=<hex address>: every write of that 4-byte word, on any thread, its value after and
// the writer's stack (the first 40): who overwrote an object a crash found corrupted. A hardware
// breakpoint, debug register 0, set on each thread of the process as it appears.
// <ENV>_WATCH=<function>+<offset> (hex): the word at the function's first argument plus the offset,
// from its first call on (a heap object's field: its address differs from run to run). Trace.cpp
// arms it, the trace on.
// Up to four words at once (debug registers 0-3), commas between: <address>,<address> or
// <function>+<offset>,<offset> (two inputs of one computation in one run).
// <ENV>_WATCH=<global>:<offset>,<offset>: the words at the object a global of the reference's
// points to, once it points to one (shadow32.py's --watch, the same spec for both runs).
volatile uint64_t g_watch = 0;        // the first watched word: nonzero, the watch is on
volatile uint64_t g_watches[4] = {};
uint64_t g_watchGlobal = 0;
volatile int g_nWatches = 0;
volatile uint64_t g_watchArmed = 0;   // the address every thread's register held after a pass
volatile LONG g_watchHits = 0;
unsigned int g_watchOffsets[4] = {};
}  // namespace
unsigned int g_watchFn = 0;
// (Trace.cpp: the watched function entered, its first argument)
// (Trace.cpp, at the first call traced: an address watched from the start armed on this thread
// before the reference goes on, the watcher's passes slower than its first few thousand calls)
void RefWatchStart() {
    for (int k = 0; k < 5000 && g_watch && g_watchArmed != g_watch; k++) Sleep(1);
    // (and a pass begun after this thread exists)
    g_watchArmed = 0;
    for (int k = 0; k < 5000 && g_watch && g_watchArmed != g_watch; k++) Sleep(1);
}
void RefWatchEnter(unsigned int a0) {
    if (g_watch) return;
    // (<ENV>_WATCH_DEREF=<hex offset>: the offsets from the object a0 + offset points to, not a0's:
    // an image renderer's this+4 object's +4 field, written through null in one run and freed
    // memory in the next, 2026-10-28)
    wchar_t d[16] = {};
    if (RefEnv("WATCH_DEREF", d, 16)) {
        unsigned int off = static_cast<unsigned int>(wcstoul(d, nullptr, 16));
        unsigned int obj = *reinterpret_cast<volatile uint32_t*>(static_cast<uintptr_t>(a0) + off);
        fprintf(stderr, "%s: watch base *(%x + 0x%x) = %x\n", RHIPPER_NAME, a0, off, obj);
        a0 = obj;
    }
    for (int i = 0; i < g_nWatches; i++) {
        g_watches[i] = static_cast<uint64_t>(a0) + g_watchOffsets[i];
        fprintf(stderr, "%s: watch armed at %llx (now %08x)\n", RHIPPER_NAME, g_watches[i],
                *reinterpret_cast<volatile uint32_t*>(g_watches[i]));
    }
    g_watch = g_watches[0];
    fflush(stderr);
    // (the watcher thread arms every thread, this one too, meanwhile: a pass over the system's
    // threads takes longer than the 2,500 calls from here to the corruption it was set to catch)
    for (int k = 0; k < 5000 && g_watchArmed != g_watch; k++) Sleep(1);
    // (the word written back as it is: the first hit shows the watch armed on this thread)
    for (int i = 0; i < g_nWatches; i++) {
        auto w = reinterpret_cast<volatile uint32_t*>(g_watches[i]);
        *w = *w;
    }
}
namespace {

DWORD WINAPI WatchThreads(void*) {
    std::unordered_map<DWORD, uint64_t> armed;   // thread -> the address its register holds
    DWORD self = GetCurrentThreadId(), pid = GetCurrentProcessId();
    for (;;) {
        if (!g_watch && g_watchGlobal) {
            // (the global's object, the first time it holds one)
            uint32_t obj = *reinterpret_cast<volatile uint32_t*>(g_watchGlobal);
            if (obj) {
                for (int i = 0; i < g_nWatches; i++) {
                    g_watches[i] = static_cast<uint64_t>(obj) + g_watchOffsets[i];
                    fprintf(stderr, "%s: watch armed at %llx (now %08x) ([%llx] = %x)\n", RHIPPER_NAME, g_watches[i],
                            *reinterpret_cast<volatile uint32_t*>(g_watches[i]), g_watchGlobal, obj);
                }
                fflush(stderr);
                g_watch = g_watches[0];
            }
        }
        if (!g_watch) {
            Sleep(1);
            continue;
        }
        uint64_t want = g_watch;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        THREADENTRY32 te = {sizeof te};
        for (BOOL ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te)) {
            if (te.th32OwnerProcessID != pid || te.th32ThreadID == self) continue;
            auto it = armed.find(te.th32ThreadID);
            if (it != armed.end() && it->second == g_watch) continue;
            HANDLE t = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
            if (!t) continue;
            SuspendThread(t);
            CONTEXT c = {};
            c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            GetThreadContext(t, &c);
            DWORD64* dr[4] = {&c.Dr0, &c.Dr1, &c.Dr2, &c.Dr3};
            c.Dr7 &= ~0xFFFF00FFull;
            for (int i = 0; i < g_nWatches; i++) {
                *dr[i] = g_watches[i];
                c.Dr7 |= (1ull << (2 * i)) | (1ull << (16 + 4 * i)) | (3ull << (18 + 4 * i));   // Li, on writes, 4 bytes
            }
            SetThreadContext(t, &c);
            ResumeThread(t);
            CloseHandle(t);
            armed[te.th32ThreadID] = want;
        }
        CloseHandle(snap);
        g_watchArmed = want;
        Sleep(1);
    }
}

// A call into the reference's code that no translation took lands on an int3 there: log the
// address once and return 0 to the caller, as GenUnimplemented does for a stub.
LONG CALLBACK OnException(EXCEPTION_POINTERS* info) {
    auto rec = info->ExceptionRecord;
    uint64_t at = reinterpret_cast<uint64_t>(rec->ExceptionAddress);
    if (g_watch && rec->ExceptionCode == EXCEPTION_SINGLE_STEP && (info->ContextRecord->Dr6 & 0xF)) {
        int i = 0;
        while (!(info->ContextRecord->Dr6 & (1ull << i))) i++;
        info->ContextRecord->Dr6 = 0;
        uint64_t at = g_watches[i];
        if (InterlockedIncrement(&g_watchHits) <= 40 * g_nWatches) {
            const CONTEXT* c = info->ContextRecord;
            fprintf(stderr, "%s: watch: thread %lu wrote %08x to %llx (rcx %llx rdx %llx r8 %llx r9 %llx rdi %llx "
                    "rsi %llx)\n", RHIPPER_NAME, GetCurrentThreadId(), *reinterpret_cast<uint32_t*>(at), at,
                    c->Rcx, c->Rdx, c->R8, c->R9, c->Rdi, c->Rsi);
            PrintStack(GetCurrentThread(), *info->ContextRecord);
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (rec->ExceptionCode == EXCEPTION_BREAKPOINT && at >= g_textLo && at < g_textHi) {
        GenUnimplemented(static_cast<unsigned int>(at));
        CONTEXT* c = info->ContextRecord;
        c->Rip = *reinterpret_cast<uint64_t*>(c->Rsp);   // return to the caller
        c->Rsp += 8;
        c->Rax = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    // (a fault in translated code inside a reference __try: its filter's, Adapters.cpp)
    if (gen_seh_hardware(info)) return EXCEPTION_CONTINUE_EXECUTION;
    if (rec->ExceptionCode == EXCEPTION_ACCESS_VIOLATION || rec->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION) {
        fprintf(stderr, "%s: exception %08lx at %p (%s %p)\n", RHIPPER_NAME, rec->ExceptionCode, rec->ExceptionAddress,
                rec->NumberParameters >= 2 ? (rec->ExceptionInformation[0] ? "writing" : "reading") : "",
                rec->NumberParameters >= 2 ? reinterpret_cast<void*>(rec->ExceptionInformation[1]) : nullptr);
        RefTraceFlush();
        PrintStack(GetCurrentThread(), *info->ContextRecord);
        // (which thread, and the words at its stack pointer: where the instruction pointer is no
        // code, a call through a bad pointer, the stack walk has nowhere to start, and the return
        // address into the caller is the first word there)
        {
            const uint64_t* sp = reinterpret_cast<const uint64_t*>(info->ContextRecord->Rsp);
            fprintf(stderr, "%s: thread %lu, rsp %p:", RHIPPER_NAME, GetCurrentThreadId(), static_cast<const void*>(sp));
            for (int k = 0; k < 8; k++) {
                MEMORY_BASIC_INFORMATION mbi;
                if (!VirtualQuery(sp + k, &mbi, sizeof mbi) || mbi.State != MEM_COMMIT) break;
                fprintf(stderr, " %llx", static_cast<unsigned long long>(sp[k]));
            }
            fprintf(stderr, "\n");
        }
        if (g_watch) {
            // (what the watched word and its neighbours hold now: a write the debug register
            // cannot see, the kernel's into a buffer, named by what it wrote)
            fprintf(stderr, "%s: around the watched %llx:\n", RHIPPER_NAME, g_watch);
            auto p = reinterpret_cast<const uint8_t*>((g_watch & ~0xFull) - 0x80);
            for (int row = 0; row < 16; row++, p += 16) {
                char text[17] = {};
                fprintf(stderr, "  %p ", p);
                for (int k = 0; k < 16; k++) {
                    fprintf(stderr, " %02x", p[k]);
                    text[k] = p[k] >= 32 && p[k] < 127 ? static_cast<char>(p[k]) : '.';
                }
                fprintf(stderr, "  %s\n", text);
            }
            fflush(stderr);
        }
    } else if (rec->ExceptionCode != 0x406D1388 && rec->ExceptionCode != 0xE06D7363 &&
               rec->ExceptionCode != 0x40010006 && rec->ExceptionCode != 0x4001000A &&
               rec->ExceptionCode != DBG_CONTROL_C) {
        // (any other exception, once a code: a stack overflow's c00000fd first, the access
        // violation after it with no stack left to report from, a run that ended unexplained)
        static volatile LONG seen[8] = {};
        bool fresh = true;
        for (auto& s : seen) {
            LONG prev = InterlockedCompareExchange(&s, static_cast<LONG>(rec->ExceptionCode), 0);
            if (prev == 0) break;
            if (prev == static_cast<LONG>(rec->ExceptionCode)) {
                fresh = false;
                break;
            }
        }
        if (fresh) {
            fprintf(stderr, "%s: exception %08lx at %p on thread %lu\n", RHIPPER_NAME, rec->ExceptionCode,
                    rec->ExceptionAddress, GetCurrentThreadId());
            if (rec->ExceptionCode != EXCEPTION_STACK_OVERFLOW) PrintStack(GetCurrentThread(), *info->ContextRecord);
            fflush(stderr);
            RefTraceFlush();
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

}  // namespace

// Ghidra32.h's LOCK() / UNLOCK(): the reference's `lock`-prefixed read-modify-writes, atomic among
// the translated threads under one lock (an exclusive section is all the instruction promised)
namespace {
SRWLOCK g_genLock = SRWLOCK_INIT;
}
extern "C" void gen_lock_enter(void) {
    AcquireSRWLockExclusive(&g_genLock);
}
extern "C" void gen_lock_leave(void) {
    ReleaseSRWLockExclusive(&g_genLock);
}

extern "C" void GenUnimplemented(unsigned int address) {
    static std::mutex lock;
    static std::unordered_set<unsigned int> seen;
    std::lock_guard<std::mutex> guard(lock);
    if (seen.insert(address).second) {
        fprintf(stderr, "%s: not translated: %08x\n", RHIPPER_NAME, address);
        // (and who called it: the C runtime's fault reporter, a stub, ended a run in a fail-fast
        // the trace never recorded the way to)
        CONTEXT c = {};
        RtlCaptureContext(&c);
        PrintStack(GetCurrentThread(), c);
        fflush(stderr);
        // (and the trace written up to here: a fail-fast after it ends the process unflushed)
        RefTraceFlush();
    }
}

// This thread's TLS array for the reference (what fs:[0x2c] pointed at on x86): one entry, a
// copy of the image's TLS template made on the thread's first use. Allocated from the process
// heap, below 2 GB like everything else, so the array and the block are 32-bit addresses.
extern "C" unsigned int gen_tls_array(void) {
    static thread_local uint32_t array = 0;
    if (array == 0) {
        const uint32_t data = g_tlsEnd - g_tlsStart;
        auto block = static_cast<uint8_t*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, data + g_tlsZero + 16));
        if (data) memcpy(block, reinterpret_cast<void*>(static_cast<uintptr_t>(g_tlsStart)), data);
        auto slots = static_cast<uint32_t*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 64 * sizeof(uint32_t)));
        slots[0] = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(block));
        array = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(slots));
    }
    return array;
}

// The native jmp_buf standing for the reference's at `ref` (Ghidra32.h GEN_SETJMP): per thread, one
// per buffer address the program uses, as many as it has
extern "C" jmp_buf* gen_jmpbuf(unsigned int ref) {
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

// The reference's x86 TEB and PEB (Ghidra32.h gen_teb32): what its code reads through fs. Per
// thread a zeroed block below 2 GB with the fields 32-bit Windows sets: the SEH chain head (empty),
// the stack's bounds, itself, the process and thread ids, the TLS array, the PEB. The PEB, one per
// process, holds the image base and the process heap.
static thread_local uint8_t* t_teb32 = nullptr;
// (whether this thread has one yet, without making it: an exception handler's question, which
// must not allocate)
extern "C" int gen_teb32_made(void) { return t_teb32 != nullptr; }
extern "C" unsigned int gen_teb32(void) {
    static uint8_t* peb = nullptr;
    uint8_t*& teb = t_teb32;
    if (teb == nullptr) {
        if (peb == nullptr) {
            auto p = static_cast<uint8_t*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x1000));
            *reinterpret_cast<uint32_t*>(p + 0x08) = gen_ref_base;                // ImageBaseAddress
            *reinterpret_cast<uint32_t*>(p + 0x18) =
                static_cast<uint32_t>(reinterpret_cast<uintptr_t>(GetProcessHeap()));  // ProcessHeap
            // (and ProcessParameters, zeroed: the static C runtime's exit reads its Flags, whether
            // the process is a packaged app's, and a null one faulted, rhtest stl /MT)
            *reinterpret_cast<uint32_t*>(p + 0x10) = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(
                HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x400)));
            peb = p;
        }
        auto t = static_cast<uint8_t*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x1000));
        auto w = [t](unsigned off, uint32_t v) { *reinterpret_cast<uint32_t*>(t + off) = v; };
        auto native = reinterpret_cast<uint8_t*>(NtCurrentTeb());
        w(0x00, 0xffffffffu);                                                       // ExceptionList
        w(0x04, static_cast<uint32_t>(*reinterpret_cast<uint64_t*>(native + 0x08)));  // StackBase
        w(0x08, static_cast<uint32_t>(*reinterpret_cast<uint64_t*>(native + 0x10)));  // StackLimit
        w(0x18, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(t)));              // Self
        w(0x20, GetCurrentProcessId());                                             // ClientId
        w(0x24, GetCurrentThreadId());
        w(0x2c, gen_tls_array());                                                   // ThreadLocalStoragePointer
        w(0x30, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(peb)));            // ProcessEnvironmentBlock
        teb = t;
    }
    return static_cast<unsigned int>(reinterpret_cast<uintptr_t>(teb));
}

namespace {
// A function above 4 GB (ntdll's), reached from a 4-byte slot: a `jmp [rip]` to it, below 2 GB
uint32_t LowStub(void* fn) {
    static std::mutex lock;
    static uint8_t* page = nullptr;
    static size_t used = 0;
    std::lock_guard<std::mutex> hold(lock);
    if (page == nullptr || used + 16 > 0x1000) {
        // (the first free 64 KB below 2 GB above the port's image)
        for (uintptr_t at = 0x70000000; at < 0x80000000 && page == nullptr; at += 0x10000) {
            page = static_cast<uint8_t*>(VirtualAlloc(reinterpret_cast<void*>(at), 0x1000,
                                                      MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
        }
        used = 0;
        if (page == nullptr) return 0;
    }
    uint8_t* s = page + used;
    s[0] = 0xff, s[1] = 0x25, s[2] = s[3] = s[4] = s[5] = 0;        // jmp qword ptr [rip + 0]
    memcpy(s + 6, &fn, 8);
    used += 16;
    return static_cast<uint32_t>(reinterpret_cast<uintptr_t>(s));
}
}  // namespace

// (for the runtime's other files: a 64-bit function the reference is handed, Com32.cpp's NVAPI)
uint32_t RefLowStub(void* fn) {
    uintptr_t at = reinterpret_cast<uintptr_t>(fn);
    return at > 0xffffffffu ? LowStub(fn) : static_cast<uint32_t>(at);
}

// a function of a library the runtime bridges, by name (Com32.cpp): 0 for none
uint32_t Com32Proc(uint32_t module, const char* name);

// GetProcAddress: a function the reference resolves at run time goes through the adapter its
// import would (the CRT's __crtMessageBoxW finds MessageBoxW so, and its old pointer-encoding
// path EncodePointer, whose x64 one scrambles all 64 bits), and one above 4 GB through a stub
// below 2 GB. One the reference does not import is called as it is: its arguments are 32 bits.
extern "C" unsigned int gen_imp_GetProcAddress(uint32_t module, uint32_t name) {
    if (name > 0xffff) {
        const char* n = reinterpret_cast<const char*>(static_cast<uintptr_t>(name));
        if (uint32_t bridged = Com32Proc(module, n)) return bridged;
        for (unsigned k = 0; k < g_genImportCount; k++) {
            if (strcmp(g_genImports[k].name, n) == 0) {
                return static_cast<uint32_t>(reinterpret_cast<uintptr_t>(g_genImports[k].adapter));
            }
        }
    }
    FARPROC fn = GetProcAddress(reinterpret_cast<HMODULE>(static_cast<uintptr_t>(module)),
                                reinterpret_cast<LPCSTR>(static_cast<uintptr_t>(name)));
    uintptr_t at = reinterpret_cast<uintptr_t>(fn);
    return at > 0xffffffffu ? LowStub(reinterpret_cast<void*>(fn)) : static_cast<uint32_t>(at);
}

unsigned RefEnv(const char* suffix, wchar_t* buf, unsigned size);

void RefPrintStack(HANDLE thread, CONTEXT c);   // (below: HEAPCHECK's)

// <ENV>_GUARDHEAP=1: the reference's heap blocks (up to 256 KB) each end against a page nothing may
// touch, and a freed one's pages are taken away, so an overrun or a use after free faults at the
// instruction that does it, with its stack, not in a later heap check that fails fast without one
// (STATUS_HEAP_CORRUPTION). For finding them; a block takes a page at least and its own guard page.
namespace {

struct GuardHeap {
    uintptr_t lo = 0, hi = 0, next = 0;
    // (every n-th allocation guarded, <ENV>_GUARDHEAP=n; 1 all of them: too slow for a UI 20 s in,
    // a client's title never drew. Sampled, a run gets there and a fraction of its blocks are
    // watched, the culprit's caught in the run whose sample holds it)
    unsigned every = 1;
    volatile long count = 0;
    std::mutex lock;
    std::unordered_map<uintptr_t, size_t> sizes;
    gen_real_fn alloc = nullptr, free = nullptr, realloc = nullptr, size = nullptr;

    bool Owns(intptr_t p) const { return lo && static_cast<uintptr_t>(p) >= lo && static_cast<uintptr_t>(p) < hi; }
    void* Alloc(size_t n) {
        if (n > 0x40000) return nullptr;
        size_t pages = (std::max<size_t>(n, 1) + 0xfff) / 0x1000;
        std::lock_guard<std::mutex> hold(lock);
        if (next + (pages + 1) * 0x1000 > hi) return nullptr;
        uintptr_t base = next;
        next += (pages + 1) * 0x1000;
        if (!VirtualAlloc(reinterpret_cast<void*>(base), pages * 0x1000, MEM_COMMIT, PAGE_READWRITE)) return nullptr;
        // (16-aligned as the heap's, so up to 15 bytes past the end go unseen)
        uintptr_t p = base + pages * 0x1000 - ((std::max<size_t>(n, 1) + 15) & ~size_t(15));
        sizes[p] = n;
        return reinterpret_cast<void*>(p);
    }
    size_t SizeOf(intptr_t p) {
        std::lock_guard<std::mutex> hold(lock);
        auto it = sizes.find(static_cast<uintptr_t>(p));
        return it == sizes.end() ? size_t(-1) : it->second;
    }
    void Free(intptr_t p) {
        size_t n;
        {
            std::lock_guard<std::mutex> hold(lock);
            auto it = sizes.find(static_cast<uintptr_t>(p));
            if (it == sizes.end()) return;
            n = it->second;
            sizes.erase(it);
        }
        size_t pages = (std::max<size_t>(n, 1) + 0xfff) / 0x1000;
        // (the block's first page: its end is its pages' end)
        uintptr_t base = static_cast<uintptr_t>(p) + ((std::max<size_t>(n, 1) + 15) & ~size_t(15)) - pages * 0x1000;
        VirtualFree(reinterpret_cast<void*>(base), pages * 0x1000, MEM_DECOMMIT);
    }
};
GuardHeap g_guard;

intptr_t GuardHeapAlloc(intptr_t heap, intptr_t flags, intptr_t n, intptr_t a3, intptr_t a4, intptr_t a5, intptr_t a6,
                        intptr_t a7, intptr_t a8, intptr_t a9, intptr_t a10, intptr_t a11, intptr_t a12, intptr_t a13) {
    if (g_guard.every <= 1 || InterlockedIncrement(&g_guard.count) % static_cast<long>(g_guard.every) == 0)
        if (void* p = g_guard.Alloc(static_cast<uint32_t>(n))) return reinterpret_cast<intptr_t>(p);   // (zeroed: fresh pages)
    return g_guard.alloc(heap, flags, n, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13);
}
intptr_t GuardHeapFree(intptr_t heap, intptr_t flags, intptr_t p, intptr_t a3, intptr_t a4, intptr_t a5, intptr_t a6,
                       intptr_t a7, intptr_t a8, intptr_t a9, intptr_t a10, intptr_t a11, intptr_t a12, intptr_t a13) {
    if (g_guard.Owns(p)) {
        g_guard.Free(p);
        return 1;
    }
    return g_guard.free(heap, flags, p, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13);
}
intptr_t GuardHeapSize(intptr_t heap, intptr_t flags, intptr_t p, intptr_t a3, intptr_t a4, intptr_t a5, intptr_t a6,
                       intptr_t a7, intptr_t a8, intptr_t a9, intptr_t a10, intptr_t a11, intptr_t a12, intptr_t a13) {
    if (g_guard.Owns(p)) return static_cast<intptr_t>(g_guard.SizeOf(p));
    return g_guard.size(heap, flags, p, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13);
}
intptr_t GuardHeapReAlloc(intptr_t heap, intptr_t flags, intptr_t p, intptr_t n, intptr_t a4, intptr_t a5, intptr_t a6,
                          intptr_t a7, intptr_t a8, intptr_t a9, intptr_t a10, intptr_t a11, intptr_t a12, intptr_t a13) {
    if (!g_guard.Owns(p)) {
        // (a block of the real heap's grown into a guarded one: its size from the real heap)
        if (static_cast<uint32_t>(n) > 0x40000 || (flags & HEAP_REALLOC_IN_PLACE_ONLY))
            return g_guard.realloc(heap, flags, p, n, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13);
        size_t old = static_cast<size_t>(g_guard.size(heap, 0, p, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));
        void* q = g_guard.Alloc(static_cast<uint32_t>(n));
        if (!q) return g_guard.realloc(heap, flags, p, n, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13);
        memcpy(q, reinterpret_cast<void*>(p), std::min<size_t>(old, static_cast<uint32_t>(n)));
        g_guard.free(heap, 0, p, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        return reinterpret_cast<intptr_t>(q);
    }
    if (flags & HEAP_REALLOC_IN_PLACE_ONLY) return 0;
    size_t old = g_guard.SizeOf(p);
    intptr_t q = GuardHeapAlloc(heap, flags & ~HEAP_ZERO_MEMORY, n, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    if (!q) return 0;
    memcpy(reinterpret_cast<void*>(q), reinterpret_cast<void*>(p), std::min<size_t>(old, static_cast<uint32_t>(n)));
    if ((flags & HEAP_ZERO_MEMORY) && static_cast<uint32_t>(n) > old)
        memset(reinterpret_cast<char*>(q) + old, 0, static_cast<uint32_t>(n) - old);
    g_guard.Free(p);
    return q;
}

void GuardHeapStart() {
    wchar_t on[8] = {};
    if (RefEnv("GUARDHEAP", on, 8) == 0 || on[0] == L'0') return;
    g_guard.every = static_cast<unsigned>(wcstoul(on, nullptr, 10));
    // (the most of the low 2 GB it can have, every block's address a 32-bit one)
    for (size_t want = 0x50000000; want >= 0x8000000 && !g_guard.lo; want /= 2) {
        if (void* r = VirtualAlloc(nullptr, want, MEM_RESERVE, PAGE_NOACCESS)) {
            g_guard.lo = g_guard.next = reinterpret_cast<uintptr_t>(r);
            g_guard.hi = g_guard.lo + want;
        }
    }
    if (!g_guard.lo) return;
    for (unsigned k = 0; k < g_genImportCount; k++) {
        const GEN_IMPORT& im = g_genImports[k];
        if (!im.real || !*im.real) continue;
        struct { const char* name; gen_real_fn* keep; gen_real_fn guard; } hooks[] = {
            {"HeapAlloc", &g_guard.alloc, GuardHeapAlloc}, {"HeapFree", &g_guard.free, GuardHeapFree},
            {"HeapSize", &g_guard.size, GuardHeapSize}, {"HeapReAlloc", &g_guard.realloc, GuardHeapReAlloc}};
        for (auto& h : hooks)
            if (strcmp(im.name, h.name) == 0) {
                *h.keep = *im.real;
                *im.real = h.guard;
            }
    }
    if (!g_guard.alloc || !g_guard.free || !g_guard.size || !g_guard.realloc) {
        fprintf(stderr, "%s: GUARDHEAP: the heap imports are not all the reference's; off\n", RHIPPER_NAME);
        g_guard.lo = g_guard.hi = 0;
        return;
    }
    fprintf(stderr, "%s: guarded heap (every %u allocations) at %llx-%llx\n", RHIPPER_NAME, g_guard.every,
            static_cast<unsigned long long>(g_guard.lo),
            static_cast<unsigned long long>(g_guard.hi));
}

// <ENV>_HEAPCHECK=<n>: every n-th call to the reference's heap imports validates that heap first
// (HeapValidate), and the first that finds it corrupt prints its stack and how many heap calls back
// the last good check was, then ends the run: a corruption narrowed to a window, where the heap's own
// check fails fast much later at whatever free next walks the damage. GUARDHEAP is the precise one,
// too slow for a UI 20 s in (a client's title screen never drew under it, 2026-10-28).
struct HeapCheck {
    unsigned every = 0;
    volatile long calls = 0;
    gen_real_fn alloc = nullptr, free = nullptr, realloc = nullptr;
    void Check(intptr_t heap, const char* what) {
        long n = InterlockedIncrement(&calls);
        if (n % static_cast<long>(every)) return;
        if (HeapValidate(reinterpret_cast<HANDLE>(heap), 0, nullptr)) return;
        fprintf(stderr, "%s: HEAPCHECK: heap %llx corrupt at heap call %ld (%s), last good at %ld:\n", RHIPPER_NAME,
                static_cast<unsigned long long>(heap), n, what, n - static_cast<long>(every));
        CONTEXT c = {};
        RtlCaptureContext(&c);
        ::RefPrintStack(GetCurrentThread(), c);
        fflush(stderr);
        TerminateProcess(GetCurrentProcess(), 0xC0000374);
    }
};
HeapCheck g_heapcheck;

intptr_t CheckHeapAlloc(intptr_t heap, intptr_t flags, intptr_t n, intptr_t a3, intptr_t a4, intptr_t a5, intptr_t a6,
                        intptr_t a7, intptr_t a8, intptr_t a9, intptr_t a10, intptr_t a11, intptr_t a12, intptr_t a13) {
    g_heapcheck.Check(heap, "HeapAlloc");
    return g_heapcheck.alloc(heap, flags, n, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13);
}
intptr_t CheckHeapFree(intptr_t heap, intptr_t flags, intptr_t p, intptr_t a3, intptr_t a4, intptr_t a5, intptr_t a6,
                       intptr_t a7, intptr_t a8, intptr_t a9, intptr_t a10, intptr_t a11, intptr_t a12, intptr_t a13) {
    g_heapcheck.Check(heap, "HeapFree");
    return g_heapcheck.free(heap, flags, p, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13);
}
intptr_t CheckHeapReAlloc(intptr_t heap, intptr_t flags, intptr_t p, intptr_t n, intptr_t a4, intptr_t a5, intptr_t a6,
                          intptr_t a7, intptr_t a8, intptr_t a9, intptr_t a10, intptr_t a11, intptr_t a12, intptr_t a13) {
    g_heapcheck.Check(heap, "HeapReAlloc");
    return g_heapcheck.realloc(heap, flags, p, n, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13);
}

void HeapCheckStart() {
    wchar_t v[16] = {};
    if (RefEnv("HEAPCHECK", v, 16) == 0) return;
    g_heapcheck.every = static_cast<unsigned>(wcstoul(v, nullptr, 10));
    if (!g_heapcheck.every) return;
    for (unsigned k = 0; k < g_genImportCount; k++) {
        const GEN_IMPORT& im = g_genImports[k];
        if (!im.real || !*im.real) continue;
        struct { const char* name; gen_real_fn* keep; gen_real_fn check; } hooks[] = {
            {"HeapAlloc", &g_heapcheck.alloc, CheckHeapAlloc}, {"HeapFree", &g_heapcheck.free, CheckHeapFree},
            {"HeapReAlloc", &g_heapcheck.realloc, CheckHeapReAlloc}};
        for (auto& h : hooks)
            if (strcmp(im.name, h.name) == 0) {
                *h.keep = *im.real;
                *im.real = h.check;
            }
    }
    if (!g_heapcheck.alloc || !g_heapcheck.free || !g_heapcheck.realloc) {
        fprintf(stderr, "%s: HEAPCHECK: the heap imports are not all the reference's; off\n", RHIPPER_NAME);
        g_heapcheck.every = 0;
        return;
    }
    fprintf(stderr, "%s: HEAPCHECK every %u heap calls\n", RHIPPER_NAME, g_heapcheck.every);
}

// <ENV>_FREECHECK=1: each block the reference frees remembered with its freer's stack until the heap
// hands it out again, so a second free of it prints both stacks, the first free the bug: a UI
// teardown's heap check failed (STATUS_HEAP_CORRUPTION) at a free of a block another had freed, the
// fail-fast saying nothing of the other (2026-10-28). The real heap underneath, its layout as is.
struct FreeCheck {
    std::mutex lock;
    struct Freed {
        void* frames[12];
        USHORT n;
        DWORD tid;
    };
    std::unordered_map<intptr_t, Freed> freed;
    gen_real_fn alloc = nullptr, free = nullptr, realloc = nullptr;
    long reported = 0;
};
FreeCheck g_fc;

void FreeCheckPrint(void* const* frames, USHORT n) {
    HANDLE self = GetCurrentProcess();
    InitSymbols();
    for (USHORT k = 0; k < n; k++) {
        char buf[sizeof(SYMBOL_INFO) + 256] = {};
        auto sym = reinterpret_cast<SYMBOL_INFO*>(buf);
        sym->SizeOfStruct = sizeof(SYMBOL_INFO);
        sym->MaxNameLen = 255;
        DWORD64 disp = 0;
        const char* name = SymFromAddr(self, reinterpret_cast<DWORD64>(frames[k]), &disp, sym) ? sym->Name : "?";
        fprintf(stderr, "    %2u  %p  %s+0x%llx\n", k, frames[k], name, disp);
    }
}

intptr_t FreeCheckAlloc(intptr_t heap, intptr_t flags, intptr_t n, intptr_t a3, intptr_t a4, intptr_t a5, intptr_t a6,
                        intptr_t a7, intptr_t a8, intptr_t a9, intptr_t a10, intptr_t a11, intptr_t a12, intptr_t a13) {
    intptr_t p = g_fc.alloc(heap, flags, n, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13);
    if (p) {
        std::lock_guard<std::mutex> hold(g_fc.lock);
        g_fc.freed.erase(p);
    }
    return p;
}
intptr_t FreeCheckFree(intptr_t heap, intptr_t flags, intptr_t p, intptr_t a3, intptr_t a4, intptr_t a5, intptr_t a6,
                       intptr_t a7, intptr_t a8, intptr_t a9, intptr_t a10, intptr_t a11, intptr_t a12, intptr_t a13) {
    if (p) {
        FreeCheck::Freed f = {};
        f.n = RtlCaptureStackBackTrace(1, 12, f.frames, nullptr);
        f.tid = GetCurrentThreadId();
        std::lock_guard<std::mutex> hold(g_fc.lock);
        auto it = g_fc.freed.find(p);
        if (it != g_fc.freed.end()) {
            if (g_fc.reported++ < 8) {
                fprintf(stderr, "%s: FREECHECK: %llx freed again, on thread %lu:\n", RHIPPER_NAME,
                        static_cast<unsigned long long>(p), f.tid);
                FreeCheckPrint(f.frames, f.n);
                fprintf(stderr, "  first freed on thread %lu:\n", it->second.tid);
                FreeCheckPrint(it->second.frames, it->second.n);
                fflush(stderr);
            }
            return 1;   // (the second free left out: the run goes on to the next)
        }
        g_fc.freed[p] = f;
    }
    return g_fc.free(heap, flags, p, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13);
}
intptr_t FreeCheckReAlloc(intptr_t heap, intptr_t flags, intptr_t p, intptr_t n, intptr_t a4, intptr_t a5, intptr_t a6,
                          intptr_t a7, intptr_t a8, intptr_t a9, intptr_t a10, intptr_t a11, intptr_t a12, intptr_t a13) {
    {
        std::lock_guard<std::mutex> hold(g_fc.lock);
        auto it = g_fc.freed.find(p);
        if (it != g_fc.freed.end() && g_fc.reported++ < 8) {
            fprintf(stderr, "%s: FREECHECK: %llx reallocated after its free; first freed on thread %lu:\n",
                    RHIPPER_NAME, static_cast<unsigned long long>(p), it->second.tid);
            FreeCheckPrint(it->second.frames, it->second.n);
            fflush(stderr);
        }
    }
    intptr_t q = g_fc.realloc(heap, flags, p, n, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13);
    if (q) {
        std::lock_guard<std::mutex> hold(g_fc.lock);
        g_fc.freed.erase(q);
    }
    return q;
}

void FreeCheckStart() {
    wchar_t on[8] = {};
    if (RefEnv("FREECHECK", on, 8) == 0 || on[0] == L'0' || g_guard.lo) return;
    for (unsigned k = 0; k < g_genImportCount; k++) {
        const GEN_IMPORT& im = g_genImports[k];
        if (!im.real || !*im.real) continue;
        struct { const char* name; gen_real_fn* keep; gen_real_fn hook; } hooks[] = {
            {"HeapAlloc", &g_fc.alloc, FreeCheckAlloc}, {"HeapFree", &g_fc.free, FreeCheckFree},
            {"HeapReAlloc", &g_fc.realloc, FreeCheckReAlloc}};
        for (auto& h : hooks)
            if (strcmp(im.name, h.name) == 0) {
                *h.keep = *im.real;
                *im.real = h.hook;
            }
    }
    fprintf(stderr, "%s: FREECHECK on (%s)\n", RHIPPER_NAME,
            g_fc.alloc && g_fc.free && g_fc.realloc ? "HeapAlloc, HeapFree, HeapReAlloc" : "not all the heap imports");
}

// <ENV>_DUMPAFTER=<seconds>[,<seconds again>]: every other thread's stack, each suspended while
// it is walked, after that long (and every so often after): where a hung run spins or waits
DWORD WINAPI DumpThreads(void* arg) {
    DWORD first = static_cast<DWORD>(reinterpret_cast<uintptr_t>(arg) & 0xffff) * 1000;
    DWORD again = static_cast<DWORD>(reinterpret_cast<uintptr_t>(arg) >> 16) * 1000;
    Sleep(first);
    for (;;) {
        DWORD me = GetCurrentThreadId(), pid = GetCurrentProcessId();
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        THREADENTRY32 te = {sizeof(te)};
        for (BOOL ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te)) {
            if (te.th32OwnerProcessID != pid || te.th32ThreadID == me) continue;
            HANDLE t = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE,
                                  te.th32ThreadID);
            if (!t) continue;
            // (the stack taken while the thread is suspended, printed once it runs again: it may
            // hold stderr's, the heap's or DbgHelp's lock, ultrareview 2026-10-27)
            if (SuspendThread(t) != DWORD(-1)) {
                CONTEXT c = {};
                c.ContextFlags = CONTEXT_FULL;
                DWORD64 pcs[64];
                int n = GetThreadContext(t, &c) ? UnwindPcs(c, pcs, 64) : -1;
                ResumeThread(t);
                if (n >= 0) {
                    fprintf(stderr, "%s: DUMPAFTER thread %lu\n", RHIPPER_NAME, te.th32ThreadID);
                    PrintPcs(pcs, n);
                }
            }
            CloseHandle(t);
        }
        CloseHandle(snap);
        fflush(stderr);
        if (!again) return 0;
        Sleep(again);
    }
}

void DumpAfterStart() {
    wchar_t v[32] = {};
    if (RefEnv("DUMPAFTER", v, 32) == 0) return;
    wchar_t* end = nullptr;
    uintptr_t first = wcstoul(v, &end, 10), again = (end && *end == L',') ? wcstoul(end + 1, nullptr, 10) : 0;
    CreateThread(nullptr, 0, DumpThreads, reinterpret_cast<void*>((again << 16) | (first & 0xffff)), 0, nullptr);
}

}  // namespace

// (the stack printer for the rest of the runtime: Trace.cpp's <ENV>_STACKAT)
void RefPrintStack(HANDLE thread, CONTEXT c) {
    PrintStack(thread, c);
}

unsigned RefEnv(const char* suffix, wchar_t* buf, unsigned size) {
    wchar_t name[96];
    swprintf_s(name, L"%hs_%hs", RHIPPER_ENV, suffix);
    return GetEnvironmentVariableW(name, buf, size);
}

void RefSetEnv(const char* suffix, const wchar_t* value) {
    wchar_t name[96];
    swprintf_s(name, L"%hs_%hs", RHIPPER_ENV, suffix);
    SetEnvironmentVariableW(name, value);
}

const wchar_t* RefImagePath() {
    // the reference in the working directory (rhipper.json "run": the folder it is installed in),
    // or <ENV>_REF
    static wchar_t path[MAX_PATH] = {};
    if (path[0] == 0 && RefEnv("REF", path, MAX_PATH) == 0) {
        wcscpy_s(path, RHIPPER_REF);
    }
    return path;
}

bool RefReadLayout(const wchar_t* path, RefLayout* out) {
    std::vector<uint8_t> file;
    Headers h;
    if (!ReadFile(path, &file) || !ReadHeaders(file, &h)) return false;
    out->base = h.nt.OptionalHeader.ImageBase;
    out->size = h.nt.OptionalHeader.SizeOfImage;
    return true;
}

bool RefMapImage(const wchar_t* path) {
    std::vector<uint8_t> file;
    Headers h;
    if (!ReadFile(path, &file) || !ReadHeaders(file, &h)) {
        fprintf(stderr, "%s: cannot read the reference %ls\n", RHIPPER_NAME, path);
        return false;
    }
    const uint32_t base = h.nt.OptionalHeader.ImageBase;
    const uint32_t size = h.nt.OptionalHeader.SizeOfImage;
    gen_ref_base = base;
    // (the launcher reserved the range: commit it)
    auto image = static_cast<uint8_t*>(VirtualAlloc(reinterpret_cast<void*>(static_cast<uintptr_t>(base)), size,
                                                    MEM_COMMIT, PAGE_READWRITE));
    if (image == nullptr) {
        fprintf(stderr, "%s: cannot commit the reference's range 0x%x (%lu)\n", RHIPPER_NAME, base, GetLastError());
        return false;
    }
    memcpy(image, file.data(), h.nt.OptionalHeader.SizeOfHeaders);
    for (const auto& s : h.sections) {
        const uint32_t raw = std::min<uint32_t>(s.SizeOfRawData, s.Misc.VirtualSize);
        if (raw) memcpy(image + s.VirtualAddress, file.data() + s.PointerToRawData, raw);
        if (s.Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            g_textLo = base + s.VirtualAddress;
            g_textHi = g_textLo + s.Misc.VirtualSize;
        }
    }
    g_entry = base + h.nt.OptionalHeader.AddressOfEntryPoint;
    // its TLS: one module, so index 0 of each thread's array (gen_tls_array)
    const IMAGE_DATA_DIRECTORY& tlsDir = h.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tlsDir.Size) {
        auto tls = reinterpret_cast<const IMAGE_TLS_DIRECTORY32*>(image + tlsDir.VirtualAddress);
        g_tlsStart = tls->StartAddressOfRawData;
        g_tlsEnd = tls->EndAddressOfRawData;
        g_tlsZero = tls->SizeOfZeroFill;
        if (tls->AddressOfIndex) *reinterpret_cast<uint32_t*>(static_cast<uintptr_t>(tls->AddressOfIndex)) = 0;
    }

    // Its code is never run: int3 over all of it, and at each function's entry a jump to the
    // port's (its translation, or a stub that logs the address). The port is linked below 2 GB, so
    // a 5-byte jmp rel32 reaches it from anywhere in the image.
    memset(image + (g_textLo - base), 0xcc, g_textHi - g_textLo);
    // (but the data between functions the translation reads, as the file has it: a byte switch's
    // index table read 0xcc and matched no case, translate32 text_data)
    unsigned kept = 0;
    for (const unsigned int* d = g_genTextData; d[0]; d += 2) {
        const auto s = std::find_if(h.sections.begin(), h.sections.end(), [&](const IMAGE_SECTION_HEADER& x) {
            return d[0] - base >= x.VirtualAddress && d[1] - base <= x.VirtualAddress + x.SizeOfRawData;
        });
        if (s == h.sections.end()) continue;
        memcpy(image + (d[0] - base), file.data() + s->PointerToRawData + (d[0] - base - s->VirtualAddress), d[1] - d[0]);
        kept += d[1] - d[0];
    }
    if (kept) fprintf(stderr, "%s: %u bytes of the code section's data kept\n", RHIPPER_NAME, kept);
    std::vector<GEN_JUMP> jumps(g_genJumps, g_genJumps + g_genJumpCount);
    std::sort(jumps.begin(), jumps.end(), [](const GEN_JUMP& a, const GEN_JUMP& b) { return a.ref < b.ref; });
    unsigned written = 0, crowded = 0;
    for (size_t k = 0; k < jumps.size(); k++) {
        const uint32_t at = jumps[k].ref;
        if (at < g_textLo || at + 5 > g_textHi) continue;
        if (k + 1 < jumps.size() && jumps[k + 1].ref < at + 5) {
            crowded++;   // (the next entry is closer than a jump: its int3 logs it)
            continue;
        }
        const int64_t rel = reinterpret_cast<int64_t>(jumps[k].port) - (static_cast<int64_t>(at) + 5);
        if (rel < INT32_MIN || rel > INT32_MAX) {
            fprintf(stderr, "%s: %08x -> %p is out of jump range\n", RHIPPER_NAME, at, jumps[k].port);
            continue;
        }
        uint8_t* p = reinterpret_cast<uint8_t*>(static_cast<uintptr_t>(at));
        p[0] = 0xe9;
        int32_t r32 = static_cast<int32_t>(rel);
        memcpy(p + 1, &r32, 4);
        written++;
    }

    // The import slots: each holds the port's adapter (below 2 GB, so it fits), and each
    // adapter's real function is resolved here.
    unsigned resolved = 0, missing = 0;
    for (unsigned k = 0; k < g_genImportCount; k++) {
        const GEN_IMPORT& im = g_genImports[k];
        *reinterpret_cast<uint32_t*>(static_cast<uintptr_t>(im.slot)) =
            static_cast<uint32_t>(reinterpret_cast<uintptr_t>(im.adapter));
        if (im.real == nullptr) {   // (an adapter of the runtime's own, Adapters.cpp)
            resolved++;
            continue;
        }
        HMODULE dll = LoadLibraryA(im.dll);
        FARPROC fn = dll ? GetProcAddress(dll, im.name) : nullptr;
        *im.real = reinterpret_cast<gen_real_fn>(fn);
        if (fn) {
            resolved++;
        } else {
            missing++;
            fprintf(stderr, "%s: import %s!%s has no x64 export (needs an adapter of its own)\n", RHIPPER_NAME, im.dll, im.name);
        }
    }
    GuardHeapStart();
    FreeCheckStart();
    HeapCheckStart();
    DumpAfterStart();

    DWORD old;
    VirtualProtect(image + (g_textLo - base), g_textHi - g_textLo, PAGE_EXECUTE_READ, &old);
    AddVectoredExceptionHandler(1, OnException);
    wchar_t watch[40] = {};
    if (RefEnv("WATCH", watch, 40)) {
        wchar_t* end = nullptr;
        uint64_t v = wcstoull(watch, &end, 16);
        if (end && *end == L':') {
            g_watchGlobal = v;
            for (; end && (*end == L':' || *end == L',') && g_nWatches < 4; g_nWatches++)
                g_watchOffsets[g_nWatches] = static_cast<unsigned int>(wcstoul(end + 1, &end, 16));
            fprintf(stderr, "%s: watching %d words at [%llx] + offsets, once it is set\n", RHIPPER_NAME, g_nWatches, v);
        } else if (end && *end == L'+') {
            g_watchFn = static_cast<unsigned int>(v);
            for (; end && (*end == L'+' || *end == L',') && g_nWatches < 4; g_nWatches++) {
                g_watchOffsets[g_nWatches] = static_cast<unsigned int>(wcstoul(end + 1, &end, 16));
                fprintf(stderr, "%s: watching writes to %x's first argument + 0x%x, from its first call\n",
                        RHIPPER_NAME, g_watchFn, g_watchOffsets[g_nWatches]);
            }
        } else {
            for (g_watches[g_nWatches++] = v; end && *end == L',' && g_nWatches < 4; g_nWatches++)
                g_watches[g_nWatches] = wcstoull(end + 1, &end, 16);
            for (int i = 0; i < g_nWatches; i++)
                fprintf(stderr, "%s: watching writes to %llx\n", RHIPPER_NAME, g_watches[i]);
            g_watch = v;
        }
        CreateThread(nullptr, 0, WatchThreads, nullptr, 0, nullptr);
    }
    fprintf(stderr, "%s: reference mapped at 0x%x (0x%x bytes): %u entry jumps (%u too close to the next), "
            "%u imports resolved, %u missing\n", RHIPPER_NAME, base, size, written, crowded, resolved, missing);
    fflush(stderr);
    return true;
}

namespace {
// <ENV>_HANGDUMP=<seconds>: after that long, the reference thread's stack, symbolized from
// the port's PDB (F_<address> names the reference function) - what it waits on when it hangs
DWORD WINAPI HangDump(void* thread) {
    wchar_t v[16] = {};
    RefEnv("HANGDUMP", v, 16);
    Sleep(static_cast<DWORD>(_wtoi(v)) * 1000);
    HANDLE t = static_cast<HANDLE>(thread);
    SuspendThread(t);
    CONTEXT c = {};
    c.ContextFlags = CONTEXT_FULL;
    GetThreadContext(t, &c);
    fprintf(stderr, "%s: the reference thread after %ls s:\n", RHIPPER_NAME, v);
    PrintStack(t, c);
    ResumeThread(t);
    return 0;
}

DWORD WINAPI RefMain(void*) {
    // the reference's entry point: its CRT startup (WinMainCRTStartup), through the jump at it
    auto entry = reinterpret_cast<int (*)(void)>(static_cast<uintptr_t>(g_entry));
    return static_cast<DWORD>(entry());
}
}  // namespace

int RefRun() {
    // on a thread of its own: translated x64 code uses more stack than the reference's x86 did,
    // and the process's main thread has the default 1 MB (CMakeLists.txt). Made now, after the
    // reference's range is taken, the stack goes elsewhere below 2 GB
    fprintf(stderr, "%s: running the reference's entry 0x%x\n", RHIPPER_NAME, g_entry);
    fflush(stderr);
    RefTraceStart();
    HANDLE t = CreateThread(nullptr, 32u << 20, RefMain, nullptr, STACK_SIZE_PARAM_IS_A_RESERVATION, nullptr);
    if (t == nullptr) {
        fprintf(stderr, "%s: cannot start the reference's thread (%lu)\n", RHIPPER_NAME, GetLastError());
        return 1;
    }
    wchar_t hang[16] = {};
    if (RefEnv("HANGDUMP", hang, 16)) {
        CloseHandle(CreateThread(nullptr, 0, HangDump, t, 0, nullptr));
    }
    WaitForSingleObject(t, INFINITE);
    RefTraceFlush();
    DWORD code = 0;
    GetExitCodeThread(t, &code);
    CloseHandle(t);
    return static_cast<int>(code);
}
