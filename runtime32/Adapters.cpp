// The import adapters the generic one in src/gen/imports.c cannot be: imports whose structures
// are laid out differently on x86 and x64, and kernel32 functions x64 Windows does not export.
// Each is listed in rhipper.json "import_overrides", so translate32.py leaves it to this file.
//
// An adapter takes the reference's 32-bit arguments (an address, below 2 GB, is its own value)
// and returns its 32-bit result.
#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <corecrt_startup.h>
#include <float.h>

extern "C" uint32_t gen_ref_base;   // RefImage.cpp

namespace {

template <typename T>
T* At(uint32_t address) {
    return reinterpret_cast<T*>(static_cast<uintptr_t>(address));
}

// The reference's CRITICAL_SECTION is 24 bytes (x86); Windows' is 40. The x86 one's first field
// (DebugInfo) holds the port's own, made when the reference initializes it.
CRITICAL_SECTION* HostSection(uint32_t refSection) {
    auto slot = At<volatile uint32_t>(refSection);
    if (*slot == 0) {
        auto cs = static_cast<CRITICAL_SECTION*>(HeapAlloc(GetProcessHeap(), 0, sizeof(CRITICAL_SECTION)));
        InitializeCriticalSection(cs);
        uint32_t mine = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(cs));
        if (InterlockedCompareExchange(reinterpret_cast<volatile LONG*>(slot), static_cast<LONG>(mine), 0) != 0) {
            DeleteCriticalSection(cs);
            HeapFree(GetProcessHeap(), 0, cs);
        }
    }
    return At<CRITICAL_SECTION>(*slot);
}

void InitSection(uint32_t refSection, DWORD spin) {
    memset(At<void>(refSection), 0, 24);
    CRITICAL_SECTION* cs = HostSection(refSection);
    SetCriticalSectionSpinCount(cs, spin);
}

#pragma pack(push, 4)
struct StartupInfo32 {
    uint32_t cb, lpReserved, lpDesktop, lpTitle;
    uint32_t dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
    uint16_t wShowWindow, cbReserved2;
    uint32_t lpReserved2, hStdInput, hStdOutput, hStdError;
};
static_assert(sizeof(StartupInfo32) == 68, "STARTUPINFO, x86");

struct SystemInfo32 {
    uint16_t wProcessorArchitecture, wReserved;
    uint32_t dwPageSize, lpMinimumApplicationAddress, lpMaximumApplicationAddress, dwActiveProcessorMask;
    uint32_t dwNumberOfProcessors, dwProcessorType, dwAllocationGranularity;
    uint16_t wProcessorLevel, wProcessorRevision;
};
static_assert(sizeof(SystemInfo32) == 36, "SYSTEM_INFO, x86");

struct MemoryInfo32 {
    uint32_t BaseAddress, AllocationBase, AllocationProtect, RegionSize, State, Protect, Type;
};
static_assert(sizeof(MemoryInfo32) == 28, "MEMORY_BASIC_INFORMATION, x86");
#pragma pack(pop)

uint32_t Low(const void* p) {
    return static_cast<uint32_t>(reinterpret_cast<uintptr_t>(p));
}

uint32_t Low(HANDLE h) {
    return static_cast<uint32_t>(reinterpret_cast<uintptr_t>(h));
}

// A reference function called by its address: the runtime's jump there reaches its translation
// (or the int3 that logs it), which takes nothing and returns its 32-bit result
int CallRef(uint32_t fn) {
    return reinterpret_cast<int (*)(void)>(static_cast<uintptr_t>(fn))();
}

// A vector of host strings as the reference's: an array of 4-byte pointers (the strings are
// below 2 GB like all the port's memory), made once, NULL-terminated
uint32_t Vector32(char** v) {
    int n = 0;
    while (v && v[n]) n++;
    auto out = static_cast<uint32_t*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (n + 1) * sizeof(uint32_t)));
    for (int k = 0; k < n; k++) out[k] = Low(v[k]);
    return Low(out);
}

// The reference's _onexit_table_t: three 4-byte pointers, first, last, end
struct OnexitTable32 {
    uint32_t first, last, end;
};

template <typename Info>
void StartupInfoTo32(const Info& si, uint32_t out) {
    auto o = At<StartupInfo32>(out);
    memset(o, 0, sizeof *o);
    o->cb = sizeof *o;
    o->lpDesktop = Low(si.lpDesktop);
    o->lpTitle = Low(si.lpTitle);
    o->dwX = si.dwX; o->dwY = si.dwY; o->dwXSize = si.dwXSize; o->dwYSize = si.dwYSize;
    o->dwXCountChars = si.dwXCountChars; o->dwYCountChars = si.dwYCountChars;
    o->dwFillAttribute = si.dwFillAttribute; o->dwFlags = si.dwFlags;
    o->wShowWindow = si.wShowWindow;
    // (cbReserved2/lpReserved2 carry the C runtime's inherited handle table, in x64 layout: none)
    o->hStdInput = Low(si.hStdInput);
    o->hStdOutput = Low(si.hStdOutput);
    o->hStdError = Low(si.hStdError);
}

}  // namespace

extern "C" {

// ---- critical sections ----------------------------------------------------------------------
unsigned int gen_imp_InitializeCriticalSection(uint32_t cs) {
    InitSection(cs, 0);
    return 0;
}
unsigned int gen_imp_InitializeCriticalSectionAndSpinCount(uint32_t cs, uint32_t spin) {
    InitSection(cs, spin);
    return 1;
}
unsigned int gen_imp_InitializeCriticalSectionEx(uint32_t cs, uint32_t spin, uint32_t) {
    InitSection(cs, spin);
    return 1;
}
unsigned int gen_imp_EnterCriticalSection(uint32_t cs) {
    EnterCriticalSection(HostSection(cs));
    return 0;
}
unsigned int gen_imp_LeaveCriticalSection(uint32_t cs) {
    LeaveCriticalSection(HostSection(cs));
    return 0;
}
unsigned int gen_imp_TryEnterCriticalSection(uint32_t cs) {
    return TryEnterCriticalSection(HostSection(cs));
}
unsigned int gen_imp_DeleteCriticalSection(uint32_t cs) {
    uint32_t mine = *At<uint32_t>(cs);
    if (mine) {
        DeleteCriticalSection(At<CRITICAL_SECTION>(mine));
        HeapFree(GetProcessHeap(), 0, At<void>(mine));
        *At<uint32_t>(cs) = 0;
    }
    return 0;
}
unsigned int gen_imp_SetCriticalSectionSpinCount(uint32_t cs, uint32_t spin) {
    return SetCriticalSectionSpinCount(HostSection(cs), spin);
}

// ---- structures laid out for x86 ------------------------------------------------------------
unsigned int gen_imp_GetStartupInfoW(uint32_t out) {
    STARTUPINFOW si = {sizeof si};
    GetStartupInfoW(&si);
    StartupInfoTo32(si, out);
    return 0;
}
unsigned int gen_imp_GetStartupInfoA(uint32_t out) {
    STARTUPINFOA si = {sizeof si};
    GetStartupInfoA(&si);
    StartupInfoTo32(si, out);
    return 0;
}
static void SystemInfoTo32(const SYSTEM_INFO& si, uint32_t out) {
    auto o = At<SystemInfo32>(out);
    o->wProcessorArchitecture = PROCESSOR_ARCHITECTURE_INTEL;   // (what the reference was built for)
    o->wReserved = 0;
    o->dwPageSize = si.dwPageSize;
    o->lpMinimumApplicationAddress = Low(si.lpMinimumApplicationAddress);
    o->lpMaximumApplicationAddress = 0x7ffeffff;                // the 2 GB the port lives in
    o->dwActiveProcessorMask = static_cast<uint32_t>(si.dwActiveProcessorMask);
    o->dwNumberOfProcessors = si.dwNumberOfProcessors;
    o->dwProcessorType = PROCESSOR_INTEL_PENTIUM;
    o->dwAllocationGranularity = si.dwAllocationGranularity;
    o->wProcessorLevel = si.wProcessorLevel;
    o->wProcessorRevision = si.wProcessorRevision;
}
unsigned int gen_imp_GetSystemInfo(uint32_t out) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    SystemInfoTo32(si, out);
    return 0;
}
unsigned int gen_imp_GetNativeSystemInfo(uint32_t out) {
    return gen_imp_GetSystemInfo(out);
}
unsigned int gen_imp_VirtualQuery(uint32_t address, uint32_t out, uint32_t length) {
    if (length < sizeof(MemoryInfo32)) return 0;
    MEMORY_BASIC_INFORMATION m;
    if (!VirtualQuery(At<void>(address), &m, sizeof m)) return 0;
    auto o = At<MemoryInfo32>(out);
    o->BaseAddress = Low(m.BaseAddress);
    o->AllocationBase = Low(m.AllocationBase);
    o->AllocationProtect = m.AllocationProtect;
    o->RegionSize = static_cast<uint32_t>(m.RegionSize);
    o->State = m.State;
    o->Protect = m.Protect;
    o->Type = m.Type;
    return sizeof(MemoryInfo32);
}

// ---- message boxes: what the reference says, on the console too ----------------------------
unsigned int gen_imp_MessageBoxW(uint32_t hwnd, uint32_t text, uint32_t caption, uint32_t type) {
    // (narrow: stderr's first output was narrow, and a wide write to it then printed nothing)
    fprintf(stderr, "%s: MessageBox [%ls] %ls\n", RHIPPER_NAME, caption ? At<wchar_t>(caption) : L"",
            text ? At<wchar_t>(text) : L"");
    fflush(stderr);
    return MessageBoxW(At<HWND__>(hwnd), At<wchar_t>(text), At<wchar_t>(caption), type);
}
unsigned int gen_imp_MessageBoxA(uint32_t hwnd, uint32_t text, uint32_t caption, uint32_t type) {
    fprintf(stderr, "%s: MessageBox [%s] %s\n", RHIPPER_NAME, caption ? At<char>(caption) : "", text ? At<char>(text) : "");
    fflush(stderr);
    return MessageBoxA(At<HWND__>(hwnd), At<char>(text), At<char>(caption), type);
}

// ---- pointer encoding: the reference keeps encoded pointers in 4 bytes ----------------------
// x64's EncodePointer scrambles all 64 bits, and the 4 the reference kept decoded to garbage that
// the C runtime then called (0xcc0a2740, 2026-10-23). The encoding only has to round-trip: none.
unsigned int gen_imp_EncodePointer(uint32_t p) {
    return p;
}
unsigned int gen_imp_DecodePointer(uint32_t p) {
    return p;
}

// ---- kernel32 exports that x64 Windows has only as compiler intrinsics -----------------------
unsigned int gen_imp_InterlockedIncrement(uint32_t p) {
    return static_cast<unsigned int>(InterlockedIncrement(At<volatile LONG>(p)));
}
unsigned int gen_imp_InterlockedDecrement(uint32_t p) {
    return static_cast<unsigned int>(InterlockedDecrement(At<volatile LONG>(p)));
}
unsigned int gen_imp_InterlockedExchange(uint32_t p, uint32_t v) {
    return static_cast<unsigned int>(InterlockedExchange(At<volatile LONG>(p), static_cast<LONG>(v)));
}
unsigned int gen_imp_InterlockedExchangeAdd(uint32_t p, uint32_t v) {
    return static_cast<unsigned int>(InterlockedExchangeAdd(At<volatile LONG>(p), static_cast<LONG>(v)));
}
unsigned int gen_imp_InterlockedCompareExchange(uint32_t p, uint32_t v, uint32_t cmp) {
    return static_cast<unsigned int>(
        InterlockedCompareExchange(At<volatile LONG>(p), static_cast<LONG>(v), static_cast<LONG>(cmp)));
}

// ---- the module: the reference's image, not the port's --------------------------------------
// (GetModuleHandle(NULL) is the image the code reads its own PE headers from: the CRT's
// __scrt_is_managed_app checked the port's x64 headers as PE32)
unsigned int gen_imp_GetModuleHandleW(uint32_t name) {
    return name ? Low(GetModuleHandleW(At<wchar_t>(name))) : gen_ref_base;
}
unsigned int gen_imp_GetModuleHandleA(uint32_t name) {
    return name ? Low(GetModuleHandleA(At<char>(name))) : gen_ref_base;
}

// An x86 SLIST_HEADER is 8 bytes; x64's is 16 and 16-aligned (the CRT's type_info list head)
unsigned int gen_imp_InitializeSListHead(uint32_t head) {
    memset(At<void>(head), 0, 8);
    return 0;
}
// An x86 filter, which Windows would call with x64 EXCEPTION_POINTERS: not installed (a crash is
// the runtime's to report)
unsigned int gen_imp_SetUnhandledExceptionFilter(uint32_t) {
    return 0;
}

// ---- the C runtime (ucrt, vcruntime) of a /MD reference: tables of 4-byte pointers -----------
// _initterm / _initterm_e: the reference's initializer tables, [first, last) of function addresses
unsigned int gen_imp__initterm(uint32_t first, uint32_t last) {
    for (uint32_t p = first; p < last; p += 4) {
        if (uint32_t fn = *At<uint32_t>(p)) CallRef(fn);
    }
    return 0;
}
unsigned int gen_imp__initterm_e(uint32_t first, uint32_t last) {
    for (uint32_t p = first; p < last; p += 4) {
        if (uint32_t fn = *At<uint32_t>(p)) {
            if (int r = CallRef(fn)) return static_cast<unsigned int>(r);
        }
    }
    return 0;
}
// a module's own atexit table (a DLL's; an exe's goes to _crt_atexit), kept in its layout
unsigned int gen_imp__initialize_onexit_table(uint32_t table) {
    if (!table) return static_cast<unsigned int>(-1);
    auto t = At<OnexitTable32>(table);
    if (t->first == 0) t->last = t->end = 0;
    return 0;
}
unsigned int gen_imp__register_onexit_function(uint32_t table, uint32_t fn) {
    if (!table) return static_cast<unsigned int>(-1);
    auto t = At<OnexitTable32>(table);
    if (t->last == t->end) {
        uint32_t n = (t->end - t->first) / 4;
        uint32_t grown = n ? n * 2 : 32;
        void* mem = t->first ? HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, At<void>(t->first), grown * 4)
                             : HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, grown * 4);
        if (!mem) return static_cast<unsigned int>(-1);
        t->first = Low(mem);
        t->last = t->first + n * 4;
        t->end = t->first + grown * 4;
    }
    *At<uint32_t>(t->last) = fn;
    t->last += 4;
    return 0;
}
unsigned int gen_imp__execute_onexit_table(uint32_t table) {
    if (!table) return static_cast<unsigned int>(-1);
    auto t = At<OnexitTable32>(table);
    uint32_t first = t->first, last = t->last;
    t->first = t->last = t->end = 0;
    while (last > first) {
        last -= 4;
        if (uint32_t fn = *At<uint32_t>(last)) CallRef(fn);
    }
    if (first) HeapFree(GetProcessHeap(), 0, At<void>(first));
    return 0;
}
// argc, argv and the environment, as the reference's 4-byte vectors
unsigned int gen_imp___p___argc(void) {
    return Low(__p___argc());
}
unsigned int gen_imp___p___argv(void) {
    static uint32_t argv = Vector32(*__p___argv());
    return Low(&argv);
}
unsigned int gen_imp___p__environ(void) {
    static uint32_t env = Vector32(*__p__environ());
    return Low(&env);
}
unsigned int gen_imp__get_initial_narrow_environment(void) {
    static uint32_t env = Vector32(_get_initial_narrow_environment());
    return env;
}
// x87 precision and infinity control have no x64 counterpart (the translation computes in
// doubles): the x86 CRT's _PC_53 at startup, without them, or the call is an invalid parameter
unsigned int gen_imp__controlfp_s(uint32_t current, uint32_t value, uint32_t mask) {
    unsigned int now = 0;
    errno_t r = _controlfp_s(&now, value, mask & ~(_MCW_PC | _MCW_IC));
    if (current) *At<uint32_t>(current) = now;
    return static_cast<unsigned int>(r);
}
// vcruntime's x86 SEH handler: x64 has none, and the reference's exceptions are the runtime's
unsigned int gen_imp__except_handler4_common(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t) {
    return ExceptionContinueSearch;
}
// an x86 exception filter's EXCEPTION_POINTERS, which x64 ucrt would read as its own
unsigned int gen_imp__seh_filter_exe(uint32_t, uint32_t) {
    return EXCEPTION_CONTINUE_SEARCH;
}

}  // extern "C"
