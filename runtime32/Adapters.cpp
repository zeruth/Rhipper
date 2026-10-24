// The import adapters the generic one in src/gen/imports.c cannot be: imports whose structures
// are laid out differently on x86 and x64, and kernel32 functions x64 Windows does not export.
// Each is listed in rhipper.json "import_overrides", so translate32.py leaves it to this file.
//
// An adapter takes the reference's 32-bit arguments (an address, below 2 GB, is its own value)
// and returns its 32-bit result.
#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>

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

}  // extern "C"
