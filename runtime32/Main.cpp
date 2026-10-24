// The port's entry: a 32-bit reference program run as x64, its code translated from the
// reference's decompilation (translate32.py).
//
// The memory model (Ghidra32.h): the port is linked /LARGEADDRESSAWARE:NO at a fixed base above
// the reference's image (no ASLR), so Windows keeps everything of the process below 2 GB, and the
// reference's 4-byte slots hold any address it is handed. The reference's image goes at its own
// addresses. The loader would put kernel32 and the first heaps there, so the port starts itself
// again, suspended, reserves that range in the new process before any DLL loads, and lets it run:
// the second process is the program.
#include <windows.h>

#include <cstdio>

#include "RefImage.hpp"

namespace {

// The first process: start the second suspended, keep the reference's range free in it.
int Launch() {
    RefLayout layout;
    if (!RefReadLayout(RefImagePath(), &layout)) {
        fprintf(stderr, "%s: cannot read %ls\n", RHIPPER_NAME, RefImagePath());
        return 1;
    }
    wchar_t self[MAX_PATH];
    GetModuleFileNameW(nullptr, self, MAX_PATH);
    RefSetEnv("CHILD", L"1");
    STARTUPINFOW si = {sizeof si};
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(self, GetCommandLineW(), nullptr, nullptr, TRUE, CREATE_SUSPENDED, nullptr, nullptr,
                        &si, &pi)) {
        fprintf(stderr, "%s: CreateProcess failed (%lu)\n", RHIPPER_NAME, GetLastError());
        return 1;
    }
    void* at = VirtualAllocEx(pi.hProcess, reinterpret_cast<void*>(static_cast<uintptr_t>(layout.base)),
                              layout.size, MEM_RESERVE, PAGE_NOACCESS);
    if (at == nullptr) {
        MEMORY_BASIC_INFORMATION mbi = {};
        VirtualQueryEx(pi.hProcess, reinterpret_cast<void*>(static_cast<uintptr_t>(layout.base)), &mbi, sizeof mbi);
        fprintf(stderr, "%s: the reference's range 0x%x..0x%x is taken in the new process (%p, state %lx)\n",
                RHIPPER_NAME, layout.base, layout.base + layout.size, mbi.AllocationBase, mbi.State);
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    ResumeThread(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return static_cast<int>(code);
}

}  // namespace

int main() {
    wchar_t flag[4] = {};
    if (RefEnv("CHILD", flag, 4) == 0) {
        return Launch();
    }
    RefSetEnv("CHILD", nullptr);   // (not inherited by what the program starts)
    if (!RefMapImage(RefImagePath())) {
        return 1;
    }
    return RefRun();
}
