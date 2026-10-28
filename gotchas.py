r"""The traps that keep costing a port's runs time, in one report: from a run's log (the runtime's
stderr) and the generated C.

    python gotchas.py RUN.LOG          the run's suspects, stubs, refusals, and the gen's risky imports
    python gotchas.py                  the gen's risky imports and suspects only

What it looks for:
- suspect functions that ran: translate32 found each reading a local it never assigns (a register
  the decompiler lost, `this_00`); the run used whatever the host left there. A UI hit test's node
  a code address, a crash on a click (2026-10-28).
- stubs that ran ("not translated"), by their manifest reason: what the run could not do.
- COM: methods the runtime has no proxy for yet, classes it refused.
- imports passed through the generic adapter that take or return what differs between x86 and x64
  (a structure with pointers, handles or SOCKETs in it; a pointer that may sit above 4 GB): each
  needs an adapter of its own. select's fd_set kept a lobby connection's failure from being seen
  (2026-10-28).
"""
from __future__ import annotations

import argparse
import collections
import json
import re

import project

GEN = project.ROOT / "src" / "gen"

# imports whose arguments or result are laid out differently on x64, and why (the generic adapter
# passes 32-bit words through as they are)
RISKY = {
    # winsock
    "select": "fd_set holds SOCKETs, 4 bytes on x86 and 8 on x64",
    "__WSAFDIsSet": "fd_set holds SOCKETs",
    "getaddrinfo": "addrinfo holds pointers (ai_addr, ai_canonname, ai_next)",
    "freeaddrinfo": "addrinfo holds pointers",
    "gethostbyname": "returns a hostent of pointers, above 4 GB",
    "gethostbyaddr": "returns a hostent of pointers, above 4 GB",
    "inet_ntoa": "returns a pointer to winsock's buffer, above 4 GB",
    "WSASend": "WSABUF holds a pointer", "WSARecv": "WSABUF holds a pointer",
    "WSASendTo": "WSABUF holds a pointer", "WSARecvFrom": "WSABUF holds a pointer",
    "WSAIoctl": "its in and out buffers' contents differ by ioctl (pointers in some)",
    # messages and windows
    "GetMessageA": "MSG holds a HWND, WPARAM and LPARAM, 8 bytes each on x64",
    "GetMessageW": "MSG holds a HWND, WPARAM and LPARAM",
    "PeekMessageA": "MSG", "PeekMessageW": "MSG", "DispatchMessageA": "MSG", "DispatchMessageW": "MSG",
    "TranslateMessage": "MSG", "TranslateAcceleratorA": "MSG", "TranslateAcceleratorW": "MSG",
    "IsDialogMessageA": "MSG", "IsDialogMessageW": "MSG",
    "SetWindowLongA": "GWL_WNDPROC / GWL_USERDATA hold pointers", "SetWindowLongW": "GWL_WNDPROC",
    "GetWindowLongA": "GWL_WNDPROC", "GetWindowLongW": "GWL_WNDPROC",
    "SetClassLongA": "GCL_WNDPROC", "SetClassLongW": "GCL_WNDPROC",
    "CallWindowProcA": "a window procedure's address", "CallWindowProcW": "a window procedure's address",
    "SendMessageA": "LPARAM pointers to structures in some messages", "SendMessageW": "LPARAM",
    "GetOpenFileNameA": "OPENFILENAME holds pointers", "GetOpenFileNameW": "OPENFILENAME",
    "GetSaveFileNameA": "OPENFILENAME", "GetSaveFileNameW": "OPENFILENAME",
    "ShellExecuteExA": "SHELLEXECUTEINFO holds pointers and handles", "ShellExecuteExW": "SHELLEXECUTEINFO",
    "SHBrowseForFolderA": "BROWSEINFO holds pointers", "SHBrowseForFolderW": "BROWSEINFO",
    # processes, memory, files
    "CreateProcessA": "STARTUPINFO and PROCESS_INFORMATION hold pointers and handles",
    "CreateProcessW": "STARTUPINFO and PROCESS_INFORMATION",
    "GetStartupInfoA": "STARTUPINFO", "GetStartupInfoW": "STARTUPINFO",
    "GetSystemInfo": "SYSTEM_INFO holds pointers and a DWORD_PTR", "GetNativeSystemInfo": "SYSTEM_INFO",
    "VirtualQuery": "MEMORY_BASIC_INFORMATION holds pointers and a SIZE_T",
    "VirtualQueryEx": "MEMORY_BASIC_INFORMATION",
    "ReadFile": "OVERLAPPED begins with two ULONG_PTRs", "WriteFile": "OVERLAPPED",
    "ReadFileEx": "OVERLAPPED", "WriteFileEx": "OVERLAPPED", "GetOverlappedResult": "OVERLAPPED",
    "DeviceIoControl": "OVERLAPPED", "ConnectNamedPipe": "OVERLAPPED", "WaitCommEvent": "OVERLAPPED",
    "GetQueuedCompletionStatus": "OVERLAPPED** and a ULONG_PTR key",
    "PostQueuedCompletionStatus": "a ULONG_PTR key and OVERLAPPED*",
    "MapViewOfFile": "returns a view that may sit above 4 GB", "MapViewOfFileEx": "a view above 4 GB",
    "GetProcAddress": "returns an x64 function, above 4 GB",
    "SetUnhandledExceptionFilter": "the filter gets EXCEPTION_POINTERS of x64 records",
    "AddVectoredExceptionHandler": "EXCEPTION_POINTERS of x64 records",
    "InitializeSListHead": "SLIST_HEADER is 16 bytes, 16-aligned on x64",
    "InterlockedPushEntrySList": "SLIST", "InterlockedPopEntrySList": "SLIST",
    "InterlockedFlushSList": "SLIST",
    "CreateThreadpoolWork": "a callback", "QueueUserWorkItem": "a callback",
    "CreateTimerQueueTimer": "a callback", "timeSetEvent": "a callback",
    "RegisterWaitForSingleObject": "a callback",
    "GetModuleInformation": "MODULEINFO holds pointers",
    "EnumProcessModules": "HMODULEs, 8 bytes each",
    "CoTaskMemAlloc": "returns memory that may sit above 4 GB",
    "SysAllocString": "returns memory that may sit above 4 GB",
}


def generic_imports() -> set[str]:
    """the imports imports.c passes through the generic adapter (not the runtime's own)"""
    p = GEN / "imports.c"
    if not p.exists():
        return set()
    text = p.read_text(encoding="utf-8", errors="replace")
    return set(re.findall(r'^unsigned int gen_imp_(\w+)\(int a0, int a1, int a2, int a3, \.\.\.\)', text, re.M))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("log", nargs="?")
    a = ap.parse_args()
    manifest = json.loads((GEN / "manifest.json").read_text()) if (GEN / "manifest.json").exists() else {}
    stubs = manifest.get("stubs", {})
    suspect = manifest.get("suspect", {})
    problems = 0
    if a.log:
        text = open(a.log, encoding="utf-8", errors="replace").read()
        ran = sorted(set(re.findall(r"suspect ([0-9a-f]{8}) ran, reading ([^\n]*?) uninitialized", text)))
        # (a lost register, `this_00` or a `pVar`, is a miscompile; a stack slot, `local_8`, is often
        # the reference's own: MSVC copying a structure whose last word nothing set, the same
        # garbage in both runs. The x86 says which: a write to the slot there or none)
        stack = re.compile(r"^(?:local|[a-zA-Z]{0,5}Stack[XY]?)_[0-9a-f]+$")
        lost = [(a2, n) for a2, n in ran if any(not stack.match(x.strip()) for x in n.split(","))]
        slots = [(a2, n) for a2, n in ran if (a2, n) not in lost]
        print(f"suspect functions that ran, a register lost: {len(lost)}")
        for addr, names in lost:
            print(f"  {addr}  reads {names} uninitialized")
        print(f"suspect functions that ran, a stack slot never written (check the x86 writes it): {len(slots)}")
        for addr, names in slots:
            print(f"  {addr}  reads {names} uninitialized")
        problems += len(lost)
        st = collections.OrderedDict((s, None) for s in re.findall(r"not translated: ([0-9a-f]{8})", text))
        print(f"stubs that ran: {len(st)}")
        for s in st:
            print(f"  {s}  {stubs.get(s, '?')}")
        problems += len(st)
        com = sorted(set(re.findall(r"COM: ([^\n]*?)(?: is not given to the reference yet| refused \(no proxies\))", text)))
        print(f"COM the runtime refused: {len(com)}")
        for c in com:
            print(f"  {c}")
        faults = re.findall(r"exception (\w+) at \w+[^\n]*\n\s*0\s+\w+\s+(\S+)", text)
        if faults:
            print(f"faults: {len(faults)}")
            for code, where in faults[:5]:
                print(f"  {code} at {where}")
            problems += len(faults)
    risky = sorted(n for n in generic_imports() if n in RISKY)
    print(f"imports through the generic adapter that differ on x64: {len(risky)}")
    for n in risky:
        print(f"  {n}: {RISKY[n]}")
    problems += len(risky)
    print(f"functions marked suspect in the gen: {len(suspect)} (uninit.py lists them)")
    print(f"{problems} things to look at")


if __name__ == "__main__":
    main()
