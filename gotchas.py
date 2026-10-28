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
- faults: what the address's shape says (null + a field, a round float's bits, a reference address
  carried into bit 32, a debug fill), and the gen's lines the top frames are at (llvm-symbolizer
  on the build's exe): three crashes on a client's sound path, each read off by hand, 2026-10-28.
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


def fault_hint(v: int) -> str:
    """what an access violation's address most often means in a port, by its shape"""
    lo = v & 0xFFFFFFFF
    if v >> 32 and 0x400000 <= lo < 0x4000000:
        # (a client's sound table read at 0x1_0134f86c, `&DAT + u * -4`, 2026-10-28)
        return ("a reference address with a carry into bit 32: a 32-bit sum done in 64 bits (an unsigned"
                " term scaled by a negative constant, a negative index as uint, added to a pointer)")
    if v >> 32:
        return "above 4 GB: a host pointer truncated or a 32-bit word read as a pointer's half"
    if v < 0x10000:
        return f"a field of a null pointer, +0x{v:x}: an object never set, or an argument one word off"
    if lo in (0xCCCCCCCC, 0xCDCDCDCD, 0xDDDDDDDD, 0xFEEEFEEE, 0xBAADF00D) or lo >> 16 in (0xCCCC, 0xCDCD):
        return "a debug fill pattern: an uninitialized local or freed memory"
    # (a round float's bits, 1.0f = 0x3f800000, plus a small field offset: a float argument where
    # a pointer was read, the words one off; a DynamicValue's set took 1.0f for `this`, 2026-10-28)
    if 0x70 <= (lo >> 23 & 0xFF) <= 0x90 and lo & 0x7FFFF < 0x400:
        f = re.sub(r"0+$", "", f"{lo & 0xFFFFFC00:08x}")
        return (f"a round float's bits (0x{f}..., +0x{lo & 0x3ff:x}): a float where a pointer was read,"
                " arguments one word off or a lost `this` (unless the heap is there)")
    return ""


def symbolize(addrs: list[str]) -> list[str]:
    """gen file:line and its text for port addresses, through llvm-symbolizer and the build's exe"""
    import shutil
    import subprocess
    from pathlib import Path
    tool = shutil.which("llvm-symbolizer") or next(
        (str(p) for p in [Path(r"C:\Program Files\LLVM\bin\llvm-symbolizer.exe")] if p.exists()), None)
    b = project.CONFIG.get("build", {})
    exes = sorted((project.ROOT / b.get("dir", "build/cmake") / "bin" / b.get("config", "Release")).glob("*.exe"),
                  key=lambda p: p.stat().st_mtime)
    if not tool or not exes or not addrs:
        return []
    r = subprocess.run([tool, f"--obj={exes[-1]}", *addrs], capture_output=True, text=True)
    out = []
    for block in r.stdout.strip().split("\n\n"):
        ls = block.strip().split("\n")
        if len(ls) < 2:
            continue
        m = re.match(r"(.*):(\d+):\d+$", ls[1])
        text = ""
        if m and Path(m.group(1)).exists():
            src = Path(m.group(1)).read_text(encoding="utf-8", errors="replace").split("\n")
            n = int(m.group(2))
            text = src[n - 1].strip()[:160] if 0 < n <= len(src) else ""
        where = f"{Path(m.group(1)).name}:{m.group(2)}" if m else ls[1]
        out.append(f"{ls[0]} {where}  {text}")
    return out


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
        faults = re.findall(r"exception (\w+) at \w+(?: \((reading|writing|executing) (\w+)\))?[^\n]*\n"
                            r"((?:\s*\d+\s+[0-9a-f]{8,16}\s+\S+\n?){1,4})", text)
        if faults:
            print(f"faults: {len(faults)}")
            for code, how, at, frames in faults[:5]:
                fr = re.findall(r"\d+\s+([0-9a-f]{8,16})\s+(\S+)", frames)
                print(f"  {code} at {fr[0][1] if fr else '?'}" + (f", {how} {at}" if how else ""))
                # (what the address's shape says, and the gen's lines the top frames are at)
                if at and fault_hint(int(at, 16)):
                    print(f"    {fault_hint(int(at, 16))}")
                for line in symbolize(["0x" + x for x, _n in fr[:3]]):
                    print(f"    {line}")
            problems += len(faults)
    # (the ones a project has looked at and found harmless as used, rhipper.json "gotchas_reviewed":
    # {name: why}, shown apart so the rest stand out)
    reviewed = project.CONFIG.get("gotchas_reviewed", {})
    risky = sorted(n for n in generic_imports() if n in RISKY and n not in reviewed)
    print(f"imports through the generic adapter that differ on x64: {len(risky)}")
    for n in risky:
        print(f"  {n}: {RISKY[n]}")
    problems += len(risky)
    seen = sorted(n for n in generic_imports() if n in reviewed)
    if seen:
        print(f"  (and {len(seen)} reviewed as harmless here: {', '.join(seen)})")
    print(f"functions marked suspect in the gen: {len(suspect)} (uninit.py lists them)")
    print(f"{problems} things to look at")


if __name__ == "__main__":
    main()
