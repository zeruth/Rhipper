"""A sampling profiler for a running port: where its threads spend their time, by function.

Every --interval ms each thread of the process is suspended, its instruction pointer read and the
thread resumed; after --samples rounds the addresses are counted per function: the port's own
through its PDB (llvm-symbolizer), a system DLL's as module+offset to its nearest export below.
A thread that spends its samples waiting shows a wait function at the top (NtWaitForSingleObject
and friends): that is its idle time, not work.

    python sample.py --pid <pid> [--samples 300] [--interval 10] [--exe <the port's exe>] [--top 30]
"""
from __future__ import annotations

import argparse
import ctypes
import os
import subprocess
import time
from collections import Counter, defaultdict
from ctypes import wintypes as W

import project

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)
TH32CS_SNAPTHREAD = 0x4
THREAD_ACCESS = 0x0002 | 0x0008 | 0x0040   # suspend/resume, get context, query
PROCESS_ACCESS = 0x0400 | 0x0010            # query information, vm read
CONTEXT_CONTROL = 0x00100001
CONTEXT_SIZE, OFF_FLAGS, OFF_RIP = 0x4D0, 0x30, 0xF8
SYMBOLIZER = r"C:\Program Files\LLVM\bin\llvm-symbolizer.exe"


class THREADENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", W.DWORD), ("cntUsage", W.DWORD), ("th32ThreadID", W.DWORD),
                ("th32OwnerProcessID", W.DWORD), ("tpBasePri", W.LONG), ("tpDeltaPri", W.LONG),
                ("dwFlags", W.DWORD)]


class MODULEINFO(ctypes.Structure):
    _fields_ = [("lpBaseOfDll", ctypes.c_void_p), ("SizeOfImage", W.DWORD), ("EntryPoint", ctypes.c_void_p)]


k32.CreateToolhelp32Snapshot.restype = W.HANDLE
k32.OpenThread.restype = W.HANDLE
k32.OpenThread.argtypes = [W.DWORD, W.BOOL, W.DWORD]
k32.OpenProcess.restype = W.HANDLE
k32.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
k32.SuspendThread.argtypes = [W.HANDLE]
k32.ResumeThread.argtypes = [W.HANDLE]
k32.GetThreadContext.argtypes = [W.HANDLE, ctypes.c_void_p]
k32.CloseHandle.argtypes = [W.HANDLE]
psapi.EnumProcessModulesEx.argtypes = [W.HANDLE, ctypes.POINTER(W.HMODULE), W.DWORD, ctypes.POINTER(W.DWORD), W.DWORD]
psapi.GetModuleInformation.argtypes = [W.HANDLE, W.HMODULE, ctypes.POINTER(MODULEINFO), W.DWORD]
psapi.GetModuleFileNameExW.argtypes = [W.HANDLE, W.HMODULE, W.LPWSTR, W.DWORD]


def threads_of(pid: int) -> list[int]:
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    te = THREADENTRY32()
    te.dwSize = ctypes.sizeof(te)
    out = []
    ok = k32.Thread32First(snap, ctypes.byref(te))
    while ok:
        if te.th32OwnerProcessID == pid:
            out.append(te.th32ThreadID)
        ok = k32.Thread32Next(snap, ctypes.byref(te))
    k32.CloseHandle(snap)
    return out


def modules_of(pid: int) -> list[tuple[int, int, str]]:
    """(base, end, path) of each module loaded in the process."""
    hp = k32.OpenProcess(PROCESS_ACCESS, False, pid)
    arr = (W.HMODULE * 1024)()
    need = W.DWORD()
    psapi.EnumProcessModulesEx(hp, arr, ctypes.sizeof(arr), ctypes.byref(need), 3)
    out = []
    for i in range(need.value // ctypes.sizeof(W.HMODULE)):
        mi = MODULEINFO()
        psapi.GetModuleInformation(hp, arr[i], ctypes.byref(mi), ctypes.sizeof(mi))
        name = ctypes.create_unicode_buffer(520)
        psapi.GetModuleFileNameExW(hp, arr[i], name, 520)
        base = mi.lpBaseOfDll or 0
        out.append((base, base + mi.SizeOfImage, name.value))
    k32.CloseHandle(hp)
    return out


def exports_of(path: str) -> list[tuple[int, str]]:
    import pefile
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
    out = [(s.address, s.name.decode()) for s in getattr(pe, "DIRECTORY_ENTRY_EXPORT", None).symbols
           if s.name] if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") else []
    return sorted(out)


def symbolize(addrs: list[int], pid: int, exe: str) -> dict[int, str]:
    mods = modules_of(pid)
    exe_norm = os.path.normcase(os.path.abspath(exe))
    out: dict[int, str] = {}
    by_mod: dict[str, list[int]] = defaultdict(list)
    where = {}
    for x in addrs:
        m = next((m for m in mods if m[0] <= x < m[1]), None)
        if m is None:
            out[x] = "?"
            continue
        where[x] = m
        by_mod[m[2]].append(x)
    for path, xs in by_mod.items():
        base = next(m[0] for m in mods if m[2] == path)
        name = os.path.basename(path)
        if os.path.normcase(path) == exe_norm:
            text = "\n".join(f"0x{x - base:x}" for x in xs)
            r = subprocess.run([SYMBOLIZER, f"--obj={exe}", "--relative-address", "--demangle", "--functions=linkage",
                                "--no-inlines"], input=text, capture_output=True, text=True)
            lines = [l for l in r.stdout.split("\n")]
            # (two lines per address, function then file:line, a blank line between)
            funcs, i = [], 0
            while i < len(lines) and len(funcs) < len(xs):
                if lines[i].strip():
                    funcs.append(lines[i].strip())
                    i += 2
                else:
                    i += 1
            for x, f in zip(xs, funcs):
                out[x] = f
        else:
            ex = exports_of(path)
            for x in xs:
                rva = x - base
                below = [e for e in ex if e[0] <= rva]
                out[x] = f"{name}!{below[-1][1]}" if below else f"{name}+0x{rva:x}"
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--samples", type=int, default=300)
    ap.add_argument("--interval", type=float, default=10.0, help="ms between rounds")
    ap.add_argument("--exe", default=str(project.path(project.CONFIG["run"]["exe"])))
    ap.add_argument("--top", type=int, default=30)
    a = ap.parse_args()
    raw = ctypes.create_string_buffer(CONTEXT_SIZE + 16)
    ctx = (ctypes.addressof(raw) + 15) & ~15
    handles: dict[int, int] = {}
    hits: dict[int, list[int]] = defaultdict(list)
    for _ in range(a.samples):
        for tid in threads_of(a.pid):
            h = handles.get(tid)
            if h is None:
                h = handles[tid] = k32.OpenThread(THREAD_ACCESS, False, tid)
            if not h or k32.SuspendThread(h) == 0xFFFFFFFF:
                continue
            ctypes.c_uint32.from_address(ctx + OFF_FLAGS).value = CONTEXT_CONTROL
            if k32.GetThreadContext(h, ctypes.c_void_p(ctx)):
                hits[tid].append(ctypes.c_uint64.from_address(ctx + OFF_RIP).value)
            k32.ResumeThread(h)
        time.sleep(a.interval / 1000)
    for h in handles.values():
        if h:
            k32.CloseHandle(h)
    sym = symbolize(sorted({x for v in hits.values() for x in v}), a.pid, a.exe)
    total = Counter()
    for tid, v in sorted(hits.items(), key=lambda kv: -len(kv[1])):
        c = Counter(sym.get(x, "?") for x in v)
        total.update(c)
        print(f"thread {tid}: " + "; ".join(f"{n} {k}" for k, n in c.most_common(3)))
    print(f"\nall threads, top {a.top}:")
    n = sum(total.values())
    for k, c in total.most_common(a.top):
        print(f"  {100 * c / n:5.1f}%  {k}")


if __name__ == "__main__":
    main()
