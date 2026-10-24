"""The shadow run: the reference program itself, its function calls recorded the way the port's
shadow trace records them (runtime32/Trace.cpp), so shadow_diff.py can line the two runs up
call for call and point at the first place they part.

A small debugger for the 32-bit reference (it runs under WoW64; this script is 64-bit Python). An
int3 is written at every function's entry (build/facts/functions.json, rebased to where the loader
put the image). At each hit the function's logical arguments are read where its convention keeps
them (protos.json: ecx/edx and the stack words above the return address), a record is written, the
original byte is put back, one instruction is single-stepped, and the int3 is written again. A
function keeps its breakpoint only for its first --per-function hits, so a hot leaf like memcpy
does not take the run; the run ends at --max records, at --until (a reference address), or when the
program exits.

    python shadow32.py --out build/shadow-ref.bin [--max 400000] [--per-function 2000] \
                       [--until 0xc5c6db] [-- args to the program...]

Run it from where the program is installed, with the arguments it is normally started with. Each
record is 24 bytes: tid, reference address, and four argument words, matching the port's
<ENV>_TRACE file exactly.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import struct
import sys
import time
from ctypes import wintypes as W

from pebin import FACTS, Binary
import project

k32 = ctypes.WinDLL("kernel32", use_last_error=True)

DEBUG_ONLY_THIS_PROCESS = 0x00000002
EXCEPTION_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT, CREATE_PROCESS_DEBUG_EVENT = 1, 2, 3
EXIT_THREAD_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT = 4, 5
DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED = 0x00010002, 0x80010001
STATUS_BREAKPOINT, STATUS_SINGLE_STEP = 0x80000003, 0x80000004
STATUS_WX86_BREAKPOINT, STATUS_WX86_SINGLE_STEP = 0x4000001F, 0x4000001E
WOW64_CONTEXT_CONTROL, WOW64_CONTEXT_INTEGER = 0x00010001, 0x00010002
WOW64_CONTEXT_FULL = WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_INTEGER | 0x00010004
TRAP_FLAG = 0x100
PAGE_EXECUTE_READWRITE = 0x40
INFINITE = 0xFFFFFFFF
CC = 0xCC

# the register order a "custom" convention lists its register parameters in (protos32.py REG_NAMES)
CUSTOM_ORDER = ["eax", "ecx", "edx", "ebx", "esi", "edi"]


class WOW64_FLOATING_SAVE_AREA(ctypes.Structure):
    _fields_ = [("ControlWord", W.DWORD), ("StatusWord", W.DWORD), ("TagWord", W.DWORD),
                ("ErrorOffset", W.DWORD), ("ErrorSelector", W.DWORD), ("DataOffset", W.DWORD),
                ("DataSelector", W.DWORD), ("RegisterArea", ctypes.c_byte * 80), ("Cr0NpxState", W.DWORD)]


class WOW64_CONTEXT(ctypes.Structure):
    _fields_ = [("ContextFlags", W.DWORD), ("Dr0", W.DWORD), ("Dr1", W.DWORD), ("Dr2", W.DWORD),
                ("Dr3", W.DWORD), ("Dr6", W.DWORD), ("Dr7", W.DWORD), ("FloatSave", WOW64_FLOATING_SAVE_AREA),
                ("SegGs", W.DWORD), ("SegFs", W.DWORD), ("SegEs", W.DWORD), ("SegDs", W.DWORD),
                ("Edi", W.DWORD), ("Esi", W.DWORD), ("Ebx", W.DWORD), ("Edx", W.DWORD), ("Ecx", W.DWORD),
                ("Eax", W.DWORD), ("Ebp", W.DWORD), ("Eip", W.DWORD), ("SegCs", W.DWORD),
                ("EFlags", W.DWORD), ("Esp", W.DWORD), ("SegSs", W.DWORD),
                ("ExtendedRegisters", ctypes.c_byte * 512)]


class EXCEPTION_RECORD(ctypes.Structure):
    _fields_ = [("ExceptionCode", W.DWORD), ("ExceptionFlags", W.DWORD), ("ExceptionRecord", ctypes.c_void_p),
                ("ExceptionAddress", ctypes.c_void_p), ("NumberParameters", W.DWORD),
                ("ExceptionInformation", ctypes.c_size_t * 15)]


class CREATE_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("hFile", W.HANDLE), ("hProcess", W.HANDLE), ("hThread", W.HANDLE),
                ("lpBaseOfImage", ctypes.c_void_p), ("dwDebugInfoFileOffset", W.DWORD), ("nDebugInfoSize", W.DWORD),
                ("lpThreadLocalBase", ctypes.c_void_p), ("lpStartAddress", ctypes.c_void_p),
                ("lpImageName", ctypes.c_void_p), ("fUnicode", W.WORD)]


class CREATE_THREAD_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("hThread", W.HANDLE), ("lpThreadLocalBase", ctypes.c_void_p), ("lpStartAddress", ctypes.c_void_p)]


class EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("ExceptionRecord", EXCEPTION_RECORD), ("dwFirstChance", W.DWORD)]


class _U(ctypes.Union):
    _fields_ = [("Exception", EXCEPTION_DEBUG_INFO), ("CreateThread", CREATE_THREAD_DEBUG_INFO),
                ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO), ("pad", ctypes.c_byte * 164)]


class DEBUG_EVENT(ctypes.Structure):
    _fields_ = [("dwDebugEventCode", W.DWORD), ("dwProcessId", W.DWORD), ("dwThreadId", W.DWORD), ("u", _U)]


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [("cb", W.DWORD), ("lpReserved", W.LPWSTR), ("lpDesktop", W.LPWSTR), ("lpTitle", W.LPWSTR),
                ("dwX", W.DWORD), ("dwY", W.DWORD), ("dwXSize", W.DWORD), ("dwYSize", W.DWORD),
                ("dwXCountChars", W.DWORD), ("dwYCountChars", W.DWORD), ("dwFillAttribute", W.DWORD),
                ("dwFlags", W.DWORD), ("wShowWindow", W.WORD), ("cbReserved2", W.WORD),
                ("lpReserved2", ctypes.c_void_p), ("hStdInput", W.HANDLE), ("hStdOutput", W.HANDLE),
                ("hStdError", W.HANDLE)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", W.HANDLE), ("hThread", W.HANDLE), ("dwProcessId", W.DWORD), ("dwThreadId", W.DWORD)]


k32.CreateProcessW.argtypes = [W.LPCWSTR, W.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, W.BOOL, W.DWORD,
                               ctypes.c_void_p, W.LPCWSTR, ctypes.POINTER(STARTUPINFOW),
                               ctypes.POINTER(PROCESS_INFORMATION)]
k32.WaitForDebugEvent.argtypes = [ctypes.POINTER(DEBUG_EVENT), W.DWORD]
k32.ContinueDebugEvent.argtypes = [W.DWORD, W.DWORD, W.DWORD]
k32.ReadProcessMemory.argtypes = [W.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
k32.WriteProcessMemory.argtypes = [W.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
k32.VirtualProtectEx.argtypes = [W.HANDLE, ctypes.c_void_p, ctypes.c_size_t, W.DWORD, ctypes.POINTER(W.DWORD)]
k32.FlushInstructionCache.argtypes = [W.HANDLE, ctypes.c_void_p, ctypes.c_size_t]
k32.Wow64GetThreadContext.argtypes = [W.HANDLE, ctypes.POINTER(WOW64_CONTEXT)]
k32.Wow64SetThreadContext.argtypes = [W.HANDLE, ctypes.POINTER(WOW64_CONTEXT)]
k32.TerminateProcess.argtypes = [W.HANDLE, W.UINT]
k32.OpenThread.restype = W.HANDLE
k32.OpenThread.argtypes = [W.DWORD, W.BOOL, W.DWORD]


class Shadow:
    def __init__(self, exe, cmdline, cwd, args):
        self.exe, self.cmdline, self.cwd = exe, cmdline, cwd
        self.limit, self.per_function, self.until = args.max, args.per_function, args.until
        self.hproc = None
        self.base = 0                           # where the loader put the image
        self.delta = 0                          # base - reference_base (functions.json is reference-based)
        self.orig: dict[int, int] = {}          # live address -> original byte
        self.argspec: dict[int, tuple] = {}      # reference address -> (nreg, reg_list, nargs)
        self.hits: dict[int, int] = {}          # reference address -> times recorded
        self.threads: dict[int, int] = {}       # tid -> handle
        self.stepping: dict[int, int | None] = {}   # tid -> the live address to re-arm after its step
        self.records = bytearray()
        self.n = 0
        self.done = False
        self._load_facts()

    # ---- the functions and their conventions -----------------------------------------------------
    def _load_facts(self):
        b = Binary()
        self.ref_base = b.base
        self.image_size = len(b.image)
        self.text_lo, self.text_hi = b.text.start, b.text.end
        funcs = json.loads((FACTS / "functions.json").read_text())["functions"]
        self.entries = [int(f["entry"], 16) for f in funcs]
        protos = {}
        pr = FACTS / "protos.json"
        if pr.exists():
            protos = json.loads(pr.read_text())["functions"]
        for f in funcs:
            a = int(f["entry"], 16)
            e = protos.get(f"0x{a:x}") or protos.get("0x%08x" % a)
            self.argspec[a] = self._spec(e)

    @staticmethod
    def _spec(e):
        """(register slots, the registers, total logical args capped at 4) for a function, matching
        how translate32.py orders gen_a0..gen_a3: register parameters first, then stack."""
        if not e:
            return (0, [], 4)                    # unknown: four stack words, as __cdecl
        cc = e.get("cc")
        nparams = len(e.get("params", []))
        if cc == "__thiscall":
            regs = ["ecx"]
        elif cc == "__fastcall":
            regs = ["ecx", "edx"]
        elif cc == "custom":
            regs = list(e.get("regs", []))
        else:
            regs = []
        return (len(regs), regs, min(nparams, 4))

    # ---- memory ----------------------------------------------------------------------------------
    def _read(self, addr, size):
        buf = (ctypes.c_char * size)()
        got = ctypes.c_size_t(0)
        if not k32.ReadProcessMemory(self.hproc, ctypes.c_void_p(addr), buf, size, ctypes.byref(got)):
            return None
        return bytes(buf[:got.value])

    def _write_byte(self, addr, value):
        b = ctypes.c_char(value)
        wrote = ctypes.c_size_t(0)
        k32.WriteProcessMemory(self.hproc, ctypes.c_void_p(addr), ctypes.byref(b), 1, ctypes.byref(wrote))

    def _u32(self, addr):
        d = self._read(addr, 4)
        return struct.unpack("<I", d)[0] if d and len(d) == 4 else 0

    # ---- breakpoints -----------------------------------------------------------------------------
    def _arm_all(self):
        # the whole .text made writable once, the originals read in one pass, a CC at each entry
        old = W.DWORD(0)
        lo, hi = self.text_lo + self.delta, self.text_hi + self.delta
        k32.VirtualProtectEx(self.hproc, ctypes.c_void_p(lo), hi - lo, PAGE_EXECUTE_READWRITE, ctypes.byref(old))
        text = self._read(lo, hi - lo)
        armed = 0
        for a in self.entries:
            if not (self.text_lo <= a < self.text_hi):
                continue
            live = a + self.delta
            self.orig[live] = text[a - self.text_lo]
            self._write_byte(live, CC)
            armed += 1
        k32.FlushInstructionCache(self.hproc, ctypes.c_void_p(lo), hi - lo)
        print(f"shadow32: armed {armed} function entries at base 0x{self.base:x}", file=sys.stderr, flush=True)

    def _context(self, tid):
        h = self.threads.get(tid)
        if h is None:
            h = k32.OpenThread(0x1FFFFF, False, tid)
            self.threads[tid] = h
        ctx = WOW64_CONTEXT()
        ctx.ContextFlags = WOW64_CONTEXT_FULL
        if not k32.Wow64GetThreadContext(h, ctypes.byref(ctx)):
            return None, None
        return h, ctx

    def _record(self, tid, ref_addr, ctx):
        nreg, regs, nargs = self.argspec.get(ref_addr, (0, [], 4))
        vals = []
        for name in regs:
            # (a narrow one as its register, cl as ecx; one the context has no field for, st0, an
            # xmm or ebp's frame, as 0: protos32 names those too since 2026-10-24)
            full = {"al": "eax", "ax": "eax", "cl": "ecx", "cx": "ecx", "dl": "edx", "dx": "edx"}.get(name, name)
            mask = {"al": 0xFF, "cl": 0xFF, "dl": 0xFF, "ax": 0xFFFF, "cx": 0xFFFF, "dx": 0xFFFF}.get(name, 0xFFFFFFFF)
            vals.append(getattr(ctx, full.capitalize(), 0) & mask)
        # the stack parameters, above the return address (esp + 4 at entry)
        slot = ctx.Esp + 4
        while len(vals) < nargs:
            vals.append(self._u32(slot))
            slot += 4
        vals = (vals + [0, 0, 0, 0])[:4]
        # (an address inside the image as the reference's own: the loader may have moved the image
        # (ASLR), and the port maps it at its preferred base)
        if self.delta:
            lo, hi = self.base, self.base + self.image_size
            vals = [(v - self.delta) & 0xFFFFFFFF if lo <= v < hi else v for v in vals]
        self.records += struct.pack("<6I", tid, ref_addr, *vals)
        self.n += 1

    def _on_breakpoint(self, tid, live_addr):
        """A CC we planted (live_addr is its address). Record, restore, single-step to re-arm."""
        if live_addr not in self.orig:
            return False                         # the loader's own breakpoint, or not ours
        ref_addr = live_addr - self.delta
        h, ctx = self._context(tid)
        if ctx is None:
            return True
        ctx.Eip = live_addr                      # back onto the real instruction
        if self.hits.get(ref_addr, 0) < self.per_function:
            self.hits[ref_addr] = self.hits.get(ref_addr, 0) + 1
            self._record(tid, ref_addr, ctx)
        # restore the byte and step; re-arm on the step unless the function has had its fill
        self._write_byte(live_addr, self.orig[live_addr])
        rearm = live_addr if self.hits.get(ref_addr, 0) < self.per_function else None
        self.stepping[tid] = rearm
        ctx.EFlags |= TRAP_FLAG
        k32.Wow64SetThreadContext(h, ctypes.byref(ctx))
        if self.until is not None and ref_addr == self.until:
            self.done = True
        if self.n >= self.limit:
            self.done = True
        return True

    def _on_singlestep(self, tid):
        rearm = self.stepping.pop(tid, None)
        if rearm is not None:
            self._write_byte(rearm, CC)
        h, ctx = self._context(tid)
        if ctx is not None and ctx.EFlags & TRAP_FLAG:
            ctx.EFlags = ctx.EFlags & 0xFFFFFFFF & ~TRAP_FLAG & 0xFFFFFFFF
            k32.Wow64SetThreadContext(h, ctypes.byref(ctx))

    # ---- the loop --------------------------------------------------------------------------------
    def run(self):
        si = STARTUPINFOW()
        si.cb = ctypes.sizeof(si)
        pi = PROCESS_INFORMATION()
        cmd = ctypes.create_unicode_buffer(self.cmdline)
        if not k32.CreateProcessW(self.exe, cmd, None, None, False, DEBUG_ONLY_THIS_PROCESS,
                                  None, self.cwd, ctypes.byref(si), ctypes.byref(pi)):
            sys.exit(f"shadow32: cannot start {self.exe} ({ctypes.get_last_error()})")
        t0 = time.time()
        ev = DEBUG_EVENT()
        while not self.done:
            if not k32.WaitForDebugEvent(ctypes.byref(ev), INFINITE):
                break
            code = ev.dwDebugEventCode
            status = DBG_CONTINUE
            if code == CREATE_PROCESS_DEBUG_EVENT:
                info = ev.u.CreateProcessInfo
                self.hproc = info.hProcess
                self.base = info.lpBaseOfImage or 0
                self.delta = self.base - self.ref_base
                self.threads[ev.dwThreadId] = info.hThread
                self._arm_all()
            elif code == CREATE_THREAD_DEBUG_EVENT:
                self.threads[ev.dwThreadId] = ev.u.CreateThread.hThread
            elif code == EXIT_THREAD_DEBUG_EVENT:
                self.threads.pop(ev.dwThreadId, None)
            elif code == EXIT_PROCESS_DEBUG_EVENT:
                break
            elif code == EXCEPTION_DEBUG_EVENT:
                rec = ev.u.Exception.ExceptionRecord
                ec = rec.ExceptionCode & 0xFFFFFFFF
                at = rec.ExceptionAddress or 0
                if ec in (STATUS_BREAKPOINT, STATUS_WX86_BREAKPOINT):
                    if not self._on_breakpoint(ev.dwThreadId, at):
                        # the loader's initial breakpoint and anything not ours: let it run
                        pass
                elif ec in (STATUS_SINGLE_STEP, STATUS_WX86_SINGLE_STEP):
                    self._on_singlestep(ev.dwThreadId)
                else:
                    status = DBG_EXCEPTION_NOT_HANDLED   # a real fault: the program's own
            k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, status)
            if self.n and self.n % 100000 == 0:
                print(f"shadow32: {self.n} calls, {time.time() - t0:.0f}s", file=sys.stderr, flush=True)
        if self.hproc:
            k32.TerminateProcess(self.hproc, 0)
            # drain so the process actually goes away
            for _ in range(200):
                if not k32.WaitForDebugEvent(ctypes.byref(ev), 50):
                    break
                if ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT:
                    k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE)
                    break
                k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE)
        return bytes(self.records)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, help="the trace file (24-byte records: tid, address, 4 args)")
    ap.add_argument("--exe", help="the reference to launch (default: the project's)")
    ap.add_argument("--max", type=int, default=400000, help="stop after this many recorded calls")
    ap.add_argument("--per-function", type=int, default=2000,
                    help="record each function at most this many times, then remove its breakpoint")
    ap.add_argument("--until", help="stop when this reference address (hex) is first reached")
    ap.add_argument("args", nargs=argparse.REMAINDER, help="-- then the program's own arguments")
    a = ap.parse_args()
    a.until = int(a.until, 16) if a.until else None
    exe = a.exe or str(project.EXE)
    prog_args = a.args[1:] if a.args and a.args[0] == "--" else a.args
    cmdline = " ".join([f'"{exe}"'] + [f'"{x}"' if " " in x else x for x in prog_args])
    import os
    sh = Shadow(exe, cmdline, os.getcwd(), a)
    data = sh.run()
    with open(a.out, "wb") as f:
        f.write(data)
    print(f"shadow32: wrote {len(data) // 24} calls to {a.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
