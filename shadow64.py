"""The shadow run of a 64-bit reference: shadow32.py's counterpart for an x86-64 project. The
program's function calls are recorded the way the port's shadow trace will record them, so
shadow_diff.py can line the two runs up call for call and point at the first place they part.

A small debugger for the reference (native x64, no WoW64). An int3 is written at every function's
entry (the roots of .pdata, rebased to where the loader put the image). At each hit the first four
logical arguments are read where the Win64 ABI keeps them (protos.json: position k in rcx/rdx/r8/r9,
or the low 8 bytes of xmm0-3 when its kind is a float, double or vector; past four, the stack word
at entry rsp + 8 + 8k), a record is written, the original byte is put back, one instruction is
single-stepped, and the int3 is written again. A function keeps its breakpoint only for its first
--per-function hits, so a hot leaf like memcpy does not take the run; the run ends at --max records,
at --until (a reference address), or when the program exits.

    python shadow64.py --out build/shadow-ref.bin [--max 400000] [--per-function 2000] \\
                       [--until 0x1414fc8b0] [--protection] [-- args to the program...]

Run it from where the program is installed, with the arguments it is normally started with.

Where it differs from shadow32.py, because the x64 reference carries the anti-tamper layer
(the project's protection plugin):
- the protection's functions (the protection facts file's "protection") are left unarmed unless
  --protection: the port stubs them, so they are not calls the two runs can share, and some run
  out of encrypted code that an int3 would corrupt;
- a breakpoint or single step that is not ours is passed back to the program
  (DBG_EXCEPTION_NOT_HANDLED), since the layer traps on purpose and handles its own; only the
  loader's initial breakpoint is swallowed. The layer also hashes code pages and times itself, so
  a run that dies early in the protection is the layer seeing the debugger, not a finding.

Each record is 48 bytes: tid (u32), 0 (u32), the reference address (u64), four argument words
(u64, each masked to the width protos.json gives it; a float argument as its xmm register's bits,
an unread position 0). An address inside the image is
written as the reference's own, as if loaded at its preferred base. The port's trace for a 64-bit
project has to write the same layout for shadow_diff.py to compare the two.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
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
LOAD_DLL_DEBUG_EVENT = 6
DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED = 0x00010002, 0x80010001
STATUS_BREAKPOINT, STATUS_SINGLE_STEP = 0x80000003, 0x80000004
CONTEXT_AMD64 = 0x00100000
CONTEXT_FULL = CONTEXT_AMD64 | 0x1 | 0x2 | 0x8      # control, integer, floating point (the xmm)
TRAP_FLAG = 0x100
PAGE_EXECUTE_READWRITE = 0x40
INFINITE = 0xFFFFFFFF
CC = 0xCC
RECORD = struct.Struct("<IIQQQQQ")

# the AMD64 CONTEXT, by offset (winnt.h): it must sit on a 16-byte boundary, which ctypes does not
# promise a Structure, so it lives in a buffer and is read and written in place
CONTEXT_SIZE = 0x4D0
OFF_FLAGS, OFF_EFLAGS, OFF_RSP, OFF_RIP, OFF_XMM0 = 0x30, 0x44, 0x98, 0xF8, 0x1A0
OFF_REG = {"rcx": 0x80, "rdx": 0x88, "r8": 0xB8, "r9": 0xC0}
INT_REGS = ("rcx", "rdx", "r8", "r9")
FLOAT_KINDS = ("f", "d", "x", "v")      # protos64.py's kinds that arrive in xmm


class Context:
    def __init__(self):
        self._raw = ctypes.create_string_buffer(CONTEXT_SIZE + 16)
        self.addr = (ctypes.addressof(self._raw) + 15) & ~15
        self.view = (ctypes.c_char * CONTEXT_SIZE).from_address(self.addr)

    def q(self, off):
        return struct.unpack_from("<Q", self.view, off)[0]

    def d(self, off):
        return struct.unpack_from("<I", self.view, off)[0]

    def set_q(self, off, v):
        struct.pack_into("<Q", self.view, off, v & 0xFFFFFFFFFFFFFFFF)

    def set_d(self, off, v):
        struct.pack_into("<I", self.view, off, v & 0xFFFFFFFF)


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


class LOAD_DLL_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("hFile", W.HANDLE), ("lpBaseOfDll", ctypes.c_void_p), ("dwDebugInfoFileOffset", W.DWORD),
                ("nDebugInfoSize", W.DWORD), ("lpImageName", ctypes.c_void_p), ("fUnicode", W.WORD)]


class EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("ExceptionRecord", EXCEPTION_RECORD), ("dwFirstChance", W.DWORD)]


class _U(ctypes.Union):
    _fields_ = [("Exception", EXCEPTION_DEBUG_INFO), ("CreateThread", CREATE_THREAD_DEBUG_INFO),
                ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO), ("LoadDll", LOAD_DLL_DEBUG_INFO),
                ("pad", ctypes.c_byte * 164)]


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
k32.GetThreadContext.argtypes = [W.HANDLE, ctypes.c_void_p]
k32.SetThreadContext.argtypes = [W.HANDLE, ctypes.c_void_p]
k32.TerminateProcess.argtypes = [W.HANDLE, W.UINT]
k32.CloseHandle.argtypes = [W.HANDLE]
k32.OpenThread.restype = W.HANDLE
k32.OpenThread.argtypes = [W.DWORD, W.BOOL, W.DWORD]


class Shadow:
    def __init__(self, exe, cmdline, cwd, args):
        self.exe, self.cmdline, self.cwd = exe, cmdline, cwd
        self.limit, self.per_function, self.until = args.max, args.per_function, args.until
        self.hproc = None
        self.base = 0                           # where the loader put the image
        self.delta = 0                          # base - reference base (the facts are reference-based)
        self.orig: dict[int, int] = {}          # live address -> original byte
        self.argspec: dict[int, list] = {}      # reference address -> four (where, which) slots
        self.hits: dict[int, int] = {}          # reference address -> times recorded
        self.threads: dict[int, int] = {}       # tid -> handle
        self.stepping: dict[int, int | None] = {}   # tid -> the live address to re-arm after its step
        self.ctx = Context()
        self.records = bytearray()
        self.n = 0
        self.passed = 0                         # breakpoints and steps handed back to the program
        self.done = False
        self.initial_seen = False
        self._load_facts(args.protection)

    # ---- the functions and their parameters ------------------------------------------------------
    def _load_facts(self, with_protection):
        b = Binary()
        self.ref_base = b.base
        self.image_size = len(b.image)
        self.text_lo, self.text_hi = b.text.start, b.text.end
        skip = set()
        # (the protection plugin's facts file, rhipper.json "protection_facts")
        ae = FACTS / project.CONFIG.get("protection_facts", "protection.json")
        if not with_protection and ae.exists():
            skip = {int(a, 16) for a in json.loads(ae.read_text()).get("protection", [])}
        self.entries = [a for a in b.func_starts if self.text_lo <= a < self.text_hi and a not in skip]
        self.skipped = len(skip)
        protos = {}
        pr = FACTS / "protos.json"
        if pr.exists():
            protos = json.loads(pr.read_text())["functions"]
        for a in self.entries:
            self.argspec[a] = self._spec(protos.get(f"0x{a:x}"))

    @staticmethod
    def _spec(e):
        """The first four logical arguments' places, (where, which, mask): ("reg", name), ("xmm",
        k), ("stack", k), or ("none", k) for a position nothing reads (protos64.py's "-", recorded
        0). The mask is the width the function reads: what a register holds above it is whatever
        the caller left, and would make two equal calls differ. A function protos.json does not
        know records none: the port's trace (translate64.py trace_widths) cannot know them either."""
        full = 0xFFFFFFFFFFFFFFFF
        if not e:
            return [("none", k, 0) for k in range(4)]
        out = []
        for k, (kind, size) in enumerate(e.get("params", [])[:4]):
            mask = full if size >= 8 else (1 << (8 * size)) - 1
            if kind in FLOAT_KINDS:
                out.append(("xmm", k, mask))
            elif kind == "s":
                out.append(("stack", k, mask))
            elif kind == "-":
                out.append(("none", k, 0))
            else:
                out.append(("reg", INT_REGS[k], mask))
        return out

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
        k32.FlushInstructionCache(self.hproc, ctypes.c_void_p(addr), 1)

    def _u64(self, addr):
        d = self._read(addr, 8)
        return struct.unpack("<Q", d)[0] if d and len(d) == 8 else 0

    # ---- breakpoints -----------------------------------------------------------------------------
    def _arm_all(self):
        # the whole .text made writable once, the originals read in one pass, a CC at each entry
        old = W.DWORD(0)
        lo, hi = self.text_lo + self.delta, self.text_hi + self.delta
        k32.VirtualProtectEx(self.hproc, ctypes.c_void_p(lo), hi - lo, PAGE_EXECUTE_READWRITE, ctypes.byref(old))
        text = self._read(lo, hi - lo)
        if text is None or len(text) != hi - lo:
            sys.exit(f"shadow64: cannot read .text at 0x{lo:x} ({ctypes.get_last_error()})")
        cc = ctypes.c_char(CC)
        wrote = ctypes.c_size_t(0)
        for a in self.entries:
            live = a + self.delta
            self.orig[live] = text[a - self.text_lo]
            k32.WriteProcessMemory(self.hproc, ctypes.c_void_p(live), ctypes.byref(cc), 1, ctypes.byref(wrote))
        k32.FlushInstructionCache(self.hproc, ctypes.c_void_p(lo), hi - lo)
        print(f"shadow64: armed {len(self.entries)} function entries at base 0x{self.base:x}"
              f" ({self.skipped} protection functions left alone)", file=sys.stderr, flush=True)

    def _thread(self, tid):
        h = self.threads.get(tid)
        if h is None:
            h = k32.OpenThread(0x1FFFFF, False, tid)
            self.threads[tid] = h
        return h

    def _get(self, tid):
        h = self._thread(tid)
        self.ctx.set_d(OFF_FLAGS, CONTEXT_FULL)
        if not k32.GetThreadContext(h, ctypes.c_void_p(self.ctx.addr)):
            return None
        return h

    def _record(self, tid, ref_addr):
        c = self.ctx
        rsp = c.q(OFF_RSP)
        vals = []
        for where, which, mask in self.argspec.get(ref_addr, ()):
            if where == "reg":
                v = c.q(OFF_REG[which])
            elif where == "xmm":
                v = c.q(OFF_XMM0 + 16 * which)
            elif where == "stack":               # past the home area: [entry rsp + 8 + 8k]
                v = self._u64(rsp + 8 + 8 * which)
            else:
                v = 0
            vals.append(v & mask)
        vals = (vals + [0, 0, 0, 0])[:4]
        # (an address inside the image as the reference's own: the loader may have moved it (ASLR),
        # and the port maps it at its preferred base)
        if self.delta:
            lo, hi = self.base, self.base + self.image_size
            vals = [(v - self.delta) & 0xFFFFFFFFFFFFFFFF if lo <= v < hi else v for v in vals]
        self.records += RECORD.pack(tid, 0, ref_addr, *vals)
        self.n += 1

    def _on_breakpoint(self, tid, live_addr):
        """A CC we planted (live_addr is its address). Record, restore, single-step to re-arm.
        False when it is not ours."""
        if live_addr not in self.orig:
            return False
        ref_addr = live_addr - self.delta
        h = self._get(tid)
        if h is None:
            return True
        self.ctx.set_q(OFF_RIP, live_addr)       # back onto the real instruction
        count = self.hits.get(ref_addr, 0)
        if count < self.per_function:
            self.hits[ref_addr] = count + 1
            self._record(tid, ref_addr)
        # restore the byte and step; re-arm on the step unless the function has had its fill
        self._write_byte(live_addr, self.orig[live_addr])
        self.stepping[tid] = live_addr if self.hits.get(ref_addr, 0) < self.per_function else None
        self.ctx.set_d(OFF_EFLAGS, self.ctx.d(OFF_EFLAGS) | TRAP_FLAG)
        k32.SetThreadContext(h, ctypes.c_void_p(self.ctx.addr))
        if (self.until is not None and ref_addr == self.until) or self.n >= self.limit:
            self.done = True
        return True

    def _on_singlestep(self, tid):
        """The step after a hit: re-arm. False when this thread was not stepping for us."""
        if tid not in self.stepping:
            return False
        rearm = self.stepping.pop(tid)
        if rearm is not None:
            self._write_byte(rearm, CC)
        h = self._get(tid)
        if h is not None and self.ctx.d(OFF_EFLAGS) & TRAP_FLAG:
            self.ctx.set_d(OFF_EFLAGS, self.ctx.d(OFF_EFLAGS) & ~TRAP_FLAG)
            k32.SetThreadContext(h, ctypes.c_void_p(self.ctx.addr))
        return True

    # ---- the loop --------------------------------------------------------------------------------
    def run(self):
        si = STARTUPINFOW()
        si.cb = ctypes.sizeof(si)
        pi = PROCESS_INFORMATION()
        cmd = ctypes.create_unicode_buffer(self.cmdline)
        if not k32.CreateProcessW(self.exe, cmd, None, None, False, DEBUG_ONLY_THIS_PROCESS,
                                  None, self.cwd, ctypes.byref(si), ctypes.byref(pi)):
            sys.exit(f"shadow64: cannot start {self.exe} ({ctypes.get_last_error()})")
        t0 = time.time()
        ev = DEBUG_EVENT()
        last = 0
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
                if info.hFile:
                    k32.CloseHandle(info.hFile)
                self._arm_all()
            elif code == CREATE_THREAD_DEBUG_EVENT:
                self.threads[ev.dwThreadId] = ev.u.CreateThread.hThread
            elif code == EXIT_THREAD_DEBUG_EVENT:
                self.threads.pop(ev.dwThreadId, None)
                self.stepping.pop(ev.dwThreadId, None)
            elif code == LOAD_DLL_DEBUG_EVENT:
                if ev.u.LoadDll.hFile:
                    k32.CloseHandle(ev.u.LoadDll.hFile)
            elif code == EXIT_PROCESS_DEBUG_EVENT:
                break
            elif code == EXCEPTION_DEBUG_EVENT:
                rec = ev.u.Exception.ExceptionRecord
                ec = rec.ExceptionCode & 0xFFFFFFFF
                at = rec.ExceptionAddress or 0
                if ec == STATUS_BREAKPOINT:
                    if not self._on_breakpoint(ev.dwThreadId, at):
                        if self.initial_seen:
                            # the program's own int3 (the protection traps on purpose): its to handle
                            status = DBG_EXCEPTION_NOT_HANDLED
                            self.passed += 1
                        self.initial_seen = True     # the loader's, once
                elif ec == STATUS_SINGLE_STEP:
                    if not self._on_singlestep(ev.dwThreadId):
                        status = DBG_EXCEPTION_NOT_HANDLED
                        self.passed += 1
                else:
                    status = DBG_EXCEPTION_NOT_HANDLED   # a real fault: the program's own
            k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, status)
            if self.n - last >= 100000:
                last = self.n
                print(f"shadow64: {self.n} calls, {time.time() - t0:.0f}s", file=sys.stderr, flush=True)
        if self.hproc:
            k32.TerminateProcess(self.hproc, 0)
            # drain so the process actually goes away
            for _ in range(200):
                if not k32.WaitForDebugEvent(ctypes.byref(ev), 50):
                    break
                k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE)
                if ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT:
                    break
        if self.passed:
            print(f"shadow64: {self.passed} breakpoints/steps were the program's own, passed back",
                  file=sys.stderr)
        return bytes(self.records)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, help="the trace file (48-byte records: tid, 0, address, 4 args)")
    ap.add_argument("--exe", help="the reference to launch (default: the project's)")
    ap.add_argument("--cwd", help="the program's working directory (default: this one)")
    ap.add_argument("--max", type=int, default=400000, help="stop after this many recorded calls")
    ap.add_argument("--per-function", type=int, default=2000,
                    help="record each function at most this many times, then remove its breakpoint")
    ap.add_argument("--until", help="stop when this reference address (hex) is first reached")
    ap.add_argument("--protection", action="store_true",
                    help="arm the anti-tamper layer's functions too (protection facts; off by default)")
    ap.add_argument("args", nargs=argparse.REMAINDER, help="-- then the program's own arguments")
    a = ap.parse_args()
    if project.ARCH != "x86_64":
        sys.exit(f"shadow64: {project.NAME} is {project.ARCH}; use shadow32.py")
    a.until = int(a.until, 16) if a.until else None
    exe = a.exe or str(project.EXE)
    prog_args = a.args[1:] if a.args and a.args[0] == "--" else a.args
    cmdline = " ".join([f'"{exe}"'] + [f'"{x}"' if " " in x else x for x in prog_args])
    sh = Shadow(exe, cmdline, a.cwd or os.getcwd(), a)
    data = sh.run()
    with open(a.out, "wb") as f:
        f.write(data)
    print(f"shadow64: wrote {len(data) // RECORD.size} calls to {a.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
