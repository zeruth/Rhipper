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

With --from ADDR the run starts recording at a known-good point instead of the entry: only ADDR has
a breakpoint, the program runs at full speed to it, and from its first call there on every function
is armed and recorded (the port's trace starts there too with <ENV>_TRACE_FROM=ADDR). The part
before it is checked now and then from the start, for regressions.

    python shadow32.py --out build/shadow-ref.bin [--max 400000] [--per-function 2000] \
                       [--from 0xa0e240] [--until 0xc5c6db] [-- args to the program...]

Run it from where the program is installed, with the arguments it is normally started with. Each
record is 24 bytes: tid, reference address, and four argument words, matching the port's
<ENV>_TRACE file exactly.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import struct
import sys
import time
from pathlib import Path
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
WOW64_CONTEXT_DEBUG_REGISTERS = 0x00010010
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


class EXIT_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("dwExitCode", W.DWORD)]


class _U(ctypes.Union):
    _fields_ = [("Exception", EXCEPTION_DEBUG_INFO), ("CreateThread", CREATE_THREAD_DEBUG_INFO),
                ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO), ("ExitProcess", EXIT_PROCESS_DEBUG_INFO),
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
k32.Wow64GetThreadContext.argtypes = [W.HANDLE, ctypes.POINTER(WOW64_CONTEXT)]
k32.Wow64SetThreadContext.argtypes = [W.HANDLE, ctypes.POINTER(WOW64_CONTEXT)]
k32.TerminateProcess.argtypes = [W.HANDLE, W.UINT]
k32.OpenThread.restype = W.HANDLE
k32.OpenThread.argtypes = [W.DWORD, W.BOOL, W.DWORD]


k32.SuspendThread.argtypes = [W.HANDLE]
k32.ResumeThread.argtypes = [W.HANDLE]
k32.VirtualAllocEx.restype = ctypes.c_void_p
k32.VirtualAllocEx.argtypes = [W.HANDLE, ctypes.c_void_p, ctypes.c_size_t, W.DWORD, W.DWORD]
k32.CreateRemoteThread.restype = W.HANDLE
k32.CreateRemoteThread.argtypes = [W.HANDLE, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p,
                                   W.DWORD, ctypes.POINTER(W.DWORD)]
k32.DebugActiveProcessStop.argtypes = [W.DWORD]
k32.DebugSetProcessKillOnExit.argtypes = [W.BOOL]
k32.WaitForSingleObject.argtypes = [W.HANDLE, W.DWORD]
k32.GetExitCodeProcess.argtypes = [W.HANDLE, ctypes.POINTER(W.DWORD)]
psapi = ctypes.WinDLL("psapi", use_last_error=True)
psapi.EnumProcessModulesEx.argtypes = [W.HANDLE, ctypes.POINTER(W.HMODULE), W.DWORD, ctypes.POINTER(W.DWORD), W.DWORD]
psapi.GetModuleBaseNameW.argtypes = [W.HANDLE, W.HMODULE, W.LPWSTR, W.DWORD]

# ---- --inproc: the recording done in the reference itself (shadow32dll/ShadowTrace.cpp) -------------
# The debugger only starts it: a breakpoint at the image's entry, the tracer DLL loaded there by a
# thread of the process's own (the main thread held), then detached. The DLL arms every function
# entry and records in the process, each call one exception there instead of a stop of the whole
# process for this debugger: the run goes at a good fraction of the program's own speed.
JCC = {"jo": 0, "jno": 1, "jb": 2, "jae": 3, "je": 4, "jne": 5, "jbe": 6, "ja": 7, "js": 8, "jns": 9,
       "jp": 10, "jnp": 11, "jl": 12, "jge": 13, "jle": 14, "jg": 15}
REG_CODES = {"eax": 0, "ecx": 1, "edx": 2, "ebx": 3, "esi": 4, "edi": 5, "ebp": 6,
             "al": 0x10, "cl": 0x11, "dl": 0x12, "bl": 0x13, "ax": 0x20, "cx": 0x21, "dx": 0x22}


def write_table(path):
    """The tracer's table (ShadowTrace.cpp's header): every function's entry, its first instruction's
    length and kind, and where its arguments are (protos.json, as Shadow._spec reads them)."""
    import capstone
    b = Binary()
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    funcs = json.loads((FACTS / "functions.json").read_text())["functions"]
    pr = FACTS / "protos.json"
    protos = json.loads(pr.read_text())["functions"] if pr.exists() else {}
    lines = [f"{b.base:x} {len(b.image):x}"]
    for f in funcs:
        a = int(f["entry"], 16)
        if not (b.text.start <= a < b.text.end):
            continue
        ins = next(md.disasm(bytes(b.image[a - b.base:a - b.base + 16]), a, 1), None)
        if ins is None:
            continue
        mn, ops = ins.mnemonic, ins.op_str
        kind, target, cc = 0, 0, 0
        if mn == "call" and ops.startswith("0x"):
            kind, target = 1, int(ops, 16)
        elif mn == "jmp" and ops.startswith("0x"):
            kind, target = 2, int(ops, 16)
        elif mn in JCC and ops.startswith("0x"):
            kind, target, cc = 3, int(ops, 16), JCC[mn]
        elif mn.startswith("loop") or mn in ("jecxz", "jcxz") or ins.size > 15:
            kind = 4
        e = protos.get(f"0x{a:x}") or protos.get("0x%08x" % a)
        nreg, regs, nargs = Shadow._spec(e)
        codes = "".join(f"{REG_CODES[r]:02x}" for r in regs if r in REG_CODES) or "-"
        lines.append(f"{a:x} {ins.size:x} {kind:x} {target:x} {cc:x} {codes} {nargs:x}")
    Path(path).write_text("\n".join(lines) + "\n")
    return len(lines) - 1


def build_tracer() -> Path:
    """ShadowTrace.dll, built with the x86 compiler when its source is newer (vcvars32 through
    vswhere), into the project's build folder."""
    import subprocess
    src = Path(__file__).resolve().parent / "shadow32dll" / "ShadowTrace.cpp"
    out = project.BUILD / "shadow32" / "ShadowTrace.dll"
    if out.exists() and out.stat().st_mtime >= src.stat().st_mtime:
        return out
    out.parent.mkdir(parents=True, exist_ok=True)
    vswhere = Path(r"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe")
    vs = subprocess.run([str(vswhere), "-latest", "-property", "installationPath"], capture_output=True,
                        text=True).stdout.strip()
    vcvars = Path(vs) / "VC" / "Auxiliary" / "Build" / "vcvars32.bat"
    # (through a batch file: cmd /c's own quoting of a command line with quoted paths in it)
    bat = out.parent / "build.bat"
    bat.write_text(f'@call "{vcvars}" >nul\r\ncl /nologo /O2 /LD /MT /EHsc /W3 "{src}" /Fe"{out}" '
                   f'/Fo"{out.parent}\\\\" /link /NOLOGO kernel32.lib\r\n')
    r = subprocess.run(["cmd", "/c", str(bat)], capture_output=True, text=True, cwd=out.parent)
    if not out.exists():
        sys.exit(f"shadow32: the tracer did not build:\n{r.stdout}\n{r.stderr}")
    return out


def inproc_run(exe, cmdline, cwd, a):
    """The reference run with the tracer in it (see above); returns its exit code."""
    import os
    table, out = os.environ.get("SHADOW_TABLE"), os.environ.get("SHADOW_OUT")
    if not table or not out:
        # (set by the caller, for the reference's run and the port's alike: the CRT walks the
        # environment, and a variable one run has and the other does not parts them)
        sys.exit("shadow32 --inproc: set SHADOW_TABLE and SHADOW_OUT (and the same in the port's run)")
    n = write_table(table)
    dll = build_tracer()
    import pefile
    entry = Binary().base + pefile.PE(exe, fast_load=True).OPTIONAL_HEADER.AddressOfEntryPoint
    k32w = pefile.PE(r"C:\Windows\SysWOW64\kernel32.dll", fast_load=True)
    k32w.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
    load_rva = next(s.address for s in k32w.DIRECTORY_ENTRY_EXPORT.symbols if s.name == b"LoadLibraryW")
    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()
    if not k32.CreateProcessW(exe, ctypes.create_unicode_buffer(cmdline), None, None, False, DEBUG_ONLY_THIS_PROCESS,
                              None, cwd, ctypes.byref(si), ctypes.byref(pi)):
        sys.exit(f"shadow32: cannot start {exe} ({ctypes.get_last_error()})")
    t0 = time.time()
    ev = DEBUG_EVENT()
    hproc, live_entry, orig, delta = None, None, None, 0
    injected_tid = None
    main_thread = pi.hThread
    while True:
        if not k32.WaitForDebugEvent(ctypes.byref(ev), INFINITE):
            break
        code, status = ev.dwDebugEventCode, DBG_CONTINUE
        if code == CREATE_PROCESS_DEBUG_EVENT:
            hproc = ev.u.CreateProcessInfo.hProcess
            delta = (ev.u.CreateProcessInfo.lpBaseOfImage or 0) - Binary().base
            live_entry = entry + delta
            buf = (ctypes.c_char * 1)()
            k32.ReadProcessMemory(hproc, ctypes.c_void_p(live_entry), buf, 1, None)
            orig = buf.raw[0]
            cc = ctypes.c_char(CC)
            k32.WriteProcessMemory(hproc, ctypes.c_void_p(live_entry), ctypes.byref(cc), 1, None)
            k32.FlushInstructionCache(hproc, ctypes.c_void_p(live_entry), 1)
        elif code == EXIT_PROCESS_DEBUG_EVENT:
            sys.exit("shadow32: the reference exited before its entry")
        elif code == EXIT_THREAD_DEBUG_EVENT and ev.dwThreadId == injected_tid:
            # (the tracer loaded and armed: the program goes on without this debugger)
            k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE)
            k32.DebugSetProcessKillOnExit(False)
            k32.DebugActiveProcessStop(pi.dwProcessId)
            k32.ResumeThread(main_thread)
            break
        elif code == EXCEPTION_DEBUG_EVENT:
            rec = ev.u.Exception.ExceptionRecord
            ec, at = rec.ExceptionCode & 0xFFFFFFFF, rec.ExceptionAddress or 0
            if ec in (STATUS_BREAKPOINT, STATUS_WX86_BREAKPOINT) and at == live_entry and injected_tid is None:
                # the entry reached: its byte back, the main thread held there, the tracer loaded
                b = ctypes.c_char(orig)
                k32.WriteProcessMemory(hproc, ctypes.c_void_p(live_entry), ctypes.byref(b), 1, None)
                k32.FlushInstructionCache(hproc, ctypes.c_void_p(live_entry), 1)
                h = k32.OpenThread(0x1FFFFF, False, ev.dwThreadId)
                ctx = WOW64_CONTEXT()
                ctx.ContextFlags = WOW64_CONTEXT_FULL
                k32.Wow64GetThreadContext(h, ctypes.byref(ctx))
                ctx.Eip = live_entry
                k32.Wow64SetThreadContext(h, ctypes.byref(ctx))
                main_thread = h
                k32.SuspendThread(h)
                mods = (W.HMODULE * 512)()
                need = W.DWORD(0)
                psapi.EnumProcessModulesEx(hproc, mods, ctypes.sizeof(mods), ctypes.byref(need), 1)
                base = None
                name = ctypes.create_unicode_buffer(260)
                for m in mods[:need.value // ctypes.sizeof(W.HMODULE)]:
                    if m and psapi.GetModuleBaseNameW(hproc, m, name, 260) and name.value.lower() == "kernel32.dll":
                        base = m
                if base is None:
                    sys.exit("shadow32: no 32-bit kernel32 in the reference at its entry")
                path = str(dll) + "\0"
                mem = k32.VirtualAllocEx(hproc, None, len(path) * 2, 0x3000, 0x04)
                k32.WriteProcessMemory(hproc, ctypes.c_void_p(mem), ctypes.create_unicode_buffer(path), len(path) * 2, None)
                tid = W.DWORD(0)
                k32.CreateRemoteThread(hproc, None, 0, ctypes.c_void_p(base + load_rva), ctypes.c_void_p(mem), 0,
                                       ctypes.byref(tid))
                injected_tid = tid.value
            elif ec not in (STATUS_BREAKPOINT, STATUS_WX86_BREAKPOINT, STATUS_SINGLE_STEP, STATUS_WX86_SINGLE_STEP):
                status = DBG_EXCEPTION_NOT_HANDLED
        k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, status)
    print(f"shadow32: tracing in the reference ({n} functions) after {time.time() - t0:.1f}s; waiting for it to exit",
          file=sys.stderr, flush=True)
    while k32.WaitForSingleObject(hproc, 30000) != 0:
        size = os.path.getsize(out) if os.path.exists(out) else 0
        print(f"shadow32: {size // 24} calls, {time.time() - t0:.0f}s", file=sys.stderr, flush=True)
    code = W.DWORD(0)
    k32.GetExitCodeProcess(hproc, ctypes.byref(code))
    size = os.path.getsize(out) if os.path.exists(out) else 0
    print(f"shadow32: the reference exited with 0x{code.value & 0xFFFFFFFF:08x}; {size // 24} calls in {out}",
          file=sys.stderr, flush=True)
    return code.value


class Shadow:
    def __init__(self, exe, cmdline, cwd, args):
        self.exe, self.cmdline, self.cwd = exe, cmdline, cwd
        self.limit, self.per_function, self.until = args.max, args.per_function, args.until
        # (--sites FILE: each indirect call site and the functions it reached, merged into FILE)
        self.sites = {} if getattr(args, "sites", None) else None
        self.start = getattr(args, "start", None)      # --from: the address recording starts at
        self.recording = self.start is None
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
        self.out = None                         # the trace file, written as it grows (run())
        self.faults = 0
        # (--watch GLOBAL:OFF,...: the global and the offsets; the addresses once it is set)
        self.watch, self.watch_at = None, None
        self.watch_only = bool(getattr(args, "watch_only", False))
        self.secs = getattr(args, "secs", 0) or 0
        if getattr(args, "watch", None):
            g, offs = args.watch.split(":")
            self.watch = (int(g, 16), [int(x, 16) for x in offs.split(",")])
        self.done = False
        # (--fake-cursor X,Y: the reference's GetCursorPos answers with that client point)
        self.fake = tuple(int(v) for v in args.fake_cursor.split(",")) if getattr(args, "fake_cursor", None) else None
        self.fake_hwnd_slot = None
        self.pid = 0
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
        # (the stack's words count too where the parameter list is short of them: a __thiscall
        # with `stack` 12 and three params took three stack words, its third recorded as 0)
        words = len(regs) + e.get("stack", 0) // 4
        return (len(regs), regs, min(max(nparams, words), 4))

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
            # (with --from, only its address now: the rest when it is first reached, _arm_rest)
            if self.start is None or a == self.start:
                self._write_byte(live, CC)
                armed += 1
        k32.FlushInstructionCache(self.hproc, ctypes.c_void_p(lo), hi - lo)
        what = f"0x{self.start:x}, the rest when it is reached" if self.start is not None else f"{armed} function entries"
        print(f"shadow32: armed {what} at base 0x{self.base:x}", file=sys.stderr, flush=True)

    def _arm_rest(self):
        """--from's address reached: every other function entry armed, recording from here."""
        lo, hi = self.text_lo + self.delta, self.text_hi + self.delta
        start_live = self.start + self.delta
        for live in self.orig:
            if live != start_live:
                self._write_byte(live, CC)
        k32.FlushInstructionCache(self.hproc, ctypes.c_void_p(lo), hi - lo)
        self.recording = True
        print(f"shadow32: reached 0x{self.start:x}; recording every function from here", file=sys.stderr, flush=True)

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
        # (written out as it grows: a run cut short, the reference or this process killed from
        # outside, keeps what it recorded. One killed at 400,000 calls kept nothing, 2026-10-25)
        if self.out is not None and len(self.records) >= 1 << 20:
            self.out.write(self.records)
            self.out.flush()
            self.records = bytearray()

    def _site(self, ref_addr, ctx):
        """--sites: the indirect call that reached this function, by its return address: `call
        reg` / `call [reg]` (2 bytes), `call [reg + d8]` (3, 4 with a SIB byte), `call [reg + d32]`
        / `call [abs]` (6, 7 with a SIB byte). site -> the functions it reached."""
        ret = self._u32(ctx.Esp)
        if not ret:
            return
        live = ret
        for n in (2, 3, 4, 6, 7):
            buf = (ctypes.c_char * 2)()
            if not k32.ReadProcessMemory(self.hproc, ctypes.c_void_p(live - n), buf, 2, None):
                return
            op, modrm = buf.raw[0], buf.raw[1]
            if op != 0xFF or (modrm >> 3) & 7 != 2:
                continue
            mod, rm = modrm >> 6, modrm & 7
            want = {3: 2, 0: 2 if rm not in (4, 5) else (3 if rm == 4 else 6), 1: 3 if rm != 4 else 4,
                    2: 6 if rm != 4 else 7}.get(mod)
            if want == n:
                site = live - n - self.delta
                self.sites.setdefault(site, set()).add(ref_addr)
                return

    def _on_breakpoint(self, tid, live_addr):
        """A CC we planted (live_addr is its address). Record, restore, single-step to re-arm."""
        if live_addr not in self.orig:
            return False                         # the loader's own breakpoint, or not ours
        ref_addr = live_addr - self.delta
        self._watch_poll()
        h, ctx = self._context(tid)
        if ctx is None:
            return True
        if not self.recording and ref_addr == self.start:
            if self.watch_only:
                # (only the watch from here: no function breakpoints, the reference at full speed.
                # Recording every call from --from made a loading screen hang, 2026-10-27)
                self._watch_poll()
            else:
                self._arm_rest()
        ctx.Eip = live_addr                      # back onto the real instruction
        if self.hits.get(ref_addr, 0) < self.per_function:
            self.hits[ref_addr] = self.hits.get(ref_addr, 0) + 1
            self._record(tid, ref_addr, ctx)
            if self.sites is not None:
                self._site(ref_addr, ctx)
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

    # ---- --fake-cursor: the reference's cursor where a run says, as the port's <ENV>_VCURSOR ---------
    def _import_slot(self, name: str) -> int | None:
        """the live address of the reference's import slot for `name`"""
        import pefile
        pe = pefile.PE(str(project.EXE), fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        for dll in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            for imp in dll.imports:
                if imp.name and imp.name.decode() == name:
                    return imp.address - pe.OPTIONAL_HEADER.ImageBase + self.base
        return None

    def _fake_install(self):
        """GetCursorPos's import slot pointed at a stub of our own in the reference: the point the
        run gave, through ClientToScreen on the game's window (its handle filled in once it exists,
        _fake_window): the title menu's hover and clicks tried on the reference as on the port, the
        user's mouse untouched (2026-10-28)."""
        gcp, c2s = self._import_slot("GetCursorPos"), self._import_slot("ClientToScreen")
        if gcp is None or c2s is None:
            print("shadow32: --fake-cursor: no GetCursorPos or ClientToScreen import", file=sys.stderr, flush=True)
            self.fake = None
            return
        page = k32.VirtualAllocEx(self.hproc, None, 0x1000, 0x3000, 0x40)
        hwnd_slot = page + 0x80
        x, y = self.fake
        code = (b"\x8b\x44\x24\x04"                                   # mov eax, [esp+4]
                + b"\xc7\x00" + struct.pack("<i", x)                  # mov dword [eax], x
                + b"\xc7\x40\x04" + struct.pack("<i", y)              # mov dword [eax+4], y
                + b"\x50"                                             # push eax
                + b"\xff\x35" + struct.pack("<I", hwnd_slot)          # push dword [hwnd]
                + b"\xff\x15" + struct.pack("<I", c2s)                # call [ClientToScreen]
                + b"\xb8\x01\x00\x00\x00"                             # mov eax, 1
                + b"\xc2\x04\x00")                                    # ret 4
        buf = ctypes.create_string_buffer(code + bytes(0x84 - len(code)))
        k32.WriteProcessMemory(self.hproc, ctypes.c_void_p(page), buf, 0x84, None)
        old = W.DWORD()
        k32.VirtualProtectEx(self.hproc, ctypes.c_void_p(gcp), 4, PAGE_EXECUTE_READWRITE, ctypes.byref(old))
        v = ctypes.c_uint32(page)
        k32.WriteProcessMemory(self.hproc, ctypes.c_void_p(gcp), ctypes.byref(v), 4, None)
        k32.VirtualProtectEx(self.hproc, ctypes.c_void_p(gcp), 4, old.value, ctypes.byref(old))
        self.fake_hwnd_slot = hwnd_slot
        print(f"shadow32: --fake-cursor {x},{y}: GetCursorPos's slot {gcp:#x} -> {page:#x}", file=sys.stderr, flush=True)

    def _fake_window(self):
        """the game's window handle into the stub, once it has one (its class FFXIVGAME)"""
        if not self.fake_hwnd_slot:
            return
        u32 = ctypes.windll.user32
        found = []
        proc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)

        def each(h, _l):
            pid = ctypes.c_ulong()
            u32.GetWindowThreadProcessId(ctypes.c_void_p(h), ctypes.byref(pid))
            if pid.value == self.pid and u32.IsWindowVisible(ctypes.c_void_p(h)):
                found.append(h)
            return True
        u32.EnumWindows(proc(each), None)
        if found:
            v = ctypes.c_uint32(found[0] & 0xFFFFFFFF)
            k32.WriteProcessMemory(self.hproc, ctypes.c_void_p(self.fake_hwnd_slot), ctypes.byref(v), 4, None)
            print(f"shadow32: --fake-cursor: the window {found[0]:#x}", file=sys.stderr, flush=True)
            self.fake_hwnd_slot = None

    # ---- --watch: hardware write watches on an object a global points to -------------------------
    def _watch_poll(self):
        """Once the watched global holds a pointer, debug registers 0-3 watch 4-byte writes at
        pointer + each offset, on every thread (a new thread is armed as it starts)."""
        if not self.watch or self.watch_at:
            return
        ptr = self._u32(self.watch[0] + self.delta)
        if not ptr:
            return
        self.watch_at = [(ptr + off) & 0xFFFFFFFF for off in self.watch[1][:4]]
        print("shadow32: watching writes at " + ", ".join(f"{a:#x} (now {self._u32(a):#010x})" for a in self.watch_at)
              + f" ([{self.watch[0]:#x}] = {ptr:#x})", file=sys.stderr, flush=True)
        for tid in list(self.threads):
            self._watch_arm(tid)

    def _watch_arm(self, tid):
        if not self.watch_at:
            return
        h = self.threads.get(tid)
        if h is None:
            return
        ctx = WOW64_CONTEXT()
        ctx.ContextFlags = WOW64_CONTEXT_DEBUG_REGISTERS
        if not k32.Wow64GetThreadContext(h, ctypes.byref(ctx)):
            return
        dr7 = 0
        for k, a in enumerate(self.watch_at):
            setattr(ctx, f"Dr{k}", a)
            # (local enable; RW 01 a write; LEN 11 four bytes)
            dr7 |= (1 << (2 * k)) | (0b01 << (16 + 4 * k)) | (0b11 << (18 + 4 * k))
        ctx.Dr7 = dr7
        k32.Wow64SetThreadContext(h, ctypes.byref(ctx))

    def _watch_hit(self, tid) -> bool:
        """A debug-register trap: a watched write. Logged with the writing instruction's next
        address (the trap comes after the write) and the value now there."""
        h = self.threads.get(tid)
        if h is None or not self.watch_at:
            return False
        ctx = WOW64_CONTEXT()
        ctx.ContextFlags = WOW64_CONTEXT_DEBUG_REGISTERS | WOW64_CONTEXT_CONTROL
        if not k32.Wow64GetThreadContext(h, ctypes.byref(ctx)) or not ctx.Dr6 & 0xF:
            return False
        for k, a in enumerate(self.watch_at):
            if ctx.Dr6 & (1 << k):
                eip = ctx.Eip - self.delta if self.base <= ctx.Eip < self.base + self.image_size else ctx.Eip
                # (and the callers, cheaply: the stack's words that point into the image's code)
                ictx = WOW64_CONTEXT()
                ictx.ContextFlags = WOW64_CONTEXT_CONTROL
                k32.Wow64GetThreadContext(h, ctypes.byref(ictx))
                lo, hi = self.text_lo + self.delta, self.text_hi + self.delta
                chain = []
                for s in range(48):
                    w = self._u32(ictx.Esp + 4 * s)
                    if lo <= w < hi:
                        chain.append(f"{w - self.delta:#x}")
                    if len(chain) >= 10:
                        break
                print(f"shadow32: watch: thread {tid} wrote {self._u32(a):#010x} to {a:#x} (+{self.watch[1][k]:#x}), "
                      f"after the instruction before {eip:#x}; stack {' '.join(chain)}", file=sys.stderr, flush=True)
        ctx.Dr6 = 0
        k32.Wow64SetThreadContext(h, ctypes.byref(ctx))
        return True

    def _on_singlestep(self, tid):
        if self._watch_hit(tid) and tid not in self.stepping:
            return
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
        self.pid = pi.dwProcessId
        fake_installed, fake_next = False, 0.0
        ev = DEBUG_EVENT()
        while not self.done:
            # (--fake-cursor: the stub once the image's imports are bound, its first breakpoint of
            # ours or the loader's; the window's handle when there is one, every 2 s until then)
            if self.fake and self.hproc and time.time() >= fake_next:
                fake_next = time.time() + 2
                if fake_installed:
                    self._fake_window()
            # (a second at a time, so --secs ends a run that records nothing, --watch-only's)
            if not k32.WaitForDebugEvent(ctypes.byref(ev), 1000):
                if self.secs and time.time() - t0 > self.secs:
                    print(f"shadow32: {self.secs}s up", file=sys.stderr, flush=True)
                    break
                continue
            if self.secs and time.time() - t0 > self.secs:
                self.done = True
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
                self._watch_arm(ev.dwThreadId)
            elif code == EXIT_THREAD_DEBUG_EVENT:
                self.threads.pop(ev.dwThreadId, None)
            elif code == EXIT_PROCESS_DEBUG_EVENT:
                # (how the reference ended, when it ends on its own: a run cut short by the shadow
                # itself is no record of the reference)
                print(f"shadow32: the reference exited with 0x{ev.u.ExitProcess.dwExitCode & 0xFFFFFFFF:08x} "
                      f"after {self.n} calls", file=sys.stderr, flush=True)
                break
            elif code == EXCEPTION_DEBUG_EVENT:
                rec = ev.u.Exception.ExceptionRecord
                ec = rec.ExceptionCode & 0xFFFFFFFF
                at = rec.ExceptionAddress or 0
                if ec in (STATUS_BREAKPOINT, STATUS_WX86_BREAKPOINT):
                    # (at a breakpoint of ours in the image, not the loader's first: that comes before
                    # the imports are bound, and the binding wrote GetCursorPos's slot over the stub)
                    if self.fake and not fake_installed and self.base <= at < self.base + self.image_size:
                        self._fake_install()
                        fake_installed = True
                    if not self._on_breakpoint(ev.dwThreadId, at):
                        # the loader's initial breakpoint and anything not ours: let it run
                        pass
                elif ec in (STATUS_SINGLE_STEP, STATUS_WX86_SINGLE_STEP):
                    self._on_singlestep(ev.dwThreadId)
                else:
                    status = DBG_EXCEPTION_NOT_HANDLED   # a real fault: the program's own
                    # (each logged, the first 50: one the program does not handle ends it, and a
                    # recording that stops early says why here)
                    self.faults += 1
                    if self.faults <= 50:
                        first = "first" if ev.u.Exception.dwFirstChance else "SECOND"
                        ref = at - self.delta if self.base <= at < self.base + self.image_size else at
                        print(f"shadow32: exception {ec:08x} ({first} chance) at {ref:#x} on thread "
                              f"{ev.dwThreadId} after {self.n} calls", file=sys.stderr, flush=True)
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
    ap.add_argument("--watch", metavar="GLOBAL:OFF,...",
                    help="hardware write watches (up to 4) at the object a reference global points to, "
                         "plus each offset, all hex: 1371288:48,4c,50,54. Armed once the global is set "
                         "(checked at each breakpoint); each write logged with the instruction after it")
    ap.add_argument("--secs", type=int, default=0, help="stop after this many seconds (0: no limit)")
    ap.add_argument("--sites", metavar="FILE",
                    help="each indirect call site and the functions it reached, merged into FILE (JSON): "
                         "protos32's call-site shapes from the callees the reference really called")
    ap.add_argument("--watch-only", action="store_true",
                    help="with --watch and --from: arm the watch when --from's function is reached and "
                         "nothing else, recording no calls: the reference at full speed")
    ap.add_argument("--fake-cursor", metavar="X,Y",
                    help="the reference's GetCursorPos answers with this client point of its window: hover and "
                         "clicks (posted to the window) tried without moving anyone's mouse, as the port's "
                         "<ENV>_VCURSOR")
    ap.add_argument("--from", dest="start",help="start recording when this reference address (hex) is first "
                                                  "called, running at full speed until then")
    ap.add_argument("--inproc", action="store_true",
                    help="record in the reference itself (shadow32dll): many times faster. The trace goes to "
                         "SHADOW_OUT, the function table to SHADOW_TABLE, both set by the caller (and in the "
                         "port's run too); SHADOW_FROM, SHADOW_MAX and SHADOW_PER_FUNCTION as --from, --max and "
                         "--per-function")
    ap.add_argument("args", nargs=argparse.REMAINDER, help="-- then the program's own arguments")
    a = ap.parse_args()
    a.until = int(a.until, 16) if a.until else None
    a.start = int(a.start, 16) if a.start else None
    exe = a.exe or str(project.EXE)
    prog_args = a.args[1:] if a.args and a.args[0] == "--" else a.args
    cmdline = " ".join([f'"{exe}"'] + [f'"{x}"' if " " in x else x for x in prog_args])
    import os
    if a.inproc:
        inproc_run(exe, cmdline, os.getcwd(), a)
        return
    sh = Shadow(exe, cmdline, os.getcwd(), a)
    with open(a.out, "wb") as f:
        sh.out = f
        try:
            sh.run()
        finally:
            # (what is left of the records, also when the run ends in an exception)
            f.write(sh.records)
            sh.records = bytearray()
    print(f"shadow32: wrote {sh.n} calls to {a.out}", file=sys.stderr)
    if a.sites and sh.sites is not None:
        path = Path(a.sites)
        have = json.loads(path.read_text()) if path.exists() else {}
        for site, ts in sh.sites.items():
            k = f"0x{site:x}"
            have[k] = sorted(set(have.get(k, [])) | {f"0x{t:x}" for t in ts})
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(dict(sorted(have.items(), key=lambda x: int(x[0], 16))), indent=0))
        os.replace(tmp, path)
        print(f"shadow32: {len(sh.sites)} indirect call sites seen, {len(have)} in {path}", file=sys.stderr)


if __name__ == "__main__":
    main()
