"""Every function's calling convention and parameters on a 32-bit x86 image, read off its
instructions: build/facts/protos.json (protos.py's x86 counterpart; protos.py runs this when the
project's arch is "x86").

MSVC's 32-bit conventions differ in who cleans the stack and which registers carry arguments:
__cdecl (stack, the caller cleans up), __stdcall (stack, the callee: `ret N`), __thiscall (`this`
in ecx, the rest as __stdcall) and __fastcall (ecx and edx, the rest as __stdcall). Built with
whole-program optimization (/LTCG), the compiler also gives internal functions conventions of its
own, arguments in any register (`test dl, dl` and `mov [eax], dx` before either is written, at
the entry of functions the standard conventions cannot describe). Ghidra's analysis leaves 99% of
this beta client's functions "unknown" (2026-10-23). So, per function:

1. Its stack cleanup: the N of its `ret N` (0 for a plain ret), or its tail-jump target's.
2. One forward pass over its control flow, the state at each instruction being which of eax, ecx,
   edx, ebx, esi, edi are written on every path from the entry (must-define), and esp and ebp as offsets from the
   entry esp (unknown where paths disagree). esp follows pushes, pops, `sub/add esp`, frame setup
   (`mov ebp, esp`, `leave`, `lea esp, [ebp - k]`), MSVC's frame helpers (`__SEH_prolog4` and
   `__EH_prolog3` leave ebp at entry - 4) and `_alloca_probe` (`mov eax, N; call`), and each
   callee's cleanup. A callee whose cleanup is unknown (an import, a call through a register) is
   taken to pop what was pushed for it unless the caller then does `add esp, k`.
3. A read of one of them where it is not yet written is a register parameter (not `push reg`:
   that saves a register, or reserves a local); a memory read above the return address
   ([entry esp + 4] up, through esp or ebp) is a stack parameter.
4. A fixpoint across direct calls and tail jumps: a callee's register inputs are its caller's too
   where the caller had not written them (a `this` handed down).

Then: ecx and edx inputs -> __fastcall; ecx alone -> __thiscall; none, `ret N` > 0 ->
__stdcall, else __cdecl; any other set of registers -> "custom", with "regs" listing them in
order (eax, ecx, edx, ebx, esi, edi). A callee-cleanup function's stack parameters are its N bytes; a
__cdecl one's run to the highest slot it reads. A function that leaves through an indirect jump
that is no switch may read more than it shows: `open`.

    python protos32.py [--jobs N] [--show 0x4cba10 ...]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from multiprocessing import Pool

import capstone
from capstone import x86_const as X

from pebin import FACTS, Binary, disassembler, hexa, regs_access, write_facts

EAX, ECX, EDX, EBX, ESI, EDI = 1, 2, 4, 8, 16, 32
# (and the xmm registers, which /LTCG passes floats in to the functions it calls internally:
# Ghidra's `in_XMM1_Da`, a float parameter it did not know of; all of them a call's to clobber)
XMMS = [getattr(X, f"X86_REG_XMM{i}") for i in range(8)]
XMM_BITS = {r: 1 << (8 + i) for i, r in enumerate(XMMS)}
XMM_ALL = sum(XMM_BITS.values())
# (and st0, an x87 value a caller leaves on the register stack for it: Ghidra's in_ST0)
ST0 = 1 << 16
X87_LOADS = ("fld", "fild", "fldz", "fld1", "fldpi", "fldl2e", "fldl2t", "fldlg2", "fldln2", "fbld")
X87_READS = ("fst", "fstp", "fist", "fistp", "fisttp", "fadd", "fsub", "fsubr", "fmul", "fdiv", "fdivr",
             "faddp", "fsubp", "fsubrp", "fmulp", "fdivp", "fdivrp", "fcom", "fcomp", "fcompp", "fucom",
             "fucomp", "fucompp", "fcomi", "fcomip", "fucomi", "fucomip", "fxch", "fchs", "fabs", "fsqrt",
             "fsin", "fcos", "fptan", "fpatan", "frndint", "fscale", "fprem", "fprem1", "ftst", "fxam",
             "fiadd", "fisub", "fimul", "fidiv", "ficom", "ficomp", "f2xm1", "fyl2x", "fyl2xp1")
SCALAR_DEFS = {"movss", "movsd", "cvtsi2ss", "cvtsi2sd", "cvtss2sd", "cvtsd2ss", "sqrtss", "sqrtsd",
               "rsqrtss", "rcpss", "movd", "movq", "cvttsd2si", "roundss", "roundsd"}
ALL = 63 | XMM_ALL | ST0
VOLATILE = EAX | ECX | EDX | XMM_ALL | ST0    # a call's to clobber (st0: its float result)
REG_NAMES = [(EAX, "eax"), (ECX, "ecx"), (EDX, "edx"), (EBX, "ebx"), (ESI, "esi"), (EDI, "edi")] + \
    [(1 << (8 + i), f"xmm{i}") for i in range(8)] + [(ST0, "st0")]
REG_BITS = {X.X86_REG_EAX: EAX, X.X86_REG_AX: EAX, X.X86_REG_AL: EAX, X.X86_REG_AH: EAX,
            X.X86_REG_ECX: ECX, X.X86_REG_CX: ECX, X.X86_REG_CL: ECX, X.X86_REG_CH: ECX,
            X.X86_REG_EDX: EDX, X.X86_REG_DX: EDX, X.X86_REG_DL: EDX, X.X86_REG_DH: EDX,
            X.X86_REG_EBX: EBX, X.X86_REG_BX: EBX, X.X86_REG_BL: EBX, X.X86_REG_BH: EBX,
            X.X86_REG_ESI: ESI, X.X86_REG_SI: ESI, X.X86_REG_EDI: EDI, X.X86_REG_DI: EDI, **XMM_BITS}
FULL = {X.X86_REG_EAX: EAX, X.X86_REG_ECX: ECX, X.X86_REG_EDX: EDX, X.X86_REG_EBX: EBX,
        X.X86_REG_ESI: ESI, X.X86_REG_EDI: EDI}
END = {"ret", "retf", "int3", "ud2", "hlt", "iretd"}
FRAME_HELPERS = ("SEH_prolog", "EH_prolog")
ALLOCA = ("alloca_probe", "chkstk")

_b: Binary | None = None
_names: dict[int, str] = {}
_cleanup: dict[int, int] = {}
_noreturn: set[int] = set()
_imp_cleanup: dict[int, int] = {}    # import slot -> the bytes the import pops
_cdecl_args: dict[int, int] = {}     # a __cdecl function -> its stack parameter bytes (the last run's)


def _init(names, cleanup, noreturn, imp_cleanup, cdecl_args=None):
    global _b, _names, _cleanup, _noreturn, _imp_cleanup, _cdecl_args
    _b = Binary()
    _names, _cleanup, _noreturn, _imp_cleanup = names, cleanup, noreturn, imp_cleanup
    _cdecl_args = cdecl_args or {}


def decode(b: Binary, root: int, ranges, md):
    """{address: capstone insn} over a function's ranges."""
    out = {}
    for lo, hi in ranges:
        o = b.off(lo)
        for ins in md.disasm(bytes(b.image[o:o + (hi - lo)]), lo):
            if ins.mnemonic != "ret" and ins.mnemonic.endswith(" ret"):
                # (`repz ret`, the CRT's two-byte return, is a ret: decoded without its prefix, at
                # the same address. Read as something else, __security_check_cookie returned
                # nowhere, was noreturn, and 8,878 callers lost what follows the check)
                ins = next(md.disasm(bytes(b.image[b.off(ins.address) + 1:b.off(ins.address) + ins.size]),
                                     ins.address), ins)
            out[ins.address] = ins
    return out


def ret_bytes(insns) -> int | None:
    """The function's own `ret N` (the largest, where they differ), or None without a ret."""
    ns = [ins.operands[0].imm if ins.operands else 0 for ins in insns.values() if ins.mnemonic == "ret"]
    return max(ns) if ns else None


def _target(ins) -> int | None:
    if ins.operands and ins.operands[0].type == X.X86_OP_IMM:
        return ins.operands[0].imm & 0xFFFFFFFF
    return None


def analyse(root: int, ranges):
    """Local facts of one function: register inputs, highest stack slot read, calls/tail jumps
    with the registers not yet written there, open, stack-tracking losses."""
    b = _b
    md = disassembler()
    md.detail = True
    insns = decode(b, root, ranges, md)
    order = sorted(insns)
    nxt = {a: order[i + 1] if i + 1 < len(order) else None for i, a in enumerate(order)}
    prv = {a: order[i - 1] if i else None for i, a in enumerate(order)}
    entry_state = (0, 0, None, 0)            # written mask, esp, ebp, bytes pushed since the last call
    state = {root: entry_state}
    work = [root]
    inputs = 0
    stack_hi = 0                              # highest entry-relative byte read above the return address
    addr_taken = False                        # `lea r, [param]`: the parameter block as an array (varargs)
    calls = []                                # (target, undefined mask, "call"/"jmp")
    open_ = False
    lost = 0
    indirect_jumps = []
    anchor = [None]                           # ebx's entry-relative esp where it anchors the frame

    def merge(a, s):
        old = state.get(a)
        if old is None:
            state[a] = s
            work.append(a)
            return
        new = (old[0] & s[0], old[1] if old[1] == s[1] else None, old[2] if old[2] == s[2] else None,
               old[3] if old[3] == s[3] else 0)
        if new != old:
            state[a] = new
            work.append(a)

    def visit(a):
        nonlocal inputs, stack_hi, addr_taken, open_, lost
        mask, esp, ebp, pushed = state[a]
        ins = insns[a]
        mn = ins.mnemonic
        ops = ins.operands
        reads, writes = regs_access(ins)
        # (instructions that only write their register, whatever it held: `xor r, r`, `sub r, r`,
        # `sbb r, r` (the carry), `or r, -1`, `and r, 0`)
        same = len(ops) == 2 and ops[0].type == ops[1].type == X.X86_OP_REG and ops[0].reg == ops[1].reg
        constant = len(ops) == 2 and ops[0].type == X.X86_OP_REG and ops[1].type == X.X86_OP_IMM \
            and ((mn == "or" and ops[1].imm & 0xFFFFFFFF in (0xFFFFFFFF, 0xFF, 0xFFFF)) or (mn == "and" and ops[1].imm == 0))
        zero_idiom = (mn in ("xor", "sub", "sbb", "xorps", "xorpd", "pxor", "subps", "pcmpeqd") and same) or constant
        # (and the ones that do nothing: the CRT's hot-patch `mov edi, edi`, alignment filler
        # `lea ebx, [ebx]`. Read as reads, sprintf_s took edi, and so did its 7,953 callers)
        nop = (mn == "mov" and same) or (mn == "lea" and len(ops) == 2 and ops[1].type == X.X86_OP_MEM
                                         and ops[1].mem.base == ops[0].reg and not ops[1].mem.index
                                         and not ops[1].mem.disp)
        # (`push reg` saves a callee-saved register, or is how MSVC reserves a 4-byte local
        # (`push ecx`): a read of nothing anyone passed. A `this` saved that way is read again
        # from the slot, not from ecx, so it shows elsewhere)
        reserve = mn == "push" and ops and ops[0].type == X.X86_OP_REG and ops[0].reg in FULL
        # (a scalar SSE write keeps the register's upper lanes, so it reads it too, to the decoder:
        # `movss xmm1, [m]`, `cvtsi2ss xmm1, eax`. It defines lane 0, the float a parameter is:
        # no read of an input. Read so, 126 functions had in_XMM1_Da)
        scalar_def = mn in SCALAR_DEFS and ops and ops[0].type == X.X86_OP_REG and ops[0].reg in XMM_BITS \
            and not (len(ops) > 1 and ops[1].type == X.X86_OP_REG and ops[1].reg == ops[0].reg)
        if not zero_idiom and not reserve and not nop:
            for r in reads:
                bit = REG_BITS.get(r)
                if scalar_def and r == ops[0].reg:
                    continue
                if bit and not mask & bit:
                    inputs |= bit
        # (st0: read by an x87 instruction before anything loaded it, an input; a load defines it)
        if mn in X87_READS and not mask & ST0:
            inputs |= ST0
        if mn in X87_LOADS or mn in X87_READS:
            mask |= ST0
        # stack parameter reads (and lea of their address)
        # (and through ebx where it anchors a realigned frame: `push ebx; mov ebx, esp; sub esp, 8;
        # and esp, -16`, the parameters then at [ebx + 8] up: 0 parameters, and the decompiler's
        # in_stack_00000004, in the x87/SSE math functions, 2026-10-23)
        if mn == "mov" and len(ops) == 2 and ops[0].type == ops[1].type == X.X86_OP_REG \
                and ops[0].reg == X.X86_REG_EBX and ops[1].reg == X.X86_REG_ESP and esp is not None:
            anchor[0] = esp
        for op in ops:
            if op.type != X.X86_OP_MEM:
                continue
            base = op.mem.base
            at = esp if base == X.X86_REG_ESP else ebp if base == X.X86_REG_EBP else \
                anchor[0] if base == X.X86_REG_EBX else None
            if at is None or op.mem.index:
                continue
            off = at + op.mem.disp
            if off >= 4:
                stack_hi = max(stack_hi, off + (op.size or 4))
                if mn == "lea":
                    addr_taken = True
        # registers written (a full write defines; partial writes do not)
        # (a byte or word write defines the register too: `mov bl, [edi]; test bl, bl` read
        # its own byte, and counted as wanting ebx in 2,383 functions. Code that writes the low
        # part and then reads the whole, its upper part an input, is not what compilers emit)
        # (a no-op defines nothing either: the CRT's parse_cmdline opens with `mov edi, edi` and
        # takes its argument count's address in edi, which that wrote over in this analysis)
        for r in writes if not nop else ():
            if r in REG_BITS:
                mask |= REG_BITS[r]
        # esp / ebp
        if mn == "push":
            esp = None if esp is None else esp - (op_size(ops[0]) if ops else 4)
            # (outstanding argument bytes: a register saved while it holds its entry value is no
            # argument, nor is a local reserved so)
            # (nor the frame pointer's save, `push ebp`)
            frame = ops and ops[0].type == X.X86_OP_REG and ops[0].reg == X.X86_REG_EBP
            if not (reserve and not mask & FULL[ops[0].reg]) and not frame:
                pushed += 4
        elif mn == "pop":
            if ops and ops[0].type == X.X86_OP_REG and ops[0].reg == X.X86_REG_EBP:
                ebp = None
            esp = None if esp is None else esp + 4
            pushed = max(0, pushed - 4)
        elif mn in ("pushal", "pushad"):
            esp = None if esp is None else esp - 32
        elif mn in ("popal", "popad"):
            esp = None if esp is None else esp + 32
        elif mn in ("pushfd", "pushf"):
            esp = None if esp is None else esp - 4
        elif mn in ("popfd", "popf"):
            esp = None if esp is None else esp + 4
        elif mn == "leave":
            esp = None if ebp is None else ebp + 4
            ebp = None
        elif len(ops) == 2 and ops[0].type == X.X86_OP_REG and ops[0].reg == X.X86_REG_ESP:
            src = ops[1]
            if mn in ("sub", "add") and src.type == X.X86_OP_IMM and esp is not None:
                esp += -src.imm if mn == "sub" else src.imm
                # (right after a call, its arguments' cleanup: the call consumed them already)
                after_call = prv[a] is not None and insns[prv[a]].mnemonic == "call" \
                    and prv[a] + insns[prv[a]].size == a
                if mn == "add" and not after_call:
                    pushed = max(0, pushed - src.imm)
            elif mn == "mov" and src.type == X.X86_OP_REG and src.reg == X.X86_REG_EBP:
                esp = ebp
            elif mn == "lea" and src.type == X.X86_OP_MEM and src.mem.base == X.X86_REG_EBP and not src.mem.index:
                esp = None if ebp is None else ebp + src.mem.disp
            elif mn == "lea" and src.type == X.X86_OP_MEM and src.mem.base == X.X86_REG_ESP and not src.mem.index:
                esp = None if esp is None else esp + src.mem.disp
            else:
                esp = None                    # `and esp, -16` and the like
        elif len(ops) == 2 and ops[0].type == X.X86_OP_REG and ops[0].reg == X.X86_REG_EBP:
            src = ops[1]
            if mn == "mov" and src.type == X.X86_OP_REG and src.reg == X.X86_REG_ESP:
                ebp = esp
            elif mn == "lea" and src.type == X.X86_OP_MEM and src.mem.base == X.X86_REG_ESP and not src.mem.index:
                ebp = None if esp is None else esp + src.mem.disp
            else:
                ebp = None
        elif X.X86_REG_EBP in writes or X.X86_REG_ESP in writes and mn not in ("call", "ret", "jmp"):
            if X.X86_REG_EBP in writes:
                ebp = None
            if X.X86_REG_ESP in writes and mn not in ("call", "ret", "jmp", "push", "pop"):
                esp = None

        succ = []
        fall = nxt[a] if nxt[a] == a + ins.size else None
        if mn == "call":
            t = _target(ins)
            name = _names.get(t, "") if t is not None else ""
            if t is not None:
                calls.append((t, ~mask & ALL, "call"))
            if t is not None and any(h in name for h in FRAME_HELPERS):
                # the helper builds the frame: ebp at entry - 4, esp below the locals (and what
                # was pushed for it is frame now)
                ebp, esp = -4, None
                pushed = 0
            elif t is not None and any(h in name for h in ALLOCA):
                prev = insns.get(prv[a]) if prv[a] is not None else None
                if esp is not None and prev is not None and prev.mnemonic == "mov" and prev.operands \
                        and prev.operands[0].type == X.X86_OP_REG and prev.operands[0].reg == X.X86_REG_EAX \
                        and prev.operands[1].type == X.X86_OP_IMM:
                    esp -= prev.operands[1].imm
                else:
                    esp = None
            else:
                clean = _cleanup.get(t) if t is not None else None
                slot = import_slot(insns, prv, a) if t is None else None
                if slot is not None:
                    clean = _imp_cleanup.get(slot)
                known = clean
                if clean is None:
                    # unknown: the callee popped what was pushed for it, unless the caller now
                    # cleans up itself
                    after = insns.get(fall) if fall else None
                    cdecl = after is not None and after.mnemonic == "add" and after.operands \
                        and after.operands[0].type == X.X86_OP_REG and after.operands[0].reg == X.X86_REG_ESP
                    # (what was pushed for it, not what the next call takes: next_call_deficit)
                    clean = 0 if cdecl else max(0, pushed - next_call_deficit(insns, prv, nxt, a))
                    known = clean if not cdecl and t is None else None
                if esp is not None:
                    esp += clean
                # (each call consumes its own arguments, and what was pushed before them for a
                # later call stays outstanding: `push _freefls; push [FlsAlloc]; call
                # DecodePointer; call eax`, and `push [__flsindex]; call __get_flsgetvalue; call
                # eax`. A callee that pops its own takes what it pops; a __cdecl one the
                # caller's `add esp, k` right after (not subtracted again there), or else its
                # parameter bytes as the last run found them. A call none of these tell takes
                # all of it: carried on past __cdecl calls whose cleanup is deferred, outstanding
                # bytes made saved registers arguments of later calls, 12,000 functions' unaff_)
                after = insns.get(fall) if fall else None
                if known is not None and (known or (t is None and slot is None)):
                    # (a callee that pops its own, or an indirect one taking what was pushed for
                    # it, the next call's arguments left outstanding)
                    pushed = max(0, pushed - known)
                elif after is not None and after.mnemonic == "add" and len(after.operands) == 2 \
                        and after.operands[0].type == X.X86_OP_REG and after.operands[0].reg == X.X86_REG_ESP \
                        and after.operands[1].type == X.X86_OP_IMM:
                    pushed = max(0, pushed - after.operands[1].imm)
                elif t is not None and t in _cdecl_args:
                    pushed = max(0, pushed - _cdecl_args[t])
                else:
                    pushed = 0
            mask |= VOLATILE                  # eax, ecx and edx are the callee's to clobber
            if t is not None and t in _noreturn:
                fall = None
            if fall is not None:
                succ.append(fall)
        elif mn == "jmp":
            t = _target(ins)
            if t is not None:
                if t in insns:
                    succ.append(t)
                else:
                    calls.append((t, ~mask & ALL, "jmp"))
            elif ops and ops[0].type == X.X86_OP_MEM and ops[0].mem.index and ops[0].mem.scale == 4:
                indirect_jumps.append((mask, esp, ebp))   # a switch: its targets are found below
            else:
                open_ = True
        elif mn.startswith("j") or mn.startswith("loop"):
            t = _target(ins)
            if t is not None and t in insns:
                succ.append(t)
            if fall is not None:
                succ.append(fall)
        elif mn not in END:
            if fall is not None:
                succ.append(fall)
        if esp is None and state[a][1] is not None:
            lost += 1
        for s in succ:
            merge(s, (mask, esp, ebp, pushed))

    while work:
        visit(work.pop())
    # code only a switch reaches: from the dispatching jump's state, in address order
    if indirect_jumps:
        m = ALL
        for jm, _e, _b2 in indirect_jumps:
            m &= jm
        seed = (m, indirect_jumps[0][1], indirect_jumps[0][2], 0)
        for a in order:
            if a not in state:
                merge(a, seed)
                while work:
                    visit(work.pop())
    results, passes = result_reads(insns, state, nxt)
    # (which result registers the function writes itself, anywhere: a read after a call to one
    # that writes neither is of a value the caller kept across it, /LTCG knowing the callee)
    writes_ret = 0
    # (and which volatile registers it writes at all, and whether it calls what cannot be followed,
    # for the registers it leaves as it found them: main's keep)
    vol_writes, opaque = 0, False
    for a2, ins in insns.items():
        if a2 not in state:
            continue
        if ins.mnemonic == "call" and _target(ins) is None:
            opaque = True
        elif ins.mnemonic == "jmp" and _target(ins) is None:
            opaque = True
        if ins.mnemonic in ("push", "call", "jmp"):
            continue
        for x in regs_access(ins)[1]:
            vol_writes |= EAX if x in EAX_REGS else EDX if x in EDX_REGS else \
                ECX if x in (X.X86_REG_ECX, X.X86_REG_CX, X.X86_REG_CL, X.X86_REG_CH) else 0
    for ins in insns.values():
        if ins.mnemonic in ("push", "call"):
            continue
        w = regs_access(ins)[1]
        if any(x in EAX_REGS for x in w):
            writes_ret |= EAX
        if any(x in EDX_REGS for x in w):
            writes_ret |= EDX
        if ins.mnemonic.startswith("fld") or ins.mnemonic.startswith("fild"):
            writes_ret |= 64
    labels = {_target(i) for i in insns.values() if i.mnemonic.startswith("j") or i.mnemonic.startswith("loop")}
    inputs |= pushed_inputs(insns, prv, nxt, state, labels)
    icalls = {a: icall_shape(insns, prv, nxt, state, a, labels, bool(inputs & ECX)) for a in state
              if insns[a].mnemonic == "call" and _target(insns[a]) is None and import_slot(insns, prv, a) is None}
    return {"inputs": inputs, "stack_hi": stack_hi, "addr_taken": addr_taken, "calls": calls,
            "open": open_, "lost": lost, "ret": ret_bytes(insns), "visited": len(state), "insns": len(insns),
            "icalls": {a: s for a, s in icalls.items() if s is not None},
            "results": {t: k for t, k in results.items() if not isinstance(t, tuple)},
            # (an indirect call's x87 result, for its call-site signature: `(float)extraout_ST0`
            # after a virtual getter of a float, 305 stubs, 2026-10-23)
            "icall_rets": {t[1]: k for t, k in results.items() if isinstance(t, tuple) and k in ("f4", "d8")},
            "passes": passes, "writes_ret": writes_ret, "vol_writes": vol_writes, "opaque": opaque}


EAX_REGS = {X.X86_REG_EAX, X.X86_REG_AX, X.X86_REG_AL, X.X86_REG_AH}
EDX_REGS = {X.X86_REG_EDX, X.X86_REG_DX, X.X86_REG_DL, X.X86_REG_DH}


def result_reads(insns, state, nxt):
    """What this function does with each direct callee's result: {callee: kind} for a result
    it reads (eax "i4", edx:eax "i8", st0 "f4"/"d8" by its first store's width), and the callees
    whose result it returns as its own (eax untouched up to a ret, or a tail jump). Ghidra left
    most x86 functions' returns void, and a caller's read of eax after the call was then nothing:
    the allocator FUN_004067a0 and its wrapper FUN_00406bb0 returned void, and the memory
    manager's setup stored their 0 (2026-10-23). Read off the instructions after the call, in a
    straight line: eax or edx read before written, an x87 instruction taking st0."""
    reads: dict[int, str] = {}
    passes: list[int] = []
    for a, ins in insns.items():
        t = _target(ins)
        if a not in state:
            continue
        if t is None:
            # (an indirect call's: by its address, for its call-site signature)
            if ins.mnemonic != "call":
                continue
            t = ("site", a)
        if ins.mnemonic == "jmp":
            if not isinstance(t, tuple) and t not in insns:
                passes.append(t)
            continue
        if ins.mnemonic != "call" or t in _noreturn:
            continue
        p = nxt[a]
        eax_w = edx_w = False
        kind = None
        end = a + ins.size
        for _ in range(12):
            # (the next instruction only where the last one ends: across a gap in the decode, a
            # function range Ghidra cut short, the bytes are misread)
            if p != end:
                break
            if p in insns:
                end = p + insns[p].size
            # (reachable code only: after a call the decoder took for one that returns, the bytes
            # that follow can be data, `add byte ptr [eax], al; add dh, al` after a free wrapper
            # made it an edx:eax one, 2026-10-23)
            if p is None or p not in insns or p not in state:
                break
            pi = insns[p]
            mn = pi.mnemonic
            if mn == "ret":
                if not eax_w and not isinstance(t, tuple):
                    passes.append(t)
                break
            if mn.startswith("f") and not mn.startswith("fn"):
                # (st0: the callee's x87 result, if the first x87 instruction reads it)
                if mn in ("fstp", "fst", "fcomp", "fcom", "fxch", "fadd", "fmul", "fsub", "fdiv",
                          "fistp", "fist", "fchs", "fabs", "fsqrt", "fucomp", "fucom", "fcomip", "fucomip",
                          "faddp", "fmulp", "fsubp", "fsubrp", "fdivp", "fdivrp", "fcompp", "fucompp", "ftst"):
                    width = pi.operands[0].size if pi.operands and pi.operands[0].type == X.X86_OP_MEM else 8
                    kind = kind or ("f4" if width == 4 else "d8")
                break
            if mn in ("call", "jmp") or mn.startswith("j") or mn.startswith("loop"):
                break
            r, w = regs_access(pi)
            ops = pi.operands
            # (`xor r, r`, `sub r, r`, `sbb r, r` only write r: `cmp ecx, edi; sbb edx, edx` after
            # a call is no read of an edx result)
            zero = len(ops) == 2 and ops[0].type == ops[1].type == X.X86_OP_REG and ops[0].reg == ops[1].reg \
                and mn in ("xor", "sub", "sbb")
            if not zero:
                # (as wide as the caller reads it: `test al, al` of a bool, all of eax of a
                # pointer. Taken as 4 bytes, a byte result's upper three were what eax held on
                # entry: `CONCAT31((int3)((uint)in_EAX >> 8), bVar1)`, 900 stubs, 2026-10-23)
                if not eax_w and kind in (None, "i1", "i2", "i4"):
                    for x in r:
                        if x in EAX_REGS:
                            width = 4 if x == X.X86_REG_EAX else 2 if x == X.X86_REG_AX else 1
                            if kind is None or int(kind[1]) < width:
                                kind = f"i{width}"
                if not edx_w and any(x in EDX_REGS for x in r) and kind in ("i1", "i2", "i4", None):
                    kind = "i8"
            # (a byte or word write defines the register too, as in analyse: the caller's `mov dl,
            # [esi + 0xfb]` after FUN_004296a0, then dl read, made the allocator an edx:eax one)
            if any(x in EAX_REGS for x in w):
                eax_w = True
            if any(x in EDX_REGS for x in w):
                edx_w = True
            if eax_w and edx_w:
                break
            p = nxt[p]
        if kind is not None:
            old = reads.get(t)
            reads[t] = kind if old is None or RET_RANK[kind] > RET_RANK[old] else old
    return reads, passes


# a return's kinds, the wider winning where callers differ
RET_RANK = {"i1": 1, "i2": 2, "i4": 3, "f4": 4, "d8": 4, "i8": 5}


def pushed_inputs(insns, prv, nxt, state, labels) -> int:
    """The registers a function passes on as stack arguments before writing them: `push ecx` among
    the pushes a call takes is the caller's ecx handed over, not a save. FUN_00403720 builds a
    string with `push edx; push eax; push ecx; mov ecx, esi; call FUN_00403430` (a __thiscall of
    12 bytes): its own ecx was the third argument, and without it as an input the decompiler had
    `in_ECX` (2026-10-23). A call's arguments are the last pushes before it in its block, as many
    as it pops (`ret N`, or the caller's `add esp, N` after)."""
    found = 0
    for a, ins in insns.items():
        if ins.mnemonic != "call" or a not in state:
            continue
        t = _target(ins)
        n = _cleanup.get(t) if t is not None else None
        after = insns.get(nxt[a]) if nxt[a] is not None else None
        if after is not None and after.mnemonic == "add" and len(after.operands) == 2 \
                and after.operands[0].type == X.X86_OP_REG and after.operands[0].reg == X.X86_REG_ESP \
                and after.operands[1].type == X.X86_OP_IMM:
            n = after.operands[1].imm
        if not n:
            continue
        left, q, p = n // 4, a, prv[a]
        while left > 0 and p is not None and p in insns and q not in labels:
            pi = insns[p]
            mn = pi.mnemonic
            if mn in ("call", "jmp", "ret", "pop") or mn.startswith("j") or any(
                    o.type == X.X86_OP_REG and o.reg == X.X86_REG_ESP for o in pi.operands):
                break
            if mn == "push":
                left -= 1
                o = pi.operands[0] if pi.operands else None
                if o is not None and o.type == X.X86_OP_REG and o.reg in FULL and p in state \
                        and not state[p][0] & FULL[o.reg]:
                    found |= FULL[o.reg]
            q, p = p, prv[p]
    return found


def _iat_slot(op) -> int | None:
    if op is not None and op.type == X.X86_OP_MEM and not op.mem.base and not op.mem.index \
            and _b.iat[0] <= op.mem.disp & 0xFFFFFFFF < _b.iat[1]:
        return op.mem.disp & 0xFFFFFFFF
    return None


def import_slot(insns, prv, a) -> int | None:
    """The import slot a call goes through: `call [__imp_X]`, or `call r` of an `mov r,
    [__imp_X]` before it (MSVC loads an import it calls repeatedly into a callee-saved register:
    _mtinit's `mov edi, [__imp_DecodePointer]; ...; call edi`). Ghidra types either from the
    import's signature."""
    ins = insns[a]
    op = ins.operands[0] if ins.operands else None
    slot = _iat_slot(op)
    if slot is not None or op is None or op.type != X.X86_OP_REG:
        return slot
    reg = op.reg
    p = prv[a]
    for _ in range(96):
        if p is None or p not in insns:
            return None
        pi = insns[p]
        if pi.mnemonic in ("ret", "jmp"):
            return None
        _r, w = regs_access(pi)
        if reg in w:
            if pi.mnemonic == "mov" and len(pi.operands) == 2:
                return _iat_slot(pi.operands[1])
            return None
        if pi.mnemonic == "call" and reg not in (X.X86_REG_EBX, X.X86_REG_ESI, X.X86_REG_EDI, X.X86_REG_EBP):
            return None                            # (a call clobbers eax, ecx and edx)
        p = prv[p]
    return None


def import_call(ins) -> bool:
    """`call [__imp_X]`: an import's slot, which Ghidra types from the import's signature."""
    return _iat_slot(ins.operands[0] if ins.operands else None) is not None


ICALL_WINDOW = 48


def virtual_call(insns, prv, a) -> bool:
    """`call [r + K]`, or `call r` of `mov r, [r2 + K]`, where r2 (or r) was loaded from `[r3]`:
    a slot of a vtable an object points to."""
    def loaded(reg, at, deref_only):
        """Whether reg's last write before `at` (in a short scan back) is a load from memory
        through a register: [base + K] (any K), or [base] alone when deref_only."""
        p = prv[at]
        for _ in range(16):
            if p is None or p not in insns:
                return None
            ins = insns[p]
            if ins.mnemonic in ("call", "jmp", "ret"):
                return None
            _r, w = regs_access(ins)
            if reg in w:
                ops = ins.operands
                if ins.mnemonic == "mov" and len(ops) == 2 and ops[1].type == X.X86_OP_MEM \
                        and ops[1].mem.base and not ops[1].mem.index and (not deref_only or not ops[1].mem.disp):
                    return p, ops[1].mem.base
                return None
            p = prv[p]
        return None
    op = insns[a].operands[0] if insns[a].operands else None
    if op is None:
        return False
    if op.type == X.X86_OP_MEM and op.mem.base and not op.mem.index:
        vt = op.mem.base
        at = a
    elif op.type == X.X86_OP_REG:
        got = loaded(op.reg, a, False)
        if got is None:
            return False
        at, vt = got
    else:
        return False
    return loaded(vt, at, True) is not None


def icall_shape(insns, prv, nxt, state, a, labels, own_this):
    """An indirect call's convention and stack arguments, as its caller sets it up: (cc, n).
    Ghidra's decompiler gives such a call the arguments it sees pushed and nothing in ecx, so a
    virtual call lost its object: F_00405f60's `(*(vt + 0x14))(8, 0, 1)` of an allocator took 8 for
    `this` (2026-10-23). ecx written since the last call, and not pushed since, is `this`
    (__thiscall), and so is a method's own ecx that nothing has clobbered yet (`mov esi, ecx; mov
    eax, [esi]; call [eax + 0x2ac]`); otherwise the arguments are on the stack alone. A caller's
    `add esp, k` after the call is a __cdecl call of k bytes; without one the callee pops the
    argument bytes outstanding at the call (analyse's count: pushes, less what each call before
    popped, a register saved while it holds its entry value not among them). Counted back only to
    the previous call, `push _freefls; push [FlsAlloc]; call DecodePointer; call eax` gave
    FlsAlloc no argument and DecodePointer two, and _mtinit failed (R6016, 2026-10-23)."""
    after = insns.get(nxt[a]) if nxt[a] is not None else None
    k = None
    if after is not None and after.mnemonic == "add" and len(after.operands) == 2 \
            and after.operands[0].type == X.X86_OP_REG and after.operands[0].reg == X.X86_REG_ESP \
            and after.operands[1].type == X.X86_OP_IMM:
        k = after.operands[1].imm
    # ecx: written in the scan back to the previous call, and not pushed after its write
    ecx_set, ecx_pushed = False, False
    p = prv[a]
    for _ in range(ICALL_WINDOW):
        if p is None or p not in insns:
            break
        ins = insns[p]
        mn = ins.mnemonic
        if mn in ("call", "jmp", "ret", "int3"):
            break
        ops = ins.operands
        if mn == "push":
            if ops and ops[0].type == X.X86_OP_REG and ops[0].reg == X.X86_REG_ECX:
                ecx_pushed = True
        elif mn == "pop":
            if ops and ops[0].type == X.X86_OP_REG and ops[0].reg == X.X86_REG_ECX:
                break                              # (`pop ecx`: a __cdecl call's cleanup, no `this`)
        elif any(REG_BITS.get(r) == ECX for r in regs_access(ins)[1]):
            ecx_set = not ecx_pushed
            break
        p = prv[p]
    # (the method's own `this`, still in ecx: nothing wrote ecx since the entry, calls included,
    # and the call a virtual one, through a slot of a vtable loaded from an object. `mov edi,
    # [__imp_CloseHandle]; ...; call edi` is no method's, and took `this` for its handle)
    if not ecx_set and not ecx_pushed and own_this and a in state and not state[a][0] & ECX \
            and virtual_call(insns, prv, a):
        ecx_set = True
    if k is not None:
        return ("__cdecl", k // 4)                 # (ecx then a scratch register: a variadic
                                                   # method passes `this` on the stack)
    if a not in state:
        return None
    n = max(0, state[a][3] - next_call_deficit(insns, prv, nxt, a))
    return ("__thiscall" if ecx_set else "__stdcall", n // 4)


def next_call_deficit(insns, prv, nxt, a) -> int:
    """The bytes the next call after `a` (in a straight line) takes beyond what is pushed between
    the two: arguments pushed for an outer call before an inner one is made. `push 2; push 0xcf;
    call [vt + 0x3c]; mov ecx, eax; call FUN_0043c920` (ret 8) is `FUN_0043c920(getter(), 0xcf, 2)`:
    taken as the getter's, the 8 bytes made FUN_0043c920's arguments of the caller's saved
    registers, 2,200 functions' unaff_ (2026-10-23)."""
    p, end, after = nxt[a], a + insns[a].size, 0
    for _ in range(24):
        if p is None or p != end or p not in insns:
            return 0
        pi = insns[p]
        end = p + pi.size
        if pi.mnemonic == "push":
            after += 4
        elif pi.mnemonic == "pop":
            after -= 4
        elif pi.mnemonic in ("ret", "jmp") or pi.mnemonic.startswith("j"):
            return 0
        elif any(o.type == X.X86_OP_REG and o.reg == X.X86_REG_ESP for o in pi.operands) and pi.mnemonic != "call":
            return 0                                   # (esp adjusted otherwise: no telling)
        elif pi.mnemonic == "call":
            t = _target(pi)
            take = _cleanup.get(t) if t is not None else None
            if t is None:
                slot = import_slot(insns, prv, p)
                take = _imp_cleanup.get(slot) if slot is not None else None
            nx = insns.get(nxt[p]) if nxt[p] is not None else None
            if not take and nx is not None and nx.mnemonic == "add" and len(nx.operands) == 2 \
                    and nx.operands[0].type == X.X86_OP_REG and nx.operands[0].reg == X.X86_REG_ESP \
                    and nx.operands[1].type == X.X86_OP_IMM:
                take = nx.operands[1].imm
            if not take and t is not None:
                take = _cdecl_args.get(t)
            return max(0, (take or 0) - after)
        p = nxt[p]
    return 0


def code_pointers(b: Binary) -> set[int]:
    """The code no function covers that the image points to: a relocated pointer into .text in
    data (the CRT's __xi_a..__xi_z initializer tables, atexit destructors, vtable slots, SEH scope
    tables) or an immediate in code (`push fn`, `mov [x], fn`: a callback handed over). Ghidra's
    analysis made none of them functions: 2,268 in the beta client, the CRT's own
    initializers among them (`__initterm_e` called 00c47d79 into int3s, 2026-10-23). A relocated
    address used as a memory operand is data (the 32-bit jump tables between functions in .text),
    and a target of zero bytes or int3 padding is no code."""
    md = disassembler()
    md.detail = True
    out = set()
    for site in b.relocs():
        if not b.is_code(site):
            t = b.ptr(site)
            if b.is_code(t) and b.func_containing(t) is None:
                out.add(t)
    for insn, t, _site in b._abs_refs(keep=lambda t: b.is_code(t) and b.func_containing(t) is None):
        o = b.off(insn)
        ins = next(md.disasm(bytes(b.image[o:o + 16]), insn, 1), None)
        if ins is not None and any(op.type == X.X86_OP_IMM and op.imm & 0xFFFFFFFF == t for op in ins.operands):
            out.add(t)
    return {t for t in out if b.image[b.off(t)] not in (0x00, 0xCC)}


def op_size(op) -> int:
    return op.size if op.size in (2, 4) else 4


def _job(item):
    root, ranges = item
    try:
        return root, analyse(root, ranges)
    except Exception as e:  # noqa: BLE001
        return root, {"error": repr(e)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=None)
    ap.add_argument("--show", nargs="*", default=[])
    ap.add_argument("--why-ret", nargs="*", default=[], metavar="ADDR",
                    help="the caller whose read typed a function's return (through the wrappers that return it)")
    args = ap.parse_args()
    t0 = time.time()

    exported = json.loads((FACTS / "functions.json").read_text())
    funcs = exported["functions"]
    imp_cleanup = {int(k, 16): v for k, v in exported.get("import_cleanup", {}).items()}
    # (each __cdecl function's stack parameter bytes, as the last run found them: what a call to
    # one consumes of what its caller pushed, analyse)
    cdecl_args = {}
    prev = FACTS / "protos.json"
    if prev.exists():
        for k, e in json.loads(prev.read_text())["functions"].items():
            if e.get("cc") == "__cdecl" or (e.get("cc") == "custom" and not e.get("callee_cleans")):
                cdecl_args[int(k, 16)] = e.get("stack", 0)
    names = {int(f["entry"], 16): f["name"] for f in funcs}
    ranges = {int(f["entry"], 16): [(int(lo, 16), int(hi, 16)) for lo, hi in f["ranges"]] for f in funcs}
    nr_path = FACTS / "noreturn.json"
    noreturn = {int(k, 16) for k in json.loads(nr_path.read_text())["functions"]} if nr_path.exists() else set()

    # 1. each function's own `ret N`, then through tail jumps (thunks) to a fixpoint
    b = Binary()
    md = disassembler()
    cleanup: dict[int, int] = {}
    tail_of: dict[int, int] = {}
    for root, rs in ranges.items():
        insns = {a: i for lo, hi in rs for a, i in ((x[0], x) for x in md.disasm_lite(
            bytes(b.image[b.off(lo):b.off(lo) + (hi - lo)]), lo))}
        ns = []
        for a, (_addr, _size, mn, ops) in insns.items():
            if mn == "ret" or mn.endswith(" ret"):         # (and `repz ret`)
                ns.append(int(ops, 16) if ops else 0)
            elif mn == "jmp" and ops.startswith("0x") and int(ops, 16) not in insns \
                    and b.is_func_start(int(ops, 16)):
                tail_of[root] = int(ops, 16)
            elif mn == "jmp" and not ns:
                # (a thunk to an import, `jmp dword ptr [__imp_send]`: the import's cleanup. Taken
                # as unknown, the 16 bytes pushed for send stayed outstanding, and the virtual call
                # after it took them as arguments, `(this, unaff_ESI, unaff_EBP, unaff_retaddr, ...)`)
                mm = re.fullmatch(r"dword ptr \[(0x[0-9a-f]+)\]", ops)
                if mm and int(mm.group(1), 16) in imp_cleanup:
                    ns.append(imp_cleanup[int(mm.group(1), 16)])
        if ns:
            cleanup[root] = max(ns)
    for _ in range(8):
        for f, t in tail_of.items():
            if f not in cleanup and t in cleanup:
                cleanup[f] = cleanup[t]

    if args.show:
        _init(names, cleanup, noreturn, imp_cleanup, cdecl_args)
        for s in args.show:
            a = int(s, 16)
            print(hexa(a), names.get(a), "cleanup", cleanup.get(a), analyse(a, ranges[a]))
        return

    # 2. local pass, in parallel
    with Pool(args.jobs, initializer=_init, initargs=(names, cleanup, noreturn, imp_cleanup, cdecl_args)) as pool:
        local = dict(pool.imap_unordered(_job, list(ranges.items()), chunksize=64))
    errors = sum(1 for v in local.values() if "error" in v)

    # the code no function covers, for ApplyFacts to make functions (prototyped on the next run,
    # over the extents then exported): what a pointer reaches, and the direct call and tail-jump
    # targets Ghidra did not follow
    pointed = code_pointers(b)
    called = {t for v in local.values() for t, _u, _k in v.get("calls", ())
              if b.is_code(t) and b.func_containing(t) is None}
    leaves = pointed | called

    # 3. register inputs through calls and tail jumps (not from a function that never returns:
    # __report_gsfailure saves every register into its crash context, and through
    # __security_check_cookie's failure jump that made all of them inputs of every caller)
    inputs = {f: v.get("inputs", 0) for f, v in local.items()}
    changed = True
    while changed:
        changed = False
        for f, v in local.items():
            for t, undef, _kind in v.get("calls", ()):
                if t in noreturn:
                    continue
                add = inputs.get(t, 0) & undef & ~inputs[f]
                if add:
                    inputs[f] |= add
                    changed = True
    # (and stack parameters through tail jumps: a thunk that builds a frame and jumps on, `push
    # ebp; mov ebp, esp; pop ebp; jmp FUN_00b9e7f0`, takes its target's)
    stack_hi = {f: v.get("stack_hi", 0) for f, v in local.items()}
    changed = True
    while changed:
        changed = False
        for f, v in local.items():
            for t, _undef, kind in v.get("calls", ()):
                if kind == "jmp" and stack_hi.get(t, 0) > stack_hi[f]:
                    stack_hi[f] = stack_hi[t]
                    changed = True

    # 3b. returns: a function returns what its callers read of it, and what a function that
    # returns its result (a wrapper, a tail jump) is read for
    rank = RET_RANK
    ret_of: dict[int, str] = {}
    why: dict[int, str] = {}
    need = {"i1": EAX, "i2": EAX, "i4": EAX, "i8": EDX, "f4": 64, "d8": 64}
    def give(t, k, src):
        v = local.get(t)
        if v is None:
            return False
        # (only a result the callee makes: it writes the register, or returns a callee's. memcpy,
        # free and __SEH_epilog4 leave edx alone, and callers keeping a value in it across them
        # made them edx:eax ones; one that writes eax but not edx is an eax one)
        if not v.get("writes_ret", 0) & need[k] and not v.get("passes"):
            if k == "i8" and v.get("writes_ret", 0) & EAX:
                k = "i4"
            else:
                return False
        if t not in ret_of or rank[k] > rank[ret_of[t]]:
            ret_of[t] = k
            why[t] = src
            return True
        return False
    for f, v in local.items():
        for t, k in v.get("results", {}).items():
            give(t, k, f"read by {hexa(f)}")
    changed = True
    while changed:
        changed = False
        for f, v in local.items():
            for t in v.get("passes", ()):
                if f in ret_of:
                    changed |= give(t, ret_of[f], f"returned by {hexa(f)}")
                # (and the other way: a function that returns a callee's result returns one. The
                # system allocator's Alloc, FUN_00404d60, returns _aligned_malloc's, and is called
                # only through its vtable, where no caller's read reaches it: void, the memory
                # manager's every allocation came back 0, 2026-10-23)
                # (eax only: memcpy and memset show as edx:eax ones, and every function that ends
                # in one became one too)
                if t in ret_of:
                    changed |= give(f, "i4" if ret_of[t] == "i8" else ret_of[t], f"returns {hexa(t)}'s")
    for s in args.why_ret:
        a = int(s, 16)
        while a in why:
            print(f"{hexa(a)} {ret_of[a]}: {why[a]}")
            nxt_a = int(why[a].split()[-1].removesuffix("'s"), 16)
            if why[a].startswith("read") or nxt_a == a:
                break
            a = nxt_a

    # 3c. the volatile registers each function leaves as it found them: written by neither it nor
    # anything it calls (a call through a pointer or to an import can write any). /LTCG knows them:
    # a caller keeps a value in ecx or edx across a call to one, and the decompiler, told each call
    # kills them, made that `extraout_ECX` (550 stubs, 2026-10-23). eax only where nothing reads a
    # result. ApplyFacts gives each a convention with them unaffected
    kills = {f: (v.get("vol_writes", 0) | (EAX | ECX | EDX if v.get("opaque") else 0)) for f, v in local.items()}
    changed = True
    while changed:
        changed = False
        for f, v in local.items():
            k = kills[f]
            for t, _u, _kind in v.get("calls", ()):
                k |= kills.get(t, EAX | ECX | EDX)
            if k != kills[f]:
                kills[f] = k
                changed = True

    # the methods: every slot of a C++ class's vtable (one whose functions read `this` in ecx; a
    # COM interface's take it on the stack, and none of its do). A method that does not use its
    # `this` reads no ecx, and showed as a __stdcall: the system allocator's Alloc, FUN_00404d60,
    # then took the virtual call's `this` for its first stack argument, everything after one off,
    # and _aligned_malloc failed (2026-10-23)
    methods: set[int] = set()
    vt_path = FACTS / "vtables.json"
    if vt_path.exists():
        for vt in json.loads(vt_path.read_text())["vtables"]:
            slots = [int(s, 16) for s in vt["slots"]]
            if any(inputs.get(s, 0) & ECX for s in slots):
                methods.update(slots)

    # 4. conventions and parameters
    out = {}
    counts: dict[str, int] = {}
    for f, v in sorted(local.items()):
        if "error" in v:
            continue
        reg = inputs[f]
        ret_n = cleanup.get(f)
        if reg == ECX | EDX:
            cc = "__fastcall"
        elif reg == ECX:
            cc = "__thiscall"
        elif reg:
            cc = "custom"
        elif ret_n and f in methods:
            cc = "__thiscall"                 # (a method that leaves its `this` alone)
        elif ret_n:
            cc = "__stdcall"
        else:
            cc = "__cdecl"
        callee_cleans = bool(ret_n) or cc in ("__fastcall", "__thiscall")
        # (a callee that pops its arguments has its `ret N` of them; one with a plain `ret`, a
        # method too, what it reads: FUN_0068aff0, a __thiscall that returns with `ret` and reads
        # [esp + 4], had none, and the decompiler's in_stack_00000004)
        stack = ret_n if callee_cleans and ret_n else max(0, stack_hi[f] - 4)
        stack = (stack + 3) & ~3
        # (at most what the language's models place: x86win.cspec's stack entry is 500 bytes, and
        # FUN_00b2f1e0's 520, assigned whole, failed its decompilation, "Cannot assign parameter
        # address")
        if not callee_cleans or not ret_n:
            stack = min(stack, 496)
        regs = [n for bit, n in REG_NAMES if reg & bit]
        params = [["i", 4]] * (len(regs) + stack // 4)
        e = {"cc": cc, "params": params, "stack": stack}
        if cc == "custom":
            e["regs"] = regs                  # the register parameters, before the stack ones
            e["callee_cleans"] = callee_cleans
        if v["open"]:
            e["open"] = True
        if v["addr_taken"]:
            e["param_addr"] = True        # `lea r, [param]`: a parameter passed by address, or a va_list
        if callee_cleans and ret_n and stack_hi[f] - 4 > ret_n:
            e["reads_beyond"] = stack_hi[f] - 4   # reads past its own cleanup: a check for later
        if ret_n is None:
            e["no_ret"] = True
        if f in ret_of:
            e["ret"] = ret_of[f]                  # what its callers read of its result
        keep = [n for bit, n in ((EAX, "eax"), (ECX, "ecx"), (EDX, "edx"))
                if not kills[f] & bit and not (bit == EAX and f in ret_of)
                and not (bit == EDX and ret_of.get(f) == "i8")]
        # (on a __cdecl or __stdcall only, and never a register it takes: a keep convention is a new
        # name, which Ghidra does not treat as __thiscall, its `this` lost, and an input register
        # kept the decompiler reads as a saved one, unaff_ECX; 10,000 stubs, 2026-10-23)
        keep = [n for n in keep if not reg & dict((nm, b) for b, nm in REG_NAMES)[n]]
        if keep and cc in ("__cdecl", "__stdcall"):
            e["keep"] = keep                      # the volatile registers it leaves alone
        out[hexa(f)] = e
        counts[cc] = counts.get(cc, 0) + 1

    path = write_facts("protos", {
        "rule": "x86 (protos32.py): ret N -> callee-cleanup stack bytes; ecx/edx read before "
                "written on some path (must-define, closed over direct calls and tail jumps) -> "
                "__thiscall / __fastcall; __cdecl stack parameters to the highest [entry esp + 4..] "
                "slot read through esp or ebp",
        "arch": "x86",
        "functions": out,
        "leaves": [hexa(g) for g in sorted(leaves)],
        "pointed": [hexa(g) for g in sorted(pointed)]})
    # each indirect call's convention and arguments: ApplyFacts' call-site signatures
    calls, ccs, rets = {}, {}, {}
    for f, v in local.items():
        for a, (cc, n) in v.get("icalls", {}).items():
            calls[hexa(a)] = [["i", 4]] * (n + (cc == "__thiscall"))
            ccs[hexa(a)] = cc
            k = v.get("icall_rets", {}).get(a)
            if k:
                rets[hexa(a)] = ["f", 4] if k == "f4" else ["d", 8]
    shapes: dict[str, int] = {}
    for cc in ccs.values():
        shapes[cc] = shapes.get(cc, 0) + 1
    write_facts("callsites", {
        "rule": "x86 (protos32.py icall_shape): ecx written since the last call and not pushed -> "
                "__thiscall, `this` first; `add esp, k` after the call -> __cdecl of k bytes; else "
                "the callee pops the arguments pushed since the last call",
        "arch": "x86", "calls": calls, "cc": ccs, "rets": rets})
    print(f"indirect calls: {shapes}", file=sys.stderr)

    print(f"returns read by callers: {dict((k, sum(1 for x in ret_of.values() if x == k)) for k in rank)}",
          file=sys.stderr)
    lost = sum(1 for v in local.values() if v.get("lost"))
    print(f"{len(out)} functions ({errors} not analysed): {counts}; esp lost in {lost}; "
          f"{sum(1 for e in out.values() if e.get('open'))} open, "
          f"{sum(1 for e in out.values() if e.get('reads_beyond'))} read past their ret N; "
          f"{len(leaves)} code no function covers ({len(pointed)} pointed to) -> {path} "
          f"({time.time() - t0:.0f}s)")


if __name__ == "__main__":
    main()
