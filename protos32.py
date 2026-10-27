"""Every function's calling convention and parameters on a 32-bit x86 image, read off its
instructions: build/facts/protos.json (protos.py's x86 counterpart; protos.py runs this when the
project's arch is "x86").

MSVC's 32-bit conventions differ in who cleans the stack and which registers carry arguments:
__cdecl (stack, the caller cleans up), __stdcall (stack, the callee: `ret N`), __thiscall (`this`
in ecx, the rest as __stdcall) and __fastcall (ecx and edx, the rest as __stdcall). Built with
whole-program optimization (/LTCG), the compiler also gives internal functions conventions of its
own, arguments in any register (`test dl, dl` and `mov [eax], dx` before either is written, at
the entry of functions the standard conventions cannot describe). Ghidra's analysis leaves 99% of
a VS2010 client's functions "unknown" (2026-10-23). So, per function:

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
import bisect
import json
import re
import sys
import time
from multiprocessing import Pool
from pathlib import Path

import project

import capstone
from capstone import x86_const as X

from pebin import FACTS, Binary, disassembler, hexa, write_facts
from pebin import regs_access as _regs_access

EAX, ECX, EDX, EBX, ESI, EDI = 1, 2, 4, 8, 16, 32
# (and the xmm registers, which /LTCG passes floats in to the functions it calls internally:
# Ghidra's `in_XMM1_Da`, a float parameter it did not know of; all of them a call's to clobber)
XMMS = [getattr(X, f"X86_REG_XMM{i}") for i in range(8)]
XMM_BITS = {r: 1 << (8 + i) for i, r in enumerate(XMMS)}
XMM_ALL = sum(XMM_BITS.values())
# (and st0, an x87 value a caller leaves on the register stack for it: Ghidra's in_ST0)
ST0 = 1 << 16
# (and ebp, read before set: the parent's frame an EH funclet runs on)
EBP_IN = 1 << 17
X87_LOADS = ("fld", "fild", "fldz", "fld1", "fldpi", "fldl2e", "fldl2t", "fldlg2", "fldln2", "fbld")
# the x87 instructions that touch only the control and status words, never the stack
X87_CONTROL = {"fldcw", "fnstcw", "fstcw", "fnstsw", "fstsw", "fnclex", "fclex", "fwait", "wait", "fninit",
               "fnstenv", "fstenv", "fldenv"}
X87_READS = ("fst", "fstp", "fist", "fistp", "fisttp", "fadd", "fsub", "fsubr", "fmul", "fdiv", "fdivr",
             "faddp", "fsubp", "fsubrp", "fmulp", "fdivp", "fdivrp", "fcom", "fcomp", "fcompp", "fucom",
             "fucomp", "fucompp", "fcomi", "fcomip", "fucomi", "fucomip", "fxch", "fchs", "fabs", "fsqrt",
             "fsin", "fcos", "fptan", "fpatan", "frndint", "fscale", "fprem", "fprem1", "ftst", "fxam",
             "fiadd", "fisub", "fimul", "fidiv", "ficom", "ficomp", "f2xm1", "fyl2x", "fyl2xp1")
SCALAR_DEFS = {"movss", "movsd", "cvtsi2ss", "cvtsi2sd", "cvtss2sd", "cvtsd2ss", "sqrtss", "sqrtsd",
               "rsqrtss", "rcpss", "movd", "movq", "cvttsd2si", "roundss", "roundsd"}
# the instructions whose memory destination they only write
LOCAL_STORE = re.compile(r"mov|movs[sd]|mov[au]p[sd]|movdq[au]|mov[dq]|mov[lh]p[sd]|fstp?|fistt?p?|set\w+$")
ALL = 63 | XMM_ALL | ST0
VOLATILE = EAX | ECX | EDX | XMM_ALL | ST0    # a call's to clobber (st0: its float result)
REG_NAMES = [(EAX, "eax"), (ECX, "ecx"), (EDX, "edx"), (EBX, "ebx"), (ESI, "esi"), (EDI, "edi")] + \
    [(1 << (8 + i), f"xmm{i}") for i in range(8)] + [(ST0, "st0"), (EBP_IN, "ebp")]
REG_BITS = {X.X86_REG_EAX: EAX, X.X86_REG_AX: EAX, X.X86_REG_AL: EAX, X.X86_REG_AH: EAX,
            X.X86_REG_ECX: ECX, X.X86_REG_CX: ECX, X.X86_REG_CL: ECX, X.X86_REG_CH: ECX,
            X.X86_REG_EDX: EDX, X.X86_REG_DX: EDX, X.X86_REG_DL: EDX, X.X86_REG_DH: EDX,
            X.X86_REG_EBX: EBX, X.X86_REG_BX: EBX, X.X86_REG_BL: EBX, X.X86_REG_BH: EBX,
            X.X86_REG_ESI: ESI, X.X86_REG_SI: ESI, X.X86_REG_EDI: EDI, X.X86_REG_DI: EDI, **XMM_BITS}
# the bytes a read of each general register's part takes (its high byte, ah, counted whole: no
# parameter is passed there alone)
REG_WIDTH = {**{r: 1 for r in (X.X86_REG_AL, X.X86_REG_CL, X.X86_REG_DL, X.X86_REG_BL)},
             **{r: 2 for r in (X.X86_REG_AX, X.X86_REG_CX, X.X86_REG_DX, X.X86_REG_BX, X.X86_REG_SI, X.X86_REG_DI)}}
# a register parameter's name at a width (protos.json "regs": `cl`, the shift count of the CRT's
# __allshl, a byte; as ecx, every caller's decompilation needed ecx's upper bytes, extraout_ECX)
NARROW = {("ecx", 1): "cl", ("edx", 1): "dl", ("eax", 1): "al", ("ebx", 1): "bl",
          ("ecx", 2): "cx", ("edx", 2): "dx", ("eax", 2): "ax", ("ebx", 2): "bx", ("esi", 2): "si", ("edi", 2): "di",
          # (an xmm register a double is read from: ApplyFacts' double in its low 8 bytes)
          **{(f"xmm{i}", 8): f"xmm{i}d" for i in range(8)}}
FULL = {X.X86_REG_EAX: EAX, X.X86_REG_ECX: ECX, X.X86_REG_EDX: EDX, X.X86_REG_EBX: EBX,
        X.X86_REG_ESI: ESI, X.X86_REG_EDI: EDI}
END = {"ret", "retf", "int3", "ud2", "hlt", "iretd"}
FRAME_HELPERS = ("SEH_prolog", "EH_prolog")
DVRM_HELPERS = ("alldvrm", "aulldvrm")
ALLOCA = ("alloca_probe", "chkstk")
# the stack words a function that forwards through an indirect tail jump takes and hands on
FORWARD_WORDS = 8

_b: Binary | None = None
_names: dict[int, str] = {}
_cleanup: dict[int, int] = {}
_noreturn: set[int] = set()
_imp_cleanup: dict[int, int] = {}    # import slot -> the bytes the import pops
_cdecl_args: dict[int, int] = {}     # a __cdecl function -> its stack parameter bytes (the last run's)
_untyped: dict[int, int] = {}        # an import's thunk or slot with no prototype -> its slot
_thunk_slot: dict[int, int] = {}     # an import's thunk -> its slot
_imp_params: dict[int, int] = {}     # import slot -> its prototype's stack parameter bytes


def _init(names, cleanup, noreturn, imp_cleanup, cdecl_args=None, untyped=None, thunk_slot=None, imp_params=None):
    global _b, _names, _cleanup, _noreturn, _imp_cleanup, _cdecl_args, _untyped, _thunk_slot, _imp_params
    _b = Binary()
    _names, _cleanup, _noreturn, _imp_cleanup = names, cleanup, noreturn, imp_cleanup
    _cdecl_args = cdecl_args or {}
    _untyped = untyped or {}
    _thunk_slot = thunk_slot or {}
    _imp_params = imp_params or {}


class Insn:
    """A capstone instruction with what the analysis reads of it computed once: capstone decodes
    the mnemonic, rebuilds the operand list and asks the C side for the registers on every access,
    and the passes read each instruction's many times over (most of protos32's time, 2026-10-25).
    Anything else is the instruction's own."""
    __slots__ = ("_i", "mnemonic", "address", "size", "_ops", "_ra")

    def __init__(self, i):
        self._i = i
        self.mnemonic = i.mnemonic
        self.address = i.address
        self.size = i.size
        self._ops = None
        self._ra = None

    @property
    def operands(self):
        if self._ops is None:
            self._ops = self._i.operands
        return self._ops

    def regs_access(self):
        return self._i.regs_access()

    def __getattr__(self, name):
        return getattr(self._i, name)


def regs_access(ins) -> tuple[tuple[int, ...], tuple[int, ...]]:
    """pebin.regs_access, once per decoded instruction (read-only: every caller only tests it)."""
    r = ins._ra
    if r is None:
        reads, writes = _regs_access(ins)
        r = ins._ra = (tuple(reads), tuple(writes))
    return r


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
            out[ins.address] = Insn(ins)
    return out


_written: dict[int, tuple[object, int]] = {}


def written_bits(insns) -> int:
    """The registers (REG_BITS) any instruction of the function writes, a pop's included."""
    hit = _written.get(id(insns))
    if hit is not None and hit[0] is insns:
        return hit[1]
    bits = 0
    for ins in insns.values():
        for r in regs_access(ins)[1]:
            bits |= REG_BITS.get(r, 0)
    _written.clear()
    _written[id(insns)] = (insns, bits)
    return bits


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
    in_width: dict[int, int] = {}             # input register -> the widest read of it as an input
    stack_hi = 0                              # highest entry-relative byte read above the return address
    slots: dict[int, str] = {}                # stack parameter offset -> "d"/"f": read as a double/float
    touched: set[int] = set()                 # parameter slots something else used first
    addr_taken = False                        # `lea r, [param]`: the parameter block as an array (varargs)
    direct_hi = 0                             # highest parameter byte read other than by address
    lea_offs: set[int] = set()                # the parameter slots whose address it takes
    calls = []                                # (target, undefined mask, "call"/"jmp")
    open_ = False
    lost = 0
    indirect_jumps = []
    table_size: dict[int, int] = {}           # a switch table's entries, by its range check
    anchor = [None]                           # ebx's entry-relative esp where it anchors the frame
    loc_store: dict[int, int] = {}            # local offset -> widest store to it
    loc_read: set[int] = set()                # local bytes read (other than by address)
    loc_lea: set[int] = set()                 # locals whose address it takes
    unset_pushes: set[int] = set()            # `push ebx/esi/edi` before anything set it
    tail_ijmps: list[tuple[int, bool]] = []   # indirect tail jumps, and whether ecx was set there
    unset_saved = [0]                         # the registers pushed so
    unset_slots: set[tuple[int, int]] = set()  # and the slots they were pushed to (register, esp)
    floor = [None, None, None]                # the locals a `sub esp, n` makes: bottom, top; the
                                              # frame's allocation (its first after `mov ebp, esp`)

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
        nonlocal inputs, stack_hi, addr_taken, open_, lost, direct_hi
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
        # (and a multi-byte nop, `nop word ptr [eax + eax]`, whose operand addresses nothing: as
        # a read, mixed_va took eax ahead of its format, rhtest calls 2026-10-24)
        nop = mn == "nop" or (mn == "mov" and same) or (mn == "lea" and len(ops) == 2 and ops[1].type == X.X86_OP_MEM
                                         and ops[1].mem.base == ops[0].reg and not ops[1].mem.index
                                         and not ops[1].mem.disp)
        # (`push reg` saves a callee-saved register, or is how MSVC reserves a 4-byte local
        # (`push ecx`): a read of nothing anyone passed. A `this` saved that way is read again
        # from the slot, not from ecx, so it shows elsewhere)
        reserve = mn == "push" and ops and ops[0].type == X.X86_OP_REG and ops[0].reg in FULL
        # (a callee-saved one pushed before anything set it: a save, or an argument the next call
        # takes, decided below, push_args)
        if reserve and ops[0].reg in (X.X86_REG_EBX, X.X86_REG_ESI, X.X86_REG_EDI) \
                and not mask & REG_BITS[ops[0].reg]:
            unset_pushes.add(a)
            unset_saved[0] |= REG_BITS[ops[0].reg]
            if esp is not None:
                unset_slots.add((ops[0].reg, esp - 4))
        # (a scalar SSE write keeps the register's upper lanes, so it reads it too, to the decoder:
        # `movss xmm1, [m]`, `cvtsi2ss xmm1, eax`. It defines lane 0, the float a parameter is:
        # no read of an input. Read so, 126 functions had in_XMM1_Da)
        scalar_def = mn in SCALAR_DEFS and ops and ops[0].type == X.X86_OP_REG and ops[0].reg in XMM_BITS \
            and not (len(ops) > 1 and ops[1].type == X.X86_OP_REG and ops[1].reg == ops[0].reg)
        # (MemoryBarrier() on x86, `xchg [ebp - 4], eax`: a fence, the register's value thrown into a
        # local nothing reads. Taken for a read, an XAudio2 effect's lock check took eax for an
        # input, its every caller through the vtable too, and the effect's Process ran one
        # argument off on XAudio2's thread, the process's end, 2026-10-26)
        fence = mn == "xchg" and len(ops) == 2 and any(
            o.type == X.X86_OP_MEM and o.mem.base in (X.X86_REG_EBP, X.X86_REG_ESP) for o in ops)
        if not zero_idiom and not reserve and not nop and not fence:
            for r in reads:
                bit = REG_BITS.get(r)
                if scalar_def and r == ops[0].reg:
                    continue
                if bit and not mask & bit:
                    inputs |= bit
                    # (an xmm register by its scalar op: a double where `sd` reads it, /LTCG's
                    # sd_dbl taking its doubles in xmm0 and xmm2. As floats, the caller cut them
                    # to 4 bytes, rhtest calls-GL 2026-10-24)
                    w = (8 if re.search(r"sd$|pd$|^cvtsd2|^cvttsd2", mn) else 4) if r in XMM_BITS \
                        else REG_WIDTH.get(r, 4)
                    in_width[bit] = max(in_width.get(bit, 0), w)
        # (ebp: read before anything set it, its parent's frame pointer: an EH funclet's or a catch's
        # continuation, `mov eax, [ebp - 0x18]; ...; mov eax, 0x401265; ret`, all of them stubs for
        # the unaff_EBP. Not its save, `push ebp` or __SEH_prolog4's `mov [esp + 0x10], ebp`, nor
        # /O2's ebp as a register, `xor ebp, ebp`: read so, cmp64 took ebp and sum_lcg returned 0,
        # rhtest int64-O2 2026-10-24)
        save = zero_idiom or nop or (mn == "push" and ops and ops[0].type == X.X86_OP_REG) or \
            (mn == "mov" and len(ops) == 2 and ops[0].type == X.X86_OP_MEM and ops[1].type == X.X86_OP_REG
             and ops[1].reg == X.X86_REG_EBP and ops[0].mem.base != X.X86_REG_EBP)
        if X.X86_REG_EBP in reads and not mask & EBP_IN and not save:
            inputs |= EBP_IN
        if X.X86_REG_EBP in writes and mn != "push":
            mask |= EBP_IN
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
            width = scalar_width(mn, op.size)
            if off < 0:
                # (the locals: which it stores to and never reads, and which it takes the address of)
                if mn == "lea":
                    loc_lea.add(off)
                elif op is ops[0] and LOCAL_STORE.match(mn):
                    # (not an outgoing argument, `mov [esp + 8], eax` with a call ahead and esp as
                    # it is: the callee's to read. Taken in, templates' block spanned clamp_t's
                    # arguments and the return address, rhtest cpp-O2 2026-10-24)
                    if not (base == X.X86_REG_ESP and argument_store(insns, nxt, a)):
                        loc_store[off] = max(loc_store.get(off, 0), op.size or 4)
                else:
                    loc_read.update(range(off, off + (op.size or 4)))
            if off >= 4:
                # (an unaligned parameter address taken, a byte's: a temporary in the dead slot of a
                # parameter already read, to its word's end only. Havok's stream loader 0xdeb100 in a
                # VS2010 client, `lea edx, [ebp + 0xf]` for a bool out of its second parameter's top
                # byte, took a third, and its callers' edi went in unaffected: 2 stubs, 2026-10-26)
                if mn == "lea" and off & 3:
                    width = 4 - (off & 3)
                stack_hi = max(stack_hi, off + (width or 4))
                if mn != "lea":
                    direct_hi = max(direct_hi, off + (width or 4))
                if mn == "lea":
                    addr_taken = True
                    lea_offs.add(off)
                    # (and where the pointer is first read: VS2010's va_start takes the last fixed
                    # parameter's own address and reads past it, `lea edx, [esp + 8]; ...; mov edi,
                    # [edx + 4]`, sum_va's first variadic word; the newer compilers take the slot
                    # past it, `lea esi, [esp + 0x10]`, rhtest msvc-16.00-x86 calls-O2)
                    r = ops[0].reg if ops and ops[0].type == X.X86_OP_REG else None
                    q = nxt.get(a)
                    for _ in range(8):
                        if r is None or q is None or q not in insns:
                            break
                        qi = insns[q]
                        mem = next((o for o in qi.operands if o.type == X.X86_OP_MEM and o.mem.base == r
                                    and not o.mem.index), None)
                        if mem is not None and qi.mnemonic != "lea":
                            if mem.mem.disp > 0:
                                lea_offs.add(off + mem.mem.disp)
                            break
                        if r in regs_access(qi)[1] or qi.mnemonic in ("call", "ret") or qi.mnemonic.startswith("j"):
                            break
                        q = nxt.get(q)
                # (a parameter read as a float, by its width: a double is two slots, and as two
                # 4-byte integers the decompiler read it as `*(double *)&param_3`, 8 bytes of a
                # 4-byte parameter, rhtest float 2026-10-24)
                # (by the first use of the slot: one read as integers or written first holds
                # something else then, ul2d's u64 masked in place and reloaded through
                # `fstp/fld qword [esp+4]` was a double, rhtest float-IA32 2026-10-24)
                elif float_read(mn) and width in (4, 8) and (off - 4) % 4 == 0 and off not in touched:
                    slots[off] = "d" if width == 8 else slots.get(off, "f")
                elif float_read(mn) and off in touched and off not in slots:
                    # (an integer the function reuses the slot of for a float once read: an "n",
                    # an integer as ApplyFacts types it, or the decompiler took the float for the
                    # parameter, fsum's count `(int)gen_fl2bits(param_2)`, rhtest float-IA32)
                    slots[off] = "n"
                elif off not in slots:
                    touched.update(range(off - off % 4, off + (op.size or 4), 4))
        # registers written (a full write defines; partial writes do not)
        # (a byte or word write defines the register too: `mov bl, [edi]; test bl, bl` read
        # its own byte, and counted as wanting ebx in 2,383 functions. Code that writes the low
        # part and then reads the whole, its upper part an input, is not what compilers emit)
        # (a no-op defines nothing either: the CRT's parse_cmdline opens with `mov edi, edi` and
        # takes its argument count's address in edi, which that wrote over in this analysis)
        # (nor a pop that restores a callee-saved register the function saved unset: the caller's
        # value again. _tsopen_nolock saves edi, pops it, then pushes it as /GL's zero argument)
        # (from the save's own slot: VS2010's `push 0x16; pop edi` loads a constant, and taken for
        # a restore, edi stayed unset and _cftog_l took it as an input, rhtest msvc-16.00-x86 crt.
        # Where the offset is not known, by the register alone)
        restore = mn == "pop" and ops and ops[0].type == X.X86_OP_REG and ops[0].reg in (
            X.X86_REG_EBX, X.X86_REG_ESI, X.X86_REG_EDI) and REG_BITS[ops[0].reg] & unset_saved[0] \
            and (esp is None or (ops[0].reg, esp) in unset_slots)
        for r in writes if not nop and not restore else ():
            if r in REG_BITS:
                mask |= REG_BITS[r]
        # esp / ebp
        if mn == "push":
            esp = None if esp is None else esp - (op_size(ops[0]) if ops else 4)
            # (outstanding argument bytes: a register saved while it holds its entry value is no
            # argument, nor is a local reserved so)
            # (nor the frame pointer's save, `push ebp`)
            frame = ops and ops[0].type == X.X86_OP_REG and ops[0].reg == X.X86_REG_EBP
            # (nor the /GS cookie a frame with an EH record saves, `xor eax, ebp; push eax`)
            p0 = insns.get(prv[a]) if prv[a] is not None else None
            cookie = ops and ops[0].type == X.X86_OP_REG and p0 is not None and p0.mnemonic == "xor" \
                and len(p0.operands) == 2 and p0.operands[0].type == p0.operands[1].type == X.X86_OP_REG \
                and p0.operands[0].reg == ops[0].reg and p0.operands[1].reg in (X.X86_REG_EBP, X.X86_REG_ESP)
            # (but a scratch register the function already read as an input is one it hands on:
            # /GL's call_sd takes x in eax and pushes it for sd3 after `lea ecx, [eax + 2]`. As
            # a reserved local, sd3 took 8 bytes of 12 and call_sd six words of its caller's,
            # unaff_ registers, a stub, rhtest msvc-16.00-x86 calls-GL)
            handed = reserve and ops[0].reg in (X.X86_REG_EAX, X.X86_REG_ECX, X.X86_REG_EDX) \
                and inputs & REG_BITS[ops[0].reg]
            # (and a callee-saved one it takes and never writes, nor pops: no save, nothing to
            # restore. /GL's com_calls takes s in ebx and pushes it for the interface's get, `push 3;
            # push ebx; push esi; call eax`; as a save, get had two words, rhtest msvc-16.00-x86 calls-GL)
            handed = handed or (reserve and ops[0].reg in (X.X86_REG_EBX, X.X86_REG_ESI, X.X86_REG_EDI)
                                and inputs & REG_BITS[ops[0].reg] and not written_bits(insns) & REG_BITS[ops[0].reg])
            if (handed or not (reserve and not mask & FULL[ops[0].reg])) and not frame and not cookie:
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
                # (what was pushed before the frame's allocation, its first `sub esp, n` after
                # `mov ebp, esp`, is frame: an EH record's state, handler and link, `push -1; push
                # handler; push fs:[0]; sub esp, 0x2c`. As arguments, multi's virtual get() took
                # four more, rhtest cpp-Od 2026-10-24)
                if mn == "sub" and ebp is not None and floor[2] in (None, a):
                    floor[2] = a
                    pushed = 0
                if mn == "sub" and (floor[0] is None or esp < floor[0]):
                    floor[0], floor[1] = esp, esp + src.imm
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
        elif mn == "mov" and len(ops) == 2 and ops[0].type == X.X86_OP_MEM and ops[0].mem.base == X.X86_REG_EBP \
                and ops[1].type == X.X86_OP_REG and ops[1].reg == X.X86_REG_ESP:
            # (esp saved in the frame, `mov [ebp - 0x18], esp`: the inline SEH prologue's restore
            # point, its registration record and cookie pushed before it frame now, as
            # __SEH_prolog4's are. Counted as arguments, they were __scrt_common_main_seh's
            # guard_check_icall's five more, its saved registers, rhtest 2026-10-24)
            pushed = 0
        elif mn == "mov" and len(ops) == 2 and ops[0].type == X.X86_OP_MEM and ops[0].mem.segment == X.X86_REG_FS \
                and not ops[0].mem.base and not ops[0].mem.index and ops[0].mem.disp == 0:
            # (the EH record linked, `mov fs:[0], eax`: what was pushed before it is frame, the
            # record's state, handler and link, the saves and the cookie, with or without ebp.
            # /O2's frameless diamond, `push -1; push handler; push fs:[0]; sub esp, 0x24`, took
            # them as a virtual call's arguments, rhtest msvc-16.00-x86 cpp)
            pushed = 0
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
                mask |= EBP_IN
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
                    # (or a later call's cleanup pops its bytes too, icall_shape: the stack keeps
                    # them, and the esp offsets after the call are as before it)
                    if not cdecl and pushed and t is None and folded_cleanup(insns, nxt, a, pushed):
                        known, clean = pushed, 0
                    else:
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
                elif t is not None and after is not None and after.mnemonic == "call" and after.operands \
                        and after.operands[0].type == X.X86_OP_REG and after.operands[0].reg == X.X86_REG_EAX:
                    # (a __cdecl call's arguments, never cleaned, taken by the call through the
                    # pointer it returns: VS2010's FLS_GETVALUE, `push [__flsindex]; call
                    # ___set_flsgetvalue; call eax`, FlsGetValue's index. Subtracted, FlsGetValue
                    # got no argument, read the host runtime's slot 3 for the CRT's thread data,
                    # and the host's freed it at exit, rhtest msvc-16.00-x86 2026-10-24)
                    pass
                elif t is not None and t in _cdecl_args:
                    pushed = max(0, pushed - _cdecl_args[t])
                elif known == 0 and (slot if slot is not None else _thunk_slot.get(t)) in _imp_params \
                        and (slot if slot is not None else _thunk_slot.get(t)) not in _untyped:
                    # (an import with a prototype that pops nothing: its own parameter bytes, the
                    # rest outstanding for a later call. GetCurrentProcessId among a crash
                    # handler's pushes for MiniDumpWriteDump, `push edx; push 1; push esi; call
                    # [GetCurrentProcessId]; push eax; ...`, took them all, a VS2010 client)
                    pushed = max(0, pushed - _imp_params[slot if slot is not None else _thunk_slot.get(t)])
                else:
                    pushed = 0
            # eax, ecx and edx are the callee's to clobber; the stack probe's eax only (`push ecx ...
            # pop ecx`: a method with a large frame reads its `this` after it. FUN_00403800 lost its
            # ecx and passed 0 for the string it fills, WinMain's first crash, 2026-10-24)
            if t is not None and any(h in name for h in ALLOCA):
                mask |= EAX
            else:
                mask |= VOLATILE
            # (the CRT's 64-bit divide-with-remainder returns the remainder in ebx:ecx: ebx is its
            # output, not the caller's input; ApplyFacts' call fixup gives the decompiler the same)
            if t is not None and re.sub(r"^_+", "", name.split("::")[-1]) in DVRM_HELPERS:
                mask |= EBX
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
                # (a switch: its targets are found below, from its table)
                indirect_jumps.append((mask, esp, ebp, ops[0].mem.disp & 0xFFFFFFFF))
                # (and its size, by the range check before it, `cmp eax, 5; ja default`)
                q = prv.get(a)
                for _ in range(4):
                    if q is None or q not in insns:
                        break
                    qi = insns[q]
                    if qi.mnemonic == "cmp" and len(qi.operands) == 2 and qi.operands[1].type == X.X86_OP_IMM:
                        table_size[ops[0].mem.disp & 0xFFFFFFFF] = (qi.operands[1].imm & 0xFFFFFFFF) + 1
                        break
                    q = prv.get(q)
            else:
                open_ = True
                # (a tail jump through a pointer with the frame gone: a call that returns, its
                # arguments the caller's, forwards below. Not an import's thunk)
                if esp == 0 and import_slot(insns, prv, a) is None:
                    tail_ijmps.append((a, bool(mask & ECX)))
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
        # (ebp's bit too: from ALL alone, every switch target read ebp unset, and memcpy's tails,
        # `mov eax, [ebp + 8]; leave`, made it take ebp. Its every caller was a stub for the
        # unaff_EBP, FUN_00b9d7c0 on WinMain's path among them, 2026-10-24)
        m = ALL | EBP_IN
        for jm, _e, _b2, _t in indirect_jumps:
            m &= jm
        seed = (m, indirect_jumps[0][1], indirect_jumps[0][2], 0)
        # (the cases its tables name, each from its own jump's state: not every address nothing else
        # reached, which takes in the dead code after a noreturn call. llex's `call lexerror; add esp,
        # 0x40` so seeded at the switch's esp came out 0x40 high, its epilogue's cookie read as 15
        # stack parameters, and luaX_next a stub, 2026-10-25)
        any_case = False
        # (each table as long as its range check says, else to the next table's start: two
        # switches' tables side by side, 0x44d2fc and 0x44d314, read the second's cases as the
        # first's; and a switch found inside another's cases, its own in turn)
        done = 0
        while done < len(indirect_jumps):
            jm, je, jb, table = indirect_jumps[done]
            done += 1
            starts = {tb for _m, _e, _b, tb in indirect_jumps}
            cases = []
            for k in range(table_size.get(table, 1024)):
                if k and table + 4 * k in starts:
                    break
                try:
                    t = b.u32(table + 4 * k)
                except Exception:  # noqa: BLE001
                    break
                if t not in insns:
                    break
                # (its own jump's registers, not every switch's in common: a handler's second
                # switch, after `mov ebx, [ebp + 8]; mov edi, [ebp + 0x18]`, seeded with the first's
                # read them as inputs, and its callers through a table passed its words one off,
                # 2026-10-26)
                cases.append((t, (jm | (m & EBP_IN), je, jb, 0)))
            any_case = any_case or bool(cases)
            for t, s in cases:
                if t not in state:
                    merge(t, s)
                    while work:
                        visit(work.pop())
        cases = any_case
        if not cases:
            for a in order:
                if a not in state:
                    merge(a, seed)
                    while work:
                        visit(work.pop())
    results, passes, handoffs, passes_via, st_over = result_reads(insns, state, nxt)
    ecx_hands = ecx_handoffs(insns, state, nxt)
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
        # (not a switch's `jmp [eax*4 + table]`, whose cases are this function's own and followed
        # as such: VS2010 kept level2's loop counters in ecx and edx across its switch functions,
        # which write eax alone, and as opaque ones they lost them, rhtest msvc-16.00-x86)
        elif ins.mnemonic == "jmp" and _target(ins) is None and not (
                ins.operands and ins.operands[0].type == X.X86_OP_MEM and ins.operands[0].mem.index
                and ins.operands[0].mem.scale == 4):
            opaque = True
        if ins.mnemonic in ("push", "call", "jmp"):
            continue
        for x in regs_access(ins)[1]:
            vol_writes |= EAX if x in EAX_REGS else EDX if x in EDX_REGS else \
                ECX if x in (X.X86_REG_ECX, X.X86_REG_CX, X.X86_REG_CL, X.X86_REG_CH) else 0
    for ins in insns.values():
        # (a call to an import or through a pointer writes eax too, its result: operator new's
        # `call malloc; test eax, eax; jne` returns malloc's past the branch, where no straight
        # line from the call reaches the ret, and void, every `new` gave 0, rhtest cpp-O2 2026-10-24.
        # And an import thunk's `jmp [slot]`)
        if ins.mnemonic in ("call", "jmp") and _target(ins) is None:
            writes_ret |= EAX
        if ins.mnemonic in ("push", "call"):
            continue
        w = regs_access(ins)[1]
        if any(x in EAX_REGS for x in w):
            writes_ret |= EAX
        if any(x in EDX_REGS for x in w):
            writes_ret |= EDX
        if ins.mnemonic.startswith("fld") or ins.mnemonic.startswith("fild"):
            writes_ret |= 64
        if X.X86_REG_XMM0 in w:
            writes_ret |= 128                     # (xmm0: an /LTCG SSE result)
    # (a callee-saved register pushed unset as one of the next call's arguments: the caller's
    # value, an input. /GL's CRT passes 0 in edi: _sopen_helper's `xor edi, edi` reaches
    # _tsopen_nolock, which pushes it for __lseeki64_nolock's offset and __invoke_watson's
    # arguments; as a save, its unaff_EDI made it a stub on fopen's path, a VS2010 client 2026-10-24)
    # (not the prologue's run of saves: one reached back over register pushes from the entry, its
    # frame's `push ebp; mov ebp, esp` or `sub esp, n`, a save even before a call's arguments)
    def prologue(a):
        p = prv.get(a)
        while p is not None and p in insns and insns[p].mnemonic == "push" and insns[p].operands \
                and insns[p].operands[0].type == X.X86_OP_REG:
            p = prv.get(p)
        if p is None or p not in insns or p < root:
            return True
        pi = insns[p]
        po = pi.operands
        return (pi.mnemonic == "mov" and len(po) == 2 and po[0].type == po[1].type == X.X86_OP_REG
                and (po[0].reg == po[1].reg or (po[0].reg == X.X86_REG_EBP and po[1].reg == X.X86_REG_ESP))) \
            or (pi.mnemonic == "sub" and po and po[0].type == X.X86_OP_REG and po[0].reg == X.X86_REG_ESP)
    # (a save is restored: a `pop` of the same register from the same slot. VS2010 places its
    # saves late, `...; push esi; push edi; push 0x16; ...; call __fltout2` in _cftog_l and `push
    # ebx` in a branch, popped before its ret: taken for arguments, ebx, esi and edi became inputs
    # of the whole printf engine, rhtest msvc-16.00-x86 crt. An argument's slot goes with the
    # call's cleanup instead)
    pops = [(insns[q].operands[0].reg, state[q][1]) for q in state
            if insns[q].mnemonic == "pop" and insns[q].operands and insns[q].operands[0].type == X.X86_OP_REG]
    restored = {(r, o) for r, o in pops if o is not None}
    # (and where paths with different pushes join, the pop's offset is not known: a pop of the
    # register there is taken for the save's, _cftog_l's `pop edi` after one path's `pop ebx`)
    restored_any = {r for r, o in pops if o is None}

    # (where esp is not known at the push either, after the frame's `and esp, -64`, the pop's offset
    # is not known: fmt_floats' `push esi` at /O2, after the alignment, counted for an eighth
    # double's word of its sprintf and read as unaff_ESI, rhtest msvc-16.00-x86 crt)
    def overwritten_next(p):
        """the pushed register written again, unread, before the next call or branch: a save
        (shrink-wrapped, on one path: `push ebx; mov ebx, [ebp + 8]`)"""
        bit = REG_BITS.get(insns[p].operands[0].reg)
        q = nxt.get(p)
        for _ in range(8):
            if q is None or q not in insns:
                return False
            qi = insns[q]
            if qi.mnemonic in ("call", "ret") or qi.mnemonic.startswith("j"):
                return False
            reads, writes = regs_access(qi)
            if any(REG_BITS.get(r) == bit for r in reads):
                return False
            if any(REG_BITS.get(r) == bit for r in writes):
                return True
            q = nxt.get(q)
        return False

    def saved(p):
        if state.get(p) is None:
            return False
        reg = insns[p].operands[0].reg
        if overwritten_next(p):
            return True
        if state[p][1] is None:
            return reg in restored_any
        return (reg, state[p][1] - 4) in restored or reg in restored_any
    for a in sorted(unset_pushes):
        if prologue(a) or saved(a):
            continue
        after, p = 0, nxt.get(a)
        pushed_reg = insns[a].operands[0].reg
        for _ in range(10):
            if p is None or p not in insns:
                break
            pi = insns[p]
            # (the register written again next: the push saved it, a shrink-wrapped save on one
            # path, `push ebx; mov ebx, [ebp + 8]; ...; push edi; mov edi, [ebp + 0x18]` in a
            # switch's case. Taken for arguments, ebx and edi became inputs of a handler called
            # through a table, and its stack words came one off, 2026-10-26)
            if REG_BITS.get(pushed_reg) and any(REG_BITS.get(r) == REG_BITS[pushed_reg] for r in regs_access(pi)[1]) \
                    and not any(REG_BITS.get(r) == REG_BITS[pushed_reg] for r in regs_access(pi)[0]):
                break
            if pi.mnemonic == "push":
                after += 4
            elif pi.mnemonic == "call":
                t = _target(pi)
                takes = _cleanup.get(t) if t is not None else None
                nx = insns.get(nxt.get(p)) if nxt.get(p) is not None else None
                if not takes and nx is not None and nx.mnemonic == "add" and len(nx.operands) == 2 \
                        and nx.operands[0].type == X.X86_OP_REG and nx.operands[0].reg == X.X86_REG_ESP \
                        and nx.operands[1].type == X.X86_OP_IMM:
                    takes = nx.operands[1].imm
                elif not takes and t is not None:
                    takes = _cdecl_args.get(t)
                if takes and takes > after:
                    bit = REG_BITS[insns[a].operands[0].reg]
                    inputs |= bit
                    in_width[bit] = 4
                break
            elif pi.mnemonic not in ("mov", "lea", "movzx", "movsx") or pi.mnemonic.startswith("j"):
                break
            p = nxt.get(p)
    # (eax set by the function itself just before a ret, past only its frame's teardown: its
    # result. FUN_004066a0, the system allocator's Alloc, ends `mov eax, esi; pop esi; pop ebp;
    # ret 0xc`, its virtual Alloc's result; called only through its vtable, no caller's read typed
    # it, void, and every allocation through it came back 0: FUN_00405f60 skipped the managed
    # allocator's setup, and WinMain gave up, a VS2010 client 2026-10-24)
    # (as wide as it sets it, the widest over its rets: `mov al, 1; ret 4` is a bool, and as an i4
    # its upper bytes were a void callee's eax, extraout_EAX, FUN_005e3700 in a VS2010 client
    # 2026-10-25)
    # (and whether every ret has its own byte or word write so: a bool on each path, whatever
    # width a caller reads it at, main())
    sets_eax = sets_eax_far = 0
    rets = rets_set = 0
    # (and whether st0 can hold a value at a ret: the last x87 instruction before it not one that
    # pops what it used, `fstp`, `fcompp`. A load or an operation leaves its result in st0)
    x87_ret_live = False
    for a in state:
        if insns[a].mnemonic != "ret":
            continue
        q = prv.get(a)
        for _ in range(32):
            if q is None or q not in insns:
                break
            qm = insns[q].mnemonic
            if qm.startswith("f") and not qm.startswith(("fn", "fwait")):
                if not (qm.endswith("p") or qm in ("fcompp", "fucompp")):
                    x87_ret_live = True
                break
            if qm == "call" or qm.startswith("j"):
                x87_ret_live = x87_ret_live or qm == "call"   # (a callee's st0 passed on)
                break
            q = prv.get(q)
    # (and whether st0 is certainly empty at its rets: each ret reached, back from it, from an x87
    # instruction that pops before any branch or call, and the function's x87 pushes and pops
    # balancing (`fld a; fld b; fstp c; ret` returns a). A float setter, `fld [esp + 4]; fstp
    # [ecx + 0x1c]; ret 4`, and a listener's sin/cos update, typed by a caller's read, printed
    # their st0 as in_ST0, stubs on a sound path, 2026-10-26)
    x87_ret_dead = False
    depth, used, ends = 0, False, []
    for a in state:
        m = insns[a].mnemonic
        if m == "ret":
            # (back along the fall-through path, past a loop's closing jcc, `fstp [edi]; ...;
            # jl top; pop edi; ...; ret 4`; to the entry with no x87 or call on the way, empty too)
            q, end = prv.get(a), False
            for _ in range(48):
                if q is None or q not in insns:
                    end = q is None
                    break
                qm = insns[q].mnemonic
                if qm.startswith("f") and not qm.startswith(("fn", "fwait")):
                    end = qm.endswith("p")
                    break
                if qm in ("call", "jmp") or qm.startswith("loop"):
                    break
                q = prv.get(q)
            ends.append(end)
        if not m.startswith("f") or m.startswith(("fn", "fwait")):
            continue
        used = True
        if m.startswith(("fld", "fild", "fbld")):
            depth += 1
        if m in ("fcompp", "fucompp"):
            depth -= 2
        elif m.endswith("p"):
            depth -= 1
    x87_ret_dead = used and depth == 0 and bool(ends) and all(ends)
    # (the pushes and pops balancing along each way to a ret, not summed over the function: Horner's
    # loop, `fldz; ...; js done; fld x; loop: ...; fstp st(1); ret` and `done: ret`, balances to 0
    # summed but reaches each ret with its result loaded. Typed void by the sum, its caller's
    # extraout_ST0 was a stub, rhtest msvc-14.51-x86 float-IA32)
    if x87_ret_dead:
        x87_ret_dead = x87_depth_at_rets(insns, nxt, state, root) == {0}
    # (and an x87 result of its own: every ret reached with one value on the stack, the last x87
    # instruction before each a load from memory of one width, `call f; fstp [m]; fld [m]; ret`,
    # a float rounded and returned. Typed only through the callee it seemed to pass on, the
    # caller's st0 popped before the ret, such wrappers lost their float, 2026-10-27)
    x87_own_ret = None
    # (the last x87 instruction before each ret its load, nothing called after it: what is in st0
    # there is that load, whatever a call before it left deeper)
    if any(insns[q].mnemonic.startswith("f") for q in state) and not x87_ret_dead:
        widths = set()
        for a in state:
            if insns[a].mnemonic != "ret":
                continue
            q = prv.get(a)
            for _ in range(16):
                if q is None or q not in insns:
                    break
                qi = insns[q]
                if qi.mnemonic.startswith("f") and qi.mnemonic not in X87_CONTROL:
                    ops = qi.operands
                    if qi.mnemonic == "fld" and ops and ops[0].type == X.X86_OP_MEM:
                        widths.add(ops[0].size)
                    else:
                        widths.add(None)
                    break
                if qi.mnemonic in ("call", "jmp") or qi.mnemonic.startswith("j"):
                    widths.add(None)
                    break
                q = prv.get(q)
        if widths in ({4}, {8}):
            x87_own_ret = "f4" if widths == {4} else "d8"
    for a in state:
        if insns[a].mnemonic != "ret":
            continue
        rets += 1
        p = prv.get(a)
        x87_on_way = crossed = False
        # (24 back: a vector's normalize sets eax before eight x87 stores and its epilogue)
        for _ in range(24):
            if p is None or p not in insns or p not in state or p + insns[p].size not in insns:
                break
            pi = insns[p]
            po = pi.operands
            x87_on_way |= pi.mnemonic.startswith("f") and not pi.mnemonic.startswith(("fn", "fwait"))
            if pi.mnemonic in ("pop", "leave") or (pi.mnemonic in ("mov", "lea", "add") and po
                                                   and po[0].type == X.X86_OP_REG and po[0].reg == X.X86_REG_ESP):
                p = prv.get(p)
                continue
            # (nor a store of it on the way: VS2010's Sink::take, `got = x * 16 + flags; return
            # got;`, ends `mov [ecx + 4], eax; ret 8`, and as void its virtual call came back 0,
            # rhtest msvc-16.00-x86 cpp-O2 sinks)
            if pi.mnemonic == "mov" and len(po) == 2 and po[0].type == X.X86_OP_MEM and po[1].type == X.X86_OP_REG:
                p = prv.get(p)
                continue
            # (nor the cookie check, which keeps eax: `xor al, al; pop ebx; call
            # __security_check_cookie; mov esp, ebp; pop ebp; ret 4` sets al before it. Stopped at
            # the call, that path went uncounted, the bool an i4, and its upper bytes extraout_EAX:
            # a VS2010 client's 0x4d14a0 a stub on WinMain's path, 2026-10-26)
            if pi.mnemonic == "call" and "security_check_cookie" in _names.get(_target(pi), ""):
                p = prv.get(p)
                continue
            # (nor anything else that leaves eax, short of a branch or a call: Havok's lazy
            # singletons, `push 0x14; call eax; mov [eax + 4], 0x10014; mov [eax], vtable; ...; ret`,
            # return the allocator's object and are reached only through their init list's
            # pointers; void, FUN_00d9bbc0 took none made, a VS2010 client's 0x105a400 2026-10-25)
            if pi.mnemonic != "call" and not pi.mnemonic.startswith(("j", "loop", "ret")) \
                    and not any(x in EAX_REGS for x in regs_access(pi)[1]):
                p = prv.get(p)
                continue
            # (nor a conditional jump, whose fall-through comes on to the ret: a resource handle's
            # load callback, `mov eax, [ebp + 0xc]; cmp eax, 1; jne out; ...; je out; out: pop ebp;
            # ret 8`, returns its argument, void stopped at the je, and returning 0 the file it
            # loaded was failed: a client's root.exl, its "unexpected error (ed)", 2026-10-26)
            # (a forward one only: a loop's, `add eax, 8; jne top; ret 0xc`, closes on a counter, no
            # result, and a byte swapper so made i4 took its callers' x87 results with it. Nor
            # past an x87 load on the way: `call edx; test al, al; je out; fld [k]; ret` returns
            # st0, the call's al only its condition)
            # (what is found past one counts only where nothing else is: a result for a function
            # that had none, never a bool's every-path al widened, its upper bytes extraout_EAX)
            if pi.mnemonic.startswith("j") and pi.mnemonic != "jmp" and (_target(pi) or 0) > pi.address \
                    and not x87_on_way:
                crossed = True
                p = prv.get(p)
                continue
            if pi.mnemonic not in ("call", "jmp") and not pi.mnemonic.startswith("j") \
                    and any(x in EAX_REGS for x in regs_access(pi)[1]):
                w = regs_access(pi)[1]
                # (not the address of its own frame or arguments, `lea eax, [esp + k]`: no value a
                # caller can use once the frame is gone, the pointer a clamp through locals leaves,
                # std::min/max's shape. As a result the port returned its frame's address (C4172)
                # where callers read nothing, a VS2010 client's FUN_00571440 2026-10-25)
                if pi.mnemonic == "lea" and po and po[1].type == X.X86_OP_MEM \
                        and po[1].mem.base in (X.X86_REG_ESP, X.X86_REG_EBP):
                    break
                width = 4 if X.X86_REG_EAX in w else 2 if X.X86_REG_AX in w else 1
                if crossed:
                    sets_eax_far = max(sets_eax_far, width)
                else:
                    sets_eax = max(sets_eax, width)
                    rets_set += 1
            # (and a call through a pointer just before it: what that returns, passed on. The
            # allocator's FUN_00404d40, `call eax; pop ebp; ret 0x10`, the next in that chain. A
            # result given to a void one is ignored by its callers; one lost is 0)
            elif pi.mnemonic == "call" and _target(pi) is None and import_slot(insns, prv, p) is None:
                if crossed:
                    sets_eax_far = 4
                else:
                    sets_eax = 4
            break
    if not sets_eax:
        sets_eax = sets_eax_far
    labels = {_target(i) for i in insns.values() if i.mnemonic.startswith("j") or i.mnemonic.startswith("loop")}
    inputs |= pushed_inputs(insns, prv, nxt, state, labels)
    icalls = {a: icall_shape(insns, prv, nxt, state, a, labels, bool(inputs & ECX)) for a in state
              if insns[a].mnemonic == "call" and _target(insns[a]) is None and import_slot(insns, prv, a) is None}
    # (and a call through a register holding an import, its words as the import pops them: VS2010's
    # _output_l loads DecodePointer into esi far ahead, across branches, and the decompiler, not
    # seeing it there, gave `call esi` a guess, and every argument of the _cfltcvt call after it
    # moved a slot, rhtest msvc-16.00-x86 crt)
    for a in state:
        ins = insns[a]
        if ins.mnemonic == "call" and ins.operands and ins.operands[0].type == X.X86_OP_REG:
            slot = import_slot(insns, prv, a)
            # (one that pops its own: a __cdecl import's 0 is no count of its arguments, and the
            # caller's `add esp, k` after the call, icall_shape's, is. As none, the /MD CRT's
            # bsearch through esi got no arguments and called its comparator at 7, rhtest crt-O2)
            if slot is not None and _imp_cleanup.get(slot):
                icalls[a] = ("__stdcall", _imp_cleanup[slot] // 4)
    # (whether it runs x87 code at all, and the calls it makes with its own result in st0 still to
    # return: one followed only by its teardown and ret, no x87 instruction or other call between,
    # `fld result; ...; call __security_check_cookie; leave; ret`. Such a callee keeps st0, main())
    x87_use = any(insns[q].mnemonic.startswith("f") for q in state)
    st0_live: list[int] = []
    for a in state:
        ins = insns[a]
        t = _target(ins)
        if ins.mnemonic != "call" or t is None:
            continue
        q = nxt.get(a)
        for _ in range(8):
            if q is None or q not in insns:
                break
            qm = insns[q].mnemonic
            if qm == "ret":
                st0_live.append(t)
                break
            if qm.startswith("f") or qm in ("call", "jmp") or qm.startswith("j"):
                break
            q = nxt.get(q)
    # (each direct call's own pushes, back to the call before it with no jump target between: a
    # variadic callee's arguments at that call, main()'s call-site signatures. /GL folds the
    # cleanup into a later one, and the decompiler, which counts a variadic call's arguments by its
    # `add esp`, gave sum_via(5, i, ...) its 5 alone, rhtest msvc-16.00-x86 calls-GL)
    call_pushes: dict[int, tuple[int, int]] = {}
    # (and the pushes before a direct call the scan stopped at, one that no `add esp` cleans up
    # after: {call: (that callee, the bytes pushed before it, this call's own cleanup)}. A callee
    # taking no stack words, a register helper, leaves them to this call, main(): mixed_va(fmt, i,
    # (i64)s << 35, d, -i) pushes -i and the double, then calls __allshl, then pushes the rest,
    # and counted back to __allshl alone the call took four words of seven, rhtest calls-Od)
    pushes_past: dict[int, tuple[int, int, int]] = {}
    for a in state:
        ins = insns[a]
        t = _target(ins)
        if ins.mnemonic != "call" or t is None:
            continue
        n, p = 0, a
        stop = None
        while True:
            if p in labels and p != a:
                break
            p = prv.get(p)
            if p is None or p not in insns:
                break
            pi = insns[p]
            pm, po = pi.mnemonic, pi.operands
            # (not the prologue's save of a callee-saved register, call_va's `push edi` before
            # sum_va's arguments, nor one popped again later: the same tests as for its inputs)
            if pm == "push" and p in unset_pushes and (prologue(p) or saved(p)):
                continue
            if pm == "push":
                n += 4
            # (room made for a double, `sub esp, 8; fstp qword ptr [esp]`: mixed_va's)
            elif pm == "sub" and len(po) == 2 and po[0].type == X.X86_OP_REG and po[0].reg == X.X86_REG_ESP \
                    and po[1].type == X.X86_OP_IMM:
                n += po[1].imm
            elif pm in ("call", "jmp", "ret") or pm.startswith("j") or any(
                    o.type == X.X86_OP_REG and o.reg == X.X86_REG_ESP for o in po):
                if pm == "call":
                    stop = p
                break
        # (no more than its own cleanup, where it has one: sscanf's `add esp, 0x1c` after scan's
        # seven, the save of esi before them no eighth)
        k = later_cleanup(insns, nxt, a)
        if stop is not None and k and k > n and _target(insns[stop]) is not None \
                and not later_cleanup(insns, nxt, stop):
            q, m = stop, 0
            while True:
                if q in labels:
                    break
                q = prv.get(q)
                if q is None or q not in insns:
                    break
                qi = insns[q]
                qm, qo = qi.mnemonic, qi.operands
                if qm == "push" and q in unset_pushes and (prologue(q) or saved(q)):
                    continue
                if qm == "push":
                    m += 4
                elif qm == "sub" and len(qo) == 2 and qo[0].type == X.X86_OP_REG and qo[0].reg == X.X86_REG_ESP \
                        and qo[1].type == X.X86_OP_IMM:
                    m += qo[1].imm
                elif qm in ("call", "jmp", "ret") or qm.startswith("j") or any(
                        o.type == X.X86_OP_REG and o.reg == X.X86_REG_ESP for o in qo):
                    break
            if m:
                pushes_past[a] = (_target(insns[stop]), m, k)
        if k:
            n = min(n, k)
        call_pushes[a] = (t, n)
    # (the bytes outstanding at each call to an import with no prototype, and the caller's own
    # cleanup after it: main() takes what most of its calls push as its own, where none cleans up)
    untyped_pushed: dict[int, tuple[int, int, int]] = {}
    if _untyped:
        for a in state:
            ins = insns[a]
            if ins.mnemonic != "call":
                continue
            t = _target(ins)
            s = _untyped.get(t) if t is not None else None
            if t is None:
                slot = import_slot(insns, prv, a)
                s = _untyped.get(slot) if slot is not None else None
            if s is not None:
                untyped_pushed[a] = (s, state[a][3], later_cleanup(insns, nxt, a) or 0)
    # (a callee taking more stack words than were pushed for it reads the caller's own slots above
    # them; where one is a push of a callee-saved register still as it came in, that push hands the
    # caller's input on: /GL's sort_check takes cmp in esi and pushes it early, among unrelated
    # work, then only v right before isort(v, cmp). Taken for a save, sort_check read unaff_ESI,
    # rhtest msvc-16.00-x86 calls-GL. Not a save, popped again: a callee that takes more words than
    # were pushed for it reaches those too)
    push_slot = {}
    for p in unset_pushes:
        if p in state and state[p][1] is not None and not saved(p):
            push_slot[state[p][1] - 4] = REG_BITS[insns[p].operands[0].reg]
    for a, (t, _n) in call_pushes.items():
        esp_at = state[a][1]
        takes = _cdecl_args.get(t) or _cleanup.get(t)
        if not push_slot or esp_at is None or not takes:
            continue
        # (every word it takes: /GL interleaves the pushes with other work, so which were pushed
        # "for it" is not a count back from the call)
        for off in range(0, takes, 4):
            bit = push_slot.get(esp_at + off)
            if bit:
                inputs |= bit
                in_width[bit] = 4
    # (and a virtual call made as a tail jump, `mov ecx, esi; pop esi; jmp [eax + 4]`, through a
    # slot of an object's table (not a switch's, which indexes): `this` as for a call, and the stack
    # what the jumper's own `ret N` would pop, the callee popping it in its place. Without one, bump's
    # v.get() went without its object, rhtest cpp-O2 2026-10-24)
    # (what each direct callee is passed here: what it pushed for it, at most the caller's `add esp,
    # k` right after. main() gives a __cdecl one the fewest any call passes, where it reads fewer.
    # Every call counts: the CRT's folded `return true` takes `push 0` from one caller and nothing
    # from two, and given the one, the others' stacks went one slot off)
    passed: dict[int, int] = {}
    for a in state:
        ins = insns[a]
        t = _target(ins)
        if ins.mnemonic != "call" or t is None:
            continue
        after = insns.get(nxt[a]) if nxt[a] == a + ins.size else None
        k = state[a][3]
        if after is not None and after.mnemonic == "add" and len(after.operands) == 2 \
                and after.operands[0].type == X.X86_OP_REG and after.operands[0].reg == X.X86_REG_ESP \
                and after.operands[1].type == X.X86_OP_IMM:
            k = min(after.operands[1].imm, k)
        passed[t] = min(passed.get(t, k), k)
    for a in state:
        ins = insns[a]
        if ins.mnemonic != "jmp" or _target(ins) is not None or not ins.operands:
            continue
        op = ins.operands[0]
        if op.type != X.X86_OP_MEM or not op.mem.base or op.mem.index or import_slot(insns, prv, a) is not None:
            continue
        # (one with no ret of its own to tell its stack is a forwarder, its words the forwarded
        # call's, tail_ijmps: as none, Front::grab's `mov ecx, [ecx + 4]; mov eax, [ecx]; jmp [eax +
        # 4]` handed Backend::grab no size, rhtest msvc-14.51-x86 cpp-O2 fronts 2026-10-25)
        if ret_bytes(insns) is None:
            continue
        shape = icall_shape(insns, prv, nxt, state, a, labels, bool(inputs & ECX))
        if shape is not None:
            icalls[a] = (shape[0] if shape[0] != "__cdecl" else "__stdcall", (ret_bytes(insns) or 0) // 4)
    # (variadic: the address of the slot just past the last parameter it reads, `lea eax, [esp + 8]`
    # after reading [esp + 4]: va_start of what follows its fixed ones. Typed with only what it
    # reads, sum_va(int n, ...) had one more parameter and its callers passed two, rhtest calls)
    variadic = (direct_hi - 4) // 4 if direct_hi >= 8 and direct_hi in lea_offs and direct_hi % 4 == 0 \
        and max(lea_offs) == direct_hi else None
    # (an object below the pointer it passes on: stores it never reads under the lowest local whose
    # address it takes are read through that pointer, a compiler emitting no dead stores. A Diamond's
    # Left and Right parts lie below the Base0 that via_base(&dm) is given, and the decompiler, its
    # alias boundary at the pointer, dropped them as dead, rhtest cpp-O2 2026-10-24. One array from
    # the lowest up to the next local whose address it takes, or the allocation's top, is one
    # variable, aliased whole: to the taken slot only, the Base0's own b0 above it went unstored)
    block = None
    if loc_lea and floor[0] is not None:
        t = min(loc_lea)
        unread = [o for o, w in loc_store.items() if floor[0] <= o < t
                  and not any(x in loc_read for x in range(o, o + w))]
        if unread and t < floor[1]:
            top = min([o for o in loc_lea if o > t] + [floor[1]])
            block = [min(unread), top - min(unread)]
    # (and an object a callee fills at the lowest local whose address it takes, read past its first
    # slot and never stored here: its fields. ___crtGetStringTypeA's _LocaleUpdate, built by its
    # constructor through `lea ecx, [ebp - 0x10]`, read at ebp-8 and ebp-4: the decompiler made
    # those locals of their own, the constructor's 16 bytes went into a 4-byte buffer and smashed
    # the frame, a VS2010 client's first CRT call 2026-10-24. One array from the address up to the
    # last such byte. Past its first 8 bytes only: a value up to 8 the decompiler takes whole, and
    # a LARGE_INTEGER QueryPerformanceCounter fills, returned in edx:eax, made the function's
    # return a `byte [8]`, no C)
    if block is None and loc_lea and floor[0] is not None:
        t = min(loc_lea)
        top = min([o for o in loc_lea if o > t] + [floor[1]])
        stored = {x for o, w in loc_store.items() for x in range(o, o + w)}
        fields = [x for x in loc_read if t + 8 <= x < top and x not in stored]
        if fields:
            block = [t, ((max(fields) + 1 - t) + 3) & ~3]
    tail_jumps = any(insns[a].mnemonic == "jmp" and (_target(insns[a]) is None or _target(insns[a]) not in insns)
                     for a in state)
    # (the constants it pushes or loads into eax: an EH4 frame's scope table, `push -2; push
    # 0x403a00; push __except_handler4`, and a C++ handler thunk's FuncInfo, `mov eax, 0x4037d8`;
    # main() reads their funclets from them)
    eh_imms = sorted({insns[a].operands[0].imm & 0xFFFFFFFF if insns[a].mnemonic == "push" else
                      insns[a].operands[1].imm & 0xFFFFFFFF for a in state
                      if (insns[a].mnemonic == "push" and insns[a].operands and insns[a].operands[0].type == X.X86_OP_IMM)
                      or (insns[a].mnemonic == "mov" and len(insns[a].operands) == 2
                          and insns[a].operands[0].type == X.X86_OP_REG and insns[a].operands[0].reg == X.X86_REG_EAX
                          and insns[a].operands[1].type == X.X86_OP_IMM)})
    # (a function that stores the segment registers records the machine's state, a CONTEXT for a
    # crash report: the general registers it stores beside them are recorded, not passed to it.
    # Taken for inputs, the CRT's __call_reportfault took esi and edi, and through _abort every
    # caller of abort passed its own, unaff_ESI, a stub, rhtest msvc-16.00-x86)
    seg = (X.X86_REG_ES, X.X86_REG_CS, X.X86_REG_SS, X.X86_REG_DS, X.X86_REG_FS, X.X86_REG_GS)
    if any(insns[a].mnemonic == "mov" and len(insns[a].operands) == 2 and insns[a].operands[0].type == X.X86_OP_MEM
           and insns[a].operands[1].type == X.X86_OP_REG and insns[a].operands[1].reg in seg for a in state):
        inputs = 0
    # (and one that clears the x87 exception flags, `fnclex`: translate32 clears them after its
    # status word's read, which the decompiler keeps and the clear it drops, __clrfp)
    fpu_clear = any(insns[a].mnemonic in ("fnclex", "fclex") for a in state)
    # (and whether it leaves the x87 stack alone: no x87 instruction but the control and status
    # words' (fldcw, fnstsw, ...), and no call through a pointer; its direct callees decided in main)
    x87_data = any(insns[a].mnemonic.startswith("f") and insns[a].mnemonic not in X87_CONTROL for a in state) \
        or any(insns[a].mnemonic == "call" and _target(insns[a]) is None for a in state) \
        or any(indirect_tail_jump(insns[a]) for a in state)
    return {"fpu_clear": fpu_clear, "x87_data": x87_data, "x87_own_ret": x87_own_ret, "local_block": block, "passed": passed, "tail_jumps": tail_jumps, "eh_imms": eh_imms,
            "frame": -floor[0] if floor[0] is not None and floor[0] < 0 else None,"inputs": inputs, "in_width": in_width, "stack_hi": stack_hi, "slots": slots,
            "addr_taken": addr_taken, "calls": calls, "variadic": variadic, "call_pushes": call_pushes, "pushes_past": pushes_past,
            "untyped_pushed": untyped_pushed,
            "x87_use": x87_use, "st0_live": st0_live,
            "open": open_, "lost": lost, "ret": ret_bytes(insns), "visited": len(state), "insns": len(insns),
            "icalls": {a: s for a, s in icalls.items() if s is not None},
            "results": {t: k for t, k in results.items() if not isinstance(t, tuple)},
            "handoffs": handoffs, "ecx_handoffs": ecx_hands,
            # (an indirect call's x87 result, for its call-site signature: `(float)extraout_ST0`
            # after a virtual getter of a float, 305 stubs, 2026-10-23)
            # (and its edx:eax one, i8: a sound thread's `uVar9 = (*vt[1])(..)` read edx after it
            # into a 64-bit count, extraout_EDX, a stub, 2026-10-26)
            "icall_rets": {t[1]: k for t, k in results.items() if isinstance(t, tuple) and k in ("f4", "d8", "i8")},
            "passes": passes, "passes_via": passes_via, "st_over": st_over, "writes_ret": writes_ret, "vol_writes": vol_writes, "opaque": opaque,
            "sets_eax": sets_eax, "x87_ret_live": x87_ret_live, "x87_ret_dead": x87_ret_dead, "narrow_ret": sets_eax if sets_eax in (1, 2) and rets and rets_set == rets else 0,
            "eax_unset": root in state and eax_reaches_ret(insns, state, nxt, root, limit=256),
            "tail_ijmps": [(j, c or bool(inputs & ECX)) for j, c in tail_ijmps]}


EAX_REGS = {X.X86_REG_EAX, X.X86_REG_AX, X.X86_REG_AL, X.X86_REG_AH}
EDX_REGS = {X.X86_REG_EDX, X.X86_REG_DX, X.X86_REG_DL, X.X86_REG_DH}
# (a static C runtime's setjmp, by the name Ghidra's function ID gives it: VS2010's /MT __setjmp3)
SETJMP_NAME = re.compile(r"(?:FID_conflict:)?_*(?:setjmp3|setjmp)")
# (x87 pushes of a memory operand or a constant: no st0 read. `fld st(i)` reads the stack)
X87_LOADS = {"fld", "fild", "fbld", "fldz", "fld1", "fldpi", "fldl2e", "fldl2t", "fldlg2", "fldln2"}


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
    # (callee -> the next direct call reached with its eax / edx untouched: that call's register
    # inputs read them, `call lcg64; mov ecx, esi; call __aullshr`, the shift of lcg64's edx:eax.
    # Credited once the inputs are known, main())
    handoffs: list[tuple[int, int, bool, bool]] = []
    # (callee -> the direct calls between it and a ret that leaves its eax: its result returned if
    # they leave eax and edx alone, decided in main())
    passes_via: list[tuple[int, list[int]]] = []
    st_over: list = []
    st_clean: set = set()           # (callees some site hands to the ret with st0 untouched)
    for a, ins in insns.items():
        t = _target(ins)
        if a not in state:
            continue
        # (running off the end into the next function is a tail jump to it: VS2010's _sqrt goes on
        # into __sqrt_default, whose st0 is its result)
        fall = a + ins.size
        if fall not in insns and ins.mnemonic not in ("ret", "jmp", "int3", "hlt", "ud2") \
                and not (ins.mnemonic == "call" and t in _noreturn) and _b is not None and _b.is_func_start(fall) \
                and fall not in passes:
            passes.append(fall)
        if t is None:
            # (an indirect call's: by its address, for its call-site signature)
            if ins.mnemonic != "call":
                continue
            t = ("site", a)
        if ins.mnemonic == "jmp":
            # (a tail jump to one that does not return passes nothing back: __security_check_cookie's
            # `jne ___report_gsfailure` made the cookie check an edx:eax one, 2026-10-24)
            if not isinstance(t, tuple) and t not in insns and t not in _noreturn:
                passes.append(t)
            continue
        if ins.mnemonic != "call" or t in _noreturn:
            continue
        p = nxt[a]
        eax_w = edx_w = xmm0_w = st_loaded = False
        st_depth = 0
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
                # (an import's or an indirect call's result returned as it is counts too, by the
                # call site: the CRT's printf wrapper returns __stdio_common_vfprintf's count, void
                # otherwise and print()'s `n = printf(...)` 0, rhtest crt-O2 2026-10-24)
                if not eax_w:
                    passes.append(t)
                    # (its eax, not its st0, with a value loaded over it on the way: a stream's
                    # float read, `call read_bytes; fld dword ptr [ebp - 4]; ret`, returns its own
                    # load, and as float the byte reader 0x105aec0 was a stub, its st0 lost, a
                    # VS2010 client 2026-10-26)
                    if st_loaded and t not in st_over:
                        st_over.append(t)
                    elif not st_loaded:
                        st_clean.add(t)
                break
            # (a load onto the x87 stack reads no st0, and the straight line goes on for eax and
            # edx: walk's V2 came back in edx:eax, read past `fld qword ptr [c]`, and as an i4 the
            # y half was extraout_EDX, rhtest msvc-16.00-x86 cpp-O2. What the x87 code reads after
            # it is no result of the callee's)
            if mn in X87_LOADS and not (pi.operands and pi.operands[0].type == X.X86_OP_REG):
                st_loaded = True
                st_depth += 1
                p = nxt[p]
                continue
            if st_loaded and mn.startswith("f") and not mn.startswith("fn"):
                # (but an operand st(n), n the values loaded since the call, is the callee's result
                # under them: a determinant's caller, `call det; fld1; fdivrp st(1)`, its 1/det. As
                # no read, the determinant was void and its caller's extraout_ST0 a stub, 9,564
                # calls on a VS2010 client's startup path, 2026-10-26)
                if st_depth and any(o.type == X.X86_OP_REG and o.reg == X.X86_REG_ST0 + st_depth
                                    for o in pi.operands):
                    kind = kind or "d8"
                    break
                p = nxt[p]
                continue
            # (the control and status words touch no st0: a float rounded toward zero, `call f;
            # fnstcw [m]; ...; fldcw [m2]; fistp qword ptr [t]`, its fldcw taken for the first x87
            # instruction and no read, f void and its callers stubs for extraout_ST0, 2026-10-26)
            if mn in ("fldcw", "fstcw", "fnstcw", "fstsw", "fnstsw", "fclex", "fnclex", "fwait", "wait"):
                p = nxt[p]
                continue
            if mn.startswith("f") and not mn.startswith("fn"):
                # (st0: the callee's x87 result, if the first x87 instruction reads it)
                if mn in ("fstp", "fst", "fcomp", "fcom", "fxch", "fadd", "fmul", "fsub", "fdiv",
                          "fistp", "fist", "fchs", "fabs", "fsqrt", "fucomp", "fucom", "fcomip", "fucomip",
                          "faddp", "fmulp", "fsubp", "fsubrp", "fdivp", "fdivrp", "fcompp", "fucompp", "ftst"):
                    width = pi.operands[0].size if pi.operands and pi.operands[0].type == X.X86_OP_MEM else 8
                    kind = kind or ("f4" if width == 4 else "d8")
                    # (and one that pops it, `call f; fstp [esi + 0xfc]; ... ret`: the callee's st0
                    # is the caller's to store, not to return, whatever eax reaches the ret. Taken
                    # for passed on, a camera update returned a float, its decompilation failed
                    # "Forced merge caused intersection", a VS2010 client's 0xb75490 2026-10-27)
                    if (mn.endswith("p") or mn in ("fcompp", "fucompp")) and t not in st_over:
                        st_over.append(t)
                break
            # (an unconditional jump within the function goes on there: `call ctor; jmp join` with
            # `join: mov [g], eax`, the other path's `xor eax, eax`. Stopped at the jump, the
            # constructor FUN_004f5b30 returned nothing, its object 0, and FUN_004f5b80 wrote
            # through it, a VS2010 client 2026-10-24)
            if mn == "jmp" and _target(pi) is not None and _target(pi) in insns:
                p = end = _target(pi)
                continue
            if mn in ("call", "jmp") or mn.startswith("j") or mn.startswith("loop"):
                t2 = _target(pi)
                if mn == "call" and t2 is not None and not isinstance(t, tuple) and not (eax_w and edx_w):
                    handoffs.append((t, t2, eax_w, edx_w))
                break
            r, w = regs_access(pi)
            ops = pi.operands
            # (xmm0 read before written: the callee's SSE result, which /LTCG returns there, a
            # double by an `sd` read. fc_dbl's caller multiplied its xmm0 and, the result
            # unknown, Ghidra took the value from before the call, rhtest calls-GL 2026-10-24)
            defines = mn in SCALAR_DEFS and ops and ops[0].type == X.X86_OP_REG and ops[0].reg == X.X86_REG_XMM0 \
                and not (len(ops) > 1 and ops[1].type == X.X86_OP_REG and ops[1].reg == X.X86_REG_XMM0)
            # (`xorps xmm0, xmm0` zeroes it, no read: after free, FUN_00406ad0, it made free an xmm0
            # one, and through its wrappers 1,900 functions, 2026-10-24)
            defines = defines or (mn in ("xorps", "xorpd", "pxor", "subps", "subpd", "psubd", "psubq", "pcmpeqd")
                                  and len(ops) == 2 and all(o.type == X.X86_OP_REG and o.reg == X.X86_REG_XMM0 for o in ops))
            if not xmm0_w and kind is None and X.X86_REG_XMM0 in r and not defines:
                kind = "q8" if re.search(r"sd$|pd$|^cvtsd2|^cvttsd2", mn) else "s4"
                break
            if X.X86_REG_XMM0 in w:
                xmm0_w = True
            # (`xor r, r`, `sub r, r`, `sbb r, r` only write r: `cmp ecx, edi; sbb edx, edx` after
            # a call is no read of an edx result)
            zero = only_writes(pi)
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
        # (or a read of eax past the branches the straight line stops at, nothing writing it on the
        # way: VS2010 kept bump()'s result in eax across two loops of x87 code and added it at the
        # end. Void, after_call lost it, rhtest msvc-16.00-x86 float-O2 2026-10-24)
        if kind is None and not eax_w and not isinstance(t, tuple):
            kind = eax_read_ahead(insns, state, nxt, a + ins.size)
        # (and edx's, an edx:eax result's high half read past a branch: pair_of's Pair32, its hi
        # stored after `jns` in /arch:IA32 x87 code, rhtest float-IA32 pair_scale)
        if kind in (None, "i1", "i2", "i4") and not edx_w and not isinstance(t, tuple) \
                and eax_read_ahead(insns, state, nxt, a + ins.size, regs=EDX_REGS):
            kind = "i8"
        if kind is not None:
            old = reads.get(t)
            reads[t] = kind if old is None or RET_RANK[kind] > RET_RANK[old] else old
        if t not in passes and eax_reaches_ret(insns, state, nxt, a + ins.size):
            passes.append(t)
        # (or across direct calls that may leave eax: the /GS check's, `call rec_sum; mov ecx,
        # [esp + 0x68]; xor ecx, esp; call __security_check_cookie; ret`. Not seen as returned,
        # rec_sum went untyped, and then i4 by its own `mov eax, ebx` before its ret, the high
        # word of rec_check's sum lost, rhtest int64-O2 2026-10-24)
        elif t not in passes and not isinstance(t, tuple):
            via: set[int] = set()
            if eax_reaches_ret(insns, state, nxt, a + ins.size, through=via) and via:
                passes_via.append((t, sorted(via)))
    # (not the cookie check: it keeps eax, the function's own value, and returns none of its own.
    # Taken as passed on, a bool returned in al stayed an i4 and its upper bytes extraout_EAX, a
    # VS2010 client's 0x4d14a0 on WinMain's path, 2026-10-26)
    passes = [p for p in passes if isinstance(p, tuple) or "security_check_cookie" not in _names.get(p, "")]
    # (per site: a callee whose st0 one site pops and another hands to the ret untouched, `call f;
    # pop edi; ...; ret 4`, is passed on all the same, 0x539e30 in a VS2010 client)
    st_over = [t for t in st_over if t not in st_clean]
    return reads, passes, handoffs, passes_via, st_over


def ecx_handoffs(insns, state, nxt) -> list[tuple[int, int]]:
    """(callee, next): a direct call followed in the straight line by a direct call or jump to
    `next`, nothing reading or writing ecx between them: what `next` takes in ecx, if it takes
    ecx, is the callee's ecx. MSVC hands a value so between a function and its own funclets' code:
    seh's normal path runs its __finally's body (`call 0x4018fd`, which adds 100 to r in ecx and
    stores it) and jumps on to the code after it, which reads r in ecx, rhtest eh-O2."""
    out = []
    for a, ins in insns.items():
        t = _target(ins)
        if ins.mnemonic != "call" or t is None or a not in state:
            continue
        p, end = nxt[a], a + ins.size
        for _ in range(8):
            if p is None or p != end or p not in insns or p not in state:
                break
            pi = insns[p]
            end = p + pi.size
            t2 = _target(pi)
            if pi.mnemonic in ("call", "jmp") and t2 is not None and t2 not in insns:
                out.append((t, t2))
                break
            if pi.mnemonic in ("call", "jmp", "ret") or pi.mnemonic.startswith(("j", "loop")):
                break
            r, w = regs_access(pi)
            if any(REG_BITS.get(x) == ECX for x in (*r, *w)):
                break
            p = nxt[p]
    return out


def only_writes(pi) -> bool:
    """An instruction that only writes its register, whatever it held: `xor r, r`, `sub r, r`,
    `sbb r, r` (the carry), `or r, -1`, `and r, 0`. (`or eax, 0xffffffff`, __setenvp's -1 after
    a free, read as a read made _free an i4 one, and ___free_lconv_num, which ends in its
    calls, a stub of extraout_EAX in every VS2010 program, rhtest msvc-16.00-x86 2026-10-25)"""
    ops = pi.operands
    if len(ops) != 2 or ops[0].type != X.X86_OP_REG:
        return False
    if ops[1].type == X.X86_OP_REG:
        return ops[0].reg == ops[1].reg and pi.mnemonic in ("xor", "sub", "sbb")
    if ops[1].type == X.X86_OP_IMM:
        ones = (1 << (8 * ops[0].size)) - 1
        return (pi.mnemonic == "or" and ops[1].imm & ones == ones) or (pi.mnemonic == "and" and ops[1].imm == 0)
    return False


def eax_read_ahead(insns, state, nxt, start, limit=256, regs=EAX_REGS) -> str | None:
    """The width of the first read of eax on some path from start before anything writes it (a
    call ends a path: it writes eax; a ret is result_reads' pass-through, not a read here), as a
    result kind, across branches and loops; None when no path reads it. (Or of edx, regs:
    EDX_REGS)"""
    EAX_REGS = regs
    seen, work, width = set(), [start], 0
    while work and len(seen) < limit:
        p = work.pop()
        if p is None or p in seen or p not in insns or p not in state:
            continue
        seen.add(p)
        pi = insns[p]
        mn = pi.mnemonic
        if mn in ("ret", "call", "int3", "hlt"):
            continue
        zero = only_writes(pi)
        r, w = regs_access(pi)
        if not zero:
            for x in r:
                if x in EAX_REGS:
                    width = max(width, 4 if x == X.X86_REG_EAX else 2 if x == X.X86_REG_AX else 1)
        if width or any(x in EAX_REGS for x in w):
            if width:
                break
            continue
        if mn.startswith("j") or mn.startswith("loop"):
            t = _target(pi)
            if t is None:
                continue
            work.append(t)
            if mn == "jmp":
                continue
        work.append(nxt.get(p))
    return f"i{width}" if width else None


def eax_reaches_ret(insns, state, nxt, start, limit=64, through=None):
    """Whether a path from start reaches a ret with eax unwritten, across branches: operator new's
    `call malloc; test eax, eax; jne done; ...; done: ret` returns malloc's, where the straight line
    stops at the jne and every `new` came back 0, rhtest cpp-O2 2026-10-24. A call ends a path (it
    writes eax), as does a jump that cannot be followed; with `through`, a direct call does not,
    and its target is added there."""
    seen, work = set(), [start]
    while work and len(seen) < limit:
        p = work.pop()
        if p in seen or p not in insns or p not in state:
            continue
        seen.add(p)
        pi = insns[p]
        mn = pi.mnemonic
        if mn == "ret":
            return True
        if mn == "call" and through is not None and _target(pi) is not None:
            through.add(_target(pi))
            work.append(nxt.get(p))
            continue
        if mn == "call" or any(x in EAX_REGS for x in regs_access(pi)[1]):
            continue
        if mn.startswith("j") or mn.startswith("loop"):
            t = _target(pi)
            if t is None:
                continue
            work.append(t)
            if mn == "jmp":
                continue
        work.append(nxt.get(p))
    return False


# a return's kinds, the wider winning where callers differ
# (s4 / q8: a float / double in xmm0, /LTCG's)
RET_RANK = {"i1": 1, "i2": 2, "i4": 3, "f4": 4, "d8": 4, "s4": 4, "q8": 4, "i8": 5}


def later_cleanup(insns, nxt, a) -> int | None:
    """The caller's `add esp, k` after the call at `a`: right after it, or a few instructions on
    in the straight line, nothing between moving esp or leaving (/LTCG schedules the result's
    first read ahead of it: sort_check's `call isort; mov eax, [esp + 0x14]; add esp, 4`)."""
    p, end = nxt[a], a + insns[a].size
    for _ in range(6):
        if p is None or p != end or p not in insns:
            return None
        pi = insns[p]
        end = p + pi.size
        mn, ops = pi.mnemonic, pi.operands
        if mn == "add" and len(ops) == 2 and ops[0].type == X.X86_OP_REG and ops[0].reg == X.X86_REG_ESP \
                and ops[1].type == X.X86_OP_IMM:
            return ops[1].imm
        if mn in ("call", "jmp", "ret", "push", "pop") or mn.startswith(("j", "loop")) or \
                X.X86_REG_ESP in regs_access(pi)[1]:
            return None
        p = nxt[p]
    return None


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
        k = later_cleanup(insns, nxt, a)
        if k:
            n = k
        if not n:
            continue
        left, q, p = n // 4, a, prv[a]
        # (the argument slots written after their push, by esp offset at the call: `push ecx;
        # movss [esp], xmm0; call fbits` passes the float, the push only made the room)
        depth, written = 0, set()
        while left > 0 and p is not None and p in insns and q not in labels:
            pi = insns[p]
            mn = pi.mnemonic
            if mn in ("call", "jmp", "ret", "pop") or mn.startswith("j") or any(
                    o.type == X.X86_OP_REG and o.reg == X.X86_REG_ESP for o in pi.operands):
                break
            if mn == "push":
                o = pi.operands[0] if pi.operands else None
                left -= 1
                if o is not None and o.type == X.X86_OP_REG and o.reg in FULL and p in state \
                        and not state[p][0] & FULL[o.reg] and depth not in written:
                    found |= FULL[o.reg]
                depth += 4
            else:
                for i, o in enumerate(pi.operands):
                    if i == 0 and o.type == X.X86_OP_MEM and o.mem.base == X.X86_REG_ESP and not o.mem.index \
                            and mn.startswith(("mov", "fst")):
                        written.add(depth + o.mem.disp)
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
        # (but an if's jump on to its join, between it and the call: a branch's end, its other
        # branch scanned too on the way back. Havok's tagfile reader 0xe0c190, `mov ebx,
        # [__imp_TlsGetValue]` above an if/else, `call ebx` below it with `xor ecx, ecx` between:
        # a __thiscall of 2, the index the second, read at 0, 2026-10-26)
        if pi.mnemonic == "jmp" and _target(pi) is not None and p < _target(pi) <= a:
            p = prv[p]
            continue
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


def vtable_from_ecx(insns, prv, a) -> bool:
    """The virtual call at `a` reads its vtable from `[ecx]`, and nothing writes ecx from that load
    to the call: ecx holds the object at the call, its `this`, whatever earlier call it was set
    before (VS2010's sinks: `mov ecx, [esp + 4]; push ecx; call note; mov eax, [ecx]; ...; call
    eax`, ecx kept across note)."""
    op = insns[a].operands[0] if insns[a].operands else None
    if op is None:
        return False
    regs = {op.mem.base} if op.type == X.X86_OP_MEM and op.mem.base and not op.mem.index else \
        {op.reg} if op.type == X.X86_OP_REG else set()
    if not regs:
        return False
    p = prv[a]
    for _ in range(24):
        if p is None or p not in insns:
            return False
        ins = insns[p]
        mn, ops = ins.mnemonic, ins.operands
        if mn in ("call", "jmp", "ret") or mn.startswith("j"):
            return False
        _r, w = regs_access(ins)
        if any(REG_BITS.get(r) == ECX for r in w):
            return False
        hit = [r for r in w if r in regs]
        if hit:
            if mn != "mov" or len(ops) != 2 or ops[1].type != X.X86_OP_MEM or ops[1].mem.index:
                return False
            if ops[1].mem.base == X.X86_REG_ECX and not ops[1].mem.disp:
                return True                        # the vtable, `mov r, [ecx]`
            regs = {ops[1].mem.base}               # the slot, `mov r, [vt + K]`
        p = prv[p]
    return False


def pushed_object_vtable(insns, prv, a) -> bool:
    """The indirect call at `a` goes through the vtable of the object last pushed: its target is
    `[vt + K]` (or a register loaded so), vt is loaded from `[obj]`, and the last push before the
    call is obj itself. A COM call, `this` on the stack, whatever ecx holds: `mov edx, [esi]; mov
    eax, [edx + 4]; push esi; call eax` (AddRef) on a path where ecx held a global's object was
    taken for a __thiscall of it (a VS2010 client's 0x4e02b7, 2026-10-25)."""
    op = insns[a].operands[0] if insns[a].operands else None
    if op is None:
        return False
    # the straight line back to the previous call or branch, nearest first
    line = []
    p = prv[a]
    while p is not None and p in insns and len(line) < 24:
        mn = insns[p].mnemonic
        if mn in ("call", "jmp", "ret", "int3") or mn.startswith("j") or mn.startswith("loop"):
            break
        line.append(insns[p])
        p = prv[p]

    def def_of(reg, after):
        """the nearest write of reg in line past index `after`: (index, insn)"""
        for i in range(after + 1, len(line)):
            if reg in regs_access(line[i])[1]:
                return i, line[i]
        return None, None

    def load(ins, disp_ok):
        ops = ins.operands
        return ins.mnemonic == "mov" and len(ops) == 2 and ops[1].type == X.X86_OP_MEM and not ops[1].mem.index \
            and ops[1].mem.base and (disp_ok or not ops[1].mem.disp)

    if op.type == X.X86_OP_REG:
        i1, d = def_of(op.reg, -1)
        if d is None or not load(d, True):
            return False
        vt = d.operands[1].mem.base
    elif op.type == X.X86_OP_MEM and not op.mem.index and op.mem.base:
        i1, vt = -1, op.mem.base
    else:
        return False
    i2, d = def_of(vt, i1)
    if d is None or not load(d, False):
        return False
    obj = d.operands[1].mem.base
    ip = next((i for i, ins in enumerate(line) if ins.mnemonic == "push"), None)
    if ip is None or not line[ip].operands or line[ip].operands[0].type != X.X86_OP_REG \
            or line[ip].operands[0].reg != obj:
        return False
    # (not a push that only reserves a slot the next store fills, `push ecx; fstp dword ptr
    # [esp]`: a float argument, the object in ecx all the same, slot_overwritten)
    if slot_overwritten(insns, line[ip].address):
        return False
    # (the same object: obj not written between its push and its vtable's load)
    lo, hi = sorted((ip, i2))
    if any(obj in regs_access(line[i])[1] for i in range(lo + 1, hi)):
        return False
    # (but ecx loaded with that object too is a __thiscall that also passes it: `mov eax, [esi];
    # mov edx, [eax + 0x14]; push esi; mov ecx, esi; call edx`, a worker thread's entry handing
    # its object to its own run method. Taken for COM, the method's argument was its own address,
    # a VS2010 client's 0x4cf90f 2026-10-25)
    for ins in line:
        ops = ins.operands
        if ins.mnemonic == "mov" and len(ops) == 2 and ops[0].type == X.X86_OP_REG and ops[0].reg == X.X86_REG_ECX:
            return not (ops[1].type == X.X86_OP_REG and ops[1].reg == obj)
    return True


def com_call(insns, prv, a) -> bool:
    """The indirect call at `a` is a COM one through ecx as the vtable: its target is loaded from
    `[ecx + K]` (or is `[ecx + K]` itself), and ecx from `[R]`, the first word of an object. A
    __thiscall's ecx is the object, whose vtable is loaded into another register. IMalloc's
    `mov ecx, [eax]; push edx; push eax; mov eax, [ecx + 0x14]; call eax` was a __thiscall of the
    vtable, Release's stack `this` dropped, a VS2010 client's FUN_00420900 2026-10-25."""
    op = insns[a].operands[0] if insns[a].operands else None
    if op is None:
        return False
    if op.type == X.X86_OP_MEM:
        if op.mem.base != X.X86_REG_ECX or op.mem.index:
            return False
        found = True
    elif op.type == X.X86_OP_REG:
        # (a call through ecx itself: ecx is the target, never an object. VS2010's `mov ecx,
        # [eax + 4]; push esi; call ecx`, AddRef given its own address for `this`, rhtest
        # msvc-16.00-x86 calls com_calls)
        if REG_BITS.get(op.reg) == ECX:
            return True
        found = False
    else:
        return False
    target = None if found else op.reg
    p = prv.get(a)
    for _ in range(24):
        if p is None or p not in insns:
            return False
        ins = insns[p]
        mn, ops = ins.mnemonic, ins.operands
        if mn in ("call", "jmp", "ret") or mn.startswith("j"):
            return False
        w = regs_access(ins)[1]
        if not found and target in w:
            # (the slot, `mov r, [ecx + K]`)
            if mn != "mov" or len(ops) != 2 or ops[1].type != X.X86_OP_MEM or ops[1].mem.index \
                    or ops[1].mem.base != X.X86_REG_ECX:
                return False
            found = True
        elif any(REG_BITS.get(r) == ECX for r in w):
            # (the vtable, `mov ecx, [R]`, R no ecx)
            if not (found and mn == "mov" and len(ops) == 2 and ops[1].type == X.X86_OP_MEM
                    and not ops[1].mem.index and ops[1].mem.base not in (0, X.X86_REG_ECX)):
                return False
            if not ops[1].mem.disp:
                return True
            # (or `mov ecx, [R + d]`, an interface at d inside an object, when R is moved on to it,
            # `add R, d`, and pushed last: the interface pointer is `this`. An effect's
            # `mov ecx, [eax + 0x20]; add eax, 0x20; push 4; push edx; push eax; call [ecx + 0x10]`
            # took ecx for `this` and its size went unpassed, 2026-10-26)
            return embedded_interface_pushed(insns, nxt_of(insns, prv, p, a), p, a, ops[1].mem.base, ops[1].mem.disp)
        p = prv.get(p)
    return False


def nxt_of(insns, prv, start, end) -> list[int]:
    """the addresses from start to end (exclusive) in order, by walking prv back from end"""
    out, p = [], prv.get(end)
    while p is not None and p != start and len(out) < 32:
        out.append(p)
        p = prv.get(p)
    return list(reversed(out))


def embedded_interface_pushed(insns, between, load, a, base, disp) -> bool:
    """between the vtable's load and the call, `base` moved on by disp (`add base, disp`, `lea
    base, [base + disp]`) and then the last word pushed before the call"""
    # (as it stood when pushed: the slot may be loaded into it after, `push eax; mov eax, [ecx +
    # 0x10]; call eax`)
    moved, pushed_moved = False, False
    for q in between:
        ins = insns[q]
        mn, ops = ins.mnemonic, ins.operands
        if mn == "push":
            pushed_moved = bool(ops) and ops[0].type == X.X86_OP_REG and ops[0].reg == base and moved
            continue
        if mn == "add" and len(ops) == 2 and ops[0].type == X.X86_OP_REG and ops[0].reg == base \
                and ops[1].type == X.X86_OP_IMM and ops[1].imm == disp:
            moved = True
        elif mn == "lea" and len(ops) == 2 and ops[0].type == X.X86_OP_REG and ops[0].reg == base \
                and ops[1].type == X.X86_OP_MEM and ops[1].mem.base == base and not ops[1].mem.index \
                and ops[1].mem.disp == disp:
            moved = True
        elif base in regs_access(ins)[1]:
            moved = False
    return pushed_moved


def pushed_this(insns, prv, a) -> bool:
    """The last word pushed before the indirect call at `a` is what ecx holds there, loaded from
    the same place: a COM call at /Od, `mov eax, [ebp - 0xc]; push eax; mov ecx, [ebp - 0xc]; mov
    edx, [ecx]; mov eax, [edx + 0xc]; call eax`, its `this` pushed, ecx the compiler's scratch
    copy. As a __thiscall, every argument went one along, rhtest msvc-16.00-x86 calls-Od com_calls."""
    def source(p, reg, limit=12):
        # (what `reg` was loaded from, walking back from p: the `mov reg, src` operand's text)
        for _ in range(limit):
            if p is None or p not in insns:
                return None
            ins = insns[p]
            if ins.mnemonic in ("call", "jmp", "ret") or ins.mnemonic.startswith("j"):
                return None
            if any(REG_BITS.get(r) == REG_BITS.get(reg) for r in regs_access(ins)[1]):
                ops = ins.operands
                if ins.mnemonic == "mov" and len(ops) == 2 and ops[0].type == X.X86_OP_REG and ops[0].size == 4:
                    return ins.op_str.split(",", 1)[1].strip()
                return None
            p = prv.get(p)
        return None
    ecx_src = source(prv.get(a), X.X86_REG_ECX)
    if ecx_src is None:
        return False
    p = prv.get(a)
    for _ in range(12):
        if p is None or p not in insns:
            return False
        ins = insns[p]
        if ins.mnemonic in ("call", "jmp", "ret") or ins.mnemonic.startswith("j"):
            return False
        if ins.mnemonic == "push":
            op = ins.operands[0]
            if op.type == X.X86_OP_REG:
                if REG_BITS.get(op.reg) == ECX:
                    return False
                src = source(prv.get(p), op.reg)
            else:
                src = ins.op_str.removeprefix("dword ptr ").strip()
            return src is not None and src.removeprefix("dword ptr ") == ecx_src.removeprefix("dword ptr ") \
                and "[" in src and "esp" not in src
        p = prv.get(p)
    return False


def reused_slots(insns, prv, nxt, a, n):
    """The bytes of argument slots a call reuses above the n it was pushed: a __cdecl call's
    argument left on the stack (its cleanup deferred) and stored into again, `push esi; call
    FUN_00d9b8e0; mov eax, esp; mov [eax], 3; ...; push eax; call edx`, the virtual call's second
    argument. Counted as consumed by the first call, the 3 went unpassed, FUN_00db68c0 read
    garbage for its flags, and Havok's thread memory was never set up (a VS2010 client, 2026-10-24)."""
    # (back to the previous call, then forward with esp's offset from there)
    p, start = prv.get(a), None
    for _ in range(ICALL_WINDOW):
        if p is None or p not in insns:
            break
        if insns[p].mnemonic in ("call", "jmp", "ret"):
            start = p
            break
        p = prv.get(p)
    if start is None:
        return 0
    cur, alias, stores = 0, {}, set()
    p = nxt.get(start)
    while p is not None and p != a and p in insns:
        ins = insns[p]
        ops = ins.operands
        mn = ins.mnemonic
        if mn == "push":
            cur -= 4
        elif mn == "pop":
            cur += 4
        elif mn == "mov" and len(ops) == 2 and ops[0].type == X.X86_OP_REG and ops[1].type == X.X86_OP_REG \
                and ops[1].reg == X.X86_REG_ESP:
            alias[ops[0].reg] = cur
        elif mn == "mov" and len(ops) == 2 and ops[0].type == X.X86_OP_MEM and not ops[0].mem.index \
                and (ops[0].mem.base == X.X86_REG_ESP or ops[0].mem.base in alias) and ops[0].size == 4:
            base = cur if ops[0].mem.base == X.X86_REG_ESP else alias[ops[0].mem.base]
            stores.add(base + ops[0].mem.disp)
        elif mn.startswith("j") or mn in ("call", "ret") or \
                (ops and ops[0].type == X.X86_OP_REG and ops[0].reg == X.X86_REG_ESP):
            return 0
        else:
            for r in regs_access(ins)[1]:
                alias.pop(r, None)
        p = nxt.get(p)
    if p != a:
        return 0
    extra = 0
    while cur + n + extra in stores:
        extra += 4
    return extra


def slot_overwritten(insns, p) -> bool:
    """the slot the push at p makes is stored over, `[esp]`, before the stack moves again: a push
    that only reserves room (`push ecx; fstp dword ptr [esp]`)"""
    q = p + insns[p].size
    for _ in range(4):
        ins = insns.get(q)
        if ins is None or ins.mnemonic in ("call", "ret", "push", "pop") or ins.mnemonic.startswith("j"):
            return False
        ops = ins.operands
        if ops and ops[0].type == X.X86_OP_MEM and ops[0].mem.base == X.X86_REG_ESP \
                and not ops[0].mem.disp and not ops[0].mem.index \
                and ins.mnemonic in ("fstp", "fst", "fistp", "fist", "mov", "movss", "movd"):
            return True
        if any(r == X.X86_REG_ESP for r in regs_access(ins)[1]):
            return False
        q += ins.size
    return False


def ecx_scan(insns, prv, p, budget, labels, preds, pushed, seen) -> tuple[bool, bool, int]:
    """Back from p to the previous call: (ecx written there, and not pushed after its write; ecx
    pushed on the way; steps taken). At a jump target the scan goes on along every way in, the
    jumps to it and the fall into it, and ecx is written only if it is on each: `mov ecx, esi;
    test al, al; jne 0x4de99b` then `mov edx, [esi]; mov eax, [edx + 8]; call eax` there, after a
    `ret 8` in address order. Scanned back over the ret alone, AddRef took no `this` (a VS2010
    client's 0x4de9a0, 2026-10-25)."""
    steps = 0
    while steps < budget:
        if p is None or p not in insns:
            return False, pushed, steps
        ins = insns[p]
        mn = ins.mnemonic
        if mn in ("call", "jmp", "ret", "int3"):
            return False, pushed, steps
        # (nor back over a loop's back edge: what the loop body writes is its own. /O2's
        # shell_malloc fills the block with ecx its counter, `inc ecx; cmp ecx, edi; jb top`, then
        # calls IMalloc's Realloc, a __thiscall of the count, rhtest msvc-14.51-x86 misc-O2)
        if (mn.startswith("j") or mn.startswith("loop")) and _target(ins) is not None and _target(ins) < p:
            return False, pushed, steps
        ops = ins.operands
        steps += 1
        if mn == "push":
            # (not one that only reserves its slot, overwritten through [esp] next: `push ecx; fstp
            # dword ptr [esp]` passes a float. Taken for `this` pushed, a reverb's update lost
            # its object, the sound driver's setup 2026-10-26)
            # (nor the prologue's, `push ebp; mov ebp, esp; push ecx`: a 4-byte local reserved.
            # Taken for `this` passed, a resource handle's slot 9 called its own slot 4 with no
            # object, `mov esi, ecx; mov eax, [esi]; call [eax + 0x10]`, and 0xcccccccc read, a
            # VS2010 client's 0x50144d 2026-10-26)
            if ops and ops[0].type == X.X86_OP_REG and ops[0].reg == X.X86_REG_ECX \
                    and not slot_overwritten(insns, p) and not in_prologue(insns, prv, p):
                pushed = True
        elif mn == "pop":
            if ops and ops[0].type == X.X86_OP_REG and ops[0].reg == X.X86_REG_ECX:
                return False, pushed, steps        # (`pop ecx`: a __cdecl call's cleanup, no `this`)
        elif any(REG_BITS.get(r) == ECX for r in regs_access(ins)[1]):
            return not pushed, pushed, steps
        if p in labels and p not in seen:
            s_set, s_pushed, s_steps = ecx_ways(insns, prv, p, budget - steps, labels, preds, pushed, seen)
            return s_set, s_pushed, steps + s_steps
        p = prv[p]
    return False, pushed, steps


def indirect_tail_jump(ins) -> bool:
    """A jump through a pointer that is no switch table's: `jmp [eax + 8]`, `jmp eax`, a forwarder
    to whatever the pointer holds (which may load st0), not `jmp [eax*4 + table]`. Taken for a
    function leaving the x87 stack alone, a forwarder's callers kept a stale st0 (ultrareview,
    2026-10-27)"""
    if ins.mnemonic != "jmp" or _target(ins) is not None or not ins.operands:
        return False
    op = ins.operands[0]
    return not (op.type == X.X86_OP_MEM and op.mem.index != 0)


def x87_depth_at_rets(insns, nxt, state, root=None) -> set:
    """The x87 stack depths each ret is reached with, along every way from the entry (falling
    through and jumping): loads push one, a popping instruction pops one (fcompp two). A call on a
    way leaves the stack as a callee leaves it, empty or its result in st0: depth 0 after it, and a
    pop of the result left at 0 (`call g; fstp [m]; fld [m]; fstp [n]; ret`, dead at its ret, as
    the return-path check before it said; unknown from any call on, it lost that, ultrareview
    2026-10-27). From the function's entry, not its lowest address (a chunk below it)."""
    entry = root if root is not None else (min(state) if state else None)
    depth: dict[int, object] = {}
    work = [(entry, 0)] if entry is not None else []
    out = set()
    while work:
        a, d = work.pop()
        if a is None or a not in insns:
            continue
        if a in depth and (depth[a] == d or depth[a] is None):
            continue
        # (two ways in with different depths: unknown, and so on from it)
        d = None if a in depth else d
        depth[a] = d
        ins = insns[a]
        m = ins.mnemonic
        if m == "ret":
            out.add(d)
            continue
        if d is not None:
            if m == "call":
                d = 0
            elif m.startswith(("fld", "fild", "fbld")) and m not in ("fldcw", "fldenv"):
                d += 1
            elif m in ("fcompp", "fucompp"):
                d -= 2
            elif m.startswith("f") and m.endswith("p") and not m.startswith(("fn", "fwait")):
                d -= 1
            # (popping a value it did not load: a callee's result, or one it was handed)
            d = max(d, 0)
        t = _target(ins)
        if (m.startswith("j") or m.startswith("loop")) and t is not None:
            work.append((t, d))
        if m != "jmp":
            work.append((nxt.get(a), d))
    return out


def in_prologue(insns, prv, p) -> bool:
    """Whether only a frame's setup comes before p, back to the function's entry: `push ebp`,
    `mov ebp, esp`, `sub esp, k`, `and esp, k` and register pushes."""
    q = prv.get(p)
    for _ in range(12):
        if q is None or q not in insns:
            return True
        ins = insns[q]
        ops = ins.operands
        if ins.mnemonic == "push" and ops and ops[0].type == X.X86_OP_REG:
            pass
        elif ins.mnemonic == "mov" and ins.op_str == "ebp, esp":
            pass
        elif ins.mnemonic in ("sub", "and") and ops and ops[0].type == X.X86_OP_REG and ops[0].reg == X.X86_REG_ESP:
            pass
        else:
            return False
        q = prv.get(q)
    return False


def reaches(insns, start, goal, limit=4096) -> bool:
    """Whether control flows from start to goal within the function (falling through, branching,
    jumping; a ret, or a call that does not return, ends a path)."""
    order = sorted(insns)
    nxt = {a: order[i + 1] if i + 1 < len(order) else None for i, a in enumerate(order)}
    work, seen = [start], set()
    while work and len(seen) < limit:
        a = work.pop()
        if a in seen or a not in insns:
            continue
        seen.add(a)
        if a == goal:
            return True
        ins = insns[a]
        mn = ins.mnemonic
        if mn.startswith("ret") or mn in ("int3", "hlt", "ud2"):
            continue
        t = _target(ins)
        if (mn.startswith("j") or mn.startswith("loop")) and t is not None:
            work.append(t)
        if mn != "jmp" and nxt.get(a) is not None:
            work.append(nxt[a])
    return False


def ecx_ways(insns, prv, p, budget, labels, preds, pushed, seen) -> tuple[bool, bool, int]:
    """ecx_scan over every way into the jump target p: each jump here, and the instruction before
    if it falls through, ecx written only if it is on each. One from below, a loop's back edge,
    ends it (unwritten)."""
    if not preds:
        for q, qi in insns.items():
            if qi.mnemonic.startswith("j") or qi.mnemonic.startswith("loop"):
                t = _target(qi)
                if t is not None:
                    preds.setdefault(t, []).append(q)
    srcs = preds.get(p, [])
    # (a jump from below is a loop's back edge only where the code from p reaches it again: an
    # out-of-line arm that jumps back up to a shared call is none. `mov ecx, esi; jne arm` ...
    # `call eax`, `arm: mov eax, [edx + 0x80]; jmp call` above a ret: taken for a loop, the call
    # lost `this`, and a resource handle's slot 32 read its argument from 0, a VS2010 client's
    # 0x4fcfac, 2026-10-25)
    if any(s > p and reaches(insns, p, s) for s in srcs):
        return False, pushed, 0
    before = prv[p]
    ways = [prv[s] for s in srcs]
    if before is not None and before in insns and insns[before].mnemonic not in ("jmp", "ret", "int3") \
            and not insns[before].mnemonic.startswith("ret"):
        ways.append(before)
    if not ways:
        return False, pushed, 0
    all_set, any_pushed, steps = True, pushed, 0
    for w in ways:
        s_set, s_pushed, s_steps = ecx_scan(insns, prv, w, budget - steps, labels, preds, pushed, seen | {p})
        steps += s_steps
        all_set &= s_set
        any_pushed |= s_pushed
    return all_set, any_pushed, steps


def ecx_index_only(insns, prv, a) -> bool:
    """ecx's uses between its last write (in the straight line back from the call at `a`) and
    the call are all as data: a memory operand's index, `[eax + ecx*4 + 0x20]`, or a value stored
    to memory, `mov [esp + 0x38], ecx`. A number or a structure's field, no `this`.
    `mov ecx, [idx]; mov eax, [eax + ecx*4 + 0x20]; mov edx, [eax]; push eax; mov eax, [edx +
    0x30]; call eax`, an index buffer's Unlock, took the index for its object (a VS2010 client's
    0x4dee41, 2026-10-25)."""
    uses = 0
    p = prv[a]
    for _ in range(ICALL_WINDOW):
        if p is None or p not in insns:
            return False
        ins = insns[p]
        mn = ins.mnemonic
        if mn in ("call", "jmp", "ret", "int3") or mn.startswith("j"):
            return False
        reads, writes = regs_access(ins)
        ops = ins.operands
        as_index = sum(1 for o in ops if o.type == X.X86_OP_MEM and o.mem.index == X.X86_REG_ECX
                       and o.mem.base != X.X86_REG_ECX)
        # (or stored to memory, `mov [esp + 0x38], ecx`: a value put in a structure. A display
        # query's driver-data address, `lea ecx, [esp + 0x40]` then stored as D3DKMT_ESCAPE's
        # pPrivateDriverData, was taken for D3DKMTEscape's `this`, a VS2010 client's 0xb1b39d,
        # 2026-10-25)
        stored = mn == "mov" and len(ops) == 2 and ops[0].type == X.X86_OP_MEM and ops[1].type == X.X86_OP_REG \
            and REG_BITS.get(ops[1].reg) == ECX and ops[0].mem.base != X.X86_REG_ECX and ops[0].mem.index != X.X86_REG_ECX
        if any(REG_BITS.get(r) == ECX for r in writes) and not (mn == "push"):
            # (the write itself may read ecx too: `mov ecx, [ecx*4 + table]`)
            return uses > 0
        if any(REG_BITS.get(r) == ECX for r in reads):
            if stored:
                uses += 1
                p = prv[p]
                continue
            if not as_index or any(o.type == X.X86_OP_REG and REG_BITS.get(o.reg) == ECX for o in ops) \
                    or any(o.type == X.X86_OP_MEM and o.mem.base == X.X86_REG_ECX for o in ops):
                return False
            uses += 1
        p = prv[p]
    return False


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
    # (the caller's cleanup, right after or a few instructions on: /LTCG's fold, `call edi; inc
    # esi; add esp, 8`, a __cdecl call of two, taken for one, rhtest msvc-16.00-x86 calls-GL)
    k = later_cleanup(insns, nxt, a)
    # ecx: written in the scan back to the previous call, and not pushed after its write
    # (and a call that is itself a jump target, from each way in: counted_take's `mov ecx, esi;
    # test al, al; jne grab_call` with the address order's predecessor the other path's `ret`. Scanned
    # from the ret, grab took the vtable for `this`, incremented its slot, and the next init call
    # ran a byte into init, rhtest msvc-14.51-x86 cpp-O2 counteds 2026-10-25)
    if a in labels:
        ecx_set, ecx_pushed, _steps = ecx_ways(insns, prv, a, ICALL_WINDOW, labels, {}, False, frozenset())
    else:
        ecx_set, ecx_pushed, _steps = ecx_scan(insns, prv, prv[a], ICALL_WINDOW, labels, {}, False, frozenset())
    # (the method's own `this`, still in ecx: nothing wrote ecx since the entry, calls included,
    # and the call a virtual one, through a slot of a vtable loaded from an object. `mov edi,
    # [__imp_CloseHandle]; ...; call edi` is no method's, and took `this` for its handle)
    if not ecx_set and not ecx_pushed and own_this and a in state and not state[a][0] & ECX \
            and virtual_call(insns, prv, a):
        ecx_set = True
    # (or the vtable read from `[ecx]` after an earlier call that keeps ecx: the object is ecx)
    if not ecx_set and not ecx_pushed and vtable_from_ecx(insns, prv, a):
        ecx_set = True
    # (but ecx holding a COM vtable, the call's slot read from it, is no `this`: the interface
    # pointer is the last word pushed, com_call)
    if ecx_set and (com_call(insns, prv, a) or pushed_this(insns, prv, a) or pushed_object_vtable(insns, prv, a)):
        ecx_set = False
    # (nor ecx holding an index, used since its write only to address memory)
    if ecx_set and ecx_index_only(insns, prv, a):
        ecx_set = False
    if k is not None:
        return ("__cdecl", k // 4)                 # (ecx then a scratch register: a variadic
                                                   # method passes `this` on the stack)
    if a not in state:
        return None
    # (a __cdecl call whose cleanup the compiler folded into a later call's: `push ..; call [f];
    # push ..; call [f]; add esp, 0x18` pops both. Taken for the callee's own, call_va's first
    # call left its 16 bytes uncounted and the second read the wrong pointer, rhtest calls O2.
    # Before next_call_deficit, which reads that cleanup as the next call's need)
    raw = state[a][3]
    if raw and folded_cleanup(insns, nxt, a, raw):
        return ("__cdecl", raw // 4)
    n = max(0, raw - next_call_deficit(insns, prv, nxt, a))
    n += reused_slots(insns, prv, nxt, a, n)
    # (and edx beside ecx, written since the last call and read by nothing before this one, the
    # call's own operand included: __fastcall's second register argument. `mov edx, 3; mov ecx,
    # x; call [ebp + 8]` passed only x, and call_fc's callback took 3 from nowhere, rhtest calls)
    if ecx_set and edx_argument(insns, prv, a):
        return ("__fastcall", n // 4)
    return ("__thiscall" if ecx_set else "__stdcall", n // 4)


def eh_funclets(b, local) -> set[int]:
    """The funclets whose result the EH runtime reads, from the tables the functions' constants
    name: a FuncInfo's catch handlers (each returns its continuation), an EH4 scope table's filters
    (each its verdict). A scope table is taken where its records are one: each one's enclosing level
    an earlier record's or -2, its handler a function's, as many as hold."""
    out: set[int] = set()
    for v in local.values():
        for x in v.get("eh_imms", ()):
            # (a C++ frame's handler thunk, `mov eax, FuncInfo; jmp __CxxFrameHandler3`: its
            # FuncInfo. Skipped as code, VS2010's catch funclets went unseen, rhtest
            # msvc-16.00-x86 eh-O2)
            if b.section_of(x) is not None and b.is_code(x):
                try:
                    if b.image[b.off(x)] == 0xB8:
                        x = b.u32(x + 1)
                except Exception:
                    continue
            if x in local or b.section_of(x) is None or b.is_code(x):
                continue
            try:
                if b.u32(x) & 0xFFFFFFF0 == 0x19930520:
                    tries, ptry = b.i32(x + 0xC), b.u32(x + 0x10)
                    for k in range(max(0, min(tries, 256))):
                        n, ph = b.i32(ptry + 20 * k + 0xC), b.u32(ptry + 20 * k + 0x10)
                        for h in range(max(0, min(n, 64))):
                            out.add(b.u32(ph + 16 * h + 0xC))
                    continue
                if b.i32(x) not in (-2,) and not -0x10000 < b.i32(x) < 0:
                    continue
                for k in range(64):
                    rec = x + 0x10 + 12 * k
                    enclosing, filt, handler = b.i32(rec), b.u32(rec + 4), b.u32(rec + 8)
                    if not (-2 <= enclosing < k) or enclosing == -1 or handler not in local \
                            or (filt and filt not in local):
                        break
                    if filt:
                        out.add(filt)
            except Exception:
                continue
    return out


def eh_continuations(b, ranges, funclets) -> set[int]:
    """The continuations the catch funclets return (`mov eax, <code>; ret`) that are no function's
    entry: VS2010's /O2 rethrows() resumes at its normal path's join, inside its own body, where
    MSVC 14 puts the code after the catch past the funclets. The EH runtime calls a continuation as
    a function on the frame's ebp; as no function there, `not translated` (rhtest msvc-16.00-x86
    eh-O2). ApplyFacts makes each one a function, the body it was in cut there and falling into it."""
    md = disassembler()
    out: set[int] = set()
    for h in funclets:
        for lo, hi in ranges.get(h, ()):
            got = list(md.disasm_lite(bytes(b.image[b.off(lo):b.off(lo) + (hi - lo)]), lo))
            # (the last load of eax before a ret, stores between: VS2010's `mov eax, 0x40138c;
            # mov [ebp - 0x14], edx; ret`)
            for k, (_a, _s, mn, _ops) in enumerate(got):
                if mn != "ret":
                    continue
                for _a2, _s2, mn2, ops2 in reversed(got[max(0, k - 4):k]):
                    m = re.fullmatch(r"eax, (0x[0-9a-f]+)", ops2) if mn2 == "mov" else None
                    if m:
                        t = int(m.group(1), 16)
                        if b.is_code(t) and not b.is_func_start(t) and b.func_containing(t) is not None:
                            out.add(t)
                        break
                    if mn2 in ("call", "jmp") or mn2.startswith("j") or re.match(r"(e?ax|al|ah)\b", ops2):
                        break
    return out


def argument_store(insns, nxt, a) -> bool:
    """A call ahead of the store at `a` in a straight line, esp unchanged on the way."""
    p, end = nxt[a], a + insns[a].size
    for _ in range(24):
        if p is None or p != end or p not in insns:
            return False
        ins = insns[p]
        end = p + ins.size
        mn = ins.mnemonic
        if mn == "call":
            return True
        if mn.startswith("j") or mn.startswith("loop") or mn == "ret" or mn in ("push", "pop") \
                or X.X86_REG_ESP in regs_access(ins)[1]:
            return False
        p = nxt[p]
    return False


def frame_alloc(insns) -> int | None:
    """The function's frame allocation, the `sub esp, K` among its first instructions, or None."""
    for k, ins in enumerate(sorted(insns.values(), key=lambda i: i.address)):
        if k >= 8:
            break
        ops = ins.operands
        if ins.mnemonic == "sub" and len(ops) == 2 and ops[0].type == X.X86_OP_REG and ops[0].reg == X.X86_REG_ESP \
                and ops[1].type == X.X86_OP_IMM:
            return ops[1].imm
    return None


def folded_cleanup(insns, nxt, a, n) -> bool:
    """A later `add esp, K` in the straight line after the call at `a` that pops more than what is
    pushed after it: the n argument bytes of `a` among them, so `a`'s callee left them."""
    p, end, pushed = nxt[a], a + insns[a].size, 0
    for _ in range(32):
        if p is None or p != end or p not in insns:
            return False
        ins = insns[p]
        end = p + ins.size
        mn, ops = ins.mnemonic, ins.operands
        if mn == "push":
            pushed += 4
        elif mn == "pop":
            # (a pop of what was there before the call: the epilogue restoring its saves, and its
            # `add esp, k` the frame's. diamond's `pop ecx; pop esi; add esp, 0x30` made its
            # virtual call a __cdecl of two, rhtest msvc-16.00-x86 cpp)
            if pushed <= 0:
                return False
            pushed -= 4
        elif mn == "add" and len(ops) == 2 and ops[0].type == X.X86_OP_REG and ops[0].reg == X.X86_REG_ESP \
                and ops[1].type == X.X86_OP_IMM:
            # (not the frame's release, `add esp, K; ret` of the prologue's `sub esp, K`: the calls
            # between popped their own, which this count does not see. com_release_last's AddRef,
            # `push edi; call eax`, a __stdcall, was a __cdecl by it, and the array read after it
            # one word off, rhtest calls com_release_last)
            after = insns.get(nxt.get(p)) if nxt.get(p) == end else None
            if after is not None and after.mnemonic == "ret" and ops[1].imm == frame_alloc(insns):
                return False
            return ops[1].imm >= pushed + n
        elif mn == "call":
            # (a __cdecl call between that takes more than was pushed after `a`: the words pushed
            # before `a` are its arguments, pushed early, not `a`'s. `push ebx; call [vt + 4]; add
            # eax, edi; push eax; push dst; call memcpy; add esp, 0xc`: the getter took memcpy's
            # size for `this`, and a shader load read 0xd4 + 8, a VS2010 client's 0x504190)
            t = _target(ins)
            need = _cdecl_args.get(t) if t is not None else None
            if need and need > pushed:
                return False
        elif mn in ("ret", "jmp") or mn.startswith("j") or any(
                o.type == X.X86_OP_REG and o.reg == X.X86_REG_ESP for o in ops[:1]):
            return False
        p = nxt[p]
    return False


def edx_argument(insns, prv, a) -> bool:
    """edx written in the straight line back to the previous call, not pushed, and read by
    nothing between its write and the call at `a` (the call's operand included: `mov edx, [ecx];
    call [edx + 8]` is a vtable's, no argument)."""
    read_after = any(REG_BITS.get(r) == EDX for r in regs_access(insns[a])[0])
    p = prv[a]
    for _ in range(ICALL_WINDOW):
        if p is None or p not in insns:
            return False
        ins = insns[p]
        mn = ins.mnemonic
        if mn in ("call", "jmp", "ret", "int3") or mn.startswith("j"):
            return False
        reads, writes = regs_access(ins)
        if mn == "push" and any(REG_BITS.get(r) == EDX for r in reads):
            return False
        if any(REG_BITS.get(r) == EDX for r in writes) and not (mn == "push"):
            return not read_after and REG_WIDTH.get(next(r for r in writes if REG_BITS.get(r) == EDX), 4) == 4
        if any(REG_BITS.get(r) == EDX for r in reads):
            read_after = True
        p = prv[p]
    return False


def next_call_deficit(insns, prv, nxt, a, depth=0) -> int:
    """The bytes the next call after `a` (in a straight line) takes beyond what is pushed between
    the two: arguments pushed for an outer call before an inner one is made. `push 2; push 0xcf;
    call [vt + 0x3c]; mov ecx, eax; call FUN_0043c920` (ret 8) is `FUN_0043c920(getter(), 0xcf, 2)`:
    taken as the getter's, the 8 bytes made FUN_0043c920's arguments of the caller's saved
    registers, 2,200 functions' unaff_ (2026-10-23)."""
    # (and the calls after that one, in a straight line, each taking the latest words first: the
    # arguments of two later calls pushed before a virtual getter, `push edx (-1); push 0; call
    # [vt + 8]; mov ecx, eax; call cb0950 (ret 4); push eax; call 0x42cc20 (ret 8)`. Counted for
    # the next call alone, the getter took the 0, cb0950 the -1, and a string init its length
    # from a saved register, an empty string, 2026-10-26)
    p, end, after = nxt[a], a + insns[a].size, 0
    deficit, calls_seen = 0, 0
    for _ in range(40):
        if p is None or p != end or p not in insns:
            return deficit
        pi = insns[p]
        end = p + pi.size
        if pi.mnemonic == "push":
            after += 4
        elif pi.mnemonic == "pop":
            # (a pop of nothing pushed since: the epilogue's restores, `pop esi; pop ebx; call
            # __security_check_cookie`, no outer call's arguments. Counted as owed to the cookie
            # check, they took IMalloc::Release's one word, `push eax; call edx`, a VS2010
            # client's FUN_00420900 2026-10-25)
            if after <= 0:
                return deficit
            after -= 4
        elif pi.mnemonic in ("ret", "jmp") or pi.mnemonic.startswith("j"):
            return deficit
        elif any(o.type == X.X86_OP_REG and o.reg == X.X86_REG_ESP for o in pi.operands) and pi.mnemonic != "call":
            return deficit                             # (esp adjusted otherwise: no telling)
        elif pi.mnemonic == "call":
            t = _target(pi)
            take = _cleanup.get(t) if t is not None else None
            if t is None:
                slot = import_slot(insns, prv, p)
                take = _imp_cleanup.get(slot) if slot is not None else None
            # (its cleanup right after or a few instructions on: VS2010's _output_l, `push [_cfltcvt_
            # tab]; call esi; call eax; mov edi, [ebp - 0x210]; add esp, 0x1c`. Seen only right
            # after, DecodePointer took _cfltcvt's seven arguments too, rhtest msvc-16.00-x86 crt)
            if not take:
                take = later_cleanup(insns, nxt, p)
            if not take and t is not None:
                take = _cdecl_args.get(t)
            # (what a call through a pointer takes, unknown here, is no count to go on past; but
            # the words pushed for it are, less what the calls after it still need of them, the
            # same count from there: `push edx; call [vt + 0x50]; push eax; call [vt + 0x1c];
            # mov ecx, eax; call f (ret 8)` is f(getter(), a(), edx), the getter's 0 words and f's
            # two. As unknown, the first call kept edx and f took its caller's saved edi, a stub
            # on a VS2010 client's frame path, 0x46d690 2026-10-26)
            if t is None and not take and calls_seen == 0 and depth < 3:
                take = max(0, after - next_call_deficit(insns, prv, nxt, p, depth + 1))
            known = t is not None or bool(take) or (t is None and calls_seen == 0 and depth < 3)
            # (a call through a pointer after the first: what it takes is not known here, so the
            # count stops there, as before)
            if calls_seen and t is None:
                return deficit
            take = take or 0
            # (a chain of calls each on the last one's result, `mov ecx, eax` right after: a
            # stream's `s << a << b << c`, every operand pushed before the first, the latest
            # words its. Havok's error report in 0xe0e030 pushes five around a virtual getter's
            # call, and the getter took the third's string, a stub, 2026-10-26)
            q = nxt.get(p)
            chained = known and q in insns and insns[q].mnemonic == "mov" and insns[q].op_str == "ecx, eax"
            # (on only while each call is short: calls nested in each other's arguments, the
            # later's words pushed first. One with its own words all pushed ends it: past it a
            # later call's shortfall is someone else's, `push 7; call [vt + 0xc]; push eax; push
            # fmt; push 0x40; push ecx; call fmt_s` gave the getter's 7 to a call two on. Not in a
            # chain, whose next takes the words left over first)
            if take > after:
                deficit += take - after
                after = 0
            elif chained:
                after -= take
            else:
                return deficit
            calls_seen += 1
            if calls_seen >= (12 if chained else 3):
                return deficit
        p = nxt[p]
    return deficit


def code_pointers(b: Binary) -> set[int]:
    """The code no function covers that the image points to: a relocated pointer into .text in
    data (the CRT's __xi_a..__xi_z initializer tables, atexit destructors, vtable slots, SEH scope
    tables) or an immediate in code (`push fn`, `mov [x], fn`: a callback handed over). Ghidra's
    analysis made none of them functions: 2,268 in a VS2010 client, the CRT's own
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


def import_args(b: Binary, ranges, funcs, takes: dict[int, int] | None = None) -> dict[str, int]:
    """Each __cdecl import's stack arguments as its callers clean them up: thunk (or IAT slot) ->
    the words of the `add esp, k` right after a call to it, the count most sites agree on (one
    `add` can clean up after two calls). Ghidra has no prototype for some of the ucrt's, and its
    decompiler then passes none: the /MD CRT's atexit called `_crt_atexit()` without the function,
    which ucrt then called at exit from whatever ecx held, 2026-10-24. ApplyFacts gives such an
    import that many, where it has no signature of its own."""
    from collections import Counter
    thunks = {int(f["entry"], 16) for f in funcs if f.get("thunk") and "::" in f["name"]}
    lo, hi = b.iat
    md = disassembler()
    seen: dict[int, Counter] = {}
    pend_pushes = 0
    for root, rs in ranges.items():
        if root in thunks:
            continue
        for lo_r, hi_r in rs:
            prev, pushes, ahead = None, 0, 0
            for ins in md.disasm_lite(bytes(b.image[b.off(lo_r):b.off(hi_r)]), lo_r):
                if prev is not None:
                    # (the cleanup, scheduled up to a few instructions on: `call _crt_atexit; xor
                    # ecx, ecx; add esp, 4`, nothing between that branches or moves esp)
                    tgt, k = prev, None
                    if ins[2] == "add" and ins[3].startswith("esp, "):
                        try:
                            k = int(ins[3][5:], 16) // 4
                        except ValueError:
                            k = None
                    elif ins[2] == "pop" and ins[3] in ("ecx", "edx") and ahead == 0:
                        k = 1                          # (MSVC's cleanup of one word, right after)
                    if k is not None:
                        # (no more than was pushed for it, nothing if nothing was: one `add` cleans
                        # up after two calls, and an epilogue's `pop ecx` after a call of none)
                        if pend_pushes:
                            seen.setdefault(tgt, Counter())[min(k, pend_pushes)] += 1
                        prev = None
                    else:
                        ahead += 1
                        if ahead > 4 or ins[2] in ("call", "ret", "push", "pop", "leave") or ins[2].startswith("j") \
                                or "esp" in ins[3]:
                            prev = None
                if ins[2] == "push":
                    pushes += 1
                if ins[2] == "call":
                    ops = ins[3]
                    t = None
                    if ops.startswith("0x"):
                        t = int(ops, 16) if int(ops, 16) in thunks else None
                    else:
                        m = re.fullmatch(r"dword ptr \[(0x[0-9a-f]+)\]", ops)
                        if m and lo <= int(m.group(1), 16) < hi:
                            t = int(m.group(1), 16)
                    if t is not None:
                        prev, pend_pushes, ahead = t, pushes, 0
                        pushes = 0
                    elif ops.startswith("0x") and takes is not None and int(ops, 16) in takes:
                        # (a direct call between the pushes and the import's call takes only its
                        # own words: the CRT's printf wrappers push five arguments, call
                        # __local_stdio_printf_options (none), push the options' two words and
                        # call __stdio_common_vsprintf, 7 words, counted 2, rhtest crt 2026-10-24)
                        pushes = max(0, pushes - takes[int(ops, 16)] // 4)
                    else:
                        pushes = 0
    return {hexa(t): max(c.items(), key=lambda kv: (kv[1], -kv[0]))[0] for t, c in sorted(seen.items())}


def thunk_slots(b: Binary, funcs) -> dict[int, int]:
    """Each import thunk, `jmp dword ptr [slot]`, and its slot."""
    md = disassembler()
    out = {}
    for f in funcs:
        if f.get("thunk") and "::" in f["name"]:
            e = int(f["entry"], 16)
            ins = next(md.disasm_lite(bytes(b.image[b.off(e):b.off(e) + 6]), e), None)
            m = re.fullmatch(r"dword ptr \[(0x[0-9a-f]+)\]", ins[3]) if ins and ins[2] == "jmp" else None
            if m:
                out[e] = int(m.group(1), 16)
    return out


def untyped_cleanup(local: dict, untyped: dict[int, int]) -> dict[int, int]:
    """The bytes each import with no prototype pops, from analyse's untyped_pushed: what most of
    its calls have outstanding, where no caller cleans up after it (a __cdecl one's callers do) and
    the count is a word or more. Its decompiled calls take what Ghidra sees pushed, but this
    analysis took the import for one that pops nothing: d3d9's Direct3DCreate9, `push 0x20; call
    thunk`, left its word outstanding on one path to a join, the other path's count differed, and
    the virtual call after it, `push edi; push esi; call edx`, took no `this`. And dinput8's
    DirectInput8Create, `push 0; ...; push 0x800; push 0; call [GetModuleHandleW]; push eax; call
    thunk`: five words, one since the call before (a VS2010 client, 2026-10-25). Slot -> bytes."""
    from collections import Counter
    votes: dict[int, Counter] = {}
    cleaned: set[int] = set()
    for v in local.values():
        for _a, (slot, pushed, k) in v.get("untyped_pushed", {}).items():
            if k:
                cleaned.add(slot)
            votes.setdefault(slot, Counter())[pushed] += 1
    out = {}
    for slot, c in votes.items():
        n, hits = c.most_common(1)[0]
        if slot not in cleaned and n >= 4 and n % 4 == 0 and hits * 2 > sum(c.values()):
            out[slot] = n
    return out


def cleans_later(after: list[tuple[str, str]], own: int = 0) -> bool:
    """Whether the instructions after a call, (mnemonic, operands) in a straight line, clean up
    its words: the compiler folding several calls' cleanups into one, /O2's `push ..; call
    [strtol]; push ..; call [strtoul]; ...; add esp, 0x24`. An `add esp, k` larger than what was
    pushed since the call pops the call's words too; one that pops only the later ones leaves them
    to the callee. Seen only right after, the CRT's conversions popped their own, a caller's locals
    read as its parameters and its caller's saved ebx passed for one (rhtest msvc-14.51-x86 crt-O2,
    tests/unit/test_protos32.py). Given the call's own parameter bytes, the `add` must pop at
    least those and the later pushes (`sub esp, k` a push of k, `sub esp, 8; fstp qword ptr
    [esp]`). One that pops more may also be covering earlier calls' deferred words, so a site is
    only a vote (stdcall_import_cleanup; ultrareview 2026-10-27, a stdcall import otherwise taken
    for __cdecl everywhere by one site)."""
    pushed = 0
    for mn, ops in after:
        if mn == "push":
            pushed += 4
        elif mn == "sub" and ops.startswith("esp, "):
            try:
                pushed += int(ops.split(", ")[1], 0)
            except ValueError:
                return False
        elif mn == "add" and ops.startswith("esp, "):
            try:
                k = int(ops.split(", ")[1], 0)
            except ValueError:
                return False
            return k >= pushed + own if own else k > pushed
        elif mn == "ret" or mn.startswith("j"):
            return False
    return False


def stdcall_import_cleanup(b: Binary, ranges, funcs, imp_cleanup: dict[int, int],
                           imp_params: dict[int, int]) -> dict[int, int]:
    """The bytes an import its type library calls __cdecl pops when it is __stdcall: its
    prototype's parameter bytes (ExportFunctions' import_params), where it is called and none of
    its callers cleans up after it. d3d9's Direct3DCreate9, so declared, popped nothing to this
    analysis: `push 0x20; call thunk` left its word outstanding on one path to a join, the other
    path's count differed, and the virtual call after the join, `push edi; push esi; call edx`,
    took no `this` (a VS2010 client, 2026-10-25). Slot -> bytes."""
    thunk_slot = thunk_slots(b, funcs)
    lo, hi = b.iat
    md = disassembler()
    called: set[int] = set()
    cleaned: set[int] = set()
    sites: dict[int, int] = {}
    later: dict[int, int] = {}
    for root, rs in ranges.items():
        if root in thunk_slot:
            continue
        for lo_r, hi_r in rs:
            got = list(md.disasm_lite(bytes(b.image[b.off(lo_r):b.off(hi_r)]), lo_r))
            for k, (_a, _s, mn, ops) in enumerate(got):
                if mn != "call":
                    continue
                slot = None
                if ops.startswith("0x"):
                    slot = thunk_slot.get(int(ops, 16))
                else:
                    m = re.fullmatch(r"dword ptr \[(0x[0-9a-f]+)\]", ops)
                    if m and lo <= int(m.group(1), 16) < hi:
                        slot = int(m.group(1), 16)
                if slot is None or imp_cleanup.get(slot) != 0 or not imp_params.get(slot):
                    continue
                called.add(slot)
                # (cleaned up by the caller within a few instructions: a __cdecl one indeed)
                for _a2, _s2, mn2, ops2 in got[k + 1:k + 5]:
                    if (mn2 == "add" and ops2.startswith("esp, ")) or (mn2 == "pop" and ops2 in ("ecx", "edx")):
                        cleaned.add(slot)
                        break
                    if mn2 in ("call", "ret", "push") or mn2.startswith("j"):
                        break
                if slot not in cleaned:
                    sites[slot] = sites.get(slot, 0) + 1
                    if cleans_later([(mn2, ops2) for _a2, _s2, mn2, ops2 in got[k + 1:k + 40]], imp_params[slot]):
                        later[slot] = later.get(slot, 0) + 1
    # (a folded cleanup at a site of its own is no proof alone: at least half its sites so, one
    # misread site does not take a stdcall import for __cdecl program-wide)
    cleaned |= {slot for slot, n in later.items() if n * 2 >= sites[slot]}
    return {slot: imp_params[slot] for slot in called - cleaned}


SSE_FLOAT = {f"{op}{w}" for op in ("mov", "add", "sub", "mul", "div", "sqrt", "min", "max", "comi", "ucomi")
             for w in ("ss", "sd")} | {"cvtss2sd", "cvtsd2ss", "cvtss2si", "cvtsd2si", "cvttss2si", "cvttsd2si"}
X87_FLOAT = {"fld", "fst", "fstp", "fadd", "fsub", "fsubr", "fmul", "fdiv", "fdivr", "fcom", "fcomp"}


def scalar_width(mn: str, size: int) -> int:
    """A scalar SSE instruction's memory operand by what it reads, `ss` 4 bytes and `sd` 8 (the
    source's for a conversion, cvtss2sd's 4): capstone sizes comisd's `xmmword ptr` 16, and as
    16 bytes dclamp's last double read two more parameters (rhtest float-Od, 2026-10-24)."""
    if mn not in SSE_FLOAT:
        return size
    m = re.match(r"cvtt?(ss|sd)2", mn)
    return {"ss": 4, "sd": 8}.get(m.group(1) if m else mn[-2:], size)


def float_read(mn: str) -> bool:
    """Whether an instruction's memory operand is a float: SSE scalar and x87 arithmetic (not
    x87's integer loads and stores, fild/fist, nor its control and state ones). (A string
    `movsd` reads through esi, never a parameter slot.)"""
    return mn in SSE_FLOAT or mn in X87_FLOAT


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
    # (the last run's of this binary only, "exe": a reference rebuilt with another layout took the
    # old one's stack bytes at each address for its first round, rhtest 2026-10-25)
    import hashlib
    exe_sha = hashlib.sha256(Path(project.EXE).read_bytes()).hexdigest()
    last = json.loads(prev.read_text()) if prev.exists() else {}
    if last.get("exe") == exe_sha:
        for k, e in last["functions"].items():
            if e.get("cc") == "__cdecl" or (e.get("cc") == "custom" and not e.get("callee_cleans")):
                cdecl_args[int(k, 16)] = e.get("stack", 0)
    names = {int(f["entry"], 16): f["name"] for f in funcs}
    ranges = {int(f["entry"], 16): [(int(lo, 16), int(hi, 16)) for lo, hi in f["ranges"]] for f in funcs}
    nr_path = FACTS / "noreturn.json"
    noreturn = {int(k, 16) for k in json.loads(nr_path.read_text())["functions"]} if nr_path.exists() else set()

    # 1. each function's own `ret N`, then through tail jumps (thunks) to a fixpoint
    b = Binary()
    md = disassembler()
    # (and the imports their type library calls __cdecl that pop their own: no caller cleans up)
    imp_params = {int(k, 16): v for k, v in exported.get("import_params", {}).items()}
    std_imp = stdcall_import_cleanup(b, ranges, funcs, imp_cleanup, imp_params)
    imp_cleanup.update(std_imp)
    print(f"imports typed __cdecl popping their own arguments: {len(std_imp)}", flush=True)
    # (a jump into the middle of another function shares its code: that function's range is this
    # one's too, from where it lands. VS2010's strcpy is `push edi; mov edi, [esp + 8]; jmp` into
    # strcat's copy loop, which reads its source at [esp + 0xc]: with its 7 bytes alone, strcpy
    # took one parameter and its source was in_stack_00000008, rhtest msvc-16.00-x86 crt. Only
    # code the walk reaches from the entry is read, so the rest of the range adds nothing)
    starts = set(ranges)
    owner = sorted((lo, hi, e) for e, rs in ranges.items() for lo, hi in rs)
    lows = [o[0] for o in owner]
    cleanup: dict[int, int] = {}
    tail_of: dict[int, int] = {}
    # (one pass: a root's ranges, extended so, are disassembled once for both its extension and its
    # `ret N` below; the extension reads only the original ranges, `owner`)
    for root, rs in list(ranges.items()):
        extra = []
        decoded = []
        for lo, hi in rs:
            got = list(md.disasm_lite(bytes(b.image[b.off(lo):b.off(lo) + (hi - lo)]), lo))
            decoded.append(got)
            for _a, _s, mn, ops in got:
                if not mn.startswith("j") or not ops.startswith("0x"):
                    continue
                t = int(ops, 16)
                if t in starts or any(l <= t < h for l, h in rs):
                    continue
                k = bisect.bisect_right(lows, t) - 1
                if k >= 0 and owner[k][0] <= t < owner[k][1] and (owner[k][0], owner[k][1]) not in extra:
                    extra.append((owner[k][0], owner[k][1]))
        if extra:
            ranges[root] = rs = rs + extra
            decoded += [list(md.disasm_lite(bytes(b.image[b.off(lo):b.off(lo) + (hi - lo)]), lo)) for lo, hi in extra]
        insns = {x[0]: x for got in decoded for x in got}
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
        # (and one that runs off its end into the next function, a tail jump without the jump:
        # VS2010's _sqrt, `lea edx, [esp + 4]; call __load_CW` and on into __sqrt_default, which
        # __CIsqrt calls. No ret of its own, it was no_ret, and dsqrt's code after it went)
        elif insns:
            last = max(insns)
            _a, size, mn, _ops = insns[last]
            if mn not in ("ret", "jmp", "int3", "hlt", "ud2") and not mn.endswith(" ret") \
                    and b.is_func_start(last + size) and last + size not in insns:
                tail_of[root] = last + size
    for _ in range(8):
        for f, t in tail_of.items():
            if f not in cleanup and t in cleanup:
                cleanup[f] = cleanup[t]

    # (the imports with no prototype, by slot and by thunk: their cleanup from their callers, below)
    t_slots = thunk_slots(b, funcs)
    untyped = {int(s, 16): int(s, 16) for s in exported.get("import_untyped", [])}
    untyped.update({t: s for t, s in t_slots.items() if s in untyped})

    # (and a typed import's parameter bytes: one that pops none still takes its own off what was
    # pushed, analyse)
    typed_params = {s: n for s, n in imp_params.items() if s not in untyped}
    init_args = lambda: (names, cleanup, noreturn, imp_cleanup, cdecl_args, untyped, t_slots, typed_params)  # noqa: E731

    if args.show:
        _init(*init_args())
        for s in args.show:
            a = int(s, 16)
            print(hexa(a), names.get(a), "cleanup", cleanup.get(a), analyse(a, ranges[a]))
        return

    # 2. local pass, in parallel
    with Pool(args.jobs, initializer=_init, initargs=init_args()) as pool:
        # (by address, whatever order the workers finish in: the passes below are order-sensitive,
        # and two runs over the same facts typed different returns, 2026-10-25)
        local = dict(sorted(pool.imap_unordered(_job, list(ranges.items()), chunksize=64)))
    # (an import with no prototype pops what its callers push, if none cleans up after it: its
    # cleanup set, and the functions calling one analysed again with it, until the counts hold.
    # Counted while another one's was still unknown, d3d9's D3DPERF_SetOptions took the word
    # pushed for Direct3DCreate9 before it as its own too)
    popped: dict[int, int] = {}
    for _round in range(4):
        found = untyped_cleanup(local, untyped)
        changed = {s: n for s, n in found.items() if popped.get(s) != n}
        if not changed:
            break
        popped.update(changed)
        imp_cleanup.update(changed)
        for t, s in t_slots.items():
            if s in changed:
                cleanup[t] = changed[s]
        again = [(f, ranges[f]) for f, v in local.items()
                 if any(s in changed for s, _p, _k in v.get("untyped_pushed", {}).values())]
        with Pool(args.jobs, initializer=_init, initargs=init_args()) as pool:
            local.update(pool.imap_unordered(_job, again, chunksize=8))
        local = dict(sorted(local.items()))
    print(f"imports with no prototype popping their callers' words: {len(popped)} "
          f"({', '.join(f'{hexa(s)} {n}' for s, n in sorted(popped.items()))})", flush=True)
    errors = sum(1 for v in local.values() if "error" in v)

    # the code no function covers, for ApplyFacts to make functions (prototyped on the next run,
    # over the extents then exported): what a pointer reaches, and the direct call and tail-jump
    # targets Ghidra did not follow
    pointed = code_pointers(b)
    called = {t for v in local.values() for t, _u, _k in v.get("calls", ())
              if b.is_code(t) and b.func_containing(t) is None}
    # (and the catch continuations inside a function's body, an entry the EH runtime calls)
    pointed |= eh_continuations(b, ranges, eh_funclets(b, local))
    leaves = pointed | called

    # 3. register inputs through calls and tail jumps (not from a function that never returns:
    # __report_gsfailure saves every register into its crash context, and through
    # __security_check_cookie's failure jump that made all of them inputs of every caller)
    inputs = {f: v.get("inputs", 0) for f, v in local.items()}
    # (nor from a static C runtime's setjmp, which reads the callee-saved registers to save them:
    # its prototype is the import's, SETJMP_SHAPE)
    setjmps = {f for f in local if SETJMP_NAME.fullmatch(names.get(f, ""))}
    for f in setjmps:
        inputs[f] = 0
    # (nor xmm registers from the C runtime's x87 math, which helpers32.py identified on a run before:
    # its SSE2 branches read xmm registers they never take, and handed on they made a rotation's
    # caller read in_XMM2_Da, a stub; each takes st0 (and pow st1), its call a fixup in ApplyFacts)
    hp = FACTS / "helpers32.json"
    math_helpers = set()
    if hp.exists():
        for k, n in json.loads(hp.read_text()).get("helpers", {}).items():
            if n in ("CIsqrt", "CIsin", "CIcos", "CIpow", "sqrt") and int(k, 16) in inputs:
                inputs[int(k, 16)] &= ST0
                math_helpers.add(int(k, 16))
    changed = True
    while changed:
        changed = False
        for f, v in local.items():
            if f in math_helpers:
                continue                          # (nor from their own SSE2 branches' callees)
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
                # (not into one that does not return: ___report_gsfailure reads the stack it is
                # handed, and __security_check_cookie's `jne` to it gave the check a stack parameter
                # its every caller filled with junk, WinMain's `unaff_EDI`, 2026-10-24)
                if t in noreturn:
                    continue
                if kind == "jmp" and stack_hi.get(t, 0) > stack_hi[f]:
                    stack_hi[f] = stack_hi[t]
                    changed = True

    # (a callee's result returned across direct calls that leave eax and edx as they found them,
    # and so does everything they call: the /GS check, result_reads' passes_via)
    def leaves_result(c, seen=()):
        v = local.get(c)
        if v is None or c in seen or len(seen) > 8:
            return False
        if v.get("writes_ret", 0) & (EAX | EDX) or v.get("opaque"):
            return False
        # (what it calls or jumps on to, too: the check's `jne` to the fast-fail stub, `mov ecx,
        # 2; int 0x29`, which no noreturn fact names)
        callees = {t for t, _u, _k in v.get("calls", ()) if not isinstance(t, tuple)} | set(v.get("passes", ()))
        return all(t in noreturn or leaves_result(t, (*seen, c)) for t in callees)
    for v in local.values():
        for t, via in v.get("passes_via", ()):
            if t not in v["passes"] and all(leaves_result(c) for c in via):
                v["passes"].append(t)

    # 3b. returns: a function returns what its callers read of it, and what a function that
    # returns its result (a wrapper, a tail jump) is read for
    rank = RET_RANK
    ret_of: dict[int, str] = {}
    why: dict[int, str] = {}
    need = {"i1": EAX, "i2": EAX, "i4": EAX, "i8": EDX, "f4": 64, "d8": 64, "s4": 128, "q8": 128}
    # (a result's register family: an integer in eax, an x87 one in st0, an SSE one in xmm0. A rank
    # orders kinds within one; across them it is no evidence. A wrapper whose returns reach both an
    # SSE math helper and an integer callee made the callee xmm0 too, and through every pass the
    # allocators: 7,136 xmm0 returns in a VS2010 client, _aligned_malloc's among them,
    # 2026-10-24)
    family = {"i1": "i", "i2": "i", "i4": "i", "i8": "i", "f4": "x87", "d8": "x87", "s4": "sse", "q8": "sse"}
    x87_firm: set[int] = set()
    unset_void: set[int] = set()

    def makes_edx(t, seen=()):
        """t writes edx, or returns a result one it calls makes (an import, a function the analysis
        has not seen, or an opaque one may)"""
        v = local.get(t)
        if v is None or v.get("opaque") or v.get("writes_ret", 0) & EDX:
            return True
        return any(makes_edx(c, (*seen, t)) for c in v.get("passes", ()) if c != t and c not in seen)

    def reaches_x87(f, seen=()):
        """whether a function's result can be an x87 value: it runs x87 code itself, or returns
        what a callee that can returns (its passes; an indirect call's might)"""
        v = local.get(f)
        if v is None or v.get("x87_use") or f in seen or len(seen) > 8:
            return True
        return any(isinstance(t, tuple) or reaches_x87(t, (*seen, f)) for t in v.get("passes", ()))

    def give(t, k, src, down=False):
        v = local.get(t)
        if v is None:
            return False
        # (no float result for one that runs no x87 code, nor anything it calls: a caller's x87
        # read after it is of the caller's own st0, kept across. 0x50c620 in a VS2010 client returns
        # al; as a double, its callers' st0 and its own paths read in_ST0, a stub on its startup path)
        if k in ("f4", "d8") and not reaches_x87(t):
            return False
        # (nor for one that sets all of eax just before its ret and leaves nothing on the x87 stack
        # there: what it returns. A vector's normalize, `mov eax, esi; ... fstp [esi + 8]; ret`,
        # returns itself, and as a double its callers' `*extraout_EAX` made 0x634920 a stub; a
        # random float's `... fld [ebp - 4]; ret` returns st0 though eax holds its bits, a VS2010
        # client 2026-10-26)
        if k in ("f4", "d8") and v.get("sets_eax") == 4 and not v.get("x87_ret_live", True):
            return False
        # (nor one whose st0 is certainly empty at its ret, analyse's x87_ret_dead)
        if k in ("f4", "d8") and v.get("x87_ret_dead"):
            return False
        # (no integer result inferred, none a caller reads, for one with a path to its ret that
        # never writes eax, which it does not take: what it leaves there is its caller's own. _free's
        # `if (p == 0) return;` beside its errno store `mov [esi], eax; pop esi; ret`, an i4 by
        # __get_errno_from_oserr's, and through it every function ending in a free, rhtest
        # msvc-16.00-x86 2026-10-25. One its caller returns, `call t; pop ebp; ret`, still takes it:
        # refused, the caller's own read of it was extraout_EAX, 392 stubs in a VS2010 client)
        if family.get(k) == "i" and v.get("eax_unset") and not v.get("inputs", 0) & EAX \
                and re.match(r"(returns |sets eax|keeps its eax)", src):
            unset_void.add(t)
            return False
        # (only a result the callee makes: it writes the register, or returns a callee's. memcpy,
        # free and __SEH_epilog4 leave edx alone, and callers keeping a value in it across them
        # made them edx:eax ones; one that writes eax but not edx is an eax one)
        # (or one that takes eax and leaves it as it came, its result its input: /GL's struct
        # return, the buffer's address in eax and handed back there untouched, VS2010's quad_mix,
        # whose caller read the Quad through it, rhtest msvc-16.00-x86 calls-GL)
        eax_kept = k in ("i1", "i2", "i4") and v.get("inputs", 0) & EAX and not v.get("vol_writes", 0) & EAX \
            and not v.get("opaque")
        if not v.get("writes_ret", 0) & need[k] and not v.get("passes") and not eax_kept:
            if k == "i8" and v.get("writes_ret", 0) & EAX:
                k = "i4"
            else:
                return False
        # (an edx:eax one only where some function its result comes from writes edx: a recursive
        # one passing only its own result on makes none. 0x414500, `push ebx; call 0x414500;
        # ... ret 4`, never writes edx, and its callers keep a pointer there across it: as edx:eax,
        # the pointer came back as its lost edx, 0, a VS2010 client 2026-10-25)
        if k == "i8" and not makes_edx(t):
            if not v.get("writes_ret", 0) & EAX and not v.get("passes"):
                return False
            k = "i4"
        if t in ret_of and family[k] != family[ret_of[t]]:
            # (another family: what its own code returns wins over what a caller passes on of it,
            # and a callee's type given down never replaces one it has)
            # (but an x87 result its callers read, through those that pass it on, over an eax one
            # only inferred from eax left alone or set before the ret, where it loads st0 itself:
            # VS2010's _fabs ends in a call to _ctrlfp with eax untouched, i4 by that, and
            # dabs's st0 was lost, rhtest msvc-16.00-x86 float-Od 2026-10-24)
            # (and kept: the family once settled so is not taken back by the eax inference, which
            # each round of the loop below would make again, forever)
            if t in x87_firm:
                return False
            inferred = re.match(r"(returns |sets eax|keeps its eax)", why[t]) is not None
            x87_own = family[k] == "x87" and v.get("writes_ret", 0) & 64
            if inferred and x87_own:
                x87_firm.add(t)
            elif down or not why[t].startswith("returned by"):
                return False
            ret_of[t] = k
            why[t] = src
            return True
        if t not in ret_of or rank[k] > rank[ret_of[t]]:
            ret_of[t] = k
            why[t] = src
            return True
        return False
    for f, v in local.items():
        for t, k in v.get("results", {}).items():
            give(t, k, f"read by {hexa(f)}")
        # (a result the next call takes in its registers: the 64-bit shift helpers' edx:eax)
        for t, t2, eax_w, edx_w in v.get("handoffs", ()):
            took = inputs.get(t2, 0)
            if took & EDX and not edx_w and not eax_w:
                give(t, "i8", f"passed by {hexa(f)} to {hexa(t2)}")
            elif took & EAX and not eax_w:
                give(t, "i4", f"passed by {hexa(f)} to {hexa(t2)}")
    # (and what only the EH runtime reads: a catch funclet's continuation address, an __except
    # filter's verdict. A filter returning its callee's, `push code; call filter; ret`, typed by no
    # caller of its own, returned void and 0, and RaiseException went unhandled, rhtest eh)
    for g in eh_funclets(b, local):
        give(g, "i4", "an EH funclet's result")
    # (and one that sets eax itself just before its ret, read by no caller it can see: a virtual
    # one's result, analyse's sets_eax)
    # (and one that loads its own x87 result before each ret, analyse's x87_own_ret)
    for f, v in local.items():
        if v.get("x87_own_ret") and f not in ret_of:
            give(f, v["x87_own_ret"], "loads st0 before its ret")
    for f, v in local.items():
        if v.get("sets_eax") and f not in ret_of:
            give(f, f"i{v['sets_eax']}", "sets eax before its ret")
    changed = True
    while changed:
        changed = False
        for f, v in local.items():
            for t in v.get("passes", ()):
                if f in ret_of and not (family[ret_of[f]] == "x87" and t in v.get("st_over", ())):
                    changed |= give(t, ret_of[f], f"returned by {hexa(f)}", down=True)
                # (and the other way: a function that returns a callee's result returns one. The
                # system allocator's Alloc, FUN_00404d60, returns _aligned_malloc's, and is called
                # only through its vtable, where no caller's read reaches it: void, the memory
                # manager's every allocation came back 0, 2026-10-23)
                # (eax only: memcpy and memset show as edx:eax ones, and every function that ends
                # in one became one too)
                # (an x87 one not where the callee's st0 was popped or loaded over before the ret,
                # st_over: the caller's own, stored, b75490's)
                if t in ret_of and not (family[ret_of[t]] == "x87" and t in v.get("st_over", ())):
                    changed |= give(f, "i4" if ret_of[t] == "i8" else ret_of[t], f"returns {hexa(t)}'s")
                # (one that leaves eax alone, the result is the caller's own: `mov eax, r; ...; call
                # __security_check_cookie; ret`. 4,830 functions had theirs only through the cookie
                # check's edx:eax, and many are called only through a vtable, 2026-10-24)
                elif t in local and not local[t].get("writes_ret", 0) & EAX and not local[t].get("passes") \
                        and not local[t].get("opaque") and v.get("writes_ret", 0) & EAX:
                    changed |= give(f, "i4", f"keeps its eax across {hexa(t)}")
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
                # (what a callee that does not return writes never reaches the caller's callers)
                if t in noreturn:
                    continue
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
            # (a COM interface first, whatever its other slots read: slot 0 QueryInterface's shape,
            # `ret 0xc` reading no ecx. Its methods take `this` on the stack; one slot of an XAPO's
            # reading ecx made every slot a method, `this` a dummy ecx before the real one, and
            # XAudio2's QueryInterface wrote through its riid, 2026-10-26. A slot that reads ecx
            # is a __thiscall by its own inputs all the same)
            # (or slot 0 an adjustor thunk to one, `sub [esp + 4], 4; jmp QueryInterface`: a second
            # interface's vtable, IXAPOParameters beside IXAPO, whose SetParameters took XAudio2's
            # parameters one word off, 2026-10-26)
            def qi_shaped(f, depth=2):
                v = local.get(f)
                if v is None:
                    return False
                if v.get("ret") == 12 and not inputs.get(f, 0) & ECX:
                    return True
                return depth > 0 and v.get("ret") is None and any(
                    k == "jmp" and isinstance(t, int) and qi_shaped(t, depth - 1) for t, _m, k in v.get("calls", ()))
            if slots and qi_shaped(slots[0]):
                continue
            if any(inputs.get(s, 0) & ECX for s in slots):
                methods.update(slots)
                continue
            # (and one none of whose slots reads ecx, unless it is a COM interface, slot 0 shaped as
            # QueryInterface: `ret 0xc`, three words, `this` the first. Havok's memory router's
            # slots, `call TlsGetValue; mov ecx, [eax + 0x2c]; ...; jmp edx`, each overwrite ecx and
            # jump on to the thread's allocator: __cdecl, the virtual call's `this` taken for the
            # size, a VS2010 client's 0x1138954 2026-10-25. Not a table of __cdecl functions, a slot
            # with a plain `ret` that reads stack arguments: pointers to callbacks, no vtable)
            first = local.get(slots[0]) if slots else None
            com = first is not None and first.get("ret") == 12
            cdecl_like = any(s in local and local[s].get("ret") == 0 and stack_hi.get(s, 0) > 4 for s in slots)
            if slots and not com and not cdecl_like and all(s in local for s in slots):
                methods.update(slots)

    # (the callees a float-returning caller calls with that result live in st0, analyse's st0_live;
    # and whether a function, or anything it calls, runs x87 code: a call through a pointer might)
    keeps_st0 = {t for f, v in local.items() if ret_of.get(f) in ("f4", "d8") for t in v.get("st0_live", ())}

    def x87_reach(f, seen=()):
        v = local.get(f)
        if v is None or v.get("x87_use") or v.get("opaque") or f in seen or len(seen) > 8:
            return True
        return any(not isinstance(t, tuple) and t not in noreturn and x87_reach(t, (*seen, f))
                   for t, _u, _k in v.get("calls", ()))

    # (and a result in ecx, analyse's ecx_handoffs: a callee that writes ecx, and returns nothing
    # else, whose caller's next call or jump takes ecx as it left it. Ghidra cannot see a result
    # there, and seh's code after its __finally read r as in_ecx, a stub, rhtest eh-O2. ApplyFacts
    # "c4": an int in ECX)
    for f, v in local.items():
        for t, t2 in v.get("ecx_handoffs", ()):
            lt = local.get(t)
            if lt is not None and t not in ret_of and t not in noreturn and inputs.get(t2, 0) & ECX \
                    and lt.get("vol_writes", 0) & ECX:
                ret_of[t] = "c4"
                why[t] = f"its ecx taken by {hexa(t2)} after {hexa(f)}'s call"

    # 4. conventions and parameters
    # (the functions some direct call or jump reaches)
    called_directly = {t for v in local.values() for t, _m, _k in v.get("calls", ()) if not isinstance(t, tuple)}
    passed_min: dict[int, int] = {}
    for v in local.values():
        for t, k in v.get("passed", {}).items():
            passed_min[t] = min(passed_min.get(t, k), k)
    # (the functions that leave the x87 stack as they found it, their callees too: st0 is the
    # caller's across a call to one, translate32's kept st0. The CRT's __load_CW, `fldcw [esp+4]`,
    # between a math tail's argument and its use: as a call that may load st0, `in_st0 =
    # extraout_ST0`, a stub, rhtest msvc-16.00-x86 float)
    leaves_x87 = {f for f, v in local.items() if "error" not in v and not v.get("x87_data", True)}
    changed = True
    while changed:
        changed = False
        for f in list(leaves_x87):
            if any(not isinstance(t, tuple) and t not in leaves_x87 and t not in noreturn
                   for t, _m, _k in local[f].get("calls", ())):
                leaves_x87.discard(f)
                changed = True
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
        elif f in methods and v.get("tail_ijmps"):
            cc = "__thiscall"                 # (and one that jumps on through a pointer: the memory
                                              # router's slots, their target's arguments after `this`)
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
        variadic = local[f].get("variadic") if not callee_cleans else None
        if variadic is not None:
            stack = 4 * variadic                  # (its fixed parameters; the rest each call's own)
        # (a __cdecl one every caller passes more than it reads: sized operator delete(p, size)
        # reads only p, and the deleting destructors' sizes went unpassed, rhtest cpp-O2 2026-10-24)
        # (not one that jumps on, an import's thunk above all: its callers' arguments are its
        # target's, and typed its own the CRT's stack check failed fast at entry)
        elif not callee_cleans and passed_min.get(f, 0) > stack and not v.get("tail_jumps"):
            stack = passed_min[f]
        # (a __cdecl import's thunk, `jmp [__imp__set_fmode]`, reads nothing itself: its import's
        # prototype's parameters. Typed so only while the import was taken for one popping its
        # own; once its callers' folded cleanup made it __cdecl, _set_fmode took none, rhtest
        # msvc-14.51-x86 int64-Od)
        if not callee_cleans and t_slots.get(f) in typed_params:
            stack = max(stack, typed_params[t_slots[f]])
        # (at most what the language's models place: x86win.cspec's stack entry is 500 bytes, and
        # FUN_00b2f1e0's 520, assigned whole, failed its decompilation, "Cannot assign parameter
        # address")
        if not callee_cleans or not ret_n:
            stack = min(stack, 496)
        # (one that forwards through an indirect tail jump, `ecx = this + 0x10c; jmp [vt + 8]`,
        # takes what its callers pass, unknown here: as many words as a forwarded call is given,
        # FORWARD_WORDS, all of them handed on. As a call of none, FUN_004f58c0 gave the graphics
        # allocator's Alloc garbage for its sizes, a VS2010 client 2026-10-24)
        # (only one no direct call reaches: a direct caller would pass the extra words from its
        # own stack, `in_stack_`, and be a stub)
        if local[f].get("tail_ijmps") and f not in called_directly:
            stack = max(stack, 4 * FORWARD_WORDS)
        # (and one a direct call reaches, with no ret of its own: what every caller pushes, handed
        # on. A client's Exd module getter, `mov ecx, [ecx + 0x10]; jmp [vt + 8]`, took no words,
        # and the sheet name its caller pushed reached the sheet lookup as garbage, 2026-10-26)
        elif local[f].get("tail_ijmps") and not ret_n and passed_min.get(f, 0) > stack:
            stack = min(passed_min[f], 4 * FORWARD_WORDS)
        regs = [n for bit, n in REG_NAMES if reg & bit]
        # (the stack ones by what reads them: a double two slots, ApplyFacts' double)
        slot_kinds = local[f].get("slots", {})
        stack_params, off = [], 4
        while off < 4 + stack:
            k = slot_kinds.get(off)
            if k == "d" and off + 8 <= 4 + stack:
                stack_params.append(["d", 8])
                off += 8
                continue
            stack_params.append([k, 4] if k in ("f", "n") else ["i", 4])
            off += 4
        params = [["i", 4]] * len(regs) + stack_params
        e = {"cc": cc, "params": params, "stack": stack}
        if v.get("fpu_clear"):
            e["fpu_clear"] = True
        if f in leaves_x87:
            e["keeps_st0"] = True
        # (the bytes below its entry its frame allocation reaches: translate32.py lays out that much
        # of a function that links an EH frame, whose funclets reach into it through ebp)
        if v.get("frame"):
            e["frame"] = v["frame"]
        if cc == "custom":
            # (the register parameters, before the stack ones; each at the width its own reads take,
            # an input it only hands on through a call whole)
            widths = local[f].get("in_width", {})
            e["regs"] = [NARROW.get((n, widths.get(bit, 4)), n) for bit, n in REG_NAMES if reg & bit]
            e["callee_cleans"] = callee_cleans
        if v["open"]:
            e["open"] = True
        if v["addr_taken"]:
            e["param_addr"] = True        # `lea r, [param]`: a parameter passed by address, or a va_list
        if variadic is not None:
            e["variadic"] = variadic      # its fixed parameter count: ApplyFacts marks it varargs
        if callee_cleans and ret_n and stack_hi[f] - 4 > ret_n:
            e["reads_beyond"] = stack_hi[f] - 4   # reads past its own cleanup: a check for later
        if ret_n is None:
            e["no_ret"] = True
        if f in ret_of:
            e["ret"] = ret_of[f]                  # what its callers read of its result
            # (but no wider than it makes it, al or ax set before every ret and no callee's returned:
            # a caller reading all of eax read bytes nothing set. FUN_005ef7d0's `xor al, al` and
            # `mov al, 1`, an i4, its eax past 0xb5b440, a void one, extraout_EAX, a VS2010 client)
            n = local[f].get("narrow_ret", 0)
            if n and ret_of[f] in ("i2", "i4") and int(ret_of[f][1]) > n and not local[f].get("passes"):
                e["ret"] = f"i{n}"
        elif local[f].get("tail_ijmps") and f not in called_directly:
            e["ret"] = "i4"                       # (what the forwarded call returns)
        elif f in unset_void or (local[f].get("eax_unset") and not inputs.get(f, 0) & EAX) \
                or any(t in local and t not in ret_of for t in local[f].get("passes", ())):
            # (or what it returns is a void callee's, `call 0xa92090; mov [esi + 4], edi; ...; ret`:
            # FUN_00a941f0 kept the uint an earlier round gave it through 0xa92090, its read of that
            # one's eax extraout_EAX, a VS2010 client 2026-10-25)
            e["ret"] = "v"                        # (give's refusal, a path that never sets eax: void,
                                                  # whatever a round before typed)
        keep = [n for bit, n in ((EAX, "eax"), (ECX, "ecx"), (EDX, "edx"))
                if not kills[f] & bit and not (bit == EAX and f in ret_of and ret_of[f] != "c4")
                and not (bit == EDX and ret_of.get(f) == "i8")]
        # (and st0, for one a caller calls with its float result in st0 still to return, that runs
        # no x87 code, nor does anything it calls: VS2010's _strtod_l returns its double past
        # __security_check_cookie, and the decompiler, the call killing st0, read extraout_ST0)
        if f in keeps_st0 and not x87_reach(f) and ret_of.get(f) not in ("f4", "d8"):
            keep.append("st0")
        # (on a __cdecl or __stdcall only, and never a register it takes: a keep convention is a new
        # name, which Ghidra does not treat as __thiscall, its `this` lost, and an input register
        # kept the decompiler reads as a saved one, unaff_ECX; 10,000 stubs, 2026-10-23)
        keep = [n for n in keep if not reg & dict((nm, b) for b, nm in REG_NAMES)[n]]
        # (a register convention that keeps some: custom, its inputs named in their registers, so
        # the keep convention ApplyFacts makes on the __cdecl / __stdcall base loses no `this`.
        # __security_check_cookie takes ecx and leaves eax and edx alone: as a __thiscall its
        # callers' `return __security_check_cookie(...)` read a result it never makes, 0 in the
        # port, and every function the cookie guards returned 0, 2026-10-24)
        if keep and reg and cc in ("__thiscall", "__fastcall"):
            widths = local[f].get("in_width", {})
            e["cc"] = cc = "custom"
            e["regs"] = [NARROW.get((n, widths.get(bit, 4)), n) for bit, n in REG_NAMES if reg & bit]
            # (what it pops is its own `ret N`: a __thiscall's assumed cleanup made the cookie
            # check, a plain `ret`, a __stdcall base popping 4 bytes)
            e["callee_cleans"] = bool(ret_n)
        if keep and cc in ("__cdecl", "__stdcall", "custom"):
            e["keep"] = keep                      # the volatile registers it leaves alone
        # (and the register inputs it leaves as it found them, by their place among its register
        # parameters: a caller that keeps `this` in ecx across the call reads `extraout_ECX` after
        # it, which translate32 takes for what it passed. Not a keep convention: Ghidra reads a kept
        # input as a saved one, unaff_ECX. FUN_00d7be90's call to FUN_00d79e80, a stub on WinMain's
        # path, 2026-10-24)
        in_regs = [(bit, n) for bit, n in REG_NAMES if reg & bit]
        keeps_in = {n: i for i, (bit, n) in enumerate(in_regs) if bit in (ECX, EDX) and not kills[f] & bit}
        if keeps_in:
            e["keeps_in"] = keeps_in
        out[hexa(f)] = e
        counts[cc] = counts.get(cc, 0) + 1
    # (a function with no ret of its own that jumps on to another directly, taking no stack words
    # itself, takes that one's: its callers' words are its target's. An Excel module getter,
    # `mov ecx, [ecx + 4]; jmp 0x52fba0`, took none, and the sheet name it hands on was its
    # in_stack_00000004, a stub on an add-on's path, 2026-10-26. Through chains of them, twice)
    def nregs(e):
        return {"__thiscall": 1, "__fastcall": 2}.get(e.get("cc"), len(e.get("regs", ())) if e.get("cc") == "custom" else 0)
    for _ in range(2):
        for f, v in local.items():
            e = out.get(hexa(f))
            # (no ret instruction at all: not one ending `ret` with a jump elsewhere on a path,
            # __security_check_cookie's `jne __report_gsfailure`, which took that one's word
            # and every function's frame checked so came out wrong)
            if e is None or e.get("stack", 0) or v.get("ret") is not None or e.get("variadic") is not None:
                continue
            jt = [t for t, _m, k in v.get("calls", ()) if k == "jmp" and isinstance(t, int) and hexa(t) in out]
            if len(jt) != 1 or not out[hexa(jt[0])].get("stack"):
                continue
            g = out[hexa(jt[0])]
            e["params"] = e["params"][:nregs(e)] + g["params"][nregs(g):]
            e["stack"] = g["stack"]
    # (a static C runtime's setjmp as the import is, `int __cdecl _setjmp3(jmp_buf, int, ...)`: read
    # off its instructions it took ebx, esi and edi and four words, the caller's locals above the
    # two pushed, and VS2010's jumps passed its volatile counter by value, kept in a register past
    # the longjmp back, rhtest msvc-16.00-x86 misc-O2)
    for f in setjmps:
        if hexa(f) in out:
            e = out[hexa(f)]
            for k in ("regs", "callee_cleans", "param_addr", "keep", "keeps_in"):
                e.pop(k, None)
            e.update(cc="__cdecl", params=[["i", 4], ["i", 4]], stack=8, variadic=2, ret="i4")

    path = write_facts("protos", {
        "exe": exe_sha,
        "rule": "x86 (protos32.py): ret N -> callee-cleanup stack bytes; ecx/edx read before "
                "written on some path (must-define, closed over direct calls and tail jumps) -> "
                "__thiscall / __fastcall; __cdecl stack parameters to the highest [entry esp + 4..] "
                "slot read through esp or ebp",
        "arch": "x86",
        "functions": out,
        "imports": import_args(b, ranges, funcs, {int(k, 16): v["stack"] for k, v in out.items()}),
        "leaves": [hexa(g) for g in sorted(leaves)],
        "pointed": [hexa(g) for g in sorted(pointed)],
        # (the locals one object spans below a pointer to it: ApplyFacts applyStackBlocks)
        "stack_blocks": {hexa(f): [v["local_block"]] for f, v in sorted(local.items()) if v.get("local_block")}})
    # each indirect call's convention and arguments: ApplyFacts' call-site signatures
    calls, ccs, rets = {}, {}, {}
    jumps = []
    for f, v in local.items():
        # (an indirect tail jump: a call that returns, ApplyFacts' "jumps", given the forwarder's
        # own words, `this` first where ecx holds one)
        # (one a direct call reaches hands on its own words, as many as its callers push: bump's
        # `mov ecx, esi; jmp edx` to the object's virtual get, at /O2. As a call of none, `this`
        # was lost and get read its object at the method's own address, rhtest msvc-16.00-x86 cpp)
        for a, ecx in v.get("tail_ijmps", ()):
            words = FORWARD_WORDS if f not in called_directly else out.get(hexa(f), {}).get("stack", 0) // 4
            jumps.append(hexa(a))
            calls[hexa(a)] = [["i", 4]] * (words + (1 if ecx else 0))
            ccs[hexa(a)] = "__thiscall" if ecx else "__stdcall"
        for a, (cc, n) in v.get("icalls", {}).items():
            calls[hexa(a)] = [["i", 4]] * (n + {"__thiscall": 1, "__fastcall": 2}.get(cc, 0))
            ccs[hexa(a)] = cc
            # (and its x87 result, where the caller reads one: `call edx; fcomp [x]`. Looked up in
            # the direct calls' loop below, by their addresses, no indirect call's ever matched:
            # every virtual float getter's result extraout_ST0, a VS2010 client's 0xcd9d70 a stub
            # its job threads call 3 million times, 2026-10-26)
            k = v.get("icall_rets", {}).get(a)
            if k:
                rets[hexa(a)] = {"f4": ["f", 4], "d8": ["d", 8], "i8": ["i", 8]}[k]
        # (a direct call to a variadic function: the words pushed for it, where more than its
        # fixed ones, analyse's call_pushes)
        for a, (t, n) in v.get("call_pushes", {}).items():
            # (and what was pushed before a register helper between them, analyse's pushes_past)
            past = v.get("pushes_past", {}).get(a)
            if past is not None:
                t2, m, k = past
                e2 = out.get(hexa(t2))
                if e2 is not None and not e2.get("stack") and not e2.get("callee_cleans"):
                    n = min(n + m, k)
            fixed = out.get(hexa(t), {}).get("variadic")
            if fixed is not None and n // 4 > fixed:
                calls[hexa(a)] = [["i", 4]] * (n // 4)
                ccs[hexa(a)] = "__cdecl"
    shapes: dict[str, int] = {}
    for cc in ccs.values():
        shapes[cc] = shapes.get(cc, 0) + 1
    write_facts("callsites", {
        "rule": "x86 (protos32.py icall_shape): ecx written since the last call and not pushed -> "
                "__thiscall, `this` first; `add esp, k` after the call -> __cdecl of k bytes; else "
                "the callee pops the arguments pushed since the last call",
        "arch": "x86", "calls": calls, "cc": ccs, "rets": rets, "jumps": jumps})
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
