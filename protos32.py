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
import sys
import time
from multiprocessing import Pool

import capstone
from capstone import x86_const as X

from pebin import FACTS, Binary, disassembler, hexa, regs_access, write_facts

EAX, ECX, EDX, EBX, ESI, EDI = 1, 2, 4, 8, 16, 32
ALL = 63
VOLATILE = EAX | ECX | EDX                    # a call's to clobber
REG_NAMES = [(EAX, "eax"), (ECX, "ecx"), (EDX, "edx"), (EBX, "ebx"), (ESI, "esi"), (EDI, "edi")]
REG_BITS = {X.X86_REG_EAX: EAX, X.X86_REG_AX: EAX, X.X86_REG_AL: EAX, X.X86_REG_AH: EAX,
            X.X86_REG_ECX: ECX, X.X86_REG_CX: ECX, X.X86_REG_CL: ECX, X.X86_REG_CH: ECX,
            X.X86_REG_EDX: EDX, X.X86_REG_DX: EDX, X.X86_REG_DL: EDX, X.X86_REG_DH: EDX,
            X.X86_REG_EBX: EBX, X.X86_REG_BX: EBX, X.X86_REG_BL: EBX, X.X86_REG_BH: EBX,
            X.X86_REG_ESI: ESI, X.X86_REG_SI: ESI, X.X86_REG_EDI: EDI, X.X86_REG_DI: EDI}
FULL = {X.X86_REG_EAX: EAX, X.X86_REG_ECX: ECX, X.X86_REG_EDX: EDX, X.X86_REG_EBX: EBX,
        X.X86_REG_ESI: ESI, X.X86_REG_EDI: EDI}
END = {"ret", "retf", "int3", "ud2", "hlt", "iretd"}
FRAME_HELPERS = ("SEH_prolog", "EH_prolog")
ALLOCA = ("alloca_probe", "chkstk")

_b: Binary | None = None
_names: dict[int, str] = {}
_cleanup: dict[int, int] = {}
_noreturn: set[int] = set()


def _init(names, cleanup, noreturn):
    global _b, _names, _cleanup, _noreturn
    _b = Binary()
    _names, _cleanup, _noreturn = names, cleanup, noreturn


def decode(b: Binary, root: int, ranges, md):
    """{address: capstone insn} over a function's ranges."""
    out = {}
    for lo, hi in ranges:
        o = b.off(lo)
        for ins in md.disasm(bytes(b.image[o:o + (hi - lo)]), lo):
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
        zero_idiom = (mn in ("xor", "sub", "sbb") and same) or constant
        # (and the ones that do nothing: the CRT's hot-patch `mov edi, edi`, alignment filler
        # `lea ebx, [ebx]`. Read as reads, sprintf_s took edi, and so did its 7,953 callers)
        nop = (mn == "mov" and same) or (mn == "lea" and len(ops) == 2 and ops[1].type == X.X86_OP_MEM
                                         and ops[1].mem.base == ops[0].reg and not ops[1].mem.index
                                         and not ops[1].mem.disp)
        # (`push reg` saves a callee-saved register, or is how MSVC reserves a 4-byte local
        # (`push ecx`): a read of nothing anyone passed. A `this` saved that way is read again
        # from the slot, not from ecx, so it shows elsewhere)
        reserve = mn == "push" and ops and ops[0].type == X.X86_OP_REG and ops[0].reg in FULL
        if not zero_idiom and not reserve and not nop:
            for r in reads:
                bit = REG_BITS.get(r)
                if bit and not mask & bit:
                    inputs |= bit
        # stack parameter reads (and lea of their address)
        for op in ops:
            if op.type != X.X86_OP_MEM:
                continue
            base = op.mem.base
            at = esp if base == X.X86_REG_ESP else ebp if base == X.X86_REG_EBP else None
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
        for r in writes:
            if r in REG_BITS:
                mask |= REG_BITS[r]
        # esp / ebp
        if mn == "push":
            esp = None if esp is None else esp - (op_size(ops[0]) if ops else 4)
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
                if mn == "add":
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
                # the helper builds the frame: ebp at entry - 4, esp below the locals
                ebp, esp = -4, None
            elif t is not None and any(h in name for h in ALLOCA):
                prev = insns.get(prv[a]) if prv[a] is not None else None
                if esp is not None and prev is not None and prev.mnemonic == "mov" and prev.operands \
                        and prev.operands[0].type == X.X86_OP_REG and prev.operands[0].reg == X.X86_REG_EAX \
                        and prev.operands[1].type == X.X86_OP_IMM:
                    esp -= prev.operands[1].imm
                else:
                    esp = None
            elif esp is not None:
                clean = _cleanup.get(t) if t is not None else None
                if clean is None:
                    # unknown: the callee popped what was pushed for it, unless the caller now
                    # cleans up itself
                    after = insns.get(fall) if fall else None
                    cdecl = after is not None and after.mnemonic == "add" and after.operands \
                        and after.operands[0].type == X.X86_OP_REG and after.operands[0].reg == X.X86_REG_ESP
                    clean = 0 if cdecl else pushed
                esp += clean
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
    return {"inputs": inputs, "stack_hi": stack_hi, "addr_taken": addr_taken, "calls": calls,
            "open": open_, "lost": lost, "ret": ret_bytes(insns), "visited": len(state), "insns": len(insns)}


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
    args = ap.parse_args()
    t0 = time.time()

    funcs = json.loads((FACTS / "functions.json").read_text())["functions"]
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
            if mn == "ret":
                ns.append(int(ops, 16) if ops else 0)
            elif mn == "jmp" and ops.startswith("0x") and int(ops, 16) not in insns \
                    and b.is_func_start(int(ops, 16)):
                tail_of[root] = int(ops, 16)
        if ns:
            cleanup[root] = max(ns)
    for _ in range(8):
        for f, t in tail_of.items():
            if f not in cleanup and t in cleanup:
                cleanup[f] = cleanup[t]

    if args.show:
        _init(names, cleanup, noreturn)
        for s in args.show:
            a = int(s, 16)
            print(hexa(a), names.get(a), "cleanup", cleanup.get(a), analyse(a, ranges[a]))
        return

    # 2. local pass, in parallel
    with Pool(args.jobs, initializer=_init, initargs=(names, cleanup, noreturn)) as pool:
        local = dict(pool.imap_unordered(_job, list(ranges.items()), chunksize=64))
    errors = sum(1 for v in local.values() if "error" in v)

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
        elif ret_n:
            cc = "__stdcall"
        else:
            cc = "__cdecl"
        callee_cleans = bool(ret_n) or cc in ("__fastcall", "__thiscall")
        stack = ret_n if callee_cleans and ret_n is not None else max(0, v["stack_hi"] - 4)
        stack = (stack + 3) & ~3
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
        if callee_cleans and ret_n is not None and v["stack_hi"] - 4 > ret_n:
            e["reads_beyond"] = v["stack_hi"] - 4   # reads past its own cleanup: a check for later
        if ret_n is None:
            e["no_ret"] = True
        out[hexa(f)] = e
        counts[cc] = counts.get(cc, 0) + 1

    path = write_facts("protos", {
        "rule": "x86 (protos32.py): ret N -> callee-cleanup stack bytes; ecx/edx read before "
                "written on some path (must-define, closed over direct calls and tail jumps) -> "
                "__thiscall / __fastcall; __cdecl stack parameters to the highest [entry esp + 4..] "
                "slot read through esp or ebp",
        "arch": "x86",
        "functions": out})
    lost = sum(1 for v in local.values() if v.get("lost"))
    print(f"{len(out)} functions ({errors} not analysed): {counts}; esp lost in {lost}; "
          f"{sum(1 for e in out.values() if e.get('open'))} open, "
          f"{sum(1 for e in out.values() if e.get('reads_beyond'))} read past their ret N -> {path} "
          f"({time.time() - t0:.0f}s)")


if __name__ == "__main__":
    main()
