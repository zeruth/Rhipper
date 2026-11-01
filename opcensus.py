"""Operation census for fidelity32.py: what each function does to its values, reference x86 against
the port's x64, which the calls/fields/consts presence comparisons cannot see (a bit move the C
converted by value keeps every call, field and constant; 2026-10-31, UpdateSimulation 0xbbc320's
0x3f800000 substeps, F_00bce490's byte-truncated arena size).

Strong flags (fidelity32 scores them): KIND, a kind of conversion the port makes that the
reference never does (i2f:int, i2f:u64, i2f:fbits, f2i:int), and NARROWED, a callee's result the
port reads as a byte or word where the reference reads all of eax. Weak (reported only): the
conversion counts differ, which the compilers' duplicated and merged blocks move too.

Census per function (each side's own pieces / its F_ procedure):
  i2f  integer -> floating point by value   ref: fild*, cvtsi2s*, cvtdq2p*, cvtpi2p*, calls of
                                             the CRT's __ltod3/__ultod3/...; port: cvtsi2s*, cvtdq2p*
  f2i  floating point -> integer by value   ref: fist/fistp/fisttp, cvt(t)s*2si, cvt(t)p*2dq/pi,
                                             calls of _ftol/__ftol2(_sse)/__dtoui3/...; port: cvt(t)s*2si,
                                             cvt(t)p*2dq
  (cvtss2sd/cvtsd2ss/cvtps2pd/cvtpd2ps are float<->double: float10 is double in the port, x87 code
  is SSE there, so they are not counted. The port's gen_bits2f/gen_fl2bits are movd: no conversion.)
  The x64 compiler's unsigned 64-bit idioms (two cvtsi2s* around `shr r, 1`; the 2^63 split of
  cvtt*2si) count once.
  ret  each call's result, how the caller first consumes it: 8 / 16 bits (al, ax: test al, movzx,
       a byte store) or 32 (eax whole: arithmetic, an address, a dword store), by callee
       (F_x = x, an import by name, every indirect call one pool)."""
from __future__ import annotations

import re
from collections import Counter

import capstone

# (x87's integer-operand arithmetic converts its memory operand too: `fidivr dword ptr [ebp - 0xc4]`
# is the C's `x / (float10)n`)
I2F = re.compile(r"^v?(?:cvtsi2s[sd]|cvtdq2p[sd]|cvtpi2p[sd]|cvtusi2s[sd])$|^fild$|^fi(?:add|sub|subr|mul|div|divr|comp?)$")
F2I = re.compile(r"^v?(?:cvtt?s[sd]2si|cvtt?p[sd]2dq|cvtt?p[sd]2pi|cvtt?s[sd]2usi)$|^fistp?$|^fisttp$")
# the C runtime's conversion helpers the reference calls (by its corpus name)
REF_F2I_CALL = re.compile(r"(?:^|::)(?:rh_)?_*(?:ftol\d*(?:_sse|_sse_excpt|_pentium4)?|dtol\d*|ftoui\d*|dtoui\d*|ftoul\d*|dtoul\d*|"
                          r"ftoi\d*|dtoi\d*|ftoll\d*|dtoll\d*|ftoull\d*|dtoull\d*)$")
REF_I2F_CALL = re.compile(r"(?:^|::)(?:rh_)?_*(?:ltod\d*|ultod\d*|ltof\d*|ultof\d*|uitod\d*|uitof\d*|itod\d*|itof\d*|lltod\d*|ulltod\d*)$")
PORT_F2I_CALL = re.compile(r"^_*(?:dtoul3|dtoui3|ftoul3|ftoui3|dtol3|ftol3|l?l?rintf?|l?l?roundf?)$")
PORT_I2F_CALL = re.compile(r"^_*(?:ultod3|ltod3|ultof3|ltof3)$")

# registers by family: name -> (family, bits)
REGS = {}
for fam, names in {"a": ("al", "ah", "ax", "eax", "rax"), "b": ("bl", "bh", "bx", "ebx", "rbx"),
                   "c": ("cl", "ch", "cx", "ecx", "rcx"), "d": ("dl", "dh", "dx", "edx", "rdx"),
                   "si": ("sil", None, "si", "esi", "rsi"), "di": ("dil", None, "di", "edi", "rdi"),
                   "bp": ("bpl", None, "bp", "ebp", "rbp"), "sp": ("spl", None, "sp", "esp", "rsp")}.items():
    for n, w in zip(names, (8, 8, 16, 32, 64)):
        if n:
            REGS[n] = (fam, w)
for k in range(8, 16):
    for suf, w in (("b", 8), ("w", 16), ("d", 32), ("", 64)):
        REGS[f"r{k}{suf}"] = (f"r{k}", w)
REG_TOKEN = re.compile(r"\b(" + "|".join(sorted(REGS, key=len, reverse=True)) + r")\b")
X86_CALLER_SAVED = {"a", "c", "d"}
X64_CALLER_SAVED = {"a", "c", "d", "r8", "r9", "r10", "r11"}
X64_ARGS = {"c", "d", "r8", "r9"}
PURE_WRITE = {"mov", "movzx", "movsx", "movsxd", "lea", "pop", "setb", "seta", "sete", "setne", "setl", "setg",
              "setle", "setge", "setbe", "setae", "sets", "setns", "setp", "setnp", "seto", "setno"}


def split_ops(op_str: str) -> list[str]:
    return [o.strip() for o in op_str.split(",")] if op_str else []


def regs_in(op: str):
    return [REGS[m] for m in REG_TOKEN.findall(op)]


def int_source(insns: list, k: int) -> str | None:
    """the integer an x64 int->float conversion reads: its general register or memory operand, or
    for a packed one from an xmm the register a `movd xmm, r` just put there"""
    ops = split_ops(insns[k][2])
    if len(ops) != 2:
        return None
    src = ops[1]
    if "xmm" in src and "[" not in src:
        for j in range(k - 1, max(-1, k - 4), -1):
            o = split_ops(insns[j][2])
            if insns[j][1] == "movd" and len(o) == 2 and o[0] == src:
                src = o[1]
                break
        else:
            return None
    r = regs_in(src)
    return f"{r[0][0]}" if r and "[" not in src else src


FLOAT_OP = re.compile(r"^v?(?:cvt(?:sd2ss|ss2sd|pd2ps|ps2pd|si2ss|si2sd|dq2ps|dq2pd)|(?:add|sub|mul|div|sqrt|min|max)s[sd]|"
                      r"(?:add|sub|mul|div|sqrt|min|max)p[sd]|movss|movsd|rcpss|rsqrtss)$")


def float_made(insns: list, k: int, xmm: str) -> bool:
    """the last write of xmm before insns[k] is a floating-point operation (not an integer moved in)"""
    for j in range(k - 1, max(-1, k - 24), -1):
        mn, ops = insns[j][1], split_ops(insns[j][2])
        if ops and ops[0] == xmm:
            if mn in ("movd", "movq") and len(ops) == 2 and "xmm" not in ops[1]:
                return False
            if mn in ("movss", "movsd") and len(ops) == 2 and "[" in ops[1]:
                return True                            # a float loaded from memory
            return bool(FLOAT_OP.match(mn))
        if mn == "call":
            return xmm == "xmm0"                       # a float result
    return False


def i2f_kind(insns: list, k: int, x64: bool) -> str:
    """what an int->float conversion converts: 'u64' (an unsigned 64-bit integer, by the compiler's
    idiom for it), 'fbits' (a float's own bits, back from an xmm register or a slot a float was
    stored to: a bit move the C converted by value), or 'int'"""
    mn, ops = insns[k][1], split_ops(insns[k][2])
    near = insns[max(0, k - 6):k]
    if x64:
        if len(ops) == 2 and "[" not in ops[1] and regs_in(ops[1]) and regs_in(ops[1])[0][1] == 64 \
                and any(x[1] == "js" for x in insns[max(0, k - 3):k]):
            return "u64"
        src = ops[1] if len(ops) == 2 else ""
        if "xmm" in src and "[" not in src:              # cvtdq2p*: the movd that filled it
            for j in range(k - 1, max(-1, k - 4), -1):
                o = split_ops(insns[j][2])
                if insns[j][1] == "movd" and len(o) == 2 and o[0] == src:
                    src, k = o[1], j
                    break
            else:
                return "int"
        # trace a register back through copies to what made it
        for _ in range(4):
            if "[" in src:
                for j in range(k - 1, max(-1, k - 12), -1):
                    o = split_ops(insns[j][2])
                    if o and "[" in o[0] and o[0][o[0].index("["):] == src[src.index("["):]:
                        return "fbits" if insns[j][1] in ("movss", "movd", "movsd", "movq") and "xmm" in insns[j][2] \
                            else "int"
                return "int"
            r = regs_in(src)
            if not r:
                return "int"
            fam = r[0][0]
            for j in range(k - 1, max(-1, k - 8), -1):
                o = split_ops(insns[j][2])
                if o and "[" not in o[0] and regs_in(o[0]) and regs_in(o[0])[0][0] == fam:
                    m2 = insns[j][1]
                    if m2 in ("movd", "movq") and len(o) == 2 and "xmm" in o[1]:
                        # (a float's bits only where a float operation made that xmm: the x64
                        # compiler keeps integers in xmm registers too, `movd xmm8, eax` a spill)
                        return "fbits" if float_made(insns, j, o[1]) else "int"
                    if m2 == "mov" and len(o) == 2:
                        src, k = o[1], j
                        break
                    return "int"
            else:
                return "int"
        return "int"
    # x86
    if mn == "fild" and ops and ops[0].startswith("qword ptr"):
        if any(x[1] == "and" and x[2].endswith(", 0x7fffffff") for x in near):
            return "u64"
        after = [x[1] for x in insns[k + 1:k + 5]]
        if ("jge" in after or "jns" in after) and "fadd" in after:
            return "u64"
    if ops and "[" in ops[0]:
        m = ops[0][ops[0].index("["):]
        for j in range(k - 1, max(-1, k - 12), -1):
            o = split_ops(insns[j][2])
            if o and o[0].endswith(m):
                return "fbits" if insns[j][1] in ("fstp", "fst", "movss", "movd") else "int"
    return "int"


def writes_between(insns: list, lo: int, hi: int, src: str) -> bool:
    """an instruction in (lo, hi) that writes the register family or memory operand src"""
    for j in range(lo + 1, hi):
        o = split_ops(insns[j][2])
        if not o or insns[j][1] in ("cmp", "test", "push") or insns[j][1].startswith(("j", "comis", "ucomis")):
            continue
        d = o[0]
        if "[" in src:
            if d == src:
                return True
        elif "[" not in d and regs_in(d) and regs_in(d)[0][0] == src:
            return True
        if insns[j][1] == "call":
            return True
    return False


def result_use(insns: list, at: int, x64: bool) -> tuple[str, int | None]:
    """How the result of the call at insns[at] is first consumed: '8', '16', '32', 'arg', 'ret',
    'none' (overwritten or lost first), and the consuming instruction's address."""
    tracked = {"a"}
    for k in range(at + 1, min(len(insns), at + 24)):
        addr, mn, op_str = insns[k]
        ops = split_ops(op_str)
        if mn in ("ret", "retn"):
            return ("ret", addr) if "a" in tracked else ("none", addr)
        if mn == "call":
            if x64 and tracked & X64_ARGS:
                return "arg", addr
            if not x64 and "c" in tracked:
                return "arg", addr
            tracked -= (X64_CALLER_SAVED if x64 else X86_CALLER_SAVED)
            if not tracked:
                return "none", addr
            continue
        if mn == "jmp":
            return "none", addr
        if mn.startswith("j") or mn.startswith("nop") or mn == "int3":
            continue
        if not ops:
            continue
        dst = ops[0]
        dst_mem = "[" in dst
        dst_regs = regs_in(dst)
        src_ops = ops[1:]
        # reads of tracked families: in any memory operand (an address) full; a register operand by
        # its width; the destination register is read too unless the instruction only writes it
        reads = []
        for i, op in enumerate(ops):
            if "[" in op:
                for fam, w in regs_in(op):
                    if fam in tracked:
                        reads.append(("addr", 32))
            elif i > 0 or (mn not in PURE_WRITE and not (mn in ("xor", "sub", "sbb", "pxor", "xorps") and len(ops) == 2
                                                            and ops[0] == ops[1])):
                for fam, w in regs_in(op):
                    if fam in tracked:
                        reads.append(("reg", min(w, 32)))
        if mn == "push":
            if reads:
                return "arg", addr
            continue
        if mn in ("mov", "movsxd") and not dst_mem and dst_regs and src_ops and "[" not in src_ops[0] \
                and regs_in(src_ops[0]) and regs_in(src_ops[0])[0][0] in tracked:
            sw = regs_in(src_ops[0])[0][1]
            if sw >= 32:
                tracked.add(dst_regs[0][0])               # a copy: the value lives on there too
                continue
            return str(sw), addr
        if mn == "xchg" and reads:
            return "32", addr
        if reads:
            if mn == "and" and len(ops) == 2 and ops[1] in ("0xff", "0xffff") and reads[0][0] == "reg":
                return ("8" if ops[1] == "0xff" else "16"), addr
            w = max(w for _, w in reads)
            return str(w if w in (8, 16) else 32), addr
        # a write of a tracked register without reading it: that copy is gone
        if dst_regs and not dst_mem:
            fam, w = dst_regs[0]
            if fam in tracked and (w >= 32 or mn in PURE_WRITE):
                tracked.discard(fam)
                if not tracked:
                    return "none", addr
    return "none", None


class Census:
    """fidelity32's: the reference and port Images, the reference's Binary (pieces, func_containing),
    the corpus (names, C: the call fixups by their warnings), the port's procs and publics by address,
    and each translated function's port procedure (f_of_ref, proc_at)."""

    def __init__(self, ref, port, refbin, cor: dict, proc_at: dict, f_of_ref: dict):
        self.ref, self.port, self.b = ref, port, refbin
        self.ref_iat = ref.iat
        # (an address's names: the procs', and the import adapters' publics fidelity32 folded in)
        self.at = {va: [name] for va, (_size, name) in proc_at.items()}
        self.proc_at, self.f_of_ref = proc_at, f_of_ref
        self.md32 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.md64 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.pieces: dict[int, list] = {}
        for lo, hi, r in zip(refbin.piece_starts, refbin.piece_ends, refbin.piece_root):
            self.pieces.setdefault(r, []).append((lo, hi))
        self.names = {a: e.get("name", "") for a, e in cor.items()}
        # (the call fixups' names by the function they replace: `Function: FUN_00c49790 replaced with
        # injection: rh_ftol2_sse`, the unnamed __ftol2_sse; an x87 leaf's, rh_x87leaf_<addr>)
        by_name = {n: a for a, n in self.names.items()}
        self.inject = {}
        for e in cor.values():
            for n, inj in re.findall(r"Function: (\S+) replaced with injection: (\w+)", e.get("c", "")):
                t = by_name.get(n) or by_name.get(n[len("thunk_"):] if n.startswith("thunk_") else n)
                if t is None and re.fullmatch(r"FUN_[0-9a-f]{8}", n):
                    t = int(n[4:], 16)
                if t is not None:
                    self.inject[t] = inj

    # ---- the two sides' instructions
    def ref_insns(self, a: int, ranges: list | None = None) -> list:
        out = []
        for lo, hi in sorted(ranges if ranges is not None else self.pieces.get(a, [])):
            out.extend(self.md32.disasm_lite(self.ref.read(lo, hi - lo), lo))
        return [(x[0], x[2], x[3]) for x in out]

    def port_insns(self, a: int) -> list | None:
        va = self.f_of_ref.get(a)
        if va is None:
            return None
        size = self.proc_at[va][0]
        return [(x[0], x[2], x[3]) for x in self.md64.disasm_lite(self.port.read(va, size), va)]

    def ref_root(self, t: int) -> int:
        """a reference call target through its `jmp rel32` thunks, as its function"""
        b = self.b
        for _ in range(4):
            code = self.ref.read(t, 6) if self.ref.contains(t) else b""
            if len(code) >= 5 and code[0] == 0xE9:
                t = (t + 5 + int.from_bytes(code[1:5], "little", signed=True)) & 0xFFFFFFFF
                continue
            if code[:2] == b"\xff\x25":
                slot = int.from_bytes(code[2:6], "little")
                if slot in self.ref_iat:
                    return "imp:" + self.ref_iat[slot]
            break
        r = b.func_containing(t)
        return r if r is not None else t

    def callee(self, mn, op_str, x64, addr, size=None):
        ops = op_str
        if re.fullmatch(r"0x[0-9a-f]+", ops):
            t = int(ops, 16)
            if x64:
                ns = self.at.get(t, [])
                for n in ns:
                    m = re.fullmatch(r"F_([0-9a-f]{8})", n)
                    if m:
                        return int(m.group(1), 16)
                for n in ns:
                    if n.startswith("gen_imp_"):
                        return "imp:" + n[len("gen_imp_"):].lstrip("_")
                return "rt:" + (ns[0] if ns else f"{t:x}")
            return self.ref_root(t)
        m = re.fullmatch(r"dword ptr \[(0x[0-9a-f]+)\]", ops)
        if m and not x64:
            slot = int(m.group(1), 16)
            return "imp:" + self.ref_iat.get(slot, f"{slot:x}")
        if x64 and "rip" in ops:
            return "pimp"                                   # the port's own import (its CRT, kernel32)
        return "ind"

    def side(self, insns: list, x64: bool, depth: int = 0) -> dict:
        i2f = f2i = bits = 0
        rets: dict = {}
        sites = []
        inlined: set = set()
        for k, (addr, mn, ops) in enumerate(insns):
            # (the port is SSE: an x87 mnemonic there is data its procedure's range takes in, a
            # jump table or padding disassembled as code)
            if x64 and mn.startswith("f"):
                continue
            if I2F.match(mn):
                # (the x64 compiler's unsigned 64-bit to float: the second cvtsi2s* after `shr r, 1`)
                if x64 and any(insns[j][1] == "shr" and insns[j][2].endswith(", 1") for j in range(max(0, k - 5), k)):
                    continue
                # (and the x86 one's: the top bit loaded alone, `and eax, 0x80000000; ...; fild qword`,
                # the low 63 bits' fild before it)
                if not x64 and any(insns[j][1] == "and" and insns[j][2].endswith(", 0x80000000")
                                   for j in range(max(0, k - 4), k)):
                    continue
                # (one integer converted twice by the x64 code, to float and to double: `movd xmm0, ecx;
                # cvtdq2ps xmm0, xmm0; movd xmm1, ecx; cvtdq2pd xmm1, xmm1`, the C's (float)n and
                # (float10)n, one conversion of the reference's x87)
                if x64:
                    src = int_source(insns, k)
                    if src and any(int_source(insns, j) == src and I2F.match(insns[j][1])
                                   and not writes_between(insns, j, k, src) for j in range(max(0, k - 8), k)):
                        continue
                i2f += 1
                kind = i2f_kind(insns, k, x64)
                sites.append(("i2f", addr, f"{mn} {kind}"))
                # (the converted value's bits taken straight back as an integer: `cvtsi2ss xmm1, ..;
                # movd eax, xmm1`, gen_fl2bits((float)n), a bit move the C converted by value)
                dst = split_ops(ops)[0] if ops else ""
                for j in range(k + 1, min(len(insns), k + 5)):
                    o2 = split_ops(insns[j][2])
                    if x64 and insns[j][1] in ("movd", "movq") and len(o2) == 2 and o2[1] == dst and "xmm" not in o2[0]:
                        bits += 1
                        break
                    if dst and dst in insns[j][2]:
                        break
                if not x64 and mn == "fild":
                    # (x87: fild then `fstp dword [m]` and an integer load of [m])
                    for j in range(k + 1, min(len(insns), k + 4)):
                        if insns[j][1] == "fstp" and insns[j][2].startswith("dword ptr"):
                            m = insns[j][2][len("dword ptr "):]
                            if any(insns[q][1] == "mov" and insns[q][2].endswith("dword ptr " + m)
                                   for q in range(j + 1, min(len(insns), j + 5))):
                                bits += 1
                            break
                        if insns[j][1].startswith("f"):
                            break
            elif F2I.match(mn):
                # (and its 2^63 split of float to unsigned 64-bit: the cvtt*2si a `btc r, 0x3f` follows,
                # or after a subtraction of 2^63, the other path's twin)
                if x64 and any(insns[j][1] in ("btc", "bts") or (insns[j][1] in ("subss", "subsd")) for j in
                               range(max(0, k - 3), min(len(insns), k + 4))) and \
                        any("cvtt" in insns[j][1] and j != k for j in range(max(0, k - 12), min(len(insns), k + 12))):
                    if any(insns[j][1] in ("subss", "subsd") for j in range(max(0, k - 3), k)):
                        continue
                f2i += 1
                sites.append(("f2i", addr, mn))
            elif mn == "call" or (mn == "jmp" and re.fullmatch(r"0x[0-9a-f]+", ops)):
                c = self.callee(mn, ops, x64, addr)
                name = self.names.get(c, "") if isinstance(c, int) else (c[3:] if c.startswith("rt:") else "")
                if not x64 and isinstance(c, int) and c in self.inject:
                    name = self.inject[c]
                if mn == "jmp":
                    # (a tail jump counts only into a conversion helper: `fadd; jmp __ftol2_sse`)
                    if not x64 and isinstance(c, int) and REF_F2I_CALL.search(name):
                        f2i += 1
                        sites.append(("f2i", addr, name))
                    elif not x64 and isinstance(c, int) and REF_I2F_CALL.search(name):
                        i2f += 1
                        sites.append(("i2f", addr, name))
                    continue
                if not x64 and isinstance(c, int) and c in self.inject:
                    # (an x87 leaf the decompiler injects: its p-code, conversions too, is the caller's)
                    if name.startswith("rh_x87leaf_") and depth < 2:
                        inner = self.side(self.ref_insns(c), False, depth + 1)
                        i2f += inner["i2f"]
                        f2i += inner["f2i"]
                        sites.extend(inner["sites"])
                        continue
                if not x64 and name == "rh_CIfmod":
                    # (the fixup models fmod as `x - (float10)(longlong)(x / y) * y`: a conversion
                    # each way in the port, fprem's in the reference)
                    f2i += 1
                    i2f += 1
                    sites += [("f2i", addr, name), ("i2f", addr, name)]
                    continue
                if not x64 and isinstance(c, int) and REF_F2I_CALL.search(name):
                    f2i += 1
                    sites.append(("f2i", addr, name))
                    continue
                if not x64 and isinstance(c, int) and REF_I2F_CALL.search(name):
                    i2f += 1
                    sites.append(("i2f", addr, name))
                    continue
                if x64 and isinstance(c, str) and c.startswith("rt:") and PORT_F2I_CALL.match(name):
                    f2i += 1
                    sites.append(("f2i", addr, name))
                    continue
                if x64 and c == "rt:gen_trace_enter":
                    # (GEN_ENTER's `mov ecx, <ref address>`: another's is a translation inlined here)
                    for j in range(k - 1, max(-1, k - 8), -1):
                        if insns[j][1] == "mov" and insns[j][2].startswith("ecx, 0x"):
                            inlined.add(int(insns[j][2][5:], 16))
                            break
                    continue
                if x64 and isinstance(c, str) and (c.startswith("rt:") or c == "pimp"):
                    continue                                 # the port's runtime: no reference call
                use, uat = result_use(insns, k, x64)
                rets.setdefault(c, []).append((use, addr, uat))
        return {"i2f": i2f, "f2i": f2i, "bits": bits, "rets": rets, "sites": sites, "inlined": inlined}

    @staticmethod
    def kinds(sites: list) -> Counter:
        """the conversions by (direction, kind): what the strong check compares by presence"""
        out = Counter()
        for d, _, what in sites:
            k = what.split()[-1]
            if k not in ("int", "u64", "fbits"):
                k = "u64" if re.search(r"ul|ull", what) else "int"
            out[(d, k)] += 1
        return out

    def run(self, a: int, ranges: list | None = None, inlined=()) -> dict | None:
        """a's census, both sides, and its flags: KIND/NARROWED strong, i2f/f2i counts weak.
        `ranges`: the reference's pieces (fidelity32's own_pieces); `inlined`: reference addresses of
        translations the PDB says the port inlined here (besides GEN_ENTER's markers)"""
        pi = self.port_insns(a)
        if pi is None:
            return None
        ri = self.ref_insns(a, ranges)
        r, p = self.side(ri, False), self.side(pi, True)
        p["inlined"] |= set(inlined)
        # (a translation the port's compiler inlined: its reference body's census is the caller's)
        for y in sorted(p["inlined"] - {a}):
            if y in self.pieces:
                inner = self.side(self.ref_insns(y), False, 1)
                r["i2f"] += inner["i2f"]
                r["f2i"] += inner["f2i"]
                r["bits"] += inner["bits"]
                r["sites"].extend(inner["sites"])
                for c, us in inner["rets"].items():
                    r["rets"].setdefault(c, []).extend(us)
        flags = []
        rk, pk = self.kinds(r["sites"]), self.kinds(p["sites"])
        # strong: a kind of conversion the port makes and the reference never does
        for key in sorted(pk):
            if not rk.get(key):
                flags.append(f"KIND {key[0]}:{key[1]} ref 0 port {pk[key]}")
        # weak: the counts differ (a compiler's duplicated or merged blocks move them too)
        if p["i2f"] != r["i2f"]:
            flags.append(f"i2f ref {r['i2f']} port {p['i2f']}")
        if p["f2i"] != r["f2i"]:
            flags.append(f"f2i ref {r['f2i']} port {p['f2i']}")
        narrowed = []
        for c, uses in p["rets"].items():
            ru = Counter(u for u, _, _ in r["rets"].get(c, []))
            pu = Counter(u for u, _, _ in uses)
            n = min(pu["8"] + pu["16"] - ru["8"] - ru["16"], ru["32"] - pu["32"])
            if n > 0:
                key = f"{c:08x}" if isinstance(c, int) else c
                narrowed.append({"callee": key, "n": n, "ref": dict(ru), "port": dict(pu),
                                 "port_sites": [f"{x:#x}->{y:#x}" if y else f"{x:#x}" for u, x, y in uses if u in ("8", "16")],
                                 "ref_sites": [f"{x:#x}->{y:#x}" if y else f"{x:#x}" for u, x, y in r["rets"].get(c, []) if u == "32"]})
        if narrowed:
            flags.append("NARROWED " + ", ".join(f"{d['callee']}x{d['n']}" for d in narrowed))
        return {"addr": f"{a:08x}", "name": self.names.get(a, ""),
                "ref": {"i2f": r["i2f"], "f2i": r["f2i"], "bits": r["bits"]},
                "port": {"i2f": p["i2f"], "f2i": p["f2i"], "bits": p["bits"]}, "flags": flags, "narrowed": narrowed,
                "ref_sites": [f"{k} {x:#x} {m}" for k, x, m in r["sites"]],
                "port_sites": [f"{k} {x:#x} {m}" for k, x, m in p["sites"]],
                "ret_hist": {"ref": dict(Counter(u for us in r["rets"].values() for u, _, _ in us)),
                             "port": dict(Counter(u for us in p["rets"].values() for u, _, _ in us))}}


