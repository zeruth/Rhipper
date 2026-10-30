"""Fidelity of a 32-bit project's translation (translate32.py), binary against binary.

Each reference function is compared with its translation, F_<address> in the port's PDB (the x64
port, rhipper.json "run" "exe" and the .pdb beside it), on fidelity.py's signals:

  calls   the functions called directly, by presence (the order is each compiler's block layout,
          and one compiler merges two calls another keeps). A port callee F_x is reference function x, a
          gen_imp_<name> adapter the reference's import <name> (`call [slot]` or its `jmp [slot]`
          thunk there): imp:<name>, the C underscore aside. The runtime's own helpers
          (gen_trace_enter, GenUnimplemented, gen_teb32, ...) are left out, and a translated
          function the port's compiler inlined is put back where the PDB says it was.
  fields  the displacements read and written through a pointer ([reg+0x1c]), the stack and
          indexed operands aside.
  consts  strings, float constants and integer immediates; and the reference's globals, g:<addr>,
          which both sides name by the same address (x86: an absolute operand or immediate in the
          image; the port: REFG/REFP, an immediate or displacement in the reference's image).
  shape   mnemonic trigrams: x86 against x64, so reported only.

Fields and constants count by presence too (how often is the compilers' choice), a comparison's
constant matches its neighbour (`cmp 1000` / `cmp 1001`), and a global matches one up to 16 bytes
below it (neighbours stored as one vector). The port is best measured built without inlining or
identical-code folding (/Ob0, /OPT:NOICF), each translation its own function.

A stubbed function scores 0 and is listed with its reason (gen/manifest.json).

    python fidelity32.py                  the totals, then the 25 lowest
    python fidelity32.py --all            every function, lowest first
    python fidelity32.py --show 0x401440  one function in full: its calls side by side, what the
                                          port misses and adds
    python fidelity32.py --html           also build/fidelity.html

Writes build/fidelity.json.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

import capstone
import pefile
from capstone import x86

import fidelity as F
import project
from corpus import load_corpus
from pebin import Binary
from project import ROOT

OUT_JSON = ROOT / "build/fidelity.json"
OUT_HTML = ROOT / "build/fidelity.html"
JCC = re.compile(r"^j(?!mp)\w+$")
STACK_REGS = {"esp", "ebp", "rsp", "rbp"}
STACK_PTRS = {"rsp", "rbp"}                  # (STACK_REGS by canon_reg's names)
# Ghidra32.h's traps, the reference's `int 3` / `int 0x29`
TRAPS = {"gen_swi_break": "trap:3", "gen_swi_fastfail": "trap:29", "gen_ud2": "trap:ud2"}
# the port's own setjmp and longjmp (Ghidra32.h GEN_SETJMP, GEN_LONGJMP), the reference's imports
# (by name less its leading underscores, as Image.iat has them)
PORT_JUMPS = {"setjmp": "imp:setjmp3", "setjmpex": "imp:setjmp3", "intrinsic_setjmp": "imp:setjmp3",
              "intrinsic_setjmpex": "imp:setjmp3", "longjmp": "imp:longjmp"}
FLOAT_MNEMONIC = re.compile(r"(ss|sd|ps|pd)$|^f(?!(?:nstcw|ldcw|nstsw|stsw|xch|wait|nclex))")


class Image:
    """A PE mapped at its own base: the bytes and sections fidelity reads."""

    def __init__(self, path: Path):
        pe = pefile.PE(str(path), fast_load=True)
        self.base = pe.OPTIONAL_HEADER.ImageBase
        # (the whole image: the mapped bytes stop at the last section's raw data, and a global in
        # .data's zero-filled tail read as an integer, not an address of the image)
        self.image = bytearray(pe.get_memory_mapped_image()).ljust(pe.OPTIONAL_HEADER.SizeOfImage, b"\0")
        self.sections = []
        for s in pe.sections:
            self.sections.append(type("S", (), {"start": self.base + s.VirtualAddress,
                                                "end": self.base + s.VirtualAddress + s.Misc_VirtualSize,
                                                "exec": bool(s.Characteristics & 0x20000000)})())
        self.iat = {}
        self.ordinal_slots: set[int] = set()     # (imports by ordinal: named from Ghidra's labels)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        for dll in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            for imp in dll.imports:
                if imp.name:
                    self.iat[imp.address] = imp.name.decode().lstrip("_")
                else:
                    self.ordinal_slots.add(imp.address)
        pe.close()

    def contains(self, va: int) -> bool:
        return self.base <= va < self.base + len(self.image)

    def is_code(self, va: int) -> bool:
        return any(s.exec and s.start <= va < s.end for s in self.sections)

    def cstr(self, va: int, limit: int = 256) -> str | None:
        if not self.contains(va):
            return None
        o = va - self.base
        end = self.image.find(b"\0", o, o + limit)
        if end < 0:
            return None
        try:
            s = bytes(self.image[o:end]).decode("ascii")
        except UnicodeDecodeError:
            return None
        # (a line's end and a tab are text too: `"printf: %d %s %.2f\n"`, a format, rhtest crt)
        return s if len(s) >= 3 and s.replace("\n", "").replace("\r", "").replace("\t", "").isprintable() else None

    def wstr(self, va: int, limit: int = 256) -> str | None:
        """a UTF-16 string at va, as cstr a narrow one: a wide literal the reference indexes,
        `movzx edx, word ptr [ecx*2 + 0x404170]`, the port's own copy of `L"rhtest_seek.bin"`"""
        if not self.contains(va) or (va - self.base) % 2:
            return None
        o = va - self.base
        raw = bytes(self.image[o:o + 2 * limit])
        end = next((k for k in range(0, len(raw) - 1, 2) if raw[k] == 0 and raw[k + 1] == 0), -1)
        if end < 6:
            return None
        try:
            s = raw[:end].decode("utf-16-le")
        except UnicodeDecodeError:
            return None
        return s if s.replace("\n", "").replace("\r", "").replace("\t", "").isprintable() and s.isascii() else None

    def read(self, va: int, n: int) -> bytes:
        return bytes(self.image[va - self.base:va - self.base + n])


# SIMD instructions whose immediate selects lanes, a rounding mode or a predicate
SIMD_CONTROL = re.compile(r"v?(?:p?shuf|pshuf[lh]?w|palignr|p?blend|insertps|extractps|pinsr|pextr|round|cmp\w*p[sd]$|"
                          r"cmp\w*s[sd]$|dpp|mpsadbw|pclmul|vperm|perm)")


def canon_reg(name: str) -> str:
    """A general register by its full name, whatever width an instruction names it at."""
    m = re.fullmatch(r"(r\d+)[dwb]?", name)
    if m:
        return m.group(1)
    return {"eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx", "esi": "rsi", "edi": "rdi",
            "ebp": "rbp", "esp": "rsp"}.get(name, name)


def norm_mnemonic(mn: str) -> str:
    return "jcc" if JCC.match(mn) else ("cmov" if mn.startswith("cmov") else mn)


class Fn:
    """What one function's instructions use, comparable across x86 and x64."""

    def __init__(self):
        self.calls: list = []        # (site, target address or "imp:name")
        self.fields = Counter()
        self.consts = Counter()
        self.mnemonics: list[str] = []
        self.float_at: dict[int, str] = {}   # a float constant's reference address -> its f: key
        self.packed: set[int] = set()        # 16-byte float constants read whole
        self.str_at: dict[str, set] = {}     # a string's s: key -> the reference addresses it is at
        self.imms: set[int] = set()          # every immediate above 0x10000, whatever it was taken for
        self.negdisp: set[int] = set()       # -d of each negative displacement from a register not the stack's
        self.steps: set[str] = set()         # the i: keys of `add/sub r, imm`, a register stepped
        self.member_at: dict[int, set] = {}  # a field -> its offset plus the lea's that made its base


def dead_stack_stores(insns: list) -> set[int]:
    """The addresses of constant stores to an esp slot that nothing reads: overwritten before any
    read, or the function's ret reached first with only register work and pops between (a pop into
    eax or edx reads it, a result). The compiler's own dead stores of a local it then kept in a
    register: `unsigned long lo = 99; _BitScanForward(&lo, a)` stores 99 twice to a slot bsf never
    reads, `bsf esi, eax` (rhtest misc scans). Conservative: any jump, call, memory operand on esp
    or ebp, or esp written otherwise, and the store counts"""
    out = set()
    for at, insn in enumerate(insns):
        ops = insn.operands
        if not (insn.mnemonic == "mov" and len(ops) == 2 and ops[0].type == x86.X86_OP_MEM
                and ops[1].type == x86.X86_OP_IMM and ops[0].mem.base and not ops[0].mem.index
                and insn.reg_name(ops[0].mem.base) in ("esp", "ebp")):
            continue
        # (an esp slot moves with the pushes and pops after it, an ebp one, /Od's, stays put)
        base = insn.reg_name(ops[0].mem.base)
        slot = ops[0].mem.disp                  # (relative to the base at the store)
        width = ops[0].size
        delta = 0                               # (esp since the store, as pops and pushes move it)
        dead = False
        for nxt in insns[at + 1:]:
            m, nops = nxt.mnemonic, nxt.operands
            if m == "ret":
                dead = True
                break
            if m.startswith("j") or m in ("call", "loop", "int", "int3"):
                break
            if m in ("pop", "push"):
                if nops and nops[0].type == x86.X86_OP_MEM:
                    break
                if base == "esp":
                    if m == "pop":
                        # (popping the slot itself into a result register reads it)
                        if nops and nops[0].type == x86.X86_OP_REG and nxt.reg_name(nops[0].reg) in ("eax", "edx", "ax", "dx") \
                                and slot + delta == 0:
                            break
                        delta -= 4
                    else:
                        delta += 4
                elif m == "pop" and nops and nops[0].type == x86.X86_OP_REG and nxt.reg_name(nops[0].reg) == "ebp":
                    dead = True                 # (the frame's ebp restored: the slot is gone, unread)
                    break
                continue
            # (an ebp frame torn down, `mov esp, ebp`: its slots past use, as at the ret)
            if base == "ebp" and m == "mov" and len(nops) == 2 and all(o.type == x86.X86_OP_REG for o in nops) \
                    and nxt.reg_name(nops[0].reg) == "esp" and nxt.reg_name(nops[1].reg) == "ebp":
                continue
            if m == "lea" and any(o.type == x86.X86_OP_MEM and o.mem.base and nxt.reg_name(o.mem.base) in ("esp", "ebp")
                                  for o in nops):
                break                           # (a frame address taken: anything may read it)
            touched = False
            for o in nops:
                if o.type != x86.X86_OP_MEM or not o.mem.base or nxt.reg_name(o.mem.base) not in ("esp", "ebp"):
                    continue
                if nxt.reg_name(o.mem.base) != base or o.mem.index:
                    touched = None              # (the other stack register, or indexed: unknown)
                    break
                at_ = o.mem.disp - (delta if base == "esp" else 0)
                if at_ < slot + width and slot < at_ + o.size:
                    # (a store over the whole slot only overwrites it)
                    if m == "mov" and len(nops) == 2 and o is nops[0] and nops[1].type != x86.X86_OP_MEM \
                            and at_ <= slot and slot + width <= at_ + o.size:
                        touched = "dead"
                    else:
                        touched = None
                    break
            if touched == "dead":
                dead = True
                break
            if touched is None:
                break
            if any(o.type == x86.X86_OP_REG and nxt.reg_name(o.reg) in ("esp", "sp", "ebp", "bp") for o in nops):
                break
        if dead:
            out.add(insn.address)
    return out


def dead_compares(insns: list) -> set[int]:
    """The addresses of a span that does nothing: register arithmetic with constants and branches
    that all land where falling through lands, the register then written before any read. A
    switch's leftover, `mov eax, ecx; sub eax, 0x2460; je X; sub eax, 0x10; X: mov esi, edi; call`,
    every way to X the same, which the decompiler drops (4 of a client's functions missed 0x2460)"""
    out = set()
    by_addr = {x.address: k for k, x in enumerate(insns)}
    span_ok = ("mov", "sub", "add", "cmp", "test", "dec", "inc", "and", "or", "xor")
    for at, insn in enumerate(insns):
        # (a span starts after a branch to its end, or at its first instruction: try each start)
        regs = set()
        cut = None
        for k in range(at, len(insns)):
            x = insns[k]
            ops = x.operands
            if JCC.match(x.mnemonic) and ops and ops[0].type == x86.X86_OP_IMM:
                cut = ops[0].imm
                break
            if x.mnemonic not in span_ok or not ops or ops[0].type != x86.X86_OP_REG \
                    or any(o.type == x86.X86_OP_MEM for o in ops):
                break
            r = canon_reg(x.reg_name(ops[0].reg))
            if r in ("rsp", "rbp"):
                break
            regs.add(r)
        if cut is None or not regs or cut not in by_addr:
            continue
        # (every branch in the span to the same end, which it falls into or jumps to, `sub eax, 0x10;
        # jmp X`)
        end = by_addr[cut]
        if end <= at:
            continue
        span = []
        for x in insns[at:end]:
            span.append(x)
            if x.mnemonic == "jmp":
                break
        good = True
        for x in span:
            ops = x.operands
            if x.mnemonic == "jmp":
                good = bool(ops) and ops[0].type == x86.X86_OP_IMM and ops[0].imm == cut
            elif JCC.match(x.mnemonic):
                good = bool(ops) and ops[0].type == x86.X86_OP_IMM and ops[0].imm == cut
            elif x.mnemonic in span_ok and ops and ops[0].type == x86.X86_OP_REG \
                    and not any(o.type == x86.X86_OP_MEM for o in ops) \
                    and canon_reg(x.reg_name(ops[0].reg)) not in ("rsp", "rbp"):
                regs.add(canon_reg(x.reg_name(ops[0].reg)))
            else:
                good = False
            if not good:
                break
        # (and the flags and every register it wrote dead at its end: written before read)
        if not good or not any(not JCC.match(x.mnemonic) and x.mnemonic != "jmp" for x in span):
            continue
        live = set(regs)
        flags_dead = False
        for x in insns[end:end + 12]:
            ops = x.operands
            if x.mnemonic == "call":
                live -= {"rax"}
                flags_dead = True
                break
            if x.mnemonic in ("ret", "jmp") or JCC.match(x.mnemonic):
                break
            reads = {canon_reg(x.reg_name(o.reg)) for o in ops[1:] if o.type == x86.X86_OP_REG}
            reads |= {canon_reg(x.reg_name(r)) for o in ops if o.type == x86.X86_OP_MEM for r in (o.mem.base, o.mem.index) if r}
            if x.mnemonic not in ("mov", "movzx", "movsx", "lea"):
                reads |= {canon_reg(x.reg_name(o.reg)) for o in ops[:1] if o.type == x86.X86_OP_REG}
            if reads & live:
                break
            if x.mnemonic in ("mov", "movzx", "movsx", "lea") and ops and ops[0].type == x86.X86_OP_REG:
                live.discard(canon_reg(x.reg_name(ops[0].reg)))
        if live or not flags_dead:
            continue
        # (its branches kept: scan's skip of an unreachable block ends at one)
        out |= {x.address for x in span if x.mnemonic != "jmp" and not JCC.match(x.mnemonic)}
    return out


def dead_masks(insns: list) -> set[int]:
    """The addresses of an `and r, M` whose bits the value's extraction then clears: a bitfield
    inserted and read back, `and edx, 0xf80007ff; or eax, edx; ...; shr eax, 0xb; and eax, 0xffff`,
    where r's part of the word (M) and what is kept ((W << k)) share no bit. The decompiler folds
    the word to the inserted field, 0xf80007ff in no C (3 of a client's GUI functions)"""
    out = set()
    for at, x in enumerate(insns):
        ops = x.operands
        if not (x.mnemonic == "and" and len(ops) == 2 and ops[0].type == x86.X86_OP_REG and ops[0].size == 4
                and ops[1].type == x86.X86_OP_IMM):
            continue
        m = ops[1].imm & 0xFFFFFFFF
        r = canon_reg(x.reg_name(ops[0].reg))
        word = None
        k = 0
        for y in insns[at + 1:at + 12]:
            yo = y.operands
            names = [canon_reg(y.reg_name(o.reg)) if o.type == x86.X86_OP_REG else None for o in yo]
            if y.mnemonic.startswith("j") or y.mnemonic in ("call", "ret"):
                break
            if word is None:
                if y.mnemonic == "or" and len(yo) == 2 and r in names:
                    word = names[0]
                elif r in names or any(o.type == x86.X86_OP_MEM and canon_reg(y.reg_name(o.mem.base or o.mem.index or 0) or "") == r
                                       for o in yo if o.mem.base or o.mem.index):
                    break
                continue
            if word not in names:
                continue
            if y.mnemonic == "shr" and names[0] == word and len(yo) == 2 and yo[1].type == x86.X86_OP_IMM:
                k += yo[1].imm
                continue
            if y.mnemonic == "and" and names[0] == word and len(yo) == 2 and yo[1].type == x86.X86_OP_IMM:
                if k and m & (((yo[1].imm & 0xFFFFFFFF) << k) & 0xFFFFFFFF) == 0:
                    out.add(x.address)
            break
    return out


def lane_folds(insns: list) -> set[int]:
    """The addresses of shifts that are a width's, no constant of the source: a packed pair that
    extends each lane's low half, `pslld xmm0, 0x10; psrad xmm0, 0x10` (the port's `movswl` per
    element), and a word's halves added, `mov eax, ecx; movzx ecx, cx; shr eax, 0x10; add eax, ecx`,
    a popcount's last step that the decompiler drops where the value fits in 16 bits"""
    out = set()
    for at, x in enumerate(insns):
        ops = x.operands
        if len(ops) != 2 or ops[1].type != x86.X86_OP_IMM:
            continue
        if x.mnemonic in ("pslld", "psllw", "psllq"):
            w = x.mnemonic[-1]
            for y in insns[at + 1:at + 3]:
                yo = y.operands
                if y.mnemonic in (f"psra{w}", f"psrl{w}") and len(yo) == 2 and yo[0].type == x86.X86_OP_REG \
                        and ops[0].type == x86.X86_OP_REG and yo[0].reg == ops[0].reg \
                        and yo[1].type == x86.X86_OP_IMM and yo[1].imm == ops[1].imm:
                    out |= {x.address, y.address}
                    break
        elif x.mnemonic == "shr" and ops[1].imm == 16 and ops[0].type == x86.X86_OP_REG and 2 <= at < len(insns) - 1:
            r = canon_reg(x.reg_name(ops[0].reg))
            add = insns[at + 1]
            zx = next((p for p in insns[at - 2:at] if p.mnemonic == "movzx" and p.operands[1].type == x86.X86_OP_REG
                       and p.operands[1].size == 2), None)
            if zx is None or len(add.operands) != 2:
                continue
            z = canon_reg(zx.reg_name(zx.operands[0].reg))
            ao = add.operands
            # (or through a lea, `lea eax, [edx + eax - 1]`)
            if add.mnemonic == "add" and all(o.type == x86.X86_OP_REG for o in ao) \
                    and canon_reg(add.reg_name(ao[0].reg)) == r and canon_reg(add.reg_name(ao[1].reg)) == z:
                out.add(x.address)
            elif add.mnemonic == "lea" and ao[1].type == x86.X86_OP_MEM and ao[1].mem.base and ao[1].mem.index \
                    and ao[1].mem.scale == 1 and {canon_reg(add.reg_name(ao[1].mem.base)),
                                                   canon_reg(add.reg_name(ao[1].mem.index))} == {r, z}:
                out.add(x.address)
    return out


def address_steps(insns: list) -> dict[int, int | None]:
    """An address loaded and moved at once, `mov ecx, 0x134bf00; sub ecx, 0x60`: the mov's address
    -> the address made (G - 0x60), the step's -> None (no constant of its own). The CRT's
    __multtenpow12 table pointer, `&DAT_0134bea0` in the C (3 of a client's)"""
    # (the step a few instructions on, none of them touching the register, `mov ecx, 0x134c060;
    # mov [ebp - 0x54], eax; sub ecx, 0x60`)
    out: dict[int, int | None] = {}
    # (never across a branch target: a loop's step, `mov esi, 0x14a2e6c; loop: sub esi, 0x54`, is
    # each round's, the start address the C's own)
    targets = {x.operands[0].imm for x in insns if (x.mnemonic.startswith("j") or x.mnemonic.startswith("loop"))
               and x.operands and x.operands[0].type == x86.X86_OP_IMM}
    for at, x in enumerate(insns):
        xo = x.operands
        if not (x.mnemonic == "mov" and len(xo) == 2 and xo[0].type == x86.X86_OP_REG and xo[1].type == x86.X86_OP_IMM
                and xo[1].imm > 0x10000):
            continue
        r = canon_reg(x.reg_name(xo[0].reg))
        for y in insns[at + 1:at + 5]:
            if y.address in targets:
                break
            yo = y.operands
            if y.mnemonic in ("add", "sub") and len(yo) == 2 and yo[0].type == x86.X86_OP_REG \
                    and yo[0].reg == xo[0].reg and yo[1].type == x86.X86_OP_IMM and 0 < yo[1].imm < 0x1000:
                d = yo[1].imm if y.mnemonic == "add" else -yo[1].imm
                out[x.address] = (xo[1].imm + d) & 0xFFFFFFFF
                out[y.address] = None
                break
            if y.mnemonic.startswith("j") or y.mnemonic in ("call", "ret") or any(
                    o.type == x86.X86_OP_REG and canon_reg(y.reg_name(o.reg)) == r
                    or o.type == x86.X86_OP_MEM and r in (canon_reg(y.reg_name(o.mem.base)) if o.mem.base else "",
                                                           canon_reg(y.reg_name(o.mem.index)) if o.mem.index else "")
                    for o in yo):
                break
    return out


def rounded_adds(insns: list) -> dict[int, list[int]]:
    """An addition rounded down by an alignment mask straight after, `add eax, 0x23; ...; and eax,
    0xfffffff0` with eax a multiple of 16: the addition's -> the multiple it comes to (0x20), which
    the decompiler folds, `(c - 1) * 0x10 + 0x20` (2 of a client's chunk walkers)"""
    out: dict[int, list[int]] = {}
    for at, x in enumerate(insns):
        ops = x.operands
        if not (x.mnemonic == "add" and len(ops) == 2 and ops[0].type == x86.X86_OP_REG and ops[1].type == x86.X86_OP_IMM
                and 0 < ops[1].imm < 0x10000):
            continue
        # (the value a multiple of the alignment going in: shifted left by the mask's bits)
        p = insns[at - 1] if at else None
        for y in insns[at + 1:at + 4]:
            yo = y.operands
            if y.mnemonic == "and" and len(yo) == 2 and yo[0].type == x86.X86_OP_REG and yo[0].reg == ops[0].reg \
                    and yo[1].type == x86.X86_OP_IMM:
                m = yo[1].imm & 0xFFFFFFFF
                low = ~m & 0xFFFFFFFF
                if low and low & (low + 1) == 0 and p is not None and p.mnemonic == "shl" \
                        and p.operands[0].type == x86.X86_OP_REG and p.operands[0].reg == ops[0].reg \
                        and p.operands[1].type == x86.X86_OP_IMM and (1 << p.operands[1].imm) > low:
                    out[x.address] = [ops[1].imm & m]
                break
            if any(o.type == x86.X86_OP_REG and o.reg == ops[0].reg for o in yo):
                break
    return out


def mask_chains(insns: list) -> dict[int, list[int]]:
    """A run of three or more `and r, imm` / `or r, imm` on one register, nothing else touching it
    between: the bitfield stores of one word, which a compiler or decompiler folds to one mask and
    one value, `x & A | O`. Its first instruction -> A and O (each but an all-clear or all-set
    mask), the others -> nothing. A client's flags word, `and eax, 0xff7f8ff1; or eax, 0x7000001;
    and eax, 0xfffff54f; ...` that the decompiler made the constant 0x7080541"""
    out: dict[int, list[int]] = {}
    at = 0
    while at < len(insns):
        x = insns[at]
        ops = x.operands
        if not (x.mnemonic in ("and", "or") and len(ops) == 2 and ops[0].type == x86.X86_OP_REG
                and ops[1].type == x86.X86_OP_IMM and ops[0].size == 4):
            at += 1
            continue
        r = ops[0].reg
        chain = [at]
        k = at + 1
        while k < len(insns) and k - chain[-1] <= 4:
            y = insns[k]
            yo = y.operands
            if y.mnemonic in ("and", "or") and len(yo) == 2 and yo[0].type == x86.X86_OP_REG and yo[0].reg == r \
                    and yo[1].type == x86.X86_OP_IMM:
                chain.append(k)
            # (and on through a copy, `and ecx, 0xfffffff; mov edx, ecx; and edx, 0xfffffdff; or
            # edx, 0x1c0`, the word's fields set in the copy)
            elif y.mnemonic == "mov" and len(yo) == 2 and all(o.type == x86.X86_OP_REG for o in yo) \
                    and yo[1].reg == r and yo[0].size == 4:
                r = yo[0].reg
                x = y
            elif y.mnemonic.startswith("j") or y.mnemonic in ("call", "ret") \
                    or any(o.type == x86.X86_OP_REG and canon_reg(y.reg_name(o.reg)) == canon_reg(x.reg_name(r))
                           for o in yo) \
                    or any(o.type == x86.X86_OP_MEM and r in (o.mem.base, o.mem.index) for o in yo):
                break
            k += 1
        if len(chain) >= 3:
            a_mask, o_val = 0xFFFFFFFF, 0
            for c in chain:
                m = insns[c].operands[1].imm & 0xFFFFFFFF
                if insns[c].mnemonic == "and":
                    a_mask &= m
                    o_val &= m
                else:
                    o_val |= m
                    a_mask &= ~m & 0xFFFFFFFF
            out[insns[chain[0]].address] = [v for v in dict.fromkeys((a_mask, o_val)) if v not in (0, 0xFFFFFFFF)]
            for c in chain[1:]:
                out[insns[c].address] = []
            at = chain[-1] + 1
        else:
            at += 1
    return out


def stack_arity(c: str) -> int | None:
    """The stack parameters a decompiled function's signature takes (`this` in ecx, __fastcall's
    two and register inputs `in_eax` not among them), or None for a variadic or unreadable one."""
    head = re.sub(r"/\*.*?\*/", "", c, flags=re.S).split("{", 1)[0]
    k = head.rfind(")")
    depth, i = 0, k
    while i >= 0:
        depth += {")": 1, "(": -1}.get(head[i], 0)
        if depth == 0:
            break
        i -= 1
    if k < 0 or i < 0:
        return None
    inner = head[i + 1:k].strip()
    if inner in ("", "void"):
        return 0
    parts, depth, cur = [], 0, ""
    for ch in inner:
        depth += {"(": 1, "<": 1, ")": -1, ">": -1}.get(ch, 0)
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    parts.append(cur)
    if any(p.strip() == "..." for p in parts):
        return None
    n = sum(not re.search(r"\bin_[a-z]{2,3}\s*$", p.strip()) for p in parts)
    n -= {"__thiscall": 1, "__fastcall": 2}.get(next((cc for cc in ("__thiscall", "__fastcall") if cc in head), ""), 0)
    return max(n, 0)


def scan(img: Image, ref: Image, md, ranges: list[tuple[int, int]], own: int, port: bool,
         dead: set[int] = frozenset(), injected: set[int] = frozenset(), arity: dict | None = None,
         takes_ecx: set | frozenset = frozenset()) -> Fn:
    """A function's features. `ref` names the reference's globals and strings: the port reads
    them at the reference's own addresses. `dead`: the starts of blocks the decompiler proved
    unreachable, left out to the next jump or return (__RTC_Initialize's loop over an empty table).
    `injected`: functions the decompiler replaced with their p-code (call fixups): a count loaded
    into cl for one, `mov cl, 0x20; call __aullshr`, is the operation's, which the decompiler may
    fold away (`(edx:eax) >> 32` is the high half), no constant of the function."""
    f = Fn()
    skipping = False
    last_cl = None
    select: dict = {}                       # register -> the mask of an `sbb r, r; and r, -k` select
    held: dict = {}                         # register -> the address a `mov r, imm` put in it
    stackp: set = set()                     # registers holding an address in the frame
    lea_disp: dict = {}                     # register -> the displacement of the indexed lea that set it
    pushed: list = []                       # the integer immediates pushed since the last call
    ecx_fields: list = []                   # the fields read into ecx since the last call
    reg_fields: dict = {}                   # register -> the fields read into it since the last call
    reg_imms: dict = {}                     # register -> the constants computed into it since then
    args: list = []                         # each push since the last call: the constants it carries
    arg_fields: list = []                   # and the fields read into the register it pushes

    def inside(t):
        return any(lo <= t < hi for lo, hi in ranges)

    def global_or_const(v: int, mn: str, size: int) -> str | None:
        """An address in the reference's image: a string, a float constant it loads, a global."""
        if not ref.contains(v) or (port and img.contains(v) and img is not ref):
            return None
        # (the image base itself as an immediate is a number, `cmp eax, 0x400000` for a counter's
        # `0x3fffff < n`: no address of anything the port names, its headers aside)
        if v == ref.base and not FLOAT_MNEMONIC.search(mn):
            return None
        # (a scalar operand by its suffix: capstone sizes comisd's `xmmword ptr` 16)
        # (cvtsi2sd's source is an integer)
        m = re.search(r"(?:^cvtt?(ss|sd)2|(ss|sd)$)", mn)
        # (and x87's integer operands, `fild dword ptr [eax*4 + 0x13281b8]`: an int table's, no
        # float's bits, 2 of a client's)
        if mn.startswith("cvtsi2") or mn.startswith("fi"):
            return f"g:{v:x}"
        if m:
            size = 4 if (m.group(1) or m.group(2)) == "ss" else 8
        if FLOAT_MNEMONIC.search(mn) and size in (4, 8):
            k = F.float_text(ref.read(v, size))
            f.float_at[v] = k
            return k
        if FLOAT_MNEMONIC.search(mn) and size == 16:
            f.packed.add(v)
        s = ref.cstr(v)
        if s is None:
            s = ref.wstr(v)
        if s is not None:
            f.str_at.setdefault("s:" + s, set()).add(v)
            return "s:" + s
        # (an address in the reference's code is a function's or a jump table's: the port has its
        # own tables, and a function taken as a value is a call target, not data)
        if ref.is_code(v):
            return "code"
        return f"g:{v:x}"

    def overwritten(insn, after) -> bool:
        """The register an instruction only writes, overwritten by the next one unread: a value
        no one uses, which the decompiler drops (the CRT's dtol3 raises inexact with `cvttss2si
        ebx, [m]` and pops ebx straight after: no constant of the source)."""
        ops = insn.operands
        if after is None or not (insn.mnemonic.startswith(("cvt", "mov")) and len(ops) == 2
                                 and ops[0].type == x86.X86_OP_REG and ops[1].type == x86.X86_OP_MEM):
            return False
        r = ops[0].reg
        nxt = after.operands
        return after.mnemonic == "pop" and nxt and nxt[0].type == x86.X86_OP_REG and nxt[0].reg == r

    for lo, hi in ranges:
        insns = list(md.disasm(img.read(lo, hi - lo), lo))
        dead_stores = dead_stack_stores(insns) | dead_compares(insns) | dead_masks(insns) | lane_folds(insns) if not port else set()
        chains = mask_chains(insns)
        if not port:
            chains.update(rounded_adds(insns))
        steps = address_steps(insns) if not port else {}
        imm_in: dict = {}                       # register -> the constant a `mov r, imm` put in it
        # (the frame's registers as a forward branch leaves them, for its target past a ret or
        # jmp: an early return's epilogue, `mov esp, ebx; pop ebx; ret 4`, undid the realigned
        # frame's anchor for the code the branch skips to, its `[ebx + 8]` taken for a field)
        at_branch: dict = {}
        for at, insn in enumerate(insns):
            mn = insn.mnemonic
            if at and insn.address in at_branch and (insns[at - 1].mnemonic in ("ret", "jmp")):
                sp, ld = at_branch[insn.address]
                stackp.clear()
                stackp |= sp
                lea_disp.clear()
                lea_disp.update(ld)
            if (JCC.match(mn) or mn == "jmp") and insn.operands and insn.operands[0].type == x86.X86_OP_IMM \
                    and insn.operands[0].imm > insn.address:
                at_branch.setdefault(insn.operands[0].imm, (set(stackp), dict(lea_disp)))
            # (a locked operation on a frame slot, `lock cmpxchg [edx], ecx` with edx `lea [esp + k]`:
            # an atomic on a local no other thread sees, a volatile one, which the decompiler folds
            # to its value. The constants it takes are the fold's: `_InterlockedCompareExchange(&n,
            # 100, ...)` on `volatile long n`, rhtest misc atomics)
            if not port and insn.operands and (insn.prefix[0] == 0xF0 or mn == "xchg"):
                mops = [o for o in insn.operands if o.type == x86.X86_OP_MEM]
                if mops and mops[0].mem.base and (insn.reg_name(mops[0].mem.base) in STACK_REGS
                                                 or canon_reg(insn.reg_name(mops[0].mem.base)) in stackp):
                    for o in insn.operands:
                        if o.type == x86.X86_OP_REG:
                            k = imm_in.pop(canon_reg(insn.reg_name(o.reg)), None)
                            if k and f.consts.get(k):
                                f.consts[k] -= 1
                                if f.consts[k] <= 0:
                                    del f.consts[k]
            if insn.operands and insn.operands[0].type == x86.X86_OP_REG:
                r = canon_reg(insn.reg_name(insn.operands[0].reg))
                if mn == "mov" and len(insn.operands) == 2 and insn.operands[1].type == x86.X86_OP_IMM:
                    imm_in[r] = f"i:{insn.operands[1].imm & 0xFFFFFFFF:x}"
                elif not (insn.prefix[0] == 0xF0 or mn == "xchg"):
                    imm_in.pop(r, None)
            if insn.address in dead_stores:
                continue
            if insn.address in dead:
                skipping = True
            if skipping:
                skipping = not (mn in ("jmp", "ret") or JCC.match(mn))
                continue
            f.mnemonics.append(norm_mnemonic(mn))
            ops = insn.operands
            if not port and overwritten(insn, insns[at + 1] if at + 1 < len(insns) else None):
                continue
            # (a trap is no constant: `int 0x29` is __fastfail, which the port raises in its
            # gen_swi_* helpers; compared as a call)
            if mn == "int3" or (mn == "int" and ops):
                # (not the port's `int3` after a call that does not return, x64 MSVC's padding
                # there: dive's longjmp, rhtest misc 2026-10-24)
                # (nor the reference's there, where it ends the function or pads on to the next:
                # `push msg; call _Xout_of_range; int3`, unreachable after a call that throws,
                # rhtest stl-O2's 0x40be30)
                after_call = at and insns[at - 1].mnemonic == "call"
                pad = at + 1 >= len(insns) or insns[at + 1].mnemonic == "int3"
                if not (mn == "int3" and after_call and (port or pad)):
                    f.calls.append((insn.address, f"trap:{ops[0].imm & 0xff:x}" if ops else "trap:3"))
                continue
            if mn == "ret":
                continue                               # (`ret 0x10`: the callee's cleanup, no constant)
            # (a mask on ah is a float comparison's flags, `fnstsw ax` or `lahf` then `test ah,
            # 0x44`: how the compiler reads C0/C2/C3 or ZF/PF, no constant of the source)
            if ops and ops[0].type == x86.X86_OP_REG and insn.reg_name(ops[0].reg) == "ah":
                continue
            # (a select between two constants without a branch: `sbb rcx, rcx; and rcx, -0xa0;
            # movsd xmm2, [rcx + 0x4041b8]` reads 0x4041b8 or 0x404118. The mask is the distance
            # between them, and the constant at its far end is read too, series' 1.0 and -1.0)
            if mn == "sbb" and len(ops) == 2 and ops[0].type == ops[1].type == x86.X86_OP_REG \
                    and ops[0].reg == ops[1].reg:
                select[ops[0].reg] = None
            elif mn == "and" and len(ops) == 2 and ops[0].type == x86.X86_OP_REG and ops[1].type == x86.X86_OP_IMM \
                    and ops[0].reg in select and -0x10000 < ops[1].imm < 0:
                select[ops[0].reg] = ops[1].imm
                continue
            elif select and ops and ops[0].type == x86.X86_OP_REG and ops[0].reg in select and mn not in ("and", "sbb"):
                select.pop(ops[0].reg)
            # (an address the compiler makes from another it holds, `mov r9d, 0x4050ac; lea r8d,
            # [r9 + 4]`: two strings side by side, fmt_va's name and format, rhtest crt-Od)
            base_r = canon_reg(insn.reg_name(ops[1].mem.base)) if len(ops) == 2 and ops[1].type == x86.X86_OP_MEM \
                and ops[1].mem.base else None
            if mn == "lea" and base_r in held and not ops[1].mem.index and ops[1].mem.disp:
                k = global_or_const((held[base_r] + ops[1].mem.disp) & 0xFFFFFFFF, mn, 0)
                if k is not None and k != "code":
                    f.consts[k] += 1
            if ops and ops[0].type == x86.X86_OP_REG:
                r0 = canon_reg(insn.reg_name(ops[0].reg))
                if mn == "mov" and len(ops) == 2 and ops[1].type == x86.X86_OP_IMM and ops[1].imm > 0x10000:
                    held[r0] = ops[1].imm & 0xFFFFFFFF
                else:
                    held.pop(r0, None)
                # (a register holding a stack address, `lea esi, [esp + 0x10]`, and stepped from it:
                # an access through it is the frame's, as one through esp, not a structure's field.
                # The reference walked its frame's packed records through esi, [esi + 5], the port
                # at [rsp + k] (rhtest core-O2 0x401ff0))
                src = ops[1] if len(ops) == 2 else None
                # (a member's address, `lea edi, [eax + ecx + 0x1c4]`: its fields' offsets plus it
                # are the C's, `this + i * 0xb4 + 0x21c` for [edi + 0x58])
                if mn == "lea" and src is not None and src.type == x86.X86_OP_MEM and src.mem.index \
                        and 0 < src.mem.disp < 0x10000:
                    lea_disp[r0] = src.mem.disp
                elif mn == "lea" and src is not None and src.type == x86.X86_OP_MEM and src.mem.base \
                        and canon_reg(insn.reg_name(src.mem.base)) in lea_disp and not src.mem.index:
                    lea_disp[r0] = lea_disp[canon_reg(insn.reg_name(src.mem.base))] + src.mem.disp
                elif not (mn in ("push", "cmp", "test")):
                    lea_disp.pop(r0, None)
                if mn == "lea" and src is not None and src.mem.base and \
                        canon_reg(insn.reg_name(src.mem.base)) in STACK_PTRS | stackp:
                    stackp.add(r0)
                # (or a copy of esp or ebp itself: a realigned frame's anchor, `push ebx; mov ebx, esp;
                # and esp, -8`, its arguments at [ebx + 8] on: no fields. 58 of a client's functions
                # missed "field 0xc", their second argument, 2026-10-30)
                elif mn == "mov" and src is not None and src.type == x86.X86_OP_REG and \
                        canon_reg(insn.reg_name(src.reg)) in STACK_PTRS | stackp:
                    stackp.add(r0)
                elif r0 in stackp and not (mn in ("add", "sub", "inc", "dec", "cmp", "test", "push")
                                           and (src is None or src.type != x86.X86_OP_MEM)):
                    stackp.discard(r0)
            for op in ops:
                if op.type == x86.X86_OP_MEM and select.get(op.mem.base) and not op.mem.index:
                    k = global_or_const((op.mem.disp + select[op.mem.base]) & 0xFFFFFFFF, mn, op.size)
                    if k is not None and k != "code":
                        f.consts[k] += 1
            if mn in ("call", "jmp") or JCC.match(mn):
                # (and the immediates pushed as its operands since the last call: `push 0x100;
                # push 0; ...; call __allmul` for `* 0x10000000000`, which the decompiler folds
                # with the next multiply into `* 0x600`, rhtest int64-Od's gcd64 operands)
                if ops and ops[0].type == x86.X86_OP_IMM and ops[0].imm in injected:
                    for k in ([last_cl] if last_cl else []) + (pushed if mn == "call" else []):
                        f.consts[k] -= 1
                        if f.consts[k] <= 0:
                            del f.consts[k]
                    # (and the fields read into ecx for it, its register argument: an EH handler's
                    # `mov ecx, [edx + 0x74]; xor ecx, eax; call __security_check_cookie`, the
                    # frame's cookie, rhtest engine-O2's 0x402c5d)
                    # (a tail jump to it too, and the fields that reached ecx through another
                    # register: _ValidateLocalCookies' `mov eax, [esi + 8]; mov ecx, [esi + 0xc];
                    # add ecx, edi; xor ecx, [eax + edi]; jmp __security_check_cookie`, which the
                    # fixup's no-op check leaves the port without, rhtest stl-O2)
                    for d in ecx_fields:
                        if d in f.fields:
                            f.fields[d] -= 1
                            if f.fields[d] <= 0:
                                del f.fields[d]
                    ecx_fields = []
                last_cl = None
                # (the constants of arguments pushed past what the callee takes, which nothing
                # reads: sized operator delete's `add edx, 0x23; push edx; push eax; call delete` of
                # a callee that takes the pointer alone, the port passing none, rhtest stl-O2)
                # (and what is loaded into ecx for a callee that takes nothing there: an atexit
                # thunk's `mov ecx, obj; jmp dtor` to a body that never reads ecx, rhtest stl-O2)
                # (an import takes nothing in ecx either: `call [slot]`, or its thunk `jmp [slot]`
                # called, GetCurrentThreadId's in a client's 0x500f70 after `mov ecx, [0x1375a1c]`,
                # 10 like it, 2026-10-30)
                to_import = False
                if mn == "call" and ops and ops[0].type == x86.X86_OP_MEM and not ops[0].mem.base \
                        and not ops[0].mem.index and (ops[0].mem.disp & 0xFFFFFFFF) in img.iat:
                    to_import = True
                elif mn in ("call", "jmp") and ops and ops[0].type == x86.X86_OP_IMM:
                    code = img.read(ops[0].imm & 0xFFFFFFFF, 6)
                    to_import = len(code) == 6 and code[:2] == b"\xff\x25" \
                        and int.from_bytes(code[2:6], "little") in img.iat
                    # (or an empty method, `ret 4` and nothing else, no function of its own: a
                    # tail jump to it after `mov ecx, [ecx + 0x14]` reads nothing, and the
                    # decompiler's `return;` is the call. 11 of a client's functions, 2026-10-30)
                    to_import = to_import or (len(code) >= 1 and (code[0] == 0xC3 or code[0] == 0xC2))
                if mn in ("call", "jmp") and (arity or to_import) and ops \
                        and (ops[0].type == x86.X86_OP_IMM or to_import):
                    t = ops[0].imm & 0xFFFFFFFF if ops[0].type == x86.X86_OP_IMM else None
                    # (or a tail jump, the range's last instruction, into code the decompiler took
                    # into this function, whose own signature takes nothing in ecx)
                    tail_in = mn == "jmp" and t not in (arity or {}) and at + 1 == len(insns) and own not in takes_ecx
                    if (t in (arity or {}) and t not in takes_ecx) or tail_in or to_import:
                        for k in reg_imms.get(canon_reg("ecx"), ()):
                            if f.consts.get(k):
                                f.consts[k] -= 1
                                if f.consts[k] <= 0:
                                    del f.consts[k]
                        reg_imms.pop(canon_reg("ecx"), None)
                        # (and the fields read into it, `mov ecx, [esi + 0xc]; call f` of a callee
                        # that never reads ecx: its dead `this`, 13 of a client's functions)
                        for d in ecx_fields:
                            if f.fields.get(d):
                                f.fields[d] -= 1
                                if f.fields[d] <= 0:
                                    del f.fields[d]
                        ecx_fields = []
                if mn == "call" and arity and ops and ops[0].type == x86.X86_OP_IMM:
                    n = arity.get(ops[0].imm & 0xFFFFFFFF)
                    if n is not None:
                        for ks in args[:max(0, len(args) - n)]:
                            for k in ks:
                                if f.consts.get(k):
                                    f.consts[k] -= 1
                                    if f.consts[k] <= 0:
                                        del f.consts[k]
                        # (and the fields read into a register pushed past them: `movzx ecx, word
                        # [esi + 0x12]; push ecx` for a callee taking three of the four pushed, a
                        # layout instance's vf4 and 21 like it, 2026-10-30)
                        for ds in arg_fields[:max(0, len(arg_fields) - n)]:
                            for d in ds:
                                if f.fields.get(d):
                                    f.fields[d] -= 1
                                    if f.fields[d] <= 0:
                                        del f.fields[d]
                if mn == "call":
                    ecx_fields = []
                    reg_fields = {}
                    pushed = []
                    args = []
                    arg_fields = []
                    reg_imms = {}
                if ops and ops[0].type == x86.X86_OP_IMM:
                    t = ops[0].imm
                    if not inside(t):
                        # (a jump is a tail call only to a function's entry: a jump into another's
                        # middle is code the two share, an epilogue an SEH funclet was cut from)
                        f.calls.append((insn.address, t if mn == "call" else ("jump", t)))
                    continue
                if ops and ops[0].type == x86.X86_OP_MEM and not ops[0].mem.base and not ops[0].mem.index:
                    slot = ops[0].mem.disp & 0xFFFFFFFF
                    if slot in img.iat:
                        f.calls.append((insn.address, "imp:" + img.iat[slot]))
                    continue
            # (what each push carries, and what a register holds of the constants computed into it)
            if mn == "push" and ops:
                if ops[0].type == x86.X86_OP_REG:
                    args.append(list(reg_imms.get(canon_reg(insn.reg_name(ops[0].reg)), ())))
                    arg_fields.append(list(reg_fields.get(insn.reg_name(ops[0].reg), ())))
                else:
                    args.append([])
                    arg_fields.append([])
            elif ops and ops[0].type == x86.X86_OP_REG and not any(o.type == x86.X86_OP_IMM for o in ops[1:]) \
                    and mn in ("mov", "lea", "movzx", "movsx", "pop", "xor"):
                # (loaded through itself, `mov ecx, [0x1379860]; mov ecx, [ecx + 0xc]`: what it held
                # made the new value, a dead `this` chain's global with it, 7 of a client's functions)
                # (or through another, `mov edx, [g]; mov ecx, [edx + 0xc]`: what the base carried)
                r0 = canon_reg(insn.reg_name(ops[0].reg))
                if len(ops) == 2 and ops[1].type == x86.X86_OP_MEM and ops[1].mem.base and mn == "mov":
                    reg_imms[r0] = list(reg_imms.get(canon_reg(insn.reg_name(ops[1].mem.base)), ()))
                else:
                    reg_imms[r0] = []
            # (ecx computed from another register: the fields that register holds reach ecx)
            if ops and ops[0].type == x86.X86_OP_REG and insn.reg_name(ops[0].reg) == "ecx" and mn != "lea":
                for op in ops[1:]:
                    rs = [op.reg] if op.type == x86.X86_OP_REG else \
                        [r for r in (op.mem.base, op.mem.index) if r] if op.type == x86.X86_OP_MEM else []
                    for r in rs:
                        ecx_fields.extend(reg_fields.get(insn.reg_name(r), ()))
            for op in ops:
                if op.type == x86.X86_OP_MEM:
                    base = insn.reg_name(op.mem.base) if op.mem.base else ""
                    disp = op.mem.disp
                    if base == "rip":
                        t = insn.address + insn.size + disp
                        if mn == "lea" and img.is_code(t):
                            # (a function's address taken: Ghidra32.h's swi(n) is a trap helper's,
                            # called through a register)
                            f.calls.append((insn.address, ("addr", t)))
                            continue
                        if mn == "lea" and (img.cstr(t) or img.wstr(t)):
                            f.consts["s:" + (img.cstr(t) or img.wstr(t))] += 1
                        elif FLOAT_MNEMONIC.search(mn) and op.size in (4, 8):
                            # (not one past the image's end: no bytes to read there)
                            raw = img.read(t, op.size)
                            if len(raw) == op.size:
                                f.consts[F.float_text(raw)] += 1
                        continue
                    # (a switch's jump table, `jmp [eax*4 + 0x4242fc]`: the compiler's lowering of
                    # the cases, no constant of the source; its first entry's bytes read as a
                    # string, "3AB", rhtest stl-O2's undname)
                    if mn == "jmp" and op.mem.index:
                        continue
                    k = global_or_const(disp & 0xFFFFFFFF, mn, op.size)
                    # (an array of words indexed, `mov eax, [ecx*4 + 0x13281b8]`, no string read
                    # whatever its bytes spell: its base, the global)
                    if k is not None and k.startswith("s:") and op.mem.index and op.mem.scale > 1:
                        k = f"g:{disp & 0xFFFFFFFF:x}"
                    if k is not None and disp > 0x10000:
                        # (a float read through a register, `movsd xmm0, [edx + 0x405090]`: an array's
                        # element, not the value at its base, which its constant would be. The port
                        # reads the element at its folded address, g_vals[5], rhtest fpenv-Od)
                        if k.startswith("f:") and (op.mem.base or op.mem.index):
                            k = f"a:{disp & 0xFFFFFFFF:x}"
                        if k != "code" and not (img is ref and disp & 0xFFFFFFFF in img.iat):
                            f.consts[k] += 1
                            # (a global's value loaded into a register, `mov ecx, [0x14c4e78]`: as an
                            # immediate moved there, what a callee taking nothing in ecx drops below.
                            # A manager's method that never reads `this` (0xb595f0, `ret 4`), its
                            # caller's dead `this` load, 91 of a client's functions, 2026-10-30)
                            if mn == "mov" and op is ops[-1] and ops[0].type == x86.X86_OP_REG \
                                    and not op.mem.base and not op.mem.index:
                                reg_imms.setdefault(canon_reg(insn.reg_name(ops[0].reg)), []).append(k)
                        continue
                    if port and op.mem.base and base not in STACK_REGS and -0x1000 < op.mem.disp < 0:
                        f.negdisp.add(-op.mem.disp)
                    # (not an indexed operand's: `[esi + eax*4 + 4]` is an array offset, which the
                    # other compiler folds as it likes)
                    if base not in STACK_REGS and canon_reg(base) not in stackp and mn != "lea" \
                            and op.mem.base and not op.mem.index:
                        # (a wide access is the 4-byte ones x86 makes of it: a 64-bit value at
                        # [rcx] is the reference's [esi] and [esi + 4])
                        # (a vector's lanes are no fields: `vmovdqu ymm0, [esi]` is one access, the
                        # port's helper a copy of its bytes, rhtest stl-Od's AVX2 reverse)
                        for d in range(disp, disp + (max(op.size, 4) if op.size <= 8 else 4), 4):
                            if d > 0:
                                f.fields[d] += 1
                                if canon_reg(base) in lea_disp:
                                    f.member_at.setdefault(d, set()).add(lea_disp[canon_reg(base)] + d)
                                if ops[0].type == x86.X86_OP_REG and op is not ops[0]:
                                    reg_fields.setdefault(insn.reg_name(ops[0].reg), []).append(d)
                                    if insn.reg_name(ops[0].reg) == "ecx":
                                        ecx_fields.append(d)
                elif op.type == x86.X86_OP_IMM:
                    v = op.imm & 0xFFFFFFFF
                    if v == own:
                        continue                       # (GEN_ENTER's own address)
                    # (an address and its step as the address made, address_steps)
                    if insn.address in steps:
                        if steps[insn.address] is None:
                            continue
                        v = steps[insn.address]
                    # (a chain of one word's masks as its fold, mask_chains)
                    if insn.address in chains:
                        for c in chains[insn.address]:
                            if 0x10 <= c <= 0xFFFFFFF0:
                                f.consts[f"i:{c:x}"] += 1
                        continue
                    k = global_or_const(v, mn, 0) if v > 0x10000 else None
                    if v > 0x10000:
                        f.imms.add(v)
                    if k is not None:
                        if k != "code":
                            f.consts[k] += 1
                            if mn == "mov" and ops[0].type == x86.X86_OP_REG:
                                reg_imms.setdefault(canon_reg(insn.reg_name(ops[0].reg)), []).append(k)
                            elif mn == "push" and args:
                                args[-1].append(k)
                    # (not the stack's own arithmetic, `sub esp, k` or a realignment `and esp, -0x40`,
                    # nor a SIMD op's lane control, `shufps xmm1, xmm0, 0xdd`: the machine's, no
                    # constant of the source)
                    elif 0x10 <= v <= 0xFFFFFFF0 and not (mn in ("add", "sub", "and") and ops[0].type == x86.X86_OP_REG
                                                          and insn.reg_name(ops[0].reg) in STACK_REGS) \
                            and not SIMD_CONTROL.match(mn):
                        f.consts[f"i:{v:x}"] += 1
                        if mn in ("add", "sub") and ops[0].type == x86.X86_OP_REG:
                            f.steps.add(f"i:{v:x}")
                        if mn == "mov" and ops[0].type == x86.X86_OP_REG and insn.reg_name(ops[0].reg) in ("cl", "ecx"):
                            last_cl = f"i:{v:x}"
                        if mn == "push":
                            pushed.append(f"i:{v:x}")
                            if args:
                                args[-1].append(f"i:{v:x}")
                        elif ops[0].type == x86.X86_OP_REG:
                            reg_imms.setdefault(canon_reg(insn.reg_name(ops[0].reg)), []).append(f"i:{v:x}")
    return f


def near(k, have: set) -> bool:
    """A constant the other side has, or a comparison's by one (`x > 1000` is `cmp 1000` to one
    compiler and `cmp 1001` to another)."""
    if k in have:
        return True
    if isinstance(k, str) and k.startswith("i:"):
        v = int(k[2:], 16)
        # (or negated: `sub ecx, 0x20` is `add ecx, -0x20` to another compiler)
        return any(f"i:{w & 0xFFFFFFFF:x}" in have for w in (v + 1, v - 1, -v))
    if isinstance(k, str) and k.startswith("g:"):
        # (a global within 16 bytes of one the other side uses: neighbours stored as one vector,
        # `movups [g], xmm0` for four of them, or one address made from another's register)
        v = int(k[2:], 16)
        if any(f"g:{v + d:x}" in have for d in range(-15, 16) if d):
            return True
        # (or a record's further on, an index's constant part folded in by whole words, `[eax +
        # 0x10993b0]` for the port's 0x10993d0, element -1 of a 32-byte table)
        if any(f"g:{v + d:x}" in have for d in range(-0x40, 0x41, 4) if d):
            return True
        # (or its address folded into a scaled index, as an array's below: `table[-i]` of a
        # pointer table at 0x10efcc8 as `mov eax, 0x43bf32; sub rax, rbx; mov eax, [rax*4]`, the
        # x64 compiler's (0x10efcc8 / 4 - i) * 4, a client's 0xb1a580 scored 0, 2026-10-30)
        # (as an integer, or as a "global" itself where the quotient falls in the image, 0x43bf32)
        return any(f"{p}:{(v + d) // s:x}" in have for p in ("i", "g") for s in (2, 4, 8)
                   for d in range(-16, 17) if (v + d) % s == 0)
    if isinstance(k, str) and k.startswith("a:"):
        # (an array's base, a float array read through a register: the other side's array, or an
        # element of it the decompiler folded the index into, within 256 bytes on)
        v = int(k[2:], 16)
        # (or its address an immediate the other side indexes from, `mov eax, 0x404360`, or that
        # immediate scaled, the base folded into the index: `[(i + 0x8086c) * 8]` for a double
        # table at 0x404360, float-O2's on CI, 2026-10-30)
        if any(f"{p}:{v + d:x}" in have for p in ("a", "g", "i") for d in range(0, 256)):
            return True
        # (or a record table's base below it the port indexes from, `&DAT_013503a0 + i * 0x18`'s
        # bytes beside the floats at +0x18 on, 2 of a client's sound layouts)
        if any(f"{p}:{v - d:x}" in have for p in ("a", "g") for d in range(1, 256)):
            return True
        return any(f"i:{(v + d) // s:x}" in have for s in (2, 4, 8) for d in range(0, 256, s) if (v + d) % s == 0)
    return False


def presence(ref: Counter, port: Counter, source: set[int] = frozenset(),
             bases: tuple[set[int], set[int]] = (frozenset(), frozenset()),
             moved: tuple[dict, set, set] | None = None) -> tuple[float | None, list]:
    """The share of what the reference uses that the port uses too, by presence: how often a
    constant or field appears is the compilers' (unrolling, what stays in a register), x86 and x64
    apart. And what it misses. `source`: the integers the translation's C has, where an integer
    constant the x64 compiler turned into something else counts (`| 0x80000000` as `bts eax, 31`,
    `* 100` as `lea`s, a switch's cases as ranges): the translation kept it."""
    if not ref:
        return None, []
    have = set(port)

    def kept(k):
        if near(k, have):
            return True
        # (a string or global the port reaches from another by one of its immediates: a choice of
        # three messages as `0x44f5d8 + (b ? -0x18 : 0)`, ios_base::clear's, rhtest stl-Od)
        if moved and isinstance(k, str) and k[:2] in ("s:", "g:"):
            ref_at, port_addrs, port_ints = moved
            addrs = ref_at.get(k, set()) if k.startswith("s:") else {int(k[2:], 16)}
            if any(((a - d) & 0xFFFFFFFF) in port_addrs for a in addrs for d in port_ints):
                return True
            # (or a "string" at an address the port names as data: a vtable whose bytes spell
            # " gG", or a name table the port indexes, `mov ebx, 0x134fbc0` for "vorbis")
            # (and a global the port reads as a string there, the other way, or a few bytes on: a
            # table of 8-byte records indexed from 0x1093a00 that the port reads at its +0xc,
            # the bytes there spelling a string's tail)
            if addrs & port_addrs or (k.startswith("g:") and any(a + d in port_addrs for a in addrs for d in range(-16, 16) if d)):
                return True
            # (or folded into a scaled index, the address over the element's size an immediate of
            # the port's, whatever it was taken for: `table[-i]` of a pointer table at 0x10efcc8
            # as `mov eax, 0x43bf32; sub rax, rbx; mov eax, [rax*4]`, 0x43bf32 in the reference's
            # code range, a client's 0xb1a580 scored 0, 2026-10-30)
            if k.startswith("g:") and any((a + d) % s == 0 and (a + d) // s in port_ints
                                          for a in addrs for s in (2, 4, 8) for d in range(-16, 17)):
                return True
        # (a global the translation names, `REFP(0x1159910)`, that its compiler dropped as a dead
        # store: a constructor's base vtable at +0x11c overwritten by the derived one's straight
        # after, both in the C, the first gone from the x64 code. As an integer the C has, below.
        # 25 of a client's network work definitions, 2026-10-30)
        if isinstance(k, str) and k.startswith("g:") and int(k[2:], 16) in source:
            return True
        # (the same of a vtable whose bytes read as a string, `REFP(0x1090ba0)` for " gG")
        if moved and isinstance(k, str) and k.startswith("s:") and moved[0].get(k, set()) & set(source):
            return True
        # (0.0, the reference's constant in memory: the x64 compiler's is `xorps xmm0, xmm0`, no
        # constant at all, rhtest float-O2's 0x402320)
        if k in ("f:0", "f:-0", "f:0.0"):
            return True
        # (2^32, the constant MSVC's x86 lowering of an unsigned to floating point conversion adds
        # where the value's top bit is set: no constant of the source, the x64 port converting
        # through 64 bits. 5 of a client's functions, 2026-10-30)
        if k == "f:4.29497e+09":
            return True
        # (-1.0 as a multiplier where the port flips the sign bit, `xorps` with -0.0's mask)
        if k == "f:-1" and ("f:-0" in have or "i:80000000" in have):
            return True
        if isinstance(k, int):
            # (a field: its offset in the translation's address arithmetic, `*(int *)(p + 8)`,
            # or an index scaled by its element, `param_1[3]` of an int *)
            if any(k % s == 0 and k // s in source for s in (1, 2, 4, 8)):
                return True
            # (or a record's field the decompiler addressed from a global, `&DAT_004040f2 + i * 0xc`
            # for the record at 0x4040e8's +0xa: the port uses the global G + k)
            ref_globals, port_globals = bases
            if any(g + k in port_globals for g in ref_globals):
                return True
            # (or a field of a member the reference's compiler addressed first, `lea ecx, [edi +
            # 0x3c]; mov esi, [ecx + 0x404]` for the translation's `this + 0x440` beside its
            # `this + 0x3c`: the formatting buffer's members in the CRT's printf, rhtest stl-O2)
            if any(s > k and s - k in source for s in source):
                return True
            # (the same with the C's indices as the offsets they are, an int array's [0x17] at 0x5c:
            # `lea esi, [ecx + 8]; ... mov eax, [esi + 0x54]` for `param_3[0x17]` beside its
            # `param_3 + 2`, a copy of a record's tail, 10 of a client's functions, 2026-10-30)
            scaled = {v * m for v in source if 0 < v < 0x10000 for m in (1, 2, 4, 8)}
            return any(0 < b < 0x1000 and b + k in scaled for b in scaled)
        if isinstance(k, str) and k.startswith("i:"):
            v = int(k[2:], 16)
            if v in source or (v + 1) & 0xFFFFFFFF in source or (v - 1) & 0xFFFFFFFF in source:
                return True
            # (or a subtraction at a word's or byte's width as its addition, `c - 0x27` of a
            # ushort as `add ecx, 0xffd9`, the CRT's hex digits in rhtest stl-O2)
            if any(v < (1 << w) and (-v) & ((1 << w) - 1) in source for w in (8, 16)):
                return True
            # (or a word's or byte's mask kept at 32 bits, its upper bits set: `and eax, 0xffff23ff`
            # for a ushort's `& 0x23ff`, the x87 control word's rounding cleared, rhtest stl-O2)
            if any(v >> w == (1 << (32 - w)) - 1 and v & ((1 << w) - 1) in source for w in (8, 16)):
                return True
            # (a division by a constant as the reference's compiler made it: its divisor's
            # reciprocal, and the signed one's `>> 31` correction, where the translation divides)
            if v == 0x1f and any(division_magic(m, source) for m in ref if isinstance(m, str) and m.startswith("i:")):
                return True
            if division_magic(k, source):
                return True
            # (a signed remainder by a power of two as the reference's compiler made it, `and edx,
            # 0x8000001f; jns; dec; or edx, -0x20; inc` for `x % 32`, which the decompiler folds to
            # `x & 0x1f` where the sign cannot matter (a shift's count): the mask, its sign bit
            # aside. The CRT's 80-bit helpers, __ZeroTail's, 85 of a client's functions, 2026-10-30)
            low = v & 0x7FFFFFFF
            if v & 0x80000000 and low and low & (low + 1) == 0 and (low in source or f"i:{low:x}" in have):
                return True
            # (characters stored together, `mov word ptr [ecx], 0x3649` for the C's `p[0] = 'I'; p[1]
            # = '6'`, the port pairing others, `movw $0x3436, 1(%rcx)`: each byte one the C stores.
            # A printf format's conversion, 2 of a client's)
            bs = v.to_bytes(4, "little").rstrip(b"\x00")
            if len(bs) >= 2 and all(0x20 <= c < 0x7F and c in source for c in bs):
                return True
            # (a mask before a left shift, its top bits the shift's to drop: the port's compiler sets
            # them where the reference's clears them, `and r8d, 0xd5555555; lea eax, [r8 + r8]` for
            # `and edx, 0x55555555; add eax, eax`, a Morton code's interleave, 4 of a client's)
            for p in have:
                if isinstance(p, str) and p.startswith("i:"):
                    pv = int(p[2:], 16)
                    for s in range(1, 5):
                        keep = (1 << (32 - s)) - 1
                        if pv != v and (pv ^ v) & keep == 0 and bin(v & keep).count("1") >= 8:
                            return True
            # (or shifted: a bitfield's store the decompiler folds, `(s * 0x3e8 & 0xffff) << 16` as
            # `s * 0x3e80000`, `(x & 0x7f) << 3` as `x & 0x3f8`, rhtest misc's bitfields)
            if any(((v << s) & 0xFFFFFFFF) in source for s in range(1, 32)):
                return True
            # (or a low-bit mask a shift makes redundant at a width: `x >> 16 & 0xffff` is `x >> 16`,
            # `(ushort)x >> 4 & 0xfff` the ushort's shift alone)
            n = (v + 1).bit_length() - 1
            if v and (v + 1) == 1 << n and any(0 < s < 32 and s + n in (8, 16, 32) for s in source):
                return True
            # (or the difference of two: a compare chain walks a switch's cases by subtracting
            # each from the next, `sub ecx, 0x5a` between case 10 and case 100)
            return any((v + s) & 0xFFFFFFFF in source for s in source if s < 0x10000)
        return False
    missing = sorted((k for k in ref if not kept(k)), key=str)
    return 1 - len(missing) / len(ref), missing


def division_magic(k: str, source: set[int]) -> bool:
    """Whether i:<v> is the multiplier a compiler divides by one of the source's constants with
    (v = ceil(2^(32+s) / d), signed or unsigned)."""
    v = int(k[2:], 16)
    if v < 0x10000:
        return False
    for d in source:
        if 2 < d < 0x100000:
            for s in range(0, 33):
                m = -(-(1 << (32 + s)) // d)
                if m & 0xFFFFFFFF == v or (m - (1 << 32)) & 0xFFFFFFFF == v:
                    return True
    return False


INT_LITERAL = re.compile(r"(?<![\w.])(-?)(0x[0-9a-fA-F]+|\d+)[uUlL]*(?![\w.])")


CHAR_LITERAL = re.compile(r"'(\\x[0-9a-fA-F]{1,2}|\\[0-7]{1,3}|\\.|[^'\\])'")
ESCAPES = {"n": 10, "t": 9, "r": 13, "0": 0, "\\": 92, "'": 39, '"': 34, "a": 7, "b": 8, "f": 12, "v": 11}


def literals(c: str) -> set[int]:
    """Every integer literal in a translation (and character literal), as 32 bits, negated and
    complemented too (`& ~0x40` is `and 0xffffffbf`)."""
    vals = []
    for _sign, num in INT_LITERAL.findall(c):
        vals.append(int(num, 0) if num.lower().startswith("0x") else int(num))
    for ch in CHAR_LITERAL.findall(c):
        if ch.startswith("\\x"):
            vals.append(int(ch[2:], 16))
        elif ch.startswith("\\") and ch[1:].isdigit():
            vals.append(int(ch[1:], 8))
        elif ch.startswith("\\"):
            vals.append(ESCAPES.get(ch[1], ord(ch[1])))
        else:
            vals.append(ord(ch))
    # (a narrowing cast is its mask to the other compiler: `(byte)a < (byte)b` as `and eax, 0xff`
    # at /Od, movzx in the port, rhtest stl-Od)
    if re.search(r"\((?:byte|uchar|char|undefined1|bool)\)", c):
        vals.append(0xFF)
    if re.search(r"\((?:ushort|short|word|undefined2|wchar_t)\)", c):
        vals.append(0xFFFF)
    out = set()
    # (and an 8-byte value's high word: `*(ulonglong *)(this + 0x18)` is the reference's [ecx +
    # 0x18] and [ecx + 0x1c], the port's one read through the address, rhtest stl-Od)
    if re.search(r"\b(?:u?longlong|double|undefined8|float10|__int64)\b", c):
        vals += [v + 4 for v in vals if 0 < v < 0x10000]
    for v in vals:
        out |= {v & 0xFFFFFFFF, (-v) & 0xFFFFFFFF, ~v & 0xFFFFFFFF}
        if v > 0xFFFFFFFF:
            # (a 64-bit constant is two to x86: `0x5851f42d4c957f2d` the push of each half)
            out |= {(v >> 32) & 0xFFFFFFFF, ((-v) >> 32) & 0xFFFFFFFF}
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--all", action="store_true", help="every function, lowest first")
    ap.add_argument("--show", nargs="*", default=[], help="these reference addresses in full")
    ap.add_argument("--limit", type=int, default=25)
    ap.add_argument("--html", action="store_true", help="also write build/fidelity.html")
    ap.add_argument("--html-only", action="store_true",
                    help="only build/fidelity.html, from the last build/fidelity.json (and bytes32.json)")
    ap.add_argument("--quiet", action="store_true", help="the totals only")
    ap.add_argument("--only", nargs="*", default=[], metavar="ADDR",
                    help="measure only these functions, merged into the last build/fidelity.json, each "
                         "printed with its score before and after: a fix's check in seconds, not the whole port")
    ap.add_argument("--low", action="store_true",
                    help="measure only the functions the last build/fidelity.json has below 1.0 or as stubs "
                         "(with --only's too), merged into it")
    ap.add_argument("--port", type=Path, help="the port to measure (default rhipper.json \"run\" \"exe\"): "
                                              "best one with its translation built /Od /Ob0")
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if args.html_only:
        write_html(json.loads(OUT_JSON.read_text(encoding="utf-8")))
        print(f"wrote {OUT_HTML}")
        return

    run_exe = args.port or project.CONFIG["run"].get("exe")
    if not run_exe:
        sys.exit("rhipper.json has no \"run\" \"exe\" (the port)")
    port_exe = ROOT / run_exe
    port_pdb = port_exe.with_suffix(".pdb")
    if not port_exe.exists() or not port_pdb.exists():
        sys.exit(f"no port at {port_exe} (and its .pdb)")
    F.PORT_EXE, F.PORT_PDB = port_exe, port_pdb

    refbin = Binary()
    ref = Image(project.EXE)
    # (and the imports by ordinal by the names Ghidra gives their slots, as translate32.py's
    # load_imports: `PTR_RemoveWindowSubclass_0107e020`, comctl32's subclassing, which the port
    # calls by name. Without, its thunk was no import and 9 of a client's input devices missed it)
    refdata = ROOT / "build/refdata.jsonl"
    if refdata.exists():
        with open(refdata, encoding="utf-8") as fh:
            for line in fh:
                if '"PTR_' not in line:
                    continue
                m = re.search(r'"name":"PTR_(\w+?)_([0-9a-f]{8})"', line)
                if m and not m.group(1).startswith(("Ordinal_", "DAT_", "FUN_")):
                    slot = int(m.group(2), 16)
                    ref.iat.setdefault(slot, m.group(1)) if slot in ref.ordinal_slots else None
    port = Image(port_exe)
    md32 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md64 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md32.detail = md64.detail = True
    cor = load_corpus()
    gen = Path(project.GEN)
    manifest = json.loads((gen / "manifest.json").read_text(encoding="utf-8"))
    stubbed = {int(a, 16): why for a, why in manifest.get("stubs", {}).items()}

    by_name = {e["name"]: a for a, e in cor.items()}
    # (and by the name less its namespaces, where one function has it)
    tails = Counter(e["name"].rsplit("::", 1)[-1] for e in cor.values())
    by_tail = {e["name"].rsplit("::", 1)[-1]: a for a, e in cor.items() if tails[e["name"].rsplit("::", 1)[-1]] == 1}
    # (each function's stack parameters, as the decompiler signed it: what a call's pushes past
    # them carry is read by nothing)
    arity = {a: n for a, e in cor.items() if e.get("c") and (n := stack_arity(e["c"])) is not None}
    # (and those whose signature takes ecx: `this`, __fastcall's first, a register input)
    takes_ecx = {a for a, e in cor.items()
                 if re.search(r"__thiscall|__fastcall|\bin_ecx\b|\bin_ECX\b|\bin_CL\b|\bin_cl\b",
                              re.sub(r"/\*.*?\*/", "", e.get("c", ""), flags=re.S).split("{", 1)[0])
                 or not e.get("c")}

    def injections(c: str) -> set:
        """The callees the decompiler replaced with p-code (call fixups) in a function, by the
        warnings it leaves: a function's address, a thunk's target (`thunk_FUN_00402350`, which
        the reference's call reaches through), or an import (`imp:libm_sse2_sqrt_precise`)."""
        out = set()
        for n in re.findall(r"Function: (\S+) replaced with injection", c):
            t = n[len("thunk_"):] if n.startswith("thunk_") else n
            if t in by_name:
                out.add(by_name[t])
            # (or named in a namespace the warning leaves out: `__ftol2` is Global::__ftol2, and
            # its call was counted missing in 23 of a client's functions, __CIfmod's in 9, 2026-10-30)
            elif t in by_tail:
                out.add(by_tail[t])
            elif re.fullmatch(r"FUN_[0-9a-f]{8}", t):
                out.add(int(t[4:], 16))
            else:
                out.add("imp:" + t.lstrip("_"))
        return out
    # the functions the decompiler injects as p-code (call fixups), by the warnings it leaves
    # (one the decompiler failed on has an "error" and no C: none injected there)
    fixed_up = {x for e in cor.values() for x in injections(e.get("c", "")) if isinstance(x, int)}
    # (where the static libraries' code starts, the C runtime's names, translate32's is_library: a
    # program function's piece beyond it is a runtime helper's tail the decompiler took in, `jmp
    # __dtoul3`, whose dispatch it models as the operation (its feature test `test [__isa], 0x20`
    # and tables no constants of the function's), rhtest float-O2 d2ul)
    crt = re.compile(r"^_{1,3}(?:security_check_cookie|scrt_|except_handler|report_gsfailure|"
                     r"aull|alldiv|allmul|allrem|allshl|allshr|aullshr|ftol|chkstk|EH_prolog|SEH_prolog|"
                     r"SEH_epilog|CRT_|crt|onexit|initterm|guard_)")
    library_from = min([a for a, e in cor.items() if crt.match(e.get("name", ""))] or [1 << 32])

    def own_pieces(a: int, ps: list) -> list:
        """a function's pieces, a program function's without those in the libraries' code"""
        if a >= library_from:
            return ps
        return [p for p in ps if p[0] < library_from] or ps
    # each translation's C, by its reference address (gen/translated_*.c, `/* ref: */` headed)
    translations: dict[int, str] = {}
    for path in sorted(gen.glob("translated_*.c")):
        text = path.read_text(encoding="utf-8")
        for m in re.finditer(r"/\* ref: [^\n]*\*/\n[^\n]*\bF_([0-9a-f]{8})\(.*?\n}\n", text, re.S):
            translations[int(m.group(1), 16)] = re.sub(r"GEN_ENTER\([^;]*\);", "", m.group(0))
    procs, inline_sites = F.load_pdb(port)
    proc_at = {va: (size, name) for va, size, name in procs}
    # (the import adapters the linker folded into one, identical code at one address (/OPT:ICF):
    # gen_imp_DecodePointer and gen_imp_EncodePointer, both `return p`, named after one of them,
    # so every call of the other read as a different import. 27 of a client's C runtime
    # functions missed DecodePointer or EncodePointer, 2026-10-30)
    # (the publics have every name, the module's procedures the folded one alone: with Ghidra32.h's
    # gen_top_i, `return (uintptr_t)(unsigned)x`, the same code, the procedure was gen_top_i and
    # the call no import's at all)
    pe = pefile.PE(str(port_exe), fast_load=True)
    names_at: dict[int, set] = {}
    for m in re.finditer(r"`(gen_imp_\w+)`\s*\n\s*flags = function, addr = (\d+):(\d+)", F.pdbutil("-publics")):
        seg, off = int(m.group(2)), int(m.group(3))
        if 0 < seg <= len(pe.sections):
            va = pe.OPTIONAL_HEADER.ImageBase + pe.sections[seg - 1].VirtualAddress + off
            names_at.setdefault(va, set()).add("imp:" + m.group(1)[len("gen_imp_"):].lstrip("_"))
    folded = {n: group for group in names_at.values() if len(group) > 1 for n in group}
    # (an adapter's address named for another function: by the adapter's name)
    for va, group in names_at.items():
        if va in proc_at and not proc_at[va][1].startswith("gen_imp_"):
            proc_at[va] = (proc_at[va][0], "gen_imp_" + sorted(group)[0][len("imp:"):])
    f_of_ref = {}
    for va, size, name in procs:
        m = re.fullmatch(r"F_([0-9a-f]{8})", name)
        if m:
            f_of_ref[int(m.group(1), 16)] = va

    # the reference's import thunks (`jmp [slot]`) by name
    ref_thunk = {}
    for root in refbin.func_starts:
        code = ref.read(root, 6)
        if code[:2] == b"\xff\x25":
            slot = int.from_bytes(code[2:6], "little")
            if slot in ref.iat:
                ref_thunk[root] = "imp:" + ref.iat[slot]
    pieces: dict[int, list] = {}
    for lo, hi, root in zip(refbin.piece_starts, refbin.piece_ends, refbin.piece_root):
        pieces.setdefault(root, []).append((lo, hi))

    entries = set(refbin.func_starts)

    def slot_thunk(t: int, code: bytes) -> int | None:
        """the function a `jmp [slot]` thunk reaches through a data word of the image's own, not an
        import's, holding a function's entry: the CFG check's `jmp [__guard_check_icall_fptr]`,
        whose slot is the no-op check the decompiler (and the port) calls, rhtest stl"""
        if code[:2] != b"\xff\x25":
            return None
        slot = int.from_bytes(code[2:6], "little")
        if slot in ref.iat or not ref.contains(slot):
            return None
        target = int.from_bytes(ref.read(slot, 4), "little")
        return target if target in entries and target != t else None

    def ref_calls(fn: Fn) -> list:
        out = []
        for _site, t in fn.calls:
            if isinstance(t, tuple):
                # (a jump to an import's thunk is a call of the import, a function Ghidra made of
                # the thunk or not: the C++ EH handler thunks' `jmp __CxxFrameHandler3`)
                code = ref.read(t[1], 6)
                if t[1] not in entries and not (code[:2] == b"\xff\x25"
                                                and int.from_bytes(code[2:6], "little") in ref.iat):
                    continue
                # (nor one into a piece of another function's, code the two share: an EH funclet's
                # `jmp` to its parent's epilogue, which the decompiler follows, eh-Od)
                root = refbin.func_containing(t[1])
                if root is not None and root != t[1] and code[:2] != b"\xff\x25":
                    continue
                t = t[1]
                if t not in ref_thunk and code[:2] == b"\xff\x25":
                    t = "imp:" + ref.iat[int.from_bytes(code[2:6], "little")]
            if isinstance(t, int):
                # (through local `jmp rel32` thunks: translate32.py calls their targets)
                for _ in range(4):
                    code = ref.read(t, 6)
                    nt = slot_thunk(t, code)
                    if nt is not None:
                        t = nt
                        continue
                    if t in ref_thunk or len(code) < 5 or code[0] != 0xE9:
                        break
                    t = (t + 5 + int.from_bytes(code[1:5], "little", signed=True)) & 0xFFFFFFFF
                t = ref_thunk.get(t, t)
                # (or a thunk of a table of them no function starts at, `jmp [slot]` every six
                # bytes, comctl32's RemoveWindowSubclass at 0xc8e972: the import, by its bytes,
                # not the function the table falls inside. 9 of a client's input devices)
                if isinstance(t, int):
                    tc = ref.read(t, 6)
                    if len(tc) == 6 and tc[:2] == b"\xff\x25" and int.from_bytes(tc[2:6], "little") in ref.iat:
                        t = "imp:" + ref.iat[int.from_bytes(tc[2:6], "little")]
                if isinstance(t, int):
                    root = refbin.func_containing(t)
                    t = root if root is not None else t
            out.append(t)
        return out

    def through_thunks(t: int) -> int:
        """a reference function by way of its local `jmp rel32` thunks (an unwind funclet's `jmp
        0x409770` to `jmp 0x409320`, the translation calling F_00409770: as the reference's
        ref_calls counts it, rhtest stl-O2)"""
        for _ in range(4):
            code = ref.read(t, 6)
            nt = slot_thunk(t, code)
            if nt is not None:
                t = nt
                continue
            if t in ref_thunk or len(code) < 5 or code[0] != 0xE9 or t not in entries:
                break
            t = (t + 5 + int.from_bytes(code[1:5], "little", signed=True)) & 0xFFFFFFFF
        return t

    def port_calls(va: int, fn: Fn) -> list:
        out = port_calls_raw(va, fn)
        return [through_thunks(t) if isinstance(t, int) else t for t in out]

    def port_calls_raw(va: int, fn: Fn) -> list:
        events = [(site, t) for site, t in fn.calls]
        events += [(site, ("inline", name)) for site, name in inline_sites.get(va, [])]
        events.sort(key=lambda e: e[0])
        out = []
        for _site, t in events:
            if isinstance(t, tuple) and t[0] == "addr":
                name = proc_at.get(t[1], (0, ""))[1]
                if name in TRAPS:
                    out.append(TRAPS[name])
                continue
            if isinstance(t, tuple) and t[0] == "jump":
                t = t[1]
            elif isinstance(t, tuple):
                m = re.fullmatch(r"F_([0-9a-f]{8})", t[1])
                if m:
                    out.append(int(m.group(1), 16))
                continue
            if isinstance(t, str):
                out.append(t)
                continue
            name = proc_at.get(t, (0, ""))[1]
            m = re.fullmatch(r"F_([0-9a-f]{8})", name)
            if m:
                out.append(int(m.group(1), 16))
            elif name.startswith("gen_imp_"):
                out.append("imp:" + name[len("gen_imp_"):].lstrip("_"))
            elif name.lstrip("_") in PORT_JUMPS:
                out.append(PORT_JUMPS[name.lstrip("_")])
            elif name in TRAPS:
                out.append(TRAPS[name])
            elif not name:
                # (an import's thunk, `jmp [rip + x]`, the CRT DLL's: by its slot's name)
                code = port.read(t, 6)
                if code[:2] == b"\xff\x25":
                    imp = port.iat.get(t + 6 + int.from_bytes(code[2:6], "little", signed=True), "")
                    if imp in PORT_JUMPS:
                        out.append(PORT_JUMPS[imp])
            # (anything else is the runtime's own: tracing, the TEB, locks, the stub logger)
        return out

    # the /GS cookie: the global __security_check_cookie compares with
    cookies = set()
    for a, e in cor.items():
        if e["name"].lstrip("_@") .startswith("security_check_cookie"):
            fn = scan(ref, ref, md32, sorted(pieces.get(a, [(a, a + e.get("size", 0))])), a, False)
            cookies |= {int(k[2:], 16) for k in fn.consts if k.startswith("g:")}

    callee_cache: dict[int, list] = {}

    def callees_of(c: int) -> list:
        """the reference function's own calls, as ref_calls counts them"""
        if c not in callee_cache:
            ec = cor[c]
            try:
                fc = scan(ref, ref, md32, own_pieces(c, sorted(pieces.get(c, [(c, c + ec.get("size", 0))]))), c, False,
                          set(), fixed_up)
                callee_cache[c] = [x for x in ref_calls(fc) if x not in injections(ec["c"])]
            except Exception:
                callee_cache[c] = []
        return callee_cache[c]

    def label(x) -> str:
        if isinstance(x, str):
            return x
        e = cor.get(x)
        return f"{x:08x} {e['name']}" if e else f"{x:08x}"

    # (a subset: --only's functions and --low's, measured alone and merged into the last report)
    subset, previous = None, {}
    if args.only or args.low:
        if OUT_JSON.exists():
            previous = {int(r["addr"], 16): r for r in json.loads(OUT_JSON.read_text(encoding="utf-8"))}
        subset = {int(x.lower().removeprefix("0x").removeprefix("fun_").removeprefix("f_"), 16) for x in args.only}
        if args.low:
            subset |= {a for a, r in previous.items() if r.get("kind") == "stub" or (r.get("score") or 0) < 0.999}
        print(f"measuring {len(subset)} functions", flush=True)

    rows = []
    for a in sorted(cor):
        if subset is not None and a not in subset:
            continue
        e = cor[a]
        size = e.get("size", 0)
        row = {"addr": f"{a:08x}", "name": e["name"], "size": size}
        if a in fixed_up:
            # (a helper the decompiler injects at every call, ApplyFacts' call fixups: its p-code
            # is its translation, wherever it is called; its own body never runs)
            row.update(kind="folded", score=1.0, why="injected at every call site (a call fixup)")
            rows.append(row)
            continue
        if a in stubbed or a not in f_of_ref:
            row.update(kind="stub", score=0.0, why=stubbed.get(a, "not in the port"))
            rows.append(row)
            continue
        # (a function the decompiler proved does nothing, its blocks unreachable and its body
        # empty, __RTC_Initialize's loop over an empty table: its translation does nothing too)
        body = e["c"].partition("{")[2]
        if "Removing unreachable block" in e["c"] and \
                not re.sub(r"\breturn\s*;|[{}\s]|/\*.*?\*/", "", body, flags=re.S):
            row.update(kind="folded", score=1.0, why="the decompiler proved it does nothing (unreachable blocks removed)")
            rows.append(row)
            continue
        dead = {int(x, 16) for x in re.findall(r"Removing unreachable block \(ram,0x([0-9a-f]+)\)", e["c"])}
        rf = scan(ref, ref, md32, own_pieces(a, sorted(pieces.get(a, [(a, a + size)]))), a, False, dead, fixed_up,
                  arity, takes_ecx)
        pva = f_of_ref[a]
        psize = proc_at[pva][0]
        pf = scan(port, ref, md64, [(pva, pva + psize)], a, True)
        # (a call Ghidra replaced with an injection, the stack cookie check, is in no translation)
        injected = injections(e["c"])
        rseq = [x for x in ref_calls(rf) if x not in injected]
        pseq = port_calls(pva, pf)
        # (a folded adapter's call as the name the reference calls among those it stands for)
        # (dealt out by what the reference calls of each: a function calling both DecodePointer and
        # EncodePointer, two calls of one folded address, has one of each)
        if folded and any(x in folded for x in pseq):
            want = Counter(x for x in rseq if x in folded)
            mapped = []
            for x in pseq:
                if x in folded:
                    pick = max(sorted(folded[x]), key=lambda n: want[n])
                    if want[pick] > 0:
                        want[pick] -= 1
                        x = pick
                mapped.append(x)
            pseq = mapped
        # (a callee the port does not call whose own calls it makes instead: inlined, the decompiler
        # following a conditional tail jump into it, `je abort` in the C runtime's __vcrt_getptd,
        # abort's body printed in its caller's. The same behavior; its calls stand for it)
        have = set(pseq)
        for c in [x for x in dict.fromkeys(rseq) if isinstance(x, int) and x not in have and x in cor]:
            inner = callees_of(c)
            if inner and set(inner) <= have | {c}:
                rseq = [y for x in rseq for y in (inner if x == c else [x])]
        # (a callee the translation calls that its compiler proved unreachable: vector's `if
        # (size == 0xaaaaaaa) _Xlength()` of a signed difference divided by 0x18, which can never
        # reach it, gone from the x64 build and kept by the reference's, rhtest stl-O2)
        src = translations.get(a, "")
        for c in [x for x in dict.fromkeys(rseq) if isinstance(x, int) and x not in have]:
            if re.search(rf"\bF_{c:08x}\s*\(", src):
                pseq.append(c)
                # (and the strings it is passed, gone with it: `F_00c457e7("invalid vector<T>
                # subscript")` under `if (n == 0)` inside `if (n != 0)`, 2 of a client's)
                for line in re.findall(rf"\bF_{c:08x}\s*\(.*", src):
                    for lit in re.findall(r'"((?:[^"\\]|\\.)*)"', line):
                        if f"s:{lit}" in rf.consts and f"s:{lit}" not in pf.consts:
                            del rf.consts[f"s:{lit}"]
        # (by which callees, not in what order: the order is each compiler's block layout, a cold
        # path's call last in one and first in the other, and two calls of one function in two
        # branches one call to a compiler that merges them)
        calls, missing_calls = presence(Counter(rseq), Counter(pseq))
        if re.search(r"replaced with injection: (?:rh_)?security_check_cookie", e["c"]):
            # (and the cookie the injected check compares with, read in the prologue)
            for g in cookies:
                rf.consts.pop(f"g:{g:x}", None)
        # (a float constant one side loads as a float and the other moves as bits, `movsd xmm0,
        # [0x404288]` and `mov rax, [0x404288]` into a select: the same constant, by its address)
        # (on both sides alike: one read as a float and its address pushed besides, `push 0x453c58`
        # for a callee, left the reference's g: unmatched by the port's, converted, rhtest stl-O2)
        floats = {**pf.float_at, **rf.float_at}
        for v, k in floats.items():
            g = f"g:{v:x}"
            for side in (rf, pf):
                if g in side.consts:
                    side.consts[k] += side.consts.pop(g)
        # (a 16-byte constant one side reads whole, `movaps xmm0, [0x404290]` for two doubles of
        # an array it fills, and the other a lane at a time: the same constant, by a lane's value)
        for v in rf.packed:
            g = f"g:{v:x}"
            data = ref.read(v, 16)
            lanes = {F.float_text(data[i:i + 8]) for i in (0, 8)} | {F.float_text(data[i:i + 4]) for i in (0, 4, 8, 12)}
            # (or integer lanes, `movaps xmm2, [0x4033f0]` of four multipliers the port uses one by one)
            lanes |= {f"i:{int.from_bytes(data[i:i + 4], 'little'):x}" for i in (0, 4, 8, 12)}
            hit = next((k for k in sorted(lanes) if k in pf.consts), None)
            if g in rf.consts and g not in pf.consts and hit:
                rf.consts[hit] += rf.consts.pop(g)
        # (and a float the reference stores as its bits, `mov [esp + 0x20], 0x3dcccccd`, that the
        # port loads as the float: 0.1f, by its value)
        for k in [k for k in rf.consts if k.startswith("i:") and k not in pf.consts]:
            v = int(k[2:], 16)
            fk = F.float_text(v.to_bytes(4, "little"))
            if v > 0xFFFF and fk in pf.consts:
                rf.consts[fk] += rf.consts.pop(k)
        source = literals(translations.get(a, ""))
        # (an empty string the reference passes by its address, `push 0x109cfce` of a byte 0 in
        # .rdata, which the translation passes as its own `""`: a string by its value, as others.
        # 15 of a client's string initializations, 2026-10-30)
        # (a float constant the reference loads from an address the translation names, `REFG(..,
        # 0x1097254)` for -1.0, that the port's compiler dropped as dead: kept, as a global the C
        # names is. 5 of a client's sound obstruction methods, 2026-10-30)
        for v, k in rf.float_at.items():
            if v in source and k in rf.consts and k not in pf.consts:
                del rf.consts[k]
        if '""' in translations.get(a, ""):
            for k in [k for k in rf.consts if k.startswith("g:")]:
                if ref.read(int(k[2:], 16), 1) == b"\x00" and k not in pf.consts:
                    del rf.consts[k]
        # (a pointer's step back, `sub edx, 0x10` of a loop over 16-byte records, that the port
        # folds into its accesses, `mov eax, [rcx - 0x10]`: the C's `p - 4` of an int pointer)
        for k in [k for k in rf.consts if k.startswith("i:") and k not in pf.consts]:
            v = int(k[2:], 16)
            if v in pf.negdisp and any(v % s == 0 and v // s in source for s in (1, 2, 4, 8)):
                del rf.consts[k]
                continue
            # (or a pointer's step the port unrolled away, `sub esi, 0x70` for the C's `p + -0x1c`
            # of a 4-byte pointer: a destructor's loop over two members, 2 of a client's)
            if k in rf.steps and v < 0x10000 and any(v % s == 0 and v // s in source for s in (2, 4, 8)):
                del rf.consts[k]
                continue
            # (one bit cleared, `and ebx, 0xfffffdff`, that the port clears with `btr` or a byte's
            # `and byte ptr [r + 1], 0xfd`: a flag word's bits, 5 in one of a client's functions)
            bit = (~v & 0xFFFFFFFF)
            if bit and bit & (bit - 1) == 0:
                b = bit.bit_length() - 1
                if "btr" in pf.mnemonics or f"i:{~(1 << (b % 8)) & 0xFF:x}" in pf.consts \
                        or f"i:{~(1 << (b % 16)) & 0xFFFF:x}" in pf.consts:
                    del rf.consts[k]
        # (a wide string the reference's address reads as one character, `push 0x1118b18` for
        # L"?*", the port's literal its own: by the text, _wstat's wildcard check)
        # (a float table read through an index the port's compiler made a constant: its element's
        # value loaded as a constant, `fld [esi + 0x10a6b78]` for the port's 0.307173. 2 of a
        # client's camera presets)
        port_floats = {k for k in pf.consts if k.startswith("f:")}
        for k in [k for k in rf.consts if k.startswith("a:") and k not in pf.consts]:
            v = int(k[2:], 16)
            if port_floats and any(F.float_text(ref.read(v + d, 4)) in port_floats or
                                   F.float_text(ref.read(v + d, 8)) in port_floats
                                   for d in range(0, 0x400, 4)):
                del rf.consts[k]
        # (too short for a string key on either side: its literal in the translation's source)
        src_text = translations.get(a, "")
        for k in [k for k in rf.consts if k.startswith("g:") and k not in pf.consts]:
            raw = ref.read(int(k[2:], 16), 16)
            wide = raw.decode("utf-16-le", "replace").split("\0")[0]
            narrow = raw.split(b"\0")[0].decode("latin-1")
            for w, lit in ((wide, f'L"{wide}"'), (narrow, f'"{narrow}"')):
                if w and w.isprintable() and (f"s:{w}" in pf.consts or lit in src_text):
                    del rf.consts[k]
                    break
        # (a field of a member addressed by an indexed lea, `lea edi, [eax + ecx + 0x1c4]; cmp
        # [edi + 0x58], 0` for the C's `this + i * 0xb4 + 0x21c`, 4 of a client's)
        for d in [d for d in rf.fields if d not in pf.fields and d in rf.member_at]:
            if rf.member_at[d] & set(source):
                del rf.fields[d]
        globals_of = (lambda fn: {int(k[2:], 16) for k in fn.consts if k.startswith("g:")})
        fields, missing_fields = presence(rf.fields, pf.fields, source, (globals_of(rf), globals_of(pf)))
        port_addrs = globals_of(pf) | {x for xs in pf.str_at.values() for x in xs} \
            | {int(k[2:], 16) for k in pf.consts if k.startswith("a:")}
        # (an immediate, or a displacement from a register holding the other: `lea rcx, [rax + 0x50]`)
        port_ints = {int(k[2:], 16) for k in pf.consts if k.startswith("i:")} | set(pf.fields) | pf.imms
        consts, missing_consts = presence(rf.consts, pf.consts, source, moved=(rf.str_at, port_addrs, port_ints))
        parts = {
            "calls": calls,
            "fields": fields,
            "consts": consts,
            "shape": F.trigram_score(rf.mnemonics, pf.mnemonics),
        }
        avail = {k: v for k, v in parts.items() if v is not None and F.WEIGHTS[k] > 0}
        score = sum(F.WEIGHTS[k] * v for k, v in avail.items()) / sum(F.WEIGHTS[k] for k in avail) if avail else 1.0
        row.update(kind="translated", score=round(score, 4), parts={k: (round(v, 4) if v is not None else None)
                                                                     for k, v in parts.items()},
                   missing_calls=[label(x) for x in missing_calls],
                   extra_calls=[label(x) for x in sorted(set(pseq) - set(rseq), key=str)],
                   missing_fields=[f"{k:#x}" for k in missing_fields],
                   missing_consts=missing_consts,
                   extra_consts=sorted(k for k in pf.consts if not near(k, set(rf.consts))))
        rows.append(row)
        if f"{a:08x}" in {s.lower().removeprefix("0x").rjust(8, "0") for s in args.show}:
            print(f"==== {a:08x} {e['name']}  score {score:.3f}  {row['parts']}")
            print(f"  reference calls: {[label(x) for x in rseq]}")
            print(f"  port calls:      {[label(x) for x in pseq]}")
            for k in ("missing_calls", "extra_calls", "missing_fields", "missing_consts", "extra_consts"):
                if row[k]:
                    print(f"  {k}: {row[k]}")

    if subset is not None:
        # (each measured function against its last score, then the whole report again, merged)
        moved = 0
        for r in rows:
            before = previous.get(int(r["addr"], 16), {}).get("score")
            if before is None or abs(before - r["score"]) > 0.0005:
                moved += 1
            if args.only or before is None or abs(before - r["score"]) > 0.0005:
                b = "-" if before is None else f"{before:.3f}"
                why = r.get("why") or "; ".join(f"{k.replace('_', ' ')} {r[k][:3]}" for k in
                                                 ("missing_calls", "extra_calls", "missing_fields", "missing_consts")
                                                 if r.get(k))
                print(f"  {r['addr']}  {b} -> {r['score']:.3f}  {r['name'][:32]:<32} {why[:110]}")
        print(f"{len(rows)} measured, {moved} changed")
        merged = dict(previous)
        merged.update({int(r["addr"], 16): r for r in rows})
        rows = [merged[a] for a in sorted(merged)]
    OUT_JSON.write_text(json.dumps(rows, indent=1), encoding="utf-8")
    scored = [r for r in rows if r["kind"] != "stub"]
    stubs = [r for r in rows if r["kind"] == "stub"]
    total_size = sum(r["size"] for r in rows) or 1
    mean = sum(r["score"] for r in rows) / len(rows) if rows else 0.0
    weighted = sum(r["score"] * r["size"] for r in rows) / total_size
    perfect = sum(r["score"] >= 0.999 for r in scored)
    print(f"{project.NAME}: {len(rows)} functions, {len(scored)} translated ({perfect} at 1.0), {len(stubs)} stubs; "
          f"mean {mean:.3f}, by size {weighted:.3f}")
    if not args.quiet:
        low = sorted((r for r in rows if r["score"] < 0.999), key=lambda r: (r["score"], -r["size"]))
        for r in low if args.all else low[:args.limit]:
            if r["kind"] == "stub":
                print(f"  {r['addr']}  stub   {r['name'][:28]:<28} {r['why'][:70]}")
                continue
            p = r["parts"]
            ps = " ".join(f"{k}={p[k]:.2f}" if p[k] is not None else f"{k}=-" for k in ("calls", "fields", "consts"))
            what = "; ".join(f"{k.replace('_', ' ')} {r[k][:3]}" for k in ("missing_calls", "missing_fields", "missing_consts")
                             if r[k])
            print(f"  {r['addr']}  {r['score']:.3f}  {r['name'][:28]:<28} {ps}  {what[:110]}")
    if args.html:
        write_html(rows)
        print(f"wrote {OUT_HTML}")


def write_html(rows: list) -> None:
    """build/fidelity.html from the rows (and build/bytes32.json beside them): fidelity_html.py"""
    import fidelity_html
    OUT_HTML.write_text(fidelity_html.page(project.NAME, rows, ROOT / "build/bytes32.json"), encoding="utf-8")


if __name__ == "__main__":
    main()
