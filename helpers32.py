"""The compiler's helper routines in a 32-bit image, identified by running them:
build/facts/helpers32.json.

MSVC's x86 code calls small CRT routines for what the instruction set lacks: 64-bit multiply,
divide, remainder and shifts (__allmul, __alldiv, __alldvrm, __allshl, ...) and the conversions
between floats and 64-bit integers (__dtol3, __dtoul3, __ltod3, __ultod3, _ftol2, _ftoul2, ...).
Each has a convention of its own: values in edx:eax, xmm0 or st0, a count in cl, the callee
popping 16 bytes, __alldvrm's remainder in ebx:ecx. ApplyFacts gives each a call fixup, so
callers decompile to the operation itself; this finds them where Ghidra's function ID did not
name them (the SSE2 conversions of a recent CRT, rhtest float 2026-10-24).

A candidate (by its protos32.py shape: register inputs, stack cleanup) is run under Unicorn with
each helper's convention on a few values, and is that helper if every result matches.

    python helpers32.py
"""
from __future__ import annotations

import json
import math
import struct
import sys

from unicorn import UC_ARCH_X86, UC_MODE_32, Uc, UcError
from unicorn.x86_const import (
    UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_ESP, UC_X86_REG_XMM0,
)

from pebin import FACTS, Binary, hexa, write_facts

STACK, STACK_SIZE = 0x0F000000, 0x100000
STUB = 0x0E000000
RETURN = STUB + 0x800
DATA = STUB + 0xC00
M64 = (1 << 64) - 1


def f64(v: float) -> int:
    return struct.unpack("<Q", struct.pack("<d", v))[0]


def s64(v: int) -> int:
    v &= M64
    return v - (1 << 64) if v >> 63 else v


def trunc_div(a: int, b: int) -> int:
    q = abs(a) // abs(b)
    return q if (a < 0) == (b < 0) else -q


def trunc_rem(a: int, b: int) -> int:
    return a - trunc_div(a, b) * b


PAIRS = [(0x123456789ABCDEF, 0x10001), (-0x7654321FEDCBA9, 0x3E8), (0x7FFFFFFFFFFFFFFF, -3),
         (-1000000000000, -77777)]
SHIFTS = [(0x8123456789ABCDEF, 4), (0x8123456789ABCDEF, 36), (0x0000000100000001, 63), (0x8000000000000000, 1)]
DOUBLES = [1.5, -2.75, 1.0e15 + 0.5, -3.0e18, 123456789.9]
UDOUBLES = [1.5, 3.0e18, 1.8e19, 0.99, 9.3e18]
INTS = [-5, (1 << 40) + 7, -(1 << 62) + 3, 12345]
UINTS = [(1 << 63) + (1 << 20), 5, (1 << 64) - (1 << 12), (1 << 53) + 1]

# name -> (shape, cases: [(inputs, expected outputs)])
SPECS: dict[str, tuple[str, list]] = {
    # (divide-with-remainder first: its quotient in edx:eax matches the plain divide too)
    "alldvrm": ("stack16", [((a, b), {"edx:eax": trunc_div(a, b), "ebx:ecx": trunc_rem(a, b)}) for a, b in PAIRS]),
    "aulldvrm": ("stack16", [((a, b), {"edx:eax": (a & M64) // (b & M64), "ebx:ecx": (a & M64) % (b & M64)})
                             for a, b in PAIRS]),
    "allmul": ("stack16", [((a, b), {"edx:eax": a * b}) for a, b in PAIRS]),
    "alldiv": ("stack16", [((a, b), {"edx:eax": trunc_div(a, b)}) for a, b in PAIRS]),
    "allrem": ("stack16", [((a, b), {"edx:eax": trunc_rem(a, b)}) for a, b in PAIRS]),
    "aulldiv": ("stack16", [((a, b), {"edx:eax": (a & M64) // (b & M64)}) for a, b in PAIRS]),
    "aullrem": ("stack16", [((a, b), {"edx:eax": (a & M64) % (b & M64)}) for a, b in PAIRS]),
    "allshl": ("shift", [((v, n), {"edx:eax": v << n}) for v, n in SHIFTS]),
    "allshr": ("shift", [((v, n), {"edx:eax": s64(v) >> n}) for v, n in SHIFTS]),
    "aullshr": ("shift", [((v, n), {"edx:eax": (v & M64) >> n}) for v, n in SHIFTS]),
    # (the unsigned conversions first: their values past 2^63 tell them from the signed ones, which
    # a legacy unsigned one also matches on the signed cases)
    "dtoul3": ("xmm0", [((d,), {"edx:eax": int(d)}) for d in UDOUBLES]),
    "dtol3": ("xmm0", [((d,), {"edx:eax": int(d)}) for d in DOUBLES]),
    # (the 64-bit integer in edx:ecx, the low half in ecx: __ltod3's `movd xmm0, ecx`)
    "ultod3": ("edx:ecx", [((u,), {"xmm0": f64(float(u))}) for u in UINTS]),
    "ltod3": ("edx:ecx", [((i,), {"xmm0": f64(float(i))}) for i in INTS]),
    "ftoul2": ("st0", [((d,), {"edx:eax": int(d)}) for d in UDOUBLES]),
    "ftol2": ("st0", [((d,), {"edx:eax": int(d)}) for d in DOUBLES]),
    # (__ftoi2, and __ftol2_sse jumping to it: an int in eax alone, `fisttp dword ptr [esp]`)
    "ftoi2": ("st0", [((d,), {"eax": int(d) & 0xFFFFFFFF}) for d in (1.5, -2.75, 123456.9, -2000000000.5)]),
}


class Runner:
    def __init__(self, b: Binary):
        self.b = b
        self.uc = uc = Uc(UC_ARCH_X86, UC_MODE_32)
        size = (len(b.image) + 0xFFF) & ~0xFFF
        uc.mem_map(b.base, size)
        uc.mem_write(b.base, bytes(b.image))
        uc.mem_map(STACK, STACK_SIZE)
        uc.mem_map(STUB, 0x1000)
        uc.mem_write(RETURN, b"\xf4")
        self.image = bytes(b.image)

    def run(self, entry: int, shape: str, inputs: tuple) -> dict | None:
        uc = self.uc
        uc.mem_write(self.b.base, self.image)          # (a clean image each time: globals)
        esp = STACK + STACK_SIZE - 0x100
        for r in (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX):
            uc.reg_write(r, 0)
        start = entry
        if shape == "stack16":
            a, b = inputs[0] & M64, inputs[1] & M64
            for word in (b >> 32, b & 0xFFFFFFFF, a >> 32, a & 0xFFFFFFFF):
                esp -= 4
                uc.mem_write(esp, struct.pack("<I", word))
        elif shape == "shift":
            v, n = inputs[0] & M64, inputs[1]
            uc.reg_write(UC_X86_REG_EAX, v & 0xFFFFFFFF)
            uc.reg_write(UC_X86_REG_EDX, v >> 32)
            uc.reg_write(UC_X86_REG_ECX, n)
        elif shape == "edx:ecx":
            v = inputs[0] & M64
            uc.reg_write(UC_X86_REG_ECX, v & 0xFFFFFFFF)
            uc.reg_write(UC_X86_REG_EDX, v >> 32)
        elif shape == "xmm0":
            uc.reg_write(UC_X86_REG_XMM0, f64(inputs[0]))
        elif shape == "st0":
            # (a stub loads st0 and calls: fld qword [DATA]; call entry; hlt)
            uc.mem_write(DATA, struct.pack("<d", inputs[0]))
            code = b"\xdd\x05" + struct.pack("<I", DATA)
            call_at = STUB + len(code)
            code += b"\xe8" + struct.pack("<i", entry - (call_at + 5)) + b"\xf4"
            uc.mem_write(STUB, code)
            start = STUB
        if shape != "st0":
            esp -= 4
            uc.mem_write(esp, struct.pack("<I", RETURN))
        uc.reg_write(UC_X86_REG_ESP, esp)
        try:
            uc.emu_start(start, RETURN if shape != "st0" else STUB + len(code) - 1, count=20000)
        except UcError:
            return None
        eax, edx = uc.reg_read(UC_X86_REG_EAX), uc.reg_read(UC_X86_REG_EDX)
        ebx, ecx = uc.reg_read(UC_X86_REG_EBX), uc.reg_read(UC_X86_REG_ECX)
        return {"eax": eax, "edx:eax": (edx << 32) | eax, "ebx:ecx": (ebx << 32) | ecx,
                "xmm0": uc.reg_read(UC_X86_REG_XMM0) & M64}


def shape_of(e: dict) -> set[str]:
    """The helper shapes a function's protos32.py facts allow."""
    regs = set(e.get("regs", []))
    out = set()
    if e.get("stack") == 16 and e.get("cc") in ("__stdcall", "custom"):
        out.add("stack16")
    if e.get("stack", 0) == 0:
        if {"eax", "edx"} <= regs and ("cl" in regs or "ecx" in regs):
            out.add("shift")
        if {"ecx", "edx"} <= regs or e.get("cc") == "__fastcall":
            out.add("edx:ecx")
        if "xmm0" in regs:
            out.add("xmm0")
        if "st0" in regs:
            out.add("st0")
        # (one that shows no inputs may hand them on through a jump, `__ftoul2: jmp
        # __ftoul2_legacy` past a check: the register shapes, for a small one, cost little)
        if not regs and not e.get("params"):
            out |= {"st0", "xmm0", "edx:ecx"}
    return out


def main() -> None:
    b = Binary()
    protos = json.loads((FACTS / "protos.json").read_text())["functions"]
    sizes = {int(f["entry"], 16): sum(int(hi, 16) - int(lo, 16) for lo, hi in f["ranges"])
             for f in json.loads((FACTS / "functions.json").read_text())["functions"] if not f.get("thunk")}
    runner = Runner(b)
    found = {}
    for k, e in protos.items():
        a = int(k, 16)
        if sizes.get(a, 0x10000) > 0x400:
            continue
        shapes = shape_of(e)
        for name, (shape, cases) in SPECS.items():
            if shape not in shapes:
                continue
            ok = True
            for inputs, want in cases:
                got = runner.run(a, shape, inputs)
                if got is None or any(got[reg] != (v & M64) for reg, v in want.items()):
                    ok = False
                    break
            if ok:
                found[hexa(a)] = name
                break
    path = write_facts("helpers32", {"rule": "helpers32.py: run under Unicorn in each helper's convention, "
                                              "every case matching", "helpers": found})
    print(f"{len(found)} helpers: {found} -> {path}", file=sys.stderr)
    print(f"{len(found)} compiler helpers identified -> {path}")


if __name__ == "__main__":
    main()
