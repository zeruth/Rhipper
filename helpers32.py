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
import re
import struct
import sys

from unicorn import UC_ARCH_X86, UC_HOOK_MEM_WRITE, UC_MODE_32, Uc, UcError
from unicorn.x86_const import (
    UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_ESP, UC_X86_REG_FP0,
    UC_X86_REG_FPSW, UC_X86_REG_XMM0,
)

from pebin import FACTS, Binary, disassembler, hexa, write_facts

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
    # (and the C runtime's x87 square root, st0 to st0: a static CRT's __CIsqrt, which function ID
    # left unnamed in VS2010's, and its callers reached its stub, rhtest msvc-16.00-x86 float.
    # Squares, whose roots are exact whatever precision the x87 rounds to)
    "CIsqrt": ("st0", [((d,), {"st0": f64(math.sqrt(d))}) for d in (2.25, 4.0, 1.0e10, 0.0625)]),
    # (and its power, x in st1 and y in st0, x^y in st0: a VS2010 client's 0xc4cb50, which function
    # ID left unnamed, its 56 callers handing it six xmm registers and st0 alone. Powers of two:
    # Unicorn's x87 logarithm is exact only there, 3^4 coming out a bit short of 81)
    # (and its sine and cosine, st0 to st0: a VS2010 client's 0xc4cde0 and 0xc4ca20, unnamed. Their
    # SSE2 branches read xmm registers, which protos32 handed on to every caller as inputs, a
    # rotation's caller a stub for in_XMM2_Da. Values Unicorn's x87 gives exactly as Python's)
    "CIsin": ("st0", [((x,), {"st0": f64(math.sin(x))}) for x in (0.5, 1.0, 3.0, 0.25)]),
    "CIcos": ("st0", [((x,), {"st0": f64(math.cos(x))}) for x in (0.5, 1.0, 3.0, 0.25)]),
    "CIpow": ("st01", [((x, y), {"st0": f64(x ** y)}) for x, y in ((2.0, 10.0), (4.0, 0.5), (2.0, -2.0),
                                                                    (16.0, 0.25), (0.5, 3.0))]),
    # (and the library's sqrt, a __cdecl double on the stack, its root pushed in st0: what VS2010
    # calls at /Od, `_sqrt`, which runs on into the body __CIsqrt shares and branches on the flags
    # its call to __load_CW left, a stub for in_ZF, rhtest msvc-16.00-x86 float-Od)
    # (and roots that are not exact, correctly rounded only by the instruction: rhtest's own Newton
    # iteration, `newton`, matched the squares)
    "sqrt": ("stackd", [((d,), {"st0": f64(math.sqrt(d))}) for d in (2.25, 4.0, 1.0e10, 0.0625, 2.0, 3.0, 0.1)]),
}
# the instruction a helper's result comes from, which it has to run: the square roots' fsqrt. A
# program's own Newton iteration (rhtest float's `newton`) matches every value at the x87's
# precision, and was taken for the CRT's sqrt
NEEDS = {"CIsqrt": b"\xd9\xfa", "sqrt": b"\xd9\xfa"}


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
        # (the image's pages a run wrote, put back before the next: rewriting the whole image
        # each run was most of the time, ~0.6 ms a run over ~50k runs on a 13 MB image)
        self.dirty: set[int] = set()

        def wrote(_uc, _access, addr, size, _value, _data):
            self.dirty.update(range(addr >> 12, ((addr + size - 1) >> 12) + 1))
        uc.hook_add(UC_HOOK_MEM_WRITE, wrote, begin=b.base, end=b.base + size - 1)

    def run(self, entry: int, shape: str, inputs: tuple) -> dict | None:
        uc = self.uc
        # (a clean image each time: globals)
        for page in sorted(self.dirty):
            at = (page << 12) - self.b.base
            uc.mem_write(page << 12, self.image[at:at + 0x1000].ljust(0x1000, b"\0"))
        self.dirty.clear()
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
        elif shape == "stackd":
            # (the double pushed as a __cdecl argument, under the return address; st0 empty, as
            # fninit leaves it: a stub `fninit; call entry; hlt` with the double where it reads it)
            for word in reversed(struct.unpack("<II", struct.pack("<d", inputs[0]))):
                esp -= 4
                uc.mem_write(esp, struct.pack("<I", word))
            code = b"\xdb\xe3"
            call_at = STUB + len(code)
            code += b"\xe8" + struct.pack("<i", entry - (call_at + 5)) + b"\xf4"
            uc.mem_write(STUB, code)
            start = STUB
        elif shape == "st0":
            # (a stub loads st0 and calls: fninit; fld qword [DATA]; call entry; hlt. fninit masks the
            # exceptions, as Windows starts a thread; a result left in st0 is read off the register)
            uc.mem_write(DATA, struct.pack("<d", inputs[0]))
            code = b"\xdb\xe3" + b"\xdd\x05" + struct.pack("<I", DATA)
            call_at = STUB + len(code)
            code += b"\xe8" + struct.pack("<i", entry - (call_at + 5)) + b"\xf4"
            uc.mem_write(STUB, code)
            start = STUB
        elif shape == "st01":
            # (two loaded, x first: x in st1, y in st0, as `fld x; fld y; call __CIpow`)
            uc.mem_write(DATA, struct.pack("<dd", inputs[0], inputs[1]))
            code = b"\xdb\xe3" + b"\xdd\x05" + struct.pack("<I", DATA) + b"\xdd\x05" + struct.pack("<I", DATA + 8)
            call_at = STUB + len(code)
            code += b"\xe8" + struct.pack("<i", entry - (call_at + 5)) + b"\xf4"
            uc.mem_write(STUB, code)
            start = STUB
        stub = shape in ("st0", "st01", "stackd")
        if not stub:
            esp -= 4
            uc.mem_write(esp, struct.pack("<I", RETURN))
        uc.reg_write(UC_X86_REG_ESP, esp)
        try:
            uc.emu_start(start, RETURN if not stub else STUB + len(code) - 1, count=20000)
        except UcError:
            return None
        eax, edx = uc.reg_read(UC_X86_REG_EAX), uc.reg_read(UC_X86_REG_EDX)
        ebx, ecx = uc.reg_read(UC_X86_REG_EBX), uc.reg_read(UC_X86_REG_ECX)
        return {"eax": eax, "edx:eax": (edx << 32) | eax, "ebx:ecx": (ebx << 32) | ecx,
                "xmm0": uc.reg_read(UC_X86_REG_XMM0) & M64,
                "st0": self.st0() if stub else None}

    def runs(self, entry: int, shape: str, inputs: tuple, insn: bytes) -> bool:
        """Whether a run executes the instruction (its bytes)."""
        from unicorn import UC_HOOK_CODE
        saw = []

        def hook(uc, addr, size, _):
            if not saw and size == len(insn) and bytes(uc.mem_read(addr, size)) == insn:
                saw.append(addr)
        h = self.uc.hook_add(UC_HOOK_CODE, hook)
        # (the code already translated runs as it was, without the hook: dropped first)
        self.uc.ctl_flush_tb()
        try:
            self.run(entry, shape, inputs)
        finally:
            self.uc.hook_del(h)
            self.uc.ctl_flush_tb()
        return bool(saw)

    def st0(self) -> int | None:
        """st0 as a double's bits: the physical register the status word's TOP names (Unicorn's
        UC_X86_REG_ST0 gives the mantissa alone)."""
        top = (self.uc.reg_read(UC_X86_REG_FPSW) >> 11) & 7
        return st0_double(self.uc.reg_read(UC_X86_REG_FP0 + top))


def st0_double(reg) -> int | None:
    """An x87 register's 80-bit value, Unicorn's (mantissa, sign and exponent), as a double's bits.
    (Read off the register: an `fst` after a helper that popped st0 faulted, masked, and Unicorn's
    stores after that one wrote nothing, every later candidate's result 0)"""
    # (a tuple in some Unicorn versions, the 80 bits as one integer in others)
    mantissa, se = reg if isinstance(reg, tuple) else (reg & M64, reg >> 64)
    exp = se & 0x7FFF
    if exp == 0 and mantissa == 0:
        v = 0.0
    elif exp == 0x7FFF:
        v = math.nan if mantissa & ((1 << 63) - 1) else math.inf
    else:
        v = math.ldexp(mantissa, exp - 16383 - 63)
    return f64(-v if se & 0x8000 else v)


def shape_of(e: dict) -> set[str]:
    """The helper shapes a function's protos32.py facts allow."""
    # (`xmm0d`: protos32.py's name for xmm0 read as a double, __dtol3's)
    regs = {re.sub(r"^(xmm\d)d$", r"\1", r) for r in e.get("regs", [])}
    out = set()
    if e.get("stack") == 16 and e.get("cc") in ("__stdcall", "custom"):
        out.add("stack16")
    # (a __cdecl one taking a double: 8 bytes, or 4 where it reads the slot by its address)
    if e.get("cc") == "__cdecl" and e.get("stack") in (4, 8) and not e.get("regs"):
        out.add("stackd")
    if e.get("stack", 0) == 0:
        if {"eax", "edx"} <= regs and ("cl" in regs or "ecx" in regs):
            out.add("shift")
        if {"ecx", "edx"} <= regs or e.get("cc") == "__fastcall":
            out.add("edx:ecx")
        if "xmm0" in regs:
            out.add("xmm0")
        if "st0" in regs:
            out |= {"st0", "st01"}
        # (one that shows no inputs may hand them on through a jump, `__ftoul2: jmp
        # __ftoul2_legacy` past a check: the register shapes, for a small one, cost little)
        if not regs and not e.get("params"):
            out |= {"st0", "st01", "xmm0", "edx:ecx"}
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
            if ok and name in NEEDS and not runner.runs(a, shape, cases[0][0], NEEDS[name]):
                ok = False
            if ok:
                found[hexa(a)] = name
                break
    # (the helper, not a function wrapping it: one that calls another found is the program's
    # own, `dsqrt(x) { return sqrt(x); }` in rhtest float, and stays translated code)
    md = disassembler()
    ranges = {int(f["entry"], 16): f["ranges"] for f in json.loads((FACTS / "functions.json").read_text())["functions"]}
    found_at = {int(k, 16) for k in found}
    for k in list(found):
        a = int(k, 16)
        calls = set()
        for lo, hi in ranges.get(a, ()):
            lo, hi = int(lo, 16), int(hi, 16)
            for ins in md.disasm(bytes(b.image[b.off(lo):b.off(lo) + (hi - lo)]), lo):
                if ins.mnemonic == "call" and ins.op_str.startswith("0x"):
                    calls.add(int(ins.op_str, 16))
        if calls & (found_at - {a}):
            del found[k]
    # (an ftol2 by its run that converts to 32 bits itself where SSE2 is there, `cmp [__sse2_avail],
    # 0; je __ftol2; ...; cvttsd2si eax, [esp]`, is __ftol2_sse, (int)double's: the run, before the
    # CRT set the flag, took the jump. On the machine it is cvttsd2si's, the integer indefinite past
    # 32 bits, and as __ftol2's 64-bit truncation 7e10 came out 0x4c533c00, rhtest msvc-16.00-x86
    # float d2i_huge 2026-10-25)
    for k, name in list(found.items()):
        if name != "ftol2":
            continue
        a = int(k, 16)
        for lo, hi in ranges.get(a, ()):
            lo, hi = int(lo, 16), int(hi, 16)
            if any(ins.mnemonic == "cvttsd2si" and ins.op_str.startswith("eax")
                   for ins in md.disasm(bytes(b.image[b.off(lo):b.off(lo) + (hi - lo)]), lo)):
                found[k] = "ftol2_sse"
    path = write_facts("helpers32", {"rule": "helpers32.py: run under Unicorn in each helper's convention, "
                                              "every case matching", "helpers": found})
    print(f"{len(found)} helpers: {found} -> {path}", file=sys.stderr)
    print(f"{len(found)} compiler helpers identified -> {path}")


if __name__ == "__main__":
    main()
