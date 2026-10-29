"""The reference globals its code reads and writes as floating point, from the instructions.

The data export types most globals by size alone (`undefined4`), and the decompilation does not
say a global is a float when it is only ever used through SSE instructions, so a translated
`DAT_a * DAT_b` became an integer multiply where the reference does `mulss`. Every scalar SSE
instruction with a RIP-relative memory operand names a float (`ss`, `ps`, `comiss`) or a double
(`sd`, `pd`, `comisd`) at that address; this collects them, once, into build/refdata-float.json.

    python tools/floatdata.py      (tools/translate64.py runs it when the cache is missing)
"""

from __future__ import annotations

import json
from pathlib import Path

import capstone

from pebin import Binary

from project import ROOT
CACHE = ROOT / "build" / "refdata-float.json"

# Only what does floating-point arithmetic, compares, converts or moves one scalar says a float.
# The packed moves (movaps, movups) are MSVC's 16-byte copy of anything, and the bitwise ops
# (andps, xorps, ...) work on bits: a global pair of function pointers copied with movups was
# typed float, and `REFG(float, 0x142d2b310) = <a function>` did not compile (C2440, 2026-10-16)
FLOAT = {"movss", "addss", "subss", "mulss", "divss", "minss", "maxss", "sqrtss", "comiss", "ucomiss",
         "cvtss2sd", "cvtss2si", "cvttss2si", "addps", "mulps", "subps", "divps", "minps", "maxps",
         "vmovss", "vaddss", "vsubss", "vmulss", "vdivss", "vcomiss", "vucomiss", "vcvtss2sd",
         "vminss", "vmaxss", "vsqrtss", "vfmadd213ss", "vfmadd231ss", "vfmadd132ss"}
DOUBLE = {"movsd", "addsd", "subsd", "mulsd", "divsd", "minsd", "maxsd", "sqrtsd", "comisd", "ucomisd",
          "cvtsd2ss", "cvtsd2si", "cvttsd2si", "addpd", "mulpd", "subpd",
          "vmovsd", "vaddsd", "vsubsd", "vmulsd", "vdivsd", "vcomisd", "vucomisd", "vcvtsd2ss"}


# 32-bit code does its floating point on the x87 stack as much as in SSE: a memory operand's width
# says the type (`fld qword ptr [0x1087ef0]` a double: the data export typed that one `pointer`,
# and `(float10)REFG(undefined * PTR32, 0x1087ef0)` did not compile in 205 functions, 2026-10-23)
X87 = {"fld", "fst", "fstp", "fadd", "fsub", "fsubr", "fmul", "fdiv", "fdivr", "fcom", "fcomp"}
X87_WIDTH = {"dword": "float", "qword": "double", "tbyte": "float10"}


def scan32() -> dict[str, str]:
    """The x86 counterpart: absolute memory operands (`[0x...]`, `[eax*8 + 0x...]`), x87 by the
    operand's width, SSE as on x64."""
    import re
    from pebin import disassembler
    b = Binary()
    md = disassembler()
    mem = re.compile(r"(byte|word|dword|qword|xmmword|tbyte) ptr \[([a-z0-9*+ ]*\+ )?(0x[0-9a-f]+)\]")
    out: dict[int, str] = {}
    # (an array read through an index, `movsd xmm0, [edx + 0x405090]`: its elements the same type.
    # Typed at its base alone, `g_vals[5]` the decompiler folded to `DAT_004050b8` was undefined8,
    # its multiply an integer's converted and its `(int)` a truncation of bits, rhtest fpenv-Od)
    arrays: dict[int, str] = {}
    refs: set[int] = set()
    for start, end in zip(b.piece_starts, b.piece_ends):
        o = b.off(start)
        for _address, _size, mnemonic, ops in md.disasm_lite(bytes(b.image[o:o + (end - start)]), start):
            m = mem.search(ops)
            if m is None:
                continue
            target = int(m.group(3), 16)
            if not m.group(2):
                refs.add(target)
            if mnemonic in X87:
                kind = X87_WIDTH.get(m.group(1))
            else:
                kind = "float" if mnemonic in FLOAT else "double" if mnemonic in DOUBLE else None
            if kind is None:
                continue
            if b.section_of(target) is None:
                continue
            out[target] = kind if out.get(target, kind) == kind else "mixed"
            if m.group(2) and re.search(r"[a-z]", m.group(2)) and kind in ("float", "double"):
                arrays[target] = kind if arrays.get(target, kind) == kind else "mixed"
    # (each array's elements up to the next address the code names by itself, another typed one,
    # its section's end, or 64 of them)
    for base, kind in arrays.items():
        if kind == "mixed" or out.get(base) != kind:
            continue
        size = 8 if kind == "double" else 4
        for k in range(1, 64):
            a = base + size * k
            if a in refs or a in arrays or (a in out and out[a] != kind) or b.section_of(a) != b.section_of(base):
                break
            out.setdefault(a, kind)
    return {f"{a:x}": k for a, k in out.items() if k != "mixed"}


def scan() -> dict[str, str]:
    from pebin import X86
    if X86:
        return scan32()
    b = Binary()
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    out: dict[int, str] = {}

    def instructions():
        # function by function (the unwind table's pieces), so data between functions never
        # puts the decoder out of step
        for start, end in zip(b.piece_starts, b.piece_ends):
            o = b.off(start)
            yield from md.disasm_lite(bytes(b.image[o:o + (end - start)]), start)

    for ins in instructions():
        address, size, mnemonic, ops = ins
        if "rip" not in ops:
            continue
        kind = "float" if mnemonic in FLOAT else "double" if mnemonic in DOUBLE else None
        if kind is None:
            continue
        # the memory operand: `[rip + 0x...]` (or `- 0x...`)
        at = ops.find("[rip ")
        expr = ops[at + 5:ops.find("]", at)]
        sign, disp = expr.split()
        target = address + size + int(disp, 16) * (1 if sign == "+" else -1)
        # a packed access starts a vector of them; only the first element's type is certain
        if out.get(target, kind) != kind:
            out[target] = "mixed"
        else:
            out[target] = kind
    return {f"{a:x}": k for a, k in out.items() if k != "mixed"}


def _exe_hash() -> str:
    """The reference's sha256: the cache is of one binary. Kept across a rebuilt reference, it typed
    the old layout's addresses, and a double constant at a new one read as an integer converted to
    double (-1.0 as -4616189618054758400.0, rhtest float-O2 series, 2026-10-25)."""
    import hashlib
    from project import EXE
    return hashlib.sha256(Path(EXE).read_bytes()).hexdigest()


def load() -> dict[int, str]:
    key = CACHE.with_suffix(".sha256")
    h = _exe_hash()
    if not CACHE.exists() or not key.exists() or key.read_text(encoding="utf-8").strip() != h:
        CACHE.write_text(json.dumps(scan()), encoding="utf-8")
        key.write_text(h, encoding="utf-8")
    return {int(a, 16): k for a, k in json.loads(CACHE.read_text(encoding="utf-8")).items()}


if __name__ == "__main__":
    found = scan()
    CACHE.write_text(json.dumps(found), encoding="utf-8")
    CACHE.with_suffix(".sha256").write_text(_exe_hash(), encoding="utf-8")
    kinds = {}
    for k in found.values():
        kinds[k] = kinds.get(k, 0) + 1
    print(f"{len(found)} globals typed by their instructions: {kinds}")
