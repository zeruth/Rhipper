r"""Functions Ghidra made at a jump target inside another function: a DEFAULT-named (FUN_) one that
nothing calls and no vtable or pointer table names, its entry reached only by jumps from the
function just before it. Each splits its parent: the parent's body ends at the piece, and what the
parent's code does past it -- a call site's facts, its frame -- belongs to the wrong function. A UI
reset 0x594d90 lost its loop to FUN_00594da8 (its `je` past a `ret 4`), the call-site facts of the
loop's `call [eax + 8]` were not applied, the call went out with no `this`, and a mouse-over of a
settings tab called 0xcccccccc (2026-10-28). ApplyFacts removes them (cleanFunctions32).

    python jumppieces.py                 the pieces, each with its parent
    python jumppieces.py --write FILE    and their entries as JSON, for ApplyFacts
"""
from __future__ import annotations

import argparse
import bisect
import json

from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone import x86_const as X

from pebin import EXE, FACTS, Binary


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", metavar="FILE")
    a = ap.parse_args()
    b = Binary(EXE)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    funcs = json.loads((FACTS / "functions.json").read_text())["functions"]
    entries = sorted(int(f["entry"], 16) for f in funcs)
    name = {int(f["entry"], 16): f["name"] for f in funcs}
    called, jumped = set(), {}
    for f in funcs:
        e = int(f["entry"], 16)
        for lo, hi in f.get("ranges", []):
            lo, hi = int(lo, 16), int(hi, 16)
            o = b.off(lo)
            for ins in md.disasm(bytes(b.image[o:o + (hi - lo)]), lo):
                if not ins.operands or ins.operands[0].type != X.X86_OP_IMM:
                    continue
                t = ins.operands[0].imm & 0xFFFFFFFF
                if ins.mnemonic == "call":
                    called.add(t)
                elif ins.mnemonic.startswith("j"):
                    jumped.setdefault(t, set()).add(e)
    # (named by a vtable, or a pointer to it anywhere in the image's data: kept)
    vt = json.loads((FACTS / "vtables.json").read_text())["vtables"]
    pointed = {int(s, 16) for e in vt for s in e["slots"]}
    pieces = []
    for e in entries:
        if not name[e].startswith("FUN_") or e in called or e in pointed or e not in jumped:
            continue
        k = bisect.bisect_left(entries, e) - 1
        prev = entries[k] if k >= 0 else None
        if prev is None or jumped[e] != {prev}:
            continue
        pieces.append((e, prev))
    for e, prev in pieces[:40]:
        print(f"  {e:08x}  piece of {prev:08x} {name[prev][:50]}")
    print(f"{len(pieces)} functions at a jump target of the function before them, nothing else reaching them")
    if a.write:
        open(a.write, "w").write(json.dumps({"pieces": [f"{e:#x}" for e, _ in pieces]}))


if __name__ == "__main__":
    main()
