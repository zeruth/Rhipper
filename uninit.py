r"""Locals the translation reads but never assigns, in the generated C (translate32.uninit_locals):
a register the decompiler lost and named like a variable (`this_00`, `pvVar5`), not `extraout_*`
or `in_*`, which translate32 resolves or stubs. Read uninitialized, each is whatever the host's
register or stack held: a UI hit test handed its node a code address, a crash on a click
(2026-10-28). translate32 marks each such function GEN_SUSPECT, its first call logged.

    python uninit.py                     every function in src/gen with one, its names
    python uninit.py --count             how many
"""
from __future__ import annotations

import argparse
import re

import project
from translate32 import uninit_locals

FUNC = re.compile(r"(?m)^/\* ref: ([^\n]*?) \*/\n([^\n]*\bF_([0-9a-f]{8})\(.*?\n\}\n)", re.S)


def scan() -> list[tuple[str, str, list[str]]]:
    found = []
    for p in sorted((project.ROOT / "src" / "gen").glob("translated_*.c")):
        text = p.read_text(encoding="utf-8", errors="replace")
        for m in FUNC.finditer(text):
            names = uninit_locals(m.group(2))
            if names:
                found.append((m.group(3), m.group(1), names))
    return found


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", action="store_true")
    a = ap.parse_args()
    found = scan()
    if not a.count:
        for addr, name, names in found:
            print(f"{addr}  {name[:50]:50s}  {', '.join(names)}")
    print(f"{len(found)} functions read a local they never assign")


if __name__ == "__main__":
    main()
