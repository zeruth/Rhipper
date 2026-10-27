"""Diff the generated C of named functions between a git revision of the project's gen and the
working tree (or between two revisions). A retranslation moves functions between the
translated_NNN.c files, so a file-level git diff can't line a function up with its old self;
this finds each one by its `/* ref: ... */` tag and F_<addr> name on both sides.

    python gendiff.py 4dd100 5584e0            HEAD against the working tree
    python gendiff.py 4dd100 --rev 85dd9f4     that commit against the working tree
    python gendiff.py 4dd100 --rev A --to B    two commits
    python gendiff.py --changed [--rev R]      list the functions whose text changed (address, lines)
"""
from __future__ import annotations

import argparse
import difflib
import re
import subprocess
import sys

from project import GEN, ROOT

TAG = re.compile(r"^/\* ref: .* \*/\n[^\n]*?\bF_([0-9a-f]{8})\(", re.M)


def split(text: str) -> dict[int, str]:
    """Each tagged function's text, from its tag to the next tag, by the address in its F_ name
    (a named function's tag carries its name, not its address)."""
    out = {}
    marks = list(TAG.finditer(text))
    for i, m in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(text)
        out[int(m.group(1), 16)] = text[m.start():end].rstrip() + "\n"
    return out


def gen_files(rev: str | None) -> list[str]:
    """The text of each translated_*.c (and the other generated .c) at a revision, or on disk."""
    rel = GEN.relative_to(ROOT).as_posix()
    if rev is None:
        return [p.read_text(encoding="utf-8", errors="replace") for p in sorted(GEN.glob("*.c"))]
    names = subprocess.run(["git", "-C", str(ROOT), "ls-tree", "--name-only", rev, rel + "/"],
                           capture_output=True, text=True, check=True).stdout.split()
    out = []
    for n in names:
        if n.endswith(".c"):
            out.append(subprocess.run(["git", "-C", str(ROOT), "show", f"{rev}:{n}"], capture_output=True,
                                      check=True).stdout.decode("utf-8", "replace"))
    return out


def functions(rev: str | None) -> dict[int, str]:
    out: dict[int, str] = {}
    for text in gen_files(rev):
        out.update(split(text.replace("\r\n", "\n")))
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("addrs", nargs="*", type=lambda s: int(s, 16))
    ap.add_argument("--rev", default="HEAD", help="the old side (default HEAD)")
    ap.add_argument("--to", default=None, help="the new side (default the working tree)")
    ap.add_argument("--changed", action="store_true", help="list the functions that differ")
    ap.add_argument("-U", type=int, default=3, help="context lines")
    args = ap.parse_args()
    old, new = functions(args.rev), functions(args.to)
    if args.changed:
        diff = sorted(a for a in old.keys() | new.keys() if old.get(a) != new.get(a))
        for a in diff:
            o, n = old.get(a, "").count("\n"), new.get(a, "").count("\n")
            print(f"{a:08x}  {o:5d} -> {n:5d}" + ("  (new)" if a not in old else "  (gone)" if a not in new else ""))
        print(f"{len(diff)} of {len(new)} functions changed", file=sys.stderr)
        return
    for a in args.addrs:
        o, n = old.get(a), new.get(a)
        if o is None and n is None:
            print(f"{a:08x}: on neither side")
            continue
        if o == n:
            print(f"{a:08x}: unchanged")
            continue
        sys.stdout.writelines(difflib.unified_diff((o or "").splitlines(True), (n or "").splitlines(True),
                                                   f"{args.rev}:{a:08x}", f"{args.to or 'work'}:{a:08x}", n=args.U))


if __name__ == "__main__":
    main()
