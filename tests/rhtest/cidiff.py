"""The CI's rhtest results side by side, publish by publish, from the gh-pages branch (each push to
main publishes <toolset>/summary.json there): every project's status, stubs and perfect functions,
the ones that changed marked. A project worse than before is a regression to fix.

    python tests/rhtest/cidiff.py                       the last 3 publishes of msvc-14.51-x86
    python tests/rhtest/cidiff.py -n 5 --toolset msvc-16.00-x86
    python tests/rhtest/cidiff.py --changed             only the projects whose results changed
"""
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

RH = Path(__file__).resolve().parents[2]


def git(*args: str) -> str:
    return subprocess.run(["git", "-C", str(RH), *args], capture_output=True, text=True, check=True).stdout


def row(v: dict) -> str:
    f = v.get("fidelity") or {}
    if not f:
        return str(v.get("status"))
    return f"{v.get('status')} s={f.get('stubs')} {f.get('perfect')}/{f.get('functions')}"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", type=int, default=3, help="publishes to compare, oldest first")
    ap.add_argument("--toolset", default="msvc-14.51-x86")
    ap.add_argument("--changed", action="store_true")
    a = ap.parse_args()
    git("fetch", "-q", "origin", "gh-pages")
    path = f"{a.toolset}/summary.json"
    pubs = git("log", "origin/gh-pages", f"-{a.n}", "--format=%h %s", "--", path).splitlines()[::-1]
    sums = [json.loads(git("show", f"{p.split()[0]}:{path}")) for p in pubs]
    # (the Rhipper commit each publish tested, its subject's last word)
    heads = [p.split()[-1][:9] for p in pubs]
    names = sorted(set().union(*sums))
    w = max(len(row(s.get(n, {}))) for s in sums for n in names) + 1
    print(f"{'':24s} " + " | ".join(f"{h:{w}s}" for h in heads))
    for n in names:
        vals = [row(s[n]) if n in s else "-" for s in sums]
        changed = len(set(vals)) > 1
        if changed or not a.changed:
            print(f"{n:24s} " + " | ".join(f"{v:{w}s}" for v in vals) + ("  <-" if changed else ""))


if __name__ == "__main__":
    main()
