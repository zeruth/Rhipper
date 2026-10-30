"""Triage: the problem functions of build/fidelity.json (stubs, and translations below 1.0) in
batches by cause, the commonest first, so that one fix can be checked against every function it
should mend.

Each function's defects are its stub reason, or its missing and extra calls, fields and constants
(fidelity32's rows), normalized: a register the decompiler lost is its kind (`extraout_ST0`,
`extraout_ST0_00` as one), a global, a constant or a field by its value. A function joins the batch
of its defect that the most functions share (a greedy cover): the batch a fix is likeliest to clear
whole. A defect only one function has is that function's own.

    python triage32.py                    the batches, the largest first, with a few functions each
    python triage32.py --batch 3          one batch: every function in it, the smallest first
    python triage32.py --batch 3 --addrs  its addresses alone, for `fidelity32.py --only`
    python triage32.py --json             every batch to build/triage.json, for tools (the IDE's MCP)

A fix's check: `fidelity32.py --only $(triage32.py --batch N --addrs)` measures the batch in
seconds, and `fidelity32.py --low` every problem function.
"""
from __future__ import annotations

import argparse
import collections
import json
import re
import sys

import project

FIDELITY = project.BUILD / "fidelity.json"
TRIAGE = project.BUILD / "triage.json"


def stub_key(why: str) -> str:
    """a stub's reason, its variable numbering and addresses dropped"""
    why = re.sub(r"\b(extraout|unaff|in)_([A-Za-z]+?)(?:_?\d+)*\b", r"\1_\2", why)
    why = re.sub(r"\bstack0x[0-9a-f]+\b", "stack0x*", why)
    why = re.sub(r"\b(?:0x)?[0-9a-f]{6,8}\b", "*", why)
    return "stub: " + why


def lab(x: str) -> str:
    return re.sub(r"^[0-9a-f]{8} ", "", x)


def defects(r: dict) -> list[str]:
    """a function's defects, normalized: what lowers its score, the reference's calls, fields and
    constants the port misses (fidelity32's presence; what the port has besides scores nothing)"""
    if r.get("kind") == "stub":
        return [stub_key(r.get("why", ""))]
    out = []
    out += [f"missing call {lab(x)}" for x in r.get("missing_calls", [])]
    out += [f"missing field {x}" for x in r.get("missing_fields", [])]
    out += [f"missing const {x}" for x in r.get("missing_consts", [])]
    return out or ["shape only (no call, field or constant missing)"]


def extras(r: dict) -> list[str]:
    """what the port has besides, no part of the score: a lead to the cause"""
    return [f"extra call {lab(x)}" for x in r.get("extra_calls", [])] + \
           [f"extra const {x}" for x in r.get("extra_consts", [])]


def batches(rows: list) -> list[dict]:
    problems = [r for r in rows if r.get("kind") == "stub" or
                (r.get("kind") == "translated" and r.get("score") is not None and r["score"] < 0.999)]
    of = {r["addr"]: defects(r) for r in problems}
    share = collections.Counter(d for ds in of.values() for d in set(ds))
    groups: dict[str, list] = collections.defaultdict(list)
    for r in problems:
        # (its defect the most share; a missing defect before an extra one, then by name)
        best = min(of[r["addr"]], key=lambda d: (-share[d], not d.startswith(("stub", "missing")), d))
        groups[best].append(r)
    out = []
    for key, rs in groups.items():
        rs.sort(key=lambda r: (r["size"], r["addr"]))
        out.append({"key": key, "count": len(rs), "shared_by": share[key],
                    "functions": [{"addr": r["addr"], "name": r["name"], "size": r["size"], "score": r.get("score"),
                                   "defects": of[r["addr"]][:8], "extras": extras(r)[:8]} for r in rs]})
    out.sort(key=lambda b: (-b["count"], b["key"]))
    for i, b in enumerate(out, 1):
        b["batch"] = i
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--batch", type=int, help="one batch, by its number (which moves as batches are fixed)")
    ap.add_argument("--key", help="one batch, by its defect: `missing const i:8000001f` (or a part of it)")
    ap.add_argument("--addrs", action="store_true", help="with --batch: its addresses alone")
    ap.add_argument("--json", action="store_true", help="every batch as JSON")
    ap.add_argument("--limit", type=int, default=40, help="the batches to list")
    a = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    rows = json.loads(FIDELITY.read_text(encoding="utf-8"))
    bs = batches(rows)
    if a.json:
        # (to a file: a tool's captured output is cut where it is long, 64 KB in the IDE)
        TRIAGE.write_text(json.dumps(bs, indent=1), encoding="utf-8")
        print(f"{sum(b['count'] for b in bs)} problem functions in {len(bs)} batches -> {TRIAGE}")
        return
    if a.batch or a.key:
        if a.key:
            b = next((b for b in bs if b["key"] == a.key), None) or next((b for b in bs if a.key in b["key"]), None)
        else:
            b = next((b for b in bs if b["batch"] == a.batch), None)
        if b is None:
            sys.exit(f"no batch {a.batch or a.key!r}: there are {len(bs)}")
        if a.addrs:
            print(" ".join(f["addr"] for f in b["functions"]))
            return
        print(f"batch {b['batch']}: {b['key']}  ({b['count']} functions here, {b['shared_by']} have it)")
        for f in b["functions"]:
            score = "stub " if f["score"] is None or f["score"] == 0 and b["key"].startswith("stub") else f"{f['score']:.3f}"
            print(f"  {f['addr']} {f['size']:6d}B {score} {f['name'][:40]:<40} {'; '.join(f['defects'][:3])[:100]}")
        return
    n = sum(b["count"] for b in bs)
    print(f"{n} problem functions in {len(bs)} batches ({sum(1 for b in bs if b['count'] == 1)} of one)")
    for b in bs[:a.limit]:
        eg = ", ".join(f["addr"] for f in b["functions"][:3])
        print(f"  {b['batch']:4d}  {b['count']:5d}  {b['key'][:80]:<80}  {eg}")


if __name__ == "__main__":
    main()
