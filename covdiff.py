"""Coverage diff of two shadow traces (shadow32.py's reference, the runtime's port): the functions
the reference called that the port never did, in the order the reference first called them. The
first few mark where the port's path leaves the reference's (a branch taken differently, a step it
never reaches), cheaper than a call-by-call diff when the two runs' thread interleaving and timing
differ.

    python covdiff.py build/shadow-ref-from-401e10.bin build/shadow-port-from-401e10.bin [-n 40]
    python covdiff.py REF PORT --both            and the port-only ones too
    python covdiff.py REF PORT --after 5a8770    only what each run first called past that function's
                                                 first call: the next step once a landmark both reach
    python covdiff.py REF PORT --by-count        the reference's most called first: a frame's work

Reads either trace whole (24-byte records, x86); a capped port trace still covers its first calls.
"""
from __future__ import annotations

import argparse
import json
import re

import numpy as np

from pebin import FACTS
from shadow_diff import HELPERS, helper_callees, name, names


def first_calls(path: str, after: int | None = None) -> tuple[np.ndarray, np.ndarray]:
    """(addresses, index of first call) in first-call order; with after, from that function's
    first call on (nothing if the run never calls it)"""
    rec = np.fromfile(path, dtype="<u4")
    rec = rec[:len(rec) // 6 * 6].reshape(-1, 6)
    addrs = rec[:, 1]
    if after is not None:
        at = np.nonzero(addrs == after)[0]
        start = int(at[0]) if len(at) else len(addrs)
        u, first = np.unique(addrs[start:], return_index=True)
        order = np.argsort(first)
        return u[order], first[order] + start
    u, first = np.unique(addrs, return_index=True)
    order = np.argsort(first)
    return u[order], first[order]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("ref")
    ap.add_argument("port")
    ap.add_argument("-n", type=int, default=40)
    ap.add_argument("--both", action="store_true", help="also the functions only the port called")
    ap.add_argument("--by-count", action="store_true", help="the reference's most called first")
    ap.add_argument("--after",type=lambda s: int(s, 16), help="from this function's first call in each run")
    a = ap.parse_args()
    ra, rf = first_calls(a.ref, a.after)
    pa, pf = first_calls(a.port, a.after)
    # (what the port called before the landmark is not missing from it after: the reference's
    # first call past it may be the port's second)
    pset = set(pa.tolist()) | (set(first_calls(a.port)[0].tolist()) if a.after is not None else set())
    rset = set(ra.tolist())
    nm = names()
    # (what the port never calls by design, as shadow_diff leaves out: the frame and exception
    # helpers, import thunks, the compiler's arithmetic helpers and their bodies; and the image's
    # own thunks, which the translation calls straight through)
    skip = {a for a, n in nm.items() if any(h in n for h in HELPERS) or re.search(r"\.(?:dll|DLL|drv|DRV)::", n)
            or n.startswith("thunk_")}
    hp = FACTS / "helpers32.json"
    helpers = {int(x, 16) for x in json.loads(hp.read_text())["helpers"]} if hp.exists() else set()
    skip |= helpers | set(helper_callees(frozenset(helpers)))
    # (every function functions.json marks a thunk, named or not: the port's jump at one goes
    # straight to its target's translation. AddonImage's vf36, `jmp 0x55dc60`, was the first UI
    # "divergence" of a client's black screen, 2026-10-28)
    fj = FACTS / "functions.json"
    if fj.exists():
        skip |= {int(f["entry"], 16) for f in json.loads(fj.read_text())["functions"] if f.get("thunk")}
    only_ref = [(int(x), int(i)) for x, i in zip(ra, rf) if int(x) not in pset and int(x) not in skip]
    print(f"reference: {len(ra)} functions, port: {len(pa)}; {len(only_ref)} only the reference called")
    if a.by_count:
        # (the most called first: what a frame does each time, a draw the port never reaches,
        # over a one-off a network reply or a timer decided)
        rec = np.fromfile(a.ref, dtype="<u4")
        addrs = rec[:len(rec) // 6 * 6].reshape(-1, 6)[:, 1]
        u, n = np.unique(addrs, return_counts=True)
        count = dict(zip(u.tolist(), n.tolist()))
        only_ref.sort(key=lambda xi: -count.get(xi[0], 0))
        for x, i in only_ref[:a.n]:
            print(f"  {count.get(x, 0):8d}x  #{i:9d}  {x:08x}  {name(nm, x)[:60]}")
        return
    for x, i in only_ref[:a.n]:
        print(f"  #{i:9d}  {x:08x}  {name(nm, x)[:70]}")
    if a.both:
        only_port = [(int(x), int(i)) for x, i in zip(pa, pf) if int(x) not in rset]
        print(f"{len(only_port)} only the port called")
        for x, i in only_port[:a.n]:
            print(f"  #{i:9d}  {x:08x}  {name(nm, x)[:70]}")


if __name__ == "__main__":
    main()
