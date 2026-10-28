"""Coverage diff of two shadow traces (shadow32.py's reference, the runtime's port): the functions
the reference called that the port never did, in the order the reference first called them. The
first few mark where the port's path leaves the reference's (a branch taken differently, a step it
never reaches), cheaper than a call-by-call diff when the two runs' thread interleaving and timing
differ.

    python covdiff.py build/shadow-ref-from-401e10.bin build/shadow-port-from-401e10.bin [-n 40]
    python covdiff.py REF PORT --both            and the port-only ones too

Reads either trace whole (24-byte records, x86); a capped port trace still covers its first calls.
"""
from __future__ import annotations

import argparse
import json
import re

import numpy as np

from pebin import FACTS
from shadow_diff import HELPERS, helper_callees, name, names


def first_calls(path: str) -> tuple[np.ndarray, np.ndarray]:
    """(addresses, index of first call) in first-call order"""
    rec = np.fromfile(path, dtype="<u4")
    rec = rec[:len(rec) // 6 * 6].reshape(-1, 6)
    addrs = rec[:, 1]
    u, first = np.unique(addrs, return_index=True)
    order = np.argsort(first)
    return u[order], first[order]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("ref")
    ap.add_argument("port")
    ap.add_argument("-n", type=int, default=40)
    ap.add_argument("--both", action="store_true", help="also the functions only the port called")
    a = ap.parse_args()
    ra, rf = first_calls(a.ref)
    pa, pf = first_calls(a.port)
    pset, rset = set(pa.tolist()), set(ra.tolist())
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
    for x, i in only_ref[:a.n]:
        print(f"  #{i:9d}  {x:08x}  {name(nm, x)[:70]}")
    if a.both:
        only_port = [(int(x), int(i)) for x, i in zip(pa, pf) if int(x) not in rset]
        print(f"{len(only_port)} only the port called")
        for x, i in only_port[:a.n]:
            print(f"  #{i:9d}  {x:08x}  {name(nm, x)[:70]}")


if __name__ == "__main__":
    main()
