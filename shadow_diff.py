"""Compare a shadow run of the reference (shadow32.py, or shadow64.py for an x86-64 project) with
the port's shadow trace (runtime32/Trace.cpp, <ENV>_TRACE): the first call where the two runs part
is where the port's bug is. Both files are 24-byte records (tid, reference address, four argument
words) on x86, 48-byte ones on x86-64 (see shadow64.py).

    python shadow_diff.py build/shadow-ref.bin run-port.bin [--args] [--thread N]

Threads are matched between the runs by the order they first appear (the startup thread is 0). For
each matched thread the two call sequences are walked together; the first place they differ --- a
different function called, or the same function with different arguments if --args --- is printed,
with the shared calls just before it for context. Function names come from build/facts/functions.json.
"""
from __future__ import annotations

import argparse
import json
import re
import struct
import sys

from pebin import FACTS
import project


def load(path):
    """[(tid, addr, a0..a3)]: 24-byte records on x86 (shadow32.py), 48 on x86-64 (shadow64.py:
    tid, a zero word, then the address and the arguments 8 bytes each)."""
    data = open(path, "rb").read()
    if project.ARCH == "x86_64":
        rec = struct.Struct("<IIQQQQQ")
        return [(t, *rest) for t, _z, *rest in rec.iter_unpack(data[:len(data) - len(data) % rec.size])]
    n = len(data) // 24
    recs = [struct.unpack_from("<6I", data, i * 24) for i in range(n)]  # (tid, addr, a0..a3)
    return recs


# MSVC's frame helpers: Ghidra folds each into the function that calls it (the SEH frame, the
# stack probe), so the port never calls them; the reference's calls to them are left out
HELPERS = ("SEH_prolog", "SEH_epilog", "EH_prolog", "EH_epilog", "alloca_probe", "chkstk")


def by_thread(recs, skip=frozenset()):
    """{thread index in first-seen order: [(addr, args), ...]}, the frame helpers left out."""
    order, seqs = {}, {}
    for tid, addr, a0, a1, a2, a3 in recs:
        if addr in skip:
            continue
        if tid not in order:
            order[tid] = len(order)
        seqs.setdefault(order[tid], []).append((addr, (a0, a1, a2, a3)))
    return seqs


def names():
    """{entry: name}: functions.json's (a 32-bit project), else the corpus's (an x86-64 project
    has no functions.json; its names are in each corpus line, read without the decompilation)."""
    out = {}
    fj = FACTS / "functions.json"
    if fj.exists():
        for f in json.loads(fj.read_text())["functions"]:
            out[int(f["entry"], 16)] = f["name"]
        return out
    if project.CORPUS.exists():
        pat = re.compile(r'"addr":\s*"([0-9a-fA-F]+)",\s*"name":\s*"([^"]*)"')
        with open(project.CORPUS, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = pat.search(line, 0, 200)
                if m:
                    out[int(m.group(1), 16)] = m.group(2)
    return out


def name(nm, addr):
    return f"{nm.get(addr, '?')} (0x{addr:x})"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ref", help="the reference run (shadow32.py --out)")
    ap.add_argument("port", help="the port's trace (<ENV>_TRACE)")
    ap.add_argument("--args", action="store_true", help="compare arguments too, not just the call sequence")
    ap.add_argument("--thread", type=int, help="only this thread index (default: every matched thread)")
    ap.add_argument("--context", type=int, default=12, help="calls of shared history to show before a divergence")
    a = ap.parse_args()
    nm = names()
    skip = frozenset(addr for addr, n in nm.items() if any(h in n for h in HELPERS))
    ref, port = by_thread(load(a.ref), skip), by_thread(load(a.port), skip)
    print(f"reference: {len(ref)} threads, {sum(len(v) for v in ref.values())} calls; "
          f"port: {len(port)} threads, {sum(len(v) for v in port.values())} calls\n")
    threads = [a.thread] if a.thread is not None else sorted(set(ref) & set(port))
    found = False
    for t in threads:
        r, p = ref.get(t, []), port.get(t, [])
        i = 0
        while i < len(r) and i < len(p):
            ra, rargs = r[i]
            pa, pargs = p[i]
            if ra != pa or (a.args and rargs != pargs):
                break
            i += 1
        else:
            # one ran out: the shorter stopped (the port's crash, usually)
            if len(r) == len(p):
                print(f"thread {t}: {len(r)} calls, identical")
                continue
            i = min(len(r), len(p))
        found = True
        print(f"thread {t}: diverges at call {i} of {min(len(r), len(p))}")
        for j in range(max(0, i - a.context), i):
            print(f"       {j:>7}  {name(nm, r[j][0])}")
        print("  ---- the two runs part here ----")
        if i < len(r):
            ra, rargs = r[i]
            print(f"  ref  {i:>7}  {name(nm, ra)}  args {[hex(x) for x in rargs]}")
        else:
            print(f"  ref  {i:>7}  (the reference made no more calls on this thread)")
        if i < len(p):
            pa, pargs = p[i]
            print(f"  port {i:>7}  {name(nm, pa)}  args {[hex(x) for x in pargs]}")
        else:
            print(f"  port {i:>7}  (the port stopped here --- its crash)")
        print()
    if not found:
        print("the runs agree on every matched thread")


if __name__ == "__main__":
    main()
