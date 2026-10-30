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
import collections
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
HELPERS = ("SEH_prolog", "SEH_epilog", "EH_prolog", "EH_epilog", "alloca_probe", "chkstk",
           # (and what Windows' exception dispatch runs, which the port's runtime does itself: the
           # handlers and their checks, the filter reached directly. 10 job threads named by
           # RaiseException under _except_handler3 parted a VS2010 client's runs, 2026-10-25)
           "except_handler", "ValidateEH3RN", "ValidateScopeTableHandler", "ValidateImageBase",
           "FindPESection", "EH4_CallFilterFunc", "EH4_TransferToHandler", "EH4_GlobalUnwind",
           "EH4_LocalUnwind", "local_unwind", "global_unwind", "CallSettingFrame",
           # (and setjmp, which the port's runtime does natively: a protected call's every entry
           # parted the runs by one call)
           "_setjmp3",
           # (and the /GS check, a call fixup the translation does inline, GEN_COOKIE: a static C
           # runtime's undecorator parted the runs at its first return, rhtest stl /MT)
           "security_check_cookie")


def by_thread(recs, skip=frozenset(), helpers=frozenset(), inner=frozenset()):
    """{thread index in first-seen order: [(addr, args), ...]}, the frame helpers left out, and
    the calls a compiler helper's body makes (inner) straight after its entry (helpers): the
    translation does the helper inline and never calls them."""
    order, seqs, under = {}, {}, {}
    for tid, addr, a0, a1, a2, a3 in recs:
        if addr in helpers:
            under[tid] = True
            continue
        if under.get(tid):
            if addr in inner:
                continue
            under[tid] = False
        if addr in skip:
            continue
        if tid not in order:
            order[tid] = len(order)
        seqs.setdefault(order[tid], []).append((addr, (a0, a1, a2, a3)))
    return seqs


def helper_callees(helpers):
    """Every function a helper's body reaches by a direct call or jump, through its callees in
    turn (the C runtime's sin: _CIsin, its SSE2 body at another entry, _errno, its exception
    raiser), from functions.json's extents and the image."""
    from pebin import Binary, disassembler
    fj = FACTS / "functions.json"
    if not helpers or not fj.exists():
        return set()
    ranges = {int(f["entry"], 16): [(int(lo, 16), int(hi, 16)) for lo, hi in f["ranges"]]
              for f in json.loads(fj.read_text())["functions"]}
    pe, cs = Binary(), disassembler()
    seen, todo = set(), list(helpers)
    while todo:
        f = todo.pop()
        for lo, hi in ranges.get(f, ()):
            for insn in cs.disasm(bytes(pe.image[lo - pe.base:hi - pe.base + 1]), lo):
                if insn.mnemonic in ("call", "jmp") or insn.mnemonic.startswith("j"):
                    try:
                        t = int(insn.op_str, 16)
                    except ValueError:
                        continue
                    if t in ranges and t not in seen and t not in helpers:
                        seen.add(t)
                        todo.append(t)
    return seen


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
    ap.add_argument("--resync", type=int, default=0, metavar="N",
                    help="step over up to N calls one run makes and the other does not, where the two agree "
                         "again after them (an inner call of a library routine the translation does inline, "
                         "memcpy's own pieces), listing each, before stopping at a divergence they do not "
                         "agree after")
    ap.add_argument("--small-args", type=lambda s: int(s, 0), nargs="?", const=0x1000000, default=None,
                    metavar="LIMIT",
                    help="compare the argument words both runs hold below LIMIT (default 0x1000000): numbers and "
                         "the image's addresses, not each run's heap and stack addresses")
    ap.add_argument("--list-args", type=int, default=0, metavar="N",
                    help="with --small-args: list the first N calls of the same function with other arguments "
                         "and walk on, stopping only where the functions called part")
    ap.add_argument("--after", type=int, default=0, metavar="N",
                    help="at a divergence, the context and each run's next N calls side by side, with arguments")
    ap.add_argument("--start", type=lambda s: int(s, 16), metavar="ADDR",
                    help="walk each thread from its first call of ADDR in both runs (a point the two are "
                         "known to reach alike, past a stretch where worker threads' timing parts them)")
    ap.add_argument("--pair-by-calls", action="store_true",
                    help="pair each reference thread with the port's that calls the most of the same functions in "
                         "its first 200 calls, not by the order they appear: worker threads start in another "
                         "order run to run, and a render thread was 22 in one and 24 in the other")
    ap.add_argument("--skip", nargs="*", default=[], metavar="ADDR",
                    help="more functions to leave out of both runs (an unnamed exception handler)")
    ap.add_argument("--capped", type=int, nargs="?", const=200, metavar="N",
                    help="leave out of both runs every function the reference recorded N times or more (200 by "
                         "default): shadow32.py --per-function stops recording one there, and the port's later calls "
                         "of it read as calls the reference never made (a -Sites run's dialog teardown, 2026-10-28)")
    a = ap.parse_args()
    nm = names()
    # (and the reference's import thunks, `KERNEL32.DLL::GetCurrentThreadId`'s `jmp [iat]`: the
    # translation calls the import itself, through no thunk the port's trace records)
    skip = frozenset(addr for addr, n in nm.items() if any(h in n for h in HELPERS)
                     or re.search(r"\.(?:dll|DLL|drv|DRV)::", n)) | {int(x, 16) for x in a.skip}
    # (and the compiler's arithmetic helpers helpers32.py identified, which the translation does
    # inline: `__time64`'s __aulldiv parted a client's runs, 2026-10-25)
    hp = FACTS / "helpers32.json"
    helpers = frozenset(int(a, 16) for a in json.loads(hp.read_text())["helpers"]) if hp.exists() else frozenset()
    # (and what their bodies call, recorded in the reference's run straight after each: sin's
    # SSE2 body at its second entry parted a client's runs at a sincos, 2026-10-26)
    inner = frozenset(helper_callees(helpers))
    nwords = {}
    pr = FACTS / "protos.json"
    if a.small_args is not None and pr.exists():
        for k, e in json.loads(pr.read_text())["functions"].items():
            nwords[int(k, 16)] = min(len(e.get("params", [])), 4)
    ref_recs = load(a.ref)
    if a.capped:
        counts = collections.Counter(r[1] for r in ref_recs)
        capped = {f for f, n in counts.items() if n >= a.capped}
        print(f"{len(capped)} functions the reference recorded {a.capped} times or more, left out of both")
        skip = skip | capped
    ref, port = (by_thread(ref_recs, skip, helpers, inner),
                 by_thread(load(a.port), skip, helpers, inner))
    if a.pair_by_calls:
        # (the port's threads renumbered to the reference's index of the thread with the same
        # first call, in order among those; the startup thread stays 0)
        # (by the functions their first 200 calls reach, the unused port thread sharing the most,
        # half at least: every CRT thread starts in __threadstartex's prologue, so no first few
        # calls tell a render thread from a job worker)
        def head(seq):
            return {c[0] for c in seq[:200]}
        free = {t: head(port[t]) for t in port if t and port[t]}
        paired = {0: port.get(0, [])}
        for t in sorted(ref):
            if not t or not ref[t] or not free:
                continue
            h = head(ref[t])
            best = max(free, key=lambda u: (len(h & free[u]) / max(1, len(h | free[u])), -u))
            if len(h & free[best]) / max(1, len(h | free[best])) >= 0.5:
                paired[t] = port[best]
                del free[best]
        port = paired
        print(f"threads paired by what they call: {len(paired) - 1} of {len(ref) - 1}")
    if inner:
        print(f"the helpers' own callees, left out after a helper: {', '.join(name(nm, x) for x in sorted(inner))}")
    print(f"reference: {len(ref)} threads, {sum(len(v) for v in ref.values())} calls; "
          f"port: {len(port)} threads, {sum(len(v) for v in port.values())} calls\n")
    threads = [a.thread] if a.thread is not None else sorted(set(ref) & set(port))
    found = False
    for t in threads:
        r, p = ref.get(t, []), port.get(t, [])
        if a.start is not None:
            ri = next((k for k, c in enumerate(r) if c[0] == a.start), None)
            pj = next((k for k, c in enumerate(p) if c[0] == a.start), None)
            if ri is None or pj is None:
                continue
            print(f"thread {t}: from 0x{a.start:x}, reference call {ri}, port call {pj} (numbered from there)")
            r, p = r[ri:], p[pj:]

        def same(x, y):
            if x[0] != y[0]:
                return False
            if a.small_args is not None:
                # (a word both runs hold below the limit is a number or the image's address, the
                # same in both; above it a heap or stack address, each run's own. Only the words
                # of the function's parameter list: a recording before shadow32.py counted the
                # stack's words too has zeros past it)
                n = nwords.get(x[0], 4)
                return all(u == v for u, v in list(zip(x[1], y[1]))[:n] if u < a.small_args and v < a.small_args)
            return not a.args or x[1] == y[1]

        def agree(ri, pi, k=32):
            """the next k calls the same from ri in the reference and pi in the port"""
            n = min(k, len(r) - ri, len(p) - pi)
            return n > 0 and all(same(r[ri + j], p[pi + j]) for j in range(n))
        # i in the reference, j in the port: equal until a step over
        i = j = 0
        skips = 0
        listed = 0
        while i < len(r) and j < len(p):
            if same(r[i], p[j]):
                i += 1
                j += 1
                continue
            if a.list_args and r[i][0] == p[j][0]:
                # (the same function called with other arguments: listed, the walk on in step)
                listed += 1
                if listed <= a.list_args:
                    print(f"thread {t}: ref {i} / port {j}  {name(nm, r[i][0])}  ref {[hex(x) for x in r[i][1]]}"
                          f"  port {[hex(x) for x in p[j][1]]}")
                i += 1
                j += 1
                continue
            # (a few calls one run makes and the other not, or a stretch each makes differently
            # (printf of the time of day, other digits), the two in step again after them: the
            # fewest calls stepped over)
            step = None
            for total in range(1, 2 * a.resync + 1):
                for ki in range(max(0, total - a.resync), min(total, a.resync) + 1):
                    if agree(i + ki, j + total - ki):
                        step = (ki, total - ki)
                        break
                if step:
                    break
            if step is None:
                break
            ki, kj = step
            skips += 1
            if skips <= 20:
                def calls(s):
                    names_ = [name(nm, c[0]) for c in s[:6]]
                    return ", ".join(names_) + (f", ... ({len(s)})" if len(s) > 6 else "") if s else "nothing"
                print(f"thread {t}: at reference call {i} stepped over ref: {calls(r[i:i + ki])} | port: {calls(p[j:j + kj])}")
            i += ki
            j += kj
        if i >= len(r) or j >= len(p):
            # one ran out: the shorter stopped (the port's crash, usually)
            if i >= len(r) and j >= len(p):
                print(f"thread {t}: {len(r)} calls, identical" + (f" ({skips} stepped over)" if skips else ""))
                continue
        found = True
        print(f"thread {t}: diverges at reference call {i} of {len(r)} (port call {j} of {len(p)})"
              + (f", {skips} stepped over before" if skips else ""))
        for k in range(max(0, i - a.context), i):
            print(f"       {k:>7}  {name(nm, r[k][0])}")
        print("  ---- the two runs part here ----")
        if i < len(r):
            ra, rargs = r[i]
            print(f"  ref  {i:>7}  {name(nm, ra)}  args {[hex(x) for x in rargs]}")
        else:
            print(f"  ref  {i:>7}  (the reference made no more calls on this thread)")
        if j < len(p):
            pa, pargs = p[j]
            print(f"  port {j:>7}  {name(nm, pa)}  args {[hex(x) for x in pargs]}")
        else:
            print(f"  port {j:>7}  (the port stopped here --- its crash)")
        if a.after:
            # (each run's own next calls, side by side with their arguments: an extra loop pass,
            # a branch the other did not take, read off directly)
            def row(s, k):
                if k >= len(s):
                    return ""
                ad, ar = s[k]
                return f"{k:>8} {nm.get(ad, '?')[:30]:30} {ad:>7x} " + " ".join(f"{x:>8x}" for x in ar)
            print(f"  {'reference':^86} | {'port':^86}")
            for k in range(-min(a.context, i, j), a.after):
                print(f"  {row(r, i + k):86} | {row(p, j + k)}")
        print()
    if not found:
        print("the runs agree on every matched thread")


if __name__ == "__main__":
    main()
