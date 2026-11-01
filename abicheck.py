r"""The indirect calls whose convention disagrees with a function they reach, from the facts.

    python abicheck.py              every disagreeing (site, target) pair, by kind
    python abicheck.py --all        and the sites that agree, counted

On x86 a __thiscall site calling a __stdcall function is harmless: the callee ignores ecx and pops
the same words. In the x64 port the two disagree on where each argument is (a __thiscall
function's first parameter is ecx's): every word arrives one off. A list's delegate, `mov ecx,
[esi + 0x1cc]; call [esi + 0x1d0]`, handed a __stdcall row callback the list's index for its row,
a fault on a client's title screen; an XAudio2 voice callback read its object through 0
(2026-10-28). The targets are the ones reference runs saw (data/icall_targets.json, shadow.ps1 ref
-Sites); the conventions are protos32's (protos.json, callsites.json).

Not counted (each read from the reference's code): a target that reads no argument at all (`ret
4`, given a spare ecx or word it never reads); a site that passes its context both ways, `mov ecx,
[ecx + 0x10]; push ecx; call eax`, the word and ecx the same; and a target a forwarder among the
site's others reaches by its tail jump, `mov ecx, [ebp + 8]; jmp [pmf]` (the run records the
jump's destination at the call: InvokeMember thunks 0x427ce0 / 0x427cf0 and 0x425040, 0x550fa0).
Those are listed apart, as "not harmful".
"""
from __future__ import annotations

import argparse
import collections
import json
import re

import project
from pebin import Binary, disassembler

FACTS = project.FACTS
ARG_READ = re.compile(r"\[(?:esp|ebp) \+ (?:0x[0-9a-f]+|\d+)\]")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true")
    a = ap.parse_args()
    protos = json.loads((FACTS / "protos.json").read_text())["functions"]
    sites = json.loads((FACTS / "callsites.json").read_text())
    seen_path = project.ROOT / "data" / "icall_targets.json"
    seen = json.loads(seen_path.read_text()) if seen_path.exists() else {}
    names = {}
    names_path = FACTS / "names.json"
    if names_path.exists():
        for k, v in json.loads(names_path.read_text()).items():
            if k.startswith("0x") and isinstance(v, dict):
                names[int(k, 16)] = f"{v.get('ns', '')}::{v.get('name', '')}".strip(":")
    b = Binary()
    md = disassembler()
    pieces = collections.defaultdict(list)
    for lo, hi, root in zip(b.piece_starts, b.piece_ends, b.piece_root):
        pieces[root].append((lo, hi))

    def body(t: int) -> list:
        out = []
        for lo, hi in pieces.get(t, ()):
            out += list(md.disasm_lite(bytes(b.image[b.off(lo):b.off(hi)]), lo))
        return out

    def reads_args(t: int) -> bool:
        """any stack argument read (or the frame's address taken), or a jump on through a pointer"""
        for _x, _s, mn, ops in body(t):
            if ARG_READ.search(ops) and not ops.startswith("esp,") or (mn == "jmp" and not ops.startswith("0x")):
                return True
        return False

    def forwarder(f: int, t: int) -> bool:
        """f tail-jumps to t, or through a pointer (`jmp edx`, `jmp [eax]`, no switch table's)"""
        return any(mn == "jmp" and ((not ops.startswith("0x") and "*" not in ops) or ops == hex(t))
                   for _x, _s, mn, ops in body(f))

    def both_ways(site: int) -> bool:
        """`push ecx` the last instruction but the slot's load before the call, ecx unwritten after it"""
        f = b.func_containing(site)
        ins = [x for x in body(f) if x[0] < site][-4:] if f is not None else []
        for x, _s, mn, ops in reversed(ins):
            if mn == "push":
                return ops == "ecx"
            if re.match(r"(ecx|cx|cl)\b", ops) or mn == "call":
                return False
        return False

    bad: dict[str, list] = collections.defaultdict(list)
    harmless: dict[str, list] = collections.defaultdict(list)
    agree = 0
    for site, targets in sorted(seen.items(), key=lambda kv: int(kv[0], 16)):
        cc = sites.get("cc", {}).get(site)
        words = len(sites.get("calls", {}).get(site, [])) - (1 if cc == "__thiscall" else 2 if cc == "__fastcall" else 0)
        if cc is None:
            continue
        for t in targets:
            p = protos.get(t)
            if p is None:
                continue
            tcc = p.get("cc")
            # (what matters on x64: whether ecx comes first; a custom one of ecx alone is __thiscall)
            site_this = cc in ("__thiscall", "__fastcall")
            t_this = tcc in ("__thiscall", "__fastcall") or (tcc == "custom" and "ecx" in p.get("regs", []))
            if site_this == t_this:
                agree += 1
                continue
            # (harmless: a target of no parameters at all, given a spare ecx it never reads)
            if site_this and not p.get("params"):
                agree += 1
                continue
            kind = f"site {cc}, target {tcc}"
            row = (site, t, words, p.get("stack", 0) // 4)
            ti = int(t, 16)
            if site_this and not reads_args(ti):
                harmless[kind + ": target reads no argument"].append(row)
            elif site_this and both_ways(int(site, 16)):
                harmless[kind + ": context passed both ways"].append(row)
            elif any(x != t and x in protos and forwarder(int(x, 16), ti) for x in targets):
                harmless[kind + ": a forwarder's tail-jump destination"].append(row)
            else:
                bad[kind].append(row)
    total = sum(len(v) for v in bad.values())
    print(f"{total} (site, target) pairs disagree on ecx" + (f", {agree} agree" if a.all else ""))
    for title, groups in (("", bad), ("not harmful: ", harmless)):
        for kind, rows in sorted(groups.items(), key=lambda kv: -len(kv[1])):
            print(f"  {len(rows)}  {title}{kind}")
            for site, t, w, tw in rows[:12]:
                n = names.get(int(t, 16), "")
                print(f"      {site} -> {t} {n}  (site {w} stack words, target {tw})")
            if len(rows) > 12:
                print(f"      ... {len(rows) - 12} more")
    # (the count again last, the line a pipeline's log shows of the step)
    print(f"{total} (site, target) pairs disagree on ecx")


if __name__ == "__main__":
    main()
