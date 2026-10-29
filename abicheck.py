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
"""
from __future__ import annotations

import argparse
import collections
import json

import project

FACTS = project.FACTS


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
    bad: dict[str, list] = collections.defaultdict(list)
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
            bad[kind].append((site, t, words, p.get("stack", 0) // 4))
    total = sum(len(v) for v in bad.values())
    print(f"{total} (site, target) pairs disagree on ecx" + (f", {agree} agree" if a.all else ""))
    for kind, rows in sorted(bad.items(), key=lambda kv: -len(kv[1])):
        print(f"  {len(rows)}  {kind}")
        for site, t, w, tw in rows[:12]:
            n = names.get(int(t, 16), "")
            print(f"      {site} -> {t} {n}  (site {w} stack words, target {tw})")
        if len(rows) > 12:
            print(f"      ... {len(rows) - 12} more")
    # (the count again last, the line a pipeline's log shows of the step)
    print(f"{total} (site, target) pairs disagree on ecx")


if __name__ == "__main__":
    main()
