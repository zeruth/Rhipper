"""A translate32 change checked on the functions it is about, in seconds, before a pipeline run:
each one translated again against the corpus as it is, nothing written.

    python stubcheck.py --reason "extraout_ECX"     the stubs (manifest.json) whose reason has it:
                                                    how many translate now, the rest's reasons
    python stubcheck.py 4c0790 5584e0               those functions, their C or why not
    python stubcheck.py --reason fpatan --show      and each one's C

Run it from the project, before pushing a translate32 fix: a fix that turns a reason's stubs
into others shows here, not 40 minutes later as a higher stub count (982a7e8's atan2, 47 functions
stubbed again for a name the header lacked, 2026-10-27).
"""
from __future__ import annotations

import argparse
import collections
import json

import translate32


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("addrs", nargs="*", type=lambda s: int(s, 16))
    ap.add_argument("--reason", help="the manifest's stubs whose reason contains this")
    ap.add_argument("--show", action="store_true", help="print each function's C")
    a = ap.parse_args()
    want = list(a.addrs)
    if a.reason:
        stubs = json.load(open(translate32.MANIFEST))["stubs"]
        want += [int(k, 16) for k, why in stubs.items() if a.reason in why]
    if not want:
        ap.error("no functions: give addresses or --reason")
    t = translate32.Translator32()
    ok_now, rest = [], collections.Counter()
    for addr in want:
        _a, ok, text = t.translate_one(addr)
        if a.show or (a.addrs and not a.reason):
            print(f"== {addr:08x} {'translated' if ok else 'STUB'}\n{text}")
        if ok:
            ok_now.append(addr)
        else:
            rest[text.splitlines()[0][:100] if text else "?"] += 1
    print(f"{len(ok_now)} of {len(want)} translate: " + " ".join(f"{x:x}" for x in ok_now[:60])
          + (" ..." if len(ok_now) > 60 else ""))
    for why, n in rest.most_common(15):
        print(f"{n:5d}  {why}")


if __name__ == "__main__":
    main()
