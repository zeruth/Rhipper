"""The functions the corpus export spent its time on, slowest first: each corpus line's "ms"
(ExportDecompAll, the decompile's own time), and the first pass's failures, which reach the corpus
only through their retry, from build/ghidra-export.log's `took` lines.

The times are wall-clock under the export's load (every core decompiling), so they rank the
functions rather than measure them: replay one alone with ghidra/DebugDecompile.java and the
decompiler console (decomp_dbg) to see where its time goes.

    python decomptimes.py [--top 40]
"""
from __future__ import annotations

import argparse
import json
import re

import project


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--top", type=int, default=40)
    args = ap.parse_args()
    rows: dict[str, dict] = {}
    total = 0
    with open(project.CORPUS, encoding="utf-8", errors="replace") as f:
        for line in f:
            if '"ms":' not in line[:600]:
                continue
            e = json.loads(line)
            total += e["ms"]
            rows[e["addr"]] = {"ms": e["ms"], "size": e["size"], "name": e["name"],
                               "error": (e.get("error") or "").strip().split("\n")[0]}
    if not rows:
        raise SystemExit(f"{project.CORPUS}: no decompile times (an export from before ExportDecompAll kept them)")
    # (a first-pass failure: its time there too, and why, beside its retry's)
    log = project.BUILD / "ghidra-export.log"
    first = {}
    if log.exists():
        for m in re.finditer(r"ExportDecompAll: took ([0-9a-f]+) \((\d+) bytes\) (\d+)s(?:, failed: (.*?))?\s*\(GhidraScript\)",
                             log.read_text(encoding="utf-8", errors="replace")):
            first[m.group(1)] = (int(m.group(3)) * 1000, m.group(4))
    for a, (ms, why) in first.items():
        if why is not None:
            r = rows.setdefault(a, {"ms": 0, "size": 0, "name": "", "error": ""})
            r["first"] = f"first pass {ms // 1000}s: {why}"
            r["ms"] += ms
            total += ms
    ranked = sorted(rows.items(), key=lambda kv: -kv[1]["ms"])
    top = ranked[:args.top]
    share = sum(r["ms"] for _a, r in top)
    print(f"{len(rows)} functions, {total / 1000:.0f} s of decompiling; the {len(top)} slowest "
          f"{share / 1000:.0f} s ({100 * share / max(total, 1):.1f}%)")
    for a, r in top:
        note = r.get("first") or r["error"]
        print(f"{r['ms'] / 1000:8.1f}s  {a:>8}  {r['size']:6} bytes  {r['name'][:40]:40}  {note[:70]}")


if __name__ == "__main__":
    main()
