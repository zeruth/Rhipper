"""The corpus export (ExportDecompAll.java) in K Ghidra sessions at once, each over its own slice
of the address space, into build/corpus.jsonl.new.

One session does not scale past a couple of cores: its decompiler processes spend most of their
time waiting on the Java side, which answers their questions about the program (symbols, types,
signatures) through the program database one at a time. Measured 2026-10-23 on 93k functions:
ten decompilers at 25-30% each and Java at 1.7 cores, 5.4 of 20 cores in all, ~13 minutes. K
sessions have K databases, so K times the answers.

Each session opens its own copy of the project (one project cannot be opened twice), read-only,
after `ghidra.sh all` has applied the facts and saved. The slices are cut where the previous
corpus's function sizes split evenly, so the sessions end together; together they cover the whole
address space, so no function is left out whatever moved since. The heap (rhipper.json
ghidra.maxmem) is shared out between them.

    python ghidra/shards.py [--shards K] [--out build/corpus.jsonl.new]

Exits non-zero, writing nothing, unless every session reported "ExportDecompAll: wrote".
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import project  # noqa: E402

HERE = Path(__file__).resolve().parent
# the functions an export has had to retry with the long limits (one hex address a line): every
# later export decompiles them that way from the start, beside its main pass (ExportDecompAll
# slow=). Grown from each run's "again" lines, never shrunk: a function slow once stays slow
SLOW = project.BUILD / "ghidra-slow.txt"


def remember_slow(log: str) -> int:
    """Adds a run's retried functions to SLOW; how many were new."""
    have = set(SLOW.read_text().split()) if SLOW.exists() else set()
    new = set(re.findall(r"ExportDecompAll: again ([0-9a-f]+) ", log)) - have
    if new:
        SLOW.write_text("".join(f"{a}\n" for a in sorted(have | new)))
    return len(new)


def cuts(k: int) -> list[tuple[int, int]]:
    """k address ranges [lo, hi) covering everything, balanced by the previous corpus's sizes."""
    rows = []
    pat = re.compile(r'"addr":\s*"([0-9a-f]+)".*?"size":\s*(\d+)')
    if project.CORPUS.exists():
        with open(project.CORPUS, encoding="utf-8", errors="replace") as f:
            for line in f:
                m = pat.search(line, 0, 400)
                if m:
                    # (a fixed cost per function, beside its size: a small function still makes
                    # its round trips to the Java side)
                    rows.append((int(m.group(1), 16), int(m.group(2)) + 300))
    rows.sort()
    if not rows or k == 1:
        return [(0, 1 << 64)]
    total = sum(w for _a, w in rows)
    out, lo, acc, i = [], 0, 0, 1
    for a, w in rows:
        if acc >= total * i / k and len(out) < k - 1:
            out.append((lo, a))
            lo, i = a, i + 1
        acc += w
    out.append((lo, 1 << 64))
    return out


def heap_each(k: int) -> str:
    m = re.fullmatch(r"(\d+)([GgMm])", str(project.CONFIG["ghidra"]["maxmem"]))
    mb = int(m.group(1)) * (1024 if m.group(2) in "Gg" else 1) if m else 8192
    return f"{max(1024, mb // k)}M"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--shards", type=int, default=int(project.CONFIG["ghidra"].get("shards", 2)))
    ap.add_argument("--out", type=Path, default=project.BUILD / "corpus.jsonl.new")
    a = ap.parse_args()
    g = project.CONFIG["ghidra"]
    install = Path(project.ghidra_install())
    projects = Path(g["projects"])
    name = g["project"] or project.NAME
    prog = g["program"] or project.EXE.name
    work = project.BUILD / "ghidra-shards"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    ranges = cuts(a.shards)
    heap = heap_each(len(ranges))
    t0 = time.time()
    procs = []
    for k, (lo, hi) in enumerate(ranges):
        d = work / str(k)
        d.mkdir()
        # (the project's lock files stay behind: each copy is its own project)
        shutil.copyfile(projects / f"{name}.gpr", d / f"{name}.gpr")
        shutil.copytree(projects / f"{name}.rep", d / f"{name}.rep")
        out = work / f"corpus.{k}.jsonl"
        log = open(work / f"ghidra.{k}.log", "w", encoding="utf-8", errors="replace")
        env = dict(os.environ, GHIDRA_HEADLESS_MAXMEM=heap)
        cmd = [str(install / "support" / "analyzeHeadless.bat"), str(d), name, "-process", prog, "-noanalysis",
               "-readOnly", "-scriptPath", str(HERE), "-postScript", "ExportDecompAll.java", str(out),
               f"slow={SLOW}",
               # (ExportDecompAll parses the bounds with Long.parseLong: signed, so the open end is
               # the largest signed value, still far past any image address)
               f"{lo:x}", f"{min(hi, (1 << 63) - 1):x}"]
        # (no console input: a session that fails ends in launch.bat's `pause`, which otherwise
        # waits for a key, "Press any key to continue", 2026-10-25)
        procs.append((k, out, log, subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, env=env,
                                                    stdin=subprocess.DEVNULL)))
        print(f"  shard {k}: 0x{lo:x}..0x{hi:x} ({heap} heap)", flush=True)
    print(f"  {len(procs)} sessions started ({time.time() - t0:.0f}s to copy the project)", flush=True)
    failed = []
    for k, out, log, p in procs:
        p.wait()
        log.close()
        text = (work / f"ghidra.{k}.log").read_text(encoding="utf-8", errors="replace")
        wrote = re.search(r"ExportDecompAll: wrote (\d+) functions .* in (\d+)s", text)
        if not wrote or not out.exists():
            failed.append(k)
            print(f"  shard {k}: did not finish (build/ghidra-shards/ghidra.{k}.log)", flush=True)
        else:
            print(f"  shard {k}: {wrote.group(1)} functions in {wrote.group(2)}s", flush=True)
    if failed:
        sys.exit(1)
    n = 0
    with open(a.out, "w", encoding="utf-8", newline="\n") as dst:
        for k, out, _log, _p in procs:
            with open(out, encoding="utf-8") as src:
                for line in src:
                    dst.write(line)
                    n += 1
    # (one log for ghidra.sh's checks, as a single session leaves it)
    logs = "".join((work / f"ghidra.{k}.log").read_text(encoding="utf-8", errors="replace") for k in range(len(procs)))
    with open(project.BUILD / "ghidra-export.log", "w", encoding="utf-8") as f:
        f.write(logs)
        f.write(f"ExportDecompAll: wrote {n} functions to {a.out} in {time.time() - t0:.0f}s\n")
    added = remember_slow(logs)
    if added:
        print(f"  {added} functions newly slow -> {SLOW}", flush=True)
    shutil.rmtree(work, ignore_errors=True)
    print(f"  {n} functions -> {a.out} ({time.time() - t0:.0f}s)", flush=True)


if __name__ == "__main__":
    main()
