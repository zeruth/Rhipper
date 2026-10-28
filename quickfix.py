"""A fix to a few functions through Ghidra, the translation and the build in minutes, not a full
pipeline's 25: the functions decompiled again with the facts as they are now (ghidra.sh sample,
the facts applied and only these exported), merged into the corpus, translated again, and
spliced into the generated C where they are (a translated block, or a stub's line), with
translated.h's prototype and the manifest kept in step. Run from the project (or with
RHIPPER_PROJECT), after the facts tool that changed them (protos32.py ...):

    python quickfix.py 9d7230 4afe10           those functions
    python quickfix.py 9d7230 --callers        and every function that calls one of them (a
                                               changed signature changes its callers' C)
    python quickfix.py 9d7230 --no-ghidra      the corpus as it is (a translate32 change)
    python quickfix.py 9d7230 --build          and build the port after

A full pipeline is still the record (src/gen is committed only after one): this is the loop
between, where a call-site fix for one constructor took a 25-minute run to see (2026-10-28).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import project  # noqa: E402
import translate32  # noqa: E402

ROOT = project.ROOT
GEN = translate32.GEN
CORPUS = ROOT / "build" / "corpus.jsonl"
GIT_BASH = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Git" / "bin" / "bash.exe"


def callers_of(addrs: set[int]) -> set[int]:
    """the functions whose decompilation calls one of addrs by name (FUN_ or F_ form)"""
    pat = re.compile(r"\b(?:FUN|F)_00(" + "|".join(f"{a:06x}" for a in addrs) + r")\b")
    out = set()
    with open(CORPUS, encoding="utf-8") as f:
        for line in f:
            e = json.loads(line)
            if pat.search(e.get("c") or ""):
                out.add(int(e["addr"], 16))
    return out - addrs


def decompile(addrs: list[int]) -> None:
    """ghidra.sh sample: the facts applied, these exported; merged into the corpus in place"""
    lst = ROOT / "build" / "quickfix-list.txt"
    out = ROOT / "build" / "quickfix-corpus.jsonl"
    lst.write_text("".join(f"{a:x}\n" for a in addrs))
    if out.exists():
        out.unlink()
    r = subprocess.run([str(GIT_BASH), str(HERE / "ghidra" / "ghidra.sh"), "sample", str(lst), str(out)],
                       cwd=ROOT, capture_output=True, text=True)
    if not out.exists() or not out.stat().st_size:
        sys.exit(f"quickfix: Ghidra exported nothing (build/ghidra-last.log)\n{r.stdout[-2000:]}")
    new = {}
    for line in out.read_text(encoding="utf-8").splitlines():
        if line.strip():
            e = json.loads(line)
            new[e["addr"]] = line
    tmp = CORPUS.with_suffix(".jsonl.quick")
    n = 0
    with open(CORPUS, encoding="utf-8") as f, open(tmp, "w", encoding="utf-8") as w:
        for line in f:
            a = json.loads(line)["addr"]
            if a in new:
                line = new.pop(a) + "\n"
                n += 1
            w.write(line)
        for line in new.values():                      # (a function the corpus lacked)
            w.write(line + "\n")
            n += 1
    os.replace(tmp, CORPUS)
    print(f"quickfix: {n} functions decompiled again into the corpus")


def stub_line(t, a: int) -> str:
    """the stub as translate32.emit writes it"""
    d = t.stub_decl(a)
    ret = d.split(f"F_{a:08x}")[0].strip()
    ps = d[d.index("(") + 1:d.rindex(")")].split(", ")
    args = [re.search(r"\bgen_a\d+\b", p).group(0) if p.startswith("unsigned int gen_a") else "0u"
            for p in ps[:4] if p not in ("void", "...")]
    ret = re.sub(r"\s*\bGEN_(?:THIS|STD|FAST)CALL\b", "", ret)
    args += ["0u"] * (4 - len(args))
    body = "GEN_ENTER(0x%xu, %s); GenUnimplemented(0x%x);" % (a, ", ".join(args), a)
    r = "" if ret == "void" else " return 0;"
    if ret != "void" and "*" not in ret and ret.split()[-1] in translate32.FLOATS:
        r = " return 0.0;"
    return f"{d} {{ {body}{r} }}"


def block_span(text: str, a: int) -> tuple[int, int] | None:
    """where the translated function's block is in a gen file: its `/* ref:` line to the next's"""
    m = re.search(r"^/\* ref: .* \*/\n[^\n]*?\bF_%08x\(" % a, text, re.M)
    if not m:
        return None
    nxt = text.find("\n/* ref: ", m.start() + 1)
    return m.start(), (nxt + 1 if nxt >= 0 else len(text))


def splice(t, addrs: list[int]) -> list[Path]:
    files = sorted(GEN.glob("translated_*.c"))
    texts = {p: p.read_text(encoding="utf-8") for p in files}
    stubs = (GEN / "stubs.c").read_text(encoding="utf-8").split("\n")
    header = (GEN / "translated.h").read_text(encoding="utf-8").split("\n")
    manifest = json.loads((GEN / "manifest.json").read_text(encoding="utf-8"))
    touched: set[Path] = set()
    for a in addrs:
        _a, ok, text = t.translate_one(a)
        name = f"F_{a:08x}("
        where = next((p for p in files if name in texts[p] and block_span(texts[p], a)), None)
        si = next((k for k, l in enumerate(stubs) if f" {name}" in l or l.startswith(name)), None)
        if ok:
            block = text.strip() + "\n\n"
            if where is not None:
                s, e = block_span(texts[where], a)
                old = texts[where][s:e]
                if old.strip() == text.strip():
                    print(f"  {a:08x} unchanged")
                    continue
                texts[where] = texts[where][:s] + block + texts[where][e:]
            else:
                # (a stub translated now: into the smallest file, its line out of stubs.c)
                where = min(files, key=lambda p: len(texts[p]))
                texts[where] = texts[where].rstrip("\n") + "\n" + block
                if si is not None:
                    del stubs[si]
                manifest["stubs"].pop(f"{a:08x}", None)
            touched.add(where)
            print(f"  {a:08x} translated -> {where.name}")
        else:
            why = text.splitlines()[0] if text else "?"
            if where is not None:
                s, e = block_span(texts[where], a)
                texts[where] = texts[where][:s] + texts[where][e:]
                touched.add(where)
            line = stub_line(t, a)
            if si is not None:
                stubs[si] = line
            else:
                stubs.insert(len(stubs) - 1 if stubs and not stubs[-1] else len(stubs), line)
            manifest["stubs"][f"{a:08x}"] = why
            print(f"  {a:08x} STUB: {why[:100]}")
        # (its prototype, which a changed signature changes)
        hi = next((k for k, l in enumerate(header) if name in l and l.rstrip().endswith(";")), None)
        decl = t.stub_decl(a) + ";"
        if hi is not None and header[hi] != decl:
            header[hi] = decl
    manifest["stubbed"] = len(manifest["stubs"])
    for p in touched:
        p.write_text(texts[p], encoding="utf-8")
    (GEN / "stubs.c").write_text("\n".join(stubs), encoding="utf-8")
    (GEN / "translated.h").write_text("\n".join(header), encoding="utf-8")
    (GEN / "manifest.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    print(f"quickfix: {len(touched)} gen files changed, {manifest['stubbed']} stubs")
    return sorted(touched)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("addrs", nargs="+", type=lambda s: int(s, 16))
    ap.add_argument("--callers", action="store_true", help="and the functions that call them")
    ap.add_argument("--no-ghidra", action="store_true", help="translate from the corpus as it is")
    ap.add_argument("--build", action="store_true", help="build the port after")
    a = ap.parse_args()
    addrs = set(a.addrs)
    if a.callers:
        addrs |= callers_of(addrs)
    addrs = sorted(addrs)
    print(f"quickfix: {len(addrs)} functions")
    if not a.no_ghidra:
        decompile(addrs)
    t = translate32.Translator32()
    splice(t, addrs)
    if a.build:
        b = json.loads((ROOT / "rhipper.json").read_text()).get("build", {})
        r = subprocess.run(["cmake", "--build", str(ROOT / b.get("dir", "build/cmake")), "--config",
                            b.get("config", "Release")], capture_output=True, text=True)
        errs = [l for l in r.stdout.splitlines() if " error " in l]
        print("\n".join(errs[:20]) or r.stdout.strip().splitlines()[-1])
        sys.exit(r.returncode)


if __name__ == "__main__":
    main()
