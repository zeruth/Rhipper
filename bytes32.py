"""Byte-level fidelity of a 32-bit project's translation: the translated C built as x86, and each
function's machine code compared with the reference function's, addresses masked on both sides.

fidelity32.py compares what a function does (its calls, fields, constants) against the x64 port;
x64 code can never match x86 bytes. Here the same C is compiled for the reference's own
architecture (MSVC's x86 cl, /O2 /Gy /arch:IA32 for the reference's x87 floating point, the shadow
trace compiled out: GEN_FIDELITY), so the closer
the translation is to the source the reference was built from, the closer the bytes come:

  same    the masked bytes are identical (every absolute address and relative branch target the
          only difference)
  sim     the instruction streams' similarity, 0..1: difflib's ratio over each instruction's
          mnemonic and operands, addresses masked; how much of the reference's code the
          translation's matches in order
  size    the translation's length against the reference's

The reference was built by its own toolchain (toolchain.py: a VS2010 client's 16.00); this build
uses the newest x86 cl, whose code generation differs too, so `same` is a ceiling to work toward
and `sim` the measure to move. A stub scores 0.

    python bytes32.py                  build (cached by each file's time) and compare: totals, the
                                       25 lowest, the distribution
    python bytes32.py --show 0x4cf410  one function side by side
    python bytes32.py --json           also build/bytes32.json, every function's scores

Writes build/x86obj/ (the objects) and build/bytes32.txt (the report).
"""
from __future__ import annotations

import argparse
import difflib
import json
import os
import re
import struct
import subprocess
import sys
from pathlib import Path

import capstone

from pebin import FACTS, Binary
from project import BUILD, GEN, ROOT

HERE = Path(__file__).resolve().parent
OBJ = BUILD / "x86obj"
VCVARS = os.environ.get("RHIPPER_VCVARS32", "")


def vcvars32() -> str:
    """The newest Visual Studio's vcvars32.bat (RHIPPER_VCVARS32 to choose another)."""
    if VCVARS:
        return VCVARS
    roots = [Path("C:/Program Files/Microsoft Visual Studio"), Path("C:/Program Files (x86)/Microsoft Visual Studio")]
    # (the install whose MSVC tools are newest, by the version file beside vcvars: folder names
    # are no order, "18" newer than "2022")
    def version(p: Path) -> tuple:
        v = p.parent / "Microsoft.VCToolsVersion.default.txt"
        return tuple(int(x) for x in v.read_text().split()[0].split(".")) if v.exists() else ()
    found = sorted((p for r in roots if r.exists() for p in r.glob("*/*/VC/Auxiliary/Build/vcvars32.bat")),
                   key=version, reverse=True)
    if not found:
        sys.exit("bytes32: no vcvars32.bat (set RHIPPER_VCVARS32)")
    return str(found[0])


def cl_env() -> dict[str, str]:
    """vcvars32's environment, captured once (a batch file: cmd /c with a quoted path in one
    argument came out escaped, \\"...\\"); vswhere, which it calls, is in the installer's folder."""
    bat = OBJ / "env.bat"
    inst = "C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer"
    bat.write_text(f'@echo off\r\nset "PATH=%PATH%;{inst}"\r\ncall "{vcvars32()}" >nul\r\nset\r\n', encoding="utf-8")
    r = subprocess.run(["cmd", "/c", str(bat)], capture_output=True, text=True, errors="replace")
    env = dict(line.split("=", 1) for line in r.stdout.splitlines() if "=" in line)
    if "VCToolsInstallDir" not in env:
        sys.exit("bytes32: vcvars32 gave no compiler environment:\n" + (r.stdout + r.stderr)[-1500:])
    return env


def build(jobs: int) -> list[Path]:
    """Every translated_*.c compiled for x86 into build/x86obj, the ones newer than their object."""
    OBJ.mkdir(parents=True, exist_ok=True)
    srcs = sorted(GEN.glob("translated_*.c"))
    # (an empty object is a compile that died, the compiler's internal error on one file: built again)
    stale = [s for s in srcs if not (OBJ / (s.stem + ".obj")).exists() or (OBJ / (s.stem + ".obj")).stat().st_size < 20
             or (OBJ / (s.stem + ".obj")).stat().st_mtime < max(s.stat().st_mtime, (GEN / "translated.h").stat().st_mtime)]
    if stale:
        print(f"bytes32: compiling {len(stale)} of {len(srcs)} files for x86", flush=True)
        env = cl_env()
        # (the compiler by the captured PATH: CreateProcess searches the parent's, not env's)
        import shutil
        cl = shutil.which("cl", path=env.get("Path") or env.get("PATH"))
        # (one cl to a file, several at once: /MP's batch died whole when one file hit the
        # compiler's internal error, 181 files unbuilt)
        from concurrent.futures import ThreadPoolExecutor

        def one(s: Path) -> str:
            # (/arch:IA32: x87 floating point, as the reference's VS2010 build; the newest cl's
            # x86 default is SSE2, and every float function compared as 0)
            r = subprocess.run([cl, "/nologo", "/c", "/O2", "/Gy", "/arch:IA32", "/std:c17", "/w", "/DGEN_FIDELITY",
                                f"/I{HERE / 'runtime32'}", f"/I{GEN}", f"/Fo{OBJ / (s.stem + '.obj')}", str(s)],
                               cwd=OBJ, env=env, capture_output=True, text=True, errors="replace")
            return "" if r.returncode == 0 else f"{s.name}: " + " | ".join(
                l.strip() for l in r.stdout.splitlines() if "error" in l)[:300]
        with ThreadPoolExecutor(jobs) as ex:
            errs = [e for e in ex.map(one, stale) if e]
        for e in errs:
            print("  " + e)
    built = [OBJ / (s.stem + ".obj") for s in srcs
             if (OBJ / (s.stem + ".obj")).exists() and (OBJ / (s.stem + ".obj")).stat().st_size >= 20]
    if len(built) < len(srcs):
        print(f"bytes32: {len(srcs) - len(built)} files did not build for x86; their functions are not compared")
    return built


def coff_functions(path: Path) -> dict[int, tuple[bytes, set[int]]]:
    """{reference address: (code, offsets of relocated bytes)} for each F_<addr> in an x86 object
    built with /Gy (one function to a COMDAT section)."""
    data = path.read_bytes()
    _m, nsec, _t, symptr, nsym, opt, _c = struct.unpack_from("<HHIIIHH", data, 0)
    secs = []
    for i in range(nsec):
        (_n, _vs, _va, size, raw, relptr, _ln, nrel, _nln, _ch) = struct.unpack_from("<8sIIIIIIHHI", data, 20 + opt + 40 * i)
        relocs = set()
        for k in range(nrel):
            off, _sym, typ = struct.unpack_from("<IIH", data, relptr + 10 * k)
            # (dir32 and rel32: four bytes either way)
            relocs.update(range(off, off + 4))
        secs.append((raw, size, relocs))
    strtab = symptr + 18 * nsym
    out = {}
    i = 0
    while i < nsym:
        name8, value, secnum, typ, cls, naux = struct.unpack_from("<8sIhHBB", data, symptr + 18 * i)
        if name8[:4] == b"\0\0\0\0":
            off = struct.unpack_from("<I", name8, 4)[0]
            name = data[strtab + off:data.index(b"\0", strtab + off)].decode("latin1")
        else:
            name = name8.rstrip(b"\0").decode("latin1")
        m = re.fullmatch(r"_?F_([0-9a-f]{8})(?:@\d+)?", name)
        if m and secnum > 0 and cls == 2:
            raw, size, relocs = secs[secnum - 1]
            code = data[raw + value:raw + size]
            out[int(m.group(1), 16)] = (code, {r - value for r in relocs if r >= value})
        i += 1 + naux
    return out


def tokens(md, code: bytes, base: int, masked: set[int], lo: int, hi: int) -> tuple[list[str], bytes]:
    """Each instruction as `mnemonic operands`, addresses masked; and the masked bytes. An
    address is a relocated word (`masked`, offsets in `code`), or a branch's target."""
    toks, mb = [], bytearray(code)
    for i in masked:
        if 0 <= i < len(mb):
            mb[i] = 0
    for ins in md.disasm(code, base):
        if ins.mnemonic == "int3":
            break
        s = f"{ins.mnemonic} {ins.op_str}"
        off = ins.address - base
        if ins.id == 0:                       # (a byte that does not decode, skipped as data)
            toks.append(s)
            continue
        if ins.group(capstone.CS_GRP_JUMP) or ins.group(capstone.CS_GRP_CALL):
            for k in range(off + 1, off + ins.size):
                mb[k] = 0
            s = ins.mnemonic + (" L" if re.fullmatch(r"0x[0-9a-f]+", ins.op_str) else " " + ins.op_str)
        if any(off <= r < off + ins.size for r in masked):
            s = re.sub(r"0x[0-9a-f]{5,}", "A", s)
        toks.append(s)
        if ins.mnemonic in ("ret", "retn") and ins.address + ins.size >= hi:
            break
    return toks, bytes(mb)


_MD = None


def compare(task) -> tuple[dict, str]:
    """One function's scores (a worker process's, its own disassembler), and its side-by-side if asked."""
    global _MD
    if _MD is None:
        _MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        _MD.detail = True
        _MD.skipdata = True
    row, rcode, lo, hi, rmask, pcode, prel, show = task
    rt, rb = tokens(_MD, rcode, lo, rmask, lo, hi)
    pt, pb = tokens(_MD, pcode, 0, prel, 0, len(pcode))
    sm = difflib.SequenceMatcher(None, rt, pt, autojunk=False)
    sim = sm.ratio() if rt and pt else 0.0
    same = rb.rstrip(b"\xcc") == pb.rstrip(b"\xcc")
    row.update(kind="same" if same else "translated", sim=round(sim, 4), same=same,
               size=round(len(pb.rstrip(b"\xcc")) / max(1, len(rb.rstrip(b"\xcc"))), 3), port_size=len(pcode))
    text = ""
    if show:
        out = [f"== {row['addr']:08x} {row['name']}: sim {sim:.3f}, size {row['size']}"]
        for op, i1, i2, j1, j2 in sm.get_opcodes():
            for k in range(max(i2 - i1, j2 - j1)):
                l = rt[i1 + k] if i1 + k < i2 else ""
                r = pt[j1 + k] if j1 + k < j2 else ""
                out.append(f"  {'=' if op == 'equal' else '|'} {l:42s} {r}")
        text = "\n".join(out)
    return row, text


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--show", nargs="*", default=[])
    ap.add_argument("--limit", type=int, default=25)
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-build", action="store_true", help="compare the objects already built")
    a = ap.parse_args()
    objs = (sorted(o for o in OBJ.glob("translated_*.obj") if o.stat().st_size >= 20) if a.no_build
            else build(a.jobs))
    port: dict[int, tuple[bytes, set[int]]] = {}
    for o in objs:
        port.update(coff_functions(o))
    b = Binary()
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    md.skipdata = True
    # (the reference's relocated words: the image's base relocations)
    relocs = {va + k for va in b.relocs() for k in range(4)}
    show = {int(s, 16) for s in a.show}
    funcs = json.load(open(FACTS / "functions.json"))["functions"]
    stubs = json.load(open(GEN / "manifest.json"))["stubs"]
    rows, tasks = [], []
    for f in funcs:
        ent = int(f["entry"], 16)
        rng = next(((int(lo, 16), int(hi, 16)) for lo, hi in f.get("ranges", []) if int(lo, 16) <= ent < int(hi, 16)), None)
        if rng is None or f.get("thunk"):
            continue
        lo, hi = rng
        row = {"addr": ent, "name": f["name"], "ref_size": hi - lo}
        if f"{ent:08x}" in stubs or ent not in port:
            row.update(kind="stub" if f"{ent:08x}" in stubs else "absent", sim=0.0, same=False, size=0.0)
            rows.append(row)
            continue
        rcode = bytes(b.image[b.off(lo):b.off(hi)])
        pcode, prel = port[ent]
        tasks.append((row, rcode, lo, hi, {va - lo for va in range(lo, hi) if va in relocs}, pcode, prel, ent in show))
    # (the comparisons in parallel: difflib over 87k functions' instructions took minutes on one)
    from multiprocessing import Pool
    with Pool(a.jobs) as pool:
        for row, shown in pool.imap_unordered(compare, tasks, chunksize=64):
            rows.append(row)
            if shown:
                print(shown)
    n = len(rows)
    tr = [r for r in rows if r["kind"] in ("same", "translated")]
    same = sum(r["same"] for r in rows)
    w = sum(r["ref_size"] for r in rows)
    lines = [f"bytes32: {n} reference functions, {len(tr)} compared ({n - len(tr)} stubs or not built)",
             f"  byte-identical (addresses masked): {same} ({100 * same / max(1, n):.2f}%)",
             f"  mean similarity: {sum(r['sim'] for r in rows) / max(1, n):.4f} over all, "
             f"{sum(r['sim'] for r in tr) / max(1, len(tr)):.4f} over the compared; "
             f"by size {sum(r['sim'] * r['ref_size'] for r in rows) / max(1, w):.4f}",
             f"  median size ratio: {sorted(r['size'] for r in tr)[len(tr) // 2] if tr else 0}"]
    buckets = [0] * 11
    for r in tr:
        buckets[min(10, int(r["sim"] * 10))] += 1
    lines.append("  similarity: " + "  ".join(f"{k / 10:.1f}+ {c}" for k, c in enumerate(buckets)))
    lines.append(f"\nlowest {a.limit} compared (by reference size, the larger first among equals):")
    for r in sorted(tr, key=lambda r: (r["sim"], -r["ref_size"]))[:a.limit]:
        lines.append(f"  {r['addr']:08x} sim {r['sim']:.3f} size {r['size']:5.2f} {r['ref_size']:6d}B  {r['name'][:60]}")
    text = "\n".join(lines)
    print(text)
    (BUILD / "bytes32.txt").write_text(text + "\n", encoding="utf-8")
    if a.json:
        (BUILD / "bytes32.json").write_text(json.dumps(rows), encoding="utf-8")


if __name__ == "__main__":
    main()
