"""The whole pipeline of a 32-bit (x86) project, from the binary to its running port, step by step
(pipeline.sh hands an x86 project here). Each step's output is in build/pipeline/<step>.log:

    facts      ghidra.sh functions (the extents, names and import prototypes as Ghidra has them),
               toolchain, noreturn, vtables, srcrefs, protos32 (and ghidra.sh apply-functions while
               protos32 finds code no function covers and the count still falls), helpers32,
               rtti32 (virtual functions named after their classes)
    ghidra     ghidra.sh all: apply the facts, export the data and the corpus
    translate  translate32.py, its rounds until none is demoted
    build      the CMake build of the port (rhipper.json "build"), configured again first
    run        the port (rhipper.json "run": exe, cwd, args), its log; "run.with" side processes
               started first and stopped after (a server it talks to), "run.screenshot" a command
               taking a window capture every 15 s ({out}: the image's path)

    python pipeline32.py [--from STEP] [--only STEP] [--jobs N] [--run-secs S]

Run from inside the project (or with RHIPPER_PROJECT set): project.py finds its rhipper.json.
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

import project

RH = Path(__file__).resolve().parent
ROOT = project.ROOT
OUT = project.BUILD / "pipeline"
STEPS = ["facts", "ghidra", "translate", "build", "run"]
ENV = dict(os.environ, RHIPPER_PROJECT=str(ROOT))
T0 = time.time()


def bash() -> str:
    """Git's bash (`bash` on PATH may be WSL's, which cannot run ghidra.sh's Windows paths)"""
    for p in (r"C:\Program Files\Git\bin\bash.exe", r"C:\Program Files (x86)\Git\bin\bash.exe"):
        if Path(p).exists():
            return p
    return shutil.which("bash") or "bash"


def stamp(msg: str) -> None:
    print(f"[{time.time() - T0:5.0f}s] {msg}", flush=True)


def step(name: str, cmd: list[str], tail: int = 3, cwd: Path = ROOT) -> tuple[int, str]:
    t0 = time.time()
    log = OUT / f"{name}.log"
    with open(log, "w", encoding="utf-8", errors="replace") as f:
        r = subprocess.run(cmd, cwd=cwd, env=ENV, stdout=f, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
    lines = log.read_text(encoding="utf-8", errors="replace").splitlines()
    for line in lines[-tail:] if tail else []:
        print(f"    {line[:220]}")
    print(f"    ({time.time() - t0:.0f}s, exit {r.returncode}) -> {log}", flush=True)
    return r.returncode, "\n".join(lines)


def facts(jobs: int) -> bool:
    py = sys.executable
    # (the function extents, names and import prototypes as Ghidra has them now, first: the last
    # session's renames and the functions made since, which every step below reads)
    stamp("ghidra.sh functions")
    if step("functions", [bash(), str(RH / "ghidra" / "ghidra.sh"), "functions"], tail=1)[0]:
        return False
    for tool in ("toolchain", "noreturn", "vtables", "srcrefs"):
        stamp(tool)
        if step(tool, [py, str(RH / f"{tool}.py")], tail=2)[0]:
            return False
    last = None
    for rnd in range(4):
        stamp(f"protos32 (round {rnd})")
        code, text = step(f"protos32-{rnd}", [py, str(RH / "protos32.py"), "--jobs", str(jobs)], tail=1)
        if code:
            return False
        # (code no function covers, which protos32 finds: Ghidra makes functions of it, and
        # protos32 runs again while the count still falls)
        m = re.search(r"(\d+) code no function covers", text)
        n = int(m.group(1)) if m else 0
        if n == 0 or (last is not None and n >= last):
            break
        last = n
        stamp(f"{n} code no function covers: ghidra.sh apply-functions")
        if step(f"apply-functions-{rnd}", [bash(), str(RH / "ghidra" / "ghidra.sh"), "apply-functions"], tail=2)[0]:
            return False
    stamp("helpers32")
    if step("helpers32", [py, str(RH / "helpers32.py")], tail=1)[0]:
        return False
    # (virtual functions named from RTTI, once Ghidra's functions are final: ghidra.sh all applies them)
    stamp("rtti32")
    return step("rtti32", [py, str(RH / "rtti32.py")], tail=1)[0] == 0


def ghidra(_jobs: int) -> bool:
    stamp("ghidra.sh all")
    code, text = step("ghidra", [bash(), str(RH / "ghidra" / "ghidra.sh"), "all"], tail=4)
    return code == 0 and "wrote build/refdata.jsonl, build/corpus.jsonl" in text


def translate(jobs: int) -> bool:
    stamp("translate32")
    return step("translate32", [sys.executable, str(RH / "translate32.py"), "--jobs", str(jobs)], tail=8)[0] == 0


def build(jobs: int) -> bool:
    stamp("build")
    cfg = project.CONFIG["build"]
    d = str(ROOT / cfg["dir"])
    # (configured again first: the generated file list changes with the translation, and a build
    # linked the last one's object of a file the new translation no longer has beside the new
    # files', LNK2005)
    step("configure", ["cmake", d], tail=1)
    code, text = step("build", ["cmake", "--build", d, "--config", cfg["config"], "--target", cfg["target"],
                                "--", f"/m:{jobs}", "/v:minimal"], tail=3)
    groups: dict[str, int] = {}
    for w in re.findall(r": warning (C\d+)", text):
        groups[w] = groups.get(w, 0) + 1
    print(f"    {sum(groups.values())} warnings {groups}", flush=True)
    return code == 0


def run_port(_jobs: int, secs: int) -> bool:
    stamp("run")
    r = project.CONFIG["run"]
    fill = {"out": str(OUT), "root": str(ROOT)}
    side = [subprocess.Popen([a.format(**fill) for a in cmd], cwd=ROOT, env=ENV, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL) for cmd in r.get("with", [])]
    log = open(OUT / "run.log", "w", encoding="utf-8", errors="replace")
    # (unattended: a message box logged and answered, not left open for no one, the runtime's
    # <ENV>_NODIALOGS; the prefix the project's name, as its CMakeLists gives RHIPPER_ENV)
    env = dict(ENV, **{project.CONFIG.get("env", project.NAME.upper()) + "_NODIALOGS": "1"})
    p = subprocess.Popen([str(ROOT / r["exe"]), *r.get("args", [])], cwd=ROOT / r.get("cwd", "."), env=env,
                         stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
    t0, k = time.time(), 0
    while time.time() - t0 < secs and p.poll() is None:
        time.sleep(min(15, max(1, secs - (time.time() - t0))))
        if p.poll() is None and r.get("screenshot"):
            img = OUT / f"run-{k}.png"
            subprocess.run([a.format(out=str(img), root=str(ROOT)) for a in r["screenshot"]], cwd=ROOT,
                           capture_output=True, timeout=60)
            k += 1
    alive = p.poll() is None
    if alive:
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(p.pid)], capture_output=True)
    for s in side:
        s.kill()
    log.close()
    text = (OUT / "run.log").read_text(encoding="utf-8", errors="replace")
    print("\n".join(f"    {l[:200]}" for l in text.splitlines()[-25:]))
    print(f"    {'still running after' if alive else f'exited, code {p.returncode:#x}, after'} "
          f"{time.time() - t0:.0f}s; {k} screenshots in {OUT}", flush=True)
    return True


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--from", dest="start", default="facts", choices=STEPS)
    ap.add_argument("--only", choices=STEPS)
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--run-secs", type=int, default=90)
    # (pipeline.sh's own options, as it hands them on)
    ap.add_argument("--facts", action="store_true", help="facts only")
    ap.add_argument("--from-ghidra", action="store_true", help="from the Ghidra step")
    a = ap.parse_args()
    if project.ARCH != "x86":
        sys.exit(f"pipeline32: {project.CONFIG_FILE} is an {project.ARCH} project (pipeline.sh)")
    OUT.mkdir(parents=True, exist_ok=True)
    start = "ghidra" if a.from_ghidra else a.start
    steps = ["facts"] if a.facts else [a.only] if a.only else STEPS[STEPS.index(start):]
    fns = {"facts": facts, "ghidra": ghidra, "translate": translate, "build": build,
           "run": lambda j: run_port(j, a.run_secs)}
    for s in steps:
        if not fns[s](a.jobs):
            stamp(f"{s} failed: stopping")
            sys.exit(1)
    stamp("done")


if __name__ == "__main__":
    main()
