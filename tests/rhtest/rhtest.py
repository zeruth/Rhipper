"""rhtest: Rhipper against a program built from source.

src/rhtest.c is compiled with MSVC (x86, /MD) once per variant, each variant a Rhipper project of
its own (<variant>/rhipper.json): O2 and Od. The reference's own output is the expectation; the
whole pipeline runs on it, the port is built against runtime32, and the port's output must match.

    python rhtest.py                     every step, every variant
    python rhtest.py --variant O2        one variant
    python rhtest.py --level 1           the program's level (src/rhtest.c), default 2
    python rhtest.py --from translate    resume from a step: ref, import, facts, ghidra,
                                         translate, port, run
    python rhtest.py --only run          one step

Per variant it writes ref/ (the reference, its map file, expected.txt), build/ (facts, corpus,
the port's build), gen/ (the translation) and build/actual.txt, build/port-stderr.txt.
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
RHIPPER = HERE.parents[1]
SRC = HERE / "src" / "rhtest.c"
GIT_BASH = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Git" / "bin" / "bash.exe"

VARIANTS = {
    "O2": ["/O2"],
    "Od": ["/Od"],
}
STEPS = ["ref", "import", "facts", "ghidra", "translate", "port", "run"]

_envs: dict[str, dict] = {}


def msvc_env(arch: str) -> dict:
    """vcvars32 / vcvars64's environment, captured once each."""
    if arch not in _envs:
        vswhere = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Microsoft Visual Studio/Installer/vswhere.exe"
        vs = subprocess.run([str(vswhere), "-latest", "-property", "installationPath"],
                            capture_output=True, text=True).stdout.strip()
        bat = Path(vs) / f"VC/Auxiliary/Build/vcvars{arch}.bat"
        out = subprocess.run(f'"{bat}" >nul 2>nul && set', shell=True, capture_output=True, text=True).stdout
        _envs[arch] = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    return _envs[arch]


def run(cmd: list[str], cwd: Path, env: dict | None = None, log: Path | None = None, tail: int = 0) -> int:
    """Runs a step's command; its output to a log (and its last lines shown) or to the console."""
    t0 = time.time()
    if log:
        with open(log, "w", encoding="utf-8", errors="replace") as f:
            r = subprocess.run(cmd, cwd=cwd, env=env, stdout=f, stderr=subprocess.STDOUT)
        lines = log.read_text(encoding="utf-8", errors="replace").splitlines()
        for line in lines[-tail:] if tail else []:
            print(f"    {line}")
    else:
        r = subprocess.run(cmd, cwd=cwd, env=env)
    print(f"    ({time.time() - t0:.0f}s, exit {r.returncode})")
    return r.returncode


class Variant:
    def __init__(self, name: str, level: int):
        self.name = name
        self.level = level
        self.root = HERE / name
        self.ref = self.root / "ref"
        self.exe = self.ref / "rhtest.exe"
        self.build = self.root / "build"
        self.config = json.loads((self.root / "rhipper.json").read_text(encoding="utf-8"))
        # every tool finds its project from here
        self.env = {**os.environ, "RHIPPER_PROJECT": str(self.root)}

    # ---- steps ------------------------------------------------------------------------------
    def step_ref(self) -> bool:
        """The reference: x86, /MD, no PDB (Ghidra would read it; a real binary has none), a map
        file for us. /DYNAMICBASE:NO, so it has no relocations either (/FIXED is the default
        then), as many older binaries ship: pebin.py finds the image's pointers itself."""
        self.ref.mkdir(parents=True, exist_ok=True)
        obj = self.build / "ref-obj"
        obj.mkdir(parents=True, exist_ok=True)
        cmd = ["cl", "/nologo", "/MD", "/W3", f"/DRHTEST_LEVEL={self.level}", *VARIANTS[self.name],
               f"/Fo{obj}\\", f"/Fe{self.exe}", str(SRC),
               "/link", "/DYNAMICBASE:NO", "/INCREMENTAL:NO", "/SUBSYSTEM:CONSOLE",
               f"/MAP:{self.ref / 'rhtest.map'}", "kernel32.lib"]
        env = msvc_env("32")
        cl = shutil.which("cl", path=env.get("PATH") or env.get("Path"))
        if run([cl, *cmd[1:]], self.root, env, self.build / "ref-build.log", tail=8) != 0:
            return False
        # the expectation: the reference's own run
        r = subprocess.run([str(self.exe)], capture_output=True, cwd=self.ref)
        text = r.stdout.decode("utf-8", errors="replace").replace("\r\n", "\n")
        (self.ref / "expected.txt").write_text(text + f"exit = {r.returncode}\n", encoding="utf-8")
        print(f"    expected: {len(text.splitlines())} lines, exit {r.returncode}")
        return True

    def gproject(self) -> Path:
        g = self.config["ghidra"]
        return Path(g["projects"]) / f"{g['project']}.gpr"

    def step_import(self) -> bool:
        """Ghidra's import and analysis, again whenever the reference changed since the last."""
        digest = hashlib.sha256(self.exe.read_bytes()).hexdigest()
        stamp = self.build / "imported.sha256"
        if self.gproject().exists() and stamp.exists() and stamp.read_text().strip() == digest:
            print("    (the reference is unchanged since its import)")
            return True
        args = ["import"] + (["--overwrite"] if self.gproject().exists() else [])
        if run([str(GIT_BASH), str(RHIPPER / "ghidra" / "ghidra.sh"), *args], self.root, self.env,
               self.build / "import.log", tail=6) != 0:
            return False
        if not (self.build / "facts" / "functions.json").exists():
            print("    no build/facts/functions.json: the import failed (build/ghidra-import.log)")
            return False
        stamp.write_text(digest)
        return True

    def step_facts(self) -> bool:
        """noreturn.py and protos32.py; while protos32.py finds code no function covers (what only
        a pointer reaches: the CRT's initializer tables), ApplyFacts makes it functions and their
        extents are exported again, so the next round prototypes them."""
        for rnd in range(4):
            for tool, extra in (("noreturn.py", []), ("protos32.py", ["--jobs", "2"])):
                print(f"  {tool}")
                if run([sys.executable, str(RHIPPER / tool), *extra], self.root, self.env,
                       self.build / f"{Path(tool).stem}.log", tail=1) != 0:
                    return False
            log = (self.build / "protos32.log").read_text(encoding="utf-8", errors="replace")
            m = re.search(r"(\d+) code no function covers", log)
            if not m or m.group(1) == "0":
                return True
            print(f"  {m.group(1)} code no function covers: ghidra.sh apply, functions")
            for args in (["apply"], ["functions"]):
                if run([str(GIT_BASH), str(RHIPPER / "ghidra" / "ghidra.sh"), *args], self.root, self.env,
                       self.build / f"ghidra-{args[0]}.log", tail=3) != 0:
                    return False
        print("  (still uncovered code after 4 rounds)")
        return True

    def step_ghidra(self) -> bool:
        return run([str(GIT_BASH), str(RHIPPER / "ghidra" / "ghidra.sh"), "all"], self.root, self.env,
                   self.build / "ghidra-all.log", tail=6) == 0

    def step_translate(self) -> bool:
        return run([sys.executable, str(RHIPPER / "translate32.py"), "--jobs", "4"], self.root, self.env,
                   self.build / "translate.log", tail=8) == 0

    def step_port(self) -> bool:
        out = self.build / "port"
        env = msvc_env("64")
        cmake = shutil.which("cmake")
        if run([cmake, "-S", str(HERE / "port"), "-B", str(out), "-A", "x64",
                f"-DRHTEST_VARIANT={self.root.as_posix()}"], self.root, env, self.build / "port-configure.log") != 0:
            print(f"    see {self.build / 'port-configure.log'}")
            return False
        if run([cmake, "--build", str(out), "--config", "Release", "--", "/m", "/v:minimal"], self.root, env,
               self.build / "port-build.log") != 0:
            log = (self.build / "port-build.log").read_text(encoding="utf-8", errors="replace").splitlines()
            for line in [l for l in log if " error " in l][:15]:
                print(f"    {line.strip()}")
            return False
        return True

    def step_run(self) -> bool:
        port = self.build / "port" / "bin" / "Release" / "rhtest-port.exe"
        env = {**os.environ, "RHTEST_REF": str(self.exe)}
        try:
            r = subprocess.run([str(port)], capture_output=True, cwd=self.ref, env=env, timeout=60)
            out, err, code = r.stdout, r.stderr, r.returncode
        except subprocess.TimeoutExpired as e:
            out, err, code = e.stdout or b"", (e.stderr or b"") + b"\n(timed out)", "timeout"
        actual = out.decode("utf-8", errors="replace").replace("\r\n", "\n") + f"exit = {code}\n"
        err = err.decode("utf-8", errors="replace").replace("\r\n", "\n")
        (self.build / "actual.txt").write_text(actual, encoding="utf-8")
        (self.build / "port-stderr.txt").write_text(err, encoding="utf-8")
        expected = (self.ref / "expected.txt").read_text(encoding="utf-8")
        missing = [l for l in err.splitlines() if "not translated" in l]
        manifest = self.root / "gen" / "manifest.json"
        if manifest.exists():
            m = json.loads(manifest.read_text(encoding="utf-8"))
            print(f"    translated {m['translated']}, stubbed {m['stubbed']}; "
                  f"{len(missing)} untranslated functions reached at run time")
        if actual == expected:
            print(f"    PASS: {len(expected.splitlines())} lines match")
            return True
        print("    FAIL: the port's output differs (build/actual.txt, build/port-stderr.txt)")
        diff = list(difflib.unified_diff(expected.splitlines(), actual.splitlines(), "expected", "actual", lineterm="", n=0))
        for line in diff[:40]:
            print(f"      {line}")
        for line in err.splitlines()[-12:]:
            print(f"    stderr: {line}")
        return False


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--variant", choices=list(VARIANTS), action="append")
    ap.add_argument("--level", type=int, default=2)
    ap.add_argument("--from", dest="start", choices=STEPS, default="ref")
    ap.add_argument("--only", choices=STEPS)
    args = ap.parse_args()
    steps = [args.only] if args.only else STEPS[STEPS.index(args.start):]
    results = {}
    for name in args.variant or list(VARIANTS):
        v = Variant(name, args.level)
        v.build.mkdir(parents=True, exist_ok=True)
        ok = True
        for step in steps:
            print(f"[{name}] {step}")
            if not getattr(v, f"step_{step}")():
                print(f"[{name}] stopped at {step}")
                ok = False
                break
        results[name] = ok
    print("\n" + "  ".join(f"{n}: {'PASS' if ok else 'FAIL'}" for n, ok in results.items()))
    sys.exit(0 if all(results.values()) else 1)


if __name__ == "__main__":
    main()
