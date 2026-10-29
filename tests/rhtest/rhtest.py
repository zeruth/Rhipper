"""rhtest: Rhipper against programs built from source.

Each program (src/<name>.c or .cpp, linked with src/rhtest_main.c) is small and tests one area;
each is built with MSVC (x86, /MD) once per variant, and each program x variant is a Rhipper project
of its own under work/<name>-<variant>/ (its rhipper.json written here). The reference's own output
is the expectation: the whole pipeline runs on it, the port is built against runtime32, and the port
must print the same lines and exit the same. No build may warn: the reference compiles with
/W4 /WX, and a warning in the port's build (the translation or the runtime) fails the run.

    python rhtest.py                       every program, every variant, every step
    python rhtest.py core int64            some programs
    python rhtest.py float --variant IA32  one variant
    python rhtest.py --from translate      resume from a step: ref, import, facts, ghidra,
                                           translate, port, run (--from import reimports)
    python rhtest.py --only run
    python rhtest.py --jobs 4              more workers per tool (serial by default)
    python rhtest.py --parallel 3          projects at once (1 by default; a full run, the end of
                                           a phase's regression, runs FULL_PARALLEL at once)
    python rhtest.py --toolset msvc-16.00-x86   the references built by another compiler (TOOLSETS)
    python rhtest.py --save-bins           also keep each reference in bins/<toolset>/ (to commit)
    python rhtest.py --bins msvc-14.51-x86 test a toolset's committed references, not a build (CI)

Per project: ref/ (the reference, its map file, expected.txt), build/ (facts, corpus, the port's
build, actual.txt, port-stderr.txt, logs), gen/ (the translation).

A toolset is the compiler that builds the references and their target (TOOLSETS): msvc-14.51-x86,
the newest MSVC, and msvc-16.00-x86, Visual Studio 2010 SP1 as /MT game clients are built. Each has its
projects (work/ for the first, work/<toolset>/ for the others), its Ghidra projects, its report, and
its references as committed, bins/<toolset>/<name>-<variant>/: CI tests those, so its result does
not depend on the runner's compiler. The port is built by the newest MSVC whatever the toolset.

The Ghidra install and projects folder default to this machine's; RHTEST_GHIDRA and
RHTEST_GHIDRA_PROJECTS override them, and RHTEST_VS2010 the Visual Studio 2010 SP1 tools
(README.md: the compiler update and the Windows SDK 7.1, extracted).
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
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
RHIPPER = HERE.parents[1]
SRC = HERE / "src"
WORK = HERE / "work"
BINS = HERE / "bins"
# the committed references to test in place of building them (--bins), and whether a build keeps
# its reference there (--save-bins)
USE_BINS: str | None = None
SAVE_BINS = False
GIT_BASH = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Git" / "bin" / "bash.exe"
GHIDRA = os.environ.get("RHTEST_GHIDRA", "C:/Users/tyler/tools/ghidra_*")
GHIDRA_PROJECTS = os.environ.get("RHTEST_GHIDRA_PROJECTS", "C:/Users/tyler/tools/ghidra-projects")

# build variants: compiler flags, linker flags
VARIANTS = {
    "O2": (["/O2"], []),
    "Od": (["/Od"], []),
    # x87 code: the default builds use SSE2 for floats
    "IA32": (["/O2", "/arch:IA32"], []),
    # whole-program optimization: the compiler's own register conventions between functions
    "GL": (["/O2", "/GL"], ["/LTCG"]),
    # SSE2 floats where a toolset's default is x87 (VS2010: no /arch:IA32, x87 unless asked)
    "SSE2": (["/O2", "/arch:SSE2"], []),
    # a VS2010 game client's own build, as its binary shows it: whole-program optimization (its
    # custom register conventions), frame pointers kept (46,389 of 47,792 functions open `push ebp;
    # mov ebp, esp`), floats in SSE and doubles on the x87 unit (/arch:SSE: 45,124 scalar `ss`
    # instructions to 376 `sd`), the C runtime linked in
    "client": (["/O2", "/Oy-", "/GL", "/arch:SSE"], ["/LTCG"]),
}
# the toolsets: how each builds a reference. vs: which Visual Studio's tools ("latest", vswhere's,
# or "2010", RHTEST_VS2010's); cl: the compiler version it must be; crt and subsystem: the runtime
# and Windows it targets; variants: a program's variant it builds as another (or not at all, None)
TOOLSETS = {
    "msvc-14.51-x86": {"vs": "latest", "cl": "19.51.", "crt": "/MD", "subsystem": "CONSOLE", "variants": {}},
    # (a /MT client's: VS2010 SP1, cl 16.00.40219, the C runtime linked in, for Windows XP. Its
    # floats are x87 by default, so the program built /arch:IA32 elsewhere is the SSE2 one here)
    # (and every program built as the client was too, "extra")
    "msvc-16.00-x86": {"vs": "2010", "cl": "16.00.40219", "crt": "/MT", "subsystem": "CONSOLE,5.01",
                       "variants": {"IA32": "SSE2"}, "extra": ["client"]},
}
DEFAULT_TOOLSET = "msvc-14.51-x86"
# the toolset this run builds and tests (--toolset, --bins)
TOOLSET = DEFAULT_TOOLSET
VS2010 = Path(os.environ.get("RHTEST_VS2010", "C:/Users/tyler/tools/vs2010"))
# program -> (its sources besides rhtest_main.c, its variants)
PROGRAMS = {
    "core": (["core.c"], ["O2", "Od"]),
    "int64": (["int64.c"], ["O2", "Od"]),
    "float": (["float.c"], ["O2", "Od", "IA32"]),
    "calls": (["calls.c"], ["O2", "Od", "GL"]),
    "crt": (["crt.c"], ["O2", "Od"]),
    "cpp": (["cpp.cpp"], ["O2", "Od"]),
    "misc": (["misc.c"], ["O2", "Od"]),
    "eh": (["eh.cpp"], ["O2", "Od"]),
    "win": (["win.c"], ["O2", "Od"]),
    "engine": (["engine.cpp"], ["O2", "Od", "GL"]),
    "sys": (["sys.c"], ["O2", "Od"]),
    "com": (["com.cpp"], ["O2", "Od"]),
    "stl": (["stl.cpp"], ["O2", "Od"]),
    "fpenv": (["fpenv.c"], ["O2", "Od", "IA32"]),
    "seh": (["seh.c"], ["O2", "Od"]),
}
STEPS = ["ref", "import", "facts", "ghidra", "translate", "port", "run", "fidelity", "bytes"]
# workers for the tools that take them (protos32.py, translate32.py, the port's MSBuild): serial
# unless --jobs says otherwise, so a test run leaves the machine usable (Ghidra: one shard)
JOBS = 1
# projects at once in a full run (every program, every variant, every step: the regression at the
# end of a phase). Each holds a Ghidra of 2 GB at most, and 4 fit beside other work on 24 GB
FULL_PARALLEL = 4
WARNING = re.compile(r"\bwarning [A-Z]+\d+|CMake Warning", re.I)

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


def ref_env() -> dict:
    """The environment the toolset's compiler builds a reference in: vcvars32's for the newest,
    and for VS2010 its extracted tools and the Windows SDK 7.1 (with toolsets/<toolset>/include,
    what its install lacks), checked once to be the compiler the toolset names."""
    if "ref" in _envs:
        return _envs["ref"]
    ts = TOOLSETS[TOOLSET]
    if ts["vs"] == "latest":
        env = dict(msvc_env("32"))
    else:
        vs = VS2010 / "sp1" / "Program Files" / "Microsoft Visual Studio 10.0"
        sdk = VS2010 / "sdk" / "Program Files" / "Microsoft SDKs" / "Windows" / "v7.1"
        env = {k: v for k, v in os.environ.items() if k.upper() not in ("PATH", "INCLUDE", "LIB", "LIBPATH")}
        env["PATH"] = os.pathsep.join([str(vs / "VC" / "bin"), str(vs / "Common7" / "IDE"), os.environ.get("PATH", "")])
        env["INCLUDE"] = os.pathsep.join([str(vs / "VC" / "include"), str(sdk / "Include"),
                                          str(HERE / "toolsets" / TOOLSET / "include")])
        env["LIB"] = os.pathsep.join([str(vs / "VC" / "lib"), str(sdk / "Lib")])
    cl = shutil.which("cl", path=env.get("PATH") or env.get("Path"))
    banner = subprocess.run([cl], capture_output=True, text=True, env=env).stderr if cl else ""
    if f"Version {ts['cl']}" not in banner:
        sys.exit(f"rhtest: {TOOLSET} needs cl {ts['cl']}, found {banner.splitlines()[0] if banner else 'no cl'}"
                 + (f" (RHTEST_VS2010: {VS2010})" if ts["vs"] == "2010" else ""))
    _envs["ref"] = env
    return env


def work_dir(toolset: str) -> Path:
    """A toolset's projects: work/ for the default one (as before there were others), work/<toolset>/."""
    return WORK if toolset == DEFAULT_TOOLSET else WORK / toolset


def report_path(toolset: str) -> Path:
    return HERE / "fidelity.html" if toolset == DEFAULT_TOOLSET else work_dir(toolset) / "fidelity.html"


def ghidra_prefix(toolset: str) -> str:
    return "rhtest-" if toolset == DEFAULT_TOOLSET else f"rhtest-{toolset}-"


def variants_of(program: str) -> list[str]:
    """A program's variants as the toolset builds them."""
    swap = TOOLSETS[TOOLSET]["variants"]
    own = [swap.get(v, v) for v in PROGRAMS[program][1] if swap.get(v, v)]
    return own + [v for v in TOOLSETS[TOOLSET].get("extra", []) if v not in own]


def run(cmd: list[str], cwd: Path, env: dict | None, log: Path, tail: int = 0) -> int:
    """Runs a step's command, its output to a log (and its last lines shown)."""
    t0 = time.time()
    with open(log, "w", encoding="utf-8", errors="replace") as f:
        r = subprocess.run(cmd, cwd=cwd, env=env, stdout=f, stderr=subprocess.STDOUT)
    lines = log.read_text(encoding="utf-8", errors="replace").splitlines()
    for line in lines[-tail:] if tail else []:
        print(f"    {line}")
    print(f"    ({time.time() - t0:.0f}s, exit {r.returncode})")
    return r.returncode


def warnings_in(log: Path) -> list[str]:
    return [line.strip() for line in log.read_text(encoding="utf-8", errors="replace").splitlines()
            if WARNING.search(line)]


class Project:
    def __init__(self, program: str, variant: str):
        self.program, self.variant = program, variant
        self.name = f"{program}-{variant}"
        self.root = work_dir(TOOLSET) / self.name
        self.ref = self.root / "ref"
        self.exe = self.ref / f"{program}.exe"
        self.build = self.root / "build"
        self.build.mkdir(parents=True, exist_ok=True)
        self.ref.mkdir(parents=True, exist_ok=True)
        self.gproject = f"{ghidra_prefix(TOOLSET)}{self.name}"
        self.config = {
            "name": self.gproject,
            "exe": f"ref/{program}.exe",
            "arch": "x86",
            # (declared: the toolset built it, whatever toolchain.py reads)
            "toolchain": TOOLSET,
            "image_base": "0x400000",
            "sources": [],
            "gen": "gen",
            "run": {"exe": "build/port/bin/Release/rhtest-port.exe", "cwd": "ref"},
            "ghidra": {"install": GHIDRA, "projects": GHIDRA_PROJECTS, "project": self.gproject,
                       "program": f"{program}.exe", "maxmem": "2G", "shards": 1},
        }
        path = self.root / "rhipper.json"
        text = json.dumps(self.config, indent=2) + "\n"
        if not path.exists() or path.read_text(encoding="utf-8") != text:
            path.write_text(text, encoding="utf-8")
        # every tool finds its project from here
        self.env = {**os.environ, "RHIPPER_PROJECT": str(self.root)}
        self.stubs: dict | None = None
        self.fidelity: dict | None = None
        self.bytes: dict | None = None

    def ghidra_sh(self, *args: str, log: str, tail: int = 4) -> bool:
        # (Ghidra's file cache the project's own, %LOCALAPPDATA%\ghidra: --parallel's projects
        # starting Ghidra at once raced to create the shared one, "Unable to initialize cache dir
        # ... fscache2", and a whole project failed on CI, core-O2 at one commit and core-Od at
        # another, 2026-10-27)
        env = self.env
        if os.name == "nt":
            cache = self.root / "build" / "ghidra-local"
            cache.mkdir(parents=True, exist_ok=True)
            env = {**env, "LOCALAPPDATA": str(cache)}
        return run([str(GIT_BASH), str(RHIPPER / "ghidra" / "ghidra.sh"), *args], self.root, env,
                   self.build / log, tail) == 0

    # ---- steps ----------------------------------------------------------------------------------
    def step_ref(self) -> bool:
        """The reference: x86, the toolset's runtime (/MD, or VS2010's /MT) and Windows, /W4 /WX;
        no PDB (Ghidra would read it; a real binary has none), a map file for reading a failure.
        /DYNAMICBASE:NO, so no relocations either (/FIXED is the default then), as many older
        binaries ship: pebin.py finds the pointers itself. With --bins, the committed reference
        instead (bins/<toolset>/<name>/)."""
        files = [self.exe.name, f"{self.program}.map", "expected.txt"]
        ts = TOOLSETS[TOOLSET]
        if USE_BINS:
            saved = BINS / TOOLSET / self.name
            missing = [f for f in files if not (saved / f).exists()]
            if missing:
                print(f"    no committed {', '.join(missing)} in {saved}")
                return False
            for f in files:
                if not (self.ref / f).exists() or (self.ref / f).read_bytes() != (saved / f).read_bytes():
                    shutil.copyfile(saved / f, self.ref / f)
            print(f"    the committed reference, {TOOLSET}")
            return True
        cflags, lflags = VARIANTS[self.variant]
        obj = self.build / "ref-obj"
        obj.mkdir(parents=True, exist_ok=True)
        srcs = [str(SRC / s) for s in PROGRAMS[self.program][0]] + [str(SRC / "rhtest_main.c")]
        cpp = any(s.endswith(".cpp") for s in srcs)
        env = ref_env()
        cl = shutil.which("cl", path=env.get("PATH") or env.get("Path"))
        cmd = [cl, "/nologo", ts["crt"], "/W4", "/WX", *cflags, *(["/EHsc"] if cpp else []),
               f"/Fo{obj}\\", f"/Fe{self.exe}", *srcs,
               "/link", "/WX", "/DYNAMICBASE:NO", "/INCREMENTAL:NO", f"/SUBSYSTEM:{ts['subsystem']}",
               f"/MAP:{self.ref / (self.program + '.map')}", *lflags, "kernel32.lib"]
        log = self.build / "ref-build.log"
        if run(cmd, self.root, env, log) != 0:
            for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
                if re.search(r"\b(error|warning)\b", line):
                    print(f"    {line.strip()}")
            return False
        r = subprocess.run([str(self.exe)], capture_output=True, cwd=self.ref)
        text = r.stdout.decode("utf-8", errors="replace").replace("\r\n", "\n")
        (self.ref / "expected.txt").write_text(text + f"exit = {r.returncode}\n", encoding="utf-8")
        print(f"    expected: {len(text.splitlines())} lines, exit {r.returncode}")
        if SAVE_BINS:
            saved = BINS / TOOLSET / self.name
            saved.mkdir(parents=True, exist_ok=True)
            for f in files:
                shutil.copyfile(self.ref / f, saved / f)
            print(f"    kept in {saved.relative_to(HERE)}")
        return True

    def step_import(self) -> bool:
        """Ghidra's import and analysis, again whenever the reference changed since the last."""
        digest = hashlib.sha256(self.exe.read_bytes()).hexdigest()
        stamp = self.build / "imported.sha256"
        gpr = Path(GHIDRA_PROJECTS) / f"{self.gproject}.gpr"
        if gpr.exists() and stamp.exists() and stamp.read_text().strip() == digest and not getattr(self, "fresh", False):
            print("    (the reference is unchanged since its import)")
            return True
        # (the stamp goes first: an import stopped after --overwrite removed the program left it
        # matching, and the next run skipped the import and found no program, "Requested project
        # program file(s) not found")
        stamp.unlink(missing_ok=True)
        if not self.ghidra_sh("import", *(["--overwrite"] if gpr.exists() else []), log="import.log"):
            return False
        if not (self.build / "facts" / "functions.json").exists():
            print("    no build/facts/functions.json: the import failed (build/ghidra-import.log)")
            return False
        stamp.write_text(digest)
        return True

    def step_facts(self) -> bool:
        """noreturn.py and protos32.py; while protos32.py finds code no function covers (what only
        a pointer reaches: the CRT's initializer tables), ApplyFacts makes it functions and their
        extents are exported again, so the next round prototypes them. First toolchain.py, whose
        reading of the reference has to agree with the toolset that built it."""
        log = self.build / "toolchain.log"
        if run([sys.executable, str(RHIPPER / "toolchain.py")], self.root, self.env, log) != 0:
            return False
        for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
            if "declares" in line or "no rhtest toolset" in line:
                print(f"    {line}")
        # (the vtables, as a real project has them: protos32.py makes every slot of a class's vtable
        # a __thiscall, the methods that leave `this` alone too. Without them Backend::grab was a
        # __stdcall of two, and the virtual call's `this` its first argument, rhtest msvc-16.00-x86
        # cpp-O2 fronts; a real project's facts had them)
        if run([sys.executable, str(RHIPPER / "vtables.py")], self.root, self.env, self.build / "vtables.log") != 0:
            return False
        for _ in range(4):
            for tool, extra in (("noreturn.py", []), ("protos32.py", ["--jobs", str(JOBS)]), ("helpers32.py", [])):
                if run([sys.executable, str(RHIPPER / tool), *extra], self.root, self.env,
                       self.build / f"{Path(tool).stem}.log") != 0:
                    return False
            log = (self.build / "protos32.log").read_text(encoding="utf-8", errors="replace")
            m = re.search(r"(\d+) code no function covers", log)
            if not m or m.group(1) == "0":
                # (and the static C runtime named by the toolchain's signatures, as a real
                # project's facts step does)
                return run([sys.executable, str(RHIPPER / "crtsigs.py")], self.root, self.env,
                           self.build / "crtsigs.log") == 0
            print(f"    {m.group(1)} code no function covers: ghidra.sh apply, functions")
            if not self.ghidra_sh("apply-functions", log="ghidra-apply.log", tail=0):
                return False
        print("    (still uncovered code after 4 rounds)")
        return True

    def step_ghidra(self) -> bool:
        return self.ghidra_sh("all", log="ghidra-all.log", tail=0)

    def step_translate(self) -> bool:
        ok = run([sys.executable, str(RHIPPER / "translate32.py"), "--jobs", str(JOBS)], self.root, self.env,
                 self.build / "translate.log") == 0
        for line in (self.build / "translate.log").read_text(encoding="utf-8", errors="replace").splitlines():
            if "demoted" in line or ": ok" not in line and ".c:" in line:
                print(f"    {line.strip()}")
        self.report_stubs()
        return ok

    def report_stubs(self) -> None:
        """The stubs and why, against the last run's (build/stubs-prev.json)."""
        manifest = self.root / "gen" / "manifest.json"
        if not manifest.exists():
            return
        m = json.loads(manifest.read_text(encoding="utf-8"))
        prev_path = self.build / "stubs-prev.json"
        prev = json.loads(prev_path.read_text(encoding="utf-8")) if prev_path.exists() else None
        self.stubs = {"translated": m["translated"], "stubbed": m["stubbed"], "stubs": m["stubs"]}
        delta = "" if prev is None else f" ({m['stubbed'] - prev['stubbed']:+d} since the last run)"
        print(f"    translated {m['translated']}, stubbed {m['stubbed']}{delta}")
        for addr, why in sorted(m["stubs"].items()):
            new = "" if prev is None or addr in prev["stubs"] else "  (new)"
            print(f"      {addr}  {why[:100]}{new}")
        if prev:
            for addr in sorted(set(prev["stubs"]) - set(m["stubs"])):
                print(f"      {addr}  translated now (was: {prev['stubs'][addr][:80]})")
        prev_path.write_text(json.dumps(self.stubs, indent=1), encoding="utf-8")

    def step_port(self) -> bool:
        out = self.build / "port"
        env = msvc_env("64")
        cmake = shutil.which("cmake")
        conf = self.build / "port-configure.log"
        if run([cmake, "-S", str(HERE / "port"), "-B", str(out), "-A", "x64",
                f"-DRHTEST_VARIANT={self.root.as_posix()}"], self.root, env, conf) != 0:
            print(f"    see {conf}")
            return False
        log = self.build / "port-build.log"
        code = run([cmake, "--build", str(out), "--config", "Release", "--", f"/m:{JOBS}", "/v:minimal"], self.root, env, log)
        if code != 0:
            for line in [l for l in log.read_text(encoding="utf-8", errors="replace").splitlines() if " error " in l][:15]:
                print(f"    {line.strip()}")
            return False
        # (no warnings: a warning in the translation is a translation problem, README.md)
        warns = sorted(set(warnings_in(conf) + warnings_in(log)))
        if warns:
            print(f"    {len(warns)} warnings in the port's build:")
            for w in warns[:20]:
                print(f"      {w}")
            return False
        return True

    def step_run(self) -> bool:
        port = self.build / "port" / "bin" / "Release" / "rhtest-port.exe"
        # (a hang prints the reference thread's stack after 20 s, runtime32/RefImage.cpp)
        env = {**os.environ, "RHTEST_REF": str(self.exe), "RHTEST_HANGDUMP": "20"}
        # (the port starts itself again, runtime32/Main.cpp: on a timeout the whole tree goes, or
        # the second process kept the pipes open and the run waited on it for good)
        with subprocess.Popen([str(port)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.ref, env=env) as proc:
            try:
                out, err = proc.communicate(timeout=60)
                code = proc.returncode
            except subprocess.TimeoutExpired:
                subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True)
                out, err = proc.communicate()
                err += b"\n(timed out after 60 s)"
                code = "timeout"
        actual = out.decode("utf-8", errors="replace").replace("\r\n", "\n") + f"exit = {code}\n"
        err = err.decode("utf-8", errors="replace").replace("\r\n", "\n")
        (self.build / "actual.txt").write_text(actual, encoding="utf-8")
        (self.build / "port-stderr.txt").write_text(err, encoding="utf-8")
        expected = (self.ref / "expected.txt").read_text(encoding="utf-8")
        missing = [l for l in err.splitlines() if "not translated" in l]
        if actual == expected:
            print(f"    PASS: {len(expected.splitlines())} lines match"
                  + (f"; {len(missing)} untranslated functions reached" if missing else ""))
            return True
        print("    FAIL: the port's output differs (build/actual.txt, build/port-stderr.txt)")
        diff = list(difflib.unified_diff(expected.splitlines(), actual.splitlines(), "expected", "actual", lineterm="", n=0))
        for line in diff[2:42]:
            print(f"      {line}")
        for line in err.splitlines()[-12:]:
            print(f"    stderr: {line}")
        return False


    def step_fidelity(self) -> bool:
        """fidelity32.py: each function against its translation, build/fidelity.html. Reported,
        not a pass/fail: the low ones are where to look."""
        # (measured on the translation built as written, /Od /Ob0: port/CMakeLists.txt RHTEST_MEASURE)
        out = self.build / "port-measure"
        env = msvc_env("64")
        cmake = shutil.which("cmake")
        if run([cmake, "-S", str(HERE / "port"), "-B", str(out), "-A", "x64", "-DRHTEST_MEASURE=ON",
                f"-DRHTEST_VARIANT={self.root.as_posix()}"], self.root, env, self.build / "measure-configure.log") != 0 \
                or run([cmake, "--build", str(out), "--config", "Release", "--", f"/m:{JOBS}", "/v:minimal"],
                       self.root, env, self.build / "measure-build.log") != 0:
            print("    the measured port did not build (build/measure-build.log)")
            return False
        log = self.build / "fidelity.log"
        if run([sys.executable, str(RHIPPER / "fidelity32.py"), "--html", "--limit", "8",
                "--port", str(out / "bin" / "Release" / "rhtest-port.exe")], self.root, self.env, log) != 0:
            return False
        lines = log.read_text(encoding="utf-8", errors="replace").splitlines()
        for line in lines[:10]:
            print(f"    {line}")
        m = re.search(r"(\d+) functions, (\d+) translated \((\d+) at 1\.0\), (\d+) stubs; mean ([\d.]+), by size ([\d.]+)",
                      "\n".join(lines))
        if m:
            self.fidelity = {"functions": int(m.group(1)), "translated": int(m.group(2)), "perfect": int(m.group(3)),
                             "stubs": int(m.group(4)), "mean": float(m.group(5)), "by_size": float(m.group(6))}
        return True

    def step_bytes(self) -> bool:
        """bytes32.py: the translation built for x86 against the reference's own bytes, each
        function's similarity (build/bytes32.json), and the project's fidelity.html again with its
        byte-for-byte grouping. Reported, not a pass/fail: the measure to move toward byte 1:1."""
        log = self.build / "bytes.log"
        if run([sys.executable, str(RHIPPER / "bytes32.py"), "--json", "--limit", "8", "--jobs", str(JOBS)],
               self.root, self.env, log) != 0:
            print("    bytes32 failed (build/bytes.log): no byte report")
            return True
        text = log.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines()[:6]:
            print(f"    {line}")
        same = re.search(r"byte-identical \(addresses masked\): (\d+)", text)
        mean = re.search(r"mean similarity: ([\d.]+) over all, [\d.]+ over the compared; by size ([\d.]+)", text)
        if same and mean:
            self.bytes = {"identical": int(same.group(1)), "mean": float(mean.group(1)), "by_size": float(mean.group(2))}
        # (the page again, its byte-for-byte grouping from the json just written)
        run([sys.executable, str(RHIPPER / "fidelity32.py"), "--html-only"], self.root, self.env,
            self.build / "fidelity-html.log")
        return True

    def fidelity_current(self, stopped: str | None) -> bool:
        """Whether the translation is the corpus's, so a fidelity report of it means something:
        a translation exists and this run did not stop at or before translating (translate32.py
        rewrites only the files that changed, so their times do not say)."""
        if not (self.root / "gen" / "manifest.json").exists():
            return False
        return stopped is None or STEPS.index(stopped) > STEPS.index("translate")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("programs", nargs="*", choices=[[]] + list(PROGRAMS), default=[])
    ap.add_argument("--variant", choices=list(VARIANTS), action="append")
    ap.add_argument("--from", dest="start", choices=STEPS, default="ref")
    ap.add_argument("--only", choices=STEPS)
    ap.add_argument("--jobs", type=int, default=1, help="workers for protos32, translate32 and MSBuild (default 1)")
    ap.add_argument("--parallel", type=int, default=None,
                    help=f"projects at once (default 1; {FULL_PARALLEL} for a full run, the end of a phase's regression)")
    ap.add_argument("--toolset", choices=list(TOOLSETS), help=f"the compiler the references are built with "
                    f"(default {DEFAULT_TOOLSET})")
    ap.add_argument("--bins", metavar="TOOLSET", choices=list(TOOLSETS),
                    help="test the toolset's references committed in bins/TOOLSET, not a build")
    ap.add_argument("--save-bins", action="store_true", help="keep each reference built in bins/<toolset>/")
    args = ap.parse_args()
    global JOBS, USE_BINS, SAVE_BINS, TOOLSET, REPORT
    JOBS = args.jobs
    USE_BINS, SAVE_BINS = args.bins, args.save_bins
    if args.bins and args.toolset and args.bins != args.toolset:
        ap.error("--bins and --toolset name different toolsets")
    TOOLSET = args.bins or args.toolset or DEFAULT_TOOLSET
    REPORT = report_path(TOOLSET)
    if USE_BINS and not (BINS / USE_BINS).is_dir():
        ap.error(f"no {BINS / USE_BINS}")
    if USE_BINS and SAVE_BINS:
        ap.error("--save-bins keeps references built, --bins tests committed ones")
    steps = [args.only] if args.only else STEPS[STEPS.index(args.start):]
    programs = args.programs or [p for p in PROGRAMS if (SRC / PROGRAMS[p][0][0]).exists()]
    full = not args.programs and not args.variant and steps == STEPS
    parallel = args.parallel or (FULL_PARALLEL if full else 1)
    projects = [(program, variant) for program in programs for variant in variants_of(program)
                if not args.variant or variant in args.variant]
    if not projects:
        ap.error(f"no such variant in {TOOLSET}")
    if TOOLSET != DEFAULT_TOOLSET:
        print(f"toolset {TOOLSET}: {work_dir(TOOLSET).relative_to(HERE)}")

    def one(program: str, variant: str) -> tuple[Project, str]:
        p = Project(program, variant)
        # (the import asked for by name is a fresh one: facts applied over a project that
        # kept an earlier run's types hid what a new one lacks, the float returns ApplyFacts
        # left to the decompiler, until a full run reimported, 2026-10-24)
        p.fresh = steps[0] == "import"
        ok, ran, stopped = True, set(), None
        for step in steps:
            print(f"[{p.name}] {step}")
            ran.add(step)
            if not getattr(p, f"step_{step}")():
                print(f"[{p.name}] stopped at {step}")
                ok, stopped = False, step
                p.stop = (step, stop_detail(p, step))
                break
        # (the fidelity report on every run that touched the project, whatever stopped it:
        # a failing run is when it is read. Not over a translation older than its corpus)
        if "fidelity" not in ran and p.fidelity_current(stopped):
            print(f"[{p.name}] fidelity")
            p.step_fidelity()
        # (and its bytes, the same: what the x86 build of the translation makes of the reference)
        if "bytes" not in ran and p.fidelity_current(stopped) and "bytes" in steps:
            print(f"[{p.name}] bytes")
            p.step_bytes()
        return p, "PASS" if ok else "FAIL"

    results: dict[str, Project] = {}
    status: dict[str, str] = {}
    if parallel <= 1:
        for program, variant in projects:
            p, s = one(program, variant)
            results[p.name], status[p.name] = p, s
    else:
        # (projects at once, each in a thread of its own: their work is the tools they start.
        # A project's lines are kept and printed together when it ends, not interleaved)
        import threading
        from concurrent.futures import ThreadPoolExecutor
        # (captured once, before the threads; the reference's compiler only where it builds them)
        msvc_env("64")
        if "ref" in steps and not USE_BINS:
            ref_env()
        lock = threading.Lock()
        real = sys.stdout

        class PerThread:
            def write(self, s):
                buf = getattr(local, "buf", None)
                if buf is None:
                    with lock:
                        real.write(s)
                else:
                    buf.append(s)

            def flush(self):
                real.flush()

        local = threading.local()
        sys.stdout = PerThread()

        def task(pv):
            local.buf = []
            try:
                return one(*pv)
            finally:
                text, local.buf = "".join(local.buf), None
                with lock:
                    real.write(text)
                    real.flush()

        print(f"{len(projects)} projects, {parallel} at once")
        try:
            with ThreadPoolExecutor(parallel) as pool:
                for p, s in pool.map(task, projects):
                    results[p.name], status[p.name] = p, s
        finally:
            sys.stdout = real
    print()
    reasons = Counter()
    for name, p in results.items():
        s = f"translated {p.stubs['translated']}, stubbed {p.stubs['stubbed']}" if p.stubs else ""
        if p.fidelity:
            s += f"  fidelity {p.fidelity['mean']:.3f}/{p.fidelity['by_size']:.3f} (mean/by size)"
        if p.bytes:
            s += f"  bytes {p.bytes['mean']:.3f}/{p.bytes['by_size']:.3f}, {p.bytes['identical']} identical"
        print(f"  {name:<12} {status[name]}  {s}")
        for why in (p.stubs or {}).get("stubs", {}).values():
            reasons[re.sub(r"\(.*", "", why).strip()] += 1
    if reasons:
        print("  stubs by reason: " + ", ".join(f"{n} {r}" for r, n in reasons.most_common()))
    write_report(results, status, "run" in steps)
    print(f"  report: {REPORT}")
    sys.exit(0 if all(s == "PASS" for s in status.values()) else 1)


REPORT = HERE / "fidelity.html"


def stop_detail(p, step: str, lines: int = 40) -> str:
    """What a stopped step left to read, for the report (CI's logs are an artifact only a
    signed-in download reaches, and a project that stopped before scoring showed nothing but
    "no report"): a run's output against the reference's, else the end of the newest log."""
    import difflib
    try:
        if step == "run" and (p.build / "actual.txt").exists():
            exp = (p.ref / "expected.txt").read_text(encoding="utf-8", errors="replace").splitlines()
            act = (p.build / "actual.txt").read_text(encoding="utf-8", errors="replace").splitlines()
            diff = list(difflib.unified_diff(exp, act, "expected", "actual", n=1, lineterm=""))[:lines]
            err = (p.build / "port-stderr.txt")
            tail = err.read_text(encoding="utf-8", errors="replace").splitlines()[-15:] if err.exists() else []
            return "\n".join(diff + (["", "stderr:"] + tail if tail else []))
        logs = sorted((f for f in p.build.glob("*.log") if f.is_file()), key=lambda f: f.stat().st_mtime)
        if not logs:
            return ""
        text = logs[-1].read_text(encoding="utf-8", errors="replace").splitlines()
        out = f"{logs[-1].name}:\n" + "\n".join(text[-lines:])
        # (and the generated lines a compile error points at, quoted: the log names only a line
        # number in a file the run's artifact alone has)
        quoted, seen = [], set()
        for line in text:
            m = re.search(r"([A-Za-z]:[^()]*?\.(?:c|h|cpp))\((\d+)(?:,\d+)?\)\s*:\s*error", line)
            if not m or (m.group(1), m.group(2)) in seen or len(seen) >= 4:
                continue
            seen.add((m.group(1), m.group(2)))
            try:
                src = Path(m.group(1)).read_text(encoding="utf-8", errors="replace").splitlines()
                quoted.append(f"{Path(m.group(1)).name}:{m.group(2)}: {src[int(m.group(2)) - 1][:300]}")
            except (OSError, IndexError):
                pass
        return out + ("\n\nat:\n" + "\n".join(quoted) if quoted else "")
    except OSError as e:
        return f"({e})"


# (the fidelity bands the summary's bars show, fidelity_html.py's)
BAND_NAMES = {"b10": "100%", **{f"b{i}": f"{10 * i}-{10 * i + 9}%" for i in range(10)}, "stub": "stub"}


def write_report(results: dict, status: dict, ran_port: bool) -> None:
    """fidelity.html beside this file: every project's last result and fidelity, and per project
    what is below 1.0 and what is a stub, from each one's build/fidelity.json. A run re-scores the
    projects it ran; the others show their last scores (and when they were made) until a full run
    (`python rhtest.py`, at the end of a phase) remakes them all."""
    import datetime
    import html
    work = work_dir(TOOLSET)
    # (the projects' reports, as the report links them: work/<name>/... beside this file, or
    # <name>/... beside work/<toolset>/fidelity.html)
    rel = work.relative_to(REPORT.parent).as_posix()
    rel = "" if rel == "." else rel + "/"
    path = work / "summary.json"
    summary = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    for name, p in results.items():
        entry = summary.get(name, {})
        # (a result only from a run that ran the port, or stopped before it: `--only fidelity`
        # passing says nothing of the port's output)
        if status[name] != "PASS" or ran_port:
            entry.update(status=status[name], when=now)
            # (where a failing one stopped, and what it left: a pass has none)
            stop = getattr(p, "stop", None)
            if stop:
                entry.update(stopped=stop[0], detail=stop[1])
            else:
                entry.pop("stopped", None)
                entry.pop("detail", None)
        entry.setdefault("status", "-")
        entry.setdefault("when", "-")
        if p.fidelity:
            entry["fidelity"] = p.fidelity
        if p.bytes:
            entry["bytes"] = p.bytes
        summary[name] = entry
    path.write_text(json.dumps(summary, indent=1, sort_keys=True), encoding="utf-8")

    def order(n):
        prog = n.split("-")[0]
        return (list(PROGRAMS).index(prog) if prog in PROGRAMS else 99, n)

    rows, sections = [], []
    totals = Counter()
    for name in sorted(summary, key=order):
        e = summary[name]
        f = e.get("fidelity")
        report = work / name / "build" / "fidelity.html"
        data = work / name / "build" / "fidelity.json"
        scored_at = datetime.datetime.fromtimestamp(data.stat().st_mtime).strftime("%Y-%m-%d %H:%M") if data.exists() else "-"
        link = f'<a href="{rel}{name}/build/fidelity.html">{html.escape(name)}</a>' if report.exists() else html.escape(name)
        cls = "pass" if e["status"] == "PASS" else "fail" if e["status"].startswith("FAIL") else "muted"
        if f:
            totals.update(functions=f["functions"], translated=f["translated"], perfect=f["perfect"], stubs=f["stubs"])
            cells = (f'<td class="num">{f["mean"]:.3f}</td><td class="num">{f["by_size"]:.3f}</td>'
                     f'<td class="num">{f["perfect"]}/{f["translated"]}</td><td class="num">{f["stubs"]}</td>')
        else:
            cells = '<td colspan="4" class="muted">no report</td>'
        shown = e["status"] + (f' at {e["stopped"]}' if e.get("stopped") else "")
        # (its functions by fidelity band, a stacked bar: fidelity_html's bands and colours)
        def stack(counts: Counter) -> str:
            n = sum(counts.values()) or 1
            segs = "".join(f'<span class="seg {k}" style="width:{100 * counts[k] / n:.2f}%" '
                           f'title="{BAND_NAMES[k]}: {counts[k]}"></span>'
                           for k in ["b10"] + [f"b{i}" for i in range(9, -1, -1)] + ["stub"] if counts[k])
            return f'<td class="bars"><div class="stack">{segs}</div></td>'

        groups = '<td class="muted">–</td>'
        if data.exists():
            frows = json.loads(data.read_text(encoding="utf-8"))
            groups = stack(Counter("stub" if r["kind"] == "stub" else
                                   "b10" if r["score"] >= 0.999 else f"b{max(0, min(9, int(r['score'] * 10)))}"
                                   for r in frows))
        # (and by byte similarity, bytes32's: identical as 100%, the ones it has none of as stubs)
        bdata = work / name / "build" / "bytes32.json"
        bgroups = '<td class="muted">–</td>'
        if bdata.exists():
            brows = json.loads(bdata.read_text(encoding="utf-8"))
            bgroups = stack(Counter("stub" if r.get("kind") in ("stub", "absent") else
                                    "b10" if r.get("same") else f"b{max(0, min(9, int(r.get('sim', 0) * 10)))}"
                                    for r in brows))
        b = e.get("bytes")
        bcells = (f'<td class="num">{b["mean"]:.3f}</td><td class="num">{b["identical"]}</td>' if b
                  else '<td colspan="2" class="muted">–</td>')
        rows.append(f'<tr><td><a href="#{name}">{html.escape(name)}</a></td><td class="{cls}">{html.escape(shown)}</td>{cells}'
                    f'{groups}{bcells}{bgroups}<td class="muted">{e["when"]}</td><td class="muted">{scored_at}</td></tr>')
        # (what the stopped step left: the run's diff against the reference, or its log's end)
        stopped = (f'<p>stopped at {html.escape(e["stopped"])}</p><pre>{html.escape(e.get("detail", ""))}</pre>'
                   if e.get("stopped") else "")
        if not data.exists():
            if stopped:
                sections.append(f'<details id="{name}" open><summary>{html.escape(name)}</summary>{stopped}</details>')
            continue
        items = [r for r in json.loads(data.read_text(encoding="utf-8")) if r["score"] < 0.999]
        items.sort(key=lambda r: (r["kind"] != "stub", r["score"], -r["size"]))
        body = []
        for r in items:
            if r["kind"] == "stub":
                body.append(f'<tr><td>{r["addr"]}</td><td>{html.escape(r["name"])}</td><td class="num s0">stub</td>'
                            f'<td class="muted">{html.escape(r["why"])}</td></tr>')
                continue
            notes = "; ".join(f"{k.replace('_', ' ')}: {', '.join(map(str, r[k][:4]))}"
                              for k in ("missing_calls", "extra_calls", "missing_fields", "missing_consts") if r.get(k))
            band = "s2" if r["score"] >= 0.9 else "s1" if r["score"] >= 0.6 else "s0"
            body.append(f'<tr><td>{r["addr"]}</td><td>{html.escape(r["name"])}</td>'
                        f'<td class="num {band}">{r["score"]:.3f}</td><td class="muted">{html.escape(notes)}</td></tr>')
        inner = (f'<div class="wrap"><table><thead><tr><th>address</th><th>function</th><th class="num">score</th>'
                 f'<th>why</th></tr></thead><tbody>{"".join(body)}</tbody></table></div>'
                 if body else '<p class="muted">every function at 1.0</p>')
        sections.append(f'<details id="{name}"{" open" if body or stopped else ""}><summary>{html.escape(name)} '
                        f'<span class="muted">({len(items)} below 1.0, full report: {link})</span></summary>{stopped}{inner}</details>')
    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>rhtest {TOOLSET}</title>
<style>
:root {{ --bg:#fbfbfa; --fg:#1d1d1b; --muted:#6b6b66; --line:#e4e3df; --pass:#2f9e5b; --fail:#d0503c; --link:#3f51d8;
  --s2:#7aa83a; --s1:#d49a2a; --s0:#d0503c; }}
pre {{ overflow-x:auto; font-size:12px; border:1px solid var(--line); padding:8px; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#17171a; --fg:#e9e8e4; --muted:#9a9993; --line:#2c2c31;
  --link:#8f9bff; }} }}
body {{ background:var(--bg); color:var(--fg); font:14px/1.45 system-ui,sans-serif; margin:0; padding:24px 16px; }}
main {{ max-width:1100px; margin:0 auto; }} h1 {{ font-size:20px; margin:0 0 4px; }} h2 {{ font-size:16px; margin:28px 0 8px; }}
.sub {{ color:var(--muted); margin-bottom:16px; }}
.wrap {{ overflow-x:auto; }} table {{ border-collapse:collapse; width:100%; font-size:13px; }}
th,td {{ text-align:left; padding:5px 8px; border-bottom:1px solid var(--line); vertical-align:top; }}
th {{ color:var(--muted); font-weight:600; }} .num {{ text-align:right; font-variant-numeric:tabular-nums; }}
td:first-child {{ font-family:ui-monospace,monospace; }}
.muted {{ color:var(--muted); }} .pass {{ color:var(--pass); font-weight:600; }} .fail {{ color:var(--fail); font-weight:600; }}
.s2 {{ color:var(--s2); }} .s1 {{ color:var(--s1); }} .s0 {{ color:var(--s0); font-weight:600; }}
details {{ border:1px solid var(--line); border-radius:8px; padding:8px 12px; margin:8px 0; }}
summary {{ cursor:pointer; font-weight:600; }} a {{ color:var(--link); }}
td.bars {{ min-width:180px; vertical-align:middle; }}
.stack {{ display:flex; height:12px; border-radius:6px; overflow:hidden; background:var(--line); }} .seg {{ height:100%; }}
.legend {{ display:flex; flex-wrap:wrap; gap:4px 12px; font-size:12px; color:var(--muted); margin:-6px 0 12px; }}
.legend i {{ display:inline-block; width:10px; height:10px; border-radius:3px; margin-right:5px; vertical-align:-1px; }}
.b10 {{ background:#1f9d55; }} .b9 {{ background:#56b04a; }} .b8 {{ background:#8cbd3f; }} .b7 {{ background:#b8c13a; }}
.b6 {{ background:#d8b532; }} .b5 {{ background:#e39a2c; }} .b4 {{ background:#e57f2a; }} .b3 {{ background:#e0632c; }}
.b2 {{ background:#d84b33; }} .b1 {{ background:#c9393b; }} .b0 {{ background:#b02a3f; }} .stub {{ background:#8b8a95; }}
</style></head><body><main><h1>rhtest fidelity: {TOOLSET}</h1>
<div class="sub">{len(summary)} projects, {totals['functions']} functions: {totals['perfect']} of {totals['translated']}
translated at 1.0, {totals['stubs']} stubs. Written {now}; a project shows the scores of its last run (scored column).</div>
<div class="legend">{"".join(f'<span><i class="{k}"></i>{BAND_NAMES[k]}</span>' for k in ["b10"] + [f"b{i}" for i in range(9, -1, -1)] + ["stub"])}</div>
<div class="wrap"><table>
<thead><tr><th>project</th><th>result</th><th class="num">fidelity</th><th class="num">by size</th>
<th class="num">at 1.0</th><th class="num">stubs</th><th>fidelity grouping</th><th class="num">bytes</th>
<th class="num">identical</th><th>byte grouping</th><th>run</th><th>scored</th></tr></thead><tbody>
{"".join(rows)}
</tbody></table></div>
<h2>Below 1.0, by project</h2>
{"".join(sections)}
</main></body></html>
"""
    REPORT.write_text(page, encoding="utf-8")
    old = work / "index.html"
    if old.exists():
        old.unlink()


if __name__ == "__main__":
    main()
