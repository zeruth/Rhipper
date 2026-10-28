r"""Compile the Ghidra scripts against the install's jars, in seconds: a script that does not
compile fails a headless session minutes in ("The class could not be found"), and a pipeline with
it (ApplyFacts' getFunctionBefore, the script API's not FunctionManager's, 2026-10-28).

    python ghidra/checkscripts.py               every *.java here
    python ghidra/checkscripts.py ApplyFacts    those named
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import project  # noqa: E402


def classpath(install: Path) -> str:
    jars = [str(p) for p in install.rglob("*.jar") if "lib" in p.parts and "patch" not in p.parts]
    return os.pathsep.join(jars)


def main() -> int:
    install = Path(project.ghidra_install())
    names = sys.argv[1:]
    scripts = [p for p in sorted(HERE.glob("*.java")) if not names or p.stem in names]
    cp = classpath(install)
    bad = 0
    with tempfile.TemporaryDirectory() as out:
        argfile = Path(out) / "cp.txt"
        argfile.write_text(f'-cp "{cp.replace(chr(92), "/")}"\n')
        for s in scripts:
            r = subprocess.run(["javac", "-nowarn", "-proc:none", "-d", out, f"@{argfile}", str(s)],
                               capture_output=True, text=True)
            errors = [l for l in (r.stdout + r.stderr).splitlines() if ": error:" in l]
            if r.returncode != 0:
                bad += 1
                print(f"{s.name}: {len(errors)} error(s)")
                print("\n".join("  " + l for l in (r.stdout + r.stderr).splitlines()[:12]))
            else:
                print(f"{s.name}: ok")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
