"""The project Rhipper works on, from its rhipper.json.

Rhipper is the tooling; a project is a reference binary and the source tree its translation goes
into. A project names itself with a rhipper.json at its root, and every tool finds it the same
way: RHIPPER_PROJECT (the file or its directory) if set, else the first rhipper.json at or above
the working directory. Paths in it are relative to the file's directory.

    {
      "name": "FrostLite",
      "exe": "client/_classic_/WowClassic-clean.exe",       the reference binary (required)
      "arch": "x86_64",                                      or "x86"
      "toolchain": null,                                     the compiler that built it, msvc-16.00-x86:
                                                             toolchain.py reads it off the binary;
                                                             set it where the binary hides it
      "image_base": "0x140000000",
      "sources": ["src", "vendor"],                          the hand-written sources
      "gen": "src/gen",                                      where the translation is written
      "build": {"dir": "build/cmake", "config": "Release",
                "gen_target": "gen", "target": "FrostLite"},
      "run": {"exe": "build/cmake/bin/Release/FrostLite.exe", "cwd": "client/_classic_"},
      "ghidra": {"install": "C:/Users/me/tools/ghidra_*", "projects": "C:/Users/me/tools/ghidra-projects",
                 "project": "FrostLite", "program": "WowClassic-clean.exe", "maxmem": "14G"},
      "plugins": {"protection": "tools/aegis.py"},           project modules the pipeline calls into
      "hooks": {"pre_link": ["tools/gen_script_api.py", "--emit"]},
      "handlers": {"roots": "build/script-handlers.json", "stubs": "src/glue/ScriptAPIStubs.cpp"},
      "facts_extra": ["tools/luabind.py"],                   project fact extractors, run with the rest
      "translate_args": ["--all", "--depth", "24", "--fix", "--jobs", "4"]    pipeline.sh's translate
    }

Everything but "exe" has the default shown. The project's own data the tools read (facts under
build/facts, data/*.json, the exception lists in tools/) keeps its place relative to the root.

    python project.py            the project found, and its settings
    python project.py --sh       the settings as shell assignments (ghidra.sh evaluates them)
"""
from __future__ import annotations

import glob
import importlib.util
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent          # Rhipper itself

DEFAULTS = {
    "arch": "x86_64",
    "toolchain": None,
    "image_base": "0x140000000",
    "sources": ["src", "vendor"],
    "gen": "src/gen",
    "build": {"dir": "build/cmake", "config": "Release", "gen_target": "gen", "target": None},
    "run": {"exe": None, "cwd": "."},
    "ghidra": {"install": None, "projects": None, "project": None, "program": None, "maxmem": "14G"},
    "plugins": {},
    "hooks": {},
    "handlers": {"roots": "build/script-handlers.json", "stubs": None},
    "facts_extra": [],
    "translate_args": ["--all", "--depth", "24", "--fix", "--jobs", "4"],
}


def _find() -> Path:
    env = os.environ.get("RHIPPER_PROJECT")
    if env:
        p = Path(env).resolve()
        return p / "rhipper.json" if p.is_dir() else p
    here = Path.cwd().resolve()
    for d in (here, *here.parents):
        if (d / "rhipper.json").is_file():
            return d / "rhipper.json"
    sys.exit("no rhipper.json at or above the working directory (or set RHIPPER_PROJECT)")


CONFIG_FILE = _find()
ROOT = CONFIG_FILE.parent
_raw = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
CONFIG = {k: ({**v, **_raw.get(k, {})} if isinstance(v, dict) else _raw.get(k, v)) for k, v in DEFAULTS.items()}
CONFIG.update({k: v for k, v in _raw.items() if k not in DEFAULTS})

if "exe" not in CONFIG:
    sys.exit(f"{CONFIG_FILE}: no \"exe\" (the reference binary)")

NAME = CONFIG.get("name", ROOT.name)
EXE = ROOT / CONFIG["exe"]
ARCH = CONFIG["arch"]
POINTER_SIZE = 8 if ARCH == "x86_64" else 4
IMAGE_BASE = int(str(CONFIG["image_base"]), 16)
GEN = ROOT / CONFIG["gen"]
BUILD = ROOT / "build"
# (RHIPPER_FACTS redirects the facts, e.g. to compare two versions of the extractors' output)
FACTS = Path(os.environ["RHIPPER_FACTS"]).resolve() if os.environ.get("RHIPPER_FACTS") else BUILD / "facts"
CORPUS = BUILD / "corpus.jsonl"
SOURCES = [ROOT / s for s in CONFIG["sources"]]


def path(rel: str | None) -> Path | None:
    """A project-relative setting as a path (None stays None)."""
    return None if rel is None else ROOT / rel


def ghidra_install() -> str:
    """The Ghidra installation (the "install" setting may be a glob: the first match)."""
    pattern = CONFIG["ghidra"]["install"]
    found = sorted(glob.glob(pattern)) if pattern else []
    if not found:
        sys.exit(f"{CONFIG_FILE}: ghidra.install ({pattern!r}) matches no Ghidra installation")
    return found[0]


_plugins: dict[str, object] = {}


def plugin(name: str):
    """The project's module for a plugin slot ("protection", ...), or None when it has none."""
    if name in _plugins:
        return _plugins[name]
    rel = CONFIG["plugins"].get(name)
    module = None
    if rel:
        file = ROOT / rel
        # (plugins import the tools by name, and their own project's modules beside them)
        for d in (str(HERE), str(file.parent)):
            if d not in sys.path:
                sys.path.insert(0, d)
        spec = importlib.util.spec_from_file_location(f"rhipper_plugin_{name}", file)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    _plugins[name] = module
    return module


def hook(name: str) -> list[str] | None:
    """A project hook's command (a project script and its arguments), or None."""
    cmd = CONFIG["hooks"].get(name)
    if not cmd:
        return None
    first = ROOT / cmd[0]
    return ([sys.executable, str(first)] if first.suffix == ".py" else [str(first)]) + list(cmd[1:])


def _sh() -> None:
    g = CONFIG["ghidra"]
    pairs = {
        "ROOT": ROOT.as_posix(),
        "RHIPPER": HERE.as_posix(),
        "EXE": EXE.as_posix(),
        "ARCH": ARCH,
        "G": Path(ghidra_install()).as_posix() if g["install"] else "",
        "PROJ": g["projects"] or "",
        "GPROJECT": g["project"] or NAME,
        "PROG": g["program"] or EXE.name,
        "GMAXMEM": g["maxmem"],
        "FACTS_EXTRA": " ".join((ROOT / p).as_posix() for p in CONFIG["facts_extra"]),
        "TRANSLATE_ARGS": " ".join(CONFIG["translate_args"]),
    }
    for k, v in pairs.items():
        print(f"{k}='{v}'")


if __name__ == "__main__":
    if "--sh" in sys.argv:
        _sh()
    else:
        print(f"project {NAME} at {ROOT} ({CONFIG_FILE.name})")
        print(json.dumps(CONFIG, indent=1))
