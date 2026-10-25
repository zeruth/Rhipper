"""The toolchain that built the reference: build/facts/toolchain.json.

    python toolchain.py           detect, write the fact, print it (and warn without an rhtest toolset)
    python toolchain.py --check   only print it

A toolchain is named as rhtest names its toolsets, `msvc-<version>-<arch>`: msvc-14.51-x86 (Visual
Studio 2026's toolset 14.51), msvc-16.00-x86 (Visual Studio 2010's compiler, cl 16.00). The rules
Rhipper applies stay patterns in the code whatever the compiler; the toolchain says which rhtest
toolset proves them for this project (tests/rhtest/bins/<toolchain>), and names the runtime the
reference links (a CRT DLL needs runtime32's adapters for it; a static one is translated code).

Read off the binary: the linker's version in the optional header (the linkers since Visual Studio
2015 write their toolset there, 14.51; the older ones their own version, 10.0 for cl 16.00), the
Rich header's tools and builds (each object's compiler, and how many: the CRT's prebuilt objects
are among them, so the linker, not the most objects, names the toolchain), the C runtime it imports
(or none: linked in), the machine, and the Windows version it targets.

rhipper.json "toolchain" overrides the name, for a binary whose Rich header or linker version is
stripped or forged (an obfuscated or repacked build); the detection is still recorded beside it.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

import pefile

HERE = Path(__file__).resolve().parent
RHTEST_BINS = HERE / "tests" / "rhtest" / "bins"

# the Rich header's product ids Rhipper knows: (tool, Visual Studio)
PRODUCTS = {
    0x006d: ("C", "2005"), 0x006e: ("C++", "2005"), 0x0078: ("linker", "2005"),
    0x0083: ("C", "2008"), 0x0084: ("C++", "2008"), 0x0091: ("linker", "2008"), 0x0093: ("import lib", "2008"),
    0x009d: ("linker", "2010"), 0x009e: ("masm", "2010"), 0x00aa: ("C", "2010"), 0x00ab: ("C++", "2010"),
    0x0101: ("import lib", "2015+"), 0x0102: ("linker", "2015+"), 0x0103: ("masm", "2015+"),
    0x0104: ("C", "2015+"), 0x0105: ("C++", "2015+"),
}
# a C runtime by the DLL it is imported from
CRT_DLLS = {"msvcr80.dll": "msvcr80", "msvcr90.dll": "msvcr90", "msvcr100.dll": "msvcr100",
            "msvcr110.dll": "msvcr110", "msvcr120.dll": "msvcr120", "msvcrt.dll": "msvcrt",
            "ucrtbase.dll": "ucrt", "vcruntime140.dll": "ucrt"}
MACHINES = {0x14c: "x86", 0x8664: "x64"}


def detect(exe: Path) -> dict:
    pe = pefile.PE(str(exe), fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    oh = pe.OPTIONAL_HEADER
    major, minor = oh.MajorLinkerVersion, oh.MinorLinkerVersion
    # (cl's version: the linker's since 2015's 14.x, the linker's + 6 before it: link 10.0, cl 16.00)
    version = f"14.{minor:02d}" if major == 14 else f"{major + 6}.00" if 6 <= major < 14 else f"{major}.{minor:02d}"
    arch = MACHINES.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine))
    tools: list[dict] = []
    linker_build = None
    rich = pe.parse_rich_header()
    if rich:
        v = rich["values"]
        for i in range(0, len(v) - 1, 2):
            prod, build, count = v[i] >> 16, v[i] & 0xffff, v[i + 1]
            if prod == 1:
                continue                                    # (Import0: the imports, not a tool)
            tool, vs = PRODUCTS.get(prod, (f"tool {prod:#06x}", "?"))
            tools.append({"tool": tool, "vs": vs, "build": build, "objects": count})
            if tool == "linker":
                linker_build = build
    dlls = [e.dll.decode(errors="replace").lower() for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])]
    crt = next((CRT_DLLS[d] for d in dlls if d in CRT_DLLS), None)
    if crt is None and any(d.startswith("api-ms-win-crt-") for d in dlls):
        crt = "ucrt"
    return {
        "toolchain": f"msvc-{version}-{arch}",
        "linker": f"{major}.{minor:02d}" + (f".{linker_build}" if linker_build else ""),
        "arch": arch,
        "crt": crt or "static",
        "subsystem": f"{oh.MajorSubsystemVersion}.{oh.MinorSubsystemVersion:02d}",
        "rich_header": bool(rich),
        "tools": tools,
    }


def summary(d: dict) -> str:
    compilers = Counter()
    for t in d["tools"]:
        if t["tool"] in ("C", "C++"):
            compilers[f"{t['tool']} {t['build']}"] += t["objects"]
    objs = ", ".join(f"{n} {k}" for k, n in compilers.most_common(4))
    return (f"{d['toolchain']}: linker {d['linker']}, CRT {d['crt']}, Windows {d['subsystem']}"
            + (f"; objects: {objs}" if objs else "") + ("" if d["rich_header"] else "; no Rich header"))


def main() -> None:
    sys.path.insert(0, str(HERE))
    import project
    # (`--structs`: only the merged layouts, for ghidra.sh apply, by the toolchain already found)
    if "--structs" in sys.argv:
        tc = project.FACTS / "toolchain.json"
        name = json.loads(tc.read_text(encoding="utf-8"))["name"] if tc.exists() else detect(project.EXE)["toolchain"]
        project.FACTS.mkdir(parents=True, exist_ok=True)
        write_structs(project, name)
        return
    found = detect(project.EXE)
    declared = project.CONFIG.get("toolchain")
    name = declared or found["toolchain"]
    print(f"toolchain {summary(found)}")
    if declared and declared != found["toolchain"]:
        print(f"toolchain: rhipper.json declares {declared}; the binary reads as {found['toolchain']}")
    if not (RHTEST_BINS / name).is_dir():
        print(f"toolchain: no rhtest toolset for {name} (tests/rhtest/bins/{name}): the facts are "
              f"proven on other compilers only")
    if "--check" in sys.argv:
        return
    project.FACTS.mkdir(parents=True, exist_ok=True)
    out = {"name": name, "declared": declared, "detected": found}
    (project.FACTS / "toolchain.json").write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")
    write_structs(project, name)


def write_structs(project, name: str) -> None:
    """build/facts/structs.json: the toolchain's layouts (toolchains/<name>/structs.json, its C
    runtime's types, for every program built with it) and the project's own (data/structs.json),
    the project's winning. Kept in one project alone, the VS2010 CRT's _LocaleUpdate and DName
    were placeholders in every rhtest msvc-16.00-x86 program, and their users stubs."""
    merged: dict = {}
    for src in (HERE / "toolchains" / name / "structs.json", project.ROOT / "data" / "structs.json"):
        if src.exists():
            merged.update(json.loads(src.read_text(encoding="utf-8")).get("structs", {}))
    dest = project.FACTS / "structs.json"
    if merged:
        dest.write_text(json.dumps({"rule": "toolchain.py write_structs: the toolchain's and the project's",
                                    "structs": merged}, indent=1) + "\n", encoding="utf-8")
    elif dest.exists():
        dest.unlink()


if __name__ == "__main__":
    main()
