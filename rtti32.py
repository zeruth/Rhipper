"""Names from an x86 binary's RTTI: each virtual function after the class whose vtable holds it.

MSVC keeps a CompleteObjectLocator pointer in the word before a vtable of a class with RTTI. The
locator names the class (its TypeDescriptor's mangled `.?AV...@@`) and its bases (the
ClassHierarchyDescriptor). A function in slot k of one class's primary vtable (the locator's
offset 0) is `Class::vf<k>`. One several classes' vtables share (a base's method no derived
class overrides) is the base's: the class among them every other one derives from. One shared by
classes none of which derives from all the others (identical code folded, _purecall) keeps its
name. Only functions Ghidra has no name for (FUN_) are named.

Writes build/facts/names_rtti.json in data/names.json's form; ApplyFacts applies it before the
project's hand-identified names, which win.

    python rtti32.py
"""
from __future__ import annotations

import json
import re
import struct
from collections import defaultdict

import pefile

import project
from pebin import FACTS


def demangle(raw: str) -> str | None:
    """`.?AVManagedBlock@Managed@Memory@@` -> `Memory::Managed::ManagedBlock`; a template's or a
    local class's parts as identifiers (`ComBase_IDropTarget...`)"""
    m = re.fullmatch(r"\.\?A[VU](.+)@@", raw)
    if not m:
        return None
    body = m.group(1)
    if "?$" in body or "?1" in body:
        # (a template or a function-local class: one identifier of its words)
        words = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", body)
        return "_".join(words[:6]) or None
    parts = body.split("@")
    if not all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", p) for p in parts):
        return None
    return "::".join(reversed(parts))


def main() -> None:
    pe = pefile.PE(str(project.EXE), fast_load=True)
    img = pe.get_memory_mapped_image()
    base = pe.OPTIONAL_HEADER.ImageBase

    def u32(a):
        o = a - base
        return struct.unpack_from("<I", img, o)[0] if 0 <= o <= len(img) - 4 else None

    def cstr(a):
        o = a - base
        if not 0 <= o < len(img):
            return ""
        return img[o:img.find(b"\0", o)].decode("latin-1")

    def type_name(td):
        return cstr(td + 8) if td and u32(td + 8) is not None else ""

    unnamed = {int(f["entry"], 16) for f in json.loads((FACTS / "functions.json").read_text())["functions"]
               if f["name"].startswith("FUN_") or int(f["entry"], 16) in project.suggested()}
    vtables = json.loads((FACTS / "vtables.json").read_text())["vtables"]

    classes: dict[int, str] = {}           # vtable -> class
    bases: dict[str, set[str]] = {}        # class -> every class it derives from (itself too)
    slots: dict[int, list[tuple[str, int]]] = defaultdict(list)   # function -> (class, slot)
    for v in vtables:
        vt = int(v["vtable"], 16)
        col = u32(vt - 4)
        if not col or u32(col) != 0 or u32(col + 4) != 0:
            continue                       # (no locator, or a secondary vtable of a multiple base)
        cls = demangle(type_name(u32(col + 12) or 0))
        if not cls:
            continue
        classes[vt] = cls
        chd = u32(col + 16)
        if chd and cls not in bases:
            n, arr = u32(chd + 8) or 0, u32(chd + 12) or 0
            bs = set()
            for k in range(min(n, 64)):
                bcd = u32(arr + 4 * k) if arr else None
                b = demangle(type_name(u32(bcd) or 0)) if bcd else None
                if b:
                    bs.add(b)
            bases[cls] = bs | {cls}
        for k, s in enumerate(v["slots"]):
            slots[int(s, 16)].append((cls, k))

    out, shared = {}, 0
    for f, owners in sorted(slots.items()):
        if f not in unnamed:
            continue
        cands = {c for c, _ in owners}
        # (the class every other one derives from: the base whose method they all inherit)
        root = [c for c in cands if all(c in bases.get(o, {o}) for o in cands)]
        if len(root) != 1:
            shared += 1
            continue
        cls = root[0]
        k = min(k for c, k in owners if c == cls)
        out[f"{f:#x}"] = {"ns": cls, "name": f"vf{k}",
                          "evidence": f"slot {k} of {cls}'s vtable (RTTI)"
                          + (f", inherited by {len(cands) - 1} more" if len(cands) > 1 else "")}
    (FACTS / "names_rtti.json").write_text(json.dumps(
        {"_comment": "virtual functions named from RTTI by rtti32.py", "functions": out}, indent=1))
    print(f"rtti32: {len(classes)} of {len(vtables)} vtables with RTTI, {len(bases)} classes; "
          f"{len(out)} functions named, {shared} shared by unrelated classes left as they are "
          f"-> {FACTS / 'names_rtti.json'}")


if __name__ == "__main__":
    main()
