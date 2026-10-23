"""Forward the port's FROST_UNIMPLEMENTED stubs to the reference's own code, translated.

A stub that a run reached (its name in Logs/FrostLite.log as `[unimplemented] <name>`) and that
carries a `// ref: FUN_x` tag is rewritten in place as a forwarder:

    // translated: FUN_x
    void Sub1412345() {
        __try { FUN_x(); } __except (GenFault(0x..., GetExceptionInformation())) {}
    }

tools/translate64.py takes every `// translated:` forwarder as a root, so the next translation
brings in FUN_x and what it calls (the link fallbacks below cover the build in between). A
port object goes to the translated body only when its layout is the reference's: a type whose
size is pinned with `static_assert(sizeof(X) == 0x..)` or a raw-layout class, for parameters,
results and members' `this` alike; plain data, `void*` and callbacks always go. Constructors and
destructors stay hand ports; a teardown is forwarded only beside a forwarded maker of the same
object (the translation built it, so its own teardown takes it apart). When the port passes more
parameters than the reference body reads (a CVar callback's userData), the leading ones are
handed on. The network services stay offline stubs (docs/stubs.md), and the crash, error and
allocator hooks stay the port's. (2026-10-22: these rules took the reached stubs from 2
forwardable to 169.)

    python tools/forward_stubs.py --log client/_classic_/Logs/FrostLite.log [--apply]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from project import ROOT
KEEP_FILES = ("src/services/", "src/client/CrashReport.cpp", "src/storm/ErrorReport.cpp", "src/storm/Memory.cpp",
              "src/client/Telemetry", "src/glue/ScriptAPIStubs.cpp")
VALUE_TYPE = re.compile(r"^(?:const\s+)?(?:bool|int|unsigned|unsigned int|int(?:8|16|32|64)_t|uint(?:8|16|32|64)_t|"
                        r"size_t|DWORD|BOOL|float|double|long|unsigned long)$")
# a pointer to plain data (a string, a float buffer): no object, so no layout to agree on. Not
# `uint8_t *`, which the port also uses for an object it has not typed (`DownloadQueueDestroy(
# uint8_t* queue)`), so a layout after all
DATA_POINTER = re.compile(r"^(?:const\s+)?(?:char|float|double)\s*\*$")
# teardown: the port leaves through its own quit path, and the shutdown faults came from code
# walking its containers at exit (2026-10-17)
TEARDOWN = re.compile(r"Shutdown|Destroy|Release|Clear|AddRef")
# stubs kept the port's by what they do: the WowConnection network layer (offline), the
# reference's unhandled-exception filter, the allocator hooks
KEEP_NAMES = {"Sub1415002E0", "OsInitializeExceptionHandling", "Sub14165C0E0",
              # the final shutdown: the port tears its subsystems down itself
              "Sub140216880"}
# the stubs held back on purpose, by the registry of them (docs/stubs.md: the network services
# until they are ported against our own server), and the families it covers by name, whose
# members also live outside their own files (`TelemetryEncryptionHandler` in Startup.cpp,
# forwarded with --all, ran the telemetry key setup and CAS init failed, 2026-10-18)
DELIBERATE = set(re.findall(r"\b0x(1[0-9a-f]{8})\b", (ROOT / "docs/stubs.md").read_text(encoding="utf-8")))
OFFLINE_NAMES = re.compile(r"^(?:Telemetry|Agent|WowDownload|ClientServices|BattleNet|RealmConnection|NetClient)")
DEFAULT_RESULT ={"void": "", "bool": "false", "float": "0.0f", "double": "0.0"}


def split_params(params: str) -> list[str]:
    """A parameter list split at its top-level commas: a callback parameter's own list
    (`void (*callback)(uint32_t code, const char* text)`) stays in one piece."""
    out, depth, cur = [], 0, ""
    for ch in params:
        if ch in "(<":
            depth += 1
        elif ch in ")>":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return [p for p in out if p and p != "void"]


def param_name(p: str) -> str | None:
    """The name a parameter declares, or None for an unnamed one (`bool`, `CVar*`)."""
    m = re.match(r"^[^(]*\(\s*\*\s*(\w*)\s*\)\s*\(", p)
    if m:
        return m.group(1) or None   # a callback: `void (*name)(...)`
    m = re.search(r"[\w\]>*&]\s*[\s*&]\s*(\w+)$", p)
    if m and not VALUE_TYPE.match(p) and m.group(1) not in ("const", "int", "long", "char", "float", "double"):
        return m.group(1)
    return None


def param_type(p: str) -> str:
    name = param_name(p)
    if name is None:
        return p.strip()
    if "(*" in p.replace(" ", ""):
        return re.sub(r"\(\s*\*\s*\w+\s*\)", "(*)", p, count=1).strip()
    return p[:p.rindex(name)].strip()


def stub_at(lines: list[str], i: int):
    """The stub defined after the tag on line i: (first, last line, signature) or None."""
    j = i + 1
    while j < len(lines) and lines[j].strip().startswith("//"):
        j += 1
    sig = lines[j] if j < len(lines) else ""
    m = re.match(r"^(?:static\s+)?([\w:<>\s\*&]+?)\s+([\w:~]+)\((.*)\)\s*(const)?\s*\{\s*$", sig)
    if not m:
        return None
    depth, k = 0, j
    body = []
    while k < len(lines):
        depth += lines[k].count("{") - lines[k].count("}")
        body.append(lines[k])
        if depth == 0:
            break
        k += 1
    # (a marker's own note, `FROST_UNIMPLEMENTED();  // FUN_x on DAT_y`, is still the marker)
    inner = [re.sub(r"\s*//.*$", "", l.strip()) for l in body[1:-1] if l.strip() and not l.strip().startswith("//")]
    if "FROST_UNIMPLEMENTED();" not in inner:
        return None
    rest = [l for l in inner if l != "FROST_UNIMPLEMENTED();" and not re.fullmatch(r"\(void\)\w+;", l)
            and not re.fullmatch(r"return [^;]*;", l)]
    if rest:
        return None   # a stub with behaviour of its own around the marker: left for a hand port
    return j, k, m.group(1).strip(), m.group(2), m.group(3).strip(), bool(m.group(4))


def raw_layout_classes() -> set[str]:
    """The classes whose only data member is `uint8_t m_data[N]`, read through Field<T>(offset):
    their bytes are the reference object's by construction, so a member stub can hand `this`
    to the translated body (CWorldMap's map loader, 2026-10-21)."""
    out = set()
    for path in (ROOT / "src").rglob("*.hpp"):
        text = path.read_text(encoding="utf-8", errors="replace")
        for m in re.finditer(r"^(?:class|struct) (\w+)(?:\s*:[^{]*)?\s*\{\n(.*?)^\};", text, re.M | re.S):
            if ":" in text[m.start():text.index("{", m.start())]:
                continue   # a base class brings its own members
            body = re.sub(r"//[^\n]*", "", m.group(2))
            body = re.sub(r"\{[^{}]*\}", "{}", body)   # inline bodies (one level is enough here)
            body = re.sub(r"\{[^{}]*\}", "{}", body)
            members = [re.sub(r"^(?:(?:public|private|protected):\s*)+", "", s.strip()) for s in body.split(";")]
            members = [s for s in members
                       if s and "(" not in s and not s.startswith(("template", "using", "static", "friend", "enum",
                                                                   "typedef"))]
            if len(members) == 1 and re.fullmatch(r"uint8_t m_data\[\w+\]", members[0]) and "virtual" not in body:
                out.add(m.group(1))
    return out


def laid_out_classes() -> set[str]:
    """The port's types whose size is pinned to the reference's (`static_assert(sizeof(X) ==
    0x..)`): built at the reference's offsets, so translated code can be handed one. Most of the
    port's objects are (2026-10-22: 450 of them), which the rule above predates."""
    out = set()
    for path in (ROOT / "src").rglob("*"):
        if path.suffix in (".hpp", ".cpp", ".h") and not path.relative_to(ROOT).as_posix().startswith("src/gen/"):
            out |= set(re.findall(r"static_assert\(sizeof\((\w+)\)\s*==\s*0x[0-9a-fA-F]+",
                                  path.read_text(encoding="utf-8", errors="replace")))
    return out


# plain data behind a pointer: the reference's bytes and the port's are the same. Not `uint8_t`,
# which the port also uses for an object it has not typed (see DATA_POINTER)
PLAIN_POINTEE = {"void", "char", "float", "double", "bool", "int8_t", "int16_t", "uint16_t", "int32_t",
                 "uint32_t", "int64_t", "uint64_t", "int", "unsigned", "size_t", "lua_State"}


def forwardable(ptype: str, objects: set[str]) -> bool:
    """A parameter or result the translated body can take as the port has it."""
    t = ptype.strip()
    if VALUE_TYPE.match(t) or DATA_POINTER.match(t):
        return True
    if re.search(r"\(\s*\*\s*\)\s*\(", t):
        return True   # a callback: called, never read
    m = re.fullmatch(r"(?:const\s+)?(?:struct\s+|class\s+)?([\w:]+)\s*((?:\*\s*(?:const\s*)?)+)", t)
    if not m:
        return False
    base = m.group(1).split("::")[-1]
    return base in PLAIN_POINTEE or base in objects


def corpus_arity(addrs: set[str]) -> dict[str, int]:
    """The parameter count of each address's decompiled signature (build/corpus.jsonl)."""
    out = {}
    corpus = ROOT / "build/corpus.jsonl"
    if not addrs or not corpus.exists():
        return out
    want = {f'"addr":"{a}"' for a in addrs}
    with corpus.open(encoding="utf-8") as f:
        for line in f:
            head = line[:40]
            if not any(w in head for w in want):
                continue
            row = json.loads(line)
            name = re.escape(row.get("name") or f"FUN_{row['addr']}")
            m = re.search(r"(?:\bFUN_" + row["addr"] + r"|" + name + r")\s*\(([^)]*)\)\s*\{", row.get("c", ""))
            if m:
                out[row["addr"]] = len(split_params(m.group(1)))
    return out


MAKER = re.compile(r"Create|Initialize|Init|Startup|Setup")


def forwarded_names() -> set[str]:
    """The port functions already forwarded to their translations."""
    out = set()
    for path in (ROOT / "src").rglob("*.cpp"):
        if path.relative_to(ROOT).as_posix().startswith("src/gen/"):
            continue
        out |= set(re.findall(r"^// translated: FUN_[0-9a-f]{9}\n[^\n(]*?([\w:~]+)\(",
                              path.read_text(encoding="utf-8", errors="replace"), re.M))
    return out


def made_translated(name: str, made: set[str]) -> bool:
    """A teardown whose object the translation builds (`WorldScene6d8Destroy` beside a forwarded
    `WorldScene6d8Create`): the reference's own teardown has to take it apart, since the port's
    never knew its members. The quit-path rule above is for the port's own subsystems."""
    stem = TEARDOWN.split(name.split("::")[-1])[0]
    return bool(stem) and any(MAKER.search(m.split("::")[-1]) and m.split("::")[-1].startswith(stem)
                              for m in made)


def plan(log: Path | None):
    # (every tagged stub with --all, not only those a run reached)
    # (__FUNCTION__ names a function in an unnamed namespace "`anonymous-namespace'::Name")
    hits = None if log is None else {h.replace("`anonymous-namespace'::", "") for h in re.findall(
        r"\[unimplemented\] (.+?)\s*$", log.read_text(encoding="utf-8", errors="replace"), re.M)}
    out, skipped = [], []
    raw = raw_layout_classes()
    objects = raw | laid_out_classes()
    made = forwarded_names()
    pending = []
    manifest = json.loads((ROOT / "src/gen/manifest.json").read_text(encoding="utf-8"))
    translated = set(manifest["translated"])
    # what the next translation can bring in: a forwarder is a root (tools/translate64.py), and the
    # link fallbacks below cover the build in between. Not the C runtime or the protection.
    excluded = set(manifest.get("excluded", {})) | set(manifest.get("native", {}))
    # each translated definition's parameter count (translated.h declares them unprototyped)
    arity = {}
    for f in (ROOT / "src/gen").glob("translated_*.c"):
        for d in re.finditer(r"^/\* ref: FUN_([0-9a-f]{9}) \*/\n[^\n]*?\bFUN_\1\(([^\n]*)\)\s*$",
                             f.read_text(encoding="utf-8"), re.M):
            arity[d.group(1)] = len([p for p in d.group(2).split(",") if p.strip() and p.strip() != "void"])
    for path in (ROOT / "src").rglob("*.cpp"):
        rel = path.relative_to(ROOT).as_posix()
        if rel.startswith("src/gen/"):
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines):
            m = re.match(r"^// ref: FUN_([0-9a-f]{9})\s*$", line)
            if not m:
                continue
            s = stub_at(lines, i)
            if s is None:
                continue
            first, last, ret, name, params, const = s
            if hits is not None and name not in hits and name.split("::")[-1] not in hits:
                continue
            why = None
            if rel.startswith(KEEP_FILES) or name in KEEP_NAMES or m.group(1) in DELIBERATE \
                    or OFFLINE_NAMES.search(name):
                why = "kept offline / the port's own"
            elif TEARDOWN.search(name) and not made_translated(name, made):
                why = "teardown (the quit path is the port's)"
            elif "::" in name and name.rsplit("::", 1)[0].split("::")[-1] not in objects:
                why = "a member function (a port object at the reference's offsets)"
            elif "::" in name and (name.rsplit("::", 1)[1] == name.rsplit("::", 1)[0].split("::")[-1]
                                   or "~" in name):
                why = "a constructor or destructor"
            elif ret not in DEFAULT_RESULT and not forwardable(ret, objects):
                why = f"returns {ret}"
            else:
                for p in split_params(params):
                    ptype = param_type(p)
                    if not forwardable(ptype, objects):
                        why = f"takes {ptype}"
                        break
            if why is None and m.group(1) not in translated:
                if m.group(1) in excluded:
                    why = "not translated (" + (manifest.get("excluded", {}).get(m.group(1))
                                                or "native: " + str(manifest["native"][m.group(1)])) + ")"
                else:
                    pending.append(m.group(1))
            entry = {"file": rel, "line": i + 1, "addr": m.group(1), "name": name, "ret": ret, "params": params,
                     "first": first, "last": last, "const": const}
            (skipped if why else out).append(entry | ({"why": why} if why else {}))
    # a stub whose signature is not the reference's ("Signature not yet known", a callback
    # declared `()`): forwarded, the translated body reads the parameters it was never given
    # (15 of the first 77, 2026-10-18). What is not translated yet is measured on the corpus.
    arity |= corpus_arity(set(pending))
    for e in list(out):
        n = len(split_params(e["params"])) + ("::" in e["name"])
        if arity.get(e["addr"]) is not None and arity[e["addr"]] < n:
            # the port passes more than the reference body reads: a CVar callback's userData, a
            # registration's Lua state the reference fetches itself. Ghidra's count is of the
            # parameters used, so the leading ones are handed on and the rest dropped
            e["pass"] = arity[e["addr"]]
            continue
        if arity.get(e["addr"]) != n:
            out.remove(e)
            skipped.append(e | {"why": f"signature differs (the port's {n} parameters, the reference's "
                                       f"{arity.get(e['addr'])})"})
    return out, skipped


def forwarder(e: dict) -> list[str]:
    params = split_params(e["params"])
    # an unnamed parameter (`void FfxInitialize(bool)`, `CVar*`, `void (*)()`) gets a name to pass
    # along, not its type as one (`(unsigned long long)bool`, C2062)
    named = []
    for k, p in enumerate(params):
        if param_name(p) is not None:
            named.append(p)
        elif re.search(r"\(\s*\*\s*\)", p):
            named.append(re.sub(r"\(\s*\*\s*\)", f"(*p{k})", p, count=1))
        else:
            named.append(f"{p} p{k}")
    params = named
    e = e | {"params": ", ".join(params) if params else e["params"]}
    names = [param_name(p) for p in params]
    types = [param_type(p) for p in params]
    if "::" in e["name"]:
        # a member of a class at the reference's layout: the object first, as the reference passes it
        names, types = ["this"] + names, ["void*"] + types
    dropped = []
    if e.get("pass") is not None:
        dropped = [n for n in names[e["pass"]:] if n != "this"]
        names, types = names[:e["pass"]], types[:e["pass"]]
    # the translated definitions take a float promoted to double (their callers are unprototyped)
    ctypes = ["double" if t.strip().endswith(("float", "double")) else "unsigned long long" for t in types]
    args = ", ".join(f"({c}){n}" for c, n in zip(ctypes, names))
    decl = f"extern \"C\" {'double' if e['ret'] in ('float', 'double') else 'unsigned long long'} FUN_{e['addr']}({', '.join(ctypes)});"
    call = f"FUN_{e['addr']}({args})"
    ret = e["ret"]
    if ret == "void":
        do, fail = f"{call};", ""
    elif ret == "bool":
        do, fail = f"return ({call} & 0xff) != 0;", "return false;"
    elif ret.endswith("*"):
        do, fail = f"return reinterpret_cast<{ret}>({call});", "return nullptr;"
    else:
        do, fail = f"return static_cast<{ret}>({call});", f"return {DEFAULT_RESULT.get(ret, f'static_cast<{ret}>(0)')};"
    return [decl,
            f"// translated: FUN_{e['addr']}",
            f"{ret} {e['name']}({e['params']}){' const' if e.get('const') else ''} {{",
            *[f"    (void){n};" for n in dropped],
            "    __try {",
            f"        {do}",
            f"    }} __except (GenFault(0x{e['addr']}ull, GetExceptionInformation())) {{",
            *([f"        {fail}"] if fail else []),
            "    }",
            "}"]


def apply(entries: list[dict]):
    by_file = {}
    for e in entries:
        by_file.setdefault(e["file"], []).append(e)
    for rel, es in by_file.items():
        path = ROOT / rel
        lines = path.read_text(encoding="utf-8").splitlines()
        for e in sorted(es, key=lambda e: -e["line"]):
            tag = e["line"] - 1
            lines[tag:e["last"] + 1] = forwarder(e)
        if not any("int GenFault(" in l for l in lines):
            # the guard every forwarder runs under (src/gen/RefImage.cpp), after the includes
            last = 0
            for k, l in enumerate(lines):
                s = l.strip()
                if s.startswith("#include"):
                    last = k
                elif s and not s.startswith(("#", "//", "/*", "*")) and k > last:
                    break
            have = any(l.strip() == "#include <windows.h>" for l in lines)
            lines[last + 1:last + 1] = ([] if have else ["#include <windows.h>"]) + [
                "", "extern \"C\" int GenFault(unsigned long long address, EXCEPTION_POINTERS* info);"]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


FALLBACK_START = "// ---- GENERATED by tools/forward_stubs.py: link fallbacks where src/gen is not linked ----"
FALLBACK_END = "// ---- end of link fallbacks ----"


def link_fallbacks() -> int:
    """At the end of each port file that calls translated code: the alternates the linker takes
    when nothing defines the translated function or GenFault (src/util/Unimplemented.cpp).

    A forwarder names them directly, and a test executable that links the library without
    src/gen did not link: ObjectAllocTest pulled os's Path.cpp in for its own reasons and failed on
    FUN_140214150 and GenFault (LNK2019, 2026-10-18). The client links src/gen, which defines both,
    and an alternate name is only used for a symbol nothing defines."""
    changed = 0
    for path in sorted((ROOT / "src").rglob("*.cpp")):
        if path.relative_to(ROOT).as_posix().startswith("src/gen/"):
            continue
        text = path.read_text(encoding="utf-8")
        if FALLBACK_START in text:
            text = text[:text.index(FALLBACK_START)].rstrip("\n") + "\n" + text[text.index(FALLBACK_END) + len(FALLBACK_END):].lstrip("\n")
        code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("//"))
        funs = sorted(set(re.findall(r"\b(FUN_[0-9a-f]{9})\b", code)))
        if not funs and "GenFault(" not in code:
            if text != path.read_text(encoding="utf-8"):
                path.write_text(text, encoding="utf-8", newline="\n")
                changed += 1
            continue
        block = [FALLBACK_START, '#pragma comment(linker, "/include:GenForwardMissing")']
        if "GenFault(" in code:
            block.append('#pragma comment(linker, "/alternatename:GenFault=GenFaultMissing")')
        block += [f'#pragma comment(linker, "/alternatename:{f}=GenForwardMissing")' for f in funs]
        block.append(FALLBACK_END)
        new = text.rstrip("\n") + "\n\n" + "\n".join(block) + "\n"
        if new != path.read_text(encoding="utf-8"):
            path.write_text(new, encoding="utf-8", newline="\n")
            changed += 1
    return changed


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--log")
    ap.add_argument("--all", action="store_true", help="every tagged stub, reached or not")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--list", action="store_true", help="every stub with what is done with it")
    ap.add_argument("--link-fallbacks", action="store_true",
                    help="only refresh the link fallbacks of the files that call translated code")
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if args.link_fallbacks:
        print(f"link fallbacks refreshed in {link_fallbacks()} files")
        return
    if not args.all and not args.log:
        ap.error("--log or --all")
    out, skipped = plan(None if args.all else Path(args.log))
    print(f"{len(out)} stubs to forward, {len(skipped)} left as they are")
    reasons = {}
    for s in skipped:
        reasons.setdefault(s["why"].split(" (")[0] if not s["why"].startswith(("takes", "returns")) else s["why"].split()[0], []).append(s["name"])
    for k, v in sorted(reasons.items(), key=lambda kv: -len(kv[1])):
        print(f"  {len(v):3} {k}: {', '.join(v[:6])}{' ...' if len(v) > 6 else ''}")
    if args.list:
        for e in out:
            print(f"  fwd  {e['file']}:{e['line']}  {e['name']}  FUN_{e['addr']}")
        for e in skipped:
            print(f"  keep {e['file']}:{e['line']}  {e['name']}  FUN_{e['addr']}  -- {e['why']}")
    if args.apply:
        apply(out)
        link_fallbacks()
        print("applied")


if __name__ == "__main__":
    main()
