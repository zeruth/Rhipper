"""The toolchain's C runtime functions named by their bytes.

    python crtsigs.py build [TOOLCHAIN]   signatures from tests/rhtest/bins/<toolchain>/*: each
                                          reference's map names its static C runtime's functions
    python crtsigs.py                     the project's functions matched against its toolchain's
                                          signatures: build/facts/names_crt.json

A static C runtime (/MT) is the same library code in every program its toolchain links: the same
bytes but for the addresses in them. Function ID names a part of it (a VS2010 client's 962 of
1,432); the rest are FUN_ names, and what knows a function by its name (noreturn, the helpers,
the runtime's own versions of the CRT's math) misses them. The rhtest references of the same
toolchain are built with map files naming every function, so their bytes, the image's addresses
and the relative call and jump targets masked, are a signature per name. A project's function
whose masked bytes over a signature's length hash the same is named so, where one name has them.

Signatures: toolchains/<toolchain>/crt_signatures.json. Names: build/facts/names_crt.json, in
data/names.json's form, applied by ApplyFacts before RTTI's and the hand names.
"""
import hashlib, json, re, struct, sys
from collections import defaultdict
from pathlib import Path

import capstone as C

HERE = Path(__file__).resolve().parent
MIN_LEN = 12          # (shorter is too common a run of bytes to name anything by)
SCAN = 4096           # (the most of a function's bytes masked and compared)


class Image:
    def __init__(self, path: Path):
        self.data = path.read_bytes()
        pe = struct.unpack_from("<I", self.data, 0x3c)[0]
        nsec = struct.unpack_from("<H", self.data, pe + 6)[0]
        optsz = struct.unpack_from("<H", self.data, pe + 20)[0]
        self.base = struct.unpack_from("<I", self.data, pe + 24 + 28)[0]
        self.size = struct.unpack_from("<I", self.data, pe + 24 + 56)[0]
        self.secs = []
        for k in range(nsec):
            o = pe + 24 + optsz + 40 * k
            vsz, va, rsz, raw = struct.unpack_from("<IIII", self.data, o + 8)
            self.secs.append((self.base + va, max(vsz, rsz), raw, rsz))

    def read(self, a: int, n: int) -> bytes:
        for va, vsz, raw, rsz in self.secs:
            if va <= a < va + vsz:
                off = a - va
                return self.data[raw + off: raw + min(rsz, off + n)]
        return b""


_md = C.Cs(C.CS_ARCH_X86, C.CS_MODE_32)
_md.detail = True


def masked(img: Image, start: int, n: int) -> bytes:
    """n bytes from start, each instruction's operand that is an address in the image or a
    relative call or jump target zeroed."""
    raw = bytearray(img.read(start, n))
    lo, hi = img.base, img.base + img.size
    for ins in _md.disasm(bytes(raw), start):
        off = ins.address - start
        if ins.mnemonic in ("call", "jmp") or ins.mnemonic.startswith("j") or ins.mnemonic.startswith("loop"):
            # (a relative target: rel32 its last 4 bytes; a rel8 short jump stays, inside the function)
            if ins.size >= 5 and ins.bytes[0] in (0xe8, 0xe9) or (ins.bytes[0] == 0x0f and 0x80 <= ins.bytes[1] <= 0x8f):
                raw[off + ins.size - 4: off + ins.size] = b"\0\0\0\0"
                continue
        for op in ins.operands:
            if op.type == C.x86.X86_OP_IMM and lo <= (op.imm & 0xffffffff) < hi and ins.imm_offset:
                raw[off + ins.imm_offset: off + ins.imm_offset + ins.imm_size] = b"\0" * ins.imm_size
            if op.type == C.x86.X86_OP_MEM and lo <= (op.mem.disp & 0xffffffff) < hi and ins.disp_offset:
                raw[off + ins.disp_offset: off + ins.disp_offset + ins.disp_size] = b"\0" * ins.disp_size
    return bytes(raw)


def digest(b: bytes) -> str:
    return hashlib.sha1(b).hexdigest()[:20]


def callees(img: Image, start: int, n: int) -> list[int]:
    """The targets of the direct calls in n bytes from start, in order."""
    out = []
    for ins in _md.disasm(img.read(start, n), start):
        if ins.mnemonic == "call" and ins.bytes[0] == 0xe8:
            out.append(ins.operands[0].imm & 0xffffffff)
    return out


def signature(img: Image, start: int, b: bytes) -> str:
    """A function's signature: its masked bytes and, for each direct call in them, the masked
    opening bytes of the function called. Masked alone, wrappers that differ only in what they
    call are the same: a client's _swprintf_s took for _sprintf_s, its targets told apart so."""
    parts = [b]
    for t in callees(img, start, len(b)):
        parts.append(masked(img, t, 64)[:2 * MIN_LEN])
    return digest(b"\0".join(parts))


def map_functions(path: Path):
    """(address, name, object) of each function the map lists, by address."""
    out = []
    for line in path.read_text(errors="replace").split("\n"):
        m = re.match(r"\s*[0-9a-f]{4}:[0-9a-f]{8}\s+(\S+)\s+([0-9a-f]{8})\s+f\s+(?:i\s+)?(\S+)", line)
        if m:
            out.append((int(m.group(2), 16), m.group(1), m.group(3)))
    return sorted(set(out))


def build(toolchain: str) -> None:
    bins = HERE / "tests" / "rhtest" / "bins" / toolchain
    sigs: dict[str, set] = defaultdict(set)           # "len:hash" -> names
    # (and each one's first MIN_LEN bytes, masked as the first 64 are: a project's function is
    # masked whole only where its start is one of them, a VS2010 client's 87,000 otherwise slow)
    prefixes: set[str] = set()
    for d in sorted(bins.iterdir()):
        exe = next(d.glob("*.exe"), None)
        mp = next(d.glob("*.map"), None)
        if not exe or not mp:
            continue
        img = Image(exe)
        fns = map_functions(mp)
        for i, (a, name, obj) in enumerate(fns):
            # (the static runtime's: LIBCMT's objects, and its import thunks are no code of its own)
            if not obj.upper().startswith("LIBCMT"):
                continue
            end = fns[i + 1][0] if i + 1 < len(fns) else a + 64
            n = min(end - a, SCAN)
            if n < MIN_LEN:
                continue
            b = masked(img, a, n)
            # (int3 padding after it is no part of it)
            b = b.rstrip(b"\xcc")
            if len(b) < MIN_LEN:
                continue
            sigs[f"{len(b)}:{signature(img, a, b)}"].add(name)
            prefixes.add(digest(masked(img, a, 64)[:MIN_LEN]))
    out = {k: sorted(v) for k, v in sigs.items()}
    dest = HERE / "toolchains" / toolchain / "crt_signatures.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps({"toolchain": toolchain, "signatures": out, "prefixes": sorted(prefixes)},
                               indent=0, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    names = {n for v in out.values() for n in v}
    print(f"{len(out)} signatures of {len(names)} names from {bins} -> {dest}")


def apply() -> None:
    import project
    from pebin import FACTS
    tc = json.loads((FACTS / "toolchain.json").read_text()).get("name") if (FACTS / "toolchain.json").exists() else None
    src = HERE / "toolchains" / str(tc) / "crt_signatures.json"
    dest = FACTS / "names_crt.json"
    if not tc or not src.exists():
        dest.write_text(json.dumps({"_comment": "no C runtime signatures for this toolchain", "functions": {}}) + "\n")
        print(f"no signatures for {tc}")
        return
    db = json.loads(src.read_text())
    sigs = db["signatures"]
    prefixes = set(db.get("prefixes", []))
    by_len: dict[int, dict[str, list]] = defaultdict(dict)
    for k, v in sigs.items():
        n, h = k.split(":")
        by_len[int(n)][h] = v
    lens = sorted(by_len)
    img = Image(Path(project.EXE))
    fns = json.loads((FACTS / "functions.json").read_text())["functions"]
    named, ambiguous = {}, 0
    for f in fns:
        a = int(f["entry"], 16)
        # (only a function nothing named: Function ID's and the RTTI's names stand, an alias's
        # other spelling, `__alloca_probe` for `__chkstk`, no better)
        if not f["name"].startswith("FUN_"):
            continue
        if digest(masked(img, a, 64)[:MIN_LEN]) not in prefixes:
            continue
        b = masked(img, a, SCAN)
        hits = set()
        for n in lens:
            if n > len(b):
                break
            names = by_len[n].get(signature(img, a, b[:n]))
            if names:
                hits.update(names)
                best = (n, names)
        if not hits:
            continue
        # (the longest signature's names: a short one is often a prefix of several)
        n, names = best
        if len(names) != 1:
            ambiguous += 1
            continue
        if f["name"] == names[0]:
            continue
        named[hexa(a)] = {"name": names[0], "evidence": f"{tc} C runtime bytes ({n}), crtsigs.py"}
    dest.write_text(json.dumps({"_comment": "C runtime functions named by their bytes, crtsigs.py",
                                "functions": named}, indent=1) + "\n", encoding="utf-8", newline="\n")
    print(f"{len(named)} functions named from {tc}'s C runtime ({ambiguous} with several names) -> {dest}")


def hexa(a: int) -> str:
    return f"0x{a:x}"


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "build":
        build(sys.argv[2] if len(sys.argv) > 2 else "msvc-16.00-x86")
    else:
        apply()
