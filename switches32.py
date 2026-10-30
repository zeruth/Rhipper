"""MSVC x86 jump tables, read off the instructions: build/facts/switches.json, as switches.py writes
it for x64 (ApplyFacts applies either).

A 32-bit switch jumps through a table of absolute addresses, after a bound check:

    cmp   edx, N ; ja default
    movzx edx, byte ptr [edx + B]              ; (two-level: a byte index table first)
    jmp   dword ptr [edx*4 + T]

Ghidra resolves most of these itself. Where it does not, it reads the table on past its end: a
two-level one's index bytes taken for more addresses (`00 01 01 01`, 0x1010100), decoded as code
and decompiled into the function, "Sanity check requires truncation of jumptable". A client's
FUN_00b75490 ran on so into a JSON writer, `unaff_EDI` its stub, on its startup path 2026-10-27.
ApplyFacts writes each table found here as an override where Ghidra's targets differ.

The case count comes from the bound check (`cmp r, N; ja`: N + 1 cases), on the index register or
the register the byte table is indexed by. Every target must land inside the jump's own function
(its ranges in functions.json), or the table is dropped.

    python switches32.py   -> build/facts/switches.json
"""
from __future__ import annotations

import json

import capstone
from capstone import x86_const as X

from pebin import FACTS, Binary, hexa, write_facts


def main() -> None:
    b = Binary()
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    md.skipdata = True
    funcs = json.load(open(FACTS / "functions.json"))["functions"]
    out: dict[str, list[str]] = {}
    tables: list[tuple[int, int]] = []
    one = two = dropped = 0
    import bisect
    starts = sorted(int(f["entry"], 16) for f in funcs)
    covered = sorted((int(lo, 16), int(hi, 16)) for f in funcs for lo, hi in f.get("ranges", []))
    cov_lo = [c[0] for c in covered]

    def owned(t: int) -> bool:
        k = bisect.bisect_right(cov_lo, t) - 1
        return k >= 0 and covered[k][0] <= t < covered[k][1]

    for f in funcs:
        ranges = [(int(lo, 16), int(hi, 16)) for lo, hi in f.get("ranges", [])]
        entry = int(f["entry"], 16)
        k = bisect.bisect_right(starts, entry)
        next_start = starts[k] if k < len(starts) else entry + 0x10000

        # (or code no function covers between it and the next function: cases Ghidra never
        # followed, the jump taken for a call, "too many branches", a client's 0xcfe7a0)
        def inside(t: int) -> bool:
            return any(lo <= t < hi for lo, hi in ranges) or \
                (entry < t < next_start and b.is_code(t) and not owned(t))

        for lo, hi in ranges:
            if not b.is_code(lo):
                continue
            o = b.off(lo)
            insns = list(md.disasm(bytes(b.image[o:o + (hi - lo)]), lo))
            for k, j in enumerate(insns):
                if j.mnemonic != "jmp" or len(j.operands) != 1 or j.operands[0].type != X.X86_OP_MEM:
                    continue
                m = j.operands[0].mem
                if m.base != 0 or m.index == 0 or m.scale != 4 or m.segment != 0:
                    continue
                table, idx_reg = m.disp & 0xFFFFFFFF, m.index
                # the byte index table and the bound check, walking back
                back = insns[max(0, k - 12):k][::-1]
                bytes_at, bounded, bound = None, {md.reg_name(idx_reg)}, None
                for p, i in enumerate(back):
                    if (bytes_at is None and i.mnemonic == "movzx" and len(i.operands) == 2
                            and i.operands[0].type == X.X86_OP_REG and i.operands[0].reg == idx_reg
                            and i.operands[1].type == X.X86_OP_MEM and i.operands[1].size == 1
                            and i.operands[1].mem.index == 0 and i.operands[1].mem.base != 0):
                        bytes_at = i.operands[1].mem.disp & 0xFFFFFFFF
                        bounded = {md.reg_name(i.operands[1].mem.base)}
                        continue
                    # (another write to the index first: not this table's shape)
                    if (i.operands and i.operands[0].type == X.X86_OP_REG and md.reg_name(i.operands[0].reg) in bounded
                            and i.mnemonic not in ("cmp", "test")):
                        break
                    if (i.mnemonic == "cmp" and len(i.operands) == 2 and i.operands[0].type == X.X86_OP_REG
                            and i.operands[1].type == X.X86_OP_IMM and md.reg_name(i.operands[0].reg) in bounded
                            and p > 0 and back[p - 1].mnemonic == "ja"):
                        bound = i.operands[1].imm
                        break
                # (no bound check at all, the index trusted: `mov edx, [ecx + 0x10]; jmp [edx*4 +
                # 0xcfeaf8]`, a decoder's state machine. Its table runs while its words land in the
                # jump's function: Ghidra, "too many branches", called through it, its cases'
                # register state lost, a client's 0xcfe7a0 2026-10-30)
                # (or the index masked, `and ecx, 3; jmp [ecx*4 + TrailUpVec]`: memcpy's tails)
                if bound is None and bytes_at is None:
                    for i in back:
                        if i.operands and i.operands[0].type == X.X86_OP_REG and i.operands[0].reg == idx_reg:
                            if i.mnemonic == "and" and len(i.operands) == 2 and i.operands[1].type == X.X86_OP_IMM \
                                    and 0 < i.operands[1].imm < 256 and i.operands[1].imm & (i.operands[1].imm + 1) == 0:
                                bound = i.operands[1].imm
                            break
                if bound is None and bytes_at is None and not any(
                        i.operands and i.operands[0].type == X.X86_OP_REG and i.operands[0].reg == idx_reg
                        and i.mnemonic in ("cmp", "test", "and") for i in back):
                    # (up to the next table another jump of the function reads)
                    others = {x.operands[0].mem.disp & 0xFFFFFFFF for x in insns
                              if x.mnemonic == "jmp" and x.operands and x.operands[0].type == X.X86_OP_MEM
                              and x.operands[0].mem.index and x.operands[0].mem.scale == 4}
                    c = 0
                    while c < 256 and 0 <= b.off(table + 4 * c) <= len(b.image) - 4 and inside(b.u32(table + 4 * c)) \
                            and not (c and table + 4 * c in others):
                        c += 1
                    if c >= 2:
                        bound = c - 1
                if bound is None or not (0 <= bound < 4096):
                    continue
                n = bound + 1
                if bytes_at is not None:
                    if not 0 <= b.off(bytes_at) <= len(b.image) - n:
                        continue
                    idx = [b.image[b.off(bytes_at) + c] for c in range(n)]
                else:
                    idx = list(range(n))
                ordered, ok = [], True
                for c in idx:
                    t = b.u32(table + 4 * c)
                    if not inside(t):
                        ok = False
                        break
                    if t not in ordered:
                        ordered.append(t)
                if not ok:
                    dropped += 1
                    continue
                out[hexa(j.address)] = [hexa(t) for t in ordered]
                tables.append((table, table + 4 * (max(idx) + 1)))
                if bytes_at is not None:
                    tables.append((bytes_at, bytes_at + n))
                    two += 1
                else:
                    one += 1
    path = write_facts("switches", {
        "rule": "an indirect jmp through a table of absolute 32-bit addresses (optionally indexed by a byte table) "
                "after a bound check; every target inside the jump's own function",
        "jumps": out,
        "tables": [[hexa(lo), hexa(hi)] for lo, hi in sorted(set(tables))]})
    print(f"{len(out)} jump tables ({one} one-level, {two} two-level), {dropped} dropped -> {path}")


if __name__ == "__main__":
    main()
