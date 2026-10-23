"""Functions that never return.

Two independent signals, and a function is marked only with clear evidence:

1. Structural (the callee): its body -- every .pdata piece of it -- contains no `ret`,
   and every jump out of it (a tail call) goes to a function already known not to
   return. Iterated to a fixed point. An indirect jump that leaves the function counts
   as "may return", so this only ever errs toward leaving a function unmarked.

2. Call sites (the compiler's view): MSVC emits nothing reachable after calling a
   noreturn function. Where the call is the last instruction of its piece or is
   followed by int3 padding, the compiler knew. A callee whose sites are nearly all
   dead-ended was noreturn to the compiler. This only sees calls at the end of a
   block, so it finds few functions, but it confirms the structural set.

This replaces Ghidra's "Non-Returning Functions - Discovered", which stalled on this
binary and is disabled at import (tools/ghidra/ImportOptions.java).

    python tools/noreturn.py   -> build/facts/noreturn.json
"""
from __future__ import annotations

import bisect
import re
import struct
from collections import defaultdict

from pebin import X86, Binary, disassembler, hexa, write_facts

MIN_SITES = 3
MIN_RATIO = 0.95
# and by hand, where neither signal can see it: Lua's error path ends in a longjmp (or the panic
# handler's exit) that the structural pass reads as a return, and the compiler tail-calls
# luaL_error from every handler (`return luaL_error(L, "Usage: ...")`), so no call site is dead.
# Unmarked, Ghidra decompiled the code after a usage error, and the anti-tamper check placed there
# (SendChatMessage) could not be stripped, leaving the handler stubbed as junk (2026-10-18)
HAND = {
    0x142424D80: "luaL_error",
    0x1402B29F0: "lua_error",
    0x1402B5250: "luaG_errormsg",
    0x1402B72D0: "luaD_throw",
}


# 32-bit: imports that never return, standing for themselves as a tail target (DEAD) where a
# function's last instruction calls one through its import slot
NORETURN_IMPORTS = {"ExitProcess", "ExitThread", "FreeLibraryAndExitThread", "RaiseException",
                    "TerminateProcess", "_exit", "exit", "abort", "_invoke_watson", "_CxxThrowException"}
DEAD = -1
# 32-bit: MSVC runtime functions that never return, by the names Ghidra's function ID gave them
# (functions.json): ___report_gsfailure ends in TerminateProcess with code after it, so neither
# signal sees it, and it saves every register into its crash context (protos32.py would read
# them as inputs of every caller of __security_check_cookie)
CRT_NORETURN = {"___report_gsfailure", "__invoke_watson", "__invalid_parameter", "__exit", "_exit",
                "__amsg_exit", "_abort", "terminate", "___crtExitProcess", "__endthreadex",
                "__CxxThrowException@8", "_inconsistency", "__purecall", "___raise_securityfailure"}


def noreturn_slots(b: Binary) -> set[int]:
    """The import slots (VA) of NORETURN_IMPORTS."""
    import pefile
    pe = pefile.PE(str(b.path), fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    slots = {imp.address for dll in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) for imp in dll.imports
             if imp.name and imp.name.decode(errors="replace") in NORETURN_IMPORTS}
    pe.close()
    return slots


def body_facts(b: Binary):
    """Per root function: has a ret?, direct tail-jump targets outside it, any
    indirect jump that is not a switch."""
    dead_slots = noreturn_slots(b) if X86 else set()
    md = disassembler()
    md.skipdata = True
    pieces_of = defaultdict(list)
    for st, en, r in zip(b.piece_starts, b.piece_ends, b.piece_root):
        pieces_of[r].append((st, en))
    facts = {}
    for root, pieces in pieces_of.items():
        has_ret = False
        tails = set()
        indirect_out = False
        raises_cxx = raises_cxx_call = False
        for st, en in pieces:
            o = b.off(st)
            mn = None
            for ins in md.disasm_lite(bytes(b.image[o : o + (en - st)]), st):
                _addr, _size, mn, ops = ins
                if X86:
                    # the 'msc' exception code, inline or as the first word of the static
                    # EXCEPTION_RECORD template the function copies (`mov esi, 0x1118af0`)
                    for tok in re.findall(r"0x[0-9a-f]+", ops):
                        v = int(tok, 16)
                        if v == 0xE06D7363 or (b.section_of(v) and b.off(v) + 4 <= len(b.image)
                                               and b.u32(v) == 0xE06D7363):
                            raises_cxx = True
                    if mn == "call" and ops.startswith("dword ptr [0x") and int(ops[11:-1], 16) in dead_slots:
                        raises_cxx_call = True
                if mn in ("ret", "retf", "iretq", "iretd", "iret"):
                    has_ret = True
                elif mn == "jmp":
                    if ops.startswith("0x"):
                        t = int(ops, 16)
                        if b.func_containing(t) != root:
                            tails.add(t)
                    elif "rip" not in ops and not ops.startswith("qword ptr [r"):
                        # jmp reg: a switch dispatch inside the function, or a tail
                        # call through a register; either way it may leave and return
                        indirect_out = True
                    else:
                        indirect_out = True
            # 32-bit: Ghidra ends a range where code runs on into the next function it made
            # (the CRT's strchr at 0xc51da0 is 6 bytes, then falls into its shared tail): that
            # is a tail call to whatever follows. .pdata pieces end on a ret or jmp. A range
            # that ends on a call ends there because the callee does not return (a throw
            # helper's _CxxThrowException), so it continues only if the callee does.
            if X86 and mn not in ("ret", "retf", "iret", "iretd", "jmp", "int3", "ud2", "hlt", None):
                if mn == "call" and ops.startswith("0x"):
                    tails.add(int(ops, 16))
                elif mn == "call" and ops.startswith("dword ptr [0x") and int(ops[11:-1], 16) in dead_slots:
                    tails.add(DEAD)
                elif b.func_containing(en) != root:
                    tails.add(en)
        if raises_cxx and raises_cxx_call:
            # MSVC's _CxxThrowException: RaiseException(0xE06D7363 'msc', ...) then a ret the
            # compiler knows is never reached (it declares the function noreturn)
            has_ret, tails, indirect_out = False, {DEAD}, False
        facts[root] = (has_ret, tails, indirect_out)
    return facts


def main() -> None:
    b = Binary()
    # (HAND names FrostLite's binary: on any other, those addresses are no function starts)
    hand = {a: n for a, n in HAND.items() if b.is_func_start(a)}
    if X86:
        import json
        from project import FACTS
        for f in json.loads((FACTS / "functions.json").read_text())["functions"]:
            if f["name"] in CRT_NORETURN:
                hand[int(f["entry"], 16)] = f["name"]

    # ---- structural fixed point -------------------------------------------------
    facts = body_facts(b)
    # (the 32-bit runtime names seed it: a function that ends by calling one does not return either)
    noret: set[int] = {DEAD} | (set(hand) if X86 else set())
    changed = True
    while changed:
        changed = False
        for f, (has_ret, tails, indirect) in facts.items():
            if f in noret or has_ret or indirect:
                continue
            if all(t in noret for t in tails):
                noret.add(f)
                changed = True
    noret.discard(DEAD)

    # ---- call-site signal -------------------------------------------------------
    s, d = b.bytes_of(".text")
    piece_end = set(b.piece_ends)
    sites: dict[int, int] = defaultdict(int)
    dead: dict[int, int] = defaultdict(int)
    for m in re.finditer(rb"\xe8(....)", d, re.S):
        insn = s + m.start()
        i = bisect.bisect_right(b.piece_starts, insn) - 1
        if i < 0 or insn >= b.piece_ends[i]:
            continue
        tgt = insn + 5 + struct.unpack("<i", m.group(1))[0]
        if not b.is_func_start(tgt):
            continue
        nxt = insn + 5
        sites[tgt] += 1
        if nxt in piece_end or d[nxt - s] == 0xCC:
            dead[tgt] += 1
    callsite = {t for t, n in sites.items() if n >= MIN_SITES and dead[t] / n >= MIN_RATIO}

    out = write_facts("noreturn", {
        "rule": "structural: no ret in any piece and every tail jump to a noreturn function; "
                f"call-site: >= {MIN_SITES} sites, >= {MIN_RATIO:.0%} followed by int3 / end of piece",
        "functions": {
            hexa(f): {"structural": f in noret, "callsite": f in callsite,
                      "sites": sites.get(f, 0), "dead_sites": dead.get(f, 0),
                      **({"hand": hand[f]} if f in hand else {})}
            for f in sorted(noret | callsite | set(hand))
        },
    })
    both = noret & callsite
    print(f"structural {len(noret)}, call-site {len(callsite)}, both {len(both)}, "
          f"call-site only {len(callsite - noret)} -> {out}")
    print("most-called structural noreturn functions:")
    for f in sorted(noret, key=lambda f: -sites.get(f, 0))[:15]:
        print(f"  {hexa(f)}  sites {sites.get(f, 0):5}  dead {dead.get(f, 0):5}"
              f"{'  (call-site agrees)' if f in callsite else ''}")
    for f in sorted(callsite - noret):
        print(f"  call-site only: {hexa(f)}  {dead[f]}/{sites[f]}  has_ret={facts.get(f, (None,))[0]}")


if __name__ == "__main__":
    main()
