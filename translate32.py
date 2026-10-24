"""A 32-bit reference's decompilation translated to C for an x64 port: translate.py's counterpart
for rhipper.json "arch": "x86" (first CrystalCore, FFXIV's ARR beta client).

The port's memory model (runtime32/Ghidra32.h says it at length): the port is linked
/LARGEADDRESSAWARE:NO, so Windows keeps all of its memory below 2 GB (2026-10-23: its stack,
heaps, VirtualAlloc, kernel32/user32/d3d9, GetProcAddress, the command line; only ntdll stays
high); the reference's image is mapped at its own addresses; so every address fits the reference's
4-byte slots. What changes from Ghidra's text:

- a pointer stored in memory is 4 bytes: every pointer type with more than one level spells its
  inner levels __ptr32 (`int **` -> `int * PTR32 *`), which MSVC loads and stores as 4 bytes and
  widens on use. The outer level, a register's or a local's, is the host's own;
- every translated function is F_<address>, its parameters 32-bit integers it narrows itself into
  Ghidra's declared types, as the reference's code passed them (a caller handing over an `int`
  that holds an address and one handing over a pointer pass the same 32 bits);
- a virtual call gets its object: on x86 `this` travels in ecx and Ghidra leaves it out of
  `(**(code **)(*(int *)this + 0x10))()`;
- the reference's globals are their addresses (REFG / REFP), its functions as values their
  reference addresses (the runtime writes a jump at each to its translation), its imports calls to
  gen_imp_<name> adapters (gen/imports.c);
- what the decompiler lost (in_ / unaff_ / extraout_ registers, member access through types C does
  not have, the caller's stack) becomes a stub that logs its address once (GenUnimplemented).

    python translate32.py                    every function, then compile and demote until clean
    python translate32.py --no-build         write src/gen only
    python translate32.py --only 0x4045e0    one function (and stubs for the rest)

Writes <gen>/translated_NNN.c, translated.h, stubs.c, jumps.c, imports.c, manifest.json.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import project
from project import FACTS, GEN, ROOT
from signedness import signed_tests

CORPUS = ROOT / "build/corpus.jsonl"
REFDATA = ROOT / "build/refdata.jsonl"
OBJ = ROOT / "build/gen-obj"
MANIFEST = GEN / "manifest.json"
DEMOTED = GEN / "demoted.json"
# the header the translation is written against: Rhipper's, copied into the gen directory on each
# emit, so a project builds against the one its translation was made for
HEADER = Path(__file__).resolve().parent / "runtime32" / "Ghidra32.h"
PER_FILE = 400

# the type words Ghidra32.h defines (or C has)
KNOWN_TYPES = {
    "gen_v16", "gen_v8", "gen_v12", "gen_v24", "gen_v32", "gen_v48", "gen_v64", "gen_code32", "void", "char", "short", "int", "long", "float", "double", "bool", "wchar_t", "signed", "unsigned",
    "undefined", "undefined1", "undefined2", "undefined3", "undefined4", "undefined5", "undefined6",
    "undefined7", "undefined8", "byte", "uchar", "uint1", "sbyte", "int1", "ushort", "word", "wchar16", "uint2",
    "int2", "uint", "uint3", "uint4", "dword", "int3", "int4", "ulong", "longlong", "ulonglong", "qword",
    "uint5", "uint6", "uint7", "uint8", "int5", "int6", "int7", "int8", "float4", "float8", "float10",
    "gen_size32", "gen_ptrdiff32", "__time64_t", "code", "pointer",
    "HANDLE", "HMODULE", "HINSTANCE", "HWND", "HDC", "HKEY", "HICON", "HCURSOR", "HMENU", "HBRUSH", "HGLOBAL",
    "HLOCAL", "HKL", "HGDIOBJ", "HIMC", "LPVOID", "PVOID", "LPCVOID", "LPSTR", "LPCSTR", "LPWSTR", "LPCWSTR",
    "LPDWORD", "LPLONG", "LPBYTE", "LPBOOL", "LPWORD", "FARPROC", "BOOL", "BOOLEAN", "BYTE", "WORD", "DWORD",
    "DWORD64", "DWORDLONG", "UINT", "INT", "LONG", "ULONG", "SHORT", "USHORT", "CHAR", "WCHAR", "LONGLONG",
    "ULONGLONG", "HRESULT", "LSTATUS", "LCID", "ATOM", "SIZE_T", "ULONG_PTR", "DWORD_PTR", "UINT_PTR",
    "LONG_PTR", "INT_PTR", "LPARAM", "WPARAM", "LRESULT", "SOCKET", "BSTR", "GEN_LPANY",
    "LPCRITICAL_SECTION", "PRTL_CRITICAL_SECTION",
}
# the Windows structures Ghidra32.h lays out as on x86: a local of one may be used by member
STRUCT_TYPES = {"_FILETIME", "FILETIME", "_LARGE_INTEGER", "LARGE_INTEGER", "_ULARGE_INTEGER", "ULARGE_INTEGER",
                "_STARTUPINFOW", "STARTUPINFOW", "_STARTUPINFOA", "STARTUPINFOA", "_SYSTEMTIME", "SYSTEMTIME",
                "_OSVERSIONINFOA", "OSVERSIONINFOA", "_OSVERSIONINFOW", "OSVERSIONINFOW", "_SYSTEM_INFO",
                "SYSTEM_INFO", "tagPOINT", "POINT", "tagRECT", "RECT"}
STRUCT_POINTERS = {"LPPOINT", "LPRECT"}
# the 8-byte ones a function takes or returns by value (in edx:eax on x86): 64-bit integers across
# the call, the structure inside
STRUCT8 = {"_FILETIME": "ULONGLONG", "FILETIME": "ULONGLONG", "_LARGE_INTEGER": "LONGLONG",
           "LARGE_INTEGER": "LONGLONG", "_ULARGE_INTEGER": "ULONGLONG", "ULARGE_INTEGER": "ULONGLONG"}
KNOWN_TYPES |= STRUCT_TYPES | STRUCT_POINTERS
# the image's own DOS header as Ghidra names its fields: (offset, type), or None for an array's address
DOS_HEADER = {"e_magic": (0x0, "ushort"), "e_cblp": (0x2, "ushort"), "e_cp": (0x4, "ushort"),
              "e_crlc": (0x6, "ushort"), "e_cparhdr": (0x8, "ushort"), "e_minalloc": (0xa, "ushort"),
              "e_maxalloc": (0xc, "ushort"), "e_ss": (0xe, "ushort"), "e_sp": (0x10, "ushort"),
              "e_csum": (0x12, "ushort"), "e_ip": (0x14, "ushort"), "e_cs": (0x16, "ushort"),
              "e_lfarlc": (0x18, "ushort"), "e_ovno": (0x1a, "ushort"), "e_res_4_": (0x1c, None),
              "e_res": (0x1c, None), "e_oemid": (0x24, "ushort"), "e_oeminfo": (0x26, "ushort"),
              "e_res2_10_": (0x28, None), "e_res2": (0x28, None), "e_lfanew": (0x3c, "int"),
              "e_program": (0x40, None)}
# the Windows typedefs Ghidra32.h makes (4-byte) pointers
WIN_POINTERS = {"HANDLE", "HMODULE", "HINSTANCE", "HWND", "HDC", "HKEY", "HICON", "HCURSOR", "HMENU", "HBRUSH",
                "HGLOBAL", "HLOCAL", "HKL", "HGDIOBJ", "HIMC", "LPVOID", "PVOID", "LPCVOID", "LPSTR", "LPCSTR",
                "LPWSTR", "LPCWSTR", "LPDWORD", "LPLONG", "LPBYTE", "LPBOOL", "LPWORD", "FARPROC", "BSTR",
                "GEN_LPANY", "LPCRITICAL_SECTION", "PRTL_CRITICAL_SECTION", "pointer", "LPPOINT", "LPRECT"}
# C words that look like types to the scans below but are not
NOT_TYPES = {"return", "sizeof", "if", "while", "for", "switch", "case", "goto", "else", "do", "break",
             "continue", "default", "const", "volatile", "struct", "union", "enum", "static", "extern"}
FLOATS = {"float", "double", "float4", "float8", "float10"}
WIDE = {"longlong", "ulonglong", "qword", "undefined8", "uint8", "int8", "uint5", "uint6", "uint7", "int5",
        "int6", "int7", "undefined5", "undefined6", "undefined7", "DWORD64", "DWORDLONG", "LONGLONG",
        "ULONGLONG", "__time64_t"}
# (and their keep variants, `__thiscall_keep_edx`: ApplyFacts' x86 keep conventions)
CC = re.compile(r"\b(__thiscall|__cdecl|__stdcall|__fastcall|__vectorcall)(?:_keep(?:_[a-z]+)+)?\b\s*")
LOST = re.compile(r"\b(in_[A-Z][A-Za-z0-9_]*|in_stack_[0-9a-f]+|unaff_[A-Za-z0-9_]+|extraout_[A-Za-z0-9_]+|in_FS_OFFSET)\b")
# a symbol ending in its address (DAT_00401000, PTR_FUN_00401000, s_text_00401000, LAB_...)
ADDR_SYM = re.compile(r"(?<![\w$])(_*(?:DAT|PTR|LAB|UNK|BYTE|WORD|DWORD|QWORD|s|u|ws|switchdataD|vtable)(?:_\w*?)?_([0-9a-f]{8})(?:_\d+)?)(?![\w$])")
# C's own words, and the names Ghidra32.h defines that the body may use
C_WORDS = {"if", "else", "while", "for", "do", "switch", "case", "default", "break", "continue", "return",
           "goto", "sizeof", "const", "volatile", "struct", "union", "enum", "static", "extern", "unsigned",
           "signed", "true", "false", "NULL", "this"}
HEADER_NAMES = {"REFG", "REFP", "GP", "PTR32", "MXCSR", "ExceptionList", "GenUnimplemented", "POPCOUNT", "ABS",
                "SQRT", "ROUND", "TRUNC", "FLOOR", "CEIL", "HeapCompatibilityInformation", "uintptr_t",
                "intptr_t", "uint32_t", "int32_t", "uint64_t", "int64_t", "uint16_t", "int16_t", "uint8_t",
                "int8_t", "__ptr32", "__uptr", "_InterlockedExchange", "NAN", "INFINITY",
                "__debugbreak", "_rotl", "_rotr", "_rotl64", "_rotr64", "fabs", "sqrt",
                "floor", "ceil", "trunc", "nearbyint", "memcpy", "memset", "rdtsc", "GEN_PIECE", "GEN_ISNAN",
                "gen_piece_set", "gen_fl2bits", "gen_d2bits", "gen_bits2f", "gen_bits2d", "GEN_TOF", "GEN_TOD",
                "GEN_TOP", "GEN_FLT_TO"}
_header_names: set[str] | None = None


def header_names() -> set[str]:
    """The names the project's Ghidra32.h defines (macros, functions, typedefs, variables): read
    from the header itself, so a helper it lacks (CONCAT28, a pseudo-op) makes its user a stub
    here, not an implicit declaration the linker cannot resolve."""
    global _header_names
    if _header_names is None:
        text = strip_comments(HEADER.read_text(encoding="utf-8"))
        names = set(re.findall(r"#define\s+([A-Za-z_]\w*)", text))
        names |= set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", text))      # functions declared or defined
        names |= set(re.findall(r"\b([A-Za-z_]\w*)\s*;", text))        # typedef names, variables
        _header_names = names | HEADER_NAMES
    return _header_names
# where Ghidra maps the x86 fs segment (the TEB) of a 32-bit Windows program
TEB_LO, TEB_HI = 0xFFDFF000, 0xFFE00000
# imports whose adapters the runtime writes itself (their structures differ between x86 and x64):
# every gen_imp_<name> runtime32's sources define (a project listing them too would be a duplicate
# symbol otherwise), and rhipper.json "import_overrides" for a project's own
OVERRIDES = set(project.CONFIG.get("import_overrides", [])) | {
    n for f in (Path(__file__).resolve().parent / "runtime32").glob("*.cpp")
    for n in re.findall(r"(?m)^\s*(?:extern \"C\"\s+)?unsigned int gen_imp_(\w+)\s*\(", f.read_text(encoding="utf-8"))}
IDENT = r"[A-Za-z_~][\w$@]*(?:::[A-Za-z_~][\w$@]*)*"


# the C runtime's and Winsock's type names Ghidra uses, at the reference's widths (intptr_t and
# size_t are 32-bit there; the host's would be 8 bytes)
TYPE_ALIASES = {
    "size_t": "gen_size32", "rsize_t": "gen_size32", "ptrdiff_t": "gen_ptrdiff32", "intptr_t": "int",
    "uintptr_t": "uint", "errno_t": "int", "wint_t": "ushort", "wctype_t": "ushort", "u_short": "ushort",
    "u_long": "ulong", "u_int": "uint", "u_char": "uchar", "__uint64": "ulonglong", "_locale_t": "void *",
    "time_t": "__time64_t", "__time32_t": "int", "LPCH": "LPSTR", "LPWCH": "LPWSTR", "PCHAR": "LPSTR",
    # the CRT's initializer function types (_initterm's tables)
    "_PVFV": "code *", "PVFV": "code *", "_PIFV": "code *", "PIFV": "code *",
}
_ALIAS = re.compile(r"\b(" + "|".join(TYPE_ALIASES) + r")\b")
# Windows' pointer typedefs Ghidra spells from its type library (LPCRITICAL_SECTION, PBYTE,
# LPSECURITY_ATTRIBUTES, PEXCEPTION_RECORD, ...): 4-byte pointers, as LPVOID is (Ghidra32.h)
_WINPTR = re.compile(r"\b(?!PTR_)(?:LP|P)C?[A-Z]+(?:_[A-Z]+)*\b")


def alias_types(text: str) -> str:
    text = _ALIAS.sub(lambda m: TYPE_ALIASES[m.group(1)], text)
    return _WINPTR.sub(lambda m: m.group(0) if m.group(0) in KNOWN_TYPES else "GEN_LPANY", text)


# Ghidra's names for raw memory it has no symbol for (iRam00401234, pvRam00401234): the prefix
# is the type
RAM = re.compile(r"\b([a-z]{0,3})Ram([0-9a-f]{8})\b")
RAM_TYPES = {"i": "int", "u": "uint", "c": "char", "b": "byte", "s": "short", "us": "ushort", "f": "float",
             "d": "double", "uc": "uchar", "l": "longlong", "ul": "ulonglong", "pv": "undefined * PTR32",
             "pc": "char * PTR32", "pi": "int * PTR32", "pu": "uint * PTR32", "pp": "undefined * PTR32",
             "pf": "float * PTR32", "pb": "byte * PTR32", "pcV": "code * PTR32", "pcVar": "code * PTR32"}


# the words of a variadic function's arguments after its fixed ones that its argument block holds
# (rewrite): a printf's format and its values, a scanf's pointers
VA_WORDS = 32

# the stack below a function's locals, by its offset from the entry esp (`&stack0xffffeffc`,
# `in_stack_fffff000`): where it builds what it passes by value (out_stack)
OUT_STACK = re.compile(r"(?:in_stack_|stack0x)(f[0-9a-f]{7})")


def out_stack(body: str) -> str:
    """An object passed by value, as MSVC passes one: the caller reserves room below its locals,
    builds the object there in place (`FUN_0042cc20(&stack0xffffeffc, ...)`, a string's
    constructor), and calls, the room now the callee's stack arguments, which Ghidra shows as
    `in_stack_ffffeffc, in_stack_fffff000, ...` (FUN_00415b00's log tab names, 2026-10-23). The
    room is one block: a local buffer here, each offset into it at its distance from the lowest."""
    offs = sorted({int(m.group(1), 16) for m in re.finditer(r"\b" + OUT_STACK.pattern + r"\b", body)})
    if not offs:
        return body
    lo, hi = offs[0], offs[-1] + 4
    # (their declarations go: each is a place in the buffer now, of its declared type, a pointer
    # stored as the reference stores one)
    types = {}
    for m in re.finditer(r"(?m)^\s*([A-Za-z_][\w ]*?[\s*]+)in_stack_(f[0-9a-f]{7})\s*;", body):
        t = m.group(1).strip()
        stars = t.count("*")
        base = t.replace("*", "").strip()
        # (a function pointer stored: gen_code32, as code_slots makes every one)
        types[m.group(2)] = "gen_code32" if base == "code" and stars == 1 else \
            (base + " * PTR32" * stars) if stars else t
    body = re.sub(r"(?m)^\s*[A-Za-z_][\w ]*?[\s*]+in_stack_f[0-9a-f]{7}\s*;\s*\n", "", body)
    body = re.sub(r"&\s*stack0x(f[0-9a-f]{7})\b", lambda m: f"(gen_out + 0x{int(m.group(1), 16) - lo:x})", body)
    body = re.sub(r"\(uint\)\s*\(gen_out", "(uint)(uintptr_t)(gen_out", body)
    body = re.sub(r"\bin_stack_(f[0-9a-f]{7})\b",
                  lambda m: f"(*({types.get(m.group(1), 'undefined4')} *)(gen_out + 0x{int(m.group(1), 16) - lo:x}))", body)
    return body.replace("{", "{\n  undefined1 gen_out[0x%x];" % (hi - lo), 1)


# the byte-array sizes Ghidra32.h has a gen_v<n> for (`undefined1 (*p) [12]`, a vector of three floats)
V_SIZES = "8|12|16|24|32|48|64"


def cpu_state(c: str) -> str:
    """Processor state Ghidra reads as a lost register that the host has as an intrinsic: XCR0
    (xgetbv, ecx = 0; the CRT's __isa_available_init, whose result picks /O2's vector paths)."""
    if "in_XCR0" not in c:
        return c
    c = re.sub(r"(?m)^[ \t]*\w+ in_XCR0;\n", "", c)
    return re.sub(r"\bin_XCR0\b", "(uint)_xgetbv(0)", c)


def v16_forms(c: str) -> str:
    """An SSE register's 16 bytes as C can have them (Ghidra32.h gen_v16): `undefined1 (*p) [16]`
    a `gen_v16 *` (a pointer to the 16-byte array, stepping 16 and indexing its bytes), and a
    value stored into one, `*p = (undefined1 [16])0x0;`, GEN_V16_SET. __VEC_memzero, the CRT
    memset's path for large zero fills, is written so (2026-10-23)."""
    c = re.sub(r"\bundefined1\s*\(\s*\*\s*([A-Za-z_]\w*)\s*\)\s*\[\s*(" + V_SIZES + r")\s*\]", r"gen_v\2 * \1", c)
    c = re.sub(r"\(\s*undefined1\s*\(\s*\*\s*\)\s*\[\s*(" + V_SIZES + r")\s*\]\s*\)", r"(gen_v\1 *)", c)
    c = re.sub(r"(?m)^([ \t]*)([^=;\n{}]+?)\s*=\s*\(\s*undefined1\s*\[\s*16\s*\]\s*\)\s*([^;\n]+);[ \t]*$",
               r"\1GEN_V16_SET(\2, \3);", c)
    # (and one copied whole, `auVar1 = *(gen_v16 *)p;`, `*p = auVar1;`: 16 bytes)
    arrays = set(re.findall(r"(?m)^[ \t]+undefined1\s+([A-Za-z_]\w*)\s*\[\s*(?:" + V_SIZES + r")\s*\]\s*;", c))
    ptrs = set(re.findall(r"\bgen_v\d+\s*\*\s*([A-Za-z_]\w*)", c))

    def v16(e: str) -> bool:
        e = e.strip()
        return e in arrays or bool(re.match(r"\*\s*\(\s*gen_v16\s*\*\s*\)", e)) \
            or any(re.fullmatch(r"\*\s*" + p + r"|" + p + r"\s*\[[^\]]+\]", e) for p in ptrs)

    def copy(m):
        lhs, rhs = m.group(2), m.group(3)
        # (16 bytes on both sides: `puVar5 = local_50;` is a pointer taking an array's address,
        # and copied as 16 bytes it overran the pointer, C4789)
        if v16(lhs) and v16(rhs):
            # (the smaller of the two: `auVar35 = *param_4` of a 12-byte vector into a register)
            l, r = lhs.strip(), rhs.strip()
            return (f"{m.group(1)}memcpy(&({l}), &({r}), sizeof({r}) < sizeof({l}) ? sizeof({r}) : sizeof({l}));")
        return m.group(0)
    c = re.sub(r"(?m)^([ \t]*)([^=;\n{}()]+?|\*\s*\(\s*gen_v16\s*\*\s*\)[^=;\n]+?)\s*=(?!=)\s*([^;\n]+);[ \t]*$", copy, c)
    return sse_ops(c, arrays, v16)


SSE_OPS = {"minps", "maxps", "divps", "rsqrtps", "rcpps", "sqrtps", "packssdw", "psllw", "pmulld"}
SSE_BITS = {"|": "or", "&": "and", "^": "xor"}
# (the ones on integer lanes)
SSE_INT_OPS = {"packssdw", "psllw", "pmulld"}


def sse_ops(c: str, arrays: set[str], v16) -> str:
    """Ghidra's SSE pseudo-ops as Ghidra32.h's helpers: `auVar9 = rsqrtps(in_XMM3, auVar1);` ->
    `gen_rsqrtps(&(auVar9), &(in_XMM3), &(auVar1));`, a vector `a | b` operand computed into a
    temporary before its statement, `movmskps(r, v)` the int `gen_movmskps(&(v))` wherever it is.
    A full xmm register the decompiler lost (`in_XMM3`, the pseudo-op's destination as it found it,
    ignored by the unary ones) a zeroed 16-byte local. 273 functions, the game's vector math,
    were stubs (2026-10-23)."""
    if not re.search(r"\b(?:" + "|".join(SSE_OPS | {"movmskps"}) + r")\(", c) and "in_XMM" not in c:
        return c
    lines = c.split("\n")
    temps = [0]
    out = []

    def operand(e: str, pre: list) -> str | None:
        """An operand's address (pre: the statements computing a temporary first), or None."""
        e = e.strip()
        while e.startswith("(") and match_paren(e, 0) == len(e) and e[1:-1].count("(") == e[1:-1].count(")"):
            e = e[1:-1].strip()
        parts = None
        for op in ("|", "^", "&"):
            ps = split_top(e, op)
            if len(ps) == 2 and not ps[0].strip().endswith("&") and ps[1].strip():
                parts = (op, ps)
                break
        if parts:
            op, (x, y) = parts
            ax, ay = operand(x, pre), operand(y, pre)
            if ax is None or ay is None:
                return None
            t = f"gen_vt{temps[0]}"
            temps[0] += 1
            pre.append(f"undefined1 {t}[16]; gen_v16_{SSE_BITS[op]}({t}, {ax}, {ay});")
            return t
        if re.fullmatch(r"0x[0-9a-f]+|\d+", e):
            return f"(&(unsigned long long[2]){{{e}, 0}})"
        if v16(e) or re.fullmatch(r"_*(?:DAT|UNK)_[0-9a-f]{8}", e):
            return f"&({e})"
        return None

    for line in lines:
        pre: list[str] = []
        ind = re.match(r"[ \t]*", line).group(0)
        # (movmskps in any expression: an int)
        ok = True

        def mov(m):
            nonlocal ok
            args = split_top(line[m.end() - 1 + 1:match_paren(line, m.end() - 1) - 1])
            a = operand(args[-1], pre) if args else None
            if a is None:
                ok = False
                return m.group(0)
            return f"gen_movmskps({a})"
        while ok:
            mm = re.search(r"\bmovmskps\(", line)
            if not mm:
                break
            close = match_paren(line, mm.end() - 1)
            if close < 0:
                break
            rep = mov(mm)
            if not ok:
                break
            line = line[:mm.start()] + rep + line[close:]
        sm = re.fullmatch(r"([ \t]*)(.+?)\s*=\s*(" + "|".join(SSE_OPS) + r")\((.*)\);[ \t]*", line)
        if sm:
            args = split_top(sm.group(4))
            dst = operand(sm.group(2), pre)
            ops = [operand(x, pre) for x in args]
            if dst is not None and len(ops) == 2 and None not in ops:
                line = f"{sm.group(1)}gen_{sm.group(3)}({dst}, {ops[0]}, {ops[1]});"
        else:
            bm = re.fullmatch(r"([ \t]*)([A-Za-z_]\w*)\s*=\s*(.+);[ \t]*", line)
            if bm and bm.group(2) in arrays:
                r = operand(bm.group(3), pre)
                if r is not None and r.startswith("gen_vt"):
                    line = f"{bm.group(1)}memcpy({bm.group(2)}, {r}, 16);"
        # (a temporary's statements before a loop condition would run once: left as it was)
        if pre and re.match(r"\s*(?:while|for|\}\s*while)\b", line):
            out.append(line)
            continue
        out.extend(ind + p for p in pre)
        out.append(line)
    return "\n".join(out)


FRAME_LOCAL = r"(?:local|[a-z]{0,3}Stack)_([0-9a-f]+)"
FRAME_DECL = re.compile(r"(?m)^[ \t]+(?!(?:return|goto|case|else|do)\b)(?!(?:local|[a-z]{0,3}Stack)_[0-9a-f]+\b)"
                        r"((?:struct\s+)?[A-Za-z_]\w*(?:[ \t]+[A-Za-z_]\w*)*?(?:[ \t]*\*(?:[ \t]*PTR32)?)*)"
                        r"[ \t]*\b(" + FRAME_LOCAL + r")[ \t]*(\[[ \t]*(?:0x)?[0-9a-f]+[ \t]*\])?[ \t]*;[ \t]*\n")


def frame_locals(body: str) -> str:
    """The reference's frame, where its code takes a local's address or uses a local array: every
    `local_N` and `*Stack_N` a slot of one buffer at its offset in the x86 frame (N, below the
    entry esp). Ghidra splits an aggregate the code builds on the stack into one local per field;
    as separate C locals they lie wherever the compiler puts them, and a callee handed the first's
    address read the others from the wrong place: FUN_00415b00's config entry `&local_24`, its
    string pointer `local_18` at +0xc of it, read as 0 (2026-10-23)."""
    if not (re.search(r"&\s*" + FRAME_LOCAL + r"\b", body) or
            re.search(r"(?m)^[ \t]+[A-Za-z_][\w \t*]*?\b" + FRAME_LOCAL + r"[ \t]*\[", body)):
        return body
    decls = list(FRAME_DECL.finditer(body))
    if not decls:
        return body
    size = max(int(m.group(3), 16) for m in decls)
    size = (size + 15) & ~15
    repl = {}
    for m in decls:
        t = " ".join(m.group(1).split())
        name, at = m.group(2), size - int(m.group(3), 16)
        stored = t + " PTR32" if t.endswith("*") else t      # (a pointer, as the reference stores one)
        if re.fullmatch(r"code\s*\*", t) and not m.group(4):
            # (a function pointer: 4 bytes as gen_code32, a call through it converted, code_slots)
            stored = "gen_code32"
            body = re.sub(r"\(\s*\*\s*" + name + r"\s*\)(?=\s*\()", f"((code *){name})", body)
        if m.group(4):
            repl[name] = f"(({stored} *)(gen_frame + 0x{at:x}))"
        else:
            repl[name] = f"(*({stored} *)(gen_frame + 0x{at:x}))"
    body = FRAME_DECL.sub(lambda m: "" if m.group(2) in repl else m.group(0), body)
    # (an array's address is where it starts)
    arrays = [m.group(2) for m in decls if m.group(4)]
    if arrays:
        alt = "|".join(arrays)
        # (`&(local_x)`, as the member passes parenthesize one)
        for _ in range(3):
            body = re.sub(r"&\s*\(\s*(" + alt + r")\s*\)", r"&\1", body)
        body = re.sub(r"&\s*(" + alt + r")(?![\w$\[])", lambda m: repl[m.group(1)], body)
    body = re.sub(r"(?<![\w$])(" + "|".join(map(re.escape, repl)) + r")(?![\w$])", lambda m: repl[m.group(1)], body)
    return body.replace("{", "{\n  __declspec(align(16)) undefined1 gen_frame[0x%x];" % size, 1)


RESULT_REG = re.compile(r"\b(?:in|extraout)_E[AD]X(?:_\d+)?\b")


def returned_only(c: str) -> set[str]:
    """The result registers the decompiler lost that the function only returns: `in_EAX` (eax
    as the function found it) and `extraout_EAX` (what a void callee left in it), read nowhere but
    in a return, or into another such one. A function protos32.py typed by its callers' reads
    returns them on the paths that set nothing (FUN_00406ad0, a free wrapper: `if (p == 0)
    return in_EAX`), and what is there is nothing the caller relies on: 0."""
    # (eax, ecx or edx as the function found them, wherever read: never an argument, which
    # protos32.py gives a parameter of its own, `in_eax`, but what a path that sets nothing returns,
    # the decompiler's name for a scratch register it merged with that, or the garbage a `push
    # ecx` reserving a local starts it with, `local_5 = (undefined1)((uint)in_ECX >> 0x18)`: 0)
    entry = set(re.findall(r"\bin_E[ACD]X(?:_\d+)?\b", c))
    # (and the upper bytes of eax a byte or word result came with, `CONCAT31(extraout_var, bVar3)`:
    # its callers read al, a bool's, and what the callee left above it is nothing they use)
    entry |= set(re.findall(r"\bextraout_var(?:_\d+)?\b", c))
    names = set(RESULT_REG.findall(c)) | entry
    if not names:
        return set()
    lines = c.split("\n")
    ok = set(names)
    changed = True
    while changed:
        changed = False
        for n in list(ok):
            for line in lines:
                if not re.search(r"\b" + n + r"\b", line):
                    continue
                s = line.strip()
                if re.fullmatch(r"(?:undefined\d?|uint|int|ulonglong|longlong|u?int\d*)\s+" + n + r";", s):
                    continue                                    # its declaration
                if re.match(r"return\b", s):
                    continue
                m = re.fullmatch(r"(\w+)\s*=\s*(.+);", s)
                if m and m.group(1) == n:
                    continue                                    # written
                if m and m.group(1) in ok and re.fullmatch(r"(?:CONCAT44\()?[\w ,]+\)?", m.group(2)):
                    continue                                    # copied into another one
                ok.discard(n)
                changed = True
                break
    return ok | entry


def load_corpus() -> dict[int, dict]:
    out = {}
    with open(CORPUS, encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            # (Ghidra writes Windows newlines; every pattern here reads \n. One it could not
            # decompile has an "error" and no C: no signature, so a stub)
            r["c"] = r.get("c", "").replace("\r\n", "\n").replace("\r", "\n")
            out[int(r["addr"], 16)] = r
    return out


def load_refdata() -> tuple[dict[int, tuple[int, str]], dict[str, int]]:
    by_addr, by_name = {}, {}
    with open(REFDATA, encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            a = int(r["addr"], 16)
            by_addr[a] = (int(r["len"]), r["type"])
            if r["name"]:
                by_name[r["name"]] = a
    return by_addr, by_name


def strip_comments(c: str) -> str:
    # (strings first, so a `/*` inside one is not a comment's start)
    return re.sub(r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|/\*.*?\*/',
                  lambda m: m.group(0) if m.group(0)[0] in "\"'" else "", c, flags=re.S)


def split_decls(body: str) -> tuple[str, str]:
    """A body's declarations (Ghidra writes them first, then a blank line) and the rest."""
    k = re.search(r"\n[ \t]*\n", body)
    return (body[:k.end()], body[k.end():]) if k else ("", body)


def balanced(body: str) -> bool:
    """Braces paired, outside string and character literals."""
    depth = 0
    for m in re.finditer(r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|[{}]', body):
        t = m.group(0)
        if t == "{":
            depth += 1
        elif t == "}":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


def split_top(s: str, sep: str = ",") -> list[str]:
    """s split at the separators outside parentheses and brackets."""
    out, depth, cur = [], 0, []
    for ch in s:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == sep and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur))
    return out


def operand_end(s: str, i: int) -> int:
    """The end of the unary expression that starts at s[i] (what a cast applies to): prefix
    operators and casts, then a parenthesized expression, a name or a literal, then subscripts,
    calls and members."""
    n = len(s)
    # (an operand may start on the next line: Ghidra wraps a long assignment after its cast)
    while i < n and s[i] in " \t\n":
        i += 1
    while i < n and s[i] in "*&-!~":
        i += 1
        while i < n and s[i] in " \t\n":
            i += 1
    if i < n and s[i] == "(":
        j = match_paren(s, i)
        if j < 0:
            return n
        inner = s[i + 1:j - 1].strip()
        # a cast: its operand follows
        if re.fullmatch(r"[A-Za-z_][\w ]*(?:\*[\s*]*|PTR32[\s*]*)*", inner) and j < n and s[j] not in ";,)]}":
            nxt = s[j:].lstrip()
            if nxt and (nxt[0].isalnum() or nxt[0] in "_(*&-!~"):
                return operand_end(s, j)
        i = j
    else:
        m = re.match(r"[\w.$]+", s[i:])
        if not m:
            return i
        i += m.end()
        if i < n and s[i] in "'\"":
            m2 = re.match(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', s[i:])
            if m2:
                i += m2.end()
    while i < n:
        # (Ghidra wraps a long call's arguments onto the next line)
        k = i
        while k < n and s[k] in " \t\n":
            k += 1
        if k < n and s[k] in "([" and k > i:
            i = k
        if s[i] == "[":
            depth = 0
            for k in range(i, n):
                depth += s[k] == "["
                depth -= s[k] == "]"
                if depth == 0:
                    i = k + 1
                    break
            else:
                return n
        elif s[i] == "(":
            j = match_paren(s, i)
            if j < 0:
                return n
            i = j
        elif s.startswith("->", i) or (s[i] == "." and i + 1 < n and (s[i + 1].isalpha() or s[i + 1] == "_")):
            i += 2 if s[i] == "-" else 1
            m = re.match(r"\w+", s[i:])
            i += m.end() if m else 0
        else:
            break
    return i


def unary_deref(body: str, name: str) -> bool:
    """Whether `*name` appears as a dereference, not a multiplication (`a * name`)."""
    for m in re.finditer(r"\*\s*" + re.escape(name) + r"\b", body):
        k = m.start() - 1
        while k >= 0 and body[k] in " \t":
            k -= 1
        if k < 0 or not (body[k].isalnum() or body[k] in "_)]"):
            return True
    return False


def is_type(t: str) -> bool:
    """Whether a parenthesized text is a type (a cast), not an expression: `(int *)`, not
    `(fVar2 * fVar3)`."""
    words = re.findall(r"[A-Za-z_]\w*", t)
    return bool(words) and all(w in KNOWN_TYPES or w in ("PTR32", "unsigned", "signed", "const") for w in words)


FLOATISH = re.compile(r"\b\d+\.\d*(?:[eE][-+]?\d+)?f?\b|\(float(?:10)?\)|\(double\)|REFG\((?:float|double), |\b[fd]Var\d+\b")


def match_paren(s: str, i: int) -> int:
    """The index just past the parenthesis group that opens at s[i]."""
    depth = 0
    for j in range(i, len(s)):
        if s[j] == "(":
            depth += 1
        elif s[j] == ")":
            depth -= 1
            if depth == 0:
                return j + 1
    return -1


def split_params(p: str) -> list[str]:
    """A parameter list at its top-level commas, a template's angle brackets nesting too
    (`basic_string<char,std::char_traits<char>,std::allocator<char>_> *this`: one parameter)."""
    out, depth, start = [], 0, 0
    for i, ch in enumerate(p):
        if ch in "(<[":
            depth += 1
        elif ch in ")>]":
            depth -= 1
        elif ch == "," and depth == 0:
            out.append(p[start:i])
            start = i + 1
    out.append(p[start:])
    return out


class Signature:
    """A function's Ghidra signature: return type, printed name, parameters (type, name)."""
    # (the name is the last word before the parameters, whatever it is made of: C++ operators
    # print as `operator+_00c76239`, templates with commas and brackets)
    SIG = re.compile(r"^(?P<ret>.*?)(?P<name>[^\s(*]+)\s*\((?P<params>.*)\)\s*$", re.S)

    def __init__(self, text: str, name: str | None = None):
        head = strip_comments(text).split("{", 1)[0]
        head = CC.sub("", " ".join(head.split()))
        # (a long name wrapped after a `::` and before its parameters, `std::\n_Cons_val<...>_005c3320
        # \n(...)`: one name again, so the corpus's finds it)
        head = re.sub(r"::\s+", "::", head)
        if name:
            head = head.replace(name + " (", name + "(")
        # (the corpus's own name, where the head has it: a template's name has spaces and commas
        # in it, `void std::basic_string<char, ...>::assign(...)`, that no pattern takes whole)
        at = head.find(name + "(") if name else -1
        if at > 0:
            self.ret, self.name, p = head[:at].strip() or "void", name, head[at + len(name) + 1:].rstrip()
            if not p.endswith(")"):
                raise ValueError(f"no signature in {head[:80]!r}")
            p = p[:-1].strip()
        else:
            m = self.SIG.match(head)
            if not m:
                raise ValueError(f"no signature in {head[:80]!r}")
            self.ret, self.name, p = m.group("ret").strip() or "void", m.group("name"), m.group("params").strip()
        self.params: list[tuple[str, str]] = []
        self.variadic = False
        if p and p != "void":
            for part in split_params(p):
                part = part.strip()
                if part == "...":
                    self.variadic = True
                    continue
                # a function pointer: `int (*_PtFuncCompare)(void *,void *)`
                fm = re.match(r"^.*\(\s*\*\s*([A-Za-z_]\w*)\s*\)\s*\(.*\)$", part)
                if fm:
                    self.params.append(("code *", fm.group(1)))
                    continue
                # a pointer to an SSE register's 16 bytes, `undefined1 (*param_1) [16]`
                # (__VEC_memzero's blocks): a gen_v16 *, as v16_forms writes the body's
                am = re.match(r"^undefined1\s*\(\s*\*\s*([A-Za-z_]\w*)\s*\)\s*\[\s*(" + V_SIZES + r")\s*\]$", part)
                if am:
                    self.params.append((f"gen_v{am.group(2)} *", am.group(1)))
                    continue
                pm = re.match(r"^(.*?)([A-Za-z_]\w*)\s*$", part)
                if not pm:
                    raise ValueError(f"parameter {part!r}")
                self.params.append((pm.group(1).strip(), pm.group(2)))


def ptr32_type(t: str) -> str:
    """A type with its inner pointer levels __ptr32: `int **` -> `int * PTR32 *`. A pointer to
    void is a pointer to bytes: Ghidra does byte arithmetic on one (`this + 8`), which C refuses."""
    t = " ".join(t.replace("*", " * ").split())
    stars = t.count("*")
    base = t.replace("*", "").strip()
    if stars and base in ("void", "const void"):
        base = base.replace("void", "undefined")
    if stars == 0:
        return base
    return base + " * PTR32" * (stars - 1) + " *"


def abi_type(t: str) -> str:
    """How a parameter of type t crosses a call: 32 bits unless a float or an 8-byte integer."""
    b = t.replace("*", "").strip()
    if "*" in t:
        return "unsigned int"
    if b in STRUCT8:
        return "unsigned long long"
    if b in FLOATS:
        return "double" if b in ("double", "float8", "float10") else "float"
    if b in WIDE:
        return "unsigned long long"
    return "unsigned int"


class Translator32:
    def __init__(self):
        t0 = time.time()
        self.corpus = load_corpus()
        self.refdata, self.ref_names = load_refdata()
        self.sigs: dict[int, Signature] = {}
        self.by_printed: dict[str, int] = {}
        bad = 0
        for a, r in self.corpus.items():
            try:
                s = Signature(r["c"], r["name"])
            except ValueError:
                bad += 1
                continue
            self.sigs[a] = s
            self.by_printed.setdefault(s.name, a)
        self.thunks = self.local_thunks()
        for name, (_at, target) in self.thunks.items():
            self.by_printed.setdefault(name, target)
        self.imports = self.load_imports()
        # names a plain identifier scan cannot take whole (templates, backquoted scopes, spaces):
        # looked up by a backward scan from where they end, at these lengths
        odd = re.compile(r"[^\w:~$@]")
        self.odd_functions = {n for n in self.by_printed if odd.search(n)}
        self.odd_data = {n for n in self.ref_names if odd.search(n)}
        self.odd_lengths = sorted({len(n) for n in self.odd_functions | self.odd_data}, reverse=True)
        # by each name's first word, so a body's own words pick the few that can be in it
        self.odd_by_word: dict[str, list[str]] = defaultdict(list)
        for n in self.odd_functions | self.odd_data:
            w = re.search(r"[\w~]+", n)
            if w:
                self.odd_by_word[w.group(0)].append(n)
        self.tls_index = self.ref_names.get("_tls_index") or self.tls_index_slot()
        # the globals the code loads and stores as floats (floatdata.py: x87 and SSE operand widths)
        import floatdata
        self.floats = floatdata.load()
        # the program's structures and typedefs (ghidra/ExportTypes.java -> build/types.json)
        tpath = ROOT / "build/types.json"
        types = json.loads(tpath.read_text(encoding="utf-8")) if tpath.exists() else {}
        self.composites = {n: v for n, v in types.get("composites", {}).items() if v["fields"]}
        self.typedefs = types.get("typedefs", {})
        print(f"corpus {len(self.corpus)} functions ({bad} without a signature), refdata {len(self.refdata)}, "
              f"imports {len(self.imports)} ({time.time() - t0:.0f}s)")

    def tls_index_slot(self) -> int | None:
        """The image's TLS index slot (the TLS directory's AddressOfIndex)."""
        import pefile
        pe = pefile.PE(str(project.EXE), fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"]])
        tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
        slot = tls.struct.AddressOfIndex if tls else None
        pe.close()
        return slot

    # ---- imports --------------------------------------------------------------------------------
    def load_imports(self) -> dict[str, tuple[int, str]]:
        """Import name -> (IAT slot VA, dll)."""
        import pefile
        pe = pefile.PE(str(project.EXE), fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        out = {}
        for dll in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            for imp in dll.imports:
                if imp.name:
                    out[imp.name.decode()] = (imp.address, dll.dll.decode())
        pe.close()
        return out

    def local_thunks(self) -> dict[str, tuple[int, int]]:
        """name -> (thunk, target) for each `jmp rel32` thunk Ghidra made a function of in the
        image's own code (functions.json "thunk", not an import's): the corpus leaves thunks out,
        so a call by its name is the target's, and the runtime's jump at it goes to the target's
        translation (`thunk_FUN_00403020`, which the /MD CRT's pre_c_initialization calls,
        2026-10-24)."""
        path = FACTS / "functions.json"
        if not path.exists():
            return {}
        import pefile
        pe = pefile.PE(str(project.EXE), fast_load=True)
        base = pe.OPTIONAL_HEADER.ImageBase
        out = {}
        for f in json.loads(path.read_text())["functions"]:
            if not f.get("thunk") or "::" in f["name"]:
                continue
            at = int(f["entry"], 16)
            target = at
            for _ in range(4):                       # (through thunks of thunks)
                code = pe.get_data(target - base, 5)
                if len(code) < 5 or code[0] != 0xE9:
                    break
                target = (target + 5 + int.from_bytes(code[1:5], "little", signed=True)) & 0xFFFFFFFF
            if target != at and target in self.corpus:
                out[f["name"]] = (at, target)
        pe.close()
        return out

    def import_of(self, name: str) -> str | None:
        """The import a name in the body calls: its own, or the one Ghidra printed without its
        C underscore (ucrt's `_initterm_e` as `initterm_e`, `_crt_atexit` as `crt_atexit`)."""
        if name in self.imports:
            return name
        return "_" + name if "_" + name in self.imports else None

    # ---- one function ---------------------------------------------------------------------------
    def why_not(self, a: int) -> str | None:
        c = v16_forms(cpu_state(strip_comments(self.corpus[a]["c"])))
        if a not in self.sigs:
            return "no signature"
        # (and a full xmm register as an SSE pseudo-op's destination found it: zeroed, sse_ops)
        ok = returned_only(c) | {"in_FPUControlWord"} | \
            set(re.findall(r"(?m)^[ \t]+undefined1\s+(in_XMM\d+)\s*\[\s*16\s*\]\s*;", c))
        m = next((m for m in LOST.finditer(c) if m.group(1) not in ok and not OUT_STACK.fullmatch(m.group(1))), None)
        if m:
            return f"a register the decompiler lost ({m.group(1)})"
        if "halt_baddata" in c or "halt_unimplemented" in c:
            return "bad instruction data"
        # (an address in its own arguments is its argument block, rewrite; a read there is not)
        if re.search(r"stack0x(?!f[0-9a-f]{7}\b)", re.sub(r"&\s*stack0x[0-9a-f]+", "", c)):
            return "the caller's stack (stack0x)"
        if re.search(r"\bcase\s+-?\d+\.\d", c):
            return "a switch on a floating point value"
        # an SSE register as a 16-byte array (`(undefined1 [16])x`, `*(undefined1 (*) [16])p`)
        if re.search(r"\(\s*undefined\d*\s*\[\s*(?:0x)?[0-9a-f]+\s*\]\s*\)|\(\*\)\s*\[", c):
            return "a cast to an array (an SSE register)"
        return None

    def known_type(self, word: str) -> bool:
        return word in KNOWN_TYPES

    # ---- member access, by the exported layouts -------------------------------------------------
    def struct_of(self, t: str) -> str | None:
        """The composite a type names, through typedefs (`pthreadlocinfo` -> `threadlocinfostruct *`
        is a pointer, not a composite: None)."""
        t = re.sub(r"^(?:struct|union|const)\s+", "", t.strip())
        for _ in range(8):
            if t in self.composites:
                return t
            if t in self.typedefs:
                t = self.typedefs[t].strip()
                continue
            return None
        return None

    def tinfo(self, t: str, length: int) -> tuple:
        """A field's type: ("scalar", C type) / ("ptr", pointee composite or None, C type of the
        stored pointer) / ("array", element tinfo, count, element size) / ("struct", name)."""
        t = re.sub(r"^(?:struct|union|const)\s+", "", t.strip())
        # (a function pointer: `void (*)(void)`, `_func_void *`, `_PVFV`: called through)
        if "(" in t or re.match(r"_func_|code\s*\*$", t) or t in ("_PVFV", "PVFV", "_PIFV", "PIFV"):
            return ("ptr", None, "code * PTR32")
        m = re.fullmatch(r"(.+?)\s*\[(\d+)\]", t)
        if m:
            n = int(m.group(2))
            esize = length // n if n else length
            return ("array", self.tinfo(m.group(1), esize), n, esize)
        if t.endswith("*"):
            base = t[:-1].strip()
            s = self.struct_of(base)
            scalar = alias_types(base).strip()
            ct = f"{scalar} * PTR32" if (scalar in KNOWN_TYPES and "*" not in scalar and not s) else "undefined * PTR32"
            return ("ptr", s, ct)
        s = self.struct_of(t)
        if s:
            return ("struct", s)
        for _ in range(8):
            # (a Windows type Ghidra32.h has as a plain pointer, followed only to an exported
            # composite: `HMODULE` -> `HINSTANCE__ *`, the CRT's PE header checks through it)
            if t in self.typedefs and (t not in KNOWN_TYPES or
                                       self.struct_of(re.sub(r"\s*\*$", "", self.typedefs[t].strip()))):
                nxt = self.typedefs[t].strip()
                if nxt.endswith("*") or re.search(r"\[\d+\]$", nxt):
                    return self.tinfo(nxt, length)
                t = nxt
            else:
                break
        ct = alias_types(t).strip()
        if ct in KNOWN_TYPES and "*" not in ct and ct not in STRUCT_TYPES:
            return ("scalar", ct)
        return ("scalar", {1: "undefined1", 2: "undefined2", 4: "undefined4", 8: "undefined8"}.get(length, "undefined4"))

    def struct_vars(self, body: str, a: int) -> dict[str, tuple[str, str]]:
        """name -> (composite, "val" / "ptr" / "array") for the locals and parameters declared with
        an exported composite (not the ones Ghidra32.h lays out itself: STRUCT_TYPES)."""
        out = {}
        for m in re.finditer(r"(?m)^\s+(?:struct\s+)?([A-Za-z_]\w*)\s*(\*?)\s*([A-Za-z_]\w*)\s*(\[[^\]]*\])?\s*;",
                             split_decls(body)[0]):
            s = self.struct_of(m.group(1))
            if s and m.group(1) not in STRUCT_TYPES:
                out[m.group(3)] = (s, "ptr" if m.group(2) else "array" if m.group(4) else "val")
        for t, n in self.sigs[a].params:
            base = t.replace("*", "").strip()
            s = self.struct_of(base)
            if s and base not in STRUCT_TYPES and t.count("*") == 1:
                out[n] = (s, "ptr")
            elif not s and t.count("*") == 0:
                # (a typedef to a pointer: `pthreadlocinfo ptloci`)
                info = self.tinfo(t, 4)
                if info[0] == "ptr" and info[1]:
                    out[n] = (info[1], "ptr")
        for m in re.finditer(r"(?m)^\s+([A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s*;", split_decls(body)[0]):
            if m.group(2) not in out and not self.struct_of(m.group(1)):
                info = self.tinfo(m.group(1), 4)
                if info[0] == "ptr" and info[1]:
                    out[m.group(2)] = (info[1], "ptr")
        return out

    def members(self, body: str, a: int) -> str:
        """`ptd->_thandle`, `local_6c.dwFlags`, `p->arr[2].x`, `((_tiddata *)p)->_terrno`: reads and
        writes at the field's offset, typed by the field (a stored pointer 4 bytes). A local
        declared with an exported composite becomes bytes of its size. What it cannot place
        (an unexported type, a call's result) is left for leftover_members to refuse."""
        if not self.composites or not re.search(r"->|\.[A-Za-z_]", body):
            return body
        svars = self.struct_vars(body, a)
        out, i = [], 0
        for m in re.finditer(r"(->|\.)\s*([A-Za-z_]\w*)", body):
            if m.start() < i:
                continue
            if m.group(1) == "." and re.search(r"(?<![\w$])\d+$", body[:m.start()]):
                continue                                   # (a float literal: digits alone, not
                                                           # `local_14.locinfo`, a name ending in one)
            start = self.base_start(body, m.start())
            if start is None:
                continue
            base = body[start:m.start()].strip()
            got = self.base_type(base, svars)
            if got is None:
                continue
            addr, cur = got
            j = m.start()
            ok = True
            # the chain: -> and . fields, and subscripts of array fields
            while True:
                mm = re.match(r"\s*(->|\.)\s*([A-Za-z_]\w*)", body[j:])
                if mm and not (mm.group(1) == "." and cur[0] != "struct") \
                        and not (mm.group(1) == "->" and cur[0] not in ("ptr", "ptrval")):
                    if mm.group(1) == "->" and cur[0] == "ptr":
                        # (a pointer stored in a field: load it, 4 bytes, and go there)
                        if cur[1] is None:
                            ok = False
                            break
                        addr = f"(char *)(*({cur[2]} *)({addr}))"
                    sname = cur[1]
                    f = next((x for x in self.composites[sname]["fields"] if x[0] == mm.group(2)), None)
                    if f is None:
                        ok = False
                        break
                    addr = f"({addr} + {f[1]})" if f[1] else addr
                    cur = self.tinfo(f[3], f[2])
                    j += mm.end()
                    continue
                sm = re.match(r"\s*\[", body[j:])
                if sm and cur[0] == "ptr" and cur[1] and cur[1] in self.composites:
                    # (a pointer field indexed, `local_14.locinfo[1].lc_category`: the struct that
                    # many past where it points, as C steps a pointer)
                    k = j + sm.end() - 1
                    depth = 0
                    for q in range(k, len(body)):
                        depth += body[q] == "["
                        depth -= body[q] == "]"
                        if depth == 0:
                            break
                    idx = body[k + 1:q]
                    size = self.composites[cur[1]]["size"]
                    addr = f"((char *)(*({cur[2]} *)({addr})) + ({idx}) * {size})"
                    cur = ("struct", cur[1])
                    j = q + 1
                    continue
                if sm and cur[0] == "array":
                    k = j + sm.end() - 1
                    depth = 0
                    for q in range(k, len(body)):
                        depth += body[q] == "["
                        depth -= body[q] == "]"
                        if depth == 0:
                            break
                    idx = body[k + 1:q]
                    addr = f"({addr} + ({idx}) * {cur[3]})"
                    cur = cur[1]
                    j = q + 1
                    continue
                break
            if not ok or j == m.start():
                continue
            out.append(body[i:start])
            out.append(self.lvalue(addr, cur))
            i = j
        out.append(body[i:])
        body = "".join(out)
        # the composite locals as bytes of their size
        def decl(mm):
            n = mm.group(3)
            if n in svars and svars[n][1] in ("val", "array"):
                size = self.composites[svars[n][0]]["size"]
                count = mm.group(4)
                # (one of 1, 2, 4 or 8 bytes is an integer of that size: assigned whole from a
                # call's result, as edx:eax returned it)
                if not count and size in (1, 2, 4, 8):
                    return f"{mm.group(1)}undefined{size} {n};"
                total = f"{size} * ({count[1:-1]})" if count else str(size)
                return f"{mm.group(1)}undefined {n}[{total}];"
            return mm.group(0)
        decls, rest = split_decls(body)
        decls = re.sub(r"(?m)^(\s+)(?:struct\s+)?([A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s*(\[[^\]]*\])?\s*;", decl, decls)
        return decls + rest

    def lvalue(self, addr: str, cur: tuple) -> str:
        """The C for a member at addr: a scalar or stored pointer as the lvalue of its type, an
        array as its first element's address (as an array would decay), a structure as an array
        of its bytes (so `&p->sub` and passing it along keep the address)."""
        if cur[0] == "scalar":
            return f"(*({cur[1]} *)({addr}))"
        if cur[0] == "ptr":
            return f"(*({cur[2]} *)({addr}))"
        if cur[0] == "array":
            el = cur[1]
            et = el[1] if el[0] == "scalar" else el[2] if el[0] == "ptr" else "undefined"
            return f"(({et} *)({addr}))"
        if cur[0] == "ptrval":
            return f"((undefined *)({addr}))"
        return f"(*(undefined (*)[{self.composites[cur[1]]['size']}])({addr}))"

    def base_type(self, base: str, svars: dict) -> tuple[str, tuple] | None:
        """The address (as a char * expression) and type of a member access's base."""
        m = re.fullmatch(r"([A-Za-z_]\w*)", base)
        if m and m.group(1) in svars:
            s, kind = svars[m.group(1)]
            if kind == "ptr":
                # (a pointer in a local: its value is the struct's address)
                return f"(char *)({base})", ("ptrval", s)
            return f"(char *)&({base})", ("struct", s)
        m = re.fullmatch(r"([A-Za-z_]\w*)\s*\[(.*)\]", base, re.S)
        if m and m.group(1) in svars:
            s, kind = svars[m.group(1)]
            size = self.composites[s]["size"]
            if kind == "ptr":
                return f"((char *)({m.group(1)}) + ({m.group(2)}) * {size})", ("struct", s)
            return f"((char *)({m.group(1)}) + ({m.group(2)}) * {size})", ("struct", s)
        m = re.fullmatch(r"\(\s*\*\s*([A-Za-z_]\w*)\s*\)", base)
        if m and m.group(1) in svars and svars[m.group(1)][1] == "ptr":
            return f"(char *)({m.group(1)})", ("struct", svars[m.group(1)][0])
        m = re.fullmatch(r"\(\s*\(\s*(?:struct\s+)?([A-Za-z_]\w*)\s*\*\s*\)\s*(.+)\)", base, re.S)
        if m and self.struct_of(m.group(1)):
            return f"(char *)({m.group(2)})", ("ptrval", self.struct_of(m.group(1)))
        m = re.fullmatch(r"_*(?:DAT|PTR)_[0-9a-f]{0,}?([0-9a-f]{8})", base)
        if m:
            n, t = self.refdata.get(int(m.group(1), 16), (0, ""))
            s = self.struct_of(t)
            if s:
                return f"(char *)REFP(0x{int(m.group(1), 16):x})", ("struct", s)
        return None

    @staticmethod
    def base_start(body: str, p: int) -> int | None:
        """Where the base of the member access at body[p] starts: a name, subscripts, a
        parenthesized expression."""
        j = p - 1
        while j >= 0 and body[j] in " \t":
            j -= 1
        if j < 0:
            return None
        while True:
            if body[j] in ")]":
                close, open_ = body[j], "(" if body[j] == ")" else "["
                depth = 0
                k = j
                while k >= 0:
                    depth += body[k] == close
                    depth -= body[k] == open_
                    if depth == 0:
                        break
                    k -= 1
                if k < 0:
                    return None
                if close == "]":
                    j = k - 1
                    continue
                # a call's result is no base this can type
                q = k - 1
                while q >= 0 and body[q] in " \t":
                    q -= 1
                if q >= 0 and (body[q].isalnum() or body[q] == "_"):
                    return None
                return k
            if body[j].isalnum() or body[j] == "_":
                k = j
                while k >= 0 and (body[k].isalnum() or body[k] == "_"):
                    k -= 1
                return k + 1
            return None

    def paren_pieces(self, body: str) -> str:
        out, i = [], 0
        for m in re.finditer(r"\)\s*\._(\d+)_(\d+)_", body):
            if m.start() < i:
                continue
            start = self.base_start(body, m.start() + 1)
            if start is None or start < i:
                continue
            base = body[start:m.start() + 1]
            n = m.group(2)
            rep = (f"(*(undefined{n} *)((char *)&{base} + {m.group(1)}))" if n in ("1", "2", "4", "8")
                   else f"GEN_PIECE(&{base}, {m.group(1)}, {n})")
            out.append(body[i:start])
            out.append(rep)
            i = m.end()
        out.append(body[i:])
        return "".join(out)

    def leftover_members(self, body: str, a: int) -> None:
        """A member access members() could not place, other than through the structures
        Ghidra32.h lays out itself (on a local declared with one): the function's stub."""
        decls = split_decls(body.partition("{")[2])[0]
        structs = {m.group(2) for m in re.finditer(r"(?m)^\s+(\w+)\s+(\w+)\s*(?:\[[^\]]*\])?\s*;", decls)
                   if m.group(1) in STRUCT_TYPES}
        spointers = {m.group(3) for m in re.finditer(r"(?m)^\s+(\w+)\s*(\*?)\s*(\w+)\s*;", decls)
                     if (m.group(1) in STRUCT_POINTERS and not m.group(2)) or (m.group(1) in STRUCT_TYPES and m.group(2))}
        spointers |= {n for t, n in self.sigs[a].params
                      if t.strip() in STRUCT_POINTERS or t.replace("*", "").strip() in STRUCT_TYPES}
        rest = re.sub(r'L?"(?:\\.|[^"\\])*"', '""', body)
        if structs:
            rest = re.sub(r"\b(?:" + "|".join(map(re.escape, structs)) + r")\s*(?:\[[^\]]*\])?(?:\.[A-Za-z_]\w*)+", "", rest)
        if spointers:
            rest = re.sub(r"\b(?:" + "|".join(map(re.escape, spointers)) + r")\s*->\s*[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", "", rest)
        m = re.search(r"[\w\)\]]\s*->\s*\w|(?<![\d.])\b[A-Za-z_]\w*\s*\.[A-Za-z_]|[\)\]]\s*\.[A-Za-z_]", rest)
        if m:
            raise ValueError(f"member access through a type C does not have ({m.group(0)[:30]})")

    def rewrite(self, a: int) -> str:
        """The function's C, translated (raises ValueError when it cannot be)."""
        sig = self.sigs[a]
        c = v16_forms(cpu_state(strip_comments(self.corpus[a]["c"])))
        # (a long C++ name Ghidra wraps at a `::`, `IpcChannel::\n        PacketBufferTmpl<...>::\n
        # vftable`: one name again, as the data export has it. 1,090 stubs, 2026-10-23)
        c = re.sub(r"::[ \t]*\n[ \t]*", "::", c)
        c = re.sub(r"(?<=[\w>])[ \t]*\n[ \t]*::", "::", c)
        head, sep, body = c.partition("{")
        body = out_stack("{" + body)
        # (the x87 control word an `fnstcw` stores, which Ghidra reads as an input and never writes:
        # MSVC's default, 53-bit precision and every exception masked; the conversions it is set
        # for (`| 0xc00`, truncation) are C's own here)
        body = re.sub(r"(?m)^\s*[A-Za-z_]\w*\s+in_FPUControlWord\s*;\s*\n", "", body)
        body = re.sub(r"\bin_FPUControlWord\b", "((undefined2)0x27f)", body)
        # a jump table's address (switchD_00403f1a::switchdataD_00403f30), and the labels Ghidra
        # qualifies (switchD_00403f1a::caseD_5)
        body = re.sub(r"\bswitchD_[0-9a-f]+::switchdataD_([0-9a-f]{8})\b",
                      lambda m: self.global_lvalue(int(m.group(1), 16)), body)
        body = re.sub(r"\b(switchD_[0-9a-f]+)::(\w+)", r"\1__\2", body)
        # the image's DOS header by field, and a field of an unnamed global (`UNK_00400080.
        # field_0x68`: the byte there); Ghidra compares e_magic, a char[2] to it, as `(char [2])`
        def dos(m):
            base, field = int(m.group(1), 16), m.group(2)
            off, t = DOS_HEADER.get(field, (None, None))
            if off is None:
                raise ValueError(f"DOS header field {field}")
            return f"((undefined *)REFP(0x{base + off:x}))" if t is None else f"REFG({t}, 0x{base + off:x})"
        body = re.sub(r"\bIMAGE_DOS_HEADER_([0-9a-f]{8})\.(\w+)", dos, body)
        body = re.sub(r"\((?:unsigned\s+)?char\s*\[2\]\)", "(ushort)", body)
        # (an 8-byte structure by value is its 64-bit integer: STRUCT8)
        body = re.sub(r"\((" + "|".join(STRUCT8) + r")\)", lambda m: f"({STRUCT8[m.group(1)]})", body)
        body = re.sub(r"(&?)\b(?:UNK|DAT)_([0-9a-f]{8})\.field_0x([0-9a-f]+)",
                      lambda m: (f"((undefined *)REFP(0x{int(m.group(2), 16) + int(m.group(3), 16):x}))" if m.group(1)
                                 else f"REFG(undefined, 0x{int(m.group(2), 16) + int(m.group(3), 16):x})"), body)
        # Ghidra's pseudo-ops and piece access (`local_7c[0]._0_2_`: 2 bytes at offset 0)
        body = re.sub(r"\bNAN\s*\(", "GEN_ISNAN(", body)
        # (a 4-byte piece of an SSE register's 16 bytes, a local or a lost xmm register Ghidra has as
        # `undefined1 [16]` or a 16-byte constant, is a float lane: `auVar27._4_4_ *
        # DAT_01138af0._4_4_` is a float multiply, and as undefined4 C multiplied the bits)
        lanes = set(re.findall(r"(?m)^[ \t]+undefined1\s+([A-Za-z_]\w*)\s*\[\s*16\s*\]\s*;", body))
        for full, at in set(re.findall(r"\b(_*(?:DAT|UNK)_([0-9a-f]{8}))\._\d+_4_", body)):
            if self.refdata.get(int(at, 16), (0, ""))[0] == 16:
                lanes.add(full)
        # (but a register an integer op reads or writes has integer lanes: /O2's vectorized
        # `s += k * k` builds its operands lane by lane from ints for pmulld, and as floats they
        # were converted, rhtest's sum_to, 2026-10-24)
        for args in re.findall(r"\bgen_(?:" + "|".join(SSE_INT_OPS) + r")\(([^;]*)\);", body):
            lanes -= set(re.findall(r"&\(\s*([A-Za-z_]\w*)\s*\)", args))

        def piece(m):
            name, off, size = m.group(1), m.group(2), m.group(3)
            if size not in ("1", "2", "4", "8"):
                return f"GEN_PIECE(&{name}, {off}, {size})"
            t = "float" if size == "4" and name in lanes else f"undefined{size}"
            return f"(*({t} *)((char *)&{name} + {off}))"
        body = re.sub(r"\b([A-Za-z_]\w*(?:\[[^\]\[]*\])?)\._(\d+)_(\d+)_", piece, body)
        # (a float lane in a bit mask, `~-(uint)(fVar15 < fVar11) & auVar2._4_4_`: Ghidra's SSE
        # compare-and-select, its float and its bits in one expression C cannot have)
        for line in body.split("\n"):
            if "(*(float *)((char *)&" in line:
                rest = re.sub(r"\(\*\(float \*\)\(\(char \*\)&[\w\[\]]+ \+ \d+\)\)", "LANE", line)
                if "LANE" in rest and re.search(r"(?<![&|])[&|^~](?![&|=])", re.sub(r"\(\w[\w ]*\*\)&|&\w", "", rest)):
                    raise ValueError("an SSE lane in a bit mask")
        # (and a piece of a parenthesized expression: `(*ptd)._0_4_`)
        body = self.paren_pieces(body)
        # a member chain Ghidra parenthesizes before going on: `(_Ptd->_setloc_data)._cachein`
        for _ in range(4):
            body = re.sub(r"\(\s*([A-Za-z_]\w*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)+)\s*\)(?=\s*(?:->|\.[A-Za-z_]))", r"\1", body)
        # (a virtual call's object: Ghidra's own now, from protos32.py's call-site signatures, which
        # give it ecx. virtual_this guessed it from the text, and missed every call whose vtable
        # was loaded into a local first)
        # member access by the exported layouts (before the types, which forget the struct names)
        body = self.members(body, a)
        self.leftover_members(body, a)
        # (types before names: a C++ type in a cast, `(Client::UI::Foo *)`, is no symbol)
        body = self.types(body)
        body = self.names(body)
        body = CC.sub("", body)
        body = re.sub(r"\(uint\)&stack0x[0-9a-f]+", "0u", body)
        body = RAM.sub(lambda m: f"REFG({RAM_TYPES.get(m.group(1), 'undefined4')}, 0x{m.group(2)})", body)
        body = re.sub(r"\b(\w+)_exref\b",
                      lambda m: f"((code *)gen_imp_{self.import_of(m.group(1))})" if self.import_of(m.group(1))
                      else m.group(0), body)
        # an undefinedN value in a signed comparison as the signed type of its width (Ghidra32.h's
        # are unsigned: insertion_sort's `-1 < local_8` was never true at /Od, rhtest 2026-10-24)
        body = signed_tests(body, [f"{t} {n}" for t, n in sig.params])
        # a label is followed by a statement, even where it ends a block
        body = re.sub(r"(?m)^(\s*[A-Za-z_]\w*\s*:)(\s*)$", r"\1 ;\2", body)
        body = re.sub(r"(?m)^(\s*[A-Za-z_]\w*\s*:)(\s*\})", r"\1 ;\2", body)
        body = re.sub(r"(?m)^(\s*case [^:\n]+:)(\s*)$", r"\1 ;\2", body)
        body = self.switch_values(body)
        # the parameters: 32 bits across the call, Ghidra's types inside
        params, prologue = [], []
        var_types: dict[str, str] = {}
        for k, (t, n) in enumerate(sig.params):
            tt = self.type_text(t)
            at = abi_type(tt)
            var_types[n] = tt
            params.append(f"{at} gen_a{k}")
            if "*" in tt:
                prologue.append(f"  {tt} {n} = ({tt})(uintptr_t)gen_a{k};")
            elif tt.strip() in STRUCT8:
                prologue.append(f"  {tt} {n}; memcpy(&{n}, &gen_a{k}, sizeof {n});")
            else:
                prologue.append(f"  {tt} {n} = ({tt})gen_a{k};")
        # the reference's argument block, where the body takes an address in it (`&stack0x00000014`,
        # a variadic function's va_list): its 4-byte slots in a local array, the fixed parameters
        # first, then what a variadic one's caller passed after them, as many words as VA_WORDS.
        # The CRT's _output_l steps that va_list 4 bytes at a time, as the reference laid it out
        # (__snwprintf_s and the scanf family, the caller's stack, 2026-10-23)
        if sig.variadic or re.search(r"&\s*stack0x(?!f[0-9a-f]{7}\b)[0-9a-f]{8}", body):
            if sig.variadic and not params:
                raise ValueError("variadic with no fixed parameter")
            if any(abi_type(self.type_text(t)) != "unsigned int" for t, _n in sig.params):
                raise ValueError("an argument block with a parameter of 8 bytes")
            words = len(sig.params) + (VA_WORDS if sig.variadic else 0)
            block = [f"  unsigned int gen_args[{max(words, 1)}];"]
            block += [f"  gen_args[{k}] = gen_a{k};" for k in range(len(sig.params))]
            if sig.variadic:
                last = len(sig.params) - 1
                block += [f"  {{ va_list gen_va; va_start(gen_va, gen_a{last});",
                          f"    for (int gen_i = {len(sig.params)}; gen_i < {words}; gen_i++) "
                          f"gen_args[gen_i] = va_arg(gen_va, unsigned int);",
                          "    va_end(gen_va); }"]
            prologue = block + prologue
            var_types["gen_args"] = "unsigned int[]"

            def slot(m):
                off = int(m.group(1), 16)
                if off < 4 or off % 4 or (off - 4) // 4 >= words:
                    raise ValueError(f"the caller's stack beyond its arguments (stack0x{m.group(1)})")
                return f"((undefined *)&gen_args[{(off - 4) // 4}])"
            body = re.sub(r"\(uint\)\s*&\s*stack0x(?!f[0-9a-f]{7}\b)([0-9a-f]{8})",
                          lambda m: f"(uint)(uintptr_t){slot(m)}", body)
            body = re.sub(r"&\s*stack0x(?!f[0-9a-f]{7}\b)([0-9a-f]{8})", slot, body)
            if sig.variadic:
                params.append("...")
        for m in re.finditer(r"(?m)^\s+((?:unsigned\s+)?[A-Za-z_]\w*(?:\s*\*[\s*]*(?:PTR32\s*\*\s*)*)?)\s*([A-Za-z_]\w*)\s*(\[[^\]]*\])?\s*;",
                             split_decls(body)[0]):
            # (an array is its element type with [] on: what indexes and dereferences it is fine)
            var_types.setdefault(m.group(2), m.group(1) + ("[]" if m.group(3) else ""))
        # (and sse_ops' temporaries, declared where they are computed)
        for n in set(re.findall(r"\bgen_vt\d+\b", body)):
            var_types[n] = "undefined1[]"
        body = self.typed_casts(body, var_types)
        body = self.call_args(body, var_types)
        # (an 8-byte structure cast to an integer: its 64 bits)
        struct8_locals = [n for n, t in var_types.items() if t.strip() in STRUCT8]
        if struct8_locals:
            body = re.sub(r"\(((?:unsigned\s+)?[A-Za-z_]\w*)\)\s*(" + "|".join(map(re.escape, struct8_locals)) + r")\b(?!\s*[.\[])",
                          lambda m: f"({m.group(1)})(*(ULONGLONG *)&{m.group(2)})"
                          if m.group(1).strip() in KNOWN_TYPES and m.group(1).strip() not in STRUCT_TYPES else m.group(0), body)
        if sig.ret.strip() in STRUCT8:
            # (an 8-byte structure returned by value: its 64 bits, as edx:eax held them)
            body = re.sub(r"\breturn\s+([A-Za-z_]\w*)\s*;",
                          lambda m: f"return *(ULONGLONG *)&{m.group(1)};"
                          if var_types.get(m.group(1), "").strip() in STRUCT8 else m.group(0), body)
        # a 3, 5, 6 or 7-byte piece written (`local_8._1_3_ = ...`)
        body = re.sub(r"GEN_PIECE\((&[^,]+), (\d+), (\d+)\)\s*=\s*([^;]+);",
                      r"gen_piece_set(\1, \2, \3, (unsigned long long)(\4));", body)
        # a float global under a bitwise operator is its bits (xorps with the sign mask: Ghidra
        # writes `(uint)x ^ DAT_010920d0`)
        body = re.sub(r"([\^|]\s*|&\s+)REFG\(float, (0x[0-9a-f]+)\)", r"\1REFG(uint, \2)", body)
        body = re.sub(r"REFG\(float, (0x[0-9a-f]+)\)(?=\s*(?:\^|\||&(?!&)|>>|<<))", r"REFG(uint, \1)", body)
        body = re.sub(r"([\^|]\s*|&\s+)REFG\(double, (0x[0-9a-f]+)\)", r"\1REFG(ulonglong, \2)", body)
        body = re.sub(r"REFG\(double, (0x[0-9a-f]+)\)(?=\s*(?:\^|\||&(?!&)|>>|<<))", r"REFG(ulonglong, \1)", body)
        # a float global copied whole into whatever Ghidra typed the target (a mov of its 4 bytes
        # into a pointer slot): the value into a float, the bits into anything else
        def flt_to(m):
            lhs, rhs = m.group(2), m.group(3)
            # (a plain local by its declared type: the bits into a pointer, the value otherwise)
            if re.fullmatch(r"[A-Za-z_]\w*", lhs) and lhs in var_types:
                t = var_types[lhs].strip()
                if "*" not in t or "[" in t:
                    return m.group(0)
                return f"{m.group(1)}{lhs} = ({t})(uintptr_t)gen_fl2bits((float)({rhs}))"
            return f"{m.group(1)}{lhs} = GEN_FLT_TO({lhs}, {rhs})"
        body = re.sub(r"(?m)((?:^|[;{(,])\s*)((?:\*\s*)*[A-Za-z_]\w*(?:\s*\[[^\]\[]*\])*)\s*=(?!=)\s*"
                      r"(REFG\((?:float|double), 0x[0-9a-f]+\)|\(&REFG\((?:float|double), 0x[0-9a-f]+\)\)\[[^\]\[]*\])"
                      r"(?=\s*[;,)])", flt_to, body)
        # (unary: `a * (*(undefined4 *)(...))` is a multiplication)
        if re.search(r"(?:^|[^\w)\]\s])\s*\*\s*\(\*\(undefined4 \*\)\(\(char \*\)&", body, re.M):
            raise ValueError("a 4-byte piece dereferenced as a pointer")
        for n, t in var_types.items():
            if t.strip() == "code *" and re.search(r"\b" + re.escape(n) + r"\s*[-+]\s", body):
                raise ValueError("arithmetic on a code pointer")
        body = self.code_pointer_calls(body, var_types)
        body = self.called_pointers(body)
        body = self.code_slots(body, var_types)
        body = self.float_assignments(body, var_types)
        body = self.pointer_locals(body, var_types)
        # (a pointer-typed local in integer arithmetic C only allows integers in, `pcVar4 * 4` of
        # an index Ghidra typed `char *` (a copy of an array's char * element): its integer value)
        for n, t in var_types.items():
            if "*" in t and "[" not in t:
                body = re.sub(r"(?<![\w$.>*&])\b(" + re.escape(n) + r")\s*(\*|/|%|<<|>>)\s*(?=[\w(])",
                              lambda m: f"((int)(uintptr_t){m.group(1)}) {m.group(2)} ", body)
        # (a float result cast to a pointer type, Ghidra reusing a local of one for it, `local_c4 =
        # (HGDIOBJ)FUN_00c4ca20()`: its bits, GEN_TOP, as C converts no float to a pointer)
        out, i = [], 0
        for m in re.finditer(r"\(([A-Za-z_][\w \t]*?(?:\*[\s*]*(?:PTR32[\s*]*)*)?)\)\s*(F_[0-9a-f]{8})\(", body):
            t, f = m.group(1).strip(), m.group(2)
            fa = int(f[2:], 16)
            ret = self.sigs[fa].ret.strip() if fa in self.sigs else ""
            if m.start() < i or ret not in FLOATS or not (t.endswith("*") or t in WIN_POINTERS):
                continue
            close = match_paren(body, m.end() - 1)
            if close < 0:
                continue
            out.append(body[i:m.start()])
            out.append(f"({t})GEN_TOP({body[m.start(2):close]})")
            i = close
        out.append(body[i:])
        body = "".join(out)
        # (and of a float read, `(HGDIOBJ)(*(float *)(iVar7 + 0x4c))`)
        out, i = [], 0
        for m in re.finditer(r"\(([A-Za-z_][\w \t]*?(?:\*[\s*]*(?:PTR32[\s*]*)*)?)\)\s*(?=\(\s*\*\s*\(\s*(?:float|double)\s*\*\s*\))", body):
            t = m.group(1).strip()
            if m.start() < i or not (t.endswith("*") or t in WIN_POINTERS):
                continue
            close = match_paren(body, m.end())
            if close < 0:
                continue
            out.append(body[i:m.start()])
            out.append(f"({t})GEN_TOP({body[m.end():close]})")
            i = close
        out.append(body[i:])
        body = "".join(out)
        # (and a piece of a local indexed as a pointer, `local_28._4_4_[0x30]`: an element of no
        # type the code says)
        if re.search(r"\._\d+_4_\s*\[", c):
            raise ValueError("a 4-byte piece indexed as a pointer")
        # (in the code, not in a string: "ios_base::eofbit set" is text)
        code_only = re.sub(r'"(?:[^"\\\n]|\\.)*"', '""', body)
        # (Ghidra's stack pieces, `_uStack_1c`; not a library signature's `_StackCookie`)
        left = re.search(r"::|`|\bregister0x|\b_(?:local|param|[a-z]*Stack(?![A-Za-z])|auStack)\w*|\bin_(?!E[ACD]X\b|E[ACD]X_\d+\b|XMM\d+\b)[A-Z]", code_only)
        if left:
            raise ValueError(f"a name C cannot take ({left.group(0)})")
        self.undeclared(body, var_types)
        ret = self.ret_type(sig.ret)
        if sig.ret.strip() == "void":
            body = re.sub(r"\breturn\s*;", "return 0;", body)
        if not balanced(body):
            raise ValueError("unbalanced braces")
        # (the lost result registers it only returns: 0 where nothing set them, why_not. Last, as
        # the passes above read the declarations as `type name;`)
        for n in returned_only(c):
            body = re.sub(r"(?m)^(\s*[A-Za-z_][\w ]*?\s+" + n + r")\s*;", r"\1 = 0;", body, count=1)
        body = frame_locals(body)
        # (a frame slot of a pointer type converted to a float, Ghidra reusing one local for both:
        # its bits, as GEN_TOF takes a pointer's)
        # (not one indexed: `(float)local_x[i]` converts the element)
        body = re.sub(r"\((float|double)\)\s*(\(\*\([^()]*\*\s*PTR32\s*\*\)\(gen_frame \+ 0x[0-9a-f]+\)\))(?!\s*\[)",
                      lambda m: f"{'GEN_TOF' if m.group(1) == 'float' else 'GEN_TOD'}({m.group(2)})", body)
        # (an odd-sized piece copied into a 16-byte array: its bytes, `auVar14 = GEN_PIECE(&x, 0, 12)`)
        body = re.sub(r"(?m)^([ \t]*)([A-Za-z_]\w*)\s*=\s*GEN_PIECE\((.+), (\d+), (\d+)\);[ \t]*$",
                      lambda m: f"{m.group(1)}memcpy({m.group(2)}, (char *)({m.group(3)}) + {m.group(4)}, {m.group(5)});"
                      if re.search(r"(?m)^[ \t]+undefined1\s+" + m.group(2) + r"\s*\[", body) else m.group(0), body)
        # (the lost full xmm registers: zeroed 16-byte locals, sse_ops)
        body = re.sub(r"(?m)^([ \t]+undefined1\s+in_XMM\d+\s*\[\s*16\s*\])\s*;", r"\1 = {0};", body)
        decl = f"{ret} F_{a:08x}({', '.join(params) or 'void'})"
        # (the shadow trace's record of the call, first: its address and first four integer
        # arguments, as shadow32.py records the reference's)
        args = [f"gen_a{k}" if abi_type(self.type_text(t)) == "unsigned int" else "0u"
                for k, (t, _n) in enumerate(sig.params[:4])]
        args += ["0u"] * (4 - len(args))
        prologue = [f"  GEN_ENTER(0x{a:x}u, {', '.join(args)});"] + prologue
        # (the parameters' names are locals now, declared first in the body)
        body = body.replace("{", "{\n" + "\n".join(prologue), 1)
        return f"/* ref: {self.corpus[a]['name']} */\n{decl}\n{body.strip()}\n"

    def undeclared(self, body: str, var_types: dict[str, str]) -> None:
        """Every name left in the body is one C will know: a local or parameter, a label, a
        translated function, an import adapter, a type, or Ghidra32.h's. One that is none (a C++
        class or helper the decompiler spelled by name: DName, exception, operator) is the
        function's stub now, not a compile error later."""
        text = re.sub(r'L?"(?:\\.|[^"\\\n])*"|L?\'(?:\\.|[^\'\\\n])*\'', "", body)
        labels = set(re.findall(r"(?m)^\s*([A-Za-z_]\w*)\s*:", text))
        for m in re.finditer(r"(?<![\w$.>])([A-Za-z_]\w*)\b", text):
            n = m.group(1)
            if n in var_types or n in labels or n in KNOWN_TYPES or n in C_WORDS or n in HEADER_NAMES:
                continue
            if n.startswith(("F_", "gen_imp_", "LAB_", "switchD_", "caseD_")) or n in header_names():
                continue
            raise ValueError(f"undeclared name {n}")

    @staticmethod
    def switch_values(body: str) -> str:
        """`switch (x)` on a value C will not switch on (a pointer, a float): its integer."""
        out, i = [], 0
        for m in re.finditer(r"\bswitch\s*\(", body):
            if m.start() < i:
                continue
            open_ = m.end() - 1
            close = match_paren(body, open_)
            if close < 0:
                continue
            out.append(body[i:open_])
            out.append(f"((unsigned int)(uintptr_t)({body[open_ + 1:close - 1]}))")
            i = close
        out.append(body[i:])
        return "".join(out)

    @staticmethod
    def called_pointers(body: str) -> str:
        """`(*(*(T * PTR32 *)p))(...)`: a stored pointer called, whatever Ghidra typed it, is a
        function's."""
        out, i = [], 0
        for m in re.finditer(r"\(\*\s*\(\*\s*\(\(?([A-Za-z_]\w*) \* PTR32 \*\)", body):
            if m.start() < i or m.group(1) == "code":
                continue
            close = match_paren(body, m.start())
            if close < 0 or not body[close:].lstrip().startswith("("):
                continue
            out.append(body[i:m.start(1)])
            out.append("code")
            i = m.end(1)
        out.append(body[i:])
        return "".join(out)

    @staticmethod
    def code_slots(body: str, var_types: dict[str, str]) -> str:
        """A stored function pointer is a 4-byte integer, gen_code32, and a call through one
        converts it to a function pointer first. MSVC drops __ptr32 from a pointer to a function:
        `(**(code * PTR32 *)(vt + 0x14))()` loaded the slot as 8 bytes and called its garbage
        (F_00405f60's first virtual call, 2026-10-23), and a __ptr32 function-pointer typedef
        compiles to a 32-bit `jmp dword ptr`. The integer converts, zero-extended, as a
        reference address does."""
        body = re.sub(r"\(\s*\*\s*\*\s*(\(?)\(code \* PTR32 \*\)", r"((code *)*\1(gen_code32 *)", body)
        # (a global called through, whatever Ghidra typed its pointer: `(*REFG(char * PTR32, x))()`)
        body = re.sub(r"\(\*REFG\([A-Za-z_][\w ]*\* PTR32, (0x[0-9a-f]+)\)\)(?=\s*\()", r"((code *)REFG(gen_code32, \1))", body)
        body = re.sub(r"\(\*\s*\(\*\s*(\(?)\(code \* PTR32 \*\)", r"((code *)(\1*(gen_code32 *)", body)
        for n, t in var_types.items():
            if t.strip() in ("FARPROC", "code * PTR32", "gen_code32"):
                # (code_pointer_calls' `((code *)*n)` of a pointer stored __ptr32 too)
                body = re.sub(r"\(\s*\*\s*" + re.escape(n) + r"\s*\)(?=\s*\()", f"((code *){n})", body)
                body = body.replace(f"((code *)*{n})(", f"((code *){n})(")
        return body.replace("code * PTR32", "gen_code32")

    @staticmethod
    def code_pointer_calls(body: str, var_types: dict[str, str]) -> str:
        """A call through a function pointer stored in memory: `(*param_1)()` of a `code **`
        (one of _initterm's tables). The stored pointer is __ptr32, and MSVC calls through the
        function a __ptr32 pointer designates, not through the pointer value: one more `*`."""
        for n, t in var_types.items():
            if "PTR32" in t and "[" not in t:
                body = re.sub(r"\(\s*\*\s*" + re.escape(n) + r"\s*\)\s*\(", f"((code *)*{n})(", body)
            elif "*" in t and "[" not in t and not t.strip().startswith("code"):
                # (a pointer Ghidra typed void * and calls: qsort's comparison, a continuation)
                body = re.sub(r"\(\s*\*\s*" + re.escape(n) + r"\s*\)\s*\(", f"((code *){n})(", body)
        return re.sub(r"\(\s*\*\s*\(code \* PTR32 \*\)", "(**(code * PTR32 *)", body)

    @staticmethod
    def float_assignments(body: str, var_types: dict[str, str]) -> str:
        """`local_18 = DAT_01087f04;` of a `char *local_18` and a float global: Ghidra reusing a
        register's variable for a float, as with float_operands. The value's bits."""
        def rep(m):
            n, rhs = m.group(2), m.group(3)
            t = var_types.get(n, "")
            if "*" not in t or "[" in t:
                return m.group(0)
            bare = re.sub(r'L?"(?:\\.|[^"\\])*"', '""', rhs)   # (`"Havok-3.0.0"` holds no float)
            if not FLOATISH.search(bare) or re.search(r'&|""|\bF_[0-9a-f]{8}\s*\(|\bREFG\((?!float|double)|\(\s*[A-Za-z_][\w ]*\*', bare):
                return m.group(0)
            return f"{m.group(1)}{n} = ({t.strip()})(uintptr_t)gen_fl2bits((float)({rhs}));"
        return re.sub(r"(?m)^(\s*)([A-Za-z_]\w*)\s*=\s*([^;=]+);\s*$", rep, body)

    @staticmethod
    def pointer_locals(body: str, var_types: dict[str, str]) -> str:
        """A local Ghidra declared `undefined4` that its code dereferences or indexes: the type of
        the pointer assigned to it (`undefined4 local_80; ... local_80 = param_1 + 0xb2; uVar1 =
        *local_80;` of a `ushort *param_1`)."""
        for n, t in list(var_types.items()):
            if t.strip() not in ("undefined4", "uint", "int"):
                continue
            if not (unary_deref(body, n) or re.search(r"\b" + re.escape(n) + r"\s*\[", body)):
                continue
            m = re.search(r"\b" + re.escape(n) + r"\s*=\s*\(?([A-Za-z_]\w*)\b", body)
            src = var_types.get(m.group(1), "") if m else ""
            if "*" not in src:
                c = re.search(r"\b" + re.escape(n) + r"\s*=\s*\(([A-Za-z_][\w ]*\*[\w *]*)\)", body)
                src = c.group(1) if c and is_type(c.group(1)) else ""
            if "*" not in src:
                raise ValueError(f"an integer local used as a pointer ({n})")
            body = re.sub(r"(?m)^(\s*)" + re.escape(t.strip()) + r"\s+" + re.escape(n) + r"\s*;",
                          lambda mm: f"{mm.group(1)}{src.strip()} {n};", body, count=1)
            var_types[n] = src
        return body

    def kind_of(self, e: str, var_types: dict[str, str]) -> str | None:
        """What an expression is, as far as its text says: "float", "ptr", "int", or None."""
        e = e.strip()
        while e.startswith("(") and match_paren(e, 0) == len(e):
            e = e[1:-1].strip()
        if re.fullmatch(r"-?\d+\.\d*(?:[eE][-+]?\d+)?f?", e):
            return "float"
        if re.fullmatch(r"-?(?:0x[0-9a-fA-F]+|\d+)[uUlL]*", e) or re.fullmatch(r"L?'(?:\\.|[^'\\])*'", e):
            return "int"
        if re.fullmatch(r"L?\"(?:\\.|[^\"\\])*\"", e) or (e.startswith("&") and not e.startswith("&&")):
            return "ptr"

        def of_type(t: str) -> str:
            t = t.strip()
            if "[" in t or "*" in t or t in WIN_POINTERS:
                return "ptr"
            return "float" if t in FLOATS else "int"
        if re.fullmatch(r"[A-Za-z_]\w*", e):
            t = var_types.get(e)
            return of_type(t) if t else None
        m = re.fullmatch(r"\*\s*([A-Za-z_]\w*)", e)
        if m and m.group(1) in var_types:
            t = var_types[m.group(1)].strip()
            if t.endswith("[]"):
                return of_type(t[:-2])
            if t.endswith("*"):
                inner = re.sub(r"\s*(?:PTR32\s*)?\*\s*$", "", t)
                return of_type(inner)
            return None
        m = re.fullmatch(r"([A-Za-z_]\w*)\s*\[[^\[\]]*\]", e)
        if m and m.group(1) in var_types:
            t = var_types[m.group(1)].strip()
            inner = t[:-2] if t.endswith("[]") else re.sub(r"\s*(?:PTR32\s*)?\*\s*$", "", t)
            return of_type(inner)
        m = re.fullmatch(r"REFG\(([^,]+),\s*0x[0-9a-f]+\)", e)
        if m:
            return of_type(m.group(1))
        m = re.match(r"\*\s*\(([A-Za-z_][\w ]*(?:\*|PTR32)[\w *]*)\)", e)
        if m and is_type(m.group(1)) and operand_end(e, 1) == len(e):
            return of_type(re.sub(r"\s*(?:PTR32\s*)?\*\s*$", "", m.group(1).strip()))
        m = re.match(r"\(([A-Za-z_][\w *]*)\)", e)
        if m and is_type(m.group(1)) and operand_end(e, m.end()) == len(e):
            return of_type(m.group(1))
        m = re.fullmatch(r"F_([0-9a-f]{8})\s*\(.*\)", e, re.S)
        if m and match_paren(e, e.index("(")) == len(e):
            sig = self.sigs.get(int(m.group(1), 16))
            try:
                return of_type(self.ret_type(sig.ret)) if sig else None
            except ValueError:
                return None
        # a binary expression: float if any side is, otherwise what its sides agree on
        parts = [p for p in re.split(r"\s(?:[-+*/%|^]|<<|>>|&(?!&))\s", e) if p.strip()]
        if len(parts) > 1 and all(p.count("(") == p.count(")") for p in parts):
            kinds = [self.kind_of(p, var_types) for p in parts]
            if "float" in kinds:
                return "float"
            if None not in kinds:
                return "ptr" if "ptr" in kinds else "int"
        return None

    def call_args(self, body: str, var_types: dict[str, str]) -> str:
        """Each argument of a call to a translated function as its parameter's type: a float
        parameter given a pointer or what the text cannot type (Ghidra's variable for a register
        that held one), by GEN_TOF; an integer parameter given a float, its bits (the reference
        pushed the float's 4 bytes and the callee read them as an integer)."""
        out, i = [], 0
        for m in re.finditer(r"\bF_([0-9a-f]{8})\s*\(", body):
            if m.start() < i:
                continue
            open_ = m.end() - 1
            close = match_paren(body, open_)
            if close < 0:
                continue
            sig = self.sigs.get(int(m.group(1), 16))
            inner = body[open_ + 1:close - 1]
            args = split_top(inner) if inner.strip() else []
            if sig is None or sig.variadic or len(args) != len(sig.params):
                new_args = [self.call_args(x, var_types) for x in args]
            else:
                new_args = []
                for x, (t, _n) in zip(args, sig.params):
                    x = self.call_args(x, var_types)
                    try:
                        abi = abi_type(self.type_text(t))
                    except ValueError:
                        new_args.append(x)
                        continue
                    k = self.kind_of(x, var_types)
                    if abi == "unsigned long long" and var_types.get(x.strip(), "").strip() in STRUCT8:
                        # (an 8-byte structure passed by value: its 64 bits)
                        x = f"(*(ULONGLONG *)&{x.strip()})"
                    if abi in ("float", "double"):
                        if k not in ("float", "int"):
                            x = f"{'GEN_TOF' if abi == 'float' else 'GEN_TOD'}({x.strip()})"
                    elif abi == "unsigned int" and k == "float":
                        x = f"(unsigned int)gen_fl2bits((float)({x.strip()}))"
                    new_args.append(x)
            out.append(body[i:open_ + 1])
            out.append(",".join(new_args))
            out.append(")")
            i = close
        out.append(body[i:])
        return "".join(out)

    def typed_casts(self, body: str, var_types: dict[str, str]) -> str:
        """A cast between floating point and a pointer (Ghidra's register bits) as the bits: by
        the operand's type where its text says it, through GEN_TOF / GEN_TOP (Ghidra32.h, by C's
        own type) where it does not."""
        out, i = [], 0
        for m in re.finditer(r"\(([A-Za-z_][\w *]*)\)", body):
            if m.start() < i:
                continue
            t = m.group(1).strip()
            if not is_type(t):
                continue
            to_float = t in FLOATS
            to_ptr = "*" in t
            if not (to_float or to_ptr):
                continue
            j = m.end()
            # (`(code *)REFP(...)` and the like are addresses; a cast of a cast is the inner's)
            nxt = body[j:].lstrip()
            if not nxt or nxt[0] in ";,)]}" or nxt.startswith(("REFP(", "GP(", "REFG(code")):
                continue
            end = operand_end(body, j)
            operand = body[j:end].strip()
            if not operand:
                continue
            k = self.kind_of(operand, var_types)
            # (the operand's own casts too, before it is wrapped whole)
            operand = self.typed_casts(operand, var_types)
            if to_float:
                if k in ("float", "int"):
                    continue
                conv = "GEN_TOD" if t in ("double", "float8", "float10") else "GEN_TOF"
                rep = f"(({t})gen_bits2f((unsigned int)(uintptr_t)({operand})))" if k == "ptr" else f"(({t}){conv}({operand}))"
            else:
                if k in ("ptr", "int"):
                    continue
                rep = f"(({t})(uintptr_t)gen_fl2bits((float)({operand})))" if k == "float" else f"(({t})GEN_TOP({operand}))"
            out.append(body[i:m.start()])
            out.append(rep)
            i = end
        out.append(body[i:])
        return "".join(out)

    @staticmethod
    def float_operands(body: str, var_types: dict[str, str]) -> str:
        """A pointer cast of a floating point expression (`param_1 = (float *)(1.0 - param_3)`:
        Ghidra reusing a register's variable for an x87 value) is the value's bits."""
        floats = {n for n, t in var_types.items() if t.strip() in FLOATS}
        out, i = [], 0
        for m in re.finditer(r"\(([A-Za-z_][\w ]*\*[\w *]*)\)", body):
            if m.start() < i or not is_type(m.group(1)):
                continue
            j = m.end()
            end = operand_end(body, j)
            operand = body[j:end].strip()
            if not operand or operand.startswith("(" + m.group(1)):
                continue
            words = set(re.findall(r"[A-Za-z_]\w*", operand))
            if not (FLOATISH.search(operand) or words & floats):
                continue
            # (an address is no float value, nor a call, whose type is its own)
            if re.search(r"\bREFG\((?!float|double)|&|\bF_[0-9a-f]{8}\s*\(|\bgen_imp_", operand):
                continue
            out.append(body[i:j])
            out.append(f"(uintptr_t)gen_fl2bits((float)({operand}))")
            i = end
        out.append(body[i:])
        return "".join(out)

    @staticmethod
    def reinterpret_casts(body: str, var_types: dict[str, str]) -> str:
        """A cast between a float and a pointer is Ghidra moving a register's bits (movd, or a
        value through the x87 stack): `(float)pvVar1`, `(int *)fVar2`. C converts a value
        between float and integer and refuses float and pointer outright: the bits, here."""
        def is_ptr(n):
            t = var_types.get(n, "")
            return "*" in t and "[" not in t

        def is_float(n):
            return var_types.get(n, "").strip() in FLOATS

        def to_float(m):
            t, n = m.group(1), m.group(2)
            if is_ptr(n):
                return f"(({t})gen_bits2f((unsigned int)(uintptr_t){n}))"
            return m.group(0)
        body = re.sub(r"\((float|double|float10|float4|float8)\)\s*([A-Za-z_]\w*)\b(?!\s*[\[(])", to_float, body)

        def to_ptr(m):
            t, n = m.group(1), m.group(2)
            if is_float(n) and is_type(t):
                bits = "gen_fl2bits" if var_types[n].strip() in ("float", "float4") else "gen_d2bits"
                return f"(({t})(uintptr_t)(unsigned int){bits}({n}))"
            return m.group(0)
        return re.sub(r"\(([A-Za-z_][\w ]*\*[\w *]*)\)\s*([A-Za-z_]\w*)\b(?!\s*[\[(])", to_ptr, body)

    def ret_type(self, t: str) -> str:
        """A return type as the port declares it: a void function returns its eax anyway, and
        callers Ghidra saw use it (`uVar4 = FUN_004308f0(...)` of a void FUN_004308f0); a bare
        `code` (a function type) is the address it was."""
        t = self.type_text(t)
        return "unsigned int" if t in ("void", "code") else STRUCT8.get(t.strip(), t)

    def type_text(self, t: str) -> str:
        t = CC.sub("", t).strip()
        t = alias_types(t)
        t = re.sub(r"\b_func_\w+\b", "code", t)
        # a C++ type (templates, scopes): bytes under a pointer, nothing C can hold otherwise
        if re.search(r"[<>:`',]", t):
            if "*" not in t:
                raise ValueError(f"type {t[:40]}")
            t = "undefined " + "*" * t.count("*") if not re.search(r"\*.*[<>:]", t) else "undefined *"
        words = re.findall(r"[A-Za-z_]\w*", t.replace("unsigned", "").replace("signed", ""))
        for w in words:
            if w not in KNOWN_TYPES and w not in ("const", "volatile"):
                tc = self.typedef_c(w)
                if tc is not None:
                    t = re.sub(r"\b" + re.escape(w) + r"\b", tc, t)
                    continue
                if "*" in t:
                    t = re.sub(r"\b" + re.escape(w) + r"\b", "undefined", t)
                else:
                    raise ValueError(f"type {w}")
        return ptr32_type(t)

    def types(self, body: str) -> str:
        """Casts and declarations: unknown types under a pointer as bytes, size_t 32-bit, inner
        pointer levels __ptr32."""
        body = alias_types(body)
        body = re.sub(r"\b_func_\w+\b", "code", body)

        # (a cast to an exported typedef, `(_ptiddata)p`)
        body = re.sub(r"\(\s*([A-Za-z_]\w*)\s*\)",
                      lambda m: f"({self.typedef_c(m.group(1))})" if self.typedef_c(m.group(1)) else m.group(0), body)

        def cast(m):
            return "(" + self.type_text(m.group(1)) + ")"
        body = re.sub(r"\(\s*((?:const\s+)?[A-Za-z_~`][\w:`']*(?:<[^()]*?>)?(?:\s+[A-Za-z_]\w*)?\s*\*[\s*]*)\)", cast, body)

        def decl(m):
            t, rest = m.group(2), m.group(3)
            word = t.replace("*", "").strip()
            if word in NOT_TYPES:
                return m.group(0)
            return m.group(1) + self.type_text(t) + " " + rest
        # (a type and its name are apart by blanks or stars: `return;` is no `retur n;`). Only in
        # the declarations, which Ghidra writes first and ends with a blank line: a wrapped
        # expression's last line `fStack_54 * local_40;` is no declaration of local_40
        decls, rest = split_decls(body)
        decls = re.sub(r"(?m)^(\s+)((?:(?:unsigned|signed)\s+)?[A-Za-z_]\w*(?:::\w+)*(?:<[^;()]*?>)?(?:\s*\*[\s*]*|\s+))([A-Za-z_]\w*\s*(?:\[[^\]]*\])?\s*;)",
                       lambda m: decl(m) if "*" in m.group(2) or self.type_word_ok(m.group(2)) else m.group(0), decls)
        return decls + rest

    def type_word_ok(self, t: str) -> bool:
        w = t.replace("unsigned", "").replace("signed", "").replace("*", "").strip()
        if w in NOT_TYPES:
            return False
        if w not in KNOWN_TYPES and self.typedef_c(w) is None:
            raise ValueError(f"local of type {w}")
        return True

    def typedef_c(self, w: str) -> str | None:
        """An exported typedef as C: to a pointer, bytes (`_ptiddata` -> `undefined *`: members()
        has already placed its fields); to a scalar C knows, that scalar."""
        if w not in self.typedefs or w in KNOWN_TYPES:
            return None
        info = self.tinfo(w, 4)
        if info[0] == "ptr":
            return "undefined *"
        if info[0] == "scalar" and info[1] in KNOWN_TYPES:
            return info[1]
        return None

    def names(self, body: str) -> str:
        """Functions, imports and data symbols as what the port has for them."""
        # names with templates, backquoted scopes or spaces first (`ComBase<IDropTarget,...>::
        # vftable`, `` `long___stdcall_FFXIVException(undefined *)'::__l2::Callback::vftable``):
        # each ends at a call's `(` or a scope's last part, and is found by scanning back
        body = self.odd_names(body)

        def call(m):
            name = m.group(1)
            a = self.by_printed.get(name)
            if a is not None:
                return f"F_{a:08x}("
            imp = self.import_of(name)
            if imp is not None:
                return f"gen_imp_{imp}("
            if name in self.ref_names:
                return f"((code *)REFP(0x{self.ref_names[name]:x}))("
            return m.group(0)
        body = re.sub(r"(?<![\w$:])(" + IDENT + r")\s*\(", call, body)

        # (a label's address is an address; the label itself, `LAB_x:` and `goto LAB_x`, stays)
        body = re.sub(r"&\s*(LAB_([0-9a-f]{8}))\b", lambda m: f"REFP(0x{m.group(2)})", body)
        body = re.sub(r"&\s*(_*(?:s|u|ws)_\w*?_([0-9a-f]{8}))\b", lambda m: f"REFP(0x{m.group(2)})", body)

        # (a DAT_ with no data defined that the body only takes the address of is 1 byte to the
        # decompiler, so its `&DAT_x + k` counts bytes: __GET_RTERRMSG's `*(wchar_t **)(&DAT_01119cfc
        # + i * 8)` read 32-byte strides as an undefined4, and named R6033 for R6016, 2026-10-23)
        address_only = {n for n in set(re.findall(r"(?<![\w$])DAT_[0-9a-f]{8}(?![\w$])", body))
                        if int(n[4:], 16) not in self.refdata
                        and len(re.findall(r"(?<![\w$])" + n + r"(?![\w$])", body))
                        == len(re.findall(r"&\s*" + n + r"(?![\w$])", body))}

        def sym(m):
            name, addr = m.group(1), int(m.group(2), 16)
            if name.startswith("LAB_"):
                return name
            if name.startswith(("s_", "u_", "ws_")):
                return f"((char *)REFP(0x{addr:x}))" if name.startswith("s_") else f"((wchar_t *)REFP(0x{addr:x}))"
            if name.startswith("switchdataD_"):
                return f"REFP(0x{addr:x})"
            if name in address_only:
                return f"REFG(undefined, 0x{addr:x})"
            # (an UNK_ is a place with no data defined: 1 byte to the decompiler, so its
            # `&UNK_x + k` counts bytes. rhtest's table of 12-byte records, `&UNK_004040f0 + i * 0xc`,
            # stepped 48 as an undefined4 and read a name's bytes as its pointer, 2026-10-24.
            # `_UNK_x`, a wider read of the same place, is sized by the default)
            if name.startswith("UNK_") and addr not in self.refdata:
                return f"REFG(undefined, 0x{addr:x})"
            return self.global_lvalue(addr)
        body = ADDR_SYM.sub(sym, body)

        # the reference's TLS: its per-thread block array, by its index slot
        body = re.sub(r"\bThreadLocalStoragePointer\b", "GEN_TLS_ARRAY", body)
        if self.tls_index is not None:
            body = re.sub(r"(?<![\w$])_tls_index\b", f"REFG(int, 0x{self.tls_index:x})", body)

        # functions as values (their reference address: the runtime jumps from there), and
        # named data (Class::vftable, FID's CRT globals) by the refdata names
        def value(m):
            name = m.group(1)
            if name.startswith(("F_", "gen_", "REFG", "REFP", "GEN_", "LAB_")) or name in KNOWN_TYPES:
                return name
            a = self.by_printed.get(name)
            if a is not None:
                return f"((code *)REFP(0x{a:x}))"
            if name in self.ref_names:
                return self.global_lvalue(self.ref_names[name])
            return name
        body = re.sub(r"(?<![\w$:.])(" + IDENT + r")(?![\w$(:])(?!\s*\()", value, body)
        return self.pointer_globals(body)

    def odd_names(self, body: str) -> str:
        """Names made of more than word characters (operators, templates, backquoted scopes),
        every one the corpus and the data export have, matched whole, longest first."""
        cands = sorted({n for w in set(re.findall(r"[\w~]+", body)) for n in self.odd_by_word.get(w, ())
                        if n in body}, key=len, reverse=True)
        if not cands:
            return body
        odd_re = re.compile(r"(?<![\w$])(" + "|".join(map(re.escape, cands)) + r")(?![\w$])")

        def rep(m):
            name = m.group(1)
            rest = body[m.end():].lstrip()
            if name in self.odd_functions:
                a = self.by_printed[name]
                return f"F_{a:08x}" if rest.startswith("(") else f"((code *)REFP(0x{a:x}))"
            return self.global_lvalue(self.ref_names[name])
        return odd_re.sub(rep, body)

    @staticmethod
    def pointer_globals(body: str) -> str:
        """A global the data export does not type (undefined4) that the code uses as a pointer:
        dereferenced (`*DAT_x + 8`), indexed (`DAT_x[i]`) or called (`(*DAT_x)(...)`)."""
        body = re.sub(r"\(\*REFG\(undefined4, (0x[0-9a-f]+)\)\)\s*\(", r"(*REFG(code * PTR32, \1))(", body)
        body = re.sub(r"REFG\(undefined4, (0x[0-9a-f]+)\)(?=\s*\[)", r"REFG(int * PTR32, \1)", body)
        out, i = [], 0
        for m in re.finditer(r"\*\s*REFG\(undefined4, (0x[0-9a-f]+)\)", body):
            k = m.start() - 1
            while k >= 0 and body[k] in " \t":
                k -= 1
            # (a multiplication, unless the `)` before it closes a cast: `(int *)*DAT_x`)
            cast = k >= 0 and body[k] == ")" and re.search(r"\(\s*[A-Za-z_][\w ]*(?:\*[\s*]*|PTR32[\s*]*)*\)$", body[:k + 1])
            if k >= 0 and (body[k].isalnum() or body[k] in "_)]") and not cast:
                continue
            out.append(body[i:m.start()])
            out.append(f"*REFG(int * PTR32, {m.group(1)})")
            i = m.end()
        out.append(body[i:])
        return "".join(out)

    def global_lvalue(self, addr: int) -> str:
        n, t = self.refdata.get(addr, (4, "undefined4"))
        t = t.strip()
        # Ghidra's fs segment (its "tdb" block): this thread's x86 TEB (Ghidra32.h gen_teb32)
        if TEB_LO <= addr < TEB_HI:
            m = re.fullmatch(r"(.+?)\s*\[(\d+)\]", t)
            at = f"(gen_teb32() + 0x{addr - TEB_LO:x})"
            if m:
                et = self.c_data_type(m.group(1)) or "undefined4"
                return f"(({et} *)(uintptr_t){at})"
            ct = self.c_data_type(t) or {1: "undefined1", 2: "undefined2", 8: "undefined8"}.get(n, "undefined4")
            return f"(*({ct} *)(uintptr_t){at})"
        m = re.fullmatch(r"(.+?)\s*\[(\d+)\]", t)
        # (a scalar the instructions load as a float is one, whatever the export says)
        if addr in self.floats and not m:
            return f"REFG({self.floats[addr]}, 0x{addr:x})"
        if m:
            # (an array the instructions read as floats has float elements)
            et = self.floats[addr] if addr in self.floats else self.c_data_type(m.group(1))
            return f"(*({et} (*)[{m.group(2)}])REFP(0x{addr:x}))"
        if t in ("pointer", "addr"):
            return f"REFG(undefined * PTR32, 0x{addr:x})"
        ct = self.c_data_type(t)
        if ct is None:
            return f"(*(undefined (*)[{max(n, 1)}])REFP(0x{addr:x}))"
        return f"REFG({ct}, 0x{addr:x})"

    def c_data_type(self, t: str) -> str | None:
        t = t.strip()
        if t in ("pointer", "addr", "ImageBaseOffset32"):
            return "undefined * PTR32"
        if t.endswith("*"):
            base = t.rstrip("* ").strip()
            stars = t.count("*")
            if base not in KNOWN_TYPES:
                base = "undefined"
            return base + " * PTR32" * stars
        if t in KNOWN_TYPES:
            return t
        if t in ("string", "TerminatedCString", "char"):
            return "char"
        if t in ("unicode", "TerminatedUnicode"):
            return "wchar_t"
        return None

    # ---- the whole program ---------------------------------------------------------------------
    def translate_all(self, only: set[int] | None, demoted: dict[str, str]):
        translated, stubbed = {}, {}
        for a in sorted(self.corpus):
            if only is not None and a not in only:
                stubbed[a] = "not selected"
                continue
            if f"{a:08x}" in demoted:
                stubbed[a] = "demoted: " + demoted[f"{a:08x}"]
                continue
            why = self.why_not(a)
            if why:
                stubbed[a] = why
                continue
            try:
                translated[a] = self.rewrite(a)
            except ValueError as e:
                stubbed[a] = str(e)
        return translated, stubbed

    def stub_decl(self, a: int) -> str:
        sig = self.sigs.get(a)
        if sig is None:
            return f"unsigned int F_{a:08x}()"
        try:
            ret = self.ret_type(sig.ret)
            ps = [f"{abi_type(self.type_text(t))} gen_a{k}" for k, (t, _n) in enumerate(sig.params)]
        except ValueError:
            return f"unsigned int F_{a:08x}()"
        if sig.variadic:
            ps.append("...")
        return f"{ret} F_{a:08x}({', '.join(ps) or 'void'})"

    def emit(self, translated: dict[int, str], stubbed: dict[int, str]) -> list[Path]:
        GEN.mkdir(parents=True, exist_ok=True)
        decls = {a: self.stub_decl(a) for a in self.corpus}
        # every function's prototype, translated or not
        h = ["/* generated by translate32.py: every reference function's prototype */",
             "#pragma once", '#include "Ghidra32.h"']
        h += [f"{decls[a]};" for a in sorted(decls)]
        h += [f"unsigned int gen_imp_{n}();" for n in sorted(self.imports)]
        write(GEN / "translated.h", "\n".join(h) + "\n")
        write(GEN / "Ghidra32.h", HEADER.read_text(encoding="utf-8"))
        files = []
        items = sorted(translated.items())
        for k in range(0, len(items), PER_FILE):
            chunk = items[k:k + PER_FILE]
            path = GEN / f"translated_{k // PER_FILE:03d}.c"
            text = ['#include "translated.h"', "#pragma warning(disable: 4024 4047 4133 4244 4305 4311 4312 4700 4715 4716 4022 4028 4090 4146 4554)"]
            for a, t in chunk:
                text.append(t)
            write(path, "\n".join(text) + "\n")
            files.append(path)
        # (a file a larger translation wrote before is not this one's: the build compiles every
        # translated_*.c there is)
        for old in GEN.glob("translated_*.c"):
            if old not in files:
                old.unlink()
        # stubs
        s = ['#include "translated.h"']
        for a in sorted(stubbed):
            d = decls[a]
            ret = d.split(f"F_{a:08x}")[0].strip()
            # (a stub records its call in the shadow trace too: what the port could not do is a
            # place the two runs part)
            ps = d[d.index("(") + 1:d.rindex(")")].split(", ")
            args = [p.split()[-1] if p.startswith("unsigned int gen_a") else "0u" for p in ps[:4] if p not in ("void", "...")]
            args += ["0u"] * (4 - len(args))
            body = "GEN_ENTER(0x%xu, %s); GenUnimplemented(0x%x);" % (a, ", ".join(args), a)
            r = "" if ret == "void" else (" return 0;" if "*" not in ret else " return 0;")
            if ret not in ("void",) and not any(x in ret for x in ("*",)) and ret.split()[-1] in FLOATS:
                r = " return 0.0;"
            s.append(f"{d} {{ {body}{r} }}")
        write(GEN / "stubs.c", "\n".join(s) + "\n")
        # the jumps the runtime writes at each reference entry
        j = ['#include "translated.h"', "typedef struct { unsigned int ref; void *port; } GEN_JUMP;",
             "const GEN_JUMP g_genJumps[] = {"]
        j += [f"  {{0x{a:x}u, (void *)F_{a:08x}}}," for a in sorted(self.corpus)]
        # (and each local thunk, to its target's)
        j += [f"  {{0x{at:x}u, (void *)F_{t:08x}}}," for at, t in sorted(self.thunks.values())]
        j += ["};", f"const unsigned int g_genJumpCount = {len(self.corpus) + len(self.thunks)};"]
        write(GEN / "jumps.c", "\n".join(j) + "\n")
        # imports: an adapter per name, its real function resolved by the runtime
        im = ['/* generated by translate32.py: the reference\'s imports. Each adapter takes the 32-bit',
              '   arguments the reference passed (sign-extended: addresses are below 2 GB, and handles',
              '   such as INVALID_HANDLE_VALUE or HKEY_CURRENT_USER widen as Windows expects) and calls',
              '   the real function with them, ten stack words past the four in registers whatever the',
              '   import takes. Those are read through va_arg, never written: a Win64 callee owns its',
              '   parameter slots and widens them in place, and past the few the caller passed they are',
              '   its locals (GetACP() sign-extending ten of them wiped __setmbcp\'s _LocaleUpdate).',
              '   The runtime overrides the ones whose structures differ between x86 and x64. */',
              "#include <stdint.h>",
              "#include <stdarg.h>",
              "#define GEN_REST(last) intptr_t r[10]; va_list ap; va_start(ap, last); \\",
              "    for (int k = 0; k < 10; k++) r[k] = va_arg(ap, int); va_end(ap)",
              "typedef intptr_t (*gen_real_fn)(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t,",
              "                                intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t);",
              "typedef struct { unsigned int slot; const char *dll; const char *name; void *adapter; gen_real_fn *real; } GEN_IMPORT;"]
        for n, (slot, dll) in sorted(self.imports.items()):
            im.append(f"gen_real_fn gen_real_{n};")
            if n in OVERRIDES:
                im.append(f"unsigned int gen_imp_{n}();   /* the runtime's */")
                continue
            im.append(f"unsigned int gen_imp_{n}(int a0, int a1, int a2, int a3, ...) {{ GEN_REST(a3); "
                      f"return (unsigned int)gen_real_{n}(a0, a1, a2, a3, "
                      + ", ".join(f"r[{k}]" for k in range(10)) + "); }")
        im.append("const GEN_IMPORT g_genImports[] = {")
        # (an adapter the runtime writes calls Windows itself: nothing to resolve for it)
        for n, (slot, dll) in sorted(self.imports.items()):
            real = "0" if n in OVERRIDES else f"&gen_real_{n}"
            im.append(f'  {{0x{slot:x}u, "{dll}", "{n}", (void *)gen_imp_{n}, {real}}},')
        im += ["};", f"const unsigned int g_genImportCount = {len(self.imports)};"]
        write(GEN / "imports.c", "\n".join(im) + "\n")
        reasons = Counter(re.sub(r"\(.*", "", v).split(":")[0].strip() for v in stubbed.values())
        write(MANIFEST, json.dumps({"translated": len(translated), "stubbed": len(stubbed),
                                    "reasons": dict(reasons.most_common()),
                                    "stubs": {f"{a:08x}": v for a, v in sorted(stubbed.items())}}, indent=1))
        return files


def write(path: Path, text: str) -> None:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if path.exists() and path.read_bytes().decode("utf-8", errors="replace") == text:
        return
    # (as written: Windows newlines would double the corpus's own \r)
    path.write_bytes(text.encode("utf-8"))


# ---- the compile loop ---------------------------------------------------------------------------
_env: dict | None = None


def msvc_env() -> dict:
    """The x64 MSVC environment (vcvars64), captured once."""
    global _env
    if _env is None:
        vswhere = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Microsoft Visual Studio/Installer/vswhere.exe"
        vs = subprocess.run([str(vswhere), "-latest", "-property", "installationPath"], capture_output=True, text=True).stdout.strip()
        bat = Path(vs) / "VC/Auxiliary/Build/vcvars64.bat"
        out = subprocess.run(f'"{bat}" >nul 2>nul && set', shell=True, capture_output=True, text=True).stdout
        _env = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    return _env


def compile_one(path: Path) -> list[tuple[int, str]]:
    """(line, message) of every error compiling one generated file."""
    OBJ.mkdir(parents=True, exist_ok=True)
    env = msvc_env()
    # (Windows looks a program up on this process's PATH, not the one passed to it)
    import shutil
    cl = shutil.which("cl", path=env.get("PATH") or env.get("Path"))
    r = subprocess.run([cl, "/nologo", "/c", "/O1", "/W1", "/we4013", "/TC", "/bigobj", "/std:c17",
                        f"/Fo{OBJ / (path.stem + '.obj')}", str(path)],
                       capture_output=True, text=True, env=msvc_env(), cwd=str(GEN))
    errs = []
    for line in r.stdout.splitlines():
        m = re.match(r"^(.*?)\((\d+)\)\s*: (?:fatal )?error (\w+): (.*)$", line)
        if m and Path(m.group(1)).name == path.name:
            errs.append((int(m.group(2)), f"{m.group(3)}: {m.group(4)}"))
    return errs


def function_at_line(path: Path) -> list[tuple[int, int]]:
    """(first line, address) of each function in a generated file."""
    out = []
    for k, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        m = re.match(r"/\* ref: .* \*/", line)
        if m:
            nxt = None
            out.append((k, None))
        m2 = re.match(r"^.*\bF_([0-9a-f]{8})\(", line)
        if m2 and out and out[-1][1] is None:
            out[-1] = (out[-1][0], int(m2.group(1), 16))
    return [(k, a) for k, a in out if a is not None]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-build", action="store_true")
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--rounds", type=int, default=20)
    ap.add_argument("--keep-demoted", action="store_true",
                    help="start from the last run's demotions (by default every function is tried again: "
                         "a fix in the translator shows as a round with none)")
    args = ap.parse_args()
    t = Translator32()
    only = {int(x, 16) for x in args.only} if args.only else None
    demoted = json.loads(DEMOTED.read_text()) if DEMOTED.exists() and args.keep_demoted else {}
    for rnd in range(args.rounds):
        translated, stubbed = t.translate_all(only, demoted)
        files = t.emit(translated, stubbed)
        print(f"round {rnd}: translated {len(translated)}, stubbed {len(stubbed)} in {len(files)} files")
        if args.no_build:
            return
        t0 = time.time()
        with ThreadPoolExecutor(args.jobs) as pool:
            results = dict(zip(files, pool.map(compile_one, files)))
        new = 0
        for path, errs in results.items():
            if not errs:
                continue
            starts = function_at_line(path)
            lines = path.read_text(encoding="utf-8").splitlines()
            for line, msg in errs:
                owner = None
                for k, a in starts:
                    if k <= line:
                        owner = a
                    else:
                        break
                if owner is not None and f"{owner:08x}" not in demoted:
                    # (the line too: what the translator should have written differently)
                    src = lines[line - 1].strip() if 0 < line <= len(lines) else ""
                    demoted[f"{owner:08x}"] = f"{msg[:120]} | {src[:200]}"
                    new += 1
        write(DEMOTED, json.dumps(demoted, indent=1, sort_keys=True))
        print(f"  compiled in {time.time() - t0:.0f}s: {new} functions demoted")
        if new == 0:
            break
    # the stubs, jumps and imports must build too
    for extra in ("stubs.c", "jumps.c", "imports.c"):
        errs = compile_one(GEN / extra)
        print(f"  {extra}: {'ok' if not errs else errs[:5]}")


if __name__ == "__main__":
    main()
