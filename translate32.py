"""A 32-bit reference's decompilation translated to C for an x64 port: translate.py's counterpart
for rhipper.json "arch": "x86" (first a VS2010 /MT game client).

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
--port-longs DIR rewrites an existing gen directory's `long`s for an LP64 host (port_longs).
"""
from __future__ import annotations

import argparse
import itertools
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import Pool
from pathlib import Path

import project
import vec32
from project import FACTS, GEN, ROOT
from signedness import signed_siblings, signed_tests

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
    "gen_v16", "gen_r16", "gen_v8","gen_v12", "gen_v24", "gen_v32", "gen_v48", "gen_v64", "gen_code32", "gen_long",
    "gen_ulong", "void", "char", "short", "int", "long", "float", "double", "bool", "wchar_t", "signed", "unsigned",
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
# an x86 CRITICAL_SECTION's fields: (offset, type)
CS_FIELDS = {"DebugInfo": (0, "unsigned int"), "LockCount": (4, "int"), "RecursionCount": (8, "int"),
             "OwningThread": (0xc, "unsigned int"), "LockSemaphore": (0x10, "unsigned int"),
             "SpinCount": (0x14, "unsigned int")}
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
CC = re.compile(r"\b(__thiscall|__cdecl|__stdcall|__fastcall|__vectorcall)(?:_keep(?:_[a-z][a-z0-9]*)+)?\b\s*")
LOST = re.compile(r"\b(in_[A-Z][A-Za-z0-9_]*|in_stack_[0-9a-f]+|unaff_[A-Za-z0-9_]+|extraout_[A-Za-z0-9_]+|in_FS_OFFSET)\b")
# a symbol ending in its address (DAT_00401000, PTR_FUN_00401000, s_text_00401000, LAB_...)
# (the address its last: Ghidra's suffix for a repeated name is a short count, `_1`. As any digits,
# it took the address of `PTR_vtable_004031d8_00404088` for one, and thing_open returned the
# vtable it points at, not the object, rhtest msvc-14.51-x86 calls-GL com_calls 2026-10-25)
# (a string's label keeps some of its text's punctuation: `s_<name>_or_______expected_01348094`,
# `s_in_function_<_s:_d>_013483cc`, Lua's messages. Read up to its `<`, the name was `s_`, undeclared)
ADDR_SYM = re.compile(r"(?<![\w$])(_*(?:(?:DAT|PTR|LAB|UNK|BYTE|WORD|DWORD|QWORD|switchdataD|vtable)(?:_\w*?)?"
                      r"|(?:s|u|ws)(?:_[\w<>:]*?)?)_([0-9a-f]{8})(?:_\d{1,7})?)(?![\w$])")
# C's own words, and the names Ghidra32.h defines that the body may use
C_WORDS = {"if", "else", "while", "for", "do", "switch", "case", "default", "break", "continue", "return",
           "goto", "sizeof", "const", "volatile", "struct", "union", "enum", "static", "extern", "unsigned",
           "signed", "true", "false", "NULL", "this"}
HEADER_NAMES = {"REFG", "REFP", "GP", "PTR32", "MXCSR", "ExceptionList", "GenUnimplemented", "POPCOUNT", "ABS",
                "SQRT", "ROUND", "TRUNC", "FLOOR", "CEIL", "HeapCompatibilityInformation", "uintptr_t",
                "intptr_t", "uint32_t", "int32_t", "uint64_t", "int64_t", "uint16_t", "int16_t", "uint8_t",
                "int8_t", "__ptr32", "__uptr", "_InterlockedExchange", "_InterlockedExchangeAdd",
                "_InterlockedCompareExchange", "NAN", "INFINITY",
                "__debugbreak", "_rotl", "_rotr", "_rotl64", "_rotr64", "fabs", "sqrt", "pow", "atan2", "fsin", "fcos",
                "log2",
                "builtin_strncpy", "builtin_memcpy", "builtin_memset",
                "floor", "ceil", "trunc", "nearbyint", "memcpy", "memset", "rdtsc", "GEN_PIECE", "GEN_ISNAN",
                "gen_piece_set", "gen_sext_n", "gen_ld80", "gen_fl2bits", "gen_d2bits", "gen_bits2f", "gen_bits2d", "GEN_TOF", "GEN_TOD", "GEN_ARGF", "GEN_SLOT", "GEN_LOW",
                "gen_ac", "GEN_LO32", "GEN_HI32",
                "GEN_TOP", "GEN_FLT_TO", "gen_vzero", "GEN_NE"}
_header_names: set[str] | None = None


def cid(name: str) -> str:
    """An import's name as a C identifier: itself, or a C++ import's mangled name with every
    character C refuses spelled `_xx` in hex, `??0?$basic_ios@...` (msvcp140's, rhtest stl: as it
    was, imports.c did not compile)."""
    if re.fullmatch(r"[A-Za-z_]\w*", name):
        return name
    return "x" + re.sub(r"[^A-Za-z0-9]", lambda m: f"_{ord(m.group(0)):02x}", name)


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
        # (the vector lane ops, and MMX's and 3DNow!'s, the helpers a macro makes)
        names |= set(re.findall(r"(?<!define )\bGEN_(?:VLANES|MM_W|3DN_F|3DN_CMP)\(\s*([A-Za-z_]\w*)", text))
        _header_names = names | HEADER_NAMES
    return _header_names
# where Ghidra maps the x86 fs segment (the TEB) of a 32-bit Windows program
TEB_LO, TEB_HI = 0xFFDFF000, 0xFFE00000
# imports whose adapters the runtime writes itself (their structures differ between x86 and x64):
# every gen_imp_<name> runtime32's sources define (a project listing them too would be a duplicate
# symbol otherwise), and rhipper.json "import_overrides" for a project's own
# (each with the return type the runtime gives it: div's 8-byte structure in edx:eax as an
# `unsigned long long`, strtod's double, rhtest crt 2026-10-24)
OVERRIDE_RET = {
    n: t for f in (Path(__file__).resolve().parent / "runtime32").glob("*.cpp")
    for t, n in re.findall(r"(?m)^\s*(?:extern \"C\"\s+)?(unsigned int|unsigned long long|double|float) gen_imp_(\w+)\s*\(",
                           f.read_text(encoding="utf-8"))}
OVERRIDES = set(project.CONFIG.get("import_overrides", [])) | set(OVERRIDE_RET)
# (and functions the project writes itself, rhipper.json "own_functions" {address: why}: declared in
# translated.h as the translation would, defined by the project's sources, no stub of their own.
# The C runtime's x87 internals with several results in registers at once, which no prototype the
# decompiler takes holds, 2026-10-30)
# (each a reason, or {"why": .., "decl": "<its prototype>"} where the project's definition returns
# what the facts give no type for: an x87 fragment ending in its dispatcher's exit, its st0 a result)
OWN_DECL = {int(k, 16): v["decl"] for k, v in project.CONFIG.get("own_functions", {}).items()
            if isinstance(v, dict) and v.get("decl")}
OWN = {int(k, 16): (v.get("why", "") if isinstance(v, dict) else v)
       for k, v in project.CONFIG.get("own_functions", {}).items()}
IDENT = r"[A-Za-z_~][\w$@]*(?:::[A-Za-z_~][\w$@]*)*"
# the C runtime's math imports, typed: their floats pass and return as floats (the integer adapter
# returned fabs's double as the int in eax, rhtest float-Od dabs, 2026-10-24). Pointers are the
# reference's, below 2 GB.
_D1 = ("double", ["double"])
_F1 = ("float", ["float"])
MATH = {
    **{n: _D1 for n in ("fabs", "sqrt", "sin", "cos", "tan", "asin", "acos", "atan", "sinh", "cosh",
                        "tanh", "exp", "exp2", "expm1", "log", "log10", "log2", "log1p", "floor", "ceil",
                        "trunc", "round", "rint", "nearbyint", "cbrt", "erf", "erfc", "tgamma", "lgamma")},
    **{n + "f": _F1 for n in ("fabs", "sqrt", "sin", "cos", "tan", "asin", "acos", "atan", "sinh", "cosh",
                              "tanh", "exp", "exp2", "log", "log10", "log2", "floor", "ceil", "trunc",
                              "round", "cbrt")},
    **{n: ("double", ["double", "double"]) for n in ("pow", "atan2", "fmod", "hypot", "_hypot", "fmin",
                                                     "fmax", "copysign", "_copysign", "remainder", "nextafter")},
    **{n: ("float", ["float", "float"]) for n in ("powf", "atan2f", "fmodf", "hypotf", "_hypotf", "fminf",
                                                  "fmaxf", "copysignf", "_copysignf")},
    "ldexp": ("double", ["double", "int"]), "frexp": ("double", ["double", "int *"]),
    "modf": ("double", ["double", "double *"]), "_chgsign": _D1, "_logb": _D1,
    "lround": ("long", ["double"]), "lrint": ("long", ["double"]),
    "llround": ("long long", ["double"]), "llrint": ("long long", ["double"]),
    "ilogb": ("int", ["double"]), "_finite": ("int", ["double"]), "_isnan": ("int", ["double"]),
    # (and the bit intrinsics /Od calls in the CRT, not inline: a 64-bit one returns edx:eax, its
    # high half lost through the untyped adapter, rhtest misc-Od's swap64)
    "_byteswap_uint64": ("unsigned long long", ["unsigned long long"]),
    "_byteswap_ulong": ("unsigned long", ["unsigned long"]),
    "_byteswap_ushort": ("unsigned short", ["unsigned short"]),
    "_rotl64": ("unsigned long long", ["unsigned long long", "int"]),
    "_rotr64": ("unsigned long long", ["unsigned long long", "int"]),
    "_rotl": ("unsigned int", ["unsigned int", "int"]), "_rotr": ("unsigned int", ["unsigned int", "int"]),
    "_lrotl": ("unsigned long", ["unsigned long", "int"]), "_lrotr": ("unsigned long", ["unsigned long", "int"]),
}
WIDE_INTS = ("unsigned long long", "long long")


def math_params(n: str) -> tuple[list[str], list[str]]:
    """An import's adapter parameters and the real function's arguments made of them: an 8-byte
    integer is two words, low then high, as ApplyFacts' splitWideImportArgs32 has every import's
    (`_byteswap_uint64(param_1,param_2)`, too many arguments for the adapter, rhtest
    msvc-14.51-x86 misc-Od swap64 2026-10-25)."""
    params, args = [], []
    for k, p in enumerate(MATH[n][1]):
        if p in WIDE_INTS:
            params += [f"unsigned int a{k}lo", f"unsigned int a{k}hi"]
            args.append(f"({p})(((unsigned long long)a{k}hi << 32) | a{k}lo)")
        else:
            params.append(f"{p} a{k}")
            args.append(f"a{k}")
    return params, args


# the C runtime's and Winsock's type names Ghidra uses, at the reference's widths (intptr_t and
# size_t are 32-bit there; the host's would be 8 bytes)
TYPE_ALIASES = {
    "size_t": "gen_size32", "rsize_t": "gen_size32", "ptrdiff_t": "gen_ptrdiff32", "intptr_t": "int",
    "uintptr_t": "uint", "errno_t": "int", "wint_t": "ushort", "wctype_t": "ushort", "u_short": "ushort",
    "u_long": "ulong", "u_int": "uint", "u_char": "uchar", "__uint64": "ulonglong", "_locale_t": "void *",
    "time_t": "__time64_t", "__time32_t": "int", "LPCH": "LPSTR", "LPWCH": "LPWSTR", "PCHAR": "LPSTR",
    # the CRT's initializer function types (_initterm's tables)
    "_PVFV": "code *", "PVFV": "code *", "_PIFV": "code *", "PIFV": "code *",
    # (an exception handler's result, an enum: the /MT CRT's CatchGuardHandler and
    # TranslatorGuardHandler, rhtest msvc-16.00-x86 cpp and eh 2026-10-25)
    "_EXCEPTION_DISPOSITION": "int", "EXCEPTION_DISPOSITION": "int",
}
# the return types narrower than eax, by the unsigned type of their width (emit's jump wrappers)
NARROW_RETS = {t: "unsigned char" for t in ("byte", "uchar", "char", "bool", "undefined1", "sbyte", "int1", "uint1")}
NARROW_RETS.update({t: "unsigned short" for t in ("ushort", "short", "undefined2", "wchar_t", "word", "int2", "uint2", "wchar16")})
_ALIAS = re.compile(r"\b(" + "|".join(TYPE_ALIASES) + r")\b")
# Windows' pointer typedefs Ghidra spells from its type library (LPCRITICAL_SECTION, PBYTE,
# LPSECURITY_ATTRIBUTES, PEXCEPTION_RECORD, ...): 4-byte pointers, as LPVOID is (Ghidra32.h)
_WINPTR = re.compile(r"\b(?!PTR_)(?:LP|P)C?[A-Z]+(?:_[A-Z]+)*\b")


_LITERAL = re.compile(r'L?"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)+\'')


def alias_types(text: str) -> str:
    # (outside string and character literals: the C runtime's `__dupenv_s(&p, 0, "PATH")` passed
    # "GEN_LPANY", PATH a P and capitals, and _spawnvpe searched no path, 2 of a client's)
    parts = []
    i = 0
    for m in _LITERAL.finditer(text):
        parts.append(_alias_code(text[i:m.start()]))
        parts.append(m.group(0))
        i = m.end()
    parts.append(_alias_code(text[i:]))
    return "".join(parts)


def _alias_code(text: str) -> str:
    text = _ALIAS.sub(lambda m: TYPE_ALIASES[m.group(1)], text)
    # (not a name Ghidra32.h defines: POPCOUNT is a P and capitals too, and popcount's
    # `POPCOUNT(x)` became a call of a pointer type, rhtest misc-O2 2026-10-24)
    return _WINPTR.sub(lambda m: m.group(0) if m.group(0) in KNOWN_TYPES or m.group(0) in HEADER_NAMES
                       else "GEN_LPANY", text)


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


def out_stack(body: str, alloca: bool = False, eh: bool = False) -> str:
    """An object passed by value, as MSVC passes one: the caller reserves room below its locals,
    builds the object there in place (`FUN_0042cc20(&stack0xffffeffc, ...)`, a string's
    constructor), and calls, the room now the callee's stack arguments, which Ghidra shows as
    `in_stack_ffffeffc, in_stack_fffff000, ...` (FUN_00415b00's log tab names, 2026-10-23). The
    room is one block: a local buffer here, each offset into it at its distance from the lowest."""
    offs = sorted({int(m.group(1), 16) for m in re.finditer(r"\b" + OUT_STACK.pattern + r"\b", body)})
    if not offs:
        return body
    # (and a local the decompiler named by a slot in that room, `uStack_14` beside a constructor's
    # `&stack0xffffffec`: one word, the tuple Od's map insert builds in place and passes, read
    # back as uStack_14. Apart, the constructor wrote gen_out and the call passed the garbage the
    # local held, a map node's key copied from nowhere, rhtest stl-Od)
    # (all of a run of them, each next to the room as it grows: a 0x54-byte string built in place
    # and passed by value, words 2..20 the decompiler's uStack_58..uStack_10. One word beyond the
    # room alone, the rest were locals the constructor never wrote and the call passed garbage, its
    # length 0xffffffff on Android, FUN_0043d1b0's hotbar names (the Android session's find,
    # 2026-11-01); and gen_out only 8 bytes, the constructor's other 0x4c ran over its neighbours)
    named = {}
    cands = {}
    if not has_frame(body) and not eh:
        for m in re.finditer(r"(?m)^\s*(?!return\b)([A-Za-z_][^;=()\n]*?[\s*]+)(\w+Stack_([0-9a-f]{1,7}))\s*;", body):
            cands[m.group(2)] = (m.group(1).strip(), (1 << 32) - int(m.group(3), 16))
    lo_r, hi_r = offs[0], offs[-1]
    grew = True
    while grew:
        grew = False
        for n, (t, off) in cands.items():
            if n not in named and lo_r - 4 <= off <= hi_r + 4:
                named[n] = (t, off)
                lo_r, hi_r = min(lo_r, off), max(hi_r, off)
                grew = True
    if named:
        offs = sorted(set(offs) | {off for _, off in named.values()})
        for n, (t, off) in named.items():
            body = re.sub(r"(?m)^\s*[A-Za-z_][^;=()\n]*?[\s*]+" + n + r"\s*;\s*\n", "", body)
            body = re.sub(r"\b" + n + r"\b", f"in_stack_{off:08x}", body)
            body = body.replace("{", "{\n  " + t + " in_stack_%08x;" % off, 1)
    # (in a function whose frame frame_locals lays out, the same frame: each place GEN_SLOT(d),
    # d bytes below the entry esp, which frame_locals puts in its buffer. As a buffer of its own
    # it lay wherever the compiler put it: rhtest's put_u writes its digits from `&stack0xffffffef
    # + k`, one below its char array local_10, and its 4-byte gen_out took eleven, the caller's
    # locals the rest, 2026-10-24)
    # (and one that links an EH frame, whose whole frame frame_locals lays out whatever it takes the
    # address of: VS2010's fflush hands its __finally `&stack0xfffffffc`, its ebp, and as a gen_out
    # of its own the funclet read the stream from garbage, rhtest msvc-16.00-x86 crt)
    framed = has_frame(body) or eh
    lo, hi = offs[0], offs[-1] + 4
    # (in a function that allocates on its stack, where the decompiler lost the size: _malloca's
    # buffer is `&stack0xffffffe8` as it is, no `+ iVar5` below it. The reference's lies below the
    # frame, as long as asked: the bottom of frame_locals' room for it, GEN_LOW, each place at its
    # distance from the lowest. As a 0x18-byte gen_out, __crtGetStringTypeA_stat's wide string ran
    # over GetStringTypeW's output pointer, a VS2010 client 2026-10-24)
    low = alloca and not re.search(r"stack0xf[0-9a-f]{7}\s*\)?\s*[+-]\s*\(?\s*[A-Za-z_]", body)

    def place(off: int) -> str:
        if low:
            return f"GEN_LOW(0x{off - lo:x})"
        return f"GEN_SLOT(0x{(1 << 32) - off:x})" if framed else f"(gen_out + 0x{off - lo:x})"
    # (their declarations go: each is a place in the buffer now, of its declared type, a pointer
    # stored as the reference stores one)
    types = {}
    # (a template's type too, `allocator<char> *in_stack_fffffff4;`, rhtest stl-Od)
    for m in re.finditer(r"(?m)^\s*([A-Za-z_][^;=()\n]*?[\s*]+)in_stack_(f[0-9a-f]{7})\s*;", body):
        t = m.group(1).strip()
        stars = t.count("*")
        base = t.replace("*", "").strip()
        # (a C++ type, C has none of: its bytes)
        if re.search(r"[<>:]", base):
            base, t = "undefined", "undefined" + " *" * stars if stars else "undefined4"
        # (a function pointer stored: gen_code32, as code_slots makes every one)
        types[m.group(2)] = "gen_code32" if base == "code" and stars == 1 else \
            (base + " * PTR32" * stars) if stars else t
    body = re.sub(r"(?m)^\s*[A-Za-z_][^;=()\n]*?[\s*]+in_stack_f[0-9a-f]{7}\s*;\s*\n", "", body)
    body = re.sub(r"&\s*stack0x(f[0-9a-f]{7})\b", lambda m: place(int(m.group(1), 16)), body)
    # (and the place itself, a word of the frame no local covers that the decompiler names bare:
    # strings()'s inlined strcpy at /O2 writes `stack0xffffffa0 = 0x78787878;` past its char[5],
    # rhtest msvc-16.00-x86 crt-O2)
    body = re.sub(r"(?<![\w&])stack0x(f[0-9a-f]{7})\b",
                  lambda m: f"(*(undefined4 *){place(int(m.group(1), 16))})", body)
    body = re.sub(r"\(uint\)\s*(\(gen_out|GEN_SLOT|GEN_LOW)", r"(uint)(uintptr_t)\1", body)
    body = re.sub(r"\bin_stack_(f[0-9a-f]{7})\b",
                  lambda m: f"(*({types.get(m.group(1), 'undefined4')} *){place(int(m.group(1), 16))})", body)
    if framed or low:
        return body
    return body.replace("{", "{\n  undefined1 gen_out[0x%x];" % (hi - lo), 1)


# the byte-array sizes Ghidra32.h has a gen_v<n> for (`undefined1 (*p) [12]`, a vector of three floats)
V_SIZES = "8|12|16|24|32|48|64"


def fastfail_dead(c: str) -> str:
    if "swi(0x29)" not in c:
        return c
    lines = c.split("\n")
    out, i = [], 0
    while i < len(lines):
        out.append(lines[i])
        m = re.fullmatch(r"\s*\(\*(\w+)\)\(\);\s*", lines[i])
        if m and any(re.fullmatch(rf"\s*{m.group(1)} = \(code \*\)swi\(0x29\);\s*", l) for l in lines[max(0, i - 3):i]):
            j = i + 1
            # (the copies of a register the decompiler lost only, `iVar4 = extraout_ECX;`: the
            # `int3` the reference has after it, `pcVar3 = (code *)swi(3); (*pcVar3)();`, stays,
            # its trap the reference's code too)
            while j < len(lines) and re.fullmatch(r"\s*[A-Za-z_]\w* = (?:extraout|unaff|in)_\w+;\s*", lines[j]):
                j += 1
            i = j
            continue
        i += 1
    return "\n".join(out)


def cpu_state(c: str) -> str:
    """Processor state Ghidra reads as a lost register that the host has as an intrinsic: XCR0
    (xgetbv, ecx = 0; the CRT's __isa_available_init, whose result picks /O2's vector paths),
    without AVX-512's state, as Ghidra32.h's gen_cpuid reports none."""
    # (and an SSE value's low 12 bytes zeroed, `auVar9._0_12_ = ZEXT812(0);`, the upper lane
    # set apart: no C type is 12 bytes, so their bytes. Havok's vector code in a client, 10
    # functions, 2026-10-27)
    c = re.sub(r"(?m)^([ \t]*)(\w+)\._0_12_\s*=\s*ZEXT812\(0\);", r"\1memset(&\2, 0, 12);", c)
    # (and the statements after a __fastfail, `pcVar2 = (code *)swi(0x29); (*pcVar2)();`, up to the
    # next label or block end: no code runs there, the process ends. The decompiler goes on as if
    # the trap returned, `iVar4 = extraout_ECX;` into the code after it, a register it lost,
    # std::vector's _Xlength path in rhtest stl /MT)
    c = fastfail_dead(c)
    if "in_XCR0" not in c:
        return c
    c = re.sub(r"(?m)^[ \t]*\w+ in_XCR0;\n", "", c)
    return re.sub(r"\bin_XCR0\b", "GEN_XCR0()", c)


def v16_forms(c: str) -> str:
    """An SSE register's 16 bytes as C can have them (Ghidra32.h gen_v16): `undefined1 (*p) [16]`
    a `gen_v16 *` (a pointer to the 16-byte array, stepping 16 and indexing its bytes), and a
    value stored into one, `*p = (undefined1 [16])0x0;`, GEN_V16_SET. __VEC_memzero, the CRT
    memset's path for large zero fills, is written so (2026-10-23)."""
    # (a unary MMX or 3DNow! op's first operand, the destination as it was, which the op ignores
    # (ia.sinc's `mmxreg = op(mmxreg, m64)`): a lost register there is no input, Ghidra32.h's helper
    # takes 0. POP.EXE's 3DNow! math library, sands3 2026-11-01)
    c = re.sub(r"\b(FloatingReciprocalAprox|PackedFloatingReciprocalSQRAprox|PackedIntToFloatingDwordConv|"
               r"PackedFloatingToIntDwordConv|PackedIntToFloatingWord|PackedFloatingToIntWord|PackedSwapDWords)"
               r"\(\s*in_MM\d+\s*,", r"\1(0,", c)
    # (and a port write, `out(port, v);`, Ghidra32.h's gen_port_out: a macro named `out` would take
    # every other `out`, std::codecvt's out() among them)
    c = re.sub(r"(?m)^([ \t]*)out\((.*)\);", r"\1gen_port_out(\2);", c)
    # (and a pointer to one stored, `*(undefined1 (**) [16])((int)this + 0x10)`: the stored pointer
    # 4 bytes, as the reference stores one. Read as a host pointer, 8 bytes, the memset of a VS2010
    # client's 0xb16250 wrote through its neighbour's bits above 4 GB, 2026-10-27)
    c = re.sub(r"\bundefined1\s*\(\s*\*\s*\*\s*([A-Za-z_]\w*)\s*\)\s*\[\s*(" + V_SIZES + r")\s*\]",
               r"gen_v\2 * PTR32 * \1", c)
    c = re.sub(r"\(\s*undefined1\s*\(\s*\*\s*\*\s*\)\s*\[\s*(" + V_SIZES + r")\s*\]\s*\)", r"(gen_v\1 * PTR32 *)", c)
    c = re.sub(r"\bundefined1\s*\(\s*\*\s*([A-Za-z_]\w*)\s*\)\s*\[\s*(" + V_SIZES + r")\s*\]", r"gen_v\2 * \1", c)
    c = re.sub(r"\(\s*undefined1\s*\(\s*\*\s*\)\s*\[\s*(" + V_SIZES + r")\s*\]\s*\)", r"(gen_v\1 *)", c)
    # (and a function's return type, `undefined1 (*) [32]` on the line before its name)
    c = re.sub(r"(?m)^undefined1\s*\(\s*\*\s*\)\s*\[\s*(" + V_SIZES + r")\s*\]", r"gen_v\1 *", c)
    # (a zeroed register's piece stored into a local's, `local_860._4_12_ = SUB1612((undefined1
    # [16])0x0,4);`: those bytes zero. 2 of a client's large-frame initializers)
    c = re.sub(r"(?m)^([ \t]*)([A-Za-z_]\w*)\._(\d+)_(\d+)_\s*=\s*SUB16\d+\(\s*\(\s*undefined1\s*\[\s*16\s*\]\s*\)\s*0x0\s*,\s*\d+\s*\);",
               r"\1memset((char *)&\2 + \3, 0, \4);", c)
    # (or a whole local, `stack0xffffffb4 = SUB1612(..)`, its N bytes)
    c = re.sub(r"(?m)^([ \t]*)([A-Za-z_]\w*)\s*=\s*SUB16(\d+)\(\s*\(\s*undefined1\s*\[\s*16\s*\]\s*\)\s*0x0\s*,\s*\d+\s*\);",
               r"\1memset(&\2, 0, \3);", c)
    # (a value into a small array, `auVar6 = (undefined1 [4]) gen_fl2bits(x);`: its bytes, the
    # array's size. A float's bits kept for an SSE op, 0xd473c0)
    def small_array(m):
        n = int(m.group(3))
        t = {4: "unsigned int", 8: "unsigned long long"}[n]
        ind = m.group(1)
        return (f"{ind}{{\n{ind}  {t} gen_sa = ({t})({m.group(4)});\n"
                f"{ind}  memcpy(&{m.group(2)}, &gen_sa, {n});\n{ind}}}")
    c = re.sub(r"(?m)^([ \t]*)([A-Za-z_]\w*)\s*=\s*\(\s*undefined1\s*\[\s*([48])\s*\]\s*\)\s*([^;]+);[ \t]*$", small_array, c)
    c = re.sub(r"(?m)^([ \t]*)([^=;\n{}]+?)\s*=\s*\(\s*undefined1\s*\[\s*16\s*\]\s*\)\s*([^;\n]+);[ \t]*$",
               r"\1GEN_V16_SET(\2, \3);", c)
    # (the first bytes of one, `*(undefined1 (*) [12])*(undefined1 (*) [16])(pfVar25 + 8)`: those
    # bytes where it is, C's inner `*` being the whole array, FUN_00d5c7e0 in a VS2010 client 2026-10-25)
    c = re.sub(r"\*\s*\(\s*(gen_v\d+)\s*\*\s*\)\s*\*\s*\(\s*gen_v\d+\s*\*\s*\)", r"*(\1 *)", c)
    # (a function returning one, protos32's "v16", `undefined1 [16] FUN_00666280(...)`: C returns no
    # array, so its value as gen_r16, an __m128 in xmm0 as the reference's. Each `return auVar3;`
    # stores into a 16-byte local of its own, which the copies and pseudo-ops below take, and returns
    # that, GEN_R16. 0x666280's rsqrtps, typed uint before, its body lost, 2026-10-30)
    if re.search(r"(?m)^undefined1\s*\[\s*16\s*\][ \t\n]", c.split("{", 1)[0]):
        c = re.sub(r"\{[ \t]*\n", "{\n  undefined1 gen_rv16 [16];\n", c, count=1)
        c = re.sub(r"(?m)^([ \t]*)return\s+([^;]+);",
                   lambda m: f"{m.group(1)}gen_rv16 = {' '.join(m.group(2).split())};\n"
                             f"{m.group(1)}return GEN_R16(gen_rv16);", c)
    # (and one copied whole, `auVar1 = *(gen_v16 *)p;`, `*p = auVar1;`: 16 bytes)
    arrays = set(re.findall(r"(?m)^[ \t]+undefined1\s+([A-Za-z_]\w*)\s*\[\s*(?:" + V_SIZES + r")\s*\]\s*;", c))
    ptrs = set(re.findall(r"\bgen_v\d+\s*\*\s*([A-Za-z_]\w*)", c))

    def v16(e: str) -> bool:
        e = e.strip()
        return e in arrays or bool(re.match(r"\*\s*\(\s*gen_v(?:" + V_SIZES + r")\s*\*\s*\)", e)) \
            or any(re.fullmatch(r"\*\s*" + p + r"|" + p + r"\s*\[[^\]]+\]", e) for p in ptrs)

    # (and a call's into a 16-byte local, `auVar1 = FUN_00666280(param_1);`: the callee's gen_r16
    # stored there, GEN_R16_SET. A bare call is assigned a 16-byte array only for a 16-byte result,
    # a narrower one the decompiler widens, ZEXT, 2026-10-30)
    c = re.sub(r"(?m)^([ \t]*)([^=;\n{}()]+?)\s*=\s*((?:thunk_)?FUN_[0-9a-f]{8}\s*\([^;\n]*\));[ \t]*$",
               lambda m: f"{m.group(1)}GEN_R16_SET({m.group(2).strip()}, {m.group(3)});"
               if v16(m.group(2)) else m.group(0), c)

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
    # (and the AVX2 and SSE4.2 pseudo-ops, pieces and operators on whole vectors, vec32.py)
    return vec32.vec_forms(sse_ops(c, arrays, v16))


SSE_OPS = {"minps", "maxps", "divps", "rsqrtps", "rcpps", "sqrtps", "packssdw", "psllw", "pmulld", "vpsllvd_avx2",
           # (MSVC 14.51's float to u64, AVX-512VL behind __isa_available, rhtest msvc-14.51-x86 fpenv)
           "vcvttps2qq_avx512vl",
           # (the scalar approximations, the destination's upper lanes kept: POP.EXE's math, 12 stubs,
           # sands3 2026-11-01)
           "rsqrtss", "rcpss"}
SSE_BITS = {"|": "or", "&": "and", "^": "xor"}
# (the ones on integer lanes)
SSE_INT_OPS = {"packssdw", "psllw", "pmulld", "vpsllvd_avx2", "vcvttps2qq_avx512vl"}
# (the ones whose helper takes the source alone, gen_x(r, a))
SSE_UNARY = {"vcvttps2qq_avx512vl"}


def sse_ops(c: str, arrays: set[str], v16) -> str:
    """Ghidra's SSE pseudo-ops as Ghidra32.h's helpers: `auVar9 = rsqrtps(in_XMM3, auVar1);` ->
    `gen_rsqrtps(&(auVar9), &(in_XMM3), &(auVar1));`, a vector `a | b` operand computed into a
    temporary before its statement, `movmskps(r, v)` the int `gen_movmskps(&(v))` wherever it is.
    A full xmm register the decompiler lost (`in_XMM3`, the pseudo-op's destination as it found it,
    ignored by the unary ones) a zeroed 16-byte local. 273 functions, the game's vector math,
    were stubs (2026-10-23)."""
    if not re.search(r"\b(?:" + "|".join(SSE_OPS | {"movmskps"}) + r")\(", c) and "in_XMM" not in c:
        return c
    # (a statement with one of them wrapped onto the next lines, as Ghidra breaks a long call: one
    # line again, rhtest misc-O2's `vpsllvd_avx2(*(gen_v16 *)(...),\n auVar3);`)
    ops_re = re.compile(r"\b(?:" + "|".join(SSE_OPS | {"movmskps"}) + r")\(")
    joined: list[str] = []
    for line in c.split("\n"):
        if joined and ops_re.search(joined[-1]) and joined[-1].count("(") > joined[-1].count(")"):
            joined[-1] = joined[-1].rstrip() + " " + line.strip()
        else:
            joined.append(line)
    lines = joined
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
            # (not an `&` that takes an address: after a cast, `*(gen_v16 *)&REFG(...)`, the
            # decompiler's `*(undefined1 (*) [16])&DAT_004033e0`, or an operator, rhtest crt-O2)
            left = ps[0].strip() if len(ps) == 2 else ""
            if op == "&" and (not left or re.search(r"\(\s*[A-Za-z_][\w ]*\*[\s*]*\)\s*$|[-+*/&|^~!(,]\s*$", left)):
                continue
            if len(ps) == 2 and not left.endswith("&") and ps[1].strip():
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
        # (a value widened to the 16 bytes, `maxps(ZEXT816(0),auVar10)`: its low 8 bytes, the rest 0)
        m = re.fullmatch(r"ZEXT(?:[1248])16\((0x[0-9a-f]+|\d+)\)", e)
        if m:
            return f"(&(unsigned long long[2]){{{m.group(1)}, 0}})"
        # (or an expression's, `ZEXT416((uint)gen_fl2bits(x))`: a float in the low lane, a scalar
        # op's operand, the rest 0; 4 of a client's vector normalizations)
        m = re.fullmatch(r"ZEXT([48])16\((.*)\)", e, re.S)
        if m and match_paren(e, e.index("(")) == len(e):
            if m.group(1) == "4":
                return f"(&(unsigned int[4]){{(unsigned int)({m.group(2)}), 0, 0, 0}})"
            return f"(&(unsigned long long[2]){{(unsigned long long)({m.group(2)}), 0}})"
        # (a 16-byte global through the decompiler's cast, `*(undefined1 (*) [16])&DAT_01138af0`)
        m = re.fullmatch(r"\*\s*\(\s*undefined1\s*\(\s*\*\s*\)\s*\[\s*16\s*\]\s*\)\s*&\s*(_*(?:DAT|UNK)_[0-9a-f]{8})", e)
        if m:
            return f"&({m.group(1)})"
        # (16 bytes read through an address, `*(undefined1 (*) [16])(&stack0xffffffe8 + i * 4)`: the
        # address, rhtest misc-O2's vpsllvd over an alloca'd buffer)
        m = re.fullmatch(r"\*\s*\(\s*(?:undefined1\s*\(\s*\*\s*\)\s*\[\s*16\s*\]|gen_v16\s*\*)\s*\)\s*(\(.*\))", e, re.S)
        if m and match_paren(m.group(1), 0) == len(m.group(1)):
            # (an address Ghidra computed as an int, `((int)&local_8 + i)`, a pointer again)
            return f"GP{m.group(1)}" if re.match(r"\(\s*\(\s*u?int\s*\)", m.group(1)) else m.group(1)
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
        # (one whose result nothing keeps, `rsqrtps(in_XMM2,*param_1);`: the op has no other
        # effect, so nothing to do; the lost destination register goes with it)
        if not sm and re.fullmatch(r"[ \t]*(?:" + "|".join(SSE_OPS) + r")\(.*\);[ \t]*", line):
            line = ind + ";"
            sm = None
        if sm:
            args = split_top(sm.group(4))
            dst = operand(sm.group(2), pre)
            ops = [operand(x, pre) for x in args]
            # (the destination as it was, which rsqrtps, rcpps and sqrtps ignore (Ghidra32.h): any
            # 16 bytes when the decompiler's is a lost register or an expression)
            if sm.group(3) in ("rsqrtps", "rcpps", "sqrtps") and len(ops) == 2 and ops[0] is None:
                ops[0] = "(&(unsigned long long[2]){0, 0})"
            if sm.group(3) in SSE_UNARY and dst is not None and ops and None not in ops:
                # (a conversion of its source alone, whatever destination the decompiler adds)
                line = f"{sm.group(1)}gen_{sm.group(3)}({dst}, {ops[-1]});"
            elif dst is not None and len(ops) == 2 and None not in ops:
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


# (and ApplyFacts' object blocks, blk_N, N below the entry too: as a C local of its own, nested()'s
# Guards were nowhere its unwind funclets look through ebp, rhtest eh 2026-10-24). Not a variable's
# name as the type: a wrapped expression's last line, `fVar34 * local_90;`, is no declaration
# (FUN_00d657d0 in a VS2010 client 2026-10-25)
# (the stack name's prefix is its type, any case: `aCStack_1a8` an array of CHAR. Lowercase only,
# a DISPLAY_DEVICEA's DeviceName at +4 of the block a function fills was a C array of its own, and
# CreateDCA got an unwritten name, a VS2010 client's 0xb1b020 2026-10-25)
# (and Ghidra's StackY names, the same frame offsets below the entry esp (StackX ones are above it,
# the arguments', and stay out): 0x4b0a00's `aiStackY_94[type] = p`
# fills, for the types it takes, the seven locals above it, `[ebp + edx*4 - 0x90]` over local_20..
# local_8. As a C array of its own a lobby VFX's animation tracks were never bound, 2026-10-28)
# (and a prefix as long as the type's pointer levels make it, `ppppppuStack_30`: as a C local of its
# own, a std::string's capacity the callee wrote through the object's address was never seen, and
# its destructor took the stale one for a large buffer's, a fail-fast, rhtest stl /MT)
FRAME_LOCAL =r"(?:local|[A-Za-z]{0,16}StackY?|blk)_([0-9a-f]+)"
FRAME_DECL = re.compile(r"(?m)^[ \t]+(?!(?:return|goto|case|else|do)\b)(?!(?:local|[A-Za-z]{0,16}StackY?|blk)_[0-9a-f]+\b)"
                        r"(?![a-z]{1,4}Var\d+\b)(?!(?:param|in|unaff|extraout)_\w+\b)"
                        r"((?:struct\s+)?[A-Za-z_]\w*(?:[ \t]+[A-Za-z_]\w*)*?(?:[ \t]*\*(?:[ \t]*PTR32)?)*)"
                        r"[ \t]*\b(" + FRAME_LOCAL + r")[ \t]*(\[[ \t]*(?:0x)?[0-9a-f]+[ \t]*\])?[ \t]*;[ \t]*\n")


FP_STATUS = re.compile(r"\bgen_imp__*(?:statusfp2?|clearfp|status87|clear87|fetestexcept|feclearexcept|"
                       r"fegetexceptflag|feholdexcept|feupdateenv)\s*\(")


def fp_status_volatile(body: str) -> str:
    """A function that reads or clears the floating-point status flags (_statusfp, fetestexcept):
    its floating-point locals and frame slots volatile. What it computes is for the flags as much
    as the value, `_clearfp(); r = big * 10; _statusfp() & _SW_OVERFLOW`: a store nothing reads,
    and the host compiler dropped it and its multiply, the overflow never raised (rhtest fpenv;
    the decompiler keeps it now, coreaction.cc)"""
    # (and in any function, a local only ever assigned, its value floating-point work: kept by the
    # decompiler for its flags, coreaction.cc, `iVar4 = (int)-NAN;`, __ftol3's raise of the
    # invalid flag, which the host compiler drops as a dead store)
    write_only = set()
    for m in re.finditer(r"(?m)^([ \t]+)((?:unsigned\s+)?[A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s*;[ \t]*$", body):
        name = m.group(3)
        uses = [u for u in re.finditer(rf"(?<![\w$.>]){re.escape(name)}(?![\w$])", body) if u.start() != m.start(3)]
        assigns = list(re.finditer(rf"(?m)^[ \t]*{re.escape(name)}\s*=(?!=)\s*([^;]+);", body))
        if not uses or len(uses) != len(assigns):
            continue
        if any(re.search(r"\bNAN\b|REFG\((?:float|double),|\((?:float|double|float10)\s*\*?\s*\)|gen_bits2[df]|\d\.\d", a.group(1))
               for a in assigns):
            write_only.add(name)
    if write_only:
        body = re.sub(r"(?m)^([ \t]+)((?:unsigned\s+)?[A-Za-z_]\w*\s+(" + "|".join(map(re.escape, write_only)) + r")\s*;)",
                      r"\1volatile \2", body)
    if not FP_STATUS.search(body):
        return body
    body = re.sub(r"(?m)^([ \t]+)((?:double|float|float10)\s+[A-Za-z_]\w*\s*;)", r"\1volatile \2", body)
    return re.sub(r"\(\s*(double|float|float10)\s*\*\s*\)\s*\(gen_frame\b", r"(volatile \1 *)(gen_frame", body)


X87_ARITH = {"fadd", "faddp", "fiadd", "fsub", "fsubp", "fsubr", "fsubrp", "fisub", "fisubr", "fmul", "fmulp",
             "fimul", "fdiv", "fdivp", "fdivr", "fdivrp", "fidiv", "fidivr", "fsqrt"}


def binary_arith(e: str) -> bool:
    """Whether e has a binary +, -, * or / outside its parentheses: an operator after an operand,
    not a dereference's `*` or a sign, nor `->`, `++`, `--`"""
    depth, prev, i = 0, "", 0
    while i < len(e):
        ch = e[i]
        if ch in "\"'":
            k = i + 1
            while k < len(e) and e[k] != ch:
                k += 2 if e[k] == "\\" else 1
            i, prev = k + 1, "x"
            continue
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif depth == 0 and ch in "+-*/" and re.fullmatch(r"[\w)\].]", prev or " ") \
                and e[i:i + 2] not in ("->", "++", "--") and not (ch in "+-" and e[i + 1:i + 2] == ch):
            return True
        if not ch.isspace():
            prev = ch
        i += 1
    return False


def x87_precision(body: str, var_types: dict[str, str], float_ret: bool, sqrt_only: bool = False) -> str:
    """An x87 function's results as its unit rounds them, by the control word's precision control,
    GEN_X87 (Ghidra32.h): each sqrt, each assignment of floating-point arithmetic to a double, and a
    floating return of it. Under _PC_24 the reference's `1.0 / 3.0` is a float's mantissa in a
    double, the port's the double's (rhtest fpenv's pc24; Direct3D's CreateDevice sets it, and a
    client computes in 24 bits from there). A value only loaded is exact either way: not rounded"""
    def arithmetic(e: str) -> bool:
        e = e.strip()
        while e.startswith("(") and match_paren(e, 0) == len(e):
            e = e[1:-1].strip()
        if e.startswith("-"):
            e = e[1:].lstrip()
        # (a cast of the whole, `(double)(a / b)`, the arithmetic inside it)
        m = re.match(r"\(\s*(?:double|float10|float)\s*\)\s*", e)
        if m:
            return arithmetic(e[m.end():])
        # (and a conversion helper's, `GEN_TOD(a / b)`)
        m = re.match(r"GEN_TO[DF]\(", e)
        if m and match_paren(e, m.end() - 1) == len(e):
            return arithmetic(e[m.end():-1])
        return binary_arith(e) or e.startswith("SQRT(")

    def floating(lhs: str) -> bool:
        s = lhs.strip()
        t = var_types.get(s, "").strip()
        return t in ("double", "float10") or bool(re.match(r"\(?\s*\*\s*\(\s*(?:double|float10)\s*\*\)|REFG\(double,", s))

    # (sqrt: the instruction's own result)
    out, i = [], 0
    for m in re.finditer(r"\bSQRT\(", body):
        if m.start() < i:
            continue
        end = match_paren(body, m.end() - 1)
        if end <= 0:
            continue
        out.append(body[i:m.start()])
        out.append(f"GEN_X87({body[m.start():end]})")
        i = end
    out.append(body[i:])
    body = "".join(out)
    if sqrt_only:
        return body

    def assign(m):
        lhs, rhs = m.group(2), m.group(3)
        if not floating(lhs) or rhs.strip().startswith("GEN_X87(") or not arithmetic(rhs):
            return m.group(0)
        return f"{m.group(1)}{lhs} = GEN_X87({rhs.strip()});"
    # (the right-hand side and a return's value over lines as the decompiler wraps them)
    body = re.sub(r"(?m)^([ \t]*)([^=;\n{}]+?)[ \t]*=[ \t]*([^=;\n][^;{}]*);[ \t]*$", assign, body)
    if float_ret:
        body = re.sub(r"(?m)^([ \t]*)return\s+([^;{}]+);[ \t]*$",
                      lambda m: f"{m.group(1)}return GEN_X87({m.group(2).strip()});"
                      if arithmetic(m.group(2)) and not m.group(2).strip().startswith("GEN_X87(") else m.group(0), body)
    return body


def math_import_args(body: str) -> str:
    """A typed math import's double parameter given the decompiler's 8-byte integer view of a
    double, `nearbyint((undefined8)gen_d2bits(x * 3))`: the double itself. Through the typed
    adapter the bits were converted by value, nearbyint of 4.6e18 (rhtest fpenv's rounding)"""
    out, i = [], 0
    for m in re.finditer(r"\bgen_imp_(\w+)\s*\(", body):
        if m.start() < i or m.group(1) not in MATH:
            continue
        open_ = m.end() - 1
        close = match_paren(body, open_)
        if close <= 0:
            continue
        inner = body[open_ + 1:close - 1]
        args = split_top(inner) if inner.strip() else []
        ptypes = MATH[m.group(1)][1]
        new_args = []
        for k, x in enumerate(args):
            x = math_import_args(x)
            s = x.strip()
            mm = re.fullmatch(r"\((?:undefined8|ulonglong|longlong)\)\s*(gen_d2bits\((.*)\))", s, re.S)
            if k < len(ptypes) and ptypes[k] == "double" and mm and match_paren(mm.group(1), len("gen_d2bits")) == len(mm.group(1)):
                x = f"({mm.group(2)})"
            # (or its 8 bytes read as an integer, `rint(*(undefined8 *)(&DAT + i * 8))`: read as the
            # double they are)
            elif k < len(ptypes) and ptypes[k] == "double" and re.match(r"\*\s*\((?:undefined8|ulonglong|longlong)\s*\*\)", s):
                x = re.sub(r"^\*\s*\((?:undefined8|ulonglong|longlong)\s*\*\)", "*(double *)", s)
            new_args.append(x)
        out.append(body[i:open_ + 1])
        out.append(",".join(new_args))
        out.append(")")
        i = close
    out.append(body[i:])
    return "".join(out)


def top_level(s: str, ops: str) -> bool:
    """Whether s has one of the characters ops outside its parentheses (and literals)"""
    depth, i = 0, 0
    while i < len(s):
        ch = s[i]
        if ch in "\"'":
            k = i + 1
            while k < len(s) and s[k] != ch:
                k += 2 if s[k] == "\\" else 1
            i = k + 1
            continue
        depth += {"(": 1, "[": 1, ")": -1, "]": -1}.get(ch, 0)
        if depth == 0 and ch in ops:
            return True
        i += 1
    return False


def shift_counts(body: str) -> str:
    """A 32-bit shift's count as the decompiler reads `shr r32, cl`, masked: `x >> (n & 0x1f)`,
    `1 << ((byte)k & 0x1f)`. The instruction masks it itself; in C the mask stays, the x86 build's
    `and ecx, 0x1f` before each shift the reference never had. GEN_SHC(masked, bare): the port's
    the mask as it is, the x86 fidelity build's the count bare (and its `(byte)` cast, cl, off)"""
    out, i = [], 0
    for m in re.finditer(r"(?:<<|>>) \(", body):
        if m.start() < i:
            continue
        start = m.end() - 1
        end = match_paren(body, start)
        if end <= start:
            continue
        inner = body[start + 1:end - 1]
        mm = re.fullmatch(r"(.+) & 0x1f", inner, re.S)
        # (the mask the group's last operator, nothing looser beside it: `a - b & 0x1f`, not
        # `a | b & 0x1f`)
        if not mm or top_level(mm.group(1), "&|^?,=") or "&&" in mm.group(1) or "||" in mm.group(1):
            continue
        count = mm.group(1).strip()
        # (a rotate's two halves, `x >> (-n & 0x1f) | x << (n & 0x1f)`, a count the body also
        # shifts by negated: masked, the compiler's `ror`, bare two shifts and an or)
        if count.startswith("-") or ("(-" + count + " & 0x1f)") in body or ("(-" + count + ") & 0x1f)") in body:
            continue
        # (the byte's variable as an integer: Ghidra types a register by its other uses, a pointer
        # here and there, C2297 in bytes32's x86 build, the C runtime's printf in rhtest stl /MT)
        bare = re.sub(r"^\(byte\)\s*([A-Za-z_]\w*)$", r"(unsigned int)(uintptr_t)\1", count)
        out.append(body[i:start])
        out.append(f"GEN_SHC({count}, {bare})")
        i = end
    out.append(body[i:])
    return "".join(out)


def binary_amp(body: str, at: int) -> bool:
    """Whether the `&` at `at` is the binary and, an operand before it (a name, a number, a
    subscript or a parenthesized expression), not the unary address-of: `a & b` no address,
    `(int)&b` (a cast) and `f(&b)` one"""
    before = body[:at].rstrip()
    if not before or not re.fullmatch(r"[\w)\]]", before[-1]):
        return False
    # (a cast's parenthesis, `(int)`, `(uint *)`, `(undefined4 * PTR32)`: the unary after it)
    return not re.search(r"\(\s*(?:(?:const|unsigned|signed|struct)\s+)*[A-Za-z_]\w*(?:\s*\*+)?"
                         r"(?:\s*PTR32(?:\s*\*+)?)*\s*\)\Z", before)


def has_frame(body: str) -> bool:
    """Whether frame_locals lays the function's frame out: its code takes a local's address or
    uses a local array."""
    # (the unary `&`: `uVar1 & local_8` takes no address)
    # (and one parenthesized, `&(local_24)`: the member access lvalue() writes for Ghidra's
    # `local_24.dwOemId`, a SYSTEM_INFO split into nine locals. Missed, they stayed C locals,
    # GetSystemInfo's 36 bytes ran over the x64 frame's saved rbx/rbp and the fields read back as
    # the 0 they were set to: sands3 FUN_0065a260, its PageManager stored as 0x10000, 2026-11-01)
    return bool(any(not binary_amp(body, m.start())
                    for m in re.finditer(r"(?<!&)&\s*(?:\(\s*)?" + FRAME_LOCAL + r"\b", body)) or
                re.search(r"(?m)^[ \t]+[A-Za-z_][\w \t*]*?\b" + FRAME_LOCAL + r"[ \t]*\[", body))


EH_LINK = re.compile(r"(?:\bExceptionList|gen_teb32\(\) \+ 0x0\)+)\s*=\s*&")
# a register's part to its whole (protos32's narrow register parameters, `cl`)
NARROW_FULL = {"al": "eax", "ax": "eax", "cl": "ecx", "cx": "ecx", "dl": "edx", "dx": "edx",
               "bl": "ebx", "bx": "ebx", "si": "esi", "di": "edi"}
# (the CRT's prologs that link the frame, injected: Ghidra's comment on the function)
EH_PROLOG = re.compile(r"replaced with injection: (?:rh_)?(?:SEH_prolog|EH_prolog)")


def eh_landing(body: str, ret: str) -> str:
    """Where the runtime's EH dispatcher comes back to a function that links an EH frame (Ghidra32.h
    GEN_EH_LAND): after each link, a setjmp on the node's landing; a catch done, or an __except
    filter taken, the dispatcher longjmps there and the function returns what the reference's
    continuation (a function on this frame's ebp) returns."""
    def land(m):
        node = "&" + m.group(2).strip()
        value = "(void)gen_eh_resume(); return 0;" if ret.strip() == "void" else \
            f"return ({ret})(uintptr_t)gen_eh_resume();"
        return (f"{m.group(0)}\n{m.group(1)}if (setjmp(*gen_eh_landing((unsigned int)(uintptr_t)({node})))) "
                f"{{ {value} }}")
    return re.sub(r"(?m)^([ \t]*)(?:\(\*\(\(void \* PTR32 \*\)GEN_TOP\(\(uintptr_t\)\(gen_teb32\(\) \+ 0x0\)\)\)\)|"
                  r"ExceptionList)\s*=\s*&([^;\n]+);[ \t]*$", land, body)


def idiv32(body: str) -> str:
    """`cdq; idiv r32` as the decompiler prints it, `(int)(A / (longlong)(int)(B))` of a 32-bit A: a
    32-bit division, gen_idiv32 (Ghidra32.h), so INT_MIN / -1 traps as the reference's idiv does,
    EXCEPTION_INT_OVERFLOW. In 64 bits it was 0x80000000 and no fault, and the reference's __except
    never ran (rhtest msvc-14.51-x86 seh-O2, 2026-10-27)."""
    out, i = [], 0
    pat = re.compile(r"\(int\)\(\s*(-?(?:0x[0-9a-f]+|\d+)|\(\(int\)0x[0-9a-f]+\)|\(int\)0x[0-9a-f]+|[A-Za-z_]\w*)"
                     r"\s*([/%])\s*\(longlong\)\(int\)\(")
    for m in pat.finditer(body):
        if m.start() < i:
            continue
        end = match_paren(body, m.end() - 1)          # just past the divisor's group
        if end <= 0 or end >= len(body) or body[end] != ")":
            continue
        divisor = body[m.end():end - 1]
        fn = "gen_idiv32" if m.group(2) == "/" else "gen_irem32"
        out.append(body[i:m.start()])
        out.append(f"{fn}((int)({m.group(1)}), (int)({divisor}))")
        i = end + 1
    out.append(body[i:])
    return "".join(out)


# Ghidra's integer types 3, 5, 6 or 7 bytes wide, which Ghidra32.h holds in the next wider C type
ODD_WIDTH = {f"{p}{n}": n for p in ("uint", "undefined", "int") for n in (3, 5, 6, 7)}
_ODD_CAST = re.compile(r"\(\s*(" + "|".join(ODD_WIDTH) + r")\s*\*\s*\)")
_ODD_PTR_DECL = re.compile(r"\b(" + "|".join(ODD_WIDTH) + r")\s*\*\s*([A-Za-z_]\w*)\s*(?=[=;,)])")


def _operand_end(body: str, i: int) -> int:
    """The end of a cast's operand starting at body[i]: a parenthesized group, `&` and an operand,
    or a name with its calls, subscripts and members (`GEN_TOP((p + 0x6e))`, `&REFG(T, a)`)."""
    while i < len(body) and body[i] in " \t\r\n":
        i += 1
    if i < len(body) and body[i] in "&*":
        return _operand_end(body, i + 1)
    if i < len(body) and body[i] == "(":
        return match_paren(body, i)
    m = re.compile(r"[A-Za-z_]\w*").match(body, i)
    if not m:
        return -1
    j = m.end()
    while True:
        k = j
        while k < len(body) and body[k] in " \t":
            k += 1
        if k < len(body) and body[k] == "(":
            j = match_paren(body, k)
        elif k < len(body) and body[k] == "[":
            d, j = 0, k
            while j < len(body):
                d += {"[": 1, "]": -1}.get(body[j], 0)
                j += 1
                if d == 0:
                    break
        elif body.startswith("->", k) or (k < len(body) and body[k] == "." and not body[k + 1:k + 2].isdigit()):
            m2 = re.compile(r"(?:->|\.)\s*[A-Za-z_]\w*").match(body, k)
            if not m2:
                return j
            j = m2.end()
        else:
            return j
        if j < 0:
            return -1


def _unary_at(body: str, at: int) -> bool:
    """Whether the `*` at `at` is a dereference: no operand before it (a name, a number, a
    subscript or a parenthesized expression), or one a cast's parenthesis closes, `(uint)*p`, or
    a `return`."""
    before = body[:at].rstrip()
    if not before or not re.fullmatch(r"[\w)\]]", before[-1]) or re.search(r"\breturn\Z", before):
        return True
    return bool(re.search(r"\(\s*(?:(?:const|unsigned|signed|struct)\s+)*[A-Za-z_]\w*(?:\s*\*+)?"
                          r"(?:\s*PTR32(?:\s*\*+)?)*\s*\)\Z", before)) and \
        is_type(before[before.rfind("("):])


def _value_end(body: str, i: int) -> int:
    """The end of an assignment's right side from body[i]: up to the `;`, `,` or unmatched `)`
    that ends it, at its own depth."""
    d = 0
    j = i
    while j < len(body):
        ch = body[j]
        if ch in "\"'":
            k = j + 1
            while k < len(body) and body[k] != ch:
                k += 2 if body[k] == "\\" else 1
            j = k + 1
            continue
        if ch in "([":
            d += 1
        elif ch in ")]":
            if d == 0:
                return j
            d -= 1
        elif ch in ";," and d == 0:
            return j
        j += 1
    return j


def odd_width_access(body: str, var_types: dict[str, str] | None = None) -> str:
    """A 3, 5, 6 or 7-byte value read or written through a pointer, `*(uint3 *)(p + 0x6e)`,
    `(*(undefined3 *)(gen_frame + 0x88)) = x`, `*param_1` of a `uint3 *`: its own bytes, GEN_PIECE
    and gen_piece_set. Ghidra32.h holds the type in the next wider C one (uint3 an unsigned int),
    so as a dereference the load read a byte past the value, the high byte kept where no mask
    follows (`(uint)*(uint3 *)(puVar6 + 6)`, 0x59ba30), and the store wrote the byte after it,
    a frame's next local or a record's next field. A 24-bit sample's `movzx` of its three bytes,
    FUN_00cfe6c0, read four, 2026-10-30."""
    # (a pointer variable of the type, `uint3 *param_1`: its dereference and subscript the cast's)
    # (a parameter's too, its type the signature's: var_types)
    ptrs = {(m.group(1), m.group(2)) for m in _ODD_PTR_DECL.finditer(body)}
    for n, tt in (var_types or {}).items():
        pm = re.fullmatch(r"\s*(" + "|".join(ODD_WIDTH) + r")\s*\*\s*", tt)
        if pm:
            ptrs.add((pm.group(1), n))
    for t, n in sorted(ptrs):
        w = ODD_WIDTH[t]
        body = re.sub(r"\b" + re.escape(n) + r"\s*\[([^\[\]]+)\]",
                      lambda m: f"(*({t} *)((char *){n} + ({m.group(1)}) * {w}))", body)
        out, i = [], 0
        for m in re.finditer(r"\*\s*" + re.escape(n) + r"\b(?!\s*(?:\[|->|\.))", body):
            if not _unary_at(body, m.start()):
                continue                      # (a multiplication, or the declaration's own `*`)
            out.append(body[i:m.start()])
            out.append(f"(*({t} *){n})")
            i = m.end()
        out.append(body[i:])
        body = "".join(out)
        if re.search(r"\b" + re.escape(n) + r"\s*(?:\+\+|--|[-+]=?(?!=)\s*[\w(])", body):
            raise ValueError(f"pointer arithmetic on a {t} *")
    for m in reversed(list(_ODD_CAST.finditer(body))):
        t, cast_at = m.group(1), m.start()
        w = ODD_WIDTH[t]
        signed = t.startswith("int")
        # (the dereference: `*(T *)x`, or `*((T *)x)` the cast's own group)
        k = cast_at - 1
        while k >= 0 and body[k] in " \t":
            k -= 1
        if k >= 0 and body[k] == "*":
            star, addr_lo = k, cast_at
            end = _operand_end(body, m.end())
            addr_hi = end
        elif k >= 0 and body[k] == "(":
            g = k
            k -= 1
            while k >= 0 and body[k] in " \t":
                k -= 1
            if k < 0 or body[k] != "*":
                continue
            star = k
            end = match_paren(body, g)
            if end < 0 or _operand_end(body, m.end()) != end - 1:
                continue                       # (`*((T *)p + 1)`: arithmetic on the pointer)
            addr_lo, addr_hi = cast_at, end - 1
        else:
            continue
        if end < 0:
            continue
        # (a unary `*` only: not `a * (T *)b`, which C has no meaning for)
        if not _unary_at(body, star):
            continue
        addr = body[addr_lo:addr_hi]
        lo, hi = star, end
        # (the parentheses around it, `(*(T *)(gen_frame + 0x88)) = x`)
        while True:
            p = lo - 1
            while p >= 0 and body[p] in " \t":
                p -= 1
            q = hi
            while q < len(body) and body[q] in " \t":
                q += 1
            if p >= 0 and body[p] == "(" and q < len(body) and body[q] == ")" and not \
                    re.search(r"[\w\]]\s*$", body[:p]):
                lo, hi = p, q + 1
            else:
                break
        # (its address taken, `&(*(T *)p)`: the pointer, as it is)
        p = lo - 1
        while p >= 0 and body[p] in " \t":
            p -= 1
        if p >= 0 and body[p] == "&" and not binary_amp(body, p) and not body[:p].endswith("&"):
            continue
        q = hi
        while q < len(body) and body[q] in " \t\r\n":
            q += 1
        load = f"GEN_PIECE({addr}, 0, {w})"
        if signed:
            load = f"gen_sext_n({load}, {w})"
        load = f"(({t}){load})"
        if body.startswith("++", q) or body.startswith("--", q) or body[:lo].rstrip().endswith(("++", "--")):
            raise ValueError(f"an increment of a {t}")
        op = re.compile(r"(<<|>>|[-+*/%&|^])?=(?!=)").match(body, q)
        if op:
            v_lo = op.end()
            v_hi = _value_end(body, v_lo)
            value = body[v_lo:v_hi].strip()
            if op.group(1):
                if re.search(r"\+\+|--|(?<![=!<>])=(?!=)|\b(?!GEN_TOP\b|REFG\b|REFP\b|GEN_PIECE\b)[A-Za-z_]\w*\s*\(", addr):
                    raise ValueError(f"a compound assignment to a {t} through an address with effects")
                value = f"{load} {op.group(1)} ({value})"
            rep = f"gen_piece_set({addr}, 0, {w}, (unsigned long long)({value}))"
            body = body[:lo] + rep + body[v_hi:]
        else:
            body = body[:lo] + load + body[hi:]
    return body


def eh_state_volatile(body: str) -> str:
    """An EH frame's state word, volatile: the C++ frame's state at node + 8 and the SEH frame's try
    level at node + 0xc, the words the runtime's dispatcher reads when the function faults. The
    host compiler sees only stores nothing reads before the next one, `try level = 0; r = 100 / x;
    try level = -2`, the faulting division no side effect to it, and dropped the first: the
    dispatcher found no __try around the division (rhtest msvc-14.51-x86 seh-O2, 2026-10-27)."""
    offs = set()
    for m in re.finditer(r"gen_eh_landing\([^;]*?\(gen_frame \+ 0x([0-9a-f]+)\)", body):
        node = int(m.group(1), 16)
        offs |= {node + 8, node + 0xC}
    # (and __SEH_prolog4's slot, the scope table's address first and the try level after, -2 at the
    # end, in a function with no landing of its own (a __finally only): the scope table's store,
    # overwritten before anything read it, was dropped, the static C runtime's guarded calls
    # missing their tables, rhtest stl /MT)
    for m in re.finditer(r"\(\*\([^()]*\*\s*\)\(gen_frame \+ 0x([0-9a-f]+)\)\) = (?:\(\([^()]*\)GEN_TOP\(0xfffffffe\)\)|0xfffffffe)\s*;", body):
        off = int(m.group(1), 16)
        if re.search(r"\(\*\([^()]*\*\s*\)\(gen_frame \+ 0x" + f"{off:x}" + r"\)\) = &REFG\(undefined, 0x[0-9a-f]+\);", body):
            offs.add(off)
    for off in offs:
        body = re.sub(r"\(\*\(\s*((?:unsigned\s+)?[A-Za-z_]\w*(?:\s*\*\s*PTR32)?)\s*\*\s*\)\(gen_frame \+ 0x" + f"{off:x}" + r"\)\)",
                      # (the slot volatile, not what a pointer in it points at: `volatile undefined
                      # * PTR32 *` left the scope table's store a plain one, dropped all the same)
                      lambda m: f"(*({m.group(1)} volatile *)(gen_frame + 0x{off:x}))", body)
    return body


def frame_locals(body: str, reserve: int = 0, minimum: int = 0, args: list[str] | None = None,
                 ebp: bool = False) -> str:
    """The reference's frame, where its code takes a local's address or uses a local array: every
    `local_N` and `*Stack_N` a slot of one buffer at its offset in the x86 frame (N, below the
    entry esp), and every place out_stack found below them (GEN_SLOT(d), d bytes below). Ghidra
    splits an aggregate the code builds on the stack into one local per field; as separate C
    locals they lie wherever the compiler puts them, and a callee handed the first's address read
    the others from the wrong place: FUN_00415b00's config entry `&local_24`, its string pointer
    `local_18` at +0xc of it, read as 0 (2026-10-23).
    reserve: bytes below the frame for what the function allocates on the stack at run time
    (alloca: `&stack0xffffffe8 + iVar5`, iVar5 the negated size), as the reference's stack has
    room below its frame."""
    slots = [int(d, 16) for d in re.findall(r"\bGEN_SLOT\(0x([0-9a-f]+)\)", body)]
    # (and out_stack's places at the bottom of the room below the frame, GEN_LOW(d): d bytes up)
    low = "GEN_LOW(" in body or "GEN_ABOVE(" in body
    if not slots and not has_frame(body) and not args and not low:
        return body
    decls = list(FRAME_DECL.finditer(body))
    if not decls and not slots and not args and not low:
        return body
    size = max([int(m.group(3), 16) for m in decls] + slots + [minimum, 4])
    # (the frame's own size, its deepest local's; the port's buffer rounded up to 16 bytes in front
    # of it, GEN_FRAME_DECL, the x86 fidelity build's the frame alone: rounded, a one-DWORD frame
    # was `sub esp, 0x10` against the reference's `push ecx`, and every local's esp offset off)
    pad = ((size + 15) & ~15) - size
    size += reserve
    body = re.sub(r"\bGEN_SLOT\(0x([0-9a-f]+)\)", lambda m: f"(gen_frame + 0x{size - int(m.group(1), 16):x})", body)
    body = re.sub(r"\bGEN_LOW\(0x([0-9a-f]+)\)", r"(gen_frame + 0x\1)", body)
    # (and an address above the entry's esp, the argument slot's offset k: the buffer's end + k)
    body = re.sub(r"\bGEN_ABOVE\(0x([0-9a-f]+)\)", lambda m: f"(gen_frame + 0x{size + int(m.group(1), 16):x})", body)
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
    if repl:
        body = re.sub(r"(?<![\w$])(" + "|".join(map(re.escape, repl)) + r")(?![\w$])", lambda m: repl[m.group(1)], body)
    if arrays:
        body = frame_index(body, [repl[a] for a in arrays])
    if reserve:
        body = frame_wrap(body)
    # (an ebp frame's top word is the saved ebp, no local's: the x86 fidelity build's frame without
    # it, top. Kept, the frame was 4 bytes over the reference's and every local 4 lower, the
    # cookie at [ebp - 8] for its [ebp - 4], rhtest core-Od)
    # (the cookie's xor with ebp, `^ (uint)(gen_frame + top)`, is its address, not a local)
    top = 0
    rest = re.sub(r"(?m)^[^\n]*= REFG\([^,()]+, 0x[0-9a-f]+\) \^ \(uint\)[^\n]*$", "", body)
    if ebp and not args and all(int(k, 16) <= size - 8 for k in re.findall(r"\(gen_frame \+ 0x([0-9a-f]+)\)", rest)):
        top = 4
    gs = False
    if not reserve and not args and not minimum:
        body, gs = frame_cookie(body, size - top)
    if gs:
        return body.replace("{", "{\n  GEN_FRAME_DECL_GS(0x%x, %d, %d);" % (size, pad, top), 1)
    if top:
        return body.replace("{", "{\n  GEN_FRAME_DECL_TOP(0x%x, %d, %d);" % (size, pad, top), 1)
    if args:
        # (the argument block above the return address: entry + 4, as the reference's)
        words = int(re.search(r"GEN_ARGS_WORDS (\d+)", args[-1]).group(1))
        init = "\n".join(args[:-1]).replace("GEN_ARGS_AT", f"0x{size + 4:x}")
        return body.replace("{", "{\n  GEN_FRAME_DECL(0x%x, %d);\n%s" % (size + 4 + 4 * words, pad, init), 1)
    return body.replace("{", "{\n  GEN_FRAME_DECL(0x%x, %d);" % (size, pad), 1)


FRAME_AT = re.compile(r"\(gen_frame \+ 0x[0-9a-f]+\)")
# (a frame array as frame_locals names one, `((T *)(gen_frame + 0xK))`, T and the place)
FRAME_ARRAY = re.compile(r"\(\((.+?) \*\)(\(gen_frame \+ 0x[0-9a-f]+\))\)")


def frame_cookie(body: str, size: int) -> tuple[str, bool]:
    """The reference's /GS security cookie, its frame's top word set to the cookie xor a frame
    address (`mov eax, [___security_cookie]; xor eax, esp; mov [esp + 0x2c], eax`), left in the x86
    fidelity build to the compiler's own /GS, which lays the same code there: GEN_COOKIE, and
    GEN_FRAME_DECL_GS's frame without the word. Written out, it was `lea eax, [esp + 8]; xor eax,
    [cookie]` and a second cookie of the compiler's above it. The check at the end the decompiler
    drops, the call to __security_check_cookie. True where it is one."""
    top = f"(gen_frame + 0x{size - 4:x})"
    m = re.search(r"(?m)^([ \t]*)(\(\*\((?:uint|undefined4|int|DWORD) \*\)" + re.escape(top) +
                  r"\) = REFG\([^,()]+, 0x[0-9a-f]+\) \^ \(uint\)[^;\n]*\bgen_frame\b[^;\n]*);[ \t]*$", body)
    # (the word nothing else reads)
    if not m or body.count(top) != 1:
        return body, False
    return body[:m.start()] + f"{m.group(1)}GEN_COOKIE({m.group(2)});" + body[m.end():], True


def frame_index(body: str, bases: list) -> str:
    """A frame array's subscript as the reference computes it, in 32 bits: the index an int. An
    unsigned one past 0x7fffffff is a negative one there, the address wrapping below the array:
    MSVC folds `nums[log2(k - 1) + 1]` into an array based one element on, `nums1[log2(0)]` its
    first element, and as a 64-bit index 0xffffffff landed 16 GB on (a Lua table's rehash)."""
    for base in set(bases):
        out, i = [], 0
        while True:
            p = body.find(base + "[", i)
            if p < 0:
                break
            j = p + len(base) + 1
            k, depth = j, 1
            while k < len(body) and depth:
                depth += {"[": 1, "]": -1}.get(body[k], 0)
                k += 1
            e = frame_index(body[j:k - 1], bases)
            typed = FRAME_ARRAY.fullmatch(base)
            # (a literal index is the same either way; another subscript after it, a row of a
            # 2-D local, left as it was)
            if re.fullmatch(r"\s*-?(?:0x[0-9a-fA-F]+|\d+)\s*", e) or not typed or body[k:k + 1] == "[":
                out.append(body[i:j])
                out.append(e if re.fullmatch(r"\s*-?(?:0x[0-9a-fA-F]+|\d+)\s*", e) else f"(int)({e})")
                out.append("]")
            else:
                # (the element's address in 32 bits, the reference's [ebp + ecx*4 - 0x30]: an index
                # past 2^29 wraps there to a slot of the frame, and C's 64-bit sum left it. A NaN
                # gain's ftol, 0x80000000, read 9 - 0x80000000 of an 11-float table, ebp - 0xc on
                # x86 and 8 GB below the frame in the port: d2edb0 from PointSound::vf15, 2026-11-01.
                # The port's stack is below 4 GB, frame_wrap's premise)
                t, at = typed.group(1), typed.group(2)
                out.append(body[i:p])
                out.append(f"(*({t} *)GP((uint)(uintptr_t){at} + (uint)({e}) * (uint)sizeof({t})))")
            i = k
        out.append(body[i:])
        body = "".join(out)
    return body


GLOBAL_ARRAY = re.compile(r"\(&REFG\([^()]*\)\)\[")


def global_index(body: str) -> str:
    """A global array's subscript in 32 bits too, as frame_index a frame array's: the CRT's printf
    state table, `(&DAT_01119e88)[uVar8 * 8 + iVar17]`, a table folded one row on and indexed
    0xfffffff8 for its first, read 4 GB on (__vsnprintf_l from a Havok loader in a VS2010 client,
    2026-10-26)."""
    out, i = [], 0
    for m in GLOBAL_ARRAY.finditer(body):
        if m.start() < i:
            continue
        j = m.end()
        k, depth = j, 1
        while k < len(body) and depth:
            depth += {"[": 1, "]": -1}.get(body[k], 0)
            k += 1
        e = global_index(body[j:k - 1])
        typed = re.fullmatch(r"\(&REFG\((.+), (0x[0-9a-fA-F]+)\)\)\[", m.group(0))
        if re.fullmatch(r"\s*-?(?:0x[0-9a-fA-F]+|\d+)\s*", e) or not typed or body[k:k + 1] == "[":
            out.append(body[i:j])
            out.append(e if re.fullmatch(r"\s*-?(?:0x[0-9a-fA-F]+|\d+)\s*", e) else f"(int)({e})")
            out.append("]")
        else:
            # (the element's address in 32 bits, as x86's [A + ecx*S]: frame_index's rule. A table
            # looked up by a NaN's ftol, 0x80000000, wraps there to the table's base, 8 GB on in a
            # 64-bit sum, 2026-11-01)
            t, at = typed.groups()
            out.append(body[i:m.start()])
            out.append(f"(*({t} *)GP({at}u + (uint)({e}) * (uint)sizeof({t})))")
        i = k
    out.append(body[i:])
    return "".join(out)


def pointer_index(body: str, var_types: dict[str, str]) -> str:
    """A pointer's subscript, and a group added to it, in 32 bits as the reference computes the
    address, frame_index's and global_index's rule for a local's or a parameter's pointer: an
    unsigned offset past 0x7fffffff is a step back there, the sum wrapping, and C zero-extends it
    to 64 bits, 16 GB on. The CRT's memmove (FID_conflict__memcpy 0xc46aa0 and 0xc46e20) copies a
    backward tail of 2..7 dwords as `puVar4[6 - uVar1] = puVar3[6 - uVar1]` after case 7's
    `[7 - uVar1]`, x86's [esi + ecx*4 + 0x18] with ecx = -7 (`neg ecx; jmp [ecx*4 + table]`), and
    the port's `mov eax, 6; sub eax, r9d; mov eax, [r8 + rax*4]` read 0x3fffffffc on; hkMemUtil::
    MemCpyBackward 0xda37e0's byte tail `puVar8[uVar5 - uVar3]` (src - dst, dst above src) the
    same (2026-10-31). An address the reference computes fits 31 bits, so the signed reading is
    the 32-bit sum's: `(int)(E)`, a literal left as it is."""
    names = [n for n, t in var_types.items() if ("*" in t or t.endswith("[]")) and "(" not in t and not n.startswith("gen_")]
    if not names:
        return body
    alt = "|".join(map(re.escape, sorted(names, key=len, reverse=True)))
    pat = re.compile(r"(?<![\w.$])(?<!->)(?:" + alt + r")\s*(\[|\+ \()")
    literal = re.compile(r"\s*-?(?:0x[0-9a-fA-F]+|\d+)[uU]?\s*")

    ints = {"int", "short", "char", "long", "sbyte", "int8_t", "int16_t", "int32_t", "longlong", "int64_t", "bool"}

    def signed(e: str) -> bool:
        """a literal, already (int), or every operand a signed local's (`iVar5 + 4`)"""
        if literal.fullmatch(e) or re.fullmatch(r"\s*\(int\)\s*\(.*\)\s*", e, re.S):
            return True
        if re.search(r"\bunsigned\b|\(\s*(?:u\w+|undefined\d|byte|word|dword|size_t|gen_size32)\s*\)|[0-9a-fA-F]U\b|\(|\[|->|\.", e):
            return False
        words = re.findall(r"\b[A-Za-z_]\w*\b", e)
        return bool(words) and all(var_types.get(w, "").strip() in ints for w in words)

    def walk(text: str) -> str:
        out, i = [], 0
        for m in pat.finditer(text):
            if m.start() < i:
                continue
            # (the pointer cast to an integer first, `(int)p + (..)`: 32-bit arithmetic already)
            if m.group(1) != "[" and re.search(r"\)\s*$", text[max(0, m.start() - 2):m.start()]):
                continue
            j = m.end()
            k, depth = j, 1
            opener, closer = ("[", "]") if m.group(1) == "[" else ("(", ")")
            while k < len(text) and depth:
                depth += {opener: 1, closer: -1}.get(text[k], 0)
                k += 1
            if depth:
                continue
            # (an added group that is a factor's, `p + (a) * 4`: not the whole offset)
            if m.group(1) != "[" and re.match(r"\s*(?:[*/%\[.]|->|[\w(&*!~])", text[k:]):
                continue
            e = walk(text[j:k - 1])
            out.append(text[i:j - (0 if m.group(1) == "[" else 1)])
            # (an added group keeps its parentheses, signed or not: `p + (a - b >> 2)` bare was
            # `p + a - b >> 2`, the pointer shifted, 78 functions demoted 2026-10-31)
            if signed(e):
                out.append(e if m.group(1) == "[" else f"({e})")
            else:
                out.append(f"(int)({e})")
            out.append(closer if m.group(1) == "[" else "")
            i = k
        out.append(text[i:])
        return "".join(out)
    return walk(body)


_ADDEND_INTS = {"int", "short", "char", "long", "sbyte", "int8_t", "int16_t", "int32_t", "longlong", "int64_t", "bool"}


def _closes_at_end(e: str) -> bool:
    """whether e's first parenthesis closes at its end"""
    depth = 0
    for k, ch in enumerate(e):
        depth += {"(": 1, ")": -1}.get(ch, 0)
        if depth == 0:
            return k == len(e) - 1
    return False


def pointer_addends(body: str, var_types: dict[str, str]) -> str:
    """A pointer's bare addends, `pcVar3 = pcVar3 + uVar4;`, `param_1 + (uVar2 - iVar6) * 0x47`, in 32
    bits as the reference computes the address, pointer_index's rule for the terms it leaves (it
    takes a subscript and a parenthesized group): an unsigned term past 0x7fffffff is a step back
    there, the sum wrapping, and C zero-extends it, 16 GB on. A text control's length byte read
    signed, `uVar4 = (int)pcVar3[2] + 3`, stepped back on x86 and 4 GB on in the port (0x55c170,
    2026-10-31). Each term of the chain after the pointer, up to the end of its additive
    expression, `(int)(T)` unless it is a literal, already (int), every operand a signed local's,
    or another pointer (a difference of two)."""
    names = [n for n, t in var_types.items() if ("*" in t or t.endswith("[]")) and "(" not in t and not n.startswith("gen_")]
    if not names:
        return body
    ptrs = set(names)
    alt = "|".join(map(re.escape, sorted(names, key=len, reverse=True)))
    # (the pointer itself, not a cast's operand `(int)p + x` nor a member `a->p`, then + or -)
    pat = re.compile(r"(?<![\w.$)\]*&])(?<!->)(?<!\* )(?:" + alt + r")(?![\w\[(])\s*([+-])(?![+\-=>])")
    literal = re.compile(r"\s*-?(?:0x[0-9a-fA-F]+|\d+)[uU]?\s*")

    def signed(e: str) -> bool:
        if literal.fullmatch(e) or re.fullmatch(r"\s*\(int\)\s*\(.*\)\s*", e, re.S):
            return True
        if re.search(r"\bunsigned\b|\(\s*(?:u\w+|undefined\d|byte|word|dword|size_t|gen_size32)\s*\)|[0-9a-fA-F]U\b|\(|\[|->|\.", e):
            return False
        words = re.findall(r"\b[A-Za-z_]\w*\b", e)
        return bool(words) and all(var_types.get(w, "").strip() in _ADDEND_INTS for w in words)

    def term_end(text: str, j: int) -> int:
        """the end of the multiplicative term starting at j: the next top-level + - or an operator
        of lower precedence, or a closer"""
        depth, k = 0, j
        while k < len(text) and text[k] in " \t":
            k += 1
        start = k
        while k < len(text):
            ch = text[k]
            if ch in "([":
                depth += 1
            elif ch in ")]":
                if depth == 0:
                    break
                depth -= 1
            elif depth == 0:
                if ch in ",;?:" or ch == "\n" or text.startswith("GEN_", k):
                    break
                two = text[k:k + 2]
                if two in ("<<", ">>", "<=", ">=", "==", "!=", "&&", "||") or ch in "<>=|^":
                    break
                if ch == "&" and text[k + 1:k + 2] != "&":
                    break
                if ch in "+-" and k > start:
                    prev = text[start:k].rstrip()[-1:]
                    if prev and prev not in "*/%+-(":
                        break
            k += 1
        return k

    out, i = [], 0
    for m in pat.finditer(body):
        if m.start() < i:
            continue
        j = m.end()
        out.append(body[i:j])
        i = j
        # (each term of the chain: p + T1 + T2 - T3)
        while True:
            k = term_end(body, i)
            t = body[i:k]
            e = t.strip()
            lead = t[:len(t) - len(t.lstrip())]
            # (a parenthesized group whole is pointer_index's, signed or (int) already)
            whole_group = e.startswith("(") and e.endswith(")") and _closes_at_end(e)
            if not e or whole_group or any(re.search(r"\b" + re.escape(p) + r"\b", e) for p in ptrs) or signed(e) \
                    or re.match(r"\(\s*\w[\w\s]*\*\s*\)", e):
                out.append(t)
            else:
                out.append(f"{lead}(int)({e})")
            i = k
            mm = re.match(r"\s*([+-])(?![+-=])", body[i:])
            if not mm:
                break
            out.append(body[i:i + mm.end()])
            i += mm.end()
    out.append(body[i:])
    return "".join(out)


_POLL_LOAD = re.compile(r"^(?:mov|movzx|movsx)$")
_POLL_REG = re.compile(r"\b(e?[abcd]x|[abcd][lh]|e?[sd]i|e?bp|e?sp)\b")
_POLL_FAM = {"al": "eax", "ah": "eax", "ax": "eax", "bl": "ebx", "bh": "ebx", "bx": "ebx", "cl": "ecx", "ch": "ecx",
       "cx": "ecx", "dl": "edx", "dh": "edx", "dx": "edx", "si": "esi", "di": "edi", "bp": "ebp", "sp": "esp"}


def ref_polls(insns) -> bool:
    """insns [(addr, size, mnemonic, ops)]: a short backward loop of nothing but loads of memory
    the loop never readdresses, compares and conditional jumps (`mov al, [edi + 6]; test al, al;
    je $-5`): a wait on memory another thread writes"""
    at = {x[0]: k for k, x in enumerate(insns)}
    for k, (ad, _s, mn, ops) in enumerate(insns):
        if not (mn.startswith("j") and mn != "jmp" and re.fullmatch(r"0x[0-9a-f]+", ops)):
            continue
        t = int(ops, 16)
        if t > ad or t not in at or k - at[t] > 12:
            continue
        body = insns[at[t]:k + 1]
        written, mems, ok = set(), [], True
        for _a, _sz, m, o in body:
            parts = [p.strip() for p in o.split(",")] if o else []
            if m in ("cmp", "test", "nop", "pause") or (m.startswith("j") and m != "jmp"):
                mems += [p for p in parts if "[" in p]
            elif _POLL_LOAD.match(m) and len(parts) == 2 and "[" in parts[1] and "[" not in parts[0]:
                mems.append(parts[1])
                written |= {_POLL_FAM.get(r, r) for r in _POLL_REG.findall(parts[0])}
            else:
                ok = False
                break
        if not ok or not mems:
            continue
        if all(not ({_POLL_FAM.get(r, r) for r in _POLL_REG.findall(p[p.index("["):])} & written) for p in mems):
            return True
    return False


def poll_barriers(body: str) -> str:
    """GEN_POLL() first in each loop body of the function that calls nothing"""
    def match(s, i, o, c):
        d = 0
        for j in range(i, len(s)):
            d += (s[j] == o) - (s[j] == c)
            if d == 0:
                return j
        return -1

    call = re.compile(r"\b(?:F_[0-9a-f]{8}|W_[0-9a-f]{8}|gen_imp_\w+)\s*\(|GEN_TCODE|\(\s*\*\s*\(\s*code\b|\(\*\(\(code")
    out, i = [], 0
    for m in re.finditer(r"\b(?:do\s*\{|(?:while|for)\s*\()", body):
        if m.start() < i:
            continue
        if m.group(0).startswith("do"):
            bo = m.end() - 1
        else:
            pc = match(body, m.end() - 1, "(", ")")
            r = re.match(r"\s*\{", body[pc + 1:]) if pc > 0 else None
            if not r:
                continue
            # (a do-while's tail is no loop of its own)
            if body[:m.start()].rstrip().endswith("}") and body[pc + 1:].lstrip().startswith(";"):
                continue
            bo = pc + 1 + r.end() - 1
        bc = match(body, bo, "{", "}")
        if bc < 0 or call.search(body[bo:bc]):
            continue
        out.append(body[i:bo + 1])
        out.append(" GEN_POLL();")
        i = bo + 1
    out.append(body[i:])
    return "".join(out)


def frame_wrap(body: str) -> str:
    """A place in the frame offset by a run-time amount, computed in 32 bits as the reference's
    is: `(gen_frame + K) + E` and `((gen_frame + K))[E]`. E is often an unsigned sum with a negative
    term (an alloca's negated size, `uVar8 * 3 + iVar5`) that wraps in 32 bits; added to a 64-bit
    pointer it landed 4 GB on, rhtest misc-O2's stack_alloc. The port's stack is below 4 GB, as
    every (int)&local Ghidra writes takes it to be."""
    out, i = [], 0
    for m in FRAME_AT.finditer(body):
        if m.start() < i:
            continue
        j = m.end()
        # `((gen_frame + K))[E]`: the token in one more pair of parentheses, then a subscript
        if body[m.start() - 1:m.start()] == "(" and body[j:j + 2] == ")[":
            k, depth = j + 2, 1
            while k < len(body) and depth:
                depth += {"[": 1, "]": -1}.get(body[k], 0)
                k += 1
            e = body[j + 2:k - 1]
            out.append(body[i:m.start() - 1])
            out.append(f"((undefined1 *)GP((uint)(uintptr_t){m.group(0)} + ({e})))[0]")
            i = k
            continue
        # `(gen_frame + K) + E ...`, the sum to the end of its operand
        rest = re.match(r"\s*\+\s*", body[j:])
        if not rest:
            continue
        k, depth = j + rest.end(), 0
        while k < len(body):
            ch = body[k]
            if ch in "([":
                depth += 1
            elif ch in ")]":
                if depth == 0:
                    break
                depth -= 1
            elif depth == 0 and (ch in ",;?:" or body.startswith(("==", "!=", "<", ">", "&&", "||"), k)
                                 or (ch == "=" and body[k + 1:k + 2] != "=")):
                break
            k += 1
        e = body[j + rest.end():k].rstrip()
        out.append(body[i:m.start()])
        out.append(f"((undefined1 *)GP((uint)(uintptr_t){m.group(0)} + ({e})))")
        i = j + rest.end() + len(e)
    out.append(body[i:])
    return "".join(out)


# (and al/ax, a byte or bool function's: ___scrt_initialize_onexit_tables returns `in_AL` after
# __scrt_fastfail, which can return, its al whatever that left, rhtest calls 2026-10-24)
RESULT_REG = re.compile(r"\b(?:in|extraout)_(?:E[AD]X|AL|AX)(?:_\d+)?\b")


def next_is_return(v: str, lines: list[str], at: int) -> bool:
    """The next line after `at` that mentions v is `return v;`, and no goto or loop on the way: what
    the line at `at` stores in v reaches only that return. (A label passed is other paths joining
    this one, the epilogue's `LAB_0064116d: __security_check_cookie(...); return uVar8;`: this
    path's value still reaches only the return. Refused there, a VS2010 client's
    StarRenderer::vf2 was a stub on its frame path, 2026-10-27)"""
    # (and the way it really goes: a `break;` out of the switch past the cases after it, the end of
    # an if's block past its else block, `uVar7 = extraout_EAX; break; case 5: ...; uVar7 = x; break;
    # } ... return uVar7;`, a client's AgentLobby::vf5, a stub on the way to its lobby 2026-10-27)
    # (every way on is walked, a goto both taken and passed (a superset of the paths, never fewer):
    # each must reach `return v;` or a write of v that reads none of it, the value then dead, before
    # anything reads it; a loop still refuses. After the switch, `if (..) goto LAB_00904df1; ...
    # uVar7 = FUN_008844c0();`, AgentLobby::vf5)
    labels = {}
    for k, l in enumerate(lines):
        mm = re.match(r"\s*([A-Za-z_]\w*)\s*:(?!:)", l)
        if mm and not mm.group(1) in ("case", "default"):
            labels[mm.group(1)] = k
    seen: set[int] = set()

    def skip_out(j: int, below: int) -> int:
        """The line after the one where the depth falls below `below`, from j."""
        d = 0
        while j < len(lines):
            s2 = re.sub(r"\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'", "", lines[j])
            d += s2.count("{") - s2.count("}")
            j += 1
            if d < below:
                return j
        return j
    def block_end(j: int) -> int | None:
        """the line of the `}` closing the block line j opens"""
        d = 0
        for k in range(j, len(lines)):
            s2 = re.sub(r"\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'", "", lines[k])
            d += s2.count("{") - s2.count("}")
            if d <= 0 and k > j:
                return k
        return None

    def walk(j: int) -> bool:
        while j < len(lines):
            if j in seen:
                return True                              # (walked from here already)
            seen.add(j)
            s = lines[j].strip()
            # (a statement the decompiler wrapped, its lines read as one: `uVar6 = (**(code **)(..))\n
            # (.., 0x68, 0x10);` a write, a client's 0x6a6e70, 2026-10-30)
            k2 = j
            while s and not re.search(r"[;{}:]$", s) and k2 + 1 < len(lines) and not s.startswith(("/*", "#")):
                k2 += 1
                s = s + " " + lines[k2].strip()
            # (a loop by its ways: a do's body walked on into; at its `} while (c)`, a condition that
            # reads nothing of v, both the exit and the way back to the body's top; a while's header
            # so, into the body and past it. The way past an if reached a do's end, 0xea85d0's
            # tree walk, and refused there the copy before it stayed a lost register, 2026-10-30)
            vre_ = r"\b" + re.escape(v) + r"\b"
            if re.fullmatch(r"do\s*\{", s):
                j += 1
                continue
            if s.startswith("} while"):
                if re.search(vre_, s):
                    return False
                d, o = 0, j
                while o >= 0:
                    s2 = re.sub(r"\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'", "", lines[o])
                    d += s2.count("}") - s2.count("{")
                    if d <= 0 and o < j:
                        break
                    o -= 1
                if o < 0 or not re.match(r"\s*do\s*\{", lines[o]):
                    return False
                return walk(o + 1) and walk(k2 + 1)
            if re.match(r"while\s*\(", s) and s.endswith("{") and not re.search(vre_, s):
                e = block_end(j)
                if e is None or not walk(e + 1):
                    return False
                j += 1
                continue
            if re.match(r"(?:do|while|for)\b", s):
                return False
            # (an if's block with no else: the way past it too, the condition false. Walked into
            # alone, a write inside it was taken for every way's, 2026-10-30)
            if re.match(r"if\s*\(", s) and s.endswith("{"):
                e = block_end(j)
                if e is None:
                    return False
                if lines[e].strip() == "}" and not (e + 1 < len(lines) and lines[e + 1].strip().startswith("else")):
                    if not walk(e + 1):
                        return False
            g = re.search(r"\bgoto\s+([A-Za-z_]\w*)\s*;", s)
            if re.search(r"\b" + re.escape(v) + r"\b", s):
                if re.fullmatch(r"return\s+(?:\(\w+\)\s*)?" + re.escape(v) + r"\s*;", s):
                    return True
                w = re.fullmatch(re.escape(v) + r"\s*=(?!=)\s*(.+);", s)
                return w is not None and not re.search(r"\b" + re.escape(v) + r"\b", w.group(1))
            # (a goto taken, and the lines past it walked too: inside an if's block, the way that
            # skips the block goes on there. A return the same: not the end of every way)
            if g and (g.group(1) not in labels or not walk(labels[g.group(1)])):
                return False
            if s == "break;":
                j = skip_out(j + 1, 0)                   # (past the switch's closing brace)
                continue
            if re.fullmatch(r"\}\s*else\s*\{", s) or re.fullmatch(r"\}\s*else\s+if\b.*\{", s):
                j = skip_out(j + 1, 0)                   # (past the else's blocks)
                continue
            if s == "}" and j + 1 < len(lines) and re.fullmatch(r"else\s*\{", lines[j + 1].strip()):
                j = skip_out(j + 2, 0)
                continue
            j = k2 + 1                                   # (past a wrapped statement's lines)
        return False
    return walk(at + 1)


def brace_openers(lines: list[str]) -> dict[int, int]:
    """For each line starting with `}`, the line of the `{` it closes (string and character
    literals aside)."""
    stack, out = [], {}
    for j, line in enumerate(lines):
        s = re.sub(r"\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'", "", line)
        first = True
        for ch in s:
            if ch == "{":
                stack.append(j)
            elif ch == "}" and stack:
                o = stack.pop()
                if first and s.lstrip().startswith("}"):
                    out[j] = o
                first = False
    return out


def reads_after_writes(v: str, lines: list[str], bad: set[str]) -> bool:
    """Every read of local v, but in a return, comes after an assignment to it of something else
    on each way there: a write of v at the read's own level above it, or in every branch of an
    if/else chain above it, with no label, case or loop holding a bad write in between. Then what a
    `v = extraout_EAX;` (a name of bad) stores reaches only returns. 0xcc74f0 in a VS2010 client,
    a sound driver's update, `uVar1 = extraout_EAX;` after EnterCriticalSection and `uVar1 =
    (**(code **)(*this + 0x88))(this); if ((char)uVar1 == '\\0')` in its loop, a stub every frame,
    2026-10-26."""
    vre = re.compile(r"\b" + re.escape(v) + r"\b")
    badre = re.compile(r"\b(?:" + "|".join(map(re.escape, bad | {v})) + r")\b")
    opener = brace_openers(lines)

    def assign(s):
        m = re.fullmatch(re.escape(v) + r"\s*=(?!=)\s*(.+);", s)
        return m.group(1) if m else None

    def kill(s):
        rhs = assign(s)
        return rhs is not None and not badre.search(rhs)

    def bad_write_in(o, c):
        return any((rhs := assign(lines[k].strip())) is not None and badre.search(rhs) for k in range(o, c + 1))

    def top_kill(o, c):
        """a write of v of something else at the top level of the block o..c, before any label"""
        k = o + 1
        while k < c:
            s = lines[k].strip()
            if s.startswith("}") or re.match(r"[A-Za-z_]\w*\s*:(?!:)|case\b|default\s*:", s):
                return False
            if s.endswith("{"):
                # (a nested block: past its end)
                ends = [e for e, op in opener.items() if op == k]
                if not ends:
                    return False
                k = min(ends) + 1
                continue
            if kill(s):
                return True
            k += 1
        return False

    def chain_start(c):
        """the close line of an if/else chain's last branch -> (its first line, every branch
        (open, close), whether it ends in a plain else)"""
        branches, has_else = [], False
        while c in opener:
            o = opener[c]
            branches.append((o, c))
            head = lines[o].strip()
            if re.match(r"(?:\}\s*)?else\b(?!\s+if)", head):
                has_else = True
            if head.startswith("}"):
                c = o                                   # `} else {`: the branch before closes here
                continue
            if head.startswith("else") and o > 0 and lines[o - 1].strip().startswith("}"):
                c = o - 1                               # `}` / `else {` on two lines
                continue
            return o, branches, has_else
        return None, branches, has_else

    def dominated(i):
        j = i - 1
        while j >= 0:
            s = lines[j].strip()
            if lines[j].startswith("{") or re.match(r"[A-Za-z_]\w*\s*:(?!:)|case\b|default\s*:", s):
                return False                            # the function's start, a label, a case
            if s.startswith("}") and j in opener:
                start, branches, has_else = chain_start(j)
                if start is None:
                    return False
                head = lines[start].strip()
                if re.match(r"(?:do|while|for)\b", head) or s.startswith("} while"):
                    if bad_write_in(start, j):
                        return False
                elif has_else and all(top_kill(o, c) for o, c in branches):
                    return True
                j = start - 1
                continue
            if s.endswith("{"):
                # (out of the block the read is in, upward)
                if re.match(r"(?:do|while|for)\b", s):
                    ends = [e for e, op in opener.items() if op == j]
                    if not ends or bad_write_in(j, min(ends)):
                        return False
                elif re.match(r"(?:\}\s*)?else\b", s) or s.startswith("}"):
                    start, _b, _e = chain_start(j - 1 if s.startswith("else") else j)
                    if start is None:
                        return False
                    j = start - 1
                    continue
                elif re.match(r"switch\b", s):
                    return False
                j -= 1
                continue
            if kill(s):
                return True
            if assign(s) is not None:
                return False                            # the bad write itself
            j -= 1
        return False

    for i, line in enumerate(lines):
        if not vre.search(line):
            continue
        s = line.strip()
        if re.fullmatch(r"[A-Za-z_][\w ]*?[\s*]+" + re.escape(v) + r";", s) or re.match(r"return\b", s):
            continue
        if assign(s) is not None and not vre.search(assign(s)):
            continue
        if re.match(r"(?:while|for)\b", s) or not dominated(i):
            return False
    return True


def returned_local(v: str, lines: list[str]) -> bool:
    """A local whose every read is a `return v;`: what is assigned to it reaches nothing else."""
    for line in lines:
        if not re.search(r"\b" + re.escape(v) + r"\b", line):
            continue
        s = line.strip()
        if re.fullmatch(r"[\w ]+\s+\**" + re.escape(v) + r";", s):
            continue                                    # its declaration
        if re.fullmatch(r"return\s+(?:\(\w+\)\s*)?" + re.escape(v) + r"\s*;", s):
            continue
        # (or as the high half of one, `return CONCAT44(uVar4,uVar2);`: edx beside an int result,
        # the CRT's __vsnprintf_helper typed ulonglong, whose callers read eax, a VS2010
        # client 2026-10-25)
        if re.fullmatch(r"return\s+CONCAT44\(\s*" + re.escape(v) + r"\s*,[^;]*\)\s*;", s) \
                and len(re.findall(r"\b" + re.escape(v) + r"\b", s)) == 1:
            continue
        m = re.fullmatch(r"(\w+)\s*=\s*(.+);", s)
        if m and m.group(1) == v and not re.search(r"\b" + re.escape(v) + r"\b", m.group(2)):
            continue                                    # written
        return False
    return True


def int_min(c: str) -> str:
    """Ghidra's INT_MIN as a negation, `-0x80000000` (and LLONG_MIN's): signed. C reads the
    literal as unsigned and its negation too, so `-0x80000000 >> n`, an x86 `sar` making a mask of
    ones, shifted in zeros: the graphics allocator's free-bucket mask found no bucket (a VS2010 client,
    2026-10-24). A minus after an operand is a subtraction, left as it is."""
    def one(m):
        before = c[:m.start()].rstrip()
        if before and (before[-1] in ")]" or re.search(r"\w$", before)) and not re.search(r"\breturn$", before):
            return m.group(0)
        return "((longlong)0x8000000000000000)" if len(m.group(1)) > 10 else "((int)0x80000000)"
    return re.sub(r"-\s*(0x80000000|0x8000000000000000)\b(?![\w.])", one, c)


ARRAY_ELEMENT = {"undefined": 1, "undefined1": 1, "char": 1, "byte": 1, "uchar": 1, "undefined2": 2,
                 "undefined4": 4, "undefined8": 8}


def array_stores(c: str) -> str:
    """A small local array stored whole, `local_44 = (char [4])s_alpha_00410280._0_4_;`: no C
    assigns an array, so the store of its bytes, `*(undefined4 *)local_44 = ...;`. strcpy and
    memset inlined at /O2 build strings so, and the function was stubbed (rhtest msvc-16.00-x86
    crt-O2 strings)."""
    arrays = set(re.findall(r"(?m)^[ \t]+[A-Za-z_]\w*\s+([A-Za-z_]\w*)\s*\[\s*(?:0x)?[0-9a-f]+\s*\]\s*;", c))

    def one(m):
        n = ARRAY_ELEMENT.get(m.group(3), 0) * int(m.group(4), 0)
        if m.group(2) not in arrays or n not in (1, 2, 4, 8):
            return m.group(0)
        return f"{m.group(1)}*(undefined{n} *){m.group(2)} = {m.group(5)};"
    c = re.sub(r"(?m)^([ \t]+)([A-Za-z_]\w*)\s*=\s*\(\s*([A-Za-z_]\w*)\s*\[\s*((?:0x)?[0-9a-f]+)\s*\]\s*\)\s*(.+);[ \t]*$",
               one, c)

    # (and a local array stored whole through a pointer, `*(byte (*) [4])param_3 = local_28;`: its
    # bytes as one store. A Direct3D surface's description copied out so, 0x4d5a50 in a VS2010 client)
    def through(m):
        n = ARRAY_ELEMENT.get(m.group(2), 0) * int(m.group(3), 0)
        if m.group(5) not in arrays or n not in (1, 2, 4, 8):
            return m.group(0)
        return f"{m.group(1)}*(undefined{n} *)({m.group(4)}) = *(undefined{n} *){m.group(5)};"
    return re.sub(r"(?m)^([ \t]+)\*\s*\(\s*([A-Za-z_]\w*)\s*\(\s*\*\s*\)\s*\[\s*((?:0x)?[0-9a-f]+)\s*\]\s*\)\s*"
                  r"([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*;[ \t]*$", through, c)


WORD4 = r"(?:undefined4|uint|int|ulong|long|LONG|DWORD|UINT)"
PTR4 = r"(?:(?:unsigned\s+)?[A-Za-z_]\w*\s*\*\s*PTR32)"
WTYPE = r"(?:" + WORD4 + r"|" + PTR4 + r")"


def interlocked(c: str, head: str = "") -> str:
    """A `lock`-prefixed read-modify-write on a 4-byte word, Ghidra's `LOCK(); ...; UNLOCK();`, as
    the intrinsic it is: `lock xadd` an _InterlockedExchangeAdd (an add, a subtract, or 0: a locked
    read), `xchg` an _InterlockedExchange, `lock cmpxchg` an _InterlockedCompareExchange.
    Under Ghidra32.h's one process-wide lock a section was atomic only against other LOCK()
    sections, not against the intrinsics: ReferencedClassBase::AddRef 0x4f4040 an
    _InterlockedExchangeAdd(+1) and its Release 0x4f4050 `LOCK(); v = *p; *p = *p - 1; UNLOCK();`,
    an AddRef between the read and the write lost (2026-10-31). Each section is the instruction, the
    word read and written as one whatever types Ghidra gave each side (`*(uint *)p` read, `*(int *)p`
    written; `gen_fl2bits(*(float *)p)` the word's bits). `head` is the function's signature, for
    its pointer parameters (the body has none). Any other shape keeps the lock."""
    if "LOCK();" not in c:
        return c
    ptr4 = set(re.findall(r"(?m)^[ \t]+(?:" + WORD4 + r"|" + PTR4 + r")\s*\*\s*(?:PTR32\s+)?([A-Za-z_]\w*)\s*;", c))
    # (and the parameters: `in_ecx`, an entry register made one, FUN_004273f0's `uint *in_ecx`)
    ptr4 |= set(re.findall(r"[(,]\s*(?:" + WORD4 + r"|" + PTR4 + r")\s*\*\s*(?:PTR32\s+)?([A-Za-z_]\w*)\s*(?=[,)])",
                           head))
    ptrvars = set(re.findall(r"(?m)^[ \t]+(?:unsigned\s+)?[A-Za-z_]\w*\s*\*+\s*(?:PTR32\s+)?([A-Za-z_]\w*)\s*;", c))

    def balanced(s: str) -> bool:
        d = 0
        for ch in s:
            d += ch == "("
            d -= ch == ")"
            if d < 0:
                return False
        return d == 0

    def lvalue(lv: str):
        """(address, regex for any 4-byte read of the word, regex for its read as a float, pointer-typed)"""
        lv = lv.strip()
        m = re.fullmatch(r"REFG\(\s*(" + WTYPE + r")\s*,\s*(0x[0-9a-f]+)\s*\)", lv)
        if m:
            return (f"&{lv}", r"REFG\(\s*" + WTYPE + r"\s*,\s*" + m.group(2) + r"\s*\)",
                    r"REFG\(\s*float\s*,\s*" + m.group(2) + r"\s*\)", "PTR32" in m.group(1))
        m = re.fullmatch(r"([A-Za-z_]\w*)\s*\[([^\[\]]+)\]", lv)
        if m and m.group(1) in ptr4:
            return (f"&{lv}", re.escape(m.group(1)) + r"\s*\[\s*" + re.escape(m.group(2).strip()) + r"\s*\]", None, False)
        if not lv.startswith("*"):
            return None
        inner = lv[1:].strip()
        if re.fullmatch(r"[A-Za-z_]\w*", inner) and inner in ptr4:
            return (inner, r"\*\s*" + re.escape(inner) + r"(?![\w\[])", None, False)
        m = re.fullmatch(r"\(\s*\(\s*(" + WTYPE + r")\s*\*\s*\)\s*(.+)\)", inner, re.S) or \
            re.fullmatch(r"\(\s*(" + WTYPE + r")\s*\*\s*\)\s*(.+)", inner, re.S)
        if m and balanced(m.group(2)):
            e = m.group(2).strip()
            # (or a subscript, `*(undefined4 *)param_1[0x10] = 2` under LOCK, xchg on a shared word:
            # FileManager::ProcessExtendedRequest 0x4fd6e0 left on the global lock, 2026-11-01)
            if not (re.fullmatch(r"[A-Za-z_]\w*", e) or (e.startswith("(") and e.endswith(")") and balanced(e[1:-1]))
                    or re.fullmatch(r"GEN_TOP\(.*\)", e, re.S) or re.fullmatch(r"[A-Za-z_]\w*\s*\[[^\[\]]+\]", e)):
                return None
            ek = r"\s*".join(re.escape(ch) for ch in re.sub(r"\s+", "", e))
            rd = (r"(?:\(\s*(?:int|uint|undefined4)\s*\)\s*)?gen_fl2bits\(\s*\*\s*\(\s*float\s*\*\s*\)\s*" + ek + r"\s*\)"
                  r"|\*\s*\(\s*\(\s*" + WTYPE + r"\s*\*\s*\)\s*" + ek + r"\s*\)"
                  r"|\*\s*\(\s*" + WTYPE + r"\s*\*\s*\)\s*" + ek + r"(?![\w\[])")
            fr = (r"\*\s*\(\s*\(\s*float\s*\*\s*\)\s*" + ek + r"\s*\)"
                  r"|\*\s*\(\s*float\s*\*\s*\)\s*" + ek + r"(?![\w\[])")
            return (f"(({m.group(1)} *){e})", rd, fr, "PTR32" in m.group(1))
        return None

    def mentions(lv: str, s: str) -> bool:
        """s names the word's address at all (its pointer, its global, its address expression)"""
        lv = re.sub(r"\s+", "", lv)
        m = re.fullmatch(r"REFG\([^,]+,(0x[0-9a-f]+)\)", lv)
        if m:
            core = m.group(1)
        else:
            core = lv.lstrip("*")
            core = re.sub(r"^\(\([\w*]+\)(.*)\)$", r"\1", core)
            core = re.sub(r"^\([\w*]+\)", "", core).split("[")[0]
        return bool(core) and core.strip("()") in re.sub(r"\s+", "", s)

    def mark(s: str, rd: str, names=(), fr=None) -> str:
        """s with every read of the word as `@` (and the read variables; a float read `@F`)"""
        s = re.sub(rd, "@", s)
        if fr:
            s = re.sub(fr, "@F", s)
        for n in names:
            s = re.sub(r"(?<![\w.>])" + re.escape(n) + r"(?![\w\[(])", "@", s)
        return s

    def delta(e: str):
        """`@` 0, `@ + X` X, `@ - X` -(X); None for anything else that reads the word"""
        e = e.strip()
        if e == "@":
            return "0"
        m = re.fullmatch(r"@\s*([+-])\s*(.+)", e, re.S)
        if m and "@" not in m.group(2):
            x = m.group(2).strip()
            return f"(long)({x})" if m.group(1) == "+" else f"-(long)({x})"
        m = re.fullmatch(r"(.+?)\s*\+\s*@", e, re.S)
        if m and "@" not in m.group(1):
            return f"(long)({m.group(1).strip()})"
        return None

    def value(x: str, isptr: bool) -> str:
        # (a pointer's word: through uintptr_t, no truncation warning)
        if isptr or re.search(r"\*\s*\)|GEN_TOP\(", x) or x.strip() in ptrvars:
            return f"(long)(uintptr_t)({x})"
        return f"(long)({x})"

    def place(r: str, call: str, v: str) -> str | None:
        """the read `v = R` with the word's old value in R's `@`"""
        if r.count("@") != 1:
            return None
        if r.strip() == "@F":
            return f"{v} = gen_bits2f((uint)({call}));"
        if "@F" in r:
            return None
        if r.strip() == "@":
            if v in ptrvars:
                # (a pointer variable given the word: as Ghidra's own reads of it)
                return f"{v} = (void *)(uintptr_t)(uint)({call});"
            return f"{v} = {call};"
        return f"{v} = " + r.replace("@", f"(uint)({call})") + ";"

    def rewrite(stmts: list[str]) -> str | None:
        stmts = [s for s in stmts if s]
        # (`lock cmpxchg`: `V = *p; if (C == V) { *p = X; V = C; }`, the old value either way; or
        # with the old value unread, `if (C == *p) { *p = X; }`)
        if stmts and stmts[-1] == "}" and len(stmts) in (3, 4, 5):
            if len(stmts) == 3:
                m1 = re.fullmatch(r"if \((.+?) == (.+?)\) \{", stmts[0])
                m2 = re.fullmatch(r"(.+?)\s*=(?!=)\s*(.+);", stmts[1])
                if m1 and m2:
                    lvi = lvalue(m2.group(1))
                    if lvi:
                        a, rd, fr, isptr = lvi
                        l, r = mark(m1.group(1), rd), mark(m1.group(2), rd)
                        cmp = m1.group(1) if r.strip() == "@" else m1.group(2) if l.strip() == "@" else None
                        if cmp is not None and "@" not in mark(cmp, rd) and "@" not in mark(m2.group(2), rd):
                            return f"_InterlockedCompareExchange((volatile long *)({a}), {value(m2.group(2), isptr)}, " \
                                   f"{value(cmp, isptr)});"
                return None
            m0 = re.fullmatch(r"([A-Za-z_]\w*)\s*=\s*(.+);", stmts[0])
            m1 = re.fullmatch(r"if \((.+?) == (.+?)\) \{", stmts[1])
            m2 = re.fullmatch(r"(.+?)\s*=(?!=)\s*(.+);", stmts[2])
            if m0 and m1 and m2:
                v = m0.group(1)
                lvi = lvalue(m2.group(1))
                if lvi:
                    a, rd, fr, isptr = lvi
                    r0 = mark(m0.group(2), rd)
                    cmp = m1.group(1) if m1.group(2).strip() == v else m1.group(2) if m1.group(1).strip() == v else None
                    ok_tail = len(stmts) == 4 or re.fullmatch(re.escape(v) + r"\s*=\s*" + re.escape(cmp or "~") + r"\s*;",
                                                               stmts[3])
                    if cmp is not None and ok_tail and "@" not in mark(m2.group(2) + cmp, rd) and r0.count("@") == 1:
                        call = f"_InterlockedCompareExchange((volatile long *)({a}), {value(m2.group(2), isptr)}, " \
                               f"{value(cmp, isptr)})"
                        return place(r0, call, v)
            return None
        parts = []
        for s in stmts:
            m = re.fullmatch(r"(.+?)\s*=(?!=)\s*(.+);", s, re.S)
            if not m:
                return None
            parts.append((m.group(1).strip(), m.group(2).strip(), s))
        # (the write: the first statement to a memory word; the reads, every one before it, of the
        # same word into a variable; after it, statements the scheduler moved in that touch neither)
        w = next((k for k, p in enumerate(parts) if lvalue(p[0]) is not None), None)
        if w is None:
            return None
        lv, rhs, _ = parts[w]
        a, rd, fr, isptr = lvalue(lv)
        reads, tail = parts[:w], parts[w + 1:]
        names = []
        for v, r, _ in reads:
            if not re.fullmatch(r"[A-Za-z_]\w*", v) or mark(r, rd, (), fr).count("@") != 1:
                return None
            names.append(v)
        # (Ghidra's repeated reads, `u = G; u = G; i = G; G = u;`, are one: every variable the old value)
        if len(reads) > 1 and not all(mark(r, rd).strip() == "@" for _, r, _ in reads):
            return None
        for tv, tr, _ in tail:
            t = mark(tv + " = " + tr, rd, names, fr)
            if "@" in t or re.search(r"\b(?!REFG\b)[A-Za-z_]\w*\s*\(", re.sub(r"\(\s*[\w\s]+\**\s*\)", "", tr)):
                return None
        e = mark(rhs, rd, names)
        d = delta(e)
        if d is not None:
            call = f"_InterlockedExchangeAdd((volatile long *)({a}), {d})"
        elif "@" not in e and not re.search(r"(?<![\w.>])(" + "|".join(map(re.escape, names or ["\0"])) + r")(?![\w])", rhs) \
                and not mentions(lv, rhs):
            # (an exchange's value reads nothing of the word in any type: `*(int *)p = (int)f(*(float *)p)
            # - 0x8000` read outside the exchange was GrassRenderer's lost update, 0x6519d0)
            call = f"_InterlockedExchange((volatile long *)({a}), {value(rhs, isptr)})"
        else:
            return None
        if not reads:
            out = [call + ";"]
        else:
            first = place(mark(reads[0][1], rd, (), fr), call, reads[0][0])
            if first is None:
                return None
            out = [first] + [f"{v} = {reads[0][0]};" for v, _, _ in reads[1:] if v != reads[0][0]]
        return " ".join(out + [s for _, _, s in tail])

    lines = c.split("\n")
    out, i = [], 0
    while i < len(lines):
        if lines[i].strip() == "LOCK();":
            j = next((k for k in range(i + 1, min(i + 10, len(lines))) if lines[k].strip() == "UNLOCK();"), None)
            if j is not None:
                # (a statement Ghidra broke over lines joined: `*p =\n f(*p) - 0x8000;`)
                body = " ".join(l.strip() for l in lines[i + 1:j])
                stmts = [re.sub(r"\s+;$", ";", s.strip()) for s in re.split(r"(?<=[;{}])\s+", body) if s.strip()]
                rep = rewrite(stmts)
                if rep is not None:
                    out.append(re.match(r"[ \t]*", lines[i]).group(0) + rep)
                    i = j + 1
                    continue
        out.append(lines[i])
        i += 1
    return "\n".join(out)


def wide_subscripts(c: str) -> str:
    """A subscript the decompiler printed 64 bits wide, `puVar2[-0xffffffff00000002]`: x86's index
    wraps at 32 bits, `[ebx - 4]`, two shorts back. As a 64-bit constant it is +0xfffffffe elements,
    and the port wrote 8 GB past the pointer: a UI agent's reset loop 0x780040 corrupted the heap
    at character select, 26 functions and 90 subscripts like it (2026-10-31). Its 32-bit signed
    value, the offset the reference computes."""
    def rep(m):
        v = int(m.group(2), 16) * (-1 if m.group(1) else 1)
        v &= 0xFFFFFFFF
        v = v - (1 << 32) if v >= 1 << 31 else v
        return f"[{'-' if v < 0 else ''}{abs(v):#x}]"
    return re.sub(r"\[\s*(-)?\s*0x([0-9a-fA-F]{9,16})\s*\]", rep, c)


def switch_guarded_loads(c: str) -> str:
    """A load the decompiler hoisted above a switch out of the range check that guarded it, `uVar1 =
    *(table + *(int *)(p + 0x14) * 4); switch (id) { case 0x39: G = uVar1; ...`: the reference's
    `cmp ecx, 3; ja out` before the load, merged with the switch's own bound, read the table only for
    the cases. Run for every value, the load read wherever an unrelated value pointed: the bone
    physics config handler 0xa051e0, given every config change, faulted (2026-10-31). The load moves
    into each case, the variable read nowhere but in the cases and the load calling nothing."""
    lines = c.split("\n")
    i = 0
    while i < len(lines) - 1:
        m = re.fullmatch(r"([ \t]*)([A-Za-z_]\w*) = ([^;]*\*[^;]*);[ \t]*", lines[i])
        if not m or not re.match(r"[ \t]*switch\s*\(", lines[i + 1]):
            i += 1
            continue
        v, rhs = m.group(2), m.group(3)
        # (a read and nothing more: no call, no assignment, no increment)
        if re.search(r"\b[A-Za-z_]\w*\s*\(", re.sub(r"\(\s*[\w\s]+\**\s*\)", "", rhs)) \
                or re.search(r"[^=!<>]=[^=]|\+\+|--", rhs):
            i += 1
            continue
        # (the switch's block: its braces counted from its line)
        depth, end = 0, None
        for k in range(i + 1, len(lines)):
            depth += lines[k].count("{") - lines[k].count("}")
            if depth == 0 and "{" in "".join(lines[i + 1:k + 1]):
                end = k
                break
        if end is None:
            i += 1
            continue
        head = lines[i + 1].split("{", 1)[0]
        inside = lines[i + 2:end]
        rest = lines[:i] + lines[end + 1:]
        word = re.compile(rf"\b{re.escape(v)}\b")
        if word.search(head) or any(word.search(l) for l in rest
                                    if not re.fullmatch(rf"[ \t]+[A-Za-z_][\w ]*?[\s*]+{re.escape(v)}\s*;\s*", l)):
            i += 1
            continue
        # (assigned again inside a case: not the hoisted value alone)
        if any(re.search(rf"(?<![\w.>])\b{re.escape(v)}\s*(?:[-+*/|&^]|<<|>>)?=(?!=)", l) for l in inside):
            i += 1
            continue
        moved = []
        for l in inside:
            moved.append(l)
            if re.fullmatch(r"[ \t]*(?:case\s+[^:]+|default)\s*:[ \t]*", l):
                moved.append(f"{m.group(1)}  {v} = {rhs};")
        lines = lines[:i] + [lines[i + 1]] + moved + lines[end:]
        i += 1
    return "\n".join(lines)


def locked_reads(c: str) -> str:
    """An `xchg` with a global, `iVar1 = DAT_x; LOCK(); DAT_x = 1; UNLOCK();`: the decompiler reads
    the old value before the lock, and only the write is atomic. Two threads both read 0, both
    took the spin lock, and the job queue it guarded, 0x4a1010's in a VS2010 client, hung every
    thread on it, 2026-10-26. The read goes inside, as it is with a pointer's (`LOCK(); iVar1 =
    *piVar2; *piVar2 = 1; UNLOCK();`)."""
    return re.sub(r"^([ \t]*)(\w+\s*=\s*([\w.\[\]]+)\s*;)[ \t]*\n[ \t]*LOCK\(\);[ \t]*\n(?=[ \t]*\3\s*=(?!=))",
                  lambda m: f"{m.group(1)}LOCK();\n{m.group(1)}{m.group(2)}\n", c, flags=re.M)


def stack_vs_const(c: str) -> str:
    """A stack address compared with a small constant is never equal: _malloca's buffer checked
    for NULL after its 8-byte header, `&stack0x00000000 != &DAT_00000020` (__crtLCMapStringA_stat,
    __crtGetStringTypeA_stat, 2026-10-24). A stack lies far above the first 64 KB."""
    small = r"(?:&DAT_0000[0-9a-f]{4}|\(\w+ \*\)0x[0-9a-f]{1,4}|0x[0-9a-f]{1,4}|\d{1,5})"
    st = r"(?:\(\w+ \*\))?&stack0x[0-9a-f]{8}"
    c = re.sub(rf"{st}\s*!=\s*{small}|{small}\s*!=\s*{st}", "1", c)
    c = re.sub(rf"{st}\s*==\s*{small}|{small}\s*==\s*{st}", "0", c)
    return malloca_marker(c)


def malloca_marker(c: str) -> str:
    """_malloca's stack marker, which the decompiler drops: its buffer's header is 0xcccc
    (_ALLOCA_S_STACK_MARKER) on the stack path, 0xdddd (_ALLOCA_S_HEAP_MARKER) from malloc, and
    _freea frees only the second. The stack path's `mov [edx], 0xcccc` stores at a slot the
    decompiler places after the alloca fixup at a fixed `&stack0x...`, read back only through the
    pointer both paths join in (`p[-2] == 0xdddd`): a dead store to it, gone. Without it the header
    was whatever the port's frame held there (rhtest crt-O2's malloca). The store again, where one
    path sets the pointer to a stack address and the other stores 0xdddd through it"""
    for p in dict.fromkeys(re.findall(r"\*\s*(\w+)\s*=\s*0xdddd\s*;", c)):
        if re.search(r"\*\s*" + re.escape(p) + r"\s*=\s*0xcccc\b", c):
            continue
        # (the stack path's assignment of it, `p = (undefined4 *)&stack0xffffffec;`, before the
        # heap path's store)
        heap = re.search(r"\*\s*" + re.escape(p) + r"\s*=\s*0xdddd\s*;", c)
        s = re.search(r"(?m)^([ \t]*)" + re.escape(p) + r"\s*=\s*(?:\([^()]*\))?\s*&stack0x[0-9a-f]{8}\s*;[ \t]*$", c)
        if s and heap and s.start() < heap.start():
            c = c[:s.end()] + f"\n{s.group(1)}*{p} = 0xcccc;" + c[s.end():]
    return c


def neg_scaled(c: str) -> str:
    """A term scaled by a negative constant added to an address, `&DAT_x + (u >> 0x18) * -4` or
    `pfVar + uVar * -4`: x86 sums the address mod 2^32, a step back, but an unsigned `u * -4` is
    near 2^32 as C's 32-bit product, and added to a 64-bit pointer reaches 4 GB past it. A table
    on a client's sound path read at 0x1_0134f86c, 0xcee1d0 once that path ran, 2026-10-28. The term as the signed offset it is: `(int)(u * -4)`."""
    ptrs = set(re.findall(r"(?m)^\s*[A-Za-z_][\w ]*?\*+\s*(\w+)\s*;", c))
    out, last = [], 0
    for m in re.finditer(r" \* -(?:0x[0-9a-f]+|\d+)\b", c):
        i = m.start()
        if i < last:
            continue
        # the multiplicand: a parenthesised group or a name (indexed), each cast before it
        j = i
        if c[j - 1] == ")":
            d, j = 0, j - 1
            while j >= 0:
                d += {")": 1, "(": -1}.get(c[j], 0)
                if d == 0:
                    break
                j -= 1
        else:
            n = re.search(r"[A-Za-z_]\w*(?:\[[^\[\]]*\])?$", c[last:j])
            if not n:
                continue
            j = last + n.start()
        while True:
            cast = re.search(r"\((?:[A-Za-z_][\w ]*\**)\)$", c[last:j])
            if not cast:
                break
            j = last + cast.start()
        # (added to an address: a global's, or a pointer variable)
        # (not one cast to an integer first, `(int)piVar8 + ..`: 32-bit arithmetic already)
        base = re.search(r"(?:&\w+|&REFG\([^()]*\)|(?<![\w)*])(\w+)) \+\s+$", c[max(last, j - 200):j])
        if not base or (base.group(1) and base.group(1) not in ptrs):
            continue
        # (and the term ends there: `u * -10000 / 100` divides unsigned, its own value)
        if not re.match(r"\s*(?:[-+)\],;]|$)", c[m.end():]) or re.match(r"\s*->", c[m.end():]):
            continue
        out.append(c[last:j] + "(int)(" + c[j:m.end()] + ")")
        last = m.end()
    out.append(c[last:])
    return "".join(out)


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
    # (and their low parts, `in_AL` a byte function's result on the path that set none, `if (*this
    # == 0) return in_AL;`, a client's 0xa6feb0 on its frame path 2026-10-27)
    # (handed on to a call too, `FUN_00423ae0(p1, p2, p3, in_ECX)`: the word a `push ecx` reserved
    # and never set, passed as an empty object's by-value copy, garbage in the reference. A real
    # input pushed straight into a call, `push ecx; call [LeaveCriticalSection]`, is protos32.py's
    # parameter now, hkJobQueue::UnlockQueue 2026-10-31)
    entry = set(re.findall(r"\bin_(?:E[ACD]X|[ACD][LX])(?:_\d+)?\b", c))
    # (and a scratch register a keep convention leaves "unaffected", read only as the slot a `push
    # ecx` reserved: `mov al, [ebp - 1]` of a function returning its uninitialized bool, the
    # decompiler's `(byte)((uint)unaff_ECX >> 0x18)`, 276 stubs in a client 2026-10-27. protos32.py
    # gives a scratch register the function really reads a parameter of its own)
    entry |= set(re.findall(r"\bunaff_E[ACD]X(?:_\d+)?\b", c))
    # (and the upper bytes of eax a byte or word result came with, `CONCAT31(extraout_var, bVar3)`:
    # its callers read al, a bool's, and what the callee left above it is nothing they use)
    entry |= set(re.findall(r"\bextraout_var(?:_\d+)?\b", c))
    # (and st0 as the function found it, Ghidra's in_ST0 reused as the x87 result's variable, with
    # the x87 values calls left that are only copied into it, `in_ST0 = extraout_ST0;`: a function
    # typed float by its callers' reads that returns whatever st0 held on the paths that compute
    # nothing, `return in_ST0;`, 0 as the others. protos32.py gives a real st0 input a parameter.
    # A client's weather sound update 0x4af7c0, a stub on its frame path 2026-10-27)
    # (or returned itself, `return (float)extraout_ST1;`: what a callee left one below st0, never
    # popped into place, a client's font size analyzer 0x5584e0 on its startup 2026-10-27)
    if re.search(r"\bin_ST0\b", c):
        st_left = set(re.findall(r"\bextraout_ST\d(?:_\d+)?\b", c))
        lines_st = [l.strip() for l in c.split("\n")]
        # (the copy anywhere, a condition's comma expression too: `(uVar2 = FUN_00b6afa0(), in_ST0 =
        # extraout_ST0_00, uVar2 != 0)`, a scheduler clip's vf30 and 0xaef6e0, 2026-10-27)
        def only_copied(s, n):
            return not re.search(r"\b" + n + r"\b", re.sub(r"\bin_ST0 = " + n + r"(?=\s*[,;)])", "", s))
        # (or given its value by the call x87_icall_results found for it, `extraout_ST0_00 =
        # (*vf)(..);`: a value, no lost register. A sound driver's 0xcd6c00, whose tail call's st0 is
        # its result, the other paths returning st0 as they found it)
        if all(all(only_copied(s, n) or re.fullmatch(r"[A-Za-z_][\w ]*?\s+" + n + r";", s)
                   or re.fullmatch(r"return (?:\(\w+\))?" + n + r";", s)
                   or re.match(re.escape(n) + r" = \(", s)
                   for s in lines_st if re.search(r"\b" + n + r"\b", s)) for n in st_left):
            entry |= {"in_ST0"} | st_left
    # (and what a callee left in ecx or edx, where all it reaches is a store the next statement
    # overwrites: `push ecx` reserving an argument's slot, the decompiler's `uVar6 = extraout_ECX;
    # ... local_18 = (float *)uVar6; local_18 = (float *)*this_00;`, 0x415190 in a client, 2026-10-27)
    left = set(re.findall(r"\bextraout_E[CD]X(?:_\d+)?\b", c))
    names = set(RESULT_REG.findall(c)) | entry | left
    if not names:
        return set()
    lines = c.split("\n")
    stmts = [l.strip() for l in lines if l.strip()]

    def dead_store(s: str, v: str) -> bool:
        """`L = (cast)v;` (or `L = v;`) whose next statement writes L again without reading it"""
        m2 = re.fullmatch(r"(\w+)\s*=\s*(?:\([\w ]+\s*\**\s*\))?\s*" + v + r"\s*;", s)
        if not m2 or s not in stmts:
            return False
        i = stmts.index(s)
        if i + 1 >= len(stmts):
            return False
        nxt = re.fullmatch(re.escape(m2.group(1)) + r"\s*=\s*(.+);", stmts[i + 1])
        return bool(nxt) and not re.search(r"\b" + re.escape(m2.group(1)) + r"\b", nxt.group(1))

    def dead_local(v: str) -> bool:
        """a local whose every read is a dead store of it"""
        reads = [s for s in stmts if re.search(r"\b" + v + r"\b", s)
                 and not re.fullmatch(r"[A-Za-z_][\w ]*?[\s*]+" + v + r";", s)
                 and not re.fullmatch(v + r"\s*=\s*[^;]*;", s)]
        return bool(reads) and all(dead_store(s, v) for s in reads)
    ok = set(names)
    changed = True
    while changed:
        changed = False
        for n in list(ok):
            for line in lines:
                if not re.search(r"\b" + n + r"\b", line):
                    continue
                s = line.strip()
                # (of any type the decompiler gave it: `LPCRITICAL_SECTION extraout_EAX;`, what
                # LeaveCriticalSection left in eax, returned by a sound heap's create, 2026-10-26)
                if re.fullmatch(r"[A-Za-z_][\w ]*?[\s*]+" + n + r";", s):
                    continue                                    # its declaration
                if re.match(r"return\b", s):
                    continue
                m = re.fullmatch(r"(\w+)\s*=\s*(.+);", s)
                if m and m.group(1) == n:
                    continue                                    # written
                if m and m.group(1) in ok and re.fullmatch(r"(?:CONCAT44\()?[\w ,]+\)?", m.group(2)):
                    continue                                    # copied into another one
                # (copied whole into a local read only by returns: the debug printf FUN_00430c00
                # returns what OutputDebugStringA left in eax on one path, `uVar2 = extraout_EAX;
                # ... return uVar2;`, a result no caller reads, 2026-10-24)
                if m and m.group(2).strip() == n and returned_local(m.group(1), lines):
                    continue
                # (or into a local read elsewhere too, whose next mention after this is its return,
                # nothing jumping in between: `CoUninitialize(); uVar1 = extraout_EAX; } ...;
                # return uVar1;`, the COM teardown of a VS2010 client's 0xa0e240, whose one caller
                # drops the result, 2026-10-25)
                if m and m.group(2).strip() == n and next_is_return(m.group(1), lines, lines.index(line)):
                    continue
                # (or into one every other read of which a write of something else comes before)
                # (one of the lost names too: Ghidra's `in_EAX` reused as a local, TlsGetValue's
                # there and extraout_EAX after LeaveCriticalSection, Havok's removeReference
                # 0xd91a80; read before any write, it is the entry's and fails the same test)
                if m and m.group(2).strip() == n and reads_after_writes(m.group(1), lines, names - {m.group(1)}):
                    continue
                # (or a store the next statement overwrites, or a copy into a local only so stored)
                if dead_store(s, n) or (m and m.group(2).strip() == n and dead_local(m.group(1))):
                    continue
                # (or a copy into eax as the function found it, Ghidra's `in_EAX` reused as a local:
                # garbage into what is garbage there already, the reference's own eax on a path that
                # sets none. A bool method's path after a float callee, `in_EAX = extraout_EAX;
                # ... return extraout_EAX;`, its callers reading nothing, a client's 0xaf94c0, 2026-10-30)
                if m and m.group(2).strip() == n and re.fullmatch(r"in_E[ACD]X(?:_\d+)?", m.group(1)):
                    continue
                ok.discard(n)
                changed = True
                break
    return ok | entry


def icall_full_result(body: str) -> str:
    """A call through a pointer whose result Ghidra merged into a byte or word local, the rest of
    eax read after it as `extraout_var`: `bVar3 = ((code *)REFG(gen_code32, 0x1343098))(this, p);
    n = n + (int)CONCAT31(extraout_var, bVar3);`. The target returns all of eax (the reference's
    `call edx; add [ebp + 0x10], eax`), and the port's call through `code` returns all 32 bits,
    which the narrow assignment cut and returned_only's 0 replaced. The call's value kept whole in
    a local of its own, the CONCAT read as that. (The scheduler's TMB parser 0xbce490 sized a
    timeline's object arena, 0xbc1ec0, by the low byte of 0xbceda0's sum, and its bump allocator
    ran past it: the lobby's character select faulting in overwritten tracks, 2026-10-31.) A direct
    call's prototype gives its own width: a byte callee's bytes above are 0 there as here."""
    lines = body.split("\n")
    wide: dict[tuple[int, str], str] = {}
    for i, l in enumerate(lines):
        if re.match(r"\s*return\b", l):
            continue
        for m in reversed(list(re.finditer(r"CONCAT[123]1\((extraout_var(?:_\d+)?),\s*(\w+)\)", l))):
            v = m.group(2)
            for j in range(i - 1, -1, -1):
                a = re.fullmatch(rf"(\s*){re.escape(v)}\s*=\s*(\(\s*(?:\*\s*)?\(?\s*\(\s*(?:code|GEN_TCODE)\s*\*\).*\));\s*",
                                 lines[j])
                if a:
                    w = wide.get((j, v))
                    if w is None:
                        w = wide[(j, v)] = f"gen_eax{len(wide)}"
                        lines[j] = f"{a.group(1)}{v} = ({w} = {a.group(2)});"
                    l = l[:m.start()] + w + l[m.end():]
                    break
                if re.search(rf"\b{re.escape(v)}\s*=(?!=)", lines[j]) or re.match(r"\s*(?:LAB_\w+:|case\b|default:)", lines[j]):
                    break
        lines[i] = l
    if not wide:
        return body
    text = "\n".join(lines)
    d = re.search(r"(?m)^([ \t]*)[A-Za-z_][\w ]*?[ \t]+extraout_var(?:_\d+)?;[ \t]*$", text)
    if not d:
        return body
    return text[:d.start()] + "".join(f"{d.group(1)}uint {w} = 0;\n" for w in wide.values()) + text[d.start():]


def math_words(body: str) -> str:
    """A typed math import called with each double argument as the two words its caller pushed:
    the decompiler, given no prototype for an import it does not know (the ucrt's lrint at /Od),
    passes what was pushed, `lrint(uVar1, uVar2)`, and the typed adapter took one double, C2197
    (rhtest msvc-14.51-x86 fpenv-Od). Each double's pair, low word first, joined back."""
    out, i = [], 0
    for m in re.finditer(r"\bgen_imp_(\w+)\(", body):
        n = m.group(1)
        if m.start() < i or n not in MATH or "double" not in MATH[n][1]:
            continue
        j, depth, args, cur = m.end(), 1, [], ""
        while j < len(body) and depth:
            ch = body[j]
            if ch in "([":
                depth += 1
            elif ch in ")]":
                depth -= 1
                if depth == 0:
                    break
            if ch == "," and depth == 1:
                args.append(cur)
                cur = ""
            else:
                cur += ch
            j += 1
        args.append(cur)
        want = MATH[n][1]
        if len(args) != len(want) + want.count("double"):
            continue
        joined, k = [], 0
        for p in want:
            if p == "double":
                joined.append(f"gen_bits2d_(((unsigned long long)(unsigned int)({args[k + 1].strip()}) << 32) | "
                              f"(unsigned int)({args[k].strip()}))")
                k += 2
            else:
                joined.append(args[k].strip())
                k += 1
        out.append(body[i:m.end()])
        out.append(", ".join(joined))
        i = j
    out.append(body[i:])
    return "".join(out)


# the C runtime's functions that quiet a signalling NaN in st0, `test eax, 0x80000; jne; fadd
# [1.0]` of the NaN whose high word eax is (kept_st0): their effect on st0 at each call
ST0_QUIETERS = {"__convertTOStoQNaN"}

CAPTURE_SEG = re.compile(r"\bin_(?:ES|CS|SS|DS|FS|GS)\b")
CAPTURE_FLAG = re.compile(r"\bin_(?:AF|TF|IF|NT|AC|VIF|VIP|ID|CF|PF|ZF|SF|OF|DF)\b")


def context_capture(c: str) -> set[str]:
    """The registers a function records and nothing more: the CRT's failure reporters fill a CONTEXT
    with the segment registers, the flags, ebp and the return address (__report_gsfailure,
    __call_reportfault, `*(undefined2 *)&DAT_x = in_ES;`) for a crash report. The port has no x86
    machine state to record; 0 is what it records. Only segment registers and flags, and ebp and the
    return address in a function that records a segment register too, and each only stored into
    memory (an assignment's right side, a flags word or-ed together), never read otherwise."""
    # (ebp and the return address alone, stored into a global and nowhere else: __NLG_Notify's
    # record of the frame unwinding passes through, for a debugger, the same thing)
    if not CAPTURE_SEG.search(c):
        names = set(re.findall(r"\bunaff_(?:EBP|retaddr)\b", c))
        out = {n for n in names if all(
            re.fullmatch(rf"\s*(?:[A-Za-z_][\w ]*?[\s*]+{n};|(?:\*\s*\([^()]*\)\s*&?)?DAT_\w+\s*=\s*{n};)\s*", l)
            for l in c.split("\n") if re.search(rf"\b{n}\b", l))}
        # (and the flags word a pushfd made, each flag only a bit of it, `(uint)(in_ID & 1) *
        # 0x200000`: the CPUID probe's, which toggles ID through popfd and compares. Each 0, the
        # toggled bit still differs, and the probe finds CPUID, as every x64 host has it: VS2003's
        # ___sse2_available_init 0x72e54b, a stub the entry called, sands3 2026-11-01)
        for n in set(CAPTURE_FLAG.findall(c)):
            bit = rf"(?:\(\s*uint\s*\)\s*)?\(\s*{n}\s*&\s*1\s*\)\s*\*\s*(?:0x[0-9a-fA-F]+|\d+)"
            if all(re.fullmatch(rf"\s*[A-Za-z_][\w ]*?[\s*]+{n};\s*", l) or not re.search(rf"\b{n}\b", re.sub(bit, "", l))
                   for l in c.split("\n") if re.search(rf"\b{n}\b", l)):
                out.add(n)
        return out
    names = set(CAPTURE_SEG.findall(c)) | set(CAPTURE_FLAG.findall(c))
    # (and the general registers the CONTEXT records beside them, protos32 giving such a function
    # no register inputs: unaff_ESI and its kin)
    names |= set(re.findall(r"\bunaff_(?:EBP|retaddr|E[A-D]X|ESI|EDI)\b", c))
    lines = c.split("\n")
    out = set()
    for n in names:
        ok = True
        for i, line in enumerate(lines):
            if not re.search(rf"\b{n}\b", line):
                continue
            s = line.strip()
            if re.fullmatch(rf"[A-Za-z_][\w ]*?[\s*]+{n};", s):
                continue                                # its declaration
            # (the statement this line is part of: Ghidra wraps a long one, the flags word's)
            j = i
            while j > 0 and not re.search(r"[;{}]\s*$", lines[j - 1].strip()):
                j -= 1
            stmt = " ".join(l.strip() for l in lines[j:i + 1]).strip()
            m = re.match(r"(.+?)\s*=(?!=)\s*(.*)", stmt)
            # (stored somewhere: a global, through a pointer, or a local CONTEXT of the reporter's
            # own, __call_reportfault's, handed whole to UnhandledExceptionFilter)
            if not m or re.search(rf"\b{n}\b", m.group(1)):
                ok = False
                break
            rhs = m.group(2)
            # (nor as an address, cast to a pointer or subscripted, nor a call's argument; a product
            # in the flags word, `(in_AF & 1) * 0x10`, is no dereference)
            # (a flag is one bit, only ever or-ed into the word: no address, no argument)
            if not CAPTURE_FLAG.fullmatch(n) and re.search(
                    rf"\*\s*\)\s*\(?\s*{n}\b|\b{n}\s*\[|\[[^\]]*\b{n}\b|[A-Za-z_]\w*\s*\([^()]*\b{n}\b", rhs):
                ok = False
                break
        if ok:
            out.add(n)
    return out


def libm_flag(c: str) -> str | None:
    """The zero flag a VS2010 CRT math function's shared tail is entered with: its x87 entry
    point (`__CIsqrt`: `call __checkTOS_withFB; call tail`) and its C one (`_sqrt`: `call
    __fload_withFB`, falling into the tail) each leave ZF from `and eax, 0x7ff00000; cmp eax,
    0x7ff00000` on the argument's high word, the double's exponent all ones (a NaN or an infinity),
    and the tail branches on it first, `in_ZF`. As C: that test on the high word, the parameter
    the tail masks with 0xfffff (rhtest msvc-16.00-x86 float, 4 stubs a project)."""
    if not re.search(r"\bin_ZF\b", c):
        return None
    # (or that word in eax, where __fload_withFB and __checkTOS_withFB leave it: a VS2010 client's
    # cos/sin/tan/atan tails (0xc4ca78, 0xc4ce38, 0xc4d5e8, 0xc4f398) read only the low word off
    # the stack and test `in_eax & 0xfffff`; eax is the high word where ZF is set and its exponent
    # bits alone where not, the same test either way, 2026-10-30)
    m = re.search(r"\(\s*(param_\d+|in_eax)\s*&\s*0xfffff\s*\)", c)
    if not m:
        return None
    return f"(({m.group(1)} & 0x7ff00000) == 0x7ff00000)"


def declared_only(c: str) -> set[str]:
    """The lost names the decompiler declares and never uses: a parameter's other half as the
    caller's stack (`undefined2 in_stack_00000006;` beside __towlower_l's wint_t `_C`, which it
    reads as `*(uint *)&_C`: a stub a VS2010 client called, 2026-10-25). A local of its own in the
    port, unread."""
    out = set()
    for n in set(m.group(1) for m in LOST.finditer(c)):
        uses = [l for l in c.split("\n") if re.search(r"\b" + re.escape(n) + r"\b", l)]
        if all(re.fullmatch(r"\s*[A-Za-z_][\w ]*?[\s*]*\b" + re.escape(n) + r"\s*(?:\[[^\]]*\])?;\s*", l) for l in uses):
            out.add(n)
    return out


def upper_only(c: str) -> set[str]:
    """The registers the decompiler lost whose only reads are their upper bytes, `(uint3)((uint)V >>
    8)`, directly or through a local they are copied to (read so until it is assigned again): what
    is left above a byte a function sets in al and pushes whole, `mov al, [p + 0x21]; push eax`, a
    bool parameter whose callee reads the byte. The reference's bytes there are whatever eax held;
    0 in the port. A VS2010 client's 0x513790, `pvVar5 = extraout_EAX;` after EnterCriticalSection
    and then `uVar9 = (uint3)((uint)pvVar5 >> 8)`, 2,283 calls on its startup path."""
    # (a statement the decompiler wrapped over lines, on one: its pieces read together)
    joined, buf = [], ""
    for l in c.replace("\r", "").split("\n"):
        buf = (buf + " " + l.strip()) if buf else l
        if not l.strip() or re.search(r"[;{}:]\s*$", l) or l.strip().startswith(("/*", "#")):
            joined.append(buf)
            buf = ""
    if buf:
        joined.append(buf)
    lines = joined
    # (`(uint3)((uint)V >> 8)` or `(int3)(V >> 8)`: the three bytes above the low one)
    # (or masked to them, `V & 0xffffff00`, the same bytes kept in place: a bool built in cl over
    # what a callee left in ecx, `uVar5 = extraout_ECX & 0xffffff00; ... uVar5 | 1`, a client's
    # 0x693180 and its like stubbed, 2026-10-30)
    # (or the word around a status word's flags, `fnstsw ax; test ah, 0x44`: the decompiler's
    # `CONCAT22((short)((uint)V >> 0x10),(ushort)(byte)V)`, every byte of eax but the flags it read
    # into its compare already, a client's 0x5a0ab0 and 0x545bb0)
    # (through a float's bits too, `(int3)((uint)gen_fl2bits(fVar10) >> 8)`: a float local holding
    # what ecx was, its upper bytes a bool argument's, hkaSplineCompressedAnimation::vf4)
    upper = lambda v: (rf"(?:\(u?int3\)\(\s*(?:\(u?int\)\s*)?(?:gen_fl2bits\(\s*{re.escape(v)}\s*\)|{re.escape(v)})\s*>>\s*8\s*\)"
                       rf"|\b{re.escape(v)}\s*&\s*0xffffff00\b"
                       rf"|CONCAT22\(\(short\)\((?:\(uint\))?{re.escape(v)}\s*>>\s*0x10\),\s*\(ushort\)\(byte\){re.escape(v)}\)"
                       # (and with the flags set in, `CONCAT22((short)((uint)V >> 0x10), CONCAT11(f,
                       # (char)V))`, the status word's bits computed over the rest)
                       rf"|CONCAT22\(\(short\)\((?:\(uint\))?{re.escape(v)}\s*>>\s*0x10\),\s*CONCAT11\([^;]*?,\s*"
                       rf"\(char\){re.escape(v)}\)\)"
                       # (or above any low word, `CONCAT22((short)((uint)V >> 0x10), in_FPUControlWord)`:
                       # an x87 tail's `push edx; fnstcw [esp]`, the saved control word in edx's slot,
                       # 0xc4ca78 and its kin, 2026-10-30. Last: before the two above it took their
                       # head alone, their `(char)V` left a read, 0x545bb0 a stub again)
                       rf"|CONCAT22\(\(short\)\((?:\(uint\))?{re.escape(v)}\s*>>\s*0x10\),)")

    def reads_upper_only(v):
        """every read of v in the function its upper bytes, one at least (its assignments aside)"""
        seen = False
        for l in lines:
            if not re.search(rf"\b{re.escape(v)}\b", l) or re.match(rf"^\s*[\w ]+?[\s*]+{re.escape(v)}\s*;\s*$", l):
                continue
            # (or returned whole, on a path that sets no result: what the callee left in eax, nothing
            # a caller relies on there, returned_only's. `if (d < k) return extraout_EAX_00;` beside
            # the status word's `CONCAT22((short)(extraout_EAX_00 >> 0x10), ..)`: a client's
            # 0x545bb0, its early exit returning what _CIsqrt left, 2026-10-30)
            if re.fullmatch(rf"\s*return\s+(?:\([\w ]+\**\))?{re.escape(v)}\s*;\s*", l):
                continue
            # (its assignments anywhere on the line, a condition's comma expression's too, `(iVar2 =
            # 0, x != y)`: writes, no reads. A client's dynamically loaded calls, 0xb23680 and 15
            # like it, a bool argument built over a callee's ecx, 2026-10-30)
            rest = re.sub(rf"\b{re.escape(v)}\s*=(?!=)", "", l)
            stripped = re.sub(upper(v), "", rest)
            if re.search(rf"\b{re.escape(v)}\b", stripped):
                return False
            seen = seen or stripped != rest
        return seen

    def next_reads_upper(v, i):
        """the reads of v after line i, up to its next assignment, its upper bytes, one at least"""
        seen = False
        for l2 in lines[i + 1:]:
            if re.match(rf"^\s*{re.escape(v)}\s*=(?!=)", l2):
                # (its own value read in the assignment that ends it, the status word built over it,
                # `pfVar5 = (float *)CONCAT22((short)((uint)pfVar5 >> 0x10), CONCAT11(.., (char)pfVar5))`:
                # those reads count, a client's 0x9b8500 after an inlined RandomRange, 2026-10-30)
                rhs = re.sub(rf"^\s*{re.escape(v)}\s*=(?!=)", "", l2)
                if re.search(rf"\b{re.escape(v)}\b", rhs):
                    if re.search(rf"\b{re.escape(v)}\b", re.sub(upper(v), "", rhs)):
                        return False
                    seen = True
                break
            if re.search(rf"\b{re.escape(v)}\b", l2):
                reads = re.sub(upper(v), "", re.sub(rf"\b{re.escape(v)}\s*=(?!=)", "", l2))
                if re.search(rf"\b{re.escape(v)}\b", reads):
                    return False
                seen = seen or re.search(upper(v), l2) is not None
        # (or none on to its next assignment but the loop's next round: from the top of the `do {`
        # it is assigned in, `do { f(.., (uint)p & 0xffffff00); ..; p = extraout_ECX_00; } while`,
        # a bool built over what each call left in ecx, 0xdad7f0)
        if not seen:
            # (out through the blocks it is in, an `if` inside the loop's body, to the `do {`)
            depth, k = 0, i - 1
            while k >= 0:
                depth += lines[k].count("}") - lines[k].count("{")
                if depth < 0:
                    if lines[k].strip() == "do {":
                        break
                    depth = 0
                k -= 1
            if k >= 0 and lines[k].strip() == "do {":
                for l2 in lines[k + 1:i]:
                    if re.match(rf"^\s*{re.escape(v)}\s*=(?!=)", l2):
                        break
                    if re.search(rf"\b{re.escape(v)}\b", l2):
                        reads = re.sub(upper(v), "", re.sub(rf"\b{re.escape(v)}\s*=(?!=)", "", l2))
                        if re.search(rf"\b{re.escape(v)}\b", reads):
                            return False
                        seen = seen or re.search(upper(v), l2) is not None
        return seen

    out = set()
    # (and a callee-saved register's, the caller's bits above a byte set over it, `sete bl; push
    # ebx`: `CONCAT31((int3)((uint)unaff_EBX >> 8), b == 0)`, a bool argument, 0x79dbe0)
    for n in set(re.findall(r"\b(?:extraout_E[A-D]X|unaff_E(?:[A-D]X|SI|DI)|in_E[A-D]X)(?:_\d+)?\b", c)):
        ok = True
        for i, l in enumerate(lines):
            if not re.search(rf"\b{n}\b", l) or re.match(rf"^\s*[\w ]+?[\s*]+{n}\s*;\s*$", l):
                continue
            m = re.fullmatch(rf"\s*([A-Za-z_]\w*)\s*=\s*(?:\([^()]*\)\s*)?{n}\s*;\s*", l)
            # (or in a condition's comma expression, `(b = f(x), uVar9 = extraout_EDX_00, b == 0)`,
            # the rest of the line no read of it)
            m2 = None if m else re.search(rf"(?:^|[(,;]\s*)([A-Za-z_]\w*)\s*=\s*(?:\([^()]*\)\s*)?{n}\s*(?=[,;)])", l)
            if m2 and re.search(rf"\b{n}\b", l[:m2.start(1)] + l[m2.end():].replace(n, "", 1)):
                m2 = None
            if m or m2:
                # (copied to a local: read for its upper bytes alone, next, or anywhere it is read)
                v2 = (m or m2).group(1)
                ok = next_reads_upper(v2, i) or reads_upper_only(v2)
            elif re.search(rf"\b{n}\b", re.sub(upper(n), "", l)):
                ok = False
            if not ok:
                break
        if ok:
            out.add(n)
    return out


def filler_args(c: str) -> set[str]:
    """The result registers the decompiler lost that are read only as whole arguments of calls:
    what a caller pushes for a parameter the callee never reads. /LTCG folds a constant argument
    into its callee and keeps the slot, `fc4(a, 2, c, -1)` reading ecx and one stack word but
    popping two, and its caller pushes what ecx holds there, `extraout_ECX` after the call
    before (rhtest calls-GL, 2026-10-24). 0 in the port."""
    # (or through a local it is copied to, `piVar2 = extraout_ECX;`, that is only ever assigned or
    # passed whole so: /GL's opener pushes ecx, whatever seek3 left there, for the lo seek3 ignores,
    # rhtest msvc-14.51-x86 calls-GL 2026-10-25)
    # (or stored where the next statement stores again without reading it: x87's `push ecx; fstp
    # [esp]` reserves a float argument's slot with whatever ecx holds, `local_d4 = extraout_ECX;
    # local_d4 = fVar12;` (a VS2010 client's FUN_004152c0, a stub, 2026-10-25))
    lines = c.split("\n")
    body = [l for l in lines if l.strip()]

    def dead_store(l):
        m = re.fullmatch(r"\s*([A-Za-z_]\w*)\s*=\s*(?:\([^()]*\)\s*)?[A-Za-z_]\w*\s*;\s*", l)
        if not m:
            return False
        k = next((i for i, x in enumerate(body) if x is l), None)
        if k is None or k + 1 >= len(body):
            return False
        nxt = re.fullmatch(r"\s*" + re.escape(m.group(1)) + r"\s*=(?!=)([^;]*);\s*", body[k + 1])
        return bool(nxt) and not re.search(r"\b" + re.escape(m.group(1)) + r"\b", nxt.group(1))

    def filler(n, seen):
        uses = [l for l in lines if re.search(r"\b" + re.escape(n) + r"\b", l)
                and not re.fullmatch(r"\s*[A-Za-z_][\w ]*?[\s*]*\b" + re.escape(n) + r";\s*", l)]
        if not uses:
            return False
        for l in uses:
            if re.fullmatch(r"\s*" + re.escape(n) + r"\s*=(?!=)[^;]*;\s*", l) and n not in seen[:1]:
                continue                                  # (a local's own assignment)
            if n == seen[0] and dead_store(l):
                continue
            m = re.fullmatch(r"\s*([A-Za-z_]\w*)\s*=\s*" + re.escape(n) + r"\s*;\s*", l)
            if m and m.group(1) not in seen:
                if not filler(m.group(1), seen + [m.group(1)]):
                    return False
                continue
            if len(re.findall(r"\b" + re.escape(n) + r"\b", l)) != len(re.findall(r"[(,]\s*" + re.escape(n) + r"\s*(?=[,)])", l)):
                return False
        return True
    out = set()
    # (and an xmm register as the function found it, passed on whole and read nowhere else: what a
    # callee's partial SSE writes made protos32 take for its input, `FUN_00c03850(in_XMM0_Da, ...,
    # L, 1)` where the CRT's _CIpow far below merges into xmm0, a VS2010 client's 0xbb9600
    # 2026-10-25. The function sets none of them, so whatever is there reaches the callee as it would)
    # (not a callee-saved register as the function found it, `FUN_0042cc20(local_5c, uVar1,
    # unaff_EDI)`: that was a word pushed earlier for a later call, -1 there, the call before
    # given it instead (protos32 next_call_deficit); 0 for it made an empty string, 2026-10-26)
    # (and the return address handed on whole: the CRT's x87 tails pass their frame to
    # _startOneArgErrorHandling, the saved control word, that word and the double above it, and
    # it reads the word and the double, 0xc4ca78 and its kin, 2026-10-30)
    for n in set(re.findall(r"\bextraout_E[ACD]X(?:_\d+)?\b|\bin_XMM\d+_D[a-d]\b|\bunaff_retaddr\b", c)):
        if filler(n, [n]):
            out.add(n)
    return out


def x87_pow(c: str) -> str:
    """ApplyFacts' __CIpow fixup, `fscale(from_bcd(x), y)`, as pow(x, y): whole, or split by the
    decompiler through a 10-byte temporary, `unkbyte10 Var1; Var1 = from_bcd((unkbyte10)x); ...
    fscale(Var1,(unkbyte10)y)`, which no C type holds (a Lua number formatter's 0xc03850)."""
    c = c.replace("fscale(from_bcd(", "pow((")
    # (and the rest of the library's x87 math, `fpatan(from_bcd(x), K)`: Ghidra32.h's gen_x87math,
    # K the function, ApplyFacts' call fixups by helpers32.py's MATH_CODES)
    # (the __cdecl double ones through their bits, `uVar3 = from_bcd((undefined8)gen_d2bits(x)); d =
    # gen_bits2d(fpatan(uVar3,0xd));`: the double itself in, the value out)
    c = re.sub(r"from_bcd\(\s*\((?:undefined8|ulonglong|longlong)\)\s*gen_d2bits\(", "from_bcd((", c)
    c = c.replace("gen_bits2d(fpatan(", "(fpatan(")
    c = c.replace("fpatan(from_bcd(", "GEN_X87MATH((")
    # (each temporary's uses by the assignment before them, in order, while still inside that
    # assignment's block: one temporary can be assigned again for a second power, `Var7 =
    # from_bcd(a); ... fscale(Var7, b) ... Var7 = from_bcd(c); ... fscale(Var7, d)`, a client's
    # camera update 0x4b1ed0, a stub on its frame path 2026-10-27)
    # (an assignment the decompiler wrapped over lines, `Var4 = from_bcd((unkbyte10)\n x);`, on one)
    # (and its `;` alone on the next line, `uVar1 = from_bcd(..(x))))\n ;`, a float's ceil, 0xd8aa60)
    c = re.sub(r"(?m)^([ \t]*\w+ = from_bcd\([^;]*\))[ \t]*\r?\n[ \t]*;", r"\1;", c)
    c = re.sub(r"(?m)^([ \t]*\w+ = from_bcd\()([^;]*?)\);",
               lambda m: m.group(1) + " ".join(m.group(2).split()) + ");", c)
    # (a double's bits loaded into an 8-byte integer and pushed as itself, `uVar5 = _DAT_007a9170;
    # uVar5 = from_bcd(uVar5); ... fpatan(uVar5,4)`: the double those bits are. POP.EXE's 0x449aa0,
    # 0x4382b0, sands3 2026-11-01)
    c = re.sub(r"(?m)^([ \t]*)(\w+) = from_bcd\(\s*\2\s*\);", r"\1\2 = from_bcd(gen_bits2d(\2));", c)
    for var in set(re.findall(r"(?m)^[ \t]*(\w+) = from_bcd\(", c)):
        lines = c.split("\n")
        cur, depth, at_depth, ok = None, 0, 0, True
        out = []
        for line in lines:
            m = re.fullmatch(r"[ \t]*" + re.escape(var) + r" = from_bcd\((.*)\);[ \t]*", line)
            if m:
                cur, at_depth = m.group(1), depth
                # (a double's two words, `from_bcd(CONCAT44(hi, lo))`: its bits, not the integer's
                # value. VS2010's cos/sin/tan SSE2 branches and their x87 fallbacks, 2026-11-01)
                if re.match(r"\s*CONCAT44\(", cur):
                    cur = f"gen_bits2d({cur.strip()})"
                depth += line.count("{") - line.count("}")
                continue
            if re.fullmatch(r"[ \t]*(?:unkbyte10|undefined8|ulonglong|longlong|double|float10)\s+" + re.escape(var)
                            + r"\s*;[ \t]*", line):
                # (kept where the variable is read as itself too, its bits above)
                if not re.search(r"\bfrom_bcd\(gen_bits2d\(" + re.escape(var) + r"\)\)", c):
                    continue
            if re.search(r"\b" + re.escape(var) + r"\b", line):
                if cur is None:
                    # (a use before any from_bcd, no math of it: an ordinary use)
                    if re.search(r"\b(?:fscale|fpatan)\(\s*" + re.escape(var) + r"\s*,", line):
                        ok = False
                        break
                    out.append(line)
                    depth += line.count("{") - line.count("}")
                    continue
                line = re.sub(r"\bfscale\(\s*" + re.escape(var) + r"\s*,", f"pow({cur},", line)
                line = re.sub(r"\bfpatan\(\s*" + re.escape(var) + r"\s*,", f"GEN_X87MATH({cur},", line)
                # (cur's own text aside: `pow(gen_bits2d(uVar5),` names the variable it was)
                if re.search(r"\b" + re.escape(var) + r"\b", line.replace(cur, "")):
                    ok = False
                    break
            depth += line.count("{") - line.count("}")
            if cur is not None and depth < at_depth:
                cur = None                              # (its block closed: no later use is its)
            out.append(line)
        if ok:
            c = "\n".join(out)
    # (and FPATAN's own operation, `fpatan(y, x)`, the C runtime's __CIatan2 by ApplyFacts' call
    # fixup or the instruction itself: atan2. Every fpatan the fixups above made is gone by now; one
    # on a from_bcd still is one of theirs left, not an atan2. Gated on no from_bcd at all, the 43
    # functions that also called another of the library's math kept a bare fpatan, 2026-10-27)
    c = re.sub(r"\bfpatan\((?!\s*from_bcd\()", "atan2(", c)
    # (the operands' casts to the 10-byte type, a double's value here)
    return c.replace("(unkbyte10)", "")


X87_ICALL = re.compile(r"\(\*+\s*\(code \*+\)|\(\*\w+\)\s*\(")


def x87_icall_results(c: str) -> str:
    """`extraout_ST0` read after a call through a pointer, the call's x87 result (st0) that the
    decompiler would not take for its return: read through st1 after a push, `call edx; fld1;
    fdivrp st(1)`, it is an extra output whatever the call-site override says. The call statement
    becomes the variable's assignment, `extraout_ST0 = (**(code **)(..))(args);`, which code_slots
    makes a call through gen_fcode (an XAudio2 effect's update, 307 functions, 2026-10-26).
    Only where nothing else is called between the call and the first read, and the variable is
    not read before the call."""
    # (and an indirect call already assigned, `fVar2 = (**(code **)..)(..); f((float)extraout_ST0)`:
    # its result in both, `extraout_ST0 = ..; fVar2 = extraout_ST0;`, a sound bus's update. And
    # several read together, `x(e_01 * e_00 * e)` after three calls: Ghidra numbers them in order,
    # extraout_ST0 the first call's, a bus's volume product, 2026-10-26)
    lines = c.split("\n")
    names = sorted(set(re.findall(r"\bextraout_ST0(?:_\d+)?\b", c)), key=lambda n: (len(n), n))

    # (the bit casts and Ghidra's piece macros are no calls: `local_10 = gen_bits2d((ulonglong)
    # gen_d2bits(dVar7) & 0xffffffff);` between a VFX distance's curve call and its read, 0x9af400)
    def plain(l):
        return l.endswith(";") and not re.search(r"[{}:]|\b(?:if|while|for|switch|return|goto|do)\b", l) \
            and not re.search(r"\b(?!(?:sizeof|gen_(?:bits2[fd]|[fd]2bits|fl2bits)|CONCAT\d+|SUB\d+|ZEXT\d+|SEXT\d+)\b)"
                              r"[A-Za-z_]\w*\s*\(", re.sub(r"\(\s*[\w ]+\s*\**\s*\)", "", l))

    def call_stmt(k):
        """(start, assigned name or None) of the indirect call statement ending on line k"""
        # (or its `;` alone on the line after, the decompiler's wrap of a long call: a member
        # pointer's `(**(code **)(&DAT_014a0c60 + i * 8))\n (this + adj, x)\n ;`, 0x999080's three
        # curve evaluations, stubs on a client's startup path, 2026-10-28)
        if not lines[k].rstrip().endswith(");") and not (
                lines[k].strip() == ";" and k > 0 and lines[k - 1].rstrip().endswith(")")):
            return None
        s = k
        while s > k - 4 and s >= 0:
            # (only back over a statement's own continuation lines: not past one that ends a
            # statement or opens a block, `(*vf)(p);\n if (b) {\n Leave(..);` taken for one call
            # ending at Leave's line, an EnterCriticalSection pool's x87 getter a stub, 0xcc40d0)
            if s < k and re.search(r"[;{}]\s*$", lines[s]):
                return None
            m = re.match(r"\s*(?:([A-Za-z_]\w*)\s*=\s*)?(\(\*.*)", lines[s])
            if m and X87_ICALL.match(m.group(2)):
                stmt = " ".join(l.strip() for l in lines[s:k + 1])
                return (s, m.group(1)) if stmt.count("(") == stmt.count(")") else None
            s -= 1
        return None

    def stmt_start(i):
        """the first line of the statement line i is part of (a wrapped one's continuation lines)"""
        while i > 0 and not re.search(r"[;{}:]\s*$", lines[i - 1]):
            i -= 1
        return i

    def static_guard(k):
        """the first line of a function-static's one-time init block ending on line k, `if
        ((*(uint *)&DAT_014a22e8 & 1) == 0) { DAT |= 1; ctor(&obj); _atexit(dtor); }`, or None: the
        compiler stores an x87 result before it (`call edx; mov eax, 1; fstp [ebp + 0xc]`), the
        decompiler reading it after as extraout_ST0. A VFX camera curve's evaluation, 0x9b1200, a
        stub a client's logo effect went through, 2026-10-28"""
        if lines[k].strip() != "}":
            return None
        depth, s = 0, k
        while s >= 0 and s > k - 24:
            depth += lines[s].count("}") - lines[s].count("{")
            if depth == 0:
                break
            s -= 1
        if s < 0 or depth != 0 or not re.match(r"\s*if \(\(\(?\*?\(?u?int \*\)?&?DAT_[0-9a-f]+\)? & \d+\) == 0\) \{\s*$",
                                                lines[s]):
            return None
        body = "\n".join(lines[s + 1:k])
        return s if re.search(r"\b_?atexit\(", body) and "{" not in body else None

    def block_open(k):
        """the line of the `{` the `}` on line k closes, or None"""
        depth, s = 0, k
        while s >= 0:
            depth += lines[s].count("}") - lines[s].count("{")
            if depth <= 0:
                return s if depth == 0 else None
            s -= 1
        return None

    def far_calls(first, want):
        """back from line `first`, past whatever calls nothing through a pointer unassigned: the
        nearest `want` indirect call statements whose result goes nowhere (and a block that holds
        none stepped over whole, its call or none run). Only straight up through one way in: no
        label, `case`, `} else {` or return on the way"""
        calls, k = [], first - 1
        while k >= 0 and len(calls) < want:
            l = lines[k].strip()
            if l.startswith("}") and l != "}":
                return None                              # (`} while (..);`, `} else {`)
            if not l or l.endswith(";") and not re.search(r"\b(?:return|goto|break|continue)\b", l) \
                    and not call_stmt(k):
                k -= 1
                continue
            cs = call_stmt(k)
            if cs:
                if cs[1] is None:
                    calls.append((cs[0], k, None))
                k = cs[0] - 1
                continue
            # (an `if` the decompiler wrapped, its condition over several lines, by its first)
            if l == "}":
                # (whatever it calls: a call inside an `if` the read is reached around is no value
                # the read can have on the other way, an assert's handler through a pointer,
                # `if (n == 0) { (*DAT_015d861c)("pTrackData != 0", ..); }`, 0xcddf40)
                o = block_open(k)
                # (and an if/else whole, from the else's `}` back to its `if`: the read after both
                # branches has the value from before them, a clip's `vf + 0xa8` result kept across
                # `if (..) { local_c = vf_ac(); } else { local_c = 0.0; }`, 0xbe61e0)
                while o is not None and re.match(r"\s*(?:\}\s*)?else\s*\{\s*$", lines[o]):
                    if lines[o].strip().startswith("}"):
                        depth, s2 = 1, o - 1
                        while s2 >= 0:
                            depth += lines[s2].count("}") - lines[s2].count("{")
                            if depth <= 0:
                                break
                            s2 -= 1
                        o = s2 if s2 >= 0 and depth == 0 else None
                    else:
                        # (`}` on the line before, `else {` on its own)
                        p2 = o - 1
                        while p2 >= 0 and not lines[p2].strip():
                            p2 -= 1
                        o = block_open(p2) if p2 >= 0 and lines[p2].strip() == "}" else None
                if o is None or not lines[o].rstrip().endswith("{") \
                        or not re.match(r"\s*(?:\}\s*else\s+)?if \(", lines[stmt_start(o)]):
                    return None
                k = stmt_start(o) - 1
                continue
            if l == "do {" or l.endswith("{") and re.match(r"\s*(?:if|while) \(", lines[stmt_start(k)]):
                k = stmt_start(k) - 1 if l != "do {" else k - 1
                continue
            # (a statement's continuation, `(..)\n ;` or an argument line, part of the one above)
            if not re.search(r"[;{}:]\s*$", l) and not re.match(r"(?:case\b|default\b|\w+:)", l):
                k -= 1
                continue
            return None
        return calls if len(calls) == want else None

    firsts = {}
    for v in names:
        decl = re.compile(r"^\s*float10\s+" + v + r"\s*;\s*$")
        uses = [i for i, l in enumerate(lines) if re.search(r"\b" + v + r"\b", l) and not decl.match(l)]
        if uses:
            firsts.setdefault(stmt_start(uses[0]), []).append(v)
    for first, group in sorted(firsts.items()):
        # (one name, its call earlier in the same statement assigned to a float local: that local,
        # `(dVar6 = (**(code **)(*p + 0xa4))(), fVar7 < extraout_ST0)`, a clip's time compare)
        if len(group) == 1:
            v = group[0]
            end = first
            while end < len(lines) and not re.search(r"\b" + v + r"\b", lines[end]):
                end += 1
            stmt = " ".join(lines[first:end + 1])
            at = stmt.find(v)
            m = None
            for m2 in re.finditer(r"\b([A-Za-z_]\w*)\s*=\s*\(\*+\s*\(code \*+\)", stmt[:at]):
                m = m2
            if m and re.search(r"(?m)^\s*(?:float10|float|double)\s+" + re.escape(m.group(1)) + r"\s*;", c):
                for i in range(first, end + 1):
                    lines[i] = re.sub(r"\b" + v + r"\b", f"(float10){m.group(1)}", lines[i])
                continue
        # back from the first read: as many indirect call statements as names, plain ones between
        calls, k = [], first - 1
        while k >= 0 and len(calls) < len(group):
            l = lines[k].strip()
            if not l:
                k -= 1
                continue
            cs = call_stmt(k)
            # (past one an earlier group took, `extraout_ST0_00 = (*vf)(..)`: its result is that
            # name's. Taken again as an assigned call, two curve calls' results were both the second's,
            # `extraout_ST0 = (*vf44)(..); extraout_ST0_00 = extraout_ST0;`, 0xcd4db0)
            if cs and cs[1] and re.fullmatch(r"extraout_ST0(?:_\d+)?", cs[1]):
                k = cs[0] - 1
                continue
            if cs:
                calls.append((cs[0], k, cs[1]))
                k = cs[0] - 1
                continue
            g = static_guard(k)
            if g is not None:
                k = g - 1
                continue
            # (and out of the block the read is in, through its opening: `if (0 < n) {`, `do {`,
            # a condition calling nothing. A sound root's volume, three curve calls' product read in
            # a loop over its voices, 0xcd2250. Never `} else {`: the branch above it did not run)
            if l == "do {" or re.fullmatch(r"(?:if|while) \((.*)\) \{", l) and \
                    plain(re.fullmatch(r"(?:if|while) \((.*)\) \{", l).group(1) + ";"):
                k -= 1
                continue
            if not plain(l):
                break
            k -= 1
        # (or past other calls, when the decompiler carried the product into a loop: a sound
        # voice's volume, three curve calls' `call edx; fmul [m]; fstp [ebp - 0x14]` multiplied
        # into [ebp - 4] before its loop over the voices, read there after each voice's own calls
        # as `FUN_00cd8a30(.., (float)(e_17 * (e_16 * e_15 * a) * b) * c)`, 0xcd50e0. Each name is
        # one call's value: read later, it is still that call's)
        if len(calls) != len(group):
            calls = far_calls(first, len(group)) or calls
        # (or the one call through a pointer whose result goes nowhere before the read in the whole
        # function: the value the compiler kept for it, past loops' heads the walk cannot cross. A
        # clip's `vf + 0xa4` duration, divided inside its track loop, 0xbe06d0)
        # (and several names, as many such calls before them as names, in order: Ghidra numbers
        # each call's result as the calls come, a clip blend's `vf + 0xb4` of its param and of its
        # child, 0xbc4740)
        if len(calls) != len(group):
            unassigned = [(cs[0], j, None) for j in range(first) if (cs := call_stmt(j)) and cs[1] is None]
            if len(unassigned) == len(group):
                calls = list(reversed(unassigned))
        if len(calls) != len(group):
            continue
        # (a call whose result goes to an integer returns in eax, not st0: `uVar3 = (*vf)(p); cVar2 =
        # (char)uVar3; in_ST0 = extraout_ST0_02;`, the function's own st0 kept across it and returned,
        # returned_only's. As the call's result, a sound root's vf108 0xcd2c90 was a stub)
        # (only where the value is no more than copied into in_ST0: an integer-typed variable may hold
        # an x87 result the decompiler mistyped, and as no call's, 0xcd9930 and 0xcddf40 were stubs)
        def float_var(n):
            return bool(re.search(r"(?m)^\s*(?:float10|float|double|longdouble)\s+" + re.escape(n) + r"\s*;", c))

        def only_to_in_st0(n):
            uses = [l for l in lines if re.search(r"\b" + n + r"\b", l) and not re.match(r"\s*float10\s+" + n + r"\s*;", l)]
            return bool(uses) and all(re.fullmatch(r"\s*in_ST0 = " + n + r";\s*", l) for l in uses)
        if any(assigned and not float_var(assigned) and only_to_in_st0(v)
               for v, (_s, _e, assigned) in zip(group, reversed(calls))):
            continue
        for v, (s, e, assigned) in zip(group, reversed(calls)):
            indent = lines[s][:len(lines[s]) - len(lines[s].lstrip())]
            if assigned:
                lines[s] = indent + v + " = " + lines[s].lstrip()[len(assigned):].lstrip()[1:].lstrip()
                lines[e] = lines[e] + f" {assigned} = {v};"
            else:
                lines[s] = indent + v + " = " + lines[s].lstrip()
    return "\n".join(lines)


def switch_offset(c: str) -> str:
    """A switch the decompiler writes on its normalized index with its cases labelled by the
    original values: `V = E - K; ... uVar5 = (&...switchdataD_...)[V]; switch(V) { case K + i: }`,
    a two-level jump table (a byte table, then the targets) reached through `sub reg, K`. Lua's
    suffixedexp switched on the token less 0x28 against cases '(' '.' ':' '[': no case ever matched,
    every expression ended at its first suffix, and a client's scripts failed to parse ("'=' expected").
    The switch is on V + K: its cases' values then mean what they say."""
    for m in re.finditer(r"switchdataD_[0-9a-f]+\)\s*\[\s*(\w+)\s*\]", c):
        v = m.group(1)
        k = re.search(rf"(?m)^\s*{re.escape(v)}\s*=\s*[^;]*?\s-\s*(0x[0-9a-f]+|\d+)\s*;", c)
        if not k:
            continue
        off = int(k.group(1), 0)
        sw = re.search(rf"switch\s*\(\s*{re.escape(v)}\s*\)\s*\{{", c[m.end():])
        if not sw:
            continue
        # (the cases this switch labels: up to the end of its block)
        start = m.end() + sw.end()
        depth, i = 1, start
        while i < len(c) and depth:
            depth += {"{": 1, "}": -1}.get(c[i], 0)
            i += 1
        cases = [int(x, 0) for x in re.findall(r"\bcase\s+(0x[0-9a-f]+|\d+)\s*:", c[start:i])]
        if cases and min(cases) >= off:
            c = c[:m.end()] + c[m.end():].replace(sw.group(0), f"switch({v} + {k.group(1)}) {{", 1)
    # (and one that switches on the byte table's entry itself, "Could not find normalized switch
    # variable to match jumptable": `V = E - K; switch((&..switchdataD_..)[V]) { case K + i: }`, its
    # cases labelled by E's values all the same. A UI module's lookup, param 1 its byte 0, matched
    # no case and returned -1 for every slot, 0xac29c0 2026-10-28)
    for m in list(re.finditer(r"switch\s*\(\s*\(\s*&[\w:]*switchdataD_[0-9a-f]+\s*\)\s*\[\s*(\w+)\s*\]\s*\)\s*\{", c)):
        v = m.group(1)
        k = re.search(rf"(?m)^\s*{re.escape(v)}\s*=\s*[^;]*?\s-\s*(0x[0-9a-f]+|\d+)\s*;", c[:m.start()])
        if not k:
            continue
        start, depth, i = m.end(), 1, m.end()
        while i < len(c) and depth:
            depth += {"{": 1, "}": -1}.get(c[i], 0)
            i += 1
        cases = [int(x, 0) for x in re.findall(r"\bcase\s+(0x[0-9a-f]+|\d+)\s*:", c[start:i])]
        if cases and min(cases) >= int(k.group(1), 0):
            c = c.replace(m.group(0), f"switch({v} + {k.group(1)}) {{", 1)
    return c


def load_corpus() -> dict[int, dict]:
    out = {}
    with open(CORPUS, encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            # (Ghidra writes Windows newlines; every pattern here reads \n. One it could not
            # decompile has an "error" and no C: no signature, so a stub)
            r["c"] = r.get("c", "").replace("\r\n", "\n").replace("\r", "\n")
            # (the CRT's x87 power, as ApplyFacts' call fixup writes it: `fscale(from_bcd(x), y)`,
            # p-code having no pow, is pow(x, y))
            # (and __CIatan2's, a bare fpatan(y, x), with no from_bcd of its own)
            if "from_bcd(" in r["c"] or "fpatan(" in r["c"]:
                r["c"] = x87_pow(r["c"])
            # (a cast to the 10-byte type around an x87 operation's operand, `fsin((unkbyte10)x)`
            # from the __CIsin fixup: a double's value here, no C type of its own)
            if "(unkbyte10)" in r["c"]:
                r["c"] = r["c"].replace("(unkbyte10)", "")
            # (a name the decompiler scoped from the global namespace, `::BTreeNode::Find(..)` in a
            # caller whose own namespace has another BTreeNode: the name itself, by_printed's. As
            # written no name C takes, 0xb54510 a stub, 2026-10-30)
            # (only a call's, after a cast, a parenthesis or an assignment: in a template's arguments
            # or a backquoted name the scope is the name's own, and stripped there 380 names no
            # longer matched the data's, 2026-10-30)
            if "::" in r["c"]:
                r["c"] = re.sub(r"(?<=[()=])(\s*)::(?=[A-Za-z_~][\w$~]*(?:::[A-Za-z_~][\w$~]*)*\s*\()", r"\1",
                                r["c"])
            # (FPREM's quotient, truncated through the 10-byte integer and back, `(float10)(unkint10)
            # (in_ST1 / in_st0)`: C's trunc, a double's value here. As a cast to bytes it was
            # vec_forms' vector, the C runtime's fmod loop 0xc4d3e4, 2026-10-30)
            if "(unkint10)" in r["c"] or "(unkuint10)" in r["c"]:
                r["c"] = re.sub(r"\(float10\)\s*\(unku?int10\)\s*(?:\(|([A-Za-z_]\w*)\b(?!\s*\())",
                                lambda m: f"(float10)trunc({m.group(1)})" if m.group(1) else "(float10)trunc(", r["c"])
            if "switchdataD_" in r["c"]:
                r["c"] = switch_offset(r["c"])
            # (a qualified name the decompiler wrapped, its class alone on a line and `::vf3(` on the
            # next: read as an unknown type, and the lobby connection's channel manager, a
            # two-statement setter, was a stub -- and with it the title menu's START, 2026-10-28)
            if "\n::" in r["c"]:
                r["c"] = re.sub(r"(?m)^([A-Za-z_][\w:]*)\n(::[A-Za-z_~]\w*\s*\()", r"\1\2", r["c"])
            if "extraout_ST0" in r["c"]:
                r["c"] = x87_icall_results(r["c"])
            out[int(r["addr"], 16)] = r
    return out


# the widths of the scalar types the decompiler gives a global in a function (corpus "gt"), for one
# the data export has no entry for (global_lvalue). Others (structures, unknown names) None
GT_SIZES = {
    1: {"undefined", "undefined1", "byte", "char", "uchar", "sbyte", "bool", "int1", "uint1", "BYTE", "CHAR",
        "BOOLEAN", "UCHAR"},
    2: {"undefined2", "short", "ushort", "word", "wchar_t", "wchar16", "int2", "uint2", "WORD", "SHORT", "USHORT",
        "WCHAR"},
    4: {"undefined4", "int", "uint", "long", "ulong", "dword", "float", "int4", "uint4", "float4", "code",
        "pointer", "BOOL", "DWORD", "INT", "UINT", "LONG", "ULONG", "HRESULT", "HANDLE", "HMODULE",
        "HINSTANCE", "HWND", "HIMC", "PVOID", "LPVOID", "FARPROC", "size_t", "UINT_PTR", "ULONG_PTR",
        "DWORD_PTR", "LPCRITICAL_SECTION"},
    8: {"undefined8", "double", "longlong", "ulonglong", "qword", "int8", "uint8", "float8", "LONGLONG",
        "ULONGLONG", "DWORD64", "DWORDLONG", "__time64_t"},
}


def gt_size(t: str) -> int | None:
    t = t.strip()
    if t.endswith("*"):
        return 4
    return next((n for n, names in GT_SIZES.items() if t in names), None)


# the integer types the decompiler gives a global (corpus "gt"): one it gave only these in a function
# is an integer there, whatever loads elsewhere read it as (global_lvalue)
INT_GT = re.compile(r"undefined[1248]?|u?int|u?long|u?longlong|u?short|byte|char|uchar|sbyte|bool|word|dword|qword")


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


SETJMP_CALL = re.compile(r"\bgen_imp_(_setjmp3|_setjmp|setjmp|longjmp)\s*\(")
# (the same functions linked into the image, by the names Ghidra's function ID gives them: VS2010's
# /MT __setjmp3, and longjmp as `FID_conflict:___longjmp_internal`)
SETJMP_NAME = re.compile(r"(?:FID_conflict:)?_*(setjmp3|setjmp|longjmp|longjmp_internal)")
# (and the C runtime's frame helpers beside them, fidelity32's "folded": x86 that builds or tears
# down its caller's frame, moves the return address, or saves the caller's registers and esp. The
# decompiler injects each at every call (x86win.cspec's fixups, ApplyFacts' rh_SEH_prolog4), and the
# translator's frame code and GEN_SETJMP are the port's own; their bodies are the caller's frame, no
# C function's. 8 stubs of a VS2010 client, unaff_EBX and unaff_retaddr, none called, 2026-10-31)
FOLDED_NAME = re.compile(r"(?:FID_conflict:)?_*(?:setjmp3|setjmp|longjmp|longjmp_internal|"
                         r"(?:EH_prolog3|EH_epilog3|SEH_prolog4|SEH_epilog4)(?:_GS|_catch|_catch_GS)?|"
                         r"SEH_prolog|SEH_epilog|EH_prolog|"   # (VS2003's, sands3 2026-11-01)
                         r"alloca_probe(?:_8|_16)?|chkstk)")


def jump_calls(body: str, linked: dict[int, str] | None = None) -> str:
    """setjmp and longjmp the port's own (Ghidra32.h GEN_SETJMP, GEN_LONGJMP): `gen_imp__setjmp3(buf,
    0)` a setjmp in this function, on the native jmp_buf for buf, `gen_imp_longjmp(buf, v)` a
    longjmp to it. Through an adapter, the setjmp's frame was the adapter's, gone when longjmp came
    (and the CRT's x86 _setjmp3 no function of the port's: rhtest misc 2026-10-24). `linked`: the
    image's own setjmp and longjmp, {address: "setjmp" or "longjmp"}, called as F_<address>: a
    static C runtime's, x86 code that saves and restores registers and esp, which a translation
    cannot do (rhtest msvc-16.00-x86 misc jumps)."""
    pattern = SETJMP_CALL
    if linked:
        pattern = re.compile(r"\b(?:gen_imp_(_setjmp3|_setjmp|setjmp|longjmp)|("
                             + "|".join(f"F_{x:08x}" for x in linked) + r"))\s*\(")
    out, i = [], 0
    for m in pattern.finditer(body):
        if m.start() < i:
            continue
        open_ = m.end() - 1
        close = match_paren(body, open_)
        args = split_top(body[open_ + 1:close - 1])
        kind = m.group(1) or linked[int(m.group(2)[2:], 16)]
        if kind == "longjmp":
            new = f"GEN_LONGJMP({args[0].strip()}, {args[1].strip() if len(args) > 1 else '1'})"
        else:
            new = f"GEN_SETJMP({args[0].strip()})"
        out.append(body[i:m.start()])
        out.append(new)
        i = close
    out.append(body[i:])
    return "".join(out)


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
    """The index just past the parenthesis group that opens at s[i]. (Not counting those in a
    string or character literal: `F_00d9fe80(buf,"Block (")`, the undecorator's strings in
    a VS2010 client, 2026-10-25.)"""
    depth = 0
    j = i
    while j < len(s):
        ch = s[j]
        if ch in "\"'":
            k = j + 1
            while k < len(s) and s[k] != ch:
                k += 2 if s[k] == "\\" else 1
            j = k + 1
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    return -1


# (a pointer just loaded from its 4-byte slot, `*(T * PTR32 *)x`: ptr32_derefs)
PTR32_LOAD = re.compile(r"\*\s*\(\(?\s*(?:struct\s+)?(?P<b>[A-Za-z_]\w*)(?:\s+[A-Za-z_]\w*)*(?:\s*\*\s*PTR32)*"
                        r"\s*\*\s*PTR32\s*\*\s*\)")


def ptr32_derefs(body: str) -> str:
    """The checked build's blind spot (CMake GEN_CHECKED, runtime32/Checked.cpp): clang's
    AddressSanitizer pass checks no load or store through a __ptr32 pointer (LLVM's address space
    271), 1.7% of the translation's, sampled 2026-10-31. Where a pointer just loaded from its slot is
    dereferenced, `**(T * PTR32 *)x`, `*(*(T * PTR32 *)x + n)`, `(*(T * PTR32 *)x)[i]` or `->f`,
    the access is spelled GEN_NE(...), Ghidra32.h: in the checked build the lvalue at its own
    address converted to a host pointer (the address computed the 32 bits' way first, as before), so
    checked, 0.12% left; in any other build the lvalue as it is, the same code (MSVC's objects for
    translated_100.c and _150.c identical, 2026-10-31)."""
    spans: list[tuple[int, int]] = []
    for m in PTR32_LOAD.finditer(body):
        # (not a function's pointer, called, nor a volatile access: GEN_NE's cast drops the qualifier)
        if m.group("b") == "code" or "volatile" in m.group(0):
            continue
        k = m.start() - 1
        while k >= 0 and body[k] in " \t":
            k -= 1
        if k < 0:
            continue
        if body[k] == "*":
            # `**(T * PTR32 *)x`: a dereference, not a product (`a * *p` has no pointer to multiply)
            p = k - 1
            while p >= 0 and body[p] in " \t":
                p -= 1
            if p >= 0 and (body[p].isalnum() or body[p] in "_)]"):
                continue
            spans.append((k, operand_end(body, k)))
        elif body[k] == "(":
            j = match_paren(body, k)
            if j < 0:
                continue
            # `*(*(T * PTR32 *)x + n)`: the group dereferenced, its address the 32 bits' sum
            p = k - 1
            while p >= 0 and body[p] in " \t":
                p -= 1
            if p >= 0 and body[p] == "*":
                q = p - 1
                while q >= 0 and body[q] in " \t":
                    q -= 1
                if q < 0 or not (body[q].isalnum() or body[q] in "_)]"):
                    spans.append((p, j))
                    continue
            # `(*(T * PTR32 *)x)` subscripted or a member taken: the group and those, no call
            if not (body.startswith("[", j) or body.startswith("->", j)):
                continue
            e = j
            while True:
                if body.startswith("[", e):
                    depth = 0
                    for q in range(e, len(body)):
                        depth += body[q] == "["
                        depth -= body[q] == "]"
                        if depth == 0:
                            e = q + 1
                            break
                    else:
                        break
                elif body.startswith("->", e) and (mm := re.match(r"->\s*[A-Za-z_]\w*", body[e:])):
                    e += mm.end()
                else:
                    break
            if body.startswith("(", e):
                continue   # (a call: its result is no lvalue)
            spans.append((k, e))
    if not spans:
        return body
    # (opened outermost first, closed innermost first; a span's end before another's start at one place)
    marks = [(s, 1, -e, "GEN_NE(") for s, e in spans] + [(e, 0, -s, ")") for s, e in spans]
    out = body
    for pos, _kind, _o, text in sorted(marks, key=lambda x: (x[0], x[1], x[2]), reverse=True):
        out = out[:pos] + text + out[pos:]
    return out


BOOL_PRODUCT = re.compile(r"\((ulonglong|longlong)\)\s*(!?)\s*\(")
OPERAND = re.compile(r"\s*\*\s*((?:\(\s*(?:unsigned\s+)?[A-Za-z_]\w*\s*\**\s*\)\s*)*)")


def bool_products(body: str) -> str:
    """`(ulonglong)(c) * x`, Ghidra's branchless select of x or 0 (and the call fixups' bodies'),
    as `(c ? x : 0)`: MSVC's x64 optimizer (14.51, /O1 and /O2) computes some of them in 32 bits,
    `(ulonglong)(k < 0x40) * (v >> k)` and `(ulonglong)(c) * v` with their high halves 0. rhtest
    int64 sum_lcg read its shifted values' low words alone, 2026-10-25."""
    # (nested ones, the operand itself a product, a pass each)
    for _ in range(8):
        out, i, changed = [], 0, False
        while True:
            m = BOOL_PRODUCT.search(body, i)
            if not m:
                break
            c0 = m.end() - 1
            c1 = match_paren(body, c0)
            om = OPERAND.match(body, c1) if c1 > 0 else None
            if om is None:
                out.append(body[i:m.end()])
                i = m.end()
                continue
            j = om.end()
            # (the operand: a parenthesized expression, or a name with its calls and subscripts,
            # each after the casts OPERAND took)
            if j < len(body) and body[j] == "(":
                k = match_paren(body, j)
            else:
                nm = re.match(r"[A-Za-z_]\w*", body[j:])
                k = j + nm.end() if nm else -1
                while 0 < k < len(body) and body[k] in "([":
                    k = match_paren(body, k) if body[k] == "(" else body.find("]", k) + 1
            if k <= j:
                out.append(body[i:m.end()])
                i = m.end()
                continue
            cond = body[c0:c1]
            # (only a condition, a comparison or a logical operator at its top level, or one
            # negated: `(ulonglong)(a + b) * c` is a product)
            top = cond[1:-1]
            while True:
                q = top.find("(")
                if q < 0:
                    break
                e = match_paren(top, q)
                if e < 0:
                    break
                top = top[:q] + " " + top[e:]
            if not m.group(2) and not re.search(r"(?<![<>])[<>]=?(?![<>])|[=!]=|&&|\|\|", top):
                out.append(body[i:m.end()])
                i = m.end()
                continue
            operand = om.group(1) + body[j:k]
            test = f"!{cond}" if m.group(2) else cond
            out.append(body[i:m.start()])
            out.append(f"(({m.group(1)})({test} ? ({operand}) : 0))")
            i = k
            changed = True
        out.append(body[i:])
        body = "".join(out)
        if not changed:
            break
    return body


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


def printed_name(n: str) -> str:
    """A function's name as the decompiler prints it in C: a Function ID conflict's `FID_conflict:`
    as `FID_conflict_`, a backquoted scope's ` and ' as _"""
    if n.startswith("FID_conflict:"):
        n = "FID_conflict_" + n[len("FID_conflict:"):]
    return n.replace("`", "_").replace("'", "_")


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
        # (the name as the head has it, its conventions gone too: a template over a function
        # pointer type, `__crt_fast_encode_pointer<void_(__stdcall*)(void*,unsigned_long,void*)>`,
        # no signature, rhtest stl-O2)
        hname = CC.sub("", name) if name else name
        # (a Function ID conflict's, which the head prints `FID_conflict_` for `FID_conflict:`)
        # (and a backquoted scope's ` and ' as _)
        if name and hname not in head:
            printed = printed_name(hname)
            if printed in head:
                hname = printed
        if name:
            head = head.replace(hname + " (", hname + "(")
        # (the corpus's own name, where the head has it: a template's name has spaces and commas
        # in it, `void std::basic_string<char, ...>::assign(...)`, that no pattern takes whole)
        at = head.find(hname + "(") if name else -1
        if at > 0:
            self.ret, self.name, p = head[:at].strip() or "void", name, head[at + len(hname) + 1:].rstrip()
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
        # (the enums the decompiler names anywhere, `enum CV_methodprop_e`: an unexported one is an int)
        self.enum_words = {w for r in self.corpus.values() if "enum" in r.get("c", "")
                           # (a scoped one by its last part, as the decompiler declares it: `enum
                           # std::ios_base::event` in a comment, `event param_1` in the signature,
                           # std::ios_base::_Callfns a stub on a client's path, "type event")
                           for w in re.findall(r"\benum\s+(?:[A-Za-z_]\w*::)*([A-Za-z_]\w*)", r["c"])}
        self._pe = None                           # (truncates: the image, opened when first read)
        self._library_from = None                 # (is_library's start, found when first asked)
        # (the image's own setjmp and longjmp, a static C runtime's: jump_calls)
        self.linked_jumps = {a: "longjmp" if "longjmp" in m.group(1) else "setjmp" for a, r in self.corpus.items()
                             if (m := SETJMP_NAME.fullmatch(r["name"]))}
        self.refdata, self.ref_names = load_refdata()
        # (data named for a function's local class, `` `public: static void __cdecl X::Update(
        # Skeleton*_const,float,..)'::__l2::SetToReferencePose::vftable ``: no name a scan can
        # take, its quote read as a character literal's. By address, DAT_x, as data with no name)
        odd = sorted(((n, a) for n, a in self.ref_names.items() if "`" in n), key=lambda x: -len(x[0]))
        if odd:
            for r in self.corpus.values():
                if "`" in r.get("c", ""):
                    # (its long name wrapped by the decompiler after the quote, `'\n    ::__l2::..`)
                    r["c"] = re.sub(r"'[ \t]*\n[ \t]*::", "'::", r["c"])
                    for n, a in odd:
                        if n in r["c"]:
                            r["c"] = r["c"].replace(n, f"DAT_{a:08x}")
        # (each function's frame allocation, protos32.py's "frame": an EH frame's is laid out whole)
        pp = FACTS / "protos.json"
        protos = json.loads(pp.read_text())["functions"] if pp.exists() else {}
        self.frames = {int(k, 16): v["frame"] for k, v in protos.items() if v.get("frame")}
        # (and the register inputs each leaves as it found them, kept_inputs)
        self.keeps_in = {int(k, 16): v["keeps_in"] for k, v in protos.items() if v.get("keeps_in")}
        # (and those that clear the x87 exception flags, fnclex: the status word read then cleared)
        self.fpu_clear = {int(k, 16) for k, v in protos.items() if v.get("fpu_clear")}
        # (and those that leave the x87 stack alone, kept_st0)
        self.keeps_st0 = {int(k, 16) for k, v in protos.items() if v.get("keeps_st0")}
        # (and those that hand a callee reading through ebp their own frame: laid out whole, as an
        # EH frame's, protos32's hands_ebp)
        self.hands_ebp = {int(k, 16) for k, v in protos.items() if v.get("hands_ebp")}
        # (and the C runtime's x87 dispatchers, protos32's x87_dispatch: their operand count)
        self.x87_dispatch = {int(k, 16): v["x87_dispatch"] for k, v in protos.items() if v.get("x87_dispatch")}
        self.keeps = {int(k, 16): set(v["keep"]) for k, v in protos.items() if v.get("keep")}
        # (the functions no caller reads a result of: protos32's "v")
        self.ret_void = {int(k, 16) for k, v in protos.items() if v.get("ret") == "v"}
        # (and those it gave no result at all, no caller seen reading one: unread_result)
        self.ret_unread = {int(k, 16) for k, v in protos.items() if "ret" not in v}
        # (and each one's calling convention for the x86 fidelity build, Ghidra32.h's GEN_THISCALL
        # and the rest: what the reference's code does with ecx and edx and who pops the stack)
        self.conv = {}
        for k, v in protos.items():
            cc, regs, cleans = v.get("cc"), v.get("regs"), v.get("callee_cleans")
            # (a register convention protos32 calls custom, when the callee pops its stack words
            # or has none to pop: `mov eax, [ecx]; ret` is __thiscall's code)
            pops = cleans or not v.get("stack")
            if cc == "custom" and regs == ["ecx"] and pops:
                cc = "__thiscall"
            elif cc == "custom" and regs == ["ecx", "edx"] and pops:
                cc = "__fastcall"
            if cc in ("__thiscall", "__stdcall", "__fastcall") and not v.get("variadic"):
                self.conv[int(k, 16)] = cc
        # (and the registers each takes its parameters in, entry_registers)
        self.param_regs = {}
        for k, v in protos.items():
            regs = v.get("regs") or (["ecx"] if v.get("cc") == "__thiscall" else
                                     ["ecx", "edx"] if v.get("cc") == "__fastcall" else [])
            if regs:
                self.param_regs[int(k, 16)] = regs
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
            # (and a Function ID conflict's name as a call prints it, `FID_conflict_` for its
            # `FID_conflict:`, rhtest stl-Od's _Vector_const_iterator constructors)
            if printed_name(s.name) != s.name:
                self.by_printed.setdefault(printed_name(s.name), a)
        self.thunks = self.local_thunks()
        for name, (_at, target) in self.thunks.items():
            if not name.startswith("<thunk "):
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
        # (and each by its scopes' suffixes, as Ghidra writes one relative to a namespace the
        # function shares with it: `System::Data::ChunkWrite<unsigned_char,unsigned_short>::vftable`
        # inside `Client::UI::Misc`, for `Client::System::Data::...`. Only a suffix one name has)
        self.odd_suffix: dict[str, str | None] = {}
        for n in self.odd_functions | self.odd_data:
            depth, cuts = 0, []
            for i, ch in enumerate(n):
                depth += ch in "<(" and 1 or ch in ">)" and -1 or 0
                if depth == 0 and n.startswith("::", i) and i > 0:
                    cuts.append(i + 2)
            for c in cuts:
                s = n[c:]
                if odd.search(s) and s not in self.by_printed and s not in self.ref_names:
                    self.odd_suffix[s] = n if s not in self.odd_suffix else None
        for s, n in self.odd_suffix.items():
            if n is not None:
                w = re.search(r"[\w~]+", s)
                if w:
                    self.odd_by_word[w.group(0)].append(s)
        self.tls_index = self.ref_names.get("_tls_index") or self.tls_index_slot()
        # the globals the code loads and stores as floats (floatdata.py: x87 and SSE operand widths)
        import floatdata
        self.floats = floatdata.load()
        # the program's structures and typedefs (ghidra/ExportTypes.java -> build/types.json)
        tpath = ROOT / "build/types.json"
        types = json.loads(tpath.read_text(encoding="utf-8")) if tpath.exists() else {}
        self.composites = {n: v for n, v in types.get("composites", {}).items() if v["fields"]}
        # (and every one's size, a placeholder's too: types' opaque locals)
        self.composite_sizes = {n: v["size"] for n, v in types.get("composites", {}).items() if v.get("size")}
        self.typedefs = types.get("typedefs", {})
        # (and the enums' constants, which the decompiler prints by name: enum_constants)
        self.enum_values = types.get("enum_values", {})
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
        # (an import by ordinal by the name Ghidra gives its slot, `PTR_XInputEnable_0107e5a0`: the
        # decompiled code calls it by that name, and the x64 DLL exports it so. Left out, its slot
        # held its ordinal and the functions calling XInput or comctl32's SetWindowSubclass were
        # stubs, a VS2010 client 2026-10-25)
        by_slot = {}
        for n in self.ref_names:
            m = re.fullmatch(r"PTR_(\w+?)_([0-9a-f]{8})", n)
            if m:
                by_slot[int(m.group(2), 16)] = m.group(1)
        for dll in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            for imp in dll.imports:
                if imp.name:
                    out[imp.name.decode()] = (imp.address, dll.dll.decode())
                elif imp.address in by_slot and not by_slot[imp.address].startswith(("Ordinal_", "DAT_", "FUN_")):
                    out[by_slot[imp.address]] = (imp.address, dll.dll.decode())
        pe.close()
        return out

    def func_ranges(self, a: int) -> list[tuple[int, int]]:
        """The function's extents, functions.json's ranges (the corpus's size is the decompiler's,
        short of the last instruction at times: d74e00's 82 bytes cut its loop's `test [esi + 4]`)."""
        if getattr(self, "_ranges", None) is None:
            self._ranges = {}
            path = FACTS / "functions.json"
            if path.exists():
                for f in json.loads(path.read_text())["functions"]:
                    self._ranges[int(f["entry"], 16)] = [(int(x, 16), int(y, 16)) for x, y in f.get("ranges", [])]
        return self._ranges.get(a) or [(a, a + (self.corpus[a].get("size") or 0))]

    def local_thunks(self) -> dict[str, tuple[int, int]]:
        """name -> (thunk, target) for each `jmp` thunk Ghidra made a function of in the
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
            if not f.get("thunk"):
                continue
            at = int(f["entry"], 16)
            target = at
            for _ in range(4):                       # (through thunks of thunks)
                code = pe.get_data(target - base, 5)
                # (and `jmp short`: VS2010's catch continuation in nested(), `jmp 0x40149b` in two
                # bytes, its thunk's name undeclared and the catch demoted, rhtest msvc-16.00-x86 eh)
                if len(code) >= 2 and code[0] == 0xEB:
                    target = (target + 2 + int.from_bytes(code[1:2], "little", signed=True)) & 0xFFFFFFFF
                    continue
                if len(code) < 5 or code[0] != 0xE9:
                    break
                target = (target + 5 + int.from_bytes(code[1:5], "little", signed=True)) & 0xFFFFFFFF
            if target != at and target in self.corpus:
                # (a method's, `Client::...::vf1`, its slot in a vtable folded onto another's body
                # by the linker: no name a call is printed by, but the runtime's jump at it all the
                # same. Without one a camera's virtual call ran into the reference's own code,
                # 2026-10-26)
                out[f"<thunk {at:x}>" if "::" in f["name"] else f["name"]] = (at, target)
        pe.close()
        return out

    def truncates(self, a: int) -> bool:
        """Whether the function sets the x87 control word's rounding to truncation (`or eax,
        0xc00; mov [esp], eax; fldcw [esp]`) for its `fistp`: Ghidra drops the fldcw and reads
        fistp as ROUND, the current mode's (VS2010's inline (u32)double, d2u, rounded
        4200000000.75 up, rhtest msvc-16.00-x86 float 2026-10-25)."""
        import capstone
        import pefile
        if self._pe is None:
            self._pe = pefile.PE(str(project.EXE), fast_load=True)
        base = self._pe.OPTIONAL_HEADER.ImageBase
        code = self._pe.get_data(a - base, self.corpus[a].get("size") or 0)
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        mode = False
        for ins in md.disasm(code, a):
            if ins.mnemonic == "or" and ("0xc00" in ins.op_str or ins.op_str.endswith("h, 0xc")):
                mode = True
            elif ins.mnemonic == "fldcw" and mode:
                return True
        return False

    def hlt_loops(self, a: int, body: str) -> str:
        """`hlt`, which the language models as a jump to itself: the decompiler's "Do nothing block
        with infinite loop", `do { } while( true );`. In user mode the instruction faults, a
        privileged instruction the reference's __except catches (__halt() under __try, rhtest
        msvc-14.51-x86 seh): Ghidra32.h's gen_hlt, the host's own, where the function's bytes hold
        one; a real spin (`jmp $`) stays the loop it is."""
        if "Do nothing block with infinite loop" not in self.corpus[a]["c"]:
            return body
        import capstone
        import pefile
        if self._pe is None:
            self._pe = pefile.PE(str(project.EXE), fast_load=True)
        base = self._pe.OPTIONAL_HEADER.ImageBase
        code = self._pe.get_data(a - base, self.corpus[a].get("size") or 0)
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        if not any(m == "hlt" for _ad, _s, m, _o in md.disasm_lite(code, a)):
            return body
        return re.sub(r"do\s*\{\s*(?:/\*[^*]*\*/\s*)?\}\s*while\(\s*true\s*\);", "gen_hlt();", body)

    STALE_CAST = re.compile(r"\*\((float|double|int|uint|undefined4|undefined8|short|ushort|undefined2)\s*\*\)"
                            r"\(([A-Za-z_]\w*) \+ (0x[0-9a-f]+|\d+)\)")
    STALE_IDX = re.compile(r"\b([A-Za-z_]\w*)\[(0x[0-9a-f]+|\d+)\]")
    STALE_SIZES = {"float": 4, "int": 4, "uint": 4, "undefined4": 4, "double": 8, "undefined8": 8,
                   "short": 2, "ushort": 2, "undefined2": 2}
    STALE_BREAK = re.compile(r"[{}]|^\s*(?:if|else|while|do|for|switch|case|default|goto|return)\b|^\s*\w+\s*:(?!:)")

    def spin_polls(self, a: int, body: str) -> str:
        """A reference loop that only polls memory, `mov al, [edi + 6]; test al, al; je $-5` (0xa3dac0,
        0xa3e4c0: a byte another thread sets), is `cVar1 = p[6]; while (cVar1 == 0) { cVar1 = p[6]; }`
        here, with no volatile, call or store, and /O2 hoisted the load: `jmp $` in F_00a3dac0
        (2026-10-31). In such a function each loop that calls nothing starts with GEN_POLL(), a
        compiler barrier, so every iteration reads memory again."""
        new = poll_barriers(body)
        if new == body:
            return body
        import capstone
        import pefile
        if self._pe is None:
            self._pe = pefile.PE(str(project.EXE), fast_load=True)
        base = self._pe.OPTIONAL_HEADER.ImageBase
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        ins = [x for lo, hi in sorted(self.func_ranges(a)) for x in md.disasm_lite(self._pe.get_data(lo - base, hi - lo), lo)]
        return new if ref_polls(ins) else body

    def stale_loads(self, a: int, body: str) -> str:
        """A field read again after it is stored, in straight-line code, where the reference read
        it once before the store and kept the value (an x87 temporary on the stack, `fld [esi+0x28];
        fstp [ebp-8]`, then `[ebp-8]` after the `movss [esi+0x28], xmm0`): the decompiler prints
        the temporary as the field, read after the store. The value before the store, saved there,
        `gen_staleN`. Only a displacement the function never loads after its first store to it
        (a client's x-axis rotation matrix, its row 2 from the new row 1: the camera's up vector
        (0, 0, 0) for (0, -1, 0), 2026-10-28)."""
        decl: dict[str, str] = {}
        for m in re.finditer(r"(?m)^\s*(\w+)\s*\*\s*([A-Za-z_]\w*);", body):
            decl[m.group(2)] = m.group(1)
        for m in re.finditer(r"\b(\w+)\s*\*\s*(param_\d+)[,)]", self.corpus[a]["c"].partition("{")[0]):
            decl[m.group(2)] = m.group(1)

        def keys(text: str, at: int):
            """(key, base, type, displacement, start) of each field read or written in text"""
            for m in self.STALE_CAST.finditer(text):
                yield m.group(0), m.group(2), m.group(1), int(m.group(3), 0), at + m.start()
            for m in self.STALE_IDX.finditer(text):
                t = decl.get(m.group(1))
                if t in self.STALE_SIZES:
                    yield m.group(0), m.group(1), t, int(m.group(2), 0) * self.STALE_SIZES[t], at + m.start()

        # statements: (start, end) spans, split at ; { }
        stmts, s = [], 0
        for m in re.finditer(r"[;{}]", body):
            stmts.append((s, m.end()))
            s = m.end()
        stored: dict[str, tuple] = {}   # key -> (type, displacement, statement start)
        found: dict[tuple, list] = {}   # (key, store start) -> [read starts]
        # (the fields read on this straight line so far, the store's own right side included: the
        # decompiler's temporary is a value of the field read before the store, so the field is
        # read there too. `p[1] = f(); g(p[1])` reads only the new value, its own result kept in
        # a register: the pass took it for a stale read and passed the old object to a call, a
        # client's 0xe14a10 faulting on null, 2026-10-28)
        read: set[str] = set()
        for s, e in stmts:
            text = body[s:e]
            if self.STALE_BREAK.search(text.strip()) or text.strip() in ("{", "}"):
                stored, read = {}, set()
                continue
            m = re.match(r"(\s*)(.+?)\s=(?!=)\s(.*)$", text, re.S)
            lhs, rhs, roff = (m.group(2), m.group(3), s + m.start(3)) if m else ("", text, s)
            for k, _b, _t, _d, at in keys(rhs, roff):
                if k in stored:
                    found.setdefault((k, stored[k][2]), []).append(at)
                read.add(k)
            if m:
                lead = s + len(m.group(1))
                if re.fullmatch(r"[A-Za-z_]\w*", lhs.strip()):
                    # (a base reassigned: its fields are another object's)
                    gone = lambda k: re.search(r"\b" + lhs.strip() + r"\b", k)  # noqa: E731
                    stored = {k: v for k, v in stored.items() if not gone(k)}
                    read = {k for k in read if not gone(k)}
                for k, _b, t, d, _at in keys(lhs, lead):
                    if lhs.strip() == k and k not in stored and k in read:
                        stored[k] = (t, d, lead)
        if not found:
            return body
        # the reference: displacement -> first store, last load (any base but the frame's)
        import capstone
        from capstone import x86 as X86
        import pefile
        if self._pe is None:
            self._pe = pefile.PE(str(project.EXE), fast_load=True)
        base_va = self._pe.OPTIONAL_HEADER.ImageBase
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        md.detail = True
        insns = [ins for lo, hi in sorted(self.func_ranges(a))
                 for ins in md.disasm(self._pe.get_data(lo - base_va, hi - lo), lo)]
        # (base register, displacement) -> first store; -> its loads; and where control leaves the
        # straight line (a jump or a return between a load and the store: another path's load)
        first_w, loads, breaks = {}, {}, []
        rmw = ("add", "sub", "and", "or", "xor", "inc", "dec", "neg", "not")
        for ins in insns:
            if ins.mnemonic.startswith(("j", "ret", "call")):
                breaks.append(ins.address)
            for i, op in enumerate(ins.operands):
                if op.type != X86.X86_OP_MEM or op.mem.base in (0, X86.X86_REG_EBP, X86.X86_REG_ESP):
                    continue
                bd = (op.mem.base, op.mem.disp & 0xFFFFFFFF)
                write = i == 0 and (ins.mnemonic.startswith(("mov", "fst", "fist")) or ins.mnemonic in rmw)
                if write:
                    first_w.setdefault(bd, ins.address)
                if not write or ins.mnemonic in rmw:
                    loads.setdefault(bd, []).append(ins.address)

        def kept(d: int) -> bool:
            """a field of displacement d loaded before its store, on the same straight line, by the
            same base register, and never loaded after by any (the C's base is no register: a
            loop's `inc [esi + 4]; test [esi + 4], edx` reloads it, while another object's field
            at +4 kept by edi passed, d74e00's counter read as its value before the increment)"""
            ok = False
            for (base, dd), w in first_w.items():
                ls = loads.get((base, dd), [])
                if dd != d:
                    continue
                if ls and max(ls) > w:
                    return False
                if ls and not any(max(ls) < x < w for x in breaks):
                    ok = True
            return ok
        edits = []   # (position, length, replacement)
        decls = []
        for (k, at), reads in found.items():
            t, d, _ = next((stored_t, stored_d, 0) for kk, _b, stored_t, stored_d, _a in keys(k, 0) if kk == k)
            # (a field never loaded at all is a value the function stored and kept: read back, the
            # new one)
            if not kept(d):
                continue
            n = f"gen_stale{len(decls)}"
            decls.append(f"  {t} {n};" + ("\r\n" if "\r\n" in body else "\n"))
            edits.append((at, 0, f"{n} = {k}; "))
            edits += [(r, len(k), n) for r in reads]
        if not edits:
            return body
        for pos, ln, rep in sorted(edits, key=lambda x: x[0], reverse=True):
            body = body[:pos] + rep + body[pos + ln:]
        # (among the locals, first after the brace)
        return re.sub(r"\{[ \t]*\r?\n", lambda m: m.group(0) + "".join(decls), body, count=1)

    def text_data(self, translated: dict[int, str]) -> list[tuple[int, int]]:
        """Each stretch of the code section between functions (functions.json's ranges) that the
        translation reads through REFG/REFP: a switch's index table, a constant the compiler put
        after its function. Only those: the rest stays int3 for the runtime, a jump into code no
        function covers trapping rather than running x86 bytes."""
        import bisect
        import pefile
        pe = pefile.PE(str(project.EXE), fast_load=True)
        base = pe.OPTIONAL_HEADER.ImageBase
        text = next((s for s in pe.sections if s.Characteristics & 0x20000000), None)
        pe.close()
        path = FACTS / "functions.json"
        if text is None or not path.exists():
            return []
        lo, hi = base + text.VirtualAddress, base + text.VirtualAddress + text.Misc_VirtualSize
        rs = sorted((int(x, 16), int(y, 16)) for f in json.loads(path.read_text())["functions"]
                    for x, y in f.get("ranges", []))
        gaps, at = [], lo
        for x, y in rs:
            if x > at:
                gaps.append((at, x))
            at = max(at, y)
        if at < hi:
            gaps.append((at, hi))
        starts = [x for x, _ in gaps]
        keep = set()
        ref = re.compile(r"\bREF[GP]\((?:[^,()]+,\s*)?0x([0-9a-fA-F]+)\)")
        for t in translated.values():
            for m in ref.finditer(t):
                v = int(m.group(1), 16)
                k = bisect.bisect_right(starts, v) - 1
                if lo <= v < hi and k >= 0 and v < gaps[k][1]:
                    keep.add(k)
        return [gaps[k] for k in sorted(keep)]

    def eh_funcinfos(self) -> dict[int, int]:
        """handler -> FuncInfo for each function whose first instructions load a FuncInfo into eax
        (`mov eax, 0x4037d8`, its magic 0x1993052x there) before jumping on to __CxxFrameHandler3."""
        import pefile
        pe = pefile.PE(str(project.EXE), fast_load=True)
        base, size = pe.OPTIONAL_HEADER.ImageBase, pe.OPTIONAL_HEADER.SizeOfImage
        out = {}
        for a in self.corpus:
            code = pe.get_data(a - base, 0x30)
            for k in range(len(code) - 5):
                if code[k] != 0xB8:
                    continue
                fi = int.from_bytes(code[k + 1:k + 5], "little")
                if base <= fi < base + size - 4 and \
                        int.from_bytes(pe.get_data(fi - base, 4), "little") & 0xFFFFFFF0 == 0x19930520:
                    out[a] = fi
                    break
        pe.close()
        return out

    def import_of(self, name: str) -> str | None:
        """The import a name in the body calls: its own, or the one Ghidra printed without its
        C underscore (ucrt's `_initterm_e` as `initterm_e`, `_crt_atexit` as `crt_atexit`), or a
        decorated __stdcall one with its @ as Ghidra prints it (`_BinkOpen@8` as `_BinkOpen_8`)."""
        if name in self.imports:
            return name
        if "_" + name in self.imports:
            return "_" + name
        # (a decorated __stdcall import, `_BinkOpen@8`, as Ghidra prints it: `_BinkOpen_8`, its @ no C
        # name holds; POP.EXE's binkw32.dll, 4 stubs, sands3 2026-11-01)
        m = re.fullmatch(r"(.+)_(\d+)", name)
        if m and f"{m.group(1)}@{m.group(2)}" in self.imports:
            return f"{m.group(1)}@{m.group(2)}"
        return None

    def unread_result(self, a: int, c: str) -> set[str]:
        """The eax a void callee left that a function no caller reads a result of (protos32 gave it
        none, its int Ghidra's own) only copies or returns: `iVar3 = extraout_EAX;` beside a
        quotient on another path, `return iVar3;`. What reaches the return there is nothing anyone
        reads: 0. A sound buffer's flush 0xce1f50 kept EnterCriticalSection's eax, a stub on a
        client's sound path, 2026-10-28."""
        if a not in self.ret_unread:
            return set()
        out = set()
        for n in set(re.findall(r"\bextraout_EAX(?:_\d+)?\b", c)):
            uses = [l.strip() for l in c.split("\n") if re.search(r"\b" + n + r"\b", l)
                    and not re.match(r"\s*[A-Za-z_][\w ]*?[\s*]+" + n + r"\s*;", l)]
            if uses and all(re.fullmatch(r"(?:[A-Za-z_]\w* = |return )(?:\([\w ]+\**\))?" + n + r";", u) for u in uses):
                out.add(n)
        return out

    def ref_slot_unwritten(self, a: int, name: str) -> bool:
        """Whether the reference's own code leaves the stack local `name` (`local_8`, `uStack_1a`:
        the decompiler's offset below the entry esp) unwritten: in a plain `push ebp; mov ebp, esp`
        frame no instruction writes memory covering [ebp + off + 4], and no `lea` takes an address
        at or below it (a callee could fill it through that). Other frames: unknown, False."""
        m = re.fullmatch(r"(?:local_|[a-zA-Z]{0,16}Stack[XY]?_)([0-9a-f]+)", name)
        if not m:
            return False
        off = -int(m.group(1), 16)
        import capstone
        from capstone import x86 as X86
        import pefile
        if self._pe is None:
            self._pe = pefile.PE(str(project.EXE), fast_load=True)
        base_va = self._pe.OPTIONAL_HEADER.ImageBase
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        md.detail = True
        insns = [ins for lo, hi in sorted(self.func_ranges(a))
                 for ins in md.disasm(self._pe.get_data(lo - base_va, hi - lo), lo)]
        head = [f"{i.mnemonic} {i.op_str}" for i in insns[:3]]
        if not (head[:2] == ["push ebp", "mov ebp, esp"] or head[1:3] == ["push ebp", "mov ebp, esp"]):
            return False
        if any(i.mnemonic == "and" and i.op_str.startswith("esp,") for i in insns):
            return False                              # (an aligned frame: its locals through esp)
        for ins in insns:
            for k, op in enumerate(ins.operands):
                if op.type != X86.X86_OP_MEM or op.mem.base != X86.X86_REG_EBP:
                    continue
                lo = op.mem.disp - 4                  # (its offset from the entry esp)
                if ins.mnemonic == "lea":
                    if lo <= off:
                        return False
                    continue
                written = bool(op.access & capstone.CS_AC_WRITE) or (k == 0 and ins.mnemonic.startswith(
                    ("mov", "fst", "fist", "stos", "movs", "set", "cmov", "xchg", "pop")))
                if written and lo <= off < lo + max(op.size, 1):
                    return False
        return True

    def literal_places(self, body: str, a: int | None = None) -> str:
        """A string literal used beside a reference address inside or just past its own bytes,
        `widen("0123456789ABCDEFabcdef-+Xx", &DAT_0042c4c7, buf)`: the reference's copy of it,
        REFP. The decompiler prints the string the reference points to; as the port's own copy,
        `last - first` measured from two images, and std::num_get's widen copied gigabytes, rhtest
        stl /MT's istream."""
        # (and any literal the image holds once: the reference's own copy, as the reference points
        # to it. strtol's digit is its memchr's result less the table's address, which the
        # decompiler folded to `(char)pvVar5 + 'p'`, the low byte of 0x42f690: through the port's
        # copy every digit was wrong, and `in >> a` overflowed, rhtest stl /MT)
        if '"' not in body:
            return body
        import pefile
        if self._pe is None:
            self._pe = pefile.PE(str(project.EXE), fast_load=True)
        if not hasattr(self, "_image_data"):
            base = self._pe.OPTIONAL_HEADER.ImageBase
            self._image_data = [(base + s.VirtualAddress, s.get_data()) for s in self._pe.sections]
        # (the copies the function's own code names, `push 0x42f690`: where the image holds two,
        # the one it uses)
        code = self.ref_code(a) if a is not None else b""
        # (the decompiler's mark of a cut literal is a comment, gone with the others before this
        # (translate_one's strip_comments): the literals it marked, by their text in the corpus's C,
        # 0xb3aec0's three, 2026-10-30)
        cut = {m.group(1) for m in re.finditer(
            r'(?<![\w\\L])"((?:\\.|[^"\\])*)\.\.\."\s*/\* TRUNCATED STRING LITERAL \*/',
            self.corpus[a]["c"])} if a is not None and a in self.corpus else set()
        out = []
        for line in body.split("\n"):
            if '"' not in line:
                out.append(line)
                continue

            # (a literal the decompiler cut short, `"5_DBLEGACYRETAINE\' AS ... COLUMN_..." /* TRUNCATED
            # STRING LITERAL */`, its first bytes and "...": the reference's own copy, the address its
            # code names whose bytes start so, `push 0x121bdc6`, 2KB of SQL a client's 0xb3aec0 hands
            # its hooks. As written the port passed another string, 2026-10-30)
            def trunc(m):
                try:
                    raw = m.group(1).encode("latin-1").decode("unicode_escape").encode("latin-1")
                except Exception:
                    return m.group(0)
                hits = set()
                for va, data in self._image_data:
                    k = data.find(raw)
                    while k >= 0:
                        if (va + k).to_bytes(4, "little") in code:
                            hits.add(va + k)
                        k = data.find(raw, k + 1)
                return f"((char *)REFP(0x{hits.pop():x}))" if len(hits) == 1 else m.group(0)
            if code and cut and '..."' in line:
                line = re.sub(r'(?<![\w\\L])"((?:\\.|[^"\\])*)\.\.\."',
                              lambda m: trunc(m) if m.group(1) in cut else m.group(0), line)
            refs = [int(x, 16) for x in re.findall(r"&REFG\(undefined, (0x[0-9a-f]+)\)", line)]

            def rep(m):
                text = m.group(1)
                try:
                    raw = text.encode("latin-1").decode("unicode_escape").encode("latin-1")
                except Exception:
                    return m.group(0)
                if not raw:
                    return m.group(0)
                places, tails = [], []
                for va, data in self._image_data:
                    k = data.find(raw + b"\0")
                    while k >= 0:
                        # (a string's own start, a NUL or the section's start before it; another
                        # string's tail only where there is none)
                        (places if k == 0 or data[k - 1] == 0 else tails).append(va + k)
                        k = data.find(raw + b"\0", k + 1)
                every = places + tails
                named = [p for p in every if code and p.to_bytes(4, "little") in code]
                if len(named) == 1:
                    return f"((char *)REFP(0x{named[0]:x}))"
                # (or an address inside its bytes the code names, where the C does arithmetic on the
                # literal: `*(int *)("bgcommon/nature/sky/texture/sky_016.tex" + i * 8 + 0xc)`, the
                # decompiler's base for `mov eax, [edi*8 + 0x1093a00]`, a table of 8-byte records
                # whose element -1 overlaps the string. Through the port's copy the read went past
                # its end, a client's 0x4a9ff0 and 0x4aeb20, 2026-10-30)
                if code and re.match(r"\s*[+\[]", line[m.end():]):
                    inner = [p for p in every if any((p + d).to_bytes(4, "little") in code
                                                      for d in range(1, len(raw) + 1))]
                    if len(inner) == 1:
                        return f"((char *)REFP(0x{inner[0]:x}))"
                near = [p for p in every if any(p < r <= p + len(raw) + 1 for r in refs)]
                if near:
                    return f"((char *)REFP(0x{near[0]:x}))"
                places = places or tails
                if len(places) == 1 and not code:
                    return f"((char *)REFP(0x{places[0]:x}))"
                return m.group(0)
            out.append(re.sub(r'(?<![\w\\L])"((?:\\.|[^"\\])*)"', rep, line))
        return "\n".join(out)

    def unread_params(self, c: str) -> set[str]:
        """The callee-saved registers the decompiler lost that are only whole arguments of direct
        calls whose callee never reads that parameter: a catch's continuation cut from its body
        takes the body's `ret 4` for a stack parameter of its own, and the body falling into it
        hands it whatever is on the stack, `FUN_00402096(this, &stack0xfffffffc, unaff_EDI)`
        (rhtest stl-O2's stream extractors). 0 in the port."""
        out = set()
        # (and a stack word past the function's own, handed to a callee that never reads that
        # parameter: a tail jump's forwarding, `____mb_cur_max_func(0, in_stack_00000008)` of a
        # function that reads none, the CRT's ____mb_cur_max_l_func)
        for n in set(re.findall(r"\b(?:unaff_E(?:BX|SI|DI|BP)(?:_\d+)?|in_stack_[0-9a-f]{8})\b", c)):
            uses = [m for m in re.finditer(r"\b" + re.escape(n) + r"\b", c)]
            ok = bool(uses)
            for m in uses:
                line_start = c.rfind("\n", 0, m.start()) + 1
                if re.match(r"[ \t]+[A-Za-z_][^;=()\n]*?[\s*]+" + re.escape(n) + r"\s*;", c[line_start:]):
                    continue                                   # (its declaration, a template's too)
                # (the call it is an argument of: the innermost open paren before it, its index)
                depth, k, idx = 0, m.start() - 1, 0
                while k >= 0:
                    ch = c[k]
                    if ch in ")]":
                        depth += 1
                    elif ch in "([":
                        if depth == 0:
                            break
                        depth -= 1
                    elif ch == "," and depth == 0:
                        idx += 1
                    elif ch in ";{}" and depth == 0:
                        k = -1
                        break
                    k -= 1
                after = c[m.end():].lstrip()
                # (the callee's name, a template's and a scope's too: `std::_Adl_verify_range<char*,
                # char_const*>(param_2, unaff_EBP)`, rhtest stl-Od)
                fn = re.search(r"((?:[\w~]+(?:<[^()]*>)?::)*[\w~]+(?:<[^()]*>)?)\s*$", c[:k]) if k > 0 else None
                if not fn or not after[:1] in (",", ")") or not re.match(r"\s*[,)]", c[m.end():]):
                    ok = False
                    break
                ca = self.by_printed.get(fn.group(1))
                if ca is None and re.fullmatch(r"FUN_[0-9a-f]{8}", fn.group(1)):
                    ca = int(fn.group(1)[4:], 16)
                sig = self.sigs.get(ca) if ca is not None else None
                if sig is None:
                    ok = False
                    break
                # (one past the callee's parameters, not variadic: read by nothing)
                if idx >= len(sig.params):
                    if sig.variadic:
                        ok = False
                        break
                    continue
                pname = sig.params[idx][1]
                cbody = strip_comments(self.corpus[ca]["c"]).partition("{")[2]
                if re.search(r"\b" + re.escape(pname) + r"\b", cbody):
                    ok = False
                    break
            if ok:
                out.add(n)
        return out

    def noreturn_args_only(self, a: int, c: str) -> set[str]:
        """The registers the decompiler lost that are read only as the arguments of a call that does
        not return (Ghidra marks it `WARNING: Subroutine does not return`): what they hold cannot
        reach anything after it. __security_check_cookie hands ___report_gsfailure the unaff_
        registers it found; a stub of it returned 0 for every function the cookie guards, the
        result it passes through in eax (a VS2010 client, 2026-10-24). They are 0 in the port."""
        calls = re.findall(r"/\*\s*WARNING: Subroutine does not return\s*\*/\s*\n\s*([^;{}]*;)", self.corpus[a]["c"])
        if not calls:
            return set()
        out = set()
        for n in set(m.group(1) for s in calls for m in LOST.finditer(s)):
            uses = len(re.findall(r"\b" + re.escape(n) + r"\b", c))
            decls = len(re.findall(r"(?m)^[ \t]+[A-Za-z_][\w ]*?\s+" + re.escape(n) + r"\s*;", c))
            if uses - decls == sum(len(re.findall(r"\b" + re.escape(n) + r"\b", s)) for s in calls):
                out.add(n)
                continue
            # (or used besides as a local the function assigns before anything reads it: the
            # register it found is only what the call that does not return is handed, on a path
            # that set nothing. VS2010's __tzset_nolock, `unaff_EDI = (int *)0xffffffff;` first,
            # `__invoke_watson(unaff_EDI,0,0,0,0,0)` on an early error, a VS2010 client 2026-10-25)
            body = split_decls(c.partition("{")[2])[1]
            first = re.search(r"\b" + re.escape(n) + r"\b.*", body)
            if first and re.match(re.escape(n) + r"\s*=(?!=)", first.group(0)):
                out.add(n)
        return out

    def kept_st0(self, c: str) -> str:
        """`V = extraout_ST0;` right after a call to a function that leaves the x87 stack alone
        (protos32's keeps_st0): st0 is what it was before the call, which the decompiler, told
        the call may load it, lost. Its st0 holder there is V itself, `FUN_00403815(cw); in_st0 =
        extraout_ST0;` (__load_CW between a VS2010 CRT math tail's argument and its use): the
        statement goes, V keeping its value (rhtest msvc-16.00-x86 float). A quieter's
        (ST0_QUIETERS) st0 is the value handed with its `fadd [1.0]`, under its own test: taken as
        st0 kept, the port's sqrt and atan of a signalling NaN returned it signalling, and
        _atan_default (0xc4f398) read its `in_st0_00` uninitialized, 2026-10-30."""
        if not self.keeps_st0 or ("extraout_ST0" not in c and "in_st0_" not in c and "(float10)" not in c):
            return c
        self.set_kept_ns(c)
        lines = c.split("\n")
        # (or the call's own assignment, `fVar10 = (float10)FUN_00cef770(..);` of a void callee that
        # leaves st0, the decompiler's st0 after it: the float10 as it was, the scale it held before.
        # As a cast of the call, eax converted by value, an audio mix's PCM scale, 0xcf2d10 and
        # 0xb67550, the operation census 2026-10-31)
        float10s = set(re.findall(r"(?m)^[ \t]+float10\s+([A-Za-z_]\w*)\s*;", c))
        for i in range(len(lines)):
            m = re.fullmatch(r"(\s*)([A-Za-z_]\w*)\s*=\s*\(\s*float10\s*\)\s*(" + IDENT + r")(\s*(?:\(.*)?)", lines[i])
            if not m or m.group(2) not in float10s:
                continue
            # (the statement the call alone, not an operand of more: `(..);` closing at its `;`)
            rest = m.group(4).strip()
            if ";" in rest and not (rest.startswith("(") and rest.endswith(";")
                                    and match_paren(rest, 0) == len(rest.rstrip(";").rstrip())):
                continue
            a2 = self.printed_addr(m.group(3))
            sig = self.sigs.get(a2) if a2 is not None else None
            if a2 not in self.keeps_st0 or sig is None or sig.ret.strip() != "void" \
                    or not self.held_before(lines, i, m.group(2)):
                continue
            lines[i] = f"{m.group(1)}{m.group(3)}{m.group(4)}"
        for i in range(1, len(lines)):
            m = re.fullmatch(r"\s*([A-Za-z_]\w*)\s*=\s*(extraout_ST0(?:_\d+)?|in_st0_\d+)\s*;\s*", lines[i])
            if not m:
                continue
            # (or st0 after the call under a name of its own the decompiler never assigns, `fVar1 =
            # in_st0_00;`: a quieter's only)
            lost = m.group(2).startswith("in_st0_")
            if lost and re.search(r"\b" + m.group(2) + r"\s*=(?!=)", c):
                continue
            prev = lines[i - 1]
            # (a qualified name too, crtsigs.py's `Global::__load_CW`: by a bare identifier no call,
            # and the C runtime's sqrt and log tails 0xc4bdbd, 0xc496d8 and 3 like them kept
            # extraout_ST0, stubs, 2026-10-30)
            call = re.fullmatch(r"\s*(?:[\w.\->\[\]]+\s*=\s*)?(?:\([^()]*\))?\s*(" + IDENT + r")\s*\(.*\);\s*", prev)
            if not call:
                continue
            a2 = self.printed_addr(call.group(1))
            # (or one that quiets a signalling NaN in st0, the CRT's __convertTOStoQNaN: its name
            # from Function ID or crtsigs.py, its effect at the call, below)
            quiets = a2 is not None and \
                self.corpus.get(a2, {}).get("name", "").split("::")[-1] in ST0_QUIETERS
            if a2 is None or (a2 not in self.keeps_st0 and not quiets) or (lost and not quiets):
                continue
            # (st0 before the call: the x87 value the call is handed, `FUN_0040382c(hi, in_st0);
            # fVar2 = extraout_ST0_00;` its in_st0, or else V itself, an x87 value of the function's
            # own that held it, `in_st0 = extraout_ST0;`)
            float10s = set(re.findall(r"(?m)^[ \t]+float10\s+([A-Za-z_]\w*)\s*;", c)) | \
                set(re.findall(r"\bfloat10\s+([A-Za-z_]\w*)\s*[,)]", c))
            args = prev[call.end(1):]
            args = args[args.find("(") + 1:args.rfind(")")]
            handed = [x for x in re.findall(r"[A-Za-z_]\w*", args) if x in float10s]
            held = None
            if len(set(handed)) == 1:
                held = handed[0]
            # (V only where it held st0 before the call: a parameter, or assigned before it. A
            # fresh float10 the line first assigns would be read uninitialized, ultrareview
            # 2026-10-27; that one stays as it is)
            elif m.group(1) in float10s and self.held_before(lines, i - 1, m.group(1)):
                held = m.group(1)
            if held is None:
                continue
            if quiets:
                hi = split_top(args)[0].strip()
                value = f"(({hi}) & 0x80000) != 0 ? {held} : {held} + 1.0"
                if lost:
                    ind = re.match(r"\s*", lines[i]).group(0)
                    lines[i] = f"{ind}{m.group(2)} = {value};\n{lines[i]}"
                else:
                    lines[i] = re.sub(r"=\s*extraout_ST0(?:_\d+)?\s*;", lambda _m: f"= {value};", lines[i])
            elif held != m.group(1):
                lines[i] = re.sub(r"=\s*extraout_ST0(?:_\d+)?\s*;", f"= {held};", lines[i])
            else:
                lines[i] = ""
        return "\n".join(lines)

    @staticmethod
    def held_before(lines: list[str], end: int, v: str) -> bool:
        """Whether v holds a value before line `end`: a parameter of the function's signature, or
        assigned (not just declared) in a line before it."""
        head = "\n".join(lines[:end])
        sig, _, body = head.partition("{")
        # (an input register's local, in_ST0 or its renaming in_st0, holds what the function was handed)
        if v.lower().startswith("in_st") or re.search(rf"\b{re.escape(v)}\s*[,)]", sig):
            return True
        return re.search(rf"(?<![\w.>])\b{re.escape(v)}\s*(?:[-+*/]?=)(?!=)", body) is not None

    def set_kept_ns(self, c: str) -> None:
        """The caller's namespaces, from its signature's name, innermost first: printed_addr's for
        a call the decompiler printed relative to them (kept_st0, kept_inputs)."""
        head = " ".join(c.split("{", 1)[0].split())
        own = re.search(r"(" + IDENT + r")\s*\(", head)
        parts = own.group(1).split("::")[:-1] if own else []
        self.kept_ns = ["::".join(parts[:k]) + "::" for k in range(len(parts), 0, -1)]

    def kept_inputs(self, c: str) -> str:
        """`extraout_ECX` (or EDX) read in the statement right after a call to a function that
        leaves that register input as it found it (protos32's keeps_in): what the call was passed
        there. /LTCG keeps `this` in ecx across a call to a method that never writes ecx, and the
        decompiler, told the call kills it, lost it: FUN_00d7be90's `FUN_00d79e80(this); this =
        extraout_ECX;`, a stub on a VS2010 client's WinMain path, 2026-10-24."""
        # (and the decompiler's lowercase name for a custom callee's register argument the caller
        # never set, `FUN_00d8b150(in_ecx, 1)` after `FUN_00d8b150(uVar3, 0)`: ecx kept through the
        # call before, a matrix row's accessor 0xd8fa10)
        # (never assigned in the function: one it assigns, `in_ecx_00 = in_ecx + 0x16;`, is a local
        # of its own, and taken for a kept register 9 functions were assignments to an address)
        self.set_kept_ns(c)
        lower = set(re.findall(r"\bin_e[cd]x_\d+\b", c))
        if re.search(r"(?m)^\s+\w+\s+in_ecx;\s*$", c) and not re.search(r"\bin_ecx\b", c.split("{", 1)[0]):
            lower.add("in_ecx")
        lower = {n for n in lower if not re.search(rf"(?<![=!<>])\b{n}\s*=(?!=)", c)}
        # (eax too, a custom callee's input it neither writes nor returns in: `FUN_00dbf6c0(p, c);
        # if (*extraout_EAX == 0)`, eax p throughout, hkBsdSocket's vf7 0xdbf6d0, 2026-10-31)
        names = [(n, "eax" if "ax" in n.lower() else "ecx" if "cx" in n.lower() else "edx")
                 for n in sorted(set(re.findall(r"\bextraout_E[ACD]X(?:_\d+)?\b", c)) | lower)]
        # (and a local the decompiler declared and reads but never assigns: a kept register it
        # named for the parameter it is passed as, `this_00` in a VS2010 client's 0x50b800, ecx
        # its `this` across two calls that keep it; translated as written, an uninitialized local
        # handed a deque's push_back its object, a crash at startup 2026-10-26)
        kept_locals: set[str] = set()
        for n in sorted(set(re.findall(r"(?m)^[ \t]+[A-Za-z_][\w ]*?[\s*]+(this_\d+|pv\w+|p\w*Var\d+)\s*;\s*$", c))):
            if not re.search(rf"\b{n}\b(?!\s*;\s*$)", c, re.M):
                continue
            if re.search(rf"(?<![\w.>])\b{n}\s*(?:[-+*/|&^]|<<|>>)?=(?!=)|&\s*{n}\b|\b{n}\s*(?:\+\+|--)|(?:\+\+|--)\s*{n}\b", c):
                continue
            uses_n = [l for l in c.split("\n") if re.search(rf"\b{n}\b", l)]
            if len(uses_n) < 2:
                continue
            names += [(n, "ecx"), (n, "edx")]
            kept_locals.add(n)
        if not names or not self.keeps_in:
            return c
        # (a statement the decompiler wrapped over lines on one: the call above a use is the whole
        # statement, not its last line's tail, `uVar3 = FUN_00559f00(extraout_ECX_00,\n (float)...);`)
        # (a qualified name wrapped at its `::`, `Client::Graphics::\n JobSystem<..>\n ::vftable`, joined
        # with no space: as words apart, the name was no name, 0xbcab40 a stub at startup)
        joined, buf = [], ""
        for l in c.split("\n"):
            s = l.strip()
            if buf:
                buf += ("" if buf.rstrip().endswith("::") or s.startswith("::") else " ") + s
            else:
                buf = l.rstrip("\r")
            if not s or (s.endswith((";", "{", "}", ":", "*/")) and not s.endswith("::")) or s.startswith(("/*", "#")):
                joined.append(buf.rstrip("\r"))
                buf = ""
        if buf:
            joined.append(buf)
        c = "\n".join(joined)
        lines = c.split("\n")
        orig = list(lines)                        # (as written: the scan back reads them so)
        # (the body's alone: a signature the decompiler wrapped, `uint __thiscall\n
        # hkClassMemberAccessor::hkClassMemberAccessor(void *this,undefined4 param_1,...)`, joined
        # above, read as the call before the use, its `void *this` the value: `(uint)(void *this)`,
        # 20 demotions once a client's functions were named, 2026-10-30)
        body_at = next((i for i, l in enumerate(orig) if l.strip().startswith("{")), 0)
        for i in range(body_at):
            orig[i] = ""
        done = set()
        resolved: dict[str, str] = {}
        for n, reg in names:
            if n in done:
                continue
            decl = re.compile(rf"^[ \t]+([A-Za-z_][\w ]*?[\s*]*?)\s*\b{n};\s*$")
            dl = next((i for i, l in enumerate(lines) if l is not None and decl.match(l)), None)
            uses = [i for i, l in enumerate(lines) if l is not None and re.search(rf"\b{n}\b", l) and i != dl]
            if dl is None or not uses:
                continue
            value = None
            for u in uses:
                p = u - 1
                # (back over the other registers kept by the same call, read first: `param_1 =
                # extraout_ECX; param_2 = extraout_EDX;` after box_touch(param_1, param_2), VS2010's
                # box_chain. What they assign is noted: an argument made of it is not the same)
                assigned = set()
                while p >= 0 and (not orig[p].strip()
                                  or re.fullmatch(r"\s*\w+\s*=\s*extraout_E[ACD]X(?:_\d+)?;\s*", orig[p])):
                    if orig[p].strip():
                        assigned.add(orig[p].split("=")[0].strip())
                    p -= 1
                call = self.kept_call(orig[p], reg) if p >= 0 else None
                if call is not None and any(re.search(rf"\b{re.escape(v)}\b", call) for v in assigned):
                    call = None
                # (a call whose result replaces what it was passed, a list walk's `p = next(p);
                # q = extraout_ECX;`: ecx is p as it was before the line, kept in the name just
                # above it. Havok's 0xd929e0, the last node's flag, 2026-10-26)
                if call is None and p >= 0 and len(uses) == 1 and n.startswith("extraout_") \
                        and orig[p].rstrip().endswith(";") and lines[p] is not None \
                        and re.fullmatch(rf"\s*\w+\s*=\s*{n};\s*", orig[u]):
                    before = self.kept_call(orig[p], reg, lhs_ok=True)
                    if before is not None and not assigned:
                        t = decl.match(lines[dl]).group(1).strip()
                        indent = re.match(r"[ \t]*", orig[p]).group(0)
                        lines[p] = f"{indent}{n} = (({t})(uintptr_t)({before}));\n" + lines[p]
                        done.add(n)
                        value = None
                        break
                if call is None or (value is not None and call != value):
                    value = None
                    break
                value = call
            if n in done:
                continue
            # (or used further on: the name is one call's register, the decompiler numbering each
            # call's apart, so the nearest call above its first use, back over plain statements,
            # where nothing its argument reads is assigned after it. A determinant's caller,
            # `FUN_004ef2d0(param_2); ... extraout_ECX[1] ... extraout_ECX[10]`, its matrix in ecx
            # throughout, 0x4ef780 in a VS2010 client, 9,564 calls on its startup path)
            if value is None:
                p = uses[0] - 1
                # (back to the nearest line with a call in it, a name and its parenthesis: casts,
                # conditions and braces between are no call)
                calls_in = re.compile(r"\b(?!(?:if|while|for|switch|return|sizeof)\b)[A-Za-z_]\w*\s*\(")
                call = None
                # (or the call is on the use's own line, before it, a condition's comma expression:
                # `(bVar9 = F_004d2770(this), this = this_00, bVar9 != 0)`, ecx kept through it. A
                # frame scheduler's 0x4d2f40, 345 calls a boot with an uninitialized `this`, 2026-10-28)
                first = orig[uses[0]]
                at = re.search(rf"\b{re.escape(n)}\b", first)
                if at and calls_in.search(first[:at.start()]):
                    same = self.kept_call(first[:at.start()], reg)
                    if same is not None:
                        # (an earlier name's value through the chain, `f(this) || f(in_ecx) ||
                        # f(in_ecx_00)`, each the one before: 0xaec080, a stub on Start, 2026-10-31)
                        for k2, v2 in resolved.items():
                            same = re.sub(rf"\b{re.escape(k2)}\b", f"({v2})", same)
                        value = same
                        resolved[n] = value
                        dl_type = decl.match(lines[dl]).group(1).strip()
                        for i in uses:
                            lines[i] = re.sub(rf"\b{re.escape(n)}\b", f"(({dl_type})(uintptr_t)({value}))", lines[i])
                        lines[dl] = None
                        done.add(n)
                        continue
                    # (or the call assigns what it passed, `(u = FUN_0055a2d0(u), (char)u != 0) &&
                    # FUN_00570d10(extraout_ECX, ..)`: the value captured at the call, in the name
                    # itself, before it runs. 0x576160's `this` was 0, 2026-10-31)
                    cap = self.kept_call(first[:at.start()], reg, lhs_ok=True, whole=True)
                    if cap is not None and n.startswith("extraout_") and lines[uses[0]] is not None \
                            and lines[uses[0]].count(cap[1]) == 1:
                        t = decl.match(lines[dl]).group(1).strip()
                        lines[uses[0]] = lines[uses[0]].replace(
                            cap[1], f"({n} = (({t})(uintptr_t)({cap[0]})), {cap[1]})")
                        done.add(n)
                        continue

                def real_call(l):
                    # (a function's name or a call through a pointer; not LOCK() / UNLOCK(), the
                    # decompiler's marks around a locked instruction, which run no code)
                    return "))(" in l.replace(" ", "") or any(
                        self.printed_addr(m.group(1)) is not None
                        for m in re.finditer(r"(?<![\w:])((?:[A-Za-z_]\w*::)*[A-Za-z_]\w*)\s*\(", l))
                # (and if that finds no kept call, again over each block that never falls through to
                # the use, its last statement a return or goto: what it calls is on another path. A
                # drop-down list's vf2 0x5a33e0, `if (..) { LAB_x: ..; return FUN_0059cc00(..); } ..
                # if (extraout_ECX != 0)`, ecx the list kept through 0x5622f0 before the block, a
                # stub when a client's settings filled their tabs, 2026-10-28)
                start = p
                captured = False
                for skip_returning in (False, True):
                    p, call = start, None
                    while p >= 0:
                        if skip_returning and orig[p].strip() == "}":
                            depth, o = 0, p
                            while o >= 0:
                                depth += orig[o].count("}") - orig[o].count("{")
                                if depth <= 0:
                                    break
                                o -= 1
                            body = [l.strip() for l in orig[o + 1:p] if l.strip()]
                            if o >= 0 and body and re.match(r"(?:return\b|goto\s)", body[-1]) \
                                    and re.match(r"\s*(?:\}\s*else\s*)?if\s*\(", orig[o]) \
                                    and not real_call(orig[o][:orig[o].rfind("{")]):
                                p = o - 1
                                continue
                        if calls_in.search(orig[p]) and real_call(orig[p]):
                            call = self.kept_call(orig[p], reg)
                            # (back over a call that leaves the register alone, its keep convention:
                            # `FUN_00504070(this, x); n = FUN_004ff570(k); FUN_00529340(this_00 +
                            # ...)`, ecx `this` through both, a VS2010 client's 0x50b800)
                            if call is None and self.call_keeps(orig[p], reg):
                                p -= 1
                                continue
                            # (a statement that assigns what it passed, `param_1 = Type::GetClass(
                            # param_1); local_14 = 0; ...; FindTypesUsingClass(this, extraout_ECX,
                            # ..)`: its value before the line, kept in the name. Havok's
                            # hkTypeManager::RemoveClass 0xe1ac10 passed 0, 2026-10-31)
                            if call is None and n.startswith("extraout_") and lines[p] is not None \
                                    and orig[p].rstrip().endswith(";"):
                                before = self.kept_call(orig[p], reg, lhs_ok=True)
                                if before is not None:
                                    t = decl.match(lines[dl]).group(1).strip()
                                    indent = re.match(r"[ \t]*", orig[p]).group(0)
                                    lines[p] = f"{indent}{n} = (({t})(uintptr_t)({before}));\n" + lines[p]
                                    captured = True
                            break
                        p -= 1
                    if call is not None or captured:
                        break
                if captured:
                    done.add(n)
                    continue
                if call is not None:
                    # (assigned between the call and the name's last use: after it, no matter. The UI
                    # hit test 0x5791d0's `piVar4 = FUN_00559c20(iVar2); if (piVar4 == 0) {
                    # FUN_005c8430(this_00, ..)`, iVar2 assigned again further down its loop: the
                    # node refused, this_00 left uninitialized, and a click on the title menu handed
                    # the hit test a code address for its node, 2026-10-28)
                    later = "\n".join(orig[p + 1:max(uses) + 1])
                    names_in = set(re.findall(r"[A-Za-z_]\w*", call))
                    if not any(re.search(rf"(?<![=!<>])\b{re.escape(v)}\s*(?:[-+*/|&^]|<<|>>)?=(?!=)", later)
                               for v in names_in):
                        value = call
                    # (what it is made of assigned further on, a list walk's `this = *(void **)(this
                    # + 4)` past it: the value as it was after the call, kept in the name itself.
                    # Havok's array chunk lookup 0xd92800, `FUN_00d927e0(this)` and then ecx, its
                    # first chunk, read after the walk; a stub, its null a crash, 2026-10-26)
                    # (and a never-assigned local the decompiler named for the kept register, `this_00`
                    # after `FUN_00b64ec0(pvVar13, ..)` in a loop that assigns pvVar13 at its end: the
                    # value kept in it after the call. A curve sampler's 0xb65e10 read garbage for its
                    # object, the zone loading screen's AV, 2026-11-01)
                    elif orig[p].rstrip().endswith(";") and lines[p] is not None \
                            and (n.startswith("extraout_") or n in kept_locals):
                        t = decl.match(lines[dl]).group(1).strip()
                        indent = re.match(r"[ \t]*", orig[p]).group(0)
                        lines[p] = lines[p] + f"\n{indent}{n} = (({t})(uintptr_t)({call}));"
                        done.add(n)
                        continue
            if value is None:
                continue
            # (a value that is itself an earlier call's kept register, resolved already: that one's
            # value, the chain `f(extraout_ECX); g(extraout_ECX_00)` through one `this`)
            for k2, v2 in resolved.items():
                value = re.sub(rf"\b{re.escape(k2)}\b", f"({v2})", value)
            resolved[n] = value
            t = decl.match(lines[dl]).group(1).strip()
            for u in uses:
                lines[u] = re.sub(rf"\b{n}\b", f"(({t})(uintptr_t)({value}))", lines[u])
            # (the declaration gone, not blanked: an empty line ends the declarations, and those
            # after it were undeclared, FUN_00dc0b40's iVar2, 2026-10-24)
            lines[dl] = None
            done.add(n)
        return "\n".join(l for l in lines if l is not None)

    def entry_registers(self, a: int, c: str) -> str:
        """A local the decompiler named for a register as the function found it, `in_ecx` (a
        callee's parameter name it took), that the function never assigns: the parameter it takes
        in that register. FUN_00dc0b40, a __thiscall, hands `in_ecx` (its `this`, ecx unchanged
        across the call before) to FUN_00dc07b0 and returns it; translated as a local of its own,
        it was garbage, and 683 functions declare one (a VS2010 client, 2026-10-24). One no parameter
        is in is a register the decompiler lost (why_not)."""
        # (numbered too, `in_ecx_00`: the entry's register again, read past calls that keep it, the
        # decompiler naming each read apart. Havok's 0xda6030 reads its `this` so after 0xda5ff0;
        # as locals of their own they were 0, a crash, 2026-10-26)
        names = set(re.findall(r"(?m)^[ \t]+(?!return\b)[A-Za-z_][\w ]*?[ \t*]+(in_[a-z]{2,3}(?:_\d+)?)[ \t]*;", c))
        if not names:
            return c
        sig = self.sigs.get(a)
        regs = [NARROW_FULL.get(r, r) for r in self.param_regs.get(a, [])]
        lines = c.split("\n")
        for n in sorted(names):
            if re.search(rf"(?<![\w.>])\b{n}\s*(?:[-+*/|&^]|<<|>>)?=(?!=)|&\s*{n}\b|\b{n}\s*(?:\+\+|--)|(?:\+\+|--)\s*{n}\b", c):
                continue                          # (assigned: a local like any other)
            base = re.sub(r"_\d+$", "", n[3:])
            reg = NARROW_FULL.get(base, base)
            if sig is None or reg not in regs or regs.index(reg) >= len(sig.params):
                continue                          # (lost: why_not says so)
            decl = re.compile(rf"^[ \t]+([A-Za-z_][\w ]*?[\s*]*?)\s*\b{n};\s*$")
            dl = next((i for i, l in enumerate(lines) if l is not None and decl.match(l)), None)
            if dl is None:
                continue
            t = decl.match(lines[dl]).group(1).strip()
            p = sig.params[regs.index(reg)][1]
            # (through uintptr_t: a pointer `this` to a 4-byte integer, or the other way)
            lines = [l if l is None or i == dl else re.sub(rf"\b{n}\b", f"(({t})(uintptr_t)({p}))", l)
                     for i, l in enumerate(lines)]
            lines[dl] = None
        return "\n".join(l for l in lines if l is not None)

    def printed_addr(self, name: str) -> int | None:
        """A called function by the name the decompiler printed: whole, or a qualified one relative
        to the caller's namespace, `EventHandler::vf14` for Client::Game::Event::EventHandler::vf14,
        when that suffix names one function alone (kept_call runs before names() knows the
        caller's namespaces)."""
        a = self.by_printed.get(name)
        # (or a bare one in the global namespace, which the decompiler leaves off where the caller
        # is in it too: `MatrixDeterminant3x3(param_2)` for Global::MatrixDeterminant3x3, named
        # in the data, its kept ecx then lost, 0x4ef780 a stub on a client's startup, 2026-10-30)
        if a is None and "::" not in name:
            a = self.by_printed.get("Global::" + name)
        # (or one in the caller's own namespace, by the scopes of the name its signature has,
        # innermost first: `GetNumMembers(this)` in hkClass::GetMember, 0xd92800, 2026-10-30)
        for ns in getattr(self, "kept_ns", ()) if a is None else ():
            a = self.by_printed.get(ns + name)
            if a is not None:
                break
        if a is not None or "::" not in name:
            return a
        if not hasattr(self, "_by_suffix"):
            self._by_suffix: dict[str, int | None] = {}
            for full, a2 in self.by_printed.items():
                parts = full.split("::")
                for k in range(1, len(parts) - 1):
                    s = "::".join(parts[k:])
                    self._by_suffix[s] = a2 if s not in self._by_suffix or self._by_suffix[s] == a2 else None
        return self._by_suffix.get(name)

    def call_keeps(self, line: str, reg: str) -> bool:
        """Whether a statement's one call is to a function that leaves `reg` as it was, its keep
        convention (protos32's keep): the register goes on past it."""
        m = re.fullmatch(r"\s*(?:[\w.\->\[\]]+\s*=\s*)?(?:\([^()]*\))?\s*((?:[A-Za-z_]\w*::)*~?[A-Za-z_]\w*)\s*\((.*)\);\s*", line)
        if not m or len(re.findall(r"\b(?!(?:if|while|for|switch|return|sizeof)\b)[A-Za-z_]\w*\s*\(", line)) != 1:
            return False
        a2 = self.printed_addr(m.group(1))
        return a2 is not None and reg in self.keeps.get(a2, ())

    def kept_call(self, line: str, reg: str, lhs_ok: bool = False, whole: bool = False):
        """The argument a statement's one call passes in `reg`, when the callee leaves it as it
        found it and nothing on the line assigns what it is made of (kept_inputs). With lhs_ok, one
        the statement's own assignment changes too: its value before the line. With whole, the
        pair (that argument, the call's own text), for a capture at the call (kept_inputs)."""
        # (a qualified name too, `bVar1 = EventHandler::vf14((EventHandler *)this,param_1);` in a
        # quest handler's override, `this` read on through ecx: printed_addr)
        m = re.fullmatch(r"\s*(?:[\w.\->\[\]]+\s*=\s*)?(?:\([^()]*\))?\s*((?:[A-Za-z_]\w*::)*~?[A-Za-z_]\w*)\s*\((.*)\);\s*", line)
        # (the statement's outer call a conversion around the real one, `fVar2 = gen_bits2f(
        # FUN_00bd1f30(param_1, ..));`, a float result's bits: the one inside, as below. A clip's
        # vf21 read its object on through ecx and was stubbed, 19 like it, 2026-10-30)
        if m and self.printed_addr(m.group(1)) is None:
            m = None
        if m:
            name, inner = m.group(1), m.group(2)
            self_assigned, text = None, line[m.start(1):m.end(2) + 1]
        else:
            # (or the one call of a line that is more than it, a condition's: `if ((in_ecx != 0) &&
            # (uVar3 = FUN_0055a2d0(in_ecx), (char)uVar3 != '\0')) {`, its `this` read on in the
            # block, extraout_ECX; 91 stubs in a client 2026-10-27)
            found = [mm for mm in re.finditer(r"(?<![\w:~])((?:[A-Za-z_]\w*::)*~?[A-Za-z_]\w*)\s*\(", line)
                     if self.printed_addr(mm.group(1)) is not None]
            if not found or (lhs_ok and not whole):
                return None
            # (of several, the one run last, its parenthesis closing last: the later of a
            # condition's `&&` chain, or the outer of nested ones. `(b = FUN_00535b40(p), b != 0)
            # && (u = FUN_00535990(p, k), ..)`, ecx 0x535990's `this` kept, 0x5409a0)
            # (not one still open where the line is cut, the call the use is an argument of: it
            # runs after. `(u = FUN_0055a2d0(u), ..) && (b = FUN_00570d10(extraout_ECX, ..)`, a
            # client's 0x576160, refused for it and its `this` passed as 0, 2026-10-31)
            closes = [(match_paren(line, mm.end() - 1), mm) for mm in found]
            if any(cl < 0 for cl, _ in closes) and line.rstrip().endswith(";"):
                return None
            closes = [x for x in closes if x[0] >= 0]
            if not closes:
                return None
            close, last = max(closes, key=lambda x: x[0])
            name, inner = last.group(1), line[last.end():close - 1]
            # (nor one whose own assignment, inside the condition, changes what it was passed:
            # `u = FUN_0055a2d0(u)`, ecx u as it was before, not after)
            own = re.search(r"\b([A-Za-z_]\w*)\s*=\s*(?:\([^()]*\)\s*)?$", line[:last.start()])
            if own and not lhs_ok:
                self_assigned = own.group(1)
            else:
                self_assigned = None
            text = line[last.start():close]
        a2 = self.printed_addr(name)
        idx = self.keeps_in.get(a2, {}).get(reg) if a2 is not None else None
        if idx is None:
            return None
        args, depth, cur = [], 0, ""
        for ch in inner:
            if ch == "," and depth == 0:
                args.append(cur.strip())
                cur = ""
                continue
            depth += ch in "([" and 1 or ch in ")]" and -1 or 0
            cur += ch
        args.append(cur.strip())
        if idx >= len(args) or not args[idx]:
            return None
        arg = args[idx]
        # (no call, no side effect, and nothing the statement assigns: the value it had)
        if re.search(r"\w\s*\(|\+\+|--|[^=!<>]=[^=]", arg):
            return None
        lhs = re.match(r"\s*([A-Za-z_]\w*)\s*=", line)
        if lhs and re.search(rf"\b{lhs.group(1)}\b", arg) and not lhs_ok:
            return None
        if self_assigned and re.search(rf"\b{self_assigned}\b", arg):
            return None
        return (arg, text) if whole else arg

    def after_float_call(self, c: str) -> set[str]:
        """What eax or edx held after a call whose result is on the x87 stack: nothing the ABI
        defines, the callee's scratch, garbage in the reference too. A message handler's path that
        returns it, `dVar20 = FUN_0054cd20(&v); puVar6 = extraout_EAX; ... return puVar6;` (the
        client's Order handler 0xa55f80, stubbed with 14 more), 0."""
        out = set()
        lines = c.split("\n")
        for n in set(re.findall(r"\bextraout_E[AD]X(?:_\d+)?\b", c)):
            first = next((i for i, l in enumerate(lines) if re.search(rf"\b{n}\b", l)
                          and not re.fullmatch(rf"\s*(?!return\b)[A-Za-z_][\w ]*?[\s*]+{n}\s*;\s*", l)), None)
            if first is None:
                continue
            # (the call it comes out of: the last one at or before its first use)
            callee = None
            for l in reversed(lines[max(0, first - 3):first + 1]):
                calls = re.findall(r"\bFUN_([0-9a-f]{8})\s*\(", l)
                if calls:
                    callee = int(calls[-1], 16)
                    break
            sig = self.sigs.get(callee) if callee is not None else None
            # (or void: protos32.py makes a callee void where no caller reads eax after it, so this
            # is the decompiler's merge of a register, no read. The Order handler's
            # `(FUN_00a6aed0(..), puVar6 = extraout_EAX_00, pvVar12 != 0)`)
            # (by the signature's own type: ret_type makes void the port's word)
            if sig is not None and (sig.ret.strip() == "void" or self.ret_type(sig.ret).strip() in FLOATS):
                out.add(n)
        return out

    def upper_lanes(self, a: int, c: str) -> set[str]:
        """An xmm register's upper half as the function found it (`in_XMM2_Qb`, `in_XMM0_Dd`) where its
        facts take no more of the register than a double, or none of it: the caller's leftover, which
        the C runtime's hand-written SSE2 math carries through packed ops into lanes it never returns.
        asin's 0xc6790e, `movlpd xmm2, [c]; ...; andpd xmm2, xmm7` and `pmovmskb eax, xmm0; and eax,
        0x80`, its sign alone; 0 for them, as its caller's `movq xmm0, [esp]` leaves xmm0's
        (2026-10-30). Not one the facts take as a float, `xmm1`: an __m128 argument's packed reads
        give that width, and its upper lanes are its own."""
        regs = self.param_regs.get(a, [])
        return {n for n, k in set(re.findall(r"\b(in_XMM(\d)_(?:Qb|D[cd]))\b", c)) if f"xmm{k}" not in regs}

    # ---- one function ---------------------------------------------------------------------------
    def why_not(self, a: int) -> str | None:
        c = self.entry_registers(a, self.kept_inputs(self.kept_st0(stack_vs_const(neg_scaled(v16_forms(cpu_state(array_stores(locked_reads(switch_guarded_loads(wide_subscripts(strip_comments(self.corpus[a]["c"]))))))))))))
        if a not in self.sigs:
            return "no signature"
        # (a register as the function found it that no parameter is in, never assigned: lost)
        for n in set(re.findall(r"(?m)^[ \t]+(?!return\b)[A-Za-z_][\w ]*?[ \t*]+(in_[a-z]{2,3})[ \t]*;", c)):
            if not re.search(rf"(?<![\w.>])\b{n}\s*(?:[-+*/|&^]|<<|>>)?=(?!=)|&\s*{n}\b|\b{n}\s*(?:\+\+|--)|(?:\+\+|--)\s*{n}\b", c):
                return f"a register the decompiler lost ({n})"
        # (and a full xmm register as an SSE pseudo-op's destination found it: zeroed, sse_ops)
        # (and a call's x87 result made its assignment, x87_icall_results)
        ok = returned_only(c) | self.unread_result(a, c) | self.noreturn_args_only(a, c) | filler_args(c) | upper_only(c) | declared_only(c) | \
            self.after_float_call(c) | self.upper_lanes(a, c) | \
            self.unread_params(c) | \
            context_capture(c) | {"in_FPUControlWord", "in_FPUStatusWord"} | ({"in_ZF"} if libm_flag(c) else set()) | \
            set(re.findall(r"(?m)^\s*(extraout_ST0(?:_\d+)?) = \(\*", c)) | \
            set(re.findall(r"(?m)^[ \t]+undefined1\s+(in_XMM\d+)\s*\[\s*16\s*\]\s*;", c)) | \
            set(re.findall(r"(?m)^\s*(extraout_E[ACD]X(?:_\d+)?) = \(\(.*\)\(uintptr_t\)\(", c)) | \
            set(re.findall(r"\((extraout_E[ACD]X(?:_\d+)?) = \(\(.*?\)\(uintptr_t\)\(", c))
        # (a variadic function's argument word its signature names no parameter for: its block's,
        # rewrite)
        if self.sigs[a].variadic:
            ok |= set(re.findall(r"\bin_stack_0000[0-9a-f]{4}\b", c))
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
    def small_arrays(self, body: str) -> str:
        """A byte array of 1, 2, 4 or 8 bytes Ghidra assigns or reads as a whole value (`local_8 =
        SUB42(uVar2,0);`, `(ushort)local_8`, `CONCAT22(0x804,local_8)` of an `undefined1 local_8
        [2]`): its bytes as one integer of that size. C has no array assignment, and the array
        read as a value is its address."""
        decls, rest = split_decls(body)
        esize = {"char": 1, "undefined1": 1, "byte": 1, "uchar": 1, "undefined": 1, "wchar_t": 2,
                 "ushort": 2, "short": 2, "undefined2": 2, "undefined4": 4, "uint": 4, "int": 4}
        ints = {1: "unsigned char", 2: "unsigned short", 4: "unsigned int", 8: "unsigned long long"}
        small = {}
        for m in re.finditer(r"(?m)^\s+(" + "|".join(esize) + r")\s+([A-Za-z_]\w*)\s*\[\s*(\d+)\s*\]\s*;", decls):
            n = esize[m.group(1)] * int(m.group(3))
            if n in ints:
                small[m.group(2)] = n
        # (the ones assigned a value whole through an array cast, `local_cc = (undefined1 [4])this;`,
        # and never addressed: value holders, small_arrays below)
        # (array_set has made that `{ unsigned int gen_ac = (unsigned int)(this); memcpy(&local_cc,
        # &gen_ac, 4); }` by now: its own `&` no address the code takes)
        # (or array_stores' `*(undefined4 *)local_cc = this;`)
        whole_set = r"memcpy\(&{0}, &gen_ac, {1}\)|\*\(undefined{1} \*\){0}(?= = )"
        held_whole = {name: bool(re.search(whole_set.format(name, n), rest))
                      and not re.search(rf"&\s*{name}\b|\b{name}\s*\[", re.sub(whole_set.format(name, n), "", rest))
                      for name, n in small.items()}
        for name, n in small.items():
            t = ints[n]

            def assign(mm, name=name, n=n, t=t):
                # (another one copied in, `auVar6 = local_cc;`: its bytes, not its address,
                # FUN_006835d0 in a VS2010 client)
                v = mm.group(2).strip()
                v = f"(*({ints[small[v]]} *){v})" if v in small else v
                return f"{mm.group(1)}{{ {t} gen_ac = ({t})({v}); memcpy({name}, &gen_ac, {n}); }}"
            rest = re.sub(rf"(?m)^([ \t]*){name} = ([^;\n]+);", assign, rest)
            whole = f"(*({t} *){name})"
            # (a cast of one read whole: of a register's, `auVar6`, which has no address, any cast,
            # `(int)auVar6 + 0x147c` its pointer's value (FUN_006835d0). Of a stack array a
            # pointer-sized cast is its address, `(int)aiStack_1c + iVar1 + 4` in VS2010's alloca
            # path and the /GS cookie's `(uint)local_c` (rhtest msvc-16.00-x86 misc-O2, crt-O2):
            # only a narrower or wider one, `(uint3)(ushort)local_8`, not added to)
            if name.startswith("auVar"):
                casts = r"char|uchar|byte|ushort|short|uint|int|uint3|ulonglong|longlong|undefined[1248]?"
                after = r"(?!\s*[\[.])"
            else:
                casts = r"char|uchar|byte|ushort|short|uint3|ulonglong|longlong|undefined[128]?"
                after = r"(?!\s*[\[.+-])"
            rest = re.sub(rf"(\(\s*(?:unsigned\s+)?(?:{casts})\s*\)\s*){name}\b{after}", rf"\1{whole}", rest)
            # (and a stack one cast to an int with a constant past its own bytes added, `*(int *)((int)
            # local_cc + 0x172c)`: no address inside the array, its value, the object pointer the
            # slot holds. As its address, a VS2010 client's 0x6835d0 wrote 6 KB past its own frame,
            # a crash on its frame path, 2026-10-27)
            # (or any pointer-sized cast of one assigned a value whole, `local_cc = (undefined1 [4])
            # this;`: a register's worth spilled, never an address the code takes, so `(int)local_cc +
            # (i + k * 3) * 4 + 0x14cc` indexes the object it holds, the same function)
            if not name.startswith("auVar"):
                if held_whole.get(name):
                    rest = re.sub(rf"\(\s*(?:unsigned\s+)?(?:int|uint)\s*\)\s*{name}\b(?!\s*[\[.])",
                                  f"(int){whole}", rest)
                rest = re.sub(rf"\(\s*(?:unsigned\s+)?(?:int|uint)\s*\)\s*{name}\b(\s*\+\s*)(0x[0-9a-f]+|\d+)\b",
                              lambda mm: f"(int){whole}{mm.group(1)}{mm.group(2)}" if int(mm.group(2), 0) >= int(n)
                              else mm.group(0), rest)
            rest = re.sub(rf"(\bCONCAT\d\d\((?:[^(),]|\([^()]*\))*,\s*){name}\s*\)", rf"\1{whole})", rest)
            rest = re.sub(rf"(\bCONCAT\d\d\(\s*){name}\s*,", rf"\1{whole},", rest)
        return decls + rest

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
                # (an array of pointers to one, `IMalloc *local_28 [2]`: each element a pointer, not
                # the structure, SHGetMalloc's out slot, rhtest msvc-14.51-x86 misc-O2 shell_malloc)
                out[m.group(3)] = (s, "ptrarray" if m.group(2) and m.group(4) else
                                   "ptr" if m.group(2) else "array" if m.group(4) else "val")
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
        # (nested ones from the inside out, a pass each: `((IMAGE_OPTIONAL_HEADER32 *)(IMAGE_NT_
        # HEADERS32_004000d0.OptionalHeader.DataDirectory + -0xc))->Magic`, whose cast's operand is
        # C only once the inner chain is placed. In one pass the outer one took the inner's text
        # as it was, VS2010's ___tmainCRTStartup at /Od)
        for _ in range(4):
            body, nested = self.members_pass(body, svars)
            if not nested:
                break
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

    def members_pass(self, body: str, svars: dict) -> tuple[str, bool]:
        """One pass of members(): each access it can place, and whether one was left for the next
        because it holds another placed in this pass."""
        out, i = [], 0
        nested = False
        for m in re.finditer(r"(->|\.)\s*([A-Za-z_]\w*)", body):
            if m.start() < i:
                continue
            if m.group(1) == "." and re.search(r"(?<![\w$])\d+$", body[:m.start()]):
                continue                                   # (a float literal: digits alone, not
                                                           # `local_14.locinfo`, a name ending in one)
            start = self.base_start(body, m.start())
            if start is None:
                continue
            if start < i:
                nested = True                              # (holds one placed now: the next pass)
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
        return "".join(out), nested

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
            # (an array of structures steps by the structure: `DataDirectory + -0xc` is 12 of its
            # 8-byte IMAGE_DATA_DIRECTORYs back, not 12 bytes)
            if el[0] == "struct" and self.composites.get(el[1], {}).get("size"):
                return f"((undefined (*)[{self.composites[el[1]]['size']}])({addr}))"
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
        if m and m.group(1) in svars and svars[m.group(1)][1] == "ptrarray":
            return f"(char *)({m.group(1)}[{m.group(2)}])", ("ptrval", svars[m.group(1)][0])
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
        # (a pointer to one, read from where a cast puts it: an SEH filter's `(*(_EXCEPTION_POINTERS
        # **)(in_ebp + -0x14))->ExceptionRecord`, the frame's saved pointers; mainCRTStartup's
        # filter in every VS2010 program was a stub, rhtest msvc-16.00-x86 2026-10-25)
        m = re.fullmatch(r"\(\s*\*\s*\(\s*(?:struct\s+)?([A-Za-z_]\w*)\s*\*\s*\*\s*\)\s*(.+)\)", base, re.S)
        if m and self.struct_of(m.group(1)):
            return f"(char *)(*(undefined * PTR32 *)({m.group(2)}))", ("ptrval", self.struct_of(m.group(1)))
        # (and one of an array a cast says is of them: FindHandlerForForeignException's
        # `((HandlerType *)local_c[1])[*local_c + -1].pType`, the /MT CRT's, rhtest msvc-16.00-x86)
        m = re.fullmatch(r"\(\s*\(\s*(?:struct\s+)?([A-Za-z_]\w*)\s*\*\s*\)\s*(.+)\)\s*\[(.*)\]", base, re.S)
        def paired(x):
            depth = 0
            for ch in x:
                depth += ch in "(["
                depth -= ch in ")]"
                if depth < 0:
                    return False
            return depth == 0
        if m and self.struct_of(m.group(1)) and paired(m.group(2)) and paired(m.group(3)):
            s = self.struct_of(m.group(1))
            return f"((char *)({m.group(2)}) + ({m.group(3)}) * {self.composites[s]['size']})", ("struct", s)
        m = re.fullmatch(r"_*(?:DAT|PTR)_[0-9a-f]{0,}?([0-9a-f]{8})", base)
        if m:
            n, t = self.refdata.get(int(m.group(1), 16), (0, ""))
            s = self.struct_of(t)
            if s:
                return f"(char *)REFP(0x{int(m.group(1), 16):x})", ("struct", s)
        # (and one Ghidra labels by its type, as the data there is: the image's own
        # IMAGE_NT_HEADERS32_004000e0, which VS2010's static startup reads to tell a managed app,
        # `IMAGE_NT_HEADERS32_004000e0.Signature + e_lfanew + 8`; its ___tmainCRTStartup was a
        # stub for it, rhtest msvc-16.00-x86 2026-10-24)
        m = re.fullmatch(r"([A-Za-z_]\w*?)_([0-9a-f]{8})", base)
        if m:
            n, t = self.refdata.get(int(m.group(2), 16), (0, ""))
            s = self.struct_of(t) if t == m.group(1) else None
            if s:
                return f"(char *)REFP(0x{int(m.group(2), 16):x})", ("struct", s)
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
        for m in re.finditer(r"\)\s*\._(\d+)_(\d+)(f?)_", body):
            if m.start() < i:
                continue
            start = self.base_start(body, m.start() + 1)
            if start is None or start < i:
                continue
            base = body[start:m.start() + 1]
            n = m.group(2)
            t = {"4": "float", "8": "double"}.get(n, f"undefined{n}") if m.group(3) else f"undefined{n}"
            # (an array member's place, already its bytes' address, `((char *)(frame + 0x494) + 2)`
            # for `local_30.sa_data`: a piece of it there, no address of an address, 0xdbf920)
            addr = base if re.match(r"\(\s*\(\s*(?:char|undefined\d*|unsigned char)\s*\*\s*\)", base) else f"&{base}"
            rep = (f"(*({t} *)((char *){addr} + {m.group(1)}))" if n in ("1", "2", "4", "8")
                   else f"GEN_PIECE({addr}, {m.group(1)}, {n})")
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
        # (character literals first: `'"'` opened a string to the next quote, and a path's
        # "hkxEnvironment.cpp" after it read as a member, 0xde59e0)
        rest = re.sub(r"L?'(?:\\.|[^'\\\n])+'", "0", body)
        rest = re.sub(r'L?"(?:\\.|[^"\\])*"', '""', rest)
        if structs:
            rest = re.sub(r"\b(?:" + "|".join(map(re.escape, structs)) + r")\s*(?:\[[^\]]*\])?(?:\.[A-Za-z_]\w*)+", "", rest)
            # (and an element of one as the decompiler indexes it, `(&local_298)[uVar5].left`)
            rest = re.sub(r"\(\s*&\s*(?:" + "|".join(map(re.escape, structs)) + r")\s*\)\s*\[[^\]]*\](?:\.[A-Za-z_]\w*)+", "", rest)
        if spointers:
            rest = re.sub(r"\b(?:" + "|".join(map(re.escape, spointers)) + r")\s*->\s*[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", "", rest)
        m = re.search(r"[\w\)\]]\s*->\s*\w|(?<![\d.])\b[A-Za-z_]\w*\s*\.[A-Za-z_]|[\)\]]\s*\.[A-Za-z_]", rest)
        if m:
            raise ValueError(f"member access through a type C does not have ({m.group(0)[:30]})")

    def rewrite(self, a: int) -> str:
        """The function's C, translated (raises ValueError when it cannot be)."""
        sig = self.sigs[a]
        self.cur_params = sig.params              # (pointer_steps: the parameters' types)
        self.cur_gt = self.corpus[a].get("gt") or {}  # (global_lvalue: the decompiler's types of the globals)
        c = self.entry_registers(a, self.kept_inputs(self.kept_st0(stack_vs_const(neg_scaled(v16_forms(cpu_state(array_stores(locked_reads(switch_guarded_loads(wide_subscripts(strip_comments(self.corpus[a]["c"]))))))))))))
        # (the registers a failure reporter only records, context_capture: locals of their own,
        # zeroed at the end, by names that read as no register: `in_ES` would be one)
        for n in context_capture(c):
            c = re.sub(rf"\b{n}\b", "cap_" + n.split("_", 1)[1], c)
        # (and a CRT math tail's entry flag, libm_flag: the test it stands for)
        flag = libm_flag(c)
        if flag:
            c = re.sub(r"(?m)^[ \t]*\w+\s+in_ZF\s*;[ \t]*\n", "", c)
            c = re.sub(r"\bin_ZF\b", flag, c)
        # (a long C++ name Ghidra wraps at a `::`, `IpcChannel::\n        PacketBufferTmpl<...>::\n
        # vftable`: one name again, as the data export has it. 1,090 stubs, 2026-10-23)
        c = re.sub(r"::[ \t]*\n[ \t]*", "::", c)
        # (or wraps before it, `...::ChatProtoDownCallbackInterface\n                 ::vf0`, a
        # name's end then a line starting `::`: one name too, before the global scope's `::` goes)
        c = re.sub(r"(?<=[\w>])[ \t]*\n[ \t]*::(?=[A-Za-z_~])", "::", c)
        # (and a name Ghidra qualifies from the global scope, `::Common::Config::Item::vftable`, where
        # the function's own namespace has a `Common` too: the data export has it without the
        # leading `::`. Left so, 140 functions of a client with RTTI class names were stubs,
        # 2026-10-25)
        c = re.sub(r"(?<![\w$:>)\]])::(?=[A-Za-z_])", "", c)
        # (Ghidra's INT_MIN, `-0x80000000`: C reads 0x80000000 as unsigned, and its negation too,
        # so `-0x80000000 >> n`, an x86 `sar` making a mask of ones, shifted in zeros. The
        # graphics allocator's free-bucket mask found no bucket, a VS2010 client 2026-10-24)
        c = int_min(c)
        c = bool_products(c)
        # (a shift's 8-byte constant as the decompiler suffixes it, `1L << k`: long is 4 bytes on the
        # Windows host, so the shift was 32-bit, 1 << (k & 31), and 1L << 31 sign-extended into the high
        # word. CharacterBase::SetMaskBit 0x689570, 30 functions, 2026-10-31)
        c = re.sub(r"(?<![\w.'])((?:0x[0-9a-fA-F]+|\d+)U?)L(?=\s*<<)", r"\1LL", c)
        c = re.sub(r"(?<=[\w>])[ \t]*\n[ \t]*::", "::", c)
        # (a label named as the function that starts there, `FUN_00410044:` and `goto FUN_00410044;`
        # inside FUN_0041002d: a label still, not that function's address, a VS2010 client 2026-10-25)
        for lab in set(re.findall(r"(?m)^\s*(FUN_[0-9a-f]{8})\s*:(?!:)", c)):
            c = re.sub(rf"(?m)^(\s*){lab}(\s*:)(?!:)", rf"\1LAB_{lab[4:]}_f\2", c)
            c = re.sub(rf"\bgoto\s+{lab}\s*;", f"goto LAB_{lab[4:]}_f;", c)
        head, sep, body = c.partition("{")
        body = out_stack("{" + body, "replaced with injection: alloca_probe" in self.corpus[a]["c"],
                         bool(EH_PROLOG.search(self.corpus[a]["c"]) or EH_LINK.search(body)) or a in self.hands_ebp)
        # (a small array assigned whole from its bytes, `local_64 = (char [4])s_alpha_0040324c._0_4_;`,
        # strcpy of a literal inlined: the bytes through a temporary of that size, C having no
        # array assignment, rhtest crt-O2 2026-10-24)
        def array_set(m):
            n = int(m.group(4)) * (2 if m.group(3) in ("wchar_t", "ushort", "short", "undefined2") else 1)
            t = {1: "unsigned char", 2: "unsigned short", 4: "unsigned int", 8: "unsigned long long"}.get(n)
            if t is None:
                return m.group(0)
            return f"{m.group(1)}{{ {t} gen_ac = ({t})({m.group(5)}); memcpy(&{m.group(2)}, &gen_ac, {n}); }}"
        body = re.sub(r"(?m)^([ \t]*)([A-Za-z_]\w*) = \(\s*(char|undefined1|byte|uchar|wchar_t|ushort|short|undefined2)"
                      r"\s*\[(\d+)\]\s*\)\s*([^;\n]+);", array_set, body)
        # (and from a value with no array cast, `local_8 = SUB42(uVar2,0);` of an `undefined1
        # local_8 [2]`, or read whole, `(ushort)local_8`: Ghidra's word store into a byte array,
        # FUN_005b2c00 in a VS2010 client 2026-10-25)
        body = self.small_arrays(body)
        body = self.stale_loads(a, body)
        # (the entry esp itself, in a function whose frame frame_locals lays out: the frame's top,
        # GEN_SLOT(0), each local GEN_SLOT(N) below it. Ghidra folds a sum of `p - buf` over a local
        # buffer into `(int)&stack0x00000000 * -8`, strings()'s strchr and strrchr offsets, rhtest
        # crt-Od 2026-10-24)
        if has_frame(body):
            body = re.sub(r"&\s*stack0x00000000\b", "GEN_SLOT(0x0)", body)
            body = re.sub(r"\(\s*(u?int)\s*\)\s*GEN_SLOT\(0x0\)", r"(\1)(uintptr_t)GEN_SLOT(0x0)", body)
        # (the x87 control word, `fnstcw` read and `fldcw` written: the runtime's per-thread
        # virtual one, gen_x87_cw, MSVC's default 0x27f until the program or Direct3D sets it. As
        # the constant 0x27f, the CRT's math took its 53-bit path where the reference, its precision
        # 24 bits since Direct3D's CreateDevice, took the other, a client's shadow trace parting in
        # its tan, 2026-10-26. The conversions it is set for, `| 0xc00`, are C's own casts here)
        body = re.sub(r"(?m)^\s*[A-Za-z_]\w*\s+in_FPUControlWord\s*;\s*\n", "", body)
        body = re.sub(r"(?m)^([ \t]*)in_FPUControlWord\s*=\s*([^;\n]*);",
                      r"\1gen_set_x87_cw((unsigned short)(\2));", body)
        body = re.sub(r"\bin_FPUControlWord\b", "gen_x87_cw", body)
        # (and the loads the patched SLEIGH keeps as operations, ghidra/sleigh/patch_sinc.py: `fldcw`
        # the word, `fldenv` the environment's first word)
        body = re.sub(r"\bx87_fldcw\s*\(", "gen_set_x87_cw((unsigned short)", body)
        body = re.sub(r"\bx87_fldenv\s*\(", "gen_set_x87_cw(*(unsigned short *)", body)
        # (and the status word, `fnstsw`: the host's floating-point flags as x87 bits; cleared after
        # the read where the function runs fnclex, which the decompiler drops, protos32's fpu_clear:
        # __clrfp, rhtest msvc-16.00-x86 float)
        body = re.sub(r"(?m)^\s*[A-Za-z_]\w*\s+in_FPUStatusWord\s*;\s*\n", "", body)
        body = re.sub(r"\bin_FPUStatusWord\b", f"gen_fpusw({1 if a in self.fpu_clear else 0})", body)
        if "ROUND(" in body and self.truncates(a):
            body = re.sub(r"\bROUND\(", "TRUNC(", body)
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

        # (a 4-byte piece the body dereferences or indexes holds a pointer, as the reference stores
        # one: a double's stack slot reused for a buffer's address, `local_2f0._4_4_ = (undefined4
        # *)uVar9; *local_2f0._4_4_ = local_60[0]; local_2f0._4_4_[1] = local_50;`. As undefined4,
        # C refused the dereference and a VS2010 client's WeatherRenderer::vf2 was a stub on its
        # frame path, 2026-10-27)
        # (its element type the one the body assigns it as, `= (undefined4 *)`: with none, the
        # element's size is unknown and the function stays a stub)
        used = set(re.findall(r"(?:^|[=(,;{}!?:]|\breturn)\s*\*\s*([A-Za-z_]\w*\._\d+_4_)(?![\w.\[])", body, re.M))
        used |= set(re.findall(r"(?<![.\w>])\b([A-Za-z_]\w*\._\d+_4_)\s*\[", body))
        ptr_pieces = {}
        for p in used:
            ts = set(re.findall(r"(?<![.\w>])\b" + re.escape(p) + r"\s*=(?!=)\s*\(\s*((?:unsigned\s+)?[A-Za-z_]\w*)\s*\*\s*\)", body))
            if len(ts) == 1 and next(iter(ts)) in KNOWN_TYPES:
                ptr_pieces[p] = next(iter(ts))

        def piece(m):
            name, off, size, tag = m.group(1), m.group(2), m.group(3), m.group(4)
            if size not in ("1", "2", "4", "8"):
                return f"GEN_PIECE(&{name}, {off}, {size})"
            if not tag and size == "4" and f"{name}._{off}_4_" in ptr_pieces:
                return f"(*({ptr_pieces[f'{name}._{off}_4_']} * PTR32 *)((char *)&{name} + {off}))"
            # (the decompiler's float tag, `_4_4f_` (patch/printc.cc): a piece it types as a float,
            # and an untagged one its bits. The guess before the tag, every 4-byte piece of a
            # 16-byte register a float lane, made /O2's packed doubles' halves floats: horner's
            # coefficients converted, rhtest float 2026-10-24)
            if tag:
                t = {"4": "float", "8": "double"}.get(size, f"undefined{size}")
            else:
                t = f"undefined{size}"
            return f"(*({t} *)((char *)&{name} + {off}))"
        # (`(float)x` of an untyped 8-byte x: its low half's bits as a float, the piece the decompiler
        # prints as a cast where it tags the high one `x._4_4f_`. Converted by value, VS2010's
        # /arch:SSE2 vec_check read cross()'s c.x as 2^62-odd, rhtest msvc-16.00-x86 float-SSE2)
        # (the decompiler's own bit view of a wider symbol's low piece, `gen_bits2f((uint)local_58)`
        # (patch/printc.cc pushPartialSymbol): that piece, whatever type a later pass gives the
        # symbol. A global typed float by its other uses read `(uint)REFG(float, ...)`, a value
        # conversion, 0xd93970's bone transform)
        body = re.sub(r"\bgen_bits2([fd])\(\s*\(\s*(?:uint|ulonglong|unsigned int|unsigned long long)\s*\)\s*"
                      r"([A-Za-z_]\w*)\s*\)", lambda m: f"{m.group(2)}._0_{'4' if m.group(1) == 'f' else '8'}f_", body)
        wide = set(re.findall(r"(?m)^[ \t]+undefined8[ \t]+([A-Za-z_]\w*)[ \t]*;", body))
        if wide:
            body = re.sub(r"\(float\)\s*(" + "|".join(sorted(wide)) + r")\b(?![.\[(])", r"\1._0_4f_", body)
        # (a field of an x86 CRITICAL_SECTION through a cast pointer, `((LPCRITICAL_SECTION)*p)[1]
        # .DebugInfo`: its offset in the reference's 24-byte layout, the type C has only as bytes
        # (GEN_CRITICAL_SECTION32). A lock table's "initialized" flag, 0xcc6700)
        def cs_field(m):
            off, t = CS_FIELDS[m.group(3)]
            return f"(*({t} *)((char *)(uintptr_t)({m.group(1)}) + ({m.group(2)}) * 24 + {off}))"
        body = re.sub(r"\(\s*\(\s*(?:LPCRITICAL_SECTION|PRTL_CRITICAL_SECTION)\s*\)\s*([^()]*?)\s*\)\s*\[\s*([^\]]+?)\s*\]\s*\.\s*("
                      + "|".join(CS_FIELDS) + r")\b", cs_field, body)
        # (a string label's piece, `s_<SystemRoot_01127fef._1_4_`: the bytes at its address plus
        # the offset, as its own name's characters, `<` among them, would not survive the piece's
        # name. The C runtime's spawn copying "<SystemRoot>" by words, 0xc7e791)
        body = re.sub(r"(?<![\w$])_*(?:s|u|ws)_[\w<>:]*?_([0-9a-f]{8})\._(\d+)_([1248])_",
                      lambda m: f"(*(undefined{m.group(3)} *)REFP(0x{int(m.group(1), 16) + int(m.group(2)):x}))", body)
        # (an in_addr's union, its one member at 0: `in.S_un._2_1_` a piece of `in`'s 4 bytes, a
        # socket address printed with inet_ntoa, 0xdbf920)
        body = re.sub(r"\b([A-Za-z_]\w*)\.S_un(?=\._\d+_\d+f?_|\.S_addr\b)", r"\1", body)
        body = re.sub(r"\b([A-Za-z_]\w*)\.S_addr\b", r"(*(unsigned int *)&\1)", body)
        # (a piece the decompiler wrapped after its dot, `in_XMM3.\n _4_4f_`, whole again)
        body = re.sub(r"(\w)\.[ \t]*\r?\n[ \t]*(_\d+_\d+f?_)", r"\1.\2", body)
        body = re.sub(r"(\w)\.[ \t]+(_\d+_\d+f?_)", r"\1.\2", body)
        # (not a field's, `local_20.x._0_4_`: members() places the field first, paren_pieces after)
        body = re.sub(r"(?<![.\w>])(?<!\.\s)\b([A-Za-z_]\w*(?:\[[^\]\[]*\])?)\._(\d+)_(\d+)(f?)_", piece, body)
        # (a float lane in a bit mask, `~-(uint)(fVar15 < fVar11) & auVar2._4_4_`: Ghidra's SSE
        # compare-and-select, its float and its bits in one expression C cannot have)
        # (the lane itself an operand of the bit operator: not one assigned bits through the
        # decompiler's bit views, `piece = gen_bits2f(gen_fl2bits(x) ^ mask)`, rhtest float)
        # (by statement, the decompiler's wrapped lines joined: `gen_fl2bits((c - a * b)\n * d) &
        # m` read line by line had its second line's `) &` after a lane)
        for line in (re.sub(r"\s*\n\s*", " ", s) for s in re.split(r"(?<=[;{}])[ \t]*\n", body)):
            if "(*(float *)((char *)&" in line:
                rest = re.sub(r"\(\*\(float \*\)\(\(char \*\)&[\w\[\]]+ \+ \d+\)\)", "LANE", line)
                rest = re.sub(r"\(\w[\w ]*\*\)&|&\w", "", rest)
                # (its bits are no lane: `(uint)gen_fl2bits(c.x) ^ ...`, vec_check)
                # (nor an expression's bits, `gen_fl2bits((c - LANE * LANE) * LANE) & mask`, its
                # parentheses balanced: an SSE reciprocal's Newton step masked, 7 of a client's)
                while True:
                    m = re.search(r"\bgen_fl2bits\(", rest)
                    if not m:
                        break
                    depth, j = 1, m.end()
                    while j < len(rest) and depth:
                        depth += {"(": 1, ")": -1}.get(rest[j], 0)
                        j += 1
                    rest = rest[:m.start()] + "BITS" + rest[j:]
                if re.search(r"LANE\s*\)*\s*(?<![&|])[&|^](?![&|=])|(?<![&|])[&|^~](?![&|=])\s*\(*\s*LANE", rest):
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
        # (and a piece of a field, `local_20.x._0_4_`, now that the field is an lvalue: VS2010's
        # __fltin2, its _CRT_DOUBLE's halves, rhtest msvc-16.00-x86 crt)
        body = self.paren_pieces(body)
        self.leftover_members(body, a)
        # (a pointer cast of an 8-byte integer, `(int *)local_30`: its low four bytes, the decompiler's
        # truncation. Whole on x64, the sentry's ok flag in the pointer's upper half, and ostream's
        # operator<< faulted, rhtest stl /MT)
        wide = set(re.findall(r"(?m)^[ \t]+(?:undefined8|ulonglong|longlong|qword|uint8|int8)\s+([A-Za-z_]\w*)\s*;",
                              split_decls(body)[0]))
        if wide:
            body = re.sub(r"(\(\s*[A-Za-z_][\w ]*?\s*\*+\s*\))(\s*)(" + "|".join(map(re.escape, sorted(wide)))
                          + r")\b(?!\s*(?:\.|\[|->))", r"\1\2(uint)\3", body)
        # (types before names: a C++ type in a cast, `(Client::UI::Foo *)`, is no symbol)
        body = self.types(body)
        # (`a + -b` as `a - b`, the same for integers and pointers: a 32-bit unsigned b negated is
        # 2^32 - b, and added to a 64-bit pointer it moved it 4 GB on, VS2010's qsort stepping back
        # by `puVar9 + -_SizeOfElements`, rhtest msvc-16.00-x86 crt)
        body = re.sub(r"(?<![+\-])\+\s*-\s*(?=[A-Za-z_(])", "- ", body)
        # (the function's own namespaces, innermost first: a name Ghidra prints relative to them,
        # `vftable` in std::exception's constructor, eh-Od)
        parts = self.corpus[a]["name"].split("::")[:-1]
        self.cur_ns = ["::".join(parts[:k]) + "::" for k in range(len(parts), 0, -1)]
        # (and a call to a method of the same class, which Ghidra prints unqualified: the scalar
        # deleting destructor's `_vbase_destructor_(this + -0xc)`, FID's std::basic_iostream for
        # cpp's Left, rhtest msvc-16.00-x86 cpp-Od 2026-10-25)
        parts = self.sigs[a].name.split("::")[:-1]
        self.cur_call_ns = ["::".join(parts[:k]) + "::" for k in range(len(parts), 0, -1)]
        body = self.names(body)
        body = self.literal_places(body, a)
        body = interlocked(body, re.split(r"(?m)^\{", self.corpus[a]["c"], 1)[0])
        body = jump_calls(body, self.linked_jumps)
        body = CC.sub("", body)
        body = re.sub(r"\(uint\)&stack0x[0-9a-f]+", "0u", body)
        body = RAM.sub(lambda m: f"REFG({RAM_TYPES.get(m.group(1), 'undefined4')}, 0x{m.group(2)})", body)
        body = re.sub(r"\b(\w+)_exref\b",
                      lambda m: f"((code *)gen_imp_{cid(self.import_of(m.group(1)))})" if self.import_of(m.group(1))
                      else m.group(0), body)
        # an undefinedN value in a signed comparison as the signed type of its width (Ghidra32.h's
        # are unsigned: insertion_sort's `-1 < local_8` was never true at /Od, rhtest 2026-10-24)
        body = signed_tests(body, [f"{t} {n}" for t, n in sig.params])
        # (and one beside a signed operand: the op is signed, `uStack_1c / (longlong)x`)
        body = signed_siblings(body, [f"{t} {n}" for t, n in sig.params])
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
        # (__snwprintf_s and the scanf family, the caller's stack, 2026-10-23).
        # A parameter's address taken (`&param_2`) is an address in that block too: an object
        # passed by value is several parameters to Ghidra, and the callee given &param_2 reads
        # param_4 at +8. Every parameter is then its slot, read and written there (a VS2010 client's
        # FUN_00414960 passed its by-value string's first word to FUN_0042cbc0, which copied a
        # garbage length from the next local, 2026-10-24)
        param_names = [n for _t, n in sig.params]
        # (the unary `&` only: `param_1 & param_2` is no address, and its parameters' slots for it
        # were the x86 build's every read a load from a copy, rhtest core-Od's bits)
        param_addressed = bool(param_names) and any(
            not binary_amp(body, m.start()) for m in re.finditer(r"(?<![&\w])&\s*(?:" + "|".join(map(re.escape, param_names)) +
                                 r")\b(?!\s*(?:\[|\.|->))", body))
        # (a function that links an EH frame: its arguments in its frame, above the return address,
        # as the reference's are, its funclets reaching them through ebp. deep()'s Guard lives in
        # its parameter's slot, [ebp + 8], and the unwind funclet read past the frame, rhtest eh)
        # (or links it through the CRT's prolog, whose call fixup shows no link: __wfsopen keeps its
        # stream in its first parameter's slot for its __finally, a VS2010 client 2026-10-24)
        eh_prolog = bool(EH_PROLOG.search(self.corpus[a]["c"]))
        # (or hands its ebp to a callee reading through it, its arguments at [ebp + 8] that
        # callee's to copy: __ctrandisp1's helper 0xc6ba5c, hands_ebp)
        eh = (bool(EH_LINK.search(body)) or eh_prolog or a in self.hands_ebp) and bool(sig.params)
        eh_args: list[str] = []
        # (or esp itself read as it came in, register0x00000010, the walk below: a structure by value
        # copied off the stack, `lea esi, [esp + 0x44]; rep movsd`, VS2010's sum_big, rhtest
        # msvc-16.00-x86 core-O2 big)
        if sig.variadic or param_addressed or eh or re.search(r"&\s*stack0x(?!f[0-9a-f]{7}\b)[0-9a-f]{8}", body) \
                or (re.search(r"\bregister0x00000010\b", body) and sig.params):
            if sig.variadic and not params:
                raise ValueError("variadic with no fixed parameter")
            # (each parameter at its slot as the reference pushed it: a double or an 8-byte integer
            # two words, a float one; a float10 is 12 bytes there, and its 8 here do not fill them)
            # (a register parameter has no slot: a __thiscall's `this` in ecx, a __fastcall's first
            # two. The CRT's __crt_seh_guarded_call<void>::operator(), __thiscall by its FID
            # signature, gave `this` [ebp + 8], and its __finally funclet read the lock's pointer
            # there, rhtest stl-O2's startup)
            # (the signature's own convention, not a Function ID comment's above it)
            head = strip_comments(self.corpus[a]["c"]).split("{", 1)[0]
            ccm = CC.search(head)
            in_regs = {"__thiscall": 1, "__fastcall": 2}.get(ccm.group(1) if ccm else "", 0)
            at_slot, fixed = [], 0
            for k, (t, _n) in enumerate(sig.params):
                # (and one ApplyFacts gave a register, `in_eax`, `in_st0`: the C runtime's
                # _startOneArgErrorHandling takes st0 and three registers before its stack words)
                if (k < in_regs and abi_type(self.type_text(t)) == "unsigned int") or \
                        re.fullmatch(r"in_(?!stack)[A-Za-z]\w*", _n):
                    at_slot.append(None)
                    continue
                if self.type_text(t).replace("*", "").strip() == "float10" and "*" not in self.type_text(t):
                    raise ValueError("an argument block with a float10 parameter")
                at_slot.append(fixed)
                fixed += 2 if abi_type(self.type_text(t)) in ("double", "unsigned long long") else 1
            words = fixed + (VA_WORDS if sig.variadic else 0)
            block = [f"  unsigned int gen_args[{max(words, 1)}];"]
            # (the register parameters' own locals, as the parameters' prologue declared them)
            in_reg = [prologue[k] for k in range(len(sig.params)) if at_slot[k] is None]
            for k, (t, _n) in enumerate(sig.params):
                if at_slot[k] is None:
                    continue
                if abi_type(self.type_text(t)) == "unsigned int":
                    block.append(f"  gen_args[{at_slot[k]}] = gen_a{k};")
                else:
                    block.append(f"  memcpy(&gen_args[{at_slot[k]}], &gen_a{k}, sizeof gen_a{k});")
            if sig.variadic:
                last = len(sig.params) - 1
                block += [f"  {{ va_list gen_va; va_start(gen_va, gen_a{last});",
                          f"    for (int gen_i = {fixed}; gen_i < {words}; gen_i++) "
                          f"gen_args[gen_i] = va_arg(gen_va, unsigned int);",
                          "    va_end(gen_va); }"]
            if param_addressed or eh:
                # (the slots are the parameters: a pointer one a 32-bit pointer in its slot)
                for k, (t, n) in enumerate(sig.params):
                    if at_slot[k] is None:
                        continue
                    tt = self.type_text(t)
                    slot_t = f"{tt} PTR32" if "*" in tt else tt
                    if re.fullmatch(r"code\s*\*", tt.strip()):
                        # (a function pointer: 4 bytes as gen_code32, as frame_locals stores one, a
                        # call through it converted; as a `(code *)` cast it could not be assigned,
                        # FUN_00db9550's `param_1 = (code *)(...)` in a VS2010 client 2026-10-25)
                        slot_t = "gen_code32"
                        body = re.sub(rf"\(\s*\*\s*{re.escape(n)}\s*\)(?=\s*\()", f"((code *){n})", body)
                    body = re.sub(rf"\b{re.escape(n)}\b", f"(*({slot_t} *)&gen_args[{at_slot[k]}])", body)
                prologue = in_reg + block
            else:
                prologue = block + prologue
            if eh:
                # (the block is the frame's own, frame_locals: declared after it, filled there)
                eh_args = [f"  unsigned int *gen_args = (unsigned int *)(gen_frame + GEN_ARGS_AT);"] + block[1:]
                eh_args.append(f"  /* GEN_ARGS_WORDS {max(words, 1)} */")
                prologue = in_reg
            var_types["gen_args"] = "unsigned int[]"

            def slot(m):
                off = int(m.group(1), 16)
                # (an address past the arguments taken, never a read: a frame array's end, `lea esi,
                # [ebp + 8]` stepped down 0x74 at a time to destroy each, 0x828fe0. Above the
                # frame's buffer as the reference's is above its frame, frame_locals' GEN_ABOVE)
                if off >= 4 + 4 * words:
                    return f"((undefined *)GEN_ABOVE(0x{off:x}))"
                if off < 4:
                    raise ValueError(f"the caller's stack beyond its arguments (stack0x{m.group(1)})")
                # (or a byte inside a word, `&stack0x0000000a`: a char parameter's slot's upper
                # bytes used for a short, the reference's own scratch, a client's 0x62e0b0)
                if off % 4:
                    return f"((undefined *)&gen_args[{(off - 4) // 4}] + {off % 4})"
                return f"((undefined *)&gen_args[{(off - 4) // 4}])"
            body = re.sub(r"\(uint\)\s*&\s*stack0x(?!f[0-9a-f]{7}\b)([0-9a-f]{8})",
                          lambda m: f"(uint)(uintptr_t){slot(m)}", body)
            body = re.sub(r"&\s*stack0x(?!f[0-9a-f]{7}\b)([0-9a-f]{8})", slot, body)
            # (and a word of the block the signature names no parameter for, `in_stack_0000000c`: a
            # variadic function's Function ID signature one fixed parameter short, _swprintf's for
            # sprintf_s(dest, size, format, ...), rhtest stl-Od. Its slot, of its declared type)
            for m in list(re.finditer(r"(?m)^[ \t]+([A-Za-z_][\w ]*?[\s*]*)\bin_stack_(0000[0-9a-f]{4})\s*;[ \t]*\n", body)):
                off = int(m.group(2), 16)
                if off < 4 or off % 4 or (off - 4) // 4 >= words:
                    continue
                t = m.group(1).strip()
                t = f"{t} PTR32" if t.endswith("*") else t
                body = body.replace(m.group(0), "", 1)
                body = re.sub(rf"\bin_stack_{m.group(2)}\b", f"(*({t} *)&gen_args[{(off - 4) // 4}])", body)
            # (and esp itself as it came in, where the decompiler could say the address no other
            # way, `register0x00000010` (BADSPACEBASE *): VS2010's va_start takes the last fixed
            # parameter's address, `lea edx, [esp + 8]`, and steps it, and past the parameter's
            # symbol the walk is esp's. The entry esp is the return address's slot, a word below
            # the block, rhtest msvc-16.00-x86 calls-O2 sum_va)
            if re.search(r"\bregister0x00000010\b", body) and not eh:
                body = re.sub(r"\(\s*BADSPACEBASE\s*\*\s*\)", "(uintptr_t)", body)
                body = re.sub(r"\bregister0x00000010\b", "gen_esp0", body)
                # (the cast types() made of BADSPACEBASE *, an unknown type under a pointer)
                body = re.sub(r"\bgen_esp0\s*=\s*\(\s*undefined\s*\*\s*\)", "gen_esp0 = (uintptr_t)", body)
                prologue.append("  uintptr_t gen_esp0 = (uintptr_t)gen_args - 4;")
                var_types["gen_esp0"] = "uintptr_t"
            if sig.variadic:
                params.append("...")
        for m in re.finditer(r"(?m)^\s+((?:unsigned\s+)?[A-Za-z_]\w*(?:\s*\*[\s*]*(?:PTR32\s*\*\s*)*)?)\s*([A-Za-z_]\w*)\s*(\[[^\]]*\])?\s*;",
                             split_decls(body)[0]):
            # (an array is its element type with [] on: what indexes and dereferences it is fine)
            var_types.setdefault(m.group(2), m.group(1) + ("[]" if m.group(3) else ""))
        # (and sse_ops' temporaries, declared where they are computed)
        for n in set(re.findall(r"\bgen_v[tx]\d+\b", body)):
            var_types[n] = "undefined1[]"
        body = self.typed_casts(body, var_types)
        # (and a switch on a pointer variable, `switch(piVar1)` where the decompiler typed the index
        # a pointer, on its 32 bits: C switches on an integer, and its cases are integers above)
        body = re.sub(r"\bswitch\s*\(\s*([A-Za-z_]\w*)\s*\)",
                      lambda m: f"switch((unsigned int)(uintptr_t)({m.group(1)}))"
                      if "*" in var_types.get(m.group(1), "") else m.group(0), body)
        body = self.call_args(body, var_types)
        # (a code label's address indexed, `(&LAB_00436475)[param_2]`: its bytes, a jump table's
        # index bytes kept in code, FUN_004387b0 in a VS2010 client 2026-10-25)
        body = re.sub(r"\(\s*REFP\((0x[0-9a-fA-F]+)\)\s*\)\s*\[", r"((undefined *)REFP(\1))[", body)
        # (an 8-byte structure cast to an integer: its 64 bits)
        struct8_locals =[n for n, t in var_types.items() if t.strip() in STRUCT8]
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
        # (not a logical operator's, `&& DAT_01088128 != fVar1` or `|| ..`: its second character
        # read as a bitwise one made the float compared a uint converted by value, a NaN-aware
        # compare in 0x412980 and 4 like it, the operation census 2026-10-31)
        bitop = r"(\^\s*|(?<!\|)\|(?![|=])\s*|(?<!&)&\s+)"
        after = r"(?=\s*(?:\^|\|(?!\|)|&(?!&)|>>|<<))"
        body = re.sub(bitop + r"REFG\(float, (0x[0-9a-f]+)\)", r"\1REFG(uint, \2)", body)
        body = re.sub(r"REFG\(float, (0x[0-9a-f]+)\)" + after, r"REFG(uint, \1)", body)
        body = re.sub(bitop + r"REFG\(double, (0x[0-9a-f]+)\)", r"\1REFG(ulonglong, \2)", body)
        body = re.sub(r"REFG\(double, (0x[0-9a-f]+)\)" + after, r"REFG(ulonglong, \1)", body)
        # (and its low word beside its high one, a double passed as the two stack words it is:
        # `f(this, (int)DAT_004034a0, (int)((ulonglong)DAT_004034a0 >> 0x20), ...)`, the decompiler's
        # 8 bytes cut in two. `(int)` of the double was its value, 9, not its low bits, and a COM
        # method's `a / b` divided 0, rhtest com's Ratio(9.0, 2.0f))
        for x in set(re.findall(r"REFG\(ulonglong, (0x[0-9a-f]+)\)\s*>>\s*0x20", body)):
            body = re.sub(r"\((u?int|undefined4)\)\s*REFG\(double, " + x + r"\)", r"(\1)REFG(ulonglong, " + x + ")", body)
        # a float global copied whole into whatever Ghidra typed the target (a mov of its 4 bytes
        # into a pointer slot): the value into a float, the bits into anything else
        def flt_to(m):
            lhs, rhs = m.group(2), m.group(3)
            # (a plain local by its declared type: the value into a float, the bits into a pointer or
            # an integer. A decompiler's assignment across types is a copy of the bytes, a conversion
            # it prints as one, `(int)x`: `uVar8 = DAT_01087f04;` of 1.0f is 0x3f800000, which C made 1)
            if re.fullmatch(r"[A-Za-z_]\w*", lhs) and lhs in var_types:
                t = var_types[lhs].strip()
                if "[" in t or t in FLOATS:
                    return m.group(0)
                if "*" not in t:
                    if t not in KNOWN_TYPES:
                        return m.group(0)
                    bits = "gen_d2bits((double)(" if rhs.startswith("REFG(double") else "gen_fl2bits((float)("
                    return f"{m.group(1)}{lhs} = ({t}){bits}{rhs}))"
                return f"{m.group(1)}{lhs} = ({t})(uintptr_t)gen_fl2bits((float)({rhs}))"
            return f"{m.group(1)}{lhs} = GEN_FLT_TO({lhs}, {rhs})"
        # (or through a cast, `*(int * PTR32 *)&REFG(undefined, 0x14882cc) = REFG(float, ...)`, a
        # global Ghidra typed a pointer that a float is stored in: C2440, a VS2010 client's camera
        # update demoted on its frame path, 2026-10-27)
        body = re.sub(r"(?m)((?:^|[;{(,])\s*)((?:\*\s*)*[A-Za-z_]\w*(?:\s*\[[^\]\[]*\])*"
                      r"|\*\s*\(\s*[A-Za-z_][\w\s*]*\)\s*(?:&\s*REFG\([\w ,]+\)|\([^;=()]*(?:\([^;=()]*\)[^;=()]*)*\)))\s*=(?!=)\s*"
                      # (an index with one more inside, `[(int)((*(int *)&gen_args[2]))]`: a table of
                      # floats Ghidra typed pointers indexed by a spilled argument, C2440, 0x9919e0
                      # demoted on a client's startup path, 2026-10-28)
                      r"(REFG\((?:float|double), 0x[0-9a-f]+\)|\(&REFG\((?:float|double), 0x[0-9a-f]+\)\)"
                      r"\[(?:[^\]\[]|\[[^\]\[]*\])*\])"
                      r"(?=\s*[;,)])", flt_to, body)
        # (a statement of its own storing one through a dereference nested any deeper, `*(undefined4
        # *)((int)(*(unsigned int *)(gen_frame + 0x34)) + 0x1738) = REFG(float, ...);`: the line's
        # left side whole)
        # (or the dereference in parentheses, `(*(undefined4 *)(gen_frame + 0x10)) = REFG(float, ..)`
        # (a frame slot), or twice, `**(undefined4 * PTR32 *)(p + 0x1ec) = ..`: a vector's lanes
        # filled with the float's value converted, 0xc1fa10 and 0x9d8a20, the operation census
        # 2026-10-31)
        body = re.sub(r"(?m)^([ \t]*)(\(?\*+\s*\(.+?)\s*=(?!=)\s*(REFG\((?:float|double), 0x[0-9a-f]+\))\s*;[ \t]*$",
                      lambda m: f"{m.group(1)}{m.group(2)} = GEN_FLT_TO({m.group(2)}, {m.group(3)});", body)
        # (the other way, an integer local's bits stored to a global the instructions read as a
        # float: `DAT_015d766c = uVar3;` copies 4 bytes, `REFG(float, ..) = uVar3` converted them,
        # 0xc98b30)
        def int_into_float(m):
            indent, ft, addr, name = m.groups()
            t = var_types.get(name, "").strip()
            if not t or t in FLOATS or "[" in t or "*" in t or t not in KNOWN_TYPES:
                return m.group(0)
            return f"{indent}REFG({'ulonglong' if ft == 'double' else 'uint'}, {addr}) = {name};"
        body = re.sub(r"(?m)^([ \t]*)REFG\((float|double), (0x[0-9a-f]+)\)\s*=(?!=)\s*([A-Za-z_]\w*)\s*;",
                      int_into_float, body)
        # (and a float global's bytes cut to an undefined piece, `(undefined4)DAT_01375ad0` beside its
        # `._4_4_`: its low word's bits, 0x6452c0, not the float's value)
        body = re.sub(r"\(\s*undefined4\s*\)\s*REFG\(float, (0x[0-9a-f]+)\)", r"(undefined4)REFG(uint, \1)", body)
        body = re.sub(r"\(\s*undefined([48])\s*\)\s*REFG\(double, (0x[0-9a-f]+)\)",
                      lambda m: f"(undefined{m.group(1)})REFG(ulonglong, {m.group(2)})", body)
        # (unary: `a * (*(undefined4 *)(...))` is a multiplication)
        # (the piece a pointer, as Ghidra typed what it holds: a locale facet's pointer kept in a
        # double's upper half, `*local_33c._4_4_ + 8`, std::num_get's do_get, rhtest stl-O2. An int *
        # as the decompiler's arithmetic on it counts ints)
        body = re.sub(r"(?m)((?:^|[^\w)\]\s])\s*\*\s*)\(\*\(undefined4 \*\)\(\(char \*\)&",
                      r"\1(*(int * PTR32 *)((char *)&", body)
        if re.search(r"(?:^|[^\w)\]\s])\s*\*\s*\(\*\(undefined4 \*\)\(\(char \*\)&", body, re.M):
            raise ValueError("a 4-byte piece dereferenced as a pointer")
        for n, t in var_types.items():
            # (not on its address: _tsopen_nolock's byte-order mark buffer, a `code *` to Ghidra for
            # UTF-8's EF BB BF read as FUN_00bfbbef, written from `(int)&local_20 + iVar12`)
            if t.strip() == "code *" and re.search(r"(?<![&\w])" + re.escape(n) + r"\s*[-+]\s", body):
                # (a local never called through: a byte pointer, as Ghidra counts it. The CRT's
                # atexit table grown by __recalloc_base, `local_8 + uVar6 * 4`, a pointer to
                # encoded function pointers, rhtest stl-O2)
                e = re.escape(n)
                decl = re.compile(r"(?m)^([ \t]*)code\s*\*\s*" + e + r";")
                if decl.search(body) and not re.search(r"\(\s*\*\s*" + e + r"\s*\)\s*\(|(?<![\w$])" + e + r"\s*\(", body):
                    body = decl.sub(lambda m: f"{m.group(1)}undefined *{n};", body)
                    var_types[n] = "undefined *"
                    continue
                raise ValueError("arithmetic on a code pointer")
        body = self.code_pointer_calls(body, var_types)
        body = self.called_pointers(body)
        body = self.code_slots(body, var_types)
        if a in self.x87_dispatch:
            body = self.x87_dispatch_call(body, self.x87_dispatch[a])
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
        # (one typed by its assignment is translated as that pointer, pieces above)
        if re.search(r"\._\d+_4_\s*\[", body):
            raise ValueError("a 4-byte piece indexed as a pointer")
        # (in the code, not in a string: "ios_base::eofbit set" is text)
        code_only = re.sub(r'"(?:[^"\\\n]|\\.)*"', '""', body)
        # (nor a character constant, `'`' < DAT_01372878`, a test for a lowercase letter)
        code_only = re.sub(r"'(?:[^'\\\n]|\\.)'", "0", code_only)
        # (Ghidra's stack pieces, `_uStack_1c`; not a library signature's `_StackCookie`)
        # (one the function declares is a local of its own: __setmbcp_nolock's `_cpinfo _Stack_1c;`,
        # a struct the decompiler named so, 2026-10-24)
        left = next((m for m in re.finditer(r"::|`|\bregister0x|\b_(?:local|param|[a-z]*Stack(?![A-Za-z])|auStack)\w*|\bin_(?!E[ACD]X\b|E[ACD]X_\d+\b|[ACD][LX]\b|[ACD][LX]_\d+\b|XMM\d+\b|XMM\d+_D[a-d]\b|XMM\d+_Q[ab]\b|ST0\b)[A-Z]", code_only)
                     if not (m.group(0).startswith("_") and re.search(
                         rf"^[ \t]+[\w ]+?[\s*]{re.escape(m.group(0))}(?:\s*\[\w+\])?;", code_only, re.M))), None)
        if left:
            # (with the name around it: `::` alone says nothing of which)
            around = re.search(r"[\w$:<>,~`']*\Z", code_only[:left.start()]).group(0) + \
                re.match(r"[\w$:<>,~`']*", code_only[left.start():]).group(0)
            raise ValueError(f"a name C cannot take ({left.group(0)}: {around[:80]})")
        self.undeclared(body, var_types)
        ret = self.ret_type(sig.ret)
        # (a void function's return: nothing in eax, as the reference's bare `ret` leaves it, where
        # no caller reads it (protos32's "v"; C4033 off, the port's return type stays unsigned
        # int for the calls through pointers); 0 where Ghidra saw a caller use it all the same,
        # `uVar4 = FUN_004308f0(...)`. A void function was `xor eax, eax; ret` against the
        # reference's `ret`, bytes32's smallest functions, 2026-10-27)
        if sig.ret.strip() == "void" and a not in self.ret_void:
            # (a call statement just before the return is what the function returns: the
            # reference's tail call, `jmp eax`, leaves the callee's eax for the callers that read
            # it, where Ghidra's void dropped it and 0 came back, 0x439610 in a client 2026-10-27)
            # (not Ghidra32.h's UNLOCK(), a void macro: a locked increment last, C2069 in a lambda's
            # operator() of the CRT, rhtest stl-O2)
            # (a statement of its own, the line above ended: not a wrapped call's arguments line,
            # `F_00411df0\n ((undefined *)this);`, a destructor's base call in rhtest stl-Od)
            body = re.sub(r"(?m)((?:^|[;{}])[ \t]*\n[ \t]*)((?:\(\(\w+ \*\)[^;\n]*|(?!(?:UN)?LOCK\(\))[A-Za-z_]\w*(?:[ \t]*\n[ \t]*)?\([^;\n]*)\));\s*\n[ \t]*return\s*;",
                          lambda m: m.group(1) + "return (uint)(" + re.sub(r"[ \t]*\n[ \t]*", "", m.group(2)) + ");",
                          body)
            body = re.sub(r"\breturn\s*;", "return 0;", body)
        if not balanced(body):
            raise ValueError("unbalanced braces")
        # (an indirect call's eax read whole after Ghidra narrowed its result, icall_full_result:
        # before the zeroing below takes its extraout_var for nothing)
        body = icall_full_result(body)
        # (the lost result registers it only returns: 0 where nothing set them, why_not. Last, as
        # the passes above read the declarations as `type name;`)
        # (and those only a call that does not return is given, noreturn_args_only)
        for n in returned_only(c) | self.unread_result(a, c) | self.noreturn_args_only(a, c) | filler_args(c) | upper_only(c) | context_capture(c) \
                | self.unread_params(c) | self.after_float_call(c) | self.upper_lanes(a, c):
            # (a pointer's too, `undefined * extraout_EAX;`: as no match it stayed uninitialized)
            body = re.sub(r"(?m)^(\s*[A-Za-z_][\w ]*?[\s*]+" + n + r")\s*;", r"\1 = 0;", body, count=1)
        body = re.sub(r"(?m)^([ \t]*[A-Za-z_][\w ]*?[ \t*]+cap_(?:[A-Z]{2,3}|EBP|retaddr))\s*;", r"\1 = 0;", body)
        # (a function that allocates on its stack, the alloca probe's injection: room below the
        # frame for it, rhtest misc stack_alloc 2026-10-24)
        alloca = "replaced with injection: alloca_probe" in self.corpus[a]["c"]
        # (and one that links an EH frame, all of its frame: its catch funclets and continuations
        # write through ebp into locals the body itself never touches, by_type's result and catch
        # object at [ebp - 0x14] and [ebp - 0x18], below the 16 bytes it did, rhtest eh 2026-10-24)
        eh = bool(EH_LINK.search(body)) or eh_prolog
        body = frame_locals(body, 0x10000 if alloca else 0, self.frames.get(a, 0) if eh or a in self.hands_ebp else 0, eh_args,
                            ebp=self.has_frame(a))
        body = global_index(body)
        body = pointer_index(body, var_types)
        # (and a pointer's bare addends, `pcVar3 + uVar4`: 32-bit as x86 adds them, 0x55c170)
        body = pointer_addends(body, var_types)
        body = idiv32(body)
        body = self.hlt_loops(a, body)
        body = self.spin_polls(a, body)
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
        if eh:
            body = eh_landing(body, ret)
            body = eh_state_volatile(body)
        decl = self.conv_decl(a, ret, params)
        body = self.conv_calls(body, a)
        # (an integer added negated as the subtraction it was, `(int)this + -4` -> `- 4`: the same
        # value, and the compiler's `sub ecx, 4` for it where `+ -4` was `add ecx, -4`, bytes32)
        body = re.sub(r"\+ -((?:0x[0-9a-f]+|\d+)\b)(?![.\w])", r"- \1", body)
        # (where the reference's code masks no count itself, `and ecx, 0x1f`: the source's own mask,
        # `x << (n & 31)` a /Od build keeps, prints the same, rhtest core-Od's rotl)
        if b"\x83\xe1\x1f" not in self.ref_code(a):
            body = shift_counts(body)
        # (a float argument of a call through a pointer, its bits: late, the globals REFG and the
        # x87 result's calls gen_fcode by now)
        # (a 3, 5, 6 or 7-byte value through a pointer, its own bytes: odd_width_access)
        body = odd_width_access(body, var_types)
        body = self.pointer_call_args(body, var_types)
        body = math_import_args(body)
        # (an x87 extended constant of the reference's read as one, `*(float10 *)&REFG(undefined,
        # 0x111ad1e)` for `fld tbyte [0x111ad1e]` (32767.5): float10 is a double here and the plain
        # read took its mantissa's 8 bytes, NaN, so the C runtime's exp core 0xc5eb1e always took its
        # out-of-range path and its +inf at 0x111ad00 read -0.0. Its 10 bytes, gen_ld80. Reads only;
        # the frame's 10-byte slots stay doubles stored and loaded alike. 2026-10-30)
        body = re.sub(r"\*\s*\(\s*float10\s*\*\s*\)\s*&\s*REFG\(\s*undefined\s*,\s*(0x[0-9a-f]+)\s*\)(?!\s*=[^=])",
                      r"gen_ld80(&REFG(undefined, \1))", body)
        # (and a function that reads the unit's status flags: its floating-point locals volatile)
        body = fp_status_volatile(body)
        # (and an x87 function's results under the control word's precision, GEN_X87)
        # (or only its sqrt, the C runtime's, which the decompiler injects, rh_sqrt: x87's fsqrt
        # whatever the caller computes in, rhtest fpenv-Od's sqrt under _PC_24)
        if self.x87_arith(a):
            body = x87_precision(body, var_types, self.ret_type(sig.ret).strip() in ("double", "float10", "float"))
        elif "replaced with injection: rh_sqrt" in self.corpus[a]["c"]:
            body = x87_precision(body, var_types, False, sqrt_only=True)
        # (a pointer loaded from its slot and dereferenced at once, through GEN_NE: checked in the
        # checked build, as it is in any other; last, no pass after reads these forms)
        body = ptr32_derefs(body)
        # (the shadow trace's record of the call, first: its address and first four integer
        # arguments, as shadow32.py records the reference's: its words, a float's bits and an
        # 8-byte argument's two words)
        args = []
        for k, (t, _n) in enumerate(sig.params[:4]):
            abi = abi_type(self.type_text(t))
            if abi == "float":
                args.append(f"gen_trace_f(gen_a{k})")
            elif abi == "double":
                args += [f"(unsigned int)gen_trace_d(gen_a{k})", f"(unsigned int)(gen_trace_d(gen_a{k}) >> 32)"]
            elif abi == "unsigned long long":
                args += [f"(unsigned int)gen_a{k}", f"(unsigned int)(gen_a{k} >> 32)"]
            else:
                args.append(f"gen_a{k}")
        args = (args + ["0u"] * 4)[:4]
        prologue = [f"  GEN_ENTER(0x{a:x}u, {', '.join(args)});"] + prologue
        # (the parameters' names are locals now, declared first in the body)
        body = body.replace("{", "{\n" + "\n".join(prologue), 1)
        # (a 4-byte integer parameter whose address is taken is the argument itself, not a local
        # copy of it: `lea eax, [ebp + 8]; push eax`, where the copy was `mov [ebp - 4], eax; lea
        # eax, [ebp - 4]`, bytes32. Its uses the argument's storage, `*(T *)&gen_aN`)
        for k, (t, n) in enumerate(sig.params):
            if not any(not binary_amp(body, m.start())
                       for m in re.finditer(r"(?<!&)&\s*\(?\s*" + re.escape(n) + r"\b", body)):
                continue
            try:
                tt = self.type_text(t)
            except ValueError:
                continue
            if not re.fullmatch(WORD4, tt.strip()):
                continue
            copy = re.compile(r"(?m)^[ \t]*" + re.escape(tt) + r"\s+" + re.escape(n) + r"\s*=\s*\(" + re.escape(tt)
                              + r"\)gen_a" + str(k) + r";[ \t]*\n")
            if not copy.search(body):
                continue
            body = copy.sub("", body, count=1)
            body = re.sub(r"\b" + re.escape(n) + r"\b", f"(*({tt} *)&gen_a{k})", body)
        # (the parameters themselves in the x86 fidelity build, GEN_P / GEN_PIN: the port takes each
        # as its 32-bit word and copies it into Ghidra's type, a local the optimizer drops, but /Od
        # keeps every local in a stack slot, and a reference built /Od reads its arguments where
        # they are. Each copy a store and a load more: rhtest core-Od's functions, 3 of 127
        # identical. Where the body names a word otherwise, its argument block or its storage, as
        # it is)
        copies = [re.compile(r"(?m)^([ \t]*)(" + re.escape(self.type_text(t)) + r"\s+" + re.escape(n)
                             + r"(?:\s*=\s*\([^;\n]*\)(?:\(uintptr_t\))?gen_a" + str(k) + r";|; memcpy\(&" + re.escape(n)
                             + r", &gen_a" + str(k) + r", sizeof " + re.escape(n) + r"\);))[ \t]*$")
                  for k, (t, n) in enumerate(sig.params)] if sig.params and not sig.variadic else []
        if copies and "gen_args" not in body and all(c.search(body) for c in copies):
            rest = body
            for c in copies:
                rest = c.sub("", rest, count=1)
            rest = re.sub(r"(?m)^[ \t]*GEN_ENTER\([^\n]*$", "", rest)
            if not re.search(r"\bgen_a\d+\b", rest):
                for k, c in enumerate(copies):
                    body = c.sub(lambda m: f"{m.group(1)}GEN_PIN({m.group(2)})", body, count=1)
                for k, (t, n) in enumerate(sig.params):
                    ab = f"{abi_type(self.type_text(t))} gen_a{k}"
                    decl = decl.replace(ab, f"GEN_P({self.type_text(t)} {n}, {ab})", 1)
        # (the frame as the reference's, for the x86 fidelity build: GEN_FRAME, GEN_NOFRAME)
        frame = "GEN_FRAME " if self.has_frame(a) else "GEN_NOFRAME "
        # (and its code generation, the program's or a library's: GEN_OWN, GEN_LIB)
        # (a function whose security cookie the x86 build leaves to its own /GS, frame_locals: _GS)
        gs = "_GS" if "GEN_COOKIE(" in body else ""
        frame = ("GEN_LIB" if self.is_library(a) else "GEN_OWN") + gs + " " + frame
        return f"/* ref: {self.corpus[a]['name']} */\n{frame}{decl}\n{body.strip()}\n"

    def is_library(self, a: int) -> bool:
        """Whether a function is the static libraries' (the C runtime's), built by their vendor with
        its own optimization, not the program's options: from the lowest function with a C runtime
        name on. The linker places the program's objects
        first and the libraries' after (rhtest core-Od: __security_check_cookie at 0x403490, then
        the runtime's startup to the end; built /Od as the program, 35 of them scored under 0.3)"""
        if self._library_from is None:
            crt = re.compile(r"^_{1,3}(?:security_check_cookie|scrt_|except_handler|report_gsfailure|"
                             r"aull|alldiv|allmul|allrem|allshl|allshr|aullshr|ftol|chkstk|EH_prolog|SEH_prolog|"
                             r"SEH_epilog|CRT_|crt|onexit|initterm|guard_)")
            # (by the C runtime's own names only: the decompiler's "Library Function" marks templates
            # instantiated in the program's code too, a client's std::basic_string at 0x40e080 among
            # its own, where its runtime starts at __security_check_cookie, 0xc47745)
            libs = [x for x, r in self.corpus.items() if crt.match(r.get("name", ""))]
            self._library_from = min(libs) if libs else 1 << 32
        return a >= self._library_from

    def x87_arith(self, a: int) -> bool:
        """Whether the reference function does x87 arithmetic (fadd, fdiv, fsqrt ...): its results
        rounded by the control word's precision, x87_precision"""
        import capstone
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        return any(m in X87_ARITH for _a, _s, m, _o in md.disasm_lite(self.ref_code(a), a))

    def ref_code(self, a: int) -> bytes:
        """The reference function's bytes, its decompiled size of them (b"" where unread)"""
        import pefile
        if self._pe is None:
            self._pe = pefile.PE(str(project.EXE), fast_load=True)
        try:
            return self._pe.get_data(a - self._pe.OPTIONAL_HEADER.ImageBase, int(self.corpus[a].get("size") or 0))
        except Exception:
            return b""

    def has_frame(self, a: int) -> bool:
        """Whether the reference function opens an ebp frame, `push ebp; mov ebp, esp` (55 8b ec)."""
        import pefile
        if self._pe is None:
            self._pe = pefile.PE(str(project.EXE), fast_load=True)
        try:
            return self._pe.get_data(a - self._pe.OPTIONAL_HEADER.ImageBase, 3) == b"\x55\x8b\xec"
        except Exception:
            return False

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
            # (and v16_forms' block-local temporary, small_array's gen_sa)
            if n.startswith(("F_", "gen_imp_", "LAB_", "switchD_", "caseD_")) or n in ("gen_sa", "GEN_ABOVE") \
                    or n in header_names():
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
    def x87_dispatch_call(body: str, n: int) -> str:
        """The C runtime's x87 dispatcher's tail jump through its record, `jmp dword ptr [ebx]`
        (protos32's x87_dispatch_records), a call that returns of ecx alone by its call-site shape.
        Every handler takes ecx, st0 (st1 for two operands) and the entry's frame in ebp and returns
        the function's value in st0, as its jumps.c W_ entry takes them, a double as its two words:
        passed so, and its value returned. Called with ecx alone and `return 0` after, every handler
        read garbage for its st0 and frame and its value was lost (2026-10-31)."""
        m = re.search(r"\(\((?:code|gen_fcode) \*\)\*\(?\(gen_code32 \*\)", body)
        if m is None:
            return body

        def close(i):
            d = 0
            for k in range(i, len(body)):
                d += {"(": 1, ")": -1}.get(body[k], 0)
                if d == 0:
                    return k
            return -1
        ce = close(m.start())
        j = ce + 1
        while 0 < j < len(body) and body[j] in " \t\r\n":
            j += 1
        if ce < 0 or j >= len(body) or body[j] != "(":
            return body
        ae = close(j)
        if ae < 0:
            return body
        args = [body[j + 1:ae].strip() or "0u"]
        for s in ("in_st0", "in_st1")[:n]:
            args += [f"(unsigned int)gen_d2bits((double){s})", f"(unsigned int)(gen_d2bits((double){s}) >> 32)"]
        args.append("(unsigned int)in_ebp")
        call = body[m.start():ce + 1].replace("((code *)", "((gen_fcode *)", 1) + "(" + ",".join(args) + ")"
        ls = body.rfind("\n", 0, m.start()) + 1
        tail = re.match(r"\s*;\s*return\b[^;]*;", body[ae + 1:])
        if body[ls:m.start()].strip() == "" and tail:
            return body[:m.start()] + "return (float10)" + call + ";" + body[ae + 1 + tail.end():]
        return body[:m.start()] + call + body[ae + 1:]

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
        # (a call whose x87 result goes to a float, double or float10, `fVar1 = ((code *)..)()`:
        # through gen_fcode, a double's type, as each such callee's entry returns it (jumps.c W_).
        # Through code, an unsigned int's, the number taken was what eax held, 2026-10-26)
        floats = {n for n, t in var_types.items() if t.strip() in ("float", "double", "float10", "float8")}
        # (and dereferenced first, `(*((code *)vt[1]))(this)`: a virtual slot's, 14.51's /O2
        # IntToken::value called through its vtable, its 64-bit result's high word lost, rhtest engine)
        if floats:
            body = re.sub(r"(?m)^(\s*)(" + "|".join(sorted(map(re.escape, floats))) + r")(\s*=\s*)(\(\*\s*)?\(\(code \*\)",
                          r"\1\2\3\4((gen_fcode *)", body)
            # (or through a local the decompiler typed `code *`, `extraout_ST0 = (*pcVar1)();`: as
            # code, eax converted by value, a mixer's level 0xb67a70, the operation census 2026-10-31)
            fptrs = [n for n, t in var_types.items() if re.fullmatch(r"code\s*\*(?:\s*PTR32)?", t.strip())]
            if fptrs:
                body = re.sub(r"(?m)^(\s*)(" + "|".join(sorted(map(re.escape, floats))) + r")(\s*=\s*)\(\s*\*\s*("
                              + "|".join(sorted(map(re.escape, fptrs))) + r")\s*\)(?=\s*\()",
                              r"\1\2\3((gen_fcode *)\4)", body)
        # (and one whose edx:eax result goes to an 8-byte integer: through gen_lcode, its rax whole)
        longs = {n for n, t in var_types.items() if t.strip() in ("ulonglong", "longlong", "undefined8", "uint8", "int8")}
        if longs:
            body = re.sub(r"(?m)^(\s*)(" + "|".join(sorted(map(re.escape, longs))) + r")(\s*=\s*)(\(\*\s*)?\(\(code \*\)",
                          r"\1\2\3\4((gen_lcode *)", body)
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
            # (nor a float's bits, gen_fl2bits(x), an integer: `this + (int)gen_fl2bits(fVar5) * 2 +
            # 0x210` is a pointer, and as a float's bits the cast of a pointer to float failed to
            # compile, three of a client's Apricot emitters demoted to stubs on its startup path,
            # 2026-10-28)
            while (k := bare.find("gen_fl2bits(")) >= 0 or (k := bare.find("gen_d2bits(")) >= 0:
                o = bare.index("(", k)
                bare = bare[:k] + "0" + bare[match_paren(bare, o):]
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
            # (a bitwise operator's is an integer whatever its sides: a float's sign flipped by
            # xor, `(uint)gen_fl2bits(f) ^ DAT_010920d0`, taken for a float and passed as
            # gen_fl2bits((float)(..)), the bits converted by value, 0x8b4eb0's 8 calls, the
            # operation census 2026-10-31)
            if re.search(r"\s(?:[%|^]|<<|>>|&(?!&))\s", e):
                return "int"
            kinds = [self.kind_of(p, var_types) for p in parts]
            if "float" in kinds:
                return "float"
            if None not in kinds:
                return "ptr" if "ptr" in kinds else "int"
        return None

    def call_args(self, body: str, var_types: dict[str, str]) -> str:
        """Each argument of a call to a translated function as its parameter's type: a float
        parameter given a pointer or what the text cannot type (Ghidra's variable for a register
        that held one), by GEN_ARGF: an integer's or a pointer's bits; an integer parameter given a
        float, its bits (the reference pushed the float's 4 bytes and the callee read them as an
        integer)."""
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
            if sig is not None and sig.variadic:
                # (a variadic callee reads its arguments as the reference's 4-byte words, gen_args:
                # an 8-byte one after the fixed ones, a double or a 64-bit integer the decompiler
                # spells `(undefined8)...` or holds in such a variable, is two of them. Passed as
                # one, each double after a printf format lost its high half, rhtest crt 2026-10-24)
                new_args = []
                for k, x in enumerate(args):
                    x = self.call_args(x, var_types)
                    s = x.strip()
                    wide = k >= len(sig.params) and (
                        re.match(r"\(\s*(?:undefined8|ulonglong|longlong|double|float8|float10|int8|uint8)\s*\)", s)
                        or var_types.get(s, "").strip() in ("double", "ulonglong", "longlong", "undefined8",
                                                            "float10", "float8"))
                    if wide:
                        if re.search(r"\bF_[0-9a-f]{8}\s*\(|\bgen_imp_\w+\s*\(|\+\+|--|(?<![=!<>])=(?!=)", s):
                            raise ValueError("an 8-byte variadic argument with a side effect")
                        x = f"GEN_LO32({s}),GEN_HI32({s})"
                    new_args.append(x)
            elif sig is None or len(args) != len(sig.params):
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
                        # (an operand whose kind the text does not say, by its C type: for a float
                        # parameter an integer's bits, GEN_ARGF, as the reference's call passes its
                        # 4 bytes; GEN_TOF converted it by value, a client's `this` typed float,
                        # 0x4e8640 from 0x425b80, 2026-10-30)
                        if k not in ("float", "int"):
                            x = f"{'GEN_ARGF' if abi == 'float' else 'GEN_TOD'}({x.strip()})"
                        # (an integer for a float parameter is its 4 bytes: the decompiler converts
                        # in words of its own, `(float)x`. Converted by value, a pointer the callee
                        # typed float, the stack address 0x910f9a0, came back 0x4d110f9a and was
                        # read through, a client's 0x6452c0 2026-10-27)
                        elif k == "int" and abi == "float":
                            x = f"gen_bits2f((unsigned int)({x.strip()}))"
                    elif abi == "unsigned int" and k == "float":
                        x = f"(unsigned int)gen_fl2bits((float)({x.strip()}))"
                    new_args.append(x)
            out.append(body[i:open_ + 1])
            out.append(",".join(new_args))
            out.append(")")
            i = close
        out.append(body[i:])
        return "".join(out)

    def pointer_call_args(self, body: str, var_types: dict[str, str]) -> str:
        """Each float argument of a call through a pointer as its 4 bytes, the word the reference
        pushed: the call is unprototyped, a float there promoted to a double, and the callee's entry
        (jumps.c's wrapper) takes the word's bits. As a value, `((gen_fcode *)vt[4])(this, lo, hi,
        REFG(float, 0x4044e0))` gave Ratio's 2.0f the double's low word, 0, and it divided by it
        (rhtest com-Od)"""
        out, i = [], 0
        for m in re.finditer(r"\(\((?:code|gen_fcode|GEN_TCODE)\s*\*\)", body):
            if m.start() < i:
                continue
            callee_end = match_paren(body, m.start())
            # (the arguments' parenthesis after it, a line break between as the decompiler wraps)
            while 0 < callee_end < len(body) and body[callee_end] in " \t\r\n":
                callee_end += 1
            if callee_end <= 0 or callee_end >= len(body) or body[callee_end] != "(":
                continue
            close = match_paren(body, callee_end)
            if close <= 0:
                continue
            inner = body[callee_end + 1:close - 1]
            args = split_top(inner) if inner.strip() else []
            new_args = []
            for x in args:
                x = self.pointer_call_args(x, var_types)
                s = x.strip()
                # (a float plainly: a float global, variable or cast, or a literal with f. Not a
                # double: its words are two arguments, the decompiler's own split)
                single = re.fullmatch(r"REFG\(float, 0x[0-9a-f]+\)|\(float\)[^,]+|-?\d+\.\d*(?:[eE][-+]?\d+)?f", s) \
                    or var_types.get(s, "").strip() == "float"
                if single:
                    x = f"(unsigned int)gen_fl2bits((float)({s}))"
                new_args.append(x)
            out.append(body[i:callee_end + 1])
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
            # (and a Windows pointer typedef, `local_c4 = (HGDIOBJ)(float)fVar12` where Ghidra
            # reused a handle's slot for a float, for a float only: C converts no float to a
            # pointer, C2440 demoted a client's sound layout's vf29 0xd15130, 2026-10-30. An
            # integer's `(HANDLE)-1` stays C's, sign-extended as the system's INVALID_HANDLE_VALUE)
            win_ptr = not to_ptr and t in WIN_POINTERS
            if not (to_float or to_ptr or win_ptr):
                continue
            j = m.end()
            # (a case label's pointer, `case (char *)0x0:` in a switch on a pointer, is the integer
            # alone: C's case wants a constant, and the cast's GEN_TOP is a call. 38 of a client's
            # functions were demoted for it, C2051, 2026-10-30)
            if to_ptr and re.fullmatch(r"\s*case\s*", body[body.rfind("\n", 0, m.start()) + 1:m.start()]):
                out.append(body[i:m.start()])
                i = j
                continue
            # (`(code *)REFP(...)` and the like are addresses; a cast of a cast is the inner's)
            nxt = body[j:].lstrip()
            if not nxt or nxt[0] in ";,)]}" or nxt.startswith(("REFP(", "GP(", "REFG(code")):
                continue
            end = operand_end(body, j)
            operand = body[j:end].strip()
            if not operand:
                continue
            k = self.kind_of(operand, var_types)
            if win_ptr and k != "float":
                continue
            # (the operand's own casts too, before it is wrapped whole)
            operand = self.typed_casts(operand, var_types)
            if to_float:
                if k in ("float", "int"):
                    continue
                conv = "GEN_TOD" if t in ("double", "float8", "float10") else "GEN_TOF"
                rep = f"(({t})gen_bits2f((unsigned int)(uintptr_t)({operand})))" if k == "ptr" else f"(({t}){conv}({operand}))"
            else:
                # (an int too: its 32 bits zero-extended, as the reference's pointer is. Sign-extended
                # on x64, `p = (uint *)((int)p - 1)` from 0 was never `(uint *)0xffffffff`, and the
                # CRT's big-integer shift ran off the stack's end, rhtest stl /MT's double formatting)
                if k == "ptr":
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
        # (a structure of 8 bytes or fewer returned by value comes back in edx:eax: its bits.
        # VS2010's __Getcoll's _Collvec)
        w = re.sub(r"^(?:struct\s+)?", "", CC.sub("", t).strip())
        # (a vector in xmm0, protos32's "v16", `undefined1 [16]`: gen_r16, Ghidra32.h's __m128, as C
        # returns no array; v16_forms returns the body's 16 bytes as one. 0x666280 2026-10-30)
        if re.fullmatch(r"undefined1\s*\[\s*16\s*\]", w):
            return "gen_r16"
        if w not in KNOWN_TYPES and self.composite_sizes.get(w) in (1, 2, 4, 8):
            return "unsigned long long" if self.composite_sizes[w] == 8 else "unsigned int"
        t = self.type_text(t)
        return "unsigned int" if t in ("void", "code") else STRUCT8.get(t.strip(), t)

    def type_text(self, t: str) -> str:
        t = CC.sub("", t).strip()
        # (a pointer to an array, `undefined1 (*) [32]`, a function's return or parameter: a pointer
        # to its bytes. As the words it was, translated.h declared `undefined1 (  ) [32] *`, rhtest stl)
        if re.search(r"\(\s*\*+\s*\)\s*\[", t):
            return "undefined *"
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
                # (an enum the types export left out, which the decompiler names `enum W` somewhere:
                # an int. Function ID's debug-library names, `fVirtual(enum CV_methodprop_e)`, 6
                # stubs in a client, 2026-10-27)
                if w in self.enum_words:
                    t = re.sub(r"\b" + re.escape(w) + r"\b", "uint", t)
                    continue
                if "*" in t:
                    t = re.sub(r"\b" + re.escape(w) + r"\b", "undefined", t)
                # (a composite of a scalar's size by value, its bytes: Ghidra's 1-byte placeholder
                # for an RTTI class, `EventHandler param_2` beside `EventHandler *param_1`, a byte
                # compared and stored, 0xb8c640)
                elif self.composite_sizes.get(w) in (1, 2, 4, 8):
                    t = re.sub(r"\b" + re.escape(w) + r"\b", f"undefined{self.composite_sizes[w]}", t)
                else:
                    raise ValueError(f"type {w}")
        return ptr32_type(t)

    def enum_constants(self, body: str) -> str:
        """An enum constant the decompiler names, as its value: `return INTRNCVT_OVERFLOW;` in
        VS2010's __fltin2, which C has no declaration of (rhtest msvc-16.00-x86 crt). Not a member,
        a call, nor a name the body declares or Ghidra32.h has."""
        if not self.enum_values:
            return body
        decls, rest = split_decls(body)
        # (the names the body has otherwise: its declarations, its signature's parameters)
        known = set(re.findall(r"\b[A-Za-z_]\w*\b", decls))
        # (only what reads as a constant, CAPITALS with an underscore: the program's type libraries
        # hold enums with every kind of name, and taken for constants, `uint` and `HMODULE` in
        # declarations and fields after a `.` went, 40 functions of crt, 2026-10-24)

        def rep(m):
            n = m.group(1)
            v = self.enum_values.get(n)
            if v is None or n in known or n in HEADER_NAMES or n in KNOWN_TYPES:
                return m.group(0)
            return f"({v})"
        rest = re.sub(r"(?<![.\w>])(?<!\.\s)(?<!->\s)\b([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)\b(?!\s*\()", rep, rest)
        return decls + rest

    def pointer_steps(self, body: str) -> str:
        """Arithmetic on a local that points to a structure, by the structure: such a pointer is
        bytes in the translation (an unknown type under a pointer, or a Windows pointer typedef as
        GEN_LPANY), and `p_Var2 = p_Var2 + 1`, the next of VS2010 __FindPESection's 40-byte section
        headers, stepped one byte: _IsNonwritableInCurrentImage never found .rdata, the CRT never
        installed its float formatting, R6002 (rhtest msvc-16.00-x86 crt). What follows the
        pointer to the end of its additive expression is scaled."""
        decls, rest = split_decls(body)
        steps = {}
        # (the locals, and the parameters: VS2010's _lock_file(FILE *_File) indexes its lock by
        # `(_File + -0x20a14) >> 5`, FILE-sized steps, and a byte's put stdout's lock past the table)
        typed = [(m.group(1), m.group(2), m.group(3)) for m in re.finditer(
            r"(?m)^\s+(?:struct\s+)?([A-Za-z_]\w*)\s*(\*?)\s*([A-Za-z_]\w*)\s*;", decls)]
        for t, n in getattr(self, "cur_params", ()):
            pm = re.fullmatch(r"(?:const\s+)?(?:struct\s+)?([A-Za-z_]\w*)\s*(\*?)", t.strip())
            if pm:
                typed.append((pm.group(1), pm.group(2), n))
        for t, star, v in typed:
            if star:
                s = self.struct_of(t)
            else:
                info = self.tinfo(t, 4) if t in self.typedefs and t not in KNOWN_TYPES else None
                s = info[1] if info and info[0] == "ptr" else None
            size = self.composites.get(s, {}).get("size") if s else None
            if size and size > 1:
                steps[v] = size
        if not steps:
            return body

        def scale(text: str, v: str, size: int) -> str:
            out, i = [], 0
            for m in re.finditer(rf"\b{re.escape(v)}\s*(\+|-)(?![=+\->])\s*|\b{re.escape(v)}\s*(\+=|-=)\s*", text):
                if m.start() < i:
                    continue
                # (not the pointer cast to an integer, `(int)p_Var13 - (int)piVar14`: integer
                # arithmetic, its bytes. Scaled, std::string's append of a type name took a length
                # four times too short, negative, rhtest stl /MT's typeid)
                if re.search(r"\(\s*(?:unsigned\s+)?(?:u?int|u?long|uint\d*|int\d*|undefined\d|u?longlong|dword|"
                             r"uintptr_t|intptr_t|size_t)\s*\)\s*$", text[:m.start()]):
                    continue
                # (the rest of the additive expression: to a closing bracket, a separator or an
                # operator binding looser than + at this depth)
                j, depth = m.end(), 0
                while j < len(text):
                    ch = text[j]
                    if ch in "([":
                        depth += 1
                    elif ch in ")]":
                        if depth == 0:
                            break
                        depth -= 1
                    elif depth == 0 and (ch in ",;?:" or text.startswith(("==", "!=", "<", ">", "&&", "||", "&", "|", "^"), j)
                                         or (ch == "=" and not text.startswith("==", j))):
                        break
                    j += 1
                operand = text[m.end():j].strip()
                if not operand:
                    continue
                out.append(text[i:m.end()])
                out.append(f"({operand}) * {size}")
                if text[j - 1:j].isspace():
                    out.append(" ")
                i = j
            out.append(text[i:])
            return "".join(out)
        # (every line but a declaration: a body with no locals has no declaration block, and
        # split_decls gave _unlock_file's statements as its declarations, unscaled)
        decl_line = re.compile(r"\s*(?:struct\s+)?[A-Za-z_]\w*[\s*]+[A-Za-z_]\w*\s*(?:\[[^\]]*\])?\s*;\s*")
        lines = body.split("\n")
        for i, line in enumerate(lines):
            if decl_line.fullmatch(line):
                continue
            for v, size in steps.items():
                if v in line:
                    line = scale(line, v, size)
            lines[i] = line
        return "\n".join(lines)

    def types(self, body: str) -> str:
        """Casts and declarations: unknown types under a pointer as bytes, size_t 32-bit, inner
        pointer levels __ptr32."""
        body = self.pointer_steps(body)
        body = self.enum_constants(body)
        body = alias_types(body)
        body = re.sub(r"\b_func_\w+\b", "code", body)

        # (a cast to an exported typedef, `(_ptiddata)p`)
        body = re.sub(r"\(\s*([A-Za-z_]\w*)\s*\)",
                      lambda m: f"({self.typedef_c(m.group(1))})" if self.typedef_c(m.group(1)) else m.group(0), body)
        # (and to a structure by value of an integer's size: its bytes. A class Function ID names
        # but Ghidra has no layout for is a 1-byte placeholder, and its constructor's `this[0xc] =
        # (_LocaleUpdate)0x0` stores a byte: VS2010's _LocaleUpdate, rhtest msvc-16.00-x86)
        # (of a dereference or address too, `(RaptureAtkModule)*pcVar10`: no variable is named so)
        body = re.sub(r"\(\s*([A-Za-z_]\w*)\s*\)(?=\s*[\w(*&!~-])",
                      lambda m: f"(undefined{self.composite_sizes[m.group(1)]})"
                      if m.group(1) not in KNOWN_TYPES and self.composite_sizes.get(m.group(1)) in (1, 2, 4, 8)
                      else m.group(0), body)

        def cast(m):
            return "(" + self.type_text(m.group(1)) + ")"
        # (not a convention in a template's name, `__crt_fast_encode_pointer<void_(__stdcall*)(...)>`:
        # a cast to it lost the name, undeclared, rhtest stl-O2)
        # (and a template over a function type, `(function<void___cdecl(void)> *)p`: one level of
        # parentheses in its arguments, rhtest stl-Od's std::function locals)
        body = re.sub(r"\(\s*(?!(?:__thiscall|__cdecl|__stdcall|__fastcall)\s*\*)((?:const\s+)?[A-Za-z_~`][\w:`']*"
                      r"(?:<(?:[^()<>]|\([^()]*\)|<[^<>()]*>)*?>)?(?:\s+[A-Za-z_]\w*)?\s*\*[\s*]*)\)", cast, body)

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

        # (a local of a structure the body reaches no member of: its bytes. Function ID took
        # rhtest's Derived constructor for the C++ library's money_base, and its caller's
        # exception object became a `scheduler_resource_allocation_error[16]`, eh-Od)
        def opaque(m):
            word, name, count = m.group(2), m.group(3), m.group(4)
            # (through a typedef to one, `WSADATA local_198;` of struct WSAData, WSAStartup's)
            if word not in self.composite_sizes and self.typedefs.get(word) in self.composite_sizes \
                    and word not in KNOWN_TYPES:
                word = self.typedefs[word]
            if word not in self.composite_sizes or word in KNOWN_TYPES \
                    or re.search(rf"\b{name}\b\s*(?:\[[^\]]*\]\s*)?(?:\.|->)", rest):
                return m.group(0)
            size = self.composite_sizes[word] * (int(count, 0) if count else 1)
            # (one of 1, 2, 4 or 8 bytes is an integer of that size: VS2010's _Getcoll takes the
            # _Collvec __Getcoll returns in edx:eax, `_Var1 = __Getcoll(); *param_1 = _Var1;`)
            if not count and size in (1, 2, 4, 8):
                small[name] = size
                return f"{m.group(1)}undefined{size} {name};"
            return f"{m.group(1)}undefined1 {name}[{size}];"
        small = {}
        decls = re.sub(r"(?m)^(\s+)([A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s*(?:\[\s*((?:0x)?[0-9a-f]+)\s*\])?\s*;",
                       opaque, decls)

        # (and one of a template's or a lambda's type the body reaches no member of,
        # `__crt_seh_guarded_call<void> local_5;`, `<lambda_32aa...> local_9;`: its bytes, as the
        # export sizes it. The static CRT's guarded calls take its address only, rhtest stl /MT)
        def opaque_t(m):
            word, name, count = m.group(2).strip(), m.group(3), m.group(4)
            if word not in self.composite_sizes or re.search(rf"\b{name}\b\s*(?:\[[^\]]*\]\s*)?(?:\.|->)", rest):
                return m.group(0)
            size = max(1, self.composite_sizes[word])
            # (and an array of them, `istreambuf_iterator<char,...> local_28 [14];`, the bytes
            # std::num_get's _Getffld collects its digits in, rhtest stl)
            if count:
                return f"{m.group(1)}undefined{size} {name}[{count}];" if size in (1, 2, 4, 8) else \
                    f"{m.group(1)}undefined1 {name}[{size * int(count, 0)}];"
            return f"{m.group(1)}undefined{size} {name};" if size in (1, 2, 4, 8) else \
                f"{m.group(1)}undefined1 {name}[{size}];"
        decls = re.sub(r"(?m)^(\s+)((?:[A-Za-z_][\w:]*)?<[^;\n]*>)\s+([A-Za-z_]\w*)\s*(?:\[\s*((?:0x)?[0-9a-f]+)\s*\])?\s*;",
                       opaque_t, decls)
        # (a cast to one by value, `(istreambuf_iterator<char,std::char_traits<char>_>)0x1`: to its
        # bytes, an integer of its size)
        # (in either part: a function with no locals has its body in the first, split_decls)
        for word in {w for w in re.findall(r"\(\s*((?:[A-Za-z_][\w:]*)?<[^;()\n]*>)\s*\)", decls + rest)}:
            size = self.composite_sizes.get(word.strip())
            if size in (1, 2, 4, 8):
                rest = re.sub(r"\(\s*" + re.escape(word) + r"\s*\)", f"(undefined{size})", rest)
                decls = re.sub(r"\(\s*" + re.escape(word) + r"\s*\)", f"(undefined{size})", decls)
        # (and copied whole through a pointer, `*param_1 = _Var1;`: all its bytes, not the one
        # byte the `undefined *` it became points at)
        for name, size in small.items():
            rest = re.sub(rf"(?m)^(\s*)\*\s*([A-Za-z_]\w*)\s*=\s*{name}\s*;",
                          rf"\1*(undefined{size} *)\2 = {name};", rest)
            rest = re.sub(rf"(?m)^(\s*){name}\s*=\s*\*\s*([A-Za-z_]\w*)\s*;",
                          rf"\1{name} = *(undefined{size} *)\2;", rest)
        decls = re.sub(r"(?m)^(\s+)((?:(?:unsigned|signed)\s+)?[A-Za-z_]\w*(?:::\w+)*(?:<(?:[^;()<>]|\([^();]*\)|<[^<>();]*>)*?>)?(?:\s*\*[\s*]*|\s+))([A-Za-z_]\w*\s*(?:\[[^\]]*\])?\s*;)",
                       lambda m: decl(m) if "*" in m.group(2) or self.type_word_ok(m.group(2)) else m.group(0), decls)
        return decls + rest

    def type_word_ok(self, t: str) -> bool:
        w = t.replace("unsigned", "").replace("signed", "").replace("*", "").strip()
        if w in NOT_TYPES:
            return False
        if w not in KNOWN_TYPES and self.typedef_c(w) is None and w not in self.enum_words:
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
        # vftable`, `` `long___stdcall_AppException(undefined *)'::__l2::Callback::vftable``):
        # each ends at a call's `(` or a scope's last part, and is found by scanning back
        # (a qualified name the decompiler wrapped after its scope, `__crt_seh_guarded_call<void>::`
        # then `operator()<<lambda_...>,...>` on the next line: one name, as the corpus has it,
        # the static CRT's guarded calls, rhtest stl's /MT construct_ptd)
        body = re.sub(r"::[ \t]*\n[ \t]*(?=[\w~<])", "::", body)
        body = self.odd_names(body)
        # (a cast to a lambda's type, its object's address: a pointer, `(<lambda_15ade...> *)&local_18`)
        body = re.sub(r"\(\s*<lambda_[0-9a-f]+>\s*\*\s*\)", "(void *)", body)
        # (and a local pointing to one, which the decompiler names after the type's first letters,
        # `<lambda_39ca...> *p<Var1;`: bytes, named p_lVar1. The static CRT's guarded calls, rhtest
        # stl /MT)
        body = re.sub(r"(?<![\w>])([a-z]+)<Var(\d+)\b", r"\1_lVar\2", body)
        body = re.sub(r"(?m)^([ \t]+)<lambda_[0-9a-f]+>\s*\*(?=\s*\w+\s*;)", r"\1undefined *", body)

        # (an operator of the same class, called unqualified: std::exception's copy constructor's
        # `operator=(this,param_1)`, rhtest msvc-16.00-x86 cpp 2026-10-25)
        def operator(m):
            for ns in getattr(self, "cur_call_ns", ()):
                if ns + m.group(1) in self.by_printed:
                    return f"F_{self.by_printed[ns + m.group(1)]:08x}("
            return m.group(0)
        body = re.sub(r"(?<![\w$:~])(operator[^\w\s(),;]{1,3})\s*\(", operator, body)

        def call(m):
            name = m.group(1)
            a = self.by_printed.get(name)
            if a is not None:
                return f"F_{a:08x}("
            for ns in getattr(self, "cur_call_ns", ()):
                if ns + name in self.by_printed:
                    return f"F_{self.by_printed[ns + name]:08x}("
            imp = self.import_of(name)
            if imp is not None:
                return f"gen_imp_{cid(imp)}("
            if name in self.ref_names:
                return f"((code *)REFP(0x{self.ref_names[name]:x}))("
            return m.group(0)
        body = re.sub(r"(?<![\w$:])(" + IDENT + r")\s*\(", call, body)
        body = math_words(body)

        # (a label's address is an address; the label itself, `LAB_x:` and `goto LAB_x`, stays)
        body = re.sub(r"&\s*(LAB_([0-9a-f]{8}))\b", lambda m: f"REFP(0x{m.group(2)})", body)
        body = re.sub(r"&\s*(_*(?:s|u|ws)_\w*?_([0-9a-f]{8}))\b", lambda m: f"REFP(0x{m.group(2)})", body)
        # (and an EH table's, the decompiler's label for the data, `&FuncInfo_012f6f5c` a C++ frame
        # handler thunk hands ___InternalCxxFrameHandler: its address. 0x1070093, 2026-10-30)
        body = re.sub(r"&\s*((?:FuncInfo|UnwindMap|TryBlockMap|HandlerType|IPToStateMap|ThrowInfo|"
                      r"CatchableType(?:Array)?|ScopeTable)_([0-9a-f]{8}))\b", lambda m: f"REFP(0x{m.group(2)})", body)

        # (a DAT_ with no data defined that the body only takes the address of is 1 byte to the
        # decompiler, so its `&DAT_x + k` counts bytes: __GET_RTERRMSG's `*(wchar_t **)(&DAT_01119cfc
        # + i * 8)` read 32-byte strides as an undefined4, and named R6033 for R6016, 2026-10-23)
        address_only = {n for n in set(re.findall(r"(?<![\w$])DAT_[0-9a-f]{8}(?![\w$])", body))
                        if int(n[4:], 16) not in self.refdata
                        and len(re.findall(r"(?<![\w$])" + n + r"(?![\w$])", body))
                        == sum(not binary_amp(body, m.start()) for m in re.finditer(r"(?<!&)&\s*" + n + r"(?![\w$])", body))}

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
            for ns in getattr(self, "cur_ns", ()):
                if ns + name in self.ref_names:
                    return self.global_lvalue(self.ref_names[ns + name])
            # (and a method of the function's own class as a value, by its unqualified name: the
            # decompiler's `this_00[7] = OnCharaSheetsLoaded;`, a waiter's continuation in the lobby
            # client's WaitCharaSheets 0x904e60, a stub as "undeclared name". Not a field, `p->x`)
            if m.string[max(0, m.start() - 2):m.start()] != "->":
                for ns in getattr(self, "cur_call_ns", ()):
                    if ns + name in self.by_printed:
                        return f"((code *)REFP(0x{self.by_printed[ns + name]:x}))"
            return name
        # (outside string literals: `"vec size"` names no function `size`, rhtest stl-Od's output)
        parts = re.split(r'''("(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])+')''', body)
        body = "".join(p if k % 2 else re.sub(r"(?<![\w$:.])(" + IDENT + r")(?![\w$(:])(?!\s*\()", value, p)
                       for k, p in enumerate(parts))
        return self.float_global_casts(self.pointer_globals(body))

    def float_global_casts(self, body: str) -> str:
        """`(byte)REFG(float, a)`: an integer cast of a global the instructions read as a float
        (floatdata) that the decompiler, in this function, typed no float: a piece of its bits, as
        the reference's `mov al, [a]` (Ghidra's `(byte)DAT_010c449c`), not its value converted.
        0x7db120 stored 1 for each byte of 1.33f, 0x5f9fc0's `(undefined2)` of 1.0f was 1, and
        Matrix34Invert3x3's `~m & (uint)DAT_01138af0` (0xda2230) and-ed the mask with 1, 2026-10-31.
        (A float it typed float is converted: `(int)DAT_010abc60`, _ftol in 0xcce920)"""
        gt = getattr(self, "cur_gt", {})

        def rep(m):
            seen = set(gt.get(f"{int(m.group(3), 16):x}", ()))
            if not seen or seen & {"float", "double", "float10", "longdouble"}:
                return m.group(0)
            bits = "gen_d2bits" if m.group(2) == "double" else "gen_fl2bits"
            return f"({m.group(1)}){bits}(REFG({m.group(2)}, {m.group(3)}))"
        return re.sub(r"\(\s*(byte|char|uchar|sbyte|bool|undefined1?|undefined2|undefined4|undefined8|short|ushort|"
                      r"int|uint|long|ulong|longlong|ulonglong|word|dword|qword)\s*\)\s*REFG\((float|double), "
                      r"(0x[0-9a-f]+)\)", rep, body)

    def odd_names(self, body: str) -> str:
        """Names made of more than word characters (operators, templates, backquoted scopes),
        every one the corpus and the data export have, matched whole, longest first."""
        cands = sorted({n for w in set(re.findall(r"[\w~]+", body)) for n in self.odd_by_word.get(w, ())
                        if n in body}, key=len, reverse=True)
        if not cands:
            return body
        odd_re = re.compile(r"(?<![\w$:])(" + "|".join(map(re.escape, cands)) + r")(?![\w$])")

        def rep(m):
            name = m.group(1)
            # (a relative spelling: the full name it is the suffix of)
            name = self.odd_suffix.get(name) or name
            # (what follows in the piece matched: an offset into the whole body is past every
            # string literal before, and a call there read as a value, `((code *)REFP(0x411e30))(..)`,
            # the destructors of a function with a string, rhtest stl-Od)
            rest = m.string[m.end():].lstrip()
            if name in self.odd_functions:
                a = self.by_printed[name]
                return f"F_{a:08x}" if rest.startswith("(") else f"((code *)REFP(0x{a:x}))"
            return self.global_lvalue(self.ref_names[name])
        # (outside string literals: `"vec size"` is no call of a `size`, rhtest stl-Od's output)
        parts = re.split(r'''("(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])+')''', body)
        return "".join(p if k % 2 else odd_re.sub(rep, p) for k, p in enumerate(parts))

    @staticmethod
    def pointer_globals(body: str) -> str:
        """A global the data export does not type (undefined4) that the code uses as a pointer:
        dereferenced (`*DAT_x + 8`), indexed (`DAT_x[i]`) or called (`(*DAT_x)(...)`)."""
        body = re.sub(r"\(\*REFG\(undefined4, (0x[0-9a-f]+)\)\)\s*\(", r"(*REFG(code * PTR32, \1))(", body)
        # (indexed as the pointer the function compares or sets it to: `DAT_0040b390 == (char *)
        # 0x200`, `DAT_0040b390[0x40b398] = c`, a byte. As an int *, rhtest's put() wrote 4 bytes
        # at four times the offset, VS2010's core-O2 2026-10-24; int * where nothing says)
        typed = {}
        for m in re.finditer(r"REFG\(undefined4, (0x[0-9a-f]+)\)\s*(?:==|!=|=(?!=))\s*\(\s*((?:unsigned\s+)?[A-Za-z_]\w*)\s*\*\s*\)", body):
            typed.setdefault(m.group(1), set()).add(m.group(2))
        body = re.sub(r"REFG\(undefined4, (0x[0-9a-f]+)\)(?=\s*\[)",
                      lambda m: f"REFG({next(iter(typed[m.group(1)]))} * PTR32, {m.group(1)})"
                      if len(typed.get(m.group(1), ())) == 1 else f"REFG(int * PTR32, {m.group(1)})", body)
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
        # (an address the data export has no entry for, a label the decompiler made for the access:
        # the width it gave the global in this function, its one undefinedN. As 4 bytes, a byte
        # store `DAT_014a2479 = uVar1` wrote its neighbours too, the bone physics config's
        # 0x14a2479..7b (0xa051e0), 2026-10-31)
        # (and by any type it gave it, not only an undefinedN: `byte`, `char` and `bool` were 4
        # bytes, `DAT_014ac17c = param_1` (0x6bef90), `DAT_013723ba = c` (0x4352e0), `DAT_014c0a78 =
        # bVar1` (0xae8ef0) writing 3 neighbours, `DAT_015d6858 != '\0'` (0xc50917) comparing 4)
        if addr not in self.refdata:
            seen = set(getattr(self, "cur_gt", {}).get(f"{addr:x}", ()))
            sizes = {gt_size(s) for s in seen}
            if seen and len(sizes) == 1 and None not in sizes:
                n = next(iter(sizes))
                t = f"undefined{n}"
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
        # (a global the decompiler typed float10 in this function, `fld tbyte [0x801e3a]`: its 10 bytes
        # (gen_ld80, below), not the data export's undefined4 converted by value, POP.EXE 0x7334cc/0x72f466)
        gt_seen = {s.strip() for s in getattr(self, "cur_gt", {}).get(f"{addr:x}", ())}
        if gt_seen and gt_seen <= {"float10", "longdouble"}:
            return f"(*(float10 *)&REFG(undefined, 0x{addr:x}))"
        m = re.fullmatch(r"(.+?)\s*\[(\d+)\]", t)
        # (a scalar the instructions load as a float is one, whatever the export says)
        # (Not one narrower than the data, though: a vector's two floats a `movq` copies whole, the
        # decompiler's `*(undefined8 *)(p + 0x20) = DAT_01138c80`, as a float stored the first and
        # zeroed the second, hkxScene's identity matrix with [1][1] 0 (0xde6760), 2026-10-31)
        # (nor where the decompiler gave it only integer types in this function (gt): every use there an
        # integer's. As a float `DAT_00b1ab68 = 0x4322f983` stored 1.13e9f (POP.EXE 0x79bf40), a word
        # copied `= *(undefined4 *)(p + 0xb8)` (0x6b92f0; a VS2010 client's movss copies, 0x62a390) was
        # converted, a lexer's int `DAT_009ec75c * 10 + c - 0x30` (0x43da90) done in floats, a pointer
        # `DAT_00a7c44c + 0x1c` (0x45aa50) built through one, 2026-11-01)
        int_only = bool(gt_seen) and all(INT_GT.fullmatch(s) for s in gt_seen) and not re.search(r"float|double", t)
        if addr in self.floats and not m and not int_only and {"float": 4, "double": 8}.get(self.floats[addr], n) >= n:
            return f"REFG({self.floats[addr]}, 0x{addr:x})"
        if m:
            # (an array the instructions read as floats has float elements)
            et = self.floats[addr] if addr in self.floats else self.c_data_type(m.group(1))
            return f"(*({et} (*)[{m.group(2)}])REFP(0x{addr:x}))"
        if t in ("pointer", "addr"):
            return f"REFG(undefined * PTR32, 0x{addr:x})"
        # (data with no type of its own, undefinedN, an unsigned in C, takes the signed one the
        # decompiler gave the global in this function, where it gave one: its compares, shifts and
        # divides are signed, printed without a cast. _ld12cvt's `exponent > pFmt->min_exp`, -1023,
        # compared unsigned and every double sscanf and strtod parsed came out 0.0, rhtest
        # msvc-16.00-x86 crt; corpus "gt", ExportDecompAll)
        if re.fullmatch(r"undefined[1248]?", t):
            seen = set(getattr(self, "cur_gt", {}).get(f"{addr:x}", ()))
            signed = {1: "char", 2: "short", 4: "int", 8: "longlong"}.get(n)
            if signed and seen and seen <= {signed} | ({"long"} if n == 4 else set()):
                return f"REFG({signed}, 0x{addr:x})"
            # (or the float it gave one, its every use `gen_fl2bits(DAT_x)` the bits: as undefined4,
            # an unsigned, each converted by value. /GL's inlined seed() read a global the function
            # stored to a float local, and `seed() + 100` came out the float's bits, rhtest engine-GL)
            if seen and seen == {{4: "float", 8: "double"}.get(n)}:
                return f"REFG({next(iter(seen))}, 0x{addr:x})"
            # (and the one pointer type it gave a 4-byte one: its arithmetic steps the pointee.
            # A client's resource manager, `int *DAT_x`, passed `DAT_x + 1` as an interface's this:
            # as undefined4 a byte on, not four, the next object's field read as a list, 2026-10-26)
            if n == 4 and len(seen) == 1 and next(iter(seen)).endswith("*"):
                pt = self.c_data_type(next(iter(seen)))
                # (a structure's pointer has no C type here: undefined *, a byte step, as before)
                if pt and not (pt.startswith("undefined *") and not next(iter(seen)).startswith("undefined ")):
                    return f"REFG({pt}, 0x{addr:x})"
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
    def translate_one(self, a: int) -> tuple[int, bool, str]:
        """(address, translated?, its C or why not)."""
        if a in OWN:
            return a, False, f"the project's own: {OWN[a]}"
        why = self.why_not(a)
        if why:
            return a, False, why
        try:
            return a, True, self.rewrite(a)
        except ValueError as e:
            return a, False, str(e)

    def translate_all(self, only: set[int] | None, demoted: dict[str, str], pool=None):
        translated, stubbed = {}, {}
        todo = []
        for a in sorted(self.corpus):
            if only is not None and a not in only:
                stubbed[a] = "not selected"
                continue
            if f"{a:08x}" in demoted:
                stubbed[a] = "demoted: " + demoted[f"{a:08x}"]
                continue
            todo.append(a)
        # (each function on its own, from the same inputs every round: one translated in an earlier
        # round of this run is as it was, and a later round redoes none. In worker processes when
        # there is a pool, each with its own Translator32, _worker_init)
        done = getattr(self, "_done", None)
        if done is None:
            done = self._done = {}
        fresh = [a for a in todo if a not in done]
        if pool is not None:
            # (the largest first, one at a time while they are large: a function of a few thousand
            # lines takes as long as hundreds of small ones, and handed out last it kept one worker
            # busy long after the rest were idle. Small chunks, so the workers end together)
            fresh.sort(key=lambda a: -len(self.corpus[a]["c"]))
            big = [a for a in fresh if len(self.corpus[a]["c"]) >= 20000]
            got = itertools.chain(pool.imap_unordered(_translate_one, big, chunksize=1),
                                  pool.imap_unordered(_translate_one, fresh[len(big):], chunksize=16))
        else:
            got = map(self.translate_one, fresh)
        for a, ok, text in got:
            done[a] = (ok, text)
        for a in todo:
            ok, text = done[a]
            (translated if ok else stubbed)[a] = text
        return dict(sorted(translated.items())), dict(sorted(stubbed.items()))

    def conv_decl(self, a: int, ret: str, params: list[str]) -> str:
        """A function's declaration with the reference's convention for the x86 fidelity build:
        `uint GEN_THISCALL F_x(unsigned int gen_a0 GEN_EDX_PARAM, ...)` (Ghidra32.h, empty on x64)."""
        conv = self.conv.get(a)
        ps = list(params)
        cc = ""
        if conv == "__thiscall" and ps and ps[0] != "...":
            ps[0] += " GEN_EDX_PARAM"
            cc = "GEN_THISCALL "
        elif conv == "__fastcall" and ps:
            cc = "GEN_FASTCALL "
        elif conv == "__stdcall":
            cc = "GEN_STDCALL "
        return f"{ret} {cc}F_{a:08x}({', '.join(ps) or 'void'})"

    def conv_calls(self, body: str, a: int | None = None) -> str:
        """Each direct call to a __thiscall function given the dummy edx after `this`, GEN_EDX_ARG;
        and each virtual call, through the vtable of the object it passes first, as __thiscall's
        too (vcalls)."""
        body = self.vcalls(body)
        body = self.direct_thiscalls(body)
        # (a __thiscall function's first such call, with no call before it to change edx: its own
        # dummy handed on, GEN_EDX_FWD, edx as it came, where a 0 was `xor edx, edx` the reference
        # has not: a `sub ecx, 4; jmp` thunk, bytes32's 8-byte functions 2026-10-27)
        if a is not None and self.conv.get(a) == "__thiscall":
            k = body.find(" GEN_EDX_ARG")
            if k >= 0:
                line_start = body.rfind("\n", 0, k) + 1
                before = body[:line_start]
                if not re.search(r"\bF_[0-9a-f]{8}\(|\(\((?:GEN_TCODE|code) \*\)|\bgen_imp_\w+\(", before):
                    body = body[:k] + " GEN_EDX_FWD" + body[k + len(" GEN_EDX_ARG"):]
        return body

    def direct_thiscalls(self, body: str) -> str:
        out, last = [], 0
        # (and one whose `(` Ghidra wrapped onto the next line after a long name: bytes32's x86
        # build, too few arguments, rhtest stl /MT)
        for m in re.finditer(r"\bF_([0-9a-f]{8})\s*\(", body):
            if self.conv.get(int(m.group(1), 16)) != "__thiscall":
                continue
            # the end of the first argument, at the call's top level
            depth, k = 0, m.end()
            while k < len(body):
                ch = body[k]
                if ch in "([":
                    depth += 1
                elif ch in ")]":
                    if depth == 0:
                        break
                    depth -= 1
                elif ch == "," and depth == 0:
                    break
                k += 1
            if k == m.end():                    # (no argument at all)
                continue
            out.append(body[last:k])
            out.append(" GEN_EDX_ARG")
            last = k
        out.append(body[last:])
        return "".join(out)

    @staticmethod
    def vcalls(body: str) -> str:
        """`((code *)*(gen_code32 *)(*piVar1 + 0x18))(piVar1, ...)`, a call through the vtable of
        its first argument: a method, __thiscall in the reference (`this` in ecx, the callee
        popping the rest), so for the x86 fidelity build `((GEN_TCODE *)...)(piVar1 GEN_EDX_ARG,
        ...)`, Ghidra32.h's unprototyped __fastcall there and `code` elsewhere. As a __cdecl call
        it pushed `this` and its caller popped: a forwarding thunk's tail call became a call that
        pushed its eight arguments again, bytes32 2026-10-27."""
        if "(code *)" not in body:
            return body

        def close(s: str, k: int) -> int:
            """the index past the parenthesis matching s[k] == '(', or -1"""
            depth = 0
            for j in range(k, len(s)):
                if s[j] == "(":
                    depth += 1
                elif s[j] == ")":
                    depth -= 1
                    if depth == 0:
                        return j + 1
            return -1

        out, pos = [], 0
        for m in re.finditer(r"\(\(code \*\)", body):
            if m.start() < pos:
                continue
            end = close(body, m.start())             # past `((code *)E)`
            if end < 0:
                continue
            k = end
            while k < len(body) and body[k] in " \t\r\n":
                k += 1
            if k >= len(body) or body[k] != "(":
                continue
            args_end = close(body, k)
            if args_end < 0:
                continue
            # the first argument, at the call's top level
            depth, j = 0, k + 1
            while j < args_end - 1:
                ch = body[j]
                if ch in "([":
                    depth += 1
                elif ch in ")]":
                    depth -= 1
                elif ch == "," and depth == 0:
                    break
                j += 1
            first = body[k + 1:j].strip()
            callee = body[m.start() + len("((code *)"):end - 1]
            # (the first argument read through for the callee: `*X`, `*(int *)X`, `**(int **)(X + 8)`)
            core = re.sub(r"^(?:\(\s*[\w\s*]+\)\s*)+", "", first).strip()
            # (the name's end by what follows it, not \b: `REFG(int * PTR32, 0x1371294)` ends in `)`)
            if not core or not re.search(r"\*\s*(?:\(\s*[\w\s*]+\)\s*)*\(?\s*" + re.escape(core) + r"(?!\w)", callee):
                continue
            out.append(body[pos:m.start()])
            # (the dummy edx 0, or the function's own forwarded, conv_calls. The method's address
            # as it, GEN_EDX_VAL, came out `mov edx, eax; call eax` and lost a thunk's tail call)
            out.append("((GEN_TCODE *)" + callee + ")" + body[end:j] + " GEN_EDX_ARG")
            pos = j
        out.append(body[pos:])
        return "".join(out)

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
        return self.conv_decl(a, ret, ps)

    @staticmethod
    def jump_wrapper(a: int, d: str) -> str | None:
        """jumps.c's wrapper for the function declared d, W_<a>, where its entry needs one, else
        None: a byte or word result widened to all of eax (an indirect caller reads eax whole), an
        x87 one returned as a double (gen_fcode's type). quickfix.py writes them again for the
        functions it changes."""
        ret = d.split(f"F_{a:08x}")[0].strip()
        # (the return type without the convention: `float GEN_THISCALL` read as no float since the
        # conventions were declared, every __thiscall float getter called through a pointer without
        # its double wrapper, a float's bits read as a double: a sound filter's frequency 16384 for
        # 0.5, and its assert, DynamicValue::vf4 2026-10-28)
        ret = re.sub(r"\s*\bGEN_(?:THIS|STD|FAST)CALL\b", "", ret)
        width = NARROW_RETS.get(ret)
        ps = [p.strip() for p in d[d.index("(") + 1:d.rindex(")")].split(",")]
        names = [] if ps in ([""], ["void"]) else [re.split(r"[\s*]+", p)[-1] for p in ps]
        # (the parameter's name, not the convention macro after it: `gen_a0 GEN_EDX_PARAM`, and
        # the dummy edx forwarded)
        names = [(re.search(r"\bgen_a\d+\b", p).group(0) + (" GEN_EDX_FWD" if "GEN_EDX_PARAM" in p else ""))
                 if re.search(r"\bgen_a\d+\b", p) else nm for p, nm in zip(ps, names)]
        # (and float or double parameters taken as their bits: an indirect caller passes each word
        # as an integer, `(undefined4)gen_fl2bits(f)` through code, in an integer register, where
        # the callee reads its float from an xmm one. A sound filter's set read 16384 and 1.0 from
        # xmm2 and xmm3 for its frequency and Q, and asserted, 0xcc1720 2026-10-28)
        wps, conv = [], False
        if "..." not in ps:
            for p, nm in zip(ps, names):
                # (the first with the convention's dummy edx after it too, `float gen_a0
                # GEN_EDX_PARAM`: a __thiscall's `this` Ghidra typed float, taken from xmm0 while
                # its caller passed ecx's word in rcx. 0xbba5e0's this read as garbage, a crash on
                # Start, 12 like it, 2026-10-31)
                m = re.fullmatch(r"(float|double)\s+(gen_a\d+)(\s+GEN_EDX_PARAM)?", p)
                if m:
                    conv = True
                    edx = " GEN_EDX_PARAM" if m.group(3) else ""
                    if m.group(1) == "float":
                        wps.append(f"unsigned int {m.group(2)}{edx}")
                        names[names.index(nm)] = f"gen_bits2f({m.group(2)})" + (" GEN_EDX_FWD" if edx else "")
                    else:
                        # (a double its two stack words, low first, as an indirect caller passes
                        # them, each an integer argument: as one 64-bit word, the low word was the
                        # double and the high one the next parameter, a COM method's Ratio(9.0,
                        # 2.0f) dividing 0 by 2.53, rhtest com)
                        wps += [f"unsigned int {m.group(2)}", f"unsigned int {m.group(2)}_h"]
                        names[names.index(nm)] = \
                            f"gen_bits2d((unsigned long long){m.group(2)}_h << 32 | {m.group(2)})"
                else:
                    wps.append(p)
        else:
            wps = ps
        call = f"F_{a:08x}({', '.join(names)})"
        sig = ", ".join(wps) or "void"
        # (and one returning an x87 value, float, double or float10, as a double: an indirect
        # caller reading it calls through gen_fcode, double's type, and a float in xmm0 read so
        # was another number, code_slots, 2026-10-26)
        # (not a variadic one: no wrapper can pass its `...` on)
        if width is None and "*" not in ret and ret.split()[-1] in FLOATS and "..." not in ps:
            return f"static double W_{a:08x}({sig}) {{ return (double){call}; }}"
        if width is not None:
            return f"static unsigned int W_{a:08x}({sig}) {{ return (unsigned int)({width}){call}; }}"
        if not conv:
            return None
        # (a 16-byte vector one, gen_r16: its __m128 as it is, 2026-10-30)
        if ret == "gen_r16":
            return f"static gen_r16 W_{a:08x}({sig}) {{ return {call}; }}"
        if ret == "void":
            return f"static unsigned int W_{a:08x}({sig}) {{ {call}; return 0; }}"
        if "*" in ret:
            return f"static unsigned int W_{a:08x}({sig}) {{ return (unsigned int)(uintptr_t){call}; }}"
        if ret.split()[-1] in ("longlong", "ulonglong", "undefined8", "int8", "uint8"):
            return f"static unsigned long long W_{a:08x}({sig}) {{ return (unsigned long long){call}; }}"
        return f"static unsigned int W_{a:08x}({sig}) {{ return (unsigned int){call}; }}"

    def emit(self, translated: dict[int, str], stubbed: dict[int, str],
             layout: dict[int, int] | None = None) -> list[Path]:
        """layout: each function's file as the last run wrote it (--update), a new one in its
        predecessor's: only the files of the functions that changed are written again."""
        GEN.mkdir(parents=True, exist_ok=True)
        decls = {a: OWN_DECL.get(a) or self.stub_decl(a) for a in self.corpus}
        # every function's prototype, translated or not
        h = ["/* generated by translate32.py: every reference function's prototype */",
             "#pragma once", '#include "Ghidra32.h"']
        # (a translated one's as its definition declares it: GEN_P's parameters, typed in the x86
        # fidelity build, must be the header's too)
        h += [f"{definition_decl(translated[a]) or decls[a]};" if a in translated else f"{decls[a]};"
              for a in sorted(decls)]
        # (the C runtime's imports that never return as such, GEN_NORETURN: the reference's compiler
        # knew it and put nothing after the call, `call terminate` its function's last block; the
        # x86 build's fell through into the epilogue, bytes32)
        # (and each one in the x86 fidelity build as the reference calls it, through its import
        # table, `call dword ptr [__imp_X]`, the callee popping a Windows API's arguments: as a
        # function of the port's, `call X; add esp, k`, bytes32)
        # (a C runtime DLL's function only as the program's code calls it: the runtime's static
        # library calls those through a thunk of its own, `call _set_new_mode` -> `jmp [__imp_]`,
        # built without the DLL's headers. One no program function calls, a direct call)
        own_calls = set()
        for a, text in translated.items():
            if not self.is_library(a):
                own_calls |= set(re.findall(r"\bgen_imp_(\w+)\s*\(", text))
        h += [f"{MATH[n][0]} gen_imp_{n}({', '.join(math_params(n)[0])});" if n in MATH and n not in OVERRIDES
              else ("GEN_NORETURN " if cid(n).lstrip("_") in NORETURN_IMPORTS else "")
              + ("GEN_DLLIMPORT " if not CDECL_DLLS.match(dll or "") or cid(n) in own_calls else "")
              + f"{OVERRIDE_RET.get(n, 'unsigned int')} "
              + ("GEN_STDCALL " if import_stdcall(dll, n) else "") + f"gen_imp_{cid(n)}();"
              for n, (_, dll) in sorted(self.imports.items())]
        write(GEN / "translated.h", "\n".join(h) + "\n")
        write(GEN / "Ghidra32.h", HEADER.read_text(encoding="utf-8"))
        files = []
        # (each function reading a local it never assigns logs its first call, GEN_SUSPECT: a silent
        # miscompile otherwise, found only by the crash it leads to)
        suspect = {}
        for a in list(translated):
            # (one read back from the last run's files has its suspect line already, --update)
            if "GEN_SUSPECT(" in translated[a]:
                continue
            names = uninit_locals(translated[a])
            # (a stack slot the reference never writes either, its address never taken: its own
            # garbage, a structure's padding copied whole, `mov eax, [ebp - 4]; mov [ecx + 0xc], eax`
            # with nothing storing [ebp - 4]. 0, the same every run, and no suspect: those four
            # printed at every start of a client, its UI header copies, 2026-10-28)
            for n in [n for n in names if self.ref_slot_unwritten(a, n)]:
                names.remove(n)
                translated[a] = re.sub(r"(?m)^(\s*[A-Za-z_][\w ]*?[\s*]+" + n + r")\s*;", r"\1 = 0;",
                                       translated[a], count=1)
            if names:
                suspect[a] = names
                translated[a] = re.sub(r"(?m)^([ \t]*GEN_ENTER\(0x[0-9a-f]+u,[^\n]*;)$",
                                       lambda m: m.group(1) + f'\n  GEN_SUSPECT(0x{a:x}u, "{", ".join(names)}");',
                                       translated[a], count=1)
        items = sorted(translated.items())
        if layout is not None:
            groups: dict[int, list] = {}
            last = 0
            for a, t in items:
                last = layout.get(a, last)
                groups.setdefault(last, []).append((a, t))
            chunks = [(k, groups[k]) for k in sorted(groups)]
        else:
            chunks = [(k // PER_FILE, items[k:k + PER_FILE]) for k in range(0, len(items), PER_FILE)]
        for k, chunk in chunks:
            path = GEN / f"translated_{k:03d}.c"
            # (4717, recursive on all paths: a function whose other path ends in a call that does not
            # return, which the port's declarations do not say. VS2010's /MT dive() bottoms out in
            # the CRT's translated longjmp, rhtest msvc-16.00-x86 misc)
            # (4033: a void function's valueless return in the port's unsigned int one, ret_void)
            text = ['#include "translated.h"', "#pragma warning(disable: 4024 4047 4133 4244 4305 4311 4312 4700 4715 4716 4717 4022 4028 4090 4146 4554 4033)"]
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
            if a in OWN:
                continue                                 # (the project's own definition)
            d = decls[a]
            ret = d.split(f"F_{a:08x}")[0].strip()
            # (a stub records its call in the shadow trace too: what the port could not do is a
            # place the two runs part)
            ps = d[d.index("(") + 1:d.rindex(")")].split(", ")
            # (the parameter's name, not a convention macro after it: `gen_a0 GEN_EDX_PARAM`)
            args = [re.search(r"\bgen_a\d+\b", p).group(0) if p.startswith("unsigned int gen_a") else "0u"
                    for p in ps[:4] if p not in ("void", "...")]
            # (and the return type without the convention: `uint GEN_THISCALL F_x(...)`)
            ret = re.sub(r"\s*\bGEN_(?:THIS|STD|FAST)CALL\b", "", ret)
            args += ["0u"] * (4 - len(args))
            body = "GEN_ENTER(0x%xu, %s); GenUnimplemented(0x%x);" % (a, ", ".join(args), a)
            r = "" if ret == "void" else (" return 0;" if "*" not in ret else " return 0;")
            if ret not in ("void",) and not any(x in ret for x in ("*",)) and ret.split()[-1] in FLOATS:
                r = " return 0.0;"
            # (a 16-byte vector one's, gen_r16: its lanes 0, as C converts no 0 to an __m128, 2026-10-30;
            # Ghidra32.h's GEN_R16_ZERO, the host's own vector off x86)
            if ret == "gen_r16":
                r = " return GEN_R16_ZERO;"
            s.append(f"{d} {{ {body}{r} }}")
        write(GEN / "stubs.c", "\n".join(s) + "\n")
        # the jumps the runtime writes at each reference entry
        j = ['#include "translated.h"', "typedef struct { unsigned int ref; void *port; } GEN_JUMP;"]
        # (a function returning a byte or a word, reached through a pointer, is called as one that
        # returns all of eax: x64 leaves the rest of rax undefined, so its entry widens the result.
        # /GL's thing_query, `xor eax, eax; ...; setne al`, an i1, came back 0xcccccc5f to an
        # indirect caller, and the next call went there, rhtest msvc-14.51-x86 calls-GL com_calls)
        narrow = {}
        for a in sorted(self.corpus):
            w = self.jump_wrapper(a, decls[a])
            if w is not None:
                j.append(w)
                narrow[a] = f"W_{a:08x}"
        j += ["const GEN_JUMP g_genJumps[] = {"]
        j += [f"  {{0x{a:x}u, (void *){narrow.get(a, f'F_{a:08x}')}}}," for a in sorted(self.corpus)]
        # (and each local thunk, to its target's)
        j += [f"  {{0x{at:x}u, (void *){narrow.get(t, f'F_{t:08x}')}}}," for at, t in sorted(self.thunks.values())]
        j += ["};", f"const unsigned int g_genJumpCount = {len(self.corpus) + len(self.thunks)};"]
        # (and the reference addresses whose function is a __thiscall one, `this` in ecx before its
        # stack words, sorted: the runtime calls a reference object's method for a system callback
        # as COM does, __stdcall with `this` the first stack word, and on x64 a __thiscall function's
        # first parameter is ecx's. A voice callback's slots, `mov esi, [ebp + 8]` with nothing read
        # of ecx, are __thiscall as methods that leave their `this` alone; called with the object
        # first, each word was one off and OnVoiceProcessingPassStart read its object through 0,
        # Com32.cpp CallMethod)
        this_at = sorted({a for a in self.corpus if self.conv.get(a) == "__thiscall"}
                         | {at for at, t in self.thunks.values() if self.conv.get(t) == "__thiscall"})
        j += ["const unsigned int g_genThiscall[] = {"]
        j += ["  " + ", ".join(f"0x{a:x}u" for a in this_at[i:i + 8]) + "," for i in range(0, len(this_at), 8)]
        j += ["  0u", "};", f"const unsigned int g_genThiscallCount = {len(this_at)};"]
        # (the C++ EH frames' handler thunks and their FuncInfo, for the runtime's dispatcher, which
        # cannot read the reference's code: int3 over all of it, Adapters.cpp eh::FuncInfoOf)
        fis = self.eh_funcinfos()
        j += ["/* each C++ frame handler thunk (`mov eax, FuncInfo; jmp __CxxFrameHandler3`), its FuncInfo; 0-ended */",
              "const unsigned int g_genEhFuncInfo[] = {"]
        j += [f"  0x{h:x}u, 0x{fi:x}u," for h, fi in sorted(fis.items())]
        j += ["  0u, 0u", "};"]
        # (the data in the code section the translation reads, which the runtime keeps through its
        # int3 over the rest: a byte switch's index table after its function, `movzx ecx, byte
        # [ecx + 0x90171c]; jmp [ecx*4 + 0x9016c8]`, read 0xcc for every index, matched no case, and
        # a lobby agent never showed the logo, 2026-10-28)
        td = self.text_data(translated)
        j += ["/* the reference's code-section data the translation reads: [lo, hi) pairs, 0-ended */",
              "const unsigned int g_genTextData[] = {"]
        j += [f"  0x{x:x}u, 0x{y:x}u," for x, y in td]
        j += ["  0u, 0u", "};"]
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
              IMPORTS_LONGS,
              "#define GEN_REST(last) intptr_t r[10]; va_list ap; va_start(ap, last); \\",
              "    for (int k = 0; k < 10; k++) r[k] = va_arg(ap, int); va_end(ap)",
              "typedef intptr_t (*gen_real_fn)(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t,",
              "                                intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t);",
              "typedef struct { unsigned int slot; const char *dll; const char *name; void *adapter; gen_real_fn *real; } GEN_IMPORT;"]
        for n, (slot, dll) in sorted(self.imports.items()):
            im.append(f"gen_real_fn gen_real_{cid(n)};")
            if n in OVERRIDES:
                im.append(f"{OVERRIDE_RET.get(n, 'unsigned int')} gen_imp_{cid(n)}();   /* the runtime's */")
                continue
            if n in MATH:
                ret, ps = MATH[n]
                params, args = math_params(n)
                im.append(f"{ret} gen_imp_{n}(" + ", ".join(params) + ") { "
                          f"return (({ret} (*)({', '.join(ps)}))gen_real_{n})(" + ", ".join(args) + "); }")
                continue
            im.append(f"unsigned int gen_imp_{cid(n)}(int a0, int a1, int a2, int a3, ...) {{ GEN_REST(a3); "
                      f"return (unsigned int)gen_real_{cid(n)}(a0, a1, a2, a3, "
                      + ", ".join(f"r[{k}]" for k in range(10)) + "); }")
        im.append("const GEN_IMPORT g_genImports[] = {")
        # (an adapter the runtime writes calls Windows itself: nothing to resolve for it)
        for n, (slot, dll) in sorted(self.imports.items()):
            real = "0" if n in OVERRIDES else f"&gen_real_{cid(n)}"
            # (the name as Windows has it, `?` escaped: no trigraph in a C++ import's mangled name)
            raw = n.replace("?", "\\?")
            im.append(f'  {{0x{slot:x}u, "{dll}", "{raw}", (void *)gen_imp_{cid(n)}, {real}}},')
        im += ["};", f"const unsigned int g_genImportCount = {len(self.imports)};"]
        write(GEN / "imports.c", "\n".join(im) + "\n")
        # (the frame helpers and setjmp no translation calls, FOLDED_NAME: their stubs stay, reached
        # by nothing, a trap all the same; listed "folded" as fidelity32 scores them, not as stubs.
        # One a translation names stays a stub)
        folded = {a: v for a, v in stubbed.items() if a not in OWN
                  and FOLDED_NAME.fullmatch(self.corpus.get(a, {}).get("name", ""))
                  and not any(f"F_{a:08x}" in t for t in translated.values())}
        kept = {a: v for a, v in stubbed.items() if a not in folded}
        reasons = Counter(re.sub(r"\(.*", "", v).split(":")[0].strip() for v in kept.values())
        write(MANIFEST, json.dumps({"translated": len(translated), "stubbed": len(kept),
                                    "suspect": {f"{a:08x}": n for a, n in sorted(suspect.items())},
                                    "reasons": dict(reasons.most_common()),
                                    "stubs": {f"{a:08x}": v for a, v in sorted(kept.items()) if a not in OWN},
                                    "own": {f"{a:08x}": v for a, v in sorted(stubbed.items()) if a in OWN},
                                    "folded": {f"{a:08x}": f"{self.corpus[a]['name']}: {v}"
                                               for a, v in sorted(folded.items())}}, indent=1))
        return files


UNINIT_DECL = re.compile(r"(?m)^[ \t]+(?!(?:return|goto|break|continue|case)\b)[A-Za-z_][\w \t]*?[\s*]+([A-Za-z_]\w*)[ \t]*;[ \t]*$")


# the C runtime's and the system's functions that never return, by name less leading underscores
NORETURN_IMPORTS = {"terminate", "abort", "exit", "Exit", "quick_exit", "CxxThrowException", "std_terminate",
                    "invalid_parameter_noinfo_noreturn", "invoke_watson", "longjmp", "ExitProcess", "ExitThread",
                    "FatalExit", "FatalAppExitA", "FatalAppExitW", "endthread", "endthreadex", "amsg_exit",
                    "report_rangecheckfailure", "report_gsfailure"}

# the C and C++ runtimes' DLLs, whose functions are __cdecl: the caller pops their arguments
CDECL_DLLS = re.compile(r"(?i)^(?:ucrtbased?|api-ms-win-crt-.*|msvc[rp]\d*d?|vcruntime\d*d?|msvcrt)\.dll$")
# (and the system's that take a variable argument list)
CDECL_IMPORTS = {"wsprintfA", "wsprintfW", "DbgPrint", "DbgPrintEx", "ShellMessageBoxA", "ShellMessageBoxW"}


def import_stdcall(dll: str, name: str) -> bool:
    """Whether an import is __stdcall, the callee popping its arguments: the Windows API's, not the
    C runtime's nor a variadic one"""
    return not CDECL_DLLS.match(dll or "") and name not in CDECL_IMPORTS


def definition_decl(text: str) -> str | None:
    """A translated function's declaration as its definition writes it, the frame macro aside"""
    m = re.search(r"(?m)^(?:GEN_(?:LIB|OWN)(?:_GS)? )?(?:GEN_FRAME |GEN_NOFRAME )(.+F_[0-9a-f]{8}\(.*\))[ \t]*$", text)
    return m.group(1) if m else None


def uninit_locals(text: str) -> list[str]:
    """The locals a translated function reads but never assigns: a register the decompiler lost and
    named like a variable (`this_00`, `pvVar5`), past the passes that resolve `extraout_*`. Read so,
    each is what the host's register or stack slot held: a UI hit test's `this_00`, its node, a code
    address, and a click on the title menu crashed (2026-10-28). emit marks each GEN_SUSPECT."""
    _head, _, rest = text.partition("{")
    out = []
    for m in UNINIT_DECL.finditer(rest):
        n = m.group(1)
        if ":" in m.group(0) or n.startswith(("gen_", "param_", "in_", "extraout_", "unaff_", "LAB_", "joined_")):
            continue
        code = rest[:m.start()] + rest[m.end():]
        if not re.search(rf"\b{n}\b", code):
            continue
        if re.search(rf"(?<![\w.>])\b{n}\s*(?:[-+*/|&^%]|<<|>>)?=(?!=)|&\s*{n}\b|\b{n}\s*(?:\+\+|--)|(?:\+\+|--)\s*{n}\b"
                     rf"|\b{n}\s*\[|\(\s*{n}\s*\)\s*\[|\b{n}\s*\.\w+\s*=(?!=)|\b{n}\s*->", code):
            continue
        out.append(n)
    return out


# ---- the reference's `long` ---------------------------------------------------------------------
# 4 bytes on x86 (and on Win64, LLP64), 8 on an LP64 host (aarch64 Linux/Android): the generated
# sources never spell C's `long` for it, but Ghidra32.h's gen_long and gen_ulong, long on Windows
# and int on LP64. Ghidra's own types (strtol's `long`, `long lVar1;`), this translator's
# (`(volatile long *)` for _InterlockedExchange) and MATH's import types alike, at the one place
# every generated source passes, write(). `long long` and `long double` are left as they are, and
# a string, character or comment (`"vector<T> too long"`) is no type, nor the definition of the two
# names themselves (imports.c's, IMPORTS_LONGS)
LONG_SCAN = re.compile(
    r"(?P<skip>\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'|/\*.*?\*/|//[^\n]*"
    r"|\b(?:(?:un)?signed\s+)?long\s+(?:long|double)\b"
    r"|\btypedef\s+(?:unsigned\s+)?long\s+gen_u?long\s*;)"
    r"|(?P<u>\bunsigned\s+long(?:\s+int)?\b|\blong\s+unsigned(?:\s+int)?\b)"
    r"|(?P<s>\b(?:signed\s+)?long(?:\s+signed)?(?:\s+int)?\b)", re.S)


def port_longs(text: str) -> str:
    """text, a generated C source, with each C `long` of the reference's 4 bytes spelled gen_long
    (`long`, `long int`, `signed long`) or gen_ulong (`unsigned long`, `unsigned long int`, `long
    unsigned`). Idempotent: callers may apply it to a gen directory written before it existed
    (port_longs_dir) as well as to new text."""
    def rep(m):
        if m.group("skip") is not None:
            return m.group(0)
        return "gen_ulong" if m.group("u") is not None else "gen_long"
    return LONG_SCAN.sub(rep, text)


# (the sources port_longs applies to: Ghidra32.h defines gen_long by C's long, and is copied whole)
def ported_source(path: Path) -> bool:
    return path.suffix in (".c", ".h") and path.name != "Ghidra32.h"


def port_longs_dir(gen: Path, check: bool = False) -> list[Path]:
    """port_longs over a gen directory's sources in place (a copy of one written before it, for an
    LP64 build without translating again), or with check only read: the files with a `long` left."""
    changed = []
    for p in sorted(gen.iterdir()):
        if not p.is_file() or not ported_source(p):
            continue
        text = p.read_bytes().decode("utf-8")
        new = port_longs(text)
        if new != text:
            changed.append(p)
            if not check:
                # (imports.c includes no Ghidra32.h: its own definitions, as emit writes them)
                if p.name == "imports.c" and "gen_long;" not in new:
                    new = new.replace("#include <stdarg.h>\n", "#include <stdarg.h>\n" + IMPORTS_LONGS + "\n", 1)
                p.write_bytes(new.encode("utf-8"))
    return changed


# (imports.c's gen_long and gen_ulong, Ghidra32.h's: it includes none of the generated headers)
IMPORTS_LONGS = ("#if defined(__LP64__) || defined(_LP64)\n"
                 "typedef int gen_long; typedef unsigned int gen_ulong;\n"
                 "#else\n"
                 "typedef long gen_long; typedef unsigned long gen_ulong;\n"
                 "#endif")


def write(path: Path, text: str) -> None:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if ported_source(path):
        text = port_longs(text)
    if path.exists() and path.read_bytes().decode("utf-8", errors="replace") == text:
        return
    # (as written: Windows newlines would double the corpus's own \r)
    # (into a file beside it, then put in its place: another process with the file mapped while it
    # reads it, the IDE's clangd indexing the generated sources, makes Windows refuse its truncation,
    # EINVAL, and the whole translation was lost at its last step, 2026-10-30. A replace it allows,
    # the reader's open sharing deletion; the reader keeps the old bytes it mapped)
    data = text.encode("utf-8")
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    for k in range(30):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            if k == 29:
                raise
            time.sleep(1)


# ---- the compile loop ---------------------------------------------------------------------------
_env: dict | None = None


def msvc_env() -> dict:
    """The x64 MSVC environment (vcvars64), captured once."""
    global _env
    if _env is None:
        vswhere = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Microsoft Visual Studio/Installer/vswhere.exe"
        vs = subprocess.run([str(vswhere), "-latest", "-property", "installationPath"], capture_output=True, text=True).stdout.strip()
        bat = Path(vs) / "VC/Auxiliary/Build/vcvars64.bat"
        # (what vcvars sets, kept between runs while the batch file is the same one: running it
        # takes ~4 s, as long as a small program's whole compile. Laid over this process's own
        # environment, never a copy of another's)
        import tempfile
        saved = Path(tempfile.gettempdir()) / "rhipper-vcvars64.json"
        stamp = f"{bat}|{bat.stat().st_mtime if bat.exists() else 0}"
        try:
            got = json.loads(saved.read_text(encoding="utf-8"))
            delta = got["vars"] if got.get("stamp") == stamp else None
        except (OSError, ValueError, KeyError):
            delta = None
        if delta is None:
            out = subprocess.run(f'"{bat}" >nul 2>nul && set', shell=True, capture_output=True, text=True).stdout
            full = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
            here = {k.upper(): v for k, v in os.environ.items()}
            delta = {k.upper(): v for k, v in full.items() if here.get(k.upper()) != v}
            try:
                saved.write_text(json.dumps({"stamp": stamp, "vars": delta}), encoding="utf-8")
            except OSError:
                pass
        _env = {**os.environ, **delta}
    return _env


# each compile's errors by what it compiled (the file, the headers it includes, the compiler): a
# file the translation wrote the same as before compiles as it did, and is not compiled again. The
# objects are only the check's, nothing links them
COMPILED = OBJ / "compiled.json"
_compiled: dict[str, list] | None = None
_used: set[str] = set()                  # (what this run compiled: all the cache keeps)


def compiled_cache() -> dict[str, list]:
    global _compiled
    if _compiled is None:
        try:
            _compiled = json.loads(COMPILED.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            _compiled = {}
    return _compiled


def compile_one(path: Path) -> list[tuple[int, str]]:
    """(line, message) of every error compiling one generated file."""
    import hashlib
    OBJ.mkdir(parents=True, exist_ok=True)
    env = msvc_env()
    # (Windows looks a program up on this process's PATH, not the one passed to it)
    import shutil
    cl = shutil.which("cl", path=env.get("PATH") or env.get("Path"))
    cmd = [cl, "/nologo", "/c", "/O1", "/W1", "/we4013", "/TC", "/bigobj", "/std:c17",
           f"/Fo{OBJ / (path.stem + '.obj')}", str(path)]
    h = hashlib.sha256("\0".join(cmd + [str(os.path.getmtime(cl))]).encode())
    for f in (path, GEN / "translated.h", GEN / "Ghidra32.h"):
        h.update(f.read_bytes() if f.exists() else b"")
    key = h.hexdigest()
    cache = compiled_cache()
    _used.add(key)
    if key in cache:
        return [tuple(e) for e in cache[key]]
    r = subprocess.run(cmd, capture_output=True, text=True, env=msvc_env(), cwd=str(GEN))
    errs = []
    for line in r.stdout.splitlines():
        m = re.match(r"^(.*?)\((\d+)\)\s*: (?:fatal )?error (\w+): (.*)$", line)
        if m and Path(m.group(1)).name == path.name:
            errs.append((int(m.group(2)), f"{m.group(3)}: {m.group(4)}"))
    # (only a compile that ran: one cl could not start, or that died, says nothing of the file)
    if r.returncode == 0 or errs:
        cache[key] = errs
    return errs


def save_compiled() -> None:
    if _compiled is not None:
        OBJ.mkdir(parents=True, exist_ok=True)
        COMPILED.write_text(json.dumps({k: v for k, v in _compiled.items() if k in _used}), encoding="utf-8")


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


# the translation's worker processes: each loads the inputs once (~8 s and ~0.5 GB for a VS2010 client's
# 87k functions), so a pool is only for a program that large; a small one translates in-process
POOL_MIN = 5000
_worker: Translator32 | None = None


def _worker_init() -> None:
    global _worker
    # (its loading report is the parent's, already printed)
    sys.stdout = open(os.devnull, "w")
    _worker = Translator32()


def _translate_one(a: int) -> tuple[int, bool, str]:
    return _worker.translate_one(a)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-build", action="store_true")
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--rounds", type=int, default=20)
    ap.add_argument("--keep-demoted", action="store_true",
                    help="start from the last run's demotions (by default every function is tried again: "
                         "a fix in the translator shows as a round with none)")
    ap.add_argument("--update", nargs="*", help="these functions (hex, or @file of them) translated again into "
                    "the last run's files, only the changed files compiled")
    ap.add_argument("--port-longs", metavar="DIR", help="port_longs over a gen directory's sources in place "
                    "(one written before it, for an LP64 host), nothing translated")
    ap.add_argument("--check-longs", metavar="DIR", help="the sources of a gen directory that spell C's long "
                    "for the reference's (exit 1 if any)")
    args = ap.parse_args()
    if args.port_longs or args.check_longs:
        left = port_longs_dir(Path(args.port_longs or args.check_longs), check=bool(args.check_longs))
        print(f"{'long left in' if args.check_longs else 'port_longs:'} {len(left)} files"
              + "".join(f"\n  {p.name}" for p in left))
        sys.exit(1 if args.check_longs and left else 0)
    t = Translator32()
    if args.update:
        addrs = set()
        for x in args.update:
            if x.startswith("@"):
                addrs |= {int(y, 16) for y in Path(x[1:]).read_text().split() if y.strip()}
            else:
                addrs.add(int(x, 16))
        update(t, addrs, args.jobs)
        return
    only = {int(x, 16) for x in args.only} if args.only else None
    demoted = json.loads(DEMOTED.read_text()) if DEMOTED.exists() and args.keep_demoted else {}
    many = len(t.corpus) if only is None else len(only)
    pool = Pool(args.jobs, initializer=_worker_init) if args.jobs > 1 and many >= POOL_MIN else None
    try:
        rounds(t, args, only, demoted, pool)
    finally:
        if pool is not None:
            pool.terminate()


def read_gen() -> tuple[dict[int, str], dict[int, int], set[int]]:
    """The last run's translations as it wrote them, each function's file, and its stubs."""
    translated, layout = {}, {}
    for path in sorted(GEN.glob("translated_*.c")):
        k = int(path.stem.split("_")[1])
        lines = path.read_text(encoding="utf-8").split("\n")[2:]
        block: list[str] = []

        def flush():
            text = "\n".join(block).rstrip("\n")
            m = re.search(r"(?m)^\S[^\n]*?\bF_([0-9a-f]{8})\s*\(", text)
            if m:
                translated[int(m.group(1), 16)] = text
                layout[int(m.group(1), 16)] = k
        for line in lines:
            if line.startswith("/* ref: ") and block:
                flush()
                block = []
            block.append(line)
        if block:
            flush()
    stubs = {int(x, 16) for x in re.findall(r"\bF_([0-9a-f]{8})\s*\(", (GEN / "stubs.c").read_text(encoding="utf-8"))}
    return translated, layout, stubs


def update(t: Translator32, addrs: set[int], jobs: int) -> None:
    """--update: these functions translated again into the last run's files, each where it was
    (a new one beside its predecessor), and only the files that changed compiled: seconds for a
    group of problem functions, where a whole run is many minutes."""
    old, layout, stubs = read_gen()
    demoted: dict[str, str] = {}
    for _ in range(4):
        new_t, new_s = t.translate_all(addrs, demoted, None)
        translated = {a: x for a, x in old.items() if a not in addrs}
        translated.update({a: x for a, x in new_t.items() if a in addrs})
        stubbed = {a: "" for a in stubs if a not in addrs and a not in translated}
        stubbed.update({a: r for a, r in new_s.items() if a in addrs})
        before = {p: p.read_text(encoding="utf-8") for p in GEN.glob("translated_*.c")}
        files = t.emit(translated, stubbed, layout)
        changed = [p for p in files if before.get(p) != p.read_text(encoding="utf-8")]
        print(f"update: {len(new_t)} of {len(addrs)} translated, {len(changed)} files written")
        with ThreadPoolExecutor(max(1, jobs)) as compilers:
            results = dict(zip(changed, compilers.map(compile_one, changed)))
        new = 0
        for path, errs in results.items():
            starts = function_at_line(path)
            for line, msg in errs or ():
                owner = None
                for k, a in starts:
                    if k <= line:
                        owner = a
                    else:
                        break
                if owner is not None and owner in addrs and f"{owner:08x}" not in demoted:
                    demoted[f"{owner:08x}"] = msg[:160]
                    print(f"  demoted {owner:08x}: {msg[:160]}")
                    new += 1
        if not new:
            break
    for extra in ("stubs.c", "jumps.c", "imports.c"):
        errs = compile_one(GEN / extra)
        print(f"  {extra}: {'ok' if not errs else errs[:3]}")


def rounds(t: Translator32, args, only: set[int] | None, demoted: dict[str, str], pool) -> None:
    for rnd in range(args.rounds):
        translated, stubbed = t.translate_all(only, demoted, pool)
        files = t.emit(translated, stubbed)
        print(f"round {rnd}: translated {len(translated)}, stubbed {len(stubbed)} in {len(files)} files")
        if args.no_build:
            return
        t0 = time.time()
        # (its own name: as `pool` it was the next round's translation pool, and round 1 failed,
        # 'ThreadPoolExecutor' object has no attribute 'imap_unordered')
        with ThreadPoolExecutor(args.jobs) as compilers:
            results = dict(zip(files, compilers.map(compile_one, files)))
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
    save_compiled()


if __name__ == "__main__":
    main()
