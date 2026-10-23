"""A 32-bit reference's decompilation translated to C for an x64 port: translate.py's counterpart
for rhipper.json "arch": "x86" (first CrystalCore, FFXIV's ARR beta client).

The port's memory model (the project's Ghidra32.h says it at length): the port is linked
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

CORPUS = ROOT / "build/corpus.jsonl"
REFDATA = ROOT / "build/refdata.jsonl"
OBJ = ROOT / "build/gen-obj"
MANIFEST = GEN / "manifest.json"
DEMOTED = GEN / "demoted.json"
PER_FILE = 400

# the type words Ghidra32.h defines (or C has)
KNOWN_TYPES = {
    "void", "char", "short", "int", "long", "float", "double", "bool", "wchar_t", "signed", "unsigned",
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
# the Windows typedefs Ghidra32.h makes (4-byte) pointers
WIN_POINTERS = {"HANDLE", "HMODULE", "HINSTANCE", "HWND", "HDC", "HKEY", "HICON", "HCURSOR", "HMENU", "HBRUSH",
                "HGLOBAL", "HLOCAL", "HKL", "HGDIOBJ", "HIMC", "LPVOID", "PVOID", "LPCVOID", "LPSTR", "LPCSTR",
                "LPWSTR", "LPCWSTR", "LPDWORD", "LPLONG", "LPBYTE", "LPBOOL", "LPWORD", "FARPROC", "BSTR",
                "GEN_LPANY", "LPCRITICAL_SECTION", "PRTL_CRITICAL_SECTION", "pointer"}
# C words that look like types to the scans below but are not
NOT_TYPES = {"return", "sizeof", "if", "while", "for", "switch", "case", "goto", "else", "do", "break",
             "continue", "default", "const", "volatile", "struct", "union", "enum", "static", "extern"}
FLOATS = {"float", "double", "float4", "float8", "float10"}
WIDE = {"longlong", "ulonglong", "qword", "undefined8", "uint8", "int8", "uint5", "uint6", "uint7", "int5",
        "int6", "int7", "undefined5", "undefined6", "undefined7", "DWORD64", "DWORDLONG", "LONGLONG",
        "ULONGLONG", "__time64_t"}
CC = re.compile(r"\b(__thiscall|__cdecl|__stdcall|__fastcall|__vectorcall)\b\s*")
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
                "int8_t", "__ptr32", "__uptr", "LOCK", "UNLOCK", "_InterlockedExchange", "NAN", "INFINITY",
                "__debugbreak", "__readfsdword", "_rotl", "_rotr", "_rotl64", "_rotr64", "fabs", "sqrt",
                "floor", "ceil", "trunc", "nearbyint", "memcpy", "memset", "rdtsc", "GEN_PIECE", "GEN_ISNAN",
                "gen_piece_set", "gen_fl2bits", "gen_d2bits", "gen_bits2f", "gen_bits2d", "GEN_TOF", "GEN_TOD",
                "GEN_TOP", "GEN_FLT_TO"}
HEADER_PREFIX = re.compile(r"^(?:CONCAT\d+|SUB\d+|ZEXT\d+|SEXT\d+|CARRY\d|SCARRY\d|SBORROW\d)$")
# imports whose adapters the runtime writes itself (their structures differ between x86 and x64):
# rhipper.json "import_overrides"
OVERRIDES = set(project.CONFIG.get("import_overrides", []))
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


def load_corpus() -> dict[int, dict]:
    out = {}
    with open(CORPUS, encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            # (Ghidra writes Windows newlines; every pattern here reads \n)
            r["c"] = r["c"].replace("\r\n", "\n").replace("\r", "\n")
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


class Signature:
    """A function's Ghidra signature: return type, printed name, parameters (type, name)."""
    # (the name is the last word before the parameters, whatever it is made of: C++ operators
    # print as `operator+_00c76239`, templates with commas and brackets)
    SIG = re.compile(r"^(?P<ret>.*?)(?P<name>[^\s(*]+)\s*\((?P<params>.*)\)\s*$", re.S)

    def __init__(self, text: str, name: str | None = None):
        head = strip_comments(text).split("{", 1)[0]
        head = CC.sub("", " ".join(head.split()))
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
            for part in split_top(p):
                part = part.strip()
                if part == "...":
                    self.variadic = True
                    continue
                # a function pointer: `int (*_PtFuncCompare)(void *,void *)`
                fm = re.match(r"^.*\(\s*\*\s*([A-Za-z_]\w*)\s*\)\s*\(.*\)$", part)
                if fm:
                    self.params.append(("code *", fm.group(1)))
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

    # ---- one function ---------------------------------------------------------------------------
    def why_not(self, a: int) -> str | None:
        c = strip_comments(self.corpus[a]["c"])
        if a not in self.sigs:
            return "no signature"
        m = LOST.search(c)
        if m:
            return f"a register the decompiler lost ({m.group(1)})"
        if "halt_baddata" in c or "halt_unimplemented" in c:
            return "bad instruction data"
        if re.search(r"stack0x", re.sub(r"\(uint\)&stack0x[0-9a-f]+", "", c)):
            return "the caller's stack (stack0x)"
        nopiece = re.sub(r"\._\d+_\d+_", "", c)
        if re.search(r"[\w\)\]]\s*->\s*\w", nopiece) or re.search(r"(?<![\d.])\b[A-Za-z_]\w*\.[A-Za-z_]", nopiece) \
                or re.search(r"\]\s*\.[A-Za-z_]", nopiece):
            return "member access through a type C does not have"
        if re.search(r"\bcase\s+-?\d+\.\d", c):
            return "a switch on a floating point value"
        # an SSE register as a 16-byte array (`(undefined1 [16])x`, `*(undefined1 (*) [16])p`)
        if re.search(r"\(\s*undefined\d*\s*\[\s*(?:0x)?[0-9a-f]+\s*\]\s*\)|\(\*\)\s*\[", c):
            return "a cast to an array (an SSE register)"
        return None

    def known_type(self, word: str) -> bool:
        return word in KNOWN_TYPES

    def rewrite(self, a: int) -> str:
        """The function's C, translated (raises ValueError when it cannot be)."""
        sig = self.sigs[a]
        c = strip_comments(self.corpus[a]["c"])
        head, sep, body = c.partition("{")
        body = "{" + body
        # a jump table's address (switchD_00403f1a::switchdataD_00403f30), and the labels Ghidra
        # qualifies (switchD_00403f1a::caseD_5)
        body = re.sub(r"\bswitchD_[0-9a-f]+::switchdataD_([0-9a-f]{8})\b",
                      lambda m: self.global_lvalue(int(m.group(1), 16)), body)
        body = re.sub(r"\b(switchD_[0-9a-f]+)::(\w+)", r"\1__\2", body)
        # Ghidra's pseudo-ops and piece access (`local_7c[0]._0_2_`: 2 bytes at offset 0)
        body = re.sub(r"\bNAN\s*\(", "GEN_ISNAN(", body)
        body = re.sub(r"\b([A-Za-z_]\w*(?:\[[^\]\[]*\])?)\._(\d+)_(\d+)_",
                      lambda m: (f"(*(undefined{m.group(3)} *)((char *)&{m.group(1)} + {m.group(2)}))"
                                 if m.group(3) in ("1", "2", "4", "8")
                                 else f"GEN_PIECE(&{m.group(1)}, {m.group(2)}, {m.group(3)})"), body)
        body = self.virtual_this(body)
        # (types before names: a C++ type in a cast, `(Client::UI::Foo *)`, is no symbol)
        body = self.types(body)
        body = self.names(body)
        body = CC.sub("", body)
        body = re.sub(r"\(uint\)&stack0x[0-9a-f]+", "0u", body)
        body = RAM.sub(lambda m: f"REFG({RAM_TYPES.get(m.group(1), 'undefined4')}, 0x{m.group(2)})", body)
        body = re.sub(r"\b(\w+)_exref\b",
                      lambda m: f"((code *)gen_imp_{m.group(1)})" if m.group(1) in self.imports else m.group(0), body)
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
            else:
                prologue.append(f"  {tt} {n} = ({tt})gen_a{k};")
        if sig.variadic:
            raise ValueError("variadic")
        for m in re.finditer(r"(?m)^\s+((?:unsigned\s+)?[A-Za-z_]\w*(?:\s*\*[\s*]*(?:PTR32\s*\*\s*)*)?)\s*([A-Za-z_]\w*)\s*(\[[^\]]*\])?\s*;",
                             split_decls(body)[0]):
            # (an array is its element type with [] on: what indexes and dereferences it is fine)
            var_types.setdefault(m.group(2), m.group(1) + ("[]" if m.group(3) else ""))
        body = self.typed_casts(body, var_types)
        body = self.call_args(body, var_types)
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
        if re.search(r"\*\s*\(\*\(undefined4 \*\)\(\(char \*\)&", body):
            raise ValueError("a 4-byte piece dereferenced as a pointer")
        for n, t in var_types.items():
            if t.strip() == "code *" and re.search(r"\b" + re.escape(n) + r"\s*[-+]\s", body):
                raise ValueError("arithmetic on a code pointer")
        body = self.code_pointer_calls(body, var_types)
        body = self.float_assignments(body, var_types)
        body = self.pointer_locals(body, var_types)
        left = re.search(r"::|`|\bregister0x|\b_(?:local|param|[a-z]*Stack|auStack)\w*|\bin_[A-Z]", body)
        if left:
            raise ValueError(f"a name C cannot take ({left.group(0)})")
        self.undeclared(body, var_types)
        ret = self.ret_type(sig.ret)
        if sig.ret.strip() == "void":
            body = re.sub(r"\breturn\s*;", "return 0;", body)
        if not balanced(body):
            raise ValueError("unbalanced braces")
        decl = f"{ret} F_{a:08x}({', '.join(params) or 'void'})"
        # (the parameters' names are locals now, declared first in the body)
        body = body.replace("{", "{\n" + "\n".join(prologue), 1) if prologue else body
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
            if n.startswith(("F_", "gen_imp_", "GEN_", "gen_", "LAB_", "switchD_", "caseD_")) \
                    or HEADER_PREFIX.match(n) or (n.endswith(tuple("0123456789")) and n[:-1] in ("caseD_",)):
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
        return "unsigned int" if t in ("void", "code") else t

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
        if w not in KNOWN_TYPES:
            raise ValueError(f"local of type {w}")
        return True

    def virtual_this(self, body: str) -> str:
        """`(**(code **)(*OBJ + K))(args)` -> the object as the first argument, unless Ghidra
        already passes it there (a COM call, `this` on the stack)."""
        out, i = [], 0
        key = "(**(code **)("
        while True:
            j = body.find(key, i)
            if j < 0:
                out.append(body[i:])
                break
            inner_open = j + len("(**(code **)")
            inner_end = match_paren(body, inner_open)
            if inner_end < 0 or body[j:].startswith(key) is False:
                out.append(body[i:j + 1])
                i = j + 1
                continue
            call_close = inner_end + 1            # past the ')' that closes `(**(code **)(...)`
            if call_close >= len(body) or body[call_close] != "(":
                out.append(body[i:call_close])
                i = call_close
                continue
            args_end = match_paren(body, call_close)
            inner = body[inner_open + 1:inner_end - 1].strip()
            obj = None
            if inner.startswith("*"):
                e = inner[1:].strip()
                parts = split_top(e, "+")
                if len(parts) >= 2 and re.fullmatch(r"\s*(0x[0-9a-f]+|\d+)\s*", parts[-1]):
                    e = "+".join(parts[:-1]).strip()
                obj = re.sub(r"^\((?:int|uint|undefined4|void) \*\)\s*", "", e)
            args = body[call_close + 1:args_end - 1].strip()
            first = split_top(args)[0].strip() if args else ""
            norm = lambda s: re.sub(r"\((?:int|uint|undefined4|void|int \*|void \*|undefined4 \*)\)|\s", "", s)
            out.append(body[i:call_close + 1])
            if obj and norm(first) != norm(obj):
                out.append(f"{obj}{', ' if args else ''}")
            i = call_close + 1
        return "".join(out)

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
            if name in self.imports:
                return f"gen_imp_{name}("
            if name in self.ref_names:
                return f"((code *)REFP(0x{self.ref_names[name]:x}))("
            return m.group(0)
        body = re.sub(r"(?<![\w$:])(" + IDENT + r")\s*\(", call, body)

        # (a label's address is an address; the label itself, `LAB_x:` and `goto LAB_x`, stays)
        body = re.sub(r"&\s*(LAB_([0-9a-f]{8}))\b", lambda m: f"REFP(0x{m.group(2)})", body)
        body = re.sub(r"&\s*(_*(?:s|u|ws)_\w*?_([0-9a-f]{8}))\b", lambda m: f"REFP(0x{m.group(2)})", body)

        def sym(m):
            name, addr = m.group(1), int(m.group(2), 16)
            if name.startswith("LAB_"):
                return name
            if name.startswith(("s_", "u_", "ws_")):
                return f"((char *)REFP(0x{addr:x}))" if name.startswith("s_") else f"((wchar_t *)REFP(0x{addr:x}))"
            if name.startswith("switchdataD_"):
                return f"REFP(0x{addr:x})"
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
        files = []
        items = sorted(translated.items())
        for k in range(0, len(items), PER_FILE):
            chunk = items[k:k + PER_FILE]
            path = GEN / f"translated_{k // PER_FILE:03d}.c"
            text = ['#include "translated.h"', "#pragma warning(disable: 4013 4024 4047 4133 4244 4305 4311 4312 4700 4715 4716 4022 4028 4090 4146 4554)"]
            for a, t in chunk:
                text.append(t)
            write(path, "\n".join(text) + "\n")
            files.append(path)
        # stubs
        s = ['#include "translated.h"']
        for a in sorted(stubbed):
            d = decls[a]
            ret = d.split(f"F_{a:08x}")[0].strip()
            body = "GenUnimplemented(0x%x);" % a
            r = "" if ret == "void" else (" return 0;" if "*" not in ret else " return 0;")
            if ret not in ("void",) and not any(x in ret for x in ("*",)) and ret.split()[-1] in FLOATS:
                r = " return 0.0;"
            s.append(f"{d} {{ {body}{r} }}")
        write(GEN / "stubs.c", "\n".join(s) + "\n")
        # the jumps the runtime writes at each reference entry
        j = ['#include "translated.h"', "typedef struct { unsigned int ref; void *port; } GEN_JUMP;",
             "const GEN_JUMP g_genJumps[] = {"]
        j += [f"  {{0x{a:x}u, (void *)F_{a:08x}}}," for a in sorted(self.corpus)]
        j += ["};", f"const unsigned int g_genJumpCount = {len(self.corpus)};"]
        write(GEN / "jumps.c", "\n".join(j) + "\n")
        # imports: an adapter per name, its real function resolved by the runtime
        im = ['/* generated by translate32.py: the reference\'s imports. Each adapter takes the 32-bit',
              '   arguments the reference passed (sign-extended: addresses are below 2 GB, and handles',
              '   such as INVALID_HANDLE_VALUE or HKEY_CURRENT_USER widen as Windows expects) and calls',
              '   the real function with them; Win64 callers clean up, so the extra ones are harmless.',
              '   The runtime overrides the ones whose structures differ between x86 and x64. */',
              "#include <stdint.h>",
              "typedef intptr_t (*gen_real_fn)(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t,",
              "                                intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t);",
              "typedef struct { unsigned int slot; const char *dll; const char *name; void *adapter; gen_real_fn *real; } GEN_IMPORT;"]
        for n, (slot, dll) in sorted(self.imports.items()):
            im.append(f"gen_real_fn gen_real_{n};")
            if n in OVERRIDES:
                im.append(f"unsigned int gen_imp_{n}();   /* the runtime's */")
                continue
            im.append(f"unsigned int gen_imp_{n}(int a0, int a1, int a2, int a3, int a4, int a5, int a6, int a7, "
                      f"int a8, int a9, int a10, int a11, int a12, int a13) {{ return (unsigned int)gen_real_{n}("
                      + ", ".join(f"(intptr_t)a{k}" for k in range(14)) + "); }")
        im.append("const GEN_IMPORT g_genImports[] = {")
        for n, (slot, dll) in sorted(self.imports.items()):
            im.append(f'  {{0x{slot:x}u, "{dll}", "{n}", (void *)gen_imp_{n}, &gen_real_{n}}},')
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
    r = subprocess.run([cl, "/nologo", "/c", "/O1", "/W1", "/TC", "/bigobj", "/std:c17",
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
    args = ap.parse_args()
    t = Translator32()
    only = {int(x, 16) for x in args.only} if args.only else None
    demoted = json.loads(DEMOTED.read_text()) if DEMOTED.exists() else {}
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
