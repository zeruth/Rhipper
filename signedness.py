"""Signed comparisons of Ghidra's sign-agnostic undefinedN values, shared by translate64.py and
translate32.py: both headers make the typedefs unsigned, and Ghidra prints a signed test of one
without a cast (`-1 < local_8`), which C then compiled as a constant (signed_tests).
"""
from __future__ import annotations

import bisect
import re

SIGNED_OF = {"1": "int8_t", "2": "int16_t", "4": "int32_t", "8": "int64_t"}
UNDEFINED_LOCAL = re.compile(r"^[ \t]*undefined([1248]) (\w+)(?: = \{0\})?;", re.M)
# a test only a signed comparison is written as: Ghidra prints a negative literal for INT_SLESS and
# friends, and an unsigned one in hex (`-1 < DAT_x` is "DAT_x >= 0"; `x < 0` is never unsigned).
# The literal is a whole side of the comparison: `-1 < x`, `x < -5`, `x < 0`, `0 > x`
SIGNED_LITERAL_LEFT = re.compile(r"(-\d+|(?<![\w.])0(?![x\d.]))\s*(<=?|>=?)(?![<>=])")
SIGNED_LITERAL_RIGHT = re.compile(r"(?<![<>])(<=?|>=?)\s*(-\d+|0(?![x\d.]))\b(?!\s*[\w(.\[*/%+-])")


def operand_end(s: str, i: int) -> int:
    """Where the operand of a relational operator that starts at s[i] ends: the first token at its
    own nesting level that binds looser than `<` (comparison, equality, bitwise, logical,
    conditional, assignment, comma, statement end) or a closing bracket it did not open."""
    depth = 0
    j = i
    while j < len(s):
        c = s[j]
        if c in "([":
            depth += 1
        elif c in ")]":
            if depth == 0:
                return j
            depth -= 1
        elif depth == 0:
            if c in ",;?:{}":
                return j
            if c in "<>":
                if s[j:j + 2] in ("<<", ">>"):
                    j += 2
                    continue
                if c == ">" and j > 0 and s[j - 1] == "-":
                    j += 1
                    continue
                return j
            if c == "=" or (c == "!" and s[j + 1:j + 2] == "="):
                return j
            if c in "&|^":
                k = j - 1
                while k >= i and s[k] in " \t\n":
                    k -= 1
                if k >= i and (s[k].isalnum() or s[k] in "_)]"):
                    return j
        j += 1
    return j


def operand_start(s: str, i: int) -> int:
    """The same backwards: where the operand that ends just before s[i] begins."""
    depth = 0
    j = i - 1
    while j >= 0:
        c = s[j]
        if c in ")]":
            depth += 1
        elif c in "([":
            if depth == 0:
                return j + 1
            depth -= 1
        elif depth == 0:
            if c in ",;?:{}":
                return j + 1
            if c in "<>":
                if j > 0 and s[j - 1] == c:
                    j -= 2
                    continue
                if c == ">" and j > 0 and s[j - 1] == "-":
                    j -= 2
                    continue
                return j + 1
            if c == "=":
                return j + 1
            if c in "&|^":
                if j > 0 and s[j - 1] == c and c != "^":
                    return j + 1
                k = j - 1
                while k >= 0 and s[k] in " \t\n":
                    k -= 1
                if k >= 0 and (s[k].isalnum() or s[k] in "_)]"):
                    return j + 1
        j -= 1
    return 0


def signed_sides(body: str) -> list[tuple[int, int]]:
    """The spans of the expressions a signed comparison compares with a literal (SIGNED_LITERAL_*)."""
    spans = []
    for m in SIGNED_LITERAL_LEFT.finditer(body):
        k = m.start() - 1
        while k >= 0 and body[k] in " \t\n":
            k -= 1
        # (the literal is the whole left side, not the end of `x + -5 < y`)
        if k >= 0 and (body[k].isalnum() or body[k] in "_)]"):
            continue
        if m.group(1) == "0" and m.group(2) not in (">", "<="):
            continue
        spans.append((m.end(), operand_end(body, m.end())))
    for m in SIGNED_LITERAL_RIGHT.finditer(body):
        if m.group(2) == "0" and m.group(1) not in ("<", ">="):
            continue
        spans.append((operand_start(body, m.start()), m.start()))
    return spans


def signed_tests(body: str, params=()) -> str:
    """An undefinedN value in a signed comparison, read as the signed type of its width.

    Ghidra's `undefined4` is sign-agnostic, so it prints a signed test of one without a cast:
    `if (-1 < DAT_142d23a20)`. Ghidra64.h has to give the typedef a signedness, and it is unsigned,
    which made each such test a constant: `-1 < (unsigned)x` is never true and `x < 0` never is
    either, so the compiler deleted what they guarded. 411 functions had one (2026-10-22): among
    them FUN_14192eec0, next to the frame end, compiled to `return 0` from 253 bytes, and the
    fidelity report's 0.0 translations were mostly this. The operand is a global
    (`REFG(undefinedN, a)`), a load (`*(undefinedN *)p`, possibly parenthesized) or an undefinedN
    local; it is retyped there and nowhere else. The `_Init_thread_epoch` guards are one case."""
    und_locals = {v: n for n, v in UNDEFINED_LOCAL.findall(body)}
    for p in params:
        pm = re.fullmatch(r"\s*undefined([1248])\s+(\w+)\s*", p)
        if pm:
            und_locals[pm.group(2)] = pm.group(1)

    def close(s: str, i: int) -> int:
        """The index past the parenthesized group starting at s[i] == '('."""
        depth = 0
        for j in range(i, len(s)):
            if s[j] == "(":
                depth += 1
            elif s[j] == ")":
                depth -= 1
                if depth == 0:
                    return j + 1
        return -1

    operand = re.compile(r"REFG\(undefined([1248]), (0x[0-9a-f]+)\)|\*\(undefined([1248]) \*\)"
                         + (r"|(?<![\w.&])(?<!->)(" + "|".join(map(re.escape, und_locals)) + r")\b(?!\s*(?:[\[.(]|->|=[^=]))"
                            if und_locals else ""))
    # (anywhere in a side of a signed comparison: `-1 < (param_1 - *(undefined4 *)g) + -300000`,
    # FUN_14192ebc0's idle timer, is signed arithmetic that one unsigned term made unsigned)
    spans = sorted(signed_sides(body))
    starts = [lo for lo, _ in spans]

    def in_signed_side(lo: int, hi: int) -> bool:
        k = bisect.bisect_right(starts, lo) - 1
        while k >= 0:
            if spans[k][0] <= lo and hi <= spans[k][1]:
                return True
            k -= 1
            if k >= 0 and lo - spans[k][0] > 4000:
                break
        return False

    out, at = [], 0
    for m in operand.finditer(body):
        if m.start() < at:
            continue
        start, end = m.start(), m.end()
        if m.group(1):
            width, new = m.group(1), f"REFG({SIGNED_OF[m.group(1)]}, {m.group(2)})"
        elif m.group(3):
            width = m.group(3)
            if end < len(body) and body[end] == "(":
                end = close(body, end)
            else:
                ident = re.match(r"\w+", body[end:])
                end = end + ident.end() if ident else -1
            if end < 0:
                continue
            new = f"*({SIGNED_OF[width]} *)" + body[m.end():end]
        else:
            width = und_locals[m.group(4)]
            new = f"(({SIGNED_OF[width]}){m.group(4)})"
        # (wrapped in its own parentheses, the test is on the group: `-1 < (*(undefined4 *)p)`)
        lo, hi = start, end
        while lo > 0 and body[lo - 1] == "(" and hi < len(body) and body[hi] == ")" and close(body, lo - 1) == hi + 1:
            lo, hi = lo - 1, hi + 1
        if not in_signed_side(lo, hi):
            continue
        # (its address, `&REFG(undefined1, a) + i`, is no value read)
        k = lo - 1
        while k >= 0 and body[k] in " \t\n":
            k -= 1
        if k >= 0 and body[k] == "&":
            k2 = k - 1
            while k2 >= 0 and body[k2] in " \t\n":
                k2 -= 1
            cast = re.search(r"\((?:unsigned |signed )?\w+(?: \*+)?\)$", body[max(0, k2 - 40):k2 + 1])
            if cast or not (k2 >= 0 and (body[k2].isalnum() or body[k2] in "_)]")):
                continue
        # (under a cast, `(int)uVar4 < 0`, the test is on the cast's type: already signed)
        if re.search(r"\((?:unsigned |signed )?\w+(?: \*+)?\)\s*$", body[max(0, lo - 40):lo]):
            continue
        out.append(body[at:start])
        out.append(new)
        at = end
    out.append(body[at:])
    return "".join(out)


# the signed types Ghidra prints (and their widths), for a sibling operand that says an op is signed
SIGNED_TYPES = {"char": "1", "short": "2", "int": "4", "long": "4", "longlong": "8", "int8_t": "1",
                "int16_t": "2", "int32_t": "4", "int64_t": "8", "sbyte": "1", "int1": "1", "int2": "2",
                "int4": "4", "int8": "8"}
SIGN_OPS = re.compile(r" (/|%|>>|<=|>=|<|>) ")
SIGNED_CAST = re.compile(r"\((" + "|".join(SIGNED_TYPES) + r")\)")
DECL = re.compile(r"^[ \t]*(\w+) (\w+)(?: = [^;]*)?;", re.M)


def signed_siblings(body: str, params=()) -> str:
    """An undefinedN variable an op reads beside a signed operand, read as the signed type of its
    width. Ghidra casts whichever operand's type the op does not take; an undefined one takes any,
    so the other side's type is the op's: `uStack_1c / (longlong)CONCAT44(b, a)` is a signed
    divide (MSVC's __alldiv, through Ghidra's call fixup), and in C an unsigned long long beside a
    long long makes it unsigned (rhtest int64's divmod64, 2026-10-24). Read by the ops whose sign
    matters: / % >> and the comparisons; the variable as a whole operand, the sibling a signed
    cast or a variable declared signed."""
    decls = [m.groups() for m in DECL.finditer(body)] + [tuple(p.split()) for p in params if len(p.split()) == 2]
    und = {n: t[len("undefined"):] for t, n in decls if re.fullmatch(r"undefined[1248]", t)}
    signed = {n for t, n in decls if t in SIGNED_TYPES}
    if not und:
        return body
    alt = "|".join(map(re.escape, und))
    # (a whole operand: not a member, an element or a call, nor under a cast already)
    left_var = re.compile(r"(?<![\w.>)\]])(?<!\)\s)(" + alt + r")$")
    right_var = re.compile(r"^(" + alt + r")(?![\w\[(.]|->)")

    def signed_left(text: str) -> bool:
        """Whether the operand ending text is signed: a signed variable, or a signed cast's operand."""
        t = text.rstrip()
        m = re.search(r"(?<![\w.>])(\w+)$", t)
        if m and m.group(1) in signed and not re.search(r"\)\s*$", t[:m.start()]):
            return True
        if t.endswith(")"):
            depth, k = 0, len(t) - 1
            while k >= 0:
                depth += t[k] == ")"
                depth -= t[k] == "("
                if depth == 0:
                    break
                k -= 1
            head = re.search(r"(\w*)$", t[:k]).group(1)
            before = t[:k - len(head)]
            return bool(re.search(SIGNED_CAST.pattern + r"\s*$", before))
        return False

    def signed_right(text: str) -> bool:
        m = re.match(r"(\w+)(?![\w\[(.]|->)", text)
        return bool(SIGNED_CAST.match(text) or (m and m.group(1) in signed))

    edits = []                                     # (start, end, replacement)
    for m in SIGN_OPS.finditer(body):
        op = m.group(1)
        before, after = body[:m.start()], body[m.end():]
        lv = left_var.search(before)
        if lv and signed_right(after) and not re.search(r"[*/%]\s*$", before[:lv.start()]):
            edits.append((lv.start(), lv.end(), f"(({SIGNED_OF[und[lv.group(1)]]}){lv.group(1)})"))
        rv = right_var.match(after) if op != ">>" else None
        if rv and signed_left(before):
            s = m.end()
            edits.append((s, s + rv.end(), f"(({SIGNED_OF[und[rv.group(1)]]}){rv.group(1)})"))
    for s, e, rep in sorted(set(edits), reverse=True):
        body = body[:s] + rep + body[e:]
    return body
