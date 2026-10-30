"""Ghidra's vector values as C (Ghidra32.h's gen_v helpers): the AVX2 and SSE4.2 code of the static C
runtime's and C++ library's string and search routines, behind __isa_available (rhtest stl /MT).

The decompiler prints a vector as a byte array local (`undefined1 auVar9 [32];`) or a pointer to one
(`gen_v32 *pauVar4` once v16_forms has the casts), and its operations as calls C has none of:
pseudo-ops (`auVar2 = vpcmpeqb_avx2(auVar9,*pauVar4);`), pieces (`SUB321(auVar2 >> 0x97,0)`,
`ZEXT1664((undefined1 [16])0x0)`, `auVar9._16_16_ = auVar8;`) and integer operators on whole
vectors (`(auVar3 & auVar4) == (undefined1 [16])0x0`). Each statement holding one is parsed, its
vector parts written as calls on their bytes (a temporary before the statement where one is
computed), the rest of it left as it was, text for text.

    vec_forms(c) -> c
"""
import re

# the pseudo-ops: Ghidra32.h's helper, the result's width (None: the destination's) and the
# operands, v a vector's address and i an integer (the x86 sinc files' argument order)
OPS = {
    "vpcmpeqb_avx2": ("gen_vpcmpeqb", 32, "vv"), "vpcmpeqb_avx": ("gen_vpcmpeqb", 16, "vv"),
    "vpcmpeqw_avx2": ("gen_vpcmpeqw", 32, "vv"), "vpcmpeqw_avx": ("gen_vpcmpeqw", 16, "vv"),
    "vpcmpeqd_avx2": ("gen_vpcmpeqd", 32, "vv"), "vpcmpeqd_avx": ("gen_vpcmpeqd", 16, "vv"),
    "vpcmpgtd_avx2": ("gen_vpcmpgtd", 32, "vv"),
    "vpminsd_avx2": ("gen_vpminsd", 32, "vv"), "vpmaxsd_avx2": ("gen_vpmaxsd", 32, "vv"),
    "vpminud_avx2": ("gen_vpminud", 32, "vv"), "vpsubd_avx2": ("gen_vpsubd", 32, "vv"),
    "vpand_avx2": ("gen_vpand", 32, "vv"), "vpand_avx": ("gen_vpand", 16, "vv"),
    "vpblendvb_avx2": ("gen_vpblendvb", 32, "vvv"), "pblendvb": ("gen_vpblendvb", 16, "vvv"),
    "vpshufb_avx2": ("gen_vpshufb", 32, "vv"), "vpshufb_avx": ("gen_vpshufb", 16, "vv"),
    "pshufb": ("gen_vpshufb", 16, "vv"),
    "vpshufd_avx2": ("gen_vpshufd", 32, "vi"), "vpermq_avx2": ("gen_vpermq", 32, "vi"),
    "vpermd_avx2": ("gen_vpermd", 32, "vv"),
    "vpmaskmovd_avx2": ("gen_vpmaskmovd", None, "vv"),
    "pshuflw": ("gen_pshuflw", 16, "vvi"), "roundsd": ("gen_roundsd", 16, "vvi"),
}
# (and the ones with an integer result, anywhere in an expression)
INT_OPS = {"pcmpestri": "vviii", "pcmpestri_flags": "vviii", "pcmpistri": "vvi", "pcmpistri_flags": "vvi"}

TRIGGER = re.compile(r"\b(?:ZEXT\d+|SUB\d+|CONCAT\d+|" + "|".join(map(re.escape, sorted(OPS) + sorted(INT_OPS)))
                     + r")\s*\(|\._\d+_(?:1[6-9]|[2-6]\d)_|\(\s*undefined1\s*\[|\b(?:pcmp[ei]stri_flags)\b")

TOKEN = re.compile(r"""\s*(?:
    (?P<num>0x[0-9a-fA-F]+[uUlL]*|\d+\.\d*(?:[eE][-+]?\d+)?[fFlL]?|\d+[uUlL]*)
  | (?P<id>[A-Za-z_]\w*)
  | (?P<chr>'(?:\\.|[^'\\])*')
  | (?P<str>"(?:\\.|[^"\\])*")
  | (?P<op>->|\+\+|--|<<=|>>=|<<|>>|<=|>=|==|!=|&&|\|\||[-+*/%&|^]=|[-+*/%&|^~!<>=?:,.()\[\]])
)""", re.X)

TYPE_WORDS = {"void", "char", "short", "int", "long", "float", "double", "bool", "unsigned", "signed", "const",
              "volatile", "struct", "uint", "uchar", "ushort", "ulong", "byte", "sbyte", "word", "dword",
              "qword", "longlong", "ulonglong", "code", "pointer", "wchar_t", "wchar16", "float10", "PTR32"}
TYPE_RE = re.compile(r"undefined\d*|u?int\d+(?:_t)?|gen_\w+|float\d+|[A-Z][A-Z0-9_]*")

PREC = {"*": 10, "/": 10, "%": 10, "+": 9, "-": 9, "<<": 8, ">>": 8, "<": 7, "<=": 7, ">": 7, ">=": 7,
        "==": 6, "!=": 6, "&": 5, "^": 4, "|": 3, "&&": 2, "||": 1}
ASSIGN = {"=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>="}


class Fail(Exception):
    pass


class Node:
    def __init__(self, k, s, e, **kw):
        self.k, self.s, self.e = k, s, e
        self.__dict__.update(kw)


class Parser:
    def __init__(self, text: str):
        self.text = text
        self.toks = []
        pos = 0
        while pos < len(text):
            m = TOKEN.match(text, pos)
            if not m or m.end() == pos:
                if text[pos:].strip() == "":
                    break
                raise Fail(f"token at {text[pos:pos + 20]!r}")
            kind = m.lastgroup
            self.toks.append((kind, m.group(kind), m.start(kind), m.end(kind)))
            pos = m.end()
        self.i = 0

    def peek(self, k=0):
        j = self.i + k
        return self.toks[j] if j < len(self.toks) else (None, None, len(self.text), len(self.text))

    def take(self, v=None):
        t = self.peek()
        if v is not None and t[1] != v:
            raise Fail(f"expected {v!r}, got {t[1]!r}")
        self.i += 1
        return t

    def expr(self):                                  # (the comma operator)
        first = self.assign()
        items = [first]
        while self.peek()[1] == ",":
            self.take()
            items.append(self.assign())
        if len(items) == 1:
            return first
        return Node("comma", first.s, items[-1].e, items=items)

    def assign(self):
        left = self.cond()
        t = self.peek()
        if t[1] in ASSIGN:
            self.take()
            right = self.assign()
            return Node("assign", left.s, right.e, op=t[1], l=left, r=right)
        return left

    def cond(self):
        c = self.binary(1)
        if self.peek()[1] == "?":
            self.take()
            a = self.expr()
            self.take(":")
            b = self.cond()
            return Node("cond", c.s, b.e, c=c, a=a, b=b)
        return c

    def binary(self, level):
        left = self.unary()
        while True:
            t = self.peek()
            p = PREC.get(t[1]) if t[0] == "op" else None
            if p is None or p < level:
                return left
            self.take()
            right = self.binary(p + 1)
            left = Node("bin", left.s, right.e, op=t[1], l=left, r=right)

    def cast_type(self):
        """the type of a cast at `(`, as (text, end token index), or None"""
        j, depth, words = self.i + 1, 0, []
        while j < len(self.toks):
            kind, v = self.toks[j][0], self.toks[j][1]
            if v == "(":
                depth += 1
            elif v == ")":
                if depth == 0:
                    break
                depth -= 1
            elif kind == "id":
                words.append(v)
            elif v not in ("*", "[", "]") and kind != "num":
                return None
            j += 1
        if j >= len(self.toks) or not words:
            return None
        inner = self.text[self.toks[self.i][3]:self.toks[j][2]]
        first = words[0] if words[0] not in ("const", "volatile", "struct", "unsigned", "signed") else \
            (words[1] if len(words) > 1 else words[0])
        if not (first in TYPE_WORDS or TYPE_RE.fullmatch(first) or "*" in inner):
            return None
        # (a parenthesized product is no cast: `(a * b)` has two names)
        if len([w for w in words if w not in TYPE_WORDS and w != "PTR32"]) > 1:
            return None
        # (and a cast is followed by an operand)
        nxt = self.toks[j + 1] if j + 1 < len(self.toks) else (None, None, 0, 0)
        if nxt[0] is None or (nxt[0] == "op" and nxt[1] not in ("(", "*", "&", "-", "~", "!")):
            return None
        return inner.strip(), j

    def unary(self):
        t = self.peek()
        if t[1] == "(":
            ct = self.cast_type()
            if ct is not None:
                s = t[2]
                self.i = ct[1] + 1
                x = self.unary()
                return Node("cast", s, x.e, type=ct[0], x=x)
        if t[0] == "op" and t[1] in ("-", "+", "!", "~", "*", "&", "++", "--"):
            self.take()
            x = self.unary()
            return Node("unary", t[2], x.e, op=t[1], x=x)
        if t[0] == "id" and t[1] == "sizeof":
            self.take()
            x = self.unary()
            return Node("sizeof", t[2], x.e, x=x)
        return self.postfix(self.primary())

    def primary(self):
        t = self.take()
        if t[0] in ("num", "chr", "str", "id"):
            return Node(t[0], t[2], t[3], v=t[1])
        if t[1] == "(":
            x = self.expr()
            r = self.take(")")
            return Node("paren", t[2], r[3], x=x)
        raise Fail(f"unexpected {t[1]!r}")

    def postfix(self, x):
        while True:
            t = self.peek()
            if t[1] == "(":
                self.take()
                args = []
                if self.peek()[1] != ")":
                    args.append(self.assign())
                    while self.peek()[1] == ",":
                        self.take()
                        args.append(self.assign())
                r = self.take(")")
                x = Node("call", x.s, r[3], f=x, args=args)
            elif t[1] == "[":
                self.take()
                i = self.expr()
                r = self.take("]")
                x = Node("index", x.s, r[3], b=x, i=i)
            elif t[1] in (".", "->"):
                self.take()
                n = self.take()
                x = Node("member", x.s, n[3], b=x, name=n[1], arrow=t[1] == "->")
            elif t[1] in ("++", "--"):
                self.take()
                x = Node("post", x.s, t[3], op=t[1], x=x)
            else:
                return x


def parse(text: str) -> Node:
    p = Parser(text)
    n = p.expr()
    if p.i != len(p.toks):
        raise Fail(f"left over at {p.peek()[1]!r}")
    return n


def const_value(n: Node):
    while n.k == "paren":
        n = n.x
    if n.k == "num" and not re.search(r"[.eE]", n.v) or (n.k == "num" and n.v.startswith("0x")):
        return int(re.sub(r"[uUlL]+$", "", n.v), 0)
    if n.k == "cast":
        return const_value(n.x)
    return None


class Writer:
    """One statement's vector parts written as C: arrays and ptrs the function's vectors (name ->
    bytes), pre the statements its temporaries take"""

    def __init__(self, text: str, arrays: dict, ptrs: dict, temps: list):
        self.text, self.arrays, self.ptrs, self.temps = text, arrays, ptrs, temps
        self.pre: list[str] = []

    def src(self, n: Node) -> str:
        return self.text[n.s:n.e]

    def temp(self) -> str:
        t = f"gen_vx{self.temps[0]}"
        self.temps[0] += 1
        self.pre.append(f"unsigned char {t}[64];")
        return t

    # ---- a vector's width, or None ----
    def width(self, n: Node):
        k = n.k
        if k == "paren":
            return self.width(n.x)
        if k == "id":
            return self.arrays.get(n.v)
        if k == "unary" and n.op == "*":
            x = n.x
            while x.k == "paren":
                x = x.x
            if x.k == "id":
                return self.ptrs.get(x.v)
            if x.k == "cast":
                m = re.fullmatch(r"gen_v(\d+)\s*\*", x.type)
                return int(m.group(1)) if m else None
            return None
        if k == "index":
            b = n.b
            while b.k == "paren":
                b = b.x
            return self.ptrs.get(b.v) if b.k == "id" else None
        if k == "member":
            m = re.fullmatch(r"_(\d+)_(\d+)_", n.name)
            if m and int(m.group(2)) > 8 and not n.arrow and self.width(n.b):
                return int(m.group(2))
            return None
        if k == "cast":
            m = re.fullmatch(r"undefined1\s*\[\s*(\d+)\s*\]", n.type)
            return int(m.group(1)) if m else None
        if k == "call" and n.f.k == "id":
            f = n.f.v
            m = re.fullmatch(r"ZEXT(\d+)(\d\d)", f) or re.fullmatch(r"ZEXT(\d)(\d+)", f)
            if m and int(m.group(2)) > 8:
                return int(m.group(2))
            m = re.fullmatch(r"SUB(\d\d)(\d+)", f)
            if m and int(m.group(2)) > 8:
                return int(m.group(2))
            if re.fullmatch(r"CONCAT\d+", f):
                a, b = self.concat_sizes(f)
                if a is not None and a + b > 8:
                    return a + b
            if f in OPS:
                return OPS[f][1] or 32
            return None
        if k == "bin" and n.op in ("&", "|", "^"):
            wl, wr = self.width(n.l), self.width(n.r)
            if (wl or wr) and (wl or self.is_zero(n.l)) and (wr or self.is_zero(n.r)):
                return wl or wr
            return None
        if k == "bin" and n.op in (">>", "<<"):
            return self.width(n.l)
        if k == "unary" and n.op == "~":
            return self.width(n.x)
        return None

    def concat_sizes(self, f: str):
        """CONCAT's two sizes: `CONCAT1616` 16 and 16, `CONCAT412` 4 and 12 (the plausible split)"""
        d = f[6:]
        for k in range(1, len(d)):
            a, b = int(d[:k]), int(d[k:])
            if a in (1, 2, 3, 4, 5, 6, 7, 8, 12, 14, 15, 16, 24, 28, 32) and b in (1, 2, 3, 4, 5, 6, 7, 8, 12, 14, 15, 16, 24, 28, 32) \
                    and not d[k:].startswith("0"):
                return a, b
        return None, None

    def is_zero(self, n: Node) -> bool:
        while n.k == "paren":
            n = n.x
        if n.k == "cast" and re.fullmatch(r"undefined1\s*\[\s*\d+\s*\]", n.type):
            return const_value(n.x) == 0
        if n.k == "call" and n.f.k == "id" and re.fullmatch(r"(?:ZEXT|SUB)\d+", n.f.v) and n.args:
            return self.is_zero(n.args[0]) or const_value(n.args[0]) == 0
        return const_value(n) == 0 and n.k == "num"

    # ---- a vector's bytes: an expression C takes for a `const void *` ----
    def ptr(self, n: Node) -> str:
        while n.k == "paren":
            n = n.x
        if self.is_zero(n):
            return "gen_vzero"
        w = self.width(n)
        k = n.k
        if k == "id" and w:
            return n.v
        if k in ("unary", "index") and w:
            return f"({self.src(n)})"
        if k == "member" and w:
            a = int(re.fullmatch(r"_(\d+)_(\d+)_", n.name).group(1))
            return f"((unsigned char *)({self.ptr(n.b)}) + {a})"
        if k == "cast" and w:
            t = self.temp()
            self.pre.append(f"gen_vzext({t}, (unsigned long long)({self.scalar(n.x)}), 8);")
            return t
        if k == "call" and n.f.k == "id":
            f, args = n.f.v, n.args
            m = re.fullmatch(r"ZEXT(\d+)(\d\d)", f) or re.fullmatch(r"ZEXT(\d)(\d+)", f)
            if m and int(m.group(2)) > 8:
                src_w = int(m.group(1))
                t = self.temp()
                if self.width(args[0]):
                    self.pre.append(f"gen_vset({t}, 64, {self.ptr(args[0])}, {src_w});")
                else:
                    self.pre.append(f"gen_vzext({t}, (unsigned long long)({self.scalar(args[0])}), {src_w});")
                return t
            m = re.fullmatch(r"SUB(\d\d)(\d+)", f)
            if m and int(m.group(2)) > 8:
                j = const_value(args[1])
                if j is None:
                    raise Fail("a piece at no constant")
                return f"((unsigned char *)({self.ptr(args[0])}) + {j})"
            if f.startswith("CONCAT"):
                a, b = self.concat_sizes(f)
                t = self.temp()
                hi = self.ptr(args[0]) if self.width(args[0]) else self.boxed(args[0])
                lo = self.ptr(args[1]) if self.width(args[1]) else self.boxed(args[1])
                self.pre.append(f"gen_vcat({t}, {hi}, {a}, {lo}, {b});")
                return t
            if f in OPS:
                t = self.temp()
                self.pre.append(self.op_call(f, args, t, OPS[f][1] or 32) + ";")
                return t
        if k == "bin" and n.op in ("&", "|", "^") and w:
            pa, pb = self.ptr(n.l), self.ptr(n.r)
            t = self.temp()
            self.pre.append(f"gen_vbin({t}, {pa}, {pb}, {w}, '{n.op}');")
            return t
        if k == "bin" and n.op in (">>", "<<") and w:
            kk = self.scalar(n.r)
            pa = self.ptr(n.l)
            t = self.temp()
            self.pre.append(f"gen_vshift({t}, {pa}, {w}, (int)({kk}), {1 if n.op == '>>' else 0});")
            return t
        if k == "unary" and n.op == "~" and w:
            pa = self.ptr(n.x)
            t = self.temp()
            self.pre.append(f"gen_vnot({t}, {pa}, {w});")
            return t
        raise Fail(f"no vector: {self.src(n)[:60]}")

    def boxed(self, n: Node) -> str:
        """a scalar's bytes"""
        return f"(&(unsigned long long){{(unsigned long long)({self.scalar(n)})}})"

    def op_call(self, f: str, args, dst: str, width: int) -> str:
        helper, _w, kinds = OPS[f]
        if len(args) != len(kinds):
            raise Fail(f"{f} with {len(args)} operands")
        out = [dst]
        for a, kd in zip(args, kinds):
            out.append(self.ptr(a) if kd == "v" else f"(int)({self.scalar(a)})")
        return f"{helper}({', '.join(out)}, {width})"

    # ---- a scalar expression, its vector parts rewritten ----
    def scalar(self, n: Node) -> str:
        if not self.has_vector(n):
            return self.src(n)
        k = n.k
        if k == "call" and n.f.k == "id":
            f = n.f.v
            m = re.fullmatch(r"SUB(\d\d)(\d)", f)
            if m and int(m.group(2)) <= 8:
                x, j = n.args[0], const_value(n.args[1])
                nb = int(m.group(2))
                if j is None:
                    raise Fail("a piece at no constant")
                bit = 8 * j
                while x.k == "paren":
                    x = x.x
                if x.k == "bin" and x.op == ">>" and self.width(x.l) and const_value(x.r) is not None:
                    bit += const_value(x.r)
                    x = x.l
                w = self.width(x)
                if w:
                    t = {1: "unsigned char", 2: "unsigned short", 4: "unsigned int"}.get(nb, "unsigned long long")
                    return f"(({t})gen_vbits({self.ptr(x)}, {w}, {bit}, {nb}))"
            if f in INT_OPS:
                kinds = INT_OPS[f]
                if len(n.args) != len(kinds):
                    raise Fail(f"{f} with {len(n.args)} operands")
                out = [self.ptr(a) if kd == "v" else f"(int)({self.scalar(a)})" for a, kd in zip(n.args, kinds)]
                return f"gen_{f}({', '.join(out)})"
        if k == "bin" and n.op in ("==", "!=") and (self.width(n.l) or self.width(n.r)):
            w = self.width(n.l) or self.width(n.r)
            pa, pb = self.ptr(n.l), self.ptr(n.r)
            return f"({'!' if n.op == '==' else ''}gen_vcmp({pa}, {pb}, {w}))"
        if k == "assign" and self.width(n.l):
            return self.vassign(n)
        if k == "member" and self.width(n.b) and not self.width(n):
            # (a scalar piece of a vector, `auVar1._8_4_`: its bytes)
            m = re.fullmatch(r"_(\d+)_(\d+)_", n.name)
            if m:
                a, b = int(m.group(1)), int(m.group(2))
                t = {1: "unsigned char", 2: "unsigned short", 4: "unsigned int"}.get(b, "unsigned long long")
                return f"(*({t} *)((unsigned char *)({self.ptr(n.b)}) + {a}))"
        # (anything else: its children rewritten, its own text kept between them)
        return self.rebuild(n)

    def vassign(self, n: Node) -> str:
        dst, wd = self.ptr(n.l), self.width(n.l)
        if n.op != "=":
            raise Fail(f"a vector {n.op}")
        r = n.r
        while r.k == "paren":
            r = r.x
        if r.k == "call" and r.f.k == "id" and r.f.v in OPS:
            return self.op_call(r.f.v, r.args, dst, OPS[r.f.v][1] or wd)
        wr = self.width(r)
        if not wr and not self.is_zero(r):
            # (a scalar into a vector: its low bytes, `auVar6._0_8_ = x` is a piece and no vector)
            return f"gen_vset({dst}, {wd}, {self.boxed(r)}, 8)"
        return f"gen_vset({dst}, {wd}, {self.ptr(r)}, {wr or wd})"

    def has_vector(self, n: Node) -> bool:
        if self.width(n):
            return True
        if n.k == "call" and n.f.k == "id" and n.f.v in INT_OPS:
            return True
        for c in self.children(n):
            if self.has_vector(c):
                return True
        return False

    @staticmethod
    def children(n: Node):
        k = n.k
        if k in ("paren", "cast", "unary", "sizeof", "post"):
            return [n.x]
        if k in ("bin", "assign"):
            return [n.l, n.r]
        if k == "cond":
            return [n.c, n.a, n.b]
        if k == "comma":
            return n.items
        if k == "call":
            return [n.f] + n.args
        if k == "index":
            return [n.b, n.i]
        if k == "member":
            return [n.b]
        return []

    def rebuild(self, n: Node) -> str:
        """n's text with each child that holds a vector rewritten"""
        kids = sorted(self.children(n), key=lambda c: c.s)
        out, at = [], n.s
        for c in kids:
            out.append(self.text[at:c.s])
            out.append(self.scalar(c) if self.has_vector(c) else self.src(c))
            at = c.e
        out.append(self.text[at:n.e])
        return "".join(out)


DECL_ARRAY = re.compile(r"(?m)^[ \t]+(?:undefined1|unsigned char)\s+([A-Za-z_]\w*)\s*\[\s*(\d+)\s*\]\s*;")
DECL_PTR = re.compile(r"\bgen_v(\d+)\s*\*\s*(?:PTR32\s+)?([A-Za-z_]\w*)\s*[;,)]")
# (a statement's expression: the forms Ghidra writes a line in)
FORMS = [re.compile(p, re.S) for p in (
    r"(?P<a>[ \t]*(?:\}\s*)?(?:else\s+)?if\s*\()(?P<e>.*)(?P<b>\)\s*(?:\{|goto\s+\w+\s*;|return\b.*;|break\s*;|continue\s*;)?[ \t]*)$",
    r"(?P<a>[ \t]*(?:\}\s*)?while\s*\()(?P<e>.*)(?P<b>\)\s*(?:\{|;)?[ \t]*)$",
    r"(?P<a>[ \t]*return\s+)(?P<e>.*)(?P<b>;[ \t]*)$",
    r"(?P<a>[ \t]*)(?P<e>[^\s{}].*)(?P<b>;[ \t]*)$",
)]


def vec_forms(c: str) -> str:
    if not TRIGGER.search(c):
        return c
    arrays = {m.group(1): int(m.group(2)) for m in DECL_ARRAY.finditer(c) if int(m.group(2)) >= 12}
    ptrs = {m.group(2): int(m.group(1)) for m in DECL_PTR.finditer(c)}
    if not arrays and not ptrs and "pcmp" not in c:
        return c
    lines = c.split("\n")
    # (a statement wrapped onto the next lines, as Ghidra breaks a long one: its lines, each
    # unfinished one, not ending a statement or opening or closing a block, with the next)
    groups: list[list[str]] = []
    for line in lines:
        prev = groups[-1][-1].rstrip() if groups else ""
        sofar = "".join(groups[-1]) if groups else ""
        if groups and ((prev.strip() and not re.search(r"[;{}:]$", prev) and not prev.lstrip().startswith(("#", "/"))
                        and not re.fullmatch(r"\s*(?:else|do)", prev))
                       or sofar.count("(") > sofar.count(")")):
            groups[-1].append(line)
        else:
            groups.append([line])
    temps = [0]
    out = []
    # (and a statement naming one of its vectors, `auVar6 = auVar6 | auVar2;`: an operator on it)
    named = re.compile(r"\b(?:" + "|".join(map(re.escape, sorted(arrays) + sorted(ptrs))) + r")\b") \
        if arrays or ptrs else None
    for group in groups:
        line = group[0].rstrip() + "".join(" " + g.strip() for g in group[1:])
        hit = TRIGGER.search(line) or (named is not None and named.search(line) and re.search(r"[|^~]|[^&]&[^&]", line))
        new = rewrite(line, arrays, ptrs, temps) if hit else None
        out.extend(group if new is None else new)
    return "\n".join(out)


def rewrite(line: str, arrays: dict, ptrs: dict, temps: list) -> list[str] | None:
    """one statement's line with its vector parts written as C, the temporaries' statements first;
    None where it has none, or one this cannot write"""
    if re.match(r"\s*(?:undefined|unsigned|gen_v)\w*[\s*]", line) and "=" not in line:
        return None                                     # (a declaration)
    ind = re.match(r"[ \t]*", line).group(0)
    # (a for loop's header: each of its three parts, none needing a temporary)
    fm = re.match(r"(?P<a>[ \t]*for\s*\()(?P<e>.*)(?P<b>\)\s*\{?[ \t]*)$", line, re.S)
    if fm:
        parts, depth, cur = [], 0, ""
        for ch in fm.group("e"):
            if ch == ";" and depth == 0:
                parts.append(cur)
                cur = ""
                continue
            depth += ch in "([" and 1 or ch in ")]" and -1 or 0
            cur += ch
        parts.append(cur)
        if len(parts) != 3:
            return None
        done = []
        for p in parts:
            if not p.strip() or not TRIGGER.search(p):
                done.append(p)
                continue
            lead = re.match(r"\s*", p).group(0)
            try:
                n = parse(p)
                w = Writer(p.strip(), arrays, ptrs, temps)
                n = parse(p.strip())
                body = w.scalar(n) if w.has_vector(n) else p.strip()
            except Fail:
                return None
            if w.pre:
                return None
            done.append(lead + body)
        return [fm.group("a") + ";".join(done) + fm.group("b")]
    for k, form in enumerate(FORMS):
        m = form.match(line)
        if not m:
            continue
        e = m.group("e")
        try:
            n = parse(e)
        except Fail:
            continue
        w = Writer(e, arrays, ptrs, temps)
        try:
            if not w.has_vector(n):
                return None
            body = w.scalar(n)
        except Fail:
            return None
        if w.pre and k == 1:
            return None                                 # (a loop's condition runs each time)
        return [ind + p for p in w.pre] + [m.group("a") + body + m.group("b")]
    return None
