"""Bug-class probes for fidelity32.py: the classes the presence comparisons (calls, fields, consts)
and opcensus.py's conversions cannot see, each a check of the reference x86 against the port's x64
(or the translation's C) that found a real crash class on 2026-10-31.

Strong flags (fidelity32 scores them, part "probes"). Each was run over the whole port of 23:11
2026-10-31 and over the port of 02:22 the same day (before the fixes), and its hits read against
the assembly; the counts are those runs'.
  LOCK      the reference's locked read-modify-writes (a `lock` prefix, an xchg with memory, but
            not MemoryBarrier()'s xchg with a frame slot) where the port has none, or where the port
            calls gen_lock_enter (Ghidra32.h LOCK(), translate32 interlocked()'s fallback: a global
            lock that races with the real intrinsics) for one. 02:22: 86 functions; now 1 (0x4fd6e0).
  WRAP      an x64 address built from a zero-extended 32-bit index that can be negative (a sub of
            two values, neg, not, dec, movsx, sar, a negative constant), scaled, or added to a global's
            address; or a 64-bit immediate past 2^31 used as an address. x86 wraps the 32-bit sum
            and the port lands 4..16 GB away (pointer_index / pointer_addends / wide_subscripts).
            02:22: 5 functions, memmove's 0xc46aa0 / 0xc46e20 among them; now 0.
  WIDE      a global, addressed absolutely, that the port stores or loads wider than any reference
            access to it, past bytes the reference never accesses there (global_lvalue's 4-byte
            default for a byte). Fields are not checked: one displacement belongs to many pointers
            in a function, and 13 of 14 field hits were false. 02:22: 69 functions; now 0.
  THIS      a virtual call in the C, `((T *)*(gen_code32 *)GEN_TOP(*X + d))(args)`, passing one
            word fewer than every reference __thiscall site at vtable offset d (callsites.json: the
            words a site passes, ecx's `this` among them). HEAD's C (10-30): 255 functions; the C of
            11-01 00:52: 6, all real (0x520030's frees in a GAP; 0xb66530 and 4 like it, whose
            second `call edx` callsites.json has as __stdcall []).
  ARGS      such a call passing a number of words no reference site at d passes: a push the
            reference leaves on the stack for a later call, whose callee pops nothing, that
            Ghidra's C gives to the earlier call (TriggerBoxLayoutInstance::vf4: vf63 takes `this`
            only, and vf27 lost its second argument). The C of 10-31 22:26: 14 functions; of 00:52, 0.
  GAP       a jump of the function's, or a piece's fall-through, into code no function's pieces
            hold: the decompiler's C has that code, the facts (made per piece) never saw it, its
            indirect calls no callsites.json entry (0x520030). Now 20 functions, 9 of them the C
            runtime's x87 functions' jump to 0xc5ee4b.
  GUARD     a global table the reference loads on some paths only (under a switch's case or a
            range check: an exit is reachable from the entry past no load of it; x86 jump tables
            followed) that the port loads on every path, outside any loop (a loop's first pass a
            do-while the compiler proved). 02:22: 0xa051e0, the hoisted switch load; now 0.
  ZEROREG   the translation zero-initializes a register input (`in_EAX = 0;`) that the reference
            reads at entry with no write of any width before it (a lost register input, protos32
            keeps_in / kept_inputs). Now 1 function: ___report_gsfailure's register snapshot.
Weak flags (reported only):
  LOCK?     fewer locked operations in the port than the reference (the compiler merges one in two
            branches), or gen_lock_enter for MemoryBarrier()'s frame-slot xchg
  WRAP?     the WRAP index added at scale 1 to another 64-bit register (which is the pointer is
            unknown)
  SIGN      more signed forms (sar, idiv, jl/jg, movsx, setl, cmovl) in the port and fewer unsigned
            ones (shr, div, jb/ja, movzx, ...) than the reference, or the reverse for div and shift
            (cast.cc's hidden ZEXT). 538 functions; 0 of the 7 div and shift hits read were reachable
            bugs (idiv of values known non-negative, `(ulonglong)x % (ulonglong)(longlong)(int)y` of
            a ushort y); the jcc and ext hits were not triaged
  MERGE     a register variable of Ghidra's C assigned twice with no read and no control flow between
            them (merge.cc's speculative merge). The corpus of 10-25: 8 functions (the puddle's
            matrix multiplies); now 0. The 48 integer hits of the looser scan were all
            `v = a; if (c) break; v = b;`, a value live out of the break (3 of 3 read).
"""
from __future__ import annotations

import re
from collections import Counter

import capstone

WIDTH = {"byte": 1, "word": 2, "dword": 4, "qword": 8, "xmmword": 16, "ymmword": 32, "tbyte": 10}
MEM = re.compile(r"(byte|word|dword|qword|xmmword|ymmword|tbyte) ptr (?:\w+:)?\[([^\]]+)\]")
REG64 = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"}
R32_OF = {"rax": "eax", "rbx": "ebx", "rcx": "ecx", "rdx": "edx", "rsi": "esi", "rdi": "edi",
          **{f"r{k}": f"r{k}d" for k in range(8, 16)}}
R64_OF = {v: k for k, v in R32_OF.items()}
# (the family of each general register name)
FAM = {}
for _f, _ns in {"a": ("al", "ah", "ax", "eax", "rax"), "b": ("bl", "bh", "bx", "ebx", "rbx"),
                "c": ("cl", "ch", "cx", "ecx", "rcx"), "d": ("dl", "dh", "dx", "edx", "rdx"),
                "si": ("sil", "", "si", "esi", "rsi"), "di": ("dil", "", "di", "edi", "rdi"),
                "bp": ("bpl", "", "bp", "ebp", "rbp"), "sp": ("spl", "", "sp", "esp", "rsp")}.items():
    for _n in _ns:
        if _n:
            FAM[_n] = _f
for _k in range(8, 16):
    for _s in ("", "d", "w", "b"):
        FAM[f"r{_k}{_s}"] = f"r{_k}"
REG_TOKEN = re.compile(r"\b(" + "|".join(sorted(FAM, key=len, reverse=True)) + r")\b")

# instructions that write their first (memory) operand
WRITES = re.compile(r"^(?:lock )?(?:mov|movb|movw|movd|movq|movss|movsd|movaps|movups|movapd|movupd|movdqa|movdqu|"
                    r"movnt\w*|movlps|movhps|movlpd|movhpd|add|sub|and|or|xor|adc|sbb|inc|dec|neg|not|shl|shr|sar|sal|"
                    r"rol|ror|rcl|rcr|set\w+|xchg|cmpxchg|xadd|pop|fstp?|fistp?|fisttp|btr|bts|btc|shld|shrd|"
                    r"pextr\w|extractps|stmxcsr|fnstcw|fnstsw|fnsave|fsave|fnstenv)$")
STACK = {"esp", "ebp", "rsp", "rbp", "rip"}
STACK64 = {"rsp", "rip"}                     # (rbp is a general register in MSVC's x64 code)
JCC = re.compile(r"^j(?!mp)\w+$")
SIGNED = {"jl": "jcc", "jle": "jcc", "jg": "jcc", "jge": "jcc", "setl": "set", "setle": "set", "setg": "set",
          "setge": "set", "cmovl": "cmov", "cmovle": "cmov", "cmovg": "cmov", "cmovge": "cmov",
          "sar": "shift", "idiv": "div", "movsx": "ext"}
UNSIGNED = {"jb": "jcc", "jbe": "jcc", "ja": "jcc", "jae": "jcc", "setb": "set", "setbe": "set", "seta": "set",
            "setae": "set", "cmovb": "cmov", "cmovbe": "cmov", "cmova": "cmov", "cmovae": "cmov",
            "shr": "shift", "div": "div", "movzx": "ext"}
# (instructions MSVC's x64 code never has: data a procedure's range takes in, decoded)
JUNK = {"in", "out", "insb", "insd", "outsb", "outsd", "hlt", "int", "into", "les", "lds", "xlatb", "aaa", "aas", "daa",
        "das", "salc", "cli", "sti", "iretd", "retf", "(bad)", "enter", "loop", "loope", "loopne", "jrcxz", "bound",
        "arpl", "lcall", "ljmp"}
STRONG = ("LOCK", "WRAP", "WIDE", "THIS", "ARGS", "GUARD", "ZEROREG", "GAP")


def mem_of(ops: str):
    """(width, address text) of an operand string's memory operand, or None"""
    m = MEM.search(ops)
    return (WIDTH[m.group(1)], m.group(2).replace(" ", "")) if m else None


def addr_parts(a: str):
    """an address text's registers (with their scales) and displacement"""
    regs, disp = [], 0
    for term in re.findall(r"[+-]?[^+-]+", a):
        sign = -1 if term.startswith("-") else 1
        t = term.lstrip("+-")
        if "*" in t:
            r, s = t.split("*")
            regs.append((r, int(s)))
        elif t.startswith("0x") or t.isdigit():
            disp += sign * int(t, 0)
        else:
            regs.append((t, 1))
    return regs, disp


class Probes:
    """fidelity32's: the reference and port Images, the reference Binary, the corpus, the port's procs
    by address, each translation's port procedure (f_of_ref) and C (translations)."""

    def __init__(self, ref, port, refbin, cor: dict, proc_at: dict, f_of_ref: dict, translations: dict,
                 callsites: dict | None = None):
        self.ref, self.port, self.b, self.cor = ref, port, refbin, cor
        self.callsites = callsites or {}
        self.proc_at, self.f_of_ref, self.tr = proc_at, f_of_ref, translations
        self.md32 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.md64 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.pieces: dict[int, list] = {}
        for lo, hi, r in zip(refbin.piece_starts, refbin.piece_ends, refbin.piece_root):
            self.pieces.setdefault(r, []).append((lo, hi))
        self.lock_enter = {va for va, (_s, n) in proc_at.items() if n in ("gen_lock_enter", "gen_lock_enter_")}
        self.trace_enter = {va for va, (_s, n) in proc_at.items() if n == "gen_trace_enter"}
        self.data_lo = min(s.start for s in ref.sections)
        self.data_hi = max(s.end for s in ref.sections)

    # ---- instructions
    def ref_insns(self, a: int, ranges=None) -> list:
        out = []
        for lo, hi in sorted(ranges if ranges is not None else self.pieces.get(a, [])):
            out.extend(self.md32.disasm_lite(self.ref.read(lo, hi - lo), lo))
        return out

    def port_insns(self, a: int) -> list | None:
        va = self.f_of_ref.get(a)
        if va is None:
            return None
        return list(self.md64.disasm_lite(self.port.read(va, self.proc_at[va][0]), va))

    def in_image(self, v: int) -> bool:
        return self.data_lo <= v < self.data_hi

    # ---- LOCK
    @staticmethod
    def locks(insns, x64: bool = False) -> int:
        """the locked read-modify-writes, but (x86) an xchg with a frame slot: MSVC's MemoryBarrier(),
        `xchg [ebp - 4], eax`, or through a register a `lea r, [ebp - 8]` just made"""
        n = 0
        for k, (_a, _s, mn, ops) in enumerate(insns):
            if mn.startswith("lock "):
                n += 1
            elif mn == "xchg" and "ptr" in ops:
                if re.search(r"\[(?:esp|rsp)\b", ops) or (not x64 and re.search(r"\[ebp\b", ops)):
                    continue
                m = re.search(r"\[(\w+)\]", ops)
                if not x64 and m and any(insns[j][2] == "lea" and insns[j][3].startswith(m.group(1) + ", [e")
                                         and re.search(r"\[e[bs]p\b", insns[j][3]) for j in range(max(0, k - 4), k)):
                    continue
                n += 1
        return n

    def lock_probe(self, ri, pi, inl_ref) -> tuple[list, list]:
        r = self.locks(ri) + sum(self.locks(x) for x in inl_ref)
        p = self.locks(pi, True)
        fb = sum(1 for _a, _s, mn, ops in pi if mn in ("call", "jmp") and ops.startswith("0x")
                 and int(ops, 16) in self.lock_enter)
        strong, weak = [], []
        if fb and r > p:
            strong.append(f"LOCK fallback x{fb} (gen_lock_enter) for an atomic: ref {r} locked, port {p}")
        elif fb:
            weak.append(f"LOCK? barrier x{fb} by gen_lock_enter (MemoryBarrier's xchg with a frame slot)")
        elif p == 0 and self.locks(ri):
            strong.append(f"LOCK ref {r} locked, port none")
        elif p == 0 and r:
            # (only an inlined translation's, the inlined copy's path with it its constant arguments'
            # dead: F_0058f7a0's in 0x5929b0)
            weak.append(f"LOCK? ref {r} locked (inlined callees'), port none")
        elif p < r:
            # (the port's compiler merges one atomic in two branches into one: by count, weak)
            weak.append(f"LOCK? ref {r} locked, port {p}")
        return strong, weak

    # ---- WRAP
    def wrap_probe(self, pi) -> tuple[list, list]:
        """(tier A hits, tier B hits): each (port address, instruction, the index's definition)"""
        targets = {int(ops, 16) for _a, _s, mn, ops in pi if (JCC.match(mn) or mn == "jmp") and ops.startswith("0x")}
        A, B = [], []
        for k, (addr, _s, mn, ops) in enumerate(pi):
            # (padding, and data the procedure's range takes in: a jump table read as code)
            if mn.startswith("nop") or mn.startswith("f") or re.search(r"\b(?:ah|bh|ch|dh)\b", ops):
                continue
            if mn == "lea":
                parts = ops.split(", ", 1)
                if len(parts) != 2 or parts[0] not in REG64:
                    continue
                at = parts[1].strip("[]").replace(" ", "")
            else:
                m = mem_of(ops)
                if not m:
                    continue
                at = m[1]
            if "rip" in at:
                continue
            regs, disp = addr_parts(at)
            r64 = [(r, s) for r, s in regs if r in REG64]
            if not r64 or any(r in STACK64 for r, _ in regs):
                continue
            # (the port's own switch tables, `mov eax, [r13 + rax*4 + rva]` off the image base a
            # `lea r13, [rip - x]` loaded: the compiler's dispatch, its index bound-checked)
            if any(self.image_base_reg(pi, k, r) for r, _ in r64):
                continue
            # (data the range takes in decodes as rare instructions around it)
            if any(pi[j][2] in JUNK for j in range(max(0, k - 3), min(len(pi), k + 4))):
                continue
            # (a lea whose 64-bit sum only its low half is used of, `lea rcx, [rsi + r9]; add ecx,
            # r13d`: the compiler's 32-bit add)
            if mn == "lea" and not self.used_64(pi, k, FAM[ops.split(", ")[0]]):
                continue
            for r, s in r64:
                d = self.def_of(pi, k, r, targets)
                if d is None:
                    continue
                kind, text = d
                other = [x for x, _ in r64 if x != r]
                if kind == "big64":
                    A.append((addr, f"{mn} {ops}", text))
                elif kind == "neg32":
                    if s > 1 or (self.in_image(disp & 0xFFFFFFFF) and disp > 0):
                        A.append((addr, f"{mn} {ops}", text))
                    elif other:
                        B.append((addr, f"{mn} {ops}", text))
        return A, B

    @staticmethod
    def used_64(pi, k, fam):
        """the register pi[k] writes is next used whole (an address, a 64-bit operand), not by its
        low 32 bits; unknown past a jump or call: whole"""
        for j in range(k + 1, min(len(pi), k + 12)):
            mn, ops = pi[j][2], pi[j][3]
            toks = REG_TOKEN.findall(ops)
            mine = [t for t in toks if FAM.get(t) == fam]
            if mine:
                # (a 32-bit lea of it, `lea ebx, [rax + rcx*8]`, keeps the low half too)
                if mn == "lea" and ops.split(", ")[0] in R64_OF:
                    return False
                if any(t in REG64 for t in mine):
                    return True
                return False
            if mn in ("call", "ret", "jmp") or JCC.match(mn):
                return True
        return True

    @staticmethod
    def image_base_reg(pi, k, r64):
        """r64 holds the port's image base: its last write before pi[k] a `lea r64, [rip +- x]`,
        anywhere in the procedure (the compiler keeps it in a callee-saved register)"""
        for j in range(k - 1, -1, -1):
            mn, ops = pi[j][2], pi[j][3]
            o = ops.split(", ")
            if o and FAM.get(o[0]) == FAM[r64] and mn not in ("cmp", "test", "push"):
                return mn == "lea" and "rip" in ops
        return False

    @staticmethod
    def def_of(pi, k, r64, targets):
        """the last write of r64's family before pi[k] in its run (no label, call or jump between):
        ('neg32', text) a 32-bit write that can leave a negative number zero-extended,
        ('big64', text) a 64-bit immediate past 2^31, else None"""
        r32 = R32_OF[r64]
        fam = FAM[r64]
        for j in range(k - 1, max(-1, k - 16), -1):
            addr, _s, mn, ops = pi[j]
            if pi[j + 1][0] in targets:
                return None                 # (a label: the value may come from elsewhere)
            if mn in ("call", "ret") or JCC.match(mn) or mn == "jmp":
                return None
            if mn in ("cdqe", "cqo", "cwde", "cdq"):
                if fam == "a" and mn in ("cdqe", "cwde"):
                    return None             # (rax sign-extended: the fix's own)
                if fam == "d" and mn == "cdq":
                    return None
                continue
            o = ops.split(", ")
            if not o or not o[0] or "[" in o[0] or FAM.get(o[0]) != fam:
                continue
            dst = o[0]
            text = f"{mn} {ops}"
            if mn in ("cmp", "test"):
                continue
            if dst == r64:
                if mn == "movabs" or (mn == "mov" and len(o) == 2 and o[1].startswith("0x")):
                    v = int(o[1], 16)
                    # (past 2^31 and not a small negative's sign extension; nor a word twice,
                    # 0xb98a0111b98a0111, a table's words decoded as a movabs)
                    if 0x80000000 <= v < (1 << 64) - 0x80000000 and (v >> 32) != (v & 0xFFFFFFFF):
                        return ("big64", text)
                return None
            if dst != r32:
                return None                 # (a byte or word write merges: not a zero extension)
            if mn in ("neg", "not", "dec"):
                return ("neg32", text)
            if mn == "sub" and len(o) == 2:
                if o[1].startswith("0x"):
                    return None             # (r - c: a pointer's or count's step back)
                # (an unsigned remainder, `x - x / c * c` after the division's magic multiply)
                if any(pi[q][2] in ("mul", "imul") for q in range(max(0, j - 8), j)):
                    return None
                # (x - x is 0; a difference of two)
                return ("neg32", text) if o[1] != dst else None
            if mn == "add" and len(o) == 2 and o[1].startswith("0x") and int(o[1], 16) >= 0x80000000:
                return ("neg32", text)
            if mn == "lea" and len(o) == 2 and re.search(r"- 0x[0-9a-f]+\]", o[1]):
                return ("neg32", text)
            if mn == "mov" and len(o) == 2 and o[1].startswith("0x") and int(o[1], 16) >= 0x80000000:
                return ("neg32", text)
            if mn in ("movsx", "sar", "cdq"):
                return ("neg32", text)
            return None
        return None

    # ---- WIDE
    def accesses(self, insns, x64: bool):
        """{(kind, key): Counter(width)} for kind store/load, key ('g', addr) or ('f', disp)"""
        out: dict = {}
        for _a, _s, mn, ops in insns:
            if mn == "lea" or mn.startswith(("nop", "prefetch", "rep", "stos", "movs", "lods", "scas", "cmps")):
                continue
            if x64 and mn.startswith("f"):
                continue
            m = mem_of(ops)
            if not m:
                continue
            w, at = m
            if w == 10:
                continue
            regs, disp = addr_parts(at)
            if any(r in (STACK64 if x64 else STACK) for r, _ in regs):
                continue
            first_mem = "[" in ops.split(", ")[0]
            kind = "store" if first_mem and WRITES.match(mn) else "load"
            if mn in ("cmpxchg", "xadd", "xchg") or mn.startswith("lock "):
                kind = "store"
            dv = disp & 0xFFFFFFFF
            if self.in_image(dv) and dv >= 0x400000:
                # (an array's element, indexed: the port's compiler fills a loop's bytes by qwords)
                key = ("g", dv) if not regs else ("a", dv)
            elif len(regs) == 1 and regs[0][1] == 1 and -0x10000 < disp < 0x10000:
                key = ("f", disp)
            else:
                continue
            out.setdefault((kind, key), Counter())[w] += 1
        return out

    def wide_probe(self, ri, pi, inl_ref) -> tuple[list, list]:
        ra = self.accesses(ri, False)
        for x in inl_ref:
            for k, v in self.accesses(x, False).items():
                ra.setdefault(k, Counter()).update(v)
        pa = self.accesses(pi, True)
        strong, weak = [], []
        rep = any(mn.startswith("rep") for _a, _s, mn, _o in ri)
        for (kind, key), ws in sorted(pa.items(), key=str):
            w = max(ws)
            # (globals only: a field's displacement is many pointers' in one function, and the port's
            # frame saves through `mov rax, rsp` read as fields; 2026-10-31, 1 of 14 field hits real)
            # (and up to 8 bytes: a 16-byte load is a packed constant or a block copy in vectors)
            if key[0] != "g" or w > 8:
                continue
            rk = ra.get((kind, key))
            any_ref = rk or ra.get(("load" if kind == "store" else "store", key))
            if not any_ref:
                continue
            rmax = max((any_ref or Counter()) | (rk or Counter()))
            if rmax >= w:
                continue
            # (the bytes past the reference's width are its own accesses: two stores merged)
            covered = set()
            for (k2, key2), ws2 in ra.items():
                if key2[0] != key[0]:
                    continue
                for w2 in ws2:
                    covered |= {key2[1] + i for i in range(w2)}
            if all(key[1] + i in covered for i in range(w)):
                continue
            label = (f"{key[1]:#x}" if key[0] == "g" else f"+{key[1]:#x}")
            s = f"WIDE {kind} {label} port {w} ref {rmax}"
            (strong if key[0] == "g" or kind == "store" else weak).append(s)
        return strong, weak

    # ---- SIGN
    @staticmethod
    def sign_counts(insns, x64: bool):
        s, u = Counter(), Counter()
        for _a, _sz, mn, ops in insns:
            if x64 and mn.startswith("f"):
                continue
            if mn in SIGNED:
                s[SIGNED[mn]] += 1
            elif mn in UNSIGNED:
                u[UNSIGNED[mn]] += 1
        return s, u

    def sign_probe(self, ri, pi, inl_ref) -> list:
        rs, ru = self.sign_counts(ri, False)
        for x in inl_ref:
            a, b = self.sign_counts(x, False)
            rs.update(a)
            ru.update(b)
        ps, pu = self.sign_counts(pi, True)
        out = []
        for cls in ("div", "shift", "jcc", "ext", "set", "cmov"):
            more_s = ps[cls] - rs[cls]
            less_u = ru[cls] - pu[cls]
            if more_s > 0 and less_u > 0:
                out.append(f"SIGN {cls} signed ref {rs[cls]} port {ps[cls]}, unsigned ref {ru[cls]} port {pu[cls]}")
            more_u = pu[cls] - ru[cls]
            less_s = rs[cls] - ps[cls]
            if more_u > 0 and less_s > 0 and cls in ("div", "shift"):
                out.append(f"SIGN {cls} unsigned ref {ru[cls]} port {pu[cls]}, signed ref {rs[cls]} port {ps[cls]}")
        return out

    # ---- GUARD
    def table_targets(self, ops, addrs) -> list:
        """an x86 jump table's targets, `jmp dword ptr [eax*4 + 0x4ddc10]`: its words while each is
        an instruction of the function"""
        m = re.fullmatch(r"dword ptr \[e\w\w\*4 \+ (0x[0-9a-f]+)\]", ops)
        if not m:
            return []
        t, out = int(m.group(1), 16), []
        for k in range(512):
            v = int.from_bytes(self.ref.read(t + 4 * k, 4), "little")
            if v not in addrs:
                break
            out.append(v)
        return out

    def blocks(self, insns):
        """basic blocks: (start index, end index exclusive), successors by block index (an x86
        jump table's by its words; an unknown indirect jump's -1)"""
        if not insns:
            return [], [], {}
        addrs = {x[0]: i for i, x in enumerate(insns)}
        leaders = {0}
        tables = {}
        for i, (a, s, mn, ops) in enumerate(insns):
            if JCC.match(mn) or mn == "jmp" or mn.startswith("ret"):
                if i + 1 < len(insns):
                    leaders.add(i + 1)
                if ops.startswith("0x") and int(ops, 16) in addrs:
                    leaders.add(addrs[int(ops, 16)])
                if mn == "jmp" and "*4 +" in ops:
                    tables[i] = self.table_targets(ops, addrs)
                    leaders.update(addrs[v] for v in tables[i])
        ls = sorted(leaders)
        bl = [(ls[i], ls[i + 1] if i + 1 < len(ls) else len(insns)) for i in range(len(ls))]
        of = {s: n for n, (s, _e) in enumerate(bl)}
        succ = []
        for s, e in bl:
            a, _sz, mn, ops = insns[e - 1]
            out = []
            if JCC.match(mn) or mn == "jmp":
                if ops.startswith("0x") and int(ops, 16) in addrs:
                    out.append(of[addrs[int(ops, 16)]])
                elif mn == "jmp" and tables.get(e - 1):
                    out.extend(sorted({of[addrs[v]] for v in tables[e - 1]}))
                elif mn == "jmp":
                    out.append(-1)               # (an indirect jump: its targets unknown)
            if not (mn == "jmp" or mn.startswith("ret")) and e < len(insns):
                out.append(of[e])
            succ.append(out)
        return bl, succ, of

    def guard_consts(self, insns, x64):
        """{table address: [for each load of it, whether it runs on every path from the entry]}"""
        loads = []
        for i, (_a, _s, mn, ops) in enumerate(insns):
            if mn in ("jmp", "call", "lea") or (x64 and mn.startswith("f")):
                continue
            m = mem_of(ops)
            if not m:
                continue
            regs, disp = addr_parts(m[1])
            dv = disp & 0xFFFFFFFF
            if regs and all(r not in (STACK64 if x64 else STACK) for r, _ in regs) and self.in_image(dv) \
                    and dv >= 0x400000 and not self.ref.is_code(dv):
                loads.append((i, dv))
        # (the port's in a loop aside: a loop's first pass the compiler proved, `for (i = 0; i <
        # 0x158; ...)` as do-while, which the reference tests before it; 8 of 9 hits, 2026-11-01)
        if x64:
            back = [(int(ops, 16), a) for a, _s, mn, ops in insns
                    if (JCC.match(mn) or mn == "jmp") and ops.startswith("0x") and int(ops, 16) <= a]
            loads = [(i, t) for i, t in loads if not any(lo <= insns[i][0] <= hi for lo, hi in back)]
        if not loads:
            return {}
        bl, succ, of = self.blocks(insns)
        if len(bl) > 1500:
            return {}
        bidx = []
        for n, (s, e) in enumerate(bl):
            bidx.extend([n] * (e - s))
        # (whether each load runs on every path from the entry: its block post-dominates the entry,
        # the exits the returns, an indirect jump's and a trap's blocks; GEN_ENTER's branch over
        # gen_trace_enter rejoins)
        # (by the loads of a table together: copies of one load in each case of a switch, the
        # compiler's tail duplicated, cover every path as one does; whether an exit is reachable
        # from the entry past none of them)
        n = len(bl)
        rsucc = [[s for s in ss if s >= 0] for ss in succ]
        by_t: dict = {}
        for i, t in loads:
            by_t.setdefault(t, set()).add(bidx[i])
        out = {}
        for t, bs in by_t.items():
            seen, todo, escaped = {0}, [0], False
            if 0 in bs:
                out[t] = True
                continue
            while todo and not escaped:
                b = todo.pop()
                if not rsucc[b]:
                    escaped = True
                    break
                for s in rsucc[b]:
                    if s not in seen and s not in bs:
                        seen.add(s)
                        todo.append(s)
            out[t] = not escaped
        return out

    def guard_probe(self, ri, pi) -> list:
        """a table the reference loads only on some paths (under a branch: a switch's case, a range
        check) that the port loads on every path: a load hoisted out of its guard"""
        rg = self.guard_consts(ri, False)
        if not rg:
            return []
        pg = self.guard_consts(pi, True)
        out = []
        for t, ralways in rg.items():
            if t in pg and not ralways and pg[t]:
                out.append(f"GUARD {t:#x} the reference loads it on some paths, the port on every path")
        return out

    # ---- THIS (the translation's C)
    VCALL = re.compile(r"\(\((\w+) \*\)\*\(\(gen_code32 \*\)GEN_TOP\(")

    @staticmethod
    def balanced(text, i, open_="(", close=")"):
        d = 0
        for k in range(i, len(text)):
            ch = text[k]
            if ch == open_:
                d += 1
            elif ch == close:
                d -= 1
                if d == 0:
                    return k
        return -1

    @staticmethod
    def norm(e: str) -> str:
        e = e.strip()
        for _ in range(8):
            e0 = e
            e = re.sub(r"^\(\s*(?:const\s+)?[\w ]+\s*\**\s*(?:PTR32\s*\**)?\)\s*", "", e).strip()
            if e.startswith("GEN_TOP(") and e.endswith(")"):
                e = e[len("GEN_TOP("):-1].strip()
            if e.startswith("(") and Probes.balanced(e, 0) == len(e) - 1:
                e = e[1:-1].strip()
            if e == e0:
                break
        return e.replace(" ", "")

    def ref_vcalls(self, ri) -> dict:
        """the reference's virtual call sites by vtable offset: {d: [(site, cc, words)]}, from
        callsites.json (protos32 icall_shape: `this` among the words of a __thiscall site)"""
        out: dict = {}
        cs = self.callsites
        for k, (a, _s, mn, ops) in enumerate(ri):
            if mn != "call" or ops.startswith("0x") or ("ptr [" in ops and re.fullmatch(r"dword ptr \[0x[0-9a-f]+\]", ops)):
                continue
            key = f"{a:#x}"
            if key not in cs.get("cc", {}):
                continue
            d = None
            m = re.fullmatch(r"dword ptr \[(e\w\w)(?: \+ (0x[0-9a-f]+|\d+))?\]", ops)
            if m:
                d = int(m.group(2), 0) if m.group(2) else 0
            elif re.fullmatch(r"e\w\w", ops):
                for j in range(k - 1, max(-1, k - 10), -1):
                    o = ri[j][3]
                    m2 = re.fullmatch(ops + r", dword ptr \[e\w\w(?: \+ (0x[0-9a-f]+|\d+))?\]", o)
                    if ri[j][2] == "mov" and m2:
                        d = int(m2.group(1), 0) if m2.group(1) else 0
                        break
                    if o.startswith(ops + ",") or ri[j][2] == "call":
                        break
            if d is None:
                continue
            out.setdefault(d, []).append((a, cs["cc"][key], len(cs["calls"].get(key, []))))
        return out

    @staticmethod
    def split_args(args: str) -> list:
        parts, d0, cur = [], 0, ""
        for ch in args:
            if ch == "," and d0 == 0:
                parts.append(cur)
                cur = ""
                continue
            d0 += {"(": 1, ")": -1}.get(ch, 0)
            cur += ch
        parts.append(cur)
        parts = [p for p in (re.sub(r"\bGEN_EDX_\w+", "", p).strip() for p in parts) if p]
        return parts

    def this_probe(self, c: str, ri=None) -> list:
        """a virtual call of the C passing one word fewer than every reference site at its vtable
        offset, those sites __thiscall (the object in ecx) and its first argument not the object:
        `this` dropped (35 sites of 2026-10-31, protos32 icall_shape / object_in_ecx)"""
        out = []
        sites = self.ref_vcalls(ri) if ri is not None and self.callsites else {}
        for m in self.VCALL.finditer(c):
            i = m.end() - 1                       # the '(' of GEN_TOP(
            j = self.balanced(c, i)
            if j < 0:
                continue
            inner = c[i + 1:j]
            k = j + 1
            while k < len(c) and c[k] == ")":
                k += 1
            if k >= len(c) or c[k] != "(":
                continue
            e = self.balanced(c, k)
            args = self.split_args(c[k + 1:e])
            v = self.norm(inner)
            md = re.search(r"\+(0x[0-9a-f]+|\d+)U?$", v)
            d = int(md.group(1), 0) if md else 0
            # (a vtable's slot, `*X + d`: not a member function pointer, `*(this + 0x10)`, whose
            # offset another site's vtable shares)
            base = self.norm(v[:md.start()] if md else v)
            if not (base.startswith("*") or base.startswith("GEN_NE(*")):
                continue
            refs = sites.get(d, [])
            if not refs:
                continue
            words = {n for _a, _cc, n in refs}
            if len(args) in words:
                continue
            text = re.sub(r"\s+", " ", c[m.start():e + 1])[:200]
            at = ", ".join(f"{a:#x}" for a, _c, _n in refs[:3])
            if len(args) + 1 in words and all(cc in ("__thiscall", "__fastcall") for _a, cc, _n in refs):
                out.append(f"THIS vcall +{d:#x}: C passes {len(args)}, the reference's __thiscall sites {at} "
                           f"pass {sorted(words)} with ecx `{text}`")
            else:
                # (a push the reference leaves for a later call, its callee popping none, that the
                # decompiler gave the earlier one: TriggerBoxLayoutInstance::vf4's vf63 and vf27)
                out.append(f"ARGS vcall +{d:#x}: C passes {len(args)}, the reference's sites {at} pass "
                           f"{sorted(words)} `{text}`")
        return out

    # ---- ZEROREG
    ZERO = re.compile(r"^\s*\w[\w ]*?\b(in_(E?[A-D]X|E[SD]I|EBP|[A-D][LH]))\s*=\s*0;", re.M)

    def zeroreg_probe(self, ri, c: str) -> list:
        out = []
        regs = {m.group(2) for m in self.ZERO.finditer(c)}
        if not regs:
            return out
        for r in sorted(regs):
            fam = FAM.get(r.lower())
            if not fam:
                continue
            # (the reference reads it before writing it, on its entry block's straight run)
            read = self.reads_at_entry(ri, fam)
            if read:
                out.append(f"ZEROREG in_{r} = 0, the reference reads {r.lower()} at {read[0]:#x} ({read[1]})")
        return out

    @staticmethod
    def reads_at_entry(ri, fam):
        """the reference's first read of a register family on its entry run, before any write"""
        for a, _s, mn, ops in ri[:64]:
            o = ops.split(", ") if ops else []
            if (mn in ("fnstsw", "fstsw", "lahf") and fam == "a") or (mn == "rdtsc" and fam in "ad") \
                    or (mn == "cpuid" and fam in "abcd"):
                return None                         # (an implicit write: the status word, flags, the TSC)
            if mn in ("pushal", "pushad"):
                continue
            if mn == "push":
                # (a push is a save or MSVC's slot reserve, `push ecx` for `sub esp, 4`: no input)
                continue
            implicit = {"cdq": "a", "cwde": "a", "div": "ad", "idiv": "ad", "mul": "a", "stosd": "ac",
                        "stosb": "ac", "lodsd": "c", "movsd": "c" if not o else "", "movsb": "c"}
            if mn.startswith("rep") and fam == "c":
                return (a, f"{mn} {ops}")
            if mn in implicit and fam in implicit[mn] and (mn not in ("mul",) or len(o) == 1):
                return (a, f"{mn} {ops}")
            write_only = mn.startswith(("mov", "cvt", "pmovmsk", "pextr", "lea", "set", "bs", "popcnt",
                                        "lzcnt", "tzcnt")) or mn == "pop" or (mn == "imul" and len(o) == 3)
            zeroing = mn in ("xor", "sub", "sbb", "pxor") and len(o) == 2 and o[0] == o[1]
            srcs = o[1:] if write_only or zeroing else o
            if zeroing:
                srcs = []
            # (a write of any width defines it: `mov al, [esp + 4]` before `cmp [ecx], al`)
            dst_writes = o and "[" not in o[0] and FAM.get(o[0]) == fam and (write_only or zeroing)
            for x in srcs + ([o[0]] if o and "[" in o[0] else []):
                if fam in {FAM.get(t) for t in REG_TOKEN.findall(x)}:
                    return (a, f"{mn} {ops}")
            if dst_writes:
                return None
            if mn == "call":
                return None
            if JCC.match(mn) or mn in ("jmp", "ret"):
                return None
        return None

    # ---- MERGE (Ghidra's C)
    ASSIGN = re.compile(r"^\s*([a-z]+Var\d+) = (.*);\s*$")
    VAR = re.compile(r"\b[a-z]+Var\d+\b")
    # (any control flow ends the run: `if (c) break;` leaves the first value live on its exit)
    BREAK = re.compile(r"[{}]|^\s*LAB_|\bgoto\b|\breturn\b|\bcase\b|\bdefault:|\bbreak\b|\bcontinue\b|\bif\s*\(|"
                       r"\bwhile\b|\bfor\s*\(|\bswitch\b|\belse\b|\bdo\b")

    def merge_probe(self, c: str) -> list:
        pending, hits, stmt = {}, [], ""
        for line in c.replace("\r", "").split("\n"):
            if self.BREAK.search(line):
                pending.clear()
                stmt = ""
                continue
            stmt += " " + line.strip()
            if not stmt.rstrip().endswith(";"):
                continue
            s, stmt = stmt.strip(), ""
            m = self.ASSIGN.match(s)
            if m:
                v, rhs = m.group(1), m.group(2)
                for u in set(self.VAR.findall(rhs)):
                    pending.pop(u, None)
                # (a global read again is a poll of it, a lock word's: not two values)
                if v in pending and "DAT_" not in rhs and "DAT_" not in pending[v] \
                        and not re.search(r"\w+\s*\(", re.sub(r"\((?:float10|float|double)\)", "", rhs)):
                    hits.append(f"MERGE {v}: `{pending[v][:60]}` then `{s[:60]}`")
                pending[v] = s
            else:
                for u in set(self.VAR.findall(s)):
                    pending.pop(u, None)
        return hits

    # ---- GAP
    def gap_probe(self, a, ri) -> list:
        """a jump of the function's into code no function's pieces hold: the decompiler follows it
        (its C has that code) but the facts, made per piece, never saw it, its indirect calls no
        callsites.json entry (VectorDeletingDestructor 0x520030's 0x520053..0x520098, the array's
        frees through the allocator's vtable with `this` lost)"""
        b = self.b
        out, seen = [], set()
        starts = {x[0] for x in ri}
        for k, (x, s, mn, ops) in enumerate(ri):
            # (and a piece's end that falls through into it)
            nxt = x + s
            # (but a call's: a callee that does not return, what follows dead, _Xlength's)
            falls = not (mn in ("jmp", "call", "int3", "hlt") or mn.startswith("ret")) and nxt not in starts
            # (not padding after a call that does not return)
            if falls and self.ref.is_code(nxt) and nxt not in seen and b.func_containing(nxt) is None \
                    and nxt not in self.cor and self.ref.read(nxt, 1) not in (b"\xcc", b"\x90", b"\x00"):
                seen.add(nxt)
                out.append(f"GAP {nxt:#x}: the piece ending at {x:#x} falls into code in no function's pieces")
            if not ((JCC.match(mn) or mn == "jmp") and ops.startswith("0x")):
                continue
            t = int(ops, 16)
            if t in seen or not self.ref.is_code(t):
                continue
            seen.add(t)
            if b.func_containing(t) is None and t not in self.cor:
                out.append(f"GAP {t:#x}: a jump into code in no function's pieces")
        return out

    # ---- all
    def run(self, a: int, ranges=None, inlined=()) -> dict | None:
        pi = self.port_insns(a)
        if pi is None:
            return None
        ri = self.ref_insns(a, ranges)
        # (translations the port inlined here, the PDB's and GEN_ENTER's markers: their reference
        # bodies are the caller's)
        inl = set(inlined)
        for k, (_x, _s, mn, ops) in enumerate(pi):
            if mn == "call" and ops.startswith("0x") and int(ops, 16) in self.trace_enter:
                for j in range(k - 1, max(-1, k - 8), -1):
                    if pi[j][2] == "mov" and pi[j][3].startswith("ecx, 0x"):
                        inl.add(int(pi[j][3][5:], 16))
                        break
        inl_ref = [self.ref_insns(y) for y in sorted(inl - {a}) if y in self.pieces]
        c = self.tr.get(a, "")
        gc = self.cor.get(a, {}).get("c", "") or ""
        flags, weak = [], []
        s_, w_ = self.lock_probe(ri, pi, inl_ref)
        flags += s_
        weak += w_
        wa, wb = self.wrap_probe(pi)
        flags += [f"WRAP {x:#x} `{i}` <- `{d}`" for x, i, d in wa]
        weak += [f"WRAP? {x:#x} `{i}` <- `{d}`" for x, i, d in wb]
        s_, w_ = self.wide_probe(ri, pi, inl_ref)
        flags += s_
        weak += w_
        flags += self.this_probe(c, ri)
        flags += self.guard_probe(ri, pi)
        flags += self.zeroreg_probe(ri, c)
        flags += self.gap_probe(a, ri)
        weak += self.sign_probe(ri, pi, inl_ref)
        weak += self.merge_probe(gc)
        return {"addr": f"{a:08x}", "flags": flags, "weak": weak}
