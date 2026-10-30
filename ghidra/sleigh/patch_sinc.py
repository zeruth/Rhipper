"""Rhipper's fixes to Ghidra's x86 SLEIGH spec, applied to an install's ia.sinc (kept as
ia.sinc.orig; install.sh recompiles x86.sla and x86-64.sla after). Each fix marked RHIPPER.

    python ghidra/sleigh/patch_sinc.py <ghidra install> [--restore]

The fixes:
  PCMPESTRI / PCMPISTRI  the flags they set: the release writes ECX alone, and the string searches
      branching on them (`pcmpestri xmm1, [esi], 0xc; jb found`) read whatever an older
      instruction left: the static C++ library's vectorized search and strstr decompiled to
      `bVar13 = (undefined1 *)0xfffffff3 < &stack0xffffff84` (rhtest stl /MT). CF, ZF, SF and OF
      are the bits of pcmpestri_flags / pcmpistri_flags (1, 2, 4, 8), Ghidra32.h's gen_ ones
"""
import sys
from pathlib import Path

MARK = "# RHIPPER"

FIXES = [
    ("define pcodeop pcmpestri;\n",
     "define pcodeop pcmpestri;\n"
     f"{MARK}: the flags too, pcmpestri_flags' bits CF 1, ZF 2, SF 4, OF 8\n"
     "define pcodeop pcmpestri_flags;\n"
     "macro pcmpstri_flags(f) { CF = (f & 1) != 0; ZF = (f & 2) != 0; SF = (f & 4) != 0; OF = (f & 8) != 0;"
     " AF = 0; PF = 0; }\n"),
    ("{ ECX = pcmpestri(XmmReg, m128, imm8:8, EAX, EDX); }",
     "{ ECX = pcmpestri(XmmReg, m128, imm8:8, EAX, EDX); local f:4 = pcmpestri_flags(XmmReg, m128, imm8:8, EAX, EDX);"
     " pcmpstri_flags(f); }"),
    ("{ ECX = pcmpestri(XmmReg1, XmmReg2, imm8:8, EAX, EDX); }",
     "{ ECX = pcmpestri(XmmReg1, XmmReg2, imm8:8, EAX, EDX); local f:4 = pcmpestri_flags(XmmReg1, XmmReg2, imm8:8, EAX, EDX);"
     " pcmpstri_flags(f); }"),
    ("{ ECX = pcmpestri(XmmReg, m128, imm8:8, RAX, RDX); }",
     "{ ECX = pcmpestri(XmmReg, m128, imm8:8, RAX, RDX); local f:4 = pcmpestri_flags(XmmReg, m128, imm8:8, RAX, RDX);"
     " pcmpstri_flags(f); }"),
    ("{ ECX = pcmpestri(XmmReg1, XmmReg2, imm8:8, RAX, RDX); }",
     "{ ECX = pcmpestri(XmmReg1, XmmReg2, imm8:8, RAX, RDX); local f:4 = pcmpestri_flags(XmmReg1, XmmReg2, imm8:8, RAX, RDX);"
     " pcmpstri_flags(f); }"),
    ("define pcodeop pcmpistri;\n",
     "define pcodeop pcmpistri;\n"
     f"{MARK}: the flags too\n"
     "define pcodeop pcmpistri_flags;\n"),
    ("{ ECX = pcmpistri(XmmReg, m128, imm8:8); }",
     "{ ECX = pcmpistri(XmmReg, m128, imm8:8); local f:4 = pcmpistri_flags(XmmReg, m128, imm8:8); pcmpstri_flags(f); }"),
    ("{ ECX = pcmpistri(XmmReg1, XmmReg2, imm8:8); }",
     "{ ECX = pcmpistri(XmmReg1, XmmReg2, imm8:8); local f:4 = pcmpistri_flags(XmmReg1, XmmReg2, imm8:8); pcmpstri_flags(f); }"),
]


def main() -> None:
    lang = Path(sys.argv[1]) / "Ghidra" / "Processors" / "x86" / "data" / "languages"
    sinc, orig = lang / "ia.sinc", lang / "ia.sinc.orig"
    if "--restore" in sys.argv:
        if orig.exists():
            sinc.write_bytes(orig.read_bytes())
        print("restored the release's ia.sinc")
        return
    if not orig.exists():
        orig.write_bytes(sinc.read_bytes())
    # (always from the release's text: a fix changed here replaces the one applied before)
    text = orig.read_bytes().decode("utf-8")
    nl = "\r\n" if "\r\n" in text else "\n"
    text = text.replace("\r\n", "\n")
    for old, new in FIXES:
        if text.count(old) != 1:
            sys.exit(f"patch_sinc: {old[:60]!r} is not in ia.sinc once ({text.count(old)})")
        text = text.replace(old, new)
    new_bytes = text.replace("\n", nl).encode("utf-8")
    if sinc.read_bytes() != new_bytes:
        sinc.write_bytes(new_bytes)
        print("patched ia.sinc")
    else:
        print("ia.sinc already patched")


if __name__ == "__main__":
    main()
