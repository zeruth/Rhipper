#!/bin/bash
# Builds the decompiler with Rhipper's fixes (CMakeLists.txt beside this, patch/) and puts it in
# the Ghidra install in place of the release's, which is kept as decompile.exe.orig.
#
#   bash ghidra/decompiler/install.sh            build and install
#   bash ghidra/decompiler/install.sh --restore  put the release's decompiler back
#
# The install is this machine's Ghidra, or RHIPPER_GHIDRA's.
#
# The fixes (each marked RHIPPER in patch/):
#   dynamic.cc  dynamic hashes tell apart up to 64 colliding varnodes, not 8: a SIMD instruction's
#               lanes hash alike, and "Unable to find unique hash for varnode" failed whole functions
#   printc.cc   a value wider than the symbol at its address prints as `*(T *)&sym`, not the
#               release's `_sym` (a mark for a reader, no C: 993 functions of WowClassic 3.4.3);
#               a signed CONCAT/SUB used in place prints its type, `(longlong)CONCAT44(a,b)`; a
#               CAST or SUBPIECE between a float and an integer prints as the reader's bit views
#               (gen_fl2bits, gen_bits2f, ...), not a C conversion; a float-typed piece is `_4_4f_`
#               float + and * are not associative (a nested sum keeps its parentheses), and an
#               unlocked undefinedN local takes its variable's inferred type before printing
#   printc.hh   (the float tokens' declarations)
#   ruleaction.cc  a NaN test guarding a float comparison stays (the default drops it): x87 and SSE
#               compares set the less/equal flags on unordered, and branches read them so; a test
#               and comparison one comparison means exactly fold, `NAN(a) || NAN(b) || a <= b`
#               to `!(b < a)`
#   opcodes.cc  a float < or <= is not negated by flipping (`!(a < b)` is not `b <= a` for a NaN)
#   subflow.cc  a float operation is narrowed only when every input fits (a double operand kept
#               `f * d` from becoming `f * (float)d`), and an x87 value never below a double:
#               MSVC's x87 runs at 53 bits, so a float's arithmetic there is a double's; nor
#               an op fed by another wide op, a chain rounded once (VS2010's /arch:SSE2 floats)
#   heritage.cc a LOAD whose pointer may reach both locals and parameters (its range wraps) is
#               guarded over the whole stack, not from the locals up only: a parameter's slot
#               reused for a std::min/max operand kept its store
#   cast.cc     a float into an untyped place (copy, store, argument) gets a cast: its bits
#   typeop.cc/.hh  a float into a PIECE or SUBPIECE (CONCAT44(f,g), SUB84(d,0)) gets an integer
#               cast: its bits, as the reader's CONCAT and SUB take integers
#   varmap.cc   a call to setjmp aliases the frame above its stack pointer: longjmp comes back
#               into it, and a local the function changes and reads again stays memory; and a
#               function that links an x86 EH frame (fs:[0]) has all of its frame aliased, its
#               funclets reaching locals and parameters' slots through ebp
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
RH="$(cd "$HERE/../.." && pwd)"
# (the Ghidra install: RHIPPER_GHIDRA, as CI sets it, or this machine's)
G="${RHIPPER_GHIDRA:-$(ls -d /c/Users/tyler/tools/ghidra_* | head -1)}"
G="$(cygpath -u "$G")"
OS="$G/Ghidra/Features/Decompiler/os/win_x86_64"
if [ "$1" = "--restore" ]; then
  [ -f "$OS/decompile.exe.orig" ] && mv -f "$OS/decompile.exe.orig" "$OS/decompile.exe"
  echo "restored the release's decompiler"; exit 0
fi
cmake -S "$HERE" -B "$RH/build/decompiler" -DGHIDRA="$(cygpath -m "$G")" > /dev/null
cmake --build "$RH/build/decompiler" --config Release --target decompile -- -m:1 -v:minimal
[ -f "$OS/decompile.exe.orig" ] || cp "$OS/decompile.exe" "$OS/decompile.exe.orig"
# (a running Ghidra holds decompile.exe open: Windows will not replace it then)
cp -f "$RH/build/decompiler/Release/decompile.exe" "$OS/decompile.exe"
echo "installed $OS/decompile.exe (the release's is decompile.exe.orig)"
