#!/bin/bash
# Builds the decompiler with Rhipper's fixes (CMakeLists.txt beside this, patch/) and puts it in
# the Ghidra install in place of the release's, which is kept as decompile.exe.orig.
#
#   bash ghidra/decompiler/install.sh            build and install
#   bash ghidra/decompiler/install.sh --restore  put the release's decompiler back
#
# The fixes (each marked RHIPPER in patch/):
#   dynamic.cc  dynamic hashes tell apart up to 64 colliding varnodes, not 8: a SIMD instruction's
#               lanes hash alike, and "Unable to find unique hash for varnode" failed whole functions
#   printc.cc   a value wider than the symbol at its address prints as `*(T *)&sym`, not the
#               release's `_sym` (a mark for a reader, no C: 993 functions of WowClassic 3.4.3)
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
RH="$(cd "$HERE/../.." && pwd)"
G=$(ls -d /c/Users/tyler/tools/ghidra_* | head -1)
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
