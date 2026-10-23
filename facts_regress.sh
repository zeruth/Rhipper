#!/bin/bash
# Run every fact extractor of pipeline.sh's first step into a scratch facts directory, so two
# versions of the tooling can be compared on a project without touching its build/facts.
#
#   bash path/to/Rhipper/facts_regress.sh <out dir>        (from inside the project)
#   diff -r <before dir> <after dir>
#
# The out dir starts as a copy of the project's build/facts (the inputs some extractors read
# and nothing here rebuilds: imports.json, names.json, ...), then each extractor rewrites its own.
set -e
RH="$(cd "$(dirname "$0")" && pwd)"
eval "$(python "$RH/project.py" --sh)"
cd "$ROOT"
OUT="$(mkdir -p "$1" && cd "$1" && pwd)"
cp -r "$ROOT/build/facts/." "$OUT/"
export RHIPPER_FACTS="$OUT"
start=$(date +%s)
run() { python "$@" 2>&1 | tail -1 | sed "s|^|  $(basename "$1" .py): |"; }
for t in pieces vtables srcrefs cregister typetags noreturn globalptrs switches; do run "$RH/$t.py" & done
for f in $FACTS_EXTRA; do run "$f" & done
wait
run "$RH/retcheck.py"
run "$RH/funcptrs.py" &
run "$RH/protos64.py"
run "$RH/intparams.py"
wait
run "$RH/preserved.py"
echo "facts -> $OUT ($(( $(date +%s) - start ))s)"
