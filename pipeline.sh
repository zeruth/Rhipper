#!/bin/bash
# The whole pipeline, from the binary to the project's generated sources, in three steps:
#
#   1. facts: every extractor over the reference binary -> build/facts/*.json (in parallel)
#   2. Ghidra, one session: apply the facts, export the data and the corpus
#   3. translate: translate64.py with the project's translate_args (rhipper.json)
#
#   bash path/to/Rhipper/pipeline.sh              all three
#   bash path/to/Rhipper/pipeline.sh --no-ghidra  facts and translate (the corpus as it is)
#   bash path/to/Rhipper/pipeline.sh --facts      facts only
#   bash path/to/Rhipper/pipeline.sh --from-ghidra  Ghidra and translate (the facts as they are)
#
# Run from inside the project (or with RHIPPER_PROJECT set): project.py finds its rhipper.json.
# The prototypes come from protos64.py (parameters and results read off the instructions) and are
# applied by ApplyFacts; the Decompiler Parameter ID pass (CommitPrototypes.java) is gone.
set -e
RH="$(cd "$(dirname "$0")" && pwd)"
eval "$(python "$RH/project.py" --sh)"
cd "$ROOT"
start=$(date +%s)
stamp() { echo "[$(( $(date +%s) - start ))s] $*"; }

if [ "$1" != "--from-ghidra" ]; then
stamp "facts"
# (the compiler that built the reference, and whether an rhtest toolset proves the facts for it)
python "$RH/toolchain.py" 2>&1 | sed "s/^/  /"
# independent of one another (and the project's own extractors, rhipper.json "facts_extra")
pids=()
for t in pieces vtables srcrefs typetags noreturn globalptrs switches; do
  ( python "$RH/$t.py" 2>&1 | tail -1 | sed "s/^/  $t: /" ) &
  pids+=($!)
done
for f in $FACTS_EXTRA; do
  ( python "$f" 2>&1 | tail -1 | sed "s/^/  $(basename "$f" .py): /" ) &
  pids+=($!)
done
for p in "${pids[@]}"; do wait "$p"; done
# (the return-address checks after the switches: their tables' bytes are no jumps over junk)
python "$RH/retcheck.py" 2>&1 | tail -1 | sed "s/^/  retcheck: /"
# these read the facts above (imports, vtables, noreturn, retcheck); protos64.py also writes
# varargs.json, the variadic functions read off their prologues
( python "$RH/funcptrs.py" 2>&1 | tail -1 | sed "s/^/  funcptrs: /" ) &
p1=$!
python "$RH/protos64.py" 2>&1 | tail -2 | sed "s/^/  protos: /"
# (the integer positions the current corpus shows as floats, against those prototypes: sticky)
python "$RH/intparams.py" 2>&1 | tail -1 | sed "s/^/  intparams: /"
wait $p1
# (the registers each function leaves alone, through the switches above, and protos64.py's xmm0:
# ApplyFacts gives them their keep conventions)
python "$RH/preserved.py" 2>&1 | tail -2 | sed "s/^/  preserved: /"
[ "$1" = "--facts" ] && { stamp "done"; exit 0; }
fi

if [ "$1" != "--no-ghidra" ]; then
  stamp "ghidra: apply + export"
  bash "$RH/ghidra/ghidra.sh" all
fi

stamp "translate"
# (the arguments callees return in other registers, for the reads the new corpus has of them)
python "$RH/leftover.py" 2>&1 | tail -2 | sed "s/^/  leftover: /"
# (what still decodes as junk in the new corpus, and the entries that are no function at all, the
# padding between two that Ghidra made functions of: translate64.py leaves both out)
python "$RH/junkscan.py" 2>&1 | tail -4 | sed "s/^/  junkscan: /"
python "$RH/translate64.py" $TRANSLATE_ARGS
stamp "done"
