#!/bin/bash
# Headless Ghidra against the project's Ghidra program (rhipper.json "ghidra"), run from inside
# the project (or with RHIPPER_PROJECT set).
#
#   ghidra.sh apply                    apply build/facts/*.json
#   ghidra.sh decomp <out> <addr>...   decompile functions to a file
#   ghidra.sh script <Script.java> [args...]
#   ghidra.sh all                      apply, then export the data and the corpus
#                                      (pipeline.sh); the corpus in rhipper.json
#                                      ghidra.shards sessions at once (shards.py, default 2)
#   ghidra.sh sample <list> <out>      apply, then decompile the listed functions
#   ghidra.sh import [--overwrite]     import the reference binary into a new Ghidra program with
#                                      full auto-analysis, then export its function extents
#                                      (build/facts/functions.json, what 32-bit projects use in
#                                      place of .pdata)
#   ghidra.sh functions                re-export the function extents from the program as it is
#   ghidra.sh apply-functions          apply, then export the extents: the two above in one session
#
# Each run takes a minute or more to open the program: batch addresses.
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
# ROOT, G (the Ghidra install), PROJ, GPROJECT, PROG, GMAXMEM: the project's settings
eval "$(python "$HERE/../project.py" --sh)"
G="$(cygpath -u "$G")"
PROJ="$(cygpath -w "$PROJ")"
# one directory only: cmd.exe splits a ";"-joined script path into separate arguments
SCRIPTS="$(cygpath -w "$HERE")"
export GHIDRA_HEADLESS_MAXMEM=${GHIDRA_HEADLESS_MAXMEM:-$GMAXMEM}
mkdir -p "$ROOT/build"

run() {
  "$G/support/analyzeHeadless.bat" "$PROJ" "$GPROJECT" -process "$PROG" -noanalysis \
    -scriptPath "$SCRIPTS" "$@" > "$ROOT/build/ghidra-last.log" 2>&1 || true
  grep -E "ApplyFacts:|ERROR|Exception|wrote" "$ROOT/build/ghidra-last.log" | head -20
}

# the project's committed facts, where it has them: imports.json needs a live client to
# regenerate, so a committed copy backs it; names.json is hand-identified, always current
project_data() {
  mkdir -p "$ROOT/build/facts"
  if [ ! -f "$ROOT/build/facts/imports.json" ] && [ -f "$ROOT/data/imports.json" ]; then
    cp "$ROOT/data/imports.json" "$ROOT/build/facts/"
  fi
  if [ -f "$ROOT/data/names.json" ]; then cp "$ROOT/data/names.json" "$ROOT/build/facts/names.json"; fi
  # (and layouts for the types Ghidra has only as placeholders: ApplyFacts applyStructs)
  if [ -f "$ROOT/data/structs.json" ]; then cp "$ROOT/data/structs.json" "$ROOT/build/facts/structs.json"; fi
}

case "$1" in
  apply)  project_data
          run -postScript ApplyFacts.java "$(cygpath -w "$ROOT/build/facts")" ;;
  all)    project_data
          # the facts go in and the data comes out in one session, which saves the program; the
          # corpus then comes out of several read-only sessions over copies of it at once
          # (ghidra/shards.py: one session's decompilers wait on its database, ~5 of 20 cores).
          # Written beside the old files and moved over only when complete
          rm -f "$ROOT/build/refdata.jsonl.new" "$ROOT/build/corpus.jsonl.new" "$ROOT/build/ghidra-export.log"
          # (x86: the structure layouts too, translate32.py's member access)
          types=(); [ "$ARCH" = x86 ] && types=(-postScript ExportTypes.java "$(cygpath -w "$ROOT/build/types.json")")
          "$G/support/analyzeHeadless.bat" "$PROJ" "$GPROJECT" -process "$PROG" -noanalysis \
            -scriptPath "$SCRIPTS" \
            -postScript ApplyFacts.java "$(cygpath -w "$ROOT/build/facts")" \
            "${types[@]}" \
            -postScript ExportData.java "$(cygpath -w "$ROOT/build/refdata.jsonl.new")" \
            2>&1 | tee "$ROOT/build/ghidra-last.log" | grep --line-buffered -E "ApplyFacts:|ExportD|ERROR|Exception" || true
          grep -q "ExportData: wrote " "$ROOT/build/ghidra-last.log" && [ -s "$ROOT/build/refdata.jsonl.new" ] \
            || { echo "the facts session did not finish (build/ghidra-last.log): the old exports are kept"; exit 1; }
          python "$HERE/shards.py" || { echo "the corpus export did not finish (build/ghidra-shards/): the old corpus is kept"; exit 1; }
          [ -s "$ROOT/build/corpus.jsonl.new" ] || { echo "export incomplete"; exit 1; }
          # (and each export said it finished: a session stopped mid-export left both files
          # non-empty and partial, and the partial corpus replaced the good one, 2026-10-18)
          grep -q "ExportDecompAll: wrote " "$ROOT/build/ghidra-export.log" \
            || { echo "export did not finish (build/ghidra-export.log): the old corpus is kept"; exit 1; }
          # (Windows will not replace a file another process has open: a tool reading the old
          # corpus left the new one beside it once, and the session still reported success)
          for f in refdata corpus; do
            n=0
            until mv -f "$ROOT/build/$f.jsonl.new" "$ROOT/build/$f.jsonl" 2>/dev/null; do
              n=$((n + 1))
              [ $n -ge 30 ] && { echo "could not replace build/$f.jsonl (open elsewhere?); the new one is build/$f.jsonl.new"; exit 1; }
              sleep 10
            done
          done
          echo "wrote build/refdata.jsonl, build/corpus.jsonl" ;;
  decomp) out=$(cygpath -w "$2"); shift 2; run -postScript DecompileList.java "$out" "$@"; echo "wrote $out" ;;
  # apply the facts, then decompile only the functions listed in a file (one hex address a
  # line) to corpus-format JSON lines: a check of the facts on a sample before `all`
  sample) project_data
          list=$(cygpath -w "$2"); out=$(cygpath -w "$3")
          "$G/support/analyzeHeadless.bat" "$PROJ" "$GPROJECT" -process "$PROG" -noanalysis \
            -scriptPath "$SCRIPTS" \
            -postScript ApplyFacts.java "$(cygpath -w "$ROOT/build/facts")" \
            -postScript ExportDecompAll.java "$out" "@$list" \
            2>&1 | tee "$ROOT/build/ghidra-last.log" | grep --line-buffered -E "ApplyFacts:|ExportD|ERROR|Exception" || true
          echo "wrote $3" ;;
  script) s="$2"; shift 2; run -postScript "$s" "$@" ;;
  # (a one-time step: a project already in Ghidra keeps its program, and its hand naming, unless
  # the program is deleted first)
  import) mkdir -p "$ROOT/build/facts"
          # (--overwrite replaces the program, and everything done to it since: hand naming too)
          over=""; [ "$2" = "--overwrite" ] && over="-overwrite"
          "$G/support/analyzeHeadless.bat" "$PROJ" "$GPROJECT" -import "$(cygpath -w "$EXE")" $over \
            -scriptPath "$SCRIPTS" \
            -postScript ExportFunctions.java "$(cygpath -w "$ROOT/build/facts/functions.json")" \
            2>&1 | tee "$ROOT/build/ghidra-import.log" | grep --line-buffered -E "ExportFunctions:|ERROR|Exception|Import succeeded|already exists" || true ;;
  functions) mkdir -p "$ROOT/build/facts"
          run -postScript ExportFunctions.java "$(cygpath -w "$ROOT/build/facts/functions.json")" ;;
  # (the program opened once for both: each session's start is most of a small program's run)
  apply-functions) project_data
          run -postScript ApplyFacts.java "$(cygpath -w "$ROOT/build/facts")" \
              -postScript ExportFunctions.java "$(cygpath -w "$ROOT/build/facts/functions.json")" ;;
  *) sed -n '2,8p' "$0"; exit 1 ;;
esac
