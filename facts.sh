#!/bin/bash
# Rebuild every fact file from the project's reference binary, then apply them to its Ghidra
# project.
#
#   bash path/to/Rhipper/facts.sh            extract + apply
#   bash path/to/Rhipper/facts.sh --no-apply extract only (e.g. while Ghidra has the project open)
#
# The extractors are pipeline.sh's first step (one list, run in parallel); the whole pipeline,
# apply and both exports in one Ghidra session, is `bash pipeline.sh`. imports.json is not rebuilt
# here: it needs a live process (iat_dump.py), and the project's data/imports.json stands in for it.
set -e
RH="$(cd "$(dirname "$0")" && pwd)"
bash "$RH/pipeline.sh" --facts
if [ "$1" != "--no-apply" ]; then
  bash "$RH/ghidra/ghidra.sh" apply
fi
