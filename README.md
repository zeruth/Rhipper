# Rhipper

Ghidra-to-C recompilation tooling for Windows PE binaries (x86-64 and 32-bit x86). Facts are
read off the binary in Python, applied to a Ghidra program in one session, the whole program is
decompiled to a corpus, and the corpus is translated to C that builds and runs.

The rule throughout: a defect is fixed where it arises, in a fact or in the translator's reading
of a construct, never patched per function. A translation must compile in one round.

## Projects

Rhipper works on a **project**: a reference binary and the source tree its translation goes into,
named by a `rhipper.json` at the project's root (`project.py` lists every setting). Every tool
finds it from the working directory, or from `RHIPPER_PROJECT`.

```json
{
  "name": "Example",
  "exe": "ref/example.exe",
  "arch": "x86",
  "image_base": "0x400000",
  "gen": "src/gen",
  "import_overrides": ["InitializeCriticalSection", "GetStartupInfoW"],
  "ghidra": {"install": "C:/tools/ghidra_*", "projects": "C:/tools/ghidra-projects",
             "project": "Example", "program": "example.exe", "maxmem": "8G"}
}
```

A project keeps its own data relative to its root: `build/facts/` (generated), `data/*.json`
(committed: hand-identified `names.json`, `structs.json` layouts for types Ghidra only has as
placeholders, `imports.json`). Binary-specific extractors stay in the project and plug in through
`rhipper.json` (`plugins`, `hooks`, `facts_extra`).

## Pipeline

```bash
bash ghidra/ghidra.sh import            # once: import and analyze, export function extents
python noreturn.py                       # facts (x86: protos32.py; x64: facts.sh runs them all)
python protos32.py --jobs 2
python helpers32.py                      # x86: the compiler's 64-bit/float helpers, by running them
bash ghidra/ghidra.sh all                # apply the facts, export types, data and the corpus
python translate32.py --jobs 2           # translate, compile, report (x64: translate64.py)
```

`ghidra.sh all` opens the program once: `ApplyFacts.java` applies every fact (re-runnable, never
replacing a `USER_DEFINED` name), then `ExportTypes`, `ExportData` and `ExportDecompAll` write
`build/types.json`, `build/refdata.jsonl` and `build/corpus.jsonl`, each moved over the old one
only when complete.

After every translation, build and read the warnings: they are likely real translation problems.
Fix them, then start again from the facts.

## Tools

| | |
|---|---|
| `project.py` | the project's settings (`--sh` for shell variables) |
| `pebin.py` | the PE: sections, function extents (`.pdata`, or Ghidra's on x86), relocations, references |
| `protos32.py` / `protos64.py` | every function's convention, parameters, result and kept registers, and every indirect call's arguments, read off the instructions (must-define analysis) |
| `noreturn.py` | functions that never return |
| `vtables.py`, `switches.py`, `pieces.py`, `funcptrs.py`, `globalptrs.py`, `floatdata.py`, `intparams.py`, `preserved.py`, `srcrefs.py` | further facts: vtables, jump tables, chained pieces, function-pointer slots, pointer globals, float data, integer parameters, preserved registers, source paths |
| `corpus.py` | renders the corpus by address, range or source file |
| `translate32.py` | the x86 translator: the reference's 32-bit memory model on x64 (see `runtime32/Ghidra32.h`) |
| `translate64.py` | the x64 translator, beside a hand port |
| `signedness.py` | both translators' signed comparisons of Ghidra's sign-agnostic `undefinedN` values |
| `fidelity.py`, `fidelity_report.py` | each port's fidelity to the reference, function by function |
| `disasm.py`, `callers.py`, `calltree.py`, `xrefs.py`, `hexdump.py` | inspection |
| `oracle.py` | runs reference functions under emulation (Unicorn), to check a port |

Ghidra scripts are in `ghidra/`; `ghidra.sh` runs them headless (`import`, `functions`, `apply`,
`all`, `script <name>`).

## 32-bit programs

`runtime32/` holds what a translated x86 program needs to run as x64:

- `Ghidra32.h`, the header the translation is written against: x86 type widths, `PTR32` stored
  pointers, Ghidra's helpers (`CONCAT`, pieces), float/pointer bit conversions, the SSE
  pseudo-ops, Windows structures at their x86 layouts, TEB and TLS access. `translate32.py`
  copies it into the project's gen directory.
- An example runtime: mapping the reference's image at its own base below 2 GB, the jumps from
  its entry points into the translation, its imports through adapters (`Adapters.cpp`: the
  imports whose structures differ on x64, the `/MD` C runtime's startup among them; translate32.py
  leaves every `gen_imp_<name>` runtime32 defines to it, and a project's own in
  `import_overrides`), the x86 TEB and TLS, a handler for calls into untranslated code, and a hang
  dump. Link the port with `/LARGEADDRESSAWARE:NO /DYNAMICBASE:NO /FIXED` at a base above the
  reference's image.

## Tests

`tests/rhtest/` builds a program from source with MSVC (x86 `/MD`, `/O2` and `/Od`), runs the
whole pipeline on it, and checks that the port prints what the reference does:
`python tests/rhtest/rhtest.py`. The program grows by levels (its README).

## 64-bit programs

`runtime64/` holds the header a translated x64 program is compiled against:

- `Ghidra64.h`: Ghidra's type words and helpers (`CONCAT`, pieces, `SUB`), the 16-byte values
  (`gen_v16`) and SSE pseudo-ops `v16.py` writes, float/bit views (`GEN_FABS`, `gen_bits2f`),
  thread-local and static-guard access, and the Windows types the corpus names. `translate64.py`
  copies it into the project's gen directory every run, next to `translated.h`, which includes it
  from there; edit it here, never in a project.

The runtime that maps the reference's image and runs the translation against it (`RefImage.cpp`
in FrostLite: the image at its own base, the jumps from its entry points, `GenFault`, the trap for
calls into untranslated code) stays in the project for now: it logs and allocates through the
project's own facilities.
