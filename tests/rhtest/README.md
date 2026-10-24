# rhtest

Rhipper against a program built from source. `src/rhtest.c` is compiled with MSVC as x86 `/MD`,
once per variant, each variant a Rhipper project of its own (`O2/`, `Od/`, each with its
`rhipper.json`). The reference's own output is the expectation: the whole pipeline runs on it, the
port is built against `runtime32/`, and the port must print the same lines and exit the same.

```bash
python rhtest.py                         # every step, both variants
python rhtest.py --variant O2            # one variant
python rhtest.py --from translate        # resume: ref, import, facts, ghidra, translate, port, run
python rhtest.py --only run
python rhtest.py --level 1               # an earlier level of the program
```

Steps per variant: `ref` (cl, then the reference's run as `ref/expected.txt`), `import` (Ghidra's
import and analysis, again only when the reference changed), `facts` (noreturn.py, protos32.py;
while protos32.py finds code only a pointer reaches, `ghidra.sh apply` and `functions` make it
functions and the facts run again), `ghidra` (`ghidra.sh all`), `translate` (translate32.py),
`port` (`port/CMakeLists.txt`, x64), `run` (the port against the reference, `build/actual.txt`
diffed with `ref/expected.txt`).

The reference has no PDB (Ghidra would read it; the binaries Rhipper is for have none) and no
relocations (`/DYNAMICBASE:NO` implies `/FIXED`), but `ref/rhtest.map` names every address, for
reading a failure.

Both variants pass at level 2 (2026-10-24): every function but the CRT's four SEH filter and
handler blocks (`unaff_EBP`, run only by an exception) is translated.

## Levels

The program prints one line per check, each check its own `NOINLINE` function fed from a
volatile seed so `/O2` cannot fold it. Its output goes through `WriteFile`, not `printf`, until
the CRT is a level of its own. A level is added once the ones before it pass on both variants.

| level | constructs |
|---|---|
| 1 | integer arithmetic (division by constants, shifts, rotates), sign/zero extension, signed vs unsigned compares, branches, loops with break/continue, recursion, mutual recursion |
| 2 | dense, fall-through, sparse and char switches; arrays, a sort, 2D arrays; structs by value (edx:eax and hidden-pointer returns) and by pointer; a read-only table of records with string pointers; strings; globals and static locals; a linked list |

Planned: 64-bit integers on x86 (`__allmul`, `__alldiv`), floats (x87 and SSE), the CRT
(`printf`, `qsort` with a callback, `malloc`), function pointers and calling conventions
(`__stdcall`, `__fastcall`, varargs), C++ (classes, virtuals, multiple inheritance, statics,
templates), then SEH and C++ exceptions, TLS and intrinsics; and an x64 build, and a `/MT` one.
