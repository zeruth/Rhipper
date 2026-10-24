# rhtest

Rhipper against programs built from source. Each program is small and tests one area
(`src/<name>.c` or `.cpp`, linked with `src/rhtest_main.c`). It is compiled with MSVC as x86 `/MD`
once per variant, and each program × variant is a Rhipper project of its own under
`work/<name>-<variant>/`, with its `rhipper.json` written by `rhtest.py`. The reference's own output
is the expectation: the whole pipeline runs on it, the port is built against `runtime32/`, and the
port must print the same lines and exit the same. No build may warn: the reference compiles with
`/W4 /WX`, and a warning in the port's build fails the run.

```bash
python rhtest.py                         # every program, every variant, every step
python rhtest.py float                   # one program (or several)
python rhtest.py float --variant IA32    # one variant
python rhtest.py --from translate        # resume: ref, import, facts, ghidra, translate, port, run, fidelity
python rhtest.py --only fidelity         # rescore without rebuilding
python rhtest.py --jobs 4                # more workers (serial by default)
```

Steps per project:

- `ref`: cl, then the reference is run to produce `ref/expected.txt`.
- `import`: Ghidra's import and analysis, rerun only when the reference changed.
- `facts`: noreturn.py, protos32.py and helpers32.py. While protos32.py finds code that only a pointer reaches, `ghidra.sh apply` and `functions` turn it into functions and the facts run again.
- `ghidra`: `ghidra.sh all`.
- `translate`: translate32.py.
- `port`: `port/CMakeLists.txt`, built for x64.
- `run`: the port runs against the reference, and `build/actual.txt` is diffed with `ref/expected.txt`.
- `fidelity`: fidelity32.py scores each reference function against its translation. It uses a port built `/O1 /Ob0` (`RHTEST_MEASURE`) so that inlining and unrolling don't blur the comparison.

Each run rewrites `fidelity.html` here. It holds the overview of every project and, per project,
the functions below 1.0 and the stubs. Only the projects a run touched are rescored. A project's
PASS/FAIL changes only when the run included the `run` step. While working on a program, run only
that program. At the end of a phase, run everything (`python rhtest.py`) to check for
regressions.

The reference has no PDB (Ghidra would read it, and the binaries Rhipper is for have none) and no
relocations (`/DYNAMICBASE:NO`), but `ref/<name>.map` names every address, which helps when reading
a failure.

## Programs

| program | variants | constructs |
|---|---|---|
| core | O2, Od | integer arithmetic (division by constants, shifts, rotates), extension, signed vs unsigned compares, branches, loops, recursion; switches, arrays, a sort, structs by value and by pointer, a table of records, strings, globals, static locals, a linked list |
| int64 | O2, Od | 64-bit integers on x86: the CRT's `__allmul`, `__alldiv`, `__aullrem`, shift helpers and their kin |
| float | O2, Od, IA32 | SSE2 and x87 (`/arch:IA32`) floats and doubles: arithmetic, mixed widths, conversions both ways (`__dtol3`, `__ftol2`, `__ltod3`, ...), comparisons with NaN and infinity, `fabs`/`sqrt`, loops, structs of floats |
| calls | O2, Od, GL | function pointers, calling conventions (`__stdcall`, `__fastcall`, varargs), `/GL`'s own conventions (planned) |
| crt | O2, Od | `printf` and `va_list`, `qsort` with a callback, `malloc` (planned) |
| cpp | O2, Od | classes, virtuals, multiple inheritance, statics, templates (planned) |
| misc | O2, Od | TLS, intrinsics, bitfields, `alloca`, `setjmp` (planned) |
| eh | O2, Od | SEH and C++ exceptions (planned) |

Status as of 2026-10-24: core, int64 and float pass on all their variants, and every translated
function scores 1.0. The only exceptions are the CRT's four SEH filter and handler blocks
(`unaff_EBP`, run only by an exception), which `eh` covers.
