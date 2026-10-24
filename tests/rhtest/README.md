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
python rhtest.py --parallel 4            # projects at once (a full run's default)
python rhtest.py --save-bins             # also keep each reference in bins/<toolset>/, to commit
python rhtest.py --bins msvc-14.51-x86   # test the committed references instead of building them
```

The Ghidra install and projects folder default to this machine's. `RHTEST_GHIDRA` and
`RHTEST_GHIDRA_PROJECTS` override them.

Steps per project:

- `ref`: cl, then the reference is run to produce `ref/expected.txt`. With `--bins`, the committed reference, map and `expected.txt` are copied in instead.
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
| calls | O2, Od, GL | calling conventions (`__cdecl`, `__stdcall`, `__fastcall`) with several argument shapes, structs by value, varargs and a `va_list` handed on, function pointers (tables, callbacks of each convention, one returned, one in a struct), `/GL`'s own conventions |
| crt | O2, Od | the `/MD` ucrt: `printf`'s family and a `va_list` handed to it, scanning, conversions, `qsort`/`bsearch` calling a translated comparator, the allocator, strings and memory, ctype, stdout |
| cpp | O2, Od | `__thiscall`, constructors and destructors, virtual dispatch, multiple and virtual inheritance (thunks, vbtables), templates, operator overloading, values by value, statics built and torn down by the CRT, references, placement new |
| misc | O2, Od | thread-local storage (`__declspec(thread)` and `TlsAlloc`), intrinsics, bitfields, `alloca`, `setjmp`/`longjmp` |
| eh | O2, Od | C++ exceptions (`/EHsc`): catch by type, rethrow, nested, across frames, unwinding destructors, a throwing constructor; C's `__try`/`__except`/`__finally` with `RaiseException` |

Status as of 2026-10-24: all 18 projects pass. Every translated function scores 1.0 in core,
int64, float, calls and crt. cpp, misc and eh are at 0.97–1.0; the gaps are decompiler folds that
are equivalent but not the reference's instructions. The few stubs left are CRT helpers (AVX-512
conversion paths, `__alloca_probe`'s return address). Hardware faults inside `__try` and `/EHa`
are not covered yet.

## The committed references and CI

`bins/<toolset>/<name>-<variant>/` holds the references as one compiler built them, with their map
files and `expected.txt`. The toolset is named by the compiler and target, `msvc-14.51-x86`: MSVC
14.51 (Visual Studio 2026), x86. Each toolset has a GitHub Actions workflow of its own,
`.github/workflows/<toolset>.yml`, which runs `rhtest.py --bins <toolset>` on every push to main.
The result is the same on any runner: the runner's compiler builds only the port, not the
references. Each workflow publishes its report to the
[Pages site](https://zeruth.github.io/Rhipper/) under `<toolset>/` (`pages.py`, on `gh-pages`).
The site's front page lists every toolset.

To add a toolset (another MSVC, another target):

1. On a machine with it, run `python rhtest.py --save-bins` and commit `bins/<toolset>/`.
2. Copy the workflow to `<toolset>.yml` and change its `name` and `TOOLSET`.

After a change to a program's source, rebuild the references the same way and commit them with the
change. Otherwise CI tests the old binaries.
