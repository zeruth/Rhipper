# rhtest

Rhipper against programs built from source. Each program is small and tests one area
(`src/<name>.c` or `.cpp`, linked with `src/rhtest_main.c`). Each toolset (see
[Toolsets](#toolsets)) compiles it once per variant, and each program × variant is a Rhipper
project of its own: `work/<name>-<variant>/` for `msvc-14.51-x86`, and
`work/<toolset>/<name>-<variant>/` for the others. `rhtest.py` writes each project's
`rhipper.json`, with the toolset as its `toolchain`. The reference's own output
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
python rhtest.py --toolset msvc-16.00-x86  # another toolset's references (msvc-14.51-x86 by default)
python rhtest.py --save-bins             # also keep each reference in bins/<toolset>/, to commit
python rhtest.py --bins msvc-16.00-x86   # test a toolset's committed references instead of building them
```

The Ghidra install and projects folder default to this machine's. `RHTEST_GHIDRA` and
`RHTEST_GHIDRA_PROJECTS` override them, and `RHTEST_VS2010` sets where the VS2010 tools are.

Steps per project:

- `ref`: cl, then the reference is run to produce `ref/expected.txt`. With `--bins`, the committed reference, map and `expected.txt` are copied in instead.
- `import`: Ghidra's import and analysis, rerun only when the reference changed.
- `facts`: toolchain.py, vtables.py, noreturn.py, protos32.py and helpers32.py (vtables.py as a real project's facts have it: protos32.py reads every slot of a class's vtable as a method). toolchain.py's reading of the reference is printed when it disagrees with the toolset. While protos32.py finds code that only a pointer reaches, `ghidra.sh apply` and `functions` turn it into functions and the facts run again.
- `ghidra`: `ghidra.sh all`.
- `translate`: translate32.py.
- `port`: `port/CMakeLists.txt`, built for x64.
- `run`: the port runs against the reference, and `build/actual.txt` is diffed with `ref/expected.txt`.
- `fidelity`: fidelity32.py scores each reference function against its translation. It uses a port built `/O1 /Ob0` (`RHTEST_MEASURE`) so that inlining and unrolling don't blur the comparison.

Each run rewrites its toolset's report: `fidelity.html` here for `msvc-14.51-x86`, and
`work/<toolset>/fidelity.html` for the others. It holds the overview of every project and, per project,
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

Status as of 2026-10-25: every project passes on both toolsets from a fresh import (18 on
`msvc-14.51-x86`, 18 on `msvc-16.00-x86`). On `msvc-14.51-x86` nearly every translated function
scores 1.0 (misc 0.97); the gaps are decompiler folds that are equivalent but not the reference's
instructions. `msvc-16.00-x86` scores 0.93–0.97: its `/MT` C runtime is translated code, and
10–21 of its functions per program are still stubs (registers the decompiler lost in the CRT's
SEH prolog and epilog, `__report_gsfailure`, `__ftol2`, the locale frees). The few stubs left are CRT helpers (AVX-512
conversion paths, `__alloca_probe`'s return address). Hardware faults inside `__try` and `/EHa`
are not covered yet.

## Toolsets

A toolset is the compiler and target that build the references (`TOOLSETS` in `rhtest.py`). A
project's `toolchain` (`toolchain.py`, read off its binary or set in its `rhipper.json`) names the
toolset that proves its facts. A fix made for one project has to keep every toolset passing.

| toolset | compiler | runtime, target | variants | for |
|---|---|---|---|---|
| `msvc-14.51-x86` | MSVC 14.51 (Visual Studio 2026), from vswhere | `/MD` (ucrt), Vista+ | O2, Od, IA32, GL | current code |
| `msvc-16.00-x86` | Visual Studio 2010 SP1, cl 16.00.40219 | `/MT` (the CRT linked in and translated), Windows XP | O2, Od, SSE2, GL | VS2010 /MT clients |

VS2010's floats are x87 unless asked, so the program the newer toolset builds `/arch:IA32` it
builds `/arch:SSE2`. The sources build with both: `src/rhtest.h` fills in what VS2010 lacks
(`override`, `noexcept`, C89's warnings), and the programs keep to C89 declarations and C++03
initializers, which don't change what the newer compiler makes of them.

**Setting up VS2010 SP1** (only to build its references; CI uses the committed ones). Nothing
needs installing. Extract these into `C:/Users/<you>/tools/vs2010`, or set `RHTEST_VS2010`:

1. The [Windows SDK 7.1 ISO](https://download.microsoft.com/download/f/1/0/f10113f5-b750-4969-a255-274341ac6bce/GRMSDK_EN_DVD.iso)
   (x86). Mount it and run
   `msiexec /a <dvd>\Setup\WinSDKBuild\WinSDKBuild_x86.msi /qn TARGETDIR=<vs2010>\sdk`. This gives
   the XP-era headers and libraries.
2. The [Visual C++ 2010 SP1 compiler update](https://download.microsoft.com/download/7/5/0/75040801-126c-4591-bce4-4cd1fd1499aa/VC-Compiler-KB2519277.exe)
   (KB2519277). Its cabinet holds `vc_stdx86.msi`; extract the cabinet with `tar -xf`, then
   `msiexec /a vc_stdx86.msi /qn TARGETDIR=<vs2010>\sp1`. This gives cl and link 16.00.40219.
3. The update leaves out `ammintrin.h`, which `intrin.h` includes.
   `toolsets/msvc-16.00-x86/include` has an empty one, already on the toolset's include path.

`rhtest.py` checks the compiler's banner against the toolset before it builds anything.

## The committed references and CI

`bins/<toolset>/<name>-<variant>/` holds each toolset's references as its compiler built them,
with their map files and `expected.txt`. Each toolset has a GitHub Actions workflow of its own,
`.github/workflows/<toolset>.yml`, which runs the shared `rhtest.yml` with
`rhtest.py --bins <toolset>` on every push to main. The result is the same on any runner: the
runner's compiler builds only the port, never the references. Each workflow publishes its report
to the [Pages site](https://zeruth.github.io/Rhipper/) under `<toolset>/` (`pages.py`, on
`gh-pages`). The site's front page lists every toolset.

To add a toolset (another MSVC, another target):

1. Add it to `TOOLSETS` in `rhtest.py`.
2. On a machine with that compiler, run `python rhtest.py --toolset <toolset> --save-bins` and
   commit `bins/<toolset>/`.
3. Add `.github/workflows/<toolset>.yml`, a copy of another toolset's with its name changed.

After a change to a program's source, rebuild every toolset's references the same way and commit
them with the change. Otherwise CI tests the old binaries.
