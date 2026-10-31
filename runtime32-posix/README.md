# runtime32-posix

The POSIX/Android (arm64) counterpart of Rhipper's Windows `runtime32/`. It maps a 32-bit x86
reference executable, runs its translation (Rhipper's `translate32.py` output: `src/gen`) as a native
arm64 library, and provides a Win32 personality so the reference boots and runs on an Android phone.

Target: Android arm64-v8a, API 29+ (built against Android 17's NDK sysroot with stock clang ≥ 22,
which has `__ptr32` on aarch64). The Ghidra32.h aarch64 branch (another agent) makes `DWORD` etc.
4 bytes, `wchar_t` 2 bytes (`-fshort-wchar`), and replaces SSE with portable code; this runtime does
not include Ghidra32.h.

## Memory map

The whole memory model (Ghidra32.h) is: the reference stores pointers in 4-byte slots, so everything
the reference is handed must live below 2 GB.

```
0x00000000 - 0x00400000   left to the system (null page, small ART bits)
0x00400000 + image size   the reference's PE image, at its own base (ffxiv.exe)
  immediately after       the per-function island table (B-targets, ±128 MB of the image)
  ... up to ~0x10000000    the reference's heaps, VirtualAlloc, thread stacks, TEBs, COM objects
0x10000000 - 0x70000000   lib<name>.so (the translation + this runtime), placed here by the boot
                          library; the general island table; more heap
0x70000000 - 0x80000000   kept clear at reserve time as a search floor for the .so
>= 0x80000000             ART's Java heap, the boot image, this runtime's non-reference C++ objects
                          (std::map nodes, etc. — never handed to the reference)
```

At the library's load (`Host.cpp` constructor) and again at `rhipper_host_run`, `LowReserve()` reads
`/proc/self/maps`, mmaps every still-free range below 2 GB `PROT_NONE`, and hands it out itself
afterwards (`LowMem.cpp`): the reference's image (`LowClaim`), its heaps (a segregated-fit allocator
behind `HeapAlloc`/`VirtualAlloc`), thread stacks, TEBs. ART keeps 2–4 GB for its own low needs.

### Why two libraries

The Android linker loads a `.so` high (above 4 GB). The generated code truncates host addresses to
32 bits (a string literal passed to an `unsigned int`, an adapter address returned as `uint32`,
`imports.c` sign-extending through `va_arg(int)`), so the port's own code, rodata, data and bss must
also be below 2 GB — not only the reference's heap.

- `lib<name>_boot.so` (`android_jni.c`) is what the app's `System.loadLibrary` loads. It holds the
  JNI glue (the `RhipperNative` methods) and no truncated addresses, so being loaded high is fine. In
  `nativeInit` it reserves a low range and loads `lib<name>.so` into it with `android_dlopen_ext` +
  `ANDROID_DLEXT_RESERVED_ADDRESS` (falling back to `_HINT`, then a plain high `dlopen` with a loud
  warning), then resolves `rhipper_host_*` with `dlsym` and forwards every call.
- `lib<name>.so` is the translation plus this runtime, mapped below 2 GB. It exports `rhipper_host_*`.

The host must load `lib<name>_boot.so` (i.e. its configured library name is `<name>_boot`). JNI method
names and signatures are `RhipperNative.kt`'s, unchanged.

## Calls, islands and the SIGBUS fallback

An indirect call in the generated code calls a 32-bit reference address as a native function pointer
(`((code *)*slot)(args)`); the runtime calls reference functions the same way. The reference's code is
never run, so its `.text` is repurposed:

- every 4-aligned word is overwritten with a trap, `brk #0xcc`;
- at each 4-aligned function entry a 4-byte `B` to that function's island entry (right after the
  image, within the branch's ±128 MB), which `ldr x16, #8; br x16` jumps on to the translation (a
  full 64-bit indirect branch, so the translation may be anywhere);
- a trap that is actually reached (an address no translation covers) is looked up and logged, 0
  returned to the caller — like the x64 runtime's `int3`.

1,269 of CrystalCore's 87,623 functions start at a non-4-aligned address and cannot hold a branch; a
call there raises a PC-alignment fault (SIGBUS `BUS_ADRALN`) with PC = the entry and LR already set.
A few hundred more have the code section's data (the translation reads it) at their entry. For both,
`RefImage.cpp`'s signal handler looks the PC up in the (sorted) jump table and resumes at the
translation — the slow path, counted and periodically logged. On arm64 two 4-aligned entries are
always ≥ 4 bytes apart, so the x64 "crowded entry" case does not arise; only unaligned entries do.

`brk #0xf000`/`brk #1` (int3/`__fastfail`) and `udf #0`/`udf #1` (ud2/hlt) from the Ghidra32.h aarch64
branch are translated into the reference's exceptions by the same handler.

### Trampolines (islands)

A native function address the reference must hold in 4 bytes (an import adapter, a COM vtable thunk, a
callback) goes through a 16-byte island below 2 GB: `ldr x16, #8; br x16; .quad target`. When the `.so`
is below 2 GB (the normal case) a port function already fits a slot and `Island()` returns its address
unchanged; islands are then only for the rare function above 2 GB (none, in practice). Islands are
written through a second writable mapping of a `memfd` (RX below 2 GB, RW elsewhere) so no page is
ever writable and executable at once; `__builtin___clear_cache` after each.

## Threads, TLS, exceptions

- Threads (`kernel32_thread.cpp`) are native pthreads whose stacks are placed below 2 GB with a guard
  page; each gets its x86 TEB/PEB on first use (`Hooks.cpp` `gen_teb32`), holding the SEH chain head,
  the TLS array (`gen_tls_array`), last-error, and the Tls* slots at the x86 offsets.
- Exceptions (`Eh.cpp`) reproduce `runtime32/Adapters.cpp`'s x86 SEH dispatch over the fs:[0] chain:
  C++ (`__CxxFrameHandler3`), EH4 and EH3 frames, with the same checks. A hardware fault inside a
  reference `__try` is sent to a trampoline that dispatches on the faulting thread's stack; a filter
  that asks to continue execution cannot resume the instruction here (bionic has no `setcontext`) and
  ends the run, logged. `gen_int_fault` raises the reference's integer-divide/overflow exceptions.

## What is real vs stubbed, per DLL

Real enough to boot and reach the lobby:

- **kernel32** — files (case-insensitive path mapping to the game dir, drives → the root, overlapped
  read/write as positioned I/O), directory searches, the heap and VirtualAlloc family on the
  reservation, threads, critical sections (the native mutex lives in the reference's 24-byte section),
  events/mutexes/semaphores and the waits on them, time (QPC at 10 MHz, tick, file/system time),
  environment and command line, modules, the en-US locale and the code pages (1252 and UTF-8, via
  `CRYSTALCORE_ACP`), interlocked, TLS. Version: Windows 7 SP1.
- **user32** — one window system: classes, a window per thread with the reference's WNDPROC, a message
  queue (Peek/Get/Dispatch/Post/Send, inter-thread SendMessage, timers → WM_TIMER/TIMERPROC, WM_QUIT),
  the host's surface as the screen (GetSystemMetrics, GetClientRect), lifecycle → WM_ACTIVATE*/WM_CLOSE.
  Keyboard/mouse report nothing yet (input comes through XInput); the cursor and clipboard are no-ops;
  comctl32 window subclasses.
- **ws2_32** — BSD sockets, the x86 structures, WSAAsyncSelect posting window messages from a watcher
  thread, WSAIoctl's SIO_UDP_CONNRESET and keepalive.
- **xinput1_3** — the host's pads (`rhipper_host_set_pad`) and rumble.
- **dinput8** — keyboard and mouse objects that exist and report nothing (so a game that insists on
  them boots); replaceable by a project factory.
- **d3d9** — a null renderer: a device, resources with real memory behind their locks, state kept,
  Present counted. `d3d9_null.cpp` is the seam — a project registers its own `Direct3DCreate9` with
  `rhipper_com_set_factory` (CrystalCore's Vulkan `IDirect3D9` later).
- **ole32 / oleaut32 / shell32** — COM lifetime, the task allocator/IMalloc, BSTR, VARIANT (x86
  layout), the known folders (made under the game dir).
- **advapi32** — an in-memory registry, empty but for what `<game>/registry.reg` seeds; user "Player".
- **version** — the reference's own version resource (`Resources.cpp`); another file's has none.

Logged stubs with correct return conventions:

- **winhttp** — every call fails (no HTTP yet; the reference takes its no-network path).
- **gdi32 / imm32** — GDI draws nothing (the reference draws through Direct3D); the IME is off.
- **dbghelp** — no minidump (the runtime's own crash report is in the log).
- **d3dx9_43** — the screenshot savers fail (nothing to save from a null renderer).
- Any import with no personality function gets a per-import logged stub that returns 0 (`RefImage.cpp`).

## Logging and crashes

Every line goes to logcat (tag = the project name) and to `<log dir>/<name>.log`. A SIGSEGV/SIGBUS/
SIGILL/SIGTRAP/SIGFPE handler maps native PCs back to `F_xxxx` symbol names (via `dladdr`, else the
nearest translation in the jump table), prints the registers and a frame-pointer backtrace, flushes
the shadow trace, and lets the system tombstone follow.

## Environment variables (`<ENV>_` prefix, e.g. `CRYSTALCORE_`)

- `_REF` — the reference's path (else `rhipper_host_run`'s argument).
- `_TRACE`, `_TRACE_MAX`, `_TRACE_FROM`, `_TRACE_SYNC` — the shadow trace (`shadow32.py`'s side).
- `_ACP` — the ANSI code page: `1252` (default) or `65001`.
- `RH_EHTRACE=1` — log every SEH funclet the dispatcher runs.

## Open issues / to verify

- The reservation walks down from 0x70000000 for the `.so`; a very large translated `.so` plus the
  reference's heaps may crowd the low 2 GB. Measure on device; if tight, shrink the trace/debug code
  or split the reservation.
- No host keyboard/mouse yet: `GetAsyncKeyState`, DirectInput devices and user32 input report nothing.
  Pad input works through XInput.
- `winhttp` is unimplemented; the game's news/patch fetches fail.
- The d3d9 null renderer's vtable slot numbers are from d3d9.h; verify against the reference's calls
  (the per-slot call counts are logged every 600 presents).
- `android_dlopen_ext` with `ANDROID_DLEXT_RESERVED_ADDRESS` must place the `.so` below 2 GB; if it
  falls back to a high load the run will fault on the first truncated address (logged loudly).
