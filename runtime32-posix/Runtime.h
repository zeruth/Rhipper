// runtime32-posix's internals, shared by its files: the reference's addresses, the low memory, the
// log, the handle table and how a Win32 function of the personality is registered.
//
// The memory model is Ghidra32.h's: the reference's image at its base, everything it is handed
// below 2 GB, so a 4-byte slot holds any address. Here the port's own code is a high .so: a native
// function the reference must hold in 4 bytes goes through a low trampoline (Island()).
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <memory>
#include <mutex>
#include <string>
#include <type_traits>
#include <utility>

#ifndef RHIPPER_NAME
#define RHIPPER_NAME "port"
#endif
#ifndef RHIPPER_ENV
#define RHIPPER_ENV "PORT"
#endif

namespace rh {

// ---- addresses ---------------------------------------------------------------------------------
template <typename T = void>
inline T* At(uint32_t address) {
    return reinterpret_cast<T*>(static_cast<uintptr_t>(address));
}
inline uint32_t Low(const void* p) {
    return static_cast<uint32_t>(reinterpret_cast<uintptr_t>(p));
}
inline uint32_t U32(uint32_t a) { return *At<uint32_t>(a); }
// a 32-bit word the generated code passed where it may also pass a port-side (high) pointer, a
// string literal of its own: the whole value when it lies in the port's .so, else its low half
uintptr_t PortOrLow(uintptr_t raw);
inline const char* Str(uintptr_t raw) { return reinterpret_cast<const char*>(PortOrLow(raw)); }
inline const char16_t* WStr(uintptr_t raw) { return reinterpret_cast<const char16_t*>(PortOrLow(raw)); }

// ---- the log: logcat (the project's tag) and <log dir>/<name>.log ---------------------------------
void Log(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
// once per distinct key (a stubbed API's first call)
void LogOnce(const char* key, const char* fmt, ...) __attribute__((format(printf, 2, 3)));
void LogFlush();
// signal-safe: a fixed string and numbers, no allocation
void LogRaw(const char* s);
const std::string& LogDir();

// an environment variable of the project's, RHIPPER_ENV "_" suffix: "" when unset
std::string Env(const char* suffix);

// ---- low memory (LowMem.cpp) --------------------------------------------------------------------
// the reservation: every free range below 2 GB taken PROT_NONE at startup
void LowReserve();
size_t PageSize();
// pages for the runtime's and the reference's use, committed read-write, zeroed (granule: 64 KB
// reservations, page commits). 0 when the low memory is spent
uint32_t LowAlloc(uint32_t size, uint32_t align = 0x10000);
void LowFree(uint32_t at, uint32_t size);
// the image's own range, taken out of the reservation (false: not free)
bool LowClaim(uint32_t at, uint32_t size);
// an allocation of the runtime's below 2 GB (a native structure the reference holds the address
// of: a section's mutex, a COM object, a vtable), from the process heap
void* LowNew(size_t size);
void LowDelete(void* p);
template <typename T, typename... A>
T* LowMake(A&&... a) {
    return new (LowNew(sizeof(T))) T(std::forward<A>(a)...);
}
// the process heap's handle, GetProcessHeap()
uint32_t ProcessHeap();
uint32_t HeapAllocIn(uint32_t heap, uint32_t flags, uint32_t size);
uint32_t HeapFreeIn(uint32_t heap, uint32_t flags, uint32_t p);
// VirtualQuery's answer for an address (MEMORY_BASIC_INFORMATION's x86 fields)
struct Region {
    uint32_t base, allocBase, allocProtect, size, state, protect, type;
};
bool LowQuery(uint32_t address, Region* out);

// ---- low trampolines (Islands.cpp) --------------------------------------------------------------
// a 4-byte address that, called, runs `fn`: `ldr x16, #8; br x16; .quad fn` below 2 GB
uint32_t Island(const void* fn);
// the image's per-function islands, within a branch's 128 MB of the image (RefImage.cpp)
void IslandsNearImage(uint32_t imageEnd, uint32_t count);
uint32_t IslandNear(const void* fn);

// ---- the reference (RefImage.cpp) ---------------------------------------------------------------
extern "C" uint32_t gen_ref_base;
uint32_t RefImageSize();
bool InImage(uint32_t a);
bool InText(uint32_t a);
// a reference function's translation by the jump table, nullptr for none
void* PortOf(uint32_t ref);
// a reference function called with the reference's 32-bit words (through its translation directly)
template <typename... A>
uint32_t CallRef(uint32_t fn, A... args) {
    void* port = PortOf(fn);
    auto f = reinterpret_cast<uint32_t (*)(decltype(static_cast<uint32_t>(args))...)>(
        port ? port : reinterpret_cast<void*>(static_cast<uintptr_t>(fn)));
    return f(static_cast<uint32_t>(args)...);
}
// the reference's virtual-path view of its own executable (GetModuleFileName)
const std::u16string& RefModulePath();
const std::string& RefHostPath();

// ---- threads (kernel32_thread.cpp) --------------------------------------------------------------
// a native thread that may run the reference's code: its stack below 2 GB, its TEB on first use
struct LowThread;
uint32_t StartLowThread(void (*fn)(void*), void* arg, uint32_t stack, bool suspended, uint32_t* tid);
uint32_t CurrentThreadId();
// the TEB's last error (x86 TEB + 0x34)
void SetLastError(uint32_t e);
uint32_t GetLastError();

// ---- waitable objects and the handle table (Handles.cpp) ----------------------------------------
// One lock and one condition variable for every wait the reference makes: events, mutexes,
// semaphores, threads and the message queue all signal through it, so WaitForMultipleObjects and
// MsgWaitForMultipleObjects are one loop over plain state. A game's few dozen threads do not mind.
std::mutex& WaitLock();
void WaitNotify();   // (the lock held or not)
// wait on the shared condition for up to `ms` (a unique_lock on WaitLock held): woken by WaitNotify
void WaitLockWaitFor(std::unique_lock<std::mutex>& lk, uint32_t ms);

struct Object {
    virtual ~Object() = default;
    virtual const char* Kind() const = 0;
    // waitable: signalled (WaitLock held), and what a satisfied wait takes from it
    virtual bool Waitable() const { return false; }
    virtual bool Signalled(uint32_t tid) const { (void)tid; return false; }
    virtual void Acquire(uint32_t tid) { (void)tid; }
    // CloseHandle's: false refuses
    virtual bool Close() { return true; }
};
uint32_t NewHandle(std::shared_ptr<Object> o);
std::shared_ptr<Object> GetHandle(uint32_t h);
template <typename T>
std::shared_ptr<T> GetAs(uint32_t h) {
    return std::dynamic_pointer_cast<T>(GetHandle(h));
}
bool CloseHandle32(uint32_t h);
uint32_t DupHandle(uint32_t h);
// a wait as WaitForMultipleObjects: WAIT_OBJECT_0 + k, WAIT_TIMEOUT, WAIT_FAILED; `messages`
// wakes it for the calling thread's queue (MsgWait: returns WAIT_OBJECT_0 + n)
uint32_t WaitAny(const uint32_t* hs, uint32_t n, bool all, uint32_t ms, uint32_t wakeMask);
uint64_t NowMs();   // a monotonic clock

constexpr uint32_t kCurrentProcess = 0xFFFFFFFFu;
constexpr uint32_t kCurrentThread = 0xFFFFFFFEu;
constexpr uint32_t kInvalidHandle = 0xFFFFFFFFu;

// ---- strings ------------------------------------------------------------------------------------
std::string Narrow(const char16_t* s, int n = -1);       // UTF-16 -> UTF-8
std::u16string Widen(const char* s, int n = -1);         // UTF-8 -> UTF-16
std::u16string Ansi16(const char* s, int n = -1);        // the reference's code page (1252 / UTF-8)
size_t Len16(const char16_t* s);
std::string AnsiOf(const std::u16string& s);             // UTF-16 -> the ANSI code page
uint32_t AnsiCodePage();
char16_t Upper16(char16_t c);
char16_t Lower16(char16_t c);
std::string HexGuid(uint32_t guid);                      // a GUID in reference memory, for the log
uint64_t FileTimeOf(const struct timespec& t);           // a FILETIME's 100 ns since 1601

// ---- paths (Paths.cpp) --------------------------------------------------------------------------
// a Windows path the reference names (drive, backslashes, any case) as the host's file: the game
// directory stands for every drive's root
std::string HostPath(const std::string& windows, bool forCreate = false);
std::string HostPath16(const char16_t* windows, bool forCreate = false);
void SetGameRoot(const std::string& dir);
const std::string& GameRoot();
std::u16string CurrentDirectory();
bool SetCurrentDirectory16(const std::u16string& dir);
std::u16string FullPath(const std::u16string& p);
uint32_t ErrnoToWin(int e);

// ---- the Win32 personality: a function per import ------------------------------------------------
// gen_real_<name> takes 14 intptr_t (imports.c: a0..a3 and ten more words); a personality function
// takes the 32-bit words it has, typed uint32_t, and returns one. RH_REG(dll, name, fn) wraps `fn`
// as that 14-word function and registers it under <name> for RefImage's import fill and GetProcAddress.
using RealFn = intptr_t (*)(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t,
                            intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t);
struct ApiEntry {
    const char* dll;
    const char* name;
    RealFn real;
    const void* direct;   // the typed function itself, for GetProcAddress's island
    ApiEntry* next;
};
ApiEntry*& ApiList();
struct ApiRegister {
    ApiRegister(ApiEntry* e) {
        e->next = ApiList();
        ApiList() = e;
    }
};
const ApiEntry* FindApi(const char* name);

template <typename F>
struct Arity;
template <typename R, typename... A>
struct Arity<R (*)(A...)> {
    static constexpr size_t value = sizeof...(A);
    using Ret = R;
};
template <auto F, size_t... I>
intptr_t CallWords(const intptr_t* a, std::index_sequence<I...>) {
    using R = typename Arity<decltype(F)>::Ret;
    if constexpr (std::is_void_v<R>) {
        F(static_cast<uint32_t>(a[I])...);
        return 0;
    } else {
        return static_cast<intptr_t>(static_cast<uint32_t>(F(static_cast<uint32_t>(a[I])...)));
    }
}
template <auto F>
intptr_t Real(intptr_t a0, intptr_t a1, intptr_t a2, intptr_t a3, intptr_t a4, intptr_t a5, intptr_t a6, intptr_t a7,
              intptr_t a8, intptr_t a9, intptr_t a10, intptr_t a11, intptr_t a12, intptr_t a13) {
    const intptr_t a[14] = {a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13};
    static_assert(Arity<decltype(F)>::value <= 14, "an import takes 14 words at most");
    return CallWords<F>(a, std::make_index_sequence<Arity<decltype(F)>::value>{});
}

}  // namespace rh

// A personality function is written plainly, `static uint32_t CloseHandle_(uint32_t h) {...}`, and
// registered after its body: RH_REG(KERNEL32, CloseHandle, CloseHandle_). The registration is a
// static object, so these files are compiled into the library itself (never an archive the linker
// could drop them from: Runtime32Posix.cmake)
#define RH_API_CAT(a, b) a##b
#define RH_REG(dll, name, fn)                                                                     \
    static rh::ApiEntry RH_API_CAT(rh_entry_, name) = {#dll, #name, &rh::Real<fn>,                \
                                                       reinterpret_cast<const void*>(fn), nullptr}; \
    static rh::ApiRegister RH_API_CAT(rh_reg_, name)(&RH_API_CAT(rh_entry_, name));

// a stub: logged on its first call, `ret` returned (SetLastError(err) when err != 0)
#define RH_STUB(dll, name, nargs, ret, err)                                                      \
    static uint32_t RH_API_CAT(stub_, name)(RH_STUB_ARGS_##nargs) {                               \
        rh::LogOnce(#name, "%s!%s: not implemented, returns %#x", #dll, #name, (unsigned)(ret));   \
        if (err) rh::SetLastError(err);                                                           \
        return (ret);                                                                             \
    }                                                                                             \
    RH_REG(dll, name, RH_API_CAT(stub_, name))
#define RH_STUB_ARGS_0 void
#define RH_STUB_ARGS_1 uint32_t
#define RH_STUB_ARGS_2 uint32_t, uint32_t
#define RH_STUB_ARGS_3 uint32_t, uint32_t, uint32_t
#define RH_STUB_ARGS_4 uint32_t, uint32_t, uint32_t, uint32_t
#define RH_STUB_ARGS_5 uint32_t, uint32_t, uint32_t, uint32_t, uint32_t
#define RH_STUB_ARGS_6 uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t
#define RH_STUB_ARGS_7 uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t
#define RH_STUB_ARGS_8 uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t
#define RH_STUB_ARGS_9 uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t
#define RH_STUB_ARGS_10 uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t

// Win32's numbers the personality uses
namespace win {
constexpr uint32_t ERROR_SUCCESS = 0, ERROR_FILE_NOT_FOUND = 2, ERROR_PATH_NOT_FOUND = 3, ERROR_ACCESS_DENIED = 5,
                   ERROR_INVALID_HANDLE = 6, ERROR_NOT_ENOUGH_MEMORY = 8, ERROR_NO_MORE_FILES = 18,
                   ERROR_HANDLE_EOF = 38, ERROR_NOT_SUPPORTED = 50, ERROR_FILE_EXISTS = 80,
                   ERROR_INVALID_PARAMETER = 87, ERROR_INSUFFICIENT_BUFFER = 122, ERROR_MOD_NOT_FOUND = 126,
                   ERROR_PROC_NOT_FOUND = 127, ERROR_ALREADY_EXISTS = 183, ERROR_ENVVAR_NOT_FOUND = 203,
                   ERROR_MORE_DATA = 234, ERROR_NO_MORE_ITEMS = 259, ERROR_NOT_OWNER = 288,
                   ERROR_IO_PENDING = 997, ERROR_CALL_NOT_IMPLEMENTED = 120, ERROR_DIR_NOT_EMPTY = 145;
constexpr uint32_t WAIT_OBJECT_0 = 0, WAIT_ABANDONED = 0x80, WAIT_TIMEOUT = 258, WAIT_FAILED = 0xFFFFFFFFu,
                   INFINITE = 0xFFFFFFFFu;
constexpr uint32_t S_OK = 0, S_FALSE = 1, E_NOTIMPL = 0x80004001u, E_NOINTERFACE = 0x80004002u,
                   E_POINTER = 0x80004003u, E_FAIL = 0x80004005u, E_INVALIDARG = 0x80070057u,
                   E_OUTOFMEMORY = 0x8007000Eu, REGDB_E_CLASSNOTREG = 0x80040154u;
}  // namespace win
