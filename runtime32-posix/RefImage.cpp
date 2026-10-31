// The reference's image in the port's process (runtime32/RefImage.cpp's counterpart for arm64):
// its sections at their own addresses below 2 GB, a branch at each function's entry to its
// translation, its import slots holding the personality's adapters, its TLS template, and its entry
// run on a thread whose stack is below 2 GB.
//
// Calls into the reference's code. The generated code calls a reference address as a native
// function (`((code *)*(gen_code32 *)slot)(...)`), and the runtime does too. The reference's code is
// never run, so its .text is free for the port's use:
//   - every 4-aligned word a trap, `brk #0xcc` (an unknown address called: logged, 0 returned);
//   - at each 4-aligned function entry a `b` to that function's island entry (Islands.cpp), placed
//     just after the image within a branch's 128 MB, which jumps on to the translation;
//   - a function whose entry is not 4-aligned (1,269 of CrystalCore's 87,623) cannot hold an
//     instruction: a call there faults at once, PC alignment, SIGBUS BUS_ADRALN with the PC the
//     entry and LR already the return address, and the handler below sends the PC to the
//     translation (logged, counted: a slow path). The same for an entry whose word is the code
//     section's data the translation reads (g_genTextData), its trap word kept as the data.
#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include <signal.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <fstream>
#include <vector>

#include "Runtime.h"

extern "C" {
struct GEN_JUMP {
    unsigned int ref;
    void* port;
};
extern const GEN_JUMP g_genJumps[];
extern const unsigned int g_genJumpCount;
extern const unsigned int g_genTextData[];

typedef intptr_t (*gen_real_fn)(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t,
                                intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t);
struct GEN_IMPORT {
    unsigned int slot;
    const char* dll;
    const char* name;
    void* adapter;
    gen_real_fn* real;
};
extern const GEN_IMPORT g_genImports[];
extern const unsigned int g_genImportCount;

uint32_t gen_ref_base = 0x400000;
void GenUnimplemented(unsigned int address);
}

namespace rh {

void RefTraceStart();   // Trace.cpp
void RefTraceFlush();
void PrintBacktrace(uintptr_t fp, uintptr_t pc, uintptr_t lr);
int SehHardwareFault(int sig, siginfo_t* info, ucontext_t* uc);   // Eh.cpp

namespace {

// ---- the PE file, as x86 lays it out ------------------------------------------------------------
#pragma pack(push, 1)
struct DosHeader {
    uint16_t e_magic;
    uint8_t pad[58];
    int32_t e_lfanew;
};
struct FileHeader {
    uint16_t Machine, NumberOfSections;
    uint32_t TimeDateStamp, PointerToSymbolTable, NumberOfSymbols;
    uint16_t SizeOfOptionalHeader, Characteristics;
};
struct DataDir {
    uint32_t VirtualAddress, Size;
};
struct OptionalHeader32 {
    uint16_t Magic;
    uint8_t MajorLinkerVersion, MinorLinkerVersion;
    uint32_t SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData, AddressOfEntryPoint, BaseOfCode, BaseOfData;
    uint32_t ImageBase, SectionAlignment, FileAlignment;
    uint16_t MajorOsVersion, MinorOsVersion, MajorImageVersion, MinorImageVersion, MajorSubsystemVersion,
        MinorSubsystemVersion;
    uint32_t Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum;
    uint16_t Subsystem, DllCharacteristics;
    uint32_t SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit, LoaderFlags,
        NumberOfRvaAndSizes;
    DataDir Dirs[16];
};
struct NtHeaders32 {
    uint32_t Signature;
    FileHeader File;
    OptionalHeader32 Opt;
};
struct SectionHeader {
    char Name[8];
    uint32_t VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData, PointerToRelocations,
        PointerToLinenumbers;
    uint16_t NumberOfRelocations, NumberOfLinenumbers;
    uint32_t Characteristics;
};
struct TlsDirectory32 {
    uint32_t StartAddressOfRawData, EndAddressOfRawData, AddressOfIndex, AddressOfCallBacks, SizeOfZeroFill,
        Characteristics;
};
#pragma pack(pop)
static_assert(sizeof(OptionalHeader32) == 224, "IMAGE_OPTIONAL_HEADER32");
static_assert(sizeof(SectionHeader) == 40, "IMAGE_SECTION_HEADER");
static_assert(sizeof(TlsDirectory32) == 24, "IMAGE_TLS_DIRECTORY32");

constexpr uint32_t kScnExecute = 0x20000000, kScnWrite = 0x80000000;
constexpr uint32_t kBrkCC = 0xd4201980u;   // brk #0xcc: the reference's code, never run

uint32_t g_size = 0, g_textLo = 0, g_textHi = 0, g_entry = 0;
std::string g_hostPath;
std::u16string g_modulePath;

// the jump table, sorted by reference address: the fault handler's lookup (no allocation, no lock)
std::vector<GEN_JUMP> g_byRef;
// and by port address, for the crash report's names
std::vector<GEN_JUMP> g_byPort;
std::atomic<uint64_t> g_slowCalls{0};
std::atomic<uint32_t> g_slowLogged{0};

// the port's own .so: [lo, hi)
uintptr_t g_portLo = 0, g_portHi = 0;

void FindPortRange() {
    Dl_info info;
    if (!dladdr(reinterpret_cast<void*>(&FindPortRange), &info)) return;
    struct Ctx {
        uintptr_t base, lo, hi;
    } ctx{reinterpret_cast<uintptr_t>(info.dli_fbase), 0, 0};
    dl_iterate_phdr(
        [](dl_phdr_info* pi, size_t, void* p) {
            auto c = static_cast<Ctx*>(p);
            uintptr_t lo = UINTPTR_MAX, hi = 0;
            for (int k = 0; k < pi->dlpi_phnum; k++) {
                const auto& ph = pi->dlpi_phdr[k];
                if (ph.p_type != PT_LOAD) continue;
                lo = std::min<uintptr_t>(lo, pi->dlpi_addr + ph.p_vaddr);
                hi = std::max<uintptr_t>(hi, pi->dlpi_addr + ph.p_vaddr + ph.p_memsz);
            }
            if (lo <= c->base && c->base < hi) {
                c->lo = lo;
                c->hi = hi;
                return 1;
            }
            return 0;
        },
        &ctx);
    g_portLo = ctx.lo;
    g_portHi = ctx.hi;
}

const GEN_JUMP* FindRef(uint32_t ref) {
    auto it = std::lower_bound(g_byRef.begin(), g_byRef.end(), ref,
                               [](const GEN_JUMP& j, uint32_t r) { return j.ref < r; });
    return it != g_byRef.end() && it->ref == ref ? &*it : nullptr;
}

bool InTextData(uint32_t lo, uint32_t hi) {
    for (const unsigned int* d = g_genTextData; d[0]; d += 2)
        if (lo < d[1] && d[0] < hi) return true;
    return false;
}

bool ReadAll(const char* path, std::vector<uint8_t>* out) {
    FILE* f = fopen(path, "rb");
    if (!f) return false;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    out->resize(n > 0 ? static_cast<size_t>(n) : 0);
    bool ok = n > 0 && fread(out->data(), 1, out->size(), f) == out->size();
    fclose(f);
    return ok;
}

// ---- imports with no personality function: each a stub of its own, so the log names it ---------
constexpr unsigned kMaxMissing = 512;
const GEN_IMPORT* g_missing[kMaxMissing];
template <unsigned K>
intptr_t Missing(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t,
                 intptr_t, intptr_t, intptr_t, intptr_t) {
    const GEN_IMPORT* im = g_missing[K];
    LogOnce(im->name, "import %s!%s has no personality function: 0 returned", im->dll, im->name);
    return 0;
}
template <unsigned... K>
constexpr std::array<gen_real_fn, sizeof...(K)> MissingTable(std::integer_sequence<unsigned, K...>) {
    return {&Missing<K>...};
}
const auto g_missingFns = MissingTable(std::make_integer_sequence<unsigned, kMaxMissing>{});

// ---- faults ------------------------------------------------------------------------------------
thread_local bool t_inReport = false;

void Report(int sig, siginfo_t* info, ucontext_t* uc) {
    char line[256];
    auto& m = uc->uc_mcontext;
    snprintf(line, sizeof line, "%s: signal %d (code %d) at pc %llx, address %p, thread %u", RHIPPER_NAME, sig,
             info->si_code, static_cast<unsigned long long>(m.pc), info->si_addr, CurrentThreadId());
    LogRaw(line);
    for (int k = 0; k < 31; k += 4) {
        snprintf(line, sizeof line, "  x%-2d %016llx %016llx %016llx %016llx", k,
                 static_cast<unsigned long long>(m.regs[k]), static_cast<unsigned long long>(m.regs[k + 1]),
                 static_cast<unsigned long long>(k + 2 < 31 ? m.regs[k + 2] : 0),
                 static_cast<unsigned long long>(k + 3 < 31 ? m.regs[k + 3] : m.sp));
        LogRaw(line);
    }
    PrintBacktrace(m.regs[29], m.pc, m.regs[30]);
}

void OnFault(int sig, siginfo_t* info, void* ctx) {
    auto uc = static_cast<ucontext_t*>(ctx);
    uint64_t pc = uc->uc_mcontext.pc;
    // a call to a reference function the branch at its entry could not reach (an unaligned entry,
    // or one whose word is data): its translation, entered with the caller's registers as they are
    if (pc >= g_textLo && pc < g_textHi && (sig == SIGBUS || sig == SIGTRAP || sig == SIGILL || sig == SIGSEGV)) {
        if (const GEN_JUMP* j = FindRef(static_cast<uint32_t>(pc))) {
            uc->uc_mcontext.pc = reinterpret_cast<uint64_t>(j->port);
            uint64_t n = ++g_slowCalls;
            if ((n & (n - 1)) == 0 && g_slowLogged++ < 24) {
                char line[128];
                snprintf(line, sizeof line, "%s: %llu calls by the slow path so far (the last %08llx)", RHIPPER_NAME,
                         static_cast<unsigned long long>(n), static_cast<unsigned long long>(pc));
                LogRaw(line);
            }
            return;
        }
        // (a trap: an address no translation covers was called. Logged once, 0 returned to the
        // caller, as the x64 runtime's int3)
        if (sig == SIGTRAP || sig == SIGILL || sig == SIGBUS) {
            GenUnimplemented(static_cast<uint32_t>(pc));
            uc->uc_mcontext.regs[0] = 0;
            uc->uc_mcontext.pc = uc->uc_mcontext.regs[30];
            return;
        }
    }
    // (a fault in translated code inside a reference __try: its filter's, Eh.cpp)
    if (SehHardwareFault(sig, info, uc)) return;
    if (!t_inReport) {
        t_inReport = true;
        Report(sig, info, uc);
        RefTraceFlush();
        LogFlush();
    }
    // (the default action, the system's tombstone after ours)
    signal(sig, SIG_DFL);
}

void InstallHandlers() {
    struct sigaction sa = {};
    sa.sa_sigaction = OnFault;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    for (int sig : {SIGSEGV, SIGBUS, SIGILL, SIGTRAP, SIGFPE}) sigaction(sig, &sa, nullptr);
}

}  // namespace

// (each thread that runs reference code: a signal stack of its own, a fault there reported even
// when the thread's own stack is what overflowed)
void ThreadSignalStack() {
    static thread_local bool done = false;
    if (done) return;
    done = true;
    stack_t ss = {};
    ss.ss_size = 64 * 1024;
    ss.ss_sp = malloc(ss.ss_size);
    sigaltstack(&ss, nullptr);
}

uintptr_t PortOrLow(uintptr_t raw) {
    if (g_portHi && raw >= g_portLo && raw < g_portHi) return raw;
    return static_cast<uint32_t>(raw);
}

bool InPort(uintptr_t pc) { return pc >= g_portLo && pc < g_portHi; }

uint32_t RefImageSize() { return g_size; }
bool InImage(uint32_t a) { return a >= gen_ref_base && a - gen_ref_base < g_size; }
bool InText(uint32_t a) { return a >= g_textLo && a < g_textHi; }
void* PortOf(uint32_t ref) {
    const GEN_JUMP* j = FindRef(ref);
    return j ? j->port : nullptr;
}
const std::u16string& RefModulePath() { return g_modulePath; }
const std::string& RefHostPath() { return g_hostPath; }

// a native pc as the reference function it is in: its translation's F_ name where the .so exports
// it, else the nearest translation below it in the jump table (approximate: "~")
void NamePc(uintptr_t pc, char* out, size_t n) {
    Dl_info info;
    if (dladdr(reinterpret_cast<void*>(pc), &info) && info.dli_sname) {
        snprintf(out, n, "%s+0x%lx", info.dli_sname, static_cast<unsigned long>(pc - reinterpret_cast<uintptr_t>(info.dli_saddr)));
        return;
    }
    auto it = std::upper_bound(g_byPort.begin(), g_byPort.end(), pc, [](uintptr_t p, const GEN_JUMP& j) {
        return p < reinterpret_cast<uintptr_t>(j.port);
    });
    if (InPort(pc) && it != g_byPort.begin()) {
        --it;
        snprintf(out, n, "~F_%08x+0x%lx", it->ref, static_cast<unsigned long>(pc - reinterpret_cast<uintptr_t>(it->port)));
        return;
    }
    snprintf(out, n, "%s", info.dli_fname ? info.dli_fname : "?");
}

bool RefMapImage(const char* path) {
    InstallHandlers();
    ThreadSignalStack();
    FindPortRange();
    LowReserve();
    std::vector<uint8_t> file;
    if (!ReadAll(path, &file) || file.size() < sizeof(DosHeader)) {
        Log("cannot read the reference %s", path);
        return false;
    }
    auto dos = reinterpret_cast<const DosHeader*>(file.data());
    if (dos->e_magic != 0x5a4d || file.size() < dos->e_lfanew + sizeof(NtHeaders32)) {
        Log("%s is no PE file", path);
        return false;
    }
    NtHeaders32 nt;
    memcpy(&nt, file.data() + dos->e_lfanew, sizeof nt);
    if (nt.Signature != 0x4550 || nt.Opt.Magic != 0x10b) {
        Log("%s is no 32-bit PE image", path);
        return false;
    }
    auto sections = reinterpret_cast<const SectionHeader*>(file.data() + dos->e_lfanew + 4 + sizeof(FileHeader) +
                                                           nt.File.SizeOfOptionalHeader);
    const uint32_t base = nt.Opt.ImageBase, size = nt.Opt.SizeOfImage;
    gen_ref_base = base;
    g_size = size;
    g_hostPath = path;
    // (at its own base or nowhere: the translation addresses its globals there)
    if (!LowClaim(base, size)) {
        Log("the reference's range %08x-%08x is not free in this process (see the map above)", base, base + size);
        return false;
    }
    auto image = At<uint8_t>(base);
    memcpy(image, file.data(), std::min<size_t>(nt.Opt.SizeOfHeaders, file.size()));
    std::vector<std::pair<uint32_t, uint32_t>> writable;
    for (unsigned k = 0; k < nt.File.NumberOfSections; k++) {
        const SectionHeader& s = sections[k];
        uint32_t raw = std::min(s.SizeOfRawData, s.VirtualSize ? s.VirtualSize : s.SizeOfRawData);
        if (raw && s.PointerToRawData + raw <= file.size()) memcpy(image + s.VirtualAddress, file.data() + s.PointerToRawData, raw);
        if (s.Characteristics & kScnExecute) {
            g_textLo = base + s.VirtualAddress;
            g_textHi = g_textLo + s.VirtualSize;
        }
        if (s.Characteristics & kScnWrite) writable.emplace_back(base + s.VirtualAddress, base + s.VirtualAddress + s.VirtualSize);
    }
    g_entry = base + nt.Opt.AddressOfEntryPoint;
    // its TLS: one module, index 0 of each thread's array (Hooks.cpp's gen_tls_array)
    extern uint32_t g_tlsStart, g_tlsEnd, g_tlsZero;
    if (nt.Opt.Dirs[9].Size) {
        auto tls = At<TlsDirectory32>(base + nt.Opt.Dirs[9].VirtualAddress);
        g_tlsStart = tls->StartAddressOfRawData;
        g_tlsEnd = tls->EndAddressOfRawData;
        g_tlsZero = tls->SizeOfZeroFill;
        if (tls->AddressOfIndex) *At<uint32_t>(tls->AddressOfIndex) = 0;
        if (tls->AddressOfCallBacks && U32(tls->AddressOfCallBacks))
            Log("the reference has TLS callbacks (%08x...): not called, as on x64", U32(tls->AddressOfCallBacks));
    }

    // the code section: traps, its data where the translation reads it, a branch at each entry
    const uint32_t textLo4 = (g_textLo + 3) & ~3u, textHi4 = g_textHi & ~3u;
    for (uint32_t a = textLo4; a < textHi4; a += 4) *At<uint32_t>(a) = kBrkCC;
    unsigned kept = 0;
    for (const unsigned int* d = g_genTextData; d[0]; d += 2) {
        for (unsigned k = 0; k < nt.File.NumberOfSections; k++) {
            const SectionHeader& s = sections[k];
            if (d[0] - base >= s.VirtualAddress && d[1] - base <= s.VirtualAddress + s.SizeOfRawData) {
                memcpy(image + (d[0] - base), file.data() + s.PointerToRawData + (d[0] - base - s.VirtualAddress), d[1] - d[0]);
                kept += d[1] - d[0];
                break;
            }
        }
    }
    g_byRef.assign(g_genJumps, g_genJumps + g_genJumpCount);
    std::sort(g_byRef.begin(), g_byRef.end(), [](const GEN_JUMP& a, const GEN_JUMP& b) { return a.ref < b.ref; });
    g_byPort = g_byRef;
    std::sort(g_byPort.begin(), g_byPort.end(), [](const GEN_JUMP& a, const GEN_JUMP& b) { return a.port < b.port; });
    IslandsNearImage(base + size, g_genJumpCount);
    unsigned written = 0, unaligned = 0, onData = 0, far = 0;
    for (const GEN_JUMP& j : g_byRef) {
        if (j.ref < g_textLo || j.ref + 4 > g_textHi) continue;
        if (j.ref & 3) {
            unaligned++;
            continue;
        }
        if (InTextData(j.ref, j.ref + 4)) {
            onData++;
            continue;
        }
        uint32_t island = IslandNear(j.port);
        int64_t rel = static_cast<int64_t>(island) - static_cast<int64_t>(j.ref);
        if (!island || rel < -(1ll << 27) || rel >= (1ll << 27)) {
            far++;
            continue;
        }
        *At<uint32_t>(j.ref) = 0x14000000u | (static_cast<uint32_t>(rel >> 2) & 0x03FFFFFFu);
        written++;
    }

    // the import slots: each holds a low address of its adapter; each adapter's real function is the
    // personality's (or a stub that names the import)
    unsigned resolved = 0, missing = 0;
    for (unsigned k = 0; k < g_genImportCount; k++) {
        const GEN_IMPORT& im = g_genImports[k];
        *At<uint32_t>(im.slot) = Island(im.adapter);
        if (im.real == nullptr) {   // (an adapter of the runtime's own: gen_imp_<name> is defined here)
            resolved++;
            continue;
        }
        if (const ApiEntry* api = FindApi(im.name)) {
            *im.real = api->real;
            resolved++;
        } else {
            if (missing < kMaxMissing) {
                g_missing[missing] = &im;
                *im.real = g_missingFns[missing];
            }
            missing++;
            Log("import %s!%s: no personality function (a logged stub)", im.dll, im.name);
        }
    }

    // read-execute over the code section (its host pages): a page it shares with a writable
    // section read-write-execute instead
    const size_t page = PageSize();
    uintptr_t lo = g_textLo & ~(page - 1), hi = (g_textHi + page - 1) & ~(page - 1);
    bool shared = false;
    for (auto& [wlo, whi] : writable)
        if (wlo < hi && lo < whi) shared = true;
    if (mprotect(At(static_cast<uint32_t>(lo)), hi - lo, PROT_READ | PROT_EXEC | (shared ? PROT_WRITE : 0)) != 0)
        Log("the code section's protection failed (%d)", errno);
    if (shared) Log("the code section shares a page with a writable section: read-write-execute there");
    __builtin___clear_cache(At<char>(static_cast<uint32_t>(lo)), At<char>(static_cast<uint32_t>(hi)));

    // its path as the reference sees it: under the game root, C:\ (Paths.cpp)
    std::string root = GameRoot(), p = path;
    std::string rel = (!root.empty() && p.compare(0, root.size(), root) == 0) ? p.substr(root.size()) : p.substr(p.rfind('/') + 1);
    while (!rel.empty() && rel[0] == '/') rel.erase(0, 1);
    for (char& c : rel)
        if (c == '/') c = '\\';
    g_modulePath = Widen(("C:\\" + rel).c_str());

    Log("reference mapped at %08x (%#x bytes), code %08x-%08x: %u entry branches, %u unaligned and %u on data "
        "(the slow path), %u out of reach; %u bytes of code data kept; %u imports resolved, %u stubbed; port .so "
        "%lx-%lx", base, size, g_textLo, g_textHi, written, unaligned, onData, far, kept, resolved, missing,
        static_cast<unsigned long>(g_portLo), static_cast<unsigned long>(g_portHi));
    return true;
}

namespace {
int g_exitCode = 0;
pthread_t g_mainThread;
bool g_mainStarted = false;

void RefMain(void*) {
    // the reference's entry point, its CRT startup (WinMainCRTStartup), through its translation
    g_exitCode = static_cast<int>(CallRef(g_entry));
}
}  // namespace

// ExitProcess on the reference's main thread: its end (kernel32_thread.cpp)
void RefExit(int code) { g_exitCode = code; }
int RefExitCode() { return g_exitCode; }

int RefRun() {
    Log("running the reference's entry %08x", g_entry);
    RefTraceStart();
    uint32_t tid = 0;
    // (32 MB, as the x64 runtime's: translated frames are larger than the reference's)
    uint32_t h = StartLowThread(RefMain, nullptr, 32u << 20, false, &tid);
    if (!h) {
        Log("cannot start the reference's thread");
        return -1;
    }
    uint32_t hs[1] = {h};
    WaitAny(hs, 1, false, win::INFINITE, 0);
    RefTraceFlush();
    Log("the reference's thread ended: %d (%llu calls by the slow path)", g_exitCode,
        static_cast<unsigned long long>(g_slowCalls.load()));
    LogFlush();
    return g_exitCode;
}

}  // namespace rh

using namespace rh;

// ---- the module functions: the reference's own image, and names it looks up ---------------------
namespace {

// a library the reference loads: a module handle of its own, 64 KB of zeros below 2 GB (a handle a
// caller may read a header from)
std::mutex g_modLock;
std::vector<std::pair<std::string, uint32_t>> g_modules;

std::string LowerFile(const std::string& name) {
    std::string f = name.substr(name.find_last_of("\\/") == std::string::npos ? 0 : name.find_last_of("\\/") + 1);
    for (char& c : f) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    if (f.find('.') == std::string::npos) f += ".dll";
    return f;
}

bool KnownLibrary(const std::string& f) {
    for (unsigned k = 0; k < g_genImportCount; k++) {
        std::string d = LowerFile(g_genImports[k].dll);
        if (d == f) return true;
    }
    static const char* const more[] = {"ntdll.dll", "kernel32.dll", "user32.dll", "gdi32.dll", "advapi32.dll",
                                       "shell32.dll", "ole32.dll", "oleaut32.dll", "ws2_32.dll", "winmm.dll",
                                       "d3d9.dll", "dinput8.dll", "xinput1_3.dll", "kernelbase.dll"};
    for (const char* m : more)
        if (f == m) return true;
    return false;
}

uint32_t ModuleFor(const std::string& name, bool load) {
    std::string f = LowerFile(name);
    std::lock_guard<std::mutex> hold(g_modLock);
    for (auto& [n, h] : g_modules)
        if (n == f) return h;
    if (!KnownLibrary(f)) {
        LogOnce(("module " + f).c_str(), "%s(%s): no such library here", load ? "LoadLibrary" : "GetModuleHandle",
                name.c_str());
        SetLastError(win::ERROR_MOD_NOT_FOUND);
        return 0;
    }
    // (GetModuleHandle of a known library answers as LoadLibrary would: the reference's imports are
    // loaded from the start on Windows)
    uint32_t h = LowAlloc(0x10000);
    g_modules.emplace_back(f, h);
    Log("module %s: handle %08x", f.c_str(), h);
    return h;
}

std::string ModuleName(uint32_t h) {
    std::lock_guard<std::mutex> hold(g_modLock);
    for (auto& [n, m] : g_modules)
        if (m == h) return n;
    return "";
}

}  // namespace

extern "C" {

// (the string parameters as uintptr_t: the generated code passes its own literals, high, here)
unsigned int gen_imp_GetModuleHandleA(uintptr_t name) {
    if (!PortOrLow(name)) return gen_ref_base;
    return ModuleFor(Str(name), false);
}
unsigned int gen_imp_GetModuleHandleW(uintptr_t name) {
    if (!PortOrLow(name)) return gen_ref_base;
    return ModuleFor(Narrow(WStr(name)), false);
}
unsigned int gen_imp_LoadLibraryA(uintptr_t name) {
    if (!PortOrLow(name)) return 0;
    return ModuleFor(Str(name), true);
}
static uint32_t LoadLibraryW_(uint32_t name) { return name ? ModuleFor(Narrow(At<char16_t>(name)), true) : 0; }
RH_REG(KERNEL32, LoadLibraryW, LoadLibraryW_)
static uint32_t FreeLibrary_(uint32_t) { return 1; }
RH_REG(KERNEL32, FreeLibrary, FreeLibrary_)

// GetProcAddress: a function the reference resolves at run time goes through the adapter its import
// would (the slot's), or the personality's own, through a low island; one there is none of, 0
unsigned int gen_imp_GetProcAddress(uint32_t module, uintptr_t name) {
    uintptr_t n = PortOrLow(name);
    if (n < 0x10000) {
        LogOnce("GetProcAddress-ordinal", "GetProcAddress(%08x, ordinal %lu): no ordinals", module,
                static_cast<unsigned long>(n));
        SetLastError(win::ERROR_PROC_NOT_FOUND);
        return 0;
    }
    const char* s = reinterpret_cast<const char*>(n);
    for (unsigned k = 0; k < g_genImportCount; k++)
        if (strcmp(g_genImports[k].name, s) == 0) return Island(g_genImports[k].adapter);
    if (const ApiEntry* api = FindApi(s)) return Island(api->direct);
    LogOnce((std::string("GetProcAddress ") + s).c_str(), "GetProcAddress(%s, %s): none, 0 (its fallback)",
            module == gen_ref_base ? "the reference" : ModuleName(module).c_str(), s);
    SetLastError(win::ERROR_PROC_NOT_FOUND);
    return 0;
}

static unsigned int ModuleFileName(uint32_t module, char16_t* out16, char* out8, uint32_t n) {
    std::u16string full = module == 0 || module == gen_ref_base ? RefModulePath()
                                                                : u"C:\\Windows\\system32\\" + Widen(ModuleName(module).c_str());
    if (n == 0) return 0;
    size_t len = full.size(), k = len < n ? len : n - 1;
    for (size_t i = 0; i < k; i++) {
        if (out16) out16[i] = full[i];
        else out8[i] = static_cast<char>(full[i] < 0x80 ? full[i] : '?');
    }
    if (out16) out16[k] = 0;
    else out8[k] = 0;
    if (len >= n) {
        SetLastError(win::ERROR_INSUFFICIENT_BUFFER);
        return n;
    }
    return static_cast<unsigned int>(len);
}
unsigned int gen_imp_GetModuleFileNameW(uint32_t module, uint32_t buf, uint32_t n) {
    return ModuleFileName(module, At<char16_t>(buf), nullptr, n);
}
unsigned int gen_imp_GetModuleFileNameA(uint32_t module, uint32_t buf, uint32_t n) {
    return ModuleFileName(module, nullptr, At<char>(buf), n);
}

}  // extern "C"

// psapi: the process is the reference's image alone
static uint32_t EnumProcessModules_(uint32_t process, uint32_t mods, uint32_t cb, uint32_t needed) {
    (void)process;
    if (needed) *At<uint32_t>(needed) = 4;
    if (mods && cb >= 4) *At<uint32_t>(mods) = gen_ref_base;
    return 1;
}
RH_REG(PSAPI, EnumProcessModules, EnumProcessModules_)
static uint32_t GetModuleFileNameExA_(uint32_t, uint32_t module, uint32_t buf, uint32_t n) {
    return ModuleFileName(module, nullptr, At<char>(buf), n);
}
RH_REG(PSAPI, GetModuleFileNameExA, GetModuleFileNameExA_)
static uint32_t EnumProcesses_(uint32_t ids, uint32_t cb, uint32_t needed) {
    if (ids && cb >= 4) *At<uint32_t>(ids) = static_cast<uint32_t>(getpid());
    if (needed) *At<uint32_t>(needed) = 4;
    return 1;
}
RH_REG(PSAPI, EnumProcesses, EnumProcesses_)
