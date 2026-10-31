// The reference's exceptions: x86 SEH dispatch over its fs:[0] chain (Ghidra32.h gen_eh_*), as
// runtime32/Adapters.cpp does it; the same algorithm, with nothing of Windows under it. The frames'
// nodes are the reference's x86 ones in the translated functions' frames (below 2 GB), the handlers
// vcruntime's C++ one (FuncInfo, by its thunk: jumps.c's g_genEhFuncInfo) and the CRT's EH4 and EH3
// ones (their scope tables), and funclets are reference addresses whose translations run on their
// frame's ebp. See Adapters.cpp for the history behind each check.
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>

#include <csetjmp>
#include <memory>
#include <mutex>
#include <vector>

#include "Runtime.h"

extern "C" const unsigned int g_genEhFuncInfo[];   // gen/jumps.c
extern "C" unsigned int gen_teb32(void);
extern "C" int gen_teb32_made(void);

namespace rh {
void RefTraceFlush();
void PrintHere();
void PrintBacktrace(uintptr_t fp, uintptr_t pc, uintptr_t lr);
bool InPort(uintptr_t pc);
}  // namespace rh

using namespace rh;

namespace eh {

constexpr uint32_t kCxxCode = 0xE06D7363;
constexpr uint32_t kEndOfChain = 0xFFFFFFFF;
constexpr int32_t kTryNone = -2;
constexpr int32_t kTryNone3 = -1;

uint32_t U(uint32_t a) { return *At<uint32_t>(a); }
int32_t I(uint32_t a) { return *At<int32_t>(a); }

bool Tracing() {
    static int on = -1;
    if (on < 0) on = getenv("RH_EHTRACE") != nullptr;
    return on != 0;
}
uint32_t Call1(uint32_t ref, uint32_t a0) {
    if (Tracing()) Log("eh: call %08X (%08X)", ref, a0);
    return CallRef(ref, a0);
}

[[noreturn]] void Die(uint32_t code) {
    RefTraceFlush();
    LogFlush();
    _exit(static_cast<int>(code & 0xFF ? code & 0xFF : 3));
}

uint32_t& Head() { return *At<uint32_t>(gen_teb32()); }

uint32_t Cookie() {
    uint32_t pe = gen_ref_base + U(gen_ref_base + 0x3C);
    uint32_t dir = U(pe + 0x18 + 0x60 + 10 * 8);
    if (dir == 0 || U(pe + 0x18 + 0x60 + 10 * 8 + 4) < 0x40) return 0;
    uint32_t va = U(gen_ref_base + dir + 0x3C);
    return va ? U(va) : 0;
}

uint32_t FuncInfoOf(uint32_t handler) {
    for (const unsigned int* p = g_genEhFuncInfo; p[0]; p += 2)
        if (p[0] == handler) return p[1];
    return 0;
}

uint32_t ScopeTableOf(uint32_t node) {
    uint32_t st = U(node + 8) ^ Cookie();
    int32_t level = I(node + 0xC);
    if (!InImage(st) || level < kTryNone || level > 0x400) return 0;
    for (int32_t l = level; l != kTryNone;) {
        uint32_t rec = st + 0x10 + 12 * l;
        if (!InImage(rec) || (U(rec + 4) && !InImage(U(rec + 4))) || !InImage(U(rec + 8))) return 0;
        int32_t enclosing = I(rec);
        if (enclosing >= l) return 0;
        l = enclosing;
    }
    return st;
}

uint32_t ScopeTable3Of(uint32_t node) {
    uint32_t st = U(node + 8);
    int32_t level = I(node + 0xC);
    if (!InImage(st) || level < kTryNone3 || level > 0x400) return 0;
    for (int32_t l = level; l != kTryNone3;) {
        uint32_t rec = st + 12 * l;
        if (!InImage(rec) || (U(rec + 4) && !InImage(U(rec + 4))) || !InImage(U(rec + 8))) return 0;
        int32_t enclosing = I(rec);
        if (enclosing >= l) return 0;
        l = enclosing;
    }
    return st;
}

void LocalUnwind3(uint32_t node, uint32_t st, int32_t target) {
    uint32_t ebp = node + 0x10;
    int32_t level = I(node + 0xC);
    while (level != kTryNone3 && level != target) {
        uint32_t rec = st + 12 * level;
        int32_t enclosing = I(rec);
        *At<int32_t>(node + 0xC) = enclosing;
        if (U(rec + 4) == 0) Call1(U(rec + 8), ebp);
        level = enclosing;
    }
}

struct Thrown {
    uint32_t code, object, info, pointers;
    bool rethrown;
};
thread_local std::vector<Thrown> g_caught;

struct Landing {
    uint32_t node;
    size_t depth;
    jmp_buf buf;
};
thread_local std::vector<std::unique_ptr<Landing>> g_landings;
thread_local uint32_t g_resumeAt, g_resumeEbp;

Landing* LandingOf(uint32_t node) {
    for (auto& l : g_landings)
        if (l->node == node) return l.get();
    return nullptr;
}

// the reference's EXCEPTION_RECORD and CONTEXT (x86: 0x50, 0x2cc bytes) and the pointers to them
uint32_t Pointers(uint32_t code, uint32_t flags, uint32_t n, const uint32_t* args) {
    auto p = static_cast<uint8_t*>(LowNew(8 + 0x50 + 0x2CC));
    uint32_t base = Low(p), rec = base + 8, ctx = base + 8 + 0x50;
    *At<uint32_t>(base) = rec;
    *At<uint32_t>(base + 4) = ctx;
    *At<uint32_t>(rec) = code;
    *At<uint32_t>(rec + 4) = flags;
    *At<uint32_t>(rec + 0x10) = n > 15 ? 15 : n;
    for (uint32_t k = 0; k < n && k < 15; k++) *At<uint32_t>(rec + 0x14 + 4 * k) = args[k];
    return base;
}

uint32_t Adjust(uint32_t object, uint32_t ct) {
    int32_t mdisp = I(ct + 8), pdisp = I(ct + 0xC), vdisp = I(ct + 0x10);
    uint32_t p = object + mdisp;
    if (pdisp >= 0) p += I(U(object + pdisp) + vdisp) + pdisp;
    return p;
}

const char* TypeName(uint32_t td) { return td ? At<const char>(td + 8) : ""; }

uint32_t Matches(uint32_t handler, const Thrown& t) {
    uint32_t adjectives = U(handler), type = U(handler + 4);
    if (type == 0 || TypeName(type)[0] == 0 || (adjectives & 0x40)) return 1;
    if (t.code != kCxxCode || t.info == 0) return 0;
    uint32_t cta = U(t.info + 0xC);
    for (uint32_t k = 0, n = U(cta); k < n; k++) {
        uint32_t ct = U(cta + 4 + 4 * k);
        uint32_t ctType = U(ct + 4);
        if (ctType != type && strcmp(TypeName(ctType), TypeName(type)) != 0) continue;
        if ((U(ct) & 2) && !(adjectives & 8)) continue;
        return ct;
    }
    return 0;
}

void BuildCatchObject(uint32_t handler, uint32_t ct, const Thrown& t, uint32_t ebp) {
    int32_t disp = I(handler + 8);
    if (ct <= 1 || disp == 0) return;
    uint32_t dest = ebp + disp, src = Adjust(t.object, ct);
    uint32_t props = U(ct), size = U(ct + 0x14), copy = U(ct + 0x18);
    if (U(handler) & 8)
        *At<uint32_t>(dest) = src;
    else if ((props & 1) || copy == 0)
        memcpy(At(dest), At(src), size);
    else if (props & 4)
        CallRef(copy, dest, src, 1u);
    else
        CallRef(copy, dest, src);
}

void UnwindToState(uint32_t node, uint32_t fi, int32_t target) {
    uint32_t ebp = node + 0xC, map = U(fi + 8);
    int32_t maxState = I(fi + 4);
    int32_t state = I(node + 8);
    while (state != target && state >= 0 && state < maxState) {
        int32_t next = I(map + 8 * state);
        uint32_t action = U(map + 8 * state + 4);
        *At<int32_t>(node + 8) = next;
        if (action) Call1(action, ebp);
        state = next;
    }
}

void LocalUnwind4(uint32_t node, uint32_t st, int32_t target) {
    uint32_t ebp = node + 0x10;
    int32_t level = I(node + 0xC);
    while (level != kTryNone && level != target) {
        uint32_t rec = st + 0x10 + 12 * level;
        int32_t enclosing = I(rec);
        *At<int32_t>(node + 0xC) = enclosing;
        if (U(rec + 4) == 0) Call1(U(rec + 8), ebp);
        level = enclosing;
    }
}

void UnwindFrame(uint32_t node) {
    uint32_t handler = U(node + 4);
    if (uint32_t fi = FuncInfoOf(handler))
        UnwindToState(node, fi, -1);
    else if (uint32_t st = ScopeTableOf(node))
        LocalUnwind4(node, st, kTryNone);
    else if (uint32_t st3 = ScopeTable3Of(node))
        LocalUnwind3(node, st3, kTryNone3);
}

[[noreturn]] void Land(uint32_t node, uint32_t at, uint32_t ebp) {
    Head() = node;
    Landing* l = LandingOf(node);
    if (l == nullptr) {
        Log("an exception caught by a frame with no landing (node %08X, at %08X)", node, at);
        Die(3);
    }
    while (g_caught.size() > l->depth) {
        Thrown done = g_caught.back();
        g_caught.pop_back();
        if (!done.rethrown && done.object && U(done.info + 4)) Call1(U(done.info + 4), done.object);
    }
    g_resumeAt = at;
    g_resumeEbp = ebp;
    if (Tracing()) Log("eh: land at node %08X, continuation %08X", node, at);
    longjmp(l->buf, 1);
}

uint32_t g_unhandledFilter = 0;   // SetUnhandledExceptionFilter's

// the search, the unwind and the landing; returns where a filter continues execution
void Dispatch(Thrown t) {
    for (uint32_t node = Head(); node != kEndOfChain && node != 0; node = U(node)) {
        uint32_t handler = U(node + 4);
        if (uint32_t fi = FuncInfoOf(handler)) {
            if (t.code != kCxxCode) continue;
            int32_t state = I(node + 8);
            uint32_t tries = U(fi + 0x10);
            for (uint32_t k = 0, n = U(fi + 0xC); k < n; k++) {
                uint32_t tb = tries + 20 * k;
                int32_t low = I(tb), high = I(tb + 4);
                if (state < low || state > high) continue;
                for (uint32_t h = 0, nh = U(tb + 0xC); h < nh; h++) {
                    uint32_t ht = U(tb + 0x10) + 16 * h;
                    uint32_t ct = Matches(ht, t);
                    if (!ct) continue;
                    uint32_t ebp = node + 0xC;
                    BuildCatchObject(ht, ct, t, ebp);
                    for (uint32_t above = Head(); above != node; above = U(above)) {
                        Head() = above;
                        UnwindFrame(above);
                    }
                    Head() = node;
                    UnwindToState(node, fi, low);
                    *At<int32_t>(node + 8) = high + 1;
                    g_caught.push_back(t);
                    uint32_t at = Call1(U(ht + 0xC), ebp);
                    Land(node, at, ebp);
                }
            }
        } else if (uint32_t st = ScopeTableOf(node)) {
            uint32_t ebp = node + 0x10;
            for (int32_t level = I(node + 0xC); level != kTryNone;) {
                uint32_t rec = st + 0x10 + 12 * level;
                int32_t enclosing = I(rec);
                uint32_t filter = U(rec + 4);
                if (filter) {
                    *At<uint32_t>(ebp - 0x14) = t.pointers;
                    int32_t r = static_cast<int32_t>(Call1(filter, ebp));
                    if (r < 0) return;
                    if (r > 0) {
                        for (uint32_t above = Head(); above != node; above = U(above)) {
                            Head() = above;
                            UnwindFrame(above);
                        }
                        Head() = node;
                        LocalUnwind4(node, st, level);
                        *At<int32_t>(node + 0xC) = enclosing;
                        Land(node, U(rec + 8), ebp);
                    }
                }
                level = enclosing;
            }
        } else if (uint32_t st3 = ScopeTable3Of(node)) {
            uint32_t ebp = node + 0x10;
            for (int32_t level = I(node + 0xC); level != kTryNone3;) {
                uint32_t rec = st3 + 12 * level;
                int32_t enclosing = I(rec);
                uint32_t filter = U(rec + 4);
                if (filter) {
                    *At<uint32_t>(ebp - 0x14) = t.pointers;
                    int32_t r = static_cast<int32_t>(Call1(filter, ebp));
                    if (r < 0) return;
                    if (r > 0) {
                        for (uint32_t above = Head(); above != node; above = U(above)) {
                            Head() = above;
                            UnwindFrame(above);
                        }
                        Head() = node;
                        LocalUnwind3(node, st3, level);
                        *At<int32_t>(node + 0xC) = enclosing;
                        Land(node, U(rec + 8), ebp);
                    }
                }
                level = enclosing;
            }
        }
    }
    Log("unhandled exception %08X on thread %u; the chain:", t.code, CurrentThreadId());
    for (uint32_t node = Head(); node != kEndOfChain && node != 0; node = U(node))
        Log("  node %08X handler %08X FuncInfo %08X scope table %08X state %d", node, U(node + 4),
            FuncInfoOf(U(node + 4)), ScopeTableOf(node), I(node + 8));
    PrintHere();
    // (the reference's own last word, its unhandled-exception filter: a crash reporter's)
    if (g_unhandledFilter) {
        Log("calling the reference's unhandled-exception filter %08x", g_unhandledFilter);
        CallRef(g_unhandledFilter, t.pointers);
    }
    Die(t.code == kCxxCode ? 3 : t.code);
}

}  // namespace eh

// ---- a hardware fault in translated code inside a reference __try -------------------------------
// The signal handler sends the faulting thread to HwTrampoline, as if the faulting instruction had
// called it (its pc the return address), which dispatches on the thread's own stack. A landing
// longjmps out of it into the frame that linked the node. A filter's EXCEPTION_CONTINUE_EXECUTION
// cannot resume the faulting instruction here (bionic has no setcontext): logged, the process ends.
namespace {
struct HwFault {
    uint32_t code, n, a[4];
};
thread_local HwFault t_fault;

[[noreturn]] void HwTrampoline() {
    HwFault& f = t_fault;
    eh::Thrown t{f.code, 0, 0, eh::Pointers(f.code, 0, f.n, f.a), false};
    eh::Dispatch(t);
    Log("a filter continued execution after a hardware fault (%08x): not resumable here", f.code);
    eh::Die(f.code);
}
}  // namespace

namespace rh {
// The reference's traps as Ghidra32.h's aarch64 branch spells them: `brk #0xf000` its int3,
// `brk #1` __fastfail, `udf #0` ud2, `udf #1` hlt. A fault's signal and instruction as the x86
// exception the reference's handlers expect (0: not one of the translation's)
uint32_t ExceptionCodeOf(int sig, uint64_t pc) {
    uint32_t insn = 0;
    if (InPort(pc) && !(pc & 3)) insn = *reinterpret_cast<const uint32_t*>(pc);
    switch (sig) {
        case SIGSEGV: case SIGBUS: return 0xC0000005;            // EXCEPTION_ACCESS_VIOLATION
        case SIGFPE: return 0xC0000094;                          // EXCEPTION_INT_DIVIDE_BY_ZERO
        case SIGTRAP:
            if ((insn & 0xFFE0001Fu) == 0xD4200000u && ((insn >> 5) & 0xFFFF) == 1) return 0xC0000409;   // __fastfail
            return 0x80000003;                                   // EXCEPTION_BREAKPOINT
        case SIGILL:
            if ((insn & 0xFFFF0000u) == 0 && (insn & 0xFFFF) == 1) return 0xC0000096;   // hlt: PRIV_INSTRUCTION
            return 0xC000001D;                                   // EXCEPTION_ILLEGAL_INSTRUCTION
        default: return 0;
    }
}

int SehHardwareFault(int sig, siginfo_t* info, ucontext_t* uc) {
    uint64_t pc = uc->uc_mcontext.pc;
    uint32_t code = ExceptionCodeOf(sig, pc);
    if (!code || !InPort(pc)) return 0;
    if (code == 0xC0000409) {
        // (a fail-fast reaches no handler: the process ends, reported, as on Windows)
        LogRaw(RHIPPER_NAME ": __fastfail: the process ends (0xc0000409)");
        RefTraceFlush();
        _exit(0x09);
    }
    if (!gen_teb32_made()) return 0;
    uint32_t head = eh::Head();
    if (head == eh::kEndOfChain || head == 0) return 0;
    HwFault& f = t_fault;
    f.code = code;
    f.n = code == 0xC0000005 ? 2 : 0;
    f.a[0] = 0;   // (read or write: not reported by the signal)
    f.a[1] = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(info->si_addr));
    uint64_t sp = (uc->uc_mcontext.sp - 256) & ~uint64_t(15);
    uc->uc_mcontext.sp = sp;
    uc->uc_mcontext.regs[30] = pc;
    uc->uc_mcontext.pc = reinterpret_cast<uint64_t>(&HwTrampoline);
    return 1;
}
}  // namespace rh

extern "C" {

jmp_buf* gen_eh_landing(unsigned int node) {
    eh::Landing* l = eh::LandingOf(node);
    if (l == nullptr) {
        eh::g_landings.push_back(std::make_unique<eh::Landing>());
        l = eh::g_landings.back().get();
        l->node = node;
    }
    l->depth = eh::g_caught.size();
    if (eh::Tracing()) Log("eh: frame linked at node %08X", node);
    return &l->buf;
}

unsigned long long gen_eh_resume(void) { return eh::Call1(eh::g_resumeAt, eh::g_resumeEbp); }

[[noreturn]] static void CxxThrow(uint32_t magic, uint32_t object, uint32_t info) {
    eh::Thrown t{eh::kCxxCode, object, info, 0, false};
    if (object == 0 && info == 0) {
        if (eh::g_caught.empty()) {
            Log("a rethrow with no exception");
            eh::Die(3);
        }
        eh::g_caught.back().rethrown = true;
        t = eh::g_caught.back();
        t.rethrown = false;
    }
    uint32_t args[3] = {magic, t.object, t.info};
    t.pointers = eh::Pointers(eh::kCxxCode, 1, 3, args);
    eh::Dispatch(t);
    Log("a C++ exception continued");
    eh::Die(3);
}

// RaiseException (the static CRT's _CxxThrowException raises 0xE06D7363 through it)
unsigned int gen_imp_RaiseException(uint32_t code, uint32_t flags, uint32_t n, uint32_t args) {
    uint32_t a[15] = {};
    for (uint32_t k = 0; k < n && k < 15; k++) a[k] = *At<uint32_t>(args + 4 * k);
    if (code == eh::kCxxCode && n >= 3 && a[0] >= 0x19930520u && a[0] <= 0x19930522u) CxxThrow(a[0], a[1], a[2]);
    // (a debugger's thread name, MS_VC_EXCEPTION: no debugger, nothing to do)
    if (code == 0x406D1388) return 0;
    eh::Thrown t{code, 0, 0, eh::Pointers(code, flags, n, a), false};
    eh::Dispatch(t);
    return 0;
}

// an integer fault the translation found where x86 faults and AArch64 does not (Ghidra32.h's
// division: a zero divisor 0xc0000094, INT_MIN / -1 0xc0000095), raised through the reference's
// handlers; returns only where a filter continues execution
void gen_int_fault(unsigned int code) {
    eh::Thrown t{code, 0, 0, eh::Pointers(code, 0, 0, nullptr), false};
    eh::Dispatch(t);
}

unsigned int gen_imp_SetUnhandledExceptionFilter(uint32_t fn) {
    uint32_t old = eh::g_unhandledFilter;
    eh::g_unhandledFilter = fn;
    return old;
}

}  // extern "C"

// UnhandledExceptionFilter: the CRT's last resort calls it; the process ends after
static uint32_t UnhandledExceptionFilter_(uint32_t pointers) {
    Log("UnhandledExceptionFilter(%08x): code %08x", pointers, pointers ? eh::U(eh::U(pointers)) : 0);
    PrintHere();
    return 1;   // EXCEPTION_EXECUTE_HANDLER
}
RH_REG(KERNEL32, UnhandledExceptionFilter, UnhandledExceptionFilter_)

// RtlUnwind(target frame, ...): the static CRT's _global_unwind2, every frame above the target
// left as its function would leave it
static uint32_t RtlUnwind_(uint32_t target, uint32_t, uint32_t, uint32_t) {
    for (uint32_t node = eh::Head(); node != eh::kEndOfChain && node != 0 && node != target; node = eh::U(node)) {
        eh::Head() = node;
        eh::UnwindFrame(node);
        eh::Head() = eh::U(node);
    }
    return 0;
}
RH_REG(KERNEL32, RtlUnwind, RtlUnwind_)
