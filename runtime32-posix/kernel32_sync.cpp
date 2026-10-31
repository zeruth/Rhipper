// kernel32's handles and synchronization: the handle table, events, mutexes, semaphores, the waits
// on them, critical sections (in the reference's memory, x86 layout), the interlocked functions.
//
// Every waitable object's state is guarded by one lock (WaitLock) and every change wakes one
// condition variable: a wait is a loop over plain state. The message queues (user32.cpp) share the
// lock, so MsgWaitForMultipleObjects wakes on a posted message as on an object.
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

#include "Runtime.h"

namespace rh {

namespace {
std::mutex g_waitLock;
std::condition_variable g_waitCv;

std::mutex g_tableLock;
std::unordered_map<uint32_t, std::shared_ptr<Object>> g_table;
uint32_t g_next = 0x100;
}  // namespace

// the calling thread's message queue has what `mask` asks for (user32.cpp; WaitLock held)
bool QueueHasInput(uint32_t tid, uint32_t mask);

std::mutex& WaitLock() { return g_waitLock; }
void WaitNotify() { g_waitCv.notify_all(); }
void WaitLockWaitFor(std::unique_lock<std::mutex>& lk, uint32_t ms) {
    g_waitCv.wait_for(lk, std::chrono::milliseconds(ms));
}

uint64_t NowMs() {
    timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000 + ts.tv_nsec / 1000000;
}

uint32_t NewHandle(std::shared_ptr<Object> o) {
    std::lock_guard<std::mutex> hold(g_tableLock);
    while (g_table.count(g_next) || g_next == 0) g_next += 4;
    uint32_t h = g_next;
    g_next += 4;
    g_table[h] = std::move(o);
    return h;
}

std::shared_ptr<Object> GetHandle(uint32_t h) {
    std::lock_guard<std::mutex> hold(g_tableLock);
    auto it = g_table.find(h);
    return it == g_table.end() ? nullptr : it->second;
}

bool CloseHandle32(uint32_t h) {
    std::shared_ptr<Object> o;
    {
        std::lock_guard<std::mutex> hold(g_tableLock);
        auto it = g_table.find(h);
        if (it == g_table.end()) return false;
        if (!it->second->Close()) return false;
        o = std::move(it->second);
        g_table.erase(it);
    }
    return true;
}

uint32_t DupHandle(uint32_t h) {
    auto o = GetHandle(h);
    return o ? NewHandle(o) : 0;
}

uint32_t WaitAny(const uint32_t* hs, uint32_t n, bool all, uint32_t ms, uint32_t wakeMask) {
    std::vector<std::shared_ptr<Object>> objs(n);
    for (uint32_t k = 0; k < n; k++) {
        objs[k] = GetHandle(hs[k]);
        if (hs[k] == kCurrentThread || hs[k] == kCurrentProcess) continue;   // (never signalled)
        if (!objs[k] || !objs[k]->Waitable()) {
            LogOnce("wait-bad", "wait on %08x, which is no waitable object (%s)", hs[k], objs[k] ? objs[k]->Kind() : "none");
            SetLastError(win::ERROR_INVALID_HANDLE);
            return win::WAIT_FAILED;
        }
    }
    const uint32_t tid = CurrentThreadId();
    const uint64_t deadline = ms == win::INFINITE ? UINT64_MAX : NowMs() + ms;
    std::unique_lock<std::mutex> lk(g_waitLock);
    for (;;) {
        if (all && n) {
            bool every = true;
            for (auto& o : objs) every = every && o && o->Signalled(tid);
            if (every) {
                for (auto& o : objs) o->Acquire(tid);
                return win::WAIT_OBJECT_0;
            }
        } else {
            for (uint32_t k = 0; k < n; k++)
                if (objs[k] && objs[k]->Signalled(tid)) {
                    objs[k]->Acquire(tid);
                    return win::WAIT_OBJECT_0 + k;
                }
        }
        if (wakeMask && QueueHasInput(tid, wakeMask)) return win::WAIT_OBJECT_0 + n;
        if (ms == 0) return win::WAIT_TIMEOUT;
        if (deadline == UINT64_MAX) {
            g_waitCv.wait(lk);
        } else {
            uint64_t now = NowMs();
            if (now >= deadline) return win::WAIT_TIMEOUT;
            g_waitCv.wait_for(lk, std::chrono::milliseconds(deadline - now));
        }
    }
}

// ---- the objects -------------------------------------------------------------------------------
struct Event : Object {
    bool manual, set;
    Event(bool m, bool s) : manual(m), set(s) {}
    const char* Kind() const override { return "event"; }
    bool Waitable() const override { return true; }
    bool Signalled(uint32_t) const override { return set; }
    void Acquire(uint32_t) override {
        if (!manual) set = false;
    }
};

struct Mutex : Object {
    uint32_t owner = 0, count = 0;
    const char* Kind() const override { return "mutex"; }
    bool Waitable() const override { return true; }
    bool Signalled(uint32_t tid) const override { return owner == 0 || owner == tid; }
    void Acquire(uint32_t tid) override {
        owner = tid;
        count++;
    }
};

struct Semaphore : Object {
    int32_t count, max;
    Semaphore(int32_t c, int32_t m) : count(c), max(m) {}
    const char* Kind() const override { return "semaphore"; }
    bool Waitable() const override { return true; }
    bool Signalled(uint32_t) const override { return count > 0; }
    void Acquire(uint32_t) override { count--; }
};

namespace {
// named objects: one per name, opened again by name (a second instance's mutex check)
std::mutex g_namesLock;
std::map<std::string, std::weak_ptr<Object>> g_names;

template <typename T, typename Make>
uint32_t Named(const char* name, Make make) {
    if (!name || !*name) return NewHandle(make());
    std::lock_guard<std::mutex> hold(g_namesLock);
    auto it = g_names.find(name);
    if (it != g_names.end())
        if (auto o = it->second.lock()) {
            if (!std::dynamic_pointer_cast<T>(o)) {
                SetLastError(6 /* ERROR_INVALID_HANDLE */);
                return 0;
            }
            SetLastError(win::ERROR_ALREADY_EXISTS);
            return NewHandle(o);
        }
    auto o = make();
    g_names[name] = o;
    SetLastError(0);
    return NewHandle(o);
}
}  // namespace

std::shared_ptr<Object> MakeEvent(bool manual, bool initial) { return std::make_shared<Event>(manual, initial); }
void SignalEvent(const std::shared_ptr<Object>& o) {
    if (auto e = std::dynamic_pointer_cast<Event>(o)) {
        std::lock_guard<std::mutex> hold(g_waitLock);
        e->set = true;
        g_waitCv.notify_all();
    }
}

}  // namespace rh

using namespace rh;

extern "C" {

// (the SECURITY_ATTRIBUTES pointer ignored: no security here; names as the generated code passes)
unsigned int gen_imp_CreateEventA(uint32_t, uint32_t manual, uint32_t initial, uintptr_t name) {
    return Named<Event>(Str(name), [&] { return std::make_shared<Event>(manual != 0, initial != 0); });
}
unsigned int gen_imp_CreateMutexA(uint32_t, uint32_t owner, uintptr_t name) {
    uint32_t tid = CurrentThreadId();
    return Named<Mutex>(Str(name), [&] {
        auto m = std::make_shared<Mutex>();
        if (owner) m->owner = tid, m->count = 1;
        return m;
    });
}
unsigned int gen_imp_CreateSemaphoreA(uint32_t, uint32_t initial, uint32_t maximum, uintptr_t name) {
    return Named<Semaphore>(Str(name), [&] {
        return std::make_shared<Semaphore>(static_cast<int32_t>(initial), static_cast<int32_t>(maximum));
    });
}

unsigned int gen_imp_WaitForMultipleObjects(uint32_t n, uint32_t p, uint32_t all, uint32_t ms) {
    if (n == 0 || n > 64) {
        SetLastError(win::ERROR_INVALID_PARAMETER);
        return win::WAIT_FAILED;
    }
    return WaitAny(At<uint32_t>(p), n, all != 0, ms, 0);
}

unsigned int gen_imp_DuplicateHandle(uint32_t, uint32_t from, uint32_t, uint32_t out, uint32_t, uint32_t,
                                     uint32_t options) {
    uint32_t h = from == kCurrentThread || from == kCurrentProcess ? from : DupHandle(from);
    if (!h) {
        SetLastError(win::ERROR_INVALID_HANDLE);
        return 0;
    }
    if (out) *At<uint32_t>(out) = h;
    if (options & 1) CloseHandle32(from);   // DUPLICATE_CLOSE_SOURCE
    return 1;
}

}  // extern "C"

static uint32_t OpenMutexA_(uint32_t, uint32_t, uint32_t name) {
    std::lock_guard<std::mutex> hold(g_namesLock);
    auto it = g_names.find(name ? At<char>(name) : "");
    if (it != g_names.end())
        if (auto o = it->second.lock()) return NewHandle(o);
    SetLastError(win::ERROR_FILE_NOT_FOUND);
    return 0;
}
RH_REG(KERNEL32, OpenMutexA, OpenMutexA_)

static uint32_t SetEvent_(uint32_t h) {
    auto e = GetAs<Event>(h);
    if (!e) return SetLastError(win::ERROR_INVALID_HANDLE), 0;
    std::lock_guard<std::mutex> hold(WaitLock());
    e->set = true;
    WaitNotify();
    return 1;
}
RH_REG(KERNEL32, SetEvent, SetEvent_)

static uint32_t ResetEvent_(uint32_t h) {
    auto e = GetAs<Event>(h);
    if (!e) return SetLastError(win::ERROR_INVALID_HANDLE), 0;
    std::lock_guard<std::mutex> hold(WaitLock());
    e->set = false;
    return 1;
}
RH_REG(KERNEL32, ResetEvent, ResetEvent_)

static uint32_t ReleaseMutex_(uint32_t h) {
    auto m = GetAs<Mutex>(h);
    if (!m) return SetLastError(win::ERROR_INVALID_HANDLE), 0;
    std::lock_guard<std::mutex> hold(WaitLock());
    if (m->owner != CurrentThreadId()) return SetLastError(win::ERROR_NOT_OWNER), 0;
    if (--m->count == 0) m->owner = 0;
    WaitNotify();
    return 1;
}
RH_REG(KERNEL32, ReleaseMutex, ReleaseMutex_)

static uint32_t ReleaseSemaphore_(uint32_t h, uint32_t n, uint32_t prev) {
    auto s = GetAs<Semaphore>(h);
    if (!s) return SetLastError(win::ERROR_INVALID_HANDLE), 0;
    std::lock_guard<std::mutex> hold(WaitLock());
    if (prev) *At<int32_t>(prev) = s->count;
    if (s->count + static_cast<int32_t>(n) > s->max) return SetLastError(298 /* ERROR_TOO_MANY_POSTS */), 0;
    s->count += static_cast<int32_t>(n);
    WaitNotify();
    return 1;
}
RH_REG(KERNEL32, ReleaseSemaphore, ReleaseSemaphore_)

static uint32_t WaitForSingleObject_(uint32_t h, uint32_t ms) { return WaitAny(&h, 1, false, ms, 0); }
RH_REG(KERNEL32, WaitForSingleObject, WaitForSingleObject_)

static uint32_t CloseHandle_(uint32_t h) {
    if (h == kCurrentProcess || h == kCurrentThread) return 1;
    if (!CloseHandle32(h)) {
        SetLastError(win::ERROR_INVALID_HANDLE);
        return 0;
    }
    return 1;
}
RH_REG(KERNEL32, CloseHandle, CloseHandle_)

// ---- sleeping ----------------------------------------------------------------------------------
static uint32_t Sleep_(uint32_t ms) {
    if (ms == 0) {
        sched_yield();
        return 0;
    }
    timespec ts{static_cast<time_t>(ms / 1000), static_cast<long>(ms % 1000) * 1000000};
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {}
    return 0;
}
RH_REG(KERNEL32, Sleep, Sleep_)
static uint32_t SleepEx_(uint32_t ms, uint32_t) { return Sleep_(ms), 0; }
RH_REG(KERNEL32, SleepEx, SleepEx_)
static uint32_t SwitchToThread_() { return sched_yield(), 1; }
RH_REG(KERNEL32, SwitchToThread, SwitchToThread_)

// ---- critical sections: the reference's 24-byte x86 CRITICAL_SECTION holds, in its first word
// (DebugInfo), a native recursive mutex of the runtime's, made when it is initialized (or on first
// use: a zeroed static one). OwningThread (+0xC) and RecursionCount (+8) kept as x86 Windows keeps
// them, for code that reads them -----------------------------------------------------------------
namespace {
struct Section {
    pthread_mutex_t m;
};

Section* HostSection(uint32_t ref) {
    auto slot = At<std::atomic<uint32_t>>(ref);
    uint32_t mine = slot->load(std::memory_order_acquire);
    if (mine == 0 || mine == 0xFFFFFFFFu) {
        auto s = LowMake<Section>();
        pthread_mutexattr_t a;
        pthread_mutexattr_init(&a);
        pthread_mutexattr_settype(&a, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(&s->m, &a);
        pthread_mutexattr_destroy(&a);
        uint32_t expected = mine;
        if (slot->compare_exchange_strong(expected, Low(s))) return s;
        pthread_mutex_destroy(&s->m);
        LowDelete(s);
        mine = expected;
    }
    return At<Section>(mine);
}

void InitSection(uint32_t cs, uint32_t spin) {
    memset(At(cs), 0, 24);
    *At<int32_t>(cs + 4) = -1;            // LockCount
    *At<uint32_t>(cs + 0x14) = spin;      // SpinCount
    HostSection(cs);
}
}  // namespace

extern "C" {
unsigned int gen_imp_InitializeCriticalSection(uint32_t cs) {
    InitSection(cs, 0);
    return 0;
}
unsigned int gen_imp_InitializeCriticalSectionAndSpinCount(uint32_t cs, uint32_t spin) {
    InitSection(cs, spin);
    return 1;
}
unsigned int gen_imp_EnterCriticalSection(uint32_t cs) {
    pthread_mutex_lock(&HostSection(cs)->m);
    *At<uint32_t>(cs + 0xC) = CurrentThreadId();
    ++*At<int32_t>(cs + 8);
    return 0;
}
unsigned int gen_imp_LeaveCriticalSection(uint32_t cs) {
    if (--*At<int32_t>(cs + 8) == 0) *At<uint32_t>(cs + 0xC) = 0;
    pthread_mutex_unlock(&HostSection(cs)->m);
    return 0;
}
unsigned int gen_imp_TryEnterCriticalSection(uint32_t cs) {
    if (pthread_mutex_trylock(&HostSection(cs)->m) != 0) return 0;
    *At<uint32_t>(cs + 0xC) = CurrentThreadId();
    ++*At<int32_t>(cs + 8);
    return 1;
}
unsigned int gen_imp_DeleteCriticalSection(uint32_t cs) {
    uint32_t mine = *At<uint32_t>(cs);
    if (mine && mine != 0xFFFFFFFFu) {
        pthread_mutex_destroy(&At<Section>(mine)->m);
        LowDelete(At<Section>(mine));
        *At<uint32_t>(cs) = 0;
    }
    return 0;
}

// ---- interlocked: the reference's words, 4-aligned as Windows requires --------------------------
unsigned int gen_imp_InterlockedIncrement(uint32_t p) {
    return __atomic_add_fetch(At<uint32_t>(p), 1u, __ATOMIC_SEQ_CST);
}
unsigned int gen_imp_InterlockedDecrement(uint32_t p) {
    return __atomic_sub_fetch(At<uint32_t>(p), 1u, __ATOMIC_SEQ_CST);
}
unsigned int gen_imp_InterlockedExchange(uint32_t p, uint32_t v) {
    return __atomic_exchange_n(At<uint32_t>(p), v, __ATOMIC_SEQ_CST);
}
unsigned int gen_imp_InterlockedExchangeAdd(uint32_t p, uint32_t v) {
    return __atomic_fetch_add(At<uint32_t>(p), v, __ATOMIC_SEQ_CST);
}
unsigned int gen_imp_InterlockedCompareExchange(uint32_t p, uint32_t v, uint32_t cmp) {
    uint32_t expected = cmp;
    __atomic_compare_exchange_n(At<uint32_t>(p), &expected, v, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    return expected;
}

// pointer encoding round-trips, nothing more (Adapters.cpp: the reference keeps the 4 bytes)
unsigned int gen_imp_EncodePointer(uint32_t p) { return p; }
unsigned int gen_imp_DecodePointer(uint32_t p) { return p; }

}  // extern "C"
