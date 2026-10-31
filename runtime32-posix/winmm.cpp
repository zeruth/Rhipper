// winmm: the multimedia clock and its timers. timeSetEvent's callbacks run on one timer thread of
// the runtime's (a low-stack thread: they are the reference's code), with x86's arguments (timer id,
// 0, the user word, 0, 0; CrystalCore's rhipper.json gotcha: 0xa01790 and 0xd2fac0 take them so).
// timeKillEvent returns once its timer's callback is not running, as Windows' does.
#include <time.h>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <map>

#include "Runtime.h"

namespace rh {
std::shared_ptr<Object> MakeEvent(bool manual, bool initial);   // kernel32_sync.cpp
void SignalEvent(const std::shared_ptr<Object>& o);

namespace {
struct MmTimer {
    uint64_t due;
    uint32_t period, cb, user, flags;
};
std::mutex g_lock;
std::condition_variable g_cv;
std::map<uint32_t, MmTimer> g_timers;
uint32_t g_nextId = 1, g_running = 0, g_timerTid = 0;
bool g_started = false;

void TimerThread(void*) {
    g_timerTid = CurrentThreadId();
    std::unique_lock<std::mutex> lk(g_lock);
    for (;;) {
        if (g_timers.empty()) {
            g_cv.wait(lk);
            continue;
        }
        uint64_t now = NowMs();
        auto next = g_timers.begin();
        for (auto it = g_timers.begin(); it != g_timers.end(); ++it)
            if (it->second.due < next->second.due) next = it;
        if (next->second.due > now) {
            g_cv.wait_for(lk, std::chrono::milliseconds(next->second.due - now));
            continue;
        }
        uint32_t id = next->first;
        MmTimer t = next->second;
        if (t.flags & 1) next->second.due = now + std::max<uint32_t>(t.period, 1);   // TIME_PERIODIC
        else g_timers.erase(next);
        g_running = id;
        lk.unlock();
        if (t.flags & 0x30) {   // TIME_CALLBACK_EVENT_SET / _PULSE: the callback is an event
            if (auto e = GetHandle(t.cb)) SignalEvent(e);
        } else {
            CallRef(t.cb, id, 0u, t.user, 0u, 0u);
        }
        lk.lock();
        g_running = 0;
        g_cv.notify_all();
    }
}
}  // namespace
}  // namespace rh

using namespace rh;

static uint32_t timeGetTime_() { return static_cast<uint32_t>(NowMs()); }
RH_REG(WINMM, timeGetTime, timeGetTime_)
static uint32_t timeBeginPeriod_(uint32_t) { return 0; }   // TIMERR_NOERROR
RH_REG(WINMM, timeBeginPeriod, timeBeginPeriod_)
static uint32_t timeEndPeriod_(uint32_t) { return 0; }
RH_REG(WINMM, timeEndPeriod, timeEndPeriod_)
// TIMECAPS: wPeriodMin, wPeriodMax
static uint32_t timeGetDevCaps_(uint32_t out, uint32_t size) {
    if (size < 8) return 97;   // TIMERR_STRUCT
    *At<uint32_t>(out) = 1;
    *At<uint32_t>(out + 4) = 1000000;
    return 0;
}
RH_REG(WINMM, timeGetDevCaps, timeGetDevCaps_)

static uint32_t timeSetEvent_(uint32_t delay, uint32_t, uint32_t cb, uint32_t user, uint32_t flags) {
    std::lock_guard<std::mutex> hold(g_lock);
    if (!g_started) {
        g_started = true;
        if (!StartLowThread(TimerThread, nullptr, 8u << 20, false, nullptr)) {
            g_started = false;
            return 0;
        }
    }
    uint32_t id = g_nextId++;
    g_timers[id] = {NowMs() + delay, delay, cb, user, flags};
    g_cv.notify_all();
    return id;
}
RH_REG(WINMM, timeSetEvent, timeSetEvent_)

static uint32_t timeKillEvent_(uint32_t id) {
    std::unique_lock<std::mutex> lk(g_lock);
    bool had = g_timers.erase(id) != 0;
    if (CurrentThreadId() != g_timerTid) g_cv.wait(lk, [&] { return g_running != id; });
    g_cv.notify_all();
    return had || g_running == id ? 0 : 97;   // TIMERR_NOERROR / MMSYSERR_INVALPARAM
}
RH_REG(WINMM, timeKillEvent, timeKillEvent_)
