// user32: windows and their messages, the runtime's own. One process, a few windows (the game's main
// one, perhaps a hidden helper), each with the reference's window procedure (a reference address,
// called on the window's thread) and a message queue per thread: posted messages, messages sent from
// another thread (run inside the receiver's GetMessage/PeekMessage/MsgWait, as Windows does), timers
// (WM_TIMER generated when due, a TIMERPROC called by DispatchMessage) and WM_QUIT.
//
// The queues share kernel32_sync.cpp's wait lock, so MsgWaitForMultipleObjects wakes on a message.
// A window procedure is never called with the lock held.
//
// The window has no frame: its client area is the window, at (0,0) of a screen the size of the
// host's surface (rhipper_host_set_window). The game sizes its own window; the renderer scales to
// the surface. Lifecycle events arrive as the messages Windows would send: WM_ACTIVATEAPP,
// WM_ACTIVATE and focus on pause and resume, WM_CLOSE on quit.
#include <strings.h>

#include <algorithm>
#include <deque>
#include <map>
#include <unordered_map>
#include <vector>

#include "Runtime.h"

namespace rh {

bool FindResource32(uint32_t type, uint32_t name, uint32_t* data, uint32_t* size);   // Resources.cpp

namespace {

constexpr uint32_t WM_CREATE = 1, WM_DESTROY = 2, WM_MOVE = 3, WM_SIZE = 5, WM_ACTIVATE = 6, WM_SETFOCUS = 7,
                   WM_KILLFOCUS = 8, WM_CLOSE = 0x10, WM_QUIT = 0x12, WM_ERASEBKGND = 0x14, WM_SHOWWINDOW = 0x18,
                   WM_ACTIVATEAPP = 0x1C, WM_COMPACTING = 0x41, WM_NCCREATE = 0x81, WM_NCDESTROY = 0x82,
                   WM_NCACTIVATE = 0x86, WM_SYSCOMMAND = 0x112, WM_TIMER = 0x113;

#pragma pack(push, 4)
struct Msg32 {
    uint32_t hwnd, message, wParam, lParam, time;
    int32_t x, y;
};
struct WndClassEx32 {
    uint32_t cbSize, style, lpfnWndProc;
    int32_t cbClsExtra, cbWndExtra;
    uint32_t hInstance, hIcon, hCursor, hbrBackground, lpszMenuName, lpszClassName, hIconSm;
};
struct CreateStruct32 {
    uint32_t lpCreateParams, hInstance, hMenu, hwndParent;
    int32_t cy, cx, y, x, style;
    uint32_t lpszName, lpszClass, dwExStyle;
};
struct Rect32 {
    int32_t left, top, right, bottom;
};
#pragma pack(pop)
static_assert(sizeof(Msg32) == 28, "MSG, x86");
static_assert(sizeof(WndClassEx32) == 48, "WNDCLASSEX, x86");
static_assert(sizeof(CreateStruct32) == 48, "CREATESTRUCT, x86");

struct Class {
    std::string name;
    uint32_t atom, proc, style, cursor, icon, brush;
    int32_t clsExtra, wndExtra;
};

struct Subclass {
    uint32_t proc, id, ref;
};

struct Window {
    uint32_t hwnd, tid, proc, atom, style, exStyle, parent, menu, instance, userData = 0, param = 0;
    int32_t x, y, w, h;
    bool visible = false, shown = false, enabled = true;
    std::string title;
    std::vector<uint8_t> extra;
    std::vector<Subclass> subclasses;
};

struct Timer {
    uint32_t hwnd, id, ms, proc;
    uint64_t due;
};

struct Sent {
    Msg32 m;
    uint32_t result = 0;
    bool done = false;
};

struct Queue {
    std::deque<Msg32> posted;
    std::deque<Sent*> sent;
    std::vector<Timer> timers;
    bool quit = false;
    uint32_t quitCode = 0;
};

// (all under WaitLock())
std::map<uint32_t, Class> g_classes;
std::map<uint32_t, Window> g_windows;
std::unordered_map<uint32_t, Queue> g_queues;
uint32_t g_nextAtom = 0xC000, g_nextHwnd = 0x00010010, g_nextTimer = 0x7000;
uint32_t g_main = 0, g_active = 0, g_focus = 0;
int32_t g_screenW = 1920, g_screenH = 1080;
bool g_paused = false;
std::map<std::string, uint32_t> g_registeredMessages;

Window* WindowOf(uint32_t hwnd) {
    auto it = g_windows.find(hwnd);
    return it == g_windows.end() ? nullptr : &it->second;
}

bool Matches(const Msg32& m, uint32_t hwnd, uint32_t lo, uint32_t hi) {
    if (hwnd && hwnd != 0xFFFFFFFFu && m.hwnd != hwnd) return false;
    if (hwnd == 0xFFFFFFFFu && m.hwnd != 0) return false;   // (-1: thread messages only)
    if (lo == 0 && hi == 0) return true;
    return m.message >= lo && m.message <= hi;
}

Msg32 Make(uint32_t hwnd, uint32_t msg, uint32_t wp, uint32_t lp) {
    return {hwnd, msg, wp, lp, static_cast<uint32_t>(NowMs()), 0, 0};
}

void PostTo(uint32_t tid, const Msg32& m) {
    g_queues[tid].posted.push_back(m);
    WaitNotify();
}

// the reference's procedure for a window, through its subclasses (comctl32): the top one first
thread_local int t_subclassDepth = -1;

uint32_t CallProc(uint32_t hwnd, uint32_t msg, uint32_t wp, uint32_t lp) {
    uint32_t proc = 0;
    Subclass top{};
    bool sub = false;
    {
        std::lock_guard<std::mutex> hold(WaitLock());
        Window* w = WindowOf(hwnd);
        if (!w) return 0;
        proc = w->proc;
        if (!w->subclasses.empty()) {
            top = w->subclasses.back();
            sub = true;
        }
    }
    if (sub) {
        int saved = t_subclassDepth;
        t_subclassDepth = 0;
        uint32_t r = CallRef(top.proc, hwnd, msg, wp, lp, top.id, top.ref);
        t_subclassDepth = saved;
        return r;
    }
    return proc ? CallRef(proc, hwnd, msg, wp, lp) : 0;
}

// a message sent to a window: its procedure now on its own thread, or run by its thread's queue
uint32_t Send(uint32_t hwnd, uint32_t msg, uint32_t wp, uint32_t lp);

// run one message sent from another thread to this one (the lock held, released for the call)
bool RunSent(std::unique_lock<std::mutex>& lk, Queue& q) {
    if (q.sent.empty()) return false;
    Sent* s = q.sent.front();
    q.sent.pop_front();
    lk.unlock();
    uint32_t r = CallProc(s->m.hwnd, s->m.message, s->m.wParam, s->m.lParam);
    lk.lock();
    s->result = r;
    s->done = true;
    WaitNotify();
    return true;
}

uint32_t Send(uint32_t hwnd, uint32_t msg, uint32_t wp, uint32_t lp) {
    uint32_t tid;
    {
        std::lock_guard<std::mutex> hold(WaitLock());
        Window* w = WindowOf(hwnd);
        if (!w) return 0;
        tid = w->tid;
    }
    const uint32_t me = CurrentThreadId();
    if (tid == me) return CallProc(hwnd, msg, wp, lp);
    Sent s;
    s.m = Make(hwnd, msg, wp, lp);
    std::unique_lock<std::mutex> lk(WaitLock());
    g_queues[tid].sent.push_back(&s);
    WaitNotify();
    // Wait for the receiver to run it, meanwhile running this thread's own sent messages so two
    // threads that send to each other do not deadlock. The shared wait condition wakes on every
    // change; a short timeout bounds the wait if a wake is missed.
    while (!s.done) {
        if (RunSent(lk, g_queues[me])) continue;
        WaitLockWaitFor(lk, 5);
    }
    return s.result;
}

// the next message for GetMessage/PeekMessage: sent ones run first, then posted, then a due timer;
// `wait` blocks until there is one. False: none (PeekMessage)
bool Next(uint32_t hwnd, uint32_t lo, uint32_t hi, bool remove, bool wait, Msg32* out) {
    const uint32_t me = CurrentThreadId();
    std::unique_lock<std::mutex> lk(WaitLock());
    for (;;) {
        Queue& q = g_queues[me];
        if (RunSent(lk, q)) continue;
        for (auto it = q.posted.begin(); it != q.posted.end(); ++it) {
            if (!Matches(*it, hwnd, lo, hi)) continue;
            *out = *it;
            if (remove) q.posted.erase(it);
            return true;
        }
        uint64_t now = NowMs(), soonest = UINT64_MAX;
        for (Timer& t : q.timers) {
            if (t.due <= now) {
                Msg32 m = Make(t.hwnd, WM_TIMER, t.id, t.proc);
                if (Matches(m, hwnd, lo, hi)) {
                    if (remove) t.due = now + std::max<uint32_t>(t.ms, 10);
                    *out = m;
                    return true;
                }
            }
            soonest = std::min(soonest, t.due);
        }
        if (q.quit && Matches(Make(0, WM_QUIT, 0, 0), hwnd == 0xFFFFFFFFu ? 0 : 0, lo, hi)) {
            *out = Make(0, WM_QUIT, q.quitCode, 0);
            if (remove) q.quit = false;
            return true;
        }
        if (!wait) return false;
        lk.unlock();
        uint32_t ms = soonest == UINT64_MAX ? win::INFINITE : static_cast<uint32_t>(soonest > now ? soonest - now : 0);
        WaitAny(nullptr, 0, false, ms, 0xFF);
        lk.lock();
    }
}

void PutMsg(uint32_t out, const Msg32& m) {
    if (out) *At<Msg32>(out) = m;
}

void Destroy(uint32_t hwnd) {
    Send(hwnd, WM_DESTROY, 0, 0);
    Send(hwnd, WM_NCDESTROY, 0, 0);
    std::lock_guard<std::mutex> hold(WaitLock());
    for (auto& [tid, q] : g_queues) {
        q.timers.erase(std::remove_if(q.timers.begin(), q.timers.end(), [&](const Timer& t) { return t.hwnd == hwnd; }),
                       q.timers.end());
    }
    g_windows.erase(hwnd);
    if (g_main == hwnd) g_main = 0;
    if (g_active == hwnd) g_active = 0;
    if (g_focus == hwnd) g_focus = 0;
}

void Show(uint32_t hwnd, bool show) {
    bool first = false;
    int32_t w = 0, h = 0, x = 0, y = 0;
    {
        std::lock_guard<std::mutex> hold(WaitLock());
        Window* win = WindowOf(hwnd);
        if (!win || win->visible == show) return;
        win->visible = show;
        first = show && !win->shown;
        win->shown = win->shown || show;
        w = win->w, h = win->h, x = win->x, y = win->y;
        if (show && !win->parent) g_active = g_focus = hwnd;
    }
    Send(hwnd, WM_SHOWWINDOW, show, 0);
    if (show) {
        Send(hwnd, WM_ACTIVATEAPP, 1, 0);
        Send(hwnd, WM_NCACTIVATE, 1, 0);
        Send(hwnd, WM_ACTIVATE, g_paused ? 0 : 1, 0);
        Send(hwnd, WM_SETFOCUS, 0, 0);
    }
    if (first) {
        Send(hwnd, WM_SIZE, 0, static_cast<uint32_t>((w & 0xFFFF) | (h << 16)));
        Send(hwnd, WM_MOVE, 0, static_cast<uint32_t>((x & 0xFFFF) | (y << 16)));
    }
}

uint32_t ClassAtom(uint32_t nameOrAtom) {
    if (nameOrAtom < 0x10000) return nameOrAtom;
    const char* n = At<char>(nameOrAtom);
    for (auto& [atom, c] : g_classes)
        if (strcasecmp(c.name.c_str(), n) == 0) return atom;
    return 0;
}

}  // namespace

// the calling thread's queue has input (kernel32_sync.cpp's MsgWait; WaitLock held)
bool QueueHasInput(uint32_t tid, uint32_t mask) {
    (void)mask;
    auto it = g_queues.find(tid);
    if (it == g_queues.end()) return false;
    const Queue& q = it->second;
    if (!q.posted.empty() || !q.sent.empty() || q.quit) return true;
    uint64_t now = NowMs();
    for (const Timer& t : q.timers)
        if (t.due <= now) return true;
    return false;
}

// ---- the host's side (Host.cpp) ---------------------------------------------------------------------
void HostScreen(int w, int h) {
    std::lock_guard<std::mutex> hold(WaitLock());
    if (w > 0 && h > 0) g_screenW = w, g_screenH = h;
}

void HostLifecycle(int event) {
    std::lock_guard<std::mutex> hold(WaitLock());
    Window* w = WindowOf(g_main);
    if (!w) {
        Log("lifecycle %d before the reference has a window", event);
        if (event == 1) g_paused = true;
        if (event == 2) g_paused = false;
        return;
    }
    switch (event) {
        case 1:   // pause: the window inactive, its focus gone
            g_paused = true;
            PostTo(w->tid, Make(w->hwnd, WM_ACTIVATEAPP, 0, 0));
            PostTo(w->tid, Make(w->hwnd, WM_ACTIVATE, 0, 0));
            PostTo(w->tid, Make(w->hwnd, WM_KILLFOCUS, 0, 0));
            break;
        case 2:
            g_paused = false;
            PostTo(w->tid, Make(w->hwnd, WM_ACTIVATEAPP, 1, 0));
            PostTo(w->tid, Make(w->hwnd, WM_ACTIVATE, 1, 0));
            PostTo(w->tid, Make(w->hwnd, WM_SETFOCUS, 0, 0));
            break;
        case 3:
            PostTo(w->tid, Make(w->hwnd, WM_CLOSE, 0, 0));
            break;
        case 4:
            PostTo(w->tid, Make(w->hwnd, WM_COMPACTING, 0x8000, 0));
            break;
    }
}

uint32_t MainWindow() {
    std::lock_guard<std::mutex> hold(WaitLock());
    return g_main;
}

// a message posted from any thread (ws2_32's WSAAsyncSelect, winmm)
bool PostMessage32(uint32_t hwnd, uint32_t msg, uint32_t wp, uint32_t lp) {
    std::lock_guard<std::mutex> hold(WaitLock());
    Window* w = WindowOf(hwnd);
    if (!w) return false;
    PostTo(w->tid, Make(hwnd, msg, wp, lp));
    return true;
}

}  // namespace rh

using namespace rh;

extern "C" {

unsigned int gen_imp_RegisterClassExA(uint32_t p) {
    auto c = At<WndClassEx32>(p);
    std::lock_guard<std::mutex> hold(WaitLock());
    std::string name = c->lpszClassName < 0x10000 ? "#" + std::to_string(c->lpszClassName) : At<char>(c->lpszClassName);
    for (auto& [atom, k] : g_classes)
        if (strcasecmp(k.name.c_str(), name.c_str()) == 0) {
            SetLastError(1410);   // ERROR_CLASS_ALREADY_EXISTS
            return 0;
        }
    uint32_t atom = g_nextAtom++;
    g_classes[atom] = Class{name, atom, c->lpfnWndProc, c->style, c->hCursor, c->hIcon, c->hbrBackground, c->cbClsExtra,
                            c->cbWndExtra};
    Log("window class %s (%04x): procedure %08x", name.c_str(), atom, c->lpfnWndProc);
    return atom;
}

unsigned int gen_imp_SetClassLongA(uint32_t hwnd, uint32_t index, uint32_t value) {
    std::lock_guard<std::mutex> hold(WaitLock());
    Window* w = WindowOf(hwnd);
    if (!w) return 0;
    Class& c = g_classes[w->atom];
    uint32_t* field = nullptr;
    switch (static_cast<int32_t>(index)) {
        case -12: field = &c.cursor; break;   // GCL_HCURSOR
        case -14: field = &c.icon; break;     // GCL_HICON
        case -10: field = &c.brush; break;    // GCL_HBRBACKGROUND
        case -26: field = &c.style; break;    // GCL_STYLE
        case -24: field = &c.proc; break;     // GCL_WNDPROC
        default: return 0;
    }
    uint32_t old = *field;
    *field = value;
    return old;
}

unsigned int gen_imp_DefWindowProcA(uint32_t hwnd, uint32_t msg, uint32_t wp, uint32_t lp) {
    (void)lp;
    switch (msg) {
        case WM_NCCREATE: return 1;
        case WM_ERASEBKGND: return 1;
        case WM_NCACTIVATE: return 1;
        case WM_CLOSE: Destroy(hwnd); return 0;
        case WM_SYSCOMMAND:
            if ((wp & 0xFFF0) == 0xF060) Send(hwnd, WM_CLOSE, 0, 0);   // SC_CLOSE
            return 0;
        default: return 0;
    }
}

unsigned int gen_imp_GetMessageW(uint32_t msg, uint32_t hwnd, uint32_t lo, uint32_t hi) {
    Msg32 m;
    Next(hwnd, lo, hi, true, true, &m);
    PutMsg(msg, m);
    return m.message == WM_QUIT ? 0 : 1;
}
unsigned int gen_imp_PeekMessageA(uint32_t msg, uint32_t hwnd, uint32_t lo, uint32_t hi, uint32_t flags) {
    Msg32 m;
    if (!Next(hwnd, lo, hi, (flags & 1) != 0, false, &m)) return 0;
    PutMsg(msg, m);
    return 1;
}
unsigned int gen_imp_PeekMessageW(uint32_t msg, uint32_t hwnd, uint32_t lo, uint32_t hi, uint32_t flags) {
    return gen_imp_PeekMessageA(msg, hwnd, lo, hi, flags);
}
unsigned int gen_imp_TranslateMessage(uint32_t) { return 0; }   // (no keyboard from the host yet)
unsigned int gen_imp_TranslateAcceleratorA(uint32_t, uint32_t, uint32_t) { return 0; }
unsigned int gen_imp_DispatchMessageA(uint32_t msg) {
    const Msg32 m = *At<Msg32>(msg);
    if (m.message == WM_TIMER && m.lParam) return CallRef(m.lParam, m.hwnd, WM_TIMER, m.wParam, m.time);
    if (!m.hwnd) return 0;
    return CallProc(m.hwnd, m.message, m.wParam, m.lParam);
}
unsigned int gen_imp_DispatchMessageW(uint32_t msg) { return gen_imp_DispatchMessageA(msg); }

// MsgWaitForMultipleObjects(n, handles, all, ms, wake mask)
unsigned int gen_imp_MsgWaitForMultipleObjects(uint32_t n, uint32_t p, uint32_t all, uint32_t ms, uint32_t mask) {
    return WaitAny(n ? At<uint32_t>(p) : nullptr, n, all != 0, ms, mask ? mask : 0xFF);
}

// MessageBox: logged; answered with its default button (no dialog over the game on a phone)
static unsigned int Answer(uint32_t type) {
    static const unsigned buttons[][3] = {{1, 1, 1}, {1, 2, 2}, {3, 4, 5}, {6, 7, 2}, {6, 7, 7}, {4, 2, 2}, {2, 10, 11}};
    unsigned kind = type & 0xF, def = (type >> 8) & 0xF;
    return buttons[kind < 7 ? kind : 0][def < 3 ? def : 0];
}
unsigned int gen_imp_MessageBoxW(uint32_t, uintptr_t text, uintptr_t caption, uint32_t type) {
    Log("MessageBox [%s] %s", Narrow(WStr(caption)).c_str(), Narrow(WStr(text)).c_str());
    return Answer(type);
}
unsigned int gen_imp_MessageBoxA(uint32_t, uintptr_t text, uintptr_t caption, uint32_t type) {
    Log("MessageBox [%s] %s", Narrow(Ansi16(Str(caption)).c_str()).c_str(), Narrow(Ansi16(Str(text)).c_str()).c_str());
    return Answer(type);
}

// (the screen's centre: no mouse from the host yet)
unsigned int gen_imp_GetCursorPos(uint32_t out) {
    std::lock_guard<std::mutex> hold(WaitLock());
    if (out) *At<int32_t>(out) = g_screenW / 2, *At<int32_t>(out + 4) = g_screenH / 2;
    return 1;
}

}  // extern "C"

// CreateWindowExA(exStyle, class, name, style, x, y, w, h, parent, menu, instance, param)
static uint32_t CreateWindowExA_(uint32_t exStyle, uint32_t cls, uint32_t name, uint32_t style, uint32_t x, uint32_t y,
                                 uint32_t w, uint32_t h, uint32_t parent, uint32_t menu, uint32_t instance, uint32_t param) {
    uint32_t hwnd;
    CreateStruct32 cs;
    {
        std::lock_guard<std::mutex> hold(WaitLock());
        uint32_t atom = ClassAtom(cls);
        auto it = g_classes.find(atom);
        if (it == g_classes.end()) {
            Log("CreateWindowEx: no class %s", cls < 0x10000 ? "(atom)" : At<char>(cls));
            SetLastError(1407);   // ERROR_CANNOT_FIND_WND_CLASS
            return 0;
        }
        hwnd = g_nextHwnd;
        g_nextHwnd += 0x10;
        Window win{};
        win.hwnd = hwnd;
        win.tid = CurrentThreadId();
        win.proc = it->second.proc;
        win.atom = atom;
        win.style = style;
        win.exStyle = exStyle;
        win.parent = parent;
        win.menu = menu;
        win.instance = instance;
        win.param = param;
        const bool useDefault = static_cast<int32_t>(w) == static_cast<int32_t>(0x80000000);
        win.x = static_cast<int32_t>(x) == static_cast<int32_t>(0x80000000) ? 0 : static_cast<int32_t>(x);
        win.y = static_cast<int32_t>(y) == static_cast<int32_t>(0x80000000) ? 0 : static_cast<int32_t>(y);
        win.w = useDefault ? g_screenW : static_cast<int32_t>(w);
        win.h = useDefault ? g_screenH : static_cast<int32_t>(h);
        win.title = name ? At<char>(name) : "";
        win.extra.resize(std::max<int32_t>(it->second.wndExtra, 0));
        g_windows[hwnd] = win;
        if (!parent && !g_main) g_main = hwnd;
        cs = {param, instance, menu, parent, win.h, win.w, win.y, win.x, static_cast<int32_t>(style), name, cls, exStyle};
        Log("window %08x \"%s\" %dx%d at (%d,%d), style %08x, class %s", hwnd, win.title.c_str(), win.w, win.h, win.x,
            win.y, style, it->second.name.c_str());
    }
    // (the structure on this thread's stack: below 2 GB, as the reference's own)
    if (!Send(hwnd, WM_NCCREATE, 0, Low(&cs))) {
        Log("window %08x: WM_NCCREATE refused", hwnd);
        Destroy(hwnd);
        return 0;
    }
    if (static_cast<int32_t>(Send(hwnd, WM_CREATE, 0, Low(&cs))) == -1) {
        Log("window %08x: WM_CREATE refused", hwnd);
        Destroy(hwnd);
        return 0;
    }
    if (style & 0x10000000) Show(hwnd, true);   // WS_VISIBLE
    return hwnd;
}
RH_REG(USER32, CreateWindowExA, CreateWindowExA_)

static uint32_t ShowWindow_(uint32_t hwnd, uint32_t cmd) {
    bool was;
    {
        std::lock_guard<std::mutex> hold(WaitLock());
        Window* w = WindowOf(hwnd);
        if (!w) return 0;
        was = w->visible;
    }
    Show(hwnd, cmd != 0 /* SW_HIDE */ && cmd != 6 /* SW_MINIMIZE */);
    return was;
}
RH_REG(USER32, ShowWindow, ShowWindow_)
static uint32_t UpdateWindow_(uint32_t) { return 1; }
RH_REG(USER32, UpdateWindow, UpdateWindow_)
static uint32_t ValidateRect_(uint32_t, uint32_t) { return 1; }
RH_REG(USER32, ValidateRect, ValidateRect_)

static uint32_t SetWindowPos_(uint32_t hwnd, uint32_t, uint32_t x, uint32_t y, uint32_t cx, uint32_t cy, uint32_t flags) {
    bool sized = false, moved = false;
    int32_t w, h, nx, ny;
    {
        std::lock_guard<std::mutex> hold(WaitLock());
        Window* win = WindowOf(hwnd);
        if (!win) return 0;
        if (!(flags & 0x1) && (win->w != static_cast<int32_t>(cx) || win->h != static_cast<int32_t>(cy))) {   // SWP_NOSIZE
            win->w = static_cast<int32_t>(cx), win->h = static_cast<int32_t>(cy);
            sized = true;
        }
        if (!(flags & 0x2) && (win->x != static_cast<int32_t>(x) || win->y != static_cast<int32_t>(y))) {     // SWP_NOMOVE
            win->x = static_cast<int32_t>(x), win->y = static_cast<int32_t>(y);
            moved = true;
        }
        w = win->w, h = win->h, nx = win->x, ny = win->y;
    }
    if (sized) Send(hwnd, WM_SIZE, 0, static_cast<uint32_t>((w & 0xFFFF) | (h << 16)));
    if (moved) Send(hwnd, WM_MOVE, 0, static_cast<uint32_t>((nx & 0xFFFF) | (ny << 16)));
    if (flags & 0x40) Show(hwnd, true);    // SWP_SHOWWINDOW
    if (flags & 0x80) Show(hwnd, false);   // SWP_HIDEWINDOW
    return 1;
}
RH_REG(USER32, SetWindowPos, SetWindowPos_)

static uint32_t GetClientRect_(uint32_t hwnd, uint32_t out) {
    std::lock_guard<std::mutex> hold(WaitLock());
    Window* w = WindowOf(hwnd);
    if (!w) return SetLastError(1400 /* ERROR_INVALID_WINDOW_HANDLE */), 0;
    *At<Rect32>(out) = {0, 0, w->w, w->h};
    return 1;
}
RH_REG(USER32, GetClientRect, GetClientRect_)
static uint32_t GetWindowRect_(uint32_t hwnd, uint32_t out) {
    std::lock_guard<std::mutex> hold(WaitLock());
    Window* w = WindowOf(hwnd);
    if (!w) return SetLastError(1400), 0;
    *At<Rect32>(out) = {w->x, w->y, w->x + w->w, w->y + w->h};
    return 1;
}
RH_REG(USER32, GetWindowRect, GetWindowRect_)
// (no frame: the window's rectangle is its client area's)
static uint32_t AdjustWindowRect_(uint32_t, uint32_t, uint32_t) { return 1; }
RH_REG(USER32, AdjustWindowRect, AdjustWindowRect_)
static uint32_t ClientToScreen_(uint32_t hwnd, uint32_t pt) {
    std::lock_guard<std::mutex> hold(WaitLock());
    Window* w = WindowOf(hwnd);
    if (!w) return 0;
    *At<int32_t>(pt) += w->x;
    *At<int32_t>(pt + 4) += w->y;
    return 1;
}
RH_REG(USER32, ClientToScreen, ClientToScreen_)
static uint32_t ScreenToClient_(uint32_t hwnd, uint32_t pt) {
    std::lock_guard<std::mutex> hold(WaitLock());
    Window* w = WindowOf(hwnd);
    if (!w) return 0;
    *At<int32_t>(pt) -= w->x;
    *At<int32_t>(pt + 4) -= w->y;
    return 1;
}
RH_REG(USER32, ScreenToClient, ScreenToClient_)

// SetWindowLongA: GWL_WNDPROC -4, GWL_USERDATA -21, GWL_STYLE -16, GWL_EXSTYLE -20, extra bytes >= 0
static uint32_t SetWindowLongA_(uint32_t hwnd, uint32_t index, uint32_t value) {
    std::lock_guard<std::mutex> hold(WaitLock());
    Window* w = WindowOf(hwnd);
    if (!w) return SetLastError(1400), 0;
    int32_t i = static_cast<int32_t>(index);
    uint32_t old = 0;
    switch (i) {
        case -4: old = w->proc, w->proc = value; break;
        case -21: old = w->userData, w->userData = value; break;
        case -16: old = w->style, w->style = value; break;
        case -20: old = w->exStyle, w->exStyle = value; break;
        case -12: old = w->menu, w->menu = value; break;
        default:
            if (i >= 0 && static_cast<size_t>(i) + 4 <= w->extra.size()) {
                memcpy(&old, &w->extra[i], 4);
                memcpy(&w->extra[i], &value, 4);
            } else {
                return SetLastError(1413 /* ERROR_INVALID_INDEX */), 0;
            }
    }
    SetLastError(0);
    return old;
}
RH_REG(USER32, SetWindowLongA, SetWindowLongA_)

static uint32_t GetParent_(uint32_t hwnd) {
    std::lock_guard<std::mutex> hold(WaitLock());
    Window* w = WindowOf(hwnd);
    return w ? w->parent : 0;
}
RH_REG(USER32, GetParent, GetParent_)
static uint32_t GetActiveWindow_() {
    std::lock_guard<std::mutex> hold(WaitLock());
    return g_paused ? 0 : g_active;
}
RH_REG(USER32, GetActiveWindow, GetActiveWindow_)
static uint32_t SetForegroundWindow_(uint32_t hwnd) {
    std::lock_guard<std::mutex> hold(WaitLock());
    if (WindowOf(hwnd)) g_active = hwnd;
    return 1;
}
RH_REG(USER32, SetForegroundWindow, SetForegroundWindow_)
static uint32_t IsIconic_(uint32_t) {
    std::lock_guard<std::mutex> hold(WaitLock());
    return g_paused;
}
RH_REG(USER32, IsIconic, IsIconic_)
static uint32_t IsZoomed_(uint32_t) { return 0; }
RH_REG(USER32, IsZoomed, IsZoomed_)
static uint32_t IsWindowVisible_(uint32_t hwnd) {
    std::lock_guard<std::mutex> hold(WaitLock());
    Window* w = WindowOf(hwnd);
    return w && w->visible;
}
RH_REG(USER32, IsWindowVisible, IsWindowVisible_)
static uint32_t IsWindowEnabled_(uint32_t hwnd) {
    std::lock_guard<std::mutex> hold(WaitLock());
    Window* w = WindowOf(hwnd);
    return w && w->enabled;
}
RH_REG(USER32, IsWindowEnabled, IsWindowEnabled_)
static uint32_t GetWindowTextA_(uint32_t hwnd, uint32_t buf, uint32_t cap) {
    std::lock_guard<std::mutex> hold(WaitLock());
    Window* w = WindowOf(hwnd);
    if (!w || !cap) return 0;
    size_t n = std::min<size_t>(w->title.size(), cap - 1);
    memcpy(At(buf), w->title.data(), n);
    At<char>(buf)[n] = 0;
    return static_cast<uint32_t>(n);
}
RH_REG(USER32, GetWindowTextA, GetWindowTextA_)
static uint32_t GetClassNameA_(uint32_t hwnd, uint32_t buf, uint32_t cap) {
    std::lock_guard<std::mutex> hold(WaitLock());
    Window* w = WindowOf(hwnd);
    if (!w || !cap) return 0;
    const std::string& n = g_classes[w->atom].name;
    size_t k = std::min<size_t>(n.size(), cap - 1);
    memcpy(At(buf), n.data(), k);
    At<char>(buf)[k] = 0;
    return static_cast<uint32_t>(k);
}
RH_REG(USER32, GetClassNameA, GetClassNameA_)
// EnumWindows(callback, lParam): the top-level windows, until the callback says stop
static uint32_t EnumWindows_(uint32_t fn, uint32_t lp) {
    std::vector<uint32_t> hs;
    {
        std::lock_guard<std::mutex> hold(WaitLock());
        for (auto& [h, w] : g_windows)
            if (!w.parent) hs.push_back(h);
    }
    for (uint32_t h : hs)
        if (!CallRef(fn, h, lp)) break;
    return 1;
}
RH_REG(USER32, EnumWindows, EnumWindows_)

// ---- posting and sending ---------------------------------------------------------------------------
static uint32_t PostMessageA_(uint32_t hwnd, uint32_t msg, uint32_t wp, uint32_t lp) {
    std::lock_guard<std::mutex> hold(WaitLock());
    if (hwnd == 0) {
        PostTo(CurrentThreadId(), Make(0, msg, wp, lp));
        return 1;
    }
    if (hwnd == 0xFFFF) {   // HWND_BROADCAST: the top-level windows
        for (auto& [h, w] : g_windows)
            if (!w.parent) PostTo(w.tid, Make(h, msg, wp, lp));
        return 1;
    }
    Window* w = WindowOf(hwnd);
    if (!w) return SetLastError(1400), 0;
    PostTo(w->tid, Make(hwnd, msg, wp, lp));
    return 1;
}
RH_REG(USER32, PostMessageA, PostMessageA_)
static uint32_t PostThreadMessageA_(uint32_t tid, uint32_t msg, uint32_t wp, uint32_t lp) {
    std::lock_guard<std::mutex> hold(WaitLock());
    PostTo(tid, Make(0, msg, wp, lp));
    return 1;
}
RH_REG(USER32, PostThreadMessageA, PostThreadMessageA_)
static uint32_t PostQuitMessage_(uint32_t code) {
    std::lock_guard<std::mutex> hold(WaitLock());
    Queue& q = g_queues[CurrentThreadId()];
    q.quit = true;
    q.quitCode = code;
    WaitNotify();
    return 0;
}
RH_REG(USER32, PostQuitMessage, PostQuitMessage_)
static uint32_t SendMessageA_(uint32_t hwnd, uint32_t msg, uint32_t wp, uint32_t lp) { return Send(hwnd, msg, wp, lp); }
RH_REG(USER32, SendMessageA, SendMessageA_)
// GetQueueStatus: the input kinds waiting (high word) and new (low word), approximately
static uint32_t GetQueueStatus_(uint32_t flags) {
    std::lock_guard<std::mutex> hold(WaitLock());
    bool any = QueueHasInput(CurrentThreadId(), flags);
    uint32_t s = any ? (flags & 0x4FF) : 0;
    return (s << 16) | s;
}
RH_REG(USER32, GetQueueStatus, GetQueueStatus_)
static uint32_t RegisterWindowMessageA_(uint32_t name) {
    std::lock_guard<std::mutex> hold(WaitLock());
    std::string n = At<char>(name);
    for (char& c : n) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    auto it = g_registeredMessages.find(n);
    if (it != g_registeredMessages.end()) return it->second;
    uint32_t id = 0xC000 + static_cast<uint32_t>(g_registeredMessages.size()) + 0x100;
    g_registeredMessages[n] = id;
    return id;
}
RH_REG(USER32, RegisterWindowMessageA, RegisterWindowMessageA_)

// ---- timers ---------------------------------------------------------------------------------------
static uint32_t SetTimer_(uint32_t hwnd, uint32_t id, uint32_t ms, uint32_t proc) {
    std::lock_guard<std::mutex> hold(WaitLock());
    uint32_t tid = CurrentThreadId();
    if (hwnd) {
        Window* w = WindowOf(hwnd);
        if (!w) return SetLastError(1400), 0;
        tid = w->tid;
    } else {
        id = g_nextTimer++;
    }
    Queue& q = g_queues[tid];
    for (Timer& t : q.timers)
        if (t.hwnd == hwnd && t.id == id) {
            t.ms = ms, t.proc = proc, t.due = NowMs() + ms;
            return hwnd ? 1 : id;
        }
    q.timers.push_back({hwnd, id, ms, proc, NowMs() + ms});
    WaitNotify();
    return hwnd ? (id ? id : 1) : id;
}
RH_REG(USER32, SetTimer, SetTimer_)
static uint32_t KillTimer_(uint32_t hwnd, uint32_t id) {
    std::lock_guard<std::mutex> hold(WaitLock());
    for (auto& [tid, q] : g_queues)
        for (auto it = q.timers.begin(); it != q.timers.end(); ++it)
            if (it->hwnd == hwnd && it->id == id) {
                q.timers.erase(it);
                return 1;
            }
    return 0;
}
RH_REG(USER32, KillTimer, KillTimer_)

// ---- the system's metrics: the host's screen ---------------------------------------------------------
static uint32_t GetSystemMetrics_(uint32_t i) {
    std::lock_guard<std::mutex> hold(WaitLock());
    switch (i) {
        case 0: case 16: case 61: case 78: return static_cast<uint32_t>(g_screenW);   // CXSCREEN, CXFULLSCREEN, CXMAXIMIZED, CXVIRTUALSCREEN
        case 1: case 17: case 62: case 79: return static_cast<uint32_t>(g_screenH);
        case 76: case 77: return 0;   // the virtual screen's origin
        case 80: return 1;            // SM_CMONITORS
        case 19: return 1;            // SM_MOUSEPRESENT
        case 43: return 3;            // SM_CMOUSEBUTTONS
        case 5: case 6: return 1;     // borders
        case 7: case 8: return 3;     // fixed frame
        case 32: case 33: return 8;   // sizing frame
        case 4: return 23;            // SM_CYCAPTION
        case 11: case 12: return 32;  // icon
        case 13: case 14: return 32;  // cursor
        case 49: case 50: return 16;  // small icon
        case 0x1000: return 0;        // SM_REMOTESESSION
        default: return 0;
    }
}
RH_REG(USER32, GetSystemMetrics, GetSystemMetrics_)

// ---- the keyboard: none from the host yet; the tables the reference reads -------------------------
static uint32_t GetKeyboardState_(uint32_t out) {
    memset(At(out), 0, 256);
    return 1;
}
RH_REG(USER32, GetKeyboardState, GetKeyboardState_)
namespace {
// US layout scan codes for VK 0x30-0x5A, and the few named keys
uint32_t ScanOf(uint32_t vk) {
    static const uint8_t digits[10] = {0x0B, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A};
    static const uint8_t letters[26] = {0x1E, 0x30, 0x2E, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26, 0x32,
                                        0x31, 0x18, 0x19, 0x10, 0x13, 0x1F, 0x14, 0x16, 0x2F, 0x11, 0x2D, 0x15, 0x2C};
    if (vk >= '0' && vk <= '9') return digits[vk - '0'];
    if (vk >= 'A' && vk <= 'Z') return letters[vk - 'A'];
    switch (vk) {
        case 0x08: return 0x0E; case 0x09: return 0x0F; case 0x0D: return 0x1C; case 0x10: return 0x2A;
        case 0x11: return 0x1D; case 0x12: return 0x38; case 0x1B: return 0x01; case 0x20: return 0x39;
        default: return (vk >= 0x70 && vk <= 0x79) ? 0x3B + (vk - 0x70) : 0;
    }
}
uint32_t VkOf(uint32_t scan) {
    for (uint32_t vk = 1; vk < 0xFF; vk++)
        if (ScanOf(vk) == scan) return vk;
    return 0;
}
}  // namespace
// MapVirtualKeyA(code, MAPVK_VK_TO_VSC 0 / VSC_TO_VK 1 / VK_TO_CHAR 2 / VSC_TO_VK_EX 3)
static uint32_t MapVirtualKeyA_(uint32_t code, uint32_t type) {
    switch (type) {
        case 0: return ScanOf(code);
        case 1: case 3: return VkOf(code);
        case 2: return (code >= '0' && code <= '9') || (code >= 'A' && code <= 'Z') || code == ' ' ? code : 0;
        default: return 0;
    }
}
RH_REG(USER32, MapVirtualKeyA, MapVirtualKeyA_)
static uint32_t GetKeyNameTextA_(uint32_t lp, uint32_t buf, uint32_t cap) {
    uint32_t vk = VkOf((lp >> 16) & 0xFF);
    char name[32];
    if ((vk >= '0' && vk <= '9') || (vk >= 'A' && vk <= 'Z')) snprintf(name, sizeof name, "%c", static_cast<char>(vk));
    else snprintf(name, sizeof name, "Key %u", (lp >> 16) & 0xFF);
    if (!cap) return 0;
    size_t n = std::min<size_t>(strlen(name), cap - 1);
    memcpy(At(buf), name, n);
    At<char>(buf)[n] = 0;
    return static_cast<uint32_t>(n);
}
RH_REG(USER32, GetKeyNameTextA, GetKeyNameTextA_)
static uint32_t ToAscii_(uint32_t vk, uint32_t, uint32_t state, uint32_t out, uint32_t) {
    bool shift = state && (At<uint8_t>(state)[0x10] & 0x80);
    uint32_t c = 0;
    if (vk >= 'A' && vk <= 'Z') c = shift ? vk : vk + 32;
    else if ((vk >= '0' && vk <= '9') || vk == ' ' || vk == 0x0D || vk == 0x08) c = vk;
    if (!c) return 0;
    *At<uint16_t>(out) = static_cast<uint16_t>(c);
    return 1;
}
RH_REG(USER32, ToAscii, ToAscii_)
static uint32_t ToUnicode_(uint32_t vk, uint32_t scan, uint32_t state, uint32_t out, uint32_t cap, uint32_t) {
    if (!cap) return 0;
    uint16_t c = 0;
    if (!ToAscii_(vk, scan, state, Low(&c), 0)) return 0;
    *At<char16_t>(out) = c;
    return 1;
}
RH_REG(USER32, ToUnicode, ToUnicode_)
static uint32_t SendInput_(uint32_t, uint32_t, uint32_t) { return 0; }
RH_REG(USER32, SendInput, SendInput_)
static uint32_t RegisterHotKey_(uint32_t, uint32_t, uint32_t, uint32_t) { return 1; }
RH_REG(USER32, RegisterHotKey, RegisterHotKey_)
static uint32_t UnregisterHotKey_(uint32_t, uint32_t) { return 1; }
RH_REG(USER32, UnregisterHotKey, UnregisterHotKey_)

// ---- the cursor: no mouse pointer on a phone; handles of their own, kept --------------------------
static uint32_t SetCursorPos_(uint32_t, uint32_t) { return 1; }
RH_REG(USER32, SetCursorPos, SetCursorPos_)
static uint32_t g_cursor = 0;
static uint32_t SetCursor_(uint32_t c) {
    uint32_t old = g_cursor;
    g_cursor = c;
    return old;
}
RH_REG(USER32, SetCursor, SetCursor_)
static uint32_t ClipCursor_(uint32_t) { return 1; }
RH_REG(USER32, ClipCursor, ClipCursor_)
static uint32_t g_capture = 0;
static uint32_t SetCapture_(uint32_t hwnd) {
    uint32_t old = g_capture;
    g_capture = hwnd;
    return old;
}
RH_REG(USER32, SetCapture, SetCapture_)
static uint32_t ReleaseCapture_() { return g_capture = 0, 1; }
RH_REG(USER32, ReleaseCapture, ReleaseCapture_)
// (an icon, cursor or image: a handle that names it, never drawn here)
static uint32_t FakeHandle() {
    static std::atomic<uint32_t> next{0x00020000};
    return next += 4;
}
static uint32_t LoadCursorA_(uint32_t, uint32_t) { return FakeHandle(); }
RH_REG(USER32, LoadCursorA, LoadCursorA_)
static uint32_t LoadIconA_(uint32_t, uint32_t) { return FakeHandle(); }
RH_REG(USER32, LoadIconA, LoadIconA_)
static uint32_t LoadImageA_(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t) { return FakeHandle(); }
RH_REG(USER32, LoadImageA, LoadImageA_)

// LoadStringA(instance, id, buffer, size): the image's string table (RT_STRING: block id/16 + 1,
// its 16 counted UTF-16 strings), in the ANSI code page
static uint32_t LoadStringA_(uint32_t, uint32_t id, uint32_t buf, uint32_t cap) {
    uint32_t data = 0, size = 0;
    if (!FindResource32(6, id / 16 + 1, &data, &size)) {
        if (cap) *At<char>(buf) = 0;
        return SetLastError(1814 /* ERROR_RESOURCE_NAME_NOT_FOUND */), 0;
    }
    uint32_t p = data;
    for (uint32_t k = 0; k < id % 16; k++) p += 2 + 2 * *At<uint16_t>(p);
    uint16_t len = *At<uint16_t>(p);
    std::string s = AnsiOf(std::u16string(At<char16_t>(p + 2), len));
    if (cap == 0) {
        // (0: a read-only pointer to the resource itself, as Windows')
        *At<uint32_t>(buf) = p + 2;
        return len;
    }
    size_t n = std::min<size_t>(s.size(), cap - 1);
    memcpy(At(buf), s.data(), n);
    At<char>(buf)[n] = 0;
    return static_cast<uint32_t>(n);
}
RH_REG(USER32, LoadStringA, LoadStringA_)

// ---- the clipboard: empty, and kept so --------------------------------------------------------------
static uint32_t OpenClipboard_(uint32_t) { return 1; }
RH_REG(USER32, OpenClipboard, OpenClipboard_)
static uint32_t CloseClipboard_() { return 1; }
RH_REG(USER32, CloseClipboard, CloseClipboard_)
static uint32_t GetClipboardData_(uint32_t) { return 0; }
RH_REG(USER32, GetClipboardData, GetClipboardData_)
static uint32_t SetClipboardData_(uint32_t, uint32_t h) { return h; }
RH_REG(USER32, SetClipboardData, SetClipboardData_)
static uint32_t GetPriorityClipboardFormat_(uint32_t, uint32_t) { return 0; }   // (the clipboard empty)
RH_REG(USER32, GetPriorityClipboardFormat, GetPriorityClipboardFormat_)
static uint32_t SetClipboardViewer_(uint32_t) { return 0; }
RH_REG(USER32, SetClipboardViewer, SetClipboardViewer_)
static uint32_t ChangeClipboardChain_(uint32_t, uint32_t) { return 0; }
RH_REG(USER32, ChangeClipboardChain, ChangeClipboardChain_)

// ---- comctl32's window subclasses: a chain of procedures before the window's own, each called with
// (hwnd, msg, wParam, lParam, id, ref data); DefSubclassProc passes a message to the next ----------
static uint32_t SetWindowSubclass_(uint32_t hwnd, uint32_t proc, uint32_t id, uint32_t ref) {
    std::lock_guard<std::mutex> hold(WaitLock());
    Window* w = WindowOf(hwnd);
    if (!w) return 0;
    for (Subclass& s : w->subclasses)
        if (s.proc == proc && s.id == id) {
            s.ref = ref;
            return 1;
        }
    w->subclasses.push_back({proc, id, ref});
    return 1;
}
RH_REG(COMCTL32, SetWindowSubclass, SetWindowSubclass_)
static uint32_t RemoveWindowSubclass_(uint32_t hwnd, uint32_t proc, uint32_t id) {
    std::lock_guard<std::mutex> hold(WaitLock());
    Window* w = WindowOf(hwnd);
    if (!w) return 0;
    for (auto it = w->subclasses.begin(); it != w->subclasses.end(); ++it)
        if (it->proc == proc && it->id == id) {
            w->subclasses.erase(it);
            return 1;
        }
    return 0;
}
RH_REG(COMCTL32, RemoveWindowSubclass, RemoveWindowSubclass_)
static uint32_t DefSubclassProc_(uint32_t hwnd, uint32_t msg, uint32_t wp, uint32_t lp) {
    Subclass next{};
    uint32_t proc = 0;
    bool sub = false;
    {
        std::lock_guard<std::mutex> hold(WaitLock());
        Window* w = WindowOf(hwnd);
        if (!w) return 0;
        // (the chain is called from the top, the last set: depth d is subclasses[size - 1 - d])
        int depth = t_subclassDepth < 0 ? 0 : t_subclassDepth + 1;
        if (depth < static_cast<int>(w->subclasses.size())) {
            next = w->subclasses[w->subclasses.size() - 1 - depth];
            sub = true;
        }
        proc = w->proc;
    }
    if (sub) {
        int saved = t_subclassDepth;
        t_subclassDepth = saved < 0 ? 0 : saved + 1;
        uint32_t r = CallRef(next.proc, hwnd, msg, wp, lp, next.id, next.ref);
        t_subclassDepth = saved;
        return r;
    }
    return proc ? CallRef(proc, hwnd, msg, wp, lp) : 0;
}
RH_REG(COMCTL32, DefSubclassProc, DefSubclassProc_)
