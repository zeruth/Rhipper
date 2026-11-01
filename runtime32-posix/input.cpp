// The host's keyboard, mouse and touch as Win32 and DirectInput 8 report them (input.h).
//
// One state for the whole process, under g_lock: the keys (by virtual key, as GetAsyncKeyState
// sees them, and by DirectInput scan code), the mouse's buttons, the cursor on the screen, the touch
// gesture, and each DirectInput device's buffer and deltas. A host event updates it and makes the
// messages Windows would post; they go to the reference's window (user32's PostInput) once the lock
// is released, so the two locks never nest. GetKeyState's state is apart: it follows the messages
// the reference has taken from its queue (InputSyncMessage), as Windows' does.
//
// A key is a Win32 virtual key and a DirectInput scan code (the PC's set-1 code, 0x80 for its E0
// prefix), from Android's key code (kKeys: a US keyboard's keys) or, failing that, the scan code
// Linux reports (the same as set 1 for the main block). The characters keys type are the device's
// own layout's (the host gives them), else the US layout's.
//
// Touch is the mouse for now, a provisional scheme until a proper touch one: one finger moves the
// cursor and, once it has moved past a slop, drags with the left button (a tap is a left click);
// a second finger landing before the first has dragged makes a two-finger gesture: lifted without
// moving, a right click; moved vertically, the wheel (fingers down = wheel forward, as content
// follows the fingers).
#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdio>
#include <deque>
#include <map>
#include <vector>

#include "Runtime.h"
#include "input.h"
#include "rhipper_host.h"

namespace rh {

namespace {

constexpr uint32_t WM_KEYDOWN = 0x100, WM_KEYUP = 0x101, WM_CHAR = 0x102, WM_SYSKEYDOWN = 0x104,
                   WM_SYSKEYUP = 0x105, WM_MOUSEMOVE = 0x200, WM_LBUTTONDOWN = 0x201, WM_LBUTTONUP = 0x202,
                   WM_RBUTTONDOWN = 0x204, WM_RBUTTONUP = 0x205, WM_MBUTTONDOWN = 0x207, WM_MBUTTONUP = 0x208,
                   WM_MOUSEWHEEL = 0x20A, WM_XBUTTONDOWN = 0x20B, WM_XBUTTONUP = 0x20C, WM_MOUSEHWHEEL = 0x20E;
constexpr uint32_t MK_LBUTTON = 1, MK_RBUTTON = 2, MK_SHIFT = 4, MK_CONTROL = 8, MK_MBUTTON = 0x10,
                   MK_XBUTTON1 = 0x20, MK_XBUTTON2 = 0x40;
constexpr uint8_t VK_LBUTTON = 1, VK_RBUTTON = 2, VK_MBUTTON = 4, VK_XBUTTON1 = 5, VK_XBUTTON2 = 6, VK_BACK = 8,
                  VK_TAB = 9, VK_CLEAR = 0x0C, VK_RETURN = 0x0D, VK_SHIFT = 0x10, VK_CONTROL = 0x11, VK_MENU = 0x12,
                  VK_PAUSE = 0x13, VK_CAPITAL = 0x14, VK_ESCAPE = 0x1B, VK_SPACE = 0x20, VK_PRIOR = 0x21,
                  VK_NEXT = 0x22, VK_END = 0x23, VK_HOME = 0x24, VK_LEFT = 0x25, VK_UP = 0x26, VK_RIGHT = 0x27,
                  VK_DOWN = 0x28, VK_SNAPSHOT = 0x2C, VK_INSERT = 0x2D, VK_DELETE = 0x2E, VK_NUMPAD0 = 0x60,
                  VK_F10 = 0x79, VK_NUMLOCK = 0x90, VK_SCROLL = 0x91, VK_LSHIFT = 0xA0, VK_RSHIFT = 0xA1,
                  VK_LCONTROL = 0xA2, VK_RCONTROL = 0xA3, VK_LMENU = 0xA4, VK_RMENU = 0xA5;
// Android's KeyEvent meta state
constexpr int META_CAPS_LOCK_ON = 0x100000, META_NUM_LOCK_ON = 0x200000,
              META_SCROLL_LOCK_ON = 0x400000;
// DirectInput's mouse offsets (DIMOUSESTATE2): lX, lY, lZ, rgbButtons[8]
constexpr uint32_t DIMOFS_X = 0, DIMOFS_Y = 4, DIMOFS_Z = 8, DIMOFS_BUTTON0 = 12;

// ---- the keys: Android key code -> Win32 virtual key, DirectInput scan code ------------------------
struct KeyDef {
    int16_t android;
    uint8_t vk, dik;
};
// (first match wins for the reverse lookups: the main block's keys before the keypad's)
constexpr KeyDef kKeys[] = {
    {111, VK_ESCAPE, 0x01},                 // ESCAPE
    {8, '1', 0x02}, {9, '2', 0x03}, {10, '3', 0x04}, {11, '4', 0x05}, {12, '5', 0x06},
    {13, '6', 0x07}, {14, '7', 0x08}, {15, '8', 0x09}, {16, '9', 0x0A}, {7, '0', 0x0B},
    {69, 0xBD, 0x0C},                       // MINUS          VK_OEM_MINUS
    {70, 0xBB, 0x0D},                       // EQUALS         VK_OEM_PLUS
    {67, VK_BACK, 0x0E},                    // DEL (backspace)
    {61, VK_TAB, 0x0F},                     // TAB
    {45, 'Q', 0x10}, {51, 'W', 0x11}, {33, 'E', 0x12}, {46, 'R', 0x13}, {48, 'T', 0x14},
    {53, 'Y', 0x15}, {49, 'U', 0x16}, {37, 'I', 0x17}, {43, 'O', 0x18}, {44, 'P', 0x19},
    {71, 0xDB, 0x1A},                       // LEFT_BRACKET   VK_OEM_4
    {72, 0xDD, 0x1B},                       // RIGHT_BRACKET  VK_OEM_6
    {66, VK_RETURN, 0x1C},                  // ENTER
    {113, VK_LCONTROL, 0x1D},               // CTRL_LEFT
    {29, 'A', 0x1E}, {47, 'S', 0x1F}, {32, 'D', 0x20}, {34, 'F', 0x21}, {35, 'G', 0x22},
    {36, 'H', 0x23}, {38, 'J', 0x24}, {39, 'K', 0x25}, {40, 'L', 0x26},
    {74, 0xBA, 0x27},                       // SEMICOLON      VK_OEM_1
    {75, 0xDE, 0x28},                       // APOSTROPHE     VK_OEM_7
    {68, 0xC0, 0x29},                       // GRAVE          VK_OEM_3
    {59, VK_LSHIFT, 0x2A},                  // SHIFT_LEFT
    {73, 0xDC, 0x2B},                       // BACKSLASH      VK_OEM_5
    {54, 'Z', 0x2C}, {52, 'X', 0x2D}, {31, 'C', 0x2E}, {50, 'V', 0x2F}, {30, 'B', 0x30},
    {42, 'N', 0x31}, {41, 'M', 0x32},
    {55, 0xBC, 0x33},                       // COMMA          VK_OEM_COMMA
    {56, 0xBE, 0x34},                       // PERIOD         VK_OEM_PERIOD
    {76, 0xBF, 0x35},                       // SLASH          VK_OEM_2
    {60, VK_RSHIFT, 0x36},                  // SHIFT_RIGHT
    {155, 0x6A, 0x37},                      // NUMPAD_MULTIPLY
    {57, VK_LMENU, 0x38},                   // ALT_LEFT
    {62, VK_SPACE, 0x39},                   // SPACE
    {115, VK_CAPITAL, 0x3A},                // CAPS_LOCK
    {131, 0x70, 0x3B}, {132, 0x71, 0x3C}, {133, 0x72, 0x3D}, {134, 0x73, 0x3E}, {135, 0x74, 0x3F},
    {136, 0x75, 0x40}, {137, 0x76, 0x41}, {138, 0x77, 0x42}, {139, 0x78, 0x43}, {140, 0x79, 0x44},   // F1-F10
    {143, VK_NUMLOCK, 0x45},                // NUM_LOCK
    {116, VK_SCROLL, 0x46},                 // SCROLL_LOCK
    {151, 0x67, 0x47}, {152, 0x68, 0x48}, {153, 0x69, 0x49},   // NUMPAD_7-9
    {156, 0x6D, 0x4A},                      // NUMPAD_SUBTRACT
    {148, 0x64, 0x4B}, {149, 0x65, 0x4C}, {150, 0x66, 0x4D},   // NUMPAD_4-6
    {157, 0x6B, 0x4E},                      // NUMPAD_ADD
    {145, 0x61, 0x4F}, {146, 0x62, 0x50}, {147, 0x63, 0x51},   // NUMPAD_1-3
    {144, 0x60, 0x52},                      // NUMPAD_0
    {158, 0x6E, 0x53},                      // NUMPAD_DOT
    {217, 0xE2, 0x73},                      // RO (JIS)       VK_OEM_102, DIK_ABNT_C1
    {141, 0x7A, 0x57}, {142, 0x7B, 0x58},   // F11, F12
    {218, 0x15, 0x70},                      // KANA           VK_KANA, DIK_KANA
    {214, 0x1C, 0x79},                      // HENKAN         VK_CONVERT
    {213, 0x1D, 0x7B},                      // MUHENKAN       VK_NONCONVERT
    {216, 0xDC, 0x7D},                      // YEN            VK_OEM_5, DIK_YEN
    {161, 0x92, 0x8D},                      // NUMPAD_EQUALS  VK_OEM_NEC_EQUAL
    {160, VK_RETURN, 0x9C},                 // NUMPAD_ENTER
    {114, VK_RCONTROL, 0x9D},               // CTRL_RIGHT
    {159, 0x6C, 0xB3},                      // NUMPAD_COMMA   VK_SEPARATOR
    {154, 0x6F, 0xB5},                      // NUMPAD_DIVIDE
    {120, VK_SNAPSHOT, 0xB7},               // SYSRQ (print screen)
    {58, VK_RMENU, 0xB8},                   // ALT_RIGHT
    {121, VK_PAUSE, 0xC5},                  // BREAK (pause)
    {122, VK_HOME, 0xC7},                   // MOVE_HOME
    {19, VK_UP, 0xC8},                      // DPAD_UP (a keyboard's arrows are DPAD keys)
    {92, VK_PRIOR, 0xC9},                   // PAGE_UP
    {21, VK_LEFT, 0xCB},                    // DPAD_LEFT
    {22, VK_RIGHT, 0xCD},                   // DPAD_RIGHT
    {123, VK_END, 0xCF},                    // MOVE_END
    {20, VK_DOWN, 0xD0},                    // DPAD_DOWN
    {93, VK_NEXT, 0xD1},                    // PAGE_DOWN
    {124, VK_INSERT, 0xD2},                 // INSERT
    {112, VK_DELETE, 0xD3},                 // FORWARD_DEL
    {117, 0x5B, 0xDB},                      // META_LEFT      VK_LWIN
    {118, 0x5C, 0xDC},                      // META_RIGHT     VK_RWIN
    {82, 0x5D, 0xDD},                       // MENU           VK_APPS
    {23, VK_RETURN, 0x1C},                  // DPAD_CENTER (a remote's OK)
};

const KeyDef* KeyOfAndroid(int code) {
    for (const KeyDef& k : kKeys)
        if (k.android == code) return &k;
    return nullptr;
}
// Linux KEY_* 1..88 are set 1's codes for the main block: a key Android has no code for
const KeyDef* KeyOfLinuxScan(int scan) {
    if (scan <= 0 || scan > 0x58) return nullptr;
    for (const KeyDef& k : kKeys)
        if (k.dik == scan) return &k;
    return nullptr;
}

// a DirectInput code as Win32's lParam has it: the set-1 code and the E0 (extended) bit. Two keys
// differ: Pause is 0x45 not extended, Num Lock 0x45 extended (DirectInput: 0xC5 and 0x45)
void Win32Scan(uint8_t dik, uint32_t* scan, bool* ext) {
    if (dik == 0xC5) *scan = 0x45, *ext = false;
    else if (dik == 0x45) *scan = 0x45, *ext = true;
    else *scan = dik & 0x7F, *ext = (dik & 0x80) != 0;
}

uint8_t GenericOf(uint8_t vk) {
    switch (vk) {
        case VK_LSHIFT: case VK_RSHIFT: return VK_SHIFT;
        case VK_LCONTROL: case VK_RCONTROL: return VK_CONTROL;
        case VK_LMENU: case VK_RMENU: return VK_MENU;
        default: return vk;
    }
}

// a keypad digit with Num Lock off is its navigation key (the same scan code)
uint8_t NumpadNav(uint8_t vk) {
    static const uint8_t nav[10] = {VK_INSERT, VK_END, VK_DOWN, VK_NEXT, VK_LEFT, VK_CLEAR, VK_RIGHT, VK_HOME, VK_UP, VK_PRIOR};
    if (vk >= VK_NUMPAD0 && vk <= VK_NUMPAD0 + 9) return nav[vk - VK_NUMPAD0];
    if (vk == 0x6E) return VK_DELETE;
    return vk;
}

// ---- the state -------------------------------------------------------------------------------------
std::mutex g_lock;
// the keys as the host reports them (written under g_lock, read anywhere): 0x80 down, 0x01 toggled
std::atomic<uint8_t> g_async[256];
uint8_t g_asyncPressed[256];                 // pressed since the last GetAsyncKeyState
std::atomic<uint8_t> g_sync[256];            // as the reference has retrieved them
std::atomic<uint32_t> g_downChar[256];       // the character the host gave with the key's last down
bool g_altOnly = false;                      // Alt down with no other key since: its up is WM_SYSKEYUP
uint8_t g_diKeys[256];                       // DirectInput's keyboard state

// the cursor, screen pixels (float: a captured mouse's motion is fractional once scaled)
bool g_cursorSet = false;
float g_cursorX = 0, g_cursorY = 0;
bool g_clip = false;
int32_t g_clipRect[4] = {};
std::atomic<int32_t> g_showCount{0};

int g_buttons = 0;                           // the mouse's RhipperButton bits
bool g_havePointer = false;                  // a last absolute point to measure DirectInput motion from
float g_lastX = 0, g_lastY = 0;
float g_diFracX = 0, g_diFracY = 0, g_wheelFrac = 0, g_hwheelFrac = 0;

// touch
enum class Touch { None, Pending, Drag, Two, TwoDone };
struct Finger {
    int id = -1;
    float x = 0, y = 0, x0 = 0, y0 = 0;
};
constexpr float kSlop = 24.f;                // surface pixels before a touch is a drag
constexpr uint64_t kTwoTapMs = 400;          // a two-finger tap's longest
constexpr float kWheelPerClientPixel = 4.f;  // a 30-pixel two-finger drag: one notch (120)
Touch g_touch = Touch::None;
Finger g_fingers[2];
uint64_t g_twoAt = 0;
bool g_twoMoved = false;
float g_twoY = 0, g_twoWheel = 0;

// DirectInput
struct DiEvent {
    uint32_t ofs, data, time, seq;
};
struct Sink {
    bool keyboard = false, absolute = false, foreground = false, acquired = false;
    bool lost = false, pauseLost = false, overflow = false;
    uint32_t bufferSize = 0;
    std::deque<DiEvent> events;
    int32_t dx = 0, dy = 0, dz = 0;          // since the last GetDeviceState
    int32_t ax = 0, ay = 0, az = 0;          // DIPROPAXISMODE_ABS's positions
};
std::map<int, Sink> g_sinks;
int g_nextSink = 1;
uint32_t g_diSeq = 0;
bool g_paused = false;

// messages made under the lock, posted after it
struct Out {
    uint32_t msg, wp, lp;
    int32_t x, y;
};

// a key's or a button's change into each acquired device's buffer (full: dropped, and said so)
void DiPush(bool keyboard, uint32_t ofs, uint32_t data) {
    uint32_t now = static_cast<uint32_t>(NowMs()), seq = ++g_diSeq;
    for (auto& [id, s] : g_sinks) {
        if (s.keyboard != keyboard || !s.acquired || s.bufferSize == 0) continue;
        if (s.events.size() >= s.bufferSize) {
            s.overflow = true;
            continue;
        }
        s.events.push_back({ofs, data, now, seq});
    }
}

inline void Put(std::atomic<uint8_t>& a, int v) { a.store(static_cast<uint8_t>(v)); }

void DiMouseAxis(uint32_t ofs, int32_t delta) {
    for (auto& [id, s] : g_sinks) {
        if (s.keyboard || !s.acquired) continue;
        int32_t* d = ofs == DIMOFS_X ? &s.dx : ofs == DIMOFS_Y ? &s.dy : &s.dz;
        int32_t* a = ofs == DIMOFS_X ? &s.ax : ofs == DIMOFS_Y ? &s.ay : &s.az;
        *d += delta;
        *a += delta;
    }
    // (the absolute value differs per device: pushed per sink)
    uint32_t now = static_cast<uint32_t>(NowMs()), seq = ++g_diSeq;
    for (auto& [id, s] : g_sinks) {
        if (s.keyboard || !s.acquired || s.bufferSize == 0) continue;
        if (s.events.size() >= s.bufferSize) {
            s.overflow = true;
            continue;
        }
        int32_t a = ofs == DIMOFS_X ? s.ax : ofs == DIMOFS_Y ? s.ay : s.az;
        s.events.push_back({ofs, static_cast<uint32_t>(s.absolute ? a : delta), now, seq});
    }
}

// the mouse's relative motion in client pixels, as DirectInput's mickeys (fractions carried)
void DiMotion(float dx, float dy) {
    g_diFracX += dx;
    g_diFracY += dy;
    int32_t ix = static_cast<int32_t>(g_diFracX), iy = static_cast<int32_t>(g_diFracY);
    g_diFracX -= static_cast<float>(ix);
    g_diFracY -= static_cast<float>(iy);
    if (ix) DiMouseAxis(DIMOFS_X, ix);
    if (iy) DiMouseAxis(DIMOFS_Y, iy);
}

int32_t CursorXi() { return static_cast<int32_t>(std::floor(g_cursorX)); }
int32_t CursorYi() { return static_cast<int32_t>(std::floor(g_cursorY)); }

void EnsureCursor(const InputWindow& w) {
    if (g_cursorSet) return;
    g_cursorSet = true;
    g_cursorX = static_cast<float>(w.x + w.w / 2);
    g_cursorY = static_cast<float>(w.y + w.h / 2);
}

// the cursor kept in the window's client area (all the surface shows: nothing lies beyond it on a
// phone) and in the clip rectangle (right and bottom exclusive) when there is one
void ClampCursor(const InputWindow* w) {
    float l = -1e9f, t = -1e9f, r = 1e9f, b = 1e9f;
    if (w) {
        l = static_cast<float>(w->x), t = static_cast<float>(w->y);
        r = static_cast<float>(w->x + std::max(w->w, 1) - 1), b = static_cast<float>(w->y + std::max(w->h, 1) - 1);
    }
    if (g_clip) {
        l = std::max(l, static_cast<float>(g_clipRect[0])), t = std::max(t, static_cast<float>(g_clipRect[1]));
        r = std::min(r, static_cast<float>(g_clipRect[2] - 1)), b = std::min(b, static_cast<float>(g_clipRect[3] - 1));
    }
    if (r < l) r = l;
    if (b < t) b = t;
    g_cursorX = std::clamp(g_cursorX, l, r);
    g_cursorY = std::clamp(g_cursorY, t, b);
}

uint32_t MkFlags() {
    uint32_t mk = 0;
    if (g_buttons & RHIPPER_BUTTON_LEFT) mk |= MK_LBUTTON;
    if (g_buttons & RHIPPER_BUTTON_RIGHT) mk |= MK_RBUTTON;
    if (g_buttons & RHIPPER_BUTTON_MIDDLE) mk |= MK_MBUTTON;
    if (g_buttons & RHIPPER_BUTTON_X1) mk |= MK_XBUTTON1;
    if (g_buttons & RHIPPER_BUTTON_X2) mk |= MK_XBUTTON2;
    if (g_async[VK_SHIFT] & 0x80) mk |= MK_SHIFT;
    if (g_async[VK_CONTROL] & 0x80) mk |= MK_CONTROL;
    return mk;
}

// MAKELPARAM(x, y): two signed 16-bit halves
uint32_t PackPoint(int32_t x, int32_t y) {
    return (static_cast<uint32_t>(x) & 0xFFFF) | ((static_cast<uint32_t>(y) & 0xFFFF) << 16);
}

// a mouse message at the cursor: wParam MK_ flags (| high word), lParam the client point
void MouseMsg(std::vector<Out>& out, const InputWindow& w, uint32_t msg, uint32_t high = 0) {
    out.push_back({msg, MkFlags() | (high << 16), PackPoint(CursorXi() - w.x, CursorYi() - w.y), CursorXi(), CursorYi()});
}

// the cursor moved to a screen point by an absolute pointer: WM_MOUSEMOVE, DirectInput's motion
void MoveTo(std::vector<Out>& out, const InputWindow& w, float x, float y) {
    if (g_havePointer) DiMotion(x - g_lastX, y - g_lastY);
    g_havePointer = true;
    g_lastX = x, g_lastY = y;
    int32_t ox = CursorXi(), oy = CursorYi();
    g_cursorSet = true;
    g_cursorX = x, g_cursorY = y;
    ClampCursor(&w);
    if (CursorXi() != ox || CursorYi() != oy) MouseMsg(out, w, WM_MOUSEMOVE);
}

void SetButton(std::vector<Out>& out, const InputWindow& w, int bit, bool down) {
    if (((g_buttons & bit) != 0) == down) return;
    g_buttons = down ? g_buttons | bit : g_buttons & ~bit;
    int index = bit == RHIPPER_BUTTON_LEFT ? 0 : bit == RHIPPER_BUTTON_RIGHT ? 1 : bit == RHIPPER_BUTTON_MIDDLE ? 2
              : bit == RHIPPER_BUTTON_X1 ? 3 : 4;
    static const uint8_t vks[5] = {VK_LBUTTON, VK_RBUTTON, VK_MBUTTON, VK_XBUTTON1, VK_XBUTTON2};
    static const uint32_t downs[5] = {WM_LBUTTONDOWN, WM_RBUTTONDOWN, WM_MBUTTONDOWN, WM_XBUTTONDOWN, WM_XBUTTONDOWN};
    static const uint32_t ups[5] = {WM_LBUTTONUP, WM_RBUTTONUP, WM_MBUTTONUP, WM_XBUTTONUP, WM_XBUTTONUP};
    uint8_t vk = vks[index];
    Put(g_async[vk], down ? 0x80 : 0);
    if (down) g_asyncPressed[vk] = 1;
    MouseMsg(out, w, down ? downs[index] : ups[index], index == 3 ? 1 : index == 4 ? 2 : 0);
    DiPush(false, DIMOFS_BUTTON0 + index, down ? 0x80 : 0);
}

void SetButtons(std::vector<Out>& out, const InputWindow& w, int buttons) {
    for (int bit : {RHIPPER_BUTTON_LEFT, RHIPPER_BUTTON_RIGHT, RHIPPER_BUTTON_MIDDLE, RHIPPER_BUTTON_X1, RHIPPER_BUTTON_X2})
        SetButton(out, w, bit, (buttons & bit) != 0);
}

void Wheel(std::vector<Out>& out, float v, float h) {
    g_wheelFrac += v * 120.f;
    g_hwheelFrac += h * 120.f;
    int32_t dv = static_cast<int32_t>(g_wheelFrac), dh = static_cast<int32_t>(g_hwheelFrac);
    g_wheelFrac -= static_cast<float>(dv);
    g_hwheelFrac -= static_cast<float>(dh);
    // (the wheel's lParam is the screen point, not the client's)
    if (dv) {
        out.push_back({WM_MOUSEWHEEL, MkFlags() | (static_cast<uint32_t>(dv) << 16), PackPoint(CursorXi(), CursorYi()),
                       CursorXi(), CursorYi()});
        DiMouseAxis(DIMOFS_Z, dv);
    }
    if (dh) {
        out.push_back({WM_MOUSEHWHEEL, MkFlags() | (static_cast<uint32_t>(dh) << 16), PackPoint(CursorXi(), CursorYi()),
                       CursorXi(), CursorYi()});
    }
}

void Post(const std::vector<Out>& out) {
    for (const Out& o : out) PostInput(o.msg, o.wp, o.lp, o.x, o.y);
}

// ---- touch as the mouse (provisional) ----------------------------------------------------------------
Finger* FingerOf(int id) {
    for (Finger& f : g_fingers)
        if (f.id == id) return &f;
    return nullptr;
}

void TouchReset() {
    g_touch = Touch::None;
    for (Finger& f : g_fingers) f = Finger{};
}

void TouchMoveCursor(std::vector<Out>& out, const InputWindow& w, float sx, float sy) {
    float cx, cy;
    SurfaceToClient(w, sx, sy, &cx, &cy);
    MoveTo(out, w, static_cast<float>(w.x) + cx, static_cast<float>(w.y) + cy);
}

void TouchEvent(std::vector<Out>& out, const InputWindow& w, int action, int id, float x, float y) {
    if (action == RHIPPER_POINTER_CANCEL) {
        SetButton(out, w, RHIPPER_BUTTON_LEFT, false);
        TouchReset();
        return;
    }
    Finger* f = FingerOf(id);
    switch (action) {
        case RHIPPER_POINTER_DOWN:
            if (g_touch == Touch::None) {
                TouchReset();
                g_fingers[0] = {id, x, y, x, y};
                g_touch = Touch::Pending;
                g_havePointer = false;   // (no DirectInput jump from wherever the cursor was)
                TouchMoveCursor(out, w, x, y);
            } else if (g_touch == Touch::Pending && !f) {
                g_fingers[1] = {id, x, y, x, y};
                g_touch = Touch::Two;
                g_twoAt = NowMs();
                g_twoMoved = false;
                g_twoY = (g_fingers[0].y + y) / 2;
                g_twoWheel = 0;
            }
            break;   // (a finger more while dragging or in a gesture: not followed)
        case RHIPPER_POINTER_MOVE:
            if (!f) break;
            f->x = x, f->y = y;
            if (g_touch == Touch::Pending) {
                if (std::hypot(x - f->x0, y - f->y0) < kSlop) break;
                // past the slop: the press where the finger landed, then the drag
                g_touch = Touch::Drag;
                SetButton(out, w, RHIPPER_BUTTON_LEFT, true);
                TouchMoveCursor(out, w, x, y);
            } else if (g_touch == Touch::Drag) {
                TouchMoveCursor(out, w, x, y);
            } else if (g_touch == Touch::Two) {
                float avg = (g_fingers[0].y + g_fingers[1].y) / 2;
                float startAvg = (g_fingers[0].y0 + g_fingers[1].y0) / 2;
                if (std::fabs(avg - startAvg) >= kSlop) g_twoMoved = true;
                if (!g_twoMoved) break;
                float dyClient = (avg - g_twoY) * static_cast<float>(w.h) / static_cast<float>(std::max(w.screenH, 1));
                g_twoY = avg;
                g_twoWheel += dyClient * kWheelPerClientPixel;
                // (in thirds of a notch at least: the reference takes ten messages a frame)
                if (std::fabs(g_twoWheel) >= 40.f) {
                    Wheel(out, g_twoWheel / 120.f, 0);
                    g_twoWheel = 0;
                }
            }
            break;
        case RHIPPER_POINTER_UP:
            if (!f) break;
            if (g_touch == Touch::Pending) {
                // a tap: a left click where the finger landed
                SetButton(out, w, RHIPPER_BUTTON_LEFT, true);
                SetButton(out, w, RHIPPER_BUTTON_LEFT, false);
                TouchReset();
            } else if (g_touch == Touch::Drag) {
                TouchMoveCursor(out, w, x, y);
                SetButton(out, w, RHIPPER_BUTTON_LEFT, false);
                TouchReset();
            } else if (g_touch == Touch::Two) {
                if (!g_twoMoved && NowMs() - g_twoAt <= kTwoTapMs) {
                    SetButton(out, w, RHIPPER_BUTTON_RIGHT, true);
                    SetButton(out, w, RHIPPER_BUTTON_RIGHT, false);
                }
                f->id = -1;
                g_touch = Touch::TwoDone;
            } else if (g_touch == Touch::TwoDone) {
                TouchReset();
            }
            break;
    }
}

}  // namespace

// ---- the coordinate mapping --------------------------------------------------------------------------
void SurfaceToClient(const InputWindow& win, float sx, float sy, float* cx, float* cy) {
    float sw = static_cast<float>(std::max(win.screenW, 1)), sh = static_cast<float>(std::max(win.screenH, 1));
    float x = sx * static_cast<float>(win.w) / sw, y = sy * static_cast<float>(win.h) / sh;
    *cx = std::clamp(x, 0.f, static_cast<float>(std::max(win.w - 1, 0)));
    *cy = std::clamp(y, 0.f, static_cast<float>(std::max(win.h - 1, 0)));
}

bool SurfaceToClientPoint(float sx, float sy, int32_t* cx, int32_t* cy) {
    InputWindow w;
    if (!InputWindowOf(&w)) {
        *cx = *cy = 0;
        return false;
    }
    float x, y;
    SurfaceToClient(w, sx, sy, &x, &y);
    *cx = static_cast<int32_t>(x), *cy = static_cast<int32_t>(y);
    return true;
}

// ---- the host's events -----------------------------------------------------------------------------
void InputKey(int android_keycode, int scancode, bool down, int meta, int unicode) {
    const KeyDef* k = KeyOfAndroid(android_keycode);
    if (!k) k = KeyOfLinuxScan(scancode);
    InputWindow w{};
    bool haveWindow = InputWindowOf(&w);
    std::vector<Out> out;
    {
        std::lock_guard<std::mutex> hold(g_lock);
        if (haveWindow) EnsureCursor(w);
        if (!k) {
            // a key with no virtual key of ours (a soft keyboard's '@', another layout's own): its character
            if (down && unicode > 0 && unicode < 0x10000)
                out.push_back({WM_CHAR, static_cast<uint32_t>(unicode), 1, CursorXi(), CursorYi()});
            else LogOnce("input-key", "input: Android key %d (scan %d) has no Win32 key", android_keycode, scancode);
        } else {
            // the lock keys' toggles, as the host's meta state has them
            auto toggle = [](uint8_t vk, bool on) { Put(g_async[vk], (g_async[vk] & 0x80) | (on ? 1 : 0)); };
            toggle(VK_CAPITAL, (meta & META_CAPS_LOCK_ON) != 0);
            toggle(VK_NUMLOCK, (meta & META_NUM_LOCK_ON) != 0);
            toggle(VK_SCROLL, (meta & META_SCROLL_LOCK_ON) != 0);
            uint8_t vk = k->vk;
            if (!(meta & META_NUM_LOCK_ON) && k->dik >= 0x47 && k->dik <= 0x53 && vk >= VK_NUMPAD0) vk = NumpadNav(vk);
            const uint8_t generic = GenericOf(vk);
            const bool was = (g_async[vk] & 0x80) != 0;
            Put(g_async[vk], (g_async[vk] & 1) | (down ? 0x80 : 0));
            if (down && !was) g_asyncPressed[vk] = g_asyncPressed[generic] = 1;
            if (generic != vk) {
                uint8_t l = generic == VK_SHIFT ? VK_LSHIFT : generic == VK_CONTROL ? VK_LCONTROL : VK_LMENU;
                bool any = ((g_async[l] | g_async[l + 1]) & 0x80) != 0;
                Put(g_async[generic], any ? 0x80 : 0);
            }
            if (down) g_downChar[vk] = static_cast<uint32_t>(unicode > 0 ? unicode : 0);
            if (k->dik && was != down) {
                g_diKeys[k->dik] = down ? 0x80 : 0;
                DiPush(true, k->dik, down ? 0x80 : 0);
            }

            const bool alt = (g_async[VK_MENU] & 0x80) != 0, ctrl = (g_async[VK_CONTROL] & 0x80) != 0;
            bool sys;
            if (generic == VK_MENU) {
                if (down && !was) g_altOnly = true;
                sys = down ? !ctrl : g_altOnly && !ctrl;
                if (!down) g_altOnly = false;
            } else {
                if (down) g_altOnly = false;
                sys = (alt && !ctrl) || vk == VK_F10;
            }
            uint32_t scan;
            bool ext;
            Win32Scan(k->dik, &scan, &ext);
            uint32_t lp = 1 | (scan << 16) | (ext ? 1u << 24 : 0) | (alt && sys ? 1u << 29 : 0) |
                          (was ? 1u << 30 : 0) | (down ? 0 : 1u << 31);
            uint32_t msg = down ? (sys ? WM_SYSKEYDOWN : WM_KEYDOWN) : (sys ? WM_SYSKEYUP : WM_KEYUP);
            // (the message names the generic key: VK_SHIFT, not VK_LSHIFT)
            if (haveWindow) out.push_back({msg, generic, lp, CursorXi(), CursorYi()});
        }
    }
    Post(out);
}

void InputPointer(int action, int id, float x, float y, int buttons, float scroll_v, float scroll_h, int source) {
    InputWindow w{};
    if (!InputWindowOf(&w)) return;   // (no window to point at yet)
    std::vector<Out> out;
    {
        std::lock_guard<std::mutex> hold(g_lock);
        EnsureCursor(w);
        if (source == RHIPPER_SOURCE_TOUCH) {
            TouchEvent(out, w, action, id, x, y);
        } else if (action == RHIPPER_POINTER_RELATIVE) {
            // a captured mouse: scaled as the surface is to the client, so it moves as it did uncaptured
            float sx = static_cast<float>(w.w) / static_cast<float>(std::max(w.screenW, 1));
            float sy = static_cast<float>(w.h) / static_cast<float>(std::max(w.screenH, 1));
            float dx = x * sx, dy = y * sy;
            g_havePointer = false;   // (the next absolute point starts afresh)
            DiMotion(dx, dy);
            int32_t ox = CursorXi(), oy = CursorYi();
            g_cursorX += dx, g_cursorY += dy;
            ClampCursor(&w);
            if (CursorXi() != ox || CursorYi() != oy) MouseMsg(out, w, WM_MOUSEMOVE);
            SetButtons(out, w, buttons);
        } else if (action == RHIPPER_POINTER_SCROLL) {
            Wheel(out, scroll_v, scroll_h);
        } else {
            float cx, cy;
            SurfaceToClient(w, x, y, &cx, &cy);
            MoveTo(out, w, static_cast<float>(w.x) + cx, static_cast<float>(w.y) + cy);
            SetButtons(out, w, buttons);
        }
    }
    Post(out);
}

void InputText(const char* utf8) {
    if (!utf8) return;
    std::vector<uint32_t> units;
    for (const unsigned char* p = reinterpret_cast<const unsigned char*>(utf8); *p;) {
        uint32_t c = *p++;
        int more = c >= 0xF0 ? 3 : c >= 0xE0 ? 2 : c >= 0xC0 ? 1 : 0;
        c &= more == 3 ? 0x07 : more == 2 ? 0x0F : more == 1 ? 0x1F : 0x7F;
        for (; more > 0 && (*p & 0xC0) == 0x80; more--) c = (c << 6) | (*p++ & 0x3F);
        if (c == '\n') c = '\r';
        if (c >= 0x10000 || (c >= 0xD800 && c <= 0xDFFF)) {
            // (the reference encodes WM_CHAR's unit by itself, BMP only: a surrogate would be garbage;
            // JNI's modified UTF-8 brings such a character as its two surrogates)
            LogOnce("input-astral", "input: text outside the BMP (U+%X...) dropped", c);
            continue;
        }
        units.push_back(c);
    }
    int32_t x, y;
    CursorScreenPos(&x, &y);
    for (uint32_t u : units) PostInput(WM_CHAR, u, 1, x, y);
}

void InputLifecycle(int event) {
    std::lock_guard<std::mutex> hold(g_lock);
    if (event == RHIPPER_PAUSE) {
        g_paused = true;
        // nothing stays held while away (the reference releases its own on WM_ACTIVATE)
        for (int k = 0; k < 256; k++) {
            Put(g_async[k], g_async[k] & 1);
            Put(g_sync[k], g_sync[k] & 1);
        }
        memset(g_diKeys, 0, sizeof g_diKeys);
        g_buttons = 0;
        g_altOnly = false;
        g_havePointer = false;
        TouchReset();
        for (auto& [id, s] : g_sinks)
            if (s.acquired && s.foreground) {
                s.acquired = false;
                s.lost = s.pauseLost = true;
                s.events.clear();
            }
    } else if (event == RHIPPER_RESUME) {
        g_paused = false;
        // a device lost to the pause says so again, so the reference acquires it anew
        for (auto& [id, s] : g_sinks)
            if (s.pauseLost && !s.acquired) s.lost = true, s.pauseLost = false;
    }
}

// ---- user32's queries ----------------------------------------------------------------------------
void CursorScreenPos(int32_t* x, int32_t* y) {
    InputWindow w{};
    bool have = InputWindowOf(&w);
    std::lock_guard<std::mutex> hold(g_lock);
    if (!g_cursorSet) {
        // (no pointer yet: the window's centre, else the screen's)
        if (have) EnsureCursor(w);
        else {
            *x = 960, *y = 540;
            return;
        }
    }
    *x = CursorXi(), *y = CursorYi();
}

void SetCursorScreenPos(int32_t x, int32_t y) {
    InputWindow w{};
    bool have = InputWindowOf(&w);
    std::vector<Out> out;
    {
        std::lock_guard<std::mutex> hold(g_lock);
        int32_t ox = g_cursorSet ? CursorXi() : INT32_MIN, oy = g_cursorSet ? CursorYi() : INT32_MIN;
        g_cursorSet = true;
        g_cursorX = static_cast<float>(x), g_cursorY = static_cast<float>(y);
        ClampCursor(have ? &w : nullptr);
        // (Windows follows SetCursorPos with a WM_MOUSEMOVE)
        if (have && (CursorXi() != ox || CursorYi() != oy)) MouseMsg(out, w, WM_MOUSEMOVE);
    }
    Post(out);
}

void ClipCursorScreen(const int32_t* rect) {
    InputWindow w{};
    bool have = InputWindowOf(&w);
    std::lock_guard<std::mutex> hold(g_lock);
    g_clip = rect != nullptr;
    if (rect) memcpy(g_clipRect, rect, sizeof g_clipRect);
    if (g_cursorSet) ClampCursor(have ? &w : nullptr);
}

int32_t ShowCursorCount(bool show) { return show ? ++g_showCount : --g_showCount; }

void InputSyncMessage(uint32_t msg, uint32_t wp, uint32_t lp) {
    if (msg >= WM_KEYDOWN && msg <= WM_SYSKEYUP && msg != WM_CHAR && msg != 0x103) {
        bool down = msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN;
        uint8_t vk = static_cast<uint8_t>(wp);
        uint8_t side = vk;
        if (vk == VK_SHIFT) side = ((lp >> 16) & 0xFF) == 0x36 ? VK_RSHIFT : VK_LSHIFT;
        else if (vk == VK_CONTROL) side = (lp & (1u << 24)) ? VK_RCONTROL : VK_LCONTROL;
        else if (vk == VK_MENU) side = (lp & (1u << 24)) ? VK_RMENU : VK_LMENU;
        // (the lock keys' toggles are the host's: its meta state is the truth of them)
        auto set = [&](uint8_t k, bool d) {
            int toggle = (k == VK_CAPITAL || k == VK_NUMLOCK || k == VK_SCROLL) ? (g_async[k] & 1) : (g_sync[k] & 1);
            Put(g_sync[k], toggle | (d ? 0x80 : 0));
        };
        set(side, down);
        if (side != vk) {
            uint8_t l = vk == VK_SHIFT ? VK_LSHIFT : vk == VK_CONTROL ? VK_LCONTROL : VK_LMENU;
            set(vk, ((g_sync[l] | g_sync[l + 1]) & 0x80) != 0);
        } else {
            set(vk, down);
        }
    } else if (msg >= WM_MOUSEMOVE && msg <= WM_MOUSEHWHEEL) {
        uint32_t mk = wp & 0xFFFF;
        Put(g_sync[VK_LBUTTON], (mk & MK_LBUTTON) ? 0x80 : 0);
        Put(g_sync[VK_RBUTTON], (mk & MK_RBUTTON) ? 0x80 : 0);
        Put(g_sync[VK_MBUTTON], (mk & MK_MBUTTON) ? 0x80 : 0);
        Put(g_sync[VK_XBUTTON1], (mk & MK_XBUTTON1) ? 0x80 : 0);
        Put(g_sync[VK_XBUTTON2], (mk & MK_XBUTTON2) ? 0x80 : 0);
    }
}

uint8_t SyncKeyState(uint32_t vk) { return vk < 256 ? g_sync[vk].load() : 0; }

void SyncKeyboardState(uint8_t* out) {
    for (int k = 0; k < 256; k++) out[k] = g_sync[k];
}

uint16_t AsyncKeyState(uint32_t vk) {
    if (vk >= 256) return 0;
    std::lock_guard<std::mutex> hold(g_lock);
    uint16_t r = static_cast<uint16_t>((g_async[vk] & 0x80) ? 0x8000 : 0) | (g_asyncPressed[vk] ? 1 : 0);
    g_asyncPressed[vk] = 0;
    return r;
}

uint32_t InputCharFor(uint32_t vk, uint32_t lp) {
    (void)lp;
    if (vk >= 256) return 0;
    uint8_t state[256];
    SyncKeyboardState(state);
    bool ctrl = state[VK_CONTROL] & 0x80, alt = state[VK_MENU] & 0x80;
    uint32_t c = g_downChar[vk];
    if (ctrl && !alt) return UsCharOf(vk, state);   // (the control characters)
    if (c) return c == '\n' ? '\r' : c;
    if (ctrl && alt) return 0;                      // (AltGr: only what the device's layout typed)
    return UsCharOf(vk, state);
}

// ---- the US layout ---------------------------------------------------------------------------------
uint32_t ScanOfVk(uint32_t vk) {
    switch (vk) {
        case VK_SHIFT: return 0x2A;
        case VK_CONTROL: return 0x1D;
        case VK_MENU: return 0x38;
        case VK_CLEAR: return 0x4C;
        default: break;
    }
    for (const KeyDef& k : kKeys)
        if (k.vk == vk) {
            uint32_t scan;
            bool ext;
            Win32Scan(k.dik, &scan, &ext);
            return scan;
        }
    // (a navigation key the keypad makes with Num Lock off has its own entry above; none else)
    return 0;
}

uint32_t VkOfScan(uint32_t scan, bool extended, bool leftRight) {
    for (const KeyDef& k : kKeys) {
        uint32_t s;
        bool e;
        Win32Scan(k.dik, &s, &e);
        if (s == scan && e == extended) return leftRight ? k.vk : GenericOf(k.vk);
    }
    if (!extended) return 0;
    return VkOfScan(scan, false, leftRight);   // (an E0 code with no key of its own: its base key's)
}

uint32_t UsCharOf(uint32_t vk, const uint8_t* state) {
    bool shift = state && (state[VK_SHIFT] & 0x80), caps = state && (state[VK_CAPITAL] & 1);
    bool ctrl = state && (state[VK_CONTROL] & 0x80), alt = state && (state[VK_MENU] & 0x80);
    if (ctrl && alt) return 0;
    if (ctrl) {
        if (vk >= 'A' && vk <= 'Z') return vk - 'A' + 1;
        switch (vk) {
            case 0xDB: return 0x1B;
            case 0xDC: return 0x1C;
            case 0xDD: return 0x1D;
            case VK_RETURN: return 0x0A;
            case VK_BACK: return 0x7F;
            case VK_SPACE: return ' ';
            default: return 0;
        }
    }
    if (vk >= 'A' && vk <= 'Z') return (shift != caps) ? vk : vk + 32;
    if (vk >= '0' && vk <= '9') return shift ? static_cast<uint32_t>(")!@#$%^&*("[vk - '0']) : vk;
    if (vk >= VK_NUMPAD0 && vk <= VK_NUMPAD0 + 9) return '0' + (vk - VK_NUMPAD0);
    switch (vk) {
        case VK_SPACE: return ' ';
        case VK_BACK: return 0x08;
        case VK_TAB: return 0x09;
        case VK_RETURN: return 0x0D;
        case VK_ESCAPE: return 0x1B;
        case 0x6A: return '*';
        case 0x6B: return '+';
        case 0x6D: return '-';
        case 0x6E: return '.';
        case 0x6F: return '/';
        case 0xBA: return shift ? ':' : ';';
        case 0xBB: return shift ? '+' : '=';
        case 0xBC: return shift ? '<' : ',';
        case 0xBD: return shift ? '_' : '-';
        case 0xBE: return shift ? '>' : '.';
        case 0xBF: return shift ? '?' : '/';
        case 0xC0: return shift ? '~' : '`';
        case 0xDB: return shift ? '{' : '[';
        case 0xDC: case 0xE2: return shift ? '|' : '\\';
        case 0xDD: return shift ? '}' : ']';
        case 0xDE: return shift ? '"' : '\'';
        default: return 0;
    }
}

void KeyNameOf(uint32_t lp, char* out, unsigned cap) {
    if (!cap) return;
    uint32_t scan = (lp >> 16) & 0xFF;
    bool ext = (lp >> 24) & 1;
    struct Name {
        uint8_t scan;
        bool ext;
        const char* name;
    };
    static const Name names[] = {
        {0x01, false, "Esc"}, {0x0E, false, "Backspace"}, {0x0F, false, "Tab"}, {0x1C, false, "Enter"},
        {0x1D, false, "Ctrl"}, {0x2A, false, "Shift"}, {0x36, false, "Right Shift"}, {0x37, false, "Num *"},
        {0x38, false, "Alt"}, {0x39, false, "Space"}, {0x3A, false, "Caps Lock"}, {0x3B, false, "F1"},
        {0x3C, false, "F2"}, {0x3D, false, "F3"}, {0x3E, false, "F4"}, {0x3F, false, "F5"}, {0x40, false, "F6"},
        {0x41, false, "F7"}, {0x42, false, "F8"}, {0x43, false, "F9"}, {0x44, false, "F10"}, {0x45, false, "Pause"},
        {0x46, false, "Scroll Lock"}, {0x47, false, "Num 7"}, {0x48, false, "Num 8"}, {0x49, false, "Num 9"},
        {0x4A, false, "Num -"}, {0x4B, false, "Num 4"}, {0x4C, false, "Num 5"}, {0x4D, false, "Num 6"},
        {0x4E, false, "Num +"}, {0x4F, false, "Num 1"}, {0x50, false, "Num 2"}, {0x51, false, "Num 3"},
        {0x52, false, "Num 0"}, {0x53, false, "Num Del"}, {0x57, false, "F11"}, {0x58, false, "F12"},
        {0x1C, true, "Num Enter"}, {0x1D, true, "Right Ctrl"}, {0x35, true, "Num /"}, {0x37, true, "Prnt Scrn"},
        {0x38, true, "Right Alt"}, {0x45, true, "Num Lock"}, {0x47, true, "Home"}, {0x48, true, "Up"},
        {0x49, true, "Page Up"}, {0x4B, true, "Left"}, {0x4D, true, "Right"}, {0x4F, true, "End"},
        {0x50, true, "Down"}, {0x51, true, "Page Down"}, {0x52, true, "Insert"}, {0x53, true, "Delete"},
        {0x5B, true, "Left Windows"}, {0x5C, true, "Right Windows"}, {0x5D, true, "Application"},
    };
    for (const Name& n : names)
        if (n.scan == scan && n.ext == ext) {
            snprintf(out, cap, "%s", n.name);
            return;
        }
    // a character key: the character it types unshifted, a letter in capitals
    uint32_t c = UsCharOf(VkOfScan(scan, false, false), nullptr);
    if (c >= 'a' && c <= 'z') c -= 32;
    if (c > ' ' && c < 0x7F) snprintf(out, cap, "%c", static_cast<char>(c));
    else out[0] = 0;
}

// ---- DirectInput -----------------------------------------------------------------------------------
int InputDiOpen(bool keyboard) {
    std::lock_guard<std::mutex> hold(g_lock);
    int id = g_nextSink++;
    g_sinks[id].keyboard = keyboard;
    return id;
}

void InputDiClose(int sink) {
    std::lock_guard<std::mutex> hold(g_lock);
    g_sinks.erase(sink);
}

void InputDiSetBufferSize(int sink, uint32_t n) {
    std::lock_guard<std::mutex> hold(g_lock);
    auto it = g_sinks.find(sink);
    if (it == g_sinks.end()) return;
    it->second.bufferSize = std::min<uint32_t>(n, 4096);
    while (it->second.events.size() > it->second.bufferSize) it->second.events.pop_front();
}

uint32_t InputDiBufferSize(int sink) {
    std::lock_guard<std::mutex> hold(g_lock);
    auto it = g_sinks.find(sink);
    return it == g_sinks.end() ? 0 : it->second.bufferSize;
}

void InputDiSetAbsolute(int sink, bool absolute) {
    std::lock_guard<std::mutex> hold(g_lock);
    auto it = g_sinks.find(sink);
    if (it != g_sinks.end()) it->second.absolute = absolute;
}

void InputDiSetForeground(int sink, bool foreground) {
    std::lock_guard<std::mutex> hold(g_lock);
    auto it = g_sinks.find(sink);
    if (it != g_sinks.end()) it->second.foreground = foreground;
}

uint32_t InputDiAcquire(int sink, bool acquire) {
    std::lock_guard<std::mutex> hold(g_lock);
    auto it = g_sinks.find(sink);
    if (it == g_sinks.end()) return DIERR_NOTACQUIRED;
    Sink& s = it->second;
    if (!acquire) {
        if (!s.acquired) return 1;   // DI_NOEFFECT
        s.acquired = false;
        s.events.clear();
        return 0;
    }
    if (s.acquired) return 1;
    if (g_paused && s.foreground) return DIERR_OTHERAPPHASPRIO;
    s.acquired = true;
    s.lost = s.pauseLost = s.overflow = false;
    s.events.clear();
    s.dx = s.dy = s.dz = 0;
    return 0;
}

uint32_t InputDiState(int sink, uint8_t* out, uint32_t size) {
    std::lock_guard<std::mutex> hold(g_lock);
    auto it = g_sinks.find(sink);
    if (it == g_sinks.end()) return DIERR_NOTACQUIRED;
    Sink& s = it->second;
    if (s.lost) {
        s.lost = false;
        return DIERR_INPUTLOST;
    }
    if (!s.acquired) return DIERR_NOTACQUIRED;
    memset(out, 0, size);
    if (s.keyboard) {
        memcpy(out, g_diKeys, std::min<uint32_t>(size, 256));
        return 0;
    }
    // DIMOUSESTATE(2): lX, lY, lZ, then 4 (8) button bytes
    int32_t axes[3] = {s.absolute ? s.ax : s.dx, s.absolute ? s.ay : s.dy, s.absolute ? s.az : s.dz};
    memcpy(out, axes, std::min<uint32_t>(size, 12));
    for (uint32_t b = 0; b < 8 && 12 + b < size; b++) out[12 + b] = (b < 5 && (g_buttons & (1 << b))) ? 0x80 : 0;
    s.dx = s.dy = s.dz = 0;
    return 0;
}

uint32_t InputDiData(int sink, uint32_t cb, uint8_t* out, uint32_t* inOut, bool peek) {
    std::lock_guard<std::mutex> hold(g_lock);
    auto it = g_sinks.find(sink);
    if (it == g_sinks.end()) return DIERR_NOTACQUIRED;
    Sink& s = it->second;
    if (s.lost) {
        s.lost = false;
        return DIERR_INPUTLOST;
    }
    if (!s.acquired) return DIERR_NOTACQUIRED;
    if (s.bufferSize == 0) return DIERR_NOTBUFFERED;
    uint32_t room = inOut ? *inOut : 0;
    uint32_t n = std::min<uint32_t>(room, static_cast<uint32_t>(s.events.size()));
    if (out && cb >= 16) {
        for (uint32_t k = 0; k < n; k++) {
            const DiEvent& e = s.events[k];
            // DIDEVICEOBJECTDATA: dwOfs, dwData, dwTimeStamp, dwSequence, uAppData (DirectInput 8's)
            uint32_t rec[5] = {e.ofs, e.data, e.time, e.seq, 0};
            uint8_t* to = out + static_cast<size_t>(k) * cb;
            memset(to, 0, cb);
            memcpy(to, rec, std::min<uint32_t>(cb, sizeof rec));
        }
    }
    uint32_t result = s.overflow ? DI_BUFFEROVERFLOW : 0;
    if (!peek) {
        s.events.erase(s.events.begin(), s.events.begin() + n);
        s.overflow = false;
    }
    if (inOut) *inOut = n;
    return result;
}

}  // namespace rh
