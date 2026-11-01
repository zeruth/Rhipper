// The host's keyboard, mouse and touch (rhipper_host_key / _pointer / _text) as the reference sees
// them: Win32 key and mouse messages posted to its window, the key state user32 answers from, the
// cursor, and DirectInput 8's device state and buffered data. input.cpp keeps it all under a lock of
// its own and never calls user32 while holding it; user32 calls in here without the wait lock held,
// except InputSyncMessage and InputCharFor (atomics only), which Next/TranslateMessage call with it.
#pragma once

#include <cstdint>

namespace rh {

// ---- the host's events (Host.cpp) ------------------------------------------------------------------
// android_keycode is KeyEvent.getKeyCode(), scancode its getScanCode() (Linux KEY_*, 0: none),
// meta_state getMetaState(), unicode the character the key types with that meta state (0: none)
void InputKey(int android_keycode, int scancode, bool down, int meta_state, int unicode);
// rhipper_host.h's RhipperPointerAction / RhipperButton / RhipperPointerSource
void InputPointer(int action, int pointer_id, float x, float y, int buttons, float scroll_v, float scroll_h, int source);
// committed text (an IME's, a soft keyboard's): WM_CHAR per UTF-16 unit
void InputText(const char* utf8);
// pause: every key and button up silently, DirectInput's foreground devices lost; resume: reacquirable
void InputLifecycle(int event);

// ---- the reference's window, as input needs it (user32.cpp) ------------------------------------------
struct InputWindow {
    uint32_t hwnd;           // the focus window (else the main one)
    int32_t x, y, w, h;      // its client area on the screen (no frame: the window's rectangle)
    int32_t screenW, screenH;   // the screen: the host's surface, in pixels
};
bool InputWindowOf(InputWindow* out);   // false: no window yet
// an input message for that window, posted to its thread with the cursor's screen point. A
// WM_MOUSEMOVE replaces one still waiting at the back of the queue (Windows makes one on demand), a
// button down becomes a double click for a CS_DBLCLKS class. False: no window
bool PostInput(uint32_t msg, uint32_t wp, uint32_t lp, int32_t ptx, int32_t pty);

// ---- the coordinate mapping: the one place a host point becomes a reference point ------------------
// The renderer stretches the reference's client area over the whole surface (no letterbox), so a
// point on the surface (pixels, as Android reports it) is the client point scaled by client/surface:
// (sx * w / screenW, sy * h / screenH), clamped into the client area. Float, unrounded.
void SurfaceToClient(const InputWindow& win, float sx, float sy, float* cx, float* cy);
// the same with the current window, rounded down; false (and 0,0) with no window yet
bool SurfaceToClientPoint(float sx, float sy, int32_t* cx, int32_t* cy);

// ---- user32's queries ----------------------------------------------------------------------------
void CursorScreenPos(int32_t* x, int32_t* y);
void SetCursorScreenPos(int32_t x, int32_t y);   // SetCursorPos: clipped; a WM_MOUSEMOVE follows
void ClipCursorScreen(const int32_t* rect);      // ClipCursor (left, top, right, bottom), nullptr: none
int32_t ShowCursorCount(bool show);              // ShowCursor's display counter
// a key or mouse message the reference retrieved (Next, the wait lock held): GetKeyState's state
// follows the messages taken from the queue, GetAsyncKeyState's the host's events
void InputSyncMessage(uint32_t msg, uint32_t wp, uint32_t lp);
uint8_t SyncKeyState(uint32_t vk);               // 0x80 down, 0x01 toggled
void SyncKeyboardState(uint8_t* out256);
uint16_t AsyncKeyState(uint32_t vk);             // 0x8000 down, 0x0001 pressed since the last call
// TranslateMessage's character for a WM_KEYDOWN/WM_SYSKEYDOWN: the host's (the device's own layout)
// when it gave one, else the US layout's from the retrieved key state; 0: none
uint32_t InputCharFor(uint32_t vk, uint32_t lp);

// ---- the US layout tables (user32's MapVirtualKey, ToAscii, ToUnicode, GetKeyNameText) ----------------
uint32_t ScanOfVk(uint32_t vk);                  // MAPVK_VK_TO_VSC: the scan code without its E0 prefix
uint32_t VkOfScan(uint32_t scan, bool extended, bool leftRight);   // MAPVK_VSC_TO_VK(_EX)
// the character `vk` types on a US keyboard with `state` (a GetKeyboardState table; nullptr: none
// down): control characters with Ctrl, nothing with Ctrl+Alt
uint32_t UsCharOf(uint32_t vk, const uint8_t* state);
// GetKeyNameText's name for lParam's scan code (bits 16-23) and extended bit (24)
void KeyNameOf(uint32_t lp, char* out, unsigned cap);

// ---- DirectInput 8 (dinput8.cpp): a device's view of the same input -----------------------------
constexpr uint32_t DI_BUFFEROVERFLOW = 1, DIERR_INPUTLOST = 0x8007001Eu, DIERR_NOTACQUIRED = 0x8007000Cu,
                   DIERR_OTHERAPPHASPRIO = 0x80070005u, DIERR_NOTBUFFERED = 0x80040207u;
int InputDiOpen(bool keyboard);                  // a device's sink, 0 none
void InputDiClose(int sink);
void InputDiSetBufferSize(int sink, uint32_t n); // DIPROP_BUFFERSIZE
uint32_t InputDiBufferSize(int sink);
void InputDiSetAbsolute(int sink, bool absolute);   // DIPROP_AXISMODE
void InputDiSetForeground(int sink, bool foreground);   // DISCL_FOREGROUND
uint32_t InputDiAcquire(int sink, bool acquire); // DI_OK, DI_NOEFFECT (1, already), or DIERR_OTHERAPPHASPRIO
// the state (256 key bytes; DIMOUSESTATE for 16 bytes, DIMOUSESTATE2 for 20, deltas since the last
// read): DI_OK, DIERR_NOTACQUIRED or DIERR_INPUTLOST
uint32_t InputDiState(int sink, uint8_t* out, uint32_t size);
// buffered DIDEVICEOBJECTDATA (`cb` bytes each, 16 or 20) into `out` (nullptr: drop them), `*inOut`
// on the way in the room, on the way out the count; DIGDD_PEEK leaves them
uint32_t InputDiData(int sink, uint32_t cb, uint8_t* out, uint32_t* inOut, bool peek);

}  // namespace rh
