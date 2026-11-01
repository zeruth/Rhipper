/* What a platform host (android/host: an Activity; later iOS, Linux) and runtime32-posix say to
   each other. The host owns the window, the input devices and the app's lifecycle; the runtime owns
   the reference: its image, its memory below 2 GB, its threads, and the Win32 it calls.

   A port's native library (the translation, runtime32-posix, the project's own platform code) exports
   these; the host loads it (System.loadLibrary) and calls them from its own threads. */
#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 2: keyboard, mouse, touch and text (rhipper_host_key, _pointer, _text); everything of 1 unchanged */
#define RHIPPER_HOST_VERSION 2

/* ---- the run ------------------------------------------------------------------------------------ */

/* Runs the reference to its end on the calling thread (the host's dedicated game thread): maps
   `ref_exe` (the reference's own PE, e.g. game/ffxiv.exe) at its image base, sets the working
   directory to `cwd`, and calls its entry with `argv` as its command line (argv[0] the program).
   Returns its exit code, or a negative value when the image could not be mapped (logged first).
   Called once per process: the reference's memory stays where it was mapped. */
int rhipper_host_run(const char *ref_exe, const char *cwd, int argc, const char *const *argv);

/* A directory the runtime may write its logs, traces and crash reports to (before run). */
void rhipper_host_set_log_dir(const char *dir);

/* ---- the window --------------------------------------------------------------------------------- */

/* The surface the reference's window draws into: an ANativeWindow* on Android, NULL while there is
   none (the app paused, the surface destroyed). Width and height in pixels. Any thread. */
void rhipper_host_set_window(void *native_window, int width, int height);

/* ---- input -------------------------------------------------------------------------------------- */

/* One controller's state, as XInput reports it (XINPUT_GAMEPAD): the button bits are XInput's
   (DPAD_UP 0x0001 ... Y 0x8000), triggers 0..255, thumbsticks -32768..32767 with up positive. */
typedef struct RhipperPad {
    uint32_t connected;
    uint16_t buttons;
    uint8_t left_trigger, right_trigger;
    int16_t thumb_lx, thumb_ly, thumb_rx, thumb_ry;
} RhipperPad;

/* The latest state of controller `index` (0..3), whenever it changes. Any thread. */
void rhipper_host_set_pad(int index, const RhipperPad *pad);

/* Vibration the reference asked for (XInputSetState), 0..65535 per motor: the runtime calls the
   host's function, set before run (NULL: none). */
typedef void (*RhipperRumbleFn)(int index, uint16_t low_motor, uint16_t high_motor);
void rhipper_host_set_rumble(RhipperRumbleFn fn);

/* ---- keyboard, mouse, touch (version 2) ------------------------------------------------------------ */

/* A key of a keyboard (not a controller's: those are pads), down or up, auto-repeat as more downs.
   `android_keycode` is the platform's key code (Android's KeyEvent.getKeyCode(); another host maps
   to Android's numbering), `scancode` the hardware's (Linux KEY_*, the PC set-1 code for the main
   block; 0 if none), `meta_state` Android's (META_SHIFT_ON 0x1, META_ALT_ON 0x2, META_CTRL_ON 0x1000,
   META_CAPS_LOCK_ON 0x100000, META_NUM_LOCK_ON 0x200000, META_SCROLL_LOCK_ON 0x400000), and
   `unicode_char` the character the key types under that meta state on the device's own layout,
   Ctrl ignored (0: none, or a dead key). The runtime makes the Win32 virtual key and the DirectInput
   scan code of it: WM_KEYDOWN/WM_KEYUP (WM_SYSKEYDOWN/UP with Alt or F10), WM_CHAR through the
   reference's TranslateMessage, the key state, DirectInput's keyboard. Any thread. */
void rhipper_host_key(int android_keycode, int scancode, int down, int meta_state, int unicode_char);

enum RhipperPointerAction {
    RHIPPER_POINTER_MOVE = 0,      /* a mouse at (x, y), hovering or not; a touch pointer moved */
    RHIPPER_POINTER_DOWN = 1,      /* a touch pointer down; a mouse's button pressed (at x, y) */
    RHIPPER_POINTER_UP = 2,        /* a touch pointer up; a mouse's button released */
    RHIPPER_POINTER_CANCEL = 3,    /* every touch pointer gone, no clicks */
    RHIPPER_POINTER_SCROLL = 4,    /* a mouse wheel: scroll_v notches (+ away from the user),
                                      scroll_h (+ right) */
    RHIPPER_POINTER_RELATIVE = 5   /* a captured mouse moved by (x, y) */
};
enum RhipperButton {   /* Android's MotionEvent.BUTTON_* bits */
    RHIPPER_BUTTON_LEFT = 1,
    RHIPPER_BUTTON_RIGHT = 2,
    RHIPPER_BUTTON_MIDDLE = 4,
    RHIPPER_BUTTON_X1 = 8,         /* back */
    RHIPPER_BUTTON_X2 = 16         /* forward */
};
enum RhipperPointerSource {
    RHIPPER_SOURCE_MOUSE = 1,      /* a mouse, a touchpad's pointer, DeX */
    RHIPPER_SOURCE_TOUCH = 2       /* a touchscreen's fingers (a stylus too) */
};

/* A pointer event. (x, y) in surface pixels (rhipper_host_set_window's), or the motion for RELATIVE.
   A mouse's `buttons` is its whole button state on every event (the runtime tells the changes);
   a touch's `pointer_id` tells its fingers apart (MotionEvent.getPointerId). Touch is the mouse for
   now (provisional): one finger moves and drags with the left button, a tap clicks, a two-finger tap
   right-clicks, a two-finger vertical drag turns the wheel. Any thread. */
void rhipper_host_pointer(int action, int pointer_id, float x, float y, int buttons, float scroll_v, float scroll_h,
                          int source);

/* Committed text (an IME's, a soft keyboard's), UTF-8: WM_CHAR per UTF-16 unit. Any thread. */
void rhipper_host_text(const char *utf8);

/* ---- lifecycle ---------------------------------------------------------------------------------- */

enum RhipperLifecycle {
    RHIPPER_PAUSE = 1,     /* the app left the foreground: the reference's window is inactive */
    RHIPPER_RESUME = 2,
    RHIPPER_QUIT = 3,      /* the user closed it: the reference's window gets WM_CLOSE */
    RHIPPER_LOW_MEMORY = 4
};
void rhipper_host_lifecycle(int event);

#ifdef __cplusplus
}
#endif
