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

#define RHIPPER_HOST_VERSION 1

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
