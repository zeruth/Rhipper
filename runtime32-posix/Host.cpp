// rhipper_host.h's runtime side: what the platform host tells the runtime (the run, the log
// directory, the surface, the pads, the keyboard/mouse/touch, the lifecycle) and the runtime's
// accessors for its own users (xinput1_3, the renderer seam in Com32Posix.h).
#include <android/native_window.h>
#include <unistd.h>

#include <cerrno>
#include <condition_variable>
#include <mutex>

#include "Com32Posix.h"
#include "Runtime.h"
#include "input.h"
#include "rhipper_host.h"

namespace rh {

void SetLogDir(const char* dir);                          // Log.cpp
bool RefMapImage(const char* path);                       // RefImage.cpp
int RefRun();
void InitEnvironment();                                    // kernel32_misc.cpp
void SetCommandLine(int argc, const char* const* argv);
void HostScreen(int w, int h);                             // user32.cpp
void HostLifecycle(int event);

namespace {
std::mutex g_hostLock;
std::condition_variable g_windowIdle;
ANativeWindow* g_window = nullptr;   // the runtime's own reference on the host's surface
int g_windowW = 0, g_windowH = 0, g_windowUsers = 0;
RhipperPad g_pads[4] = {};
uint32_t g_padPackets[4] = {};
RhipperRumbleFn g_rumble = nullptr;
bool g_ran = false;

// The subsystems told of the lifecycle after user32 (which turns it into the window's messages),
// in this order: input's first, then whoever adds themselves (OnHostLifecycle). Called on the
// host's thread, the host lock not held.
constexpr int kMaxLifecycle = 8;
void (*g_lifecycle[kMaxLifecycle])(int event) = {InputLifecycle};
int g_lifecycleCount = 1;
}  // namespace

// A subsystem's lifecycle callback (RhipperLifecycle's events): audio pausing its voices, say.
// Declare it where needed, `namespace rh { void OnHostLifecycle(void (*fn)(int)); }`, and call it
// once (at its first use, or a static constructor: the list is constant-initialized)
void OnHostLifecycle(void (*fn)(int event)) {
    std::lock_guard<std::mutex> hold(g_hostLock);
    for (int k = 0; k < g_lifecycleCount; k++)
        if (g_lifecycle[k] == fn) return;
    if (g_lifecycleCount == kMaxLifecycle) {
        Log("OnHostLifecycle: more than %d listeners, one dropped", kMaxLifecycle);
        return;
    }
    g_lifecycle[g_lifecycleCount++] = fn;
}

// the low reservation as early as the library's load: before ART, a JIT or another library takes
// more of the low 2 GB
__attribute__((constructor)) static void ReserveAtLoad() { LowReserve(); }

bool PadState(int index, RhipperPad* out, uint32_t* packet) {
    std::lock_guard<std::mutex> hold(g_hostLock);
    if (index < 0 || index > 3 || !g_pads[index].connected) return false;
    *out = g_pads[index];
    *packet = g_padPackets[index];
    return true;
}

void Rumble(int index, uint16_t low, uint16_t high) {
    RhipperRumbleFn fn;
    {
        std::lock_guard<std::mutex> hold(g_hostLock);
        fn = g_rumble;
    }
    if (fn) fn(index, low, high);
}

}  // namespace rh

using namespace rh;

extern "C" {

int rhipper_host_run(const char* ref_exe, const char* cwd, int argc, const char* const* argv) {
    {
        std::lock_guard<std::mutex> hold(g_hostLock);
        if (g_ran) {
            Log("rhipper_host_run called again: once per process");
            return -2;
        }
        g_ran = true;
    }
    Log("%s: run %s in %s (host interface %d, page %ld)", RHIPPER_NAME, ref_exe ? ref_exe : "-", cwd ? cwd : "-",
        RHIPPER_HOST_VERSION, sysconf(_SC_PAGESIZE));
    if (!ref_exe || !cwd) return -1;
    SetGameRoot(cwd);
    if (chdir(cwd) != 0) Log("chdir(%s) failed (%d)", cwd, errno);
    LowReserve();
    InitEnvironment();
    if (!RefMapImage(ref_exe)) {
        LogFlush();
        return -1;
    }
    SetCommandLine(argc, argv);
    return RefRun();
}

void rhipper_host_set_log_dir(const char* dir) { SetLogDir(dir); }

// The surface: the runtime keeps a reference of its own (ANativeWindow_acquire) while it has one,
// and a change returns only once no user (the renderer, rhipper_window_use) holds the old one
void rhipper_host_set_window(void* native_window, int width, int height) {
    std::unique_lock<std::mutex> lk(g_hostLock);
    auto next = static_cast<ANativeWindow*>(native_window);
    if (next) ANativeWindow_acquire(next);
    g_windowIdle.wait(lk, [] { return g_windowUsers == 0; });
    ANativeWindow* old = g_window;
    g_window = next;
    g_windowW = next ? width : 0;
    g_windowH = next ? height : 0;
    lk.unlock();
    if (old) ANativeWindow_release(old);
    if (next) HostScreen(width, height);
    Log("surface %p %dx%d", native_window, width, height);
}

void rhipper_host_set_pad(int index, const RhipperPad* pad) {
    if (index < 0 || index > 3 || !pad) return;
    std::lock_guard<std::mutex> hold(g_hostLock);
    if (memcmp(&g_pads[index], pad, sizeof *pad) != 0) g_padPackets[index]++;
    g_pads[index] = *pad;
}

void rhipper_host_set_rumble(RhipperRumbleFn fn) {
    std::lock_guard<std::mutex> hold(g_hostLock);
    g_rumble = fn;
}

void rhipper_host_lifecycle(int event) {
    Log("lifecycle %d", event);
    if (event == RHIPPER_LOW_MEMORY) Log("low memory warning from the system");
    HostLifecycle(event);
    void (*fns[kMaxLifecycle])(int);
    int n;
    {
        std::lock_guard<std::mutex> hold(g_hostLock);
        n = g_lifecycleCount;
        memcpy(fns, g_lifecycle, sizeof fns);
    }
    for (int k = 0; k < n; k++) fns[k](event);
}

// ---- keyboard, mouse, touch (input.cpp) ---------------------------------------------------------------
void rhipper_host_key(int android_keycode, int scancode, int down, int meta_state, int unicode_char) {
    InputKey(android_keycode, scancode, down != 0, meta_state, unicode_char);
}

void rhipper_host_pointer(int action, int pointer_id, float x, float y, int buttons, float scroll_v, float scroll_h,
                          int source) {
    InputPointer(action, pointer_id, x, y, buttons, scroll_v, scroll_h, source);
}

void rhipper_host_text(const char* utf8) { InputText(utf8); }

// ---- the renderer's access to the surface (Com32Posix.h) -------------------------------------------
void* rhipper_window_use(int* width, int* height) {
    std::lock_guard<std::mutex> hold(g_hostLock);
    if (!g_window) return nullptr;
    g_windowUsers++;
    if (width) *width = g_windowW;
    if (height) *height = g_windowH;
    return g_window;
}

void rhipper_window_done(void* window) {
    if (!window) return;
    std::lock_guard<std::mutex> hold(g_hostLock);
    if (--g_windowUsers == 0) g_windowIdle.notify_all();
}

}  // extern "C"
