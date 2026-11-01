package dev.rhipper.host

import android.view.Surface

/**
 * The port's native library, as rhipper_host.h defines it. The JNI side is
 * Rhipper/runtime32-posix/android_jni.c, compiled into the port's own .so (the runtime's functions
 * live there), so these resolve only after [RhipperSession.load] has loaded that library.
 */
object RhipperNative {
    /** RHIPPER_HOST_VERSION: the interface this host is written against. 2 adds the keyboard, the
     *  mouse, touch and text; a library that speaks 1 still runs, with those left to the system. */
    const val HOST_VERSION = 2

    // enum RhipperLifecycle
    const val PAUSE = 1
    const val RESUME = 2
    const val QUIT = 3
    const val LOW_MEMORY = 4

    // enum RhipperPointerAction
    const val POINTER_MOVE = 0
    const val POINTER_DOWN = 1
    const val POINTER_UP = 2
    const val POINTER_CANCEL = 3
    const val POINTER_SCROLL = 4
    const val POINTER_RELATIVE = 5

    // enum RhipperPointerSource (the buttons are MotionEvent.BUTTON_*'s bits)
    const val SOURCE_MOUSE = 1
    const val SOURCE_TOUCH = 2

    /** The interface the loaded library speaks (what [nativeInit] returned; 0 before). */
    @Volatile
    var libraryVersion = 0
        internal set

    /** The library takes keys, pointers and text (interface 2 or later). */
    val hasInput: Boolean get() = libraryVersion >= 2

    /** Caches the JavaVM and [onRumble] for native threads, installs the rumble callback, and
     *  returns the library's RHIPPER_HOST_VERSION (1 for a library without the input calls). */
    @JvmStatic external fun nativeInit(): Int

    @JvmStatic external fun nativeSetLogDir(dir: String)

    /** The Surface to draw into (null: none), its size in pixels. */
    @JvmStatic external fun nativeSetSurface(surface: Surface?, width: Int, height: Int)

    @JvmStatic external fun nativeSetPad(
        index: Int, connected: Boolean, buttons: Int,
        leftTrigger: Int, rightTrigger: Int,
        thumbLX: Int, thumbLY: Int, thumbRX: Int, thumbRY: Int,
    )

    @JvmStatic external fun nativeLifecycle(event: Int)

    /** A keyboard's key (rhipper_host_key): its key code, scan code, meta state and the character
     *  it types on the device's layout (Ctrl ignored; 0: none). Version 2. */
    @JvmStatic external fun nativeKey(keyCode: Int, scanCode: Int, down: Boolean, metaState: Int, unicodeChar: Int)

    /** A mouse or touch event (rhipper_host_pointer): (x, y) in surface pixels, or the motion for
     *  [POINTER_RELATIVE]; a mouse's whole button state; wheel notches. Version 2. */
    @JvmStatic external fun nativePointer(
        action: Int, pointerId: Int, x: Float, y: Float, buttons: Int,
        scrollV: Float, scrollH: Float, source: Int,
    )

    /** Committed text (rhipper_host_text): WM_CHAR per UTF-16 unit. Version 2. */
    @JvmStatic external fun nativeText(text: String)

    /** Runs the reference to its end on the calling thread; argv[0] is the program. */
    @JvmStatic external fun nativeRun(refExe: String, cwd: String, argv: Array<String>): Int

    /** Who receives the reference's XInputSetState (index, low motor, high motor; 0..65535). */
    @Volatile
    var rumbleListener: ((Int, Int, Int) -> Unit)? = null

    /** Called by native code, on whichever runtime thread asked for vibration. */
    @JvmStatic
    fun onRumble(index: Int, lowMotor: Int, highMotor: Int) {
        rumbleListener?.invoke(index, lowMotor, highMotor)
    }
}
