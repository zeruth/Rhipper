package dev.rhipper.host

import android.view.Surface

/**
 * The port's native library, as rhipper_host.h defines it. The JNI side is
 * Rhipper/runtime32-posix/android_jni.c, compiled into the port's own .so (the runtime's functions
 * live there), so these resolve only after [RhipperSession.load] has loaded that library.
 */
object RhipperNative {
    /** RHIPPER_HOST_VERSION: the interface this host is written against. */
    const val HOST_VERSION = 1

    // enum RhipperLifecycle
    const val PAUSE = 1
    const val RESUME = 2
    const val QUIT = 3
    const val LOW_MEMORY = 4

    /** Caches the JavaVM and [onRumble] for native threads, installs the rumble callback, and
     *  returns the library's RHIPPER_HOST_VERSION. */
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
