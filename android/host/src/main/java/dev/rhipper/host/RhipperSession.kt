package dev.rhipper.host

import android.os.Handler
import android.os.Looper
import android.util.Log
import java.io.File

internal const val TAG = "rhipper"

/**
 * The one run of the reference in this process. rhipper_host_run may be called only once per
 * process (the reference's image stays mapped where it was), so the game thread belongs to the
 * process, not to an activity: an activity the system recreates attaches to the run already going.
 * That is also why a port's game activity should live in a process of its own (android:process),
 * so a second Play gets a fresh one. Main thread only, except where noted.
 */
internal object RhipperSession {
    /**
     * The game thread's stack. The runtime runs the reference on its own pthread (with the low
     * stack it needs), so this thread only carries the runtime's setup and the JNI frames: a few
     * MB would do; 16 MB leaves room for a runtime that does more here without costing anything
     * until touched.
     */
    private const val STACK_SIZE = 16L shl 20

    private val main = Handler(Looper.getMainLooper())
    private var loaded: String? = null
    private var thread: Thread? = null

    /** The reference's exit code once it has returned. */
    var exitCode: Int? = null
        private set

    /** Told the exit code on the main thread (the current activity sets it). */
    var onExit: ((Int) -> Unit)? = null

    val started: Boolean get() = thread != null
    val running: Boolean get() = thread != null && exitCode == null

    /** Loads the port's library and checks it speaks this host's interface: null, or what failed. */
    fun load(library: String): String? {
        if (loaded != null) return if (loaded == library) null else "lib$loaded.so is already loaded"
        try {
            System.loadLibrary(library)
        } catch (e: UnsatisfiedLinkError) {
            return "Could not load lib$library.so: ${e.message}"
        }
        val version = try {
            RhipperNative.nativeInit()
        } catch (e: UnsatisfiedLinkError) {
            return "lib$library.so has no Rhipper host interface (android_jni.c not linked in?): ${e.message}"
        }
        if (version != RhipperNative.HOST_VERSION) {
            return "lib$library.so speaks host interface $version, this app ${RhipperNative.HOST_VERSION}"
        }
        loaded = library
        return null
    }

    /** Starts the run on its own thread, once per process. */
    fun start(config: RhipperConfig) {
        if (thread != null) return
        File(config.logDir).mkdirs()
        RhipperNative.nativeSetLogDir(config.logDir)
        val run = Runnable {
            Log.i(TAG, "run ${config.referenceExe} in ${config.workingDir}: ${config.args.joinToString(" ")}")
            val code = try {
                RhipperNative.nativeRun(config.referenceExe, config.workingDir, config.argv)
            } catch (t: Throwable) {
                Log.e(TAG, "the run threw", t)
                Int.MIN_VALUE
            }
            Log.i(TAG, "the reference exited with $code")
            main.post {
                exitCode = code
                onExit?.invoke(code)
            }
        }
        thread = Thread(null, run, "rhipper-game", STACK_SIZE).also { it.start() }
    }
}
