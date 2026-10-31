package dev.rhipper.host

import android.app.Activity
import android.app.AlertDialog
import android.content.ComponentCallbacks2
import android.os.Build
import android.os.Bundle
import android.os.Process
import android.os.SystemClock
import android.view.KeyEvent
import android.view.MotionEvent
import android.view.SurfaceHolder
import android.view.SurfaceView
import android.view.WindowInsets
import android.view.WindowInsetsController
import android.view.WindowManager
import android.widget.Toast
import android.window.OnBackInvokedDispatcher
import java.io.File

/**
 * The reference's window: a fullscreen SurfaceView whose Surface the runtime draws into, the
 * controllers, and the app's lifecycle passed on as rhipper_host_lifecycle events.
 *
 * Declare a subclass (or this class) in the app's manifest with:
 * - android:process=":game": the run is once per process ([RhipperSession]), and a native crash
 *   then takes down only the game, not the app's other screens;
 * - android:configChanges covering orientation|screenSize|smallestScreenSize|screenLayout|density
 *   (and keyboard|keyboardHidden|navigation|uiMode): folding, unfolding and rotating must resize the
 *   surface, never recreate the activity under a running reference.
 *
 * Configure it with [RhipperConfig] Intent extras, or override [createConfig].
 */
open class RhipperActivity : Activity(), SurfaceHolder.Callback {
    protected lateinit var config: RhipperConfig
        private set

    private lateinit var gamepads: RhipperGamepads
    private var ready = false
    private var hasSurface = false
    private var lastBackPress = 0L
    private var quitRequestedAt = 0L

    /** What to run. The default reads [RhipperConfig]'s extras from the Intent. */
    protected open fun createConfig(): RhipperConfig =
        RhipperConfig.fromIntent(intent) ?: error("no ${RhipperConfig.EXTRA_LIBRARY} / ${RhipperConfig.EXTRA_REFERENCE_EXE} extras")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        window.attributes = window.attributes.apply {
            layoutInDisplayCutoutMode = WindowManager.LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_ALWAYS
        }
        window.setDecorFitsSystemWindows(false)

        val surfaceView = SurfaceView(this).apply {
            isFocusable = true
            isFocusableInTouchMode = true
            holder.addCallback(this@RhipperActivity)
        }
        setContentView(surfaceView)
        surfaceView.requestFocus()
        hideSystemBars()

        gamepads = RhipperGamepads(this)
        if (Build.VERSION.SDK_INT >= 33) {
            onBackInvokedDispatcher.registerOnBackInvokedCallback(OnBackInvokedDispatcher.PRIORITY_DEFAULT) { onBackRequested() }
        }

        val error = try {
            config = createConfig()
            RhipperSession.load(config.library)
        } catch (e: Exception) {
            e.message ?: e.toString()
        }
        if (error != null) return showStartFailure(error)

        ready = true
        RhipperNative.rumbleListener = gamepads::rumble
        RhipperSession.onExit = ::onGameExit
        RhipperSession.exitCode?.let { return onGameExit(it) } // it ended while no activity was showing
        RhipperSession.start(config)
    }

    override fun onResume() {
        super.onResume()
        if (!ready) return
        gamepads.start()
        RhipperNative.nativeLifecycle(RhipperNative.RESUME)
    }

    override fun onPause() {
        if (ready) {
            RhipperNative.nativeLifecycle(RhipperNative.PAUSE)
            gamepads.stop()
        }
        super.onPause()
    }

    override fun onDestroy() {
        if (ready) {
            if (RhipperSession.onExit == ::onGameExit) RhipperSession.onExit = null
            RhipperNative.rumbleListener = null
            // finishing while the reference runs (swiped away): let it close itself
            if (isFinishing && RhipperSession.running) RhipperNative.nativeLifecycle(RhipperNative.QUIT)
        }
        super.onDestroy()
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (hasFocus) hideSystemBars()
    }

    override fun onLowMemory() {
        super.onLowMemory()
        if (ready) RhipperNative.nativeLifecycle(RhipperNative.LOW_MEMORY)
    }

    @Suppress("DEPRECATION") // the RUNNING_* levels are still how a foreground app hears of pressure
    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        if (ready && (level == ComponentCallbacks2.TRIM_MEMORY_RUNNING_CRITICAL || level >= ComponentCallbacks2.TRIM_MEMORY_MODERATE)) {
            RhipperNative.nativeLifecycle(RhipperNative.LOW_MEMORY)
        }
    }

    // ---- the surface: its size changes as the device folds, unfolds and rotates

    override fun surfaceCreated(holder: SurfaceHolder) {}

    override fun surfaceChanged(holder: SurfaceHolder, format: Int, width: Int, height: Int) {
        if (!ready) return
        hasSurface = true
        RhipperNative.nativeSetSurface(holder.surface, width, height)
    }

    override fun surfaceDestroyed(holder: SurfaceHolder) {
        // (the runtime must be done with the old window when this returns: the Surface goes away next)
        if (ready && hasSurface) RhipperNative.nativeSetSurface(null, 0, 0)
        hasSurface = false
    }

    // ---- input

    override fun dispatchKeyEvent(event: KeyEvent): Boolean =
        (ready && gamepads.onKey(event)) || super.dispatchKeyEvent(event)

    override fun dispatchGenericMotionEvent(event: MotionEvent): Boolean =
        (ready && gamepads.onMotion(event)) || super.dispatchGenericMotionEvent(event)

    @Deprecated("Below API 33 only; 33+ uses OnBackInvokedCallback")
    override fun onBackPressed() = onBackRequested()

    /**
     * Back never kills the reference: twice in a row asks it to close (WM_CLOSE), so it can save
     * and shut down; if it has not closed a while later, back offers to force it.
     */
    private fun onBackRequested() {
        if (!ready || !RhipperSession.running) return finish()
        val now = SystemClock.elapsedRealtime()
        when {
            quitRequestedAt != 0L && now - quitRequestedAt > FORCE_AFTER_MS -> confirmForceClose()
            quitRequestedAt != 0L -> Unit
            now - lastBackPress < DOUBLE_BACK_MS -> {
                quitRequestedAt = now
                Toast.makeText(this, R.string.rhipper_closing, Toast.LENGTH_SHORT).show()
                RhipperNative.nativeLifecycle(RhipperNative.QUIT)
            }
            else -> Toast.makeText(this, R.string.rhipper_back_again, Toast.LENGTH_SHORT).show()
        }
        lastBackPress = now
    }

    private fun confirmForceClose() {
        AlertDialog.Builder(this)
            .setTitle(R.string.rhipper_force_close_title)
            .setMessage(R.string.rhipper_force_close_message)
            .setPositiveButton(R.string.rhipper_force_close) { _, _ -> endProcess() }
            .setNegativeButton(R.string.rhipper_wait, null)
            .show()
    }

    // ---- the end of the run

    /** The reference returned: says how, with where the logs are, then ends this process. */
    protected open fun onGameExit(code: Int) {
        writeExitRecord(code)
        if (isFinishing || isDestroyed) return endProcess()
        // (a Windows exit code such as 0xC0000005 is negative as an int too, so the hex is shown)
        val message = getString(R.string.rhipper_exit_message, code, code, config.logDir)
        AlertDialog.Builder(this)
            .setTitle(R.string.rhipper_exit_title)
            .setMessage(message)
            .setCancelable(false)
            .setPositiveButton(R.string.rhipper_ok) { _, _ -> endProcess() }
            .show()
    }

    private fun showStartFailure(error: String) {
        android.util.Log.e(TAG, error)
        AlertDialog.Builder(this)
            .setTitle(R.string.rhipper_start_failed_title)
            .setMessage(error)
            .setCancelable(false)
            .setPositiveButton(R.string.rhipper_ok) { _, _ -> finish() }
            .show()
    }

    /** last-exit.txt in the log dir: the launcher's record of how the last run ended. */
    private fun writeExitRecord(code: Int) {
        runCatching {
            File(config.logDir, EXIT_RECORD).writeText("exit $code ${System.currentTimeMillis()}\n")
        }
    }

    /** The reference cannot run twice in one process: this one ends with the activity. */
    private fun endProcess() {
        finish()
        window.decorView.postDelayed({ Process.killProcess(Process.myPid()) }, 300)
    }

    private fun hideSystemBars() {
        window.insetsController?.apply {
            hide(WindowInsets.Type.systemBars())
            systemBarsBehavior = WindowInsetsController.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE
        }
    }

    companion object {
        /** In the log dir after each run: "exit <code> <epoch ms>". */
        const val EXIT_RECORD = "last-exit.txt"
        private const val DOUBLE_BACK_MS = 2500L
        private const val FORCE_AFTER_MS = 8000L
    }
}
