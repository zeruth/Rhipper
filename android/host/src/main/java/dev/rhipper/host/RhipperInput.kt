package dev.rhipper.host

import android.content.Context
import android.hardware.input.InputManager
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.view.InputDevice
import android.view.KeyCharacterMap
import android.view.KeyEvent
import android.view.MotionEvent
import android.view.View
import android.widget.Toast

/**
 * The keyboard, the mouse and the touchscreen as the reference's (rhipper_host_key / _pointer /
 * _text): a controller's events are never taken here ([RhipperGamepads] has them first, and what
 * it leaves goes on to the system), nor the system's own keys (volume, home, a non-keyboard back).
 *
 * The mouse: uncaptured, its hover, buttons and wheel at the pointer Android draws; captured
 * (pointer capture, while a mouse is attached and the window has focus, unless turned off), its
 * motion relative, so a camera turned with the mouse never meets the screen's edge. Ctrl+Alt+M
 * toggles the capture (the key itself is not passed on). Touch is the runtime's provisional
 * touch-as-mouse (rhipper_host.h). Main thread only.
 */
class RhipperInput(
    private val context: Context,
    private val view: View,
    /** Capture the mouse when one is attached, until Ctrl+Alt+M says otherwise. */
    captureByDefault: Boolean = true,
) : InputManager.InputDeviceListener {
    private val inputManager = context.getSystemService(InputManager::class.java)
    private val main = Handler(Looper.getMainLooper())
    private var listening = false
    private var focused = false
    private var mousePresent = false
    private var captureWanted = captureByDefault

    init {
        view.setOnCapturedPointerListener { _, event -> onCapturedPointer(event) }
    }

    fun start() {
        if (listening) return
        listening = true
        inputManager.registerInputDeviceListener(this, main)
        mousePresent = anyMouse()
        updateCapture()
    }

    fun stop() {
        if (!listening) return
        listening = false
        inputManager.unregisterInputDeviceListener(this)
        if (view.hasPointerCapture()) view.releasePointerCapture()
    }

    fun onFocus(hasFocus: Boolean) {
        focused = hasFocus
        updateCapture()
    }

    // ---- keys

    /** A key event: true when it was the keyboard's and is now the reference's. */
    @Suppress("DEPRECATION") // ACTION_MULTIPLE: still how a soft keyboard's keyless text can arrive
    fun onKey(event: KeyEvent): Boolean {
        if (!RhipperNative.hasInput || isFromPad(event.source)) return false
        val code = event.keyCode
        if (code == KeyEvent.KEYCODE_BACK) {
            // a mouse's back button: already the reference's as XBUTTON1, not the system's back
            if (event.isFromSource(InputDevice.SOURCE_MOUSE)) return true
            // a keyboard that reports its Esc as back (scan code KEY_ESC): Esc; any other back is the system's
            return if (isPhysicalEsc(event)) forwardKey(event, KeyEvent.KEYCODE_ESCAPE) else false
        }
        if (event.isSystem) return false
        if (code == KeyEvent.KEYCODE_M && event.isCtrlPressed && event.isAltPressed) {
            if (event.action == KeyEvent.ACTION_DOWN && event.repeatCount == 0) toggleCapture()
            return true
        }
        if (event.action == KeyEvent.ACTION_MULTIPLE) {
            // (a soft keyboard's text that has no key, delivered as one event)
            val text = event.characters
            if (!text.isNullOrEmpty()) sendText(text)
            return true
        }
        return forwardKey(event, code)
    }

    private fun forwardKey(event: KeyEvent, code: Int): Boolean {
        val down = when (event.action) {
            KeyEvent.ACTION_DOWN -> true
            KeyEvent.ACTION_UP -> false
            else -> return false
        }
        RhipperNative.nativeKey(code, event.scanCode, down, event.metaState, typedChar(event))
        return true
    }

    /** Committed text for the reference (an IME's, a soft keyboard's): its WM_CHARs. The hook a
     *  soft keyboard will use, once the view has an InputConnection (onCreateInputConnection). */
    fun sendText(text: CharSequence) {
        if (RhipperNative.hasInput && text.isNotEmpty()) RhipperNative.nativeText(text.toString())
    }

    // ---- the mouse and the touchscreen

    /** Hover, wheel and button events (dispatchGenericMotionEvent): true when a mouse's. */
    fun onGenericMotion(event: MotionEvent): Boolean {
        if (!RhipperNative.hasInput || !event.isFromSource(InputDevice.SOURCE_MOUSE)) return false
        when (event.actionMasked) {
            MotionEvent.ACTION_SCROLL -> RhipperNative.nativePointer(
                RhipperNative.POINTER_SCROLL, 0, event.x, event.y, event.buttonState,
                event.getAxisValue(MotionEvent.AXIS_VSCROLL), event.getAxisValue(MotionEvent.AXIS_HSCROLL),
                RhipperNative.SOURCE_MOUSE,
            )
            else -> mouseAt(event)
        }
        return true
    }

    /** Touch and a mouse's presses (dispatchTouchEvent): true when the reference's. */
    fun onTouch(event: MotionEvent): Boolean {
        if (!RhipperNative.hasInput) return false
        if (event.isFromSource(InputDevice.SOURCE_MOUSE)) {
            mouseAt(event)
            return true
        }
        if (!event.isFromSource(InputDevice.SOURCE_TOUCHSCREEN)) return false
        val touch = RhipperNative.SOURCE_TOUCH
        when (event.actionMasked) {
            MotionEvent.ACTION_DOWN, MotionEvent.ACTION_POINTER_DOWN -> {
                val i = event.actionIndex
                RhipperNative.nativePointer(RhipperNative.POINTER_DOWN, event.getPointerId(i), event.getX(i), event.getY(i), 0, 0f, 0f, touch)
            }
            MotionEvent.ACTION_MOVE -> for (i in 0 until event.pointerCount) {
                RhipperNative.nativePointer(RhipperNative.POINTER_MOVE, event.getPointerId(i), event.getX(i), event.getY(i), 0, 0f, 0f, touch)
            }
            MotionEvent.ACTION_UP, MotionEvent.ACTION_POINTER_UP -> {
                val i = event.actionIndex
                RhipperNative.nativePointer(RhipperNative.POINTER_UP, event.getPointerId(i), event.getX(i), event.getY(i), 0, 0f, 0f, touch)
            }
            MotionEvent.ACTION_CANCEL -> RhipperNative.nativePointer(RhipperNative.POINTER_CANCEL, 0, 0f, 0f, 0, 0f, 0f, touch)
        }
        return true
    }

    /** The mouse where the event has it, with its whole button state (the runtime tells the changes). */
    private fun mouseAt(event: MotionEvent) {
        val buttons = if (event.actionMasked == MotionEvent.ACTION_CANCEL) 0 else event.buttonState
        RhipperNative.nativePointer(RhipperNative.POINTER_MOVE, 0, event.x, event.y, buttons, 0f, 0f, RhipperNative.SOURCE_MOUSE)
    }

    private fun onCapturedPointer(event: MotionEvent): Boolean {
        if (!RhipperNative.hasInput) return false
        val mouse = RhipperNative.SOURCE_MOUSE
        if (event.actionMasked == MotionEvent.ACTION_SCROLL) {
            RhipperNative.nativePointer(
                RhipperNative.POINTER_SCROLL, 0, 0f, 0f, event.buttonState,
                event.getAxisValue(MotionEvent.AXIS_VSCROLL), event.getAxisValue(MotionEvent.AXIS_HSCROLL), mouse,
            )
            return true
        }
        // (a captured touchpad reports its fingers' absolute positions: not mapped yet)
        if (!event.isFromSource(InputDevice.SOURCE_MOUSE_RELATIVE)) return false
        // each sample of a batched move is a motion of its own
        var dx = event.x
        var dy = event.y
        for (h in 0 until event.historySize) {
            dx += event.getHistoricalX(h)
            dy += event.getHistoricalY(h)
        }
        RhipperNative.nativePointer(RhipperNative.POINTER_RELATIVE, 0, dx, dy, event.buttonState, 0f, 0f, mouse)
        return true
    }

    // ---- pointer capture

    private fun toggleCapture() {
        captureWanted = !captureWanted
        Log.i(TAG, "mouse capture ${if (captureWanted) "on" else "off"} (Ctrl+Alt+M)")
        val message = if (captureWanted) "Mouse captured: Ctrl+Alt+M releases it" else "Mouse released: Ctrl+Alt+M captures it"
        Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
        updateCapture()
    }

    private fun updateCapture() {
        val want = RhipperNative.hasInput && listening && focused && mousePresent && captureWanted
        if (want && !view.hasPointerCapture()) view.requestPointerCapture()
        else if (!want && view.hasPointerCapture()) view.releasePointerCapture()
    }

    override fun onInputDeviceAdded(deviceId: Int) = devicesChanged()
    override fun onInputDeviceRemoved(deviceId: Int) = devicesChanged()
    override fun onInputDeviceChanged(deviceId: Int) = devicesChanged()

    private fun devicesChanged() {
        val present = anyMouse()
        if (present == mousePresent) return
        mousePresent = present
        Log.i(TAG, if (present) "a mouse is attached" else "no mouse attached")
        updateCapture()
    }

    private companion object {
        fun isFromPad(source: Int) =
            (source and InputDevice.SOURCE_GAMEPAD) == InputDevice.SOURCE_GAMEPAD ||
                (source and InputDevice.SOURCE_JOYSTICK) == InputDevice.SOURCE_JOYSTICK

        fun anyMouse() = InputDevice.getDeviceIds().any { id ->
            InputDevice.getDevice(id)?.let { !it.isVirtual && it.supportsSource(InputDevice.SOURCE_MOUSE) } == true
        }

        /** KEY_ESC (Linux scan code 1) from a real keyboard, whatever key code its layout gave it. */
        fun isPhysicalEsc(event: KeyEvent): Boolean {
            val device = event.device ?: return false
            return !device.isVirtual && event.isFromSource(InputDevice.SOURCE_KEYBOARD) && event.scanCode == 1
        }

        /**
         * The character the key types on the device's layout, as Windows' WM_CHAR would carry it
         * before Ctrl: Ctrl and Meta ignored (the runtime makes Ctrl's control characters), left Alt
         * too (Windows types the plain character with it, as WM_SYSCHAR), right Alt kept (AltGr).
         * 0 for none, and for a dead key (no composition yet).
         */
        fun typedChar(event: KeyEvent): Int {
            var meta = event.metaState and (KeyEvent.META_CTRL_MASK or KeyEvent.META_META_MASK).inv()
            if ((meta and KeyEvent.META_ALT_LEFT_ON) != 0) {
                meta = meta and KeyEvent.META_ALT_LEFT_ON.inv()
                if ((meta and KeyEvent.META_ALT_RIGHT_ON) == 0) meta = meta and KeyEvent.META_ALT_ON.inv()
            }
            val c = event.getUnicodeChar(meta)
            return if ((c and KeyCharacterMap.COMBINING_ACCENT) != 0) 0 else c
        }
    }
}
