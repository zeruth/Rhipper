package dev.rhipper.host

import android.os.CombinedVibration
import android.os.VibrationEffect
import android.os.VibratorManager
import android.view.InputDevice
import android.view.KeyEvent
import android.view.MotionEvent
import kotlin.math.max

/** One controller in XInput slot [index]: its state as the reference sees it, and its motors. */
internal class Pad(val deviceId: Int, val index: Int, device: InputDevice) {
    private val vibrators: VibratorManager = device.vibratorManager

    // buttons from key events and from the hat axes, kept apart so one never clears the other
    private var keyButtons = 0
    private var hatButtons = 0
    // L2/R2 as keys (pads without analog triggers) and as axes
    private var digitalLeft = false
    private var digitalRight = false
    private var leftTrigger = 0
    private var rightTrigger = 0
    private var lx = 0
    private var ly = 0
    private var rx = 0
    private var ry = 0
    private var sent: IntArray? = null

    /** A key from this pad: true when it is one of XInput's. */
    fun onKey(event: KeyEvent): Boolean {
        val down = event.action == KeyEvent.ACTION_DOWN
        when (event.keyCode) {
            KeyEvent.KEYCODE_BUTTON_L2 -> digitalLeft = down
            KeyEvent.KEYCODE_BUTTON_R2 -> digitalRight = down
            else -> {
                val bit = XInput.buttonFor(event.keyCode)
                if (bit == 0) return false
                keyButtons = if (down) keyButtons or bit else keyButtons and bit.inv()
            }
        }
        send()
        return true
    }

    fun onMotion(event: MotionEvent) {
        lx = XInput.stick(event.getAxisValue(MotionEvent.AXIS_X))
        ly = XInput.stick(-event.getAxisValue(MotionEvent.AXIS_Y)) // XInput: up positive
        // Android's standard right stick is Z/RZ; a few pads report RX/RY instead
        val z = event.getAxisValue(MotionEvent.AXIS_Z)
        val rz = event.getAxisValue(MotionEvent.AXIS_RZ)
        val useRxRy = z == 0f && rz == 0f
        rx = XInput.stick(if (useRxRy) event.getAxisValue(MotionEvent.AXIS_RX) else z)
        ry = XInput.stick(-(if (useRxRy) event.getAxisValue(MotionEvent.AXIS_RY) else rz))
        // triggers: LTRIGGER/RTRIGGER, or BRAKE/GAS on pads that map them there
        leftTrigger = XInput.trigger(max(event.getAxisValue(MotionEvent.AXIS_LTRIGGER), event.getAxisValue(MotionEvent.AXIS_BRAKE)))
        rightTrigger = XInput.trigger(max(event.getAxisValue(MotionEvent.AXIS_RTRIGGER), event.getAxisValue(MotionEvent.AXIS_GAS)))
        val hx = event.getAxisValue(MotionEvent.AXIS_HAT_X)
        val hy = event.getAxisValue(MotionEvent.AXIS_HAT_Y)
        hatButtons = (if (hx < -0.5f) XInput.DPAD_LEFT else 0) or
            (if (hx > 0.5f) XInput.DPAD_RIGHT else 0) or
            (if (hy < -0.5f) XInput.DPAD_UP else 0) or
            (if (hy > 0.5f) XInput.DPAD_DOWN else 0)
        send()
    }

    /** Hands the state to the runtime when it changed (or always, with [force]). */
    fun send(force: Boolean = false) {
        val state = intArrayOf(
            keyButtons or hatButtons,
            max(leftTrigger, if (digitalLeft) 255 else 0),
            max(rightTrigger, if (digitalRight) 255 else 0),
            lx, ly, rx, ry,
        )
        if (!force && state contentEquals sent) return
        sent = state
        RhipperNative.nativeSetPad(index, true, state[0], state[1], state[2], state[3], state[4], state[5], state[6])
    }

    fun disconnect() {
        stopRumble()
        RhipperNative.nativeSetPad(index, false, 0, 0, 0, 0, 0, 0, 0)
    }

    /**
     * XInputSetState's motors, 0..65535 each. XInput's state holds until changed, Android's
     * effects have a length: each one runs [RUMBLE_MS] at most, so a reference that dies mid-rumble
     * does not leave the pad shaking. Two vibrators: the first is taken as the low-frequency (left,
     * heavy) motor, as on Xbox and PlayStation pads; one: the stronger of the two.
     */
    fun rumble(low: Int, high: Int) {
        val ids = vibrators.vibratorIds
        if (ids.isEmpty()) return
        if (low == 0 && high == 0) return stopRumble()
        val effect = if (ids.size >= 2) {
            val parallel = CombinedVibration.startParallel()
            if (low > 0) parallel.addVibrator(ids[0], oneShot(low))
            if (high > 0) parallel.addVibrator(ids[1], oneShot(high))
            parallel.combine()
        } else {
            CombinedVibration.createParallel(oneShot(max(low, high)))
        }
        vibrators.vibrate(effect)
    }

    fun stopRumble() = vibrators.cancel()

    private fun oneShot(level: Int): VibrationEffect =
        VibrationEffect.createOneShot(RUMBLE_MS, (level * 255 / 65535).coerceIn(1, 255))

    private companion object {
        const val RUMBLE_MS = 10_000L
    }
}
