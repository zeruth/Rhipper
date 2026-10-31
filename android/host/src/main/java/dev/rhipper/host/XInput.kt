package dev.rhipper.host

import android.view.KeyEvent
import kotlin.math.roundToInt

/**
 * Android's gamepad keys and axes as XInput reports them (XINPUT_GAMEPAD), the form the runtime
 * hands the reference.
 *
 * Android normalizes controllers by position through its key layout files: KEYCODE_BUTTON_A is the
 * bottom face button on an Xbox pad (A), a PlayStation pad (Cross) and a Switch Pro pad (B) alike,
 * so XInput's A is always the bottom button, as on the Xbox pad XInput was made for. Generic HID
 * pads without a layout file may report differently; nothing here guesses at those.
 */
internal object XInput {
    const val MAX_PADS = 4

    const val DPAD_UP = 0x0001
    const val DPAD_DOWN = 0x0002
    const val DPAD_LEFT = 0x0004
    const val DPAD_RIGHT = 0x0008
    const val START = 0x0010
    const val BACK = 0x0020
    const val LEFT_THUMB = 0x0040
    const val RIGHT_THUMB = 0x0080
    const val LEFT_SHOULDER = 0x0100
    const val RIGHT_SHOULDER = 0x0200
    const val A = 0x1000
    const val B = 0x2000
    const val X = 0x4000
    const val Y = 0x8000

    /** The XInput button for a key a gamepad sent, or 0. (L2/R2 are triggers: see [Pad].) */
    fun buttonFor(keyCode: Int): Int = when (keyCode) {
        KeyEvent.KEYCODE_BUTTON_A -> A
        KeyEvent.KEYCODE_BUTTON_B -> B
        KeyEvent.KEYCODE_BUTTON_X -> X
        KeyEvent.KEYCODE_BUTTON_Y -> Y
        KeyEvent.KEYCODE_BUTTON_L1 -> LEFT_SHOULDER
        KeyEvent.KEYCODE_BUTTON_R1 -> RIGHT_SHOULDER
        KeyEvent.KEYCODE_BUTTON_THUMBL -> LEFT_THUMB
        KeyEvent.KEYCODE_BUTTON_THUMBR -> RIGHT_THUMB
        KeyEvent.KEYCODE_BUTTON_START -> START
        // the Xbox pad's View / PlayStation's Share-Create; some pads send BACK for it instead
        KeyEvent.KEYCODE_BUTTON_SELECT, KeyEvent.KEYCODE_BACK -> BACK
        // pads whose d-pad is buttons rather than a hat
        KeyEvent.KEYCODE_DPAD_UP -> DPAD_UP
        KeyEvent.KEYCODE_DPAD_DOWN -> DPAD_DOWN
        KeyEvent.KEYCODE_DPAD_LEFT -> DPAD_LEFT
        KeyEvent.KEYCODE_DPAD_RIGHT -> DPAD_RIGHT
        else -> 0
    }

    /** An axis (-1..1, Android's down positive for Y: callers negate) as a thumbstick value. */
    fun stick(v: Float): Int =
        (if (v >= 0f) v * 32767f else v * 32768f).roundToInt().coerceIn(-32768, 32767)

    /** A trigger axis (0..1) as XInput's 0..255. */
    fun trigger(v: Float): Int = (v * 255f).roundToInt().coerceIn(0, 255)
}
