package dev.rhipper.host

import android.content.Context
import android.hardware.input.InputManager
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.view.InputDevice
import android.view.KeyEvent
import android.view.MotionEvent

/**
 * Android's game controllers as XInput's four slots: each controller (by device id) takes the
 * lowest free slot when it connects and gives it back when it disconnects. Main thread only,
 * except [rumble].
 */
class RhipperGamepads(context: Context) : InputManager.InputDeviceListener {
    private val inputManager = context.getSystemService(InputManager::class.java)
    private val main = Handler(Looper.getMainLooper())
    private val pads = arrayOfNulls<Pad>(XInput.MAX_PADS)
    private var listening = false

    fun start() {
        if (listening) return
        listening = true
        inputManager.registerInputDeviceListener(this, main)
        // controllers that left while we were not listening
        for (pad in pads) if (pad != null && InputDevice.getDevice(pad.deviceId) == null) onInputDeviceRemoved(pad.deviceId)
        for (id in InputDevice.getDeviceIds()) onInputDeviceAdded(id)
    }

    /** Stops listening and silences the motors. The pads stay connected for the reference. */
    fun stop() {
        if (!listening) return
        listening = false
        inputManager.unregisterInputDeviceListener(this)
        for (pad in pads) pad?.stopRumble()
    }

    /** A key event: true when it was a controller's and is now the reference's. */
    fun onKey(event: KeyEvent): Boolean {
        if (!isFromPad(event.source)) return false
        val pad = padFor(event.deviceId) ?: return false
        // (auto-repeat: XInput has no repeats; swallowed when the key is one of the pad's)
        if (event.repeatCount > 0) return XInput.buttonFor(event.keyCode) != 0
        return pad.onKey(event)
    }

    /** A motion event: true when it was a controller's sticks, triggers or hat. */
    fun onMotion(event: MotionEvent): Boolean {
        if (!event.isFromSource(InputDevice.SOURCE_JOYSTICK) || event.action != MotionEvent.ACTION_MOVE) return false
        val pad = padFor(event.deviceId) ?: return false
        pad.onMotion(event)
        return true
    }

    /** XInputSetState, from any thread (the runtime's). */
    fun rumble(index: Int, low: Int, high: Int) {
        main.post { pads.getOrNull(index)?.rumble(low, high) }
    }

    override fun onInputDeviceAdded(deviceId: Int) {
        if (pads.any { it?.deviceId == deviceId }) return
        val device = InputDevice.getDevice(deviceId) ?: return
        if (!isPad(device)) return
        val slot = pads.indexOfFirst { it == null }
        if (slot < 0) {
            Log.w(TAG, "controller ${device.name}: all ${XInput.MAX_PADS} XInput slots taken")
            return
        }
        Log.i(TAG, "controller ${device.name} (id $deviceId) -> XInput pad $slot")
        pads[slot] = Pad(deviceId, slot, device).also { it.send(force = true) }
    }

    override fun onInputDeviceRemoved(deviceId: Int) {
        val slot = pads.indexOfFirst { it?.deviceId == deviceId }
        if (slot < 0) return
        Log.i(TAG, "XInput pad $slot disconnected")
        pads[slot]?.disconnect()
        pads[slot] = null
    }

    override fun onInputDeviceChanged(deviceId: Int) {
        val device = InputDevice.getDevice(deviceId)
        if (device == null || !isPad(device)) onInputDeviceRemoved(deviceId) else onInputDeviceAdded(deviceId)
    }

    private fun padFor(deviceId: Int): Pad? {
        pads.firstOrNull { it?.deviceId == deviceId }?.let { return it }
        onInputDeviceAdded(deviceId) // an event from a controller we have not heard connect
        return pads.firstOrNull { it?.deviceId == deviceId }
    }

    private companion object {
        fun isFromPad(source: Int) =
            (source and InputDevice.SOURCE_GAMEPAD) == InputDevice.SOURCE_GAMEPAD ||
                (source and InputDevice.SOURCE_JOYSTICK) == InputDevice.SOURCE_JOYSTICK

        // (a PlayStation pad's touchpad and motion sensors are devices of their own, of other sources)
        fun isPad(device: InputDevice) = !device.isVirtual &&
            (device.supportsSource(InputDevice.SOURCE_GAMEPAD) || device.supportsSource(InputDevice.SOURCE_JOYSTICK))
    }
}
