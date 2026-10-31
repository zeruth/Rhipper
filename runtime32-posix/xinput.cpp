// xinput1_3: the host's pads (rhipper_host_set_pad) as XInput reports them, its vibration through
// the host's rumble callback.
#include "Runtime.h"
#include "rhipper_host.h"

namespace rh {
bool PadState(int index, RhipperPad* out, uint32_t* packet);   // Host.cpp
void Rumble(int index, uint16_t low, uint16_t high);
}  // namespace rh

using namespace rh;

namespace {
constexpr uint32_t ERROR_DEVICE_NOT_CONNECTED = 1167;
bool g_enabled = true;

#pragma pack(push, 2)
struct XInputState {
    uint32_t packet;
    uint16_t buttons;
    uint8_t leftTrigger, rightTrigger;
    int16_t lx, ly, rx, ry;
};
#pragma pack(pop)
static_assert(sizeof(XInputState) == 16, "XINPUT_STATE");
}  // namespace

static uint32_t XInputGetState_(uint32_t index, uint32_t out) {
    RhipperPad pad;
    uint32_t packet = 0;
    if (index > 3 || !PadState(static_cast<int>(index), &pad, &packet)) return ERROR_DEVICE_NOT_CONNECTED;
    auto s = At<XInputState>(out);
    if (!g_enabled) {
        // (disabled: neutral, as XInputEnable(FALSE) reports)
        *s = {packet, 0, 0, 0, 0, 0, 0, 0};
        return 0;
    }
    *s = {packet, pad.buttons, pad.left_trigger, pad.right_trigger, pad.thumb_lx, pad.thumb_ly, pad.thumb_rx, pad.thumb_ry};
    return 0;
}
RH_REG(XINPUT1_3, XInputGetState, XInputGetState_)

// XINPUT_VIBRATION: wLeftMotorSpeed (the low-frequency motor), wRightMotorSpeed
static uint32_t XInputSetState_(uint32_t index, uint32_t vib) {
    RhipperPad pad;
    uint32_t packet;
    if (index > 3 || !PadState(static_cast<int>(index), &pad, &packet)) return ERROR_DEVICE_NOT_CONNECTED;
    if (g_enabled) Rumble(static_cast<int>(index), *At<uint16_t>(vib), *At<uint16_t>(vib + 2));
    return 0;
}
RH_REG(XINPUT1_3, XInputSetState, XInputSetState_)

static uint32_t XInputEnable_(uint32_t enable) {
    g_enabled = enable != 0;
    if (!g_enabled)
        for (int k = 0; k < 4; k++) Rumble(k, 0, 0);
    return 0;
}
RH_REG(XINPUT1_3, XInputEnable, XInputEnable_)
