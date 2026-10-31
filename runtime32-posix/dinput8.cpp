// dinput8: DirectInput 8's objects, the runtime's (Com32Posix.h). The host has no keyboard or mouse
// for the reference yet (rhipper_host.h passes pads, which XInput serves), so a device is one that
// exists and reports nothing pressed: a game that insists on its keyboard and mouse boots, and its
// pad input comes through XInput. A project may replace the whole with its own factory,
// rhipper_com_set_factory("DirectInput8Create", ...).
#include "Com32Posix.h"

namespace rh {

using namespace com;

namespace {

constexpr uint8_t kClsidDirectInput8[16] = {0xe4, 0x09, 0xe6, 0x25, 0x59, 0xb2, 0xcf, 0x11,
                                            0xbf, 0xc7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00};
constexpr uint8_t kSysKeyboard[16] = {0x61, 0x2b, 0x1d, 0x6f, 0xa0, 0xd5, 0xcf, 0x11,
                                      0xbf, 0xc7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00};
constexpr uint8_t kSysMouse[16] = {0x60, 0x2b, 0x1d, 0x6f, 0xa0, 0xd5, 0xcf, 0x11,
                                   0xbf, 0xc7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00};
constexpr uint32_t DI_OK = 0, DIERR_DEVICENOTREG = 0x80040154u, DI_NOEFFECT = 1;

struct Device : Refcounted {
    bool keyboard;
    uint32_t dataFormatSize = 0;
    uint32_t QueryInterface(uint32_t, uint32_t out) {
        AddRef();
        *At<uint32_t>(out) = self;
        return DI_OK;
    }
    uint32_t AddRef_() { return AddRef(); }
    uint32_t Release_() { return Release(); }
    // DIDEVCAPS: dwSize, dwFlags (DIDC_ATTACHED 1), dwDevType, axes, buttons, POVs, ...
    uint32_t GetCapabilities(uint32_t caps) {
        uint32_t size = U32(caps);
        memset(At(caps + 4), 0, size > 4 ? size - 4 : 0);
        *At<uint32_t>(caps + 4) = 1;
        *At<uint32_t>(caps + 8) = keyboard ? 0x413 : 0x112;   // DI8DEVTYPE_KEYBOARD / MOUSE with subtypes
        *At<uint32_t>(caps + 12) = keyboard ? 0 : 3;
        *At<uint32_t>(caps + 16) = keyboard ? 128 : 3;
        return DI_OK;
    }
    uint32_t EnumObjects(uint32_t, uint32_t, uint32_t) { return DI_OK; }
    uint32_t GetProperty(uint32_t, uint32_t) { return 0x80070032u; }   // DIERR_UNSUPPORTED
    uint32_t SetProperty(uint32_t, uint32_t) { return DI_OK; }
    uint32_t Acquire() { return DI_OK; }
    uint32_t Unacquire() { return DI_OK; }
    // the state: nothing pressed, the mouse still
    uint32_t GetDeviceState(uint32_t size, uint32_t data) {
        if (data) memset(At(data), 0, size);
        return DI_OK;
    }
    // buffered data: none (DIDEVICEOBJECTDATA count in *inOut set to 0)
    uint32_t GetDeviceData(uint32_t, uint32_t, uint32_t inOut, uint32_t) {
        if (inOut) *At<uint32_t>(inOut) = 0;
        return DI_OK;
    }
    uint32_t SetDataFormat(uint32_t format) {
        if (format) dataFormatSize = U32(format + 12);   // DIDATAFORMAT.dwDataSize
        return DI_OK;
    }
    uint32_t SetEventNotification(uint32_t) { return DI_OK; }
    uint32_t SetCooperativeLevel(uint32_t, uint32_t) { return DI_OK; }
    uint32_t NotImpl() { return win::E_NOTIMPL; }
    uint32_t Poll() { return DI_NOEFFECT; }
};

struct DirectInput : Refcounted {
    uint32_t QueryInterface(uint32_t, uint32_t out) {
        AddRef();
        *At<uint32_t>(out) = self;
        return DI_OK;
    }
    uint32_t AddRef_() { return AddRef(); }
    uint32_t Release_() { return Release(); }
    uint32_t CreateDevice(uint32_t guid, uint32_t out, uint32_t outer);
    uint32_t EnumDevices(uint32_t, uint32_t, uint32_t, uint32_t) { return DI_OK; }   // (no callbacks: none attached)
    uint32_t GetDeviceStatus(uint32_t guid) {
        return SameGuid(guid, kSysKeyboard) || SameGuid(guid, kSysMouse) ? DI_OK : 0x80040156u;   // DI_NOTATTACHED
    }
    uint32_t RunControlPanel(uint32_t, uint32_t) { return DI_OK; }
    uint32_t Initialize(uint32_t, uint32_t) { return DI_OK; }
    uint32_t FindDevice(uint32_t, uint32_t, uint32_t) { return DIERR_DEVICENOTREG; }
    uint32_t EnumDevicesBySemantics(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t) { return DI_OK; }
    uint32_t ConfigureDevices(uint32_t, uint32_t, uint32_t, uint32_t) { return win::E_NOTIMPL; }
};

uint32_t DeviceVtable() {
    static uint32_t v = [] {
        const void* m[32];
        for (auto& p : m) p = M_<&Device::NotImpl>();
        m[0] = M_<&Device::QueryInterface>();
        m[1] = M_<&Device::AddRef_>();
        m[2] = M_<&Device::Release_>();
        m[3] = M_<&Device::GetCapabilities>();
        m[4] = M_<&Device::EnumObjects>();
        m[5] = M_<&Device::GetProperty>();
        m[6] = M_<&Device::SetProperty>();
        m[7] = M_<&Device::Acquire>();
        m[8] = M_<&Device::Unacquire>();
        m[9] = M_<&Device::GetDeviceState>();
        m[10] = M_<&Device::GetDeviceData>();
        m[11] = M_<&Device::SetDataFormat>();
        m[12] = M_<&Device::SetEventNotification>();
        m[13] = M_<&Device::SetCooperativeLevel>();
        m[25] = M_<&Device::Poll>();
        return Vtable(m, 32);
    }();
    return v;
}

uint32_t DirectInput::CreateDevice(uint32_t guid, uint32_t out, uint32_t) {
    bool kb = SameGuid(guid, kSysKeyboard), mouse = SameGuid(guid, kSysMouse);
    if (!kb && !mouse) {
        Log("DirectInput: CreateDevice %s: no such device", HexGuid(guid).c_str());
        if (out) *At<uint32_t>(out) = 0;
        return DIERR_DEVICENOTREG;
    }
    auto d = new Device();
    d->keyboard = kb;
    d->self = NewObject(DeviceVtable(), d);
    *At<uint32_t>(out) = d->self;
    Log("DirectInput: the %s (reports nothing: the host gives no %s)", kb ? "keyboard" : "mouse", kb ? "keys" : "pointer");
    return DI_OK;
}

uint32_t InputVtable() {
    static uint32_t v = [] {
        const void* m[] = {M_<&DirectInput::QueryInterface>(), M_<&DirectInput::AddRef_>(), M_<&DirectInput::Release_>(),
                           M_<&DirectInput::CreateDevice>(), M_<&DirectInput::EnumDevices>(),
                           M_<&DirectInput::GetDeviceStatus>(), M_<&DirectInput::RunControlPanel>(),
                           M_<&DirectInput::Initialize>(), M_<&DirectInput::FindDevice>(),
                           M_<&DirectInput::EnumDevicesBySemantics>(), M_<&DirectInput::ConfigureDevices>()};
        return Vtable(m, sizeof m / sizeof m[0]);
    }();
    return v;
}

}  // namespace

bool IsDirectInput8Class(uint32_t clsid) { return SameGuid(clsid, kClsidDirectInput8); }

uint32_t DinputCreate(uint32_t version, uint32_t riid, uint32_t out) {
    auto di = new DirectInput();
    di->self = NewObject(InputVtable(), di);
    if (out) *At<uint32_t>(out) = di->self;
    Log("DirectInput8Create(version %#x, %s): the runtime's (no keyboard or mouse yet)", version, HexGuid(riid).c_str());
    return DI_OK;
}

}  // namespace rh
