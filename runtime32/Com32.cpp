// The reference's COM objects (Com32.h): the proxies, the methods whose structures are laid out
// differently on x64 (a pointer or handle inside), the objects the reference implements itself and
// hands to Windows (XAudio2's callbacks: a native face over its 4-byte vtable), and the imports
// that make the objects (Direct3DCreate9, DirectInput8Create, CoCreateInstance, CoGetClassObject).
#define DIRECTINPUT_VERSION 0x0800
#include "Com32.h"

#include <d3d9.h>
#include <dinput.h>

#include <cstdio>
#include <mutex>
#include <unordered_map>
#include <vector>

#include "RefImage.hpp"

extern "C" uint32_t gen_ref_base;   // RefImage.cpp

namespace com32 {

extern Type32 IUnknown_32, IClassFactory_32, IDirect3D9_32, IDirect3DDevice9_32, IDirect3DSwapChain9_32,
    IDirectInput8A_32, IXAudio2SourceVoice_32, IXAudio2SubmixVoice_32, IXAudio2MasteringVoice_32;

namespace {

std::mutex g_lock;
std::unordered_map<void*, Proxy32*> g_proxies;

bool Derives(const Type32* t, const Type32* from) {
    for (; t; t = t->base)
        if (t == from) return true;
    return false;
}

uint32_t VtableOf(Type32* t) {
    if (t->vtbl == 0) {
        auto v = static_cast<uint32_t*>(HeapAlloc(GetProcessHeap(), 0, t->count * 4));
        for (unsigned k = 0; k < t->count; k++) v[k] = Low(t->thunks[k]);
        t->vtbl = Low(v);
    }
    return t->vtbl;
}

}  // namespace

// One proxy per native object, kept for good: the reference compares the pointers it is handed
// (the render target it set with the one it gets back), and a proxy it still holds after the
// object is gone must not be another's. A native address seen again with a type unrelated to its
// proxy's is a new object there: the proxy is given the new type; a more derived type of the
// same object (GetTexture's base texture, later a texture) the derived one
uint32_t Wrap(void* native, Type32* type) {
    if (!native) return 0;
    std::lock_guard<std::mutex> hold(g_lock);
    Proxy32*& p = g_proxies[native];
    if (!p) {
        p = static_cast<Proxy32*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(Proxy32)));
        p->magic = kProxyMagic;
        p->native = native;
        p->type = type;
    } else if (!Derives(p->type, type)) {
        p->type = type;
    }
    p->vtbl = VtableOf(p->type);
    return Low(p);
}

void* Unwrap(uint32_t proxy) {
    if (!proxy) return nullptr;
    auto p = At<Proxy32>(proxy);
    if (p->magic != kProxyMagic) {
        fprintf(stderr, "%s: COM: %08x is not an object the port gave the reference\n", RHIPPER_NAME, proxy);
        return At<void>(proxy);
    }
    return p->native;
}

Type32* TypeOf(uint32_t riid) {
    if (riid) {
        const GUID& g = *At<GUID>(riid);
        for (Type32* const* t = kTypes; *t; t++)
            if ((*t)->iid && IsEqualGUID(*(*t)->iid, g)) return *t;
    }
    return &IUnknown_32;
}

unsigned int Unsupported(const char* what) {
    fprintf(stderr, "%s: COM: %s is not given to the reference yet\n", RHIPPER_NAME, what);
    return static_cast<unsigned int>(E_NOTIMPL);
}

void* Instance32(uint32_t h) {
    if (h == gen_ref_base) return GetModuleHandleW(nullptr);
    return Handle32(h);
}

namespace {

// a function of the reference's, by its address, with the reference's words
template <typename... A>
uint32_t CallRef(uint32_t fn, A... args) {
    return reinterpret_cast<uint32_t (*)(decltype(static_cast<uint32_t>(args))...)>(static_cast<uintptr_t>(fn))(
        static_cast<uint32_t>(args)...);
}
// a method of an object of the reference's: slot k of its 4-byte vtable, `this` first (__stdcall)
template <typename... A>
uint32_t CallMethod(uint32_t obj, unsigned k, A... args) {
    uint32_t fn = At<uint32_t>(*At<uint32_t>(obj))[k];
    return CallRef(fn, obj, args...);
}

// ---- Direct3D 9 ------------------------------------------------------------------------------------
#pragma pack(push, 4)
struct PresentParams32 {
    uint32_t BackBufferWidth, BackBufferHeight, BackBufferFormat, BackBufferCount;
    uint32_t MultiSampleType, MultiSampleQuality, SwapEffect, hDeviceWindow, Windowed;
    uint32_t EnableAutoDepthStencil, AutoDepthStencilFormat, Flags, FullScreen_RefreshRateInHz;
    uint32_t PresentationInterval;
};
static_assert(sizeof(PresentParams32) == 56, "D3DPRESENT_PARAMETERS, x86");
struct CreationParams32 {
    uint32_t AdapterOrdinal, DeviceType, hFocusWindow, BehaviorFlags;
};
struct LockedRect32 {
    int32_t Pitch;
    uint32_t pBits;
};
struct LockedBox32 {
    int32_t RowPitch, SlicePitch;
    uint32_t pBits;
};
#pragma pack(pop)

D3DPRESENT_PARAMETERS Native(const PresentParams32& p) {
    D3DPRESENT_PARAMETERS n = {};
    n.BackBufferWidth = p.BackBufferWidth;
    n.BackBufferHeight = p.BackBufferHeight;
    n.BackBufferFormat = static_cast<D3DFORMAT>(p.BackBufferFormat);
    n.BackBufferCount = p.BackBufferCount;
    n.MultiSampleType = static_cast<D3DMULTISAMPLE_TYPE>(p.MultiSampleType);
    n.MultiSampleQuality = p.MultiSampleQuality;
    n.SwapEffect = static_cast<D3DSWAPEFFECT>(p.SwapEffect);
    n.hDeviceWindow = static_cast<HWND>(Handle32(p.hDeviceWindow));
    n.Windowed = p.Windowed;
    n.EnableAutoDepthStencil = p.EnableAutoDepthStencil;
    n.AutoDepthStencilFormat = static_cast<D3DFORMAT>(p.AutoDepthStencilFormat);
    n.Flags = p.Flags;
    n.FullScreen_RefreshRateInHz = p.FullScreen_RefreshRateInHz;
    n.PresentationInterval = p.PresentationInterval;
    return n;
}
void Back(const D3DPRESENT_PARAMETERS& n, PresentParams32& p) {
    p.BackBufferWidth = n.BackBufferWidth;
    p.BackBufferHeight = n.BackBufferHeight;
    p.BackBufferFormat = n.BackBufferFormat;
    p.BackBufferCount = n.BackBufferCount;
    p.MultiSampleType = n.MultiSampleType;
    p.MultiSampleQuality = n.MultiSampleQuality;
    p.SwapEffect = n.SwapEffect;
    p.hDeviceWindow = Low(n.hDeviceWindow);
    p.Windowed = n.Windowed;
    p.EnableAutoDepthStencil = n.EnableAutoDepthStencil;
    p.AutoDepthStencilFormat = n.AutoDepthStencilFormat;
    p.Flags = n.Flags;
    p.FullScreen_RefreshRateInHz = n.FullScreen_RefreshRateInHz;
    p.PresentationInterval = n.PresentationInterval;
}

unsigned int Locked(HRESULT hr, const D3DLOCKED_RECT& n, uint32_t out) {
    if (SUCCEEDED(hr)) {
        At<LockedRect32>(out)->Pitch = n.Pitch;
        At<LockedRect32>(out)->pBits = Low(n.pBits);
    }
    return static_cast<unsigned int>(hr);
}
unsigned int Locked(HRESULT hr, const D3DLOCKED_BOX& n, uint32_t out) {
    if (SUCCEEDED(hr)) {
        At<LockedBox32>(out)->RowPitch = n.RowPitch;
        At<LockedBox32>(out)->SlicePitch = n.SlicePitch;
        At<LockedBox32>(out)->pBits = Low(n.pBits);
    }
    return static_cast<unsigned int>(hr);
}

}  // namespace
}  // namespace com32

using namespace com32;

extern "C" {

unsigned int S_IDirect3D9_CreateDevice(uint32_t self, uint32_t adapter, uint32_t type, uint32_t focus,
                                       uint32_t flags, uint32_t pp, uint32_t out) {
    auto d3d = static_cast<IDirect3D9*>(Unwrap(self));
    D3DPRESENT_PARAMETERS n = Native(*At<PresentParams32>(pp));
    IDirect3DDevice9* dev = nullptr;
    HRESULT hr = d3d->CreateDevice(adapter, static_cast<D3DDEVTYPE>(type), static_cast<HWND>(Handle32(focus)), flags,
                                   &n, &dev);
    Back(n, *At<PresentParams32>(pp));
    if (out) *At<uint32_t>(out) = Wrap(dev, &IDirect3DDevice9_32);
    return static_cast<unsigned int>(hr);
}

unsigned int S_IDirect3DDevice9_Reset(uint32_t self, uint32_t pp) {
    auto dev = static_cast<IDirect3DDevice9*>(Unwrap(self));
    D3DPRESENT_PARAMETERS n = Native(*At<PresentParams32>(pp));
    HRESULT hr = dev->Reset(&n);
    Back(n, *At<PresentParams32>(pp));
    return static_cast<unsigned int>(hr);
}

unsigned int S_IDirect3DDevice9_CreateAdditionalSwapChain(uint32_t self, uint32_t pp, uint32_t out) {
    auto dev = static_cast<IDirect3DDevice9*>(Unwrap(self));
    D3DPRESENT_PARAMETERS n = Native(*At<PresentParams32>(pp));
    IDirect3DSwapChain9* sc = nullptr;
    HRESULT hr = dev->CreateAdditionalSwapChain(&n, &sc);
    Back(n, *At<PresentParams32>(pp));
    if (out) *At<uint32_t>(out) = Wrap(sc, &IDirect3DSwapChain9_32);
    return static_cast<unsigned int>(hr);
}

unsigned int S_IDirect3DDevice9_GetCreationParameters(uint32_t self, uint32_t out) {
    auto dev = static_cast<IDirect3DDevice9*>(Unwrap(self));
    D3DDEVICE_CREATION_PARAMETERS n = {};
    HRESULT hr = dev->GetCreationParameters(&n);
    if (SUCCEEDED(hr)) {
        auto p = At<CreationParams32>(out);
        p->AdapterOrdinal = n.AdapterOrdinal;
        p->DeviceType = n.DeviceType;
        p->hFocusWindow = Low(n.hFocusWindow);
        p->BehaviorFlags = n.BehaviorFlags;
    }
    return static_cast<unsigned int>(hr);
}

unsigned int S_IDirect3DSwapChain9_GetPresentParameters(uint32_t self, uint32_t pp) {
    auto sc = static_cast<IDirect3DSwapChain9*>(Unwrap(self));
    D3DPRESENT_PARAMETERS n = {};
    HRESULT hr = sc->GetPresentParameters(&n);
    if (SUCCEEDED(hr)) Back(n, *At<PresentParams32>(pp));
    return static_cast<unsigned int>(hr);
}

unsigned int S_IDirect3DTexture9_LockRect(uint32_t self, uint32_t level, uint32_t out, uint32_t rect, uint32_t flags) {
    D3DLOCKED_RECT n = {};
    HRESULT hr = static_cast<IDirect3DTexture9*>(Unwrap(self))->LockRect(level, &n, At<RECT>(rect), flags);
    return Locked(hr, n, out);
}
unsigned int S_IDirect3DCubeTexture9_LockRect(uint32_t self, uint32_t face, uint32_t level, uint32_t out, uint32_t rect,
                                              uint32_t flags) {
    D3DLOCKED_RECT n = {};
    HRESULT hr = static_cast<IDirect3DCubeTexture9*>(Unwrap(self))
                     ->LockRect(static_cast<D3DCUBEMAP_FACES>(face), level, &n, At<RECT>(rect), flags);
    return Locked(hr, n, out);
}
unsigned int S_IDirect3DSurface9_LockRect(uint32_t self, uint32_t out, uint32_t rect, uint32_t flags) {
    D3DLOCKED_RECT n = {};
    HRESULT hr = static_cast<IDirect3DSurface9*>(Unwrap(self))->LockRect(&n, At<RECT>(rect), flags);
    return Locked(hr, n, out);
}
unsigned int S_IDirect3DVolumeTexture9_LockBox(uint32_t self, uint32_t level, uint32_t out, uint32_t box, uint32_t flags) {
    D3DLOCKED_BOX n = {};
    HRESULT hr = static_cast<IDirect3DVolumeTexture9*>(Unwrap(self))->LockBox(level, &n, At<D3DBOX>(box), flags);
    return Locked(hr, n, out);
}
unsigned int S_IDirect3DVolume9_LockBox(uint32_t self, uint32_t out, uint32_t box, uint32_t flags) {
    D3DLOCKED_BOX n = {};
    HRESULT hr = static_cast<IDirect3DVolume9*>(Unwrap(self))->LockBox(&n, At<D3DBOX>(box), flags);
    return Locked(hr, n, out);
}

}  // extern "C"

// ---- DirectInput 8 ---------------------------------------------------------------------------------
namespace {

#pragma pack(push, 4)
struct DataFormat32 {
    uint32_t dwSize, dwObjSize, dwFlags, dwDataSize, dwNumObjs, rgodf;
};
struct ObjectDataFormat32 {
    uint32_t pguid, dwOfs, dwType, dwFlags;
};
struct DeviceObjectData32 {
    uint32_t dwOfs, dwData, dwTimeStamp, dwSequence, uAppData;
};
#pragma pack(pop)

// an enumeration's callback: the reference's function and its context word
struct Enum32 {
    uint32_t fn, ref;
};
BOOL CALLBACK EnumDevice(LPCDIDEVICEINSTANCEA ddi, LPVOID ctx) {
    auto e = static_cast<Enum32*>(ctx);
    return CallRef(e->fn, Low(ddi), e->ref);
}
BOOL CALLBACK EnumObject(LPCDIDEVICEOBJECTINSTANCEA doi, LPVOID ctx) {
    auto e = static_cast<Enum32*>(ctx);
    return CallRef(e->fn, Low(doi), e->ref);
}

}  // namespace

extern "C" {

unsigned int S_IDirectInput8A_EnumDevices(uint32_t self, uint32_t type, uint32_t cb, uint32_t ref, uint32_t flags) {
    Enum32 e = {cb, ref};
    return static_cast<unsigned int>(
        static_cast<IDirectInput8A*>(Unwrap(self))->EnumDevices(type, cb ? EnumDevice : nullptr, &e, flags));
}

unsigned int S_IDirectInputDevice8A_EnumObjects(uint32_t self, uint32_t cb, uint32_t ref, uint32_t flags) {
    Enum32 e = {cb, ref};
    return static_cast<unsigned int>(
        static_cast<IDirectInputDevice8A*>(Unwrap(self))->EnumObjects(cb ? EnumObject : nullptr, &e, flags));
}

// (DirectInput copies the format)
unsigned int S_IDirectInputDevice8A_SetDataFormat(uint32_t self, uint32_t df) {
    auto d = static_cast<IDirectInputDevice8A*>(Unwrap(self));
    if (!df) return static_cast<unsigned int>(d->SetDataFormat(nullptr));
    auto f = At<DataFormat32>(df);
    std::vector<DIOBJECTDATAFORMAT> objs(f->dwNumObjs);
    for (uint32_t k = 0; k < f->dwNumObjs; k++) {
        auto o = At<ObjectDataFormat32>(f->rgodf + k * f->dwObjSize);
        objs[k].pguid = At<const GUID>(o->pguid);
        objs[k].dwOfs = o->dwOfs;
        objs[k].dwType = o->dwType;
        objs[k].dwFlags = o->dwFlags;
    }
    DIDATAFORMAT n = {sizeof(DIDATAFORMAT), sizeof(DIOBJECTDATAFORMAT), f->dwFlags, f->dwDataSize, f->dwNumObjs,
                      objs.empty() ? nullptr : objs.data()};
    return static_cast<unsigned int>(d->SetDataFormat(&n));
}

// (the reference's records 16 bytes, DirectX 3's, or 20 with its 4-byte uAppData; x64's are 24)
unsigned int S_IDirectInputDevice8A_GetDeviceData(uint32_t self, uint32_t size, uint32_t data, uint32_t inout,
                                                  uint32_t flags) {
    auto d = static_cast<IDirectInputDevice8A*>(Unwrap(self));
    DWORD n = inout ? *At<DWORD>(inout) : 0;
    std::vector<DIDEVICEOBJECTDATA> rec(data ? n : 0);
    HRESULT hr = d->GetDeviceData(sizeof(DIDEVICEOBJECTDATA), data ? rec.data() : nullptr, inout ? &n : nullptr, flags);
    if (SUCCEEDED(hr) && data) {
        for (DWORD k = 0; k < n; k++) {
            auto r = At<DeviceObjectData32>(data + k * size);
            r->dwOfs = rec[k].dwOfs;
            r->dwData = rec[k].dwData;
            r->dwTimeStamp = rec[k].dwTimeStamp;
            r->dwSequence = rec[k].dwSequence;
            if (size >= sizeof(DeviceObjectData32)) r->uAppData = static_cast<uint32_t>(rec[k].uAppData);
        }
    }
    if (inout) *At<DWORD>(inout) = n;
    return static_cast<unsigned int>(hr);
}

}  // extern "C"

// ---- XAudio2 2.7 (its own layouts, packed to 1 byte; methods by vtable index) -----------------------
namespace {

#pragma pack(push, 1)
struct Send32 { uint32_t Flags, pOutputVoice; };
struct Sends32 { uint32_t SendCount, pSends; };
struct Effect32 { uint32_t pEffect, InitialState, OutputChannels; };
struct Chain32 { uint32_t EffectCount, pEffectDescriptors; };
struct Buffer32 { uint32_t Flags, AudioBytes, pAudioData, PlayBegin, PlayLength, LoopBegin, LoopLength, LoopCount, pContext; };
struct BufferWma32 { uint32_t pDecodedPacketCumulativeBytes, PacketCount; };
struct VoiceState32 { uint32_t pCurrentBufferContext, BuffersQueued; uint64_t SamplesPlayed; };

struct Send64 { uint32_t Flags; void* pOutputVoice; };
struct Sends64 { uint32_t SendCount; Send64* pSends; };
struct Effect64 { void* pEffect; uint32_t InitialState, OutputChannels; };
struct Chain64 { uint32_t EffectCount; Effect64* pEffectDescriptors; };
struct Buffer64 { uint32_t Flags, AudioBytes; const void* pAudioData; uint32_t PlayBegin, PlayLength, LoopBegin, LoopLength, LoopCount; void* pContext; };
struct BufferWma64 { const uint32_t* pDecodedPacketCumulativeBytes; uint32_t PacketCount; };
struct VoiceState64 { void* pCurrentBufferContext; uint32_t BuffersQueued; uint64_t SamplesPlayed; };
#pragma pack(pop)

// the IXAudio2 and IXAudio2Voice vtable slots the conversions call
enum : unsigned {
    kRegisterForCallbacks = 6, kUnregisterForCallbacks = 7, kCreateSourceVoice = 8, kCreateSubmixVoice = 9,
    kCreateMasteringVoice = 10, kSetOutputVoices = 1, kSetEffectChain = 2, kSubmitSourceBuffer = 21, kGetState = 25,
};

struct SendsN {
    Sends64 s = {};
    std::vector<Send64> d;
    const Sends64* Of(uint32_t p) {
        if (!p) return nullptr;
        auto a = At<Sends32>(p);
        d.resize(a->SendCount);
        for (uint32_t k = 0; k < a->SendCount; k++) {
            auto e = At<Send32>(a->pSends + k * sizeof(Send32));
            d[k] = {e->Flags, Unwrap(e->pOutputVoice)};
        }
        s = {a->SendCount, d.empty() ? nullptr : d.data()};
        return &s;
    }
};
struct ChainN {
    Chain64 c = {};
    std::vector<Effect64> d;
    const Chain64* Of(uint32_t p) {
        if (!p) return nullptr;
        auto a = At<Chain32>(p);
        d.resize(a->EffectCount);
        for (uint32_t k = 0; k < a->EffectCount; k++) {
            auto e = At<Effect32>(a->pEffectDescriptors + k * sizeof(Effect32));
            d[k] = {Unwrap(e->pEffect), e->InitialState, e->OutputChannels};
        }
        c = {a->EffectCount, d.empty() ? nullptr : d.data()};
        return &c;
    }
};

// The reference's callback objects, with a native face: XAudio2 calls these (on its own thread),
// each the reference's method in the same slot of its 4-byte vtable
struct VoiceCallback {
    virtual void STDMETHODCALLTYPE OnVoiceProcessingPassStart(UINT32 bytes) { CallMethod(obj, 0, bytes); }
    virtual void STDMETHODCALLTYPE OnVoiceProcessingPassEnd() { CallMethod(obj, 1); }
    virtual void STDMETHODCALLTYPE OnStreamEnd() { CallMethod(obj, 2); }
    virtual void STDMETHODCALLTYPE OnBufferStart(void* ctx) { CallMethod(obj, 3, Low(ctx)); }
    virtual void STDMETHODCALLTYPE OnBufferEnd(void* ctx) { CallMethod(obj, 4, Low(ctx)); }
    virtual void STDMETHODCALLTYPE OnLoopEnd(void* ctx) { CallMethod(obj, 5, Low(ctx)); }
    virtual void STDMETHODCALLTYPE OnVoiceError(void* ctx, HRESULT error) { CallMethod(obj, 6, Low(ctx), error); }
    uint32_t obj = 0;
};
struct EngineCallback {
    virtual void STDMETHODCALLTYPE OnProcessingPassStart() { CallMethod(obj, 0); }
    virtual void STDMETHODCALLTYPE OnProcessingPassEnd() { CallMethod(obj, 1); }
    virtual void STDMETHODCALLTYPE OnCriticalError(HRESULT error) { CallMethod(obj, 2, error); }
    uint32_t obj = 0;
};
// one face per reference object, kept for good (XAudio2 may call it until the voice is gone)
template <typename F>
F* FaceOf(uint32_t obj) {
    static std::mutex lock;
    static std::unordered_map<uint32_t, F*> faces;
    if (!obj) return nullptr;
    std::lock_guard<std::mutex> hold(lock);
    F*& f = faces[obj];
    if (!f) {
        f = new F;
        f->obj = obj;
    }
    return f;
}

template <typename R, typename... A>
R Native(void* n, unsigned k, A... args) {
    return reinterpret_cast<R(STDMETHODCALLTYPE*)(void*, A...)>(Slot(n, k))(n, args...);
}

}  // namespace

extern "C" {

unsigned int S_IXAudio2_RegisterForCallbacks(uint32_t self, uint32_t cb) {
    void* n = Unwrap(self);
    return Native<uint32_t>(n, kRegisterForCallbacks, static_cast<void*>(FaceOf<EngineCallback>(cb)));
}
unsigned int S_IXAudio2_UnregisterForCallbacks(uint32_t self, uint32_t cb) {
    void* n = Unwrap(self);
    Native<void>(n, kUnregisterForCallbacks, static_cast<void*>(FaceOf<EngineCallback>(cb)));
    return 0;
}

unsigned int S_IXAudio2_CreateSourceVoice(uint32_t self, uint32_t out, uint32_t format, uint32_t flags, uint64_t ratio,
                                          uint32_t cb, uint32_t sends, uint32_t chain) {
    void* n = Unwrap(self);
    SendsN s;
    ChainN c;
    void* v = nullptr;
    uint32_t hr = Native<uint32_t>(n, kCreateSourceVoice, &v, At<const void>(format), flags, Float32(ratio),
                                   static_cast<void*>(FaceOf<VoiceCallback>(cb)), s.Of(sends), c.Of(chain));
    if (out) *At<uint32_t>(out) = Wrap(v, &IXAudio2SourceVoice_32);
    return hr;
}
unsigned int S_IXAudio2_CreateSubmixVoice(uint32_t self, uint32_t out, uint32_t channels, uint32_t rate, uint32_t flags,
                                          uint32_t stage, uint32_t sends, uint32_t chain) {
    void* n = Unwrap(self);
    SendsN s;
    ChainN c;
    void* v = nullptr;
    uint32_t hr = Native<uint32_t>(n, kCreateSubmixVoice, &v, channels, rate, flags, stage, s.Of(sends), c.Of(chain));
    if (out) *At<uint32_t>(out) = Wrap(v, &IXAudio2SubmixVoice_32);
    return hr;
}
unsigned int S_IXAudio2_CreateMasteringVoice(uint32_t self, uint32_t out, uint32_t channels, uint32_t rate,
                                             uint32_t flags, uint32_t device, uint32_t chain) {
    void* n = Unwrap(self);
    ChainN c;
    void* v = nullptr;
    uint32_t hr = Native<uint32_t>(n, kCreateMasteringVoice, &v, channels, rate, flags, device, c.Of(chain));
    if (out) *At<uint32_t>(out) = Wrap(v, &IXAudio2MasteringVoice_32);
    return hr;
}

unsigned int S_IXAudio2Voice_SetOutputVoices(uint32_t self, uint32_t sends) {
    SendsN s;
    return Native<uint32_t>(Unwrap(self), kSetOutputVoices, s.Of(sends));
}
unsigned int S_IXAudio2Voice_SetEffectChain(uint32_t self, uint32_t chain) {
    ChainN c;
    return Native<uint32_t>(Unwrap(self), kSetEffectChain, c.Of(chain));
}

// (XAudio2 copies the buffer's description, not its audio)
unsigned int S_IXAudio2SourceVoice_SubmitSourceBuffer(uint32_t self, uint32_t buffer, uint32_t wma) {
    auto b = At<Buffer32>(buffer);
    Buffer64 n = {b->Flags, b->AudioBytes, At<const void>(b->pAudioData), b->PlayBegin, b->PlayLength,
                  b->LoopBegin, b->LoopLength, b->LoopCount, At<void>(b->pContext)};
    BufferWma64 w = {};
    if (wma) w = {At<const uint32_t>(At<BufferWma32>(wma)->pDecodedPacketCumulativeBytes), At<BufferWma32>(wma)->PacketCount};
    return Native<uint32_t>(Unwrap(self), kSubmitSourceBuffer, static_cast<const Buffer64*>(&n),
                            wma ? static_cast<const BufferWma64*>(&w) : nullptr);
}
unsigned int S_IXAudio2SourceVoice_GetState(uint32_t self, uint32_t out) {
    VoiceState64 n = {};
    Native<void>(Unwrap(self), kGetState, &n);
    auto s = At<VoiceState32>(out);
    s->pCurrentBufferContext = Low(n.pCurrentBufferContext);
    s->BuffersQueued = n.BuffersQueued;
    s->SamplesPlayed = n.SamplesPlayed;
    return 0;
}

}  // extern "C"

// ---- the imports that make the objects ---------------------------------------------------------------
namespace {

FARPROC Real(const wchar_t* dll, const char* name) {
    HMODULE m = LoadLibraryW(dll);
    return m ? GetProcAddress(m, name) : nullptr;
}

// the classes the reference may make: those with proxies (DirectInput, XAudio2 2.7 and its effects).
// The rest (DirectShow's filters, the text services) are refused, as on a system without them
bool Supported(const GUID& clsid) {
    static const GUID known[] = {
        {0x25e609e4, 0xb259, 0x11cf, {0xbf, 0xc7, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00}},   // DirectInput8
        {0x5a508685, 0xa254, 0x4fba, {0x9b, 0x82, 0x9a, 0x24, 0xb0, 0x03, 0x06, 0xaf}},   // XAudio2 2.7
        {0xdb05ea35, 0x0329, 0x4d4b, {0xa5, 0x3a, 0x6d, 0xea, 0xd0, 0x3d, 0x38, 0x52}},   // XAudio2_Debug 2.7
        {0x6a93130e, 0x1d53, 0x41d1, {0xa9, 0xcf, 0xe7, 0x58, 0x80, 0x0b, 0xb1, 0x79}},   // AudioReverb 2.7
        {0xcac1105f, 0x619b, 0x4d04, {0x83, 0x1a, 0x44, 0xe1, 0xcb, 0xf1, 0x2d, 0x57}},   // AudioVolumeMeter 2.7
    };
    for (const GUID& g : known)
        if (IsEqualGUID(g, clsid)) return true;
    return false;
}

void Refused(const char* what, uint32_t clsid) {
    const GUID& g = *At<GUID>(clsid);
    fprintf(stderr, "%s: COM: %s of {%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x} refused (no proxies)\n",
            RHIPPER_NAME, what, g.Data1, g.Data2, g.Data3, g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3], g.Data4[4],
            g.Data4[5], g.Data4[6], g.Data4[7]);
}

}  // namespace

extern "C" {

unsigned int gen_imp_Direct3DCreate9(uint32_t sdk) {
    auto create = reinterpret_cast<IDirect3D9*(WINAPI*)(UINT)>(Real(L"d3d9.dll", "Direct3DCreate9"));
    return create ? Wrap(create(sdk), &IDirect3D9_32) : 0;
}

unsigned int gen_imp_DirectInput8Create(uint32_t inst, uint32_t version, uint32_t riid, uint32_t out, uint32_t outer) {
    auto create = reinterpret_cast<HRESULT(WINAPI*)(HINSTANCE, DWORD, REFIID, LPVOID*, LPUNKNOWN)>(
        Real(L"dinput8.dll", "DirectInput8Create"));
    if (!create) return static_cast<unsigned int>(E_FAIL);
    void* o = nullptr;
    HRESULT hr = create(static_cast<HINSTANCE>(Instance32(inst)), version, *At<IID>(riid), &o,
                        static_cast<LPUNKNOWN>(Unwrap(outer)));
    if (out) *At<uint32_t>(out) = Wrap(o, TypeOf(riid));
    return static_cast<unsigned int>(hr);
}

unsigned int gen_imp_CoCreateInstance(uint32_t clsid, uint32_t outer, uint32_t context, uint32_t riid, uint32_t out) {
    if (!Supported(*At<GUID>(clsid))) {
        Refused("CoCreateInstance", clsid);
        if (out) *At<uint32_t>(out) = 0;
        return static_cast<unsigned int>(REGDB_E_CLASSNOTREG);
    }
    void* o = nullptr;
    HRESULT hr = CoCreateInstance(*At<CLSID>(clsid), static_cast<LPUNKNOWN>(Unwrap(outer)), context, *At<IID>(riid), &o);
    if (out) *At<uint32_t>(out) = Wrap(o, TypeOf(riid));
    return static_cast<unsigned int>(hr);
}

unsigned int gen_imp_CoGetClassObject(uint32_t clsid, uint32_t context, uint32_t server, uint32_t riid, uint32_t out) {
    if (!Supported(*At<GUID>(clsid))) {
        Refused("CoGetClassObject", clsid);
        if (out) *At<uint32_t>(out) = 0;
        return static_cast<unsigned int>(REGDB_E_CLASSNOTREG);
    }
    void* o = nullptr;
    HRESULT hr = CoGetClassObject(*At<CLSID>(clsid), context, At<COSERVERINFO>(server), *At<IID>(riid), &o);
    if (out) *At<uint32_t>(out) = Wrap(o, TypeOf(riid));
    return static_cast<unsigned int>(hr);
}

}  // extern "C"
