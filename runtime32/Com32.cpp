// The reference's COM objects (Com32.h): the proxies, the methods whose structures are laid out
// differently on x64 (a pointer or handle inside), the objects the reference implements itself and
// hands to Windows (XAudio2's callbacks: a native face over its 4-byte vtable), and the imports
// that make the objects (Direct3DCreate9, DirectInput8Create, CoCreateInstance, CoGetClassObject).
#define DIRECTINPUT_VERSION 0x0800
#include "Com32.h"

#include <d3d9.h>
#include <dinput.h>
#include <mmreg.h>
#include <oleauto.h>

#include <algorithm>
#include <cstdio>
#include <mutex>
#include <unordered_map>
#include <vector>

#include "RefImage.hpp"

extern "C" uint32_t gen_ref_base;   // RefImage.cpp
extern "C" const unsigned int g_genThiscall[];   // jumps.c, sorted
extern "C" const unsigned int g_genThiscallCount;
extern "C" __declspec(thread) unsigned short gen_x87_cw;   // Adapters.cpp
extern "C" void gen_set_x87_cw(unsigned short cw);

namespace com32 {

extern Type32 IUnknown_32, IClassFactory_32, IDirect3D9_32, IDirect3DDevice9_32, IDirect3DSwapChain9_32,
    IDirectInput8A_32, IXAudio2SourceVoice_32, IXAudio2SubmixVoice_32, IXAudio2MasteringVoice_32;

namespace {

std::mutex g_lock;
std::unordered_map<void*, Proxy32*> g_proxies;

// the methods called so far (ComCount), and <ENV>_COMSTATS's printer
ComStat* volatile g_stats = nullptr;
std::once_flag g_statsOnce;

void PrintStats(unsigned secs) {
    for (unsigned round = 1;; round++) {
        Sleep(secs * 1000);
        fprintf(stderr, "%s: COMSTATS at %us (calls since the last, then in all):\n", RHIPPER_NAME, round * secs);
        for (ComStat* s = g_stats; s; s = s->next) {
            long now = s->calls;
            if (now != s->printed) fprintf(stderr, "  %8ld %10ld  %s\n", now - s->printed, now, s->name);
            s->printed = now;
        }
        fflush(stderr);
    }
}

}  // namespace

void ComCountFirst(ComStat* s) {
    std::call_once(g_statsOnce, [] {
        wchar_t v[16] = {};
        if (RefEnv("COMSTATS", v, 16) == 0) return;
        static unsigned secs = static_cast<unsigned>(wcstoul(v, nullptr, 10));
        if (secs == 0) secs = 10;
        CreateThread(nullptr, 0, [](LPVOID) -> DWORD { PrintStats(secs); return 0; }, nullptr, 0, nullptr);
    });
    ComStat* head;
    do {
        head = g_stats;
        s->next = head;
    } while (InterlockedCompareExchangePointer(reinterpret_cast<PVOID volatile*>(&g_stats), s, head) != head);
}

namespace {

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
        // (its vtable word too: one in the reference's image is an object the reference made itself)
        fprintf(stderr, "%s: COM: %08x is not an object the port gave the reference (vtable %08x)\n", RHIPPER_NAME,
                proxy, *At<uint32_t>(proxy));
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
// whether the reference's function at fn is a __thiscall one in the gen (translate32's
// g_genThiscall, sorted): on x64 its first parameter is ecx's, its stack words after it
bool GenThiscall(uint32_t fn) {
    return std::binary_search(g_genThiscall, g_genThiscall + g_genThiscallCount, fn);
}

// a method of an object of the reference's: slot k of its 4-byte vtable, `this` first (__stdcall,
// as COM calls it). One the gen has as __thiscall, a method that leaves ecx alone and reads its
// object from the stack, `mov esi, [ebp + 8]`, takes ecx first: the object there too, and on the
// stack as COM puts it (a voice callback's slots, one word off, read their object through 0)
template <typename... A>
uint32_t CallMethod(uint32_t obj, unsigned k, A... args) {
    uint32_t fn = At<uint32_t>(*At<uint32_t>(obj))[k];
    if (GenThiscall(fn)) return CallRef(fn, obj, obj, args...);
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
    // (Direct3D 9 sets the creating thread's x87 unit to 24-bit precision, every exception masked
    // and rounding to nearest, unless the caller asks it to keep its own: an x86 client computes in
    // single precision from here on, and its CRT's math reads the control word to choose its paths)
    if (SUCCEEDED(hr) && !(flags & D3DCREATE_FPU_PRESERVE)) gen_set_x87_cw(static_cast<unsigned short>(0x007f));
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

// <ENV>_FRAMEDUMP=<every>[,<count>]: every that many presents (4 times by default), the back buffer
// as it is before the present, written to <ENV>_FRAMEDUMP_OUT (`frame` by default) + `-<n>.bmp`,
// its average colour and how much of it is not black printed beside the swap chain's window and
// size. What the game drew: PrintWindow and a screen copy of a Direct3D 9 window are black for the
// reference and the port alike, and a client at its title menu read as a black window for days
// (2026-10-28)
namespace {
void DumpBackBuffer(IDirect3DSwapChain9* sc, unsigned frame) {
    IDirect3DDevice9* dev = nullptr;
    IDirect3DSurface9* bb = nullptr;
    IDirect3DSurface9* sys = nullptr;
    D3DSURFACE_DESC d = {};
    D3DPRESENT_PARAMETERS pp = {};
    sc->GetPresentParameters(&pp);
    if (FAILED(sc->GetDevice(&dev)) || FAILED(sc->GetBackBuffer(0, D3DBACKBUFFER_TYPE_MONO, &bb)) ||
        FAILED(bb->GetDesc(&d)) ||
        FAILED(dev->CreateOffscreenPlainSurface(d.Width, d.Height, d.Format, D3DPOOL_SYSTEMMEM, &sys, nullptr)) ||
        FAILED(dev->GetRenderTargetData(bb, sys))) {
        fprintf(stderr, "%s: FRAMEDUMP %u: no back buffer copy (format %u, multisample %u)\n", RHIPPER_NAME, frame,
                d.Format, d.MultiSampleType);
    } else {
        D3DLOCKED_RECT lr = {};
        if (SUCCEEDED(sys->LockRect(&lr, nullptr, D3DLOCK_READONLY))) {
            wchar_t out[MAX_PATH] = L"frame";
            RefEnv("FRAMEDUMP_OUT", out, MAX_PATH);
            wchar_t path[MAX_PATH + 16];
            swprintf_s(path, L"%s-%u.bmp", out, frame);
            uint64_t sum[3] = {}, lit = 0;
            const bool argb = d.Format == D3DFMT_X8R8G8B8 || d.Format == D3DFMT_A8R8G8B8;
            FILE* f = nullptr;
            if (argb && _wfopen_s(&f, path, L"wb") == 0 && f) {
                BITMAPFILEHEADER fh = {0x4d42, 0, 0, 0, sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER)};
                BITMAPINFOHEADER ih = {sizeof ih, static_cast<LONG>(d.Width), -static_cast<LONG>(d.Height), 1, 32};
                fh.bfSize = fh.bfOffBits + d.Width * d.Height * 4;
                fwrite(&fh, sizeof fh, 1, f);
                fwrite(&ih, sizeof ih, 1, f);
                for (UINT y = 0; y < d.Height; y++) {
                    auto row = static_cast<const uint8_t*>(lr.pBits) + static_cast<size_t>(y) * lr.Pitch;
                    fwrite(row, 4, d.Width, f);
                    for (UINT x = 0; x < d.Width; x++) {
                        const uint8_t* p = row + x * 4;
                        sum[0] += p[2], sum[1] += p[1], sum[2] += p[0];
                        if (p[0] | p[1] | p[2]) lit++;
                    }
                }
                fclose(f);
            }
            sys->UnlockRect();
            const uint64_t px = static_cast<uint64_t>(d.Width) * d.Height;
            fprintf(stderr, "%s: FRAMEDUMP %u: %ux%u format %u, window %p (windowed %d, swap %u), average rgb "
                    "%.1f %.1f %.1f, %.1f%% not black -> %ls\n", RHIPPER_NAME, frame, d.Width, d.Height, d.Format,
                    pp.hDeviceWindow, pp.Windowed, pp.SwapEffect, px ? double(sum[0]) / px : 0.0,
                    px ? double(sum[1]) / px : 0.0, px ? double(sum[2]) / px : 0.0, px ? 100.0 * lit / px : 0.0,
                    argb ? path : L"(not written: not X8R8G8B8)");
        }
    }
    fflush(stderr);
    if (sys) sys->Release();
    if (bb) bb->Release();
    if (dev) dev->Release();
}
}  // namespace

unsigned int S_IDirect3DSwapChain9_Present(uint32_t self, uint32_t src, uint32_t dst, uint32_t wnd, uint32_t dirty,
                                           uint32_t flags) {
    static ComStat stat = {"IDirect3DSwapChain9::Present", 0, 0, nullptr};
    ComCount(&stat);
    auto sc = static_cast<IDirect3DSwapChain9*>(Unwrap(self));
    // (<every>[,<count>]: count dumps, 4 by default)
    static unsigned count = 4;
    static unsigned every = [] {
        wchar_t v[24] = {};
        if (!RefEnv("FRAMEDUMP", v, 24)) return 0u;
        wchar_t* end = nullptr;
        unsigned e = static_cast<unsigned>(wcstoul(v, &end, 10));
        if (end && *end == L',') count = static_cast<unsigned>(wcstoul(end + 1, nullptr, 10));
        return e;
    }();
    static volatile long frames = 0;
    const long n = InterlockedIncrement(&frames);
    const bool dump = every && n % every == 0 && static_cast<unsigned>(n / every) <= count;
    if (dump) DumpBackBuffer(sc, static_cast<unsigned>(n));
    HRESULT hr = sc->Present(At<RECT>(src), At<RECT>(dst), static_cast<HWND>(Handle32(wnd)), At<RGNDATA>(dirty), flags);
    if (dump) {
        D3DPRESENT_PARAMETERS pp = {};
        sc->GetPresentParameters(&pp);
        HWND w = wnd ? static_cast<HWND>(Handle32(wnd)) : pp.hDeviceWindow;
        wchar_t title[128] = {}, cls[64] = {};
        GetWindowTextW(w, title, 128);
        GetClassNameW(w, cls, 64);
        RECT rc = {};
        GetClientRect(w, &rc);
        // (and whether it waits on a paint, its update region never validated: the class's brush
        // erasing every blit)
        RECT upd = {};
        const BOOL pending = GetUpdateRect(w, &upd, FALSE);
        // (and what GDI reads back from the window, centre and a quarter in, and its display
        // affinity: a capture-excluded window is black to every screenshot)
        HDC dc = GetDC(w);
        const COLORREF c1 = GetPixel(dc, rc.right / 2, rc.bottom / 2), c2 = GetPixel(dc, rc.right / 4, rc.bottom / 4);
        ReleaseDC(w, dc);
        DWORD affinity = 0;
        GetWindowDisplayAffinity(w, &affinity);
        DWORD owner = 0;
        const DWORD owner_tid = GetWindowThreadProcessId(w, &owner);
        fprintf(stderr, "%s: FRAMEDUMP %ld: swap chain %p, window pixels %06lx %06lx, display affinity %lu, window "
                "of process %lu thread %lu (this process %lu thread %lu)\n", RHIPPER_NAME, n, static_cast<void*>(sc),
                static_cast<unsigned long>(c1), static_cast<unsigned long>(c2), affinity, owner, owner_tid,
                GetCurrentProcessId(), GetCurrentThreadId());
        fprintf(stderr, "%s: FRAMEDUMP %ld: Present(src %x, dst %x, window %x, dirty %x, flags %x) = %lx to %p \"%ls\" "
                "(%ls, visible %d, client %ldx%ld, parent %p, update %d %ld,%ld-%ld,%ld, brush %llx, wndproc %llx)\n",
                RHIPPER_NAME, n, src, dst, wnd, dirty, flags, hr, w, title, cls, IsWindowVisible(w), rc.right, rc.bottom,
                GetParent(w), pending, upd.left, upd.top, upd.right, upd.bottom,
                static_cast<unsigned long long>(GetClassLongPtrW(w, GCLP_HBRBACKGROUND)),
                static_cast<unsigned long long>(GetWindowLongPtrW(w, GWLP_WNDPROC)));
        fflush(stderr);
    }
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
void* EffectOf(uint32_t p);   // (below: a proxy's native object, or a face over the reference's own)
struct ChainN {
    Chain64 c = {};
    std::vector<Effect64> d;
    const Chain64* Of(uint32_t p) {
        if (!p) return nullptr;
        auto a = At<Chain32>(p);
        d.resize(a->EffectCount);
        for (uint32_t k = 0; k < a->EffectCount; k++) {
            auto e = At<Effect32>(a->pEffectDescriptors + k * sizeof(Effect32));
            d[k] = {EffectOf(e->pEffect), e->InitialState, e->OutputChannels};
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
// The reference's own XAPO effects (an effect chain's pEffect, the reference's objects with a 4-byte
// vtable, CXAPOBase's): a native IXAPO / IXAPOParameters face, each method the reference's in the
// same slot, its formats copied below 4 GB and its parameter arrays in the x86 layouts
#pragma pack(push, 1)
struct LockParams32 { uint32_t pFormat, MaxFrameCount; };
struct ProcessParams32 { uint32_t pBuffer, BufferFlags, ValidFrameCount; };
#pragma pack(pop)
struct LockParams64 { const WAVEFORMATEX* pFormat; UINT32 MaxFrameCount; };
struct ProcessParams64 { void* pBuffer; UINT32 BufferFlags; UINT32 ValidFrameCount; };
// IXAPO, IXAPOParameters (xapo.h)
const GUID kIID_IXAPO = {0xA90BC001, 0xE897, 0xE897, {0x55, 0xE4, 0x9E, 0x47, 0x00, 0x00, 0x00, 0x00}};
const GUID kIID_IXAPOParameters = {0xA90BC001, 0xE897, 0xE897, {0x55, 0xE4, 0x9E, 0x47, 0x00, 0x00, 0x00, 0x01}};

// a native format copied where the reference can read it (WAVEFORMATEX and its cbSize extra)
uint32_t LowFormat(const WAVEFORMATEX* f, std::vector<uint8_t>& buf) {
    if (!f) return 0;
    size_t n = sizeof(WAVEFORMATEX) + (f->wFormatTag == WAVE_FORMAT_PCM ? 0 : f->cbSize);
    buf.assign(reinterpret_cast<const uint8_t*>(f), reinterpret_cast<const uint8_t*>(f) + n);
    return Low(buf.data());
}
// what the reference can address of a native buffer XAudio2 hands it (below 2 GB in this process)
uint32_t LowBuffer(void* p) {
    if (reinterpret_cast<uintptr_t>(p) >> 32) {
        static bool told = false;
        if (!told) {
            told = true;
            fprintf(stderr, "%s: XAPO: a buffer above 4 GB (%p), out of the reference's reach\n", RHIPPER_NAME, p);
        }
    }
    return Low(p);
}

template <typename F>
F* FaceOf(uint32_t obj);
void* XapoFaceFor(uint32_t obj, REFIID riid);

struct XapoFace {
    virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** out) {
        if (!out) return E_POINTER;
        GUID iid = riid;   // (the caller's may be in a DLL above 4 GB)
        uint32_t got = 0;
        uint32_t hr = CallMethod(obj, 0, Low(&iid), Low(&got));
        *out = SUCCEEDED(static_cast<HRESULT>(hr)) && got ? XapoFaceFor(got, riid) : nullptr;
        return static_cast<HRESULT>(hr);
    }
    virtual ULONG STDMETHODCALLTYPE AddRef() { return CallMethod(obj, 1); }
    virtual ULONG STDMETHODCALLTYPE Release() { return CallMethod(obj, 2); }
    virtual HRESULT STDMETHODCALLTYPE GetRegistrationProperties(void** props) {
        uint32_t got = 0;
        HRESULT hr = static_cast<HRESULT>(CallMethod(obj, 3, Low(&got)));
        if (props) *props = At<void>(got);   // (XAPOAlloc's, CoTaskMemAlloc: XAudio2 frees it so)
        return hr;
    }
    virtual HRESULT STDMETHODCALLTYPE IsInputFormatSupported(const WAVEFORMATEX* output, const WAVEFORMATEX* requested,
                                                            WAVEFORMATEX** supported) {
        return FormatQuery(4, output, requested, supported);
    }
    virtual HRESULT STDMETHODCALLTYPE IsOutputFormatSupported(const WAVEFORMATEX* input, const WAVEFORMATEX* requested,
                                                             WAVEFORMATEX** supported) {
        return FormatQuery(5, input, requested, supported);
    }
    virtual HRESULT STDMETHODCALLTYPE Initialize(const void* data, UINT32 size) {
        std::vector<uint8_t> copy(static_cast<const uint8_t*>(data), static_cast<const uint8_t*>(data) + (data ? size : 0));
        return static_cast<HRESULT>(CallMethod(obj, 6, data ? Low(copy.data()) : 0u, size));
    }
    virtual void STDMETHODCALLTYPE Reset() { CallMethod(obj, 7); }
    virtual HRESULT STDMETHODCALLTYPE LockForProcess(UINT32 nin, const LockParams64* in, UINT32 nout, const LockParams64* out) {
        std::vector<LockParams32> i32(nin), o32(nout);
        std::vector<std::vector<uint8_t>> formats(nin + nout);
        for (UINT32 k = 0; k < nin; k++) i32[k] = {LowFormat(in[k].pFormat, formats[k]), in[k].MaxFrameCount};
        for (UINT32 k = 0; k < nout; k++) o32[k] = {LowFormat(out[k].pFormat, formats[nin + k]), out[k].MaxFrameCount};
        // (the reference keeps the formats it is locked with: kept here as long as the lock)
        locked = std::move(formats);
        return static_cast<HRESULT>(CallMethod(obj, 8, nin, nin ? Low(i32.data()) : 0u, nout, nout ? Low(o32.data()) : 0u));
    }
    virtual void STDMETHODCALLTYPE UnlockForProcess() { CallMethod(obj, 9); }
    virtual void STDMETHODCALLTYPE Process(UINT32 nin, const ProcessParams64* in, UINT32 nout, ProcessParams64* out,
                                           BOOL enabled) {
        ProcessParams32 i32[8], o32[8];
        if (nin > 8 || nout > 8) return;
        for (UINT32 k = 0; k < nin; k++) i32[k] = {LowBuffer(in[k].pBuffer), in[k].BufferFlags, in[k].ValidFrameCount};
        for (UINT32 k = 0; k < nout; k++) o32[k] = {LowBuffer(out[k].pBuffer), out[k].BufferFlags, out[k].ValidFrameCount};
        CallMethod(obj, 10, nin, Low(i32), nout, Low(o32), static_cast<uint32_t>(enabled));
        for (UINT32 k = 0; k < nout; k++) {
            out[k].BufferFlags = o32[k].BufferFlags;
            out[k].ValidFrameCount = o32[k].ValidFrameCount;
        }
    }
    virtual UINT32 STDMETHODCALLTYPE CalcInputFrames(UINT32 n) { return CallMethod(obj, 11, n); }
    virtual UINT32 STDMETHODCALLTYPE CalcOutputFrames(UINT32 n) { return CallMethod(obj, 12, n); }
    uint32_t obj = 0;
    std::vector<std::vector<uint8_t>> locked;

    HRESULT FormatQuery(unsigned k, const WAVEFORMATEX* other, const WAVEFORMATEX* requested, WAVEFORMATEX** supported) {
        std::vector<uint8_t> a, b;
        uint32_t got = 0;
        HRESULT hr = static_cast<HRESULT>(
            CallMethod(obj, k, LowFormat(other, a), LowFormat(requested, b), supported ? Low(&got) : 0u));
        if (supported) *supported = At<WAVEFORMATEX>(got);   // (XAPOAlloc's, freed by XAudio2)
        return hr;
    }
};
struct XapoParamsFace {
    virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** out) {
        if (!out) return E_POINTER;
        GUID iid = riid;
        uint32_t got = 0;
        uint32_t hr = CallMethod(obj, 0, Low(&iid), Low(&got));
        *out = SUCCEEDED(static_cast<HRESULT>(hr)) && got ? XapoFaceFor(got, riid) : nullptr;
        return static_cast<HRESULT>(hr);
    }
    virtual ULONG STDMETHODCALLTYPE AddRef() { return CallMethod(obj, 1); }
    virtual ULONG STDMETHODCALLTYPE Release() { return CallMethod(obj, 2); }
    virtual void STDMETHODCALLTYPE SetParameters(const void* p, UINT32 size) {
        std::vector<uint8_t> copy(static_cast<const uint8_t*>(p), static_cast<const uint8_t*>(p) + (p ? size : 0));
        CallMethod(obj, 3, p ? Low(copy.data()) : 0u, size);
    }
    virtual void STDMETHODCALLTYPE GetParameters(void* p, UINT32 size) {
        std::vector<uint8_t> copy(p ? size : 0);
        CallMethod(obj, 4, p ? Low(copy.data()) : 0u, size);
        if (p) memcpy(p, copy.data(), size);
    }
    uint32_t obj = 0;
};

void* XapoFaceFor(uint32_t obj, REFIID riid) {
    if (IsEqualGUID(riid, kIID_IXAPOParameters)) return static_cast<void*>(FaceOf<XapoParamsFace>(obj));
    return static_cast<void*>(FaceOf<XapoFace>(obj));
}

// an effect the reference names: the native object of a proxy the port gave it, else a face over
// the reference's own
void* EffectOf(uint32_t p) {
    if (!p) return nullptr;
    if (At<Proxy32>(p)->magic == kProxyMagic) return Unwrap(p);
    return static_cast<void*>(FaceOf<XapoFace>(p));
}

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

// (the hand-written methods counted too, COMSTATS, and their failures apart: a create that fails
// leaves a sound silent with nothing in the log)
#define COM_COUNTED(name, expr)                                                    \
    [&]() -> uint32_t {                                                            \
        static ComStat stat = {name, 0, 0, nullptr};                               \
        static ComStat failed = {name " (failed)", 0, 0, nullptr};                 \
        ComCount(&stat);                                                           \
        uint32_t r_ = (expr);                                                      \
        if (FAILED(static_cast<HRESULT>(r_))) {                                    \
            ComCount(&failed);                                                     \
            if (failed.calls <= 3)                                                 \
                fprintf(stderr, "%s: %s failed %08x\n", RHIPPER_NAME, name, r_);   \
        }                                                                          \
        return r_;                                                                 \
    }()

}  // namespace

extern "C" {

unsigned int S_IXAudio2_RegisterForCallbacks(uint32_t self, uint32_t cb) {
    void* n = Unwrap(self);
    return COM_COUNTED("IXAudio2::RegisterForCallbacks",
                       Native<uint32_t>(n, kRegisterForCallbacks, static_cast<void*>(FaceOf<EngineCallback>(cb))));
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
    uint32_t hr = COM_COUNTED("IXAudio2::CreateSourceVoice",
                              Native<uint32_t>(n, kCreateSourceVoice, &v, At<const void>(format), flags, Float32(ratio),
                                               static_cast<void*>(FaceOf<VoiceCallback>(cb)), s.Of(sends), c.Of(chain)));
    if (out) *At<uint32_t>(out) = Wrap(v, &IXAudio2SourceVoice_32);
    return hr;
}
unsigned int S_IXAudio2_CreateSubmixVoice(uint32_t self, uint32_t out, uint32_t channels, uint32_t rate, uint32_t flags,
                                          uint32_t stage, uint32_t sends, uint32_t chain) {
    void* n = Unwrap(self);
    SendsN s;
    ChainN c;
    void* v = nullptr;
    uint32_t hr = COM_COUNTED("IXAudio2::CreateSubmixVoice",
                              Native<uint32_t>(n, kCreateSubmixVoice, &v, channels, rate, flags, stage, s.Of(sends),
                                               c.Of(chain)));
    if (out) *At<uint32_t>(out) = Wrap(v, &IXAudio2SubmixVoice_32);
    return hr;
}
unsigned int S_IXAudio2_CreateMasteringVoice(uint32_t self, uint32_t out, uint32_t channels, uint32_t rate,
                                             uint32_t flags, uint32_t device, uint32_t chain) {
    void* n = Unwrap(self);
    ChainN c;
    void* v = nullptr;
    uint32_t hr = COM_COUNTED("IXAudio2::CreateMasteringVoice",
                              Native<uint32_t>(n, kCreateMasteringVoice, &v, channels, rate, flags, device, c.Of(chain)));
    if (out) *At<uint32_t>(out) = Wrap(v, &IXAudio2MasteringVoice_32);
    return hr;
}

unsigned int S_IXAudio2Voice_SetOutputVoices(uint32_t self, uint32_t sends) {
    SendsN s;
    return COM_COUNTED("IXAudio2Voice::SetOutputVoices", Native<uint32_t>(Unwrap(self), kSetOutputVoices, s.Of(sends)));
}
unsigned int S_IXAudio2Voice_SetEffectChain(uint32_t self, uint32_t chain) {
    ChainN c;
    return COM_COUNTED("IXAudio2Voice::SetEffectChain", Native<uint32_t>(Unwrap(self), kSetEffectChain, c.Of(chain)));
}

// (XAudio2 copies the buffer's description, not its audio)
unsigned int S_IXAudio2SourceVoice_SubmitSourceBuffer(uint32_t self, uint32_t buffer, uint32_t wma) {
    auto b = At<Buffer32>(buffer);
    Buffer64 n = {b->Flags, b->AudioBytes, At<const void>(b->pAudioData), b->PlayBegin, b->PlayLength,
                  b->LoopBegin, b->LoopLength, b->LoopCount, At<void>(b->pContext)};
    BufferWma64 w = {};
    if (wma) w = {At<const uint32_t>(At<BufferWma32>(wma)->pDecodedPacketCumulativeBytes), At<BufferWma32>(wma)->PacketCount};
    return COM_COUNTED("IXAudio2SourceVoice::SubmitSourceBuffer",
                       Native<uint32_t>(Unwrap(self), kSubmitSourceBuffer, static_cast<const Buffer64*>(&n),
                                        wma ? static_cast<const BufferWma64*>(&w) : nullptr));
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

// ---- DxDiag (DirectX's system information): DXDIAG_INIT_PARAMS holds a pointer, and a VARIANT is
// 16 bytes on x86 and 24 on x64 (its union is the size of two pointers there). The reference
// reads each property as an x86 VARIANT, and frees it with VariantClear, adapted below ------------
namespace {

#pragma pack(push, 4)
struct DxDiagInit32 {
    uint32_t dwSize, dwDxDiagHeaderVersion, bAllowWHQLChecks, pReserved;
};
struct Variant32 {
    uint16_t vt, r1, r2, r3;
    uint32_t lo, hi;   // the union: a 4-byte value or pointer in lo, an 8-byte one in both
};
#pragma pack(pop)
static_assert(sizeof(Variant32) == 16, "VARIANT, x86");

struct DxDiagInit64 {
    uint32_t dwSize, dwDxDiagHeaderVersion, bAllowWHQLChecks;
    void* pReserved;
};

enum : unsigned { kDxDiagInitialize = 3, kDxDiagGetProp = 8 };

}  // namespace

extern "C" {

unsigned int S_IDxDiagProvider_Initialize(uint32_t self, uint32_t params) {
    auto p = At<DxDiagInit32>(params);
    DxDiagInit64 n = {sizeof(DxDiagInit64), p->dwDxDiagHeaderVersion, p->bAllowWHQLChecks, At<void>(p->pReserved)};
    return Native<uint32_t>(Unwrap(self), kDxDiagInitialize, &n);
}

// (a property as an x86 VARIANT: its type, and the value or pointer as x86 holds it; a BSTR's
// memory is below 2 GB like all the port's, its 4-byte address the reference's to free)
unsigned int S_IDxDiagContainer_GetProp(uint32_t self, uint32_t name, uint32_t out) {
    VARIANT v;
    VariantInit(&v);
    uint32_t hr = Native<uint32_t>(Unwrap(self), kDxDiagGetProp, At<const wchar_t>(name), &v);
    auto o = At<Variant32>(out);
    memset(o, 0, sizeof *o);
    if (SUCCEEDED(static_cast<HRESULT>(hr))) {
        o->vt = v.vt;
        uint64_t raw = 0;
        memcpy(&raw, &v.llVal, 8);
        if (v.vt == VT_BSTR || v.vt == VT_UNKNOWN || v.vt == VT_DISPATCH || (v.vt & VT_BYREF)) {
            o->lo = static_cast<uint32_t>(raw);   // (a pointer: its 4-byte address)
            if (v.vt == VT_UNKNOWN || v.vt == VT_DISPATCH) o->lo = Wrap(v.punkVal, &IUnknown_32);
        } else {
            o->lo = static_cast<uint32_t>(raw);
            o->hi = static_cast<uint32_t>(raw >> 32);
        }
    }
    return hr;
}

// oleaut32's VARIANT functions on the reference's x86 VARIANTs (16 bytes: a 24-byte x64 one would be
// read past it)
unsigned int gen_imp_VariantInit(uint32_t p) {
    if (p) memset(At<Variant32>(p), 0, sizeof(Variant32));
    return 0;
}
unsigned int gen_imp_VariantClear(uint32_t p) {
    if (!p) return static_cast<unsigned int>(E_INVALIDARG);
    auto v = At<Variant32>(p);
    if (v->vt == VT_BSTR) {
        SysFreeString(At<OLECHAR>(v->lo));
    } else if ((v->vt == VT_UNKNOWN || v->vt == VT_DISPATCH) && v->lo) {
        IUnknown* u = static_cast<IUnknown*>(Unwrap(v->lo));
        if (u) u->Release();
    }
    memset(v, 0, sizeof *v);
    return S_OK;
}

}  // extern "C"

// ---- NVIDIA's NVAPI: nvapi64.dll in nvapi.dll's place (Adapters.cpp's LoadLibraryA), its one
// export, nvapi_QueryInterface(id), given to the reference as a 32-bit one. Each function it hands
// back is the 64-bit one reached from a 4-byte slot (its arguments all numbers or pointers to
// structures laid out alike), or an adapter where one is an object of ours: the Direct3D device
// of NvAPI_D3D_GetCurrentSLIState is a proxy (Com32.h) -------------------------------------------
uint32_t RefLowStub(void* fn);   // RefImage.cpp

namespace {

void* (__cdecl* g_nvQueryInterface)(unsigned id) = nullptr;
int (__cdecl* g_nvSliState)(void* device, void* state) = nullptr;

int Nv_D3D_GetCurrentSLIState(uint32_t device, uint32_t state) {
    return g_nvSliState(Unwrap(device), At<void>(state));
}

uint32_t Nv_QueryInterface(uint32_t id) {
    void* fn = g_nvQueryInterface ? g_nvQueryInterface(id) : nullptr;
    if (!fn) return 0;
    switch (id) {
        case 0x4b708b54:   // NvAPI_D3D_GetCurrentSLIState(IUnknown *, NV_GET_CURRENT_SLI_STATE *)
            g_nvSliState = reinterpret_cast<int(__cdecl*)(void*, void*)>(fn);
            return Low(reinterpret_cast<void*>(Nv_D3D_GetCurrentSLIState));
        default:
            return RefLowStub(fn);
    }
}

// ---- the kernel display functions a reference finds in gdi32 by name: their structures hold an HDC
// or a pointer, 8 bytes on x64. Given the 64-bit ones, the reference's 20-byte
// D3DKMT_OPENADAPTERFROMHDC read as 24 failed, and its display query took the error path the
// reference never did (a VS2010 client's 0xb1b020, 2026-10-25) -------------------------------------
#pragma pack(push, 4)
struct OpenAdapterFromHdc32 {
    uint32_t hDc, hAdapter, luidLow;
    int32_t luidHigh;
    uint32_t vidPnSourceId;
};
struct Escape32 {
    uint32_t hAdapter, hDevice, type, flags, pPrivateDriverData, privateDriverDataSize, hContext;
};
#pragma pack(pop)
struct OpenAdapterFromHdc64 {
    void* hDc;
    uint32_t hAdapter, luidLow;
    int32_t luidHigh;
    uint32_t vidPnSourceId;
};
struct Escape64 {
    uint32_t hAdapter, hDevice, type, flags;
    void* pPrivateDriverData;
    uint32_t privateDriverDataSize, hContext;
};
static_assert(sizeof(OpenAdapterFromHdc32) == 20 && sizeof(OpenAdapterFromHdc64) == 24, "D3DKMT_OPENADAPTERFROMHDC");
static_assert(sizeof(Escape32) == 28 && sizeof(Escape64) == 32, "D3DKMT_ESCAPE");

LONG (APIENTRY* g_kmtOpenAdapterFromHdc)(OpenAdapterFromHdc64*) = nullptr;
LONG (APIENTRY* g_kmtEscape)(const Escape64*) = nullptr;

unsigned int Kmt_OpenAdapterFromHdc(uint32_t p) {
    auto a = At<OpenAdapterFromHdc32>(p);
    OpenAdapterFromHdc64 n = {Handle32(a->hDc), a->hAdapter, a->luidLow, a->luidHigh, a->vidPnSourceId};
    LONG st = g_kmtOpenAdapterFromHdc(&n);
    a->hAdapter = n.hAdapter;
    a->luidLow = n.luidLow;
    a->luidHigh = n.luidHigh;
    a->vidPnSourceId = n.vidPnSourceId;
    return static_cast<unsigned int>(st);
}

unsigned int Kmt_Escape(uint32_t p) {
    auto e = At<Escape32>(p);
    Escape64 n = {e->hAdapter, e->hDevice, e->type, e->flags, At<void>(e->pPrivateDriverData),
                  e->privateDriverDataSize, e->hContext};
    return static_cast<unsigned int>(g_kmtEscape(&n));
}

}  // namespace

// a function the reference resolves by name that the runtime gives it in a 32-bit form: NVAPI's
// QueryInterface, the kernel display functions with structures of their own
uint32_t Com32Proc(uint32_t module, const char* name) {
    HMODULE m = reinterpret_cast<HMODULE>(static_cast<uintptr_t>(module));
    if (strcmp(name, "D3DKMTOpenAdapterFromHdc") == 0) {
        g_kmtOpenAdapterFromHdc = reinterpret_cast<LONG(APIENTRY*)(OpenAdapterFromHdc64*)>(GetProcAddress(m, name));
        return g_kmtOpenAdapterFromHdc ? Low(reinterpret_cast<void*>(Kmt_OpenAdapterFromHdc)) : 0;
    }
    if (strcmp(name, "D3DKMTEscape") == 0) {
        g_kmtEscape = reinterpret_cast<LONG(APIENTRY*)(const Escape64*)>(GetProcAddress(m, name));
        return g_kmtEscape ? Low(reinterpret_cast<void*>(Kmt_Escape)) : 0;
    }
    HMODULE nv = GetModuleHandleW(L"nvapi64.dll");
    if (!nv || module != Low(nv) || strcmp(name, "nvapi_QueryInterface") != 0) return 0;
    g_nvQueryInterface = reinterpret_cast<void*(__cdecl*)(unsigned)>(GetProcAddress(nv, name));
    return g_nvQueryInterface ? Low(reinterpret_cast<void*>(Nv_QueryInterface)) : 0;
}

// ---- the imports that make the objects ---------------------------------------------------------------
bool DxDiagBridgeClass(REFCLSID clsid);           // DxDiagBridge.cpp
HRESULT DxDiagBridgeCreate(REFIID riid, void** out);

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
        {0xa65b8071, 0x3bfe, 0x4213, {0x9a, 0x5b, 0x49, 0x1d, 0xa4, 0x46, 0x1c, 0xa7}},   // DxDiagProvider
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
    // (DxDiag's provider the 32-bit one, in its helper: DxDiagBridge.cpp)
    HRESULT hr = DxDiagBridgeClass(*At<CLSID>(clsid))
                     ? DxDiagBridgeCreate(*At<IID>(riid), &o)
                     : CoCreateInstance(*At<CLSID>(clsid), static_cast<LPUNKNOWN>(Unwrap(outer)), context, *At<IID>(riid), &o);
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
