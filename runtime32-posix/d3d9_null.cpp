// d3d9: a null renderer, the runtime's Direct3DCreate9 until the project registers its own
// (rhipper_com_set_factory("Direct3DCreate9", ...): CrystalCore's Vulkan IDirect3D9 is the seam).
//
// Every call succeeds and draws nothing: the device made, resources made with memory behind their
// locks, state set and forgotten, Present counted. Enough for the reference to boot past its
// renderer's setup and run its frames (and its lobby connection) with nothing on the screen. The
// calls are counted per method, the first of each logged, and the counts every 600 presents.
//
// The vtable layouts are d3d9.h's (slot numbers in the tables below). A method's float argument
// arrives as a double (Com32Posix.h); none here reads one.
#include <algorithm>
#include <atomic>
#include <map>
#include <mutex>
#include <vector>

#include "Com32Posix.h"

extern "C" void gen_set_x87_cw(unsigned short cw);   // Hooks.cpp

namespace rh {

using namespace com;

namespace {

constexpr uint32_t D3D_OK = 0, D3DERR_NOTAVAILABLE = 0x8876086Au, D3DERR_INVALIDCALL = 0x8876086Cu;

std::atomic<uint64_t> g_calls[3][128];   // [interface kind][slot]
std::atomic<uint64_t> g_presents{0};

// ---- resources: one class for every kind, its vtable by kind ---------------------------------------
enum Kind { kSurface, kTexture, kCubeTexture, kVolumeTexture, kVertexBuffer, kIndexBuffer, kQuery, kStateBlock,
            kVertexDecl, kVertexShader, kPixelShader, kSwapChain, kKinds };
const char* const kKindNames[kKinds] = {"Surface", "Texture", "CubeTexture", "VolumeTexture", "VertexBuffer",
                                        "IndexBuffer", "Query", "StateBlock", "VertexDeclaration", "VertexShader",
                                        "PixelShader", "SwapChain"};

struct Device;

struct Resource : Refcounted {
    Kind kind;
    Device* device;
    uint32_t width = 0, height = 0, depth = 1, levels = 1, format = 0, usage = 0, pool = 0, size = 0, type = 0;
    uint32_t lockMem = 0, lockSize = 0;
    std::vector<uint32_t> surfaces;   // a texture's levels as surfaces, made on demand
    std::vector<uint8_t> blob;        // a shader's function, a declaration's elements

    ~Resource() override {
        if (lockMem) HeapFreeIn(ProcessHeap(), 0, lockMem);
        for (uint32_t s : surfaces)
            if (auto r = As<Resource>(s)) r->Release();
    }
    uint32_t Memory(uint32_t bytes) {
        if (!lockMem || lockSize < bytes) {
            if (lockMem) HeapFreeIn(ProcessHeap(), 0, lockMem);
            lockMem = HeapAllocIn(ProcessHeap(), 8, bytes ? bytes : 16);
            lockSize = bytes;
        }
        return lockMem;
    }
    uint32_t Pitch(uint32_t w) const {
        // (DXT1 8 bytes and DXT2-5 16 per 4x4 block; everything else at most 4 bytes a pixel, 16 for
        // the 128-bit formats)
        if (format == 0x31545844) return ((w + 3) / 4) * 8;
        if (format >= 0x32545844 && format <= 0x35545844) return ((w + 3) / 4) * 16;
        if (format == 116 || format == 115) return w * 16;   // A32B32G32R32F, A16B16G16R16F (8, rounded up)
        return w * 4;
    }
    uint32_t Rows(uint32_t h) const { return format >= 0x31545844 && format <= 0x35545844 ? (h + 3) / 4 : h; }

    // IUnknown and IDirect3DResource9
    uint32_t QueryInterface(uint32_t, uint32_t out) {
        AddRef();
        *At<uint32_t>(out) = self;
        return D3D_OK;
    }
    uint32_t AddRef_() { return AddRef(); }
    uint32_t Release_() { return Release(); }
    uint32_t GetDevice(uint32_t out);
    uint32_t Ok() { return D3D_OK; }
    uint32_t GetType() { return type; }
    uint32_t GetPriority() { return 0; }
    uint32_t GetLevelCount() { return levels; }

    // D3DSURFACE_DESC (32 bytes): Format, Type, Usage, Pool, MultiSampleType, Quality, Width, Height
    void Desc(uint32_t out, uint32_t w, uint32_t h) {
        uint32_t d[8] = {format, 1 /* D3DRTYPE_SURFACE */, usage, pool, 0, 0, w, h};
        memcpy(At(out), d, sizeof d);
    }
    uint32_t SurfaceGetDesc(uint32_t out) { return Desc(out, width, height), D3D_OK; }
    // D3DLOCKED_RECT: Pitch, pBits
    uint32_t LockRectAt(uint32_t locked, uint32_t w, uint32_t h) {
        uint32_t pitch = Pitch(w);
        *At<int32_t>(locked) = static_cast<int32_t>(pitch);
        *At<uint32_t>(locked + 4) = Memory(pitch * Rows(h));
        return D3D_OK;
    }
    uint32_t SurfaceLockRect(uint32_t locked, uint32_t, uint32_t) { return LockRectAt(locked, width, height); }
    uint32_t SurfaceGetDC(uint32_t out) {
        *At<uint32_t>(out) = 0;
        return D3DERR_INVALIDCALL;
    }
    uint32_t GetContainer(uint32_t, uint32_t out) {
        *At<uint32_t>(out) = 0;
        return win::E_NOINTERFACE;
    }
    // textures
    uint32_t Level(uint32_t level) { return level < 16 ? std::max<uint32_t>(1, width >> level) : 1; }
    uint32_t LevelH(uint32_t level) { return level < 16 ? std::max<uint32_t>(1, height >> level) : 1; }
    uint32_t TexGetLevelDesc(uint32_t level, uint32_t out) {
        if (level >= levels) return D3DERR_INVALIDCALL;
        return Desc(out, Level(level), LevelH(level)), D3D_OK;
    }
    uint32_t TexGetSurfaceLevel(uint32_t level, uint32_t out);
    uint32_t TexLockRect(uint32_t level, uint32_t locked, uint32_t, uint32_t) {
        return LockRectAt(locked, Level(level), LevelH(level));
    }
    uint32_t CubeGetCubeMapSurface(uint32_t, uint32_t level, uint32_t out) { return TexGetSurfaceLevel(level, out); }
    uint32_t CubeLockRect(uint32_t, uint32_t level, uint32_t locked, uint32_t, uint32_t) {
        return LockRectAt(locked, Level(level), LevelH(level));
    }
    // D3DLOCKED_BOX: RowPitch, SlicePitch, pBits
    uint32_t VolLockBox(uint32_t level, uint32_t locked, uint32_t, uint32_t) {
        uint32_t pitch = Pitch(Level(level)), slice = pitch * Rows(LevelH(level));
        *At<int32_t>(locked) = static_cast<int32_t>(pitch);
        *At<int32_t>(locked + 4) = static_cast<int32_t>(slice);
        *At<uint32_t>(locked + 8) = Memory(slice * std::max<uint32_t>(1, depth >> level));
        return D3D_OK;
    }
    // buffers: Lock(offset, size, ppbData, flags)
    uint32_t BufLock(uint32_t offset, uint32_t, uint32_t out, uint32_t) {
        *At<uint32_t>(out) = Memory(size) + std::min(offset, size);
        return D3D_OK;
    }
    // D3DVERTEXBUFFER_DESC / D3DINDEXBUFFER_DESC: Format, Type, Usage, Pool, Size (FVF for a VB)
    uint32_t BufGetDesc(uint32_t out) {
        uint32_t d[6] = {kind == kIndexBuffer ? format : 100 /* D3DFMT_VERTEXDATA */, kind == kIndexBuffer ? 7u : 6u,
                         usage, pool, size, format};
        memcpy(At(out), d, kind == kIndexBuffer ? 20 : 24);
        return D3D_OK;
    }
    // a query: its data ready at once, zeros (an occlusion query's 0 pixels, an event's done)
    uint32_t QueryGetType() { return type; }
    uint32_t QueryGetDataSize() { return type == 9 /* OCCLUSION */ ? 4 : type == 8 /* EVENT */ ? 4 : 8; }
    uint32_t QueryGetData(uint32_t data, uint32_t n, uint32_t) {
        if (data && n) {
            memset(At(data), 0, n);
            if (type == 8 && n >= 4) *At<uint32_t>(data) = 1;   // (an event: done)
        }
        return D3D_OK;
    }
    // a shader's function or a declaration's elements, as given
    uint32_t GetBlob(uint32_t out, uint32_t sizeOut) {
        if (out) memcpy(At(out), blob.data(), blob.size());
        if (sizeOut) *At<uint32_t>(sizeOut) = static_cast<uint32_t>(blob.size());
        return D3D_OK;
    }
    uint32_t DeclGetDeclaration(uint32_t out, uint32_t count) {
        if (out) memcpy(At(out), blob.data(), blob.size());
        if (count) *At<uint32_t>(count) = static_cast<uint32_t>(blob.size() / 8);
        return D3D_OK;
    }
    // a swap chain
    uint32_t ScPresent(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
    uint32_t ScGetBackBuffer(uint32_t, uint32_t, uint32_t out);
    uint32_t ScGetDisplayMode(uint32_t out);
    uint32_t ScGetPresentParameters(uint32_t out);
    uint32_t ScGetRasterStatus(uint32_t out) {
        memset(At(out), 0, 8);
        return D3D_OK;
    }
};

uint32_t ResourceVtable(Kind kind) {
    static uint32_t made[kKinds] = {};
    static std::mutex lock;
    std::lock_guard<std::mutex> hold(lock);
    if (made[kind]) return made[kind];
    const void* m[32];
    for (auto& p : m) p = M_<&Resource::Ok>();
    m[0] = M_<&Resource::QueryInterface>();
    m[1] = M_<&Resource::AddRef_>();
    m[2] = M_<&Resource::Release_>();
    m[3] = M_<&Resource::GetDevice>();
    unsigned n = 32;
    switch (kind) {
        case kSurface:
            m[8] = M_<&Resource::GetPriority>(), m[10] = M_<&Resource::GetType>();
            m[11] = M_<&Resource::GetContainer>(), m[12] = M_<&Resource::SurfaceGetDesc>();
            m[13] = M_<&Resource::SurfaceLockRect>(), m[15] = M_<&Resource::SurfaceGetDC>();
            n = 17;
            break;
        case kTexture: case kCubeTexture: case kVolumeTexture:
            m[8] = M_<&Resource::GetPriority>(), m[10] = M_<&Resource::GetType>();
            m[13] = M_<&Resource::GetLevelCount>(), m[17] = M_<&Resource::TexGetLevelDesc>();
            m[18] = kind == kCubeTexture ? M_<&Resource::CubeGetCubeMapSurface>() : M_<&Resource::TexGetSurfaceLevel>();
            m[19] = kind == kTexture ? M_<&Resource::TexLockRect>()
                  : kind == kCubeTexture ? M_<&Resource::CubeLockRect>() : M_<&Resource::VolLockBox>();
            n = 22;
            break;
        case kVertexBuffer: case kIndexBuffer:
            m[8] = M_<&Resource::GetPriority>(), m[10] = M_<&Resource::GetType>();
            m[11] = M_<&Resource::BufLock>(), m[13] = M_<&Resource::BufGetDesc>();
            n = 14;
            break;
        case kQuery:
            m[4] = M_<&Resource::QueryGetType>(), m[5] = M_<&Resource::QueryGetDataSize>(), m[7] = M_<&Resource::QueryGetData>();
            n = 8;
            break;
        case kStateBlock: n = 6; break;
        case kVertexDecl: m[4] = M_<&Resource::DeclGetDeclaration>(), n = 5; break;
        case kVertexShader: case kPixelShader: m[4] = M_<&Resource::GetBlob>(), n = 5; break;
        case kSwapChain:
            m[3] = M_<&Resource::ScPresent>(), m[5] = M_<&Resource::ScGetBackBuffer>();
            m[6] = M_<&Resource::ScGetRasterStatus>(), m[7] = M_<&Resource::ScGetDisplayMode>();
            m[8] = M_<&Resource::GetDevice>(), m[9] = M_<&Resource::ScGetPresentParameters>();
            n = 10;
            break;
        default: break;
    }
    made[kind] = Vtable(m, n);
    return made[kind];
}

Resource* NewResource(Kind kind, Device* dev) {
    auto r = new Resource();
    r->kind = kind;
    r->device = dev;
    r->self = NewObject(ResourceVtable(kind), r);
    return r;
}

uint32_t Resource::TexGetSurfaceLevel(uint32_t level, uint32_t out) {
    if (level >= levels) return D3DERR_INVALIDCALL;
    if (surfaces.size() < levels) surfaces.resize(levels);
    if (!surfaces[level]) {
        Resource* s = NewResource(kSurface, device);
        s->width = Level(level), s->height = LevelH(level), s->format = format, s->usage = usage, s->pool = pool;
        s->type = 1;
        surfaces[level] = s->self;
    }
    As<Resource>(surfaces[level])->AddRef();
    *At<uint32_t>(out) = surfaces[level];
    return D3D_OK;
}

// ---- the device ---------------------------------------------------------------------------------
#pragma pack(push, 4)
struct PresentParams32 {
    uint32_t BackBufferWidth, BackBufferHeight, BackBufferFormat, BackBufferCount, MultiSampleType, MultiSampleQuality,
        SwapEffect, hDeviceWindow, Windowed, EnableAutoDepthStencil, AutoDepthStencilFormat, Flags,
        FullScreen_RefreshRateInHz, PresentationInterval;
};
#pragma pack(pop)
static_assert(sizeof(PresentParams32) == 56, "D3DPRESENT_PARAMETERS, x86");

struct D3D9;

struct Device : Refcounted {
    D3D9* d3d;
    uint32_t d3dObj;
    PresentParams32 pp;
    uint32_t adapter, deviceType, focus, behavior;
    Resource *backBuffer = nullptr, *depth = nullptr, *swapChain = nullptr;
    uint32_t renderTargets[4] = {}, depthStencil = 0;
    uint32_t renderStates[256] = {};

    void MakeBuffers() {
        uint32_t w = pp.BackBufferWidth ? pp.BackBufferWidth : 1280, h = pp.BackBufferHeight ? pp.BackBufferHeight : 720;
        backBuffer = NewResource(kSurface, this);
        backBuffer->width = w, backBuffer->height = h, backBuffer->format = pp.BackBufferFormat ? pp.BackBufferFormat : 22;
        backBuffer->usage = 1, backBuffer->type = 1;
        renderTargets[0] = backBuffer->self;
        if (pp.EnableAutoDepthStencil) {
            depth = NewResource(kSurface, this);
            depth->width = w, depth->height = h, depth->format = pp.AutoDepthStencilFormat, depth->usage = 2, depth->type = 1;
            depthStencil = depth->self;
        }
        swapChain = NewResource(kSwapChain, this);
    }

    uint32_t QueryInterface(uint32_t, uint32_t out) {
        AddRef();
        *At<uint32_t>(out) = self;
        return D3D_OK;
    }
    uint32_t AddRef_() { return AddRef(); }
    uint32_t Release_() { return Release(); }
    uint32_t Ok() { return D3D_OK; }
    uint32_t TestCooperativeLevel() { return D3D_OK; }
    uint32_t GetAvailableTextureMem() { return 512u << 20; }
    uint32_t GetDirect3D(uint32_t out);
    uint32_t GetDeviceCaps(uint32_t out);
    uint32_t GetDisplayMode(uint32_t, uint32_t out) {
        uint32_t m[4] = {pp.BackBufferWidth, pp.BackBufferHeight, 60, 22 /* X8R8G8B8 */};
        memcpy(At(out), m, sizeof m);
        return D3D_OK;
    }
    uint32_t GetCreationParameters(uint32_t out) {
        uint32_t c[4] = {adapter, deviceType, focus, behavior};
        memcpy(At(out), c, sizeof c);
        return D3D_OK;
    }
    uint32_t ShowCursor(uint32_t) { return 0; }
    uint32_t CreateAdditionalSwapChain(uint32_t, uint32_t out) {
        *At<uint32_t>(out) = NewResource(kSwapChain, this)->self;
        return D3D_OK;
    }
    uint32_t GetSwapChain(uint32_t, uint32_t out) {
        swapChain->AddRef();
        *At<uint32_t>(out) = swapChain->self;
        return D3D_OK;
    }
    uint32_t GetNumberOfSwapChains() { return 1; }
    uint32_t Reset(uint32_t p) {
        pp = *At<PresentParams32>(p);
        if (backBuffer) backBuffer->width = pp.BackBufferWidth, backBuffer->height = pp.BackBufferHeight;
        if (depth) depth->width = pp.BackBufferWidth, depth->height = pp.BackBufferHeight;
        Log("d3d9 (null): Reset %ux%u", pp.BackBufferWidth, pp.BackBufferHeight);
        return D3D_OK;
    }
    uint32_t Present(uint32_t, uint32_t, uint32_t, uint32_t) {
        uint64_t n = ++g_presents;
        if (n == 1 || n % 600 == 0) Report(n);
        return D3D_OK;
    }
    uint32_t GetBackBuffer(uint32_t, uint32_t, uint32_t, uint32_t out) {
        backBuffer->AddRef();
        *At<uint32_t>(out) = backBuffer->self;
        return D3D_OK;
    }
    uint32_t GetRasterStatus(uint32_t, uint32_t out) {
        memset(At(out), 0, 8);
        return D3D_OK;
    }
    uint32_t CreateTexture(uint32_t w, uint32_t h, uint32_t levels, uint32_t usage, uint32_t format, uint32_t pool,
                           uint32_t out, uint32_t) {
        return Texture(kTexture, w, h, 1, levels, usage, format, pool, out);
    }
    uint32_t CreateVolumeTexture(uint32_t w, uint32_t h, uint32_t d, uint32_t levels, uint32_t usage, uint32_t format,
                                 uint32_t pool, uint32_t out, uint32_t) {
        return Texture(kVolumeTexture, w, h, d, levels, usage, format, pool, out);
    }
    uint32_t CreateCubeTexture(uint32_t edge, uint32_t levels, uint32_t usage, uint32_t format, uint32_t pool,
                               uint32_t out, uint32_t) {
        return Texture(kCubeTexture, edge, edge, 1, levels, usage, format, pool, out);
    }
    uint32_t Texture(Kind kind, uint32_t w, uint32_t h, uint32_t d, uint32_t levels, uint32_t usage, uint32_t format,
                     uint32_t pool, uint32_t out) {
        Resource* t = NewResource(kind, this);
        uint32_t full = 1;
        for (uint32_t m = std::max(w, h); m > 1; m >>= 1) full++;
        t->width = w, t->height = h, t->depth = d, t->levels = levels ? std::min(levels, full) : full;
        t->usage = usage, t->format = format, t->pool = pool;
        t->type = kind == kTexture ? 3 : kind == kVolumeTexture ? 4 : 5;
        *At<uint32_t>(out) = t->self;
        return D3D_OK;
    }
    uint32_t CreateBuffer(Kind kind, uint32_t length, uint32_t usage, uint32_t format, uint32_t pool, uint32_t out) {
        Resource* b = NewResource(kind, this);
        b->size = length, b->usage = usage, b->format = format, b->pool = pool, b->type = kind == kVertexBuffer ? 6 : 7;
        *At<uint32_t>(out) = b->self;
        return D3D_OK;
    }
    uint32_t CreateVertexBuffer(uint32_t length, uint32_t usage, uint32_t fvf, uint32_t pool, uint32_t out, uint32_t) {
        return CreateBuffer(kVertexBuffer, length, usage, fvf, pool, out);
    }
    uint32_t CreateIndexBuffer(uint32_t length, uint32_t usage, uint32_t format, uint32_t pool, uint32_t out, uint32_t) {
        return CreateBuffer(kIndexBuffer, length, usage, format, pool, out);
    }
    uint32_t Surface(uint32_t w, uint32_t h, uint32_t format, uint32_t usage, uint32_t pool, uint32_t out) {
        Resource* s = NewResource(kSurface, this);
        s->width = w, s->height = h, s->format = format, s->usage = usage, s->pool = pool, s->type = 1;
        *At<uint32_t>(out) = s->self;
        return D3D_OK;
    }
    uint32_t CreateRenderTarget(uint32_t w, uint32_t h, uint32_t format, uint32_t, uint32_t, uint32_t, uint32_t out, uint32_t) {
        return Surface(w, h, format, 1, 0, out);
    }
    uint32_t CreateDepthStencilSurface(uint32_t w, uint32_t h, uint32_t format, uint32_t, uint32_t, uint32_t, uint32_t out,
                                       uint32_t) {
        return Surface(w, h, format, 2, 0, out);
    }
    uint32_t CreateOffscreenPlainSurface(uint32_t w, uint32_t h, uint32_t format, uint32_t pool, uint32_t out, uint32_t) {
        return Surface(w, h, format, 0, pool, out);
    }
    uint32_t SetRenderTarget(uint32_t index, uint32_t surface) {
        if (index < 4) renderTargets[index] = surface;
        return D3D_OK;
    }
    uint32_t GetRenderTarget(uint32_t index, uint32_t out) {
        uint32_t s = index < 4 ? renderTargets[index] : 0;
        if (s)
            if (auto r = As<Resource>(s)) r->AddRef();
        *At<uint32_t>(out) = s;
        return s ? D3D_OK : 0x8876086Fu;   // D3DERR_NOTFOUND
    }
    uint32_t SetDepthStencilSurface(uint32_t s) { return depthStencil = s, D3D_OK; }
    uint32_t GetDepthStencilSurface(uint32_t out) {
        if (depthStencil)
            if (auto r = As<Resource>(depthStencil)) r->AddRef();
        *At<uint32_t>(out) = depthStencil;
        return depthStencil ? D3D_OK : 0x8876086Fu;
    }
    uint32_t SetRenderState(uint32_t state, uint32_t value) {
        if (state < 256) renderStates[state] = value;
        return D3D_OK;
    }
    uint32_t GetRenderState(uint32_t state, uint32_t out) {
        *At<uint32_t>(out) = state < 256 ? renderStates[state] : 0;
        return D3D_OK;
    }
    uint32_t CreateStateBlock(uint32_t, uint32_t out) {
        *At<uint32_t>(out) = NewResource(kStateBlock, this)->self;
        return D3D_OK;
    }
    uint32_t EndStateBlock(uint32_t out) { return CreateStateBlock(0, out); }
    uint32_t GetNull1(uint32_t out) {
        if (out) *At<uint32_t>(out) = 0;
        return D3D_OK;
    }
    uint32_t GetNull2(uint32_t, uint32_t out) { return GetNull1(out); }
    uint32_t ValidateDevice(uint32_t passes) {
        if (passes) *At<uint32_t>(passes) = 1;
        return D3D_OK;
    }
    // a vertex declaration's elements, D3DVERTEXELEMENT9 (8 bytes) to D3DDECL_END's Stream 0xFF
    uint32_t CreateVertexDeclaration(uint32_t elements, uint32_t out) {
        Resource* d = NewResource(kVertexDecl, this);
        uint32_t n = 0;
        while (*At<uint16_t>(elements + 8 * n) != 0xFF && n < 64) n++;
        d->blob.assign(At<uint8_t>(elements), At<uint8_t>(elements) + 8 * (n + 1));
        *At<uint32_t>(out) = d->self;
        return D3D_OK;
    }
    // a shader's function: its tokens to the end token 0x0000FFFF
    uint32_t Shader(Kind kind, uint32_t function, uint32_t out) {
        Resource* s = NewResource(kind, this);
        uint32_t n = 0;
        while (function && U32(function + 4 * n) != 0x0000FFFF && n < 65536) n++;
        if (function) s->blob.assign(At<uint8_t>(function), At<uint8_t>(function) + 4 * (n + 1));
        *At<uint32_t>(out) = s->self;
        return D3D_OK;
    }
    uint32_t CreateVertexShader(uint32_t function, uint32_t out) { return Shader(kVertexShader, function, out); }
    uint32_t CreatePixelShader(uint32_t function, uint32_t out) { return Shader(kPixelShader, function, out); }
    uint32_t CreateQuery(uint32_t type, uint32_t out) {
        if (!out) return D3D_OK;   // (a support check)
        Resource* q = NewResource(kQuery, this);
        q->type = type;
        *At<uint32_t>(out) = q->self;
        return D3D_OK;
    }
    uint32_t GetFVF(uint32_t out) { return *At<uint32_t>(out) = 0, D3D_OK; }
    uint32_t GetSoftwareVertexProcessing() { return 0; }

    static void Report(uint64_t presents) {
        Log("d3d9 (null): %llu presents; calls so far:", static_cast<unsigned long long>(presents));
        for (int k = 0; k < 119; k++)
            if (uint64_t n = g_calls[1][k].load()) Log("  device slot %3d: %llu", k, static_cast<unsigned long long>(n));
    }
};

// (each device method counted, its first call logged: what the reference asks of its renderer)
template <unsigned K>
uint32_t CountedOk(uint32_t self) {
    if (g_calls[1][K]++ == 0) Log("d3d9 (null): device slot %u first called", K);
    (void)self;
    return D3D_OK;
}
template <unsigned... K>
void FillCounted(const void** m, std::integer_sequence<unsigned, K...>) {
    ((m[K] = reinterpret_cast<const void*>(&CountedOk<K>)), ...);
}

uint32_t DeviceVtable() {
    static uint32_t v = [] {
        const void* m[119];
        FillCounted(m, std::make_integer_sequence<unsigned, 119>{});
        m[0] = M_<&Device::QueryInterface>(), m[1] = M_<&Device::AddRef_>(), m[2] = M_<&Device::Release_>();
        m[3] = M_<&Device::TestCooperativeLevel>(), m[4] = M_<&Device::GetAvailableTextureMem>();
        m[6] = M_<&Device::GetDirect3D>(), m[7] = M_<&Device::GetDeviceCaps>(), m[8] = M_<&Device::GetDisplayMode>();
        m[9] = M_<&Device::GetCreationParameters>(), m[12] = M_<&Device::ShowCursor>();
        m[13] = M_<&Device::CreateAdditionalSwapChain>(), m[14] = M_<&Device::GetSwapChain>();
        m[15] = M_<&Device::GetNumberOfSwapChains>(), m[16] = M_<&Device::Reset>(), m[17] = M_<&Device::Present>();
        m[18] = M_<&Device::GetBackBuffer>(), m[19] = M_<&Device::GetRasterStatus>();
        m[23] = M_<&Device::CreateTexture>(), m[24] = M_<&Device::CreateVolumeTexture>();
        m[25] = M_<&Device::CreateCubeTexture>(), m[26] = M_<&Device::CreateVertexBuffer>();
        m[27] = M_<&Device::CreateIndexBuffer>(), m[28] = M_<&Device::CreateRenderTarget>();
        m[29] = M_<&Device::CreateDepthStencilSurface>(), m[36] = M_<&Device::CreateOffscreenPlainSurface>();
        m[37] = M_<&Device::SetRenderTarget>(), m[38] = M_<&Device::GetRenderTarget>();
        m[39] = M_<&Device::SetDepthStencilSurface>(), m[40] = M_<&Device::GetDepthStencilSurface>();
        m[57] = M_<&Device::SetRenderState>(), m[58] = M_<&Device::GetRenderState>();
        m[59] = M_<&Device::CreateStateBlock>(), m[61] = M_<&Device::EndStateBlock>();
        m[64] = M_<&Device::GetNull2>();   // GetTexture(stage, out)
        m[70] = M_<&Device::ValidateDevice>(), m[78] = M_<&Device::GetSoftwareVertexProcessing>();
        m[86] = M_<&Device::CreateVertexDeclaration>(), m[88] = M_<&Device::GetNull1>();   // GetVertexDeclaration
        m[90] = M_<&Device::GetFVF>(), m[91] = M_<&Device::CreateVertexShader>(), m[93] = M_<&Device::GetNull1>();
        m[105] = M_<&Device::GetNull1>(), m[106] = M_<&Device::CreatePixelShader>(), m[108] = M_<&Device::GetNull1>();
        m[118] = M_<&Device::CreateQuery>();
        return Vtable(m, 119);
    }();
    return v;
}

uint32_t Resource::GetDevice(uint32_t out) {
    device->AddRef();
    *At<uint32_t>(out) = device->self;
    return D3D_OK;
}
uint32_t Resource::ScPresent(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t) { return device->Present(a, b, c, d); }
uint32_t Resource::ScGetBackBuffer(uint32_t i, uint32_t t, uint32_t out) { return device->GetBackBuffer(0, i, t, out); }
uint32_t Resource::ScGetDisplayMode(uint32_t out) { return device->GetDisplayMode(0, out); }
uint32_t Resource::ScGetPresentParameters(uint32_t out) {
    *At<PresentParams32>(out) = device->pp;
    return D3D_OK;
}

// ---- IDirect3D9 -----------------------------------------------------------------------------------
struct D3D9 : Refcounted {
    uint32_t QueryInterface(uint32_t, uint32_t out) {
        AddRef();
        *At<uint32_t>(out) = self;
        return D3D_OK;
    }
    uint32_t AddRef_() { return AddRef(); }
    uint32_t Release_() { return Release(); }
    uint32_t Ok() { return D3D_OK; }
    uint32_t GetAdapterCount() { return 1; }
    // D3DADAPTER_IDENTIFIER9 (1,100 bytes): Driver[512], Description[512], DeviceName[32], the
    // driver version, ids, the GUID, WHQL level
    uint32_t GetAdapterIdentifier(uint32_t adapter, uint32_t, uint32_t out) {
        if (adapter) return D3DERR_INVALIDCALL;
        memset(At(out), 0, 1100);
        strcpy(At<char>(out), "rhipper");
        strcpy(At<char>(out + 512), "Rhipper null renderer");
        strcpy(At<char>(out + 1024), "\\\\.\\DISPLAY1");
        *At<uint32_t>(out + 1056) = 0x10DE;   // VendorId: a common one, so a vendor check passes
        *At<uint32_t>(out + 1060) = 0x0DE1;
        return D3D_OK;
    }
    uint32_t GetAdapterModeCount(uint32_t, uint32_t) { return 1; }
    // D3DDISPLAYMODE: Width, Height, RefreshRate, Format
    uint32_t Mode(uint32_t out) {
        int w = 1920, h = 1080;
        if (void* win = rhipper_window_use(&w, &h)) rhipper_window_done(win);
        uint32_t m[4] = {static_cast<uint32_t>(w), static_cast<uint32_t>(h), 60, 22};
        memcpy(At(out), m, sizeof m);
        return D3D_OK;
    }
    uint32_t EnumAdapterModes(uint32_t, uint32_t, uint32_t, uint32_t out) { return Mode(out); }
    uint32_t GetAdapterDisplayMode(uint32_t, uint32_t out) { return Mode(out); }
    uint32_t GetDeviceCaps(uint32_t, uint32_t, uint32_t out);
    uint32_t GetAdapterMonitor(uint32_t) { return 0x00030000; }
    uint32_t CreateDevice(uint32_t adapter, uint32_t type, uint32_t focus, uint32_t behavior, uint32_t pp, uint32_t out) {
        auto d = new Device();
        d->d3d = this;
        d->d3dObj = self;
        d->adapter = adapter, d->deviceType = type, d->focus = focus, d->behavior = behavior;
        d->pp = *At<PresentParams32>(pp);
        if (!d->pp.BackBufferWidth || !d->pp.BackBufferHeight) {
            d->pp.BackBufferWidth = 1280, d->pp.BackBufferHeight = 720;
            *At<PresentParams32>(pp) = d->pp;
        }
        d->self = NewObject(DeviceVtable(), d);
        d->MakeBuffers();
        AddRef();
        *At<uint32_t>(out) = d->self;
        Log("d3d9 (null): CreateDevice %ux%u format %u, windowed %u, behavior %#x: nothing is drawn",
            d->pp.BackBufferWidth, d->pp.BackBufferHeight, d->pp.BackBufferFormat, d->pp.Windowed, behavior);
        // (Direct3D 9 sets the x87 unit to 24-bit precision unless asked to keep it: Com32.cpp)
        if (!(behavior & 2 /* D3DCREATE_FPU_PRESERVE */)) gen_set_x87_cw(0x007f);
        return D3D_OK;
    }
};

// D3DCAPS9 (304 bytes): a Shader Model 3 card's essentials
void FillCaps(uint32_t out) {
    auto c = At<uint32_t>(out);
    memset(c, 0, 304);
    c[0] = 1;                    // DeviceType: HAL
    c[3] = 0x20000;              // Caps2: D3DCAPS2_DYNAMICTEXTURES
    c[5] = 0x80000000u | 0x20;   // PresentationIntervals: IMMEDIATE | ONE
    c[7] = 0x40 | 0x400 | 0x10000 | 0x80000 | 0x200000;   // DevCaps: HW T&L, pure device, ...
    c[8] = 0x7FFFFFFF;           // PrimitiveMiscCaps
    c[9] = 0x7FFFFFFF;           // RasterCaps
    c[10] = c[11] = 0xFF;        // ZCmpCaps, SrcBlendCaps
    c[12] = 0x1FFF;              // DestBlendCaps
    c[13] = 0xFF;                // AlphaCmpCaps
    c[15] = 0x7FFF;              // TextureCaps
    c[16] = c[17] = c[18] = 0x7FFFFFFF;   // filter caps
    c[19] = 0x3F;                // TextureAddressCaps
    c[22] = c[23] = 8192;        // MaxTextureWidth, Height
    c[24] = 2048;                // MaxVolumeExtent
    c[25] = 8192;                // MaxTextureRepeat
    c[26] = 8192;                // MaxTextureAspectRatio
    c[27] = 16;                  // MaxAnisotropy
    c[36] = 0x1FF;               // StencilCaps
    c[37] = 0xFFFFF;             // FVFCaps (8 texture coordinate sets)
    c[38] = 0x3FFFFFF;           // TextureOpCaps
    c[39] = 8;                   // MaxTextureBlendStages
    c[40] = 8;                   // MaxSimultaneousTextures
    c[41] = 0x3FF;               // VertexProcessingCaps
    c[42] = 8;                   // MaxActiveLights
    c[43] = 6;                   // MaxUserClipPlanes
    c[44] = 4;                   // MaxVertexBlendMatrices
    c[45] = 0;
    float pointSize = 8192.0f;
    memcpy(&c[46], &pointSize, 4);
    c[47] = 0xFFFFFF;            // MaxPrimitiveCount
    c[48] = 0xFFFFFF;            // MaxVertexIndex
    c[49] = 16;                  // MaxStreams
    c[50] = 255;                 // MaxStreamStride
    c[51] = 0xFFFE0300;          // VertexShaderVersion 3.0
    c[52] = 256;                 // MaxVertexShaderConst
    c[53] = 0xFFFF0300;          // PixelShaderVersion 3.0
    float maxValue = 65504.0f;
    memcpy(&c[54], &maxValue, 4);
    c[55] = 0x3;                 // DevCaps2
    c[60] = 4;                   // NumSimultaneousRTs
    c[61] = 0x3FF;               // StretchRectFilterCaps
    c[62] = 1, c[63] = 24, c[64] = 32, c[65] = 4;   // VS20Caps
    c[66] = 0xFFFFFFFF, c[67] = 24, c[68] = 32, c[69] = 4, c[70] = 512;   // PS20Caps
    c[71] = 0x300;               // VertexTextureFilterCaps
    c[72] = c[73] = 32768;       // MaxVShaderInstructionsExecuted, MaxPShaderInstructionsExecuted
    c[74] = c[75] = 32768;       // MaxVertexShader30InstructionSlots, MaxPixelShader30InstructionSlots
}
uint32_t Device::GetDeviceCaps(uint32_t out) { return FillCaps(out), D3D_OK; }
uint32_t D3D9::GetDeviceCaps(uint32_t, uint32_t, uint32_t out) { return FillCaps(out), D3D_OK; }
uint32_t Device::GetDirect3D(uint32_t out) {
    d3d->AddRef();
    *At<uint32_t>(out) = d3dObj;
    return D3D_OK;
}

uint32_t D3D9Vtable() {
    static uint32_t v = [] {
        const void* m[17] = {
            M_<&D3D9::QueryInterface>(), M_<&D3D9::AddRef_>(), M_<&D3D9::Release_>(),
            M_<&D3D9::Ok>(),                       // RegisterSoftwareDevice
            M_<&D3D9::GetAdapterCount>(), M_<&D3D9::GetAdapterIdentifier>(), M_<&D3D9::GetAdapterModeCount>(),
            M_<&D3D9::EnumAdapterModes>(), M_<&D3D9::GetAdapterDisplayMode>(),
            M_<&D3D9::Ok>(), M_<&D3D9::Ok>(), M_<&D3D9::Ok>(), M_<&D3D9::Ok>(), M_<&D3D9::Ok>(),   // the Check*s: all supported
            M_<&D3D9::GetDeviceCaps>(), M_<&D3D9::GetAdapterMonitor>(), M_<&D3D9::CreateDevice>()};
        return Vtable(m, 17);
    }();
    return v;
}

}  // namespace

uint32_t NullDirect3DCreate9(uint32_t sdk) {
    auto d = new D3D9();
    d->self = NewObject(D3D9Vtable(), d);
    Log("Direct3DCreate9(%u): the null renderer (no project renderer registered)", sdk);
    return d->self;
}

}  // namespace rh

// d3d9's other export, and d3dx9's screenshot savers: nothing to save from a null renderer
static uint32_t D3DPERF_SetOptions_(uint32_t) { return 0; }
RH_REG(d3d9, D3DPERF_SetOptions, D3DPERF_SetOptions_)
RH_STUB(d3dx9_43, D3DXSaveSurfaceToFileA, 5, win::E_FAIL, 0)
RH_STUB(d3dx9_43, D3DXSaveSurfaceToFileW, 5, win::E_FAIL, 0)
RH_STUB(d3dx9_43, D3DXSaveTextureToFileA, 4, win::E_FAIL, 0)
