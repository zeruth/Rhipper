// d3d9vk: Direct3D 9 on Vulkan for the Android runtime, the declarations its files share.
//
// The reference's IDirect3D9, IDirect3DDevice9 and their resources are x86 COM objects (Com32Posix.h)
// whose native side is here:
//
//   Device.cpp         Vulkan's instance and device, IDirect3D9, the device's state and its setters,
//                      submissions, Present to the host's surface
//   Draw.cpp           the draw path: render passes, clears, descriptors, the draws, copies between
//                      surfaces, readbacks
//   Pipeline.cpp       pipelines by state, the render and sampler states in Vulkan's terms, samplers
//   Image.cpp          device memory, images and their layouts, the per-submission upload ring
//   VkResources.cpp    textures, surfaces, buffers, queries, declarations, shaders, state blocks and
//                      swap chains: their vtables and locks
//   Formats.cpp        D3DFORMAT to VkFormat, and the CPU conversions where Vulkan has no equal
//   FixedFunction.cpp  the fixed-function vertex and pixel shaders (SPIR-V made here) for FVF draws
//   Shader.cpp         (the shader translator, Shader.h: another file's)
//
// The model: one command buffer recorded as the reference calls, submitted per Present (and when a
// query or a readback needs the GPU's answer), kSlots submissions in flight. A submission is a serial;
// what the GPU may still read (an image, a buffer, a ring chunk) is freed once its serial completes.
// Uploads to a resource the current submission has not used go to a second command buffer that runs
// first (no render pass broken); to one it has used, inline in the main one.
//
// Everything is guarded by the device's lock (the reference's device is MULTITHREADED: its loader
// threads lock and fill textures while its render thread draws).
#pragma once

#ifndef VK_USE_PLATFORM_ANDROID_KHR
#define VK_USE_PLATFORM_ANDROID_KHR 1
#endif
#include <vulkan/vulkan.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <bitset>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "Com32Posix.h"
#include "Shader.h"

namespace rh::d3d9vk {

using com::As;
using com::FreeObject;
using com::M_;
using com::NewObject;
using com::Vtable;

// ---- Direct3D 9's numbers ---------------------------------------------------------------------------
constexpr uint32_t D3D_OK = 0, S_FALSE = 1;
constexpr uint32_t D3DERR_NOTFOUND = 0x88760866u, D3DERR_DEVICELOST = 0x88760868u,
                   D3DERR_NOTAVAILABLE = 0x8876086Au, D3DERR_INVALIDCALL = 0x8876086Cu,
                   D3DERR_WASSTILLDRAWING = 0x8876021Cu, D3DERR_OUTOFVIDEOMEMORY = 0x8876017Cu,
                   D3DOK_NOAUTOGEN = 0x0876086Fu;

constexpr uint32_t FourCC(char a, char b, char c, char d) {
    return uint32_t(uint8_t(a)) | uint32_t(uint8_t(b)) << 8 | uint32_t(uint8_t(c)) << 16 | uint32_t(uint8_t(d)) << 24;
}
enum : uint32_t {
    F_UNKNOWN = 0, F_R8G8B8 = 20, F_A8R8G8B8 = 21, F_X8R8G8B8 = 22, F_R5G6B5 = 23, F_X1R5G5B5 = 24,
    F_A1R5G5B5 = 25, F_A4R4G4B4 = 26, F_R3G3B2 = 27, F_A8 = 28, F_A8R3G3B2 = 29, F_X4R4G4B4 = 30,
    F_A2B10G10R10 = 31, F_A8B8G8R8 = 32, F_X8B8G8R8 = 33, F_G16R16 = 34, F_A2R10G10B10 = 35,
    F_A16B16G16R16 = 36, F_L8 = 50, F_A8L8 = 51, F_A4L4 = 52, F_V8U8 = 60, F_Q8W8V8U8 = 63, F_V16U16 = 64,
    F_D16_LOCKABLE = 70, F_D32 = 71, F_D15S1 = 73, F_D24S8 = 75, F_D24X8 = 77, F_D24X4S4 = 79, F_D16 = 80,
    F_L16 = 81, F_D32F_LOCKABLE = 82, F_D24FS8 = 83, F_VERTEXDATA = 100, F_INDEX16 = 101, F_INDEX32 = 102,
    F_R16F = 111, F_G16R16F = 112, F_A16B16G16R16F = 113, F_R32F = 114, F_G32R32F = 115,
    F_A32B32G32R32F = 116,
    F_DXT1 = FourCC('D', 'X', 'T', '1'), F_DXT2 = FourCC('D', 'X', 'T', '2'), F_DXT3 = FourCC('D', 'X', 'T', '3'),
    F_DXT4 = FourCC('D', 'X', 'T', '4'), F_DXT5 = FourCC('D', 'X', 'T', '5'), F_INTZ = FourCC('I', 'N', 'T', 'Z'),
    F_NULL = FourCC('N', 'U', 'L', 'L'), F_RAWZ = FourCC('R', 'A', 'W', 'Z'), F_DF24 = FourCC('D', 'F', '2', '4'),
    F_DF16 = FourCC('D', 'F', '1', '6'),
};
// usage, pools, locks, resource types
enum : uint32_t {
    U_RENDERTARGET = 1, U_DEPTHSTENCIL = 2, U_WRITEONLY = 8, U_DYNAMIC = 0x200, U_AUTOGENMIPMAP = 0x400,
    U_QUERY_SRGBREAD = 0x10000, U_QUERY_FILTER = 0x20000, U_QUERY_SRGBWRITE = 0x40000,
    U_QUERY_POSTPIXELSHADER_BLENDING = 0x80000, U_QUERY_VERTEXTEXTURE = 0x100000, U_QUERY_WRAPANDMIP = 0x200000,
    POOL_DEFAULT = 0, POOL_MANAGED = 1, POOL_SYSTEMMEM = 2, POOL_SCRATCH = 3,
    LOCK_READONLY = 0x10, LOCK_NOOVERWRITE = 0x1000, LOCK_DISCARD = 0x2000, LOCK_DONOTWAIT = 0x4000,
    RT_SURFACE = 1, RT_VOLUME = 2, RT_TEXTURE = 3, RT_VOLUMETEXTURE = 4, RT_CUBETEXTURE = 5,
    RT_VERTEXBUFFER = 6, RT_INDEXBUFFER = 7,
};
// render states (D3DRENDERSTATETYPE)
enum : uint32_t {
    RS_ZENABLE = 7, RS_FILLMODE = 8, RS_SHADEMODE = 9, RS_ZWRITEENABLE = 14, RS_ALPHATESTENABLE = 15,
    RS_LASTPIXEL = 16, RS_SRCBLEND = 19, RS_DESTBLEND = 20, RS_CULLMODE = 22, RS_ZFUNC = 23, RS_ALPHAREF = 24,
    RS_ALPHAFUNC = 25, RS_DITHERENABLE = 26, RS_ALPHABLENDENABLE = 27, RS_FOGENABLE = 28,
    RS_SPECULARENABLE = 29, RS_FOGCOLOR = 34, RS_FOGTABLEMODE = 35, RS_FOGSTART = 36, RS_FOGEND = 37,
    RS_FOGDENSITY = 38, RS_RANGEFOGENABLE = 48, RS_STENCILENABLE = 52, RS_STENCILFAIL = 53,
    RS_STENCILZFAIL = 54, RS_STENCILPASS = 55, RS_STENCILFUNC = 56, RS_STENCILREF = 57, RS_STENCILMASK = 58,
    RS_STENCILWRITEMASK = 59, RS_TEXTUREFACTOR = 60, RS_CLIPPING = 136, RS_LIGHTING = 137, RS_AMBIENT = 139,
    RS_FOGVERTEXMODE = 140, RS_COLORVERTEX = 141, RS_LOCALVIEWER = 142, RS_NORMALIZENORMALS = 143,
    RS_DIFFUSEMATERIALSOURCE = 145, RS_SPECULARMATERIALSOURCE = 146, RS_AMBIENTMATERIALSOURCE = 147,
    RS_EMISSIVEMATERIALSOURCE = 148, RS_VERTEXBLEND = 151, RS_CLIPPLANEENABLE = 152, RS_POINTSIZE = 154,
    RS_POINTSIZE_MIN = 155, RS_POINTSPRITEENABLE = 156, RS_POINTSCALEENABLE = 157, RS_POINTSCALE_A = 158,
    RS_POINTSCALE_B = 159, RS_POINTSCALE_C = 160, RS_MULTISAMPLEANTIALIAS = 161, RS_MULTISAMPLEMASK = 162,
    RS_PATCHEDGESTYLE = 163, RS_DEBUGMONITORTOKEN = 165, RS_POINTSIZE_MAX = 166,
    RS_INDEXEDVERTEXBLENDENABLE = 167, RS_COLORWRITEENABLE = 168, RS_TWEENFACTOR = 170, RS_BLENDOP = 171,
    RS_POSITIONDEGREE = 172, RS_NORMALDEGREE = 173, RS_SCISSORTESTENABLE = 174, RS_SLOPESCALEDEPTHBIAS = 175,
    RS_ANTIALIASEDLINEENABLE = 176, RS_MINTESSELLATIONLEVEL = 178, RS_MAXTESSELLATIONLEVEL = 179,
    RS_ADAPTIVETESS_X = 180, RS_ADAPTIVETESS_Y = 181, RS_ADAPTIVETESS_Z = 182, RS_ADAPTIVETESS_W = 183,
    RS_ENABLEADAPTIVETESSELLATION = 184, RS_TWOSIDEDSTENCILMODE = 185, RS_CCW_STENCILFAIL = 186,
    RS_CCW_STENCILZFAIL = 187, RS_CCW_STENCILPASS = 188, RS_CCW_STENCILFUNC = 189,
    RS_COLORWRITEENABLE1 = 190, RS_COLORWRITEENABLE2 = 191, RS_COLORWRITEENABLE3 = 192, RS_BLENDFACTOR = 193,
    RS_SRGBWRITEENABLE = 194, RS_DEPTHBIAS = 195, RS_SEPARATEALPHABLENDENABLE = 206, RS_SRCBLENDALPHA = 207,
    RS_DESTBLENDALPHA = 208, RS_BLENDOPALPHA = 209,
};
// sampler states (D3DSAMPLERSTATETYPE), texture stage states (D3DTEXTURESTAGESTATETYPE)
enum : uint32_t {
    SS_ADDRESSU = 1, SS_ADDRESSV = 2, SS_ADDRESSW = 3, SS_BORDERCOLOR = 4, SS_MAGFILTER = 5, SS_MINFILTER = 6,
    SS_MIPFILTER = 7, SS_MIPMAPLODBIAS = 8, SS_MAXMIPLEVEL = 9, SS_MAXANISOTROPY = 10, SS_SRGBTEXTURE = 11,
    SS_ELEMENTINDEX = 12, SS_DMAPOFFSET = 13, kSamplerStates = 14,
    TSS_COLOROP = 1, TSS_COLORARG1 = 2, TSS_COLORARG2 = 3, TSS_ALPHAOP = 4, TSS_ALPHAARG1 = 5,
    TSS_ALPHAARG2 = 6, TSS_TEXCOORDINDEX = 11, TSS_TEXTURETRANSFORMFLAGS = 24, TSS_COLORARG0 = 26,
    TSS_ALPHAARG0 = 27, TSS_RESULTARG = 28, TSS_CONSTANT = 32, kStageStates = 33,
};
// FVF bits
enum : uint32_t {
    FVF_XYZ = 0x2, FVF_XYZRHW = 0x4, FVF_XYZW = 0x4002, FVF_POSITION_MASK = 0x400E, FVF_NORMAL = 0x10,
    FVF_PSIZE = 0x20, FVF_DIFFUSE = 0x40, FVF_SPECULAR = 0x80, FVF_TEXCOUNT_MASK = 0xF00,
    FVF_LASTBETA_UBYTE4 = 0x1000, FVF_LASTBETA_D3DCOLOR = 0x8000,
};
// D3DDECLUSAGE, D3DDECLTYPE
enum : uint8_t {
    DU_POSITION = 0, DU_BLENDWEIGHT = 1, DU_BLENDINDICES = 2, DU_NORMAL = 3, DU_PSIZE = 4, DU_TEXCOORD = 5,
    DU_TANGENT = 6, DU_BINORMAL = 7, DU_TESSFACTOR = 8, DU_POSITIONT = 9, DU_COLOR = 10, DU_FOG = 11,
    DU_DEPTH = 12, DU_SAMPLE = 13,
    DT_FLOAT1 = 0, DT_FLOAT2 = 1, DT_FLOAT3 = 2, DT_FLOAT4 = 3, DT_D3DCOLOR = 4, DT_UBYTE4 = 5, DT_SHORT2 = 6,
    DT_SHORT4 = 7, DT_UBYTE4N = 8, DT_SHORT2N = 9, DT_SHORT4N = 10, DT_USHORT2N = 11, DT_USHORT4N = 12,
    DT_UDEC3 = 13, DT_DEC3N = 14, DT_FLOAT16_2 = 15, DT_FLOAT16_4 = 16, DT_UNUSED = 17,
};

#pragma pack(push, 4)
struct PresentParams32 {
    uint32_t BackBufferWidth, BackBufferHeight, BackBufferFormat, BackBufferCount, MultiSampleType,
        MultiSampleQuality, SwapEffect, hDeviceWindow, Windowed, EnableAutoDepthStencil, AutoDepthStencilFormat,
        Flags, FullScreen_RefreshRateInHz, PresentationInterval;
};
struct Element32 {   // D3DVERTEXELEMENT9
    uint16_t stream, offset;
    uint8_t type, method, usage, usageIndex;
};
#pragma pack(pop)
static_assert(sizeof(PresentParams32) == 56, "D3DPRESENT_PARAMETERS, x86");
static_assert(sizeof(Element32) == 8, "D3DVERTEXELEMENT9");

struct Rect {
    int32_t left = 0, top = 0, right = 0, bottom = 0;
};
inline Rect RectAt(uint32_t p) {
    Rect r;
    memcpy(&r, At(p), 16);
    return r;
}
inline float AsFloat(uint32_t v) {
    float f;
    memcpy(&f, &v, 4);
    return f;
}
inline uint32_t FloatBits(float f) {
    uint32_t v;
    memcpy(&v, &f, 4);
    return v;
}

// ---- formats (Formats.cpp) ------------------------------------------------------------------------
// D3D side texels in, Vulkan side texels out: a region w x h in pixels, rows at the given pitches
using Convert = void (*)(const uint8_t* src, uint32_t srcPitch, uint8_t* dst, uint32_t dstPitch, uint32_t w, uint32_t h);

struct FormatInfo {
    uint32_t d3d = 0;
    VkFormat vk = VK_FORMAT_UNDEFINED;     // what the image holds
    VkFormat srgb = VK_FORMAT_UNDEFINED;   // its sRGB view (SRGBTEXTURE, SRGBWRITEENABLE), if any
    VkComponentMapping swizzle = {VK_COMPONENT_SWIZZLE_IDENTITY, VK_COMPONENT_SWIZZLE_IDENTITY,
                                  VK_COMPONENT_SWIZZLE_IDENTITY, VK_COMPONENT_SWIZZLE_IDENTITY};
    uint8_t blockW = 1, blockH = 1;        // the D3D side's block (4x4 for DXTn)
    uint8_t bytes = 4;                     // D3D bytes per block
    uint8_t vkBytes = 4;                   // Vulkan bytes per block (vkBlock) or per texel
    bool vkBlock = false;                  // the image is block-compressed too
    Convert convert = nullptr;             // D3D to Vulkan (nullptr: the same bytes)
    bool depth = false, stencil = false;
    bool null = false;                     // the NULL render target: no image at all
    bool alphaOne = false;                 // an X format: destination alpha reads as one
    // what Vulkan does with vk (optimal tiling)
    bool sampled = false, filter = false, color = false, blend = false, ds = false, blit = false;
};
void InitFormats(VkPhysicalDevice phys, bool bc);
const FormatInfo* LookupFormat(uint32_t d3d);   // nullptr: not supported
const char* FormatName(uint32_t d3d);
// CheckDeviceFormat's answer
uint32_t CheckFormat(uint32_t usage, uint32_t rtype, uint32_t format);

// ---- the Vulkan instance and adapter (Device.cpp) ------------------------------------------------------
struct Fns {
    PFN_vkCmdBeginRendering CmdBeginRendering = nullptr;
    PFN_vkCmdEndRendering CmdEndRendering = nullptr;
    PFN_vkCmdSetCullMode CmdSetCullMode = nullptr;
    PFN_vkCmdSetFrontFace CmdSetFrontFace = nullptr;
    PFN_vkCmdSetPrimitiveTopology CmdSetPrimitiveTopology = nullptr;
    PFN_vkCmdSetDepthTestEnable CmdSetDepthTestEnable = nullptr;
    PFN_vkCmdSetDepthWriteEnable CmdSetDepthWriteEnable = nullptr;
    PFN_vkCmdSetDepthCompareOp CmdSetDepthCompareOp = nullptr;
    PFN_vkCmdSetStencilTestEnable CmdSetStencilTestEnable = nullptr;
    PFN_vkCmdSetStencilOp CmdSetStencilOp = nullptr;
    PFN_vkCmdSetDepthBiasEnable CmdSetDepthBiasEnable = nullptr;
    PFN_vkCmdBindVertexBuffers2 CmdBindVertexBuffers2 = nullptr;
    PFN_vkCmdPushDescriptorSetKHR CmdPushDescriptorSet = nullptr;
    PFN_vkResetQueryPool ResetQueryPool = nullptr;
};

struct Vulkan {
    VkInstance instance = VK_NULL_HANDLE;
    VkPhysicalDevice phys = VK_NULL_HANDLE;
    VkPhysicalDeviceProperties props{};
    VkPhysicalDeviceFeatures features{};
    VkPhysicalDeviceMemoryProperties memProps{};
    uint32_t family = 0;
    bool pushDescriptorExt = false, hostQueryReset = false, a4r4g4b4 = false;
};
Vulkan* GetVulkan();   // made once; nullptr when there is no usable Vulkan 1.3

// ---- device memory and images (Image.cpp) ----------------------------------------------------------
struct Block;
struct Alloc {
    VkDeviceMemory memory = VK_NULL_HANDLE;
    VkDeviceSize offset = 0, size = 0;
    uint8_t* mapped = nullptr;   // persistently mapped (host visible), at offset
    Block* block = nullptr;
};

class MemAllocator {
public:
    MemAllocator(VkDevice dev, const VkPhysicalDeviceMemoryProperties& props) : dev_(dev), props_(props) {}
    // `want` must all be there; `prefer` is tried first
    bool Allocate(const VkMemoryRequirements& req, VkMemoryPropertyFlags want, VkMemoryPropertyFlags prefer,
                  bool linear, Alloc* out);
    void Free(Alloc& a);
    VkDeviceSize Used() const { return used_; }

private:
    int TypeFor(uint32_t bits, VkMemoryPropertyFlags want) const;
    VkDevice dev_;
    VkPhysicalDeviceMemoryProperties props_;
    std::vector<Block*> blocks_;
    VkDeviceSize used_ = 0;
};

struct Image {
    VkImage image = VK_NULL_HANDLE;
    Alloc mem;
    const FormatInfo* fmt = nullptr;
    VkFormat format = VK_FORMAT_UNDEFINED;
    VkImageViewType viewType = VK_IMAGE_VIEW_TYPE_2D;
    uint32_t width = 1, height = 1, depth = 1, levels = 1, layers = 1;
    VkImageAspectFlags aspect = VK_IMAGE_ASPECT_COLOR_BIT;
    VkImageUsageFlags usage = 0;
    bool general = false;            // sampled while bound as a target: every use in GENERAL
    std::vector<VkImageLayout> layouts;   // per subresource: layer * levels + level
    VkImageView sampled = VK_NULL_HANDLE, sampledSrgb = VK_NULL_HANDLE;
    std::vector<VkImageView> targets;     // 2 per subresource: [2 * sub + srgb]
    uint64_t lastUse = 0;            // the last submission that read or wrote it

    uint32_t Sub(uint32_t level, uint32_t layer) const { return layer * levels + level; }
    uint32_t W(uint32_t level) const { return std::max(1u, width >> level); }
    uint32_t H(uint32_t level) const { return std::max(1u, height >> level); }
    uint32_t D(uint32_t level) const { return std::max(1u, depth >> level); }
};

// a host-visible slice of the current submission's upload ring
struct RingSlice {
    VkBuffer buffer = VK_NULL_HANDLE;
    VkDeviceSize offset = 0;
    uint8_t* ptr = nullptr;
};
struct Chunk {
    VkBuffer buffer = VK_NULL_HANDLE;
    Alloc mem;
    VkDeviceSize size = 0, used = 0;
};

// ---- objects ---------------------------------------------------------------------------------------
struct Device;
struct Texture;

// what every object the device makes has: the reference's count, the device's own holds (a bound or
// captured object lives on, as Direct3D 9's do, until unbound), IDirect3DResource9's common methods
struct Base {
    uint32_t self = 0;
    Device* dev = nullptr;
    int refs = 1;    // the reference's (AddRef / Release), under the device's lock
    int binds = 0;   // the device's and state blocks'
    uint32_t priority = 0;
    std::map<std::string, std::vector<uint8_t>> privateData;
    virtual ~Base() = default;

    virtual void Bind();
    virtual void Unbind();
    void MaybeDestroy();

    uint32_t QueryInterface(uint32_t riid, uint32_t out);
    virtual uint32_t AddRef_();
    virtual uint32_t Release_();
    uint32_t GetDevice(uint32_t out);
    uint32_t SetPrivateData(uint32_t guid, uint32_t data, uint32_t size, uint32_t flags);
    uint32_t GetPrivateData(uint32_t guid, uint32_t data, uint32_t sizeInOut);
    uint32_t FreePrivateData(uint32_t guid);
    uint32_t SetPriority(uint32_t p);
    uint32_t GetPriority();
    uint32_t PreLoad();
};
// hold `next` in `slot` for the device (Bind), letting go of what was there
template <typename T>
void Hold(T*& slot, T* next) {
    if (slot == next) return;
    if (next) next->Bind();
    T* old = slot;
    slot = next;
    if (old) old->Unbind();
}

// a level or face's CPU side: its lock
struct Sub {
    uint32_t mem = 0, size = 0;   // low memory, the reference's pointer
    bool locked = false;
    uint32_t flags = 0;
    uint32_t x = 0, y = 0, z = 0, w = 0, h = 0, d = 0;   // the locked region, texels
};

// a texture's or a standalone surface's contents: the image, and the CPU side of its locks
struct Storage {
    Device* dev = nullptr;
    const FormatInfo* fmt = nullptr;
    uint32_t format = 0, usage = 0, pool = 0, rtype = RT_TEXTURE;
    uint32_t width = 1, height = 1, depth = 1, levels = 1, layers = 1;
    Image* img = nullptr;   // nullptr: CPU only (SYSTEMMEM, SCRATCH) or the NULL format
    bool cpuOnly = false;
    bool mipsDirty = false;
    std::vector<Sub> subs;

    uint32_t W(uint32_t l) const { return std::max(1u, width >> l); }
    uint32_t H(uint32_t l) const { return std::max(1u, height >> l); }
    uint32_t D(uint32_t l) const { return std::max(1u, depth >> l); }
    uint32_t Pitch(uint32_t l) const { return (W(l) + fmt->blockW - 1) / fmt->blockW * fmt->bytes; }
    uint32_t Rows(uint32_t l) const { return (H(l) + fmt->blockH - 1) / fmt->blockH; }
    uint32_t SubSize(uint32_t l) const { return Pitch(l) * Rows(l) * D(l); }
    Sub& SubAt(uint32_t level, uint32_t layer) { return subs[layer * levels + level]; }
    // the CPU memory of a CPU-only level, made on first use
    uint32_t CpuMem(uint32_t level, uint32_t layer);

    uint32_t Lock(uint32_t level, uint32_t layer, uint32_t region, bool box, uint32_t out, uint32_t flags);
    uint32_t Unlock(uint32_t level, uint32_t layer);
    void Release();
};

struct Surface : Base {
    Texture* container = nullptr;   // a texture's level or face (its counts are the texture's)
    uint32_t level = 0, layer = 0;
    Storage own;                    // a standalone surface's
    Storage* st = nullptr;          // own, or the container's

    ~Surface() override;
    void Bind() override;
    void Unbind() override;
    uint32_t AddRef_() override;
    uint32_t Release_() override;
    Image* Img() const { return st->img; }
    uint32_t W() const { return st->W(level); }
    uint32_t H() const { return st->H(level); }
    const FormatInfo* Fmt() const { return st->fmt; }

    uint32_t GetType();
    uint32_t GetContainer(uint32_t riid, uint32_t out);
    uint32_t GetDesc(uint32_t out);
    uint32_t LockRect(uint32_t locked, uint32_t rect, uint32_t flags);
    uint32_t UnlockRect();
    uint32_t GetDC(uint32_t out);
    uint32_t ReleaseDC(uint32_t dc);
};

struct Volume;
struct Texture : Base {
    Storage st;
    uint32_t apiLevels = 1;   // GetLevelCount (1 for an AUTOGENMIPMAP texture: its chain is the device's)
    uint32_t lod = 0, autoGenFilter = 2;
    std::vector<Surface*> surfaces;   // per subresource, made on demand
    std::vector<Volume*> volumes;

    ~Texture() override;
    uint32_t Kind() const { return st.rtype; }
    Surface* SurfaceOf(uint32_t level, uint32_t layer);

    uint32_t GetType();
    uint32_t SetLOD(uint32_t l);
    uint32_t GetLOD();
    uint32_t GetLevelCount();
    uint32_t SetAutoGenFilterType(uint32_t f);
    uint32_t GetAutoGenFilterType();
    uint32_t GenerateMipSubLevels();
    uint32_t GetLevelDesc(uint32_t level, uint32_t out);
    uint32_t GetSurfaceLevel(uint32_t level, uint32_t out);
    uint32_t LockRect(uint32_t level, uint32_t locked, uint32_t rect, uint32_t flags);
    uint32_t UnlockRect(uint32_t level);
    uint32_t AddDirtyRect(uint32_t rect);
    uint32_t CubeGetLevelDesc(uint32_t level, uint32_t out);
    uint32_t GetCubeMapSurface(uint32_t face, uint32_t level, uint32_t out);
    uint32_t CubeLockRect(uint32_t face, uint32_t level, uint32_t locked, uint32_t rect, uint32_t flags);
    uint32_t CubeUnlockRect(uint32_t face, uint32_t level);
    uint32_t CubeAddDirtyRect(uint32_t face, uint32_t rect);
    uint32_t VolGetLevelDesc(uint32_t level, uint32_t out);
    uint32_t GetVolumeLevel(uint32_t level, uint32_t out);
    uint32_t LockBox(uint32_t level, uint32_t locked, uint32_t box, uint32_t flags);
    uint32_t UnlockBox(uint32_t level);
    uint32_t AddDirtyBox(uint32_t box);
};

// IDirect3DVolume9: a volume texture's level (its counts are the texture's)
struct Volume : Base {
    Texture* container = nullptr;
    uint32_t level = 0;
    uint32_t AddRef_() override;
    uint32_t Release_() override;
    uint32_t GetContainer(uint32_t riid, uint32_t out);
    uint32_t GetDesc(uint32_t out);
    uint32_t LockBox(uint32_t locked, uint32_t box, uint32_t flags);
    uint32_t UnlockBox();
};

struct Buffer : Base {
    bool index = false;
    uint32_t length = 0, usage = 0, format = 0 /* the FVF, or the index format */, pool = 0;
    bool dynamic = false;   // versions in the upload ring (DYNAMIC, SYSTEMMEM)
    // static: a device buffer
    VkBuffer buffer = VK_NULL_HANDLE;
    Alloc mem;
    uint64_t lastUse = 0, pendingCopy = 0;
    // dynamic: the whole contents in low memory, and the version the GPU reads
    uint32_t shadow = 0;
    VkBuffer verBuffer = VK_NULL_HANDLE;
    VkDeviceSize verOffset = 0;
    uint8_t* verPtr = nullptr;
    uint64_t verSerial = 0;
    bool verUsed = false;
    // the open lock
    int locks = 0;
    uint32_t lockMem = 0, lockOff = 0, lockEnd = 0, lockFlags = 0;

    ~Buffer() override;
    uint32_t GetType();
    uint32_t Lock(uint32_t offset, uint32_t size, uint32_t out, uint32_t flags);
    uint32_t Unlock();
    uint32_t GetDesc(uint32_t out);
    // what a draw binds (a dynamic buffer's current version made here)
    void Use(VkBuffer* b, VkDeviceSize* off);
    void NewVersion(bool copyAll);
};

struct Query : Base {
    uint32_t type = 0;
    uint64_t serial = 0;           // the submission its end is in (0: not issued)
    bool building = false;         // an occlusion query between its begin and end
    std::vector<uint32_t> slots;   // an occlusion query's Vulkan queries (one per render pass it spans)
    uint64_t cpuTime = 0;
    ~Query() override;
    uint32_t GetType();
    uint32_t GetDataSize();
    uint32_t Issue(uint32_t flags);
    uint32_t GetData(uint32_t data, uint32_t size, uint32_t flags);
};

struct Decl : Base {
    std::vector<Element32> elems;   // to D3DDECL_END, not including it
    uint32_t GetDeclaration(uint32_t out, uint32_t count);
};

struct Shader : Base {
    Stage stage = Stage::Vertex;
    std::vector<uint32_t> tokens;
    ShaderInfo info;
    VkShaderModule module = VK_NULL_HANDLE;
    uint64_t id = 0;
    ~Shader() override;
    uint32_t GetFunction(uint32_t out, uint32_t sizeOut);
};

// ---- device state -----------------------------------------------------------------------------------
constexpr unsigned kSamplers = 20;   // pixel 0..15, vertex 16..19 (D3DVERTEXTEXTURESAMPLER0..3)
constexpr unsigned kStreams = 16;
constexpr unsigned kTransforms = 11; // world, view, projection, texture 0..7
constexpr unsigned kVsConsts = 256, kPsConsts = 224;

struct Stream {
    Buffer* vb = nullptr;
    uint32_t offset = 0, stride = 0, freq = 1;
};
struct Viewport {
    uint32_t x = 0, y = 0, w = 1, h = 1;
    float minZ = 0, maxZ = 1;
};

struct State {
    uint32_t rs[256] = {};
    uint32_t ss[kSamplers][kSamplerStates] = {};
    uint32_t tss[8][kStageStates] = {};
    Texture* tex[kSamplers] = {};
    Shader* vs = nullptr;
    Shader* ps = nullptr;
    Decl* decl = nullptr;
    uint32_t fvf = 0;
    float vsF[kVsConsts][4] = {};
    int32_t vsI[16][4] = {};
    uint32_t vsB[16] = {};
    float psF[kPsConsts][4] = {};
    int32_t psI[16][4] = {};
    uint32_t psB[16] = {};
    Stream streams[kStreams];
    Buffer* ib = nullptr;
    Viewport vp;
    Rect scissor;
    float transforms[kTransforms][16] = {};
    float clip[6][4] = {};
    uint8_t material[68] = {};
};

// which parts of a State a state block holds
struct StateMask {
    std::bitset<256> rs;
    std::bitset<kSamplers * kSamplerStates> ss;
    std::bitset<8 * kStageStates> tss;
    std::bitset<kVsConsts> vsF;
    std::bitset<kPsConsts> psF;
    uint32_t tex = 0;
    uint16_t vsI = 0, vsB = 0, psI = 0, psB = 0, streams = 0, freqs = 0, transforms = 0;
    uint8_t clip = 0;
    bool vs = false, ps = false, decl = false, fvf = false, ib = false, vp = false, scissor = false, material = false;
};

struct StateBlock : Base {
    State s;
    StateMask m;
    ~StateBlock() override;
    uint32_t Capture();
    uint32_t Apply();
};

struct SwapChain : Base {
    PresentParams32 pp{};
    Surface* backBuffer = nullptr;
    bool implicit = false;
    ~SwapChain() override;
    uint32_t Present(uint32_t src, uint32_t dst, uint32_t window, uint32_t dirty, uint32_t flags);
    uint32_t GetFrontBufferData(uint32_t surface);
    uint32_t GetBackBuffer(uint32_t index, uint32_t type, uint32_t out);
    uint32_t GetRasterStatus(uint32_t out);
    uint32_t GetDisplayMode(uint32_t out);
    uint32_t GetPresentParameters(uint32_t out);
};

// ---- pipelines (Pipeline.cpp) -------------------------------------------------------------------------
struct VertexLayout {   // zero-filled, compared as bytes
    struct Attr {
        uint8_t location, binding;
        uint16_t offset;
        uint32_t format;   // VkFormat
    } attrs[16];
    uint8_t count;
    uint8_t pad;
    uint16_t bindings;      // a bit per binding used
    uint16_t instanced;     // a bit per binding read per instance
    uint16_t pad2;
};
struct PipelineKey {    // zero-filled, compared as bytes
    uint64_t vs, ps;        // shader ids (the fixed-function ones too)
    VertexLayout layout;
    uint32_t colorFormats[4];
    uint32_t depthFormat, stencilFormat;
    uint32_t blend;         // enable, src/dst/op color, src/dst/op alpha (packed)
    uint8_t writeMask[4];
    uint8_t colorCount, topologyClass, polygonMode;
    uint8_t alphaOne;       // a bit per target whose format has no alpha (DESTALPHA reads one)
};
struct KeyHash {
    size_t operator()(const PipelineKey& k) const;
};
struct KeyEq {
    bool operator()(const PipelineKey& a, const PipelineKey& b) const { return memcmp(&a, &b, sizeof a) == 0; }
};
struct SamplerKey {
    uint32_t v[8];
    bool operator==(const SamplerKey& o) const { return memcmp(v, o.v, sizeof v) == 0; }
};
struct SamplerHash {
    size_t operator()(const SamplerKey& k) const;
};
VkFormat DeclFormat(uint8_t type);
VkCompareOp CompareOp(uint32_t d3dcmp);
VkStencilOp StencilOp(uint32_t d3dop);

// ---- the fixed function (FixedFunction.cpp) -------------------------------------------------------
std::vector<uint32_t> FixedVertexSpirv();
std::vector<uint32_t> FixedPixelSpirv();
// the fixed-function vertex shader's inputs: position 0, diffuse 1, specular 2, texcoord0 3, texcoord1 4
void FixedVertexInfo(ShaderInfo* info);
void FixedPixelInfo(ShaderInfo* info);
constexpr uint32_t kFixedVsBytes = 16 * 16, kFixedPsBytes = 16 * 16;
// their uniform blocks from the device's state (vec4 c[16] each)
void FixedVertexConstants(const State& s, uint32_t fvf, float out[16][4]);
void FixedPixelConstants(const State& s, bool textured, float out[16][4]);

// ---- the IDirect3D9 ------------------------------------------------------------------------------------
struct D3D9 {
    uint32_t self = 0;
    std::atomic<int> refs{1};
    Vulkan* vk = nullptr;
    uint32_t QueryInterface(uint32_t riid, uint32_t out);
    uint32_t AddRef_();
    uint32_t Release_();
    uint32_t RegisterSoftwareDevice(uint32_t);
    uint32_t GetAdapterCount();
    uint32_t GetAdapterIdentifier(uint32_t adapter, uint32_t flags, uint32_t out);
    uint32_t GetAdapterModeCount(uint32_t adapter, uint32_t format);
    uint32_t EnumAdapterModes(uint32_t adapter, uint32_t format, uint32_t mode, uint32_t out);
    uint32_t GetAdapterDisplayMode(uint32_t adapter, uint32_t out);
    uint32_t CheckDeviceType(uint32_t adapter, uint32_t type, uint32_t displayFormat, uint32_t bbFormat, uint32_t windowed);
    uint32_t CheckDeviceFormat(uint32_t adapter, uint32_t type, uint32_t adapterFormat, uint32_t usage, uint32_t rtype,
                               uint32_t format);
    uint32_t CheckDeviceMultiSampleType(uint32_t adapter, uint32_t type, uint32_t format, uint32_t windowed,
                                        uint32_t samples, uint32_t quality);
    uint32_t CheckDepthStencilMatch(uint32_t adapter, uint32_t type, uint32_t adapterFormat, uint32_t rtFormat,
                                    uint32_t dsFormat);
    uint32_t CheckDeviceFormatConversion(uint32_t adapter, uint32_t type, uint32_t src, uint32_t dst);
    uint32_t GetDeviceCaps(uint32_t adapter, uint32_t type, uint32_t out);
    uint32_t GetAdapterMonitor(uint32_t adapter);
    uint32_t CreateDevice(uint32_t adapter, uint32_t type, uint32_t focus, uint32_t behavior, uint32_t pp, uint32_t out);
};
void FillCaps(const Vulkan* vk, uint32_t out);

// ---- the device ------------------------------------------------------------------------------------------
constexpr unsigned kSlots = 3;   // submissions in flight
constexpr uint32_t kDummyBinding = 15;

struct Slot {
    VkCommandPool pool = VK_NULL_HANDLE;
    VkCommandBuffer cmd = VK_NULL_HANDLE, upload = VK_NULL_HANDLE;
    VkFence fence = VK_NULL_HANDLE;
    VkSemaphore acquire = VK_NULL_HANDLE;
    uint64_t serial = 0;
    bool pending = false, uploadOpen = false, uploadBarrier = false;
    std::vector<Chunk*> chunks;
    std::vector<std::function<void()>> deferred;
};

enum Dirty : uint32_t {
    kDirtyPipeline = 1u << 0, kDirtyViewport = 1u << 1, kDirtyScissor = 1u << 2, kDirtyDepth = 1u << 3,
    kDirtyStencil = 1u << 4, kDirtyCull = 1u << 5, kDirtyBias = 1u << 6, kDirtyBlendConst = 1u << 7,
    kDirtyVsConst = 1u << 8, kDirtyPsConst = 1u << 9, kDirtyTextures = 1u << 10, kDirtyStreams = 1u << 11,
    kDirtyIndices = 1u << 12, kDirtyPush = 1u << 13, kDirtyFixed = 1u << 14, kDirtyTargets = 1u << 15,
    kDirtyAll = 0xFFFFu,
};

struct Device {
    uint32_t self = 0;
    int refs = 1;
    D3D9* d3d = nullptr;
    std::recursive_mutex mu;

    // Vulkan
    Vulkan* vk = nullptr;
    VkDevice device = VK_NULL_HANDLE;
    VkQueue queue = VK_NULL_HANDLE;
    Fns fn;
    MemAllocator* mem = nullptr;
    bool lost = false;
    bool independentBlend = false, anisotropy = false, fillNonSolid = false, preciseOcclusion = false,
         mirrorClamp = false, hostQueryReset = false;

    // submissions
    Slot slots[kSlots];
    unsigned cur = 0;
    uint64_t serial = 1, completed = 0;
    VkCommandBuffer cmd = VK_NULL_HANDLE;   // the current slot's main command buffer, recording
    std::vector<Chunk*> freeChunks;
    uint64_t presents = 0, draws = 0, frameDraws = 0;

    // the host's surface and its swapchain
    void* window = nullptr;   // the ANativeWindow the surface was made from
    VkSurfaceKHR surface = VK_NULL_HANDLE;
    VkSwapchainKHR swapchain = VK_NULL_HANDLE;
    VkFormat scFormat = VK_FORMAT_UNDEFINED;
    VkExtent2D scExtent{};
    std::vector<VkImage> scImages;
    std::vector<VkSemaphore> scDone;
    bool scStale = false;

    // creation
    PresentParams32 pp{};
    uint32_t adapter = 0, deviceType = 1, focus = 0, behavior = 0;
    SwapChain* implicit = nullptr;
    Surface* autoDepth = nullptr;

    // state
    State st;
    StateBlock* rec = nullptr;   // a state block being recorded (BeginStateBlock)
    uint32_t dirty = kDirtyAll;
    Surface* rt[4] = {};
    Surface* ds = nullptr;
    uint32_t vsHigh = 0, psHigh = 0;   // the highest float constant ever set, +1
    std::map<uint32_t, std::vector<uint8_t>> lights;
    std::map<uint32_t, bool> lightOn;
    uint8_t gamma[1536] = {};
    uint32_t clipStatus[2] = {};
    bool softwareVp = false;
    float nPatch = 0;
    uint32_t palette = 0;

    // the render pass (dynamic rendering)
    bool passActive = false;
    VkExtent2D passExtent{};
    bool clearColor = false, clearDepth = false, clearStencil = false;   // pending, for the pass's begin
    VkClearColorValue clearColorValue{};
    float clearDepthValue = 1;
    uint32_t clearStencilValue = 0;

    // pipelines, descriptors
    VkDescriptorSetLayout setLayout = VK_NULL_HANDLE;
    VkPipelineLayout pipelineLayout = VK_NULL_HANDLE;
    VkPipelineCache pipelineCache = VK_NULL_HANDLE;
    std::unordered_map<PipelineKey, VkPipeline, KeyHash, KeyEq> pipelines;
    std::unordered_map<SamplerKey, VkSampler, SamplerHash> samplers;
    VkPipeline boundPipeline = VK_NULL_HANDLE;
    PipelineKey lastKey{};
    bool lastKeyValid = false;
    uint64_t nextShaderId = 16;
    // the uniform blocks last pushed
    RingSlice vsBlock, psBlock;
    uint32_t vsBlockSize = 0, psBlockSize = 0;
    bool lastFixedVs = false, lastFixedPs = false;

    // the fixed function
    VkShaderModule ffVs = VK_NULL_HANDLE, ffPs = VK_NULL_HANDLE;
    ShaderInfo ffVsInfo, ffPsInfo;
    std::map<uint32_t, std::vector<Element32>> fvfDecls;

    // stand-ins: unbound samplers, vertex inputs no stream feeds
    Image* black2D = nullptr;
    Image* white2D = nullptr;
    Image* blackCube = nullptr;
    Image* black3D = nullptr;
    VkBuffer dummyVb = VK_NULL_HANDLE;
    Alloc dummyVbMem;

    // a DrawPrimitiveUP's / DrawIndexedPrimitiveUP's data, in the ring for the draw
    bool upActive = false, upIndexed = false, upIndex32 = false;
    RingSlice upVb, upIb;
    int hostW = 0, hostH = 0;   // the host surface's size the swapchain was made for

    // occlusion queries
    VkQueryPool occPool = VK_NULL_HANDLE;
    std::vector<uint32_t> occFree;
    Query* activeOcc = nullptr;
    bool occOpen = false;   // a Vulkan query of activeOcc's is running in the pass

    ~Device();
    bool Init();

    // ---- submissions (Device.cpp) ----
    void BeginSlot();
    // end the pass and submit what is recorded (waiting on `wait`, signalling `signal`), then move to
    // the next slot (waiting for its last submission)
    void Submit(VkSemaphore wait = VK_NULL_HANDLE, VkSemaphore signal = VK_NULL_HANDLE);
    void Poll();
    void WaitSerial(uint64_t s);   // until submission s is done (submitting the current one if it is s)
    void Defer(std::function<void()> fn);
    VkCommandBuffer Upload();   // the current slot's upload command buffer, begun on demand
    // the command buffer an update of something last used at `lastUse` goes in (the pass ended if main)
    VkCommandBuffer CmdFor(uint64_t lastUse);
    RingSlice Ring(VkDeviceSize size, VkDeviceSize align);
    bool Check(VkResult r, const char* what);

    // ---- images (Image.cpp) ----
    Image* CreateImage(const FormatInfo* fmt, VkImageViewType type, uint32_t w, uint32_t h, uint32_t d,
                       uint32_t levels, uint32_t layers, VkImageUsageFlags usage);
    void DestroyImage(Image* img);
    VkImageView SampleView(Image* img, bool srgb);
    VkImageView TargetView(Image* img, uint32_t level, uint32_t layer, bool srgb);
    void Transition(VkCommandBuffer cb, Image* img, uint32_t level0, uint32_t nLevels, uint32_t layer0,
                    uint32_t nLayers, VkImageLayout to);
    void TransitionAll(VkCommandBuffer cb, Image* img, VkImageLayout to) {
        Transition(cb, img, 0, img->levels, 0, img->layers, to);
    }
    void ClearImage(Image* img, const VkClearColorValue& color);
    void GenerateMips(Image* img);
    // texels from the D3D side into a subresource region (converted as the format says)
    void UploadRegion(Storage* st, uint32_t level, uint32_t layer, uint32_t x, uint32_t y, uint32_t z, uint32_t w,
                      uint32_t h, uint32_t d, const uint8_t* src, uint32_t srcPitch, uint32_t srcSlice);
    // a subresource's texels back to the D3D side (waits for the GPU)
    bool ReadRegion(Image* img, uint32_t level, uint32_t layer, uint32_t w, uint32_t h, uint8_t* dst, uint32_t dstPitch);
    bool MakeBuffer(VkDeviceSize size, VkBufferUsageFlags usage, VkMemoryPropertyFlags want,
                    VkMemoryPropertyFlags prefer, VkBuffer* buf, Alloc* mem);
    void DestroyBuffer(VkBuffer buf, Alloc mem);

    // ---- pipelines (Pipeline.cpp) ----
    bool InitPipelines();
    VkPipeline GetPipeline(const PipelineKey& key, VkShaderModule vsModule, VkShaderModule psModule);
    VkSampler GetSampler(const uint32_t* ss, bool filterable, uint32_t lod);
    uint32_t PackBlend() const;
    void WriteMasks(uint8_t out[4]) const;

    // ---- the draw path (Draw.cpp) ----
    bool BeginPass();
    void EndPass();
    bool IsTarget(const Image* img) const;
    VkExtent2D TargetExtent() const;
    bool PrepareDraw(uint32_t primitive, bool indexed, uint32_t* instances);
    bool BuildLayout(const ShaderInfo& vsInfo, bool fixedVs, VertexLayout* out);
    const std::vector<Element32>& FvfElements(uint32_t fvf);
    void BeginOcclusion();
    void EndOcclusion();
    uint32_t AllocOcclusion();

    // ---- the reference's calls: IDirect3DDevice9 ----
    uint32_t QueryInterface(uint32_t riid, uint32_t out);
    uint32_t AddRef_();
    uint32_t Release_();
    uint32_t TestCooperativeLevel();
    uint32_t GetAvailableTextureMem();
    uint32_t EvictManagedResources();
    uint32_t GetDirect3D(uint32_t out);
    uint32_t GetDeviceCaps(uint32_t out);
    uint32_t GetDisplayMode(uint32_t sc, uint32_t out);
    uint32_t GetCreationParameters(uint32_t out);
    uint32_t SetCursorProperties(uint32_t x, uint32_t y, uint32_t surface);
    uint32_t SetCursorPosition(uint32_t x, uint32_t y, uint32_t flags);
    uint32_t ShowCursor(uint32_t show);
    uint32_t CreateAdditionalSwapChain(uint32_t pp, uint32_t out);
    uint32_t GetSwapChain(uint32_t index, uint32_t out);
    uint32_t GetNumberOfSwapChains();
    uint32_t Reset(uint32_t pp);
    uint32_t Present(uint32_t src, uint32_t dst, uint32_t window, uint32_t dirty);
    uint32_t GetBackBuffer(uint32_t sc, uint32_t index, uint32_t type, uint32_t out);
    uint32_t GetRasterStatus(uint32_t sc, uint32_t out);
    uint32_t SetDialogBoxMode(uint32_t on);
    uint32_t SetGammaRamp(uint32_t sc, uint32_t flags, uint32_t ramp);
    uint32_t GetGammaRamp(uint32_t sc, uint32_t ramp);
    uint32_t CreateTexture(uint32_t w, uint32_t h, uint32_t levels, uint32_t usage, uint32_t format, uint32_t pool,
                           uint32_t out, uint32_t shared);
    uint32_t CreateVolumeTexture(uint32_t w, uint32_t h, uint32_t d, uint32_t levels, uint32_t usage, uint32_t format,
                                 uint32_t pool, uint32_t out, uint32_t shared);
    uint32_t CreateCubeTexture(uint32_t edge, uint32_t levels, uint32_t usage, uint32_t format, uint32_t pool,
                               uint32_t out, uint32_t shared);
    uint32_t CreateVertexBuffer(uint32_t length, uint32_t usage, uint32_t fvf, uint32_t pool, uint32_t out, uint32_t shared);
    uint32_t CreateIndexBuffer(uint32_t length, uint32_t usage, uint32_t format, uint32_t pool, uint32_t out, uint32_t shared);
    uint32_t CreateRenderTarget(uint32_t w, uint32_t h, uint32_t format, uint32_t ms, uint32_t quality, uint32_t lockable,
                                uint32_t out, uint32_t shared);
    uint32_t CreateDepthStencilSurface(uint32_t w, uint32_t h, uint32_t format, uint32_t ms, uint32_t quality,
                                       uint32_t discard, uint32_t out, uint32_t shared);
    uint32_t UpdateSurface(uint32_t src, uint32_t srcRect, uint32_t dst, uint32_t dstPoint);
    uint32_t UpdateTexture(uint32_t src, uint32_t dst);
    uint32_t GetRenderTargetData(uint32_t rt, uint32_t dst);
    uint32_t GetFrontBufferData(uint32_t sc, uint32_t dst);
    uint32_t StretchRect(uint32_t src, uint32_t srcRect, uint32_t dst, uint32_t dstRect, uint32_t filter);
    uint32_t ColorFill(uint32_t surface, uint32_t rect, uint32_t color);
    uint32_t CreateOffscreenPlainSurface(uint32_t w, uint32_t h, uint32_t format, uint32_t pool, uint32_t out, uint32_t shared);
    uint32_t SetRenderTarget(uint32_t index, uint32_t surface);
    uint32_t GetRenderTarget(uint32_t index, uint32_t out);
    uint32_t SetDepthStencilSurface(uint32_t surface);
    uint32_t GetDepthStencilSurface(uint32_t out);
    uint32_t BeginScene();
    uint32_t EndScene();
    // (Z comes as its float's bits: FFXIV's ExecuteClear 0x4d8900 passes the word, not a double)
    uint32_t Clear(uint32_t count, uint32_t rects, uint32_t flags, uint32_t color, uint32_t zBits, uint32_t stencil);
    uint32_t SetTransform(uint32_t state, uint32_t matrix);
    uint32_t GetTransform(uint32_t state, uint32_t matrix);
    uint32_t MultiplyTransform(uint32_t state, uint32_t matrix);
    uint32_t SetViewport(uint32_t vp);
    uint32_t GetViewport(uint32_t vp);
    uint32_t SetMaterial(uint32_t m);
    uint32_t GetMaterial(uint32_t m);
    uint32_t SetLight(uint32_t index, uint32_t light);
    uint32_t GetLight(uint32_t index, uint32_t light);
    uint32_t LightEnable(uint32_t index, uint32_t on);
    uint32_t GetLightEnable(uint32_t index, uint32_t out);
    uint32_t SetClipPlane(uint32_t index, uint32_t plane);
    uint32_t GetClipPlane(uint32_t index, uint32_t plane);
    uint32_t SetRenderState(uint32_t state, uint32_t value);
    uint32_t GetRenderState(uint32_t state, uint32_t out);
    uint32_t CreateStateBlock(uint32_t type, uint32_t out);
    uint32_t BeginStateBlock();
    uint32_t EndStateBlock(uint32_t out);
    uint32_t SetClipStatus(uint32_t status);
    uint32_t GetClipStatus(uint32_t status);
    uint32_t GetTexture(uint32_t stage, uint32_t out);
    uint32_t SetTexture(uint32_t stage, uint32_t tex);
    uint32_t GetTextureStageState(uint32_t stage, uint32_t type, uint32_t out);
    uint32_t SetTextureStageState(uint32_t stage, uint32_t type, uint32_t value);
    uint32_t GetSamplerState(uint32_t sampler, uint32_t type, uint32_t out);
    uint32_t SetSamplerState(uint32_t sampler, uint32_t type, uint32_t value);
    uint32_t ValidateDevice(uint32_t passes);
    uint32_t SetPaletteEntries(uint32_t n, uint32_t entries);
    uint32_t GetPaletteEntries(uint32_t n, uint32_t entries);
    uint32_t SetCurrentTexturePalette(uint32_t n);
    uint32_t GetCurrentTexturePalette(uint32_t out);
    uint32_t SetScissorRect(uint32_t rect);
    uint32_t GetScissorRect(uint32_t rect);
    uint32_t SetSoftwareVertexProcessing(uint32_t on);
    uint32_t GetSoftwareVertexProcessing();
    uint32_t SetNPatchMode(uint32_t segmentsBits);   // (a float's bits, as Clear's Z)
    uint32_t GetNPatchMode();
    uint32_t DrawPrimitive(uint32_t type, uint32_t start, uint32_t count);
    uint32_t DrawIndexedPrimitive(uint32_t type, int32_t base, uint32_t minIndex, uint32_t numVertices,
                                  uint32_t startIndex, uint32_t count);
    uint32_t DrawPrimitiveUP(uint32_t type, uint32_t count, uint32_t data, uint32_t stride);
    uint32_t DrawIndexedPrimitiveUP(uint32_t type, uint32_t minIndex, uint32_t numVertices, uint32_t count,
                                    uint32_t indices, uint32_t indexFormat, uint32_t data, uint32_t stride);
    uint32_t ProcessVertices(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
    uint32_t CreateVertexDeclaration(uint32_t elements, uint32_t out);
    uint32_t SetVertexDeclaration(uint32_t decl);
    uint32_t GetVertexDeclaration(uint32_t out);
    uint32_t SetFVF(uint32_t fvf);
    uint32_t GetFVF(uint32_t out);
    uint32_t CreateVertexShader(uint32_t function, uint32_t out);
    uint32_t SetVertexShader(uint32_t shader);
    uint32_t GetVertexShader(uint32_t out);
    uint32_t SetVertexShaderConstantF(uint32_t start, uint32_t data, uint32_t count);
    uint32_t GetVertexShaderConstantF(uint32_t start, uint32_t data, uint32_t count);
    uint32_t SetVertexShaderConstantI(uint32_t start, uint32_t data, uint32_t count);
    uint32_t GetVertexShaderConstantI(uint32_t start, uint32_t data, uint32_t count);
    uint32_t SetVertexShaderConstantB(uint32_t start, uint32_t data, uint32_t count);
    uint32_t GetVertexShaderConstantB(uint32_t start, uint32_t data, uint32_t count);
    uint32_t SetStreamSource(uint32_t stream, uint32_t vb, uint32_t offset, uint32_t stride);
    uint32_t GetStreamSource(uint32_t stream, uint32_t vb, uint32_t offset, uint32_t stride);
    uint32_t SetStreamSourceFreq(uint32_t stream, uint32_t freq);
    uint32_t GetStreamSourceFreq(uint32_t stream, uint32_t out);
    uint32_t SetIndices(uint32_t ib);
    uint32_t GetIndices(uint32_t out);
    uint32_t CreatePixelShader(uint32_t function, uint32_t out);
    uint32_t SetPixelShader(uint32_t shader);
    uint32_t GetPixelShader(uint32_t out);
    uint32_t SetPixelShaderConstantF(uint32_t start, uint32_t data, uint32_t count);
    uint32_t GetPixelShaderConstantF(uint32_t start, uint32_t data, uint32_t count);
    uint32_t SetPixelShaderConstantI(uint32_t start, uint32_t data, uint32_t count);
    uint32_t GetPixelShaderConstantI(uint32_t start, uint32_t data, uint32_t count);
    uint32_t SetPixelShaderConstantB(uint32_t start, uint32_t data, uint32_t count);
    uint32_t GetPixelShaderConstantB(uint32_t start, uint32_t data, uint32_t count);
    uint32_t DrawRectPatch(uint32_t, uint32_t, uint32_t);
    uint32_t DrawTriPatch(uint32_t, uint32_t, uint32_t);
    uint32_t DeletePatch(uint32_t);
    uint32_t CreateQuery(uint32_t type, uint32_t out);

    // ---- helpers ----
    State& S() { return rec ? rec->s : st; }
    void SetDefaults();
    Surface* NewSurface(uint32_t w, uint32_t h, uint32_t format, uint32_t usage, uint32_t pool, uint32_t* hr);
    uint32_t NewTexture(uint32_t rtype, uint32_t w, uint32_t h, uint32_t d, uint32_t levels, uint32_t usage,
                        uint32_t format, uint32_t pool, uint32_t out);
    uint32_t NewBuffer(bool index, uint32_t length, uint32_t usage, uint32_t format, uint32_t pool, uint32_t out);
    SwapChain* NewSwapChain(PresentParams32* pp, bool implicit);
    Surface* MakeBackBuffer(PresentParams32* pp);   // (zero sizes become the host surface's)
    uint32_t PresentImage(Image* img, uint32_t w, uint32_t h);
    bool EnsureSwapchain(void* window, int w, int h);
    void DestroySwapchain(bool surfaceToo);
    void MarkRenderState(uint32_t state);
    void ApplyBlock(StateBlock* b);
    void CaptureBlock(StateBlock* b);
};

// an object's vtable, made once per kind (VkResources.cpp)
uint32_t SurfaceVtable();
uint32_t TextureVtable(uint32_t rtype);
uint32_t VolumeVtable();
uint32_t BufferVtable(bool index);
uint32_t QueryVtable();
uint32_t StateBlockVtable();
uint32_t DeclVtable();
uint32_t ShaderVtable();
uint32_t SwapChainVtable();
// an object of ours behind a reference handle, by kind (nullptr: none, or another kind's)
template <typename T>
T* Native(uint32_t obj) {
    if (!obj) return nullptr;
    return dynamic_cast<T*>(static_cast<Base*>(com::NativeOf(obj)));
}

}  // namespace rh::d3d9vk
