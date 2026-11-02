// d3d9vk's formats: each D3DFORMAT the device takes as a VkFormat, a view swizzle for what D3D9
// samples differently (an X format's alpha, L8's replicated red), and a CPU conversion for what this
// GPU cannot hold as D3D lays it out: DXTn without textureCompressionBC (Adreno on Android has none),
// 16-bit color formats Vulkan lacks or the driver does not sample, 24- and 8-bit packed RGB. A
// conversion's target is B8G8R8A8 (A8R8G8B8's own bytes), so locks, uploads and sRGB views stay one path.
#include <cstdio>
#include <unordered_map>

#include "Vk.h"

namespace rh::d3d9vk {

namespace {

std::unordered_map<uint32_t, FormatInfo>& Table() {
    static std::unordered_map<uint32_t, FormatInfo> t;
    return t;
}

constexpr VkComponentSwizzle R = VK_COMPONENT_SWIZZLE_R, G = VK_COMPONENT_SWIZZLE_G, ONE = VK_COMPONENT_SWIZZLE_ONE,
                             ZERO = VK_COMPONENT_SWIZZLE_ZERO, ID = VK_COMPONENT_SWIZZLE_IDENTITY;
constexpr VkComponentMapping kIdentity = {ID, ID, ID, ID};

// ---- the conversions: D3D's texels to B8G8R8A8 -------------------------------------------------------
inline uint8_t Expand5(uint32_t v) { return static_cast<uint8_t>((v << 3) | (v >> 2)); }
inline uint8_t Expand6(uint32_t v) { return static_cast<uint8_t>((v << 2) | (v >> 4)); }
inline uint8_t Expand4(uint32_t v) { return static_cast<uint8_t>(v * 17); }
inline uint8_t Expand3(uint32_t v) { return static_cast<uint8_t>((v << 5) | (v << 2) | (v >> 1)); }
inline uint8_t Expand2(uint32_t v) { return static_cast<uint8_t>(v * 85); }

inline void Put(uint8_t* p, uint8_t r, uint8_t g, uint8_t b, uint8_t a) {
    p[0] = b, p[1] = g, p[2] = r, p[3] = a;
}

template <typename F>
void Rows16(const uint8_t* src, uint32_t srcPitch, uint8_t* dst, uint32_t dstPitch, uint32_t w, uint32_t h, F px) {
    for (uint32_t y = 0; y < h; y++) {
        const uint8_t* s = src + y * srcPitch;
        uint8_t* d = dst + y * dstPitch;
        for (uint32_t x = 0; x < w; x++) {
            uint32_t v = s[2 * x] | (s[2 * x + 1] << 8);
            px(v, d + 4 * x);
        }
    }
}

void Conv565(const uint8_t* s, uint32_t sp, uint8_t* d, uint32_t dp, uint32_t w, uint32_t h) {
    Rows16(s, sp, d, dp, w, h, [](uint32_t v, uint8_t* o) { Put(o, Expand5(v >> 11), Expand6((v >> 5) & 63), Expand5(v & 31), 255); });
}
void Conv1555(const uint8_t* s, uint32_t sp, uint8_t* d, uint32_t dp, uint32_t w, uint32_t h) {
    Rows16(s, sp, d, dp, w, h, [](uint32_t v, uint8_t* o) {
        Put(o, Expand5((v >> 10) & 31), Expand5((v >> 5) & 31), Expand5(v & 31), (v & 0x8000) ? 255 : 0);
    });
}
void ConvX1555(const uint8_t* s, uint32_t sp, uint8_t* d, uint32_t dp, uint32_t w, uint32_t h) {
    Rows16(s, sp, d, dp, w, h, [](uint32_t v, uint8_t* o) { Put(o, Expand5((v >> 10) & 31), Expand5((v >> 5) & 31), Expand5(v & 31), 255); });
}
void Conv4444(const uint8_t* s, uint32_t sp, uint8_t* d, uint32_t dp, uint32_t w, uint32_t h) {
    Rows16(s, sp, d, dp, w, h, [](uint32_t v, uint8_t* o) {
        Put(o, Expand4((v >> 8) & 15), Expand4((v >> 4) & 15), Expand4(v & 15), Expand4(v >> 12));
    });
}
void ConvX4444(const uint8_t* s, uint32_t sp, uint8_t* d, uint32_t dp, uint32_t w, uint32_t h) {
    Rows16(s, sp, d, dp, w, h, [](uint32_t v, uint8_t* o) { Put(o, Expand4((v >> 8) & 15), Expand4((v >> 4) & 15), Expand4(v & 15), 255); });
}
void ConvA8332(const uint8_t* s, uint32_t sp, uint8_t* d, uint32_t dp, uint32_t w, uint32_t h) {
    Rows16(s, sp, d, dp, w, h, [](uint32_t v, uint8_t* o) {
        Put(o, Expand3((v >> 5) & 7), Expand3((v >> 2) & 7), Expand2(v & 3), static_cast<uint8_t>(v >> 8));
    });
}
void Conv332(const uint8_t* s, uint32_t sp, uint8_t* d, uint32_t dp, uint32_t w, uint32_t h) {
    for (uint32_t y = 0; y < h; y++)
        for (uint32_t x = 0; x < w; x++) {
            uint32_t v = s[y * sp + x];
            Put(d + y * dp + 4 * x, Expand3(v >> 5), Expand3((v >> 2) & 7), Expand2(v & 3), 255);
        }
}
void ConvA4L4(const uint8_t* s, uint32_t sp, uint8_t* d, uint32_t dp, uint32_t w, uint32_t h) {
    for (uint32_t y = 0; y < h; y++)
        for (uint32_t x = 0; x < w; x++) {
            uint32_t v = s[y * sp + x];
            uint8_t l = Expand4(v & 15);
            Put(d + y * dp + 4 * x, l, l, l, Expand4(v >> 4));
        }
}
void Conv888(const uint8_t* s, uint32_t sp, uint8_t* d, uint32_t dp, uint32_t w, uint32_t h) {
    for (uint32_t y = 0; y < h; y++)
        for (uint32_t x = 0; x < w; x++) {
            const uint8_t* p = s + y * sp + 3 * x;   // (B, G, R in memory)
            uint8_t* o = d + y * dp + 4 * x;
            o[0] = p[0], o[1] = p[1], o[2] = p[2], o[3] = 255;
        }
}

// DXTn: 4x4 blocks, a 565 endpoint pair and 2-bit indices for the color (8 bytes), DXT3's explicit
// 4-bit alpha or DXT5's interpolated alpha before it (8 bytes)
void ColorBlock(const uint8_t* b, bool dxt1, uint8_t out[16][4]) {
    uint32_t c0 = b[0] | (b[1] << 8), c1 = b[2] | (b[3] << 8);
    uint8_t pal[4][4];
    Put(pal[0], Expand5(c0 >> 11), Expand6((c0 >> 5) & 63), Expand5(c0 & 31), 255);
    Put(pal[1], Expand5(c1 >> 11), Expand6((c1 >> 5) & 63), Expand5(c1 & 31), 255);
    if (c0 > c1 || !dxt1) {
        for (int k = 0; k < 3; k++) {
            pal[2][k] = static_cast<uint8_t>((2 * pal[0][k] + pal[1][k] + 1) / 3);
            pal[3][k] = static_cast<uint8_t>((pal[0][k] + 2 * pal[1][k] + 1) / 3);
        }
        pal[2][3] = pal[3][3] = 255;
    } else {
        for (int k = 0; k < 3; k++) pal[2][k] = static_cast<uint8_t>((pal[0][k] + pal[1][k]) / 2);
        pal[2][3] = 255;
        pal[3][0] = pal[3][1] = pal[3][2] = pal[3][3] = 0;
    }
    uint32_t bits = b[4] | (b[5] << 8) | (b[6] << 16) | (static_cast<uint32_t>(b[7]) << 24);
    for (int i = 0; i < 16; i++) memcpy(out[i], pal[(bits >> (2 * i)) & 3], 4);
}
void Dxt3Alpha(const uint8_t* b, uint8_t out[16][4]) {
    for (int i = 0; i < 16; i++) out[i][3] = Expand4((b[i / 2] >> ((i & 1) * 4)) & 15);
}
void Dxt5Alpha(const uint8_t* b, uint8_t out[16][4]) {
    uint32_t a0 = b[0], a1 = b[1], pal[8];
    pal[0] = a0, pal[1] = a1;
    if (a0 > a1) {
        for (int k = 1; k < 7; k++) pal[k + 1] = ((7 - k) * a0 + k * a1 + 3) / 7;
    } else {
        for (int k = 1; k < 5; k++) pal[k + 1] = ((5 - k) * a0 + k * a1 + 2) / 5;
        pal[6] = 0, pal[7] = 255;
    }
    uint64_t bits = 0;
    for (int k = 0; k < 6; k++) bits |= static_cast<uint64_t>(b[2 + k]) << (8 * k);
    for (int i = 0; i < 16; i++) out[i][3] = static_cast<uint8_t>(pal[(bits >> (3 * i)) & 7]);
}
template <int Kind>   // 1, 3, 5
void ConvDxt(const uint8_t* s, uint32_t sp, uint8_t* d, uint32_t dp, uint32_t w, uint32_t h) {
    constexpr uint32_t kBytes = Kind == 1 ? 8 : 16;
    uint8_t px[16][4];
    for (uint32_t by = 0; by < (h + 3) / 4; by++)
        for (uint32_t bx = 0; bx < (w + 3) / 4; bx++) {
            const uint8_t* b = s + by * sp + bx * kBytes;
            ColorBlock(Kind == 1 ? b : b + 8, Kind == 1, px);
            if (Kind == 3) Dxt3Alpha(b, px);
            if (Kind == 5) Dxt5Alpha(b, px);
            for (uint32_t y = 0; y < 4 && by * 4 + y < h; y++)
                for (uint32_t x = 0; x < 4 && bx * 4 + x < w; x++)
                    memcpy(d + (by * 4 + y) * dp + (bx * 4 + x) * 4, px[y * 4 + x], 4);
        }
}

// ---- the table ------------------------------------------------------------------------------------
struct Probe {
    VkPhysicalDevice phys;
    VkFormatFeatureFlags Features(VkFormat f) const {
        if (f == VK_FORMAT_UNDEFINED) return 0;
        VkFormatProperties p{};
        vkGetPhysicalDeviceFormatProperties(phys, f, &p);
        return p.optimalTilingFeatures;
    }
};

void Fill(FormatInfo& f, const Probe& probe) {
    VkFormatFeatureFlags ff = probe.Features(f.vk);
    f.sampled = ff & VK_FORMAT_FEATURE_SAMPLED_IMAGE_BIT;
    f.filter = ff & VK_FORMAT_FEATURE_SAMPLED_IMAGE_FILTER_LINEAR_BIT;
    f.color = ff & VK_FORMAT_FEATURE_COLOR_ATTACHMENT_BIT;
    f.blend = ff & VK_FORMAT_FEATURE_COLOR_ATTACHMENT_BLEND_BIT;
    f.ds = ff & VK_FORMAT_FEATURE_DEPTH_STENCIL_ATTACHMENT_BIT;
    f.blit = (ff & VK_FORMAT_FEATURE_BLIT_SRC_BIT) && (ff & VK_FORMAT_FEATURE_BLIT_DST_BIT);
}

void Add(const Probe& probe, uint32_t d3d, VkFormat vk, uint8_t bytes, VkComponentMapping sw = kIdentity,
         VkFormat srgb = VK_FORMAT_UNDEFINED) {
    FormatInfo f;
    f.d3d = d3d, f.vk = vk, f.bytes = bytes, f.vkBytes = bytes, f.swizzle = sw, f.srgb = srgb;
    f.alphaOne = sw.a == ONE;
    Fill(f, probe);
    Table()[d3d] = f;
}
// held as B8G8R8A8, converted on upload
void AddDecoded(const Probe& probe, uint32_t d3d, uint8_t bytes, Convert c, uint8_t block = 1, bool alphaOne = false) {
    FormatInfo f;
    f.d3d = d3d, f.vk = VK_FORMAT_B8G8R8A8_UNORM, f.srgb = VK_FORMAT_B8G8R8A8_SRGB, f.bytes = bytes, f.vkBytes = 4;
    f.blockW = f.blockH = block;
    f.convert = c;
    f.alphaOne = alphaOne;
    Fill(f, probe);
    Table()[d3d] = f;
}
// native if the GPU samples it (and, for render targets, renders to it), else decoded
void AddOrDecode(const Probe& probe, uint32_t d3d, VkFormat vk, uint8_t bytes, VkComponentMapping sw, Convert c) {
    VkFormatFeatureFlags ff = probe.Features(vk);
    bool ok = (ff & VK_FORMAT_FEATURE_SAMPLED_IMAGE_BIT) && (ff & VK_FORMAT_FEATURE_SAMPLED_IMAGE_FILTER_LINEAR_BIT);
    if (ok) Add(probe, d3d, vk, bytes, sw);
    else AddDecoded(probe, d3d, bytes, c, 1, sw.a == ONE);
}
void AddDepth(const Probe& probe, uint32_t d3d, VkFormat vk, bool stencil, VkComponentMapping sw = kIdentity) {
    FormatInfo f;
    f.d3d = d3d, f.vk = vk, f.bytes = 4, f.vkBytes = 4, f.swizzle = sw;
    f.depth = true, f.stencil = stencil;
    if (vk == VK_FORMAT_D16_UNORM) f.bytes = f.vkBytes = 2;
    Fill(f, probe);
    Table()[d3d] = f;
}

}  // namespace

void InitFormats(VkPhysicalDevice phys, bool bc) {
    Probe p{phys};
    auto& t = Table();
    t.clear();
    VkComponentMapping xrgb = {ID, ID, ID, ONE};
    Add(p, F_A8R8G8B8, VK_FORMAT_B8G8R8A8_UNORM, 4, kIdentity, VK_FORMAT_B8G8R8A8_SRGB);
    Add(p, F_X8R8G8B8, VK_FORMAT_B8G8R8A8_UNORM, 4, xrgb, VK_FORMAT_B8G8R8A8_SRGB);
    Add(p, F_A8B8G8R8, VK_FORMAT_R8G8B8A8_UNORM, 4, kIdentity, VK_FORMAT_R8G8B8A8_SRGB);
    Add(p, F_X8B8G8R8, VK_FORMAT_R8G8B8A8_UNORM, 4, xrgb, VK_FORMAT_R8G8B8A8_SRGB);
    AddOrDecode(p, F_R5G6B5, VK_FORMAT_R5G6B5_UNORM_PACK16, 2, kIdentity, Conv565);
    AddOrDecode(p, F_A1R5G5B5, VK_FORMAT_A1R5G5B5_UNORM_PACK16, 2, kIdentity, Conv1555);
    AddOrDecode(p, F_X1R5G5B5, VK_FORMAT_A1R5G5B5_UNORM_PACK16, 2, xrgb, ConvX1555);
    // (VK_FORMAT_A4R4G4B4_UNORM_PACK16 is D3D's bit order; 1.3's optional formatA4R4G4B4)
    AddOrDecode(p, F_A4R4G4B4, VK_FORMAT_A4R4G4B4_UNORM_PACK16, 2, kIdentity, Conv4444);
    AddOrDecode(p, F_X4R4G4B4, VK_FORMAT_A4R4G4B4_UNORM_PACK16, 2, xrgb, ConvX4444);
    AddDecoded(p, F_R8G8B8, 3, Conv888);
    AddDecoded(p, F_R3G3B2, 1, Conv332);
    AddDecoded(p, F_A8R3G3B2, 2, ConvA8332);
    AddDecoded(p, F_A4L4, 1, ConvA4L4);
    Add(p, F_A8, VK_FORMAT_R8_UNORM, 1, {ZERO, ZERO, ZERO, R});
    Add(p, F_L8, VK_FORMAT_R8_UNORM, 1, {R, R, R, ONE});
    Add(p, F_A8L8, VK_FORMAT_R8G8_UNORM, 2, {R, R, R, G});
    Add(p, F_L16, VK_FORMAT_R16_UNORM, 2, {R, R, R, ONE});
    Add(p, F_V8U8, VK_FORMAT_R8G8_SNORM, 2, {R, G, ONE, ONE});
    Add(p, F_Q8W8V8U8, VK_FORMAT_R8G8B8A8_SNORM, 4);
    Add(p, F_V16U16, VK_FORMAT_R16G16_SNORM, 4, {R, G, ONE, ONE});
    Add(p, F_A2B10G10R10, VK_FORMAT_A2B10G10R10_UNORM_PACK32, 4);
    Add(p, F_A2R10G10B10, VK_FORMAT_A2R10G10B10_UNORM_PACK32, 4);
    Add(p, F_G16R16, VK_FORMAT_R16G16_UNORM, 4, {R, G, ONE, ONE});
    Add(p, F_A16B16G16R16, VK_FORMAT_R16G16B16A16_UNORM, 8);
    // (D3D9 samples a float format's missing channels as one)
    Add(p, F_R16F, VK_FORMAT_R16_SFLOAT, 2, {R, ONE, ONE, ONE});
    Add(p, F_G16R16F, VK_FORMAT_R16G16_SFLOAT, 4, {R, G, ONE, ONE});
    Add(p, F_A16B16G16R16F, VK_FORMAT_R16G16B16A16_SFLOAT, 8);
    Add(p, F_R32F, VK_FORMAT_R32_SFLOAT, 4, {R, ONE, ONE, ONE});
    Add(p, F_G32R32F, VK_FORMAT_R32G32_SFLOAT, 8, {R, G, ONE, ONE});
    Add(p, F_A32B32G32R32F, VK_FORMAT_R32G32B32A32_SFLOAT, 16);

    struct Dxt {
        uint32_t d3d;
        VkFormat vk, srgb;
        uint8_t bytes;
        Convert c;
    } dxts[] = {
        {F_DXT1, VK_FORMAT_BC1_RGBA_UNORM_BLOCK, VK_FORMAT_BC1_RGBA_SRGB_BLOCK, 8, ConvDxt<1>},
        {F_DXT2, VK_FORMAT_BC2_UNORM_BLOCK, VK_FORMAT_BC2_SRGB_BLOCK, 16, ConvDxt<3>},
        {F_DXT3, VK_FORMAT_BC2_UNORM_BLOCK, VK_FORMAT_BC2_SRGB_BLOCK, 16, ConvDxt<3>},
        {F_DXT4, VK_FORMAT_BC3_UNORM_BLOCK, VK_FORMAT_BC3_SRGB_BLOCK, 16, ConvDxt<5>},
        {F_DXT5, VK_FORMAT_BC3_UNORM_BLOCK, VK_FORMAT_BC3_SRGB_BLOCK, 16, ConvDxt<5>},
    };
    for (const Dxt& d : dxts) {
        if (bc && (p.Features(d.vk) & VK_FORMAT_FEATURE_SAMPLED_IMAGE_BIT)) {
            FormatInfo f;
            f.d3d = d.d3d, f.vk = d.vk, f.srgb = d.srgb, f.bytes = f.vkBytes = d.bytes;
            f.blockW = f.blockH = 4, f.vkBlock = true;
            Fill(f, p);
            t[d.d3d] = f;
        } else {
            AddDecoded(p, d.d3d, d.bytes, d.c, 4);
        }
    }

    // depth: D24S8 where the GPU renders to it, else D32F S8; INTZ is D24S8 sampled as depth in every
    // channel. DF16, DF24 and RAWZ (vendor depth textures) are left out: CheckDeviceFormat says no.
    VkFormat d24 = (p.Features(VK_FORMAT_D24_UNORM_S8_UINT) & VK_FORMAT_FEATURE_DEPTH_STENCIL_ATTACHMENT_BIT)
                       ? VK_FORMAT_D24_UNORM_S8_UINT
                       : VK_FORMAT_D32_SFLOAT_S8_UINT;
    VkFormat d16 = (p.Features(VK_FORMAT_D16_UNORM) & VK_FORMAT_FEATURE_DEPTH_STENCIL_ATTACHMENT_BIT)
                       ? VK_FORMAT_D16_UNORM
                       : d24;
    AddDepth(p, F_D24S8, d24, true);
    AddDepth(p, F_D24X8, d24, true);
    AddDepth(p, F_D24X4S4, d24, true);
    AddDepth(p, F_D15S1, d24, true);
    AddDepth(p, F_D24FS8, VK_FORMAT_D32_SFLOAT_S8_UINT, true);
    AddDepth(p, F_D16, d16, d16 != VK_FORMAT_D16_UNORM);
    AddDepth(p, F_D16_LOCKABLE, d16, d16 != VK_FORMAT_D16_UNORM);
    AddDepth(p, F_D32, VK_FORMAT_D32_SFLOAT, false);
    AddDepth(p, F_D32F_LOCKABLE, VK_FORMAT_D32_SFLOAT, false);
    AddDepth(p, F_INTZ, d24, true, {R, R, R, R});
    for (uint32_t d : {F_D24S8, F_D24X8, F_D24X4S4, F_D15S1, F_INTZ, F_D24FS8})
        if (t[d].vk == VK_FORMAT_D32_SFLOAT_S8_UINT) t[d].bytes = t[d].vkBytes = 8;

    FormatInfo n;
    n.d3d = F_NULL, n.null = true, n.color = true;
    t[F_NULL] = n;

    Log("d3d9vk: formats: BC %s, D24S8 as %s, 4444 %s, 565 %s", bc ? "native" : "decoded on the CPU",
        d24 == VK_FORMAT_D24_UNORM_S8_UINT ? "D24S8" : "D32F S8", t[F_A4R4G4B4].convert ? "decoded" : "native",
        t[F_R5G6B5].convert ? "decoded" : "native");
}

const FormatInfo* LookupFormat(uint32_t d3d) {
    auto& t = Table();
    auto it = t.find(d3d);
    return it == t.end() ? nullptr : &it->second;
}

const char* FormatName(uint32_t d3d) {
    switch (d3d) {
        case F_A8R8G8B8: return "A8R8G8B8";
        case F_X8R8G8B8: return "X8R8G8B8";
        case F_R5G6B5: return "R5G6B5";
        case F_A1R5G5B5: return "A1R5G5B5";
        case F_A4R4G4B4: return "A4R4G4B4";
        case F_A8: return "A8";
        case F_L8: return "L8";
        case F_A8L8: return "A8L8";
        case F_G16R16: return "G16R16";
        case F_A2R10G10B10: return "A2R10G10B10";
        case F_A16B16G16R16: return "A16B16G16R16";
        case F_R16F: return "R16F";
        case F_G16R16F: return "G16R16F";
        case F_A16B16G16R16F: return "A16B16G16R16F";
        case F_R32F: return "R32F";
        case F_G32R32F: return "G32R32F";
        case F_A32B32G32R32F: return "A32B32G32R32F";
        case F_D24S8: return "D24S8";
        case F_D24X8: return "D24X8";
        case F_D16: return "D16";
        case F_D32: return "D32";
        case F_INDEX16: return "INDEX16";
        case F_INDEX32: return "INDEX32";
        default: break;
    }
    static thread_local char buf[16];
    if (d3d > 0xFFFF) {
        snprintf(buf, sizeof buf, "%c%c%c%c", char(d3d), char(d3d >> 8), char(d3d >> 16), char(d3d >> 24));
    } else {
        snprintf(buf, sizeof buf, "%u", d3d);
    }
    return buf;
}

uint32_t CheckFormat(uint32_t usage, uint32_t rtype, uint32_t format) {
    const FormatInfo* f = LookupFormat(format);
    if (!f) return D3DERR_NOTAVAILABLE;
    bool texture = rtype == RT_TEXTURE || rtype == RT_CUBETEXTURE || rtype == RT_VOLUMETEXTURE;
    if (f->null)
        return (usage & U_RENDERTARGET) && (rtype == RT_SURFACE || rtype == RT_TEXTURE) ? D3D_OK : D3DERR_NOTAVAILABLE;
    if (usage & 0x4000 /* D3DUSAGE_DMAP */) return D3DERR_NOTAVAILABLE;
    if (f->depth) {
        if (!(usage & U_DEPTHSTENCIL) || !f->ds) return D3DERR_NOTAVAILABLE;
        // a depth texture: INTZ's raw depth, not the hardware shadow compare a D24S8 texture means
        if (texture && (format != F_INTZ || rtype == RT_VOLUMETEXTURE || !f->sampled)) return D3DERR_NOTAVAILABLE;
        if (usage & (U_RENDERTARGET | U_QUERY_SRGBREAD | U_QUERY_SRGBWRITE | U_AUTOGENMIPMAP)) return D3DERR_NOTAVAILABLE;
        return D3D_OK;
    }
    if (usage & U_DEPTHSTENCIL) return D3DERR_NOTAVAILABLE;
    if ((usage & U_RENDERTARGET) && (!f->color || f->vkBlock)) return D3DERR_NOTAVAILABLE;
    if (rtype == RT_VOLUMETEXTURE && (usage & U_RENDERTARGET)) return D3DERR_NOTAVAILABLE;
    if ((texture || !(usage & U_RENDERTARGET)) && !f->sampled) return D3DERR_NOTAVAILABLE;
    if ((usage & U_QUERY_FILTER) && !f->filter) return D3DERR_NOTAVAILABLE;
    if ((usage & U_QUERY_POSTPIXELSHADER_BLENDING) && !f->blend) return D3DERR_NOTAVAILABLE;
    if ((usage & (U_QUERY_SRGBREAD | U_QUERY_SRGBWRITE)) && f->srgb == VK_FORMAT_UNDEFINED) return D3DERR_NOTAVAILABLE;
    if ((usage & U_QUERY_VERTEXTEXTURE) && !f->sampled) return D3DERR_NOTAVAILABLE;
    if ((usage & U_AUTOGENMIPMAP) && !(f->blit && f->filter && !f->vkBlock)) return D3DOK_NOAUTOGEN;
    return D3D_OK;
}

}  // namespace rh::d3d9vk
