// The D3D9 shader translator's interface: shader model 1.1-3.0 bytecode (what CreateVertexShader /
// CreatePixelShader receive) to SPIR-V for Vulkan 1.1+, and what the device needs to know to bind it.
// Shader.cpp implements it; Device.cpp (d3d9vk) uses it. Written ahead of both so they agree.
//
// The binding model every translated shader follows (descriptor set 0 unless noted):
//
//   binding 0   uniform block VsConsts { vec4 c[256]; ivec4 i[16]; uint b[16]; }   vertex shaders
//   binding 1   uniform block PsConsts { vec4 c[224]; ivec4 i[16]; uint b[16]; }   pixel shaders
//               (b[k] is bool register k, 0 or 1; the device fills both blocks per draw, std140)
//   binding 2+s combined image sampler for pixel sampler s (s0..s15): bindings 2..17
//   binding 18+s combined image sampler for vertex sampler s (D3DVERTEXTEXTURESAMPLER0..3): 18..21
//               (the image's dimension is the shader's dcl: 2D, cube or 3D, see Sampler below)
//
//   push constants (both stages, 32 bytes, offset 0):
//     vec4  viewport;     // x: 2/width, y: 2/height (the D3D9 half-pixel offset: the translated
//                         // vertex shader moves its position by (-viewport.x, +viewport.y) * w / 2),
//                         // z, w: unused
//     uint  alphaFunc;    // D3DCMPFUNC (1 NEVER .. 8 ALWAYS); 8 when alpha test is off
//     float alphaRef;     // D3DRS_ALPHAREF / 255
//     uint  flags;        // bit 0: flip Y in the vertex shader (render to the swapchain or a target:
//                         // the device sets it so D3D's top-left origin lands right in Vulkan)
//     uint  pad;
//
// Vertex shader output position: D3D clip space, z in [0, 1] as Vulkan's; the translator adds the
// half-pixel offset and the Y flip from the push constants. Pixel shader output: color k at
// location k (oC0..oC3), oDepth as FragDepth. Alpha test is done in the pixel shader (discard) from
// the push constants, since Vulkan has none.
//
// Vertex inputs: one Vulkan location per input register the shader declares (dcl_position0,
// dcl_texcoord3 ...); Input says which (usage, index) each location wants, and the device binds the
// vertex declaration's element of that usage and index there. A shader model 1/2 vertex shader's
// v registers without a usage get usage = register number as D3D9 maps them (the device's job:
// Input carries usage 0xff and the register).
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace rh::d3d9vk {

enum class Stage : uint8_t { Vertex, Pixel };

struct Input {
    uint8_t usage;      // D3DDECLUSAGE (0 POSITION, 3 NORMAL, 5 TEXCOORD, 10 COLOR, ...); 0xff: none
    uint8_t usageIndex;
    uint8_t reg;        // the v register
    uint8_t location;   // the Vulkan location it is bound at
};

struct Sampler {
    uint8_t reg;        // s register (pixel 0..15, vertex 0..3)
    uint8_t type;       // D3DSAMPLER_TEXTURE_TYPE >> 27: 2 2D, 3 cube, 4 volume
};

struct ShaderInfo {
    Stage stage;
    uint8_t major, minor;                 // the shader model
    std::vector<Input> inputs;            // vertex shaders: what each location wants
    std::vector<Sampler> samplers;        // what the shader samples
    uint32_t outputColors = 0;            // pixel shaders: a bit per oCk written
    bool writesDepth = false;             // pixel shaders: oDepth
    // a vertex shader's outputs and a pixel shader's inputs are matched by (usage, index): both sides
    // use the same location for the same pair, location = LinkLocation(usage, index), so any vertex
    // shader links with any pixel shader without a per-pair recompile
};

// the location a vertex shader output / pixel shader input of (usage, index) is at: TEXCOORD0..15 at
// 0..15, COLOR0..1 at 16..17, FOG at 18, PSIZE 19, others 20+ (shader model 3 only); shader model 1/2
// oTn/tn are TEXCOORDn, oDn/vn COLORn
uint32_t LinkLocation(uint8_t usage, uint8_t index);

// Translate one shader. `tokens` is the bytecode as CreateVertexShader got it (the version token
// first, ending at the 0x0000FFFF end token). On failure returns an empty vector and says why in
// `error`; the device then skips draws with it (logged once).
std::vector<uint32_t> TranslateShader(const uint32_t* tokens, size_t count, ShaderInfo* info, std::string* error);

}  // namespace rh::d3d9vk
