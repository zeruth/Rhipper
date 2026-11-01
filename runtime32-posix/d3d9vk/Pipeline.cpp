// d3d9vk's pipelines and samplers. One descriptor set layout for every shader (Shader.h's binding
// model: the two uniform blocks, the 16 pixel and 4 vertex samplers), pushed per draw; one pipeline
// layout with the 32 bytes of push constants. A pipeline per (shaders, vertex layout, blend, write
// masks, target formats, topology class, fill mode); everything else D3D9 changes per draw is Vulkan
// 1.3's dynamic state: viewport, scissor, cull, front face, topology, depth test/write/compare,
// stencil, depth bias, blend constants, vertex strides.
#include "Vk.h"

namespace rh::d3d9vk {

namespace {
size_t Fnv(const void* p, size_t n) {
    auto b = static_cast<const uint8_t*>(p);
    uint64_t h = 1469598103934665603ull;
    for (size_t k = 0; k < n; k++) h = (h ^ b[k]) * 1099511628211ull;
    return static_cast<size_t>(h);
}

VkBlendFactor BlendFactor(uint32_t b, bool alphaOne) {
    switch (b) {
        case 1: return VK_BLEND_FACTOR_ZERO;
        case 2: return VK_BLEND_FACTOR_ONE;
        case 3: return VK_BLEND_FACTOR_SRC_COLOR;
        case 4: return VK_BLEND_FACTOR_ONE_MINUS_SRC_COLOR;
        case 5: return VK_BLEND_FACTOR_SRC_ALPHA;
        case 6: return VK_BLEND_FACTOR_ONE_MINUS_SRC_ALPHA;
        case 7: return alphaOne ? VK_BLEND_FACTOR_ONE : VK_BLEND_FACTOR_DST_ALPHA;
        case 8: return alphaOne ? VK_BLEND_FACTOR_ZERO : VK_BLEND_FACTOR_ONE_MINUS_DST_ALPHA;
        case 9: return VK_BLEND_FACTOR_DST_COLOR;
        case 10: return VK_BLEND_FACTOR_ONE_MINUS_DST_COLOR;
        case 11: return alphaOne ? VK_BLEND_FACTOR_ZERO : VK_BLEND_FACTOR_SRC_ALPHA_SATURATE;
        case 14: return VK_BLEND_FACTOR_CONSTANT_COLOR;
        case 15: return VK_BLEND_FACTOR_ONE_MINUS_CONSTANT_COLOR;
        case 16: case 17:
            LogOnce("vk-blend-dual", "d3d9vk: dual-source blend factors (SRCCOLOR2) done as SRCCOLOR");
            return b == 16 ? VK_BLEND_FACTOR_SRC_COLOR : VK_BLEND_FACTOR_ONE_MINUS_SRC_COLOR;
        default: return VK_BLEND_FACTOR_ONE;
    }
}
VkBlendOp BlendOp(uint32_t op) {
    switch (op) {
        case 2: return VK_BLEND_OP_SUBTRACT;
        case 3: return VK_BLEND_OP_REVERSE_SUBTRACT;
        case 4: return VK_BLEND_OP_MIN;
        case 5: return VK_BLEND_OP_MAX;
        default: return VK_BLEND_OP_ADD;
    }
}
// BOTHSRCALPHA / BOTHINVSRCALPHA set both factors from the source one
void Both(uint32_t& src, uint32_t& dst) {
    if (src == 12) src = 5, dst = 6;
    else if (src == 13) src = 6, dst = 5;
}
VkSamplerAddressMode Address(uint32_t a, bool mirrorClamp) {
    switch (a) {
        case 2: return VK_SAMPLER_ADDRESS_MODE_MIRRORED_REPEAT;
        case 3: return VK_SAMPLER_ADDRESS_MODE_CLAMP_TO_EDGE;
        case 4: return VK_SAMPLER_ADDRESS_MODE_CLAMP_TO_BORDER;
        case 5: return mirrorClamp ? VK_SAMPLER_ADDRESS_MODE_MIRROR_CLAMP_TO_EDGE : VK_SAMPLER_ADDRESS_MODE_CLAMP_TO_EDGE;
        default: return VK_SAMPLER_ADDRESS_MODE_REPEAT;
    }
}
}  // namespace

size_t KeyHash::operator()(const PipelineKey& k) const { return Fnv(&k, sizeof k); }
size_t SamplerHash::operator()(const SamplerKey& k) const { return Fnv(&k, sizeof k); }

VkFormat DeclFormat(uint8_t type) {
    switch (type) {
        case DT_FLOAT1: return VK_FORMAT_R32_SFLOAT;
        case DT_FLOAT2: return VK_FORMAT_R32G32_SFLOAT;
        case DT_FLOAT3: return VK_FORMAT_R32G32B32_SFLOAT;
        case DT_FLOAT4: return VK_FORMAT_R32G32B32A32_SFLOAT;
        case DT_D3DCOLOR: return VK_FORMAT_B8G8R8A8_UNORM;   // (ARGB in a dword: B, G, R, A bytes)
        case DT_UBYTE4: return VK_FORMAT_R8G8B8A8_USCALED;
        case DT_SHORT2: return VK_FORMAT_R16G16_SSCALED;
        case DT_SHORT4: return VK_FORMAT_R16G16B16A16_SSCALED;
        case DT_UBYTE4N: return VK_FORMAT_R8G8B8A8_UNORM;
        case DT_SHORT2N: return VK_FORMAT_R16G16_SNORM;
        case DT_SHORT4N: return VK_FORMAT_R16G16B16A16_SNORM;
        case DT_USHORT2N: return VK_FORMAT_R16G16_UNORM;
        case DT_USHORT4N: return VK_FORMAT_R16G16B16A16_UNORM;
        case DT_UDEC3: return VK_FORMAT_A2B10G10R10_USCALED_PACK32;
        case DT_DEC3N: return VK_FORMAT_A2B10G10R10_SNORM_PACK32;
        case DT_FLOAT16_2: return VK_FORMAT_R16G16_SFLOAT;
        case DT_FLOAT16_4: return VK_FORMAT_R16G16B16A16_SFLOAT;
        default: return VK_FORMAT_UNDEFINED;
    }
}

VkCompareOp CompareOp(uint32_t f) {   // D3DCMP_NEVER (1) .. ALWAYS (8) are Vulkan's 0 .. 7
    return f >= 1 && f <= 8 ? static_cast<VkCompareOp>(f - 1) : VK_COMPARE_OP_ALWAYS;
}
VkStencilOp StencilOp(uint32_t op) {  // D3DSTENCILOP_KEEP (1) .. DECR (8): the same order as Vulkan's
    return op >= 1 && op <= 8 ? static_cast<VkStencilOp>(op - 1) : VK_STENCIL_OP_KEEP;
}

bool Device::InitPipelines() {
    VkDescriptorSetLayoutBinding b[22];
    for (uint32_t k = 0; k < 22; k++) {
        b[k] = VkDescriptorSetLayoutBinding{};
        b[k].binding = k;
        b[k].descriptorCount = 1;
        b[k].descriptorType = k < 2 ? VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER : VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER;
        b[k].stageFlags = (k == 0 || k >= 18) ? VK_SHADER_STAGE_VERTEX_BIT : VK_SHADER_STAGE_FRAGMENT_BIT;
    }
    VkDescriptorSetLayoutCreateInfo dl{VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO};
    dl.flags = VK_DESCRIPTOR_SET_LAYOUT_CREATE_PUSH_DESCRIPTOR_BIT_KHR;
    dl.bindingCount = 22;
    dl.pBindings = b;
    if (!Check(vkCreateDescriptorSetLayout(device, &dl, nullptr, &setLayout), "vkCreateDescriptorSetLayout")) return false;
    VkPushConstantRange pc{VK_SHADER_STAGE_VERTEX_BIT | VK_SHADER_STAGE_FRAGMENT_BIT, 0, 32};
    VkPipelineLayoutCreateInfo pl{VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO};
    pl.setLayoutCount = 1;
    pl.pSetLayouts = &setLayout;
    pl.pushConstantRangeCount = 1;
    pl.pPushConstantRanges = &pc;
    if (!Check(vkCreatePipelineLayout(device, &pl, nullptr, &pipelineLayout), "vkCreatePipelineLayout")) return false;
    VkPipelineCacheCreateInfo cc{VK_STRUCTURE_TYPE_PIPELINE_CACHE_CREATE_INFO};
    Check(vkCreatePipelineCache(device, &cc, nullptr, &pipelineCache), "vkCreatePipelineCache");
    return true;
}

// the blend state from the render states: enable, src/dst/op of color then of alpha
uint32_t Device::PackBlend() const {
    const uint32_t* rs = st.rs;
    if (!rs[RS_ALPHABLENDENABLE]) return 0;
    uint32_t src = rs[RS_SRCBLEND], dst = rs[RS_DESTBLEND], op = rs[RS_BLENDOP];
    Both(src, dst);
    uint32_t srcA = src, dstA = dst, opA = op;
    if (rs[RS_SEPARATEALPHABLENDENABLE]) {
        srcA = rs[RS_SRCBLENDALPHA], dstA = rs[RS_DESTBLENDALPHA], opA = rs[RS_BLENDOPALPHA];
        Both(srcA, dstA);
    }
    return 1u | (src & 31) << 1 | (dst & 31) << 6 | (op & 7) << 11 | (srcA & 31) << 14 | (dstA & 31) << 19 |
           (opA & 7) << 24;
}

void Device::WriteMasks(uint8_t out[4]) const {
    const uint32_t states[4] = {RS_COLORWRITEENABLE, RS_COLORWRITEENABLE1, RS_COLORWRITEENABLE2, RS_COLORWRITEENABLE3};
    for (int k = 0; k < 4; k++) out[k] = static_cast<uint8_t>(st.rs[states[k]] & 0xF);   // (R G B A: Vulkan's bits)
}

VkPipeline Device::GetPipeline(const PipelineKey& key, VkShaderModule vsModule, VkShaderModule psModule) {
    auto it = pipelines.find(key);
    if (it != pipelines.end()) return it->second;

    VkPipelineShaderStageCreateInfo stages[2] = {{VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO},
                                                 {VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO}};
    stages[0].stage = VK_SHADER_STAGE_VERTEX_BIT;
    stages[0].module = vsModule;
    stages[0].pName = "main";
    stages[1].stage = VK_SHADER_STAGE_FRAGMENT_BIT;
    stages[1].module = psModule;
    stages[1].pName = "main";

    VkVertexInputBindingDescription binds[16];
    VkVertexInputAttributeDescription attrs[16];
    uint32_t nb = 0;
    for (uint32_t b = 0; b < 16; b++)
        if (key.layout.bindings & (1u << b))
            binds[nb++] = {b, 0, (key.layout.instanced & (1u << b)) ? VK_VERTEX_INPUT_RATE_INSTANCE : VK_VERTEX_INPUT_RATE_VERTEX};
    for (uint32_t k = 0; k < key.layout.count; k++) {
        const auto& a = key.layout.attrs[k];
        attrs[k] = {a.location, a.binding, static_cast<VkFormat>(a.format), a.offset};
    }
    VkPipelineVertexInputStateCreateInfo vi{VK_STRUCTURE_TYPE_PIPELINE_VERTEX_INPUT_STATE_CREATE_INFO};
    vi.vertexBindingDescriptionCount = nb;
    vi.pVertexBindingDescriptions = binds;
    vi.vertexAttributeDescriptionCount = key.layout.count;
    vi.pVertexAttributeDescriptions = attrs;

    VkPipelineInputAssemblyStateCreateInfo ia{VK_STRUCTURE_TYPE_PIPELINE_INPUT_ASSEMBLY_STATE_CREATE_INFO};
    ia.topology = key.topologyClass == 0   ? VK_PRIMITIVE_TOPOLOGY_POINT_LIST
                  : key.topologyClass == 1 ? VK_PRIMITIVE_TOPOLOGY_LINE_LIST
                                           : VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST;
    VkPipelineViewportStateCreateInfo vp{VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_STATE_CREATE_INFO};
    vp.viewportCount = 1;
    vp.scissorCount = 1;
    VkPipelineRasterizationStateCreateInfo rs{VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_CREATE_INFO};
    rs.polygonMode = static_cast<VkPolygonMode>(key.polygonMode);
    rs.lineWidth = 1.0f;
    VkPipelineMultisampleStateCreateInfo ms{VK_STRUCTURE_TYPE_PIPELINE_MULTISAMPLE_STATE_CREATE_INFO};
    ms.rasterizationSamples = VK_SAMPLE_COUNT_1_BIT;
    VkPipelineDepthStencilStateCreateInfo dss{VK_STRUCTURE_TYPE_PIPELINE_DEPTH_STENCIL_STATE_CREATE_INFO};
    dss.minDepthBounds = 0, dss.maxDepthBounds = 1;

    VkPipelineColorBlendAttachmentState att[4] = {};
    uint32_t blend = key.blend;
    for (uint32_t k = 0; k < key.colorCount; k++) {
        VkPipelineColorBlendAttachmentState& a = att[k];
        a.colorWriteMask = independentBlend ? key.writeMask[k] : key.writeMask[0];
        bool canBlend = false;
        if (key.colorFormats[k] != VK_FORMAT_UNDEFINED) {
            VkFormatProperties fp{};
            vkGetPhysicalDeviceFormatProperties(vk->phys, static_cast<VkFormat>(key.colorFormats[k]), &fp);
            canBlend = fp.optimalTilingFeatures & VK_FORMAT_FEATURE_COLOR_ATTACHMENT_BLEND_BIT;
            if ((blend & 1) && !canBlend)
                LogOnce(("vk-noblend-" + std::to_string(key.colorFormats[k])).c_str(),
                        "d3d9vk: VkFormat %u does not blend: drawn unblended", key.colorFormats[k]);
        }
        if ((blend & 1) && canBlend) {
            bool one = key.alphaOne & (1u << k);
            if (!independentBlend) one = key.alphaOne & 1;
            a.blendEnable = VK_TRUE;
            a.srcColorBlendFactor = BlendFactor((blend >> 1) & 31, one);
            a.dstColorBlendFactor = BlendFactor((blend >> 6) & 31, one);
            a.colorBlendOp = BlendOp((blend >> 11) & 7);
            a.srcAlphaBlendFactor = BlendFactor((blend >> 14) & 31, one);
            a.dstAlphaBlendFactor = BlendFactor((blend >> 19) & 31, one);
            a.alphaBlendOp = BlendOp((blend >> 24) & 7);
        }
    }
    VkPipelineColorBlendStateCreateInfo cb{VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO};
    cb.attachmentCount = key.colorCount;
    cb.pAttachments = att;

    VkDynamicState dyn[] = {VK_DYNAMIC_STATE_VIEWPORT,
                            VK_DYNAMIC_STATE_SCISSOR,
                            VK_DYNAMIC_STATE_DEPTH_BIAS,
                            VK_DYNAMIC_STATE_BLEND_CONSTANTS,
                            VK_DYNAMIC_STATE_STENCIL_COMPARE_MASK,
                            VK_DYNAMIC_STATE_STENCIL_WRITE_MASK,
                            VK_DYNAMIC_STATE_STENCIL_REFERENCE,
                            VK_DYNAMIC_STATE_CULL_MODE,
                            VK_DYNAMIC_STATE_FRONT_FACE,
                            VK_DYNAMIC_STATE_PRIMITIVE_TOPOLOGY,
                            VK_DYNAMIC_STATE_DEPTH_TEST_ENABLE,
                            VK_DYNAMIC_STATE_DEPTH_WRITE_ENABLE,
                            VK_DYNAMIC_STATE_DEPTH_COMPARE_OP,
                            VK_DYNAMIC_STATE_STENCIL_TEST_ENABLE,
                            VK_DYNAMIC_STATE_STENCIL_OP,
                            VK_DYNAMIC_STATE_VERTEX_INPUT_BINDING_STRIDE,
                            VK_DYNAMIC_STATE_DEPTH_BIAS_ENABLE};
    VkPipelineDynamicStateCreateInfo ds{VK_STRUCTURE_TYPE_PIPELINE_DYNAMIC_STATE_CREATE_INFO};
    ds.dynamicStateCount = sizeof dyn / sizeof dyn[0];
    ds.pDynamicStates = dyn;

    VkFormat colors[4];
    for (int k = 0; k < 4; k++) colors[k] = static_cast<VkFormat>(key.colorFormats[k]);
    VkPipelineRenderingCreateInfo ri{VK_STRUCTURE_TYPE_PIPELINE_RENDERING_CREATE_INFO};
    ri.colorAttachmentCount = key.colorCount;
    ri.pColorAttachmentFormats = colors;
    ri.depthAttachmentFormat = static_cast<VkFormat>(key.depthFormat);
    ri.stencilAttachmentFormat = static_cast<VkFormat>(key.stencilFormat);

    VkGraphicsPipelineCreateInfo ci{VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO};
    ci.pNext = &ri;
    ci.stageCount = 2;
    ci.pStages = stages;
    ci.pVertexInputState = &vi;
    ci.pInputAssemblyState = &ia;
    ci.pViewportState = &vp;
    ci.pRasterizationState = &rs;
    ci.pMultisampleState = &ms;
    ci.pDepthStencilState = &dss;
    ci.pColorBlendState = &cb;
    ci.pDynamicState = &ds;
    ci.layout = pipelineLayout;
    VkPipeline p = VK_NULL_HANDLE;
    VkResult r = vkCreateGraphicsPipelines(device, pipelineCache, 1, &ci, nullptr, &p);
    if (r != VK_SUCCESS) {
        LogOnce(("vk-pipeline-" + std::to_string(key.vs) + "-" + std::to_string(key.ps)).c_str(),
                "d3d9vk: vkCreateGraphicsPipelines failed (%d) for shaders %llu/%llu, %u attributes, %u targets", r,
                static_cast<unsigned long long>(key.vs), static_cast<unsigned long long>(key.ps), key.layout.count,
                key.colorCount);
        p = VK_NULL_HANDLE;
    }
    pipelines[key] = p;
    if (pipelines.size() % 256 == 0) Log("d3d9vk: %zu pipelines", pipelines.size());
    return p;
}

// a sampler for a stage's D3DSAMP_* states; `filterable`: the bound format filters linearly; `lod`: the
// texture's SetLOD (the most detailed level a managed texture may use)
VkSampler Device::GetSampler(const uint32_t* ss, bool filterable, uint32_t lod) {
    SamplerKey key{};
    key.v[0] = (ss[SS_ADDRESSU] & 7) | (ss[SS_ADDRESSV] & 7) << 4 | (ss[SS_ADDRESSW] & 7) << 8 |
               (ss[SS_MAGFILTER] & 15) << 12 | (ss[SS_MINFILTER] & 15) << 16 | (ss[SS_MIPFILTER] & 15) << 20 |
               (filterable ? 1u : 0u) << 24;
    key.v[1] = ss[SS_MIPMAPLODBIAS];
    key.v[2] = std::max(ss[SS_MAXMIPLEVEL], lod);
    key.v[3] = ss[SS_MAXANISOTROPY];
    key.v[4] = ss[SS_BORDERCOLOR];
    auto it = samplers.find(key);
    if (it != samplers.end()) return it->second;

    auto filter = [&](uint32_t f) { return f >= 2 && filterable ? VK_FILTER_LINEAR : VK_FILTER_NEAREST; };
    VkSamplerCreateInfo ci{VK_STRUCTURE_TYPE_SAMPLER_CREATE_INFO};
    uint32_t mag = ss[SS_MAGFILTER], min = ss[SS_MINFILTER], mip = ss[SS_MIPFILTER];
    ci.magFilter = filter(mag);
    ci.minFilter = filter(min);
    ci.mipmapMode = mip == 2 && filterable ? VK_SAMPLER_MIPMAP_MODE_LINEAR : VK_SAMPLER_MIPMAP_MODE_NEAREST;
    ci.addressModeU = Address(ss[SS_ADDRESSU], mirrorClamp);
    ci.addressModeV = Address(ss[SS_ADDRESSV], mirrorClamp);
    ci.addressModeW = Address(ss[SS_ADDRESSW], mirrorClamp);
    float maxBias = vk->props.limits.maxSamplerLodBias;
    ci.mipLodBias = std::max(-maxBias, std::min(maxBias, AsFloat(ss[SS_MIPMAPLODBIAS])));
    if (anisotropy && (min == 3 || mag == 3) && filterable) {
        ci.anisotropyEnable = VK_TRUE;
        ci.maxAnisotropy = std::min(static_cast<float>(std::max(1u, ss[SS_MAXANISOTROPY])),
                                    vk->props.limits.maxSamplerAnisotropy);
    }
    ci.minLod = static_cast<float>(key.v[2]);
    ci.maxLod = mip == 0 ? ci.minLod + 0.25f : VK_LOD_CLAMP_NONE;   // (MIPFILTER NONE: one level)
    // the border: the nearest of Vulkan's three (no custom border colors here)
    uint32_t bc = ss[SS_BORDERCOLOR];
    uint32_t sum = ((bc >> 16) & 255) + ((bc >> 8) & 255) + (bc & 255);
    ci.borderColor = (bc >> 24) < 128 ? VK_BORDER_COLOR_FLOAT_TRANSPARENT_BLACK
                     : sum > 384      ? VK_BORDER_COLOR_FLOAT_OPAQUE_WHITE
                                      : VK_BORDER_COLOR_FLOAT_OPAQUE_BLACK;
    if ((ss[SS_ADDRESSU] == 4 || ss[SS_ADDRESSV] == 4) && bc != 0 && bc != 0xFF000000u && bc != 0xFFFFFFFFu)
        LogOnce("vk-border", "d3d9vk: border color %08x approximated by Vulkan's nearest", bc);
    VkSampler s = VK_NULL_HANDLE;
    Check(vkCreateSampler(device, &ci, nullptr, &s), "vkCreateSampler");
    samplers[key] = s;
    return s;
}

}  // namespace rh::d3d9vk
