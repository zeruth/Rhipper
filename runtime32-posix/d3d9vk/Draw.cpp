// d3d9vk: the draw path. Render passes (dynamic rendering) over the bound targets, Clear inside them,
// the draws (pipeline by state, dynamic state, push descriptors, the uniform blocks Shader.h lays out,
// vertex and index buffers), occlusion queries per pass, and the copies between surfaces: StretchRect,
// ColorFill, UpdateSurface, UpdateTexture, GetRenderTargetData.
//
// A draw goes in three steps: what may end the pass (a texture's mipmaps, its layout for sampling),
// the pass (begun again only when the targets changed or something ended it), then the recording.
#include "Vk.h"

namespace rh::d3d9vk {

namespace {
constexpr uint64_t kFixedVsId = 1, kFixedPsId = 2;
constexpr uint32_t kStreamIndexed = 0x40000000u, kStreamInstance = 0x80000000u;
// the uniform blocks (Shader.h; offsets as Shader.cpp's std140 layout): c, then i, then b at stride 16
constexpr uint32_t kVsBlockBytes = kVsConsts * 16 + 16 * 16 + 16 * 16;
constexpr uint32_t kPsBlockBytes = kPsConsts * 16 + 16 * 16 + 16 * 16;

uint32_t VertexCount(uint32_t type, uint32_t prims) {
    switch (type) {
        case 1: return prims;               // POINTLIST
        case 2: return prims * 2;           // LINELIST
        case 3: return prims + 1;           // LINESTRIP
        case 4: return prims * 3;           // TRIANGLELIST
        case 5: case 6: return prims + 2;   // TRIANGLESTRIP, TRIANGLEFAN
        default: return 0;
    }
}
VkPrimitiveTopology Topology(uint32_t type) {
    switch (type) {
        case 1: return VK_PRIMITIVE_TOPOLOGY_POINT_LIST;
        case 2: return VK_PRIMITIVE_TOPOLOGY_LINE_LIST;
        case 3: return VK_PRIMITIVE_TOPOLOGY_LINE_STRIP;
        case 5: return VK_PRIMITIVE_TOPOLOGY_TRIANGLE_STRIP;
        case 6: return VK_PRIMITIVE_TOPOLOGY_TRIANGLE_FAN;
        default: return VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST;
    }
}
uint8_t TopologyClass(uint32_t type) { return type == 1 ? 0 : type <= 3 ? 1 : 2; }

VkClearColorValue ColorOf(uint32_t argb) {
    VkClearColorValue v{};
    v.float32[0] = ((argb >> 16) & 255) / 255.0f;
    v.float32[1] = ((argb >> 8) & 255) / 255.0f;
    v.float32[2] = (argb & 255) / 255.0f;
    v.float32[3] = (argb >> 24) / 255.0f;
    return v;
}

// a rectangle clipped to [0, w) x [0, h): false when nothing is left
bool Clip(Rect& r, uint32_t w, uint32_t h) {
    r.left = std::max(r.left, 0), r.top = std::max(r.top, 0);
    r.right = std::min(r.right, int32_t(w)), r.bottom = std::min(r.bottom, int32_t(h));
    return r.right > r.left && r.bottom > r.top;
}
Rect Intersect(const Rect& a, const Rect& b) {
    return Rect{std::max(a.left, b.left), std::max(a.top, b.top), std::min(a.right, b.right), std::min(a.bottom, b.bottom)};
}

// a draw may write the depth surface: Z writes with the test on, or stencil writes
bool DsWrites(const Device& d) {
    const uint32_t* rs = d.st.rs;
    Image* img = d.ds ? d.ds->Img() : nullptr;
    if (!img) return false;
    if (rs[RS_ZENABLE] && rs[RS_ZWRITEENABLE]) return true;
    return img->fmt->stencil && rs[RS_STENCILENABLE] && (rs[RS_STENCILWRITEMASK] & 0xff);
}
}  // namespace

// ---- the render pass --------------------------------------------------------------------------------------
bool Device::IsTarget(const Image* img) const {
    if (!img) return false;
    for (Surface* s : rt)
        if (s && s->Img() == img) return true;
    return ds && ds->Img() == img;
}

// the render area: the smallest of the bound targets (Direct3D 9 lets the depth surface be larger)
VkExtent2D Device::TargetExtent() const {
    VkExtent2D e{0, 0};
    bool any = false;
    auto take = [&](const Surface* s) {
        if (!s) return;
        uint32_t w = s->W(), h = s->H();
        e = any ? VkExtent2D{std::min(e.width, w), std::min(e.height, h)} : VkExtent2D{w, h};
        any = true;
    };
    for (Surface* s : rt) take(s);
    take(ds);
    return e;
}

// A Clear just before (clearColor ...) is the pass's load ops: the tiles start cleared instead of
// loaded and then drawn over. The depth surface is read-only in the pass when a draw samples it
// (wantDsReadOnly) and no clear writes it.
bool Device::BeginPass() {
    if (passActive && !(dirty & kDirtyTargets)) return true;
    EndPass();
    VkExtent2D ext = TargetExtent();
    bool loadClearColor = clearColor, loadClearDepth = clearDepth, loadClearStencil = clearStencil;
    clearColor = clearDepth = clearStencil = false;
    if (!ext.width || !ext.height) {
        static Once<> once;
        if (once.First()) Log("d3d9vk: a draw or clear with no render target or depth surface bound: skipped");
        return false;
    }
    bool srgb = st.rs[RS_SRGBWRITEENABLE] != 0;
    VkRenderingAttachmentInfo colors[4];
    uint32_t count = 0;
    for (uint32_t k = 0; k < 4; k++) {
        if (rt[k]) count = k + 1;
    }
    for (uint32_t k = 0; k < count; k++) {
        VkRenderingAttachmentInfo& a = colors[k];
        a = VkRenderingAttachmentInfo{VK_STRUCTURE_TYPE_RENDERING_ATTACHMENT_INFO};
        Surface* s = rt[k];
        Image* img = s ? s->Img() : nullptr;
        if (!img) continue;   // (the NULL format, or a hole: no writes)
        Transition(cmd, img, s->level, 1, s->layer, 1, VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL);
        a.imageView = TargetView(img, s->level, s->layer, srgb);
        a.imageLayout = img->layouts[img->Sub(s->level, s->layer)];
        a.loadOp = loadClearColor ? VK_ATTACHMENT_LOAD_OP_CLEAR : VK_ATTACHMENT_LOAD_OP_LOAD;
        a.storeOp = VK_ATTACHMENT_STORE_OP_STORE;
        a.clearValue.color = clearColorValue;
        img->lastUse = serial;
    }
    VkRenderingAttachmentInfo depth{VK_STRUCTURE_TYPE_RENDERING_ATTACHMENT_INFO};
    VkRenderingAttachmentInfo stencil{VK_STRUCTURE_TYPE_RENDERING_ATTACHMENT_INFO};
    Image* dimg = ds ? ds->Img() : nullptr;
    bool readOnly = dimg && wantDsReadOnly && !loadClearDepth && !loadClearStencil;
    if (readOnly != dsReadOnly) dirty |= kDirtyDepth | kDirtyStencil;   // (writes off while read-only)
    dsReadOnly = readOnly;
    if (dimg) {
        Transition(cmd, dimg, ds->level, 1, ds->layer, 1,
                   readOnly ? VK_IMAGE_LAYOUT_DEPTH_STENCIL_READ_ONLY_OPTIMAL : VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL);
        depth.imageView = TargetView(dimg, ds->level, ds->layer, false);
        depth.imageLayout = dimg->layouts[dimg->Sub(ds->level, ds->layer)];
        depth.loadOp = loadClearDepth ? VK_ATTACHMENT_LOAD_OP_CLEAR : VK_ATTACHMENT_LOAD_OP_LOAD;
        depth.storeOp = readOnly ? VK_ATTACHMENT_STORE_OP_NONE : VK_ATTACHMENT_STORE_OP_STORE;
        depth.clearValue.depthStencil = {clearDepthValue, clearStencilValue};
        if (dimg->fmt->stencil) {
            stencil = depth;
            stencil.loadOp = loadClearStencil ? VK_ATTACHMENT_LOAD_OP_CLEAR : VK_ATTACHMENT_LOAD_OP_LOAD;
        }
        dimg->lastUse = serial;
    }
    VkRenderingInfo ri{VK_STRUCTURE_TYPE_RENDERING_INFO};
    ri.renderArea = {{0, 0}, ext};
    ri.layerCount = 1;
    ri.colorAttachmentCount = count;
    ri.pColorAttachments = colors;
    ri.pDepthAttachment = dimg ? &depth : nullptr;
    ri.pStencilAttachment = dimg && dimg->fmt->stencil ? &stencil : nullptr;
    fn.CmdBeginRendering(cmd, &ri);
    passActive = true;
    // (the scissor is clipped to the render area; dynamic state outlives the pass otherwise)
    if (ext.width != passExtent.width || ext.height != passExtent.height) dirty |= kDirtyScissor;
    passExtent = ext;
    dirty &= ~kDirtyTargets;
    if (activeOcc && activeOcc->building) BeginOcclusion();
    return true;
}

void Device::EndPass() {
    if (!passActive) return;
    if (occOpen) EndOcclusion();   // (the query goes on in the next pass, in another Vulkan query)
    fn.CmdEndRendering(cmd);
    passActive = false;
}

// ---- occlusion queries: a Vulkan query per pass a D3D one spans, summed by GetData --------------------------
uint32_t Device::AllocOcclusion() {
    if (!occPool || occFree.empty()) return UINT32_MAX;
    uint32_t s = occFree.back();
    occFree.pop_back();
    fn.ResetQueryPool(device, occPool, s, 1);
    return s;
}

void Device::BeginOcclusion() {
    if (!occPool || !activeOcc || occOpen || !passActive) return;
    uint32_t s = AllocOcclusion();
    if (s == UINT32_MAX) {
        LogOnce("vk-occ-full", "d3d9vk: out of occlusion queries: a query counts less");
        return;
    }
    vkCmdBeginQuery(cmd, occPool, s, preciseOcclusion ? VK_QUERY_CONTROL_PRECISE_BIT : 0);
    activeOcc->slots.push_back(s);
    occOpen = true;
}

void Device::EndOcclusion() {
    if (!occOpen) return;
    if (activeOcc && !activeOcc->slots.empty()) vkCmdEndQuery(cmd, occPool, activeOcc->slots.back());
    occOpen = false;
}

// ---- vertex input -------------------------------------------------------------------------------------------
// an FVF as the vertex elements it stands for (made once per FVF)
const std::vector<Element32>& Device::FvfElements(uint32_t fvf) {
    auto it = fvfDecls.find(fvf);
    if (it != fvfDecls.end()) return it->second;
    std::vector<Element32> e;
    uint16_t off = 0;
    auto add = [&](uint8_t type, uint8_t usage, uint8_t index, uint16_t size) {
        e.push_back(Element32{0, off, type, 0, usage, index});
        off = static_cast<uint16_t>(off + size);
    };
    uint32_t pos = fvf & FVF_POSITION_MASK;
    if (pos == FVF_XYZRHW) add(DT_FLOAT4, DU_POSITIONT, 0, 16);
    else if (pos == FVF_XYZW) add(DT_FLOAT4, DU_POSITION, 0, 16);
    else if (pos) {
        add(DT_FLOAT3, DU_POSITION, 0, 12);
        // XYZB1..XYZB5: blend weights after the position, the last maybe indices
        uint32_t weights = pos >= 6 && pos <= 0xE ? (pos - 4) / 2 : 0;
        bool lastIndices = fvf & (FVF_LASTBETA_UBYTE4 | FVF_LASTBETA_D3DCOLOR);
        if (lastIndices && weights) weights--;
        static const uint8_t kFloats[5] = {DT_FLOAT1, DT_FLOAT1, DT_FLOAT2, DT_FLOAT3, DT_FLOAT4};
        if (weights) add(kFloats[weights], DU_BLENDWEIGHT, 0, static_cast<uint16_t>(4 * weights));
        if (lastIndices) add((fvf & FVF_LASTBETA_D3DCOLOR) ? DT_D3DCOLOR : DT_UBYTE4, DU_BLENDINDICES, 0, 4);
    }
    if (fvf & FVF_NORMAL) add(DT_FLOAT3, DU_NORMAL, 0, 12);
    if (fvf & FVF_PSIZE) add(DT_FLOAT1, DU_PSIZE, 0, 4);
    if (fvf & FVF_DIFFUSE) add(DT_D3DCOLOR, DU_COLOR, 0, 4);
    if (fvf & FVF_SPECULAR) add(DT_D3DCOLOR, DU_COLOR, 1, 4);
    uint32_t texCount = (fvf & FVF_TEXCOUNT_MASK) >> 8;
    for (uint32_t t = 0; t < texCount && t < 8; t++) {
        // D3DFVF_TEXCOORDSIZEn: 0 two floats, 1 three, 2 four, 3 one
        switch ((fvf >> (16 + 2 * t)) & 3) {
            case 0: add(DT_FLOAT2, DU_TEXCOORD, static_cast<uint8_t>(t), 8); break;
            case 1: add(DT_FLOAT3, DU_TEXCOORD, static_cast<uint8_t>(t), 12); break;
            case 2: add(DT_FLOAT4, DU_TEXCOORD, static_cast<uint8_t>(t), 16); break;
            default: add(DT_FLOAT1, DU_TEXCOORD, static_cast<uint8_t>(t), 4); break;
        }
    }
    return fvfDecls[fvf] = std::move(e);
}

// The vertex shader's inputs bound to the declaration's elements by (usage, index); an input no
// stream feeds reads the dummy buffer ((0, 0, 0, 1), or (1, 1, 1, 1) for the fixed function's colors)
bool Device::BuildLayout(const ShaderInfo& vsInfo, bool fixedVs, VertexLayout* out) {
    memset(out, 0, sizeof *out);
    const std::vector<Element32>& elems = st.decl ? st.decl->elems : FvfElements(st.fvf);
    for (const Input& in : vsInfo.inputs) {
        if (out->count == 16) break;
        const Element32* found = nullptr;
        for (const Element32& e : elems) {
            bool usage = e.usage == in.usage ||
                         (in.usage == DU_POSITION && e.usage == DU_POSITIONT) ||
                         (in.usage == 0xff && &e - elems.data() == in.reg);
            if (usage && (in.usage == 0xff || e.usageIndex == in.usageIndex)) {
                found = &e;
                break;
            }
        }
        VkFormat f = found ? DeclFormat(found->type) : VK_FORMAT_UNDEFINED;
        bool fed = found && f != VK_FORMAT_UNDEFINED && found->stream < kStreams &&
                   (upActive ? found->stream == 0 : st.streams[found->stream].vb != nullptr);
        auto& a = out->attrs[out->count++];
        a.location = in.location;
        if (fed) {
            a.binding = static_cast<uint8_t>(found->stream);
            a.offset = found->offset;
            a.format = f;
            out->bindings |= static_cast<uint16_t>(1u << found->stream);
            if (!upActive && (st.streams[found->stream].freq & kStreamInstance))
                out->instanced |= static_cast<uint16_t>(1u << found->stream);
        } else {
            a.binding = kDummyBinding;
            a.offset = fixedVs && in.usage == DU_COLOR ? 16 : 0;
            a.format = VK_FORMAT_R32G32B32A32_SFLOAT;
            out->bindings |= static_cast<uint16_t>(1u << kDummyBinding);
        }
    }
    return true;
}

// ---- a draw's state ------------------------------------------------------------------------------------------
// The textures the shaders sample, and what may end the pass for them (their mipmaps, their layouts):
// looked at again only when something they depend on changed (kDirtyTextures: a binding, a sampler
// state, the shaders, the targets, a layout an upload or copy moved, Z writes for the depth surface)
void Device::BindTextures(const ShaderInfo& vsInfo, const ShaderInfo& psInfo, bool fixedPs) {
    nBoundTex = 0;
    descValid = false;
    wantDsReadOnly = false;
    Image* dimg = ds ? ds->Img() : nullptr;
    bool dsWrites = DsWrites(*this);
    auto sample = [&](const ShaderInfo& info, bool vertex) {
        for (const Sampler& sm : info.samplers) {
            uint32_t idx = vertex ? 16 + sm.reg : sm.reg;
            if (idx >= kSamplers || nBoundTex == kSamplers) continue;
            Texture* t = st.tex[idx];
            Image* img = t ? t->st.img : nullptr;
            VkImageLayout layout = VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL;
            uint32_t want = sm.type == 3 ? RT_CUBETEXTURE : sm.type == 4 ? RT_VOLUMETEXTURE : RT_TEXTURE;
            if (img && t->Kind() != want) {
                static Once<> once;
                if (once.First(t->Kind() * 8 + want))
                    Log("d3d9vk: a texture of kind %u sampled as kind %u: the stand-in instead", t->Kind(), want);
                img = nullptr;
            }
            if (img && !(img->usage & VK_IMAGE_USAGE_SAMPLED_BIT)) {
                static Once<> once;
                if (once.First()) Log("d3d9vk: a texture of %s the GPU cannot sample: the stand-in", FormatName(img->fmt->d3d));
                img = nullptr;
            }
            if (img && img == dimg) {
                // (the depth surface, read as a texture while bound: valid read-only, as soft particles
                // and the like do on D3D9; while the draw writes depth or stencil, the stand-in)
                if (!dsWrites) {
                    layout = VK_IMAGE_LAYOUT_DEPTH_STENCIL_READ_ONLY_OPTIMAL;
                    wantDsReadOnly = true;
                } else {
                    static Once<> once;
                    if (once.First()) Log("d3d9vk: the depth surface sampled while depth writes are on: the stand-in instead");
                    img = nullptr;
                }
            } else if (img && IsTarget(img)) {
                static Once<> once;
                if (once.First()) Log("d3d9vk: a texture sampled while bound as a render target: the stand-in instead");
                img = nullptr;
            }
            if (img && layout == VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL && t->st.mipsDirty &&
                (t->st.usage & U_AUTOGENMIPMAP)) {
                GenerateMips(img);
                t->st.mipsDirty = false;
            }
            VkImageView view = VK_NULL_HANDLE;
            if (img) {
                if (layout == VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL) {
                    if (img->general) layout = VK_IMAGE_LAYOUT_GENERAL;
                    for (VkImageLayout l : img->layouts)
                        if (l != layout) {
                            EndPass();
                            TransitionAll(cmd, img, VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL);
                            break;
                        }
                }
                view = SampleView(img, st.ss[idx][SS_SRGBTEXTURE] != 0);
                img->lastUse = serial;
            }
            VkSampler sampler;
            if (view) {
                sampler = GetSampler(st.ss[idx], img->fmt->filter, t->lod);
            } else {
                Image* stand = sm.type == 3 ? blackCube : sm.type == 4 ? black3D : (fixedPs && !vertex ? white2D : black2D);
                view = SampleView(stand, false);
                sampler = GetSampler(st.ss[idx], true, 0);
                layout = VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL;
            }
            boundTex[nBoundTex++] = {(vertex ? 18u : 2u) + sm.reg, view, sampler, layout};
        }
    };
    sample(psInfo, false);
    sample(vsInfo, true);
}

void Device::ResetBindings() {
    boundPipeline = VK_NULL_HANDLE;
    lastKeyValid = false;
    vsBlockSize = psBlockSize = 0;
    descValid = pushValid = false;
    lastTopology = ~0u;
    for (uint32_t b = 0; b < 16; b++) vbBound[b] = VK_NULL_HANDLE;
    ibBound = VK_NULL_HANDLE;
    dsReadOnly = false;
}

bool Device::PrepareDraw(uint32_t primitive, bool indexed, uint32_t* instances) {
    if (lost) return false;
    if (!fn.CmdPushDescriptorSet || !fn.CmdBeginRendering) {
        static Once<> once;
        if (once.First()) Log("d3d9vk: no push descriptors or dynamic rendering: nothing is drawn");
        return false;
    }
    Shader* vs = st.vs;
    Shader* ps = st.ps;
    if ((vs && !vs->module) || (ps && !ps->module)) return false;   // (a shader that did not translate, logged then)
    bool fixedVs = !vs, fixedPs = !ps;
    const ShaderInfo& vsInfo = fixedVs ? ffVsInfo : vs->info;
    const ShaderInfo& psInfo = fixedPs ? ffPsInfo : ps->info;

    // 1. what may end the pass: the textures' mipmaps and layouts
    if (dirty & kDirtyTextures) {
        BindTextures(vsInfo, psInfo, fixedPs);
        dirty &= ~kDirtyTextures;   // (what the pass's begin moves below marks the next draw's)
    }

    // 2. the pass: again when the targets changed, or the depth surface's read-only use does
    if (passActive && ((wantDsReadOnly && !dsReadOnly) || (!wantDsReadOnly && dsReadOnly && DsWrites(*this))))
        dirty |= kDirtyTargets;
    if (!BeginPass()) return false;

    // 3. the pipeline, when its state changed
    uint8_t topologyClass = TopologyClass(primitive);
    if ((dirty & kDirtyPipeline) || !lastKeyValid || lastKey.topologyClass != topologyClass) {
        PipelineKey key;
        memset(&key, 0, sizeof key);
        key.vs = fixedVs ? kFixedVsId : vs->id;
        key.ps = fixedPs ? kFixedPsId : ps->id;
        BuildLayout(vsInfo, fixedVs, &key.layout);
        bool srgb = st.rs[RS_SRGBWRITEENABLE] != 0;
        uint32_t colorCount = 0;
        for (uint32_t k = 0; k < 4; k++) {
            if (!rt[k]) continue;
            colorCount = k + 1;
            if (Image* img = rt[k]->Img()) {
                key.colorFormats[k] = srgb && img->fmt->srgb != VK_FORMAT_UNDEFINED ? img->fmt->srgb : img->format;
                if (img->fmt->alphaOne) key.alphaOne |= static_cast<uint8_t>(1u << k);
            }
        }
        key.colorCount = static_cast<uint8_t>(colorCount);
        if (Image* d = ds ? ds->Img() : nullptr) {
            key.depthFormat = d->format;
            if (d->fmt->stencil) key.stencilFormat = d->format;
        }
        key.blend = PackBlend();
        WriteMasks(key.writeMask);
        key.topologyClass = topologyClass;
        uint32_t fill = st.rs[RS_FILLMODE];
        key.polygonMode = static_cast<uint8_t>(!fillNonSolid || fill == 3 ? VK_POLYGON_MODE_FILL
                                               : fill == 2              ? VK_POLYGON_MODE_LINE
                                                                        : VK_POLYGON_MODE_POINT);
        VkPipeline pipeline = GetPipeline(key, fixedVs ? ffVs : vs->module, fixedPs ? ffPs : ps->module);
        if (!pipeline) return false;
        if (pipeline != boundPipeline) {
            vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_GRAPHICS, pipeline);
            boundPipeline = pipeline;
        }
        lastKey = key, lastKeyValid = true;
    }
    const PipelineKey& key = lastKey;

    // 4. dynamic state
    if (dirty & kDirtyViewport) {
        // (D3D9's pixel centers are at integer coordinates, Vulkan's at +0.5: the viewport moved half a
        // pixel right and down, as DXVK does, so D3D9's geometry covers the same pixels. A full-screen
        // pass otherwise left the last column and row unwritten, their old contents showing: a bright
        // right and bottom edge on FFXIV's title screen)
        const Viewport& v = st.vp;
        VkViewport vv{float(v.x) + 0.5f, float(v.y) + 0.5f, float(std::max(1u, v.w)), float(std::max(1u, v.h)),
                      v.minZ, v.maxZ};
        vkCmdSetViewport(cmd, 0, 1, &vv);
        dirty |= kDirtyPush;
    }
    if (dirty & (kDirtyScissor | kDirtyViewport)) {
        // (D3D9 writes no pixel outside the viewport: a wide point or line near its edge either)
        const Viewport& v = st.vp;
        Rect r{int32_t(v.x), int32_t(v.y), int32_t(v.x + v.w), int32_t(v.y + v.h)};
        if (st.rs[RS_SCISSORTESTENABLE]) r = Intersect(r, st.scissor);
        if (!Clip(r, passExtent.width, passExtent.height)) r = Rect{0, 0, 0, 0};
        VkRect2D sc{{r.left, r.top}, {uint32_t(std::max(0, r.right - r.left)), uint32_t(std::max(0, r.bottom - r.top))}};
        vkCmdSetScissor(cmd, 0, 1, &sc);
    }
    if (dirty & kDirtyCull) {
        // (front is clockwise, as D3D9's default; the vertex shader's Y flip keeps the winding on screen)
        uint32_t cull = st.rs[RS_CULLMODE];
        fn.CmdSetFrontFace(cmd, VK_FRONT_FACE_CLOCKWISE);
        fn.CmdSetCullMode(cmd, cull == 2 ? VK_CULL_MODE_FRONT_BIT : cull == 3 ? VK_CULL_MODE_BACK_BIT : VK_CULL_MODE_NONE);
    }
    if (uint32_t topology = Topology(primitive); topology != lastTopology) {
        fn.CmdSetPrimitiveTopology(cmd, static_cast<VkPrimitiveTopology>(topology));
        lastTopology = topology;
    }
    bool hasDepth = key.depthFormat != VK_FORMAT_UNDEFINED, hasStencil = key.stencilFormat != VK_FORMAT_UNDEFINED;
    if (dirty & (kDirtyDepth | kDirtyTargets)) {
        fn.CmdSetDepthTestEnable(cmd, hasDepth && st.rs[RS_ZENABLE] != 0);
        fn.CmdSetDepthWriteEnable(cmd, hasDepth && st.rs[RS_ZWRITEENABLE] != 0 && !dsReadOnly);
        fn.CmdSetDepthCompareOp(cmd, CompareOp(st.rs[RS_ZFUNC]));
    }
    if (dirty & (kDirtyStencil | kDirtyTargets)) {
        const uint32_t* rs = st.rs;
        bool on = hasStencil && rs[RS_STENCILENABLE] != 0;
        fn.CmdSetStencilTestEnable(cmd, on);
        fn.CmdSetStencilOp(cmd, VK_STENCIL_FACE_FRONT_BIT, StencilOp(rs[RS_STENCILFAIL]), StencilOp(rs[RS_STENCILPASS]),
                           StencilOp(rs[RS_STENCILZFAIL]), CompareOp(rs[RS_STENCILFUNC]));
        if (rs[RS_TWOSIDEDSTENCILMODE])
            fn.CmdSetStencilOp(cmd, VK_STENCIL_FACE_BACK_BIT, StencilOp(rs[RS_CCW_STENCILFAIL]),
                               StencilOp(rs[RS_CCW_STENCILPASS]), StencilOp(rs[RS_CCW_STENCILZFAIL]),
                               CompareOp(rs[RS_CCW_STENCILFUNC]));
        else
            fn.CmdSetStencilOp(cmd, VK_STENCIL_FACE_BACK_BIT, StencilOp(rs[RS_STENCILFAIL]), StencilOp(rs[RS_STENCILPASS]),
                               StencilOp(rs[RS_STENCILZFAIL]), CompareOp(rs[RS_STENCILFUNC]));
        vkCmdSetStencilCompareMask(cmd, VK_STENCIL_FACE_FRONT_AND_BACK, rs[RS_STENCILMASK] & 0xff);
        vkCmdSetStencilWriteMask(cmd, VK_STENCIL_FACE_FRONT_AND_BACK, dsReadOnly ? 0 : rs[RS_STENCILWRITEMASK] & 0xff);
        vkCmdSetStencilReference(cmd, VK_STENCIL_FACE_FRONT_AND_BACK, rs[RS_STENCILREF] & 0xff);
    }
    if (dirty & (kDirtyBias | kDirtyTargets)) {
        float bias = AsFloat(st.rs[RS_DEPTHBIAS]), slope = AsFloat(st.rs[RS_SLOPESCALEDEPTHBIAS]);
        // (D3D9's bias is in depth units: Vulkan's constant factor counts the format's smallest step)
        float scale = key.depthFormat == VK_FORMAT_D16_UNORM ? 65535.0f : 16777215.0f;
        bool on = bias != 0 || slope != 0;
        fn.CmdSetDepthBiasEnable(cmd, on);
        vkCmdSetDepthBias(cmd, bias * scale, 0, slope);
    }
    if (dirty & kDirtyBlendConst) {
        VkClearColorValue c = ColorOf(st.rs[RS_BLENDFACTOR]);
        vkCmdSetBlendConstants(cmd, c.float32);
    }

    // 5. the uniform blocks: a new one when the constants (or the shader) changed, filled as far as
    // the shader reads it (ShaderInfo::floatConsts, its i and b only when it reads them)
    VkDeviceSize align = std::max<VkDeviceSize>(16, vk->props.limits.minUniformBufferOffsetAlignment);
    bool blocksChanged = false;
    auto fill = [](uint8_t* p, const ShaderInfo& info, const float (*f)[4], uint32_t count, uint32_t high,
                   const int32_t (*iv)[4], const uint32_t* bv) {
        uint32_t n = std::min(info.floatConsts, count), copied = std::min(n, high);
        memcpy(p, f, copied * 16);
        if (n > copied) memset(p + copied * 16, 0, (n - copied) * 16);   // (never set: zero)
        if (info.intConsts) memcpy(p + count * 16, iv, 16 * 16);
        if (info.boolConsts)
            for (uint32_t k = 0; k < 16; k++) {
                uint32_t b[4] = {bv[k] ? 1u : 0u, 0, 0, 0};
                memcpy(p + count * 16 + 256 + 16 * k, b, 16);
            }
    };
    if ((fixedVs ? (dirty & kDirtyFixed) : (dirty & kDirtyVsConst)) || !vsBlockSize || lastFixedVs != fixedVs) {
        uint32_t size = fixedVs ? kFixedVsBytes : kVsBlockBytes;
        vsBlock = Ring(size, align);
        if (!vsBlock.ptr) return false;
        if (fixedVs) {
            float c[16][4];
            FixedVertexConstants(st, st.fvf, c);
            memcpy(vsBlock.ptr, c, sizeof c);
        } else {
            fill(vsBlock.ptr, vsInfo, st.vsF, kVsConsts, vsHigh, st.vsI, st.vsB);
        }
        vsBlockSize = size;
        lastFixedVs = fixedVs;
        blocksChanged = true;
    }
    if ((fixedPs ? (dirty & kDirtyFixed) : (dirty & kDirtyPsConst)) || !psBlockSize || lastFixedPs != fixedPs) {
        uint32_t size = fixedPs ? kFixedPsBytes : kPsBlockBytes;
        psBlock = Ring(size, align);
        if (!psBlock.ptr) return false;
        if (fixedPs) {
            float c[16][4];
            FixedPixelConstants(st, st.tex[0] != nullptr, c);
            memcpy(psBlock.ptr, c, sizeof c);
        } else {
            fill(psBlock.ptr, psInfo, st.psF, kPsConsts, psHigh, st.psI, st.psB);
        }
        psBlockSize = size;
        lastFixedPs = fixedPs;
        blocksChanged = true;
    }

    // 6. the descriptors, pushed when a block or a texture changed (push descriptors outlive pipeline
    // binds of the one layout and the passes)
    if (!descValid || blocksChanged) {
        VkDescriptorBufferInfo blocks[2] = {{vsBlock.buffer, vsBlock.offset, vsBlockSize},
                                            {psBlock.buffer, psBlock.offset, psBlockSize}};
        VkDescriptorImageInfo images[kSamplers];
        VkWriteDescriptorSet writes[2 + kSamplers];
        uint32_t nw = 0;
        for (uint32_t k = 0; k < 2; k++) {
            VkWriteDescriptorSet& w = writes[nw++];
            w = VkWriteDescriptorSet{VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET};
            w.dstBinding = k;
            w.descriptorCount = 1;
            w.descriptorType = VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER;
            w.pBufferInfo = &blocks[k];
        }
        for (uint32_t k = 0; k < nBoundTex; k++) {
            images[k] = {boundTex[k].sampler, boundTex[k].view, boundTex[k].layout};
            VkWriteDescriptorSet& w = writes[nw++];
            w = VkWriteDescriptorSet{VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET};
            w.dstBinding = boundTex[k].binding;
            w.descriptorCount = 1;
            w.descriptorType = VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER;
            w.pImageInfo = &images[k];
        }
        fn.CmdPushDescriptorSet(cmd, VK_PIPELINE_BIND_POINT_GRAPHICS, pipelineLayout, 0, nw, writes);
        descValid = true;
    }

    // 7. the push constants (Shader.h), when they changed
    struct {
        float viewport[4];
        uint32_t alphaFunc;
        float alphaRef;
        uint32_t flags, pad;
    } push{};
    // (no offset in the shaders: the half pixel is the viewport's, above; Shader.h's moved the other way)
    push.viewport[0] = 0.0f;
    push.viewport[1] = 0.0f;
    float pointMin = AsFloat(st.rs[RS_POINTSIZE_MIN]), pointMax = AsFloat(st.rs[RS_POINTSIZE_MAX]);
    push.viewport[2] = std::min(std::max(AsFloat(st.rs[RS_POINTSIZE]), pointMin), pointMax);
    push.viewport[3] = pointMax;
    push.alphaFunc = st.rs[RS_ALPHATESTENABLE] ? st.rs[RS_ALPHAFUNC] : 8;
    push.alphaRef = float(st.rs[RS_ALPHAREF] & 0xff) / 255.0f;
    push.flags = 1;   // (always: D3D's top-left origin is Vulkan's framebuffer's too, its clip Y is not)
    if (primitive == 1 && st.rs[RS_POINTSPRITEENABLE]) push.flags |= 2;
    static_assert(sizeof push == 32, "Shader.h's push constants");
    if (!pushValid || memcmp(&push, lastPush, sizeof push) != 0) {
        vkCmdPushConstants(cmd, pipelineLayout, VK_SHADER_STAGE_VERTEX_BIT | VK_SHADER_STAGE_FRAGMENT_BIT, 0, sizeof push,
                           &push);
        memcpy(lastPush, &push, sizeof push);
        pushValid = true;
    }

    // 8. the vertex and index buffers, bound when they changed
    *instances = 1;
    if (indexed && !upActive && (st.streams[0].freq & kStreamIndexed)) *instances = std::max(1u, st.streams[0].freq & 0x3fffffffu);
    for (uint32_t b = 0; b < 16; b++) {
        if (!(key.layout.bindings & (1u << b))) continue;
        VkBuffer buf = VK_NULL_HANDLE;
        VkDeviceSize off = 0, stride = 0;
        if (b == kDummyBinding && !(st.streams[b].vb && !upActive)) {
            buf = dummyVb;
        } else if (upActive) {
            buf = upVb.buffer, off = upVb.offset, stride = st.streams[0].stride;
        } else {
            Stream& s = st.streams[b];
            s.vb->Use(&buf, &off);
            off += s.offset;
            stride = s.stride;
        }
        if (buf != vbBound[b] || off != vbOffset[b] || stride != vbStride[b]) {
            fn.CmdBindVertexBuffers2(cmd, b, 1, &buf, &off, nullptr, &stride);
            vbBound[b] = buf, vbOffset[b] = off, vbStride[b] = stride;
        }
    }
    if (indexed) {
        VkBuffer buf;
        VkDeviceSize off;
        VkIndexType type;
        if (upActive) {
            buf = upIb.buffer, off = upIb.offset, type = upIndex32 ? VK_INDEX_TYPE_UINT32 : VK_INDEX_TYPE_UINT16;
        } else {
            if (!st.ib) return false;
            st.ib->Use(&buf, &off);
            type = st.ib->format == F_INDEX32 ? VK_INDEX_TYPE_UINT32 : VK_INDEX_TYPE_UINT16;
        }
        if (buf != ibBound || off != ibOffset || type != ibType) {
            vkCmdBindIndexBuffer(cmd, buf, off, type);
            ibBound = buf, ibOffset = off, ibType = type;
        }
    }

    dirty &= ~(kDirtyPipeline | kDirtyViewport | kDirtyScissor | kDirtyDepth | kDirtyStencil | kDirtyCull | kDirtyBias |
               kDirtyBlendConst | kDirtyVsConst | kDirtyPsConst | kDirtyStreams | kDirtyIndices | kDirtyPush |
               kDirtyFixed);
    if (draws++ == 0) Log("d3d9vk: the first draw (%s vertex shader, %s pixel shader, %u targets)",
                          fixedVs ? "fixed" : "a", fixedPs ? "fixed" : "a", key.colorCount);
    frameDraws++;
    return true;
}

// ---- the draws ---------------------------------------------------------------------------------------------
uint32_t Device::DrawPrimitive(uint32_t type, uint32_t start, uint32_t count) {
    std::lock_guard<std::recursive_mutex> hold(mu);
    uint32_t n = VertexCount(type, count), instances = 1;
    if (!n || !PrepareDraw(type, false, &instances)) return D3D_OK;
    vkCmdDraw(cmd, n, instances, start, 0);
    return D3D_OK;
}

uint32_t Device::DrawIndexedPrimitive(uint32_t type, int32_t base, uint32_t, uint32_t, uint32_t startIndex,
                                      uint32_t count) {
    std::lock_guard<std::recursive_mutex> hold(mu);
    uint32_t n = VertexCount(type, count), instances = 1;
    if (!n || !PrepareDraw(type, true, &instances)) return D3D_OK;
    vkCmdDrawIndexed(cmd, n, instances, startIndex, base, 0);
    return D3D_OK;
}

// (Direct3D 9 leaves stream 0, and the indices for the indexed one, unset after an UP draw)
uint32_t Device::DrawPrimitiveUP(uint32_t type, uint32_t count, uint32_t data, uint32_t stride) {
    std::lock_guard<std::recursive_mutex> hold(mu);
    uint32_t n = VertexCount(type, count), instances = 1;
    if (!n || !data || !stride) return D3DERR_INVALIDCALL;
    upVb = Ring(static_cast<VkDeviceSize>(n) * stride, 16);
    if (!upVb.ptr) return D3D_OK;
    memcpy(upVb.ptr, At(data), static_cast<size_t>(n) * stride);
    Hold(st.streams[0].vb, static_cast<Buffer*>(nullptr));
    st.streams[0].offset = 0, st.streams[0].stride = stride;
    upActive = true, upIndexed = false;
    dirty |= kDirtyPipeline | kDirtyStreams;
    if (PrepareDraw(type, false, &instances)) vkCmdDraw(cmd, n, 1, 0, 0);
    upActive = false;
    st.streams[0].stride = 0;
    dirty |= kDirtyPipeline | kDirtyStreams;
    return D3D_OK;
}

uint32_t Device::DrawIndexedPrimitiveUP(uint32_t type, uint32_t minIndex, uint32_t numVertices, uint32_t count,
                                        uint32_t indices, uint32_t indexFormat, uint32_t data, uint32_t stride) {
    std::lock_guard<std::recursive_mutex> hold(mu);
    uint32_t n = VertexCount(type, count), instances = 1;
    if (!n || !data || !stride || !indices) return D3DERR_INVALIDCALL;
    uint32_t vertices = minIndex + numVertices, isize = indexFormat == F_INDEX32 ? 4 : 2;
    upVb = Ring(static_cast<VkDeviceSize>(vertices) * stride, 16);
    upIb = Ring(static_cast<VkDeviceSize>(n) * isize, 16);
    if (!upVb.ptr || !upIb.ptr) return D3D_OK;
    memcpy(upVb.ptr, At(data), static_cast<size_t>(vertices) * stride);
    memcpy(upIb.ptr, At(indices), static_cast<size_t>(n) * isize);
    Hold(st.streams[0].vb, static_cast<Buffer*>(nullptr));
    Hold(st.ib, static_cast<Buffer*>(nullptr));
    st.streams[0].offset = 0, st.streams[0].stride = stride;
    upActive = true, upIndexed = true, upIndex32 = isize == 4;
    dirty |= kDirtyPipeline | kDirtyStreams | kDirtyIndices;
    if (PrepareDraw(type, true, &instances)) vkCmdDrawIndexed(cmd, n, 1, 0, 0, 0);
    upActive = false;
    st.streams[0].stride = 0;
    dirty |= kDirtyPipeline | kDirtyStreams | kDirtyIndices;
    return D3D_OK;
}

// ---- Clear: inside the pass, the viewport's rectangle (and the rects, and the scissor) --------------------------
// D3DCLEAR_TARGET 1, ZBUFFER 2, STENCIL 4
// A clear of the whole render area with no pass begun (or one to begin again) is the pass's load ops
uint32_t Device::Clear(uint32_t count, uint32_t rects, uint32_t flags, uint32_t color, uint32_t zBits, uint32_t stencil) {
    std::lock_guard<std::recursive_mutex> hold(mu);
    if (lost) return D3D_OK;
    Image* dimg = ds ? ds->Img() : nullptr;
    bool doColor = false;
    if (flags & 1)
        for (Surface* s : rt)
            if (s && s->Img()) doColor = true;
    bool doDepth = (flags & 2) && dimg, doStencil = (flags & 4) && dimg && dimg->fmt->stencil;
    if (!doColor && !doDepth && !doStencil) return D3D_OK;
    if ((doDepth || doStencil) && (dsReadOnly || wantDsReadOnly)) {   // (a clear writes it: not read-only)
        wantDsReadOnly = false;
        if (dsReadOnly) dirty |= kDirtyTargets;
        dirty |= kDirtyTextures;
    }
    float z = std::min(1.0f, std::max(0.0f, AsFloat(zBits)));
    Rect area{int32_t(st.vp.x), int32_t(st.vp.y), int32_t(st.vp.x + st.vp.w), int32_t(st.vp.y + st.vp.h)};
    if (st.rs[RS_SCISSORTESTENABLE]) area = Intersect(area, st.scissor);
    if ((!passActive || (dirty & kDirtyTargets)) && !(count && rects)) {
        VkExtent2D ext = TargetExtent();
        Rect r = area;
        if (Clip(r, ext.width, ext.height) && r.left == 0 && r.top == 0 && r.right == int32_t(ext.width) &&
            r.bottom == int32_t(ext.height)) {
            clearColor = doColor, clearDepth = doDepth, clearStencil = doStencil;
            clearColorValue = ColorOf(color), clearDepthValue = z, clearStencilValue = stencil & 0xff;
            BeginPass();
            return D3D_OK;
        }
    }
    if (!BeginPass()) return D3D_OK;
    VkClearAttachment atts[5];
    uint32_t na = 0;
    if (doColor) {
        for (uint32_t k = 0; k < 4; k++) {
            if (!rt[k] || !rt[k]->Img()) continue;
            VkClearAttachment& a = atts[na++];
            a = VkClearAttachment{VK_IMAGE_ASPECT_COLOR_BIT, k, {}};
            a.clearValue.color = ColorOf(color);
        }
    }
    VkImageAspectFlags aspects = (doDepth ? VK_IMAGE_ASPECT_DEPTH_BIT : 0) | (doStencil ? VK_IMAGE_ASPECT_STENCIL_BIT : 0);
    if (aspects) {
        VkClearAttachment& a = atts[na++];
        a = VkClearAttachment{aspects, 0, {}};
        a.clearValue.depthStencil = {z, stencil & 0xff};
    }
    VkClearRect out[16];
    uint32_t n = 0;
    auto flush = [&]() {
        if (n) vkCmdClearAttachments(cmd, na, atts, n, out);
        n = 0;
    };
    auto add = [&](Rect r) {
        r = Intersect(r, area);
        if (!Clip(r, passExtent.width, passExtent.height)) return;
        out[n++] = {{{r.left, r.top}, {uint32_t(r.right - r.left), uint32_t(r.bottom - r.top)}}, 0, 1};
        if (n == 16) flush();
    };
    if (count && rects)
        for (uint32_t k = 0; k < count; k++) add(RectAt(rects + 16 * k));
    else
        add(area);
    flush();
    return D3D_OK;
}

// ---- copies between surfaces ------------------------------------------------------------------------------------
uint32_t Device::ColorFill(uint32_t surface, uint32_t rect, uint32_t color) {
    std::lock_guard<std::recursive_mutex> hold(mu);
    Surface* s = Native<Surface>(surface);
    if (!s) return D3DERR_INVALIDCALL;
    Image* img = s->Img();
    if (!img || img->fmt->depth) return D3DERR_INVALIDCALL;
    if (lost) return D3D_OK;
    Rect r{0, 0, int32_t(s->W()), int32_t(s->H())};
    if (rect) r = RectAt(rect);
    if (!Clip(r, s->W(), s->H())) return D3D_OK;
    EndPass();
    Transition(cmd, img, s->level, 1, s->layer, 1, VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL);
    VkImageLayout layout = img->layouts[img->Sub(s->level, s->layer)];
    const FormatInfo* f = img->fmt;
    if (f->bytes == 4 && f->vkBytes == 4 && !f->convert && !f->vkBlock) {
        // (the word as the format holds it: copied in, so a rectangle and any channel order work)
        uint32_t w = uint32_t(r.right - r.left), h = uint32_t(r.bottom - r.top);
        RingSlice slice = Ring(static_cast<VkDeviceSize>(w) * h * 4, 16);
        if (!slice.ptr) return D3D_OK;
        for (uint32_t k = 0; k < w * h; k++) memcpy(slice.ptr + 4 * k, &color, 4);
        VkBufferImageCopy c{};
        c.bufferOffset = slice.offset;
        c.imageSubresource = {VK_IMAGE_ASPECT_COLOR_BIT, s->level, s->layer, 1};
        c.imageOffset = {r.left, r.top, 0};
        c.imageExtent = {w, h, 1};
        vkCmdCopyBufferToImage(cmd, slice.buffer, img->image, layout, 1, &c);
    } else {
        if (rect) LogOnce("vk-colorfill-rect", "d3d9vk: ColorFill of a rectangle of %s: the whole surface", FormatName(f->d3d));
        VkClearColorValue v = ColorOf(color);
        VkImageSubresourceRange range{VK_IMAGE_ASPECT_COLOR_BIT, s->level, 1, s->layer, 1};
        vkCmdClearColorImage(cmd, img->image, layout, &v, 1, &range);
    }
    img->lastUse = serial;
    return D3D_OK;
}

uint32_t Device::StretchRect(uint32_t src, uint32_t srcRect, uint32_t dst, uint32_t dstRect, uint32_t filter) {
    std::lock_guard<std::recursive_mutex> hold(mu);
    Surface* s = Native<Surface>(src);
    Surface* d = Native<Surface>(dst);
    if (!s || !d) return D3DERR_INVALIDCALL;
    Image* si = s->Img();
    Image* di = d->Img();
    if (!si || !di) {
        LogOnce("vk-stretch-cpu", "d3d9vk: StretchRect with a surface that has no image (system memory, or NULL)");
        return D3DERR_INVALIDCALL;
    }
    if (si == di && s->level == d->level && s->layer == d->layer) return D3DERR_INVALIDCALL;   // (D3D9's rule too)
    if (lost) return D3D_OK;
    Rect sr{0, 0, int32_t(s->W()), int32_t(s->H())}, dr{0, 0, int32_t(d->W()), int32_t(d->H())};
    if (srcRect) sr = RectAt(srcRect);
    if (dstRect) dr = RectAt(dstRect);
    if (!Clip(sr, s->W(), s->H()) || !Clip(dr, d->W(), d->H())) return D3D_OK;
    EndPass();
    Transition(cmd, si, s->level, 1, s->layer, 1, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL);
    Transition(cmd, di, d->level, 1, d->layer, 1, VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL);
    VkImageLayout sl = si->layouts[si->Sub(s->level, s->layer)], dl = di->layouts[di->Sub(d->level, d->layer)];
    int32_t sw = sr.right - sr.left, sh = sr.bottom - sr.top, dw = dr.right - dr.left, dh = dr.bottom - dr.top;
    bool same = sw == dw && sh == dh && si->format == di->format;
    if (same || si->fmt->depth) {
        if (!same) {
            LogOnce("vk-stretch-depth", "d3d9vk: StretchRect of a depth surface that scales or converts: skipped");
            return D3D_OK;
        }
        VkImageCopy c{};
        c.srcSubresource = {si->aspect, s->level, s->layer, 1};
        c.srcOffset = {sr.left, sr.top, 0};
        c.dstSubresource = {di->aspect, d->level, d->layer, 1};
        c.dstOffset = {dr.left, dr.top, 0};
        c.extent = {uint32_t(sw), uint32_t(sh), 1};
        vkCmdCopyImage(cmd, si->image, sl, di->image, dl, 1, &c);
    } else if (si->fmt->blit && di->fmt->blit) {
        VkImageBlit b{};
        b.srcSubresource = {si->aspect, s->level, s->layer, 1};
        b.srcOffsets[0] = {sr.left, sr.top, 0};
        b.srcOffsets[1] = {sr.right, sr.bottom, 1};
        b.dstSubresource = {di->aspect, d->level, d->layer, 1};
        b.dstOffsets[0] = {dr.left, dr.top, 0};
        b.dstOffsets[1] = {dr.right, dr.bottom, 1};
        bool linear = filter >= 2 && si->fmt->filter;   // D3DTEXF_LINEAR 2 (and above)
        vkCmdBlitImage(cmd, si->image, sl, di->image, dl, 1, &b, linear ? VK_FILTER_LINEAR : VK_FILTER_NEAREST);
    } else {
        static Once<4> once;
        if (once.First(si->fmt->d3d * 31 + di->fmt->d3d))
            Log("d3d9vk: StretchRect %s to %s cannot blit: skipped", FormatName(si->fmt->d3d), FormatName(di->fmt->d3d));
        return D3D_OK;
    }
    si->lastUse = di->lastUse = serial;
    if (d->container && (d->container->st.usage & U_AUTOGENMIPMAP)) d->container->st.mipsDirty = true, dirty |= kDirtyTextures;
    return D3D_OK;
}

// a system-memory surface's texels into a default-pool one
uint32_t Device::UpdateSurface(uint32_t src, uint32_t srcRect, uint32_t dst, uint32_t dstPoint) {
    Surface* s;
    Surface* d;
    {
        std::lock_guard<std::recursive_mutex> hold(mu);
        s = Native<Surface>(src), d = Native<Surface>(dst);
        if (!s || !d || !s->st->cpuOnly || !d->Img() || s->Fmt() != d->Fmt()) return D3DERR_INVALIDCALL;
    }
    Rect r{0, 0, int32_t(s->W()), int32_t(s->H())};
    if (srcRect) r = RectAt(srcRect);
    if (!Clip(r, s->W(), s->H())) return D3D_OK;
    int32_t p[2] = {0, 0};
    if (dstPoint) memcpy(p, At(dstPoint), 8);
    const FormatInfo* f = s->Fmt();
    uint32_t pitch = s->st->Pitch(s->level);
    const uint8_t* base = At<uint8_t>(s->st->CpuMem(s->level, s->layer)) + (r.top / f->blockH) * pitch +
                          (r.left / f->blockW) * f->bytes;
    UploadRegion(d->st, d->level, d->layer, uint32_t(p[0]), uint32_t(p[1]), 0, uint32_t(r.right - r.left),
                 uint32_t(r.bottom - r.top), 1, base, pitch, 0);
    return D3D_OK;
}

// a system-memory texture's levels into a default-pool one (the source's extra top levels skipped)
uint32_t Device::UpdateTexture(uint32_t src, uint32_t dst) {
    Texture* s;
    Texture* d;
    {
        std::lock_guard<std::recursive_mutex> hold(mu);
        s = Native<Texture>(src), d = Native<Texture>(dst);
        if (!s || !d || !s->st.cpuOnly || !d->st.img || s->Kind() != d->Kind() || s->st.fmt != d->st.fmt)
            return D3DERR_INVALIDCALL;
    }
    uint32_t skip = 0;
    while (skip < s->st.levels && s->st.W(skip) > d->st.W(0)) skip++;
    bool autogen = d->st.usage & U_AUTOGENMIPMAP;
    uint32_t levels = autogen ? 1 : std::min(d->st.levels, s->st.levels - skip);
    for (uint32_t layer = 0; layer < d->st.layers && layer < s->st.layers; layer++)
        for (uint32_t l = 0; l < levels; l++) {
            uint32_t sl = l + skip;
            const uint8_t* texels = At<uint8_t>(s->st.CpuMem(sl, layer));
            uint32_t pitch = s->st.Pitch(sl);
            UploadRegion(&d->st, l, layer, 0, 0, 0, s->st.W(sl), s->st.H(sl), s->st.D(sl), texels, pitch,
                         pitch * s->st.Rows(sl));
        }
    if (autogen) {
        std::lock_guard<std::recursive_mutex> hold(mu);
        d->st.mipsDirty = true;
        dirty |= kDirtyTextures;
    }
    return D3D_OK;
}

// a render target's texels into a system-memory surface (the GPU waited for)
uint32_t Device::GetRenderTargetData(uint32_t rtSurface, uint32_t dst) {
    std::lock_guard<std::recursive_mutex> hold(mu);
    Surface* r = Native<Surface>(rtSurface);
    Surface* d = Native<Surface>(dst);
    if (!r || !d || !r->Img() || !d->st->cpuOnly) return D3DERR_INVALIDCALL;
    uint8_t* out = At<uint8_t>(d->st->CpuMem(d->level, d->layer));
    if (!ReadRegion(r->Img(), r->level, r->layer, std::min(r->W(), d->W()), std::min(r->H(), d->H()), out,
                    d->st->Pitch(d->level)))
        return D3DERR_INVALIDCALL;
    return D3D_OK;
}

// the front buffer as the implicit swap chain's back buffer last presented it
uint32_t Device::GetFrontBufferData(uint32_t, uint32_t dst) {
    Surface* bb;
    {
        std::lock_guard<std::recursive_mutex> hold(mu);
        bb = implicit ? implicit->backBuffer : nullptr;
        if (!bb) return D3DERR_INVALIDCALL;
    }
    return GetRenderTargetData(bb->self, dst);
}

}  // namespace rh::d3d9vk
