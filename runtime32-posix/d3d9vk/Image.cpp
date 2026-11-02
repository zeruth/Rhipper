// d3d9vk's device memory and images: a first-fit suballocator over 64 MB blocks (a game's thousands
// of textures would pass maxMemoryAllocationCount one allocation each), images with a layout per
// subresource and their views, the upload ring each submission writes its transient data to, and
// the transfers between the reference's texels and an image.
#include "Vk.h"

namespace rh::d3d9vk {

namespace {
constexpr VkDeviceSize kBlockSize = 64ull << 20, kDedicated = 32ull << 20, kChunkSize = 8ull << 20;
VkDeviceSize AlignUp(VkDeviceSize v, VkDeviceSize a) { return a ? (v + a - 1) / a * a : v; }
}  // namespace

struct Block {
    VkDeviceMemory memory = VK_NULL_HANDLE;
    VkDeviceSize size = 0, used = 0;
    uint32_t type = 0;
    bool linear = false, dedicated = false;
    uint8_t* mapped = nullptr;
    std::map<VkDeviceSize, VkDeviceSize> free;   // offset -> size
};

// ---- the allocator ------------------------------------------------------------------------------------
int MemAllocator::TypeFor(uint32_t bits, VkMemoryPropertyFlags want) const {
    for (uint32_t k = 0; k < props_.memoryTypeCount; k++)
        if ((bits & (1u << k)) && (props_.memoryTypes[k].propertyFlags & want) == want) return static_cast<int>(k);
    return -1;
}

bool MemAllocator::Allocate(const VkMemoryRequirements& req, VkMemoryPropertyFlags want, VkMemoryPropertyFlags prefer,
                            bool linear, Alloc* out) {
    int type = prefer ? TypeFor(req.memoryTypeBits, want | prefer) : -1;
    if (type < 0) type = TypeFor(req.memoryTypeBits, want);
    if (type < 0) {
        LogOnce("vk-memtype", "d3d9vk: no memory type for bits %#x flags %#x", req.memoryTypeBits, want);
        return false;
    }
    // (mapped only when coherent: nothing here flushes)
    VkMemoryPropertyFlags coherent = VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT;
    bool host = (props_.memoryTypes[type].propertyFlags & coherent) == coherent;
    VkDeviceSize align = std::max<VkDeviceSize>(req.alignment, 16);
    auto carve = [&](Block* b) -> bool {
        for (auto it = b->free.begin(); it != b->free.end(); ++it) {
            VkDeviceSize off = it->first, len = it->second, at = AlignUp(off, align);
            if (at + req.size > off + len) continue;
            b->free.erase(it);
            if (at > off) b->free[off] = at - off;
            if (at + req.size < off + len) b->free[at + req.size] = off + len - (at + req.size);
            b->used += req.size;
            out->memory = b->memory, out->offset = at, out->size = req.size, out->block = b;
            out->mapped = b->mapped ? b->mapped + at : nullptr;
            used_ += req.size;
            return true;
        }
        return false;
    };
    if (req.size <= kDedicated)
        for (Block* b : blocks_)
            if (!b->dedicated && b->type == static_cast<uint32_t>(type) && b->linear == linear && carve(b)) return true;
    auto b = new Block();
    b->type = static_cast<uint32_t>(type);
    b->linear = linear;
    b->dedicated = req.size > kDedicated;
    b->size = b->dedicated ? AlignUp(req.size, align) : kBlockSize;
    VkMemoryAllocateInfo ai{VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO};
    ai.allocationSize = b->size;
    ai.memoryTypeIndex = b->type;
    VkResult r = vkAllocateMemory(dev_, &ai, nullptr, &b->memory);
    if (r != VK_SUCCESS) {
        Log("d3d9vk: vkAllocateMemory(%llu MB, type %d) failed: %d (in use %llu MB)",
            static_cast<unsigned long long>(b->size >> 20), type, r, static_cast<unsigned long long>(used_ >> 20));
        delete b;
        return false;
    }
    if (host) {
        void* p = nullptr;
        if (vkMapMemory(dev_, b->memory, 0, VK_WHOLE_SIZE, 0, &p) == VK_SUCCESS) b->mapped = static_cast<uint8_t*>(p);
    }
    b->free[0] = b->size;
    blocks_.push_back(b);
    return carve(b);
}

void MemAllocator::Free(Alloc& a) {
    Block* b = a.block;
    if (!b) return;
    used_ -= a.size;
    b->used -= a.size;
    if (b->dedicated) {
        if (b->mapped) vkUnmapMemory(dev_, b->memory);
        vkFreeMemory(dev_, b->memory, nullptr);
        blocks_.erase(std::find(blocks_.begin(), blocks_.end(), b));
        delete b;
    } else {
        VkDeviceSize off = a.offset, len = a.size;
        auto next = b->free.lower_bound(off);
        if (next != b->free.end() && off + len == next->first) {
            len += next->second;
            next = b->free.erase(next);
        }
        if (next != b->free.begin()) {
            auto prev = std::prev(next);
            if (prev->first + prev->second == off) {
                off = prev->first;
                len += prev->second;
                b->free.erase(prev);
            }
        }
        b->free[off] = len;
    }
    a = Alloc{};
}

// ---- buffers ------------------------------------------------------------------------------------------
bool Device::MakeBuffer(VkDeviceSize size, VkBufferUsageFlags usage, VkMemoryPropertyFlags want,
                        VkMemoryPropertyFlags prefer, VkBuffer* buf, Alloc* m) {
    VkBufferCreateInfo ci{VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO};
    ci.size = std::max<VkDeviceSize>(size, 16);
    ci.usage = usage;
    ci.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    if (!Check(vkCreateBuffer(device, &ci, nullptr, buf), "vkCreateBuffer")) return false;
    VkMemoryRequirements req;
    vkGetBufferMemoryRequirements(device, *buf, &req);
    if (!mem->Allocate(req, want, prefer, true, m) ||
        !Check(vkBindBufferMemory(device, *buf, m->memory, m->offset), "vkBindBufferMemory")) {
        vkDestroyBuffer(device, *buf, nullptr);
        *buf = VK_NULL_HANDLE;
        return false;
    }
    return true;
}

void Device::DestroyBuffer(VkBuffer buf, Alloc m) {
    if (!buf) return;
    Defer([this, buf, m]() mutable {
        vkDestroyBuffer(device, buf, nullptr);
        mem->Free(m);
    });
}

// ---- the upload ring: what this submission writes for the GPU, recycled when it completes ---------------
RingSlice Device::Ring(VkDeviceSize size, VkDeviceSize align) {
    Slot& s = slots[cur];
    if (!s.chunks.empty()) {
        Chunk* c = s.chunks.back();
        VkDeviceSize at = AlignUp(c->used, align);
        if (at + size <= c->size) {
            c->used = at + size;
            return {c->buffer, at, c->mem.mapped + at};
        }
    }
    Chunk* c = nullptr;
    for (auto it = freeChunks.begin(); it != freeChunks.end(); ++it)
        if ((*it)->size >= size) {
            c = *it;
            freeChunks.erase(it);
            break;
        }
    if (!c) {
        c = new Chunk();
        c->size = std::max(kChunkSize, AlignUp(size, 1u << 20));
        if (!MakeBuffer(c->size,
                        VK_BUFFER_USAGE_VERTEX_BUFFER_BIT | VK_BUFFER_USAGE_INDEX_BUFFER_BIT |
                            VK_BUFFER_USAGE_UNIFORM_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT,
                        VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT,
                        VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT, &c->buffer, &c->mem) ||
            !c->mem.mapped) {
            LogOnce("vk-ring", "d3d9vk: the upload ring could not grow (%llu bytes)", static_cast<unsigned long long>(size));
            delete c;
            return {};
        }
    }
    c->used = size;
    s.chunks.push_back(c);
    return {c->buffer, 0, c->mem.mapped};
}

// ---- images -------------------------------------------------------------------------------------------
Image* Device::CreateImage(const FormatInfo* fmt, VkImageViewType type, uint32_t w, uint32_t h, uint32_t d,
                           uint32_t levels, uint32_t layers, VkImageUsageFlags usage) {
    auto img = new Image();
    img->fmt = fmt;
    img->format = fmt->vk;
    img->viewType = type;
    img->width = std::max(1u, w), img->height = std::max(1u, h), img->depth = std::max(1u, d);
    img->levels = std::max(1u, levels), img->layers = std::max(1u, layers);
    img->usage = usage | VK_IMAGE_USAGE_TRANSFER_SRC_BIT | VK_IMAGE_USAGE_TRANSFER_DST_BIT;
    img->aspect = fmt->depth ? (VK_IMAGE_ASPECT_DEPTH_BIT | (fmt->stencil ? VK_IMAGE_ASPECT_STENCIL_BIT : 0))
                             : VK_IMAGE_ASPECT_COLOR_BIT;
    VkImageCreateInfo ci{VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO};
    ci.imageType = type == VK_IMAGE_VIEW_TYPE_3D ? VK_IMAGE_TYPE_3D : VK_IMAGE_TYPE_2D;
    ci.format = fmt->vk;
    ci.extent = {img->width, img->height, img->depth};
    ci.mipLevels = img->levels;
    ci.arrayLayers = img->layers;
    ci.samples = VK_SAMPLE_COUNT_1_BIT;
    ci.tiling = VK_IMAGE_TILING_OPTIMAL;
    ci.usage = img->usage;
    ci.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    ci.initialLayout = VK_IMAGE_LAYOUT_UNDEFINED;
    if (type == VK_IMAGE_VIEW_TYPE_CUBE) ci.flags |= VK_IMAGE_CREATE_CUBE_COMPATIBLE_BIT;
    // an sRGB view of the same texels (SRGBTEXTURE / SRGBWRITEENABLE), the list so the driver can keep
    // its compression
    VkFormat list[2] = {fmt->vk, fmt->srgb};
    VkImageFormatListCreateInfo fl{VK_STRUCTURE_TYPE_IMAGE_FORMAT_LIST_CREATE_INFO};
    if (fmt->srgb != VK_FORMAT_UNDEFINED) {
        ci.flags |= VK_IMAGE_CREATE_MUTABLE_FORMAT_BIT;
        fl.viewFormatCount = 2;
        fl.pViewFormats = list;
        ci.pNext = &fl;
    }
    if (!Check(vkCreateImage(device, &ci, nullptr, &img->image), "vkCreateImage")) {
        Log("d3d9vk: image %ux%ux%u %u levels %u layers of %s (usage %#x) not made", w, h, d, levels, layers,
            FormatName(fmt->d3d), usage);
        delete img;
        return nullptr;
    }
    VkMemoryRequirements req;
    vkGetImageMemoryRequirements(device, img->image, &req);
    if (!mem->Allocate(req, VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT, 0, false, &img->mem) ||
        !Check(vkBindImageMemory(device, img->image, img->mem.memory, img->mem.offset), "vkBindImageMemory")) {
        vkDestroyImage(device, img->image, nullptr);
        if (img->mem.block) mem->Free(img->mem);
        delete img;
        return nullptr;
    }
    img->layouts.assign(img->levels * img->layers, VK_IMAGE_LAYOUT_UNDEFINED);
    img->targets.assign(2 * img->levels * img->layers, VK_NULL_HANDLE);
    return img;
}

void Device::DestroyImage(Image* img) {
    if (!img) return;
    Defer([this, img]() {
        if (img->sampled) vkDestroyImageView(device, img->sampled, nullptr);
        if (img->sampledSrgb) vkDestroyImageView(device, img->sampledSrgb, nullptr);
        for (VkImageView v : img->targets)
            if (v) vkDestroyImageView(device, v, nullptr);
        vkDestroyImage(device, img->image, nullptr);
        mem->Free(img->mem);
        delete img;
    });
}

VkImageView Device::SampleView(Image* img, bool srgb) {
    if (!(img->usage & VK_IMAGE_USAGE_SAMPLED_BIT)) return VK_NULL_HANDLE;
    srgb = srgb && img->fmt->srgb != VK_FORMAT_UNDEFINED;
    VkImageView& v = srgb ? img->sampledSrgb : img->sampled;
    if (v) return v;
    VkImageViewCreateInfo ci{VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO};
    ci.image = img->image;
    ci.viewType = img->viewType;
    ci.format = srgb ? img->fmt->srgb : img->format;
    ci.components = img->fmt->swizzle;
    ci.subresourceRange = {img->fmt->depth ? VkImageAspectFlags(VK_IMAGE_ASPECT_DEPTH_BIT) : img->aspect, 0,
                           img->levels, 0, img->layers};
    Check(vkCreateImageView(device, &ci, nullptr, &v), "vkCreateImageView (sampled)");
    return v;
}

VkImageView Device::TargetView(Image* img, uint32_t level, uint32_t layer, bool srgb) {
    srgb = srgb && img->fmt->srgb != VK_FORMAT_UNDEFINED;
    VkImageView& v = img->targets[2 * img->Sub(level, layer) + (srgb ? 1 : 0)];
    if (v) return v;
    VkImageViewCreateInfo ci{VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO};
    ci.image = img->image;
    ci.viewType = VK_IMAGE_VIEW_TYPE_2D;
    ci.format = srgb ? img->fmt->srgb : img->format;
    ci.subresourceRange = {img->aspect, level, 1, layer, 1};
    Check(vkCreateImageView(device, &ci, nullptr, &v), "vkCreateImageView (target)");
    return v;
}

// A layout per subresource; a barrier for each that changes (and for a write after a write in the same
// layout). The barriers are coarse, every stage to every stage: correct, and on a tiler the render
// passes they fall between cost more than they do.
void Device::Transition(VkCommandBuffer cb, Image* img, uint32_t level0, uint32_t nLevels, uint32_t layer0,
                        uint32_t nLayers, VkImageLayout to) {
    VkImageMemoryBarrier bars[32];
    uint32_t n = 0;
    auto flush = [&]() {
        if (n) vkCmdPipelineBarrier(cb, VK_PIPELINE_STAGE_ALL_COMMANDS_BIT, VK_PIPELINE_STAGE_ALL_COMMANDS_BIT, 0, 0,
                                    nullptr, 0, nullptr, n, bars);
        n = 0;
    };
    VkImageLayout want = img->general ? VK_IMAGE_LAYOUT_GENERAL : to;
    // (a sampled image leaving the layout draws read it in: the next draw looks at its textures again)
    bool leaves = (img->usage & VK_IMAGE_USAGE_SAMPLED_BIT) && want != VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL;
    for (uint32_t layer = layer0; layer < layer0 + nLayers && layer < img->layers; layer++)
        for (uint32_t level = level0; level < level0 + nLevels && level < img->levels; level++) {
            VkImageLayout& cur = img->layouts[img->Sub(level, layer)];
            if (cur == want && want != VK_IMAGE_LAYOUT_GENERAL && want != VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL) continue;
            if (leaves && cur != want) dirty |= kDirtyTextures;
            VkImageMemoryBarrier& b = bars[n++];
            b = VkImageMemoryBarrier{VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER};
            b.srcAccessMask = VK_ACCESS_MEMORY_WRITE_BIT;
            b.dstAccessMask = VK_ACCESS_MEMORY_READ_BIT | VK_ACCESS_MEMORY_WRITE_BIT;
            b.oldLayout = cur;
            b.newLayout = want;
            b.srcQueueFamilyIndex = b.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
            b.image = img->image;
            b.subresourceRange = {img->aspect, level, 1, layer, 1};
            cur = want;
            if (n == 32) flush();
        }
    flush();
}

// a new target's contents: defined (D3D9's are whatever the memory held; ours would be undefined
// layouts, which a first LOAD may not read)
void Device::ClearImage(Image* img, const VkClearColorValue& color) {
    VkCommandBuffer cb = Upload();
    TransitionAll(cb, img, VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL);
    VkImageSubresourceRange range{img->aspect, 0, img->levels, 0, img->layers};
    VkImageLayout layout = img->layouts[0];
    if (img->fmt->depth) {
        VkClearDepthStencilValue v{1.0f, 0};
        vkCmdClearDepthStencilImage(cb, img->image, layout, &v, 1, &range);
        TransitionAll(cb, img, VK_IMAGE_LAYOUT_DEPTH_STENCIL_ATTACHMENT_OPTIMAL);
    } else {
        vkCmdClearColorImage(cb, img->image, layout, &color, 1, &range);
        TransitionAll(cb, img, (img->usage & VK_IMAGE_USAGE_SAMPLED_BIT) ? VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL
                                                                         : VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL);
    }
}

// AUTOGENMIPMAP / GenerateMipSubLevels: each level blitted from the one above, linear
void Device::GenerateMips(Image* img) {
    if (img->levels < 2) return;
    if (!img->fmt->blit || !img->fmt->filter || img->fmt->vkBlock) {
        static Once<4> once;
        if (once.First(img->fmt->d3d))
            Log("d3d9vk: mipmaps of %s not generated (the format does not blit linearly)", FormatName(img->fmt->d3d));
        return;
    }
    VkCommandBuffer cb = CmdFor(img->lastUse);
    for (uint32_t layer = 0; layer < img->layers; layer++)
        for (uint32_t l = 1; l < img->levels; l++) {
            Transition(cb, img, l - 1, 1, layer, 1, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL);
            Transition(cb, img, l, 1, layer, 1, VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL);
            VkImageBlit b{};
            b.srcSubresource = {img->aspect, l - 1, layer, 1};
            b.srcOffsets[1] = {int32_t(img->W(l - 1)), int32_t(img->H(l - 1)), int32_t(img->D(l - 1))};
            b.dstSubresource = {img->aspect, l, layer, 1};
            b.dstOffsets[1] = {int32_t(img->W(l)), int32_t(img->H(l)), int32_t(img->D(l))};
            vkCmdBlitImage(cb, img->image, img->layouts[img->Sub(l - 1, layer)], img->image,
                           img->layouts[img->Sub(l, layer)], 1, &b, VK_FILTER_LINEAR);
        }
    TransitionAll(cb, img, VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL);
}

// The reference's texels into a region of a subresource: converted (outside the device's lock: a DXT
// decode of a large texture is the slow part), then into the ring and copied, before the main command
// buffer if this submission has not used the image yet
void Device::UploadRegion(Storage* st, uint32_t level, uint32_t layer, uint32_t x, uint32_t y, uint32_t z, uint32_t w,
                          uint32_t h, uint32_t d, const uint8_t* src, uint32_t srcPitch, uint32_t srcSlice) {
    const FormatInfo* f = st->fmt;
    if (!st->img || !w || !h || !d) return;
    if (f->depth) {
        LogOnce("vk-upload-depth", "d3d9vk: a lock's texels into a depth surface (%s): not uploaded", FormatName(f->d3d));
        return;
    }
    uint32_t bw = f->vkBlock ? f->blockW : 1, bh = f->vkBlock ? f->blockH : 1;
    uint32_t cols = (w + bw - 1) / bw, rows = (h + bh - 1) / bh;
    uint32_t rowBytes = cols * f->vkBytes, sliceBytes = rowBytes * rows;
    std::vector<uint8_t> conv;
    const uint8_t* data = src;
    uint32_t dataPitch = srcPitch, dataSlice = srcSlice;
    if (f->convert) {
        conv.resize(static_cast<size_t>(sliceBytes) * d);
        for (uint32_t k = 0; k < d; k++) f->convert(src + k * srcSlice, srcPitch, conv.data() + k * sliceBytes, rowBytes, w, h);
        data = conv.data(), dataPitch = rowBytes, dataSlice = sliceBytes;
    }
    std::lock_guard<std::recursive_mutex> hold(mu);
    Image* img = st->img;
    if (lost || !img) return;
    RingSlice r = Ring(static_cast<VkDeviceSize>(sliceBytes) * d, 16);
    if (!r.ptr) return;
    for (uint32_t k = 0; k < d; k++)
        for (uint32_t row = 0; row < rows; row++)
            memcpy(r.ptr + k * sliceBytes + row * rowBytes, data + k * dataSlice + row * dataPitch, rowBytes);
    VkCommandBuffer cb = CmdFor(img->lastUse);
    Transition(cb, img, level, 1, layer, 1, VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL);
    VkBufferImageCopy c{};
    c.bufferOffset = r.offset;
    c.imageSubresource = {VK_IMAGE_ASPECT_COLOR_BIT, level, layer, 1};
    c.imageOffset = {int32_t(x), int32_t(y), int32_t(z)};
    c.imageExtent = {std::min(w, img->W(level) - x), std::min(h, img->H(level) - y), std::min(d, img->D(level) - z)};
    vkCmdCopyBufferToImage(cb, r.buffer, img->image, img->layouts[img->Sub(level, layer)], 1, &c);
    Transition(cb, img, level, 1, layer, 1,
               (img->usage & VK_IMAGE_USAGE_SAMPLED_BIT) ? VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL
                                                         : VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL);
}

// A subresource back to the reference (GetRenderTargetData, a READONLY lock): copied out, the GPU
// waited for. Only formats held as D3D lays them out.
bool Device::ReadRegion(Image* img, uint32_t level, uint32_t layer, uint32_t w, uint32_t h, uint8_t* dst,
                        uint32_t dstPitch) {
    std::lock_guard<std::recursive_mutex> hold(mu);
    const FormatInfo* f = img->fmt;
    if (lost) return false;
    if (f->convert || f->depth) {
        LogOnce(("vk-readback-" + std::to_string(f->d3d)).c_str(), "d3d9vk: reading back %s (held converted, or depth): not supported", FormatName(f->d3d));
        return false;
    }
    w = std::min(w, img->W(level)), h = std::min(h, img->H(level));
    uint32_t bw = f->vkBlock ? f->blockW : 1, bh = f->vkBlock ? f->blockH : 1;
    uint32_t cols = (w + bw - 1) / bw, rows = (h + bh - 1) / bh, rowBytes = cols * f->vkBytes;
    VkBuffer buf;
    Alloc m;
    if (!MakeBuffer(static_cast<VkDeviceSize>(rowBytes) * rows, VK_BUFFER_USAGE_TRANSFER_DST_BIT,
                    VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT,
                    VK_MEMORY_PROPERTY_HOST_CACHED_BIT, &buf, &m) ||
        !m.mapped)
        return false;
    EndPass();
    Transition(cmd, img, level, 1, layer, 1, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL);
    VkBufferImageCopy c{};
    c.imageSubresource = {VK_IMAGE_ASPECT_COLOR_BIT, level, layer, 1};
    c.imageExtent = {w, h, 1};
    vkCmdCopyImageToBuffer(cmd, img->image, img->layouts[img->Sub(level, layer)], buf, 1, &c);
    VkMemoryBarrier mb{VK_STRUCTURE_TYPE_MEMORY_BARRIER};
    mb.srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;
    mb.dstAccessMask = VK_ACCESS_HOST_READ_BIT;
    vkCmdPipelineBarrier(cmd, VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_HOST_BIT, 0, 1, &mb, 0, nullptr, 0, nullptr);
    img->lastUse = serial;
    uint64_t s = serial;
    Submit();
    WaitSerial(s);
    bool ok = !lost;
    if (ok)
        for (uint32_t row = 0; row < rows; row++) memcpy(dst + row * dstPitch, m.mapped + row * rowBytes, rowBytes);
    vkDestroyBuffer(device, buf, nullptr);
    mem->Free(m);
    return ok;
}

}  // namespace rh::d3d9vk
