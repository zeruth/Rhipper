// d3d9vk's resources as the reference sees them: surfaces, textures (2D, cube, volume) and their
// levels, vertex and index buffers, queries, vertex declarations, shaders, state blocks, swap chains.
// Their vtables are d3d9.h's (slot numbers in the tables below).
//
// A lock hands the reference low memory (its pointers are 32 bits): a CPU-only resource (SYSTEMMEM,
// SCRATCH) keeps it, a GPU one gets it for the lock's length and its unlock uploads what it covered.
// A dynamic buffer keeps its whole contents in low memory and versions the GPU reads (its own, kept
// across submissions; see "buffers" below for the lock flags).
#include <time.h>

#include "Vk.h"

namespace rh::d3d9vk {

namespace {
constexpr uint32_t D3DERR_MOREDATA = 0x88760867u;
std::string GuidKey(uint32_t guid) { return std::string(At<char>(guid), 16); }
uint32_t LowAllocZero(uint32_t n) { return HeapAllocIn(ProcessHeap(), 8, n ? n : 16); }
void LowFreeMem(uint32_t& p) {
    if (p) HeapFreeIn(ProcessHeap(), 0, p);
    p = 0;
}
}  // namespace

// ---- Base: IUnknown, IDirect3DResource9's common methods ------------------------------------------------
void Base::Bind() { binds++; }
void Base::Unbind() {
    if (--binds <= 0) {
        binds = 0;
        MaybeDestroy();
    }
}
void Base::MaybeDestroy() {
    if (refs <= 0 && binds <= 0) {
        FreeObject(self);
        delete this;
    }
}
uint32_t Base::QueryInterface(uint32_t, uint32_t out) {
    AddRef_();
    if (out) *At<uint32_t>(out) = self;
    return D3D_OK;
}
uint32_t Base::AddRef_() {
    std::lock_guard<std::recursive_mutex> hold(dev->mu);
    return static_cast<uint32_t>(++refs);
}
uint32_t Base::Release_() {
    std::lock_guard<std::recursive_mutex> hold(dev->mu);
    int r = --refs;
    if (r <= 0) {
        refs = 0, r = 0;
        MaybeDestroy();   // (this may be gone after)
    }
    return static_cast<uint32_t>(r);
}
uint32_t Base::GetDevice(uint32_t out) {
    dev->AddRef_();
    *At<uint32_t>(out) = dev->self;
    return D3D_OK;
}
// private data: the bytes, behind a byte of the flags (D3DSPD_IUNKNOWN 1: the data is an object held)
uint32_t Base::SetPrivateData(uint32_t guid, uint32_t data, uint32_t size, uint32_t flags) {
    std::lock_guard<std::recursive_mutex> hold(dev->mu);
    FreePrivateData(guid);
    std::vector<uint8_t> v(1 + size);
    v[0] = static_cast<uint8_t>(flags & 1);
    if (flags & 1) {
        if (data) com::CallMethod(data, 1);   // AddRef
        memcpy(v.data() + 1, &data, 4);
        v.resize(5);
    } else if (size && data) {
        memcpy(v.data() + 1, At(data), size);
    }
    privateData[GuidKey(guid)] = std::move(v);
    return D3D_OK;
}
uint32_t Base::GetPrivateData(uint32_t guid, uint32_t data, uint32_t sizeInOut) {
    std::lock_guard<std::recursive_mutex> hold(dev->mu);
    auto it = privateData.find(GuidKey(guid));
    if (it == privateData.end()) return D3DERR_NOTFOUND;
    uint32_t n = static_cast<uint32_t>(it->second.size() - 1);
    if (!data) {
        *At<uint32_t>(sizeInOut) = n;
        return D3D_OK;
    }
    if (*At<uint32_t>(sizeInOut) < n) {
        *At<uint32_t>(sizeInOut) = n;
        return D3DERR_MOREDATA;
    }
    memcpy(At(data), it->second.data() + 1, n);
    *At<uint32_t>(sizeInOut) = n;
    if (it->second[0] & 1) {
        uint32_t obj;
        memcpy(&obj, it->second.data() + 1, 4);
        if (obj) com::CallMethod(obj, 1);
    }
    return D3D_OK;
}
uint32_t Base::FreePrivateData(uint32_t guid) {
    std::lock_guard<std::recursive_mutex> hold(dev->mu);
    auto it = privateData.find(GuidKey(guid));
    if (it == privateData.end()) return D3DERR_NOTFOUND;
    if (it->second[0] & 1) {
        uint32_t obj;
        memcpy(&obj, it->second.data() + 1, 4);
        if (obj) com::CallMethod(obj, 2);   // Release
    }
    privateData.erase(it);
    return D3D_OK;
}
uint32_t Base::SetPriority(uint32_t p) {
    uint32_t old = priority;
    priority = p;
    return old;
}
uint32_t Base::GetPriority() { return priority; }
uint32_t Base::PreLoad() { return D3D_OK; }

// ---- Storage: an image's levels and their locks -----------------------------------------------------
uint32_t Storage::CpuMem(uint32_t level, uint32_t layer) {
    Sub& s = SubAt(level, layer);
    if (!s.mem) {
        s.size = SubSize(level);
        s.mem = LowAllocZero(s.size);
    }
    return s.mem;
}

uint32_t Storage::Lock(uint32_t level, uint32_t layer, uint32_t region, bool box, uint32_t out, uint32_t flags) {
    if (level >= levels || layer >= layers || !out) return D3DERR_INVALIDCALL;
    if (fmt->null) return D3DERR_INVALIDCALL;
    Sub& s = SubAt(level, layer);
    if (s.locked) {
        LogOnce("vk-lock-twice", "d3d9vk: a level locked twice");
        return D3DERR_INVALIDCALL;
    }
    uint32_t x = 0, y = 0, z = 0, w = W(level), h = H(level), d = D(level);
    if (region) {
        auto r = rh::At<uint32_t>(region);
        uint32_t l = r[0], t = r[1], rr = r[2], b = r[3];
        if (rr > l && b > t) x = l, y = t, w = std::min(rr, W(level)) - std::min(l, W(level)), h = std::min(b, H(level)) - std::min(t, H(level));
        if (box && r[5] > r[4]) z = r[4], d = std::min(r[5], D(level)) - std::min(r[4], D(level));
    }
    // (a block format's region in whole blocks)
    uint32_t bw = fmt->blockW, bh = fmt->blockH;
    if (bw > 1) {
        uint32_t x1 = std::min(W(level), (x + w + bw - 1) / bw * bw), y1 = std::min(H(level), (y + h + bh - 1) / bh * bh);
        x = x / bw * bw, y = y / bh * bh, w = x1 - x, h = y1 - y;
    }
    uint32_t pitch = Pitch(level), slice = pitch * Rows(level);
    uint32_t base;
    if (cpuOnly || !img) {
        base = CpuMem(level, layer);
    } else {
        if (!s.mem) {
            s.size = SubSize(level);
            s.mem = LowAllocZero(s.size);
        }
        base = s.mem;
        if (!base) return D3DERR_OUTOFVIDEOMEMORY;
        if (flags & LOCK_READONLY) dev->ReadRegion(img, level, layer, W(level), H(level), rh::At<uint8_t>(base), pitch);
    }
    if (!base) return D3DERR_OUTOFVIDEOMEMORY;
    s.locked = true, s.flags = flags;
    s.x = x, s.y = y, s.z = z, s.w = w, s.h = h, s.d = d;
    uint32_t bits = base + z * slice + (y / bh) * pitch + (x / bw) * fmt->bytes;
    auto o = rh::At<uint32_t>(out);
    if (box) {
        o[0] = pitch, o[1] = slice, o[2] = bits;
    } else {
        o[0] = pitch, o[1] = bits;
    }
    return D3D_OK;
}

uint32_t Storage::Unlock(uint32_t level, uint32_t layer) {
    if (level >= levels || layer >= layers) return D3DERR_INVALIDCALL;
    Sub& s = SubAt(level, layer);
    if (!s.locked) return D3DERR_INVALIDCALL;
    s.locked = false;
    if (cpuOnly || !img) return D3D_OK;
    if (!(s.flags & LOCK_READONLY) && s.mem) {
        uint32_t pitch = Pitch(level), slice = pitch * Rows(level);
        const uint8_t* src = rh::At<uint8_t>(s.mem) + s.z * slice + (s.y / fmt->blockH) * pitch + (s.x / fmt->blockW) * fmt->bytes;
        dev->UploadRegion(this, level, layer, s.x, s.y, s.z, s.w, s.h, s.d, src, pitch, slice);
        if ((usage & U_AUTOGENMIPMAP) && level == 0) {
            std::lock_guard<std::recursive_mutex> hold(dev->mu);   // (the render thread reads them)
            mipsDirty = true;
            dev->dirty |= kDirtyTextures;
        }
    }
    if (!(usage & U_DYNAMIC)) LowFreeMem(s.mem);
    return D3D_OK;
}

void Storage::Release() {
    for (Sub& s : subs) LowFreeMem(s.mem);
    if (img) dev->DestroyImage(img);
    img = nullptr;
}

// ---- surfaces ---------------------------------------------------------------------------------------------
Surface::~Surface() {
    if (!container) own.Release();
}
void Surface::Bind() {
    if (container) container->Bind();
    else Base::Bind();
}
void Surface::Unbind() {
    if (container) container->Unbind();
    else Base::Unbind();
}
uint32_t Surface::AddRef_() { return container ? container->AddRef_() : Base::AddRef_(); }
uint32_t Surface::Release_() { return container ? container->Release_() : Base::Release_(); }
uint32_t Surface::GetType() { return RT_SURFACE; }
uint32_t Surface::GetContainer(uint32_t, uint32_t out) {
    if (container) {
        container->AddRef_();
        *At<uint32_t>(out) = container->self;
    } else {
        dev->AddRef_();
        *At<uint32_t>(out) = dev->self;
    }
    return D3D_OK;
}
// D3DSURFACE_DESC: Format, Type, Usage, Pool, MultiSampleType, MultiSampleQuality, Width, Height
uint32_t Surface::GetDesc(uint32_t out) {
    uint32_t d[8] = {st->format, RT_SURFACE, st->usage, st->pool, 0, 0, W(), H()};
    memcpy(At(out), d, sizeof d);
    return D3D_OK;
}
uint32_t Surface::LockRect(uint32_t locked, uint32_t rect, uint32_t flags) {
    return st->Lock(level, layer, rect, false, locked, flags);
}
uint32_t Surface::UnlockRect() { return st->Unlock(level, layer); }
uint32_t Surface::GetDC(uint32_t out) {
    LogOnce("vk-getdc", "d3d9vk: IDirect3DSurface9::GetDC is not supported");
    if (out) *At<uint32_t>(out) = 0;
    return D3DERR_INVALIDCALL;
}
uint32_t Surface::ReleaseDC(uint32_t) { return D3DERR_INVALIDCALL; }

// ---- textures ---------------------------------------------------------------------------------------------
Texture::~Texture() {
    for (Surface* s : surfaces)
        if (s) {
            FreeObject(s->self);
            delete s;
        }
    for (Volume* v : volumes)
        if (v) {
            FreeObject(v->self);
            delete v;
        }
    st.Release();
}
Surface* Texture::SurfaceOf(uint32_t level, uint32_t layer) {
    if (surfaces.empty()) surfaces.assign(st.levels * st.layers, nullptr);
    Surface*& s = surfaces[layer * st.levels + level];
    if (!s) {
        s = new Surface();
        s->dev = dev;
        s->container = this;
        s->st = &st;
        s->level = level, s->layer = layer;
        s->self = NewObject(SurfaceVtable(), static_cast<Base*>(s));
    }
    return s;
}
uint32_t Texture::GetType() { return st.rtype; }
uint32_t Texture::SetLOD(uint32_t l) {
    std::lock_guard<std::recursive_mutex> hold(dev->mu);   // (a loader thread's call, the render thread's dirty)
    uint32_t old = lod;
    if (st.pool == POOL_MANAGED) lod = std::min(l, apiLevels - 1);
    if (lod != old) dev->dirty |= kDirtyTextures;
    return old;
}
uint32_t Texture::GetLOD() { return lod; }
uint32_t Texture::GetLevelCount() { return apiLevels; }
uint32_t Texture::SetAutoGenFilterType(uint32_t f) { return autoGenFilter = f, D3D_OK; }
uint32_t Texture::GetAutoGenFilterType() { return autoGenFilter; }
uint32_t Texture::GenerateMipSubLevels() {
    std::lock_guard<std::recursive_mutex> hold(dev->mu);
    if (st.usage & U_AUTOGENMIPMAP) st.mipsDirty = true, dev->dirty |= kDirtyTextures;
    return D3D_OK;
}
uint32_t Texture::GetLevelDesc(uint32_t level, uint32_t out) {
    if (level >= apiLevels) return D3DERR_INVALIDCALL;
    uint32_t d[8] = {st.format, RT_SURFACE, st.usage, st.pool, 0, 0, st.W(level), st.H(level)};
    memcpy(At(out), d, sizeof d);
    return D3D_OK;
}
uint32_t Texture::GetSurfaceLevel(uint32_t level, uint32_t out) {
    std::lock_guard<std::recursive_mutex> hold(dev->mu);
    if (level >= apiLevels || !out) return D3DERR_INVALIDCALL;
    Surface* s = SurfaceOf(level, 0);
    AddRef_();
    *At<uint32_t>(out) = s->self;
    return D3D_OK;
}
uint32_t Texture::LockRect(uint32_t level, uint32_t locked, uint32_t rect, uint32_t flags) {
    if (level >= apiLevels) return D3DERR_INVALIDCALL;
    return st.Lock(level, 0, rect, false, locked, flags);
}
uint32_t Texture::UnlockRect(uint32_t level) { return st.Unlock(level, 0); }
uint32_t Texture::AddDirtyRect(uint32_t) { return D3D_OK; }
uint32_t Texture::CubeGetLevelDesc(uint32_t level, uint32_t out) { return GetLevelDesc(level, out); }
uint32_t Texture::GetCubeMapSurface(uint32_t face, uint32_t level, uint32_t out) {
    std::lock_guard<std::recursive_mutex> hold(dev->mu);
    if (level >= apiLevels || face >= 6 || !out) return D3DERR_INVALIDCALL;
    Surface* s = SurfaceOf(level, face);
    AddRef_();
    *At<uint32_t>(out) = s->self;
    return D3D_OK;
}
uint32_t Texture::CubeLockRect(uint32_t face, uint32_t level, uint32_t locked, uint32_t rect, uint32_t flags) {
    if (level >= apiLevels || face >= 6) return D3DERR_INVALIDCALL;
    return st.Lock(level, face, rect, false, locked, flags);
}
uint32_t Texture::CubeUnlockRect(uint32_t face, uint32_t level) { return st.Unlock(level, face); }
uint32_t Texture::CubeAddDirtyRect(uint32_t, uint32_t) { return D3D_OK; }
// D3DVOLUME_DESC: Format, Type, Usage, Pool, Width, Height, Depth
uint32_t Texture::VolGetLevelDesc(uint32_t level, uint32_t out) {
    if (level >= apiLevels) return D3DERR_INVALIDCALL;
    uint32_t d[7] = {st.format, RT_VOLUME, st.usage, st.pool, st.W(level), st.H(level), st.D(level)};
    memcpy(At(out), d, sizeof d);
    return D3D_OK;
}
uint32_t Texture::GetVolumeLevel(uint32_t level, uint32_t out) {
    std::lock_guard<std::recursive_mutex> hold(dev->mu);
    if (level >= apiLevels || !out) return D3DERR_INVALIDCALL;
    if (volumes.empty()) volumes.assign(st.levels, nullptr);
    Volume*& v = volumes[level];
    if (!v) {
        v = new Volume();
        v->dev = dev;
        v->container = this;
        v->level = level;
        v->self = NewObject(VolumeVtable(), static_cast<Base*>(v));
    }
    AddRef_();
    *At<uint32_t>(out) = v->self;
    return D3D_OK;
}
uint32_t Texture::LockBox(uint32_t level, uint32_t locked, uint32_t box, uint32_t flags) {
    if (level >= apiLevels) return D3DERR_INVALIDCALL;
    return st.Lock(level, 0, box, true, locked, flags);
}
uint32_t Texture::UnlockBox(uint32_t level) { return st.Unlock(level, 0); }
uint32_t Texture::AddDirtyBox(uint32_t) { return D3D_OK; }

uint32_t Volume::AddRef_() { return container->AddRef_(); }
uint32_t Volume::Release_() { return container->Release_(); }
uint32_t Volume::GetContainer(uint32_t, uint32_t out) {
    container->AddRef_();
    *At<uint32_t>(out) = container->self;
    return D3D_OK;
}
uint32_t Volume::GetDesc(uint32_t out) { return container->VolGetLevelDesc(level, out); }
uint32_t Volume::LockBox(uint32_t locked, uint32_t box, uint32_t flags) { return container->LockBox(level, locked, box, flags); }
uint32_t Volume::UnlockBox() { return container->UnlockBox(level); }

// ---- buffers ------------------------------------------------------------------------------------------------
// A dynamic buffer's lock writes its shadow; the unlock copies the locked range into a version, as
// D3D9 says: DISCARD a fresh version (only the range copied: the rest is undefined after a discard),
// NOOVERWRITE the current one in place (the reference promises the GPU reads none of the range), no
// flag the current one in place when the GPU is done with it, else a fresh one with everything. A
// version is the buffer's own and outlives submissions, so a buffer drawn from frame after frame is
// copied once, not per submission; past kMaxVersions (or the budget) versions are ring slices.
namespace {
constexpr size_t kMaxVersions = 8;
constexpr VkDeviceSize kVersionBudget = 256ull << 20;
constexpr uint32_t kToDynamicMax = 1u << 20;   // a static buffer this small may become a dynamic one
uint32_t LowAlloc(uint32_t n) { return HeapAllocIn(ProcessHeap(), 0, n ? n : 16); }   // (not zeroed)
}  // namespace

Buffer::~Buffer() {
    LowFreeMem(shadow);
    LowFreeMem(lockMem);
    if (buffer) dev->DestroyBuffer(buffer, mem);
    for (Version& v : versions) {
        dev->DestroyBuffer(v.buffer, v.mem);
        dev->dynamicBytes -= length;
    }
}
uint32_t Buffer::GetType() { return index ? RT_INDEXBUFFER : RT_VERTEXBUFFER; }

bool Buffer::Current() const { return verBuffer && (cur >= 0 || verSerial == dev->serial); }

bool Buffer::Busy() {
    uint64_t use = cur >= 0 ? versions[cur].lastUse : verUse;
    if (use > dev->completed && use < dev->serial) dev->Poll();
    return use > dev->completed;
}

void Buffer::Rename(bool copyAll) {
    auto free = [&]() {
        for (size_t k = 0; k < versions.size(); k++)
            if (static_cast<int>(k) != cur && versions[k].lastUse <= dev->completed) return static_cast<int>(k);
        return -1;
    };
    int pick = free();
    if (pick < 0 && !versions.empty()) {
        dev->Poll();
        pick = free();
    }
    if (pick < 0 && versions.size() < kMaxVersions && dev->dynamicBytes + length <= kVersionBudget) {
        Version v;
        if (dev->MakeBuffer(length,
                            VK_BUFFER_USAGE_VERTEX_BUFFER_BIT | VK_BUFFER_USAGE_INDEX_BUFFER_BIT |
                                VK_BUFFER_USAGE_TRANSFER_SRC_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT,
                            VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT,
                            VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT, &v.buffer, &v.mem)) {
            if (v.mem.mapped) {
                versions.push_back(v);
                dev->dynamicBytes += length;
                pick = static_cast<int>(versions.size() - 1);
            } else {
                dev->DestroyBuffer(v.buffer, v.mem);
            }
        }
    }
    if (pick >= 0) {
        cur = pick;
        Version& v = versions[pick];
        verBuffer = v.buffer, verOffset = 0, verPtr = v.mem.mapped, verSerial = 0;
        verUse = v.lastUse;
    } else {
        cur = -1;
        RingSlice r = dev->Ring(length, 256);
        verBuffer = r.buffer, verOffset = r.offset, verPtr = r.ptr, verSerial = dev->serial, verUse = 0;
        if (!r.ptr) return;
    }
    if (copyAll && shadow) memcpy(verPtr, rh::At(shadow), length);
}

// (a static buffer locked again in the submission that drew from it: the copy would end the pass;
// as a versioned buffer it renames instead. Its device buffer, host visible, is the first version)
void Buffer::ToDynamic() {
    uint32_t s = LowAlloc(length);
    if (!s) return;
    memcpy(rh::At(s), mem.mapped, length);
    shadow = s;
    Version v;
    v.buffer = buffer, v.mem = mem, v.lastUse = lastUse;
    versions.push_back(v);
    dev->dynamicBytes += length;
    buffer = VK_NULL_HANDLE, mem = Alloc{};
    cur = 0;
    verBuffer = v.buffer, verOffset = 0, verPtr = v.mem.mapped, verSerial = 0, verUse = v.lastUse;
    dynamic = true;
    static Once<> once;
    if (once.First())
        Log("d3d9vk: a static %s buffer (%u bytes) locked after a draw in the same frame: versioned from now on",
            index ? "index" : "vertex", length);
}

void Buffer::Use(VkBuffer* b, VkDeviceSize* off) {
    if (dynamic) {
        if (!Current()) Rename(true);
        if (!verBuffer) {   // (the ring could not grow: logged there)
            *b = dev->dummyVb, *off = 0;
            return;
        }
        verUse = dev->serial;
        if (cur >= 0) versions[cur].lastUse = dev->serial;
        *b = verBuffer, *off = verOffset;
    } else {
        lastUse = dev->serial;
        *b = buffer, *off = 0;
    }
}

uint32_t Buffer::Lock(uint32_t offset, uint32_t size, uint32_t out, uint32_t flags) {
    std::lock_guard<std::recursive_mutex> hold(dev->mu);
    if (!out) return D3DERR_INVALIDCALL;
    offset = std::min(offset, length);
    if (size == 0 || offset + size > length) size = length - offset;
    if (!dynamic && locks == 0 && !(flags & LOCK_READONLY) && mem.mapped && length <= kToDynamicMax &&
        lastUse == dev->serial) {
        dev->Poll();
        if (pendingCopy <= dev->completed) ToDynamic();
    }
    if (dynamic) {
        if (!shadow) shadow = LowAllocZero(length);
        if (!shadow) return D3DERR_OUTOFVIDEOMEMORY;
        if (locks == 0) {
            lockOff = offset, lockEnd = offset + size, lockFlags = flags;
        } else {
            lockOff = std::min(lockOff, offset), lockEnd = std::max(lockEnd, offset + size);
        }
        locks++;
        *At<uint32_t>(out) = shadow + offset;
        return D3D_OK;
    }
    // static: low memory over the whole buffer for the lock, the range filled from the device's copy
    // (the GPU only reads it; one it is still to be written by a copy is waited for). Not zeroed: only
    // the range is touched, so a small lock of a large buffer costs its range
    if (locks == 0) {
        lockMem = LowAlloc(length);
        if (!lockMem) return D3DERR_OUTOFVIDEOMEMORY;
        lockOff = offset, lockEnd = offset + size, lockFlags = flags;
    } else {
        lockOff = std::min(lockOff, offset), lockEnd = std::max(lockEnd, offset + size);
        lockFlags &= flags | ~LOCK_READONLY;
    }
    if (!(flags & LOCK_DISCARD) && size) {
        if (mem.mapped) {
            dev->Poll();
            if (pendingCopy > dev->completed) dev->WaitSerial(pendingCopy);
            memcpy(rh::At<uint8_t>(lockMem) + offset, mem.mapped + offset, size);
        } else if (flags & LOCK_READONLY) {
            LogOnce("vk-vb-readback", "d3d9vk: reading a static buffer back is not supported here (not host visible)");
        }
    }
    locks++;
    *At<uint32_t>(out) = lockMem + offset;
    return D3D_OK;
}

uint32_t Buffer::Unlock() {
    std::lock_guard<std::recursive_mutex> hold(dev->mu);
    if (locks <= 0) return D3DERR_INVALIDCALL;
    if (--locks > 0) return D3D_OK;
    uint32_t off = lockOff, n = lockEnd - lockOff;
    if (dynamic) {
        auto copyRange = [&]() {
            if (verPtr && n) memcpy(verPtr + off, rh::At<uint8_t>(shadow) + off, n);
        };
        if (lockFlags & LOCK_READONLY) {
        } else if (lockFlags & LOCK_DISCARD) {
            Rename(false);
            copyRange();
        } else if (lockFlags & LOCK_NOOVERWRITE) {
            if (Current()) copyRange();
            else Rename(true);
        } else {
            if (Current() && !Busy()) copyRange();
            else Rename(true);
        }
        return D3D_OK;
    }
    if (!(lockFlags & LOCK_READONLY) && n && buffer && !dev->lost) {
        const uint8_t* src = rh::At<uint8_t>(lockMem) + off;
        dev->Poll();
        if (mem.mapped && lastUse <= dev->completed && pendingCopy <= dev->completed) {
            memcpy(mem.mapped + off, src, n);   // (the GPU is done with it: written in place)
        } else if (RingSlice r = dev->Ring(n, 16); r.ptr) {
            memcpy(r.ptr, src, n);
            VkCommandBuffer cb = dev->CmdFor(lastUse);
            if (cb == dev->cmd)   // (after the draws before that read it)
                vkCmdPipelineBarrier(cb, VK_PIPELINE_STAGE_VERTEX_INPUT_BIT, VK_PIPELINE_STAGE_TRANSFER_BIT, 0, 0, nullptr,
                                     0, nullptr, 0, nullptr);
            VkBufferCopy c{r.offset, off, n};
            vkCmdCopyBuffer(cb, r.buffer, buffer, 1, &c);
            if (cb == dev->cmd) {
                VkMemoryBarrier mb{VK_STRUCTURE_TYPE_MEMORY_BARRIER};
                mb.srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;
                mb.dstAccessMask = VK_ACCESS_VERTEX_ATTRIBUTE_READ_BIT | VK_ACCESS_INDEX_READ_BIT | VK_ACCESS_TRANSFER_WRITE_BIT;
                vkCmdPipelineBarrier(cb, VK_PIPELINE_STAGE_TRANSFER_BIT,
                                     VK_PIPELINE_STAGE_VERTEX_INPUT_BIT | VK_PIPELINE_STAGE_TRANSFER_BIT, 0, 1, &mb, 0,
                                     nullptr, 0, nullptr);
            } else {
                dev->slots[dev->cur].uploadBarrier = true;
            }
            pendingCopy = dev->serial;
        }
    }
    LowFreeMem(lockMem);
    return D3D_OK;
}

// D3DVERTEXBUFFER_DESC: Format, Type, Usage, Pool, Size, FVF; D3DINDEXBUFFER_DESC: Format, Type,
// Usage, Pool, Size
uint32_t Buffer::GetDesc(uint32_t out) {
    uint32_t d[6] = {index ? format : static_cast<uint32_t>(F_VERTEXDATA), GetType(), usage, pool, length, index ? 0 : format};
    memcpy(At(out), d, index ? 20 : 24);
    return D3D_OK;
}

// ---- queries ----------------------------------------------------------------------------------------------
namespace {
uint64_t NowNs() {
    timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return static_cast<uint64_t>(t.tv_sec) * 1000000000ull + static_cast<uint64_t>(t.tv_nsec);
}
void FreeSlots(Device* dev, std::vector<uint32_t>& slots) {
    if (slots.empty()) return;
    std::vector<uint32_t> s = std::move(slots);
    slots.clear();
    dev->Defer([dev, s]() { dev->occFree.insert(dev->occFree.end(), s.begin(), s.end()); });
}
}  // namespace

Query::~Query() {
    if (dev->activeOcc == this) {
        if (dev->occOpen) dev->EndOcclusion();
        dev->activeOcc = nullptr;
    }
    FreeSlots(dev, slots);
}
uint32_t Query::GetType() { return type; }
uint32_t Query::GetDataSize() { return type == 10 || type == 12 ? 8 : 4; }

// D3DISSUE_END 1, BEGIN 2
uint32_t Query::Issue(uint32_t flags) {
    std::lock_guard<std::recursive_mutex> hold(dev->mu);
    polls = 0;
    if (type == 9 /* OCCLUSION */) {
        if (flags & 2) {
            if (dev->activeOcc && dev->activeOcc != this) {
                LogOnce("vk-occ-overlap", "d3d9vk: overlapping occlusion queries: the earlier one ends early");
                if (dev->occOpen) dev->EndOcclusion();
                dev->activeOcc->building = false;
                dev->activeOcc->serial = dev->serial;
                dev->activeOcc = nullptr;
            }
            if (dev->activeOcc == this && dev->occOpen) dev->EndOcclusion();
            FreeSlots(dev, slots);
            building = true;
            serial = 0;
            dev->activeOcc = this;
            if (dev->passActive) dev->BeginOcclusion();
        }
        if (flags & 1) {
            if (dev->activeOcc == this) {
                if (dev->occOpen) dev->EndOcclusion();
                dev->activeOcc = nullptr;
            }
            building = false;
            serial = dev->serial;
        }
        return D3D_OK;
    }
    if (flags & 1) {
        serial = dev->serial;
        if (type == 10 /* TIMESTAMP */) cpuTime = NowNs();
    }
    return D3D_OK;
}

// D3DGETDATA_FLUSH 1. Event and occlusion answers wait for the submission the query ended in; one
// still being recorded is submitted when the caller says FLUSH, or once it has asked 64 times
// without (a caller spinning on GetData with no flag, as D3D9's drivers flushed on their own): a
// poll per draw call of a query issued this frame does not split the frame into submissions
uint32_t Query::GetData(uint32_t data, uint32_t size, uint32_t flags) {
    std::lock_guard<std::recursive_mutex> hold(dev->mu);
    uint64_t v = 0;
    switch (type) {
        case 8:    // EVENT
        case 9: {  // OCCLUSION
            if (building) return S_FALSE;
            if (serial && serial > dev->completed && !dev->lost) {
                dev->Poll();
                if (serial > dev->completed) {
                    if (serial == dev->serial && ((flags & 1) || ++polls >= 64)) {
                        polls = 0;
                        dev->Submit();
                    }
                    return S_FALSE;
                }
            }
            if (type == 8) {
                v = 1;
            } else if (!dev->occPool) {
                v = 1000;   // (no queries here: visible)
            } else {
                for (uint32_t s : slots) {
                    uint64_t n = 0;
                    if (vkGetQueryPoolResults(dev->device, dev->occPool, s, 1, 8, &n, 8, VK_QUERY_RESULT_64_BIT) == VK_SUCCESS)
                        v += n;
                }
            }
            break;
        }
        case 10: v = cpuTime; break;          // TIMESTAMP: the CPU's clock in ns at the issue
        case 11: v = 0; break;                // TIMESTAMPDISJOINT: never
        case 12: v = 1000000000ull; break;    // TIMESTAMPFREQ: 1 GHz (0 hangs FFXIV's 0x4da7c0)
        default: break;
    }
    if (data && size) {
        uint32_t n = std::min(size, GetDataSize());
        memset(At(data), 0, size);
        memcpy(At(data), &v, n);
    }
    return D3D_OK;
}

// ---- declarations, shaders --------------------------------------------------------------------------------
uint32_t Decl::GetDeclaration(uint32_t out, uint32_t count) {
    uint32_t n = static_cast<uint32_t>(elems.size()) + 1;
    if (out) {
        memcpy(At(out), elems.data(), elems.size() * sizeof(Element32));
        Element32 end{0xFF, 0, DT_UNUSED, 0, 0, 0};
        memcpy(At(out + 8 * (n - 1)), &end, 8);
    }
    if (count) *At<uint32_t>(count) = n;
    return D3D_OK;
}

Shader::~Shader() {
    if (module) {
        VkShaderModule m = module;
        Device* d = dev;
        dev->Defer([d, m]() { vkDestroyShaderModule(d->device, m, nullptr); });
    }
}
uint32_t Shader::GetFunction(uint32_t out, uint32_t sizeOut) {
    uint32_t n = static_cast<uint32_t>(tokens.size() * 4);
    if (out) memcpy(At(out), tokens.data(), n);
    if (sizeOut) *At<uint32_t>(sizeOut) = n;
    return D3D_OK;
}

// ---- state blocks, swap chains ------------------------------------------------------------------------------
StateBlock::~StateBlock() {
    for (auto& t : s.tex)
        if (t) t->Unbind();
    if (s.vs) s.vs->Unbind();
    if (s.ps) s.ps->Unbind();
    if (s.decl) s.decl->Unbind();
    for (auto& str : s.streams)
        if (str.vb) str.vb->Unbind();
    if (s.ib) s.ib->Unbind();
    if (dev->rec == this) dev->rec = nullptr;
}
uint32_t StateBlock::Capture() {
    std::lock_guard<std::recursive_mutex> hold(dev->mu);
    dev->CaptureBlock(this);
    return D3D_OK;
}
uint32_t StateBlock::Apply() {
    std::lock_guard<std::recursive_mutex> hold(dev->mu);
    dev->ApplyBlock(this);
    return D3D_OK;
}

SwapChain::~SwapChain() {
    if (backBuffer) backBuffer->Unbind();
}
uint32_t SwapChain::Present(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t) {
    std::lock_guard<std::recursive_mutex> hold(dev->mu);
    return dev->PresentImage(backBuffer ? backBuffer->Img() : nullptr, pp.BackBufferWidth, pp.BackBufferHeight);
}
uint32_t SwapChain::GetFrontBufferData(uint32_t surface) { return dev->GetRenderTargetData(backBuffer->self, surface); }
uint32_t SwapChain::GetBackBuffer(uint32_t index, uint32_t, uint32_t out) {
    if (index != 0 || !out || !backBuffer) return D3DERR_INVALIDCALL;
    backBuffer->AddRef_();
    *At<uint32_t>(out) = backBuffer->self;
    return D3D_OK;
}
uint32_t SwapChain::GetRasterStatus(uint32_t out) {
    memset(At(out), 0, 8);
    return D3D_OK;
}
uint32_t SwapChain::GetDisplayMode(uint32_t out) { return dev->GetDisplayMode(0, out); }
uint32_t SwapChain::GetPresentParameters(uint32_t out) {
    *At<PresentParams32>(out) = pp;
    return D3D_OK;
}

// ---- making them (the device's Create*, under its lock) ---------------------------------------------------------
namespace {
uint32_t FullChain(uint32_t w, uint32_t h, uint32_t d) {
    uint32_t n = 1;
    for (uint32_t m = std::max({w, h, d}); m > 1; m >>= 1) n++;
    return n;
}
}  // namespace

uint32_t Device::NewTexture(uint32_t rtype, uint32_t w, uint32_t h, uint32_t d, uint32_t levels, uint32_t usage,
                            uint32_t format, uint32_t pool, uint32_t out) {
    std::lock_guard<std::recursive_mutex> hold(mu);
    if (!out || !w || !h || !d) return D3DERR_INVALIDCALL;
    *At<uint32_t>(out) = 0;
    const FormatInfo* fmt = LookupFormat(format);
    // (the NULL format: a render target texture with no texels, whose levels are bound as color
    // targets beside a depth surface, as D3D9's drivers allow; FFXIV's Kernel::Texture of its 0x5100)
    bool nullTarget = fmt && fmt->null && rtype == RT_TEXTURE && (usage & U_RENDERTARGET);
    if (!fmt || (fmt->null && !nullTarget)) {
        static Once<4> once;
        if (once.First(format)) Log("d3d9vk: a texture of format %s: not supported", FormatName(format));
        return D3DERR_INVALIDCALL;
    }
    auto t = new Texture();
    t->dev = this;
    Storage& s = t->st;
    s.dev = this, s.fmt = fmt, s.format = format, s.usage = usage, s.pool = pool, s.rtype = rtype;
    s.width = w, s.height = h, s.depth = d;
    uint32_t full = FullChain(w, h, d);
    if (usage & U_AUTOGENMIPMAP) {
        s.levels = levels == 1 ? 1 : full;
        t->apiLevels = 1;
    } else {
        s.levels = t->apiLevels = levels ? std::min(levels, full) : full;
    }
    s.layers = rtype == RT_CUBETEXTURE ? 6 : 1;
    s.cpuOnly = pool == POOL_SYSTEMMEM || pool == POOL_SCRATCH;
    s.subs.resize(s.levels * s.layers);
    if (!s.cpuOnly && !nullTarget) {
        VkImageUsageFlags u = fmt->sampled ? VK_IMAGE_USAGE_SAMPLED_BIT : 0;
        if (usage & U_RENDERTARGET) {
            if (!fmt->color) {
                Log("d3d9vk: a render target texture of %s: the GPU cannot render to it", FormatName(format));
                delete t;
                return D3DERR_NOTAVAILABLE;
            }
            u |= VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT;
        }
        if ((usage & U_DEPTHSTENCIL) || fmt->depth) u |= VK_IMAGE_USAGE_DEPTH_STENCIL_ATTACHMENT_BIT;
        VkImageViewType vt = rtype == RT_CUBETEXTURE    ? VK_IMAGE_VIEW_TYPE_CUBE
                             : rtype == RT_VOLUMETEXTURE ? VK_IMAGE_VIEW_TYPE_3D
                                                         : VK_IMAGE_VIEW_TYPE_2D;
        s.img = CreateImage(fmt, vt, w, h, d, s.levels, s.layers, u);
        if (!s.img) {
            delete t;
            return D3DERR_OUTOFVIDEOMEMORY;
        }
        if (usage & (U_RENDERTARGET | U_DEPTHSTENCIL)) ClearImage(s.img, VkClearColorValue{});
    }
    t->self = NewObject(TextureVtable(rtype), static_cast<Base*>(t));
    *At<uint32_t>(out) = t->self;
    return D3D_OK;
}

Surface* Device::NewSurface(uint32_t w, uint32_t h, uint32_t format, uint32_t usage, uint32_t pool, uint32_t* hr) {
    std::lock_guard<std::recursive_mutex> hold(mu);
    *hr = D3D_OK;
    const FormatInfo* fmt = LookupFormat(format);
    if (!fmt || !w || !h) {
        static Once<4> once;
        if (once.First(format)) Log("d3d9vk: a surface of format %s: not supported", FormatName(format));
        *hr = D3DERR_INVALIDCALL;
        return nullptr;
    }
    auto s = new Surface();
    s->dev = this;
    s->st = &s->own;
    Storage& o = s->own;
    o.dev = this, o.fmt = fmt, o.format = format, o.usage = usage, o.pool = pool, o.rtype = RT_SURFACE;
    o.width = w, o.height = h;
    o.cpuOnly = pool == POOL_SYSTEMMEM || pool == POOL_SCRATCH;
    o.subs.resize(1);
    if (!o.cpuOnly && !fmt->null) {
        VkImageUsageFlags u = 0;
        if ((usage & U_RENDERTARGET) && fmt->color) u |= VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT | (fmt->sampled ? VK_IMAGE_USAGE_SAMPLED_BIT : 0);
        if (fmt->depth) u |= VK_IMAGE_USAGE_DEPTH_STENCIL_ATTACHMENT_BIT;
        o.img = CreateImage(fmt, VK_IMAGE_VIEW_TYPE_2D, w, h, 1, 1, 1, u);
        if (!o.img) {
            delete s;
            *hr = D3DERR_OUTOFVIDEOMEMORY;
            return nullptr;
        }
        if (usage & (U_RENDERTARGET | U_DEPTHSTENCIL)) ClearImage(o.img, VkClearColorValue{});
    }
    s->self = NewObject(SurfaceVtable(), static_cast<Base*>(s));
    return s;
}

uint32_t Device::NewBuffer(bool index, uint32_t length, uint32_t usage, uint32_t format, uint32_t pool, uint32_t out) {
    std::lock_guard<std::recursive_mutex> hold(mu);
    if (!out || !length) return D3DERR_INVALIDCALL;
    *At<uint32_t>(out) = 0;
    auto b = new Buffer();
    b->dev = this;
    b->index = index, b->length = length, b->usage = usage, b->format = format, b->pool = pool;
    b->dynamic = (usage & U_DYNAMIC) || pool == POOL_SYSTEMMEM || pool == POOL_SCRATCH;
    if (b->dynamic) {
        b->shadow = LowAllocZero(length);
    } else if (!MakeBuffer(length,
                           VK_BUFFER_USAGE_VERTEX_BUFFER_BIT | VK_BUFFER_USAGE_INDEX_BUFFER_BIT |
                               VK_BUFFER_USAGE_TRANSFER_DST_BIT,
                           VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT,
                           VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT, &b->buffer, &b->mem)) {
        delete b;
        return D3DERR_OUTOFVIDEOMEMORY;
    }
    if (!b->dynamic && !b->mem.mapped) LogOnce("vk-vb-unmapped", "d3d9vk: static buffers are not host visible here: their locks start empty");
    b->self = NewObject(BufferVtable(index), static_cast<Base*>(b));
    *At<uint32_t>(out) = b->self;
    return D3D_OK;
}

Surface* Device::MakeBackBuffer(PresentParams32* p) {
    std::lock_guard<std::recursive_mutex> hold(mu);
    int ww = 0, wh = 0;
    if (void* win = rhipper_window_use(&ww, &wh)) rhipper_window_done(win);
    if (!p->BackBufferWidth || !p->BackBufferHeight) {
        p->BackBufferWidth = ww > 0 ? static_cast<uint32_t>(ww) : 1280;
        p->BackBufferHeight = wh > 0 ? static_cast<uint32_t>(wh) : 720;
    }
    if (!p->BackBufferFormat) p->BackBufferFormat = F_X8R8G8B8;
    if (!p->BackBufferCount) p->BackBufferCount = 1;
    uint32_t hr;
    Surface* bb = NewSurface(p->BackBufferWidth, p->BackBufferHeight, p->BackBufferFormat, U_RENDERTARGET, POOL_DEFAULT, &hr);
    if (!bb) return nullptr;
    bb->refs = 0;   // (held by its swap chain alone: GetBackBuffer's AddRef is the reference's)
    bb->Bind();
    return bb;
}

SwapChain* Device::NewSwapChain(PresentParams32* p, bool isImplicit) {
    std::lock_guard<std::recursive_mutex> hold(mu);
    Surface* bb = MakeBackBuffer(p);
    if (!bb) return nullptr;
    auto sc = new SwapChain();
    sc->dev = this;
    sc->pp = *p;
    sc->backBuffer = bb;
    sc->implicit = isImplicit;
    sc->self = NewObject(SwapChainVtable(), static_cast<Base*>(sc));
    return sc;
}

// ---- the vtables -------------------------------------------------------------------------------------------
namespace {
template <typename T>
void Common(const void** m) {
    m[0] = M_<&Base::QueryInterface>();
    m[1] = M_<&Base::AddRef_>();
    m[2] = M_<&Base::Release_>();
    m[3] = M_<&Base::GetDevice>();
}
void ResourceCommon(const void** m) {
    Common<Base>(m);
    m[4] = M_<&Base::SetPrivateData>();
    m[5] = M_<&Base::GetPrivateData>();
    m[6] = M_<&Base::FreePrivateData>();
    m[7] = M_<&Base::SetPriority>();
    m[8] = M_<&Base::GetPriority>();
    m[9] = M_<&Base::PreLoad>();
}
}  // namespace

uint32_t SurfaceVtable() {
    static uint32_t v = [] {
        const void* m[17];
        ResourceCommon(m);
        m[10] = M_<&Surface::GetType>(), m[11] = M_<&Surface::GetContainer>(), m[12] = M_<&Surface::GetDesc>();
        m[13] = M_<&Surface::LockRect>(), m[14] = M_<&Surface::UnlockRect>(), m[15] = M_<&Surface::GetDC>();
        m[16] = M_<&Surface::ReleaseDC>();
        return Vtable(m, 17);
    }();
    return v;
}

uint32_t TextureVtable(uint32_t rtype) {
    static uint32_t made[3] = {};
    static std::once_flag once[3];
    unsigned k = rtype == RT_CUBETEXTURE ? 1 : rtype == RT_VOLUMETEXTURE ? 2 : 0;
    std::call_once(once[k], [k] {
        const void* m[22];
        ResourceCommon(m);
        m[10] = M_<&Texture::GetType>(), m[11] = M_<&Texture::SetLOD>(), m[12] = M_<&Texture::GetLOD>();
        m[13] = M_<&Texture::GetLevelCount>(), m[14] = M_<&Texture::SetAutoGenFilterType>();
        m[15] = M_<&Texture::GetAutoGenFilterType>(), m[16] = M_<&Texture::GenerateMipSubLevels>();
        if (k == 0) {
            m[17] = M_<&Texture::GetLevelDesc>(), m[18] = M_<&Texture::GetSurfaceLevel>();
            m[19] = M_<&Texture::LockRect>(), m[20] = M_<&Texture::UnlockRect>(), m[21] = M_<&Texture::AddDirtyRect>();
        } else if (k == 1) {
            m[17] = M_<&Texture::CubeGetLevelDesc>(), m[18] = M_<&Texture::GetCubeMapSurface>();
            m[19] = M_<&Texture::CubeLockRect>(), m[20] = M_<&Texture::CubeUnlockRect>();
            m[21] = M_<&Texture::CubeAddDirtyRect>();
        } else {
            m[17] = M_<&Texture::VolGetLevelDesc>(), m[18] = M_<&Texture::GetVolumeLevel>();
            m[19] = M_<&Texture::LockBox>(), m[20] = M_<&Texture::UnlockBox>(), m[21] = M_<&Texture::AddDirtyBox>();
        }
        made[k] = Vtable(m, 22);
    });
    return made[k];
}

uint32_t VolumeVtable() {
    static uint32_t v = [] {
        const void* m[11];
        Common<Base>(m);
        m[4] = M_<&Base::SetPrivateData>(), m[5] = M_<&Base::GetPrivateData>(), m[6] = M_<&Base::FreePrivateData>();
        m[7] = M_<&Volume::GetContainer>(), m[8] = M_<&Volume::GetDesc>(), m[9] = M_<&Volume::LockBox>();
        m[10] = M_<&Volume::UnlockBox>();
        return Vtable(m, 11);
    }();
    return v;
}

uint32_t BufferVtable(bool index) {
    static uint32_t made[2] = {};
    static std::once_flag once[2];
    std::call_once(once[index ? 1 : 0], [index] {
        const void* m[14];
        ResourceCommon(m);
        m[10] = M_<&Buffer::GetType>(), m[11] = M_<&Buffer::Lock>(), m[12] = M_<&Buffer::Unlock>();
        m[13] = M_<&Buffer::GetDesc>();
        made[index ? 1 : 0] = Vtable(m, 14);
    });
    return made[index ? 1 : 0];
}

uint32_t QueryVtable() {
    static uint32_t v = [] {
        const void* m[8];
        Common<Base>(m);
        m[4] = M_<&Query::GetType>(), m[5] = M_<&Query::GetDataSize>(), m[6] = M_<&Query::Issue>();
        m[7] = M_<&Query::GetData>();
        return Vtable(m, 8);
    }();
    return v;
}

uint32_t StateBlockVtable() {
    static uint32_t v = [] {
        const void* m[6];
        Common<Base>(m);
        m[4] = M_<&StateBlock::Capture>(), m[5] = M_<&StateBlock::Apply>();
        return Vtable(m, 6);
    }();
    return v;
}

uint32_t DeclVtable() {
    static uint32_t v = [] {
        const void* m[5];
        Common<Base>(m);
        m[4] = M_<&Decl::GetDeclaration>();
        return Vtable(m, 5);
    }();
    return v;
}

uint32_t ShaderVtable() {
    static uint32_t v = [] {
        const void* m[5];
        Common<Base>(m);
        m[4] = M_<&Shader::GetFunction>();
        return Vtable(m, 5);
    }();
    return v;
}

uint32_t SwapChainVtable() {
    static uint32_t v = [] {
        const void* m[10];
        m[0] = M_<&Base::QueryInterface>(), m[1] = M_<&Base::AddRef_>(), m[2] = M_<&Base::Release_>();
        m[3] = M_<&SwapChain::Present>(), m[4] = M_<&SwapChain::GetFrontBufferData>();
        m[5] = M_<&SwapChain::GetBackBuffer>(), m[6] = M_<&SwapChain::GetRasterStatus>();
        m[7] = M_<&SwapChain::GetDisplayMode>(), m[8] = M_<&Base::GetDevice>();
        m[9] = M_<&SwapChain::GetPresentParameters>();
        return Vtable(m, 10);
    }();
    return v;
}

}  // namespace rh::d3d9vk
