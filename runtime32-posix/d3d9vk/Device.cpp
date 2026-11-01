// d3d9vk's device: Vulkan's instance, adapter and device, the IDirect3D9 the reference gets from
// Direct3DCreate9, the IDirect3DDevice9 (its state and setters), submissions and Present.
//
// Direct3DCreate9 (d3d9_null.cpp's NullDirect3DCreate9 asks here first) makes this IDirect3D9 when
// Vulkan 1.3 with dynamic rendering and push descriptors is there; else the null renderer, logged.
// <ENV>_D3D9=null forces the null one, <ENV>_VKDEBUG=1 turns the validation layer on when present.
//
// The host's surface (rhipper_window_use) is taken per Present only: a Vulkan surface is made from
// it the first time and again whenever the host's window or its size changes, the swapchain with it,
// so a pause / resume (surfaceDestroyed / surfaceCreated) costs one frame without a present.
#include <android/native_window.h>

#include "Vk.h"

extern "C" void gen_set_x87_cw(unsigned short cw);   // Hooks.cpp

namespace rh {
uint32_t NullDirect3DCreate9(uint32_t sdk);   // d3d9_null.cpp
}

namespace rh::d3d9vk {

namespace {

bool HasExtension(const std::vector<VkExtensionProperties>& list, const char* name) {
    for (const auto& e : list)
        if (strcmp(e.extensionName, name) == 0) return true;
    return false;
}

Vulkan* MakeVulkan() {
    if (Env("D3D9") == "null") {
        Log("d3d9vk: " RHIPPER_ENV "_D3D9=null: the null renderer");
        return nullptr;
    }
    auto enumerateVersion =
        reinterpret_cast<PFN_vkEnumerateInstanceVersion>(vkGetInstanceProcAddr(nullptr, "vkEnumerateInstanceVersion"));
    uint32_t version = VK_API_VERSION_1_0;
    if (enumerateVersion) enumerateVersion(&version);
    if (version < VK_API_VERSION_1_3) {
        Log("d3d9vk: the Vulkan loader is %u.%u: 1.3 is needed", VK_API_VERSION_MAJOR(version), VK_API_VERSION_MINOR(version));
        return nullptr;
    }
    uint32_t n = 0;
    vkEnumerateInstanceExtensionProperties(nullptr, &n, nullptr);
    std::vector<VkExtensionProperties> exts(n);
    vkEnumerateInstanceExtensionProperties(nullptr, &n, exts.data());
    if (!HasExtension(exts, VK_KHR_SURFACE_EXTENSION_NAME) || !HasExtension(exts, VK_KHR_ANDROID_SURFACE_EXTENSION_NAME)) {
        Log("d3d9vk: no VK_KHR_android_surface");
        return nullptr;
    }
    const char* instExts[] = {VK_KHR_SURFACE_EXTENSION_NAME, VK_KHR_ANDROID_SURFACE_EXTENSION_NAME};
    std::vector<const char*> layers;
    if (Env("VKDEBUG") == "1") {
        uint32_t nl = 0;
        vkEnumerateInstanceLayerProperties(&nl, nullptr);
        std::vector<VkLayerProperties> ls(nl);
        vkEnumerateInstanceLayerProperties(&nl, ls.data());
        for (const auto& l : ls)
            if (strcmp(l.layerName, "VK_LAYER_KHRONOS_validation") == 0) layers.push_back("VK_LAYER_KHRONOS_validation");
        Log("d3d9vk: validation layer %s", layers.empty() ? "asked for, not present" : "on");
    }
    VkApplicationInfo app{VK_STRUCTURE_TYPE_APPLICATION_INFO};
    app.pApplicationName = RHIPPER_NAME;
    app.pEngineName = "rhipper d3d9vk";
    app.apiVersion = VK_API_VERSION_1_3;
    VkInstanceCreateInfo ci{VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO};
    ci.pApplicationInfo = &app;
    ci.enabledExtensionCount = 2;
    ci.ppEnabledExtensionNames = instExts;
    ci.enabledLayerCount = static_cast<uint32_t>(layers.size());
    ci.ppEnabledLayerNames = layers.data();
    auto vk = new Vulkan();
    VkResult r = vkCreateInstance(&ci, nullptr, &vk->instance);
    if (r != VK_SUCCESS) {
        Log("d3d9vk: vkCreateInstance failed: %d", r);
        delete vk;
        return nullptr;
    }
    uint32_t nd = 0;
    vkEnumeratePhysicalDevices(vk->instance, &nd, nullptr);
    std::vector<VkPhysicalDevice> devs(nd);
    vkEnumeratePhysicalDevices(vk->instance, &nd, devs.data());
    auto features2 = reinterpret_cast<PFN_vkGetPhysicalDeviceFeatures2>(
        vkGetInstanceProcAddr(vk->instance, "vkGetPhysicalDeviceFeatures2"));
    for (VkPhysicalDevice pd : devs) {
        VkPhysicalDeviceProperties props;
        vkGetPhysicalDeviceProperties(pd, &props);
        if (props.apiVersion < VK_API_VERSION_1_3) continue;
        uint32_t nq = 0;
        vkGetPhysicalDeviceQueueFamilyProperties(pd, &nq, nullptr);
        std::vector<VkQueueFamilyProperties> qs(nq);
        vkGetPhysicalDeviceQueueFamilyProperties(pd, &nq, qs.data());
        uint32_t family = ~0u;
        for (uint32_t k = 0; k < nq; k++)
            if (qs[k].queueFlags & VK_QUEUE_GRAPHICS_BIT) {
                family = k;
                break;
            }
        if (family == ~0u) continue;
        uint32_t ne = 0;
        vkEnumerateDeviceExtensionProperties(pd, nullptr, &ne, nullptr);
        std::vector<VkExtensionProperties> dexts(ne);
        vkEnumerateDeviceExtensionProperties(pd, nullptr, &ne, dexts.data());
        if (!HasExtension(dexts, VK_KHR_SWAPCHAIN_EXTENSION_NAME)) continue;
        bool push = HasExtension(dexts, VK_KHR_PUSH_DESCRIPTOR_EXTENSION_NAME);
        if (!push && props.apiVersion < VK_MAKE_API_VERSION(0, 1, 4, 0)) {
            Log("d3d9vk: %s has no push descriptors", props.deviceName);
            continue;
        }
        VkPhysicalDeviceVulkan13Features f13{VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_3_FEATURES};
        VkPhysicalDeviceVulkan12Features f12{VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_2_FEATURES};
        f12.pNext = &f13;
        VkPhysicalDeviceFeatures2 f2{VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FEATURES_2};
        f2.pNext = &f12;
        if (features2) features2(pd, &f2);
        if (!f13.dynamicRendering) {
            Log("d3d9vk: %s has no dynamic rendering", props.deviceName);
            continue;
        }
        vk->phys = pd;
        vk->props = props;
        vk->features = f2.features;
        vk->family = family;
        vk->pushDescriptorExt = push;
        vk->hostQueryReset = f12.hostQueryReset;
        vkGetPhysicalDeviceMemoryProperties(pd, &vk->memProps);
        break;
    }
    if (!vk->phys) {
        Log("d3d9vk: no Vulkan 1.3 GPU with graphics, a swapchain and push descriptors (%u devices)", nd);
        vkDestroyInstance(vk->instance, nullptr);
        delete vk;
        return nullptr;
    }
    InitFormats(vk->phys, vk->features.textureCompressionBC);
    const auto& p = vk->props;
    Log("d3d9vk: %s, Vulkan %u.%u.%u, driver %#x, vendor %#x device %#x; BC %u, anisotropy %u, host query reset %u",
        p.deviceName, VK_API_VERSION_MAJOR(p.apiVersion), VK_API_VERSION_MINOR(p.apiVersion),
        VK_API_VERSION_PATCH(p.apiVersion), p.driverVersion, p.vendorID, p.deviceID, vk->features.textureCompressionBC,
        vk->features.samplerAnisotropy, vk->hostQueryReset);
    return vk;
}

template <typename T>
void LoadFn(VkDevice d, T& out, const char* a, const char* b = nullptr) {
    out = reinterpret_cast<T>(vkGetDeviceProcAddr(d, a));
    if (!out && b) out = reinterpret_cast<T>(vkGetDeviceProcAddr(d, b));
}

uint32_t DeviceVtable();
uint32_t D3D9Vtable();

}  // namespace

Vulkan* GetVulkan() {
    static Vulkan* vk = nullptr;
    static std::once_flag once;
    std::call_once(once, [] { vk = MakeVulkan(); });
    return vk;
}

bool Device::Check(VkResult r, const char* what) {
    if (r == VK_SUCCESS) return true;
    if (r == VK_ERROR_DEVICE_LOST) {
        if (!lost) Log("d3d9vk: %s: the device is lost; nothing more is drawn", what);
        lost = true;
    } else {
        LogOnce((std::string("vk-fail-") + what + std::to_string(r)).c_str(), "d3d9vk: %s failed: %d", what, r);
    }
    return false;
}

// ---- the device's Vulkan side -------------------------------------------------------------------------
bool Device::Init() {
    const VkPhysicalDeviceFeatures& have = vk->features;
    VkPhysicalDeviceFeatures2 f2{VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FEATURES_2};
    f2.features.textureCompressionBC = have.textureCompressionBC;
    f2.features.samplerAnisotropy = have.samplerAnisotropy;
    f2.features.fillModeNonSolid = have.fillModeNonSolid;
    f2.features.occlusionQueryPrecise = have.occlusionQueryPrecise;
    f2.features.independentBlend = have.independentBlend;
    VkPhysicalDeviceVulkan12Features f12{VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_2_FEATURES};
    VkPhysicalDeviceVulkan13Features f13{VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_3_FEATURES};
    {
        VkPhysicalDeviceVulkan12Features q12{VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_2_FEATURES};
        VkPhysicalDeviceFeatures2 q{VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FEATURES_2};
        q.pNext = &q12;
        auto features2 = reinterpret_cast<PFN_vkGetPhysicalDeviceFeatures2>(
            vkGetInstanceProcAddr(vk->instance, "vkGetPhysicalDeviceFeatures2"));
        if (features2) features2(vk->phys, &q);
        f12.hostQueryReset = q12.hostQueryReset;
        f12.samplerMirrorClampToEdge = q12.samplerMirrorClampToEdge;
    }
    f13.dynamicRendering = VK_TRUE;
    f2.pNext = &f12;
    f12.pNext = &f13;
    float priority = 1.0f;
    VkDeviceQueueCreateInfo qi{VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO};
    qi.queueFamilyIndex = vk->family;
    qi.queueCount = 1;
    qi.pQueuePriorities = &priority;
    std::vector<const char*> exts = {VK_KHR_SWAPCHAIN_EXTENSION_NAME};
    if (vk->pushDescriptorExt) exts.push_back(VK_KHR_PUSH_DESCRIPTOR_EXTENSION_NAME);
    VkDeviceCreateInfo ci{VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO};
    ci.pNext = &f2;
    ci.queueCreateInfoCount = 1;
    ci.pQueueCreateInfos = &qi;
    ci.enabledExtensionCount = static_cast<uint32_t>(exts.size());
    ci.ppEnabledExtensionNames = exts.data();
    if (!Check(vkCreateDevice(vk->phys, &ci, nullptr, &device), "vkCreateDevice")) return false;
    vkGetDeviceQueue(device, vk->family, 0, &queue);
    independentBlend = have.independentBlend, anisotropy = have.samplerAnisotropy;
    fillNonSolid = have.fillModeNonSolid, preciseOcclusion = have.occlusionQueryPrecise;
    mirrorClamp = f12.samplerMirrorClampToEdge, hostQueryReset = f12.hostQueryReset;

    LoadFn(device, fn.CmdBeginRendering, "vkCmdBeginRendering", "vkCmdBeginRenderingKHR");
    LoadFn(device, fn.CmdEndRendering, "vkCmdEndRendering", "vkCmdEndRenderingKHR");
    LoadFn(device, fn.CmdSetCullMode, "vkCmdSetCullMode", "vkCmdSetCullModeEXT");
    LoadFn(device, fn.CmdSetFrontFace, "vkCmdSetFrontFace", "vkCmdSetFrontFaceEXT");
    LoadFn(device, fn.CmdSetPrimitiveTopology, "vkCmdSetPrimitiveTopology", "vkCmdSetPrimitiveTopologyEXT");
    LoadFn(device, fn.CmdSetDepthTestEnable, "vkCmdSetDepthTestEnable", "vkCmdSetDepthTestEnableEXT");
    LoadFn(device, fn.CmdSetDepthWriteEnable, "vkCmdSetDepthWriteEnable", "vkCmdSetDepthWriteEnableEXT");
    LoadFn(device, fn.CmdSetDepthCompareOp, "vkCmdSetDepthCompareOp", "vkCmdSetDepthCompareOpEXT");
    LoadFn(device, fn.CmdSetStencilTestEnable, "vkCmdSetStencilTestEnable", "vkCmdSetStencilTestEnableEXT");
    LoadFn(device, fn.CmdSetStencilOp, "vkCmdSetStencilOp", "vkCmdSetStencilOpEXT");
    LoadFn(device, fn.CmdSetDepthBiasEnable, "vkCmdSetDepthBiasEnable", "vkCmdSetDepthBiasEnableEXT");
    LoadFn(device, fn.CmdBindVertexBuffers2, "vkCmdBindVertexBuffers2", "vkCmdBindVertexBuffers2EXT");
    LoadFn(device, fn.CmdPushDescriptorSet, "vkCmdPushDescriptorSetKHR", "vkCmdPushDescriptorSet");
    LoadFn(device, fn.ResetQueryPool, "vkResetQueryPool", "vkResetQueryPoolEXT");
    if (!fn.CmdBeginRendering || !fn.CmdEndRendering || !fn.CmdSetCullMode || !fn.CmdSetFrontFace ||
        !fn.CmdSetPrimitiveTopology || !fn.CmdSetDepthTestEnable || !fn.CmdSetDepthWriteEnable ||
        !fn.CmdSetDepthCompareOp || !fn.CmdSetStencilTestEnable || !fn.CmdSetStencilOp || !fn.CmdSetDepthBiasEnable ||
        !fn.CmdBindVertexBuffers2 || !fn.CmdPushDescriptorSet) {
        Log("d3d9vk: a Vulkan 1.3 command is missing from the driver");
        return false;
    }
    mem = new MemAllocator(device, vk->memProps);

    for (Slot& s : slots) {
        VkCommandPoolCreateInfo pi{VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO};
        pi.flags = VK_COMMAND_POOL_CREATE_TRANSIENT_BIT;
        pi.queueFamilyIndex = vk->family;
        if (!Check(vkCreateCommandPool(device, &pi, nullptr, &s.pool), "vkCreateCommandPool")) return false;
        VkCommandBufferAllocateInfo ai{VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO};
        ai.commandPool = s.pool;
        ai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
        ai.commandBufferCount = 2;
        VkCommandBuffer cbs[2];
        if (!Check(vkAllocateCommandBuffers(device, &ai, cbs), "vkAllocateCommandBuffers")) return false;
        s.cmd = cbs[0], s.upload = cbs[1];
        VkFenceCreateInfo fi{VK_STRUCTURE_TYPE_FENCE_CREATE_INFO};
        if (!Check(vkCreateFence(device, &fi, nullptr, &s.fence), "vkCreateFence")) return false;
        VkSemaphoreCreateInfo si{VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO};
        if (!Check(vkCreateSemaphore(device, &si, nullptr, &s.acquire), "vkCreateSemaphore")) return false;
    }
    if (!InitPipelines()) return false;
    BeginSlot();

    // the fixed function's shaders
    auto module = [&](const std::vector<uint32_t>& words, VkShaderModule* out) {
        VkShaderModuleCreateInfo mi{VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO};
        mi.codeSize = words.size() * 4;
        mi.pCode = words.data();
        return Check(vkCreateShaderModule(device, &mi, nullptr, out), "vkCreateShaderModule (fixed function)");
    };
    if (!module(FixedVertexSpirv(), &ffVs) || !module(FixedPixelSpirv(), &ffPs)) return false;
    FixedVertexInfo(&ffVsInfo);
    FixedPixelInfo(&ffPsInfo);

    // stand-ins: (0, 0, 0, 1) for an unbound sampler (white for the fixed function's), the vertex inputs
    // no stream feeds read (0, 0, 0, 1) at 0 and (1, 1, 1, 1) at 16
    const FormatInfo* argb = LookupFormat(F_A8R8G8B8);
    black2D = CreateImage(argb, VK_IMAGE_VIEW_TYPE_2D, 1, 1, 1, 1, 1, VK_IMAGE_USAGE_SAMPLED_BIT);
    white2D = CreateImage(argb, VK_IMAGE_VIEW_TYPE_2D, 1, 1, 1, 1, 1, VK_IMAGE_USAGE_SAMPLED_BIT);
    blackCube = CreateImage(argb, VK_IMAGE_VIEW_TYPE_CUBE, 1, 1, 1, 1, 6, VK_IMAGE_USAGE_SAMPLED_BIT);
    black3D = CreateImage(argb, VK_IMAGE_VIEW_TYPE_3D, 1, 1, 1, 1, 1, VK_IMAGE_USAGE_SAMPLED_BIT);
    if (!black2D || !white2D || !blackCube || !black3D) return false;
    ClearImage(black2D, VkClearColorValue{{0, 0, 0, 1}});
    ClearImage(white2D, VkClearColorValue{{1, 1, 1, 1}});
    ClearImage(blackCube, VkClearColorValue{{0, 0, 0, 1}});
    ClearImage(black3D, VkClearColorValue{{0, 0, 0, 1}});
    if (!MakeBuffer(32, VK_BUFFER_USAGE_VERTEX_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT,
                    VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT, 0, &dummyVb, &dummyVbMem))
        return false;
    const float dummy[8] = {0, 0, 0, 1, 1, 1, 1, 1};
    if (RingSlice r = Ring(32, 16); r.ptr) {
        memcpy(r.ptr, dummy, 32);
        VkBufferCopy c{r.offset, 0, 32};
        vkCmdCopyBuffer(Upload(), r.buffer, dummyVb, 1, &c);
    }

    if (hostQueryReset && fn.ResetQueryPool) {
        VkQueryPoolCreateInfo qp{VK_STRUCTURE_TYPE_QUERY_POOL_CREATE_INFO};
        qp.queryType = VK_QUERY_TYPE_OCCLUSION;
        qp.queryCount = 4096;
        if (Check(vkCreateQueryPool(device, &qp, nullptr, &occPool), "vkCreateQueryPool")) {
            fn.ResetQueryPool(device, occPool, 0, 4096);
            for (uint32_t k = 4096; k-- > 0;) occFree.push_back(k);
        }
    } else {
        Log("d3d9vk: no host query reset: occlusion queries answer visible");
    }
    return true;
}

Device::~Device() {
    // (the Vulkan device is kept: resources the reference still holds would outlive it)
    Log("d3d9vk: device released after %llu presents, %llu draws", static_cast<unsigned long long>(presents),
        static_cast<unsigned long long>(draws));
}

// ---- submissions ----------------------------------------------------------------------------------------
void Device::BeginSlot() {
    Slot& s = slots[cur];
    if (s.pending) {
        if (vkWaitForFences(device, 1, &s.fence, VK_TRUE, UINT64_MAX) == VK_ERROR_DEVICE_LOST) lost = true;
        completed = std::max(completed, s.serial);
        s.pending = false;
        vkResetFences(device, 1, &s.fence);
    }
    std::vector<std::function<void()>> deferred = std::move(s.deferred);
    s.deferred.clear();
    for (auto& f : deferred) f();
    for (Chunk* c : s.chunks) {
        c->used = 0;
        if (c->size > (8u << 20) || freeChunks.size() >= 24) {
            vkDestroyBuffer(device, c->buffer, nullptr);
            mem->Free(c->mem);
            delete c;
        } else {
            freeChunks.push_back(c);
        }
    }
    s.chunks.clear();
    vkResetCommandPool(device, s.pool, 0);
    VkCommandBufferBeginInfo bi{VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO};
    bi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    vkBeginCommandBuffer(s.cmd, &bi);
    s.uploadOpen = false, s.uploadBarrier = false;
    s.serial = serial;
    cmd = s.cmd;
    dirty = kDirtyAll;
    boundPipeline = VK_NULL_HANDLE;
    lastKeyValid = false;
    vsBlockSize = psBlockSize = 0;
}

VkCommandBuffer Device::Upload() {
    Slot& s = slots[cur];
    if (!s.uploadOpen) {
        VkCommandBufferBeginInfo bi{VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO};
        bi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
        vkBeginCommandBuffer(s.upload, &bi);
        s.uploadOpen = true;
    }
    return s.upload;
}

VkCommandBuffer Device::CmdFor(uint64_t lastUse) {
    if (lastUse == serial) {
        EndPass();
        return cmd;
    }
    return Upload();
}

void Device::Defer(std::function<void()> f) { slots[cur].deferred.push_back(std::move(f)); }

void Device::Submit(VkSemaphore wait, VkSemaphore signal) {
    EndPass();
    Slot& s = slots[cur];
    VkCommandBuffer bufs[2];
    uint32_t n = 0;
    if (s.uploadOpen) {
        // (everything the uploads wrote, visible to everything after)
        VkMemoryBarrier mb{VK_STRUCTURE_TYPE_MEMORY_BARRIER};
        mb.srcAccessMask = VK_ACCESS_MEMORY_WRITE_BIT;
        mb.dstAccessMask = VK_ACCESS_MEMORY_READ_BIT | VK_ACCESS_MEMORY_WRITE_BIT;
        vkCmdPipelineBarrier(s.upload, VK_PIPELINE_STAGE_ALL_COMMANDS_BIT, VK_PIPELINE_STAGE_ALL_COMMANDS_BIT, 0, 1, &mb,
                             0, nullptr, 0, nullptr);
        vkEndCommandBuffer(s.upload);
        bufs[n++] = s.upload;
    }
    vkEndCommandBuffer(s.cmd);
    bufs[n++] = s.cmd;
    VkPipelineStageFlags waitStage = VK_PIPELINE_STAGE_TRANSFER_BIT;
    VkSubmitInfo si{VK_STRUCTURE_TYPE_SUBMIT_INFO};
    si.waitSemaphoreCount = wait ? 1 : 0;
    si.pWaitSemaphores = &wait;
    si.pWaitDstStageMask = &waitStage;
    si.commandBufferCount = n;
    si.pCommandBuffers = bufs;
    si.signalSemaphoreCount = signal ? 1 : 0;
    si.pSignalSemaphores = &signal;
    if (!lost && Check(vkQueueSubmit(queue, 1, &si, s.fence), "vkQueueSubmit")) s.pending = true;
    frameDraws = 0;
    serial++;
    cur = (cur + 1) % kSlots;
    BeginSlot();
}

void Device::Poll() {
    for (Slot& s : slots)
        if (s.pending && s.serial > completed && vkGetFenceStatus(device, s.fence) == VK_SUCCESS)
            completed = std::max(completed, s.serial);
}

void Device::WaitSerial(uint64_t want) {
    if (want >= serial) Submit();
    for (Slot& s : slots)
        if (s.pending && s.serial <= want && s.serial > completed) {
            if (vkWaitForFences(device, 1, &s.fence, VK_TRUE, UINT64_MAX) == VK_ERROR_DEVICE_LOST) lost = true;
            completed = std::max(completed, s.serial);
        }
    completed = std::max(completed, want);
}

// ---- presentation ---------------------------------------------------------------------------------------
void Device::DestroySwapchain(bool surfaceToo) {
    if (!swapchain && !(surfaceToo && surface)) return;
    vkDeviceWaitIdle(device);
    for (Slot& s : slots)
        if (s.pending) completed = std::max(completed, s.serial);
    for (VkSemaphore sem : scDone) vkDestroySemaphore(device, sem, nullptr);
    scDone.clear();
    scImages.clear();
    if (swapchain) vkDestroySwapchainKHR(device, swapchain, nullptr);
    swapchain = VK_NULL_HANDLE;
    if (surfaceToo) {
        if (surface) vkDestroySurfaceKHR(vk->instance, surface, nullptr);
        surface = VK_NULL_HANDLE;
        window = nullptr;
    }
}

bool Device::EnsureSwapchain(void* win, int w, int h) {
    if (win != window) {
        DestroySwapchain(true);
        VkAndroidSurfaceCreateInfoKHR si{VK_STRUCTURE_TYPE_ANDROID_SURFACE_CREATE_INFO_KHR};
        si.window = static_cast<ANativeWindow*>(win);
        if (!Check(vkCreateAndroidSurfaceKHR(vk->instance, &si, nullptr, &surface), "vkCreateAndroidSurfaceKHR")) {
            surface = VK_NULL_HANDLE;
            return false;
        }
        window = win;
        VkBool32 ok = VK_FALSE;
        vkGetPhysicalDeviceSurfaceSupportKHR(vk->phys, vk->family, surface, &ok);
        if (!ok) Log("d3d9vk: the graphics queue says it cannot present to the host's surface");
        Log("d3d9vk: a surface for the host's window %p (%dx%d)", win, w, h);
        scStale = true;
    }
    if (swapchain && !scStale && w == hostW && h == hostH) return true;
    VkSurfaceCapabilitiesKHR caps;
    if (!Check(vkGetPhysicalDeviceSurfaceCapabilitiesKHR(vk->phys, surface, &caps), "vkGetPhysicalDeviceSurfaceCapabilitiesKHR"))
        return false;
    VkExtent2D ext = caps.currentExtent;
    if (ext.width == 0xFFFFFFFFu) ext = {static_cast<uint32_t>(std::max(1, w)), static_cast<uint32_t>(std::max(1, h))};
    if (!ext.width || !ext.height) return false;
    if (!(caps.supportedUsageFlags & VK_IMAGE_USAGE_TRANSFER_DST_BIT)) {
        LogOnce("vk-sc-usage", "d3d9vk: the swapchain cannot be a transfer destination: nothing is presented");
        return false;
    }
    uint32_t nf = 0;
    vkGetPhysicalDeviceSurfaceFormatsKHR(vk->phys, surface, &nf, nullptr);
    std::vector<VkSurfaceFormatKHR> fmts(nf);
    vkGetPhysicalDeviceSurfaceFormatsKHR(vk->phys, surface, &nf, fmts.data());
    if (fmts.empty()) return false;
    VkSurfaceFormatKHR pick = fmts[0];
    for (const auto& f : fmts)
        if (f.format == VK_FORMAT_R8G8B8A8_UNORM || f.format == VK_FORMAT_B8G8R8A8_UNORM) {
            pick = f;
            break;
        }
    uint32_t count = std::max(caps.minImageCount, 3u);
    if (caps.maxImageCount) count = std::min(count, caps.maxImageCount);
    VkCompositeAlphaFlagBitsKHR alpha = VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR;
    if (!(caps.supportedCompositeAlpha & alpha))
        alpha = (caps.supportedCompositeAlpha & VK_COMPOSITE_ALPHA_INHERIT_BIT_KHR) ? VK_COMPOSITE_ALPHA_INHERIT_BIT_KHR
                                                                                  : static_cast<VkCompositeAlphaFlagBitsKHR>(
                                                                                        caps.supportedCompositeAlpha & -caps.supportedCompositeAlpha);
    VkSwapchainCreateInfoKHR ci{VK_STRUCTURE_TYPE_SWAPCHAIN_CREATE_INFO_KHR};
    ci.surface = surface;
    ci.minImageCount = count;
    ci.imageFormat = pick.format;
    ci.imageColorSpace = pick.colorSpace;
    ci.imageExtent = ext;
    ci.imageArrayLayers = 1;
    ci.imageUsage = VK_IMAGE_USAGE_TRANSFER_DST_BIT | (caps.supportedUsageFlags & VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT);
    ci.imageSharingMode = VK_SHARING_MODE_EXCLUSIVE;
    // (the compositor rotates when the display is: one transform less to get wrong here)
    ci.preTransform = (caps.supportedTransforms & VK_SURFACE_TRANSFORM_IDENTITY_BIT_KHR) ? VK_SURFACE_TRANSFORM_IDENTITY_BIT_KHR
                                                                                         : caps.currentTransform;
    ci.compositeAlpha = alpha;
    ci.presentMode = VK_PRESENT_MODE_FIFO_KHR;
    ci.clipped = VK_TRUE;
    ci.oldSwapchain = swapchain;
    VkSwapchainKHR next = VK_NULL_HANDLE;
    VkResult r = vkCreateSwapchainKHR(device, &ci, nullptr, &next);
    if (swapchain) DestroySwapchain(false);
    if (!Check(r, "vkCreateSwapchainKHR")) return false;
    swapchain = next;
    scFormat = pick.format;
    scExtent = ext;
    hostW = w, hostH = h;
    scStale = false;
    uint32_t ni = 0;
    vkGetSwapchainImagesKHR(device, swapchain, &ni, nullptr);
    scImages.resize(ni);
    vkGetSwapchainImagesKHR(device, swapchain, &ni, scImages.data());
    scDone.resize(ni);
    for (auto& sem : scDone) {
        VkSemaphoreCreateInfo si{VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO};
        vkCreateSemaphore(device, &si, nullptr, &sem);
    }
    VkFormatProperties fp;
    vkGetPhysicalDeviceFormatProperties(vk->phys, scFormat, &fp);
    if (!(fp.optimalTilingFeatures & VK_FORMAT_FEATURE_BLIT_DST_BIT))
        LogOnce("vk-sc-blit", "d3d9vk: the swapchain's format %d cannot be blitted to", scFormat);
    Log("d3d9vk: swapchain %ux%u, %u images, format %d, transform %#x (current %#x)", ext.width, ext.height, ni,
        scFormat, ci.preTransform, caps.currentTransform);
    return true;
}

// a swap chain's back buffer to the host's surface, stretched to it; then the submission
uint32_t Device::PresentImage(Image* img, uint32_t, uint32_t) {
    presents++;
    if (lost) return D3D_OK;
    EndPass();
    int w = 0, h = 0;
    void* win = rhipper_window_use(&w, &h);
    bool presented = false;
    if (!win && window) DestroySwapchain(true);   // (the host's surface is gone)
    if (win && img && EnsureSwapchain(win, w, h)) {
        Slot& s = slots[cur];
        VkSemaphore acquire = s.acquire;
        uint32_t index = 0;
        VkResult r = vkAcquireNextImageKHR(device, swapchain, 1000000000ull, acquire, VK_NULL_HANDLE, &index);
        if (r == VK_SUCCESS || r == VK_SUBOPTIMAL_KHR) {
            if (r == VK_SUBOPTIMAL_KHR) scStale = true;
            Transition(cmd, img, 0, 1, 0, 1, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL);
            VkImageMemoryBarrier b{VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER};
            b.srcAccessMask = 0;
            b.dstAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;
            b.oldLayout = VK_IMAGE_LAYOUT_UNDEFINED;
            b.newLayout = VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL;
            b.srcQueueFamilyIndex = b.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
            b.image = scImages[index];
            b.subresourceRange = {VK_IMAGE_ASPECT_COLOR_BIT, 0, 1, 0, 1};
            vkCmdPipelineBarrier(cmd, VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_TRANSFER_BIT, 0, 0, nullptr, 0,
                                 nullptr, 1, &b);
            VkImageBlit blit{};
            blit.srcSubresource = {VK_IMAGE_ASPECT_COLOR_BIT, 0, 0, 1};
            blit.srcOffsets[1] = {int32_t(img->width), int32_t(img->height), 1};
            blit.dstSubresource = {VK_IMAGE_ASPECT_COLOR_BIT, 0, 0, 1};
            blit.dstOffsets[1] = {int32_t(scExtent.width), int32_t(scExtent.height), 1};
            vkCmdBlitImage(cmd, img->image, img->layouts[0], scImages[index], VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, 1,
                           &blit, VK_FILTER_LINEAR);
            b.srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;
            b.dstAccessMask = 0;
            b.oldLayout = VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL;
            b.newLayout = VK_IMAGE_LAYOUT_PRESENT_SRC_KHR;
            vkCmdPipelineBarrier(cmd, VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT, 0, 0, nullptr,
                                 0, nullptr, 1, &b);
            img->lastUse = serial;
            VkSemaphore done = scDone[index];
            Submit(acquire, done);
            VkPresentInfoKHR pi{VK_STRUCTURE_TYPE_PRESENT_INFO_KHR};
            pi.waitSemaphoreCount = 1;
            pi.pWaitSemaphores = &done;
            pi.swapchainCount = 1;
            pi.pSwapchains = &swapchain;
            pi.pImageIndices = &index;
            VkResult pr = vkQueuePresentKHR(queue, &pi);
            if (pr == VK_ERROR_OUT_OF_DATE_KHR || pr == VK_SUBOPTIMAL_KHR) scStale = true;
            else if (pr != VK_SUCCESS) Check(pr, "vkQueuePresentKHR");
            presented = true;
        } else if (r == VK_ERROR_OUT_OF_DATE_KHR) {
            scStale = true;
        } else if (r == VK_ERROR_SURFACE_LOST_KHR) {
            DestroySwapchain(true);
        } else if (r != VK_TIMEOUT && r != VK_NOT_READY) {
            Check(r, "vkAcquireNextImageKHR");
        }
    }
    if (!presented) Submit();
    if (win) rhipper_window_done(win);
    if (presents == 1 || presents % 600 == 0)
        Log("d3d9vk: %llu presents, %llu draws, %zu pipelines, %llu MB of device memory",
            static_cast<unsigned long long>(presents), static_cast<unsigned long long>(draws), pipelines.size(),
            static_cast<unsigned long long>(mem->Used() >> 20));
    return D3D_OK;
}

// ---- state ------------------------------------------------------------------------------------------------
void Device::SetDefaults() {
    for (auto& t : st.tex) Hold(t, static_cast<Texture*>(nullptr));
    Hold(st.vs, static_cast<Shader*>(nullptr));
    Hold(st.ps, static_cast<Shader*>(nullptr));
    Hold(st.decl, static_cast<Decl*>(nullptr));
    for (auto& s : st.streams) Hold(s.vb, static_cast<Buffer*>(nullptr));
    Hold(st.ib, static_cast<Buffer*>(nullptr));
    st = State{};
    uint32_t* rs = st.rs;
    auto f = FloatBits;
    rs[RS_ZENABLE] = autoDepth ? 1 : 0, rs[RS_FILLMODE] = 3, rs[RS_SHADEMODE] = 2, rs[RS_ZWRITEENABLE] = 1;
    rs[RS_LASTPIXEL] = 1, rs[RS_SRCBLEND] = 2, rs[RS_DESTBLEND] = 1, rs[RS_CULLMODE] = 3, rs[RS_ZFUNC] = 4;
    rs[RS_ALPHAFUNC] = 8, rs[RS_FOGEND] = f(1.0f), rs[RS_FOGDENSITY] = f(1.0f);
    rs[RS_STENCILFAIL] = rs[RS_STENCILZFAIL] = rs[RS_STENCILPASS] = 1, rs[RS_STENCILFUNC] = 8;
    rs[RS_STENCILMASK] = rs[RS_STENCILWRITEMASK] = 0xFFFFFFFFu, rs[RS_TEXTUREFACTOR] = 0xFFFFFFFFu;
    rs[RS_CLIPPING] = 1, rs[RS_LIGHTING] = 1, rs[RS_COLORVERTEX] = 1, rs[RS_LOCALVIEWER] = 1;
    rs[RS_DIFFUSEMATERIALSOURCE] = 1, rs[RS_SPECULARMATERIALSOURCE] = 2;
    rs[RS_POINTSIZE] = f(1.0f), rs[RS_POINTSIZE_MIN] = f(1.0f), rs[RS_POINTSCALE_A] = f(1.0f);
    rs[RS_MULTISAMPLEANTIALIAS] = 1, rs[RS_MULTISAMPLEMASK] = 0xFFFFFFFFu, rs[RS_DEBUGMONITORTOKEN] = 0xbaadcafe;
    rs[RS_POINTSIZE_MAX] = f(64.0f), rs[RS_COLORWRITEENABLE] = 0xF, rs[RS_BLENDOP] = 1, rs[RS_POSITIONDEGREE] = 3;
    rs[RS_NORMALDEGREE] = 1, rs[RS_MINTESSELLATIONLEVEL] = f(1.0f), rs[RS_MAXTESSELLATIONLEVEL] = f(1.0f);
    rs[RS_ADAPTIVETESS_Z] = f(1.0f);
    rs[RS_CCW_STENCILFAIL] = rs[RS_CCW_STENCILZFAIL] = rs[RS_CCW_STENCILPASS] = 1, rs[RS_CCW_STENCILFUNC] = 8;
    rs[RS_COLORWRITEENABLE1] = rs[RS_COLORWRITEENABLE2] = rs[RS_COLORWRITEENABLE3] = 0xF;
    rs[RS_BLENDFACTOR] = 0xFFFFFFFFu, rs[RS_SRCBLENDALPHA] = 2, rs[RS_DESTBLENDALPHA] = 1, rs[RS_BLENDOPALPHA] = 1;
    for (auto& s : st.ss) {
        s[SS_ADDRESSU] = s[SS_ADDRESSV] = s[SS_ADDRESSW] = 1;
        s[SS_MAGFILTER] = s[SS_MINFILTER] = 1;
        s[SS_MAXANISOTROPY] = 1;
    }
    for (uint32_t k = 0; k < 8; k++) {
        uint32_t* t = st.tss[k];
        t[TSS_COLOROP] = k == 0 ? 4 : 1, t[TSS_COLORARG1] = 2, t[TSS_COLORARG2] = 1;
        t[TSS_ALPHAOP] = k == 0 ? 2 : 1, t[TSS_ALPHAARG1] = 2, t[TSS_ALPHAARG2] = 1;
        t[TSS_TEXCOORDINDEX] = k, t[TSS_COLORARG0] = t[TSS_ALPHAARG0] = t[TSS_RESULTARG] = 1;
    }
    for (auto& m : st.transforms)
        for (int k = 0; k < 4; k++) m[k * 5] = 1.0f;
    for (auto& s : st.streams) s.freq = 1;
    Surface* bb = implicit ? implicit->backBuffer : nullptr;
    Hold(rt[0], bb);
    for (int k = 1; k < 4; k++) Hold(rt[k], static_cast<Surface*>(nullptr));
    Hold(ds, autoDepth);
    uint32_t w = bb ? bb->W() : 1, h = bb ? bb->H() : 1;
    st.vp = {0, 0, w, h, 0.0f, 1.0f};
    st.scissor = {0, 0, static_cast<int32_t>(w), static_cast<int32_t>(h)};
    vsHigh = psHigh = 0;
    dirty = kDirtyAll;
}

void Device::MarkRenderState(uint32_t state) {
    switch (state) {
        case RS_ALPHABLENDENABLE: case RS_SRCBLEND: case RS_DESTBLEND: case RS_BLENDOP: case RS_SEPARATEALPHABLENDENABLE:
        case RS_SRCBLENDALPHA: case RS_DESTBLENDALPHA: case RS_BLENDOPALPHA: case RS_COLORWRITEENABLE:
        case RS_COLORWRITEENABLE1: case RS_COLORWRITEENABLE2: case RS_COLORWRITEENABLE3: case RS_FILLMODE:
            dirty |= kDirtyPipeline;
            break;
        case RS_SRGBWRITEENABLE: dirty |= kDirtyPipeline | kDirtyTargets; break;
        case RS_ZENABLE: case RS_ZWRITEENABLE: case RS_ZFUNC: dirty |= kDirtyDepth; break;
        case RS_STENCILENABLE: case RS_STENCILFAIL: case RS_STENCILZFAIL: case RS_STENCILPASS: case RS_STENCILFUNC:
        case RS_STENCILREF: case RS_STENCILMASK: case RS_STENCILWRITEMASK: case RS_TWOSIDEDSTENCILMODE:
        case RS_CCW_STENCILFAIL: case RS_CCW_STENCILZFAIL: case RS_CCW_STENCILPASS: case RS_CCW_STENCILFUNC:
            dirty |= kDirtyStencil;
            break;
        case RS_CULLMODE: dirty |= kDirtyCull; break;
        case RS_DEPTHBIAS: case RS_SLOPESCALEDEPTHBIAS: dirty |= kDirtyBias; break;
        case RS_BLENDFACTOR: dirty |= kDirtyBlendConst; break;
        case RS_SCISSORTESTENABLE: dirty |= kDirtyScissor; break;
        case RS_ALPHATESTENABLE: case RS_ALPHAFUNC: case RS_ALPHAREF: dirty |= kDirtyPush; break;
        case RS_TEXTUREFACTOR: case RS_LIGHTING: case RS_FOGENABLE: dirty |= kDirtyFixed; break;
        case RS_CLIPPLANEENABLE:
            if (st.rs[state]) LogOnce("vk-clipplanes", "d3d9vk: user clip planes (%#x) are not done", st.rs[state]);
            break;
        case RS_POINTSPRITEENABLE:
            if (st.rs[state]) LogOnce("vk-pointsprite", "d3d9vk: point sprites are not done");
            break;
        default: break;
    }
}

// ---- state blocks ------------------------------------------------------------------------------------
void Device::CaptureBlock(StateBlock* b) {
    State& s = b->s;
    const StateMask& m = b->m;
    for (uint32_t k = 0; k < 256; k++)
        if (m.rs[k]) s.rs[k] = st.rs[k];
    for (uint32_t k = 0; k < kSamplers * kSamplerStates; k++)
        if (m.ss[k]) s.ss[k / kSamplerStates][k % kSamplerStates] = st.ss[k / kSamplerStates][k % kSamplerStates];
    for (uint32_t k = 0; k < 8 * kStageStates; k++)
        if (m.tss[k]) s.tss[k / kStageStates][k % kStageStates] = st.tss[k / kStageStates][k % kStageStates];
    for (uint32_t k = 0; k < kSamplers; k++)
        if (m.tex & (1u << k)) Hold(s.tex[k], st.tex[k]);
    if (m.vs) Hold(s.vs, st.vs);
    if (m.ps) Hold(s.ps, st.ps);
    if (m.decl) Hold(s.decl, st.decl);
    if (m.fvf) s.fvf = st.fvf;
    for (uint32_t k = 0; k < kVsConsts; k++)
        if (m.vsF[k]) memcpy(s.vsF[k], st.vsF[k], 16);
    for (uint32_t k = 0; k < kPsConsts; k++)
        if (m.psF[k]) memcpy(s.psF[k], st.psF[k], 16);
    for (uint32_t k = 0; k < 16; k++) {
        if (m.vsI & (1u << k)) memcpy(s.vsI[k], st.vsI[k], 16);
        if (m.psI & (1u << k)) memcpy(s.psI[k], st.psI[k], 16);
        if (m.vsB & (1u << k)) s.vsB[k] = st.vsB[k];
        if (m.psB & (1u << k)) s.psB[k] = st.psB[k];
        if (m.streams & (1u << k)) {
            Hold(s.streams[k].vb, st.streams[k].vb);
            s.streams[k].offset = st.streams[k].offset, s.streams[k].stride = st.streams[k].stride;
        }
        if (m.freqs & (1u << k)) s.streams[k].freq = st.streams[k].freq;
    }
    if (m.ib) Hold(s.ib, st.ib);
    if (m.vp) s.vp = st.vp;
    if (m.scissor) s.scissor = st.scissor;
    for (uint32_t k = 0; k < kTransforms; k++)
        if (m.transforms & (1u << k)) memcpy(s.transforms[k], st.transforms[k], 64);
    for (uint32_t k = 0; k < 6; k++)
        if (m.clip & (1u << k)) memcpy(s.clip[k], st.clip[k], 16);
    if (m.material) memcpy(s.material, st.material, sizeof s.material);
}

namespace {
const uint32_t kTransformStates[kTransforms] = {256, 2, 3, 16, 17, 18, 19, 20, 21, 22, 23};
uint32_t SamplerStage(uint32_t k) { return k < 16 ? k : 257 + (k - 16); }
}  // namespace

void Device::ApplyBlock(StateBlock* b) {
    State& s = b->s;
    const StateMask& m = b->m;
    for (uint32_t k = 0; k < 256; k++)
        if (m.rs[k]) SetRenderState(k, s.rs[k]);
    for (uint32_t k = 0; k < kSamplers * kSamplerStates; k++)
        if (m.ss[k]) SetSamplerState(SamplerStage(k / kSamplerStates), k % kSamplerStates, s.ss[k / kSamplerStates][k % kSamplerStates]);
    for (uint32_t k = 0; k < 8 * kStageStates; k++)
        if (m.tss[k]) SetTextureStageState(k / kStageStates, k % kStageStates, s.tss[k / kStageStates][k % kStageStates]);
    for (uint32_t k = 0; k < kSamplers; k++)
        if (m.tex & (1u << k)) SetTexture(SamplerStage(k), s.tex[k] ? s.tex[k]->self : 0);
    if (m.vs) SetVertexShader(s.vs ? s.vs->self : 0);
    if (m.ps) SetPixelShader(s.ps ? s.ps->self : 0);
    if (m.decl && s.decl) SetVertexDeclaration(s.decl->self);
    if (m.fvf && s.fvf) SetFVF(s.fvf);
    for (uint32_t k = 0; k < kVsConsts; k++)
        if (m.vsF[k]) {
            memcpy(st.vsF[k], s.vsF[k], 16);
            vsHigh = std::max(vsHigh, k + 1);
            dirty |= kDirtyVsConst;
        }
    for (uint32_t k = 0; k < kPsConsts; k++)
        if (m.psF[k]) {
            memcpy(st.psF[k], s.psF[k], 16);
            psHigh = std::max(psHigh, k + 1);
            dirty |= kDirtyPsConst;
        }
    for (uint32_t k = 0; k < 16; k++) {
        if (m.vsI & (1u << k)) memcpy(st.vsI[k], s.vsI[k], 16), dirty |= kDirtyVsConst;
        if (m.psI & (1u << k)) memcpy(st.psI[k], s.psI[k], 16), dirty |= kDirtyPsConst;
        if (m.vsB & (1u << k)) st.vsB[k] = s.vsB[k], dirty |= kDirtyVsConst;
        if (m.psB & (1u << k)) st.psB[k] = s.psB[k], dirty |= kDirtyPsConst;
        if (m.streams & (1u << k))
            SetStreamSource(k, s.streams[k].vb ? s.streams[k].vb->self : 0, s.streams[k].offset, s.streams[k].stride);
        if (m.freqs & (1u << k)) SetStreamSourceFreq(k, s.streams[k].freq);
    }
    if (m.ib) SetIndices(s.ib ? s.ib->self : 0);
    if (m.vp) {
        st.vp = s.vp;
        dirty |= kDirtyViewport | kDirtyFixed;
    }
    if (m.scissor) {
        st.scissor = s.scissor;
        dirty |= kDirtyScissor;
    }
    for (uint32_t k = 0; k < kTransforms; k++)
        if (m.transforms & (1u << k)) memcpy(st.transforms[k], s.transforms[k], 64), dirty |= kDirtyFixed;
    for (uint32_t k = 0; k < 6; k++)
        if (m.clip & (1u << k)) memcpy(st.clip[k], s.clip[k], 16);
    if (m.material) memcpy(st.material, s.material, sizeof s.material);
}

// ---- IDirect3DDevice9 ---------------------------------------------------------------------------------
#define LOCKED std::lock_guard<std::recursive_mutex> hold_(mu)

uint32_t Device::QueryInterface(uint32_t, uint32_t out) {
    AddRef_();
    if (out) *At<uint32_t>(out) = self;
    return D3D_OK;
}
uint32_t Device::AddRef_() {
    LOCKED;
    return static_cast<uint32_t>(++refs);
}
uint32_t Device::Release_() {
    LOCKED;
    int r = --refs;
    if (r <= 0) {
        refs = 0;
        Log("d3d9vk: the device's last reference released (kept: its resources may still be held)");
    }
    return static_cast<uint32_t>(std::max(r, 0));
}
uint32_t Device::TestCooperativeLevel() { return D3D_OK; }
uint32_t Device::GetAvailableTextureMem() { return 0x60000000u; }   // (1.5 GB)
uint32_t Device::EvictManagedResources() { return D3D_OK; }
uint32_t Device::GetDirect3D(uint32_t out) {
    d3d->AddRef_();
    *At<uint32_t>(out) = d3d->self;
    return D3D_OK;
}
uint32_t Device::GetDeviceCaps(uint32_t out) { return FillCaps(vk, out), D3D_OK; }
// D3DDISPLAYMODE: Width, Height, RefreshRate, Format
uint32_t Device::GetDisplayMode(uint32_t, uint32_t out) {
    int w = static_cast<int>(pp.BackBufferWidth), h = static_cast<int>(pp.BackBufferHeight);
    if (void* win = rhipper_window_use(&w, &h)) rhipper_window_done(win);
    uint32_t m[4] = {static_cast<uint32_t>(w), static_cast<uint32_t>(h), 60, F_X8R8G8B8};
    memcpy(At(out), m, sizeof m);
    return D3D_OK;
}
uint32_t Device::GetCreationParameters(uint32_t out) {
    uint32_t c[4] = {adapter, deviceType, focus, behavior};
    memcpy(At(out), c, sizeof c);
    return D3D_OK;
}
uint32_t Device::SetCursorProperties(uint32_t, uint32_t, uint32_t) {
    LogOnce("vk-cursor", "d3d9vk: the device cursor is not drawn");
    return D3D_OK;
}
uint32_t Device::SetCursorPosition(uint32_t, uint32_t, uint32_t) { return D3D_OK; }
uint32_t Device::ShowCursor(uint32_t) { return 0; }
uint32_t Device::CreateAdditionalSwapChain(uint32_t ppIn, uint32_t out) {
    LOCKED;
    if (!ppIn || !out) return D3DERR_INVALIDCALL;
    PresentParams32 p = *At<PresentParams32>(ppIn);
    SwapChain* sc = NewSwapChain(&p, false);
    if (!sc) return D3DERR_OUTOFVIDEOMEMORY;
    *At<PresentParams32>(ppIn) = p;
    *At<uint32_t>(out) = sc->self;
    Log("d3d9vk: CreateAdditionalSwapChain %ux%u format %s", p.BackBufferWidth, p.BackBufferHeight, FormatName(p.BackBufferFormat));
    return D3D_OK;
}
uint32_t Device::GetSwapChain(uint32_t index, uint32_t out) {
    LOCKED;
    if (index != 0 || !out) return D3DERR_INVALIDCALL;
    implicit->AddRef_();
    *At<uint32_t>(out) = implicit->self;
    return D3D_OK;
}
uint32_t Device::GetNumberOfSwapChains() { return 1; }
uint32_t Device::Reset(uint32_t ppIn) {
    LOCKED;
    if (!ppIn) return D3DERR_INVALIDCALL;
    EndPass();
    PresentParams32 p = *At<PresentParams32>(ppIn);
    Surface* bb = MakeBackBuffer(&p);
    if (!bb) return D3DERR_OUTOFVIDEOMEMORY;
    Surface* old = implicit->backBuffer;
    implicit->backBuffer = bb;
    implicit->pp = p;
    if (old) old->Unbind();
    Hold(autoDepth, static_cast<Surface*>(nullptr));
    if (p.EnableAutoDepthStencil) {
        uint32_t hr;
        if (Surface* d = NewSurface(p.BackBufferWidth, p.BackBufferHeight, p.AutoDepthStencilFormat, U_DEPTHSTENCIL,
                                    POOL_DEFAULT, &hr)) {
            d->refs = 0;
            Hold(autoDepth, d);
        }
    }
    pp = p;
    *At<PresentParams32>(ppIn) = p;
    SetDefaults();
    Log("d3d9vk: Reset %ux%u format %s", p.BackBufferWidth, p.BackBufferHeight, FormatName(p.BackBufferFormat));
    return D3D_OK;
}
uint32_t Device::Present(uint32_t, uint32_t, uint32_t, uint32_t) {
    LOCKED;
    Surface* bb = implicit->backBuffer;
    return PresentImage(bb ? bb->Img() : nullptr, pp.BackBufferWidth, pp.BackBufferHeight);
}
uint32_t Device::GetBackBuffer(uint32_t sc, uint32_t index, uint32_t type, uint32_t out) {
    LOCKED;
    if (sc != 0) return D3DERR_INVALIDCALL;
    return implicit->GetBackBuffer(index, type, out);
}
uint32_t Device::GetRasterStatus(uint32_t, uint32_t out) {
    memset(At(out), 0, 8);
    return D3D_OK;
}
uint32_t Device::SetDialogBoxMode(uint32_t) { return D3D_OK; }
uint32_t Device::SetGammaRamp(uint32_t, uint32_t, uint32_t ramp) {
    if (ramp) memcpy(gamma, At(ramp), sizeof gamma);
    LogOnce("vk-gamma", "d3d9vk: the gamma ramp is kept, not applied");
    return D3D_OK;
}
uint32_t Device::GetGammaRamp(uint32_t, uint32_t ramp) {
    if (ramp) memcpy(At(ramp), gamma, sizeof gamma);
    return D3D_OK;
}

uint32_t Device::CreateTexture(uint32_t w, uint32_t h, uint32_t levels, uint32_t usage, uint32_t format, uint32_t pool,
                               uint32_t out, uint32_t) {
    return NewTexture(RT_TEXTURE, w, h, 1, levels, usage, format, pool, out);
}
uint32_t Device::CreateVolumeTexture(uint32_t w, uint32_t h, uint32_t d, uint32_t levels, uint32_t usage,
                                     uint32_t format, uint32_t pool, uint32_t out, uint32_t) {
    return NewTexture(RT_VOLUMETEXTURE, w, h, d, levels, usage, format, pool, out);
}
uint32_t Device::CreateCubeTexture(uint32_t edge, uint32_t levels, uint32_t usage, uint32_t format, uint32_t pool,
                                   uint32_t out, uint32_t) {
    return NewTexture(RT_CUBETEXTURE, edge, edge, 1, levels, usage, format, pool, out);
}
uint32_t Device::CreateVertexBuffer(uint32_t length, uint32_t usage, uint32_t fvf, uint32_t pool, uint32_t out, uint32_t) {
    return NewBuffer(false, length, usage, fvf, pool, out);
}
uint32_t Device::CreateIndexBuffer(uint32_t length, uint32_t usage, uint32_t format, uint32_t pool, uint32_t out, uint32_t) {
    return NewBuffer(true, length, usage, format, pool, out);
}
uint32_t Device::CreateRenderTarget(uint32_t w, uint32_t h, uint32_t format, uint32_t ms, uint32_t, uint32_t,
                                    uint32_t out, uint32_t) {
    if (!out) return D3DERR_INVALIDCALL;
    if (ms > 1) LogOnce("vk-msaa", "d3d9vk: multisampled render targets are made single-sampled");
    uint32_t hr;
    Surface* s = NewSurface(w, h, format, U_RENDERTARGET, POOL_DEFAULT, &hr);
    *At<uint32_t>(out) = s ? s->self : 0;
    return hr;
}
uint32_t Device::CreateDepthStencilSurface(uint32_t w, uint32_t h, uint32_t format, uint32_t, uint32_t, uint32_t,
                                           uint32_t out, uint32_t) {
    if (!out) return D3DERR_INVALIDCALL;
    uint32_t hr;
    Surface* s = NewSurface(w, h, format, U_DEPTHSTENCIL, POOL_DEFAULT, &hr);
    *At<uint32_t>(out) = s ? s->self : 0;
    return hr;
}
uint32_t Device::CreateOffscreenPlainSurface(uint32_t w, uint32_t h, uint32_t format, uint32_t pool, uint32_t out, uint32_t) {
    if (!out) return D3DERR_INVALIDCALL;
    uint32_t hr;
    Surface* s = NewSurface(w, h, format, 0, pool, &hr);
    *At<uint32_t>(out) = s ? s->self : 0;
    return hr;
}

uint32_t Device::SetRenderTarget(uint32_t index, uint32_t surface) {
    LOCKED;
    if (index >= 4 || (index == 0 && !surface)) return D3DERR_INVALIDCALL;
    Surface* s = Native<Surface>(surface);
    if (surface && !s) return D3DERR_INVALIDCALL;
    if (rt[index] != s) {
        EndPass();
        Hold(rt[index], s);
        dirty |= kDirtyPipeline | kDirtyTargets | kDirtyPush;
    }
    if (index == 0) {   // (D3D9 resets the viewport and the scissor rect to the new target)
        st.vp = {0, 0, s->W(), s->H(), 0.0f, 1.0f};
        st.scissor = {0, 0, static_cast<int32_t>(s->W()), static_cast<int32_t>(s->H())};
        dirty |= kDirtyViewport | kDirtyScissor | kDirtyFixed;
    }
    return D3D_OK;
}
uint32_t Device::GetRenderTarget(uint32_t index, uint32_t out) {
    LOCKED;
    if (index >= 4 || !out) return D3DERR_INVALIDCALL;
    Surface* s = rt[index];
    if (s) s->AddRef_();
    *At<uint32_t>(out) = s ? s->self : 0;
    return s ? D3D_OK : D3DERR_NOTFOUND;
}
uint32_t Device::SetDepthStencilSurface(uint32_t surface) {
    LOCKED;
    Surface* s = Native<Surface>(surface);
    if (ds != s) {
        EndPass();
        Hold(ds, s);
        dirty |= kDirtyPipeline | kDirtyTargets | kDirtyDepth | kDirtyStencil | kDirtyBias;
    }
    return D3D_OK;
}
uint32_t Device::GetDepthStencilSurface(uint32_t out) {
    LOCKED;
    if (!out) return D3DERR_INVALIDCALL;
    if (ds) ds->AddRef_();
    *At<uint32_t>(out) = ds ? ds->self : 0;
    return ds ? D3D_OK : D3DERR_NOTFOUND;
}
uint32_t Device::BeginScene() { return D3D_OK; }
uint32_t Device::EndScene() { return D3D_OK; }

namespace {
int TransformIndex(uint32_t state) {
    if (state == 256) return 0;
    if (state == 2) return 1;
    if (state == 3) return 2;
    if (state >= 16 && state <= 23) return 3 + static_cast<int>(state - 16);
    LogOnce(("vk-transform-" + std::to_string(state)).c_str(), "d3d9vk: transform %u is kept nowhere", state);
    return -1;
}
}  // namespace

uint32_t Device::SetTransform(uint32_t state, uint32_t matrix) {
    LOCKED;
    int k = TransformIndex(state);
    if (k < 0 || !matrix) return D3D_OK;
    memcpy(S().transforms[k], At(matrix), 64);
    if (rec) rec->m.transforms |= 1u << k;
    else dirty |= kDirtyFixed;
    return D3D_OK;
}
uint32_t Device::GetTransform(uint32_t state, uint32_t matrix) {
    LOCKED;
    int k = TransformIndex(state);
    if (!matrix) return D3DERR_INVALIDCALL;
    if (k < 0) {
        float id[16] = {1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1};
        memcpy(At(matrix), id, 64);
    } else {
        memcpy(At(matrix), st.transforms[k], 64);
    }
    return D3D_OK;
}
uint32_t Device::MultiplyTransform(uint32_t state, uint32_t matrix) {
    LOCKED;
    int k = TransformIndex(state);
    if (k < 0 || !matrix) return D3D_OK;
    float m[16], r[16];
    memcpy(m, At(matrix), 64);
    const float* a = st.transforms[k];
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++) {
            float v = 0;
            for (int x = 0; x < 4; x++) v += a[i * 4 + x] * m[x * 4 + j];
            r[i * 4 + j] = v;
        }
    memcpy(st.transforms[k], r, 64);
    dirty |= kDirtyFixed;
    return D3D_OK;
}
// D3DVIEWPORT9: X, Y, Width, Height, MinZ, MaxZ
uint32_t Device::SetViewport(uint32_t vpIn) {
    LOCKED;
    if (!vpIn) return D3DERR_INVALIDCALL;
    auto v = At<uint32_t>(vpIn);
    Viewport n{v[0], v[1], std::max(1u, v[2]), std::max(1u, v[3]), AsFloat(v[4]), AsFloat(v[5])};
    S().vp = n;
    if (rec) rec->m.vp = true;
    else dirty |= kDirtyViewport | kDirtyFixed;
    return D3D_OK;
}
uint32_t Device::GetViewport(uint32_t out) {
    LOCKED;
    uint32_t v[6] = {st.vp.x, st.vp.y, st.vp.w, st.vp.h, FloatBits(st.vp.minZ), FloatBits(st.vp.maxZ)};
    memcpy(At(out), v, sizeof v);
    return D3D_OK;
}
uint32_t Device::SetMaterial(uint32_t m) {
    LOCKED;
    if (m) memcpy(S().material, At(m), sizeof st.material);
    if (rec) rec->m.material = true;
    return D3D_OK;
}
uint32_t Device::GetMaterial(uint32_t m) {
    LOCKED;
    if (m) memcpy(At(m), st.material, sizeof st.material);
    return D3D_OK;
}
// D3DLIGHT9 (104 bytes): kept, not lit
uint32_t Device::SetLight(uint32_t index, uint32_t light) {
    LOCKED;
    if (!light) return D3DERR_INVALIDCALL;
    lights[index].assign(At<uint8_t>(light), At<uint8_t>(light) + 104);
    return D3D_OK;
}
uint32_t Device::GetLight(uint32_t index, uint32_t light) {
    LOCKED;
    auto it = lights.find(index);
    if (it == lights.end() || !light) return D3DERR_INVALIDCALL;
    memcpy(At(light), it->second.data(), 104);
    return D3D_OK;
}
uint32_t Device::LightEnable(uint32_t index, uint32_t on) {
    LOCKED;
    lightOn[index] = on != 0;
    if (on) LogOnce("vk-lights", "d3d9vk: fixed-function lights are kept, not lit");
    return D3D_OK;
}
uint32_t Device::GetLightEnable(uint32_t index, uint32_t out) {
    LOCKED;
    auto it = lightOn.find(index);
    if (it == lightOn.end()) return D3DERR_INVALIDCALL;
    *At<uint32_t>(out) = it->second ? 128 : 0;   // (D3D9 answers 128 for TRUE)
    return D3D_OK;
}
uint32_t Device::SetClipPlane(uint32_t index, uint32_t plane) {
    LOCKED;
    if (index >= 6 || !plane) return D3DERR_INVALIDCALL;
    memcpy(S().clip[index], At(plane), 16);
    if (rec) rec->m.clip |= 1u << index;
    return D3D_OK;
}
uint32_t Device::GetClipPlane(uint32_t index, uint32_t plane) {
    LOCKED;
    if (index >= 6 || !plane) return D3DERR_INVALIDCALL;
    memcpy(At(plane), st.clip[index], 16);
    return D3D_OK;
}
uint32_t Device::SetRenderState(uint32_t state, uint32_t value) {
    LOCKED;
    if (state >= 256) return D3DERR_INVALIDCALL;
    if (rec) {
        rec->s.rs[state] = value;
        rec->m.rs.set(state);
        return D3D_OK;
    }
    if (st.rs[state] == value) return D3D_OK;
    if (state == RS_SRGBWRITEENABLE) EndPass();
    st.rs[state] = value;
    MarkRenderState(state);
    return D3D_OK;
}
uint32_t Device::GetRenderState(uint32_t state, uint32_t out) {
    LOCKED;
    if (!out) return D3DERR_INVALIDCALL;
    *At<uint32_t>(out) = state < 256 ? st.rs[state] : 0;
    return D3D_OK;
}

uint32_t Device::CreateStateBlock(uint32_t type, uint32_t out) {
    LOCKED;
    if (!out || type < 1 || type > 3) return D3DERR_INVALIDCALL;
    auto b = new StateBlock();
    b->dev = this;
    StateMask& m = b->m;
    m.rs.set();   // (every render state for each type: a superset of D3D9's lists)
    if (type == 1 || type == 2) {   // ALL, PIXELSTATE
        m.ss.set(), m.tss.set(), m.psF.set();
        m.ps = true, m.psI = m.psB = 0xFFFF;
    }
    if (type == 1 || type == 3) {   // ALL, VERTEXSTATE
        m.vsF.set();
        m.vs = m.decl = m.fvf = true, m.vsI = m.vsB = 0xFFFF, m.freqs = 0xFFFF;
        if (type == 3)
            for (uint32_t k = 16; k < kSamplers; k++)
                for (uint32_t s = 0; s < kSamplerStates; s++) m.ss.set(k * kSamplerStates + s);
    }
    if (type == 1) {
        m.tex = (1u << kSamplers) - 1, m.streams = 0xFFFF, m.ib = m.vp = m.scissor = m.material = true;
        m.transforms = (1u << kTransforms) - 1, m.clip = 0x3F;
    }
    if (type != 1) LogOnce("vk-sb-partial", "d3d9vk: pixel / vertex state blocks hold every render state");
    CaptureBlock(b);
    b->self = NewObject(StateBlockVtable(), static_cast<Base*>(b));
    *At<uint32_t>(out) = b->self;
    return D3D_OK;
}
uint32_t Device::BeginStateBlock() {
    LOCKED;
    if (rec) return D3DERR_INVALIDCALL;
    rec = new StateBlock();
    rec->dev = this;
    return D3D_OK;
}
uint32_t Device::EndStateBlock(uint32_t out) {
    LOCKED;
    if (!rec || !out) return D3DERR_INVALIDCALL;
    StateBlock* b = rec;
    rec = nullptr;
    b->self = NewObject(StateBlockVtable(), static_cast<Base*>(b));
    *At<uint32_t>(out) = b->self;
    return D3D_OK;
}
uint32_t Device::SetClipStatus(uint32_t s) {
    if (s) memcpy(clipStatus, At(s), 8);
    return D3D_OK;
}
uint32_t Device::GetClipStatus(uint32_t s) {
    if (s) memcpy(At(s), clipStatus, 8);
    return D3D_OK;
}

namespace {
// SetTexture's / SetSamplerState's stage: 0..15 pixel, D3DVERTEXTEXTURESAMPLER0..3 (257..260) vertex
int SamplerIndex(uint32_t stage) {
    if (stage < 16) return static_cast<int>(stage);
    if (stage >= 257 && stage <= 260) return static_cast<int>(16 + stage - 257);
    return -1;
}
}  // namespace

uint32_t Device::GetTexture(uint32_t stage, uint32_t out) {
    LOCKED;
    if (!out) return D3DERR_INVALIDCALL;
    int k = SamplerIndex(stage);
    Texture* t = k >= 0 ? st.tex[k] : nullptr;
    if (t) t->AddRef_();
    *At<uint32_t>(out) = t ? t->self : 0;
    return D3D_OK;
}
uint32_t Device::SetTexture(uint32_t stage, uint32_t tex) {
    LOCKED;
    int k = SamplerIndex(stage);
    if (k < 0) return stage == 256 ? D3D_OK : D3DERR_INVALIDCALL;   // (the displacement map sampler: ignored)
    Texture* t = Native<Texture>(tex);
    if (rec) {
        Hold(rec->s.tex[k], t);
        rec->m.tex |= 1u << k;
        return D3D_OK;
    }
    if (st.tex[k] == t) return D3D_OK;
    Hold(st.tex[k], t);
    dirty |= kDirtyTextures;
    return D3D_OK;
}
uint32_t Device::GetTextureStageState(uint32_t stage, uint32_t type, uint32_t out) {
    LOCKED;
    if (stage >= 8 || type >= kStageStates || !out) return D3DERR_INVALIDCALL;
    *At<uint32_t>(out) = st.tss[stage][type];
    return D3D_OK;
}
uint32_t Device::SetTextureStageState(uint32_t stage, uint32_t type, uint32_t value) {
    LOCKED;
    if (stage >= 8 || type >= kStageStates) return D3DERR_INVALIDCALL;
    S().tss[stage][type] = value;
    if (rec) rec->m.tss.set(stage * kStageStates + type);
    else dirty |= kDirtyFixed;
    return D3D_OK;
}
uint32_t Device::GetSamplerState(uint32_t sampler, uint32_t type, uint32_t out) {
    LOCKED;
    int k = SamplerIndex(sampler);
    if (k < 0 || type >= kSamplerStates || !out) return D3DERR_INVALIDCALL;
    *At<uint32_t>(out) = st.ss[k][type];
    return D3D_OK;
}
uint32_t Device::SetSamplerState(uint32_t sampler, uint32_t type, uint32_t value) {
    LOCKED;
    int k = SamplerIndex(sampler);
    if (k < 0 || type >= kSamplerStates) return sampler == 256 ? D3D_OK : D3DERR_INVALIDCALL;
    if (rec) {
        rec->s.ss[k][type] = value;
        rec->m.ss.set(k * kSamplerStates + type);
        return D3D_OK;
    }
    if (st.ss[k][type] == value) return D3D_OK;
    st.ss[k][type] = value;
    dirty |= kDirtyTextures;
    return D3D_OK;
}
uint32_t Device::ValidateDevice(uint32_t passes) {
    if (passes) *At<uint32_t>(passes) = 1;
    return D3D_OK;
}
uint32_t Device::SetPaletteEntries(uint32_t, uint32_t) {
    LogOnce("vk-palette", "d3d9vk: palettes are not supported");
    return D3D_OK;
}
uint32_t Device::GetPaletteEntries(uint32_t, uint32_t) { return D3DERR_INVALIDCALL; }
uint32_t Device::SetCurrentTexturePalette(uint32_t n) { return palette = n, D3D_OK; }
uint32_t Device::GetCurrentTexturePalette(uint32_t out) {
    if (out) *At<uint32_t>(out) = palette;
    return D3D_OK;
}
uint32_t Device::SetScissorRect(uint32_t rect) {
    LOCKED;
    if (!rect) return D3DERR_INVALIDCALL;
    S().scissor = RectAt(rect);
    if (rec) rec->m.scissor = true;
    else dirty |= kDirtyScissor;
    return D3D_OK;
}
uint32_t Device::GetScissorRect(uint32_t rect) {
    LOCKED;
    if (rect) memcpy(At(rect), &st.scissor, 16);
    return D3D_OK;
}
uint32_t Device::SetSoftwareVertexProcessing(uint32_t on) { return softwareVp = on != 0, D3D_OK; }
uint32_t Device::GetSoftwareVertexProcessing() { return softwareVp ? 1 : 0; }
uint32_t Device::SetNPatchMode(uint32_t bits) {
    nPatch = AsFloat(bits);
    if (nPatch > 0) LogOnce("vk-npatch", "d3d9vk: N-patches are not done");
    return D3D_OK;
}
uint32_t Device::GetNPatchMode() { return FloatBits(nPatch); }
uint32_t Device::ProcessVertices(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t) {
    LogOnce("vk-processvertices", "d3d9vk: ProcessVertices is not supported");
    return D3DERR_INVALIDCALL;
}

uint32_t Device::CreateVertexDeclaration(uint32_t elements, uint32_t out) {
    LOCKED;
    if (!elements || !out) return D3DERR_INVALIDCALL;
    auto d = new Decl();
    d->dev = this;
    for (uint32_t n = 0; n < 64; n++) {
        Element32 e;
        memcpy(&e, At(elements + 8 * n), 8);
        if (e.stream == 0xFF) break;
        d->elems.push_back(e);
    }
    d->self = NewObject(DeclVtable(), static_cast<Base*>(d));
    *At<uint32_t>(out) = d->self;
    return D3D_OK;
}
uint32_t Device::SetVertexDeclaration(uint32_t decl) {
    LOCKED;
    Decl* d = Native<Decl>(decl);
    if (rec) {
        Hold(rec->s.decl, d);
        rec->s.fvf = 0;
        rec->m.decl = rec->m.fvf = true;
        return D3D_OK;
    }
    if (st.decl == d && !st.fvf) return D3D_OK;
    Hold(st.decl, d);
    st.fvf = 0;
    dirty |= kDirtyPipeline | kDirtyFixed;
    return D3D_OK;
}
uint32_t Device::GetVertexDeclaration(uint32_t out) {
    LOCKED;
    if (!out) return D3DERR_INVALIDCALL;
    if (st.decl) st.decl->AddRef_();
    *At<uint32_t>(out) = st.decl ? st.decl->self : 0;
    return D3D_OK;
}
uint32_t Device::SetFVF(uint32_t fvf) {
    LOCKED;
    if (rec) {
        Hold(rec->s.decl, static_cast<Decl*>(nullptr));
        rec->s.fvf = fvf;
        rec->m.decl = rec->m.fvf = true;
        return D3D_OK;
    }
    if (st.fvf == fvf && !st.decl) return D3D_OK;
    Hold(st.decl, static_cast<Decl*>(nullptr));
    st.fvf = fvf;
    dirty |= kDirtyPipeline | kDirtyFixed;
    return D3D_OK;
}
uint32_t Device::GetFVF(uint32_t out) {
    LOCKED;
    if (out) *At<uint32_t>(out) = st.fvf;
    return D3D_OK;
}

namespace {
uint32_t MakeShader(Device* dev, Stage stage, uint32_t function, uint32_t out) {
    if (!function || !out) return D3DERR_INVALIDCALL;
    auto s = new Shader();
    s->dev = dev;
    s->stage = stage;
    uint32_t n = 0;
    while (n < (1u << 20) && U32(function + 4 * n) != 0x0000FFFFu) n++;
    s->tokens.assign(At<uint32_t>(function), At<uint32_t>(function) + n + 1);
    s->id = dev->nextShaderId++;
    std::string err;
    std::vector<uint32_t> spirv = TranslateShader(s->tokens.data(), s->tokens.size(), &s->info, &err);
    uint32_t version = s->tokens[0];
    if (spirv.empty()) {
        Log("d3d9vk: %s shader %u.%u (%u tokens, id %llu) not translated: %s: its draws are skipped",
            stage == Stage::Vertex ? "vertex" : "pixel", (version >> 8) & 0xFF, version & 0xFF, n + 1,
            static_cast<unsigned long long>(s->id), err.c_str());
    } else {
        VkShaderModuleCreateInfo mi{VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO};
        mi.codeSize = spirv.size() * 4;
        mi.pCode = spirv.data();
        if (!dev->Check(vkCreateShaderModule(dev->device, &mi, nullptr, &s->module), "vkCreateShaderModule"))
            s->module = VK_NULL_HANDLE;
    }
    s->self = NewObject(ShaderVtable(), static_cast<Base*>(s));
    *At<uint32_t>(out) = s->self;
    return D3D_OK;
}
}  // namespace

uint32_t Device::CreateVertexShader(uint32_t function, uint32_t out) {
    LOCKED;
    return MakeShader(this, Stage::Vertex, function, out);
}
uint32_t Device::SetVertexShader(uint32_t shader) {
    LOCKED;
    Shader* s = Native<Shader>(shader);
    if (rec) {
        Hold(rec->s.vs, s);
        rec->m.vs = true;
        return D3D_OK;
    }
    if (st.vs == s) return D3D_OK;
    Hold(st.vs, s);
    dirty |= kDirtyPipeline | kDirtyVsConst | kDirtyTextures;
    return D3D_OK;
}
uint32_t Device::GetVertexShader(uint32_t out) {
    LOCKED;
    if (!out) return D3DERR_INVALIDCALL;
    if (st.vs) st.vs->AddRef_();
    *At<uint32_t>(out) = st.vs ? st.vs->self : 0;
    return D3D_OK;
}
uint32_t Device::CreatePixelShader(uint32_t function, uint32_t out) {
    LOCKED;
    return MakeShader(this, Stage::Pixel, function, out);
}
uint32_t Device::SetPixelShader(uint32_t shader) {
    LOCKED;
    Shader* s = Native<Shader>(shader);
    if (rec) {
        Hold(rec->s.ps, s);
        rec->m.ps = true;
        return D3D_OK;
    }
    if (st.ps == s) return D3D_OK;
    Hold(st.ps, s);
    dirty |= kDirtyPipeline | kDirtyPsConst | kDirtyTextures;
    return D3D_OK;
}
uint32_t Device::GetPixelShader(uint32_t out) {
    LOCKED;
    if (!out) return D3DERR_INVALIDCALL;
    if (st.ps) st.ps->AddRef_();
    *At<uint32_t>(out) = st.ps ? st.ps->self : 0;
    return D3D_OK;
}

// the constant setters: float4s, int4s, BOOLs
#define CONSTS_F(Name, arr, limit, high, bits, maskF)                                         \
    uint32_t Device::Set##Name(uint32_t start, uint32_t data, uint32_t count) {               \
        LOCKED;                                                                               \
        if (!data || start + count > limit) return D3DERR_INVALIDCALL;                         \
        memcpy(S().arr[start], At(data), 16 * count);                                         \
        if (rec) {                                                                            \
            for (uint32_t k = start; k < start + count; k++) rec->m.maskF.set(k);             \
        } else {                                                                              \
            high = std::max(high, start + count);                                             \
            dirty |= bits;                                                                    \
        }                                                                                     \
        return D3D_OK;                                                                        \
    }                                                                                         \
    uint32_t Device::Get##Name(uint32_t start, uint32_t data, uint32_t count) {               \
        LOCKED;                                                                               \
        if (!data || start + count > limit) return D3DERR_INVALIDCALL;                         \
        memcpy(At(data), st.arr[start], 16 * count);                                          \
        return D3D_OK;                                                                        \
    }
CONSTS_F(VertexShaderConstantF, vsF, kVsConsts, vsHigh, kDirtyVsConst, vsF)
CONSTS_F(PixelShaderConstantF, psF, kPsConsts, psHigh, kDirtyPsConst, psF)
#undef CONSTS_F

#define CONSTS_I(Name, arr, bits, mask)                                                       \
    uint32_t Device::Set##Name(uint32_t start, uint32_t data, uint32_t count) {               \
        LOCKED;                                                                               \
        if (!data || start + count > 16) return D3DERR_INVALIDCALL;                            \
        memcpy(S().arr[start], At(data), 16 * count);                                         \
        if (rec) rec->m.mask |= static_cast<uint16_t>(((1u << count) - 1) << start);           \
        else dirty |= bits;                                                                   \
        return D3D_OK;                                                                        \
    }                                                                                         \
    uint32_t Device::Get##Name(uint32_t start, uint32_t data, uint32_t count) {               \
        LOCKED;                                                                               \
        if (!data || start + count > 16) return D3DERR_INVALIDCALL;                            \
        memcpy(At(data), st.arr[start], 16 * count);                                          \
        return D3D_OK;                                                                        \
    }
CONSTS_I(VertexShaderConstantI, vsI, kDirtyVsConst, vsI)
CONSTS_I(PixelShaderConstantI, psI, kDirtyPsConst, psI)
#undef CONSTS_I

#define CONSTS_B(Name, arr, bits, mask)                                                       \
    uint32_t Device::Set##Name(uint32_t start, uint32_t data, uint32_t count) {               \
        LOCKED;                                                                               \
        if (!data || start + count > 16) return D3DERR_INVALIDCALL;                            \
        for (uint32_t k = 0; k < count; k++) S().arr[start + k] = U32(data + 4 * k) ? 1 : 0;  \
        if (rec) rec->m.mask |= static_cast<uint16_t>(((1u << count) - 1) << start);           \
        else dirty |= bits;                                                                   \
        return D3D_OK;                                                                        \
    }                                                                                         \
    uint32_t Device::Get##Name(uint32_t start, uint32_t data, uint32_t count) {               \
        LOCKED;                                                                               \
        if (!data || start + count > 16) return D3DERR_INVALIDCALL;                            \
        for (uint32_t k = 0; k < count; k++) *At<uint32_t>(data + 4 * k) = st.arr[start + k]; \
        return D3D_OK;                                                                        \
    }
CONSTS_B(VertexShaderConstantB, vsB, kDirtyVsConst, vsB)
CONSTS_B(PixelShaderConstantB, psB, kDirtyPsConst, psB)
#undef CONSTS_B

uint32_t Device::SetStreamSource(uint32_t stream, uint32_t vb, uint32_t offset, uint32_t stride) {
    LOCKED;
    if (stream >= kStreams) return D3DERR_INVALIDCALL;
    Buffer* b = Native<Buffer>(vb);
    Stream& s = S().streams[stream];
    if (rec) {
        Hold(s.vb, b);
        s.offset = offset, s.stride = stride;
        rec->m.streams |= 1u << stream;
        return D3D_OK;
    }
    if (s.vb != b) dirty |= kDirtyPipeline;   // (bound or not changes the layout)
    Hold(s.vb, b);
    s.offset = offset, s.stride = stride;
    dirty |= kDirtyStreams;
    return D3D_OK;
}
uint32_t Device::GetStreamSource(uint32_t stream, uint32_t vb, uint32_t offset, uint32_t stride) {
    LOCKED;
    if (stream >= kStreams) return D3DERR_INVALIDCALL;
    const Stream& s = st.streams[stream];
    if (s.vb) s.vb->AddRef_();
    if (vb) *At<uint32_t>(vb) = s.vb ? s.vb->self : 0;
    if (offset) *At<uint32_t>(offset) = s.offset;
    if (stride) *At<uint32_t>(stride) = s.stride;
    return D3D_OK;
}
uint32_t Device::SetStreamSourceFreq(uint32_t stream, uint32_t freq) {
    LOCKED;
    if (stream >= kStreams) return D3DERR_INVALIDCALL;
    S().streams[stream].freq = freq;
    if (rec) rec->m.freqs |= 1u << stream;
    else dirty |= kDirtyPipeline;
    return D3D_OK;
}
uint32_t Device::GetStreamSourceFreq(uint32_t stream, uint32_t out) {
    LOCKED;
    if (stream >= kStreams || !out) return D3DERR_INVALIDCALL;
    *At<uint32_t>(out) = st.streams[stream].freq;
    return D3D_OK;
}
uint32_t Device::SetIndices(uint32_t ib) {
    LOCKED;
    Buffer* b = Native<Buffer>(ib);
    if (rec) {
        Hold(rec->s.ib, b);
        rec->m.ib = true;
        return D3D_OK;
    }
    Hold(st.ib, b);
    dirty |= kDirtyIndices;
    return D3D_OK;
}
uint32_t Device::GetIndices(uint32_t out) {
    LOCKED;
    if (!out) return D3DERR_INVALIDCALL;
    if (st.ib) st.ib->AddRef_();
    *At<uint32_t>(out) = st.ib ? st.ib->self : 0;
    return D3D_OK;
}
uint32_t Device::DrawRectPatch(uint32_t, uint32_t, uint32_t) {
    LogOnce("vk-patches", "d3d9vk: patches are not drawn");
    return D3DERR_INVALIDCALL;
}
uint32_t Device::DrawTriPatch(uint32_t, uint32_t, uint32_t) { return DrawRectPatch(0, 0, 0); }
uint32_t Device::DeletePatch(uint32_t) { return D3D_OK; }
uint32_t Device::CreateQuery(uint32_t type, uint32_t out) {
    LOCKED;
    // EVENT 8, OCCLUSION 9, TIMESTAMP 10, TIMESTAMPDISJOINT 11, TIMESTAMPFREQ 12
    if (type < 8 || type > 12) {
        LogOnce(("vk-query-" + std::to_string(type)).c_str(), "d3d9vk: query type %u is not supported", type);
        if (out) *At<uint32_t>(out) = 0;
        return D3DERR_NOTAVAILABLE;
    }
    if (!out) return D3D_OK;   // (a support check)
    auto q = new Query();
    q->dev = this;
    q->type = type;
    q->self = NewObject(QueryVtable(), static_cast<Base*>(q));
    *At<uint32_t>(out) = q->self;
    return D3D_OK;
}

// ---- the IDirect3D9 ---------------------------------------------------------------------------------------
uint32_t D3D9::QueryInterface(uint32_t, uint32_t out) {
    AddRef_();
    if (out) *At<uint32_t>(out) = self;
    return D3D_OK;
}
uint32_t D3D9::AddRef_() { return static_cast<uint32_t>(++refs); }
uint32_t D3D9::Release_() {
    int r = --refs;
    if (r == 0) {
        FreeObject(self);
        delete this;
    }
    return static_cast<uint32_t>(std::max(r, 0));
}
uint32_t D3D9::RegisterSoftwareDevice(uint32_t) { return D3D_OK; }
uint32_t D3D9::GetAdapterCount() { return 1; }
// D3DADAPTER_IDENTIFIER9 (1,100 bytes): Driver[512], Description[512], DeviceName[32], DriverVersion
// (8, at 1056), VendorId 1064, DeviceId 1068, SubSysId 1072, Revision 1076, the GUID 1080, WHQLLevel 1096
uint32_t D3D9::GetAdapterIdentifier(uint32_t adapter, uint32_t, uint32_t out) {
    if (adapter || !out) return D3DERR_INVALIDCALL;
    memset(At(out), 0, 1100);
    strcpy(At<char>(out), "nvd3dum.dll");
    snprintf(At<char>(out + 512), 512, "NVIDIA GeForce GTX 680 (%s via Vulkan)", vk->props.deviceName);
    strcpy(At<char>(out + 1024), "\\\\.\\DISPLAY1");
    // (an NVIDIA card of the game's era: a vendor it knows takes its usual paths)
    uint32_t ver[2] = {0x000D0000u | 1234u, 0x00090012u};
    memcpy(At(out + 1056), ver, 8);
    *At<uint32_t>(out + 1064) = 0x10DE;
    *At<uint32_t>(out + 1068) = 0x1180;
    *At<uint32_t>(out + 1076) = 0xA1;
    const uint8_t guid[16] = {0xD7, 0xB7, 0x1E, 0x3E, 0x4C, 0x20, 0x11, 0xCF, 0x8E, 0x6A, 0x4A, 0x52, 0x68, 0x76, 0x31, 0x2A};
    memcpy(At(out + 1080), guid, 16);
    *At<uint32_t>(out + 1096) = 1;
    return D3D_OK;
}
uint32_t D3D9::GetAdapterModeCount(uint32_t, uint32_t format) { return format == F_X8R8G8B8 || format == F_A8R8G8B8 ? 1 : 0; }
uint32_t D3D9::EnumAdapterModes(uint32_t adapter, uint32_t, uint32_t mode, uint32_t out) {
    if (mode != 0) return D3DERR_INVALIDCALL;
    return GetAdapterDisplayMode(adapter, out);
}
uint32_t D3D9::GetAdapterDisplayMode(uint32_t, uint32_t out) {
    if (!out) return D3DERR_INVALIDCALL;
    int w = 1920, h = 1080;
    if (void* win = rhipper_window_use(&w, &h)) rhipper_window_done(win);
    uint32_t m[4] = {static_cast<uint32_t>(w), static_cast<uint32_t>(h), 60, F_X8R8G8B8};
    memcpy(At(out), m, sizeof m);
    return D3D_OK;
}
uint32_t D3D9::CheckDeviceType(uint32_t, uint32_t, uint32_t, uint32_t bb, uint32_t) {
    return bb == 0 || bb == F_X8R8G8B8 || bb == F_A8R8G8B8 ? D3D_OK : D3DERR_NOTAVAILABLE;
}
uint32_t D3D9::CheckDeviceFormat(uint32_t, uint32_t, uint32_t, uint32_t usage, uint32_t rtype, uint32_t format) {
    uint32_t r = CheckFormat(usage, rtype, format);
    LogOnce(("vk-check-" + std::to_string(format) + "-" + std::to_string(usage) + "-" + std::to_string(rtype)).c_str(),
            "d3d9vk: CheckDeviceFormat %s usage %#x type %u: %s", FormatName(format), usage, rtype,
            r == D3D_OK ? "yes" : r == D3DOK_NOAUTOGEN ? "no autogen" : "no");
    return r;
}
uint32_t D3D9::CheckDeviceMultiSampleType(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t samples, uint32_t quality) {
    if (samples == 0) {
        if (quality) *At<uint32_t>(quality) = 1;
        return D3D_OK;
    }
    if (quality) *At<uint32_t>(quality) = 0;
    return D3DERR_NOTAVAILABLE;
}
uint32_t D3D9::CheckDepthStencilMatch(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t) { return D3D_OK; }
uint32_t D3D9::CheckDeviceFormatConversion(uint32_t, uint32_t, uint32_t src, uint32_t dst) {
    return LookupFormat(src) && LookupFormat(dst) ? D3D_OK : D3DERR_NOTAVAILABLE;
}
uint32_t D3D9::GetDeviceCaps(uint32_t, uint32_t, uint32_t out) { return FillCaps(vk, out), D3D_OK; }
uint32_t D3D9::GetAdapterMonitor(uint32_t) { return 0x00030000; }

uint32_t D3D9::CreateDevice(uint32_t adapterIn, uint32_t type, uint32_t focusIn, uint32_t behaviorIn, uint32_t ppIn,
                            uint32_t out) {
    if (!ppIn || !out) return D3DERR_INVALIDCALL;
    auto d = new Device();
    d->d3d = this;
    d->vk = vk;
    d->adapter = adapterIn, d->deviceType = type, d->focus = focusIn, d->behavior = behaviorIn;
    d->pp = *At<PresentParams32>(ppIn);
    if (!d->Init()) {
        // (the null renderer's device then: the reference runs, nothing is drawn)
        Log("d3d9vk: the Vulkan device could not be made: the null renderer's instead");
        uint32_t null = NullDirect3DCreate9(32);
        return com::CallMethod(null, 16, adapterIn, type, focusIn, behaviorIn, ppIn, out);
    }
    std::lock_guard<std::recursive_mutex> hold(d->mu);
    d->self = NewObject(DeviceVtable(), d);
    d->implicit = d->NewSwapChain(&d->pp, true);
    if (!d->implicit) return D3DERR_OUTOFVIDEOMEMORY;
    d->implicit->refs = 0;
    d->implicit->Bind();
    if (d->pp.EnableAutoDepthStencil) {
        uint32_t hr;
        if (Surface* ds = d->NewSurface(d->pp.BackBufferWidth, d->pp.BackBufferHeight, d->pp.AutoDepthStencilFormat,
                                        U_DEPTHSTENCIL, POOL_DEFAULT, &hr)) {
            ds->refs = 0;
            Hold(d->autoDepth, ds);
        }
    }
    *At<PresentParams32>(ppIn) = d->pp;
    d->SetDefaults();
    AddRef_();
    *At<uint32_t>(out) = d->self;
    Log("d3d9vk: CreateDevice %ux%u format %s, windowed %u, behavior %#x, auto depth %s", d->pp.BackBufferWidth,
        d->pp.BackBufferHeight, FormatName(d->pp.BackBufferFormat), d->pp.Windowed, behaviorIn,
        d->pp.EnableAutoDepthStencil ? FormatName(d->pp.AutoDepthStencilFormat) : "none");
    // (Direct3D 9 sets the x87 unit to 24-bit precision unless asked to keep it: Com32.cpp)
    if (!(behaviorIn & 2 /* D3DCREATE_FPU_PRESERVE */)) gen_set_x87_cw(0x007f);
    return D3D_OK;
}

// D3DCAPS9 (304 bytes, 76 words): a Shader Model 3 card of 2013, within what this GPU does
void FillCaps(const Vulkan* vk, uint32_t out) {
    auto c = At<uint32_t>(out);
    memset(c, 0, 304);
    auto f = [&](int k, float v) { memcpy(&c[k], &v, 4); };
    const VkPhysicalDeviceLimits& l = vk->props.limits;
    c[0] = 1;                               // DeviceType: HAL
    c[2] = 0x20000;                         // Caps: READ_SCANLINE
    c[3] = 0x20000 | 0x20000000 | 0x40000000;   // Caps2: FULLSCREENGAMMA, DYNAMICTEXTURES, CANAUTOGENMIPMAP
    c[4] = 0x20 | 0x80 | 0x100 | 0x200;     // Caps3: ALPHA_FULLSCREEN_FLIP_OR_DISCARD, LINEAR_TO_SRGB, COPY_TO_*
    c[5] = 0x8000000Fu;                     // PresentationIntervals: IMMEDIATE, ONE .. FOUR
    c[6] = 1;                               // CursorCaps: COLOR
    c[7] = 0x1BBEF0;                        // DevCaps: HW T&L, pure device, video memory everything
    c[8] = 0x2 | 0x10 | 0x20 | 0x40 | 0x80 | 0x200 | 0x400 | 0x800 | (vk->features.independentBlend ? 0x4000 : 0) |
           0x8000 | 0x10000 | 0x20000 | 0x40000 | 0x80000 | 0x100000;   // PrimitiveMiscCaps
    c[9] = 0xF732191;                       // RasterCaps: z test, fog, anisotropy, scissor, depth bias ...
    c[10] = 0xFF;                           // ZCmpCaps
    c[11] = c[12] = 0x3FFF;                 // Src/DestBlendCaps (no dual source)
    c[13] = 0xFF;                           // AlphaCmpCaps
    c[14] = 0x84208;                        // ShadeCaps
    c[15] = 0x1EC05;                        // TextureCaps: perspective, alpha, projected, cube, volume, mips (non-pow2)
    c[16] = c[17] = c[18] = 0x7030700;      // texture filter caps: point, linear, anisotropic
    c[19] = c[20] = 0x3F;                   // TextureAddressCaps
    c[21] = 0x1F;                           // LineCaps
    c[22] = c[23] = std::min(l.maxImageDimension2D, 8192u);
    c[24] = std::min(l.maxImageDimension3D, 2048u);
    c[25] = c[26] = 8192;                   // MaxTextureRepeat, MaxTextureAspectRatio
    c[27] = vk->features.samplerAnisotropy ? std::min(16u, static_cast<uint32_t>(l.maxSamplerAnisotropy)) : 1;
    f(28, 1e10f);                           // MaxVertexW
    f(29, -32768.0f), f(30, -32768.0f), f(31, 32768.0f), f(32, 32768.0f);   // guard band
    c[34] = 0x1FF;                          // StencilCaps (two-sided)
    c[35] = 0x100008;                       // FVFCaps: 8 texture coordinates, PSIZE
    c[36] = 0x3FFFFFF;                      // TextureOpCaps
    c[37] = c[38] = 8;                      // MaxTextureBlendStages, MaxSimultaneousTextures
    c[39] = 0x17B;                          // VertexProcessingCaps
    c[40] = 8;                              // MaxActiveLights
    c[41] = 6;                              // MaxUserClipPlanes (taken, not clipped: logged)
    c[42] = 4;                              // MaxVertexBlendMatrices
    f(44, 256.0f);                          // MaxPointSize
    c[45] = c[46] = 0xFFFFFF;               // MaxPrimitiveCount, MaxVertexIndex
    c[47] = 16;                             // MaxStreams
    c[48] = 255;                            // MaxStreamStride
    c[49] = 0xFFFE0300;                     // VertexShaderVersion 3.0
    c[50] = 256;                            // MaxVertexShaderConst
    c[51] = 0xFFFF0300;                     // PixelShaderVersion 3.0
    f(52, 65504.0f);                        // PixelShader1xMaxValue
    c[53] = 0x51;                           // DevCaps2: STREAMOFFSET, CAN_STRETCHRECT_FROM_TEXTURES, shared offsets
    c[58] = 1;                              // NumberOfAdaptersInGroup
    c[59] = 0x3FF;                          // DeclTypes
    c[60] = std::min(4u, l.maxColorAttachments);   // NumSimultaneousRTs
    c[61] = 0x3000300;                      // StretchRectFilterCaps: point, linear
    c[62] = 1, c[63] = 24, c[64] = 32, c[65] = 4;              // VS20Caps
    c[66] = 0x1F, c[67] = 24, c[68] = 32, c[69] = 4, c[70] = 512;   // PS20Caps
    c[71] = 0x3000300;                      // VertexTextureFilterCaps
    c[72] = c[73] = 65535;                  // Max V/P ShaderInstructionsExecuted
    c[74] = c[75] = 32768;                  // Max V/P Shader30InstructionSlots
}

// ---- the vtables ------------------------------------------------------------------------------------------
namespace {
uint32_t DeviceVtable() {
    static uint32_t v = [] {
        const void* m[119] = {
            M_<&Device::QueryInterface>(), M_<&Device::AddRef_>(), M_<&Device::Release_>(),
            M_<&Device::TestCooperativeLevel>(), M_<&Device::GetAvailableTextureMem>(),
            M_<&Device::EvictManagedResources>(), M_<&Device::GetDirect3D>(), M_<&Device::GetDeviceCaps>(),
            M_<&Device::GetDisplayMode>(), M_<&Device::GetCreationParameters>(), M_<&Device::SetCursorProperties>(),
            M_<&Device::SetCursorPosition>(), M_<&Device::ShowCursor>(), M_<&Device::CreateAdditionalSwapChain>(),
            M_<&Device::GetSwapChain>(), M_<&Device::GetNumberOfSwapChains>(), M_<&Device::Reset>(),
            M_<&Device::Present>(), M_<&Device::GetBackBuffer>(), M_<&Device::GetRasterStatus>(),
            M_<&Device::SetDialogBoxMode>(), M_<&Device::SetGammaRamp>(), M_<&Device::GetGammaRamp>(),
            M_<&Device::CreateTexture>(), M_<&Device::CreateVolumeTexture>(), M_<&Device::CreateCubeTexture>(),
            M_<&Device::CreateVertexBuffer>(), M_<&Device::CreateIndexBuffer>(), M_<&Device::CreateRenderTarget>(),
            M_<&Device::CreateDepthStencilSurface>(), M_<&Device::UpdateSurface>(), M_<&Device::UpdateTexture>(),
            M_<&Device::GetRenderTargetData>(), M_<&Device::GetFrontBufferData>(), M_<&Device::StretchRect>(),
            M_<&Device::ColorFill>(), M_<&Device::CreateOffscreenPlainSurface>(), M_<&Device::SetRenderTarget>(),
            M_<&Device::GetRenderTarget>(), M_<&Device::SetDepthStencilSurface>(),
            M_<&Device::GetDepthStencilSurface>(), M_<&Device::BeginScene>(), M_<&Device::EndScene>(),
            M_<&Device::Clear>(), M_<&Device::SetTransform>(), M_<&Device::GetTransform>(),
            M_<&Device::MultiplyTransform>(), M_<&Device::SetViewport>(), M_<&Device::GetViewport>(),
            M_<&Device::SetMaterial>(), M_<&Device::GetMaterial>(), M_<&Device::SetLight>(), M_<&Device::GetLight>(),
            M_<&Device::LightEnable>(), M_<&Device::GetLightEnable>(), M_<&Device::SetClipPlane>(),
            M_<&Device::GetClipPlane>(), M_<&Device::SetRenderState>(), M_<&Device::GetRenderState>(),
            M_<&Device::CreateStateBlock>(), M_<&Device::BeginStateBlock>(), M_<&Device::EndStateBlock>(),
            M_<&Device::SetClipStatus>(), M_<&Device::GetClipStatus>(), M_<&Device::GetTexture>(),
            M_<&Device::SetTexture>(), M_<&Device::GetTextureStageState>(), M_<&Device::SetTextureStageState>(),
            M_<&Device::GetSamplerState>(), M_<&Device::SetSamplerState>(), M_<&Device::ValidateDevice>(),
            M_<&Device::SetPaletteEntries>(), M_<&Device::GetPaletteEntries>(),
            M_<&Device::SetCurrentTexturePalette>(), M_<&Device::GetCurrentTexturePalette>(),
            M_<&Device::SetScissorRect>(), M_<&Device::GetScissorRect>(), M_<&Device::SetSoftwareVertexProcessing>(),
            M_<&Device::GetSoftwareVertexProcessing>(), M_<&Device::SetNPatchMode>(), M_<&Device::GetNPatchMode>(),
            M_<&Device::DrawPrimitive>(), M_<&Device::DrawIndexedPrimitive>(), M_<&Device::DrawPrimitiveUP>(),
            M_<&Device::DrawIndexedPrimitiveUP>(), M_<&Device::ProcessVertices>(),
            M_<&Device::CreateVertexDeclaration>(), M_<&Device::SetVertexDeclaration>(),
            M_<&Device::GetVertexDeclaration>(), M_<&Device::SetFVF>(), M_<&Device::GetFVF>(),
            M_<&Device::CreateVertexShader>(), M_<&Device::SetVertexShader>(), M_<&Device::GetVertexShader>(),
            M_<&Device::SetVertexShaderConstantF>(), M_<&Device::GetVertexShaderConstantF>(),
            M_<&Device::SetVertexShaderConstantI>(), M_<&Device::GetVertexShaderConstantI>(),
            M_<&Device::SetVertexShaderConstantB>(), M_<&Device::GetVertexShaderConstantB>(),
            M_<&Device::SetStreamSource>(), M_<&Device::GetStreamSource>(), M_<&Device::SetStreamSourceFreq>(),
            M_<&Device::GetStreamSourceFreq>(), M_<&Device::SetIndices>(), M_<&Device::GetIndices>(),
            M_<&Device::CreatePixelShader>(), M_<&Device::SetPixelShader>(), M_<&Device::GetPixelShader>(),
            M_<&Device::SetPixelShaderConstantF>(), M_<&Device::GetPixelShaderConstantF>(),
            M_<&Device::SetPixelShaderConstantI>(), M_<&Device::GetPixelShaderConstantI>(),
            M_<&Device::SetPixelShaderConstantB>(), M_<&Device::GetPixelShaderConstantB>(),
            M_<&Device::DrawRectPatch>(), M_<&Device::DrawTriPatch>(), M_<&Device::DeletePatch>(),
            M_<&Device::CreateQuery>()};
        return Vtable(m, 119);
    }();
    return v;
}

uint32_t D3D9Vtable() {
    static uint32_t v = [] {
        const void* m[17] = {
            M_<&D3D9::QueryInterface>(), M_<&D3D9::AddRef_>(), M_<&D3D9::Release_>(),
            M_<&D3D9::RegisterSoftwareDevice>(), M_<&D3D9::GetAdapterCount>(), M_<&D3D9::GetAdapterIdentifier>(),
            M_<&D3D9::GetAdapterModeCount>(), M_<&D3D9::EnumAdapterModes>(), M_<&D3D9::GetAdapterDisplayMode>(),
            M_<&D3D9::CheckDeviceType>(), M_<&D3D9::CheckDeviceFormat>(), M_<&D3D9::CheckDeviceMultiSampleType>(),
            M_<&D3D9::CheckDepthStencilMatch>(), M_<&D3D9::CheckDeviceFormatConversion>(), M_<&D3D9::GetDeviceCaps>(),
            M_<&D3D9::GetAdapterMonitor>(), M_<&D3D9::CreateDevice>()};
        return Vtable(m, 17);
    }();
    return v;
}
}  // namespace

}  // namespace rh::d3d9vk

// Direct3DCreate9's Vulkan IDirect3D9 (d3d9_null.cpp asks here first): 0 when Vulkan can't
namespace rh {
uint32_t VkDirect3DCreate9(uint32_t sdk) {
    using namespace d3d9vk;
    Vulkan* vk = GetVulkan();
    if (!vk) return 0;
    auto d = new D3D9();
    d->vk = vk;
    d->self = NewObject(D3D9Vtable(), d);
    Log("Direct3DCreate9(%u): Vulkan on %s", sdk, vk->props.deviceName);
    return d->self;
}
}  // namespace rh
