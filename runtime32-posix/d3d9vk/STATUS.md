# d3d9vk status (2026-11-01)

Direct3D 9 on Vulkan for runtime32-posix: in Runtime32Posix.cmake (every file here, `vulkan` linked),
and Direct3DCreate9's default (Com32Posix.cpp: a project factory first, then VkDirect3DCreate9, then
d3d9_null.cpp's null renderer when there is no usable Vulkan 1.3 or `<ENV>_D3D9=null`).

## State
- Renders FINAL FANTASY XIV's 2013 beta title screen correctly on an Adreno 840 (Vulkan 1.4).
- Every file compiles for aarch64-linux-android with no warnings.
- `Shader.cpp`, `SpirvBuilder.*`: SM1.1-3.0 to SPIR-V. `tests/shader_cases.cpp`: 7 cases, all pass
  `spirv-val --target-env vulkan1.1` (NDK shader-tools). The fixed-function shaders pass it too (built
  natively over a stub Vk.h: FixedFunction.cpp needs only LinkLocation and the State's fields).
- `Draw.cpp` (the draw path): render passes over the bound targets (dynamic rendering), Clear inside
  them or as their load ops, PrepareDraw, the four draws, occlusion queries per pass, StretchRect,
  ColorFill, UpdateSurface, UpdateTexture, GetRenderTargetData, GetFrontBufferData.

## Performance (2026-11-01: the lobby profile's hot spots)
- Dynamic buffers (DYNAMIC, SYSTEMMEM): versions are the buffer's own host-visible VkBuffers (up to 8,
  256 MB for all), kept across submissions and reused once the GPU is done; the ring only past that.
  DISCARD: a free version, the locked range copied. NOOVERWRITE: in place. No flag: in place when the
  GPU is done with the version, else a fresh one with the whole shadow. Use() copies only when the
  buffer has no current version (a ring one from an older submission). Was: a whole-buffer copy into
  the ring at each submission's first use, and at every NOOVERWRITE unlock of a new frame.
- A static buffer (<= 1 MB, host visible) locked again in the submission that drew from it becomes a
  dynamic one (its device buffer the first version) instead of ending the pass for an inline copy.
- Static buffer locks: their low memory is not zeroed (a small lock of a large buffer costs its range).
- PrepareDraw records only what changed: textures looked at again on kDirtyTextures (bindings, sampler
  states, shaders, targets, an image's layout moved by an upload or copy, mips to make, Z writes);
  pipeline key and lookup on kDirtyPipeline (a stream's buffer changing no longer sets it, only bound
  vs unbound); descriptors pushed when a block or texture changed; push constants, topology, vertex
  and index buffers when their values differ from what the command buffer has.
- Uniform blocks: filled as far as the shader reads (ShaderInfo::floatConsts, i/b only if read; all of
  c under relative addressing), not the whole 4.6 KB; the setters return early on unchanged values
  (constants, viewport, scissor, texture stage states, stream frequency).
- A Clear of the whole render area that begins a pass is the pass's load ops (CLEAR, not LOAD then
  vkCmdClearAttachments); the scissor is set again only when the render area's size changed.
- No heap allocation per draw: hot-path logs use `Once<>` (Vk.h, a flag per site) instead of LogOnce's
  key strings; Clear's rects in a fixed array.
- GetData without D3DGETDATA_FLUSH no longer submits mid-frame (after 64 polls it does).

## Choices to check on the device
- Y: the push constants' flip bit is always set (D3D's clip Y up, Vulkan's down, both framebuffers
  top-left). Front faces are clockwise, CULL_CW culls front, CULL_CCW culls back.
- The half pixel: the Vulkan viewport moved +0.5 (shader offset push 0). The scissor is the viewport
  intersected with the scissor rect (D3D9 writes nothing outside the viewport).
- Depth bias: D3D9's units scaled by 2^24 - 1 (2^16 - 1 for D16).
- A texture bound as a color target and sampled gets the stand-in, logged. The depth surface sampled
  (INTZ) while depth and stencil writes are off: the pass keeps it DEPTH_STENCIL_READ_ONLY_OPTIMAL and
  the draw samples it (soft particles and the like); with writes on, the stand-in.
- Point sprites: gl_PointSize is D3DRS_POINTSIZE clamped to MIN..MAX (a shader's own clamped to MAX),
  largePoints enabled; a point list with POINTSPRITEENABLE replaces every texture coordinate with
  (PointCoord, 0, 1) (push flags bit 1). POINTSCALEENABLE's distance scale is not done (logged).
- Swapchain: acquire times out after 500 ms (the host's surface change waits while Present holds the
  window); SUBOPTIMAL keeps presenting; OUT_OF_DATE remakes it; SURFACE_LOST (acquire or present)
  drops the surface, made again from the host's next window.
- oDepth is clamped to [0, 1].
- Float arguments: Device.cpp takes Clear's Z and SetNPatchMode's value as float bits, as FFXIV
  passes them (gen_fl2bits). Any other float parameter: check its call sites in src/gen.

## Not done
- Shadow samplers (depth compare): no flag in Shader.h yet.
- User clip planes, fixed-function lighting and fog, patches, ProcessVertices: logged.
- A texture whose other mip level is the bound target (a downsample chain in one texture): stand-in.
- An upload into a texture a draw of this submission already sampled ends the pass (the copy must
  come after those draws); a font atlas updated between text draws costs a pass per update.
- GetRenderTargetData / LOCK_READONLY of a format held converted (565, 4444, DXTn decoded): refused.
- A non-dynamic texture lock that is not READONLY starts zeroed, not with the level's contents.
