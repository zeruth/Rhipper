# d3d9vk status (2026-10-31)

Direct3D 9 on Vulkan for runtime32-posix: in Runtime32Posix.cmake (every file here, `vulkan` linked),
and Direct3DCreate9's default (Com32Posix.cpp: a project factory first, then VkDirect3DCreate9, then
d3d9_null.cpp's null renderer when there is no usable Vulkan 1.3 or `<ENV>_D3D9=null`).

## State
- Every file compiles for aarch64-linux-android with no errors, and no d3d9vk symbol is left undefined.
  None of it has run on a GPU yet.
- `Shader.cpp`, `SpirvBuilder.*`: SM1.1-3.0 to SPIR-V. `tests/shader_cases.cpp`: 5 cases, all pass
  `spirv-val --target-env vulkan1.1` (NDK shader-tools).
- `Draw.cpp` (the draw path): render passes over the bound targets (dynamic rendering), Clear inside
  them, PrepareDraw (textures' mips and layouts first, then the pass, then pipeline, dynamic state,
  push descriptors, the uniform blocks, push constants, vertex and index buffers), the four draws,
  occlusion queries per pass, StretchRect, ColorFill, UpdateSurface, UpdateTexture,
  GetRenderTargetData, GetFrontBufferData.

## Choices to check on the device
- Y: the push constants' flip bit is always set (D3D's clip Y up, Vulkan's down, both framebuffers
  top-left). Front faces are clockwise, CULL_CW culls front, CULL_CCW culls back.
- Depth bias: D3D9's units scaled by 2^24 - 1 (2^16 - 1 for D16).
- A texture bound as a target and sampled gets the stand-in, logged.
- Float arguments: Device.cpp takes Clear's Z and SetNPatchMode's value as float bits, as FFXIV
  passes them (gen_fl2bits). Any other float parameter: check its call sites in src/gen.

## Not done
- Shadow samplers (depth compare): no flag in Shader.h yet.
- User clip planes, point sprites, fixed-function lighting and fog, patches, ProcessVertices: logged.
