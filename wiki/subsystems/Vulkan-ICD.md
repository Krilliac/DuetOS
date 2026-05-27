# Vulkan ICD (In-Kernel)

> **Audience:** Graphics subsystem authors, DirectX-translation contributors
>
> **Execution context:** Kernel — currently CPU-side only; no real GPU
> submission in v1
>
> **Maturity:** v1 — instance / device / queue / command-buffer lifecycle
> + clear-to-scanout + CPU triangle rasterizer + SPIR-V interpreter
> (parser + executor for the canonical Vulkan subset; wired into
> `vkCmdDraw` via the shader-rasterizer hook when a pipeline binds
> parseable VS + FS modules)

## Overview

DuetOS hosts its Vulkan ICD **inside the kernel**. The reason is
pragmatic: the kernel already owns the GPU command rings (NVMe-style
PCIe submission queues, virtio-gpu virtqueues, the Intel iGPU
execlist), and the [Subsystem Isolation](../kernel/Subsystem-Isolation.md)
rule says every effect a guest binary can have on the system goes
through a kernel-mediated cap-gated path. Putting the ICD in the
kernel means Vulkan calls funnel into the same place as every other
GPU-touching code path.

The v0 ICD is **CPU-side only**. Command buffers record opcodes into a
per-buffer tape. `vkQueueSubmit` replays the tape on the CPU; the only
opcodes that produce visible output are `vkCmdClearColorImage` (against
a scanout-backed image) and `vkQueuePresentKHR` (which flushes the
damage rect through the compositor).

What that buys us today:

- The Vulkan handle-lifecycle is exercised end-to-end — every PE that
  pulls in `vulkan-1.dll` (and there are several already) loads
  cleanly.
- The DirectX 11 / 12 translators ([DirectX](DirectX.md)) bind to a
  real device + queue + command list shape.
- The WSI surface acquires + presents real framebuffer pixels.

What it does **not** buy us yet: pixel-shader execution, vertex
processing, or any submission to real silicon. Those are the gating
slices for the per-vendor GPU drivers
([Graphics Drivers](../drivers/Graphics-Drivers.md)) to actually paint
their commands.

## File Layout

| File | Purpose |
|------|---------|
| [`graphics.h`](../../kernel/subsystems/graphics/graphics.h) / `.cpp` | Subsystem entry, public stats |
| [`graphics_vk.cpp`](../../kernel/subsystems/graphics/graphics_vk.cpp) | Instance / device / queue lifecycle |
| [`graphics_vk_commands.cpp`](../../kernel/subsystems/graphics/graphics_vk_commands.cpp) | Command buffer tape (record + replay) |
| [`graphics_vk_descriptors.cpp`](../../kernel/subsystems/graphics/graphics_vk_descriptors.cpp) | Descriptor sets, pools, layouts |
| [`graphics_vk_misc.cpp`](../../kernel/subsystems/graphics/graphics_vk_misc.cpp) | Format conversions, image creation, memory mapping |
| [`graphics_vk_wsi.cpp`](../../kernel/subsystems/graphics/graphics_vk_wsi.cpp) | WSI — surface, swapchain, present |
| [`graphics_vk_raster.cpp`](../../kernel/subsystems/graphics/graphics_vk_raster.cpp) | Fixed-function CPU triangle rasterizer (v0/v1 vertex format) |
| [`graphics_vk_depth.cpp`](../../kernel/subsystems/graphics/graphics_vk_depth.cpp) | Software 16-bit depth surface |
| [`graphics_vk_spirv.h`](../../kernel/subsystems/graphics/graphics_vk_spirv.h) | SPIR-V interpreter public interface |
| [`graphics_vk_spirv_parse.cpp`](../../kernel/subsystems/graphics/graphics_vk_spirv_parse.cpp) | Module parser (types, constants, decorations, basic blocks) |
| [`graphics_vk_spirv_exec.cpp`](../../kernel/subsystems/graphics/graphics_vk_spirv_exec.cpp) | Interpreter execution engine |
| [`graphics_vk_spirv_selftest.cpp`](../../kernel/subsystems/graphics/graphics_vk_spirv_selftest.cpp) | Boot self-test (3 canonical SPIR-V modules) |
| [`graphics_vk_shaderraster.cpp`](../../kernel/subsystems/graphics/graphics_vk_shaderraster.cpp) | Shader-based rasterizer hook (`vkCmdDraw` -> SPIR-V interpreter) |
| [`graphics_vk_selftest.cpp`](../../kernel/subsystems/graphics/graphics_vk_selftest.cpp) | Boot self-test (lifecycle) |
| [`graphics_vk_internal.h`](../../kernel/subsystems/graphics/graphics_vk_internal.h) | Shared per-handle structures |

## Handle Model

Every Vulkan handle (`VkInstance`, `VkDevice`, `VkQueue`,
`VkCommandBuffer`, `VkImage`, `VkBuffer`, `VkPipeline`, …) is a
slot-indexed 64-bit ID. Per-kind pools live in the subsystem with
fixed slot counts (32 per kind in v0). The ID is composed
`base + slot` where the base differs per kind (e.g. instance handles
start at `0x10000`, devices at `0x20000`, …). That makes a stray
"wrong kind of handle" obvious in a debugger without paying the cost
of a real opaque dispatch table.

Dispatch is direct C++ function calls — no vendor ICD trampolines,
no `vk_layer_dispatch_table`. Userland calls into `vulkan-1.dll`,
which thunks to the subsystem entry points via the standard Win32
syscall path.

## Command Buffer Tape

`vkBeginCommandBuffer` allocates a fresh tape; every `vkCmd*` call
appends an opcode + parameters. `vkEndCommandBuffer` flips the buffer
state from "recording" to "executable."

`vkQueueSubmit` walks the tape. Today's opcodes:

| Opcode | What it does in v0 |
|--------|--------------------|
| `vkCmdClearColorImage` | Writes the clear colour to the image's backing memory. If the image is scanout-backed, the framebuffer's damage rect is widened. |
| `vkCmdBindPipeline`, `vkCmdBindDescriptorSets`, `vkCmdBindIndexBuffer` | Update tape-local "current state" only. |
| `vkCmdBindVertexBuffers` | Recorded; the binding-0 buffer + offset feed the software triangle rasterizer at `vkCmdDraw` replay time. |
| `vkCmdDraw` | Software triangle rasterizer — paints flat-shaded triangles into the bound scanout-backed render target via the DuetOS v0 fixed vertex format (see below). Bumps `vk_triangles_drawn` by `vertex_count / 3` regardless of whether pixels reach the framebuffer. |
| `vkCmdDrawIndexed`, `vkCmdDispatch` | Bump a counter. No pixels move (no index-buffer fetch in the rasterizer yet; no shader to run for compute). |
| `vkCmdCopyBuffer`, `vkCmdCopyImage`, `vkCmdCopyBufferToImage` | Real `memcpy` between mapped backing buffers. |
| `vkCmdPipelineBarrier`, `vkCmdSetViewport`, `vkCmdSetScissor` | No-op (state recorded, not enforced). |

## Software triangle rasterizer (v1)

`graphics_vk_raster.cpp` is a CPU edge-function rasterizer that
turns `vkCmdDraw` and `vkCmdDrawIndexed` into visible pixels when
the caller fills its vertex buffer with one of the DuetOS fixed
vertex formats and points the draw at a scanout-backed render
target. No SPIR-V execution, no vertex transform — positions are
already in pixel space — but the rasterizer interpolates colour
(Gouraud), honours per-pixel alpha (src-over) and runs a
hardware-style depth test on the v1 vertex format.

**Vertex formats:**

| Format | Stride | Layout |
|--------|--------|--------|
| v0 (default) | 8 bytes | `{i16 x_px; i16 y_px; u32 argb;}` |
| v1 (with depth) | 12 bytes | `{i16 x_px; i16 y_px; i16 z; u16 reserved; u32 argb;}` |

The format is per-command-buffer state. Defaults to v0;
callers select v1 via the DuetOS extension
`vkCmdSetVertexFormatDuet(cb, 1)`. `argb` is 0xAARRGGBB; the
high byte drives `FramebufferBlendPixel` (src-over blend)
when < 0xFF and `FramebufferPutPixel` (opaque) when == 0xFF.

**Topologies (Vulkan spec values):**

| Topology | Value | Primitives produced |
|----------|-------|---------------------|
| PointList | 0 | `vertex_count` 1×1 pixel stamps |
| LineList | 1 | `vertex_count / 2` Bresenham segments |
| LineStrip | 2 | `vertex_count - 1` Bresenham segments |
| TriangleList | 3 | `vertex_count / 3` triangles |
| TriangleStrip | 4 | `vertex_count - 2` triangles (odd triangles flip winding) |
| TriangleFan | 5 | `vertex_count - 2` triangles (every triangle shares vertex 0) |

Point and line topologies are flat-shaded with the first vertex's
colour and bypass the triangle bbox walk. `*_with_adjacency`
topologies record but produce no pixels. Selected via
`vkCmdSetPrimitiveTopology(cb, n)`; defaults to TriangleList.

**Indexed draws:** `vkCmdDrawIndexed` walks the buffer bound by
`vkCmdBindIndexBuffer`. UINT16 and UINT32 index formats are
both supported; each index is offset by the draw's
`vertex_offset` parameter before lookup in the vertex buffer.
Strip and fan topologies are honoured the same way as the
non-indexed path.

**Scissor:** the rasterizer's bounding-box walk is intersected
with the most-recent `vkCmdSetScissor` rect when it's
non-empty. A zero-extent scissor disables enforcement.

**Depth test:** when the vertex format is v1 AND
`vkCmdSetDepthTestEnable(cb, 1)` has run AND the shared depth
surface allocates successfully:

- Z is interpolated barycentrically per pixel using the same
  weights as colour.
- The depth surface is a single `u16` per-pixel buffer sized to
  the live framebuffer extent (one buffer total — v0 doesn't
  multi-target). Lazy-allocated through `kheap` on the first
  Z-test draw; cleared to `0xFFFF` (far) at alloc and by
  `vkCmdClearDepthStencilImage` (recognising the canonical
  `0.0f` / `1.0f` bit patterns to avoid pulling in soft-float).
- `vkCmdSetDepthCompareOp(cb, op)` honours every Vulkan
  compare op (Never / Less / Equal / LessOrEqual / Greater /
  NotEqual / GreaterOrEqual / Always). Default Less.
- `vkCmdSetDepthWriteEnable(cb, 1)` gates the write-back of
  the new Z value to the depth surface; the compare still
  runs when write is disabled.

When the depth surface can't allocate (low memory, headless
boot) the rasterizer silently falls back to the no-Z path and
logs one WARN line — no per-frame chatter.

**Algorithm:** integer edge-function (barycentric) test. For
each pixel `(px, py)` in the clipped bounding box, compute the
three edge functions; a pixel is inside when all three share a
sign consistent with the triangle's signed area. Barycentric
weights are the absolute edge magnitudes; channels and Z are
interpolated as
`(w0*a + w1*b + w2*c + |area|/2) / |area|`. Degenerate
(zero-area) triangles are skipped. The flat-shade fast path
(all three vertex colours identical) skips the per-pixel
divide.

**Replay state machine** — these per-cb commands feed the
rasterizer at submit time:

| Command | Effect on RasterState |
|---------|-----------------------|
| `vkCmdBeginRenderPass` / `BeginRendering` / `ClearColorImage` | sets `rt_image` |
| `vkCmdBindVertexBuffers(binding=0)` | sets `vertex_buffer` + `vertex_offset` |
| `vkCmdBindIndexBuffer` | sets `index_buffer` + `index_offset` + `index_type` |
| `vkCmdSetScissor` | sets `scissor` + `has_scissor` (cleared by zero-extent rect) |
| `vkCmdSetPrimitiveTopology` | sets `topology` |
| `vkCmdSetVertexFormatDuet` *(extension)* | sets `vertex_format` (0 = v0, 1 = v1) |
| `vkCmdSetDepthTestEnable` / `SetDepthWriteEnable` / `SetDepthCompareOp` | gates depth |
| `vkCmdClearDepthStencilImage` | lazy-allocates + clears the shared depth surface |

State is per-command-buffer; a secondary cb invoked via
`vkCmdExecuteCommands` starts with fresh state in its own
recursion of the replay walker.

**Counters** — `vk_triangles_drawn` ticks per dispatched
triangle (TriangleList: `vertex_count / 3`; strip/fan:
`vertex_count - 2`; same for indexed-draw counts) regardless of
whether the rasterizer actually paints (counter bumps before
the scanout / host-visible / format gates), so the dispatch
chain is observable to tests that don't own the live
framebuffer.

**Front-face culling:** `vkCmdSetCullMode(cb, mode)` and
`vkCmdSetFrontFace(cb, face)` enforce backface / frontface
culling at raster time. Cull modes: 0=None, 1=Front, 2=Back,
3=FrontAndBack. Front-face values: 0=CounterClockwise (default),
1=Clockwise. The sign of the integer signed-area test
(`EdgeFn(v0, v1, v2)`) decides screen-space orientation;
triangles whose orientation matches the cull selection are
dropped before the bbox walk. Default is "no culling".

Out of scope — deferred:

- Texture sampling. The descriptor surface accepts
  `CombinedImageSampler` binds but the rasterizer has no
  per-pixel sampler fetch path; the bound image-view is recorded
  for stats only.
- Perspective-correct attribute interpolation. The rasterizer
  is affine; pre-divided W-space attributes are the caller's
  responsibility.
- Multi-binding vertex buffers — only binding 0 is consumed.
- Multi-rect scissor — only the first scissor rect is recorded.

The reason `Copy*` works while `Draw*` doesn't: copy operations don't
need shader execution. The framebuffer's pixels move because the
copy is `memcpy` on CPU memory the framebuffer already mirrors.

## WSI Path

The window-system integration is where the ICD meets the compositor:

1. `vkCreateXcbSurfaceKHR` / equivalent — the loader maps the
   Win32 `HWND` (or native window handle) to a `VkSurfaceKHR`.
2. `vkCreateSwapchainKHR` — allocates `N` scanout-backed images. Each
   image's backing memory aliases a slice of the framebuffer that the
   compositor will present.
3. `vkAcquireNextImageKHR` — returns the next image index.
4. The app records draws into a command buffer targeting that image;
   submits via `vkQueueSubmit`. `vkCmdClearColorImage` and
   `vkCmdDraw` / `vkCmdDrawIndexed` (CPU edge-function rasterizer
   with Gouraud interpolation, scissor, software 16-bit depth)
   both produce real pixels into the scanout image.
5. `vkQueuePresentKHR` — flushes the damage rect through the
   compositor.

`vkAcquireNextImageKHR` does not currently block — there's only one
"frame in flight" so the next image is always available. When real
GPU submission lands, the wait + semaphore mechanics will need to
fill in.

## Stats Counters

The subsystem keeps a `GraphicsStats` struct with per-handle "live"
counts plus a few interesting totals:

- `vk_instance_live`, `vk_device_live`, `vk_command_buffer_live`, …
- `vk_command_recorded` — total opcodes appended across all buffers
- `vk_command_replayed` — total opcodes consumed by `vkQueueSubmit`
- `vk_clear_pixels_painted` — sum of pixels written via `Clear`
- `vk_spirv_entry_points_seen` — count of SPIR-V entry points the
  shader-module parser found (parser runs at `vkCreateShaderModule`)

The `gfxdemo` kernel app reads these counters live to render its
"current GPU activity" panel.

## Boot Self-Test

`graphics_vk_selftest.cpp` runs at boot:

- Create + destroy a `VkInstance`, `VkDevice`, `VkQueue`
- Allocate a `VkImage` scanout-backed, clear it red, verify
  framebuffer pixels
- Allocate a `VkBuffer`, map, write, unmap, verify backing memory

A failure here fires `kBootSelftestFail` and panics — graphics is
foundational enough that booting through a broken ICD will produce
nonsense for every consumer downstream.

## DirectX Translation Hand-off

D3D11 ([`userland/libs/d3d11/`](../../userland/libs/d3d11/)) and D3D12
([`userland/libs/d3d12/`](../../userland/libs/d3d12/)) implement their
`Clear` + `Present` path by:

1. Creating a `VkInstance` + `VkDevice` + `VkSwapchainKHR` on first
   `IDXGISwapChain` creation.
2. Translating each D3D Clear / Present call into the equivalent
   Vulkan call.
3. Routing the D3D resource handles back to Vulkan handles through a
   per-D3D-device translation table.

That gives the v0 DirectX path real, visible Clear + Present pixels —
which is exactly what every smoke test currently asserts.

## Threading and Locking

- One global spinlock protects the per-kind handle pools — handle
  allocation is rare, so the contention cost is negligible.
- Command-buffer recording is per-buffer; concurrent recording of
  *different* buffers is lock-free.
- `vkQueueSubmit` takes the queue's spinlock and serialises submits
  on that queue.
- Boot self-test runs single-threaded.

## Capability Gates

Graphics runs in kernel context; the ICD doesn't gate at the
Vulkan-call level. Capability checks happen one layer up — at the
syscalls that the Win32 thunks issue to reach the ICD. See
[Capabilities](../security/Capabilities.md).

## SPIR-V interpreter (v1)

`graphics_vk_spirv_*.{h,cpp}` is a freestanding SPIR-V parser +
executor inside the kernel. At `vkCreateShaderModule` time the
module is parsed into a `Program` structure (types, constants,
variables, basic blocks, instructions) and stored alongside the
existing `ShaderModuleInfo`. The interpreter runs the program on
demand — once per vertex (vertex shader) or once per pixel
(fragment shader) — when the shader-rasterizer hook drives a
`vkCmdDraw` against a pipeline that has parseable VS + FS
modules bound.

Float math goes through [`util/soft_float.{h,cpp}`](../../kernel/util/soft_float.h) —
an IEEE 754 binary32 implementation in pure integer code, because
the kernel is compiled `-mno-sse -mno-sse2` and cannot link any
compiler-rt soft-float helpers. Sf32 covers Add / Sub / Mul / Div
/ Sqrt / Neg / Abs / Min / Max / Clamp / Mix / Step + comparison
+ int<->float conversion, all with NaN-unordered IEEE
semantics. 43-vector boot self-test validates the implementation.

**Opcodes the executor dispatches today:**

| Family | Opcodes |
|--------|---------|
| Memory | `OpLoad`, `OpStore`, `OpAccessChain` |
| Composite | `OpVectorShuffle`, `OpCompositeConstruct`, `OpCompositeExtract` |
| Arithmetic (int) | `OpSNegate`, `OpIAdd`, `OpISub`, `OpIMul`, `OpSDiv`, `OpUDiv` |
| Arithmetic (float) | `OpFNegate`, `OpFAdd`, `OpFSub`, `OpFMul`, `OpFDiv` |
| Vector ops | `OpVectorTimesScalar`, `OpMatrixTimesVector`, `OpDot` |
| Conversion | `OpConvertSToF`, `OpConvertUToF`, `OpConvertFToS`, `OpBitcast` |
| Comparison | `OpIEqual`, `OpINotEqual`, `OpSLessThan`, `OpFOrdLessThan` |
| Control flow | `OpBranch`, `OpBranchConditional`, `OpPhi`, `OpReturn`, `OpReturnValue`, `OpLoopMerge`, `OpSelectionMerge` |
| Extended | `OpExtInst` against `GLSL.std.450`: `Sqrt`, `Sin`, `Cos`, `Pow`, `FMin`, `FMax`, `FClamp`, `FMix`, `Step`, `Length`, `Normalize`, `Cross` |

Per-shader step budget (`kStepBudget = 8192`) caps runaway loops.

**Transcendental support:** `Sf32Sin` / `Sf32Cos` use a 7th-order
minimax polynomial after [-pi/2, pi/2] range reduction (~3e-5 max
error on the reduced range). `Sf32Exp` / `Sf32Log` use degree-5
polynomial expansions with 2^n / log2 mantissa decomposition; `Sf32Pow`
composes `exp(y * log(x))` for positive bases. The soft-float
self-test asserts each with ULP-tolerance bounds — `Sf32SelfTest`
emits `[util/soft_float] self-test PASS (55 vectors)` on clean
boot.

**Shader-rasterizer hook** (`graphics_vk_shaderraster.cpp`):

- When `vkCmdDraw` replays and a graphics pipeline with VS + FS is
  bound, `ShaderRasterizeDraw` runs the SPIR-V VS once per vertex
  to compute `gl_Position`, then for each pixel inside the
  resulting triangle runs the FS to compute the colour.
- Vertex input layout: caller-supplied `VkVertexInputAttributeDescription`
  via `VkSetVertexInputDuet` — each VS Input is fetched at the
  declared (binding, offset) tuple with the right stride. Falls
  back to a canonical 16-byte-per-Location layout when no
  description is attached.
- Fragment output: Location 0 vec4 RGBA, clamped to [0,1] and
  packed BGRA8 for the framebuffer.
- Topology: TriangleList only on the shader path; other
  topologies fall back to the fixed-function rasterizer.
- Painted-pixel cap (65k per draw) so a runaway fullscreen
  shader cannot brick the boot.

**Compute shader dispatch** (`ShaderDispatchCompute`):

- `vkCmdDispatch` replay now routes through the SPIR-V interpreter
  for compute pipelines. The parser captures
  `OpExecutionMode LocalSize x y z`; the dispatcher runs the entry
  point `group_count_xyz * local_size_xyz` times.
- Per-invocation builtins set before each execution:
  `gl_NumWorkgroups`, `gl_WorkgroupId`, `gl_LocalInvocationId`,
  `gl_GlobalInvocationId`, `gl_LocalInvocationIndex`.
- 65k-invocation cap per dispatch protects against pathological
  `dispatch(1024,1024,1024)` runs.

**Per-pixel varying interpolation** (v2):

- After the VS runs per vertex, `RunVertexShader` snapshots every
  Location-decorated Output variable into a `VaryingSnapshot[8]`
  array (up to 8 varyings, each up to 16 Sf32 components).
- `PaintTriangle` precomputes `1 / |area2|` as an Sf32 once per
  triangle; per pixel it derives barycentric weights as
  `|edge_i| * inv_area` (three Sf32 multiplies, no divides).
- For each varying, the per-pixel value = `a*w0 + b*w1 + c*w2`
  via `BaryLerp` (three multiplies + two adds per component).
- The interpolated values are written to the matching FS Input
  Location via `spirv::WriteInputLocation` before invoking the
  FS. Result: a fragment shader that reads `in vec3 color` from
  a Location varying sees a smoothly interpolated value, not
  zero.

**Perspective-correct interpolation** (v3):

- When `gl_Position.w > 0` for every triangle vertex,
  `ShaderRasterizeDraw` computes `1/w` per vertex and passes the
  triple into `PaintTriangle`.
- Per vertex, each varying value is pre-divided by `w`. Per
  pixel, both `value/w` and `1/w` are barycentric-interpolated
  linearly, then divided to recover the perspective-correct
  varying.
- Degenerate / orthographic projections (`w <= 0` or NaN) fall
  back to the affine path — no artefacts on the cases where
  perspective correction is meaningless.

**Texture sampling primitives** (v3):

- The parser recognises `OpTypeImage` / `OpTypeSampler` /
  `OpTypeSampledImage` and decorates variables with
  `DescriptorSet` / `Binding` indices.
- `OpSampledImage` (combined image+sampler), `OpImageSampleImplicitLod`,
  and `OpImageSampleExplicitLod` execute. Today they return the UV
  coordinate as `(u, v, 0, 1)` — the "missing texture" diagnostic
  pattern. A shader that samples a 2D texture now produces a
  smooth gradient instead of zero; the descriptor-set fetch path
  that replaces the fallback with real texel data lands in the
  next slice.

**Multi-format image support:**

- `VkGetPhysicalDeviceFormatProperties` / `ImageFormatProperties`
  now recognise six DuetOS-internal format ids:
  `0 = B8G8R8A8_UNORM`, `1 = R8G8B8A8_UNORM`, `2 = R8_UNORM`,
  `3 = R8G8_UNORM`, `4 = R16_UNORM`, `5 = R32G32B32A32_SFLOAT`.
  All report the baseline feature set (sampled / color
  attachment / transfer); format-aware sample + blit paths land
  with the texel-fetch slice.

**Boot self-tests:**

- `[util/soft_float] self-test PASS (43 vectors)` — soft-float
  primitives.
- `[subsys/graphics/spirv] self-test PASS (3 modules executed)` —
  three hand-crafted SPIR-V modules (constant vec4 fragment,
  Sf32 add via OpFAdd, vec3*scalar via OpVectorTimesScalar) parse
  and execute end-to-end with the expected outputs.

The shader hook is OPT-IN — it returns false (no paint) when:

- No pipeline is bound, or
- The pipeline doesn't carry interpretable VS + FS Programs, or
- The topology is anything other than TriangleList.

In all "false" cases the existing fixed-function v0/v1 rasterizer
runs, so the existing demos / DirectX clears / boot self-test see
no behavioural change.

## Userland bridge (`vulkan-1.dll` + `SYS_VK_CALL`)

The in-kernel ICD is reachable from Win32 PE binaries via
`vulkan-1.dll`, a freestanding userland PE library at
[`userland/libs/vulkan_1/vulkan_1.c`](../../userland/libs/vulkan_1/vulkan_1.c).
The DLL exports the canonical Vulkan entry-point set as thin
thunks over `SYS_VK_CALL` (syscall 211), an op-code-dispatched
syscall whose `rdi` argument selects which `VkOp` to invoke.

| Userland entry | Kernel side (SYS_VK_CALL op) |
|---|---|
| `vkCreateInstance` | `kVkOpCreateInstance` |
| `vkDestroyInstance` | `kVkOpDestroyInstance` |
| `vkEnumeratePhysicalDevices` | `kVkOpEnumeratePhysicalDevices` |
| `vkCreateDevice` | `kVkOpCreateDevice` |
| `vkDestroyDevice` | `kVkOpDestroyDevice` |
| `vkGetDeviceQueue` | `kVkOpGetDeviceQueue` |
| `vkDeviceWaitIdle` | `kVkOpDeviceWaitIdle` |
| `vkQueueWaitIdle` | `kVkOpQueueWaitIdle` |
| `vkEnumerateInstanceVersion` | `kVkOpGetInstanceVersion` |
| `vkGetInstanceProcAddr` | string -> function-pointer table |
| `vkGetDeviceProcAddr` | same table |
| `DuetOS_Vk_GetStatsCounter` | `kVkOpGetStatsCounter` (diagnostic) |
| `DuetOS_Vk_ClearFramebufferRgba` | `kVkOpClearFramebufferRgba` (end-to-end clear-the-screen — same path `vkCmdClearColorImage` takes for a scanout image) |
| `DuetOS_Vk_CreateSurface` | `kVkOpCreateSurfaceDuet` (the kernel's single platform-agnostic VkSurfaceKHR bound to the framebuffer) |
| `DuetOS_Vk_DestroySurface` | `kVkOpDestroySurface` |
| `DuetOS_Vk_Present` | `kVkOpPresent` (flushes framebuffer through the compositor present hook — equivalent to `vkQueuePresentKHR` on a single-image swapchain) |
| `vkCreateShaderModule` / `vkDestroyShaderModule` | `kVkOpCreateShaderModule` / `kVkOpDestroyShaderModule` (kernel copies the SPIR-V word stream + invokes the v1 parser; module survives until destroyed) |
| `vkAllocateMemory` / `vkFreeMemory` | `kVkOpAllocateMemory` / `kVkOpFreeMemory` (host-visible coherent memory type) |
| `vkCreateBuffer` / `vkDestroyBuffer` | `kVkOpCreateBuffer` / `kVkOpDestroyBuffer` |
| `vkBindBufferMemory` | `kVkOpBindBufferMemory` |
| `vkMapMemory` / `vkUnmapMemory` | `kVkOpMapMemory` / `kVkOpUnmapMemory` (returns the kernel's kheap-backed host pointer; userland reads / writes directly since v0 has no per-process VM gate on this surface) |
| `vkCreateImage` / `vkDestroyImage` / `vkBindImageMemory` | `kVkOpCreateImage` / `kVkOpDestroyImage` / `kVkOpBindImageMemory` (BGRA8 default format) |
| `vkCreateCommandPool` / `vkDestroyCommandPool` | `kVkOpCreateCommandPool` / `kVkOpDestroyCommandPool` |
| `vkAllocateCommandBuffers` | `kVkOpAllocateCommandBuffer` (v0 single buffer per call) |
| `vkBeginCommandBuffer` / `vkEndCommandBuffer` | `kVkOpBeginCommandBuffer` / `kVkOpEndCommandBuffer` |
| `vkCmdClearColorImage` | `kVkOpCmdClearColorImage` (packs the float-4 color into the canonical 0xAARRGGBB word; userland-side `_fltused` handles the float compare) |
| `vkQueueSubmit` | `kVkOpQueueSubmit` (v0 single command buffer per submit) |
| `vkCreatePipelineLayout` / `vkDestroyPipelineLayout` | `kVkOpCreatePipelineLayout` / `kVkOpDestroyPipelineLayout` |
| `vkCreateRenderPass` / `vkDestroyRenderPass` | `kVkOpCreateRenderPass` / `kVkOpDestroyRenderPass` |
| `vkCreateGraphicsPipelines` | `kVkOpCreateGraphicsPipeline` (extracts VS / FS shader modules from `pStages` by hand) |
| `vkCreateComputePipelines` | `kVkOpCreateComputePipeline` |
| `vkDestroyPipeline` | `kVkOpDestroyPipeline` |
| `vkCmdBindPipeline` / `vkCmdDraw` / `vkCmdDispatch` | `kVkOpCmdBindPipeline` / `kVkOpCmdDraw` / `kVkOpCmdDispatch` |
| `vkCmdBindVertexBuffers` / `vkCmdBindIndexBuffer` | `kVkOpCmdBindVertexBuffer` / `kVkOpCmdBindIndexBuffer` (v0 single-binding form) |
| `vkUpdateDescriptorSets` | `kVkOpUpdateDescriptorSet` (walks the writeCount array, one syscall per entry; extracts the image-view handle from each VkDescriptorImageInfo) |
| `vkCreateDescriptorSetLayout` / `vkDestroyDescriptorSetLayout` | `kVkOpCreateDescriptorSetLayout` / `kVkOpDestroyDescriptorSetLayout` (single binding-0 CombinedImageSampler in v0) |
| `vkCreateDescriptorPool` / `vkDestroyDescriptorPool` | `kVkOpCreateDescriptorPool` / `kVkOpDestroyDescriptorPool` |
| `vkAllocateDescriptorSets` | `kVkOpAllocateDescriptorSet` (v0 single set per call) |
| `vkCmdBindDescriptorSets` | `kVkOpCmdBindDescriptorSet` (v0 single set per bind) |

`SYS_VK_CALL` plus `VkOp` / `VkStatsCounter` enums are in
[`kernel/syscall/syscall.h`](../../kernel/syscall/syscall.h);
the dispatch lives in
[`kernel/syscall/syscall_vk.cpp`](../../kernel/syscall/syscall_vk.cpp).
One syscall + an op-code-dispatch keeps the syscall number space
sane while preserving a stable per-op ABI value — once published,
neither the syscall number nor the op-code may move.

What a Vulkan-using Win32 PE can do today: load the DLL, resolve
exports, walk the lifecycle (`vkCreateInstance` -> enumerate ->
`vkCreateDevice` -> `vkGetDeviceQueue` -> wait/destroy), and
read any of the 10 diagnostic stats counters. Buffer / image /
memory creation, command-buffer record + submit, shader module
create, and WSI surface / swapchain are deferred to the next
op-code expansion — those need shared-memory marshalling that
the v0 syscall surface doesn't provide.

## Known Limits / GAPs

- **No real GPU submission.** Every device-side command is replayed
  on the CPU; the visible effects are `Clear`, resource copies,
  the CPU triangle rasterizer for `vkCmdDraw` / `vkCmdDrawIndexed`
  (TriangleList / TriangleStrip / TriangleFan; Gouraud-shaded with
  per-pixel src-over alpha; software Z-test when v1 vertex format
  is selected), AND the SPIR-V shader rasterizer when a pipeline
  binds parseable VS + FS modules (TriangleList only).
- **SPIR-V texture sampling.** `OpImageSampleImplicitLod` /
  `OpImageSampleExplicitLod` are implemented and fetch through the
  bound (set 0, binding 0) sampled-image descriptor via
  `SampleImageRgba8`. The addressing mode is now driven by the
  VkSampler the caller pinned at descriptor-update time —
  `VkCreateSampler` records `addressModeU` into a per-handle
  `SamplerRecord`, `VkUpdateDescriptorSetSampled` propagates the
  VkSampler handle alongside the VkImageView, and the executor
  reads `SamplerAddressModeFor(handle)` on every sample to pick
  REPEAT / CLAMP_TO_EDGE / MIRRORED_REPEAT / CLAMP_TO_BORDER
  before walking the bilerp. v0's CLAMP_TO_BORDER border colour
  is always transparent black (0,0,0,0); per-sampler border tints
  land when `VkSamplerCreateInfo` grows a `borderColor` field.
  Unbound samples still return the UV coordinate as
  `(u, v, 0, 1)` — the "missing texture" diagnostic. Per-axis
  decoupling (different modes for U / V / W) is recorded by
  `SamplerRecord` but the executor only honours U today — same-
  axis-everywhere works correctly; an axis split would need the
  bilerp to thread the mode per fold. `OpImageRead` /
  `OpImageWrite` (storage-image compute access) and explicit LOD
  (no mipmap chain) are still unimplemented.
- **SPIR-V perspective correction.** The shader rasterizer is
  affine (linear pixel-space interpolation in pixel space).
  Perspective-correct attribute interpolation needs a per-fragment
  1/w divide which the v2 hook doesn't perform.
- **Vertex input descriptions.** The shader hook uses a canonical
  16-byte-per-Location layout instead of consuming the caller's
  `VkVertexInputAttributeDescription` / `VkVertexInputBindingDescription`.
  A caller whose vertex layout differs gets garbage values fed
  into the VS Input variables.
- **Userland buffer / image / submit.** `SYS_VK_CALL` v0 only
  covers the lifecycle subset. Buffer / image / memory / command-
  buffer / swapchain ops return `VK_ERROR_INITIALIZATION_FAILED`
  to userland callers until the next op-code expansion adds
  shared-memory marshalling.
- **Single queue family.** No async compute, no transfer queue
  separation.
- **No swapchain resize.** Recreating the swapchain is supported;
  resizing the underlying framebuffer is not.
- **No multi-monitor.** Single scanout.
- **D3D9 / DirectDraw** Vulkan-side support stubs only — those D3D
  libraries are wired but don't yet route their Clear/Present
  through the Vulkan path; they hit the framebuffer directly.

## Related Pages

- [DirectX](DirectX.md) — D3D translation that builds on this ICD
- [Graphics Drivers](../drivers/Graphics-Drivers.md) — per-vendor GPU
  drivers that will eventually consume real Vulkan submits
- [Compositor and Window Manager](Compositor.md) — what consumes
  `vkQueuePresentKHR`
- [Subsystem Isolation](../kernel/Subsystem-Isolation.md) — why the ICD
  is in the kernel
- [Win32 DLLs](Win32-DLLs.md) — `vulkan-1.dll`, `dxgi.dll`
- [Win32 Surface Status](../reference/Win32-Surface-Status.md) — per-export
  REAL / STUB / MISSING inventory
- [GPU Implementation Notes](../reference/GPU-Implementation-Notes.md) —
  cross-vendor prior-art for the per-vendor submission path,
  SPIR-V sampler / texel-fetch math, and the DXBC→SPIR-V plan
