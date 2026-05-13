# Vulkan ICD (In-Kernel)

> **Audience:** Graphics subsystem authors, DirectX-translation contributors
>
> **Execution context:** Kernel — currently CPU-side only; no real GPU
> submission in v0
>
> **Maturity:** v0 — instance / device / queue / command-buffer lifecycle
> + clear-to-scanout path; everything else recorded but inert

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
| [`graphics_vk_selftest.cpp`](../../kernel/subsystems/graphics/graphics_vk_selftest.cpp) | Boot self-test |
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

## Software triangle rasterizer

`graphics_vk_raster.cpp` adds a CPU edge-function rasterizer that
turns `vkCmdDraw` into visible pixels when the caller fills its
vertex buffer with the DuetOS v0 fixed vertex format and points
the draw at a scanout-backed render target. There is no SPIR-V
execution, no vertex transform, and no per-fragment shading —
positions are already in pixel space and the triangle is
flat-shaded with the colour of its first vertex.

**Vertex format (8 bytes per vertex):**

| Bytes | Field | Meaning |
|-------|-------|---------|
| 0..1  | `i16 x_px` | Signed framebuffer pixel x |
| 2..3  | `i16 y_px` | Signed framebuffer pixel y |
| 4..7  | `u32 argb` | 0xAARRGGBB; alpha is recorded but not blended in v0 |

Three consecutive vertices form one triangle (TriangleList only —
no strip topology, no indexed draw). The replay walker:

1. Tracks the most-recent `BindVertexBuffer(binding=0)` and the
   active render-target image (set by `BeginRenderPass`,
   `BeginRendering`, or `ClearColorImage` as a fallback).
2. On `Draw`: hands `(render_target, vb, vb_offset, first_vertex,
   vertex_count)` to `internal::RasterizeDuetTriangles`.
3. The rasterizer bumps `vk_triangles_drawn += vertex_count / 3`
   immediately so the dispatch chain is observable even when no
   pixels are produced (non-scanout target, no live framebuffer,
   non-host-visible vertex buffer).
4. When the render target IS scanout-backed and the vertex
   buffer IS host-visible, every covered pixel goes through
   `FramebufferPutPixel`; the per-triangle bounding box widens
   the damage rect for the next `vkQueuePresentKHR`.

Algorithm: integer edge-function (barycentric) test over the
triangle's bounding box. A pixel is inside when all three edge
functions share a sign consistent with the triangle's signed
area; the loop walks the bounding box clipped to
`min(image_extent, framebuffer_dimensions)`. Degenerate
(zero-area) triangles are skipped.

Out of scope — deferred:

- Strip / fan topologies (only TriangleList today).
- Indexed draws (`vkCmdDrawIndexed` is recorded; the index
  fetch path doesn't exist yet).
- Per-vertex colour interpolation; v0 is flat-shaded with
  vertex 0's colour.
- Z-buffering / depth testing — there's no depth attachment.
- Alpha blending — the high byte of `argb` is recorded but
  ignored.
- Viewport / scissor enforcement at raster time (clip is the
  intersection of the render-target extent and the framebuffer
  surface).

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
   submits via `vkQueueSubmit`. Today only `Clear` produces pixels.
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

## Known Limits / GAPs

- **No real GPU submission.** Every device-side command is replayed
  on the CPU; the visible effects are `Clear`, resource copies, and
  the CPU triangle rasterizer for `vkCmdDraw` (DuetOS v0 vertex
  format, scanout-backed targets, TriangleList topology only).
- **No SPIR-V execution.** Shader modules are parsed (entry points
  enumerated, descriptor bindings counted) but not run. The
  triangle rasterizer is fixed-function — flat-shaded, no per-vertex
  attribute interpolation, no depth.
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
