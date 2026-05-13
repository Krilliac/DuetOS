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
| `vkCmdBindPipeline`, `vkCmdBindDescriptorSets`, `vkCmdBindVertexBuffers`, `vkCmdBindIndexBuffer` | Update tape-local "current state" only. |
| `vkCmdDraw`, `vkCmdDrawIndexed`, `vkCmdDispatch` | Bump a counter. No pixels move. |
| `vkCmdCopyBuffer`, `vkCmdCopyImage`, `vkCmdCopyBufferToImage` | Real `memcpy` between mapped backing buffers. |
| `vkCmdPipelineBarrier`, `vkCmdSetViewport`, `vkCmdSetScissor` | No-op (state recorded, not enforced). |

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
  on the CPU; the only visible effect is `Clear` (and resource
  copies).
- **No SPIR-V execution.** Shader modules are parsed (entry points
  enumerated, descriptor bindings counted) but not run.
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
