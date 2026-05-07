# Graphics Drivers

> **Audience:** Driver authors, compositor authors
>
> **Execution context:** Kernel — IRQ + process; pixel ops in compositor pass
>
> **Maturity:** virtio-gpu v0 scanout; Intel/AMD/NVIDIA discovery only;
> Vulkan ICD v0 (CPU-side lifecycle, command tape replay, scanout-backed clears)

## Overview

The DuetOS graphics stack:

```
[ App pixel ops ]                  user32/gdi32 -> SYS_WIN_*/SYS_GDI_*
        |
[ Kernel compositor + WM ]         kernel/drivers/video/
        |
[ Framebuffer / scanout ]
        |
[ GPU driver ]                     kernel/drivers/gpu/{virtio-gpu, intel, amd, nvidia}/
```

The compositor is in-kernel for hot-path latency. Userland reaches it
through `SYS_WIN_*` (window lifecycle) and `SYS_GDI_*` (pixel
primitives). See [Compositor and Window Manager](../subsystems/Compositor.md).

## virtio-gpu v0

`kernel/drivers/gpu/virtio-gpu/` (referenced from
`kernel/drivers/video/`).

- Establishes the virtio device, maps the framebuffer scanout
  resource.
- 2D scanout cycle: write pixels, request a `RESOURCE_FLUSH`, present.
- Used as the default GPU for QEMU smoke tests
  (`-vga virtio` / `-display sdl,gl=on`).

The compositor presents through this scanout: `WindowCompose`
collects per-window dirty rectangles, paints them into the
framebuffer-backed back buffer, and a `RESOURCE_FLUSH` IOCTL marks
the rectangle as the current scanout image. EDID parsing, CVT
timing, and CEA-861 extension blocks are decoded but mode-set
negotiation against a vendor-specific GPU driver is roadmap work.

## GPU Discovery

`kernel/drivers/gpu/` walks the PCI device list at boot:

- Identifies Intel iGPU (Gen9+ recognised), AMD Radeon (GFX9+
  recognised), NVIDIA (Turing+ recognised).
- Maps BARs (deferred MMIO probe).
- Records the device for future driver bringup.

## Discrete GPU driver scaffolds

Each tier-1 vendor now has a dedicated driver TU under
`kernel/drivers/gpu/`:

- `intel_gpu.{h,cpp}` — Gen9..Gen13 register map, RCS ring scaffold
  at MMIO 0x2000.
- `amd_gpu.{h,cpp}` — GFX9+ scaffold; opportunistically maps BAR5
  (the register file lives there, not at BAR0 like Intel) and
  reads `mmGRBM_STATUS` / `mmRLC_GPM_STAT`.
- `nvidia_gpu.{h,cpp}` — Turing+ scaffold; reads `PMC_BOOT_0`,
  `PMC_INTR_EN_0`, `PFIFO_INTR`, and `PFB_PRI_RD` for diagnostics.

Each driver exposes:

- `Probe(GpuInfo&)` — pure observation: register reads stored in
  the per-controller `GpuInfo` record. Called by
  `gpu::RunVendorProbe` after BAR0 is mapped.
- `Bringup(GpuInfo&)` — allocates a 4 KiB DMA-coherent ring/
  pushbuffer, logs the would-be ring program, frees the buffer,
  and returns `Unsupported`. The skeleton stays gated until the
  vendor-specific firmware loaders (Intel GuC/HuC, AMD MEC/RLC,
  NVIDIA GSP) land. The dispatch surface is in place so
  follow-up slices flip a known set of register pokes rather
  than re-derive the bring-up shape.
- `IsBroughtUp()` — diagnostic accessor.

`gpu.cpp` no longer hosts vendor-specific register pokes; it
dispatches into the per-vendor TUs and only retains
`NvidiaArchName` (used by the cross-vendor diagnostic line).

## Compositor Primitives

The compositor exposes:

- `FramebufferPutPixel`, `FramebufferFillRect`, `FillRgba`
- `DrawLine`, `DrawCircle`, `DrawRoundRectOutline`,
  `DrawDropShadow`
- Window-chrome primitives (titlebar gradient, X-glyph close,
  taskbar gradient)

These are the same primitives the DirectX v0 DLLs (`d3d9` / `d3d11` /
`d3d12` / `dxgi`) call into when an MSVC PE goes
`D3D11CreateDeviceAndSwapChain -> ClearRenderTargetView -> Present`.

See [DirectX v0 Path](../subsystems/DirectX.md).

## Damage tracking + present pipeline

`kernel/drivers/video/framebuffer.{h,cpp}` accumulates a
single-bbox **damage rect** as primitives write pixels. The
compose-end blit copies only the damage union from the shadow
surface to the live framebuffer; `FramebufferPresent` hands the
same rect to the registered present hook so a backend can flush
only the changed region.

- **Direct backends** (firmware passthrough, Bochs VBE) — present
  hook is null; pixels are already on screen as soon as the shadow
  blit copies them. The damage rect still bounds the blit, so a
  cursor-blink frame on a 1920×1080 surface costs ~256 px instead
  of 2 megapixels.
- **virtio-gpu** — present hook calls `VirtioGpuFlushScanout(x, y,
  w, h)` with the damage rect, which runs `TRANSFER_TO_HOST_2D` +
  `RESOURCE_FLUSH` on just that subrect. A frame with no draws
  (`damage.valid == false`) skips the round-trip entirely; the
  host repaints from its prior scanout cache.

After every `FramebufferPresent` call the damage union is reset.
Callers that paint straight into the framebuffer behind the
primitive API (rare: virtio-gpu's boot test pattern is the only
one today) can call `FramebufferAddDamage(x, y, w, h)` to cover
their writes for the next present.

`FramebufferReadDamage()` snapshots the current union without
clearing it — used by tests + diagnostics.

## Render statistics

`kernel/drivers/video/render_stats.{h,cpp}` accumulates per-frame
counters that the `gfx` shell command surfaces:

- `frames_composed` / `frames_presented` — totals.
- `frames_clean` — present passes that skipped the flush because
  the compositor wrote nothing.
- `frames_full` / `frames_partial` — split by ≥95% surface
  coverage. Heavy chrome frames (full window redraw) land in
  "full"; cursor / clock / hover frames in "partial".
- `dirty_pixels_total` / `surface_pixels_total` — per-mille
  ratio is the average dirty fraction.
- `last_damage_*` — the most recently presented damage rect,
  for diagnosis.

Only the compose-end and present-end paths bump counters, never
the per-pixel inner loops, so the per-frame cost is constant.

## Display info aggregator

`kernel/drivers/video/display_info.{h,cpp}` exposes a single
`Query()` that bundles framebuffer geometry, owning GPU
identification (vendor / family / tier / arch / BAR0), and
present-backend classification (`direct` / `virtio-gpu` /
`none`) into one struct. Used by the `gfx` shell command and
by the Vulkan ICD's `vkGetPhysicalDeviceProperties` /
`vkGetPhysicalDeviceMemoryProperties` queries (it's the
source of truth for vendorID, deviceName, framebuffer-sized
DEVICE_LOCAL heap, and `maxFramebuffer*` limits).

## Vulkan ICD (v0)

`kernel/subsystems/graphics/{graphics.h, graphics.cpp,
graphics_vk.cpp}` implements a CPU-side Vulkan 1.3 ICD subset.
Lifecycle calls succeed (no more `ErrorIncompatibleDriver`
sentinels); per-kind handle pools track live counts; the boot
self-test (`GraphicsIcdSelfTest`) drives the canonical
Instance → Device → Pipeline → CommandBuffer → Submit → Destroy
flow and asserts every pool returns to zero.

Implemented:

- Instance / PhysicalDevice / Device / Queue lifecycle.
- `vkGetPhysicalDeviceProperties` / `Features` /
  `MemoryProperties` / `QueueFamilyProperties` — properties
  sourced from `display_info::Query()` (vendor ID from PCI
  vendor name, device name composed as
  `DuetOS-vk-<vendor>-<family>`, framebuffer-sized
  DEVICE_LOCAL heap, 16 MiB HOST_VISIBLE+COHERENT heap).
- Instance / Device extension + layer enumeration (zero count
  — no extensions yet).
- `vkAllocateMemory` / `vkFreeMemory`, `vkCreateBuffer` /
  `vkBindBufferMemory`, `vkCreateImage` / `vkBindImageMemory`,
  `vkCreateImageView`. Host-visible memory is backed by
  kheap so `vkMapMemory` returns a real pointer the caller
  can read/write; `vkFlushMappedMemoryRanges` and
  `vkInvalidateMappedMemoryRanges` are no-ops because memory
  type 1 advertises HOST_COHERENT.
- `vkCreateRenderPass` / `vkCreateFramebuffer`.
- `vkCreateShaderModule` validates the SPIR-V magic word
  `0x07230203` (LE) and rejects with `ErrorInvalidShaderNV`.
  A v1 header walker then runs across every accepted blob and
  aggregates entry-point / capability / execution-mode /
  decoration counts; the result hangs off `VkGetShaderModuleInfoDuet`
  (DuetOS-only diagnostic accessor — non-spec).  The bytecode
  itself is still not executed.
- `vkCreatePipelineLayout`, `vkCreateGraphicsPipeline`,
  `vkCreateComputePipeline`.
- `vkCreateCommandPool`, `vkAllocateCommandBuffers`,
  `vkBeginCommandBuffer` / `vkEndCommandBuffer` /
  `vkResetCommandBuffer`.
- Recording: `vkCmdBeginRenderPass`, `vkCmdEndRenderPass`,
  `vkCmdBindPipeline`, `vkCmdClearColorImage`, `vkCmdDraw`,
  `vkCmdDrawIndexed`, `vkCmdSetViewport`, `vkCmdSetScissor`,
  `vkCmdBindVertexBuffers`, `vkCmdBindIndexBuffer`,
  `vkCmdCopyBuffer`, `vkCmdFillBuffer`, `vkCmdPipelineBarrier`,
  `vkCmdPushConstants`, `vkCmdDispatch`,
  `vkCmdCopyBufferToImage`, `vkCmdSetEvent`,
  `vkCmdResetEvent`, `vkCmdWaitEvents`, `vkCmdBeginQuery`,
  `vkCmdEndQuery`, `vkCmdResetQueryPool`,
  `vkCmdWriteTimestamp`, `vkCmdBindDescriptorSets`. Each
  opcode is appended to the command buffer's tape (32 ops
  max). `vkResetCommandPool` resets every cb in the pool back
  to Initial.
- `vkQueueSubmit` walks the tape:
  * `vkCmdClearColorImage` and `vkCmdBeginRenderPass` clears
    against scanout-backed images forward to
    `FramebufferFillRect` + `FramebufferAddDamage`.
  * `vkCmdCopyBuffer` / `vkCmdFillBuffer` move bytes between
    host-visible buffer-bound memory ranges (real
    propagation, asserted by the self-test).
  * `vkCmdCopyBufferToImage` against a scanout-backed image
    runs through `FramebufferBlit` — a real texture-upload
    path that turns a host-visible buffer of pixels into
    framebuffer pixels.
  * `vkCmdSetEvent` / `vkCmdResetEvent` flip the device-
    visible event bit.
  * `vkCmdWriteTimestamp` writes the kernel monotonic clock
    (ns) into the query pool slot.
  * `vkCmdEndQuery` writes a monotonic counter into the
    query pool slot (occlusion queries get ordering, not
    pixel counts — no rasterizer to sample).
  Other opcodes are recorded for stats but produce no
  visible output (no SPIR-V execution yet).
- `vkCreateFence` / `vkWaitForFences` (always immediately
  signalled — submits are synchronous in this ICD),
  `vkCreateSemaphore`.
- Descriptor sets: `vkCreateDescriptorSetLayout`,
  `vkCreateDescriptorPool` (with `max_sets` budget enforcement),
  `vkAllocateDescriptorSets`, `vkUpdateDescriptorSet` (DuetOS
  one-binding-at-a-time variant of `vkUpdateDescriptorSets`),
  `vkCmdBindDescriptorSets`, `vkFreeDescriptorSets`,
  `vkResetDescriptorPool`.  Sets carry no resource state for
  shaders to consume; the surface exists so a downstream
  caller (DXVK, native compute) finds the full ladder today.
- Loader plumbing: `vkEnumerateInstanceVersion`,
  `vkGetInstanceProcAddr`, `vkGetDeviceProcAddr` (returns
  opaque token, 0 for unknown / instance-only-from-device).
- Vulkan 1.1 / 1.2 -shaped `Properties2` / `Features2` /
  `MemoryProperties2` accept a pNext chain (ignored — no
  extensions advertised) so a hosted SDK caller's setup runs.
- `vkGetBufferMemoryRequirements` /
  `vkGetImageMemoryRequirements` /
  `vkGetDeviceMemoryCommitment` /
  `vkGetBufferDeviceAddress` (returns the kheap pointer).
- VK_KHR_dynamic_rendering: `vkCmdBeginRendering` /
  `vkCmdEndRendering` — same scanout-clear path as
  `vkCmdBeginRenderPass` for the attachment image.
- Dynamic state setters: `vkCmdSetLineWidth`,
  `vkCmdSetDepthBias`, `vkCmdSetBlendConstants`,
  `vkCmdSetDepthBounds`, `vkCmdSetStencil{Compare,Write}Mask`,
  `vkCmdSetStencilReference` — recorded only.
- VK_EXT_debug_utils: `vkSetDebugUtilsObjectNameEXT` attaches
  a label to any handle; `VkGetDebugUtilsObjectNameDuet`
  reads it back.  Small fixed-size table (16 most recent).
- Image transfer suite: `vkCmdCopyImage`, `vkCmdBlitImage`,
  `vkCmdCopyImageToBuffer`, `vkCmdResolveImage`,
  `vkCmdUpdateBuffer` (real bytes when buffer host-visible),
  `vkCmdClearAttachments`, `vkCmdClearDepthStencilImage`.
- Sampler / Event / PipelineCache / QueryPool: full
  create/destroy + supporting entry points. Pipeline cache
  hands back a 32-byte VkPipelineCacheHeaderVersionOne-shaped
  blob via `vkGetPipelineCacheData` so a caller's "round-trip
  the cache to disk" path works. Query pools support
  occlusion + timestamp; `vkCmdWriteTimestamp` writes the
  kernel monotonic clock; `vkGetQueryPoolResults` returns
  `NotReady` for slots that haven't been written.
- WSI: `VkCreateDuetSurfaceKHR` (single platform-agnostic
  surface bound to the kernel framebuffer),
  `VkGetPhysicalDeviceSurfaceCapabilitiesKHR` /
  `SurfaceFormatsKHR` / `SurfacePresentModesKHR`,
  `vkCreateSwapchainKHR` (allocates 2-4 scanout-backed
  images), `vkGetSwapchainImagesKHR`,
  `vkAcquireNextImageKHR` (rotates the cursor),
  `vkQueuePresentKHR` (validates the index and calls
  `FramebufferPresent` so the compositor flushes the damage
  rect).  Only `Fifo` present mode + `B8G8R8A8_UNORM`
  format are advertised.

Out of scope — deferred:

- Real GPU command-ring submission (blocks on per-vendor
  driver bring-up: Intel GuC/HuC, AMD MEC/RLC, NVIDIA GSP).
- SPIR-V execution / shader translation.
- Descriptor sets, descriptor pools.
- Swapchain, surface, WSI (`vkAcquireNextImageKHR`,
  `vkQueuePresentKHR`).
- Multi-queue, cross-queue sync that actually blocks.
- `vkCmdBeginRenderPass` clear-attachment painting (needs
  framebuffer → image-view back-mapping).

The `gfx` shell command surfaces every per-kind `*_live`
counter plus submit / record / replay totals plus the SPIR-V
validator's rejection count.

## Themes

`kernel/drivers/video/theme.cpp` is a flat token table the window
registry, taskbar, console, and cursor backing all sample on every
recompose. Four themes ship:

- **Classic** — teal / slate-blue (the original)
- **Slate10** — Win10 x Unreal Slate hybrid
- **Amber** — single-hue retro-CRT tribute
- **Duet** — slate-charcoal with two accents (teal for native
  DuetOS, amber for Win32 PE / document apps)

`Ctrl+Alt+Y` cycles themes. See
[Duet Theme Spec](../specifications/Duet-Theme-Spec.md).

## Known Limits / GAPs

- **No real Intel/AMD/NVIDIA driver beyond discovery.** virtio-gpu is
  the only path that produces pixels today.
- **No GPU command queue.** Submission is direct register writes for
  virtio-gpu's tiny command set; a real GPU driver will need a
  proper queue.
- **Vulkan ICD does not execute shaders.** SPIR-V blobs are
  validated (magic-word check) + parsed (entry-point /
  capability / decoration counts), but the bytecode is not
  executed. `vkCmdDraw` is recorded for stats but produces
  no pixels.
- **Damage tracking is single-bbox.** A frame that touches the
  top-left and bottom-right corners flushes the whole surface. A
  list-of-rects damage tracker would help for chrome-heavy frames
  with non-contiguous writes (e.g. caret blink + clock tick on
  opposite ends of the taskbar).

## Related Pages

- [Driver Overview](Driver-Overview.md)
- [Compositor and Window Manager](../subsystems/Compositor.md)
- [DirectX v0 Path](../subsystems/DirectX.md)
- [Duet Theme Spec](../specifications/Duet-Theme-Spec.md)
