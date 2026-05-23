# Graphics Drivers

> **Audience:** Driver authors, compositor authors
>
> **Execution context:** Kernel — IRQ + process; pixel ops in compositor pass
>
> **Maturity:** virtio-gpu v0 scanout; Intel Render Command Streamer
> ring bring-up wired (MI_NOOP submission proven); AMD CP_RB0
> register file programmed + read-back verified (firmware push is
> the next gate); NVIDIA Turing+ diagnostic probe + GSP firmware
> probe wired (PFIFO submission is gated on the multi-month GSP
> RPC slice); Vulkan ICD v0 (CPU-side lifecycle, command tape
> replay, scanout-backed clears)

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

- `intel_gpu.{h,cpp}` — Gen9..Gen13 register map and **live RCS
  bring-up** at MMIO 0x2000. `Bringup` allocates a 4 KiB DMA-
  coherent ring in Zone::Dma32, programs
  `RCS_CTL=0 → RCS_TAIL=0 → RCS_HEAD=0 → RCS_START=ring.phys →
  RCS_CTL=length|enable`, walks `RCS_TAIL` past 64 `MI_NOOP`
  instructions, then bounded-polls `RCS_HEAD` (100 ms wall-clock
  OR 1 Mi iterations, whichever first) until head catches tail.
  On success the ring buffer is retained for the lifetime of the
  boot and `[gpu/intel/rcs] ring online …` is emitted. On
  timeout the ring is disabled (CTL←0), a `kGpuRingBringupFail`
  probe fires with the last-seen `RCS_HEAD`, the buffer is freed,
  and one `KLOG_WARN` summarises the failure. `IntelRcsRingSelfTest`
  hooked to `DUETOS_BOOT_SELFTEST` emits a structural sentinel —
  `[gpu/intel/rcs] selftest PASS …`, `selftest FAIL …`, or
  `no Intel device — skipped` — that CI greps for. QEMU's
  emulated `-vga std` / `-vga virtio` boots take the "skipped"
  path (vendor IDs 0x1234 / 0x1AF4, not Intel's 0x8086).
- `amd_gpu.{h,cpp}` — GFX9+ driver that opportunistically maps
  BAR5 (the register file lives there, not at BAR0 like Intel),
  reads `mmGRBM_STATUS` / `mmRLC_GPM_STAT`, probes the
  firmware-loader for the six standard AMD GFX microcode blobs
  (`gfx_pfp.bin` / `gfx_me.bin` / `gfx_ce.bin` / `gfx_mec.bin` /
  `gfx_rlc.bin` / `sdma.bin` under the open-firmware path
  policy), and on `Bringup` allocates a 4 KiB DMA-coherent CP
  ring buffer (Zone::Dma32) + programs `mmCP_RB0_BASE` /
  `mmCP_RB0_BASE_HI` / `mmCP_RB0_CNTL` (encoded as
  `log2(ring_dwords)-1` | `block-size` | `RPTR_WR_ENA`). Each
  register is read back; a readback mismatch fires
  `kGpuRingBringupFail` (carrying a packed which-register-
  mismatched bitmap as `value`), drops a `KLOG_WARN`, frees the
  buffer, and disables the ring. On success the ring buffer is
  retained for the lifetime of the boot but the CP itself stays
  inert — without a MEC/PFP/ME firmware push the engine can't
  fetch a single PM4 packet. `AmdCpRingSelfTest` hooked to
  `DUETOS_BOOT_SELFTEST` emits the structural sentinel CI greps
  for — `selftest PASS (registers programmed, firmware-pending)`,
  `selftest FAIL`, or `no AMD device — skipped`. QEMU's emulated
  `-vga std` / `-vga virtio` boots take the "skipped" path.
- `nvidia_gpu.{h,cpp}` — Turing+ scaffold. `Probe` reads
  `PMC_BOOT_0` / `PMC_BOOT_42` / `PMC_BOOT_8` (chip /
  SKU / stepping), `PMC_INTR_EN_0` / `PFIFO_INTR` /
  `PBUS_INTR_0` (engine + bus liveness), and `PFB_PRI_RD`
  (memory-subsystem decode), then walks the firmware-loader for
  the three standard GSP blobs (`gsp_rm.bin` / `gsp_log.bin` /
  `bootloader.bin` under the open-firmware path policy). Pure
  observation — not a single register is written, because
  unlike Intel (no firmware needed for `MI_NOOP`) and AMD (a few
  configuration writes are safe without microcode) NVIDIA
  Turing+ requires the GSP RPC ring alive before any host-side
  write to a PFIFO / PGRAPH register is safe. `Bringup` stays
  scaffold/`Unsupported` for the same reason — the smallest
  meaningful bring-up step is the GSP firmware push + RPC
  channel, and that is multi-month work whose RPC schema has no
  public documentation. `NvidiaGspSelfTest` hooked to
  `DUETOS_BOOT_SELFTEST` emits the structural sentinel CI greps
  for — `selftest PASS (device present, GSP RPC gated)`,
  `selftest FAIL (BAR0 decode failed)`, or `no NVIDIA device —
  skipped`. QEMU's emulated `-vga std` / `-vga virtio` boots
  take the "skipped" path.

Each driver exposes:

- `Probe(GpuInfo&)` — pure observation: register reads stored in
  the per-controller `GpuInfo` record. Called by
  `gpu::RunVendorProbe` after BAR0 is mapped.
- `Bringup(GpuInfo&)` — vendor-specific:
  * **Intel** walks `MI_NOOP`s through the Render Command Streamer
    and waits for HEAD to catch TAIL (the engine executes natively
    without firmware — see the `intel_gpu` bullet above).
  * **AMD** programs `CP_RB0_BASE` / `_BASE_HI` / `_CNTL` and
    read-back-verifies the writes (see the `amd_gpu` bullet
    above). The CP itself stays inert until microcode is pushed;
    submission-style verification needs the MEC/PFP/ME firmware
    loader, which is the next gate.
  * **NVIDIA** still logs the would-be ring program, frees the
    buffer, and returns `Unsupported` — Turing+ GSP push is a
    multi-week effort that has not started.
- `IsBroughtUp()` — diagnostic accessor.

`gpu.cpp` no longer hosts vendor-specific register pokes; it
dispatches into the per-vendor TUs and only retains
`NvidiaArchName` (used by the cross-vendor diagnostic line).

### Intel GSC firmware-image parser

`intel_gsc_fw.{h,cpp}` is a freestanding, clean-room parser for
the Intel Graphics System Controller (GSC) firmware-image
format used by Intel discrete GPUs (DG2 / Arc / Alchemist /
Battlemage) and recent integrated parts (Meteor Lake / Lunar
Lake). The format is the publicly-documented Flash Partition
Table (FPT) layout — a 32-byte `$FPT` header followed by an
array of 32-byte partition entries — that
[`intel/igsc`](https://github.com/intel/igsc) consumes when
pushing firmware updates to the GSC over MEI.

DuetOS does not yet ship an MEI driver, so we cannot push an
update. The parser is wired into `intel::Probe()` purely as a
diagnostic: if the operator drops a firmware image at
`/lib/firmware/duetos/open/intel-gsc/gsc.bin` (preferred) or
`/lib/firmware/intel-gsc/gsc.bin` (vendor namespace), the boot
log records:

- which partitions the image declares (`FTPR` / `OPRO` /
  `OPRC` / `IAFW` / `MDMV` / `GLUT` / `MFTP` / `DLMP` /
  `FPFS` / `PMCP`)
- the FITC version dwords
- whether a 16-byte ROM-bypass prelude precedes the marker
  (older Intel ME images) or not (modern GSC)
- a manufacturing-flag bitset that warns if `MFTP` / `DLMP`
  is present (test-only partitions; should not deploy)

The parser is fully covered by `IntelGscFwSelfTest`, which
runs at boot alongside the iwlwifi / Realtek / Broadcom
firmware-format self-tests. Bad-marker, oversized
`num_entries`, entry-array-overflow, single-bogus-span, and
manufacturing-flag-detection cases are all asserted.

When the MEI subsystem lands, this parser becomes the
front-end of the GSC update path: per-partition manifest
validation (CPD/SHA-256 hash chain) plugs in at the same call
site, then the updater walks each partition payload over the
MEI HECI channel.

The PCI-side scaffold has landed in
`kernel/drivers/mei/mei.{h,cpp}`. It probes every Intel device
matching `(class=0x07 / subclass=0x80)` at boot, classifies the
device-ID into CSME / GSC / TXE / SPS roles, and maps BAR0 as
MMIO so a future driver can reach H_CSR / ME_CSR without
re-running the size probe. The `mei` shell command surfaces the
inventory. What's still needed to flip the GSC update path on:
the HECI bus protocol (H2M/M2H handshake, version negotiation,
per-client multiplexing).

`intel::Probe()` also looks up `guc.bin` and `huc.bin` under the
firmware loader's open-firmware path policy — every Gen9+ GPU
needs both blobs to bring up the command rings. The lookups are
advisory today (no ring submission) and feed the existing
`fwtrace show` ring.

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
**single-bbox damage union** as primitives write pixels — every
pixel-write routes through `MarkDamage` which calls
`DamageRect::Extend` (the union math is shared with the host unit
test in `tests/host/test_damage_rect.cpp` via `constexpr`). The
compose-end blit copies only that union from the shadow surface to
the live framebuffer.

**At present time the union is promoted to a disjoint-rect list
when spatially-separated changes are detected.** `FramebufferEndCompose`
runs the content diff over the union; when it finds that the actual
changed pixels split into spatially-separated regions, it populates
`g_damage_rects[]` (count → `g_damage_rect_count`). `FramebufferPresent`
then takes the banded path: when `g_damage_rect_count > 0` it walks
the list and fires the registered present hook once per disjoint
rect; when the count is 0 it falls back to firing the hook once with
the bbox union. A frame with nothing painted (`damage.valid == false`)
short-circuits the hook entirely.

- **Direct backends** (firmware passthrough, Bochs VBE) — present
  hook is null; pixels are already on screen as soon as the shadow
  blit copies them. The damage rect still bounds the blit, so a
  cursor-blink frame on a 1920×1080 surface costs ~256 px instead
  of 2 megapixels.
- **virtio-gpu** — present hook calls `VirtioGpuFlushScanout(x, y,
  w, h)` with the damage rect, which runs `TRANSFER_TO_HOST_2D` +
  `RESOURCE_FLUSH` on just that subrect. The banded path is what
  removed the "D1 flicker": before it landed, a caret blink + clock
  tick on opposite ends of the taskbar coalesced into one fullscreen
  union and re-uploaded the entire scanout every frame; now each
  small region transfers independently.

After every `FramebufferPresent` call the damage union AND the
banded rect list are reset. Callers that paint straight into the
framebuffer behind the primitive API (rare: virtio-gpu's boot test
pattern is the only one today) can call `FramebufferAddDamage(x, y,
w, h)` to cover their writes for the next present.

`FramebufferReadDamage()` snapshots the current bbox union without
clearing it — used by tests + diagnostics. The banded-rect list is
internal and not exposed via a stable accessor today.

### Content-diff frame elision

The primitive-accumulated damage rect bounds where pixels *could*
have changed, but the desktop compositor (`DesktopCompose`)
unconditionally repaints the whole scene every pass — gradient,
wallpaper, console, windows, chrome — so its primitive damage is
always full-screen. That defeats the partial pipeline: the 1 Hz
ui-ticker recompose used to flush the entire surface every second,
which on virtio-gpu (VirtualBox) is the visible flicker and the
compositor-lock contention that made the mouse feel slow.

`FramebufferBeginCompose` allocates a second framebuffer-sized
buffer — the **presented-frame snapshot** — alongside the shadow.
`FramebufferEndCompose` compares the freshly-composed shadow
against the snapshot *within* the primitive-damage bound and
derives the **exact** changed bounding box, then blits / syncs /
presents only that. A recompose that lands pixel-identical output
(an idle desktop: same gradient, same clock minute, no caret
phase change) produces an empty diff — the blit and the
virtio-gpu round-trip are both skipped, and the snapshot already
mirrors the screen.

The decision is **content-derived**, so it cannot freeze: a
paint path can never "forget" to mark itself dirty, because a
pixel that genuinely changed is found by the compare and one that
did not is correctly skipped. `DesktopCompose` is unchanged — the
elision lives entirely in the framebuffer compose path. (This is
why the earlier hand-set-dirty-bit gate, which froze PE apps that
repaint via the periodic tick, was reverted: PR #286 → #288.) The
first frame after (re)alloc syncs the whole surface into the
snapshot and presents in full so the "snapshot == live screen"
invariant holds unconditionally thereafter; if the snapshot
allocation fails the compositor degrades gracefully to a full
present every frame.

## Render statistics

`kernel/drivers/video/render_stats.{h,cpp}` accumulates per-frame
counters that the `gfx` shell command surfaces:

- `frames_composed` / `frames_presented` — totals.
- `frames_clean` — present passes that skipped the flush because
  the compositor wrote nothing **or** the content-diff found the
  recompose pixel-identical to the presented frame. On an idle
  desktop this climbs ~once/second — the runtime signal that the
  flicker-elision is working.
- `frames_full` / `frames_partial` — split by ≥95% surface
  coverage. Heavy chrome frames (full window redraw) land in
  "full"; cursor / clock / hover frames in "partial". The split
  uses the TRUE dirty count, not the bbox area, so a banded
  present with two small spatially-separated rects is correctly
  classified `partial` even when its bbox would qualify as `full`.
- `dirty_pixels_total` — sum of per-rect dirty pixels (true area
  the GPU actually uploaded). For a banded present this is
  `sum(rects[i].w * rects[i].h)`; for a coalesced (single-rect)
  present it equals the bbox area. The earlier v0 path charged
  the bbox area unconditionally, which overstated by `bbox -
  sum(rects)` for spatially-separated changes.
- `bbox_pixels_total` — sum of union-bbox areas. The ratio
  `dirty_pixels_total / bbox_pixels_total` is the fraction of
  the bbox a backend without the banded path would have
  uploaded; the gap is what the banded path saves.
- `surface_pixels_total` — denominator for the "avg dirty
  fraction" per-mille the `gfx` command prints.
- `presents_banded` / `presents_coalesced` — split of presents
  by path. Excludes clean frames. `presents_coalesced > 0` +
  `presents_banded == 0` means the content-diff never produced
  a spatially-separated change set in the run (typical for a
  single-app workload).
- `max_band_count` — high-water mark of disjoint rects in any
  single present. Caps at `kCoalesceBands` (6) before the
  framebuffer falls back to a single bbox.
- `last_damage_*` + `last_rect_count` — the most recently
  presented damage bbox and the rect count behind it, for
  diagnosis. `last_rect_count == 0` is a clean frame; `1` is
  coalesced; `>1` is banded.

Counter regressions are pinned by
`tests/host/test_render_stats.cpp` — clean / coalesced /
banded classification, full-vs-partial threshold under both
paths, `max_band_count` as a high-water mark, and
`RenderStatsReset` zeroing every field.

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
- `vkCmdDraw` and `vkCmdDrawIndexed` against a scanout-backed
  render target run a CPU edge-function triangle rasterizer.
  Vertex buffers bound at binding 0 are interpreted in one of
  two DuetOS fixed formats (8-byte v0 default; 12-byte v1 with
  i16 Z when `vkCmdSetVertexFormatDuet(cb, 1)` is in effect —
  see [Vulkan ICD](../subsystems/Vulkan-ICD.md)). The rasterizer
  supports TriangleList / TriangleStrip / TriangleFan
  topologies, UINT16 / UINT32 indices, Gouraud-shaded
  per-vertex colour interpolation, per-pixel src-over alpha,
  scissor-rect clipping, and a software 16-bit depth buffer
  (lazy-allocated to the live framebuffer extent, cleared by
  `vkCmdClearDepthStencilImage`, gated by every Vulkan
  VkCompareOp).
  `vk_triangles_drawn` ticks per dispatched triangle whether or
  not pixels actually reach the framebuffer, so non-scanout test
  draws still exercise the dispatch chain.
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
- Format introspection: `vkGetPhysicalDeviceFormatProperties` /
  `vkGetPhysicalDeviceImageFormatProperties` (recognise
  `VK_FORMAT_B8G8R8A8_UNORM` only; everything else reports
  zero features / `ErrorFormatNotSupported`).
- Push descriptors: `vkCmdPushDescriptorSetKHR` records each
  write as a tape op for stats; no shader to consume.
- Secondary command buffers: `VkAllocateCommandBuffers2`
  (level=Secondary), `vkCmdExecuteCommands` recurses into the
  secondary's tape during replay so its ops actually run.
  Primary cbs passed to ExecuteCommands are rejected at record
  time.
- VK_EXT_debug_utils command-stream labels:
  `vkCmdBeginDebugUtilsLabelEXT` / `End` / `Insert` (string
  payload reuses the per-op push-constants slot).
- Vulkan 1.1 array-form bind: `vkBindBufferMemory2` /
  `vkBindImageMemory2`.
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

## DPMS (Display Power Management)

`kernel/drivers/gpu/dpms.{h,cpp}` is the VESA Display Power
Management state-machine bookkeeper — four states (On / Standby /
Suspend / Off) plus a single-hook integration seam that drivers
register against.

`kernel/drivers/gpu/display_power.{h,cpp}` is the canonical hook
implementation that drives the two emulated backends DuetOS ships
today:

- **Bochs VBE** — `VbeSetEnabled(bool)` toggles the `ENABLE.ENABLED`
  bit via the legacy port pair (0x1CE / 0x1CF). Other ENABLE flags
  (LFB aperture, NO_CLEAR_MEM, 8BIT_DAC) are preserved across the
  toggle so the framebuffer survives the blank.
- **virtio-gpu** — `VirtioGpuSetScanoutEnabled(bool)` issues
  `SET_SCANOUT(scanout=0, resource_id=0, rect)` to detach; per
  virtio-gpu 1.0 §5.7.6.7.5 a zero `resource_id` makes the host
  stop compositing the framebuffer into the display surface. The
  guest backing keeps its pixels. Re-enable re-binds the original
  resource and pushes one full-resource flush so the display
  catches up. `VirtioGpuFlushScanout` silently no-ops while
  detached so the compositor doesn't pump round-trips at a host
  that isn't displaying.

The hook collapses Standby / Suspend / Off to "scanout off"
because neither emulated backend models the spec's separate
H-sync / V-sync power levels. A future real-hardware driver
(Intel DDI, AMD DCN, panel-power-pin) can register a richer hook
that walks the VESA H-sync / V-sync ladder using the `from` /
`to` arguments.

Wiring: `display_power.cpp` self-registers via
`KERNEL_INITCALL(Drivers, "drivers/gpu.dpms-hook", …)`, so the
hook is live by the time the kernel shell, the settings app, or
the screensaver issues `DpmsSetState`. `DisplayPowerSelfTest`
runs as a Drivers-phase boot self-test (after `RunPhase(Drivers)`)
and drives one Off→On cycle through the hook, emitting the
structural sentinel CI greps for —
`[gpu/display-power] selftest PASS (hook commits On/Off,
bookkeeper bumped)` — on success and
`[gpu/display-power] selftest FAIL` on regression.

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

- **Intel RCS bring-up is `MI_NOOP`-only.** The Render Command
  Streamer ring is now programmed and proven alive (head catches
  tail) on Intel silicon, but the only opcode written through it
  today is `MI_NOOP`. Real workloads need
  `MI_STORE_DWORD_IMM` / `MI_BATCH_BUFFER_START` + a populated
  GTT, plus GuC/HuC firmware push (the firmware files are
  located via `intel::Probe` but never uploaded — there is no
  MEI driver to deliver them). On QEMU's emulated `-vga std` /
  `-vga virtio` the Intel RCS path is correctly inert: those
  devices report vendor IDs 0x1234 / 0x1AF4 and the
  `IntelRcsRingSelfTest` emits the structural "no Intel device
  — skipped" sentinel.
- **AMD CP ring is register-programmed, not executing.** GFX9+
  hardware has `mmCP_RB0_BASE` / `_BASE_HI` / `_CNTL` programmed
  and read-back verified, so the kernel knows it can talk to the
  CP register file. But the Command Processor can't execute a
  single PM4 packet without microcode pushed (`gfx_pfp.bin` /
  `gfx_me.bin` / `gfx_ce.bin` for the GFX pipeline, plus
  `gfx_mec.bin` for compute and `gfx_rlc.bin` for power
  management). The firmware-loader probe in `amd::Probe` logs
  which blobs an operator has dropped in; an actual MEC/PFP/ME
  push is the next gate. Until that lands, RPTR stays at 0 on
  every boot — that's expected behaviour, not a bug.
- **NVIDIA Turing+ is observation-only.** The driver now reads
  a wider diagnostic register set (PMC_BOOT_0 / _42 / _8 +
  PMC_INTR_EN_0 + PFIFO_INTR + PBUS_INTR_0 + PFB_PRI_RD) and
  probes the firmware loader for `gsp_rm.bin` / `gsp_log.bin` /
  `bootloader.bin`, but writes nothing — every PFIFO-side effect
  on Turing+ goes through the GSP RPC ring and there is no
  smaller intermediate gate to land first. GSP firmware push +
  RPC channel is a multi-month effort whose schema has no public
  documentation (the only reference is reverse-engineering work
  in the `nouveau` driver), so it stays the next gate.
- **No GPU command queue exposed to userland.** Submission is
  kernel-side direct register writes (virtio-gpu's tiny command
  set; Intel's NOOP submitter). The Vulkan ICD is still CPU-only
  and does not route through the Intel ring yet.
- **Vulkan ICD does not execute shaders.** SPIR-V blobs are
  validated (magic-word check) + parsed (entry-point /
  capability / decoration counts), but the bytecode is not
  executed. `vkCmdDraw` now drives a CPU triangle rasterizer
  (DuetOS v0 fixed vertex format, flat-shaded, TriangleList
  only — see [Vulkan ICD](../subsystems/Vulkan-ICD.md)); attribute
  interpolation, depth, and indexed draws are still gated on
  the SPIR-V execution slice.
- **Damage tracking promotes to a disjoint-rect list at present
  time.** `FramebufferAddDamage` accumulates a single union bbox
  per the existing `DamageRect::Extend` math, but `FramebufferPresent`
  has a banded path: when `g_damage_rect_count > 0` it walks
  `g_damage_rects[]` and fires the registered present hook once per
  disjoint rect (see `framebuffer.cpp` `FramebufferPresent`). The
  content diff in `FramebufferEndCompose` is what populates the
  rect list when it finds spatially-separated changes, so a frame
  with a caret blink + clock tick on opposite ends flushes two
  small rects instead of one near-fullscreen rect. The "D1 flicker"
  was the prior collapse this path fixes.

## Related Pages

- [Driver Overview](Driver-Overview.md)
- [Compositor and Window Manager](../subsystems/Compositor.md)
- [DirectX v0 Path](../subsystems/DirectX.md)
- [Duet Theme Spec](../specifications/Duet-Theme-Spec.md)
