# GPU Implementation Notes — prior art and concrete next gates

> **Audience:** Contributors picking up the next GPU/Vulkan slice
>
> **Status:** Living reference; update when a gate lands or new
> primary sources surface

Distilled from a cross-OS / cross-driver research pass (May 2026)
that scoped the per-vendor command-ring submission, the SPIR-V
sampler surface, the DXBC→SPIR-V transpiler, and the Vulkan WSI
sync model. Each section captures the key facts and the canonical
upstream URL — the per-subsystem wiki pages own the *live* state;
this page is the *prior-art* anchor.

## Intel iGPU — from MI_STORE_DWORD_IMM to accelerated 2D (Gen9–Gen12)

The Render ring at MMIO 0x2000 is already programmed (CTL / HEAD /
TAIL / START) and the boot self-test verifies `MI_STORE_DWORD_IMM`
read-back. The next gate is **batch-buffer execution via the Global
GTT**, not GuC. GuC submission is optional on Gen9–Gen12 and mandatory
only on Xe-HP+ (DG2 / Meteor Lake / Lunar Lake); bare-ring submission
works on every Gen9–Gen12 part DuetOS will see on commodity hardware.

The detail below is from a focused research pass (2026-05-29,
6 parallel agents). Values are corroborated across the Linux i915
source and Intel blogs/PRMs; where a PRM PDF wouldn't text-decode the
i915 macro that encodes the same bspec field is cited instead — treat
the linked PRM as the authority to confirm exact bit ranges on the
silicon you bring up.

### 1. Forcewake + GT-init preconditions (the real-HW gotcha)

On real silicon, GT registers in the `0x2000–0x2FFF` (ring) block and
the BLT/render engines return garbage unless **forcewake** is held.
QEMU never modelled this, which is why the current scaffold's poke
sequence is unproven on metal.

- **Handshake per domain:** a `set` reg + an `ack` reg. Writes use the
  masked-bit form `(bit<<16)|bit`. `FORCEWAKE_KERNEL = bit0`,
  `FALLBACK = bit15`. Get = wait `ack & bit0 == 0` → write
  `set = ENABLE(bit0)` → wait `ack & bit0 != 0` (50 ms timeout).
- **Gen9 offsets:** RENDER set `0xA278` / ack `0x0D84`; GT (a.k.a.
  blitter) set `0xA188` / ack `0x130044`; MEDIA set `0xA270` / ack
  `0x0D88`. Stable Gen9→Gen12; Gen11+ only adds per-instance media
  domains (irrelevant to RCS/BCS).
- **The RCS `0x2000` block spans two domains** (`__gen9_fw_ranges`):
  `0x2000–0x26FF → RENDER`, `0x2700–0x2FFF → GT`. **Hold both** before
  programming the ring.
- **Gen9–Gen11 fallback-ack erratum** (`WaRsForcewakeAddDelayForAck`):
  if the ack misses, redo the handshake on the `FALLBACK` (bit15)
  domain, sample the real ack, release fallback. Implement it — bare
  Gen9 silicon does miss the first ack. Dropped on Gen12.
- **RC6 off for v0** (`GEN6_RC_CONTROL = 0`) so the GT can't sleep
  mid-submit; holding forcewake across submission is the belt-and-
  suspenders guarantee. Skip RPS — boot frequency is fine.
- **Un-stop the ring:** `RING_MI_MODE` (RCS `0x209C`) ←
  `DISABLE(STOP_RING)`, then poll. This is the one ring-mode bit that
  is genuinely required. Reset `RING_HEAD` until it sticks (HSW+
  erratum). Everything else (GuC, LRC/execlists, PPGTT, semaphores) is
  optional for a bare single-context ring.

### 2. Global GTT (GGTT) — map a page so the GPU can address it

- **PTE:** 64-bit. `pte = (host_phys & ~0xFFFull) | PRESENT` where
  `PRESENT = bit0`. **`LM = bit1` stays 0** on iGPU (the page is system
  DRAM, not VRAM). PAT bits stay 0 on Gen9–11 (system-default
  cacheability); MTL+ moved PAT to 53:52 — not our targets. HW decodes
  phys up to bit 38 on Gen9–12 (i915's `GENMASK(45,12)` mask is just
  permissive).
- **It is MMIO, not RAM.** The GGTT page-table is aliased into the
  **upper half of BAR0 (GTTMMADR)** — Gen12 BAR0 is 16 MiB with PTEs
  starting at **+8 MiB** (generically `bar0_size/2`; older 4 MiB BARs
  put it at +2 MiB). 8 MiB of PTEs × 8 B = 1,048,576 entries → maps
  4 GiB of GPU VA. Map it write-combining; do a posting read after a
  PTE write to flush the WC buffer.
- **Install:** `pte_index = gpu_va >> 12; writeq(pte, gsm_base +
  pte_index*8)`. **Init:** allocate one scratch page, encode
  `scratch_phys | PRESENT`, write it into **every** slot first so
  stray GPU accesses hit a benign page, then install real PTEs.
- **Safe GPU-VA:** pick a 4 KiB-aligned window **above `mappable_end`**
  (the top of the BAR2/GMADR aperture), growing down from 4 GiB. The
  low aperture region holds the firmware framebuffer + stolen memory —
  staying above it avoids the FB-takeover zone. Batch/dest pages need
  **not** be in the GMADR aperture; the engine reads them through the
  GGTT directly.

### 3. Batch-buffer submission + breadcrumb

- **MI_BATCH_BUFFER_START** (Gen8+ 3-DWORD form, i915 `gen8_emit_bb_start`):
  `cs[0] = (0x31<<23) | 1 | (asi<<8)` where `asi` bit8 = address-space
  (0 = GGTT, the kernel path); `cs[1] = lower_32(bb_va)`; `cs[2] =
  upper_32(bb_va)`. **Correction to the prior note: the address is a
  full 48-bit lo/hi split, NOT "32-bit lo + 16-bit hi".** The batch
  buffer (GGTT-mapped) must end with **MI_BATCH_BUFFER_END** `(0x0A<<23)`.
- **Doorbell:** append to the ring at `RING_TAIL`, emit an **even**
  number of DWORDs (qword-aligned; pad with `MI_NOOP = 0`), handle the
  wrap by NOOP-filling the tail, issue a store fence (`sfence`/`wmb`)
  to drain the WC buffer, **then** write `RING_TAIL` = new byte offset
  (masked to ring size). `RING_CTL` length is already set.
- **Completion (poll path):** end the batch (or follow it in the ring)
  with a post-sync write of a monotonic seqno to a WC GGTT status page,
  then poll that dword. On RCS use **PIPE_CONTROL(6)** with
  `QW_WRITE(1<<14) | GLOBAL_GTT_IVB(1<<24) | CS_STALL` + addr lo/hi +
  seqno-qw so the write lands after pipeline caches drain; on BCS/VCS
  the lighter **MI_FLUSH_DW** `(0x26<<23)|1` post-sync QW store
  suffices. `MI_USER_INTERRUPT` is the IRQ alternative — defer past v0.

### 4. First user-visible win — 2D BLT for GDI accel (T4-03)

The cheapest accelerated workload (far simpler than the 3D pipe):
move GDI `FillRect`/`BitBlt` and the compositor's solid fills onto the
**BLT engine**. Present on Gen9–Gen12 (removed only at Xe-HP+/DG2).
Submit on the **BCS ring (0x22000)** to keep RCS free, or on RCS — the
parser routes by client (2D client = 0x2).

- **XY_COLOR_BLT (solid fill):** `DW0 = (2<<29)|(0x50<<22)|writemask|
  (len-2)` (32bpp ARGB writemask = `(3<<20)`); `BR13 = solid(1<<31) |
  depth[25:24] (3 = 32bpp) | ROP[23:16] (0xF0 = PATCOPY/fill) |
  pitch_bytes[15:0]`; `BR22 = (Y1<<16)|X1`; `BR23 = (Y2<<16)|X2`
  (exclusive); `BR09/BR27 = dest GGTT addr lo/hi`; final DW = ARGB
  color.
- **XY_SRC_COPY_BLT (copy):** opcode `0x53`, `ROP = 0xCC` (SRCCOPY),
  same dest fields plus src coords + src pitch + src GGTT addr lo/hi.
- **Constraints:** pitch is 16-bit **bytes** (≤ 32 KB), coords 16-bit
  (≤ 65535); surface base aligned 64/128/256 B for 8/16/32 bpp;
  linear unless tile bits set in DW0. **Flush:** the legacy blitter is
  cached — emit **MI_FLUSH_DW** after the blit before the CPU/scanout
  reads the destination.

### 5. Display modeset v0 — own the panel without PLL math

- **Pipeline:** Planes → Pipe (timings) → Transcoder → DDI/port → PHY.
- **v0 verdict: keep the firmware GOP timings** (UEFI leaves the panel
  lit; you lose modeset ability post-`ExitBootServices` but the linear
  FB persists). Just reprogram the **primary plane** — `PLANE_SURF`
  (the arming write), `PLANE_STRIDE`, `PLANE_CTL` format — to point at
  our framebuffer (SKL+ block base ≈ `0x70180`, +0x1000/pipe). No
  PLL/transcoder reprogram needed; all clock/timing state is already
  live.
- **Second-monitor detect (no lighting yet):** poll `SDEISR` (Gen9) /
  `GEN11_DE_HPD_ISR` (Gen11+) for a connected DDI, then read EDID over
  **GMBUS** (base `0x5100`, PCH `0xC5100`): `GMBUS0` ← pin+rate;
  `GMBUS1` ← `SW_RDY|CYCLE_WAIT|len|(0x50<<1)|READ`; poll `GMBUS2`
  `HW_RDY` (abort on `SATOER`); read `GMBUS3`; `GMBUS1` ← stop. DP ports
  read EDID over the AUX channel instead. Actually lighting a second
  display needs the full PLL→pipe→plane path — defer; v0 stops at
  detect + enumerate.

### 6. Real-hardware bring-up — there is no QEMU shortcut

QEMU has **no Intel-iGPU model**, so every path above is real-HW-only.

- **First target:** a **Skylake/Kaby-Lake NUC** (NUC6i3SYH / NUC7i3BNH)
  or an HD 520/620 ultrabook — Gen9 is the best-documented, and a NUC
  has no Optimus/hybrid mux fighting for the panel. Avoid
  NVIDIA-Optimus / AMD-switchable laptops for v0.
- **Non-destructive proof ladder** (read back over serial UART before
  advancing): (1) MMIO liveness reads; (2) `MI_STORE_DWORD_IMM` cookie
  to a GGTT scratch page — *we have this*; (3) the same store executed
  from a **GGTT batch buffer** (proves GGTT + batch dispatch); (4)
  `XY_COLOR_BLT` filling an **offscreen** (not scanned-out) surface,
  pixels read back over serial; (5) **only then** blit to the live
  framebuffer.
- **Watchdog:** mirror i915 hangcheck — poll `RING_HEAD` after submit;
  unchanged across N polls = hang. On hang dump `RING_HEAD/TAIL/START/
  CTL`, `ACTHD`, `IPEIR`, `IPEHR`, `INSTDONE`, `EIR` over serial and
  decode against the PRM (the same set i915's error-state captures).
- **Reference impls:** Haiku `intel_extreme` (freestanding GART +
  modeset; no command submission), SerenityOS Intel native graphics
  (PR #6277), OpenBSD/illumos `inteldrm` (smaller i915 port for ring/
  hangcheck logic), OSDev "Native Intel graphics".

### Proposed slice order

1. **Forcewake + GT-init** (§1) — un-blocks reliable real-HW MMIO; extends the current scaffold, no new subsystem.
2. **GGTT manager** (§2) — PTE encode + BAR-alias map + scratch fill + a VA allocator above the aperture.
3. **Batch submission + breadcrumb** (§3) — MI_BATCH_BUFFER_START from a GGTT batch + PIPE_CONTROL seqno poll → proof-ladder rung 3.
4. **2D BLT** (§4) — color-fill + src-copy to an offscreen surface (rung 4), then wire GDI `FillRect`/`BitBlt` to the BLT against the live FB. **This is the T4-03 daily-driver win.**
5. **Display detect/modeset** (§5) — independent of 1–4; plane-reprogram + GMBUS EDID + connector enumerate.

Primary sources:
[bwidawsk.net GGTT part 1](https://bwidawsk.net/blog/2014/6/the-global-gtt-part-1/),
[i915 intel_ggtt.c (`gen8_ggtt_pte_encode`, GSM `ioremap_wc`)](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/i915/gt/intel_ggtt.c),
[i915 intel_gtt.h (`GEN8_PAGE_PRESENT`, `GEN12_GGTT_PTE_LM`)](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/i915/gt/intel_gtt.h),
[i915 gen8_engine_cs.c (`gen8_emit_bb_start`, ggtt-write breadcrumb)](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/i915/gt/gen8_engine_cs.c),
[i915 intel_ring_submission.c (`wmb()` before RING_TAIL)](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/i915/gt/intel_ring_submission.c),
[i915 intel_gpu_commands.h (MI/BLT opcodes)](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/i915/gt/intel_gpu_commands.h),
[i915 intel_uncore.c (forcewake handshake + domains)](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/i915/intel_uncore.c),
[i915 intel_gmbus.c (EDID read)](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/i915/display/intel_gmbus.c),
[Intel TGL PRM Vol 10 Copy Engine (BLT opcodes/fields)](https://cdrdv2-public.intel.com/705824/intel-gfx-prm-osrc-tgl-vol-10-copy-engine.pdf),
[Intel ICL PRM Vol 2a Command Reference](https://cdrdv2-public.intel.com/684420/intel-gfx-prm-osrc-icllp-vol-02a-command-reference-instructions-2.pdf),
[Intel 12th-gen datasheet — GTTMMADR](https://edc.intel.com/content/www/us/en/design/publications/12th-generation-core-processor-datasheet-volume-2-of-2/graphics-translation-table-memory-mapped-range-address-gttmmadr1-0-2-0-pci-offse/),
[Haiku intel_extreme](https://www.haiku-os.org/docs/develop/drivers/intel_extreme/generations.html),
[SerenityOS Intel native graphics PR #6277](https://github.com/SerenityOS/serenity/pull/6277),
[OSDev Native Intel graphics](https://wiki.osdev.org/Native_Intel_graphics).

## AMD GFX9+ — CP microcode push for PM4 execution

CP_RB0_BASE / _BASE_HI / _CNTL are already programmed and
read-back verified at BAR5 MMIO. The next gate is **direct host
upload of PFP / ME / CE / RLC microcode** through
`mmCP_*_UCODE_ADDR` / `_DATA` register-pair streams. This works
without PSP on **GFX9 (Vega 10 / 12 / 20 / Raven / Renoir),
GFX10 (Navi 1x), and GFX10.3 (Navi 2x)** — AMD ships unsigned
microcode for these parts. **GFX11+** (RX 7000 series, Phoenix,
Strix) requires PSP-mediated upload because microcode is signed.

Sequence: halt CP via `mmCP_ME_CNTL`, walk
`mmCP_PFP_UCODE_ADDR=0` then stream dwords to
`mmCP_PFP_UCODE_DATA` (auto-increment), repeat for CE and ME
(via `mmCP_ME_RAM_WADDR` / `_DATA`), trailing version write to
each `*_ADDR`, then un-halt. RLC must be loaded and
`RLC_ENABLE_F32=1` before CP wakes — leave PG disabled
(`mmRLC_PG_CNTL=0`) for the minimum-viable path.

**Minimum PM4 demo:** emit `PACKET3_NOP` (`0xC0001000`), bump
WPTR, poll RPTR. Strong proof: `PACKET3_WRITE_DATA(0x37)` with
`DST_SEL=mem`, `ENGINE_SEL=PFP`, `WR_CONFIRM`, pointing into a
Zone::Dma32 buffer with a cookie — read-back proves execution.

Firmware-header layout: `common_firmware_header` (32 B) +
`gfx_firmware_header_v1_0` (44 B) → payload at
`ucode_array_offset_bytes`.

**Status (this branch):** the microcode-image parser landed.
`drivers/gpu/amd_gfx_fw.{h,cpp}` validates the
`common_firmware_header` + `gfx_firmware_header_v1_0` layout and
exposes the ucode payload as a (dword*, count) view to a follow-on
upload slice. Pinned by `AmdGfxFwSelfTest` (1 happy path + 6 reject
paths) and wired into `amd::Probe`. The MMIO upload sequence
(halt CP, stream dwords to `mmCP_PFP_UCODE_DATA` / `mmCP_CE_UCODE_DATA`
/ `mmCP_ME_RAM_DATA`, RLC bring-up, un-halt) is the next slice — it
only validates on real Vega 10 / Navi hardware.

Primary sources: [amdgpu gfx_v9_0.c](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/amd/amdgpu/gfx_v9_0.c),
[amdgpu_ucode.h](https://raw.githubusercontent.com/torvalds/linux/master/drivers/gpu/drm/amd/amdgpu/amdgpu_ucode.h),
[KFD PM4 opcodes](https://github.com/Xilinx/linux-xlnx/blob/master/drivers/gpu/drm/amd/amdkfd/kfd_pm4_opcodes.h),
[soc15d PM4 macros](https://raw.githubusercontent.com/torvalds/linux/master/drivers/gpu/drm/amd/amdgpu/soc15d.h).

## NVIDIA Turing+ — GSP boot is no longer "no public docs"

The Graphics-Drivers page's "multi-month with no public docs"
framing is stale. NVIDIA's `open-gpu-kernel-modules` (2022) and
nouveau's GSP-RM support (mainlined Linux 6.7+) both publish the
boot sequence and the RPC schema. Estimate is now **~7 sessions
(~2.4 kLOC)** matching nouveau's nova-core v4/v5 patches that
reach "GSP boots, RPC ready".

Steps:
1. Firmware container parser (`nvfw_bin_hdr` 24 B + per-arch HS
   header + ELF section walk for `.fwimage` / `.fwsignature_*`).
2. WPR layout + radix-3 page table builder.
3. FWSEC ucode load + FRTS run (carves WPR2).
4. Booter ucode load onto SEC2 falcon (HS-signed; you just
   orchestrate).
5. Mailbox arg push + Falcon reset + RISC-V mode kick.
6. Command/status circular queues with head/tail/doorbell.
7. Sequencer interpreter + wait for `NV_VGPU_MSG_EVENT_GSP_INIT_DONE`.

Once GSP is ready the host writes PM4-equivalent methods directly
to USERD channel ring buffers — GSP only mediates the control
plane.

**Status (this branch):** Step 1 (firmware container parser) landed.
`drivers/gpu/nvidia_gsp_fw.{h,cpp}` parses the outer `nvfw_bin_hdr`
container, classifies the inner descriptor as TU10x/GA100 (76 bytes)
or GA102+ (84 bytes), surfaces the GSP payload as a (data, size)
view, and pins the parse + 7 reject paths via `NvidiaGspFwSelfTest`
at boot. `nvidia::Probe` runs the parser on each blob the firmware
loader returns. Steps 2–7 (WPR layout / FWSEC / Booter / mailbox-kick
/ queues / sequencer / INIT_DONE) remain — those need real Turing+
hardware to validate, and most are real-HW-only.

Primary sources: [NVIDIA open-gpu-kernel-modules](https://github.com/NVIDIA/open-gpu-kernel-modules),
[nouveau nvkm GSP](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/nouveau/nvkm/subdev/gsp/rm/r535/rpc.c),
[Linux Kernel — Nova-core FWSEC docs](https://docs.kernel.org/gpu/nova/core/fwsec.html),
[GSP RPC clarification patch](http://www.mail-archive.com/nouveau@lists.freedesktop.org/msg51826.html).

## SPIR-V — sampler addressing, texel fetch, image storage

The SPIR-V interpreter executes a Vulkan subset including
`OpImageSampleImplicitLod` / `OpImageSampleExplicitLod` with
bilinear filtering and real texel fetch via the bound descriptor.
As of 2026-05-27 the sampler's address mode propagates end-to-end:
`VkCreateSampler` records `addressModeU` into a `SamplerRecord`,
`VkUpdateDescriptorSetSampled` carries the sampler handle alongside
the image view, and the executor reads
`SamplerAddressModeFor(sampler)` per sample. All four spec address
modes (REPEAT / MIRRORED_REPEAT / CLAMP_TO_EDGE / CLAMP_TO_BORDER)
work; CLAMP_TO_BORDER's border colour is transparent black in v0.

Open gates for the next slice:

- **Bilinear math correction.** Current path scales by `W-1`;
  spec convention is `u*W - 0.5` for centre-of-texel sampling.
  Behavior change — coordinate with any self-tests that assume
  the W-1 convention.
- **Explicit LOD / mipmap chains.** `OpImageSampleExplicitLod`
  ignores the Lod operand because there's no mip chain. Image
  views need a per-level array; `VkCreateImageView` needs to take
  a level count.
- **Real atomicity for parallel compute.** Atomic opcodes
  currently collapse to non-atomic ops — correct only because
  the interpreter runs invocations serially. When the dispatcher
  parallelises (real GPU back-end or work-stealing across CPUs),
  these need actual atomic intrinsics.
- **Real derivatives for fragment shaders.** `OpDPdx` / `OpDPdy` /
  `OpFwidth` return zero. Real values need 2×2-quad fragment
  execution — invocations sharing per-quad context so finite
  differences become meaningful.
- **GLSL.std.450 has no texture functions** — `textureGrad`,
  `textureLod`, `textureGather`, `texelFetch` all lower to core
  SPIR-V `OpImageSample*Grad/Lod` and `OpImageGather/Fetch`.

Primary sources: [Vulkan 1.3 spec — Image Operations](https://docs.vulkan.org/spec/latest/chapters/textures.html),
[SPIR-V unified spec](https://registry.khronos.org/SPIR-V/specs/unified1/SPIRV.html),
[SwiftShader SamplerCore.cpp](https://github.com/google/swiftshader/blob/master/src/Pipeline/SamplerCore.cpp),
[GLSL.std.450 extended-instruction set](https://registry.khronos.org/SPIR-V/specs/unified1/GLSL.std.450.html).

## DXBC → SPIR-V transpiler — the D3D11 path forward

D3D11 (SM4/SM5) emits DXBC bytecode. The `userland/libs/d3d11` and
`userland/libs/d3d12` DLLs currently return `E_FAIL` because they
don't translate draws into VkCmd*. A minimal in-kernel DXBC→SPIR-V
transpiler unblocks the "textured spinning quad" demo — ~1.5–2.5
kLOC of C++, plausible single-session bringup for a passthrough
VS + sampled FS:

| DXBC | SPIR-V |
|------|--------|
| `mov` | masked `OpStore` after `OpLoad`+shuffle |
| `mul` / `add` / `mad` | `OpFMul` / `OpFAdd` / `OpExtInst Fma` |
| `dp4` | `OpDot` |
| `sample` t#, s# | `OpSampledImage` → `OpImageSampleImplicitLod` |
| `ret` | `OpReturn` + `OpFunctionEnd` |

Reference: vendor a trimmed `d3d11TokenizedProgramFormat.hpp`
from the Windows SDK under `third_party/microsoft/` for the
opcode/operand bit-layouts. DXVK's `src/dxbc/` is the canonical
production transpiler; bgfx's `src/shader_dxbc.{h,cpp}` is a
smaller decode-only reference.

**DXIL (SM6.0+) is out of scope for v0** — it's LLVM-3.7 bitcode
with unstructured control flow. ~8× the bytecode size; defer until
the DXBC path ships.

Primary sources: [DXVK src/dxbc](https://github.com/doitsujin/dxvk/tree/master/src/dxbc),
[Windows SDK header mirror](https://github.com/tpn/winsdk-10/blob/master/Include/10.0.10240.0/um/d3d11TokenizedProgramFormat.hpp),
[Shader Model 5 assembly reference](https://learn.microsoft.com/en-us/windows/win32/direct3dhlsl/shader-model-5-assembly--directx-hlsl-),
[Maister DXIL→SPIR-V part 1](https://themaister.net/blog/2021/09/05/my-personal-hell-of-translating-dxil-to-spir-v-part-1/).

## Vulkan WSI — real sync primitives

Today the WSI is degenerate: `vkAcquireNextImageKHR` doesn't
block, semaphores are no-ops, fences signal immediately. The
kernel IPC subsystem already has `KEvent` / `KSemaphore` /
`KWaitable` — the gap is wiring them through.

**Single kernel primitive backs everything:** a u64-counter event
with monotonic signal + wait-on-value semantics (the Linux
`drm_syncobj` shape). Binary semaphores are a thin wrapper that
asserts signal `0→1` and wait `1→0`. Fences are host-waitable
variants. Timeline semaphores are the native form. Mesa's
`vk_sync_timeline.c` is the reference.

Per-image in-flight tracking: per-frame slots (image-available
semaphore + render-finished semaphore + in-flight fence), classic
2-frames-in-flight pattern from Vulkan Tutorial.

**Advertise** `VK_KHR_synchronization2` (core 1.3),
`VK_KHR_timeline_semaphore` (core 1.2), and
`VK_KHR_incremental_present` — all three are pure wins; the last
plumbs straight into the existing banded damage path.

Primary sources: [Vulkan WSI spec](https://registry.khronos.org/vulkan/specs/1.3-extensions/html/vkspec.html#_wsi_swapchain),
[Mesa vk_sync runtime](https://gitlab.freedesktop.org/mesa/mesa/-/tree/main/src/vulkan/runtime),
[Khronos timeline-semaphore blog](https://www.khronos.org/blog/vulkan-timeline-semaphores),
[Vulkan Tutorial frames-in-flight](https://vulkan-tutorial.com/Drawing_a_triangle/Drawing/Rendering_and_presentation).

## Related pages

- [Vulkan ICD](../subsystems/Vulkan-ICD.md) — live state of the
  in-kernel Vulkan implementation.
- [Graphics Drivers](../drivers/Graphics-Drivers.md) — per-vendor
  driver scaffolds and their bring-up state.
- [DirectX](../subsystems/DirectX.md) — D3D v0 path that the
  DXBC transpiler will replace.
- [Subsystem Isolation](../kernel/Subsystem-Isolation.md) — why
  the ICD is in-kernel rather than userland.
