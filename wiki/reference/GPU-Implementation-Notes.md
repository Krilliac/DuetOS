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

## Intel iGPU — Render Command Streamer beyond MI_NOOP / MI_STORE_DWORD_IMM

The Render ring at MMIO 0x2000 is already programmed (CTL / HEAD /
TAIL / START) and the boot self-test verifies `MI_STORE_DWORD_IMM`
read-back. The next gate is **batch-buffer execution via the
Global GTT**, not GuC. GuC submission is optional on Gen9–Gen12
and mandatory only on Xe (Meteor Lake / Lunar Lake / Battlemage).
Plain execlists or even bare-ring submission works on every Gen9–
Gen12 part DuetOS will see on commodity hardware.

- **Global GTT** lives in the upper half of BAR0 (GTTMMADR aperture);
  PTEs are 64-bit, bit 0 = `Valid`, address split across 31:12 +
  38:32 + low PAT bits. Software must write through the BAR-mapped
  alias, not directly to host RAM. 4 KiB pages.
- **MI_BATCH_BUFFER_START** opcode 0x31 << 23, bit 8 = address-space
  indicator (0 = GGTT, the kernel-friendly path). Three-DWORD packet:
  header + 32-bit lo + 16-bit hi. Append after the existing NOOP run
  and bump RING_TAIL.
- **Execlists submission** (Gen11+: `EXECLIST_SQ_CONTENTS` +
  `EXECLIST_CONTROL = 1`) is the path to multi-context. Skip until a
  second client wants the GPU — bare ring covers the single-context
  demo.
- **QEMU caveat:** no Intel-iGPU device model. This is a real-HW
  milestone — Skylake / KBL / TGL NUC + serial UART.

Primary sources: [bwidawsk.net GGTT-part-1](https://bwidawsk.net/blog/2014/6/the-global-gtt-part-1/),
[i915 intel_execlists_submission.c](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/i915/gt/intel_execlists_submission.c),
[i915 intel_engine_regs.h](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/i915/gt/intel_engine_regs.h),
[Intel 12th-gen datasheet — GTTMMADR](https://edc.intel.com/content/www/us/en/design/publications/12th-generation-core-processor-datasheet-volume-2-of-2/graphics-translation-table-memory-mapped-range-address-gttmmadr1-0-2-0-pci-offse/).

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

- **Format-aware texel access.** `OpImageRead` / `OpImageWrite`
  execute today against the implicit BGRA8 backing. To honour
  the other five formats DuetOS recognises (R8_UNORM, R8G8_UNORM,
  R8G8B8A8_UNORM, R16_UNORM, R32G32B32A32_SFLOAT), `VkCreateImage`
  needs to grow a format parameter and `ImageRecord` needs to
  carry it.
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
