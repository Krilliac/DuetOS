#pragma once

#include "drivers/gpu/gpu.h"
#include "util/types.h"

/*
 * DuetOS — Intel iGPU Global GTT (GGTT) manager (Gen9–Gen12).
 *
 * The GGTT is the GPU's flat page table for global (kernel-visible)
 * graphics addresses. It lives in the UPPER HALF of BAR0 (the
 * GTTMMADR aperture): on Gen12 BAR0 is 16 MiB with PTEs starting at
 * +8 MiB; generically the PTEs begin at `mmio_size/2`. 8 MiB of PTEs
 * × 8 B = 1,048,576 entries → 4 GiB of GPU VA. Software writes PTEs
 * through the BAR alias (MMIO), never to host RAM — there is no
 * host-RAM copy the GPU reads.
 *
 * This is the foundation for batch-buffer execution (slice 3): the
 * Render Command Streamer fetches MI_BATCH_BUFFER_START's target
 * through the GGTT, so the batch and any destination surface must be
 * GGTT-mapped first.
 *
 * v0 posture — DO NOT clobber the firmware display. The UEFI GOP left
 * the panel scanning out of a framebuffer mapped in the LOW aperture
 * GGTT slots. So we scratch-fill and allocate from a HIGH window only
 * (well above the GMADR aperture), leaving the firmware's low mappings
 * intact. That keeps the screen alive while we own a private VA range.
 *
 * Verification ceiling: EncodeGgttPte is proven at compile time
 * (static_assert) + a boot self-test sentinel. GgttInit / GgttMapPage
 * touch the BAR alias and are real-hardware-only (no Intel model in
 * QEMU). See wiki/reference/GPU-Implementation-Notes.md.
 */

namespace duetos::drivers::gpu::intel
{

// GGTT PTE (Gen8 format, used Gen9–12). bit0 = present; bit1 = LM
// (local memory) — left 0 for iGPU since the page is system DRAM;
// PAT bits 0 (system-default cacheability) on Gen9–11. The address is
// the page-aligned host physical address. i915's encoder is literally
// `addr | present`; we additionally page-align the address defensively.
inline constexpr u64 kGgttPresent = 1ull << 0;
inline constexpr u64 kGgttPageMask = ~0xFFFull;

constexpr u64 EncodeGgttPte(u64 host_phys)
{
    return (host_phys & kGgttPageMask) | kGgttPresent;
}

// Initialise the GGTT manager: locate the page table at BAR0
// `mmio_size/2`, allocate a scratch page, and scratch-fill ONLY the
// high VA window we'll allocate from (NOT the whole table — the low
// slots hold the firmware framebuffer). Returns the number of slots in
// our window, or 0 on failure. Idempotent. MMIO + DMA, real-HW only.
u64 GgttInit(const GpuInfo& g);

// Map one host-physical 4 KiB page into the GGTT high window; returns
// the page-aligned GPU virtual address, or 0 on failure (not
// initialised / window exhausted / unaligned phys). MMIO, real-HW only.
u64 GgttMapPage(const GpuInfo& g, u64 host_phys);

// True once GgttInit has succeeded this boot.
bool GgttReady();

// Pure boot self-test of EncodeGgttPte. Device-independent; PASSes
// under QEMU. Emits `[gpu/intel/ggtt] selftest PASS`.
void IntelGgttSelfTest();

} // namespace duetos::drivers::gpu::intel
