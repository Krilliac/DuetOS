#pragma once

#include "mm/frame_allocator.h"
#include "mm/zone.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — DMA-coherent buffer allocation (v0).
 *
 * The single primitive every device driver needs for ring buffers,
 * descriptor lists, command queues, and shared scratch. Wraps
 * `AllocateContiguousFramesInRange` (zone-clamped contiguous run)
 * with a kernel-virtual alias the CPU can read/write directly, and
 * the cache-maintenance hooks any future non-coherent platform port
 * (ARM64) will need to fill in.
 *
 *   x86_64 design choice — coherent direct-map alias
 *
 *   On x86_64 the PCIe interconnect snoops the CPU's caches; a DMA
 *   write from a device is observed by the CPU at the cached alias
 *   without an explicit invalidate, and a CPU write through the
 *   cached alias is seen by the device on its next read without an
 *   explicit flush. So `virt` here is the higher-half direct-map
 *   alias (cacheable WB), NOT a UC remap. This matches what Linux
 *   `dma_alloc_coherent()` returns on x86 (also cached). On ARM64
 *   the same call returns either a UC mapping or a non-coherent
 *   buffer with explicit cache maintenance — when DuetOS gets an
 *   ARM64 port, this TU is where the per-arch divergence lands.
 *
 *   `DmaSyncForDevice` / `DmaSyncForCpu` are therefore compiler
 *   barriers (mfence-equivalent) on x86_64. Drivers should still
 *   call them around every device-visible transition: it's the
 *   only way the same source compiles correctly on a future
 *   non-coherent port.
 *
 *   Direct-map size constraint
 *
 *   The boot direct map covers the first 1 GiB of physical RAM
 *   only. The frame-allocator bitmap reserves frames past that
 *   window as used (see `kernel/mm/frame_allocator.cpp` near the
 *   "frame past direct map" panic), so every frame the allocator
 *   actually hands out is reachable through `PhysToVirt` already.
 *   Dma (16 MiB) and Dma32 (4 GiB) zones sit comfortably inside
 *   this. If a future port grows the direct map (or adds a UC
 *   remap fallback), the v0 cached-only path here turns into the
 *   fast path and the slow path drops in alongside.
 *
 *   What this is NOT for
 *
 *   - Userland DMA. v0 keeps DMA buffer ownership in the kernel;
 *     userland reaches devices through the device's syscall
 *     surface (read/write/ioctl/mmap with explicit cap gating),
 *     not by mapping a coherent buffer into a process directly.
 *   - Scatter-gather descriptors. The first wave of consumers
 *     (Wi-Fi rings, AHCI command list, HDA CORB) all want a single
 *     contiguous region. S/G chains land when the second wave
 *     demands it.
 *   - IOMMU-isolated buffers. v0 assumes identity-mapped DMA
 *     (Intel VT-d / AMD-Vi off). When IOMMU support lands the
 *     `phys` field becomes "device-visible address" and a separate
 *     IOVA allocator backs it.
 *
 * Context: kernel. Init() runs once after `PagingInit` + `KernelHeapInit`.
 * Allocations are safe from any kernel context that may sleep; the
 * underlying frame-allocator scan is O(n) but small at v0 RAM sizes.
 * Not safe to call from IRQ context (frame allocator is not yet
 * IRQ-locked).
 */

namespace duetos::mm
{

/// A coherent DMA buffer. `phys` is the device-visible address.
/// `virt` is the kernel-VA alias the CPU reads/writes through; on
/// x86_64 it's the cached higher-half direct map.
struct DmaBuffer
{
    PhysAddr phys; ///< Page-aligned physical base (device-visible).
    void* virt;    ///< Kernel-VA alias for CPU access.
    u64 bytes;     ///< Allocated size in bytes; rounded up to a multiple of kPageSize.
    Zone zone;     ///< Zone the allocation came from (for FreeDmaCoherent bookkeeping).
};

/// Allocate `bytes` of physically-contiguous DMA-coherent memory in
/// `zone`. `bytes` is rounded up to the next page boundary; the
/// resulting buffer is zeroed before return (no info-leak from
/// previous owners).
///
/// Returns `ErrorCode::InvalidArgument` if `bytes == 0` or `zone` is
/// out of range; `ErrorCode::OutOfMemory` if no in-range contiguous
/// run is free; `ErrorCode::Unsupported` for `Zone::Mmio` (which has
/// no backing pool by design).
::duetos::core::Result<DmaBuffer> AllocDmaCoherent(u64 bytes, Zone zone);

/// Return a buffer previously obtained from `AllocDmaCoherent`.
/// Idempotent w.r.t. a default-constructed `DmaBuffer{}` (no-op).
/// Mismatched `bytes` is a kernel bug — frames outside the original
/// run will be marked free silently (matches `FreeContiguousFrames`).
void FreeDmaCoherent(const DmaBuffer& buf);

/// Synchronise CPU writes so the device will observe them on its
/// next read of `[offset, offset+len)`. On x86_64 this is a
/// compiler/CPU memory barrier (mfence) — PCIe snoops the cache.
/// Required for portability to future non-coherent architectures.
void DmaSyncForDevice(const DmaBuffer& buf, u64 offset, u64 len);

/// Synchronise so CPU reads of `[offset, offset+len)` observe
/// writes the device performed via DMA. On x86_64 this is a
/// compiler/CPU memory barrier (lfence) — see DmaSyncForDevice.
void DmaSyncForCpu(const DmaBuffer& buf, u64 offset, u64 len);

/// Boot-time self-test. Allocates + writes a marker pattern + frees
/// in each viable zone (Dma, Dma32, Normal); asserts that the
/// per-zone physical-address ceiling holds; asserts that
/// `Zone::Mmio` cleanly returns `NotSupported`. Panics on mismatch.
void DmaSelfTest();

} // namespace duetos::mm
