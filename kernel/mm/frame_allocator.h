#pragma once

#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS physical frame allocator — v0.
 *
 * Hands out 4 KiB frames of physical memory backed by a bitmap. The bitmap
 * itself lives in the first "available" region large enough to hold it that
 * sits above the kernel image (both of which are within the 1 GiB identity
 * map established by boot.S).
 *
 * Scope limits that will be fixed in later commits:
 *   - Not thread-safe. No lock today; SMP bring-up will add a spinlock.
 *   - Linear-scan allocation. Fine for boot + initial kernel plumbing;
 *     a buddy / freelist allocator lands when page-table construction
 *     starts hammering it.
 *   - Single pool. No NUMA zones, no "DMA vs normal" split.
 *
 * Context: kernel. Init() runs exactly once, after GDT + IDT are online
 * and before anything else asks for physical memory.
 */

namespace duetos::mm
{

using PhysAddr = u64;

inline constexpr u64 kPageSize = 4096;
inline constexpr u64 kPageSizeLog2 = 12;

inline constexpr PhysAddr kNullFrame = 0; // The zero frame is always reserved.

/// Parse the Multiboot2 memory map, place the bitmap, mark reserved regions
/// (kernel image, bitmap itself, Multiboot2 info page, everything below 1 MiB).
void FrameAllocatorInit(uptr multiboot_info_phys);

/// Allocate one 4 KiB frame. Returns kNullFrame on out-of-memory.
PhysAddr AllocateFrame();

/// Result-shaped sibling of `AllocateFrame`. Returns
/// `ErrorCode::OutOfMemory` on allocator exhaustion; success wraps
/// the same PhysAddr. Prefer this in new code.
inline ::duetos::core::Result<PhysAddr> TryAllocateFrame()
{
    const PhysAddr f = AllocateFrame();
    if (f == kNullFrame)
        return ::duetos::core::Err{::duetos::core::ErrorCode::OutOfMemory};
    return f;
}

/// Allocate `count` physically-contiguous 4 KiB frames. Returns the base
/// physical address of the run, or kNullFrame if no run of that length is
/// available. `count == 0` is treated as an error and returns kNullFrame.
///
/// Used by the kernel heap (which needs a contiguous virtual range backed by
/// the static higher-half direct map) and any future driver that needs a
/// contiguous DMA buffer.
PhysAddr AllocateContiguousFrames(u64 count);

/// Result-shaped sibling of `AllocateContiguousFrames`. Maps the
/// null-frame sentinel to `ErrorCode::OutOfMemory` (run not
/// available) and `count==0` to `ErrorCode::InvalidArgument`.
inline ::duetos::core::Result<PhysAddr> TryAllocateContiguousFrames(u64 count)
{
    if (count == 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    const PhysAddr f = AllocateContiguousFrames(count);
    if (f == kNullFrame)
        return ::duetos::core::Err{::duetos::core::ErrorCode::OutOfMemory};
    return f;
}

/// Return a previously-allocated frame to the pool.
void FreeFrame(PhysAddr frame);

/// Return a previously-allocated contiguous run of frames to the pool.
/// `base` must be the value returned by AllocateContiguousFrames; `count`
/// must match the original allocation. Mismatched count is a kernel bug —
/// frames outside the original run will be marked free silently.
void FreeContiguousFrames(PhysAddr base, u64 count);

/// Diagnostic counters; cheap enough to read at any time.
u64 TotalFrames();
u64 FreeFramesCount();

/// Exercise Allocate / Free / Allocate end-to-end. Intended for use during
/// boot only — prints to COM1 and halts with a [panic] message if anything
/// looks wrong.
void FrameAllocatorSelfTest();

} // namespace duetos::mm
