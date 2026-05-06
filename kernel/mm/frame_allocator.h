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

/// Allocate a 4 KiB frame whose physical address is strictly less
/// than `max_phys`. Used by per-zone allocation paths to honour
/// DMA-window constraints (e.g. a legacy ISA device wants <16 MiB,
/// most PCIe DMA engines accept <4 GiB). `max_phys == 0` is treated
/// as "no upper bound" and is identical to `AllocateFrame()`.
/// Returns kNullFrame if no in-range frame is free.
PhysAddr AllocateFrameInRange(PhysAddr max_phys);

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

/// Allocate `count` physically-contiguous 4 KiB frames whose entire run
/// sits strictly below `max_phys`. The contiguous-run sibling of
/// `AllocateFrameInRange`, used by `mm::AllocDmaCoherent` to honour the
/// per-zone DMA window (16 MiB for legacy ISA, 4 GiB for 32-bit-PCIe).
/// `max_phys == 0` is treated as "no upper bound" and is identical to
/// `AllocateContiguousFrames(count)`. Returns kNullFrame if no in-range
/// run of that length is free.
PhysAddr AllocateContiguousFramesInRange(u64 count, PhysAddr max_phys);

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

/// Test-only OOM injection. After `n_remaining` successful AllocateFrame /
/// AllocateContiguousFrames calls, the next call returns `kNullFrame` as if
/// the pool were exhausted. Decrements per call. Use 0 to disable.
///
/// Used exclusively by the loader-unwind self-tests in
/// `kernel/diag/robustness_selftest.cpp` to drive PE/ELF loaders into
/// every leg of their allocation ladder. Not for production code paths.
void FrameAllocatorSetFailAfter(u64 n_remaining);

/// Read the current value of the fail-after counter. 0 means injection is
/// disabled. Used by the self-tests to assert the injection actually fired.
u64 FrameAllocatorGetFailAfter();

/// Boot-time self-test for FrameAllocatorSetFailAfter / GetFailAfter.
/// Allocates N frames, injects OOM after one more, asserts the next
/// AllocateFrame returns kNullFrame, then verifies normal allocation
/// resumes after the counter is consumed. Frees everything it allocates.
/// Panics on regression.
void FrameAllocatorOomInjectionSelfTest();

/// Register `frame` as currently in use as a kernel page table.
/// FreeFrame consults this list and panics on any attempt to free a
/// registered PT frame — guarding against stale-pointer bugs that
/// would otherwise corrupt kernel-half page tables and triple-fault
/// the box.
///
/// SplitPsPage and similar paging-internals call this immediately
/// after AllocateFrame returns the frame they install at PD level.
/// The list is fixed-size; once full, registration becomes a no-op
/// (the guard simply doesn't catch frees of late-registered tables).
void FrameAllocatorRegisterKernelPt(PhysAddr frame);

/// True if `frame` was registered via FrameAllocatorRegisterKernelPt
/// and not subsequently unregistered. Used by FreeFrame to spot
/// stale-pointer frees of kernel page-table frames.
bool FrameAllocatorIsRegisteredKernelPt(PhysAddr frame);

} // namespace duetos::mm
