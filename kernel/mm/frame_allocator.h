#pragma once

#include "../core/types.h"

/*
 * CustomOS physical frame allocator — v0.
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

namespace customos::mm
{

using PhysAddr = u64;

inline constexpr u64 kPageSize     = 4096;
inline constexpr u64 kPageSizeLog2 = 12;

inline constexpr PhysAddr kNullFrame = 0;  // The zero frame is always reserved.

/// Parse the Multiboot2 memory map, place the bitmap, mark reserved regions
/// (kernel image, bitmap itself, Multiboot2 info page, everything below 1 MiB).
void FrameAllocatorInit(uptr multiboot_info_phys);

/// Allocate one 4 KiB frame. Returns kNullFrame on out-of-memory.
PhysAddr AllocateFrame();

/// Return a previously-allocated frame to the pool.
void FreeFrame(PhysAddr frame);

/// Diagnostic counters; cheap enough to read at any time.
u64 TotalFrames();
u64 FreeFramesCount();

/// Exercise Allocate / Free / Allocate end-to-end. Intended for use during
/// boot only — prints to COM1 and halts with a [panic] message if anything
/// looks wrong.
void FrameAllocatorSelfTest();

} // namespace customos::mm
