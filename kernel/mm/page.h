#pragma once

#include "util/types.h"
#include "mm/frame_allocator.h"

/*
 * DuetOS — kernel direct-map helpers.
 *
 * Until a managed page-table API exists, the kernel relies on the static
 * higher-half mapping installed by boot.S: the first 1 GiB of physical RAM
 * is aliased at KERNEL_VIRTUAL_BASE (0xFFFFFFFF80000000). These helpers
 * convert between physical and virtual addresses inside that window.
 *
 * Constraints (v0):
 *   - Only valid for physical addresses in [0, 1 GiB).
 *   - Only valid for virtual addresses in [KERNEL_VIRTUAL_BASE, +1 GiB).
 *   - Out-of-range inputs trigger a kernel panic — callers that need to map
 *     arbitrary physical pages must wait for the page-table API.
 *
 * Context: kernel. Safe at any IRQ level — purely arithmetic.
 */

namespace duetos::mm
{

inline constexpr u64 kKernelVirtualBase = 0xFFFFFFFF80000000ULL;
inline constexpr u64 kDirectMapBytes = 1ULL * 1024 * 1024 * 1024; // 1 GiB

/// Translate a physical address inside the 1 GiB direct map to its kernel
/// virtual alias. Panics if `phys >= 1 GiB`.
void* PhysToVirt(PhysAddr phys);

/// Translate a kernel virtual address inside the direct map back to its
/// physical address. Panics if the input is outside the direct-map window.
PhysAddr VirtToPhys(const void* virt);

} // namespace duetos::mm
