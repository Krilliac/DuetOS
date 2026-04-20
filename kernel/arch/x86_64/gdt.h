#pragma once

#include "../../core/types.h"

/*
 * CustomOS x86_64 Global Descriptor Table.
 *
 * The boot.S handoff leaves us on a temporary 3-entry GDT (null / kcode /
 * kdata). `GdtInit()` replaces it with the persistent kernel GDT and
 * reloads the segment registers so all downstream code runs against a
 * single canonical table.
 *
 * Today's GDT is deliberately minimal — null / kernel code / kernel data
 * and nothing else. User-mode segments and the TSS (with IST stacks) land
 * when userland and multi-stack interrupt handling land, not before.
 *
 * Context: kernel, called exactly once during early bring-up.
 */

namespace customos::arch
{

inline constexpr u16 kKernelCodeSelector = 0x08;
inline constexpr u16 kKernelDataSelector = 0x10;

/// Install the kernel GDT and reload all segment registers. Must be called
/// before IdtInit(), because the IDT entries reference kKernelCodeSelector.
void GdtInit();

} // namespace customos::arch
