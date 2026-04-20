#pragma once

#include "../../core/types.h"

/*
 * CustomOS x86_64 Global Descriptor Table + TSS.
 *
 * The boot.S handoff leaves us on a temporary 3-entry GDT (null / kcode /
 * kdata). `GdtInit()` replaces it with the persistent kernel GDT and
 * reloads the segment registers so all downstream code runs against a
 * single canonical table.
 *
 * The GDT now holds 5 slots: null / kcode / kdata / TSS-low / TSS-high
 * (a long-mode TSS descriptor is 16 bytes, so it occupies two slots).
 * `TssInit()` fills the TSS descriptor at runtime, initialises the TSS
 * body with per-IST stack pointers, and loads the task register.
 *
 * IST assignment:
 *   IST1 — #DF  (double fault, vector 8)
 *   IST2 — #MC  (machine check, vector 18)
 *   IST3 — #NMI (vector 2)
 *
 * Each IST stack is dedicated so these three vectors can never corrupt
 * the currently-running task's stack even if the fault happens while
 * that stack was the bug. IDT entries are patched to reference the
 * matching IST index via `IdtSetIst`.
 *
 * Context: kernel, called exactly once during early bring-up.
 */

namespace customos::arch
{

inline constexpr u16 kKernelCodeSelector = 0x08;
inline constexpr u16 kKernelDataSelector = 0x10;
inline constexpr u16 kTssSelector = 0x18;

// IST indices are 1..7 in the IDT (0 means "use the RSP-for-this-DPL
// from TSS"); we reserve 1..3 for the three critical faults.
inline constexpr u8 kIstDoubleFault = 1;
inline constexpr u8 kIstMachineCheck = 2;
inline constexpr u8 kIstNmi = 3;

/// Install the kernel GDT and reload all segment registers. Must be called
/// before IdtInit(), because the IDT entries reference kKernelCodeSelector.
void GdtInit();

/// Fill the BSP's TSS descriptor + body, then `ltr` the task register.
/// Must be called after GdtInit (the TSS occupies GDT slots 3-4) and
/// BEFORE the IDT entries for #DF / #MC / #NMI are patched to reference
/// their IST indices. Per-AP TSS install comes with SMP scheduler join
/// — each AP needs its own TSS + IST stacks.
void TssInit();

/// Check whether all three IST stack canaries are still the magic
/// pattern planted by TssInit. Returns false if any has been
/// overwritten — indicates a stack blown through its 4 KiB budget,
/// which would otherwise silently corrupt adjacent BSS. Called by
/// the crash-dump path so IST overflow is a named diagnostic
/// instead of mystery heap / data corruption.
bool IstStackCanariesIntact();

} // namespace customos::arch
