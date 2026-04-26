#pragma once

#include "util/types.h"

/*
 * DuetOS x86_64 Global Descriptor Table + TSS.
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

namespace duetos::arch
{

inline constexpr u16 kKernelCodeSelector = 0x08;
inline constexpr u16 kKernelDataSelector = 0x10;
inline constexpr u16 kTssSelector = 0x18;
// Slot 5 holds the user code descriptor (DPL=3). Consumer selectors
// must carry the RPL=3 bits, so the value the CPU sees is 0x2B, not
// 0x28. Same for user data in slot 6 — 0x33, not 0x30.
inline constexpr u16 kUserCodeSelector = 0x28 | 0x3;
inline constexpr u16 kUserDataSelector = 0x30 | 0x3;

// IST indices are 1..7 in the IDT (0 means "use the RSP-for-this-DPL
// from TSS"); we reserve 1..3 for the three critical faults.
inline constexpr u8 kIstDoubleFault = 1;
inline constexpr u8 kIstMachineCheck = 2;
inline constexpr u8 kIstNmi = 3;

/// Install the kernel GDT and reload all segment registers. Must be called
/// before IdtInit(), because the IDT entries reference kKernelCodeSelector.
void GdtInit();

/// FNV-1a hash over the 7-entry GDT + the BSP TSS's critical
/// fields (RSP0 + IST slots). Used by the runtime invariant
/// checker to flag any silent modification — rootkit-style
/// segment swap, stray write onto the descriptor table, etc.
/// Baseline captured once at `RuntimeCheckerInit`. RSP0 is
/// excluded: the scheduler legitimately rewrites it on every
/// user-mode switch, so hashing it would flag every task
/// switch as a "modification".
u64 GdtHash();

/// Raw pointer to the 7-entry GDT. The runtime-checker Heal
/// path uses it to snapshot + restore the table verbatim when
/// a descriptor swap is detected. NOT exposed as general API:
/// writing to this bypasses every safety check GdtInit makes.
u64* GdtRawBase();

/// Fill the BSP's TSS descriptor + body, then `ltr` the task register.
/// Must be called after GdtInit (the TSS occupies GDT slots 3-4) and
/// BEFORE the IDT entries for #DF / #MC / #NMI are patched to reference
/// their IST indices. Per-AP TSS install comes with SMP scheduler join
/// — each AP needs its own TSS + IST stacks.
void TssInit();

/// Update the BSP TSS's RSP0 slot. The CPU consults this value on every
/// user→kernel privilege transition (interrupt or trap from ring 3) to
/// pick the stack on which to deliver the trap frame. Must point at the
/// TOP of a valid kernel stack for whichever task is about to enter
/// ring 3 — a stale or zero value here turns the next interrupt in user
/// mode into a double fault.
///
/// Multi-task ring-3 correctness requires the scheduler to call this
/// whenever it switches IN to a user-mode-capable task; v0's single
/// ring-3 smoke task sets it once at entry and never revisits.
void TssSetRsp0(u64 rsp0);

/// Check whether all three IST stack canaries are still the magic
/// pattern planted by TssInit. Returns false if any has been
/// overwritten — indicates a stack blown through its 4 KiB budget,
/// which would otherwise silently corrupt adjacent BSS. Called by
/// the crash-dump path so IST overflow is a named diagnostic
/// instead of mystery heap / data corruption.
bool IstStackCanariesIntact();

} // namespace duetos::arch
