#pragma once

#include "util/types.h"

/*
 * Kernel-half PML4 integrity trip-wire.
 *
 * Background. A previous slice (3423df7) traced a deterministic emulator-
 * only triple-fault to a pair of kernel-half pages losing their PT
 * mappings under heavy klog volume during PE-import resolution
 * (pe-winapi / pe-winkill smoke profiles). The first fault's CR2 was the
 * .bss VA of fs::fat32::g_fat32_recursion (page not present) and the
 * cascade landed on isr_14's .text page also being missing. Multiple
 * kernel-half pages losing their mappings simultaneously is consistent
 * with a kernel-half PML4 / PDPT / PD entry being mutated to zero (or
 * to some unrelated physical address) by a stray write somewhere along
 * the FAT32 / NVMe critical path. The previous slice papered over the
 * trigger by skipping the FAT32 klog sink under emulator, but did not
 * pinpoint which write performs the mutation.
 *
 * What this trip-wire does. After all early-boot kernel-half mapping is
 * finalised (direct map fully populated, MMIO arena reservations done
 * for the boot drivers), `KernelHalfWatchArm()` snapshots all 256
 * kernel-half PML4 entries (indices 256..511) into a small static
 * array. From that point on, `KernelHalfWatchCheck(callsite_label)`
 * re-reads those entries and panics with the offending index + before /
 * after values if any of them drifts. The accessed bit (bit 5) is
 * masked out of the comparison — the CPU may set it on a present
 * entry as a side effect of any access below it, and that's not a
 * mutation we care to flag.
 *
 * Why PML4 only (for now). PML4 entries are the apex of the kernel-
 * half page-table tree. Mutating one would unmap a 512 GiB swath of
 * kernel VAs at one stroke; the symptom seen above (multiple pages
 * gone simultaneously across .bss + .text) matches a top-of-tree
 * mutation more cleanly than a single-PTE zeroing. Lower-level (PDPT /
 * PD / PT) drift catches a wider class of corruption but at a much
 * higher snapshot cost, and we'd want the PML4 tier to fire first
 * anyway to localise the level. A follow-up slice can extend the
 * watch to the PDPT/PD pages reachable from each present PML4 entry.
 *
 * Cost. 256 × 8 bytes = 2 KiB of .bss. Each Check() walks 256 u64s
 * in cache. Cheap enough to leave armed unconditionally on the
 * suspect call sites (Fat32Guard ctor + klog FileSink). Not free
 * enough to pepper everywhere; place at clear "across this call,
 * the kernel half should not change" boundaries.
 *
 * Non-goals. This is a regression trip-wire, not a fix. The
 * underlying mutation source is still unknown — once the trip-wire
 * fires, the panic banner names the offending entry and the call
 * site it tripped at, which is what the previous slice identified
 * as the missing piece. Once the root cause is found and fixed,
 * the trip-wire stays in as defence-in-depth.
 *
 * Context. Kernel-only. Safe from any non-IRQ context after
 * `KernelHalfWatchArm()` has run; no allocations along the way.
 * Calling Check() before Arm() is a no-op (returns without panic),
 * so wiring in a check at a call site that runs before boot
 * completes is safe.
 */

namespace duetos::mm
{

/// Capture the current kernel-half PML4 entries and arm the trip-wire.
/// Idempotent within a boot — re-arming overwrites the snapshot, so a
/// caller that knowingly extends the kernel half post-arm can re-arm
/// rather than tripping the wire on a legitimate change. Logs a single
/// `[mm/kpml4-watch] armed` line so the boot transcript records when
/// the trip-wire became live.
void KernelHalfWatchArm();

/// Re-read the kernel-half PML4 entries and panic if any of them
/// has drifted from the snapshot. `callsite_label` is included in the
/// panic banner so the trip-wire pinpoints the entry path that
/// observed the corruption (typically: "fat32-guard-enter",
/// "klog-filesink-enter", etc.). No-op if the snapshot has not been
/// armed yet.
void KernelHalfWatchCheck(const char* callsite_label);

/// True iff `KernelHalfWatchArm` has been called. Exposed so callers
/// can short-circuit Check() loops that they know fire many times
/// per second (e.g. a per-character log sink).
bool KernelHalfWatchArmed();

} // namespace duetos::mm
