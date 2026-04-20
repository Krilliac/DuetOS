#pragma once

#include "../../core/types.h"

/*
 * CustomOS — HPET (High Precision Event Timer) driver, v0.
 *
 * Wraps the MMIO window described by the ACPI HPET table:
 *   - Capabilities register at +0x00 (read-only).
 *   - General configuration at +0x10.
 *   - Main counter at +0xF0 (64-bit, reads atomically on 64-bit
 *     parts; on 32-bit COUNT_SIZE parts we'd need to read + retry,
 *     but QEMU q35 and every modern chipset are 64-bit).
 *
 * v0 scope:
 *   - Main counter is enabled at init; drivers can poll
 *     `HpetReadCounter()` for sub-tick precision time.
 *   - Period (femtoseconds / tick) exposed via
 *     `HpetPeriodFemtoseconds()` so callers can convert counter
 *     deltas to nanoseconds without a second MMIO read.
 *   - Per-timer IRQ routing is NOT configured here — that lands
 *     when a consumer needs HPET-driven interrupts (the LAPIC
 *     timer still owns the 100 Hz scheduler tick).
 *
 * Missing features that'll land with their first consumer:
 *   - Per-timer comparator programming (for one-shot or periodic
 *     HPET-driven interrupts independent of the LAPIC timer).
 *   - Legacy replacement mode (LEG_RT_CNF bit) for PIT/RTC IRQ
 *     routing — we've already moved the tick off the PIT, so
 *     there's no callsite that cares.
 *   - 32-bit counter fallback (for the rare chipset that sets
 *     COUNT_SIZE_CAP=0). Panic-on-init would surface it
 *     immediately if we ever saw such hardware.
 *
 * Context: kernel. Run once after AcpiInit + PagingInit.
 */

namespace customos::arch
{

/// Map the HPET MMIO window, log capabilities, enable the main
/// counter. No-op (with a Warn log line) if ACPI didn't find an
/// HPET table.
void HpetInit();

/// Read the 64-bit main counter. Returns 0 if HpetInit wasn't
/// called successfully.
u64 HpetReadCounter();

/// Femtoseconds per counter tick. 1 ns = 1'000'000 fs; 10 MHz HPET
/// is 100 MHz-equivalent period = 100'000'000 fs; 14.318 MHz is
/// ~69841279 fs. Returns 0 if HpetInit wasn't called successfully.
u32 HpetPeriodFemtoseconds();

/// Basic sanity check: read the counter twice (with a bounded busy-
/// wait between) and verify it advanced and did not go backwards.
/// Panics on failure — a broken HPET counter is a firmware or
/// emulator bug worth surfacing immediately. No-op if HpetInit
/// wasn't called successfully.
void HpetSelfTest();

} // namespace customos::arch
