#pragma once

#include "../../core/types.h"

/*
 * CMOS real-time clock — v0.
 *
 * Reads wall time from the MC146818-compatible CMOS RTC every
 * chipset in the IBM-PC lineage (and every hypervisor emulating
 * one) exposes on I/O ports 0x70 / 0x71. Single read API —
 * `RtcRead` waits out any in-progress firmware update, reads
 * all six fields, and converts BCD → binary / 12-hour → 24-hour
 * as dictated by the Status-B register the firmware published.
 *
 * Scope limits:
 *   - Read-only. Setting wall time would require re-deriving
 *     Status-B semantics + UIP race handling for writes, and
 *     we don't have a use case yet.
 *   - No periodic-interrupt mode (IRQ 8). The periodic tick
 *     already comes from the LAPIC timer; the RTC IRQ would
 *     just be a second timer source.
 *   - Century register is firmware-specific (ACPI FADT
 *     publishes the offset if present). v0 assumes 20xx —
 *     fine until ~2100.
 *   - Not SMP-safe: two cores racing the 0x70/0x71 port pair
 *     would corrupt each other's reads. A spinlock lands when
 *     AP user code lands.
 *
 * Context: kernel. Safe from any task-level caller; the UIP
 * wait can busy-spin for up to ~1 ms per read.
 */

namespace customos::arch
{

struct RtcTime
{
    u8 hour;   // 0..23
    u8 minute; // 0..59
    u8 second; // 0..59
    u8 day;    // 1..31
    u8 month;  // 1..12
    u16 year;  // e.g. 2026
};

/// Sample the RTC and populate `out` with decoded fields.
/// Safe no-op on nullptr.
void RtcRead(RtcTime* out);

} // namespace customos::arch
