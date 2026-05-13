#pragma once

#include "util/types.h"

/*
 * DuetOS — early-boot progress markers.
 *
 * `BootProgress(tag)` is a synchronous diagnostic primitive: each call
 * snapshots RDTSC, prints `[progress] tag="X" delta=0x... total=0x...`
 * to COM1, then stashes the timestamp + tag for the next call. Two
 * follow-on calls produce a precise localised window even when the
 * kernel hasn't yet brought up HPET / LAPIC / scheduler / klog.
 *
 * WHY THIS EXISTS (and why klog / TraceScope / init-wedge don't suffice):
 *
 *   * `KLOG_TRACE_SCOPE` records `(name, ElapsedMicros())` into a
 *     per-scope inflight table — but `ElapsedMicros()` reads HPET,
 *     and HPET isn't online until `HpetInit()` runs late in
 *     `main.cpp`. Before then it returns 0 unconditionally.
 *
 *   * The `init-wedge` watchdog in `arch/x86_64/timer.cpp` only
 *     arms once the LAPIC timer is firing (so it can compare the
 *     serial-byte count across heartbeats). The LAPIC isn't up
 *     until `LapicInit()`, which runs ~200 lines AFTER the first
 *     subsystem in the boot path.
 *
 *   * `KBP_PROBE` requires you to know in advance which call sites
 *     are interesting — useless for "kernel hangs somewhere in a
 *     200-line init block".
 *
 * `BootProgress` works at *any* boot phase: it only needs RDTSC
 * (guaranteed by the minimum-feature gate) and the early-init
 * serial port (initialised in `arch/x86_64/serial.cpp::SerialInit`
 * which runs before `kernel_main` does anything observable).
 *
 * USAGE
 *   Drop calls at suspect points in the boot sequence:
 *
 *     duetos::diag::BootProgress("before-foo");
 *     foo_init();
 *     duetos::diag::BootProgress("after-foo");
 *
 *   If the kernel wedges, the LAST printed `[progress]` line names
 *   the marker IMMEDIATELY before the wedged step.
 *
 *   `delta` is the TSC delta from the previous BootProgress call.
 *   `total` is the TSC delta from the first BootProgress call.
 *   Both in raw cycles — convert by hand using the host CPU rate
 *   for QEMU/KVM, or the configured Bochs IPS for Bochs.
 *
 * COST
 *   ~30 cycles for RDTSC plus the cost of the SerialWrite (which
 *   under QEMU TCG is ~50 us / character via PIO). Don't sprinkle
 *   inside hot loops; this is for boot-phase coarse-grain
 *   localisation only.
 *
 * THREAD SAFETY
 *   Single-threaded by design — boot phase. No locking.
 */

namespace duetos::diag
{

/// Emit a [progress] line and update the global last-seen marker.
/// Always-on regardless of klog levels, log-floor, or release-mode
/// filtering — bypasses klog entirely and writes directly to
/// COM1 via `arch::SerialWrite`.
///
/// `tag` must point to a string literal (or otherwise outlive the
/// kernel); we store the pointer without copying.
void BootProgress(const char* tag);

} // namespace duetos::diag
