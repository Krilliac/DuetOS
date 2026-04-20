#pragma once

#include "../../core/types.h"

/*
 * PS/2 keyboard driver — v0.
 *
 * The simplest possible end-to-end IRQ-driven device driver. Sits on
 * the 8042 keyboard controller (I/O port 0x60 data, 0x64 status), wired
 * through the IOAPIC on the GSI mapped from ISA IRQ 1. Hands raw scan
 * codes through a ring buffer to a kernel-thread reader, which blocks
 * on a wait queue until data arrives.
 *
 * This module exists to close the full ACPI → IOAPIC → IRQ → driver →
 * scheduler loop end-to-end. It's not a finished keyboard subsystem —
 * there's no scan-code-to-keysym translation, no modifier tracking, no
 * aux (mouse) channel, no typematic configuration.
 *
 * Scope limits that will be fixed in later commits:
 *   - No 8042 reset / init sequence; trusts the firmware to have left
 *     the controller in a usable state.
 *   - Scan code set 1 / 2 auto-detection not done; we return raw bytes
 *     and let a future input layer decide.
 *   - Single reader. `Ps2KeyboardRead` blocks on one wait queue; two
 *     concurrent readers would fight over the returned byte.
 *   - Ring buffer drops oldest bytes on overflow (not newest, not
 *     block-in-IRQ — that would deadlock).
 *
 * Context: kernel. Init runs once, after IoApicInit + SchedInit.
 */

namespace customos::drivers::input
{

/// Route ISA IRQ 1 through the IOAPIC to vector 0x21, drain the 8042
/// data port of any leftover bytes, then unmask. Safe to call once.
void Ps2KeyboardInit();

/// Block the calling task until at least one scan-code byte is
/// available, then return it. If the buffer has multiple queued bytes
/// the oldest is returned; the next call returns the next. Never
/// blocks if a byte is already buffered.
u8 Ps2KeyboardRead();

/// Lifetime counters for diagnostics / tests.
struct Ps2Stats
{
    u64 irqs_seen;      // total IRQ 1 deliveries
    u64 bytes_buffered; // bytes that made it into the ring
    u64 bytes_dropped;  // bytes lost to buffer-full condition
};
Ps2Stats Ps2KeyboardStats();

} // namespace customos::drivers::input
