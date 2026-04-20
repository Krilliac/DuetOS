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
 * scheduler loop end-to-end. It exposes two levels of access:
 *   - `Ps2KeyboardRead()`: raw scan code bytes, one per call. Lossless
 *     end-to-end path; suitable for a debugger or an alternate
 *     keymap consumer.
 *   - `Ps2KeyboardReadChar()`: blocks until a key press resolves to a
 *     printable ASCII byte using the built-in US QWERTY translator
 *     (scan code set 1 → ASCII, tracking LShift / RShift / Caps Lock).
 *     Releases, pure-modifier transitions, and unmapped keys are
 *     swallowed; the call only returns on real press events.
 *
 * Scope limits that will be fixed in later commits:
 *   - No 8042 reset / init sequence; trusts the firmware to have left
 *     the controller in a usable state.
 *   - Scan code set 1 only. Set 2 (post-init default for some
 *     controllers) would need either a translation table or an
 *     explicit "set 1" command sent to the 8042.
 *   - Translator is US QWERTY, no alternate layouts.
 *   - Extended (0xE0-prefixed) keys — arrow keys, right-side mods,
 *     multimedia — are consumed and dropped. Ctrl / Alt / Meta are
 *     tracked-as-held by neither API today; a future KeyEvent
 *     interface will carry them as a modifier bitmap.
 *   - Single reader for raw bytes. `Ps2KeyboardRead` blocks on one
 *     wait queue; two concurrent readers would fight over bytes.
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

/// Block the calling task until the next press resolves to an ASCII
/// character via the built-in US QWERTY translator, then return it.
/// Never returns 0: modifier transitions, releases, and unmapped
/// keys are consumed internally and the call loops. Uses the same
/// ring + wait queue as `Ps2KeyboardRead` — concurrent callers of
/// the two APIs race for bytes and will see interleaved / partial
/// results. Pick one API per reader thread.
char Ps2KeyboardReadChar();

/// Lifetime counters for diagnostics / tests.
struct Ps2Stats
{
    u64 irqs_seen;      // total IRQ 1 deliveries
    u64 bytes_buffered; // bytes that made it into the ring
    u64 bytes_dropped;  // bytes lost to buffer-full condition
};
Ps2Stats Ps2KeyboardStats();

} // namespace customos::drivers::input
