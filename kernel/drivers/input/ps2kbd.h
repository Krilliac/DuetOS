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

/// Non-blocking: return one pending ASCII char, or 0 if the ring
/// is empty. Used by the security guard prompt to poll both COM1
/// and the keyboard in one loop without taking the lock away from
/// the shell reader task. Releases / modifier scancodes consume a
/// byte and return 0 (the release is still swallowed).
char Ps2KeyboardTryReadChar();

// ---------------------------------------------------------------
// Higher-level KeyEvent API.
//
// Supersedes Ps2KeyboardReadChar for anything beyond "echo text to
// a console": reports press AND release edges, carries a modifier
// bitmask (Shift / Ctrl / Alt / Meta / Caps Lock), and exposes
// non-ASCII keys (arrows, Home/End/PgUp/PgDn, Insert/Delete, F1..F12,
// Esc, Enter, Backspace, Tab) as numeric codes. Needed for shells,
// text-input widgets, and any GUI that wants to handle Ctrl+C or
// arrow navigation.
// ---------------------------------------------------------------

enum KeyModifier : u8
{
    kKeyModShift = 1U << 0,
    kKeyModCtrl = 1U << 1,
    kKeyModAlt = 1U << 2,
    kKeyModMeta = 1U << 3, // "Windows" / "Super" / "Cmd"
    kKeyModCapsLock = 1U << 4,
};

// Logical key codes. ASCII-printable characters (0x20..0x7E) pass
// through as themselves, in the `event.code` field. Non-printable
// keys use values starting at 0x100 so they don't collide with
// ASCII. Release events set `event.is_release`; press events
// (including auto-repeat from the controller) clear it.
enum KeyCode : u16
{
    kKeyNone = 0,

    kKeyEsc = 0x1B,
    kKeyBackspace = 0x08,
    kKeyTab = 0x09,
    kKeyEnter = 0x0A,

    // Non-ASCII special keys. High enough to never collide with
    // any ASCII byte a legitimate keypress could produce.
    kKeyArrowUp = 0x100,
    kKeyArrowDown,
    kKeyArrowLeft,
    kKeyArrowRight,
    kKeyHome,
    kKeyEnd,
    kKeyPageUp,
    kKeyPageDown,
    kKeyInsert,
    kKeyDelete,
    kKeyF1,
    kKeyF2,
    kKeyF3,
    kKeyF4,
    kKeyF5,
    kKeyF6,
    kKeyF7,
    kKeyF8,
    kKeyF9,
    kKeyF10,
    kKeyF11,
    kKeyF12,
};

struct KeyEvent
{
    u16 code;        // KeyCode value or printable-ASCII byte
    u8 modifiers;    // bitmask of KeyModifier
    bool is_release; // false = press (or auto-repeat), true = release
    u8 _pad;
};

/// Block the calling task until the next keyboard edge (press or
/// release) resolves to a KeyEvent. Modifier-only transitions update
/// internal state and are returned as events with `code == kKeyNone`
/// so callers can render "Ctrl held" UI cues without polling. For
/// a simpler "give me the next typed character" loop, keep using
/// Ps2KeyboardReadChar — both APIs share the raw ring buffer, so
/// a single reader thread should pick ONE.
KeyEvent Ps2KeyboardReadEvent();

/// Lifetime counters for diagnostics / tests.
struct Ps2Stats
{
    u64 irqs_seen;      // total IRQ 1 deliveries
    u64 bytes_buffered; // bytes that made it into the ring
    u64 bytes_dropped;  // bytes lost to buffer-full condition
};
Ps2Stats Ps2KeyboardStats();

/// External key-event injection — lets another input driver push
/// pre-cooked KeyEvents into the same queue that PS/2 feeds. Used
/// by the xHCI HID keyboard path, which produces KeyEvents
/// directly (no scancodes). Thread-safe with respect to the PS/2
/// IRQ: both paths append to a ring that Ps2KeyboardReadEvent
/// drains first (before falling back to scancode decode).
///
/// Currently single-producer-per-caller; the HID polling task is
/// the only external producer in v0. Overflow drops the oldest
/// injected event.
void KeyboardInjectEvent(const KeyEvent& ev);

} // namespace customos::drivers::input
