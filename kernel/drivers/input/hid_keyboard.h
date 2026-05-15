#pragma once

#include "drivers/input/ps2kbd.h"
#include "util/types.h"

/*
 * DuetOS — transport-neutral USB-HID boot-protocol keyboard decoder.
 *
 * The 8-byte boot-protocol keyboard report (HID 1.11 Appendix B.1)
 * is the same wire shape no matter which bus carried it:
 *
 *   [0]    modifier bitmap (L/R Ctrl/Shift/Alt/Meta)
 *   [1]    reserved (OEM)
 *   [2..7] up to six concurrently-held Keyboard/Keypad usage IDs,
 *          or 0x01 (ErrorRollOver) in every slot on n-key overflow
 *
 * A USB HID keyboard (xHCI interrupt-IN poll) and a Bluetooth HID
 * keyboard (HOGP ATT notification / classic HIDP DATA frame) both
 * end up holding exactly these 8 bytes. This module owns the single
 * implementation that diffs successive reports into press/release
 * `KeyEvent`s and pushes them through `KeyboardInjectEvent` — the
 * same queue PS/2 feeds. Keeping it here (not in the xHCI TU) is
 * what stops the Bluetooth stack from having to either duplicate
 * the 256-entry usage table or reach into `drivers/usb/xhci`
 * internals (CLAUDE.md subsystem-isolation rule 5 + "one source of
 * truth per resource" rule 6).
 *
 * Layout: printable keys route through the active PS/2 keymap
 * (`Ps2KeyboardActiveLowerMap` / `…UpperMap`) so a runtime layout
 * switch (US/UK/Dvorak/DE/FR/Colemak) applies to every HID keyboard
 * regardless of transport. Non-printable keys map to the `KeyCode`
 * enum.
 *
 * Threading: `HidKeyboardDiffEvents` is pure (no globals, no
 * allocation) — safe from any context. `HidKeyboardDiffAndInject`
 * additionally calls `KeyboardInjectEvent`, which is IRQ-safe.
 */

namespace duetos::drivers::input
{

// Max KeyEvents one report→report transition can produce: one
// modifier-edge event + up to six release edges + up to six press
// edges = 13. Round up.
inline constexpr u32 kHidKbMaxEventsPerDiff = 16;

/// Translate a USB-HID Keyboard/Keypad page usage ID (HUT 1.4 §10)
/// to a `KeyEvent.code`. Printable keys honour the active PS/2
/// layout; specials map to `KeyCode`. `shift` selects the
/// upper/lower keymap. Returns `kKeyNone` for unmapped usages.
u16 HidKeyboardTranslateUsage(u8 usage, bool shift);

/// Translate the HID modifier byte (report[0]) to a `KeyModifier`
/// bitmask.
u8 HidKeyboardTranslateModifiers(u8 hid_mod);

/// Pure: diff `prev`→`curr` (two 8-byte boot reports) into ordered
/// KeyEvents written to `out` (capacity `max`). Emits a
/// modifier-only event (code == kKeyNone) on any modifier-byte
/// change, then release edges, then press edges — the same order
/// the live inject path uses. Returns the event count (≤ max). A
/// null/short arg yields 0.
u32 HidKeyboardDiffEvents(const u8 prev[8], const u8 curr[8], KeyEvent* out, u32 max);

/// Diff `prev`→`curr` and push every resulting KeyEvent through
/// `KeyboardInjectEvent`. This is the transport-neutral entry the
/// xHCI HID poll task and the Bluetooth HID path both call.
void HidKeyboardDiffAndInject(const u8 prev[8], const u8 curr[8]);

/// Boot-time self-test. Drives canned report transitions through
/// `HidKeyboardDiffEvents` and KASSERTs the decoded KeyEvents
/// (press, release, modifier edge, n-key rollover, layout). Logs
/// `[hid-kbd] selftest pass` and panics on mismatch.
void HidKeyboardSelfTest();

} // namespace duetos::drivers::input
