#pragma once

#include "../core/types.h"
#include "../drivers/video/widget.h"

/*
 * DuetOS Calculator — v0.
 *
 * A 4x4 keypad calculator wired into the widget system.
 * Layout (left-to-right, top-to-bottom):
 *
 *     7  8  9  +
 *     4  5  6  -
 *     1  2  3  *
 *     C  0  =  /
 *
 * Semantics: flat left-to-right evaluation, no operator
 * precedence (2+3*4 = 20). Integer-only; division by zero
 * clamps to 0 and shows "ERR". The display is a 16-char
 * buffer; over-long inputs truncate.
 *
 * Input routes:
 *   - Mouse clicks — `CalculatorOnWidgetEvent(id)` is called
 *     by the mouse-reader thread whenever `WidgetRouteMouse`
 *     returns a hit whose id falls in the calculator's ID
 *     range.
 *   - Keyboard — `CalculatorFeedChar(c)` is called by the
 *     kbd-reader thread when the active window is the
 *     calculator window. Accepts '0'-'9', '+', '-', '*', '/',
 *     '=' (or Enter), 'c'/'C'/Backspace.
 *
 * Context: kernel. Both entry points assume the caller holds
 * the compositor lock — same discipline as NotesFeedChar.
 */

namespace duetos::apps::calculator
{

/// Widget-ID base. Buttons carry `kIdBase + index` where
/// index ∈ [0, 16). The mouse-reader thread compares hit IDs
/// against this range to decide whether to dispatch into
/// `CalculatorOnWidgetEvent`.
inline constexpr u32 kIdBase = 0x1000;
inline constexpr u32 kIdCount = 16;

/// Install calculator state on `handle`. Registers 16 buttons
/// owned by the window, sets the window's content-draw to the
/// display renderer, and zeroes internal state.
void CalculatorInit(duetos::drivers::video::WindowHandle handle);

/// Handle of the calculator window, or `kWindowInvalid` until
/// Init. Used by the keyboard router to decide when a key goes
/// to the calculator vs. the shell.
duetos::drivers::video::WindowHandle CalculatorWindow();

/// Mouse-click handler. `id` is a widget ID returned by
/// `WidgetRouteMouse`; if it's outside the calculator's range
/// this is a no-op. Returns true iff the ID was claimed.
bool CalculatorOnWidgetEvent(u32 id);

/// Keyboard handler. Accepts the characters documented above.
/// Returns true iff the char was consumed (caller should then
/// skip other input paths).
bool CalculatorFeedChar(char c);

/// Run three boot-time arithmetic checks ("2+3=5", "9-4=5",
/// "6*7=42") through DispatchKey + ReadDisplayAsI64 and print
/// one PASS / FAIL line to COM1. Called by main.cpp right
/// after CalculatorInit. Also clears the display afterwards
/// so the window renders with a blank "0" on first paint.
void CalculatorSelfTest();

} // namespace duetos::apps::calculator
