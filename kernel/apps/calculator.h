#pragma once

#include "util/types.h"
#include "drivers/video/widget.h"

/*
 * DuetOS Calculator — v1.
 *
 * A 4x5 keypad calculator wired into the widget system.
 * Layout (left-to-right, top-to-bottom):
 *
 *     C   CE  <   /
 *     7   8   9   *
 *     4   5   6   -
 *     1   2   3   +
 *     0   .   =   +/-
 *
 * Semantics: flat left-to-right evaluation, no operator
 * precedence (2+3*4 = 20). Fixed-point arithmetic with 6
 * fractional digits (value × 10^6 in an i64 — no FPU in
 * kernel context), so 1/4 = 0.25 and 0.1+0.2 = 0.3. The
 * decimal point '.' begins a fractional part; bitwise /
 * factorial ops operate on the truncated integer part.
 * Division by zero and overflow show "ERR". The display is
 * a 16-char buffer; long values are clipped to the strip
 * width with a trailing '>' on screen (F-051).
 *
 * Clear keys are distinct (F-012): 'C' / Esc is a full reset;
 * 'CE' (keyboard 'e') clears the current operand only, leaving
 * the accumulator + pending operator intact, so
 * "5 + 3 CE 4 =" yields 9.
 *
 * Input routes:
 *   - Mouse clicks — `CalculatorOnWidgetEvent(id)` is called
 *     by the mouse-reader thread whenever `WidgetRouteMouse`
 *     returns a hit whose id falls in the calculator's ID
 *     range.
 *   - Keyboard — `CalculatorFeedChar(c)` is called by the
 *     kbd-reader thread when the active window is the
 *     calculator window. Accepts '0'-'9', '.', '+', '-', '*',
 *     '/', '=' (or Enter), 'c'/'C'/Backspace, plus extended
 *     bindings:
 *
 *       .        decimal point (begin fractional part)
 *       e        clear entry (current operand only; C is full reset)
 *       %        percent
 *       n / _    sign toggle
 *       m / s    memory recall / store
 *       l        memory clear
 *       a / b    memory add / sub
 *       q        sqrt (integer; negative input flips ERR)
 *       x        square (n*n; overflow flips ERR)
 *       y        abs
 *       !        factorial (capped at 20! -> i64 ceiling)
 *       r        reciprocal (1/n; zero flips ERR)
 *       &        bitwise AND (binary)
 *       |        bitwise OR  (binary)
 *       ^        bitwise XOR (binary)
 *       <        shift left  (binary; rhs in [0, 64))
 *       >        shift right (binary, arithmetic; keeps sign bit)
 *       ~        bitwise NOT (unary, one's complement)
 *
 * Context: kernel. Both entry points assume the caller holds
 * the compositor lock — same discipline as NotesFeedChar.
 */

namespace duetos::apps::calculator
{

/// Widget-ID base. Buttons carry `kIdBase + index` where
/// index ∈ [0, 20). The mouse-reader thread compares hit IDs
/// against this range to decide whether to dispatch into
/// `CalculatorOnWidgetEvent`.
inline constexpr u32 kIdBase = 0x1000;
inline constexpr u32 kIdCount = 20;

/// Install calculator state on `handle`. Registers 20 buttons
/// owned by the window, sets the window's content-draw to the
/// display renderer, and zeroes internal state.
void CalculatorInit(duetos::drivers::video::WindowHandle handle);

/// Handle of the calculator window, or `kWindowInvalid` until
/// Init. Used by the keyboard router to decide when a key goes
/// to the calculator vs. the shell.
duetos::drivers::video::WindowHandle CalculatorWindow();

/// Legacy widget-table dispatch entry point. Always returns false
/// in the migrated (Pass D) calculator — hit-testing now happens
/// inside the app via `CalculatorMouseInput` + g_calc.DispatchEvent.
/// The shim is kept so the boot-time mouse loop doesn't need a
/// site-by-site removal during the Pass D rollout.
bool CalculatorOnWidgetEvent(u32 id);

/// Mouse-event entry point for the migrated (Pass D) calculator.
/// Called from the boot-time mouse-reader thread on every motion
/// packet. Detects left-button press / release edges internally,
/// dispatches MouseDown / MouseUp / MouseMove events into the
/// app's WidgetGroup. The button hover state (visible on
/// tactility-on themes) tracks the cursor through this path. No-op
/// before `CalculatorInit` has wired a window.
void CalculatorMouseInput(u32 cursor_x, u32 cursor_y, u8 button_mask);

/// Keyboard handler. Accepts the characters documented above.
/// Returns true iff the char was consumed (caller should then
/// skip other input paths).
bool CalculatorFeedChar(char c);

/// Run boot-time arithmetic + memory + scientific + bitwise checks
/// through DispatchKey and the new app_widgets dispatch path, then
/// print `[calculator-selftest] PASS` or `FAIL` on COM1. Called by
/// boot_bringup.cpp after CalculatorInit. Clears state afterwards.
void CalculatorSelfTest();

/// Accessor for the Pass D umbrella aggregator. True iff the most
/// recent `CalculatorSelfTest()` invocation ran every check
/// (including the app_widgets click-dispatch path) without error.
bool CalculatorSelfTestPassed();

/// Memory register read-back. Exposed so SessionRestoreSave can
/// snapshot the user's stash through SESSION.CFG. The display
/// itself is intentionally not persisted (a calculator wakes
/// "fresh"); only the M slot mirrors a physical calculator's
/// sticky-memory expectation.
i64 CalculatorMemoryValue();
bool CalculatorMemorySet();

/// Restore the memory register from a saved snapshot. Used by
/// SessionRestoreApply on the next boot. Idempotent. Setting
/// `set` to false also zeroes the value to keep the two flags
/// coherent — the `M` indicator is driven off `set`.
void CalculatorMemoryRestore(i64 value, bool set);

} // namespace duetos::apps::calculator
