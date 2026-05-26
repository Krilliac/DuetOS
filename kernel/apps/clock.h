#pragma once

#include "util/types.h"
#include "drivers/video/widget.h"

/*
 * DuetOS Clock — v0.
 *
 * A wall-clock window that renders HH:MM:SS in 7-segment
 * style digits instead of the 8x8 text glyphs the other apps
 * use. Serves two purposes:
 *   - Proves the content-draw path can host purely graphical
 *     (non-font) rendering — each digit is composed of seven
 *     filled rectangles.
 *   - Auto-refreshes via the ui-ticker's 1 Hz recompose, so
 *     the second counter advances with no user interaction.
 *
 * No input routing: the clock is read-only. Arrow keys,
 * printable chars, and clicks on the window body are all
 * ignored.
 *
 * Context: kernel. Draw is called under the compositor lock.
 */

namespace duetos::apps::clock
{

/// Install the content-draw callback on `handle`. No other
/// state — the time is fetched from RtcRead on every paint.
void ClockInit(duetos::drivers::video::WindowHandle handle);

/// Handle of the clock window. Present for symmetry with the
/// other apps; not used by input routers (clock takes no input).
duetos::drivers::video::WindowHandle ClockWindow();

/// Keyboard handler. Tab cycles between Clock and Stopwatch
/// modes. In Stopwatch mode, Space toggles run/stop and `R`
/// resets accumulated time to zero. Returns true iff consumed.
bool ClockFeedChar(char c);

/// Boot-time self-test: verifies the digit-segment table is
/// consistent (every digit 0-9 resolves to a non-zero mask,
/// every colon position renders within bounds). Prints one
/// PASS/FAIL line to COM1.
void ClockSelfTest();

/// Pass D umbrella accessor — true iff the most recent
/// ClockSelfTest() invocation ran every check (including
/// the synthetic toolbar button click) without error.
bool ClockSelfTestPassed();

/// Mouse-event entry point for the Pass D toolbar + footer
/// label. Called from the boot-time mouse-reader thread on
/// every motion packet. Edge-detects left-button press /
/// release internally and dispatches MouseMove / MouseDown /
/// MouseUp into the WidgetGroup so AppButton hover state tracks
/// the cursor on tactility themes. The LED-style digit face
/// stays raw paint (carve-out) — toolbar mode buttons are the
/// only widget-dispatched events; the digit face has no per-
/// pixel click semantics. No-op before ClockInit has wired a
/// window.
void ClockMouseInput(duetos::u32 cursor_x, duetos::u32 cursor_y, duetos::u8 button_mask);

} // namespace duetos::apps::clock
