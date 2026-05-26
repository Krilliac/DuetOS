#pragma once

#include "drivers/video/widget.h"
#include "util/types.h"

/*
 * DuetOS Character Map — v0.
 *
 * A grid view of every printable ASCII codepoint (0x20 .. 0x7E)
 * + every glyph the bitmap font defines beyond ASCII (the
 * font8x8 table covers a small set of CP437-style box-drawing
 * + accented letters in the 0x80..0xFF range — see
 * `kernel/drivers/video/font8x8.cpp`).
 *
 * Purpose:
 *   - Discoverability — the operator sees every glyph the
 *     framebuffer can paint at a glance, instead of typing one
 *     character at a time into Notes to find out.
 *   - Copy-to-clipboard — pressing Enter on a selected cell
 *     copies that character's UTF-8 byte to the clipboard, so
 *     it can be pasted into Notes / Calculator / Browser /
 *     Files-rename via the standard Ctrl+V path.
 *
 * Layout: a 16-column grid of 24×24 cells. Each cell paints
 * the codepoint at scale=2 (8×8 glyph → 16×16 pixels) centred
 * inside the cell. The current selection is drawn with a
 * 2-pixel accent border. The header strip shows the selected
 * codepoint in hex + decimal + the literal character itself.
 *
 * Controls (when this window is focused):
 *   Arrows / H J K L  — move selection by one cell
 *   PageUp / PageDown — scroll grid by one page
 *   Home / End        — jump to first / last codepoint
 *   Enter / Space     — copy selected char to clipboard
 *   Tab               — toggle ASCII (0x20..0x7E) vs full
 *                        (0x20..0xFF) range
 *
 * Context: kernel. DrawFn runs under the compositor lock.
 */

namespace duetos::apps::charmap
{

/// Install CharMap state on `handle`. No initial scan needed —
/// the codepoint range is fixed; only selection state matters.
void CharMapInit(duetos::drivers::video::WindowHandle handle);

/// Handle of the CharMap window, or `kWindowInvalid` until Init.
duetos::drivers::video::WindowHandle CharMapWindow();

/// Keyboard handlers — chars + arrow / nav keys. Both return
/// true iff consumed.
bool CharMapFeedChar(char c);
bool CharMapFeedArrow(duetos::u16 keycode);

/// Boot self-test. Validates the codepoint <-> grid-cell
/// mapping (round-trip) and the clipboard copy helper. Pure
/// compute; runs unconditionally. Also drives a synthetic click
/// through the Pass D toolbar's WidgetGroup to verify the
/// dispatch chain is wired end-to-end.
void CharMapSelfTest();

/// Pass D umbrella accessor — true iff the most recent
/// CharMapSelfTest() invocation ran every check (including the
/// synthetic toolbar button click) without error.
bool CharMapSelfTestPassed();

/// Mouse-event entry point for the Pass D toolbar + labels.
/// Called from the boot-time mouse-reader thread on every
/// motion packet. Edge-detects left-button press / release
/// internally and dispatches MouseMove / MouseDown / MouseUp
/// into the WidgetGroup so AppButton hover state tracks the
/// cursor on tactility themes. The raw codepoint grid (16-col
/// 24×24 cells with selection border + scale-2 glyphs) stays
/// raw paint (carve-out) — per-cell AppButton would register
/// 224 widget bounds in full-range mode and AppPanel/AppLabel
/// have no per-cell centred-glyph model. Selection is reached
/// via the keyboard arrow / Tab paths. No-op before
/// CharMapInit has wired a window.
void CharMapMouseInput(duetos::u32 cursor_x, duetos::u32 cursor_y, duetos::u8 button_mask);

} // namespace duetos::apps::charmap
