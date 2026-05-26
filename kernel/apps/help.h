#pragma once

#include "drivers/video/widget.h"
#include "util/types.h"

/*
 * DuetOS Help — v0.
 *
 * Windowed shortcut reference. Mirrors what `F1` and the
 * Start menu's HELP / SHORTCUTS entry print to the framebuffer
 * console, but in a persistent window the user can leave open
 * while they try the bindings.
 *
 * Pass D chrome: AppToolbar with one AppButton (CLEAR) plus
 * three AppLabels (header "DUETOS QUICK REFERENCE", live filter
 * readout, footer hint). The multi-section reference list stays
 * raw paint (carve-out) — AppListRow has no section-header model
 * and per-row colour varies (banner_fg for sections,
 * console_fg for binding rows).
 *
 * Static reference data — no live state, but keyboard input
 * appends to a live filter buffer (case-insensitive substring
 * search over the row text). The windowed surface complements
 * the console form in `kernel/core/menu_dispatch.cpp::PrintShortcutHelp`.
 *
 * Context: kernel. DrawFn runs under the compositor lock.
 */

namespace duetos::apps::help
{

/// Install Help state on `handle`. Registers the content-draw
/// callback and binds the Pass D WidgetGroup.
void HelpInit(duetos::drivers::video::WindowHandle handle);

/// Handle of the Help window, or `kWindowInvalid` until Init.
duetos::drivers::video::WindowHandle HelpWindow();

/// Boot self-test. Validates the static reference table
/// (sections non-empty, count matches), exercises the filter
/// state machine (HelpFeedChar accept / reject / backspace +
/// ContainsCi case-insensitive), and drives a synthetic click
/// through the Pass D WidgetGroup to verify the CLEAR toolbar
/// dispatch chain wipes the live filter end-to-end. Prints
/// PASS/FAIL on COM1.
void HelpSelfTest();

/// Pass D umbrella accessor — true iff the most recent
/// HelpSelfTest() invocation ran every check (including the
/// synthetic CLEAR click) without error.
bool HelpSelfTestPassed();

/// Printable-key feed. Letters / digits / space / punctuation
/// append to the live filter; Backspace removes the last char.
/// Returns true iff the char was consumed. The filter substring
/// matches case-insensitively against any row text; section
/// headers are pulled in when at least one of their following
/// rows matches, so the filtered result still reads as
/// grouped sections.
bool HelpFeedChar(char c);

/// Mouse-event entry point for the Pass D toolbar + labels.
/// Called from the boot-time mouse-reader thread on every
/// motion packet. Edge-detects left-button press / release
/// internally and dispatches MouseMove / MouseDown / MouseUp
/// into the WidgetGroup so AppButton hover state tracks the
/// cursor on tactility themes. The raw reference-list content
/// stays raw paint (carve-out) — it has no per-row click
/// semantics in v0; selection / filter management is reached
/// via the keyboard feed (HelpFeedChar) or the CLEAR toolbar
/// button. No-op before HelpInit has wired a window.
void HelpMouseInput(duetos::u32 cursor_x, duetos::u32 cursor_y, duetos::u8 button_mask);

} // namespace duetos::apps::help
