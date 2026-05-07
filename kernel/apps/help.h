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
 * Static content — no live data, no input handling beyond the
 * usual chrome dispatch. Scrollable in v1 if the binding count
 * grows past one screenful; v0 just paints a fixed list and
 * trusts the window to be large enough.
 *
 * Why both Help-window and Help-console: the console version
 * survives across an F1 chord even when the Help window is
 * closed (e.g. mid-shell-debug). The windowed version is the
 * better discovery surface for someone seeing DuetOS for the
 * first time. They share the same reference list at compile
 * time — see `kernel/core/main.cpp::PrintShortcutHelp` for the
 * console form.
 *
 * Context: kernel. DrawFn runs under the compositor lock.
 */

namespace duetos::apps::help
{

/// Install Help state on `handle`. Registers the content-draw
/// callback; no widgets, no per-app keyboard wiring.
void HelpInit(duetos::drivers::video::WindowHandle handle);

/// Handle of the Help window, or `kWindowInvalid` until Init.
duetos::drivers::video::WindowHandle HelpWindow();

/// Boot self-test. Validates that every section has at least
/// one line and the line-table count matches the static array.
/// Pure compute; runs unconditionally.
void HelpSelfTest();

/// Printable-key feed. Letters / digits / space / punctuation
/// append to the live filter; Backspace removes the last char.
/// Returns true iff the char was consumed. The filter substring
/// matches case-insensitively against any row text; section
/// headers are pulled in when at least one of their following
/// rows matches, so the filtered result still reads as
/// grouped sections.
bool HelpFeedChar(char c);

} // namespace duetos::apps::help
