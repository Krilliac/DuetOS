#pragma once

#include "drivers/video/widget.h"
#include "util/types.h"

/*
 * DuetOS Settings — v0.
 *
 * A unified panel that aggregates the surfaces a user already
 * controls via Ctrl+Alt chord shortcuts:
 *
 *   - Theme cycle / direct picker
 *   - Active-window opacity (only meaningful when another window
 *     is active; the Settings window itself stays opaque)
 *   - Wall-clock readout (RTC, refreshed on each compose tick)
 *   - About / build banner
 *
 * The Ctrl+Alt chords still work — the Settings window is just a
 * second-class entry path so a fresh user can find these surfaces
 * without reading the Help text. Mutations all go through the
 * existing Theme* / WindowSetOpacity APIs; the app stores no
 * authoritative state of its own.
 *
 * Layout: a left column of 6 buttons spans the panel:
 *
 *     [ THEME PREV ]
 *     [ THEME NEXT ]
 *     [ OPACITY -  ]
 *     [ OPACITY +  ]
 *     [ HIGH CTRST ]
 *     [ DEFAULT    ]
 *
 * Right of the buttons, a stacked text readout shows: current
 * theme name, current active-window opacity, the wall clock, and
 * the boot version banner. The clock readout uses RtcRead on
 * every paint, so the 1 Hz compositor tick refreshes it for free.
 *
 * Input routes:
 *   - Mouse clicks — `SettingsOnWidgetEvent(id)` is called by the
 *     mouse-reader thread when WidgetRouteMouse hits a button in
 *     this app's ID range.
 *   - Keyboard — `SettingsFeedChar(c)` is called by the kbd-reader
 *     thread when the active window is the Settings window.
 *     Accepts 't' / 'T' (cycle theme), 'h' / 'H' (high contrast),
 *     '-' / '+' (opacity step), '0' (reset opacity to opaque).
 *
 * Context: kernel. Both entry points assume the caller holds the
 * compositor lock — same discipline as Calculator + Notes.
 */

namespace duetos::apps::settings
{

/// Widget-ID base. Buttons carry `kIdBase + index` where index ∈
/// [0, kIdCount). Picked at the next free 0x1000 slot above the
/// Calculator (which owns 0x1000..0x100F).
inline constexpr u32 kIdBase = 0x2000;
inline constexpr u32 kIdCount = 9;

/// Install Settings state on `handle`. Registers the buttons and
/// the content-draw callback; reads initial state lazily via the
/// Theme* / WindowGetOpacity APIs on every paint.
void SettingsInit(duetos::drivers::video::WindowHandle handle);

/// Handle of the Settings window, or `kWindowInvalid` until Init.
/// The keyboard router uses this to decide when a key goes to
/// Settings vs. the shell.
duetos::drivers::video::WindowHandle SettingsWindow();

/// Mouse-click handler. `id` is a widget ID returned by
/// `WidgetRouteMouse`; if it's outside the Settings range this is
/// a no-op. Returns true iff the ID was claimed.
bool SettingsOnWidgetEvent(u32 id);

/// Keyboard handler. Accepts the characters documented above.
/// Returns true iff the char was consumed.
bool SettingsFeedChar(char c);

/// Boot-time self-test: walks the action dispatch table for every
/// button id, asserts each action returned a stable side effect,
/// and verifies the theme cycle round-trips through the Settings
/// path. Prints one PASS/FAIL line to COM1.
void SettingsSelfTest();

} // namespace duetos::apps::settings
