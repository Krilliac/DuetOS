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
inline constexpr u32 kIdCount = 11;

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

/// Pass D umbrella accessor — true iff the most recent
/// SettingsSelfTest() invocation ran every check (including the
/// synthetic tab-strip widget click) without error.
bool SettingsSelfTestPassed();

/// Mouse-event entry point for the Pass D tab strip + footer label.
/// Called from the boot-time mouse-reader thread on every motion
/// packet. Detects left-button press / release edges internally and
/// dispatches MouseMove / MouseDown / MouseUp into the WidgetGroup
/// so AppButton hover state tracks the cursor on tactility themes.
/// No-op before SettingsInit has wired a window.
void SettingsMouseInput(duetos::u32 cursor_x, duetos::u32 cursor_y, duetos::u8 button_mask);

/// Sub-panel identifier. The Settings window's main DrawFn
/// dispatches to a sub-panel renderer; each sub-panel owns
/// its own draw + key handler. Number-key shortcuts (0..5)
/// switch panels.
enum class Panel : u8
{
    General = 0,  // existing theme / opacity / clock content
    Display = 1,  // resolution + brightness (DPMS) + theme
    Sound = 2,    // PC speaker test + future HDA volume
    Keyboard = 3, // PS/2 typematic rate + delay (session-persistent)
    Mouse = 4,    // PS/2 mouse sensitivity + double-click timing
    DateTime = 5, // RTC + timezone
    kCount,
};

/// Read the active sub-panel.
Panel SettingsActivePanel();

/// Switch sub-panel. The next compose paints the new content;
/// no immediate redraw — the ui-ticker's recompose handles it.
void SettingsSetActivePanel(Panel p);

/// Per-panel draw callback. Receives the sub-panel content
/// rectangle (excluding the side rail of buttons + the panel
/// switcher header). Each panel may freely use the rect.
using PanelDrawFn = void (*)(duetos::u32 x, duetos::u32 y, duetos::u32 w, duetos::u32 h);

/// Per-panel keyboard handler. `c` is the printable char
/// (already stripped of the panel-switching number keys).
/// Returns true iff the panel consumed the key.
using PanelKeyFn = bool (*)(char c);

/// Register a sub-panel's draw + key handlers. Late binding so
/// each panel's source file can install itself in a static
/// initialiser without making this header depend on every
/// panel's internals. Passing nullptr clears the slot.
void SettingsRegisterPanel(Panel p, PanelDrawFn draw, PanelKeyFn key);

/// Per-panel install hooks. Each settings_<panel>.cpp exposes
/// one of these and SettingsInit calls them all to register.
void SettingsDisplayInit();
void SettingsSoundInit();
void SettingsKeyboardInit();
void SettingsMouseInit();
void SettingsDateTimeInit();

/// Pass D per-sub-panel self-tests. Each verifies the panel's
/// AppLabel / AppButton chrome binds + paints without crash and
/// emits a `[settings-<panel>-selftest] PASS/FAIL` sentinel that
/// the boot-log analyzer can grep for. Aggregated by the Pass D
/// umbrella sentinel in boot_bringup.cpp.
void SettingsDateTimeSelfTest();
bool SettingsDateTimeSelfTestPassed();
void SettingsDisplaySelfTest();
bool SettingsDisplaySelfTestPassed();
void SettingsKeyboardSelfTest();
bool SettingsKeyboardSelfTestPassed();
void SettingsMouseSelfTest();
bool SettingsMouseSelfTestPassed();
void SettingsSoundSelfTest();
bool SettingsSoundSelfTestPassed();

/// Keyboard typematic — rate / delay indices currently shown by
/// the Keyboard sub-panel and pushed to the PS/2 controller. The
/// indices are the raw values accepted by Ps2KeyboardSetTypematic
/// (rate ∈ [0, 31], delay ∈ [0, 3]). Exposed so the session-
/// restore subsystem can round-trip them through SESSION.CFG;
/// the values otherwise reset to BIOS defaults at every boot.
u8 KeyboardTypematicRateIdx();
u8 KeyboardTypematicDelayIdx();

/// Apply rate + delay together. Both are clamped to the legal
/// ranges, then pushed to the controller via the same path the
/// F/S/D/Q keys take. Idempotent. Used by SessionRestoreApply.
void KeyboardSetTypematicIdx(u8 rate, u8 delay);

/// NTP auto-sync flag — true means the user has opted in to
/// NTP-driven RTC synchronisation. Persisted in SESSION.CFG
/// under `datetime.ntp`. The flag itself does not drive a
/// background sync task; pressing N on the DateTime panel
/// fires one live query when the flag is toggled on.
bool DateTimeNtpEnabled();
void DateTimeSetNtpEnabled(bool enabled);

} // namespace duetos::apps::settings
