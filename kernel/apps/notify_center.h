#pragma once

#include "drivers/video/widget.h"
#include "util/types.h"

/*
 * DuetOS Notification Center — v0.
 *
 * Windowed reader for the toast history ring kept in
 * `kernel/drivers/video/notify.cpp`. The ring already
 * coalesces duplicates and retains 16 entries; this app paints
 * them in a scrollable list. Ctrl+Shift+N continues to dump
 * the same data to the kernel console as a quick fallback;
 * this gives the user a windowed surface they can browse.
 *
 * Bindings (when this window is focused):
 *   J / Down            — next entry
 *   K / Up              — previous entry
 *   PageUp / PageDown   — page step
 *   Home / End          — jump to newest / oldest
 *   X / Del             — clear all (MessageBox confirm)
 *
 * Context: kernel. Pure read-only on the notify ring.
 */

namespace duetos::apps::notify_center
{

void NotifyCenterInit(duetos::drivers::video::WindowHandle handle);
duetos::drivers::video::WindowHandle NotifyCenterWindow();

bool NotifyCenterFeedChar(char c);
bool NotifyCenterFeedArrow(duetos::u16 keycode);
void NotifyCenterOnWheel(duetos::i32 dz, duetos::u8 modifiers);

/// Pass D mouse-input entry. Routes cursor packets through the
/// WidgetGroup dispatch chain so the toolbar CLR button hover /
/// press / release state tracks the cursor without waiting for
/// the ui-ticker. Edge-detects left-button state internally so
/// the kernel mouse loop can call unconditionally per packet.
void NotifyCenterMouseInput(duetos::u32 cursor_x, duetos::u32 cursor_y, duetos::u8 button_mask);

/// Pass D self-test. Exercises the toolbar hit-test + dispatch
/// chain via a synthetic hover (stops at the edge — the click
/// would pop a MessageBox, which would mutate dialog state) and
/// verifies the header / footer composers produce non-empty
/// text. Emits `[notify_center-selftest] PASS` or `FAIL` to the
/// serial console.
void NotifyCenterSelfTest();

/// Returns true iff the most recent NotifyCenterSelfTest()
/// invocation ran every check and set the internal pass flag.
bool NotifyCenterSelfTestPassed();

} // namespace duetos::apps::notify_center
