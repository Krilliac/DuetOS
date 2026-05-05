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
 *   J / Down  — next entry
 *   K / Up    — previous entry
 *   PageUp / PageDown — page step
 *   X / Del   — clear all (requires confirm via MessageBox)
 *
 * Context: kernel. Pure read-only on the notify ring.
 */

namespace duetos::apps::notify_center
{

void NotifyCenterInit(duetos::drivers::video::WindowHandle handle);
duetos::drivers::video::WindowHandle NotifyCenterWindow();

bool NotifyCenterFeedChar(char c);
bool NotifyCenterFeedArrow(duetos::u16 keycode);
void NotifyCenterOnWheel(duetos::i32 dz);

} // namespace duetos::apps::notify_center
