#pragma once

#include "../../core/types.h"

/*
 * Taskbar — v0.
 *
 * A thin horizontal strip painted over the top (or bottom) of
 * the framebuffer as the last step of a desktop compose. Shows:
 *   - A "START" label anchored to the left edge.
 *   - A row of per-window tabs listing every live window's
 *     title, in registration order.
 *   - An "UP NNNNs" uptime counter anchored to the right edge.
 *
 * Not a widget — purely painted chrome. Tabs don't respond to
 * clicks yet; activating a window via the taskbar lands with
 * focus + minimise in a follow-up slice.
 *
 * Scope limits:
 *   - One taskbar per framebuffer. Placement fixed at init.
 *   - No clock (real wall time): uptime counter only, derived
 *     from the scheduler tick count (100 Hz).
 *   - Tabs never wrap — if window count * tab width exceeds
 *     the middle area, the overflow is clipped off the right.
 *   - No icons. Text-only tabs.
 *
 * Context: kernel. Init after FramebufferInit and the font
 * module. Redraw is called from DesktopCompose — no thread
 * concerns provided the caller holds the compositor mutex.
 */

namespace customos::drivers::video
{

void TaskbarInit(u32 y, u32 height, u32 bg_rgb, u32 fg_rgb, u32 accent_rgb);

/// Paint the taskbar strip + its dynamic contents. Safe no-op
/// before init.
void TaskbarRedraw();

} // namespace customos::drivers::video
