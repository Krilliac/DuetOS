#pragma once

#include "util/types.h"

/*
 * DuetOS desktop gadgets — glass panels that float over the wallpaper.
 *
 * docs/aurora-theme/README.md §1 puts a gadget column down the right
 * edge of the desktop: a clock/date panel, a kernel panel (CPU
 * sparkline + stat rows) and an ABI-peers panel. The stats panels read
 * the scheduler-owned 1 Hz sample ring so they carry honest, shared
 * numbers rather than per-surface decorations.
 *
 * The panel is decoration, not a control: it has no hit-test and no
 * click handler. It paints between the wallpaper and the window list
 * (same slot as the desktop icons) so an open window occludes it, which
 * is what the reference desktop shows.
 *
 * Gadgets only paint under a palette that ships the Aurora vocabulary
 * (surface_radius != 0 and tactility on). The flat themes have no glass
 * to float a panel over, so on those this is a no-op rather than an
 * opaque rectangle sitting on the wallpaper.
 *
 * Context: kernel, compositor thread only. Reads the RTC and scheduler
 * sample ring on each paint, exactly as the taskbar clock/stats pill do.
 */

namespace duetos::drivers::video
{

/// Paint the gadget column onto the current framebuffer. Call from
/// DesktopCompose alongside DesktopIconsPaint. No-op on a non-Aurora
/// palette or a framebuffer too small to hold the column.
void DesktopGadgetsPaint();

/// Boot self-test: pure layout math — verifies the column's rect lands
/// fully inside the framebuffer and clear of the taskbar reserve at the
/// current mode. Emits a greppable PASS/FAIL sentinel; never panics (a
/// misplaced gadget is a UI bug, not a reason to halt the box).
void DesktopGadgetsSelfTest();

} // namespace duetos::drivers::video
