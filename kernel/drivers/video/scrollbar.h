#pragma once

#include "util/types.h"

/*
 * Vertical scrollbar primitive — v0.
 *
 * Pure visual indicator: paints a track + thumb at the right
 * edge of an app's content rect. The thumb's position + size
 * reflect (first, visible, total) so a user immediately sees
 * "I'm 30% down a list of 100" without reading the status
 * footer.
 *
 * Why not interactive? Drag-the-thumb to jump-to needs per-app
 * hit-test wiring + drag-state tracking, and v0's wheel
 * dispatch already covers the common case ("scroll a few rows").
 * A future slice can extend the API to take a click handler;
 * the geometry helpers below already give callers everything
 * they need to hit-test internally.
 *
 * Context: kernel. Called from app DrawFn callbacks under the
 * compositor lock.
 */

namespace duetos::drivers::video
{

struct ScrollbarState
{
    u32 total;   // total content rows (0 = empty / hide thumb)
    u32 visible; // rows that fit in the view
    u32 first;   // index of the top visible row, in [0, total-visible]
};

/// Standard scrollbar width in pixels — narrow enough not to
/// crowd the content area, wide enough to read at a glance.
constexpr u32 kScrollbarWidth = 8;

/// Paint a vertical scrollbar inside (x, y, w, h). Width is
/// typically `kScrollbarWidth`. Track fills the full rect; the
/// thumb is sized proportional to `visible / total` and
/// positioned proportional to `first / (total - visible)`.
/// No-op when `total == 0` or the rect is degenerate.
void ScrollbarPaint(u32 x, u32 y, u32 w, u32 h, ScrollbarState s);

} // namespace duetos::drivers::video
