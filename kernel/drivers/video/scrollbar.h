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

/// Hit-test result. `kScrollbarNoHit` means the click missed
/// the bar; otherwise the value is the new `first` index the
/// caller should set (clamped to [0, total - visible]).
constexpr u32 kScrollbarNoHit = 0xFFFFFFFFu;

/// Map a click at (cx, cy) inside the bar's (x, y, w, h)
/// rect to a new `first` index. Click on the thumb returns
/// the current first (no-op until a drag follows up); click
/// on the track above the thumb scrolls one page back; click
/// below scrolls one page forward; click in the empty (no-
/// thumb) state returns 0. Outside the rect returns
/// `kScrollbarNoHit`.
u32 ScrollbarHitTest(u32 cx, u32 cy, u32 x, u32 y, u32 w, u32 h, ScrollbarState s);

/// Map a drag at (cy) inside the bar's (y, h) to a new
/// `first` index. The thumb's centre tracks the cursor: a
/// drag to the top of the bar yields `first = 0`, a drag to
/// the bottom yields `first = total - visible`. Caller
/// supplies the offset of the press point inside the thumb
/// at drag-start so the thumb doesn't snap-jump on grab.
u32 ScrollbarDragTo(u32 cy, u32 y, u32 h, u32 grab_offset_in_thumb, ScrollbarState s);

/// Compute the thumb-y inside the track for a given state.
/// Used by drag-start to capture grab_offset_in_thumb.
u32 ScrollbarThumbY(u32 h, ScrollbarState s);

/// Compute the thumb height inside the track for a given
/// state.
u32 ScrollbarThumbH(u32 h, ScrollbarState s);

} // namespace duetos::drivers::video
