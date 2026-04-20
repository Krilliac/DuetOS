#pragma once

#include "../../core/types.h"

/*
 * Minimal widget layer — v0.
 *
 * The simplest thing that introduces UI events to the tree: a
 * "button" is a rectangle with two colours (normal + pressed)
 * and an owner id. An event router takes {cursor_x, cursor_y,
 * button_mask} from the mouse reader, tests each registered
 * button's bounds, and transitions visual state on edges.
 *
 * Design choices that will be revisited:
 *   - Fixed-size widget table, no dynamic allocation. Boot-time
 *     widgets only. Every GUI grows this into a proper scene
 *     graph, but a flat array is correct at the point where
 *     "there are two buttons on screen at boot."
 *   - No event callbacks yet — the router returns the id of the
 *     widget that transitioned so the caller can switch on it.
 *     Wiring a function-pointer-per-widget when exactly one
 *     caller exists is premature abstraction.
 *   - Re-rendering a widget is done behind a CursorHide/Show
 *     bracket so the cursor's backing-pixel cache doesn't hold
 *     stale colours from before the repaint.
 *   - Buttons are drawn as filled rectangles with a 2-pixel
 *     outline. No rounded corners, no gradient, no text label
 *     (labels wait on the bitmap font slice).
 *
 * Context: kernel. Register widgets during boot, drive events
 * from the mouse reader thread.
 */

namespace customos::drivers::video
{

constexpr u32 kWidgetInvalid = 0xFFFFFFFFu;

struct ButtonWidget
{
    u32 id;           // caller-assigned, returned by the router on events
    u32 x, y, w, h;   // bounds in framebuffer pixels
    u32 colour_normal;
    u32 colour_pressed;
    u32 colour_border;
    bool pressed;     // current visual state
    u8 _pad[7];
};

/// Register a button. Copies the descriptor into the widget table.
/// Returns true on success, false if the table is full. The `id`
/// field is echoed back by `WidgetRouteMouse` to identify which
/// button transitioned — callers own id allocation.
bool WidgetRegisterButton(const ButtonWidget& button);

/// Paint every registered widget in registration order. Intended
/// to be called once after the desktop background fill and before
/// the cursor is rendered. Idempotent.
void WidgetDrawAll();

/// Feed a mouse state sample to the router. If any widget changes
/// visual state (press or release edge), the router returns that
/// widget's id; otherwise returns `kWidgetInvalid`. Only one
/// transition per call — callers that want to see multiple should
/// loop until the router returns kWidgetInvalid (for v0 a single
/// packet can trigger at most one transition since we only track
/// a single button bit).
u32 WidgetRouteMouse(u32 cursor_x, u32 cursor_y, u8 button_mask);

} // namespace customos::drivers::video
