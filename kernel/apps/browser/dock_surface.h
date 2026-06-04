#pragma once

#include "drivers/video/app_widgets/widget.h" // Rect
#include "util/types.h"

/*
 * DuetOS browser — DockSurface: a movable, dismissible chrome surface
 * with a floating default and four Aero-snap dock targets. One state
 * machine reused for both the Assistant and the Library (see design spec
 * docs/superpowers/specs/2026-06-04-browser-ui-redesign-design.md §3).
 *
 * Pure geometry/state — NO rendering here, so it is fully boot-self-
 * tested. The browser chrome owns the pixels; this owns the model.
 */

namespace duetos::apps::browser
{
using duetos::drivers::video::app_widgets::Rect;

enum class DockMode : duetos::u8
{
    Hidden = 0,
    Floating = 1,
    Docked = 2,
};

enum class DockEdge : duetos::u8
{
    None = 0,
    Left = 1,
    Right = 2,
    Top = 3,
    Bottom = 4,
};

// Pixels from a window edge within which a drag snaps to that edge.
constexpr duetos::u32 kDockGutter = 24;
// Default docked sizes as a percent of the content rect.
constexpr duetos::u32 kDockSidePct = 34;   // left/right width %
constexpr duetos::u32 kDockBottomPct = 30; // bottom height %
constexpr duetos::u32 kDockTopPct = 18;    // top bar height %

struct DockSurface
{
    DockMode mode = DockMode::Hidden;
    DockEdge edge = DockEdge::None;      // valid when mode == Docked
    Rect floatRect{};                    // valid when mode == Floating (client space)
    bool dragging = false;               // header drag in progress
    DockEdge hoverEdge = DockEdge::None; // ghost-preview edge while dragging (None = no snap)

    // Summon to a visible state (Floating, default bottom-right, if never shown).
    void Summon(const Rect& client);
    // Hide (preserves floatRect / edge for the next Summon).
    void Dismiss();

    // Header drag lifecycle. `cx,cy` are the cursor in client space.
    void DragBegin();
    void DragUpdate(const Rect& client, duetos::u32 cx, duetos::u32 cy);
    void DragEnd(const Rect& client);

    // Which edge gutter (cx,cy) falls in, if any (None otherwise / when outside client).
    static DockEdge GutterHit(const Rect& client, duetos::u32 cx, duetos::u32 cy);
    // The surface's own rect for the current mode.
    Rect SurfaceRect(const Rect& client) const;
    // The content rect left for the web page after this surface docks
    // (== client when Hidden/Floating — overlay, no reflow; reduced when Docked).
    Rect ContentRect(const Rect& client) const;
};

// Boot self-test (registered in boot_bringup.cpp).
void DockSurfaceSelfTest();

} // namespace duetos::apps::browser
