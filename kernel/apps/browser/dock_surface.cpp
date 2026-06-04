#include "apps/browser/dock_surface.h"

namespace duetos::apps::browser
{
using duetos::i64;
using duetos::u32;

DockEdge DockSurface::GutterHit(const Rect& client, u32 cx, u32 cy)
{
    // Outside the client rect snaps to nothing.
    if (cx < client.x || cy < client.y || cx >= client.x + client.w || cy >= client.y + client.h)
        return DockEdge::None;

    const u32 lx = client.x;
    const u32 rx = client.x + client.w;
    const u32 ty = client.y;
    const u32 by = client.y + client.h;

    // Left/Right take priority over Top/Bottom in the corners (arbitrary but stable).
    if (cx - lx < kDockGutter)
        return DockEdge::Left;
    if (rx - cx < kDockGutter)
        return DockEdge::Right;
    if (cy - ty < kDockGutter)
        return DockEdge::Top;
    if (by - cy < kDockGutter)
        return DockEdge::Bottom;
    return DockEdge::None;
}

Rect DockSurface::SurfaceRect(const Rect& client) const
{
    if (mode == DockMode::Floating)
        return floatRect;

    if (mode == DockMode::Docked)
    {
        switch (edge)
        {
        case DockEdge::Left:
        {
            const u32 w = client.w * kDockSidePct / 100;
            return Rect{client.x, client.y, w, client.h};
        }
        case DockEdge::Right:
        {
            const u32 w = client.w * kDockSidePct / 100;
            return Rect{client.x + client.w - w, client.y, w, client.h};
        }
        case DockEdge::Top:
        {
            const u32 h = client.h * kDockTopPct / 100;
            return Rect{client.x, client.y, client.w, h};
        }
        case DockEdge::Bottom:
        {
            const u32 h = client.h * kDockBottomPct / 100;
            return Rect{client.x, client.y + client.h - h, client.w, h};
        }
        default:
            break;
        }
    }
    return Rect{}; // Hidden
}

Rect DockSurface::ContentRect(const Rect& client) const
{
    if (mode != DockMode::Docked)
        return client; // Hidden / Floating overlay — no reflow.

    const Rect s = SurfaceRect(client);
    switch (edge)
    {
    case DockEdge::Left:
        return Rect{client.x + s.w, client.y, client.w - s.w, client.h};
    case DockEdge::Right:
        return Rect{client.x, client.y, client.w - s.w, client.h};
    case DockEdge::Top:
        return Rect{client.x, client.y + s.h, client.w, client.h - s.h};
    case DockEdge::Bottom:
        return Rect{client.x, client.y, client.w, client.h - s.h};
    default:
        return client;
    }
}

void DockSurface::Summon(const Rect& client)
{
    if (mode != DockMode::Hidden)
        return; // already visible — preserve current Floating/Docked state.

    // Default to a floating card in the bottom-right if we have no prior rect.
    if (floatRect.w == 0 || floatRect.h == 0)
    {
        const u32 w = client.w * kDockSidePct / 100;
        const u32 h = client.h * kDockBottomPct / 100;
        const u32 x = (client.w > w + 16) ? client.x + client.w - w - 16 : client.x;
        const u32 y = (client.h > h + 16) ? client.y + client.h - h - 16 : client.y;
        floatRect = Rect{x, y, w, h};
    }
    mode = DockMode::Floating;
}

void DockSurface::Dismiss()
{
    mode = DockMode::Hidden; // floatRect / edge retained for re-summon.
}

void DockSurface::DragBegin()
{
    dragging = true;
    hoverEdge = DockEdge::None;
}

void DockSurface::DragUpdate(const Rect& client, u32 cx, u32 cy)
{
    if (!dragging)
        return;
    hoverEdge = GutterHit(client, cx, cy);

    // A floating surface tracks the cursor (grabbed at its header).
    if (mode == DockMode::Floating)
    {
        const u32 w = floatRect.w ? floatRect.w : client.w * kDockSidePct / 100;
        const u32 h = floatRect.h ? floatRect.h : client.h * kDockBottomPct / 100;
        i64 nx = static_cast<i64>(cx) - static_cast<i64>(w) / 2;
        i64 ny = static_cast<i64>(cy) - 8;
        const i64 maxX = static_cast<i64>(client.x) + static_cast<i64>(client.w) - static_cast<i64>(w);
        const i64 maxY = static_cast<i64>(client.y) + static_cast<i64>(client.h) - static_cast<i64>(h);
        if (nx < static_cast<i64>(client.x))
            nx = client.x;
        if (ny < static_cast<i64>(client.y))
            ny = client.y;
        if (nx > maxX)
            nx = (maxX < static_cast<i64>(client.x)) ? client.x : maxX;
        if (ny > maxY)
            ny = (maxY < static_cast<i64>(client.y)) ? client.y : maxY;
        floatRect = Rect{static_cast<u32>(nx), static_cast<u32>(ny), w, h};
    }
}

void DockSurface::DragEnd(const Rect& client)
{
    dragging = false;
    if (hoverEdge != DockEdge::None)
    {
        mode = DockMode::Docked;
        edge = hoverEdge;
    }
    else if (mode != DockMode::Floating)
    {
        // Released in the middle while docked — pop back to a centred float.
        const u32 w = client.w * kDockSidePct / 100;
        const u32 h = client.h * kDockBottomPct / 100;
        floatRect = Rect{client.x + (client.w - w) / 2, client.y + (client.h - h) / 2, w, h};
        mode = DockMode::Floating;
    }
    hoverEdge = DockEdge::None;
}

} // namespace duetos::apps::browser
