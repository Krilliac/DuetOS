#include "apps/browser/dock_surface.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"

namespace duetos::apps::browser
{
using duetos::drivers::video::app_widgets::Rect;

// Geometry + state-machine self-test for DockSurface. No rendering.
void DockSurfaceSelfTest()
{
    auto fail = [](duetos::u32 c)
    {
        arch::SerialWrite("[dock-selftest] FAIL check=");
        arch::SerialWriteHex(c);
        arch::SerialWrite("\n");
        KBP_PROBE_V(duetos::debug::ProbeId::kBootSelftestFail, c);
    };

    const Rect client{0, 0, 1000, 600};

    // 1: gutter hits per edge, miss in the middle.
    if (DockSurface::GutterHit(client, 5, 300) != DockEdge::Left)
    {
        fail(1);
        return;
    }
    if (DockSurface::GutterHit(client, 995, 300) != DockEdge::Right)
    {
        fail(2);
        return;
    }
    if (DockSurface::GutterHit(client, 500, 5) != DockEdge::Top)
    {
        fail(3);
        return;
    }
    if (DockSurface::GutterHit(client, 500, 595) != DockEdge::Bottom)
    {
        fail(4);
        return;
    }
    if (DockSurface::GutterHit(client, 500, 300) != DockEdge::None)
    {
        fail(5);
        return;
    }

    // 2: docked-right surface takes ~34% width on the right; content takes the rest.
    DockSurface d;
    d.mode = DockMode::Docked;
    d.edge = DockEdge::Right;
    const Rect sr = d.SurfaceRect(client);
    const Rect cr = d.ContentRect(client);
    if (sr.w != 340 || sr.x != 660 || sr.h != 600)
    {
        fail(6);
        return;
    }
    if (cr.w != 660 || cr.x != 0)
    {
        fail(7);
        return;
    }

    // 3: floating surface leaves content == client (overlay, no reflow).
    DockSurface f;
    f.mode = DockMode::Floating;
    f.floatRect = Rect{700, 400, 250, 180};
    const Rect fcr = f.ContentRect(client);
    if (fcr.w != client.w || fcr.h != client.h)
    {
        fail(8);
        return;
    }

    // 4: drag into the left gutter then release => Docked Left.
    DockSurface g;
    g.Summon(client); // Floating
    g.DragBegin();
    g.DragUpdate(client, 5, 300);
    if (g.hoverEdge != DockEdge::Left)
    {
        fail(9);
        return;
    }
    g.DragEnd(client);
    if (g.mode != DockMode::Docked || g.edge != DockEdge::Left)
    {
        fail(10);
        return;
    }

    // 5: dragging a docked surface to the middle pops it back to Floating.
    g.DragBegin();
    g.DragUpdate(client, 500, 300);
    g.DragEnd(client);
    if (g.mode != DockMode::Floating)
    {
        fail(11);
        return;
    }

    arch::SerialWrite("[dock-selftest] PASS (gutter hit x4+miss, dock split L/R, float overlay, drag-snap, undock)\n");
}

} // namespace duetos::apps::browser
