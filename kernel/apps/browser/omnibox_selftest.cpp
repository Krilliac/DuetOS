#include "apps/browser/omnibox.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"

namespace duetos::apps::browser
{
void OmniboxSelfTest()
{
    auto fail = [](duetos::u32 c)
    {
        arch::SerialWrite("[omnibox-selftest] FAIL check=");
        arch::SerialWriteHex(c);
        arch::SerialWrite("\n");
        KBP_PROBE_V(duetos::debug::ProbeId::kBootSelftestFail, c);
    };

    const Rect toolbar{0, 0, 800, 38};
    Omnibox o;

    // 1: edit transitions — insert "abc", backspace to "ab".
    o.BeginEdit();
    o.InsertChar('a');
    o.InsertChar('b');
    o.InsertChar('c');
    o.Backspace();
    if (o.len != 2 || o.caret != 2 || o.text[0] != 'a' || o.text[1] != 'b' || o.text[2] != '\0')
    {
        fail(1);
        return;
    }

    // 2: nav buttons tile from the left.
    if (o.NavRect(1, toolbar).x != 40)
    {
        fail(2);
        return;
    }
    // 3: pill starts after the nav cluster and does NOT overlap the Ask button.
    const Rect pill = o.PillRect(toolbar);
    const Rect ask = o.AskRect(toolbar);
    if (pill.x != 102 || pill.x + pill.w > ask.x)
    {
        fail(3);
        return;
    }
    // 4: Ask button position (right cluster: menu 767, lib 736, ask 657).
    if (ask.x != 657)
    {
        fail(4);
        return;
    }
    // 5: hit-test the Ask button.
    if (o.HitTest(toolbar, 693, 19).kind != OmniHitKind::Ask)
    {
        fail(5);
        return;
    }
    // 6: hit-test the pill.
    if (o.HitTest(toolbar, 376, 19).kind != OmniHitKind::Pill)
    {
        fail(6);
        return;
    }
    // 7: hit-test nav button 1 (forward).
    const OmniHit nh = o.HitTest(toolbar, 52, 19);
    if (nh.kind != OmniHitKind::Nav || nh.navIndex != 1)
    {
        fail(7);
        return;
    }
    // 8: hit-test the overflow menu.
    if (o.HitTest(toolbar, 779, 19).kind != OmniHitKind::Menu)
    {
        fail(8);
        return;
    }

    arch::SerialWrite("[omnibox-selftest] PASS (edit insert/backspace, nav tile, pill no-overlap, ask/menu/nav "
                      "hit-test)\n");
}

} // namespace duetos::apps::browser
