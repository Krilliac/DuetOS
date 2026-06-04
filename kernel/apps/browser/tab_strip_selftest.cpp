#include "apps/browser/tab_strip.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"

namespace duetos::apps::browser
{
namespace
{
bool StrEqZ(const char* a, const char* b)
{
    duetos::u32 i = 0;
    for (; a[i] != '\0' && b[i] != '\0'; ++i)
        if (a[i] != b[i])
            return false;
    return a[i] == b[i];
}
} // namespace

void TabStripSelfTest()
{
    auto fail = [](duetos::u32 c)
    {
        arch::SerialWrite("[tabstrip-selftest] FAIL check=");
        arch::SerialWriteHex(c);
        arch::SerialWrite("\n");
        KBP_PROBE_V(duetos::debug::ProbeId::kBootSelftestFail, c);
    };

    const Rect strip{0, 0, 500, 30};
    TabStrip ts;
    ts.AddTab("http://a", "A", TabAccent::Native);
    ts.AddTab("http://b", "B", TabAccent::Doc);
    ts.AddTab("http://c", nullptr, TabAccent::Native);

    // 1: three tabs, last is active.
    if (ts.count != 3 || ts.active != 2)
    {
        fail(1);
        return;
    }
    // 2: shrink-to-fit width — usable (500-26)/3 = 158, within [120,160].
    if (ts.TabWidth(strip) != 158)
    {
        fail(2);
        return;
    }
    // 3: tab rects tile by width.
    if (ts.TabRect(0, strip).w != 158 || ts.TabRect(1, strip).x != 158)
    {
        fail(3);
        return;
    }
    // 4: new-tab button sits after the last tab.
    const Rect nt = ts.NewTabRect(strip);
    if (nt.x != 474 || nt.w != 26)
    {
        fail(4);
        return;
    }
    // 5: hit-test the centre of tab 1.
    TabHit h = ts.HitTest(strip, 237, 15);
    if (h.kind != TabHitKind::Tab || h.index != 1)
    {
        fail(5);
        return;
    }
    // 6: hit-test the new-tab button.
    h = ts.HitTest(strip, 487, 15);
    if (h.kind != TabHitKind::NewTab)
    {
        fail(6);
        return;
    }
    // 7: hit-test tab 0's close affordance (right end of the tab).
    h = ts.HitTest(strip, 146, 15);
    if (h.kind != TabHitKind::Close || h.index != 0)
    {
        fail(7);
        return;
    }
    // 8: many narrow tabs clamp to the floor, not below.
    const Rect narrow{0, 0, 300, 30};
    if (ts.TabWidth(narrow) != 120)
    {
        fail(8);
        return;
    }
    // 9: url/title stored verbatim.
    if (!StrEqZ(ts.tabs[0].url, "http://a") || !StrEqZ(ts.tabs[0].title, "A"))
    {
        fail(9);
        return;
    }
    // 10: a null title defaults to "New Tab".
    if (!StrEqZ(ts.tabs[2].title, "New Tab"))
    {
        fail(10);
        return;
    }
    // 11: closing tab 1 ("b") shifts and re-homes active onto "c".
    ts.CloseTab(1);
    if (ts.count != 2 || ts.active != 1 || !StrEqZ(ts.tabs[1].url, "http://c"))
    {
        fail(11);
        return;
    }
    // 12: never drop below one tab.
    ts.CloseTab(0);
    ts.CloseTab(0);
    if (ts.count != 1)
    {
        fail(12);
        return;
    }

    arch::SerialWrite("[tabstrip-selftest] PASS (add/active, shrink-fit, rects, hit-test tab/new/close, clamp, "
                      "store, close+rehome, min-one)\n");
}

} // namespace duetos::apps::browser
