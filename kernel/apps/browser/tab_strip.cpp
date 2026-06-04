#include "apps/browser/tab_strip.h"

namespace duetos::apps::browser
{
using duetos::u32;

namespace
{
void CopyZ(char* dst, u32 cap, const char* src)
{
    u32 i = 0;
    if (src != nullptr)
    {
        for (; src[i] != '\0' && i + 1 < cap; ++i)
            dst[i] = src[i];
    }
    dst[i] = '\0';
}

u32 Clamp(u32 v, u32 lo, u32 hi)
{
    if (v < lo)
        return lo;
    if (v > hi)
        return hi;
    return v;
}
} // namespace

u32 TabStrip::AddTab(const char* url, const char* title, TabAccent accent)
{
    if (count >= kMaxTabs)
        return count; // full — no-op (GAP: no tab overflow / eviction in Phase 1)
    Tab& t = tabs[count];
    CopyZ(t.url, kTabUrlCap, url);
    CopyZ(t.title, kTabTitleCap, (title != nullptr && title[0] != '\0') ? title : "New Tab");
    t.accent = accent;
    t.scrollY = 0;
    t.live = false;
    active = count;
    ++count;
    return active;
}

void TabStrip::CloseTab(u32 i)
{
    if (i >= count || count <= 1)
        return; // never below one tab.
    for (u32 j = i; j + 1 < count; ++j)
        tabs[j] = tabs[j + 1];
    --count;
    // Re-home the active index.
    if (active > i)
        --active;
    else if (active == i)
        active = (i < count) ? i : count - 1;
}

void TabStrip::Select(u32 i)
{
    if (i < count)
        active = i;
}

u32 TabStrip::TabWidth(const Rect& strip) const
{
    const u32 usable = (strip.w > kNewBtnW) ? (strip.w - kNewBtnW) : 0;
    if (count == 0)
        return kTabMax;
    return Clamp(usable / count, kTabMin, kTabMax);
}

Rect TabStrip::TabRect(u32 i, const Rect& strip) const
{
    const u32 w = TabWidth(strip);
    return Rect{strip.x + i * w, strip.y, w, strip.h};
}

Rect TabStrip::NewTabRect(const Rect& strip) const
{
    const u32 w = TabWidth(strip);
    return Rect{strip.x + count * w, strip.y, kNewBtnW, strip.h};
}

Rect TabStrip::CloseRect(u32 i, const Rect& strip) const
{
    const Rect t = TabRect(i, strip);
    const u32 x = (t.w > kTabCloseW + 4) ? (t.x + t.w - kTabCloseW - 4) : t.x;
    return Rect{x, t.y, kTabCloseW, t.h};
}

TabHit TabStrip::HitTest(const Rect& strip, u32 cx, u32 cy) const
{
    if (NewTabRect(strip).Contains(cx, cy))
        return TabHit{TabHitKind::NewTab, 0};
    for (u32 i = 0; i < count; ++i)
    {
        // Close takes priority over the tab body (it sits within the tab).
        if (CloseRect(i, strip).Contains(cx, cy))
            return TabHit{TabHitKind::Close, i};
        if (TabRect(i, strip).Contains(cx, cy))
            return TabHit{TabHitKind::Tab, i};
    }
    return TabHit{TabHitKind::None, 0};
}

} // namespace duetos::apps::browser
