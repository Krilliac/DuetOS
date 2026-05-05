#include "drivers/video/scrollbar.h"

#include "drivers/video/framebuffer.h"
#include "drivers/video/theme.h"

namespace duetos::drivers::video
{

u32 ScrollbarThumbH(u32 h, ScrollbarState s)
{
    if (h == 0 || s.total == 0 || s.visible == 0 || s.visible >= s.total)
        return h;
    const u64 raw = (static_cast<u64>(h) * s.visible) / s.total;
    u32 thumb_h = static_cast<u32>(raw);
    if (thumb_h < 6)
        thumb_h = 6;
    if (thumb_h > h)
        thumb_h = h;
    return thumb_h;
}

u32 ScrollbarThumbY(u32 h, ScrollbarState s)
{
    if (s.total <= s.visible)
        return 0;
    const u32 thumb_h = ScrollbarThumbH(h, s);
    const u32 max_first = s.total - s.visible;
    const u32 max_top = (h > thumb_h) ? (h - thumb_h) : 0;
    const u32 first_clamped = (s.first > max_first) ? max_first : s.first;
    if (max_first == 0)
        return 0;
    const u64 raw = (static_cast<u64>(max_top) * first_clamped) / max_first;
    u32 thumb_y = static_cast<u32>(raw);
    if (thumb_y > max_top)
        thumb_y = max_top;
    return thumb_y;
}

void ScrollbarPaint(u32 x, u32 y, u32 w, u32 h, ScrollbarState s)
{
    if (w == 0 || h == 0)
        return;
    const auto& th = ThemeCurrent();
    constexpr u32 kTrackRgb = 0x00606878;
    constexpr u32 kThumbBorderRgb = 0x00202830;
    FramebufferFillRect(x, y, w, h, kTrackRgb);
    if (s.total == 0 || s.visible == 0 || s.visible >= s.total)
        return;
    const u32 thumb_h = ScrollbarThumbH(h, s);
    const u32 thumb_y = ScrollbarThumbY(h, s);
    FramebufferFillRect(x, y + thumb_y, w, thumb_h, th.taskbar_accent);
    FramebufferDrawRect(x, y + thumb_y, w, thumb_h, kThumbBorderRgb, 1);
}

u32 ScrollbarHitTest(u32 cx, u32 cy, u32 x, u32 y, u32 w, u32 h, ScrollbarState s)
{
    if (cx < x || cx >= x + w || cy < y || cy >= y + h)
        return kScrollbarNoHit;
    if (s.total <= s.visible)
        return 0;
    const u32 thumb_h = ScrollbarThumbH(h, s);
    const u32 thumb_y = ScrollbarThumbY(h, s);
    const u32 click_y = cy - y;
    const u32 max_first = s.total - s.visible;
    if (click_y < thumb_y)
    {
        // Page-back — step by `visible` rows.
        return (s.first > s.visible) ? (s.first - s.visible) : 0;
    }
    if (click_y >= thumb_y + thumb_h)
    {
        // Page-forward.
        const u32 nf = s.first + s.visible;
        return (nf > max_first) ? max_first : nf;
    }
    // On thumb — caller picks up drag from here.
    return s.first;
}

u32 ScrollbarDragTo(u32 cy, u32 y, u32 h, u32 grab_offset_in_thumb, ScrollbarState s)
{
    if (s.total <= s.visible || h == 0)
        return 0;
    const u32 thumb_h = ScrollbarThumbH(h, s);
    const u32 max_first = s.total - s.visible;
    const u32 max_top = (h > thumb_h) ? (h - thumb_h) : 0;
    if (max_top == 0)
        return 0;
    // Cursor's intended thumb-top inside the track.
    i64 want_top = static_cast<i64>(cy) - static_cast<i64>(y) - static_cast<i64>(grab_offset_in_thumb);
    if (want_top < 0)
        want_top = 0;
    if (want_top > static_cast<i64>(max_top))
        want_top = static_cast<i64>(max_top);
    const u64 raw = (static_cast<u64>(max_first) * static_cast<u64>(want_top)) / max_top;
    return static_cast<u32>(raw);
}

} // namespace duetos::drivers::video
