#include "drivers/video/scrollbar.h"

#include "drivers/video/framebuffer.h"
#include "drivers/video/theme.h"

namespace duetos::drivers::video
{

void ScrollbarPaint(u32 x, u32 y, u32 w, u32 h, ScrollbarState s)
{
    if (w == 0 || h == 0)
        return;
    const auto& th = ThemeCurrent();
    // Track: a slightly darker shade of the window client. We
    // use the dim banner_fg / a fixed grey to stay theme-aware
    // without piping a new colour token through the Theme
    // struct.
    constexpr u32 kTrackRgb = 0x00606878;
    constexpr u32 kThumbBorderRgb = 0x00202830;
    FramebufferFillRect(x, y, w, h, kTrackRgb);
    if (s.total == 0 || s.visible == 0 || s.visible >= s.total)
    {
        // No thumb — content fits in view. Just leave the track
        // visible so the user can tell the bar exists.
        return;
    }
    // Thumb height proportional to visible/total, with a 6-px
    // floor so the bar's grabbable even on a 1000-row list.
    const u64 thumb_h_raw = (static_cast<u64>(h) * s.visible) / s.total;
    u32 thumb_h = static_cast<u32>(thumb_h_raw);
    if (thumb_h < 6)
        thumb_h = 6;
    if (thumb_h > h)
        thumb_h = h;
    // Thumb top proportional to first/(total-visible). When the
    // user is at the very bottom (first == total-visible), the
    // thumb's top should land at h - thumb_h so it touches the
    // bottom edge.
    const u32 max_first = (s.total > s.visible) ? (s.total - s.visible) : 0;
    const u32 max_top = (h > thumb_h) ? (h - thumb_h) : 0;
    u32 first_clamped = (s.first > max_first) ? max_first : s.first;
    const u64 thumb_y_raw = (max_first == 0) ? 0 : (static_cast<u64>(max_top) * first_clamped) / max_first;
    u32 thumb_y = static_cast<u32>(thumb_y_raw);
    if (thumb_y > max_top)
        thumb_y = max_top;
    FramebufferFillRect(x, y + thumb_y, w, thumb_h, th.taskbar_accent);
    FramebufferDrawRect(x, y + thumb_y, w, thumb_h, kThumbBorderRgb, 1);
}

} // namespace duetos::drivers::video
