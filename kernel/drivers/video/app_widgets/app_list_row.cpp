#include "drivers/video/app_widgets/app_list_row.h"
#include "drivers/video/chrome_text.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/theme.h"

namespace duetos::drivers::video::app_widgets
{

void AppListRow::PaintSelf(Compose& /*c*/) const
{
    if (bounds.w == 0 || bounds.h == 0)
        return;
    const auto& theme = ThemeCurrent();
    const u32 hover_bg = theme.role_title[0] & 0x00808080U;
    const u32 sel_bg = theme.role_title[0];
    u32 bg = theme.role_client[0];
    if (selected)
        bg = sel_bg;
    else if (HasFlag(state.flags, WidgetStateFlags::Hover))
        bg = hover_bg;
    FramebufferFillRect(bounds.x, bounds.y, bounds.w, bounds.h, bg);
    const u32 accent = (accent_rgb == 0) ? theme.role_title[0] : accent_rgb;
    if (selected)
        FramebufferFillRect(bounds.x, bounds.y, 3, bounds.h, accent);
    if (label != nullptr && label[0] != '\0')
    {
        const u32 lh = ChromeTextRoleHeight(ChromeTextRole::Body);
        const u32 ty = bounds.y + (bounds.h > lh ? (bounds.h - lh) / 2 : 0);
        ChromeTextDraw(ChromeTextRole::Body, bounds.x + 8, ty, label, 0xFFFFFFU, bg);
    }
}

EventResult AppListRow::OnEventSelf(const Event& e)
{
    if (e.kind == EventKind::MouseMove)
    {
        const bool inside = bounds.Contains(e.x, e.y);
        if (inside)
            state.flags = state.flags | WidgetStateFlags::Hover;
        else
            state.flags =
                static_cast<WidgetStateFlags>(static_cast<u8>(state.flags) & ~static_cast<u8>(WidgetStateFlags::Hover));
        return inside ? EventResult::Consumed : EventResult::NotInterested;
    }
    if (e.kind == EventKind::MouseDown && bounds.Contains(e.x, e.y))
    {
        if (on_click != nullptr)
            on_click();
        return EventResult::Consumed;
    }
    return EventResult::NotInterested;
}

} // namespace duetos::drivers::video::app_widgets
