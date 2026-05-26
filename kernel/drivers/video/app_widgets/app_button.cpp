#include "drivers/video/app_widgets/app_button.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/shadow.h"
#include "drivers/video/theme.h"

namespace duetos::drivers::video::app_widgets
{

void AppButton::PaintSelf(Compose& /*c*/) const
{
    if (bounds.w == 0 || bounds.h == 0)
        return;
    const auto& theme = ThemeCurrent();
    const u32 base_bg = (bg_rgb == 0) ? theme.role_title[0] : bg_rgb;
    u32 bg = base_bg;
    if (HasFlag(state.flags, WidgetStateFlags::Pressed))
        bg = base_bg & 0x00C0C0C0U;
    else if (HasFlag(state.flags, WidgetStateFlags::Hover))
        bg = base_bg | 0x00202020U;
    if (ThemeTactilityEffective() && !HasFlag(state.flags, WidgetStateFlags::Pressed))
    {
        const u8 opacity = ThemeIntensityEffective(theme.shadow_intensity_active);
        if (opacity > 0)
        {
            RenderSoftShadow(static_cast<i32>(bounds.x), static_cast<i32>(bounds.y), bounds.w, bounds.h, 6U, opacity,
                             0x00000000U);
        }
    }
    FramebufferFillRect(bounds.x, bounds.y, bounds.w, bounds.h, bg);
    FramebufferDrawRect(bounds.x, bounds.y, bounds.w, bounds.h, theme.window_border, 1);
    if (label != nullptr && label[0] != '\0')
    {
        const u32 lw = ChromeTextMeasure(ChromeTextRole::Body, label);
        const u32 lh = ChromeTextRoleHeight(ChromeTextRole::Body);
        const u32 tx = bounds.x + (bounds.w > lw ? (bounds.w - lw) / 2 : 0);
        const u32 ty = bounds.y + (bounds.h > lh ? (bounds.h - lh) / 2 : 0);
        ChromeTextDraw(ChromeTextRole::Body, tx, ty, label, fg_rgb, bg, weight);
    }
}

EventResult AppButton::OnEventSelf(const Event& e)
{
    if (HasFlag(state.flags, WidgetStateFlags::Disabled))
        return EventResult::NotInterested;
    if (e.kind == EventKind::MouseMove)
    {
        const bool inside = bounds.Contains(e.x, e.y);
        const bool was_hover = HasFlag(state.flags, WidgetStateFlags::Hover);
        if (inside && !was_hover)
            state.flags = state.flags | WidgetStateFlags::Hover;
        else if (!inside && was_hover)
            state.flags = static_cast<WidgetStateFlags>(static_cast<u8>(state.flags)
                                                        & ~static_cast<u8>(WidgetStateFlags::Hover));
        return inside ? EventResult::Consumed : EventResult::NotInterested;
    }
    if (e.kind == EventKind::MouseDown && bounds.Contains(e.x, e.y))
    {
        state.flags = state.flags | WidgetStateFlags::Pressed;
        return EventResult::Consumed;
    }
    if (e.kind == EventKind::MouseUp && HasFlag(state.flags, WidgetStateFlags::Pressed))
    {
        state.flags = static_cast<WidgetStateFlags>(static_cast<u8>(state.flags)
                                                    & ~static_cast<u8>(WidgetStateFlags::Pressed));
        if (bounds.Contains(e.x, e.y) && on_click != nullptr)
            on_click();
        return EventResult::Consumed;
    }
    return EventResult::NotInterested;
}

} // namespace duetos::drivers::video::app_widgets
