#include "drivers/video/app_widgets/app_input.h"

#include "drivers/video/chrome_text.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/theme.h"

namespace duetos::drivers::video::app_widgets
{

void AppInput::PaintSelf(Compose& /*c*/) const
{
    if (bounds.w == 0 || bounds.h == 0)
        return;
    const auto& theme = ThemeCurrent();
    FramebufferFillRect(bounds.x, bounds.y, bounds.w, bounds.h, theme.role_client[0]);
    const u32 border = HasFlag(state.flags, WidgetStateFlags::Focused) ? theme.role_title[0] : theme.window_border;
    const u32 thickness = HasFlag(state.flags, WidgetStateFlags::Focused) ? 2U : 1U;
    FramebufferDrawRect(bounds.x, bounds.y, bounds.w, bounds.h, border, thickness);
    if (buf != nullptr && buf_len > 0)
    {
        const u32 lh = ChromeTextRoleHeight(ChromeTextRole::Body);
        const u32 ty = bounds.y + (bounds.h > lh ? (bounds.h - lh) / 2 : 0);
        if (buf_len < buf_cap)
            buf[buf_len] = '\0';
        ChromeTextDraw(ChromeTextRole::Body, bounds.x + 6, ty, buf, 0xFFFFFFU, theme.role_client[0]);
        if (HasFlag(state.flags, WidgetStateFlags::Focused))
        {
            const u32 cw = ChromeTextMeasure(ChromeTextRole::Body, buf);
            FramebufferFillRect(bounds.x + 6 + cw + 1, ty, 1, lh, 0xFFFFFFU);
        }
    }
}

EventResult AppInput::OnEventSelf(const Event& e)
{
    if (e.kind == EventKind::MouseDown)
    {
        const bool inside = bounds.Contains(e.x, e.y);
        if (inside)
            state.flags = state.flags | WidgetStateFlags::Focused;
        else
            state.flags = static_cast<WidgetStateFlags>(static_cast<u8>(state.flags) &
                                                        ~static_cast<u8>(WidgetStateFlags::Focused));
        return inside ? EventResult::Consumed : EventResult::NotInterested;
    }
    if (e.kind == EventKind::KeyDown && HasFlag(state.flags, WidgetStateFlags::Focused))
    {
        if (e.keycode == 0x08 && buf_len > 0)
        {
            buf_len--;
            caret = buf_len;
            if (on_change != nullptr)
                on_change();
            return EventResult::Consumed;
        }
        if (e.keycode >= 0x20 && e.keycode < 0x7F && buf != nullptr && buf_len + 1 < buf_cap)
        {
            buf[buf_len++] = static_cast<char>(e.keycode);
            caret = buf_len;
            if (on_change != nullptr)
                on_change();
            return EventResult::Consumed;
        }
    }
    return EventResult::NotInterested;
}

} // namespace duetos::drivers::video::app_widgets
