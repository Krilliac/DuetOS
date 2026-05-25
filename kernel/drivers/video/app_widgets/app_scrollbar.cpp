#include "drivers/video/app_widgets/app_scrollbar.h"

#include "drivers/video/framebuffer.h"
#include "drivers/video/theme.h"

namespace duetos::drivers::video::app_widgets
{

void AppScrollbar::PaintSelf(Compose& /*c*/) const
{
    if (bounds.w == 0 || bounds.h == 0 || content_size == 0)
        return;
    const auto& theme = ThemeCurrent();
    FramebufferFillRect(bounds.x, bounds.y, bounds.w, bounds.h, theme.taskbar_bg);
    const u32 track_extent = horizontal ? bounds.w : bounds.h;
    if (content_size <= viewport_size)
        return;
    const u32 thumb_extent = (viewport_size * track_extent) / content_size;
    const u32 thumb_offset = (scroll_offset * track_extent) / content_size;
    if (horizontal)
        FramebufferFillRect(bounds.x + thumb_offset, bounds.y, thumb_extent, bounds.h, theme.role_title[0]);
    else
        FramebufferFillRect(bounds.x, bounds.y + thumb_offset, bounds.w, thumb_extent, theme.role_title[0]);
}

EventResult AppScrollbar::OnEventSelf(const Event& e)
{
    if (e.kind == EventKind::MouseDown && bounds.Contains(e.x, e.y))
    {
        const u32 click_pos = horizontal ? (e.x - bounds.x) : (e.y - bounds.y);
        const u32 track_extent = horizontal ? bounds.w : bounds.h;
        if (track_extent == 0)
            return EventResult::Consumed;
        const u32 new_offset = (click_pos * content_size) / track_extent;
        scroll_offset = new_offset;
        if (on_scroll != nullptr)
            on_scroll(new_offset);
        return EventResult::Consumed;
    }
    return EventResult::NotInterested;
}

} // namespace duetos::drivers::video::app_widgets
