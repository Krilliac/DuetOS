#pragma once

#include "drivers/video/app_widgets/widget.h"

namespace duetos::drivers::video::app_widgets
{

struct AppScrollbar : Widget<AppScrollbar>
{
    u32 content_size = 0;
    u32 viewport_size = 0;
    u32 scroll_offset = 0;
    bool horizontal = false;
    void (*on_scroll)(u32 new_offset) = nullptr;

    void PaintSelf(Compose& c) const;
    EventResult OnEventSelf(const Event& e);
};

} // namespace duetos::drivers::video::app_widgets
