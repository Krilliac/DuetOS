#pragma once

#include "drivers/video/app_widgets/widget.h"

namespace duetos::drivers::video::app_widgets
{

struct AppListRow : Widget<AppListRow>
{
    const char* label = "";
    void (*on_click)() = nullptr;
    bool selected = false;
    u32 accent_rgb = 0; // 0 = theme accent stripe colour

    void PaintSelf(Compose& c) const;
    EventResult OnEventSelf(const Event& e);
};

} // namespace duetos::drivers::video::app_widgets
