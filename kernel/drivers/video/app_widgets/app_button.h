#pragma once

#include "drivers/video/app_widgets/widget.h"
#include "drivers/video/chrome_text.h"

namespace duetos::drivers::video::app_widgets
{

struct AppButton : Widget<AppButton>
{
    const char* label = "";
    void (*on_click)() = nullptr;
    ChromeTextWeight weight = ChromeTextWeight::Regular;
    u32 bg_rgb = 0; // 0 = theme role_title[0]
    u32 fg_rgb = 0xFFFFFFU;

    void PaintSelf(Compose& c) const;
    EventResult OnEventSelf(const Event& e);
};

} // namespace duetos::drivers::video::app_widgets
