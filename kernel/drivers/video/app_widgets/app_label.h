#pragma once
#include "drivers/video/app_widgets/widget.h"
#include "drivers/video/chrome_text.h"

namespace duetos::drivers::video::app_widgets
{

struct AppLabel : Widget<AppLabel>
{
    const char* text = "";
    ChromeTextRole role = ChromeTextRole::Body;
    ChromeTextWeight weight = ChromeTextWeight::Regular;
    u32 fg_rgb = 0xFFFFFFU;
    u32 bg_rgb = 0; // 0 = transparent
    bool align_left = false;

    void PaintSelf(Compose& c) const;
};

} // namespace duetos::drivers::video::app_widgets
