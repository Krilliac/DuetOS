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
    // Toolbar chips centre their label; a nav-rail row reads as a list
    // item and wants its label on the left edge. Mirrors AppLabel's
    // flag of the same name. Default false keeps every existing
    // button pixel-identical.
    bool align_left = false;
    u32 pad_left = 10; // honoured only when align_left

    void PaintSelf(Compose& c) const;
    EventResult OnEventSelf(const Event& e);
};

} // namespace duetos::drivers::video::app_widgets
