#pragma once
#include "drivers/video/app_widgets/widget.h"

namespace duetos::drivers::video::app_widgets
{

/// Theme-coloured panel with optional shadow under tactility-on themes.
/// No events; paint-only.
struct AppPanel : Widget<AppPanel>
{
    u32 bg_rgb = 0;         // 0 = use ThemeCurrent().role_client[0]
    u32 border_rgb = 0;     // 0 = use ThemeCurrent().window_border
    u8 shadow_radius = 12U; // 0 disables shadow even on tactility-on themes

    void PaintSelf(Compose& c) const;
};

} // namespace duetos::drivers::video::app_widgets
