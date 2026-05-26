#pragma once

#include "drivers/video/app_widgets/widget.h"

namespace duetos::drivers::video::app_widgets
{

struct AppToolbar : Widget<AppToolbar>
{
    u32 bg_rgb = 0;

    void PaintSelf(Compose& c) const;
};

} // namespace duetos::drivers::video::app_widgets
