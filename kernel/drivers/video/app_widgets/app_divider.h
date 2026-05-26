#pragma once
#include "drivers/video/app_widgets/widget.h"

namespace duetos::drivers::video::app_widgets
{

struct AppDivider : Widget<AppDivider>
{
    u32 rgb = 0; // 0 = use theme border

    void PaintSelf(Compose& c) const;
};

} // namespace duetos::drivers::video::app_widgets
