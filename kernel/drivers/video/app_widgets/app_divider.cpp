#include "drivers/video/app_widgets/app_divider.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/theme.h"

namespace duetos::drivers::video::app_widgets
{

void AppDivider::PaintSelf(Compose& /*c*/) const
{
    if (bounds.w == 0 || bounds.h == 0)
        return;
    const u32 colour = (rgb == 0) ? ThemeCurrent().window_border : rgb;
    FramebufferFillRect(bounds.x, bounds.y, bounds.w, bounds.h, colour);
}

} // namespace duetos::drivers::video::app_widgets
