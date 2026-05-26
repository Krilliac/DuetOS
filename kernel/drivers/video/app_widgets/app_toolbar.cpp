#include "drivers/video/app_widgets/app_toolbar.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/shadow.h"
#include "drivers/video/theme.h"

namespace duetos::drivers::video::app_widgets
{

void AppToolbar::PaintSelf(Compose& /*c*/) const
{
    if (bounds.w == 0 || bounds.h == 0)
        return;
    const auto& theme = ThemeCurrent();
    const u32 bg = (bg_rgb == 0) ? theme.taskbar_bg : bg_rgb;
    if (ThemeTactilityEffective())
    {
        const u8 opacity = ThemeIntensityEffective(theme.shadow_intensity_active);
        if (opacity > 0)
        {
            RenderSoftShadow(static_cast<i32>(bounds.x), static_cast<i32>(bounds.y), bounds.w, bounds.h, 8U, opacity,
                             0x00000000U);
        }
    }
    FramebufferFillRect(bounds.x, bounds.y, bounds.w, bounds.h, bg);
    FramebufferFillRect(bounds.x, bounds.y + bounds.h - 1, bounds.w, 1, theme.window_border);
}

} // namespace duetos::drivers::video::app_widgets
