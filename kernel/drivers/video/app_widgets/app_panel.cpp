#include "drivers/video/app_widgets/app_panel.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/shadow.h"
#include "drivers/video/theme.h"

namespace duetos::drivers::video::app_widgets
{

void AppPanel::PaintSelf(Compose& /*c*/) const
{
    if (bounds.w == 0 || bounds.h == 0)
        return;
    const auto& theme = ThemeCurrent();
    const u32 bg = (bg_rgb == 0) ? theme.role_client[0] : bg_rgb;
    const u32 border = (border_rgb == 0) ? theme.window_border : border_rgb;
    if (ThemeTactilityEffective() && shadow_radius > 0)
    {
        const u8 opacity = ThemeIntensityEffective(theme.shadow_intensity_active);
        if (opacity > 0)
        {
            RenderSoftShadow(static_cast<i32>(bounds.x), static_cast<i32>(bounds.y), bounds.w, bounds.h, shadow_radius,
                             opacity, 0x00000000U);
        }
    }
    FramebufferFillRect(bounds.x, bounds.y, bounds.w, bounds.h, bg);
    FramebufferDrawRect(bounds.x, bounds.y, bounds.w, bounds.h, border, 1);
}

} // namespace duetos::drivers::video::app_widgets
