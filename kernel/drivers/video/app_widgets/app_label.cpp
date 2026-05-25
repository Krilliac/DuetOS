#include "drivers/video/app_widgets/app_label.h"

namespace duetos::drivers::video::app_widgets
{

void AppLabel::PaintSelf(Compose& /*c*/) const
{
    if (text == nullptr || text[0] == '\0')
        return;
    const u32 w = ChromeTextMeasure(role, text);
    const u32 h = ChromeTextRoleHeight(role);
    const u32 tx = align_left ? bounds.x : bounds.x + (bounds.w > w ? (bounds.w - w) / 2 : 0);
    const u32 ty = bounds.y + (bounds.h > h ? (bounds.h - h) / 2 : 0);
    ChromeTextDraw(role, tx, ty, text, fg_rgb, bg_rgb, weight);
}

} // namespace duetos::drivers::video::app_widgets
