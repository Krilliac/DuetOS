#include "drivers/video/app_widgets/app_palette.h"

#include "drivers/video/framebuffer.h"
#include "drivers/video/theme.h"

namespace duetos::drivers::video::app_widgets
{

AppPalette AppPaletteFor(u32 body_rgb)
{
    const Theme& t = ThemeCurrent();
    // Under glass the window body is `colour_client` composited over the
    // backdrop, not stamped — so an app that fills its content area with
    // the raw role colour paints a visibly darker patch inside its own
    // window. Flatten the same blend against the desktop ground here so
    // the app's interior seams into the chrome around it.
    u32 body = body_rgb;
    if (t.glass_alpha != 0 && t.glass_alpha != 255)
        body = BlendOver(t.desktop_bg, body_rgb, t.glass_alpha);
    // `aurora_wallpaper` is the palette-level opt-in the theme self-test
    // already pins against the tactility posture, so the app interiors
    // ride it rather than enumerating theme ids (which would go stale
    // the next time a palette lands).
    return AppPaletteMake(body, t.taskbar_accent, t.accent_peer, t.aurora_wallpaper);
}

void AppStatusBarDraw(u32 x, u32 y, u32 w, u32 h, const AppPalette& p)
{
    if (w == 0 || h == 0)
        return;
    FramebufferFillRect(x, y, w, h, p.wash);
    FramebufferFillRect(x, y, w, 1, p.line);
}

} // namespace duetos::drivers::video::app_widgets
