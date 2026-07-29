#include "drivers/video/app_widgets/app_palette.h"

#include "drivers/video/framebuffer.h"
#include "drivers/video/theme.h"

namespace duetos::drivers::video::app_widgets
{

namespace
{

// Horizontal padding either side of a pill label, and the pill's
// corner radius. 9.5 px uppercase in a 99-radius capsule at 1920
// scales to "as round as a 14 px strip gets" here.
constexpr u32 kPillPadX = 5;
constexpr u32 kPillRadius = 5;
constexpr u32 kGlyphW = 8;

// Alpha of the pill's tint wash. The design fills ABI badges at 18 %
// of the channel colour and sets the label in the channel itself.
constexpr u8 kPillFillAlpha = 46;

u32 TextCells(const char* text)
{
    u32 n = 0;
    while (text != nullptr && text[n] != '\0')
        ++n;
    return n;
}

} // namespace

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

u32 AppPillWidth(const char* text)
{
    const u32 cells = TextCells(text);
    if (cells == 0)
        return 0;
    return cells * kGlyphW + 2 * kPillPadX;
}

void AppPillDraw(u32 x, u32 y, u32 w, u32 h, const char* text, u32 tint, u32 body_rgb)
{
    if (w == 0 || h == 0)
        return;
    const u32 fill = BlendOver(body_rgb & 0x00FFFFFFU, tint & 0x00FFFFFFU, kPillFillAlpha);
    const u32 radius = (h / 2 < kPillRadius) ? h / 2 : kPillRadius;
    FramebufferFillRoundRect(x, y, w, h, radius, fill);

    const u32 cells = TextCells(text);
    if (cells == 0)
        return;
    const u32 tw = cells * kGlyphW;
    const u32 tx = x + ((w > tw) ? (w - tw) / 2 : 0);
    const u32 ty = y + ((h > 8) ? (h - 8) / 2 : 0);
    FramebufferDrawString(tx, ty, text, tint, fill);
}

void AppStatusBarDraw(u32 x, u32 y, u32 w, u32 h, const AppPalette& p)
{
    if (w == 0 || h == 0)
        return;
    FramebufferFillRect(x, y, w, h, p.wash);
    FramebufferFillRect(x, y, w, 1, p.line);
}

} // namespace duetos::drivers::video::app_widgets
