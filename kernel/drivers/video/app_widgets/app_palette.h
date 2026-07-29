#pragma once

#include "drivers/video/blend_math.h"
#include "util/types.h"

/*
 * Aurora app-interior palette — docs/aurora-theme/IMPLEMENTATION.md §8.
 *
 * The shell chrome (window frame, taskbar island, wallpaper) already
 * speaks the Aurora vocabulary. The app *interiors* did not: every
 * in-kernel app baked its own saturated RGB literals (a red calculator
 * key, cyan file-list headers, green-on-black process rows), so a
 * screenshot read as "same desktop, different applications".
 *
 * This header is the one place that turns the design's token names
 * into concrete 0x00RRGGBB values. Two rules keep it honest:
 *
 *   1. **Opt-in.** `AppPalette::aurora` is false for every palette that
 *      opts out of the glass vocabulary (Classic / Slate10 / Amber /
 *      DuetClassic / HighContrast). Those themes must keep the exact
 *      look they had before this file existed, so an app that restyles
 *      picks `aurora ? pal.<token> : <its historical literal>`.
 *      The `ThemeSelfTest` Aurora invariants already pin the
 *      flat-theme opt-out; this API rides that same gate rather than
 *      re-deriving a theme whitelist (which would rot the next time a
 *      palette is added).
 *
 *   2. **Relative to the surface it paints on.** The framebuffer has no
 *      per-pixel alpha and `FramebufferDrawString` stamps an opaque
 *      background cell behind every glyph, so a row wash cannot be a
 *      live blend — it has to be resolved to an opaque colour up front.
 *      `AppPaletteFor(body)` does that: every surface token is the
 *      design's rgba() composited over the app's own client fill, and
 *      the ink ramp flips when that fill is light (Notes' cream paper,
 *      the whole DuetLight family) so dark-on-light still reads.
 *
 * The math lives in `AppPaletteMake` — constexpr, kernel-free, and
 * covered by tests/host/test_app_palette.cpp. `AppPaletteFor` is the
 * thin kernel wrapper that samples the live theme.
 */

namespace duetos::drivers::video::app_widgets
{

/// Resolved app-interior colours. Every field is an opaque
/// 0x00RRGGBB ready to hand to FramebufferFillRect / DrawString.
struct AppPalette
{
    /// True iff the active theme opts into the Aurora vocabulary.
    /// False means "paint what you painted before" — see AppPick.
    bool aurora;

    /// The client fill the rest of the tokens were resolved against.
    u32 body;

    u32 ink;   // primary content text        (--ink)
    u32 ink_2; // secondary / values          (--ink-2)
    u32 ink_3; // muted labels, units, tags   (--ink-3)

    u32 recess; // sunken content pane        (--recess)
    u32 wash;   // zebra row / raised control (--glass-3)
    u32 line;   // hairline rule              (--line)
    u32 sel;    // selected row fill          (accent 14 %)

    u32 accent;      // native ABI channel
    u32 accent_peer; // Win32 PE peer channel
    u32 danger;      // --danger #ff5f57
};

/// Design tokens, dark mode (README "Design tokens").
inline constexpr u32 kAppInkDark = 0x00EEF3F9;
inline constexpr u32 kAppInk2Dark = 0x00A7B3C2;
inline constexpr u32 kAppInk3Dark = 0x0068737F;
/// ...and light mode, for a cream / near-white client fill.
inline constexpr u32 kAppInkLight = 0x00111A24;
inline constexpr u32 kAppInk2Light = 0x004B5765;
inline constexpr u32 kAppInk3Light = 0x007B8794;

inline constexpr u32 kAppDanger = 0x00FF5F57;

/// Rec. 601 luma, 0..255. Used only to decide whether a surface is
/// light enough to need the inverted ink ramp.
constexpr u32 AppLuma(u32 rgb)
{
    const u32 r = (rgb >> 16) & 0xFFU;
    const u32 g = (rgb >> 8) & 0xFFU;
    const u32 b = rgb & 0xFFU;
    return (r * 77U + g * 150U + b * 29U) >> 8U;
}

/// Resolve the Aurora token set against `body`. Pure — no kernel
/// state, so the hosted test can exercise it directly.
///
/// `accent_peer` of 0 means "this palette has no second channel";
/// it then collapses onto `accent` exactly as the taskbar and
/// wallpaper painters already do.
constexpr AppPalette AppPaletteMake(u32 body, u32 accent, u32 accent_peer, bool aurora)
{
    const bool light = AppLuma(body) > 128U;

    // The wash / hairline overlays are white on a dark surface and the
    // design's cool near-black on a light one, so a zebra row reads as
    // "slightly raised" in both modes instead of vanishing.
    const u32 overlay = light ? 0x00091426U : 0x00FFFFFFU;
    // --recess is a deep tint, not a white wash: the same near-black in
    // both modes, just at a lower alpha over a light surface.
    const u32 recess_tint = light ? 0x00091426U : 0x0004070BU;
    const u8 recess_alpha = light ? static_cast<u8>(12U) : static_cast<u8>(107U); // .045 / .42

    AppPalette p{};
    p.aurora = aurora;
    p.body = body & 0x00FFFFFFU;
    p.ink = light ? kAppInkLight : kAppInkDark;
    p.ink_2 = light ? kAppInk2Light : kAppInk2Dark;
    p.ink_3 = light ? kAppInk3Light : kAppInk3Dark;
    p.recess = BlendOver(p.body, recess_tint, recess_alpha);
    p.wash = BlendOver(p.body, overlay, 15U); // --glass-3 .06
    p.line = BlendOver(p.body, overlay, 26U); // --line .10
    p.sel = BlendOver(p.body, accent, 36U);   // accent 14 %
    p.accent = accent & 0x00FFFFFFU;
    p.accent_peer = (accent_peer == 0) ? (accent & 0x00FFFFFFU) : (accent_peer & 0x00FFFFFFU);
    p.danger = kAppDanger;
    return p;
}

/// Live palette for an app whose client area is filled with `body`.
/// Samples the active theme's accent pair and Aurora opt-in.
AppPalette AppPaletteFor(u32 body_rgb);

/// Paint an app's bottom status strip: a `wash` band with a 1 px
/// `line` hairline along its top edge. Files, Task Manager and the
/// kernel-log viewer all carry one; the hairline is what stops the
/// strip reading as a second, detached window.
///
/// No-ops when `w` or `h` is 0. Caller holds the compositor lock.
void AppStatusBarDraw(u32 x, u32 y, u32 w, u32 h, const AppPalette& p);

} // namespace duetos::drivers::video::app_widgets
