#include "drivers/video/wallpaper.h"

#include "arch/x86_64/serial.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/svg.h"
#include "drivers/video/theme.h"
#include "drivers/video/widget.h"
#include "generated_svg_duet-mark.h"
#include "generated_svg_syscalls-grid.h"
#include "generated_svg_topo.h"
#include "mm/frame_allocator.h"

namespace duetos::drivers::video
{

namespace
{

// Saturating per-channel lighten / darken — same shape as the
// helpers in widget.cpp / taskbar.cpp / menu.cpp. Each TU keeps a
// private copy so the wallpaper module doesn't pull in a tree of
// chrome headers.
u32 LightenRgb(u32 rgb, u32 amount)
{
    u32 r = ((rgb >> 16) & 0xFFU) + amount;
    u32 g = ((rgb >> 8) & 0xFFU) + amount;
    u32 b = (rgb & 0xFFU) + amount;
    if (r > 0xFFU)
        r = 0xFFU;
    if (g > 0xFFU)
        g = 0xFFU;
    if (b > 0xFFU)
        b = 0xFFU;
    return (r << 16) | (g << 8) | b;
}

u32 DarkenRgb(u32 rgb, u32 amount)
{
    const u32 r0 = (rgb >> 16) & 0xFFU;
    const u32 g0 = (rgb >> 8) & 0xFFU;
    const u32 b0 = rgb & 0xFFU;
    const u32 r = (r0 > amount) ? r0 - amount : 0U;
    const u32 g = (g0 > amount) ? g0 - amount : 0U;
    const u32 b = (b0 > amount) ? b0 - amount : 0U;
    return (r << 16) | (g << 8) | b;
}

// Pick the right contrast direction for an ambient stroke over
// `bg`: lighten dark backgrounds, darken light ones, so the
// stroke always reads as a soft accent regardless of theme
// brightness. The mid-luminance gate (~0x80 average) picks the
// direction; saturation handling is delegated to Lighten/Darken.
u32 AmbientStrokeRgb(u32 bg, u32 amount)
{
    const u32 r = (bg >> 16) & 0xFFU;
    const u32 g = (bg >> 8) & 0xFFU;
    const u32 b = bg & 0xFFU;
    const u32 avg = (r + g + b) / 3U;
    return (avg < 0x80U) ? LightenRgb(bg, amount) : DarkenRgb(bg, amount);
}

// Slate10 grid: a sparse Win10-style "subtle grid of dots"
// pattern. Each dot is a single pixel at a regular interval —
// the grid spacing is wide enough that the desktop reads as
// "barely textured" rather than "patterned". Stroke is the
// theme's blue accent at low intensity, so the grid carries
// the Slate10 brand colour faintly.
void PaintSlate10Grid(u32 desktop_rgb, u32 fb_w, u32 fb_h)
{
    constexpr u32 kStep = 32; // pixels between dots
    // Win10 system blue is the theme's accent — slate10's
    // identity colour. We blend it heavily toward the desktop
    // bg so a dot reads as a hint of blue, not a saturated
    // pixel. The blend is 1/8 accent + 7/8 bg, computed by
    // taking the per-channel average of bg + (a small lift
    // toward blue).
    const u32 desk_b = desktop_rgb & 0xFFU;
    const u32 desk_g = (desktop_rgb >> 8) & 0xFFU;
    const u32 desk_r = (desktop_rgb >> 16) & 0xFFU;
    const u32 dot_b = (desk_b + 0xD7U) / 2U;       // bias toward Win10 blue's B
    const u32 dot_g = (desk_g + 0x78U / 4U + 18U); // small G lift
    const u32 dot_r = (desk_r + 18U > 0xFFU) ? 0xFFU : desk_r + 18U;
    const u32 dot_rgb = ((dot_r & 0xFFU) << 16) | ((dot_g & 0xFFU) << 8) | (dot_b & 0xFFU);
    for (u32 y = kStep / 2; y < fb_h; y += kStep)
    {
        for (u32 x = kStep / 2; x < fb_w; x += kStep)
        {
            FramebufferPutPixel(x, y, dot_rgb);
        }
    }
}

// Classic bubbles: a small, scattered set of low-contrast
// circles painted at deterministic positions. The pattern is
// inspired by the Win98 "bubble" wallpapers without a TTF /
// SVG loader — outlined circles via the framebuffer's
// midpoint primitive. Positions are computed from a simple
// Linear-Congruential pattern keyed on (i, fb_w, fb_h) so
// the layout is repeatable and deterministic across boots.
void PaintClassicBubbles(u32 desktop_rgb, u32 fb_w, u32 fb_h)
{
    constexpr u32 kBubbles = 12;
    const u32 stroke = LightenRgb(desktop_rgb, 18);
    // LCG-ish: each bubble's (x, y, r) = a function of i with
    // multiplicative constants chosen by hand to spread evenly.
    for (u32 i = 0; i < kBubbles; ++i)
    {
        const u32 x = ((i * 2654435761U) % fb_w);
        const u32 y = ((i * 40503U + 0x4F1B) % fb_h);
        const u32 r = 18U + (i * 7U) % 28U;
        // Skip bubbles that would land in the bottom 80 pixels
        // (taskbar zone) — keeps the chrome clean.
        if (y + r >= fb_h - 80U)
            continue;
        FramebufferDrawCircle(static_cast<i32>(x), static_cast<i32>(y), r, stroke);
    }
}

// Amber phosphor scanlines: every 3rd row gets a thin lift in
// brightness, evoking a CRT phosphor's horizontal interlace.
// The stroke is a small lift of the desktop bg — preserves the
// monochrome amber identity while adding texture. Skipped near
// the bottom so the taskbar isn't striped.
void PaintAmberScanlines(u32 desktop_rgb, u32 fb_w, u32 fb_h)
{
    constexpr u32 kStep = 3;
    const u32 stripe = LightenRgb(desktop_rgb, 14);
    const u32 floor = (fb_h > 80U) ? fb_h - 80U : fb_h;
    for (u32 y = 0; y < floor; y += kStep)
    {
        FramebufferFillRect(0, y, fb_w, 1U, stripe);
    }
}

// Paint a stack of partial arcs centred horizontally in the
// visible area, mirroring the prototype's `ArcsWallpaper` design.
// Two arc families counter-rotate around a central anchor — six
// concentric partial arcs in a teal-tinted family on the left,
// six amber-tinted arcs on the right. Each arc sweeps ~150° so
// the open ends point away from the centre, producing the
// "interlocking duet" silhouette without needing a full circle.
//
// Stroke is a low-contrast lift of the desktop colour, then
// channel-tinted toward the accent hues. The contrast direction
// flips automatically on light themes via AmbientStrokeRgb, so
// DuetLight gets soft slate-on-cream arcs while slate Duet gets
// pale-on-deep arcs.
void PaintDuetArcs(u32 desktop_rgb, u32 fb_w, u32 fb_h)
{
    const u32 short_side = (fb_w < fb_h) ? fb_w : fb_h;
    if (short_side < 96U)
        return; // pattern would be a low-contrast smudge — skip

    // Anchor the arcs around the same centre point on both
    // sides — only the offset + rotation distinguishes them.
    // Keep the centre biased above the framebuffer's vertical
    // mid-line so the taskbar at the bottom never crosses the
    // largest ring.
    const i32 cx = static_cast<i32>(fb_w / 2u);
    const i32 cy = static_cast<i32>((fb_h * 48u) / 100u);

    // Tint arrays — derived once, used for every concentric ring.
    const u32 base_lift = AmbientStrokeRgb(desktop_rgb, 18);
    const u32 lift_r = (base_lift >> 16) & 0xFFU;
    const u32 lift_g = (base_lift >> 8) & 0xFFU;
    const u32 lift_b = base_lift & 0xFFU;
    const u32 teal_r = lift_r;
    const u32 teal_g = (lift_g + 28U > 0xFFU) ? 0xFFU : lift_g + 28U;
    const u32 teal_b = (lift_b + 22U > 0xFFU) ? 0xFFU : lift_b + 22U;
    const u32 teal = (teal_r << 16) | (teal_g << 8) | teal_b;
    const u32 amber_r = (lift_r + 30U > 0xFFU) ? 0xFFU : lift_r + 30U;
    const u32 amber_g = (lift_g + 16U > 0xFFU) ? 0xFFU : lift_g + 16U;
    const u32 amber_b = lift_b;
    const u32 amber = (amber_r << 16) | (amber_g << 8) | amber_b;

    // Six concentric arcs per side, stepping 8% of the shorter
    // dimension between rings. Each arc pair rotates a small
    // amount so the rings don't visually merge into one fat
    // band.
    constexpr u32 kRings = 6;
    const u32 step = (short_side * 8u) / 100u;
    const u32 r0 = (short_side * 14u) / 100u;
    constexpr i32 kSweep = 150;
    // Horizontal centre offset: shift the arc origin slightly
    // off-centre so the sweep wraps around the shared anchor.
    const i32 offset = static_cast<i32>(short_side / 32u);

    for (u32 i = 0; i < kRings; ++i)
    {
        const i32 r = static_cast<i32>(r0 + i * step);
        const i32 wobble = static_cast<i32>(i) * 3;
        // Teal arc: rotate roughly -30° + per-ring wobble. The
        // open mouth of each arc points down-right, so the arc
        // body sweeps the upper-left quadrant of its anchor.
        FramebufferStrokeArc(cx - offset, cy, r, -90 - wobble, kSweep, 2u, teal);
        // Amber arc: rotate +150° from the teal arc so the open
        // mouth points down-left, giving the mirror sweep.
        FramebufferStrokeArc(cx + offset, cy, r, 90 + wobble, kSweep, 2u, amber);
    }

    // Centre dots — small filled disks at each arc anchor. The
    // teal dot on the left, amber on the right, mirrors the
    // DuetMark's "two halves" story.
    FramebufferFillCircle(cx - offset, cy, 4u, teal);
    FramebufferFillCircle(cx + offset, cy, 3u, amber);
}

// Paint the prototype's brand strap: small caps text in the
// upper-left ("DUETOS · BUILD 0.9.4 · X86_64") and stats in the
// lower-right ("SYSCALLS 57 · DLLS 29 · EXPORTS 760"). Painted
// at low contrast so the rings + window chrome dominate. Used
// only on Duet-family themes — the prototype is the only design
// that calls for chrome-grade typography on the wallpaper.
void PaintDuetBrandText(u32 desktop_rgb, u32 fb_w, u32 fb_h)
{
    if (fb_w < 320U || fb_h < 200U)
        return; // not enough room to read; skip
    const u32 ink = AmbientStrokeRgb(desktop_rgb, 56);
    constexpr const char* kHeader = "DUETOS  BUILD 0.9.4  X86_64";
    constexpr const char* kFooter = "SYSCALLS 57  DLLS 29  EXPORTS 760";
    // Header: 28-px from the top-left corner, monospace style.
    // bg = desktop_rgb (closest match to the gradient at the
    // anchor's row) so the glyph cell doesn't paint a hard rect.
    FramebufferDrawString(28, 28, kHeader, ink, desktop_rgb);
    // Footer: bottom-right, 28-px inset above the taskbar
    // reserve. Compute width from the string length × 8 (8x8
    // bitmap font) so the right edge sits 28-px in.
    u32 fn = 0;
    while (kFooter[fn] != '\0')
        ++fn;
    const u32 fw = fn * 8u;
    const u32 reserve = 80u; // matches Duet taskbar + spacing
    if (fb_h > reserve + 28u && fb_w > fw + 28u)
    {
        FramebufferDrawString(fb_w - fw - 28u, fb_h - reserve - 8u, kFooter, ink, desktop_rgb);
    }
}

// SVG-backed wallpaper layer. The 3 embedded assets parse once at
// boot via WallpaperSvgInit(); subsequent WallpaperPaint passes
// just call SvgRender(image, ...). Each SvgImage borrows the
// generated byte array (lifetime = kernel image), and the shape /
// path-segment storage is in static .bss (sized for the assets +
// modest headroom).

constinit SvgImage g_svg_duet_mark{};
constinit SvgImage g_svg_topo{};
constinit SvgImage g_svg_syscalls_grid{};

constinit SvgShape g_svg_shapes_duet_mark[8]{};
constinit SvgShape g_svg_shapes_topo[32]{};
constinit SvgShape g_svg_shapes_syscalls_grid[32]{};

constinit PathSegment g_svg_segs_duet_mark[64]{};
constinit PathSegment g_svg_segs_topo[16]{};
constinit PathSegment g_svg_segs_syscalls_grid[16]{};

constinit bool g_svg_inited = false;

void InitSvgImage(SvgImage& img, const u8* bytes, u32 size, SvgShape* shape_buf, u32 max_shapes, PathSegment* seg_buf,
                  u32 max_segs, const char* tag)
{
    img.shapes = shape_buf;
    img.max_shapes = max_shapes;
    img.path_segments = seg_buf;
    img.max_path_segments = max_segs;
    if (!SvgParse(bytes, size, &img))
    {
        arch::SerialWrite("[video/wallpaper] SVG parse failed: ");
        arch::SerialWrite(tag);
        arch::SerialWrite("\n");
        img.shape_count = 0;
    }
}

} // namespace

void WallpaperSvgInit()
{
    if (g_svg_inited)
        return;
    g_svg_inited = true;
    using generated::kBinSvg_duet_mark_Bytes;
    using generated::kBinSvg_syscalls_grid_Bytes;
    using generated::kBinSvg_topo_Bytes;
    InitSvgImage(g_svg_duet_mark, kBinSvg_duet_mark_Bytes, sizeof(kBinSvg_duet_mark_Bytes), g_svg_shapes_duet_mark,
                 sizeof(g_svg_shapes_duet_mark) / sizeof(g_svg_shapes_duet_mark[0]), g_svg_segs_duet_mark,
                 sizeof(g_svg_segs_duet_mark) / sizeof(g_svg_segs_duet_mark[0]), "duet-mark");
    InitSvgImage(g_svg_topo, kBinSvg_topo_Bytes, sizeof(kBinSvg_topo_Bytes), g_svg_shapes_topo,
                 sizeof(g_svg_shapes_topo) / sizeof(g_svg_shapes_topo[0]), g_svg_segs_topo,
                 sizeof(g_svg_segs_topo) / sizeof(g_svg_segs_topo[0]), "topo");
    InitSvgImage(g_svg_syscalls_grid, kBinSvg_syscalls_grid_Bytes, sizeof(kBinSvg_syscalls_grid_Bytes),
                 g_svg_shapes_syscalls_grid, sizeof(g_svg_shapes_syscalls_grid) / sizeof(g_svg_shapes_syscalls_grid[0]),
                 g_svg_segs_syscalls_grid, sizeof(g_svg_segs_syscalls_grid) / sizeof(g_svg_segs_syscalls_grid[0]),
                 "syscalls-grid");
    arch::SerialWrite("[video/wallpaper] SVG assets parsed (duet-mark/topo/syscalls-grid)\n");
}

void WallpaperPaint(u32 desktop_rgb)
{
    if (!FramebufferAvailable())
    {
        return;
    }
    const auto info = FramebufferGet();

    switch (ThemeCurrentId())
    {
    case ThemeId::Duet:
    case ThemeId::DuetLight:
    case ThemeId::DuetBlue:
    case ThemeId::DuetViolet:
    case ThemeId::DuetGreen:
    case ThemeId::DuetClassic:
        // Refined Duet wallpaper:
        //   1. Concentric partial arcs in teal + amber, mirroring
        //      the prototype's `ArcsWallpaper` motif.
        //   2. Brand text strap (top-left build banner +
        //      bottom-right stats footer) for the prototype's
        //      "instrumented surface" feel.
        //
        // Earlier slices stacked topo contour rings underneath
        // the arcs; the layered look read as visual noise once
        // the chrome (windows + taskbar) sat on top. Dropping
        // the topo layer keeps the desktop reading as "calm
        // surface, sharp chrome" the way the prototype does.
        // Both paints use AmbientStrokeRgb internally so the
        // contrast direction flips on the light variant
        // automatically. Accent variants share the neutral arc
        // tints since the START button + active-tab dot already
        // carry the variant's brand hue.
        PaintDuetArcs(desktop_rgb, info.width, info.height);
        PaintDuetBrandText(desktop_rgb, info.width, info.height);
        // Live kernel-stats footer used to paint syscall / DLL / export
        // counts in the bottom-right of the wallpaper. With the chrome
        // polish slice (drag affordance, focus shadow, app glyphs) the
        // wallpaper competes with window content for the eye; the
        // stats are reachable from Sysmon + About anyway. Skipped to
        // keep the desktop reading as "calm surface, sharp chrome".
        break;
    case ThemeId::Classic:
        PaintClassicBubbles(desktop_rgb, info.width, info.height);
        break;
    case ThemeId::Slate10:
        PaintSlate10Grid(desktop_rgb, info.width, info.height);
        // Subtle syscalls-grid accent over the Slate10 grid — the
        // grid pattern fits the Win10/Unreal slate aesthetic.
        if (g_svg_inited)
        {
            SvgRender(g_svg_syscalls_grid, 0, 0, info.width, info.height);
        }
        break;
    case ThemeId::Amber:
        PaintAmberScanlines(desktop_rgb, info.width, info.height);
        break;
    default:
        break;
    }
}

} // namespace duetos::drivers::video
