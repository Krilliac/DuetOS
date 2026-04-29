#include "drivers/video/wallpaper.h"

#include "arch/x86_64/serial.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/svg.h"
#include "drivers/video/theme.h"
#include "generated_svg_duet-mark.h"
#include "generated_svg_syscalls-grid.h"
#include "generated_svg_topo.h"

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

// Topo backdrop: a stack of low-contrast concentric circles
// centered in the visible area. The prototype's `topo` wallpaper
// is a contour-line motif; concentric circles approximate it
// without needing a vector path stroker. Painted UNDER the
// duet-arcs rings so the desktop reads as layered terrain rather
// than a single graphic element.
void PaintTopo(u32 desktop_rgb, u32 fb_w, u32 fb_h)
{
    // Multi-source contour layer — better match for the
    // prototype's topo SVG than a single bullseye. Four
    // "peaks" scattered across the frame each carry an
    // independent concentric stack; their outermost rings
    // overlap so the surface reads as a real topo map.
    // Painted UNDER the duet-arcs rings so foreground chrome
    // still dominates.
    const u32 short_side = (fb_w < fb_h) ? fb_w : fb_h;
    if (short_side < 64U)
        return;
    // Adaptive contrast — half the duet-arcs strength so topo
    // sits as ambient ground.
    const u32 stroke_rgb = AmbientStrokeRgb(desktop_rgb, 9);
    // Four anchor peaks at (x%, y%) of the framebuffer. The
    // % coords are deliberately spread so adjacent rings
    // overlap regardless of aspect ratio: corners + a centred
    // peak below the duet-arcs would compete; biased above
    // makes room for the chrome below.
    struct Peak
    {
        u32 cx_pct;
        u32 cy_pct;
        u32 ring_step;
        u32 ring_count;
    };
    constexpr Peak kPeaks[] = {
        {18, 22, 24, 6},
        {72, 30, 28, 5},
        {38, 56, 32, 7},
        {86, 64, 22, 5},
    };
    for (const auto& p : kPeaks)
    {
        const i32 cx = static_cast<i32>((fb_w * p.cx_pct) / 100u);
        const i32 cy = static_cast<i32>((fb_h * p.cy_pct) / 100u);
        for (u32 i = 1; i <= p.ring_count; ++i)
        {
            const u32 r = i * p.ring_step;
            FramebufferDrawCircle(cx, cy, r, stroke_rgb);
        }
    }
}

// Paint two interlocking outlined circles centered horizontally
// in the visible area, each ~28% of the smaller framebuffer
// dimension. Stroke is a low-contrast lift of the desktop colour
// so the rings read as ambient texture rather than UI chrome.
// Two-pixel stroke (two concentric outline plots) so the rings
// survive the inactive-window dim overlay.
//
// The teal-tinted ring sits left, the amber-tinted ring right —
// matching the per-app icon hue convention and the in-START
// DuetMark.
void PaintDuetArcs(u32 desktop_rgb, u32 fb_w, u32 fb_h)
{
    // Diameter: ~56% of the shorter side, capped so even very
    // tall framebuffers don't draw rings off the visible area.
    const u32 short_side = (fb_w < fb_h) ? fb_w : fb_h;
    const u32 r = (short_side * 28) / 100;
    if (r < 32U)
        return; // pattern would be a low-contrast smudge — skip
    // Vertical anchor: 38% down the framebuffer, biased above
    // the centre so the taskbar at the bottom doesn't overlap
    // the rings.
    const u32 cy = (fb_h * 38) / 100;
    // Horizontal: rings overlap by half their radius — gives
    // the prototype's "interlocking" feel without having to
    // compute precise geometry from the SVG.
    const u32 cx_a = fb_w / 2 - r / 2;
    const u32 cx_b = fb_w / 2 + r / 2;
    // Stroke colours: shift the desktop bg by a small amount in
    // the right contrast direction (light theme darkens, dark
    // theme lightens), then tint slightly toward teal / amber.
    // Strong enough to be visible on the gradient, weak enough
    // not to compete with windows.
    const u32 base_lift = AmbientStrokeRgb(desktop_rgb, 22);
    // Tint = base_lift biased toward the accent hue. We do this
    // by running another lighten on the relevant channel and
    // letting the others stay at the base lift's level. The
    // channel-mix approximation is good enough for a backdrop.
    const u32 lift_r = (base_lift >> 16) & 0xFFU;
    const u32 lift_g = (base_lift >> 8) & 0xFFU;
    const u32 lift_b = base_lift & 0xFFU;
    // Teal: bias toward G + B.
    const u32 teal_r = lift_r;
    const u32 teal_g = (lift_g + 30U > 0xFFU) ? 0xFFU : lift_g + 30U;
    const u32 teal_b = (lift_b + 22U > 0xFFU) ? 0xFFU : lift_b + 22U;
    const u32 teal = (teal_r << 16) | (teal_g << 8) | teal_b;
    // Amber: bias toward R + G.
    const u32 amber_r = (lift_r + 32U > 0xFFU) ? 0xFFU : lift_r + 32U;
    const u32 amber_g = (lift_g + 18U > 0xFFU) ? 0xFFU : lift_g + 18U;
    const u32 amber_b = lift_b;
    const u32 amber = (amber_r << 16) | (amber_g << 8) | amber_b;

    FramebufferDrawCircle(static_cast<i32>(cx_a), static_cast<i32>(cy), r, teal);
    FramebufferDrawCircle(static_cast<i32>(cx_a), static_cast<i32>(cy), r - 1U, teal);
    FramebufferDrawCircle(static_cast<i32>(cx_b), static_cast<i32>(cy), r, amber);
    FramebufferDrawCircle(static_cast<i32>(cx_b), static_cast<i32>(cy), r - 1U, amber);

    // Connecting Bezier ribbon: a single cubic that arcs above
    // the rings, peaks roughly between the two centres, and
    // settles back to the rings' anchor on each side. Renders
    // through `FramebufferStrokePath` so the new primitive gets
    // a real wallpaper-side consumer rather than living unwired.
    // Stroke colour blends the two accents — cool-warm midpoint
    // sits naturally between the two arc tints. Thickness 2
    // keeps it secondary to the main rings.
    const u32 mid_r = (teal_r + amber_r) / 2U;
    const u32 mid_g = (teal_g + amber_g) / 2U;
    const u32 mid_b = (teal_b + amber_b) / 2U;
    const u32 ribbon = (mid_r << 16) | (mid_g << 8) | mid_b;
    const i32 ax = static_cast<i32>(cx_a);
    const i32 ay = static_cast<i32>(cy) - static_cast<i32>(r / 2U);
    const i32 bx = static_cast<i32>(cx_b);
    const i32 by = ay;
    const i32 cp1y = static_cast<i32>(cy) - static_cast<i32>(r);
    const PathSegment ribbon_path[] = {
        {PathOp::Move, {{ax, ay}, {0, 0}, {0, 0}}},
        {PathOp::Cubic, {{ax, cp1y}, {bx, cp1y}, {bx, by}}},
    };
    FramebufferStrokePath(ribbon_path, 2, 2, ribbon);
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
        // Every Duet-family theme stacks the topo backdrop under
        // the foreground arcs — the layered look matches the
        // prototype's multi-layer SVG composition. Both paints
        // use AmbientStrokeRgb internally so the contrast
        // direction flips on the light variant automatically.
        // The accent variants share the same neutral arc tints
        // since the START button + active-tab dot already carry
        // the variant's brand hue.
        PaintTopo(desktop_rgb, info.width, info.height);
        PaintDuetArcs(desktop_rgb, info.width, info.height);
        // Layered SVG accents (parsed once at boot via
        // WallpaperSvgInit). Topo SVG covers the full surface as
        // the backdrop; the DuetMark sits centred at ~14% of the
        // shorter dimension as a subtle brand tag. No-op when
        // SvgInit hasn't been run.
        if (g_svg_inited)
        {
            SvgRender(g_svg_topo, 0, 0, info.width, info.height);
            const u32 mark_w = (info.width < info.height ? info.width : info.height) / 4u;
            const u32 mark_h = mark_w / 2u;
            SvgRender(g_svg_duet_mark, static_cast<i32>((info.width - mark_w) / 2u),
                      static_cast<i32>(info.height * 70u / 100u - mark_h / 2u), mark_w, mark_h);
        }
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
