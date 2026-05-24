#include "drivers/video/wallpaper.h"

#include "arch/x86_64/serial.h"
#include "log/klog.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/svg.h"
#include "drivers/video/theme.h"
#include "drivers/video/widget.h"
#include "generated_svg_duet-mark.h"
#include "generated_svg_syscalls-grid.h"
#include "generated_svg_topo.h"
#include "mm/frame_allocator.h"
#include "time/timekeeper.h"

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

// -----------------------------------------------------------------------
// Pass B — ambient motion state + phase-math helpers.
//
// All three helpers mirror tests/host/test_motion_math.cpp exactly for
// ArcRotationDegrees and TopoDriftOffsetPx. PulseAlphaBoost uses a
// smoothstep approximation (3u²-2u³) instead of 0.5-0.5*cos(2πt)
// because the kernel has no <math.h>. Both forms are bounded [0, peak],
// both reach 0 at t=0 and t=1, both peak at midperiod — the max curve
// deviation vs the true cosine is ~1.5 %, invisible at the 8 % alpha
// amplitude this drives.
// -----------------------------------------------------------------------

struct MotionState
{
    u64  base_ms;        // monotonic base captured on first tick
    u64  last_minute;    // minute of last clock-roll detection (login path)
    i32  topo_drift_px;  // current horizontal drift offset, [0, fb_w)
    double arc_rot_deg;  // current rotation, [-5, +5]
    double pulse_boost;  // current pulse alpha boost, [0, kPulsePeak]
};
static MotionState g_motion = {0, 0, 0, 0.0, 0.0};

constexpr u64    kArcRotPeriodMs    = 60000; // ±5° sweep over 60 s
constexpr u64    kPulsePeriodMs     =  8000; // 8 s breath
constexpr double kPulsePeak         =  0.08; // alpha boost at peak
constexpr i32    kTopoDriftPxPerSec =     1; // 1 px/s

// Triangular sweep −5 → +5 → −5 over period_ms.
// Matches tests/host/test_motion_math.cpp ArcRotationDegrees exactly.
inline double ArcRotationDegrees(u64 now_ms, u64 period_ms)
{
    if (period_ms == 0)
        return 0.0;
    const double t     = double(now_ms % period_ms) / double(period_ms);
    const double phase = t < 0.5 ? (t * 4.0) - 1.0 : 3.0 - (t * 4.0);
    return 5.0 * phase;
}

// Smoothstep breath [0..peak..0] over period_ms.
// Kernel approximation of the sine breath in the hosted test — no
// <math.h> available. Max deviation from true sine ≈ 1.5 % at 8 %
// amplitude, invisible in practice.
inline double PulseAlphaBoost(u64 now_ms, u64 period_ms, double peak)
{
    if (period_ms == 0)
        return 0.0;
    const double t = double(now_ms % period_ms) / double(period_ms);
    const double u = t < 0.5 ? t * 2.0 : (1.0 - t) * 2.0; // 0..1..0
    const double s = (3.0 * u * u) - (2.0 * u * u * u);    // smoothstep
    return peak * s;
}

// Horizontal drift offset that wraps at fb_w pixels.
// Matches tests/host/test_motion_math.cpp TopoDriftOffsetPx exactly.
inline i32 TopoDriftOffsetPx(u64 now_ms, i32 speed_px_per_s, i32 fb_w)
{
    if (fb_w <= 0)
        return 0;
    const i64 total = (i64(now_ms) * speed_px_per_s) / 1000;
    i64 mod = total % i64(fb_w);
    if (mod < 0)
        mod += i64(fb_w);
    return i32(mod);
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
// rot_deg: added to each arc's start angle for ambient rotation
//          ([-5, +5] from WallpaperTick; 0.0 when motion is off).
// pulse:   fractional extra brightness boost [0, kPulsePeak] applied
//          to the stroke colours, giving the arcs a slow breathing
//          presence. 0.0 when motion is off.
void PaintDuetArcs(u32 desktop_rgb, u32 fb_w, u32 fb_h, double rot_deg, double pulse)
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
    const u32 amber_r = (lift_r + 30U > 0xFFU) ? 0xFFU : lift_r + 30U;
    const u32 amber_g = (lift_g + 16U > 0xFFU) ? 0xFFU : lift_g + 16U;
    const u32 amber_b = lift_b;

    // Pulse boost: convert the fractional boost to a per-channel
    // integer lift (0..20 at kPulsePeak=0.08, scale is 255*0.08≈20).
    const u32 pulse_lift = static_cast<u32>(pulse * 255.0);
    const u32 teal = ((teal_r < 0xFFU - pulse_lift ? teal_r + pulse_lift : 0xFFU) << 16) |
                     ((teal_g < 0xFFU - pulse_lift ? teal_g + pulse_lift : 0xFFU) << 8) |
                     (teal_b < 0xFFU - pulse_lift ? teal_b + pulse_lift : 0xFFU);
    const u32 amber = ((amber_r < 0xFFU - pulse_lift ? amber_r + pulse_lift : 0xFFU) << 16) |
                      ((amber_g < 0xFFU - pulse_lift ? amber_g + pulse_lift : 0xFFU) << 8) |
                      (amber_b < 0xFFU - pulse_lift ? amber_b + pulse_lift : 0xFFU);

    // Rotation: convert rot_deg (double, [-5, +5]) to an integer degree
    // offset applied to every arc's start angle, giving a slow sweep.
    const i32 rot_i = static_cast<i32>(rot_deg);

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
        // Teal arc: rotate roughly -30° + per-ring wobble + ambient rotation.
        FramebufferStrokeArc(cx - offset, cy, r, -90 - wobble + rot_i, kSweep, 2u, teal);
        // Amber arc: rotate +150° from the teal arc + ambient rotation.
        FramebufferStrokeArc(cx + offset, cy, r,  90 + wobble + rot_i, kSweep, 2u, amber);
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
        // SVG decoder rejected the blob — either truncated /
        // malformed input from an asset bake step regression, or
        // a feature our parser doesn't support. Surface via klog
        // with the asset tag so a regression in the wallpaper
        // bake pipeline is visible in dmesg.
        KLOG_WARN_S("drivers/video/wallpaper", "SVG parse failed", "tag", tag);
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
        //
        // Pass B: topo SVG renders under the arcs with horizontal
        // drift applied as a shifted render pass. When motion is
        // active the topo drifts at 1 px/s with a wrap-around
        // copy so the seam is invisible. When motion is off
        // drift_px == 0 and the two render calls collapse to
        // the same origin (the second is entirely off-screen
        // and clipped by the framebuffer driver).
        if (g_svg_inited && g_svg_topo.shape_count > 0)
        {
            const i32 drift = g_motion.topo_drift_px;
            // Pulse tint: blend topo curves toward the theme accent colour
            // proportional to the current pulse_boost so the contour lines
            // breathe in sync with the arc brightness. Alpha byte encodes
            // pulse_boost [0, kPulsePeak=0.08] scaled to [0, 255*0.08≈20].
            // When motion is off pulse_boost == 0.0 and tint_argb alpha == 0
            // → SvgRender uses raw SVG stroke colours (no overhead).
            const u32 pulse_alpha = static_cast<u32>(g_motion.pulse_boost * 255.0);
            const u32 tint_argb = (pulse_alpha << 24) | (ThemeCurrent().taskbar_accent & 0x00FFFFFFU);
            SvgRender(g_svg_topo, -drift, 0, info.width, info.height, tint_argb);
            // Wrap-around copy: covers the right-hand gap that
            // appears when the primary shifted render slides left.
            if (drift > 0)
            {
                SvgRender(g_svg_topo, i32(info.width) - drift, 0, info.width, info.height, tint_argb);
            }
        }
        PaintDuetArcs(desktop_rgb, info.width, info.height,
                      g_motion.arc_rot_deg, g_motion.pulse_boost);
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

void WallpaperTick()
{
    if (!FramebufferAvailable())
        return;

    const u8 motion = ThemeEffectiveMotionIntensity();
    if (motion == 0)
        return; // master gate: cmdline motion=off or theme opts out

    // Derive monotonic time in milliseconds. MonotonicNs returns 0
    // before the timekeeper is initialised — treat as "not ready yet"
    // and skip the tick rather than accumulating a spurious base.
    const u64 now_ns = time::MonotonicNs();
    if (now_ns == 0)
        return;
    const u64 now_ms = now_ns / 1'000'000ULL;

    // Capture the monotonic base on the first tick that actually runs.
    // The phase wraps at its period, so theme switches don't reset motion —
    // the wrap-around behaviour is the intended feature.
    if (g_motion.base_ms == 0)
        g_motion.base_ms = now_ms;
    const u64 t_ms = now_ms - g_motion.base_ms;

    // Scale animation periods by motion intensity (0..255):
    //   intensity=255 (Duet/Slate10/Amber) → full speed (60 s rotation)
    //   intensity=77  (Classic) → ~3× slower rotation (~197 s)
    // Pulse period is fixed at kPulsePeriodMs regardless of intensity
    // (the breath already scales via pulse_peak_eff).
    const u32 intensity_nz = motion;  // motion != 0 is guaranteed above
    const u64 rot_period_ms = (kArcRotPeriodMs * 255ULL) / intensity_nz;
    const double pulse_peak_eff = kPulsePeak * (double(intensity_nz) / 255.0);
    const i32 drift_speed_eff   = (kTopoDriftPxPerSec * i32(intensity_nz)) / 255;

    // Compute the new phase values.
    g_motion.arc_rot_deg = ArcRotationDegrees(t_ms, rot_period_ms);
    g_motion.pulse_boost = PulseAlphaBoost(t_ms, kPulsePeriodMs, pulse_peak_eff);

    const auto info = FramebufferGet();

    // Topo drift: update and mark dirty only when the offset changes.
    const i32 new_drift = TopoDriftOffsetPx(t_ms, drift_speed_eff, i32(info.width));
    const bool topo_moved = (new_drift != g_motion.topo_drift_px);
    if (topo_moved)
        g_motion.topo_drift_px = new_drift;

    // Dirty-rect notifications. There is no CompositorOpaqueRectIntersects
    // equivalent in the current codebase — always mark the regions dirty
    // and rely on the compositor's content-diff layer (Pass A) to elide
    // the blit if the pixels didn't change. The arc bbox is a 340×340
    // region centred on the Duet arc anchor (~48 % down from the top).
    //
    // NOTE: FramebufferAddDamage is the real dirty-mark API. There is no
    // opaque-window intersection check available yet; if a window covers
    // the arcs the compositor's damage diff will still skip the pixel blit
    // because the shadow-buffer content won't differ. No wasted PCIe
    // bandwidth in that path.
    const u32 arcs_x = (info.width  > 170U) ? info.width  / 2U - 170U : 0U;
    const u32 arcs_y = (info.height > 170U) ? (info.height * 48U) / 100U - 170U : 0U;
    FramebufferAddDamage(arcs_x, arcs_y, 340U, 340U);

    if (topo_moved && info.height > 280U)
    {
        // Topo contour band: rows 200–600 (or top-half of screen if
        // smaller). Marking the full width ensures the wrap-around
        // copy pass in WallpaperPaint covers its strip too.
        FramebufferAddDamage(0U, 200U, info.width, 400U);
    }
}

void WallpaperMotionSelfTest()
{
    // Implemented in Task 7. Declared here so the linker sees the
    // symbol. Task 7 fills in the body.
    // STUB: body pending Task 7 — returns without running any checks.
}

bool WallpaperMotionSelfTestPassed()
{
    // STUB: returns false until Task 7 implements the self-test.
    return false;
}

} // namespace duetos::drivers::video
