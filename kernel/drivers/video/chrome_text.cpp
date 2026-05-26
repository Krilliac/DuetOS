/*
 * DuetOS chrome text — TTF/bitmap dispatcher (implementation).
 *
 * Public API: see drivers/video/chrome_text.h. This TU owns the
 * per-role pixel-size table, the TTF-vs-bitmap dispatch decision,
 * and the boot-time self-test that validates the dispatch math is
 * deterministic + monotone in role.
 *
 * Measurement notes:
 *   - TTF measure routes through `TtfMeasureString` (real per-glyph
 *     `hmtx` advance sum at the requested pixel height). Pen advance
 *     matches `TtfDrawString` exactly. Defensive fallback to the
 *     historical `chars * px * 0.55` Liberation-Sans estimate only
 *     when no chrome font is registered (in which case Draw wouldn't
 *     take the TTF path either, so measure stays in lock-step with
 *     paint).
 *   - Bitmap measure is exact: `chars * scale * 8`. The 8x8 ROM
 *     font is fixed-width, integer-scaled.
 *
 * Bold weight notes:
 *   - Bitmap path synthesises bold by double-painting with a 1-px
 *     x-offset (visually thicker stroke without a second font
 *     asset). Cheap and correct for the 8x8 font.
 *   - TTF path dispatches to the registered bold face when
 *     `weight == Bold` and `TtfChromeBoldGet() != nullptr`, via
 *     `TtfDrawStringFont`. When the bold font failed to load
 *     (no asset, parse failure) the dispatcher falls back to the
 *     Regular face — surfaced at boot via the
 *     `chrome font bold load FAILED — Bold weight will degrade
 *     to Regular` advisory.
 *
 * Self-test: validates the role table + dispatch math without
 * touching the framebuffer (so it runs cleanly headless and at
 * boot before the framebuffer is necessarily ready). The
 * structural sentinel is `[chrome-text-selftest] PASS` / `FAIL`
 * on COM1 — CI greps for this line and the Pass C umbrella
 * aggregator reads `ChromeTextSelfTestPassed()`.
 */

#include "drivers/video/chrome_text.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/theme.h"
#include "drivers/video/ttf.h"
#include "drivers/video/ttf_raster.h"

namespace duetos::drivers::video
{

namespace
{

// Per-role size table. Index by static_cast<u32>(ChromeTextRole).
// Keep in lock-step with the ChromeTextRole enum in chrome_text.h
// AND with the Pass C design spec (§3 Role Table).
struct RoleSpec
{
    u32 ttf_px;       // TTF pixel height (em-square scale target)
    u32 bitmap_scale; // 8x8 bitmap font integer scale factor
};

constexpr RoleSpec kRoles[] = {
    {72, 8}, // Display — hero numerals (clock, hero metrics)
    {16, 2}, // Title   — window titlebars, modal titles, card names
    {13, 1}, // Body    — menu rows, button labels, dialog text
    {11, 1}, // Caption — hints, status, tooltips, timestamps
};

constexpr u32 kRoleCount = sizeof(kRoles) / sizeof(kRoles[0]);

inline const RoleSpec& Spec(ChromeTextRole role)
{
    const u32 idx = static_cast<u32>(role);
    return kRoles[idx < kRoleCount ? idx : 0];
}

// Does the active theme + registered fonts support TTF for this call?
// Returns true iff the theme opted into TTF AND a Regular chrome
// font is registered. Bitmap themes (font_kind != Ttf) always take
// the bitmap path even if fonts are loaded; a TTF theme with no
// Regular font registered also falls back to bitmap (TtfDrawString
// would refuse internally, but routing through bitmap here keeps
// the measure math consistent with the actual paint path).
//
// Weight is not consulted here: Bold rides the TTF path whenever
// the theme + Regular registration permit it. `ChromeTextDraw`
// picks the bold face when present and falls back to Regular when
// the bold load failed (advertised at boot).
inline bool UseTtf(ChromeTextWeight /*weight*/)
{
    if (ThemeCurrent().font_kind != Theme::FontKind::Ttf)
    {
        return false;
    }
    if (TtfChromeFontGet() == nullptr)
    {
        return false;
    }
    return true;
}

constinit bool s_passed = false;

} // namespace

void ChromeTextDraw(ChromeTextRole role, u32 x, u32 y, const char* text, u32 fg, u32 bg, ChromeTextWeight weight)
{
    if (text == nullptr || text[0] == '\0')
    {
        return;
    }

    const RoleSpec& spec = Spec(role);

    if (UseTtf(weight))
    {
        // Bold dispatches through the bold face when one is
        // registered; otherwise falls back to Regular (surfaced
        // at boot via the bold-load FAILED advisory). Regular
        // always uses the Regular face. `TtfDrawStringFont` lets
        // us pick the face explicitly instead of going through
        // `TtfDrawString`'s implicit `TtfChromeFontGet()` lookup.
        const TtfFont* face = nullptr;
        if (weight == ChromeTextWeight::Bold)
        {
            face = TtfChromeBoldGet();
        }
        if (face == nullptr)
        {
            face = TtfChromeFontGet();
        }
        if (face != nullptr)
        {
            TtfDrawStringFont(*face, x, y, text, fg, spec.ttf_px);
        }
        (void)bg; // TTF blends src-over; no opaque background fill.
        return;
    }

    FramebufferDrawStringScaled(x, y, text, fg, bg, spec.bitmap_scale);
    if (weight == ChromeTextWeight::Bold)
    {
        // Synthesise bold on the bitmap path by double-painting
        // with a 1-px x-offset. Visually thicker stroke without a
        // second font asset.
        FramebufferDrawStringScaled(x + 1, y, text, fg, bg, spec.bitmap_scale);
    }
}

u32 ChromeTextMeasure(ChromeTextRole role, const char* text)
{
    if (text == nullptr || text[0] == '\0')
    {
        return 0;
    }

    const RoleSpec& spec = Spec(role);

    if (UseTtf(ChromeTextWeight::Regular))
    {
        // Route through TtfMeasureString for the real per-glyph
        // advance sum. Pen advance matches what TtfDrawString will
        // commit for the same string + size on the same font, so
        // hit-rects and centring math line up with the rasterizer
        // even on wide ASCII ("Mwwwwww..." runs) that the previous
        // chars * px * 0.55 estimate mis-sized by ~+15%.
        const TtfFont* font = TtfChromeFontGet();
        if (font != nullptr)
        {
            return TtfMeasureString(*font, text, spec.ttf_px);
        }
        // Defensive: UseTtf already gates on TtfChromeFontGet() != nullptr,
        // so this branch is unreachable in normal operation. Fall back to
        // the historical estimate so a future refactor of UseTtf doesn't
        // silently divide by zero or assert. Match the bitmap path's
        // char-counting loop shape.
        u32 count = 0;
        for (const char* p = text; *p != '\0'; ++p)
        {
            ++count;
        }
        return (count * spec.ttf_px * 55U) / 100U;
    }

    // Bitmap path is exact: 8x8 ROM font scaled to integer multiple.
    u32 count = 0;
    for (const char* p = text; *p != '\0'; ++p)
    {
        ++count;
    }
    return count * spec.bitmap_scale * 8U;
}

u32 ChromeTextRoleHeight(ChromeTextRole role)
{
    const RoleSpec& spec = Spec(role);
    if (UseTtf(ChromeTextWeight::Regular))
    {
        return spec.ttf_px;
    }
    return spec.bitmap_scale * 8U;
}

void ChromeTextSelfTest()
{
    using duetos::arch::SerialWrite;

    auto mark_fail = [](u32 code, const char* msg)
    {
        SerialWrite(msg);
        SerialWrite("\n");
        KBP_PROBE_V(duetos::debug::ProbeId::kBootSelftestFail, code);
    };

    // (1) Every role's ttf_px and bitmap_scale must be non-zero.
    //     A zero entry would silently collapse Measure/RoleHeight
    //     to 0 for that role, which would in turn break the
    //     monotonicity check below and confuse the chrome paint
    //     sites whose layout reads RoleHeight as a row stride.
    for (u32 i = 0; i < kRoleCount; ++i)
    {
        if (kRoles[i].ttf_px == 0 || kRoles[i].bitmap_scale == 0)
        {
            mark_fail(0xC0, "[chrome-text-selftest] FAIL role-spec table has zero entry");
            return;
        }
    }

    // (2) Measure is deterministic — same call twice returns same
    //     value. Catches a future regression where Measure picks
    //     up implicit state (e.g. accidentally consulting a
    //     mutable per-call cache).
    const char* probe = "Sign in";
    const u32 m1 = ChromeTextMeasure(ChromeTextRole::Body, probe);
    const u32 m2 = ChromeTextMeasure(ChromeTextRole::Body, probe);
    if (m1 != m2)
    {
        mark_fail(0xC1, "[chrome-text-selftest] FAIL Measure not deterministic");
        return;
    }

    // (3) Measure monotone in role: Display >= Title >= Body >= Caption
    //     for the same string. Catches a future regression where the
    //     role table is reordered or sizes are flipped — the design
    //     spec depends on this ordering for chrome layout sanity
    //     (a Caption-sized run must never be wider than a Body run
    //     of the same string).
    const u32 d = ChromeTextMeasure(ChromeTextRole::Display, "X");
    const u32 t = ChromeTextMeasure(ChromeTextRole::Title, "X");
    const u32 b = ChromeTextMeasure(ChromeTextRole::Body, "X");
    const u32 c = ChromeTextMeasure(ChromeTextRole::Caption, "X");
    if (!(d >= t && t >= b && b >= c))
    {
        mark_fail(0xC2, "[chrome-text-selftest] FAIL Measure not monotone in role");
        return;
    }

    // (4) RoleHeight > 0 for every role. Independent check from
    //     (1) because RoleHeight could be made conditional on the
    //     active theme's font_kind in a future refactor.
    for (u32 i = 0; i < kRoleCount; ++i)
    {
        if (ChromeTextRoleHeight(static_cast<ChromeTextRole>(i)) == 0)
        {
            mark_fail(0xC3, "[chrome-text-selftest] FAIL RoleHeight returned 0");
            return;
        }
    }

    SerialWrite("[chrome-text-selftest] PASS\n");
    s_passed = true;
}

bool ChromeTextSelfTestPassed()
{
    return s_passed;
}

} // namespace duetos::drivers::video
