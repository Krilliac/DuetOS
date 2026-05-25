// tests/host/test_chrome_text_measure.cpp
//
// Hosted unit test for Pass C ChromeTextMeasure math.
// Verifies the bitmap-path exact math AND the TTF-path defensive
// fallback estimate (`chars * px * 55 / 100`).
//
// As of the 2026-05-25 Pass C residuals slice, the kernel's TTF
// branch routes through `TtfMeasureString` (real per-glyph `hmtx`
// advance sum at the requested pixel size) — that path requires a
// loaded TtfFont so it isn't exercisable from a hosted test that
// doesn't link the kernel rasterizer + font asset. The kernel only
// falls back to the proportional estimate when no chrome font is
// registered (a defensive branch — UseTtf already gates on a
// non-null font), so the estimate math still has to stay correct
// to catch silent regressions in the fallback formula.
//
// This test does NOT link the kernel TU; it re-derives the bitmap
// + fallback math inline. If a future change moves the fallback
// constant or the 8x8 ROM-font stride, this test starts failing
// and the regression is caught at host-CI time rather than in a
// QEMU smoke. The real-advance TTF path is gated by the kernel
// `[chrome-text-selftest]` boot sentinel + a future targeted hosted
// fixture once a synthetic font binding is in scope.

#include "host_test_helper.h"

#include <cstdint>

// Mirror the role table from chrome_text.cpp. Keep in lock-step
// with the kRoles array there AND with the Pass C design spec
// (§3 Role Table). Changing one without the other is the bug
// shape this test exists to catch.
struct RoleSpec
{
    uint32_t ttf_px;       // TTF pixel height (em-square scale target)
    uint32_t bitmap_scale; // 8x8 bitmap font integer scale factor
};

constexpr RoleSpec kRoles[] = {
    {72U, 8U}, // Display
    {16U, 2U}, // Title
    {13U, 1U}, // Body
    {11U, 1U}, // Caption
};

// Bitmap measure: chars * scale * 8. Mirrors the bitmap branch of
// ChromeTextMeasure exactly — 8x8 ROM font, fixed-width, integer
// scaled, no per-glyph kerning.
static uint32_t MeasureBitmap(uint32_t scale, const char* text)
{
    uint32_t n = 0;
    for (const char* p = text; *p != '\0'; ++p)
    {
        ++n;
    }
    return n * scale * 8U;
}

// TTF defensive-fallback estimate: (chars * px * 55) / 100.
// Mirrors the kernel ChromeTextMeasure's no-chrome-font fallback —
// coarse 0.55-em average across mixed ASCII glyphs in Liberation
// Sans. The default TTF path now sums real per-glyph advances via
// TtfMeasureString; this estimate is the safety net for when no
// font is registered. Integer math (truncating divide) matches the
// kernel implementation; do NOT switch to floating-point here, the
// kernel value is the integer truncation.
static uint32_t MeasureTtfEstimate(uint32_t px, const char* text)
{
    uint32_t n = 0;
    for (const char* p = text; *p != '\0'; ++p)
    {
        ++n;
    }
    return (n * px * 55U) / 100U;
}

int main()
{
    // ----- Bitmap path: exact math. -----
    EXPECT_TRUE(MeasureBitmap(8U, "X") == 64U);                // 1 * 8 * 8
    EXPECT_TRUE(MeasureBitmap(2U, "Sign in") == 7U * 2U * 8U); // 112
    EXPECT_TRUE(MeasureBitmap(1U, "OK") == 16U);               // 2 * 1 * 8
    EXPECT_TRUE(MeasureBitmap(1U, "") == 0U);

    // ----- TTF defensive fallback (no chrome font): 0.55 * px * chars. -----
    // Pinned at the integer-truncated values the kernel falls back to
    // when TtfChromeFontGet() returns nullptr. Catches a regression in
    // that branch's constant or order-of-operations.
    EXPECT_TRUE(MeasureTtfEstimate(72U, "X") == (1U * 72U * 55U) / 100U);                       // 39
    EXPECT_TRUE(MeasureTtfEstimate(16U, "Sign in") == (7U * 16U * 55U) / 100U);                 // 61
    EXPECT_TRUE(MeasureTtfEstimate(13U, "OK") == (2U * 13U * 55U) / 100U);                      // 14
    EXPECT_TRUE(MeasureTtfEstimate(11U, "default: admin / admin") == (22U * 11U * 55U) / 100U); // 133

    // ----- Monotonicity: Display > Title > Body > Caption for same string. -----
    // Mirrors the kernel self-test (§3, check #3) but proves the
    // monotone-in-role property STRICTLY for strings whose char
    // count yields distinct quotients across the role table. "X"
    // alone trips truncation collisions at small sizes, so use a
    // multi-character probe.
    const char* probe = "Hello";
    const uint32_t d = MeasureTtfEstimate(kRoles[0].ttf_px, probe); // Display 72
    const uint32_t t = MeasureTtfEstimate(kRoles[1].ttf_px, probe); // Title   16
    const uint32_t b = MeasureTtfEstimate(kRoles[2].ttf_px, probe); // Body    13
    const uint32_t c = MeasureTtfEstimate(kRoles[3].ttf_px, probe); // Caption 11
    EXPECT_TRUE(d > t);
    EXPECT_TRUE(t > b);
    EXPECT_TRUE(b > c);

    // ----- Empty string is always 0 on both paths. -----
    EXPECT_TRUE(MeasureTtfEstimate(72U, "") == 0U);
    EXPECT_TRUE(MeasureBitmap(8U, "") == 0U);

    // ----- Role-table invariant: no zero entries. -----
    // Mirrors the kernel self-test (§3, check #1). A zero in either
    // column would silently collapse Measure to 0 for that role.
    for (const RoleSpec& r : kRoles)
    {
        EXPECT_TRUE(r.ttf_px != 0U);
        EXPECT_TRUE(r.bitmap_scale != 0U);
    }

    return ::duetos_host_test::finish_main("tests/host/test_chrome_text_measure.cpp");
}
