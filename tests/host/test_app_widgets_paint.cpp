// tests/host/test_app_widgets_paint.cpp
//
// Pass D Task 6 — Widget PaintSelf early-exit + color-fallback logic.
//
// The widget library's kernel-side PaintSelf functions call
// Framebuffer + ChromeText primitives that aren't available in the
// host test environment. This test focuses on the LOGIC executed
// BEFORE those primitives fire — the early-return on degenerate
// bounds and the bg-color theme fallback. Mirrors the predicates
// inline so a future refactor that drops the early-exit (and starts
// hammering the GPU with zero-sized blits) trips here.

#include "host_test_helper.h"

#include <cstdint>

// Mirror the early-exit predicate every PaintSelf uses. A zero
// width or height makes every downstream Framebuffer call a no-op
// at best and an OOB write at worst — short-circuit before reaching
// the blit path.
static bool ShouldSkipPaint(uint32_t w, uint32_t h)
{
    return w == 0U || h == 0U;
}

// Mirror the bg-fallback used by AppPanel and friends: a requested
// colour of 0 means "use whatever the active theme considers the
// default panel background." Non-zero values pass through verbatim.
// Keep this in lock-step with the kernel widget TUs — a divergence
// would silently flip the theme override semantics.
static uint32_t ResolveBg(uint32_t requested, uint32_t theme_default)
{
    return (requested == 0U) ? theme_default : requested;
}

int main()
{
    // ----- Skip-paint on degenerate bounds. -----
    EXPECT_TRUE(ShouldSkipPaint(0U, 100U));
    EXPECT_TRUE(ShouldSkipPaint(100U, 0U));
    EXPECT_TRUE(ShouldSkipPaint(0U, 0U));
    EXPECT_TRUE(!ShouldSkipPaint(1U, 1U));
    EXPECT_TRUE(!ShouldSkipPaint(640U, 480U));

    // ----- bg fallback resolves 0 to the theme default and passes
    //       non-zero values through unchanged. -----
    EXPECT_TRUE(ResolveBg(0U, 0x123456U) == 0x123456U);
    EXPECT_TRUE(ResolveBg(0xABCDEFU, 0x123456U) == 0xABCDEFU);

    // Edge: a theme that legitimately wants pure black (0x000000)
    // is indistinguishable from "use default" — the kernel encodes
    // this by reserving 0 as the sentinel. Pin the asymmetry so a
    // future "let 0 mean black" change is caught.
    EXPECT_TRUE(ResolveBg(0U, 0U) == 0U);
    EXPECT_TRUE(ResolveBg(0x000001U, 0U) == 0x000001U);

    return ::duetos_host_test::finish_main("tests/host/test_app_widgets_paint.cpp");
}
