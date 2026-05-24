// tests/host/test_blend.cpp
//
// Hosted unit tests for the Porter-Duff "over" blend math used by
// FramebufferBlendRgba / FramebufferBlendFill in kernel/drivers/video/blend_math.h.
//
// The math is pure (no kernel deps, no MMIO) so we test it in isolation —
// fast iteration without a kernel boot. This test will FAIL until Task 3
// lands the blend_math.h header and BlendOver() function.

#include "host_test_helper.h"
#include "drivers/video/blend_math.h"

using duetos::u32;
using duetos::drivers::video::BlendOver;

int main()
{
    // ----- blend alpha=0 keeps dst -----
    {
        const u32 result = BlendOver(/*dst*/ 0x123456, /*src*/ 0xABCDEF, /*src_a*/ 0);
        EXPECT_EQ(result, 0x123456u);
    }

    // ----- blend alpha=255 replaces dst -----
    {
        const u32 result = BlendOver(0x123456, 0xABCDEF, 255);
        EXPECT_EQ(result, 0xABCDEFu);
    }

    // ----- blend alpha=128 is roughly halfway -----
    {
        const u32 mid = BlendOver(0x000000, 0xFFFFFF, 128);
        // Each channel should be ~128 — accept rounding within ±2
        const u32 r_chan = (mid >> 16) & 0xFF;
        const u32 g_chan = (mid >>  8) & 0xFF;
        const u32 b_chan = (mid >>  0) & 0xFF;

        EXPECT_TRUE(r_chan >= 126 && r_chan <= 130);
        EXPECT_TRUE(g_chan >= 126 && g_chan <= 130);
        EXPECT_TRUE(b_chan >= 126 && b_chan <= 130);
    }

    // ----- blend per-channel correctness -----
    {
        // Blue full over red full at alpha=128 → midpoint of each channel
        const u32 result = BlendOver(/*dst*/ 0xFF0000, /*src*/ 0x0000FF, 128);

        const u32 r_chan = (result >> 16) & 0xFF;
        const u32 g_chan = (result >>  8) & 0xFF;
        const u32 b_chan = (result >>  0) & 0xFF;

        // Red channel: full (0xFF) blended toward nothing (0x00) at alpha=128
        EXPECT_TRUE(r_chan >= 126 && r_chan <= 130);
        // Green channel: no contribution from either
        EXPECT_EQ(g_chan, 0u);
        // Blue channel: nothing (0x00) blended toward full (0xFF) at alpha=128
        EXPECT_TRUE(b_chan >= 126 && b_chan <= 130);
    }

    return ::duetos_host_test::finish_main(__FILE__);
}
