// tests/host/test_shadow_atlas.cpp
//
// Hosted unit tests for the soft-shadow falloff curve in
// kernel/drivers/video/shadow_falloff.h.
//
// The falloff math is pure (one integer-only constexpr function on
// (x, y) → alpha), so the curve's invariants — origin == 255, edge ==
// 0, monotonic along an axis, rotationally symmetric within ±1 LSB —
// can be exercised in milliseconds without booting QEMU. This test
// fails until Task 5 lands the shadow_falloff.h header.

#include "host_test_helper.h"

#include <cstdlib> // std::abs(int)

#include "drivers/video/shadow_falloff.h"

using duetos::drivers::video::ShadowFalloffAlpha;

int main()
{
    // ----- alpha at origin (corner of the 32×32 atlas) is full -----
    EXPECT_EQ(ShadowFalloffAlpha(0, 0), 255);

    // ----- alpha at the atlas edge (32, 0) has decayed to 0 -----
    EXPECT_EQ(ShadowFalloffAlpha(32, 0), 0);

    // ----- alpha at the diagonal corner (32, 32) is 0 -----
    // (32, 32) is sqrt(2048) ≈ 45 px from origin — well beyond the
    // 32-px radius where the curve clamps to 0.
    EXPECT_EQ(ShadowFalloffAlpha(32, 32), 0);

    // ----- alpha is monotonically non-increasing along x -----
    {
        int prev = 256; // start above max so 255 at x=0 still passes
        for (int x = 0; x <= 32; ++x)
        {
            const int a = ShadowFalloffAlpha(x, 0);
            EXPECT_TRUE(a <= prev);
            prev = a;
        }
    }

    // ----- alpha is monotonically non-increasing along y too -----
    {
        int prev = 256;
        for (int y = 0; y <= 32; ++y)
        {
            const int a = ShadowFalloffAlpha(0, y);
            EXPECT_TRUE(a <= prev);
            prev = a;
        }
    }

    // ----- rotationally symmetric: f(x, y) == f(y, x) within ±1 -----
    // ±1 tolerance is the irreducible cost of an integer-only isqrt
    // — different rounding at the same Euclidean distance.
    EXPECT_TRUE(std::abs(ShadowFalloffAlpha(8, 0) - ShadowFalloffAlpha(0, 8)) <= 1);
    EXPECT_TRUE(std::abs(ShadowFalloffAlpha(20, 5) - ShadowFalloffAlpha(5, 20)) <= 1);
    EXPECT_TRUE(std::abs(ShadowFalloffAlpha(12, 16) - ShadowFalloffAlpha(16, 12)) <= 1);

    return ::duetos_host_test::finish_main(__FILE__);
}
