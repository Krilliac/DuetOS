#pragma once

// DuetOS — soft-shadow falloff curve.
//
// Pure integer math (no float, no kernel deps) so the hosted unit
// test (tests/host/test_shadow_atlas.cpp) can include this header
// directly and exercise the curve in milliseconds. The on-target
// shadow renderer (shadow.cpp) uses the bake-time atlas
// (generated_shadow_atlas.h, Task 1) for the actual draw, so this
// header is the SPEC for the curve, not the runtime path. Keeping
// the spec and the bake-time generator in agreement is what the
// host test guarantees.
//
// Curve: alpha(d) = 255 * (1 - d/32)² for Euclidean d in [0, 32],
//   clamped to 0 outside the radius. Quadratic falloff matches the
//   bake script (tools/build/gen_shadow_atlas.py).

#include "util/types.h"

namespace duetos::drivers::video
{

// Integer isqrt — bit starts at the largest power of 4 that
// covers the valid input range (max d² for inputs in [-32, 32]
// is 2*32² = 2048; 4^6 = 4096 covers it). Shifts by 2 require
// `bit` to live on the 4^k grid — starting at a non-power-of-4
// (e.g. 1<<15 = 32768) makes the shrink loop overshoot and
// return wrong sqrts on power-of-4 inputs (1024 → 44 instead of
// 32). 4^6 = 4096 is the smallest valid start for our domain.
constexpr int ShadowIsqrt(int n)
{
    if (n <= 0)
    {
        return 0;
    }
    int s = 0;
    int bit = 1 << 12; // 4096 = 4^6
    while (bit > n)
    {
        bit >>= 2;
    }
    while (bit != 0)
    {
        if (n >= s + bit)
        {
            n -= s + bit;
            s = (s >> 1) + bit;
        }
        else
        {
            s >>= 1;
        }
        bit >>= 2;
    }
    return s;
}

// Alpha at (x, y) relative to the shadow's anchor corner. Inputs
// are atlas-coordinate-space (0..32). Returns 0..255.
constexpr int ShadowFalloffAlpha(int x, int y)
{
    constexpr int kRadius = 32;
    constexpr int kMax2 = kRadius * kRadius;
    const int d2 = x * x + y * y;
    if (d2 >= kMax2)
    {
        return 0;
    }
    const int s = ShadowIsqrt(d2);
    const int diff = kRadius - s;
    if (diff <= 0)
    {
        return 0;
    }
    // (1 - s/R)² × 255 = (diff² × 255) / R²
    return (255 * diff * diff) / kMax2;
}

} // namespace duetos::drivers::video
