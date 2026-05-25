// tests/host/test_motion_math.cpp
//
// Hosted unit tests for Pass B motion phase math. Mirrors the inline
// helpers WallpaperTick lands in Phase 2 so the math has a regression
// guard independent of QEMU boot timing.
//
// Covers:
//   ArcRotationDegrees  — triangular sweep [-5, +5] over period_ms
//   PulseAlphaBoost     — sine-breath [0, peak] over period_ms
//   TopoDriftOffsetPx   — pixel offset with fb_w wrapping

#include "host_test_helper.h"

#include <cstdint>
#include <cmath>

// pi without M_PI (POSIX extension not available under -Wpedantic).
static constexpr double kPi = 3.14159265358979323846;

// Triangular sweep: 0 -> +5 -> 0 -> -5 -> 0 over period_ms.
static double ArcRotationDegrees(uint64_t now_ms, uint64_t period_ms)
{
    if (period_ms == 0)
        return 0.0;
    const double t     = double(now_ms % period_ms) / double(period_ms);
    const double phase = t < 0.5 ? (t * 4.0) - 1.0 : 3.0 - (t * 4.0);
    return 5.0 * phase;
}

// Pulse alpha boost: 0 .. peak via sine breath over period_ms.
static double PulseAlphaBoost(uint64_t now_ms, uint64_t period_ms, double peak)
{
    if (period_ms == 0)
        return 0.0;
    const double t = double(now_ms % period_ms) / double(period_ms);
    const double s = 0.5 - 0.5 * std::cos(2.0 * kPi * t); // 0..1..0
    return peak * s;
}

// Topo horizontal drift offset, wraps at fb_w pixels.
static int TopoDriftOffsetPx(uint64_t now_ms, int speed_px_per_s, int fb_w)
{
    if (fb_w <= 0)
        return 0;
    const int64_t total = (int64_t(now_ms) * speed_px_per_s) / 1000;
    int64_t mod = total % int64_t(fb_w);
    if (mod < 0)
        mod += int64_t(fb_w);
    return int(mod);
}

int main()
{
    // ArcRotationDegrees: at t=0 the triangular sweep starts at -5.
    EXPECT_TRUE(std::abs(ArcRotationDegrees(0, 60000) + 5.0) < 1e-9);

    // ArcRotationDegrees: at half period the sweep peaks at +5.
    EXPECT_TRUE(std::abs(ArcRotationDegrees(30000, 60000) - 5.0) < 1e-9);

    // ArcRotationDegrees: bounded [-5, +5] for all sample points.
    for (uint64_t ms = 0; ms <= 60000; ms += 100)
    {
        const double d = ArcRotationDegrees(ms, 60000);
        EXPECT_TRUE(d >= -5.0 && d <= 5.0);
    }

    // PulseAlphaBoost: starts at 0 (sine is 0 at t=0).
    EXPECT_TRUE(std::abs(PulseAlphaBoost(0, 8000, 0.08)) < 1e-9);

    // PulseAlphaBoost: peaks at half period (sine is 1 at t=0.5).
    EXPECT_TRUE(std::abs(PulseAlphaBoost(4000, 8000, 0.08) - 0.08) < 1e-6);

    // PulseAlphaBoost: bounded [0, peak] for all sample points.
    for (uint64_t ms = 0; ms <= 8000; ms += 50)
    {
        const double v = PulseAlphaBoost(ms, 8000, 0.08);
        EXPECT_TRUE(v >= 0.0 && v <= 0.08001);
    }

    // TopoDriftOffsetPx: at 1 px/s after 1000 ms, offset == 1.
    EXPECT_EQ(TopoDriftOffsetPx(1000, 1, 1024), 1);

    // TopoDriftOffsetPx: after exactly fb_w seconds at 1 px/s, wraps to 0.
    EXPECT_EQ(TopoDriftOffsetPx(1024000, 1, 1024), 0);

    return ::duetos_host_test::finish_main(__FILE__);
}
