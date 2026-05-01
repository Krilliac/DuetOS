// tests/host/test_cvt.cpp
//
// Hosted unit test for the CVT timing generator in
// kernel/drivers/gpu/cvt.cpp. Mirrors the algorithm here rather
// than linking the kernel TU (which would drag in console.h,
// panic.h, and friends), exactly the same way test_string.cpp
// re-states the byte-loop primitives. If the kernel-side formula
// changes the host expectations follow, because both reference
// the same VESA CVT 1.1 / 1.2 spec.
//
// What's locked down:
//
//   1. Pixel-clock convergence on six well-known timings
//      (5x RB + 1x Standard) within the same ±5% / ±2% windows
//      the kernel-side CvtSelfTest enforces.
//
//   2. The unit-mismatch regression that pushed the Standard-mode
//      1280x1024@60 case 100x off its target — the divisor in
//      `frame_period_ns_x1000 = 1e15 / refresh_mhz` MUST be 1e15,
//      and the duty-cycle scale MUST divide by 10000 (not 1e6).
//      Either bug regresses one or more of the timings below.

#include "host_test_helper.h"

#include <cstdint>

namespace cvt_local
{

using u8 = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;
using i32 = std::int32_t;
using i64 = std::int64_t;

constexpr u32 kCellGran = 8;
constexpr u32 kMinPorch = 3;
constexpr u32 kMinVsyncBpUsStd = 550;
constexpr u32 kMinVsyncBpUsRb = 460;
constexpr u32 kRbHBlank = 160;
constexpr u32 kRbVFrontPorch = 3;
constexpr u32 kRbVBackPorch = 6;
constexpr i32 kCPrimeX100 = 3000;
constexpr i32 kMPrimeUsPerS = 300;

enum class Mode
{
    Rb,
    Std
};

inline u32 SyncLinesForAspect(u32 w, u32 h)
{
    if (h == 0)
        return 10;
    if (w * 3 == h * 4)
        return 4;
    if (w * 9 == h * 16)
        return 5;
    if (w * 10 == h * 16)
        return 6;
    if (w * 4 == h * 5)
        return 7;
    if (w * 9 == h * 15)
        return 7;
    return 10;
}

inline u32 RoundUpToCellGran(u32 v)
{
    return ((v + kCellGran - 1) / kCellGran) * kCellGran;
}

inline u32 DivRoundUp(u64 num, u64 den)
{
    return den == 0 ? 0 : static_cast<u32>((num + den - 1) / den);
}

inline u32 DivRoundNearest(u64 num, u64 den)
{
    return den == 0 ? 0 : static_cast<u32>((num + den / 2) / den);
}

inline u32 GenerateRbPclkKhz(u32 h_active_in, u32 v_active, u32 refresh_mhz)
{
    const u32 h_active = RoundUpToCellGran(h_active_in);
    const u32 h_total = h_active + kRbHBlank;
    const u32 v_sync_lines = SyncLinesForAspect(h_active_in, v_active);
    u32 v_blanking = kRbVFrontPorch + v_sync_lines + kRbVBackPorch;
    for (u32 iter = 0; iter < 4; ++iter)
    {
        const u64 v_total_est = static_cast<u64>(v_active) + v_blanking;
        const u64 needed = static_cast<u64>(kMinVsyncBpUsRb) * v_total_est * refresh_mhz;
        const u32 min_v_blank_lines = DivRoundUp(needed, 1000000000ULL);
        const u32 vbf_min = kRbVFrontPorch + v_sync_lines + kRbVBackPorch;
        const u32 cand = (min_v_blank_lines < vbf_min) ? vbf_min : min_v_blank_lines;
        if (cand == v_blanking)
            break;
        v_blanking = cand;
    }
    const u32 v_total = v_active + v_blanking;
    const u64 pclk_num = static_cast<u64>(refresh_mhz) * v_total * h_total;
    return DivRoundNearest(pclk_num, 1000000ULL);
}

inline u32 GenerateStdPclkKhz(u32 h_active_in, u32 v_active, u32 refresh_mhz)
{
    const u32 h_active = RoundUpToCellGran(h_active_in);
    const u32 v_sync = SyncLinesForAspect(h_active_in, v_active);

    // 1e15 / refresh_mhz — the regression fix point. With 1e12 the
    // value is in microseconds-times-1000, the comparison below
    // mistakenly trips, and Std falls back to RB.
    const u64 frame_period_ns_x1000 = 1000000000000000ULL / refresh_mhz;
    if (frame_period_ns_x1000 <= static_cast<u64>(kMinVsyncBpUsStd) * 1000ULL * 1000ULL)
        return GenerateRbPclkKhz(h_active_in, v_active, refresh_mhz);

    const u64 h_period_num = frame_period_ns_x1000 - static_cast<u64>(kMinVsyncBpUsStd) * 1000ULL * 1000ULL;
    const u64 h_period_den = static_cast<u64>(v_active) + kMinPorch;
    const u64 h_period_ns_x1000 = h_period_num / h_period_den;
    if (h_period_ns_x1000 == 0)
        return GenerateRbPclkKhz(h_active_in, v_active, refresh_mhz);

    const u64 vsync_bp_num = static_cast<u64>(kMinVsyncBpUsStd) * 1000000ULL;
    u32 v_sync_bp = DivRoundNearest(vsync_bp_num, h_period_ns_x1000) + 1;
    if (v_sync_bp < v_sync + kMinPorch)
        v_sync_bp = v_sync + kMinPorch;

    const u64 h_period_us_x1000 = h_period_ns_x1000 / 1000ULL;
    // Divide by 10000 — the second regression fix point. With 1e6
    // duty_x100 lands at ~30% (no porch growth); h_blanking comes
    // out 100x too small and pclk overshoots tolerance.
    const i64 duty_x100 = static_cast<i64>(kCPrimeX100) -
                          static_cast<i64>(static_cast<u64>(kMPrimeUsPerS) * h_period_us_x1000 / 10000ULL);

    u32 h_blanking = 0;
    if (duty_x100 < 2000)
    {
        const u32 raw = DivRoundUp(static_cast<u64>(20) * h_active, 80ULL);
        h_blanking = static_cast<u32>(((raw + 2 * kCellGran - 1) / (2 * kCellGran)) * (2 * kCellGran));
    }
    else
    {
        const u64 num = static_cast<u64>(h_active) * static_cast<u64>(duty_x100);
        const i64 den_x100 = 10000 - duty_x100;
        if (den_x100 <= 0)
            h_blanking = kRbHBlank;
        else
        {
            const u64 raw = num / static_cast<u64>(den_x100);
            h_blanking = static_cast<u32>(((raw + 2 * kCellGran - 1) / (2 * kCellGran)) * (2 * kCellGran));
        }
    }
    const u32 h_total = h_active + h_blanking;
    const u64 pclk_num = static_cast<u64>(h_total) * 1000000000ULL;
    return DivRoundNearest(pclk_num, h_period_ns_x1000);
}

struct Case
{
    const char* tag;
    u32 w, h, refresh_mhz;
    Mode mode;
    u32 expected_pclk_khz;
    u32 tol_pct;
};

inline bool InTol(u32 got, u32 expected, u32 tol_pct)
{
    const u64 lo = static_cast<u64>(expected) * (100 - tol_pct) / 100;
    const u64 hi = static_cast<u64>(expected) * (100 + tol_pct) / 100;
    return got >= lo && got <= hi;
}

} // namespace cvt_local

int main()
{
    using namespace cvt_local;

    // Same six cases the kernel-side CvtSelfTest checks. If this
    // host test passes, the kernel-side test passes (modulo the
    // bad-input rejection paths, which the kernel test owns alone
    // since they exercise the public CvtGenerate entry).
    const Case cases[] = {
        {"640x480@60 RB", 640, 480, 60000, Mode::Rb, 24000, 5},
        {"1024x768@60 RB", 1024, 768, 60000, Mode::Rb, 56120, 5},
        {"1280x1024@60 RB", 1280, 1024, 60000, Mode::Rb, 90720, 5},
        {"1920x1080@60 RB", 1920, 1080, 60000, Mode::Rb, 138600, 5},
        {"2560x1440@60 RB", 2560, 1440, 60000, Mode::Rb, 241500, 5},
        {"1280x1024@60 STD", 1280, 1024, 60000, Mode::Std, 109000, 5},
    };

    for (const Case& c : cases)
    {
        const u32 got = (c.mode == Mode::Rb) ? GenerateRbPclkKhz(c.w, c.h, c.refresh_mhz)
                                             : GenerateStdPclkKhz(c.w, c.h, c.refresh_mhz);
        if (!InTol(got, c.expected_pclk_khz, c.tol_pct))
        {
            std::fprintf(stderr, "%s: FAIL pclk=%u expected=%u (tol ±%u%%)\n", c.tag, got, c.expected_pclk_khz,
                         c.tol_pct);
            ++::duetos_host_test::failure_count();
        }
    }

    // Direct regression guard against the unit-mismatch bug — even
    // if the tolerance were widened to 100% the broken Std path
    // would still land 91 MHz instead of 109 MHz (it falls back to
    // the 1280x1024@60 RB pclk). Compare exact values.
    {
        const u32 std_pclk = GenerateStdPclkKhz(1280, 1024, 60000);
        const u32 rb_pclk = GenerateRbPclkKhz(1280, 1024, 60000);
        // STD must NOT have fallen back to RB.
        EXPECT_NE(std_pclk, rb_pclk);
        // STD must be in the 109 MHz neighbourhood (within 5 MHz).
        const u32 expected = 109000;
        const u32 diff = std_pclk > expected ? std_pclk - expected : expected - std_pclk;
        EXPECT_TRUE(diff < 5000);
    }

    return ::duetos_host_test::finish_main("test_cvt");
}
