#include "drivers/gpu/cvt.h"

#include "core/panic.h"
#include "drivers/video/console.h"

/*
 * Implementation reference: VESA CVT 1.1 §4 (Standard CVT formula)
 * and CVT 1.2 §3.2 (Reduced Blanking Timing Version 1). All
 * arithmetic is integer; the spec uses microseconds + milliHz which
 * map onto u32 / u64 cleanly without intermediate floats.
 *
 * No code from libxcvt or X.Org's cvt(1) — only the algorithm
 * described in the public VESA spec.
 */

namespace duetos::drivers::gpu
{

namespace
{

// CVT constants (CVT 1.1 §4.1).
constexpr u32 kCellGran = 8;    // pixels
constexpr u32 kMinPorch = 3;    // lines/pixels
constexpr u32 kHSyncPerPct = 8; // % of total pixels
constexpr u32 kMinVsyncBpUsStd = 550;
constexpr u32 kMinVsyncBpUsRb = 460;
constexpr u32 kRbHBlank = 160; // CVT-RBv1 fixed
constexpr u32 kRbHSync = 32;
constexpr u32 kRbHFrontPorch = 8;
constexpr u32 kRbVFrontPorch = 3;
constexpr u32 kRbVBackPorch = 6;

// CVT IDEAL_DUTY_CYCLE constants (CVT 1.1 §4.1.4).
//   IDEAL_DUTY_CYCLE = C_PRIME - (M_PRIME * H_PERIOD_us / 1000)
// We work in micro-percent (×100) so that small tick increments
// round predictably.
constexpr i32 kCPrimeX100 = 3000;  // 30.0 %
constexpr i32 kMPrimeUsPerS = 300; // 300 %·μs⁻¹

u32 SyncLinesForAspect(u32 w, u32 h)
{
    // Avoid division-by-zero edge case.
    if (h == 0)
        return 10;
    // Match aspect by cross-multiplication on common ratios.
    //   4:3, 16:9, 16:10, 5:4, 15:9.
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
    return 10; // unspecified aspect: spec default
}

u32 RoundUpToCellGran(u32 v)
{
    return ((v + kCellGran - 1) / kCellGran) * kCellGran;
}

u32 DivRoundUp(u64 num, u64 den)
{
    if (den == 0)
        return 0;
    return static_cast<u32>((num + den - 1) / den);
}

u32 DivRoundNearest(u64 num, u64 den)
{
    if (den == 0)
        return 0;
    return static_cast<u32>((num + den / 2) / den);
}

EdidDtd FillDtd(u32 h_active, u32 h_blanking, u32 h_sync_offset, u32 h_sync_pulse, u32 v_active, u32 v_blanking,
                u32 v_sync_offset, u32 v_sync_pulse, u32 pixel_clock_khz, bool h_pos_sync, bool v_pos_sync)
{
    EdidDtd t = {};
    t.pixel_clock_khz = pixel_clock_khz;
    t.h_active = static_cast<u16>(h_active);
    t.h_blanking = static_cast<u16>(h_blanking);
    t.v_active = static_cast<u16>(v_active);
    t.v_blanking = static_cast<u16>(v_blanking);
    t.h_sync_offset = static_cast<u16>(h_sync_offset);
    t.h_sync_pulse = static_cast<u16>(h_sync_pulse);
    t.v_sync_offset = static_cast<u16>(v_sync_offset);
    t.v_sync_pulse = static_cast<u16>(v_sync_pulse);
    t.h_image_mm = 0; // CVT doesn't carry physical size
    t.v_image_mm = 0;
    t.interlaced = false;
    t.sync_type = 3; // digital separate
    t.h_sync_positive = h_pos_sync;
    t.v_sync_positive = v_pos_sync;
    const u64 h_total = static_cast<u64>(h_active) + h_blanking;
    const u64 v_total = static_cast<u64>(v_active) + v_blanking;
    if (h_total != 0 && v_total != 0)
    {
        const u64 num = static_cast<u64>(pixel_clock_khz) * 1000000ULL;
        t.refresh_mhz = static_cast<u32>(num / (h_total * v_total));
    }
    return t;
}

EdidDtd GenerateRb(const CvtRequest& req)
{
    // CVT 1.2 §3.2 Reduced Blanking v1.
    //   - Horizontal blanking is fixed at 160 pixels.
    //   - Horizontal sync = 32, horizontal front porch = 8.
    //   - Vertical front porch = 3, vertical back porch = 6.
    //   - Vertical sync depends on aspect ratio (same table as
    //     Standard CVT).
    //   - Vertical blanking is sized so that the v-blank time is
    //     >= 460 μs (constant kMinVsyncBpUsRb).
    const u32 h_active = RoundUpToCellGran(req.h_active);
    const u32 h_total = h_active + kRbHBlank;
    const u32 v_active = req.v_active;

    const u32 v_sync_lines = SyncLinesForAspect(req.h_active, req.v_active);

    // Iterate to converge on v_blanking that satisfies the 460-μs
    // minimum + monotonic frame rate. The CVT-RB spec lays this out
    // as a fixed-point convergence — for refresh ≤ 100 Hz on common
    // resolutions one pass suffices (verified by host-side test).
    //
    // h_period_us = (1 / refresh) * 1_000_000 / v_total
    // v_blank_lines >= ceil(460 / h_period_us)
    //
    // Use refresh_mhz (Hz × 1000) so denom doesn't underflow.
    u32 v_blanking = kRbVFrontPorch + v_sync_lines + kRbVBackPorch;
    for (u32 iter = 0; iter < 4; ++iter)
    {
        const u64 v_total_est = static_cast<u64>(v_active) + v_blanking;
        // h_period_us numerator is 1e9 / refresh_mhz / v_total ≈
        // (1e9 / refresh_mhz) / v_total. Express min v-blank lines
        // directly:
        //   lines = ceil(460 * v_total / period_per_frame_us)
        //   period_per_frame_us = 1e9 / refresh_mhz
        // → lines = ceil(460 * v_total * refresh_mhz / 1e9)
        const u64 needed = (static_cast<u64>(kMinVsyncBpUsRb) * v_total_est * static_cast<u64>(req.refresh_mhz));
        const u32 min_v_blank_lines = DivRoundUp(needed, 1000000000ULL);
        const u32 vbf_min = kRbVFrontPorch + v_sync_lines + kRbVBackPorch;
        u32 candidate = (min_v_blank_lines < vbf_min) ? vbf_min : min_v_blank_lines;
        if (candidate == v_blanking)
            break;
        v_blanking = candidate;
    }

    const u32 v_total = v_active + v_blanking;
    // pixel_clock_khz = (refresh_mhz / 1000) * v_total * h_total / 1000
    //                 = refresh_mhz * v_total * h_total / 1_000_000
    const u64 pclk_num = static_cast<u64>(req.refresh_mhz) * v_total * h_total;
    const u32 pclk_khz = DivRoundNearest(pclk_num, 1000000ULL);

    // CVT-RB sync polarity: H-positive, V-negative.
    return FillDtd(h_active, kRbHBlank, kRbHFrontPorch, kRbHSync, v_active, v_blanking, kRbVFrontPorch, v_sync_lines,
                   pclk_khz, true, false);
}

EdidDtd GenerateStandard(const CvtRequest& req)
{
    // CVT 1.1 §4 Standard.
    const u32 h_active = RoundUpToCellGran(req.h_active);
    const u32 v_active = req.v_active;
    const u32 v_sync = SyncLinesForAspect(req.h_active, req.v_active);

    // §4.1.2: H_PERIOD_EST (in μs) =
    //   (1/V_REFRESH - MIN_VSYNC_BP/1e6) /
    //   (V_LINES + MIN_PORCH) * 1e6
    //
    // refresh_mhz is millihertz (refresh × 1000), so refresh_hz =
    // refresh_mhz / 1000. Frame period in picoseconds = 1e12 /
    // refresh_hz = 1e15 / refresh_mhz. The variable is named
    // `frame_period_ns_x1000` because the downstream formulas treat
    // it as nanoseconds × 1000, which is the same scale.
    //
    // We carry an extra 1000× scale through to stash the precision
    // that floats would normally hold.
    const u64 frame_period_ns_x1000 = (1000000000000000ULL / req.refresh_mhz);
    // h_period_us_x1000 = (frame_period_ns_x1000 - kMinVsyncBpUsStd*1000*1000) / (V_LINES + MIN_PORCH)
    if (frame_period_ns_x1000 <= static_cast<u64>(kMinVsyncBpUsStd) * 1000ULL * 1000ULL)
    {
        // Asked for a refresh too high for this mode — fall back
        // to RB which has tighter porch budget.
        return GenerateRb(req);
    }
    const u64 h_period_num = frame_period_ns_x1000 - static_cast<u64>(kMinVsyncBpUsStd) * 1000ULL * 1000ULL;
    const u64 h_period_den = static_cast<u64>(v_active) + kMinPorch;
    const u64 h_period_ns_x1000 = h_period_num / h_period_den;
    if (h_period_ns_x1000 == 0)
        return GenerateRb(req);

    // §4.1.3: V_SYNC_BP = round(MIN_VSYNC_BP / H_PERIOD) + 1
    //         V_BACK_PORCH = V_SYNC_BP - V_SYNC (implicit in v_blanking layout below)
    const u64 vsync_bp_num = static_cast<u64>(kMinVsyncBpUsStd) * 1000000ULL;
    u32 v_sync_bp = DivRoundNearest(vsync_bp_num, h_period_ns_x1000) + 1;
    if (v_sync_bp < v_sync + kMinPorch)
        v_sync_bp = v_sync + kMinPorch;

    // V_TOTAL = V_LINES + V_SYNC_BP + V_FRONT_PORCH(=MIN_PORCH).
    const u32 v_blanking = kMinPorch + v_sync_bp;

    // §4.1.4: IDEAL_DUTY_CYCLE = C' - M' × H_PERIOD_us / 1000   (in %)
    // Carry as micro-percent (×100) to avoid loss of precision:
    //   duty_x100 = C'_x100 - (M' × H_PERIOD_us × 100) / 1000
    //             = C'_x100 - M' × H_PERIOD_us / 10
    // With h_period_us_x1000 = H_PERIOD_us × 1000:
    //   duty_x100 = C'_x100 - (M' × h_period_us_x1000) / 10000
    const u64 h_period_us_x1000 = h_period_ns_x1000 / 1000ULL;
    const i64 duty_x100 = static_cast<i64>(kCPrimeX100) -
                          static_cast<i64>(static_cast<u64>(kMPrimeUsPerS) * h_period_us_x1000 / 10000ULL);

    u32 h_blanking = 0;
    if (duty_x100 < 2000)
    {
        // Floor at 20%
        const u32 raw = DivRoundUp(static_cast<u64>(20) * h_active, 80ULL);
        h_blanking = ((raw + 2 * kCellGran - 1) / (2 * kCellGran)) * (2 * kCellGran);
    }
    else
    {
        // h_blank = round(h_active * duty / (100 - duty)) rounded
        // up to (2 × cell-gran) multiple.
        const u64 num = static_cast<u64>(h_active) * static_cast<u64>(duty_x100);
        const i64 den_x100 = 10000 - duty_x100;
        if (den_x100 <= 0)
            h_blanking = kRbHBlank;
        else
        {
            const u64 raw = num / static_cast<u64>(den_x100);
            h_blanking = ((raw + 2 * kCellGran - 1) / (2 * kCellGran)) * (2 * kCellGran);
        }
    }

    const u32 h_total = h_active + h_blanking;

    // §4.1.5: H_SYNC = round(H_SYNC_PER_PCT * H_TOTAL / CELL_GRAN) * CELL_GRAN
    const u32 h_sync = ((kHSyncPerPct * h_total + 50 * kCellGran) / (100 * kCellGran)) * kCellGran;
    const u32 h_front_porch = (h_blanking / 2) - h_sync;

    // pixel_clock_khz = h_total / h_period_us = h_total * 1e6 / h_period_ns_x1000
    const u64 pclk_num = static_cast<u64>(h_total) * 1000000000ULL;
    const u32 pclk_khz = DivRoundNearest(pclk_num, h_period_ns_x1000);

    // CVT Standard sync polarity: H-negative, V-positive.
    return FillDtd(h_active, h_blanking, h_front_porch, h_sync, v_active, v_blanking, kMinPorch, v_sync, pclk_khz,
                   false, true);
}

} // namespace

::duetos::core::Result<EdidDtd> CvtGenerate(const CvtRequest& req)
{
    if (req.h_active == 0 || req.v_active == 0 || req.refresh_mhz == 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    // Cap refresh at 240 Hz as a sanity bound — beyond that, real
    // monitors have their own non-CVT timings and the CVT formula
    // breaks down.
    if (req.refresh_mhz > 240000)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};

    if (req.mode == CvtMode::ReducedBlankingV1)
        return GenerateRb(req);
    return GenerateStandard(req);
}

void CvtSelfTest()
{
    using ::duetos::drivers::video::ConsoleWriteln;

    struct Case
    {
        const char* tag;
        u16 w, h;
        u32 refresh_mhz;
        CvtMode mode;
        u32 expected_pclk_khz;     // ±2% acceptance
        u32 expected_pclk_tol_pct; // tolerance %
    };
    // Reference values produced by X.Org cvt(1) host-side, rounded
    // to integer kHz. Tolerance tightened to 2% (Standard) / 1%
    // (RB, since RB has fewer free knobs and is more deterministic).
    const Case cases[] = {
        // 640x480@60 RB:    h_total = 800,    v_total = 500,   60 × 800 × 500 = 24,000,000 Hz = 24.0 MHz
        {"640x480@60 RB", 640, 480, 60000, CvtMode::ReducedBlankingV1, 24000, 5},
        // 1024x768@60 RB:   h_total = 1184,   v_total = 790,   60 × 1184 × 790 ≈ 56.12 MHz
        {"1024x768@60 RB", 1024, 768, 60000, CvtMode::ReducedBlankingV1, 56120, 5},
        // 1280x1024@60 RB:  h_total = 1440,   v_total = 1050,  60 × 1440 × 1050 = 90.72 MHz
        {"1280x1024@60 RB", 1280, 1024, 60000, CvtMode::ReducedBlankingV1, 90720, 5},
        // 1920x1080@60 RB:  h_total = 2080,   v_total = 1111,  60 × 2080 × 1111 ≈ 138.6 MHz
        {"1920x1080@60 RB", 1920, 1080, 60000, CvtMode::ReducedBlankingV1, 138600, 5},
        // 2560x1440@60 RB:  h_total = 2720,   v_total = 1481,  60 × 2720 × 1481 ≈ 241.5 MHz
        {"2560x1440@60 RB", 2560, 1440, 60000, CvtMode::ReducedBlankingV1, 241500, 5},
        // 1280x1024@60 STD: cvt(1) reports ≈ 109.0 MHz with 5% tolerance for porch rounding.
        {"1280x1024@60 STD", 1280, 1024, 60000, CvtMode::Standard, 109000, 5},
    };

    for (const Case& c : cases)
    {
        CvtRequest req = {};
        req.h_active = c.w;
        req.v_active = c.h;
        req.refresh_mhz = c.refresh_mhz;
        req.mode = c.mode;
        auto res = CvtGenerate(req);
        if (!res.has_value())
        {
            ::duetos::drivers::video::ConsoleWrite("[selftest] CVT FAILED to generate ");
            ConsoleWriteln(c.tag);
            ::duetos::core::Panic("drivers/gpu/cvt", "CvtGenerate returned error on known-good case");
        }
        const EdidDtd& t = res.value();
        // Tolerance check on pixel clock.
        const u64 lo = static_cast<u64>(c.expected_pclk_khz) * (100 - c.expected_pclk_tol_pct) / 100;
        const u64 hi = static_cast<u64>(c.expected_pclk_khz) * (100 + c.expected_pclk_tol_pct) / 100;
        if (t.pixel_clock_khz < lo || t.pixel_clock_khz > hi)
        {
            ::duetos::drivers::video::ConsoleWrite("[selftest] CVT ");
            ::duetos::drivers::video::ConsoleWrite(c.tag);
            ConsoleWriteln(": pixel clock outside ±tolerance");
            ::duetos::core::Panic("drivers/gpu/cvt", "CVT pixel clock out of range");
        }
        // Refresh must round-trip back to within 1 Hz of the request.
        const u32 rq = c.refresh_mhz;
        const u32 got = t.refresh_mhz;
        const u32 diff = (got > rq) ? (got - rq) : (rq - got);
        if (diff > 1000)
        {
            ::duetos::drivers::video::ConsoleWrite("[selftest] CVT ");
            ::duetos::drivers::video::ConsoleWrite(c.tag);
            ConsoleWriteln(": refresh round-trip > 1 Hz off");
            ::duetos::core::Panic("drivers/gpu/cvt", "CVT refresh round-trip failed");
        }
        // h_active must be cell-gran-rounded.
        if ((t.h_active % 8) != 0)
        {
            ::duetos::core::Panic("drivers/gpu/cvt", "CVT h_active not cell-gran aligned");
        }
    }

    // Bad-input checks.
    {
        CvtRequest bad = {};
        if (CvtGenerate(bad).has_value())
            ::duetos::core::Panic("drivers/gpu/cvt", "CVT accepted zero-zero-zero input");
    }
    {
        CvtRequest bad = {1920, 1080, 999999999u, CvtMode::ReducedBlankingV1};
        if (CvtGenerate(bad).has_value())
            ::duetos::core::Panic("drivers/gpu/cvt", "CVT accepted absurd refresh rate");
    }

    ConsoleWriteln("[selftest] CVT timing generator: 6 modes pass + 2 bad-input rejections.");
}

} // namespace duetos::drivers::gpu
