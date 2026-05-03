#include "drivers/gpu/gtf.h"

#include "core/panic.h"

namespace duetos::drivers::gpu
{

namespace
{

// VESA GTF 1.1 default constants (§3.6).
constexpr u32 kGtfMinVporchLines = 3;
constexpr u32 kGtfMinVporchSyncUs = 550; // micro-seconds for VBI minimum
constexpr u32 kGtfVSyncLines = 3;
constexpr u32 kGtfHsyncFraction = 8; // h_sync ≈ 8% of h_total
constexpr u32 kGtfHsyncRoundPx = 8;
constexpr u32 kGtfCellGran = 8; // h_active rounded to 8-pixel boundary

// GTF blanking-formula coefficients in micro-percent (×100):
//   duty_micropct = C_micropct - M_micropct * h_period_us / 1000
// Defaults C=40 → 4_000_000, M=600 → 600.
constexpr u32 kGtfCMicropct = 40u * 100u * 100u; // = 400_000
constexpr u32 kGtfMMicroSlope = 600u * 100u;     // 600 × 100 = 60_000 per ms

EdidDtd FillDtd(u16 h_active, u16 h_blanking, u16 h_sync_offset, u16 h_sync_pulse, u16 v_active, u16 v_blanking,
                u16 v_sync_offset, u16 v_sync_pulse, u32 pixel_clock_khz, bool h_pos, bool v_pos)
{
    EdidDtd dtd = {};
    dtd.pixel_clock_khz = pixel_clock_khz;
    dtd.h_active = h_active;
    dtd.h_blanking = h_blanking;
    dtd.v_active = v_active;
    dtd.v_blanking = v_blanking;
    dtd.h_sync_offset = h_sync_offset;
    dtd.h_sync_pulse = h_sync_pulse;
    dtd.v_sync_offset = v_sync_offset;
    dtd.v_sync_pulse = v_sync_pulse;
    dtd.interlaced = false;
    dtd.sync_type = 3; // digital separate
    dtd.h_sync_positive = h_pos;
    dtd.v_sync_positive = v_pos;
    const u32 h_total = u32(h_active) + u32(h_blanking);
    const u32 v_total = u32(v_active) + u32(v_blanking);
    if (h_total > 0 && v_total > 0)
        dtd.refresh_mhz = u32(u64(pixel_clock_khz) * 1000000ull / (u64(h_total) * v_total));
    return dtd;
}

} // namespace

::duetos::core::Result<EdidDtd> GtfGenerate(const GtfRequest& req)
{
    if (req.h_active == 0 || req.v_active == 0 || req.refresh_mhz == 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    if (req.refresh_mhz > 200000)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};

    // Round h_active up to the nearest cell-granularity boundary
    // (8 px). Real GTF starts from "ideal h_pixels" and rounds.
    const u32 h_active = (u32(req.h_active) + kGtfCellGran - 1) & ~(kGtfCellGran - 1);

    // Step 1: vertical lines. Add 3 lines for sync, plus min v-porch
    // lines (initial minimum 3; refined after we know h_period).
    // Refresh in milli-Hz; convert to period (ns) for a moment.
    //   v_total_period_us = 1_000_000 / refresh_hz
    // At 60.000 Hz we get 16667 us per frame.
    const u64 frame_period_us = 1000000ull * 1000ull / u64(req.refresh_mhz); // 1e6 / (refresh × 1e-3)

    // First-pass v_total: active + sync + min v-porch lines + min porch in lines.
    // Compute h_period_us = frame_period_us / v_total. We solve for v_total
    // using the GTF iteration:
    //   est_v_lines = 1_000_000 / (refresh_mhz * h_period_us / 1000)
    // For simplicity, pin v_porch at the spec's minimum (no
    // iteration needed for v0 — accuracy is good enough for the
    // legacy CRT tier this slice targets).
    const u32 v_sync = kGtfVSyncLines;
    const u32 v_back_porch = kGtfMinVporchLines;
    // Front porch defaults to 1 line per spec.
    const u32 v_front_porch = 1;
    const u32 v_blanking = v_sync + v_back_porch + v_front_porch;
    const u32 v_total = u32(req.v_active) + v_blanking;

    // h_period_us (the time for one scanline).
    const u64 h_period_us_x1000 = u64(frame_period_us) * 1000 / v_total;

    // GTF duty cycle in micro-percent (×100):
    //   duty_micropct = (C×100×100) - (M×100 × h_period_us)/1000
    if (h_period_us_x1000 == 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    const u32 h_period_us = u32(h_period_us_x1000 / 1000);
    if (h_period_us == 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};

    // duty_micropct: spec value is (C - M*h_period_us/1000) percent.
    // We carry it as integer micro-percent: 1 micro-percent = 0.0001%.
    // C = 40 % = 4_000_000 micro-percent.
    // M_per_us = 600 / 1000 = 0.6 percent per us → 60_000 micro-percent per us.
    // So duty_micropct = 4_000_000 - 60_000 × h_period_us / 1.
    // For h_period_us ≈ 16, duty ≈ 4_000_000 - 960_000 = 3_040_000 micro-percent = 30.4 %.
    i64 duty_micropct = i64(kGtfCMicropct) - i64(kGtfMMicroSlope) * i64(h_period_us);
    if (duty_micropct < 200000) // < 2 %
        duty_micropct = 200000;
    if (duty_micropct > 9000000) // > 90 %
        duty_micropct = 9000000;
    // h_blanking = h_active * duty / (100 - duty)
    // In micro-percent terms: h_blank = h_active * duty_micropct / (10_000_000 - duty_micropct)
    const u64 num = u64(h_active) * u64(duty_micropct);
    const u64 den = 10000000ull - u64(duty_micropct);
    if (den == 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    u32 h_blanking = u32(num / den);
    h_blanking = (h_blanking + kGtfCellGran - 1) & ~(kGtfCellGran - 1);
    if (h_blanking < kGtfHsyncRoundPx * 4)
        h_blanking = kGtfHsyncRoundPx * 4;

    const u32 h_total = h_active + h_blanking;

    // h_sync ≈ 8 % of h_total, rounded to the nearest 8 px.
    u32 h_sync = (h_total * kGtfHsyncFraction) / 100;
    h_sync = ((h_sync + kGtfHsyncRoundPx / 2) / kGtfHsyncRoundPx) * kGtfHsyncRoundPx;
    if (h_sync == 0)
        h_sync = kGtfHsyncRoundPx;
    if (h_sync >= h_blanking)
        h_sync = h_blanking - kGtfHsyncRoundPx;

    // h_front_porch default per GTF: half of (h_blanking - h_sync).
    u32 h_front_porch = (h_blanking - h_sync) / 2;
    h_front_porch = ((h_front_porch + kGtfCellGran - 1) / kGtfCellGran) * kGtfCellGran;
    if (h_front_porch + h_sync > h_blanking)
        h_front_porch = (h_blanking - h_sync) / 2;
    // h_back_porch is the remainder (consumed implicitly via h_sync_offset/pulse).
    // h_sync_offset (front porch in pixels), per EdidDtd.

    // pixel clock (kHz):
    //   pclk_khz = h_total * refresh_hz * v_total / 1000
    //            = h_total * v_total * refresh_mhz / 1_000_000 (kHz)
    const u64 pclk_khz = u64(h_total) * u64(v_total) * u64(req.refresh_mhz) / 1000000ull;

    return FillDtd(u16(h_active), u16(h_blanking), u16(h_front_porch), u16(h_sync), req.v_active, u16(v_blanking),
                   u16(v_front_porch), u16(v_sync), u32(pclk_khz),
                   /*h_pos=*/false, /*v_pos=*/true);
}

void GtfSelfTest()
{
    // Sanity: 640×480@60 — well-known mode. GTF gives h_total around
    // 832 and pixel clock around 25 MHz; the actual VESA-published
    // 640×480@60 uses 25.175 MHz. We accept ±10% for v0.
    {
        GtfRequest r = {};
        r.h_active = 640;
        r.v_active = 480;
        r.refresh_mhz = 60000;
        const auto result = GtfGenerate(r);
        KASSERT(result.has_value(), "drivers/gpu/gtf", "640x480@60 generate failed");
        const auto& dtd = result.value();
        KASSERT(dtd.h_active == 640, "drivers/gpu/gtf", "h_active wrong");
        KASSERT(dtd.v_active == 480, "drivers/gpu/gtf", "v_active wrong");
        // h_total in [780, 880]
        const u32 h_total = u32(dtd.h_active) + u32(dtd.h_blanking);
        KASSERT(h_total >= 780 && h_total <= 880, "drivers/gpu/gtf", "h_total out of band");
        // pixel clock 22..28 MHz
        KASSERT(dtd.pixel_clock_khz >= 22000 && dtd.pixel_clock_khz <= 28000, "drivers/gpu/gtf",
                "640x480@60 pclk out of band");
        // refresh within ±2% of 60.000
        KASSERT(dtd.refresh_mhz >= 58000 && dtd.refresh_mhz <= 62000, "drivers/gpu/gtf",
                "640x480@60 refresh out of band");
    }

    // Sanity: 1024×768@70 (a common CRT mode).
    {
        GtfRequest r = {};
        r.h_active = 1024;
        r.v_active = 768;
        r.refresh_mhz = 70000;
        const auto result = GtfGenerate(r);
        KASSERT(result.has_value(), "drivers/gpu/gtf", "1024x768@70 generate failed");
        const auto& dtd = result.value();
        KASSERT(dtd.h_active == 1024 && dtd.v_active == 768, "drivers/gpu/gtf", "1024x768@70 dims wrong");
        KASSERT(dtd.refresh_mhz >= 68000 && dtd.refresh_mhz <= 72000, "drivers/gpu/gtf",
                "1024x768@70 refresh out of band");
    }

    // Negative cases.
    {
        GtfRequest r = {};
        r.h_active = 0;
        r.v_active = 480;
        r.refresh_mhz = 60000;
        KASSERT(!GtfGenerate(r).has_value(), "drivers/gpu/gtf", "h=0 not rejected");
        r.h_active = 640;
        r.v_active = 480;
        r.refresh_mhz = 0;
        KASSERT(!GtfGenerate(r).has_value(), "drivers/gpu/gtf", "refresh=0 not rejected");
        r.refresh_mhz = 250000;
        KASSERT(!GtfGenerate(r).has_value(), "drivers/gpu/gtf", "refresh>200kHz not rejected");
    }
}

} // namespace duetos::drivers::gpu
