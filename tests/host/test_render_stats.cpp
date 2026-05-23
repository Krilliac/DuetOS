// tests/host/test_render_stats.cpp
//
// Hosted unit tests for `kernel/drivers/video/render_stats.cpp`,
// the compositor counters that back the kernel shell's `gfx`
// command. The TU is integer-only (saturating-counter arithmetic
// over a `DamageRect` snapshot) so it compiles cleanly on the
// host once we shim the `util/saturating.h` log-emit symbol.
//
// What this pins:
//
//   1. `RenderStatsOnPresent` charges the TRUE dirty pixel count
//      (sum of per-rect areas), not the union bbox area. Banded
//      presents with spatially-separated rects used to overcount
//      by `bbox - sum(rects)`; this is the regression sentinel
//      for that fix.
//   2. The full/partial classification uses the true dirty count
//      (the 95%-of-surface threshold), so a banded present that
//      barely touches the surface is `partial` even when its
//      bbox would qualify as `full`.
//   3. `presents_banded` / `presents_coalesced` / `max_band_count`
//      track rect_count correctly: 0 = clean, 1 = coalesced,
//      >1 = banded.
//   4. `frames_clean` ticks when `bbox.valid == false` and no
//      other counter advances (specifically, `dirty_pixels_total`
//      and `bbox_pixels_total` stay put).
//   5. `RenderStatsReset` zeroes every field.
//
// We don't try to test the framebuffer's MMIO/compose path; the
// damage-tracker math has its own host test in
// test_damage_rect.cpp. This test scopes to RenderStats itself.

#include "host_test_helper.h"

// RenderStats includes <drivers/video/framebuffer.h> for DamageRect.
// That header is freestanding-friendly (constexpr struct + method
// declarations) and matches the existing test_damage_rect.cpp model.
#include "drivers/video/render_stats.h"

#include <cstdint>

using duetos::u32;
using duetos::u64;
using duetos::drivers::video::DamageRect;
using duetos::drivers::video::RenderStats;
using duetos::drivers::video::RenderStatsOnComposeEnd;
using duetos::drivers::video::RenderStatsOnPresent;
using duetos::drivers::video::RenderStatsRead;
using duetos::drivers::video::RenderStatsReset;

// Host-side stub for `util/saturating.h`'s log-emit, same shape as
// test_saturating.cpp. Counters in render_stats use SatU64 which
// only triggers a clamp at u64-max — we won't reach that in this
// test, but the stub is needed so the symbol resolves at link time.
namespace duetos::util
{
void SatLogClamp(const char* /*tag*/, u64 /*attempted*/, u64 /*clamped*/, void* /*caller_rip*/) {}
} // namespace duetos::util

namespace
{

DamageRect MakeRect(u32 x, u32 y, u32 w, u32 h)
{
    DamageRect r{};
    if (w != 0 && h != 0)
    {
        r.Extend(x, y, w, h);
    }
    return r;
}

DamageRect Clean()
{
    return DamageRect{};
}

} // namespace

int main()
{
    constexpr u32 kSurfaceW = 1280;
    constexpr u32 kSurfaceH = 800;
    constexpr u64 kSurfacePx = static_cast<u64>(kSurfaceW) * kSurfaceH;

    // ----- baseline: reset clears every counter ---------------------
    {
        // First seed some non-zero state, then reset.
        RenderStatsOnComposeEnd();
        RenderStatsOnPresent(MakeRect(0, 0, 100, 100), 10000, 1, kSurfaceW, kSurfaceH);
        RenderStatsReset();
        const RenderStats rs = RenderStatsRead();
        EXPECT_EQ(rs.frames_composed, 0ull);
        EXPECT_EQ(rs.frames_presented, 0ull);
        EXPECT_EQ(rs.frames_clean, 0ull);
        EXPECT_EQ(rs.frames_full, 0ull);
        EXPECT_EQ(rs.frames_partial, 0ull);
        EXPECT_EQ(rs.dirty_pixels_total, 0ull);
        EXPECT_EQ(rs.bbox_pixels_total, 0ull);
        EXPECT_EQ(rs.surface_pixels_total, 0ull);
        EXPECT_EQ(rs.presents_banded, 0ull);
        EXPECT_EQ(rs.presents_coalesced, 0ull);
        EXPECT_EQ(rs.max_band_count, 0u);
        EXPECT_EQ(rs.last_damage_x, 0u);
        EXPECT_EQ(rs.last_damage_y, 0u);
        EXPECT_EQ(rs.last_damage_w, 0u);
        EXPECT_EQ(rs.last_damage_h, 0u);
        EXPECT_EQ(rs.last_rect_count, 0u);
        EXPECT_FALSE(rs.last_damage_valid);
    }

    // ----- clean present: only frames_presented + frames_clean tick -
    {
        RenderStatsReset();
        RenderStatsOnPresent(Clean(), 0, 0, kSurfaceW, kSurfaceH);
        const RenderStats rs = RenderStatsRead();
        EXPECT_EQ(rs.frames_presented, 1ull);
        EXPECT_EQ(rs.frames_clean, 1ull);
        EXPECT_EQ(rs.frames_full, 0ull);
        EXPECT_EQ(rs.frames_partial, 0ull);
        EXPECT_EQ(rs.dirty_pixels_total, 0ull);
        EXPECT_EQ(rs.bbox_pixels_total, 0ull);
        EXPECT_EQ(rs.surface_pixels_total, 0ull);
        EXPECT_EQ(rs.presents_banded, 0ull);
        EXPECT_EQ(rs.presents_coalesced, 0ull);
        EXPECT_EQ(rs.last_rect_count, 0u);
        EXPECT_FALSE(rs.last_damage_valid);
    }

    // ----- coalesced (single-rect) present: bbox == dirty -----------
    {
        RenderStatsReset();
        const DamageRect d = MakeRect(10, 20, 200, 100);
        const u64 dirty = static_cast<u64>(d.w) * d.h; // 20000
        RenderStatsOnPresent(d, dirty, 1, kSurfaceW, kSurfaceH);
        const RenderStats rs = RenderStatsRead();
        EXPECT_EQ(rs.frames_presented, 1ull);
        EXPECT_EQ(rs.frames_clean, 0ull);
        EXPECT_EQ(rs.dirty_pixels_total, dirty);
        EXPECT_EQ(rs.bbox_pixels_total, dirty);
        EXPECT_EQ(rs.surface_pixels_total, kSurfacePx);
        EXPECT_EQ(rs.presents_coalesced, 1ull);
        EXPECT_EQ(rs.presents_banded, 0ull);
        EXPECT_EQ(rs.max_band_count, 1u);
        EXPECT_EQ(rs.frames_partial, 1ull); // 20k px is way under 95% of surface
        EXPECT_EQ(rs.frames_full, 0ull);
        EXPECT_EQ(rs.last_rect_count, 1u);
        EXPECT_TRUE(rs.last_damage_valid);
        EXPECT_EQ(rs.last_damage_x, 10u);
        EXPECT_EQ(rs.last_damage_y, 20u);
        EXPECT_EQ(rs.last_damage_w, 200u);
        EXPECT_EQ(rs.last_damage_h, 100u);
    }

    // ----- BANDED PRESENT: bbox area >> sum(rects) ------------------
    //
    // This is the regression sentinel for the v0-banded overcounting
    // bug. Two small spatially-separated rects (taskbar at top,
    // tray clock at bottom-right) produce a bbox spanning most of
    // the surface — but the GPU only uploads the per-rect area.
    {
        RenderStatsReset();
        // Two disjoint rects: 1280x24 (taskbar) at y=0, 100x20 (clock)
        // at (1180, 760). Bbox: (0, 0) → (1280, 780), area = 998400.
        // True dirty: 1280*24 + 100*20 = 30720 + 2000 = 32720.
        DamageRect bbox{};
        bbox.Extend(0, 0, 1280, 24);
        bbox.Extend(1180, 760, 100, 20);
        const u64 true_dirty = 1280ull * 24 + 100ull * 20; // 32720
        const u64 bbox_area = static_cast<u64>(bbox.w) * bbox.h;
        EXPECT_EQ(bbox_area, 1280ull * 780); // 998400

        RenderStatsOnPresent(bbox, true_dirty, 2, kSurfaceW, kSurfaceH);
        const RenderStats rs = RenderStatsRead();
        EXPECT_EQ(rs.frames_presented, 1ull);
        // Charged the TRUE dirty count, not the bbox area.
        EXPECT_EQ(rs.dirty_pixels_total, true_dirty);
        EXPECT_EQ(rs.bbox_pixels_total, bbox_area);
        EXPECT_EQ(rs.presents_banded, 1ull);
        EXPECT_EQ(rs.presents_coalesced, 0ull);
        EXPECT_EQ(rs.max_band_count, 2u);
        // 32720 pixels is ~3% of a 1280x800 surface — partial.
        // (The bbox is ~97%; if classification used bbox it would
        // be "full" — that's the historical bug we're regressing.)
        EXPECT_EQ(rs.frames_partial, 1ull);
        EXPECT_EQ(rs.frames_full, 0ull);
        EXPECT_EQ(rs.last_rect_count, 2u);
    }

    // ----- BANDED PRESENT: true dirty crosses the 95% threshold -----
    //
    // A "real big repaint" — many bands changed, sum of rects is
    // ≥95% of surface. Should classify as `full`, not `partial`.
    {
        RenderStatsReset();
        // Simulate: caller pre-aggregated 980000 dirty pixels across
        // a 12-rect banded present whose bbox happens to be 1280x780.
        DamageRect bbox{};
        bbox.Extend(0, 0, 1280, 780);
        const u64 dirty_pixels = 980000; // > 95% of 1280*800 = 1024000
        RenderStatsOnPresent(bbox, dirty_pixels, 12, kSurfaceW, kSurfaceH);
        const RenderStats rs = RenderStatsRead();
        EXPECT_EQ(rs.frames_full, 1ull);
        EXPECT_EQ(rs.frames_partial, 0ull);
        EXPECT_EQ(rs.presents_banded, 1ull);
        EXPECT_EQ(rs.max_band_count, 12u);
        EXPECT_EQ(rs.last_rect_count, 12u);
    }

    // ----- max_band_count is a high-water mark, not the last value -
    {
        RenderStatsReset();
        RenderStatsOnPresent(MakeRect(0, 0, 10, 10), 100, 5, kSurfaceW, kSurfaceH);
        RenderStatsOnPresent(MakeRect(0, 0, 10, 10), 100, 12, kSurfaceW, kSurfaceH);
        RenderStatsOnPresent(MakeRect(0, 0, 10, 10), 100, 3, kSurfaceW, kSurfaceH);
        const RenderStats rs = RenderStatsRead();
        EXPECT_EQ(rs.max_band_count, 12u);
        EXPECT_EQ(rs.presents_banded, 3ull);
        EXPECT_EQ(rs.last_rect_count, 3u); // last value, separate from max
    }

    // ----- accumulation across many frames --------------------------
    {
        RenderStatsReset();
        // 3 coalesced presents of 100x100 = 10000 px each.
        for (int i = 0; i < 3; ++i)
        {
            RenderStatsOnPresent(MakeRect(0, 0, 100, 100), 10000, 1, kSurfaceW, kSurfaceH);
        }
        // 1 clean present (skipped — only frames_clean ticks).
        RenderStatsOnPresent(Clean(), 0, 0, kSurfaceW, kSurfaceH);
        // 1 banded present: bbox 500x500 = 250000, true dirty 1000.
        {
            DamageRect bbox{};
            bbox.Extend(0, 0, 500, 500);
            RenderStatsOnPresent(bbox, 1000, 4, kSurfaceW, kSurfaceH);
        }
        const RenderStats rs = RenderStatsRead();
        EXPECT_EQ(rs.frames_presented, 5ull);
        EXPECT_EQ(rs.frames_clean, 1ull);
        EXPECT_EQ(rs.presents_coalesced, 3ull);
        EXPECT_EQ(rs.presents_banded, 1ull);
        EXPECT_EQ(rs.dirty_pixels_total, 3ull * 10000 + 1000);  // 31000
        EXPECT_EQ(rs.bbox_pixels_total, 3ull * 10000 + 250000); // 280000
        // Each non-clean present contributes one full surface area.
        EXPECT_EQ(rs.surface_pixels_total, 4ull * kSurfacePx);
        EXPECT_EQ(rs.max_band_count, 4u);
    }

    // ----- ComposeEnd is independent of presents --------------------
    {
        RenderStatsReset();
        RenderStatsOnComposeEnd();
        RenderStatsOnComposeEnd();
        RenderStatsOnComposeEnd();
        const RenderStats rs = RenderStatsRead();
        EXPECT_EQ(rs.frames_composed, 3ull);
        EXPECT_EQ(rs.frames_presented, 0ull);
    }

    return duetos_host_test::finish_main("render_stats");
}
