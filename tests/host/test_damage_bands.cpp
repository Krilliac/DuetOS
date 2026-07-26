// tests/host/test_damage_bands.cpp
//
// Hosted unit tests for `DamageBandSet` in
// kernel/drivers/video/framebuffer.h — the banded-damage math that
// `FramebufferEndCompose` uses to decide what the present hook
// uploads. Companion to test_damage_rect.cpp (which covers the
// single-rect union `DamageRect::Extend` underneath it).
//
// The framebuffer driver itself is freestanding-hostile (MMIO,
// multiboot, frame allocator), but the band slicing / compaction /
// union math is pure constexpr state on `DamageBandSet`, so we can
// exercise the exact code the kernel runs.
//
// Why this matters: `EndCompose` publishes damage from TWO sources —
// the shadow-vs-snapshot content diff, and the forced snapshot-
// invalidation rects posted by direct-to-live writers (the cursor
// sprite; `WindowRaise`'s full-surface z-order guard). The forced
// pass re-syncs the snapshot at each rect, which makes the content
// diff report those pixels as UNCHANGED. If the forced rects are not
// folded back into the published damage, `FramebufferPresent` treats
// the frame as clean and a present-hook backend (virtio-gpu) never
// runs TRANSFER_TO_HOST_2D over them: the pixels land on the live
// surface and never reach the host scanout. Symptom on a virtio
// scanout: a moved cursor leaves its old sprite behind, and a
// z-order raise doesn't repaint (the "windows beneath bleed
// through" report). `ForcedRectSurvivesEmptyDiff` below is the
// regression sentinel for exactly that.

#include "drivers/video/framebuffer.h"
#include "host_test_helper.h"

using duetos::u32;
using duetos::u64;
using duetos::drivers::video::DamageBandSet;
using duetos::drivers::video::kDamageBandHeight;
using duetos::drivers::video::kDamageCoalesceBands;
using duetos::drivers::video::kDamageMaxRects;

namespace
{

// Which path `FramebufferEndCompose` + `FramebufferPresent` take for a
// given accumulated band set. Mirrors the driver's decision ladder so
// the test asserts on the published outcome, not just on intermediate
// state.
enum class PresentPath
{
    Clean,     // nothing to publish — hook skipped entirely
    Coalesced, // one union-bbox flush (overflow or too many bands)
    Banded,    // one flush per dirty band
};

PresentPath ClassifyPath(DamageBandSet& set, u32& rect_count_out)
{
    if (!set.bbox.valid)
    {
        rect_count_out = 0;
        return PresentPath::Clean;
    }
    const u32 dirty = set.Compact();
    if (set.overflow || dirty > kDamageCoalesceBands)
    {
        rect_count_out = 1;
        return PresentPath::Coalesced;
    }
    rect_count_out = dirty;
    return PresentPath::Banded;
}

// Sum of the per-band rect areas — what the backend actually uploads
// on the banded path.
u64 BandedArea(const DamageBandSet& set, u32 count)
{
    u64 area = 0;
    for (u32 i = 0; i < count; ++i)
    {
        area += static_cast<u64>(set.bands[i].w) * set.bands[i].h;
    }
    return area;
}

} // namespace

int main()
{
    // ----- Reset sizes the band array from the surface height -----
    {
        DamageBandSet set{};
        set.Reset(768);
        EXPECT_EQ(set.band_count, (768u + kDamageBandHeight - 1u) / kDamageBandHeight);
        EXPECT_FALSE(set.bbox.valid);
        EXPECT_FALSE(set.overflow);
        for (u32 b = 0; b < set.band_count; ++b)
        {
            EXPECT_FALSE(set.bands[b].valid);
        }

        // A surface shorter than one band still gets one band.
        set.Reset(1);
        EXPECT_EQ(set.band_count, 1u);

        // A zero-height surface gets zero bands: every Add then
        // overflows rather than writing out of bounds.
        set.Reset(0);
        EXPECT_EQ(set.band_count, 0u);
        set.Add(0, 0, 4, 4);
        EXPECT_TRUE(set.overflow);

        // Taller than the array covers -> clamped to capacity.
        set.Reset(kDamageMaxRects * kDamageBandHeight * 2u);
        EXPECT_EQ(set.band_count, kDamageMaxRects);
    }

    // ----- empty rects are silent no-ops -----
    {
        DamageBandSet set{};
        set.Reset(768);
        set.Add(10, 10, 0, 5);
        set.Add(10, 10, 5, 0);
        EXPECT_FALSE(set.bbox.valid);
        EXPECT_FALSE(set.overflow);
        u32 rects = 0;
        EXPECT_TRUE(ClassifyPath(set, rects) == PresentPath::Clean);
        EXPECT_EQ(rects, 0u);
    }

    // ----- a single scanline span lands in exactly one band -----
    {
        DamageBandSet set{};
        set.Reset(768);
        set.Add(100, 200, 50, 1); // band 3 (200 / 64)
        EXPECT_TRUE(set.bands[3].valid);
        EXPECT_FALSE(set.bands[2].valid);
        EXPECT_FALSE(set.bands[4].valid);
        EXPECT_EQ(set.bands[3].x, 100u);
        EXPECT_EQ(set.bands[3].y, 200u);
        EXPECT_EQ(set.bands[3].w, 50u);
        EXPECT_EQ(set.bands[3].h, 1u);
        EXPECT_EQ(set.bbox.x, 100u);
        EXPECT_EQ(set.bbox.w, 50u);
    }

    // ----- a rect crossing a band boundary is SLICED, not smeared:
    //       each band records only the scanlines it owns. -----
    {
        DamageBandSet set{};
        set.Reset(768);
        set.Add(10, 60, 20, 10); // rows 60..69 -> band 0 (60..63), band 1 (64..69)
        EXPECT_TRUE(set.bands[0].valid);
        EXPECT_TRUE(set.bands[1].valid);
        EXPECT_FALSE(set.bands[2].valid);
        EXPECT_EQ(set.bands[0].y, 60u);
        EXPECT_EQ(set.bands[0].h, 4u);
        EXPECT_EQ(set.bands[1].y, 64u);
        EXPECT_EQ(set.bands[1].h, 6u);
        // No band claims a scanline outside the rect.
        EXPECT_EQ(set.bands[0].y + set.bands[0].h, 64u);
        EXPECT_EQ(set.bands[1].y + set.bands[1].h, 70u);
        // The per-band areas sum to the rect's area — the slice is a
        // partition, so the backend uploads no extra pixels.
        u32 rects = 0;
        EXPECT_TRUE(ClassifyPath(set, rects) == PresentPath::Banded);
        EXPECT_EQ(rects, 2u);
        EXPECT_EQ(BandedArea(set, rects), 20ull * 10ull);
    }

    // ----- spatially-separated changes stay separate rects (the "D1"
    //       fix): two small far-apart spans must NOT fuse into one
    //       near-fullscreen upload. -----
    {
        DamageBandSet set{};
        set.Reset(768);
        set.Add(0, 0, 16, 16);     // top-left widget, band 0
        set.Add(900, 740, 60, 12); // taskbar clock, band 11
        u32 rects = 0;
        EXPECT_TRUE(ClassifyPath(set, rects) == PresentPath::Banded);
        EXPECT_EQ(rects, 2u);
        // Banded upload is the two tight rects; the bbox a non-banded
        // backend would have uploaded is over 100x larger.
        EXPECT_EQ(BandedArea(set, rects), 16ull * 16ull + 60ull * 12ull);
        EXPECT_TRUE(static_cast<u64>(set.bbox.w) * set.bbox.h > 100ull * BandedArea(set, rects));
    }

    // ----- Compact() moves dirty bands to the front, in band order,
    //       and is idempotent. -----
    {
        DamageBandSet set{};
        set.Reset(768);
        set.Add(5, 130, 10, 4); // band 2
        set.Add(7, 5, 10, 4);   // band 0
        set.Add(9, 400, 10, 4); // band 6
        const u32 first = set.Compact();
        EXPECT_EQ(first, 3u);
        EXPECT_EQ(set.bands[0].y, 5u);
        EXPECT_EQ(set.bands[1].y, 130u);
        EXPECT_EQ(set.bands[2].y, 400u);
        EXPECT_FALSE(set.bands[3].valid);
        // Second call with no intervening Add must not double-count or
        // reorder — EndCompose reads the array after this returns.
        const u32 second = set.Compact();
        EXPECT_EQ(second, first);
        EXPECT_EQ(set.bands[0].y, 5u);
        EXPECT_EQ(set.bands[1].y, 130u);
        EXPECT_EQ(set.bands[2].y, 400u);
        EXPECT_FALSE(set.bands[3].valid);
    }

    // ----- too many dirty bands -> the consumer coalesces to one
    //       bbox flush rather than firing N backend round-trips. -----
    {
        DamageBandSet set{};
        set.Reset(768);
        for (u32 b = 0; b <= kDamageCoalesceBands; ++b)
        {
            set.Add(10, b * kDamageBandHeight, 20, 2);
        }
        u32 rects = 0;
        EXPECT_TRUE(ClassifyPath(set, rects) == PresentPath::Coalesced);
        EXPECT_EQ(rects, 1u);
        EXPECT_TRUE(set.bbox.valid);
    }

    // ----- overflow (a rect past the band array) forces the bbox
    //       path, because the per-band list no longer covers every
    //       changed pixel. -----
    {
        DamageBandSet set{};
        // Pretend the array only covers the first two bands.
        set.Reset(2u * kDamageBandHeight);
        EXPECT_EQ(set.band_count, 2u);
        set.Add(0, 0, 8, 8);
        EXPECT_FALSE(set.overflow);
        set.Add(0, 4u * kDamageBandHeight, 8, 8); // band 4 — past the end
        EXPECT_TRUE(set.overflow);
        u32 rects = 0;
        EXPECT_TRUE(ClassifyPath(set, rects) == PresentPath::Coalesced);
        EXPECT_EQ(rects, 1u);
        // The bbox still covers the out-of-range rect, so the flush is
        // complete even though the band list isn't.
        EXPECT_EQ(set.bbox.y, 0u);
        EXPECT_EQ(set.bbox.y + set.bbox.h, 4u * kDamageBandHeight + 8u);
    }

    // ===== REGRESSION: ForcedRectSurvivesEmptyDiff ==================
    // A cursor move produces NO content diff (the forced-invalidation
    // pass already re-synced the snapshot at both the old and the new
    // sprite rect), so the only thing left to publish is the forced
    // rects. The frame must NOT classify as clean: on a virtio-gpu
    // scanout the forced blit reaches the guest's live surface but
    // nothing reaches the host until the present hook fires.
    {
        DamageBandSet set{};
        set.Reset(768);
        // Content diff found nothing this pass.
        EXPECT_FALSE(set.bbox.valid);
        // Fold the two forced cursor rects (old + new sprite position).
        set.Add(300, 300, 12, 20); // erase the sprite at the old spot
        set.Add(316, 308, 12, 20); // paint it at the new spot
        u32 rects = 0;
        const PresentPath path = ClassifyPath(set, rects);
        EXPECT_TRUE(path != PresentPath::Clean);
        EXPECT_TRUE(path == PresentPath::Banded);
        // Rows 300..327 straddle the band-4 / band-5 boundary at 320.
        EXPECT_EQ(rects, 2u);
        // Band 4 carries both sprite positions' overlapping rows.
        EXPECT_EQ(set.bands[0].x, 300u);
        EXPECT_EQ(set.bands[0].x + set.bands[0].w, 328u);
        EXPECT_EQ(set.bands[0].y, 300u);
        EXPECT_EQ(set.bands[0].y + set.bands[0].h, 320u);
        // Band 5 carries only the new position's tail rows.
        EXPECT_EQ(set.bands[1].x, 316u);
        EXPECT_EQ(set.bands[1].x + set.bands[1].w, 328u);
        EXPECT_EQ(set.bands[1].y, 320u);
        EXPECT_EQ(set.bands[1].y + set.bands[1].h, 328u);
        // Union spans both sprite rects and nothing more.
        EXPECT_EQ(set.bbox.x, 300u);
        EXPECT_EQ(set.bbox.y, 300u);
        EXPECT_EQ(set.bbox.x + set.bbox.w, 328u);
        EXPECT_EQ(set.bbox.y + set.bbox.h, 328u);
    }

    // ===== REGRESSION: full-surface forced invalidation publishes ====
    // `WindowRaise` posts a full-surface invalidation as its z-order
    // repaint guard. After the forced pass re-syncs the snapshot the
    // content diff is empty, so the fold is the ONLY thing that keeps
    // the guard alive. It must land as a single full-surface flush.
    {
        DamageBandSet set{};
        set.Reset(768);
        set.Add(0, 0, 1024, 768);
        u32 rects = 0;
        EXPECT_TRUE(ClassifyPath(set, rects) == PresentPath::Coalesced);
        EXPECT_EQ(rects, 1u);
        EXPECT_EQ(set.bbox.x, 0u);
        EXPECT_EQ(set.bbox.y, 0u);
        EXPECT_EQ(set.bbox.w, 1024u);
        EXPECT_EQ(set.bbox.h, 768u);
    }

    // ----- forced rects fold into diff spans without losing either.
    //       Diff span at the top, forced cursor rect near the bottom:
    //       both must be published, as two separate bands. -----
    {
        DamageBandSet set{};
        set.Reset(768);
        set.Add(400, 8, 120, 1);  // content diff: title-bar scanline, band 0
        set.Add(50, 460, 12, 20); // forced: cursor erase, rows 460..479, band 7
        u32 rects = 0;
        EXPECT_TRUE(ClassifyPath(set, rects) == PresentPath::Banded);
        EXPECT_EQ(rects, 2u);
        EXPECT_EQ(set.bands[0].y, 8u);
        EXPECT_EQ(set.bands[1].y, 460u);
        EXPECT_EQ(BandedArea(set, rects), 120ull * 1ull + 12ull * 20ull);
    }

    // ----- constexpr evaluability: the same math must fold at compile
    //       time, which is what keeps it kernel-safe (no hidden state,
    //       no UB on the paths the driver takes). -----
    {
        constexpr u32 folded = []
        {
            DamageBandSet set{};
            set.Reset(256);
            set.Add(0, 0, 4, 4);
            set.Add(0, 200, 4, 4);
            return set.Compact();
        }();
        static_assert(folded == 2u, "band fold must be constexpr-evaluable");
        EXPECT_EQ(folded, 2u);
    }

    return duetos_host_test::finish_main("damage_bands");
}
