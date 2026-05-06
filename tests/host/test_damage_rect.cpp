// tests/host/test_damage_rect.cpp
//
// Hosted unit tests for `DamageRect::Extend` in
// kernel/drivers/video/framebuffer.h. The framebuffer driver
// itself is freestanding-hostile (it touches MMIO + multiboot
// state), but the union-rect math is a pure constexpr method on
// `DamageRect` so we can exercise it directly.
//
// Why this matters: every pixel-write primitive routes its post-
// clip rect through this method, and the End-of-compose blit
// + the virtio-gpu present hook only flush the resulting bbox.
// If `Extend` regresses (e.g. forgets to cover a corner case)
// the symptom is "the screen is missing pixels" — visible on a
// real display but invisible to a build-clean check. A host
// regression sentinel keeps the math honest.

#include "drivers/video/framebuffer.h"
#include "host_test_helper.h"

using duetos::u32;
using duetos::drivers::video::DamageRect;

int main()
{
    // ----- empty starting state -----
    {
        DamageRect d{};
        EXPECT_FALSE(d.valid);
        EXPECT_EQ(d.x, 0u);
        EXPECT_EQ(d.y, 0u);
        EXPECT_EQ(d.w, 0u);
        EXPECT_EQ(d.h, 0u);
    }

    // ----- first non-empty Extend populates the union -----
    {
        DamageRect d{};
        d.Extend(10, 20, 30, 40);
        EXPECT_TRUE(d.valid);
        EXPECT_EQ(d.x, 10u);
        EXPECT_EQ(d.y, 20u);
        EXPECT_EQ(d.w, 30u);
        EXPECT_EQ(d.h, 40u);
    }

    // ----- zero-w / zero-h are silent no-ops, even on an empty
    //       DamageRect (they don't accidentally promote to valid). -----
    {
        DamageRect d{};
        d.Extend(10, 10, 0, 5);
        EXPECT_FALSE(d.valid);
        d.Extend(10, 10, 5, 0);
        EXPECT_FALSE(d.valid);
        d.Extend(10, 10, 0, 0);
        EXPECT_FALSE(d.valid);
    }

    // ----- zero-w / zero-h on a populated DamageRect leave it
    //       unchanged. -----
    {
        DamageRect d{};
        d.Extend(10, 10, 5, 5);
        const u32 before_x = d.x;
        const u32 before_y = d.y;
        const u32 before_w = d.w;
        const u32 before_h = d.h;
        d.Extend(0, 0, 0, 0);
        d.Extend(50, 50, 0, 7);
        EXPECT_TRUE(d.valid);
        EXPECT_EQ(d.x, before_x);
        EXPECT_EQ(d.y, before_y);
        EXPECT_EQ(d.w, before_w);
        EXPECT_EQ(d.h, before_h);
    }

    // ----- Extend by a contained rect leaves the union unchanged. -----
    {
        DamageRect d{};
        d.Extend(0, 0, 100, 100);
        d.Extend(20, 20, 30, 30); // entirely inside (0,0,100,100)
        EXPECT_EQ(d.x, 0u);
        EXPECT_EQ(d.y, 0u);
        EXPECT_EQ(d.w, 100u);
        EXPECT_EQ(d.h, 100u);
    }

    // ----- Extend by a containing rect replaces the union. -----
    {
        DamageRect d{};
        d.Extend(20, 20, 30, 30);
        d.Extend(0, 0, 100, 100);
        EXPECT_EQ(d.x, 0u);
        EXPECT_EQ(d.y, 0u);
        EXPECT_EQ(d.w, 100u);
        EXPECT_EQ(d.h, 100u);
    }

    // ----- Two disjoint rects produce a bbox covering both. The
    //       single-bbox tracker intentionally widens here — see the
    //       Design-Decisions entry justifying single-bbox over a
    //       rect list.
    {
        DamageRect d{};
        d.Extend(0, 0, 10, 10);     // top-left
        d.Extend(990, 990, 10, 10); // bottom-right (1024x1024 surface)
        EXPECT_EQ(d.x, 0u);
        EXPECT_EQ(d.y, 0u);
        EXPECT_EQ(d.w, 1000u); // 990 + 10 - 0
        EXPECT_EQ(d.h, 1000u);
    }

    // ----- Adjacent (non-overlapping but touching) rects coalesce
    //       into a single rect, no gap. -----
    {
        DamageRect d{};
        d.Extend(0, 0, 50, 100);
        d.Extend(50, 0, 50, 100); // shares the seam at x=50
        EXPECT_EQ(d.x, 0u);
        EXPECT_EQ(d.y, 0u);
        EXPECT_EQ(d.w, 100u);
        EXPECT_EQ(d.h, 100u);
    }

    // ----- Reset drops back to the empty state — and a subsequent
    //       Extend rebuilds from there. -----
    {
        DamageRect d{};
        d.Extend(10, 10, 5, 5);
        d.Reset();
        EXPECT_FALSE(d.valid);
        EXPECT_EQ(d.x, 0u);
        EXPECT_EQ(d.y, 0u);
        EXPECT_EQ(d.w, 0u);
        EXPECT_EQ(d.h, 0u);
        d.Extend(7, 8, 9, 10);
        EXPECT_TRUE(d.valid);
        EXPECT_EQ(d.x, 7u);
        EXPECT_EQ(d.y, 8u);
        EXPECT_EQ(d.w, 9u);
        EXPECT_EQ(d.h, 10u);
    }

    // ----- Single-pixel writes (the PutPixel + DrawLine hot path)
    //       accumulate correctly. -----
    {
        DamageRect d{};
        d.Extend(5, 5, 1, 1);
        d.Extend(10, 10, 1, 1);
        EXPECT_EQ(d.x, 5u);
        EXPECT_EQ(d.y, 5u);
        EXPECT_EQ(d.w, 6u); // 11 - 5
        EXPECT_EQ(d.h, 6u);
    }

    // ----- One-axis growth: same vertical extent, expanding x. -----
    {
        DamageRect d{};
        d.Extend(50, 10, 10, 30);
        d.Extend(20, 10, 10, 30); // pulls the left edge in
        EXPECT_EQ(d.x, 20u);
        EXPECT_EQ(d.y, 10u);
        EXPECT_EQ(d.w, 40u); // 60 - 20
        EXPECT_EQ(d.h, 30u);
    }

    // ----- constexpr smoke: compute a union at compile time. If
    //       Extend stops being constexpr, this test fails to build,
    //       which is the correct signal — the compose path runs the
    //       function thousands of times per frame and the kernel
    //       depends on the optimizer inlining it.
    {
        constexpr auto union_of = []
        {
            DamageRect d{};
            d.Extend(1, 2, 3, 4);
            d.Extend(100, 200, 1, 1);
            return d;
        };
        constexpr DamageRect r = union_of();
        static_assert(r.valid);
        static_assert(r.x == 1);
        static_assert(r.y == 2);
        // First rect ends at x1=4,y1=6; second at x1=101,y1=201.
        // Union: x=1, y=2, w=101-1=100, h=201-2=199.
        static_assert(r.w == 100);
        static_assert(r.h == 199);
    }

    return ::duetos_host_test::finish_main(__FILE__);
}
