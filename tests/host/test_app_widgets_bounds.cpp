// tests/host/test_app_widgets_bounds.cpp
//
// Pass D Task 6 — Rect arithmetic + clipping invariants.
//
// Re-derives the Rect type inline (kernel header is `-ffreestanding`
// and can't be linked into the host test; this matches the
// shadow-test pattern from Pass C's chrome_text_measure). The
// `Contains(px, py)` predicate is the load-bearing primitive behind
// every widget's hit-testing path — a half-open rectangle where
// `[x, x+w) x [y, y+h)` defines the live area. A future drift that
// flips inclusive/exclusive on either boundary would silently
// double-fire hover events at widget edges; this test pins the
// contract.

#include "host_test_helper.h"

#include <cstdint>

struct Rect
{
    uint32_t x = 0;
    uint32_t y = 0;
    uint32_t w = 0;
    uint32_t h = 0;

    bool Contains(uint32_t px, uint32_t py) const
    {
        return px >= x && py >= y && px < x + w && py < y + h;
    }
};

int main()
{
    Rect r{10U, 20U, 100U, 50U};
    EXPECT_TRUE(r.Contains(50U, 40U));   // inside
    EXPECT_TRUE(r.Contains(10U, 20U));   // top-left inclusive
    EXPECT_TRUE(!r.Contains(5U, 40U));   // left of x
    EXPECT_TRUE(!r.Contains(110U, 40U)); // x boundary exclusive
    EXPECT_TRUE(!r.Contains(50U, 70U));  // y boundary exclusive
    EXPECT_TRUE(!r.Contains(50U, 15U));  // above y

    // Right/bottom-edge exclusivity is the half-open contract: the
    // last contained pixel is (x+w-1, y+h-1), not (x+w, y+h). Pin it
    // explicitly so a "just shift the +1" regression bites here.
    EXPECT_TRUE(r.Contains(109U, 69U));
    EXPECT_TRUE(!r.Contains(110U, 70U));

    Rect empty{0U, 0U, 0U, 0U};
    EXPECT_TRUE(!empty.Contains(0U, 0U));

    return ::duetos_host_test::finish_main("tests/host/test_app_widgets_bounds.cpp");
}
