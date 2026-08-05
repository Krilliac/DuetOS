// test_gdi32_region.cpp — hosted unit test for the GDI region geometry.
//
// Covers: userland/libs/gdi32/gdi32_region.h — the freestanding
// rect-list region math behind gdi32.c's GetRgnBox / PtInRegion /
// RectInRegion / OffsetRgn / SetRectRgn / EqualRgn exports. Those
// run only in a bare-metal PE smoke (Win32 DLLs aren't on the QEMU CI
// path), so this hosted test is the gate for the logic.

#include "host_test_helper.h"

#include "../../userland/libs/gdi32/gdi32_region.h"

using namespace duetos_host_test;

int main()
{
    // --- NormRect ---
    {
        GdiRgnRect r = {10, 20, 30, 40};
        EXPECT_TRUE(GdiRgnNormRect(&r));
        EXPECT_EQ(r.left, 10);
        EXPECT_EQ(r.right, 30);

        GdiRgnRect inv = {30, 40, 10, 20}; // inverted both axes
        EXPECT_TRUE(GdiRgnNormRect(&inv));
        EXPECT_EQ(inv.left, 10);
        EXPECT_EQ(inv.top, 20);
        EXPECT_EQ(inv.right, 30);
        EXPECT_EQ(inv.bottom, 40);

        GdiRgnRect degen = {5, 5, 5, 10}; // zero width
        EXPECT_FALSE(GdiRgnNormRect(&degen));
    }

    // --- BBox ---
    {
        GdiRgnRect out;
        EXPECT_FALSE(GdiRgnBBox(nullptr, 0, &out)); // empty region
        EXPECT_EQ(out.left, 0);
        EXPECT_EQ(out.right, 0);

        GdiRgnRect single[1] = {{1, 2, 3, 4}};
        EXPECT_TRUE(GdiRgnBBox(single, 1, &out));
        EXPECT_EQ(out.left, 1);
        EXPECT_EQ(out.bottom, 4);

        GdiRgnRect multi[3] = {{10, 10, 20, 20}, {0, 5, 5, 8}, {15, 15, 40, 30}};
        EXPECT_TRUE(GdiRgnBBox(multi, 3, &out));
        EXPECT_EQ(out.left, 0);   // min left
        EXPECT_EQ(out.top, 5);    // min top
        EXPECT_EQ(out.right, 40); // max right
        EXPECT_EQ(out.bottom, 30);
    }

    // --- PtIn (half-open: [left,right) x [top,bottom)) ---
    {
        GdiRgnRect r[1] = {{10, 10, 20, 20}};
        EXPECT_TRUE(GdiRgnPtIn(r, 1, 10, 10));  // top-left corner included
        EXPECT_TRUE(GdiRgnPtIn(r, 1, 19, 19));  // inside
        EXPECT_FALSE(GdiRgnPtIn(r, 1, 20, 15)); // right edge excluded
        EXPECT_FALSE(GdiRgnPtIn(r, 1, 15, 20)); // bottom edge excluded
        EXPECT_FALSE(GdiRgnPtIn(r, 1, 9, 15));  // left of region
        EXPECT_FALSE(GdiRgnPtIn(r, 0, 15, 15)); // empty region

        // Multi-rect: point in the second rect only.
        GdiRgnRect two[2] = {{0, 0, 5, 5}, {100, 100, 110, 110}};
        EXPECT_TRUE(GdiRgnPtIn(two, 2, 105, 105));
        EXPECT_FALSE(GdiRgnPtIn(two, 2, 50, 50));
    }

    // --- RectIn (overlap; edge-touch is NOT overlap) ---
    {
        GdiRgnRect r[1] = {{10, 10, 30, 30}};
        GdiRgnRect overlap = {20, 20, 40, 40};
        EXPECT_TRUE(GdiRgnRectIn(r, 1, &overlap));
        GdiRgnRect contained = {12, 12, 15, 15};
        EXPECT_TRUE(GdiRgnRectIn(r, 1, &contained));
        GdiRgnRect edge = {30, 10, 40, 30}; // touches right edge, no area overlap
        EXPECT_FALSE(GdiRgnRectIn(r, 1, &edge));
        GdiRgnRect disjoint = {100, 100, 110, 110};
        EXPECT_FALSE(GdiRgnRectIn(r, 1, &disjoint));
        EXPECT_FALSE(GdiRgnRectIn(r, 0, &overlap)); // empty region
    }

    // --- Offset ---
    {
        GdiRgnRect r[2] = {{0, 0, 10, 10}, {20, 20, 30, 30}};
        GdiRgnOffset(r, 2, 5, -3);
        EXPECT_EQ(r[0].left, 5);
        EXPECT_EQ(r[0].top, -3);
        EXPECT_EQ(r[0].right, 15);
        EXPECT_EQ(r[1].bottom, 27);
    }

    // --- Equal ---
    {
        GdiRgnRect a[1] = {{1, 2, 3, 4}};
        GdiRgnRect b[1] = {{1, 2, 3, 4}};
        GdiRgnRect c[1] = {{1, 2, 3, 5}};
        EXPECT_TRUE(GdiRgnEqual(a, 1, b, 1));
        EXPECT_FALSE(GdiRgnEqual(a, 1, c, 1));
        EXPECT_FALSE(GdiRgnEqual(a, 1, a, 0));            // count mismatch
        EXPECT_TRUE(GdiRgnEqual(nullptr, 0, nullptr, 0)); // both empty
    }

    // --- ISqrt ---
    {
        EXPECT_EQ(GdiRgnISqrt(0), 0);
        EXPECT_EQ(GdiRgnISqrt(1), 1);
        EXPECT_EQ(GdiRgnISqrt(4), 2);
        EXPECT_EQ(GdiRgnISqrt(9), 3);
        EXPECT_EQ(GdiRgnISqrt(15), 3); // floor(sqrt(15)) = 3
        EXPECT_EQ(GdiRgnISqrt(16), 4);
        EXPECT_EQ(GdiRgnISqrt(100), 10);
        EXPECT_EQ(GdiRgnISqrt(10000), 100);
        EXPECT_EQ(GdiRgnISqrt(-5), 0); // negative -> 0
    }

    // --- EllipseRects (degenerate cases) ---
    {
        GdiRgnRect buf[8];
        // Zero-width
        EXPECT_EQ(GdiRgnEllipseRects(10, 10, 10, 20, buf, 8), 0);
        // Zero-height
        EXPECT_EQ(GdiRgnEllipseRects(10, 10, 20, 10, buf, 8), 0);
        // Inverted coords (should normalise internally)
        int n = GdiRgnEllipseRects(20, 20, 10, 10, buf, 8);
        EXPECT_TRUE(n > 0);
        // max_rects = 0
        EXPECT_EQ(GdiRgnEllipseRects(0, 0, 10, 10, buf, 0), 0);
    }

    // --- EllipseRects (small: 4x4, height fits in max_rects) ---
    {
        GdiRgnRect buf[8];
        int n = GdiRgnEllipseRects(0, 0, 4, 4, buf, 8);
        EXPECT_TRUE(n > 0);
        EXPECT_TRUE(n <= 4); // height=4, at most 4 bands

        for (int i = 0; i < n; ++i)
        {
            EXPECT_TRUE(buf[i].left >= 0);
            EXPECT_TRUE(buf[i].right <= 4);
            EXPECT_TRUE(buf[i].top >= 0);
            EXPECT_TRUE(buf[i].bottom <= 4);
            EXPECT_TRUE(buf[i].right > buf[i].left);
            EXPECT_TRUE(buf[i].bottom > buf[i].top);
        }
        // Bands must be vertically non-overlapping
        for (int i = 1; i < n; ++i)
        {
            EXPECT_TRUE(buf[i].top >= buf[i - 1].bottom);
        }
    }

    // --- EllipseRects (large: 100x100, banded to max_rects=8) ---
    {
        GdiRgnRect buf[8];
        int n = GdiRgnEllipseRects(0, 0, 100, 100, buf, 8);
        EXPECT_TRUE(n > 0);
        EXPECT_TRUE(n <= 8);

        // Middle bands should be at least as wide as top/bottom
        if (n >= 3)
        {
            int mid = n / 2;
            int mid_w = buf[mid].right - buf[mid].left;
            int top_w = buf[0].right - buf[0].left;
            EXPECT_TRUE(mid_w >= top_w);
        }
        // Symmetry: each rect's horizontal centre should be near 50
        for (int i = 0; i < n; ++i)
        {
            int cx = (buf[i].left + buf[i].right) / 2;
            EXPECT_TRUE(cx >= 45 && cx <= 55);
        }
    }

    // --- EllipseRects (PtIn: centre inside, corner outside) ---
    {
        GdiRgnRect buf[8];
        int n = GdiRgnEllipseRects(10, 20, 50, 60, buf, 8);
        EXPECT_TRUE(n > 0);
        // Centre of bounding rect (30, 40) must be inside
        EXPECT_TRUE(GdiRgnPtIn(buf, n, 30, 40));
        // Corner of bounding rect must be outside (ellipse inscribed)
        EXPECT_FALSE(GdiRgnPtIn(buf, n, 10, 20));
    }

    return finish_main("gdi32_region");
}
