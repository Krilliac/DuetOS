// test_gdi32_region_combine.cpp — hosted unit test for the exact
// rect-list combine ops (intersect / subtract / union / xor) in
// userland/libs/gdi32/gdi32_region.h. These back gdi32.c's
// CombineRgn and the DC clip engine (ExtSelectClipRgn /
// IntersectClipRect / ExcludeClipRect), which only run in a
// bare-metal PE smoke — this hosted test is the gate for the math.

#include "host_test_helper.h"

#include "../../userland/libs/gdi32/gdi32_region.h"

using namespace duetos_host_test;

static int total_area(const GdiRgnRect* r, int n)
{
    int a = 0;
    for (int i = 0; i < n; ++i)
        a += (r[i].right - r[i].left) * (r[i].bottom - r[i].top);
    return a;
}

static bool same_rect(const GdiRgnRect& a, int l, int t, int r, int b)
{
    return a.left == l && a.top == t && a.right == r && a.bottom == b;
}

int main()
{
    GdiRgnRect out[32];

    // --- SubtractRect: disjoint -> r survives whole ---
    {
        GdiRgnRect r = {0, 0, 10, 10};
        GdiRgnRect s = {20, 20, 30, 30};
        EXPECT_EQ(GdiRgnSubtractRect(&r, &s, out), 1);
        EXPECT_TRUE(same_rect(out[0], 0, 0, 10, 10));
    }

    // --- SubtractRect: full cover -> nothing survives ---
    {
        GdiRgnRect r = {5, 5, 8, 8};
        GdiRgnRect s = {0, 0, 10, 10};
        EXPECT_EQ(GdiRgnSubtractRect(&r, &s, out), 0);
    }

    // --- SubtractRect: punch a centre hole -> 4 bands ---
    {
        GdiRgnRect r = {0, 0, 10, 10};
        GdiRgnRect s = {3, 3, 7, 7};
        EXPECT_EQ(GdiRgnSubtractRect(&r, &s, out), 4);
        EXPECT_EQ(total_area(out, 4), 84); // 100 - 16
        EXPECT_TRUE(GdiRgnPtIn(out, 4, 0, 0));
        EXPECT_FALSE(GdiRgnPtIn(out, 4, 5, 5)); // inside the hole
        EXPECT_TRUE(GdiRgnPtIn(out, 4, 9, 9));
    }

    // --- SubtractRect: corner overlap -> 2 bands ---
    {
        GdiRgnRect r = {0, 0, 10, 10};
        GdiRgnRect s = {5, 5, 15, 15};
        EXPECT_EQ(GdiRgnSubtractRect(&r, &s, out), 2);
        EXPECT_EQ(total_area(out, 2), 75); // 100 - 25
        EXPECT_FALSE(GdiRgnPtIn(out, 2, 6, 6));
        EXPECT_TRUE(GdiRgnPtIn(out, 2, 2, 2));
    }

    // --- Intersect: basic overlap ---
    {
        GdiRgnRect a = {0, 0, 10, 10};
        GdiRgnRect b = {5, 5, 15, 15};
        EXPECT_EQ(GdiRgnIntersect(&a, 1, &b, 1, out, 1), 1);
        EXPECT_TRUE(same_rect(out[0], 5, 5, 10, 10));
    }

    // --- Intersect: no overlap ---
    {
        GdiRgnRect a = {0, 0, 10, 10};
        GdiRgnRect b = {20, 0, 30, 10};
        EXPECT_EQ(GdiRgnIntersect(&a, 1, &b, 1, out, 1), 0);
    }

    // --- Intersect: cap overflow -> -1 (caller falls back to bbox) ---
    {
        GdiRgnRect a[2] = {{0, 0, 10, 10}, {20, 0, 30, 10}};
        GdiRgnRect b[2] = {{0, 0, 30, 5}, {0, 6, 30, 9}};
        // 4 non-empty pairwise pieces, cap 3.
        EXPECT_EQ(GdiRgnIntersect(a, 2, b, 2, out, 3), -1);
        EXPECT_EQ(GdiRgnIntersect(a, 2, b, 2, out, 4), 4);
    }

    // --- Subtract list: carve both ends off a strip ---
    {
        GdiRgnRect a = {0, 0, 20, 10};
        GdiRgnRect b[2] = {{0, 0, 5, 10}, {15, 0, 20, 10}};
        const int n = GdiRgnSubtract(&a, 1, b, 2, out, 8);
        EXPECT_EQ(n, 1); // survives as one middle rect {5,0,15,10}
        EXPECT_EQ(total_area(out, n), 100);
        EXPECT_TRUE(GdiRgnPtIn(out, n, 10, 5));
        EXPECT_FALSE(GdiRgnPtIn(out, n, 2, 5));
        EXPECT_FALSE(GdiRgnPtIn(out, n, 17, 5));
    }

    // --- Union: disjoint operands concatenate ---
    {
        GdiRgnRect a = {0, 0, 10, 10};
        GdiRgnRect b = {20, 0, 30, 10};
        EXPECT_EQ(GdiRgnUnion(&a, 1, &b, 1, out, 3), 2);
        EXPECT_EQ(total_area(out, 2), 200);
    }

    // --- Union: overlap counted once (disjoint output) ---
    {
        GdiRgnRect a = {0, 0, 10, 10};
        GdiRgnRect b = {5, 0, 15, 10};
        const int n = GdiRgnUnion(&a, 1, &b, 1, out, 3);
        EXPECT_EQ(n, 2); // a + (b \ a) = {0,0,10,10} + {10,0,15,10}
        EXPECT_EQ(total_area(out, n), 150);
        EXPECT_TRUE(GdiRgnPtIn(out, n, 12, 5));
        EXPECT_TRUE(GdiRgnPtIn(out, n, 7, 5));
    }

    // --- Union: identical operands -> just a ---
    {
        GdiRgnRect a = {0, 0, 10, 10};
        GdiRgnRect b = {0, 0, 10, 10};
        const int n = GdiRgnUnion(&a, 1, &b, 1, out, 3);
        EXPECT_EQ(n, 1);
        EXPECT_EQ(total_area(out, n), 100);
    }

    // --- Xor: overlap drops out entirely ---
    {
        GdiRgnRect a = {0, 0, 10, 10};
        GdiRgnRect b = {5, 0, 15, 10};
        const int n = GdiRgnXor(&a, 1, &b, 1, out, 3);
        EXPECT_EQ(n, 2);
        EXPECT_EQ(total_area(out, n), 100); // 150 minus overlap twice
        EXPECT_TRUE(GdiRgnPtIn(out, n, 2, 5));
        EXPECT_FALSE(GdiRgnPtIn(out, n, 7, 5));
        EXPECT_TRUE(GdiRgnPtIn(out, n, 12, 5));
    }

    // --- Xor: identical operands -> empty ---
    {
        GdiRgnRect a = {0, 0, 10, 10};
        GdiRgnRect b = {0, 0, 10, 10};
        EXPECT_EQ(GdiRgnXor(&a, 1, &b, 1, out, 3), 0);
    }

    return finish_main("gdi32_region_combine");
}
