// test_gdi32_fill.cpp — hosted unit test for the GDI scanline fill geometry.
//
// Covers: userland/libs/gdi32/gdi32_fill.h — the freestanding edge-list
// / active-edge scan behind gdi32.c's FillPath and StrokeAndFillPath.
// Those exports run only in a bare-metal PE smoke (Win32 DLLs aren't on
// the QEMU CI path), so this hosted test is the gate for the logic.
//
// The core check is differential: for every fixture polygon and both
// fill modes, the set of pixels the scan converter emits must match, to
// the pixel, an independent floating-point ray-crossing oracle. That
// catches off-by-one sampling errors the "does it look filled" style of
// test sails straight past.

#include "host_test_helper.h"

#include "../../userland/libs/gdi32/gdi32_fill.h"

using namespace duetos_host_test;

namespace
{

// --- Fixtures ---------------------------------------------------------
//
// A regular pentagon centred at (50, 50) with circumradius 40, vertex 0
// straight up, on a y-down screen (screen y = 50 - 40*sin(angle)):
//   P0 (50, 10)  P1 (12, 38)  P2 (26, 82)  P3 (74, 82)  P4 (88, 38)
// Visiting them in the order 0, 2, 4, 1, 3 traces the classic pentagram
// as ONE self-intersecting loop — the canonical shape whose centre is
// hollow under ALTERNATE and solid under WINDING.
const int kStarX[] = {50, 26, 88, 12, 74};
const int kStarY[] = {10, 82, 38, 38, 82};
const int kStarCount = 5;

// Convex square.
const int kSquareX[] = {10, 60, 60, 10};
const int kSquareY[] = {10, 10, 60, 60};
const int kSquareCount = 4;

// Concave "L", clockwise on a y-down screen.
const int kElX[] = {10, 50, 50, 30, 30, 10};
const int kElY[] = {10, 10, 30, 30, 60, 60};
const int kElCount = 6;

// Convex triangle with one horizontal edge (exercises the drop path).
const int kTriX[] = {20, 70, 20};
const int kTriY[] = {10, 60, 60};
const int kTriCount = 3;

// Self-intersecting "bowtie" quadrilateral: the two lobes wind in
// opposite directions, so nonzero and even-odd agree here — a useful
// control against the star.
const int kBowX[] = {10, 50, 10, 50};
const int kBowY[] = {10, 50, 50, 10};
const int kBowCount = 4;

// --- Oracle -----------------------------------------------------------

// Independent ray-crossing point-in-polygon test over a multi-subpath
// path, evaluated at the pixel centre (px + 0.5, py + 0.5). Every
// subpath is closed implicitly, matching GdiFillBuildEdges.
//
// Half-open straddle test (y0 <= fy && y1 > fy for a downward edge,
// mirrored for upward) so a shared vertex is counted exactly once.
bool OraclePtInside(const int* xs, const int* ys, int pt_count, const int* sub_start, int sub_count, int mode, int px,
                    int py)
{
    const double fx = static_cast<double>(px) + 0.5;
    const double fy = static_cast<double>(py) + 0.5;
    int crossings = 0;
    int winding = 0;

    for (int s = 0; s < sub_count; ++s)
    {
        const int start = sub_start[s];
        const int end = (s + 1 < sub_count) ? sub_start[s + 1] : pt_count;
        if (end - start < 3)
        {
            continue;
        }
        for (int i = start; i < end; ++i)
        {
            const int j = (i + 1 < end) ? i + 1 : start;
            const double x0 = static_cast<double>(xs[i]);
            const double y0 = static_cast<double>(ys[i]);
            const double x1 = static_cast<double>(xs[j]);
            const double y1 = static_cast<double>(ys[j]);

            const bool down = (y0 <= fy && y1 > fy);
            const bool up = (y1 <= fy && y0 > fy);
            if (!down && !up)
            {
                continue;
            }
            const double xc = x0 + (fy - y0) * (x1 - x0) / (y1 - y0);
            if (xc > fx)
            {
                ++crossings;
                winding += down ? 1 : -1;
            }
        }
    }

    if (mode == GDI_FILL_WINDING)
    {
        return winding != 0;
    }
    return (crossings & 1) != 0;
}

// --- Span collector ---------------------------------------------------

constexpr int kMaxSpans = 512;

struct SpanBag
{
    int y[kMaxSpans];
    int x0[kMaxSpans];
    int x1[kMaxSpans];
    int count;
    bool overflowed;
};

void BagInit(SpanBag* bag)
{
    bag->count = 0;
    bag->overflowed = false;
}

void BagCollect(void* ctx, int y, int x0, int x1)
{
    SpanBag* bag = static_cast<SpanBag*>(ctx);
    if (bag->count >= kMaxSpans)
    {
        bag->overflowed = true;
        return;
    }
    bag->y[bag->count] = y;
    bag->x0[bag->count] = x0;
    bag->x1[bag->count] = x1;
    ++bag->count;
}

bool BagContains(const SpanBag* bag, int px, int py)
{
    for (int i = 0; i < bag->count; ++i)
    {
        if (bag->y[i] == py && px >= bag->x0[i] && px < bag->x1[i])
        {
            return true;
        }
    }
    return false;
}

// Spans must arrive in increasing y, then strictly increasing and
// non-touching x (GdiFillScan merges before emitting), and never empty.
bool BagWellFormed(const SpanBag* bag)
{
    for (int i = 0; i < bag->count; ++i)
    {
        if (bag->x1[i] <= bag->x0[i])
        {
            return false;
        }
        if (i == 0)
        {
            continue;
        }
        if (bag->y[i] < bag->y[i - 1])
        {
            return false;
        }
        if (bag->y[i] == bag->y[i - 1] && bag->x0[i] <= bag->x1[i - 1])
        {
            return false;
        }
    }
    return true;
}

// --- Differential harness ---------------------------------------------

// Scan-convert the path, then compare the emitted pixel set against the
// oracle over a window that comfortably contains the shape. Returns the
// number of disagreeing pixels (0 == the two agree exactly).
int DiffAgainstOracle(const char* name, const int* xs, const int* ys, int pt_count, const int* sub_start, int sub_count,
                      int mode)
{
    GdiFillEdge work[64];
    SpanBag bag;
    BagInit(&bag);

    const int spans = GdiFillPathSpans(xs, ys, pt_count, sub_start, sub_count, mode, work, 64, BagCollect, &bag);
    if (spans < 0 || bag.overflowed)
    {
        std::fprintf(stderr, "  %s mode=%d: scan failed (spans=%d overflow=%d)\n", name, mode, spans,
                     bag.overflowed ? 1 : 0);
        return -1;
    }
    if (!BagWellFormed(&bag))
    {
        std::fprintf(stderr, "  %s mode=%d: span list not well-formed\n", name, mode);
        return -1;
    }

    int mismatches = 0;
    for (int py = -5; py <= 105; ++py)
    {
        for (int px = -5; px <= 105; ++px)
        {
            const bool got = BagContains(&bag, px, py);
            const bool want = OraclePtInside(xs, ys, pt_count, sub_start, sub_count, mode, px, py);
            if (got != want)
            {
                if (mismatches < 8)
                {
                    std::fprintf(stderr, "  %s mode=%d: (%d,%d) got=%d want=%d\n", name, mode, px, py, got ? 1 : 0,
                                 want ? 1 : 0);
                }
                ++mismatches;
            }
        }
    }
    return mismatches;
}

int DiffSimple(const char* name, const int* xs, const int* ys, int n, int mode)
{
    const int sub_start[1] = {0};
    return DiffAgainstOracle(name, xs, ys, n, sub_start, 1, mode);
}

} // namespace

int main()
{
    // --- CeilDiv ---
    {
        EXPECT_EQ(GdiFillCeilDiv(7, 2), 4);
        EXPECT_EQ(GdiFillCeilDiv(8, 2), 4);
        EXPECT_EQ(GdiFillCeilDiv(-7, 2), -3);
        EXPECT_EQ(GdiFillCeilDiv(-8, 2), -4);
        EXPECT_EQ(GdiFillCeilDiv(0, 3), 0);
        EXPECT_EQ(GdiFillCeilDiv(1, 3), 1);
        EXPECT_EQ(GdiFillCeilDiv(-1, 3), 0);
    }

    // --- BuildEdges: horizontal edges dropped, winding recorded ---
    {
        GdiFillEdge e[16];
        const int sub_start[1] = {0};

        // Square: the two horizontal edges drop, leaving the verticals.
        EXPECT_EQ(GdiFillBuildEdges(kSquareX, kSquareY, kSquareCount, sub_start, 1, e, 16), 2);

        // Triangle: one of the three edges is horizontal.
        EXPECT_EQ(GdiFillBuildEdges(kTriX, kTriY, kTriCount, sub_start, 1, e, 16), 2);

        // Star: P1 and P4 share y == 38, so the pentagram's cross-bar
        // edge is horizontal and drops; four of the five survive.
        const int ns = GdiFillBuildEdges(kStarX, kStarY, kStarCount, sub_start, 1, e, 16);
        EXPECT_EQ(ns, 4);
        for (int i = 0; i < ns; ++i)
        {
            EXPECT_TRUE(e[i].ybot > e[i].ytop); // normalized
            EXPECT_TRUE(e[i].winding == 1 || e[i].winding == -1);
        }
    }

    // --- BuildEdges: rejection paths ---
    {
        GdiFillEdge e[16];
        const int sub_start[1] = {0};

        // Capacity too small for the star's five edges.
        EXPECT_EQ(GdiFillBuildEdges(kStarX, kStarY, kStarCount, sub_start, 1, e, 3), -1);

        // A coordinate past the arithmetic-safety limit is rejected.
        const int big_x[3] = {0, GDI_FILL_COORD_LIMIT + 1, 10};
        const int big_y[3] = {0, 10, 20};
        EXPECT_EQ(GdiFillBuildEdges(big_x, big_y, 3, sub_start, 1, e, 16), -1);

        // A two-point subpath encloses no area and is skipped.
        const int seg_x[2] = {0, 10};
        const int seg_y[2] = {0, 10};
        EXPECT_EQ(GdiFillBuildEdges(seg_x, seg_y, 2, sub_start, 1, e, 16), 0);

        // Null / empty inputs are refused rather than dereferenced.
        EXPECT_EQ(GdiFillBuildEdges(nullptr, kSquareY, 4, sub_start, 1, e, 16), 0);
        EXPECT_EQ(GdiFillBuildEdges(kSquareX, kSquareY, 0, sub_start, 1, e, 16), 0);
    }

    // --- Square: exact span geometry (half-open, Win32 convention) ---
    {
        GdiFillEdge work[16];
        SpanBag bag;
        BagInit(&bag);
        const int sub_start[1] = {0};
        const int spans = GdiFillPathSpans(kSquareX, kSquareY, kSquareCount, sub_start, 1, GDI_FILL_ALTERNATE, work, 16,
                                           BagCollect, &bag);
        // One span per scanline for y in [10, 60).
        EXPECT_EQ(spans, 50);
        EXPECT_EQ(bag.count, 50);
        ASSERT_TRUE(bag.count == 50);
        EXPECT_EQ(bag.y[0], 10);
        EXPECT_EQ(bag.y[49], 59);
        for (int i = 0; i < bag.count; ++i)
        {
            EXPECT_EQ(bag.x0[i], 10);
            EXPECT_EQ(bag.x1[i], 60);
        }
        // Corner pixel is in, the pixel past the far edge is out.
        EXPECT_TRUE(BagContains(&bag, 10, 10));
        EXPECT_TRUE(BagContains(&bag, 59, 59));
        EXPECT_FALSE(BagContains(&bag, 60, 30));
        EXPECT_FALSE(BagContains(&bag, 30, 60));
    }

    // --- The star: ALTERNATE and WINDING genuinely differ ---
    {
        GdiFillEdge work[16];
        const int sub_start[1] = {0};

        SpanBag alt;
        BagInit(&alt);
        EXPECT_TRUE(GdiFillPathSpans(kStarX, kStarY, kStarCount, sub_start, 1, GDI_FILL_ALTERNATE, work, 16, BagCollect,
                                     &alt) > 0);

        SpanBag wind;
        BagInit(&wind);
        EXPECT_TRUE(GdiFillPathSpans(kStarX, kStarY, kStarCount, sub_start, 1, GDI_FILL_WINDING, work, 16, BagCollect,
                                     &wind) > 0);

        // Centre of the pentagram: hollow under even-odd, solid under
        // nonzero. This is the whole reason PolyFillMode exists.
        EXPECT_FALSE(BagContains(&alt, 50, 50));
        EXPECT_TRUE(BagContains(&wind, 50, 50));

        // A point inside the upper arm is filled under both rules.
        EXPECT_TRUE(BagContains(&alt, 50, 25));
        EXPECT_TRUE(BagContains(&wind, 50, 25));

        // A point outside the star's outline is filled under neither.
        EXPECT_FALSE(BagContains(&alt, 15, 15));
        EXPECT_FALSE(BagContains(&wind, 15, 15));

        // WINDING is a strict superset here: every ALTERNATE pixel is
        // also a WINDING pixel, and the centre proves it is strict.
        for (int i = 0; i < alt.count; ++i)
        {
            for (int x = alt.x0[i]; x < alt.x1[i]; ++x)
            {
                EXPECT_TRUE(BagContains(&wind, x, alt.y[i]));
            }
        }
    }

    // --- Differential: scan converter vs. independent oracle ---
    {
        EXPECT_EQ(DiffSimple("square", kSquareX, kSquareY, kSquareCount, GDI_FILL_ALTERNATE), 0);
        EXPECT_EQ(DiffSimple("square", kSquareX, kSquareY, kSquareCount, GDI_FILL_WINDING), 0);

        EXPECT_EQ(DiffSimple("triangle", kTriX, kTriY, kTriCount, GDI_FILL_ALTERNATE), 0);
        EXPECT_EQ(DiffSimple("triangle", kTriX, kTriY, kTriCount, GDI_FILL_WINDING), 0);

        EXPECT_EQ(DiffSimple("ell", kElX, kElY, kElCount, GDI_FILL_ALTERNATE), 0);
        EXPECT_EQ(DiffSimple("ell", kElX, kElY, kElCount, GDI_FILL_WINDING), 0);

        EXPECT_EQ(DiffSimple("bowtie", kBowX, kBowY, kBowCount, GDI_FILL_ALTERNATE), 0);
        EXPECT_EQ(DiffSimple("bowtie", kBowX, kBowY, kBowCount, GDI_FILL_WINDING), 0);

        EXPECT_EQ(DiffSimple("star", kStarX, kStarY, kStarCount, GDI_FILL_ALTERNATE), 0);
        EXPECT_EQ(DiffSimple("star", kStarX, kStarY, kStarCount, GDI_FILL_WINDING), 0);
    }

    // --- Multi-subpath: outer square with an inner square ---
    {
        // Inner subpath wound the OPPOSITE way from the outer one: a
        // hole under both rules.
        const int hole_x[8] = {10, 60, 60, 10, /* inner, reversed */ 25, 25, 45, 45};
        const int hole_y[8] = {10, 10, 60, 60, /* inner, reversed */ 25, 45, 45, 25};
        const int hole_sub[2] = {0, 4};

        EXPECT_EQ(DiffAgainstOracle("hole", hole_x, hole_y, 8, hole_sub, 2, GDI_FILL_ALTERNATE), 0);
        EXPECT_EQ(DiffAgainstOracle("hole", hole_x, hole_y, 8, hole_sub, 2, GDI_FILL_WINDING), 0);

        GdiFillEdge work[16];
        SpanBag bag;
        BagInit(&bag);
        EXPECT_TRUE(GdiFillPathSpans(hole_x, hole_y, 8, hole_sub, 2, GDI_FILL_WINDING, work, 16, BagCollect, &bag) > 0);
        EXPECT_FALSE(BagContains(&bag, 35, 35)); // inside the hole
        EXPECT_TRUE(BagContains(&bag, 15, 35));  // in the ring
        // The ring scanlines each emit two spans, so the merge logic
        // must not have glued them across the hole.
        EXPECT_TRUE(bag.count > 50);

        // Same nesting, inner subpath wound the SAME way as the outer:
        // still a hole under ALTERNATE, but solid under WINDING.
        const int same_x[8] = {10, 60, 60, 10, /* inner, same order */ 25, 45, 45, 25};
        const int same_y[8] = {10, 10, 60, 60, /* inner, same order */ 25, 25, 45, 45};

        EXPECT_EQ(DiffAgainstOracle("nest", same_x, same_y, 8, hole_sub, 2, GDI_FILL_ALTERNATE), 0);
        EXPECT_EQ(DiffAgainstOracle("nest", same_x, same_y, 8, hole_sub, 2, GDI_FILL_WINDING), 0);

        SpanBag alt;
        BagInit(&alt);
        EXPECT_TRUE(GdiFillPathSpans(same_x, same_y, 8, hole_sub, 2, GDI_FILL_ALTERNATE, work, 16, BagCollect, &alt) >
                    0);
        EXPECT_FALSE(BagContains(&alt, 35, 35));

        SpanBag wind;
        BagInit(&wind);
        EXPECT_TRUE(GdiFillPathSpans(same_x, same_y, 8, hole_sub, 2, GDI_FILL_WINDING, work, 16, BagCollect, &wind) >
                    0);
        EXPECT_TRUE(BagContains(&wind, 35, 35));
        // Solid: exactly one span per scanline for y in [10, 60).
        EXPECT_EQ(wind.count, 50);
    }

    // --- Empty / degenerate inputs produce no spans ---
    {
        GdiFillEdge work[16];
        SpanBag bag;
        BagInit(&bag);
        const int sub_start[1] = {0};

        // Two-point "path" — nothing to fill.
        const int seg_x[2] = {0, 10};
        const int seg_y[2] = {0, 10};
        EXPECT_EQ(GdiFillPathSpans(seg_x, seg_y, 2, sub_start, 1, GDI_FILL_ALTERNATE, work, 16, BagCollect, &bag), 0);
        EXPECT_EQ(bag.count, 0);

        // A fully horizontal triangle — every edge drops.
        const int flat_x[3] = {0, 10, 20};
        const int flat_y[3] = {5, 5, 5};
        EXPECT_EQ(GdiFillPathSpans(flat_x, flat_y, 3, sub_start, 1, GDI_FILL_ALTERNATE, work, 16, BagCollect, &bag), 0);
        EXPECT_EQ(bag.count, 0);

        // A null sink must not be called.
        EXPECT_EQ(GdiFillPathSpans(kSquareX, kSquareY, kSquareCount, sub_start, 1, GDI_FILL_ALTERNATE, work, 16,
                                   nullptr, nullptr),
                  0);
    }

    // --- Negative coordinates scan correctly (no signed-shift bugs) ---
    {
        const int neg_x[4] = {-30, -10, -10, -30};
        const int neg_y[4] = {-30, -30, -10, -10};
        EXPECT_EQ(DiffSimple("negative", neg_x, neg_y, 4, GDI_FILL_ALTERNATE), 0);
        EXPECT_EQ(DiffSimple("negative", neg_x, neg_y, 4, GDI_FILL_WINDING), 0);

        GdiFillEdge work[16];
        SpanBag bag;
        BagInit(&bag);
        const int sub_start[1] = {0};
        EXPECT_EQ(GdiFillPathSpans(neg_x, neg_y, 4, sub_start, 1, GDI_FILL_ALTERNATE, work, 16, BagCollect, &bag), 20);
        ASSERT_TRUE(bag.count == 20);
        EXPECT_EQ(bag.y[0], -30);
        EXPECT_EQ(bag.x0[0], -30);
        EXPECT_EQ(bag.x1[0], -10);
    }

    // --- Crossing overflow is reported, not silently truncated ---
    {
        // A comb with more teeth than GDI_FILL_MAX_CROSSINGS / 2, so one
        // scanline is crossed by more edges than the scan can track.
        constexpr int kTeeth = 40;
        constexpr int kPts = kTeeth * 2;
        int comb_x[kPts];
        int comb_y[kPts];
        for (int i = 0; i < kTeeth; ++i)
        {
            comb_x[i * 2] = i * 3;
            comb_y[i * 2] = 0;
            comb_x[i * 2 + 1] = i * 3 + 1;
            comb_y[i * 2 + 1] = 20;
        }
        GdiFillEdge work[256];
        SpanBag bag;
        BagInit(&bag);
        const int sub_start[1] = {0};
        EXPECT_EQ(GdiFillPathSpans(comb_x, comb_y, kPts, sub_start, 1, GDI_FILL_ALTERNATE, work, 256, BagCollect, &bag),
                  -1);
    }

    return finish_main("gdi32_fill");
}
