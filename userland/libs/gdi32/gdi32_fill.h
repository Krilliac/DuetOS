/*
 * gdi32_fill.h — freestanding scanline polygon-fill geometry.
 *
 * Pure integer geometry factored out of gdi32.c so it can be
 * exercised by a hosted unit test (tests/host/test_gdi32_fill.cpp)
 * without the Win32 syscall / handle-pool plumbing — the same split
 * gdi32_region.h uses for the HRGN math. gdi32.c owns the path pool
 * and the __declspec(dllexport) wrappers; this header owns the math
 * behind FillPath and StrokeAndFillPath.
 *
 * Path model: a flat point list plus per-subpath start indices (what
 * the GdiPath recorder in gdi32.c stores). Filling implicitly closes
 * every subpath, as Win32's FillPath specifies. Every closed subpath
 * contributes its edges to ONE shared edge list and the whole path
 * fills as a single figure — so overlapping subpaths interact through
 * the fill rule rather than each filling independently.
 *
 * Fill rules, selected by the DC's polygon fill mode:
 *   ALTERNATE (1) — even-odd. A pixel is inside when a ray from it
 *       crosses an odd number of edges.
 *   WINDING (2) — nonzero. A pixel is inside when the signed sum of
 *       crossings (+1 for an edge running downward, -1 for one
 *       running upward) is not zero.
 * A five-pointed star drawn as one self-intersecting loop is the
 * canonical case where they differ: the central pentagon is hollow
 * under ALTERNATE and solid under WINDING.
 *
 * Sampling: scanline y samples the pixel centre at y + 0.5, and an
 * edge covers scanline y when ytop <= y < ybot. That half-open rule
 * counts a vertex shared by two edges exactly once, so no spurious
 * crossing appears at a vertex. Horizontal edges contribute nothing
 * and are dropped while the edge list is built.
 *
 * Arithmetic: crossings are computed exactly in 64-bit integer
 * rational arithmetic and rounded to the first pixel whose centre
 * lies at or after the crossing. No floating point anywhere.
 *
 * Freestanding: no includes, plain int / long long, all static
 * inline.
 */
#pragma once

/* Polygon fill modes — the Win32 ALTERNATE / WINDING values that
 * SetPolyFillMode accepts. */
#define GDI_FILL_ALTERNATE 1
#define GDI_FILL_WINDING 2

/* Maximum edge crossings tracked on one scanline. A path capped at
 * GDI_PATH_MAX_PTS points can in principle cross a scanline more
 * often than this; GdiFillScan reports the overflow rather than
 * truncating silently.
 * GAP: a path whose single scanline is crossed by more than
 * GDI_FILL_MAX_CROSSINGS edges fails the fill instead of filling
 * partially. Raise the cap if a real PE drives a denser path. */
#define GDI_FILL_MAX_CROSSINGS 64

/* Coordinate magnitude the crossing arithmetic is proven safe for.
 * The widest intermediate is 2 * (xtop * 2 * dy + dx * 2 * dy), which
 * for |coord| <= 2^20 stays under 2^45 — comfortably inside 64 bits.
 * Any larger coordinate is rejected at edge-build time rather than
 * silently overflowing. 2^20 is ~16x the widest plausible display. */
#define GDI_FILL_COORD_LIMIT (1 << 20)

/* One non-horizontal edge, normalized so ytop < ybot. `winding`
 * records the direction the edge was authored in (+1 downward, -1
 * upward) — the nonzero rule needs it, the even-odd rule ignores it. */
typedef struct
{
    int ytop;    /* first scanline covered (inclusive) */
    int ybot;    /* one past the last scanline covered; ybot > ytop */
    int xtop;    /* x at y == ytop */
    int xbot;    /* x at y == ybot */
    int winding; /* +1 if authored top-to-bottom, -1 if bottom-to-top */
} GdiFillEdge;

/* Span sink. Called once per maximal run of inside pixels, in
 * increasing y then increasing x. The run covers x in [x0, x1). */
typedef void (*GdiFillSpanFn)(void* ctx, int y, int x0, int x1);

/* ceil(a / b) for b > 0, without floating point. C division truncates
 * toward zero, so the remainder carries the sign of `a`: a positive
 * remainder means the quotient was rounded down and needs a bump; a
 * negative one means it was already rounded up. */
static inline long long GdiFillCeilDiv(long long a, long long b)
{
    const long long q = a / b;
    const long long r = a - q * b;
    return (r > 0) ? q + 1 : q;
}

/* Build the edge list for a whole path.
 *
 * `xs` / `ys` are the flat point arrays, `pt_count` their length.
 * `sub_start[s]` is the index of subpath s's first point; subpath s
 * runs to sub_start[s + 1] (or pt_count for the last one). Every
 * subpath is closed implicitly.
 *
 * Returns the number of edges written to `out`, or -1 if the path
 * needs more than `cap` edges or carries a coordinate outside
 * +/-GDI_FILL_COORD_LIMIT. Subpaths with fewer than 3 points enclose
 * no area and are skipped. */
static inline int GdiFillBuildEdges(const int* xs, const int* ys, int pt_count, const int* sub_start, int sub_count,
                                    GdiFillEdge* out, int cap)
{
    if (!xs || !ys || !sub_start || !out || pt_count <= 0 || sub_count <= 0 || cap <= 0)
        return 0;

    int n = 0;
    for (int s = 0; s < sub_count; ++s)
    {
        const int start = sub_start[s];
        const int end = (s + 1 < sub_count) ? sub_start[s + 1] : pt_count;
        if (start < 0 || end > pt_count || end - start < 3)
            continue; /* degenerate subpath — encloses no area */

        for (int i = start; i < end; ++i)
        {
            const int j = (i + 1 < end) ? i + 1 : start; /* closing edge wraps */
            const int xi = xs[i];
            const int yi = ys[i];
            const int xj = xs[j];
            const int yj = ys[j];

            if (xi > GDI_FILL_COORD_LIMIT || xi < -GDI_FILL_COORD_LIMIT || yi > GDI_FILL_COORD_LIMIT ||
                yi < -GDI_FILL_COORD_LIMIT)
                return -1;

            if (yi == yj)
                continue; /* horizontal — contributes no crossing */
            if (n >= cap)
                return -1;

            if (yi < yj)
            {
                out[n].ytop = yi;
                out[n].ybot = yj;
                out[n].xtop = xi;
                out[n].xbot = xj;
                out[n].winding = 1;
            }
            else
            {
                out[n].ytop = yj;
                out[n].ybot = yi;
                out[n].xtop = xj;
                out[n].xbot = xi;
                out[n].winding = -1;
            }
            ++n;
        }
    }
    return n;
}

/* Vertical extent of an edge list: [*ymin, *ymax) in scanlines.
 * Returns 1 if the list is non-empty, 0 otherwise. */
static inline int GdiFillEdgeBounds(const GdiFillEdge* edges, int ecount, int* ymin, int* ymax)
{
    if (!edges || ecount <= 0 || !ymin || !ymax)
        return 0;
    *ymin = edges[0].ytop;
    *ymax = edges[0].ybot;
    for (int i = 1; i < ecount; ++i)
    {
        if (edges[i].ytop < *ymin)
            *ymin = edges[i].ytop;
        if (edges[i].ybot > *ymax)
            *ymax = edges[i].ybot;
    }
    return 1;
}

/* First pixel whose centre lies at or after where `e` crosses the
 * centre of scanline `y`. Caller must have checked ytop <= y < ybot.
 *
 * The crossing sits at x = xtop + dx * (y + 0.5 - ytop) / dy, i.e.
 * the rational xnum/den with den = 2*dy. The wanted pixel is the
 * smallest px with px + 0.5 >= xnum/den, which rearranges to
 * px >= (2*xnum - den) / (2*den). */
static inline int GdiFillCrossPixel(const GdiFillEdge* e, int y)
{
    const long long dy = (long long)e->ybot - (long long)e->ytop;
    const long long dx = (long long)e->xbot - (long long)e->xtop;
    const long long den = 2 * dy;
    const long long tnum = 2 * ((long long)y - (long long)e->ytop) + 1;
    const long long xnum = (long long)e->xtop * den + dx * tnum;
    return (int)GdiFillCeilDiv(2 * xnum - den, 2 * den);
}

/* Scan-convert an edge list into horizontal spans.
 *
 * `mode` is GDI_FILL_ALTERNATE or GDI_FILL_WINDING; anything else is
 * treated as ALTERNATE (matching SetPolyFillMode's default). Spans
 * come out in increasing y, then increasing x, already merged so
 * touching or overlapping runs on one scanline arrive as one call.
 *
 * Returns the number of spans emitted, or -1 if some scanline was
 * crossed by more than GDI_FILL_MAX_CROSSINGS edges. */
static inline int GdiFillScan(const GdiFillEdge* edges, int ecount, int mode, GdiFillSpanFn emit, void* ctx)
{
    int ymin = 0;
    int ymax = 0;
    if (!emit || !GdiFillEdgeBounds(edges, ecount, &ymin, &ymax))
        return 0;

    const int nonzero = (mode == GDI_FILL_WINDING);
    int spans = 0;

    for (int y = ymin; y < ymax; ++y)
    {
        int cross_x[GDI_FILL_MAX_CROSSINGS];
        int cross_w[GDI_FILL_MAX_CROSSINGS];
        int n = 0;

        for (int e = 0; e < ecount; ++e)
        {
            if (y < edges[e].ytop || y >= edges[e].ybot)
                continue;
            if (n >= GDI_FILL_MAX_CROSSINGS)
                return -1;
            cross_x[n] = GdiFillCrossPixel(&edges[e], y);
            cross_w[n] = edges[e].winding;
            ++n;
        }
        if (n < 2)
            continue;

        /* Insertion sort by crossing x, carrying the winding with it.
         * n is bounded by GDI_FILL_MAX_CROSSINGS, so quadratic is
         * cheaper than any structure with a setup cost. */
        for (int i = 1; i < n; ++i)
        {
            const int kx = cross_x[i];
            const int kw = cross_w[i];
            int j = i - 1;
            while (j >= 0 && cross_x[j] > kx)
            {
                cross_x[j + 1] = cross_x[j];
                cross_w[j + 1] = cross_w[j];
                --j;
            }
            cross_x[j + 1] = kx;
            cross_w[j + 1] = kw;
        }

        /* Walk the sorted crossings. `acc` is the parity (even-odd) or
         * the signed winding count for the interval that STARTS at
         * crossing i, so it updates before the interval is tested. */
        int acc = 0;
        int have = 0;
        int sx0 = 0;
        int sx1 = 0;
        for (int i = 0; i + 1 < n; ++i)
        {
            acc = nonzero ? acc + cross_w[i] : (acc ^ 1);
            if (acc == 0)
                continue; /* interval [i, i+1) is outside */

            const int a = cross_x[i];
            const int b = cross_x[i + 1];
            if (b <= a)
                continue; /* sliver thinner than a pixel centre */

            if (have && a <= sx1)
            {
                if (b > sx1)
                    sx1 = b; /* merge with the run in progress */
            }
            else
            {
                if (have)
                {
                    emit(ctx, y, sx0, sx1);
                    ++spans;
                }
                sx0 = a;
                sx1 = b;
                have = 1;
            }
        }
        if (have)
        {
            emit(ctx, y, sx0, sx1);
            ++spans;
        }
    }
    return spans;
}

/* Convenience wrapper: build the edge list into caller-supplied
 * scratch and scan it in one call. Returns GdiFillScan's result, or
 * -1 if the edge list could not be built. */
static inline int GdiFillPathSpans(const int* xs, const int* ys, int pt_count, const int* sub_start, int sub_count,
                                   int mode, GdiFillEdge* work, int work_cap, GdiFillSpanFn emit, void* ctx)
{
    const int ecount = GdiFillBuildEdges(xs, ys, pt_count, sub_start, sub_count, work, work_cap);
    if (ecount < 0)
        return -1;
    if (ecount == 0)
        return 0;
    return GdiFillScan(work, ecount, mode, emit, ctx);
}
