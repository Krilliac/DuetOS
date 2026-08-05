/*
 * gdi32_region.h — freestanding rect-list region geometry.
 *
 * Pure integer geometry for GDI HRGN regions, factored out of
 * gdi32.c so it can be exercised by a hosted unit test
 * (tests/host/test_gdi32_region.cpp) without the Win32 syscall /
 * handle-pool plumbing. gdi32.c owns the HRGN pool and the
 * __declspec(dllexport) wrappers; this header owns the math the
 * query/manipulation exports (GetRgnBox, PtInRegion, RectInRegion,
 * OffsetRgn, SetRectRgn, EqualRgn) are built from, plus the exact
 * combine ops (intersect / subtract / union / xor) behind
 * CombineRgn and the DC clip engine.
 *
 * Region model: a region is a list of `count` rectangles. A
 * single-rect region is exact; multi-rect regions (CombineRgn) are
 * whatever gdi32.c stored. Every predicate below is consistent with
 * that stored rect list — point/rect containment scans the list, so
 * the answer is exact for the single-rect case real apps hit most.
 *
 * Coordinate convention matches Win32: rectangles are half-open —
 * a rect covers x in [left, right) and y in [top, bottom). A rect
 * with right<=left or bottom<=top is empty.
 *
 * Freestanding: no includes, plain `int`, all `static inline`.
 */
#pragma once

typedef struct
{
    int left;
    int top;
    int right;
    int bottom;
} GdiRgnRect;

/* Normalize so left<=right and top<=bottom (GDI accepts inverted
 * rects and normalizes them). Returns 1 if the result encloses a
 * non-empty area, 0 if degenerate (zero width or height). */
static inline int GdiRgnNormRect(GdiRgnRect* r)
{
    if (r->right < r->left)
    {
        int t = r->left;
        r->left = r->right;
        r->right = t;
    }
    if (r->bottom < r->top)
    {
        int t = r->top;
        r->top = r->bottom;
        r->bottom = t;
    }
    return (r->right > r->left && r->bottom > r->top) ? 1 : 0;
}

/* Union bounding box of `count` rects into *out. Returns 1 if the
 * region is non-empty (count>0), 0 otherwise (out set to an empty
 * {0,0,0,0} box, matching GetRgnBox on a NULLREGION). */
static inline int GdiRgnBBox(const GdiRgnRect* rects, int count, GdiRgnRect* out)
{
    if (count <= 0)
    {
        out->left = out->top = out->right = out->bottom = 0;
        return 0;
    }
    *out = rects[0];
    for (int i = 1; i < count; ++i)
    {
        if (rects[i].left < out->left)
            out->left = rects[i].left;
        if (rects[i].top < out->top)
            out->top = rects[i].top;
        if (rects[i].right > out->right)
            out->right = rects[i].right;
        if (rects[i].bottom > out->bottom)
            out->bottom = rects[i].bottom;
    }
    return 1;
}

/* 1 if point (x,y) lies inside any rect (half-open bounds). */
static inline int GdiRgnPtIn(const GdiRgnRect* rects, int count, int x, int y)
{
    for (int i = 0; i < count; ++i)
        if (x >= rects[i].left && x < rects[i].right && y >= rects[i].top && y < rects[i].bottom)
            return 1;
    return 0;
}

/* 1 if `q` has a non-empty intersection with any rect in the region.
 * `q` is treated half-open and is NOT required to be normalized by
 * the caller — callers that take a user RECT should normalize first. */
static inline int GdiRgnRectIn(const GdiRgnRect* rects, int count, const GdiRgnRect* q)
{
    for (int i = 0; i < count; ++i)
    {
        const int l = q->left > rects[i].left ? q->left : rects[i].left;
        const int t = q->top > rects[i].top ? q->top : rects[i].top;
        const int r = q->right < rects[i].right ? q->right : rects[i].right;
        const int b = q->bottom < rects[i].bottom ? q->bottom : rects[i].bottom;
        if (r > l && b > t)
            return 1;
    }
    return 0;
}

/* Translate every rect by (dx,dy). */
static inline void GdiRgnOffset(GdiRgnRect* rects, int count, int dx, int dy)
{
    for (int i = 0; i < count; ++i)
    {
        rects[i].left += dx;
        rects[i].right += dx;
        rects[i].top += dy;
        rects[i].bottom += dy;
    }
}

/* Integer square-root (floor). Used by the ellipse scan-line
 * decomposition -- no floating point in this freestanding header. */
static inline int GdiRgnISqrt(long long v)
{
    if (v <= 0)
        return 0;
    long long r = 0;
    long long bit = 1LL << 30;
    while (bit > v)
        bit >>= 2;
    /* Binary-search accumulation: candidate bits must descend by
     * powers of TWO for the `t*t <= v` acceptance test to be sound
     * (the classic power-of-4 remainder algorithm has a different
     * acceptance test). The pre-narrowing above only picks a starting
     * point; bit > v/4 >= isqrt(v) holds for all v > 0. */
    while (bit > 0)
    {
        long long t = r + bit;
        if (t * t <= v)
            r = t;
        bit >>= 1;
    }
    return (int)r;
}

/* Decompose an axis-aligned ellipse (given by its bounding rect
 * [left, right) x [top, bottom)) into horizontal scan-line
 * rectangles, writing at most `max_rects` entries into `out`.
 *
 * When the ellipse height exceeds `max_rects` the vertical span is
 * split into `max_rects` equal-height bands; each band uses the
 * x-extent at the INNER (narrowest) scanline to stay inside the
 * ellipse. Returns the number of rects written (0 for empty). */
static inline int GdiRgnEllipseRects(int left, int top, int right, int bottom, GdiRgnRect* out, int max_rects)
{
    if (right < left)
    {
        int t = left;
        left = right;
        right = t;
    }
    if (bottom < top)
    {
        int t = top;
        top = bottom;
        bottom = t;
    }
    int w = right - left;
    int h = bottom - top;
    if (w <= 0 || h <= 0 || max_rects <= 0)
        return 0;

    /* Work in doubled coordinates so the centre is at integer
     * position (cx2, cy2) without half-pixel rounding. Semi-axes
     * in doubled coords: a2 = w, b2 = h. Ellipse equation in 2x:
     *   (2x+1 - cx2)^2 / a2^2 + (2y+1 - cy2)^2 / b2^2 <= 1
     * x-extent at scanline y: solve for x. */
    int cx2 = left + right; /* 2 * centre_x */
    int cy2 = top + bottom; /* 2 * centre_y */
    long long a2 = (long long)w;
    long long b2 = (long long)h;
    long long b2sq = b2 * b2;

    int bands = h < max_rects ? h : max_rects;
    int written = 0;

    for (int i = 0; i < bands; ++i)
    {
        int y0 = top + (i * h) / bands;
        int y1 = top + ((i + 1) * h) / bands;
        if (y1 <= y0)
            continue;

        /* Pick the scanline in this band farthest from the centre
         * (narrowest x-extent) so the rect stays inside the ellipse. */
        long long dy_top2 = (long long)(2 * y0 + 1 - cy2);
        long long dy_bot2 = (long long)(2 * (y1 - 1) + 1 - cy2);
        long long adt = dy_top2 * dy_top2;
        long long adb = dy_bot2 * dy_bot2;
        long long dy2 = adt > adb ? adt : adb;

        long long num = a2 * a2 * (b2sq - dy2);
        if (num <= 0)
            continue;
        int half_w2 = GdiRgnISqrt(num / b2sq);
        int xl = (cx2 - half_w2) / 2;
        int xr = (cx2 + half_w2 + 1) / 2;
        if (xl < left)
            xl = left;
        if (xr > right)
            xr = right;
        if (xr <= xl)
            continue;

        out[written].left = xl;
        out[written].top = y0;
        out[written].right = xr;
        out[written].bottom = y1;
        ++written;
    }
    return written;
}

/* --- Combine ops (exact rect-list set algebra) -------------------
 *
 * All lists are assumed to hold pairwise-disjoint, normalized,
 * non-empty rects (the invariant every producer in this header and
 * in gdi32.c maintains). Every operation preserves that invariant:
 * intersection of disjoint lists is disjoint; subtraction only
 * shrinks; union is computed as a + (b \ a).
 *
 * Overflow contract: each op returns -1 when the exact result does
 * not fit the caller's `cap` (or an internal work list would exceed
 * GDI_RGN_WORK_CAP). Callers fall back to their bounding-box
 * approximation on -1 rather than silently dropping area. */
#define GDI_RGN_WORK_CAP 32

/* Subtract rect `s` from rect `r` (both normalized, non-empty,
 * half-open). Writes the up-to-4 disjoint surviving pieces of `r`
 * into `out` (top band, bottom band, middle-left, middle-right).
 * Returns the piece count: 0 when `s` covers `r`, 1 (== *r) when
 * they do not overlap. */
static inline int GdiRgnSubtractRect(const GdiRgnRect* r, const GdiRgnRect* s, GdiRgnRect* out)
{
    if (s->right <= r->left || s->left >= r->right || s->bottom <= r->top || s->top >= r->bottom)
    {
        out[0] = *r;
        return 1;
    }
    int n = 0;
    const int midTop = s->top > r->top ? s->top : r->top;
    const int midBot = s->bottom < r->bottom ? s->bottom : r->bottom;
    if (s->top > r->top)
    {
        out[n].left = r->left;
        out[n].top = r->top;
        out[n].right = r->right;
        out[n].bottom = s->top;
        ++n;
    }
    if (s->bottom < r->bottom)
    {
        out[n].left = r->left;
        out[n].top = s->bottom;
        out[n].right = r->right;
        out[n].bottom = r->bottom;
        ++n;
    }
    if (s->left > r->left)
    {
        out[n].left = r->left;
        out[n].top = midTop;
        out[n].right = s->left;
        out[n].bottom = midBot;
        ++n;
    }
    if (s->right < r->right)
    {
        out[n].left = s->right;
        out[n].top = midTop;
        out[n].right = r->right;
        out[n].bottom = midBot;
        ++n;
    }
    return n;
}

/* Pairwise intersection of two disjoint rect lists. Returns the
 * count written to `out`, or -1 if a non-empty piece would exceed
 * `cap`. */
static inline int GdiRgnIntersect(const GdiRgnRect* a, int an, const GdiRgnRect* b, int bn, GdiRgnRect* out, int cap)
{
    int n = 0;
    for (int i = 0; i < an; ++i)
    {
        for (int j = 0; j < bn; ++j)
        {
            const int l = a[i].left > b[j].left ? a[i].left : b[j].left;
            const int t = a[i].top > b[j].top ? a[i].top : b[j].top;
            const int r = a[i].right < b[j].right ? a[i].right : b[j].right;
            const int bo = a[i].bottom < b[j].bottom ? a[i].bottom : b[j].bottom;
            if (r > l && bo > t)
            {
                if (n >= cap)
                    return -1;
                out[n].left = l;
                out[n].top = t;
                out[n].right = r;
                out[n].bottom = bo;
                ++n;
            }
        }
    }
    return n;
}

/* List subtraction a \ b. Iteratively carves every rect of `b` out
 * of a working copy of `a`. Returns the count written to `out`, or
 * -1 on overflow of `cap` or the internal work lists. */
static inline int GdiRgnSubtract(const GdiRgnRect* a, int an, const GdiRgnRect* b, int bn, GdiRgnRect* out, int cap)
{
    GdiRgnRect cur[GDI_RGN_WORK_CAP];
    GdiRgnRect next[GDI_RGN_WORK_CAP];
    if (an > GDI_RGN_WORK_CAP)
        return -1;
    int cn = an;
    for (int i = 0; i < an; ++i)
        cur[i] = a[i];
    for (int j = 0; j < bn; ++j)
    {
        int nn = 0;
        for (int i = 0; i < cn; ++i)
        {
            GdiRgnRect pieces[4];
            const int pc = GdiRgnSubtractRect(&cur[i], &b[j], pieces);
            for (int k = 0; k < pc; ++k)
            {
                if (nn >= GDI_RGN_WORK_CAP)
                    return -1;
                next[nn] = pieces[k];
                ++nn;
            }
        }
        for (int i = 0; i < nn; ++i)
            cur[i] = next[i];
        cn = nn;
    }
    if (cn > cap)
        return -1;
    for (int i = 0; i < cn; ++i)
        out[i] = cur[i];
    return cn;
}

/* Disjoint union: a followed by (b \ a). Returns the count written
 * to `out`, or -1 on overflow. `out` must not alias `a` or `b`. */
static inline int GdiRgnUnion(const GdiRgnRect* a, int an, const GdiRgnRect* b, int bn, GdiRgnRect* out, int cap)
{
    GdiRgnRect extra[GDI_RGN_WORK_CAP];
    const int en = GdiRgnSubtract(b, bn, a, an, extra, GDI_RGN_WORK_CAP);
    if (en < 0 || an + en > cap)
        return -1;
    for (int i = 0; i < an; ++i)
        out[i] = a[i];
    for (int i = 0; i < en; ++i)
        out[an + i] = extra[i];
    return an + en;
}

/* Symmetric difference: (a \ b) followed by (b \ a). Returns the
 * count written to `out`, or -1 on overflow. `out` must not alias
 * `a` or `b`. */
static inline int GdiRgnXor(const GdiRgnRect* a, int an, const GdiRgnRect* b, int bn, GdiRgnRect* out, int cap)
{
    GdiRgnRect ab[GDI_RGN_WORK_CAP];
    GdiRgnRect ba[GDI_RGN_WORK_CAP];
    const int nab = GdiRgnSubtract(a, an, b, bn, ab, GDI_RGN_WORK_CAP);
    const int nba = GdiRgnSubtract(b, bn, a, an, ba, GDI_RGN_WORK_CAP);
    if (nab < 0 || nba < 0 || nab + nba > cap)
        return -1;
    for (int i = 0; i < nab; ++i)
        out[i] = ab[i];
    for (int i = 0; i < nba; ++i)
        out[nab + i] = ba[i];
    return nab + nba;
}

/* 1 if the two rect lists are identical (same count, same rects in
 * the same order). gdi32 stores single-rect and bounding-box regions
 * in a canonical order, so order-sensitive comparison is correct for
 * the cases this v0 produces; EqualRgn on two independently-built
 * complex regions with differently-ordered (but set-equal) rect lists
 * is the documented GAP. */
static inline int GdiRgnEqual(const GdiRgnRect* a, int an, const GdiRgnRect* b, int bn)
{
    if (an != bn)
        return 0;
    for (int i = 0; i < an; ++i)
        if (a[i].left != b[i].left || a[i].top != b[i].top || a[i].right != b[i].right || a[i].bottom != b[i].bottom)
            return 0;
    return 1;
}
