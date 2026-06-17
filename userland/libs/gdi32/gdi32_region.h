/*
 * gdi32_region.h — freestanding rect-list region geometry.
 *
 * Pure integer geometry for GDI HRGN regions, factored out of
 * gdi32.c so it can be exercised by a hosted unit test
 * (tests/host/test_gdi32_region.cpp) without the Win32 syscall /
 * handle-pool plumbing. gdi32.c owns the HRGN pool and the
 * __declspec(dllexport) wrappers; this header owns the math the
 * query/manipulation exports (GetRgnBox, PtInRegion, RectInRegion,
 * OffsetRgn, SetRectRgn, EqualRgn) are built from.
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
