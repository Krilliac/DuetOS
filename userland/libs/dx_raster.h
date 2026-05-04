/*
 * userland/libs/dx_raster.h
 *
 * Header-only software rasterizer shared between the four DirectX
 * DLLs (d3d9, d3d11, d3d12, d3d2d). Sits beside dx_shared.h; each
 * DLL that needs to draw includes both:
 *
 *   #include "../dx_shared.h"
 *   #include "../dx_raster.h"
 *
 * Capabilities (all pure software, all targeting the BGRA8 row-major
 * DxBackBuffer that dx_shared.h owns):
 *
 *   - 2D triangle fill via the Pineda edge-function rasterizer with
 *     the top-left fill rule (matches what D3D11 / D3D12 specify so
 *     adjacent triangles don't double-shade their shared edge).
 *   - 2D line via Bresenham (with stroke-width via plot_stamp).
 *   - 3D vertex transform with a 4x4 row-major matrix, perspective
 *     divide, viewport mapping. No clipping in homogeneous space —
 *     vertices that go behind the near plane (w <= 0) drop the
 *     triangle.
 *   - Solid colour fill (one BGRA per triangle). Per-vertex colour
 *     interpolation (Gouraud) for the cases where the caller hands
 *     us 3 RGBA values.
 *   - 4x4 row-major matrix helpers (identity, multiply, perspective,
 *     orthographic) used by D3D9's SetTransform path and the D3D11
 *     constant-buffer view matrix.
 *
 * Deliberately NOT included:
 *   - Z-buffer (depth write/test). Adds a width*height*4 buffer per
 *     swap chain; v0 doesn't carry it. Triangles paint in submission
 *     order — fine for the single-mesh test apps, broken for any
 *     scene that relies on depth.
 *   - Texture sampling. The shared BGRA8 buffer is the only texture
 *     unit; samplers / SRVs are gated below the v0 cut-line.
 *   - Sub-pixel precision / anti-aliasing. Edge function works in
 *     integer pixel space, top-left rule rounds toward zero — good
 *     enough for the shaded-cube / textured-quad smoke tests.
 *
 * No dynamic allocation. Everything operates on caller-owned memory.
 */

#ifndef DUETOS_DX_RASTER_H
#define DUETOS_DX_RASTER_H

#include "dx_shared.h"

/* ---------------------------------------------------------------- *
 * Pixel write helpers                                              *
 * ---------------------------------------------------------------- */

static DX_NO_BUILTIN inline void dxr_plot(DxBackBuffer* bb, int x, int y, DWORD packed)
{
    if (!bb || !bb->pixels)
        return;
    if (x < 0 || y < 0 || x >= (int)bb->width || y >= (int)bb->height)
        return;
    ((DWORD*)bb->pixels)[y * (int)bb->width + x] = packed;
}

/* Pack a normalised (0..1) RGBA quad into BGRA8 for the back buffer. */
static DX_NO_BUILTIN inline DWORD dxr_pack_rgba(float r, float g, float b, float a)
{
    if (r < 0.f)
        r = 0.f;
    else if (r > 1.f)
        r = 1.f;
    if (g < 0.f)
        g = 0.f;
    else if (g > 1.f)
        g = 1.f;
    if (b < 0.f)
        b = 0.f;
    else if (b > 1.f)
        b = 1.f;
    if (a < 0.f)
        a = 0.f;
    else if (a > 1.f)
        a = 1.f;
    BYTE br = (BYTE)(r * 255.f);
    BYTE bg = (BYTE)(g * 255.f);
    BYTE bb_ = (BYTE)(b * 255.f);
    BYTE ba = (BYTE)(a * 255.f);
    return ((DWORD)ba << 24) | ((DWORD)br << 16) | ((DWORD)bg << 8) | (DWORD)bb_;
}

/* D3DCOLOR (0xAARRGGBB) → BGRA8 packed. Used by D3D9 + DDraw. */
static DX_NO_BUILTIN inline DWORD dxr_pack_d3dcolor(DWORD argb)
{
    BYTE a = (BYTE)((argb >> 24) & 0xFF);
    BYTE r = (BYTE)((argb >> 16) & 0xFF);
    BYTE g = (BYTE)((argb >> 8) & 0xFF);
    BYTE b = (BYTE)(argb & 0xFF);
    return ((DWORD)a << 24) | ((DWORD)r << 16) | ((DWORD)g << 8) | (DWORD)b;
}

/* ---------------------------------------------------------------- *
 * Lines (Bresenham + plot_stamp for stroke width)                  *
 * ---------------------------------------------------------------- */

static DX_NO_BUILTIN inline void dxr_stamp(DxBackBuffer* bb, int x, int y, int hw, DWORD packed)
{
    if (hw <= 0)
    {
        dxr_plot(bb, x, y, packed);
        return;
    }
    for (int dy = -hw; dy <= hw; ++dy)
        for (int dx_ = -hw; dx_ <= hw; ++dx_)
            dxr_plot(bb, x + dx_, y + dy, packed);
}

static DX_NO_BUILTIN inline void dxr_line(DxBackBuffer* bb, int x0, int y0, int x1, int y1, DWORD packed)
{
    int dx_ = x1 - x0, dy_ = y1 - y0;
    int sx = dx_ > 0 ? 1 : -1, sy = dy_ > 0 ? 1 : -1;
    if (dx_ < 0)
        dx_ = -dx_;
    if (dy_ < 0)
        dy_ = -dy_;
    int err = dx_ - dy_;
    int x = x0, y = y0, guard = 0;
    while (1)
    {
        dxr_plot(bb, x, y, packed);
        if (x == x1 && y == y1)
            break;
        if (++guard > 65536)
            break;
        int e2 = 2 * err;
        if (e2 > -dy_)
        {
            err -= dy_;
            x += sx;
        }
        if (e2 < dx_)
        {
            err += dx_;
            y += sy;
        }
    }
}

/* ---------------------------------------------------------------- *
 * Triangle rasterizer (Pineda edge function, top-left rule)        *
 *                                                                  *
 * D3D / OGL fill rule: a pixel is inside a triangle if all three   *
 * edge functions are >= 0 with strict inequality on edges that are *
 * neither top nor left. "Top edge" = horizontal edge above the     *
 * triangle. "Left edge" = goes "down" in screen-space (dy > 0).    *
 * ---------------------------------------------------------------- */

static DX_NO_BUILTIN inline long long dxr_edge(int ax, int ay, int bx, int by, int cx, int cy)
{
    return (long long)(bx - ax) * (long long)(cy - ay) - (long long)(by - ay) * (long long)(cx - ax);
}

/* True if the directed edge (a -> b) is a "top-left" edge under the
 * D3D fill rule. dy = b.y - a.y, dx = b.x - a.x. Top: dy == 0 and
 * dx < 0. Left: dy > 0. */
static DX_NO_BUILTIN inline int dxr_edge_is_top_left(int ax, int ay, int bx, int by)
{
    int dy = by - ay;
    int dx_ = bx - ax;
    if (dy == 0 && dx_ < 0)
        return 1;
    if (dy > 0)
        return 1;
    return 0;
}

/* Solid-color triangle fill into bb. Vertices are integer pixel
 * coords (post-viewport-mapped). Backface culling: a triangle whose
 * signed area is <= 0 in the framebuffer's top-down screen space is
 * dropped — which matches the default D3D cull mode (CCW front-face
 * with the typical camera). Apps that want CW front-faces should
 * swap the order of v1/v2 before calling. */
static DX_NO_BUILTIN inline void dxr_fill_tri(DxBackBuffer* bb, int x0, int y0, int x1, int y1, int x2, int y2,
                                              DWORD packed)
{
    if (!bb || !bb->pixels)
        return;
    /* Bounding box clipped to viewport. */
    int min_x = x0;
    if (x1 < min_x)
        min_x = x1;
    if (x2 < min_x)
        min_x = x2;
    int min_y = y0;
    if (y1 < min_y)
        min_y = y1;
    if (y2 < min_y)
        min_y = y2;
    int max_x = x0;
    if (x1 > max_x)
        max_x = x1;
    if (x2 > max_x)
        max_x = x2;
    int max_y = y0;
    if (y1 > max_y)
        max_y = y1;
    if (y2 > max_y)
        max_y = y2;
    if (min_x < 0)
        min_x = 0;
    if (min_y < 0)
        min_y = 0;
    if (max_x >= (int)bb->width)
        max_x = (int)bb->width - 1;
    if (max_y >= (int)bb->height)
        max_y = (int)bb->height - 1;
    if (min_x > max_x || min_y > max_y)
        return;

    /* Signed area of the triangle. <= 0 means back-facing or
     * degenerate; cull either way. */
    long long area = dxr_edge(x0, y0, x1, y1, x2, y2);
    if (area <= 0)
        return;

    /* Top-left fill bias: subtract 1 from the edge function on edges
     * that are neither top nor left, so the strict inequality "edge >
     * 0" matches D3D's spec without ever double-shading. */
    int bias0 = dxr_edge_is_top_left(x1, y1, x2, y2) ? 0 : -1;
    int bias1 = dxr_edge_is_top_left(x2, y2, x0, y0) ? 0 : -1;
    int bias2 = dxr_edge_is_top_left(x0, y0, x1, y1) ? 0 : -1;

    DWORD* px = (DWORD*)bb->pixels;
    UINT pitch = bb->width;

    for (int y = min_y; y <= max_y; ++y)
    {
        for (int x = min_x; x <= max_x; ++x)
        {
            long long w0 = dxr_edge(x1, y1, x2, y2, x, y) + bias0;
            long long w1 = dxr_edge(x2, y2, x0, y0, x, y) + bias1;
            long long w2 = dxr_edge(x0, y0, x1, y1, x, y) + bias2;
            if (w0 >= 0 && w1 >= 0 && w2 >= 0)
                px[y * pitch + x] = packed;
        }
    }
}

/* Gouraud-shaded triangle: per-vertex BGRA colours interpolated
 * across the triangle via barycentric weights. Same fill rule as
 * dxr_fill_tri. */
static DX_NO_BUILTIN inline void dxr_shade_tri(DxBackBuffer* bb, int x0, int y0, int x1, int y1, int x2, int y2,
                                               DWORD c0, DWORD c1, DWORD c2)
{
    if (!bb || !bb->pixels)
        return;
    int min_x = x0;
    if (x1 < min_x)
        min_x = x1;
    if (x2 < min_x)
        min_x = x2;
    int min_y = y0;
    if (y1 < min_y)
        min_y = y1;
    if (y2 < min_y)
        min_y = y2;
    int max_x = x0;
    if (x1 > max_x)
        max_x = x1;
    if (x2 > max_x)
        max_x = x2;
    int max_y = y0;
    if (y1 > max_y)
        max_y = y1;
    if (y2 > max_y)
        max_y = y2;
    if (min_x < 0)
        min_x = 0;
    if (min_y < 0)
        min_y = 0;
    if (max_x >= (int)bb->width)
        max_x = (int)bb->width - 1;
    if (max_y >= (int)bb->height)
        max_y = (int)bb->height - 1;
    if (min_x > max_x || min_y > max_y)
        return;

    long long area = dxr_edge(x0, y0, x1, y1, x2, y2);
    if (area <= 0)
        return;

    int bias0 = dxr_edge_is_top_left(x1, y1, x2, y2) ? 0 : -1;
    int bias1 = dxr_edge_is_top_left(x2, y2, x0, y0) ? 0 : -1;
    int bias2 = dxr_edge_is_top_left(x0, y0, x1, y1) ? 0 : -1;

    DWORD* px = (DWORD*)bb->pixels;
    UINT pitch = bb->width;

    BYTE a0 = (BYTE)((c0 >> 24) & 0xFF), r0 = (BYTE)((c0 >> 16) & 0xFF);
    BYTE g0 = (BYTE)((c0 >> 8) & 0xFF), b0 = (BYTE)(c0 & 0xFF);
    BYTE a1 = (BYTE)((c1 >> 24) & 0xFF), r1 = (BYTE)((c1 >> 16) & 0xFF);
    BYTE g1 = (BYTE)((c1 >> 8) & 0xFF), b1 = (BYTE)(c1 & 0xFF);
    BYTE a2 = (BYTE)((c2 >> 24) & 0xFF), r2 = (BYTE)((c2 >> 16) & 0xFF);
    BYTE g2 = (BYTE)((c2 >> 8) & 0xFF), b2 = (BYTE)(c2 & 0xFF);

    for (int y = min_y; y <= max_y; ++y)
    {
        for (int x = min_x; x <= max_x; ++x)
        {
            long long w0 = dxr_edge(x1, y1, x2, y2, x, y) + bias0;
            long long w1 = dxr_edge(x2, y2, x0, y0, x, y) + bias1;
            long long w2 = dxr_edge(x0, y0, x1, y1, x, y) + bias2;
            if (w0 < 0 || w1 < 0 || w2 < 0)
                continue;
            /* Normalise to [0, 1] in fixed point — cancel the area. */
            long long inv = area;
            long long rr = (w0 * r0 + w1 * r1 + w2 * r2) / inv;
            long long gg = (w0 * g0 + w1 * g1 + w2 * g2) / inv;
            long long bb_ = (w0 * b0 + w1 * b1 + w2 * b2) / inv;
            long long aa = (w0 * a0 + w1 * a1 + w2 * a2) / inv;
            DWORD packed =
                ((DWORD)(BYTE)aa << 24) | ((DWORD)(BYTE)rr << 16) | ((DWORD)(BYTE)gg << 8) | (DWORD)(BYTE)bb_;
            px[y * pitch + x] = packed;
        }
    }
}

/* ---------------------------------------------------------------- *
 * 4x4 matrix math (row-major, D3D convention)                      *
 *                                                                  *
 * D3D row-major: position is a row vector, transformed by post-    *
 * multiplication: out = in * M. M[row][col] addressed as m[row*4+col].*
 * ---------------------------------------------------------------- */

typedef struct DxMat4
{
    float m[16];
} DxMat4;

typedef struct DxVec4
{
    float x, y, z, w;
} DxVec4;

static DX_NO_BUILTIN inline DxMat4 dxr_mat_identity(void)
{
    DxMat4 r;
    for (int i = 0; i < 16; ++i)
        r.m[i] = 0.f;
    r.m[0] = r.m[5] = r.m[10] = r.m[15] = 1.f;
    return r;
}

static DX_NO_BUILTIN inline DxMat4 dxr_mat_mul(const DxMat4* a, const DxMat4* b)
{
    DxMat4 r;
    for (int i = 0; i < 4; ++i)
    {
        for (int j = 0; j < 4; ++j)
        {
            float s = 0.f;
            for (int k = 0; k < 4; ++k)
                s += a->m[i * 4 + k] * b->m[k * 4 + j];
            r.m[i * 4 + j] = s;
        }
    }
    return r;
}

static DX_NO_BUILTIN inline DxVec4 dxr_vec_mul_mat(const DxVec4* v, const DxMat4* m)
{
    DxVec4 r;
    r.x = v->x * m->m[0] + v->y * m->m[4] + v->z * m->m[8] + v->w * m->m[12];
    r.y = v->x * m->m[1] + v->y * m->m[5] + v->z * m->m[9] + v->w * m->m[13];
    r.z = v->x * m->m[2] + v->y * m->m[6] + v->z * m->m[10] + v->w * m->m[14];
    r.w = v->x * m->m[3] + v->y * m->m[7] + v->z * m->m[11] + v->w * m->m[15];
    return r;
}

/* Apply perspective divide + viewport mapping. Returns 0 if the
 * vertex is behind the near plane (w <= 0); the caller drops the
 * triangle. NDC is [-1, 1] in x/y; viewport maps that to the back
 * buffer's pixel grid (top-down screen space — y is flipped). */
static DX_NO_BUILTIN inline int dxr_project(const DxVec4* clip, int vp_x, int vp_y, int vp_w, int vp_h, int* out_x,
                                            int* out_y)
{
    if (clip->w <= 0.0001f && clip->w >= -0.0001f)
        return 0;
    float inv_w = 1.0f / clip->w;
    float ndc_x = clip->x * inv_w;
    float ndc_y = clip->y * inv_w;
    if (out_x)
        *out_x = vp_x + (int)((ndc_x * 0.5f + 0.5f) * (float)vp_w);
    if (out_y)
        *out_y = vp_y + (int)((1.0f - (ndc_y * 0.5f + 0.5f)) * (float)vp_h);
    return 1;
}

/* ---------------------------------------------------------------- *
 * Common vertex-input shapes                                       *
 *                                                                  *
 * D3D9 FVF / D3D11 input layouts come in many flavours. The two we *
 * cover are the ones every test app uses:                          *
 *   - position only (3 floats)                                     *
 *   - position + colour (3 floats + 4 floats RGBA)                 *
 *   - position + D3DCOLOR (3 floats + 1 DWORD ARGB)                *
 * dxr_read_pos_xyz reads 3 floats from a stride-bytes-apart array. *
 * ---------------------------------------------------------------- */

static DX_NO_BUILTIN inline void dxr_read_pos_xyz(const void* buf, UINT stride, UINT idx, float* out_xyz)
{
    const BYTE* p = (const BYTE*)buf + (SIZE_T)idx * stride;
    dx_memcpy(out_xyz, p, 12);
}

static DX_NO_BUILTIN inline DWORD dxr_read_color_d3d(const void* buf, UINT stride, UINT idx, UINT colour_offset)
{
    const BYTE* p = (const BYTE*)buf + (SIZE_T)idx * stride + colour_offset;
    DWORD argb;
    dx_memcpy(&argb, p, 4);
    return dxr_pack_d3dcolor(argb);
}

static DX_NO_BUILTIN inline DWORD dxr_read_color_rgba_f(const void* buf, UINT stride, UINT idx, UINT colour_offset)
{
    const BYTE* p = (const BYTE*)buf + (SIZE_T)idx * stride + colour_offset;
    float c[4];
    dx_memcpy(c, p, 16);
    return dxr_pack_rgba(c[0], c[1], c[2], c[3]);
}

#endif /* DUETOS_DX_RASTER_H */
