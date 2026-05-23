#include "subsystems/graphics/graphics_vk_internal.h"
#include "subsystems/graphics/graphics_vk_spirv.h"

#include "drivers/video/framebuffer.h"
#include "util/soft_float.h"

/*
 * DuetOS — SPIR-V shader-based rasterizer hook.
 *
 * Bridge between the command-buffer replay and the
 * `graphics_vk_spirv` interpreter. When `BindPipeline` records a
 * pipeline whose VS + FS modules both have a parseable Program,
 * `ShaderRasterizeDraw` runs the interpreter for each vertex
 * (producing gl_Position) and each pixel (producing the fragment
 * colour). Returns true on success so the caller skips the
 * fixed-function fallback.
 *
 * What this v1 hook supports:
 *   - Graphics pipeline with one vertex shader + one fragment
 *     shader, both parsed into a Program by the v1 SPIR-V parser.
 *   - Vertex shader's Input layout: Location 0 carrying the
 *     position attribute (vec2 / vec3 — the first 2 components
 *     consumed; vec3.z fed to gl_Position via the shader's own
 *     mapping if the shader writes one). Subsequent Locations
 *     carry attribute data the shader picks up via OpLoad.
 *   - Vertex shader's Output layout: a Block (gl_PerVertex)
 *     whose member 0 is BuiltIn Position (vec4) — i.e. the
 *     standard glslang output — OR a bare vec4 Output decorated
 *     BuiltIn Position. Output is read from byte offset 0 of the
 *     Output variable backing.
 *   - Fragment shader's Output layout: a single Location 0 vec4
 *     RGBA written via OpStore. The components are clamped to
 *     [0, 1] and packed BGRA8 for the framebuffer.
 *
 * Shape NOT supported (falls back to fixed-function):
 *   - Vertex buffers other than binding 0 (mirrors the
 *     fixed-function GAP).
 *   - Vertex strides other than the canonical layout
 *     `{vec2/vec3 pos; padding}` aligned to 8 bytes.
 *   - Output Locations on the vertex shader (varyings to FS) —
 *     the FS sees them as zero. A v2 slice will plumb the
 *     interpolation, which needs per-pixel evaluation of the
 *     vertex outputs.
 *   - Anything that needs perspective-correct interpolation,
 *     texture sampling, or descriptor-set-driven uniform reads.
 *
 * The hook is a true opt-in: the existing fixed-function path is
 * unchanged and remains the default for any pipeline that
 * doesn't satisfy the criteria above. Visible behaviour for the
 * gfxdemo + boot self-test is identical until a caller actually
 * binds a parseable SPIR-V pipeline.
 */

namespace duetos::subsystems::graphics::internal
{

using ::duetos::core::Sf32;
using ::duetos::core::Sf32FromBits;
using ::duetos::core::Sf32ToBits;

namespace
{

// IEEE 754 bit patterns for 0.0 and 1.0 to clamp without
// pulling in float math at the call site.
constexpr u32 kBit0 = 0u;
constexpr u32 kBit1 = 0x3F800000u;

// Clamp an Sf32 to [0, 1] and convert to a u8 in [0, 255]. NaN
// snaps to 0; +inf to 255.
u8 ToUnorm8(Sf32 x)
{
    if (::duetos::core::Sf32IsNaN(x))
        return 0;
    Sf32 clamped = ::duetos::core::Sf32Clamp(x, Sf32FromBits(kBit0), Sf32FromBits(kBit1));
    // Multiply by 255 then truncate.
    const Sf32 scaled = ::duetos::core::Sf32Mul(clamped, ::duetos::core::Sf32FromI32(255));
    const i32 v = ::duetos::core::Sf32ToI32(scaled);
    if (v < 0)
        return 0;
    if (v > 255)
        return 255;
    return static_cast<u8>(v);
}

u32 PackArgb(Sf32 r, Sf32 g, Sf32 b, Sf32 a)
{
    const u8 R = ToUnorm8(r);
    const u8 G = ToUnorm8(g);
    const u8 B = ToUnorm8(b);
    const u8 A = ToUnorm8(a);
    return (static_cast<u32>(A) << 24) | (static_cast<u32>(R) << 16) | (static_cast<u32>(G) << 8) | static_cast<u32>(B);
}

// Per-varying snapshot taken once per vertex after the VS runs.
// `data[]` holds the Sf32 bit pattern for each scalar component of
// the VS Output at this Location, packed in natural order. The
// fragment-side interpolation pass reads the same Location off
// each of the 3 vertices' snapshots and writes the interpolated
// value into the matching FS Input.
constexpr u32 kMaxVaryingComponents = 16; // up to vec4 + a few extras
constexpr u32 kMaxVaryings = 8;
struct VaryingSnapshot
{
    u32 location;
    u32 component_count;
    u32 data[kMaxVaryingComponents];
};

// Run a vertex shader for one vertex. Reads the vertex's
// per-attribute data from `vertex_buffer + vertex_index * stride`
// according to the shader's Input Locations, then executes the
// "main" entry point. Writes the gl_Position output components
// into `pos_out[0..3]` (vec4). If `varying_out` is non-null,
// also snapshots every Location-decorated Output the VS wrote
// (up to `varying_cap` entries) so the rasterizer can interpolate
// them per-pixel. When `pipe` carries an explicit vertex-input
// description (via VkSetVertexInputDuet), each Input is fetched
// at the (binding, offset) declared by the caller; otherwise the
// canonical 16-byte-per-Location fallback layout applies.
// Returns false if the shader can't be run.
bool RunVertexShader(spirv::Program* vs, const u8* vb, u64 vb_size, u64 stride, u32 vertex_index, u32* pos_out,
                     VaryingSnapshot* varying_out, u32 varying_cap, u32* varying_n_out,
                     const PipelineRecord* pipe_rec)
{
    if (vs == nullptr || vb == nullptr || pos_out == nullptr)
        return false;
    const u64 base = static_cast<u64>(vertex_index) * stride;
    if (base + stride > vb_size)
        return false;
    spirv::ResetIO(vs);

    if (pipe_rec != nullptr && pipe_rec->vertex_attribute_count > 0)
    {
        // Explicit description path: walk the attribute table and
        // fetch each entry from (binding-stride-anchored base +
        // offset_bytes). v1 still honours binding 0 only; entries
        // for other bindings are recorded but their data comes
        // from the single bound buffer.
        for (u32 i = 0; i < pipe_rec->vertex_attribute_count; ++i)
        {
            const VkVertexAttributeDuet& a = pipe_rec->vertex_attributes[i];
            // Anchor: the per-binding stride * vertex_index gives
            // the start of this vertex within the bound buffer.
            // Look up the matching binding to find its stride.
            u32 b_stride = static_cast<u32>(stride);
            for (u32 b = 0; b < pipe_rec->vertex_binding_count; ++b)
            {
                if (pipe_rec->vertex_bindings[b].binding == a.binding)
                {
                    b_stride = pipe_rec->vertex_bindings[b].stride_bytes;
                    break;
                }
            }
            const u64 vbase = static_cast<u64>(vertex_index) * b_stride;
            const u64 off = vbase + a.offset_bytes;
            if (off + a.byte_size > vb_size)
                continue;
            (void)spirv::WriteInputLocation(vs, a.location, vb + off, a.byte_size);
        }
    }
    else
    {
        // Fallback canonical layout: Location N at offset N * 16.
        for (u32 loc = 0; loc < 4; ++loc)
        {
            const u64 off = base + static_cast<u64>(loc) * 16u;
            if (off + 16u > vb_size)
                break;
            (void)spirv::WriteInputLocation(vs, loc, vb + off, 16u);
        }
    }
    // BuiltIn VertexIndex.
    (void)spirv::WriteInputBuiltin(vs, spirv::builtins::kVertexIndex, &vertex_index, sizeof(vertex_index));
    if (!spirv::ExecuteEntryPoint(vs, "main"))
        return false;
    if (!spirv::ReadOutputBuiltin(vs, spirv::builtins::kPosition, pos_out, 16u))
    {
        // Fallback: read Location 0 in case the shader writes
        // position to a non-BuiltIn Output.
        if (!spirv::ReadOutputLocation(vs, 0, pos_out, 16u))
            return false;
    }
    if (varying_out != nullptr && varying_n_out != nullptr)
    {
        spirv::LocationVar locs[kMaxVaryings]{};
        const u32 n = spirv::EnumerateLocationVars(vs, spirv::StorageClass::Output, locs, kMaxVaryings);
        const u32 nb = (n < varying_cap) ? n : varying_cap;
        for (u32 i = 0; i < nb; ++i)
        {
            varying_out[i].location = locs[i].location;
            varying_out[i].component_count =
                (locs[i].component_count < kMaxVaryingComponents) ? locs[i].component_count : kMaxVaryingComponents;
            const u32 byte_size = varying_out[i].component_count * 4u;
            (void)spirv::ReadOutputLocation(vs, locs[i].location, varying_out[i].data, byte_size);
        }
        *varying_n_out = nb;
    }
    return true;
}

// Run a fragment shader for one pixel. Sets gl_FragCoord then
// executes the entry point; reads the Location 0 vec4 colour and
// returns the packed BGRA8 word in `argb_out`. If `varyings` is
// non-null, writes the interpolated values to each matching FS
// Input Location before executing.
bool RunFragmentShader(spirv::Program* fs, const u32 pixel_xy[2], const VaryingSnapshot* varyings, u32 varying_n,
                       u32* argb_out)
{
    if (fs == nullptr || argb_out == nullptr)
        return false;
    spirv::ResetIO(fs);
    // gl_FragCoord is a vec4 (x, y, z, 1/w). v1 supplies (px, py,
    // 0, 1) so a shader that derives anything from gl_FragCoord
    // sees the right pixel-space coordinate. Z and 1/w are zero
    // because the v1 raster doesn't yet plumb perspective-correct
    // interpolation.
    Sf32 fc[4] = {::duetos::core::Sf32FromU32(pixel_xy[0]), ::duetos::core::Sf32FromU32(pixel_xy[1]),
                  ::duetos::core::Sf32Zero(), ::duetos::core::Sf32One()};
    u32 fc_bits[4] = {Sf32ToBits(fc[0]), Sf32ToBits(fc[1]), Sf32ToBits(fc[2]), Sf32ToBits(fc[3])};
    (void)spirv::WriteInputBuiltin(fs, spirv::builtins::kFragCoord, fc_bits, sizeof(fc_bits));
    // Plumb interpolated varyings. The rasterizer already
    // packed `varyings[i].data[]` with the linearly-interpolated
    // Sf32 components for the FS Input at `varyings[i].location`.
    for (u32 i = 0; i < varying_n; ++i)
    {
        const u32 bytes = varyings[i].component_count * 4u;
        (void)spirv::WriteInputLocation(fs, varyings[i].location, varyings[i].data, bytes);
    }
    if (!spirv::ExecuteEntryPoint(fs, "main"))
        return false;
    u32 color_bits[4] = {0, 0, 0, Sf32ToBits(::duetos::core::Sf32One())};
    if (!spirv::ReadOutputLocation(fs, 0, color_bits, sizeof(color_bits)))
        return false;
    *argb_out = PackArgb(Sf32FromBits(color_bits[0]), Sf32FromBits(color_bits[1]), Sf32FromBits(color_bits[2]),
                         Sf32FromBits(color_bits[3]));
    return true;
}

// Sf32 helper: a*w0 + b*w1 + c*w2 where w0+w1+w2 = 1. Used by
// the per-pixel varying interpolation. No clamping — varyings
// can legitimately be negative or > 1.
Sf32 BaryLerp(Sf32 a, Sf32 b, Sf32 c, Sf32 w0, Sf32 w1, Sf32 w2)
{
    const Sf32 t0 = ::duetos::core::Sf32Mul(a, w0);
    const Sf32 t1 = ::duetos::core::Sf32Mul(b, w1);
    const Sf32 t2 = ::duetos::core::Sf32Mul(c, w2);
    return ::duetos::core::Sf32Add(::duetos::core::Sf32Add(t0, t1), t2);
}

// Convert a vec4 clip-space position into pixel coordinates by
// applying the standard NDC -> viewport mapping. Returns false if
// the position is degenerate (w == 0) or behind the eye. v1 uses
// the full framebuffer as the viewport — no glViewport / scissor
// shrinking yet on this path.
bool ClipToPixel(const u32 pos_bits[4], u32 fb_w, u32 fb_h, i32* px_out, i32* py_out)
{
    const Sf32 x = Sf32FromBits(pos_bits[0]);
    const Sf32 y = Sf32FromBits(pos_bits[1]);
    const Sf32 w = Sf32FromBits(pos_bits[3]);
    if (::duetos::core::Sf32IsZero(w) || ::duetos::core::Sf32IsNaN(w))
        return false;
    // NDC = clip / w.
    const Sf32 ndc_x = ::duetos::core::Sf32Div(x, w);
    const Sf32 ndc_y = ::duetos::core::Sf32Div(y, w);
    // Viewport: px = (ndc_x + 1) * fb_w / 2; py = (1 - ndc_y) * fb_h / 2
    // (Vulkan y-down NDC has the same sign as the framebuffer's row
    // axis, so we don't flip; left as +1 to match GL convention which
    // most reference shaders assume — a future slice can plumb the
    // Vulkan y-flip via the viewport state when callers care).
    const Sf32 half = ::duetos::core::Sf32FromBits(0x3F000000u); // 0.5
    const Sf32 vx = ::duetos::core::Sf32Mul(::duetos::core::Sf32Add(ndc_x, ::duetos::core::Sf32One()),
                                            ::duetos::core::Sf32Mul(::duetos::core::Sf32FromU32(fb_w), half));
    const Sf32 vy = ::duetos::core::Sf32Mul(::duetos::core::Sf32Sub(::duetos::core::Sf32One(), ndc_y),
                                            ::duetos::core::Sf32Mul(::duetos::core::Sf32FromU32(fb_h), half));
    *px_out = ::duetos::core::Sf32ToI32(vx);
    *py_out = ::duetos::core::Sf32ToI32(vy);
    return true;
}

// Paint one triangle by walking its bounding box and invoking
// the fragment shader at every interior pixel. Reuses the
// integer edge-function test from `graphics_vk_raster.cpp` —
// inlined here so the shader path doesn't depend on the v0
// raster's internal helpers (which take a different signature).
//
// `varyings_per_vertex` is an array of length `3 * varying_n`:
// vertex 0's varyings at [0..varying_n), vertex 1's at
// [varying_n..2*varying_n), vertex 2's at [2*varying_n..3*varying_n).
// Each entry's `data[]` holds the Sf32 components for that VS
// Output at that vertex. The per-pixel loop interpolates them
// linearly via barycentric weights and hands the result to the
// fragment shader as Input Location N.
void PaintTriangle(i32 ax, i32 ay, i32 bx, i32 by, i32 cx, i32 cy, spirv::Program* fs, u32 fb_w, u32 fb_h,
                   const VaryingSnapshot* varyings_per_vertex, u32 varying_n, const u32* inv_w_per_vertex_bits)
{
    // Bounding box clipped to framebuffer extent.
    i32 minx = ax;
    if (bx < minx)
        minx = bx;
    if (cx < minx)
        minx = cx;
    i32 maxx = ax;
    if (bx > maxx)
        maxx = bx;
    if (cx > maxx)
        maxx = cx;
    i32 miny = ay;
    if (by < miny)
        miny = by;
    if (cy < miny)
        miny = cy;
    i32 maxy = ay;
    if (by > maxy)
        maxy = by;
    if (cy > maxy)
        maxy = cy;
    if (minx < 0)
        minx = 0;
    if (miny < 0)
        miny = 0;
    if (maxx >= static_cast<i32>(fb_w))
        maxx = static_cast<i32>(fb_w) - 1;
    if (maxy >= static_cast<i32>(fb_h))
        maxy = static_cast<i32>(fb_h) - 1;
    if (maxx < minx || maxy < miny)
        return;

    auto edge = [](i32 x0, i32 y0, i32 x1, i32 y1, i32 px, i32 py) -> i64
    { return static_cast<i64>(x1 - x0) * (py - y0) - static_cast<i64>(y1 - y0) * (px - x0); };
    const i64 area2 = edge(ax, ay, bx, by, cx, cy);
    if (area2 == 0)
        return;
    const bool ccw = area2 > 0;

    // Hard cap: with a CPU fragment shader the per-pixel cost is
    // ~1000x a memcpy, so a 1080p fullscreen triangle would take
    // many seconds. Cap the painted area so a runaway draw doesn't
    // brick the boot; the cap is generous enough for hello-world
    // shaders (256x256 ≈ 64k pixel invocations) but stops a
    // pathological caller painting the desktop.
    constexpr u64 kMaxPaintedPixels = 65536;
    u64 painted = 0;
    u32 pixel_xy[2];
    u32 argb = 0;

    // Precompute the inverse of |area2| as Sf32 so the per-pixel
    // barycentric-weight normalisation is a single multiply
    // instead of a per-pixel Sf32Div (which is the slowest soft-
    // float op). For a degenerate area we'd have returned above.
    const u64 abs_area = (area2 < 0) ? static_cast<u64>(-area2) : static_cast<u64>(area2);
    const Sf32 inv_area =
        ::duetos::core::Sf32Div(::duetos::core::Sf32One(), ::duetos::core::Sf32FromU32(static_cast<u32>(abs_area)));

    // Per-pixel scratch for the interpolated varyings the FS reads.
    VaryingSnapshot interp[kMaxVaryings]{};
    for (u32 i = 0; i < varying_n; ++i)
    {
        interp[i].location = varyings_per_vertex[i].location;
        interp[i].component_count = varyings_per_vertex[i].component_count;
    }

    // Perspective-correct interpolation precompute. When
    // `inv_w_per_vertex_bits` is non-null, the rasterizer
    // divides each varying by its vertex's w at vertex-fetch time
    // (here, just once before the per-pixel loop), interpolates
    // those `v/w` values linearly, interpolates `1/w` linearly,
    // then per-pixel multiplies `v/w` by the interpolated w to
    // recover the correct attribute. Without inv_w, the path
    // falls back to affine (linear-in-screen-space) interpolation.
    const bool persp = (inv_w_per_vertex_bits != nullptr);
    Sf32 inv_w0{0}, inv_w1{0}, inv_w2{0};
    VaryingSnapshot vdivw[3 * kMaxVaryings]{};
    if (persp)
    {
        inv_w0 = Sf32FromBits(inv_w_per_vertex_bits[0]);
        inv_w1 = Sf32FromBits(inv_w_per_vertex_bits[1]);
        inv_w2 = Sf32FromBits(inv_w_per_vertex_bits[2]);
        const Sf32 invw_per_vert[3] = {inv_w0, inv_w1, inv_w2};
        for (u32 v = 0; v < 3; ++v)
        {
            for (u32 vi = 0; vi < varying_n; ++vi)
            {
                vdivw[v * varying_n + vi].location = varyings_per_vertex[v * varying_n + vi].location;
                vdivw[v * varying_n + vi].component_count = varyings_per_vertex[v * varying_n + vi].component_count;
                for (u32 cc = 0; cc < varyings_per_vertex[v * varying_n + vi].component_count && cc < kMaxVaryingComponents; ++cc)
                {
                    vdivw[v * varying_n + vi].data[cc] = Sf32ToBits(
                        ::duetos::core::Sf32Mul(Sf32FromBits(varyings_per_vertex[v * varying_n + vi].data[cc]),
                                                invw_per_vert[v]));
                }
            }
        }
    }

    for (i32 py = miny; py <= maxy; ++py)
    {
        for (i32 px = minx; px <= maxx; ++px)
        {
            const i64 w0 = edge(bx, by, cx, cy, px, py);
            const i64 w1 = edge(cx, cy, ax, ay, px, py);
            const i64 w2 = edge(ax, ay, bx, by, px, py);
            const bool inside_ccw = (w0 >= 0 && w1 >= 0 && w2 >= 0);
            const bool inside_cw = (w0 <= 0 && w1 <= 0 && w2 <= 0);
            if (ccw ? !inside_ccw : !inside_cw)
                continue;
            pixel_xy[0] = static_cast<u32>(px);
            pixel_xy[1] = static_cast<u32>(py);

            // Normalise barycentric weights. The unsigned edge
            // magnitudes opposite each vertex sum to |area2|; dividing
            // gives weights in [0, 1] that interpolate v0->v1->v2.
            // For a CW triangle the sign flips but the magnitudes are
            // still correct; |w_i| / |area2| is the right weight either
            // way.
            const u64 aw0 = (w0 < 0) ? static_cast<u64>(-w0) : static_cast<u64>(w0);
            const u64 aw1 = (w1 < 0) ? static_cast<u64>(-w1) : static_cast<u64>(w1);
            const u64 aw2 = (w2 < 0) ? static_cast<u64>(-w2) : static_cast<u64>(w2);
            const Sf32 bw0 = ::duetos::core::Sf32Mul(::duetos::core::Sf32FromU32(static_cast<u32>(aw0)), inv_area);
            const Sf32 bw1 = ::duetos::core::Sf32Mul(::duetos::core::Sf32FromU32(static_cast<u32>(aw1)), inv_area);
            const Sf32 bw2 = ::duetos::core::Sf32Mul(::duetos::core::Sf32FromU32(static_cast<u32>(aw2)), inv_area);

            // Perspective-correct path: interpolate v/w by bary
            // weights, also interpolate 1/w, then per-pixel divide
            // to recover v. Mathematically equivalent to the
            // textbook formula, packaged for a single Sf32Div per
            // pixel (which is the slow op).
            if (persp)
            {
                const Sf32 invw_pix = BaryLerp(inv_w0, inv_w1, inv_w2, bw0, bw1, bw2);
                // Avoid divide-by-zero pixel: skip the per-pixel
                // perspective restore when interpolated 1/w
                // collapses to zero (occurs only on degenerate
                // homogeneous projections that wouldn't be visible
                // anyway).
                const Sf32 w_pix = ::duetos::core::Sf32IsZero(invw_pix)
                                       ? ::duetos::core::Sf32One()
                                       : ::duetos::core::Sf32Div(::duetos::core::Sf32One(), invw_pix);
                for (u32 vi = 0; vi < varying_n; ++vi)
                {
                    const VaryingSnapshot& a_ss = vdivw[0 * varying_n + vi];
                    const VaryingSnapshot& b_ss = vdivw[1 * varying_n + vi];
                    const VaryingSnapshot& c_ss = vdivw[2 * varying_n + vi];
                    for (u32 cc = 0; cc < interp[vi].component_count && cc < kMaxVaryingComponents; ++cc)
                    {
                        const Sf32 lerped_over_w = BaryLerp(Sf32FromBits(a_ss.data[cc]), Sf32FromBits(b_ss.data[cc]),
                                                            Sf32FromBits(c_ss.data[cc]), bw0, bw1, bw2);
                        interp[vi].data[cc] = Sf32ToBits(::duetos::core::Sf32Mul(lerped_over_w, w_pix));
                    }
                }
            }
            else
            {
                for (u32 vi = 0; vi < varying_n; ++vi)
                {
                    const VaryingSnapshot& a_ss = varyings_per_vertex[0 * varying_n + vi];
                    const VaryingSnapshot& b_ss = varyings_per_vertex[1 * varying_n + vi];
                    const VaryingSnapshot& c_ss = varyings_per_vertex[2 * varying_n + vi];
                    for (u32 cc = 0; cc < interp[vi].component_count && cc < kMaxVaryingComponents; ++cc)
                    {
                        const Sf32 lerped = BaryLerp(Sf32FromBits(a_ss.data[cc]), Sf32FromBits(b_ss.data[cc]),
                                                     Sf32FromBits(c_ss.data[cc]), bw0, bw1, bw2);
                        interp[vi].data[cc] = Sf32ToBits(lerped);
                    }
                }
            }
            if (!RunFragmentShader(fs, pixel_xy, interp, varying_n, &argb))
                continue;
            drivers::video::FramebufferPutPixel(static_cast<u32>(px), static_cast<u32>(py), argb);
            ++painted;
            if (painted >= kMaxPaintedPixels)
            {
                drivers::video::FramebufferAddDamage(static_cast<u32>(minx), static_cast<u32>(miny),
                                                     static_cast<u32>(maxx - minx + 1),
                                                     static_cast<u32>(maxy - miny + 1));
                return;
            }
        }
    }
    drivers::video::FramebufferAddDamage(static_cast<u32>(minx), static_cast<u32>(miny),
                                         static_cast<u32>(maxx - minx + 1), static_cast<u32>(maxy - miny + 1));
}

// Same as the v0 rasterizer's helper — pick the scanout-backed
// image's extent if the bound RT is scanout, otherwise fall back
// to the framebuffer Query().
bool ResolveExtent(const RasterState& st, u32* w, u32* h)
{
    if (st.fb_w > 0 && st.fb_h > 0)
    {
        *w = st.fb_w;
        *h = st.fb_h;
        return true;
    }
    return false;
}

bool ResolveVertexBuffer(const RasterState& st, const u8** base, u64* size)
{
    if (st.vertex_buffer == 0 || !HandleInRange(st.vertex_buffer, kBufferBase))
        return false;
    const u32 slot = SlotOf(st.vertex_buffer, kBufferBase);
    if (!PoolIsLive(g_buffer_pool, slot))
        return false;
    const BufferRecord& vb = g_buffer_data[slot];
    if (vb.backing == nullptr)
        return false;
    if (st.vertex_offset >= vb.size)
        return false;
    const auto* p = static_cast<const u8*>(vb.backing) + vb.backing_offset + st.vertex_offset;
    *base = p;
    *size = vb.size - st.vertex_offset;
    return true;
}

} // namespace

// --------------------------------------------------------------
// Public surface used by the executor + the cmd-buffer replay.
// --------------------------------------------------------------

spirv::Program* ShaderProgram(VkShaderModule shader)
{
    if (shader == 0 || !HandleInRange(shader, kShaderBase))
        return nullptr;
    const u32 slot = SlotOf(shader, kShaderBase);
    if (!PoolIsLive(g_shader_pool, slot))
        return nullptr;
    return g_shader_data[slot].spirv_program;
}

PipelineShaders PipelineShaderHandles(VkPipeline pipe)
{
    PipelineShaders out{};
    if (pipe == 0 || !HandleInRange(pipe, kPipelineBase))
        return out;
    const u32 slot = SlotOf(pipe, kPipelineBase);
    if (!PoolIsLive(g_pipeline_pool, slot))
        return out;
    out.vs = g_pipeline_data[slot].vertex_shader;
    out.fs = g_pipeline_data[slot].fragment_shader;
    return out;
}

bool ShaderRasterizeDraw(const RasterState& st, u32 first_vertex, u32 vertex_count)
{
    if (st.bound_pipeline == 0)
    {
        ++g_shader_raster_draws_skipped;
        return false;
    }
    const PipelineShaders ps = PipelineShaderHandles(st.bound_pipeline);
    spirv::Program* vs = ShaderProgram(ps.vs);
    spirv::Program* fs = ShaderProgram(ps.fs);
    if (vs == nullptr || fs == nullptr)
    {
        ++g_shader_raster_draws_skipped;
        return false;
    }
    const u32 pslot = SlotOf(st.bound_pipeline, kPipelineBase);
    const PipelineRecord* pipe_rec = PoolIsLive(g_pipeline_pool, pslot) ? &g_pipeline_data[pslot] : nullptr;
    u32 fb_w = 0, fb_h = 0;
    if (!ResolveExtent(st, &fb_w, &fb_h))
        return false;
    const u8* vb_base = nullptr;
    u64 vb_size = 0;
    if (!ResolveVertexBuffer(st, &vb_base, &vb_size))
        return false;

    // v1 vertex stride: 16 bytes per Location, one Location per
    // vertex (caller's vertex buffer carries `position` only).
    const u64 stride = 16;

    // Triangle-list only for v1. Strip / fan are deferred — the
    // shader hook can be extended to mirror the v0 raster's
    // topology handling in a follow-on once a real workload needs
    // it.
    if (st.topology != 3)
        return false;
    if (vertex_count < 3)
        return false;
    const u32 tri_count = vertex_count / 3u;

    // Per-vertex varying snapshots: kMaxVaryings entries per
    // vertex, 3 vertices per triangle. Packed `[vert][var]` so a
    // single base + (vert * varying_n + var) addresses the right
    // entry inside PaintTriangle's interpolation loop.
    VaryingSnapshot vary[3 * kMaxVaryings]{};
    u32 vary_n[3] = {0, 0, 0};

    for (u32 t = 0; t < tri_count; ++t)
    {
        u32 pos[3][4]{};
        for (u32 v = 0; v < 3; ++v)
        {
            if (!RunVertexShader(vs, vb_base, vb_size, stride, first_vertex + t * 3u + v, pos[v],
                                 &vary[v * kMaxVaryings], kMaxVaryings, &vary_n[v], pipe_rec))
                return false;
        }
        i32 px[3], py[3];
        bool ok = true;
        for (u32 v = 0; v < 3; ++v)
            ok = ok && ClipToPixel(pos[v], fb_w, fb_h, &px[v], &py[v]);
        if (!ok)
            continue;
        // The three vertices' VS Output sets ought to share the
        // same Location layout (they came from the same VS). Use
        // vertex 0's count as the authority — if vertex 1 or 2
        // produced more, the extras get ignored; fewer is
        // impossible because the VS is deterministic on the same
        // shader.
        const u32 vary_n_use = vary_n[0];

        // Pack into the contiguous form PaintTriangle expects:
        // varyings_per_vertex[vert * vary_n_use + var]. The
        // RunVertexShader call wrote to &vary[v * kMaxVaryings],
        // so we'd need to repack — but PaintTriangle indexes as
        // `[vert][var]` with vary_n_use stride, so just pass the
        // pointer and trust the layout matches when vary_n_use
        // <= kMaxVaryings, which it always is.
        VaryingSnapshot packed[3 * kMaxVaryings]{};
        for (u32 v = 0; v < 3; ++v)
            for (u32 i = 0; i < vary_n_use; ++i)
                packed[v * vary_n_use + i] = vary[v * kMaxVaryings + i];
        // Compute 1/w per vertex for perspective-correct
        // interpolation. pos[v][3] is gl_Position.w from the VS.
        // If any w is non-positive (orthographic projection or
        // a degenerate output), skip the perspective path —
        // affine interpolation handles those cases without
        // introducing artefacts.
        u32 inv_w_bits[3]{};
        bool ortho = false;
        for (u32 v = 0; v < 3; ++v)
        {
            const Sf32 w = Sf32FromBits(pos[v][3]);
            if (::duetos::core::Sf32IsZero(w) || ::duetos::core::Sf32IsNaN(w) || ::duetos::core::Sf32IsNegative(w))
            {
                ortho = true;
                break;
            }
            inv_w_bits[v] = Sf32ToBits(::duetos::core::Sf32Div(::duetos::core::Sf32One(), w));
        }
        PaintTriangle(px[0], py[0], px[1], py[1], px[2], py[2], fs, fb_w, fb_h, packed, vary_n_use,
                      ortho ? nullptr : inv_w_bits);
    }
    ++g_shader_raster_draws_painted;
    return true;
}

bool ShaderDispatchCompute(const RasterState& st, u32 group_count_x, u32 group_count_y, u32 group_count_z)
{
    if (st.bound_pipeline == 0)
        return false;
    if (group_count_x == 0 || group_count_y == 0 || group_count_z == 0)
        return false;
    // Look up the compute pipeline's CS shader. PipelineShaderHandles
    // returns (vs, fs); compute pipelines stash their CS in
    // g_pipeline_data[slot].compute_shader, so fetch directly.
    if (!HandleInRange(st.bound_pipeline, kPipelineBase))
        return false;
    const u32 pslot = SlotOf(st.bound_pipeline, kPipelineBase);
    if (!PoolIsLive(g_pipeline_pool, pslot))
        return false;
    const VkShaderModule cs_handle = g_pipeline_data[pslot].compute_shader;
    spirv::Program* cs = ShaderProgram(cs_handle);
    if (cs == nullptr)
        return false;
    // Find the entry point and its declared LocalSize.
    if (cs->entry_point_count == 0)
        return false;
    spirv::EntryPointRecord ep = cs->entry_points[0];
    // First entry point is the canonical "main"; if a future
    // shader uses multiple entries the caller will need to pass
    // a name — for v1 we honour the first.

    const u64 total_invocations = static_cast<u64>(group_count_x) * group_count_y * group_count_z *
                                  static_cast<u64>(ep.local_size_x) * ep.local_size_y * ep.local_size_z;
    constexpr u64 kMaxInvocationsPerDispatch = 65536;
    const u64 cap = (total_invocations < kMaxInvocationsPerDispatch) ? total_invocations : kMaxInvocationsPerDispatch;
    if (cap == 0)
        return false;

    // gl_NumWorkgroups (uvec3) is the same for every invocation; the
    // SPIR-V `Input`-storage builtin is what shaders read. We write
    // it once before the loop and rely on ResetIO not zeroing
    // builtin-decorated inputs — actually ResetIO DOES wipe input
    // storage between calls, so we re-write per invocation.
    const u32 num_wg[3] = {group_count_x, group_count_y, group_count_z};

    u64 painted = 0;
    for (u32 gz = 0; gz < group_count_z; ++gz)
    {
        for (u32 gy = 0; gy < group_count_y; ++gy)
        {
            for (u32 gx = 0; gx < group_count_x; ++gx)
            {
                const u32 wg[3] = {gx, gy, gz};
                for (u32 lz = 0; lz < ep.local_size_z; ++lz)
                {
                    for (u32 ly = 0; ly < ep.local_size_y; ++ly)
                    {
                        for (u32 lx = 0; lx < ep.local_size_x; ++lx)
                        {
                            if (painted >= cap)
                                return true;
                            const u32 li[3] = {lx, ly, lz};
                            const u32 gi[3] = {gx * ep.local_size_x + lx, gy * ep.local_size_y + ly,
                                               gz * ep.local_size_z + lz};
                            const u32 li_index = lz * ep.local_size_x * ep.local_size_y + ly * ep.local_size_x + lx;
                            spirv::ResetIO(cs);
                            (void)spirv::WriteInputBuiltin(cs, spirv::builtins::kNumWorkgroups, num_wg, sizeof(num_wg));
                            (void)spirv::WriteInputBuiltin(cs, spirv::builtins::kWorkgroupId, wg, sizeof(wg));
                            (void)spirv::WriteInputBuiltin(cs, spirv::builtins::kLocalInvocationId, li, sizeof(li));
                            (void)spirv::WriteInputBuiltin(cs, spirv::builtins::kGlobalInvocationId, gi, sizeof(gi));
                            (void)spirv::WriteInputBuiltin(cs, spirv::builtins::kLocalInvocationIndex, &li_index,
                                                           sizeof(li_index));
                            if (!spirv::ExecuteEntryPoint(cs, "main"))
                                return painted > 0;
                            ++painted;
                        }
                    }
                }
            }
        }
    }
    return true;
}

bool ShaderRasterizeDrawIndexed(const RasterState& st, u32 first_index, u32 index_count, i32 vertex_offset)
{
    // v1 indexed-draw shader path: fall back to the fixed-function
    // raster. The non-indexed path is what most hello-world
    // shaders trigger; indexed adds vertex-cache management and
    // re-fetch logic that's not worth landing without a real
    // caller. Returning false here is the documented "no-op"
    // signal — the replay walks back through the fixed-function
    // rasterizer.
    (void)st;
    (void)first_index;
    (void)index_count;
    (void)vertex_offset;
    return false;
}

} // namespace duetos::subsystems::graphics::internal
