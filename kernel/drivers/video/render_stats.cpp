/*
 * DuetOS — render statistics: implementation.
 *
 * Companion to `render_stats.h`. Counters live in this TU so the
 * read path is a single set of volatile loads against module-
 * scope storage; no allocation, no locking, no inter-TU traffic.
 */

#include "drivers/video/render_stats.h"

#include "util/saturating.h"

namespace duetos::drivers::video
{

namespace
{

// Render lifetime counters — saturating per class BB. A long-running
// desktop session at 60 fps × full-screen damage can plausibly reach
// the dirty/surface pixel ceilings; saturation closes the
// wrap-to-zero defense gap without breaking any pixel-ratio
// computation (those use local u64s).
constinit util::SatU64 g_frames_composed = 0;
constinit util::SatU64 g_frames_presented = 0;
constinit util::SatU64 g_frames_clean = 0;
constinit util::SatU64 g_frames_full = 0;
constinit util::SatU64 g_frames_partial = 0;
constinit util::SatU64 g_dirty_pixels_total = 0;
constinit util::SatU64 g_bbox_pixels_total = 0;
constinit util::SatU64 g_surface_pixels_total = 0;
constinit util::SatU64 g_presents_banded = 0;
constinit util::SatU64 g_presents_coalesced = 0;
constinit u32 g_max_band_count = 0;
constinit u32 g_last_x = 0;
constinit u32 g_last_y = 0;
constinit u32 g_last_w = 0;
constinit u32 g_last_h = 0;
constinit u32 g_last_rect_count = 0;
constinit bool g_last_valid = false;

} // namespace

RenderStats RenderStatsRead()
{
    return RenderStats{
        .frames_composed = g_frames_composed,
        .frames_presented = g_frames_presented,
        .frames_clean = g_frames_clean,
        .frames_full = g_frames_full,
        .frames_partial = g_frames_partial,
        .dirty_pixels_total = g_dirty_pixels_total,
        .bbox_pixels_total = g_bbox_pixels_total,
        .surface_pixels_total = g_surface_pixels_total,
        .presents_banded = g_presents_banded,
        .presents_coalesced = g_presents_coalesced,
        .max_band_count = g_max_band_count,
        .last_damage_x = g_last_x,
        .last_damage_y = g_last_y,
        .last_damage_w = g_last_w,
        .last_damage_h = g_last_h,
        .last_rect_count = g_last_rect_count,
        .last_damage_valid = g_last_valid,
    };
}

void RenderStatsReset()
{
    g_frames_composed = 0;
    g_frames_presented = 0;
    g_frames_clean = 0;
    g_frames_full = 0;
    g_frames_partial = 0;
    g_dirty_pixels_total = 0;
    g_bbox_pixels_total = 0;
    g_surface_pixels_total = 0;
    g_presents_banded = 0;
    g_presents_coalesced = 0;
    g_max_band_count = 0;
    g_last_x = 0;
    g_last_y = 0;
    g_last_w = 0;
    g_last_h = 0;
    g_last_rect_count = 0;
    g_last_valid = false;
}

void RenderStatsOnComposeEnd()
{
    ++g_frames_composed;
}

void RenderStatsOnPresent(const DamageRect& bbox, u64 dirty_pixels, u32 rect_count, u32 surface_width,
                          u32 surface_height)
{
    ++g_frames_presented;
    g_last_valid = bbox.valid;
    g_last_x = bbox.x;
    g_last_y = bbox.y;
    g_last_w = bbox.w;
    g_last_h = bbox.h;
    g_last_rect_count = rect_count;
    if (!bbox.valid)
    {
        ++g_frames_clean;
        return;
    }
    const u64 bbox_area = static_cast<u64>(bbox.w) * bbox.h;
    const u64 surface = static_cast<u64>(surface_width) * surface_height;
    g_dirty_pixels_total += dirty_pixels;
    g_bbox_pixels_total += bbox_area;
    g_surface_pixels_total += surface;
    if (rect_count > 1)
    {
        ++g_presents_banded;
        if (rect_count > g_max_band_count)
        {
            g_max_band_count = rect_count;
        }
    }
    else
    {
        ++g_presents_coalesced;
        if (g_max_band_count < 1)
        {
            g_max_band_count = 1;
        }
    }
    // Full vs. partial uses the TRUE dirty pixel count, not the bbox.
    // A banded present where two small disjoint rects dirty 1% of the
    // surface is partial; a single bbox covering 99% is full. Counting
    // by true dirty matches what "the GPU actually had to upload".
    if (surface != 0 && dirty_pixels * 100 >= surface * 95)
    {
        ++g_frames_full;
    }
    else
    {
        ++g_frames_partial;
    }
}

} // namespace duetos::drivers::video
