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
constinit util::SatU64 g_surface_pixels_total = 0;
constinit u32 g_last_x = 0;
constinit u32 g_last_y = 0;
constinit u32 g_last_w = 0;
constinit u32 g_last_h = 0;
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
        .surface_pixels_total = g_surface_pixels_total,
        .last_damage_x = g_last_x,
        .last_damage_y = g_last_y,
        .last_damage_w = g_last_w,
        .last_damage_h = g_last_h,
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
    g_surface_pixels_total = 0;
    g_last_x = 0;
    g_last_y = 0;
    g_last_w = 0;
    g_last_h = 0;
    g_last_valid = false;
}

void RenderStatsOnComposeEnd()
{
    ++g_frames_composed;
}

void RenderStatsOnPresent(const DamageRect& damage, u32 surface_width, u32 surface_height)
{
    ++g_frames_presented;
    g_last_valid = damage.valid;
    g_last_x = damage.x;
    g_last_y = damage.y;
    g_last_w = damage.w;
    g_last_h = damage.h;
    if (!damage.valid)
    {
        ++g_frames_clean;
        return;
    }
    const u64 dirty = static_cast<u64>(damage.w) * damage.h;
    const u64 surface = static_cast<u64>(surface_width) * surface_height;
    g_dirty_pixels_total += dirty;
    g_surface_pixels_total += surface;
    // ≥95% of surface counts as "full"; below that, "partial".
    // The damage tracker only ever produces a single bbox so a
    // 99% fill is still a partial — but if chrome touched both
    // the topmost and bottommost row, the bbox is effectively
    // full-screen and counting it as such is the right call.
    if (surface != 0 && dirty * 100 >= surface * 95)
    {
        ++g_frames_full;
    }
    else
    {
        ++g_frames_partial;
    }
}

} // namespace duetos::drivers::video
