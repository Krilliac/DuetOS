#pragma once

#include "drivers/video/framebuffer.h"
#include "util/types.h"

/*
 * DuetOS — render statistics, v0.
 *
 * Counters the framebuffer driver bumps as it composes a frame,
 * exposed to diagnostic surfaces (the `gfx` shell command, future
 * Vulkan ICD enumeration, perf-budget regression tests) so an
 * operator can answer:
 *
 *   - How many frames has the compositor produced so far?
 *   - What's the breakdown of partial vs. full presents?
 *   - How many pixels did the average frame touch?
 *   - Did the damage tracker actually save bandwidth, or are most
 *     frames still full-screen?
 *
 * Counters are kernel-internal monotonics. They are NOT a
 * performance hot-path — only the compose-end and present-end
 * paths bump them, never the per-pixel inner loops, so the cost
 * is one update per frame rather than per pixel.
 *
 * Context: kernel. Updated by `kernel/drivers/video/framebuffer.cpp`
 * at well-defined points (compose-end, present, damage reset).
 * Read by diagnostics; not racy in the kernel-shell-only callers
 * we have today, but the read snapshots all fields in a single
 * volatile-load sequence so a future SMP shell driving compose on
 * one CPU + reading on another sees a self-consistent value per
 * field.
 */

namespace duetos::drivers::video
{

struct RenderStats
{
    u64 frames_composed;      // total `FramebufferEndCompose` calls
    u64 frames_presented;     // total `FramebufferPresent` calls
    u64 frames_clean;         // present passes with damage_valid == false (skipped)
    u64 frames_full;          // present passes whose damage covered ≥95% of surface
    u64 frames_partial;       // present passes with a sub-surface damage rect
    u64 dirty_pixels_total;   // sum of per-rect dirty pixels (true area painted,
                              // NOT the union bbox area — banded presents flush
                              // disjoint rects so the bbox overstates by
                              // `bbox_area - sum(rect_area)`)
    u64 bbox_pixels_total;    // sum of union-bbox area across every present. The
                              // ratio `dirty_pixels_total / bbox_pixels_total`
                              // tells you how much the banded path saves over a
                              // naïve "flush the whole bbox" backend.
    u64 surface_pixels_total; // sum of width * height across every present (denominator
                              // for "average dirty fraction")
    u64 presents_banded;      // present passes flushed as N disjoint rects (N > 1)
    u64 presents_coalesced;   // present passes flushed as a single bbox (N == 1).
                              // Excludes clean passes (frames_clean).
    u32 max_band_count;       // high-water mark of disjoint rects in any one present
    u32 last_damage_x;        // last presented damage bbox, for debugging
    u32 last_damage_y;
    u32 last_damage_w;
    u32 last_damage_h;
    u32 last_rect_count; // number of disjoint rects in the last present
                         // (0 for clean, 1 for coalesced, >1 for banded)
    bool last_damage_valid;
};

/// Snapshot every counter. Returned by value; no reset.
RenderStats RenderStatsRead();

/// Reset every counter to zero. Used by tests + the shell's
/// `gfx reset` subcommand once one lands. Idempotent; concurrent
/// composes during a reset see undefined-but-safe values for one
/// frame, by design (this is a debug counter, not a coherence-
/// critical observable).
void RenderStatsReset();

// -------------------------------------------------------------------
// Bump points — called from `framebuffer.cpp` at the end of each
// compose / present pass. Not part of the public draw API.
// -------------------------------------------------------------------

/// Mark "the compositor ran a compose pass to completion."
/// `FramebufferEndCompose` calls this once per frame.
void RenderStatsOnComposeEnd();

/// Mark "the compositor ran a present hook (or would have, if no
/// hook was registered)." Pass:
///   - `bbox`: the union damage rect (already-clipped). `valid==false`
///     means a clean frame — counters tagged "clean" tick, no others.
///   - `dirty_pixels`: the SUM of per-rect areas the hook actually
///     flushed. For a banded present with N disjoint rects this is
///     `sum(rects[i].w * rects[i].h)`, NOT the bbox area. For a
///     coalesced (single-rect) present it equals `bbox.w * bbox.h`.
///     `RenderStats::dirty_pixels_total` accumulates this so the
///     reported avg-dirty-fraction reflects real GPU bandwidth.
///   - `rect_count`: number of disjoint rects in the present. 0 for
///     a clean frame, 1 for a single-bbox flush, >1 for the banded
///     path. Drives `presents_banded` / `presents_coalesced` and
///     `max_band_count`.
///   - `surface_width` / `surface_height`: dimensions of the live
///     surface, for the full-vs-partial classification and the
///     `surface_pixels_total` denominator.
/// `FramebufferPresent` calls this once per frame, immediately
/// before the damage union is reset.
void RenderStatsOnPresent(const DamageRect& bbox, u64 dirty_pixels, u32 rect_count, u32 surface_width,
                          u32 surface_height);

} // namespace duetos::drivers::video
