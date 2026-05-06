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
    u64 dirty_pixels_total;   // sum of damage.w * damage.h across every present
    u64 surface_pixels_total; // sum of width * height across every present (denominator
                              // for "average dirty fraction")
    u32 last_damage_x;        // last presented damage rect, for debugging
    u32 last_damage_y;
    u32 last_damage_w;
    u32 last_damage_h;
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
/// hook was registered)." Pass the damage rect handed to the hook
/// so the partial vs. full breakdown can be computed.
/// `FramebufferPresent` calls this once per frame, immediately
/// before the damage union is reset.
void RenderStatsOnPresent(const DamageRect& damage, u32 surface_width, u32 surface_height);

} // namespace duetos::drivers::video
