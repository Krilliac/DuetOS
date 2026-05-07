#pragma once

#include "util/types.h"

/*
 * DuetOS — GPU resource lifetime accounting (read-side contract).
 *
 * The leak detector (`kernel/diag/leak_detector.cpp`) consumes the
 * four `GpuLeakSnapshot*` accessors below to fold GPU resources into
 * its unified per-class report. Today each accessor returns a zeroed
 * snapshot — v0 GPU is discovery-only (`kernel/drivers/gpu/gpu.h`)
 * and there are no contexts, surfaces, command buffers, or VRAM
 * allocations to count. As the imminent GPU slice lands real tables,
 * each accessor's implementation flips from "returns zero" to
 * "returns real count" without any change to the leak detector.
 *
 * The detector links against these symbols unconditionally — it
 * never reaches into GPU internals. The driver owns the source of
 * truth (its per-resource tables); this header is the read-side
 * contract.
 *
 * Adding a new GPU resource class:
 *   1. Extend `ResourceClass` in `kernel/diag/leak_detector.h`.
 *   2. Add a sibling `GpuLeakSnapshot<NewClass>()` here.
 *   3. Adapt in `kernel/diag/leak_detector.cpp`.
 *
 * Context: kernel. Snapshot accessors are read-only and safe from
 * any context — no locks, no allocation, no blocking.
 */

namespace duetos::drivers::gpu
{

/// One per-class resource snapshot. `outstanding` is the live
/// count, `peak` the lifetime high-water, `byte_cost` the live
/// byte total (VRAM-shaped resources fill this; non-byte-shaped
/// resources may leave it 0).
struct GpuClassSnapshot
{
    u64 outstanding;
    u64 peak;
    u64 byte_cost;
};

/// Per-process GPU contexts (rendering / compute contexts owned
/// by user processes). One row per (PID, context) tuple in v0.
GpuClassSnapshot GpuLeakSnapshotContexts();

/// Surfaces — framebuffers, render targets, textures. May or may
/// not be VRAM-resident. `byte_cost` is the sum of pixel-buffer
/// bytes across live surfaces.
GpuClassSnapshot GpuLeakSnapshotSurfaces();

/// Command buffers — submitted but not yet retired. A growing
/// outstanding count indicates the GPU is not retiring submissions
/// (driver-side leak or hung context).
GpuClassSnapshot GpuLeakSnapshotCmdBuffers();

/// VRAM / GTT allocations — bytes of GPU-visible memory in flight.
/// Per-process attribution lives on each allocation in the GPU
/// driver; this snapshot is the system-wide total.
GpuClassSnapshot GpuLeakSnapshotVram();

/// Per-process exit hook. Called from the leak detector's
/// `LeakDetectorReportProcessExit()` so the GPU driver can attribute
/// any residue (orphaned contexts, surfaces, command buffers, VRAM)
/// to the exiting PID. `per_class` is filled in by the detector's
/// caller with the four GPU classes' snapshots in the order
/// (contexts, surfaces, cmd_buffers, vram); the GPU driver may use
/// it to cross-check against its own tables.
///
/// v0 implementation is a no-op — there are no GPU resources to
/// orphan yet. The contract is in place so the GPU slice's exit
/// path drops in here once it has tables to walk.
void GpuLeakReportProcessExit(u64 pid, const GpuClassSnapshot per_class[4]);

} // namespace duetos::drivers::gpu
