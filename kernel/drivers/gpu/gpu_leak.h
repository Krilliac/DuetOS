#pragma once

#include "util/types.h"

/*
 * DuetOS — GPU resource lifetime accounting (read-side contract).
 *
 * The leak detector (`kernel/diag/leak_detector.cpp`) consumes the
 * four `GpuLeakSnapshot*` accessors below to fold GPU resources into
 * its unified per-class report. Each accessor is a thin passthrough
 * over `gpu_resources.h`'s per-class snapshot tables — drivers
 * register resources via `GpuContextRegister` / `GpuSurfaceRegister`
 * / `GpuCmdBufferRegister` / `GpuVramRegister`, and the snapshots
 * here see the live count + peak + byte_cost.
 *
 * The detector links against these symbols unconditionally — it
 * never reaches into GPU internals. The drivers own the write side
 * (registering / releasing resources); this header is the read-side
 * contract.
 *
 * Adding a new GPU resource class:
 *   1. Extend `ResourceClass` in `kernel/diag/leak_detector.h`.
 *   2. Add a sibling `GpuLeakSnapshot<NewClass>()` here.
 *   3. Add the matching class to `gpu_resources.h` (table + APIs).
 *   4. Adapt in `kernel/diag/leak_detector.cpp`.
 *
 * Context: kernel. Snapshot accessors are read-only — they take
 * the resource subsystem's spinlock briefly. Safe from any
 * context that doesn't already hold that lock.
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
/// `LeakDetectorReportProcessExit()` so the GPU resource tables
/// can evict any residue (orphaned contexts, surfaces, command
/// buffers, VRAM) attributed to the exiting PID. `per_class` is
/// filled in by the detector's caller with the four GPU classes'
/// snapshots in the order (contexts, surfaces, cmd_buffers, vram);
/// the hook logs them alongside the eviction count so an operator
/// can correlate a leak warning with the system-wide outstanding
/// state at the moment of exit. Resources tagged with `kPidKernel`
/// are skipped — they outlive the user process and are released
/// through driver-shutdown paths.
void GpuLeakReportProcessExit(u64 pid, const GpuClassSnapshot per_class[4]);

} // namespace duetos::drivers::gpu
