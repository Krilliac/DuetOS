#include "drivers/gpu/gpu_leak.h"

/*
 * DuetOS — GPU resource lifetime accounting (v0 implementation).
 *
 * Each accessor returns a zeroed snapshot today. v0 GPU is
 * discovery-only — see `kernel/drivers/gpu/gpu.h`. Real per-
 * resource tables ship with the imminent GPU slice; when they
 * land, each accessor walks the corresponding driver-side table
 * and the matching `// GAP:` marker comes off.
 *
 * The detector calls these unconditionally; a zero return is the
 * correct answer until a resource type exists.
 */

namespace duetos::drivers::gpu
{

GpuClassSnapshot GpuLeakSnapshotContexts()
{
    // GAP: returns zero until per-process GPU context tracking lands
    // in the GPU driver — revisit with the GPU slice.
    return GpuClassSnapshot{0, 0, 0};
}

GpuClassSnapshot GpuLeakSnapshotSurfaces()
{
    // GAP: returns zero until surface lifetime tracking lands in the
    // GPU driver — revisit with the GPU slice.
    return GpuClassSnapshot{0, 0, 0};
}

GpuClassSnapshot GpuLeakSnapshotCmdBuffers()
{
    // GAP: returns zero until command-buffer submission tracking
    // lands in the GPU driver — revisit with the GPU slice.
    return GpuClassSnapshot{0, 0, 0};
}

GpuClassSnapshot GpuLeakSnapshotVram()
{
    // GAP: returns zero until VRAM/GTT byte accounting lands in the
    // GPU driver — revisit with the GPU slice.
    return GpuClassSnapshot{0, 0, 0};
}

void GpuLeakReportProcessExit(u64 pid, const GpuClassSnapshot per_class[4])
{
    // GAP: no-op until the GPU driver has per-process resource tables
    // to attribute against — revisit with the GPU slice.
    (void)pid;
    (void)per_class;
}

} // namespace duetos::drivers::gpu
