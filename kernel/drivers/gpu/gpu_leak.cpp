#include "drivers/gpu/gpu_leak.h"

#include "drivers/gpu/gpu_resources.h"
#include "log/klog.h"

/*
 * DuetOS — GPU resource lifetime accounting (read-side).
 *
 * Each accessor is a thin passthrough over `gpu_resources.h` —
 * the four per-class tables that GPU drivers populate when they
 * create contexts / surfaces / command buffers / VRAM allocations.
 * The tables sit empty when no driver has registered anything
 * (the v0 GPU steady state on every supported tier-1 device);
 * they fill in as drivers come online.
 */

namespace duetos::drivers::gpu
{

namespace
{

GpuClassSnapshot ToLeakSnapshot(const GpuResourceSnapshot& s)
{
    return GpuClassSnapshot{s.outstanding, s.peak, s.byte_cost};
}

} // namespace

GpuClassSnapshot GpuLeakSnapshotContexts()
{
    return ToLeakSnapshot(GpuResourcesSnapshot(GpuResourceClass::Context));
}

GpuClassSnapshot GpuLeakSnapshotSurfaces()
{
    return ToLeakSnapshot(GpuResourcesSnapshot(GpuResourceClass::Surface));
}

GpuClassSnapshot GpuLeakSnapshotCmdBuffers()
{
    return ToLeakSnapshot(GpuResourcesSnapshot(GpuResourceClass::CmdBuffer));
}

GpuClassSnapshot GpuLeakSnapshotVram()
{
    return ToLeakSnapshot(GpuResourcesSnapshot(GpuResourceClass::Vram));
}

void GpuLeakReportProcessExit(u64 pid, const GpuClassSnapshot per_class[4])
{
    // Per-process residue eviction: walk the four tables and
    // release every slot owned by `pid`. Resources tagged with
    // `kPidKernel` are skipped (driver-owned, lifetime not bound
    // to any user process). Bumping the per-class generation
    // counters means a stale handle held in process state cannot
    // accidentally retire a future resource.
    const u32 evicted = GpuResourcesReleaseByPid(pid);

    // The leak detector also passes us a snapshot of each class
    // taken at exit time — useful to log alongside the eviction
    // count so an operator can correlate "process X exited
    // owning N GPU contexts" against the system-wide snapshot
    // ("…out of M total"). The detector's caller already pre-
    // populates `per_class` in (Context, Surface, CmdBuffer,
    // VRAM) order.
    if (evicted == 0)
        return;
    KLOG_WARN_2V("drivers/gpu/gpu_leak", "process exit released GPU residue", "pid", pid, "evicted",
                 static_cast<u64>(evicted));
    KLOG_DEBUG_V("drivers/gpu/gpu_leak", "  contexts at exit (system-wide outstanding)", per_class[0].outstanding);
    KLOG_DEBUG_V("drivers/gpu/gpu_leak", "  surfaces at exit (system-wide byte_cost)", per_class[1].byte_cost);
    KLOG_DEBUG_V("drivers/gpu/gpu_leak", "  cmd_buffers at exit (system-wide outstanding)", per_class[2].outstanding);
    KLOG_DEBUG_V("drivers/gpu/gpu_leak", "  vram at exit (system-wide byte_cost)", per_class[3].byte_cost);
}

} // namespace duetos::drivers::gpu
