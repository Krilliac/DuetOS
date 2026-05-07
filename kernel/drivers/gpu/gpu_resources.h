#pragma once

#include "util/types.h"

/*
 * DuetOS — GPU resource lifetime tables (write-side contract).
 *
 * The leak detector reads four per-class snapshots through
 * `gpu_leak.h`. Until this header existed, those accessors
 * returned zero because no driver TU had a place to register
 * created resources. This is that place: four small per-class
 * tables, one spinlock guarding all of them, and a handle ABI
 * that survives slot reuse via a per-slot generation counter.
 *
 * A "GPU resource" here is something a guest (Win32 / Linux PE,
 * native userland, or the kernel itself) can leak across a
 * process exit. Drivers (vendor GPU bring-ups, virtio-gpu,
 * future Vulkan ICD) call:
 *
 *   GpuContextRegister / Release        — render + compute contexts
 *   GpuSurfaceRegister  / Release       — textures, render targets
 *   GpuCmdBufferRegister / Retire       — submitted command buffers
 *   GpuVramRegister     / Release       — VRAM/GTT byte allocations
 *
 * `gpu_leak.cpp` reads `*Snapshot()` against each class. The
 * leak-detector's per-process-exit hook (`GpuLeakReportProcessExit`)
 * walks `GpuResourcesReleaseByPid(pid)` to evict orphans and
 * publish per-class residue counts.
 *
 * Design choices:
 *   - Fixed-size tables (no kheap pressure during driver paths).
 *     Capacities are sized for the v0 expected workload — a few
 *     PE windows + Vulkan ICD scaffolding. Bumping later is a
 *     one-line edit; the accessor ABI is stable.
 *   - Single spinlock (`g_gpu_resources_lock` in the .cpp). The
 *     four tables together see a few hundred operations per
 *     second at most; a finer-grained scheme would just add
 *     code without measurable benefit.
 *   - Handle encoding: 8 bits class | 8 bits generation | 16 bits
 *     index. Releasing a slot bumps its generation, so a stale
 *     handle from a freed resource never accidentally references
 *     a slot the allocator has reused. `kInvalidGpuResource == 0`.
 *   - Special PID `kPidKernel` (0) tags resources owned by the
 *     kernel itself (e.g. virtio-gpu's scanout backing). The
 *     per-process exit walk skips PID 0; kernel-owned resources
 *     are released explicitly.
 *
 * Context: kernel. Safe to call from task or IRQ context (the
 * spinlock is irq-safe). Must NOT be called while holding the
 * leak detector's ProcessAggCookie lock — that path already
 * reads our snapshot APIs, so the inverse direction would
 * deadlock.
 */

namespace duetos::drivers::gpu
{

/// Special PID value tagging resources the kernel itself owns. The
/// per-process exit walk skips slots tagged with this PID — these
/// outlive any user process and are released through their own
/// driver-shutdown paths.
inline constexpr u64 kPidKernel = 0;

/// Opaque handle. Encoded as
/// `(class_id << 24) | (generation << 16) | index`. Zero is the
/// reserved invalid sentinel; every successful Register returns a
/// non-zero handle. Treat as opaque — never reach inside.
using GpuResourceHandle = u32;
inline constexpr GpuResourceHandle kInvalidGpuResource = 0;

/// Per-class capacities — sized for v0. Each Register call against
/// a full table returns `kInvalidGpuResource` and increments the
/// per-class `register_failed_full_count` (visible via the
/// snapshot's `peak` byte 32–63 in a future audit slice).
inline constexpr u32 kGpuMaxContexts = 256;
inline constexpr u32 kGpuMaxSurfaces = 512;
inline constexpr u32 kGpuMaxCmdBuffers = 256;
inline constexpr u32 kGpuMaxVramAllocs = 512;

/// Resource classes — keep aligned with `ResourceClass::kGpu*` in
/// `kernel/diag/leak_detector.h`. The enum value is what gets
/// packed into a handle's high byte, so reordering is an ABI break.
enum class GpuResourceClass : u8
{
    Context = 1,
    Surface = 2,
    CmdBuffer = 3,
    Vram = 4,
};

/// Aggregate snapshot of one class. Same shape as the leak
/// detector's `GpuClassSnapshot` so the read-side accessors in
/// `gpu_leak.cpp` are direct passthroughs.
struct GpuResourceSnapshot
{
    u64 outstanding;
    u64 peak;
    u64 byte_cost;
};

GpuResourceSnapshot GpuResourcesSnapshot(GpuResourceClass cls);

/// Register a render / compute context owned by `pid`. `tag` is a
/// short label retained as a non-owning pointer (caller must keep
/// the storage alive — typically a string literal). Returns
/// `kInvalidGpuResource` if the table is full.
GpuResourceHandle GpuContextRegister(u64 pid, const char* tag);

/// Release a previously-registered context. Stale handles are
/// silently ignored (the generation check fails before any state
/// is touched). Bumps `outstanding` down by 1.
void GpuContextRelease(GpuResourceHandle h);

/// Register a surface (texture / render target / framebuffer)
/// of `bytes` bytes. `bytes` participates in the class's byte_cost
/// snapshot so a leaked surface visible immediately as a byte
/// regression.
GpuResourceHandle GpuSurfaceRegister(u64 pid, u64 bytes, const char* tag);
void GpuSurfaceRelease(GpuResourceHandle h);

/// Register a command buffer of `bytes` bytes. Drivers should
/// call `GpuCmdBufferRetire` on completion, which is an alias for
/// Release that exists so audit logs can distinguish "user
/// destroyed it" from "GPU finished with it".
GpuResourceHandle GpuCmdBufferRegister(u64 pid, u64 bytes, const char* tag);
void GpuCmdBufferRelease(GpuResourceHandle h);
void GpuCmdBufferRetire(GpuResourceHandle h);

/// Register a VRAM/GTT byte allocation of `bytes` bytes. This is
/// the system-wide GPU memory accounting class.
GpuResourceHandle GpuVramRegister(u64 pid, u64 bytes, const char* tag);
void GpuVramRelease(GpuResourceHandle h);

/// Release every resource owned by `pid`, across all four classes.
/// Returns the total number of resources evicted. Tagged
/// `// GAP:`-free: the implementation walks every table and clears
/// matching slots. Skips `kPidKernel`-tagged resources.
u32 GpuResourcesReleaseByPid(u64 pid);

/// Test-only accessor: total live resources across all classes.
/// Sum of the four class `outstanding` counters. Useful for the
/// self-test's "all clear after release" invariant.
u64 GpuResourcesTotalOutstanding();

void GpuResourcesSelfTest();

} // namespace duetos::drivers::gpu
