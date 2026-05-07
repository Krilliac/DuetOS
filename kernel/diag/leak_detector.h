#pragma once

#include "mm/kheap.h"
#include "util/types.h"

/*
 * DuetOS — unified resource leak detector (read-only aggregator).
 *
 * Each kernel subsystem already tracks its own resource lifetimes:
 *   - `KernelHeapTopAllocators` ranks heap chunks by caller RIP.
 *   - `FreeFramesCount` / `TotalFrames` count physical frames.
 *   - `KernelStackStatsRead` exposes kernel-stack arena occupancy.
 *   - `AddressSpaceStatsRead` counts live address spaces.
 *   - `HandleTableLiveCount` reports per-process kobject handles.
 *   - `SocketStatsRead` reports socket pool occupancy.
 *   - GDI tables carry `alive` flags per slot.
 *   - Per-task `ticks_run` flags runaway threads.
 *   - `gpu_leak.h` exposes per-class GPU snapshots (zero today).
 *
 * This module folds those signals into a single operator-grade
 * surface with two trigger points:
 *
 *   1. The shell command `leakcheck` — on-demand summary, per-class
 *      detail, and per-PID attribution.
 *
 *   2. `LeakDetectorReportProcessExit(p)` — called from
 *      `ProcessRelease()` after `HandleTableDrain()` and before
 *      `KFree(p)`, so any residue the dying process owned is
 *      reported with full PID context. Fires the
 *      `kLeakAttributable` probe so an attached GDB can break the
 *      moment a leak is first observed.
 *
 * No new tracking lives here — every counter is read through the
 * owning subsystem's existing accessor. No locks held across class
 * boundaries; each subsystem's own lock stays authoritative.
 *
 * Context: kernel. Safe from any kernel-task context. Not safe to
 * call from IRQ context (some accessors take subsystem spinlocks).
 */

namespace duetos::core
{
struct Process;
} // namespace duetos::core

namespace duetos::diag
{

/// One resource class the detector reports on. Order is stable —
/// the integer values are exposed via the shell. New classes go
/// at the end (before `kCount`); never renumber.
enum class ResourceClass : u8
{
    kHeap = 0,     // mm/kheap   — KMalloc bytes outstanding
    kFrame,        // mm/frames  — 4 KiB frames in use
    kKStack,       // mm/kstack  — kernel-stack arena slots in use
    kAsRegion,     // mm/as      — live AddressSpace count
    kHandle,       // ipc/handle — kobject slots across all live processes
    kWin32Handle,  // win32      — Win32 per-process handle slots
    kSocket,       // net/socket — socket pool slots in use
    kGdiObject,    // win32/gdi  — MemDC + Bitmap + Brush + Pen alive count
    kCpuRunaway,   // sched      — tasks accumulating ticks past peer median
    kGpuContext,   // gpu        — per-process GPU contexts (zero today)
    kGpuSurface,   // gpu        — surfaces / framebuffers (zero today)
    kGpuCmdBuffer, // gpu        — submitted-not-retired command buffers (zero today)
    kGpuMemory,    // gpu        — VRAM / GTT bytes outstanding (zero today)
    kCount,
};

/// One row of the leakcheck report. `outstanding` is the live
/// count for the class; `peak` is the lifetime high-water (when
/// the subsystem records one) and matches `outstanding` when no
/// peak is tracked. `byte_cost` is the live byte total for byte-
/// shaped classes (heap, frames, vram); 0 for count-shaped classes
/// (handles, sockets). `name` is a stable short token for shell
/// output and per-class lookup.
struct ClassSnapshot
{
    ResourceClass cls;
    u64 outstanding;
    u64 peak;
    u64 byte_cost;
    const char* name;
};

/// Take a snapshot of every class. `out` must hold at least
/// `static_cast<u64>(ResourceClass::kCount)` entries — fill order
/// matches the enum. Cheap; no allocation, no blocking.
void LeakDetectorSnapshotAll(ClassSnapshot* out);

/// Resolve a class by name (e.g. "kHeap", "heap", "frames",
/// "gpu.contexts"). Returns `ResourceClass::kCount` on no match.
/// Tolerates the leading "k" and "Gpu" prefixes for shell-typing
/// convenience.
ResourceClass LeakDetectorClassByName(const char* name);

/// Top-N heap allocators by caller RIP. Thin forward to
/// `mm::KernelHeapTopAllocators` — kept here so the shell can hit
/// one entry point for every leakcheck variant.
u32 LeakDetectorTopHeapByRip(::duetos::mm::HeapLeakEntry* out, u32 cap);

/// Snapshot a specific PID's per-process attributable residue.
/// Walks the process's handle tables, GDI is reported global (no
/// per-PID GDI ownership today — known gap, see comment in cpp).
/// Returns false if no live process matches `pid`.
bool LeakDetectorSnapshotPid(u64 pid, ClassSnapshot* out);

/// Hook called from `ProcessRelease()` after `HandleTableDrain()`
/// and before the AS / Process struct is freed. Reads anything
/// still attributable to `p`, emits one `KLOG_WARN` line per
/// non-zero class plus a `kLeakAttributable` probe fire, and
/// forwards to `GpuLeakReportProcessExit` so the GPU driver can
/// cross-check against its own tables. No-op when the process
/// shows no residue (the clean-exit path).
void LeakDetectorReportProcessExit(const ::duetos::core::Process& p);

} // namespace duetos::diag
