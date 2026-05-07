#include "diag/leak_detector.h"

#include "debug/probes.h"
#include "drivers/gpu/gpu_leak.h"
#include "ipc/handle_table.h"
#include "log/klog.h"
#include "mm/address_space.h"
#include "mm/frame_allocator.h"
#include "mm/kheap.h"
#include "mm/kstack.h"
#include "net/socket.h"
#include "proc/process.h"
#include "sched/sched.h"
#include "subsystems/win32/gdi_objects.h"

/*
 * DuetOS — leak-detector aggregator implementation.
 *
 * Strictly read-only. Every counter comes from an existing
 * subsystem accessor; this TU folds them into a uniform shape
 * and forwards to the GPU driver's hook on process exit.
 */

namespace duetos::diag
{

namespace
{

// Names match the enum casing for grep-friendliness; the
// `LeakDetectorClassByName` lookup tolerates abbreviations and
// the leading "k".
constexpr const char* kClassNames[static_cast<u64>(ResourceClass::kCount)] = {
    "kHeap",      "kFrame",      "kKStack",     "kAsRegion",   "kHandle",       "kWin32Handle", "kSocket",
    "kGdiObject", "kCpuRunaway", "kGpuContext", "kGpuSurface", "kGpuCmdBuffer", "kGpuMemory",
};

// ---- Per-class snapshot helpers --------------------------------

ClassSnapshot SnapshotHeap()
{
    const auto stats = ::duetos::mm::KernelHeapStatsRead();
    ClassSnapshot s{ResourceClass::kHeap, 0, 0, 0, kClassNames[0]};
    s.outstanding = stats.alloc_count > stats.free_count ? (stats.alloc_count - stats.free_count) : 0;
    s.peak = s.outstanding;
    s.byte_cost = stats.used_bytes;
    return s;
}

ClassSnapshot SnapshotFrame()
{
    const u64 total = ::duetos::mm::TotalFrames();
    const u64 free = ::duetos::mm::FreeFramesCount();
    ClassSnapshot s{ResourceClass::kFrame, 0, 0, 0, kClassNames[1]};
    s.outstanding = total >= free ? (total - free) : 0;
    s.peak = s.outstanding;
    s.byte_cost = s.outstanding * ::duetos::mm::kPageSize;
    return s;
}

ClassSnapshot SnapshotKStack()
{
    const auto stats = ::duetos::mm::KernelStackStatsRead();
    ClassSnapshot s{ResourceClass::kKStack, 0, 0, 0, kClassNames[2]};
    s.outstanding = stats.slots_in_use;
    s.peak = stats.high_water_slots;
    s.byte_cost = stats.slots_in_use * ::duetos::mm::kKernelStackUsableBytes;
    return s;
}

ClassSnapshot SnapshotAsRegion()
{
    const auto stats = ::duetos::mm::AddressSpaceStatsRead();
    ClassSnapshot s{ResourceClass::kAsRegion, 0, 0, 0, kClassNames[3]};
    s.outstanding = stats.live;
    s.peak = stats.created > stats.destroyed ? stats.created : stats.live;
    s.byte_cost = 0;
    return s;
}

// Process walk helpers — gather aggregate counts across every
// live process. Each callback adds to the running totals via
// `cookie`. Reuses `sched::SchedEnumerate` (which already locks
// the scheduler queues) and dedupes by PID so multi-task
// processes are counted once.
struct ProcessAggCookie
{
    u64 handle_table_live;
    u64 win32_handle_live;
    u64 cpu_runaway_count;
    u64 cpu_runaway_ticks_over;
    // Dedupe: keep a small ring of recently seen PIDs. SchedEnumerate
    // visits tasks; we want one row per process.
    static constexpr u64 kSeenCap = 64;
    u64 seen_pids[kSeenCap];
    u64 seen_count;
};

bool PidAlreadyCounted(ProcessAggCookie& c, u64 pid)
{
    for (u64 i = 0; i < c.seen_count; ++i)
    {
        if (c.seen_pids[i] == pid)
            return true;
    }
    if (c.seen_count < ProcessAggCookie::kSeenCap)
    {
        c.seen_pids[c.seen_count++] = pid;
    }
    return false;
}

void CountTaskAgg(const ::duetos::sched::SchedTaskInfo& info, void* cookie)
{
    auto* c = static_cast<ProcessAggCookie*>(cookie);

    // Runaway: a user task whose lifetime ticks_run has crossed
    // 75% of its parent process's tick_budget. Cheap proxy for
    // "burning CPU without yielding"; the scheduler's own
    // `KillReason::TickBudget` path already terminates at 100%.
    if (info.has_process)
    {
        ::duetos::core::Process* p = ::duetos::sched::SchedFindProcessByPid(info.owner_pid);
        if (p != nullptr && p->tick_budget > 0)
        {
            const u64 threshold = (p->tick_budget * 3) / 4;
            if (info.ticks_run >= threshold)
            {
                ++c->cpu_runaway_count;
                if (info.ticks_run >= p->tick_budget)
                {
                    c->cpu_runaway_ticks_over += info.ticks_run - p->tick_budget;
                }
            }
        }
    }

    // Per-process counts: only count once per PID. Kernel-only
    // tasks (no Process) carry no per-process handles, so skip.
    if (!info.has_process)
        return;
    if (PidAlreadyCounted(*c, info.owner_pid))
        return;

    ::duetos::core::Process* p = ::duetos::sched::SchedFindProcessByPid(info.owner_pid);
    if (p == nullptr)
        return;

    c->handle_table_live += ::duetos::ipc::HandleTableLiveCount(p->kobj_handles);

    u64 win32 = 0;
    for (u64 i = 0; i < ::duetos::core::Process::kWin32HandleCap; ++i)
        if (p->win32_handles[i].kind != ::duetos::core::Process::FsBackingKind::None)
            ++win32;
    for (u64 i = 0; i < ::duetos::core::Process::kWin32ThreadCap; ++i)
        if (p->win32_threads[i].in_use)
            ++win32;
    for (u64 i = 0; i < ::duetos::core::Process::kWin32ProcessCap; ++i)
        if (p->win32_proc_handles[i].in_use)
            ++win32;
    for (u64 i = 0; i < ::duetos::core::Process::kWin32ForeignThreadCap; ++i)
        if (p->win32_foreign_threads[i].in_use)
            ++win32;
    for (u64 i = 0; i < ::duetos::core::Process::kWin32SectionCap; ++i)
        if (p->win32_section_handles[i].in_use)
            ++win32;
    for (u64 i = 0; i < ::duetos::core::Process::kWin32DirCap; ++i)
        if (p->win32_dirs[i].entries != nullptr)
            ++win32;
    for (u64 i = 0; i < ::duetos::core::Process::kWin32RegistryCap; ++i)
        if (p->win32_reg_handles[i].in_use)
            ++win32;
    c->win32_handle_live += win32;
}

ClassSnapshot SnapshotHandle(const ProcessAggCookie& c)
{
    return ClassSnapshot{ResourceClass::kHandle, c.handle_table_live, c.handle_table_live, 0, kClassNames[4]};
}

ClassSnapshot SnapshotWin32Handle(const ProcessAggCookie& c)
{
    return ClassSnapshot{ResourceClass::kWin32Handle, c.win32_handle_live, c.win32_handle_live, 0, kClassNames[5]};
}

ClassSnapshot SnapshotSocket()
{
    const auto stats = ::duetos::net::SocketStatsRead();
    ClassSnapshot s{ResourceClass::kSocket, 0, 0, 0, kClassNames[6]};
    s.outstanding = stats.allocs > stats.releases ? (stats.allocs - stats.releases) : 0;
    s.peak = stats.allocs;
    s.byte_cost = 0;
    return s;
}

// GDI is system-wide (not per-process today — known gap). Walk the
// global tables' alive flags and sum the pixel-buffer bytes. Stock
// objects are excluded from the byte cost (they are forever-live by
// design and would otherwise drown out the real signal); they DO
// count toward `outstanding` so the operator sees the table is
// populated.
ClassSnapshot SnapshotGdi()
{
    using namespace ::duetos::subsystems::win32;
    ClassSnapshot s{ResourceClass::kGdiObject, 0, 0, 0, kClassNames[7]};
    u64 outstanding = 0;
    u64 byte_cost = 0;
    // The global tables are file-static in gdi_objects.cpp; we can
    // iterate via the public `GdiLookup*` accessors over each handle
    // index. Index → handle mapping uses the kGdiTag* family.
    for (u32 i = 0; i < kMaxMemDcs; ++i)
    {
        if (GdiLookupMemDC(kGdiTagMemDC | i) != nullptr)
            ++outstanding;
    }
    for (u32 i = 0; i < kMaxBitmaps; ++i)
    {
        const Bitmap* b = GdiLookupBitmap(kGdiTagBitmap | i);
        if (b != nullptr)
        {
            ++outstanding;
            byte_cost += static_cast<u64>(b->pitch) * b->height;
        }
    }
    for (u32 i = 0; i < kMaxBrushes; ++i)
    {
        const Brush* b = GdiLookupBrush(kGdiTagBrush | i);
        if (b != nullptr && !b->stock)
            ++outstanding;
    }
    for (u32 i = 0; i < kMaxPens; ++i)
    {
        const Pen* p = GdiLookupPen(kGdiTagPen | i);
        if (p != nullptr && !p->stock)
            ++outstanding;
    }
    s.outstanding = outstanding;
    s.peak = outstanding;
    s.byte_cost = byte_cost;
    return s;
}

ClassSnapshot SnapshotCpuRunaway(const ProcessAggCookie& c)
{
    return ClassSnapshot{ResourceClass::kCpuRunaway, c.cpu_runaway_count, c.cpu_runaway_count, c.cpu_runaway_ticks_over,
                         kClassNames[8]};
}

ClassSnapshot SnapshotGpuClass(ResourceClass cls, ::duetos::drivers::gpu::GpuClassSnapshot raw)
{
    return ClassSnapshot{cls, raw.outstanding, raw.peak, raw.byte_cost, kClassNames[static_cast<u64>(cls)]};
}

void GatherProcessAgg(ProcessAggCookie& cookie)
{
    cookie.handle_table_live = 0;
    cookie.win32_handle_live = 0;
    cookie.cpu_runaway_count = 0;
    cookie.cpu_runaway_ticks_over = 0;
    cookie.seen_count = 0;
    ::duetos::sched::SchedEnumerate(&CountTaskAgg, &cookie);
}

// Case-insensitive C-string compare (no <strings.h> in
// freestanding). Tolerates leading "k" / "Gpu" prefixes for shell
// lookup convenience.
char ToLower(char c)
{
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

bool MatchesCi(const char* a, const char* b)
{
    while (*a != 0 && *b != 0)
    {
        if (ToLower(*a) != ToLower(*b))
            return false;
        ++a;
        ++b;
    }
    return *a == *b;
}

bool MatchesCiSkipPrefix(const char* enum_name, const char* user)
{
    const char* en = enum_name;
    if (en[0] == 'k')
        ++en;
    return MatchesCi(en, user);
}

} // namespace

void LeakDetectorSnapshotAll(ClassSnapshot* out)
{
    if (out == nullptr)
        return;
    ProcessAggCookie cookie{};
    GatherProcessAgg(cookie);

    out[static_cast<u64>(ResourceClass::kHeap)] = SnapshotHeap();
    out[static_cast<u64>(ResourceClass::kFrame)] = SnapshotFrame();
    out[static_cast<u64>(ResourceClass::kKStack)] = SnapshotKStack();
    out[static_cast<u64>(ResourceClass::kAsRegion)] = SnapshotAsRegion();
    out[static_cast<u64>(ResourceClass::kHandle)] = SnapshotHandle(cookie);
    out[static_cast<u64>(ResourceClass::kWin32Handle)] = SnapshotWin32Handle(cookie);
    out[static_cast<u64>(ResourceClass::kSocket)] = SnapshotSocket();
    out[static_cast<u64>(ResourceClass::kGdiObject)] = SnapshotGdi();
    out[static_cast<u64>(ResourceClass::kCpuRunaway)] = SnapshotCpuRunaway(cookie);
    out[static_cast<u64>(ResourceClass::kGpuContext)] =
        SnapshotGpuClass(ResourceClass::kGpuContext, ::duetos::drivers::gpu::GpuLeakSnapshotContexts());
    out[static_cast<u64>(ResourceClass::kGpuSurface)] =
        SnapshotGpuClass(ResourceClass::kGpuSurface, ::duetos::drivers::gpu::GpuLeakSnapshotSurfaces());
    out[static_cast<u64>(ResourceClass::kGpuCmdBuffer)] =
        SnapshotGpuClass(ResourceClass::kGpuCmdBuffer, ::duetos::drivers::gpu::GpuLeakSnapshotCmdBuffers());
    out[static_cast<u64>(ResourceClass::kGpuMemory)] =
        SnapshotGpuClass(ResourceClass::kGpuMemory, ::duetos::drivers::gpu::GpuLeakSnapshotVram());
}

ResourceClass LeakDetectorClassByName(const char* name)
{
    if (name == nullptr || name[0] == 0)
        return ResourceClass::kCount;
    for (u64 i = 0; i < static_cast<u64>(ResourceClass::kCount); ++i)
    {
        if (MatchesCi(kClassNames[i], name) || MatchesCiSkipPrefix(kClassNames[i], name))
            return static_cast<ResourceClass>(i);
    }
    return ResourceClass::kCount;
}

u32 LeakDetectorTopHeapByRip(::duetos::mm::HeapLeakEntry* out, u32 cap)
{
    return ::duetos::mm::KernelHeapTopAllocators(out, cap);
}

bool LeakDetectorSnapshotPid(u64 pid, ClassSnapshot* out)
{
    if (out == nullptr)
        return false;
    ::duetos::core::Process* p = ::duetos::sched::SchedFindProcessByPid(pid);
    if (p == nullptr)
        return false;

    // Build a cookie that contains only this process's contribution.
    ProcessAggCookie cookie{};
    cookie.handle_table_live = ::duetos::ipc::HandleTableLiveCount(p->kobj_handles);
    u64 w32 = 0;
    for (u64 i = 0; i < ::duetos::core::Process::kWin32HandleCap; ++i)
        if (p->win32_handles[i].kind != ::duetos::core::Process::FsBackingKind::None)
            ++w32;
    for (u64 i = 0; i < ::duetos::core::Process::kWin32ThreadCap; ++i)
        if (p->win32_threads[i].in_use)
            ++w32;
    for (u64 i = 0; i < ::duetos::core::Process::kWin32ProcessCap; ++i)
        if (p->win32_proc_handles[i].in_use)
            ++w32;
    for (u64 i = 0; i < ::duetos::core::Process::kWin32ForeignThreadCap; ++i)
        if (p->win32_foreign_threads[i].in_use)
            ++w32;
    for (u64 i = 0; i < ::duetos::core::Process::kWin32SectionCap; ++i)
        if (p->win32_section_handles[i].in_use)
            ++w32;
    for (u64 i = 0; i < ::duetos::core::Process::kWin32DirCap; ++i)
        if (p->win32_dirs[i].entries != nullptr)
            ++w32;
    for (u64 i = 0; i < ::duetos::core::Process::kWin32RegistryCap; ++i)
        if (p->win32_reg_handles[i].in_use)
            ++w32;
    cookie.win32_handle_live = w32;

    // CpuRunaway: this process's tasks above 75% budget.
    if (p->tick_budget > 0)
    {
        const u64 threshold = (p->tick_budget * 3) / 4;
        if (p->ticks_used >= threshold)
        {
            cookie.cpu_runaway_count = 1;
            if (p->ticks_used >= p->tick_budget)
                cookie.cpu_runaway_ticks_over = p->ticks_used - p->tick_budget;
        }
    }

    out[static_cast<u64>(ResourceClass::kHeap)] = ClassSnapshot{ResourceClass::kHeap, 0, 0, 0, kClassNames[0]};
    out[static_cast<u64>(ResourceClass::kFrame)] = ClassSnapshot{
        ResourceClass::kFrame, p->as != nullptr ? static_cast<u64>(p->as->region_count) : 0, 0,
        p->as != nullptr ? static_cast<u64>(p->as->region_count) * ::duetos::mm::kPageSize : 0, kClassNames[1]};
    out[static_cast<u64>(ResourceClass::kKStack)] = ClassSnapshot{ResourceClass::kKStack, 0, 0, 0, kClassNames[2]};
    out[static_cast<u64>(ResourceClass::kAsRegion)] = ClassSnapshot{
        ResourceClass::kAsRegion, p->as != nullptr ? static_cast<u64>(p->as->region_count) : 0, 0, 0, kClassNames[3]};
    out[static_cast<u64>(ResourceClass::kHandle)] = SnapshotHandle(cookie);
    out[static_cast<u64>(ResourceClass::kWin32Handle)] = SnapshotWin32Handle(cookie);
    out[static_cast<u64>(ResourceClass::kSocket)] = ClassSnapshot{ResourceClass::kSocket, 0, 0, 0, kClassNames[6]};
    out[static_cast<u64>(ResourceClass::kGdiObject)] =
        ClassSnapshot{ResourceClass::kGdiObject, 0, 0, 0, kClassNames[7]};
    out[static_cast<u64>(ResourceClass::kCpuRunaway)] = SnapshotCpuRunaway(cookie);
    // GPU per-PID: filled by the GPU driver in the future. Today
    // every count is global-only — the driver's exit hook attributes
    // residue when the slice lands.
    out[static_cast<u64>(ResourceClass::kGpuContext)] =
        ClassSnapshot{ResourceClass::kGpuContext, 0, 0, 0, kClassNames[9]};
    out[static_cast<u64>(ResourceClass::kGpuSurface)] =
        ClassSnapshot{ResourceClass::kGpuSurface, 0, 0, 0, kClassNames[10]};
    out[static_cast<u64>(ResourceClass::kGpuCmdBuffer)] =
        ClassSnapshot{ResourceClass::kGpuCmdBuffer, 0, 0, 0, kClassNames[11]};
    out[static_cast<u64>(ResourceClass::kGpuMemory)] =
        ClassSnapshot{ResourceClass::kGpuMemory, 0, 0, 0, kClassNames[12]};
    return true;
}

void LeakDetectorReportProcessExit(const ::duetos::core::Process& p)
{
    // Per-process tables we expect to be drained by ProcessRelease's
    // earlier steps. Anything still live here is a leak attributable
    // to this PID.
    const u32 handle_live =
        ::duetos::ipc::HandleTableLiveCount(const_cast<::duetos::ipc::HandleTable&>(p.kobj_handles));

    u32 w32 = 0;
    for (u64 i = 0; i < ::duetos::core::Process::kWin32HandleCap; ++i)
        if (p.win32_handles[i].kind != ::duetos::core::Process::FsBackingKind::None)
            ++w32;
    for (u64 i = 0; i < ::duetos::core::Process::kWin32ThreadCap; ++i)
        if (p.win32_threads[i].in_use)
            ++w32;
    for (u64 i = 0; i < ::duetos::core::Process::kWin32ProcessCap; ++i)
        if (p.win32_proc_handles[i].in_use)
            ++w32;
    for (u64 i = 0; i < ::duetos::core::Process::kWin32ForeignThreadCap; ++i)
        if (p.win32_foreign_threads[i].in_use)
            ++w32;
    for (u64 i = 0; i < ::duetos::core::Process::kWin32SectionCap; ++i)
        if (p.win32_section_handles[i].in_use)
            ++w32;
    for (u64 i = 0; i < ::duetos::core::Process::kWin32DirCap; ++i)
        if (p.win32_dirs[i].entries != nullptr)
            ++w32;
    for (u64 i = 0; i < ::duetos::core::Process::kWin32RegistryCap; ++i)
        if (p.win32_reg_handles[i].in_use)
            ++w32;

    const u64 over_budget = (p.tick_budget > 0 && p.ticks_used > p.tick_budget) ? (p.ticks_used - p.tick_budget) : 0;

    // Pull the GPU per-class snapshots so the GPU driver's exit hook
    // can cross-check (no-op today; real walk lands with the GPU
    // slice). The detector itself does NOT decide the GPU residue —
    // the driver owns that bookkeeping.
    const ::duetos::drivers::gpu::GpuClassSnapshot gpu[4] = {
        ::duetos::drivers::gpu::GpuLeakSnapshotContexts(),
        ::duetos::drivers::gpu::GpuLeakSnapshotSurfaces(),
        ::duetos::drivers::gpu::GpuLeakSnapshotCmdBuffers(),
        ::duetos::drivers::gpu::GpuLeakSnapshotVram(),
    };
    ::duetos::drivers::gpu::GpuLeakReportProcessExit(p.pid, gpu);

    const u64 total = static_cast<u64>(handle_live) + static_cast<u64>(w32) + over_budget;
    if (total == 0)
        return; // clean exit — stay silent at default log levels

    KLOG_WARN_2V("diag/leak_detector", "process exit residue", "pid", p.pid, "attributable", total);
    if (handle_live != 0)
    {
        KLOG_DEBUG_V("diag/leak_detector", "  kobj handle slots still live", handle_live);
    }
    if (w32 != 0)
    {
        KLOG_DEBUG_V("diag/leak_detector", "  win32 handle slots still live", w32);
    }
    if (over_budget != 0)
    {
        KLOG_DEBUG_V("diag/leak_detector", "  ticks over budget", over_budget);
    }
    KBP_PROBE_V(::duetos::debug::ProbeId::kLeakAttributable, total);
}

} // namespace duetos::diag
