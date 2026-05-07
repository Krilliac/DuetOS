#include "drivers/gpu/gpu_resources.h"

#include "core/panic.h"
#include "log/klog.h"
#include "sync/spinlock.h"
#include "util/types.h"

/*
 * DuetOS — GPU resource lifetime tables (implementation).
 *
 * See `gpu_resources.h` for the contract. This TU owns four
 * fixed-size slot tables, one spinlock, and per-class peak
 * counters that drive the leak detector's read side.
 */

namespace duetos::drivers::gpu
{

namespace
{

struct Slot
{
    bool in_use;
    u8 generation; // bumped on Release; survives slot reuse
    u64 pid;
    u64 bytes;
    const char* tag;
};

template <u32 Cap> struct ClassTable
{
    Slot slots[Cap];
    u64 outstanding;
    u64 peak;
    u64 byte_cost;
    u64 byte_peak;
    // Audit counters — useful when a leak shows up: who tried to
    // register but couldn't, and who released a stale handle.
    u64 register_failed_full;
    u64 release_stale;
};

constinit ClassTable<kGpuMaxContexts> g_contexts{};
constinit ClassTable<kGpuMaxSurfaces> g_surfaces{};
constinit ClassTable<kGpuMaxCmdBuffers> g_cmdbufs{};
constinit ClassTable<kGpuMaxVramAllocs> g_vram{};

constinit ::duetos::sync::SpinLock g_lock{};

constexpr u32 PackHandle(GpuResourceClass cls, u8 gen, u32 index)
{
    return (static_cast<u32>(cls) << 24) | (static_cast<u32>(gen) << 16) | (index & 0xFFFFu);
}

GpuResourceClass HandleClass(GpuResourceHandle h)
{
    return static_cast<GpuResourceClass>((h >> 24) & 0xFFu);
}

u8 HandleGen(GpuResourceHandle h)
{
    return static_cast<u8>((h >> 16) & 0xFFu);
}

u32 HandleIndex(GpuResourceHandle h)
{
    return h & 0xFFFFu;
}

template <u32 Cap>
GpuResourceHandle RegisterIn(ClassTable<Cap>& table, GpuResourceClass cls, u64 pid, u64 bytes, const char* tag)
{
    ::duetos::sync::SpinLockGuard guard{g_lock};
    for (u32 i = 0; i < Cap; ++i)
    {
        Slot& s = table.slots[i];
        if (!s.in_use)
        {
            s.in_use = true;
            s.pid = pid;
            s.bytes = bytes;
            s.tag = tag;
            ++table.outstanding;
            if (table.outstanding > table.peak)
                table.peak = table.outstanding;
            table.byte_cost += bytes;
            if (table.byte_cost > table.byte_peak)
                table.byte_peak = table.byte_cost;
            return PackHandle(cls, s.generation, i);
        }
    }
    ++table.register_failed_full;
    return kInvalidGpuResource;
}

template <u32 Cap> bool ReleaseIn(ClassTable<Cap>& table, GpuResourceHandle h)
{
    if (h == kInvalidGpuResource)
        return false;
    const u32 idx = HandleIndex(h);
    if (idx >= Cap)
        return false;
    ::duetos::sync::SpinLockGuard guard{g_lock};
    Slot& s = table.slots[idx];
    if (!s.in_use || s.generation != HandleGen(h))
    {
        ++table.release_stale;
        return false;
    }
    table.byte_cost -= s.bytes;
    --table.outstanding;
    s.in_use = false;
    s.pid = 0;
    s.bytes = 0;
    s.tag = nullptr;
    // 8-bit generation wraps after 256 reuses; that's fine — a
    // stale handle from 256 generations ago is essentially never
    // a real concern, and a wrap can only ever trip on an exact
    // (index, generation) collision which is a 1-in-256 chance
    // for a use-after-free that itself is already a bug.
    ++s.generation;
    return true;
}

template <u32 Cap> u32 ReleaseByPidIn(ClassTable<Cap>& table, u64 pid)
{
    if (pid == kPidKernel)
        return 0;
    ::duetos::sync::SpinLockGuard guard{g_lock};
    u32 evicted = 0;
    for (u32 i = 0; i < Cap; ++i)
    {
        Slot& s = table.slots[i];
        if (s.in_use && s.pid == pid)
        {
            table.byte_cost -= s.bytes;
            --table.outstanding;
            s.in_use = false;
            s.pid = 0;
            s.bytes = 0;
            s.tag = nullptr;
            ++s.generation;
            ++evicted;
        }
    }
    return evicted;
}

template <u32 Cap> GpuResourceSnapshot SnapshotIn(const ClassTable<Cap>& table)
{
    ::duetos::sync::SpinLockGuard guard{g_lock};
    return GpuResourceSnapshot{table.outstanding, table.peak, table.byte_cost};
}

} // namespace

GpuResourceSnapshot GpuResourcesSnapshot(GpuResourceClass cls)
{
    switch (cls)
    {
    case GpuResourceClass::Context:
        return SnapshotIn(g_contexts);
    case GpuResourceClass::Surface:
        return SnapshotIn(g_surfaces);
    case GpuResourceClass::CmdBuffer:
        return SnapshotIn(g_cmdbufs);
    case GpuResourceClass::Vram:
        return SnapshotIn(g_vram);
    }
    return GpuResourceSnapshot{0, 0, 0};
}

GpuResourceHandle GpuContextRegister(u64 pid, const char* tag)
{
    return RegisterIn(g_contexts, GpuResourceClass::Context, pid, 0, tag);
}

void GpuContextRelease(GpuResourceHandle h)
{
    if (HandleClass(h) != GpuResourceClass::Context)
        return;
    (void)ReleaseIn(g_contexts, h);
}

GpuResourceHandle GpuSurfaceRegister(u64 pid, u64 bytes, const char* tag)
{
    return RegisterIn(g_surfaces, GpuResourceClass::Surface, pid, bytes, tag);
}

void GpuSurfaceRelease(GpuResourceHandle h)
{
    if (HandleClass(h) != GpuResourceClass::Surface)
        return;
    (void)ReleaseIn(g_surfaces, h);
}

GpuResourceHandle GpuCmdBufferRegister(u64 pid, u64 bytes, const char* tag)
{
    return RegisterIn(g_cmdbufs, GpuResourceClass::CmdBuffer, pid, bytes, tag);
}

void GpuCmdBufferRelease(GpuResourceHandle h)
{
    if (HandleClass(h) != GpuResourceClass::CmdBuffer)
        return;
    (void)ReleaseIn(g_cmdbufs, h);
}

void GpuCmdBufferRetire(GpuResourceHandle h)
{
    GpuCmdBufferRelease(h);
}

GpuResourceHandle GpuVramRegister(u64 pid, u64 bytes, const char* tag)
{
    return RegisterIn(g_vram, GpuResourceClass::Vram, pid, bytes, tag);
}

void GpuVramRelease(GpuResourceHandle h)
{
    if (HandleClass(h) != GpuResourceClass::Vram)
        return;
    (void)ReleaseIn(g_vram, h);
}

u32 GpuResourcesReleaseByPid(u64 pid)
{
    u32 total = 0;
    total += ReleaseByPidIn(g_contexts, pid);
    total += ReleaseByPidIn(g_surfaces, pid);
    total += ReleaseByPidIn(g_cmdbufs, pid);
    total += ReleaseByPidIn(g_vram, pid);
    return total;
}

u64 GpuResourcesTotalOutstanding()
{
    ::duetos::sync::SpinLockGuard guard{g_lock};
    return g_contexts.outstanding + g_surfaces.outstanding + g_cmdbufs.outstanding + g_vram.outstanding;
}

void GpuResourcesSelfTest()
{
    KLOG_TRACE_SCOPE("drivers/gpu/gpu_resources", "SelfTest");
    // Capture pre-test state so we don't disturb anything a
    // driver registered before us (virtio-gpu may have already
    // claimed its scanout).
    const auto pre_ctx = GpuResourcesSnapshot(GpuResourceClass::Context);
    const auto pre_surf = GpuResourcesSnapshot(GpuResourceClass::Surface);
    const auto pre_cb = GpuResourcesSnapshot(GpuResourceClass::CmdBuffer);
    const auto pre_vram = GpuResourcesSnapshot(GpuResourceClass::Vram);

    constexpr u64 kFakePidA = 0x1111;
    constexpr u64 kFakePidB = 0x2222;

    // Register a context for two fake PIDs and verify outstanding
    // bumps + handles are non-zero + class encoding round-trips.
    auto ctxA = GpuContextRegister(kFakePidA, "self-test-ctxA");
    auto ctxB = GpuContextRegister(kFakePidB, "self-test-ctxB");
    KASSERT(ctxA != kInvalidGpuResource, "drivers/gpu/gpu_resources", "context register failed");
    KASSERT(ctxB != kInvalidGpuResource, "drivers/gpu/gpu_resources", "context register failed");
    KASSERT(HandleClass(ctxA) == GpuResourceClass::Context, "drivers/gpu/gpu_resources", "wrong class in handle");
    KASSERT(GpuResourcesSnapshot(GpuResourceClass::Context).outstanding == pre_ctx.outstanding + 2,
            "drivers/gpu/gpu_resources", "context outstanding did not bump by 2");

    // Surfaces with byte cost — verify byte_cost participates.
    auto surfA = GpuSurfaceRegister(kFakePidA, 4096, "self-test-surfA");
    auto surfB = GpuSurfaceRegister(kFakePidB, 8192, "self-test-surfB");
    KASSERT(surfA != kInvalidGpuResource, "drivers/gpu/gpu_resources", "surface register failed");
    KASSERT(GpuResourcesSnapshot(GpuResourceClass::Surface).byte_cost == pre_surf.byte_cost + 4096 + 8192,
            "drivers/gpu/gpu_resources", "surface byte_cost did not include both");

    // CmdBuf + VRAM smoke.
    auto cb = GpuCmdBufferRegister(kFakePidA, 256, "self-test-cb");
    auto vram = GpuVramRegister(kFakePidB, 0x10000, "self-test-vram");
    KASSERT(cb != kInvalidGpuResource && vram != kInvalidGpuResource, "drivers/gpu/gpu_resources",
            "cmdbuf/vram register failed");

    // Stale handle: release once, then again — second call must
    // not double-decrement outstanding.
    GpuContextRelease(ctxA);
    const u64 after_first_release = GpuResourcesSnapshot(GpuResourceClass::Context).outstanding;
    GpuContextRelease(ctxA); // stale
    KASSERT(GpuResourcesSnapshot(GpuResourceClass::Context).outstanding == after_first_release,
            "drivers/gpu/gpu_resources", "stale handle release double-decremented");

    // Wrong-class release: passing a Context handle to
    // SurfaceRelease must be a no-op.
    auto ctxC = GpuContextRegister(kFakePidA, "self-test-ctxC");
    const u64 surf_before = GpuResourcesSnapshot(GpuResourceClass::Surface).outstanding;
    GpuSurfaceRelease(ctxC); // wrong class
    KASSERT(GpuResourcesSnapshot(GpuResourceClass::Surface).outstanding == surf_before, "drivers/gpu/gpu_resources",
            "wrong-class release leaked into surfaces");
    GpuContextRelease(ctxC);

    // Per-PID eviction: PID A still owns ctxB? No — ctxB is PID B.
    // Only the surfA + cb belong to PID A right now.
    const u64 before_evict_total = GpuResourcesTotalOutstanding();
    const u32 evicted = GpuResourcesReleaseByPid(kFakePidA);
    KASSERT(evicted == 2, "drivers/gpu/gpu_resources", "expected 2 PID-A evictions (surfA + cb)");
    KASSERT(GpuResourcesTotalOutstanding() == before_evict_total - 2, "drivers/gpu/gpu_resources",
            "total outstanding did not drop by evicted count");

    // PID 0 (kernel) is skipped: register a kernel-owned resource,
    // call ReleaseByPid(0), verify it survives.
    auto kctx = GpuContextRegister(kPidKernel, "self-test-kernel");
    KASSERT(GpuResourcesReleaseByPid(kPidKernel) == 0, "drivers/gpu/gpu_resources",
            "ReleaseByPid(kernel) must be a no-op");
    GpuContextRelease(kctx);

    // Clean up any remaining registrations from this test so the
    // subsequent leak-detector reading reflects only real driver
    // state (not test residue).
    GpuContextRelease(ctxB);
    GpuSurfaceRelease(surfB);
    GpuVramRelease(vram);

    // Final invariant: every counter is back to its pre-test
    // value. Non-zero residue here means the test leaked.
    const auto post_ctx = GpuResourcesSnapshot(GpuResourceClass::Context);
    const auto post_surf = GpuResourcesSnapshot(GpuResourceClass::Surface);
    const auto post_cb = GpuResourcesSnapshot(GpuResourceClass::CmdBuffer);
    const auto post_vram = GpuResourcesSnapshot(GpuResourceClass::Vram);
    KASSERT(post_ctx.outstanding == pre_ctx.outstanding, "drivers/gpu/gpu_resources",
            "context outstanding leaked across self-test");
    KASSERT(post_surf.outstanding == pre_surf.outstanding, "drivers/gpu/gpu_resources",
            "surface outstanding leaked across self-test");
    KASSERT(post_cb.outstanding == pre_cb.outstanding, "drivers/gpu/gpu_resources",
            "cmdbuf outstanding leaked across self-test");
    KASSERT(post_vram.outstanding == pre_vram.outstanding, "drivers/gpu/gpu_resources",
            "vram outstanding leaked across self-test");

    KLOG_INFO("drivers/gpu/gpu_resources",
              "self-test OK (register + handle ABI + stale release + per-PID eviction + kernel-pid skip)");
}

} // namespace duetos::drivers::gpu
