#include "core/service.h"

#include "arch/x86_64/serial.h"
#include "fs/ramfs.h"
#include "log/klog.h"
#include "mm/address_space.h"
#include "proc/process.h"
#include "proc/spawn.h"
#include "sched/sched.h"
#include "time/timekeeper.h"
#include "util/string.h"

/*
 * Service manager implementation. See service.h for the design.
 *
 * The manifest is the five oneshot userland programs DuetOS shipped as
 * inline SpawnElfFile blocks in boot_bringup.cpp before this slice
 * (ServiceRestartPolicy::Never — each prints / runs a self-test and
 * exits; the supervisor tracks their Running -> Exited transition so
 * `svc` reports the truth, and the operator can re-run any with
 * `svc start <name>`), plus `netd` — the first resident daemon
 * (restart=Always), a TCP echo server the supervisor keeps alive. So
 * the respawn path is now exercised by a real process as well as by
 * ServiceManagerSelfTest's crash-loop-rate-limiter unit test.
 */

namespace duetos::core
{

namespace
{

// ---- Manifest (constant) ------------------------------------------

constexpr ServiceDesc kManifest[] = {
    {"usershell", "/bin/usershell.elf", ServiceKind::NativeElf, ServiceRestartPolicy::Never, true,
     &duetos::fs::RamfsUsershellElfBytes, &duetos::fs::RamfsUsershellElfSize},
    {"hello_native", "/bin/hello_native", ServiceKind::NativeElf, ServiceRestartPolicy::Never, true,
     &duetos::fs::RamfsHelloNativeBytes, &duetos::fs::RamfsHelloNativeSize},
    {"nat_calc", "/bin/nat_calc", ServiceKind::NativeElf, ServiceRestartPolicy::Never, true,
     &duetos::fs::RamfsNatCalcBytes, &duetos::fs::RamfsNatCalcSize},
    {"nat_sysinfo", "/bin/nat_sysinfo", ServiceKind::NativeElf, ServiceRestartPolicy::Never, true,
     &duetos::fs::RamfsNatSysinfoBytes, &duetos::fs::RamfsNatSysinfoSize},
    {"duet-pkg", "/bin/duet-pkg", ServiceKind::NativeElf, ServiceRestartPolicy::Never, true,
     &duetos::fs::RamfsDuetPkgBytes, &duetos::fs::RamfsDuetPkgSize},
    // First resident daemon: a TCP echo server on :7777. restart=Always
    // — the supervisor keeps it alive (and the crash-loop guard catches
    // a persistently broken net stack). Exercises the Always path with a
    // real process, not just the unit test.
    {"netd", "/bin/netd", ServiceKind::NativeElf, ServiceRestartPolicy::Always, true, &duetos::fs::RamfsNetdBytes,
     &duetos::fs::RamfsNetdSize},
    // Oneshot client: connects to netd and asserts the echo round-trip,
    // proving the resident daemon serves traffic cross-process. Spawned
    // after netd; retries connect while netd finishes binding.
    {"netd_probe", "/bin/netd_probe", ServiceKind::NativeElf, ServiceRestartPolicy::Never, true,
     &duetos::fs::RamfsNetdProbeBytes, &duetos::fs::RamfsNetdProbeSize},
};

constexpr u32 kManifestCount = static_cast<u32>(sizeof(kManifest) / sizeof(kManifest[0]));

// ---- Runtime (mutable, parallel to kManifest) ---------------------

struct ServiceRuntime
{
    ServiceState state;
    u64 pid;
    u32 restarts; // lifetime respawns
    u32 restarts_in_window;
    u64 window_start_ns;
    u64 last_spawn_ns;
    u64 last_exit_ns;
};

constinit ServiceRuntime g_rt[kManifestCount] = {};
constinit bool g_initialized = false;
constinit bool g_supervisor_running = false;

u64 NowNs()
{
    return duetos::time::MonotonicNs();
}

// Crash-loop rate limiter (pure aside from the in/out window state, so
// the self-test can drive it directly). Permits at most
// kServiceRestartMax respawns per kServiceRestartWindowNs; rolls the
// window forward once it elapses. Same shape as the fault-domain
// restart throttle.
bool RateLimitAllow(u32& restarts_in_window, u64& window_start_ns, u64 now_ns)
{
    if (window_start_ns == 0 || now_ns - window_start_ns >= kServiceRestartWindowNs)
    {
        window_start_ns = now_ns;
        restarts_in_window = 0;
    }
    if (restarts_in_window >= kServiceRestartMax)
        return false;
    ++restarts_in_window;
    return true;
}

i32 FindByName(const char* name)
{
    if (name == nullptr)
        return -1;
    for (u32 i = 0; i < kManifestCount; ++i)
    {
        if (StrEqual(kManifest[i].name, name))
            return static_cast<i32>(i);
    }
    return -1;
}

// Load + spawn one manifest entry. Returns the new pid, or 0 on a
// missing blob / load failure.
u64 SpawnService(const ServiceDesc& d)
{
    const u8* bytes = d.bytes != nullptr ? d.bytes() : nullptr;
    const u64 size = d.size != nullptr ? d.size() : 0;
    if (bytes == nullptr || size == 0)
        return 0; // blob not embedded (e.g. cross-toolchain absent at build)
    if (d.kind == ServiceKind::WinPe)
    {
        return duetos::core::SpawnPeFile(d.path, bytes, size, duetos::core::CapSetTrusted(),
                                         duetos::fs::RamfsTrustedRoot(), duetos::mm::kFrameBudgetTrusted,
                                         duetos::core::kTickBudgetTrusted);
    }
    return duetos::core::SpawnElfFile(d.path, bytes, size, duetos::core::CapSetTrusted(),
                                      duetos::fs::RamfsTrustedRoot(), duetos::mm::kFrameBudgetTrusted,
                                      duetos::core::kTickBudgetTrusted);
}

// Start service `idx` from a non-Running state. Updates runtime and
// logs one [svc] line mirroring the old [boot] spawn lines.
void StartIndex(u32 idx)
{
    const ServiceDesc& d = kManifest[idx];
    ServiceRuntime& rt = g_rt[idx];
    const u64 pid = SpawnService(d);
    if (pid == 0)
    {
        rt.state = ServiceState::Failed;
        rt.pid = 0;
        KLOG_WARN("svc", "service spawn failed");
        arch::SerialWrite("[svc] ");
        arch::SerialWrite(d.name);
        arch::SerialWrite(" FAILED (load/spawn)\n");
        return;
    }
    rt.state = ServiceState::Running;
    rt.pid = pid;
    rt.last_spawn_ns = NowNs();
    arch::SerialWrite("[svc] ");
    arch::SerialWrite(d.name);
    arch::SerialWrite(" pid=");
    arch::SerialWriteHex(pid);
    arch::SerialWrite("\n");
}

void SupervisorTask(void* /*arg*/)
{
    for (;;)
    {
        ServiceManagerTick();
        duetos::sched::SchedSleepTicks(100); // ~1 s at 100 Hz
    }
}

} // namespace

void ServiceManagerInit()
{
    if (g_initialized)
        return;
    g_initialized = true;
    for (u32 i = 0; i < kManifestCount; ++i)
    {
        g_rt[i] = ServiceRuntime{};
        g_rt[i].state = ServiceState::Stopped;
    }
}

void ServiceManagerStartAll()
{
    ServiceManagerInit();
    for (u32 i = 0; i < kManifestCount; ++i)
    {
        if (kManifest[i].autostart && g_rt[i].state == ServiceState::Stopped)
            StartIndex(i);
    }
    if (!g_supervisor_running)
    {
        g_supervisor_running = true;
        (void)duetos::sched::SchedCreate(&SupervisorTask, nullptr, "svcmon");
    }
}

void ServiceManagerTick()
{
    const u64 now = NowNs();
    for (u32 i = 0; i < kManifestCount; ++i)
    {
        ServiceRuntime& rt = g_rt[i];
        if (rt.state != ServiceState::Running)
            continue;
        // Liveness MUST include Blocked tasks: a resident daemon spends
        // its life parked in a blocking syscall (e.g. netd in accept()),
        // and a Blocked task is NOT on the runqueue/sleep/zombie lists
        // SchedFindProcessByPid walks — using that here made the
        // supervisor mistake a healthy blocked daemon for a dead one and
        // spawn duplicates that collided on the port. SchedProcessAlive
        // walks the all-tasks registry, so it sees Blocked tasks too.
        // Monotonic PIDs mean a "not alive" verdict can't be a reused id.
        if (duetos::sched::SchedProcessAlive(rt.pid))
            continue;
        rt.state = ServiceState::Exited;
        rt.last_exit_ns = now;
        if (kManifest[i].restart != ServiceRestartPolicy::Always)
            continue;
        if (!RateLimitAllow(rt.restarts_in_window, rt.window_start_ns, now))
        {
            rt.state = ServiceState::Failed;
            KLOG_WARN("svc", "service hit respawn rate limit — giving up");
            continue;
        }
        ++rt.restarts;
        StartIndex(i);
    }
}

bool ServiceStart(const char* name)
{
    const i32 idx = FindByName(name);
    if (idx < 0)
        return false;
    ServiceManagerInit();
    ServiceRuntime& rt = g_rt[idx];
    if (rt.state == ServiceState::Running)
        return true; // already up
    StartIndex(static_cast<u32>(idx));
    return rt.state == ServiceState::Running;
}

bool ServiceStop(const char* name)
{
    const i32 idx = FindByName(name);
    if (idx < 0)
        return false;
    ServiceRuntime& rt = g_rt[idx];
    if (rt.state == ServiceState::Running && rt.pid != 0)
        (void)duetos::sched::SchedKillByPid(rt.pid);
    // Stopped is terminal until the operator restarts it — this also
    // disables the Always respawn path (the tick only acts on Running),
    // so `svc stop` on a daemon actually keeps it down.
    rt.state = ServiceState::Stopped;
    rt.pid = 0;
    return true;
}

bool ServiceRestart(const char* name)
{
    if (!ServiceStop(name))
        return false;
    return ServiceStart(name);
}

u32 ServiceCount()
{
    return kManifestCount;
}

bool ServiceStatusAt(u32 idx, ServiceStatusView* out)
{
    if (idx >= kManifestCount || out == nullptr)
        return false;
    const ServiceDesc& d = kManifest[idx];
    const ServiceRuntime& rt = g_rt[idx];
    out->name = d.name;
    out->state = rt.state;
    out->restart = d.restart;
    out->autostart = d.autostart;
    out->pid = rt.pid;
    out->restarts = rt.restarts;
    out->last_spawn_ns = rt.last_spawn_ns;
    out->last_exit_ns = rt.last_exit_ns;
    return true;
}

void ServiceManagerSelfTest()
{
    // Exercise the crash-loop rate limiter — the one piece of logic the
    // boot path can't otherwise reach (no Always daemon ships yet).
    u32 count = 0;
    u64 window = 0;
    const u64 t0 = 1'000'000'000ull;

    // First kServiceRestartMax respawns inside the window are allowed.
    for (u32 i = 0; i < kServiceRestartMax; ++i)
    {
        if (!RateLimitAllow(count, window, t0))
        {
            arch::SerialWrite("[svc-selftest] FAIL (early deny)\n");
            return;
        }
    }
    // The next one is denied — crash-loop guard tripped.
    if (RateLimitAllow(count, window, t0))
    {
        arch::SerialWrite("[svc-selftest] FAIL (no deny at limit)\n");
        return;
    }
    // After the window elapses, respawns are permitted again.
    if (!RateLimitAllow(count, window, t0 + kServiceRestartWindowNs))
    {
        arch::SerialWrite("[svc-selftest] FAIL (window did not roll)\n");
        return;
    }
    arch::SerialWrite("[svc-selftest] PASS (respawn rate limiter)\n");
}

} // namespace duetos::core
