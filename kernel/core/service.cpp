#include "core/service.h"

#include "arch/x86_64/serial.h"
#include "fs/ramfs.h"
#include "log/klog.h"
#include "mm/address_space.h"
#include "proc/process.h"
#include "proc/spawn.h"
#include "sched/sched.h"
#include "sync/spinlock.h"
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
    bool restart_window_active;
    u64 last_spawn_ns;
    u64 last_exit_ns;
    // Every start/stop/restart reservation advances this non-wrapping token.
    // A spawn performed without the lock may publish only if its token still
    // matches.  Stop can therefore cancel an in-flight spawn without waiting
    // under the runtime spinlock.
    u64 transition_generation;
    bool desired_running;
    bool start_in_flight;
};

constinit ServiceRuntime g_rt[kManifestCount] = {};
constinit bool g_initialized = false;
constinit bool g_supervisor_running = false;
sync::SpinLock g_service_lock{};

struct StartReservation
{
    u32 index;
    u64 generation;
    bool valid;
};

enum class StartCommitResult : u8
{
    Published,
    Failed,
    Cancelled,
};

u64 NowNs()
{
    return duetos::time::MonotonicNs();
}

// Crash-loop rate limiter (pure aside from the in/out window state, so
// the self-test can drive it directly). Permits at most
// kServiceRestartMax respawns per kServiceRestartWindowNs; rolls the
// window forward once it elapses. Same shape as the fault-domain
// restart throttle.
bool RateLimitAllow(ServiceRuntime& runtime, u64 now_ns)
{
    if (!runtime.restart_window_active || now_ns < runtime.window_start_ns ||
        now_ns - runtime.window_start_ns >= kServiceRestartWindowNs)
    {
        runtime.restart_window_active = true;
        runtime.window_start_ns = now_ns;
        runtime.restarts_in_window = 0;
    }
    if (runtime.restarts_in_window >= kServiceRestartMax)
        return false;
    ++runtime.restarts_in_window;
    return true;
}

void InitLocked()
{
    if (g_initialized)
        return;
    for (u32 i = 0; i < kManifestCount; ++i)
    {
        g_rt[i] = ServiceRuntime{};
        g_rt[i].state = ServiceState::Stopped;
    }
    g_initialized = true;
}

bool ReserveStartRuntimeLocked(ServiceRuntime& runtime, u64& generation)
{
    if ((runtime.state == ServiceState::Running && runtime.desired_running) ||
        (runtime.start_in_flight && runtime.desired_running))
    {
        return false;
    }
    if (runtime.transition_generation == ~0ULL)
    {
        runtime.state = ServiceState::Failed;
        runtime.pid = 0;
        runtime.desired_running = false;
        runtime.start_in_flight = false;
        return false;
    }

    ++runtime.transition_generation;
    runtime.desired_running = true;
    runtime.start_in_flight = true;
    generation = runtime.transition_generation;
    return true;
}

bool ReserveStartLocked(u32 index, StartReservation& reservation)
{
    if (index >= kManifestCount)
        return false;
    ServiceRuntime& runtime = g_rt[index];
    u64 generation = 0;
    if (!ReserveStartRuntimeLocked(runtime, generation))
        return false;
    reservation.index = index;
    reservation.generation = generation;
    reservation.valid = true;
    return true;
}

StartCommitResult CommitStartRuntimeLocked(ServiceRuntime& runtime, u64 generation, u64 pid, u64 now_ns)
{
    if (generation == 0 || !runtime.start_in_flight || runtime.transition_generation != generation ||
        !runtime.desired_running)
    {
        return StartCommitResult::Cancelled;
    }

    runtime.start_in_flight = false;
    if (pid == 0)
    {
        runtime.state = ServiceState::Failed;
        runtime.pid = 0;
        return StartCommitResult::Failed;
    }

    runtime.state = ServiceState::Running;
    runtime.pid = pid;
    runtime.last_spawn_ns = now_ns;
    return StartCommitResult::Published;
}

StartCommitResult CommitStartLocked(const StartReservation& reservation, u64 pid, u64 now_ns)
{
    if (!reservation.valid || reservation.index >= kManifestCount)
        return StartCommitResult::Cancelled;
    return CommitStartRuntimeLocked(g_rt[reservation.index], reservation.generation, pid, now_ns);
}

u64 StopLocked(ServiceRuntime& runtime)
{
    const u64 pid = runtime.state == ServiceState::Running ? runtime.pid : 0;
    if (runtime.transition_generation != ~0ULL)
        ++runtime.transition_generation;
    runtime.desired_running = false;
    runtime.start_in_flight = false;
    runtime.state = ServiceState::Stopped;
    runtime.pid = 0;
    return pid;
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

// Execute a reserved spawn without g_service_lock, then publish it only if
// the exact transition token is still current.  A concurrent Stop invalidates
// the token; any process created after that cancellation is killed outside the
// lock and never becomes the recorded service instance.
bool ExecuteStart(const StartReservation& reservation)
{
    if (!reservation.valid || reservation.index >= kManifestCount || reservation.generation == 0)
        return false;
    const ServiceDesc& d = kManifest[reservation.index];
    const u64 pid = SpawnService(d);
    const u64 now_ns = NowNs();
    StartCommitResult result;
    {
        sync::SpinLockGuard guard(g_service_lock);
        result = CommitStartLocked(reservation, pid, now_ns);
    }

    if (result == StartCommitResult::Cancelled)
    {
        if (pid != 0)
            (void)duetos::sched::SchedKillByPid(pid);
        return false;
    }
    if (result == StartCommitResult::Failed)
    {
        KLOG_WARN("svc", "service spawn failed");
        arch::SerialWrite("[svc] ");
        arch::SerialWrite(d.name);
        arch::SerialWrite(" FAILED (load/spawn)\n");
        return false;
    }

    arch::SerialWrite("[svc] ");
    arch::SerialWrite(d.name);
    arch::SerialWrite(" pid=");
    arch::SerialWriteHex(pid);
    arch::SerialWrite("\n");
    return true;
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
    sync::SpinLockGuard guard(g_service_lock);
    InitLocked();
}

void ServiceManagerStartAll()
{
    ServiceManagerInit();
    for (u32 i = 0; i < kManifestCount; ++i)
    {
        bool should_start = false;
        {
            sync::SpinLockGuard guard(g_service_lock);
            const ServiceRuntime& runtime = g_rt[i];
            should_start = runtime.state == ServiceState::Stopped && !runtime.start_in_flight;
        }
        if (kManifest[i].autostart && should_start)
            (void)ServiceStart(kManifest[i].name);
    }

    bool create_supervisor = false;
    {
        sync::SpinLockGuard guard(g_service_lock);
        if (!g_supervisor_running)
        {
            // Reserve publication before dropping the lock so concurrent
            // StartAll calls cannot create duplicate monitor tasks.
            g_supervisor_running = true;
            create_supervisor = true;
        }
    }
    if (create_supervisor && duetos::sched::SchedCreate(&SupervisorTask, nullptr, "svcmon") == nullptr)
    {
        {
            sync::SpinLockGuard guard(g_service_lock);
            g_supervisor_running = false;
        }
        KLOG_WARN("svc", "service supervisor task creation failed");
    }
}

void ServiceManagerTick()
{
    ServiceManagerInit();
    const u64 now = NowNs();
    for (u32 i = 0; i < kManifestCount; ++i)
    {
        u64 pid = 0;
        u64 generation = 0;
        {
            sync::SpinLockGuard guard(g_service_lock);
            const ServiceRuntime& runtime = g_rt[i];
            if (runtime.state == ServiceState::Running && runtime.desired_running)
            {
                pid = runtime.pid;
                generation = runtime.transition_generation;
            }
        }
        if (pid == 0)
            continue;

        // Liveness MUST include Blocked tasks: a resident daemon spends
        // its life parked in a blocking syscall (e.g. netd in accept()),
        // and a Blocked task is NOT on the runqueue/sleep/zombie lists
        // SchedFindProcessByPid walks — using that here made the
        // supervisor mistake a healthy blocked daemon for a dead one and
        // spawn duplicates that collided on the port. SchedProcessAlive
        // walks the all-tasks registry, so it sees Blocked tasks too.
        // Monotonic PIDs mean a "not alive" verdict can't be a reused id.
        if (duetos::sched::SchedProcessAlive(pid))
            continue;

        StartReservation restart{};
        bool rate_limited = false;
        {
            sync::SpinLockGuard guard(g_service_lock);
            ServiceRuntime& runtime = g_rt[i];
            // A stop/restart or newer publication may have raced the unlocked
            // scheduler probe.  Only the exact running generation can be
            // transitioned by this observation.
            if (runtime.state != ServiceState::Running || runtime.pid != pid ||
                runtime.transition_generation != generation || !runtime.desired_running)
            {
                continue;
            }

            runtime.state = ServiceState::Exited;
            runtime.pid = 0;
            runtime.last_exit_ns = now;
            if (kManifest[i].restart != ServiceRestartPolicy::Always)
            {
                runtime.desired_running = false;
                continue;
            }

            if (!RateLimitAllow(runtime, now))
            {
                runtime.state = ServiceState::Failed;
                runtime.desired_running = false;
                rate_limited = true;
            }
            else
            {
                ++runtime.restarts;
                (void)ReserveStartLocked(i, restart);
            }
        }

        if (rate_limited)
        {
            KLOG_WARN("svc", "service hit respawn rate limit — giving up");
        }
        else if (restart.valid)
        {
            (void)ExecuteStart(restart);
        }
    }
}

bool ServiceStart(const char* name)
{
    const i32 idx = FindByName(name);
    if (idx < 0)
        return false;
    ServiceManagerInit();

    StartReservation reservation{};
    bool already_requested = false;
    {
        sync::SpinLockGuard guard(g_service_lock);
        const ServiceRuntime& runtime = g_rt[idx];
        already_requested = (runtime.state == ServiceState::Running && runtime.desired_running) ||
                            (runtime.start_in_flight && runtime.desired_running);
        if (!already_requested)
            (void)ReserveStartLocked(static_cast<u32>(idx), reservation);
    }
    if (already_requested)
        return true;
    return reservation.valid && ExecuteStart(reservation);
}

bool ServiceStop(const char* name)
{
    const i32 idx = FindByName(name);
    if (idx < 0)
        return false;
    ServiceManagerInit();

    u64 pid = 0;
    {
        sync::SpinLockGuard guard(g_service_lock);
        // Stopped is terminal until the operator restarts it.  This also
        // invalidates an unlocked spawn reservation and disables Always
        // respawn before the scheduler kill runs.
        pid = StopLocked(g_rt[idx]);
    }
    if (pid != 0)
        (void)duetos::sched::SchedKillByPid(pid);
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
    ServiceManagerInit();
    const ServiceDesc& d = kManifest[idx];
    {
        sync::SpinLockGuard guard(g_service_lock);
        const ServiceRuntime& runtime = g_rt[idx];
        out->name = d.name;
        out->state = runtime.state;
        out->restart = d.restart;
        out->autostart = d.autostart;
        out->pid = runtime.pid;
        out->restarts = runtime.restarts;
        out->last_spawn_ns = runtime.last_spawn_ns;
        out->last_exit_ns = runtime.last_exit_ns;
    }
    return true;
}

void ServiceManagerSelfTest()
{
    // Exercise the crash-loop rate limiter deterministically without
    // requiring the resident Always service to fail repeatedly at boot.
    ServiceRuntime runtime{};
    runtime.state = ServiceState::Stopped;
    const u64 t0 = 1'000'000'000ull;

    // First kServiceRestartMax respawns inside the window are allowed.
    for (u32 i = 0; i < kServiceRestartMax; ++i)
    {
        if (!RateLimitAllow(runtime, t0))
        {
            arch::SerialWrite("[svc-selftest] FAIL (early deny)\n");
            return;
        }
    }
    // The next one is denied — crash-loop guard tripped.
    if (RateLimitAllow(runtime, t0))
    {
        arch::SerialWrite("[svc-selftest] FAIL (no deny at limit)\n");
        return;
    }
    // After the window elapses, respawns are permitted again.
    if (!RateLimitAllow(runtime, t0 + kServiceRestartWindowNs))
    {
        arch::SerialWrite("[svc-selftest] FAIL (window did not roll)\n");
        return;
    }

    // A start reservation is exclusive until it commits or is cancelled.
    // Stop invalidates the token without waiting for the loader/scheduler;
    // the stale commit must request cleanup rather than publishing its PID.
    u64 first_generation = 0;
    if (!ReserveStartRuntimeLocked(runtime, first_generation) || first_generation == 0)
    {
        arch::SerialWrite("[svc-selftest] FAIL (start reservation)\n");
        return;
    }
    u64 duplicate_generation = 0;
    if (ReserveStartRuntimeLocked(runtime, duplicate_generation))
    {
        arch::SerialWrite("[svc-selftest] FAIL (duplicate start reservation)\n");
        return;
    }
    if (StopLocked(runtime) != 0 ||
        CommitStartRuntimeLocked(runtime, first_generation, 41, t0) != StartCommitResult::Cancelled)
    {
        arch::SerialWrite("[svc-selftest] FAIL (stale start publication)\n");
        return;
    }

    u64 second_generation = 0;
    if (!ReserveStartRuntimeLocked(runtime, second_generation) || second_generation <= first_generation ||
        CommitStartRuntimeLocked(runtime, second_generation, 42, t0) != StartCommitResult::Published ||
        runtime.state != ServiceState::Running || runtime.pid != 42)
    {
        arch::SerialWrite("[svc-selftest] FAIL (exact start publication)\n");
        return;
    }
    if (StopLocked(runtime) != 42 || runtime.state != ServiceState::Stopped || runtime.pid != 0 ||
        runtime.desired_running || runtime.start_in_flight)
    {
        arch::SerialWrite("[svc-selftest] FAIL (stop transition)\n");
        return;
    }

    u64 failed_generation = 0;
    if (!ReserveStartRuntimeLocked(runtime, failed_generation) ||
        CommitStartRuntimeLocked(runtime, failed_generation, 0, t0) != StartCommitResult::Failed ||
        runtime.state != ServiceState::Failed || runtime.pid != 0)
    {
        arch::SerialWrite("[svc-selftest] FAIL (spawn failure transition)\n");
        return;
    }

    arch::SerialWrite("[svc-selftest] PASS (rate limit + transactional lifecycle)\n");
}

} // namespace duetos::core
