#include "security/fault_domain.h"

#include "arch/x86_64/serial.h"
#include "sched/sched.h"
#include "log/klog.h"
#include "core/panic.h"

namespace duetos::core
{

namespace
{

constinit FaultDomain g_domains[kMaxFaultDomains] = {};
constinit u32 g_domain_count = 0;

struct DependencyEdge
{
    FaultDomainId parent;
    FaultDomainId dependent;
    bool used;
};
constinit DependencyEdge g_deps[kMaxFaultDomainDeps] = {};
constinit u32 g_dep_count = 0;
constinit u64 g_throttle_count = 0;

bool StrEq(const char* a, const char* b)
{
    if (a == nullptr || b == nullptr)
        return false;
    while (*a && *b && *a == *b)
    {
        ++a;
        ++b;
    }
    return *a == *b;
}

// Rate-throttle decision. A domain that has restarted
// `kRestartHistoryDepth` times within `kRestartThrottleWindowTicks`
// is flapping; the supervisor refuses the next restart and parks
// the domain in `Stopped` so an operator can intervene.
//
// "Fullness" is keyed on the lifetime restart counter so a fresh
// domain that hasn't restarted enough times to fill the ring
// can't accidentally trip the throttle on a zero-valued slot
// (relevant during early boot before SchedNowTicks() advances).
bool RestartTooFast(const FaultDomain& d, u64 now_ticks)
{
    if (d.restart_count < kRestartHistoryDepth)
        return false;
    u64 oldest = d.restart_history[0];
    for (u32 i = 1; i < kRestartHistoryDepth; ++i)
    {
        if (d.restart_history[i] < oldest)
            oldest = d.restart_history[i];
    }
    return (now_ticks - oldest) < kRestartThrottleWindowTicks;
}

void RecordRestartTimestamp(FaultDomain& d, u64 now_ticks)
{
    d.restart_history[d.restart_history_next % kRestartHistoryDepth] = now_ticks;
    d.restart_history_next = (d.restart_history_next + 1) % kRestartHistoryDepth;
}

void CascadeDependents(FaultDomainId parent)
{
    // O(n) over a bounded table (kMaxFaultDomainDeps = 64). One
    // level deep — `MarkRestart` is idempotent, so a dependent
    // that is itself a parent will, when its own restart runs,
    // cascade to its children on the same heartbeat tick.
    for (u32 i = 0; i < kMaxFaultDomainDeps; ++i)
    {
        if (!g_deps[i].used)
            continue;
        if (g_deps[i].parent != parent)
            continue;
        FaultDomainMarkRestart(g_deps[i].dependent);
    }
}

} // namespace

FaultDomainId FaultDomainRegister(const char* name, Result<void> (*init)(), Result<void> (*teardown)())
{
    if (name == nullptr || init == nullptr || teardown == nullptr)
        return kFaultDomainInvalid;
    if (g_domain_count >= kMaxFaultDomains)
    {
        arch::SerialWrite("[fault-domain] registry full; refused name=");
        arch::SerialWrite(name);
        arch::SerialWrite("\n");
        return kFaultDomainInvalid;
    }
    const FaultDomainId id = g_domain_count++;
    FaultDomain& d = g_domains[id];
    d.name = name;
    d.init = init;
    d.teardown = teardown;
    d.restart_count = 0;
    d.last_restart_ticks = 0;
    d.alive = true; // assume the subsystem's own Init ran already
    d.restart_pending = false;
    d.state = ModuleState::Running;
    arch::SerialWrite("[fault-domain] register id=");
    arch::SerialWriteHex(id);
    arch::SerialWrite(" name=");
    arch::SerialWrite(name);
    arch::SerialWrite("\n");
    return id;
}

u32 FaultDomainCount()
{
    return g_domain_count;
}

const FaultDomain* FaultDomainGet(FaultDomainId id)
{
    if (id >= g_domain_count)
        return nullptr;
    return &g_domains[id];
}

FaultDomain* FaultDomainGetMutable(FaultDomainId id)
{
    if (id >= g_domain_count)
        return nullptr;
    return &g_domains[id];
}

FaultDomainId FaultDomainFind(const char* name)
{
    for (u32 i = 0; i < g_domain_count; ++i)
    {
        if (StrEq(g_domains[i].name, name))
            return i;
    }
    return kFaultDomainInvalid;
}

Result<void> FaultDomainRestart(FaultDomainId id)
{
    if (id >= g_domain_count)
        return Err{ErrorCode::NotFound};
    FaultDomain& d = g_domains[id];

    arch::SerialWrite("[fault-domain] restart begin name=");
    arch::SerialWrite(d.name);
    arch::SerialWrite(" prev_count=");
    arch::SerialWriteHex(d.restart_count);
    arch::SerialWrite("\n");

    // Teardown phase — subsystem is considered dead the moment we
    // call it, regardless of outcome. A half-tore-down domain is
    // expected to land here on its next restart and self-heal.
    d.alive = false;
    const auto td = d.teardown();
    if (!td)
    {
        // Teardown failure leaves the domain in `Stopped`: the
        // subsystem will not be live again until a successful
        // restart pairs a teardown + init. The shell's
        // `module status` will reflect this.
        d.state = ModuleState::Stopped;
        arch::SerialWrite("[fault-domain] teardown failed name=");
        arch::SerialWrite(d.name);
        arch::SerialWrite(" err=");
        arch::SerialWrite(ErrorCodeName(td.error()));
        arch::SerialWrite("\n");
        return Err{td.error()};
    }

    // Init phase — brings the subsystem back to a live state.
    const auto in = d.init();
    if (!in)
    {
        // Init failure also lands in `Stopped`. An operator can
        // retry via `module start` once the underlying issue
        // (typically resource exhaustion) is resolved.
        d.state = ModuleState::Stopped;
        arch::SerialWrite("[fault-domain] init failed name=");
        arch::SerialWrite(d.name);
        arch::SerialWrite(" err=");
        arch::SerialWrite(ErrorCodeName(in.error()));
        arch::SerialWrite("\n");
        return Err{in.error()};
    }

    d.alive = true;
    d.restart_pending = false;
    d.state = ModuleState::Running;
    ++d.restart_count;
    d.last_restart_ticks = sched::SchedNowTicks();
    RecordRestartTimestamp(d, d.last_restart_ticks);
    arch::SerialWrite("[fault-domain] restart ok name=");
    arch::SerialWrite(d.name);
    arch::SerialWrite(" count=");
    arch::SerialWriteHex(d.restart_count);
    arch::SerialWrite("\n");

    // Cascade — propagate the restart to every registered
    // dependent. Off the synchronous path: we mark, the watchdog
    // drains on the next beat. A dependent that is itself a
    // parent will cascade further when its own restart fires.
    CascadeDependents(id);
    return {};
}

void FaultDomainMarkRestart(FaultDomainId id)
{
    if (id >= g_domain_count)
        return;
    // One bool write — explicitly NOT taking a lock or logging
    // here. Trap-handler context only allows the cheapest
    // possible bookkeeping; the watchdog drains this from a
    // sane process context.
    g_domains[id].restart_pending = true;
}

bool FaultDomainAddDependency(FaultDomainId parent, FaultDomainId dependent)
{
    if (parent >= g_domain_count || dependent >= g_domain_count)
        return false;
    if (parent == dependent)
        return false;
    if (g_dep_count >= kMaxFaultDomainDeps)
    {
        arch::SerialWrite("[fault-domain] dep table full — refused parent=");
        arch::SerialWrite(g_domains[parent].name);
        arch::SerialWrite(" dependent=");
        arch::SerialWrite(g_domains[dependent].name);
        arch::SerialWrite("\n");
        return false;
    }
    g_deps[g_dep_count] = {parent, dependent, true};
    ++g_dep_count;
    arch::SerialWrite("[fault-domain] dep parent=");
    arch::SerialWrite(g_domains[parent].name);
    arch::SerialWrite(" -> dependent=");
    arch::SerialWrite(g_domains[dependent].name);
    arch::SerialWrite("\n");
    return true;
}

u32 FaultDomainDependencyCount()
{
    return g_dep_count;
}

u64 FaultDomainThrottleCount()
{
    return g_throttle_count;
}

void FaultDomainTick()
{
    // Linear scan; the registry is bounded at kMaxFaultDomains
    // (16). The common-case cost is one branch per domain, so the
    // beat-rate cost is negligible. We only emit a log line when
    // something actually fires.
    const u64 now = sched::SchedNowTicks();
    for (u32 i = 0; i < g_domain_count; ++i)
    {
        if (!g_domains[i].restart_pending)
            continue;
        // Project the trap-set bool onto the operator-visible
        // state field BEFORE clearing it. A `module status`
        // running on this beat sees `Crashed`; the next beat
        // (after the restart succeeds) sees `Running`. This
        // is also the GDB hook point for `kModuleStateChange`.
        g_domains[i].state = ModuleState::Crashed;
        // Rate-throttle gate: if this domain has restarted too
        // often inside the rolling window, refuse the restart
        // and park the domain in `Stopped`. An operator must
        // explicitly `module start` it once they've decided the
        // underlying fault is fixed. This is the supervisor
        // escalation rule a buggy driver can never demote.
        if (RestartTooFast(g_domains[i], now))
        {
            g_domains[i].restart_pending = false;
            g_domains[i].alive = false;
            g_domains[i].state = ModuleState::Stopped;
            ++g_domains[i].restart_throttle_count;
            ++g_throttle_count;
            arch::SerialWrite("[fault-domain-tick] THROTTLED name=");
            arch::SerialWrite(g_domains[i].name);
            arch::SerialWrite(" — too many restarts; parked in Stopped\n");
            continue;
        }
        // Clear FIRST so a second trap landing during the
        // restart's own teardown/init can re-arm us instead of
        // being lost to a "already pending, ignore" race. The
        // restart_pending field is reset again at the end of
        // FaultDomainRestart on success.
        g_domains[i].restart_pending = false;
        arch::SerialWrite("[fault-domain-tick] draining pending restart name=");
        arch::SerialWrite(g_domains[i].name);
        arch::SerialWrite("\n");
        const auto r = FaultDomainRestart(i);
        if (!r)
        {
            arch::SerialWrite("[fault-domain-tick] restart FAILED name=");
            arch::SerialWrite(g_domains[i].name);
            arch::SerialWrite(" err=");
            arch::SerialWrite(ErrorCodeName(r.error()));
            arch::SerialWrite("\n");
        }
    }
}

// ----------------------------------------------------------------
// Self-test: register a toy domain with counters, restart it, and
// verify the bookkeeping.
// ----------------------------------------------------------------

namespace
{

constinit u32 g_selftest_init_calls = 0;
constinit u32 g_selftest_teardown_calls = 0;
constinit u32 g_selftest_throttle_init_calls = 0;
constinit u32 g_selftest_throttle_teardown_calls = 0;
constinit u32 g_selftest_cascade_a_init_calls = 0;
constinit u32 g_selftest_cascade_a_teardown_calls = 0;
constinit u32 g_selftest_cascade_b_init_calls = 0;
constinit u32 g_selftest_cascade_b_teardown_calls = 0;

Result<void> SelfTestInit()
{
    ++g_selftest_init_calls;
    return {};
}

Result<void> SelfTestTeardown()
{
    ++g_selftest_teardown_calls;
    return {};
}

Result<void> SelfTestThrottleInit()
{
    ++g_selftest_throttle_init_calls;
    return {};
}
Result<void> SelfTestThrottleTeardown()
{
    ++g_selftest_throttle_teardown_calls;
    return {};
}
Result<void> SelfTestCascadeAInit()
{
    ++g_selftest_cascade_a_init_calls;
    return {};
}
Result<void> SelfTestCascadeATeardown()
{
    ++g_selftest_cascade_a_teardown_calls;
    return {};
}
Result<void> SelfTestCascadeBInit()
{
    ++g_selftest_cascade_b_init_calls;
    return {};
}
Result<void> SelfTestCascadeBTeardown()
{
    ++g_selftest_cascade_b_teardown_calls;
    return {};
}

void Expect(bool cond, const char* what)
{
    if (cond)
        return;
    arch::SerialWrite("[fault-domain-selftest] FAIL ");
    arch::SerialWrite(what);
    arch::SerialWrite("\n");
    PanicWithValue("core/fault-domain", "self-test mismatch", 0);
}

} // namespace

void FaultDomainSelfTest()
{
    KLOG_TRACE_SCOPE("core/fault-domain", "SelfTest");

    g_selftest_init_calls = 0;
    g_selftest_teardown_calls = 0;
    const FaultDomainId id = FaultDomainRegister("selftest.synth", SelfTestInit, SelfTestTeardown);
    Expect(id != kFaultDomainInvalid, "register returns valid id");

    // First restart: teardown = 1, init = 1.
    const auto r1 = FaultDomainRestart(id);
    Expect(bool(r1), "first restart ok");
    Expect(g_selftest_teardown_calls == 1, "teardown count after r1");
    Expect(g_selftest_init_calls == 1, "init count after r1");

    // Second restart: teardown = 2, init = 2; count on the domain = 2.
    const auto r2 = FaultDomainRestart(id);
    Expect(bool(r2), "second restart ok");
    Expect(g_selftest_teardown_calls == 2, "teardown count after r2");
    Expect(g_selftest_init_calls == 2, "init count after r2");
    Expect(FaultDomainGet(id)->restart_count == 2, "domain.restart_count == 2");

    // Lookup by name round-trips.
    Expect(FaultDomainFind("selftest.synth") == id, "find by name round-trip");
    Expect(FaultDomainFind("nonexistent") == kFaultDomainInvalid, "missing name -> invalid");

    // Mark + Tick path: simulate a trap-handler MarkRestart, then
    // verify the watchdog drains it and bumps the counter.
    FaultDomainMarkRestart(id);
    Expect(FaultDomainGet(id)->restart_pending, "mark sets pending");
    FaultDomainTick();
    Expect(!FaultDomainGet(id)->restart_pending, "tick clears pending");
    Expect(FaultDomainGet(id)->restart_count == 3, "domain.restart_count == 3 after tick");
    Expect(g_selftest_teardown_calls == 3, "teardown count after tick");
    Expect(g_selftest_init_calls == 3, "init count after tick");

    // Tick with no pending flags is a no-op.
    FaultDomainTick();
    Expect(FaultDomainGet(id)->restart_count == 3, "second tick is no-op");

    // Out-of-range MarkRestart is silently ignored (trap-handler
    // contract: never panic from inside the handler).
    FaultDomainMarkRestart(kFaultDomainInvalid);

    // ---- Cross-domain dependency cascade ---------------------
    // Register A and B; A->B; restart A; verify B was cascaded.
    g_selftest_cascade_a_init_calls = 0;
    g_selftest_cascade_a_teardown_calls = 0;
    g_selftest_cascade_b_init_calls = 0;
    g_selftest_cascade_b_teardown_calls = 0;
    const FaultDomainId idA = FaultDomainRegister("selftest.cascade.A", SelfTestCascadeAInit, SelfTestCascadeATeardown);
    const FaultDomainId idB = FaultDomainRegister("selftest.cascade.B", SelfTestCascadeBInit, SelfTestCascadeBTeardown);
    Expect(idA != kFaultDomainInvalid && idB != kFaultDomainInvalid, "cascade domains registered");
    Expect(FaultDomainAddDependency(idA, idB), "add dep A->B");
    Expect(!FaultDomainAddDependency(idA, idA), "self-dep refused");
    Expect(FaultDomainDependencyCount() == 1, "one dependency edge");
    const auto rA = FaultDomainRestart(idA);
    Expect(bool(rA), "restart A");
    // Restart A cascaded MarkRestart(B); the next Tick drains.
    Expect(FaultDomainGet(idB)->restart_pending, "B marked by cascade");
    FaultDomainTick();
    Expect(g_selftest_cascade_b_init_calls >= 1, "B cascaded restart ran init");
    Expect(g_selftest_cascade_b_teardown_calls >= 1, "B cascaded restart ran teardown");

    // ---- Restart-rate throttle -------------------------------
    // Push N successful restarts in a tight loop (all in the
    // same scheduler tick); the (N+1)th MarkRestart+Tick should
    // hit the throttle and park the domain in Stopped.
    g_selftest_throttle_init_calls = 0;
    g_selftest_throttle_teardown_calls = 0;
    const FaultDomainId idT = FaultDomainRegister("selftest.throttle", SelfTestThrottleInit, SelfTestThrottleTeardown);
    Expect(idT != kFaultDomainInvalid, "throttle domain registered");
    for (u32 i = 0; i < kRestartHistoryDepth; ++i)
    {
        const auto r = FaultDomainRestart(idT);
        Expect(bool(r), "throttle test pre-fill restart");
    }
    const u32 throttle_before = FaultDomainGet(idT)->restart_throttle_count;
    const u64 global_before = FaultDomainThrottleCount();
    FaultDomainMarkRestart(idT);
    FaultDomainTick();
    Expect(FaultDomainGet(idT)->restart_throttle_count == throttle_before + 1, "throttle counted on domain");
    Expect(FaultDomainThrottleCount() == global_before + 1, "throttle counted globally");
    Expect(FaultDomainGet(idT)->state == ModuleState::Stopped, "throttled domain parked Stopped");
    Expect(!FaultDomainGet(idT)->alive, "throttled domain marked not-alive");

    arch::SerialWrite("[fault-domain-selftest] PASS (");
    arch::SerialWriteHex(g_domain_count);
    arch::SerialWrite(" domains; restart + tick + cascade + throttle verified)\n");
}

} // namespace duetos::core
