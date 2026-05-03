/*
 * DuetOS — purple-team scorecard: implementation.
 *
 * Brackets AttackSimRun() with event-ring snapshots + wall-clock
 * timing, then reports a coverage percentage. Per-attack
 * EventKind expectation tables are out of scope for v0 (they need
 * runtime_checker.cpp to publish kind-labelled events first).
 */

#include "security/purple_team.h"

#include "arch/x86_64/serial.h"
#include "security/canary.h"
#include "sync/spinlock.h"
#include "time/timekeeper.h"

namespace duetos::security
{

namespace
{

constinit ScorecardSummary g_last{};
constinit sync::SpinLock g_lock{};

// Walk the ring counting how many events of `kind` appear with
// uptime_ns >= since_ns. Used to count runbook-emitted /
// policy-change events that fired during the run window.
struct CountCookie
{
    EventKind kind;
    u64 since_ns;
    u64 count;
};

void CountVisitor(const Event& e, void* cookie)
{
    auto* c = static_cast<CountCookie*>(cookie);
    if (e.kind == c->kind && e.uptime_ns >= c->since_ns)
    {
        ++c->count;
    }
}

u64 CountEventsSince(EventKind kind, u64 since_ns)
{
    CountCookie c{kind, since_ns, 0};
    EventRingForEach(CountVisitor, &c);
    return c.count;
}

} // namespace

ScorecardSummary PurpleTeamRunAll()
{
    const EventRingStats before = EventRingStatsRead();
    const u64 start_ns = time::MonotonicNs();

    EventRingPublishKind(EventKind::AttackSimRun, 0, 0, 0, "begin");

    AttackSimRun();

    const u64 end_ns = time::MonotonicNs();
    const EventRingStats after = EventRingStatsRead();
    const AttackSummary& as = AttackSimSummary();

    ScorecardSummary s{};
    s.attacks_run = as.count;
    s.attacks_passed = as.passed;
    s.attacks_failed = as.failed;
    s.attacks_skipped = as.skipped;

    s.events_observed = after.published_total - before.published_total;
    s.events_dropped = after.dropped_oldest - before.dropped_oldest;
    s.runbooks_emitted = CountEventsSince(EventKind::IrRunbookEmitted, start_ns);
    s.policy_changes_seen = CountEventsSince(EventKind::PolicyChanged, start_ns);
    s.run_start_ns = start_ns;
    s.run_end_ns = end_ns;
    s.ran_to_completion = (as.count > 0);

    const u64 effective = (as.count > as.skipped) ? (as.count - as.skipped) : 0;
    s.coverage_pct = (effective == 0) ? 0u : static_cast<u32>((as.passed * 100ULL) / effective);

    {
        sync::SpinLockGuard guard{g_lock};
        g_last = s;
    }

    PurpleTeamReport(s);
    return s;
}

const ScorecardSummary& PurpleTeamLastSummary()
{
    // The accessor is read-only; we serve the storage directly
    // (a torn read would only show a partially-written ScorecardSummary,
    // which is fine for an operator-facing diagnostic — never used
    // for control flow).
    return g_last;
}

void PurpleTeamReport(const ScorecardSummary& s)
{
    arch::SerialWrite("[purple] scorecard:\n");
    arch::SerialWrite("[purple]   attacks: run=");
    arch::SerialWriteHex(s.attacks_run);
    arch::SerialWrite(" passed=");
    arch::SerialWriteHex(s.attacks_passed);
    arch::SerialWrite(" failed=");
    arch::SerialWriteHex(s.attacks_failed);
    arch::SerialWrite(" skipped=");
    arch::SerialWriteHex(s.attacks_skipped);
    arch::SerialWrite("\n");

    arch::SerialWrite("[purple]   events: observed=");
    arch::SerialWriteHex(s.events_observed);
    arch::SerialWrite(" dropped=");
    arch::SerialWriteHex(s.events_dropped);
    arch::SerialWrite(" runbooks=");
    arch::SerialWriteHex(s.runbooks_emitted);
    arch::SerialWrite(" policy_changes=");
    arch::SerialWriteHex(s.policy_changes_seen);
    arch::SerialWrite("\n");

    arch::SerialWrite("[purple]   timing: start_ns=");
    arch::SerialWriteHex(s.run_start_ns);
    arch::SerialWrite(" end_ns=");
    arch::SerialWriteHex(s.run_end_ns);
    arch::SerialWrite("\n");

    arch::SerialWrite("[purple]   coverage: ");
    arch::SerialWriteHex(static_cast<u64>(s.coverage_pct));
    arch::SerialWrite("% (passed/effective)\n");
}

void PurpleTeamSelfTest()
{
    const EventRingStats before = EventRingStatsRead();

    // Phase 1: ring pass-through. Publish 5 synthetic events to
    // confirm the ring + observed-count math works.
    EventRingPublishKind(EventKind::AttackSimRun, 0, 0xCAFE, 0, "self-test-begin");
    EventRingPublishKind(EventKind::CanaryTouch, 1, 0, 0, "self-test-1");
    EventRingPublishKind(EventKind::PersistenceDrop, 2, 0, 0, "self-test-2");
    EventRingPublishKind(EventKind::IrRunbookEmitted, 1, static_cast<u64>(EventKind::CanaryTouch), 0, "CanaryTouch");
    EventRingPublishKind(EventKind::AttackSimRun, 0, 0xCAFE, 0, "self-test-end");

    const EventRingStats mid = EventRingStatsRead();
    const u64 phase1_observed = mid.published_total - before.published_total;
    if (phase1_observed != 5)
    {
        arch::SerialWrite("[purple] self-test FAIL: phase1 events_observed=");
        arch::SerialWriteHex(phase1_observed);
        arch::SerialWrite(" (expected 5)\n");
        return;
    }

    // Phase 2: real publish wire. Drive PersistenceNote in Advisory
    // mode (safe — Advisory does not flag the current task for kill)
    // through a registered autostart-equivalent path. The note path
    // calls IrRunbookEmit, which itself publishes IrRunbookEmitted.
    // Expected ring delta: 1 PersistenceDrop + 1 IrRunbookEmitted.
    const PersistenceMode saved = PersistenceModeRead();
    PersistenceSetMode(PersistenceMode::Advisory);

    constexpr const char* kProbePath = "/etc/init.d/wiring-self-test";
    const bool matched = PersistenceMatchesPath(kProbePath);
    if (matched)
    {
        (void)PersistenceNote(kProbePath, "self-test");
    }
    PersistenceSetMode(saved);

    const EventRingStats after = EventRingStatsRead();
    const u64 phase2_observed = after.published_total - mid.published_total;

    // Walk the ring counting the kinds we expect from phase 2.
    struct Counts
    {
        u32 persistence;
        u32 runbook;
        u64 since_seq;
    } c{0, 0, mid.published_total};

    EventRingForEach(
        [](const Event& e, void* cookie)
        {
            auto* cp = static_cast<Counts*>(cookie);
            if (e.seq <= cp->since_seq)
                return;
            if (e.kind == EventKind::PersistenceDrop)
                ++cp->persistence;
            else if (e.kind == EventKind::IrRunbookEmitted)
                ++cp->runbook;
        },
        &c);

    if (matched && phase2_observed >= 2 && c.persistence >= 1 && c.runbook >= 1)
    {
        arch::SerialWrite("[purple] self-test PASS (phase1=5 phase2_persistence=1+ phase2_runbook=1+)\n");
    }
    else
    {
        arch::SerialWrite("[purple] self-test FAIL: phase2 matched=");
        arch::SerialWriteHex(matched ? 1 : 0);
        arch::SerialWrite(" observed=");
        arch::SerialWriteHex(phase2_observed);
        arch::SerialWrite(" persistence=");
        arch::SerialWriteHex(c.persistence);
        arch::SerialWrite(" runbook=");
        arch::SerialWriteHex(c.runbook);
        arch::SerialWrite("\n");
    }
}

} // namespace duetos::security
