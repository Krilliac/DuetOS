#include "diag/fma/diagnose.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "diag/fma/ereport.h"
#include "log/klog.h"
#include "sched/sched.h"

namespace duetos::diag::fma
{

// Hook into ereport.cpp's counter helpers (defined there to keep
// the lifetime stats in one TU). Declared here as externs.
void EreportNoteDiagnosisRun();
void EreportNoteSuspectIdentified();

namespace
{

// ---------------------------------------------------------------------------
// Suspect ring. Same shape as the ereport ring but smaller — suspects
// are the engine's CONCLUSIONS, not raw events, so 64 entries is
// plenty for a healthy boot (typically zero) and enough audit trail
// for a faulting one.
// ---------------------------------------------------------------------------

constinit Suspect g_suspects[kSuspectRingSize] = {};
constinit u64 g_suspects_head = 0;

void AppendSuspect(EreportClass primary, u64 target_id, u32 contributing, EreportSeverity sev, const char* description)
{
    const u64 new_head = __atomic_add_fetch(&g_suspects_head, 1, __ATOMIC_ACQ_REL);
    const u64 slot_idx = (new_head - 1) % kSuspectRingSize;
    Suspect& s = g_suspects[slot_idx];
    s.timestamp_ticks = sched::SchedNowTicks();
    s.primary_class = primary;
    s.target_id = target_id;
    s.contributing_events = contributing;
    s.severity = sev;

    // Copy description, capped.
    u32 i = 0;
    if (description != nullptr)
    {
        for (; i + 1 < sizeof(s.description) && description[i] != '\0'; ++i)
        {
            s.description[i] = description[i];
        }
    }
    s.description[i] = '\0';

    EreportNoteSuspectIdentified();

    // Log a structured line so an operator inspecting the boot log
    // sees the suspect immediately. Warn-gated so release builds
    // surface it but debug builds can still get the full trail.
    arch::SerialWrite("[fma] suspect class=");
    arch::SerialWriteHex(static_cast<u32>(primary));
    arch::SerialWrite(" target=");
    arch::SerialWriteHex(target_id);
    arch::SerialWrite(" n=");
    arch::SerialWriteHex(contributing);
    arch::SerialWrite(" desc=\"");
    arch::SerialWrite(s.description);
    arch::SerialWrite("\"\n");
}

// ---------------------------------------------------------------------------
// Per-rule "recently fired" gate.
// ---------------------------------------------------------------------------
//
// A rule that crosses its threshold for target T on tick N should NOT
// re-fire for T again on tick N+1 just because the contributing events
// haven't aged out yet. We track the last tick at which a rule fired
// for each (rule_id, target_id) pair and refuse to re-fire within the
// correlation window.
//
// The table is bounded: kRecentFiredCap entries, FIFO replacement when
// full. A loaded system with >32 distinct concurrent suspects has
// bigger problems than a missed rate-limit gate.

constexpr u32 kRecentFiredCap = 32;
constexpr u32 kRuleEcc = 0;
constexpr u32 kRuleDriver = 1;
constexpr u32 kRuleIntegrity = 2;

struct RecentFiredEntry
{
    u32 rule_id;
    u32 _pad;
    u64 target_id;
    u64 fired_at_tick;
};
constinit RecentFiredEntry g_recent_fired[kRecentFiredCap] = {};
constinit u32 g_recent_fired_next = 0;

bool RecentlyFired(u32 rule_id, u64 target_id, u64 now_ticks)
{
    for (u32 i = 0; i < kRecentFiredCap; ++i)
    {
        const RecentFiredEntry& e = g_recent_fired[i];
        if (e.rule_id == rule_id && e.target_id == target_id && e.fired_at_tick != 0 &&
            (now_ticks - e.fired_at_tick) < kCorrelationWindowTicks)
        {
            return true;
        }
    }
    return false;
}

void NoteFired(u32 rule_id, u64 target_id, u64 now_ticks)
{
    // FIFO replacement — overwrite the oldest slot.
    g_recent_fired[g_recent_fired_next].rule_id = rule_id;
    g_recent_fired[g_recent_fired_next]._pad = 0;
    g_recent_fired[g_recent_fired_next].target_id = target_id;
    g_recent_fired[g_recent_fired_next].fired_at_tick = now_ticks;
    g_recent_fired_next = (g_recent_fired_next + 1) % kRecentFiredCap;
}

// ---------------------------------------------------------------------------
// Per-tick target-counter table. Stack-local to keep DiagnoseTick
// re-entrancy-clean (the heartbeat is single-threaded, but a future
// shell-driven `fma diagnose` command might call this off-cycle).
// ---------------------------------------------------------------------------

constexpr u32 kMaxTargetsPerRule = 32;

struct TargetCount
{
    u64 target_id;
    u32 count;
    u32 _pad;
};

struct TargetTable
{
    TargetCount entries[kMaxTargetsPerRule];
    u32 live;
};

void TargetTableBump(TargetTable& tbl, u64 target_id)
{
    for (u32 i = 0; i < tbl.live; ++i)
    {
        if (tbl.entries[i].target_id == target_id)
        {
            ++tbl.entries[i].count;
            return;
        }
    }
    if (tbl.live < kMaxTargetsPerRule)
    {
        tbl.entries[tbl.live].target_id = target_id;
        tbl.entries[tbl.live].count = 1;
        tbl.entries[tbl.live]._pad = 0;
        ++tbl.live;
    }
    // Else: table full — drop. With 32 distinct DIMMs / drivers
    // hitting the engine in one window, the system is faulting
    // hard enough that the loss of one target's count is noise.
}

// ---------------------------------------------------------------------------
// Walk-state for DiagnoseTick. The ereport walker fires our callback
// once per ring entry; we cache the per-rule target tables AND track
// whether a single KernelIntegrity event was seen.
// ---------------------------------------------------------------------------

struct DiagnoseWalkState
{
    u64 window_start_tick; ///< now - kCorrelationWindowTicks; events older are skipped.
    TargetTable ecc;
    TargetTable driver;
    bool integrity_seen;
    EreportClass integrity_first_target_class;
    u64 integrity_first_target;
    u32 integrity_count;
};

void WalkCallback(const Ereport& ev, void* cookie)
{
    auto* state = static_cast<DiagnoseWalkState*>(cookie);

    // Outside the correlation window: skip. The walker hands us
    // entries newest-first; once we cross the boundary every
    // subsequent entry is older still, but we don't have an early-
    // exit hook in the walker so we just filter here.
    if (ev.timestamp_ticks < state->window_start_tick)
    {
        return;
    }

    switch (ev.cls)
    {
    case EreportClass::EccCorrected:
        TargetTableBump(state->ecc, ev.target_id);
        break;
    case EreportClass::DriverFault:
    case EreportClass::DriverTimeout:
        TargetTableBump(state->driver, ev.target_id);
        break;
    case EreportClass::KernelIntegrity:
        if (!state->integrity_seen)
        {
            state->integrity_seen = true;
            state->integrity_first_target_class = ev.cls;
            state->integrity_first_target = ev.target_id;
        }
        ++state->integrity_count;
        break;
    default:
        // Other classes are recorded but don't drive a rule in v0.
        break;
    }
}

} // namespace

u32 DiagnoseTick()
{
    EreportNoteDiagnosisRun();

    const u64 now = sched::SchedNowTicks();

    DiagnoseWalkState state = {};
    state.window_start_tick = (now > kCorrelationWindowTicks) ? (now - kCorrelationWindowTicks) : 0;
    state.ecc.live = 0;
    state.driver.live = 0;
    state.integrity_seen = false;
    state.integrity_count = 0;

    // Walk the entire ring — the per-class filter is fast and the
    // ring is bounded at 256 entries. Sub-millisecond on real
    // hardware; trivial on QEMU.
    EreportWalk(kEreportRingSize, &WalkCallback, &state);

    u32 new_suspects = 0;

    // Rule 1: ECC correlation.
    for (u32 i = 0; i < state.ecc.live; ++i)
    {
        const TargetCount& tc = state.ecc.entries[i];
        if (tc.count >= kEccCorrelationThreshold && !RecentlyFired(kRuleEcc, tc.target_id, now))
        {
            AppendSuspect(EreportClass::EccCorrected, tc.target_id, tc.count, EreportSeverity::Degraded,
                          "ecc dimm repeatedly correctable");
            NoteFired(kRuleEcc, tc.target_id, now);
            ++new_suspects;
        }
    }

    // Rule 2: Driver-fault correlation.
    for (u32 i = 0; i < state.driver.live; ++i)
    {
        const TargetCount& tc = state.driver.entries[i];
        if (tc.count >= kDriverFaultThreshold && !RecentlyFired(kRuleDriver, tc.target_id, now))
        {
            AppendSuspect(EreportClass::DriverFault, tc.target_id, tc.count, EreportSeverity::Degraded,
                          "driver repeatedly faulting");
            NoteFired(kRuleDriver, tc.target_id, now);
            ++new_suspects;
        }
    }

    // Rule 3: KernelIntegrity is always Critical — one event
    // suffices. We collapse multiple integrity events in the
    // window to a single suspect (target_id = the first event's
    // target_id) so a recurring drift doesn't spam the ring.
    if (state.integrity_seen && !RecentlyFired(kRuleIntegrity, state.integrity_first_target, now))
    {
        AppendSuspect(EreportClass::KernelIntegrity, state.integrity_first_target, state.integrity_count,
                      EreportSeverity::Critical, "kernel integrity drift");
        NoteFired(kRuleIntegrity, state.integrity_first_target, now);
        ++new_suspects;
    }

    return new_suspects;
}

u32 SuspectCount()
{
    const u64 head = __atomic_load_n(&g_suspects_head, __ATOMIC_ACQUIRE);
    return static_cast<u32>((head < kSuspectRingSize) ? head : kSuspectRingSize);
}

void SuspectWalk(u32 max, SuspectWalkCb cb, void* cookie)
{
    if (cb == nullptr || max == 0)
    {
        return;
    }
    const u64 head = __atomic_load_n(&g_suspects_head, __ATOMIC_ACQUIRE);
    if (head == 0)
    {
        return;
    }
    const u64 available = (head < kSuspectRingSize) ? head : kSuspectRingSize;
    const u64 to_walk = (max < available) ? max : available;
    for (u64 i = 0; i < to_walk; ++i)
    {
        const u64 slot_idx = (head - 1 - i) % kSuspectRingSize;
        cb(g_suspects[slot_idx], cookie);
    }
}

void FmaInstall()
{
    // Data-only subsystem — the heartbeat drives DiagnoseTick.
    // Kept as an explicit boot-time entry point so any future
    // initialisation (per-CPU rings, persistent suspect log) has
    // a natural home, and so the boot bringup sequence has a
    // "this subsystem was wired in" call site to grep for.
    arch::SerialWrite("[fma] installed (skeleton: 3 rules, single-ring)\n");
}

namespace
{

// Self-test snapshot helpers.
u32 g_st_suspects_at_start = 0;

void StFindSuspect(const Suspect& s, void* cookie)
{
    auto* found = static_cast<u32*>(cookie);
    // Each test phase records the WALK position of a matching
    // suspect via a stable encoding in *found. The test logic
    // below sets specific magic target_ids so we can identify
    // each phase's suspect deterministically.
    if (s.target_id == 0xECC1)
    {
        *found |= 0x1;
    }
    else if (s.target_id == 0xD042)
    {
        *found |= 0x2;
    }
    else if (s.target_id == 0xC011)
    {
        *found |= 0x4;
    }
}

} // namespace

void FmaSelfTest()
{
    arch::SerialWrite("[fma] self-test: ECC + driver + integrity correlation\n");

    g_st_suspects_at_start = SuspectCount();

    // Phase 1: ECC rule. Post `kEccCorrelationThreshold` events on
    // the same DIMM target id and assert a suspect appears.
    for (u32 i = 0; i < kEccCorrelationThreshold; ++i)
    {
        EreportPost(EreportClass::EccCorrected, EreportSeverity::Recoverable, /*target_id=*/0xECC1, /*aux0=*/i,
                    /*aux1=*/0, "fma-selftest");
    }

    // Phase 2: Driver-fault rule. Mix DriverFault and DriverTimeout
    // — the rule should aggregate both classes for the same target.
    for (u32 i = 0; i < kDriverFaultThreshold; ++i)
    {
        const EreportClass cls = (i % 2 == 0) ? EreportClass::DriverFault : EreportClass::DriverTimeout;
        EreportPost(cls, EreportSeverity::Recoverable, /*target_id=*/0xD042, /*aux0=*/i, /*aux1=*/0, "fma-selftest");
    }

    // Phase 3: KernelIntegrity. ONE event fires.
    EreportPost(EreportClass::KernelIntegrity, EreportSeverity::Critical, /*target_id=*/0xC011, /*aux0=*/0, /*aux1=*/0,
                "fma-selftest");

    // Run the diagnosis engine once over the freshly-posted events.
    const u32 new_suspects = DiagnoseTick();
    if (new_suspects != 3)
    {
        arch::SerialWrite("[fma] self-test: expected 3 new suspects, got ");
        arch::SerialWriteHex(new_suspects);
        arch::SerialWrite("\n");
        core::Panic("diag/fma", "self-test: wrong new-suspect count");
    }

    // Verify each suspect is present via the walker.
    u32 found = 0;
    SuspectWalk(kSuspectRingSize, &StFindSuspect, &found);
    if ((found & 0x7) != 0x7)
    {
        arch::SerialWrite("[fma] self-test: missing suspects, mask=");
        arch::SerialWriteHex(found);
        arch::SerialWrite("\n");
        core::Panic("diag/fma", "self-test: suspect ring missing entries");
    }

    // Rate-limit gate: a second tick on the same correlated state
    // must NOT add another set of suspects (the "recently fired"
    // table suppresses repeats inside the window).
    const u32 new_suspects_2 = DiagnoseTick();
    if (new_suspects_2 != 0)
    {
        arch::SerialWrite("[fma] self-test: re-tick fired more suspects: ");
        arch::SerialWriteHex(new_suspects_2);
        arch::SerialWrite("\n");
        core::Panic("diag/fma", "self-test: rate limit failed");
    }

    // Stats sanity. EreportStats should reflect at least the events
    // we posted + the two diagnose calls.
    const EreportStats st = EreportStatsRead();
    const u64 expected_events = kEccCorrelationThreshold + kDriverFaultThreshold + 1;
    if (st.events_total < expected_events)
    {
        core::Panic("diag/fma", "self-test: events_total under-counted");
    }
    if (st.diagnoses_total < 2)
    {
        core::Panic("diag/fma", "self-test: diagnoses_total under-counted");
    }
    if (st.suspects_identified < 3)
    {
        core::Panic("diag/fma", "self-test: suspects_identified under-counted");
    }

    arch::SerialWrite("[fma] self-test OK (ecc + driver + integrity correlation + rate limit).\n");
}

} // namespace duetos::diag::fma
