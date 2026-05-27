/*
 * DuetOS — hung-task detector, v0.
 *
 * See `hung_task.h` for the public contract. This TU owns the
 * walker, per-TID rate-limit slot table, and the self-test.
 *
 * Pattern after Linux's `kernel/hung_task.c`: scan every task,
 * compute "blocked for this long", emit one warning the first
 * time a TID crosses the threshold, suppress repeats. We do
 * NOT (yet) implement the "kill on hang" escalation Linux's
 * `hung_task_panic` sysctl offers — see hung_task.h SCOPE for
 * why (no safe cross-queue detach primitive in v0).
 */

#include "diag/hung_task.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "debug/probes.h"
#include "diag/fault_react.h"
#include "diag/fma/ereport.h"
#include "log/klog.h"
#include "sched/sched.h"
#include "security/fault_domain.h"
#include "util/types.h"

namespace duetos::diag
{

namespace
{

// Per-TID rate-limit slot. Tracks "I've already warned about this
// TID at this tick". Lookup is a linear scan over `kMaxConcurrentHungTracks`
// (32) entries — plenty for the realistic case (one or two
// concurrent hangs at a time during triage), and the constant
// scan cost is negligible compared to the all-tasks walk.
//
// Slot semantics:
//   warned_tid == 0    -> free slot (TID 0 is the boot task, which
//                        is never Blocked, so it's safe to use as
//                        the sentinel).
//   warned_at_tick     -> tick value of the warning. Compare
//                        against the current tick + the rewarm
//                        suppression window to decide "is this
//                        TID still in its quiet period?"
struct HungTaskSlot
{
    u64 warned_tid;
    u64 warned_at_tick;
};

constexpr u32 kMaxConcurrentHungTracks = 32;
constinit HungTaskSlot g_slots[kMaxConcurrentHungTracks] = {};

constinit u64 g_warnings_total = 0;
constinit bool g_enabled = true;

// Bounded stack-buffer cap for one walker pass. 32 is enough for
// every realistic concurrent-hang scenario at v0 task counts
// (typically <30 live tasks). A larger workload still gets one
// pass's worth of coverage per beat; the next beat picks up the
// rest. Avoids allocating on the heartbeat path.
constexpr u64 kMaxBlockedSnapshotEntries = 32;

// True while HungTaskSelfTest is driving its synthetic stretch
// of the state machine. The walker still runs (the test relies
// on it firing the warning), but if a stray production scan
// landed on the same beat it would see the same synthetic
// snapshot and double-fire. Gating ensures the walker is
// effectively single-tenant for the self-test window.
constinit bool g_self_test_in_progress = false;

// Look up or claim a slot for `tid`. Returns nullptr if the
// table is full AND the TID isn't already tracked. Caller has
// no lock — slot mutations are non-atomic but the heartbeat is
// single-threaded by construction (one heartbeat task per
// kernel), and the table is only read from `HungTaskTick`.
HungTaskSlot* FindOrClaimSlot(u64 tid)
{
    if (tid == 0)
    {
        return nullptr;
    }
    HungTaskSlot* free_slot = nullptr;
    for (u32 i = 0; i < kMaxConcurrentHungTracks; ++i)
    {
        if (g_slots[i].warned_tid == tid)
        {
            return &g_slots[i];
        }
        if (free_slot == nullptr && g_slots[i].warned_tid == 0)
        {
            free_slot = &g_slots[i];
        }
    }
    return free_slot;
}

// Internal one-shot walker shared by the production path and the
// self-test. Returns the number of warnings emitted during this
// invocation so the self-test can assert on it without racing
// the global counter (which other subsystems may also bump in
// principle, though today only this TU writes to it).
//
// `threshold` is the per-call gate on `stuck_for` so the self-
// test can drive the state machine without depending on the
// boot tick counter actually being large enough (boot reaches
// ~17 s by the time the self-test runs, well under the
// production 30 s threshold). Production callers pass
// `kHungTaskThresholdTicks`; the self-test passes a tiny value.
u64 TickInternal(u64 now_ticks, u64 threshold)
{
    sched::SchedBlockedTaskInfo snapshot[kMaxBlockedSnapshotEntries];
    const u64 count = sched::SchedSnapshotBlockedTasks(snapshot, kMaxBlockedSnapshotEntries);

    u64 emitted = 0;
    for (u64 i = 0; i < count; ++i)
    {
        const sched::SchedBlockedTaskInfo& info = snapshot[i];

        // Block-start anchor in the future means the tick counter
        // wrapped or the snapshot was taken right as a task entered
        // Blocked — either way, "stuck for negative ticks" is
        // nonsense; skip.
        if (info.block_start_tick > now_ticks)
        {
            continue;
        }
        const u64 stuck_for = now_ticks - info.block_start_tick;
        if (stuck_for < threshold)
        {
            continue;
        }

        HungTaskSlot* slot = FindOrClaimSlot(info.id);
        if (slot == nullptr)
        {
            // Track table is full — every slot is occupied by a
            // distinct still-suppressing TID. Drop this entry on
            // the floor for this pass; the next beat retries and
            // by then one of the existing entries has likely aged
            // out of its rewarm window. Not worth an alloc to
            // grow the table — a workload with >32 concurrent
            // hangs has bigger problems than a missed warn line.
            continue;
        }
        const bool already_tracked = (slot->warned_tid == info.id);
        const bool inside_suppression =
            already_tracked && (now_ticks - slot->warned_at_tick < kHungTaskRewarmSuppressionTicks);
        if (inside_suppression)
        {
            continue;
        }

        slot->warned_tid = info.id;
        slot->warned_at_tick = now_ticks;
        __atomic_add_fetch(&g_warnings_total, 1, __ATOMIC_RELAXED);
        ++emitted;

        // Identity line — emitted BEFORE FaultReactDispatch's
        // bare `val=<tid>` warning so a log reader sees task
        // name + stuck-ticks alongside each other. Mirror the
        // soft-lockup detector's shape so an operator parsing
        // either subsystem's lines sees the same field order.
        arch::SerialWrite("[hung-task] task blocked tid=");
        arch::SerialWriteHex(info.id);
        arch::SerialWrite(" name=\"");
        arch::SerialWrite(info.name != nullptr ? info.name : "<unknown>");
        arch::SerialWrite("\" stuck_ticks=");
        arch::SerialWriteHex(stuck_for);
        arch::SerialWrite("\n");

        // Fire the probe so an attached GDB can break on
        // `duetos::debug::ProbeFire` and inspect the offending
        // task's stack. Passing the TID lets the probe-ring entry
        // identify the task at panic time.
        KBP_PROBE_V(::duetos::debug::ProbeId::kHungTaskDetected, info.id);

        // Route through FaultReactDispatch with HungTask so the
        // per-domain policy + kernel-owned floor get a say. Domain
        // is invalid (the detector doesn't bind a domain to the
        // generic "task X is stuck" signal) — the dispatcher
        // decays RestartDomain to Continue for invalid domains,
        // matching the v0 observational policy.
        FaultEvidence ev = {};
        ev.source = "diag/hung-task";
        ev.kind = FaultKind::HungTask;
        ev.severity = FaultSeverity::Degraded;
        ev.attempt_count = 0;
        ev.faulting_rip = 0;
        ev.aux = info.id;
        (void)FaultReactDispatch(::duetos::core::kFaultDomainInvalid, ev);

        // FMA bridge: emit an ereport so the diagnosis engine can
        // correlate repeated hung-task warnings across time. The
        // correlation key is the TID (which the engine can roll up
        // by; a repeated hang on the same TID is more diagnostic
        // than a sequence of distinct TIDs). aux carries stuck_for.
        ::duetos::diag::fma::EreportPost(::duetos::diag::fma::EreportClass::HungTask,
                                         ::duetos::diag::fma::EreportSeverity::Degraded, info.id, stuck_for, 0,
                                         "diag.hungtask");
    }
    return emitted;
}

} // namespace

void HungTaskTick()
{
    if (!g_enabled)
    {
        return;
    }
    // The self-test drives TickInternal directly; if the
    // production path fires at the same beat it would land a
    // second warning on the same synthetic TID. The self-test
    // is bounded and runs once at boot, so the gate isn't
    // load-bearing on the hot path — it's the same defensive
    // shape soft-lockup uses for its synthetic state.
    if (g_self_test_in_progress)
    {
        return;
    }
    (void)TickInternal(sched::SchedNowTicks(), kHungTaskThresholdTicks);
}

void HungTaskDisable()
{
    g_enabled = false;
}

void HungTaskEnable()
{
    // Reset the slot table so a re-enable after a quiet period
    // doesn't leave stale "still-suppressed" entries that
    // permanently shadow the next legitimate hang. Same shape
    // as `SoftLockupEnable`.
    for (u32 i = 0; i < kMaxConcurrentHungTracks; ++i)
    {
        g_slots[i].warned_tid = 0;
        g_slots[i].warned_at_tick = 0;
    }
    g_enabled = true;
}

u64 HungTaskWarningsEmitted()
{
    return __atomic_load_n(&g_warnings_total, __ATOMIC_RELAXED);
}

namespace
{

// Self-test fixture: a task that blocks on its private WaitQueue
// forever. The self-test spawns one, waits for it to actually
// reach the Blocked state, rewinds its `block_start_tick` into
// the past, runs the detector, asserts a warning, then signals
// the task to exit so we don't leak.
struct SelfTestFixture
{
    sched::WaitQueue wq;
    volatile bool entered_block;
    volatile bool please_exit;
};

constexpr const char* kSelfTestTaskName = "hung-task-selftest-victim";

[[noreturn]] void SelfTestVictimMain(void* arg)
{
    auto* fx = static_cast<SelfTestFixture*>(arg);
    // Block UNTIMED on the fixture's wait queue. Untimed is
    // crucial — a timed wait would have the victim flipping
    // Blocked↔Ready repeatedly, racing with the test driver's
    // snapshot + rewind. With untimed blocking, the victim
    // stays in Blocked state until the driver explicitly calls
    // `WaitQueueWakeAll(&fx->wq)` during teardown. The Cli/Sti
    // bracket is the standard WaitQueue "check condition then
    // block" race closer.
    while (!fx->please_exit)
    {
        arch::Cli();
        if (fx->please_exit)
        {
            arch::Sti();
            break;
        }
        fx->entered_block = true;
        sched::WaitQueueBlock(&fx->wq);
        arch::Sti();
    }
    sched::SchedExit();
}

} // namespace

void HungTaskSelfTest()
{
    arch::SerialWrite("[hung-task] self-test: state machine + threshold + rate limit\n");

    g_self_test_in_progress = true;

    // Snapshot the warnings counter so we can assert on the
    // delta — other subsystems writing to it would otherwise
    // make the asserts brittle.
    const u64 saved_warnings = __atomic_load_n(&g_warnings_total, __ATOMIC_RELAXED);

    // Reserve the first slot, then clear the rest so a prior
    // session's residue can't hide our synthetic TID. (Boot-time
    // the slots are zero anyway; the save/restore makes the test
    // re-runnable from a shell command later.)
    for (u32 i = 0; i < kMaxConcurrentHungTracks; ++i)
    {
        g_slots[i].warned_tid = 0;
        g_slots[i].warned_at_tick = 0;
    }

    // Spawn the victim. SchedCreate puts it on the runqueue Ready;
    // we yield until it actually reaches the Blocked state.
    SelfTestFixture fx = {};
    fx.entered_block = false;
    fx.please_exit = false;
    sched::Task* victim = sched::SchedCreate(&SelfTestVictimMain, &fx, kSelfTestTaskName);
    if (victim == nullptr)
    {
        // SchedCreate logs its own failure; bail without panic so
        // a release build under memory pressure doesn't take the
        // box down for a self-test miss. Self-test contract is
        // "panic on the gating-logic-wrong path" — a resource
        // failure here is not a gating bug.
        g_self_test_in_progress = false;
        arch::SerialWrite("[hung-task] self-test: SKIPPED (SchedCreate failed)\n");
        return;
    }

    // Pump until the victim is actually observable in the
    // Blocked state via the same walker the detector uses.
    // `entered_block` flips to true BEFORE the victim calls
    // WaitQueueBlock, so trusting that flag races the victim's
    // own Running→Blocked transition; the snapshot is the
    // authoritative answer. Bound the spin so a regression in
    // the scheduler can't deadlock the boot self-test path.
    const u64 victim_tid = sched::TaskId(victim);
    bool victim_seen_blocked = false;
    for (u32 i = 0; i < 4096 && !victim_seen_blocked; ++i)
    {
        sched::SchedYield();
        sched::SchedBlockedTaskInfo probe_buf[kMaxBlockedSnapshotEntries];
        const u64 probe_count = sched::SchedSnapshotBlockedTasks(probe_buf, kMaxBlockedSnapshotEntries);
        for (u64 j = 0; j < probe_count; ++j)
        {
            if (probe_buf[j].id == victim_tid)
            {
                victim_seen_blocked = true;
                break;
            }
        }
    }
    if (!victim_seen_blocked)
    {
        core::Panic("diag/hung-task", "self-test: victim never reached Blocked state");
    }

    // Backdoor: rewind the victim's block_start_tick to a small
    // value so `now - block_start_tick` exceeds the self-test's
    // (deliberately tiny) threshold. We don't need to push the
    // anchor as far back as the production threshold because the
    // self-test threshold is set below to a small constant —
    // saving us from depending on the boot tick counter actually
    // being large enough to subtract the production 30 s from.
    const u64 rewind_delta = 200;
    const u64 tweaked = sched::SchedSelftestRewindBlockStart(kSelfTestTaskName, rewind_delta);
    if (tweaked == 0)
    {
        core::Panic("diag/hung-task", "self-test: selftest backdoor did not find the victim");
    }

    // First detector pass. At boot-time the system has several
    // legitimately-long-blocked tasks too (kbd-reader, mouse-
    // reader, xhci-hid-poll, reaper — anything that parks on a
    // wait queue for the duration of a quiet QEMU boot crosses
    // the 30 s threshold by the time the self-test runs). The
    // detector correctly flags every one of them. Assert
    // "at least one warning fired" — the precise number
    // depends on which boot phase the self-test lands in. The
    // global warning counter advancing by ≥1 plus a non-empty
    // post-pass slot table together prove the threshold +
    // dispatch path are wired correctly. Combined with the
    // second pass's "zero re-warns" check below, this also
    // proves the per-TID rate limit works (a broken rate limit
    // would let the second pass re-fire the same TIDs).
    // Use a small per-call threshold so the test doesn't depend
    // on the boot tick counter reaching the production 30 s
    // mark. The rewind above subtracted 200 ticks from `now`, so
    // any threshold ≤ 200 will trigger the warning for the
    // victim. The boot-time long-blocked tasks (reaper,
    // usershell) sit at 0..50 ticks blocked, well under 100, so
    // they don't false-trigger.
    const u64 selftest_threshold = 100;
    const u64 now = sched::SchedNowTicks();
    const u64 emitted_first = TickInternal(now, selftest_threshold);
    if (emitted_first < 1)
    {
        core::Panic("diag/hung-task", "self-test: first pass emitted no warnings");
    }
    if (__atomic_load_n(&g_warnings_total, __ATOMIC_RELAXED) <= saved_warnings)
    {
        core::Panic("diag/hung-task", "self-test: global warning counter did not advance");
    }
    // Confirm OUR victim was warned about by checking its TID
    // appears in the slot table. Without this check, an
    // implementation bug that filtered our victim out of the
    // snapshot but warned about the system tasks would still
    // pass the >=1 emitted check.
    bool victim_slotted = false;
    for (u32 i = 0; i < kMaxConcurrentHungTracks; ++i)
    {
        if (g_slots[i].warned_tid == sched::TaskId(victim))
        {
            victim_slotted = true;
            break;
        }
    }
    if (!victim_slotted)
    {
        core::Panic("diag/hung-task", "self-test: victim TID was not slotted after first pass");
    }

    // Second detector pass on the same tick: expect zero new
    // warnings (the per-TID rate limit suppresses the re-warn
    // for every TID we already slotted). Rewind again — the
    // production walker may have run between the two passes
    // (heartbeat-driven) and the wake path clears
    // block_start_tick on a re-block cycle, so re-prime the
    // anchor. The rate-limit lookup is on the TID and doesn't
    // depend on the anchor.
    (void)sched::SchedSelftestRewindBlockStart(kSelfTestTaskName, rewind_delta);
    const u64 emitted_second = TickInternal(now, selftest_threshold);
    if (emitted_second != 0)
    {
        core::Panic("diag/hung-task", "self-test: rate limit failed (re-warned)");
    }

    // Tell the victim to exit, kick its wait queue, and yield
    // until it's actually gone so we don't leak. The reaper
    // does the actual cleanup; we just need the task off the
    // wait queue and through Schedule() so it transitions to
    // Dead.
    fx.please_exit = true;
    {
        u64 woken = 0;
        for (u32 i = 0; i < 64 && woken == 0; ++i)
        {
            woken = sched::WaitQueueWakeAll(&fx.wq);
            sched::SchedYield();
        }
    }

    // Give the scheduler several rounds to let the victim
    // observe please_exit and call SchedExit. Bounded — if it
    // never exits, the next boot's hung-task detector will
    // flag the lingering victim itself, which is at least
    // self-consistent. We do NOT panic on lingering exit
    // because the timing depends on heartbeat-aligned races
    // that aren't part of what the self-test asserts.
    for (u32 i = 0; i < 256; ++i)
    {
        sched::SchedYield();
    }

    // Clear the slot table so the per-TID rate limit doesn't
    // carry forward into the production walker — production
    // expects an empty table at the start of its first pass.
    for (u32 i = 0; i < kMaxConcurrentHungTracks; ++i)
    {
        g_slots[i].warned_tid = 0;
        g_slots[i].warned_at_tick = 0;
    }

    g_self_test_in_progress = false;

    arch::SerialWrite("[hung-task] self-test OK (threshold + rate limit + probe).\n");
}

} // namespace duetos::diag
