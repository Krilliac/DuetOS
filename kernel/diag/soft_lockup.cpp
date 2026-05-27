/*
 * DuetOS — soft-lockup detector, v0 (plan D4).
 *
 * See `soft_lockup.h` for the public contract. This TU owns the
 * state machine + warning rate-limiting + self-test.
 *
 * Why it's a separate TU from the NMI watchdog (`arch::NmiWatchdog*`):
 *   - Watchdog runs in NMI context, fires only when timer IRQ has
 *     stopped, panics on detection.
 *   - This detector runs in IRQ context (timer IRQ tail), fires
 *     when a task hogs the CPU, logs and continues.
 *   The two failure modes are disjoint and the response policies
 *   differ; combining them would tangle the rate-limiting + the
 *   panic semantics.
 */

#include "diag/soft_lockup.h"

#include "acpi/acpi.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/smp.h"
#include "core/panic.h"
#include "cpu/percpu.h"
#include "diag/fault_react.h"
#include "diag/fma/ereport.h"
#include "log/klog.h"
#include "security/fault_domain.h"
#include "util/types.h"

namespace duetos::diag
{

namespace
{

// Per-CPU detector state. Each online CPU's LAPIC-timer tick
// indexes its own slot via `cpu::CurrentCpuIdOrBsp()`, so the
// streak counters track the task hogging THAT CPU rather than
// being thrashed by whichever CPU's tick fired most recently.
// `_pad` keeps adjacent slots on independent cache lines so a
// busy CPU's hot updates don't false-share with its neighbour's
// streak counter on the same cache line.
//
// Pre-2026-05-27 history: this used a single global slot
// (`g_per_cpu[0]` aliased as `g_state`), which raced as soon as
// SMP brought APs online — the BSP's tick reset `last_tid` to
// the BSP's task while the AP's tick reset it to the AP's task,
// preventing either streak from reaching the threshold and
// masking real lockups. Per-CPU storage mirrors the 2026-05-22
// lockdep-held-stack fix; the (source, kind) pair on the
// fault-react dispatch is unchanged so policy still applies
// uniformly across CPUs.
struct alignas(64) PerCpuState
{
    u64 last_tid;       ///< Most recently observed running TID on this CPU.
    u64 same_tid_count; ///< Consecutive ticks with that TID on this CPU.
    u64 warned_for_tid; ///< TID we've already warned about on this CPU;
                        ///< rate-limit gate.
    u64 warned_at_tick; ///< now_ticks of the most recent warn — used by the
                        ///< per-TID time-based debounce below.
    u8 _pad[32];        ///< Padding to a 64-byte cache line (4×u64 = 32 B).
};

// Suppress repeat warns for the SAME TID within this many ticks of the
// previous warn. The existing `warned_for_tid` gate only suppresses
// while the task stays on CPU continuously; it resets the moment the
// scheduler swaps to a different task and back. Under PE import
// resolution (kboot runs ~1s of synchronous work, gets briefly preempted
// by kbd-reader / timer-tick / etc., then resumes another ~1s stretch),
// the bare gate fires a fresh warn every ~1s of guest wall time.
// The 2026-05-24 VBox boot showed 10 such warns within a 20-second
// PE-resolution window — same TID, same `ticks_in_run=101` — pure spam.
// 500 ticks (~5s at 100Hz) was picked so a genuinely-stuck task still
// gets one warn per 5s (loud enough for ops) but a CPU-hogging-but-
// progressing task fires once per task burst.
constexpr u64 kRewarmSuppressionTicks = 500;

constexpr u32 kSoftLockupCpuMax = static_cast<u32>(::duetos::acpi::kMaxCpus);
constinit PerCpuState g_per_cpu[kSoftLockupCpuMax] = {};

// Current-CPU slot accessor. Falls back to slot 0 (BSP) when
// CurrentCpuIdOrBsp returns out-of-range — matches the lockdep
// pattern, and is the correct behaviour pre-BSP-install (the
// LAPIC-timer-driven SoftLockupTick is unreachable that early
// anyway, but the self-test runs at boot and explicitly drives
// slot 0).
inline u32 CurrentSoftLockupSlot()
{
    const u32 id = ::duetos::cpu::CurrentCpuIdOrBsp();
    return (id < kSoftLockupCpuMax) ? id : 0u;
}

constinit u64 g_warnings_total = 0; ///< Total warnings (across all CPUs).
constinit bool g_enabled = true;    ///< Disabled from panic path.
// True while SoftLockupSelfTest is driving synthetic ticks. The
// LAPIC-timer-driven SoftLockupTick path early-returns when this
// is set so it can't interleave its real tid into the self-test's
// synthetic state machine and trip the rate-limit assertion. The
// self-test calls a sibling helper that bypasses this gate.
constinit bool g_self_test_in_progress = false;

// Internal tick implementation. The public `SoftLockupTick` adds
// the timer-driven gates; the self-test calls the internal one
// directly so its synthetic tids reach the state machine
// regardless of whether the timer-driven path is gated.
void TickInternal(u32 slot, u64 now_ticks, u64 current_tid, const char* current_name);

} // namespace

void SoftLockupTick(u64 now_ticks, u64 current_tid, const char* current_name)
{
    if (!g_enabled || g_self_test_in_progress)
    {
        return;
    }
    TickInternal(CurrentSoftLockupSlot(), now_ticks, current_tid, current_name);
}

namespace
{

void TickInternal(u32 slot, u64 now_ticks, u64 current_tid, const char* current_name)
{
    PerCpuState& state = g_per_cpu[slot];

    // Idle / boot task (TID 0) never counts as a lockup — those
    // are legitimately always-running.
    if (current_tid == 0)
    {
        state.last_tid = 0;
        state.same_tid_count = 0;
        return;
    }

    if (current_tid != state.last_tid)
    {
        // Scheduler swapped to a different task — reset the
        // counter. NB: do NOT clear `warned_for_tid` /
        // `warned_at_tick` here; those carry the per-TID
        // time-based suppression across brief preemptions so a
        // task that hogs the CPU in repeated 1s bursts doesn't
        // spam a fresh warn after every preempt-and-resume cycle.
        // Genuine independent lockups of different TIDs are still
        // distinguished by the (warned_for_tid != current_tid)
        // check below.
        state.last_tid = current_tid;
        state.same_tid_count = 1;
        return;
    }

    ++state.same_tid_count;
    // Two-layer rate limit:
    //   1. Already-warned-for-this-TID inside the current burst (existing).
    //   2. Already-warned-for-this-TID within the past
    //      kRewarmSuppressionTicks regardless of intermediate preempts.
    // The second layer is what stops the PE-import-resolution spam
    // documented in the 2026-05-24 VBox boot log.
    const bool same_tid_recently_warned =
        (state.warned_for_tid == current_tid) && (now_ticks - state.warned_at_tick < kRewarmSuppressionTicks);
    if (state.same_tid_count > kSoftLockupThresholdTicks && state.warned_for_tid != current_tid &&
        !same_tid_recently_warned)
    {
        // First crossing of the threshold for this run. Route
        // through diag::FaultReactDispatch so the dispatch
        // counter reflects soft-lockup events. Default policy
        // for SoftLockup is RestartDomain, but we don't bind a
        // domain (there's nothing TO restart for "task X is
        // hogging the CPU") — the dispatcher decays
        // RestartDomain → Continue when domain is unbound, so
        // the observable outcome is "log + return", same as
        // the previous KLOG_WARN_V path. The "already warned"
        // gate stays at this layer to keep rate-limiting cheap.
        //
        // g_warnings_total is incremented atomically — every
        // online CPU's tick can hit this path concurrently and
        // a plain `++` would lose increments under load.
        __atomic_add_fetch(&g_warnings_total, 1, __ATOMIC_RELAXED);
        state.warned_for_tid = current_tid;
        state.warned_at_tick = now_ticks;

        // Identity line — emitted BEFORE FaultReactDispatch's
        // bare `val=<tid>` warning so a log reader sees task
        // name and stuck-ticks count next to each other. Raw
        // SerialWrite (not klog) because we are inside the timer
        // IRQ tail: klog's spinlock would deadlock if the hot
        // task happens to be holding it, and raw UART bytes get
        // out even when the rest of the world is wedged. One
        // line per first-crossing of the threshold (rate-limited
        // by `warned_for_tid` above) — costs ~120 UART bytes per
        // distinct lockup, zero cost when no lockup happens.
        arch::SerialWrite("[soft-lockup] task stuck cpu=");
        arch::SerialWriteHex(slot);
        arch::SerialWrite(" tid=");
        arch::SerialWriteHex(current_tid);
        arch::SerialWrite(" name=\"");
        arch::SerialWrite(current_name != nullptr ? current_name : "<unknown>");
        arch::SerialWrite("\" ticks_in_run=");
        arch::SerialWriteHex(state.same_tid_count);
        arch::SerialWrite("\n");

        // Broadcast NMI to peer CPUs so they each capture their
        // own panic_snapshot_* state. The peer NMI handler
        // populates the snapshot and halts; the snapshots
        // survive into a subsequent panic dump if this lockup
        // escalates. If the lockup eventually clears on its
        // own, the snapshots are just dead BSS — no cost. This
        // is the "lightweight cross-CPU visibility" half of the
        // NMI-watchdog HPET-fallback proposal — the full
        // hardware-NMI-on-no-progress lands when the HPET driver
        // gains per-timer comparator + IOAPIC routing.
        //
        // Skipped during self-test (the test exercises the state
        // machine with synthetic TIDs and shouldn't broadcast).
        if (!g_self_test_in_progress)
            ::duetos::arch::PanicBroadcastNmi();

        ::duetos::diag::FaultEvidence ev = {};
        ev.source = "diag/soft-lockup";
        ev.kind = ::duetos::diag::FaultKind::SoftLockup;
        ev.severity = ::duetos::diag::FaultSeverity::Degraded;
        ev.attempt_count = 0;
        ev.faulting_rip = 0;
        ev.aux = current_tid;
        (void)::duetos::diag::FaultReactDispatch(::duetos::core::kFaultDomainInvalid, ev);

        // FMA bridge: also post an ereport so the diagnosis engine
        // can correlate soft-lockup events across time (a single
        // task spiking once vs. a runaway pattern). target_id is
        // the stuck task's TID; aux carries the streak length.
        ::duetos::diag::fma::EreportPost(::duetos::diag::fma::EreportClass::SoftLockup,
                                         ::duetos::diag::fma::EreportSeverity::Degraded, current_tid,
                                         state.same_tid_count, slot, "diag.softlockup");
    }
}

} // namespace

void SoftLockupDisable()
{
    g_enabled = false;
}

void SoftLockupEnable()
{
    // Reset every CPU's streak state so a re-enable doesn't
    // immediately fire on a stale TID match. `warned_at_tick`
    // is reset too — otherwise a re-enable after a long quiet
    // period could leave the per-TID time-based debounce
    // (`kRewarmSuppressionTicks`) primed with a far-past tick
    // that satisfies "recently warned" indefinitely.
    for (u32 i = 0; i < kSoftLockupCpuMax; ++i)
    {
        g_per_cpu[i].last_tid = 0;
        g_per_cpu[i].same_tid_count = 0;
        g_per_cpu[i].warned_for_tid = 0;
        g_per_cpu[i].warned_at_tick = 0;
    }
    g_enabled = true;
}

u64 SoftLockupWarningsEmitted()
{
    return __atomic_load_n(&g_warnings_total, __ATOMIC_RELAXED);
}

void SoftLockupSelfTest()
{
    arch::SerialWrite("[soft-lockup] self-test: state machine + threshold + reset\n");

    // Gate the timer-driven SoftLockupTick path for the duration
    // of the test. Without this, the LAPIC tick handler interleaves
    // its real (current_tid) into the per-CPU state machine between
    // our synthetic ticks and the rate-limit assertion fires
    // spuriously on a real-world preemption boundary. The test
    // calls TickInternal directly to bypass the same gate.
    g_self_test_in_progress = true;

    // Save + reset state so the test starts from a clean slate
    // even if a prior caller already advanced counters. (At boot
    // this is fresh; the save/restore makes the test re-runnable
    // from a shell command later.) The self-test drives slot 0
    // explicitly — this runs during BSP-only boot init before
    // APs come online, so slot 0 is the only slot in play. Once
    // a shell-driven re-run path appears, this could be parameterised
    // on the current CPU id; for now the boot-time invariant is
    // strong enough that hard-coding slot 0 is correct.
    constexpr u32 kSelfTestSlot = 0;
    const u64 saved_warnings = __atomic_load_n(&g_warnings_total, __ATOMIC_RELAXED);
    PerCpuState& state = g_per_cpu[kSelfTestSlot];
    state.last_tid = 0;
    state.same_tid_count = 0;
    state.warned_for_tid = 0;
    state.warned_at_tick = 0;

    auto warnings_now = []() -> u64 { return __atomic_load_n(&g_warnings_total, __ATOMIC_RELAXED); };

    // (1) Idle TID (0) never counts. Drive 200 ticks with TID=0
    // and assert no warning.
    for (u64 i = 0; i < 200; ++i)
    {
        TickInternal(kSelfTestSlot, i, 0, "selftest-idle");
    }
    if (warnings_now() != saved_warnings)
    {
        core::Panic("diag/soft-lockup", "self-test: idle TID triggered a warning");
    }

    // (2) Same TID for threshold+1 consecutive ticks → exactly
    // one warning.
    for (u64 i = 0; i <= kSoftLockupThresholdTicks; ++i)
    {
        TickInternal(kSelfTestSlot, 1000 + i, 42, "selftest-42");
    }
    if (warnings_now() != saved_warnings + 1)
    {
        core::Panic("diag/soft-lockup", "self-test: threshold did not trigger exactly one warning");
    }

    // (3) Continuing on the same TID does NOT re-warn (rate limit).
    for (u64 i = 0; i < kSoftLockupThresholdTicks * 2; ++i)
    {
        TickInternal(kSelfTestSlot, 2000 + i, 42, "selftest-42");
    }
    if (warnings_now() != saved_warnings + 1)
    {
        core::Panic("diag/soft-lockup", "self-test: rate limit failed (re-warned)");
    }

    // (4) TID change resets the state — short subsequent run
    // does not warn. Use a tick value far enough past the prior
    // burst to outrun `kRewarmSuppressionTicks` (the per-TID
    // time-based debounce); otherwise step (5)'s threshold
    // crossing for TID 99 would be suppressed as "recently
    // warned" even though 99 has never been warned about.
    const u64 post_suppression_base = 2000 + kSoftLockupThresholdTicks * 2 + kRewarmSuppressionTicks + 1;
    TickInternal(kSelfTestSlot, post_suppression_base, 99, "selftest-99"); // single tick on TID 99; counter = 1
    if (warnings_now() != saved_warnings + 1)
    {
        core::Panic("diag/soft-lockup", "self-test: TID change spuriously warned");
    }

    // (5) Holding TID 99 long enough now warns (separate gate).
    for (u64 i = 0; i < kSoftLockupThresholdTicks; ++i)
    {
        TickInternal(kSelfTestSlot, post_suppression_base + 1 + i, 99, "selftest-99");
    }
    if (warnings_now() != saved_warnings + 2)
    {
        core::Panic("diag/soft-lockup", "self-test: post-reset threshold did not warn");
    }

    // (6) Per-CPU isolation: a different slot's state machine
    // must NOT have advanced. The single-slot bug masked real
    // lockups because every CPU's tick wrote slot 0; if a
    // future refactor regresses to that shape this check
    // catches it. Slot 1 only exists when acpi::kMaxCpus >= 2,
    // which is a constexpr — gate at compile time.
    if constexpr (kSoftLockupCpuMax >= 2)
    {
        const PerCpuState& other = g_per_cpu[1];
        if (other.last_tid != 0 || other.same_tid_count != 0 || other.warned_for_tid != 0)
        {
            core::Panic("diag/soft-lockup", "self-test: slot 1 contaminated by slot 0 writes");
        }
    }

    // Reset state for steady-state operation.
    state.last_tid = 0;
    state.same_tid_count = 0;
    state.warned_for_tid = 0;
    state.warned_at_tick = 0;

    // Re-open the timer-driven path now that the synthetic
    // sequence is done.
    g_self_test_in_progress = false;

    arch::SerialWrite("[soft-lockup] self-test OK (idle skip + threshold + rate limit + per-TID reset).\n");
}

} // namespace duetos::diag
