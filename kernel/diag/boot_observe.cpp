#include "diag/boot_observe.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "core/init.h"
#include "test/smoke_profile.h"
#include "time/timekeeper.h"
#include "util/types.h"

namespace duetos::diag
{

namespace
{

constexpr u32 kPhaseCount = static_cast<u32>(core::Phase::kPhaseCount);

// One row per phase. Written single-threaded during boot by
// BootPhaseEnter; read by the report.
struct PhaseSlot
{
    bool entered;
    u64 enter_ms; ///< NowMs() at enter; 0 == clock not online yet.
    u64 dur_ms;   ///< Finalised span (next-enter or report); valid iff dur_known.
    bool dur_known;
};

constinit PhaseSlot g_slots[kPhaseCount] = {};
constinit i32 g_active = -1;               ///< Ordinal of the active phase, -1 == none.
constinit i32 g_last_entered = -1;         ///< For panic attribution.
constinit u64 g_boot_first_ms = 0;         ///< First non-zero NowMs() seen (total basis).
constinit bool g_suppressed = false;       ///< InitSelfTest plumbing window.
constinit u32 g_stall_phase = kPhaseCount; ///< == kPhaseCount means disarmed.

u64 NowMs()
{
    const u64 ns = time::MonotonicNs();
    return ns != 0 ? ns / 1'000'000 : 0;
}

bool UnderSmoke()
{
    return test::SmokeProfileGet() != test::SmokeProfile::None;
}

// Local decimal formatter. serial.h only ships SerialWriteHex; the
// boot report's whole point is human-readable + trivially bash-
// parseable, so a tiny base-10 emitter earns its place here (and
// nowhere else — it stays file-local).
void SerialWriteDec(u64 value)
{
    char buf[21];
    u32 i = sizeof(buf);
    buf[--i] = '\0';
    if (value == 0)
    {
        buf[--i] = '0';
    }
    while (value != 0 && i > 0)
    {
        buf[--i] = static_cast<char>('0' + (value % 10));
        value /= 10;
    }
    arch::SerialWrite(&buf[i]);
}

void EmitDurField(u64 dur_ms, bool known)
{
    if (known)
    {
        SerialWriteDec(dur_ms);
    }
    else
    {
        arch::SerialWrite("unknown");
    }
}

void FinalisePhase(u32 ord, u64 now_ms)
{
    bool known = false;
    u64 dur = 0;
    if (now_ms != 0 && g_slots[ord].enter_ms != 0)
    {
        dur = now_ms - g_slots[ord].enter_ms;
        known = true;
    }
    g_slots[ord].dur_ms = dur;
    g_slots[ord].dur_known = known;

    // Hold g_serial_lock for the whole sentinel so a concurrent AP-
    // bringup / klog / stress line can't slice it. Pre-fix: an AP's
    // `[sched/smp] calling SchedStartIdle ...` (which IS line-guarded)
    // landed BETWEEN our `[boot] phase=` and the phase name, producing
    // `[boot] phase=[sched/smp] calling SchedStartIdle ...` (observed
    // 2026-05-22 on claude/assembly-files-review-ju0dI, hid the actual
    // order of events when chasing an intermittent #PF).
    arch::SerialLineGuard guard;
    arch::SerialWrite("[boot] phase=");
    arch::SerialWrite(core::PhaseName(static_cast<core::Phase>(ord)));
    arch::SerialWrite(" complete t=");
    SerialWriteDec(now_ms);
    arch::SerialWrite(" dur=");
    EmitDurField(dur, known);
    arch::SerialWrite("\n");
}

} // namespace

void BootObserveSetStallPhase(core::Phase phase)
{
    g_stall_phase = static_cast<u32>(phase);
}

void BootObserveSuppress(bool on)
{
    g_suppressed = on;
}

core::Phase BootPhaseCurrent()
{
    return g_last_entered >= 0 ? static_cast<core::Phase>(g_last_entered) : core::Phase::Earlycon;
}

void BootPhaseEnter(core::Phase phase)
{
    const u32 ord = static_cast<u32>(phase);
    if (ord >= kPhaseCount || g_suppressed)
    {
        return;
    }

    const u64 now = NowMs();

    // A phase is active until the NEXT phase enters — the real boot
    // work is the imperative code between RunPhase calls, not the
    // near-instant dispatch. Finalise the previous span here.
    if (g_active >= 0 && static_cast<u32>(g_active) != ord)
    {
        FinalisePhase(static_cast<u32>(g_active), now);
    }

    g_slots[ord].entered = true;
    g_slots[ord].enter_ms = now;
    if (g_boot_first_ms == 0 && now != 0)
    {
        g_boot_first_ms = now;
    }
    g_active = static_cast<i32>(ord);
    g_last_entered = static_cast<i32>(ord);

    {
        arch::SerialLineGuard guard;
        arch::SerialWrite("[boot] phase=");
        arch::SerialWrite(core::PhaseName(phase));
        arch::SerialWrite(" begin\n");
    }

    // Debug injection: prove the wedge path. Spinning here produces no
    // serial progress, so the existing init-wedge detector in
    // arch/x86_64/timer.cpp trips after ~15 s and calls
    // BootWatchdogOnWedge() → structured STUCK + TestExit under smoke.
    if (g_stall_phase == ord)
    {
        {
            arch::SerialLineGuard guard;
            arch::SerialWrite("[boot] phase=");
            arch::SerialWrite(core::PhaseName(phase));
            arch::SerialWrite(" STALL-INJECTED (debug boot-stall=)\n");
        }
        for (;;)
        {
            asm volatile("pause" ::: "memory");
        }
    }
}

void BootPhaseFailed(core::Phase phase, u32 errcode)
{
    if (g_suppressed)
    {
        return;
    }
    const u8 ec = EncodeExit(BootExitCode::PhaseInitFail, phase);
    {
        arch::SerialLineGuard guard;
        arch::SerialWrite("[boot] phase=");
        arch::SerialWrite(core::PhaseName(phase));
        arch::SerialWrite(" FAIL ec=");
        arch::SerialWriteHex(ec);
        arch::SerialWrite(" err=");
        arch::SerialWriteHex(errcode);
        arch::SerialWrite("\n");
    }

    // Bare-metal / interactive boots keep their current behaviour: the
    // imperative path uses `RESULT_LOG_AND_DROP` on the RunPhase Result
    // (documented "log and continue" policy in `util/result_check.h`),
    // so we only escalate under a smoke profile, where a structured
    // exit code beats the harness waiting out the full wall timeout.
    if (UnderSmoke())
    {
        arch::TestExit(ec);
    }
}

// GAP: rides the existing init-wedge detector, which only arms once
// the timer IRQ is firing (~Phase::Apic onward). A wedge strictly
// before the timer is up stays owned by the triple-fault domain and
// the early-console path — there is no periodic context to observe it
// from. Revisit only if a pre-timer hang ever needs a structured
// code (would need a non-timer observation point).
void BootWatchdogOnWedge()
{
    if (g_active < 0)
    {
        return;
    }
    const core::Phase phase = static_cast<core::Phase>(g_active);
    const u8 ec = EncodeExit(BootExitCode::HungInPhase, phase);
    {
        arch::SerialLineGuard guard;
        arch::SerialWrite("[boot] phase=");
        arch::SerialWrite(core::PhaseName(phase));
        arch::SerialWrite(" STUCK ec=");
        arch::SerialWriteHex(ec);
        arch::SerialWrite(" (init-wedge: no serial progress)\n");
    }

    // Under a smoke profile, fail fast with the structured code. On
    // real hardware we only warn — the existing init-wedge mechanism
    // owns escalation there (init-wedge-panic=N), and we must not
    // halt a merely-slow box.
    if (UnderSmoke())
    {
        arch::TestExit(ec);
    }
}

void BootReportEmit()
{
    const u64 now = NowMs();

    // Finalise the phase still active at the sentinel (typically
    // Userland) so its span shows in both the ladder and the report.
    if (g_active >= 0)
    {
        FinalisePhase(static_cast<u32>(g_active), now);
        g_active = -1;
    }

    arch::SerialWrite("[boot-report] begin\n");

    for (u32 p = 0; p < kPhaseCount; ++p)
    {
        if (!g_slots[p].entered)
        {
            continue;
        }
        arch::SerialWrite("[boot-report] phase=");
        arch::SerialWrite(core::PhaseName(static_cast<core::Phase>(p)));
        arch::SerialWrite(" dur_ms=");
        EmitDurField(g_slots[p].dur_ms, g_slots[p].dur_known);
        arch::SerialWrite("\n");
    }

    // Selftest tally from the init registry (the cheap source the
    // plan mandates — no 70-site macro touch). A failed boot
    // self-test panics, so it never reaches here: the panic path
    // owns that signal via the Panic exit class. `fail` exists for
    // parse stability and is 0 on every path that gets this far.
    u32 pass = 0;
    u32 fail = 0;
    const u32 n = core::InitcallCount();
    for (u32 i = 0; i < n; ++i)
    {
        const core::InitcallRecord* rec = core::InitcallGet(i);
        if (rec == nullptr || rec->invoke_count == 0)
        {
            continue;
        }
        if (rec->ran_ok)
        {
            ++pass;
        }
        else
        {
            ++fail;
        }
    }
    arch::SerialWrite("[boot-report] selftests pass=");
    SerialWriteDec(pass);
    arch::SerialWrite(" fail=");
    SerialWriteDec(fail);
    arch::SerialWrite("\n");

    arch::SerialWrite("[boot-report] total_ms=");
    if (now != 0 && g_boot_first_ms != 0)
    {
        SerialWriteDec(now - g_boot_first_ms);
    }
    else
    {
        arch::SerialWrite("unknown");
    }
    arch::SerialWrite("\n");

    // Any FAIL / STUCK / panic already TestExited before the sentinel,
    // so reaching here means pass. The line is fixed so the harness
    // asserts one stable token instead of the old fragile signature
    // list. (Fix-journal / translator structured summaries are
    // emitted immediately above this block and stay independently
    // greppable.)
    arch::SerialWrite("[boot-report] result=pass\n");
    arch::SerialWrite("[boot-report] end\n");
}

} // namespace duetos::diag
