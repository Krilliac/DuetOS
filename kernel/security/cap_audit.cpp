/*
 * DuetOS — capability-gate audit hook implementation.
 *
 * See cap_audit.h for the public contract.
 *
 * Two-tier mode handling:
 *   - The compile-time `core::kCapAuditMode` constexpr seeds the
 *     boot-time default — that's what the build-flavor preset
 *     selected. Off-mode builds compile away EmitLine entirely.
 *   - At runtime, `g_mode` (initialised from the constexpr at boot)
 *     can be flipped by the shell. The trace function reads `g_mode`
 *     in non-Off compile-time builds; an Off-at-compile-time build
 *     pays nothing for the indirection because the constexpr branch
 *     short-circuits before `g_mode` is consulted.
 *
 * Why both:
 *   - Compile-time gives us "release builds drop the verbosity by
 *     default and the optimizer proves it by eliminating EmitLine
 *     when Off". You can't reach Full from an Off-at-compile-time
 *     build without rebuilding. That's a feature: a release image
 *     that didn't budget for cap-audit overhead can't be tricked
 *     into paying it at runtime.
 *   - Runtime gives Sample/Full/Off-mode builds the ability to flip
 *     between the three at the shell. An operator who wants verbose
 *     forensic capture for one minute can `cap-audit mode full`,
 *     observe, then `cap-audit mode sample` to dial back.
 */

#include "security/cap_audit.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "diag/fix_journal.h"
#include "log/klog.h"
#include "proc/process.h"
#include "time/tick.h"
#include "util/build_config.h"
#include "util/types.h"

namespace duetos::security
{

namespace
{

constinit u64 g_call_count = 0;
constinit u64 g_deny_count = 0;
constinit u64 g_sample_cursor = 0;
constinit bool g_force_next_sample = false;

// When true, the persistent fix-journal mirror in RingPushDenial is skipped.
// Set by the cap-gate self-test around its table sweep so the EXPECTED
// empty/nullptr-caps denials don't pollute KERNEL.FIX (and get mis-flagged
// HIGH by the patch generator). Process-context only; the self-test runs once
// at boot on the BSP, so a plain bool needs no synchronisation.
constinit bool g_suppress_journal = false;

// Denial-history ring. Fixed-capacity, newest-overwrites-oldest, all
// access from the audit hook (which is called with IRQs already
// inhibited by the gate path). `g_deny_seq` is the monotonic
// sequence number of the *next* denial slot; `(g_deny_seq - 1) %
// kDenyRingCap` is therefore the most-recently-written index. The
// `dropped` count records how many denials would have been
// evicted by the wrap had the operator not drained the ring — a
// non-zero value is the operator's signal to widen the buffer.
constexpr u64 kDenyRingCap = 256;
constinit CapAuditDenialRecord g_deny_ring[kDenyRingCap] = {};
constinit u64 g_deny_seq = 0;
constinit u64 g_deny_dropped = 0;

void RingPushDenial(const CapAuditEvent& event)
{
    const u64 seq = g_deny_seq++;
    if (seq >= kDenyRingCap)
        ++g_deny_dropped;
    CapAuditDenialRecord& slot = g_deny_ring[seq % kDenyRingCap];
    slot.sequence = seq;
    slot.boot_tick = ::duetos::time::TickCount();
    slot.syscall_number = event.syscall_number;
    slot.proc_id = event.proc_id;
    slot.required_mask = event.required_mask;
    slot.missing = event.missing;
    for (u32 i = 0; i < sizeof(slot._pad); ++i)
        slot._pad[i] = 0;

    // Mirror the denial into the fix journal so a recurring deny
    // pattern survives across boots (the 256-slot RAM ring above
    // does not — it's overwritten by the next deny storm). The
    // journal dedups per (cap, syscall) so a 1000-call storm
    // becomes one record with repeat=1000.
    //
    // ...unless the cap-gate self-test is mid-sweep: it deliberately denies
    // every non-zero-mask row with empty/nullptr caps, and persisting those
    // would flag the patch generator with spurious "proc 0" cap denials. The
    // in-RAM ring above already captured this denial for live inspection.
    if (g_suppress_journal)
        return;
    //
    // The pin shape is `cap.<CapName>` — dedup keys on the missing
    // cap kind (not the syscall) so the same cap denied across
    // many syscalls collapses to one row keyed by "this cap is
    // chronically missing"; ctx_a / ctx_b preserve the first hit's
    // syscall + proc_id for triage.
    char pin[40] = "cap.";
    const char* cap_name = duetos::core::CapName(event.missing);
    u64 w = 4;
    if (cap_name != nullptr)
    {
        while (w + 1 < sizeof(pin) && *cap_name != '\0')
        {
            pin[w++] = *cap_name++;
        }
    }
    pin[w] = '\0';
    (void)::duetos::diag::FixJournalRecord(::duetos::diag::FixDetector::CapDenial, pin,
                                           "review cap grant / deny policy for this caller", event.syscall_number,
                                           event.proc_id);
}

// Runtime mode. Initialised from the compile-time constexpr at the
// first call (or via CapAuditSetMode). The static-initialised value
// matches the constexpr so a build that never calls CapAuditSetMode
// behaves exactly as before.
constinit duetos::core::CapAuditMode g_mode = duetos::core::kCapAuditMode;

// Decide whether THIS call should emit a klog line. The compile-time
// constexpr short-circuits the Off case so the function call vanishes
// in Off-flavor builds; runtime mode handles the rest.
bool ShouldEmit()
{
    using duetos::core::CapAuditMode;
    // If the compile-time mode is Off, no caller can flip the runtime
    // to Sample/Full because EmitLine isn't even linked in. Short-
    // circuit here so the runtime branch below is dead code.
    if constexpr (duetos::core::kCapAuditMode == CapAuditMode::Off)
    {
        return false;
    }

    const CapAuditMode mode = g_mode;
    if (mode == CapAuditMode::Off)
    {
        return false;
    }
    if (mode == CapAuditMode::Full)
    {
        return true;
    }
    // Sample. The cursor is incremented every call; a line emits
    // when the cursor crosses a stride boundary. The race under
    // SMP is benign — at worst we miss or double-emit at the
    // boundary, which the audit already tolerates as advisory.
    if (g_force_next_sample)
    {
        g_force_next_sample = false;
        return true;
    }
    const u64 next = ++g_sample_cursor;
    return (next % duetos::core::kCapAuditSampleStride) == 0;
}

void EmitLine(const CapAuditEvent& event)
{
    const bool allowed = (event.missing == duetos::core::kCapNone);
    if (allowed)
    {
        ::duetos::core::LogWith2Values(::duetos::core::LogLevel::Info, "cap-audit", "syscall allow", "nr",
                                       event.syscall_number, "pid", event.proc_id);
    }
    else
    {
        // Use LogWithString to surface the missing-cap NAME rather
        // than its raw numeric value — operators care about
        // "missing FsWrite", not "missing 0x4". The syscall number
        // is hex-formatted via the V variant so the operator can
        // correlate with `inspect syscalls`.
        ::duetos::core::LogWithString(::duetos::core::LogLevel::Warn, "cap-audit", "syscall deny",
                                      duetos::core::CapName(event.missing), "missing");
        ::duetos::core::LogWithValue(::duetos::core::LogLevel::Warn, "cap-audit", "  nr", event.syscall_number);
    }
}

} // namespace

void CapAuditTrace(const CapAuditEvent& event)
{
    using duetos::core::CapAuditMode;
    // Off is the static branch the optimizer is best-positioned to
    // eliminate. We still bump the counters so a future shell
    // toggle could surface "audit was off but cap-gate fired N
    // times" — counters are cheap u64 increments.
    ++g_call_count;
    if (event.missing != duetos::core::kCapNone)
    {
        ++g_deny_count;
        // Push into the denial ring so `caplog` from the shell can
        // see what just happened even if klog is filtered to WARN
        // or the operator missed the burst. The ring is bounded so
        // a deny storm doesn't unbounded-grow.
        RingPushDenial(event);
    }

    if constexpr (duetos::core::kCapAuditMode == CapAuditMode::Off)
    {
        return;
    }

    if (ShouldEmit())
    {
        EmitLine(event);
    }
}

u64 CapAuditCallCount()
{
    return g_call_count;
}

u64 CapAuditDenyCount()
{
    return g_deny_count;
}

void CapAuditResetCounters()
{
    g_call_count = 0;
    g_deny_count = 0;
    g_sample_cursor = 0;
    g_force_next_sample = false;
}

void CapAuditForceNextSample()
{
    g_force_next_sample = true;
}

void CapAuditSuppressJournal(bool suppress)
{
    g_suppress_journal = suppress;
}

duetos::core::CapAuditMode CapAuditGetMode()
{
    return g_mode;
}

bool CapAuditSetMode(duetos::core::CapAuditMode mode)
{
    using duetos::core::CapAuditMode;
    // An Off-at-compile-time build cannot honor a runtime flip — the
    // EmitLine path was eliminated. Tell the caller so the shell can
    // print a meaningful diagnostic instead of silently failing.
    if constexpr (duetos::core::kCapAuditMode == CapAuditMode::Off)
    {
        return false;
    }
    g_mode = mode;
    // Reset the sample cursor so the next stride starts fresh.
    // Otherwise a flip from Full → Sample would carry an arbitrary
    // cursor value and the first sample emit could happen at any
    // call within the stride.
    g_sample_cursor = 0;
    g_force_next_sample = false;
    return true;
}

duetos::core::CapAuditMode CapAuditCompileTimeMode()
{
    return duetos::core::kCapAuditMode;
}

void CapAuditSelfTest()
{
    arch::SerialWrite("[cap-audit] self-test: counters + sample path.\n");

    CapAuditResetCounters();

    const CapAuditEvent allow_event{/*syscall_number*/ 1, /*proc_id*/ 100, /*required_mask*/ 0,
                                    /*missing*/ duetos::core::kCapNone};
    const CapAuditEvent deny_event{/*syscall_number*/ 2, /*proc_id*/ 100, /*required_mask*/ 0xFFu,
                                   /*missing*/ duetos::core::kCapFsWrite};

    CapAuditTrace(allow_event);
    if (CapAuditCallCount() != 1 || CapAuditDenyCount() != 0)
    {
        core::Panic("cap-audit", "self-test: allow event did not increment call counter");
    }

    CapAuditTrace(deny_event);
    if (CapAuditCallCount() != 2 || CapAuditDenyCount() != 1)
    {
        core::Panic("cap-audit", "self-test: deny event did not increment deny counter");
    }

    // Force-sample path — every mode honors it, even Off (the
    // call still increments counters; emission is what gets
    // suppressed). For Sample mode specifically, the next call
    // emits a line even mid-stride.
    CapAuditForceNextSample();
    CapAuditTrace(allow_event);
    if (CapAuditCallCount() != 3)
    {
        core::Panic("cap-audit", "self-test: forced-sample did not increment call counter");
    }

    arch::SerialWrite("[cap-audit] self-test: OK.\n");
    CapAuditResetCounters();
}

u64 CapAuditCopyRecentDenials(CapAuditDenialRecord* out, u64 out_cap)
{
    if (out == nullptr || out_cap == 0)
        return 0;
    const u64 live = (g_deny_seq < kDenyRingCap) ? g_deny_seq : kDenyRingCap;
    const u64 n = (live < out_cap) ? live : out_cap;
    // Walk newest-first: index N-1 is the last written. We rebuild
    // the index for each step rather than chase a cursor because
    // the ring is small and the read is rare (operator-driven).
    for (u64 i = 0; i < n; ++i)
    {
        const u64 from_end = i + 1; // 1 = newest
        const u64 abs_seq = g_deny_seq - from_end;
        out[i] = g_deny_ring[abs_seq % kDenyRingCap];
    }
    return n;
}

u64 CapAuditDenialDropCount()
{
    return g_deny_dropped;
}

} // namespace duetos::security
