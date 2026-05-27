#include "cpu/cpuhp.h"

#include "acpi/acpi.h"
#include "arch/x86_64/serial.h"
#include "log/klog.h"
#include "sync/spinlock.h"
#include "util/string.h"

namespace duetos::cpu
{

namespace
{

// Per-state registration. One entry per sparse slot — most slots
// stay empty (callbacks == nullptr) which is normal: every state in
// the enum is a "potential" registration point, not a mandatory one.
struct StateEntry
{
    const char* name;       // short stable label; nullptr = unregistered
    CpuhpStartupFn startup; // may be nullptr (state is a "marker only")
    CpuhpTeardownFn teardown;
};

constinit StateEntry g_states[kMaxCpuhpStates] = {};

// Current state per CPU. Updated by CpuhpBringUp / CpuhpTakeDown /
// CpuhpMarkOnline under g_state_lock; readable lock-free for
// diagnostics (a stale read just looks one tick old, which is fine
// for a dump path).
constinit CpuhpState g_cpu_states[acpi::kMaxCpus] = {};

// Single coarse lock protecting g_states[] registrations and
// g_cpu_states[] transitions. The transition path is rare (boot +
// future hot-plug), so the spinlock's cost is negligible against
// the cost of getting per-CPU bring-up wrong.
constinit ::duetos::sync::SpinLock g_state_lock{};

// Diagnostic counters. Bumped under the lock at the appropriate
// transition site so a cross-CPU sum is unnecessary.
constinit u32 g_cpus_online = 0;
constinit u32 g_bringup_failures_total = 0;
constinit u32 g_takedown_failures_total = 0;
constinit u32 g_rollbacks_total = 0;

// Set during the self-test path's expected rollback case so the
// WARN logger demotes to a DEBUG-level line (the self-test exercises
// the failure leg by design; flooding the boot log with a WARN
// every boot would defeat the log-level system). Out-of-test
// rollbacks remain at WARN — which is where an operator triages
// them.
constinit bool g_selftest_silence_warn = false;

bool ValidState(CpuhpState s)
{
    return static_cast<u32>(s) < kMaxCpuhpStates;
}

bool ValidCpu(u32 cpu_id)
{
    return cpu_id < acpi::kMaxCpus;
}

// Walk forward from `from` (exclusive) to `to` (inclusive), invoking
// every registered startup. Returns Err of the failing state (and
// leaves the per-CPU state slot at the highest state successfully
// entered) on failure. Caller holds g_state_lock on entry; we drop
// it across the callback and re-take it for the state update so a
// callback that itself wants the lock (e.g. by calling
// CpuhpStateRead) doesn't self-deadlock.
::duetos::core::Result<void> WalkForward(u32 cpu_id, u32 from, u32 to, ::duetos::sync::IrqFlags& flags)
{
    for (u32 s = from + 1; s <= to; ++s)
    {
        const StateEntry entry = g_states[s];
        // Mark the state as entered BEFORE running the callback. The
        // rollback walker uses the per-CPU state as the high-water
        // mark, so a callback that fails partway through must still
        // be considered "entered" for the purpose of unwinding what
        // it managed to set up. Symmetric to Linux's cpuhp_state.
        g_cpu_states[cpu_id] = static_cast<CpuhpState>(s);

        if (entry.startup == nullptr)
        {
            continue;
        }

        // Drop the lock around the callback. Callbacks may issue
        // syscalls, take other kernel locks, or even read back the
        // current state — none of which is safe under our own lock.
        ::duetos::sync::SpinLockRelease(g_state_lock, flags);
        ::duetos::core::Result<void> r = entry.startup(cpu_id);
        flags = ::duetos::sync::SpinLockAcquire(g_state_lock);

        if (!r.has_value())
        {
            return ::duetos::core::Err{r.error(), r.location()};
        }

        KLOG_DEBUG_V("cpuhp", "startup OK state", static_cast<u64>(s));
    }
    return {};
}

// Walk backward from `from` (inclusive) to `to` (exclusive), invoking
// every registered teardown. Caller holds g_state_lock on entry.
// Returns Err if any teardown returns Err — but continues walking
// (a half-failed teardown is logged and the chain proceeds, mirroring
// Linux's "best-effort unwind" policy).
::duetos::core::Result<void> WalkBackward(u32 cpu_id, u32 from, u32 to, ::duetos::sync::IrqFlags& flags)
{
    bool any_failed = false;
    ::duetos::core::ErrorCode first_err = ::duetos::core::ErrorCode::Ok;
    for (u32 s = from; s > to; --s)
    {
        const StateEntry entry = g_states[s];
        if (entry.teardown != nullptr)
        {
            ::duetos::sync::SpinLockRelease(g_state_lock, flags);
            ::duetos::core::Result<void> r = entry.teardown(cpu_id);
            flags = ::duetos::sync::SpinLockAcquire(g_state_lock);

            if (!r.has_value())
            {
                if (!any_failed)
                {
                    first_err = r.error();
                }
                any_failed = true;
                ++g_takedown_failures_total;
                KLOG_WARN_V("cpuhp", "teardown failed at state", static_cast<u64>(s));
            }
            else
            {
                KLOG_DEBUG_V("cpuhp", "teardown OK state", static_cast<u64>(s));
            }
        }
        // Drop the state to the predecessor regardless: even a
        // half-failed teardown shouldn't leave a stale "still
        // entered" mark — the state IS leaving, just imperfectly.
        g_cpu_states[cpu_id] = static_cast<CpuhpState>(s - 1);
    }
    if (any_failed)
    {
        return ::duetos::core::Err{first_err};
    }
    return {};
}

// Render a CpuhpState as a hex value into a buffer, used by the
// dumper. Returns the number of bytes written.
u32 HexU32(u32 v, char* out)
{
    static const char hex[] = "0123456789abcdef";
    out[0] = '0';
    out[1] = 'x';
    u32 n = 2;
    bool started = false;
    for (i32 nibble = 7; nibble >= 0; --nibble)
    {
        const u32 d = (v >> (nibble * 4)) & 0xFu;
        if (d != 0 || started || nibble == 0)
        {
            out[n++] = hex[d];
            started = true;
        }
    }
    return n;
}

} // namespace

const char* CpuhpStateName(CpuhpState state)
{
    switch (state)
    {
    case CpuhpState::Offline:
        return "Offline";
    case CpuhpState::PrepareAllocStorage:
        return "PrepareAllocStorage";
    case CpuhpState::PrepareTopology:
        return "PrepareTopology";
    case CpuhpState::PrepareIpiMailbox:
        return "PrepareIpiMailbox";
    case CpuhpState::StartingTrampoline:
        return "StartingTrampoline";
    case CpuhpState::StartingGdt:
        return "StartingGdt";
    case CpuhpState::StartingGsBase:
        return "StartingGsBase";
    case CpuhpState::StartingIdt:
        return "StartingIdt";
    case CpuhpState::StartingCr4:
        return "StartingCr4";
    case CpuhpState::StartingSyscallMsrs:
        return "StartingSyscallMsrs";
    case CpuhpState::StartingLapic:
        return "StartingLapic";
    case CpuhpState::StartingTopology:
        return "StartingTopology";
    case CpuhpState::StartingScheduler:
        return "StartingScheduler";
    case CpuhpState::OnlineSched:
        return "OnlineSched";
    case CpuhpState::OnlineIpiCall:
        return "OnlineIpiCall";
    case CpuhpState::OnlineSoftLockup:
        return "OnlineSoftLockup";
    case CpuhpState::OnlineHeartbeat:
        return "OnlineHeartbeat";
    case CpuhpState::Online:
        return "Online";
    }
    return "?";
}

bool CpuhpInstall(CpuhpState state, const char* name, CpuhpStartupFn startup, CpuhpTeardownFn teardown)
{
    if (!ValidState(state) || name == nullptr)
    {
        return false;
    }
    const u32 idx = static_cast<u32>(state);

    ::duetos::sync::SpinLockGuard guard(g_state_lock);

    // Idempotent re-registration: same name + same slot, just refresh
    // the function pointers. The caller may legitimately re-register
    // (driver-domain restart, future hot-plug churn) — silently
    // double-installing would leak old callbacks; refusing would
    // panic on the rerun. Refresh is the right shape.
    if (g_states[idx].name != nullptr)
    {
        // Compare by pointer first (literals share .rodata), strcmp
        // as a fallback. If the name differs, refuse — two distinct
        // subsystems claiming the same numeric state is a bug worth
        // surfacing.
        if (g_states[idx].name != name)
        {
            const char* a = g_states[idx].name;
            const char* b = name;
            while (*a != '\0' && *a == *b)
            {
                ++a;
                ++b;
            }
            if (*a != *b)
            {
                KLOG_WARN_V("cpuhp", "state slot already claimed by another name", static_cast<u64>(idx));
                return false;
            }
        }
    }
    g_states[idx] = StateEntry{name, startup, teardown};
    return true;
}

::duetos::core::Result<void> CpuhpBringUp(u32 cpu_id)
{
    if (!ValidCpu(cpu_id))
    {
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    }

    ::duetos::sync::IrqFlags flags = ::duetos::sync::SpinLockAcquire(g_state_lock);

    const u32 from = static_cast<u32>(g_cpu_states[cpu_id]);
    const u32 to = static_cast<u32>(CpuhpState::Online);

    // Already at or past target — nothing to do (idempotent).
    if (from >= to)
    {
        ::duetos::sync::SpinLockRelease(g_state_lock, flags);
        return {};
    }

    ::duetos::core::Result<void> r = WalkForward(cpu_id, from, to, flags);
    if (!r.has_value())
    {
        // Roll back through everything we successfully entered. The
        // per-CPU state is at the high-water mark; unwind to `from`
        // (the original starting point).
        ++g_bringup_failures_total;
        ++g_rollbacks_total;
        const u32 high_water = static_cast<u32>(g_cpu_states[cpu_id]);
        if (g_selftest_silence_warn)
        {
            KLOG_DEBUG_V("cpuhp", "bring-up failed; rolling back at state (self-test)", static_cast<u64>(high_water));
        }
        else
        {
            KLOG_WARN_V("cpuhp", "bring-up failed; rolling back at state", static_cast<u64>(high_water));
        }
        (void)WalkBackward(cpu_id, high_water, from, flags);
        ::duetos::sync::SpinLockRelease(g_state_lock, flags);
        return r;
    }

    ++g_cpus_online;
    ::duetos::sync::SpinLockRelease(g_state_lock, flags);
    return {};
}

::duetos::core::Result<void> CpuhpTakeDown(u32 cpu_id)
{
    if (!ValidCpu(cpu_id))
    {
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    }

    ::duetos::sync::IrqFlags flags = ::duetos::sync::SpinLockAcquire(g_state_lock);
    const u32 from = static_cast<u32>(g_cpu_states[cpu_id]);
    const u32 to = static_cast<u32>(CpuhpState::Offline);
    if (from <= to)
    {
        ::duetos::sync::SpinLockRelease(g_state_lock, flags);
        return {};
    }

    ::duetos::core::Result<void> r = WalkBackward(cpu_id, from, to, flags);
    if (r.has_value() && g_cpus_online > 0)
    {
        --g_cpus_online;
    }
    ::duetos::sync::SpinLockRelease(g_state_lock, flags);
    return r;
}

CpuhpState CpuhpStateRead(u32 cpu_id)
{
    if (!ValidCpu(cpu_id))
    {
        return CpuhpState::Offline;
    }
    // Lock-free read — see comment on g_cpu_states declaration.
    return g_cpu_states[cpu_id];
}

void CpuhpMarkOnline(u32 cpu_id)
{
    if (!ValidCpu(cpu_id))
    {
        return;
    }
    ::duetos::sync::SpinLockGuard guard(g_state_lock);
    // Only bump cpus_online if this is a fresh transition.
    if (g_cpu_states[cpu_id] != CpuhpState::Online)
    {
        ++g_cpus_online;
    }
    g_cpu_states[cpu_id] = CpuhpState::Online;
}

CpuhpStats CpuhpStatsRead()
{
    ::duetos::sync::SpinLockGuard guard(g_state_lock);
    return CpuhpStats{g_cpus_online, g_bringup_failures_total, g_takedown_failures_total, g_rollbacks_total};
}

void CpuhpDumpStates()
{
    // Panic-safe: raw SerialWrite only (no klog, no spinlock — the
    // dumper runs from the panic path where klog re-entrancy and
    // lock contention are both fatal). Snapshot the per-CPU state
    // slot without taking g_state_lock — a torn read in a panic
    // dump is acceptable; deadlocking inside panic is not.
    ::duetos::arch::SerialWrite("[cpuhp] --- per-CPU states ---\n");
    for (u32 id = 0; id < acpi::kMaxCpus; ++id)
    {
        const CpuhpState s = g_cpu_states[id];
        if (id != 0 && s == CpuhpState::Offline)
        {
            // Skip empty slots beyond BSP — keeps the dump short on
            // SMP=1 / typical 4-8 CPU configurations.
            continue;
        }
        ::duetos::arch::SerialWrite("  [cpuhp] cpu=");
        char buf[16];
        const u32 n = HexU32(id, buf);
        ::duetos::arch::SerialWriteN(buf, n);
        ::duetos::arch::SerialWrite(" state=");
        ::duetos::arch::SerialWrite(CpuhpStateName(s));
        ::duetos::arch::SerialWrite("\n");
    }
}

namespace
{

// Self-test scratch state. Used by the toy callbacks to verify
// rollback order. The slot indices below are far above any real
// registration band so they can never collide.
constinit u32 g_selftest_seq[16] = {};
constinit u32 g_selftest_seq_len = 0;
constinit bool g_selftest_armed_failure = false;
constinit u32 g_selftest_cpu = 0xFFFFFFFFu;

// Use a band well past Online (which is 999) so the chain ordering
// doesn't disturb real bring-up. The framework permits any value
// strictly below kMaxCpuhpStates; the self-test borrows the upper
// quarter.
constexpr u32 kSelftestA = 700;
constexpr u32 kSelftestB = 710;
constexpr u32 kSelftestC = 720;

::duetos::core::Result<void> SelftestStartA(u32 cpu)
{
    if (cpu != g_selftest_cpu)
    {
        return {};
    }
    g_selftest_seq[g_selftest_seq_len++] = 1; // startup A
    return {};
}
::duetos::core::Result<void> SelftestTeardownA(u32 cpu)
{
    if (cpu != g_selftest_cpu)
    {
        return {};
    }
    g_selftest_seq[g_selftest_seq_len++] = 11; // teardown A
    return {};
}
::duetos::core::Result<void> SelftestStartB(u32 cpu)
{
    if (cpu != g_selftest_cpu)
    {
        return {};
    }
    g_selftest_seq[g_selftest_seq_len++] = 2; // startup B
    if (g_selftest_armed_failure)
    {
        return ::duetos::core::Err{::duetos::core::ErrorCode::Unsupported};
    }
    return {};
}
::duetos::core::Result<void> SelftestTeardownB(u32 cpu)
{
    if (cpu != g_selftest_cpu)
    {
        return {};
    }
    g_selftest_seq[g_selftest_seq_len++] = 12; // teardown B
    return {};
}
::duetos::core::Result<void> SelftestStartC(u32 cpu)
{
    if (cpu != g_selftest_cpu)
    {
        return {};
    }
    g_selftest_seq[g_selftest_seq_len++] = 3; // startup C
    return {};
}
::duetos::core::Result<void> SelftestTeardownC(u32 cpu)
{
    if (cpu != g_selftest_cpu)
    {
        return {};
    }
    g_selftest_seq[g_selftest_seq_len++] = 13; // teardown C
    return {};
}

} // namespace

void CpuhpSelfTest()
{
    // Pick a fresh "fake CPU" slot in the upper part of the kMaxCpus
    // range that no real bring-up will touch. acpi::kMaxCpus is 32;
    // use slot 31 (last) so even a fully-populated 32-CPU system
    // doesn't collide — but note that a real CPU 31 if present would
    // be in Offline at boot anyway, and we restore the slot below.
    constexpr u32 kFakeCpu = acpi::kMaxCpus - 1;

    // Register toy states.
    CpuhpInstall(static_cast<CpuhpState>(kSelftestA), "selftest-a", &SelftestStartA, &SelftestTeardownA);
    CpuhpInstall(static_cast<CpuhpState>(kSelftestB), "selftest-b", &SelftestStartB, &SelftestTeardownB);
    CpuhpInstall(static_cast<CpuhpState>(kSelftestC), "selftest-c", &SelftestStartC, &SelftestTeardownC);

    // Save and override the fake-cpu slot. Position it RIGHT BELOW
    // selftest-A so the forward walk only visits A, B, C (plus any
    // unregistered slots in 700-998, which are no-ops). The other
    // real registrations all live below 700 — Online itself is 999.
    const CpuhpState saved = g_cpu_states[kFakeCpu];
    g_cpu_states[kFakeCpu] = static_cast<CpuhpState>(kSelftestA - 1);
    g_selftest_cpu = kFakeCpu;

    // --- Test 1: clean bring-up walks A, B, C in order ---
    g_selftest_seq_len = 0;
    g_selftest_armed_failure = false;
    ::duetos::core::Result<void> r1 = CpuhpBringUp(kFakeCpu);
    // First three entries should be 1, 2, 3 in order.
    const bool clean_ok = (r1.has_value() && g_selftest_seq_len == 3 && g_selftest_seq[0] == 1 &&
                           g_selftest_seq[1] == 2 && g_selftest_seq[2] == 3);

    // Reset slot for the rollback test by directly mutating the slot
    // (the framework's CpuhpTakeDown would walk all teardowns above
    // it as well).
    {
        ::duetos::sync::SpinLockGuard guard(g_state_lock);
        g_cpu_states[kFakeCpu] = static_cast<CpuhpState>(kSelftestA - 1);
        if (g_cpus_online > 0)
        {
            --g_cpus_online; // undo the bump from the clean-test path
        }
    }

    // --- Test 2: failing B triggers rollback through A only ---
    g_selftest_seq_len = 0;
    g_selftest_armed_failure = true;
    g_selftest_silence_warn = true; // demote the expected WARN
    ::duetos::core::Result<void> r2 = CpuhpBringUp(kFakeCpu);
    g_selftest_silence_warn = false;
    g_selftest_armed_failure = false;

    // Expected sequence on failure:
    //   1 (startup A), 2 (startup B fails), 12 (teardown B), 11 (teardown A)
    // C should NEVER run; teardown B runs because B was MARKED entered
    // before its callback failed (high-water-mark contract).
    const bool rollback_ok = (!r2.has_value() && g_selftest_seq_len == 4 && g_selftest_seq[0] == 1 &&
                              g_selftest_seq[1] == 2 && g_selftest_seq[2] == 12 && g_selftest_seq[3] == 11);

    // Restore. Force the saved state back without walking — these
    // are framework-internal mutations.
    g_cpu_states[kFakeCpu] = saved;
    // Unregister the toy states so they don't litter the real
    // bring-up. Setting name=nullptr leaves the slot empty for
    // future registrations.
    {
        ::duetos::sync::SpinLockGuard guard(g_state_lock);
        g_states[kSelftestA] = StateEntry{};
        g_states[kSelftestB] = StateEntry{};
        g_states[kSelftestC] = StateEntry{};
    }
    g_selftest_cpu = 0xFFFFFFFFu;

    if (clean_ok && rollback_ok)
    {
        ::duetos::arch::SerialWrite("[cpuhp] self-test OK (clean bring-up + rollback)\n");
    }
    else
    {
        ::duetos::arch::SerialWrite("[cpuhp] self-test FAIL clean=");
        ::duetos::arch::SerialWriteHex(static_cast<u64>(clean_ok ? 1 : 0));
        ::duetos::arch::SerialWrite(" rollback=");
        ::duetos::arch::SerialWriteHex(static_cast<u64>(rollback_ok ? 1 : 0));
        ::duetos::arch::SerialWrite("\n");
    }
}

} // namespace duetos::cpu
