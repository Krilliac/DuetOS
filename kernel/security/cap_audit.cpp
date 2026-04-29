/*
 * DuetOS — capability-gate audit hook implementation.
 *
 * See cap_audit.h for the public contract. The trace function is
 * the only caller that actually pays attention to `kCapAuditMode`;
 * the counter helpers stay live regardless so a future runtime
 * `mode = Sample` flip can rely on the counter being current.
 */

#include "security/cap_audit.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "log/klog.h"
#include "proc/process.h"
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

// Decide whether THIS call should emit a klog line. Folds to a
// constant in non-Sample modes.
bool ShouldEmit()
{
    using duetos::core::CapAuditMode;
    if constexpr (duetos::core::kCapAuditMode == CapAuditMode::Off)
    {
        return false;
    }
    else if constexpr (duetos::core::kCapAuditMode == CapAuditMode::Full)
    {
        return true;
    }
    else
    {
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

} // namespace duetos::security
