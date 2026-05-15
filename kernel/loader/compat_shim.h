#pragma once

#include "util/types.h"

/*
 * DuetOS — Per-PE app-compat shim layer.
 *
 * Sidecar policy file (`<exe-basename>.duetcompat`) lets us
 * paper over the long tail of Win32 calls that aren't
 * fundamentally needed but that real PEs make: ETW telemetry,
 * SetThreadStackGuarantee, IsDebuggerPresent against a
 * production-build expectation, etc. The kernel parses the
 * sidecar at load time and stores the result on the owning
 * Process; subsystem code reads it through the accessors below
 * before deciding whether to STUB-fail a call or quietly
 * succeed.
 *
 * File format (UTF-8, LF line endings):
 *   - One key=value per line.
 *   - Lines starting with '#' are comments.
 *   - Blank lines are skipped.
 *   - Keys are case-insensitive, ASCII.
 *   - Values: `1` / `true` / `yes` = on; `0` / `false` / `no` = off.
 *
 * Recognised keys (extend as the catalogue grows — every key
 * added here should pair with the call-site that consults it,
 * so the contract is visible to a future maintainer):
 *
 *   ignore_debugger_present   IsDebuggerPresent → 0
 *   ignore_etw                EventWrite* / EventRegister* → ERROR_SUCCESS no-op
 *   fake_ok_stack_guarantee   SetThreadStackGuarantee → TRUE without
 *                             touching the stack
 *
 * Anything unrecognised is logged (KLOG_INFO) and ignored — we
 * don't reject a sidecar just because a future key isn't known
 * yet. Anything malformed (no `=`, unparseable value) is logged
 * at WARN and skipped.
 *
 * Context: kernel; called from the PE-spawn path. Allocation-
 * free. Per-process storage lives inside `Process::compat_policy`
 * so it shares the process lifecycle.
 */

namespace duetos::fs
{
struct RamfsNode;
}
namespace duetos::core
{
struct Process;
}

namespace duetos::core::compat
{

struct CompatPolicy
{
    // Each flag defaults to `false` — i.e. the kernel behaves as
    // it did before app-compat shims existed unless a sidecar
    // explicitly opts in. The zero-initialised default applies on
    // ProcessReset.
    bool ignore_debugger_present;
    bool ignore_etw;
    bool fake_ok_stack_guarantee;

    // True once `Apply` has run for this process — distinguishes
    // "no sidecar, defaults" from "sidecar parsed, no overrides
    // taken" for the operator who runs `pe-triage`.
    bool applied;

    // Count of recognised keys observed during parse + count
    // of unrecognised keys (logged). Cheap diagnostic surface
    // for the wiki / shell.
    u16 keys_applied;
    u16 keys_unknown;

    u8 _pad[2];
};

/// Reset to default state. Idempotent. Called by ProcessReset.
void Reset(CompatPolicy* policy);

/// Apply a sidecar policy file to `proc`. Looks for a Ramfs
/// child of `root` whose name matches `<program_name>.duetcompat`
/// (case-insensitive). Parses every recognised key into
/// `proc->compat_policy` and emits a KLOG_INFO line summarising
/// what was applied. Returns true iff a sidecar was found and
/// parsed (independent of whether any key actually flipped).
///
/// Safe to call before ring-3 entry; runs in kernel context.
bool ApplySidecar(Process* proc, const fs::RamfsNode* root, const char* program_name);

/// Apply an in-memory sidecar buffer directly. Useful for tests
/// + for future call sites that derive the bytes from a real
/// filesystem (FAT32 / NTFS) instead of ramfs. `buf` must be
/// NUL-terminated or `buf_len` must be the exact byte count;
/// either is fine. Returns true on parse success.
bool ApplyBuffer(Process* proc, const u8* buf, u64 buf_len);

/// Accessors. Read from `Process::compat_policy`. Safe to call
/// from any kernel context — fields are plain primitives and
/// never mutated after `ApplySidecar`. nullptr-process safe:
/// returns false (= no override active).
bool ShouldIgnoreDebugger(const Process* proc);
bool ShouldIgnoreEtw(const Process* proc);
bool ShouldFakeOkStackGuarantee(const Process* proc);

/// Pack the policy flags into the bit layout SYS_COMPAT_QUERY
/// returns to userland (`enum CompatPolicyBits` in
/// `kernel/syscall/syscall.h`). nullptr-process safe: returns 0.
u64 QueryPolicyBits(const Process* proc);

/// Boot-time check: builds a tiny in-memory sidecar through
/// `ApplyBuffer`, validates every recognised key flipped its
/// flag, then resets the policy. Panics on any mismatch.
/// Called from kernel_main alongside other diag self-tests.
void SelfTest();

} // namespace duetos::core::compat
