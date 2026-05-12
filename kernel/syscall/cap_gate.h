#pragma once

#include "proc/process.h"
#include "syscall/syscall.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — centralised syscall capability gate (plan A4).
 *
 * WHAT
 *   `SyscallGate(num, proc)` consults `kSyscallCapTable` and
 *   returns Ok if the process holds every cap the table requires
 *   for `num`, or `Err{ErrorCode::PermissionDenied}` otherwise.
 *   Records a sandbox denial against the first missing cap on
 *   error (so `Process::sandbox_denials` and the diagnostic counter
 *   stay accurate without each handler having to call
 *   `RecordSandboxDenial` itself).
 *
 *   Syscalls whose authorisation depends on runtime context
 *   (foreign-PID vs self in SYS_PROCESS_OPEN, fd=1 vs fd=2 in
 *   SYS_WRITE) are NOT in the table; the gate returns Ok for them
 *   and the handler does the conditional check. The table only
 *   covers the cases where the cap is unconditionally required.
 *
 * WHERE
 *   `SyscallDispatch` (kernel/syscall/syscall.cpp) calls this once,
 *   immediately after computing `num` and `proc`, before the
 *   per-syscall switch. On Err it sets `frame->rax = -1` and
 *   returns; on Ok dispatch falls through to the handler.
 *
 *   No userland include path: this is a kernel-internal gate. The
 *   `kSyscallCapTable` constant is also exposed for diagnostics
 *   (`inspect syscalls` could one day print "cap-required: kCapX"
 *   per row; out of scope here).
 *
 * SCOPE
 *   v0 lists ~13 syscalls in `cap_table.def`. Existing in-handler
 *   `CapSetHas` checks remain, redundantly belt-and-braces, until a
 *   follow-up cleanup removes them. The gate is the new audit
 *   surface; the handler checks are the legacy backstop. They MUST
 *   agree — a follow-up self-test asserts this in scenarios where
 *   both paths are exercisable.
 */

namespace duetos::core
{

struct SyscallCapEntry
{
    u64 nr;
    u64 required_mask;
};

inline constexpr SyscallCapEntry kSyscallCapTable[] = {
#define X(name, mask) {static_cast<u64>(name), (mask)},
#include "syscall/cap_table.def"
#undef X
};

inline constexpr u32 kSyscallCapTableCount = sizeof(kSyscallCapTable) / sizeof(kSyscallCapTable[0]);

// Compile-time min/max syscall numbers in the cap table. RequiredCapMask
// uses these for a range-bail before the linear scan: most syscall
// numbers are NOT in this table (handlers handle their own auth), so a
// single compare lets us return 0 without walking 24 rows. Computed via
// constexpr fold over the table so adding rows updates them automatically.
inline constexpr u64 SyscallCapTableMin()
{
    u64 m = kSyscallCapTable[0].nr;
    for (u32 i = 1; i < kSyscallCapTableCount; ++i)
        if (kSyscallCapTable[i].nr < m)
            m = kSyscallCapTable[i].nr;
    return m;
}
inline constexpr u64 SyscallCapTableMax()
{
    u64 m = kSyscallCapTable[0].nr;
    for (u32 i = 1; i < kSyscallCapTableCount; ++i)
        if (kSyscallCapTable[i].nr > m)
            m = kSyscallCapTable[i].nr;
    return m;
}
inline constexpr u64 kSyscallCapTableMin = SyscallCapTableMin();
inline constexpr u64 kSyscallCapTableMax = SyscallCapTableMax();

/// Look up the static cap mask for a syscall number. Returns 0 for
/// any number not present in the table — that's the "handler
/// enforces" signal, not an error. Linear scan; the table has
/// O(15) rows.
u64 RequiredCapMask(u64 syscall_number);

/// The gate. Called by `SyscallDispatch` before any handler.
/// Returns:
///   Ok                                    - proc holds every required cap (or none required).
///   Err{ErrorCode::PermissionDenied}      - one or more required caps missing; first missing cap recorded.
/// `proc` may be nullptr (kernel-thread origin); a nullptr process
/// only passes if `required_mask == 0`. A non-nullptr process with
/// an empty cap set fails any non-zero mask.
Result<void> SyscallGate(u64 syscall_number, const Process* proc);

/// Boot-time self-test. Builds two synthetic processes (empty caps
/// and trusted caps) and runs every row in `kSyscallCapTable`
/// against both, asserting empty-caps fails and trusted-caps
/// succeeds. Also confirms the "no row" path returns Ok regardless
/// of caps. Panics on mismatch — the gate is load-bearing for
/// every cap-gated syscall and a regression here is a hard stop.
void SyscallGateSelfTest();

} // namespace duetos::core
