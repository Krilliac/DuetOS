/*
 * DuetOS — central syscall capability gate, v0 (plan A4).
 *
 * See `cap_gate.h` for the public contract. This TU owns the
 * lookup, the gate function, and a self-test that walks every row
 * in `kSyscallCapTable` against synthetic empty / trusted
 * processes.
 */

#include "syscall/cap_gate.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "log/klog.h"
#include "proc/process.h"
#include "security/cap_audit.h"
#include "util/result.h"
#include "util/types.h"

namespace duetos::core
{

u64 RequiredCapMask(u64 syscall_number)
{
    // Most syscalls aren't in the cap table — the handler enforces
    // its own auth (e.g. SYS_PROCESS_OPEN cap-checks foreign PIDs
    // only). Bail without walking the table when the number is
    // outside the known range. Single compare on the common path
    // vs 24-row linear scan.
    if (syscall_number < kSyscallCapTableMin || syscall_number > kSyscallCapTableMax)
    {
        return 0;
    }
    for (u32 i = 0; i < kSyscallCapTableCount; ++i)
    {
        if (kSyscallCapTable[i].nr == syscall_number)
        {
            return kSyscallCapTable[i].required_mask;
        }
    }
    return 0;
}

namespace
{

// First missing-cap bit for diagnostic logging; returns kCapNone
// when every required bit is present.
Cap FirstMissingCap(u64 required_mask, CapSet held)
{
    const u64 missing = required_mask & ~held.bits;
    if (missing == 0)
    {
        return kCapNone;
    }
    for (u32 c = 1; c < static_cast<u32>(kCapCount); ++c)
    {
        if ((missing & (1ULL << c)) != 0)
        {
            return static_cast<Cap>(c);
        }
    }
    return kCapNone;
}

} // namespace

Result<void> SyscallGate(u64 syscall_number, const Process* proc)
{
    const u64 required = RequiredCapMask(syscall_number);
    if (required == 0)
    {
        return {};
    }

    const CapSet held = (proc != nullptr) ? proc->caps : CapSetEmpty();
    const bool allowed = ((held.bits & required) == required);
    const Cap missing = allowed ? kCapNone : FirstMissingCap(required, held);

    // Audit hook — fires on every cap-gated syscall regardless of
    // outcome. Behavior governed by the build-flavor knob
    // `core::kCapAuditMode`; in Off mode the trace is a near-NOP.
    // See kernel/security/cap_audit.{h,cpp}.
    duetos::security::CapAuditEvent event{
        /*syscall_number*/ syscall_number,
        /*proc_id*/ proc != nullptr ? proc->pid : 0,
        /*required_mask*/ required,
        /*missing*/ missing,
    };
    duetos::security::CapAuditTrace(event);

    if (allowed)
    {
        return {};
    }

    RecordSandboxDenial(missing);
    KLOG_WARN_V("syscall-gate", "cap denied", syscall_number);
    return Err{ErrorCode::PermissionDenied};
}

void SyscallGateSelfTest()
{
    arch::SerialWrite("[cap-gate] self-test: walking kSyscallCapTable.\n");

    // The sweep below deliberately denies every non-zero-mask row with
    // empty/nullptr caps. Those denials are EXPECTED — silence the persistent
    // fix-journal mirror for the duration so they don't pollute KERNEL.FIX
    // with "proc 0" cap-denial records the patch generator flags as bugs.
    duetos::security::CapAuditSuppressJournal(true);

    // Static-storage so we don't put a full Process on the boot
    // stack — the struct is ~hundreds of bytes and growing.
    static Process empty{};
    static Process trusted{};
    empty.caps = CapSetEmpty();
    trusted.caps = CapSetTrusted();

    // Every row with a non-zero mask must fail with empty caps and
    // pass with trusted caps. A row with mask == 0 (shouldn't be in
    // the table — see cap_table.def — but defensive) must pass for
    // both.
    for (u32 i = 0; i < kSyscallCapTableCount; ++i)
    {
        const SyscallCapEntry& row = kSyscallCapTable[i];
        const Result<void> r_empty = SyscallGate(row.nr, &empty);
        const Result<void> r_trusted = SyscallGate(row.nr, &trusted);

        if (row.required_mask == 0)
        {
            if (!r_empty.has_value() || !r_trusted.has_value())
            {
                Panic("cap-gate", "zero-mask row rejected a caller");
            }
            continue;
        }

        if (r_empty.has_value())
        {
            Panic("cap-gate", "empty-caps process passed gate for table row");
        }
        if (!r_trusted.has_value())
        {
            Panic("cap-gate", "trusted-caps process rejected by gate for table row");
        }
        if (r_empty.error() != ErrorCode::PermissionDenied)
        {
            Panic("cap-gate", "denial returned wrong error code");
        }
    }

    // Gate must be a no-op for an unknown syscall number. Use a
    // value past the current top of the SyscallNumber enum so we
    // don't accidentally clip a real entry that was added since
    // this test was written.
    const u64 unknown_nr = 0xFFFFFFFFu;
    if (!SyscallGate(unknown_nr, &empty).has_value())
    {
        Panic("cap-gate", "unknown-syscall path rejected by gate");
    }
    if (RequiredCapMask(unknown_nr) != 0)
    {
        Panic("cap-gate", "unknown syscall returned non-zero mask");
    }

    // nullptr-process handling: must pass for zero-mask, fail for
    // any non-zero mask (kernel-thread origin can't satisfy a cap
    // requirement).
    if (!SyscallGate(unknown_nr, nullptr).has_value())
    {
        Panic("cap-gate", "nullptr proc + zero mask rejected");
    }
    bool found_nonzero = false;
    for (u32 i = 0; i < kSyscallCapTableCount; ++i)
    {
        if (kSyscallCapTable[i].required_mask != 0)
        {
            found_nonzero = true;
            if (SyscallGate(kSyscallCapTable[i].nr, nullptr).has_value())
            {
                Panic("cap-gate", "nullptr proc passed non-zero mask");
            }
            break;
        }
    }
    if (!found_nonzero)
    {
        Panic("cap-gate", "kSyscallCapTable has no non-zero rows; nothing tested");
    }

    duetos::security::CapAuditSuppressJournal(false);
    arch::SerialWrite("[cap-gate] self-test: empty fails, trusted passes, nullptr respects mask. OK.\n");
}

} // namespace duetos::core
