#pragma once

#include "util/types.h"

/*
 * DuetOS — Fault-recoverable wrmsr.
 *
 * `WriteMsrSafe(msr, value)` writes `value` to MSR `msr` and
 * returns true on success, false if the wrmsr instruction faulted
 * (#GP — invalid MSR / reserved bits / mode mismatch). The
 * recovery is implemented via the kernel extable; the trap
 * dispatcher steers `frame->rip` to a fixup that sets the return
 * value to 0 and returns. Callers MUST treat the result as
 * authoritative — a false return means the MSR write did not
 * happen, and the wider kernel state needs to handle that.
 *
 * Use this for MSR writes that could fail due to hypervisor /
 * firmware races (the LAPIC IPI path on QEMU/KVM is the
 * load-bearing motivation). Do NOT use it for MSRs where a
 * silent failure would be a security bug (SYSCALL setup, EFER
 * NXE, CET enable) — those should panic on fault so the
 * operator sees the misconfiguration.
 *
 * Context: kernel. Caller may be in any context (IRQ, panic,
 * normal task). The fixup is small and re-entrant.
 */

namespace duetos::arch
{

extern "C" bool WriteMsrSafe(u32 msr, u64 value);

/// Register the kernel-extable row that covers the `wrmsr`
/// instruction inside `WriteMsrSafe`. Must be called once, after
/// `KernelExtableRegister` is alive (post-paging, post-IDT). Safe
/// to call before LAPIC init; the table just records the row.
void RegisterMsrSafeExtable();

} // namespace duetos::arch
