#pragma once

#include "util/types.h"

/*
 * DuetOS — Fault-recoverable wrmsr / rdmsr.
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

/*
 * `ReadMsrSafe(msr, out)` reads MSR `msr` into `*out` and returns
 * true on success, false if the `rdmsr` faulted (#GP — the part
 * does not implement that MSR, or a hypervisor declines to expose
 * it). `*out` is untouched on failure, so a caller that ignores
 * the bool reads its own initialiser rather than garbage.
 *
 * This is the PROBE primitive. Before it existed, every MSR
 * consumer in the tree (thermal.cpp, rapl.cpp, cpufreq.cpp) had to
 * PREDICT whether an MSR was present from the CPUID vendor string
 * plus an "are we under a hypervisor" heuristic, and bail
 * pessimistically whenever the prediction was uncertain — which is
 * why an AMD dev box reported no CPU temperature at all and why
 * every hypervisor reported no CPU frequency. With this, a caller
 * asks the hardware and believes the answer.
 *
 * Honesty contract: a false return means "unsupported", which is a
 * DIFFERENT fact from a successful read of 0. Callers must
 * propagate that distinction to their own callers rather than
 * collapsing both into a zeroed field — a UI showing "0 C" looks
 * broken, "unsupported on this CPU" is the truth.
 *
 * `out` must be non-null. The store into `*out` is deliberately
 * outside the extable-protected range, so a null/bad pointer
 * faults loudly instead of being silently swallowed as an
 * "unsupported MSR".
 *
 * Cost note: a faulting probe takes the whole trap path and the
 * trap dispatcher logs one `[extable] recovered kernel trap` line.
 * Probe once and cache the answer; do not call this in a loop
 * against an MSR you already know is absent.
 */
extern "C" bool ReadMsrSafe(u32 msr, u64* out);

/// Register the kernel-extable rows that cover the `wrmsr` inside
/// `WriteMsrSafe` and the `rdmsr` inside `ReadMsrSafe`. Must be
/// called once, after `KernelExtableRegister` is alive (post-paging,
/// post-IDT). Safe to call before LAPIC init; the table just records
/// the rows.
void RegisterMsrSafeExtable();

/// Boot self-test. Asserts both extable rows are registered and
/// resolve to their fixups, then exercises `ReadMsrSafe` against an
/// architectural MSR (must succeed) and an MSR no CPU implements
/// (must return without taking the kernel down). Panics on
/// mismatch; emits one "[msr-safe-selftest] PASS" line.
void MsrSafeSelfTest();

} // namespace duetos::arch
