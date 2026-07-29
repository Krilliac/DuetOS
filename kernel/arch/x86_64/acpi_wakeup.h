#pragma once

#include "util/types.h"

/*
 * DuetOS — ACPI S3 wake trampoline + CPU context save/restore.
 *
 * S3 (suspend-to-RAM) powers the CPU off. Everything architectural —
 * GDTR, IDTR, TR, CR0/CR3/CR4, EFER, the SYSCALL MSRs, FS/GS bases —
 * is lost, and the platform re-enters the OS in 16-bit REAL MODE at
 * the physical address the OS published in the FACS firmware waking
 * vector. This file owns the round trip:
 *
 *   suspend: AcpiWakeArm()      — copy the trampoline blob to low
 *                                 memory, publish the waking vector
 *            AcpiSuspendEnter() — save CPU context, call the sleep
 *                                 writer, and (on wake) return 1
 *   resume:  firmware -> 0x9000 real mode
 *            -> trampoline: real -> protected -> long mode, kernel CR3
 *            -> AcpiWakeResume64: restore raw architectural state
 *            -> returns into AcpiSuspendEnter's caller with 1
 *
 * The trampoline is a byte-for-byte copy of the linked blob into
 * physical 0x9000 (the AP trampoline owns 0x8000; the frame allocator
 * keeps the whole low 1 MiB reserved, so neither page is allocatable).
 *
 * Restoration is by SAVED RAW VALUE, not by replaying the boot init
 * functions. Replaying GdtInit/IdtInit/SyscallInit would re-derive
 * state that is *supposed* to be identical but silently is not — TSS
 * RSP0, for instance, is owned by the scheduler and would be zeroed.
 * The one exception is the TSS descriptor's BUSY bit: it survives in
 * the in-memory GDT across S3, and `ltr` on a busy TSS raises #GP, so
 * the resume path clears it before reloading TR.
 *
 * "Cannot suspend" is a first-class answer, never a zero. AcpiWakeArm
 * returns false when there is no FACS, no `\_S3` package, or the
 * waking-vector write did not read back — and the caller must refuse
 * the suspend rather than proceed with an unset vector, which would
 * resume the machine into whatever the previous OS left at that
 * address.
 *
 * Context: kernel, BSP only, interrupts disabled across the whole
 * save/enter/restore window. APs must be parked before entry — see
 * kernel/power/suspend.cpp.
 */

namespace duetos::arch
{

/// Architectural CPU state saved across S3. Layout is shared with
/// acpi_wakeup.S by byte offset; the static_asserts in acpi_wakeup.cpp
/// are the contract. Do not reorder without updating both.
struct [[gnu::packed]] AcpiWakeContext
{
    u64 rsp;            // 0   kernel stack at the save point
    u64 cr0;            // 8
    u64 cr3;            // 16  kernel PML4 physical — also fed to the trampoline
    u64 cr4;            // 24
    u64 efer;           // 32
    u64 star;           // 40  SYSCALL selectors
    u64 lstar;          // 48  SYSCALL entry RIP
    u64 sfmask;         // 56  SYSCALL RFLAGS mask
    u64 fs_base;        // 64
    u64 gs_base;        // 72
    u64 kernel_gs_base; // 80  swapgs shadow
    u64 tss_rsp0;       // 88  scheduler-owned; restored so ring 3 keeps working
    u8 gdtr[10];        // 96  sgdt image (limit + base)
    u8 idtr[10];        // 106 sidt image
    u16 tr;             // 116 task register selector
    u16 cs;             // 118
    u16 ss;             // 120
    u16 ds;             // 122
    u32 resume_count;   // 124 incremented by the resume path — wake proof
};

/// Physical address the trampoline blob is copied to and that the
/// FACS waking vector points at. Below 1 MiB and 16-byte aligned, as
/// firmware builds a real-mode CS:IP from it.
constexpr u64 kAcpiWakePhys = 0x9000;

/// Copy the trampoline to `kAcpiWakePhys`, seed its parameter block
/// (kernel CR3 + the 64-bit resume entry), and publish the address in
/// the FACS firmware waking vector.
///
/// Returns false when the blob does not fit its page, there is no
/// usable FACS, or the waking-vector write did not read back. On
/// false the caller MUST NOT enter S3.
bool AcpiWakeArm();

/// Save architectural CPU state into `ctx`, then call `enter_sleep`
/// (which writes PM1 SLP_TYP/SLP_EN). Returns 0 if `enter_sleep`
/// returned — i.e. the platform declined the transition and we never
/// slept — and 1 when the machine actually suspended and resumed
/// through the trampoline. Distinguishing those two is the whole
/// point: a "0" caller must not report a successful suspend cycle.
///
/// Caller must have interrupts disabled. `ctx` must be the same
/// object AcpiWakeArm was told about (it is the module-global one).
extern "C" u32 AcpiSuspendEnter(AcpiWakeContext* ctx, void (*enter_sleep)());

/// The module-global context. Shared with the resume path, which runs
/// before any C++ argument passing is possible.
AcpiWakeContext& AcpiWakeContextGet();

/// Pure-logic boot self-test of the context layout + the trampoline
/// blob's size/alignment invariants. Panics on mismatch; emits one
/// `[acpi-wake-selftest] PASS` line. Touches no hardware.
void AcpiWakeSelfTest();

} // namespace duetos::arch
