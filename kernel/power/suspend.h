#pragma once

#include "util/types.h"

/*
 * DuetOS — ACPI S3 suspend-to-RAM orchestration.
 *
 * Owns the sequence around the raw power transition that
 * `kernel/arch/x86_64/acpi_wakeup.{S,cpp}` implements:
 *
 *   arm trampoline -> collect device verdicts -> quiesce -> disable
 *   interrupts -> save CPU state + write SLP_TYP  ==  S3  ==
 *   firmware -> trampoline -> restore CPU state -> re-init the
 *   platform (LAPIC / IOAPIC / HPET / tick) -> device resume
 *   callbacks -> return
 *
 * THE REFUSAL CONTRACT
 *
 * S3 powers devices off. QEMU resets every device on wake; real
 * hardware is no kinder. A driver that cannot restore its controller
 * must say so, and the system must then REFUSE to suspend — a machine
 * that comes back with a wedged NVMe queue or a NIC that silently
 * drops frames is strictly worse than one that never slept.
 *
 * So every participating driver registers exactly one of:
 *
 *   PowerSuspendRegister(...) — I can quiesce and restore. `prepare`
 *       is consulted at each attempt (it may still refuse if it has
 *       in-flight state right now); `resume` runs after the CPU is
 *       back and the platform timers are live.
 *
 *   PowerSuspendVeto(name, reason) — I cannot restore my controller
 *       at all. Every attempt refuses and names me.
 *
 * A driver that registers NEITHER is invisible to this path, which is
 * why `PowerSuspendReport` exists: it prints the participant list so
 * an operator (and the boot log) can see who was actually considered.
 *
 * "Cannot suspend" is never encoded as a value. PowerSuspendToRam
 * returns a SuspendOutcome enumerating exactly why, and the caller
 * must not report a cycle unless it sees `Cycled`.
 *
 * Context: kernel, BSP, process context. Must not be called from an
 * interrupt handler — it disables interrupts and blocks for the whole
 * power transition.
 */

namespace duetos::power
{

enum class SuspendVerdict : u8
{
    Ready = 0, // quiesced; safe to power down
    Refuse,    // has state it cannot restore right now
};

/// Result of a suspend attempt. Every non-`Cycled` value is a reason
/// the machine did NOT sleep; none of them is a degraded success.
enum class SuspendOutcome : u8
{
    Cycled = 0,         // suspended and resumed — the only success
    NoAcpiSleepState,   // firmware declares no `\_S3` package
    NoWakingVector,     // no usable FACS / vector write did not stick
    DeviceRefused,      // at least one driver vetoed or was not ready
    MultipleCpusOnline, // no AP park/resume path in v0
    PlatformDeclined,   // SLP_TYP written, execution continued anyway
};

const char* SuspendOutcomeName(SuspendOutcome o);

/// Register a driver that can survive S3. `prepare` may be nullptr
/// (always Ready). `resume` must not be nullptr — a participant with
/// nothing to restore should not be registering. Returns false if the
/// participant table is full, which is a build-time sizing bug.
bool PowerSuspendRegister(const char* name, SuspendVerdict (*prepare)(), void (*resume)());

/// Register a driver that CANNOT survive S3. Every suspend attempt
/// from now on refuses and names `name` / `reason`. Deliberately has
/// no un-register: a driver that gains a restore path should convert
/// to PowerSuspendRegister, not toggle this at runtime.
bool PowerSuspendVeto(const char* name, const char* reason);

/// Whether an S3 attempt could succeed right now, without attempting
/// it. Returns the same outcome PowerSuspendToRam would, except it
/// never returns `Cycled` (it returns `Cycled` to mean "would be
/// allowed to try"). Used by the shell to explain a refusal.
SuspendOutcome PowerSuspendCheck();

/// Enter S3. Returns `Cycled` only when the machine actually slept
/// and came back through the wake trampoline.
SuspendOutcome PowerSuspendToRam();

/// Log the participant + veto lists (one line each, Info level).
void PowerSuspendReport();

/// Register the platform's own S3 participants (serial, PS/2). Called
/// once from the boot bring-up, after those drivers are initialised.
void PowerSuspendInit();

/// Boot self-test. With `run_live_cycle` false this only validates the
/// refusal bookkeeping and emits `[suspend-selftest] PASS`. With it
/// true (kernel cmdline `s3test=1`) it performs a REAL S3 cycle: the
/// machine suspends and stays down until the platform delivers a wake
/// event, then logs the resume proof. Only the harness sets that —
/// a normal boot must never suspend itself.
void PowerSuspendSelfTest(bool run_live_cycle);

} // namespace duetos::power
