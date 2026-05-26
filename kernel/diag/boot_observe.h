#pragma once

#include "core/init.h"
#include "util/types.h"

/*
 * DuetOS — boot observability: phase timeline, hang watchdog,
 * hierarchical QEMU exit codes, and a machine-readable boot report.
 *
 * WHY
 *   The headless-QEMU / CI loop diagnosed boot failures by grepping a
 *   fragile multi-line string-signature serial log; a hang just stopped
 *   with no "stuck at phase X" signal; a panic froze until the wall
 *   timeout. This subsystem instruments the single `core::RunPhase`
 *   choke point so every boot emits an ordered, parseable phase ladder,
 *   a structured `[boot-report]` block, and — on hang / phase-init
 *   failure / panic under a smoke profile — a hierarchical
 *   `arch::TestExit` code the harness decodes into a precise message.
 *
 *   This REPLACES the old `diag::BootProgress` RDTSC-cycle markers
 *   (raw cycles nobody could convert pre-calibration). It is NOT a
 *   parallel phase system: it instruments the existing `core::Phase`
 *   registry, and the watchdog reuses the existing timer-IRQ heartbeat
 *   hook in `arch/x86_64/timer.cpp` — no new timer, no new enum.
 *
 * PHASE MODEL
 *   A phase is *active* from `BootPhaseEnter(P)` until the next
 *   `BootPhaseEnter(P')` (the real boot work is the imperative code
 *   between `RunPhase` calls, not the near-instant dispatch itself, so
 *   "duration since RunPhase returned" would be meaningless ~0). The
 *   last phase is finalised by `BootReportEmit()`.
 *
 * CONTEXT
 *   Kernel, BSP, single-threaded boot. `BootWatchdogTick` runs in the
 *   timer IRQ. All state is constinit and written single-threaded
 *   during boot; the watchdog only reads it.
 */

namespace duetos::diag
{

/// Exit-code classes layered on `arch::TestExit(b)` → QEMU process
/// exit `(b<<1)|1`. `b` is kept <= 0x7F so the wait status stays in
/// 0..255. Low nibble carries the `core::Phase` ordinal (0..12);
/// `Pass` ignores it. Decode in the harness: `b=(rc-1)>>1`,
/// `class=b&0xF0`, `phase=b&0x0F`.
enum class BootExitCode : u8
{
    Pass = 0x10,          ///< Smoke sentinel reached (unchanged: QEMU exit 0x21).
    HungInPhase = 0x20,   ///< Watchdog: a phase exceeded its sane wall budget.
    PhaseInitFail = 0x40, ///< A `RunPhase` callback returned Err.
    Panic = 0x70,         ///< Kernel panic (incl. a failed boot self-test).
};

/// Pack a class + phase ordinal into the `arch::TestExit` status byte.
/// `Pass` is phase-independent. Max byte = Panic|12 = 0x7C → QEMU
/// exit 0xF9, in range.
constexpr u8 EncodeExit(BootExitCode cls, core::Phase phase)
{
    if (cls == BootExitCode::Pass)
    {
        return static_cast<u8>(BootExitCode::Pass);
    }
    const u8 ord = static_cast<u8>(static_cast<u32>(phase) & 0x0F);
    return static_cast<u8>(cls) | ord;
}

/// Called from `core::RunPhase` before the dispatch loop. Finalises
/// the previously-active phase (emits its `[boot] phase=<n> complete
/// t=<ms> dur=<ms>` line with the true span), records this phase's
/// enter time + tick, emits `[boot] phase=<n> begin`. If a debug
/// stall was injected for this phase (see `BootObserveSetStallPhase`),
/// busy-loops here forever so the watchdog path can be exercised.
void BootPhaseEnter(core::Phase phase);

/// Called from `core::RunPhase` when a registered callback returns
/// Err. Emits `[boot] phase=<n> FAIL ec=<hexbyte>`. Under a smoke
/// profile, `arch::TestExit(EncodeExit(PhaseInitFail, phase))` so CI
/// gets a structured code instead of a silent `(void)`-discarded
/// error; on bare-metal / interactive boots it only logs (the
/// existing imperative path keeps its current behaviour).
void BootPhaseFailed(core::Phase phase, u32 errcode);

/// The most recently entered phase, for panic attribution. Returns
/// `core::Phase::Earlycon` before any phase was entered.
core::Phase BootPhaseCurrent();

/// Called from `arch/x86_64/timer.cpp` at the exact point its
/// existing init-wedge detector concludes the boot is wedged (no
/// serial progress for ~15 s while the timer IRQ kept firing — an
/// environment-independent heuristic, unlike a wall-clock budget
/// that would false-fire on a chatty-but-slow phase under TCG).
/// Emits `[boot] phase=<n> STUCK ec=<hexbyte>` attributing the wedge
/// to the active phase and, under a smoke profile, `arch::TestExit`s
/// with the HungInPhase code so CI fails fast with a phase-named
/// message instead of waiting out the wall timeout. One-shot (the
/// caller's wedge block is already one-shot).
void BootWatchdogOnWedge();

/// Emit the machine-readable `[boot-report]` block (one greppable
/// key=value line per phase + totals + `result=pass`). Call once,
/// just before the smoke sentinel, after the existing fix-journal /
/// translator summaries (which remain independently greppable).
void BootReportEmit();

/// Debug injection: when `phase` is next entered, `BootPhaseEnter`
/// busy-loops forever, so a `boot-stall=<phase>` cmdline run proves
/// the watchdog fires. `core::Phase::kPhaseCount` disarms it.
void BootObserveSetStallPhase(core::Phase phase);

/// Make `BootPhaseEnter` / `BootPhaseFailed` no-ops while `on` is
/// true. The init-registry self-test (`core::InitSelfTest`) drives
/// `RunPhase` through Earlycon/Heap/Drivers and a deliberate
/// Userland Err as a plumbing test of the registry itself — those
/// invocations are NOT real boot phases and must not pollute the
/// ladder, fire the stall, or trip the PhaseInitFail exit. Bracket
/// the self-test with `(true)` / `(false)`.
void BootObserveSuppress(bool on);

/// True while the suppress window is active. Lets the init-registry
/// `RunPhase` demote its "callback failed" ERROR log to INFO when
/// the failing row is part of the deliberate self-test plumbing —
/// the test verifies that a failing Result propagates, NOT that an
/// `[E]` line appears in the boot log. Without this, the deliberate
/// failure pollutes the regression-scan output of
/// `tools/test/boot-log-analyze.sh` on every clean boot.
bool BootObserveIsSuppressed();

} // namespace duetos::diag
