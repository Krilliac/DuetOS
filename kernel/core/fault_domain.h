#pragma once

#include "result.h"
#include "types.h"

/*
 * CustomOS — fault domains + restartable subsystems, v0.
 *
 * A "fault domain" is a named subsystem that registers a
 *   (teardown, init)
 * function pair. Once registered, any caller can:
 *
 *   FaultDomainRestart(id)
 *
 * to drive the subsystem through teardown + re-init without
 * taking the kernel down. The v0 mechanism is MANUAL — the trap
 * handler doesn't automatically restart a domain on fault yet
 * (that's a follow-up slice that integrates with extable). What
 * this slice provides:
 *
 *   - A registry of named domains with their lifecycle hooks.
 *   - An explicit restart API for the shell / health scanner / a
 *     future watchdog thread.
 *   - A boot-time self-test that restarts a toy domain and
 *     verifies the sequence.
 *
 * Why this matters even before trap integration: it forces each
 * driver to grow a real teardown. Today most of our drivers only
 * have an Init() — they assume they run once at boot and never
 * stop. Making them honest about their tear-down costs nothing
 * at steady state and unlocks every later "restart on fault" /
 * "hot swap" / "live upgrade" path.
 *
 * Context: kernel. Registration runs at subsystem init time.
 * Restart runs from the caller's context; any concurrency concerns
 * are the teardown/init's responsibility (the domain registry
 * only serialises the transition, not the data structures the
 * subsystem owns).
 */

namespace customos::core
{

inline constexpr u32 kMaxFaultDomains = 16;

using FaultDomainId = u32;
inline constexpr FaultDomainId kFaultDomainInvalid = 0xFFFFFFFFu;

struct FaultDomain
{
    const char* name;           // short label: "drivers/usb/xhci"
    Result<void> (*init)();     // idempotent init; return Err on failure
    Result<void> (*teardown)(); // free resources; must leave the
                                // subsystem ready for a fresh init
    u32 restart_count;          // lifetime restart events
    u64 last_restart_ticks;     // scheduler-tick of the most recent restart
    bool alive;                 // false iff teardown ran and init hasn't yet
};

/// Register a domain. Returns the assigned id, or
/// `kFaultDomainInvalid` if the registry is full or the
/// parameters are malformed (nullptr name / init / teardown).
FaultDomainId FaultDomainRegister(const char* name, Result<void> (*init)(), Result<void> (*teardown)());

/// Number registered, for diagnostics.
u32 FaultDomainCount();

/// Accessor; nullptr for out-of-range.
const FaultDomain* FaultDomainGet(FaultDomainId id);

/// Lookup by name. Linear scan. Returns `kFaultDomainInvalid` if
/// not found.
FaultDomainId FaultDomainFind(const char* name);

/// Drive the named domain through teardown + re-init. On any
/// step's failure the domain is left `alive=false` and the error
/// propagates — the caller decides whether to retry. Logs each
/// phase.
Result<void> FaultDomainRestart(FaultDomainId id);

/// Boot-time sanity test — registers a toy domain with trivial
/// hooks + counters, restarts it twice, verifies the bookkeeping.
/// Panics on mismatch.
void FaultDomainSelfTest();

} // namespace customos::core
