#pragma once

#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — fault domains + restartable subsystems, v0.
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

namespace duetos::core
{

// Registry capacity. Sized to accommodate every restartable
// subsystem in the foundational-vs-restartable classification
// (~30 today) plus 50% headroom for follow-up migrations. The
// linear scans (`FaultDomainTick`, `FaultDomainFind`) stay
// trivially cheap at this size — one cache line per few rows.
inline constexpr u32 kMaxFaultDomains = 48;

using FaultDomainId = u32;
inline constexpr FaultDomainId kFaultDomainInvalid = 0xFFFFFFFFu;

/// Operator-visible lifecycle state of a registered domain.
/// Three states, not six: `init`/`teardown` are non-yielding and
/// serialised by the registry, so transient `Starting`/`Stopping`
/// are never observable to a reader. `Crashed` is distinct from
/// `Stopped` because they answer different questions — "operator
/// stopped me" vs "I tripped a trap and the watchdog hasn't
/// drained me yet."
enum class ModuleState : u8
{
    Stopped = 0, // teardown ran cleanly; init has not yet been called
    Running = 1, // init succeeded; subsystem is live
    Crashed = 2, // a fault tripped MarkRestart but the watchdog has not yet drained
};

/// Rolling-window rate throttle. Each domain keeps the last
/// `kRestartHistoryDepth` restart timestamps; when that many
/// restarts land within `kRestartThrottleWindowTicks`, the
/// supervisor refuses the next restart and parks the domain in
/// `Stopped` so an operator can intervene before another flap.
/// Tick rate is 100 Hz (`kTickHz`); 6000 ticks ≈ 60 seconds.
inline constexpr u32 kRestartHistoryDepth = 5;
inline constexpr u64 kRestartThrottleWindowTicks = 6000;

/// Capacity of the cross-domain dependency table. Each slot is a
/// (parent, dependent) pair: when `parent` restarts, `dependent`
/// is also marked for restart on the next watchdog tick. Sized
/// for ~PCI fan-out (one parent feeding several leaves) without
/// reaching a heap.
inline constexpr u32 kMaxFaultDomainDeps = 64;

struct FaultDomain
{
    const char* name;                          // short label: "drivers/usb/xhci"
    Result<void> (*init)();                    // idempotent init; return Err on failure
    Result<void> (*teardown)();                // free resources; must leave the
                                               // subsystem ready for a fresh init
    u32 restart_count;                         // lifetime restart events
    u64 last_restart_ticks;                    // scheduler-tick of the most recent restart
    bool alive;                                // false iff teardown ran and init hasn't yet.
                                               // Trap-safe single-bit projection of `state`
                                               // for the watchdog's lossless backbone — the
                                               // trap handler can flip this from NMI/#PF
                                               // context where a multi-byte enum write
                                               // would not be atomic.
    bool restart_pending;                      // set from trap-handler context via
                                               // `FaultDomainMarkRestart`; drained by
                                               // `FaultDomainTick` from kheartbeat,
                                               // which is allowed to take locks +
                                               // allocate memory (the trap handler
                                               // is not).
    ModuleState state;                         // operator-visible projection of the
                                               // bool pair. Written only from heartbeat
                                               // / shell context (multi-byte stores) by
                                               // `FaultDomainRestart`, `FaultDomainTick`,
                                               // `ModuleStart`, `ModuleStop`. Trap path
                                               // never touches this — it flips the
                                               // single-bit `restart_pending` and
                                               // `alive` instead.
    u64 restart_history[kRestartHistoryDepth]; // ring of recent restart
                                               // timestamps (in scheduler
                                               // ticks). Populated on every
                                               // successful restart;
                                               // consulted by the rate
                                               // throttle before draining
                                               // a pending restart.
    u32 restart_history_next;                  // FIFO write cursor into restart_history.
    u32 restart_throttle_count;                // lifetime count of throttle-aborted
                                               // restarts. Diagnostic surface; nonzero
                                               // means an operator should investigate
                                               // why this domain keeps flapping.
};

/// Register a domain. Returns the assigned id, or
/// `kFaultDomainInvalid` if the registry is full or the
/// parameters are malformed (nullptr name / init / teardown).
FaultDomainId FaultDomainRegister(const char* name, Result<void> (*init)(), Result<void> (*teardown)());

/// Number registered, for diagnostics.
u32 FaultDomainCount();

/// Accessor; nullptr for out-of-range.
const FaultDomain* FaultDomainGet(FaultDomainId id);

/// Mutating accessor used by `security/module.cpp` (ModuleStart /
/// ModuleStop / ModuleDump) to project state changes onto the
/// operator-visible `ModuleState` field. The trap path must NOT
/// use this — it flips `restart_pending` instead. Returns nullptr
/// for out-of-range. Callers run in heartbeat / shell context
/// (multi-byte stores are safe).
FaultDomain* FaultDomainGetMutable(FaultDomainId id);

/// Lookup by name. Linear scan. Returns `kFaultDomainInvalid` if
/// not found.
FaultDomainId FaultDomainFind(const char* name);

/// Drive the named domain through teardown + re-init. On any
/// step's failure the domain is left `alive=false` and the error
/// propagates — the caller decides whether to retry. Logs each
/// phase.
Result<void> FaultDomainRestart(FaultDomainId id);

/// Mark a domain for deferred restart. Cheap (one bool write)
/// and safe to call from contexts that cannot take locks or
/// allocate (trap handlers, IRQs, NMI). The actual restart runs
/// on the next `FaultDomainTick` from the heartbeat thread.
/// Out-of-range or invalid id is silently ignored — there's no
/// useful action a trap handler can take with the failure.
void FaultDomainMarkRestart(FaultDomainId id);

/// Watchdog tick. Drains any `restart_pending` flags by calling
/// `FaultDomainRestart` for each marked domain, in registration
/// order. Logs the result of every drained restart. Cheap when
/// no flags are set — one linear scan over the registry.
/// Called from `kheartbeat` on every beat.
void FaultDomainTick();

/// Boot-time sanity test — registers a toy domain with trivial
/// hooks + counters, restarts it twice, exercises the
/// MarkRestart + Tick path, verifies the bookkeeping. Panics on
/// mismatch.
void FaultDomainSelfTest();

/// Declare that `dependent` must be restarted whenever `parent`
/// restarts. Used to model topology like "PCI feeds NVMe feeds
/// VFS" — restarting PCI cascades through the leaves so the
/// operator doesn't have to drive each restart manually.
///
/// Order: a successful `FaultDomainRestart(parent)` walks the
/// dependency table and calls `FaultDomainMarkRestart(dependent)`
/// for every matching row. The watchdog drains the marks on the
/// next heartbeat — same path as a trap-recorded fault. This
/// keeps the cascade off the synchronous restart path so a slow
/// dependent's teardown can't stall the parent's recovery.
///
/// Returns false if the dependency table is full (cap
/// `kMaxFaultDomainDeps`) or either id is out of range. Self-
/// dependencies (parent == dependent) are refused; cycles are
/// not detected (the cascade is one level deep — a dependent's
/// own dependents fire on its restart, propagating the cascade
/// through the graph). Idempotent: registering the same edge
/// twice succeeds without duplication, but a clean implementation
/// stores the edge twice (cheap; the cascade tolerates duplicates
/// since `MarkRestart` is itself idempotent).
bool FaultDomainAddDependency(FaultDomainId parent, FaultDomainId dependent);

/// Number of registered dependency edges. Diagnostic surface for
/// audits and self-tests.
u32 FaultDomainDependencyCount();

/// Number of times the rate throttle has refused a restart, total
/// across every domain. `0` is the steady-state expectation.
u64 FaultDomainThrottleCount();

} // namespace duetos::core
