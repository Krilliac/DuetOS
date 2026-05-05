#pragma once

#include "diag/fault_react.h"
#include "security/fault_domain.h"
#include "util/types.h"

namespace duetos::arch
{
struct TrapFrame;
}

/*
 * DuetOS — non-fatal per-domain crash record emitter.
 *
 * `core::Panic` / `core::BeginCrashDump` are the kernel-is-dead
 * path: serial-panic mode, NMI broadcast, halt. Re-using them
 * for a per-domain dump where the kernel keeps running would
 * dilute the panic semantics and force the panic path to grow
 * a non-halting branch. This file is the parallel, non-fatal
 * shape:
 *
 *   - `BeginDomainDump(id, evidence)` writes the leading
 *     `=== DUETOS DOMAIN DUMP <name> BEGIN ===` block and the
 *     dump header (state-before, restart_count, fault kind/rip).
 *   - The dump body emits the optional trap frame and a klog
 *     tail filtered by the domain's LogArea.
 *   - `EndDomainDump()` writes the closing marker + records the
 *     finished record into the in-kernel "recent dumps" ring so
 *     a shell `module dumps <name>` can replay it after the fact.
 *
 * The format mirrors `core::BeginCrashDump`'s schema markers so
 * host-side tooling can grep both. The non-fatal version uses
 * `=== DUETOS DOMAIN DUMP …` (vs `=== DUETOS CRASH DUMP …`) so
 * tools can disambiguate.
 *
 * Context: kernel, heartbeat / shell only. Single irq-save
 * spinlock protects the serial output so concurrent emitters
 * don't interleave. Never call from a trap handler — the trap
 * path should `FaultReactReportFromTrap` instead and let the
 * heartbeat-side drain land here.
 */

namespace duetos::security
{

/// Optional fault evidence captured by the trap path or
/// constructed by an operator-driven dump. Every field is
/// optional from the dump format's perspective: a missing
/// trap frame just omits the register section, a zero rip
/// just omits the address line, etc.
struct DomainDumpEvidence
{
    ::duetos::diag::FaultKind kind = ::duetos::diag::FaultKind::Unknown;
    u64 faulting_rip = 0;
    u64 aux = 0; // kind-specific (cr2, status word, …); 0 = omit
    const ::duetos::arch::TrapFrame* frame = nullptr;
};

/// Open a dump record for `id`. Emits the BEGIN marker and the
/// header. Out-of-range id is a silent no-op (operators get an
/// error message from the shell wrapper instead).
void BeginDomainDump(::duetos::core::FaultDomainId id, const DomainDumpEvidence& ev);

/// Close the most recently opened dump record. Emits the END
/// marker and records the dump into the recent-dumps ring.
/// Pairs 1-1 with `BeginDomainDump`; calling without a prior
/// open is a no-op.
void EndDomainDump();

/// Capacity of the in-kernel "recent dumps" ring. Each slot
/// holds a small fixed-size text buffer with the dump record
/// for one domain crash. Older entries are evicted FIFO.
inline constexpr u32 kRecentDumpRingCapacity = 8;

/// Replay every retained dump record for `id` (oldest-first)
/// onto the serial console. Used by shell `module dumps <name>`.
/// Out-of-range id emits a `not found` log line and returns.
void DumpRecentDumps(::duetos::core::FaultDomainId id);

/// How many dumps for this domain are currently in the ring
/// (0..kRecentDumpRingCapacity). Used by shell status output.
u32 RecentDumpCount(::duetos::core::FaultDomainId id);

/// Boot-time self-test. Synthesises a domain, opens + closes
/// a dump, asserts the ring captured it, replays it. Panics
/// on mismatch.
void DomainDumpSelfTest();

} // namespace duetos::security
