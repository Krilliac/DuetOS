#pragma once

#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — deliberate kernel fault injection.
 *
 * A cap-gated way to exercise the kernel's panic / page-fault / slab
 * recovery paths from inside the running kernel. The harness has
 * exactly three v0 fault classes (NullDeref, Panic, OomSlab); each
 * has a known caller (the `fault-inject` kernel shell command and a
 * boot self-test for the recoverable case).
 *
 * Why this module exists: panic-path bugs and slab exhaustion bugs
 * are some of the cheapest to introduce and the most expensive to
 * find in the wild. A first-class trigger lets a regression in those
 * paths surface on a developer machine, not in the field, and gives
 * the runtime checker / probe subsystem something concrete to count.
 *
 * What it is NOT:
 *   - Not a fuzzer. It triggers ONE fault per call; it does not pick
 *     fault classes randomly.
 *   - Not a recovery mechanism. The Panic / NullDeref classes do not
 *     return; halts and reboots are the cure.
 *   - Not configurable. The class set is closed at compile time; no
 *     runtime registration, no pluggable backends.
 *
 * Cap-gating: every reach to `Trigger` is mediated. The shell
 * command calls `Trigger` directly after `RequireCap(kCapDiag, …)`.
 * The userland surface is `SYS_DIAG_FAULT_INJECT`, gated on
 * kCapDiag by the syscall cap table (see kernel/syscall/cap_table.def).
 *
 * Context: kernel. Safe from any kernel context that may take a
 * sleeping mutex (the OomSlab path drains a slab cache, which uses
 * a `sched::Mutex` internally). NOT safe from IRQ context.
 */

namespace duetos::diag::fault_inject
{

enum class FaultClass : ::duetos::u32
{
    NullDeref = 1, // load from a guaranteed-unmapped kernel VA; exercises
                   // the kernel #PF handler. Does not return.
    Panic = 2,     // calls core::Panic with a message that starts with
                   // "[fault-inject] forced panic"; exercises the panic
                   // path end-to-end. Does not return.
    OomSlab = 3,   // drain one small-class slab cache until SlabAlloc
                   // returns nullptr; exercises the recoverable OOM
                   // path. Returns Ok on a clean drain, an ErrorCode
                   // otherwise.
};

/// Trigger one of the v0 fault classes.
///
/// NullDeref and Panic are non-returning by construction; the
/// return type is preserved so the call site has uniform shape (a
/// caller that holds the trigger behind another gate sees the same
/// Result<...> independent of class).
///
/// OomSlab returns:
///   - Ok                                          when the drain
///                                                 reached the
///                                                 expected
///                                                 SlabAlloc==nullptr
///                                                 failure mode and
///                                                 the harness was
///                                                 able to free every
///                                                 object it took.
///   - Err{ErrorCode::Unsupported}                 when the harness
///                                                 could not create
///                                                 its private slab
///                                                 cache (kheap
///                                                 exhausted before
///                                                 the test could
///                                                 begin — nothing
///                                                 to test against).
///   - Err{ErrorCode::Internal}                    when the drain
///                                                 cap was reached
///                                                 without observing
///                                                 an allocation
///                                                 failure (likely a
///                                                 slab regression
///                                                 the caller wants
///                                                 to investigate).
///   - Err{ErrorCode::InvalidArgument}             on an out-of-range
///                                                 FaultClass.
duetos::core::Result<void, duetos::core::ErrorCode> Trigger(FaultClass fc);

/// Boot self-test — exercises ONLY the OomSlab class because the
/// other two are non-returning. On success emits one
/// `[fault-inject-selftest] PASS` line via `arch::SerialWrite`; on
/// failure fires `kBootSelftestFail` with a sub-check encoding and
/// logs a `[fault-inject-selftest] FAIL` warn. See
/// `wiki/kernel/Fault-Injection.md` for the contract.
void FaultInjectSelfTest();

} // namespace duetos::diag::fault_inject
