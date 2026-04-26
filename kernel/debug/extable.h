#pragma once

#include "util/types.h"

/*
 * DuetOS — kernel exception table (extable) — v0.
 *
 * Generalises the mechanism that traps.cpp already hard-codes for
 * `__copy_user_fault_fixup`: a registry of
 *   (rip_start, rip_end, fixup_rip)
 * rows the #PF / #GP trap handler consults before panicking. If
 * the faulting RIP lands inside a registered [rip_start, rip_end)
 * range, the handler rewrites `frame->rip` to `fixup_rip` and
 * iretq's. The fixup is an ordinary C/asm function in the same
 * stack frame as the faulting code — it runs with the same `rsp`
 * and returns to the caller as if the bracketed region had
 * returned a failure sentinel.
 *
 * This is the v0 shape of "one part faulting doesn't bring the
 * whole kernel down." Scope limits:
 *
 *   - Only synchronous kernel-mode traps (#PF, #GP, #UD) are
 *     caught. Asynchronous problems (IRQ storms, memory
 *     corruption, deadlocks) are a different class of failure
 *     this mechanism does NOT address.
 *
 *   - The faulting function and its fixup must share a stack
 *     frame. The `FaultScope*` helpers below enforce this by
 *     bracketing a labelled asm region.
 *
 *   - Registration is static + fixed-capacity. No dynamic
 *     unregister; a registered row is valid for the kernel's
 *     lifetime. That's fine because the kernel's code section is
 *     non-relocatable at runtime — a row never becomes stale.
 *
 * Context: kernel. Registration happens at init time from any
 * subsystem that wants fault recovery. Lookup happens from the
 * trap handler — must be O(n) linear scan over a bounded small
 * table (cap 32) since anything fancier (a lock, a tree)
 * reintroduces the concurrency / reentrancy concerns we're
 * trying to avoid in the trap path.
 */

namespace duetos::debug
{

inline constexpr u32 kMaxExtableEntries = 32;

// Sentinel for `ExtableEntry::domain_id` meaning "no fault domain
// attached to this row." Mirrors `core::kFaultDomainInvalid` but
// declared here as a plain u32 so this header doesn't have to
// pull in `security/fault_domain.h` (which would create an awkward
// debug → core dependency loop for the trap-handler include).
inline constexpr u32 kExtableNoDomain = 0xFFFFFFFFu;

struct ExtableEntry
{
    u64 rip_start;   // inclusive
    u64 rip_end;     // exclusive
    u64 fixup_rip;   // where to redirect frame->rip on a match
    const char* tag; // short label for log lines
    u32 domain_id;   // FaultDomainId or kExtableNoDomain. When
                     // set, the trap handler also marks the
                     // domain for deferred restart via
                     // `FaultDomainMarkRestart` — the immediate
                     // fixup gives the synchronous caller a
                     // failure path; the watchdog re-init's the
                     // subsystem so future calls succeed.
};

/// Register a (start, end, fixup) triple with no associated
/// fault domain. Returns false if the table is full or the input
/// is malformed (start >= end, fixup_rip == 0). Safe to call from
/// any context that isn't already the trap handler.
bool KernelExtableRegister(u64 rip_start, u64 rip_end, u64 fixup_rip, const char* tag);

/// Same as `KernelExtableRegister`, plus binds the row to a
/// fault-domain id. On match the trap handler iretq's to
/// `fixup_rip` AND calls `FaultDomainMarkRestart(domain_id)`,
/// which the watchdog drains on the next heartbeat. Use when a
/// driver entry point should both fail-fast for the immediate
/// caller AND auto-recover for future callers.
bool KernelExtableRegisterWithDomain(u64 rip_start, u64 rip_end, u64 fixup_rip, const char* tag, u32 domain_id);

/// Trap-handler hook: given a faulting RIP, return the matching
/// fixup target or 0 if no row matches. Linear scan; expected to
/// run under interrupts disabled inside the trap handler. Safe
/// to call before any registrations (returns 0 for everything).
u64 KernelExtableFindFixup(u64 rip);

/// Trap-handler hook (richer): same lookup as `FindFixup`, but
/// returns the full entry pointer so the caller can also read
/// the attached `domain_id`. Returns nullptr on miss. Same
/// re-entry guard as `FindFixup`.
const ExtableEntry* KernelExtableFindEntry(u64 rip);

/// Entry-count snapshot for diagnostics. Not safe to read
/// atomically with a concurrent register on SMP — used only by
/// boot self-tests and the `extable` shell command.
u32 KernelExtableEntryCount();

/// Accessor for a registered entry. Returns nullptr for out-of-
/// range index. Same SMP caveat as `KernelExtableEntryCount`.
const ExtableEntry* KernelExtableEntryAt(u32 i);

/// Boot-time sanity test — registers a synthetic entry, simulates
/// the lookup, and verifies both the matching and the non-matching
/// paths. PASS/FAIL line on COM1; panics on mismatch.
void ExtableSelfTest();

} // namespace duetos::debug
