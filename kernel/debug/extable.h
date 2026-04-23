#pragma once

#include "../core/types.h"

/*
 * CustomOS — kernel exception table (extable) — v0.
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

namespace customos::debug
{

inline constexpr u32 kMaxExtableEntries = 32;

struct ExtableEntry
{
    u64 rip_start;   // inclusive
    u64 rip_end;     // exclusive
    u64 fixup_rip;   // where to redirect frame->rip on a match
    const char* tag; // short label for log lines
};

/// Register a (start, end, fixup) triple. Returns false if the
/// table is full or the input is malformed (start >= end, fixup
/// not inside the range is allowed — the fixup typically lives
/// in a different function than the faulting code). Safe to call
/// from any context that isn't already the trap handler.
bool KernelExtableRegister(u64 rip_start, u64 rip_end, u64 fixup_rip, const char* tag);

/// Trap-handler hook: given a faulting RIP, return the matching
/// fixup target or 0 if no row matches. Linear scan; expected to
/// run under interrupts disabled inside the trap handler. Safe
/// to call before any registrations (returns 0 for everything).
u64 KernelExtableFindFixup(u64 rip);

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

} // namespace customos::debug
