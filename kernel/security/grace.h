#pragma once

#include "proc/process.h"
#include "util/types.h"

/*
 * DuetOS — elevation grace cache, v0.
 *
 * After the broker successfully prompts for a password and grants a
 * cap to a process, it inserts a row here so subsequent privileged
 * syscalls by the same process needing the same cap pass through
 * without reprompting. Each row is bounded by a deadline derived
 * from the role's grace policy (kRbacDefaultGraceSeconds, or the
 * per-cap override, or kRbacNoGrace which means "do not cache").
 *
 * The table is a fixed-size in-memory array of
 * `(pid, cap, deadline_ns)` rows. Lookups are linear; the table is
 * small (~64 rows) so this is cheaper than any tree at this scale.
 *
 * Eviction:
 *   - GraceCacheReap() sweeps expired rows. Called by the broker
 *     before any insert, and by the elevation prompt path before
 *     it asks the user a question (so a stale entry doesn't
 *     accidentally silence a legitimate reprompt).
 *   - GraceCacheExpirePid(pid) clears every row for a pid; called
 *     on process exit so a recycled pid does not inherit grants
 *     from its predecessor.
 *
 * Concurrency: same context discipline as the broker — called from
 * the syscall dispatcher (process context, no IRQ), the shell, and
 * the login gate. Serialised by the existing process-syscall
 * sequencing; no extra lock for v0. Promote to a spinlock the day
 * the broker grows multi-CPU-concurrent callers.
 *
 * Context: kernel. Never called from IRQ.
 */

namespace duetos::security
{

constexpr u32 kGraceCacheCapacity = 64;

struct GraceEntry
{
    u64 pid;
    duetos::core::Cap cap;
    u64 deadline_ns;
    bool in_use;
};

/// Initialize the cache (zero all rows). Idempotent. Called once
/// from kernel boot.
void GraceCacheInit();

/// Lookup: does (pid, cap) currently hold a valid grant? Returns
/// true if a non-expired row exists. Lazy-expires the row on miss
/// so the next insert can reuse the slot.
bool GraceCacheLookup(u64 pid, duetos::core::Cap cap);

/// Insert a grant for `(pid, cap)` with lifetime `seconds`. A
/// lifetime of 0 is treated as "no_cache" and is a no-op — the
/// broker still grants the syscall, but a future call will
/// reprompt. Returns true if a row was actually written. On a
/// full table, evicts the row with the earliest deadline.
bool GraceCacheInsert(u64 pid, duetos::core::Cap cap, u32 lifetime_seconds);

/// Drop every row for a pid. Called on process exit.
void GraceCacheExpirePid(u64 pid);

/// Sweep expired rows. Idempotent; safe to call from any task
/// context. Returns the number of rows reaped.
u32 GraceCacheReap();

/// Current count of live rows (after a reap pass).
u32 GraceCacheLiveCount();

/// Read-only view: copy the i-th live row out. Returns false on
/// out-of-range or stale slot. The "elevations" shell command
/// uses this to print "what's currently elevated."
bool GraceCacheEntryAt(u32 idx, GraceEntry* out);

/// Boot self-test — exercises insert / lookup / expire / reap on
/// synthetic pids. Panics on regression.
void GraceCacheSelfTest();

} // namespace duetos::security
