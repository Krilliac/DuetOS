#pragma once

#include "proc/process.h"
#include "util/types.h"

/*
 * DuetOS elevation grace cache.
 *
 * Positive-duration broker grants are generation-tagged Process
 * leases. This fixed table caches only the metadata needed to reuse
 * a live lease without prompting again. The Process deadline is the
 * authority boundary: expiry and table eviction discard cache rows
 * but never need a scheduler-wide process lookup or eager revocation.
 * The next effective capability snapshot expires an overdue lease
 * under that Process's cap lock.
 *
 * Every cache operation is serialized by one spinlock. When both
 * locks are needed, the order is grace lock -> AuthorizationContext lock;
 * Process capability helpers never call back into this cache.
 * Task context only; never IRQ context.
 */

namespace duetos::security
{

constexpr u32 kGraceCacheCapacity = 64;

struct GraceEntry
{
    u64 pid;
    duetos::core::Cap cap;
    u64 deadline_ns;
    u64 generation;
    bool in_use;
};

void GraceCacheInit();
bool GraceCacheLookup(u64 pid, duetos::core::Cap cap);

/// Reuse a live cached lease while the row remains protected.
bool GraceCacheTryGrant(duetos::core::Process* process, duetos::core::Cap cap);

/// Install a positive-duration Process lease, then publish its cache row.
bool GraceCacheGrantLease(duetos::core::Process* process, duetos::core::Cap cap, u32 lifetime_seconds);

/// Discard cache metadata only. The Process deadline remains authoritative.
void GraceCacheExpire(u64 pid, duetos::core::Cap cap);
void GraceCacheExpirePid(u64 pid);
u32 GraceCacheReap();
u32 GraceCacheLiveCount();
bool GraceCacheEntryAt(u32 idx, GraceEntry* out);
void GraceCacheSelfTest();

} // namespace duetos::security
