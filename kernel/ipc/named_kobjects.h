#pragma once

#include "ipc/kobject.h"
#include "util/types.h"

/*
 * DuetOS — cross-process named-kobject namespace.
 *
 * Win32 contract: CreateMutexW(NULL, FALSE, L"Global\\Foo") in
 * process A and OpenMutexW(0, FALSE, L"Global\\Foo") in process B
 * must return handles to the SAME kernel object. Same shape
 * for named events and semaphores.
 *
 * The userland kernel32 layer alone can't satisfy this — its
 * name table is process-local, so process B's lookup never
 * sees process A's registration. This file implements the
 * kernel-resident name table that both processes consult.
 *
 * Storage: a fixed-size table (kNamedKObjectSlots) of
 * (type, name, KObject*) triples guarded by a single
 * spinlock. Lookup is a linear scan — fine at 32 slots; swap
 * for a hash table when the slot count grows.
 *
 * Lifetime: the table holds a refcount on every registered
 * KObject. The entry's refcount is released only when the
 * slot is LRU-evicted by another Register call. Callers of
 * NamedKObjectFind receive a fresh refcount that they're
 * responsible for releasing (typically by handing the
 * kobject off to a HandleTable, which takes its own ref).
 *
 * Out of scope (residuals — keep this header narrow):
 *   - Hierarchical namespaces (`Global\` vs `Local\` prefix
 *     handling — both flatten into the same table today).
 *   - Permission gating (caller's caps aren't checked; any
 *     process can open any name).
 *   - Owner-pid tracking + process-exit cleanup. The table
 *     holds entries until LRU eviction; long-running boxes
 *     with many distinct names will see hot entries fight
 *     for slots. Bumping kNamedKObjectSlots is the v0 fix.
 */

namespace duetos::ipc
{

constexpr u32 kNamedKObjectSlots = 32;
constexpr u32 kNamedKObjectMaxNameLen = 64;

/// Look up an existing entry. Returns the registered KObject
/// with a fresh refcount taken (caller must `KObjectRelease`
/// when done, or hand it off to a `HandleTable`), or `nullptr`
/// if no entry matches.
///
/// `name` must be NUL-terminated and < kNamedKObjectMaxNameLen.
/// Type mismatch counts as a miss.
KObject* NamedKObjectFind(KObjectType type, const char* name);

/// Register `obj` under `name` for the given type. Takes a
/// refcount on `obj` that the table releases on LRU eviction.
/// Returns true on success.
///
/// If an entry for (type, name) already exists, returns true
/// without modifying it — the caller's `obj` is NOT
/// registered (the caller is expected to release the ref it
/// allocated for its create path). This makes Register
/// idempotent for the "Create returns existing" path.
bool NamedKObjectRegister(KObjectType type, const char* name, KObject* obj);

/// Boot-time self-test — register / find / refcount drift
/// checks. Called from the early-init phase.
void NamedKObjectSelfTest();

} // namespace duetos::ipc
