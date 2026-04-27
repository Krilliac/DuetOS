#pragma once

#include "ipc/kobject.h"
#include "sync/spinlock.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — per-process kernel-object handle table, v0 (plan A3).
 *
 * WHAT
 *   A fixed-size array mapping `Handle` (u32) to `KObject*`.
 *   Native and Win32/NT and Linux ABI front-ends translate their
 *   own handle shapes to/from `Handle`; the kernel-internal name
 *   for an IPC object is its `KObject*` plus its `Handle` in the
 *   owning process's table.
 *
 * INDEX 0 IS RESERVED
 *   `kHandleInvalid = 0`. Slot 0 is never handed out, so a freshly
 *   zeroed `HandleTable` is in the "all-empty" state and any code
 *   that accidentally treats `0` as a valid handle hits the
 *   invalid-handle return path.
 *
 * NO BOOT-TIME ALLOCATOR
 *   Fixed-size storage — `HandleTable` is plain-old-data, safe to
 *   declare `static` or embed in a struct. v0 capacity is sized
 *   for the kinds of handle-counts a typical process holds; the
 *   plan's "10 000-handle stress test" verification is gated on
 *   raising this constant.
 *
 * THREADING
 *   Each table has its own `SpinLock`. Acquired around every
 *   `Insert / Lookup / Remove / Duplicate` so concurrent access
 *   from different ABI front-ends in the same process serialises
 *   safely. The lock does NOT cover the underlying `KObject`'s
 *   refcount — that uses `g_kobject_lock` from `kobject.cpp`.
 */

namespace duetos::ipc
{

using Handle = u32;
inline constexpr Handle kHandleInvalid = 0;

/// v0 capacity. Sized for the typical process's live handle count
/// (a Win32 GUI app rarely exceeds 30 simultaneous handles in
/// production). Bumping this is a one-line change; the plan's
/// "10 000 handles" stress is gated on a real workload demanding
/// it.
inline constexpr u32 kHandleTableCapacity = 64;

struct HandleSlot
{
    KObject* obj; ///< nullptr = free
};

struct HandleTable
{
    HandleSlot slots[kHandleTableCapacity];
    sync::SpinLock lock;
};

/// Insert `obj` into the table. The table takes ownership of the
/// caller's reference (no extra `KObjectAcquire` is performed) —
/// this matches the typical "create object, hand to handle table,
/// return handle to user" lifecycle.
///
/// Returns the assigned `Handle` (always >= 1), or
/// `Err{ErrorCode::OutOfMemory}` if the table is full.
::duetos::core::Result<Handle> HandleTableInsert(HandleTable& table, KObject* obj);

/// Look up `h` in the table. If `expected_type` is non-Invalid,
/// the slot's object's type must match. Returns:
///   - the `KObject*` on success (no refcount change — caller must
///     not hold the pointer past a possible `HandleTableRemove`).
///   - nullptr for any of: invalid handle, out-of-range handle,
///     empty slot, type mismatch.
KObject* HandleTableLookup(HandleTable& table, Handle h, KObjectType expected_type);

/// Remove `h` from the table. Calls `KObjectRelease` on the slot's
/// object (the table held a reference; it is dropping it). Returns
/// Ok on success, `Err{ErrorCode::InvalidArgument}` for bad
/// handles.
::duetos::core::Result<void> HandleTableRemove(HandleTable& table, Handle h);

/// Duplicate handle `h` from `src` into `dst`. Calls
/// `KObjectAcquire` to add a fresh reference for `dst`. Both
/// tables' locks are taken (canonical order: lower address first
/// to avoid deadlocks under pathological pairs). Same-table
/// duplication (`&src == &dst`) is allowed and takes the lock
/// once.
///
/// Returns the new `Handle` in `dst`, or
/// `Err{ErrorCode::InvalidArgument}` for bad source handle, or
/// `Err{ErrorCode::OutOfMemory}` if dst is full. On `Err` neither
/// table is modified.
::duetos::core::Result<Handle> HandleTableDuplicate(HandleTable& src, HandleTable& dst, Handle h);

/// Total live handle count. Linear scan; cheap.
u32 HandleTableLiveCount(HandleTable& table);

/// Drop every handle in the table. Used by process tear-down.
/// Calls `KObjectRelease` for every non-empty slot. Safe to call
/// on an already-empty table.
void HandleTableDrain(HandleTable& table);

/// Boot-time self-test. Allocates a synthetic table on the boot
/// stack (no scheduler dependency), exercises:
///   - Insert into free slot → handle != kHandleInvalid.
///   - Lookup with right + wrong type-tag.
///   - Duplicate (refcount goes to 2; both handles resolve).
///   - Remove on one handle (refcount back to 1; second handle
///     still resolves).
///   - Remove on second handle (refcount = 0; destroy fires).
///   - Fill the table to capacity, assert next Insert returns
///     OutOfMemory; Drain; assert all freed.
/// Panics on any mismatch.
void HandleTableSelfTest();

} // namespace duetos::ipc
