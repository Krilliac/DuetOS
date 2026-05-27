#pragma once

#include "ipc/kobject.h"
#include "sync/spinlock.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — per-process kernel-object handle table, v0 (plan A3) +
 * per-handle rights (Fuchsia/Zircon model).
 *
 * WHAT
 *   A fixed-size array mapping `Handle` (u32) to `KObject*` plus a
 *   `u64 rights` bitmask. Native and Win32/NT and Linux ABI front-
 *   ends translate their own handle shapes to/from `Handle`; the
 *   kernel-internal name for an IPC object is its `KObject*` plus
 *   its `Handle` in the owning process's table.
 *
 * RIGHTS MODEL (ceiling vs floor)
 *   `Process::caps` (kCap*) is the CEILING — it gates whether the
 *   process can call the syscall family at all. Per-handle rights
 *   are the FLOOR — they can only NARROW from the ceiling. A handle
 *   can never grant a right the holding process's caps would not
 *   permit; `HandleDuplicate`/`HandleReplace` can produce a strictly
 *   reduced-rights variant but never an escalated one.
 *
 *   Default for a fresh handle: `kHandleRightAll`, masked by the
 *   kernel-object's `TypeAllowedRights` (KEvent has no Read/Write
 *   but does have Signal/Wait; KFile has Read/Write/Inspect but no
 *   Signal/Wait) AND by `ProcessCapsToHandleRights(proc->caps)` (a
 *   process without kCapFsWrite gets handles without Write).
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
 *   `Insert / Lookup / Remove / Duplicate / CheckRight` so concurrent
 *   access from different ABI front-ends in the same process
 *   serialises safely. The lock does NOT cover the underlying
 *   `KObject`'s refcount — that uses `g_kobject_lock` from
 *   `kobject.cpp`.
 */

namespace duetos::core
{
struct CapSet;
}

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

// ---------------------------------------------------------------
// Per-handle rights bitmask (Fuchsia/Zircon model).
//
// The rights enumeration mirrors the kernel's cap enumeration as
// much as possible so a "drop rights to read-only" call is
// intuitive. Each bit gates one class of operation on a handle:
//
//   kHandleRightRead    — read syscalls (fs read, ipc recv, evt query)
//   kHandleRightWrite   — write syscalls (fs write, ipc send, sem post)
//   kHandleRightDuplicate — caller may create a copy via HandleDuplicate
//   kHandleRightTransfer  — caller may pass the handle through IPC
//   kHandleRightWait    — caller may wait on the object (sync objects)
//   kHandleRightSignal  — caller may signal the object (events)
//   kHandleRightDestroy — caller may explicitly close (vs lifetime-managed)
//   kHandleRightInspect — caller may query state (size, type, name)
//
// New rights APPEND at the end. The numeric values are stable —
// once a rights bit is published it never moves.
// ---------------------------------------------------------------

inline constexpr u64 kHandleRightRead = 1ULL << 0;
inline constexpr u64 kHandleRightWrite = 1ULL << 1;
inline constexpr u64 kHandleRightDuplicate = 1ULL << 2;
inline constexpr u64 kHandleRightTransfer = 1ULL << 3;
inline constexpr u64 kHandleRightWait = 1ULL << 4;
inline constexpr u64 kHandleRightSignal = 1ULL << 5;
inline constexpr u64 kHandleRightDestroy = 1ULL << 6;
inline constexpr u64 kHandleRightInspect = 1ULL << 7;

/// Convenience: full rights mask. New handles get this, AND'd by
/// the kernel-object type's allowed set and by the process's caps.
inline constexpr u64 kHandleRightAll = kHandleRightRead | kHandleRightWrite | kHandleRightDuplicate |
                                       kHandleRightTransfer | kHandleRightWait | kHandleRightSignal |
                                       kHandleRightDestroy | kHandleRightInspect;

/// Return the subset of `kHandleRight*` meaningful for a given
/// kernel-object type. KEvent has no Read/Write but does have
/// Signal/Wait; KFile has Read/Write/Inspect but no Signal. KMutex
/// has Wait/Signal-equivalent (acquire/release) but no Read/Write.
/// Used at handle-creation time to mask the default-rights value
/// down to the operations the underlying type actually supports.
u64 TypeAllowedRights(KObjectType type);

/// Map a `Process::caps` bitmask to the subset of `kHandleRight*`
/// the process is permitted to GRANT on new handles. A process
/// without kCapFsWrite cannot mint handles carrying Write rights;
/// without kCapDebug it cannot mint handles carrying Inspect
/// rights. This is the policy layer that translates ambient
/// process-level authority into per-handle authority.
u64 ProcessCapsToHandleRights(const ::duetos::core::CapSet& caps);

struct HandleSlot
{
    KObject* obj; ///< nullptr = free
    u64 rights;   ///< per-handle rights mask (kHandleRight*)
};

struct HandleTable
{
    HandleSlot slots[kHandleTableCapacity];
    sync::SpinLock lock;
    /// Index to start the next insert scan from. The previous
    /// allocation lands at slots[next_free_hint]; the next insert
    /// starts looking at slots[next_free_hint + 1] and wraps. With
    /// a sparsely-populated table this skips the typically-busy
    /// prefix; with a full table behaviour is identical to a
    /// from-zero scan. Zero-init is correct (the unused slot 0 is
    /// reserved for kHandleInvalid, so wrap-skipping it is OK).
    u32 next_free_hint;
};

/// Insert `obj` into the table with the FULL default-rights mask
/// (kHandleRightAll & TypeAllowedRights(obj->type)). Process-caps
/// masking is the caller's responsibility — most syscall entry
/// sites already know their CurrentProcess and call the rights-
/// aware overload below. The table takes ownership of the caller's
/// reference (no extra `KObjectAcquire`).
///
/// Returns the assigned `Handle` (always >= 1), or
/// `Err{ErrorCode::OutOfMemory}` if the table is full.
::duetos::core::Result<Handle> HandleTableInsert(HandleTable& table, KObject* obj);

/// Insert with an explicit rights mask. The stored rights are
/// `requested_rights & TypeAllowedRights(obj->type)` — a caller can
/// only ever NARROW from the type-allowed ceiling. Use this overload
/// at syscall entry sites where the caller's `Process::caps` is
/// known and should further narrow the default. Common form:
///
///     HandleTableInsert(table, obj,
///         kHandleRightAll & ProcessCapsToHandleRights(proc->caps));
::duetos::core::Result<Handle> HandleTableInsert(HandleTable& table, KObject* obj, u64 requested_rights);

/// Look up `h` in the table. If `expected_type` is non-Invalid,
/// the slot's object's type must match. Returns:
///   - the `KObject*` on success (no refcount change — caller must
///     not hold the pointer past a possible `HandleTableRemove`).
///   - nullptr for any of: invalid handle, out-of-range handle,
///     empty slot, type mismatch.
KObject* HandleTableLookup(HandleTable& table, Handle h, KObjectType expected_type);

/// Lookup with an additional reference taken. The ref is acquired
/// under the table's lock so it cannot race with a concurrent
/// `HandleTableRemove`. Caller MUST pair the returned non-null
/// pointer with a `KObjectRelease` once done. Used by syscall
/// handlers that need the kernel object to stay alive across a
/// blocking primitive (Wait / Acquire) where the issuing process
/// could close the handle in parallel.
KObject* HandleTableLookupRef(HandleTable& table, Handle h, KObjectType expected_type);

/// Read the current rights mask of `h`. Returns 0 for any of:
/// invalid handle, out-of-range, empty slot. Cheap: one lookup +
/// one read under the table lock. Diagnostic / inspect use only.
u64 HandleTableRights(HandleTable& table, Handle h);

/// Per-handle rights check. Returns true iff:
///   - `h` exists in `table` (in-range, non-zero, non-empty slot),
///     AND
///   - every bit in `required_rights` is set in the slot's rights.
///
/// Use at every syscall that operates on a handle, AFTER the
/// kernel's process-level `CapCheck` (the ceiling) and BEFORE the
/// real work:
///
///     if (!HandleCheckRight(proc->kobj_handles, h, kHandleRightWrite))
///         return Err{ErrorCode::PermissionDenied};
///
/// Cheap: one lookup + one bitand. The kernel's process-level cap
/// check still runs upstream; this is the narrower per-handle gate.
bool HandleCheckRight(HandleTable& table, Handle h, u64 required_rights);

/// Remove `h` from the table. Calls `KObjectRelease` on the slot's
/// object (the table held a reference; it is dropping it). Returns
/// Ok on success, `Err{ErrorCode::InvalidArgument}` for bad
/// handles.
///
/// Note: Remove deliberately does NOT enforce
/// `kHandleRightDestroy` — process tear-down (`HandleTableDrain`)
/// must always be able to reclaim every handle regardless of
/// rights. Syscall front-ends that want to honour a missing
/// Destroy right should check it explicitly via
/// `HandleCheckRight` BEFORE calling Remove.
::duetos::core::Result<void> HandleTableRemove(HandleTable& table, Handle h);

/// Duplicate handle `h` from `src` into `dst`, preserving the
/// source handle's full rights mask. Calls `KObjectAcquire` to add
/// a fresh reference for `dst`.
::duetos::core::Result<Handle> HandleTableDuplicate(HandleTable& src, HandleTable& dst, Handle h);

/// Same as `HandleTableDuplicate` but with explicit rights
/// narrowing. The new handle's rights are
/// `src_rights & requested_rights`. Returns
/// `Err{ErrorCode::PermissionDenied}` if the source handle lacks
/// `kHandleRightDuplicate`, or if `requested_rights` would
/// ESCALATE (has bits not present in src's current rights).
::duetos::core::Result<Handle> HandleTableDuplicateRights(HandleTable& src, HandleTable& dst, Handle h,
                                                          u64 requested_rights);

/// Replace `src_handle` in `table` with a strictly-reduced-rights
/// variant. Equivalent to duplicate-then-close-src but atomic (no
/// window where both exist). On success the old handle id is
/// invalidated and the returned id is the new one. `requested_rights`
/// must be a subset of the source's current rights — any bit not
/// already present is treated as a request to ESCALATE and rejected.
/// Returns `Err{ErrorCode::PermissionDenied}` on attempted
/// escalation or missing `kHandleRightDuplicate`;
/// `Err{ErrorCode::InvalidArgument}` for bad source handle;
/// `Err{ErrorCode::OutOfMemory}` if the table is full (in which case
/// the source handle is preserved unchanged).
::duetos::core::Result<Handle> HandleReplace(HandleTable& table, Handle src_handle, u64 requested_rights);

/// Total live handle count. Linear scan; cheap.
u32 HandleTableLiveCount(HandleTable& table);

/// Drop every handle in the table. Used by process tear-down.
/// Calls `KObjectRelease` for every non-empty slot. Safe to call
/// on an already-empty table.
void HandleTableDrain(HandleTable& table);

/// Boot-time self-test for the base handle-table operations:
/// insert/lookup/duplicate/remove/drain. Panics on any mismatch.
void HandleTableSelfTest();

/// Boot-time self-test for the per-handle-rights extension.
/// Exercises: type-allowed masking at creation, caps-derived
/// narrowing, HandleDuplicate with reduced rights, refusal of
/// escalation attempts, refusal when source lacks Duplicate right,
/// HandleReplace atomicity, and HandleCheckRight gating. Panics on
/// any mismatch — the rights model is load-bearing for every
/// handle-mediated syscall and a regression here is a hard stop.
void HandleRightsSelfTest();

} // namespace duetos::ipc
