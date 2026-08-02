#pragma once

#include "ipc/kobject.h"
#include "sync/spinlock.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS - per-process kernel-object handle table, v2.
 *
 * Handles are opaque, generation-tagged, positive 31-bit values:
 *
 *     bits  0..11  slot (1..63 today)
 *     bits 12..30  non-zero generation
 *     bit      31  always zero
 *
 * A terminal-generation slot is retired on close rather than wrapped.
 * A stale token therefore cannot alias an object installed later in the
 * same row. The table remains fixed-capacity; dynamic paging is a later
 * extension that does not change this identity format.
 *
 * The table owns exactly one KObject reference per live slot. Insert
 * adopts the caller's reference on success and leaves it untouched on
 * failure. A publication reservation is an invisible, nonce-bound slot:
 * it owns no KObject reference and can only be published with the exact
 * reserved type and rights, or aborted. Retained lookup pins a row under
 * table.lock, performs the checked KObject retain after dropping table.lock,
 * then removes the pin.
 * Close invalidates the exact generation and waits for those short pins
 * before transferring the table-owned reference. No KObject retain,
 * release, or destroy callback runs while table.lock is held.
 */

namespace duetos::core
{
struct CapSet;
}

namespace duetos::ipc
{

using Handle = u32;
inline constexpr Handle kHandleInvalid = 0;

inline constexpr u32 kHandleSlotBits = 12;
inline constexpr Handle kHandleSlotMask = (1u << kHandleSlotBits) - 1u;
inline constexpr u32 kHandleGenerationBits = 19;
inline constexpr u32 kHandleGenerationMax = (1u << kHandleGenerationBits) - 1u;
inline constexpr Handle kHandlePositiveMax = 0x7FFFFFFFu;

/// Fixed capacity for v2. Slot zero is the invalid sentinel, so 63 rows
/// can be live. The 12-bit slot field intentionally leaves ABI room for
/// later paged tables without changing generation placement.
inline constexpr u32 kHandleTableCapacity = 64;
static_assert(kHandleTableCapacity <= kHandleSlotMask + 1u, "handle slot field too narrow");

inline constexpr Handle HandleEncode(u32 slot, u32 generation)
{
    return (slot > 0 && slot < kHandleTableCapacity && generation > 0 && generation <= kHandleGenerationMax)
               ? static_cast<Handle>((generation << kHandleSlotBits) | slot)
               : kHandleInvalid;
}

inline constexpr bool HandleDecode(Handle handle, u32* out_slot, u32* out_generation)
{
    if (handle == kHandleInvalid || handle > kHandlePositiveMax)
        return false;
    const u32 slot = handle & kHandleSlotMask;
    const u32 generation = handle >> kHandleSlotBits;
    if (slot == 0 || slot >= kHandleTableCapacity || generation == 0 || generation > kHandleGenerationMax)
        return false;
    if (out_slot != nullptr)
        *out_slot = slot;
    if (out_generation != nullptr)
        *out_generation = generation;
    return true;
}

inline constexpr u32 HandleSlotIndex(Handle handle)
{
    u32 slot = 0;
    return HandleDecode(handle, &slot, nullptr) ? slot : 0;
}

/// Preserve the generation while substituting a low-12-bit ABI type
/// band (0x200 for Mutex, 0x300 for Event, 0x500 for Semaphore, etc.).
inline constexpr bool HandleEncodeTagged(Handle handle, u32 tag_base, u64* out_value)
{
    u32 slot = 0;
    u32 generation = 0;
    if (out_value == nullptr || tag_base > kHandleSlotMask || tag_base + kHandleTableCapacity > 0x1000u ||
        !HandleDecode(handle, &slot, &generation))
        return false;
    *out_value = static_cast<u64>((generation << kHandleSlotBits) | (tag_base + slot));
    return true;
}

/// Decode a PE32-safe tagged handle. Values with upper bits, bit 31,
/// generation zero, slot zero, or a tag outside the requested band fail.
inline constexpr bool HandleDecodeTagged(u64 value, u32 tag_base, Handle* out_handle)
{
    if (out_handle == nullptr || value == 0 || value > kHandlePositiveMax || tag_base > kHandleSlotMask ||
        tag_base + kHandleTableCapacity > 0x1000u)
        return false;
    const u32 raw = static_cast<u32>(value);
    const u32 low_tag = raw & kHandleSlotMask;
    const u32 generation = raw >> kHandleSlotBits;
    if (low_tag <= tag_base || low_tag >= tag_base + kHandleTableCapacity || generation == 0)
        return false;
    const Handle decoded = HandleEncode(low_tag - tag_base, generation);
    if (decoded == kHandleInvalid)
        return false;
    *out_handle = decoded;
    return true;
}

// Per-handle rights. Numeric values are stable; append new rights.
inline constexpr u64 kHandleRightRead = 1ULL << 0;
inline constexpr u64 kHandleRightWrite = 1ULL << 1;
inline constexpr u64 kHandleRightDuplicate = 1ULL << 2;
inline constexpr u64 kHandleRightTransfer = 1ULL << 3;
inline constexpr u64 kHandleRightWait = 1ULL << 4;
inline constexpr u64 kHandleRightSignal = 1ULL << 5;
inline constexpr u64 kHandleRightDestroy = 1ULL << 6;
inline constexpr u64 kHandleRightInspect = 1ULL << 7;

inline constexpr u64 kHandleRightAll = kHandleRightRead | kHandleRightWrite | kHandleRightDuplicate |
                                       kHandleRightTransfer | kHandleRightWait | kHandleRightSignal |
                                       kHandleRightDestroy | kHandleRightInspect;

/// Rights meaningful for a concrete object type.
u64 TypeAllowedRights(KObjectType type);

/// Type-aware capability ceiling for a freshly-created handle. In
/// particular, File Read and Write map independently to kCapFsRead and
/// kCapFsWrite; filesystem policy never leaks onto mailbox Write.
u64 HandleRightsForProcess(KObjectType type, const ::duetos::core::CapSet& caps);

enum class HandleSlotState : u8
{
    Free = 0,
    Live = 1,
    Closing = 2,
    Retired = 3,
    Reserved = 4,
};

enum class HandleTableState : u8
{
    Open = 0,
    Draining,
    Closed,
};

struct HandleSlot
{
    KObject* obj;
    u64 rights;
    u64 reservation_nonce;
    u32 generation;
    u32 acquisition_pins;
    KObjectType reserved_type;
    HandleSlotState state;
};

struct HandleTable
{
    HandleSlot slots[kHandleTableCapacity];
    sync::SpinLock lock;
    u32 next_free_hint;
    u32 active_operations;
    HandleTableState state;
};

/// Install `obj` with explicit rights. Success adopts the caller's
/// existing reference; failure leaves ownership with the caller.
/// Zero or unsupported rights are rejected rather than publishing a
/// rightsless or silently-masked production handle.
::duetos::core::Result<Handle> HandleTableInsert(HandleTable& table, KObject* obj, u64 requested_rights);

/// Exact unpublished slot reservation for a multi-object transaction.
/// The returned handle is not visible to lookup, rights, live-count, or
/// snapshot APIs until Publish succeeds. A reservation owns no KObject
/// reference. Its boot-global nonce prevents replay across table reuse or
/// against another table with the same slot/generation shape.
struct HandleTableReservation
{
    Handle handle;
    u64 nonce;
};

inline constexpr HandleTableReservation kInvalidHandleTableReservation{kHandleInvalid, 0};

inline constexpr bool HandleTableReservationIsValid(HandleTableReservation reservation)
{
    return reservation.handle != kHandleInvalid && reservation.nonce != 0;
}

::duetos::core::Result<HandleTableReservation> HandleTableReserve(HandleTable& table, KObjectType object_type,
                                                                  u64 requested_rights);

/// Publish `obj` into one exact reservation. Success adopts the caller's
/// existing reference and consumes the reservation. Failure leaves caller
/// ownership unchanged; if the table is still open, the exact reservation
/// remains available for Abort.
::duetos::core::Result<Handle> HandleTablePublish(HandleTable& table, HandleTableReservation reservation, KObject* obj);

/// Abort one exact reservation. No KObject retain/release occurs. Replays,
/// cross-table tickets, published tickets, and stale generations fail closed.
::duetos::core::Result<void> HandleTableAbort(HandleTable& table, HandleTableReservation reservation);

/// Exact retained lookup. Generation, type, and required-rights checks
/// are one linearized operation. Returns nullptr on any validation or
/// checked-retain failure. Caller releases every non-null result.
KObject* HandleTableLookupRef(HandleTable& table, Handle h, KObjectType expected_type, u64 required_rights = 0);

/// Generation-safe metadata queries. Rights returns zero for an invalid,
/// stale, closing, or missing handle. CheckRight rejects a zero request.
u64 HandleTableRights(HandleTable& table, Handle h);
bool HandleCheckRight(HandleTable& table, Handle h, u64 required_rights);

/// Atomically invalidate an exact handle and transfer the table-owned
/// reference to the caller. The caller must release the returned object
/// after any type-specific close action.
::duetos::core::Result<KObject*> HandleTableDetach(HandleTable& table, Handle h, KObjectType expected_type,
                                                   u64 required_rights = 0);

/// Remove an exact handle and release its table-owned ref outside the
/// table lock. Teardown uses this rights-bypassing primitive; public
/// CloseHandle paths should use HandleTableDetach with Destroy required.
::duetos::core::Result<void> HandleTableRemove(HandleTable& table, Handle h);

/// Duplicate to `dst`, preserving or explicitly narrowing rights. The
/// source must carry Duplicate and a checked retain must succeed before
/// destination publication. No two table locks are held together.
::duetos::core::Result<Handle> HandleTableDuplicate(HandleTable& src, HandleTable& dst, Handle h);
::duetos::core::Result<Handle> HandleTableDuplicateRights(HandleTable& src, HandleTable& dst, Handle h,
                                                          u64 requested_rights);

/// In-place atomic rights replacement. The object/ref and slot stay put;
/// generation increments under one lock acquisition, invalidating the old
/// token without a duplicate-then-remove visibility window.
::duetos::core::Result<Handle> HandleReplace(HandleTable& table, Handle src_handle, u64 requested_rights);

struct HandleAdoptReplaceResult
{
    Handle handle;
    KObject* displaced;
};

/// Atomically replace the object owned by one exact live handle. The caller
/// supplies an already-owned `replacement` reference; success adopts it,
/// invalidates `existing`, and transfers the displaced table-owned reference
/// to the caller for release after all outer locks are gone. Failure leaves
/// both the table and caller ownership unchanged. No retain, release, or
/// destroy callback runs while `table.lock` is held.
::duetos::core::Result<HandleAdoptReplaceResult> HandleTableAdoptReplace(
    HandleTable& table, Handle existing, KObject* replacement, u64 requested_rights,
    KObjectType expected_type = KObjectType::Invalid);

u32 HandleTableLiveCount(HandleTable& table);

struct HandleSnapshotEntry
{
    Handle handle;
    KObjectType type;
    u64 rights;
};

/// Copy handle/type/rights metadata without exposing borrowed pointers.
/// Returns total live rows; writes at most `capacity` entries.
u32 HandleTableSnapshot(HandleTable& table, HandleSnapshotEntry* out, u32 capacity);

/// Terminal teardown. New operations fail once draining starts. All live
/// table-owned references are detached under the lock and released after
/// it. Safe and idempotent on an already-drained table.
void HandleTableDrain(HandleTable& table);

void HandleTableSelfTest();
void HandleRightsSelfTest();
void HandleTableContentionSelfTest();

} // namespace duetos::ipc
