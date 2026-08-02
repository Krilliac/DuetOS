#pragma once

/*
 * Endpoint-owned, generation-safe KObject transfer table.
 *
 * This is a kernel-internal authority boundary, not a wire decoder.  A sender
 * may supply an opaque ObjectTransferRef and ask for a narrower rights set,
 * but type, rights, and immutable metadata always come from an already-live
 * row populated by trusted kernel code.  Hostile bytes can select or narrow
 * existing authority; they cannot manufacture it.
 *
 * Export is persistent rather than consuming.  It therefore requires the
 * source handle to carry Transfer, Duplicate, and every right in the granted
 * ceiling in one exact HandleTableLookupRef operation.  The row stores only
 * the granted ceiling: Duplicate is not implicitly propagated to an imported
 * handle.  Import may be repeated until exact-generation revoke or endpoint
 * close and may narrow beneath that ceiling.
 *
 * Every live row owns exactly one KObject reference. Import first reserves an
 * exact unpublished destination HandleTable row, then pins the transfer row,
 * drops the transfer lock, performs a checked retain, removes the pin, and
 * publishes only into that reservation. Every pre-publication failure aborts
 * the exact ticket; terminal destination drain safely owns its cleanup.
 * Revoke first marks the exact row Closing. If a short acquisition pin is
 * still live, Revoke returns Busy and a later owner-scheduled retry completes
 * the detach. Close uses the same nonblocking deferred-progress contract. No
 * retain, release, destroy callback, or HandleTable operation runs under the
 * transfer lock, and no two table locks are ever held together.
 *
 * The table is embedded in an endpoint but does not pin that outer object.
 * Every table operation after Initialize therefore requires an endpoint
 * operation pin (normally a retained endpoint KObject reference) that keeps
 * the table storage alive through return. Endpoint storage reclamation occurs
 * only after outer operation quiescence. Busy close/revoke retries also hold
 * such a pin.
 */

#include "ipc/handle_table.h"
#include "util/types.h"

#if !defined(DUETOS_HOST_TEST)
#include "sync/spinlock.h"
#endif

namespace duetos::ipc
{

using ObjectTransferRef = u32;
inline constexpr ObjectTransferRef kObjectTransferRefInvalid = 0;

inline constexpr u32 kObjectTransferSlotBits = 6;
inline constexpr ObjectTransferRef kObjectTransferSlotMask = (1u << kObjectTransferSlotBits) - 1u;
inline constexpr u32 kObjectTransferGenerationBits = 31 - kObjectTransferSlotBits;
inline constexpr u32 kObjectTransferGenerationMax = (1u << kObjectTransferGenerationBits) - 1u;
inline constexpr ObjectTransferRef kObjectTransferPositiveMax = 0x7FFFFFFFu;

// Slot zero is the invalid sentinel.  Keeping the table smaller than the
// encoded slot band bounds each endpoint to 31 simultaneously-live exports.
inline constexpr u32 kObjectTransferTableCapacity = 32;
static_assert(kObjectTransferTableCapacity <= kObjectTransferSlotMask + 1u, "object-transfer slot field is too narrow");

inline constexpr ObjectTransferRef ObjectTransferRefEncode(u32 slot, u32 generation)
{
    return (slot > 0 && slot < kObjectTransferTableCapacity && generation > 0 &&
            generation <= kObjectTransferGenerationMax)
               ? static_cast<ObjectTransferRef>((generation << kObjectTransferSlotBits) | slot)
               : kObjectTransferRefInvalid;
}

struct ObjectTransferDecodedRef
{
    u32 slot;
    u32 generation;
};

inline constexpr ObjectTransferDecodedRef kInvalidObjectTransferDecodedRef{0, 0};

inline constexpr bool ObjectTransferDecodedRefIsValid(ObjectTransferDecodedRef decoded)
{
    return decoded.slot > 0 && decoded.slot < kObjectTransferTableCapacity && decoded.generation > 0 &&
           decoded.generation <= kObjectTransferGenerationMax;
}

inline constexpr ObjectTransferDecodedRef ObjectTransferRefDecode(ObjectTransferRef reference)
{
    if (reference == kObjectTransferRefInvalid || reference > kObjectTransferPositiveMax)
        return kInvalidObjectTransferDecodedRef;
    const u32 slot = reference & kObjectTransferSlotMask;
    const u32 generation = reference >> kObjectTransferSlotBits;
    if (slot == 0 || slot >= kObjectTransferTableCapacity || generation == 0 ||
        generation > kObjectTransferGenerationMax)
    {
        return kInvalidObjectTransferDecodedRef;
    }
    return ObjectTransferDecodedRef{slot, generation};
}

inline constexpr u32 kObjectTransferMetadataSealed = 1u << 0;
inline constexpr u32 kObjectTransferMetadataKnownFlags = kObjectTransferMetadataSealed;

// Trusted, immutable facts bound to the retained object by the exporting
// kernel subsystem.  `identity` is a non-zero endpoint-local stable identity;
// `content_hash` is the complete-object digest used by higher-level protocols.
// This structure must never be populated directly from an IPC payload.
struct ObjectTransferImmutableMetadata
{
    u64 identity;
    u64 object_size;
    u8 content_hash[32];
    u32 flags;
    u32 reserved;
};

// Exact authority installed by trusted kernel code.  `type` must be concrete;
// `rights` is the maximum rights set importers may request.
struct ObjectTransferAuthority
{
    KObjectType type;
    u64 rights;
    ObjectTransferImmutableMetadata metadata;
};

enum class ObjectTransferStatus : u8
{
    Ok = 0,
    InvalidArgument,
    NotInitialized,
    AlreadyInitialized,
    Closed,
    Full,
    IdentityExhausted,
    SourceRejected,
    InvalidReference,
    StaleReference,
    ReferenceReplayed,
    RightsDenied,
    TypeMismatch,
    RetainFailed,
    DestinationRejected,
    OperationOverflow,
    Busy,
    CorruptState,
};

struct ObjectTransferExportResult
{
    ObjectTransferStatus status;
    ObjectTransferRef reference;
};

struct ObjectTransferImportResult
{
    ObjectTransferStatus status;
    core::ErrorCode destination_error;
    Handle handle;
    ObjectTransferAuthority authority;
};

enum class ObjectTransferSlotState : u8
{
    Free = 0,
    Live,
    Closing,
    Retired,
};

enum class ObjectTransferTableState : u8
{
    Uninitialized = 0,
    Open,
    Draining,
    Closed,
};

#if defined(DUETOS_HOST_TEST)
struct ObjectTransferHostLock
{
    u32 next_ticket;
    u32 now_serving;
};
#endif

// Public only for allocation-free endpoint embedding. Treat all fields as
// opaque after initialization. The outer retained endpoint operation, not
// active_operations, protects the lifetime of this storage.
struct ObjectTransferSlot
{
    KObject* object;
    ObjectTransferImmutableMetadata metadata;
    u64 rights;
    u32 generation;
    u32 acquisition_pins;
    KObjectType type;
    ObjectTransferSlotState state;
};

struct ObjectTransferTable
{
#if defined(DUETOS_HOST_TEST)
    ObjectTransferHostLock lock;
#else
    sync::SpinLock lock;
#endif
    ObjectTransferSlot slots[kObjectTransferTableCapacity];
    u32 next_free_hint;
    u32 active_operations;
    u32 initialized;
    ObjectTransferTableState state;
};

// [unpublished, never-before-initialized endpoint]
// One-shot construction accepts only canonical zero-initialized storage. It
// never resets Open/Draining/Closed state or reuses a prior generation domain.
// `first_generation` is exposed only for deterministic terminal-generation
// tests. Production callers use the default. Failure leaves the table intact.
ObjectTransferStatus ObjectTransferTableInitialize(ObjectTransferTable* table, u32 first_generation = 1);

// [trusted kernel caller holding one outer endpoint operation pin]
// On success adopts the single checked reference returned by the exact source
// lookup.  Failure retains no reference.  `authority.metadata` must be derived
// from trusted immutable object state, never from sender-controlled bytes.
ObjectTransferExportResult ObjectTransferExport(ObjectTransferTable* table, HandleTable* source, Handle source_handle,
                                                const ObjectTransferAuthority& authority);

// [endpoint receive path holding one outer endpoint operation pin]
// The reference and requested narrowing may originate in hostile bytes. The
// concrete expected type is a trusted call-site decision. Destination capacity
// is reserved before the transfer row is pinned; success publishes exactly
// that reservation and returns its handle plus table-derived authority.
ObjectTransferImportResult ObjectTransferImport(ObjectTransferTable* table, ObjectTransferRef reference,
                                                HandleTable* destination, KObjectType expected_type,
                                                u64 requested_rights);

// [caller holds one outer endpoint operation pin]
// Close exactly one generation. Once Closing is visible, no new import can pin
// the row. Busy means a pre-existing pin still owns progress; schedule a later
// retry. Ok detaches and releases the row-owned reference outside the lock.
ObjectTransferStatus ObjectTransferRevoke(ObjectTransferTable* table, ObjectTransferRef reference);

// [caller holds one outer endpoint operation pin; endpoint storage is not freed
// until all such pins quiesce]
// Terminal endpoint teardown. The first call publishes Draining. Busy means an
// earlier import still owns a short pin; schedule a later retry. Any retry may
// finish the detach, publish Closed, and release its private ref list outside
// the lock. Concurrent and destructor-reentrant calls never wait. New export,
// import, and revoke operations fail once Draining begins.
ObjectTransferStatus ObjectTransferTableClose(ObjectTransferTable* table);

u32 ObjectTransferLiveCount(ObjectTransferTable* table);
const char* ObjectTransferStatusName(ObjectTransferStatus status);

} // namespace duetos::ipc
