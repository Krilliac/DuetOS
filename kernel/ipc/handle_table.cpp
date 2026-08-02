/*
 * DuetOS - generation-safe per-process handle table, v2.
 *
 * See handle_table.h for the identity, ownership, and lock contract.
 */

#include "ipc/handle_table.h"

#include "log/klog.h"
#include "proc/process.h"
#include "sync/spinlock.h"
#include "util/debug_assert.h"
#include "util/nospec.h"
#include "util/result.h"
#include "util/types.h"

#if defined(DUETOS_HOST_TEST)
#include <atomic>
#if defined(_MSC_VER)
#include <intrin.h>
#endif
#endif

namespace duetos::ipc
{

namespace
{

// Last-issued reservation nonce. Zero is invalid and UINT64_MAX is issued
// once; exhaustion is then permanent. Reservations are short-lived, but the
// boot-global authority also prevents a ticket from one HandleTable lifetime
// being replayed against a later table that happens to reuse its storage.
constinit u64 g_last_handle_reservation_nonce = 0;

#if defined(DUETOS_HOST_TEST)
u64 AtomicLoadRelaxed(u64* value)
{
    return std::atomic_ref<u64>(*value).load(std::memory_order_relaxed);
}

bool AtomicCompareExchangeWeakRelaxed(u64* value, u64* expected, u64 desired)
{
    return std::atomic_ref<u64>(*value).compare_exchange_weak(*expected, desired, std::memory_order_relaxed,
                                                              std::memory_order_relaxed);
}
#else
u64 AtomicLoadRelaxed(u64* value)
{
    return __atomic_load_n(value, __ATOMIC_RELAXED);
}

bool AtomicCompareExchangeWeakRelaxed(u64* value, u64* expected, u64 desired)
{
    return __atomic_compare_exchange_n(value, expected, desired, true, __ATOMIC_RELAXED, __ATOMIC_RELAXED);
}
#endif

struct DecodedHandle
{
    u32 slot;
    u32 generation;
};

struct RetainedSnapshot
{
    KObject* obj;
    u64 rights;
};

bool DecodeHandleNospec(Handle handle, DecodedHandle* out)
{
    u32 slot = 0;
    u32 generation = 0;
    if (out == nullptr || !HandleDecode(handle, &slot, &generation))
        return false;

    const u32 masked_slot = util::MaskedIndex32(slot, kHandleTableCapacity);
    KASSERT_WITH_VALUE(masked_slot < kHandleTableCapacity, "ipc/handle_table", "masked slot oob",
                       static_cast<u64>(masked_slot));
    if (masked_slot != slot)
        return false;
    *out = {masked_slot, generation};
    return true;
}

bool SlotMatches(const HandleSlot& slot, u32 generation)
{
    return slot.state == HandleSlotState::Live && slot.obj != nullptr && slot.generation == generation &&
           slot.reservation_nonce == 0 && slot.reserved_type == KObjectType::Invalid;
}

HandleSlotState ClosedStateFor(const HandleSlot& slot)
{
    return slot.generation == kHandleGenerationMax ? HandleSlotState::Retired : HandleSlotState::Free;
}

u64 MintHandleReservationNonce()
{
    u64 observed = AtomicLoadRelaxed(&g_last_handle_reservation_nonce);
    for (;;)
    {
        if (observed == ~0ULL)
            return 0;
        const u64 desired = observed + 1;
        if (AtomicCompareExchangeWeakRelaxed(&g_last_handle_reservation_nonce, &observed, desired))
        {
            return desired;
        }
    }
}

bool ReservationMatches(const HandleSlot& slot, const DecodedHandle& decoded, HandleTableReservation reservation)
{
    return slot.state == HandleSlotState::Reserved && slot.obj == nullptr && slot.generation == decoded.generation &&
           slot.reservation_nonce == reservation.nonce && slot.reserved_type != KObjectType::Invalid &&
           slot.rights != 0;
}

::duetos::core::Result<RetainedSnapshot> RetainSnapshot(HandleTable& table, Handle handle, KObjectType expected_type,
                                                        u64 required_rights)
{
    DecodedHandle decoded{};
    if (!DecodeHandleNospec(handle, &decoded) || (required_rights & ~kHandleRightAll) != 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};

    KObject* obj = nullptr;
    u64 rights = 0;
    {
        sync::SpinLockGuard guard(table.lock);
        if (table.state != HandleTableState::Open)
            return ::duetos::core::Err{::duetos::core::ErrorCode::BadState};

        HandleSlot& slot = table.slots[decoded.slot];
        if (!SlotMatches(slot, decoded.generation))
            return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
        if (expected_type != KObjectType::Invalid && slot.obj->type != expected_type)
            return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
        if ((slot.rights & required_rights) != required_rights)
            return ::duetos::core::Err{::duetos::core::ErrorCode::PermissionDenied};
        if (slot.acquisition_pins == static_cast<u32>(-1) || table.active_operations == static_cast<u32>(-1))
            return ::duetos::core::Err{::duetos::core::ErrorCode::Overflow};

        obj = slot.obj;
        rights = slot.rights;
        ++slot.acquisition_pins;
        ++table.active_operations;
    }

    // The table-owned reference cannot be detached while this row pin
    // is present. Retain outside table.lock to avoid table -> KObject
    // lock nesting and to keep every external lifetime callback out.
    const bool retained = KObjectAcquire(obj);

    {
        sync::SpinLockGuard guard(table.lock);
        HandleSlot& slot = table.slots[decoded.slot];
        KASSERT(slot.obj == obj, "ipc/handle_table", "pinned slot object changed");
        KASSERT(slot.acquisition_pins > 0, "ipc/handle_table", "lookup pin underflow");
        KASSERT(table.active_operations > 0, "ipc/handle_table", "active operation underflow");
        --slot.acquisition_pins;
        --table.active_operations;
    }

    if (!retained)
        return ::duetos::core::Err{::duetos::core::ErrorCode::Overflow};
    return RetainedSnapshot{obj, rights};
}

void PauseWhileClosing()
{
#if defined(DUETOS_HOST_TEST) && defined(_MSC_VER)
    _mm_pause();
#else
    asm volatile("pause" ::: "memory");
#endif
}

} // namespace

u64 TypeAllowedRights(KObjectType type)
{
    constexpr u64 kCommon = kHandleRightDuplicate | kHandleRightTransfer | kHandleRightDestroy | kHandleRightInspect;
    constexpr u64 kEndpointCommon = kHandleRightDestroy | kHandleRightInspect;
    switch (type)
    {
    case KObjectType::Mutex:
    case KObjectType::Event:
    case KObjectType::Semaphore:
        return kCommon | kHandleRightWait | kHandleRightSignal;
    case KObjectType::Mailbox:
        return kCommon | kHandleRightRead | kHandleRightWrite | kHandleRightWait;
    case KObjectType::MessagePort:
        return kCommon | kHandleRightRead | kHandleRightWrite | kHandleRightWait;
    case KObjectType::ServiceEndpoint:
        // Endpoint identity and peer binding are fixed at activation. Generic
        // handle duplication or object transfer would create an ownership path
        // outside the ServiceDirectory publication/accept lifecycle.
        return kEndpointCommon | kHandleRightRead | kHandleRightWrite | kHandleRightWait;
    case KObjectType::Waitable:
        return kCommon | kHandleRightWait;
    case KObjectType::File:
        return kCommon | kHandleRightRead | kHandleRightWrite;
    case KObjectType::Iocp:
        return kCommon | kHandleRightRead | kHandleRightWrite | kHandleRightWait;
    case KObjectType::Test:
        return kHandleRightAll;
    case KObjectType::Invalid:
        return 0;
    }
    return 0;
}

u64 HandleRightsForProcess(KObjectType type, const ::duetos::core::CapSet& caps)
{
    if (type == KObjectType::Invalid)
        return 0;

    // Duplicate/Transfer are intrinsic handle-management authority for generic
    // objects until a dedicated process cap is introduced. ServiceEndpoint is
    // deliberately non-duplicable and non-transferable: its identity is minted
    // only by the authenticated publication/accept lifecycle. Destroy remains
    // available so CloseHandle can consume the exact accepted endpoint. Inspect
    // is privileged and therefore follows Debug, not an unconditional bit.
    u64 rights = kHandleRightDestroy;
    if (type != KObjectType::ServiceEndpoint)
        rights |= kHandleRightDuplicate | kHandleRightTransfer;
    if (::duetos::core::CapSetHas(caps, ::duetos::core::kCapDebug))
        rights |= kHandleRightInspect;

    switch (type)
    {
    case KObjectType::File:
        if (::duetos::core::CapSetHas(caps, ::duetos::core::kCapFsRead))
            rights |= kHandleRightRead;
        if (::duetos::core::CapSetHas(caps, ::duetos::core::kCapFsWrite))
            rights |= kHandleRightWrite;
        break;
    case KObjectType::Mutex:
    case KObjectType::Event:
    case KObjectType::Semaphore:
        rights |= kHandleRightWait;
        if (::duetos::core::CapSetHas(caps, ::duetos::core::kCapSpawnThread))
            rights |= kHandleRightSignal;
        break;
    case KObjectType::Mailbox:
        // Mailbox traffic is object-local IPC, not filesystem I/O.
        rights |= kHandleRightRead | kHandleRightWrite | kHandleRightWait;
        break;
    case KObjectType::MessagePort:
        // Send=Write, Receive=Read, and readiness=Wait. MessagePort traffic is
        // object-local IPC and never borrows filesystem or Signal authority.
        rights |= kHandleRightRead | kHandleRightWrite | kHandleRightWait;
        break;
    case KObjectType::ServiceEndpoint:
        // Endpoint protocol authority is bound separately at connection
        // creation. Generic handle rights only gate channel send/receive/wait.
        rights |= kHandleRightRead | kHandleRightWrite | kHandleRightWait;
        break;
    case KObjectType::Waitable:
        rights |= kHandleRightWait;
        break;
    case KObjectType::Iocp:
        rights |= kHandleRightRead | kHandleRightWait;
        if (::duetos::core::CapSetHas(caps, ::duetos::core::kCapSpawnThread))
            rights |= kHandleRightWrite;
        break;
    case KObjectType::Test:
        if (::duetos::core::CapSetHas(caps, ::duetos::core::kCapFsRead))
            rights |= kHandleRightRead;
        if (::duetos::core::CapSetHas(caps, ::duetos::core::kCapFsWrite))
            rights |= kHandleRightWrite;
        rights |= kHandleRightWait;
        if (::duetos::core::CapSetHas(caps, ::duetos::core::kCapSpawnThread))
            rights |= kHandleRightSignal;
        break;
    case KObjectType::Invalid:
        return 0;
    }
    return rights & TypeAllowedRights(type);
}

::duetos::core::Result<Handle> HandleTableInsert(HandleTable& table, KObject* obj, u64 requested_rights)
{
    if (obj == nullptr || obj->type == KObjectType::Invalid || requested_rights == 0 ||
        (requested_rights & ~kHandleRightAll) != 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    const u64 allowed = TypeAllowedRights(obj->type);
    if ((requested_rights & ~allowed) != 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::PermissionDenied};
    if (KObjectRefcount(obj) == 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::BadState};

    sync::SpinLockGuard guard(table.lock);
    if (table.state != HandleTableState::Open)
        return ::duetos::core::Err{::duetos::core::ErrorCode::BadState};
    if (table.next_free_hint >= kHandleTableCapacity)
        return ::duetos::core::Err{::duetos::core::ErrorCode::BadState};

    const u32 start = (table.next_free_hint + 1u) % kHandleTableCapacity;
    for (u32 step = 0; step < kHandleTableCapacity; ++step)
    {
        u32 index = start + step;
        if (index >= kHandleTableCapacity)
            index -= kHandleTableCapacity;
        if (index == 0)
            continue;

        HandleSlot& slot = table.slots[index];
        if (slot.state != HandleSlotState::Free)
            continue;
        KASSERT(slot.obj == nullptr && slot.rights == 0 && slot.reservation_nonce == 0 && slot.acquisition_pins == 0 &&
                    slot.reserved_type == KObjectType::Invalid,
                "ipc/handle_table", "free slot retained live metadata");
        if (slot.generation == kHandleGenerationMax)
        {
            slot.state = HandleSlotState::Retired;
            continue;
        }

        ++slot.generation;
        const Handle handle = HandleEncode(index, slot.generation);
        KASSERT(handle != kHandleInvalid, "ipc/handle_table", "failed to encode allocated slot");
        slot.obj = obj;
        slot.rights = requested_rights;
        slot.reservation_nonce = 0;
        slot.reserved_type = KObjectType::Invalid;
        slot.state = HandleSlotState::Live;
        table.next_free_hint = index;
        return handle;
    }
    return ::duetos::core::Err{::duetos::core::ErrorCode::OutOfMemory};
}

::duetos::core::Result<HandleTableReservation> HandleTableReserve(HandleTable& table, KObjectType object_type,
                                                                  u64 requested_rights)
{
    if (object_type == KObjectType::Invalid || requested_rights == 0 || (requested_rights & ~kHandleRightAll) != 0)
    {
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    }
    if ((requested_rights & ~TypeAllowedRights(object_type)) != 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::PermissionDenied};

    sync::SpinLockGuard guard(table.lock);
    if (table.state != HandleTableState::Open)
        return ::duetos::core::Err{::duetos::core::ErrorCode::BadState};
    if (table.next_free_hint >= kHandleTableCapacity)
        return ::duetos::core::Err{::duetos::core::ErrorCode::BadState};

    const u32 start = (table.next_free_hint + 1u) % kHandleTableCapacity;
    for (u32 step = 0; step < kHandleTableCapacity; ++step)
    {
        u32 index = start + step;
        if (index >= kHandleTableCapacity)
            index -= kHandleTableCapacity;
        if (index == 0)
            continue;

        HandleSlot& slot = table.slots[index];
        if (slot.state != HandleSlotState::Free)
            continue;
        KASSERT(slot.obj == nullptr && slot.rights == 0 && slot.reservation_nonce == 0 && slot.acquisition_pins == 0 &&
                    slot.reserved_type == KObjectType::Invalid,
                "ipc/handle_table", "free slot retained reservation metadata");
        if (slot.generation == kHandleGenerationMax)
        {
            slot.state = HandleSlotState::Retired;
            continue;
        }

        const u64 nonce = MintHandleReservationNonce();
        if (nonce == 0)
            return ::duetos::core::Err{::duetos::core::ErrorCode::Overflow};
        ++slot.generation;
        const Handle handle = HandleEncode(index, slot.generation);
        KASSERT(handle != kHandleInvalid, "ipc/handle_table", "failed to encode reserved slot");
        slot.rights = requested_rights;
        slot.reservation_nonce = nonce;
        slot.reserved_type = object_type;
        slot.state = HandleSlotState::Reserved;
        table.next_free_hint = index;
        return HandleTableReservation{handle, nonce};
    }
    return ::duetos::core::Err{::duetos::core::ErrorCode::OutOfMemory};
}

::duetos::core::Result<Handle> HandleTablePublish(HandleTable& table, HandleTableReservation reservation, KObject* obj)
{
    DecodedHandle decoded{};
    if (!HandleTableReservationIsValid(reservation) || !DecodeHandleNospec(reservation.handle, &decoded) ||
        obj == nullptr || obj->type == KObjectType::Invalid)
    {
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    }

    // Caller owns a stable reference until success. Keep the KObject lifetime
    // lock above the table lock and adopt only at the publication point.
    if (KObjectRefcount(obj) == 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::BadState};

    sync::SpinLockGuard guard(table.lock);
    if (table.state != HandleTableState::Open)
        return ::duetos::core::Err{::duetos::core::ErrorCode::BadState};
    HandleSlot& slot = table.slots[decoded.slot];
    if (!ReservationMatches(slot, decoded, reservation))
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    if (slot.reserved_type != obj->type)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    if ((slot.rights & ~TypeAllowedRights(obj->type)) != 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::PermissionDenied};

    slot.obj = obj;
    slot.reservation_nonce = 0;
    slot.reserved_type = KObjectType::Invalid;
    slot.state = HandleSlotState::Live;
    return reservation.handle;
}

::duetos::core::Result<void> HandleTableAbort(HandleTable& table, HandleTableReservation reservation)
{
    DecodedHandle decoded{};
    if (!HandleTableReservationIsValid(reservation) || !DecodeHandleNospec(reservation.handle, &decoded))
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};

    sync::SpinLockGuard guard(table.lock);
    if (table.state != HandleTableState::Open)
        return ::duetos::core::Err{::duetos::core::ErrorCode::BadState};
    HandleSlot& slot = table.slots[decoded.slot];
    if (!ReservationMatches(slot, decoded, reservation))
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};

    slot.rights = 0;
    slot.reservation_nonce = 0;
    slot.reserved_type = KObjectType::Invalid;
    slot.state = ClosedStateFor(slot);
    return {};
}

KObject* HandleTableLookupRef(HandleTable& table, Handle h, KObjectType expected_type, u64 required_rights)
{
    auto retained = RetainSnapshot(table, h, expected_type, required_rights);
    return retained.has_value() ? retained.value().obj : nullptr;
}

u64 HandleTableRights(HandleTable& table, Handle h)
{
    DecodedHandle decoded{};
    if (!DecodeHandleNospec(h, &decoded))
        return 0;
    sync::SpinLockGuard guard(table.lock);
    if (table.state != HandleTableState::Open)
        return 0;
    const HandleSlot& slot = table.slots[decoded.slot];
    return SlotMatches(slot, decoded.generation) ? slot.rights : 0;
}

bool HandleCheckRight(HandleTable& table, Handle h, u64 required_rights)
{
    if (required_rights == 0 || (required_rights & ~kHandleRightAll) != 0)
        return false;
    DecodedHandle decoded{};
    if (!DecodeHandleNospec(h, &decoded))
        return false;
    sync::SpinLockGuard guard(table.lock);
    if (table.state != HandleTableState::Open)
        return false;
    const HandleSlot& slot = table.slots[decoded.slot];
    return SlotMatches(slot, decoded.generation) && (slot.rights & required_rights) == required_rights;
}

::duetos::core::Result<KObject*> HandleTableDetach(HandleTable& table, Handle h, KObjectType expected_type,
                                                   u64 required_rights)
{
    DecodedHandle decoded{};
    if (!DecodeHandleNospec(h, &decoded) || (required_rights & ~kHandleRightAll) != 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};

    {
        sync::SpinLockGuard guard(table.lock);
        if (table.state != HandleTableState::Open)
            return ::duetos::core::Err{::duetos::core::ErrorCode::BadState};
        HandleSlot& slot = table.slots[decoded.slot];
        if (!SlotMatches(slot, decoded.generation))
            return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
        if (expected_type != KObjectType::Invalid && slot.obj->type != expected_type)
            return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
        if ((slot.rights & required_rights) != required_rights)
            return ::duetos::core::Err{::duetos::core::ErrorCode::PermissionDenied};
        if (table.active_operations == static_cast<u32>(-1))
            return ::duetos::core::Err{::duetos::core::ErrorCode::Overflow};

        // This is the close linearization point. Exact-token lookups
        // starting after it reject Closing even before the ref detaches.
        slot.state = HandleSlotState::Closing;
        ++table.active_operations;
    }

    for (;;)
    {
        KObject* detached = nullptr;
        {
            sync::SpinLockGuard guard(table.lock);
            HandleSlot& slot = table.slots[decoded.slot];
            KASSERT(slot.state == HandleSlotState::Closing && slot.generation == decoded.generation, "ipc/handle_table",
                    "closing slot identity changed");
            if (slot.acquisition_pins == 0)
            {
                detached = slot.obj;
                slot.obj = nullptr;
                slot.rights = 0;
                slot.reservation_nonce = 0;
                slot.reserved_type = KObjectType::Invalid;
                slot.state = ClosedStateFor(slot);
                KASSERT(table.active_operations > 0, "ipc/handle_table", "close active operation underflow");
                --table.active_operations;
            }
        }
        if (detached != nullptr)
            return detached;
        PauseWhileClosing();
    }
}

::duetos::core::Result<void> HandleTableRemove(HandleTable& table, Handle h)
{
    auto detached = HandleTableDetach(table, h, KObjectType::Invalid, 0);
    if (!detached.has_value())
        return ::duetos::core::Err{detached.error()};
    KObjectRelease(detached.value());
    return {};
}

::duetos::core::Result<Handle> HandleTableDuplicateRights(HandleTable& src, HandleTable& dst, Handle h,
                                                          u64 requested_rights)
{
    if (requested_rights == 0 || (requested_rights & ~kHandleRightAll) != 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};

    auto source = RetainSnapshot(src, h, KObjectType::Invalid, kHandleRightDuplicate);
    if (!source.has_value())
        return ::duetos::core::Err{source.error()};
    KObject* obj = source.value().obj;
    const u64 source_rights = source.value().rights;
    if ((requested_rights & ~source_rights) != 0)
    {
        KObjectRelease(obj);
        return ::duetos::core::Err{::duetos::core::ErrorCode::PermissionDenied};
    }

    auto inserted = HandleTableInsert(dst, obj, requested_rights);
    if (!inserted.has_value())
    {
        KObjectRelease(obj);
        return ::duetos::core::Err{inserted.error()};
    }
    return inserted;
}

::duetos::core::Result<Handle> HandleTableDuplicate(HandleTable& src, HandleTable& dst, Handle h)
{
    auto source = RetainSnapshot(src, h, KObjectType::Invalid, kHandleRightDuplicate);
    if (!source.has_value())
        return ::duetos::core::Err{source.error()};
    KObject* obj = source.value().obj;
    auto inserted = HandleTableInsert(dst, obj, source.value().rights);
    if (!inserted.has_value())
    {
        KObjectRelease(obj);
        return ::duetos::core::Err{inserted.error()};
    }
    return inserted;
}

::duetos::core::Result<Handle> HandleReplace(HandleTable& table, Handle src_handle, u64 requested_rights)
{
    DecodedHandle decoded{};
    if (!DecodeHandleNospec(src_handle, &decoded) || requested_rights == 0 ||
        (requested_rights & ~kHandleRightAll) != 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};

    sync::SpinLockGuard guard(table.lock);
    if (table.state != HandleTableState::Open)
        return ::duetos::core::Err{::duetos::core::ErrorCode::BadState};
    HandleSlot& slot = table.slots[decoded.slot];
    if (!SlotMatches(slot, decoded.generation))
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    if ((slot.rights & kHandleRightDuplicate) == 0 || (requested_rights & ~slot.rights) != 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::PermissionDenied};
    if (slot.generation == kHandleGenerationMax)
        return ::duetos::core::Err{::duetos::core::ErrorCode::Overflow};

    ++slot.generation;
    slot.rights = requested_rights;
    const Handle replacement = HandleEncode(decoded.slot, slot.generation);
    KASSERT(replacement != kHandleInvalid, "ipc/handle_table", "failed to encode replacement");
    return replacement;
}

::duetos::core::Result<HandleAdoptReplaceResult> HandleTableAdoptReplace(HandleTable& table, Handle existing,
                                                                         KObject* replacement, u64 requested_rights,
                                                                         KObjectType expected_type)
{
    DecodedHandle decoded{};
    if (!DecodeHandleNospec(existing, &decoded) || replacement == nullptr ||
        replacement->type == KObjectType::Invalid || requested_rights == 0 ||
        (requested_rights & ~kHandleRightAll) != 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    if (expected_type != KObjectType::Invalid && replacement->type != expected_type)
        return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
    if ((requested_rights & ~TypeAllowedRights(replacement->type)) != 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::PermissionDenied};

    // Diagnostic refcount validation deliberately precedes table.lock: the
    // replacement remains caller-owned on every failure leg, and KObject's
    // lifetime lock never nests below the handle-table lock.
    if (KObjectRefcount(replacement) == 0)
        return ::duetos::core::Err{::duetos::core::ErrorCode::BadState};

    {
        sync::SpinLockGuard guard(table.lock);
        if (table.state != HandleTableState::Open)
            return ::duetos::core::Err{::duetos::core::ErrorCode::BadState};
        HandleSlot& slot = table.slots[decoded.slot];
        if (!SlotMatches(slot, decoded.generation))
            return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
        if (expected_type != KObjectType::Invalid && slot.obj->type != expected_type)
            return ::duetos::core::Err{::duetos::core::ErrorCode::InvalidArgument};
        if (slot.generation == kHandleGenerationMax || table.active_operations == static_cast<u32>(-1))
            return ::duetos::core::Err{::duetos::core::ErrorCode::Overflow};

        // Replacement's linearization begins here. New exact-token lookups
        // reject Closing; already-pinned lookups finish before the object is
        // displaced, just as on HandleTableDetach.
        slot.state = HandleSlotState::Closing;
        ++table.active_operations;
    }

    for (;;)
    {
        KObject* displaced = nullptr;
        Handle replacement_handle = kHandleInvalid;
        {
            sync::SpinLockGuard guard(table.lock);
            HandleSlot& slot = table.slots[decoded.slot];
            KASSERT(slot.state == HandleSlotState::Closing && slot.generation == decoded.generation, "ipc/handle_table",
                    "adopt-replace slot identity changed");
            if (slot.acquisition_pins == 0)
            {
                displaced = slot.obj;
                ++slot.generation;
                replacement_handle = HandleEncode(decoded.slot, slot.generation);
                KASSERT(replacement_handle != kHandleInvalid, "ipc/handle_table",
                        "failed to encode adopted replacement");
                slot.obj = replacement;
                slot.rights = requested_rights;
                slot.state = HandleSlotState::Live;
                KASSERT(table.active_operations > 0, "ipc/handle_table", "adopt-replace operation underflow");
                --table.active_operations;
            }
        }
        if (displaced != nullptr)
            return HandleAdoptReplaceResult{replacement_handle, displaced};
        PauseWhileClosing();
    }
}

u32 HandleTableLiveCount(HandleTable& table)
{
    sync::SpinLockGuard guard(table.lock);
    u32 count = 0;
    for (u32 i = 1; i < kHandleTableCapacity; ++i)
        if (table.slots[i].state == HandleSlotState::Live)
            ++count;
    return count;
}

u32 HandleTableSnapshot(HandleTable& table, HandleSnapshotEntry* out, u32 capacity)
{
    sync::SpinLockGuard guard(table.lock);
    u32 total = 0;
    for (u32 i = 1; i < kHandleTableCapacity; ++i)
    {
        const HandleSlot& slot = table.slots[i];
        if (slot.state != HandleSlotState::Live || slot.obj == nullptr)
            continue;
        if (out != nullptr && total < capacity)
            out[total] = {HandleEncode(i, slot.generation), slot.obj->type, slot.rights};
        ++total;
    }
    return total;
}

void HandleTableDrain(HandleTable& table)
{
    bool owner = false;
    {
        sync::SpinLockGuard guard(table.lock);
        if (table.state == HandleTableState::Closed)
            return;
        if (table.state == HandleTableState::Open)
        {
            table.state = HandleTableState::Draining;
            owner = true;
        }
    }

    if (!owner)
    {
        // Another drainer owns the release snapshot. Wait until it has
        // completed so the containing Process may safely free the table.
        for (;;)
        {
            bool closed = false;
            {
                sync::SpinLockGuard guard(table.lock);
                closed = table.state == HandleTableState::Closed;
            }
            if (closed)
                return;
            PauseWhileClosing();
        }
    }

    // No new retained lookup/close can start after Draining is visible.
    // Existing operations are bounded to a checked retain or pin wait.
    for (;;)
    {
        bool quiescent = false;
        {
            sync::SpinLockGuard guard(table.lock);
            quiescent = table.active_operations == 0;
        }
        if (quiescent)
            break;
        PauseWhileClosing();
    }

    KObject* victims[kHandleTableCapacity]{};
    u32 victim_count = 0;
    {
        sync::SpinLockGuard guard(table.lock);
        KASSERT(table.state == HandleTableState::Draining, "ipc/handle_table", "drain owner lost table state");
        for (u32 i = 1; i < kHandleTableCapacity; ++i)
        {
            HandleSlot& slot = table.slots[i];
            KASSERT(slot.state != HandleSlotState::Closing && slot.acquisition_pins == 0, "ipc/handle_table",
                    "drain reached non-quiescent slot");
            if (slot.state == HandleSlotState::Reserved)
            {
                KASSERT(slot.obj == nullptr && slot.rights != 0 && slot.reservation_nonce != 0 &&
                            slot.reserved_type != KObjectType::Invalid,
                        "ipc/handle_table", "drain reached corrupt reserved slot");
                slot.rights = 0;
                slot.reservation_nonce = 0;
                slot.reserved_type = KObjectType::Invalid;
                slot.state = ClosedStateFor(slot);
                continue;
            }
            if (slot.state != HandleSlotState::Live)
                continue;
            KASSERT(slot.obj != nullptr && slot.reservation_nonce == 0 && slot.reserved_type == KObjectType::Invalid &&
                        victim_count < kHandleTableCapacity,
                    "ipc/handle_table", "drain live-slot invariant failed");
            victims[victim_count++] = slot.obj;
            slot.obj = nullptr;
            slot.rights = 0;
            slot.reservation_nonce = 0;
            slot.reserved_type = KObjectType::Invalid;
            slot.state = ClosedStateFor(slot);
        }
    }

    // Keep Draining visible until every detached table-owned reference has
    // completed its release callback. A second drainer is a completion
    // waiter, not merely a row-detachment waiter: returning while a destroy
    // callback is still running could let its caller tear down state that the
    // callback is entitled to use.
    for (u32 i = 0; i < victim_count; ++i)
        KObjectRelease(victims[i]);

    {
        sync::SpinLockGuard guard(table.lock);
        KASSERT(table.state == HandleTableState::Draining, "ipc/handle_table", "drain completion lost table state");
        table.state = HandleTableState::Closed;
    }
}

} // namespace duetos::ipc
