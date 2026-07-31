#include "ipc/object_transfer.h"

#include "util/nospec.h"

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

struct DecodedTransferRef
{
    u32 slot;
    u32 generation;
};

#if defined(DUETOS_HOST_TEST)
u32 AtomicFetchAdd(u32* value, u32 increment)
{
    return std::atomic_ref<u32>(*value).fetch_add(increment, std::memory_order_acquire);
}

u32 AtomicLoadAcquire(u32* value)
{
    return std::atomic_ref<u32>(*value).load(std::memory_order_acquire);
}

void AtomicStoreRelease(u32* value, u32 next)
{
    std::atomic_ref<u32>(*value).store(next, std::memory_order_release);
}
#endif

void CpuRelax()
{
#if defined(DUETOS_HOST_TEST) && defined(_MSC_VER)
    _mm_pause();
#elif defined(DUETOS_HOST_TEST)
    __builtin_ia32_pause();
#else
    asm volatile("pause" ::: "memory");
#endif
}

class TransferGuard
{
  public:
#if defined(DUETOS_HOST_TEST)
    explicit TransferGuard(ObjectTransferTable& table)
        : m_table(table), m_ticket(AtomicFetchAdd(&table.lock.next_ticket, 1))
    {
        while (AtomicLoadAcquire(&table.lock.now_serving) != m_ticket)
            CpuRelax();
    }

    ~TransferGuard() { AtomicStoreRelease(&m_table.lock.now_serving, m_ticket + 1u); }
#else
    explicit TransferGuard(ObjectTransferTable& table) : m_guard(table.lock) {}
    ~TransferGuard() = default;
#endif

    TransferGuard(const TransferGuard&) = delete;
    TransferGuard& operator=(const TransferGuard&) = delete;
    TransferGuard(TransferGuard&&) = delete;
    TransferGuard& operator=(TransferGuard&&) = delete;

  private:
#if defined(DUETOS_HOST_TEST)
    ObjectTransferTable& m_table;
    u32 m_ticket;
#else
    sync::SpinLockGuard m_guard;
#endif
};

bool DecodeTransferRefNospec(ObjectTransferRef reference, DecodedTransferRef* out)
{
    u32 slot = 0;
    u32 generation = 0;
    if (out == nullptr || !ObjectTransferRefDecode(reference, &slot, &generation))
        return false;
    const u32 masked_slot = util::MaskedIndex32(slot, kObjectTransferTableCapacity);
    if (masked_slot != slot)
        return false;
    *out = DecodedTransferRef{masked_slot, generation};
    return true;
}

bool MetadataValid(const ObjectTransferImmutableMetadata& metadata)
{
    return metadata.identity != 0 && (metadata.flags & ~kObjectTransferMetadataKnownFlags) == 0 &&
           (metadata.flags & kObjectTransferMetadataSealed) != 0 && metadata.reserved == 0;
}

bool AuthorityValid(const ObjectTransferAuthority& authority)
{
    if (authority.type == KObjectType::Invalid || authority.rights == 0 ||
        (authority.rights & ~kHandleRightAll) != 0)
    {
        return false;
    }
    return (authority.rights & ~TypeAllowedRights(authority.type)) == 0 && MetadataValid(authority.metadata);
}

bool RequestedRightsValid(KObjectType expected_type, u64 requested_rights)
{
    return expected_type != KObjectType::Invalid && requested_rights != 0 &&
           (requested_rights & ~kHandleRightAll) == 0 &&
           (requested_rights & ~TypeAllowedRights(expected_type)) == 0;
}

bool SlotMatches(const ObjectTransferSlot& slot, u32 generation)
{
    return slot.state == ObjectTransferSlotState::Live && slot.object != nullptr && slot.generation == generation;
}

ObjectTransferStatus ReferenceFailure(const ObjectTransferSlot& slot, u32 generation)
{
    if (slot.generation != 0 && generation <= slot.generation)
        return ObjectTransferStatus::ReferenceReplayed;
    return ObjectTransferStatus::StaleReference;
}

ObjectTransferSlotState ClosedStateFor(const ObjectTransferSlot& slot)
{
    return slot.generation == kObjectTransferGenerationMax ? ObjectTransferSlotState::Retired
                                                            : ObjectTransferSlotState::Free;
}

void ClearMetadata(ObjectTransferImmutableMetadata* metadata)
{
    *metadata = ObjectTransferImmutableMetadata{};
}

void ClearSlot(ObjectTransferSlot* slot)
{
    slot->object = nullptr;
    ClearMetadata(&slot->metadata);
    slot->rights = 0;
    slot->acquisition_pins = 0;
    slot->type = KObjectType::Invalid;
    slot->state = ClosedStateFor(*slot);
}

ObjectTransferAuthority EmptyAuthority()
{
    return ObjectTransferAuthority{KObjectType::Invalid, 0, ObjectTransferImmutableMetadata{}};
}

ObjectTransferExportResult ExportFailure(ObjectTransferStatus status)
{
    return ObjectTransferExportResult{status, kObjectTransferRefInvalid};
}

ObjectTransferImportResult ImportFailure(ObjectTransferStatus status,
                                         core::ErrorCode destination_error = core::ErrorCode::Ok)
{
    return ObjectTransferImportResult{status, destination_error, kHandleInvalid, EmptyAuthority()};
}

ObjectTransferStatus StateFailure(ObjectTransferTableState state)
{
    switch (state)
    {
    case ObjectTransferTableState::Uninitialized:
        return ObjectTransferStatus::NotInitialized;
    case ObjectTransferTableState::Draining:
    case ObjectTransferTableState::Closed:
        return ObjectTransferStatus::Closed;
    case ObjectTransferTableState::Open:
        return ObjectTransferStatus::CorruptState;
    }
    return ObjectTransferStatus::CorruptState;
}

} // namespace

ObjectTransferStatus ObjectTransferTableInitialize(ObjectTransferTable* table, u32 first_generation)
{
    if (table == nullptr || first_generation == 0 || first_generation > kObjectTransferGenerationMax)
        return ObjectTransferStatus::InvalidArgument;

#if defined(DUETOS_HOST_TEST)
    table->lock.next_ticket = 0;
    table->lock.now_serving = 0;
#else
    table->lock.next_ticket = 0;
    table->lock.now_serving = 0;
    table->lock.owner_cpu = 0xFFFFFFFFu;
    table->lock.class_id = sync::kLockClassUnclassified;
#endif

    for (u32 index = 0; index < kObjectTransferTableCapacity; ++index)
    {
        ObjectTransferSlot& slot = table->slots[index];
        slot.object = nullptr;
        slot.metadata = ObjectTransferImmutableMetadata{};
        slot.rights = 0;
        slot.generation = first_generation - 1u;
        slot.acquisition_pins = 0;
        slot.type = KObjectType::Invalid;
        slot.state = index == 0 ? ObjectTransferSlotState::Retired : ObjectTransferSlotState::Free;
    }
    table->next_free_hint = 0;
    table->active_operations = 0;
    table->state = ObjectTransferTableState::Open;
    table->initialized = 1;
    return ObjectTransferStatus::Ok;
}

ObjectTransferExportResult ObjectTransferExport(ObjectTransferTable* table, HandleTable* source, Handle source_handle,
                                                const ObjectTransferAuthority& authority)
{
    if (table == nullptr || source == nullptr || source_handle == kHandleInvalid)
        return ExportFailure(ObjectTransferStatus::InvalidArgument);
    if (table->initialized != 1)
        return ExportFailure(ObjectTransferStatus::NotInitialized);

    // Snapshot all trusted authority before the source lookup can block.  The
    // caller must keep the source structure data-race-free for this value copy.
    const ObjectTransferAuthority authority_snapshot = authority;
    if (!AuthorityValid(authority_snapshot))
        return ExportFailure(ObjectTransferStatus::InvalidArgument);

    const u64 required_source_rights =
        kHandleRightTransfer | kHandleRightDuplicate | authority_snapshot.rights;
    KObject* retained =
        HandleTableLookupRef(*source, source_handle, authority_snapshot.type, required_source_rights);
    if (retained == nullptr)
        return ExportFailure(ObjectTransferStatus::SourceRejected);

    ObjectTransferStatus status = ObjectTransferStatus::Full;
    ObjectTransferRef reference = kObjectTransferRefInvalid;
    {
        TransferGuard guard(*table);
        if (table->state != ObjectTransferTableState::Open)
        {
            status = StateFailure(table->state);
        }
        else
        {
            bool future_capacity = false;
            const u32 start = (table->next_free_hint + 1u) % kObjectTransferTableCapacity;
            for (u32 step = 0; step < kObjectTransferTableCapacity; ++step)
            {
                u32 index = start + step;
                if (index >= kObjectTransferTableCapacity)
                    index -= kObjectTransferTableCapacity;
                if (index == 0)
                    continue;

                ObjectTransferSlot& slot = table->slots[index];
                if (slot.state == ObjectTransferSlotState::Retired)
                    continue;
                if (slot.state == ObjectTransferSlotState::Free &&
                    slot.generation == kObjectTransferGenerationMax)
                {
                    slot.state = ObjectTransferSlotState::Retired;
                    continue;
                }
                future_capacity = true;
                if (slot.state != ObjectTransferSlotState::Free)
                    continue;
                if (slot.object != nullptr || slot.rights != 0 || slot.acquisition_pins != 0 ||
                    slot.type != KObjectType::Invalid)
                {
                    status = ObjectTransferStatus::CorruptState;
                    break;
                }
                ++slot.generation;
                reference = ObjectTransferRefEncode(index, slot.generation);
                if (reference == kObjectTransferRefInvalid)
                {
                    status = ObjectTransferStatus::CorruptState;
                    break;
                }
                slot.object = retained;
                slot.metadata = authority_snapshot.metadata;
                slot.rights = authority_snapshot.rights;
                slot.type = authority_snapshot.type;
                slot.state = ObjectTransferSlotState::Live;
                table->next_free_hint = index;
                retained = nullptr; // The row adopts exactly this reference.
                status = ObjectTransferStatus::Ok;
                break;
            }
            if (status == ObjectTransferStatus::Full && !future_capacity)
                status = ObjectTransferStatus::IdentityExhausted;
        }
    }

    if (retained != nullptr)
        KObjectRelease(retained);
    return status == ObjectTransferStatus::Ok ? ObjectTransferExportResult{status, reference} : ExportFailure(status);
}

ObjectTransferImportResult ObjectTransferImport(ObjectTransferTable* table, ObjectTransferRef reference,
                                                HandleTable* destination, KObjectType expected_type,
                                                u64 requested_rights)
{
    if (table == nullptr || destination == nullptr || !RequestedRightsValid(expected_type, requested_rights))
        return ImportFailure(ObjectTransferStatus::InvalidArgument);
    if (table->initialized != 1)
        return ImportFailure(ObjectTransferStatus::NotInitialized);

    DecodedTransferRef decoded{};
    if (!DecodeTransferRefNospec(reference, &decoded))
        return ImportFailure(ObjectTransferStatus::InvalidReference);

    KObject* object = nullptr;
    ObjectTransferImmutableMetadata metadata{};
    {
        TransferGuard guard(*table);
        if (table->state != ObjectTransferTableState::Open)
            return ImportFailure(StateFailure(table->state));

        ObjectTransferSlot& slot = table->slots[decoded.slot];
        if (!SlotMatches(slot, decoded.generation))
        {
            if (slot.state == ObjectTransferSlotState::Closing && slot.generation == decoded.generation)
                return ImportFailure(ObjectTransferStatus::Busy);
            return ImportFailure(ReferenceFailure(slot, decoded.generation));
        }
        if (slot.type != expected_type || slot.object->type != expected_type)
            return ImportFailure(ObjectTransferStatus::TypeMismatch);
        if ((requested_rights & ~slot.rights) != 0)
            return ImportFailure(ObjectTransferStatus::RightsDenied);
        if (slot.acquisition_pins == static_cast<u32>(-1) ||
            table->active_operations == static_cast<u32>(-1))
        {
            return ImportFailure(ObjectTransferStatus::OperationOverflow);
        }

        // This pin is the import linearization point.  Revoke can mark the row
        // Closing after it, but cannot release the row-owned ref until unpin.
        ++slot.acquisition_pins;
        ++table->active_operations;
        object = slot.object;
        metadata = slot.metadata;
    }

    const bool retained = KObjectAcquire(object);
    bool identity_intact = false;
    {
        TransferGuard guard(*table);
        ObjectTransferSlot& slot = table->slots[decoded.slot];
        identity_intact = slot.generation == decoded.generation && slot.object == object &&
                          (slot.state == ObjectTransferSlotState::Live ||
                           slot.state == ObjectTransferSlotState::Closing) &&
                          slot.acquisition_pins > 0 && table->active_operations > 0;
        if (slot.acquisition_pins > 0)
            --slot.acquisition_pins;
        if (table->active_operations > 0)
            --table->active_operations;
    }

    if (!identity_intact)
    {
        if (retained)
            KObjectRelease(object);
        return ImportFailure(ObjectTransferStatus::CorruptState);
    }
    if (!retained)
        return ImportFailure(ObjectTransferStatus::RetainFailed);

    // The checked retained ref now makes `object` independent of the transfer
    // row.  Destination insertion happens after unpin and with no transfer lock.
    auto inserted = HandleTableInsert(*destination, object, requested_rights);
    if (!inserted.has_value())
    {
        const core::ErrorCode error = inserted.error();
        KObjectRelease(object);
        return ImportFailure(ObjectTransferStatus::DestinationRejected, error);
    }

    return ObjectTransferImportResult{ObjectTransferStatus::Ok,
                                      core::ErrorCode::Ok,
                                      inserted.value(),
                                      ObjectTransferAuthority{expected_type, requested_rights, metadata}};
}

ObjectTransferStatus ObjectTransferRevoke(ObjectTransferTable* table, ObjectTransferRef reference)
{
    if (table == nullptr)
        return ObjectTransferStatus::InvalidArgument;
    if (table->initialized != 1)
        return ObjectTransferStatus::NotInitialized;
    DecodedTransferRef decoded{};
    if (!DecodeTransferRefNospec(reference, &decoded))
        return ObjectTransferStatus::InvalidReference;

    {
        TransferGuard guard(*table);
        if (table->state != ObjectTransferTableState::Open)
            return StateFailure(table->state);
        ObjectTransferSlot& slot = table->slots[decoded.slot];
        if (!SlotMatches(slot, decoded.generation))
        {
            if (slot.state == ObjectTransferSlotState::Closing && slot.generation == decoded.generation)
                return ObjectTransferStatus::Busy;
            return ReferenceFailure(slot, decoded.generation);
        }
        if (table->active_operations == static_cast<u32>(-1))
            return ObjectTransferStatus::OperationOverflow;
        slot.state = ObjectTransferSlotState::Closing;
        ++table->active_operations;
    }

    for (;;)
    {
        KObject* detached = nullptr;
        bool corrupt = false;
        {
            TransferGuard guard(*table);
            ObjectTransferSlot& slot = table->slots[decoded.slot];
            if (slot.state != ObjectTransferSlotState::Closing || slot.generation != decoded.generation ||
                slot.object == nullptr || table->active_operations == 0)
            {
                corrupt = true;
                if (table->active_operations > 0)
                    --table->active_operations;
            }
            else if (slot.acquisition_pins == 0)
            {
                detached = slot.object;
                ClearSlot(&slot);
                --table->active_operations;
            }
        }
        if (corrupt)
            return ObjectTransferStatus::CorruptState;
        if (detached != nullptr)
        {
            KObjectRelease(detached);
            return ObjectTransferStatus::Ok;
        }
        CpuRelax();
    }
}

ObjectTransferStatus ObjectTransferTableClose(ObjectTransferTable* table)
{
    if (table == nullptr)
        return ObjectTransferStatus::InvalidArgument;
    if (table->initialized != 1)
        return ObjectTransferStatus::NotInitialized;

    bool owns_close = false;
    {
        TransferGuard guard(*table);
        if (table->state == ObjectTransferTableState::Uninitialized)
            return ObjectTransferStatus::NotInitialized;
        if (table->state == ObjectTransferTableState::Closed)
            return ObjectTransferStatus::Ok;
        if (table->state == ObjectTransferTableState::Open)
        {
            table->state = ObjectTransferTableState::Draining;
            owns_close = true;
            for (u32 index = 1; index < kObjectTransferTableCapacity; ++index)
            {
                ObjectTransferSlot& slot = table->slots[index];
                if (slot.state == ObjectTransferSlotState::Live)
                    slot.state = ObjectTransferSlotState::Closing;
            }
        }
        else if (table->state != ObjectTransferTableState::Draining)
        {
            return ObjectTransferStatus::CorruptState;
        }
    }

    if (!owns_close)
    {
        for (;;)
        {
            {
                TransferGuard guard(*table);
                if (table->state == ObjectTransferTableState::Closed)
                    return ObjectTransferStatus::Ok;
                if (table->state != ObjectTransferTableState::Draining)
                    return ObjectTransferStatus::CorruptState;
            }
            CpuRelax();
        }
    }

    for (;;)
    {
        KObject* detached[kObjectTransferTableCapacity - 1]{};
        u32 detached_count = 0;
        ObjectTransferStatus result = ObjectTransferStatus::Ok;
        bool completed = false;
        {
            TransferGuard guard(*table);
            if (table->state != ObjectTransferTableState::Draining)
                return ObjectTransferStatus::CorruptState;
            if (table->active_operations == 0)
            {
                for (u32 index = 1; index < kObjectTransferTableCapacity; ++index)
                {
                    if (table->slots[index].acquisition_pins != 0)
                        return ObjectTransferStatus::CorruptState;
                }
                for (u32 index = 1; index < kObjectTransferTableCapacity; ++index)
                {
                    ObjectTransferSlot& slot = table->slots[index];
                    if (slot.object != nullptr)
                    {
                        detached[detached_count++] = slot.object;
                        if (slot.state != ObjectTransferSlotState::Closing)
                            result = ObjectTransferStatus::CorruptState;
                        ClearSlot(&slot);
                    }
                    else if (slot.state == ObjectTransferSlotState::Closing ||
                             slot.state == ObjectTransferSlotState::Live)
                    {
                        result = ObjectTransferStatus::CorruptState;
                        ClearSlot(&slot);
                    }
                }
                // This is the terminal close linearization point.  Publishing
                // Closed before external releases makes destructor re-entry
                // idempotent instead of waiting on its own caller.  Everything
                // below owns only the local detached list and never touches
                // `table` again.
                table->state = ObjectTransferTableState::Closed;
                completed = true;
            }
        }

        if (completed)
        {
            for (u32 index = 0; index < detached_count; ++index)
                KObjectRelease(detached[index]);
            return result;
        }
        CpuRelax();
    }
}

u32 ObjectTransferLiveCount(ObjectTransferTable* table)
{
    if (table == nullptr)
        return 0;
    if (table->initialized != 1)
        return 0;
    TransferGuard guard(*table);
    if (table->state == ObjectTransferTableState::Uninitialized)
        return 0;
    u32 count = 0;
    for (u32 index = 1; index < kObjectTransferTableCapacity; ++index)
    {
        if (table->slots[index].state == ObjectTransferSlotState::Live)
            ++count;
    }
    return count;
}

const char* ObjectTransferStatusName(ObjectTransferStatus status)
{
    switch (status)
    {
    case ObjectTransferStatus::Ok:
        return "ok";
    case ObjectTransferStatus::InvalidArgument:
        return "invalid-argument";
    case ObjectTransferStatus::NotInitialized:
        return "not-initialized";
    case ObjectTransferStatus::Closed:
        return "closed";
    case ObjectTransferStatus::Full:
        return "full";
    case ObjectTransferStatus::IdentityExhausted:
        return "identity-exhausted";
    case ObjectTransferStatus::SourceRejected:
        return "source-rejected";
    case ObjectTransferStatus::InvalidReference:
        return "invalid-reference";
    case ObjectTransferStatus::StaleReference:
        return "stale-reference";
    case ObjectTransferStatus::ReferenceReplayed:
        return "reference-replayed";
    case ObjectTransferStatus::RightsDenied:
        return "rights-denied";
    case ObjectTransferStatus::TypeMismatch:
        return "type-mismatch";
    case ObjectTransferStatus::RetainFailed:
        return "retain-failed";
    case ObjectTransferStatus::DestinationRejected:
        return "destination-rejected";
    case ObjectTransferStatus::OperationOverflow:
        return "operation-overflow";
    case ObjectTransferStatus::Busy:
        return "busy";
    case ObjectTransferStatus::CorruptState:
        return "corrupt-state";
    }
    return "?";
}

} // namespace duetos::ipc
