#include "ipc/channel_core.h"

#include "ipc/kobject.h"

#if defined(DUETOS_HOST_TEST)
#include <atomic>
#include <mutex>
#include <new>
#if defined(_MSC_VER)
#include <intrin.h>
#endif
#else
#include "mm/kheap.h"
#endif

namespace duetos::ipc
{

namespace
{

constexpr u32 kChannelCoreInitializeUninitialized = 0;
constexpr u32 kChannelCoreInitializeInProgress = 1;
constexpr u32 kChannelCoreInitializeReady = 2;

#if defined(DUETOS_HOST_TEST)
std::mutex g_channel_epoch_lock;
std::atomic<ChannelCoreHostInitializePreClaimHook> g_initialize_preclaim_hook{nullptr};
std::atomic<void*> g_initialize_preclaim_context{nullptr};
#else
constinit sync::SpinLock g_channel_epoch_lock{};
#endif
constinit ChannelEpoch g_next_channel_epoch = 1;

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

bool AtomicCompareExchange(u32* value, u32* expected, u32 desired)
{
    return std::atomic_ref<u32>(*value).compare_exchange_strong(*expected, desired, std::memory_order_acq_rel,
                                                                std::memory_order_acquire);
}
#else
u32 AtomicLoadAcquire(u32* value)
{
    return __atomic_load_n(value, __ATOMIC_ACQUIRE);
}

void AtomicStoreRelease(u32* value, u32 next)
{
    __atomic_store_n(value, next, __ATOMIC_RELEASE);
}

bool AtomicCompareExchange(u32* value, u32* expected, u32 desired)
{
    return __atomic_compare_exchange_n(value, expected, desired, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
}
#endif

class CoreGuard
{
  public:
#if defined(DUETOS_HOST_TEST)
    explicit CoreGuard(ChannelCore& core) : m_core(core), m_ticket(AtomicFetchAdd(&core.lock.next_ticket, 1))
    {
        while (AtomicLoadAcquire(&core.lock.now_serving) != m_ticket)
        {
#if defined(_MSC_VER)
            _mm_pause();
#else
            __builtin_ia32_pause();
#endif
        }
    }

    ~CoreGuard() { AtomicStoreRelease(&m_core.lock.now_serving, m_ticket + 1U); }
#else
    explicit CoreGuard(ChannelCore& core) : m_guard(core.lock) {}
    ~CoreGuard() = default;
#endif

    CoreGuard(const CoreGuard&) = delete;
    CoreGuard& operator=(const CoreGuard&) = delete;
    CoreGuard(CoreGuard&&) = delete;
    CoreGuard& operator=(CoreGuard&&) = delete;

  private:
#if defined(DUETOS_HOST_TEST)
    ChannelCore& m_core;
    u32 m_ticket;
#else
    sync::SpinLockGuard m_guard;
#endif
};

class EpochGuard
{
  public:
#if defined(DUETOS_HOST_TEST)
    EpochGuard() : m_guard(g_channel_epoch_lock) {}
#else
    EpochGuard() : m_guard(g_channel_epoch_lock) {}
#endif

    EpochGuard(const EpochGuard&) = delete;
    EpochGuard& operator=(const EpochGuard&) = delete;

  private:
#if defined(DUETOS_HOST_TEST)
    std::lock_guard<std::mutex> m_guard;
#else
    sync::SpinLockGuard m_guard;
#endif
};

struct PreparedResources
{
    KMessagePort* ports[kChannelCoreDirectionCount];
    ObjectTransferTable* transfer_tables[kChannelCoreDirectionCount];
    ::duetos::core::ResourceChannelChargeKey resource_charge;
};

ChannelCoreOpenResult OpenFailure(ChannelCoreStatus status)
{
    return ChannelCoreOpenResult{status, kChannelEpochInvalid};
}

ChannelCorePinResult PinFailure(ChannelCoreStatus status)
{
    return ChannelCorePinResult{status, kInvalidChannelCoreOperationPin};
}

ChannelCoreDirectionLease LeaseFailure(ChannelCoreStatus status)
{
    return ChannelCoreDirectionLease{status, nullptr, nullptr, kInvalidEndpointRequestLedgerIdentity};
}

ChannelCoreRequestReserveResult ReserveFailure(
    ChannelCoreStatus status, EndpointRequestLedgerStatus ledger_status = EndpointRequestLedgerStatus::NotInitialized)
{
    return ChannelCoreRequestReserveResult{status, ledger_status, kInvalidEndpointRequestKey};
}

ChannelCoreRequestCommitResult CommitFailure(
    ChannelCoreStatus status, EndpointRequestLedgerStatus ledger_status = EndpointRequestLedgerStatus::NotInitialized)
{
    return ChannelCoreRequestCommitResult{status, ledger_status, kInvalidEndpointRequestCompletionAuthority};
}

ChannelCoreRequestTransitionResult TransitionFailure(
    ChannelCoreStatus status, EndpointRequestLedgerStatus ledger_status = EndpointRequestLedgerStatus::NotInitialized)
{
    return ChannelCoreRequestTransitionResult{status, ledger_status};
}

ChannelCoreDrainResult DrainFailure(ChannelCoreStatus status)
{
    ChannelCoreDrainResult result{};
    result.status = status;
    return result;
}

ChannelCoreInspectResult InspectFailure(ChannelCoreStatus status)
{
    return ChannelCoreInspectResult{status, ChannelCoreSnapshot{}};
}

bool ResourceChargeIsCanonicalZero(::duetos::core::ResourceChannelChargeKey charge)
{
    return charge.slot == 0 && charge.generation == 0;
}

bool OperationSlotsAreCanonical(const ChannelCore& core)
{
    u32 observed_live = 0;
    for (u32 index = 0; index < kChannelCoreOperationCapacity; ++index)
    {
        const ChannelCoreOperationSlot& slot = core.operation_slots[index];
        switch (slot.state)
        {
        case ChannelCoreOperationSlotState::Free:
            if (slot.generation == kChannelCoreOperationGenerationMaximum ||
                slot.binding != kInvalidChannelCoreOperationBinding)
                return false;
            break;
        case ChannelCoreOperationSlotState::Live:
            if (slot.generation == 0 || !ChannelCoreOperationBindingIsValid(slot.binding))
                return false;
            ++observed_live;
            break;
        case ChannelCoreOperationSlotState::Retired:
            if (slot.generation != kChannelCoreOperationGenerationMaximum ||
                slot.binding != kInvalidChannelCoreOperationBinding)
                return false;
            break;
        }
    }
    return observed_live == core.active_operations;
}

bool RequestLedgersMatch(const ChannelCore& core, EndpointRequestLedgerState required_state)
{
    for (u32 index = 0; index < kChannelCoreDirectionCount; ++index)
    {
        const EndpointRequestLedger& ledger = core.request_ledgers[index];
        if (!EndpointRequestLedgerIsCanonical(ledger) || ledger.identity.endpoint_epoch != core.channel_epoch ||
            ledger.identity.direction != ChannelCoreLedgerDirection(static_cast<ChannelCoreDirection>(index)))
        {
            return false;
        }
        if (required_state == EndpointRequestLedgerState::Open)
        {
            if (ledger.state != EndpointRequestLedgerState::Open &&
                ledger.state != EndpointRequestLedgerState::SequenceRetired)
            {
                return false;
            }
        }
        else if (ledger.state != required_state)
        {
            return false;
        }
    }
    return true;
}

bool AttachedResourcesAreCanonical(const ChannelCore& core)
{
    return core.ports[0] != nullptr && core.ports[1] != nullptr && core.ports[0] != core.ports[1] &&
           core.transfer_tables[0] != nullptr && core.transfer_tables[1] != nullptr &&
           core.transfer_tables[0] != core.transfer_tables[1] &&
           ::duetos::core::ResourceChannelChargeKeyIsValid(core.resource_charge);
}

bool DetachedResourcesAreCanonical(const ChannelCore& core)
{
    return core.ports[0] == nullptr && core.ports[1] == nullptr && core.transfer_tables[0] == nullptr &&
           core.transfer_tables[1] == nullptr && !::duetos::core::ResourceChannelChargeKeyIsValid(core.resource_charge);
}

bool CoreBodyIsCanonicalUninitialized(const ChannelCore& core)
{
    if (core.state != ChannelCoreState::Uninitialized || core.channel_epoch != kChannelEpochInvalid ||
        core.active_operations != 0 || core.next_operation_hint != 0 || core.drain_driver_active != 0 ||
        core.ports_close_notified != 0 || core.request_ledgers_drained != 0 || core.ports[0] != nullptr ||
        core.ports[1] != nullptr || core.transfer_tables[0] != nullptr || core.transfer_tables[1] != nullptr ||
        !ResourceChargeIsCanonicalZero(core.resource_charge))
    {
        return false;
    }
#if defined(DUETOS_HOST_TEST)
    if (core.lock.next_ticket != 0 || core.lock.now_serving != 0)
        return false;
#else
    if (core.lock.next_ticket != 0 || core.lock.now_serving != 0 || core.lock.owner_cpu != 0 || core.lock.class_id != 0)
        return false;
#endif
    for (u32 index = 0; index < kChannelCoreDirectionCount; ++index)
    {
        if (!EndpointRequestLedgerIsCanonical(core.request_ledgers[index]) ||
            core.request_ledgers[index].state != EndpointRequestLedgerState::Uninitialized)
        {
            return false;
        }
    }
    for (u32 index = 0; index < kChannelCoreOperationCapacity; ++index)
    {
        if (core.operation_slots[index].generation != 0 ||
            core.operation_slots[index].binding != kInvalidChannelCoreOperationBinding ||
            core.operation_slots[index].state != ChannelCoreOperationSlotState::Free)
        {
            return false;
        }
    }
    return true;
}

bool CoreIsCanonical(const ChannelCore& core)
{
    if (core.initialized != kChannelCoreInitializeReady || core.channel_epoch == kChannelEpochInvalid ||
        core.next_operation_hint >= kChannelCoreOperationCapacity || core.drain_driver_active > 1 ||
        core.ports_close_notified > 1 || core.request_ledgers_drained > 1 || !OperationSlotsAreCanonical(core))
    {
        return false;
    }

    switch (core.state)
    {
    case ChannelCoreState::Open:
        return AttachedResourcesAreCanonical(core) && core.drain_driver_active == 0 && core.ports_close_notified == 0 &&
               core.request_ledgers_drained == 0 && RequestLedgersMatch(core, EndpointRequestLedgerState::Open);
    case ChannelCoreState::Draining:
        if (!AttachedResourcesAreCanonical(core))
            return false;
        if (core.request_ledgers_drained == 0)
            return RequestLedgersMatch(core, EndpointRequestLedgerState::Open);
        return core.active_operations == 0 && RequestLedgersMatch(core, EndpointRequestLedgerState::Draining);
    case ChannelCoreState::Drained:
        return DetachedResourcesAreCanonical(core) && core.active_operations == 0 && core.drain_driver_active == 0 &&
               core.ports_close_notified == 1 && core.request_ledgers_drained == 1 &&
               RequestLedgersMatch(core, EndpointRequestLedgerState::Draining);
    case ChannelCoreState::Uninitialized:
        return false;
    }
    return false;
}

ChannelCoreStatus ReadyStatus(ChannelCore* core)
{
    if (core == nullptr)
        return ChannelCoreStatus::InvalidArgument;
    return AtomicLoadAcquire(&core->initialized) == kChannelCoreInitializeReady ? ChannelCoreStatus::Ok
                                                                                : ChannelCoreStatus::NotInitialized;
}

void InitializeCoreLock(ChannelCore& core)
{
    core.lock.next_ticket = 0;
    core.lock.now_serving = 0;
#if !defined(DUETOS_HOST_TEST)
    core.lock.owner_cpu = 0xFFFFFFFFu;
    core.lock.class_id = sync::kLockClassUnclassified;
#endif
}

ChannelEpoch AllocateChannelEpoch()
{
    EpochGuard guard;
    if (g_next_channel_epoch == kChannelEpochInvalid)
        return kChannelEpochInvalid;
    const ChannelEpoch allocated = g_next_channel_epoch;
    g_next_channel_epoch = allocated == kChannelEpochMaximum ? kChannelEpochInvalid : allocated + 1;
    return allocated;
}

ObjectTransferTable* AllocateTransferTable()
{
#if defined(DUETOS_HOST_TEST)
    return new (std::nothrow) ObjectTransferTable{};
#else
    auto* table = static_cast<ObjectTransferTable*>(duetos::mm::KMalloc(sizeof(ObjectTransferTable)));
    if (table != nullptr)
        *table = ObjectTransferTable{};
    return table;
#endif
}

void FreeTransferTable(ObjectTransferTable* table)
{
    if (table == nullptr)
        return;
#if defined(DUETOS_HOST_TEST)
    delete table;
#else
    duetos::mm::KFree(table);
#endif
}

void ReleasePreparedResources(PreparedResources* resources)
{
    if (resources == nullptr)
        return;
    for (u32 index = 0; index < kChannelCoreDirectionCount; ++index)
    {
        if (resources->ports[index] != nullptr)
        {
            KMessagePortClose(resources->ports[index]);
            KObjectRelease(&resources->ports[index]->base);
            resources->ports[index] = nullptr;
        }
        if (resources->transfer_tables[index] != nullptr)
        {
            (void)ObjectTransferTableClose(resources->transfer_tables[index]);
            FreeTransferTable(resources->transfer_tables[index]);
            resources->transfer_tables[index] = nullptr;
        }
    }
    if (::duetos::core::ResourceChannelChargeKeyIsValid(resources->resource_charge))
        (void)::duetos::core::ResourceDomainReleaseChannel(&resources->resource_charge);
}

ChannelCoreStatus PrepareResources(::duetos::core::ResourceDomainKey resource_domain, PreparedResources* resources)
{
    *resources = PreparedResources{};
    if (!::duetos::core::ResourceDomainTryChargeChannel(resource_domain, kChannelCoreQueuedBufferBytes,
                                                        &resources->resource_charge))
        return ChannelCoreStatus::ResourceChargeFailed;

    for (u32 index = 0; index < kChannelCoreDirectionCount; ++index)
    {
        auto created = KMessagePortCreate();
        if (!created.has_value())
        {
            ReleasePreparedResources(resources);
            return ChannelCoreStatus::AllocationFailed;
        }
        resources->ports[index] = created.value();
    }

    for (u32 index = 0; index < kChannelCoreDirectionCount; ++index)
    {
        resources->transfer_tables[index] = AllocateTransferTable();
        if (resources->transfer_tables[index] == nullptr)
        {
            ReleasePreparedResources(resources);
            return ChannelCoreStatus::AllocationFailed;
        }
        if (ObjectTransferTableInitialize(resources->transfer_tables[index]) != ObjectTransferStatus::Ok)
        {
            ReleasePreparedResources(resources);
            return ChannelCoreStatus::CorruptState;
        }
    }
    return ChannelCoreStatus::Ok;
}

void AdoptResources(ChannelCore& core, PreparedResources* resources)
{
    for (u32 index = 0; index < kChannelCoreDirectionCount; ++index)
    {
        core.ports[index] = resources->ports[index];
        resources->ports[index] = nullptr;
        core.transfer_tables[index] = resources->transfer_tables[index];
        resources->transfer_tables[index] = nullptr;
    }
    core.resource_charge = resources->resource_charge;
    resources->resource_charge = ::duetos::core::kInvalidResourceChannelChargeKey;
}

ChannelCoreStatus ValidatePinLocked(const ChannelCore& core, ChannelCoreOperationPin pin, bool allow_draining)
{
    if (!ChannelCoreOperationPinIsValid(pin))
        return ChannelCoreStatus::InvalidArgument;
    if (pin.channel_epoch != core.channel_epoch)
        return ChannelCoreStatus::StaleEpoch;
    const ChannelCoreOperationSlot& slot = core.operation_slots[pin.slot];
    if (slot.state != ChannelCoreOperationSlotState::Live || slot.generation != pin.generation ||
        slot.binding != pin.binding)
        return ChannelCoreStatus::StaleOperation;
    if (core.state == ChannelCoreState::Drained)
        return ChannelCoreStatus::Drained;
    if (!allow_draining && core.state == ChannelCoreState::Draining)
        return ChannelCoreStatus::Draining;
    return core.state == ChannelCoreState::Open || (allow_draining && core.state == ChannelCoreState::Draining)
               ? ChannelCoreStatus::Ok
               : ChannelCoreStatus::CorruptState;
}

bool DetachedCleanupIsComplete(const ChannelCoreDetachedCleanup& cleanup)
{
    return cleanup.channel_epoch != kChannelEpochInvalid && cleanup.ports[0] != nullptr &&
           cleanup.ports[1] != nullptr && cleanup.ports[0] != cleanup.ports[1] &&
           cleanup.transfer_tables[0] != nullptr && cleanup.transfer_tables[1] != nullptr &&
           cleanup.transfer_tables[0] != cleanup.transfer_tables[1] && cleanup.transfer_tables[0]->initialized == 1 &&
           cleanup.transfer_tables[1]->initialized == 1 &&
           cleanup.transfer_tables[0]->state == ObjectTransferTableState::Closed &&
           cleanup.transfer_tables[1]->state == ObjectTransferTableState::Closed &&
           ::duetos::core::ResourceChannelChargeKeyIsValid(cleanup.resource_charge);
}

bool DetachedCleanupIsChargeOnly(const ChannelCoreDetachedCleanup& cleanup)
{
    return cleanup.channel_epoch != kChannelEpochInvalid && cleanup.ports[0] == nullptr &&
           cleanup.ports[1] == nullptr && cleanup.transfer_tables[0] == nullptr &&
           cleanup.transfer_tables[1] == nullptr &&
           ::duetos::core::ResourceChannelChargeKeyIsValid(cleanup.resource_charge);
}

} // namespace

ChannelCoreOpenResult ChannelCoreInitialize(ChannelCore* core, ::duetos::core::ResourceDomainKey resource_domain)
{
    if (core == nullptr || !::duetos::core::ResourceDomainKeyIsValid(resource_domain))
        return OpenFailure(ChannelCoreStatus::InvalidArgument);

#if defined(DUETOS_HOST_TEST)
    const ChannelCoreHostInitializePreClaimHook hook =
        g_initialize_preclaim_hook.exchange(nullptr, std::memory_order_acq_rel);
    if (hook != nullptr)
        hook(g_initialize_preclaim_context.exchange(nullptr, std::memory_order_acq_rel));
#endif

    u32 expected = kChannelCoreInitializeUninitialized;
    if (!AtomicCompareExchange(&core->initialized, &expected, kChannelCoreInitializeInProgress))
        return OpenFailure(ChannelCoreStatus::AlreadyInitialized);
    if (!CoreBodyIsCanonicalUninitialized(*core))
    {
        AtomicStoreRelease(&core->initialized, kChannelCoreInitializeUninitialized);
        return OpenFailure(ChannelCoreStatus::CorruptState);
    }

    PreparedResources resources{};
    ChannelCoreStatus status = PrepareResources(resource_domain, &resources);
    if (status != ChannelCoreStatus::Ok)
    {
        AtomicStoreRelease(&core->initialized, kChannelCoreInitializeUninitialized);
        return OpenFailure(status);
    }

    const ChannelEpoch epoch = AllocateChannelEpoch();
    if (epoch == kChannelEpochInvalid)
    {
        ReleasePreparedResources(&resources);
        AtomicStoreRelease(&core->initialized, kChannelCoreInitializeUninitialized);
        return OpenFailure(ChannelCoreStatus::EpochExhausted);
    }

    EndpointRequestLedger ledgers[kChannelCoreDirectionCount]{};
    for (u32 index = 0; index < kChannelCoreDirectionCount; ++index)
    {
        const EndpointRequestLedgerStatus ledger_status = EndpointRequestLedgerInitialize(
            &ledgers[index],
            EndpointRequestLedgerIdentity{epoch, ChannelCoreLedgerDirection(static_cast<ChannelCoreDirection>(index))});
        if (ledger_status != EndpointRequestLedgerStatus::Ok)
        {
            ReleasePreparedResources(&resources);
            AtomicStoreRelease(&core->initialized, kChannelCoreInitializeUninitialized);
            return OpenFailure(ChannelCoreStatus::CorruptState);
        }
    }

    InitializeCoreLock(*core);
    core->request_ledgers[0] = ledgers[0];
    core->request_ledgers[1] = ledgers[1];
    AdoptResources(*core, &resources);
    core->channel_epoch = epoch;
    core->active_operations = 0;
    core->next_operation_hint = 0;
    core->drain_driver_active = 0;
    core->ports_close_notified = 0;
    core->request_ledgers_drained = 0;
    core->state = ChannelCoreState::Open;
    AtomicStoreRelease(&core->initialized, kChannelCoreInitializeReady);
    return ChannelCoreOpenResult{ChannelCoreStatus::Ok, epoch};
}

ChannelCoreOpenResult ChannelCoreReset(ChannelCore* core, ::duetos::core::ResourceDomainKey resource_domain)
{
    const ChannelCoreStatus ready = ReadyStatus(core);
    if (ready != ChannelCoreStatus::Ok)
        return OpenFailure(ready);
    if (!::duetos::core::ResourceDomainKeyIsValid(resource_domain))
        return OpenFailure(ChannelCoreStatus::InvalidArgument);

    ChannelEpoch previous_epoch = kChannelEpochInvalid;
    {
        CoreGuard guard(*core);
        if (!CoreIsCanonical(*core))
            return OpenFailure(ChannelCoreStatus::CorruptState);
        if (core->state != ChannelCoreState::Drained)
            return OpenFailure(ChannelCoreStatus::ResetNotDrained);
        previous_epoch = core->channel_epoch;
    }

    PreparedResources resources{};
    ChannelCoreStatus status = PrepareResources(resource_domain, &resources);
    if (status != ChannelCoreStatus::Ok)
        return OpenFailure(status);
    const ChannelEpoch next_epoch = AllocateChannelEpoch();
    if (next_epoch == kChannelEpochInvalid)
    {
        ReleasePreparedResources(&resources);
        return OpenFailure(ChannelCoreStatus::EpochExhausted);
    }
    if (next_epoch <= previous_epoch)
    {
        ReleasePreparedResources(&resources);
        return OpenFailure(ChannelCoreStatus::StaleEpoch);
    }

    ChannelCoreOpenResult result = OpenFailure(ChannelCoreStatus::ResetNotDrained);
    bool adopted = false;
    {
        CoreGuard guard(*core);
        if (!CoreIsCanonical(*core))
        {
            result = OpenFailure(ChannelCoreStatus::CorruptState);
        }
        else if (core->state != ChannelCoreState::Drained || core->channel_epoch != previous_epoch)
        {
            result = OpenFailure(ChannelCoreStatus::ResetNotDrained);
        }
        else
        {
            EndpointRequestLedger ledgers[kChannelCoreDirectionCount] = {core->request_ledgers[0],
                                                                         core->request_ledgers[1]};
            const EndpointRequestLedgerStatus forward = EndpointRequestLedgerReset(
                &ledgers[0], EndpointRequestLedgerIdentity{next_epoch, EndpointRequestDirection::InitiatorToAcceptor});
            const EndpointRequestLedgerStatus reverse = EndpointRequestLedgerReset(
                &ledgers[1], EndpointRequestLedgerIdentity{next_epoch, EndpointRequestDirection::AcceptorToInitiator});
            if (forward != EndpointRequestLedgerStatus::Ok || reverse != EndpointRequestLedgerStatus::Ok)
            {
                result = OpenFailure(ChannelCoreStatus::LedgerFailure);
            }
            else
            {
                core->request_ledgers[0] = ledgers[0];
                core->request_ledgers[1] = ledgers[1];
                AdoptResources(*core, &resources);
                core->channel_epoch = next_epoch;
                core->drain_driver_active = 0;
                core->ports_close_notified = 0;
                core->request_ledgers_drained = 0;
                core->state = ChannelCoreState::Open;
                adopted = true;
                result = ChannelCoreOpenResult{ChannelCoreStatus::Ok, next_epoch};
            }
        }
    }
    if (!adopted)
        ReleasePreparedResources(&resources);
    return result;
}

ChannelCorePinResult ChannelCoreAcquireOperation(ChannelCore* core, ChannelEpoch expected_epoch,
                                                 ChannelCoreOperationBinding binding)
{
    const ChannelCoreStatus ready = ReadyStatus(core);
    if (ready != ChannelCoreStatus::Ok)
        return PinFailure(ready);
    if (expected_epoch == kChannelEpochInvalid || !ChannelCoreOperationBindingIsValid(binding))
        return PinFailure(ChannelCoreStatus::InvalidArgument);

    CoreGuard guard(*core);
    if (!CoreIsCanonical(*core))
        return PinFailure(ChannelCoreStatus::CorruptState);
    if (expected_epoch != core->channel_epoch)
        return PinFailure(ChannelCoreStatus::StaleEpoch);
    if (core->state == ChannelCoreState::Draining)
        return PinFailure(ChannelCoreStatus::Draining);
    if (core->state == ChannelCoreState::Drained)
        return PinFailure(ChannelCoreStatus::Drained);
    if (core->state != ChannelCoreState::Open)
        return PinFailure(ChannelCoreStatus::CorruptState);
    if (core->active_operations == static_cast<u32>(~0U))
        return PinFailure(ChannelCoreStatus::OperationIdentityExhausted);

    bool live_slot_seen = false;
    for (u32 offset = 0; offset < kChannelCoreOperationCapacity; ++offset)
    {
        const u32 index = (core->next_operation_hint + offset) % kChannelCoreOperationCapacity;
        ChannelCoreOperationSlot& slot = core->operation_slots[index];
        if (slot.state == ChannelCoreOperationSlotState::Live)
        {
            live_slot_seen = true;
            continue;
        }
        if (slot.state != ChannelCoreOperationSlotState::Free ||
            slot.generation == kChannelCoreOperationGenerationMaximum)
        {
            continue;
        }

        ++slot.generation;
        slot.state = ChannelCoreOperationSlotState::Live;
        slot.binding = binding;
        ++core->active_operations;
        core->next_operation_hint = (index + 1U) % kChannelCoreOperationCapacity;
        return ChannelCorePinResult{ChannelCoreStatus::Ok,
                                    ChannelCoreOperationPin{core->channel_epoch, index, slot.generation, binding}};
    }
    return PinFailure(live_slot_seen ? ChannelCoreStatus::Busy : ChannelCoreStatus::OperationIdentityExhausted);
}

ChannelCoreStatus ChannelCoreReleaseOperation(ChannelCore* core, ChannelCoreOperationPin pin)
{
    const ChannelCoreStatus ready = ReadyStatus(core);
    if (ready != ChannelCoreStatus::Ok)
        return ready;
    if (!ChannelCoreOperationPinIsValid(pin))
        return ChannelCoreStatus::InvalidArgument;

    CoreGuard guard(*core);
    if (!CoreIsCanonical(*core))
        return ChannelCoreStatus::CorruptState;
    if (pin.channel_epoch != core->channel_epoch)
        return ChannelCoreStatus::StaleEpoch;
    ChannelCoreOperationSlot& slot = core->operation_slots[pin.slot];
    if (slot.state != ChannelCoreOperationSlotState::Live || slot.generation != pin.generation ||
        slot.binding != pin.binding)
        return ChannelCoreStatus::StaleOperation;
    if (core->active_operations == 0)
        return ChannelCoreStatus::CorruptState;

    slot.binding = kInvalidChannelCoreOperationBinding;
    slot.state = slot.generation == kChannelCoreOperationGenerationMaximum ? ChannelCoreOperationSlotState::Retired
                                                                           : ChannelCoreOperationSlotState::Free;
    --core->active_operations;
    core->next_operation_hint = pin.slot;
    return ChannelCoreStatus::Ok;
}

ChannelCoreDirectionLease ChannelCoreBorrowDirection(ChannelCore* core, ChannelCoreOperationPin pin,
                                                     ChannelCoreDirection direction)
{
    const ChannelCoreStatus ready = ReadyStatus(core);
    if (ready != ChannelCoreStatus::Ok)
        return LeaseFailure(ready);
    if (!ChannelCoreDirectionIsValid(direction))
        return LeaseFailure(ChannelCoreStatus::InvalidArgument);

    CoreGuard guard(*core);
    if (!CoreIsCanonical(*core))
        return LeaseFailure(ChannelCoreStatus::CorruptState);
    const ChannelCoreStatus pin_status = ValidatePinLocked(*core, pin, false);
    if (pin_status != ChannelCoreStatus::Ok)
        return LeaseFailure(pin_status);
    const u32 index = ChannelCoreDirectionIndex(direction);
    return ChannelCoreDirectionLease{ChannelCoreStatus::Ok, core->ports[index], core->transfer_tables[index],
                                     core->request_ledgers[index].identity};
}

ChannelCoreRequestReserveResult ChannelCoreReserveRequest(ChannelCore* core, ChannelCoreOperationPin pin,
                                                          ChannelCoreDirection direction, u64 request_id)
{
    const ChannelCoreStatus ready = ReadyStatus(core);
    if (ready != ChannelCoreStatus::Ok)
        return ReserveFailure(ready);
    if (!ChannelCoreDirectionIsValid(direction) || request_id == kEndpointRequestIdInvalid)
        return ReserveFailure(ChannelCoreStatus::InvalidArgument, EndpointRequestLedgerStatus::InvalidArgument);

    CoreGuard guard(*core);
    if (!CoreIsCanonical(*core))
        return ReserveFailure(ChannelCoreStatus::CorruptState, EndpointRequestLedgerStatus::CorruptState);
    const ChannelCoreStatus pin_status = ValidatePinLocked(*core, pin, false);
    if (pin_status != ChannelCoreStatus::Ok)
        return ReserveFailure(pin_status);

    const u32 index = ChannelCoreDirectionIndex(direction);
    const EndpointRequestKey key{core->request_ledgers[index].identity, request_id};
    const EndpointRequestLedgerStatus ledger_status = EndpointRequestLedgerReserve(&core->request_ledgers[index], key);
    return ledger_status == EndpointRequestLedgerStatus::Ok
               ? ChannelCoreRequestReserveResult{ChannelCoreStatus::Ok, ledger_status, key}
               : ReserveFailure(ChannelCoreStatus::LedgerFailure, ledger_status);
}

ChannelCoreRequestCommitResult ChannelCoreCommitRequest(ChannelCore* core, ChannelCoreOperationPin pin,
                                                        ChannelCoreDirection direction, EndpointRequestKey key)
{
    const ChannelCoreStatus ready = ReadyStatus(core);
    if (ready != ChannelCoreStatus::Ok)
        return CommitFailure(ready);
    if (!ChannelCoreDirectionIsValid(direction) || !EndpointRequestKeyIsValid(key))
        return CommitFailure(ChannelCoreStatus::InvalidArgument, EndpointRequestLedgerStatus::InvalidArgument);

    CoreGuard guard(*core);
    if (!CoreIsCanonical(*core))
        return CommitFailure(ChannelCoreStatus::CorruptState, EndpointRequestLedgerStatus::CorruptState);
    const ChannelCoreStatus pin_status = ValidatePinLocked(*core, pin, true);
    if (pin_status != ChannelCoreStatus::Ok)
        return CommitFailure(pin_status);

    const u32 index = ChannelCoreDirectionIndex(direction);
    const EndpointRequestCommitResult committed = EndpointRequestLedgerCommit(&core->request_ledgers[index], key);
    return committed.status == EndpointRequestLedgerStatus::Ok
               ? ChannelCoreRequestCommitResult{ChannelCoreStatus::Ok, committed.status, committed.completion_authority}
               : CommitFailure(ChannelCoreStatus::LedgerFailure, committed.status);
}

ChannelCoreRequestTransitionResult ChannelCoreCancelRequest(ChannelCore* core, ChannelCoreOperationPin pin,
                                                            ChannelCoreDirection direction, EndpointRequestKey key)
{
    const ChannelCoreStatus ready = ReadyStatus(core);
    if (ready != ChannelCoreStatus::Ok)
        return TransitionFailure(ready);
    if (!ChannelCoreDirectionIsValid(direction) || !EndpointRequestKeyIsValid(key))
        return TransitionFailure(ChannelCoreStatus::InvalidArgument, EndpointRequestLedgerStatus::InvalidArgument);

    CoreGuard guard(*core);
    if (!CoreIsCanonical(*core))
        return TransitionFailure(ChannelCoreStatus::CorruptState, EndpointRequestLedgerStatus::CorruptState);
    const ChannelCoreStatus pin_status = ValidatePinLocked(*core, pin, true);
    if (pin_status != ChannelCoreStatus::Ok)
        return TransitionFailure(pin_status);

    const u32 index = ChannelCoreDirectionIndex(direction);
    const EndpointRequestLedgerStatus ledger_status = EndpointRequestLedgerCancel(&core->request_ledgers[index], key);
    return ledger_status == EndpointRequestLedgerStatus::Ok
               ? ChannelCoreRequestTransitionResult{ChannelCoreStatus::Ok, ledger_status}
               : TransitionFailure(ChannelCoreStatus::LedgerFailure, ledger_status);
}

ChannelCoreRequestTransitionResult ChannelCoreCompleteRequest(ChannelCore* core, ChannelCoreOperationPin pin,
                                                              ChannelCoreDirection direction,
                                                              EndpointRequestCompletionAuthority completion_authority)
{
    const ChannelCoreStatus ready = ReadyStatus(core);
    if (ready != ChannelCoreStatus::Ok)
        return TransitionFailure(ready);
    if (!ChannelCoreDirectionIsValid(direction) || !EndpointRequestCompletionAuthorityIsValid(completion_authority))
    {
        return TransitionFailure(ChannelCoreStatus::InvalidArgument, EndpointRequestLedgerStatus::InvalidArgument);
    }

    CoreGuard guard(*core);
    if (!CoreIsCanonical(*core))
        return TransitionFailure(ChannelCoreStatus::CorruptState, EndpointRequestLedgerStatus::CorruptState);
    const ChannelCoreStatus pin_status = ValidatePinLocked(*core, pin, true);
    if (pin_status != ChannelCoreStatus::Ok)
        return TransitionFailure(pin_status);

    const u32 index = ChannelCoreDirectionIndex(direction);
    const EndpointRequestLedgerStatus ledger_status =
        EndpointRequestLedgerComplete(&core->request_ledgers[index], completion_authority);
    return ledger_status == EndpointRequestLedgerStatus::Ok
               ? ChannelCoreRequestTransitionResult{ChannelCoreStatus::Ok, ledger_status}
               : TransitionFailure(ChannelCoreStatus::LedgerFailure, ledger_status);
}

namespace
{

ChannelCoreDrainResult DrainCore(ChannelCore* core, ChannelEpoch expected_epoch, bool enforce_expected_epoch)
{
    const ChannelCoreStatus ready = ReadyStatus(core);
    if (ready != ChannelCoreStatus::Ok)
        return DrainFailure(ready);

    ChannelCoreDrainResult result{};
    KMessagePort* ports[kChannelCoreDirectionCount]{};
    ObjectTransferTable* transfer_tables[kChannelCoreDirectionCount]{};
    bool attempt_finalize = false;
    {
        CoreGuard guard(*core);
        if (!CoreIsCanonical(*core))
            return DrainFailure(ChannelCoreStatus::CorruptState);
        // The expected-generation check shares the exact lock that protects
        // reset and Open->Draining. No ledger, state, port, transfer table, or
        // ownership field has changed when a stale outer owner is rejected.
        if (enforce_expected_epoch && core->channel_epoch != expected_epoch)
            return DrainFailure(ChannelCoreStatus::StaleEpoch);
        result.channel_epoch = core->channel_epoch;
        if (core->state == ChannelCoreState::Drained)
        {
            result.status = ChannelCoreStatus::Ok;
            return result;
        }
        if (core->state == ChannelCoreState::Open)
            core->state = ChannelCoreState::Draining;
        if (core->state != ChannelCoreState::Draining)
            return DrainFailure(ChannelCoreStatus::CorruptState);
        if (core->drain_driver_active != 0)
        {
            result.status = ChannelCoreStatus::Busy;
            return result;
        }

        attempt_finalize = core->active_operations == 0;
        core->drain_driver_active = 1;
        ports[0] = core->ports[0];
        ports[1] = core->ports[1];
        if (attempt_finalize)
        {
            transfer_tables[0] = core->transfer_tables[0];
            transfer_tables[1] = core->transfer_tables[1];
        }
    }

    KMessagePortClose(ports[0]);
    KMessagePortClose(ports[1]);
    ObjectTransferStatus transfer_status[kChannelCoreDirectionCount] = {
        ObjectTransferStatus::Busy,
        ObjectTransferStatus::Busy,
    };
    if (attempt_finalize)
    {
        transfer_status[0] = ObjectTransferTableClose(transfer_tables[0]);
        transfer_status[1] = ObjectTransferTableClose(transfer_tables[1]);
    }

    {
        CoreGuard guard(*core);
        if (!CoreIsCanonical(*core))
        {
            core->drain_driver_active = 0;
            return DrainFailure(ChannelCoreStatus::CorruptState);
        }
        core->ports_close_notified = 1;
        core->drain_driver_active = 0;
        if (core->active_operations != 0 || !attempt_finalize)
        {
            result.status = ChannelCoreStatus::Busy;
            return result;
        }
        if (transfer_status[0] == ObjectTransferStatus::Busy || transfer_status[1] == ObjectTransferStatus::Busy)
        {
            result.status = ChannelCoreStatus::Busy;
            return result;
        }
        if (transfer_status[0] != ObjectTransferStatus::Ok || transfer_status[1] != ObjectTransferStatus::Ok)
        {
            result.status = ChannelCoreStatus::TransferCloseFailed;
            return result;
        }

        if (core->request_ledgers_drained == 0)
        {
            EndpointRequestLedger ledgers[kChannelCoreDirectionCount] = {core->request_ledgers[0],
                                                                         core->request_ledgers[1]};
            const EndpointRequestDrainResult forward = EndpointRequestLedgerDrain(&ledgers[0]);
            const EndpointRequestDrainResult reverse = EndpointRequestLedgerDrain(&ledgers[1]);
            if (forward.status != EndpointRequestLedgerStatus::Ok || reverse.status != EndpointRequestLedgerStatus::Ok)
            {
                result.status = ChannelCoreStatus::LedgerFailure;
                return result;
            }
            core->request_ledgers[0] = ledgers[0];
            core->request_ledgers[1] = ledgers[1];
            core->request_ledgers_drained = 1;
            result.request_cleanup[0] = forward;
            result.request_cleanup[1] = reverse;
        }

        result.detached.channel_epoch = core->channel_epoch;
        result.detached.ports[0] = core->ports[0];
        result.detached.ports[1] = core->ports[1];
        result.detached.transfer_tables[0] = core->transfer_tables[0];
        result.detached.transfer_tables[1] = core->transfer_tables[1];
        result.detached.resource_charge = core->resource_charge;

        core->ports[0] = nullptr;
        core->ports[1] = nullptr;
        core->transfer_tables[0] = nullptr;
        core->transfer_tables[1] = nullptr;
        core->resource_charge = ::duetos::core::kInvalidResourceChannelChargeKey;
        core->state = ChannelCoreState::Drained;
        result.status = ChannelCoreStatus::Ok;
    }
    return result;
}

} // namespace

ChannelCoreDrainResult ChannelCoreDrain(ChannelCore* core)
{
    return DrainCore(core, kChannelEpochInvalid, false);
}

ChannelCoreDrainResult ChannelCoreDrainExpected(ChannelCore* core, ChannelEpoch expected_epoch)
{
    if (expected_epoch == kChannelEpochInvalid)
        return DrainFailure(ChannelCoreStatus::InvalidArgument);
    return DrainCore(core, expected_epoch, true);
}

ChannelCoreStatus ChannelCoreReleaseDetachedCleanup(ChannelCoreDetachedCleanup* cleanup)
{
    if (cleanup == nullptr)
        return ChannelCoreStatus::InvalidCleanup;

    if (DetachedCleanupIsChargeOnly(*cleanup))
    {
        ::duetos::core::ResourceChannelChargeKey charge = cleanup->resource_charge;
        if (!::duetos::core::ResourceDomainReleaseChannel(&charge))
            return ChannelCoreStatus::ResourceReleaseFailed;
        *cleanup = ChannelCoreDetachedCleanup{};
        return ChannelCoreStatus::Ok;
    }
    if (!DetachedCleanupIsComplete(*cleanup))
        return ChannelCoreStatus::InvalidCleanup;

    const ChannelCoreDetachedCleanup detached = *cleanup;
    *cleanup = ChannelCoreDetachedCleanup{};
    FreeTransferTable(detached.transfer_tables[0]);
    FreeTransferTable(detached.transfer_tables[1]);
    KObjectRelease(&detached.ports[0]->base);
    KObjectRelease(&detached.ports[1]->base);
    ::duetos::core::ResourceChannelChargeKey charge = detached.resource_charge;
    if (!::duetos::core::ResourceDomainReleaseChannel(&charge))
    {
        cleanup->channel_epoch = detached.channel_epoch;
        cleanup->resource_charge = detached.resource_charge;
        return ChannelCoreStatus::ResourceReleaseFailed;
    }
    return ChannelCoreStatus::Ok;
}

ChannelCoreInspectResult ChannelCoreInspect(ChannelCore* core)
{
    const ChannelCoreStatus ready = ReadyStatus(core);
    if (ready != ChannelCoreStatus::Ok)
        return InspectFailure(ready);

    CoreGuard guard(*core);
    if (!CoreIsCanonical(*core))
        return InspectFailure(ChannelCoreStatus::CorruptState);
    ChannelCoreSnapshot snapshot{};
    snapshot.state = core->state;
    snapshot.channel_epoch = core->channel_epoch;
    snapshot.active_operations = core->active_operations;
    snapshot.resources_attached = core->state != ChannelCoreState::Drained;
    snapshot.ports_close_notified = core->ports_close_notified != 0;
    snapshot.request_ledgers_drained = core->request_ledgers_drained != 0;
    for (u32 index = 0; index < kChannelCoreDirectionCount; ++index)
    {
        snapshot.active_requests[index] = core->request_ledgers[index].active_count;
        snapshot.request_identities[index] = core->request_ledgers[index].identity;
    }
    return ChannelCoreInspectResult{ChannelCoreStatus::Ok, snapshot};
}

const char* ChannelCoreStatusName(ChannelCoreStatus status)
{
    switch (status)
    {
    case ChannelCoreStatus::Ok:
        return "ok";
    case ChannelCoreStatus::InvalidArgument:
        return "invalid-argument";
    case ChannelCoreStatus::NotInitialized:
        return "not-initialized";
    case ChannelCoreStatus::AlreadyInitialized:
        return "already-initialized";
    case ChannelCoreStatus::CorruptState:
        return "corrupt-state";
    case ChannelCoreStatus::ResourceChargeFailed:
        return "resource-charge-failed";
    case ChannelCoreStatus::AllocationFailed:
        return "allocation-failed";
    case ChannelCoreStatus::EpochExhausted:
        return "epoch-exhausted";
    case ChannelCoreStatus::Draining:
        return "draining";
    case ChannelCoreStatus::Drained:
        return "drained";
    case ChannelCoreStatus::ResetNotDrained:
        return "reset-not-drained";
    case ChannelCoreStatus::Busy:
        return "busy";
    case ChannelCoreStatus::OperationIdentityExhausted:
        return "operation-identity-exhausted";
    case ChannelCoreStatus::StaleOperation:
        return "stale-operation";
    case ChannelCoreStatus::StaleEpoch:
        return "stale-epoch";
    case ChannelCoreStatus::LedgerFailure:
        return "ledger-failure";
    case ChannelCoreStatus::TransferCloseFailed:
        return "transfer-close-failed";
    case ChannelCoreStatus::InvalidCleanup:
        return "invalid-cleanup";
    case ChannelCoreStatus::ResourceReleaseFailed:
        return "resource-release-failed";
    }
    return "unknown";
}

#if defined(DUETOS_HOST_TEST)
void ChannelCoreHostArmInitializePreClaimHookForTest(ChannelCoreHostInitializePreClaimHook hook, void* context)
{
    g_initialize_preclaim_context.store(context, std::memory_order_release);
    g_initialize_preclaim_hook.store(hook, std::memory_order_release);
}

void ChannelCoreHostSetNextEpochForTest(ChannelEpoch next_epoch)
{
    EpochGuard guard;
    g_next_channel_epoch = next_epoch;
}
#endif

} // namespace duetos::ipc
