#include "core/service_directory.h"

#if defined(DUETOS_HOST_TEST)
#include <atomic>
#if defined(_MSC_VER)
#include <intrin.h>
#endif
#endif

namespace duetos::core
{

namespace
{

constexpr u32 kDirectoryInitializeUninitialized = 0;
constexpr u32 kDirectoryInitializeInProgress = 1;
constexpr u32 kDirectoryInitializeReady = 2;

constinit u64 g_last_service_generations[kServiceDirectoryCapacity]{};

#if defined(DUETOS_HOST_TEST)
std::atomic<ServiceDirectoryHostPublicationHook> g_connect_publication_hook{nullptr};
std::atomic<void*> g_connect_publication_context{nullptr};
std::atomic<ServiceDirectoryHostPublicationHook> g_accept_publication_hook{nullptr};
std::atomic<void*> g_accept_publication_context{nullptr};
std::atomic<bool> g_fail_registration_publication{false};

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

u64 AtomicLoadGeneration(u64* value)
{
    return std::atomic_ref<u64>(*value).load(std::memory_order_relaxed);
}

bool AtomicCompareExchangeGeneration(u64* value, u64* expected, u64 desired)
{
    return std::atomic_ref<u64>(*value).compare_exchange_weak(*expected, desired, std::memory_order_relaxed,
                                                              std::memory_order_relaxed);
}

void AtomicStoreGeneration(u64* value, u64 next)
{
    std::atomic_ref<u64>(*value).store(next, std::memory_order_relaxed);
}

void InvokePublicationHook(std::atomic<ServiceDirectoryHostPublicationHook>& hook_slot,
                           std::atomic<void*>& context_slot)
{
    ServiceDirectoryHostPublicationHook hook = hook_slot.exchange(nullptr, std::memory_order_acq_rel);
    if (hook != nullptr)
        hook(context_slot.exchange(nullptr, std::memory_order_acq_rel));
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

u64 AtomicLoadGeneration(u64* value)
{
    return __atomic_load_n(value, __ATOMIC_RELAXED);
}

bool AtomicCompareExchangeGeneration(u64* value, u64* expected, u64 desired)
{
    return __atomic_compare_exchange_n(value, expected, desired, true, __ATOMIC_RELAXED, __ATOMIC_RELAXED);
}
#endif

class DirectoryGuard
{
  public:
#if defined(DUETOS_HOST_TEST)
    explicit DirectoryGuard(ServiceDirectory& directory)
        : m_directory(directory), m_ticket(AtomicFetchAdd(&directory.lock.next_ticket, 1))
    {
        while (AtomicLoadAcquire(&directory.lock.now_serving) != m_ticket)
        {
#if defined(_MSC_VER)
            _mm_pause();
#else
            __builtin_ia32_pause();
#endif
        }
    }

    ~DirectoryGuard() { AtomicStoreRelease(&m_directory.lock.now_serving, m_ticket + 1U); }
#else
    explicit DirectoryGuard(ServiceDirectory& directory) : m_guard(directory.lock) {}
    ~DirectoryGuard() = default;
#endif

    DirectoryGuard(const DirectoryGuard&) = delete;
    DirectoryGuard& operator=(const DirectoryGuard&) = delete;

  private:
#if defined(DUETOS_HOST_TEST)
    ServiceDirectory& m_directory;
    u32 m_ticket;
#else
    sync::SpinLockGuard m_guard;
#endif
};

ServiceDirectoryReserveResult ReserveFailure(ServiceDirectoryStatus status)
{
    return ServiceDirectoryReserveResult{status, kInvalidServiceRegistrationReservation};
}

ServiceDirectoryLookupResult LookupFailure(ServiceDirectoryStatus status)
{
    return ServiceDirectoryLookupResult{status, kInvalidServiceDirectoryOperationPin};
}

ServiceDirectoryConnectResult ConnectFailure(ServiceDirectoryStatus status,
                                             ServiceEndpointStatus endpoint_status = ServiceEndpointStatus::Ok,
                                             ErrorCode handle_status = ErrorCode::Ok,
                                             ServiceDirectoryOwnedChannel rollback = {})
{
    return ServiceDirectoryConnectResult{
        status, endpoint_status, handle_status, ipc::kHandleInvalid, kInvalidServiceEndpointIdentity, rollback};
}

ServiceDirectoryAcceptResult AcceptFailure(ServiceDirectoryStatus status,
                                           ServiceEndpointStatus endpoint_status = ServiceEndpointStatus::Ok,
                                           ErrorCode handle_status = ErrorCode::Ok)
{
    return ServiceDirectoryAcceptResult{status,
                                        endpoint_status,
                                        handle_status,
                                        ipc::kHandleInvalid,
                                        kInvalidServiceEndpointIdentity,
                                        kInvalidServiceDirectoryAcceptedChannelKey};
}

ServiceDirectoryReleaseAcceptedResult ReleaseAcceptedFailure(
    ServiceDirectoryStatus status, ServiceEndpointStatus endpoint_status = ServiceEndpointStatus::Ok)
{
    return ServiceDirectoryReleaseAcceptedResult{status, endpoint_status};
}

ServiceDirectoryDeferAcceptedProcessResult DeferAcceptedProcessFailure(ServiceDirectoryStatus status,
                                                                       u32 newly_deferred_channels = 0,
                                                                       u32 deferred_channels = 0)
{
    return ServiceDirectoryDeferAcceptedProcessResult{status, newly_deferred_channels, deferred_channels};
}

ServiceDirectoryDriveDeferredAcceptedResult DriveDeferredAcceptedFailure(
    ServiceDirectoryStatus status, ServiceEndpointStatus endpoint_status = ServiceEndpointStatus::Ok,
    u32 released_channels = 0, u32 pending_channels = 0)
{
    return ServiceDirectoryDriveDeferredAcceptedResult{status, endpoint_status, released_channels, pending_channels};
}

ServiceDirectoryCloseResult CloseFailure(ServiceDirectoryStatus status,
                                         ServiceEndpointStatus endpoint_status = ServiceEndpointStatus::Ok,
                                         u32 drained_channels = 0)
{
    return ServiceDirectoryCloseResult{status, endpoint_status, drained_channels};
}

ServiceDirectoryInspectResult InspectFailure(ServiceDirectoryStatus status)
{
    return ServiceDirectoryInspectResult{status, {}};
}

bool NameCharacterIsCanonical(u8 value, bool first)
{
    const bool lowercase = value >= static_cast<u8>('a') && value <= static_cast<u8>('z');
    const bool digit = value >= static_cast<u8>('0') && value <= static_cast<u8>('9');
    if (first)
        return lowercase;
    return lowercase || digit || value == static_cast<u8>('-') || value == static_cast<u8>('_') ||
           value == static_cast<u8>('.');
}

bool NameEquals(const ServiceDirectoryName& lhs, const ServiceDirectoryName& rhs)
{
    if (lhs.length != rhs.length)
        return false;
    u8 difference = 0;
    for (u32 index = 0; index < lhs.length; ++index)
        difference = static_cast<u8>(difference | (lhs.bytes[index] ^ rhs.bytes[index]));
    return difference == 0;
}

bool NameIsZero(const ServiceDirectoryName& name)
{
    if (name.length != 0)
        return false;
    for (u32 index = 0; index < kServiceDirectoryNameCapacity; ++index)
    {
        if (name.bytes[index] != 0)
            return false;
    }
    return true;
}

bool InstanceIsZero(ServiceInstanceToken owner)
{
    return owner.start.service_identity == 0 && owner.start.generation == 0 && owner.process.process_identity == 0 &&
           owner.process.pid == 0;
}

bool CredentialIsZero(const ServiceEndpointCredentialSnapshot& credential)
{
    const u8* bytes = reinterpret_cast<const u8*>(&credential);
    for (usize index = 0; index < sizeof(credential); ++index)
    {
        if (bytes[index] != 0)
            return false;
    }
    return true;
}

bool KeyIsZero(ServiceKey key)
{
    return key.slot == 0 && key.generation == 0;
}

bool AcceptedKeyIsInactive(const ServiceDirectoryAcceptedChannelKey& key)
{
    return !ServiceKeyIsValid(key.service) && !ServiceEndpointChannelKeyIsValid(key.channel);
}

ProcessKey ProcessKeyFromInstance(ServiceInstanceKey instance)
{
    return ProcessKey{instance.process_identity, instance.pid};
}

bool OperationSlotsAreCanonical(const ServiceDirectoryRow& row)
{
    u32 live = 0;
    for (u32 index = 0; index < kServiceDirectoryOperationCapacity; ++index)
    {
        const ServiceDirectoryOperationSlot& slot = row.operation_slots[index];
        switch (slot.state)
        {
        case ServiceDirectoryOperationSlotState::Free:
            if (slot.generation == kServiceDirectoryOperationGenerationMaximum)
                return false;
            break;
        case ServiceDirectoryOperationSlotState::Live:
            if (slot.generation == 0)
                return false;
            ++live;
            break;
        case ServiceDirectoryOperationSlotState::Retired:
            if (slot.generation != kServiceDirectoryOperationGenerationMaximum)
                return false;
            break;
        }
    }
    return live == row.active_operations && row.next_operation_hint < kServiceDirectoryOperationCapacity;
}

bool QueuedChannelIsCanonical(const ServiceDirectoryQueuedChannel& queued)
{
    if (queued.state == ServiceDirectoryQueuedChannelState::Empty)
    {
        return ServiceDirectoryOwnedChannelIsEmpty(queued.owned) && !ServiceEndpointChannelKeyIsValid(queued.channel);
    }
    return (queued.state == ServiceDirectoryQueuedChannelState::PendingClientPublish ||
            queued.state == ServiceDirectoryQueuedChannelState::Ready) &&
           ServiceEndpointOwnerReceiptIsValid(queued.owned.owner) && queued.owned.unpublished_acceptor != nullptr &&
           !queued.owned.release_driver_active && queued.channel == queued.owned.owner.channel;
}

bool QueueSlotIsOccupied(const ServiceDirectoryRow& row, u32 slot)
{
    for (u32 offset = 0; offset < row.accept_count; ++offset)
    {
        if ((row.accept_head + offset) % kServiceDirectoryAcceptCapacity == slot)
            return true;
    }
    return false;
}

bool AcceptQueueIsCanonical(const ServiceDirectoryRow& row)
{
    if (row.accept_head >= kServiceDirectoryAcceptCapacity || row.accept_count > kServiceDirectoryAcceptCapacity)
        return false;
    for (u32 index = 0; index < kServiceDirectoryAcceptCapacity; ++index)
    {
        const bool occupied = QueueSlotIsOccupied(row, index);
        if (occupied)
        {
            if (!QueuedChannelIsCanonical(row.accept_queue[index]) ||
                row.accept_queue[index].state == ServiceDirectoryQueuedChannelState::Empty)
            {
                return false;
            }
        }
        else if (!QueuedChannelIsCanonical(row.accept_queue[index]))
        {
            return false;
        }
    }
    return true;
}

bool AcceptedChannelsAreCanonical(const ServiceDirectoryRow& row)
{
    if (row.accepted_count > kServiceDirectoryAcceptedCapacity ||
        row.next_accepted_hint >= kServiceDirectoryAcceptedCapacity)
    {
        return false;
    }
    u32 observed = 0;
    for (u32 index = 0; index < kServiceDirectoryAcceptedCapacity; ++index)
    {
        const ServiceDirectoryAcceptedChannel& accepted = row.accepted_channels[index];
        if (accepted.state == ServiceDirectoryAcceptedChannelState::Free ||
            accepted.state == ServiceDirectoryAcceptedChannelState::Retired)
        {
            if (!AcceptedKeyIsInactive(accepted.key) || ServiceEndpointOwnerReceiptIsValid(accepted.owner) ||
                ProcessKeyIsValid(accepted.server_process) || accepted.server_handle != ipc::kHandleInvalid ||
                accepted.process_teardown_deferred || accepted.release_driver_active)
            {
                return false;
            }
            if (accepted.state == ServiceDirectoryAcceptedChannelState::Retired &&
                accepted.key.generation != kServiceDirectoryAcceptedGenerationMaximum)
            {
                return false;
            }
            if (accepted.state == ServiceDirectoryAcceptedChannelState::Free &&
                accepted.key.generation == kServiceDirectoryAcceptedGenerationMaximum)
            {
                return false;
            }
            continue;
        }
        ++observed;
        if (!ServiceDirectoryAcceptedChannelKeyIsValid(accepted.key) || accepted.key.service != row.key ||
            accepted.key.slot != index || !ServiceEndpointOwnerReceiptIsValid(accepted.owner) ||
            !(accepted.owner.channel == accepted.key.channel) || !ProcessKeyIsValid(accepted.server_process))
        {
            return false;
        }
        if (accepted.state == ServiceDirectoryAcceptedChannelState::Publishing)
        {
            if (accepted.server_handle != ipc::kHandleInvalid || accepted.release_driver_active)
                return false;
        }
        else if (accepted.state == ServiceDirectoryAcceptedChannelState::Published)
        {
            if (accepted.server_handle == ipc::kHandleInvalid || accepted.release_driver_active)
                return false;
        }
        else if (accepted.state == ServiceDirectoryAcceptedChannelState::Releasing)
        {
            if (accepted.server_handle == ipc::kHandleInvalid)
                return false;
        }
        else
        {
            return false;
        }
    }
    return observed == row.accepted_count;
}

bool OwnedChannelIsCanonical(const ServiceDirectoryOwnedChannel& channel)
{
    if (ServiceDirectoryOwnedChannelIsEmpty(channel))
        return true;
    return ServiceEndpointOwnerReceiptIsValid(channel.owner) && !channel.release_driver_active;
}

bool ClosingChannelsAreCanonical(const ServiceDirectoryRow& row)
{
    if (row.closing_count > kServiceDirectoryCloseBatchCapacity ||
        row.close_batch_outstanding > kServiceDirectoryCloseBatchCapacity || row.close_driver_active > 1)
    {
        return false;
    }
    for (u32 index = 0; index < kServiceDirectoryCloseBatchCapacity; ++index)
    {
        if (index < row.closing_count)
        {
            if (!OwnedChannelIsCanonical(row.closing_channels[index]) ||
                ServiceDirectoryOwnedChannelIsEmpty(row.closing_channels[index]))
            {
                return false;
            }
        }
        else if (!ServiceDirectoryOwnedChannelIsEmpty(row.closing_channels[index]))
        {
            return false;
        }
    }
    if (row.close_driver_active != 0)
        return row.close_batch_outstanding != 0 && row.closing_count == 0;
    return row.close_batch_outstanding == 0;
}

bool RowIsZeroExceptState(const ServiceDirectoryRow& row)
{
    if (!NameIsZero(row.name) || !InstanceIsZero(row.owner) || !CredentialIsZero(row.owner_credential) ||
        !KeyIsZero(row.key) || row.reservation_authority != 0 || row.manifest_slot != 0 || row.active_operations != 0 ||
        row.next_operation_hint != 0 || row.accept_head != 0 || row.accept_count != 0 || row.accepted_count != 0 ||
        row.next_accepted_hint != 0 || row.external_publishers != 0 || row.closing_count != 0 ||
        row.close_batch_outstanding != 0 || row.close_driver_active != 0 || row.ready ||
        row.close_reason != ServiceDirectoryCloseReason::None)
    {
        return false;
    }
    const u8* operation_bytes = reinterpret_cast<const u8*>(row.operation_slots);
    for (usize index = 0; index < sizeof(row.operation_slots); ++index)
    {
        if (operation_bytes[index] != 0)
            return false;
    }
    const u8* queue_bytes = reinterpret_cast<const u8*>(row.accept_queue);
    for (usize index = 0; index < sizeof(row.accept_queue); ++index)
    {
        if (queue_bytes[index] != 0)
            return false;
    }
    const u8* accepted_bytes = reinterpret_cast<const u8*>(row.accepted_channels);
    for (usize index = 0; index < sizeof(row.accepted_channels); ++index)
    {
        if (accepted_bytes[index] != 0)
            return false;
    }
    for (u32 index = 0; index < kServiceDirectoryCloseBatchCapacity; ++index)
    {
        if (!ServiceDirectoryOwnedChannelIsEmpty(row.closing_channels[index]))
            return false;
    }
    return true;
}

bool RowIsCanonical(const ServiceDirectoryRow& row)
{
    if (row.state == ServiceDirectoryEntryState::Empty || row.state == ServiceDirectoryEntryState::Retired)
        return RowIsZeroExceptState(row);
    if (!ServiceDirectoryNameIsCanonical(row.name) || !ServiceInstanceTokenIsValid(row.owner) ||
        !ServiceEndpointCredentialSnapshotIsCanonical(row.owner_credential) || !ServiceKeyIsValid(row.key) ||
        row.key.slot >= kServiceDirectoryCapacity || row.manifest_slot >= kServiceDirectoryCapacity ||
        !OperationSlotsAreCanonical(row) || !AcceptQueueIsCanonical(row) || !AcceptedChannelsAreCanonical(row) ||
        !ClosingChannelsAreCanonical(row))
    {
        return false;
    }
    switch (row.state)
    {
    case ServiceDirectoryEntryState::Reserved:
        return row.reservation_authority == row.key.generation && row.active_operations == 0 && row.accept_count == 0 &&
               row.accepted_count == 0 && row.external_publishers == 0 && row.closing_count == 0 &&
               row.close_batch_outstanding == 0 && row.close_driver_active == 0 && !row.ready &&
               row.close_reason == ServiceDirectoryCloseReason::None;
    case ServiceDirectoryEntryState::Active:
        return row.reservation_authority == 0 && row.closing_count == 0 && row.close_batch_outstanding == 0 &&
               row.close_driver_active == 0 && row.close_reason == ServiceDirectoryCloseReason::None;
    case ServiceDirectoryEntryState::Closing:
        return (row.reservation_authority == 0 || row.reservation_authority == row.key.generation) && !row.ready &&
               row.close_reason != ServiceDirectoryCloseReason::None;
    case ServiceDirectoryEntryState::Empty:
    case ServiceDirectoryEntryState::Retired:
        return false;
    }
    return false;
}

bool DirectoryBodyIsCanonicalZero(const ServiceDirectory& directory)
{
    if (directory.state != ServiceDirectoryState::Uninitialized || directory.endpoint_owner != nullptr ||
        directory.deferred_scan_hint != 0)
        return false;
#if defined(DUETOS_HOST_TEST)
    if (directory.lock.next_ticket != 0 || directory.lock.now_serving != 0)
        return false;
#else
    if (directory.lock.next_ticket != 0 || directory.lock.now_serving != 0 || directory.lock.owner_cpu != 0 ||
        directory.lock.class_id != 0)
    {
        return false;
    }
#endif
    for (u32 index = 0; index < kServiceDirectoryCapacity; ++index)
    {
        if (directory.rows[index].state != ServiceDirectoryEntryState::Empty ||
            !RowIsZeroExceptState(directory.rows[index]))
        {
            return false;
        }
    }
    return true;
}

bool DirectoryIsCanonicalLocked(const ServiceDirectory& directory)
{
    if (directory.state != ServiceDirectoryState::Open || directory.endpoint_owner == nullptr ||
        directory.deferred_scan_hint >= kServiceDirectoryDeferredAcceptedCapacity)
        return false;
    for (u32 index = 0; index < kServiceDirectoryCapacity; ++index)
    {
        if (!RowIsCanonical(directory.rows[index]))
            return false;
        if (directory.rows[index].state != ServiceDirectoryEntryState::Empty &&
            directory.rows[index].state != ServiceDirectoryEntryState::Retired &&
            directory.rows[index].key.slot != index)
        {
            return false;
        }
    }
    return true;
}

ServiceDirectoryStatus ReadyStatus(ServiceDirectory* directory)
{
    if (directory == nullptr)
        return ServiceDirectoryStatus::InvalidArgument;
    return AtomicLoadAcquire(&directory->initialized) == kDirectoryInitializeReady
               ? ServiceDirectoryStatus::Ok
               : ServiceDirectoryStatus::NotInitialized;
}

void InitializeDirectoryLock(ServiceDirectory& directory)
{
    directory.lock.next_ticket = 0;
    directory.lock.now_serving = 0;
#if !defined(DUETOS_HOST_TEST)
    directory.lock.owner_cpu = 0xFFFFFFFFu;
    directory.lock.class_id = sync::kLockClassUnclassified;
#endif
}

u64 AllocateServiceGeneration(u32 slot)
{
    u64 current = AtomicLoadGeneration(&g_last_service_generations[slot]);
    while (current < kServiceKeyGenerationMaximum)
    {
        const u64 next = current + 1;
        u64 expected = current;
        if (AtomicCompareExchangeGeneration(&g_last_service_generations[slot], &expected, next))
            return next;
        current = expected;
    }
    return 0;
}

ServiceDirectoryRow* ResolveExactLocked(ServiceDirectory& directory, ServiceKey key)
{
    if (!ServiceKeyIsValid(key))
        return nullptr;
    ServiceDirectoryRow& row = directory.rows[key.slot];
    if (row.state == ServiceDirectoryEntryState::Empty || row.state == ServiceDirectoryEntryState::Retired ||
        !(row.key == key))
    {
        return nullptr;
    }
    return &row;
}

void ClearRowLocked(ServiceDirectoryRow& row, bool terminal)
{
    row = ServiceDirectoryRow{};
    row.state = terminal ? ServiceDirectoryEntryState::Retired : ServiceDirectoryEntryState::Empty;
}

bool TryRecycleLocked(ServiceDirectoryRow& row)
{
    if (row.state != ServiceDirectoryEntryState::Closing || row.reservation_authority != 0 ||
        row.active_operations != 0 || row.accept_count != 0 || row.accepted_count != 0 ||
        row.external_publishers != 0 || row.closing_count != 0 || row.close_batch_outstanding != 0 ||
        row.close_driver_active != 0)
    {
        return false;
    }
    const bool terminal = row.key.generation == kServiceKeyGenerationMaximum;
    ClearRowLocked(row, terminal);
    return true;
}

ServiceDirectoryStatus ValidateOperationLocked(const ServiceDirectoryRow& row, ServiceDirectoryOperationPin pin)
{
    if (!(row.key == pin.service))
        return ServiceDirectoryStatus::StaleKey;
    if (pin.slot >= kServiceDirectoryOperationCapacity || pin.generation == 0)
        return ServiceDirectoryStatus::InvalidArgument;
    const ServiceDirectoryOperationSlot& slot = row.operation_slots[pin.slot];
    if (slot.state != ServiceDirectoryOperationSlotState::Live || slot.generation != pin.generation)
        return ServiceDirectoryStatus::StaleOperation;
    return ServiceDirectoryStatus::Ok;
}

void EnqueueTailLocked(ServiceDirectoryRow& row, ServiceDirectoryQueuedChannel queued)
{
    const u32 slot = (row.accept_head + row.accept_count) % kServiceDirectoryAcceptCapacity;
    row.accept_queue[slot] = queued;
    ++row.accept_count;
}

void EnqueueFrontLocked(ServiceDirectoryRow& row, ServiceDirectoryQueuedChannel queued)
{
    row.accept_head = (row.accept_head + kServiceDirectoryAcceptCapacity - 1U) % kServiceDirectoryAcceptCapacity;
    row.accept_queue[row.accept_head] = queued;
    ++row.accept_count;
}

ServiceDirectoryQueuedChannel DequeueLocked(ServiceDirectoryRow& row)
{
    const u32 slot = row.accept_head;
    const ServiceDirectoryQueuedChannel queued = row.accept_queue[slot];
    row.accept_queue[slot] = {};
    row.accept_head = (row.accept_head + 1U) % kServiceDirectoryAcceptCapacity;
    --row.accept_count;
    if (row.accept_count == 0)
        row.accept_head = 0;
    return queued;
}

bool RemoveQueuedLocked(ServiceDirectoryRow& row, ServiceEndpointChannelKey channel,
                        ServiceDirectoryQueuedChannel* removed)
{
    for (u32 offset = 0; offset < row.accept_count; ++offset)
    {
        const u32 slot = (row.accept_head + offset) % kServiceDirectoryAcceptCapacity;
        if (!(row.accept_queue[slot].channel == channel))
            continue;
        *removed = row.accept_queue[slot];
        for (u32 shift = offset; shift + 1U < row.accept_count; ++shift)
        {
            const u32 destination = (row.accept_head + shift) % kServiceDirectoryAcceptCapacity;
            const u32 source = (row.accept_head + shift + 1U) % kServiceDirectoryAcceptCapacity;
            row.accept_queue[destination] = row.accept_queue[source];
        }
        const u32 tail = (row.accept_head + row.accept_count - 1U) % kServiceDirectoryAcceptCapacity;
        row.accept_queue[tail] = {};
        --row.accept_count;
        if (row.accept_count == 0)
            row.accept_head = 0;
        return true;
    }
    return false;
}

void ClearAcceptedLocked(ServiceDirectoryAcceptedChannel& accepted)
{
    const u32 generation = accepted.key.generation;
    accepted = {};
    accepted.key.generation = generation;
    accepted.state = generation == kServiceDirectoryAcceptedGenerationMaximum
                         ? ServiceDirectoryAcceptedChannelState::Retired
                         : ServiceDirectoryAcceptedChannelState::Free;
}

ServiceDirectoryAcceptedChannel* AllocateAcceptedLocked(ServiceDirectoryRow& row, ServiceEndpointChannelKey channel,
                                                        ProcessKey server_process)
{
    for (u32 offset = 0; offset < kServiceDirectoryAcceptedCapacity; ++offset)
    {
        const u32 index = (row.next_accepted_hint + offset) % kServiceDirectoryAcceptedCapacity;
        ServiceDirectoryAcceptedChannel& accepted = row.accepted_channels[index];
        if (accepted.state != ServiceDirectoryAcceptedChannelState::Free ||
            accepted.key.generation == kServiceDirectoryAcceptedGenerationMaximum)
        {
            continue;
        }
        const u32 generation = accepted.key.generation + 1U;
        accepted = {};
        accepted.key = ServiceDirectoryAcceptedChannelKey{row.key, index, generation, channel};
        accepted.server_process = server_process;
        accepted.state = ServiceDirectoryAcceptedChannelState::Publishing;
        row.next_accepted_hint = (index + 1U) % kServiceDirectoryAcceptedCapacity;
        ++row.accepted_count;
        return &accepted;
    }
    return nullptr;
}

ServiceDirectoryAcceptedChannel* ResolveAcceptedLocked(ServiceDirectoryRow& row, ServiceDirectoryAcceptedChannelKey key)
{
    if (!ServiceDirectoryAcceptedChannelKeyIsValid(key) || !(key.service == row.key))
        return nullptr;
    ServiceDirectoryAcceptedChannel& accepted = row.accepted_channels[key.slot];
    if (accepted.state == ServiceDirectoryAcceptedChannelState::Free ||
        accepted.state == ServiceDirectoryAcceptedChannelState::Retired || !(accepted.key == key))
    {
        return nullptr;
    }
    return &accepted;
}

bool HasAcceptedReleaseDriverLocked(const ServiceDirectoryRow& row)
{
    for (u32 index = 0; index < kServiceDirectoryAcceptedCapacity; ++index)
    {
        if (row.accepted_channels[index].release_driver_active)
            return true;
    }
    return false;
}

bool AbortReservationIsSafe(ipc::HandleTable& table, ipc::HandleTableReservation reservation)
{
    const Result<void> aborted = ipc::HandleTableAbort(table, reservation);
    return aborted.has_value() || aborted.error() == ErrorCode::BadState ||
           aborted.error() == ErrorCode::InvalidArgument;
}

bool DetachPublishedHandleIsSafe(ipc::HandleTable& table, ipc::Handle handle)
{
    Result<ipc::KObject*> detached = ipc::HandleTableDetach(table, handle, ipc::KObjectType::ServiceEndpoint, 0);
    if (detached.has_value())
    {
        ipc::KObjectRelease(detached.value());
        return true;
    }
    // A concurrent exact close or terminal table drain already owns/released
    // the reference. Generation tagging prevents either status from naming a
    // replacement object.
    return detached.error() == ErrorCode::BadState || detached.error() == ErrorCode::InvalidArgument;
}

ServiceDirectoryStatus CleanupPrivatePair(ServiceEndpointPair* pair, ServiceDirectoryOwnedChannel* rollback,
                                          ServiceEndpointStatus* endpoint_status)
{
    ipc::KObject* initiator = pair->initiator;
    pair->initiator = nullptr;
    if (initiator != nullptr)
        ipc::KObjectRelease(initiator);

    rollback->owner = pair->owner;
    rollback->unpublished_acceptor = pair->acceptor;
    pair->owner = kInvalidServiceEndpointOwnerReceipt;
    pair->acceptor = nullptr;
    pair->activation = kInvalidServiceEndpointActivationTicket;
    *endpoint_status = ServiceDirectoryDrainOwnedChannel(rollback);
    return *endpoint_status == ServiceEndpointStatus::Ok ? ServiceDirectoryStatus::Ok
                                                         : ServiceDirectoryStatus::EndpointReleaseFailed;
}

ServiceDirectoryCloseResult CloseEntry(ServiceDirectory* directory, ServiceKey service, ServiceInstanceToken owner,
                                       ServiceDirectoryCloseReason reason)
{
    if (!ServiceKeyIsValid(service) || !ServiceInstanceTokenIsValid(owner) ||
        reason == ServiceDirectoryCloseReason::None || reason == ServiceDirectoryCloseReason::RegistrationAbort)
    {
        return CloseFailure(ServiceDirectoryStatus::InvalidArgument);
    }
    const ServiceDirectoryStatus ready = ReadyStatus(directory);
    if (ready != ServiceDirectoryStatus::Ok)
        return CloseFailure(ready);

    ServiceDirectoryCloseBatch batch{};
    {
        DirectoryGuard guard(*directory);
        if (!DirectoryIsCanonicalLocked(*directory))
            return CloseFailure(ServiceDirectoryStatus::CorruptState);
        ServiceDirectoryRow* row = ResolveExactLocked(*directory, service);
        if (row == nullptr)
            return CloseFailure(ServiceDirectoryStatus::StaleKey);
        if (!(row->owner == owner))
            return CloseFailure(ServiceDirectoryStatus::OwnerMismatch);

        if (row->state == ServiceDirectoryEntryState::Reserved || row->state == ServiceDirectoryEntryState::Active)
        {
            row->ready = false;
            row->state = ServiceDirectoryEntryState::Closing;
            row->close_reason = reason;
        }
        else if (row->state != ServiceDirectoryEntryState::Closing)
        {
            return CloseFailure(ServiceDirectoryStatus::StaleKey);
        }

        if (row->close_driver_active != 0 || HasAcceptedReleaseDriverLocked(*row))
            return CloseFailure(ServiceDirectoryStatus::Busy);

        if (row->closing_count != 0)
        {
            batch.count = row->closing_count;
            for (u32 index = 0; index < batch.count; ++index)
            {
                batch.channels[index] = row->closing_channels[index];
                row->closing_channels[index] = {};
            }
            row->closing_count = 0;
        }
        else
        {
            while (row->accept_count != 0)
            {
                const ServiceDirectoryQueuedChannel queued = DequeueLocked(*row);
                batch.channels[batch.count++] = queued.owned;
            }
            for (u32 index = 0; index < kServiceDirectoryAcceptedCapacity; ++index)
            {
                ServiceDirectoryAcceptedChannel& accepted = row->accepted_channels[index];
                if (accepted.state == ServiceDirectoryAcceptedChannelState::Free ||
                    accepted.state == ServiceDirectoryAcceptedChannelState::Retired)
                {
                    continue;
                }
                // Process teardown already transferred this exact owner into
                // durable deferred state. Keep its ProcessKey, generations,
                // and strong receipt in place; scheduler maintenance is the
                // sole driver that may clear it after endpoint release succeeds.
                if (accepted.process_teardown_deferred)
                    continue;
                batch.channels[batch.count++].owner = accepted.owner;
                ClearAcceptedLocked(accepted);
                --row->accepted_count;
            }
        }

        if (batch.count == 0)
        {
            const bool recycled = TryRecycleLocked(*row);
            return CloseFailure(recycled ? ServiceDirectoryStatus::Ok : ServiceDirectoryStatus::Busy);
        }
        row->close_batch_outstanding = batch.count;
        row->close_driver_active = 1;
    }

    u32 drained = 0;
    u32 failed = 0;
    ServiceEndpointStatus first_failure = ServiceEndpointStatus::Ok;
    for (u32 index = 0; index < batch.count; ++index)
    {
        const ServiceEndpointStatus endpoint_status = ServiceDirectoryDrainOwnedChannel(&batch.channels[index]);
        if (endpoint_status == ServiceEndpointStatus::Ok)
        {
            ++drained;
            continue;
        }
        if (first_failure == ServiceEndpointStatus::Ok)
            first_failure = endpoint_status;
        if (failed != index)
            batch.channels[failed] = batch.channels[index];
        ++failed;
    }
    for (u32 index = failed; index < batch.count; ++index)
        batch.channels[index] = {};

    bool recycled = false;
    {
        DirectoryGuard guard(*directory);
        if (!DirectoryIsCanonicalLocked(*directory))
            return CloseFailure(ServiceDirectoryStatus::CorruptState, first_failure, drained);
        ServiceDirectoryRow* row = ResolveExactLocked(*directory, service);
        if (row == nullptr || !(row->owner == owner) || row->state != ServiceDirectoryEntryState::Closing ||
            row->close_driver_active != 1 || row->close_batch_outstanding != batch.count)
        {
            return CloseFailure(ServiceDirectoryStatus::CorruptState, first_failure, drained);
        }
        row->close_driver_active = 0;
        row->close_batch_outstanding = 0;
        row->closing_count = failed;
        for (u32 index = 0; index < failed; ++index)
            row->closing_channels[index] = batch.channels[index];
        recycled = TryRecycleLocked(*row);
    }

    if (failed != 0)
        return CloseFailure(ServiceDirectoryStatus::EndpointReleaseFailed, first_failure, drained);
    return CloseFailure(recycled ? ServiceDirectoryStatus::Ok : ServiceDirectoryStatus::Busy, ServiceEndpointStatus::Ok,
                        drained);
}

} // namespace

bool ServiceDirectoryNameIsCanonical(const ServiceDirectoryName& name)
{
    if (name.length == 0 || name.length > kServiceDirectoryNameCapacity)
        return false;
    for (u32 index = 0; index < name.length; ++index)
    {
        if (!NameCharacterIsCanonical(name.bytes[index], index == 0))
            return false;
    }
    for (u32 index = name.length; index < kServiceDirectoryNameCapacity; ++index)
    {
        if (name.bytes[index] != 0)
            return false;
    }
    return true;
}

ServiceDirectoryStatus ServiceDirectoryInitialize(ServiceDirectory* directory, ServiceEndpointOwner* endpoint_owner)
{
    if (directory == nullptr || endpoint_owner == nullptr)
        return ServiceDirectoryStatus::InvalidArgument;
    if (!ServiceEndpointOwnerIsReady(endpoint_owner))
        return ServiceDirectoryStatus::NotInitialized;
    u32 expected = kDirectoryInitializeUninitialized;
    if (!AtomicCompareExchange(&directory->initialized, &expected, kDirectoryInitializeInProgress))
        return ServiceDirectoryStatus::AlreadyInitialized;
    if (!DirectoryBodyIsCanonicalZero(*directory))
    {
        AtomicStoreRelease(&directory->initialized, kDirectoryInitializeUninitialized);
        return ServiceDirectoryStatus::CorruptState;
    }
    InitializeDirectoryLock(*directory);
    directory->endpoint_owner = endpoint_owner;
    directory->state = ServiceDirectoryState::Open;
    AtomicStoreRelease(&directory->initialized, kDirectoryInitializeReady);
    return ServiceDirectoryStatus::Ok;
}

ServiceDirectoryStatus ServiceDirectoryValidateRuntimeOwner(ServiceDirectory* directory,
                                                            const ServiceEndpointOwner* expected_endpoint_owner)
{
    if (expected_endpoint_owner == nullptr)
        return ServiceDirectoryStatus::InvalidArgument;
    const ServiceDirectoryStatus ready = ReadyStatus(directory);
    if (ready != ServiceDirectoryStatus::Ok)
        return ready;

    DirectoryGuard guard(*directory);
    if (!DirectoryIsCanonicalLocked(*directory))
        return ServiceDirectoryStatus::CorruptState;
    return directory->endpoint_owner == expected_endpoint_owner ? ServiceDirectoryStatus::Ok
                                                                : ServiceDirectoryStatus::CorruptState;
}

ServiceDirectoryReserveResult ServiceDirectoryReserveRegistration(
    ServiceDirectory* directory, const ServiceDirectoryName* name, u32 manifest_slot, ServiceInstanceToken owner,
    const ServiceEndpointCredentialSnapshot* owner_credential)
{
    if (name == nullptr || !ServiceDirectoryNameIsCanonical(*name) || manifest_slot >= kServiceDirectoryCapacity ||
        !ServiceInstanceTokenIsValid(owner) || owner_credential == nullptr ||
        !ServiceEndpointCredentialSnapshotIsCanonical(*owner_credential))
    {
        return ReserveFailure(ServiceDirectoryStatus::InvalidArgument);
    }
    const ServiceDirectoryName name_snapshot = *name;
    const ServiceEndpointCredentialSnapshot credential_snapshot = *owner_credential;
    const ServiceDirectoryStatus ready = ReadyStatus(directory);
    if (ready != ServiceDirectoryStatus::Ok)
        return ReserveFailure(ready);

    DirectoryGuard guard(*directory);
    if (!DirectoryIsCanonicalLocked(*directory))
        return ReserveFailure(ServiceDirectoryStatus::CorruptState);
    for (u32 index = 0; index < kServiceDirectoryCapacity; ++index)
    {
        const ServiceDirectoryRow& row = directory->rows[index];
        if (row.state == ServiceDirectoryEntryState::Empty || row.state == ServiceDirectoryEntryState::Retired)
            continue;
        if (NameEquals(row.name, name_snapshot))
            return ReserveFailure(ServiceDirectoryStatus::NameConflict);
        if (row.owner.start.service_identity == owner.start.service_identity)
            return ReserveFailure(ServiceDirectoryStatus::ServiceConflict);
    }

    bool generation_exhausted = false;
    for (u32 slot_index = 0; slot_index < kServiceDirectoryCapacity; ++slot_index)
    {
        ServiceDirectoryRow& row = directory->rows[slot_index];
        if (row.state != ServiceDirectoryEntryState::Empty)
            continue;
        const u64 generation = AllocateServiceGeneration(slot_index);
        if (generation == 0)
        {
            ClearRowLocked(row, true);
            generation_exhausted = true;
            continue;
        }
        row.name = name_snapshot;
        row.owner = owner;
        row.owner_credential = credential_snapshot;
        row.key = ServiceKey{slot_index, generation};
        row.reservation_authority = generation;
        row.manifest_slot = manifest_slot;
        row.state = ServiceDirectoryEntryState::Reserved;
        return ServiceDirectoryReserveResult{ServiceDirectoryStatus::Ok,
                                             ServiceRegistrationReservation{row.key, generation}};
    }
    return ReserveFailure(generation_exhausted ? ServiceDirectoryStatus::GenerationExhausted
                                               : ServiceDirectoryStatus::CapacityExhausted);
}

ServiceDirectoryStatus ServiceDirectoryPublishRegistration(ServiceDirectory* directory,
                                                           ServiceRegistrationReservation* reservation,
                                                           ServiceInstanceToken owner)
{
    if (reservation == nullptr || !ServiceRegistrationReservationIsValid(*reservation) ||
        !ServiceInstanceTokenIsValid(owner))
    {
        return ServiceDirectoryStatus::InvalidArgument;
    }
    const ServiceRegistrationReservation supplied = *reservation;
    const ServiceDirectoryStatus ready = ReadyStatus(directory);
    if (ready != ServiceDirectoryStatus::Ok)
        return ready;
    {
        DirectoryGuard guard(*directory);
        if (!DirectoryIsCanonicalLocked(*directory))
            return ServiceDirectoryStatus::CorruptState;
        ServiceDirectoryRow* row = ResolveExactLocked(*directory, supplied.service);
        if (row == nullptr)
            return ServiceDirectoryStatus::StaleKey;
        if (!(row->owner == owner))
            return ServiceDirectoryStatus::OwnerMismatch;
        if (row->state == ServiceDirectoryEntryState::Closing)
            return ServiceDirectoryStatus::Closing;
        if (row->state != ServiceDirectoryEntryState::Reserved ||
            row->reservation_authority != supplied.authority_generation)
        {
            return ServiceDirectoryStatus::ReservationConsumed;
        }
#if defined(DUETOS_HOST_TEST)
        if (g_fail_registration_publication.exchange(false, std::memory_order_acq_rel))
            return ServiceDirectoryStatus::Busy;
#endif
        row->reservation_authority = 0;
        row->ready = false;
        row->state = ServiceDirectoryEntryState::Active;
    }
    *reservation = kInvalidServiceRegistrationReservation;
    return ServiceDirectoryStatus::Ok;
}

ServiceDirectoryStatus ServiceDirectoryCommitJointReady(ServiceDirectory* directory, ServiceKey service,
                                                        ServiceInstanceToken owner, bool* lifecycle_ready)
{
    if (!ServiceKeyIsValid(service) || !ServiceInstanceTokenIsValid(owner) || lifecycle_ready == nullptr)
        return ServiceDirectoryStatus::InvalidArgument;
    const ServiceDirectoryStatus ready = ReadyStatus(directory);
    if (ready != ServiceDirectoryStatus::Ok)
        return ready;

    DirectoryGuard guard(*directory);
    if (!DirectoryIsCanonicalLocked(*directory))
        return ServiceDirectoryStatus::CorruptState;
    ServiceDirectoryRow* row = ResolveExactLocked(*directory, service);
    if (row == nullptr)
        return ServiceDirectoryStatus::StaleKey;
    if (!(row->owner == owner))
        return ServiceDirectoryStatus::OwnerMismatch;
    if (row->state == ServiceDirectoryEntryState::Closing)
        return ServiceDirectoryStatus::Closing;
    if (row->state != ServiceDirectoryEntryState::Active)
        return ServiceDirectoryStatus::NotReady;

    // Both exact identities and states are now validated while the caller's
    // higher-ranked broker lock and this directory lock are held. These are the
    // only writes, in externally visible admission order, and neither can fail.
    row->ready = true;
    *lifecycle_ready = true;
    return ServiceDirectoryStatus::Ok;
}

ServiceDirectoryStatus ServiceDirectoryAbortRegistration(ServiceDirectory* directory,
                                                         ServiceRegistrationReservation* reservation,
                                                         ServiceInstanceToken owner)
{
    if (reservation == nullptr || !ServiceRegistrationReservationIsValid(*reservation) ||
        !ServiceInstanceTokenIsValid(owner))
    {
        return ServiceDirectoryStatus::InvalidArgument;
    }
    const ServiceRegistrationReservation supplied = *reservation;
    const ServiceDirectoryStatus ready = ReadyStatus(directory);
    if (ready != ServiceDirectoryStatus::Ok)
        return ready;
    {
        DirectoryGuard guard(*directory);
        if (!DirectoryIsCanonicalLocked(*directory))
            return ServiceDirectoryStatus::CorruptState;
        ServiceDirectoryRow* row = ResolveExactLocked(*directory, supplied.service);
        if (row == nullptr)
            return ServiceDirectoryStatus::StaleKey;
        if (!(row->owner == owner))
            return ServiceDirectoryStatus::OwnerMismatch;
        if ((row->state != ServiceDirectoryEntryState::Reserved && row->state != ServiceDirectoryEntryState::Closing) ||
            row->reservation_authority != supplied.authority_generation)
        {
            return ServiceDirectoryStatus::ReservationConsumed;
        }
        row->reservation_authority = 0;
        if (row->state == ServiceDirectoryEntryState::Reserved)
        {
            row->ready = false;
            row->state = ServiceDirectoryEntryState::Closing;
            row->close_reason = ServiceDirectoryCloseReason::RegistrationAbort;
        }
        TryRecycleLocked(*row);
    }
    *reservation = kInvalidServiceRegistrationReservation;
    return ServiceDirectoryStatus::Ok;
}

ServiceDirectoryLookupResult ServiceDirectoryLookup(ServiceDirectory* directory, const ServiceDirectoryName* name)
{
    if (name == nullptr || !ServiceDirectoryNameIsCanonical(*name))
        return LookupFailure(ServiceDirectoryStatus::InvalidArgument);
    const ServiceDirectoryName supplied = *name;
    const ServiceDirectoryStatus ready = ReadyStatus(directory);
    if (ready != ServiceDirectoryStatus::Ok)
        return LookupFailure(ready);

    DirectoryGuard guard(*directory);
    if (!DirectoryIsCanonicalLocked(*directory))
        return LookupFailure(ServiceDirectoryStatus::CorruptState);
    for (u32 row_index = 0; row_index < kServiceDirectoryCapacity; ++row_index)
    {
        ServiceDirectoryRow& row = directory->rows[row_index];
        if (row.state == ServiceDirectoryEntryState::Empty || row.state == ServiceDirectoryEntryState::Retired ||
            !NameEquals(row.name, supplied))
        {
            continue;
        }
        if (row.state == ServiceDirectoryEntryState::Reserved)
            return LookupFailure(ServiceDirectoryStatus::NotReady);
        if (row.state == ServiceDirectoryEntryState::Closing)
            return LookupFailure(ServiceDirectoryStatus::Closing);
        if (row.state != ServiceDirectoryEntryState::Active)
            return LookupFailure(ServiceDirectoryStatus::CorruptState);
        for (u32 offset = 0; offset < kServiceDirectoryOperationCapacity; ++offset)
        {
            const u32 slot_index = (row.next_operation_hint + offset) % kServiceDirectoryOperationCapacity;
            ServiceDirectoryOperationSlot& slot = row.operation_slots[slot_index];
            if (slot.state != ServiceDirectoryOperationSlotState::Free ||
                slot.generation == kServiceDirectoryOperationGenerationMaximum)
            {
                continue;
            }
            ++slot.generation;
            slot.state = ServiceDirectoryOperationSlotState::Live;
            ++row.active_operations;
            row.next_operation_hint = (slot_index + 1U) % kServiceDirectoryOperationCapacity;
            return ServiceDirectoryLookupResult{ServiceDirectoryStatus::Ok,
                                                ServiceDirectoryOperationPin{row.key, slot_index, slot.generation}};
        }
        return LookupFailure(ServiceDirectoryStatus::OperationIdentityExhausted);
    }
    return LookupFailure(ServiceDirectoryStatus::NotFound);
}

ServiceDirectoryStatus ServiceDirectoryReleaseOperation(ServiceDirectory* directory, ServiceDirectoryOperationPin* pin)
{
    if (pin == nullptr || !ServiceDirectoryOperationPinIsValid(*pin))
        return ServiceDirectoryStatus::InvalidArgument;
    const ServiceDirectoryOperationPin supplied = *pin;
    const ServiceDirectoryStatus ready = ReadyStatus(directory);
    if (ready != ServiceDirectoryStatus::Ok)
        return ready;
    {
        DirectoryGuard guard(*directory);
        if (!DirectoryIsCanonicalLocked(*directory))
            return ServiceDirectoryStatus::CorruptState;
        ServiceDirectoryRow* row = ResolveExactLocked(*directory, supplied.service);
        if (row == nullptr)
            return ServiceDirectoryStatus::StaleKey;
        const ServiceDirectoryStatus validation = ValidateOperationLocked(*row, supplied);
        if (validation != ServiceDirectoryStatus::Ok)
            return validation;
        ServiceDirectoryOperationSlot& slot = row->operation_slots[supplied.slot];
        slot.state = slot.generation == kServiceDirectoryOperationGenerationMaximum
                         ? ServiceDirectoryOperationSlotState::Retired
                         : ServiceDirectoryOperationSlotState::Free;
        --row->active_operations;
        TryRecycleLocked(*row);
    }
    *pin = kInvalidServiceDirectoryOperationPin;
    return ServiceDirectoryStatus::Ok;
}

ServiceDirectoryConnectResult ServiceDirectoryConnect(ServiceDirectory* directory, ServiceDirectoryOperationPin pin,
                                                      ResourceDomainKey resource_domain,
                                                      ipc::HandleTable* client_handles, ProcessKey client_process,
                                                      const ServiceEndpointCredentialSnapshot* client_credential,
                                                      const ServiceEndpointProtocolAuthority* protocol,
                                                      u64 client_handle_rights,
                                                      const ServiceDirectoryRequestCleanupSink* cleanup_sink)
{
    if (!ServiceDirectoryOperationPinIsValid(pin) || !ResourceDomainKeyIsValid(resource_domain) ||
        client_handles == nullptr || !ProcessKeyIsValid(client_process) || client_credential == nullptr ||
        !ServiceEndpointCredentialSnapshotIsCanonical(*client_credential) || protocol == nullptr ||
        !ServiceEndpointProtocolAuthorityIsCanonical(*protocol) || client_handle_rights == 0 ||
        !ServiceDirectoryRequestCleanupSinkIsValid(cleanup_sink))
    {
        return ConnectFailure(ServiceDirectoryStatus::InvalidArgument);
    }
    const ServiceEndpointCredentialSnapshot client_credential_snapshot = *client_credential;
    const ServiceEndpointProtocolAuthority protocol_snapshot = *protocol;
    const ServiceDirectoryRequestCleanupSink cleanup_snapshot = *cleanup_sink;
    const ServiceDirectoryStatus ready = ReadyStatus(directory);
    if (ready != ServiceDirectoryStatus::Ok)
        return ConnectFailure(ready);

    ServiceEndpointPeerSnapshot server_peer{};
    ServiceEndpointOwner* endpoint_owner = nullptr;
    {
        DirectoryGuard guard(*directory);
        if (!DirectoryIsCanonicalLocked(*directory))
            return ConnectFailure(ServiceDirectoryStatus::CorruptState);
        ServiceDirectoryRow* row = ResolveExactLocked(*directory, pin.service);
        if (row == nullptr)
            return ConnectFailure(ServiceDirectoryStatus::StaleKey);
        if (row->state == ServiceDirectoryEntryState::Closing)
            return ConnectFailure(ServiceDirectoryStatus::Closing);
        if (row->state != ServiceDirectoryEntryState::Active)
            return ConnectFailure(ServiceDirectoryStatus::NotReady);
        if (!row->ready)
            return ConnectFailure(ServiceDirectoryStatus::NotReady);
        const ServiceDirectoryStatus validation = ValidateOperationLocked(*row, pin);
        if (validation != ServiceDirectoryStatus::Ok)
            return ConnectFailure(validation);
        if (protocol_snapshot.service_identity != row->owner.start.service_identity)
            return ConnectFailure(ServiceDirectoryStatus::ProtocolMismatch);
        server_peer = ServiceEndpointPeerSnapshot{ProcessKeyFromInstance(row->owner.process), row->owner_credential};
        endpoint_owner = directory->endpoint_owner;
    }

    Result<ipc::HandleTableReservation> reserved =
        ipc::HandleTableReserve(*client_handles, ipc::KObjectType::ServiceEndpoint, client_handle_rights);
    if (!reserved.has_value())
        return ConnectFailure(ServiceDirectoryStatus::HandleReserveFailed, ServiceEndpointStatus::Ok, reserved.error());
    const ipc::HandleTableReservation handle_reservation = reserved.value();

    const ServiceEndpointPeerSnapshot client_peer{client_process, client_credential_snapshot};
    ServiceEndpointPairCreateResult created = ServiceEndpointCreatePair(
        endpoint_owner, resource_domain, &protocol_snapshot, &client_peer, &server_peer, &cleanup_snapshot);
    if (created.status != ServiceEndpointStatus::Ok)
    {
        const bool aborted = AbortReservationIsSafe(*client_handles, handle_reservation);
        return ConnectFailure(aborted ? ServiceDirectoryStatus::EndpointCreateFailed
                                      : ServiceDirectoryStatus::HandleRollbackFailed,
                              created.status, aborted ? ErrorCode::Ok : ErrorCode::BadState);
    }
    ServiceEndpointPair pair = created.pair;

    ServiceDirectoryStatus enqueue_status = ServiceDirectoryStatus::Ok;
    {
        DirectoryGuard guard(*directory);
        if (!DirectoryIsCanonicalLocked(*directory))
            enqueue_status = ServiceDirectoryStatus::CorruptState;
        else
        {
            ServiceDirectoryRow* row = ResolveExactLocked(*directory, pin.service);
            if (row == nullptr)
                enqueue_status = ServiceDirectoryStatus::StaleKey;
            else if (row->state == ServiceDirectoryEntryState::Closing)
                enqueue_status = ServiceDirectoryStatus::Closing;
            else if (row->state != ServiceDirectoryEntryState::Active)
                enqueue_status = ServiceDirectoryStatus::NotReady;
            else if (!row->ready)
                enqueue_status = ServiceDirectoryStatus::NotReady;
            else
            {
                enqueue_status = ValidateOperationLocked(*row, pin);
                if (enqueue_status == ServiceDirectoryStatus::Ok)
                {
                    if (row->accept_count == kServiceDirectoryAcceptCapacity)
                    {
                        enqueue_status = ServiceDirectoryStatus::QueueFull;
                    }
                    else
                    {
                        ServiceDirectoryQueuedChannel queued{};
                        queued.owned.owner = pair.owner;
                        queued.owned.unpublished_acceptor = pair.acceptor;
                        queued.channel = pair.owner.channel;
                        queued.state = ServiceDirectoryQueuedChannelState::PendingClientPublish;
                        EnqueueTailLocked(*row, queued);
                        ++row->external_publishers;
                        pair.owner = kInvalidServiceEndpointOwnerReceipt;
                        pair.acceptor = nullptr;
                    }
                }
            }
        }
    }

    if (enqueue_status != ServiceDirectoryStatus::Ok)
    {
        ServiceDirectoryOwnedChannel rollback{};
        ServiceEndpointStatus endpoint_status = ServiceEndpointStatus::Ok;
        const ServiceDirectoryStatus cleanup = CleanupPrivatePair(&pair, &rollback, &endpoint_status);
        const bool aborted = AbortReservationIsSafe(*client_handles, handle_reservation);
        if (cleanup != ServiceDirectoryStatus::Ok)
            return ConnectFailure(cleanup, endpoint_status, aborted ? ErrorCode::Ok : ErrorCode::BadState, rollback);
        return ConnectFailure(aborted ? enqueue_status : ServiceDirectoryStatus::HandleRollbackFailed,
                              ServiceEndpointStatus::Ok, aborted ? ErrorCode::Ok : ErrorCode::BadState);
    }

#if defined(DUETOS_HOST_TEST)
    InvokePublicationHook(g_connect_publication_hook, g_connect_publication_context);
#endif

    Result<ipc::Handle> published = ipc::HandleTablePublish(*client_handles, handle_reservation, pair.initiator);
    const bool handle_published = published.has_value();
    if (handle_published)
        pair.initiator = nullptr;

    if (!handle_published)
    {
        ServiceDirectoryQueuedChannel removed{};
        bool found = false;
        {
            DirectoryGuard guard(*directory);
            ServiceDirectoryRow* row = ResolveExactLocked(*directory, pin.service);
            if (row != nullptr)
            {
                found = RemoveQueuedLocked(*row, pair.initiator_identity.channel, &removed);
                if (row->external_publishers == 0)
                    return ConnectFailure(ServiceDirectoryStatus::CorruptState);
                --row->external_publishers;
                TryRecycleLocked(*row);
            }
        }
        const bool aborted = AbortReservationIsSafe(*client_handles, handle_reservation);
        ipc::KObjectRelease(pair.initiator);
        pair.initiator = nullptr;
        if (found)
        {
            ServiceEndpointStatus cleanup = ServiceDirectoryDrainOwnedChannel(&removed.owned);
            if (cleanup != ServiceEndpointStatus::Ok)
                return ConnectFailure(ServiceDirectoryStatus::EndpointReleaseFailed, cleanup, published.error(),
                                      removed.owned);
        }
        return ConnectFailure(aborted ? ServiceDirectoryStatus::HandlePublishFailed
                                      : ServiceDirectoryStatus::HandleRollbackFailed,
                              ServiceEndpointStatus::Ok, published.error());
    }

    const ipc::Handle client_handle = published.value();
    const ServiceEndpointStatus activation_status = ServiceEndpointActivate(&pair.activation);
    bool ready_committed = false;
    bool closing_observed = false;
    ServiceDirectoryQueuedChannel removed{};
    bool removed_for_rollback = false;
    {
        DirectoryGuard guard(*directory);
        ServiceDirectoryRow* row = ResolveExactLocked(*directory, pin.service);
        if (row != nullptr)
        {
            closing_observed = row->state == ServiceDirectoryEntryState::Closing;
            if (activation_status == ServiceEndpointStatus::Ok && row->state == ServiceDirectoryEntryState::Active)
            {
                for (u32 offset = 0; offset < row->accept_count; ++offset)
                {
                    ServiceDirectoryQueuedChannel& queued =
                        row->accept_queue[(row->accept_head + offset) % kServiceDirectoryAcceptCapacity];
                    if (queued.channel == pair.initiator_identity.channel &&
                        queued.state == ServiceDirectoryQueuedChannelState::PendingClientPublish)
                    {
                        queued.state = ServiceDirectoryQueuedChannelState::Ready;
                        ready_committed = true;
                        break;
                    }
                }
            }
            if (!ready_committed && row->state == ServiceDirectoryEntryState::Active)
                removed_for_rollback = RemoveQueuedLocked(*row, pair.initiator_identity.channel, &removed);
            if (row->external_publishers == 0)
                return ConnectFailure(ServiceDirectoryStatus::CorruptState);
            --row->external_publishers;
            TryRecycleLocked(*row);
        }
    }

    if (ready_committed)
    {
        return ServiceDirectoryConnectResult{ServiceDirectoryStatus::Ok,
                                             ServiceEndpointStatus::Ok,
                                             ErrorCode::Ok,
                                             client_handle,
                                             pair.initiator_identity,
                                             {}};
    }

    const bool handle_rollback = DetachPublishedHandleIsSafe(*client_handles, client_handle);
    if (removed_for_rollback)
    {
        const ServiceEndpointStatus cleanup = ServiceDirectoryDrainOwnedChannel(&removed.owned);
        if (cleanup != ServiceEndpointStatus::Ok)
            return ConnectFailure(ServiceDirectoryStatus::EndpointReleaseFailed, cleanup,
                                  handle_rollback ? ErrorCode::Ok : ErrorCode::BadState, removed.owned);
    }
    if (!handle_rollback)
        return ConnectFailure(ServiceDirectoryStatus::HandleRollbackFailed, activation_status, ErrorCode::BadState);
    return ConnectFailure(closing_observed || activation_status == ServiceEndpointStatus::Ok
                              ? ServiceDirectoryStatus::Closing
                              : ServiceDirectoryStatus::EndpointActivationFailed,
                          activation_status);
}

ServiceDirectoryAcceptResult ServiceDirectoryAccept(ServiceDirectory* directory, ServiceKey service,
                                                    ServiceInstanceToken owner, ipc::HandleTable* server_handles,
                                                    ProcessKey server_process,
                                                    const ServiceEndpointCredentialSnapshot* server_credential,
                                                    u64 server_handle_rights)
{
    if (!ServiceKeyIsValid(service) || !ServiceInstanceTokenIsValid(owner) || server_handles == nullptr ||
        !ProcessKeyIsValid(server_process) || server_credential == nullptr ||
        !ServiceEndpointCredentialSnapshotIsCanonical(*server_credential) || server_handle_rights == 0)
    {
        return AcceptFailure(ServiceDirectoryStatus::InvalidArgument);
    }
    const ServiceEndpointCredentialSnapshot credential_snapshot = *server_credential;
    const ServiceDirectoryStatus ready = ReadyStatus(directory);
    if (ready != ServiceDirectoryStatus::Ok)
        return AcceptFailure(ready);

    {
        DirectoryGuard guard(*directory);
        if (!DirectoryIsCanonicalLocked(*directory))
            return AcceptFailure(ServiceDirectoryStatus::CorruptState);
        ServiceDirectoryRow* row = ResolveExactLocked(*directory, service);
        if (row == nullptr)
            return AcceptFailure(ServiceDirectoryStatus::StaleKey);
        if (!(row->owner == owner))
            return AcceptFailure(ServiceDirectoryStatus::OwnerMismatch);
        if (!(ProcessKeyFromInstance(row->owner.process) == server_process))
            return AcceptFailure(ServiceDirectoryStatus::OwnerMismatch);
        if (!(row->owner_credential == credential_snapshot))
            return AcceptFailure(ServiceDirectoryStatus::CredentialMismatch);
        if (row->state == ServiceDirectoryEntryState::Closing)
            return AcceptFailure(ServiceDirectoryStatus::Closing);
        if (row->state != ServiceDirectoryEntryState::Active)
            return AcceptFailure(ServiceDirectoryStatus::NotReady);
        if (row->accept_count == 0)
            return AcceptFailure(ServiceDirectoryStatus::QueueEmpty);
        if (row->accept_queue[row->accept_head].state != ServiceDirectoryQueuedChannelState::Ready)
            return AcceptFailure(ServiceDirectoryStatus::NotReady);
        bool accepted_slot_available = false;
        for (u32 index = 0; index < kServiceDirectoryAcceptedCapacity; ++index)
        {
            if (row->accepted_channels[index].state == ServiceDirectoryAcceptedChannelState::Free)
                accepted_slot_available = true;
        }
        if (!accepted_slot_available)
            return AcceptFailure(ServiceDirectoryStatus::AcceptedCapacityExhausted);
    }

    Result<ipc::HandleTableReservation> reserved =
        ipc::HandleTableReserve(*server_handles, ipc::KObjectType::ServiceEndpoint, server_handle_rights);
    if (!reserved.has_value())
        return AcceptFailure(ServiceDirectoryStatus::HandleReserveFailed, ServiceEndpointStatus::Ok, reserved.error());
    const ipc::HandleTableReservation handle_reservation = reserved.value();

    ipc::KObject* acceptor_object = nullptr;
    ServiceEndpointIdentity acceptor_identity = kInvalidServiceEndpointIdentity;
    ServiceDirectoryAcceptedChannelKey accepted_key = kInvalidServiceDirectoryAcceptedChannelKey;
    ServiceDirectoryStatus claim_status = ServiceDirectoryStatus::Ok;
    {
        DirectoryGuard guard(*directory);
        if (!DirectoryIsCanonicalLocked(*directory))
            claim_status = ServiceDirectoryStatus::CorruptState;
        else
        {
            ServiceDirectoryRow* row = ResolveExactLocked(*directory, service);
            if (row == nullptr)
                claim_status = ServiceDirectoryStatus::StaleKey;
            else if (!(row->owner == owner) || !(ProcessKeyFromInstance(row->owner.process) == server_process))
                claim_status = ServiceDirectoryStatus::OwnerMismatch;
            else if (!(row->owner_credential == credential_snapshot))
                claim_status = ServiceDirectoryStatus::CredentialMismatch;
            else if (row->state == ServiceDirectoryEntryState::Closing)
                claim_status = ServiceDirectoryStatus::Closing;
            else if (row->state != ServiceDirectoryEntryState::Active || row->accept_count == 0 ||
                     row->accept_queue[row->accept_head].state != ServiceDirectoryQueuedChannelState::Ready)
                claim_status = ServiceDirectoryStatus::NotReady;
            else
            {
                const ServiceDirectoryQueuedChannel queued = DequeueLocked(*row);
                ServiceDirectoryAcceptedChannel* accepted =
                    AllocateAcceptedLocked(*row, queued.channel, server_process);
                if (accepted == nullptr)
                {
                    EnqueueFrontLocked(*row, queued);
                    claim_status = ServiceDirectoryStatus::AcceptedCapacityExhausted;
                }
                else
                {
                    accepted->owner = queued.owned.owner;
                    acceptor_object = queued.owned.unpublished_acceptor;
                    acceptor_identity = ServiceEndpointIdentity{queued.channel, ServiceEndpointRole::Acceptor};
                    accepted_key = accepted->key;
                    ++row->external_publishers;
                }
            }
        }
    }

    if (claim_status != ServiceDirectoryStatus::Ok)
    {
        const bool aborted = AbortReservationIsSafe(*server_handles, handle_reservation);
        return AcceptFailure(aborted ? claim_status : ServiceDirectoryStatus::HandleRollbackFailed,
                             ServiceEndpointStatus::Ok, aborted ? ErrorCode::Ok : ErrorCode::BadState);
    }

#if defined(DUETOS_HOST_TEST)
    InvokePublicationHook(g_accept_publication_hook, g_accept_publication_context);
#endif

    Result<ipc::Handle> published = ipc::HandleTablePublish(*server_handles, handle_reservation, acceptor_object);
    const bool handle_published = published.has_value();
    if (handle_published)
        acceptor_object = nullptr;

    bool committed = false;
    bool restored = false;
    {
        DirectoryGuard guard(*directory);
        ServiceDirectoryRow* row = ResolveExactLocked(*directory, service);
        if (row != nullptr)
        {
            ServiceDirectoryAcceptedChannel* accepted = ResolveAcceptedLocked(*row, accepted_key);
            if (handle_published && row->state == ServiceDirectoryEntryState::Active && accepted != nullptr &&
                accepted->state == ServiceDirectoryAcceptedChannelState::Publishing)
            {
                accepted->server_handle = published.value();
                accepted->state = ServiceDirectoryAcceptedChannelState::Published;
                committed = true;
            }
            else if (!handle_published && row->state == ServiceDirectoryEntryState::Active && accepted != nullptr &&
                     accepted->state == ServiceDirectoryAcceptedChannelState::Publishing)
            {
                ServiceDirectoryQueuedChannel queued{};
                queued.owned.owner = accepted->owner;
                queued.owned.unpublished_acceptor = acceptor_object;
                queued.channel = accepted->key.channel;
                queued.state = ServiceDirectoryQueuedChannelState::Ready;
                EnqueueFrontLocked(*row, queued);
                acceptor_object = nullptr;
                ClearAcceptedLocked(*accepted);
                --row->accepted_count;
                restored = true;
            }
            else if (handle_published && accepted != nullptr)
            {
                // Preserve a canonical accepted tracker for the close retry;
                // the exact handle is detached below before it can escape.
                accepted->server_handle = published.value();
                accepted->state = ServiceDirectoryAcceptedChannelState::Published;
            }
            if (row->external_publishers == 0)
                return AcceptFailure(ServiceDirectoryStatus::CorruptState);
            --row->external_publishers;
            TryRecycleLocked(*row);
        }
    }

    if (committed)
    {
        return ServiceDirectoryAcceptResult{ServiceDirectoryStatus::Ok, ServiceEndpointStatus::Ok, ErrorCode::Ok,
                                            published.value(),          acceptor_identity,         accepted_key};
    }

    if (!handle_published)
    {
        const bool aborted = AbortReservationIsSafe(*server_handles, handle_reservation);
        if (acceptor_object != nullptr)
        {
            ipc::KObjectRelease(acceptor_object);
            acceptor_object = nullptr;
        }
        return AcceptFailure(
            aborted ? (restored ? ServiceDirectoryStatus::HandlePublishFailed : ServiceDirectoryStatus::Closing)
                    : ServiceDirectoryStatus::HandleRollbackFailed,
            ServiceEndpointStatus::Ok, published.error());
    }

    const bool detached = DetachPublishedHandleIsSafe(*server_handles, published.value());
    return AcceptFailure(detached ? ServiceDirectoryStatus::Closing : ServiceDirectoryStatus::HandleRollbackFailed,
                         ServiceEndpointStatus::Ok, detached ? ErrorCode::Ok : ErrorCode::BadState);
}

ServiceDirectoryReleaseAcceptedResult ServiceDirectoryReleaseAcceptedChannel(
    ServiceDirectory* directory, ServiceDirectoryAcceptedChannelKey* accepted_key)
{
    if (accepted_key == nullptr || !ServiceDirectoryAcceptedChannelKeyIsValid(*accepted_key))
        return ReleaseAcceptedFailure(ServiceDirectoryStatus::InvalidArgument);
    const ServiceDirectoryAcceptedChannelKey supplied = *accepted_key;
    const ServiceDirectoryStatus ready = ReadyStatus(directory);
    if (ready != ServiceDirectoryStatus::Ok)
        return ReleaseAcceptedFailure(ready);

    ServiceEndpointOwnerReceipt owner_receipt{};
    {
        DirectoryGuard guard(*directory);
        if (!DirectoryIsCanonicalLocked(*directory))
            return ReleaseAcceptedFailure(ServiceDirectoryStatus::CorruptState);
        ServiceDirectoryRow* row = ResolveExactLocked(*directory, supplied.service);
        if (row == nullptr)
            return ReleaseAcceptedFailure(ServiceDirectoryStatus::StaleKey);
        ServiceDirectoryAcceptedChannel* accepted = ResolveAcceptedLocked(*row, supplied);
        if (accepted == nullptr)
            return ReleaseAcceptedFailure(ServiceDirectoryStatus::StaleAcceptedChannel);
        if (accepted->state == ServiceDirectoryAcceptedChannelState::Publishing || accepted->release_driver_active)
            return ReleaseAcceptedFailure(ServiceDirectoryStatus::Busy, ServiceEndpointStatus::Busy);
        if (accepted->state != ServiceDirectoryAcceptedChannelState::Published &&
            accepted->state != ServiceDirectoryAcceptedChannelState::Releasing)
        {
            return ReleaseAcceptedFailure(ServiceDirectoryStatus::StaleAcceptedChannel);
        }
        accepted->state = ServiceDirectoryAcceptedChannelState::Releasing;
        accepted->release_driver_active = true;
        owner_receipt = accepted->owner;
    }

    const ServiceEndpointStatus endpoint_status = ServiceEndpointReleaseOwner(&owner_receipt);
    bool consumed = false;
    {
        DirectoryGuard guard(*directory);
        if (!DirectoryIsCanonicalLocked(*directory))
            return ReleaseAcceptedFailure(ServiceDirectoryStatus::CorruptState, endpoint_status);
        ServiceDirectoryRow* row = ResolveExactLocked(*directory, supplied.service);
        if (row == nullptr)
            return ReleaseAcceptedFailure(ServiceDirectoryStatus::CorruptState, endpoint_status);
        ServiceDirectoryAcceptedChannel* accepted = ResolveAcceptedLocked(*row, supplied);
        if (accepted == nullptr || accepted->state != ServiceDirectoryAcceptedChannelState::Releasing ||
            !accepted->release_driver_active)
        {
            return ReleaseAcceptedFailure(ServiceDirectoryStatus::CorruptState, endpoint_status);
        }
        accepted->release_driver_active = false;
        if (endpoint_status == ServiceEndpointStatus::Ok)
        {
            ClearAcceptedLocked(*accepted);
            --row->accepted_count;
            consumed = true;
            TryRecycleLocked(*row);
        }
    }
    if (consumed)
    {
        *accepted_key = kInvalidServiceDirectoryAcceptedChannelKey;
        return ReleaseAcceptedFailure(ServiceDirectoryStatus::Ok, ServiceEndpointStatus::Ok);
    }
    return ReleaseAcceptedFailure(endpoint_status == ServiceEndpointStatus::Busy
                                      ? ServiceDirectoryStatus::Busy
                                      : ServiceDirectoryStatus::EndpointReleaseFailed,
                                  endpoint_status);
}

ServiceDirectoryReleaseAcceptedResult ServiceDirectoryReleaseAcceptedHandle(ServiceDirectory* directory,
                                                                            ProcessKey server_process,
                                                                            ipc::Handle server_handle)
{
    if (!ProcessKeyIsValid(server_process) || !ipc::HandleDecode(server_handle, nullptr, nullptr))
        return ReleaseAcceptedFailure(ServiceDirectoryStatus::InvalidArgument);
    const ServiceDirectoryStatus ready = ReadyStatus(directory);
    if (ready != ServiceDirectoryStatus::Ok)
        return ReleaseAcceptedFailure(ready);

    ServiceDirectoryAcceptedChannelKey accepted_key = kInvalidServiceDirectoryAcceptedChannelKey;
    {
        DirectoryGuard guard(*directory);
        if (!DirectoryIsCanonicalLocked(*directory))
            return ReleaseAcceptedFailure(ServiceDirectoryStatus::CorruptState);
        for (u32 row_index = 0; row_index < kServiceDirectoryCapacity; ++row_index)
        {
            const ServiceDirectoryRow& row = directory->rows[row_index];
            if (row.state == ServiceDirectoryEntryState::Empty || row.state == ServiceDirectoryEntryState::Retired)
                continue;
            for (u32 accepted_index = 0; accepted_index < kServiceDirectoryAcceptedCapacity; ++accepted_index)
            {
                const ServiceDirectoryAcceptedChannel& accepted = row.accepted_channels[accepted_index];
                if (accepted.state != ServiceDirectoryAcceptedChannelState::Published &&
                    accepted.state != ServiceDirectoryAcceptedChannelState::Releasing)
                {
                    continue;
                }
                if (!(accepted.server_process == server_process) || accepted.server_handle != server_handle)
                    continue;
                if (ServiceDirectoryAcceptedChannelKeyIsValid(accepted_key))
                    return ReleaseAcceptedFailure(ServiceDirectoryStatus::CorruptState);
                accepted_key = accepted.key;
            }
        }
    }
    if (!ServiceDirectoryAcceptedChannelKeyIsValid(accepted_key))
        return ReleaseAcceptedFailure(ServiceDirectoryStatus::NotFound);
    return ServiceDirectoryReleaseAcceptedChannel(directory, &accepted_key);
}

ServiceDirectoryDeferAcceptedProcessResult ServiceDirectoryDeferAcceptedProcess(ServiceDirectory* directory,
                                                                                ProcessKey server_process)
{
    if (!ProcessKeyIsValid(server_process))
        return DeferAcceptedProcessFailure(ServiceDirectoryStatus::InvalidArgument);
    const ServiceDirectoryStatus ready = ReadyStatus(directory);
    if (ready != ServiceDirectoryStatus::Ok)
        return DeferAcceptedProcessFailure(ready);

    u32 newly_deferred_channels = 0;
    u32 deferred_channels = 0;
    {
        DirectoryGuard guard(*directory);
        if (!DirectoryIsCanonicalLocked(*directory))
            return DeferAcceptedProcessFailure(ServiceDirectoryStatus::CorruptState);
        for (u32 row_index = 0; row_index < kServiceDirectoryCapacity; ++row_index)
        {
            ServiceDirectoryRow& row = directory->rows[row_index];
            if (row.state == ServiceDirectoryEntryState::Empty || row.state == ServiceDirectoryEntryState::Retired)
                continue;
            for (u32 accepted_index = 0; accepted_index < kServiceDirectoryAcceptedCapacity; ++accepted_index)
            {
                ServiceDirectoryAcceptedChannel& accepted = row.accepted_channels[accepted_index];
                if (accepted.state == ServiceDirectoryAcceptedChannelState::Free ||
                    accepted.state == ServiceDirectoryAcceptedChannelState::Retired ||
                    !(accepted.server_process == server_process))
                {
                    continue;
                }
                if (!accepted.process_teardown_deferred)
                {
                    accepted.process_teardown_deferred = true;
                    ++newly_deferred_channels;
                }
                ++deferred_channels;
            }
        }
    }
    return DeferAcceptedProcessFailure(ServiceDirectoryStatus::Ok, newly_deferred_channels, deferred_channels);
}

ServiceDirectoryDriveDeferredAcceptedResult ServiceDirectoryDriveDeferredAccepted(ServiceDirectory* directory)
{
    const ServiceDirectoryStatus ready = ReadyStatus(directory);
    if (ready != ServiceDirectoryStatus::Ok)
        return DriveDeferredAcceptedFailure(ready);

    ServiceDirectoryAcceptedChannelKey batch[kServiceDirectoryProcessTeardownBatchCapacity]{};
    u32 batch_count = 0;
    {
        DirectoryGuard guard(*directory);
        if (!DirectoryIsCanonicalLocked(*directory))
            return DriveDeferredAcceptedFailure(ServiceDirectoryStatus::CorruptState);

        const u32 scan_start = directory->deferred_scan_hint;
        u32 scanned = 0;
        while (scanned < kServiceDirectoryDeferredAcceptedCapacity &&
               batch_count < kServiceDirectoryProcessTeardownBatchCapacity)
        {
            const u32 flattened = (scan_start + scanned) % kServiceDirectoryDeferredAcceptedCapacity;
            const u32 row_index = flattened / kServiceDirectoryAcceptedCapacity;
            const u32 accepted_index = flattened % kServiceDirectoryAcceptedCapacity;
            const ServiceDirectoryRow& row = directory->rows[row_index];
            const ServiceDirectoryAcceptedChannel& accepted = row.accepted_channels[accepted_index];
            ++scanned;
            if (row.state == ServiceDirectoryEntryState::Empty || row.state == ServiceDirectoryEntryState::Retired ||
                accepted.state == ServiceDirectoryAcceptedChannelState::Free ||
                accepted.state == ServiceDirectoryAcceptedChannelState::Retired || !accepted.process_teardown_deferred)
            {
                continue;
            }
            batch[batch_count++] = accepted.key;
        }
        directory->deferred_scan_hint = (scan_start + scanned) % kServiceDirectoryDeferredAcceptedCapacity;
    }

    u32 released_channels = 0;
    ServiceDirectoryStatus failure_status = ServiceDirectoryStatus::Ok;
    ServiceEndpointStatus endpoint_status = ServiceEndpointStatus::Ok;
    for (u32 index = 0; index < batch_count; ++index)
    {
        ServiceDirectoryAcceptedChannelKey accepted = batch[index];
        const ServiceDirectoryReleaseAcceptedResult released =
            ServiceDirectoryReleaseAcceptedChannel(directory, &accepted);
        if (released.status == ServiceDirectoryStatus::Ok)
        {
            ++released_channels;
            continue;
        }
        if (released.status == ServiceDirectoryStatus::Busy)
        {
            endpoint_status = ServiceEndpointStatus::Busy;
            continue;
        }
        if (released.status == ServiceDirectoryStatus::StaleKey ||
            released.status == ServiceDirectoryStatus::StaleAcceptedChannel ||
            released.status == ServiceDirectoryStatus::NotFound)
        {
            // A concurrent exact handle-close or service-close driver already
            // consumed or transferred this generation-bearing owner.
            continue;
        }
        failure_status = released.status;
        endpoint_status = released.endpoint_status;
        break;
    }

    u32 pending_channels = 0;
    {
        DirectoryGuard guard(*directory);
        if (!DirectoryIsCanonicalLocked(*directory))
        {
            return DriveDeferredAcceptedFailure(ServiceDirectoryStatus::CorruptState, endpoint_status,
                                                released_channels, pending_channels);
        }
        for (u32 row_index = 0; row_index < kServiceDirectoryCapacity; ++row_index)
        {
            const ServiceDirectoryRow& row = directory->rows[row_index];
            if (row.state == ServiceDirectoryEntryState::Empty || row.state == ServiceDirectoryEntryState::Retired)
                continue;
            for (u32 accepted_index = 0; accepted_index < kServiceDirectoryAcceptedCapacity; ++accepted_index)
            {
                const ServiceDirectoryAcceptedChannel& accepted = row.accepted_channels[accepted_index];
                if (accepted.state != ServiceDirectoryAcceptedChannelState::Free &&
                    accepted.state != ServiceDirectoryAcceptedChannelState::Retired &&
                    accepted.process_teardown_deferred)
                {
                    ++pending_channels;
                }
            }
        }
    }

    if (failure_status != ServiceDirectoryStatus::Ok)
    {
        return DriveDeferredAcceptedFailure(failure_status, endpoint_status, released_channels, pending_channels);
    }
    if (pending_channels != 0)
    {
        return DriveDeferredAcceptedFailure(ServiceDirectoryStatus::Busy, endpoint_status, released_channels,
                                            pending_channels);
    }
    return DriveDeferredAcceptedFailure(ServiceDirectoryStatus::Ok, ServiceEndpointStatus::Ok, released_channels, 0);
}

ServiceEndpointStatus ServiceDirectoryDrainOwnedChannel(ServiceDirectoryOwnedChannel* channel)
{
    if (channel == nullptr || ServiceDirectoryOwnedChannelIsEmpty(*channel) ||
        !ServiceEndpointOwnerReceiptIsValid(channel->owner))
    {
        return ServiceEndpointStatus::InvalidArgument;
    }
    if (channel->release_driver_active)
        return ServiceEndpointStatus::Busy;
    channel->release_driver_active = true;

    ServiceEndpointOwnerReceipt owner = channel->owner;
    const ServiceEndpointStatus endpoint_status = ServiceEndpointReleaseOwner(&owner);

    ipc::KObject* acceptor = channel->unpublished_acceptor;
    channel->unpublished_acceptor = nullptr;
    if (acceptor != nullptr)
        ipc::KObjectRelease(acceptor);

    if (endpoint_status == ServiceEndpointStatus::Ok)
    {
        *channel = {};
    }
    else
    {
        channel->release_driver_active = false;
    }
    return endpoint_status;
}

ServiceDirectoryCloseResult ServiceDirectoryUnregister(ServiceDirectory* directory, ServiceKey service,
                                                       ServiceInstanceToken owner)
{
    return CloseEntry(directory, service, owner, ServiceDirectoryCloseReason::Unregister);
}

ServiceDirectoryCloseResult ServiceDirectoryOwnerCrashed(ServiceDirectory* directory, ServiceKey service,
                                                         ServiceInstanceToken owner)
{
    return CloseEntry(directory, service, owner, ServiceDirectoryCloseReason::OwnerCrash);
}

ServiceDirectoryInspectResult ServiceDirectoryInspectExact(ServiceDirectory* directory, ServiceKey service)
{
    if (!ServiceKeyIsValid(service))
        return InspectFailure(ServiceDirectoryStatus::InvalidArgument);
    const ServiceDirectoryStatus ready = ReadyStatus(directory);
    if (ready != ServiceDirectoryStatus::Ok)
        return InspectFailure(ready);
    DirectoryGuard guard(*directory);
    if (!DirectoryIsCanonicalLocked(*directory))
        return InspectFailure(ServiceDirectoryStatus::CorruptState);
    const ServiceDirectoryRow* row = ResolveExactLocked(*directory, service);
    if (row == nullptr)
        return InspectFailure(ServiceDirectoryStatus::StaleKey);

    ServiceDirectoryEntrySnapshot snapshot{};
    snapshot.key = row->key;
    snapshot.name = row->name;
    snapshot.owner = row->owner;
    snapshot.owner_credential = row->owner_credential;
    snapshot.manifest_slot = row->manifest_slot;
    snapshot.active_operations = row->active_operations;
    snapshot.queued_channels = row->accept_count;
    snapshot.accepted_channels = row->accepted_count;
    snapshot.closing_channels = row->closing_count + row->close_batch_outstanding;
    snapshot.external_publishers = row->external_publishers;
    snapshot.reservation_live = row->reservation_authority != 0;
    snapshot.ready = row->ready;
    snapshot.state = row->state;
    snapshot.close_reason = row->close_reason;
    return ServiceDirectoryInspectResult{ServiceDirectoryStatus::Ok, snapshot};
}

const char* ServiceDirectoryStatusName(ServiceDirectoryStatus status)
{
    switch (status)
    {
    case ServiceDirectoryStatus::Ok:
        return "ok";
    case ServiceDirectoryStatus::InvalidArgument:
        return "invalid-argument";
    case ServiceDirectoryStatus::NotInitialized:
        return "not-initialized";
    case ServiceDirectoryStatus::AlreadyInitialized:
        return "already-initialized";
    case ServiceDirectoryStatus::CorruptState:
        return "corrupt-state";
    case ServiceDirectoryStatus::NameConflict:
        return "name-conflict";
    case ServiceDirectoryStatus::ServiceConflict:
        return "service-conflict";
    case ServiceDirectoryStatus::CapacityExhausted:
        return "capacity-exhausted";
    case ServiceDirectoryStatus::GenerationExhausted:
        return "generation-exhausted";
    case ServiceDirectoryStatus::NotFound:
        return "not-found";
    case ServiceDirectoryStatus::StaleKey:
        return "stale-key";
    case ServiceDirectoryStatus::OwnerMismatch:
        return "owner-mismatch";
    case ServiceDirectoryStatus::CredentialMismatch:
        return "credential-mismatch";
    case ServiceDirectoryStatus::ProtocolMismatch:
        return "protocol-mismatch";
    case ServiceDirectoryStatus::NotReady:
        return "not-ready";
    case ServiceDirectoryStatus::Closing:
        return "closing";
    case ServiceDirectoryStatus::ReservationConsumed:
        return "reservation-consumed";
    case ServiceDirectoryStatus::Busy:
        return "busy";
    case ServiceDirectoryStatus::OperationIdentityExhausted:
        return "operation-identity-exhausted";
    case ServiceDirectoryStatus::StaleOperation:
        return "stale-operation";
    case ServiceDirectoryStatus::QueueFull:
        return "queue-full";
    case ServiceDirectoryStatus::QueueEmpty:
        return "queue-empty";
    case ServiceDirectoryStatus::AcceptedCapacityExhausted:
        return "accepted-capacity-exhausted";
    case ServiceDirectoryStatus::StaleAcceptedChannel:
        return "stale-accepted-channel";
    case ServiceDirectoryStatus::EndpointCreateFailed:
        return "endpoint-create-failed";
    case ServiceDirectoryStatus::EndpointActivationFailed:
        return "endpoint-activation-failed";
    case ServiceDirectoryStatus::EndpointReleaseFailed:
        return "endpoint-release-failed";
    case ServiceDirectoryStatus::HandleReserveFailed:
        return "handle-reserve-failed";
    case ServiceDirectoryStatus::HandlePublishFailed:
        return "handle-publish-failed";
    case ServiceDirectoryStatus::HandleRollbackFailed:
        return "handle-rollback-failed";
    }
    return "unknown";
}

#if defined(DUETOS_HOST_TEST)
void ServiceDirectoryHostArmConnectPublicationHookForTest(ServiceDirectoryHostPublicationHook hook, void* context)
{
    g_connect_publication_context.store(context, std::memory_order_release);
    g_connect_publication_hook.store(hook, std::memory_order_release);
}

void ServiceDirectoryHostArmAcceptPublicationHookForTest(ServiceDirectoryHostPublicationHook hook, void* context)
{
    g_accept_publication_context.store(context, std::memory_order_release);
    g_accept_publication_hook.store(hook, std::memory_order_release);
}

void ServiceDirectoryHostFailNextRegistrationPublicationForTest()
{
    g_fail_registration_publication.store(true, std::memory_order_release);
}

bool ServiceDirectoryHostSetLastGenerationForTest(u32 slot, u64 last_generation)
{
    if (slot >= kServiceDirectoryCapacity || last_generation > kServiceKeyGenerationMaximum)
        return false;
    if (last_generation < AtomicLoadGeneration(&g_last_service_generations[slot]))
        return false;
    AtomicStoreGeneration(&g_last_service_generations[slot], last_generation);
    return true;
}
#endif

} // namespace duetos::core
