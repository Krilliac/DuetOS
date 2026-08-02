#include "core/service_endpoint.h"

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

constexpr u32 kOwnerInitializeUninitialized = 0;
constexpr u32 kOwnerInitializeInProgress = 1;
constexpr u32 kOwnerInitializeReady = 2;

// Boot-global last-issued generations prevent a reconstructed owner object from
// recreating an endpoint identity that escaped an earlier lifetime.
constinit u64 g_last_endpoint_generations[kServiceEndpointOwnerCapacity]{};

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

class OwnerGuard
{
  public:
#if defined(DUETOS_HOST_TEST)
    explicit OwnerGuard(ServiceEndpointOwner& owner)
        : m_owner(owner), m_ticket(AtomicFetchAdd(&owner.lock.next_ticket, 1))
    {
        while (AtomicLoadAcquire(&owner.lock.now_serving) != m_ticket)
        {
#if defined(_MSC_VER)
            _mm_pause();
#else
            __builtin_ia32_pause();
#endif
        }
    }

    ~OwnerGuard() { AtomicStoreRelease(&m_owner.lock.now_serving, m_ticket + 1U); }
#else
    explicit OwnerGuard(ServiceEndpointOwner& owner) : m_guard(owner.lock) {}
    ~OwnerGuard() = default;
#endif

    OwnerGuard(const OwnerGuard&) = delete;
    OwnerGuard& operator=(const OwnerGuard&) = delete;

  private:
#if defined(DUETOS_HOST_TEST)
    ServiceEndpointOwner& m_owner;
    u32 m_ticket;
#else
    sync::SpinLockGuard m_guard;
#endif
};

ServiceEndpointPairCreateResult PairFailure(ServiceEndpointStatus status,
                                            ipc::ChannelCoreStatus channel_status = ipc::ChannelCoreStatus::Ok)
{
    return ServiceEndpointPairCreateResult{status, channel_status, {}};
}

ServiceEndpointOperationResult OperationFailure(ServiceEndpointStatus status,
                                                ipc::ChannelCoreStatus channel_status = ipc::ChannelCoreStatus::Ok)
{
    return ServiceEndpointOperationResult{status, channel_status, kInvalidServiceEndpointOperation};
}

ServiceEndpointDirectionResult DirectionFailure(ServiceEndpointStatus status,
                                                ipc::ChannelCoreStatus channel_status = ipc::ChannelCoreStatus::Ok)
{
    return ServiceEndpointDirectionResult{status, channel_status, {}};
}

ServiceEndpointRequestReserveResult RequestFailure(
    ServiceEndpointStatus status, ipc::ChannelCoreStatus channel_status = ipc::ChannelCoreStatus::Ok,
    ipc::EndpointRequestLedgerStatus ledger_status = ipc::EndpointRequestLedgerStatus::Ok)
{
    return ServiceEndpointRequestReserveResult{status, channel_status, ledger_status, ipc::kInvalidEndpointRequestKey};
}

ServiceEndpointRequestCommitResult RequestCommitFailure(
    ServiceEndpointStatus status, ipc::ChannelCoreStatus channel_status = ipc::ChannelCoreStatus::Ok,
    ipc::EndpointRequestLedgerStatus ledger_status = ipc::EndpointRequestLedgerStatus::Ok)
{
    return ServiceEndpointRequestCommitResult{status, channel_status, ledger_status,
                                              ipc::kInvalidEndpointRequestCompletionAuthority};
}

ServiceEndpointRequestTransitionResult RequestTransitionFailure(
    ServiceEndpointStatus status, ipc::ChannelCoreStatus channel_status = ipc::ChannelCoreStatus::Ok,
    ipc::EndpointRequestLedgerStatus ledger_status = ipc::EndpointRequestLedgerStatus::Ok)
{
    return ServiceEndpointRequestTransitionResult{status, channel_status, ledger_status};
}

ServiceEndpointStatus RequestChannelFailureStatus(ipc::ChannelCoreStatus channel_status)
{
    if (channel_status == ipc::ChannelCoreStatus::Draining)
        return ServiceEndpointStatus::Closing;
    if (channel_status == ipc::ChannelCoreStatus::StaleEpoch ||
        channel_status == ipc::ChannelCoreStatus::StaleOperation)
    {
        return ServiceEndpointStatus::StaleIdentity;
    }
    if (channel_status == ipc::ChannelCoreStatus::InvalidArgument)
        return ServiceEndpointStatus::InvalidArgument;
    if (channel_status == ipc::ChannelCoreStatus::LedgerFailure)
        return ServiceEndpointStatus::RequestRejected;
    return ServiceEndpointStatus::CorruptState;
}

ServiceEndpointStatus OperationAcquireFailureStatus(ipc::ChannelCoreStatus channel_status)
{
    switch (channel_status)
    {
    case ipc::ChannelCoreStatus::Draining:
        return ServiceEndpointStatus::Closing;
    case ipc::ChannelCoreStatus::Drained:
        return ServiceEndpointStatus::Drained;
    case ipc::ChannelCoreStatus::Busy:
        return ServiceEndpointStatus::Busy;
    case ipc::ChannelCoreStatus::OperationIdentityExhausted:
        return ServiceEndpointStatus::CapacityExhausted;
    case ipc::ChannelCoreStatus::StaleEpoch:
    case ipc::ChannelCoreStatus::StaleOperation:
        return ServiceEndpointStatus::StaleIdentity;
    case ipc::ChannelCoreStatus::InvalidArgument:
        return ServiceEndpointStatus::InvalidArgument;
    default:
        return ServiceEndpointStatus::CorruptState;
    }
}

ServiceEndpointInspectResult InspectFailure(ServiceEndpointStatus status)
{
    return ServiceEndpointInspectResult{status, {}};
}

bool PointerRangeIsValid(const void* pointer, usize size)
{
    if (pointer == nullptr || size == 0)
        return false;
    const usize begin = reinterpret_cast<usize>(pointer);
    return begin <= static_cast<usize>(~static_cast<usize>(0)) - size;
}

bool PointerRangesOverlap(const void* lhs, usize lhs_size, const void* rhs, usize rhs_size)
{
    if (!PointerRangeIsValid(lhs, lhs_size) || !PointerRangeIsValid(rhs, rhs_size))
        return true;
    const usize lhs_begin = reinterpret_cast<usize>(lhs);
    const usize rhs_begin = reinterpret_cast<usize>(rhs);
    return lhs_begin < rhs_begin + rhs_size && rhs_begin < lhs_begin + lhs_size;
}

bool SecurityContextsEqual(const CredentialSecurityContext& lhs, const CredentialSecurityContext& rhs)
{
    if (lhs.real_uid != rhs.real_uid || lhs.effective_uid != rhs.effective_uid || lhs.saved_uid != rhs.saved_uid ||
        lhs.fs_uid != rhs.fs_uid || lhs.real_gid != rhs.real_gid || lhs.effective_gid != rhs.effective_gid ||
        lhs.saved_gid != rhs.saved_gid || lhs.fs_gid != rhs.fs_gid ||
        lhs.supplemental_group_count != rhs.supplemental_group_count ||
        lhs.capability_effective != rhs.capability_effective || lhs.capability_permitted != rhs.capability_permitted ||
        lhs.capability_inheritable != rhs.capability_inheritable ||
        lhs.capability_bounding != rhs.capability_bounding || lhs.win32_integrity != rhs.win32_integrity)
    {
        return false;
    }
    for (u32 index = 0; index < kCredentialSupplementalGroupCapacity; ++index)
    {
        if (lhs.supplemental_groups[index] != rhs.supplemental_groups[index])
            return false;
    }
    return true;
}

ServiceEndpointStatus ReadyStatus(ServiceEndpointOwner* owner)
{
    if (owner == nullptr)
        return ServiceEndpointStatus::InvalidArgument;
    return AtomicLoadAcquire(&owner->initialized) == kOwnerInitializeReady ? ServiceEndpointStatus::Ok
                                                                           : ServiceEndpointStatus::NotInitialized;
}

void InitializeOwnerLock(ServiceEndpointOwner& owner)
{
    owner.lock.next_ticket = 0;
    owner.lock.now_serving = 0;
#if !defined(DUETOS_HOST_TEST)
    owner.lock.owner_cpu = 0xFFFFFFFFu;
    owner.lock.class_id = sync::kLockClassUnclassified;
#endif
}

bool OwnerBodyIsCanonicalZero(const ServiceEndpointOwner& owner)
{
    if (owner.state != ServiceEndpointOwnerState::Uninitialized)
        return false;
#if defined(DUETOS_HOST_TEST)
    if (owner.lock.next_ticket != 0 || owner.lock.now_serving != 0)
        return false;
#else
    if (owner.lock.next_ticket != 0 || owner.lock.now_serving != 0 || owner.lock.owner_cpu != 0 ||
        owner.lock.class_id != 0)
    {
        return false;
    }
#endif
    const u8* bytes = reinterpret_cast<const u8*>(owner.slots);
    for (usize index = 0; index < sizeof(owner.slots); ++index)
    {
        if (bytes[index] != 0)
            return false;
    }
    return true;
}

u64 AllocateEndpointGeneration(u32 slot)
{
    u64 current = AtomicLoadGeneration(&g_last_endpoint_generations[slot]);
    while (current < kServiceEndpointGenerationMaximum)
    {
        const u64 next = current + 1;
        u64 expected = current;
        if (AtomicCompareExchangeGeneration(&g_last_endpoint_generations[slot], &expected, next))
            return next;
        current = expected;
    }
    return 0;
}

ServiceEndpointOwnerSlot* ResolveExactLocked(ServiceEndpointOwner& owner, ServiceEndpointChannelKey key)
{
    if (!ServiceEndpointChannelKeyIsValid(key))
        return nullptr;
    ServiceEndpointOwnerSlot& slot = owner.slots[key.slot];
    if (slot.state == ServiceEndpointSlotState::Empty || slot.state == ServiceEndpointSlotState::Constructing ||
        slot.state == ServiceEndpointSlotState::Retired || !(slot.key == key))
    {
        return nullptr;
    }
    return &slot;
}

void ClearSlotLocked(ServiceEndpointOwnerSlot& slot, bool terminal)
{
    slot = ServiceEndpointOwnerSlot{};
    slot.state = terminal ? ServiceEndpointSlotState::Retired : ServiceEndpointSlotState::Empty;
}

bool TryRecycleLocked(ServiceEndpointOwnerSlot& slot)
{
    if (slot.state != ServiceEndpointSlotState::Drained || slot.outer_owner_live || slot.drain_driver_active ||
        slot.drain_retry_requested || slot.request_cleanup_failed || slot.endpoint_reference_live[0] ||
        slot.endpoint_reference_live[1] || !ipc::ChannelCoreDetachedCleanupIsEmpty(slot.detached_cleanup))
    {
        return false;
    }
    const bool terminal = slot.key.generation == kServiceEndpointGenerationMaximum;
    ClearSlotLocked(slot, terminal);
    return true;
}

ipc::ChannelCoreDirection ResolveDirection(ServiceEndpointRole role, ServiceEndpointTrafficDirection traffic)
{
    const bool forward = (role == ServiceEndpointRole::Initiator && traffic == ServiceEndpointTrafficDirection::Send) ||
                         (role == ServiceEndpointRole::Acceptor && traffic == ServiceEndpointTrafficDirection::Receive);
    return forward ? ipc::ChannelCoreDirection::InitiatorToAcceptor : ipc::ChannelCoreDirection::AcceptorToInitiator;
}

ServiceEndpointStatus DeliverRequestCleanup(const ipc::ChannelCoreDrainResult& drained,
                                            ipc::ChannelEpoch expected_epoch,
                                            const ServiceEndpointRequestCleanupSink& sink)
{
    bool has_requests = false;
    for (u32 direction_index = 0; direction_index < ipc::kChannelCoreDirectionCount; ++direction_index)
    {
        const ipc::EndpointRequestDrainResult& cleanup = drained.request_cleanup[direction_index];
        if (cleanup.status != ipc::EndpointRequestLedgerStatus::Ok ||
            cleanup.detached_count > ipc::kEndpointRequestLedgerCapacity)
        {
            return ServiceEndpointStatus::InvalidCleanup;
        }
        const ipc::EndpointRequestDirection expected_direction =
            direction_index == 0 ? ipc::EndpointRequestDirection::InitiatorToAcceptor
                                 : ipc::EndpointRequestDirection::AcceptorToInitiator;
        for (u32 key_index = 0; key_index < cleanup.detached_count; ++key_index)
        {
            const ipc::EndpointRequestKey key = cleanup.detached_keys[key_index];
            if (!ipc::EndpointRequestKeyIsValid(key) || key.ledger_identity.endpoint_epoch != expected_epoch ||
                key.ledger_identity.direction != expected_direction)
            {
                return ServiceEndpointStatus::InvalidCleanup;
            }
            has_requests = true;
        }
    }
    if (has_requests && (drained.channel_epoch != expected_epoch || !ServiceEndpointRequestCleanupSinkIsValid(&sink)))
        return ServiceEndpointStatus::InvalidCleanup;

    // The bounded result is fully validated before the first external callback.
    for (u32 direction_index = 0; direction_index < ipc::kChannelCoreDirectionCount; ++direction_index)
    {
        const ipc::EndpointRequestDrainResult& cleanup = drained.request_cleanup[direction_index];
        for (u32 key_index = 0; key_index < cleanup.detached_count; ++key_index)
            sink.consume(sink.context, cleanup.detached_keys[key_index]);
    }
    return ServiceEndpointStatus::Ok;
}

ServiceEndpointStatus MapDrainStatus(ipc::ChannelCoreStatus status)
{
    switch (status)
    {
    case ipc::ChannelCoreStatus::Ok:
        return ServiceEndpointStatus::Ok;
    case ipc::ChannelCoreStatus::Busy:
    case ipc::ChannelCoreStatus::Draining:
        return ServiceEndpointStatus::Busy;
    case ipc::ChannelCoreStatus::Drained:
        return ServiceEndpointStatus::Drained;
    case ipc::ChannelCoreStatus::InvalidCleanup:
        return ServiceEndpointStatus::InvalidCleanup;
    case ipc::ChannelCoreStatus::ResourceReleaseFailed:
        return ServiceEndpointStatus::ResourceReleaseFailed;
    default:
        return ServiceEndpointStatus::CorruptState;
    }
}

ServiceEndpointStatus DriveDrain(ServiceEndpointOwner* owner, ServiceEndpointChannelKey channel)
{
    ipc::ChannelCore* core = nullptr;
    ServiceEndpointRequestCleanupSink sink{};
    ipc::ChannelCoreDetachedCleanup detached{};
    bool release_saved_cleanup = false;
    bool request_cleanup_failed = false;
    {
        OwnerGuard guard(*owner);
        ServiceEndpointOwnerSlot* slot = ResolveExactLocked(*owner, channel);
        if (slot == nullptr)
            return ServiceEndpointStatus::StaleIdentity;
        if (slot->state == ServiceEndpointSlotState::Private || slot->state == ServiceEndpointSlotState::Open)
            slot->state = ServiceEndpointSlotState::Draining;
        if (slot->state == ServiceEndpointSlotState::Drained)
            return ServiceEndpointStatus::Ok;
        if (slot->state != ServiceEndpointSlotState::Draining)
            return ServiceEndpointStatus::CorruptState;
        if (slot->drain_driver_active)
        {
            // This bit is the lost-wakeup-proof handoff. In particular, a last
            // operation release can arrive while the active driver is outside
            // the owner lock closing ChannelCore resources. The active driver
            // observes this request under the same lock before it relinquishes
            // authority, and either retries itself or leaves a successor free
            // to acquire the driver.
            slot->drain_retry_requested = true;
            return ServiceEndpointStatus::Busy;
        }
        slot->drain_driver_active = true;
        slot->drain_retry_requested = false;
        core = &slot->core;
        sink = slot->request_cleanup;
        request_cleanup_failed = slot->request_cleanup_failed;
        if (!ipc::ChannelCoreDetachedCleanupIsEmpty(slot->detached_cleanup))
        {
            detached = slot->detached_cleanup;
            slot->detached_cleanup = {};
            release_saved_cleanup = true;
        }
    }

    for (;;)
    {
        ServiceEndpointStatus result =
            request_cleanup_failed ? ServiceEndpointStatus::InvalidCleanup : ServiceEndpointStatus::Ok;
        if (!release_saved_cleanup)
        {
            ipc::ChannelCoreDrainResult drained = ipc::ChannelCoreDrainExpected(core, channel.channel_epoch);
            if (!ipc::ChannelCoreDetachedCleanupIsEmpty(drained.detached))
                detached = drained.detached;
            const ServiceEndpointStatus delivery = request_cleanup_failed
                                                       ? ServiceEndpointStatus::InvalidCleanup
                                                       : DeliverRequestCleanup(drained, channel.channel_epoch, sink);
            if (delivery != ServiceEndpointStatus::Ok)
            {
                result = delivery;
                request_cleanup_failed = true;
            }
            else if (drained.status != ipc::ChannelCoreStatus::Ok)
            {
                result = MapDrainStatus(drained.status);
            }
            else if (ipc::ChannelCoreDetachedCleanupIsEmpty(drained.detached))
            {
                result = ServiceEndpointStatus::InvalidCleanup;
            }
        }

        // Detached core resources are owned by this driver even when request-key
        // validation detects corruption. Release them outside both locks, while
        // leaving the endpoint slot quarantined in Draining on the primary error.
        // A partial ResourceDomain release failure leaves the residual charge in
        // `detached` for the bounded retry path below.
        if (!ipc::ChannelCoreDetachedCleanupIsEmpty(detached))
        {
            const ipc::ChannelCoreStatus cleanup_status = ipc::ChannelCoreReleaseDetachedCleanup(&detached);
            if (cleanup_status != ipc::ChannelCoreStatus::Ok && result == ServiceEndpointStatus::Ok)
                result = MapDrainStatus(cleanup_status);
        }

        bool retry = false;
        {
            OwnerGuard guard(*owner);
            ServiceEndpointOwnerSlot* slot = ResolveExactLocked(*owner, channel);
            if (slot == nullptr || !slot->drain_driver_active || slot->state != ServiceEndpointSlotState::Draining)
                return ServiceEndpointStatus::CorruptState;
            slot->request_cleanup_failed = slot->request_cleanup_failed || request_cleanup_failed;
            if (!ipc::ChannelCoreDetachedCleanupIsEmpty(detached))
                slot->detached_cleanup = detached;
            if (result == ServiceEndpointStatus::Ok && !slot->request_cleanup_failed)
                slot->state = ServiceEndpointSlotState::Drained;

            retry = result == ServiceEndpointStatus::Busy && slot->drain_retry_requested &&
                    !slot->request_cleanup_failed && slot->state == ServiceEndpointSlotState::Draining &&
                    ipc::ChannelCoreDetachedCleanupIsEmpty(slot->detached_cleanup);
            slot->drain_retry_requested = false;
            if (!retry)
                slot->drain_driver_active = false;
            TryRecycleLocked(*slot);
        }
        if (!retry)
            return result;

        // A contender published a retry while this driver was outside the
        // owner lock. Retain driver authority and perform another bounded core
        // pass. Busy without a new handoff never spins.
        detached = {};
        release_saved_cleanup = false;
    }
}

void DestroyEndpointObject(ipc::KObject* object)
{
    if (object == nullptr || object->type != ipc::KObjectType::ServiceEndpoint)
        return;
    auto* endpoint = reinterpret_cast<ServiceEndpointObject*>(object);
    ServiceEndpointOwner* owner = endpoint->owner;
    const ServiceEndpointIdentity identity = endpoint->identity;
    if (owner == nullptr || !ServiceEndpointIdentityIsValid(identity) ||
        ReadyStatus(owner) != ServiceEndpointStatus::Ok)
    {
        return;
    }

    bool drive = false;
    {
        OwnerGuard guard(*owner);
        ServiceEndpointOwnerSlot* slot = ResolveExactLocked(*owner, identity.channel);
        const u32 role_index = ServiceEndpointRoleIndex(identity.role);
        if (slot == nullptr || &slot->endpoints[role_index] != endpoint || !slot->endpoint_reference_live[role_index])
            return;
        slot->endpoint_reference_live[role_index] = false;
        if (slot->state == ServiceEndpointSlotState::Private || slot->state == ServiceEndpointSlotState::Open)
            slot->state = ServiceEndpointSlotState::Draining;
        drive = slot->state == ServiceEndpointSlotState::Draining;
        TryRecycleLocked(*slot);
    }
    if (drive)
        (void)DriveDrain(owner, identity.channel);
}

bool PairComponentsAreCanonical(const ServiceEndpointPair& pair)
{
    return ServiceEndpointOwnerReceiptIsValid(pair.owner) && ServiceEndpointActivationTicketIsValid(pair.activation) &&
           pair.initiator != nullptr && pair.acceptor != nullptr &&
           ServiceEndpointIdentityIsValid(pair.initiator_identity) &&
           ServiceEndpointIdentityIsValid(pair.acceptor_identity) &&
           pair.initiator_identity.role == ServiceEndpointRole::Initiator &&
           pair.acceptor_identity.role == ServiceEndpointRole::Acceptor &&
           pair.initiator_identity.channel == pair.owner.channel &&
           pair.acceptor_identity.channel == pair.owner.channel && pair.activation.owner == pair.owner.owner &&
           pair.activation.channel == pair.owner.channel;
}

} // namespace

bool ServiceEndpointProtocolAuthorityIsCanonical(const ServiceEndpointProtocolAuthority& authority)
{
    return authority.authority_identity != 0 && authority.protocol_identity != 0 && authority.service_identity != 0 &&
           authority.allowed_methods != 0 && authority.protocol_version != 0 &&
           authority.protocol_version <= kServiceEndpointProtocolVersionMaximum && authority.flags == 0 &&
           authority.wire_service_id != 0 && authority.reserved32 == 0;
}

bool ServiceEndpointProtocolAuthorityAllowsRoute(const ServiceEndpointProtocolAuthority& authority, u32 wire_service_id,
                                                 u32 method_id)
{
    if (!ServiceEndpointProtocolAuthorityIsCanonical(authority) || wire_service_id != authority.wire_service_id ||
        method_id == 0 || method_id > 64)
    {
        return false;
    }
    return (authority.allowed_methods & (u64{1} << (method_id - 1U))) != 0;
}

bool ServiceEndpointCredentialSnapshotIsCanonical(const ServiceEndpointCredentialSnapshot& snapshot)
{
    return CredentialKeyIsValid(snapshot.key) && CredentialSecurityContextIsCanonical(snapshot.security);
}

bool operator==(const ServiceEndpointCredentialSnapshot& lhs, const ServiceEndpointCredentialSnapshot& rhs)
{
    return lhs.key == rhs.key && SecurityContextsEqual(lhs.security, rhs.security);
}

bool ServiceEndpointPeerSnapshotIsCanonical(const ServiceEndpointPeerSnapshot& snapshot)
{
    return ProcessKeyIsValid(snapshot.process) && ServiceEndpointCredentialSnapshotIsCanonical(snapshot.credential);
}

bool operator==(const ServiceEndpointPeerSnapshot& lhs, const ServiceEndpointPeerSnapshot& rhs)
{
    return lhs.process == rhs.process && lhs.credential == rhs.credential;
}

ServiceEndpointStatus ServiceEndpointOwnerInitialize(ServiceEndpointOwner* owner)
{
    if (owner == nullptr)
        return ServiceEndpointStatus::InvalidArgument;
    u32 expected = kOwnerInitializeUninitialized;
    if (!AtomicCompareExchange(&owner->initialized, &expected, kOwnerInitializeInProgress))
        return ServiceEndpointStatus::AlreadyInitialized;
    if (!OwnerBodyIsCanonicalZero(*owner))
    {
        AtomicStoreRelease(&owner->initialized, kOwnerInitializeUninitialized);
        return ServiceEndpointStatus::CorruptState;
    }
    InitializeOwnerLock(*owner);
    owner->state = ServiceEndpointOwnerState::Open;
    AtomicStoreRelease(&owner->initialized, kOwnerInitializeReady);
    return ServiceEndpointStatus::Ok;
}

bool ServiceEndpointOwnerIsReady(const ServiceEndpointOwner* owner)
{
    return owner != nullptr && AtomicLoadAcquire(const_cast<u32*>(&owner->initialized)) == kOwnerInitializeReady &&
           owner->state == ServiceEndpointOwnerState::Open;
}

ServiceEndpointPairCreateResult ServiceEndpointCreatePair(ServiceEndpointOwner* owner,
                                                          ResourceDomainKey resource_domain,
                                                          const ServiceEndpointProtocolAuthority* protocol,
                                                          const ServiceEndpointPeerSnapshot* initiator,
                                                          const ServiceEndpointPeerSnapshot* acceptor,
                                                          const ServiceEndpointRequestCleanupSink* cleanup_sink)
{
    if (!ResourceDomainKeyIsValid(resource_domain) || protocol == nullptr || initiator == nullptr ||
        acceptor == nullptr || !ServiceEndpointRequestCleanupSinkIsValid(cleanup_sink) ||
        !ServiceEndpointProtocolAuthorityIsCanonical(*protocol) ||
        !ServiceEndpointPeerSnapshotIsCanonical(*initiator) || !ServiceEndpointPeerSnapshotIsCanonical(*acceptor) ||
        initiator->process == acceptor->process)
    {
        return PairFailure(ServiceEndpointStatus::InvalidArgument);
    }
    const ServiceEndpointStatus ready = ReadyStatus(owner);
    if (ready != ServiceEndpointStatus::Ok)
        return PairFailure(ready);
    if (PointerRangesOverlap(protocol, sizeof(*protocol), owner, sizeof(*owner)) ||
        PointerRangesOverlap(initiator, sizeof(*initiator), owner, sizeof(*owner)) ||
        PointerRangesOverlap(acceptor, sizeof(*acceptor), owner, sizeof(*owner)) ||
        PointerRangesOverlap(cleanup_sink, sizeof(*cleanup_sink), owner, sizeof(*owner)))
    {
        return PairFailure(ServiceEndpointStatus::InvalidArgument);
    }

    const ServiceEndpointProtocolAuthority protocol_snapshot = *protocol;
    const ServiceEndpointPeerSnapshot initiator_snapshot = *initiator;
    const ServiceEndpointPeerSnapshot acceptor_snapshot = *acceptor;
    const ServiceEndpointRequestCleanupSink cleanup_snapshot = *cleanup_sink;

    u32 selected_slot = kServiceEndpointOwnerCapacity;
    u64 generation = 0;
    bool generation_exhausted = false;
    {
        OwnerGuard guard(*owner);
        if (owner->state != ServiceEndpointOwnerState::Open)
            return PairFailure(ServiceEndpointStatus::CorruptState);
        for (u32 slot_index = 0; slot_index < kServiceEndpointOwnerCapacity; ++slot_index)
        {
            ServiceEndpointOwnerSlot& slot = owner->slots[slot_index];
            if (slot.state != ServiceEndpointSlotState::Empty)
                continue;
            generation = AllocateEndpointGeneration(slot_index);
            if (generation == 0)
            {
                ClearSlotLocked(slot, true);
                generation_exhausted = true;
                continue;
            }
            selected_slot = slot_index;
            slot.key = ServiceEndpointChannelKey{slot_index, generation, ipc::kChannelEpochInvalid};
            slot.state = ServiceEndpointSlotState::Constructing;
            break;
        }
    }
    if (selected_slot == kServiceEndpointOwnerCapacity)
    {
        return PairFailure(generation_exhausted ? ServiceEndpointStatus::GenerationExhausted
                                                : ServiceEndpointStatus::CapacityExhausted);
    }

    ServiceEndpointOwnerSlot& selected = owner->slots[selected_slot];
    const ipc::ChannelCoreOpenResult opened = ipc::ChannelCoreInitialize(&selected.core, resource_domain);
    if (opened.status != ipc::ChannelCoreStatus::Ok)
    {
        OwnerGuard guard(*owner);
        if (selected.state != ServiceEndpointSlotState::Constructing || selected.key.slot != selected_slot ||
            selected.key.generation != generation)
        {
            return PairFailure(ServiceEndpointStatus::CorruptState, opened.status);
        }
        ClearSlotLocked(selected, generation == kServiceEndpointGenerationMaximum);
        return PairFailure(ServiceEndpointStatus::ChannelCreateFailed, opened.status);
    }

    const ServiceEndpointChannelKey channel{selected_slot, generation, opened.channel_epoch};
    const ServiceEndpointIdentity initiator_identity{channel, ServiceEndpointRole::Initiator};
    const ServiceEndpointIdentity acceptor_identity{channel, ServiceEndpointRole::Acceptor};

    selected.endpoints[0].owner = owner;
    selected.endpoints[0].identity = initiator_identity;
    selected.endpoints[0].protocol = protocol_snapshot;
    selected.endpoints[0].peer = acceptor_snapshot;
    ipc::KObjectInit(&selected.endpoints[0].base, ipc::KObjectType::ServiceEndpoint, &DestroyEndpointObject);

    selected.endpoints[1].owner = owner;
    selected.endpoints[1].identity = acceptor_identity;
    selected.endpoints[1].protocol = protocol_snapshot;
    selected.endpoints[1].peer = initiator_snapshot;
    ipc::KObjectInit(&selected.endpoints[1].base, ipc::KObjectType::ServiceEndpoint, &DestroyEndpointObject);

    {
        OwnerGuard guard(*owner);
        if (selected.state != ServiceEndpointSlotState::Constructing || selected.key.slot != selected_slot ||
            selected.key.generation != generation)
        {
            return PairFailure(ServiceEndpointStatus::CorruptState);
        }
        selected.key = channel;
        selected.detached_cleanup = {};
        selected.request_cleanup = cleanup_snapshot;
        selected.activation_nonce = opened.channel_epoch;
        selected.endpoint_reference_live[0] = true;
        selected.endpoint_reference_live[1] = true;
        selected.outer_owner_live = true;
        selected.drain_driver_active = false;
        selected.drain_retry_requested = false;
        selected.request_cleanup_failed = false;
        selected.state = ServiceEndpointSlotState::Private;
    }

    ServiceEndpointPair pair{};
    pair.owner = ServiceEndpointOwnerReceipt{owner, channel};
    pair.activation = ServiceEndpointActivationTicket{owner, channel, opened.channel_epoch};
    pair.initiator = &selected.endpoints[0].base;
    pair.acceptor = &selected.endpoints[1].base;
    pair.initiator_identity = initiator_identity;
    pair.acceptor_identity = acceptor_identity;
    return ServiceEndpointPairCreateResult{ServiceEndpointStatus::Ok, ipc::ChannelCoreStatus::Ok, pair};
}

ServiceEndpointStatus ServiceEndpointActivate(ServiceEndpointActivationTicket* ticket)
{
    if (ticket == nullptr || !ServiceEndpointActivationTicketIsValid(*ticket))
        return ServiceEndpointStatus::InvalidArgument;
    const ServiceEndpointActivationTicket supplied = *ticket;
    const ServiceEndpointStatus ready = ReadyStatus(supplied.owner);
    if (ready != ServiceEndpointStatus::Ok)
        return ready;

    {
        OwnerGuard guard(*supplied.owner);
        ServiceEndpointOwnerSlot* slot = ResolveExactLocked(*supplied.owner, supplied.channel);
        if (slot == nullptr)
            return ServiceEndpointStatus::StaleIdentity;
        if (slot->state == ServiceEndpointSlotState::Open)
            return ServiceEndpointStatus::AlreadyPublished;
        if (slot->state == ServiceEndpointSlotState::Draining || slot->state == ServiceEndpointSlotState::Drained)
            return ServiceEndpointStatus::Closing;
        if (slot->state != ServiceEndpointSlotState::Private || slot->activation_nonce != supplied.nonce)
            return ServiceEndpointStatus::StaleActivation;
        slot->activation_nonce = 0;
        slot->state = ServiceEndpointSlotState::Open;
    }
    *ticket = kInvalidServiceEndpointActivationTicket;
    return ServiceEndpointStatus::Ok;
}

ServiceEndpointStatus ServiceEndpointReleaseOwner(ServiceEndpointOwnerReceipt* receipt)
{
    if (receipt == nullptr || !ServiceEndpointOwnerReceiptIsValid(*receipt))
        return ServiceEndpointStatus::InvalidArgument;
    const ServiceEndpointOwnerReceipt supplied = *receipt;
    const ServiceEndpointStatus ready = ReadyStatus(supplied.owner);
    if (ready != ServiceEndpointStatus::Ok)
        return ready;

    {
        OwnerGuard guard(*supplied.owner);
        ServiceEndpointOwnerSlot* slot = ResolveExactLocked(*supplied.owner, supplied.channel);
        if (slot == nullptr)
            return ServiceEndpointStatus::StaleIdentity;
        if (!slot->outer_owner_live)
            return ServiceEndpointStatus::StaleOwner;
        if (slot->state == ServiceEndpointSlotState::Private || slot->state == ServiceEndpointSlotState::Open)
            slot->state = ServiceEndpointSlotState::Draining;
    }

    const ServiceEndpointStatus drain_status = DriveDrain(supplied.owner, supplied.channel);
    if (drain_status != ServiceEndpointStatus::Ok)
        return drain_status;

    {
        OwnerGuard guard(*supplied.owner);
        ServiceEndpointOwnerSlot* slot = ResolveExactLocked(*supplied.owner, supplied.channel);
        if (slot == nullptr)
            return ServiceEndpointStatus::StaleIdentity;
        if (!slot->outer_owner_live)
            return ServiceEndpointStatus::StaleOwner;
        if (slot->state != ServiceEndpointSlotState::Drained || slot->drain_driver_active ||
            slot->drain_retry_requested || !ipc::ChannelCoreDetachedCleanupIsEmpty(slot->detached_cleanup))
        {
            return ServiceEndpointStatus::Busy;
        }
        slot->outer_owner_live = false;
        TryRecycleLocked(*slot);
    }
    *receipt = kInvalidServiceEndpointOwnerReceipt;
    return ServiceEndpointStatus::Ok;
}

ServiceEndpointStatus ServiceEndpointAbortPair(ServiceEndpointPair* pair)
{
    if (pair == nullptr || !PairComponentsAreCanonical(*pair))
        return ServiceEndpointStatus::InvalidArgument;
    const ServiceEndpointStatus owner_status = ServiceEndpointReleaseOwner(&pair->owner);
    if (owner_status != ServiceEndpointStatus::Ok)
        return owner_status;

    ipc::KObject* initiator = pair->initiator;
    ipc::KObject* acceptor = pair->acceptor;
    *pair = ServiceEndpointPair{};
    ipc::KObjectRelease(initiator);
    ipc::KObjectRelease(acceptor);
    return ServiceEndpointStatus::Ok;
}

ServiceEndpointOperationResult ServiceEndpointAcquireOperation(ipc::KObject* retained_object)
{
    if (retained_object == nullptr || retained_object->type != ipc::KObjectType::ServiceEndpoint)
        return OperationFailure(ServiceEndpointStatus::InvalidArgument);
    if (!ipc::KObjectAcquire(retained_object))
        return OperationFailure(ServiceEndpointStatus::StaleIdentity);

    auto* endpoint = reinterpret_cast<ServiceEndpointObject*>(retained_object);
    ServiceEndpointOwner* owner = endpoint->owner;
    const ServiceEndpointIdentity identity = endpoint->identity;
    if (owner == nullptr || !ServiceEndpointIdentityIsValid(identity) ||
        ReadyStatus(owner) != ServiceEndpointStatus::Ok)
    {
        ipc::KObjectRelease(retained_object);
        return OperationFailure(ServiceEndpointStatus::StaleIdentity);
    }

    ipc::ChannelCore* core = nullptr;
    ServiceEndpointStatus status = ServiceEndpointStatus::Ok;
    {
        OwnerGuard guard(*owner);
        ServiceEndpointOwnerSlot* slot = ResolveExactLocked(*owner, identity.channel);
        const u32 role_index = ServiceEndpointRoleIndex(identity.role);
        if (slot == nullptr || &slot->endpoints[role_index] != endpoint || !slot->endpoint_reference_live[role_index])
            status = ServiceEndpointStatus::StaleIdentity;
        else if (slot->state == ServiceEndpointSlotState::Private)
            status = ServiceEndpointStatus::NotPublished;
        else if (slot->state == ServiceEndpointSlotState::Draining)
            status = ServiceEndpointStatus::Closing;
        else if (slot->state == ServiceEndpointSlotState::Drained)
            status = ServiceEndpointStatus::Drained;
        else if (slot->state != ServiceEndpointSlotState::Open)
            status = ServiceEndpointStatus::CorruptState;
        else
            core = &slot->core;
    }
    if (status != ServiceEndpointStatus::Ok)
    {
        ipc::KObjectRelease(retained_object);
        return OperationFailure(status);
    }

    const ipc::ChannelCorePinResult pinned = ipc::ChannelCoreAcquireOperation(
        core, identity.channel.channel_epoch, ServiceEndpointOperationBinding(identity.role));
    if (pinned.status != ipc::ChannelCoreStatus::Ok)
    {
        ipc::KObjectRelease(retained_object);
        return OperationFailure(OperationAcquireFailureStatus(pinned.status), pinned.status);
    }
    return ServiceEndpointOperationResult{
        ServiceEndpointStatus::Ok,
        ipc::ChannelCoreStatus::Ok,
        ServiceEndpointOperation{endpoint, identity, pinned.pin},
    };
}

ServiceEndpointDirectionResult ServiceEndpointBorrowDirection(const ServiceEndpointOperation* operation,
                                                              ServiceEndpointTrafficDirection direction)
{
    if (operation == nullptr || !ServiceEndpointOperationIsValid(*operation) ||
        !ServiceEndpointTrafficDirectionIsValid(direction))
    {
        return DirectionFailure(ServiceEndpointStatus::InvalidArgument);
    }
    ServiceEndpointOwner* owner = operation->endpoint->owner;
    if (owner == nullptr || ReadyStatus(owner) != ServiceEndpointStatus::Ok)
        return DirectionFailure(ServiceEndpointStatus::StaleIdentity);

    ipc::ChannelCore* core = nullptr;
    {
        OwnerGuard guard(*owner);
        ServiceEndpointOwnerSlot* slot = ResolveExactLocked(*owner, operation->identity.channel);
        const u32 role_index = ServiceEndpointRoleIndex(operation->identity.role);
        if (slot == nullptr || &slot->endpoints[role_index] != operation->endpoint)
            return DirectionFailure(ServiceEndpointStatus::StaleIdentity);
        core = &slot->core;
    }
    const ipc::ChannelCoreDirectionLease lease = ipc::ChannelCoreBorrowDirection(
        core, operation->core_pin, ResolveDirection(operation->identity.role, direction));
    return lease.status == ipc::ChannelCoreStatus::Ok
               ? ServiceEndpointDirectionResult{ServiceEndpointStatus::Ok, ipc::ChannelCoreStatus::Ok, lease}
               : DirectionFailure(lease.status == ipc::ChannelCoreStatus::Draining
                                      ? ServiceEndpointStatus::Closing
                                      : ServiceEndpointStatus::CorruptState,
                                  lease.status);
}

ServiceEndpointRequestReserveResult ServiceEndpointReserveRequest(const ServiceEndpointOperation* operation,
                                                                  u64 request_id)
{
    if (operation == nullptr || !ServiceEndpointOperationIsValid(*operation) ||
        request_id == ipc::kEndpointRequestIdInvalid)
    {
        return RequestFailure(ServiceEndpointStatus::InvalidArgument, ipc::ChannelCoreStatus::InvalidArgument,
                              ipc::EndpointRequestLedgerStatus::InvalidArgument);
    }
    ServiceEndpointOwner* owner = operation->endpoint->owner;
    if (owner == nullptr || ReadyStatus(owner) != ServiceEndpointStatus::Ok)
        return RequestFailure(ServiceEndpointStatus::StaleIdentity);

    ipc::ChannelCore* core = nullptr;
    {
        OwnerGuard guard(*owner);
        ServiceEndpointOwnerSlot* slot = ResolveExactLocked(*owner, operation->identity.channel);
        const u32 role_index = ServiceEndpointRoleIndex(operation->identity.role);
        if (slot == nullptr || &slot->endpoints[role_index] != operation->endpoint)
            return RequestFailure(ServiceEndpointStatus::StaleIdentity);
        core = &slot->core;
    }
    const ipc::ChannelCoreRequestReserveResult reserved = ipc::ChannelCoreReserveRequest(
        core, operation->core_pin, ResolveDirection(operation->identity.role, ServiceEndpointTrafficDirection::Send),
        request_id);
    return reserved.status == ipc::ChannelCoreStatus::Ok
               ? ServiceEndpointRequestReserveResult{ServiceEndpointStatus::Ok, ipc::ChannelCoreStatus::Ok,
                                                     reserved.ledger_status, reserved.request_key}
               : RequestFailure(RequestChannelFailureStatus(reserved.status), reserved.status, reserved.ledger_status);
}

ServiceEndpointRequestReserveResult ServiceEndpointReserveRequest(const ServiceEndpointOperation* operation,
                                                                  ServiceEndpointTrafficDirection direction,
                                                                  u64 request_id)
{
    if (direction != ServiceEndpointTrafficDirection::Send)
    {
        return RequestFailure(ServiceEndpointStatus::InvalidArgument, ipc::ChannelCoreStatus::InvalidArgument,
                              ipc::EndpointRequestLedgerStatus::InvalidArgument);
    }
    return ServiceEndpointReserveRequest(operation, request_id);
}

ServiceEndpointRequestCommitResult ServiceEndpointCommitReceivedRequest(const ServiceEndpointOperation* operation,
                                                                        ipc::EndpointRequestKey request_key)
{
    if (operation == nullptr || !ServiceEndpointOperationIsValid(*operation) ||
        !ipc::EndpointRequestKeyIsValid(request_key))
    {
        return RequestCommitFailure(ServiceEndpointStatus::InvalidArgument, ipc::ChannelCoreStatus::InvalidArgument,
                                    ipc::EndpointRequestLedgerStatus::InvalidArgument);
    }
    ServiceEndpointOwner* owner = operation->endpoint->owner;
    if (owner == nullptr || ReadyStatus(owner) != ServiceEndpointStatus::Ok)
        return RequestCommitFailure(ServiceEndpointStatus::StaleIdentity);

    ipc::ChannelCore* core = nullptr;
    {
        OwnerGuard guard(*owner);
        ServiceEndpointOwnerSlot* slot = ResolveExactLocked(*owner, operation->identity.channel);
        const u32 role_index = ServiceEndpointRoleIndex(operation->identity.role);
        if (slot == nullptr || &slot->endpoints[role_index] != operation->endpoint)
            return RequestCommitFailure(ServiceEndpointStatus::StaleIdentity);
        core = &slot->core;
    }
    const ipc::ChannelCoreRequestCommitResult committed = ipc::ChannelCoreCommitRequest(
        core, operation->core_pin, ResolveDirection(operation->identity.role, ServiceEndpointTrafficDirection::Receive),
        request_key);
    return committed.status == ipc::ChannelCoreStatus::Ok
               ? ServiceEndpointRequestCommitResult{ServiceEndpointStatus::Ok, ipc::ChannelCoreStatus::Ok,
                                                    committed.ledger_status, committed.completion_authority}
               : RequestCommitFailure(RequestChannelFailureStatus(committed.status), committed.status,
                                      committed.ledger_status);
}

ServiceEndpointRequestTransitionResult ServiceEndpointRejectReceivedRequest(const ServiceEndpointOperation* operation,
                                                                            ipc::EndpointRequestKey* request_key)
{
    if (operation == nullptr || !ServiceEndpointOperationIsValid(*operation) || request_key == nullptr ||
        !ipc::EndpointRequestKeyIsValid(*request_key))
    {
        return RequestTransitionFailure(ServiceEndpointStatus::InvalidArgument, ipc::ChannelCoreStatus::InvalidArgument,
                                        ipc::EndpointRequestLedgerStatus::InvalidArgument);
    }
    const ipc::EndpointRequestKey supplied_key = *request_key;
    ServiceEndpointOwner* owner = operation->endpoint->owner;
    if (owner == nullptr || ReadyStatus(owner) != ServiceEndpointStatus::Ok)
        return RequestTransitionFailure(ServiceEndpointStatus::StaleIdentity);

    ipc::ChannelCore* core = nullptr;
    {
        OwnerGuard guard(*owner);
        ServiceEndpointOwnerSlot* slot = ResolveExactLocked(*owner, operation->identity.channel);
        const u32 role_index = ServiceEndpointRoleIndex(operation->identity.role);
        if (slot == nullptr || &slot->endpoints[role_index] != operation->endpoint)
            return RequestTransitionFailure(ServiceEndpointStatus::StaleIdentity);
        core = &slot->core;
    }
    const ipc::ChannelCoreRequestTransitionResult cancelled = ipc::ChannelCoreCancelRequest(
        core, operation->core_pin, ResolveDirection(operation->identity.role, ServiceEndpointTrafficDirection::Receive),
        supplied_key);
    if (cancelled.status != ipc::ChannelCoreStatus::Ok)
    {
        return RequestTransitionFailure(RequestChannelFailureStatus(cancelled.status), cancelled.status,
                                        cancelled.ledger_status);
    }
    *request_key = ipc::kInvalidEndpointRequestKey;
    return ServiceEndpointRequestTransitionResult{ServiceEndpointStatus::Ok, ipc::ChannelCoreStatus::Ok,
                                                  cancelled.ledger_status};
}

ServiceEndpointRequestTransitionResult ServiceEndpointCancelSentRequest(const ServiceEndpointOperation* operation,
                                                                        ipc::EndpointRequestKey* request_key)
{
    if (operation == nullptr || !ServiceEndpointOperationIsValid(*operation) || request_key == nullptr ||
        !ipc::EndpointRequestKeyIsValid(*request_key))
    {
        return RequestTransitionFailure(ServiceEndpointStatus::InvalidArgument, ipc::ChannelCoreStatus::InvalidArgument,
                                        ipc::EndpointRequestLedgerStatus::InvalidArgument);
    }
    const ipc::EndpointRequestKey supplied_key = *request_key;
    ServiceEndpointOwner* owner = operation->endpoint->owner;
    if (owner == nullptr || ReadyStatus(owner) != ServiceEndpointStatus::Ok)
        return RequestTransitionFailure(ServiceEndpointStatus::StaleIdentity);

    ipc::ChannelCore* core = nullptr;
    {
        OwnerGuard guard(*owner);
        ServiceEndpointOwnerSlot* slot = ResolveExactLocked(*owner, operation->identity.channel);
        const u32 role_index = ServiceEndpointRoleIndex(operation->identity.role);
        if (slot == nullptr || &slot->endpoints[role_index] != operation->endpoint)
            return RequestTransitionFailure(ServiceEndpointStatus::StaleIdentity);
        core = &slot->core;
    }
    const ipc::ChannelCoreRequestTransitionResult cancelled = ipc::ChannelCoreCancelRequest(
        core, operation->core_pin, ResolveDirection(operation->identity.role, ServiceEndpointTrafficDirection::Send),
        supplied_key);
    if (cancelled.status != ipc::ChannelCoreStatus::Ok)
    {
        return RequestTransitionFailure(RequestChannelFailureStatus(cancelled.status), cancelled.status,
                                        cancelled.ledger_status);
    }
    *request_key = ipc::kInvalidEndpointRequestKey;
    return ServiceEndpointRequestTransitionResult{ServiceEndpointStatus::Ok, ipc::ChannelCoreStatus::Ok,
                                                  cancelled.ledger_status};
}

ServiceEndpointRequestTransitionResult ServiceEndpointCompleteReceivedRequest(
    const ServiceEndpointOperation* operation, ipc::EndpointRequestCompletionAuthority* completion_authority)
{
    if (operation == nullptr || !ServiceEndpointOperationIsValid(*operation) || completion_authority == nullptr ||
        !ipc::EndpointRequestCompletionAuthorityIsValid(*completion_authority))
    {
        return RequestTransitionFailure(ServiceEndpointStatus::InvalidArgument, ipc::ChannelCoreStatus::InvalidArgument,
                                        ipc::EndpointRequestLedgerStatus::InvalidArgument);
    }
    const ipc::EndpointRequestCompletionAuthority supplied_authority = *completion_authority;
    ServiceEndpointOwner* owner = operation->endpoint->owner;
    if (owner == nullptr || ReadyStatus(owner) != ServiceEndpointStatus::Ok)
        return RequestTransitionFailure(ServiceEndpointStatus::StaleIdentity);

    ipc::ChannelCore* core = nullptr;
    {
        OwnerGuard guard(*owner);
        ServiceEndpointOwnerSlot* slot = ResolveExactLocked(*owner, operation->identity.channel);
        const u32 role_index = ServiceEndpointRoleIndex(operation->identity.role);
        if (slot == nullptr || &slot->endpoints[role_index] != operation->endpoint)
            return RequestTransitionFailure(ServiceEndpointStatus::StaleIdentity);
        core = &slot->core;
    }
    const ipc::ChannelCoreRequestTransitionResult completed = ipc::ChannelCoreCompleteRequest(
        core, operation->core_pin, ResolveDirection(operation->identity.role, ServiceEndpointTrafficDirection::Receive),
        supplied_authority);
    if (completed.status != ipc::ChannelCoreStatus::Ok)
    {
        return RequestTransitionFailure(RequestChannelFailureStatus(completed.status), completed.status,
                                        completed.ledger_status);
    }
    *completion_authority = ipc::kInvalidEndpointRequestCompletionAuthority;
    return ServiceEndpointRequestTransitionResult{ServiceEndpointStatus::Ok, ipc::ChannelCoreStatus::Ok,
                                                  completed.ledger_status};
}

ServiceEndpointStatus ServiceEndpointReleaseOperation(ServiceEndpointOperation* operation)
{
    if (operation == nullptr || !ServiceEndpointOperationIsValid(*operation))
        return ServiceEndpointStatus::InvalidArgument;
    const ServiceEndpointOperation supplied = *operation;
    ServiceEndpointOwner* owner = supplied.endpoint->owner;
    if (owner == nullptr || ReadyStatus(owner) != ServiceEndpointStatus::Ok)
        return ServiceEndpointStatus::StaleIdentity;

    ipc::ChannelCore* core = nullptr;
    {
        OwnerGuard guard(*owner);
        ServiceEndpointOwnerSlot* slot = ResolveExactLocked(*owner, supplied.identity.channel);
        const u32 role_index = ServiceEndpointRoleIndex(supplied.identity.role);
        if (slot == nullptr || &slot->endpoints[role_index] != supplied.endpoint)
            return ServiceEndpointStatus::StaleIdentity;
        core = &slot->core;
    }
    const ipc::ChannelCoreStatus released = ipc::ChannelCoreReleaseOperation(core, supplied.core_pin);
    if (released != ipc::ChannelCoreStatus::Ok)
        return ServiceEndpointStatus::CorruptState;

    bool drive_drain = false;
    {
        // A normal operation release must not initiate endpoint shutdown. It
        // only helps an already-started close make progress once its last core
        // pin has quiesced.
        OwnerGuard guard(*owner);
        ServiceEndpointOwnerSlot* slot = ResolveExactLocked(*owner, supplied.identity.channel);
        const u32 role_index = ServiceEndpointRoleIndex(supplied.identity.role);
        if (slot == nullptr || &slot->endpoints[role_index] != supplied.endpoint)
            return ServiceEndpointStatus::StaleIdentity;
        drive_drain = slot->state == ServiceEndpointSlotState::Draining;
    }

    *operation = kInvalidServiceEndpointOperation;
    if (drive_drain)
        (void)DriveDrain(owner, supplied.identity.channel);
    ipc::KObjectRelease(&supplied.endpoint->base);
    return ServiceEndpointStatus::Ok;
}

ServiceEndpointStatus ServiceEndpointInspectObject(ipc::KObject* retained_object, ServiceEndpointIdentity* identity,
                                                   ServiceEndpointProtocolAuthority* protocol,
                                                   ServiceEndpointPeerSnapshot* peer)
{
    if (retained_object == nullptr || retained_object->type != ipc::KObjectType::ServiceEndpoint ||
        identity == nullptr || protocol == nullptr || peer == nullptr ||
        PointerRangesOverlap(identity, sizeof(*identity), protocol, sizeof(*protocol)) ||
        PointerRangesOverlap(identity, sizeof(*identity), peer, sizeof(*peer)) ||
        PointerRangesOverlap(protocol, sizeof(*protocol), peer, sizeof(*peer)) ||
        PointerRangesOverlap(identity, sizeof(*identity), retained_object, sizeof(ServiceEndpointObject)) ||
        PointerRangesOverlap(protocol, sizeof(*protocol), retained_object, sizeof(ServiceEndpointObject)) ||
        PointerRangesOverlap(peer, sizeof(*peer), retained_object, sizeof(ServiceEndpointObject)))
    {
        return ServiceEndpointStatus::InvalidArgument;
    }
    auto* endpoint = reinterpret_cast<ServiceEndpointObject*>(retained_object);
    ServiceEndpointOwner* owner = endpoint->owner;
    if (owner == nullptr || ReadyStatus(owner) != ServiceEndpointStatus::Ok)
        return ServiceEndpointStatus::StaleIdentity;

    ServiceEndpointIdentity identity_snapshot{};
    ServiceEndpointProtocolAuthority protocol_snapshot{};
    ServiceEndpointPeerSnapshot peer_snapshot{};
    {
        OwnerGuard guard(*owner);
        const ServiceEndpointIdentity supplied = endpoint->identity;
        if (!ServiceEndpointIdentityIsValid(supplied))
            return ServiceEndpointStatus::StaleIdentity;
        ServiceEndpointOwnerSlot* slot = ResolveExactLocked(*owner, supplied.channel);
        const u32 role_index = ServiceEndpointRoleIndex(supplied.role);
        if (slot == nullptr || &slot->endpoints[role_index] != endpoint || !slot->endpoint_reference_live[role_index])
            return ServiceEndpointStatus::StaleIdentity;
        identity_snapshot = endpoint->identity;
        protocol_snapshot = endpoint->protocol;
        peer_snapshot = endpoint->peer;
    }
    *identity = identity_snapshot;
    *protocol = protocol_snapshot;
    *peer = peer_snapshot;
    return ServiceEndpointStatus::Ok;
}

ServiceEndpointInspectResult ServiceEndpointInspectExact(ServiceEndpointOwner* owner, ServiceEndpointChannelKey channel)
{
    if (!ServiceEndpointChannelKeyIsValid(channel))
        return InspectFailure(ServiceEndpointStatus::InvalidArgument);
    const ServiceEndpointStatus ready = ReadyStatus(owner);
    if (ready != ServiceEndpointStatus::Ok)
        return InspectFailure(ready);

    OwnerGuard guard(*owner);
    ServiceEndpointOwnerSlot* slot = ResolveExactLocked(*owner, channel);
    if (slot == nullptr)
        return InspectFailure(ServiceEndpointStatus::StaleIdentity);
    ServiceEndpointSnapshot snapshot{};
    snapshot.channel = slot->key;
    snapshot.state = slot->state;
    snapshot.outer_owner_live = slot->outer_owner_live;
    snapshot.endpoint_reference_live[0] = slot->endpoint_reference_live[0];
    snapshot.endpoint_reference_live[1] = slot->endpoint_reference_live[1];
    snapshot.drain_driver_active = slot->drain_driver_active;
    snapshot.drain_retry_requested = slot->drain_retry_requested;
    snapshot.detached_cleanup_live = !ipc::ChannelCoreDetachedCleanupIsEmpty(slot->detached_cleanup);
    snapshot.request_cleanup_failed = slot->request_cleanup_failed;
    return ServiceEndpointInspectResult{ServiceEndpointStatus::Ok, snapshot};
}

const char* ServiceEndpointStatusName(ServiceEndpointStatus status)
{
    switch (status)
    {
    case ServiceEndpointStatus::Ok:
        return "ok";
    case ServiceEndpointStatus::InvalidArgument:
        return "invalid-argument";
    case ServiceEndpointStatus::NotInitialized:
        return "not-initialized";
    case ServiceEndpointStatus::AlreadyInitialized:
        return "already-initialized";
    case ServiceEndpointStatus::CorruptState:
        return "corrupt-state";
    case ServiceEndpointStatus::CapacityExhausted:
        return "capacity-exhausted";
    case ServiceEndpointStatus::GenerationExhausted:
        return "generation-exhausted";
    case ServiceEndpointStatus::ChannelCreateFailed:
        return "channel-create-failed";
    case ServiceEndpointStatus::NotPublished:
        return "not-published";
    case ServiceEndpointStatus::AlreadyPublished:
        return "already-published";
    case ServiceEndpointStatus::Closing:
        return "closing";
    case ServiceEndpointStatus::Drained:
        return "drained";
    case ServiceEndpointStatus::StaleIdentity:
        return "stale-identity";
    case ServiceEndpointStatus::StaleActivation:
        return "stale-activation";
    case ServiceEndpointStatus::StaleOwner:
        return "stale-owner";
    case ServiceEndpointStatus::Busy:
        return "busy";
    case ServiceEndpointStatus::InvalidCleanup:
        return "invalid-cleanup";
    case ServiceEndpointStatus::ResourceReleaseFailed:
        return "resource-release-failed";
    case ServiceEndpointStatus::RequestRejected:
        return "request-rejected";
    }
    return "unknown";
}

#if defined(DUETOS_HOST_TEST)
bool ServiceEndpointHostSetLastGenerationForTest(u32 slot, u64 last_generation)
{
    if (slot >= kServiceEndpointOwnerCapacity || last_generation > kServiceEndpointGenerationMaximum)
        return false;
    if (last_generation < AtomicLoadGeneration(&g_last_endpoint_generations[slot]))
        return false;
    AtomicStoreGeneration(&g_last_endpoint_generations[slot], last_generation);
    return true;
}
#endif

} // namespace duetos::core
