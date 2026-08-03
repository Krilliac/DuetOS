#include "core/service_lifecycle_broker.h"

#include "core/service_directory.h"

#if defined(DUETOS_HOST_TEST)
#include <atomic>
#endif

namespace duetos::core
{

namespace
{

u64 g_next_broker_epoch = 1;

u64 AtomicLoadEpoch(u64* value)
{
#if defined(DUETOS_HOST_TEST)
    return std::atomic_ref<u64>(*value).load(std::memory_order_relaxed);
#else
    return __atomic_load_n(value, __ATOMIC_RELAXED);
#endif
}

bool AtomicCompareExchangeEpoch(u64* value, u64* expected, u64 desired)
{
#if defined(DUETOS_HOST_TEST)
    return std::atomic_ref<u64>(*value).compare_exchange_weak(*expected, desired, std::memory_order_relaxed,
                                                              std::memory_order_relaxed);
#else
    return __atomic_compare_exchange_n(value, expected, desired, true, __ATOMIC_RELAXED, __ATOMIC_RELAXED);
#endif
}

bool RangeIsValid(const void* pointer, u64 bytes)
{
    if (pointer == nullptr || bytes == 0 || bytes > static_cast<u64>(~static_cast<uptr>(0)))
        return false;
    const uptr begin = reinterpret_cast<uptr>(pointer);
    return static_cast<uptr>(bytes) <= ~static_cast<uptr>(0) - begin;
}

bool RangesOverlap(const void* left, u64 left_bytes, const void* right, u64 right_bytes)
{
    const uptr left_begin = reinterpret_cast<uptr>(left);
    const uptr right_begin = reinterpret_cast<uptr>(right);
    return left_begin < right_begin + static_cast<uptr>(right_bytes) &&
           right_begin < left_begin + static_cast<uptr>(left_bytes);
}

void ClearRow(ServiceLifecycleRow* row)
{
    *row = ServiceLifecycleRow{};
}

void ClearBroker(ServiceLifecycleBroker* broker)
{
    broker->lock = sync::SpinLock{0, 0, 0xFFFFFFFFu, sync::kLockClassServiceLifecycle};
    broker->state = ServiceLifecycleBrokerState::Uninitialized;
    broker->initialized = 0;
    broker->service_count = 0;
    broker->dependency_count = 0;
    broker->reserved16 = 0;
    broker->broker_epoch = kServiceLifecycleInvalidBrokerEpoch;
    broker->manifest_identity = 0;
    broker->manifest_authority_identity = 0;
    broker->manifest_object_hash = {};
    broker->manifest_object_extent = 0;
    for (u32 index = 0; index < kServiceLifecycleCapacity; ++index)
        ClearRow(&broker->rows[index]);
}

bool HashIsNonZero(const loader::Hash256& hash)
{
    u8 aggregate = 0;
    for (u32 index = 0; index < static_cast<u32>(sizeof(hash.bytes)); ++index)
        aggregate |= hash.bytes[index];
    return aggregate != 0;
}

bool HashEquals(const loader::Hash256& left, const loader::Hash256& right)
{
    u8 difference = 0;
    for (u32 index = 0; index < static_cast<u32>(sizeof(left.bytes)); ++index)
        difference |= left.bytes[index] ^ right.bytes[index];
    return difference == 0;
}

u32 FindDocumentIndex(const ServiceManifestDocumentV1& document, u64 identity)
{
    u32 low = 0;
    u32 high = document.service_count;
    while (low < high)
    {
        const u32 middle = low + (high - low) / 2;
        const u64 candidate = document.services[middle].service_identity;
        if (candidate < identity)
            low = middle + 1;
        else
            high = middle;
    }
    return low < document.service_count && document.services[low].service_identity == identity
               ? low
               : kServiceLifecycleCapacity;
}

bool ManifestPlanIsCanonical(const ServiceManifestPlanV1& plan, const ServiceManifestAuthoritySnapshotV1& authority)
{
    const ServiceManifestDocumentV1& document = plan.document;
    if (ServiceManifestDocumentValidateAgainstAuthorityV1(document, authority) != ServiceManifestError::Ok ||
        plan.authority_identity != authority.authority_identity || plan.topological_count != document.service_count ||
        plan.reserved16 != 0 || plan.reserved32 != 0 || plan.sealed_object_extent != authority.sealed_object_extent ||
        plan.sealed_object_extent != ServiceManifestEncodedSizeV1(document.service_count, document.dependency_count) ||
        !HashEquals(plan.sealed_object_hash, authority.sealed_object_hash) || !HashIsNonZero(plan.sealed_object_hash))
    {
        return false;
    }

    loader::Hash256 document_hash{};
    if (ServiceManifestDocumentHashV1(document, &document_hash) != ServiceManifestError::Ok ||
        !HashEquals(document_hash, plan.sealed_object_hash))
    {
        return false;
    }

    u64 visited = 0;
    for (u32 order = 0; order < plan.topological_count; ++order)
    {
        u32 selected = kServiceLifecycleCapacity;
        for (u32 candidate = 0; candidate < document.service_count; ++candidate)
        {
            if ((visited & (1ULL << candidate)) != 0)
                continue;
            const ServiceManifestServiceV1& service = document.services[candidate];
            const u32 dependency_end = static_cast<u32>(service.dependency_first) + service.dependency_count;
            bool ready = true;
            for (u32 dependency_index = service.dependency_first; dependency_index < dependency_end; ++dependency_index)
            {
                const u32 required_index =
                    FindDocumentIndex(document, document.dependencies[dependency_index].dependency_service_identity);
                if (required_index >= document.service_count || (visited & (1ULL << required_index)) == 0)
                {
                    ready = false;
                    break;
                }
            }
            if (ready)
            {
                selected = candidate;
                break; // Identity-sorted rows make this deterministic.
            }
        }
        if (selected >= document.service_count ||
            plan.topological_identities[order] != document.services[selected].service_identity)
        {
            return false;
        }
        visited |= 1ULL << selected;
    }

    for (u32 order = plan.topological_count; order < kServiceLifecycleCapacity; ++order)
    {
        if (plan.topological_identities[order] != 0)
            return false;
    }
    const u64 expected = document.service_count == 64 ? ~0ULL : ((1ULL << document.service_count) - 1ULL);
    return visited == expected;
}

bool BuilderStateIsCanonical(const ServiceLifecycleRow& row)
{
    switch (row.builder_state)
    {
    case ServiceLifecycleBuilderState::None:
        return row.transition.phase != ServiceTransitionPhase::Starting;
    case ServiceLifecycleBuilderState::Constructing:
        return row.transition.phase == ServiceTransitionPhase::Starting;
    case ServiceLifecycleBuilderState::CancelledAwaitingRetirement:
        return row.transition.generation != 0 && (row.transition.phase == ServiceTransitionPhase::Stopped ||
                                                  row.transition.phase == ServiceTransitionPhase::GenerationExhausted);
    }
    return false;
}

bool BrokerHeaderIsCanonical(const ServiceLifecycleBroker& broker)
{
    if (broker.initialized != 1 || broker.service_count == 0 || broker.service_count > kServiceLifecycleCapacity ||
        broker.dependency_count > kServiceManifestMaximumDependencies || broker.reserved16 != 0 ||
        broker.broker_epoch == kServiceLifecycleInvalidBrokerEpoch || broker.manifest_identity == 0 ||
        broker.manifest_authority_identity == 0 || !HashIsNonZero(broker.manifest_object_hash) ||
        broker.manifest_object_extent != ServiceManifestEncodedSizeV1(broker.service_count, broker.dependency_count))
    {
        return false;
    }
    return broker.state == ServiceLifecycleBrokerState::Open || broker.state == ServiceLifecycleBrokerState::Draining ||
           broker.state == ServiceLifecycleBrokerState::Closed;
}

bool BrokerRowsAreCanonical(const ServiceLifecycleBroker& broker)
{
    const u64 valid_mask = broker.service_count == 64 ? ~0ULL : ((1ULL << broker.service_count) - 1ULL);
    u64 previous_identity = 0;
    for (u32 index = 0; index < broker.service_count; ++index)
    {
        const ServiceLifecycleRow& row = broker.rows[index];
        if (!ServiceTransitionIsCanonical(row.transition) || row.transition.service_identity <= previous_identity ||
            !BuilderStateIsCanonical(row) || row.reserved8 != 0 || row.reserved16 != 0 || row.reserved32 != 0 ||
            (row.dependency_mask & ~valid_mask) != 0 || (row.dependency_mask & (1ULL << index)) != 0 ||
            row.failed_exits > row.observed_exits || row.observed_exits > row.successful_publications ||
            static_cast<u64>(row.successful_publications) > row.transition.generation ||
            static_cast<u64>(row.spawn_failures) > row.transition.generation ||
            static_cast<u64>(row.successful_publications) + row.spawn_failures > row.transition.generation)
        {
            return false;
        }
        const ServiceTransitionPhase phase = row.transition.phase;
        if (row.ready &&
            (phase != ServiceTransitionPhase::Running || !ServiceInstanceKeyIsValid(row.transition.instance) ||
             row.builder_state != ServiceLifecycleBuilderState::None))
        {
            return false;
        }
        if (broker.state != ServiceLifecycleBrokerState::Open &&
            (phase == ServiceTransitionPhase::Starting || phase == ServiceTransitionPhase::Running))
        {
            return false;
        }
        if (broker.state == ServiceLifecycleBrokerState::Closed &&
            (phase == ServiceTransitionPhase::Stopping || row.builder_state != ServiceLifecycleBuilderState::None))
        {
            return false;
        }
        previous_identity = row.transition.service_identity;
    }
    return true;
}

bool DependenciesAreRunningLocked(const ServiceLifecycleBroker& broker, const ServiceLifecycleRow& row)
{
    for (u32 index = 0; index < broker.service_count; ++index)
    {
        if ((row.dependency_mask & (1ULL << index)) == 0)
            continue;
        const ServiceLifecycleRow& dependency = broker.rows[index];
        if (dependency.transition.phase != ServiceTransitionPhase::Running ||
            !ServiceInstanceKeyIsValid(dependency.transition.instance) ||
            dependency.builder_state != ServiceLifecycleBuilderState::None || !dependency.ready)
        {
            return false;
        }
    }
    return true;
}

bool BrokerIsCanonical(const ServiceLifecycleBroker& broker)
{
    return BrokerHeaderIsCanonical(broker) && BrokerRowsAreCanonical(broker);
}

u32 FindBrokerIndex(const ServiceLifecycleBroker& broker, u64 identity)
{
    u32 low = 0;
    u32 high = broker.service_count;
    while (low < high)
    {
        const u32 middle = low + (high - low) / 2;
        const u64 candidate = broker.rows[middle].transition.service_identity;
        if (candidate < identity)
            low = middle + 1;
        else
            high = middle;
    }
    return low < broker.service_count && broker.rows[low].transition.service_identity == identity
               ? low
               : kServiceLifecycleCapacity;
}

void IncrementSaturating(u32* value)
{
    if (*value != ~0U)
        ++*value;
}

ServiceLifecycleStartResult StartFailure(ServiceLifecycleStatus status)
{
    return ServiceLifecycleStartResult{status, kInvalidServiceLifecycleStartTicket};
}

ServiceLifecyclePublicationResult PublicationFailure(ServiceLifecycleStatus status)
{
    return ServiceLifecyclePublicationResult{status, kInvalidServiceLifecycleInstanceToken};
}

ServiceLifecycleDirectoryPublicationResult DirectoryPublicationFailure(
    ServiceLifecycleStatus lifecycle_status, ServiceDirectoryStatus directory_status = ServiceDirectoryStatus::Ok)
{
    return ServiceLifecycleDirectoryPublicationResult{lifecycle_status, directory_status,
                                                      kInvalidServiceLifecycleInstanceToken};
}

ServiceLifecycleDirectoryReadyResult DirectoryReadyFailure(
    ServiceLifecycleStatus lifecycle_status, ServiceDirectoryStatus directory_status = ServiceDirectoryStatus::Ok)
{
    return ServiceLifecycleDirectoryReadyResult{lifecycle_status, directory_status};
}

// This token never crosses the broker implementation boundary.  It exists
// only while CommitDirectoryPublication holds the lifecycle lock, so it cannot
// be retained and replayed after scheduler visibility.  Capturing the complete
// pre-commit row makes rollback exact rather than a hand-authored inverse.
struct UnpublishedPublicationRollbackToken
{
    u64 broker_epoch;
    u32 row_index;
    ServiceLifecycleStartTicket ticket;
    ServiceInstanceKey instance;
    ServiceLifecycleRow prior_row;
    bool valid;
};

ServiceLifecycleStatus RollbackUnpublishedPublicationLocked(ServiceLifecycleBroker& broker,
                                                            UnpublishedPublicationRollbackToken* rollback)
{
    if (rollback == nullptr || !rollback->valid || rollback->broker_epoch != broker.broker_epoch ||
        rollback->row_index >= broker.service_count || !ServiceLifecycleStartTicketIsValid(rollback->ticket) ||
        !ServiceInstanceKeyIsValid(rollback->instance))
    {
        return ServiceLifecycleStatus::TransitionRejected;
    }

    ServiceLifecycleRow& row = broker.rows[rollback->row_index];
    const u32 expected_publications =
        rollback->prior_row.successful_publications == ~0U ? ~0U : rollback->prior_row.successful_publications + 1U;
    if (row.transition.service_identity != rollback->ticket.transition.service_identity ||
        row.transition.generation != rollback->ticket.transition.generation ||
        row.builder_state != ServiceLifecycleBuilderState::None ||
        !ServiceTransitionIsCurrentRunning(row.transition,
                                           ServiceInstanceToken{rollback->ticket.transition, rollback->instance}) ||
        row.successful_publications != expected_publications ||
        !ServiceTransitionIsCurrentStart(rollback->prior_row.transition, rollback->ticket.transition) ||
        rollback->prior_row.builder_state != ServiceLifecycleBuilderState::Constructing)
    {
        return ServiceLifecycleStatus::TransitionRejected;
    }

    row = rollback->prior_row;
    rollback->valid = false;
    return ServiceLifecycleStatus::Ok;
}

ServiceLifecycleStopResult StopFailure(ServiceLifecycleStatus status)
{
    return ServiceLifecycleStopResult{status, kInvalidServiceLifecycleInstanceToken,
                                      kInvalidServiceLifecycleStartTicket};
}

ServiceLifecycleInspectResult InspectFailure(ServiceLifecycleStatus status)
{
    return ServiceLifecycleInspectResult{status, ServiceLifecycleSnapshot{}};
}

ServiceLifecycleBrokerInspectResult BrokerInspectFailure(ServiceLifecycleStatus status)
{
    return ServiceLifecycleBrokerInspectResult{status, ServiceLifecycleBrokerSnapshot{}};
}

ServiceLifecycleSnapshot SnapshotRow(const ServiceLifecycleRow& row)
{
    return ServiceLifecycleSnapshot{row.transition.service_identity,
                                    row.transition.phase,
                                    row.transition.generation,
                                    row.transition.instance,
                                    row.dependency_mask,
                                    row.last_transition_ns,
                                    row.successful_publications,
                                    row.spawn_failures,
                                    row.observed_exits,
                                    row.failed_exits,
                                    row.builder_state,
                                    row.ready};
}

ServiceLifecycleBrokerSnapshot SnapshotBroker(const ServiceLifecycleBroker& broker)
{
    return ServiceLifecycleBrokerSnapshot{broker.state,
                                          broker.service_count,
                                          broker.dependency_count,
                                          broker.broker_epoch,
                                          broker.manifest_identity,
                                          broker.manifest_authority_identity,
                                          broker.manifest_object_hash,
                                          broker.manifest_object_extent};
}

ServiceLifecycleStatus ValidateTicketEpoch(const ServiceLifecycleBroker& broker, ServiceLifecycleStartTicket ticket)
{
    if (!ServiceLifecycleStartTicketIsValid(ticket))
        return ServiceLifecycleStatus::TransitionRejected;
    return ticket.broker_epoch == broker.broker_epoch ? ServiceLifecycleStatus::Ok
                                                      : ServiceLifecycleStatus::StaleBrokerEpoch;
}

ServiceLifecycleStatus ValidateTokenEpoch(const ServiceLifecycleBroker& broker, ServiceLifecycleInstanceToken token)
{
    if (!ServiceLifecycleInstanceTokenIsValid(token))
        return ServiceLifecycleStatus::TransitionRejected;
    return token.start.broker_epoch == broker.broker_epoch ? ServiceLifecycleStatus::Ok
                                                           : ServiceLifecycleStatus::StaleBrokerEpoch;
}

ServiceLifecycleStatus ReadyBroker(ServiceLifecycleBroker* broker)
{
    if (!RangeIsValid(broker, sizeof(*broker)))
        return ServiceLifecycleStatus::NullArgument;
    if (broker->initialized != 1)
        return ServiceLifecycleStatus::NotInitialized;
    return ServiceLifecycleStatus::Ok;
}

ServiceLifecycleStartResult ReserveStartLocked(ServiceLifecycleBroker& broker, u64 service_identity,
                                               u64 expected_generation, u64 now_ns, bool require_dependencies)
{
    if (!BrokerIsCanonical(broker))
        return StartFailure(ServiceLifecycleStatus::CorruptState);
    if (broker.state == ServiceLifecycleBrokerState::Closed)
        return StartFailure(ServiceLifecycleStatus::Closed);
    if (broker.state == ServiceLifecycleBrokerState::Draining)
        return StartFailure(ServiceLifecycleStatus::Draining);

    const u32 index = FindBrokerIndex(broker, service_identity);
    if (index >= broker.service_count)
        return StartFailure(ServiceLifecycleStatus::NotFound);
    ServiceLifecycleRow& row = broker.rows[index];
    if (row.transition.generation != expected_generation)
        return StartFailure(ServiceLifecycleStatus::StaleGeneration);
    if (now_ns < row.last_transition_ns)
        return StartFailure(ServiceLifecycleStatus::InvalidTimestamp);
    if (row.builder_state == ServiceLifecycleBuilderState::CancelledAwaitingRetirement)
        return StartFailure(ServiceLifecycleStatus::StartRetirementPending);
    if (require_dependencies && !DependenciesAreRunningLocked(broker, row))
        return StartFailure(ServiceLifecycleStatus::DependencyNotReady);

    ServiceStartTicket ticket = kInvalidServiceStartTicket;
    const ServiceTransitionPhase prior_phase = row.transition.phase;
    switch (ServiceTransitionReserveStart(&row.transition, &ticket))
    {
    case ServiceStartReserveResult::Reserved:
        row.builder_state = ServiceLifecycleBuilderState::Constructing;
        row.ready = false;
        row.last_transition_ns = now_ns;
        return ServiceLifecycleStartResult{ServiceLifecycleStatus::Ok,
                                           ServiceLifecycleStartTicket{broker.broker_epoch, ticket}};
    case ServiceStartReserveResult::AlreadyRequested:
        return StartFailure(ServiceLifecycleStatus::AlreadyRequested);
    case ServiceStartReserveResult::StopInProgress:
        return StartFailure(ServiceLifecycleStatus::StopInProgress);
    case ServiceStartReserveResult::GenerationExhausted:
        if (prior_phase != ServiceTransitionPhase::GenerationExhausted)
            row.last_transition_ns = now_ns;
        return StartFailure(ServiceLifecycleStatus::GenerationExhausted);
    case ServiceStartReserveResult::Rejected:
        return StartFailure(ServiceLifecycleStatus::TransitionRejected);
    }
    return StartFailure(ServiceLifecycleStatus::CorruptState);
}

} // namespace

ServiceLifecycleBrokerEpoch ServiceLifecycleBrokerMintEpoch()
{
    u64 current = AtomicLoadEpoch(&g_next_broker_epoch);
    while (current != ~static_cast<u64>(0))
    {
        u64 expected = current;
        if (AtomicCompareExchangeEpoch(&g_next_broker_epoch, &expected, current + 1))
            return ServiceLifecycleBrokerEpoch(current);
        current = expected;
    }
    return ServiceLifecycleBrokerEpoch{};
}

ServiceLifecycleBroker::ServiceLifecycleBroker()
{
    ClearBroker(this);
}

ServiceLifecycleStatus ServiceLifecycleBrokerInitialize(ServiceLifecycleBroker* broker,
                                                        const ServiceManifestPlanV1* plan,
                                                        const ServiceManifestAuthoritySnapshotV1* authority,
                                                        ServiceLifecycleBrokerEpoch* broker_epoch)
{
    if (!RangeIsValid(broker, sizeof(*broker)) || !RangeIsValid(plan, sizeof(*plan)) ||
        !RangeIsValid(authority, sizeof(*authority)) || !RangeIsValid(broker_epoch, sizeof(*broker_epoch)))
        return ServiceLifecycleStatus::NullArgument;
    if (RangesOverlap(broker, sizeof(*broker), plan, sizeof(*plan)) ||
        RangesOverlap(broker, sizeof(*broker), authority, sizeof(*authority)) ||
        RangesOverlap(broker, sizeof(*broker), broker_epoch, sizeof(*broker_epoch)))
        return ServiceLifecycleStatus::AliasedOutput;
    if (RangesOverlap(plan, sizeof(*plan), authority, sizeof(*authority)) ||
        RangesOverlap(plan, sizeof(*plan), broker_epoch, sizeof(*broker_epoch)) ||
        RangesOverlap(authority, sizeof(*authority), broker_epoch, sizeof(*broker_epoch)))
        return ServiceLifecycleStatus::InvalidManifestPlan;

    if (broker->initialized != 0)
        return ServiceLifecycleStatus::AlreadyInitialized;
    if (!broker_epoch->IsValid())
        return ServiceLifecycleStatus::InvalidBrokerEpoch;
    if (!ManifestPlanIsCanonical(*plan, *authority))
        return ServiceLifecycleStatus::InvalidManifestPlan;

    const u64 broker_epoch_value = broker_epoch->m_value;
    ClearBroker(broker);
    const ServiceManifestDocumentV1& document = plan->document;
    broker->broker_epoch = broker_epoch_value;
    broker->manifest_identity = document.manifest_identity;
    broker->manifest_authority_identity = plan->authority_identity;
    broker->manifest_object_hash = plan->sealed_object_hash;
    broker->manifest_object_extent = plan->sealed_object_extent;
    broker->service_count = document.service_count;
    broker->dependency_count = document.dependency_count;

    for (u32 index = 0; index < document.service_count; ++index)
    {
        const ServiceManifestServiceV1& definition = document.services[index];
        ServiceLifecycleRow& row = broker->rows[index];
        if (!ServiceTransitionInitialize(definition.service_identity, &row.transition))
        {
            ClearBroker(broker);
            return ServiceLifecycleStatus::InvalidManifestPlan;
        }
        const u32 dependency_end = static_cast<u32>(definition.dependency_first) + definition.dependency_count;
        for (u32 dependency_index = definition.dependency_first; dependency_index < dependency_end; ++dependency_index)
        {
            const u32 required_index =
                FindDocumentIndex(document, document.dependencies[dependency_index].dependency_service_identity);
            if (required_index >= document.service_count)
            {
                ClearBroker(broker);
                return ServiceLifecycleStatus::InvalidManifestPlan;
            }
            row.dependency_mask |= 1ULL << required_index;
        }
    }

    broker->state = ServiceLifecycleBrokerState::Open;
    broker->initialized = 1;
    if (!BrokerIsCanonical(*broker))
    {
        ClearBroker(broker);
        return ServiceLifecycleStatus::InvalidManifestPlan;
    }
    broker_epoch->m_value = kServiceLifecycleInvalidBrokerEpoch;
    return ServiceLifecycleStatus::Ok;
}

ServiceLifecycleStartResult ServiceLifecycleBrokerReserveStart(ServiceLifecycleBroker* broker, u64 service_identity,
                                                               u64 expected_generation, u64 now_ns)
{
    const ServiceLifecycleStatus ready = ReadyBroker(broker);
    if (ready != ServiceLifecycleStatus::Ok)
        return StartFailure(ready);
    sync::SpinLockGuard guard(broker->lock);
    return ReserveStartLocked(*broker, service_identity, expected_generation, now_ns, false);
}

ServiceLifecycleStartResult ServiceLifecycleBrokerReserveStartWithDependencies(ServiceLifecycleBroker* broker,
                                                                               u64 service_identity,
                                                                               u64 expected_generation, u64 now_ns)
{
    const ServiceLifecycleStatus ready = ReadyBroker(broker);
    if (ready != ServiceLifecycleStatus::Ok)
        return StartFailure(ready);
    sync::SpinLockGuard guard(broker->lock);
    return ReserveStartLocked(*broker, service_identity, expected_generation, now_ns, true);
}

ServiceLifecycleStatus ServiceLifecycleBrokerRecordSpawnFailure(ServiceLifecycleBroker* broker,
                                                                ServiceLifecycleStartTicket ticket, u64 now_ns)
{
    const ServiceLifecycleStatus ready = ReadyBroker(broker);
    if (ready != ServiceLifecycleStatus::Ok)
        return ready;
    sync::SpinLockGuard guard(broker->lock);
    if (!BrokerIsCanonical(*broker))
        return ServiceLifecycleStatus::CorruptState;
    const ServiceLifecycleStatus ticket_status = ValidateTicketEpoch(*broker, ticket);
    if (ticket_status != ServiceLifecycleStatus::Ok)
        return ticket_status;
    if (broker->state == ServiceLifecycleBrokerState::Closed)
        return ServiceLifecycleStatus::Closed;

    const u32 index = FindBrokerIndex(*broker, ticket.transition.service_identity);
    if (index >= broker->service_count)
        return ServiceLifecycleStatus::NotFound;
    ServiceLifecycleRow& row = broker->rows[index];
    if (row.transition.generation != ticket.transition.generation)
        return ServiceLifecycleStatus::StaleGeneration;
    if (now_ns < row.last_transition_ns)
        return ServiceLifecycleStatus::InvalidTimestamp;
    if (row.builder_state == ServiceLifecycleBuilderState::CancelledAwaitingRetirement)
        return ServiceLifecycleStatus::StartRetirementPending;
    if (row.builder_state != ServiceLifecycleBuilderState::Constructing ||
        ServiceTransitionRecordSpawnFailure(&row.transition, ticket.transition) != ServiceSpawnFailureResult::Applied)
    {
        return ServiceLifecycleStatus::TransitionRejected;
    }

    row.builder_state = ServiceLifecycleBuilderState::None;
    row.ready = false;
    row.last_transition_ns = now_ns;
    IncrementSaturating(&row.spawn_failures);
    return ServiceLifecycleStatus::Ok;
}

ServiceLifecycleStatus ServiceLifecycleBrokerAcknowledgeCancelledStart(ServiceLifecycleBroker* broker,
                                                                       ServiceLifecycleStartTicket ticket, u64 now_ns)
{
    const ServiceLifecycleStatus ready = ReadyBroker(broker);
    if (ready != ServiceLifecycleStatus::Ok)
        return ready;
    sync::SpinLockGuard guard(broker->lock);
    if (!BrokerIsCanonical(*broker))
        return ServiceLifecycleStatus::CorruptState;
    const ServiceLifecycleStatus ticket_status = ValidateTicketEpoch(*broker, ticket);
    if (ticket_status != ServiceLifecycleStatus::Ok)
        return ticket_status;
    if (broker->state == ServiceLifecycleBrokerState::Closed)
        return ServiceLifecycleStatus::Closed;

    const u32 index = FindBrokerIndex(*broker, ticket.transition.service_identity);
    if (index >= broker->service_count)
        return ServiceLifecycleStatus::NotFound;
    ServiceLifecycleRow& row = broker->rows[index];
    if (row.transition.generation != ticket.transition.generation)
        return ServiceLifecycleStatus::StaleGeneration;
    if (now_ns < row.last_transition_ns)
        return ServiceLifecycleStatus::InvalidTimestamp;
    if (row.builder_state != ServiceLifecycleBuilderState::CancelledAwaitingRetirement)
        return ServiceLifecycleStatus::TransitionRejected;

    row.builder_state = ServiceLifecycleBuilderState::None;
    row.ready = false;
    row.last_transition_ns = now_ns;
    return ServiceLifecycleStatus::Ok;
}

ServiceLifecyclePublicationResult ServiceLifecycleBrokerCommitPublication(ServiceLifecycleBroker* broker,
                                                                          ServiceLifecycleStartTicket ticket,
                                                                          ServiceInstanceKey instance, u64 now_ns)
{
    const ServiceLifecycleStatus ready = ReadyBroker(broker);
    if (ready != ServiceLifecycleStatus::Ok)
        return PublicationFailure(ready);
    sync::SpinLockGuard guard(broker->lock);
    if (!BrokerIsCanonical(*broker))
        return PublicationFailure(ServiceLifecycleStatus::CorruptState);
    const ServiceLifecycleStatus ticket_status = ValidateTicketEpoch(*broker, ticket);
    if (ticket_status != ServiceLifecycleStatus::Ok)
        return PublicationFailure(ticket_status);
    if (broker->state == ServiceLifecycleBrokerState::Closed)
        return PublicationFailure(ServiceLifecycleStatus::Closed);
    if (broker->state == ServiceLifecycleBrokerState::Draining)
        return PublicationFailure(ServiceLifecycleStatus::Draining);

    const u32 index = FindBrokerIndex(*broker, ticket.transition.service_identity);
    if (index >= broker->service_count)
        return PublicationFailure(ServiceLifecycleStatus::NotFound);
    ServiceLifecycleRow& row = broker->rows[index];
    if (row.transition.generation != ticket.transition.generation)
        return PublicationFailure(ServiceLifecycleStatus::StaleGeneration);
    if (now_ns < row.last_transition_ns)
        return PublicationFailure(ServiceLifecycleStatus::InvalidTimestamp);
    if (row.builder_state != ServiceLifecycleBuilderState::Constructing ||
        ServiceTransitionCommitAtSchedulerPublication(&row.transition, ticket.transition, instance) !=
            ServicePublicationResult::Published)
    {
        return PublicationFailure(ServiceLifecycleStatus::TransitionRejected);
    }
    row.builder_state = ServiceLifecycleBuilderState::None;
    row.ready = false;
    row.last_transition_ns = now_ns;
    IncrementSaturating(&row.successful_publications);
    return ServiceLifecyclePublicationResult{ServiceLifecycleStatus::Ok,
                                             ServiceLifecycleInstanceToken{ticket, instance}};
}

ServiceLifecycleDirectoryPublicationResult ServiceLifecycleBrokerCommitDirectoryPublication(
    ServiceLifecycleBroker* broker, ServiceLifecycleStartTicket ticket, ServiceInstanceKey instance, u64 now_ns,
    ServiceDirectory* directory, ServiceRegistrationReservation* reservation)
{
    if (directory == nullptr || reservation == nullptr || !ServiceRegistrationReservationIsValid(*reservation))
        return DirectoryPublicationFailure(ServiceLifecycleStatus::NullArgument);

    const ServiceLifecycleStatus ready = ReadyBroker(broker);
    if (ready != ServiceLifecycleStatus::Ok)
        return DirectoryPublicationFailure(ready);

    sync::SpinLockGuard guard(broker->lock);
    if (!BrokerIsCanonical(*broker))
        return DirectoryPublicationFailure(ServiceLifecycleStatus::CorruptState);
    const ServiceLifecycleStatus ticket_status = ValidateTicketEpoch(*broker, ticket);
    if (ticket_status != ServiceLifecycleStatus::Ok)
        return DirectoryPublicationFailure(ticket_status);
    if (broker->state == ServiceLifecycleBrokerState::Closed)
        return DirectoryPublicationFailure(ServiceLifecycleStatus::Closed);
    if (broker->state == ServiceLifecycleBrokerState::Draining)
        return DirectoryPublicationFailure(ServiceLifecycleStatus::Draining);

    const u32 row_index = FindBrokerIndex(*broker, ticket.transition.service_identity);
    if (row_index >= broker->service_count)
        return DirectoryPublicationFailure(ServiceLifecycleStatus::NotFound);
    ServiceLifecycleRow& row = broker->rows[row_index];
    if (row.transition.generation != ticket.transition.generation)
        return DirectoryPublicationFailure(ServiceLifecycleStatus::StaleGeneration);
    if (now_ns < row.last_transition_ns)
        return DirectoryPublicationFailure(ServiceLifecycleStatus::InvalidTimestamp);
    if (row.builder_state != ServiceLifecycleBuilderState::Constructing ||
        !ServiceTransitionIsCurrentStart(row.transition, ticket.transition))
    {
        return DirectoryPublicationFailure(ServiceLifecycleStatus::TransitionRejected);
    }

    UnpublishedPublicationRollbackToken rollback{
        broker->broker_epoch, row_index, ticket, instance, row, true,
    };
    if (ServiceTransitionCommitAtSchedulerPublication(&row.transition, ticket.transition, instance) !=
        ServicePublicationResult::Published)
    {
        return DirectoryPublicationFailure(ServiceLifecycleStatus::TransitionRejected);
    }
    row.builder_state = ServiceLifecycleBuilderState::None;
    row.ready = false;
    row.last_transition_ns = now_ns;
    IncrementSaturating(&row.successful_publications);

    const ServiceInstanceToken directory_owner{ticket.transition, instance};
    const ServiceDirectoryStatus directory_status =
        ServiceDirectoryPublishRegistration(directory, reservation, directory_owner);
    if (directory_status != ServiceDirectoryStatus::Ok)
    {
        const ServiceLifecycleStatus rollback_status = RollbackUnpublishedPublicationLocked(*broker, &rollback);
        return DirectoryPublicationFailure(rollback_status, directory_status);
    }

    // Directory publication is the last fallible visibility mutation.  The
    // exact rollback token remains implementation-private and dies here, while
    // the still-held lifecycle lock prevents a concurrent stop from observing
    // a Running row before the Active directory identity exists.
    rollback.valid = false;
    return ServiceLifecycleDirectoryPublicationResult{ServiceLifecycleStatus::Ok, ServiceDirectoryStatus::Ok,
                                                      ServiceLifecycleInstanceToken{ticket, instance}};
}

ServiceLifecycleDirectoryReadyResult ServiceLifecycleBrokerMarkReady(ServiceLifecycleBroker* broker,
                                                                     ServiceLifecycleInstanceToken instance,
                                                                     ServiceDirectory* directory, ServiceKey service)
{
    if (directory == nullptr)
        return DirectoryReadyFailure(ServiceLifecycleStatus::NullArgument);
    const ServiceLifecycleStatus ready = ReadyBroker(broker);
    if (ready != ServiceLifecycleStatus::Ok)
        return DirectoryReadyFailure(ready);

    sync::SpinLockGuard guard(broker->lock);
    if (!BrokerIsCanonical(*broker))
        return DirectoryReadyFailure(ServiceLifecycleStatus::CorruptState);
    const ServiceLifecycleStatus token_status = ValidateTokenEpoch(*broker, instance);
    if (token_status != ServiceLifecycleStatus::Ok)
        return DirectoryReadyFailure(token_status);
    if (broker->state == ServiceLifecycleBrokerState::Closed)
        return DirectoryReadyFailure(ServiceLifecycleStatus::Closed);
    if (broker->state == ServiceLifecycleBrokerState::Draining)
        return DirectoryReadyFailure(ServiceLifecycleStatus::Draining);

    const u32 index = FindBrokerIndex(*broker, instance.start.transition.service_identity);
    if (index >= broker->service_count)
        return DirectoryReadyFailure(ServiceLifecycleStatus::NotFound);
    ServiceLifecycleRow& row = broker->rows[index];
    if (row.transition.generation != instance.start.transition.generation)
        return DirectoryReadyFailure(ServiceLifecycleStatus::StaleGeneration);
    const ServiceInstanceToken transition_instance{instance.start.transition, instance.process};
    if (row.builder_state != ServiceLifecycleBuilderState::None ||
        !ServiceTransitionIsCurrentRunning(row.transition, transition_instance))
    {
        return DirectoryReadyFailure(ServiceLifecycleStatus::TransitionRejected);
    }

    const ServiceDirectoryStatus directory_status =
        ServiceDirectoryCommitJointReady(directory, service, transition_instance, &row.ready);
    if (directory_status != ServiceDirectoryStatus::Ok)
        return DirectoryReadyFailure(ServiceLifecycleStatus::Ok, directory_status);

    // The lower-ranked directory leaf performed both ordered no-fail writes
    // before releasing its lock. This still-held broker lock prevents stop or
    // dependency admission from interleaving with the joint commit.
    return ServiceLifecycleDirectoryReadyResult{ServiceLifecycleStatus::Ok, ServiceDirectoryStatus::Ok};
}

ServiceLifecycleStopResult ServiceLifecycleBrokerRequestStop(ServiceLifecycleBroker* broker, u64 service_identity,
                                                             u64 expected_generation, u64 now_ns)
{
    const ServiceLifecycleStatus ready = ReadyBroker(broker);
    if (ready != ServiceLifecycleStatus::Ok)
        return StopFailure(ready);
    sync::SpinLockGuard guard(broker->lock);
    if (!BrokerIsCanonical(*broker))
        return StopFailure(ServiceLifecycleStatus::CorruptState);
    if (broker->state == ServiceLifecycleBrokerState::Closed)
        return StopFailure(ServiceLifecycleStatus::Closed);

    const u32 index = FindBrokerIndex(*broker, service_identity);
    if (index >= broker->service_count)
        return StopFailure(ServiceLifecycleStatus::NotFound);
    ServiceLifecycleRow& row = broker->rows[index];
    if (row.transition.generation != expected_generation)
        return StopFailure(ServiceLifecycleStatus::StaleGeneration);
    if (now_ns < row.last_transition_ns)
        return StopFailure(ServiceLifecycleStatus::InvalidTimestamp);
    if (row.builder_state == ServiceLifecycleBuilderState::CancelledAwaitingRetirement)
        return StopFailure(ServiceLifecycleStatus::StartRetirementPending);

    ServiceInstanceToken token = kInvalidServiceInstanceToken;
    switch (ServiceTransitionStop(&row.transition, &token))
    {
    case ServiceStopResult::AlreadyStopped:
        return StopFailure(ServiceLifecycleStatus::AlreadyStopped);
    case ServiceStopResult::StartCancelled:
        row.builder_state = ServiceLifecycleBuilderState::CancelledAwaitingRetirement;
        row.ready = false;
        row.last_transition_ns = now_ns;
        return ServiceLifecycleStopResult{
            ServiceLifecycleStatus::StartCancelled, kInvalidServiceLifecycleInstanceToken,
            ServiceLifecycleStartTicket{
                broker->broker_epoch, ServiceStartTicket{row.transition.service_identity, row.transition.generation}}};
    case ServiceStopResult::KillRequired:
        row.ready = false;
        row.last_transition_ns = now_ns;
        return ServiceLifecycleStopResult{
            ServiceLifecycleStatus::KillRequired,
            ServiceLifecycleInstanceToken{ServiceLifecycleStartTicket{broker->broker_epoch, token.start},
                                          token.process},
            kInvalidServiceLifecycleStartTicket};
    case ServiceStopResult::AlreadyStopping:
        return StopFailure(ServiceLifecycleStatus::AlreadyStopping);
    case ServiceStopResult::Rejected:
        return StopFailure(ServiceLifecycleStatus::TransitionRejected);
    }
    return StopFailure(ServiceLifecycleStatus::CorruptState);
}

ServiceLifecycleStatus ServiceLifecycleBrokerObserveExit(ServiceLifecycleBroker* broker,
                                                         ServiceLifecycleInstanceToken instance, u64 now_ns,
                                                         bool failed)
{
    const ServiceLifecycleStatus ready = ReadyBroker(broker);
    if (ready != ServiceLifecycleStatus::Ok)
        return ready;
    sync::SpinLockGuard guard(broker->lock);
    if (!BrokerIsCanonical(*broker))
        return ServiceLifecycleStatus::CorruptState;
    const ServiceLifecycleStatus token_status = ValidateTokenEpoch(*broker, instance);
    if (token_status != ServiceLifecycleStatus::Ok)
        return token_status;
    if (broker->state == ServiceLifecycleBrokerState::Closed)
        return ServiceLifecycleStatus::Closed;

    const u32 index = FindBrokerIndex(*broker, instance.start.transition.service_identity);
    if (index >= broker->service_count)
        return ServiceLifecycleStatus::NotFound;
    ServiceLifecycleRow& row = broker->rows[index];
    if (row.transition.generation != instance.start.transition.generation)
        return ServiceLifecycleStatus::StaleGeneration;
    if (now_ns < row.last_transition_ns)
        return ServiceLifecycleStatus::InvalidTimestamp;
    const ServiceInstanceToken transition_instance{instance.start.transition, instance.process};
    if (ServiceTransitionObserveExit(&row.transition, transition_instance) != ServiceExitResult::Applied)
        return ServiceLifecycleStatus::TransitionRejected;

    row.ready = false;
    row.last_transition_ns = now_ns;
    IncrementSaturating(&row.observed_exits);
    if (failed)
        IncrementSaturating(&row.failed_exits);
    return ServiceLifecycleStatus::Ok;
}

ServiceLifecycleStatus ServiceLifecycleBrokerBeginDrain(ServiceLifecycleBroker* broker, u64 now_ns,
                                                        ServiceLifecycleDrainPlan* plan_out)
{
    if (!RangeIsValid(plan_out, sizeof(*plan_out)))
        return ServiceLifecycleStatus::NullArgument;
    if (RangeIsValid(broker, sizeof(*broker)) && RangesOverlap(broker, sizeof(*broker), plan_out, sizeof(*plan_out)))
    {
        return ServiceLifecycleStatus::AliasedOutput;
    }
    *plan_out = ServiceLifecycleDrainPlan{};
    const ServiceLifecycleStatus ready = ReadyBroker(broker);
    if (ready != ServiceLifecycleStatus::Ok)
        return ready;

    sync::SpinLockGuard guard(broker->lock);
    if (!BrokerIsCanonical(*broker))
        return ServiceLifecycleStatus::CorruptState;
    if (broker->state == ServiceLifecycleBrokerState::Closed)
        return ServiceLifecycleStatus::Closed;
    if (broker->state == ServiceLifecycleBrokerState::Draining)
        return ServiceLifecycleStatus::Draining;

    // Timestamp validation is a preflight pass so an invalid clock sample
    // cannot partially cancel/publish drain state.
    for (u32 index = 0; index < broker->service_count; ++index)
    {
        if (now_ns < broker->rows[index].last_transition_ns)
            return ServiceLifecycleStatus::InvalidTimestamp;
    }

    broker->state = ServiceLifecycleBrokerState::Draining;
    for (u32 index = 0; index < broker->service_count; ++index)
    {
        ServiceLifecycleRow& row = broker->rows[index];
        if (row.transition.phase != ServiceTransitionPhase::Starting &&
            row.transition.phase != ServiceTransitionPhase::Running)
        {
            continue;
        }
        ServiceInstanceToken token = kInvalidServiceInstanceToken;
        const ServiceStopResult result = ServiceTransitionStop(&row.transition, &token);
        if (result == ServiceStopResult::KillRequired)
        {
            row.ready = false;
            row.last_transition_ns = now_ns;
            plan_out->instances[plan_out->kill_count++] = ServiceLifecycleInstanceToken{
                ServiceLifecycleStartTicket{broker->broker_epoch, token.start}, token.process};
        }
        else if (result == ServiceStopResult::StartCancelled)
        {
            row.builder_state = ServiceLifecycleBuilderState::CancelledAwaitingRetirement;
            row.ready = false;
            row.last_transition_ns = now_ns;
            plan_out->cancelled_starts[plan_out->cancel_count++] = ServiceLifecycleStartTicket{
                broker->broker_epoch, ServiceStartTicket{row.transition.service_identity, row.transition.generation}};
        }
        else
            return ServiceLifecycleStatus::CorruptState;
    }
    return ServiceLifecycleStatus::Ok;
}

ServiceLifecycleStatus ServiceLifecycleBrokerFinishDrain(ServiceLifecycleBroker* broker)
{
    const ServiceLifecycleStatus ready = ReadyBroker(broker);
    if (ready != ServiceLifecycleStatus::Ok)
        return ready;
    sync::SpinLockGuard guard(broker->lock);
    if (!BrokerIsCanonical(*broker))
        return ServiceLifecycleStatus::CorruptState;
    if (broker->state == ServiceLifecycleBrokerState::Closed)
        return ServiceLifecycleStatus::Closed;
    if (broker->state != ServiceLifecycleBrokerState::Draining)
        return ServiceLifecycleStatus::Busy;
    for (u32 index = 0; index < broker->service_count; ++index)
    {
        if (broker->rows[index].builder_state != ServiceLifecycleBuilderState::None)
            return ServiceLifecycleStatus::Busy;
        const ServiceTransitionPhase phase = broker->rows[index].transition.phase;
        if (phase == ServiceTransitionPhase::Starting || phase == ServiceTransitionPhase::Running ||
            phase == ServiceTransitionPhase::Stopping)
        {
            return ServiceLifecycleStatus::Busy;
        }
    }
    broker->state = ServiceLifecycleBrokerState::Closed;
    return ServiceLifecycleStatus::Ok;
}

ServiceLifecycleBrokerInspectResult ServiceLifecycleBrokerDescribe(ServiceLifecycleBroker* broker)
{
    const ServiceLifecycleStatus ready = ReadyBroker(broker);
    if (ready != ServiceLifecycleStatus::Ok)
        return BrokerInspectFailure(ready);
    sync::SpinLockGuard guard(broker->lock);
    if (!BrokerIsCanonical(*broker))
        return BrokerInspectFailure(ServiceLifecycleStatus::CorruptState);
    return ServiceLifecycleBrokerInspectResult{ServiceLifecycleStatus::Ok, SnapshotBroker(*broker)};
}

ServiceLifecycleInspectResult ServiceLifecycleBrokerInspect(ServiceLifecycleBroker* broker, u64 service_identity)
{
    const ServiceLifecycleStatus ready = ReadyBroker(broker);
    if (ready != ServiceLifecycleStatus::Ok)
        return InspectFailure(ready);
    sync::SpinLockGuard guard(broker->lock);
    if (!BrokerIsCanonical(*broker))
        return InspectFailure(ServiceLifecycleStatus::CorruptState);
    const u32 index = FindBrokerIndex(*broker, service_identity);
    return index < broker->service_count
               ? ServiceLifecycleInspectResult{ServiceLifecycleStatus::Ok, SnapshotRow(broker->rows[index])}
               : InspectFailure(ServiceLifecycleStatus::NotFound);
}

ServiceLifecycleInspectResult ServiceLifecycleBrokerInspectAt(ServiceLifecycleBroker* broker, u32 index)
{
    const ServiceLifecycleStatus ready = ReadyBroker(broker);
    if (ready != ServiceLifecycleStatus::Ok)
        return InspectFailure(ready);
    sync::SpinLockGuard guard(broker->lock);
    if (!BrokerIsCanonical(*broker))
        return InspectFailure(ServiceLifecycleStatus::CorruptState);
    return index < broker->service_count
               ? ServiceLifecycleInspectResult{ServiceLifecycleStatus::Ok, SnapshotRow(broker->rows[index])}
               : InspectFailure(ServiceLifecycleStatus::NotFound);
}

const char* ServiceLifecycleStatusName(ServiceLifecycleStatus status)
{
    switch (status)
    {
    case ServiceLifecycleStatus::Ok:
        return "ok";
    case ServiceLifecycleStatus::NullArgument:
        return "null-argument";
    case ServiceLifecycleStatus::AliasedOutput:
        return "aliased-output";
    case ServiceLifecycleStatus::InvalidManifestPlan:
        return "invalid-manifest-plan";
    case ServiceLifecycleStatus::InvalidBrokerEpoch:
        return "invalid-broker-epoch";
    case ServiceLifecycleStatus::AlreadyInitialized:
        return "already-initialized";
    case ServiceLifecycleStatus::NotInitialized:
        return "not-initialized";
    case ServiceLifecycleStatus::Closed:
        return "closed";
    case ServiceLifecycleStatus::Draining:
        return "draining";
    case ServiceLifecycleStatus::CorruptState:
        return "corrupt-state";
    case ServiceLifecycleStatus::NotFound:
        return "not-found";
    case ServiceLifecycleStatus::StaleGeneration:
        return "stale-generation";
    case ServiceLifecycleStatus::StaleBrokerEpoch:
        return "stale-broker-epoch";
    case ServiceLifecycleStatus::InvalidTimestamp:
        return "invalid-timestamp";
    case ServiceLifecycleStatus::AlreadyRequested:
        return "already-requested";
    case ServiceLifecycleStatus::StopInProgress:
        return "stop-in-progress";
    case ServiceLifecycleStatus::GenerationExhausted:
        return "generation-exhausted";
    case ServiceLifecycleStatus::TransitionRejected:
        return "transition-rejected";
    case ServiceLifecycleStatus::AlreadyStopped:
        return "already-stopped";
    case ServiceLifecycleStatus::StartCancelled:
        return "start-cancelled";
    case ServiceLifecycleStatus::KillRequired:
        return "kill-required";
    case ServiceLifecycleStatus::AlreadyStopping:
        return "already-stopping";
    case ServiceLifecycleStatus::StartRetirementPending:
        return "start-retirement-pending";
    case ServiceLifecycleStatus::DependencyNotReady:
        return "dependency-not-ready";
    case ServiceLifecycleStatus::Busy:
        return "busy";
    }
    return "unknown";
}

} // namespace duetos::core
