#include "core/service_control_platform.h"

#if defined(DUETOS_HOST_TEST)
#include <atomic>
#else
#include "proc/process.h"
#include "sched/sched.h"
#include "time/timekeeper.h"
#endif

namespace duetos::core
{
namespace
{

struct FreshAuthority
{
    ServiceRuntimeActivationAuthorityV1 authority;
    ServiceRuntimeSnapshotV1 runtime;
    ServiceLifecycleBrokerSnapshot broker;
};

u32 StateLoad(const ServiceControlPlatformAdapterV1* platform)
{
    if (platform == nullptr)
        return static_cast<u32>(ServiceControlPlatformAdapterStateV1::Uninitialized);
#if defined(DUETOS_HOST_TEST)
    return std::atomic_ref<u32>(const_cast<u32&>(platform->state)).load(std::memory_order_acquire);
#else
    return __atomic_load_n(&platform->state, __ATOMIC_ACQUIRE);
#endif
}

void StateStore(ServiceControlPlatformAdapterV1* platform, ServiceControlPlatformAdapterStateV1 state)
{
#if defined(DUETOS_HOST_TEST)
    std::atomic_ref<u32>(platform->state).store(static_cast<u32>(state), std::memory_order_release);
#else
    __atomic_store_n(&platform->state, static_cast<u32>(state), __ATOMIC_RELEASE);
#endif
}

bool BeginInitialize(ServiceControlPlatformAdapterV1* platform)
{
    u32 expected = static_cast<u32>(ServiceControlPlatformAdapterStateV1::Uninitialized);
#if defined(DUETOS_HOST_TEST)
    return std::atomic_ref<u32>(platform->state)
        .compare_exchange_strong(expected, static_cast<u32>(ServiceControlPlatformAdapterStateV1::Initializing),
                                 std::memory_order_acq_rel, std::memory_order_acquire);
#else
    return __atomic_compare_exchange_n(&platform->state, &expected,
                                       static_cast<u32>(ServiceControlPlatformAdapterStateV1::Initializing), false,
                                       __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
#endif
}

bool HashEquals(const loader::Hash256& left, const loader::Hash256& right)
{
    for (u32 index = 0; index < sizeof(left.bytes); ++index)
    {
        if (left.bytes[index] != right.bytes[index])
            return false;
    }
    return true;
}

bool AuthorityEquals(const ServiceRuntimeActivationAuthorityV1& left, const ServiceRuntimeActivationAuthorityV1& right)
{
    return left.stage == right.stage && left.lifecycle == right.lifecycle &&
           left.exit_observer == right.exit_observer && left.directory == right.directory &&
           left.exit_reap_ledger == right.exit_reap_ledger && left.manifest_identity == right.manifest_identity &&
           left.manifest_authority_identity == right.manifest_authority_identity &&
           HashEquals(left.manifest_object_hash, right.manifest_object_hash) &&
           left.manifest_object_extent == right.manifest_object_extent &&
           left.stage_registry_identity == right.stage_registry_identity;
}

bool OperationsAreCanonical(const ServiceControlPlatformOperationsV1& operations)
{
    return operations.struct_size == sizeof(operations) &&
           operations.version == kServiceControlPlatformOperationsVersion1 && operations.monotonic_ns != nullptr &&
           operations.runtime_inspect != nullptr && operations.bind_authority != nullptr &&
           operations.broker_describe != nullptr && operations.lifecycle_inspect != nullptr &&
           operations.activate != nullptr && operations.request_stop != nullptr &&
           operations.kill_exact_process != nullptr && operations.stage_find_service != nullptr &&
           operations.live_inspect != nullptr && operations.live_restage != nullptr &&
           operations.ledger_inspect != nullptr && operations.exit_dequeue != nullptr &&
           operations.restage_query_exact != nullptr && operations.exit_acknowledge_exact != nullptr &&
           operations.install_ingress != nullptr && operations.reserved[0] == 0 && operations.reserved[1] == 0;
}

ServiceControlPlatformInitializeResultV1 InitializeResult(ServiceControlPlatformAdapterStatusV1 status)
{
    return ServiceControlPlatformInitializeResultV1{
        status,
        ServiceRuntimeStatusV1::NullArgument,
        ServiceLifecycleStatus::NullArgument,
        ServiceExitReapStatus::NullArgument,
        ServiceBootstrapLiveStatusV1::NullArgument,
        ServiceControlIngressStatus::NotInitialized,
    };
}

ServiceControlPlatformStatusV1 MapRuntimeStatus(ServiceRuntimeStatusV1 status)
{
    switch (status)
    {
    case ServiceRuntimeStatusV1::Ok:
        return ServiceControlPlatformStatusV1::Ok;
    case ServiceRuntimeStatusV1::NotInitialized:
    case ServiceRuntimeStatusV1::Failed:
        return ServiceControlPlatformStatusV1::NotReady;
    case ServiceRuntimeStatusV1::CorruptState:
        return ServiceControlPlatformStatusV1::CorruptState;
    case ServiceRuntimeStatusV1::NullArgument:
    case ServiceRuntimeStatusV1::NonCanonicalStorage:
        return ServiceControlPlatformStatusV1::InvalidArgument;
    default:
        return ServiceControlPlatformStatusV1::InternalError;
    }
}

ServiceControlPlatformStatusV1 MapLifecycleStatus(ServiceLifecycleStatus status)
{
    switch (status)
    {
    case ServiceLifecycleStatus::Ok:
        return ServiceControlPlatformStatusV1::Ok;
    case ServiceLifecycleStatus::NullArgument:
    case ServiceLifecycleStatus::AliasedOutput:
    case ServiceLifecycleStatus::InvalidManifestPlan:
    case ServiceLifecycleStatus::InvalidBrokerEpoch:
    case ServiceLifecycleStatus::InvalidTimestamp:
        return ServiceControlPlatformStatusV1::InvalidArgument;
    case ServiceLifecycleStatus::NotInitialized:
    case ServiceLifecycleStatus::Closed:
    case ServiceLifecycleStatus::Draining:
    case ServiceLifecycleStatus::DependencyNotReady:
        return ServiceControlPlatformStatusV1::NotReady;
    case ServiceLifecycleStatus::NotFound:
        return ServiceControlPlatformStatusV1::NotFound;
    case ServiceLifecycleStatus::StaleGeneration:
    case ServiceLifecycleStatus::StaleBrokerEpoch:
    case ServiceLifecycleStatus::StartCancelled:
    case ServiceLifecycleStatus::StartRetirementPending:
        return ServiceControlPlatformStatusV1::Stale;
    case ServiceLifecycleStatus::AlreadyRequested:
    case ServiceLifecycleStatus::StopInProgress:
    case ServiceLifecycleStatus::KillRequired:
    case ServiceLifecycleStatus::AlreadyStopping:
        return ServiceControlPlatformStatusV1::AlreadyRequested;
    case ServiceLifecycleStatus::AlreadyStopped:
        return ServiceControlPlatformStatusV1::AlreadyStopped;
    case ServiceLifecycleStatus::GenerationExhausted:
        return ServiceControlPlatformStatusV1::GenerationExhausted;
    case ServiceLifecycleStatus::Busy:
        return ServiceControlPlatformStatusV1::Busy;
    case ServiceLifecycleStatus::CorruptState:
        return ServiceControlPlatformStatusV1::CorruptState;
    case ServiceLifecycleStatus::AlreadyInitialized:
    case ServiceLifecycleStatus::TransitionRejected:
        return ServiceControlPlatformStatusV1::InternalError;
    }
    return ServiceControlPlatformStatusV1::InternalError;
}

ServiceControlPlatformStatusV1 MapStageStatus(ServiceBootstrapStageStatus status)
{
    switch (status)
    {
    case ServiceBootstrapStageStatus::Ok:
        return ServiceControlPlatformStatusV1::Ok;
    case ServiceBootstrapStageStatus::NullArgument:
    case ServiceBootstrapStageStatus::InvalidPointerRange:
    case ServiceBootstrapStageStatus::AliasedStorage:
    case ServiceBootstrapStageStatus::InvalidSlotStorage:
        return ServiceControlPlatformStatusV1::InvalidArgument;
    case ServiceBootstrapStageStatus::NotReady:
        return ServiceControlPlatformStatusV1::NotReady;
    case ServiceBootstrapStageStatus::NotFound:
        return ServiceControlPlatformStatusV1::NotFound;
    case ServiceBootstrapStageStatus::ActivationInProgress:
        return ServiceControlPlatformStatusV1::Busy;
    case ServiceBootstrapStageStatus::StaleActivationGeneration:
    case ServiceBootstrapStageStatus::InvalidActivationReceipt:
        return ServiceControlPlatformStatusV1::Stale;
    case ServiceBootstrapStageStatus::ActivationGenerationExhausted:
    case ServiceBootstrapStageStatus::IdentityExhausted:
        return ServiceControlPlatformStatusV1::GenerationExhausted;
    case ServiceBootstrapStageStatus::SlotCapacityTooSmall:
    case ServiceBootstrapStageStatus::ResourceBudgetExceeded:
        return ServiceControlPlatformStatusV1::CapacityExhausted;
    case ServiceBootstrapStageStatus::CorruptRuntime:
    case ServiceBootstrapStageStatus::NonCanonicalRuntime:
        return ServiceControlPlatformStatusV1::CorruptState;
    default:
        return ServiceControlPlatformStatusV1::InternalError;
    }
}

ServiceControlPlatformStatusV1 MapRuntimeFailure(ServiceRuntimeStatusV1 status)
{
    return status == ServiceRuntimeStatusV1::Ok ? ServiceControlPlatformStatusV1::CorruptState
                                                : MapRuntimeStatus(status);
}

ServiceControlPlatformStatusV1 MapLifecycleFailure(ServiceLifecycleStatus status)
{
    return status == ServiceLifecycleStatus::Ok ? ServiceControlPlatformStatusV1::CorruptState
                                                : MapLifecycleStatus(status);
}

ServiceControlPlatformStatusV1 MapStageFailure(ServiceBootstrapStageStatus status)
{
    return status == ServiceBootstrapStageStatus::Ok ? ServiceControlPlatformStatusV1::CorruptState
                                                     : MapStageStatus(status);
}

ServiceControlPlatformStatusV1 MapLiveRestageStatus(const ServiceBootstrapLiveRestageResultV1& result)
{
    switch (result.status)
    {
    case ServiceBootstrapLiveRestageStatusV1::Ok:
        return ServiceControlPlatformStatusV1::Ok;
    case ServiceBootstrapLiveRestageStatusV1::NullArgument:
        return ServiceControlPlatformStatusV1::InvalidArgument;
    case ServiceBootstrapLiveRestageStatusV1::NotInitialized:
    case ServiceBootstrapLiveRestageStatusV1::RetiredTargetTeardownRequired:
        return ServiceControlPlatformStatusV1::NotReady;
    case ServiceBootstrapLiveRestageStatusV1::Busy:
        return ServiceControlPlatformStatusV1::Busy;
    case ServiceBootstrapLiveRestageStatusV1::StageRejected:
        return MapStageFailure(result.stage.status);
    case ServiceBootstrapLiveRestageStatusV1::RetiredBankNotResettable:
        return ServiceControlPlatformStatusV1::Busy;
    case ServiceBootstrapLiveRestageStatusV1::CorruptState:
        return ServiceControlPlatformStatusV1::CorruptState;
    }
    return ServiceControlPlatformStatusV1::InternalError;
}

ServiceControlPlatformStatusV1 MapReapStatus(ServiceExitReapStatus status)
{
    switch (status)
    {
    case ServiceExitReapStatus::Ok:
        return ServiceControlPlatformStatusV1::Ok;
    case ServiceExitReapStatus::NullArgument:
    case ServiceExitReapStatus::InvalidBinding:
    case ServiceExitReapStatus::InvalidProcessKey:
    case ServiceExitReapStatus::InvalidEventKey:
        return ServiceControlPlatformStatusV1::InvalidArgument;
    case ServiceExitReapStatus::NotInitialized:
    case ServiceExitReapStatus::Closed:
        return ServiceControlPlatformStatusV1::NotReady;
    case ServiceExitReapStatus::CorruptState:
        return ServiceControlPlatformStatusV1::CorruptState;
    case ServiceExitReapStatus::CapacityExhausted:
        return ServiceControlPlatformStatusV1::CapacityExhausted;
    case ServiceExitReapStatus::SequenceExhausted:
    case ServiceExitReapStatus::TokenSpaceExhausted:
        return ServiceControlPlatformStatusV1::GenerationExhausted;
    case ServiceExitReapStatus::NoEvent:
        return ServiceControlPlatformStatusV1::WouldBlock;
    case ServiceExitReapStatus::NotFound:
        return ServiceControlPlatformStatusV1::NotFound;
    case ServiceExitReapStatus::Busy:
    case ServiceExitReapStatus::RowsLive:
        return ServiceControlPlatformStatusV1::Busy;
    case ServiceExitReapStatus::WrongStage:
    case ServiceExitReapStatus::StaleTicket:
    case ServiceExitReapStatus::StaleToken:
    case ServiceExitReapStatus::StaleEvent:
    case ServiceExitReapStatus::ForeignAcknowledger:
        return ServiceControlPlatformStatusV1::ReplayRejected;
    case ServiceExitReapStatus::ObserverRefused:
    case ServiceExitReapStatus::RollbackRefused:
    case ServiceExitReapStatus::AlreadyInitialized:
        return ServiceControlPlatformStatusV1::InternalError;
    }
    return ServiceControlPlatformStatusV1::InternalError;
}

ServiceControlPlatformStatusV1 ResolveFreshAuthority(ServiceControlPlatformAdapterV1* platform,
                                                     const ServiceRuntimeActivationAuthorityV1* supplied,
                                                     FreshAuthority* fresh_out)
{
    if (platform == nullptr || supplied == nullptr || fresh_out == nullptr)
        return ServiceControlPlatformStatusV1::InvalidArgument;
    *fresh_out = {};
    if (StateLoad(platform) != static_cast<u32>(ServiceControlPlatformAdapterStateV1::Open))
        return ServiceControlPlatformStatusV1::NotReady;
    if (platform->version != kServiceControlPlatformAdapterVersion1 || platform->runtime == nullptr ||
        platform->ledger == nullptr || !OperationsAreCanonical(platform->operations))
    {
        return ServiceControlPlatformStatusV1::CorruptState;
    }

    const auto& operations = platform->operations;
    FreshAuthority fresh{};
    const ServiceRuntimeStatusV1 inspected =
        operations.runtime_inspect(operations.context, platform->runtime, &fresh.runtime);
    if (inspected != ServiceRuntimeStatusV1::Ok)
        return MapRuntimeStatus(inspected);
    const ServiceRuntimeStatusV1 bound =
        operations.bind_authority(operations.context, platform->runtime, &fresh.authority);
    if (bound != ServiceRuntimeStatusV1::Ok)
        return MapRuntimeStatus(bound);
    const ServiceLifecycleBrokerInspectResult broker =
        operations.broker_describe(operations.context, fresh.authority.lifecycle);
    if (broker.status != ServiceLifecycleStatus::Ok)
        return MapLifecycleStatus(broker.status);
    fresh.broker = broker.snapshot;

    if (fresh.runtime.state != ServiceRuntimeStateV1::Open || fresh.broker.state != ServiceLifecycleBrokerState::Open ||
        fresh.broker.broker_epoch == 0 || fresh.runtime.broker_epoch != fresh.broker.broker_epoch ||
        fresh.runtime.manifest_identity != fresh.authority.manifest_identity ||
        fresh.runtime.manifest_authority_identity != fresh.authority.manifest_authority_identity ||
        fresh.runtime.stage_registry_identity != fresh.authority.stage_registry_identity ||
        fresh.broker.manifest_identity != fresh.authority.manifest_identity ||
        fresh.broker.manifest_authority_identity != fresh.authority.manifest_authority_identity ||
        !HashEquals(fresh.broker.manifest_object_hash, fresh.authority.manifest_object_hash) ||
        fresh.broker.manifest_object_extent != fresh.authority.manifest_object_extent ||
        !AuthorityEquals(fresh.authority, platform->authority) || !AuthorityEquals(fresh.authority, *supplied))
    {
        return ServiceControlPlatformStatusV1::CorruptState;
    }
    *fresh_out = fresh;
    return ServiceControlPlatformStatusV1::Ok;
}

bool TargetBaseIsValid(const ServiceControlPlatformTargetV1& target)
{
    return target.broker_epoch != 0 && target.service_identity != 0;
}

ServiceExitReapEventKey TargetEventKey(const ServiceControlPlatformTargetV1& target)
{
    return ServiceExitReapEventKey{target.broker_epoch, target.service_identity, target.transition_generation,
                                   target.process, target.event_sequence};
}

bool SnapshotMatchesTarget(const ServiceLifecycleSnapshot& snapshot, const ServiceControlPlatformTargetV1& target)
{
    return snapshot.service_identity == target.service_identity &&
           snapshot.transition_generation == target.transition_generation;
}

ServiceControlPlatformStatusV1 ActivateCallback(void* context, const ServiceRuntimeActivationAuthorityV1* authority,
                                                ProcessKey supervisor, ServiceControlPlatformTargetV1 target)
{
    auto* platform = static_cast<ServiceControlPlatformAdapterV1*>(context);
    FreshAuthority fresh{};
    const ServiceControlPlatformStatusV1 ready = ResolveFreshAuthority(platform, authority, &fresh);
    if (ready != ServiceControlPlatformStatusV1::Ok)
        return ready;
    if (!ProcessKeyIsValid(supervisor) || !TargetBaseIsValid(target) ||
        target.broker_epoch != fresh.broker.broker_epoch ||
        target.transition_generation == kServiceTransitionGenerationMaximum ||
        !(target.process == kInvalidProcessKey) || target.event_sequence != 0)
    {
        return target.broker_epoch != fresh.broker.broker_epoch ? ServiceControlPlatformStatusV1::Stale
                                                                : ServiceControlPlatformStatusV1::InvalidArgument;
    }

    const ServiceLifecycleInspectResult lifecycle = platform->operations.lifecycle_inspect(
        platform->operations.context, fresh.authority.lifecycle, target.service_identity);
    if (lifecycle.status != ServiceLifecycleStatus::Ok)
        return MapLifecycleStatus(lifecycle.status);
    if (!SnapshotMatchesTarget(lifecycle.snapshot, target))
        return ServiceControlPlatformStatusV1::Stale;
    if (lifecycle.snapshot.phase == ServiceTransitionPhase::Starting ||
        lifecycle.snapshot.phase == ServiceTransitionPhase::Running ||
        lifecycle.snapshot.phase == ServiceTransitionPhase::Stopping)
    {
        return ServiceControlPlatformStatusV1::AlreadyRequested;
    }
    if (lifecycle.snapshot.phase == ServiceTransitionPhase::GenerationExhausted)
        return ServiceControlPlatformStatusV1::GenerationExhausted;

    const u64 now_ns = platform->operations.monotonic_ns(platform->operations.context);
    if (now_ns == 0)
        return ServiceControlPlatformStatusV1::NotReady;
    const ServiceBootstrapActivationRequestV1 request{
        kServiceBootstrapActivationVersion1, 0,     platform->runtime, target.service_identity,
        target.transition_generation,        now_ns};
    const ServiceBootstrapActivationResultV1 activated =
        platform->operations.activate(platform->operations.context, request);
    if (activated.status == ServiceBootstrapActivationStatusV1::Ok)
    {
        if (!ServiceLifecycleInstanceTokenIsValid(activated.instance) ||
            activated.instance.start.broker_epoch != target.broker_epoch ||
            activated.instance.start.transition.service_identity != target.service_identity ||
            activated.instance.start.transition.generation != target.transition_generation + 1)
        {
            return ServiceControlPlatformStatusV1::CorruptState;
        }
        return ServiceControlPlatformStatusV1::Ok;
    }
    if (activated.status == ServiceBootstrapActivationStatusV1::RuntimeRejected)
        return MapRuntimeFailure(activated.runtime_status);
    if (activated.status == ServiceBootstrapActivationStatusV1::StageRejected)
        return MapStageFailure(activated.stage_status);
    if (activated.status == ServiceBootstrapActivationStatusV1::LifecycleReserveRejected)
        return MapLifecycleFailure(activated.lifecycle_status);
    if (activated.status == ServiceBootstrapActivationStatusV1::LifecycleCleanupFailed)
        return MapLifecycleFailure(activated.lifecycle_cleanup_status);
    if (activated.status == ServiceBootstrapActivationStatusV1::LifecyclePublicationRollbackFailed)
        return MapLifecycleFailure(activated.lifecycle_publication_rollback_status);
    if (activated.status == ServiceBootstrapActivationStatusV1::ResourceBudgetExceeded)
        return ServiceControlPlatformStatusV1::CapacityExhausted;
    if (activated.lifecycle_status == ServiceLifecycleStatus::StartCancelled ||
        activated.lifecycle_status == ServiceLifecycleStatus::StartRetirementPending)
    {
        return ServiceControlPlatformStatusV1::Stale;
    }
    return ServiceControlPlatformStatusV1::InternalError;
}

ServiceControlPlatformStatusV1 StopCallback(void* context, const ServiceRuntimeActivationAuthorityV1* authority,
                                            ProcessKey supervisor, ServiceControlPlatformTargetV1 target)
{
    auto* platform = static_cast<ServiceControlPlatformAdapterV1*>(context);
    FreshAuthority fresh{};
    const ServiceControlPlatformStatusV1 ready = ResolveFreshAuthority(platform, authority, &fresh);
    if (ready != ServiceControlPlatformStatusV1::Ok)
        return ready;
    if (!ProcessKeyIsValid(supervisor) || !TargetBaseIsValid(target) || target.transition_generation == 0 ||
        target.event_sequence != 0)
        return ServiceControlPlatformStatusV1::InvalidArgument;
    if (target.broker_epoch != fresh.broker.broker_epoch)
        return ServiceControlPlatformStatusV1::Stale;

    const ServiceLifecycleInspectResult lifecycle = platform->operations.lifecycle_inspect(
        platform->operations.context, fresh.authority.lifecycle, target.service_identity);
    if (lifecycle.status != ServiceLifecycleStatus::Ok)
        return MapLifecycleStatus(lifecycle.status);
    if (!SnapshotMatchesTarget(lifecycle.snapshot, target))
        return ServiceControlPlatformStatusV1::Stale;
    if (lifecycle.snapshot.phase == ServiceTransitionPhase::Starting)
    {
        if (!(target.process == kInvalidProcessKey))
            return ServiceControlPlatformStatusV1::Stale;
    }
    else if (lifecycle.snapshot.phase == ServiceTransitionPhase::Running ||
             lifecycle.snapshot.phase == ServiceTransitionPhase::Stopping)
    {
        const ProcessKey current{lifecycle.snapshot.instance.process_identity, lifecycle.snapshot.instance.pid};
        if (!ProcessKeyIsValid(target.process) || !(target.process == current))
            return ServiceControlPlatformStatusV1::Stale;
    }
    else
    {
        return ServiceControlPlatformStatusV1::AlreadyStopped;
    }

    const u64 now_ns = platform->operations.monotonic_ns(platform->operations.context);
    if (now_ns == 0)
        return ServiceControlPlatformStatusV1::NotReady;
    const ServiceLifecycleStopResult stopped =
        platform->operations.request_stop(platform->operations.context, fresh.authority.lifecycle,
                                          target.service_identity, target.transition_generation, now_ns);
    if (stopped.status == ServiceLifecycleStatus::KillRequired)
    {
        const ServiceLifecycleInstanceToken expected{
            ServiceLifecycleStartTicket{target.broker_epoch,
                                        ServiceStartTicket{target.service_identity, target.transition_generation}},
            ServiceInstanceKey{target.process.identity, target.process.pid},
        };
        if (!ServiceLifecycleInstanceTokenIsValid(stopped.instance_to_kill) ||
            !(stopped.instance_to_kill == expected) || ServiceLifecycleStartTicketIsValid(stopped.start_to_cancel))
        {
            return ServiceControlPlatformStatusV1::CorruptState;
        }
        const ServiceControlPlatformKillExactResultV1 killed =
            platform->operations.kill_exact_process(platform->operations.context, target.process);
        return killed == ServiceControlPlatformKillExactResultV1::Rejected
                   ? ServiceControlPlatformStatusV1::InternalError
                   : ServiceControlPlatformStatusV1::Ok;
    }
    if (stopped.status == ServiceLifecycleStatus::StartCancelled)
    {
        const ServiceLifecycleStartTicket expected{
            target.broker_epoch, ServiceStartTicket{target.service_identity, target.transition_generation}};
        if (!(stopped.start_to_cancel == expected) || ServiceLifecycleInstanceTokenIsValid(stopped.instance_to_kill))
        {
            return ServiceControlPlatformStatusV1::CorruptState;
        }
        // The broker's CancelledAwaitingRetirement state is the synchronous
        // builder signal.  ServiceBootstrapActivateV1 owns teardown and the
        // exact AcknowledgeCancelledStart call on its failure path.
        return ServiceControlPlatformStatusV1::Ok;
    }
    return stopped.status == ServiceLifecycleStatus::Ok ? ServiceControlPlatformStatusV1::CorruptState
                                                        : MapLifecycleStatus(stopped.status);
}

ServiceControlPlatformStatusV1 RestageCallback(void* context, const ServiceRuntimeActivationAuthorityV1* authority,
                                               ProcessKey supervisor, ServiceControlPlatformTargetV1 target)
{
    auto* platform = static_cast<ServiceControlPlatformAdapterV1*>(context);
    FreshAuthority fresh{};
    const ServiceControlPlatformStatusV1 ready = ResolveFreshAuthority(platform, authority, &fresh);
    if (ready != ServiceControlPlatformStatusV1::Ok)
        return ready;
    const ServiceExitReapEventKey event = TargetEventKey(target);
    if (!ProcessKeyIsValid(supervisor) || !TargetBaseIsValid(target) || !ServiceExitReapEventKeyIsValid(event))
    {
        return ServiceControlPlatformStatusV1::InvalidArgument;
    }
    if (target.broker_epoch != fresh.broker.broker_epoch)
        return ServiceControlPlatformStatusV1::Stale;

    const ServiceLifecycleInspectResult lifecycle = platform->operations.lifecycle_inspect(
        platform->operations.context, fresh.authority.lifecycle, target.service_identity);
    if (lifecycle.status != ServiceLifecycleStatus::Ok)
        return MapLifecycleStatus(lifecycle.status);
    if (!SnapshotMatchesTarget(lifecycle.snapshot, target))
        return ServiceControlPlatformStatusV1::Stale;
    if (lifecycle.snapshot.phase != ServiceTransitionPhase::Exited &&
        lifecycle.snapshot.phase != ServiceTransitionPhase::Failed &&
        lifecycle.snapshot.phase != ServiceTransitionPhase::Stopped)
    {
        return ServiceControlPlatformStatusV1::NotReady;
    }

    const ServiceExitReapRestageResult gate =
        platform->operations.restage_query_exact(platform->operations.context, platform->ledger, event);
    if (gate.status != ServiceExitReapStatus::Ok)
        return MapReapStatus(gate.status);
    if (gate.eligible != 1 || gate.live_rows == 0 || gate.blocking_rows != 0)
        return gate.eligible == 0 ? ServiceControlPlatformStatusV1::Busy : ServiceControlPlatformStatusV1::CorruptState;

    ServiceBootstrapServiceSnapshotV1 staged{};
    const ServiceBootstrapStageStatus found = platform->operations.stage_find_service(
        platform->operations.context, fresh.authority.stage, target.service_identity, &staged);
    if (found != ServiceBootstrapStageStatus::Ok)
        return MapStageStatus(found);
    if (staged.service_identity != target.service_identity || staged.activation_generation == 0 ||
        (staged.activation_state != ServiceBootstrapActivationStateV1::TransferredPublished &&
         staged.activation_state != ServiceBootstrapActivationStateV1::ConsumedFailed))
    {
        return ServiceControlPlatformStatusV1::CorruptState;
    }

    const ServiceBootstrapLiveRestageResultV1 restaged = platform->operations.live_restage(
        platform->operations.context, target.service_identity, staged.activation_generation,
        ServiceBootstrapLiveRetiredTargetTeardownV1::TeardownComplete);
    if (restaged.status == ServiceBootstrapLiveRestageStatusV1::Ok &&
        (restaged.stage.status != ServiceBootstrapStageStatus::Ok || restaged.service_index != staged.manifest_index ||
         restaged.stage.service_index != staged.manifest_index ||
         restaged.previous_active_bank >= kServiceBootstrapLiveBanksPerServiceV1 ||
         restaged.active_bank >= kServiceBootstrapLiveBanksPerServiceV1 ||
         restaged.previous_active_bank == restaged.active_bank || restaged.reserved8 != 0 ||
         restaged.retired_image_status != loader::LoadImageStatus::Ok ||
         restaged.retired_admission_status != loader::ExecAdmissionStatus::Ok))
    {
        return ServiceControlPlatformStatusV1::CorruptState;
    }
    return MapLiveRestageStatus(restaged);
}

bool DeliveryRecordIsCanonical(const ServiceExitReapDeliveryRecord& record)
{
    const ServiceExitReapEventKey event{record.broker_epoch, record.service_identity, record.generation, record.process,
                                        record.event_sequence};
    return record.delivery_token != 0 && ServiceExitReapEventKeyIsValid(event) &&
           ServiceInstanceKeyIsValid(record.instance) && record.instance.process_identity == record.process.identity &&
           record.instance.pid == record.process.pid && record.failed <= 1 && record.reserved8 == 0 &&
           record.delivery_count != 0;
}

ServiceControlPlatformStatusV1 ExitDequeueCallback(void* context, const ServiceRuntimeActivationAuthorityV1* authority,
                                                   ProcessKey supervisor, ServiceControlPlatformExitEventV1* event_out)
{
    auto* platform = static_cast<ServiceControlPlatformAdapterV1*>(context);
    if (event_out == nullptr)
        return ServiceControlPlatformStatusV1::InvalidArgument;
    *event_out = {};
    FreshAuthority fresh{};
    const ServiceControlPlatformStatusV1 ready = ResolveFreshAuthority(platform, authority, &fresh);
    if (ready != ServiceControlPlatformStatusV1::Ok)
        return ready;
    if (!ProcessKeyIsValid(supervisor))
        return ServiceControlPlatformStatusV1::InvalidArgument;

    const ServiceExitReapDeliveryResult dequeued =
        platform->operations.exit_dequeue(platform->operations.context, platform->ledger, supervisor);
    if (dequeued.status != ServiceExitReapStatus::Ok)
        return MapReapStatus(dequeued.status);
    if (!DeliveryRecordIsCanonical(dequeued.record) || dequeued.record.broker_epoch != fresh.broker.broker_epoch)
        return ServiceControlPlatformStatusV1::CorruptState;

    event_out->instance = ServiceLifecycleInstanceToken{
        ServiceLifecycleStartTicket{
            dequeued.record.broker_epoch,
            ServiceStartTicket{dequeued.record.service_identity, dequeued.record.generation},
        },
        dequeued.record.instance,
    };
    event_out->event_sequence = dequeued.record.event_sequence;
    event_out->acknowledgement_token = dequeued.record.delivery_token;
    event_out->exit_status = static_cast<i64>(dequeued.record.exit_code);
    event_out->failed = dequeued.record.failed != 0;
    return ServiceControlPlatformStatusV1::Ok;
}

ServiceControlPlatformStatusV1 ExitAckCallback(void* context, const ServiceRuntimeActivationAuthorityV1* authority,
                                               ProcessKey supervisor, ServiceControlPlatformTargetV1 target,
                                               u64 acknowledgement_token)
{
    auto* platform = static_cast<ServiceControlPlatformAdapterV1*>(context);
    FreshAuthority fresh{};
    const ServiceControlPlatformStatusV1 ready = ResolveFreshAuthority(platform, authority, &fresh);
    if (ready != ServiceControlPlatformStatusV1::Ok)
        return ready;
    const ServiceExitReapEventKey event = TargetEventKey(target);
    if (!ProcessKeyIsValid(supervisor) || !ServiceExitReapEventKeyIsValid(event) || acknowledgement_token == 0)
        return ServiceControlPlatformStatusV1::InvalidArgument;
    if (target.broker_epoch != fresh.broker.broker_epoch)
        return ServiceControlPlatformStatusV1::Stale;

    return MapReapStatus(platform->operations.exit_acknowledge_exact(platform->operations.context, platform->ledger,
                                                                     event, acknowledgement_token, supervisor));
}

ServiceControlPlatformInitializeResultV1 InitializePlatform(ServiceControlPlatformAdapterV1* platform,
                                                            ServiceRuntimeV1* runtime, ServiceExitReapLedger* ledger,
                                                            const ServiceControlPlatformOperationsV1* operations)
{
    ServiceControlPlatformInitializeResultV1 result =
        InitializeResult(ServiceControlPlatformAdapterStatusV1::NullArgument);
    if (platform == nullptr || runtime == nullptr || ledger == nullptr || operations == nullptr)
        return result;
    if (!BeginInitialize(platform))
    {
        result.status = ServiceControlPlatformAdapterStatusV1::AlreadyAttempted;
        return result;
    }
    const auto fail = [&](ServiceControlPlatformAdapterStatusV1 status)
    {
        result.status = status;
        StateStore(platform, ServiceControlPlatformAdapterStateV1::Failed);
        return result;
    };
    if (!OperationsAreCanonical(*operations))
        return fail(ServiceControlPlatformAdapterStatusV1::InvalidOperations);

    ServiceRuntimeSnapshotV1 runtime_snapshot{};
    result.runtime_status = operations->runtime_inspect(operations->context, runtime, &runtime_snapshot);
    if (result.runtime_status != ServiceRuntimeStatusV1::Ok)
        return fail(ServiceControlPlatformAdapterStatusV1::RuntimeNotReady);
    ServiceRuntimeActivationAuthorityV1 authority{};
    result.runtime_status = operations->bind_authority(operations->context, runtime, &authority);
    if (result.runtime_status != ServiceRuntimeStatusV1::Ok)
        return fail(ServiceControlPlatformAdapterStatusV1::RuntimeNotReady);
    const ServiceLifecycleBrokerInspectResult broker =
        operations->broker_describe(operations->context, authority.lifecycle);
    result.broker_status = broker.status;
    if (broker.status != ServiceLifecycleStatus::Ok || runtime_snapshot.state != ServiceRuntimeStateV1::Open ||
        broker.snapshot.state != ServiceLifecycleBrokerState::Open || broker.snapshot.broker_epoch == 0)
    {
        return fail(ServiceControlPlatformAdapterStatusV1::BrokerNotReady);
    }
    if (authority.stage == nullptr || authority.lifecycle == nullptr || authority.exit_observer == nullptr ||
        authority.directory == nullptr || authority.exit_reap_ledger == nullptr ||
        authority.exit_reap_ledger != ledger || runtime_snapshot.service_count == 0 ||
        runtime_snapshot.broker_epoch != broker.snapshot.broker_epoch ||
        runtime_snapshot.manifest_identity != authority.manifest_identity ||
        runtime_snapshot.manifest_authority_identity != authority.manifest_authority_identity ||
        runtime_snapshot.stage_registry_identity != authority.stage_registry_identity ||
        broker.snapshot.service_count != runtime_snapshot.service_count ||
        broker.snapshot.manifest_identity != authority.manifest_identity ||
        broker.snapshot.manifest_authority_identity != authority.manifest_authority_identity ||
        !HashEquals(broker.snapshot.manifest_object_hash, authority.manifest_object_hash) ||
        broker.snapshot.manifest_object_extent != authority.manifest_object_extent)
    {
        return fail(ServiceControlPlatformAdapterStatusV1::CorruptState);
    }

    ServiceExitReapLedgerSnapshot ledger_snapshot{};
    result.ledger_status = operations->ledger_inspect(operations->context, ledger, &ledger_snapshot);
    if (result.ledger_status != ServiceExitReapStatus::Ok || ledger_snapshot.state != ServiceExitReapLedgerState::Open)
    {
        return fail(ServiceControlPlatformAdapterStatusV1::LedgerNotReady);
    }

    ServiceBootstrapLiveSnapshotV1 live{};
    result.live_status = operations->live_inspect(operations->context, &live);
    if (result.live_status != ServiceBootstrapLiveStatusV1::CompatibilityRequired ||
        live.state != ServiceBootstrapLiveStateV1::RuntimeOpenCompatibilityRequired ||
        live.status != ServiceBootstrapLiveStatusV1::CompatibilityRequired ||
        live.version != kServiceBootstrapLiveVersion1 ||
        live.generated_service_count != runtime_snapshot.service_count ||
        live.staged_service_count != live.generated_service_count ||
        live.stage_registry_identity != authority.stage_registry_identity || live.activation_ready != 0 ||
        live.compatibility_required != 1 || live.process_count != 0 || live.published_endpoint_count != 0)
    {
        return fail(ServiceControlPlatformAdapterStatusV1::LiveBootstrapNotReady);
    }

    platform->version = kServiceControlPlatformAdapterVersion1;
    platform->runtime = runtime;
    platform->ledger = ledger;
    platform->authority = authority;
    platform->operations = *operations;
    StateStore(platform, ServiceControlPlatformAdapterStateV1::Open);

    const ServiceControlIngressPlatformV1 ingress{
        sizeof(ServiceControlIngressPlatformV1),
        kServiceControlPlatformVersion1,
        platform,
        &ActivateCallback,
        &StopCallback,
        &RestageCallback,
        &ExitDequeueCallback,
        &ExitAckCallback,
        {0, 0},
    };
    result.ingress_status = operations->install_ingress(operations->context, &ingress);
    if (result.ingress_status != ServiceControlIngressStatus::Ok)
        return fail(ServiceControlPlatformAdapterStatusV1::InstallRejected);
    result.status = ServiceControlPlatformAdapterStatusV1::Ok;
    return result;
}

#if !defined(DUETOS_HOST_TEST)
u64 ProductionMonotonicNs(void*)
{
    return time::MonotonicNs();
}

ServiceRuntimeStatusV1 ProductionRuntimeInspect(void*, const ServiceRuntimeV1* runtime,
                                                ServiceRuntimeSnapshotV1* snapshot_out)
{
    return ServiceRuntimeInspectV1(runtime, snapshot_out);
}

ServiceRuntimeStatusV1 ProductionBindAuthority(void*, ServiceRuntimeV1* runtime,
                                               ServiceRuntimeActivationAuthorityV1* authority_out)
{
    return ServiceRuntimeBindActivationAuthorityV1(runtime, authority_out);
}

ServiceLifecycleBrokerInspectResult ProductionBrokerDescribe(void*, ServiceLifecycleBroker* broker)
{
    return ServiceLifecycleBrokerDescribe(broker);
}

ServiceLifecycleInspectResult ProductionLifecycleInspect(void*, ServiceLifecycleBroker* broker, u64 service_identity)
{
    return ServiceLifecycleBrokerInspect(broker, service_identity);
}

ServiceBootstrapActivationResultV1 ProductionActivate(void*, const ServiceBootstrapActivationRequestV1& request)
{
    return ServiceBootstrapActivateV1(request);
}

ServiceLifecycleStopResult ProductionRequestStop(void*, ServiceLifecycleBroker* broker, u64 service_identity,
                                                 u64 expected_generation, u64 now_ns)
{
    return ServiceLifecycleBrokerRequestStop(broker, service_identity, expected_generation, now_ns);
}

ServiceControlPlatformKillExactResultV1 ProductionKillExactProcess(void*, ProcessKey process)
{
    ScopedProcessRef retained(sched::SchedFindProcessByKeyRetained(process));
    if (retained.Get() == nullptr)
        return ServiceControlPlatformKillExactResultV1::AlreadyGone;
    (void)sched::SchedKillByProcess(retained.Get());
    return ServiceControlPlatformKillExactResultV1::Visited;
}

ServiceBootstrapStageStatus ProductionStageFindService(void*, const ServiceBootstrapStageRuntimeV1* stage,
                                                       u64 service_identity,
                                                       ServiceBootstrapServiceSnapshotV1* snapshot_out)
{
    return ServiceBootstrapStageFindServiceV1(stage, service_identity, snapshot_out);
}

ServiceBootstrapLiveStatusV1 ProductionLiveInspect(void*, ServiceBootstrapLiveSnapshotV1* snapshot_out)
{
    return ServiceBootstrapLiveInspectV1(snapshot_out);
}

ServiceBootstrapLiveRestageResultV1 ProductionLiveRestage(
    void*, u64 service_identity, u64 expected_activation_generation,
    ServiceBootstrapLiveRetiredTargetTeardownV1 retired_target_teardown)
{
    return ServiceBootstrapLiveRestageV1(service_identity, expected_activation_generation, retired_target_teardown);
}

ServiceExitReapStatus ProductionLedgerInspect(void*, ServiceExitReapLedger* ledger,
                                              ServiceExitReapLedgerSnapshot* snapshot_out)
{
    return ServiceExitReapLedgerInspect(ledger, snapshot_out);
}

ServiceExitReapDeliveryResult ProductionExitDequeue(void*, ServiceExitReapLedger* ledger, ProcessKey delivery_owner)
{
    return ServiceExitReapLedgerDequeueForDelivery(ledger, delivery_owner);
}

ServiceExitReapRestageResult ProductionRestageQueryExact(void*, ServiceExitReapLedger* ledger,
                                                         ServiceExitReapEventKey event)
{
    return ServiceExitReapLedgerQueryRestageExact(ledger, event);
}

ServiceExitReapStatus ProductionExitAcknowledgeExact(void*, ServiceExitReapLedger* ledger,
                                                     ServiceExitReapEventKey event, u64 delivery_token,
                                                     ProcessKey delivery_owner)
{
    return ServiceExitReapLedgerAcknowledgeDelivery(ledger, event, delivery_token, delivery_owner);
}

ServiceControlIngressStatus ProductionInstallIngress(void*, const ServiceControlIngressPlatformV1* platform)
{
    return ServiceControlIngressInstallKernelPlatformV1(platform);
}

const ServiceControlPlatformOperationsV1 kProductionOperations{
    sizeof(ServiceControlPlatformOperationsV1),
    kServiceControlPlatformOperationsVersion1,
    nullptr,
    &ProductionMonotonicNs,
    &ProductionRuntimeInspect,
    &ProductionBindAuthority,
    &ProductionBrokerDescribe,
    &ProductionLifecycleInspect,
    &ProductionActivate,
    &ProductionRequestStop,
    &ProductionKillExactProcess,
    &ProductionStageFindService,
    &ProductionLiveInspect,
    &ProductionLiveRestage,
    &ProductionLedgerInspect,
    &ProductionExitDequeue,
    &ProductionRestageQueryExact,
    &ProductionExitAcknowledgeExact,
    &ProductionInstallIngress,
    {0, 0},
};

ServiceControlPlatformAdapterV1 g_kernel_service_control_platform;
#endif

} // namespace

ServiceControlPlatformAdapterV1::ServiceControlPlatformAdapterV1()
    : state(static_cast<u32>(ServiceControlPlatformAdapterStateV1::Uninitialized)), version(0), runtime(nullptr),
      ledger(nullptr), authority{}, operations{}
{
}

#if !defined(DUETOS_HOST_TEST)
ServiceControlPlatformInitializeResultV1 ServiceControlPlatformInstallKernelV1()
{
    ServiceRuntimeV1* const runtime = ServiceRuntimeKernelV1();
    return InitializePlatform(&g_kernel_service_control_platform, runtime,
                              runtime == nullptr ? nullptr : &runtime->exit_reap_ledger, &kProductionOperations);
}
#else
ServiceControlPlatformInitializeResultV1 ServiceControlPlatformInitializeForTestV1(
    ServiceControlPlatformAdapterV1* platform, ServiceRuntimeV1* runtime, ServiceExitReapLedger* ledger,
    const ServiceControlPlatformOperationsV1* operations)
{
    return InitializePlatform(platform, runtime, ledger, operations);
}
#endif

ServiceControlPlatformAdapterStateV1 ServiceControlPlatformStateV1(const ServiceControlPlatformAdapterV1* platform)
{
    const u32 state = StateLoad(platform);
    return state <= static_cast<u32>(ServiceControlPlatformAdapterStateV1::Failed)
               ? static_cast<ServiceControlPlatformAdapterStateV1>(state)
               : ServiceControlPlatformAdapterStateV1::Failed;
}

const char* ServiceControlPlatformAdapterStatusNameV1(ServiceControlPlatformAdapterStatusV1 status)
{
    switch (status)
    {
    case ServiceControlPlatformAdapterStatusV1::Ok:
        return "ok";
    case ServiceControlPlatformAdapterStatusV1::NullArgument:
        return "null-argument";
    case ServiceControlPlatformAdapterStatusV1::InvalidOperations:
        return "invalid-operations";
    case ServiceControlPlatformAdapterStatusV1::AlreadyAttempted:
        return "already-attempted";
    case ServiceControlPlatformAdapterStatusV1::RuntimeNotReady:
        return "runtime-not-ready";
    case ServiceControlPlatformAdapterStatusV1::BrokerNotReady:
        return "broker-not-ready";
    case ServiceControlPlatformAdapterStatusV1::LedgerNotReady:
        return "ledger-not-ready";
    case ServiceControlPlatformAdapterStatusV1::LiveBootstrapNotReady:
        return "live-bootstrap-not-ready";
    case ServiceControlPlatformAdapterStatusV1::InstallRejected:
        return "install-rejected";
    case ServiceControlPlatformAdapterStatusV1::CorruptState:
        return "corrupt-state";
    }
    return "unknown";
}

} // namespace duetos::core
