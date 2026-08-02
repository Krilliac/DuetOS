#include "core/service_runtime.h"

#if defined(DUETOS_HOST_TEST)
#include <atomic>
#endif

namespace duetos::core
{
namespace
{

#if !defined(DUETOS_HOST_TEST)
// The embedded lifecycle broker and exit observer deliberately run their
// audited default constructors from the kernel init array.  This owner is
// initialized only after that boot phase, so it has static lifetime without
// pretending those non-trivial components are constant-initializable.
ServiceRuntimeV1 g_kernel_service_runtime{};
#endif

u32 RuntimeStateLoad(const ServiceRuntimeV1* runtime)
{
#if defined(DUETOS_HOST_TEST)
    return std::atomic_ref<u32>(*const_cast<u32*>(&runtime->state)).load(std::memory_order_acquire);
#else
    return __atomic_load_n(&runtime->state, __ATOMIC_ACQUIRE);
#endif
}

void RuntimeStateStore(ServiceRuntimeV1* runtime, ServiceRuntimeStateV1 state)
{
#if defined(DUETOS_HOST_TEST)
    std::atomic_ref<u32>(runtime->state).store(static_cast<u32>(state), std::memory_order_release);
#else
    __atomic_store_n(&runtime->state, static_cast<u32>(state), __ATOMIC_RELEASE);
#endif
}

bool AllZero(const void* bytes, u64 byte_count)
{
    if (bytes == nullptr)
        return false;
    const auto* current = static_cast<const u8*>(bytes);
    for (u64 index = 0; index < byte_count; ++index)
    {
        if (current[index] != 0)
            return false;
    }
    return true;
}

bool HashEquals(const loader::Hash256& left, const loader::Hash256& right)
{
    u8 difference = 0;
    for (u32 index = 0; index < sizeof(left.bytes); ++index)
        difference |= left.bytes[index] ^ right.bytes[index];
    return difference == 0;
}

bool ExitObserverStorageIsPristine(const ServiceExitObserver& observer)
{
    if (observer.lock.next_ticket != 0 || observer.lock.now_serving != 0 || observer.lock.owner_cpu != 0xFFFFFFFFu ||
        observer.lock.class_id != sync::kLockClassServiceLifecycle ||
        observer.state != ServiceExitObserverState::Uninitialized || observer.initialized != 0 ||
        observer.reserved16 != 0 || observer.active_count != 0 || observer.pending_count != 0 ||
        observer.observer_epoch != kServiceExitObserverInvalidEpoch || observer.event_sequence != 0)
    {
        return false;
    }
    for (u32 index = 0; index < kServiceExitObserverCapacity; ++index)
    {
        const ServiceExitObserverSlot& slot = observer.slots[index];
        if (slot.state != ServiceExitObserverSlotState::Free || !AllZero(slot.reserved8, sizeof(slot.reserved8)) ||
            slot.generation != 0 || !(slot.start == kInvalidServiceLifecycleStartTicket) ||
            !(slot.process == kInvalidProcessKey) || slot.exit_code != 0 || slot.reserved32 != 0)
        {
            return false;
        }
    }
    return true;
}

bool RuntimeStorageIsPristine(const ServiceRuntimeV1& runtime)
{
    return runtime.initialized == 0 && runtime.version == 0 &&
           RuntimeStateLoad(&runtime) == static_cast<u32>(ServiceRuntimeStateV1::Uninitialized) &&
           runtime.reserved == 0 && runtime.stage == nullptr && runtime.lifecycle.initialized == 0 &&
           runtime.lifecycle.state == ServiceLifecycleBrokerState::Uninitialized &&
           ExitObserverStorageIsPristine(runtime.exit_observer) && runtime.endpoint_owner.initialized == 0 &&
           runtime.endpoint_owner.state == ServiceEndpointOwnerState::Uninitialized &&
           runtime.directory.initialized == 0 && runtime.directory.state == ServiceDirectoryState::Uninitialized &&
           runtime.directory.endpoint_owner == nullptr;
}

bool RuntimeStorageWasTouched(const ServiceRuntimeV1& runtime)
{
    return RuntimeStateLoad(&runtime) != static_cast<u32>(ServiceRuntimeStateV1::Uninitialized) ||
           runtime.initialized != 0 || runtime.version != 0 || runtime.stage != nullptr ||
           runtime.lifecycle.initialized != 0 || runtime.exit_observer.initialized != 0 ||
           runtime.endpoint_owner.initialized != 0 || runtime.directory.initialized != 0;
}

ServiceRuntimeInitializeResultV1 InitializeResult(ServiceRuntimeStatusV1 status)
{
    ServiceRuntimeInitializeResultV1 result{};
    result.status = status;
    result.stage_status = ServiceBootstrapStageStatus::Ok;
    result.package_status = ServiceObjectPackageStatus::Ok;
    result.manifest_error = ServiceManifestError::Ok;
    result.lifecycle_status = ServiceLifecycleStatus::Ok;
    result.exit_observer_status = ServiceExitObserverStatus::Ok;
    result.endpoint_status = ServiceEndpointStatus::Ok;
    result.directory_status = ServiceDirectoryStatus::Ok;
    return result;
}

ServiceRuntimeDeferAcceptedProcessResultV1 DeferAcceptedProcessFailure(
    ServiceRuntimeStatusV1 runtime_status, ServiceDirectoryStatus directory_status = ServiceDirectoryStatus::Ok,
    u32 newly_deferred_channels = 0, u32 deferred_channels = 0)
{
    return ServiceRuntimeDeferAcceptedProcessResultV1{runtime_status, directory_status, newly_deferred_channels,
                                                      deferred_channels};
}

ServiceRuntimeDriveDeferredAcceptedResultV1 DriveDeferredAcceptedFailure(
    ServiceRuntimeStatusV1 runtime_status, ServiceDirectoryStatus directory_status = ServiceDirectoryStatus::Ok,
    ServiceEndpointStatus endpoint_status = ServiceEndpointStatus::Ok, u32 released_channels = 0,
    u32 pending_channels = 0)
{
    return ServiceRuntimeDriveDeferredAcceptedResultV1{runtime_status, directory_status, endpoint_status,
                                                       released_channels, pending_channels};
}

ServiceRuntimeDeferAcceptedProcessResultV1 DeferAcceptedProcess(ServiceRuntimeV1* runtime, ProcessKey process)
{
    if (runtime == nullptr || !ProcessKeyIsValid(process))
        return DeferAcceptedProcessFailure(ServiceRuntimeStatusV1::NullArgument);

    ServiceRuntimeSnapshotV1 snapshot{};
    const ServiceRuntimeStatusV1 inspected = ServiceRuntimeInspectV1(runtime, &snapshot);
    if (inspected != ServiceRuntimeStatusV1::Ok)
        return DeferAcceptedProcessFailure(inspected);

    const ServiceDirectoryDeferAcceptedProcessResult deferred =
        ServiceDirectoryDeferAcceptedProcess(&runtime->directory, process);
    return ServiceRuntimeDeferAcceptedProcessResultV1{ServiceRuntimeStatusV1::Ok, deferred.status,
                                                      deferred.newly_deferred_channels, deferred.deferred_channels};
}

ServiceRuntimeDriveDeferredAcceptedResultV1 DriveDeferredAccepted(ServiceRuntimeV1* runtime)
{
    if (runtime == nullptr)
        return DriveDeferredAcceptedFailure(ServiceRuntimeStatusV1::NullArgument);

    ServiceRuntimeSnapshotV1 snapshot{};
    const ServiceRuntimeStatusV1 inspected = ServiceRuntimeInspectV1(runtime, &snapshot);
    if (inspected != ServiceRuntimeStatusV1::Ok)
        return DriveDeferredAcceptedFailure(inspected);

    const ServiceDirectoryDriveDeferredAcceptedResult driven =
        ServiceDirectoryDriveDeferredAccepted(&runtime->directory);
    return ServiceRuntimeDriveDeferredAcceptedResultV1{ServiceRuntimeStatusV1::Ok, driven.status,
                                                       driven.endpoint_status, driven.released_channels,
                                                       driven.pending_channels};
}

ServiceRuntimeInitializeResultV1 InitializeRuntime(ServiceRuntimeV1* runtime, ServiceBootstrapStageRuntimeV1* stage,
                                                   bool install_kernel_observer)
{
    ServiceRuntimeInitializeResultV1 result = InitializeResult(ServiceRuntimeStatusV1::Ok);
    if (runtime == nullptr || stage == nullptr)
    {
        result.status = ServiceRuntimeStatusV1::NullArgument;
        return result;
    }
    if (!RuntimeStorageIsPristine(*runtime))
    {
        result.status = RuntimeStorageWasTouched(*runtime) ? ServiceRuntimeStatusV1::AlreadyInitialized
                                                           : ServiceRuntimeStatusV1::NonCanonicalStorage;
        return result;
    }

    ServiceBootstrapStageSnapshotV1 stage_snapshot{};
    result.stage_status = ServiceBootstrapStageInspectV1(stage, &stage_snapshot);
    if (result.stage_status != ServiceBootstrapStageStatus::Ok ||
        stage_snapshot.state != ServiceBootstrapStageState::Ready ||
        stage_snapshot.version != kServiceBootstrapStageVersion1 || stage_snapshot.service_count == 0 ||
        stage_snapshot.ready_count != stage_snapshot.service_count)
    {
        result.status = ServiceRuntimeStatusV1::StageRejected;
        return result;
    }

    ServiceObjectPackageManifestV1 manifest{};
    const ServiceObjectPackageResult package = ServiceObjectPackageGetManifestV1(&stage->package, &manifest);
    result.package_status = package.status;
    result.manifest_error = package.manifest_error;
    if (package.status != ServiceObjectPackageStatus::Ok || manifest.plan == nullptr || manifest.authority == nullptr)
    {
        result.status = ServiceRuntimeStatusV1::ManifestUnavailable;
        return result;
    }

    runtime->version = kServiceRuntimeVersion1;
    runtime->stage = stage;
    RuntimeStateStore(runtime, ServiceRuntimeStateV1::Initializing);

    ServiceLifecycleBrokerEpoch broker_epoch = ServiceLifecycleBrokerMintEpoch();
    if (!broker_epoch.IsValid())
    {
        result.status = ServiceRuntimeStatusV1::BrokerEpochExhausted;
        RuntimeStateStore(runtime, ServiceRuntimeStateV1::Failed);
        return result;
    }
    result.lifecycle_status =
        ServiceLifecycleBrokerInitialize(&runtime->lifecycle, manifest.plan, manifest.authority, &broker_epoch);
    if (result.lifecycle_status != ServiceLifecycleStatus::Ok)
    {
        result.status = ServiceRuntimeStatusV1::BrokerInitializeFailed;
        RuntimeStateStore(runtime, ServiceRuntimeStateV1::Failed);
        return result;
    }

    ServiceExitObserverEpoch observer_epoch = ServiceExitObserverMintEpoch();
    if (!observer_epoch.IsValid())
    {
        result.status = ServiceRuntimeStatusV1::ExitObserverEpochExhausted;
        RuntimeStateStore(runtime, ServiceRuntimeStateV1::Failed);
        return result;
    }
    result.exit_observer_status = ServiceExitObserverInitialize(&runtime->exit_observer, &observer_epoch);
    if (result.exit_observer_status != ServiceExitObserverStatus::Ok)
    {
        result.status = ServiceRuntimeStatusV1::ExitObserverInitializeFailed;
        RuntimeStateStore(runtime, ServiceRuntimeStateV1::Failed);
        return result;
    }

    result.endpoint_status = ServiceEndpointOwnerInitialize(&runtime->endpoint_owner);
    if (result.endpoint_status != ServiceEndpointStatus::Ok)
    {
        result.status = ServiceRuntimeStatusV1::EndpointOwnerInitializeFailed;
        RuntimeStateStore(runtime, ServiceRuntimeStateV1::Failed);
        return result;
    }
    result.directory_status = ServiceDirectoryInitialize(&runtime->directory, &runtime->endpoint_owner);
    if (result.directory_status != ServiceDirectoryStatus::Ok)
    {
        result.status = ServiceRuntimeStatusV1::DirectoryInitializeFailed;
        RuntimeStateStore(runtime, ServiceRuntimeStateV1::Failed);
        return result;
    }

#if !defined(DUETOS_HOST_TEST)
    if (install_kernel_observer)
    {
        result.exit_observer_status = ServiceExitObserverInstallKernelObserver(&runtime->exit_observer);
        if (result.exit_observer_status != ServiceExitObserverStatus::Ok)
        {
            result.status = ServiceRuntimeStatusV1::ExitObserverInstallFailed;
            RuntimeStateStore(runtime, ServiceRuntimeStateV1::Failed);
            return result;
        }
    }
#else
    (void)install_kernel_observer;
#endif

    runtime->initialized = kServiceRuntimeInitializedMarkerV1;
    RuntimeStateStore(runtime, ServiceRuntimeStateV1::Open);
    return result;
}

} // namespace

#if !defined(DUETOS_HOST_TEST)
ServiceRuntimeInitializeResultV1 ServiceRuntimeInitializeKernelV1(ServiceBootstrapStageRuntimeV1* stage)
{
    return InitializeRuntime(&g_kernel_service_runtime, stage, true);
}

ServiceRuntimeV1* ServiceRuntimeKernelV1()
{
    if (RuntimeStateLoad(&g_kernel_service_runtime) != static_cast<u32>(ServiceRuntimeStateV1::Open))
        return nullptr;
    return g_kernel_service_runtime.initialized == kServiceRuntimeInitializedMarkerV1 ? &g_kernel_service_runtime
                                                                                      : nullptr;
}

ServiceRuntimeDeferAcceptedProcessResultV1 ServiceRuntimeDeferAcceptedProcessKernelV1(ProcessKey process)
{
    ServiceRuntimeV1* runtime = ServiceRuntimeKernelV1();
    if (runtime == nullptr)
    {
        const u32 raw_state = RuntimeStateLoad(&g_kernel_service_runtime);
        if (raw_state == static_cast<u32>(ServiceRuntimeStateV1::Uninitialized) ||
            raw_state == static_cast<u32>(ServiceRuntimeStateV1::Initializing))
        {
            // The singleton is not externally reachable before Open, so no
            // accepted endpoint owner can exist yet.
            return DeferAcceptedProcessFailure(ServiceRuntimeStatusV1::NotInitialized,
                                               ServiceDirectoryStatus::NotInitialized);
        }
        if (raw_state == static_cast<u32>(ServiceRuntimeStateV1::Failed))
            return DeferAcceptedProcessFailure(ServiceRuntimeStatusV1::Failed);
        // Open with a missing marker, or any unknown state, is corruption. Do
        // not let Process teardown interpret it as a safe empty runtime and
        // fall through to raw ServiceEndpoint handle release.
        return DeferAcceptedProcessFailure(ServiceRuntimeStatusV1::CorruptState);
    }
    return DeferAcceptedProcess(runtime, process);
}

ServiceRuntimeDriveDeferredAcceptedResultV1 ServiceRuntimeDriveDeferredAcceptedKernelV1()
{
    ServiceRuntimeV1* runtime = ServiceRuntimeKernelV1();
    if (runtime == nullptr)
    {
        const u32 raw_state = RuntimeStateLoad(&g_kernel_service_runtime);
        if (raw_state == static_cast<u32>(ServiceRuntimeStateV1::Uninitialized) ||
            raw_state == static_cast<u32>(ServiceRuntimeStateV1::Initializing))
        {
            return DriveDeferredAcceptedFailure(ServiceRuntimeStatusV1::NotInitialized,
                                                ServiceDirectoryStatus::NotInitialized,
                                                ServiceEndpointStatus::NotInitialized);
        }
        if (raw_state == static_cast<u32>(ServiceRuntimeStateV1::Failed))
            return DriveDeferredAcceptedFailure(ServiceRuntimeStatusV1::Failed);
        return DriveDeferredAcceptedFailure(ServiceRuntimeStatusV1::CorruptState);
    }
    return DriveDeferredAccepted(runtime);
}
#else
ServiceRuntimeInitializeResultV1 ServiceRuntimeInitializeForTestV1(ServiceRuntimeV1* runtime,
                                                                   ServiceBootstrapStageRuntimeV1* stage)
{
    return InitializeRuntime(runtime, stage, false);
}

ServiceRuntimeDeferAcceptedProcessResultV1 ServiceRuntimeDeferAcceptedProcessForTestV1(ServiceRuntimeV1* runtime,
                                                                                       ProcessKey process)
{
    return DeferAcceptedProcess(runtime, process);
}

ServiceRuntimeDriveDeferredAcceptedResultV1 ServiceRuntimeDriveDeferredAcceptedForTestV1(ServiceRuntimeV1* runtime)
{
    return DriveDeferredAccepted(runtime);
}
#endif

ServiceRuntimeStatusV1 ServiceRuntimeInspectV1(const ServiceRuntimeV1* runtime, ServiceRuntimeSnapshotV1* snapshot_out)
{
    if (runtime == nullptr || snapshot_out == nullptr)
        return ServiceRuntimeStatusV1::NullArgument;

    const u32 raw_state = RuntimeStateLoad(runtime);
    if (raw_state > static_cast<u32>(ServiceRuntimeStateV1::Failed))
        return ServiceRuntimeStatusV1::CorruptState;
    const ServiceRuntimeStateV1 state = static_cast<ServiceRuntimeStateV1>(raw_state);
    if (state == ServiceRuntimeStateV1::Uninitialized)
        return ServiceRuntimeStatusV1::NotInitialized;
    if (state == ServiceRuntimeStateV1::Failed)
        return ServiceRuntimeStatusV1::Failed;
    if (state != ServiceRuntimeStateV1::Open || runtime->initialized != kServiceRuntimeInitializedMarkerV1 ||
        runtime->version != kServiceRuntimeVersion1 || runtime->reserved != 0 || runtime->stage == nullptr)
    {
        return ServiceRuntimeStatusV1::CorruptState;
    }

    const ServiceLifecycleBrokerInspectResult lifecycle =
        ServiceLifecycleBrokerDescribe(const_cast<ServiceLifecycleBroker*>(&runtime->lifecycle));
    ServiceExitObserverSnapshot observer{};
    const ServiceExitObserverStatus observer_status =
        ServiceExitObserverInspect(const_cast<ServiceExitObserver*>(&runtime->exit_observer), &observer);
    ServiceBootstrapStageSnapshotV1 stage{};
    const ServiceBootstrapStageStatus stage_status = ServiceBootstrapStageInspectV1(runtime->stage, &stage);
    const ServiceDirectoryStatus directory_status = ServiceDirectoryValidateRuntimeOwner(
        const_cast<ServiceDirectory*>(&runtime->directory), &runtime->endpoint_owner);
    const ServiceManifestPlanV1& manifest = runtime->stage->package.manifest_plan;
    const ServiceManifestAuthoritySnapshotV1& authority = runtime->stage->package.manifest_authority;
    if (lifecycle.status != ServiceLifecycleStatus::Ok || observer_status != ServiceExitObserverStatus::Ok ||
        stage_status != ServiceBootstrapStageStatus::Ok || directory_status != ServiceDirectoryStatus::Ok ||
        !ServiceEndpointOwnerIsReady(const_cast<ServiceEndpointOwner*>(&runtime->endpoint_owner)) ||
        lifecycle.snapshot.service_count != stage.service_count ||
        lifecycle.snapshot.manifest_identity != runtime->stage->package.manifest_plan.document.manifest_identity ||
        lifecycle.snapshot.manifest_authority_identity != stage.authority_identity ||
        lifecycle.snapshot.manifest_authority_identity != authority.authority_identity ||
        !HashEquals(lifecycle.snapshot.manifest_object_hash, manifest.sealed_object_hash) ||
        !HashEquals(lifecycle.snapshot.manifest_object_hash, authority.sealed_object_hash) ||
        lifecycle.snapshot.manifest_object_extent != manifest.sealed_object_extent ||
        lifecycle.snapshot.manifest_object_extent != authority.sealed_object_extent || stage.registry_identity == 0)
    {
        return ServiceRuntimeStatusV1::CorruptState;
    }

    ServiceRuntimeSnapshotV1 snapshot{};
    snapshot.state = state;
    snapshot.version = runtime->version;
    snapshot.service_count = lifecycle.snapshot.service_count;
    snapshot.manifest_identity = lifecycle.snapshot.manifest_identity;
    snapshot.manifest_authority_identity = lifecycle.snapshot.manifest_authority_identity;
    snapshot.broker_epoch = lifecycle.snapshot.broker_epoch;
    snapshot.observer_epoch = observer.observer_epoch;
    snapshot.observer_event_sequence = observer.event_sequence;
    snapshot.stage_registry_identity = stage.registry_identity;
    *snapshot_out = snapshot;
    return ServiceRuntimeStatusV1::Ok;
}

ServiceRuntimeStatusV1 ServiceRuntimeBindActivationAuthorityV1(ServiceRuntimeV1* runtime,
                                                               ServiceRuntimeActivationAuthorityV1* authority_out)
{
    if (runtime == nullptr || authority_out == nullptr)
        return ServiceRuntimeStatusV1::NullArgument;
    *authority_out = {};

    ServiceRuntimeSnapshotV1 snapshot{};
    const ServiceRuntimeStatusV1 inspected = ServiceRuntimeInspectV1(runtime, &snapshot);
    if (inspected != ServiceRuntimeStatusV1::Ok)
        return inspected;

    ServiceObjectPackageManifestV1 manifest{};
    const ServiceObjectPackageResult package = ServiceObjectPackageGetManifestV1(&runtime->stage->package, &manifest);
    if (package.status != ServiceObjectPackageStatus::Ok || manifest.plan == nullptr || manifest.authority == nullptr ||
        manifest.plan->document.manifest_identity != snapshot.manifest_identity ||
        manifest.authority->authority_identity != snapshot.manifest_authority_identity ||
        !HashEquals(manifest.plan->sealed_object_hash, manifest.authority->sealed_object_hash) ||
        manifest.plan->sealed_object_extent != manifest.authority->sealed_object_extent)
    {
        return ServiceRuntimeStatusV1::CorruptState;
    }

    *authority_out = ServiceRuntimeActivationAuthorityV1{
        runtime->stage,
        &runtime->lifecycle,
        &runtime->exit_observer,
        &runtime->directory,
        snapshot.manifest_identity,
        snapshot.manifest_authority_identity,
        manifest.plan->sealed_object_hash,
        manifest.plan->sealed_object_extent,
        snapshot.stage_registry_identity,
    };
    return ServiceRuntimeStatusV1::Ok;
}

const char* ServiceRuntimeStatusNameV1(ServiceRuntimeStatusV1 status)
{
    switch (status)
    {
    case ServiceRuntimeStatusV1::Ok:
        return "ok";
    case ServiceRuntimeStatusV1::NullArgument:
        return "null-argument";
    case ServiceRuntimeStatusV1::NonCanonicalStorage:
        return "non-canonical-storage";
    case ServiceRuntimeStatusV1::AlreadyInitialized:
        return "already-initialized";
    case ServiceRuntimeStatusV1::StageRejected:
        return "stage-rejected";
    case ServiceRuntimeStatusV1::ManifestUnavailable:
        return "manifest-unavailable";
    case ServiceRuntimeStatusV1::BrokerEpochExhausted:
        return "broker-epoch-exhausted";
    case ServiceRuntimeStatusV1::BrokerInitializeFailed:
        return "broker-initialize-failed";
    case ServiceRuntimeStatusV1::ExitObserverEpochExhausted:
        return "exit-observer-epoch-exhausted";
    case ServiceRuntimeStatusV1::ExitObserverInitializeFailed:
        return "exit-observer-initialize-failed";
    case ServiceRuntimeStatusV1::EndpointOwnerInitializeFailed:
        return "endpoint-owner-initialize-failed";
    case ServiceRuntimeStatusV1::DirectoryInitializeFailed:
        return "directory-initialize-failed";
    case ServiceRuntimeStatusV1::ExitObserverInstallFailed:
        return "exit-observer-install-failed";
    case ServiceRuntimeStatusV1::NotInitialized:
        return "not-initialized";
    case ServiceRuntimeStatusV1::Failed:
        return "failed";
    case ServiceRuntimeStatusV1::CorruptState:
        return "corrupt-state";
    }
    return "unknown";
}

} // namespace duetos::core
