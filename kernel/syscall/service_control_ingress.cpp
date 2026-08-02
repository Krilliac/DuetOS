#include "syscall/service_control_ingress.h"

#if !defined(DUETOS_HOST_TEST)
#include "arch/x86_64/traps.h"
#include "mm/address_space.h"
#include "mm/paging.h"
#include "syscall/error.h"
#include "util/defer.h"
#endif

namespace duetos::core
{

namespace
{

using AbiStatus = duet_service_control_status;

static_assert(DUET_SERVICE_CONTROL_PHASE_STOPPED == static_cast<u8>(ServiceTransitionPhase::Stopped));
static_assert(DUET_SERVICE_CONTROL_PHASE_STARTING == static_cast<u8>(ServiceTransitionPhase::Starting));
static_assert(DUET_SERVICE_CONTROL_PHASE_RUNNING == static_cast<u8>(ServiceTransitionPhase::Running));
static_assert(DUET_SERVICE_CONTROL_PHASE_EXITED == static_cast<u8>(ServiceTransitionPhase::Exited));
static_assert(DUET_SERVICE_CONTROL_PHASE_FAILED == static_cast<u8>(ServiceTransitionPhase::Failed));
static_assert(DUET_SERVICE_CONTROL_PHASE_GENERATION_EXHAUSTED ==
              static_cast<u8>(ServiceTransitionPhase::GenerationExhausted));
static_assert(DUET_SERVICE_CONTROL_PHASE_STOPPING == static_cast<u8>(ServiceTransitionPhase::Stopping));

#if defined(DUETOS_HOST_TEST)
class StateGuard
{
  public:
    explicit StateGuard(ServiceControlIngressState& state) : guard_(state.lock) {}

  private:
    std::lock_guard<std::mutex> guard_;
};
#else
class StateGuard
{
  public:
    explicit StateGuard(ServiceControlIngressState& state) : guard_(state.lock) {}

  private:
    sync::SpinLockGuard guard_;
};
#endif

struct RuntimeView
{
    ServiceRuntimeActivationAuthorityV1 authority;
    ServiceLifecycleBrokerSnapshot broker;
};

struct ServiceRowView
{
    ServiceLifecycleSnapshot snapshot;
    u32 index;
};

bool ProcessMatches(ProcessKey lhs, ProcessKey rhs)
{
    return lhs.identity == rhs.identity && lhs.pid == rhs.pid;
}

bool ProcessIsEmpty(ProcessKey process)
{
    return process.identity == 0 && process.pid == 0;
}

ProcessKey RequestProcess(const duet_service_control_request_v1& request)
{
    return ProcessKey{request.process_identity, request.pid};
}

bool PlatformIsCanonical(const ServiceControlIngressPlatformV1& platform)
{
    return platform.struct_size == sizeof(platform) && platform.version == kServiceControlPlatformVersion1 &&
           platform.activate != nullptr && platform.stop != nullptr && platform.restage != nullptr &&
           platform.exit_dequeue != nullptr && platform.exit_ack != nullptr && platform.reserved[0] == 0 &&
           platform.reserved[1] == 0;
}

bool StateIsCanonicalUninitialized(const ServiceControlIngressState& state)
{
    const auto& platform = state.platform;
    return state.initialized == 0 && state.platform_installed == 0 && platform.struct_size == 0 &&
           platform.version == 0 && platform.context == nullptr && platform.activate == nullptr &&
           platform.stop == nullptr && platform.restage == nullptr && platform.exit_dequeue == nullptr &&
           platform.exit_ack == nullptr && platform.reserved[0] == 0 && platform.reserved[1] == 0;
}

bool SnapshotPlatform(ServiceControlIngressState& state, ServiceControlIngressPlatformV1* platform_out)
{
    if (platform_out == nullptr)
        return false;
    StateGuard guard(state);
    if (state.initialized != kServiceControlIngressInitializedMarker || state.platform_installed != 1 ||
        !PlatformIsCanonical(state.platform))
    {
        return false;
    }
    *platform_out = state.platform;
    return true;
}

void InitializeResult(const duet_service_control_request_v1& request, duet_service_control_result_v1* result)
{
    *result = {};
    result->struct_size = sizeof(*result);
    result->version = DUET_SERVICE_CONTROL_ABI_VERSION;
    result->operation = request.operation;
    result->status = DUET_SERVICE_CONTROL_STATUS_INTERNAL_ERROR;
}

void SetStatus(duet_service_control_result_v1* result, AbiStatus status)
{
    result->status = static_cast<i32>(status);
}

AbiStatus MapRuntimeStatus(ServiceRuntimeStatusV1 status)
{
    switch (status)
    {
    case ServiceRuntimeStatusV1::Ok:
        return DUET_SERVICE_CONTROL_STATUS_OK;
    case ServiceRuntimeStatusV1::NotInitialized:
    case ServiceRuntimeStatusV1::Failed:
        return DUET_SERVICE_CONTROL_STATUS_NOT_READY;
    case ServiceRuntimeStatusV1::CorruptState:
        return DUET_SERVICE_CONTROL_STATUS_CORRUPT_STATE;
    case ServiceRuntimeStatusV1::NullArgument:
    case ServiceRuntimeStatusV1::NonCanonicalStorage:
        return DUET_SERVICE_CONTROL_STATUS_INVALID_ARGUMENT;
    default:
        return DUET_SERVICE_CONTROL_STATUS_INTERNAL_ERROR;
    }
}

AbiStatus MapLifecycleStatus(ServiceLifecycleStatus status)
{
    switch (status)
    {
    case ServiceLifecycleStatus::Ok:
        return DUET_SERVICE_CONTROL_STATUS_OK;
    case ServiceLifecycleStatus::InvalidManifestPlan:
    case ServiceLifecycleStatus::InvalidBrokerEpoch:
    case ServiceLifecycleStatus::InvalidTimestamp:
    case ServiceLifecycleStatus::NullArgument:
    case ServiceLifecycleStatus::AliasedOutput:
        return DUET_SERVICE_CONTROL_STATUS_INVALID_ARGUMENT;
    case ServiceLifecycleStatus::NotInitialized:
    case ServiceLifecycleStatus::Closed:
    case ServiceLifecycleStatus::Draining:
    case ServiceLifecycleStatus::DependencyNotReady:
        return DUET_SERVICE_CONTROL_STATUS_NOT_READY;
    case ServiceLifecycleStatus::NotFound:
        return DUET_SERVICE_CONTROL_STATUS_NOT_FOUND;
    case ServiceLifecycleStatus::StaleGeneration:
    case ServiceLifecycleStatus::StaleBrokerEpoch:
    case ServiceLifecycleStatus::StartCancelled:
    case ServiceLifecycleStatus::StartRetirementPending:
        return DUET_SERVICE_CONTROL_STATUS_STALE;
    case ServiceLifecycleStatus::AlreadyRequested:
    case ServiceLifecycleStatus::StopInProgress:
    case ServiceLifecycleStatus::KillRequired:
    case ServiceLifecycleStatus::AlreadyStopping:
        return DUET_SERVICE_CONTROL_STATUS_ALREADY_REQUESTED;
    case ServiceLifecycleStatus::AlreadyStopped:
        return DUET_SERVICE_CONTROL_STATUS_ALREADY_STOPPED;
    case ServiceLifecycleStatus::GenerationExhausted:
        return DUET_SERVICE_CONTROL_STATUS_GENERATION_EXHAUSTED;
    case ServiceLifecycleStatus::Busy:
        return DUET_SERVICE_CONTROL_STATUS_BUSY;
    case ServiceLifecycleStatus::CorruptState:
        return DUET_SERVICE_CONTROL_STATUS_CORRUPT_STATE;
    case ServiceLifecycleStatus::AlreadyInitialized:
    case ServiceLifecycleStatus::TransitionRejected:
        return DUET_SERVICE_CONTROL_STATUS_INTERNAL_ERROR;
    }
    return DUET_SERVICE_CONTROL_STATUS_INTERNAL_ERROR;
}

AbiStatus MapDirectoryStatus(ServiceDirectoryStatus status)
{
    switch (status)
    {
    case ServiceDirectoryStatus::Ok:
        return DUET_SERVICE_CONTROL_STATUS_OK;
    case ServiceDirectoryStatus::InvalidArgument:
        return DUET_SERVICE_CONTROL_STATUS_INVALID_ARGUMENT;
    case ServiceDirectoryStatus::NotInitialized:
    case ServiceDirectoryStatus::NotReady:
    case ServiceDirectoryStatus::Closing:
        return DUET_SERVICE_CONTROL_STATUS_NOT_READY;
    case ServiceDirectoryStatus::NotFound:
        return DUET_SERVICE_CONTROL_STATUS_NOT_FOUND;
    case ServiceDirectoryStatus::StaleKey:
    case ServiceDirectoryStatus::StaleOperation:
        return DUET_SERVICE_CONTROL_STATUS_STALE;
    case ServiceDirectoryStatus::Busy:
        return DUET_SERVICE_CONTROL_STATUS_BUSY;
    case ServiceDirectoryStatus::CapacityExhausted:
    case ServiceDirectoryStatus::OperationIdentityExhausted:
        return DUET_SERVICE_CONTROL_STATUS_CAPACITY_EXHAUSTED;
    case ServiceDirectoryStatus::GenerationExhausted:
        return DUET_SERVICE_CONTROL_STATUS_GENERATION_EXHAUSTED;
    case ServiceDirectoryStatus::CorruptState:
        return DUET_SERVICE_CONTROL_STATUS_CORRUPT_STATE;
    default:
        return DUET_SERVICE_CONTROL_STATUS_INTERNAL_ERROR;
    }
}

AbiStatus MapPlatformStatus(ServiceControlPlatformStatusV1 status)
{
    switch (status)
    {
    case ServiceControlPlatformStatusV1::Ok:
        return DUET_SERVICE_CONTROL_STATUS_OK;
    case ServiceControlPlatformStatusV1::InvalidArgument:
        return DUET_SERVICE_CONTROL_STATUS_INVALID_ARGUMENT;
    case ServiceControlPlatformStatusV1::NotReady:
        return DUET_SERVICE_CONTROL_STATUS_NOT_READY;
    case ServiceControlPlatformStatusV1::NotFound:
        return DUET_SERVICE_CONTROL_STATUS_NOT_FOUND;
    case ServiceControlPlatformStatusV1::Stale:
        return DUET_SERVICE_CONTROL_STATUS_STALE;
    case ServiceControlPlatformStatusV1::ReplayRejected:
        return DUET_SERVICE_CONTROL_STATUS_REPLAY_REJECTED;
    case ServiceControlPlatformStatusV1::WouldBlock:
        return DUET_SERVICE_CONTROL_STATUS_WOULD_BLOCK;
    case ServiceControlPlatformStatusV1::Busy:
        return DUET_SERVICE_CONTROL_STATUS_BUSY;
    case ServiceControlPlatformStatusV1::CapacityExhausted:
        return DUET_SERVICE_CONTROL_STATUS_CAPACITY_EXHAUSTED;
    case ServiceControlPlatformStatusV1::GenerationExhausted:
        return DUET_SERVICE_CONTROL_STATUS_GENERATION_EXHAUSTED;
    case ServiceControlPlatformStatusV1::AlreadyRequested:
        return DUET_SERVICE_CONTROL_STATUS_ALREADY_REQUESTED;
    case ServiceControlPlatformStatusV1::AlreadyStopped:
        return DUET_SERVICE_CONTROL_STATUS_ALREADY_STOPPED;
    case ServiceControlPlatformStatusV1::CorruptState:
        return DUET_SERVICE_CONTROL_STATUS_CORRUPT_STATE;
    case ServiceControlPlatformStatusV1::InternalError:
        return DUET_SERVICE_CONTROL_STATUS_INTERNAL_ERROR;
    }
    return DUET_SERVICE_CONTROL_STATUS_INTERNAL_ERROR;
}

bool RequestBaseIsCanonical(const duet_service_control_request_v1& request)
{
    return request.struct_size == sizeof(request) && request.flags == 0 && request.reserved[0] == 0;
}

bool RequestOperationIsKnown(u16 operation)
{
    return operation >= DUET_SERVICE_CONTROL_OP_DESCRIBE_SELF && operation <= DUET_SERVICE_CONTROL_OP_EXIT_ACK;
}

bool RequestShapeIsCanonical(const duet_service_control_request_v1& request)
{
    const ProcessKey process = RequestProcess(request);
    switch (request.operation)
    {
    case DUET_SERVICE_CONTROL_OP_DESCRIBE_SELF:
    case DUET_SERVICE_CONTROL_OP_EXIT_DEQUEUE:
        return request.service_index == 0 && request.broker_epoch == 0 && request.service_identity == 0 &&
               request.transition_generation == 0 && ProcessIsEmpty(process) && request.operation_token == 0 &&
               request.event_sequence == 0;
    case DUET_SERVICE_CONTROL_OP_MARK_READY:
        return request.service_index == 0 && request.broker_epoch != 0 && request.service_identity != 0 &&
               request.transition_generation != 0 && ProcessKeyIsValid(process) && request.operation_token == 0 &&
               request.event_sequence == 0;
    case DUET_SERVICE_CONTROL_OP_ENUMERATE:
        return request.service_identity == 0 && request.transition_generation == 0 && ProcessIsEmpty(process) &&
               request.operation_token == 0 && request.event_sequence == 0;
    case DUET_SERVICE_CONTROL_OP_ACTIVATE:
        return request.service_index == 0 && request.broker_epoch != 0 && request.service_identity != 0 &&
               ProcessIsEmpty(process) && request.operation_token == 0 && request.event_sequence == 0;
    case DUET_SERVICE_CONTROL_OP_STOP:
        return request.service_index == 0 && request.broker_epoch != 0 && request.service_identity != 0 &&
               (ProcessIsEmpty(process) || ProcessKeyIsValid(process)) && request.operation_token == 0 &&
               request.event_sequence == 0;
    case DUET_SERVICE_CONTROL_OP_RESTAGE:
        return request.service_index == 0 && request.broker_epoch != 0 && request.service_identity != 0 &&
               request.transition_generation != 0 && ProcessKeyIsValid(process) && request.operation_token == 0 &&
               request.event_sequence != 0;
    case DUET_SERVICE_CONTROL_OP_EXIT_ACK:
        return request.service_index == 0 && request.broker_epoch != 0 && request.service_identity != 0 &&
               request.transition_generation != 0 && ProcessKeyIsValid(process) && request.operation_token != 0 &&
               request.event_sequence != 0;
    default:
        return false;
    }
}

AbiStatus BindRuntime(const ServiceControlIngressCaller& caller, RuntimeView* view)
{
    if (caller.runtime == nullptr || view == nullptr)
        return DUET_SERVICE_CONTROL_STATUS_NOT_READY;
    *view = {};
    const ServiceRuntimeStatusV1 bound = ServiceRuntimeBindActivationAuthorityV1(caller.runtime, &view->authority);
    if (bound != ServiceRuntimeStatusV1::Ok)
        return MapRuntimeStatus(bound);
    if (view->authority.stage == nullptr || view->authority.lifecycle == nullptr ||
        view->authority.directory == nullptr)
    {
        return DUET_SERVICE_CONTROL_STATUS_CORRUPT_STATE;
    }
    const ServiceLifecycleBrokerInspectResult described = ServiceLifecycleBrokerDescribe(view->authority.lifecycle);
    if (described.status != ServiceLifecycleStatus::Ok)
        return MapLifecycleStatus(described.status);
    if (described.snapshot.broker_epoch == 0 || described.snapshot.service_count == 0 ||
        described.snapshot.service_count > kServiceLifecycleCapacity)
    {
        return DUET_SERVICE_CONTROL_STATUS_CORRUPT_STATE;
    }
    view->broker = described.snapshot;
    return DUET_SERVICE_CONTROL_STATUS_OK;
}

AbiStatus FindServiceByIdentity(const RuntimeView& runtime, u64 service_identity, ServiceRowView* service)
{
    if (service == nullptr || service_identity == 0)
        return DUET_SERVICE_CONTROL_STATUS_INVALID_ARGUMENT;
    bool found = false;
    ServiceRowView match{};
    for (u32 index = 0; index < runtime.broker.service_count; ++index)
    {
        const ServiceLifecycleInspectResult inspected =
            ServiceLifecycleBrokerInspectAt(runtime.authority.lifecycle, index);
        if (inspected.status != ServiceLifecycleStatus::Ok)
            return MapLifecycleStatus(inspected.status);
        if (inspected.snapshot.service_identity != service_identity)
            continue;
        if (found)
            return DUET_SERVICE_CONTROL_STATUS_CORRUPT_STATE;
        found = true;
        match = ServiceRowView{inspected.snapshot, index};
    }
    if (!found)
        return DUET_SERVICE_CONTROL_STATUS_NOT_FOUND;
    *service = match;
    return DUET_SERVICE_CONTROL_STATUS_OK;
}

AbiStatus InspectAt(const RuntimeView& runtime, u32 index, ServiceRowView* service)
{
    if (service == nullptr || index >= runtime.broker.service_count)
        return DUET_SERVICE_CONTROL_STATUS_NOT_FOUND;
    const ServiceLifecycleInspectResult inspected = ServiceLifecycleBrokerInspectAt(runtime.authority.lifecycle, index);
    if (inspected.status != ServiceLifecycleStatus::Ok)
        return MapLifecycleStatus(inspected.status);
    if (inspected.snapshot.service_identity == 0)
        return DUET_SERVICE_CONTROL_STATUS_CORRUPT_STATE;
    *service = ServiceRowView{inspected.snapshot, index};
    return DUET_SERVICE_CONTROL_STATUS_OK;
}

AbiStatus FindCallerService(const RuntimeView& runtime, ProcessKey process, ServiceRowView* service)
{
    if (service == nullptr || !ProcessKeyIsValid(process))
        return DUET_SERVICE_CONTROL_STATUS_ACCESS_DENIED;
    bool found = false;
    ServiceRowView match{};
    for (u32 index = 0; index < runtime.broker.service_count; ++index)
    {
        const ServiceLifecycleInspectResult inspected =
            ServiceLifecycleBrokerInspectAt(runtime.authority.lifecycle, index);
        if (inspected.status != ServiceLifecycleStatus::Ok)
            return MapLifecycleStatus(inspected.status);
        const ProcessKey row_process{inspected.snapshot.instance.process_identity, inspected.snapshot.instance.pid};
        if (!ProcessKeyIsValid(row_process) || !ProcessMatches(row_process, process))
            continue;
        if (found)
            return DUET_SERVICE_CONTROL_STATUS_CORRUPT_STATE;
        found = true;
        match = ServiceRowView{inspected.snapshot, index};
    }
    if (!found)
        return DUET_SERVICE_CONTROL_STATUS_ACCESS_DENIED;
    *service = match;
    return DUET_SERVICE_CONTROL_STATUS_OK;
}

void FillServiceResult(const RuntimeView& runtime, const ServiceRowView& service,
                       duet_service_control_result_v1* result)
{
    result->flags |= DUET_SERVICE_CONTROL_RESULT_HAS_SERVICE;
    if (service.snapshot.ready)
        result->flags |= DUET_SERVICE_CONTROL_RESULT_SERVICE_READY;
    result->service_index = service.index;
    result->service_count = runtime.broker.service_count;
    result->phase = static_cast<u8>(service.snapshot.phase);
    result->ready = service.snapshot.ready ? 1 : 0;
    result->broker_epoch = runtime.broker.broker_epoch;
    result->service_identity = service.snapshot.service_identity;
    result->transition_generation = service.snapshot.transition_generation;
    result->process_identity = service.snapshot.instance.process_identity;
    result->pid = service.snapshot.instance.pid;
}

bool RequestMatchesService(const duet_service_control_request_v1& request, const RuntimeView& runtime,
                           const ServiceRowView& service, bool require_process)
{
    if (request.broker_epoch != runtime.broker.broker_epoch ||
        request.service_identity != service.snapshot.service_identity ||
        request.transition_generation != service.snapshot.transition_generation)
    {
        return false;
    }
    if (!require_process)
        return true;
    return request.process_identity == service.snapshot.instance.process_identity &&
           request.pid == service.snapshot.instance.pid;
}

ServiceControlPlatformTargetV1 PlatformTarget(const duet_service_control_request_v1& request)
{
    return ServiceControlPlatformTargetV1{request.broker_epoch, request.service_identity, request.transition_generation,
                                          RequestProcess(request), request.event_sequence};
}

AbiStatus RefreshServiceResult(const RuntimeView& runtime, u64 service_identity, duet_service_control_result_v1* result)
{
    ServiceRowView refreshed{};
    const AbiStatus status = FindServiceByIdentity(runtime, service_identity, &refreshed);
    if (status == DUET_SERVICE_CONTROL_STATUS_OK)
        FillServiceResult(runtime, refreshed, result);
    return status;
}

AbiStatus MarkCallerReady(const RuntimeView& runtime, const ServiceRowView& service,
                          duet_service_control_result_v1* result)
{
    const auto& document = runtime.authority.stage->package.manifest_plan.document;
    if (service.index >= document.service_count ||
        document.services[service.index].service_identity != service.snapshot.service_identity)
    {
        return DUET_SERVICE_CONTROL_STATUS_CORRUPT_STATE;
    }
    const ServiceManifestServiceV1& manifest = document.services[service.index];
    ServiceDirectoryName name{};
    if (manifest.name_length == 0 || manifest.name_length > kServiceDirectoryNameCapacity)
        return DUET_SERVICE_CONTROL_STATUS_CORRUPT_STATE;
    name.length = manifest.name_length;
    for (u32 index = 0; index < manifest.name_length; ++index)
        name.bytes[index] = manifest.name[index];
    if (!ServiceDirectoryNameIsCanonical(name))
        return DUET_SERVICE_CONTROL_STATUS_CORRUPT_STATE;

    ServiceDirectoryLookupResult lookup = ServiceDirectoryLookup(runtime.authority.directory, &name);
    if (lookup.status != ServiceDirectoryStatus::Ok)
        return MapDirectoryStatus(lookup.status);

    const ServiceLifecycleInstanceToken instance{
        ServiceLifecycleStartTicket{
            runtime.broker.broker_epoch,
            ServiceStartTicket{service.snapshot.service_identity, service.snapshot.transition_generation}},
        service.snapshot.instance,
    };
    const ServiceLifecycleDirectoryReadyResult marked = ServiceLifecycleBrokerMarkReady(
        runtime.authority.lifecycle, instance, runtime.authority.directory, lookup.pin.service);
    const ServiceDirectoryStatus released = ServiceDirectoryReleaseOperation(runtime.authority.directory, &lookup.pin);
    if (released != ServiceDirectoryStatus::Ok)
        return DUET_SERVICE_CONTROL_STATUS_CORRUPT_STATE;
    if (marked.lifecycle_status != ServiceLifecycleStatus::Ok)
        return MapLifecycleStatus(marked.lifecycle_status);
    if (marked.directory_status != ServiceDirectoryStatus::Ok)
        return MapDirectoryStatus(marked.directory_status);

    const AbiStatus refreshed = RefreshServiceResult(runtime, service.snapshot.service_identity, result);
    return refreshed == DUET_SERVICE_CONTROL_STATUS_OK ? DUET_SERVICE_CONTROL_STATUS_OK : refreshed;
}

AbiStatus ValidateExitEvent(const RuntimeView& runtime, const ServiceControlPlatformExitEventV1& event)
{
    if (!ServiceLifecycleInstanceTokenIsValid(event.instance) ||
        event.instance.start.broker_epoch != runtime.broker.broker_epoch || event.event_sequence == 0 ||
        event.acknowledgement_token == 0)
    {
        return DUET_SERVICE_CONTROL_STATUS_CORRUPT_STATE;
    }
    for (u8 byte : event.reserved)
    {
        if (byte != 0)
            return DUET_SERVICE_CONTROL_STATUS_CORRUPT_STATE;
    }
    return DUET_SERVICE_CONTROL_STATUS_OK;
}

#if !defined(DUETOS_HOST_TEST)
constinit ServiceControlIngressState g_kernel_service_control_ingress{};
#endif

} // namespace

ServiceControlIngressStatus ServiceControlIngressInitialize(ServiceControlIngressState* state)
{
    if (state == nullptr)
        return ServiceControlIngressStatus::InvalidArgument;
    StateGuard guard(*state);
    if (state->initialized == kServiceControlIngressInitializedMarker)
        return ServiceControlIngressStatus::AlreadyInitialized;
    if (!StateIsCanonicalUninitialized(*state))
        return ServiceControlIngressStatus::CorruptState;
    state->initialized = kServiceControlIngressInitializedMarker;
    return ServiceControlIngressStatus::Ok;
}

ServiceControlIngressStatus ServiceControlIngressInstallPlatformV1(ServiceControlIngressState* state,
                                                                   const ServiceControlIngressPlatformV1* platform)
{
    if (state == nullptr || platform == nullptr || !PlatformIsCanonical(*platform))
        return ServiceControlIngressStatus::InvalidArgument;
    const ServiceControlIngressPlatformV1 platform_copy = *platform;
    StateGuard guard(*state);
    if (state->initialized != kServiceControlIngressInitializedMarker)
        return ServiceControlIngressStatus::NotInitialized;
    if (state->platform_installed != 0)
        return ServiceControlIngressStatus::PlatformAlreadyInstalled;
    state->platform = platform_copy;
    state->platform_installed = 1;
    return ServiceControlIngressStatus::Ok;
}

ServiceControlIngressStatus ServiceControlIngressExecute(ServiceControlIngressState* state,
                                                         const ServiceControlIngressCaller* caller,
                                                         const duet_service_control_request_v1* request,
                                                         duet_service_control_result_v1* result)
{
    if (state == nullptr || caller == nullptr || request == nullptr || result == nullptr)
        return ServiceControlIngressStatus::InvalidArgument;
    if (state->initialized != kServiceControlIngressInitializedMarker)
        return ServiceControlIngressStatus::NotInitialized;

    const duet_service_control_request_v1 request_copy = *request;
    InitializeResult(request_copy, result);
    if (request_copy.version != DUET_SERVICE_CONTROL_ABI_VERSION)
    {
        SetStatus(result, DUET_SERVICE_CONTROL_STATUS_BAD_VERSION);
        return ServiceControlIngressStatus::Ok;
    }
    if (!RequestBaseIsCanonical(request_copy))
    {
        SetStatus(result, DUET_SERVICE_CONTROL_STATUS_INVALID_ARGUMENT);
        return ServiceControlIngressStatus::Ok;
    }
    if (!RequestOperationIsKnown(request_copy.operation))
    {
        SetStatus(result, DUET_SERVICE_CONTROL_STATUS_UNSUPPORTED);
        return ServiceControlIngressStatus::Ok;
    }
    if (!RequestShapeIsCanonical(request_copy))
    {
        SetStatus(result, DUET_SERVICE_CONTROL_STATUS_INVALID_ARGUMENT);
        return ServiceControlIngressStatus::Ok;
    }
    if (!ProcessKeyIsValid(caller->process) || caller->runtime == nullptr)
    {
        SetStatus(result, DUET_SERVICE_CONTROL_STATUS_ACCESS_DENIED);
        return ServiceControlIngressStatus::Ok;
    }

    const bool supervisor_operation = request_copy.operation >= DUET_SERVICE_CONTROL_OP_ENUMERATE;
    if (supervisor_operation && !CapSetHas(caller->capabilities, kCapServiceControl))
    {
        SetStatus(result, DUET_SERVICE_CONTROL_STATUS_ACCESS_DENIED);
        return ServiceControlIngressStatus::Ok;
    }

    RuntimeView runtime{};
    const AbiStatus bound = BindRuntime(*caller, &runtime);
    if (bound != DUET_SERVICE_CONTROL_STATUS_OK)
    {
        SetStatus(result, bound);
        return ServiceControlIngressStatus::Ok;
    }

    if (request_copy.operation == DUET_SERVICE_CONTROL_OP_DESCRIBE_SELF ||
        request_copy.operation == DUET_SERVICE_CONTROL_OP_MARK_READY)
    {
        ServiceRowView service{};
        const AbiStatus resolved = FindCallerService(runtime, caller->process, &service);
        if (resolved != DUET_SERVICE_CONTROL_STATUS_OK)
        {
            SetStatus(result, resolved);
            return ServiceControlIngressStatus::Ok;
        }
        FillServiceResult(runtime, service, result);
        if (request_copy.operation == DUET_SERVICE_CONTROL_OP_DESCRIBE_SELF)
        {
            SetStatus(result, DUET_SERVICE_CONTROL_STATUS_OK);
            return ServiceControlIngressStatus::Ok;
        }
        if (!RequestMatchesService(request_copy, runtime, service, true))
        {
            SetStatus(result, DUET_SERVICE_CONTROL_STATUS_STALE);
            return ServiceControlIngressStatus::Ok;
        }
        SetStatus(result, MarkCallerReady(runtime, service, result));
        return ServiceControlIngressStatus::Ok;
    }

    if (request_copy.operation == DUET_SERVICE_CONTROL_OP_ENUMERATE)
    {
        if (request_copy.broker_epoch != 0 && request_copy.broker_epoch != runtime.broker.broker_epoch)
        {
            SetStatus(result, DUET_SERVICE_CONTROL_STATUS_STALE);
            return ServiceControlIngressStatus::Ok;
        }
        ServiceRowView service{};
        const AbiStatus inspected = InspectAt(runtime, request_copy.service_index, &service);
        if (inspected == DUET_SERVICE_CONTROL_STATUS_OK)
            FillServiceResult(runtime, service, result);
        SetStatus(result, inspected);
        return ServiceControlIngressStatus::Ok;
    }

    ServiceControlIngressPlatformV1 platform{};
    if (!SnapshotPlatform(*state, &platform))
    {
        SetStatus(result, DUET_SERVICE_CONTROL_STATUS_NOT_READY);
        return ServiceControlIngressStatus::Ok;
    }

    if (request_copy.operation == DUET_SERVICE_CONTROL_OP_EXIT_DEQUEUE)
    {
        ServiceControlPlatformExitEventV1 event{};
        const ServiceControlPlatformStatusV1 platform_status =
            platform.exit_dequeue(platform.context, &runtime.authority, caller->process, &event);
        const AbiStatus mapped = MapPlatformStatus(platform_status);
        if (mapped != DUET_SERVICE_CONTROL_STATUS_OK)
        {
            SetStatus(result, mapped);
            return ServiceControlIngressStatus::Ok;
        }
        const AbiStatus event_status = ValidateExitEvent(runtime, event);
        if (event_status != DUET_SERVICE_CONTROL_STATUS_OK)
        {
            SetStatus(result, event_status);
            return ServiceControlIngressStatus::Ok;
        }
        ServiceRowView current{};
        const AbiStatus found =
            FindServiceByIdentity(runtime, event.instance.start.transition.service_identity, &current);
        if (found != DUET_SERVICE_CONTROL_STATUS_OK)
        {
            SetStatus(result, found);
            return ServiceControlIngressStatus::Ok;
        }
        result->flags = DUET_SERVICE_CONTROL_RESULT_HAS_SERVICE | DUET_SERVICE_CONTROL_RESULT_HAS_EXIT_EVENT;
        if (event.failed)
            result->flags |= DUET_SERVICE_CONTROL_RESULT_EXIT_FAILED;
        result->service_index = current.index;
        result->service_count = runtime.broker.service_count;
        result->phase = static_cast<u8>(event.failed ? ServiceTransitionPhase::Failed : ServiceTransitionPhase::Exited);
        result->exit_failed = event.failed ? 1 : 0;
        result->broker_epoch = event.instance.start.broker_epoch;
        result->service_identity = event.instance.start.transition.service_identity;
        result->transition_generation = event.instance.start.transition.generation;
        result->process_identity = event.instance.process.process_identity;
        result->pid = event.instance.process.pid;
        result->operation_token = event.acknowledgement_token;
        result->event_sequence = event.event_sequence;
        result->exit_status = event.exit_status;
        SetStatus(result, DUET_SERVICE_CONTROL_STATUS_OK);
        return ServiceControlIngressStatus::Ok;
    }

    if (request_copy.operation == DUET_SERVICE_CONTROL_OP_EXIT_ACK)
    {
        if (request_copy.broker_epoch != runtime.broker.broker_epoch)
        {
            SetStatus(result, DUET_SERVICE_CONTROL_STATUS_STALE);
            return ServiceControlIngressStatus::Ok;
        }
        ServiceRowView current{};
        const AbiStatus found = FindServiceByIdentity(runtime, request_copy.service_identity, &current);
        if (found != DUET_SERVICE_CONTROL_STATUS_OK)
        {
            SetStatus(result, found);
            return ServiceControlIngressStatus::Ok;
        }
        const ServiceControlPlatformStatusV1 platform_status =
            platform.exit_ack(platform.context, &runtime.authority, caller->process, PlatformTarget(request_copy),
                              request_copy.operation_token);
        const AbiStatus mapped = MapPlatformStatus(platform_status);
        FillServiceResult(runtime, current, result);
        result->operation_token = request_copy.operation_token;
        result->event_sequence = request_copy.event_sequence;
        SetStatus(result, mapped);
        return ServiceControlIngressStatus::Ok;
    }

    ServiceRowView service{};
    const AbiStatus found = FindServiceByIdentity(runtime, request_copy.service_identity, &service);
    if (found != DUET_SERVICE_CONTROL_STATUS_OK)
    {
        SetStatus(result, found);
        return ServiceControlIngressStatus::Ok;
    }
    FillServiceResult(runtime, service, result);
    if (!RequestMatchesService(request_copy, runtime, service, false))
    {
        SetStatus(result, DUET_SERVICE_CONTROL_STATUS_STALE);
        return ServiceControlIngressStatus::Ok;
    }

    ServiceControlPlatformStatusV1 platform_status = ServiceControlPlatformStatusV1::InternalError;
    switch (request_copy.operation)
    {
    case DUET_SERVICE_CONTROL_OP_ACTIVATE:
        if (service.snapshot.transition_generation == kServiceTransitionGenerationMaximum ||
            service.snapshot.phase == ServiceTransitionPhase::GenerationExhausted)
        {
            SetStatus(result, DUET_SERVICE_CONTROL_STATUS_GENERATION_EXHAUSTED);
            return ServiceControlIngressStatus::Ok;
        }
        if (service.snapshot.phase == ServiceTransitionPhase::Starting ||
            service.snapshot.phase == ServiceTransitionPhase::Running ||
            service.snapshot.phase == ServiceTransitionPhase::Stopping)
        {
            SetStatus(result, DUET_SERVICE_CONTROL_STATUS_ALREADY_REQUESTED);
            return ServiceControlIngressStatus::Ok;
        }
        platform_status =
            platform.activate(platform.context, &runtime.authority, caller->process, PlatformTarget(request_copy));
        break;
    case DUET_SERVICE_CONTROL_OP_STOP:
        if (service.snapshot.phase == ServiceTransitionPhase::Starting)
        {
            if (!ProcessIsEmpty(RequestProcess(request_copy)))
            {
                SetStatus(result, DUET_SERVICE_CONTROL_STATUS_STALE);
                return ServiceControlIngressStatus::Ok;
            }
        }
        else if (service.snapshot.phase == ServiceTransitionPhase::Running ||
                 service.snapshot.phase == ServiceTransitionPhase::Stopping)
        {
            if (!RequestMatchesService(request_copy, runtime, service, true))
            {
                SetStatus(result, DUET_SERVICE_CONTROL_STATUS_STALE);
                return ServiceControlIngressStatus::Ok;
            }
        }
        else
        {
            SetStatus(result, DUET_SERVICE_CONTROL_STATUS_ALREADY_STOPPED);
            return ServiceControlIngressStatus::Ok;
        }
        platform_status =
            platform.stop(platform.context, &runtime.authority, caller->process, PlatformTarget(request_copy));
        break;
    case DUET_SERVICE_CONTROL_OP_RESTAGE:
        if (service.snapshot.phase != ServiceTransitionPhase::Exited &&
            service.snapshot.phase != ServiceTransitionPhase::Failed &&
            service.snapshot.phase != ServiceTransitionPhase::Stopped)
        {
            SetStatus(result, DUET_SERVICE_CONTROL_STATUS_NOT_READY);
            return ServiceControlIngressStatus::Ok;
        }
        platform_status =
            platform.restage(platform.context, &runtime.authority, caller->process, PlatformTarget(request_copy));
        break;
    default:
        SetStatus(result, DUET_SERVICE_CONTROL_STATUS_UNSUPPORTED);
        return ServiceControlIngressStatus::Ok;
    }

    const AbiStatus mapped = MapPlatformStatus(platform_status);
    if (mapped == DUET_SERVICE_CONTROL_STATUS_OK)
    {
        const AbiStatus refreshed = RefreshServiceResult(runtime, request_copy.service_identity, result);
        if (refreshed != DUET_SERVICE_CONTROL_STATUS_OK)
        {
            SetStatus(result, refreshed);
            return ServiceControlIngressStatus::Ok;
        }
    }
    SetStatus(result, mapped);
    return ServiceControlIngressStatus::Ok;
}

#if !defined(DUETOS_HOST_TEST)
ServiceControlIngressStatus ServiceControlIngressInitializeKernel()
{
    return ServiceControlIngressInitialize(&g_kernel_service_control_ingress);
}

ServiceControlIngressStatus ServiceControlIngressInstallKernelPlatformV1(
    const ServiceControlIngressPlatformV1* platform)
{
    return ServiceControlIngressInstallPlatformV1(&g_kernel_service_control_ingress, platform);
}

void DoServiceControl(arch::TrapFrame* frame)
{
    if (frame == nullptr)
        return;
    if (frame->rdi == 0 || frame->rdx == 0 || frame->rsi != sizeof(duet_service_control_request_v1) ||
        frame->r10 != sizeof(duet_service_control_result_v1))
    {
        frame->rax = static_cast<u64>(kSysErrnoEINVAL);
        return;
    }

    duet_service_control_request_v1 request{};
    if (!mm::CopyFromUser(&request, reinterpret_cast<const void*>(frame->rdi), sizeof(request)))
    {
        frame->rax = static_cast<u64>(kSysErrnoEFAULT);
        return;
    }
    if (request.struct_size != sizeof(request))
    {
        frame->rax = static_cast<u64>(kSysErrnoEINVAL);
        return;
    }

    Process* process = CurrentProcess();
    if (process == nullptr)
    {
        frame->rax = static_cast<u64>(kSysErrnoEACCES);
        return;
    }

    // The exact writable mapping is reserved before any lifecycle callback can
    // mutate state. Input was already snapshotted, so request/result aliasing is
    // safe and a racing unmap cannot turn successful mutation into lost output.
    mm::AddressSpaceWriteLease output_lease{};
    const mm::AddressSpaceWriteLeaseStatus lease_status = mm::AddressSpaceAcquireWriteLease(
        process->as, frame->rdx, sizeof(duet_service_control_result_v1), &output_lease);
    if (lease_status != mm::AddressSpaceWriteLeaseStatus::Ok)
    {
        frame->rax =
            static_cast<u64>(lease_status == mm::AddressSpaceWriteLeaseStatus::CapacityExhausted ? kSysErrnoEAGAIN
                             : lease_status == mm::AddressSpaceWriteLeaseStatus::TokenExhausted ||
                                     lease_status == mm::AddressSpaceWriteLeaseStatus::CorruptState
                                 ? kSysErrnoENOMEM
                                 : kSysErrnoEFAULT);
        return;
    }
    DUETOS_DEFER((void)mm::AddressSpaceReleaseWriteLease(&output_lease));

    const ServiceControlIngressCaller caller{
        ProcessKeySnapshot(process),
        ProcessCapsSnapshot(process),
        ServiceRuntimeKernelV1(),
    };
    duet_service_control_result_v1 result{};
    const ServiceControlIngressStatus executed =
        ServiceControlIngressExecute(&g_kernel_service_control_ingress, &caller, &request, &result);
    if (executed != ServiceControlIngressStatus::Ok)
    {
        frame->rax = static_cast<u64>(executed == ServiceControlIngressStatus::NotInitialized ? kSysErrnoENODEV
                                                                                              : kSysErrnoEINVAL);
        return;
    }
    if (!mm::AddressSpaceCopyToWriteLease(output_lease, 0, &result, sizeof(result)))
    {
        frame->rax = static_cast<u64>(kSysErrnoEFAULT);
        return;
    }
    frame->rax = 0;
}
#endif

const char* ServiceControlIngressStatusName(ServiceControlIngressStatus status)
{
    switch (status)
    {
    case ServiceControlIngressStatus::Ok:
        return "Ok";
    case ServiceControlIngressStatus::InvalidArgument:
        return "InvalidArgument";
    case ServiceControlIngressStatus::AlreadyInitialized:
        return "AlreadyInitialized";
    case ServiceControlIngressStatus::NotInitialized:
        return "NotInitialized";
    case ServiceControlIngressStatus::PlatformAlreadyInstalled:
        return "PlatformAlreadyInstalled";
    case ServiceControlIngressStatus::CorruptState:
        return "CorruptState";
    }
    return "Unknown";
}

} // namespace duetos::core
