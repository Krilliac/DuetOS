#include "core/service_bootstrap_activation.h"

#include "fs/ramfs.h"
#include "mm/frame_allocator.h"
#include "mm/page.h"
#include "mm/paging.h"
#include "proc/spawn.h"

#if !defined(DUETOS_HOST_TEST)
#include "core/panic.h"
#endif

namespace duetos::core
{

namespace
{

#if !defined(DUETOS_HOST_TEST)
struct ServiceBootstrapActivationPlatformV1
{
    void* context;
    mm::AddressSpace* (*create_address_space)(void*, u64);
    void (*release_address_space)(void*, mm::AddressSpace*);
    bool (*reserve_user_range)(void*, mm::AddressSpace*, u64, u64, mm::AddressSpaceReservationToken*);
    bool (*allocate_frame)(void*, mm::PhysAddr*);
    void (*zero_frame)(void*, mm::PhysAddr);
    void (*free_frame)(void*, mm::PhysAddr);
    bool (*map_reserved_user_page)(void*, mm::AddressSpace*, const mm::AddressSpaceReservationToken&, u64, mm::PhysAddr,
                                   u64);
    bool (*map_image_owned_frame)(void*, mm::AddressSpace*, u64, mm::PhysAddr, u64);
    bool (*unmap_image_owned_frame_exact)(void*, mm::AddressSpace*, u64, mm::PhysAddr);
    const fs::RamfsNode* (*trusted_root)(void*);
    Process* (*create_process)(void*, const char*, mm::AddressSpace*, CapSet, const fs::RamfsNode*, u64, u64, u64,
                               CapSet);
    void (*release_process)(void*, Process*);
    bool (*snapshot_process_identity)(void*, Process*, ProcessKey*, ServiceEndpointCredentialSnapshot*);
    bool (*configure_process_stack)(void*, Process*, const UserStackRange&, u64);
    bool (*replace_resource_domain)(void*, Process*, ResourceDomainKey);
    bool (*install_publication_gate)(void*, Process*, ProcessPublicationGate, void*);
    void (*prepare_owned_user_stack)(void*, sched::Task*, const UserStackRange&,
                                     const mm::AddressSpaceReservationToken&);
    sched::TaskCreateResult (*create_user_task_prepared)(void*, const char*, Process*, sched::TaskPrepareFn, void*);
};
#endif

bool HashEquals(const loader::Hash256& left, const loader::Hash256& right)
{
    u8 difference = 0;
    for (u32 index = 0; index < sizeof(left.bytes); ++index)
        difference |= left.bytes[index] ^ right.bytes[index];
    return difference == 0;
}

ServiceBootstrapActivationResultV1 ActivationResult(ServiceBootstrapActivationStatusV1 status)
{
    ServiceBootstrapActivationResultV1 result{};
    result.status = status;
    result.runtime_status = ServiceRuntimeStatusV1::Ok;
    result.stage_status = ServiceBootstrapStageStatus::Ok;
    result.package_result = ServiceObjectPackageResult{ServiceObjectPackageStatus::Ok, ServiceManifestError::Ok,
                                                       kServiceObjectPackageNoObjectIndex};
    result.lifecycle_status = ServiceLifecycleStatus::Ok;
    result.lifecycle_cleanup_status = ServiceLifecycleStatus::Ok;
    result.lifecycle_publication_rollback_status = ServiceLifecycleStatus::Ok;
    result.directory_status = ServiceDirectoryStatus::Ok;
    result.directory_cleanup_status = ServiceDirectoryStatus::Ok;
    result.exit_observer_status = ServiceExitObserverStatus::Ok;
    result.exit_observer_cleanup_status = ServiceExitObserverStatus::Ok;
    result.image_map_result =
        loader::LoadImageMapResult{loader::LoadImageStatus::Ok, loader::LoadPlanValidationError::Ok, 0, 0, 0};
    result.task = sched::TaskCreateResult{false, 0};
    result.instance = kInvalidServiceLifecycleInstanceToken;
    result.directory_service = kInvalidServiceKey;
    return result;
}

bool PlatformIsComplete(const ServiceBootstrapActivationPlatformV1* platform)
{
    return platform != nullptr && platform->create_address_space != nullptr &&
           platform->release_address_space != nullptr && platform->reserve_user_range != nullptr &&
           platform->allocate_frame != nullptr && platform->zero_frame != nullptr && platform->free_frame != nullptr &&
           platform->map_reserved_user_page != nullptr && platform->map_image_owned_frame != nullptr &&
           platform->unmap_image_owned_frame_exact != nullptr && platform->trusted_root != nullptr &&
           platform->create_process != nullptr && platform->release_process != nullptr &&
           platform->snapshot_process_identity != nullptr && platform->configure_process_stack != nullptr &&
           platform->replace_resource_domain != nullptr && platform->install_publication_gate != nullptr &&
           platform->prepare_owned_user_stack != nullptr && platform->create_user_task_prepared != nullptr;
}

struct ImageMapContext
{
    const ServiceBootstrapActivationPlatformV1* platform;
    mm::AddressSpace* address_space;
};

u64 PageFlagsForProtection(loader::VmProtection protection)
{
    const u32 bits = static_cast<u32>(protection);
    u64 flags = mm::kPagePresent | mm::kPageUser;
    if ((bits & static_cast<u32>(loader::VmProtection::Write)) != 0)
        flags |= mm::kPageWritable;
    if ((bits & static_cast<u32>(loader::VmProtection::Execute)) == 0)
        flags |= mm::kPageNoExecute;
    return flags;
}

bool MapImageOwnedFrame(void* raw_context, u64 virtual_address, loader::LoadImageFrame frame,
                        loader::VmProtection protection)
{
    auto* context = static_cast<ImageMapContext*>(raw_context);
    if (context == nullptr || context->platform == nullptr || context->address_space == nullptr ||
        frame == loader::kLoadImageInvalidFrame)
    {
        return false;
    }
    return context->platform->map_image_owned_frame(context->platform->context, context->address_space, virtual_address,
                                                    static_cast<mm::PhysAddr>(frame),
                                                    PageFlagsForProtection(protection));
}

bool UnmapImageOwnedFrameExact(void* raw_context, u64 virtual_address, loader::LoadImageFrame expected_frame)
{
    auto* context = static_cast<ImageMapContext*>(raw_context);
    if (context == nullptr || context->platform == nullptr || context->address_space == nullptr ||
        expected_frame == loader::kLoadImageInvalidFrame)
    {
        return false;
    }
    return context->platform->unmap_image_owned_frame_exact(context->platform->context, context->address_space,
                                                            virtual_address, static_cast<mm::PhysAddr>(expected_frame));
}

struct PublicationContext
{
    ServiceLifecycleBroker* broker;
    ServiceExitObserver* exit_observer;
    ServiceDirectory* directory;
    ServiceExitRegistration* exit_registration;
    bool* exit_registration_owned;
    ServiceRegistrationReservation* directory_registration;
    bool* directory_registration_owned;
    ServiceLifecycleStartTicket ticket;
    ProcessKey expected_process;
    u64 now_ns;
    bool invoked;
    ServiceExitObserverStatus bind_status;
    ServiceExitObserverStatus rollback_status;
    ServiceLifecycleDirectoryPublicationResult result;
};

bool CommitLifecyclePublication(ProcessKey process, void* raw_context)
{
    auto* context = static_cast<PublicationContext*>(raw_context);
    if (context == nullptr || context->broker == nullptr || context->exit_observer == nullptr ||
        context->directory == nullptr || context->exit_registration == nullptr ||
        context->exit_registration_owned == nullptr || context->directory_registration == nullptr ||
        context->directory_registration_owned == nullptr || !*context->exit_registration_owned ||
        !*context->directory_registration_owned || context->invoked || !ProcessKeyIsValid(process) ||
        !(process == context->expected_process))
    {
        return false;
    }
    context->invoked = true;
    context->bind_status = ServiceExitObserverBindAtSchedulerPublication(
        context->exit_observer, *context->exit_registration, process, *context->directory_registration);
    if (context->bind_status != ServiceExitObserverStatus::Ok)
        return false;

    // The joint primitive subsumes ServiceLifecycleBrokerCommitPublication so
    // the broker lock remains held through the lower-ranked directory commit.
    context->result = ServiceLifecycleBrokerCommitDirectoryPublication(
        context->broker, context->ticket, ServiceInstanceKey{process.identity, process.pid}, context->now_ns,
        context->directory, context->directory_registration);
    if (context->result.lifecycle_status != ServiceLifecycleStatus::Ok ||
        context->result.directory_status != ServiceDirectoryStatus::Ok)
    {
        context->rollback_status =
            ServiceExitObserverRollbackBound(context->exit_observer, context->exit_registration, process);
        *context->exit_registration_owned = false;
#if !defined(DUETOS_HOST_TEST)
        KASSERT(context->rollback_status == ServiceExitObserverStatus::Ok, "service-bootstrap",
                "rejected lifecycle publication could not roll back exact bound exit observer");
#endif
        return false;
    }
    *context->directory_registration_owned = false;
    *context->exit_registration_owned = false;
    return true;
}

struct TaskPrepareContext
{
    const ServiceBootstrapActivationPlatformV1* platform;
    UserStackRange stack;
    mm::AddressSpaceReservationToken reservation;
};

void PrepareOwnedStack(sched::Task* task, void* raw_context)
{
    auto* context = static_cast<TaskPrepareContext*>(raw_context);
    if (context == nullptr || context->platform == nullptr)
        return;
    context->platform->prepare_owned_user_stack(context->platform->context, task, context->stack, context->reservation);
}

ServiceLifecycleStatus RetirePrivateLifecycle(ServiceLifecycleBroker* broker, ServiceLifecycleStartTicket ticket,
                                              u64 now_ns)
{
    const ServiceLifecycleStatus failed = ServiceLifecycleBrokerRecordSpawnFailure(broker, ticket, now_ns);
    if (failed == ServiceLifecycleStatus::StartRetirementPending)
        return ServiceLifecycleBrokerAcknowledgeCancelledStart(broker, ticket, now_ns);
    return failed;
}

bool BrokerMatchesManifest(const ServiceLifecycleBrokerSnapshot& broker, const ServiceManifestPlanV1& plan,
                           const ServiceManifestAuthoritySnapshotV1& authority)
{
    return broker.service_count == plan.document.service_count &&
           broker.dependency_count == plan.document.dependency_count &&
           broker.manifest_identity == plan.document.manifest_identity &&
           broker.manifest_authority_identity == authority.authority_identity &&
           HashEquals(broker.manifest_object_hash, plan.sealed_object_hash) &&
           HashEquals(broker.manifest_object_hash, authority.sealed_object_hash) &&
           broker.manifest_object_extent == plan.sealed_object_extent &&
           broker.manifest_object_extent == authority.sealed_object_extent;
}

const ServiceManifestServiceV1* FindManifestService(const ServiceManifestPlanV1& plan, u64 service_identity,
                                                    u32* index_out)
{
    for (u32 index = 0; index < plan.document.service_count; ++index)
    {
        if (plan.document.services[index].service_identity == service_identity)
        {
            if (index_out != nullptr)
                *index_out = index;
            return &plan.document.services[index];
        }
    }
    return nullptr;
}

ServiceBootstrapActivationResultV1 ActivateWithPlatform(const ServiceBootstrapActivationRequestV1& request,
                                                        const ServiceBootstrapActivationPlatformV1* platform)
{
    ServiceBootstrapActivationResultV1 result = ActivationResult(ServiceBootstrapActivationStatusV1::Ok);
    if (request.runtime == nullptr || request.service_identity == 0 || !PlatformIsComplete(platform))
    {
        result.status = ServiceBootstrapActivationStatusV1::NullArgument;
        return result;
    }
    if (request.version != kServiceBootstrapActivationVersion1 || request.reserved != 0)
    {
        result.status = ServiceBootstrapActivationStatusV1::UnsupportedVersion;
        return result;
    }

    ServiceRuntimeActivationAuthorityV1 runtime_authority{};
    result.runtime_status = ServiceRuntimeBindActivationAuthorityV1(request.runtime, &runtime_authority);
    if (result.runtime_status != ServiceRuntimeStatusV1::Ok || runtime_authority.stage == nullptr ||
        runtime_authority.lifecycle == nullptr || runtime_authority.exit_observer == nullptr ||
        runtime_authority.directory == nullptr)
    {
        result.status = ServiceBootstrapActivationStatusV1::RuntimeRejected;
        return result;
    }
    ServiceBootstrapStageRuntimeV1* const stage = runtime_authority.stage;
    ServiceLifecycleBroker* const broker = runtime_authority.lifecycle;
    ServiceExitObserver* const exit_observer = runtime_authority.exit_observer;
    ServiceDirectory* const directory = runtime_authority.directory;

    ServiceBootstrapStageSnapshotV1 stage_snapshot{};
    result.stage_status = ServiceBootstrapStageInspectV1(stage, &stage_snapshot);
    if (result.stage_status != ServiceBootstrapStageStatus::Ok)
    {
        result.status = ServiceBootstrapActivationStatusV1::StageRejected;
        return result;
    }
    ServiceObjectPackageManifestV1 manifest{};
    result.package_result = ServiceObjectPackageGetManifestV1(&stage->package, &manifest);
    if (result.package_result.status != ServiceObjectPackageStatus::Ok || manifest.plan == nullptr ||
        manifest.authority == nullptr)
    {
        result.status = ServiceBootstrapActivationStatusV1::ManifestUnavailable;
        return result;
    }
    const ServiceLifecycleBrokerInspectResult broker_description = ServiceLifecycleBrokerDescribe(broker);
    result.lifecycle_status = broker_description.status;
    if (broker_description.status != ServiceLifecycleStatus::Ok ||
        !BrokerMatchesManifest(broker_description.snapshot, *manifest.plan, *manifest.authority) ||
        stage_snapshot.authority_identity != manifest.authority->authority_identity ||
        runtime_authority.manifest_identity != manifest.plan->document.manifest_identity ||
        runtime_authority.manifest_authority_identity != manifest.authority->authority_identity ||
        !HashEquals(runtime_authority.manifest_object_hash, manifest.plan->sealed_object_hash) ||
        runtime_authority.manifest_object_extent != manifest.plan->sealed_object_extent ||
        runtime_authority.stage_registry_identity != stage_snapshot.registry_identity)
    {
        result.status = ServiceBootstrapActivationStatusV1::BrokerManifestMismatch;
        return result;
    }

    u32 manifest_index = kServiceBootstrapNoServiceIndex;
    const ServiceManifestServiceV1* service =
        FindManifestService(*manifest.plan, request.service_identity, &manifest_index);
    ServiceBootstrapServiceSnapshotV1 staged_service{};
    result.stage_status = ServiceBootstrapStageFindServiceV1(stage, request.service_identity, &staged_service);
    ServiceExecutableTransferSnapshotV1 transfer{};
    if (service == nullptr || result.stage_status != ServiceBootstrapStageStatus::Ok ||
        staged_service.manifest_index != manifest_index || staged_service.executable_transfer_ref == 0 ||
        staged_service.executable_transfer_ref != service->executable_transfer_ref ||
        !HashEquals(staged_service.expected_source_hash, service->executable_content_hash))
    {
        result.status = ServiceBootstrapActivationStatusV1::ServiceBindingMismatch;
        return result;
    }
    result.package_result = ServiceObjectPackageResolveExecutableV1(&stage->package, service->service_identity,
                                                                    service->executable_transfer_ref, &transfer);
    if (result.package_result.status != ServiceObjectPackageStatus::Ok ||
        !HashEquals(transfer.content_hash, staged_service.expected_source_hash))
    {
        result.status = ServiceBootstrapActivationStatusV1::ServiceBindingMismatch;
        return result;
    }
    if ((service->kind != ServiceManifestKind::Native && service->kind != ServiceManifestKind::Broker) ||
        service->resource_profile != ServiceManifestResourceProfile::AuthenticatedService ||
        service->requested_section_objects == 0 ||
        service->requested_section_objects > kAuthenticatedServiceSectionObjectLimit ||
        service->requested_section_pages == 0 ||
        service->requested_section_pages > kAuthenticatedServiceSectionPageLimit)
    {
        result.status = ServiceBootstrapActivationStatusV1::UnsupportedServicePolicy;
        return result;
    }

    ServiceDirectoryName directory_name{};
    directory_name.length = service->name_length;
    for (u32 index = 0; index < service->name_length; ++index)
        directory_name.bytes[index] = service->name[index];
    if (!ServiceDirectoryNameIsCanonical(directory_name))
    {
        result.status = ServiceBootstrapActivationStatusV1::DirectoryNameInvalid;
        return result;
    }
    constexpr u64 kInitialStackPages = kUserStackCommitMinPages;
    if (service->requested_frame_budget_pages < kInitialStackPages ||
        staged_service.admitted_plan.header.entry_point == 0 ||
        staged_service.activation_state != ServiceBootstrapActivationStateV1::Staged ||
        stage->rows[manifest_index].frame_allocations > service->requested_frame_budget_pages - kInitialStackPages)
    {
        result.status = ServiceBootstrapActivationStatusV1::ResourceBudgetExceeded;
        return result;
    }

    ServiceBootstrapActivationLeaseV1 lease{};
    result.stage_status = ServiceBootstrapStageBeginActivationV1(stage, request.service_identity, &lease);
    if (result.stage_status != ServiceBootstrapStageStatus::Ok)
    {
        result.status = ServiceBootstrapActivationStatusV1::StageRejected;
        return result;
    }

    ServiceLifecycleStartTicket lifecycle_ticket = kInvalidServiceLifecycleStartTicket;
    bool lifecycle_owned = false;
    ServiceExitRegistration exit_registration = kInvalidServiceExitRegistration;
    bool exit_registration_owned = false;
    ServiceRegistrationReservation directory_registration = kInvalidServiceRegistrationReservation;
    bool directory_registration_owned = false;
    ServiceInstanceToken directory_owner = kInvalidServiceInstanceToken;
    ResourceDomainKey domain = kInvalidResourceDomainKey;
    bool domain_owned = false;
    mm::AddressSpace* address_space = nullptr;
    bool address_space_owned = false;
    Process* process = nullptr;
    bool process_owned = false;

    auto fail = [&](ServiceBootstrapActivationStatusV1 failure, bool image_consumed)
    {
        if (directory_registration_owned)
        {
            result.directory_cleanup_status =
                ServiceDirectoryAbortRegistration(directory, &directory_registration, directory_owner);
            directory_registration_owned = false;
            if (result.directory_cleanup_status != ServiceDirectoryStatus::Ok)
                failure = ServiceBootstrapActivationStatusV1::DirectoryCleanupFailed;
        }
        if (exit_registration_owned)
        {
            result.exit_observer_cleanup_status = ServiceExitObserverAbort(exit_observer, &exit_registration);
            exit_registration_owned = false;
            if (result.exit_observer_cleanup_status != ServiceExitObserverStatus::Ok)
                failure = ServiceBootstrapActivationStatusV1::ExitObserverCleanupFailed;
        }
        if (process_owned)
        {
            platform->release_process(platform->context, process);
            process_owned = false;
            process = nullptr;
        }
        else if (address_space_owned)
        {
            platform->release_address_space(platform->context, address_space);
            address_space_owned = false;
            address_space = nullptr;
        }
        if (domain_owned)
        {
            ResourceDomainRelease(domain);
            domain_owned = false;
        }
        if (lifecycle_owned)
        {
            result.lifecycle_cleanup_status = RetirePrivateLifecycle(broker, lifecycle_ticket, request.now_ns);
            lifecycle_owned = false;
            if (result.lifecycle_cleanup_status != ServiceLifecycleStatus::Ok)
                failure = ServiceBootstrapActivationStatusV1::LifecycleCleanupFailed;
        }
        result.stage_status = image_consumed
                                  ? ServiceBootstrapStageFinishActivationV1(
                                        stage, lease.receipt, ServiceBootstrapActivationOutcomeV1::ConsumedFailed)
                                  : ServiceBootstrapStageCancelActivationV1(stage, lease.receipt);
        if (result.stage_status != ServiceBootstrapStageStatus::Ok)
            failure = ServiceBootstrapActivationStatusV1::StageFinalizeFailed;
        result.status = failure;
        return result;
    };

    const ServiceLifecycleStartResult lifecycle = ServiceLifecycleBrokerReserveStartWithDependencies(
        broker, request.service_identity, request.expected_transition_generation, request.now_ns);
    result.lifecycle_status = lifecycle.status;
    if (lifecycle.status != ServiceLifecycleStatus::Ok)
        return fail(ServiceBootstrapActivationStatusV1::LifecycleReserveRejected, false);
    lifecycle_ticket = lifecycle.ticket;
    lifecycle_owned = true;

    const ServiceExitReservationResult exit_reservation = ServiceExitObserverReserve(exit_observer, lifecycle_ticket);
    result.exit_observer_status = exit_reservation.status;
    if (exit_reservation.status != ServiceExitObserverStatus::Ok)
        return fail(ServiceBootstrapActivationStatusV1::ExitObserverReserveRejected, false);
    exit_registration = exit_reservation.registration;
    exit_registration_owned = true;

    if (!ResourceDomainCreateBoundedAuthenticatedService(service->requested_section_objects,
                                                         service->requested_section_pages, &domain))
    {
        return fail(ServiceBootstrapActivationStatusV1::ResourceDomainCreateFailed, false);
    }
    domain_owned = true;

    address_space = platform->create_address_space(platform->context, service->requested_frame_budget_pages);
    if (address_space == nullptr)
        return fail(ServiceBootstrapActivationStatusV1::AddressSpaceCreateFailed, false);
    address_space_owned = true;

    result.stack = UserStackPlan(kUserStackReserveMin, kInitialStackPages * mm::kPageSize, nullptr);
    if (!UserStackRangeIsValid(result.stack) || result.stack.top - result.stack.reserve_lo != kUserStackReserveMin ||
        result.stack.top - result.stack.commit_lo != kInitialStackPages * mm::kPageSize)
    {
        return fail(ServiceBootstrapActivationStatusV1::StackPlanInvalid, false);
    }
    mm::AddressSpaceReservationToken stack_reservation{};
    if (!platform->reserve_user_range(platform->context, address_space, result.stack.guard_lo, result.stack.top,
                                      &stack_reservation))
    {
        return fail(ServiceBootstrapActivationStatusV1::StackReservationFailed, false);
    }
    for (u64 page = result.stack.commit_lo; page < result.stack.top; page += mm::kPageSize)
    {
        mm::PhysAddr frame = mm::kNullFrame;
        if (!platform->allocate_frame(platform->context, &frame) || frame == mm::kNullFrame)
            return fail(ServiceBootstrapActivationStatusV1::StackFrameAllocationFailed, false);
        platform->zero_frame(platform->context, frame);
        if (!platform->map_reserved_user_page(platform->context, address_space, stack_reservation, page, frame,
                                              mm::kPagePresent | mm::kPageUser | mm::kPageWritable |
                                                  mm::kPageNoExecute))
        {
            platform->free_frame(platform->context, frame);
            return fail(ServiceBootstrapActivationStatusV1::StackMapFailed, false);
        }
    }

    ImageMapContext image_context{platform, address_space};
    const loader::LoadImageMapHooks map_hooks{&image_context, &MapImageOwnedFrame, &UnmapImageOwnedFrameExact};
    result.image_map_result = loader::LoadImageMapInto(lease.image, map_hooks);
    if (result.image_map_result.status != loader::LoadImageStatus::Ok)
        return fail(ServiceBootstrapActivationStatusV1::ImageMapFailed,
                    lease.image->state != loader::LoadImageState::Sealed);

    const fs::RamfsNode* root = platform->trusted_root(platform->context);
    if (root == nullptr)
        return fail(ServiceBootstrapActivationStatusV1::TrustedRootUnavailable, true);

    char service_name[kServiceManifestServiceNameCapacity + 1]{};
    for (u32 index = 0; index < service->name_length; ++index)
        service_name[index] = static_cast<char>(service->name[index]);
    const CapSet caps{service->requested_capability_ceiling};
    process = platform->create_process(platform->context, service_name, address_space, caps, root,
                                       staged_service.admitted_plan.header.entry_point, result.stack.commit_lo,
                                       service->requested_tick_budget, caps);
    if (process == nullptr)
        return fail(ServiceBootstrapActivationStatusV1::ProcessCreateFailed, true);
    address_space_owned = false;
    process_owned = true;
    address_space = nullptr;

    if (!platform->configure_process_stack(platform->context, process, result.stack, result.stack.top - 8))
        return fail(ServiceBootstrapActivationStatusV1::ProcessConfigurationFailed, true);
    if (!platform->replace_resource_domain(platform->context, process, domain))
        return fail(ServiceBootstrapActivationStatusV1::ResourceDomainReplaceFailed, true);
    ResourceDomainRelease(domain);
    domain_owned = false;

    ProcessKey private_process = kInvalidProcessKey;
    ServiceEndpointCredentialSnapshot process_credential{};
    if (!platform->snapshot_process_identity(platform->context, process, &private_process, &process_credential) ||
        !ProcessKeyIsValid(private_process) || !ServiceEndpointCredentialSnapshotIsCanonical(process_credential))
    {
        return fail(ServiceBootstrapActivationStatusV1::ProcessCredentialSnapshotFailed, true);
    }
    directory_owner = ServiceInstanceToken{
        lifecycle_ticket.transition,
        ServiceInstanceKey{private_process.identity, private_process.pid},
    };
    const ServiceDirectoryReserveResult directory_reservation = ServiceDirectoryReserveRegistration(
        directory, &directory_name, manifest_index, directory_owner, &process_credential);
    result.directory_status = directory_reservation.status;
    if (directory_reservation.status != ServiceDirectoryStatus::Ok)
        return fail(ServiceBootstrapActivationStatusV1::DirectoryReserveRejected, true);
    directory_registration = directory_reservation.reservation;
    directory_registration_owned = true;
    result.directory_service = directory_registration.service;

    PublicationContext publication{broker,
                                   exit_observer,
                                   directory,
                                   &exit_registration,
                                   &exit_registration_owned,
                                   &directory_registration,
                                   &directory_registration_owned,
                                   lifecycle_ticket,
                                   private_process,
                                   request.now_ns,
                                   false,
                                   ServiceExitObserverStatus::Busy,
                                   ServiceExitObserverStatus::Ok,
                                   ServiceLifecycleDirectoryPublicationResult{ServiceLifecycleStatus::Busy,
                                                                              ServiceDirectoryStatus::Ok,
                                                                              kInvalidServiceLifecycleInstanceToken}};
    if (!platform->install_publication_gate(platform->context, process, &CommitLifecyclePublication, &publication))
        return fail(ServiceBootstrapActivationStatusV1::PublicationGateInstallFailed, true);

    TaskPrepareContext task_prepare{platform, result.stack, stack_reservation};
    result.task = platform->create_user_task_prepared(platform->context, service_name, process, &PrepareOwnedStack,
                                                      &task_prepare);
    process_owned = false; // create_user_task_prepared consumes the Process reference on every path.
    process = nullptr;
    if (!result.task.created)
    {
        result.lifecycle_status =
            publication.invoked ? publication.result.lifecycle_status : ServiceLifecycleStatus::Busy;
        result.directory_status = publication.invoked ? publication.result.directory_status : result.directory_status;
        if (publication.invoked && publication.result.directory_status != ServiceDirectoryStatus::Ok)
            result.lifecycle_publication_rollback_status = publication.result.lifecycle_status;
        result.exit_observer_status = publication.invoked ? publication.bind_status : ServiceExitObserverStatus::Ok;
        result.exit_observer_cleanup_status = publication.rollback_status;
        const bool lifecycle_rollback_failed = publication.invoked &&
                                               publication.result.directory_status != ServiceDirectoryStatus::Ok &&
                                               publication.result.lifecycle_status != ServiceLifecycleStatus::Ok;
        const bool observer_rollback_failed = publication.invoked &&
                                              publication.bind_status == ServiceExitObserverStatus::Ok &&
                                              (publication.result.lifecycle_status != ServiceLifecycleStatus::Ok ||
                                               publication.result.directory_status != ServiceDirectoryStatus::Ok) &&
                                              publication.rollback_status != ServiceExitObserverStatus::Ok;
        return fail(lifecycle_rollback_failed  ? ServiceBootstrapActivationStatusV1::LifecyclePublicationRollbackFailed
                    : observer_rollback_failed ? ServiceBootstrapActivationStatusV1::ExitObserverCleanupFailed
                    : publication.invoked && publication.result.directory_status != ServiceDirectoryStatus::Ok
                        ? ServiceBootstrapActivationStatusV1::DirectoryPublicationRejected
                    : publication.invoked ? ServiceBootstrapActivationStatusV1::PublicationRejected
                                          : ServiceBootstrapActivationStatusV1::TaskCreateFailed,
                    true);
    }
    if (!publication.invoked || publication.bind_status != ServiceExitObserverStatus::Ok ||
        publication.result.lifecycle_status != ServiceLifecycleStatus::Ok ||
        publication.result.directory_status != ServiceDirectoryStatus::Ok ||
        !ServiceLifecycleInstanceTokenIsValid(publication.result.instance) ||
        !(publication.result.instance.start == lifecycle_ticket) ||
        publication.result.instance.process.process_identity != private_process.identity ||
        publication.result.instance.process.pid != private_process.pid || exit_registration_owned ||
        directory_registration_owned || ServiceRegistrationReservationIsValid(directory_registration) ||
        !ServiceKeyIsValid(result.directory_service))
    {
        result.status = ServiceBootstrapActivationStatusV1::CorruptTransaction;
        return result;
    }
    lifecycle_owned = false;
    result.exit_observer_status = publication.bind_status;
    result.lifecycle_status = publication.result.lifecycle_status;
    result.directory_status = publication.result.directory_status;
    result.instance = publication.result.instance;
    result.stage_status = ServiceBootstrapStageFinishActivationV1(
        stage, lease.receipt, ServiceBootstrapActivationOutcomeV1::TransferredPublished);
#if !defined(DUETOS_HOST_TEST)
    KASSERT(result.stage_status == ServiceBootstrapStageStatus::Ok, "service-bootstrap",
            "published service could not commit exact stage receipt");
#endif
    if (result.stage_status != ServiceBootstrapStageStatus::Ok)
    {
        result.status = ServiceBootstrapActivationStatusV1::CorruptTransaction;
        return result;
    }
    result.status = ServiceBootstrapActivationStatusV1::Ok;
    return result;
}

#if !defined(DUETOS_HOST_TEST)
mm::AddressSpace* ProductionCreateAddressSpace(void*, u64 budget)
{
    auto created = mm::AddressSpaceCreate(budget);
    return created.has_value() ? created.value() : nullptr;
}

void ProductionReleaseAddressSpace(void*, mm::AddressSpace* address_space)
{
    mm::AddressSpaceRelease(address_space);
}

bool ProductionReserveRange(void*, mm::AddressSpace* address_space, u64 lo, u64 hi,
                            mm::AddressSpaceReservationToken* token_out)
{
    return mm::AddressSpaceReserveUserRange(address_space, lo, hi, token_out);
}

bool ProductionAllocateFrame(void*, mm::PhysAddr* frame_out)
{
    if (frame_out == nullptr)
        return false;
    auto frame = mm::AllocateFrame();
    if (!frame)
        return false;
    *frame_out = frame.value();
    return true;
}

void ProductionZeroFrame(void*, mm::PhysAddr frame)
{
    auto* bytes = static_cast<u8*>(mm::PhysToVirt(frame));
    for (u64 index = 0; index < mm::kPageSize; ++index)
        bytes[index] = 0;
}

void ProductionFreeFrame(void*, mm::PhysAddr frame)
{
    mm::FreeFrame(frame);
}

bool ProductionMapReserved(void*, mm::AddressSpace* address_space, const mm::AddressSpaceReservationToken& token,
                           u64 virtual_address, mm::PhysAddr frame, u64 flags)
{
    return mm::AddressSpaceMapReservedUserPage(address_space, token, virtual_address, frame, flags);
}

bool ProductionMapImage(void*, mm::AddressSpace* address_space, u64 virtual_address, mm::PhysAddr frame, u64 flags)
{
    return mm::AddressSpaceMapUserPage(address_space, virtual_address, frame, flags);
}

bool ProductionUnmapImageExact(void*, mm::AddressSpace* address_space, u64 virtual_address, mm::PhysAddr expected_frame)
{
    return mm::AddressSpaceLookupUserFrame(address_space, virtual_address) == expected_frame &&
           mm::AddressSpaceUnmapUserPage(address_space, virtual_address);
}

const fs::RamfsNode* ProductionTrustedRoot(void*)
{
    return fs::RamfsTrustedRoot();
}

Process* ProductionCreateProcess(void*, const char* name, mm::AddressSpace* address_space, CapSet caps,
                                 const fs::RamfsNode* root, u64 entry_point, u64 stack_base, u64 tick_budget,
                                 CapSet ceiling)
{
    return ProcessCreate(name, address_space, caps, root, entry_point, stack_base, tick_budget, ceiling);
}

void ProductionReleaseProcess(void*, Process* process)
{
    ProcessRelease(process);
}

bool ProductionSnapshotProcessIdentity(void*, Process* process, ProcessKey* process_out,
                                       ServiceEndpointCredentialSnapshot* credential_out)
{
    if (process == nullptr || process_out == nullptr || credential_out == nullptr ||
        ProcessLifecycleLoad(process) != ProcessLifecycleState::Private)
    {
        return false;
    }
    *process_out = kInvalidProcessKey;
    *credential_out = {};

    CredentialSnapshot credential{};
    if (!ProcessInspectCredentials(process, &credential))
        return false;
    const ServiceEndpointCredentialSnapshot snapshot{ProcessCredentialKeySnapshot(process), credential.security};
    const ProcessKey key = ProcessKeySnapshot(process);
    if (!ProcessKeyIsValid(key) || !ServiceEndpointCredentialSnapshotIsCanonical(snapshot))
        return false;
    *process_out = key;
    *credential_out = snapshot;
    return true;
}

bool ProductionConfigureStack(void*, Process* process, const UserStackRange& stack, u64 initial_rsp)
{
    if (process == nullptr || ProcessLifecycleLoad(process) != ProcessLifecycleState::Private)
        return false;
    process->stack = stack;
    process->user_rsp_init = initial_rsp;
    return true;
}

bool ProductionReplaceDomain(void*, Process* process, ResourceDomainKey replacement)
{
    return ProcessReplaceResourceDomainBeforePublish(process, replacement);
}

bool ProductionInstallGate(void*, Process* process, ProcessPublicationGate gate, void* context)
{
    return ProcessInstallPublicationGateBeforePublish(process, gate, context);
}

void ProductionPrepareStack(void*, sched::Task* task, const UserStackRange& stack,
                            const mm::AddressSpaceReservationToken& token)
{
    sched::SchedPrepareOwnedUserStack(task, stack, token);
}

sched::TaskCreateResult ProductionCreateTask(void*, const char* name, Process* process, sched::TaskPrepareFn prepare,
                                             void* prepare_context)
{
    return sched::SchedCreateUserPrepared(&Ring3UserEntry, nullptr, name, process, prepare, prepare_context);
}

const ServiceBootstrapActivationPlatformV1 kProductionPlatform{
    nullptr,
    &ProductionCreateAddressSpace,
    &ProductionReleaseAddressSpace,
    &ProductionReserveRange,
    &ProductionAllocateFrame,
    &ProductionZeroFrame,
    &ProductionFreeFrame,
    &ProductionMapReserved,
    &ProductionMapImage,
    &ProductionUnmapImageExact,
    &ProductionTrustedRoot,
    &ProductionCreateProcess,
    &ProductionReleaseProcess,
    &ProductionSnapshotProcessIdentity,
    &ProductionConfigureStack,
    &ProductionReplaceDomain,
    &ProductionInstallGate,
    &ProductionPrepareStack,
    &ProductionCreateTask,
};
#endif

} // namespace

#if !defined(DUETOS_HOST_TEST)
ServiceBootstrapActivationResultV1 ServiceBootstrapActivateV1(const ServiceBootstrapActivationRequestV1& request)
{
    return ActivateWithPlatform(request, &kProductionPlatform);
}
#else
ServiceBootstrapActivationResultV1 ServiceBootstrapActivateWithPlatformForTestV1(
    const ServiceBootstrapActivationRequestV1& request, const ServiceBootstrapActivationPlatformV1* platform)
{
    return ActivateWithPlatform(request, platform);
}
#endif

const char* ServiceBootstrapActivationStatusNameV1(ServiceBootstrapActivationStatusV1 status)
{
    switch (status)
    {
    case ServiceBootstrapActivationStatusV1::Ok:
        return "ok";
    case ServiceBootstrapActivationStatusV1::NullArgument:
        return "null-argument";
    case ServiceBootstrapActivationStatusV1::UnsupportedVersion:
        return "unsupported-version";
    case ServiceBootstrapActivationStatusV1::RuntimeRejected:
        return "runtime-rejected";
    case ServiceBootstrapActivationStatusV1::StageRejected:
        return "stage-rejected";
    case ServiceBootstrapActivationStatusV1::ManifestUnavailable:
        return "manifest-unavailable";
    case ServiceBootstrapActivationStatusV1::BrokerManifestMismatch:
        return "broker-manifest-mismatch";
    case ServiceBootstrapActivationStatusV1::ServiceBindingMismatch:
        return "service-binding-mismatch";
    case ServiceBootstrapActivationStatusV1::UnsupportedServicePolicy:
        return "unsupported-service-policy";
    case ServiceBootstrapActivationStatusV1::ResourceBudgetExceeded:
        return "resource-budget-exceeded";
    case ServiceBootstrapActivationStatusV1::LifecycleReserveRejected:
        return "lifecycle-reserve-rejected";
    case ServiceBootstrapActivationStatusV1::ExitObserverReserveRejected:
        return "exit-observer-reserve-rejected";
    case ServiceBootstrapActivationStatusV1::ResourceDomainCreateFailed:
        return "resource-domain-create-failed";
    case ServiceBootstrapActivationStatusV1::AddressSpaceCreateFailed:
        return "address-space-create-failed";
    case ServiceBootstrapActivationStatusV1::StackPlanInvalid:
        return "stack-plan-invalid";
    case ServiceBootstrapActivationStatusV1::StackReservationFailed:
        return "stack-reservation-failed";
    case ServiceBootstrapActivationStatusV1::StackFrameAllocationFailed:
        return "stack-frame-allocation-failed";
    case ServiceBootstrapActivationStatusV1::StackMapFailed:
        return "stack-map-failed";
    case ServiceBootstrapActivationStatusV1::ImageMapFailed:
        return "image-map-failed";
    case ServiceBootstrapActivationStatusV1::TrustedRootUnavailable:
        return "trusted-root-unavailable";
    case ServiceBootstrapActivationStatusV1::ProcessCreateFailed:
        return "process-create-failed";
    case ServiceBootstrapActivationStatusV1::ProcessConfigurationFailed:
        return "process-configuration-failed";
    case ServiceBootstrapActivationStatusV1::ProcessCredentialSnapshotFailed:
        return "process-credential-snapshot-failed";
    case ServiceBootstrapActivationStatusV1::ResourceDomainReplaceFailed:
        return "resource-domain-replace-failed";
    case ServiceBootstrapActivationStatusV1::DirectoryNameInvalid:
        return "directory-name-invalid";
    case ServiceBootstrapActivationStatusV1::DirectoryReserveRejected:
        return "directory-reserve-rejected";
    case ServiceBootstrapActivationStatusV1::PublicationGateInstallFailed:
        return "publication-gate-install-failed";
    case ServiceBootstrapActivationStatusV1::TaskCreateFailed:
        return "task-create-failed";
    case ServiceBootstrapActivationStatusV1::PublicationRejected:
        return "publication-rejected";
    case ServiceBootstrapActivationStatusV1::DirectoryPublicationRejected:
        return "directory-publication-rejected";
    case ServiceBootstrapActivationStatusV1::LifecyclePublicationRollbackFailed:
        return "lifecycle-publication-rollback-failed";
    case ServiceBootstrapActivationStatusV1::DirectoryCleanupFailed:
        return "directory-cleanup-failed";
    case ServiceBootstrapActivationStatusV1::ExitObserverCleanupFailed:
        return "exit-observer-cleanup-failed";
    case ServiceBootstrapActivationStatusV1::LifecycleCleanupFailed:
        return "lifecycle-cleanup-failed";
    case ServiceBootstrapActivationStatusV1::StageFinalizeFailed:
        return "stage-finalize-failed";
    case ServiceBootstrapActivationStatusV1::CorruptTransaction:
        return "corrupt-transaction";
    }
    return "unknown";
}

} // namespace duetos::core
