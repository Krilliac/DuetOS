#pragma once

/*
 * Publication-only authenticated boot-service activation, v1.
 *
 * This is a compiled-but-dormant transaction. It consumes one exact staged
 * image into a fresh private address space, constructs a Process under the
 * signed manifest ceilings, then atomically joins the exact ProcessKey,
 * exit-observer binding, lifecycle instance, and ServiceDirectory identity
 * inside the scheduler's first-Task publication critical section.
 * No live boot path calls it; publication deliberately leaves both lifecycle
 * and directory readiness false. It creates no endpoints, readiness signal,
 * restart policy, or service-manager loop.
 *
 * Ownership:
 *   - a successful call publishes one scheduler-owned Task/Process graph;
 *   - every prepublication failure destroys the private graph exactly once;
 *   - after LoadImageMapInto begins, target-owned frames are reclaimed only by
 *     unpublished AddressSpace/Process teardown, never LoadImageRelease;
 *   - the stage receipt is cancelled only while the image remains sealed,
 *     otherwise it is terminally recorded as ConsumedFailed.
 */

#include "core/service_runtime.h"
#include "mm/address_space.h"
#include "proc/process.h"
#include "proc/user_stack.h"
#include "sched/sched.h"

namespace duetos::fs
{
struct RamfsNode;
}

namespace duetos::core
{

inline constexpr u32 kServiceBootstrapActivationVersion1 = 1;

enum class ServiceBootstrapActivationStatusV1 : u8
{
    Ok = 0,
    NullArgument,
    UnsupportedVersion,
    RuntimeRejected,
    StageRejected,
    ManifestUnavailable,
    BrokerManifestMismatch,
    ServiceBindingMismatch,
    UnsupportedServicePolicy,
    ResourceBudgetExceeded,
    LifecycleReserveRejected,
    ExitObserverReserveRejected,
    ResourceDomainCreateFailed,
    AddressSpaceCreateFailed,
    StackPlanInvalid,
    StackReservationFailed,
    StackFrameAllocationFailed,
    StackMapFailed,
    ImageMapFailed,
    TrustedRootUnavailable,
    ProcessCreateFailed,
    ProcessConfigurationFailed,
    ProcessCredentialSnapshotFailed,
    ResourceDomainReplaceFailed,
    DirectoryNameInvalid,
    DirectoryReserveRejected,
    PublicationGateInstallFailed,
    TaskCreateFailed,
    PublicationRejected,
    DirectoryPublicationRejected,
    LifecyclePublicationRollbackFailed,
    DirectoryCleanupFailed,
    ExitObserverCleanupFailed,
    LifecycleCleanupFailed,
    StageFinalizeFailed,
    CorruptTransaction,
};

struct ServiceBootstrapActivationRequestV1
{
    u32 version;
    u32 reserved;
    // Sole authority root. Stage, broker, observer, endpoint owner, directory,
    // and manifest authority are derived and revalidated from this one fixed-
    // lifetime runtime; callers cannot mix peer components.
    ServiceRuntimeV1* runtime;
    u64 service_identity;
    u64 expected_transition_generation;
    u64 now_ns;
};

struct ServiceBootstrapActivationResultV1
{
    ServiceBootstrapActivationStatusV1 status;
    ServiceRuntimeStatusV1 runtime_status;
    ServiceBootstrapStageStatus stage_status;
    ServiceObjectPackageResult package_result;
    ServiceLifecycleStatus lifecycle_status;
    ServiceLifecycleStatus lifecycle_cleanup_status;
    ServiceLifecycleStatus lifecycle_publication_rollback_status;
    ServiceDirectoryStatus directory_status;
    ServiceDirectoryStatus directory_cleanup_status;
    ServiceExitObserverStatus exit_observer_status;
    ServiceExitObserverStatus exit_observer_cleanup_status;
    loader::LoadImageMapResult image_map_result;
    sched::TaskCreateResult task;
    ServiceLifecycleInstanceToken instance;
    ServiceKey directory_service;
    UserStackRange stack;
};

#if !defined(DUETOS_HOST_TEST)
// [boot task, task context, compiled but currently uncalled]
ServiceBootstrapActivationResultV1 ServiceBootstrapActivateV1(const ServiceBootstrapActivationRequestV1& request);
#else
// Host-only fault-injection seam. Production callers cannot select platform
// operations; ServiceBootstrapActivateV1 is hard-wired to the kernel APIs.
struct ServiceBootstrapActivationPlatformV1
{
    void* context;
    mm::AddressSpace* (*create_address_space)(void* context, u64 frame_budget_pages);
    void (*release_address_space)(void* context, mm::AddressSpace* address_space);
    bool (*reserve_user_range)(void* context, mm::AddressSpace* address_space, u64 lo, u64 hi,
                               mm::AddressSpaceReservationToken* token_out);
    bool (*allocate_frame)(void* context, mm::PhysAddr* frame_out);
    void (*zero_frame)(void* context, mm::PhysAddr frame);
    void (*free_frame)(void* context, mm::PhysAddr frame);
    bool (*map_reserved_user_page)(void* context, mm::AddressSpace* address_space,
                                   const mm::AddressSpaceReservationToken& token, u64 virtual_address,
                                   mm::PhysAddr frame, u64 flags);
    bool (*map_image_owned_frame)(void* context, mm::AddressSpace* address_space, u64 virtual_address,
                                  mm::PhysAddr frame, u64 flags);
    bool (*unmap_image_owned_frame_exact)(void* context, mm::AddressSpace* address_space, u64 virtual_address,
                                          mm::PhysAddr expected_frame);
    const fs::RamfsNode* (*trusted_root)(void* context);
    Process* (*create_process)(void* context, const char* name, mm::AddressSpace* address_space, CapSet caps,
                               const fs::RamfsNode* root, u64 entry_point, u64 stack_base, u64 tick_budget,
                               CapSet capability_ceiling);
    void (*release_process)(void* context, Process* process);
    bool (*snapshot_process_identity)(void* context, Process* process, ProcessKey* process_out,
                                      ServiceEndpointCredentialSnapshot* credential_out);
    bool (*configure_process_stack)(void* context, Process* process, const UserStackRange& stack, u64 initial_rsp);
    bool (*replace_resource_domain)(void* context, Process* process, ResourceDomainKey replacement);
    bool (*install_publication_gate)(void* context, Process* process, ProcessPublicationGate gate, void* gate_context);
    void (*prepare_owned_user_stack)(void* context, sched::Task* task, const UserStackRange& stack,
                                     const mm::AddressSpaceReservationToken& token);
    sched::TaskCreateResult (*create_user_task_prepared)(void* context, const char* name, Process* process,
                                                         sched::TaskPrepareFn prepare, void* prepare_context);
};

ServiceBootstrapActivationResultV1 ServiceBootstrapActivateWithPlatformForTestV1(
    const ServiceBootstrapActivationRequestV1& request, const ServiceBootstrapActivationPlatformV1* platform);
#endif

const char* ServiceBootstrapActivationStatusNameV1(ServiceBootstrapActivationStatusV1 status);

} // namespace duetos::core
