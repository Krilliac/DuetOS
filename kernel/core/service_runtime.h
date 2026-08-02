#pragma once

/*
 * Static-lifetime kernel owner for the extracted service runtime, v1.
 *
 * The staging package remains owned by its boot storage.  This object owns the
 * independently synchronized lifecycle broker, exact process-exit observer,
 * endpoint pool, authenticated directory, and durable exit-reap ledger that
 * consume that package.  It does not choose restart policy, parse user
 * messages, start a Process, or publish readiness.  Those are later adapters
 * over this owner.
 *
 * Initialization is a boot-only, one-shot transaction.  A failure after a
 * component becomes live leaves the complete owner terminally Failed and
 * unpublished; it is never reset or retried in place.  The production kernel
 * singleton installs its embedded exit observer only after every other
 * component is ready, and exposes the singleton only after that install.
 */

#include "core/service_bootstrap_stage.h"
#include "core/service_directory.h"
#include "core/service_exit_observer.h"
#include "core/service_exit_reap_ledger.h"
#include "core/service_lifecycle_broker.h"
#include "util/types.h"

namespace duetos::core
{

inline constexpr u32 kServiceRuntimeVersion1 = 1;
inline constexpr u32 kServiceRuntimeInitializedMarkerV1 = 0x53525631U; // "SRV1"

enum class ServiceRuntimeStateV1 : u32
{
    Uninitialized = 0,
    Initializing,
    Open,
    Failed,
};

enum class ServiceRuntimeStatusV1 : u8
{
    Ok = 0,
    NullArgument,
    NonCanonicalStorage,
    AlreadyInitialized,
    StageRejected,
    ManifestUnavailable,
    BrokerEpochExhausted,
    BrokerInitializeFailed,
    ExitObserverEpochExhausted,
    ExitObserverInitializeFailed,
    EndpointOwnerInitializeFailed,
    DirectoryInitializeFailed,
    ExitReapLedgerInitializeFailed,
    ExitObserverInstallFailed,
    NotInitialized,
    Failed,
    CorruptState,
};

// Public only for one static boot-global allocation and hostile host tests.
// Treat every member as opaque after ServiceRuntimeInitializeForTestV1 or
// ServiceRuntimeInitializeKernelV1 begins.
struct ServiceRuntimeV1
{
    u32 initialized;
    u32 version;
    u32 state;
    u32 reserved;
    ServiceBootstrapStageRuntimeV1* stage;
    ServiceLifecycleBroker lifecycle;
    ServiceExitObserver exit_observer;
    ServiceEndpointOwner endpoint_owner;
    ServiceDirectory directory;
    ServiceExitReapLedger exit_reap_ledger;
};

struct ServiceRuntimeInitializeResultV1
{
    ServiceRuntimeStatusV1 status;
    ServiceBootstrapStageStatus stage_status;
    ServiceObjectPackageStatus package_status;
    ServiceManifestError manifest_error;
    ServiceLifecycleStatus lifecycle_status;
    ServiceExitObserverStatus exit_observer_status;
    ServiceEndpointStatus endpoint_status;
    ServiceDirectoryStatus directory_status;
    ServiceExitReapStatus exit_reap_status;
};

struct [[nodiscard]] ServiceRuntimeDeferAcceptedProcessResultV1
{
    ServiceRuntimeStatusV1 runtime_status;
    ServiceDirectoryStatus directory_status;
    u32 newly_deferred_channels;
    u32 deferred_channels;
};

struct [[nodiscard]] ServiceRuntimeDriveDeferredAcceptedResultV1
{
    ServiceRuntimeStatusV1 runtime_status;
    ServiceDirectoryStatus directory_status;
    ServiceEndpointStatus endpoint_status;
    u32 released_channels;
    u32 pending_channels;
};

struct ServiceRuntimeSnapshotV1
{
    ServiceRuntimeStateV1 state;
    u32 version;
    u32 service_count;
    u64 manifest_identity;
    u64 manifest_authority_identity;
    u64 broker_epoch;
    u64 observer_epoch;
    u64 observer_event_sequence;
    u32 exit_reap_live_rows;
    u64 stage_registry_identity;
};

// Value/pointer bundle exposed only after the single runtime owner and all of
// its independently synchronized components revalidate as one authority root.
// The pointers refer exclusively to members of `runtime`; callers must not
// substitute peer objects from another runtime incarnation.
struct ServiceRuntimeActivationAuthorityV1
{
    ServiceBootstrapStageRuntimeV1* stage;
    ServiceLifecycleBroker* lifecycle;
    ServiceExitObserver* exit_observer;
    ServiceDirectory* directory;
    ServiceExitReapLedger* exit_reap_ledger;
    u64 manifest_identity;
    u64 manifest_authority_identity;
    loader::Hash256 manifest_object_hash;
    u64 manifest_object_extent;
    u64 stage_registry_identity;
};

#if !defined(DUETOS_HOST_TEST)
// Initialize and publish the sole static-lifetime kernel owner.  The stage and
// all of its caller-owned storage must remain valid for the life of the kernel.
// [boot task, single-threaded, one shot]
ServiceRuntimeInitializeResultV1 ServiceRuntimeInitializeKernelV1(ServiceBootstrapStageRuntimeV1* stage);

// Returns nullptr until the complete owner, including the global exit-observer
// route, has been published Open.  The returned storage has kernel lifetime.
ServiceRuntimeV1* ServiceRuntimeKernelV1();

// Transfer every accepted endpoint owner for an exact exiting Process into
// durable in-directory deferred state. NotInitialized is returned only before
// the singleton is published, when accepted owners cannot exist. Once Ok is
// returned, generic Process handle teardown may proceed.
// [task context, no scheduler/runtime-admission lock held]
ServiceRuntimeDeferAcceptedProcessResultV1 ServiceRuntimeDeferAcceptedProcessKernelV1(ProcessKey process);

// Drive one fair, bounded global batch from scheduler maintenance context.
// Busy retains every exact owner row for a later pass.
// [task context, no scheduler/Process/runtime-admission lock held]
ServiceRuntimeDriveDeferredAcceptedResultV1 ServiceRuntimeDriveDeferredAcceptedKernelV1();
#else
// Host-only detached initialization.  It exercises the exact component
// transaction but deliberately cannot mutate the production global observer.
ServiceRuntimeInitializeResultV1 ServiceRuntimeInitializeForTestV1(ServiceRuntimeV1* runtime,
                                                                   ServiceBootstrapStageRuntimeV1* stage);

ServiceRuntimeDeferAcceptedProcessResultV1 ServiceRuntimeDeferAcceptedProcessForTestV1(ServiceRuntimeV1* runtime,
                                                                                       ProcessKey process);
ServiceRuntimeDriveDeferredAcceptedResultV1 ServiceRuntimeDriveDeferredAcceptedForTestV1(ServiceRuntimeV1* runtime);
#endif

ServiceRuntimeStatusV1 ServiceRuntimeInspectV1(const ServiceRuntimeV1* runtime, ServiceRuntimeSnapshotV1* snapshot_out);

// Resolve the sole activation authority. This validates the stage, manifest,
// broker, observer, endpoint owner, and directory composition before exposing
// any member pointer. No lifecycle or directory row is mutated.
ServiceRuntimeStatusV1 ServiceRuntimeBindActivationAuthorityV1(ServiceRuntimeV1* runtime,
                                                               ServiceRuntimeActivationAuthorityV1* authority_out);
const char* ServiceRuntimeStatusNameV1(ServiceRuntimeStatusV1 status);

} // namespace duetos::core
