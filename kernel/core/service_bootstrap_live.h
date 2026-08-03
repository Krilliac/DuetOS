#pragma once

/*
 * Live boot anchor for the authority-bound service package, v1.
 *
 * This owner gives the generated package and ServiceRuntimeV1 real kernel
 * lifetime without crossing the service activation boundary.  Initialize is
 * [boot task, single-threaded, one shot] and runs only after the frame
 * allocator, C++ init array, and managed paging are online.  Inspection is
 * read-only after the terminal state is published.
 *
 * RuntimeOpenCompatibilityRequired is intentionally not named Ready: the
 * generated package still has ActivationReady=false, no Process/Task exists,
 * and no endpoint is registered.  The compatibility service manager remains
 * the sole live launcher until that marker and the corresponding runtime gates
 * become truthful.
 */

#include "core/service_bootstrap_stage.h"
#include "core/service_runtime.h"
#include "util/types.h"

namespace duetos::core
{

enum class ServiceControlPlatformAdapterStatusV1 : u8;

inline constexpr u32 kServiceBootstrapLiveVersion1 = 1;

// Build-frozen capacity for the currently generated package.  Growth is an
// explicit source change, not an accidental multi-megabyte BSS expansion.
inline constexpr u32 kServiceBootstrapLiveServiceCapacityV1 = 5;
inline constexpr u64 kServiceBootstrapLiveImageBytesPerServiceV1 = 64ULL * 1024ULL;
inline constexpr u32 kServiceBootstrapLivePagesPerServiceV1 =
    static_cast<u32>(kServiceBootstrapLiveImageBytesPerServiceV1 / loader::kLoadPlanPageSize);
inline constexpr u32 kServiceBootstrapLiveRegionsPerServiceV1 = 8;
inline constexpr u64 kServiceBootstrapLiveTotalArtifactByteCapacityV1 = 256ULL * 1024ULL;
inline constexpr u32 kServiceBootstrapLiveBanksPerServiceV1 = 2;
static_assert(kServiceBootstrapLiveBanksPerServiceV1 == kServiceBootstrapStageBankCapacityV1);

enum class ServiceBootstrapLiveStateV1 : u32
{
    Uninitialized = 0,
    Initializing,
    RuntimeOpenCompatibilityRequired,
    Failed,
};

enum class ServiceBootstrapLiveStatusV1 : u8
{
    CompatibilityRequired = 0,
    NullArgument,
    AlreadyAttempted,
    GeneratedPackageCountMismatch,
    StageFailed,
    RuntimeFailed,
    RuntimeFailedStageDiscardFailed,
    ServiceControlPlatformFailed,
    NotInitialized,
    Busy,
    CorruptState,
};

// A caller may assert TeardownComplete only after the old Process and its
// AddressSpace mapping ledger have been destroyed.  The proof is a stricter
// supervisor/single-instance policy, not frame ownership: after LoadImage
// transfer, the target ledger is already the sole frame owner and resetting a
// retired bank clears observer metadata without freeing or reusing frames.
enum class ServiceBootstrapLiveRetiredTargetTeardownV1 : u8
{
    NotConfirmed = 0,
    TeardownComplete,
};

enum class ServiceBootstrapLiveRestageStatusV1 : u8
{
    Ok = 0,
    NullArgument,
    NotInitialized,
    Busy,
    StageRejected,
    RetiredTargetTeardownRequired,
    RetiredBankNotResettable,
    CorruptState,
};

struct ServiceBootstrapLiveResultV1
{
    ServiceBootstrapLiveStatusV1 status;
    ServiceBootstrapStageResultV1 stage;
    ServiceRuntimeInitializeResultV1 runtime;
    ServiceControlPlatformAdapterStatusV1 platform_status;
    ServiceBootstrapStageStatus discard_status;
    u32 generated_service_count;
    u32 package_owned_pages;
};

struct ServiceBootstrapLiveSnapshotV1
{
    ServiceBootstrapLiveStateV1 state;
    ServiceBootstrapLiveStatusV1 status;
    u16 reserved16;
    u32 version;
    u32 fixed_service_capacity;
    u32 generated_service_count;
    u32 staged_service_count;
    u32 package_owned_pages;
    u32 allocation_count;
    u32 release_count;
    u64 stage_registry_identity;
    u8 activation_ready;
    u8 compatibility_required;
    u8 process_count;
    u8 published_endpoint_count;
    u8 banks_per_service;
    u8 active_bank_indices[kServiceBootstrapLiveServiceCapacityV1];
    u8 reserved8[2];
};

struct ServiceBootstrapLiveRestageResultV1
{
    ServiceBootstrapLiveRestageStatusV1 status;
    u8 previous_active_bank;
    u8 active_bank;
    u8 reserved8;
    u32 service_index;
    ServiceBootstrapStageResultV1 stage;
    loader::LoadImageStatus retired_image_status;
    loader::ExecAdmissionStatus retired_admission_status;
};

#if !defined(DUETOS_HOST_TEST)
// Anchor the generated package and static ServiceRuntime owner, then install
// the dormant service-control ingress over that exact authority.  Success is
// reported as CompatibilityRequired because no service is activated.
ServiceBootstrapLiveResultV1 ServiceBootstrapLiveInitializeV1();

// Returns a coherent terminal snapshot.  Initializing is reported as
// NotInitialized rather than exposing partially written storage.
ServiceBootstrapLiveStatusV1 ServiceBootstrapLiveInspectV1(ServiceBootstrapLiveSnapshotV1* snapshot_out);

// [service-control owner, serialized internally]
// Restage one exact terminal service into its inactive permanent bank.  A
// retired bank with TargetOwned observer records is reusable only when the
// supervisor supplies TeardownComplete for the old Process/AddressSpace.  A
// pristine bank needs no such assertion.  Every failure keeps the active-bank
// selector and published stage row unchanged; success flips the selector only
// after ServiceBootstrapStageRestageV1 commits.
ServiceBootstrapLiveRestageResultV1 ServiceBootstrapLiveRestageV1(
    u64 service_identity, u64 expected_activation_generation,
    ServiceBootstrapLiveRetiredTargetTeardownV1 retired_target_teardown);
#endif

const char* ServiceBootstrapLiveStatusNameV1(ServiceBootstrapLiveStatusV1 status);
const char* ServiceBootstrapLiveRestageStatusNameV1(ServiceBootstrapLiveRestageStatusV1 status);

} // namespace duetos::core
