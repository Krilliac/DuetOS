#include "core/service_bootstrap_live.h"
#include "core/service_control_platform.h"

#if !defined(DUETOS_HOST_TEST)
#include "mm/frame_allocator.h"
#include "mm/page.h"
#include "service-package/generated_boot_service_package_data.h"
#endif

namespace duetos::core
{
namespace
{

#if !defined(DUETOS_HOST_TEST)

static_assert(generated::kBootServicePackageArtifactsResolved);
static_assert(generated::kBootServicePackageAuthorityBound);
static_assert(generated::kBootServicePackageBootstrapPlansBound);
static_assert(!generated::kBootServicePackageProcessPublicationBound);
static_assert(!generated::kBootServicePackageEndpointReadinessBound);
static_assert(!generated::kBootServicePackageActivationReady);
static_assert(generated::kBootServicePackageArtifactCount == kServiceBootstrapLiveServiceCapacityV1);
static_assert(generated::kBootServicePackageTotalArtifactBytes <= kServiceBootstrapLiveTotalArtifactByteCapacityV1);
static_assert(kServiceBootstrapLiveImageBytesPerServiceV1 % loader::kLoadPlanPageSize == 0);

struct ServiceBootstrapLiveStorageV1
{
    u32 state;
    u32 operation_busy;
    u32 version;
    u32 last_status;
    u32 generated_service_count;
    u32 allocation_count;
    u32 release_count;
    ServiceBootstrapStageRuntimeV1 stage;
    loader::LoadImage images[kServiceBootstrapLiveServiceCapacityV1][kServiceBootstrapLiveBanksPerServiceV1];
    loader::LoadImagePage pages[kServiceBootstrapLiveServiceCapacityV1][kServiceBootstrapLiveBanksPerServiceV1]
                               [kServiceBootstrapLivePagesPerServiceV1];
    loader::LoadImageRegionAuthority regions[kServiceBootstrapLiveServiceCapacityV1]
                                            [kServiceBootstrapLiveBanksPerServiceV1]
                                            [kServiceBootstrapLiveRegionsPerServiceV1];
    alignas(8) u8 plan_storage[kServiceBootstrapLiveServiceCapacityV1][kServiceBootstrapLiveBanksPerServiceV1]
                              [loader::kLoadImageMaxPlanBytes];
    loader::ExecAdmission admissions[kServiceBootstrapLiveServiceCapacityV1][kServiceBootstrapLiveBanksPerServiceV1];
    alignas(8) u8 admission_storage[kServiceBootstrapLiveServiceCapacityV1][kServiceBootstrapLiveBanksPerServiceV1]
                                   [loader::kExecAdmissionMaxPlanBytes];
    u8 active_bank_indices[kServiceBootstrapLiveServiceCapacityV1];
};

constinit ServiceBootstrapLiveStorageV1 g_service_bootstrap_live{};

u32 LiveStateLoad()
{
    return __atomic_load_n(&g_service_bootstrap_live.state, __ATOMIC_ACQUIRE);
}

void LiveStateStore(ServiceBootstrapLiveStateV1 state)
{
    __atomic_store_n(&g_service_bootstrap_live.state, static_cast<u32>(state), __ATOMIC_RELEASE);
}

bool BeginOneShotInitialize()
{
    u32 expected = static_cast<u32>(ServiceBootstrapLiveStateV1::Uninitialized);
    return __atomic_compare_exchange_n(&g_service_bootstrap_live.state, &expected,
                                       static_cast<u32>(ServiceBootstrapLiveStateV1::Initializing), false,
                                       __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
}

bool BeginOwnerOperation()
{
    u32 expected = 0;
    return __atomic_compare_exchange_n(&g_service_bootstrap_live.operation_busy, &expected, 1u, false, __ATOMIC_ACQ_REL,
                                       __ATOMIC_ACQUIRE);
}

void EndOwnerOperation()
{
    __atomic_store_n(&g_service_bootstrap_live.operation_busy, 0u, __ATOMIC_RELEASE);
}

class LiveOwnerOperationGuard
{
  public:
    LiveOwnerOperationGuard() : m_acquired(BeginOwnerOperation()) {}
    ~LiveOwnerOperationGuard()
    {
        if (m_acquired)
            EndOwnerOperation();
    }

    LiveOwnerOperationGuard(const LiveOwnerOperationGuard&) = delete;
    LiveOwnerOperationGuard& operator=(const LiveOwnerOperationGuard&) = delete;
    bool Acquired() const { return m_acquired; }

  private:
    bool m_acquired;
};

bool AllocateLiveFrame(void*, loader::LoadImageFrame* frame_out, u8** writable_page_out)
{
    if (frame_out != nullptr)
        *frame_out = loader::kLoadImageInvalidFrame;
    if (writable_page_out != nullptr)
        *writable_page_out = nullptr;
    if (frame_out == nullptr || writable_page_out == nullptr)
        return false;

    const auto allocated = mm::AllocateFrame();
    if (!allocated.has_value())
        return false;
    const mm::PhysAddr frame = allocated.value();
    if (frame == mm::kNullFrame)
        return false;

    *frame_out = frame;
    *writable_page_out = static_cast<u8*>(mm::PhysToVirt(frame));
    ++g_service_bootstrap_live.allocation_count;
    return true;
}

void ReleaseLiveFrame(void*, loader::LoadImageFrame frame)
{
    if (frame == loader::kLoadImageInvalidFrame)
        return;
    mm::FreeFrame(frame);
    ++g_service_bootstrap_live.release_count;
}

ServiceBootstrapSlotStorageV1 BuildSlotDescriptor(u32 service_index, u32 bank_index)
{
    return ServiceBootstrapSlotStorageV1{
        &g_service_bootstrap_live.images[service_index][bank_index],
        loader::LoadImageFrameHooks{nullptr, &AllocateLiveFrame, &ReleaseLiveFrame},
        g_service_bootstrap_live.pages[service_index][bank_index],
        kServiceBootstrapLivePagesPerServiceV1,
        g_service_bootstrap_live.regions[service_index][bank_index],
        kServiceBootstrapLiveRegionsPerServiceV1,
        g_service_bootstrap_live.plan_storage[service_index][bank_index],
        loader::kLoadImageMaxPlanBytes,
        &g_service_bootstrap_live.admissions[service_index][bank_index],
        g_service_bootstrap_live.admission_storage[service_index][bank_index],
        loader::kExecAdmissionMaxPlanBytes,
        0,
    };
}

void BuildInitialSlotDescriptors(ServiceBootstrapSlotStorageV1* slots)
{
    for (u32 index = 0; index < kServiceBootstrapLiveServiceCapacityV1; ++index)
        slots[index] = BuildSlotDescriptor(index, 0);
}

bool LiveBankTopologyIsCanonical()
{
    if (g_service_bootstrap_live.stage.service_count > kServiceBootstrapLiveServiceCapacityV1)
        return false;

    for (u32 index = 0; index < g_service_bootstrap_live.stage.service_count; ++index)
    {
        const u8 active_bank = g_service_bootstrap_live.active_bank_indices[index];
        const ServiceBootstrapStageRowV1& row = g_service_bootstrap_live.stage.rows[index];
        if (active_bank >= kServiceBootstrapLiveBanksPerServiceV1 || row.active_bank_index != active_bank ||
            row.image != &g_service_bootstrap_live.images[index][active_bank] ||
            row.admission != &g_service_bootstrap_live.admissions[index][active_bank])
        {
            return false;
        }
    }
    return true;
}

bool CountPackageOwnedPages(u32* count_out)
{
    if (count_out == nullptr)
        return false;
    *count_out = 0;
    if (g_service_bootstrap_live.stage.service_count > kServiceBootstrapLiveServiceCapacityV1)
        return false;

    for (u32 index = 0; index < g_service_bootstrap_live.stage.service_count; ++index)
    {
        for (u32 bank = 0; bank < kServiceBootstrapLiveBanksPerServiceV1; ++bank)
        {
            loader::LoadImageSnapshot image{};
            if (loader::LoadImageInspect(&g_service_bootstrap_live.images[index][bank], &image) !=
                    loader::LoadImageStatus::Ok ||
                image.package_owned_pages > kServiceBootstrapLivePagesPerServiceV1 ||
                *count_out > kServiceBootstrapLiveServiceCapacityV1 * kServiceBootstrapLiveBanksPerServiceV1 *
                                     kServiceBootstrapLivePagesPerServiceV1 -
                                 image.package_owned_pages)
            {
                *count_out = 0;
                return false;
            }
            *count_out += image.package_owned_pages;
        }
    }
    return true;
}

ServiceBootstrapLiveRestageResultV1 RestageResult(ServiceBootstrapLiveRestageStatusV1 status)
{
    ServiceBootstrapLiveRestageResultV1 result{};
    result.status = status;
    result.previous_active_bank = kServiceBootstrapNoBankIndexV1;
    result.active_bank = kServiceBootstrapNoBankIndexV1;
    result.service_index = kServiceBootstrapNoServiceIndex;
    result.stage.status = ServiceBootstrapStageStatus::NotReady;
    result.retired_image_status = loader::LoadImageStatus::InvalidArgument;
    result.retired_admission_status = loader::ExecAdmissionStatus::InvalidArgument;
    return result;
}

#endif

} // namespace

#if !defined(DUETOS_HOST_TEST)

ServiceBootstrapLiveResultV1 ServiceBootstrapLiveInitializeV1()
{
    ServiceBootstrapLiveResultV1 result{};
    result.status = ServiceBootstrapLiveStatusV1::AlreadyAttempted;
    result.platform_status = ServiceControlPlatformAdapterStatusV1::NullArgument;
    result.discard_status = ServiceBootstrapStageStatus::Ok;
    if (!BeginOneShotInitialize())
        return result;

    g_service_bootstrap_live.version = kServiceBootstrapLiveVersion1;
    g_service_bootstrap_live.generated_service_count = ServiceBootstrapGeneratedServiceCountV1();
    result.generated_service_count = g_service_bootstrap_live.generated_service_count;
    if (result.generated_service_count != kServiceBootstrapLiveServiceCapacityV1)
    {
        result.status = ServiceBootstrapLiveStatusV1::GeneratedPackageCountMismatch;
        g_service_bootstrap_live.last_status = static_cast<u32>(result.status);
        LiveStateStore(ServiceBootstrapLiveStateV1::Failed);
        return result;
    }

    ServiceBootstrapSlotStorageV1 slots[kServiceBootstrapLiveServiceCapacityV1]{};
    BuildInitialSlotDescriptors(slots);
    result.stage = ServiceBootstrapStageGeneratedV1(&g_service_bootstrap_live.stage, slots,
                                                    kServiceBootstrapLiveServiceCapacityV1);
    if (result.stage.status != ServiceBootstrapStageStatus::Ok)
    {
        result.status = ServiceBootstrapLiveStatusV1::StageFailed;
        g_service_bootstrap_live.last_status = static_cast<u32>(result.status);
        LiveStateStore(ServiceBootstrapLiveStateV1::Failed);
        return result;
    }
    for (u32 index = 0; index < result.generated_service_count; ++index)
        g_service_bootstrap_live.active_bank_indices[index] = 0;

    result.runtime = ServiceRuntimeInitializeKernelV1(&g_service_bootstrap_live.stage);
    if (result.runtime.status != ServiceRuntimeStatusV1::Ok)
    {
        result.discard_status = ServiceBootstrapStageDiscardV1(&g_service_bootstrap_live.stage);
        result.status = result.discard_status == ServiceBootstrapStageStatus::Ok
                            ? ServiceBootstrapLiveStatusV1::RuntimeFailed
                            : ServiceBootstrapLiveStatusV1::RuntimeFailedStageDiscardFailed;
        if (result.discard_status != ServiceBootstrapStageStatus::Ok)
            (void)CountPackageOwnedPages(&result.package_owned_pages);
        g_service_bootstrap_live.last_status = static_cast<u32>(result.status);
        LiveStateStore(ServiceBootstrapLiveStateV1::Failed);
        return result;
    }

    ServiceRuntimeV1* runtime = ServiceRuntimeKernelV1();
    ServiceRuntimeSnapshotV1 runtime_snapshot{};
    if (runtime == nullptr || ServiceRuntimeInspectV1(runtime, &runtime_snapshot) != ServiceRuntimeStatusV1::Ok ||
        !LiveBankTopologyIsCanonical() || !CountPackageOwnedPages(&result.package_owned_pages) ||
        runtime_snapshot.service_count != result.generated_service_count)
    {
        // The runtime may already have installed the process-exit route.  It
        // cannot be reset or have its borrowed stage discarded after Open.
        result.status = ServiceBootstrapLiveStatusV1::CorruptState;
        g_service_bootstrap_live.last_status = static_cast<u32>(result.status);
        LiveStateStore(ServiceBootstrapLiveStateV1::Failed);
        return result;
    }

    result.status = ServiceBootstrapLiveStatusV1::CompatibilityRequired;
    g_service_bootstrap_live.last_status = static_cast<u32>(result.status);
    LiveStateStore(ServiceBootstrapLiveStateV1::RuntimeOpenCompatibilityRequired);

    const ServiceControlPlatformInitializeResultV1 platform = ServiceControlPlatformInstallKernelV1();
    result.platform_status = platform.status;
    if (platform.status != ServiceControlPlatformAdapterStatusV1::Ok)
    {
        result.status = ServiceBootstrapLiveStatusV1::ServiceControlPlatformFailed;
        g_service_bootstrap_live.last_status = static_cast<u32>(result.status);
        LiveStateStore(ServiceBootstrapLiveStateV1::Failed);
    }
    return result;
}

ServiceBootstrapLiveStatusV1 ServiceBootstrapLiveInspectV1(ServiceBootstrapLiveSnapshotV1* snapshot_out)
{
    if (snapshot_out == nullptr)
        return ServiceBootstrapLiveStatusV1::NullArgument;
    *snapshot_out = {};

    const u32 raw_state = LiveStateLoad();
    if (raw_state > static_cast<u32>(ServiceBootstrapLiveStateV1::Failed))
        return ServiceBootstrapLiveStatusV1::CorruptState;

    ServiceBootstrapLiveSnapshotV1 snapshot{};
    snapshot.state = static_cast<ServiceBootstrapLiveStateV1>(raw_state);
    snapshot.fixed_service_capacity = kServiceBootstrapLiveServiceCapacityV1;
    snapshot.activation_ready = 0;
    snapshot.compatibility_required = 1;
    snapshot.process_count = 0;
    snapshot.published_endpoint_count = 0;
    snapshot.banks_per_service = kServiceBootstrapLiveBanksPerServiceV1;

    if (snapshot.state == ServiceBootstrapLiveStateV1::Uninitialized ||
        snapshot.state == ServiceBootstrapLiveStateV1::Initializing)
    {
        snapshot.status = ServiceBootstrapLiveStatusV1::NotInitialized;
        *snapshot_out = snapshot;
        return snapshot.status;
    }

    LiveOwnerOperationGuard operation;
    if (!operation.Acquired())
    {
        snapshot.status = ServiceBootstrapLiveStatusV1::Busy;
        *snapshot_out = snapshot;
        return snapshot.status;
    }

    if (LiveStateLoad() != raw_state)
        return ServiceBootstrapLiveStatusV1::CorruptState;

    snapshot.version = g_service_bootstrap_live.version;
    snapshot.generated_service_count = g_service_bootstrap_live.generated_service_count;
    snapshot.allocation_count = g_service_bootstrap_live.allocation_count;
    snapshot.release_count = g_service_bootstrap_live.release_count;
    for (u32 index = 0; index < kServiceBootstrapLiveServiceCapacityV1; ++index)
        snapshot.active_bank_indices[index] = g_service_bootstrap_live.active_bank_indices[index];

    if (g_service_bootstrap_live.last_status > static_cast<u32>(ServiceBootstrapLiveStatusV1::CorruptState))
        return ServiceBootstrapLiveStatusV1::CorruptState;
    snapshot.status = static_cast<ServiceBootstrapLiveStatusV1>(g_service_bootstrap_live.last_status);
    if (snapshot.state == ServiceBootstrapLiveStateV1::Failed)
    {
        *snapshot_out = snapshot;
        return snapshot.status;
    }

    ServiceBootstrapStageSnapshotV1 stage{};
    ServiceRuntimeV1* runtime = ServiceRuntimeKernelV1();
    ServiceRuntimeSnapshotV1 runtime_snapshot{};
    if (snapshot.state != ServiceBootstrapLiveStateV1::RuntimeOpenCompatibilityRequired ||
        snapshot.status != ServiceBootstrapLiveStatusV1::CompatibilityRequired ||
        snapshot.version != kServiceBootstrapLiveVersion1 || runtime == nullptr ||
        ServiceBootstrapStageInspectV1(&g_service_bootstrap_live.stage, &stage) != ServiceBootstrapStageStatus::Ok ||
        ServiceRuntimeInspectV1(runtime, &runtime_snapshot) != ServiceRuntimeStatusV1::Ok ||
        !LiveBankTopologyIsCanonical() || !CountPackageOwnedPages(&snapshot.package_owned_pages) ||
        stage.service_count != snapshot.generated_service_count ||
        runtime_snapshot.service_count != stage.service_count)
    {
        return ServiceBootstrapLiveStatusV1::CorruptState;
    }

    snapshot.staged_service_count = stage.ready_count;
    snapshot.stage_registry_identity = stage.registry_identity;
    *snapshot_out = snapshot;
    return ServiceBootstrapLiveStatusV1::CompatibilityRequired;
}

ServiceBootstrapLiveRestageResultV1 ServiceBootstrapLiveRestageV1(
    u64 service_identity, u64 expected_activation_generation,
    ServiceBootstrapLiveRetiredTargetTeardownV1 retired_target_teardown)
{
    if (service_identity == 0 || expected_activation_generation == 0 ||
        static_cast<u8>(retired_target_teardown) >
            static_cast<u8>(ServiceBootstrapLiveRetiredTargetTeardownV1::TeardownComplete))
    {
        ServiceBootstrapLiveRestageResultV1 result = RestageResult(ServiceBootstrapLiveRestageStatusV1::NullArgument);
        result.stage.status = ServiceBootstrapStageStatus::NullArgument;
        return result;
    }
    if (LiveStateLoad() != static_cast<u32>(ServiceBootstrapLiveStateV1::RuntimeOpenCompatibilityRequired))
        return RestageResult(ServiceBootstrapLiveRestageStatusV1::NotInitialized);

    LiveOwnerOperationGuard operation;
    if (!operation.Acquired())
        return RestageResult(ServiceBootstrapLiveRestageStatusV1::Busy);
    if (LiveStateLoad() != static_cast<u32>(ServiceBootstrapLiveStateV1::RuntimeOpenCompatibilityRequired))
        return RestageResult(ServiceBootstrapLiveRestageStatusV1::NotInitialized);

    ServiceBootstrapLiveRestageResultV1 result = RestageResult(ServiceBootstrapLiveRestageStatusV1::CorruptState);
    ServiceRuntimeV1* runtime = ServiceRuntimeKernelV1();
    ServiceRuntimeSnapshotV1 runtime_snapshot{};
    if (runtime == nullptr || runtime->stage != &g_service_bootstrap_live.stage ||
        ServiceRuntimeInspectV1(runtime, &runtime_snapshot) != ServiceRuntimeStatusV1::Ok ||
        !LiveBankTopologyIsCanonical())
    {
        result.stage.status = ServiceBootstrapStageStatus::CorruptRuntime;
        return result;
    }

    ServiceBootstrapServiceSnapshotV1 service{};
    result.stage.status =
        ServiceBootstrapStageFindServiceV1(&g_service_bootstrap_live.stage, service_identity, &service);
    if (result.stage.status != ServiceBootstrapStageStatus::Ok)
    {
        result.status = ServiceBootstrapLiveRestageStatusV1::StageRejected;
        return result;
    }
    result.service_index = service.manifest_index;
    if (service.service_identity != service_identity || service.manifest_index >= runtime_snapshot.service_count ||
        service.manifest_index >= kServiceBootstrapLiveServiceCapacityV1)
    {
        result.stage.status = ServiceBootstrapStageStatus::CorruptRuntime;
        return result;
    }
    if (service.activation_generation != expected_activation_generation)
    {
        result.status = ServiceBootstrapLiveRestageStatusV1::StageRejected;
        result.stage.status = ServiceBootstrapStageStatus::StaleActivationGeneration;
        return result;
    }

    const u32 service_index = service.manifest_index;
    const u8 active_bank = g_service_bootstrap_live.active_bank_indices[service_index];
    if (active_bank >= kServiceBootstrapLiveBanksPerServiceV1)
    {
        result.stage.status = ServiceBootstrapStageStatus::CorruptRuntime;
        return result;
    }
    const u8 inactive_bank = static_cast<u8>(1u - active_bank);
    const ServiceBootstrapStageRowV1& row = g_service_bootstrap_live.stage.rows[service_index];
    if (row.service_identity != service_identity || row.activation_generation != expected_activation_generation ||
        row.active_bank_index != active_bank ||
        row.image != &g_service_bootstrap_live.images[service_index][active_bank] ||
        row.admission != &g_service_bootstrap_live.admissions[service_index][active_bank])
    {
        result.stage.status = ServiceBootstrapStageStatus::CorruptRuntime;
        return result;
    }
    result.previous_active_bank = active_bank;
    result.active_bank = active_bank;

    loader::LoadImage* const retired_image = &g_service_bootstrap_live.images[service_index][inactive_bank];
    loader::ExecAdmission* const retired_admission = &g_service_bootstrap_live.admissions[service_index][inactive_bank];
    loader::LoadImageSnapshot retired_snapshot{};
    if (loader::LoadImageInspect(retired_image, &retired_snapshot) != loader::LoadImageStatus::Ok)
    {
        result.status = ServiceBootstrapLiveRestageStatusV1::RetiredBankNotResettable;
        return result;
    }
    if (retired_snapshot.target_owned_pages != 0 &&
        retired_target_teardown != ServiceBootstrapLiveRetiredTargetTeardownV1::TeardownComplete)
    {
        result.status = ServiceBootstrapLiveRestageStatusV1::RetiredTargetTeardownRequired;
        return result;
    }

    result.retired_image_status = loader::LoadImageCanResetQuiescent(retired_image);
    result.retired_admission_status = loader::ExecAdmissionCanResetQuiescent(retired_admission);
    if (result.retired_image_status != loader::LoadImageStatus::Ok ||
        result.retired_admission_status != loader::ExecAdmissionStatus::Ok)
    {
        result.status = ServiceBootstrapLiveRestageStatusV1::RetiredBankNotResettable;
        return result;
    }

    const ServiceBootstrapSlotStorageV1 replacement = BuildSlotDescriptor(service_index, inactive_bank);
    result.stage = ServiceBootstrapStageRestageV1(&g_service_bootstrap_live.stage, service_identity,
                                                  expected_activation_generation, &replacement);
    if (result.stage.status != ServiceBootstrapStageStatus::Ok)
    {
        result.status = ServiceBootstrapLiveRestageStatusV1::StageRejected;
        return result;
    }

    // This is the sole selector mutation. The lower transaction has already
    // committed the exact replacement row, and no fallible operation remains.
    g_service_bootstrap_live.active_bank_indices[service_index] = inactive_bank;
    result.status = ServiceBootstrapLiveRestageStatusV1::Ok;
    result.active_bank = inactive_bank;
    return result;
}

#endif

const char* ServiceBootstrapLiveStatusNameV1(ServiceBootstrapLiveStatusV1 status)
{
    switch (status)
    {
    case ServiceBootstrapLiveStatusV1::CompatibilityRequired:
        return "compatibility-required";
    case ServiceBootstrapLiveStatusV1::NullArgument:
        return "null-argument";
    case ServiceBootstrapLiveStatusV1::AlreadyAttempted:
        return "already-attempted";
    case ServiceBootstrapLiveStatusV1::GeneratedPackageCountMismatch:
        return "generated-package-count-mismatch";
    case ServiceBootstrapLiveStatusV1::StageFailed:
        return "stage-failed";
    case ServiceBootstrapLiveStatusV1::RuntimeFailed:
        return "runtime-failed";
    case ServiceBootstrapLiveStatusV1::RuntimeFailedStageDiscardFailed:
        return "runtime-failed-stage-discard-failed";
    case ServiceBootstrapLiveStatusV1::ServiceControlPlatformFailed:
        return "service-control-platform-failed";
    case ServiceBootstrapLiveStatusV1::NotInitialized:
        return "not-initialized";
    case ServiceBootstrapLiveStatusV1::Busy:
        return "busy";
    case ServiceBootstrapLiveStatusV1::CorruptState:
        return "corrupt-state";
    }
    return "unknown";
}

const char* ServiceBootstrapLiveRestageStatusNameV1(ServiceBootstrapLiveRestageStatusV1 status)
{
    switch (status)
    {
    case ServiceBootstrapLiveRestageStatusV1::Ok:
        return "ok";
    case ServiceBootstrapLiveRestageStatusV1::NullArgument:
        return "null-argument";
    case ServiceBootstrapLiveRestageStatusV1::NotInitialized:
        return "not-initialized";
    case ServiceBootstrapLiveRestageStatusV1::Busy:
        return "busy";
    case ServiceBootstrapLiveRestageStatusV1::StageRejected:
        return "stage-rejected";
    case ServiceBootstrapLiveRestageStatusV1::RetiredTargetTeardownRequired:
        return "retired-target-teardown-required";
    case ServiceBootstrapLiveRestageStatusV1::RetiredBankNotResettable:
        return "retired-bank-not-resettable";
    case ServiceBootstrapLiveRestageStatusV1::CorruptState:
        return "corrupt-state";
    }
    return "unknown";
}

} // namespace duetos::core
