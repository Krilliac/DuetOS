#pragma once

/*
 * Authority-bound boot service staging, v1.
 *
 * This is the unpublished runtime seam between the immutable generated
 * ServiceObjectPackage definition and executable activation.  It performs
 * only the following transaction:
 *
 *   1. validate and retain the separately-authorized object package;
 *   2. resolve each exact service/transfer-reference pair;
 *   3. mint a boot-private, typed, stable memory-object identity;
 *   4. stage native ELF bytes through ElfLoadImagePrepare;
 *   5. require runtime output to match its bound build-time plan template; and
 *   6. copy and consume the sealed plan through ExecAdmission against the
 *      exact backing row in this registry.
 *
 * It deliberately does not map an AddressSpace, create a Process/Task,
 * install capabilities or resource domains, publish scheduler state, create
 * IPC endpoints, or start a lifecycle transition.  A Ready staging package
 * is therefore not ActivationReady. Build-time plan binding proves parser
 * agreement, but cannot stand in for process/endpoint publication authority.
 *
 * Ownership and threading:
 *   - The definition and executable bytes are borrowed through the retained
 *     ServiceObjectPackage contract.
 *   - Every LoadImage, metadata buffer, plan buffer, ExecAdmission, and
 *     admission buffer is caller-owned and must outlive the runtime object.
 *   - Successfully staged frames remain exclusively LoadImage-owned.
 *   - Initialize/Restage/Discard are [boot task, single-threaded, unpublished].
 *   - Inspect/Find/BackingQuery are [same boot task; read-only].
 *   - No lock is held while a frame hook, parser, or backing query runs.
 */

#include "core/service_object_package.h"
#include "loader/elf_load_image.h"
#include "loader/exec_admission.h"
#include "util/types.h"

namespace duetos::core
{

inline constexpr u32 kServiceBootstrapStageVersion1 = 1;
inline constexpr u32 kServiceBootstrapActivationReceiptVersion1 = 1;
inline constexpr u32 kServiceBootstrapNoServiceIndex = ~0U;
inline constexpr u32 kServiceBootstrapStageBankCapacityV1 = 2;
inline constexpr u8 kServiceBootstrapNoBankIndexV1 = 0xFFu;
inline constexpr u64 kServiceBootstrapActivationGenerationMaximum = (1ULL << 51) - 1;

// "SV" occupies the high 16 bits, followed by a non-wrapping 40-bit runtime
// registry identity and an 8-bit canonical manifest-row index plus one. The
// registry identity prevents a handle from one live/runtime generation from
// resolving in another. Callers never author or import these values.
inline constexpr loader::ObjectHandle kServiceBootstrapMemoryObjectTypeTag = 0x5356000000000000ULL;
inline constexpr loader::ObjectHandle kServiceBootstrapMemoryObjectTypeMask = 0xFFFF000000000000ULL;
inline constexpr loader::ObjectHandle kServiceBootstrapMemoryObjectRegistryMask = 0x0000FFFFFFFFFF00ULL;
inline constexpr loader::ObjectHandle kServiceBootstrapMemoryObjectIndexMask = 0x00000000000000FFULL;
inline constexpr u32 kServiceBootstrapMemoryObjectRegistryShift = 8;
inline constexpr u64 kServiceBootstrapMemoryObjectRegistryMaximum = 0xFFFFFFFFFFULL;
static_assert(kServiceManifestMaximumServices < 0xFF, "service index no longer fits typed bootstrap handle");

enum class ServiceBootstrapStageState : u8
{
    Uninitialized = 0,
    Staging,
    Ready,
    Failed,
    Discarded,
};

enum class ServiceBootstrapStageStatus : u8
{
    Ok = 0,
    NullArgument,
    InvalidPointerRange,
    AliasedStorage,
    NonCanonicalRuntime,
    PackageRejected,
    ManifestUnavailable,
    SlotCapacityTooSmall,
    InvalidSlotStorage,
    SlotStorageOverlap,
    IdentityExhausted,
    UnsupportedServiceKind,
    ExecutableResolveFailed,
    BootstrapPlanResolveFailed,
    ElfStageRejected,
    ResourceBudgetExceeded,
    PlanUnavailable,
    BootstrapPlanMismatch,
    AdmissionRejected,
    CorruptRuntime,
    NotReady,
    NotFound,
    CannotDiscard,
    ActivationInProgress,
    ActivationTerminal,
    ActivationGenerationExhausted,
    InvalidActivationReceipt,
    CannotCancelActivation,
    InvalidActivationOutcome,
    ActivationNotTerminal,
    StaleActivationGeneration,
    TerminalImageOwnsFrames,
};

enum class ServiceBootstrapActivationStateV1 : u8
{
    Staged = 0,
    Activating,
    TransferredPublished,
    ConsumedFailed,
};

enum class ServiceBootstrapActivationOutcomeV1 : u8
{
    TransferredPublished = 0,
    ConsumedFailed,
};

// Exact, non-replayable authority for one row activation generation. It is
// minted only by Begin and accepted only against the same live runtime, row,
// typed memory object, and current Activating generation.
struct ServiceBootstrapActivationReceiptV1
{
    u32 version;
    u32 manifest_index;
    u64 registry_identity;
    u64 service_identity;
    u64 activation_generation;
    loader::ObjectHandle memory_object;
};

inline constexpr ServiceBootstrapActivationReceiptV1 kInvalidServiceBootstrapActivationReceiptV1{};

// One manifest-row-indexed staging slot. Buffer capacities are explicit so a
// caller can use fixed boot storage without any allocation inside this layer.
// The LoadImage and ExecAdmission objects must be canonical all-zero storage.
// The underlying frame-hook callbacks and context are borrowed by the runtime
// and must outlive it, including discard and ownership-transfer unwind. Any
// slot adopted by Restage is permanent caller-owned runtime storage: its
// LoadImage, ExecAdmission, pages, regions, plans, and admission bytes must not
// live in the Restage call frame. The live runtime owner provisions fixed banks
// and keeps both active and retired banks alive until the whole runtime ends.
struct ServiceBootstrapSlotStorageV1
{
    loader::LoadImage* image;
    loader::LoadImageFrameHooks frame_hooks;
    loader::LoadImagePage* page_storage;
    u32 page_storage_count;
    loader::LoadImageRegionAuthority* region_storage;
    u32 region_storage_count;
    void* plan_storage;
    u32 plan_storage_bytes;
    loader::ExecAdmission* admission;
    void* admission_storage;
    u32 admission_storage_bytes;
    u32 reserved;
};

// Runtime-owned provenance for one permanent fixed bank. A binding is minted
// only when this exact row first publishes the bank, then retained across all
// swaps. The full descriptor prevents mixing an image with another service's
// admission or backing buffers; the registry/service/index tuple prevents a
// terminal bank from another runtime or row from being adopted.
struct ServiceBootstrapStageBankBindingV1
{
    ServiceBootstrapSlotStorageV1 storage;
    u64 runtime_registry_identity;
    u64 service_identity;
    u64 activation_generation;
    u32 manifest_index;
    u8 registered;
    u8 reserved[3];
};

// Public only so boot code can provide fixed allocation-free storage. Treat
// fields as opaque after Initialize succeeds.
struct ServiceBootstrapStageRowV1
{
    u64 service_identity;
    u32 executable_transfer_ref;
    u32 manifest_index;
    loader::ObjectHandle memory_object;
    loader::Hash256 expected_source_hash;
    loader::LoadImageFrameHooks source_frame_hooks;
    u64 frame_budget_pages;
    u64 frame_allocations;
    u8 frame_budget_exhausted;
    ServiceBootstrapActivationStateV1 activation_state;
    u8 reserved_budget[6];
    u64 activation_generation;
    loader::LoadImage* image;
    loader::ExecAdmission* admission;
    loader::LoadPlanViewV1 admitted_plan;
    ServiceBootstrapStageBankBindingV1 banks[kServiceBootstrapStageBankCapacityV1];
    u8 bank_count;
    u8 active_bank_index;
    u8 reserved_banks[6];
};

struct ServiceBootstrapStageRuntimeV1
{
    ServiceBootstrapStageState state;
    u8 reserved8[3];
    u32 version;
    u32 service_count;
    u32 ready_count;
    u64 registry_identity;
    ServiceObjectPackageV1 package;
    ServiceBootstrapStageRowV1 rows[kServiceManifestMaximumServices];
};

struct ServiceBootstrapStageResultV1
{
    ServiceBootstrapStageStatus status;
    u32 service_index;
    ServiceObjectPackageResult package_result;
    loader::ElfLoadImageResult elf_result;
    loader::ExecAdmissionStatus admission_status;
    loader::LoadPlanValidationError validation_error;
};

struct ServiceBootstrapStageSnapshotV1
{
    ServiceBootstrapStageState state;
    u32 version;
    u32 service_count;
    u32 ready_count;
    u64 authority_identity;
    u64 registry_identity;
};

struct ServiceBootstrapServiceSnapshotV1
{
    u64 service_identity;
    u32 executable_transfer_ref;
    u32 manifest_index;
    loader::ObjectHandle memory_object;
    loader::Hash256 expected_source_hash;
    loader::LoadPlanViewV1 admitted_plan;
    ServiceBootstrapActivationStateV1 activation_state;
    u8 reserved8[7];
    u64 activation_generation;
};

struct ServiceBootstrapActivationLeaseV1
{
    ServiceBootstrapActivationReceiptV1 receipt;
    ServiceBootstrapServiceSnapshotV1 service;
    loader::LoadImage* image;
    u64 frame_allocations;
};

// [boot task, single-threaded, unpublished]
// Initialize a canonical-zero runtime and stage every manifest service in
// dependency order. Slots are indexed by canonical manifest row, not topology
// position. Extra capacity is ignored; fewer slots fail before frame staging.
ServiceBootstrapStageResultV1 ServiceBootstrapStageInitializeV1(ServiceBootstrapStageRuntimeV1* runtime,
                                                                const ServiceObjectPackageDefinitionV1* definition,
                                                                const ServiceBootstrapSlotStorageV1* slots,
                                                                u32 slot_capacity);

// [boot task, read-only]
// Exact registry-backed authority for already-staged memory-object slices.
// Unknown, wrong-typed, stale, or cross-runtime handles fail closed.
bool ServiceBootstrapStageBackingQueryV1(loader::ObjectHandle memory_object, u64 object_offset, u64 length,
                                         loader::LoadBackingInfoV1* out_info, void* context);

ServiceBootstrapStageStatus ServiceBootstrapStageInspectV1(const ServiceBootstrapStageRuntimeV1* runtime,
                                                           ServiceBootstrapStageSnapshotV1* snapshot_out);
ServiceBootstrapStageStatus ServiceBootstrapStageFindServiceV1(const ServiceBootstrapStageRuntimeV1* runtime,
                                                               u64 service_identity,
                                                               ServiceBootstrapServiceSnapshotV1* snapshot_out);

// Begin one exact staged row. Success changes Staged -> Activating and returns
// the only receipt accepted by Cancel/Finish. A cancelled sealed attempt may
// begin again with a fresh non-wrapping generation. A terminal row can only be
// reopened by Restage into separate canonical-zero caller storage.
// lease_out must not overlap the runtime, any retained slot buffer, or any
// retained package executable extent; alias refusal occurs before output clear.
ServiceBootstrapStageStatus ServiceBootstrapStageBeginActivationV1(ServiceBootstrapStageRuntimeV1* runtime,
                                                                   u64 service_identity,
                                                                   ServiceBootstrapActivationLeaseV1* lease_out);

// Revert Activating -> Staged only while the exact image remains sealed and
// package-owned. Once mapping begins, Finish(ConsumedFailed) is mandatory.
ServiceBootstrapStageStatus ServiceBootstrapStageCancelActivationV1(ServiceBootstrapStageRuntimeV1* runtime,
                                                                    ServiceBootstrapActivationReceiptV1 receipt);

// Record the terminal ownership result for the exact current receipt.
// TransferredPublished requires a fully transferred image; ConsumedFailed
// requires the mapping transaction to have irreversibly reached Transferred or
// Failed. Neither terminal state may be replayed or reopened.
ServiceBootstrapStageStatus ServiceBootstrapStageFinishActivationV1(ServiceBootstrapStageRuntimeV1* runtime,
                                                                    ServiceBootstrapActivationReceiptV1 receipt,
                                                                    ServiceBootstrapActivationOutcomeV1 outcome);

// [service-control task, single-threaded, serialized]
// Recreate one terminal service image from the retained immutable package into
// a separate canonical-zero fixed slot. The service identity and exact current
// activation generation form the replay guard. Success preserves the monotonic
// activation generation, installs a freshly minted typed backing identity, and
// leaves the row Staged so Begin advances to the next generation. A previously
// retired replacement bank is cleared only if its complete descriptor is
// already bound to this exact runtime/service row and both its image and
// admission independently validate as quiescent/resettable. One pristine
// canonical-zero second bank may be bound on its first successful publication;
// a foreign terminal bank is never claimable. Any later error releases and
// clears only partial replacement ownership and leaves the published terminal
// row unchanged. `replacement` and all of its output extents must be disjoint
// from the runtime, package bytes, and every other registered bank extent.
ServiceBootstrapStageResultV1 ServiceBootstrapStageRestageV1(ServiceBootstrapStageRuntimeV1* runtime,
                                                             u64 service_identity, u64 expected_activation_generation,
                                                             const ServiceBootstrapSlotStorageV1* replacement);

#if defined(DUETOS_HOST_TEST)
// Single-threaded deterministic exhaustion seam. Production has no authority
// to move the global nonrecycling registry backwards.
u64 ServiceBootstrapStageExchangeNextRegistryIdentityForTestV1(u64 next_identity);
#endif

// Release only a still-unmapped Ready package. This refuses once any image is
// no longer sealed, because target-owned frames belong to a later activation
// transaction and may not be guessed free here.
ServiceBootstrapStageStatus ServiceBootstrapStageDiscardV1(ServiceBootstrapStageRuntimeV1* runtime);

#if !defined(DUETOS_HOST_TEST)
// Production seam for generated_boot_service_package_data.h. A linked live
// owner consumes authority-bound ELF and bootstrap-plan templates through this
// same entry point; process publication and endpoint readiness are bound via
// CommitLifecyclePublication and the MARK_READY syscall, so activation is live.
u32 ServiceBootstrapGeneratedServiceCountV1();
ServiceBootstrapStageResultV1 ServiceBootstrapStageGeneratedV1(ServiceBootstrapStageRuntimeV1* runtime,
                                                               const ServiceBootstrapSlotStorageV1* slots,
                                                               u32 slot_capacity);
#endif

const char* ServiceBootstrapStageStatusName(ServiceBootstrapStageStatus status);

} // namespace duetos::core
