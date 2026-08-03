#pragma once

/*
 * Immutable boot service-object package, v1.
 *
 * This is the build/package authority seam between ServiceManifest and the
 * privileged service builder.  A manifest transfer reference is only a
 * positive name until this object binds it one-to-one to exact sealed bytes.
 * Initialization therefore requires all three independently supplied inputs:
 *
 *   - canonical manifest bytes;
 *   - a trusted, separately retained manifest-authority snapshot; and
 *   - one embedded sealed executable object for every manifest service; and
 *   - optionally, one sealed relocatable bootstrap-plan template per service.
 *
 * The package never creates signer authority and never treats a path, hash, or
 * transfer reference from the manifest as proof.  It validates the manifest
 * against the supplied authority, hashes every executable object, requires an
 * exact immutable-policy match, rejects duplicate/extra/missing references,
 * and only then copies the authority and scalar plan into package-owned
 * storage. Bootstrap-plan templates are independently hashed and bound to the
 * same service/transfer pair. Resolver calls re-hash selected bytes so
 * accidental mutation after construction fails closed.
 *
 * Ownership and threading:
 *   - Definition arrays are borrowed only for Initialize.
 *   - Executable and bootstrap-plan bytes remain borrowed for the package
 *     lifetime. Production callers must use authenticated kernel-image/package
 *     storage whose bytes cannot be replaced or freed while the package lives.
 *   - The manifest plan, authority snapshot, and binding rows are copied and
 *     independently retained inside the package.
 *   - Initialize is [boot/task context, single-threaded, unpublished].
 *   - GetManifest and ResolveExecutable are [any thread; read-only].
 *   - There are no locks, callbacks, allocation, logging, or global lookups.
 */

#include "core/service_manifest.h"
#include "util/types.h"

namespace duetos::core
{

inline constexpr u32 kServiceObjectPackageVersion1 = 1;
inline constexpr u32 kServiceObjectPackageExecutableMaximumBytes = 256u * 1024u * 1024u;
inline constexpr u64 kServiceObjectPackageTotalExecutableMaximumBytes = 1024ULL * 1024ULL * 1024ULL;
inline constexpr u32 kServiceObjectDefinitionSealed = 1u << 0;
inline constexpr u32 kServiceObjectDefinitionKnownFlags = kServiceObjectDefinitionSealed;
inline constexpr u32 kServiceBootstrapPlanDefinitionSealed = 1u << 0;
inline constexpr u32 kServiceBootstrapPlanDefinitionKnownFlags = kServiceBootstrapPlanDefinitionSealed;
inline constexpr u32 kServiceObjectPackageNoObjectIndex = ~0U;

// Trusted package-builder input.  `bytes` must refer to an exact immutable
// object extent, not a mutable file lookup or user mapping.  The transfer ref
// and immutable policy are selectors only; the manifest must independently
// contain the same values.
struct ServiceExecutableObjectDefinitionV1
{
    u32 executable_transfer_ref;
    u32 immutable_policy_selector;
    const u8* bytes;
    u64 byte_count;
    u32 flags;
    u32 reserved;
};

// Relocatable LoadPlan v1 template. Every LoadRegion memory_object field must
// be zero; staging binds those slots to its freshly minted typed object handle
// and requires all remaining bytes to exactly match the runtime parser output.
struct ServiceBootstrapPlanDefinitionV1
{
    u32 executable_transfer_ref;
    u32 flags;
    const u8* bytes;
    u32 byte_count;
    u32 reserved;
    loader::Hash256 content_hash;
};

struct ServiceObjectPackageDefinitionV1
{
    const u8* manifest_bytes;
    u64 manifest_byte_count;
    const ServiceManifestAuthoritySnapshotV1* manifest_authority;
    const ServiceExecutableObjectDefinitionV1* executable_objects;
    u32 executable_object_count;
    u32 reserved;
    const ServiceBootstrapPlanDefinitionV1* bootstrap_plans;
    u32 bootstrap_plan_count;
    u32 reserved_bootstrap;
};

struct ServiceObjectPackageRowV1
{
    u64 service_identity;
    u32 executable_transfer_ref;
    u32 immutable_policy_selector;
    const u8* bytes;
    u64 byte_count;
    loader::Hash256 content_hash;
};

struct ServiceBootstrapPlanRowV1
{
    u64 service_identity;
    u32 executable_transfer_ref;
    u32 byte_count;
    const u8* bytes;
    loader::Hash256 content_hash;
};

// Public only so boot code can provide fixed, allocation-free storage.  Treat
// every field as opaque after successful initialization.
struct ServiceObjectPackageV1
{
    u32 initialized;
    u16 version;
    u16 executable_object_count;
    u16 bootstrap_plan_count;
    u16 reserved;
    ServiceManifestPlanV1 manifest_plan;
    ServiceManifestAuthoritySnapshotV1 manifest_authority;
    ServiceObjectPackageRowV1 executable_objects[kServiceManifestMaximumServices];
    ServiceBootstrapPlanRowV1 bootstrap_plans[kServiceManifestMaximumServices];
};

struct ServiceObjectPackageManifestV1
{
    const ServiceManifestPlanV1* plan;
    const ServiceManifestAuthoritySnapshotV1* authority;
};

struct ServiceExecutableTransferSnapshotV1
{
    u64 service_identity;
    u32 executable_transfer_ref;
    u32 immutable_policy_selector;
    const u8* bytes;
    u64 byte_count;
    loader::Hash256 content_hash;
};

struct ServiceBootstrapPlanTransferSnapshotV1
{
    u64 service_identity;
    u32 executable_transfer_ref;
    u32 byte_count;
    const u8* bytes;
    loader::Hash256 content_hash;
};

enum class ServiceObjectPackageStatus : u8
{
    Ok = 0,
    NullArgument,
    InvalidPointerRange,
    AliasedOutput,
    NonCanonicalStorage,
    AlreadyInitialized,
    ManifestRejected,
    InvalidSelector,
    ObjectCountMismatch,
    InvalidObject,
    ObjectRangeOverlap,
    DuplicateTransferReference,
    UnexpectedTransferReference,
    MissingTransferReference,
    ImmutablePolicyMismatch,
    ContentHashMismatch,
    NotInitialized,
    CorruptPackage,
    NotFound,
    ServiceBindingMismatch,
    PlanCountMismatch,
    InvalidBootstrapPlan,
    BootstrapPlanHashMismatch,
};

struct ServiceObjectPackageResult
{
    ServiceObjectPackageStatus status;
    ServiceManifestError manifest_error;
    u32 object_index;
};

// One-shot, failure-atomic construction into canonical zero-initialized
// storage.  The trusted authority is copied only after its exact manifest and
// every executable byte object have passed validation.  On any failure the
// package remains all-zero and owns no authority.
ServiceObjectPackageResult ServiceObjectPackageInitializeV1(ServiceObjectPackageV1* package,
                                                            const ServiceObjectPackageDefinitionV1* definition);

// Return package-owned immutable manifest inputs suitable for
// ServiceLifecycleBrokerInitialize.  The package's copied plan and authority
// are revalidated before their addresses are published.
ServiceObjectPackageResult ServiceObjectPackageGetManifestV1(const ServiceObjectPackageV1* package,
                                                             ServiceObjectPackageManifestV1* manifest_out);

// Resolve one exact manifest service/ref pair.  A valid ref belonging to a
// different service is rejected rather than silently retargeted.  The selected
// byte extent is re-hashed before a borrowed immutable snapshot is returned.
ServiceObjectPackageResult ServiceObjectPackageResolveExecutableV1(const ServiceObjectPackageV1* package,
                                                                   u64 expected_service_identity,
                                                                   u32 executable_transfer_ref,
                                                                   ServiceExecutableTransferSnapshotV1* transfer_out);

// Resolve an exact service/ref-bound bootstrap template. Packages without a
// complete template set return NotFound. The selected bytes are re-hashed
// before their immutable borrowed snapshot is returned.
ServiceObjectPackageResult ServiceObjectPackageResolveBootstrapPlanV1(
    const ServiceObjectPackageV1* package, u64 expected_service_identity, u32 executable_transfer_ref,
    ServiceBootstrapPlanTransferSnapshotV1* transfer_out);

const char* ServiceObjectPackageStatusName(ServiceObjectPackageStatus status);

} // namespace duetos::core
