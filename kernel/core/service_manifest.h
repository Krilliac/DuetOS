#pragma once

/*
 * Immutable service/capability manifest, v1.
 *
 * The wire object is a canonical little-endian document:
 *
 *   64-byte header
 *   service_count * 256-byte service rows
 *   dependency_count * 16-byte identity edges
 *
 * Rows are sorted by stable non-zero service_identity.  Array position is
 * enumeration metadata only and is never accepted as identity or authority.
 * Each row's dependency range is contiguous, owner-bound, identity-addressed,
 * and strictly sorted.  Validation rejects missing identities, duplicates,
 * and cycles and emits a deterministic identity-only topological order.
 *
 * A manifest never carries authority.  Capability masks, budgets, service and
 * resource classes, immutable-policy selectors, and the positive executable
 * transfer reference are requests only.  A separately retained trusted
 * signer/profile snapshot binds the exact sealed object SHA-256 and extent and
 * supplies every allowed mask/ceiling.  Hostile bytes can only narrow it.
 * Signature verification and creation of that trusted snapshot remain in the
 * package/transfer layer; this validator computes SHA-256 solely to bind the
 * supplied stable sealed bytes to the retained exact snapshot.
 *
 * Validation and encoding are allocation-free, callback-free, lock-free,
 * logging-free, and global-lookup-free.  No pointer into input escapes: the
 * result is a complete scalar plan in caller-owned storage.
 */

#include "loader/load_plan.h"
#include "util/types.h"

namespace duetos::core
{

inline constexpr u16 kServiceManifestVersion1 = 1;
inline constexpr u32 kServiceManifestV1HeaderBytes = 64;
inline constexpr u32 kServiceManifestV1ServiceBytes = 256;
inline constexpr u32 kServiceManifestV1DependencyBytes = 16;

inline constexpr u32 kServiceManifestMaximumServices = 64;
inline constexpr u32 kServiceManifestMaximumDependenciesPerService = 8;
inline constexpr u32 kServiceManifestMaximumDependencies = 256;
inline constexpr u32 kServiceManifestServiceNameCapacity = 32;
inline constexpr u32 kServiceManifestExecutablePathCapacity = 128;

inline constexpr u32 kServiceManifestMaximumBytes =
    kServiceManifestV1HeaderBytes + kServiceManifestMaximumServices * kServiceManifestV1ServiceBytes +
    kServiceManifestMaximumDependencies * kServiceManifestV1DependencyBytes;
static_assert(kServiceManifestMaximumBytes == 20544, "service manifest v1 maximum changed");

inline constexpr u16 kServiceManifestV1KnownFlags = 0;
inline constexpr u32 kServiceManifestAuthoritySealed = 1u << 0;
inline constexpr u32 kServiceManifestAuthorityKnownFlags = kServiceManifestAuthoritySealed;

// V1 freezes the currently-defined process capabilities (bits 1..11).  A new
// capability must make an explicit manifest-version compatibility decision.
inline constexpr u64 kServiceManifestCapabilityMaskV1 = 0xFFEULL;
inline constexpr u64 kServiceManifestFrameBudgetMaximum = 8192;
inline constexpr u64 kServiceManifestTickBudgetMaximum = 1ULL << 40;
inline constexpr u32 kServiceManifestSectionObjectMaximum = 4;
inline constexpr u32 kServiceManifestSectionPageMaximum = 2048;
inline constexpr u32 kServiceManifestPositiveTransferRefMaximum = 0x7FFFFFFFU;

enum class ServiceManifestKind : u8
{
    Invalid = 0,
    Native = 1,
    Win32 = 2,
    Linux = 3,
    Broker = 4,
};

inline constexpr u32 kServiceManifestKnownKindMask =
    (1u << static_cast<u8>(ServiceManifestKind::Native)) |
    (1u << static_cast<u8>(ServiceManifestKind::Win32)) |
    (1u << static_cast<u8>(ServiceManifestKind::Linux)) |
    (1u << static_cast<u8>(ServiceManifestKind::Broker));

enum class ServiceManifestRestartPolicy : u8
{
    Never = 0,
    Always = 1,
    OnFailure = 2,
};

// Numeric values deliberately mirror ResourceDomainProfile without importing
// a live ResourceDomainKey or treating the profile selector as authority.
enum class ServiceManifestResourceProfile : u8
{
    Sandbox = 0,
    Trusted = 1,
    AuthenticatedService = 2,
};

inline constexpr u32 kServiceManifestKnownResourceProfileMask =
    (1u << static_cast<u8>(ServiceManifestResourceProfile::Sandbox)) |
    (1u << static_cast<u8>(ServiceManifestResourceProfile::Trusted)) |
    (1u << static_cast<u8>(ServiceManifestResourceProfile::AuthenticatedService));

struct ServiceManifestDependencyV1
{
    u64 owner_service_identity;
    u64 dependency_service_identity;
};
static_assert(sizeof(ServiceManifestDependencyV1) == kServiceManifestV1DependencyBytes,
              "service dependency native mirror changed");

// Native scalar mirror of one decoded row.  Code must still use the explicit
// LE encoder/validator for byte input; no native cast is a supported decoder.
// `executable_path` is a canonical diagnostic/package label only.  Consumers
// must never reopen it: executable_transfer_ref is the sole source selector.
struct ServiceManifestServiceV1
{
    u64 service_identity;
    u32 executable_transfer_ref;
    u32 immutable_policy_selector;
    loader::Hash256 executable_content_hash;
    u64 requested_capability_ceiling;
    u64 requested_frame_budget_pages;
    u64 requested_tick_budget;
    u32 requested_section_objects;
    u32 requested_section_pages;
    u16 dependency_first;
    u16 dependency_count;
    u8 name_length;
    u8 executable_path_length;
    ServiceManifestKind kind;
    ServiceManifestRestartPolicy restart_policy;
    u8 autostart;
    ServiceManifestResourceProfile resource_profile;
    u16 flags;
    u32 reserved;
    u8 name[kServiceManifestServiceNameCapacity];
    u8 executable_path[kServiceManifestExecutablePathCapacity];
};
static_assert(sizeof(ServiceManifestServiceV1) == kServiceManifestV1ServiceBytes,
              "service row native mirror changed");

// Canonical native input accepted by the deterministic encoder.  Unused rows
// and dependencies must be zero so one logical document has one native form.
struct ServiceManifestDocumentV1
{
    u64 manifest_identity;
    u64 signer_identity;
    u64 profile_identity;
    u16 service_count;
    u16 dependency_count;
    u32 flags;
    u64 reserved;
    ServiceManifestServiceV1 services[kServiceManifestMaximumServices];
    ServiceManifestDependencyV1 dependencies[kServiceManifestMaximumDependencies];
};

// Retained kernel authority.  No field may be populated from the manifest or
// another IPC payload.  The package/transfer layer verifies the signature,
// freezes the object, and supplies its exact hash/extent here.
struct ServiceManifestAuthoritySnapshotV1
{
    u64 authority_identity;
    u64 manifest_identity;
    u64 signer_identity;
    u64 profile_identity;
    loader::Hash256 sealed_object_hash;
    u64 sealed_object_extent;
    u64 allowed_capabilities;
    u64 allowed_immutable_policies;
    u64 maximum_frame_budget_pages;
    u64 maximum_tick_budget;
    u32 allowed_service_kinds;
    u32 allowed_resource_profiles;
    u32 maximum_section_objects;
    u32 maximum_section_pages;
    u16 maximum_services;
    u16 maximum_dependencies;
    u32 flags;
    u64 reserved;
};

// Complete caller-owned result.  `topological_identities` contains stable
// identities, never array slots.  All entries beyond the published counts are
// zero, so the plan can be copied without retaining input bytes.
struct ServiceManifestPlanV1
{
    ServiceManifestDocumentV1 document;
    u64 authority_identity;
    loader::Hash256 sealed_object_hash;
    u64 sealed_object_extent;
    u16 topological_count;
    u16 reserved16;
    u32 reserved32;
    u64 topological_identities[kServiceManifestMaximumServices];
};

enum class ServiceManifestError : u8
{
    Ok = 0,
    NullArgument,
    InvalidPointerRange,
    AliasedOutput,
    DefinitionAliasesOutput,
    SnapshotFromWire,
    AuthorityMalformed,
    HeaderTruncated,
    ManifestTooLarge,
    OutputTooSmall,
    SizeOverflow,
    SizeMismatch,
    UnsupportedVersion,
    HeaderSizeMismatch,
    RecordSizeMismatch,
    InvalidOffsets,
    UnknownFlags,
    ReservedNonZero,
    InvalidManifestIdentity,
    SignerMismatch,
    ProfileMismatch,
    ObjectExtentMismatch,
    ObjectHashMismatch,
    NoServices,
    TooManyServices,
    TooManyDependencies,
    ServiceCountDenied,
    DependencyCountDenied,
    InvalidServiceIdentity,
    DuplicateServiceIdentity,
    InvalidServiceName,
    DuplicateServiceName,
    InvalidExecutablePath,
    InvalidTransferReference,
    MissingExecutableHash,
    InvalidImmutablePolicy,
    ImmutablePolicyDenied,
    InvalidServiceKind,
    ServiceKindDenied,
    InvalidRestartPolicy,
    InvalidAutostart,
    InvalidCapabilities,
    CapabilityDenied,
    InvalidResourceProfile,
    ResourceProfileDenied,
    InvalidResourceCeiling,
    ResourceCeilingDenied,
    InvalidFrameBudget,
    FrameBudgetDenied,
    InvalidTickBudget,
    TickBudgetDenied,
    InvalidDependencyRange,
    InvalidDependency,
    MissingDependency,
    DuplicateDependency,
    DependencyCycle,
    NonCanonicalUnusedStorage,
};

struct ServiceManifestEncodeResult
{
    ServiceManifestError error;
    u32 bytes_written;
};

inline constexpr u32 ServiceManifestEncodedSizeV1(u32 service_count, u32 dependency_count)
{
    return service_count > kServiceManifestMaximumServices ||
                   dependency_count > kServiceManifestMaximumDependencies
               ? 0
               : kServiceManifestV1HeaderBytes + service_count * kServiceManifestV1ServiceBytes +
                     dependency_count * kServiceManifestV1DependencyBytes;
}

// Representation-only check for a separately retained trusted snapshot.
// [any thread; pure, allocation-free, callback-free]
bool ServiceManifestAuthoritySnapshotIsCanonicalV1(const ServiceManifestAuthoritySnapshotV1& snapshot);

// Validate the complete native document shape, including canonical storage and
// DAG topology, but without granting signer/profile authority.
// [any thread; pure, allocation-free, callback-free]
ServiceManifestError ServiceManifestDocumentValidateV1(const ServiceManifestDocumentV1& document);

// Validate a native document and hash its exact canonical v1 wire encoding
// without materializing the full encoded object.  The implementation uses one
// service-row-sized scratch buffer.  Output must not overlap the document.
// Null, invalid-range, and alias failures leave output untouched; after a valid
// non-aliased output is established, every failure clears it.
// [any thread; pure, allocation-free, callback-free]
ServiceManifestError ServiceManifestDocumentHashV1(const ServiceManifestDocumentV1& document,
                                                   loader::Hash256* hash_out);

// Deterministic transactional LE encoding.  Invalid/aliased input performs no
// output write.  Success writes exactly bytes_written bytes.
// [any thread; pure, allocation-free, callback-free]
ServiceManifestEncodeResult ServiceManifestEncodeV1(void* output, u64 output_capacity,
                                                    const ServiceManifestDocumentV1& document);

// Validate stable bytes from the exact sealed object described by `authority`.
// The SHA-256 is recomputed over all `byte_count` bytes.  Output may not overlap
// the manifest or authority, and authority may not overlap the manifest.
// Alias/snapshot/pointer-range failures leave output untouched; every other
// failure clears it.  Callers must keep the sealed byte snapshot immutable for
// the full call.
// [any thread; pure, allocation-free, callback-free]
ServiceManifestError ServiceManifestValidateV1(const void* bytes, u64 byte_count,
                                               const ServiceManifestAuthoritySnapshotV1* authority,
                                               ServiceManifestPlanV1* plan_out);

const char* ServiceManifestErrorName(ServiceManifestError error);

} // namespace duetos::core
