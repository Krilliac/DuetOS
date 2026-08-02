#include "core/service_manifest.h"

#include "crypto/sha256.h"
#include "mm/address_space.h"
#include "proc/process.h"
#include "proc/resource_domain.h"

namespace duetos::core
{

namespace
{

constexpr u32 kHeaderTotalSizeOffset = 0;
constexpr u32 kHeaderVersionOffset = 4;
constexpr u32 kHeaderBytesOffset = 6;
constexpr u32 kHeaderServiceBytesOffset = 8;
constexpr u32 kHeaderDependencyBytesOffset = 10;
constexpr u32 kHeaderServiceCountOffset = 12;
constexpr u32 kHeaderDependencyCountOffset = 14;
constexpr u32 kHeaderFlagsOffset = 16;
constexpr u32 kHeaderReserved32Offset = 20;
constexpr u32 kHeaderManifestIdentityOffset = 24;
constexpr u32 kHeaderSignerIdentityOffset = 32;
constexpr u32 kHeaderProfileIdentityOffset = 40;
constexpr u32 kHeaderServicesOffset = 48;
constexpr u32 kHeaderDependenciesOffset = 52;
constexpr u32 kHeaderReserved64Offset = 56;

constexpr u32 kServiceIdentityOffset = 0;
constexpr u32 kServiceTransferRefOffset = 8;
constexpr u32 kServicePolicySelectorOffset = 12;
constexpr u32 kServiceContentHashOffset = 16;
constexpr u32 kServiceCapabilitiesOffset = 48;
constexpr u32 kServiceFrameBudgetOffset = 56;
constexpr u32 kServiceTickBudgetOffset = 64;
constexpr u32 kServiceSectionObjectsOffset = 72;
constexpr u32 kServiceSectionPagesOffset = 76;
constexpr u32 kServiceDependencyFirstOffset = 80;
constexpr u32 kServiceDependencyCountOffset = 82;
constexpr u32 kServiceNameLengthOffset = 84;
constexpr u32 kServicePathLengthOffset = 85;
constexpr u32 kServiceKindOffset = 86;
constexpr u32 kServiceRestartOffset = 87;
constexpr u32 kServiceAutostartOffset = 88;
constexpr u32 kServiceResourceProfileOffset = 89;
constexpr u32 kServiceFlagsOffset = 90;
constexpr u32 kServiceReservedOffset = 92;
constexpr u32 kServiceNameOffset = 96;
constexpr u32 kServicePathOffset = 128;

constexpr u32 kDependencyOwnerOffset = 0;
constexpr u32 kDependencyTargetOffset = 8;
constexpr u64 kIdentityReservedScope = ~0ULL;

static_assert(sizeof(loader::Hash256) == crypto::kSha256DigestBytes, "manifest hash width changed");
static_assert(kHeaderReserved64Offset + sizeof(u64) == kServiceManifestV1HeaderBytes,
              "manifest header offsets changed");
static_assert(kServicePathOffset + kServiceManifestExecutablePathCapacity == kServiceManifestV1ServiceBytes,
              "manifest service offsets changed");
static_assert(kDependencyTargetOffset + sizeof(u64) == kServiceManifestV1DependencyBytes,
              "manifest dependency offsets changed");
static_assert(kServiceManifestCapabilityMaskV1 == CapSetTrusted().bits,
              "process capabilities changed without a manifest v1 decision");
static_assert(kServiceManifestFrameBudgetMaximum == mm::kFrameBudgetTrusted,
              "frame ceiling changed without a manifest v1 decision");
static_assert(kServiceManifestTickBudgetMaximum == kTickBudgetTrusted,
              "tick ceiling changed without a manifest v1 decision");
static_assert(kServiceManifestSectionObjectMaximum == kAuthenticatedServiceSectionObjectLimit,
              "section object ceiling changed without a manifest v1 decision");
static_assert(kServiceManifestSectionPageMaximum == kAuthenticatedServiceSectionPageLimit,
              "section page ceiling changed without a manifest v1 decision");
static_assert(static_cast<u8>(ServiceManifestResourceProfile::Sandbox) ==
                      static_cast<u8>(ResourceDomainProfile::Sandbox) &&
                  static_cast<u8>(ServiceManifestResourceProfile::Trusted) ==
                      static_cast<u8>(ResourceDomainProfile::Trusted) &&
                  static_cast<u8>(ServiceManifestResourceProfile::AuthenticatedService) ==
                      static_cast<u8>(ResourceDomainProfile::AuthenticatedService),
              "resource profile numbering changed");

u16 ReadLe16(const u8* bytes)
{
    return static_cast<u16>(static_cast<u16>(bytes[0]) | (static_cast<u16>(bytes[1]) << 8u));
}

u32 ReadLe32(const u8* bytes)
{
    return static_cast<u32>(bytes[0]) | (static_cast<u32>(bytes[1]) << 8u) | (static_cast<u32>(bytes[2]) << 16u) |
           (static_cast<u32>(bytes[3]) << 24u);
}

u64 ReadLe64(const u8* bytes)
{
    return static_cast<u64>(ReadLe32(bytes)) | (static_cast<u64>(ReadLe32(bytes + 4)) << 32u);
}

void WriteLe16(u8* bytes, u16 value)
{
    bytes[0] = static_cast<u8>(value & 0xFFu);
    bytes[1] = static_cast<u8>((value >> 8u) & 0xFFu);
}

void WriteLe32(u8* bytes, u32 value)
{
    bytes[0] = static_cast<u8>(value & 0xFFu);
    bytes[1] = static_cast<u8>((value >> 8u) & 0xFFu);
    bytes[2] = static_cast<u8>((value >> 16u) & 0xFFu);
    bytes[3] = static_cast<u8>((value >> 24u) & 0xFFu);
}

void WriteLe64(u8* bytes, u64 value)
{
    WriteLe32(bytes, static_cast<u32>(value));
    WriteLe32(bytes + 4, static_cast<u32>(value >> 32u));
}

void ZeroBytes(void* destination, u64 byte_count)
{
    auto* bytes = static_cast<u8*>(destination);
    for (u64 index = 0; index < byte_count; ++index)
        bytes[index] = 0;
}

void CopyBytes(u8* destination, const u8* source, u32 byte_count)
{
    for (u32 index = 0; index < byte_count; ++index)
        destination[index] = source[index];
}

void ReadHash(const u8* bytes, loader::Hash256* hash)
{
    CopyBytes(hash->bytes, bytes, crypto::kSha256DigestBytes);
}

void WriteHash(u8* bytes, const loader::Hash256& hash)
{
    CopyBytes(bytes, hash.bytes, crypto::kSha256DigestBytes);
}

bool HashIsZero(const loader::Hash256& hash)
{
    u8 any = 0;
    for (u32 index = 0; index < crypto::kSha256DigestBytes; ++index)
        any = static_cast<u8>(any | hash.bytes[index]);
    return any == 0;
}

bool HashEquals(const loader::Hash256& left, const loader::Hash256& right)
{
    u8 difference = 0;
    for (u32 index = 0; index < crypto::kSha256DigestBytes; ++index)
        difference = static_cast<u8>(difference | (left.bytes[index] ^ right.bytes[index]));
    return difference == 0;
}

bool IdentityIsValid(u64 identity)
{
    return identity != 0 && identity != kIdentityReservedScope;
}

bool PointerRangeIsValid(const void* pointer, u64 byte_count)
{
    if (pointer == nullptr || byte_count == 0 || byte_count > static_cast<u64>(~static_cast<uptr>(0)))
        return false;
    const uptr begin = reinterpret_cast<uptr>(pointer);
    return static_cast<uptr>(byte_count) <= ~static_cast<uptr>(0) - begin;
}

bool PointerRangesOverlap(const void* left, u64 left_bytes, const void* right, u64 right_bytes)
{
    const uptr left_begin = reinterpret_cast<uptr>(left);
    const uptr right_begin = reinterpret_cast<uptr>(right);
    const uptr left_end = left_begin + static_cast<uptr>(left_bytes);
    const uptr right_end = right_begin + static_cast<uptr>(right_bytes);
    return left_begin < right_end && right_begin < left_end;
}

bool AllZero(const u8* bytes, u32 byte_count)
{
    u8 any = 0;
    for (u32 index = 0; index < byte_count; ++index)
        any = static_cast<u8>(any | bytes[index]);
    return any == 0;
}

bool NameCharacterIsCanonical(u8 value, bool first)
{
    const bool lowercase = value >= static_cast<u8>('a') && value <= static_cast<u8>('z');
    const bool digit = value >= static_cast<u8>('0') && value <= static_cast<u8>('9');
    if (first)
        return lowercase;
    return lowercase || digit || value == static_cast<u8>('-') || value == static_cast<u8>('_') ||
           value == static_cast<u8>('.');
}

bool NameIsCanonical(const ServiceManifestServiceV1& service)
{
    if (service.name_length == 0 || service.name_length > kServiceManifestServiceNameCapacity)
        return false;
    for (u32 index = 0; index < service.name_length; ++index)
    {
        if (!NameCharacterIsCanonical(service.name[index], index == 0))
            return false;
    }
    return AllZero(service.name + service.name_length, kServiceManifestServiceNameCapacity - service.name_length);
}

bool PathCharacterIsCanonical(u8 value)
{
    const bool lower = value >= static_cast<u8>('a') && value <= static_cast<u8>('z');
    const bool digit = value >= static_cast<u8>('0') && value <= static_cast<u8>('9');
    return lower || digit || value == static_cast<u8>('-') || value == static_cast<u8>('_') ||
           value == static_cast<u8>('.') || value == static_cast<u8>('/');
}

bool PathIsCanonical(const ServiceManifestServiceV1& service)
{
    const u32 length = service.executable_path_length;
    if (length < 2 || length > kServiceManifestExecutablePathCapacity ||
        service.executable_path[0] != static_cast<u8>('/') ||
        service.executable_path[length - 1] == static_cast<u8>('/'))
    {
        return false;
    }

    u32 component_start = 1;
    for (u32 index = 1; index <= length; ++index)
    {
        if (index < length && !PathCharacterIsCanonical(service.executable_path[index]))
            return false;
        if (index != length && service.executable_path[index] != static_cast<u8>('/'))
            continue;

        const u32 component_length = index - component_start;
        if (component_length == 0 ||
            (component_length == 1 && service.executable_path[component_start] == static_cast<u8>('.')) ||
            (component_length == 2 && service.executable_path[component_start] == static_cast<u8>('.') &&
             service.executable_path[component_start + 1] == static_cast<u8>('.')))
        {
            return false;
        }
        component_start = index + 1;
    }
    return AllZero(service.executable_path + length, kServiceManifestExecutablePathCapacity - length);
}

bool NamesEqual(const ServiceManifestServiceV1& left, const ServiceManifestServiceV1& right)
{
    if (left.name_length != right.name_length)
        return false;
    u8 difference = 0;
    for (u32 index = 0; index < left.name_length; ++index)
        difference = static_cast<u8>(difference | (left.name[index] ^ right.name[index]));
    return difference == 0;
}

bool KindIsValid(ServiceManifestKind kind)
{
    switch (kind)
    {
    case ServiceManifestKind::Native:
    case ServiceManifestKind::Win32:
    case ServiceManifestKind::Linux:
    case ServiceManifestKind::Broker:
        return true;
    case ServiceManifestKind::Invalid:
        return false;
    }
    return false;
}

bool RestartIsValid(ServiceManifestRestartPolicy policy)
{
    switch (policy)
    {
    case ServiceManifestRestartPolicy::Never:
    case ServiceManifestRestartPolicy::Always:
    case ServiceManifestRestartPolicy::OnFailure:
        return true;
    }
    return false;
}

bool ResourceProfileIsValid(ServiceManifestResourceProfile profile)
{
    switch (profile)
    {
    case ServiceManifestResourceProfile::Sandbox:
    case ServiceManifestResourceProfile::Trusted:
    case ServiceManifestResourceProfile::AuthenticatedService:
        return true;
    }
    return false;
}

u32 KindMask(ServiceManifestKind kind)
{
    return KindIsValid(kind) ? (1u << static_cast<u8>(kind)) : 0;
}

u32 ResourceProfileMask(ServiceManifestResourceProfile profile)
{
    return ResourceProfileIsValid(profile) ? (1u << static_cast<u8>(profile)) : 0;
}

u32 ResourceObjectMaximum(ServiceManifestResourceProfile profile)
{
    switch (profile)
    {
    case ServiceManifestResourceProfile::Sandbox:
        return kSandboxSectionObjectLimit;
    case ServiceManifestResourceProfile::Trusted:
        return kTrustedSectionObjectLimit;
    case ServiceManifestResourceProfile::AuthenticatedService:
        return kAuthenticatedServiceSectionObjectLimit;
    }
    return 0;
}

u32 ResourcePageMaximum(ServiceManifestResourceProfile profile)
{
    switch (profile)
    {
    case ServiceManifestResourceProfile::Sandbox:
        return kSandboxSectionPageLimitMaximum;
    case ServiceManifestResourceProfile::Trusted:
        return kTrustedSectionPageLimit;
    case ServiceManifestResourceProfile::AuthenticatedService:
        return kAuthenticatedServiceSectionPageLimit;
    }
    return 0;
}

u64 FrameMaximum(ServiceManifestResourceProfile profile)
{
    return profile == ServiceManifestResourceProfile::Sandbox ? mm::kFrameBudgetSandbox
                                                              : kServiceManifestFrameBudgetMaximum;
}

u64 TickMaximum(ServiceManifestResourceProfile profile)
{
    return profile == ServiceManifestResourceProfile::Sandbox ? kTickBudgetSandbox : kServiceManifestTickBudgetMaximum;
}

bool ServiceIsZero(const ServiceManifestServiceV1& service)
{
    return service.service_identity == 0 && service.executable_transfer_ref == 0 &&
           service.immutable_policy_selector == 0 && HashIsZero(service.executable_content_hash) &&
           service.requested_capability_ceiling == 0 && service.requested_frame_budget_pages == 0 &&
           service.requested_tick_budget == 0 && service.requested_section_objects == 0 &&
           service.requested_section_pages == 0 && service.dependency_first == 0 && service.dependency_count == 0 &&
           service.name_length == 0 && service.executable_path_length == 0 &&
           service.kind == ServiceManifestKind::Invalid &&
           service.restart_policy == ServiceManifestRestartPolicy::Never && service.autostart == 0 &&
           service.resource_profile == ServiceManifestResourceProfile::Sandbox && service.flags == 0 &&
           service.reserved == 0 && AllZero(service.name, kServiceManifestServiceNameCapacity) &&
           AllZero(service.executable_path, kServiceManifestExecutablePathCapacity);
}

ServiceManifestError ValidateService(const ServiceManifestServiceV1& service,
                                     const ServiceManifestAuthoritySnapshotV1* authority)
{
    if (!IdentityIsValid(service.service_identity))
        return ServiceManifestError::InvalidServiceIdentity;
    if (service.flags != kServiceManifestV1KnownFlags)
        return ServiceManifestError::UnknownFlags;
    if (service.reserved != 0)
        return ServiceManifestError::ReservedNonZero;
    if (!NameIsCanonical(service))
        return ServiceManifestError::InvalidServiceName;
    if (!PathIsCanonical(service))
        return ServiceManifestError::InvalidExecutablePath;
    if (service.executable_transfer_ref == 0 ||
        service.executable_transfer_ref > kServiceManifestPositiveTransferRefMaximum)
    {
        return ServiceManifestError::InvalidTransferReference;
    }
    if (HashIsZero(service.executable_content_hash))
        return ServiceManifestError::MissingExecutableHash;
    if (service.immutable_policy_selector == 0 || service.immutable_policy_selector >= 64)
        return ServiceManifestError::InvalidImmutablePolicy;
    if (authority != nullptr &&
        (authority->allowed_immutable_policies & (1ULL << service.immutable_policy_selector)) == 0)
    {
        return ServiceManifestError::ImmutablePolicyDenied;
    }
    if (!KindIsValid(service.kind))
        return ServiceManifestError::InvalidServiceKind;
    if (authority != nullptr && (authority->allowed_service_kinds & KindMask(service.kind)) == 0)
        return ServiceManifestError::ServiceKindDenied;
    if (!RestartIsValid(service.restart_policy))
        return ServiceManifestError::InvalidRestartPolicy;
    if (service.autostart > 1)
        return ServiceManifestError::InvalidAutostart;
    if ((service.requested_capability_ceiling & ~kServiceManifestCapabilityMaskV1) != 0)
        return ServiceManifestError::InvalidCapabilities;
    if (authority != nullptr && (service.requested_capability_ceiling & ~authority->allowed_capabilities) != 0)
        return ServiceManifestError::CapabilityDenied;
    if (!ResourceProfileIsValid(service.resource_profile))
        return ServiceManifestError::InvalidResourceProfile;
    if (authority != nullptr &&
        (authority->allowed_resource_profiles & ResourceProfileMask(service.resource_profile)) == 0)
    {
        return ServiceManifestError::ResourceProfileDenied;
    }
    if (service.requested_section_objects == 0 || service.requested_section_pages == 0 ||
        service.requested_section_objects > ResourceObjectMaximum(service.resource_profile) ||
        service.requested_section_pages > ResourcePageMaximum(service.resource_profile))
    {
        return ServiceManifestError::InvalidResourceCeiling;
    }
    if (authority != nullptr && (service.requested_section_objects > authority->maximum_section_objects ||
                                 service.requested_section_pages > authority->maximum_section_pages))
    {
        return ServiceManifestError::ResourceCeilingDenied;
    }
    if (service.requested_frame_budget_pages == 0 ||
        service.requested_frame_budget_pages > FrameMaximum(service.resource_profile))
    {
        return ServiceManifestError::InvalidFrameBudget;
    }
    if (authority != nullptr && service.requested_frame_budget_pages > authority->maximum_frame_budget_pages)
    {
        return ServiceManifestError::FrameBudgetDenied;
    }
    if (service.requested_tick_budget == 0 || service.requested_tick_budget > TickMaximum(service.resource_profile))
        return ServiceManifestError::InvalidTickBudget;
    if (authority != nullptr && service.requested_tick_budget > authority->maximum_tick_budget)
        return ServiceManifestError::TickBudgetDenied;
    if (service.dependency_count > kServiceManifestMaximumDependenciesPerService)
        return ServiceManifestError::InvalidDependencyRange;
    return ServiceManifestError::Ok;
}

u32 FindService(const ServiceManifestDocumentV1& document, u64 identity)
{
    u32 low = 0;
    u32 high = document.service_count;
    while (low < high)
    {
        const u32 middle = low + (high - low) / 2u;
        const u64 candidate = document.services[middle].service_identity;
        if (candidate < identity)
            low = middle + 1u;
        else
            high = middle;
    }
    return low < document.service_count && document.services[low].service_identity == identity
               ? low
               : kServiceManifestMaximumServices;
}

ServiceManifestError ValidateGraph(const ServiceManifestDocumentV1& document, u64* topological_identities)
{
    u16 indegree[kServiceManifestMaximumServices]{};
    bool emitted[kServiceManifestMaximumServices]{};
    for (u32 index = 0; index < document.service_count; ++index)
        indegree[index] = document.services[index].dependency_count;

    for (u32 output_index = 0; output_index < document.service_count; ++output_index)
    {
        u32 selected = kServiceManifestMaximumServices;
        for (u32 candidate = 0; candidate < document.service_count; ++candidate)
        {
            if (!emitted[candidate] && indegree[candidate] == 0)
            {
                selected = candidate;
                break; // Rows are identity-sorted: first is deterministic.
            }
        }
        if (selected == kServiceManifestMaximumServices)
            return ServiceManifestError::DependencyCycle;

        emitted[selected] = true;
        const u64 resolved_identity = document.services[selected].service_identity;
        if (topological_identities != nullptr)
            topological_identities[output_index] = resolved_identity;

        for (u32 dependent = 0; dependent < document.service_count; ++dependent)
        {
            if (emitted[dependent] || indegree[dependent] == 0)
                continue;
            const ServiceManifestServiceV1& row = document.services[dependent];
            for (u32 edge_index = row.dependency_first;
                 edge_index < static_cast<u32>(row.dependency_first) + row.dependency_count; ++edge_index)
            {
                if (document.dependencies[edge_index].dependency_service_identity == resolved_identity)
                {
                    --indegree[dependent];
                    break;
                }
            }
        }
    }
    return ServiceManifestError::Ok;
}

ServiceManifestError ValidateDocumentInternal(const ServiceManifestDocumentV1& document,
                                              const ServiceManifestAuthoritySnapshotV1* authority,
                                              u64* topological_identities)
{
    if (!IdentityIsValid(document.manifest_identity) || !IdentityIsValid(document.signer_identity) ||
        !IdentityIsValid(document.profile_identity))
    {
        return ServiceManifestError::InvalidManifestIdentity;
    }
    if (document.flags != kServiceManifestV1KnownFlags)
        return ServiceManifestError::UnknownFlags;
    if (document.reserved != 0)
        return ServiceManifestError::ReservedNonZero;
    if (document.service_count == 0)
        return ServiceManifestError::NoServices;
    if (document.service_count > kServiceManifestMaximumServices)
        return ServiceManifestError::TooManyServices;
    if (document.dependency_count > kServiceManifestMaximumDependencies)
        return ServiceManifestError::TooManyDependencies;
    if (authority != nullptr)
    {
        if (document.service_count > authority->maximum_services)
            return ServiceManifestError::ServiceCountDenied;
        if (document.dependency_count > authority->maximum_dependencies)
            return ServiceManifestError::DependencyCountDenied;
    }

    u32 dependency_cursor = 0;
    for (u32 index = 0; index < document.service_count; ++index)
    {
        const ServiceManifestServiceV1& service = document.services[index];
        const ServiceManifestError service_error = ValidateService(service, authority);
        if (service_error != ServiceManifestError::Ok)
            return service_error;
        if (index != 0 && document.services[index - 1].service_identity >= service.service_identity)
        {
            return document.services[index - 1].service_identity == service.service_identity
                       ? ServiceManifestError::DuplicateServiceIdentity
                       : ServiceManifestError::InvalidServiceIdentity;
        }
        for (u32 previous = 0; previous < index; ++previous)
        {
            if (NamesEqual(document.services[previous], service))
                return ServiceManifestError::DuplicateServiceName;
            if (document.services[previous].executable_transfer_ref == service.executable_transfer_ref)
                return ServiceManifestError::DuplicateTransferReference;
        }
        if (service.dependency_first != dependency_cursor ||
            static_cast<u32>(service.dependency_count) > document.dependency_count - dependency_cursor)
        {
            return ServiceManifestError::InvalidDependencyRange;
        }

        u64 previous_dependency = 0;
        for (u32 edge_index = dependency_cursor; edge_index < dependency_cursor + service.dependency_count;
             ++edge_index)
        {
            const ServiceManifestDependencyV1& edge = document.dependencies[edge_index];
            if (edge.owner_service_identity != service.service_identity ||
                !IdentityIsValid(edge.dependency_service_identity) ||
                edge.dependency_service_identity == service.service_identity)
            {
                return ServiceManifestError::InvalidDependency;
            }
            if (edge.dependency_service_identity <= previous_dependency)
            {
                return edge.dependency_service_identity == previous_dependency
                           ? ServiceManifestError::DuplicateDependency
                           : ServiceManifestError::InvalidDependency;
            }
            previous_dependency = edge.dependency_service_identity;
        }
        dependency_cursor += service.dependency_count;
    }
    if (dependency_cursor != document.dependency_count)
        return ServiceManifestError::InvalidDependencyRange;

    for (u32 edge_index = 0; edge_index < document.dependency_count; ++edge_index)
    {
        if (FindService(document, document.dependencies[edge_index].dependency_service_identity) ==
            kServiceManifestMaximumServices)
        {
            return ServiceManifestError::MissingDependency;
        }
    }
    for (u32 index = document.service_count; index < kServiceManifestMaximumServices; ++index)
    {
        if (!ServiceIsZero(document.services[index]))
            return ServiceManifestError::NonCanonicalUnusedStorage;
    }
    for (u32 index = document.dependency_count; index < kServiceManifestMaximumDependencies; ++index)
    {
        if (document.dependencies[index].owner_service_identity != 0 ||
            document.dependencies[index].dependency_service_identity != 0)
        {
            return ServiceManifestError::NonCanonicalUnusedStorage;
        }
    }
    return ValidateGraph(document, topological_identities);
}

u32 EncodedDependenciesOffset(const ServiceManifestDocumentV1& document)
{
    return kServiceManifestV1HeaderBytes + document.service_count * kServiceManifestV1ServiceBytes;
}

void EncodeHeader(u8* bytes, const ServiceManifestDocumentV1& document, u32 encoded_size)
{
    WriteLe32(bytes + kHeaderTotalSizeOffset, encoded_size);
    WriteLe16(bytes + kHeaderVersionOffset, kServiceManifestVersion1);
    WriteLe16(bytes + kHeaderBytesOffset, static_cast<u16>(kServiceManifestV1HeaderBytes));
    WriteLe16(bytes + kHeaderServiceBytesOffset, static_cast<u16>(kServiceManifestV1ServiceBytes));
    WriteLe16(bytes + kHeaderDependencyBytesOffset, static_cast<u16>(kServiceManifestV1DependencyBytes));
    WriteLe16(bytes + kHeaderServiceCountOffset, document.service_count);
    WriteLe16(bytes + kHeaderDependencyCountOffset, document.dependency_count);
    WriteLe32(bytes + kHeaderFlagsOffset, document.flags);
    WriteLe64(bytes + kHeaderManifestIdentityOffset, document.manifest_identity);
    WriteLe64(bytes + kHeaderSignerIdentityOffset, document.signer_identity);
    WriteLe64(bytes + kHeaderProfileIdentityOffset, document.profile_identity);
    WriteLe32(bytes + kHeaderServicesOffset, kServiceManifestV1HeaderBytes);
    WriteLe32(bytes + kHeaderDependenciesOffset, EncodedDependenciesOffset(document));
}

void EncodeService(u8* bytes, const ServiceManifestServiceV1& service)
{
    WriteLe64(bytes + kServiceIdentityOffset, service.service_identity);
    WriteLe32(bytes + kServiceTransferRefOffset, service.executable_transfer_ref);
    WriteLe32(bytes + kServicePolicySelectorOffset, service.immutable_policy_selector);
    WriteHash(bytes + kServiceContentHashOffset, service.executable_content_hash);
    WriteLe64(bytes + kServiceCapabilitiesOffset, service.requested_capability_ceiling);
    WriteLe64(bytes + kServiceFrameBudgetOffset, service.requested_frame_budget_pages);
    WriteLe64(bytes + kServiceTickBudgetOffset, service.requested_tick_budget);
    WriteLe32(bytes + kServiceSectionObjectsOffset, service.requested_section_objects);
    WriteLe32(bytes + kServiceSectionPagesOffset, service.requested_section_pages);
    WriteLe16(bytes + kServiceDependencyFirstOffset, service.dependency_first);
    WriteLe16(bytes + kServiceDependencyCountOffset, service.dependency_count);
    bytes[kServiceNameLengthOffset] = service.name_length;
    bytes[kServicePathLengthOffset] = service.executable_path_length;
    bytes[kServiceKindOffset] = static_cast<u8>(service.kind);
    bytes[kServiceRestartOffset] = static_cast<u8>(service.restart_policy);
    bytes[kServiceAutostartOffset] = service.autostart;
    bytes[kServiceResourceProfileOffset] = static_cast<u8>(service.resource_profile);
    WriteLe16(bytes + kServiceFlagsOffset, service.flags);
    WriteLe32(bytes + kServiceReservedOffset, service.reserved);
    CopyBytes(bytes + kServiceNameOffset, service.name, kServiceManifestServiceNameCapacity);
    CopyBytes(bytes + kServicePathOffset, service.executable_path, kServiceManifestExecutablePathCapacity);
}

void EncodeDependency(u8* bytes, const ServiceManifestDependencyV1& dependency)
{
    WriteLe64(bytes + kDependencyOwnerOffset, dependency.owner_service_identity);
    WriteLe64(bytes + kDependencyTargetOffset, dependency.dependency_service_identity);
}

void DecodeService(const u8* bytes, ServiceManifestServiceV1* service)
{
    service->service_identity = ReadLe64(bytes + kServiceIdentityOffset);
    service->executable_transfer_ref = ReadLe32(bytes + kServiceTransferRefOffset);
    service->immutable_policy_selector = ReadLe32(bytes + kServicePolicySelectorOffset);
    ReadHash(bytes + kServiceContentHashOffset, &service->executable_content_hash);
    service->requested_capability_ceiling = ReadLe64(bytes + kServiceCapabilitiesOffset);
    service->requested_frame_budget_pages = ReadLe64(bytes + kServiceFrameBudgetOffset);
    service->requested_tick_budget = ReadLe64(bytes + kServiceTickBudgetOffset);
    service->requested_section_objects = ReadLe32(bytes + kServiceSectionObjectsOffset);
    service->requested_section_pages = ReadLe32(bytes + kServiceSectionPagesOffset);
    service->dependency_first = ReadLe16(bytes + kServiceDependencyFirstOffset);
    service->dependency_count = ReadLe16(bytes + kServiceDependencyCountOffset);
    service->name_length = bytes[kServiceNameLengthOffset];
    service->executable_path_length = bytes[kServicePathLengthOffset];
    service->kind = static_cast<ServiceManifestKind>(bytes[kServiceKindOffset]);
    service->restart_policy = static_cast<ServiceManifestRestartPolicy>(bytes[kServiceRestartOffset]);
    service->autostart = bytes[kServiceAutostartOffset];
    service->resource_profile = static_cast<ServiceManifestResourceProfile>(bytes[kServiceResourceProfileOffset]);
    service->flags = ReadLe16(bytes + kServiceFlagsOffset);
    service->reserved = ReadLe32(bytes + kServiceReservedOffset);
    CopyBytes(service->name, bytes + kServiceNameOffset, kServiceManifestServiceNameCapacity);
    CopyBytes(service->executable_path, bytes + kServicePathOffset, kServiceManifestExecutablePathCapacity);
}

ServiceManifestError FailPlan(ServiceManifestPlanV1* plan, ServiceManifestError error)
{
    ZeroBytes(plan, sizeof(ServiceManifestPlanV1));
    return error;
}

} // namespace

bool ServiceManifestAuthoritySnapshotIsCanonicalV1(const ServiceManifestAuthoritySnapshotV1& snapshot)
{
    return IdentityIsValid(snapshot.authority_identity) && IdentityIsValid(snapshot.manifest_identity) &&
           IdentityIsValid(snapshot.signer_identity) && IdentityIsValid(snapshot.profile_identity) &&
           !HashIsZero(snapshot.sealed_object_hash) &&
           snapshot.sealed_object_extent >= kServiceManifestV1HeaderBytes + kServiceManifestV1ServiceBytes &&
           snapshot.sealed_object_extent <= kServiceManifestMaximumBytes &&
           (snapshot.allowed_capabilities & ~kServiceManifestCapabilityMaskV1) == 0 &&
           snapshot.allowed_immutable_policies != 0 && (snapshot.allowed_immutable_policies & 1ULL) == 0 &&
           snapshot.maximum_frame_budget_pages != 0 &&
           snapshot.maximum_frame_budget_pages <= kServiceManifestFrameBudgetMaximum &&
           snapshot.maximum_tick_budget != 0 && snapshot.maximum_tick_budget <= kServiceManifestTickBudgetMaximum &&
           snapshot.allowed_service_kinds != 0 &&
           (snapshot.allowed_service_kinds & ~kServiceManifestKnownKindMask) == 0 &&
           snapshot.allowed_resource_profiles != 0 &&
           (snapshot.allowed_resource_profiles & ~kServiceManifestKnownResourceProfileMask) == 0 &&
           snapshot.maximum_section_objects != 0 &&
           snapshot.maximum_section_objects <= kServiceManifestSectionObjectMaximum &&
           snapshot.maximum_section_pages != 0 &&
           snapshot.maximum_section_pages <= kServiceManifestSectionPageMaximum && snapshot.maximum_services != 0 &&
           snapshot.maximum_services <= kServiceManifestMaximumServices &&
           snapshot.maximum_dependencies <= kServiceManifestMaximumDependencies &&
           snapshot.flags == kServiceManifestAuthoritySealed && snapshot.reserved == 0;
}

ServiceManifestError ServiceManifestDocumentValidateV1(const ServiceManifestDocumentV1& document)
{
    return ValidateDocumentInternal(document, nullptr, nullptr);
}

ServiceManifestError ServiceManifestDocumentValidateAgainstAuthorityV1(
    const ServiceManifestDocumentV1& document, const ServiceManifestAuthoritySnapshotV1& authority)
{
    if (!ServiceManifestAuthoritySnapshotIsCanonicalV1(authority))
        return ServiceManifestError::AuthorityMalformed;
    if (!IdentityIsValid(document.manifest_identity) || document.manifest_identity != authority.manifest_identity)
        return ServiceManifestError::InvalidManifestIdentity;
    if (document.signer_identity != authority.signer_identity)
        return ServiceManifestError::SignerMismatch;
    if (document.profile_identity != authority.profile_identity)
        return ServiceManifestError::ProfileMismatch;
    return ValidateDocumentInternal(document, &authority, nullptr);
}

ServiceManifestError ServiceManifestDocumentHashV1(const ServiceManifestDocumentV1& document, loader::Hash256* hash_out)
{
    if (hash_out == nullptr)
        return ServiceManifestError::NullArgument;
    if (!PointerRangeIsValid(hash_out, sizeof(*hash_out)))
        return ServiceManifestError::InvalidPointerRange;
    if (PointerRangesOverlap(hash_out, sizeof(*hash_out), &document, sizeof(document)))
        return ServiceManifestError::DefinitionAliasesOutput;

    ZeroBytes(hash_out, sizeof(*hash_out));
    const ServiceManifestError document_error = ServiceManifestDocumentValidateV1(document);
    if (document_error != ServiceManifestError::Ok)
        return document_error;

    const u32 encoded_size = ServiceManifestEncodedSizeV1(document.service_count, document.dependency_count);
    if (encoded_size == 0)
        return ServiceManifestError::SizeOverflow;

    crypto::Sha256Ctx context{};
    u8 scratch[kServiceManifestV1ServiceBytes]{};
    crypto::Sha256Init(context);

    EncodeHeader(scratch, document, encoded_size);
    crypto::Sha256Update(context, scratch, kServiceManifestV1HeaderBytes);
    for (u32 index = 0; index < document.service_count; ++index)
    {
        ZeroBytes(scratch, sizeof(scratch));
        EncodeService(scratch, document.services[index]);
        crypto::Sha256Update(context, scratch, kServiceManifestV1ServiceBytes);
    }
    for (u32 index = 0; index < document.dependency_count; ++index)
    {
        ZeroBytes(scratch, kServiceManifestV1DependencyBytes);
        EncodeDependency(scratch, document.dependencies[index]);
        crypto::Sha256Update(context, scratch, kServiceManifestV1DependencyBytes);
    }
    crypto::Sha256Final(context, hash_out->bytes);
    return ServiceManifestError::Ok;
}

ServiceManifestEncodeResult ServiceManifestEncodeV1(void* output, u64 output_capacity,
                                                    const ServiceManifestDocumentV1& document)
{
    if (output == nullptr)
        return ServiceManifestEncodeResult{ServiceManifestError::NullArgument, 0};
    const ServiceManifestError document_error = ServiceManifestDocumentValidateV1(document);
    if (document_error != ServiceManifestError::Ok)
        return ServiceManifestEncodeResult{document_error, 0};

    const u32 encoded_size = ServiceManifestEncodedSizeV1(document.service_count, document.dependency_count);
    if (encoded_size == 0)
        return ServiceManifestEncodeResult{ServiceManifestError::SizeOverflow, 0};
    if (output_capacity < encoded_size)
        return ServiceManifestEncodeResult{ServiceManifestError::OutputTooSmall, 0};
    if (!PointerRangeIsValid(output, encoded_size))
        return ServiceManifestEncodeResult{ServiceManifestError::InvalidPointerRange, 0};
    if (PointerRangesOverlap(output, encoded_size, &document, sizeof(ServiceManifestDocumentV1)))
        return ServiceManifestEncodeResult{ServiceManifestError::DefinitionAliasesOutput, 0};

    ZeroBytes(output, encoded_size);
    auto* bytes = static_cast<u8*>(output);
    const u32 dependencies_offset = EncodedDependenciesOffset(document);
    EncodeHeader(bytes, document, encoded_size);

    for (u32 index = 0; index < document.service_count; ++index)
    {
        EncodeService(bytes + kServiceManifestV1HeaderBytes + index * kServiceManifestV1ServiceBytes,
                      document.services[index]);
    }
    for (u32 index = 0; index < document.dependency_count; ++index)
    {
        u8* edge = bytes + dependencies_offset + index * kServiceManifestV1DependencyBytes;
        EncodeDependency(edge, document.dependencies[index]);
    }
    return ServiceManifestEncodeResult{ServiceManifestError::Ok, encoded_size};
}

ServiceManifestError ServiceManifestValidateV1(const void* bytes_void, u64 byte_count,
                                               const ServiceManifestAuthoritySnapshotV1* authority,
                                               ServiceManifestPlanV1* plan_out)
{
    if (plan_out == nullptr)
        return ServiceManifestError::NullArgument;
    if (!PointerRangeIsValid(plan_out, sizeof(ServiceManifestPlanV1)))
        return ServiceManifestError::InvalidPointerRange;
    if (authority != nullptr && !PointerRangeIsValid(authority, sizeof(ServiceManifestAuthoritySnapshotV1)))
        return ServiceManifestError::InvalidPointerRange;
    if (bytes_void != nullptr && byte_count != 0 && !PointerRangeIsValid(bytes_void, byte_count))
        return ServiceManifestError::InvalidPointerRange;
    if (authority != nullptr && PointerRangesOverlap(plan_out, sizeof(ServiceManifestPlanV1), authority,
                                                     sizeof(ServiceManifestAuthoritySnapshotV1)))
    {
        return ServiceManifestError::AliasedOutput;
    }
    if (bytes_void != nullptr && byte_count != 0 &&
        PointerRangesOverlap(plan_out, sizeof(ServiceManifestPlanV1), bytes_void, byte_count))
    {
        return ServiceManifestError::AliasedOutput;
    }
    if (authority != nullptr && bytes_void != nullptr && byte_count != 0 &&
        PointerRangesOverlap(authority, sizeof(ServiceManifestAuthoritySnapshotV1), bytes_void, byte_count))
    {
        return ServiceManifestError::SnapshotFromWire;
    }
    if (bytes_void == nullptr || authority == nullptr)
        return FailPlan(plan_out, ServiceManifestError::NullArgument);

    const ServiceManifestAuthoritySnapshotV1 authority_snapshot = *authority;
    ZeroBytes(plan_out, sizeof(ServiceManifestPlanV1));
    if (byte_count > kServiceManifestMaximumBytes)
        return ServiceManifestError::ManifestTooLarge;
    if (byte_count == 0)
        return ServiceManifestError::HeaderTruncated;
    if (!ServiceManifestAuthoritySnapshotIsCanonicalV1(authority_snapshot))
        return ServiceManifestError::AuthorityMalformed;
    if (byte_count < kServiceManifestV1HeaderBytes)
        return ServiceManifestError::HeaderTruncated;
    if (authority_snapshot.sealed_object_extent != byte_count)
        return ServiceManifestError::ObjectExtentMismatch;

    const auto* bytes = static_cast<const u8*>(bytes_void);
    loader::Hash256 computed_hash{};
    crypto::Sha256Hash(bytes, static_cast<u32>(byte_count), computed_hash.bytes);
    if (!HashEquals(computed_hash, authority_snapshot.sealed_object_hash))
        return ServiceManifestError::ObjectHashMismatch;

    const u32 encoded_size = ReadLe32(bytes + kHeaderTotalSizeOffset);
    const u16 version = ReadLe16(bytes + kHeaderVersionOffset);
    const u16 header_bytes = ReadLe16(bytes + kHeaderBytesOffset);
    const u16 service_bytes = ReadLe16(bytes + kHeaderServiceBytesOffset);
    const u16 dependency_bytes = ReadLe16(bytes + kHeaderDependencyBytesOffset);
    const u16 service_count = ReadLe16(bytes + kHeaderServiceCountOffset);
    const u16 dependency_count = ReadLe16(bytes + kHeaderDependencyCountOffset);
    const u32 flags = ReadLe32(bytes + kHeaderFlagsOffset);
    const u32 reserved32 = ReadLe32(bytes + kHeaderReserved32Offset);
    const u64 manifest_identity = ReadLe64(bytes + kHeaderManifestIdentityOffset);
    const u64 signer_identity = ReadLe64(bytes + kHeaderSignerIdentityOffset);
    const u64 profile_identity = ReadLe64(bytes + kHeaderProfileIdentityOffset);
    const u32 services_offset = ReadLe32(bytes + kHeaderServicesOffset);
    const u32 dependencies_offset = ReadLe32(bytes + kHeaderDependenciesOffset);
    const u64 reserved64 = ReadLe64(bytes + kHeaderReserved64Offset);

    if (encoded_size != byte_count)
        return ServiceManifestError::SizeMismatch;
    if (version != kServiceManifestVersion1)
        return ServiceManifestError::UnsupportedVersion;
    if (header_bytes != kServiceManifestV1HeaderBytes)
        return ServiceManifestError::HeaderSizeMismatch;
    if (service_bytes != kServiceManifestV1ServiceBytes || dependency_bytes != kServiceManifestV1DependencyBytes)
    {
        return ServiceManifestError::RecordSizeMismatch;
    }
    if (service_count == 0)
        return ServiceManifestError::NoServices;
    if (service_count > kServiceManifestMaximumServices)
        return ServiceManifestError::TooManyServices;
    if (dependency_count > kServiceManifestMaximumDependencies)
        return ServiceManifestError::TooManyDependencies;
    const u32 expected_size = ServiceManifestEncodedSizeV1(service_count, dependency_count);
    const u32 expected_dependencies_offset =
        kServiceManifestV1HeaderBytes + service_count * kServiceManifestV1ServiceBytes;
    if (expected_size == 0)
        return ServiceManifestError::SizeOverflow;
    if (expected_size != encoded_size)
        return ServiceManifestError::SizeMismatch;
    if (services_offset != kServiceManifestV1HeaderBytes || dependencies_offset != expected_dependencies_offset)
        return ServiceManifestError::InvalidOffsets;
    if (flags != kServiceManifestV1KnownFlags)
        return ServiceManifestError::UnknownFlags;
    if (reserved32 != 0 || reserved64 != 0)
        return ServiceManifestError::ReservedNonZero;
    if (!IdentityIsValid(manifest_identity) || manifest_identity != authority_snapshot.manifest_identity)
        return ServiceManifestError::InvalidManifestIdentity;
    if (signer_identity != authority_snapshot.signer_identity)
        return ServiceManifestError::SignerMismatch;
    if (profile_identity != authority_snapshot.profile_identity)
        return ServiceManifestError::ProfileMismatch;
    if (service_count > authority_snapshot.maximum_services)
        return ServiceManifestError::ServiceCountDenied;
    if (dependency_count > authority_snapshot.maximum_dependencies)
        return ServiceManifestError::DependencyCountDenied;

    ServiceManifestDocumentV1& document = plan_out->document;
    document.manifest_identity = manifest_identity;
    document.signer_identity = signer_identity;
    document.profile_identity = profile_identity;
    document.service_count = service_count;
    document.dependency_count = dependency_count;
    document.flags = flags;
    for (u32 index = 0; index < service_count; ++index)
    {
        DecodeService(bytes + services_offset + index * kServiceManifestV1ServiceBytes, &document.services[index]);
    }
    for (u32 index = 0; index < dependency_count; ++index)
    {
        const u8* edge = bytes + dependencies_offset + index * kServiceManifestV1DependencyBytes;
        document.dependencies[index].owner_service_identity = ReadLe64(edge + kDependencyOwnerOffset);
        document.dependencies[index].dependency_service_identity = ReadLe64(edge + kDependencyTargetOffset);
    }

    const ServiceManifestError document_error =
        ValidateDocumentInternal(document, &authority_snapshot, plan_out->topological_identities);
    if (document_error != ServiceManifestError::Ok)
        return FailPlan(plan_out, document_error);

    plan_out->authority_identity = authority_snapshot.authority_identity;
    plan_out->sealed_object_hash = authority_snapshot.sealed_object_hash;
    plan_out->sealed_object_extent = authority_snapshot.sealed_object_extent;
    plan_out->topological_count = service_count;
    return ServiceManifestError::Ok;
}

const char* ServiceManifestErrorName(ServiceManifestError error)
{
    switch (error)
    {
    case ServiceManifestError::Ok:
        return "ok";
    case ServiceManifestError::NullArgument:
        return "null-argument";
    case ServiceManifestError::InvalidPointerRange:
        return "invalid-pointer-range";
    case ServiceManifestError::AliasedOutput:
        return "aliased-output";
    case ServiceManifestError::DefinitionAliasesOutput:
        return "definition-aliases-output";
    case ServiceManifestError::SnapshotFromWire:
        return "snapshot-from-wire";
    case ServiceManifestError::AuthorityMalformed:
        return "authority-malformed";
    case ServiceManifestError::HeaderTruncated:
        return "header-truncated";
    case ServiceManifestError::ManifestTooLarge:
        return "manifest-too-large";
    case ServiceManifestError::OutputTooSmall:
        return "output-too-small";
    case ServiceManifestError::SizeOverflow:
        return "size-overflow";
    case ServiceManifestError::SizeMismatch:
        return "size-mismatch";
    case ServiceManifestError::UnsupportedVersion:
        return "unsupported-version";
    case ServiceManifestError::HeaderSizeMismatch:
        return "header-size-mismatch";
    case ServiceManifestError::RecordSizeMismatch:
        return "record-size-mismatch";
    case ServiceManifestError::InvalidOffsets:
        return "invalid-offsets";
    case ServiceManifestError::UnknownFlags:
        return "unknown-flags";
    case ServiceManifestError::ReservedNonZero:
        return "reserved-nonzero";
    case ServiceManifestError::InvalidManifestIdentity:
        return "invalid-manifest-identity";
    case ServiceManifestError::SignerMismatch:
        return "signer-mismatch";
    case ServiceManifestError::ProfileMismatch:
        return "profile-mismatch";
    case ServiceManifestError::ObjectExtentMismatch:
        return "object-extent-mismatch";
    case ServiceManifestError::ObjectHashMismatch:
        return "object-hash-mismatch";
    case ServiceManifestError::NoServices:
        return "no-services";
    case ServiceManifestError::TooManyServices:
        return "too-many-services";
    case ServiceManifestError::TooManyDependencies:
        return "too-many-dependencies";
    case ServiceManifestError::InvalidServiceIdentity:
        return "invalid-service-identity";
    case ServiceManifestError::DuplicateServiceIdentity:
        return "duplicate-service-identity";
    case ServiceManifestError::InvalidServiceName:
        return "invalid-service-name";
    case ServiceManifestError::DuplicateServiceName:
        return "duplicate-service-name";
    case ServiceManifestError::InvalidExecutablePath:
        return "invalid-executable-path";
    case ServiceManifestError::InvalidTransferReference:
        return "invalid-transfer-reference";
    case ServiceManifestError::DuplicateTransferReference:
        return "duplicate-transfer-reference";
    case ServiceManifestError::MissingExecutableHash:
        return "missing-executable-hash";
    case ServiceManifestError::InvalidImmutablePolicy:
        return "invalid-immutable-policy";
    case ServiceManifestError::ImmutablePolicyDenied:
        return "immutable-policy-denied";
    case ServiceManifestError::InvalidServiceKind:
        return "invalid-service-kind";
    case ServiceManifestError::ServiceKindDenied:
        return "service-kind-denied";
    case ServiceManifestError::InvalidRestartPolicy:
        return "invalid-restart-policy";
    case ServiceManifestError::InvalidAutostart:
        return "invalid-autostart";
    case ServiceManifestError::InvalidCapabilities:
        return "invalid-capabilities";
    case ServiceManifestError::CapabilityDenied:
        return "capability-denied";
    case ServiceManifestError::InvalidResourceProfile:
        return "invalid-resource-profile";
    case ServiceManifestError::ResourceProfileDenied:
        return "resource-profile-denied";
    case ServiceManifestError::InvalidResourceCeiling:
        return "invalid-resource-ceiling";
    case ServiceManifestError::ResourceCeilingDenied:
        return "resource-ceiling-denied";
    case ServiceManifestError::InvalidFrameBudget:
        return "invalid-frame-budget";
    case ServiceManifestError::FrameBudgetDenied:
        return "frame-budget-denied";
    case ServiceManifestError::InvalidTickBudget:
        return "invalid-tick-budget";
    case ServiceManifestError::TickBudgetDenied:
        return "tick-budget-denied";
    case ServiceManifestError::InvalidDependencyRange:
        return "invalid-dependency-range";
    case ServiceManifestError::InvalidDependency:
        return "invalid-dependency";
    case ServiceManifestError::MissingDependency:
        return "missing-dependency";
    case ServiceManifestError::DuplicateDependency:
        return "duplicate-dependency";
    case ServiceManifestError::DependencyCycle:
        return "dependency-cycle";
    case ServiceManifestError::NonCanonicalUnusedStorage:
        return "noncanonical-unused-storage";
    case ServiceManifestError::ServiceCountDenied:
        return "service-count-denied";
    case ServiceManifestError::DependencyCountDenied:
        return "dependency-count-denied";
    }
    return "?";
}

} // namespace duetos::core
