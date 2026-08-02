#include "core/service_object_package.h"

#include "crypto/sha256.h"

namespace duetos::core
{

namespace
{

constexpr u64 kReservedIdentity = ~0ULL;
constexpr u32 kBootstrapPlanHeaderBytes = 64;
constexpr u32 kBootstrapPlanRegionBytes = 72;
constexpr u32 kBootstrapPlanMaximumBytes =
    kBootstrapPlanHeaderBytes + loader::kLoadPlanMaxRegions * kBootstrapPlanRegionBytes;
constexpr u32 kPlanHeaderSizeOffset = 0;
constexpr u32 kPlanHeaderVersionOffset = 4;
constexpr u32 kPlanHeaderFormatOffset = 6;
constexpr u32 kPlanHeaderRegionCountOffset = 24;
constexpr u32 kPlanHeaderDependencyCountOffset = 28;
constexpr u32 kPlanHeaderSourceHashOffset = 32;
constexpr u32 kPlanRegionMemoryObjectOffset = 16;

void ZeroBytes(void* target, u64 byte_count)
{
    auto* bytes = static_cast<u8*>(target);
    for (u64 index = 0; index < byte_count; ++index)
        bytes[index] = 0;
}

bool AllZero(const void* target, u64 byte_count)
{
    const auto* bytes = static_cast<const u8*>(target);
    for (u64 index = 0; index < byte_count; ++index)
    {
        if (bytes[index] != 0)
            return false;
    }
    return true;
}

bool RangeIsValid(const void* pointer, u64 byte_count)
{
    if (pointer == nullptr || byte_count == 0)
        return false;
    const uptr start = reinterpret_cast<uptr>(pointer);
    return byte_count <= ~static_cast<uptr>(0) - start;
}

bool RangesOverlap(const void* left, u64 left_bytes, const void* right, u64 right_bytes)
{
    if (!RangeIsValid(left, left_bytes) || !RangeIsValid(right, right_bytes))
        return false;
    const uptr left_start = reinterpret_cast<uptr>(left);
    const uptr right_start = reinterpret_cast<uptr>(right);
    return left_start < right_start + right_bytes && right_start < left_start + left_bytes;
}

bool HashEquals(const loader::Hash256& left, const loader::Hash256& right)
{
    u8 difference = 0;
    for (u32 index = 0; index < sizeof(left.bytes); ++index)
        difference |= left.bytes[index] ^ right.bytes[index];
    return difference == 0;
}

bool HashIsZero(const loader::Hash256& hash)
{
    u8 aggregate = 0;
    for (u32 index = 0; index < sizeof(hash.bytes); ++index)
        aggregate |= hash.bytes[index];
    return aggregate == 0;
}

u16 ReadLe16(const u8* bytes)
{
    return static_cast<u16>(bytes[0]) | static_cast<u16>(bytes[1]) << 8u;
}

u32 ReadLe32(const u8* bytes)
{
    return static_cast<u32>(bytes[0]) | static_cast<u32>(bytes[1]) << 8u | static_cast<u32>(bytes[2]) << 16u |
           static_cast<u32>(bytes[3]) << 24u;
}

u64 ReadLe64(const u8* bytes)
{
    return static_cast<u64>(ReadLe32(bytes)) | static_cast<u64>(ReadLe32(bytes + 4)) << 32u;
}

bool BootstrapPlanTemplateIsCanonical(const u8* bytes, u32 byte_count, const loader::Hash256& source_hash)
{
    if (!RangeIsValid(bytes, byte_count) || byte_count < kBootstrapPlanHeaderBytes ||
        byte_count > kBootstrapPlanMaximumBytes || ReadLe32(bytes + kPlanHeaderSizeOffset) != byte_count ||
        ReadLe16(bytes + kPlanHeaderVersionOffset) != loader::kLoadPlanVersion1 ||
        ReadLe16(bytes + kPlanHeaderFormatOffset) != static_cast<u16>(loader::ImageFormat::Elf64) ||
        ReadLe32(bytes + kPlanHeaderDependencyCountOffset) != 0)
    {
        return false;
    }
    const u32 region_count = ReadLe32(bytes + kPlanHeaderRegionCountOffset);
    if (region_count == 0 || region_count > loader::kLoadPlanMaxRegions ||
        byte_count != kBootstrapPlanHeaderBytes + region_count * kBootstrapPlanRegionBytes)
    {
        return false;
    }
    loader::Hash256 template_source_hash{};
    for (u32 index = 0; index < sizeof(template_source_hash.bytes); ++index)
        template_source_hash.bytes[index] = bytes[kPlanHeaderSourceHashOffset + index];
    if (!HashEquals(template_source_hash, source_hash))
        return false;
    for (u32 index = 0; index < region_count; ++index)
    {
        const u8* region = bytes + kBootstrapPlanHeaderBytes + index * kBootstrapPlanRegionBytes;
        if (ReadLe64(region + kPlanRegionMemoryObjectOffset) != 0)
            return false;
    }
    return true;
}

loader::Hash256 HashBytes(const u8* bytes, u64 byte_count)
{
    loader::Hash256 hash{};
    crypto::Sha256Hash(bytes, static_cast<u32>(byte_count), hash.bytes);
    return hash;
}

ServiceObjectPackageResult Result(ServiceObjectPackageStatus status,
                                  ServiceManifestError manifest_error = ServiceManifestError::Ok,
                                  u32 object_index = kServiceObjectPackageNoObjectIndex)
{
    return ServiceObjectPackageResult{status, manifest_error, object_index};
}

u32 FindServiceByTransferRef(const ServiceManifestDocumentV1& document, u32 transfer_ref)
{
    for (u32 index = 0; index < document.service_count; ++index)
    {
        if (document.services[index].executable_transfer_ref == transfer_ref)
            return index;
    }
    return kServiceManifestMaximumServices;
}

bool TopologicalOrderIsCanonical(const ServiceManifestPlanV1& plan)
{
    const ServiceManifestDocumentV1& document = plan.document;
    if (plan.topological_count != document.service_count || plan.reserved16 != 0 || plan.reserved32 != 0)
        return false;

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
                break;
            }
        }
        if (selected == kServiceManifestMaximumServices ||
            plan.topological_identities[output_index] != document.services[selected].service_identity)
        {
            return false;
        }

        emitted[selected] = true;
        const u64 resolved_identity = document.services[selected].service_identity;
        for (u32 dependent = 0; dependent < document.service_count; ++dependent)
        {
            if (emitted[dependent] || indegree[dependent] == 0)
                continue;
            const ServiceManifestServiceV1& row = document.services[dependent];
            const u32 dependency_end = static_cast<u32>(row.dependency_first) + row.dependency_count;
            for (u32 edge = row.dependency_first; edge < dependency_end; ++edge)
            {
                if (document.dependencies[edge].dependency_service_identity == resolved_identity)
                {
                    --indegree[dependent];
                    break;
                }
            }
        }
    }

    for (u32 index = document.service_count; index < kServiceManifestMaximumServices; ++index)
    {
        if (plan.topological_identities[index] != 0)
            return false;
    }
    return true;
}

bool PackageMetadataIsCanonical(const ServiceObjectPackageV1& package)
{
    if (package.initialized != 1 || package.version != kServiceObjectPackageVersion1 ||
        package.executable_object_count == 0 || package.executable_object_count > kServiceManifestMaximumServices ||
        (package.bootstrap_plan_count != 0 && package.bootstrap_plan_count != package.executable_object_count) ||
        package.reserved != 0)
    {
        return false;
    }
    if (!ServiceManifestAuthoritySnapshotIsCanonicalV1(package.manifest_authority) ||
        ServiceManifestDocumentValidateAgainstAuthorityV1(package.manifest_plan.document, package.manifest_authority) !=
            ServiceManifestError::Ok)
    {
        return false;
    }

    const ServiceManifestDocumentV1& document = package.manifest_plan.document;
    if (document.service_count != package.executable_object_count ||
        package.manifest_plan.authority_identity != package.manifest_authority.authority_identity ||
        package.manifest_plan.sealed_object_extent != package.manifest_authority.sealed_object_extent ||
        package.manifest_plan.sealed_object_extent !=
            ServiceManifestEncodedSizeV1(document.service_count, document.dependency_count) ||
        !HashEquals(package.manifest_plan.sealed_object_hash, package.manifest_authority.sealed_object_hash) ||
        !TopologicalOrderIsCanonical(package.manifest_plan))
    {
        return false;
    }

    loader::Hash256 document_hash{};
    if (ServiceManifestDocumentHashV1(document, &document_hash) != ServiceManifestError::Ok ||
        !HashEquals(document_hash, package.manifest_authority.sealed_object_hash))
    {
        return false;
    }

    u64 total_bytes = 0;
    for (u32 index = 0; index < package.executable_object_count; ++index)
    {
        const ServiceObjectPackageRowV1& object = package.executable_objects[index];
        const ServiceManifestServiceV1& service = document.services[index];
        if (object.service_identity != service.service_identity ||
            object.executable_transfer_ref != service.executable_transfer_ref ||
            object.immutable_policy_selector != service.immutable_policy_selector ||
            !RangeIsValid(object.bytes, object.byte_count) || object.byte_count == 0 ||
            object.byte_count > kServiceObjectPackageExecutableMaximumBytes ||
            !HashEquals(object.content_hash, service.executable_content_hash) ||
            RangesOverlap(&package, sizeof(package), object.bytes, object.byte_count) ||
            total_bytes > kServiceObjectPackageTotalExecutableMaximumBytes - object.byte_count)
        {
            return false;
        }
        total_bytes += object.byte_count;
        for (u32 previous = 0; previous < index; ++previous)
        {
            const ServiceObjectPackageRowV1& earlier = package.executable_objects[previous];
            if (RangesOverlap(earlier.bytes, earlier.byte_count, object.bytes, object.byte_count))
                return false;
        }
    }
    for (u32 index = package.executable_object_count; index < kServiceManifestMaximumServices; ++index)
    {
        if (!AllZero(&package.executable_objects[index], sizeof(package.executable_objects[index])))
            return false;
    }
    for (u32 index = 0; index < package.bootstrap_plan_count; ++index)
    {
        const ServiceBootstrapPlanRowV1& plan = package.bootstrap_plans[index];
        const ServiceManifestServiceV1& service = document.services[index];
        if (plan.service_identity != service.service_identity ||
            plan.executable_transfer_ref != service.executable_transfer_ref ||
            !RangeIsValid(plan.bytes, plan.byte_count) || plan.byte_count < kBootstrapPlanHeaderBytes ||
            plan.byte_count > kBootstrapPlanMaximumBytes || HashIsZero(plan.content_hash) ||
            !BootstrapPlanTemplateIsCanonical(plan.bytes, plan.byte_count, service.executable_content_hash) ||
            RangesOverlap(&package, sizeof(package), plan.bytes, plan.byte_count))
        {
            return false;
        }
        for (u32 artifact_index = 0; artifact_index < package.executable_object_count; ++artifact_index)
        {
            const ServiceObjectPackageRowV1& artifact = package.executable_objects[artifact_index];
            if (RangesOverlap(artifact.bytes, artifact.byte_count, plan.bytes, plan.byte_count))
                return false;
        }
        for (u32 previous = 0; previous < index; ++previous)
        {
            const ServiceBootstrapPlanRowV1& earlier = package.bootstrap_plans[previous];
            if (RangesOverlap(earlier.bytes, earlier.byte_count, plan.bytes, plan.byte_count))
                return false;
        }
    }
    for (u32 index = package.bootstrap_plan_count; index < kServiceManifestMaximumServices; ++index)
    {
        if (!AllZero(&package.bootstrap_plans[index], sizeof(package.bootstrap_plans[index])))
            return false;
    }
    return true;
}

bool AllBorrowedHashesMatch(const ServiceObjectPackageV1& package)
{
    for (u32 index = 0; index < package.executable_object_count; ++index)
    {
        const ServiceObjectPackageRowV1& object = package.executable_objects[index];
        if (!HashEquals(HashBytes(object.bytes, object.byte_count), object.content_hash))
            return false;
    }
    for (u32 index = 0; index < package.bootstrap_plan_count; ++index)
    {
        const ServiceBootstrapPlanRowV1& plan = package.bootstrap_plans[index];
        if (!HashEquals(HashBytes(plan.bytes, plan.byte_count), plan.content_hash))
            return false;
    }
    return true;
}

bool OutputAliasesBorrowedBytes(const ServiceObjectPackageV1& package, const void* output, u64 output_bytes)
{
    if (package.initialized != 1 || package.executable_object_count > kServiceManifestMaximumServices)
        return false;
    for (u32 index = 0; index < package.executable_object_count; ++index)
    {
        const ServiceObjectPackageRowV1& object = package.executable_objects[index];
        if (RangesOverlap(output, output_bytes, object.bytes, object.byte_count))
            return true;
    }
    for (u32 index = 0; index < package.bootstrap_plan_count; ++index)
    {
        const ServiceBootstrapPlanRowV1& plan = package.bootstrap_plans[index];
        if (RangesOverlap(output, output_bytes, plan.bytes, plan.byte_count))
            return true;
    }
    return false;
}

ServiceObjectPackageResult PreflightDefinition(ServiceObjectPackageV1* package,
                                               const ServiceObjectPackageDefinitionV1& definition)
{
    if (definition.reserved != 0 || definition.reserved_bootstrap != 0 || definition.executable_object_count == 0 ||
        definition.executable_object_count > kServiceManifestMaximumServices)
    {
        return Result(ServiceObjectPackageStatus::ObjectCountMismatch);
    }
    if ((definition.bootstrap_plan_count == 0) != (definition.bootstrap_plans == nullptr) ||
        (definition.bootstrap_plan_count != 0 && definition.bootstrap_plan_count != definition.executable_object_count))
    {
        return Result(ServiceObjectPackageStatus::PlanCountMismatch);
    }
    const u64 definitions_bytes =
        static_cast<u64>(definition.executable_object_count) * sizeof(ServiceExecutableObjectDefinitionV1);
    const u64 plan_definitions_bytes =
        static_cast<u64>(definition.bootstrap_plan_count) * sizeof(ServiceBootstrapPlanDefinitionV1);
    if (!RangeIsValid(definition.manifest_bytes, definition.manifest_byte_count) ||
        !RangeIsValid(definition.manifest_authority, sizeof(*definition.manifest_authority)) ||
        !RangeIsValid(definition.executable_objects, definitions_bytes) ||
        (definition.bootstrap_plan_count != 0 && !RangeIsValid(definition.bootstrap_plans, plan_definitions_bytes)))
    {
        return Result(ServiceObjectPackageStatus::InvalidPointerRange);
    }
    if (RangesOverlap(package, sizeof(*package), definition.manifest_bytes, definition.manifest_byte_count) ||
        RangesOverlap(package, sizeof(*package), definition.manifest_authority,
                      sizeof(*definition.manifest_authority)) ||
        RangesOverlap(package, sizeof(*package), definition.executable_objects, definitions_bytes) ||
        (definition.bootstrap_plan_count != 0 &&
         RangesOverlap(package, sizeof(*package), definition.bootstrap_plans, plan_definitions_bytes)))
    {
        return Result(ServiceObjectPackageStatus::AliasedOutput);
    }
    if (RangesOverlap(definition.manifest_bytes, definition.manifest_byte_count, definition.manifest_authority,
                      sizeof(*definition.manifest_authority)) ||
        RangesOverlap(definition.manifest_bytes, definition.manifest_byte_count, definition.executable_objects,
                      definitions_bytes) ||
        RangesOverlap(definition.manifest_authority, sizeof(*definition.manifest_authority),
                      definition.executable_objects, definitions_bytes) ||
        (definition.bootstrap_plan_count != 0 &&
         (RangesOverlap(definition.manifest_bytes, definition.manifest_byte_count, definition.bootstrap_plans,
                        plan_definitions_bytes) ||
          RangesOverlap(definition.manifest_authority, sizeof(*definition.manifest_authority),
                        definition.bootstrap_plans, plan_definitions_bytes) ||
          RangesOverlap(definition.executable_objects, definitions_bytes, definition.bootstrap_plans,
                        plan_definitions_bytes))))
    {
        return Result(ServiceObjectPackageStatus::ObjectRangeOverlap);
    }

    u64 total_bytes = 0;
    for (u32 index = 0; index < definition.executable_object_count; ++index)
    {
        const ServiceExecutableObjectDefinitionV1 object = definition.executable_objects[index];
        if (object.executable_transfer_ref == 0 ||
            object.executable_transfer_ref > kServiceManifestPositiveTransferRefMaximum ||
            object.immutable_policy_selector == 0 || object.immutable_policy_selector >= 64 ||
            object.flags != kServiceObjectDefinitionKnownFlags || object.reserved != 0 || object.byte_count == 0 ||
            object.byte_count > kServiceObjectPackageExecutableMaximumBytes ||
            !RangeIsValid(object.bytes, object.byte_count))
        {
            return Result(ServiceObjectPackageStatus::InvalidObject, ServiceManifestError::Ok, index);
        }
        if (total_bytes > kServiceObjectPackageTotalExecutableMaximumBytes - object.byte_count)
            return Result(ServiceObjectPackageStatus::InvalidObject, ServiceManifestError::Ok, index);
        total_bytes += object.byte_count;

        if (RangesOverlap(package, sizeof(*package), object.bytes, object.byte_count))
            return Result(ServiceObjectPackageStatus::AliasedOutput, ServiceManifestError::Ok, index);
        if (RangesOverlap(object.bytes, object.byte_count, definition.manifest_bytes, definition.manifest_byte_count) ||
            RangesOverlap(object.bytes, object.byte_count, definition.manifest_authority,
                          sizeof(*definition.manifest_authority)) ||
            RangesOverlap(object.bytes, object.byte_count, definition.executable_objects, definitions_bytes) ||
            (definition.bootstrap_plan_count != 0 &&
             RangesOverlap(object.bytes, object.byte_count, definition.bootstrap_plans, plan_definitions_bytes)))
        {
            return Result(ServiceObjectPackageStatus::ObjectRangeOverlap, ServiceManifestError::Ok, index);
        }
        for (u32 previous = 0; previous < index; ++previous)
        {
            const ServiceExecutableObjectDefinitionV1 earlier = definition.executable_objects[previous];
            if (earlier.executable_transfer_ref == object.executable_transfer_ref)
            {
                return Result(ServiceObjectPackageStatus::DuplicateTransferReference, ServiceManifestError::Ok, index);
            }
            if (RangesOverlap(earlier.bytes, earlier.byte_count, object.bytes, object.byte_count))
                return Result(ServiceObjectPackageStatus::ObjectRangeOverlap, ServiceManifestError::Ok, index);
        }
    }

    for (u32 index = 0; index < definition.bootstrap_plan_count; ++index)
    {
        const ServiceBootstrapPlanDefinitionV1 plan = definition.bootstrap_plans[index];
        if (plan.executable_transfer_ref == 0 ||
            plan.executable_transfer_ref > kServiceManifestPositiveTransferRefMaximum ||
            plan.flags != kServiceBootstrapPlanDefinitionKnownFlags || plan.reserved != 0 ||
            plan.byte_count < kBootstrapPlanHeaderBytes || plan.byte_count > kBootstrapPlanMaximumBytes ||
            !RangeIsValid(plan.bytes, plan.byte_count) || HashIsZero(plan.content_hash))
        {
            return Result(ServiceObjectPackageStatus::InvalidBootstrapPlan, ServiceManifestError::Ok, index);
        }
        if (RangesOverlap(package, sizeof(*package), plan.bytes, plan.byte_count))
            return Result(ServiceObjectPackageStatus::AliasedOutput, ServiceManifestError::Ok, index);
        if (RangesOverlap(plan.bytes, plan.byte_count, definition.manifest_bytes, definition.manifest_byte_count) ||
            RangesOverlap(plan.bytes, plan.byte_count, definition.manifest_authority,
                          sizeof(*definition.manifest_authority)) ||
            RangesOverlap(plan.bytes, plan.byte_count, definition.executable_objects, definitions_bytes) ||
            RangesOverlap(plan.bytes, plan.byte_count, definition.bootstrap_plans, plan_definitions_bytes))
        {
            return Result(ServiceObjectPackageStatus::ObjectRangeOverlap, ServiceManifestError::Ok, index);
        }
        for (u32 object_index = 0; object_index < definition.executable_object_count; ++object_index)
        {
            const ServiceExecutableObjectDefinitionV1 object = definition.executable_objects[object_index];
            if (RangesOverlap(plan.bytes, plan.byte_count, object.bytes, object.byte_count))
                return Result(ServiceObjectPackageStatus::ObjectRangeOverlap, ServiceManifestError::Ok, index);
        }
        for (u32 previous = 0; previous < index; ++previous)
        {
            const ServiceBootstrapPlanDefinitionV1 earlier = definition.bootstrap_plans[previous];
            if (earlier.executable_transfer_ref == plan.executable_transfer_ref)
                return Result(ServiceObjectPackageStatus::DuplicateTransferReference, ServiceManifestError::Ok, index);
            if (RangesOverlap(earlier.bytes, earlier.byte_count, plan.bytes, plan.byte_count))
                return Result(ServiceObjectPackageStatus::ObjectRangeOverlap, ServiceManifestError::Ok, index);
        }
    }
    return Result(ServiceObjectPackageStatus::Ok);
}

} // namespace

ServiceObjectPackageResult ServiceObjectPackageInitializeV1(ServiceObjectPackageV1* package,
                                                            const ServiceObjectPackageDefinitionV1* definition)
{
    if (package == nullptr || definition == nullptr)
        return Result(ServiceObjectPackageStatus::NullArgument);
    if (!RangeIsValid(package, sizeof(*package)) || !RangeIsValid(definition, sizeof(*definition)))
        return Result(ServiceObjectPackageStatus::InvalidPointerRange);
    if (RangesOverlap(package, sizeof(*package), definition, sizeof(*definition)))
        return Result(ServiceObjectPackageStatus::AliasedOutput);
    if (package->initialized != 0)
        return Result(ServiceObjectPackageStatus::AlreadyInitialized);
    if (!AllZero(package, sizeof(*package)))
        return Result(ServiceObjectPackageStatus::NonCanonicalStorage);

    const ServiceObjectPackageDefinitionV1 definition_snapshot = *definition;
    const ServiceObjectPackageResult preflight = PreflightDefinition(package, definition_snapshot);
    if (preflight.status != ServiceObjectPackageStatus::Ok)
        return preflight;

    const ServiceManifestAuthoritySnapshotV1 authority_snapshot = *definition_snapshot.manifest_authority;
    const ServiceManifestError manifest_error =
        ServiceManifestValidateV1(definition_snapshot.manifest_bytes, definition_snapshot.manifest_byte_count,
                                  &authority_snapshot, &package->manifest_plan);
    if (manifest_error != ServiceManifestError::Ok)
    {
        ZeroBytes(package, sizeof(*package));
        return Result(ServiceObjectPackageStatus::ManifestRejected, manifest_error);
    }

    const ServiceManifestDocumentV1& document = package->manifest_plan.document;
    if (definition_snapshot.executable_object_count != document.service_count)
    {
        ZeroBytes(package, sizeof(*package));
        return Result(ServiceObjectPackageStatus::ObjectCountMismatch);
    }

    for (u32 object_index = 0; object_index < definition_snapshot.executable_object_count; ++object_index)
    {
        const ServiceExecutableObjectDefinitionV1 object = definition_snapshot.executable_objects[object_index];
        const u32 service_index = FindServiceByTransferRef(document, object.executable_transfer_ref);
        if (service_index >= document.service_count)
        {
            ZeroBytes(package, sizeof(*package));
            return Result(ServiceObjectPackageStatus::UnexpectedTransferReference, ServiceManifestError::Ok,
                          object_index);
        }
        if (package->executable_objects[service_index].bytes != nullptr)
        {
            ZeroBytes(package, sizeof(*package));
            return Result(ServiceObjectPackageStatus::DuplicateTransferReference, ServiceManifestError::Ok,
                          object_index);
        }

        const ServiceManifestServiceV1& service = document.services[service_index];
        if (object.immutable_policy_selector != service.immutable_policy_selector)
        {
            ZeroBytes(package, sizeof(*package));
            return Result(ServiceObjectPackageStatus::ImmutablePolicyMismatch, ServiceManifestError::Ok, object_index);
        }
        const loader::Hash256 content_hash = HashBytes(object.bytes, object.byte_count);
        if (!HashEquals(content_hash, service.executable_content_hash))
        {
            ZeroBytes(package, sizeof(*package));
            return Result(ServiceObjectPackageStatus::ContentHashMismatch, ServiceManifestError::Ok, object_index);
        }

        package->executable_objects[service_index] = ServiceObjectPackageRowV1{service.service_identity,
                                                                               object.executable_transfer_ref,
                                                                               object.immutable_policy_selector,
                                                                               object.bytes,
                                                                               object.byte_count,
                                                                               content_hash};
    }
    for (u32 service_index = 0; service_index < document.service_count; ++service_index)
    {
        if (package->executable_objects[service_index].bytes == nullptr)
        {
            ZeroBytes(package, sizeof(*package));
            return Result(ServiceObjectPackageStatus::MissingTransferReference, ServiceManifestError::Ok,
                          service_index);
        }
    }

    for (u32 plan_index = 0; plan_index < definition_snapshot.bootstrap_plan_count; ++plan_index)
    {
        const ServiceBootstrapPlanDefinitionV1 plan = definition_snapshot.bootstrap_plans[plan_index];
        const u32 service_index = FindServiceByTransferRef(document, plan.executable_transfer_ref);
        if (service_index >= document.service_count)
        {
            ZeroBytes(package, sizeof(*package));
            return Result(ServiceObjectPackageStatus::UnexpectedTransferReference, ServiceManifestError::Ok,
                          plan_index);
        }
        if (package->bootstrap_plans[service_index].bytes != nullptr)
        {
            ZeroBytes(package, sizeof(*package));
            return Result(ServiceObjectPackageStatus::DuplicateTransferReference, ServiceManifestError::Ok, plan_index);
        }
        const ServiceManifestServiceV1& service = document.services[service_index];
        const loader::Hash256 observed_hash = HashBytes(plan.bytes, plan.byte_count);
        if (!HashEquals(observed_hash, plan.content_hash))
        {
            ZeroBytes(package, sizeof(*package));
            return Result(ServiceObjectPackageStatus::BootstrapPlanHashMismatch, ServiceManifestError::Ok, plan_index);
        }
        if (!BootstrapPlanTemplateIsCanonical(plan.bytes, plan.byte_count, service.executable_content_hash))
        {
            ZeroBytes(package, sizeof(*package));
            return Result(ServiceObjectPackageStatus::InvalidBootstrapPlan, ServiceManifestError::Ok, plan_index);
        }
        package->bootstrap_plans[service_index] = ServiceBootstrapPlanRowV1{
            service.service_identity, plan.executable_transfer_ref, plan.byte_count, plan.bytes, observed_hash};
    }
    if (definition_snapshot.bootstrap_plan_count != 0)
    {
        for (u32 service_index = 0; service_index < document.service_count; ++service_index)
        {
            if (package->bootstrap_plans[service_index].bytes == nullptr)
            {
                ZeroBytes(package, sizeof(*package));
                return Result(ServiceObjectPackageStatus::MissingTransferReference, ServiceManifestError::Ok,
                              service_index);
            }
        }
    }

    package->manifest_authority = authority_snapshot;
    package->version = kServiceObjectPackageVersion1;
    package->executable_object_count = document.service_count;
    package->bootstrap_plan_count = static_cast<u16>(definition_snapshot.bootstrap_plan_count);
    package->initialized = 1;
    if (!PackageMetadataIsCanonical(*package))
    {
        ZeroBytes(package, sizeof(*package));
        return Result(ServiceObjectPackageStatus::CorruptPackage);
    }
    return Result(ServiceObjectPackageStatus::Ok);
}

ServiceObjectPackageResult ServiceObjectPackageGetManifestV1(const ServiceObjectPackageV1* package,
                                                             ServiceObjectPackageManifestV1* manifest_out)
{
    if (package == nullptr || manifest_out == nullptr)
        return Result(ServiceObjectPackageStatus::NullArgument);
    if (!RangeIsValid(package, sizeof(*package)) || !RangeIsValid(manifest_out, sizeof(*manifest_out)))
        return Result(ServiceObjectPackageStatus::InvalidPointerRange);
    if (RangesOverlap(package, sizeof(*package), manifest_out, sizeof(*manifest_out)) ||
        OutputAliasesBorrowedBytes(*package, manifest_out, sizeof(*manifest_out)))
        return Result(ServiceObjectPackageStatus::AliasedOutput);

    ZeroBytes(manifest_out, sizeof(*manifest_out));
    if (package->initialized != 1)
        return Result(ServiceObjectPackageStatus::NotInitialized);
    if (!PackageMetadataIsCanonical(*package) || !AllBorrowedHashesMatch(*package))
        return Result(ServiceObjectPackageStatus::CorruptPackage);

    manifest_out->plan = &package->manifest_plan;
    manifest_out->authority = &package->manifest_authority;
    return Result(ServiceObjectPackageStatus::Ok);
}

ServiceObjectPackageResult ServiceObjectPackageResolveExecutableV1(const ServiceObjectPackageV1* package,
                                                                   u64 expected_service_identity,
                                                                   u32 executable_transfer_ref,
                                                                   ServiceExecutableTransferSnapshotV1* transfer_out)
{
    if (package == nullptr || transfer_out == nullptr)
        return Result(ServiceObjectPackageStatus::NullArgument);
    if (!RangeIsValid(package, sizeof(*package)) || !RangeIsValid(transfer_out, sizeof(*transfer_out)))
        return Result(ServiceObjectPackageStatus::InvalidPointerRange);
    if (RangesOverlap(package, sizeof(*package), transfer_out, sizeof(*transfer_out)) ||
        OutputAliasesBorrowedBytes(*package, transfer_out, sizeof(*transfer_out)))
        return Result(ServiceObjectPackageStatus::AliasedOutput);

    ZeroBytes(transfer_out, sizeof(*transfer_out));
    if (expected_service_identity == 0 || expected_service_identity == kReservedIdentity ||
        executable_transfer_ref == 0 || executable_transfer_ref > kServiceManifestPositiveTransferRefMaximum)
    {
        return Result(ServiceObjectPackageStatus::InvalidSelector);
    }
    if (package->initialized != 1)
        return Result(ServiceObjectPackageStatus::NotInitialized);
    if (!PackageMetadataIsCanonical(*package))
        return Result(ServiceObjectPackageStatus::CorruptPackage);

    for (u32 index = 0; index < package->executable_object_count; ++index)
    {
        const ServiceObjectPackageRowV1& object = package->executable_objects[index];
        if (object.executable_transfer_ref != executable_transfer_ref)
            continue;
        if (object.service_identity != expected_service_identity)
            return Result(ServiceObjectPackageStatus::ServiceBindingMismatch, ServiceManifestError::Ok, index);
        if (!HashEquals(HashBytes(object.bytes, object.byte_count), object.content_hash))
            return Result(ServiceObjectPackageStatus::CorruptPackage, ServiceManifestError::Ok, index);

        *transfer_out = ServiceExecutableTransferSnapshotV1{object.service_identity,
                                                            object.executable_transfer_ref,
                                                            object.immutable_policy_selector,
                                                            object.bytes,
                                                            object.byte_count,
                                                            object.content_hash};
        return Result(ServiceObjectPackageStatus::Ok, ServiceManifestError::Ok, index);
    }
    return Result(ServiceObjectPackageStatus::NotFound);
}

ServiceObjectPackageResult ServiceObjectPackageResolveBootstrapPlanV1(
    const ServiceObjectPackageV1* package, u64 expected_service_identity, u32 executable_transfer_ref,
    ServiceBootstrapPlanTransferSnapshotV1* transfer_out)
{
    if (package == nullptr || transfer_out == nullptr)
        return Result(ServiceObjectPackageStatus::NullArgument);
    if (!RangeIsValid(package, sizeof(*package)) || !RangeIsValid(transfer_out, sizeof(*transfer_out)))
        return Result(ServiceObjectPackageStatus::InvalidPointerRange);
    if (RangesOverlap(package, sizeof(*package), transfer_out, sizeof(*transfer_out)) ||
        OutputAliasesBorrowedBytes(*package, transfer_out, sizeof(*transfer_out)))
    {
        return Result(ServiceObjectPackageStatus::AliasedOutput);
    }

    ZeroBytes(transfer_out, sizeof(*transfer_out));
    if (expected_service_identity == 0 || expected_service_identity == kReservedIdentity ||
        executable_transfer_ref == 0 || executable_transfer_ref > kServiceManifestPositiveTransferRefMaximum)
    {
        return Result(ServiceObjectPackageStatus::InvalidSelector);
    }
    if (package->initialized != 1)
        return Result(ServiceObjectPackageStatus::NotInitialized);
    if (!PackageMetadataIsCanonical(*package))
        return Result(ServiceObjectPackageStatus::CorruptPackage);
    if (package->bootstrap_plan_count == 0)
        return Result(ServiceObjectPackageStatus::NotFound);

    for (u32 index = 0; index < package->bootstrap_plan_count; ++index)
    {
        const ServiceBootstrapPlanRowV1& plan = package->bootstrap_plans[index];
        if (plan.executable_transfer_ref != executable_transfer_ref)
            continue;
        if (plan.service_identity != expected_service_identity)
            return Result(ServiceObjectPackageStatus::ServiceBindingMismatch, ServiceManifestError::Ok, index);
        if (!HashEquals(HashBytes(plan.bytes, plan.byte_count), plan.content_hash))
            return Result(ServiceObjectPackageStatus::CorruptPackage, ServiceManifestError::Ok, index);

        *transfer_out = ServiceBootstrapPlanTransferSnapshotV1{plan.service_identity, plan.executable_transfer_ref,
                                                               plan.byte_count, plan.bytes, plan.content_hash};
        return Result(ServiceObjectPackageStatus::Ok, ServiceManifestError::Ok, index);
    }
    return Result(ServiceObjectPackageStatus::NotFound);
}

const char* ServiceObjectPackageStatusName(ServiceObjectPackageStatus status)
{
    switch (status)
    {
    case ServiceObjectPackageStatus::Ok:
        return "ok";
    case ServiceObjectPackageStatus::NullArgument:
        return "null-argument";
    case ServiceObjectPackageStatus::InvalidPointerRange:
        return "invalid-pointer-range";
    case ServiceObjectPackageStatus::AliasedOutput:
        return "aliased-output";
    case ServiceObjectPackageStatus::NonCanonicalStorage:
        return "noncanonical-storage";
    case ServiceObjectPackageStatus::AlreadyInitialized:
        return "already-initialized";
    case ServiceObjectPackageStatus::ManifestRejected:
        return "manifest-rejected";
    case ServiceObjectPackageStatus::InvalidSelector:
        return "invalid-selector";
    case ServiceObjectPackageStatus::ObjectCountMismatch:
        return "object-count-mismatch";
    case ServiceObjectPackageStatus::InvalidObject:
        return "invalid-object";
    case ServiceObjectPackageStatus::ObjectRangeOverlap:
        return "object-range-overlap";
    case ServiceObjectPackageStatus::DuplicateTransferReference:
        return "duplicate-transfer-reference";
    case ServiceObjectPackageStatus::UnexpectedTransferReference:
        return "unexpected-transfer-reference";
    case ServiceObjectPackageStatus::MissingTransferReference:
        return "missing-transfer-reference";
    case ServiceObjectPackageStatus::ImmutablePolicyMismatch:
        return "immutable-policy-mismatch";
    case ServiceObjectPackageStatus::ContentHashMismatch:
        return "content-hash-mismatch";
    case ServiceObjectPackageStatus::NotInitialized:
        return "not-initialized";
    case ServiceObjectPackageStatus::CorruptPackage:
        return "corrupt-package";
    case ServiceObjectPackageStatus::NotFound:
        return "not-found";
    case ServiceObjectPackageStatus::ServiceBindingMismatch:
        return "service-binding-mismatch";
    case ServiceObjectPackageStatus::PlanCountMismatch:
        return "plan-count-mismatch";
    case ServiceObjectPackageStatus::InvalidBootstrapPlan:
        return "invalid-bootstrap-plan";
    case ServiceObjectPackageStatus::BootstrapPlanHashMismatch:
        return "bootstrap-plan-hash-mismatch";
    }
    return "unknown";
}

} // namespace duetos::core
