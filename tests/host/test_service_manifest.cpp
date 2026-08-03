// Hosted canonical encoding, hostile decoding, authority narrowing, DAG, and
// structured mutation coverage for core/service_manifest.{h,cpp}.

#include "crypto_host_shims.h"
#include "host_test_helper.h"
#include "core/service_manifest.h"
#include "crypto/sha256.h"

#include <array>
#include <cstdio>
#include <cstring>

namespace
{

using duetos::u16;
using duetos::u32;
using duetos::u64;
using duetos::u8;
using namespace duetos::core;

constexpr u32 kHeaderFlagsOffset = 16;
constexpr u32 kHeaderReservedOffset = 20;
constexpr u32 kRowTransferRefOffset = 8;
constexpr u32 kRowPolicyOffset = 12;
constexpr u32 kRowHashOffset = 16;
constexpr u32 kRowCapabilitiesOffset = 48;
constexpr u32 kRowFrameBudgetOffset = 56;
constexpr u32 kRowTickBudgetOffset = 64;
constexpr u32 kRowSectionObjectsOffset = 72;
constexpr u32 kRowDependencyFirstOffset = 80;
constexpr u32 kRowDependencyCountOffset = 82;
constexpr u32 kRowKindOffset = 86;
constexpr u32 kRowRestartOffset = 87;
constexpr u32 kRowAutostartOffset = 88;
constexpr u32 kRowResourceProfileOffset = 89;
constexpr u32 kRowFlagsOffset = 90;
constexpr u32 kRowNameOffset = 96;
constexpr u32 kRowPathOffset = 128;

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

duetos::loader::Hash256 MakeHash(u8 seed)
{
    duetos::loader::Hash256 hash{};
    for (u32 index = 0; index < 32; ++index)
        hash.bytes[index] = static_cast<u8>(seed + index);
    return hash;
}

void SetText(u8* destination, u32 capacity, u8* length_out, const char* text)
{
    const u32 length = static_cast<u32>(std::strlen(text));
    EXPECT_TRUE(length <= capacity);
    for (u32 index = 0; index < capacity; ++index)
        destination[index] = index < length ? static_cast<u8>(text[index]) : 0;
    *length_out = static_cast<u8>(length);
}

ServiceManifestServiceV1 MakeService(u64 identity, u32 transfer_ref, const char* name, const char* path, u8 hash_seed)
{
    ServiceManifestServiceV1 service{};
    service.service_identity = identity;
    service.executable_transfer_ref = transfer_ref;
    service.immutable_policy_selector = 1;
    service.executable_content_hash = MakeHash(hash_seed);
    service.requested_capability_ceiling = 1ULL << 2;
    service.requested_frame_budget_pages = 128;
    service.requested_tick_budget = 10000;
    service.requested_section_objects = 2;
    service.requested_section_pages = 64;
    service.kind = ServiceManifestKind::Native;
    service.restart_policy = ServiceManifestRestartPolicy::OnFailure;
    service.autostart = 1;
    service.resource_profile = ServiceManifestResourceProfile::AuthenticatedService;
    SetText(service.name, kServiceManifestServiceNameCapacity, &service.name_length, name);
    SetText(service.executable_path, kServiceManifestExecutablePathCapacity, &service.executable_path_length, path);
    return service;
}

ServiceManifestDocumentV1 MakeDocument()
{
    ServiceManifestDocumentV1 document{};
    document.manifest_identity = 0xA001;
    document.signer_identity = 0xB001;
    document.profile_identity = 0xC001;
    document.service_count = 3;
    document.dependency_count = 3;
    document.services[0] = MakeService(100, 0x101, "execd", "/system/execd", 0x10);
    document.services[1] = MakeService(200, 0x102, "displayd", "/system/displayd", 0x30);
    document.services[2] = MakeService(300, 0x103, "netd", "/system/netd", 0x50);
    document.services[0].dependency_first = 0;
    document.services[0].dependency_count = 0;
    document.services[1].dependency_first = 0;
    document.services[1].dependency_count = 1;
    document.services[2].dependency_first = 1;
    document.services[2].dependency_count = 2;
    document.dependencies[0] = ServiceManifestDependencyV1{200, 100};
    document.dependencies[1] = ServiceManifestDependencyV1{300, 100};
    document.dependencies[2] = ServiceManifestDependencyV1{300, 200};
    return document;
}

ServiceManifestAuthoritySnapshotV1 MakeAuthority(const ServiceManifestDocumentV1& document, const u8* bytes,
                                                 u32 byte_count)
{
    ServiceManifestAuthoritySnapshotV1 authority{};
    authority.authority_identity = 0xD001;
    authority.manifest_identity = document.manifest_identity;
    authority.signer_identity = document.signer_identity;
    authority.profile_identity = document.profile_identity;
    duetos::crypto::Sha256Hash(bytes, byte_count, authority.sealed_object_hash.bytes);
    authority.sealed_object_extent = byte_count;
    authority.allowed_capabilities = kServiceManifestCapabilityMaskV1;
    authority.allowed_immutable_policies = (1ULL << 1) | (1ULL << 2);
    authority.maximum_frame_budget_pages = kServiceManifestFrameBudgetMaximum;
    authority.maximum_tick_budget = kServiceManifestTickBudgetMaximum;
    authority.allowed_service_kinds = kServiceManifestKnownKindMask;
    authority.allowed_resource_profiles = kServiceManifestKnownResourceProfileMask;
    authority.maximum_section_objects = kServiceManifestSectionObjectMaximum;
    authority.maximum_section_pages = kServiceManifestSectionPageMaximum;
    authority.maximum_services = static_cast<u16>(kServiceManifestMaximumServices);
    authority.maximum_dependencies = static_cast<u16>(kServiceManifestMaximumDependencies);
    authority.flags = kServiceManifestAuthoritySealed;
    return authority;
}

void RefreshHash(const u8* bytes, u32 byte_count, ServiceManifestAuthoritySnapshotV1* authority)
{
    duetos::crypto::Sha256Hash(bytes, byte_count, authority->sealed_object_hash.bytes);
    authority->sealed_object_extent = byte_count;
}

struct Fixture
{
    ServiceManifestDocumentV1 document{};
    std::array<u8, kServiceManifestMaximumBytes> bytes{};
    u32 byte_count = 0;
    ServiceManifestAuthoritySnapshotV1 authority{};

    Fixture()
    {
        document = MakeDocument();
        const ServiceManifestEncodeResult encoded = ServiceManifestEncodeV1(bytes.data(), bytes.size(), document);
        EXPECT_EQ(encoded.error, ServiceManifestError::Ok);
        byte_count = encoded.bytes_written;
        authority = MakeAuthority(document, bytes.data(), byte_count);
    }
};

void PoisonPlan(ServiceManifestPlanV1* plan)
{
    *plan = ServiceManifestPlanV1{};
    plan->document.manifest_identity = ~0ULL;
    plan->document.service_count = 0xFFFF;
    plan->authority_identity = ~0ULL;
    plan->topological_count = 0xFFFF;
    plan->topological_identities[0] = ~0ULL;
}

void ExpectCleared(const ServiceManifestPlanV1& plan)
{
    EXPECT_EQ(plan.document.manifest_identity, 0ULL);
    EXPECT_EQ(plan.document.service_count, 0U);
    EXPECT_EQ(plan.authority_identity, 0ULL);
    EXPECT_EQ(plan.topological_count, 0U);
    EXPECT_EQ(plan.topological_identities[0], 0ULL);
}

bool HashEquals(const duetos::loader::Hash256& left, const duetos::loader::Hash256& right)
{
    return std::memcmp(left.bytes, right.bytes, sizeof(left.bytes)) == 0;
}

bool HashIsZero(const duetos::loader::Hash256& hash)
{
    const duetos::loader::Hash256 zero{};
    return HashEquals(hash, zero);
}

u32 ServiceOffset(u32 index)
{
    return kServiceManifestV1HeaderBytes + index * kServiceManifestV1ServiceBytes;
}

u32 DependencyOffset(u32 service_count, u32 index)
{
    return kServiceManifestV1HeaderBytes + service_count * kServiceManifestV1ServiceBytes +
           index * kServiceManifestV1DependencyBytes;
}

ServiceManifestError ValidateMutated(Fixture* fixture, ServiceManifestPlanV1* plan)
{
    RefreshHash(fixture->bytes.data(), fixture->byte_count, &fixture->authority);
    return ServiceManifestValidateV1(fixture->bytes.data(), fixture->byte_count, &fixture->authority, plan);
}

ServiceManifestDocumentV1 MakeMaximumDocument()
{
    ServiceManifestDocumentV1 document{};
    document.manifest_identity = 0xA100;
    document.signer_identity = 0xB100;
    document.profile_identity = 0xC100;
    document.service_count = static_cast<u16>(kServiceManifestMaximumServices);

    u32 dependency_cursor = 0;
    for (u32 index = 0; index < kServiceManifestMaximumServices; ++index)
    {
        char name[16]{};
        char path[32]{};
        std::snprintf(name, sizeof(name), "svc%02u", index);
        std::snprintf(path, sizeof(path), "/system/svc%02u", index);
        ServiceManifestServiceV1& service = document.services[index];
        service = MakeService(1000 + index, 0x1000 + index, name, path, static_cast<u8>(index + 1));
        service.dependency_first = static_cast<u16>(dependency_cursor);
        const u32 remaining = kServiceManifestMaximumDependencies - dependency_cursor;
        u32 count = index < kServiceManifestMaximumDependenciesPerService
                        ? index
                        : kServiceManifestMaximumDependenciesPerService;
        if (count > remaining)
            count = remaining;
        service.dependency_count = static_cast<u16>(count);
        for (u32 dependency = index - count; dependency < index; ++dependency)
        {
            document.dependencies[dependency_cursor++] =
                ServiceManifestDependencyV1{service.service_identity, 1000 + dependency};
        }
    }
    document.dependency_count = static_cast<u16>(dependency_cursor);
    EXPECT_EQ(dependency_cursor, kServiceManifestMaximumDependencies);
    return document;
}

u32 NextFuzz(u32* state)
{
    *state = *state * 1664525u + 1013904223u;
    return *state;
}

} // namespace

int main()
{
    static_assert(kServiceManifestMaximumBytes == 20544);
    static_assert(sizeof(ServiceManifestServiceV1) == kServiceManifestV1ServiceBytes);
    static_assert(sizeof(ServiceManifestDependencyV1) == kServiceManifestV1DependencyBytes);

    // The canonical document has one deterministic byte representation and
    // validation returns a complete scalar plan with identity-only topology.
    {
        Fixture fixture;
        EXPECT_TRUE(ServiceManifestAuthoritySnapshotIsCanonicalV1(fixture.authority));
        EXPECT_EQ(ServiceManifestDocumentValidateV1(fixture.document), ServiceManifestError::Ok);
        EXPECT_EQ(fixture.byte_count, ServiceManifestEncodedSizeV1(3, 3));

        std::array<u8, kServiceManifestMaximumBytes> second{};
        const auto encoded = ServiceManifestEncodeV1(second.data(), second.size(), fixture.document);
        EXPECT_EQ(encoded.error, ServiceManifestError::Ok);
        EXPECT_EQ(encoded.bytes_written, fixture.byte_count);
        EXPECT_TRUE(std::memcmp(second.data(), fixture.bytes.data(), fixture.byte_count) == 0);

        duetos::loader::Hash256 document_hash{};
        EXPECT_EQ(ServiceManifestDocumentHashV1(fixture.document, &document_hash), ServiceManifestError::Ok);
        EXPECT_TRUE(HashEquals(document_hash, fixture.authority.sealed_object_hash));
        duetos::loader::Hash256 repeated_hash{};
        EXPECT_EQ(ServiceManifestDocumentHashV1(fixture.document, &repeated_hash), ServiceManifestError::Ok);
        EXPECT_TRUE(HashEquals(document_hash, repeated_hash));

        ServiceManifestDocumentV1 changed_policy = fixture.document;
        changed_policy.services[0].restart_policy = ServiceManifestRestartPolicy::Always;
        duetos::loader::Hash256 changed_hash{};
        EXPECT_EQ(ServiceManifestDocumentHashV1(changed_policy, &changed_hash), ServiceManifestError::Ok);
        EXPECT_FALSE(HashEquals(document_hash, changed_hash));
        EXPECT_EQ(fixture.bytes[0], static_cast<u8>(fixture.byte_count & 0xFFu));
        EXPECT_EQ(fixture.bytes[4], static_cast<u8>(kServiceManifestVersion1));

        ServiceManifestPlanV1 plan{};
        EXPECT_EQ(ServiceManifestValidateV1(fixture.bytes.data(), fixture.byte_count, &fixture.authority, &plan),
                  ServiceManifestError::Ok);
        EXPECT_EQ(plan.authority_identity, fixture.authority.authority_identity);
        EXPECT_EQ(plan.document.service_count, 3U);
        EXPECT_EQ(plan.document.services[1].service_identity, 200ULL);
        EXPECT_EQ(plan.document.services[1].requested_capability_ceiling, 1ULL << 2);
        EXPECT_EQ(plan.topological_count, 3U);
        EXPECT_EQ(plan.topological_identities[0], 100ULL);
        EXPECT_EQ(plan.topological_identities[1], 200ULL);
        EXPECT_EQ(plan.topological_identities[2], 300ULL);

        std::array<u8, kServiceManifestMaximumBytes> round_trip{};
        const auto reencoded = ServiceManifestEncodeV1(round_trip.data(), round_trip.size(), plan.document);
        EXPECT_EQ(reencoded.error, ServiceManifestError::Ok);
        EXPECT_EQ(reencoded.bytes_written, fixture.byte_count);
        EXPECT_TRUE(std::memcmp(round_trip.data(), fixture.bytes.data(), fixture.byte_count) == 0);
    }

    // The exact sealed hash is authoritative.  Mutation under the old snapshot
    // fails before hostile fields are decoded; a newly sealed malformed object
    // reaches and is rejected by the structural validator.
    {
        Fixture fixture;
        ServiceManifestPlanV1 plan{};
        fixture.bytes[ServiceOffset(0) + kRowPathOffset + 1] = static_cast<u8>('\\');
        PoisonPlan(&plan);
        EXPECT_EQ(ServiceManifestValidateV1(fixture.bytes.data(), fixture.byte_count, &fixture.authority, &plan),
                  ServiceManifestError::ObjectHashMismatch);
        ExpectCleared(plan);
        EXPECT_EQ(ValidateMutated(&fixture, &plan), ServiceManifestError::InvalidExecutablePath);
        ExpectCleared(plan);
    }
    {
        Fixture fixture;
        ServiceManifestPlanV1 plan{};
        WriteLe32(fixture.bytes.data() + kHeaderReservedOffset, 1);
        EXPECT_EQ(ValidateMutated(&fixture, &plan), ServiceManifestError::ReservedNonZero);
        WriteLe32(fixture.bytes.data() + kHeaderReservedOffset, 0);
        WriteLe32(fixture.bytes.data() + kHeaderFlagsOffset, 1);
        EXPECT_EQ(ValidateMutated(&fixture, &plan), ServiceManifestError::UnknownFlags);
        fixture = Fixture{};
        WriteLe32(fixture.bytes.data(), fixture.byte_count - 1);
        EXPECT_EQ(ValidateMutated(&fixture, &plan), ServiceManifestError::SizeMismatch);
    }
    {
        Fixture fixture;
        ServiceManifestPlanV1 plan{};
        PoisonPlan(&plan);
        EXPECT_EQ(ServiceManifestValidateV1(fixture.bytes.data(), 0, &fixture.authority, &plan),
                  ServiceManifestError::HeaderTruncated);
        ExpectCleared(plan);

        PoisonPlan(&plan);
        EXPECT_EQ(ServiceManifestValidateV1(fixture.bytes.data(), kServiceManifestMaximumBytes + 1ULL,
                                            &fixture.authority, &plan),
                  ServiceManifestError::ManifestTooLarge);
        ExpectCleared(plan);

        ServiceManifestAuthoritySnapshotV1 wrong_extent = fixture.authority;
        ++wrong_extent.sealed_object_extent;
        EXPECT_TRUE(ServiceManifestAuthoritySnapshotIsCanonicalV1(wrong_extent));
        EXPECT_EQ(ServiceManifestValidateV1(fixture.bytes.data(), fixture.byte_count, &wrong_extent, &plan),
                  ServiceManifestError::ObjectExtentMismatch);

        std::array<u8, kServiceManifestMaximumBytes> short_output{};
        short_output[0] = 0xA5;
        EXPECT_EQ(ServiceManifestEncodeV1(short_output.data(), fixture.byte_count - 1, fixture.document).error,
                  ServiceManifestError::OutputTooSmall);
        EXPECT_EQ(short_output[0], 0xA5);
        EXPECT_EQ(ServiceManifestEncodedSizeV1(kServiceManifestMaximumServices + 1, 0), 0U);
        EXPECT_EQ(ServiceManifestEncodedSizeV1(1, kServiceManifestMaximumDependencies + 1), 0U);
    }
    {
        Fixture fixture;
        ServiceManifestPlanV1 plan{};
        WriteLe16(fixture.bytes.data() + ServiceOffset(0) + kRowFlagsOffset, 1);
        EXPECT_EQ(ValidateMutated(&fixture, &plan), ServiceManifestError::UnknownFlags);
    }
    {
        Fixture fixture;
        ServiceManifestPlanV1 plan{};
        WriteLe32(fixture.bytes.data() + ServiceOffset(0) + kRowTransferRefOffset, 0x80000001U);
        EXPECT_EQ(ValidateMutated(&fixture, &plan), ServiceManifestError::InvalidTransferReference);
        fixture = Fixture{};
        WriteLe32(fixture.bytes.data() + ServiceOffset(0) + kRowTransferRefOffset, 0);
        EXPECT_EQ(ValidateMutated(&fixture, &plan), ServiceManifestError::InvalidTransferReference);
    }
    {
        Fixture fixture;
        ServiceManifestPlanV1 plan{};
        for (u32 index = 0; index < 32; ++index)
            fixture.bytes[ServiceOffset(0) + kRowHashOffset + index] = 0;
        EXPECT_EQ(ValidateMutated(&fixture, &plan), ServiceManifestError::MissingExecutableHash);
    }
    {
        Fixture fixture;
        ServiceManifestPlanV1 plan{};
        WriteLe32(fixture.bytes.data() + ServiceOffset(0) + kRowPolicyOffset, 0);
        EXPECT_EQ(ValidateMutated(&fixture, &plan), ServiceManifestError::InvalidImmutablePolicy);
        fixture = Fixture{};
        fixture.bytes[ServiceOffset(0) + kRowAutostartOffset] = 2;
        EXPECT_EQ(ValidateMutated(&fixture, &plan), ServiceManifestError::InvalidAutostart);
        fixture = Fixture{};
        WriteLe64(fixture.bytes.data() + ServiceOffset(0) + kRowCapabilitiesOffset, 1ULL << 40);
        EXPECT_EQ(ValidateMutated(&fixture, &plan), ServiceManifestError::InvalidCapabilities);
        fixture = Fixture{};
        fixture.bytes[ServiceOffset(0) + kRowKindOffset] = 0xFF;
        EXPECT_EQ(ValidateMutated(&fixture, &plan), ServiceManifestError::InvalidServiceKind);
        fixture = Fixture{};
        fixture.bytes[ServiceOffset(0) + kRowRestartOffset] = 0xFF;
        EXPECT_EQ(ValidateMutated(&fixture, &plan), ServiceManifestError::InvalidRestartPolicy);
        fixture = Fixture{};
        fixture.bytes[ServiceOffset(0) + kRowResourceProfileOffset] = 0xFF;
        EXPECT_EQ(ValidateMutated(&fixture, &plan), ServiceManifestError::InvalidResourceProfile);
        fixture = Fixture{};
        WriteLe32(fixture.bytes.data() + ServiceOffset(0) + kRowSectionObjectsOffset, 0);
        EXPECT_EQ(ValidateMutated(&fixture, &plan), ServiceManifestError::InvalidResourceCeiling);
        fixture = Fixture{};
        WriteLe64(fixture.bytes.data() + ServiceOffset(0) + kRowFrameBudgetOffset, 0);
        EXPECT_EQ(ValidateMutated(&fixture, &plan), ServiceManifestError::InvalidFrameBudget);
        fixture = Fixture{};
        WriteLe64(fixture.bytes.data() + ServiceOffset(0) + kRowTickBudgetOffset, 0);
        EXPECT_EQ(ValidateMutated(&fixture, &plan), ServiceManifestError::InvalidTickBudget);
    }

    // Signer/profile/manifest selectors bind the same sealed bytes to one exact
    // retained profile.  Replaying them under a different authority never gains
    // that profile's broader ceilings.
    {
        Fixture fixture;
        ServiceManifestPlanV1 plan{};
        ServiceManifestAuthoritySnapshotV1 replay = fixture.authority;
        EXPECT_EQ(ServiceManifestDocumentValidateAgainstAuthorityV1(fixture.document, replay),
                  ServiceManifestError::Ok);
        replay.profile_identity += 1;
        EXPECT_TRUE(ServiceManifestAuthoritySnapshotIsCanonicalV1(replay));
        EXPECT_EQ(ServiceManifestValidateV1(fixture.bytes.data(), fixture.byte_count, &replay, &plan),
                  ServiceManifestError::ProfileMismatch);
        EXPECT_EQ(ServiceManifestDocumentValidateAgainstAuthorityV1(fixture.document, replay),
                  ServiceManifestError::ProfileMismatch);
        replay = fixture.authority;
        replay.signer_identity += 1;
        EXPECT_EQ(ServiceManifestValidateV1(fixture.bytes.data(), fixture.byte_count, &replay, &plan),
                  ServiceManifestError::SignerMismatch);
        EXPECT_EQ(ServiceManifestDocumentValidateAgainstAuthorityV1(fixture.document, replay),
                  ServiceManifestError::SignerMismatch);
        replay = fixture.authority;
        replay.manifest_identity += 1;
        EXPECT_EQ(ServiceManifestValidateV1(fixture.bytes.data(), fixture.byte_count, &replay, &plan),
                  ServiceManifestError::InvalidManifestIdentity);
        EXPECT_EQ(ServiceManifestDocumentValidateAgainstAuthorityV1(fixture.document, replay),
                  ServiceManifestError::InvalidManifestIdentity);
        replay = fixture.authority;
        replay.allowed_capabilities = 0;
        EXPECT_TRUE(ServiceManifestAuthoritySnapshotIsCanonicalV1(replay));
        EXPECT_EQ(ServiceManifestValidateV1(fixture.bytes.data(), fixture.byte_count, &replay, &plan),
                  ServiceManifestError::CapabilityDenied);
        EXPECT_EQ(ServiceManifestDocumentValidateAgainstAuthorityV1(fixture.document, replay),
                  ServiceManifestError::CapabilityDenied);
        replay = fixture.authority;
        replay.maximum_frame_budget_pages = 64;
        EXPECT_EQ(ServiceManifestValidateV1(fixture.bytes.data(), fixture.byte_count, &replay, &plan),
                  ServiceManifestError::FrameBudgetDenied);
        EXPECT_EQ(ServiceManifestDocumentValidateAgainstAuthorityV1(fixture.document, replay),
                  ServiceManifestError::FrameBudgetDenied);
        replay = fixture.authority;
        replay.allowed_immutable_policies = 1ULL << 2;
        EXPECT_EQ(ServiceManifestValidateV1(fixture.bytes.data(), fixture.byte_count, &replay, &plan),
                  ServiceManifestError::ImmutablePolicyDenied);
        EXPECT_EQ(ServiceManifestDocumentValidateAgainstAuthorityV1(fixture.document, replay),
                  ServiceManifestError::ImmutablePolicyDenied);
        replay = fixture.authority;
        replay.allowed_service_kinds = 1u << static_cast<u8>(ServiceManifestKind::Win32);
        EXPECT_EQ(ServiceManifestValidateV1(fixture.bytes.data(), fixture.byte_count, &replay, &plan),
                  ServiceManifestError::ServiceKindDenied);
        EXPECT_EQ(ServiceManifestDocumentValidateAgainstAuthorityV1(fixture.document, replay),
                  ServiceManifestError::ServiceKindDenied);
        replay = fixture.authority;
        replay.allowed_resource_profiles = 1u << static_cast<u8>(ServiceManifestResourceProfile::Sandbox);
        EXPECT_EQ(ServiceManifestValidateV1(fixture.bytes.data(), fixture.byte_count, &replay, &plan),
                  ServiceManifestError::ResourceProfileDenied);
        EXPECT_EQ(ServiceManifestDocumentValidateAgainstAuthorityV1(fixture.document, replay),
                  ServiceManifestError::ResourceProfileDenied);
        replay = fixture.authority;
        replay.maximum_section_objects = 1;
        EXPECT_EQ(ServiceManifestValidateV1(fixture.bytes.data(), fixture.byte_count, &replay, &plan),
                  ServiceManifestError::ResourceCeilingDenied);
        EXPECT_EQ(ServiceManifestDocumentValidateAgainstAuthorityV1(fixture.document, replay),
                  ServiceManifestError::ResourceCeilingDenied);
        replay = fixture.authority;
        replay.maximum_tick_budget = 5000;
        EXPECT_EQ(ServiceManifestValidateV1(fixture.bytes.data(), fixture.byte_count, &replay, &plan),
                  ServiceManifestError::TickBudgetDenied);
        EXPECT_EQ(ServiceManifestDocumentValidateAgainstAuthorityV1(fixture.document, replay),
                  ServiceManifestError::TickBudgetDenied);
        replay = fixture.authority;
        replay.maximum_services = 2;
        EXPECT_EQ(ServiceManifestValidateV1(fixture.bytes.data(), fixture.byte_count, &replay, &plan),
                  ServiceManifestError::ServiceCountDenied);
        EXPECT_EQ(ServiceManifestDocumentValidateAgainstAuthorityV1(fixture.document, replay),
                  ServiceManifestError::ServiceCountDenied);
        replay = fixture.authority;
        replay.maximum_dependencies = 2;
        EXPECT_EQ(ServiceManifestValidateV1(fixture.bytes.data(), fixture.byte_count, &replay, &plan),
                  ServiceManifestError::DependencyCountDenied);
        EXPECT_EQ(ServiceManifestDocumentValidateAgainstAuthorityV1(fixture.document, replay),
                  ServiceManifestError::DependencyCountDenied);

        replay = fixture.authority;
        replay.flags = 0;
        EXPECT_EQ(ServiceManifestDocumentValidateAgainstAuthorityV1(fixture.document, replay),
                  ServiceManifestError::AuthorityMalformed);
    }

    // Output never aliases hostile bytes or trusted authority.  In particular,
    // pointing the authority parameter into the manifest cannot manufacture a
    // trusted signer/profile snapshot.
    {
        Fixture fixture;
        ServiceManifestPlanV1 plan{};
        PoisonPlan(&plan);
        auto* wire_snapshot = reinterpret_cast<const ServiceManifestAuthoritySnapshotV1*>(
            fixture.bytes.data() + kServiceManifestV1HeaderBytes);
        EXPECT_EQ(ServiceManifestValidateV1(fixture.bytes.data(), fixture.byte_count, wire_snapshot, &plan),
                  ServiceManifestError::SnapshotFromWire);
        EXPECT_EQ(plan.authority_identity, ~0ULL);

        const u8 first_byte = fixture.bytes[0];
        auto* aliased_plan = reinterpret_cast<ServiceManifestPlanV1*>(fixture.bytes.data());
        EXPECT_EQ(ServiceManifestValidateV1(fixture.bytes.data(), fixture.byte_count, &fixture.authority, aliased_plan),
                  ServiceManifestError::AliasedOutput);
        EXPECT_EQ(fixture.bytes[0], first_byte);

        const u64 document_identity = fixture.document.manifest_identity;
        EXPECT_EQ(ServiceManifestEncodeV1(&fixture.document, sizeof(fixture.document), fixture.document).error,
                  ServiceManifestError::DefinitionAliasesOutput);
        EXPECT_EQ(fixture.document.manifest_identity, document_identity);

        duetos::loader::Hash256* aliased_hash = &fixture.document.services[0].executable_content_hash;
        const duetos::loader::Hash256 preserved_hash = *aliased_hash;
        EXPECT_EQ(ServiceManifestDocumentHashV1(fixture.document, nullptr), ServiceManifestError::NullArgument);
        auto* invalid_hash = reinterpret_cast<duetos::loader::Hash256*>(~static_cast<duetos::uptr>(0) - 15);
        EXPECT_EQ(ServiceManifestDocumentHashV1(fixture.document, invalid_hash),
                  ServiceManifestError::InvalidPointerRange);
        EXPECT_EQ(ServiceManifestDocumentHashV1(fixture.document, aliased_hash),
                  ServiceManifestError::DefinitionAliasesOutput);
        EXPECT_TRUE(HashEquals(*aliased_hash, preserved_hash));

        ServiceManifestDocumentV1 invalid_document = fixture.document;
        invalid_document.flags = 1;
        duetos::loader::Hash256 cleared_hash = MakeHash(0xE0);
        EXPECT_EQ(ServiceManifestDocumentHashV1(invalid_document, &cleared_hash), ServiceManifestError::UnknownFlags);
        EXPECT_TRUE(HashIsZero(cleared_hash));
    }

    // Dependency values are identities, never slots.  Supplying array index 1
    // in place of stable identity 100 is a missing dependency, not an alias to
    // whichever service currently occupies slot 1.
    {
        Fixture fixture;
        ServiceManifestPlanV1 plan{};
        const u32 edge = DependencyOffset(fixture.document.service_count, 0);
        WriteLe64(fixture.bytes.data() + edge + 8, 1);
        EXPECT_EQ(ValidateMutated(&fixture, &plan), ServiceManifestError::MissingDependency);
    }
    {
        Fixture fixture;
        ServiceManifestPlanV1 plan{};
        WriteLe64(fixture.bytes.data() + ServiceOffset(1), 100);
        EXPECT_EQ(ValidateMutated(&fixture, &plan), ServiceManifestError::DuplicateServiceIdentity);
        fixture = Fixture{};
        for (u32 index = 0; index < kServiceManifestServiceNameCapacity; ++index)
        {
            fixture.bytes[ServiceOffset(1) + kRowNameOffset + index] =
                fixture.bytes[ServiceOffset(0) + kRowNameOffset + index];
        }
        fixture.bytes[ServiceOffset(1) + 84] = fixture.bytes[ServiceOffset(0) + 84];
        EXPECT_EQ(ValidateMutated(&fixture, &plan), ServiceManifestError::DuplicateServiceName);
        fixture = Fixture{};
        WriteLe32(fixture.bytes.data() + ServiceOffset(1) + kRowTransferRefOffset,
                  fixture.document.services[0].executable_transfer_ref);
        EXPECT_EQ(ValidateMutated(&fixture, &plan), ServiceManifestError::DuplicateTransferReference);
    }

    // Both native documents and independently sealed hostile bytes must form a
    // DAG.  A three-node cycle has valid identities/ranges but no topological
    // first node.
    {
        ServiceManifestDocumentV1 cycle = MakeDocument();
        cycle.services[0].dependency_first = 0;
        cycle.services[0].dependency_count = 1;
        cycle.services[1].dependency_first = 1;
        cycle.services[1].dependency_count = 1;
        cycle.services[2].dependency_first = 2;
        cycle.services[2].dependency_count = 1;
        cycle.dependencies[0] = ServiceManifestDependencyV1{100, 300};
        cycle.dependencies[1] = ServiceManifestDependencyV1{200, 100};
        cycle.dependencies[2] = ServiceManifestDependencyV1{300, 200};
        EXPECT_EQ(ServiceManifestDocumentValidateV1(cycle), ServiceManifestError::DependencyCycle);

        Fixture fixture;
        ServiceManifestPlanV1 plan{};
        WriteLe16(fixture.bytes.data() + ServiceOffset(0) + kRowDependencyFirstOffset, 0);
        WriteLe16(fixture.bytes.data() + ServiceOffset(0) + kRowDependencyCountOffset, 1);
        WriteLe16(fixture.bytes.data() + ServiceOffset(1) + kRowDependencyFirstOffset, 1);
        WriteLe16(fixture.bytes.data() + ServiceOffset(1) + kRowDependencyCountOffset, 1);
        WriteLe16(fixture.bytes.data() + ServiceOffset(2) + kRowDependencyFirstOffset, 2);
        WriteLe16(fixture.bytes.data() + ServiceOffset(2) + kRowDependencyCountOffset, 1);
        WriteLe64(fixture.bytes.data() + DependencyOffset(3, 0), 100);
        WriteLe64(fixture.bytes.data() + DependencyOffset(3, 0) + 8, 300);
        WriteLe64(fixture.bytes.data() + DependencyOffset(3, 1), 200);
        WriteLe64(fixture.bytes.data() + DependencyOffset(3, 1) + 8, 100);
        WriteLe64(fixture.bytes.data() + DependencyOffset(3, 2), 300);
        WriteLe64(fixture.bytes.data() + DependencyOffset(3, 2) + 8, 200);
        EXPECT_EQ(ValidateMutated(&fixture, &plan), ServiceManifestError::DependencyCycle);
    }

    // Exact maxima remain representable without allocation or arithmetic wrap.
    {
        ServiceManifestDocumentV1 maximum = MakeMaximumDocument();
        EXPECT_EQ(ServiceManifestDocumentValidateV1(maximum), ServiceManifestError::Ok);
        std::array<u8, kServiceManifestMaximumBytes> bytes{};
        const auto encoded = ServiceManifestEncodeV1(bytes.data(), bytes.size(), maximum);
        EXPECT_EQ(encoded.error, ServiceManifestError::Ok);
        EXPECT_EQ(encoded.bytes_written, kServiceManifestMaximumBytes);
        duetos::loader::Hash256 incremental_hash{};
        duetos::loader::Hash256 contiguous_hash{};
        EXPECT_EQ(ServiceManifestDocumentHashV1(maximum, &incremental_hash), ServiceManifestError::Ok);
        duetos::crypto::Sha256Hash(bytes.data(), encoded.bytes_written, contiguous_hash.bytes);
        EXPECT_TRUE(HashEquals(incremental_hash, contiguous_hash));
        auto authority = MakeAuthority(maximum, bytes.data(), encoded.bytes_written);
        ServiceManifestPlanV1 plan{};
        EXPECT_EQ(ServiceManifestValidateV1(bytes.data(), encoded.bytes_written, &authority, &plan),
                  ServiceManifestError::Ok);
        EXPECT_EQ(plan.document.service_count, kServiceManifestMaximumServices);
        EXPECT_EQ(plan.document.dependency_count, kServiceManifestMaximumDependencies);
        EXPECT_EQ(plan.topological_count, kServiceManifestMaximumServices);

        maximum.service_count = static_cast<u16>(kServiceManifestMaximumServices + 1);
        EXPECT_EQ(ServiceManifestDocumentValidateV1(maximum), ServiceManifestError::TooManyServices);
        maximum.service_count = static_cast<u16>(kServiceManifestMaximumServices);
        maximum.dependency_count = static_cast<u16>(kServiceManifestMaximumDependencies + 1);
        EXPECT_EQ(ServiceManifestDocumentValidateV1(maximum), ServiceManifestError::TooManyDependencies);
    }

    // Deterministic structured mutation: every independently re-hashed case is
    // either rejected or decodes to a document whose canonical re-encoding is
    // byte-identical.  This exercises framing, row, edge, and padding fields.
    {
        Fixture fixture;
        std::array<u8, kServiceManifestMaximumBytes> mutated{};
        std::array<u8, kServiceManifestMaximumBytes> canonical{};
        ServiceManifestPlanV1 plan{};
        u32 state = 0xC001D00Du;
        u32 rejected = 0;
        u32 accepted = 0;
        for (u32 iteration = 0; iteration < 512; ++iteration)
        {
            std::memcpy(mutated.data(), fixture.bytes.data(), fixture.byte_count);
            const u32 changes = iteration == 0 ? 0 : 1 + (NextFuzz(&state) & 3u);
            for (u32 change = 0; change < changes; ++change)
            {
                const u32 offset = NextFuzz(&state) % fixture.byte_count;
                mutated[offset] ^= static_cast<u8>(1u << (NextFuzz(&state) & 7u));
            }
            ServiceManifestAuthoritySnapshotV1 authority = fixture.authority;
            RefreshHash(mutated.data(), fixture.byte_count, &authority);
            const ServiceManifestError error =
                ServiceManifestValidateV1(mutated.data(), fixture.byte_count, &authority, &plan);
            if (error != ServiceManifestError::Ok)
            {
                ++rejected;
                ExpectCleared(plan);
                continue;
            }

            ++accepted;
            const auto encoded = ServiceManifestEncodeV1(canonical.data(), canonical.size(), plan.document);
            EXPECT_EQ(encoded.error, ServiceManifestError::Ok);
            EXPECT_EQ(encoded.bytes_written, fixture.byte_count);
            EXPECT_TRUE(std::memcmp(canonical.data(), mutated.data(), fixture.byte_count) == 0);
        }
        EXPECT_TRUE(rejected != 0);
        EXPECT_TRUE(accepted != 0);
    }

    EXPECT_STREQ(ServiceManifestErrorName(ServiceManifestError::DependencyCycle), "dependency-cycle");
    EXPECT_STREQ(ServiceManifestErrorName(static_cast<ServiceManifestError>(0xFF)), "?");
    return duetos_host_test::finish_main("test_service_manifest");
}
