// Hosted authority, one-to-one binding, mutation, and lifecycle-broker coverage
// for core/service_object_package.{h,cpp}.

#include "crypto_host_shims.h"
#include "host_test_helper.h"
#include "core/service_directory.h"
#include "core/service_lifecycle_broker.h"
#include "core/service_object_package.h"
#include "crypto/sha256.h"

#include <array>
#include <cstring>
#include <mutex>

namespace
{

std::mutex g_host_spinlock;

} // namespace

namespace duetos::sync
{

IrqFlags SpinLockAcquire(SpinLock&)
{
    g_host_spinlock.lock();
    return IrqFlags{0};
}

void SpinLockRelease(SpinLock&, IrqFlags)
{
    g_host_spinlock.unlock();
}

} // namespace duetos::sync

namespace duetos::core
{

// This fixture exercises package authority and the lifecycle state machine,
// not the separately hosted lifecycle-to-directory publication join.  The
// broker object contains both surfaces, so keep the unused join leaves inert.
ServiceDirectoryStatus ServiceDirectoryPublishRegistration(ServiceDirectory*, ServiceRegistrationReservation*,
                                                           ServiceInstanceToken)
{
    return ServiceDirectoryStatus::CorruptState;
}

ServiceDirectoryStatus ServiceDirectoryCommitJointReady(ServiceDirectory*, ServiceKey, ServiceInstanceToken, bool*)
{
    return ServiceDirectoryStatus::CorruptState;
}

} // namespace duetos::core

namespace
{

using duetos::u16;
using duetos::u32;
using duetos::u64;
using duetos::u8;
using namespace duetos::core;

constexpr u32 kSecondServiceTransferRefOffset = kServiceManifestV1HeaderBytes + kServiceManifestV1ServiceBytes + 8;

void SetText(u8* destination, u32 capacity, u8* length_out, const char* text)
{
    const u32 length = static_cast<u32>(std::strlen(text));
    EXPECT_TRUE(length <= capacity);
    for (u32 index = 0; index < capacity; ++index)
        destination[index] = index < length ? static_cast<u8>(text[index]) : 0;
    *length_out = static_cast<u8>(length);
}

void WriteLe32(u8* bytes, u32 value)
{
    bytes[0] = static_cast<u8>(value);
    bytes[1] = static_cast<u8>(value >> 8u);
    bytes[2] = static_cast<u8>(value >> 16u);
    bytes[3] = static_cast<u8>(value >> 24u);
}

bool HashEquals(const duetos::loader::Hash256& left, const duetos::loader::Hash256& right)
{
    return std::memcmp(left.bytes, right.bytes, sizeof(left.bytes)) == 0;
}

bool AllZero(const void* value, u64 byte_count)
{
    const auto* bytes = static_cast<const u8*>(value);
    for (u64 index = 0; index < byte_count; ++index)
    {
        if (bytes[index] != 0)
            return false;
    }
    return true;
}

ServiceManifestServiceV1 MakeService(u64 identity, u32 transfer_ref, u32 policy, const char* name, const char* path,
                                     const u8* bytes, u32 byte_count)
{
    ServiceManifestServiceV1 service{};
    service.service_identity = identity;
    service.executable_transfer_ref = transfer_ref;
    service.immutable_policy_selector = policy;
    duetos::crypto::Sha256Hash(bytes, byte_count, service.executable_content_hash.bytes);
    service.requested_capability_ceiling = 1ULL << 2;
    service.requested_frame_budget_pages = 128;
    service.requested_tick_budget = 10000;
    service.requested_section_objects = 2;
    service.requested_section_pages = 64;
    service.kind = ServiceManifestKind::Native;
    service.restart_policy = ServiceManifestRestartPolicy::Always;
    service.autostart = 1;
    service.resource_profile = ServiceManifestResourceProfile::AuthenticatedService;
    SetText(service.name, kServiceManifestServiceNameCapacity, &service.name_length, name);
    SetText(service.executable_path, kServiceManifestExecutablePathCapacity, &service.executable_path_length, path);
    return service;
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

struct Fixture
{
    std::array<u8, 9> serviced_bytes{{0x7F, 'E', 'L', 'F', 2, 1, 1, 0, 0x51}};
    std::array<u8, 11> execd_bytes{{'M', 'Z', 0x90, 0, 3, 0, 0, 0, 4, 0, 0x62}};
    ServiceManifestDocumentV1 document{};
    std::array<u8, kServiceManifestMaximumBytes> manifest_bytes{};
    u32 manifest_byte_count = 0;
    ServiceManifestAuthoritySnapshotV1 authority{};
    std::array<ServiceExecutableObjectDefinitionV1, 2> objects{};
    ServiceObjectPackageDefinitionV1 definition{};

    Fixture()
    {
        document.manifest_identity = 0xA001;
        document.signer_identity = 0xB001;
        document.profile_identity = 0xC001;
        document.service_count = 2;
        document.dependency_count = 1;
        document.services[0] = MakeService(0x100, 1, 1, "serviced", "/system/serviced", serviced_bytes.data(),
                                           static_cast<u32>(serviced_bytes.size()));
        document.services[1] = MakeService(0x200, 2, 2, "execd", "/system/execd", execd_bytes.data(),
                                           static_cast<u32>(execd_bytes.size()));
        document.services[0].dependency_first = 0;
        document.services[0].dependency_count = 0;
        document.services[1].dependency_first = 0;
        document.services[1].dependency_count = 1;
        document.dependencies[0] = ServiceManifestDependencyV1{0x200, 0x100};

        const ServiceManifestEncodeResult encoded =
            ServiceManifestEncodeV1(manifest_bytes.data(), manifest_bytes.size(), document);
        EXPECT_EQ(encoded.error, ServiceManifestError::Ok);
        manifest_byte_count = encoded.bytes_written;
        authority = MakeAuthority(document, manifest_bytes.data(), manifest_byte_count);

        objects[0] = ServiceExecutableObjectDefinitionV1{
            1, 1, serviced_bytes.data(), serviced_bytes.size(), kServiceObjectDefinitionSealed, 0};
        objects[1] = ServiceExecutableObjectDefinitionV1{
            2, 2, execd_bytes.data(), execd_bytes.size(), kServiceObjectDefinitionSealed, 0};
        RefreshDefinition();
    }

    void RefreshDefinition()
    {
        definition = ServiceObjectPackageDefinitionV1{manifest_bytes.data(),
                                                      manifest_byte_count,
                                                      &authority,
                                                      objects.data(),
                                                      static_cast<u32>(objects.size()),
                                                      0};
    }

    void RefreshManifestAuthority()
    {
        authority = MakeAuthority(document, manifest_bytes.data(), manifest_byte_count);
        RefreshDefinition();
    }
};

} // namespace

int main()
{
    {
        Fixture fixture;
        ServiceObjectPackageV1 package{};
        const ServiceObjectPackageResult initialized = ServiceObjectPackageInitializeV1(&package, &fixture.definition);
        EXPECT_EQ(initialized.status, ServiceObjectPackageStatus::Ok);
        EXPECT_EQ(package.executable_object_count, 2u);

        ServiceObjectPackageManifestV1 manifest{};
        EXPECT_EQ(ServiceObjectPackageGetManifestV1(&package, &manifest).status, ServiceObjectPackageStatus::Ok);
        EXPECT_TRUE(manifest.plan == &package.manifest_plan);
        EXPECT_TRUE(manifest.authority == &package.manifest_authority);

        ServiceLifecycleBroker broker{};
        ServiceLifecycleBrokerEpoch epoch = ServiceLifecycleBrokerMintEpoch();
        EXPECT_EQ(ServiceLifecycleBrokerInitialize(&broker, manifest.plan, manifest.authority, &epoch),
                  ServiceLifecycleStatus::Ok);
        EXPECT_TRUE(!epoch.IsValid());

        ServiceExecutableTransferSnapshotV1 transfer{};
        ServiceObjectPackageResult resolved = ServiceObjectPackageResolveExecutableV1(&package, 0x100, 1, &transfer);
        EXPECT_EQ(resolved.status, ServiceObjectPackageStatus::Ok);
        EXPECT_EQ(resolved.object_index, 0u);
        EXPECT_TRUE(transfer.bytes == fixture.serviced_bytes.data());
        EXPECT_EQ(transfer.byte_count, fixture.serviced_bytes.size());
        EXPECT_TRUE(HashEquals(transfer.content_hash, fixture.document.services[0].executable_content_hash));

        resolved = ServiceObjectPackageResolveExecutableV1(&package, 0x200, 1, &transfer);
        EXPECT_EQ(resolved.status, ServiceObjectPackageStatus::ServiceBindingMismatch);
        EXPECT_TRUE(transfer.bytes == nullptr);
        EXPECT_EQ(ServiceObjectPackageResolveExecutableV1(&package, 0x100, 77, &transfer).status,
                  ServiceObjectPackageStatus::NotFound);
        EXPECT_EQ(ServiceObjectPackageResolveExecutableV1(&package, 0, 1, &transfer).status,
                  ServiceObjectPackageStatus::InvalidSelector);

        const auto serviced_before_alias_probe = fixture.serviced_bytes;
        auto* aliased_manifest = reinterpret_cast<ServiceObjectPackageManifestV1*>(fixture.serviced_bytes.data());
        EXPECT_EQ(ServiceObjectPackageGetManifestV1(&package, aliased_manifest).status,
                  ServiceObjectPackageStatus::AliasedOutput);
        auto* aliased_transfer = reinterpret_cast<ServiceExecutableTransferSnapshotV1*>(fixture.serviced_bytes.data());
        EXPECT_EQ(ServiceObjectPackageResolveExecutableV1(&package, 0x100, 1, aliased_transfer).status,
                  ServiceObjectPackageStatus::AliasedOutput);
        EXPECT_TRUE(fixture.serviced_bytes == serviced_before_alias_probe);

        fixture.serviced_bytes[4] ^= 0x55;
        EXPECT_EQ(ServiceObjectPackageResolveExecutableV1(&package, 0x100, 1, &transfer).status,
                  ServiceObjectPackageStatus::CorruptPackage);
        EXPECT_EQ(ServiceObjectPackageGetManifestV1(&package, &manifest).status,
                  ServiceObjectPackageStatus::CorruptPackage);
    }

    // A duplicate ref is rejected by the manifest trust boundary before the
    // package resolver can observe an ambiguous row.
    {
        Fixture fixture;
        WriteLe32(fixture.manifest_bytes.data() + kSecondServiceTransferRefOffset, 1);
        fixture.RefreshManifestAuthority();
        ServiceObjectPackageV1 package{};
        const ServiceObjectPackageResult result = ServiceObjectPackageInitializeV1(&package, &fixture.definition);
        EXPECT_EQ(result.status, ServiceObjectPackageStatus::ManifestRejected);
        EXPECT_EQ(result.manifest_error, ServiceManifestError::DuplicateTransferReference);
        EXPECT_TRUE(AllZero(&package, sizeof(package)));
    }

    {
        Fixture fixture;
        fixture.objects[1].executable_transfer_ref = 1;
        fixture.RefreshDefinition();
        ServiceObjectPackageV1 package{};
        EXPECT_EQ(ServiceObjectPackageInitializeV1(&package, &fixture.definition).status,
                  ServiceObjectPackageStatus::DuplicateTransferReference);
        EXPECT_TRUE(AllZero(&package, sizeof(package)));
    }

    {
        Fixture fixture;
        fixture.serviced_bytes[0] ^= 0x11;
        ServiceObjectPackageV1 package{};
        EXPECT_EQ(ServiceObjectPackageInitializeV1(&package, &fixture.definition).status,
                  ServiceObjectPackageStatus::ContentHashMismatch);
        EXPECT_TRUE(AllZero(&package, sizeof(package)));
    }

    {
        Fixture fixture;
        fixture.objects[1].immutable_policy_selector = 1;
        fixture.RefreshDefinition();
        ServiceObjectPackageV1 package{};
        EXPECT_EQ(ServiceObjectPackageInitializeV1(&package, &fixture.definition).status,
                  ServiceObjectPackageStatus::ImmutablePolicyMismatch);
        EXPECT_TRUE(AllZero(&package, sizeof(package)));
    }

    {
        Fixture fixture;
        fixture.definition.executable_object_count = 1;
        ServiceObjectPackageV1 package{};
        EXPECT_EQ(ServiceObjectPackageInitializeV1(&package, &fixture.definition).status,
                  ServiceObjectPackageStatus::ObjectCountMismatch);
        EXPECT_TRUE(AllZero(&package, sizeof(package)));
    }

    {
        Fixture fixture;
        fixture.objects[1].executable_transfer_ref = 3;
        fixture.RefreshDefinition();
        ServiceObjectPackageV1 package{};
        EXPECT_EQ(ServiceObjectPackageInitializeV1(&package, &fixture.definition).status,
                  ServiceObjectPackageStatus::UnexpectedTransferReference);
        EXPECT_TRUE(AllZero(&package, sizeof(package)));
    }

    {
        Fixture fixture;
        fixture.authority.flags = 0;
        ServiceObjectPackageV1 package{};
        const ServiceObjectPackageResult result = ServiceObjectPackageInitializeV1(&package, &fixture.definition);
        EXPECT_EQ(result.status, ServiceObjectPackageStatus::ManifestRejected);
        EXPECT_EQ(result.manifest_error, ServiceManifestError::AuthorityMalformed);
        EXPECT_TRUE(AllZero(&package, sizeof(package)));
    }

    {
        Fixture fixture;
        fixture.objects[1].bytes = fixture.objects[0].bytes;
        fixture.objects[1].byte_count = fixture.objects[0].byte_count;
        fixture.RefreshDefinition();
        ServiceObjectPackageV1 package{};
        EXPECT_EQ(ServiceObjectPackageInitializeV1(&package, &fixture.definition).status,
                  ServiceObjectPackageStatus::ObjectRangeOverlap);
        EXPECT_TRUE(AllZero(&package, sizeof(package)));
    }

    {
        Fixture fixture;
        ServiceObjectPackageV1 package{};
        package.version = 9;
        EXPECT_EQ(ServiceObjectPackageInitializeV1(&package, &fixture.definition).status,
                  ServiceObjectPackageStatus::NonCanonicalStorage);
    }

    // Repeated construction exercises one-shot authority retention and exact
    // transfer resolution without retaining definition-array storage.
    {
        Fixture fixture;
        for (u32 cycle = 0; cycle < 10000; ++cycle)
        {
            ServiceObjectPackageV1 package{};
            EXPECT_EQ(ServiceObjectPackageInitializeV1(&package, &fixture.definition).status,
                      ServiceObjectPackageStatus::Ok);
            ServiceExecutableTransferSnapshotV1 transfer{};
            EXPECT_EQ(ServiceObjectPackageResolveExecutableV1(&package, 0x200, 2, &transfer).status,
                      ServiceObjectPackageStatus::Ok);
            EXPECT_TRUE(transfer.bytes == fixture.execd_bytes.data());
        }
    }

    EXPECT_STREQ(ServiceObjectPackageStatusName(ServiceObjectPackageStatus::ContentHashMismatch),
                 "content-hash-mismatch");
    EXPECT_STREQ(ServiceObjectPackageStatusName(static_cast<ServiceObjectPackageStatus>(0xFF)), "unknown");
    return duetos_host_test::finish_main("test_service_object_package");
}
