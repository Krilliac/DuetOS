// Hosted end-to-end coverage for the unpublished service bootstrap staging
// seam: authorized package -> typed LoadImage backing -> ExecAdmission.

#include "crypto_host_shims.h"
#include "host_test_helper.h"

#include "core/service_bootstrap_stage.h"
#include "crypto/sha256.h"

#include <array>
#include <cstring>

namespace parser_fixture
{

using duetos::u32;
using duetos::u64;
using duetos::u8;
using duetos::core::ElfSegment;
using duetos::core::ElfStatus;

inline std::array<ElfSegment, 4> segments{};
inline u32 segment_count = 0;
inline u64 entry_point = 0x400080;
inline ElfStatus validation_status = ElfStatus::Ok;

void Reset()
{
    segments = {};
    segment_count = 0;
    entry_point = 0x400080;
    validation_status = ElfStatus::Ok;
}

void AddSegment(u64 file_offset, u64 virtual_address, u64 file_size, u64 memory_size, u8 flags)
{
    EXPECT_TRUE(segment_count < segments.size());
    if (segment_count < segments.size())
        segments[segment_count++] = ElfSegment{file_offset, virtual_address, file_size, memory_size, 4096, flags, {}};
}

void AddSingleRxSegment()
{
    AddSegment(64, 0x400080, 32, 128, duetos::core::kElfPfR | duetos::core::kElfPfX);
}

} // namespace parser_fixture

namespace duetos::core
{

ElfStatus ElfValidate(const u8*, u64)
{
    return parser_fixture::validation_status;
}

u64 ElfEntry(const u8*)
{
    return parser_fixture::entry_point;
}

u32 ElfForEachPtLoad(const u8*, u64, ElfSegmentCb callback, void* cookie)
{
    if (callback == nullptr)
        return 0;
    for (u32 index = 0; index < parser_fixture::segment_count; ++index)
        callback(parser_fixture::segments[index], cookie);
    return parser_fixture::segment_count;
}

const char* ElfStatusName(ElfStatus)
{
    return "fake";
}

void ElfProgramHeaderInfo(const u8*, u64*, u16*, u16*) {}

} // namespace duetos::core

namespace
{

using duetos::u16;
using duetos::u32;
using duetos::u64;
using duetos::u8;
using namespace duetos::core;
using namespace duetos::loader;

constexpr u32 kPageCapacity = 4;
constexpr u32 kRegionCapacity = 4;
constexpr u32 kFrameCapacity = 8;

struct FakeFrame
{
    LoadImageFrame identity;
    std::array<u8, kLoadPlanPageSize> bytes;
    bool live;
};

struct FakeArena
{
    std::array<FakeFrame, kFrameCapacity> frames{};
    u32 attempts = 0;
    u32 count = 0;
    u32 live = 0;
    u32 releases = 0;
    u32 fail_at_attempt = ~0U;
};

bool AllocateFrame(void* raw_context, LoadImageFrame* frame_out, u8** bytes_out)
{
    auto& arena = *static_cast<FakeArena*>(raw_context);
    ++arena.attempts;
    if (arena.count == arena.fail_at_attempt || arena.count >= arena.frames.size())
        return false;
    FakeFrame& frame = arena.frames[arena.count];
    ++arena.count;
    frame = FakeFrame{arena.count, {}, true};
    ++arena.live;
    *frame_out = frame.identity;
    *bytes_out = frame.bytes.data();
    return true;
}

void ReleaseFrame(void* raw_context, LoadImageFrame identity)
{
    auto& arena = *static_cast<FakeArena*>(raw_context);
    EXPECT_TRUE(identity != 0);
    EXPECT_TRUE(identity <= arena.count);
    if (identity == 0 || identity > arena.count)
        return;
    FakeFrame& frame = arena.frames[static_cast<u32>(identity - 1u)];
    EXPECT_TRUE(frame.live);
    if (!frame.live)
        return;
    frame.live = false;
    --arena.live;
    ++arena.releases;
}

struct FakeMapTarget
{
    u32 mappings = 0;
};

bool MapOwnedFrame(void* raw_context, u64 virtual_address, LoadImageFrame frame, VmProtection protection)
{
    auto& target = *static_cast<FakeMapTarget*>(raw_context);
    EXPECT_TRUE(virtual_address != 0);
    EXPECT_TRUE(frame != kLoadImageInvalidFrame);
    EXPECT_TRUE(protection != VmProtection::None);
    if (virtual_address == 0 || frame == kLoadImageInvalidFrame || protection == VmProtection::None)
        return false;
    ++target.mappings;
    return true;
}

bool RejectOwnedFrame(void*, u64, LoadImageFrame, VmProtection)
{
    return false;
}

bool UnmapOwnedFrame(void* raw_context, u64 virtual_address, LoadImageFrame expected_frame)
{
    auto& target = *static_cast<FakeMapTarget*>(raw_context);
    EXPECT_TRUE(virtual_address != 0);
    EXPECT_TRUE(expected_frame != kLoadImageInvalidFrame);
    EXPECT_TRUE(target.mappings != 0);
    if (virtual_address == 0 || expected_frame == kLoadImageInvalidFrame || target.mappings == 0)
        return false;
    --target.mappings;
    return true;
}

struct SlotFixture
{
    FakeArena arena{};
    LoadImage image{};
    std::array<LoadImagePage, kPageCapacity> pages{};
    std::array<LoadImageRegionAuthority, kRegionCapacity> regions{};
    std::array<u8, kLoadImageMaxPlanBytes> plan{};
    ExecAdmission admission{};
    std::array<u8, kExecAdmissionMaxPlanBytes> admission_storage{};

    ServiceBootstrapSlotStorageV1 Storage()
    {
        return ServiceBootstrapSlotStorageV1{
            &image,
            LoadImageFrameHooks{&arena, &AllocateFrame, &ReleaseFrame},
            pages.data(),
            static_cast<u32>(pages.size()),
            regions.data(),
            static_cast<u32>(regions.size()),
            plan.data(),
            static_cast<u32>(plan.size()),
            &admission,
            admission_storage.data(),
            static_cast<u32>(admission_storage.size()),
            0,
        };
    }
};

void SetText(u8* destination, u32 capacity, u8* length_out, const char* text)
{
    const u32 length = static_cast<u32>(std::strlen(text));
    EXPECT_TRUE(length <= capacity);
    for (u32 index = 0; index < capacity; ++index)
        destination[index] = index < length ? static_cast<u8>(text[index]) : 0;
    *length_out = static_cast<u8>(length);
}

ServiceManifestServiceV1 MakeService(u64 identity, u32 transfer_ref, ServiceManifestKind kind, const char* name,
                                     const char* path, const u8* bytes, u32 byte_count)
{
    ServiceManifestServiceV1 service{};
    service.service_identity = identity;
    service.executable_transfer_ref = transfer_ref;
    service.immutable_policy_selector = 1;
    duetos::crypto::Sha256Hash(bytes, byte_count, service.executable_content_hash.bytes);
    service.requested_capability_ceiling = 1ULL << 2;
    service.requested_frame_budget_pages = 8;
    service.requested_tick_budget = 10000;
    service.requested_section_objects = 2;
    service.requested_section_pages = 64;
    service.kind = kind;
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
    authority.authority_identity = 0x4455455441555448ULL;
    authority.manifest_identity = document.manifest_identity;
    authority.signer_identity = document.signer_identity;
    authority.profile_identity = document.profile_identity;
    duetos::crypto::Sha256Hash(bytes, byte_count, authority.sealed_object_hash.bytes);
    authority.sealed_object_extent = byte_count;
    authority.allowed_capabilities = kServiceManifestCapabilityMaskV1;
    authority.allowed_immutable_policies = 1ULL << 1;
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

struct PackageFixture
{
    std::array<u8, 512> serviced_bytes{};
    std::array<u8, 512> execd_bytes{};
    ServiceManifestDocumentV1 document{};
    std::array<u8, kServiceManifestMaximumBytes> manifest_bytes{};
    u32 manifest_byte_count = 0;
    ServiceManifestAuthoritySnapshotV1 authority{};
    std::array<ServiceExecutableObjectDefinitionV1, 2> objects{};
    ServiceObjectPackageDefinitionV1 definition{};

    PackageFixture()
    {
        for (u32 index = 0; index < serviced_bytes.size(); ++index)
        {
            serviced_bytes[index] = static_cast<u8>((index * 17u + 3u) & 0xFFu);
            execd_bytes[index] = static_cast<u8>((index * 29u + 11u) & 0xFFu);
        }
        document.manifest_identity = 0x445545544D414E31ULL;
        document.signer_identity = 0x445545544255494CULL;
        document.profile_identity = 0x4455455453564331ULL;
        document.service_count = 2;
        document.dependency_count = 1;
        document.services[0] = MakeService(0x100, 1, ServiceManifestKind::Broker, "serviced", "/system/serviced",
                                           serviced_bytes.data(), static_cast<u32>(serviced_bytes.size()));
        document.services[1] = MakeService(0x200, 2, ServiceManifestKind::Native, "execd", "/system/execd",
                                           execd_bytes.data(), static_cast<u32>(execd_bytes.size()));
        document.services[1].dependency_first = 0;
        document.services[1].dependency_count = 1;
        document.dependencies[0] = ServiceManifestDependencyV1{0x200, 0x100};
        Refresh();
    }

    void Refresh()
    {
        manifest_bytes = {};
        const ServiceManifestEncodeResult encoded =
            ServiceManifestEncodeV1(manifest_bytes.data(), manifest_bytes.size(), document);
        EXPECT_EQ(encoded.error, ServiceManifestError::Ok);
        manifest_byte_count = encoded.bytes_written;
        authority = MakeAuthority(document, manifest_bytes.data(), manifest_byte_count);
        objects[0] = ServiceExecutableObjectDefinitionV1{
            1, 1, serviced_bytes.data(), serviced_bytes.size(), kServiceObjectDefinitionSealed, 0};
        objects[1] = ServiceExecutableObjectDefinitionV1{
            2, 1, execd_bytes.data(), execd_bytes.size(), kServiceObjectDefinitionSealed, 0};
        definition = ServiceObjectPackageDefinitionV1{manifest_bytes.data(),
                                                      manifest_byte_count,
                                                      &authority,
                                                      objects.data(),
                                                      static_cast<u32>(objects.size()),
                                                      0};
    }
};

struct StageFixture
{
    PackageFixture package{};
    std::array<SlotFixture, 2> slot_fixtures{};
    std::array<ServiceBootstrapSlotStorageV1, 2> slots{};
    ServiceBootstrapStageRuntimeV1 runtime{};

    StageFixture()
    {
        slots[0] = slot_fixtures[0].Storage();
        slots[1] = slot_fixtures[1].Storage();
    }

    ServiceBootstrapStageResultV1 Stage()
    {
        return ServiceBootstrapStageInitializeV1(&runtime, &package.definition, slots.data(),
                                                 static_cast<u32>(slots.size()));
    }
};

using StageRowBytes = std::array<u8, sizeof(ServiceBootstrapStageRowV1)>;
using ImageBytes = std::array<u8, sizeof(LoadImage)>;
using AdmissionBytes = std::array<u8, sizeof(ExecAdmission)>;

StageRowBytes CaptureRow(const ServiceBootstrapStageRowV1& row)
{
    StageRowBytes bytes{};
    std::memcpy(bytes.data(), &row, bytes.size());
    return bytes;
}

void ExpectRowUnchanged(const ServiceBootstrapStageRowV1& row, const StageRowBytes& before)
{
    EXPECT_EQ(std::memcmp(before.data(), &row, before.size()), 0);
}

template <typename T, size_t ByteCount = sizeof(T)> std::array<u8, ByteCount> CaptureObject(const T& object)
{
    std::array<u8, ByteCount> bytes{};
    std::memcpy(bytes.data(), &object, bytes.size());
    return bytes;
}

template <typename T, size_t ByteCount>
void ExpectObjectUnchanged(const T& object, const std::array<u8, ByteCount>& before)
{
    static_assert(ByteCount == sizeof(T));
    EXPECT_EQ(std::memcmp(before.data(), &object, before.size()), 0);
}

} // namespace

int main()
{
    {
        parser_fixture::Reset();
        parser_fixture::AddSingleRxSegment();
        StageFixture fixture;
        const ServiceBootstrapStageResultV1 result = fixture.Stage();
        EXPECT_EQ(result.status, ServiceBootstrapStageStatus::Ok);
        EXPECT_EQ(result.service_index, kServiceBootstrapNoServiceIndex);
        EXPECT_EQ(fixture.slot_fixtures[0].arena.live, 1u);
        EXPECT_EQ(fixture.slot_fixtures[1].arena.live, 1u);

        ServiceBootstrapStageSnapshotV1 runtime_snapshot{};
        EXPECT_EQ(ServiceBootstrapStageInspectV1(&fixture.runtime, &runtime_snapshot), ServiceBootstrapStageStatus::Ok);
        EXPECT_EQ(runtime_snapshot.state, ServiceBootstrapStageState::Ready);
        EXPECT_EQ(runtime_snapshot.service_count, 2u);
        EXPECT_EQ(runtime_snapshot.ready_count, 2u);
        EXPECT_EQ(runtime_snapshot.authority_identity, fixture.package.authority.authority_identity);
        EXPECT_TRUE(runtime_snapshot.registry_identity != 0);

        ServiceBootstrapServiceSnapshotV1 serviced{};
        ServiceBootstrapServiceSnapshotV1 execd{};
        EXPECT_EQ(ServiceBootstrapStageFindServiceV1(&fixture.runtime, 0x100, &serviced),
                  ServiceBootstrapStageStatus::Ok);
        EXPECT_EQ(ServiceBootstrapStageFindServiceV1(&fixture.runtime, 0x200, &execd), ServiceBootstrapStageStatus::Ok);
        EXPECT_TRUE(serviced.memory_object != execd.memory_object);
        EXPECT_EQ(serviced.memory_object & kServiceBootstrapMemoryObjectTypeMask, kServiceBootstrapMemoryObjectTypeTag);
        EXPECT_EQ(execd.memory_object & kServiceBootstrapMemoryObjectTypeMask, kServiceBootstrapMemoryObjectTypeTag);
        EXPECT_EQ(serviced.admitted_plan.header.format, ImageFormat::Elf64);

        LoadRegionV1 region{};
        ASSERT_TRUE(LoadPlanRegionAt(serviced.admitted_plan, 0, &region));
        LoadBackingInfoV1 backing{};
        EXPECT_TRUE(ServiceBootstrapStageBackingQueryV1(region.memory_object, region.object_offset, region.length,
                                                        &backing, &fixture.runtime));
        EXPECT_TRUE(backing.sealed != 0);
        EXPECT_FALSE(
            ServiceBootstrapStageBackingQueryV1(1, region.object_offset, region.length, &backing, &fixture.runtime));
        EXPECT_FALSE(ServiceBootstrapStageBackingQueryV1(execd.memory_object, region.object_offset + 1, region.length,
                                                         &backing, &fixture.runtime));

        const ObjectHandle saved_handle = fixture.runtime.rows[0].memory_object;
        fixture.runtime.rows[0].memory_object = execd.memory_object;
        EXPECT_EQ(ServiceBootstrapStageInspectV1(&fixture.runtime, &runtime_snapshot),
                  ServiceBootstrapStageStatus::CorruptRuntime);
        fixture.runtime.rows[0].memory_object = saved_handle;

        EXPECT_EQ(ServiceBootstrapStageDiscardV1(&fixture.runtime), ServiceBootstrapStageStatus::Ok);
        EXPECT_EQ(fixture.runtime.state, ServiceBootstrapStageState::Discarded);
        EXPECT_EQ(fixture.slot_fixtures[0].arena.live, 0u);
        EXPECT_EQ(fixture.slot_fixtures[1].arena.live, 0u);
    }

    // The same immutable package staged into a second live registry receives
    // a different non-wrapping namespace. A handle from the first runtime
    // cannot resolve against the second runtime's otherwise-identical row.
    {
        parser_fixture::Reset();
        parser_fixture::AddSingleRxSegment();
        StageFixture first;
        StageFixture second;
        EXPECT_EQ(first.Stage().status, ServiceBootstrapStageStatus::Ok);
        EXPECT_EQ(second.Stage().status, ServiceBootstrapStageStatus::Ok);
        EXPECT_TRUE(first.runtime.registry_identity != second.runtime.registry_identity);
        EXPECT_TRUE(first.runtime.rows[0].memory_object != second.runtime.rows[0].memory_object);

        LoadRegionV1 first_region{};
        ASSERT_TRUE(LoadPlanRegionAt(first.runtime.rows[0].admitted_plan, 0, &first_region));
        LoadBackingInfoV1 backing{};
        EXPECT_FALSE(ServiceBootstrapStageBackingQueryV1(first_region.memory_object, first_region.object_offset,
                                                         first_region.length, &backing, &second.runtime));
        EXPECT_EQ(ServiceBootstrapStageDiscardV1(&first.runtime), ServiceBootstrapStageStatus::Ok);
        EXPECT_EQ(ServiceBootstrapStageDiscardV1(&second.runtime), ServiceBootstrapStageStatus::Ok);
    }

    // A valid ownership transfer remains structurally canonical, but the
    // staging owner must refuse discard without releasing any sealed peer.
    {
        parser_fixture::Reset();
        parser_fixture::AddSingleRxSegment();
        StageFixture fixture;
        EXPECT_EQ(fixture.Stage().status, ServiceBootstrapStageStatus::Ok);

        FakeMapTarget target{};
        const LoadImageMapHooks map_hooks{&target, &MapOwnedFrame, &UnmapOwnedFrame};
        const LoadImageMapResult map_result = LoadImageMapInto(fixture.runtime.rows[0].image, map_hooks);
        EXPECT_EQ(map_result.status, LoadImageStatus::Ok);
        EXPECT_EQ(map_result.pages_mapped, 1u);
        EXPECT_EQ(fixture.runtime.rows[0].image->state, LoadImageState::Transferred);
        EXPECT_EQ(target.mappings, 1u);

        EXPECT_EQ(ServiceBootstrapStageDiscardV1(&fixture.runtime), ServiceBootstrapStageStatus::CannotDiscard);
        EXPECT_EQ(fixture.runtime.state, ServiceBootstrapStageState::Ready);
        EXPECT_EQ(fixture.slot_fixtures[0].arena.live, 1u);
        EXPECT_EQ(fixture.slot_fixtures[1].arena.live, 1u);
        EXPECT_EQ(fixture.slot_fixtures[0].arena.releases, 0u);
        EXPECT_EQ(fixture.slot_fixtures[1].arena.releases, 0u);
    }

    // Begin/Cancel/Finish are exact, generation-safe and one-shot. A sealed
    // cancellation is the sole retry path; transferred ownership can only be
    // recorded as a terminal publication and cannot be replayed or discarded.
    {
        parser_fixture::Reset();
        parser_fixture::AddSingleRxSegment();
        StageFixture fixture;
        EXPECT_EQ(fixture.Stage().status, ServiceBootstrapStageStatus::Ok);

        auto* aliased_lease = reinterpret_cast<ServiceBootstrapActivationLeaseV1*>(&fixture.runtime.rows[0]);
        EXPECT_EQ(ServiceBootstrapStageBeginActivationV1(&fixture.runtime, 0x100, aliased_lease),
                  ServiceBootstrapStageStatus::AliasedStorage);
        auto* image_alias = reinterpret_cast<ServiceBootstrapActivationLeaseV1*>(&fixture.slot_fixtures[0].image);
        EXPECT_EQ(ServiceBootstrapStageBeginActivationV1(&fixture.runtime, 0x100, image_alias),
                  ServiceBootstrapStageStatus::AliasedStorage);
        auto* plan_alias = reinterpret_cast<ServiceBootstrapActivationLeaseV1*>(fixture.slot_fixtures[0].plan.data());
        EXPECT_EQ(ServiceBootstrapStageBeginActivationV1(&fixture.runtime, 0x100, plan_alias),
                  ServiceBootstrapStageStatus::AliasedStorage);
        auto* artifact_alias =
            reinterpret_cast<ServiceBootstrapActivationLeaseV1*>(fixture.package.serviced_bytes.data());
        EXPECT_EQ(ServiceBootstrapStageBeginActivationV1(&fixture.runtime, 0x100, artifact_alias),
                  ServiceBootstrapStageStatus::AliasedStorage);
        ServiceBootstrapStageSnapshotV1 intact{};
        EXPECT_EQ(ServiceBootstrapStageInspectV1(&fixture.runtime, &intact), ServiceBootstrapStageStatus::Ok);

        ServiceBootstrapActivationLeaseV1 first{};
        EXPECT_EQ(ServiceBootstrapStageBeginActivationV1(&fixture.runtime, 0x100, &first),
                  ServiceBootstrapStageStatus::Ok);
        EXPECT_EQ(first.receipt.version, kServiceBootstrapActivationReceiptVersion1);
        EXPECT_EQ(first.receipt.registry_identity, fixture.runtime.registry_identity);
        EXPECT_EQ(first.receipt.service_identity, 0x100ULL);
        EXPECT_EQ(first.receipt.activation_generation, 1ULL);
        EXPECT_EQ(first.image, fixture.runtime.rows[0].image);
        EXPECT_EQ(first.service.activation_state, ServiceBootstrapActivationStateV1::Activating);

        ServiceBootstrapActivationLeaseV1 duplicate{};
        EXPECT_EQ(ServiceBootstrapStageBeginActivationV1(&fixture.runtime, 0x100, &duplicate),
                  ServiceBootstrapStageStatus::ActivationInProgress);
        ServiceBootstrapActivationReceiptV1 forged = first.receipt;
        ++forged.activation_generation;
        EXPECT_EQ(ServiceBootstrapStageCancelActivationV1(&fixture.runtime, forged),
                  ServiceBootstrapStageStatus::InvalidActivationReceipt);
        EXPECT_EQ(ServiceBootstrapStageFinishActivationV1(&fixture.runtime, first.receipt,
                                                          ServiceBootstrapActivationOutcomeV1::TransferredPublished),
                  ServiceBootstrapStageStatus::InvalidActivationOutcome);
        EXPECT_EQ(ServiceBootstrapStageCancelActivationV1(&fixture.runtime, first.receipt),
                  ServiceBootstrapStageStatus::Ok);
        EXPECT_EQ(ServiceBootstrapStageCancelActivationV1(&fixture.runtime, first.receipt),
                  ServiceBootstrapStageStatus::InvalidActivationReceipt);

        ServiceBootstrapActivationLeaseV1 second{};
        EXPECT_EQ(ServiceBootstrapStageBeginActivationV1(&fixture.runtime, 0x100, &second),
                  ServiceBootstrapStageStatus::Ok);
        EXPECT_EQ(second.receipt.activation_generation, 2ULL);
        const ServiceBootstrapActivationReceiptV1 stale = first.receipt;
        EXPECT_EQ(ServiceBootstrapStageCancelActivationV1(&fixture.runtime, stale),
                  ServiceBootstrapStageStatus::InvalidActivationReceipt);

        FakeMapTarget target{};
        const LoadImageMapHooks hooks{&target, &MapOwnedFrame, &UnmapOwnedFrame};
        EXPECT_EQ(LoadImageMapInto(second.image, hooks).status, LoadImageStatus::Ok);
        EXPECT_EQ(ServiceBootstrapStageCancelActivationV1(&fixture.runtime, second.receipt),
                  ServiceBootstrapStageStatus::CannotCancelActivation);
        EXPECT_EQ(ServiceBootstrapStageFinishActivationV1(&fixture.runtime, second.receipt,
                                                          ServiceBootstrapActivationOutcomeV1::TransferredPublished),
                  ServiceBootstrapStageStatus::Ok);
        EXPECT_EQ(ServiceBootstrapStageFinishActivationV1(&fixture.runtime, second.receipt,
                                                          ServiceBootstrapActivationOutcomeV1::TransferredPublished),
                  ServiceBootstrapStageStatus::ActivationTerminal);
        ServiceBootstrapServiceSnapshotV1 snapshot{};
        EXPECT_EQ(ServiceBootstrapStageFindServiceV1(&fixture.runtime, 0x100, &snapshot),
                  ServiceBootstrapStageStatus::Ok);
        EXPECT_EQ(snapshot.activation_state, ServiceBootstrapActivationStateV1::TransferredPublished);
        EXPECT_EQ(snapshot.activation_generation, 2ULL);
        EXPECT_EQ(ServiceBootstrapStageDiscardV1(&fixture.runtime), ServiceBootstrapStageStatus::CannotDiscard);
    }

    // Once a map attempt consumes the sealed package, failure is terminal and
    // must be explicitly recorded as ConsumedFailed. No sealed retry exists.
    {
        parser_fixture::Reset();
        parser_fixture::AddSingleRxSegment();
        StageFixture fixture;
        EXPECT_EQ(fixture.Stage().status, ServiceBootstrapStageStatus::Ok);
        ServiceBootstrapActivationLeaseV1 lease{};
        EXPECT_EQ(ServiceBootstrapStageBeginActivationV1(&fixture.runtime, 0x100, &lease),
                  ServiceBootstrapStageStatus::Ok);
        FakeMapTarget target{};
        const LoadImageMapHooks hooks{&target, &RejectOwnedFrame, &UnmapOwnedFrame};
        EXPECT_EQ(LoadImageMapInto(lease.image, hooks).status, LoadImageStatus::MapFailed);
        EXPECT_EQ(lease.image->state, LoadImageState::Failed);
        EXPECT_EQ(ServiceBootstrapStageCancelActivationV1(&fixture.runtime, lease.receipt),
                  ServiceBootstrapStageStatus::CannotCancelActivation);
        EXPECT_EQ(ServiceBootstrapStageFinishActivationV1(&fixture.runtime, lease.receipt,
                                                          ServiceBootstrapActivationOutcomeV1::ConsumedFailed),
                  ServiceBootstrapStageStatus::Ok);
        ServiceBootstrapServiceSnapshotV1 snapshot{};
        EXPECT_EQ(ServiceBootstrapStageFindServiceV1(&fixture.runtime, 0x100, &snapshot),
                  ServiceBootstrapStageStatus::Ok);
        EXPECT_EQ(snapshot.activation_state, ServiceBootstrapActivationStateV1::ConsumedFailed);
        EXPECT_EQ(ServiceBootstrapStageBeginActivationV1(&fixture.runtime, 0x100, &lease),
                  ServiceBootstrapStageStatus::ActivationTerminal);

        SlotFixture replacement_bank;
        const ServiceBootstrapSlotStorageV1 replacement = replacement_bank.Storage();
        const ObjectHandle stale_memory_object = snapshot.memory_object;
        const ServiceBootstrapStageResultV1 restaged =
            ServiceBootstrapStageRestageV1(&fixture.runtime, 0x100, snapshot.activation_generation, &replacement);
        EXPECT_EQ(restaged.status, ServiceBootstrapStageStatus::Ok);
        EXPECT_EQ(ServiceBootstrapStageFindServiceV1(&fixture.runtime, 0x100, &snapshot),
                  ServiceBootstrapStageStatus::Ok);
        EXPECT_EQ(snapshot.activation_state, ServiceBootstrapActivationStateV1::Staged);
        EXPECT_EQ(snapshot.activation_generation, 1ULL);
        EXPECT_NE(snapshot.memory_object, stale_memory_object);
        LoadBackingInfoV1 backing{};
        EXPECT_FALSE(
            ServiceBootstrapStageBackingQueryV1(stale_memory_object, 0, kLoadPlanPageSize, &backing, &fixture.runtime));
        EXPECT_TRUE(ServiceBootstrapStageBackingQueryV1(snapshot.memory_object, 0, kLoadPlanPageSize, &backing,
                                                        &fixture.runtime));
        EXPECT_EQ(ServiceBootstrapStageBeginActivationV1(&fixture.runtime, 0x100, &lease),
                  ServiceBootstrapStageStatus::Ok);
        EXPECT_EQ(lease.receipt.activation_generation, 2ULL);
    }

    // Two permanent fixed banks can alternate indefinitely. Every successful
    // restage preserves the terminal generation, mints a fresh backing
    // registry identity, advances the admission-token namespace, and makes
    // receipts/backing handles/tokens from the prior incarnation stale.
    {
        parser_fixture::Reset();
        parser_fixture::AddSingleRxSegment();
        StageFixture fixture;
        EXPECT_EQ(fixture.Stage().status, ServiceBootstrapStageStatus::Ok);
        SlotFixture alternate_bank;
        std::array<ServiceBootstrapSlotStorageV1, 2> banks{fixture.slots[0], alternate_bank.Storage()};
        u32 active_bank = 0;
        u64 expected_generation = 0;
        LoadImage* last_retired_image = nullptr;
        ExecAdmission* last_retired_admission = nullptr;
        FakeArena* last_retired_arena = nullptr;
        constexpr u32 kRestageCycles = 6;
        for (u32 cycle = 0; cycle < kRestageCycles; ++cycle)
        {
            ServiceBootstrapActivationLeaseV1 lease{};
            EXPECT_EQ(ServiceBootstrapStageBeginActivationV1(&fixture.runtime, 0x100, &lease),
                      ServiceBootstrapStageStatus::Ok);
            EXPECT_EQ(lease.receipt.activation_generation, expected_generation + 1u);
            FakeMapTarget target{};
            const LoadImageMapHooks hooks{&target, &MapOwnedFrame, &UnmapOwnedFrame};
            EXPECT_EQ(LoadImageMapInto(lease.image, hooks).status, LoadImageStatus::Ok);
            EXPECT_EQ(ServiceBootstrapStageFinishActivationV1(
                          &fixture.runtime, lease.receipt, ServiceBootstrapActivationOutcomeV1::TransferredPublished),
                      ServiceBootstrapStageStatus::Ok);

            const StageRowBytes terminal_bytes = CaptureRow(fixture.runtime.rows[0]);
            const u32 replacement_bank = 1u - active_bank;
            const u64 stale_generation = lease.receipt.activation_generation + 1u;
            EXPECT_EQ(
                ServiceBootstrapStageRestageV1(&fixture.runtime, 0x100, stale_generation, &banks[replacement_bank])
                    .status,
                ServiceBootstrapStageStatus::StaleActivationGeneration);
            ExpectRowUnchanged(fixture.runtime.rows[0], terminal_bytes);

            const ObjectHandle stale_memory_object = lease.receipt.memory_object;
            LoadImage* const retired_image = fixture.runtime.rows[0].image;
            ExecAdmission* const retired_admission = fixture.runtime.rows[0].admission;
            const u64 stale_admission_token = retired_admission->retired_identity;
            const ServiceBootstrapStageResultV1 restaged = ServiceBootstrapStageRestageV1(
                &fixture.runtime, 0x100, lease.receipt.activation_generation, &banks[replacement_bank]);
            EXPECT_EQ(restaged.status, ServiceBootstrapStageStatus::Ok);
            EXPECT_EQ(fixture.runtime.rows[0].activation_state, ServiceBootstrapActivationStateV1::Staged);
            EXPECT_EQ(fixture.runtime.rows[0].activation_generation, lease.receipt.activation_generation);
            EXPECT_EQ(fixture.runtime.rows[0].image, banks[replacement_bank].image);
            EXPECT_EQ(fixture.runtime.rows[0].bank_count, 2u);
            EXPECT_EQ(fixture.runtime.rows[0].active_bank_index, replacement_bank);
            EXPECT_EQ(fixture.runtime.rows[0].banks[replacement_bank].runtime_registry_identity,
                      fixture.runtime.registry_identity);
            EXPECT_EQ(fixture.runtime.rows[0].banks[replacement_bank].service_identity, 0x100ULL);
            EXPECT_EQ(fixture.runtime.rows[0].banks[replacement_bank].manifest_index, 0u);
            EXPECT_EQ(fixture.runtime.rows[0].banks[replacement_bank].activation_generation,
                      lease.receipt.activation_generation);
            EXPECT_NE(fixture.runtime.rows[0].memory_object, stale_memory_object);
            EXPECT_EQ(fixture.runtime.rows[0].admission->retired_identity, stale_admission_token + 1u);

            LoadBackingInfoV1 backing{};
            EXPECT_FALSE(ServiceBootstrapStageBackingQueryV1(stale_memory_object, 0, kLoadPlanPageSize, &backing,
                                                             &fixture.runtime));
            EXPECT_TRUE(ServiceBootstrapStageBackingQueryV1(fixture.runtime.rows[0].memory_object, 0, kLoadPlanPageSize,
                                                            &backing, &fixture.runtime));
            EXPECT_EQ(ServiceBootstrapStageFinishActivationV1(
                          &fixture.runtime, lease.receipt, ServiceBootstrapActivationOutcomeV1::TransferredPublished),
                      ServiceBootstrapStageStatus::InvalidActivationReceipt);

            auto* inactive_bank_alias =
                reinterpret_cast<ServiceBootstrapActivationLeaseV1*>(banks[active_bank].plan_storage);
            EXPECT_EQ(ServiceBootstrapStageBeginActivationV1(&fixture.runtime, 0x100, inactive_bank_alias),
                      ServiceBootstrapStageStatus::AliasedStorage);

            LoadPlanViewV1 stale_view{};
            EXPECT_EQ(ExecAdmissionConsume(fixture.runtime.rows[0].admission, stale_admission_token,
                                           &fixture.runtime.rows[0].expected_source_hash,
                                           &ServiceBootstrapStageBackingQueryV1, &fixture.runtime, &stale_view)
                          .status,
                      ExecAdmissionStatus::StaleToken);
            EXPECT_EQ(stale_view.bytes, nullptr);

            // Publication does not clear the old bank. It remains a coherent
            // terminal object, with target ownership held outside LoadImage,
            // until an owner deliberately resets that inactive bank.
            LoadImageSnapshot retired_snapshot{};
            EXPECT_EQ(LoadImageInspect(retired_image, &retired_snapshot), LoadImageStatus::Ok);
            EXPECT_EQ(retired_snapshot.state, LoadImageState::Transferred);
            EXPECT_EQ(retired_snapshot.package_owned_pages, 0u);
            EXPECT_TRUE(retired_snapshot.target_owned_pages != 0);
            u64 retired_successor = 0;
            EXPECT_EQ(ExecAdmissionQuiescentSuccessorIdentity(retired_admission, &retired_successor),
                      ExecAdmissionStatus::Ok);
            EXPECT_EQ(retired_successor, stale_admission_token + 1u);
            last_retired_image = retired_image;
            last_retired_admission = retired_admission;
            last_retired_arena = retired_image == &fixture.slot_fixtures[0].image ? &fixture.slot_fixtures[0].arena
                                                                                  : &alternate_bank.arena;
            active_bank = replacement_bank;
            expected_generation = lease.receipt.activation_generation;
        }

        ASSERT_TRUE(last_retired_image != nullptr);
        ASSERT_TRUE(last_retired_admission != nullptr);
        ASSERT_TRUE(last_retired_arena != nullptr);
        const u32 target_owned_live_frames = last_retired_arena->live;
        const u32 package_release_count = last_retired_arena->releases;
        LoadImageRelease(last_retired_image);
        EXPECT_EQ(LoadImageResetQuiescent(last_retired_image), LoadImageStatus::Ok);
        EXPECT_EQ(ExecAdmissionResetQuiescent(last_retired_admission), ExecAdmissionStatus::Ok);
        EXPECT_EQ(last_retired_arena->live, target_owned_live_frames);
        EXPECT_EQ(last_retired_arena->releases, package_release_count);
        EXPECT_EQ(last_retired_image->state, LoadImageState::Uninitialized);
        EXPECT_EQ(last_retired_admission->state, ExecAdmissionState::Uninitialized);
    }

    // Reusing an actually retired terminal bank is a two-phase transaction.
    // A lock holder/waiter marker, active token, or pending cancellation in
    // its admission half rejects before either half or any backing buffer is
    // changed; restoring the hostile field makes the exact retry succeed.
    {
        parser_fixture::Reset();
        parser_fixture::AddSingleRxSegment();
        StageFixture fixture;
        EXPECT_EQ(fixture.Stage().status, ServiceBootstrapStageStatus::Ok);
        SlotFixture alternate_bank;
        std::array<ServiceBootstrapSlotStorageV1, 2> banks{fixture.slots[0], alternate_bank.Storage()};

        ServiceBootstrapActivationLeaseV1 first_lease{};
        EXPECT_EQ(ServiceBootstrapStageBeginActivationV1(&fixture.runtime, 0x100, &first_lease),
                  ServiceBootstrapStageStatus::Ok);
        FakeMapTarget first_target{};
        const LoadImageMapHooks first_hooks{&first_target, &MapOwnedFrame, &UnmapOwnedFrame};
        EXPECT_EQ(LoadImageMapInto(first_lease.image, first_hooks).status, LoadImageStatus::Ok);
        EXPECT_EQ(ServiceBootstrapStageFinishActivationV1(&fixture.runtime, first_lease.receipt,
                                                          ServiceBootstrapActivationOutcomeV1::TransferredPublished),
                  ServiceBootstrapStageStatus::Ok);
        EXPECT_EQ(ServiceBootstrapStageRestageV1(&fixture.runtime, 0x100, first_lease.receipt.activation_generation,
                                                 &banks[1])
                      .status,
                  ServiceBootstrapStageStatus::Ok);

        ServiceBootstrapActivationLeaseV1 second_lease{};
        EXPECT_EQ(ServiceBootstrapStageBeginActivationV1(&fixture.runtime, 0x100, &second_lease),
                  ServiceBootstrapStageStatus::Ok);
        FakeMapTarget second_target{};
        const LoadImageMapHooks second_hooks{&second_target, &MapOwnedFrame, &UnmapOwnedFrame};
        EXPECT_EQ(LoadImageMapInto(second_lease.image, second_hooks).status, LoadImageStatus::Ok);
        EXPECT_EQ(ServiceBootstrapStageFinishActivationV1(&fixture.runtime, second_lease.receipt,
                                                          ServiceBootstrapActivationOutcomeV1::TransferredPublished),
                  ServiceBootstrapStageStatus::Ok);

        LoadImage* const retired_image = banks[0].image;
        ExecAdmission* const retired_admission = banks[0].admission;
        EXPECT_EQ(LoadImageCanResetQuiescent(retired_image), LoadImageStatus::Ok);
        EXPECT_EQ(ExecAdmissionCanResetQuiescent(retired_admission), ExecAdmissionStatus::Ok);

        const u32 original_next_ticket = retired_admission->lock.next_ticket;
        const u32 original_now_serving = retired_admission->lock.now_serving;
        constexpr u32 kHostileFieldCount = 4;
        for (u32 field = 0; field < kHostileFieldCount; ++field)
        {
            switch (field)
            {
            case 0:
                retired_admission->lock.next_ticket = original_next_ticket + 1u;
                break;
            case 1:
                retired_admission->lock.now_serving = original_now_serving + 1u;
                break;
            case 2:
                retired_admission->active_identity = 0xBAD1u;
                break;
            case 3:
                retired_admission->cancel_requested = 1;
                break;
            }

            const StageRowBytes active_before = CaptureRow(fixture.runtime.rows[0]);
            const ImageBytes image_before = CaptureObject(*retired_image);
            const AdmissionBytes admission_before = CaptureObject(*retired_admission);
            const auto pages_before = fixture.slot_fixtures[0].pages;
            const auto regions_before = fixture.slot_fixtures[0].regions;
            const auto plan_before = fixture.slot_fixtures[0].plan;
            const auto admission_storage_before = fixture.slot_fixtures[0].admission_storage;

            EXPECT_EQ(ServiceBootstrapStageRestageV1(&fixture.runtime, 0x100,
                                                     second_lease.receipt.activation_generation, &banks[0])
                          .status,
                      ServiceBootstrapStageStatus::CorruptRuntime);
            ExpectRowUnchanged(fixture.runtime.rows[0], active_before);
            ExpectObjectUnchanged(*retired_image, image_before);
            ExpectObjectUnchanged(*retired_admission, admission_before);
            EXPECT_EQ(std::memcmp(pages_before.data(), fixture.slot_fixtures[0].pages.data(), sizeof(pages_before)), 0);
            EXPECT_EQ(
                std::memcmp(regions_before.data(), fixture.slot_fixtures[0].regions.data(), sizeof(regions_before)), 0);
            EXPECT_EQ(std::memcmp(plan_before.data(), fixture.slot_fixtures[0].plan.data(), sizeof(plan_before)), 0);
            EXPECT_EQ(std::memcmp(admission_storage_before.data(), fixture.slot_fixtures[0].admission_storage.data(),
                                  sizeof(admission_storage_before)),
                      0);

            retired_admission->lock.next_ticket = original_next_ticket;
            retired_admission->lock.now_serving = original_now_serving;
            retired_admission->active_identity = 0;
            retired_admission->cancel_requested = 0;
        }

        EXPECT_EQ(ServiceBootstrapStageRestageV1(&fixture.runtime, 0x100, second_lease.receipt.activation_generation,
                                                 &banks[0])
                      .status,
                  ServiceBootstrapStageStatus::Ok);
    }

    // A terminal bank is authority-bound to the runtime/service row that
    // published it. Even an otherwise valid, disjoint bank from an identical
    // second runtime cannot be cleared, mixed into this row, or adopted.
    {
        parser_fixture::Reset();
        parser_fixture::AddSingleRxSegment();
        StageFixture owner;
        StageFixture foreign;
        EXPECT_EQ(owner.Stage().status, ServiceBootstrapStageStatus::Ok);
        EXPECT_EQ(foreign.Stage().status, ServiceBootstrapStageStatus::Ok);

        ServiceBootstrapActivationLeaseV1 owner_lease{};
        EXPECT_EQ(ServiceBootstrapStageBeginActivationV1(&owner.runtime, 0x100, &owner_lease),
                  ServiceBootstrapStageStatus::Ok);
        FakeMapTarget owner_target{};
        const LoadImageMapHooks owner_hooks{&owner_target, &MapOwnedFrame, &UnmapOwnedFrame};
        EXPECT_EQ(LoadImageMapInto(owner_lease.image, owner_hooks).status, LoadImageStatus::Ok);
        EXPECT_EQ(ServiceBootstrapStageFinishActivationV1(&owner.runtime, owner_lease.receipt,
                                                          ServiceBootstrapActivationOutcomeV1::TransferredPublished),
                  ServiceBootstrapStageStatus::Ok);

        ServiceBootstrapActivationLeaseV1 foreign_lease{};
        EXPECT_EQ(ServiceBootstrapStageBeginActivationV1(&foreign.runtime, 0x100, &foreign_lease),
                  ServiceBootstrapStageStatus::Ok);
        FakeMapTarget foreign_target{};
        const LoadImageMapHooks foreign_hooks{&foreign_target, &MapOwnedFrame, &UnmapOwnedFrame};
        EXPECT_EQ(LoadImageMapInto(foreign_lease.image, foreign_hooks).status, LoadImageStatus::Ok);
        EXPECT_EQ(ServiceBootstrapStageFinishActivationV1(&foreign.runtime, foreign_lease.receipt,
                                                          ServiceBootstrapActivationOutcomeV1::TransferredPublished),
                  ServiceBootstrapStageStatus::Ok);
        SlotFixture foreign_alternate;
        const ServiceBootstrapSlotStorageV1 foreign_alternate_storage = foreign_alternate.Storage();
        EXPECT_EQ(ServiceBootstrapStageRestageV1(&foreign.runtime, 0x100, foreign_lease.receipt.activation_generation,
                                                 &foreign_alternate_storage)
                      .status,
                  ServiceBootstrapStageStatus::Ok);

        const StageRowBytes owner_before = CaptureRow(owner.runtime.rows[0]);
        const StageRowBytes foreign_before = CaptureRow(foreign.runtime.rows[0]);
        const ImageBytes foreign_image_before = CaptureObject(foreign.slot_fixtures[0].image);
        const AdmissionBytes foreign_admission_before = CaptureObject(foreign.slot_fixtures[0].admission);
        const auto foreign_pages_before = foreign.slot_fixtures[0].pages;
        const auto foreign_regions_before = foreign.slot_fixtures[0].regions;
        const auto foreign_plan_before = foreign.slot_fixtures[0].plan;
        const auto foreign_admission_storage_before = foreign.slot_fixtures[0].admission_storage;

        EXPECT_EQ(ServiceBootstrapStageRestageV1(&owner.runtime, 0x100, owner_lease.receipt.activation_generation,
                                                 &foreign.slots[0])
                      .status,
                  ServiceBootstrapStageStatus::InvalidSlotStorage);
        ExpectRowUnchanged(owner.runtime.rows[0], owner_before);
        ExpectRowUnchanged(foreign.runtime.rows[0], foreign_before);
        ExpectObjectUnchanged(foreign.slot_fixtures[0].image, foreign_image_before);
        ExpectObjectUnchanged(foreign.slot_fixtures[0].admission, foreign_admission_before);
        EXPECT_EQ(std::memcmp(foreign_pages_before.data(), foreign.slot_fixtures[0].pages.data(),
                              sizeof(foreign_pages_before)),
                  0);
        EXPECT_EQ(std::memcmp(foreign_regions_before.data(), foreign.slot_fixtures[0].regions.data(),
                              sizeof(foreign_regions_before)),
                  0);
        EXPECT_EQ(
            std::memcmp(foreign_plan_before.data(), foreign.slot_fixtures[0].plan.data(), sizeof(foreign_plan_before)),
            0);
        EXPECT_EQ(std::memcmp(foreign_admission_storage_before.data(),
                              foreign.slot_fixtures[0].admission_storage.data(),
                              sizeof(foreign_admission_storage_before)),
                  0);

        SlotFixture owner_alternate;
        const ServiceBootstrapSlotStorageV1 owner_alternate_storage = owner_alternate.Storage();
        EXPECT_EQ(ServiceBootstrapStageRestageV1(&owner.runtime, 0x100, owner_lease.receipt.activation_generation,
                                                 &owner_alternate_storage)
                      .status,
                  ServiceBootstrapStageStatus::Ok);
    }

    // Package-hash and allocation failures never modify the active terminal
    // row. Partial replacement ownership is released and the inactive bank is
    // returned to canonical-zero form for an exact retry.
    {
        parser_fixture::Reset();
        parser_fixture::AddSingleRxSegment();
        StageFixture fixture;
        EXPECT_EQ(fixture.Stage().status, ServiceBootstrapStageStatus::Ok);
        ServiceBootstrapActivationLeaseV1 lease{};
        EXPECT_EQ(ServiceBootstrapStageBeginActivationV1(&fixture.runtime, 0x100, &lease),
                  ServiceBootstrapStageStatus::Ok);
        FakeMapTarget target{};
        const LoadImageMapHooks hooks{&target, &MapOwnedFrame, &UnmapOwnedFrame};
        EXPECT_EQ(LoadImageMapInto(lease.image, hooks).status, LoadImageStatus::Ok);
        EXPECT_EQ(ServiceBootstrapStageFinishActivationV1(&fixture.runtime, lease.receipt,
                                                          ServiceBootstrapActivationOutcomeV1::TransferredPublished),
                  ServiceBootstrapStageStatus::Ok);

        SlotFixture replacement_bank;
        const ServiceBootstrapSlotStorageV1 replacement = replacement_bank.Storage();
        const StageRowBytes terminal_bytes = CaptureRow(fixture.runtime.rows[0]);
        fixture.package.serviced_bytes[70] ^= 0x40u;
        EXPECT_EQ(
            ServiceBootstrapStageRestageV1(&fixture.runtime, 0x100, lease.receipt.activation_generation, &replacement)
                .status,
            ServiceBootstrapStageStatus::CorruptRuntime);
        ExpectRowUnchanged(fixture.runtime.rows[0], terminal_bytes);
        EXPECT_EQ(replacement_bank.arena.count, 0u);
        fixture.package.serviced_bytes[70] ^= 0x40u;

        replacement_bank.arena.fail_at_attempt = 0;
        EXPECT_EQ(
            ServiceBootstrapStageRestageV1(&fixture.runtime, 0x100, lease.receipt.activation_generation, &replacement)
                .status,
            ServiceBootstrapStageStatus::ElfStageRejected);
        ExpectRowUnchanged(fixture.runtime.rows[0], terminal_bytes);
        EXPECT_EQ(replacement_bank.arena.live, 0u);
        EXPECT_EQ(replacement_bank.image.state, LoadImageState::Uninitialized);
        EXPECT_EQ(replacement_bank.admission.state, ExecAdmissionState::Uninitialized);

        replacement_bank.arena.fail_at_attempt = ~0U;
        EXPECT_EQ(
            ServiceBootstrapStageRestageV1(&fixture.runtime, 0x100, lease.receipt.activation_generation, &replacement)
                .status,
            ServiceBootstrapStageStatus::Ok);
    }

    // The manifest frame budget is enforced during every fresh staging pass,
    // before the underlying allocator can acquire a second unauthorized frame.
    {
        parser_fixture::Reset();
        parser_fixture::AddSingleRxSegment();
        StageFixture fixture;
        fixture.package.document.services[0].requested_frame_budget_pages = 1;
        fixture.package.Refresh();
        EXPECT_EQ(fixture.Stage().status, ServiceBootstrapStageStatus::Ok);
        ServiceBootstrapActivationLeaseV1 lease{};
        EXPECT_EQ(ServiceBootstrapStageBeginActivationV1(&fixture.runtime, 0x100, &lease),
                  ServiceBootstrapStageStatus::Ok);
        FakeMapTarget target{};
        const LoadImageMapHooks hooks{&target, &MapOwnedFrame, &UnmapOwnedFrame};
        EXPECT_EQ(LoadImageMapInto(lease.image, hooks).status, LoadImageStatus::Ok);
        EXPECT_EQ(ServiceBootstrapStageFinishActivationV1(&fixture.runtime, lease.receipt,
                                                          ServiceBootstrapActivationOutcomeV1::TransferredPublished),
                  ServiceBootstrapStageStatus::Ok);

        parser_fixture::Reset();
        parser_fixture::AddSegment(64, 0x400080, 32, 128, duetos::core::kElfPfR | duetos::core::kElfPfX);
        parser_fixture::AddSegment(128, 0x402000, 32, 128, duetos::core::kElfPfR);
        SlotFixture replacement_bank;
        const ServiceBootstrapSlotStorageV1 replacement = replacement_bank.Storage();
        const StageRowBytes terminal_bytes = CaptureRow(fixture.runtime.rows[0]);
        EXPECT_EQ(
            ServiceBootstrapStageRestageV1(&fixture.runtime, 0x100, lease.receipt.activation_generation, &replacement)
                .status,
            ServiceBootstrapStageStatus::ResourceBudgetExceeded);
        ExpectRowUnchanged(fixture.runtime.rows[0], terminal_bytes);
        EXPECT_EQ(replacement_bank.arena.attempts, 1u);
        EXPECT_EQ(replacement_bank.arena.count, 1u);
        EXPECT_EQ(replacement_bank.arena.releases, 1u);
        EXPECT_EQ(replacement_bank.arena.live, 0u);
    }

    // A terminal row at the last representable activation generation cannot
    // restage into a state from which Begin would wrap or reuse authority.
    {
        parser_fixture::Reset();
        parser_fixture::AddSingleRxSegment();
        StageFixture fixture;
        EXPECT_EQ(fixture.Stage().status, ServiceBootstrapStageStatus::Ok);
        ServiceBootstrapActivationLeaseV1 lease{};
        EXPECT_EQ(ServiceBootstrapStageBeginActivationV1(&fixture.runtime, 0x100, &lease),
                  ServiceBootstrapStageStatus::Ok);
        FakeMapTarget target{};
        const LoadImageMapHooks hooks{&target, &MapOwnedFrame, &UnmapOwnedFrame};
        EXPECT_EQ(LoadImageMapInto(lease.image, hooks).status, LoadImageStatus::Ok);
        EXPECT_EQ(ServiceBootstrapStageFinishActivationV1(&fixture.runtime, lease.receipt,
                                                          ServiceBootstrapActivationOutcomeV1::TransferredPublished),
                  ServiceBootstrapStageStatus::Ok);
        fixture.runtime.rows[0].activation_generation = kServiceBootstrapActivationGenerationMaximum;
        fixture.runtime.rows[0].banks[fixture.runtime.rows[0].active_bank_index].activation_generation =
            kServiceBootstrapActivationGenerationMaximum;
        const StageRowBytes terminal_bytes = CaptureRow(fixture.runtime.rows[0]);
        SlotFixture replacement_bank;
        const ServiceBootstrapSlotStorageV1 replacement = replacement_bank.Storage();
        EXPECT_EQ(ServiceBootstrapStageRestageV1(&fixture.runtime, 0x100, kServiceBootstrapActivationGenerationMaximum,
                                                 &replacement)
                      .status,
                  ServiceBootstrapStageStatus::ActivationGenerationExhausted);
        ExpectRowUnchanged(fixture.runtime.rows[0], terminal_bytes);
        EXPECT_EQ(replacement_bank.arena.count, 0u);
    }

    // The final 40-bit registry component is minted exactly once. The next
    // restage fails before clearing its retired replacement bank and never
    // wraps a typed backing handle to registry zero or an earlier authority.
    {
        parser_fixture::Reset();
        parser_fixture::AddSingleRxSegment();
        StageFixture fixture;
        EXPECT_EQ(fixture.Stage().status, ServiceBootstrapStageStatus::Ok);
        SlotFixture alternate_bank;
        std::array<ServiceBootstrapSlotStorageV1, 2> banks{fixture.slots[0], alternate_bank.Storage()};

        ServiceBootstrapActivationLeaseV1 first_lease{};
        EXPECT_EQ(ServiceBootstrapStageBeginActivationV1(&fixture.runtime, 0x100, &first_lease),
                  ServiceBootstrapStageStatus::Ok);
        FakeMapTarget first_target{};
        const LoadImageMapHooks first_hooks{&first_target, &MapOwnedFrame, &UnmapOwnedFrame};
        EXPECT_EQ(LoadImageMapInto(first_lease.image, first_hooks).status, LoadImageStatus::Ok);
        EXPECT_EQ(ServiceBootstrapStageFinishActivationV1(&fixture.runtime, first_lease.receipt,
                                                          ServiceBootstrapActivationOutcomeV1::TransferredPublished),
                  ServiceBootstrapStageStatus::Ok);

        const u64 saved_next_registry =
            ServiceBootstrapStageExchangeNextRegistryIdentityForTestV1(kServiceBootstrapMemoryObjectRegistryMaximum);
        EXPECT_TRUE(saved_next_registry != 0);
        EXPECT_EQ(ServiceBootstrapStageRestageV1(&fixture.runtime, 0x100, first_lease.receipt.activation_generation,
                                                 &banks[1])
                      .status,
                  ServiceBootstrapStageStatus::Ok);
        EXPECT_EQ((fixture.runtime.rows[0].memory_object & kServiceBootstrapMemoryObjectRegistryMask) >>
                      kServiceBootstrapMemoryObjectRegistryShift,
                  kServiceBootstrapMemoryObjectRegistryMaximum);

        ServiceBootstrapActivationLeaseV1 final_lease{};
        EXPECT_EQ(ServiceBootstrapStageBeginActivationV1(&fixture.runtime, 0x100, &final_lease),
                  ServiceBootstrapStageStatus::Ok);
        FakeMapTarget final_target{};
        const LoadImageMapHooks final_hooks{&final_target, &MapOwnedFrame, &UnmapOwnedFrame};
        EXPECT_EQ(LoadImageMapInto(final_lease.image, final_hooks).status, LoadImageStatus::Ok);
        EXPECT_EQ(ServiceBootstrapStageFinishActivationV1(&fixture.runtime, final_lease.receipt,
                                                          ServiceBootstrapActivationOutcomeV1::TransferredPublished),
                  ServiceBootstrapStageStatus::Ok);

        const StageRowBytes active_before = CaptureRow(fixture.runtime.rows[0]);
        const ImageBytes retired_image_before = CaptureObject(*banks[0].image);
        const AdmissionBytes retired_admission_before = CaptureObject(*banks[0].admission);
        EXPECT_EQ(ServiceBootstrapStageRestageV1(&fixture.runtime, 0x100, final_lease.receipt.activation_generation,
                                                 &banks[0])
                      .status,
                  ServiceBootstrapStageStatus::IdentityExhausted);
        ExpectRowUnchanged(fixture.runtime.rows[0], active_before);
        ExpectObjectUnchanged(*banks[0].image, retired_image_before);
        ExpectObjectUnchanged(*banks[0].admission, retired_admission_before);

        EXPECT_EQ(ServiceBootstrapStageExchangeNextRegistryIdentityForTestV1(saved_next_registry),
                  kServiceBootstrapMemoryObjectRegistryMaximum + 1u);
    }

    // Capacity fails before any parser or frame hook is reached.
    {
        parser_fixture::Reset();
        parser_fixture::AddSingleRxSegment();
        StageFixture fixture;
        const ServiceBootstrapStageResultV1 result =
            ServiceBootstrapStageInitializeV1(&fixture.runtime, &fixture.package.definition, fixture.slots.data(), 1);
        EXPECT_EQ(result.status, ServiceBootstrapStageStatus::SlotCapacityTooSmall);
        EXPECT_EQ(fixture.runtime.state, ServiceBootstrapStageState::Failed);
        EXPECT_EQ(fixture.slot_fixtures[0].arena.count, 0u);
        EXPECT_EQ(fixture.slot_fixtures[1].arena.count, 0u);
    }

    // Cross-service storage aliasing is rejected before staging.
    {
        parser_fixture::Reset();
        parser_fixture::AddSingleRxSegment();
        StageFixture fixture;
        fixture.slots[1].plan_storage = fixture.slot_fixtures[0].plan.data();
        const ServiceBootstrapStageResultV1 result = fixture.Stage();
        EXPECT_EQ(result.status, ServiceBootstrapStageStatus::SlotStorageOverlap);
        EXPECT_EQ(fixture.slot_fixtures[0].arena.count, 0u);
        EXPECT_EQ(fixture.slot_fixtures[1].arena.count, 0u);
    }

    // Only Native/Broker rows reach the ELF adapter. A later unsupported row
    // unwinds the already-staged dependency.
    {
        parser_fixture::Reset();
        parser_fixture::AddSingleRxSegment();
        StageFixture fixture;
        fixture.package.document.services[1].kind = ServiceManifestKind::Win32;
        fixture.package.Refresh();
        const ServiceBootstrapStageResultV1 result = fixture.Stage();
        EXPECT_EQ(result.status, ServiceBootstrapStageStatus::UnsupportedServiceKind);
        EXPECT_EQ(result.service_index, 1u);
        EXPECT_EQ(fixture.slot_fixtures[0].arena.live, 0u);
        EXPECT_EQ(fixture.slot_fixtures[0].arena.releases, 1u);
        EXPECT_EQ(fixture.slot_fixtures[1].arena.count, 0u);
    }

    // A failure in the second executable releases the first image and leaves
    // no admission or backing identity reachable from the Failed runtime.
    {
        parser_fixture::Reset();
        parser_fixture::AddSingleRxSegment();
        StageFixture fixture;
        fixture.slot_fixtures[1].arena.fail_at_attempt = 0;
        const ServiceBootstrapStageResultV1 result = fixture.Stage();
        EXPECT_EQ(result.status, ServiceBootstrapStageStatus::ElfStageRejected);
        EXPECT_EQ(result.service_index, 1u);
        EXPECT_EQ(fixture.slot_fixtures[0].arena.live, 0u);
        EXPECT_EQ(fixture.slot_fixtures[0].arena.releases, 1u);
        EXPECT_EQ(fixture.slot_fixtures[1].arena.live, 0u);
        EXPECT_EQ(fixture.runtime.state, ServiceBootstrapStageState::Failed);
    }

    // The manifest's per-service frame budget gates the underlying allocator,
    // rather than detecting over-allocation after the parser already acquired
    // an unauthorized frame.
    {
        parser_fixture::Reset();
        parser_fixture::AddSegment(64, 0x400080, 32, 128, duetos::core::kElfPfR | duetos::core::kElfPfX);
        parser_fixture::AddSegment(128, 0x402000, 32, 128, duetos::core::kElfPfR);
        StageFixture fixture;
        fixture.package.document.services[0].requested_frame_budget_pages = 1;
        fixture.package.Refresh();
        const ServiceBootstrapStageResultV1 result = fixture.Stage();
        EXPECT_EQ(result.status, ServiceBootstrapStageStatus::ResourceBudgetExceeded);
        EXPECT_EQ(result.service_index, 0u);
        EXPECT_EQ(fixture.slot_fixtures[0].arena.attempts, 1u);
        EXPECT_EQ(fixture.slot_fixtures[0].arena.count, 1u);
        EXPECT_EQ(fixture.slot_fixtures[0].arena.releases, 1u);
        EXPECT_EQ(fixture.slot_fixtures[0].arena.live, 0u);
    }

    // Package mutation is rejected before any output storage changes.
    {
        parser_fixture::Reset();
        parser_fixture::AddSingleRxSegment();
        StageFixture fixture;
        fixture.package.serviced_bytes[70] ^= 0x40u;
        const ServiceBootstrapStageResultV1 result = fixture.Stage();
        EXPECT_EQ(result.status, ServiceBootstrapStageStatus::PackageRejected);
        EXPECT_EQ(result.package_result.status, ServiceObjectPackageStatus::ContentHashMismatch);
        EXPECT_EQ(fixture.slot_fixtures[0].arena.count, 0u);
        EXPECT_EQ(fixture.slot_fixtures[1].arena.count, 0u);
    }

    // The one-shot runtime rejects noncanonical storage without adopting it.
    {
        parser_fixture::Reset();
        parser_fixture::AddSingleRxSegment();
        StageFixture fixture;
        fixture.runtime.version = 7;
        const ServiceBootstrapStageResultV1 result = fixture.Stage();
        EXPECT_EQ(result.status, ServiceBootstrapStageStatus::NonCanonicalRuntime);
        EXPECT_EQ(fixture.slot_fixtures[0].arena.count, 0u);
    }

    EXPECT_STREQ(ServiceBootstrapStageStatusName(ServiceBootstrapStageStatus::AdmissionRejected), "admission-rejected");
    EXPECT_STREQ(ServiceBootstrapStageStatusName(static_cast<ServiceBootstrapStageStatus>(0xFF)), "unknown");
    return duetos_host_test::finish_main("test_service_bootstrap_stage");
}
