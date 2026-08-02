// Hosted ownership and integrity coverage for loader/load_image.{h,cpp}.
//
// Frame and VM operations are a deterministic fake. Every map-failure rung is
// injected so the test can prove that each allocated frame is consumed exactly
// once by either package release, reverse unmap, successful target teardown,
// or the explicitly modeled rollback-failure recovery path.

#include "crypto_host_shims.h"
#include "host_test_helper.h"
#include "loader/load_image.h"

#include <array>

namespace
{

using duetos::u32;
using duetos::u64;
using duetos::u8;
using namespace duetos::loader;

constexpr u32 kFakeFrameCap = 8;
constexpr u32 kFixturePageCap = 8;
constexpr u32 kNeverFail = 0xFFFFFFFFu;
constexpr u64 kBase = 0x0000000140000000ULL;

enum class FakeOwner : u8
{
    NeverAllocated = 0,
    Package,
    Target,
    Destroyed,
};

struct FakeFrame
{
    LoadImageFrame id;
    std::array<u8, kLoadPlanPageSize> bytes;
    FakeOwner owner;
    u32 destroy_count;
    u64 mapped_va;
    VmProtection mapped_protection;
};

struct FakeArena
{
    std::array<FakeFrame, kFakeFrameCap> frames;
    u32 frame_count;
    u32 allocation_attempts;
    u32 release_count;
    u32 map_attempts;
    u32 map_successes;
    u32 unmap_attempts;
    u32 unmap_successes;
    u32 external_destroys;
    u32 fail_allocation_attempt;
    u32 fail_map_attempt;
    LoadImageFrame fail_unmap_frame;
    bool publish_false_allocation_sentinels;
    u8 false_allocation_sentinel;
    std::array<LoadImageFrame, kFakeFrameCap> map_log;
    std::array<LoadImageFrame, kFakeFrameCap> unmap_log;
};

FakeFrame* FindFrame(FakeArena& arena, LoadImageFrame id)
{
    for (u32 index = 0; index < arena.frame_count; ++index)
    {
        if (arena.frames[index].id == id)
            return &arena.frames[index];
    }
    return nullptr;
}

bool FakeAllocate(void* context, LoadImageFrame* frame_out, u8** writable_page_out)
{
    auto* arena = static_cast<FakeArena*>(context);
    const u32 attempt = arena->allocation_attempts++;
    if (attempt == arena->fail_allocation_attempt)
    {
        if (arena->publish_false_allocation_sentinels)
        {
            *frame_out = 0xF00DF00DULL;
            *writable_page_out = &arena->false_allocation_sentinel;
        }
        return false;
    }
    if (frame_out == nullptr || writable_page_out == nullptr || arena->frame_count >= arena->frames.size())
        return false;
    FakeFrame& frame = arena->frames[arena->frame_count];
    frame.id = static_cast<LoadImageFrame>(arena->frame_count + 1u);
    for (u32 index = 0; index < frame.bytes.size(); ++index)
        frame.bytes[index] = 0xA5;
    frame.owner = FakeOwner::Package;
    frame.destroy_count = 0;
    frame.mapped_va = 0;
    frame.mapped_protection = VmProtection::None;
    ++arena->frame_count;
    *frame_out = frame.id;
    *writable_page_out = frame.bytes.data();
    return true;
}

void FakeRelease(void* context, LoadImageFrame frame_id)
{
    auto* arena = static_cast<FakeArena*>(context);
    FakeFrame* frame = FindFrame(*arena, frame_id);
    EXPECT_TRUE(frame != nullptr);
    if (frame == nullptr)
        return;
    EXPECT_EQ(frame->owner, FakeOwner::Package);
    if (frame->owner != FakeOwner::Package)
        return;
    frame->owner = FakeOwner::Destroyed;
    ++frame->destroy_count;
    ++arena->release_count;
}

bool FakeMap(void* context, u64 virtual_address, LoadImageFrame frame_id, VmProtection protection)
{
    auto* arena = static_cast<FakeArena*>(context);
    const u32 attempt = arena->map_attempts++;
    if (attempt == arena->fail_map_attempt)
        return false;
    FakeFrame* frame = FindFrame(*arena, frame_id);
    EXPECT_TRUE(frame != nullptr);
    if (frame == nullptr || frame->owner != FakeOwner::Package)
        return false;
    frame->owner = FakeOwner::Target;
    frame->mapped_va = virtual_address;
    frame->mapped_protection = protection;
    arena->map_log[arena->map_successes++] = frame_id;
    return true;
}

bool FakeUnmap(void* context, u64 virtual_address, LoadImageFrame expected_frame)
{
    auto* arena = static_cast<FakeArena*>(context);
    arena->unmap_log[arena->unmap_attempts++] = expected_frame;
    FakeFrame* frame = FindFrame(*arena, expected_frame);
    EXPECT_TRUE(frame != nullptr);
    if (frame == nullptr || frame->owner != FakeOwner::Target || frame->mapped_va != virtual_address)
        return false;
    if (expected_frame == arena->fail_unmap_frame)
        return false;
    frame->owner = FakeOwner::Destroyed;
    ++frame->destroy_count;
    ++arena->unmap_successes;
    return true;
}

void DestroyResidualTargetFrames(FakeArena& arena)
{
    for (u32 index = 0; index < arena.frame_count; ++index)
    {
        FakeFrame& frame = arena.frames[index];
        if (frame.owner != FakeOwner::Target)
            continue;
        frame.owner = FakeOwner::Destroyed;
        ++frame.destroy_count;
        ++arena.external_destroys;
    }
}

void ExpectExactlyOnce(const FakeArena& arena)
{
    for (u32 index = 0; index < arena.frame_count; ++index)
    {
        EXPECT_EQ(arena.frames[index].owner, FakeOwner::Destroyed);
        EXPECT_EQ(arena.frames[index].destroy_count, 1u);
    }
}

Hash256 MakeHash(u8 seed)
{
    Hash256 hash{};
    for (u32 index = 0; index < sizeof(hash.bytes); ++index)
        hash.bytes[index] = static_cast<u8>(seed + index);
    return hash;
}

struct Fixture
{
    FakeArena arena{};
    LoadImage image{};
    std::array<LoadImagePage, kFixturePageCap> pages{};
    std::array<LoadImageRegionAuthority, kLoadPlanMaxRegions> regions{};
    std::array<u8, kLoadImageMaxPlanBytes> plan{};

    Fixture()
    {
        arena.fail_allocation_attempt = kNeverFail;
        arena.fail_map_attempt = kNeverFail;
        arena.fail_unmap_frame = kLoadImageInvalidFrame;
    }

    LoadImageStatus Initialize(u32 image_pages = 5)
    {
        const LoadImageDescriptor descriptor{ImageFormat::Pe32Plus,
                                             kBase,
                                             0x0000000140000000ULL,
                                             kBase + kLoadPlanPageSize + 0x20,
                                             static_cast<u64>(image_pages) * kLoadPlanPageSize,
                                             0xABCD1234ULL,
                                             MakeHash(0x10)};
        const LoadImageFrameHooks hooks{&arena, &FakeAllocate, &FakeRelease};
        return LoadImageInitialize(&image, descriptor, hooks, pages.data(), static_cast<u32>(pages.size()),
                                   regions.data(), static_cast<u32>(regions.size()), plan.data(),
                                   static_cast<u32>(plan.size()));
    }

    LoadImageMapHooks MapHooks() { return LoadImageMapHooks{&arena, &FakeMap, &FakeUnmap}; }
};

void BuildFourPageImage(Fixture& fixture)
{
    EXPECT_EQ(fixture.Initialize(), LoadImageStatus::Ok);
    EXPECT_EQ(LoadImageClaimRange(&fixture.image, 0, kLoadPlanPageSize, VmProtection::Read), LoadImageStatus::Ok);
    EXPECT_EQ(LoadImageClaimRange(&fixture.image, kLoadPlanPageSize, 2 * kLoadPlanPageSize,
                                  static_cast<VmProtection>(static_cast<u32>(VmProtection::Read) |
                                                            static_cast<u32>(VmProtection::Execute))),
              LoadImageStatus::Ok);
    EXPECT_EQ(LoadImageClaimRange(&fixture.image, 3 * kLoadPlanPageSize, kLoadPlanPageSize,
                                  static_cast<VmProtection>(static_cast<u32>(VmProtection::Read) |
                                                            static_cast<u32>(VmProtection::Write))),
              LoadImageStatus::Ok);
    std::array<u8, 16> bytes{};
    for (u32 index = 0; index < bytes.size(); ++index)
        bytes[index] = static_cast<u8>(0x40u + index);
    EXPECT_EQ(LoadImageCopyIn(&fixture.image, kLoadPlanPageSize - 8u, bytes.data(), bytes.size()), LoadImageStatus::Ok);
    EXPECT_EQ(LoadImageWriteLe(&fixture.image, 2 * kLoadPlanPageSize - 4u, 8, 0x8877665544332211ULL),
              LoadImageStatus::Ok);
    EXPECT_EQ(LoadImageSeal(&fixture.image), LoadImageStatus::Ok);
}

LoadImageSnapshot Inspect(const LoadImage& image)
{
    LoadImageSnapshot snapshot{};
    EXPECT_EQ(LoadImageInspect(&image, &snapshot), LoadImageStatus::Ok);
    return snapshot;
}

} // namespace

int main()
{
    static_assert(kLoadImageMaxPlanBytes == 64 + 256 * 72);

    // Canonical regions, page-straddle access, immutable plan emission, and
    // exact live backing authority.
    Fixture canonical;
    EXPECT_EQ(canonical.Initialize(), LoadImageStatus::Ok);
    EXPECT_EQ(LoadImageClaimRange(&canonical.image, 0, 0, VmProtection::Read), LoadImageStatus::InvalidArgument);
    EXPECT_EQ(LoadImageClaimRange(&canonical.image, 0, kLoadPlanPageSize, VmProtection::None),
              LoadImageStatus::InvalidProtection);
    EXPECT_EQ(LoadImageClaimRange(&canonical.image, 0, kLoadPlanPageSize, VmProtection::Read), LoadImageStatus::Ok);
    const VmProtection read_execute =
        static_cast<VmProtection>(static_cast<u32>(VmProtection::Read) | static_cast<u32>(VmProtection::Execute));
    const VmProtection read_write =
        static_cast<VmProtection>(static_cast<u32>(VmProtection::Read) | static_cast<u32>(VmProtection::Write));
    EXPECT_EQ(LoadImageClaimRange(&canonical.image, kLoadPlanPageSize, 2 * kLoadPlanPageSize, read_execute),
              LoadImageStatus::Ok);
    // A second read claim on an executable page is folded into the same final
    // protection and cannot create a duplicate plan region.
    EXPECT_EQ(LoadImageClaimRange(&canonical.image, kLoadPlanPageSize + 17, 31, VmProtection::Read),
              LoadImageStatus::Ok);
    EXPECT_EQ(LoadImageClaimRange(&canonical.image, 3 * kLoadPlanPageSize, kLoadPlanPageSize, read_write),
              LoadImageStatus::Ok);
    EXPECT_EQ(Inspect(canonical.image).package_owned_pages, 4u);

    std::array<u8, 16> cross_page{};
    for (u32 index = 0; index < cross_page.size(); ++index)
        cross_page[index] = static_cast<u8>(index + 1u);
    EXPECT_EQ(LoadImageCopyIn(&canonical.image, 2 * kLoadPlanPageSize - 8u, cross_page.data(), cross_page.size()),
              LoadImageStatus::Ok);
    std::array<u8, 16> copied{};
    EXPECT_EQ(LoadImageCopyOut(&canonical.image, 2 * kLoadPlanPageSize - 8u, copied.data(), copied.size()),
              LoadImageStatus::Ok);
    EXPECT_TRUE(copied == cross_page);
    EXPECT_EQ(LoadImageWriteLe(&canonical.image, 2 * kLoadPlanPageSize - 4u, 8, 0x8877665544332211ULL),
              LoadImageStatus::Ok);
    u64 value = 0;
    EXPECT_EQ(LoadImageReadLe(&canonical.image, 2 * kLoadPlanPageSize - 4u, 8, &value), LoadImageStatus::Ok);
    EXPECT_EQ(value, 0x8877665544332211ULL);
    value = 0xDEADBEEF;
    EXPECT_EQ(LoadImageReadLe(&canonical.image, 4 * kLoadPlanPageSize, 4, &value), LoadImageStatus::UnmappedRange);
    EXPECT_EQ(value, 0xDEADBEEFULL);

    EXPECT_EQ(LoadImageSeal(&canonical.image), LoadImageStatus::Ok);
    EXPECT_EQ(LoadImageSeal(&canonical.image), LoadImageStatus::AlreadySealed);
    EXPECT_EQ(LoadImageWriteLe(&canonical.image, kLoadPlanPageSize, 4, 1), LoadImageStatus::WriteAfterSeal);
    EXPECT_EQ(LoadImageCopyIn(&canonical.image, 0, cross_page.data(), 1), LoadImageStatus::WriteAfterSeal);
    EXPECT_EQ(LoadImageCopyOut(&canonical.image, 2 * kLoadPlanPageSize - 8u, copied.data(), copied.size()),
              LoadImageStatus::Ok);

    const u8* plan_bytes = nullptr;
    u32 plan_size = 0;
    EXPECT_TRUE(LoadImagePlanBytes(&canonical.image, &plan_bytes, &plan_size));
    EXPECT_EQ(plan_bytes, canonical.plan.data());
    EXPECT_EQ(plan_size, kLoadPlanV1HeaderBytes + 3u * kLoadRegionV1Bytes);
    LoadPlanViewV1 plan_view{};
    EXPECT_EQ(LoadPlanValidateV1(plan_bytes, plan_size, &canonical.image.descriptor.source_hash, &LoadImageBackingQuery,
                                 &canonical.image, &plan_view),
              LoadPlanValidationError::Ok);
    EXPECT_EQ(plan_view.header.region_count, 3u);
    LoadRegionV1 region{};
    EXPECT_TRUE(LoadPlanRegionAt(plan_view, 0, &region));
    EXPECT_EQ(region.virtual_address, kBase);
    EXPECT_EQ(region.length, kLoadPlanPageSize);
    EXPECT_EQ(region.protection, VmProtection::Read);
    EXPECT_TRUE(LoadPlanRegionAt(plan_view, 1, &region));
    EXPECT_EQ(region.virtual_address, kBase + kLoadPlanPageSize);
    EXPECT_EQ(region.length, 2 * kLoadPlanPageSize);
    EXPECT_EQ(region.protection, read_execute);
    EXPECT_TRUE(LoadPlanRegionAt(plan_view, 2, &region));
    EXPECT_EQ(region.virtual_address, kBase + 3 * kLoadPlanPageSize);
    EXPECT_EQ(region.protection, read_write);
    LoadBackingInfoV1 backing{};
    EXPECT_FALSE(LoadImageBackingQuery(canonical.image.descriptor.memory_object, 0, 2 * kLoadPlanPageSize, &backing,
                                       &canonical.image));
    EXPECT_FALSE(LoadImageBackingQuery(canonical.image.descriptor.memory_object + 1u, 0, kLoadPlanPageSize, &backing,
                                       &canonical.image));

    // Shared-page W/X is a build-time refusal, whether requested directly or
    // introduced by two individually valid overlapping claims. The prior page
    // remains unchanged after the rejected second claim.
    Fixture conflict;
    EXPECT_EQ(conflict.Initialize(2), LoadImageStatus::Ok);
    EXPECT_EQ(LoadImageClaimRange(&conflict.image, 0, kLoadPlanPageSize,
                                  static_cast<VmProtection>(static_cast<u32>(VmProtection::Write) |
                                                            static_cast<u32>(VmProtection::Execute))),
              LoadImageStatus::WritableExecutableConflict);
    EXPECT_EQ(LoadImageClaimRange(&conflict.image, 0, kLoadPlanPageSize, read_execute), LoadImageStatus::Ok);
    EXPECT_EQ(LoadImageClaimRange(&conflict.image, 128, 64, read_write), LoadImageStatus::WritableExecutableConflict);
    EXPECT_EQ(conflict.image.pages[0].protection, read_execute);
    LoadImageRelease(&conflict.image);
    ExpectExactlyOnce(conflict.arena);

    // A post-seal backing mutation is detected by the authority's live hash
    // before the first map callback. MapInto consumes/releases the package on
    // this terminal integrity failure.
    Fixture tampered;
    BuildFourPageImage(tampered);
    FakeFrame* first = FindFrame(tampered.arena, tampered.image.pages[0].frame);
    ASSERT_TRUE(first != nullptr);
    first->bytes[0] ^= 0x80;
    LoadImageMapHooks tampered_hooks = tampered.MapHooks();
    LoadImageMapResult map_result = LoadImageMapInto(&tampered.image, tampered_hooks);
    EXPECT_EQ(map_result.status, LoadImageStatus::PlanRejected);
    EXPECT_EQ(map_result.validation_error, LoadPlanValidationError::ContentHashMismatch);
    EXPECT_EQ(tampered.arena.map_attempts, 0u);
    EXPECT_EQ(tampered.arena.release_count, 4u);
    ExpectExactlyOnce(tampered.arena);
    LoadImageRelease(&tampered.image);
    EXPECT_EQ(tampered.arena.release_count, 4u);

    // Reordering otherwise-valid records is accepted by the generic wire
    // validator, but not by this package: canonical order is what makes its
    // allocation-free reverse-page walk the exact reverse map order.
    Fixture reordered;
    BuildFourPageImage(reordered);
    for (u32 index = 0; index < kLoadRegionV1Bytes; ++index)
    {
        u8& first_region = reordered.plan[kLoadPlanV1HeaderBytes + index];
        u8& last_region = reordered.plan[kLoadPlanV1HeaderBytes + 2u * kLoadRegionV1Bytes + index];
        const u8 temporary = first_region;
        first_region = last_region;
        last_region = temporary;
    }
    LoadImageMapHooks reordered_hooks = reordered.MapHooks();
    map_result = LoadImageMapInto(&reordered.image, reordered_hooks);
    EXPECT_EQ(map_result.status, LoadImageStatus::PlanAuthorityMismatch);
    EXPECT_EQ(map_result.validation_error, LoadPlanValidationError::Ok);
    EXPECT_EQ(reordered.arena.map_attempts, 0u);
    ExpectExactlyOnce(reordered.arena);

    // Successful map transfers every frame. Package release is then a no-op;
    // the fake target teardown is the one and only eventual destruction.
    Fixture successful;
    BuildFourPageImage(successful);
    LoadImageMapHooks success_hooks = successful.MapHooks();
    map_result = LoadImageMapInto(&successful.image, success_hooks);
    EXPECT_EQ(map_result.status, LoadImageStatus::Ok);
    EXPECT_EQ(map_result.validation_error, LoadPlanValidationError::Ok);
    EXPECT_EQ(map_result.pages_mapped, 4u);
    EXPECT_EQ(Inspect(successful.image).target_owned_pages, 4u);
    for (u32 index = 0; index < 4; ++index)
    {
        const FakeFrame* mapped = FindFrame(successful.arena, static_cast<LoadImageFrame>(index + 1u));
        ASSERT_TRUE(mapped != nullptr);
        EXPECT_EQ(mapped->mapped_va, kBase + static_cast<u64>(index) * kLoadPlanPageSize);
        const VmProtection expected = index == 0 ? VmProtection::Read : (index < 3 ? read_execute : read_write);
        EXPECT_EQ(mapped->mapped_protection, expected);
    }
    LoadImageRelease(&successful.image);
    EXPECT_EQ(successful.arena.release_count, 0u);
    DestroyResidualTargetFrames(successful.arena);
    EXPECT_EQ(successful.arena.external_destroys, 4u);
    ExpectExactlyOnce(successful.arena);

    // Inject map refusal at every page. Earlier successful mappings unwind in
    // reverse; the refused and later frames are package-released. Every frame
    // reaches exactly one terminal consumer before MapInto returns.
    for (u32 failing_page = 0; failing_page < 4; ++failing_page)
    {
        Fixture failure;
        BuildFourPageImage(failure);
        failure.arena.fail_map_attempt = failing_page;
        LoadImageMapHooks failure_hooks = failure.MapHooks();
        map_result = LoadImageMapInto(&failure.image, failure_hooks);
        EXPECT_EQ(map_result.status, LoadImageStatus::MapFailed);
        EXPECT_EQ(map_result.pages_mapped, failing_page);
        EXPECT_EQ(map_result.pages_rolled_back, failing_page);
        EXPECT_EQ(map_result.rollback_failures, 0u);
        EXPECT_EQ(failure.arena.release_count, 4u - failing_page);
        EXPECT_EQ(failure.arena.unmap_successes, failing_page);
        EXPECT_EQ(Inspect(failure.image).target_owned_pages, 0u);
        for (u32 index = 0; index < failing_page; ++index)
            EXPECT_EQ(failure.arena.unmap_log[index], static_cast<LoadImageFrame>(failing_page - index));
        ExpectExactlyOnce(failure.arena);
        LoadImageRelease(&failure.image);
        EXPECT_EQ(failure.arena.release_count, 4u - failing_page);
    }

    // Rollback refusal is explicit rather than guessed around. Every other
    // frame is consumed; the exact residual target owner is left for whole-AS
    // teardown, after which the once-only invariant still holds.
    Fixture rollback_failure;
    BuildFourPageImage(rollback_failure);
    rollback_failure.arena.fail_map_attempt = 3;
    rollback_failure.arena.fail_unmap_frame = 2;
    LoadImageMapHooks rollback_hooks = rollback_failure.MapHooks();
    map_result = LoadImageMapInto(&rollback_failure.image, rollback_hooks);
    EXPECT_EQ(map_result.status, LoadImageStatus::RollbackFailed);
    EXPECT_EQ(map_result.pages_mapped, 3u);
    EXPECT_EQ(map_result.pages_rolled_back, 2u);
    EXPECT_EQ(map_result.rollback_failures, 1u);
    EXPECT_EQ(Inspect(rollback_failure.image).target_owned_pages, 1u);
    LoadImageRelease(&rollback_failure.image);
    EXPECT_EQ(rollback_failure.arena.release_count, 1u);
    const FakeFrame* residual = FindFrame(rollback_failure.arena, 2);
    ASSERT_TRUE(residual != nullptr);
    EXPECT_EQ(residual->owner, FakeOwner::Target);
    EXPECT_EQ(residual->destroy_count, 0u);
    EXPECT_EQ(LoadImageResetQuiescent(&rollback_failure.image), LoadImageStatus::Ok);
    EXPECT_EQ(rollback_failure.image.state, LoadImageState::Uninitialized);
    EXPECT_EQ(residual->owner, FakeOwner::Target);
    EXPECT_EQ(residual->destroy_count, 0u);
    DestroyResidualTargetFrames(rollback_failure.arena);
    EXPECT_EQ(rollback_failure.arena.external_destroys, 1u);
    ExpectExactlyOnce(rollback_failure.arena);

    // Allocation refusal is terminal and releases every earlier allocation;
    // no partially built image can be sealed or mapped.
    Fixture allocation_failure;
    EXPECT_EQ(allocation_failure.Initialize(), LoadImageStatus::Ok);
    allocation_failure.arena.fail_allocation_attempt = 2;
    allocation_failure.arena.publish_false_allocation_sentinels = true;
    EXPECT_EQ(LoadImageClaimRange(&allocation_failure.image, 0, 4 * kLoadPlanPageSize, VmProtection::Read),
              LoadImageStatus::FrameAllocationFailed);
    EXPECT_EQ(allocation_failure.arena.frame_count, 2u);
    EXPECT_EQ(allocation_failure.arena.release_count, 2u);
    EXPECT_EQ(Inspect(allocation_failure.image).state, LoadImageState::Failed);
    ExpectExactlyOnce(allocation_failure.arena);
    EXPECT_EQ(LoadImageSeal(&allocation_failure.image), LoadImageStatus::InvalidState);
    LoadImageRelease(&allocation_failure.image);
    EXPECT_EQ(allocation_failure.arena.release_count, 2u);
    EXPECT_EQ(LoadImageResetQuiescent(&allocation_failure.image), LoadImageStatus::Ok);
    EXPECT_EQ(allocation_failure.image.state, LoadImageState::Uninitialized);

    // Reset never guesses away package ownership. Even a forged terminal state
    // is rejected byte-for-byte until the normal release path consumes every
    // package-owned frame.
    {
        Fixture outstanding;
        BuildFourPageImage(outstanding);
        const u8 plan_first = outstanding.plan[0];
        outstanding.image.state = LoadImageState::Failed;
        EXPECT_EQ(LoadImageResetQuiescent(&outstanding.image), LoadImageStatus::OwnershipOutstanding);
        EXPECT_EQ(outstanding.image.state, LoadImageState::Failed);
        EXPECT_EQ(outstanding.plan[0], plan_first);
        EXPECT_EQ(outstanding.arena.release_count, 0u);
        LoadImageRelease(&outstanding.image);
        EXPECT_EQ(outstanding.arena.release_count, 4u);
        EXPECT_EQ(LoadImageResetQuiescent(&outstanding.image), LoadImageStatus::Ok);
        ExpectExactlyOnce(outstanding.arena);
    }

    // A fully transferred image owns no frame. Reset invalidates all stale
    // image/backing metadata while leaving target ownership untouched for the
    // target's independent teardown ledger.
    {
        Fixture retired;
        BuildFourPageImage(retired);
        const ObjectHandle stale_memory_object = retired.image.descriptor.memory_object;
        LoadImageMapHooks hooks = retired.MapHooks();
        EXPECT_EQ(LoadImageMapInto(&retired.image, hooks).status, LoadImageStatus::Ok);
        EXPECT_EQ(Inspect(retired.image).target_owned_pages, 4u);
        EXPECT_EQ(LoadImageResetQuiescent(&retired.image), LoadImageStatus::Ok);
        EXPECT_EQ(retired.image.state, LoadImageState::Uninitialized);
        EXPECT_EQ(retired.image.pages, nullptr);
        EXPECT_EQ(retired.image.regions, nullptr);
        EXPECT_EQ(retired.image.plan_storage, nullptr);
        for (const LoadImagePage& page : retired.pages)
            EXPECT_EQ(page.state, LoadImagePageState::Empty);
        for (u8 byte : retired.plan)
            EXPECT_EQ(byte, 0u);
        LoadBackingInfoV1 stale_backing{};
        EXPECT_FALSE(LoadImageBackingQuery(stale_memory_object, 0, kLoadPlanPageSize, &stale_backing, &retired.image));
        EXPECT_EQ(retired.arena.release_count, 0u);
        DestroyResidualTargetFrames(retired.arena);
        ExpectExactlyOnce(retired.arena);
    }

    // A false allocation result owns nothing even if the callback leaves
    // stale-looking nonzero outputs. No release callback may see them.
    Fixture false_sentinel;
    EXPECT_EQ(false_sentinel.Initialize(), LoadImageStatus::Ok);
    false_sentinel.arena.fail_allocation_attempt = 0;
    false_sentinel.arena.publish_false_allocation_sentinels = true;
    EXPECT_EQ(LoadImageClaimRange(&false_sentinel.image, 0, kLoadPlanPageSize, VmProtection::Read),
              LoadImageStatus::FrameAllocationFailed);
    EXPECT_EQ(false_sentinel.arena.frame_count, 0u);
    EXPECT_EQ(false_sentinel.arena.release_count, 0u);
    LoadImageRelease(&false_sentinel.image);
    EXPECT_EQ(false_sentinel.arena.release_count, 0u);

    EXPECT_STREQ(LoadImageStatusName(LoadImageStatus::RollbackFailed), "rollback-failed");
    EXPECT_STREQ(LoadImageStatusName(LoadImageStatus::WritableExecutableConflict), "writable-executable-conflict");
    EXPECT_STREQ(LoadImageStatusName(LoadImageStatus::OwnershipOutstanding), "ownership-outstanding");
    EXPECT_STREQ(LoadImageStatusName(static_cast<LoadImageStatus>(0xFF)), "unknown");

    LoadImageRelease(&canonical.image);
    ExpectExactlyOnce(canonical.arena);
    return duetos_host_test::finish_main("test_load_image");
}
