// Hosted hostile-boundary coverage for loader/exec_admission.{h,cpp}.
//
// The seam must freeze hostile bytes before decoding, preserve exact token
// identity across cancel/consume races, and never expose a view on failure.

#include "host_test_helper.h"
#include "loader/exec_admission.h"

#include <array>
#include <atomic>
#include <thread>

namespace
{

using duetos::u16;
using duetos::u32;
using duetos::u64;
using duetos::u8;
using duetos::uptr;
using namespace duetos::loader;

constexpr u32 kRegionCount = 2;
constexpr u32 kValidPlanBytes = kLoadPlanV1HeaderBytes + kRegionCount * kLoadRegionV1Bytes;

constexpr u32 kHeaderSize = 0;
constexpr u32 kHeaderVersion = 4;
constexpr u32 kHeaderFormat = 6;
constexpr u32 kHeaderEntry = 8;
constexpr u32 kHeaderPreferredBase = 16;
constexpr u32 kHeaderRegionCount = 24;
constexpr u32 kHeaderDependencyCount = 28;
constexpr u32 kHeaderSourceHash = 32;

constexpr u32 kRegionVirtualAddress = 0;
constexpr u32 kRegionLength = 8;
constexpr u32 kRegionMemoryObject = 16;
constexpr u32 kRegionObjectOffset = 24;
constexpr u32 kRegionProtection = 32;
constexpr u32 kRegionContentHash = 36;
constexpr u32 kRegionReserved = 68;

constexpr ObjectHandle kImageObject = 0xA001;
using ValidBlob = std::array<u8, kValidPlanBytes>;

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
    WriteLe32(bytes, static_cast<u32>(value & 0xFFFFFFFFULL));
    WriteLe32(bytes + 4, static_cast<u32>(value >> 32u));
}

Hash256 MakeHash(u8 seed)
{
    Hash256 hash{};
    for (u32 index = 0; index < 32; ++index)
        hash.bytes[index] = static_cast<u8>(seed + index);
    return hash;
}

void WriteHash(u8* bytes, const Hash256& hash)
{
    for (u32 index = 0; index < 32; ++index)
        bytes[index] = hash.bytes[index];
}

u8* RegionBytes(ValidBlob& blob, u32 index)
{
    return blob.data() + kLoadPlanV1HeaderBytes + index * kLoadRegionV1Bytes;
}

void WriteRegion(ValidBlob& blob, u32 index, u64 virtual_address, u64 length, u64 object_offset, u32 protection,
                 const Hash256& content_hash)
{
    u8* region = RegionBytes(blob, index);
    WriteLe64(region + kRegionVirtualAddress, virtual_address);
    WriteLe64(region + kRegionLength, length);
    WriteLe64(region + kRegionMemoryObject, kImageObject);
    WriteLe64(region + kRegionObjectOffset, object_offset);
    WriteLe32(region + kRegionProtection, protection);
    WriteHash(region + kRegionContentHash, content_hash);
    WriteLe32(region + kRegionReserved, 0);
}

ValidBlob MakeValidBlob()
{
    ValidBlob blob{};
    WriteLe32(blob.data() + kHeaderSize, kValidPlanBytes);
    WriteLe16(blob.data() + kHeaderVersion, kLoadPlanVersion1);
    WriteLe16(blob.data() + kHeaderFormat, static_cast<u16>(ImageFormat::Pe32Plus));
    WriteLe64(blob.data() + kHeaderEntry, 0x401000);
    WriteLe64(blob.data() + kHeaderPreferredBase, 0x400000);
    WriteLe32(blob.data() + kHeaderRegionCount, kRegionCount);
    WriteLe32(blob.data() + kHeaderDependencyCount, 0);
    WriteHash(blob.data() + kHeaderSourceHash, MakeHash(0x10));

    WriteRegion(blob, 0, 0x400000, 0x2000, 0,
                static_cast<u32>(VmProtection::Read) | static_cast<u32>(VmProtection::Execute), MakeHash(0x40));
    WriteRegion(blob, 1, 0x402000, 0x1000, 0x2000,
                static_cast<u32>(VmProtection::Read) | static_cast<u32>(VmProtection::Write), MakeHash(0x70));
    return blob;
}

struct CallbackBarrier
{
    std::atomic<u32> entered{0};
    std::atomic<u32> released{0};
};

struct BackingAuthority
{
    Hash256 source_hash;
    Hash256 code_hash;
    Hash256 data_hash;
    u32 calls;
    bool cancel_on_first;
    ExecAdmission* cancel_admission;
    u64 cancel_token;
    ExecAdmissionStatus cancel_status;
    Hash256* mutate_expected_hash;
    CallbackBarrier* barrier;
};

BackingAuthority MakeAuthority()
{
    return BackingAuthority{
        MakeHash(0x10), MakeHash(0x40), MakeHash(0x70), 0, false, nullptr, 0, ExecAdmissionStatus::CorruptState,
        nullptr,        nullptr};
}

bool QueryBacking(ObjectHandle memory_object, u64 object_offset, u64 length, LoadBackingInfoV1* out_info, void* context)
{
    if (out_info == nullptr || context == nullptr)
        return false;

    auto* authority = static_cast<BackingAuthority*>(context);
    ++authority->calls;
    if (authority->cancel_on_first && authority->calls == 1)
        authority->cancel_status = ExecAdmissionCancel(authority->cancel_admission, authority->cancel_token);
    if (authority->calls == 1 && authority->mutate_expected_hash != nullptr)
    {
        for (u32 index = 0; index < 32; ++index)
            authority->mutate_expected_hash->bytes[index] ^= 0xFFu;
    }
    if (authority->calls == 1 && authority->barrier != nullptr)
    {
        authority->barrier->entered.store(1, std::memory_order_release);
        authority->barrier->entered.notify_one();
        authority->barrier->released.wait(0, std::memory_order_acquire);
    }

    const Hash256* slice_hash = nullptr;
    if (memory_object == kImageObject && object_offset == 0 && length == 0x2000)
        slice_hash = &authority->code_hash;
    else if (memory_object == kImageObject && object_offset == 0x2000 && length == 0x1000)
        slice_hash = &authority->data_hash;
    else
        return false;

    *out_info = LoadBackingInfoV1{};
    out_info->object_size = 0x3000;
    out_info->sealed = 1;
    out_info->slice_hash = *slice_hash;
    return true;
}

struct AdmissionFixture
{
    ExecAdmission admission{};
    std::array<u8, kExecAdmissionMaxPlanBytes> storage{};

    explicit AdmissionFixture(u64 first_identity = 1)
    {
        EXPECT_EQ(ExecAdmissionInitialize(&admission, storage.data(), static_cast<u32>(storage.size()), first_identity),
                  ExecAdmissionStatus::Ok);
    }
};

void PoisonView(LoadPlanViewV1* view)
{
    *view = LoadPlanViewV1{};
    view->bytes = reinterpret_cast<const u8*>(static_cast<uptr>(1));
    view->size = 0xFFFFFFFFu;
    view->header.region_count = 0xFFFFFFFFu;
}

void ExpectNoView(const LoadPlanViewV1& view)
{
    EXPECT_EQ(view.bytes, nullptr);
    EXPECT_EQ(view.size, 0u);
    EXPECT_EQ(view.header.region_count, 0u);
}

} // namespace

int main()
{
    static_assert(kExecAdmissionMaxPlanBytes == 18496);
    static_assert(kExecAdmissionMaxPlanBytes > 4096);

    // Initialization owns a full maximum-sized frozen buffer.
    {
        ExecAdmission admission{};
        std::array<u8, kExecAdmissionMaxPlanBytes - 1> short_storage{};
        EXPECT_EQ(ExecAdmissionInitialize(&admission, short_storage.data(), static_cast<u32>(short_storage.size())),
                  ExecAdmissionStatus::StorageTooSmall);
    }

    // Prepare copies once. Mutating the hostile source afterwards cannot
    // affect validation or the decoded view.
    {
        AdmissionFixture fixture(10);
        ValidBlob source = MakeValidBlob();
        BackingAuthority authority = MakeAuthority();
        const ExecAdmissionPrepareResult prepared =
            ExecAdmissionPrepare(&fixture.admission, source.data(), static_cast<u64>(source.size()));
        EXPECT_EQ(prepared.status, ExecAdmissionStatus::Ok);
        EXPECT_EQ(prepared.token, 10ULL);

        source.fill(0xA5);
        LoadPlanViewV1 view{};
        const ExecAdmissionConsumeResult consumed = ExecAdmissionConsume(
            &fixture.admission, prepared.token, &authority.source_hash, &QueryBacking, &authority, &view);
        EXPECT_EQ(consumed.status, ExecAdmissionStatus::Ok);
        EXPECT_EQ(consumed.validation_error, LoadPlanValidationError::Ok);
        EXPECT_EQ(authority.calls, kRegionCount);
        EXPECT_EQ(view.bytes, fixture.storage.data());
        EXPECT_NE(view.bytes, source.data());
        EXPECT_EQ(view.size, kValidPlanBytes);
        EXPECT_EQ(view.header.entry_point, 0x401000ULL);
        EXPECT_EQ(view.header.region_count, kRegionCount);
        LoadRegionV1 region{};
        EXPECT_TRUE(LoadPlanRegionAt(view, 1, &region));
        EXPECT_EQ(region.virtual_address, 0x402000ULL);
        EXPECT_EQ(region.object_offset, 0x2000ULL);
    }

    // Only the active identity is accepted. Wrong tokens do not disturb it,
    // and a retired identity cannot consume a later attempt.
    {
        AdmissionFixture fixture(40);
        ValidBlob blob = MakeValidBlob();
        BackingAuthority authority = MakeAuthority();
        const ExecAdmissionPrepareResult first = ExecAdmissionPrepare(&fixture.admission, blob.data(), blob.size());
        EXPECT_EQ(first.status, ExecAdmissionStatus::Ok);

        LoadPlanViewV1 view{};
        PoisonView(&view);
        EXPECT_EQ(ExecAdmissionConsume(&fixture.admission, first.token + 1, &authority.source_hash, &QueryBacking,
                                       &authority, &view)
                      .status,
                  ExecAdmissionStatus::StaleToken);
        ExpectNoView(view);
        EXPECT_EQ(authority.calls, 0u);
        EXPECT_EQ(ExecAdmissionCancel(&fixture.admission, first.token + 1), ExecAdmissionStatus::StaleToken);
        EXPECT_EQ(ExecAdmissionCancel(&fixture.admission, first.token), ExecAdmissionStatus::Ok);

        const ExecAdmissionPrepareResult second = ExecAdmissionPrepare(&fixture.admission, blob.data(), blob.size());
        EXPECT_EQ(second.status, ExecAdmissionStatus::Ok);
        EXPECT_EQ(second.token, first.token + 1);
        PoisonView(&view);
        EXPECT_EQ(ExecAdmissionConsume(&fixture.admission, first.token, &authority.source_hash, &QueryBacking,
                                       &authority, &view)
                      .status,
                  ExecAdmissionStatus::TokenReplayed);
        ExpectNoView(view);
        EXPECT_EQ(authority.calls, 0u);
        EXPECT_EQ(ExecAdmissionCancel(&fixture.admission, second.token), ExecAdmissionStatus::Ok);
    }

    // Cancellation is exact and terminal for that token.
    {
        AdmissionFixture fixture;
        ValidBlob blob = MakeValidBlob();
        BackingAuthority authority = MakeAuthority();
        const ExecAdmissionPrepareResult prepared = ExecAdmissionPrepare(&fixture.admission, blob.data(), blob.size());
        EXPECT_EQ(prepared.status, ExecAdmissionStatus::Ok);
        EXPECT_EQ(ExecAdmissionCancel(&fixture.admission, prepared.token), ExecAdmissionStatus::Ok);
        EXPECT_EQ(ExecAdmissionCancel(&fixture.admission, prepared.token), ExecAdmissionStatus::TokenReplayed);

        LoadPlanViewV1 view{};
        PoisonView(&view);
        EXPECT_EQ(ExecAdmissionConsume(&fixture.admission, prepared.token, &authority.source_hash, &QueryBacking,
                                       &authority, &view)
                      .status,
                  ExecAdmissionStatus::TokenReplayed);
        ExpectNoView(view);
        EXPECT_EQ(authority.calls, 0u);
    }

    // A successful consume publishes one stable view and closes the object.
    {
        AdmissionFixture fixture;
        ValidBlob blob = MakeValidBlob();
        BackingAuthority authority = MakeAuthority();
        const ExecAdmissionPrepareResult prepared = ExecAdmissionPrepare(&fixture.admission, blob.data(), blob.size());
        LoadPlanViewV1 view{};
        EXPECT_EQ(ExecAdmissionConsume(&fixture.admission, prepared.token, &authority.source_hash, &QueryBacking,
                                       &authority, &view)
                      .status,
                  ExecAdmissionStatus::Ok);

        PoisonView(&view);
        EXPECT_EQ(ExecAdmissionConsume(&fixture.admission, prepared.token, &authority.source_hash, &QueryBacking,
                                       &authority, &view)
                      .status,
                  ExecAdmissionStatus::TokenReplayed);
        ExpectNoView(view);
        EXPECT_EQ(ExecAdmissionCancel(&fixture.admission, prepared.token), ExecAdmissionStatus::TokenReplayed);
        EXPECT_EQ(ExecAdmissionPrepare(&fixture.admission, blob.data(), blob.size()).status,
                  ExecAdmissionStatus::Terminal);
    }

    // A quiescent reset is the only fixed-bank reuse path. It carries the
    // logical token namespace forward, rejects reset while an attempt is
    // active, and makes every token from the prior incarnation stale.
    {
        ExecAdmission admission{};
        std::array<u8, kExecAdmissionMaxPlanBytes> storage{};
        constexpr u64 kFirstIdentity = 500;
        EXPECT_EQ(ExecAdmissionInitialize(&admission, storage.data(), static_cast<u32>(storage.size()), kFirstIdentity),
                  ExecAdmissionStatus::Ok);

        u64 expected_identity = kFirstIdentity;
        u64 prior_identity = 0;
        constexpr u32 kReuseCycles = 16;
        for (u32 cycle = 0; cycle < kReuseCycles; ++cycle)
        {
            ValidBlob blob = MakeValidBlob();
            BackingAuthority authority = MakeAuthority();
            const ExecAdmissionPrepareResult prepared = ExecAdmissionPrepare(&admission, blob.data(), blob.size());
            EXPECT_EQ(prepared.status, ExecAdmissionStatus::Ok);
            EXPECT_EQ(prepared.token, expected_identity);

            u64 untouched_successor = 0xBAD0BAD0BAD0BAD0ULL;
            EXPECT_EQ(ExecAdmissionQuiescentSuccessorIdentity(&admission, &untouched_successor),
                      ExecAdmissionStatus::NotQuiescent);
            EXPECT_EQ(untouched_successor, 0xBAD0BAD0BAD0BAD0ULL);
            EXPECT_EQ(ExecAdmissionResetQuiescent(&admission), ExecAdmissionStatus::NotQuiescent);

            if (prior_identity != 0)
            {
                LoadPlanViewV1 stale_view{};
                PoisonView(&stale_view);
                EXPECT_EQ(ExecAdmissionConsume(&admission, prior_identity, &authority.source_hash, &QueryBacking,
                                               &authority, &stale_view)
                              .status,
                          ExecAdmissionStatus::StaleToken);
                ExpectNoView(stale_view);
                EXPECT_EQ(authority.calls, 0u);
            }

            LoadPlanViewV1 view{};
            EXPECT_EQ(ExecAdmissionConsume(&admission, prepared.token, &authority.source_hash, &QueryBacking,
                                           &authority, &view)
                          .status,
                      ExecAdmissionStatus::Ok);
            EXPECT_EQ(view.bytes, storage.data());

            u64 successor = 0;
            EXPECT_EQ(ExecAdmissionQuiescentSuccessorIdentity(&admission, &successor), ExecAdmissionStatus::Ok);
            EXPECT_EQ(successor, expected_identity + 1u);
            prior_identity = prepared.token;
            expected_identity = successor;

            EXPECT_EQ(ExecAdmissionResetQuiescent(&admission), ExecAdmissionStatus::Ok);
            EXPECT_EQ(admission.initialized, 0u);
            EXPECT_EQ(admission.state, ExecAdmissionState::Uninitialized);
            EXPECT_EQ(admission.storage, nullptr);
            EXPECT_EQ(admission.next_identity, 0ULL);
            for (u8 byte : storage)
                EXPECT_EQ(byte, 0u);

            EXPECT_EQ(ExecAdmissionInitialize(&admission, storage.data(), static_cast<u32>(storage.size()), successor),
                      ExecAdmissionStatus::Ok);
        }
        EXPECT_EQ(ExecAdmissionResetQuiescent(&admission), ExecAdmissionStatus::Ok);
    }

    // The final u64 identity is issued exactly once; retirement poisons the
    // object rather than wrapping to zero or an earlier token.
    {
        constexpr u64 kLastIdentity = ~static_cast<u64>(0);
        AdmissionFixture fixture(kLastIdentity);
        ValidBlob blob = MakeValidBlob();
        const ExecAdmissionPrepareResult prepared = ExecAdmissionPrepare(&fixture.admission, blob.data(), blob.size());
        EXPECT_EQ(prepared.status, ExecAdmissionStatus::Ok);
        EXPECT_EQ(prepared.token, kLastIdentity);
        EXPECT_EQ(ExecAdmissionCancel(&fixture.admission, prepared.token), ExecAdmissionStatus::Ok);
        u64 untouched_successor = 0xA5A5A5A5A5A5A5A5ULL;
        EXPECT_EQ(ExecAdmissionQuiescentSuccessorIdentity(&fixture.admission, &untouched_successor),
                  ExecAdmissionStatus::IdentityExhausted);
        EXPECT_EQ(untouched_successor, 0xA5A5A5A5A5A5A5A5ULL);
        EXPECT_EQ(fixture.admission.next_identity, kLastIdentity);
        EXPECT_EQ(fixture.admission.retired_identity, kLastIdentity);
        const ExecAdmissionPrepareResult exhausted = ExecAdmissionPrepare(&fixture.admission, blob.data(), blob.size());
        EXPECT_EQ(exhausted.status, ExecAdmissionStatus::IdentityExhausted);
        EXPECT_EQ(exhausted.token, 0ULL);
    }

    // Framing and alias failures occur before token allocation.
    {
        AdmissionFixture fixture(70);
        std::array<u8, kExecAdmissionMaxPlanBytes + 1> oversized{};
        ValidBlob blob = MakeValidBlob();
        const ExecAdmissionPrepareResult too_large =
            ExecAdmissionPrepare(&fixture.admission, oversized.data(), oversized.size());
        EXPECT_EQ(too_large.status, ExecAdmissionStatus::PlanTooLarge);
        EXPECT_EQ(too_large.token, 0ULL);
        EXPECT_EQ(ExecAdmissionPrepare(&fixture.admission, fixture.storage.data(), kValidPlanBytes).status,
                  ExecAdmissionStatus::AliasedBuffer);
        const ExecAdmissionPrepareResult prepared = ExecAdmissionPrepare(&fixture.admission, blob.data(), blob.size());
        EXPECT_EQ(prepared.status, ExecAdmissionStatus::Ok);
        EXPECT_EQ(prepared.token, 70ULL);
        EXPECT_EQ(ExecAdmissionCancel(&fixture.admission, prepared.token), ExecAdmissionStatus::Ok);
    }

    // Aliased outputs are rejected without clearing bytes that belong to the
    // admission object or its frozen plan. The exact token remains usable.
    {
        AdmissionFixture fixture;
        ValidBlob blob = MakeValidBlob();
        BackingAuthority authority = MakeAuthority();
        const ExecAdmissionPrepareResult prepared = ExecAdmissionPrepare(&fixture.admission, blob.data(), blob.size());
        const u8 frozen_first_byte = fixture.storage[0];

        LoadPlanViewV1 authority_alias_view{};
        PoisonView(&authority_alias_view);
        const auto* plan_authored_hash = reinterpret_cast<const Hash256*>(fixture.storage.data() + kHeaderSourceHash);
        EXPECT_EQ(ExecAdmissionConsume(&fixture.admission, prepared.token, plan_authored_hash, &QueryBacking,
                                       &authority, &authority_alias_view)
                      .status,
                  ExecAdmissionStatus::AliasedBuffer);
        ExpectNoView(authority_alias_view);
        EXPECT_EQ(authority.calls, 0u);

        auto* storage_alias = reinterpret_cast<LoadPlanViewV1*>(fixture.storage.data());
        EXPECT_EQ(ExecAdmissionConsume(&fixture.admission, prepared.token, &authority.source_hash, &QueryBacking,
                                       &authority, storage_alias)
                      .status,
                  ExecAdmissionStatus::AliasedBuffer);
        EXPECT_EQ(fixture.storage[0], frozen_first_byte);

        auto* object_alias = reinterpret_cast<LoadPlanViewV1*>(&fixture.admission);
        EXPECT_EQ(ExecAdmissionConsume(&fixture.admission, prepared.token, &authority.source_hash, &QueryBacking,
                                       &authority, object_alias)
                      .status,
                  ExecAdmissionStatus::AliasedBuffer);

        LoadPlanViewV1 view{};
        EXPECT_EQ(ExecAdmissionConsume(&fixture.admission, prepared.token, &authority.source_hash, &QueryBacking,
                                       &authority, &view)
                      .status,
                  ExecAdmissionStatus::Ok);
        EXPECT_EQ(authority.calls, kRegionCount);
    }

    // Structural rejection and source-authority rejection perform no backing
    // callbacks and publish no view.
    {
        AdmissionFixture fixture;
        ValidBlob malformed = MakeValidBlob();
        WriteLe32(malformed.data() + kHeaderDependencyCount, 1);
        BackingAuthority authority = MakeAuthority();
        const ExecAdmissionPrepareResult prepared =
            ExecAdmissionPrepare(&fixture.admission, malformed.data(), malformed.size());
        LoadPlanViewV1 view{};
        PoisonView(&view);
        const ExecAdmissionConsumeResult rejected = ExecAdmissionConsume(
            &fixture.admission, prepared.token, &authority.source_hash, &QueryBacking, &authority, &view);
        EXPECT_EQ(rejected.status, ExecAdmissionStatus::PlanRejected);
        EXPECT_EQ(rejected.validation_error, LoadPlanValidationError::DependenciesUnsupported);
        EXPECT_EQ(authority.calls, 0u);
        ExpectNoView(view);
    }

    // The caller-owned expected hash is copied before callbacks. Mutating the
    // caller's object inside the first query cannot revise that decision.
    {
        AdmissionFixture fixture;
        ValidBlob blob = MakeValidBlob();
        BackingAuthority authority = MakeAuthority();
        Hash256 expected_hash = authority.source_hash;
        authority.mutate_expected_hash = &expected_hash;
        const ExecAdmissionPrepareResult prepared = ExecAdmissionPrepare(&fixture.admission, blob.data(), blob.size());
        LoadPlanViewV1 view{};
        const ExecAdmissionConsumeResult consumed =
            ExecAdmissionConsume(&fixture.admission, prepared.token, &expected_hash, &QueryBacking, &authority, &view);
        EXPECT_EQ(consumed.status, ExecAdmissionStatus::Ok);
        EXPECT_NE(expected_hash.bytes[0], authority.source_hash.bytes[0]);
        EXPECT_EQ(authority.calls, kRegionCount);
        EXPECT_EQ(view.bytes, fixture.storage.data());
    }
    {
        AdmissionFixture fixture;
        ValidBlob blob = MakeValidBlob();
        BackingAuthority authority = MakeAuthority();
        Hash256 wrong_source_hash = authority.source_hash;
        wrong_source_hash.bytes[0] ^= 0xFFu;
        const ExecAdmissionPrepareResult prepared = ExecAdmissionPrepare(&fixture.admission, blob.data(), blob.size());
        LoadPlanViewV1 view{};
        PoisonView(&view);
        const ExecAdmissionConsumeResult rejected = ExecAdmissionConsume(
            &fixture.admission, prepared.token, &wrong_source_hash, &QueryBacking, &authority, &view);
        EXPECT_EQ(rejected.status, ExecAdmissionStatus::PlanRejected);
        EXPECT_EQ(rejected.validation_error, LoadPlanValidationError::SourceHashMismatch);
        EXPECT_EQ(authority.calls, 0u);
        ExpectNoView(view);
    }
    {
        AdmissionFixture fixture;
        ValidBlob blob = MakeValidBlob();
        BackingAuthority authority = MakeAuthority();
        const ExecAdmissionPrepareResult prepared = ExecAdmissionPrepare(&fixture.admission, blob.data(), blob.size());
        LoadPlanViewV1 view{};
        PoisonView(&view);
        const ExecAdmissionConsumeResult rejected =
            ExecAdmissionConsume(&fixture.admission, prepared.token, nullptr, &QueryBacking, &authority, &view);
        EXPECT_EQ(rejected.status, ExecAdmissionStatus::PlanRejected);
        EXPECT_EQ(rejected.validation_error, LoadPlanValidationError::SourceHashAuthorityRequired);
        EXPECT_EQ(authority.calls, 0u);
        ExpectNoView(view);
    }
    {
        AdmissionFixture fixture;
        ValidBlob blob = MakeValidBlob();
        BackingAuthority authority = MakeAuthority();
        const ExecAdmissionPrepareResult prepared = ExecAdmissionPrepare(&fixture.admission, blob.data(), blob.size());
        LoadPlanViewV1 view{};
        PoisonView(&view);
        const ExecAdmissionConsumeResult rejected = ExecAdmissionConsume(
            &fixture.admission, prepared.token, &authority.source_hash, nullptr, &authority, &view);
        EXPECT_EQ(rejected.status, ExecAdmissionStatus::PlanRejected);
        EXPECT_EQ(rejected.validation_error, LoadPlanValidationError::BackingQueryRequired);
        EXPECT_EQ(authority.calls, 0u);
        ExpectNoView(view);
    }

    // A backing callback can cancel because no admission lock is held. The
    // validator completes against frozen bytes, then Consume suppresses the
    // otherwise-valid view and retires the token.
    {
        AdmissionFixture fixture;
        ValidBlob blob = MakeValidBlob();
        BackingAuthority authority = MakeAuthority();
        const ExecAdmissionPrepareResult prepared = ExecAdmissionPrepare(&fixture.admission, blob.data(), blob.size());
        authority.cancel_on_first = true;
        authority.cancel_admission = &fixture.admission;
        authority.cancel_token = prepared.token;

        LoadPlanViewV1 view{};
        PoisonView(&view);
        const ExecAdmissionConsumeResult cancelled = ExecAdmissionConsume(
            &fixture.admission, prepared.token, &authority.source_hash, &QueryBacking, &authority, &view);
        EXPECT_EQ(authority.cancel_status, ExecAdmissionStatus::CancelPending);
        EXPECT_EQ(authority.calls, kRegionCount);
        EXPECT_EQ(cancelled.status, ExecAdmissionStatus::Cancelled);
        EXPECT_EQ(cancelled.validation_error, LoadPlanValidationError::Ok);
        ExpectNoView(view);
        EXPECT_EQ(ExecAdmissionCancel(&fixture.admission, prepared.token), ExecAdmissionStatus::TokenReplayed);
    }

    // Deterministically hold Consume in its unlocked validation callback. A
    // competing exact consume sees Busy and clears its output; an exact cancel
    // remains responsive and suppresses publication by the first consumer.
    constexpr u32 kConcurrencyRepetitions = 32;
    for (u32 repetition = 0; repetition < kConcurrencyRepetitions; ++repetition)
    {
        AdmissionFixture fixture(static_cast<u64>(1000 + repetition));
        ValidBlob blob = MakeValidBlob();
        BackingAuthority authority = MakeAuthority();
        CallbackBarrier barrier{};
        authority.barrier = &barrier;
        const ExecAdmissionPrepareResult prepared = ExecAdmissionPrepare(&fixture.admission, blob.data(), blob.size());

        ExecAdmissionConsumeResult first_result{};
        LoadPlanViewV1 first_view{};
        PoisonView(&first_view);
        std::thread first_consumer(
            [&]()
            {
                first_result = ExecAdmissionConsume(&fixture.admission, prepared.token, &authority.source_hash,
                                                    &QueryBacking, &authority, &first_view);
            });

        barrier.entered.wait(0, std::memory_order_acquire);
        LoadPlanViewV1 competing_view{};
        PoisonView(&competing_view);
        EXPECT_EQ(ExecAdmissionConsume(&fixture.admission, prepared.token, &authority.source_hash, &QueryBacking,
                                       &authority, &competing_view)
                      .status,
                  ExecAdmissionStatus::Busy);
        ExpectNoView(competing_view);
        EXPECT_EQ(ExecAdmissionCancel(&fixture.admission, prepared.token), ExecAdmissionStatus::CancelPending);

        barrier.released.store(1, std::memory_order_release);
        barrier.released.notify_one();
        first_consumer.join();
        EXPECT_EQ(first_result.status, ExecAdmissionStatus::Cancelled);
        EXPECT_EQ(first_result.validation_error, LoadPlanValidationError::Ok);
        ExpectNoView(first_view);
        EXPECT_EQ(authority.calls, kRegionCount);
        EXPECT_EQ(ExecAdmissionCancel(&fixture.admission, prepared.token), ExecAdmissionStatus::TokenReplayed);
    }

    EXPECT_STREQ(ExecAdmissionStatusName(ExecAdmissionStatus::Ok), "ok");
    EXPECT_STREQ(ExecAdmissionStatusName(ExecAdmissionStatus::TokenReplayed), "token-replayed");
    EXPECT_STREQ(ExecAdmissionStatusName(ExecAdmissionStatus::PlanRejected), "plan-rejected");
    EXPECT_STREQ(ExecAdmissionStatusName(ExecAdmissionStatus::NotQuiescent), "not-quiescent");
    EXPECT_STREQ(ExecAdmissionStatusName(static_cast<ExecAdmissionStatus>(0xFF)), "unknown");

    return duetos_host_test::finish_main("test_exec_admission");
}
