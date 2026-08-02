// Hosted staging coverage for loader/elf_load_image.{h,cpp}.
//
// The production parser entry points are deterministic fakes here; their Rust
// hostile-input suite remains authoritative for byte parsing. This test owns
// the adapter contract: exact-source hashing, PT_LOAD bounds/protections,
// failure-atomic frame staging, and sealed LoadPlan output.

#include "crypto_host_shims.h"
#include "host_test_helper.h"
#include "loader/elf_load_image.h"

#include "crypto/sha256.h"

#include <array>

namespace fixture
{

using duetos::u32;
using duetos::u64;
using duetos::u8;
using duetos::core::ElfSegment;
using duetos::core::ElfStatus;

inline constexpr u32 kMaximumSegments = 260;
inline std::array<ElfSegment, kMaximumSegments> segments{};
inline u32 segment_count = 0;
inline u64 entry_point = 0x400080;
inline ElfStatus validation_status = ElfStatus::Ok;

void ResetParser()
{
    segments = {};
    segment_count = 0;
    entry_point = 0x400080;
    validation_status = ElfStatus::Ok;
}

void AddSegment(u64 file_offset, u64 vaddr, u64 filesz, u64 memsz, u8 flags)
{
    EXPECT_TRUE(segment_count < segments.size());
    if (segment_count >= segments.size())
        return;
    segments[segment_count++] = ElfSegment{file_offset, vaddr, filesz, memsz, 4096, flags, {}};
}

} // namespace fixture

namespace duetos::core
{

ElfStatus ElfValidate(const u8*, u64)
{
    return fixture::validation_status;
}

u64 ElfEntry(const u8*)
{
    return fixture::entry_point;
}

u32 ElfForEachPtLoad(const u8*, u64, ElfSegmentCb callback, void* cookie)
{
    if (callback == nullptr)
        return 0;
    for (u32 index = 0; index < fixture::segment_count; ++index)
        callback(fixture::segments[index], cookie);
    return fixture::segment_count;
}

const char* ElfStatusName(ElfStatus)
{
    return "fake";
}

void ElfProgramHeaderInfo(const u8*, u64*, u16*, u16*) {}

} // namespace duetos::core

namespace
{

using duetos::u32;
using duetos::u64;
using duetos::u8;
using namespace duetos::loader;

constexpr u32 kPageCapacity = 8;
constexpr u32 kFrameCapacity = 16;
constexpr u64 kMemoryObject = 0x5356430000000001ULL;

struct FakeFrame
{
    LoadImageFrame id;
    std::array<u8, kLoadPlanPageSize> bytes;
    bool live;
    u32 releases;
};

struct FakeArena
{
    std::array<FakeFrame, kFrameCapacity> frames;
    u32 count;
    u32 live;
    u32 release_count;
    u32 fail_at_attempt;
};

bool AllocateFrame(void* raw, LoadImageFrame* frame_out, u8** bytes_out)
{
    auto& arena = *static_cast<FakeArena*>(raw);
    const u32 attempt = arena.count;
    if (attempt == arena.fail_at_attempt || attempt >= arena.frames.size())
        return false;
    FakeFrame& frame = arena.frames[arena.count++];
    frame = FakeFrame{static_cast<LoadImageFrame>(arena.count), {}, true, 0};
    ++arena.live;
    *frame_out = frame.id;
    *bytes_out = frame.bytes.data();
    return true;
}

void ReleaseFrame(void* raw, LoadImageFrame id)
{
    auto& arena = *static_cast<FakeArena*>(raw);
    EXPECT_TRUE(id != kLoadImageInvalidFrame);
    EXPECT_TRUE(id <= arena.count);
    if (id == kLoadImageInvalidFrame || id > arena.count)
        return;
    FakeFrame& frame = arena.frames[static_cast<u32>(id - 1u)];
    EXPECT_TRUE(frame.live);
    if (!frame.live)
        return;
    frame.live = false;
    ++frame.releases;
    --arena.live;
    ++arena.release_count;
}

struct Fixture
{
    std::array<u8, 512> source{};
    FakeArena arena{};
    LoadImage image{};
    std::array<LoadImagePage, kPageCapacity> pages{};
    std::array<LoadImageRegionAuthority, kPageCapacity> regions{};
    std::array<u8, kLoadImageMaxPlanBytes> plan{};

    Fixture()
    {
        fixture::ResetParser();
        arena.fail_at_attempt = 0xFFFFFFFFu;
        for (u32 index = 0; index < source.size(); ++index)
            source[index] = static_cast<u8>((index * 17u + 3u) & 0xFFu);
    }

    Hash256 SourceHash() const
    {
        Hash256 hash{};
        duetos::crypto::Sha256Hash(source.data(), static_cast<u32>(source.size()), hash.bytes);
        return hash;
    }

    ElfLoadImageRequest Request() const
    {
        return ElfLoadImageRequest{source.data(),
                                   source.size(),
                                   SourceHash(),
                                   kMemoryObject,
                                   LoadImageFrameHooks{const_cast<FakeArena*>(&arena), &AllocateFrame, &ReleaseFrame},
                                   const_cast<LoadImagePage*>(pages.data()),
                                   static_cast<u32>(pages.size()),
                                   const_cast<LoadImageRegionAuthority*>(regions.data()),
                                   static_cast<u32>(regions.size()),
                                   const_cast<u8*>(plan.data()),
                                   static_cast<u32>(plan.size())};
    }
};

void AddValidRxSegment()
{
    fixture::AddSegment(64, 0x400080, 32, 128, duetos::core::kElfPfR | duetos::core::kElfPfX);
}

enum class HostilePreflightCase : u8
{
    FileRange,
    FileLargerThanMemory,
    VirtualAddressOverflow,
    SegmentSpan,
    SparseImageExtent,
    SegmentCount,
};

void ExpectHostilePreflightRejected(HostilePreflightCase test_case, ElfLoadImageStatus expected)
{
    Fixture f;
    switch (test_case)
    {
    case HostilePreflightCase::FileRange:
        fixture::AddSegment(500, 0x400000, 32, 32, duetos::core::kElfPfR | duetos::core::kElfPfX);
        fixture::entry_point = 0x400000;
        break;
    case HostilePreflightCase::FileLargerThanMemory:
        fixture::AddSegment(64, 0x400000, 1, 0, duetos::core::kElfPfR | duetos::core::kElfPfX);
        fixture::entry_point = 0x400000;
        break;
    case HostilePreflightCase::VirtualAddressOverflow:
        fixture::AddSegment(0, ~u64{0} - 0x1000u, 0, 0x2000, duetos::core::kElfPfR | duetos::core::kElfPfX);
        fixture::entry_point = ~u64{0} - 0x1000u;
        break;
    case HostilePreflightCase::SegmentSpan:
        fixture::AddSegment(0, 0x400000, 0, kElfLoadImageMaximumSegmentSpanBytes + 1u,
                            duetos::core::kElfPfR | duetos::core::kElfPfX);
        fixture::entry_point = 0x400000;
        break;
    case HostilePreflightCase::SparseImageExtent:
        fixture::AddSegment(64, 0x400000, 16, 16, duetos::core::kElfPfR | duetos::core::kElfPfX);
        fixture::AddSegment(96, 0x40400000, 16, 16, duetos::core::kElfPfR);
        fixture::entry_point = 0x400000;
        break;
    case HostilePreflightCase::SegmentCount:
        for (u32 index = 0; index <= kLoadPlanMaxRegions; ++index)
            fixture::AddSegment(64, 0x400000, 1, 1, duetos::core::kElfPfR | duetos::core::kElfPfX);
        fixture::entry_point = 0x400000;
        break;
    }

    EXPECT_EQ(ElfLoadImagePrepare(f.Request(), &f.image).status, expected);
    EXPECT_EQ(f.arena.count, 0u);
}

} // namespace

int main()
{
    {
        Fixture f;
        AddValidRxSegment();
        const ElfLoadImageResult result = ElfLoadImagePrepare(f.Request(), &f.image);
        EXPECT_EQ(result.status, ElfLoadImageStatus::Ok);
        EXPECT_EQ(result.segment_count, 1u);
        EXPECT_EQ(result.load_base, 0x400000u);
        EXPECT_EQ(result.image_size, kLoadPlanPageSize);
        EXPECT_EQ(result.entry_point, fixture::entry_point);
        EXPECT_EQ(f.arena.live, 1u);
        EXPECT_EQ(f.arena.frames[0].bytes[0x80], f.source[64]);
        EXPECT_EQ(f.arena.frames[0].bytes[0x9F], f.source[95]);
        EXPECT_EQ(f.arena.frames[0].bytes[0xA0], 0u);

        const u8* plan_bytes = nullptr;
        u32 plan_size = 0;
        ASSERT_TRUE(LoadImagePlanBytes(&f.image, &plan_bytes, &plan_size));
        LoadPlanViewV1 view{};
        EXPECT_EQ(LoadPlanValidateV1(plan_bytes, plan_size, &f.image.descriptor.source_hash, &LoadImageBackingQuery,
                                     &f.image, &view),
                  LoadPlanValidationError::Ok);
        EXPECT_EQ(view.header.format, ImageFormat::Elf64);
        EXPECT_EQ(view.header.entry_point, fixture::entry_point);
        EXPECT_EQ(view.header.region_count, 1u);

        const u8 sealed_byte = f.arena.frames[0].bytes[0x80];
        const u8 replacement = static_cast<u8>(sealed_byte ^ 0xFFu);
        EXPECT_EQ(LoadImageCopyIn(&f.image, 0x80, &replacement, 1), LoadImageStatus::WriteAfterSeal);
        EXPECT_EQ(f.arena.frames[0].bytes[0x80], sealed_byte);

        // The plan and staged backing retain the authenticated snapshot even
        // after the caller-owned source buffer is changed.
        f.source[64] ^= 0xFFu;
        EXPECT_EQ(LoadPlanValidateV1(plan_bytes, plan_size, &f.image.descriptor.source_hash, &LoadImageBackingQuery,
                                     &f.image, nullptr),
                  LoadPlanValidationError::Ok);
        EXPECT_EQ(f.arena.frames[0].bytes[0x80], sealed_byte);
        LoadImageRelease(&f.image);
        EXPECT_EQ(f.arena.live, 0u);
        EXPECT_EQ(f.arena.release_count, 1u);
    }

    {
        Fixture f;
        AddValidRxSegment();
        ElfLoadImageRequest request = f.Request();
        request.expected_source_hash.bytes[0] ^= 0x80u;
        EXPECT_EQ(ElfLoadImagePrepare(request, &f.image).status, ElfLoadImageStatus::SourceHashMismatch);
        EXPECT_EQ(f.arena.count, 0u);
    }

    {
        Fixture f;
        fixture::validation_status = duetos::core::ElfStatus::BadMagic;
        const ElfLoadImageResult result = ElfLoadImagePrepare(f.Request(), &f.image);
        EXPECT_EQ(result.status, ElfLoadImageStatus::ElfRejected);
        EXPECT_EQ(result.elf_status, duetos::core::ElfStatus::BadMagic);
        EXPECT_EQ(f.arena.count, 0u);
    }

    {
        Fixture f;
        fixture::AddSegment(64, 0x400000, 16, 16, duetos::core::kElfPfW | duetos::core::kElfPfX);
        EXPECT_EQ(ElfLoadImagePrepare(f.Request(), &f.image).status, ElfLoadImageStatus::WritableExecutable);
        EXPECT_EQ(f.arena.count, 0u);
    }

    {
        Fixture f;
        AddValidRxSegment();
        fixture::entry_point = 0x401000;
        EXPECT_EQ(ElfLoadImagePrepare(f.Request(), &f.image).status, ElfLoadImageStatus::EntryNotExecutable);
        EXPECT_EQ(f.arena.count, 0u);
    }

    {
        Fixture f;
        fixture::AddSegment(64, 0x400000, 16, 0x800, duetos::core::kElfPfR | duetos::core::kElfPfX);
        fixture::AddSegment(96, 0x400800, 16, 0x800, duetos::core::kElfPfR | duetos::core::kElfPfW);
        fixture::entry_point = 0x400000;
        const ElfLoadImageResult result = ElfLoadImagePrepare(f.Request(), &f.image);
        EXPECT_EQ(result.status, ElfLoadImageStatus::LoadImageRejected);
        EXPECT_EQ(result.load_image_status, LoadImageStatus::WritableExecutableConflict);
        EXPECT_EQ(f.arena.live, 0u);
        EXPECT_EQ(f.arena.release_count, 1u);
    }

    {
        Fixture f;
        fixture::AddSegment(64, 0x400000, 16, 16, duetos::core::kElfPfR | duetos::core::kElfPfX);
        fixture::AddSegment(96, 0x402000, 16, 16, duetos::core::kElfPfR);
        fixture::entry_point = 0x400000;
        f.arena.fail_at_attempt = 1;
        const ElfLoadImageResult result = ElfLoadImagePrepare(f.Request(), &f.image);
        EXPECT_EQ(result.status, ElfLoadImageStatus::LoadImageRejected);
        EXPECT_EQ(result.load_image_status, LoadImageStatus::FrameAllocationFailed);
        EXPECT_EQ(f.arena.live, 0u);
        EXPECT_EQ(f.arena.release_count, 1u);
    }

    {
        Fixture f;
        fixture::AddSegment(64, 0, 16, 16, duetos::core::kElfPfR | duetos::core::kElfPfX);
        fixture::entry_point = 0;
        EXPECT_EQ(ElfLoadImagePrepare(f.Request(), &f.image).status, ElfLoadImageStatus::RangeOutOfBounds);
    }

    ExpectHostilePreflightRejected(HostilePreflightCase::FileRange, ElfLoadImageStatus::InvalidSegment);
    ExpectHostilePreflightRejected(HostilePreflightCase::FileLargerThanMemory, ElfLoadImageStatus::InvalidSegment);
    ExpectHostilePreflightRejected(HostilePreflightCase::VirtualAddressOverflow, ElfLoadImageStatus::RangeOutOfBounds);
    ExpectHostilePreflightRejected(HostilePreflightCase::SegmentSpan, ElfLoadImageStatus::RangeOutOfBounds);
    ExpectHostilePreflightRejected(HostilePreflightCase::SparseImageExtent, ElfLoadImageStatus::RangeOutOfBounds);
    ExpectHostilePreflightRejected(HostilePreflightCase::SegmentCount, ElfLoadImageStatus::TooManySegments);

    {
        Fixture f;
        EXPECT_EQ(ElfLoadImagePrepare(f.Request(), &f.image).status, ElfLoadImageStatus::NoLoadSegments);
    }

    EXPECT_STREQ(ElfLoadImageStatusName(ElfLoadImageStatus::Ok), "ok");
    EXPECT_STREQ(ElfLoadImageStatusName(ElfLoadImageStatus::LoadImageRejected), "load-image-rejected");
    EXPECT_STREQ(ElfLoadImageStatusName(static_cast<ElfLoadImageStatus>(0xFF)), "unknown");
    return duetos_host_test::finish_main("test_elf_load_image");
}
