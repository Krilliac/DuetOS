#include "loader/elf_load_image.h"

#include "crypto/sha256.h"

namespace duetos::loader
{

namespace
{

constexpr u64 kPageMask = kLoadPlanPageSize - 1u;

bool CheckedAdd(u64 left, u64 right, u64* result)
{
    if (result == nullptr || right > ~u64{0} - left)
        return false;
    *result = left + right;
    return true;
}

bool HashIsZero(const Hash256& hash)
{
    u8 aggregate = 0;
    for (u32 index = 0; index < sizeof(hash.bytes); ++index)
        aggregate |= hash.bytes[index];
    return aggregate == 0;
}

bool HashEqual(const Hash256& left, const Hash256& right)
{
    u8 difference = 0;
    for (u32 index = 0; index < sizeof(left.bytes); ++index)
        difference |= left.bytes[index] ^ right.bytes[index];
    return difference == 0;
}

VmProtection SegmentProtection(const core::ElfSegment& segment)
{
    // x86 user pages are inherently readable. Record that truth even when a
    // hostile ELF omits PF_R, then add the two independently enforceable bits.
    u32 bits = static_cast<u32>(VmProtection::Read);
    if ((segment.flags & core::kElfPfW) != 0)
        bits |= static_cast<u32>(VmProtection::Write);
    if ((segment.flags & core::kElfPfX) != 0)
        bits |= static_cast<u32>(VmProtection::Execute);
    return static_cast<VmProtection>(bits);
}

struct BoundsContext
{
    u64 byte_count;
    u64 entry_point;
    u64 load_base;
    u64 image_end;
    u32 segment_count;
    bool entry_executable;
    ElfLoadImageStatus failure;
};

void InspectSegment(const core::ElfSegment& segment, void* cookie)
{
    auto& context = *static_cast<BoundsContext*>(cookie);
    if (context.failure != ElfLoadImageStatus::Ok)
        return;
    if (context.segment_count == kLoadPlanMaxRegions)
    {
        context.failure = ElfLoadImageStatus::TooManySegments;
        return;
    }
    ++context.segment_count;

    if (segment.filesz > segment.memsz || segment.file_offset > context.byte_count ||
        segment.filesz > context.byte_count - segment.file_offset)
    {
        context.failure = ElfLoadImageStatus::InvalidSegment;
        return;
    }
    if (segment.memsz == 0)
        return;
    if ((segment.flags & core::kElfPfW) != 0 && (segment.flags & core::kElfPfX) != 0)
    {
        context.failure = ElfLoadImageStatus::WritableExecutable;
        return;
    }

    u64 segment_end = 0;
    if (!CheckedAdd(segment.vaddr, segment.memsz, &segment_end) || segment_end <= segment.vaddr)
    {
        context.failure = ElfLoadImageStatus::RangeOutOfBounds;
        return;
    }
    u64 rounded_end = 0;
    if (!CheckedAdd(segment_end, kPageMask, &rounded_end))
    {
        context.failure = ElfLoadImageStatus::RangeOutOfBounds;
        return;
    }
    const u64 page_start = segment.vaddr & ~kPageMask;
    const u64 page_end = rounded_end & ~kPageMask;
    if (page_start < kLoadPlanUserMin || page_end <= page_start ||
        page_end - page_start > kElfLoadImageMaximumSegmentSpanBytes || page_end - 1u > kLoadPlanUserMax)
    {
        context.failure = ElfLoadImageStatus::RangeOutOfBounds;
        return;
    }

    if (context.load_base == 0 || page_start < context.load_base)
        context.load_base = page_start;
    if (page_end > context.image_end)
        context.image_end = page_end;
    if ((segment.flags & core::kElfPfX) != 0 && context.entry_point >= segment.vaddr &&
        context.entry_point < segment_end)
        context.entry_executable = true;
}

struct StageContext
{
    const ElfLoadImageRequest* request;
    LoadImage* image;
    u64 load_base;
    LoadImageStatus failure;
};

void StageSegment(const core::ElfSegment& segment, void* cookie)
{
    auto& context = *static_cast<StageContext*>(cookie);
    if (context.failure != LoadImageStatus::Ok || segment.memsz == 0)
        return;

    u64 segment_end = 0;
    u64 rounded_end = 0;
    if (!CheckedAdd(segment.vaddr, segment.memsz, &segment_end) || !CheckedAdd(segment_end, kPageMask, &rounded_end))
    {
        context.failure = LoadImageStatus::RangeOutOfBounds;
        return;
    }
    const u64 page_start = segment.vaddr & ~kPageMask;
    const u64 page_end = rounded_end & ~kPageMask;
    context.failure = LoadImageClaimRange(context.image, page_start - context.load_base, page_end - page_start,
                                          SegmentProtection(segment));
    if (context.failure != LoadImageStatus::Ok || segment.filesz == 0)
        return;
    context.failure = LoadImageCopyIn(context.image, segment.vaddr - context.load_base,
                                      context.request->bytes + segment.file_offset, segment.filesz);
}

ElfLoadImageResult Result(ElfLoadImageStatus status, core::ElfStatus elf_status = core::ElfStatus::Ok,
                          LoadImageStatus image_status = LoadImageStatus::Ok, u32 segment_count = 0, u64 load_base = 0,
                          u64 image_size = 0, u64 entry_point = 0)
{
    return ElfLoadImageResult{status, elf_status, image_status, segment_count, load_base, image_size, entry_point};
}

} // namespace

ElfLoadImageResult ElfLoadImagePrepare(const ElfLoadImageRequest& request, LoadImage* image)
{
    if (image == nullptr || request.bytes == nullptr || request.byte_count == 0 ||
        request.byte_count > kElfLoadImageMaximumSourceBytes || request.byte_count > 0xFFFFFFFFULL ||
        request.memory_object == 0 || HashIsZero(request.expected_source_hash) || request.page_storage == nullptr ||
        request.region_storage == nullptr || request.plan_storage == nullptr ||
        request.frame_hooks.allocate_frame == nullptr || request.frame_hooks.release_frame == nullptr)
        return Result(ElfLoadImageStatus::InvalidArgument);

    const core::ElfStatus elf_status = core::ElfValidate(request.bytes, request.byte_count);
    if (elf_status != core::ElfStatus::Ok)
        return Result(ElfLoadImageStatus::ElfRejected, elf_status);

    Hash256 observed_hash{};
    crypto::Sha256Hash(request.bytes, static_cast<u32>(request.byte_count), observed_hash.bytes);
    if (!HashEqual(observed_hash, request.expected_source_hash))
        return Result(ElfLoadImageStatus::SourceHashMismatch);

    const u64 entry_point = core::ElfEntry(request.bytes);
    BoundsContext bounds{request.byte_count, entry_point, 0, 0, 0, false, ElfLoadImageStatus::Ok};
    const u32 visited = core::ElfForEachPtLoad(request.bytes, request.byte_count, &InspectSegment, &bounds);
    if (bounds.failure != ElfLoadImageStatus::Ok)
        return Result(bounds.failure, elf_status, LoadImageStatus::Ok, bounds.segment_count, bounds.load_base,
                      bounds.image_end > bounds.load_base ? bounds.image_end - bounds.load_base : 0, entry_point);
    if (visited == 0 || bounds.segment_count == 0 || bounds.load_base == 0 || bounds.image_end <= bounds.load_base)
        return Result(ElfLoadImageStatus::NoLoadSegments, elf_status);
    if (!bounds.entry_executable)
        return Result(ElfLoadImageStatus::EntryNotExecutable, elf_status, LoadImageStatus::Ok, bounds.segment_count,
                      bounds.load_base, bounds.image_end - bounds.load_base, entry_point);

    const u64 image_size = bounds.image_end - bounds.load_base;
    if (image_size > kLoadPlanMaxMappedBytes)
        return Result(ElfLoadImageStatus::RangeOutOfBounds, elf_status, LoadImageStatus::Ok, bounds.segment_count,
                      bounds.load_base, image_size, entry_point);

    const LoadImageDescriptor descriptor{ImageFormat::Elf64, bounds.load_base,      bounds.load_base, entry_point,
                                         image_size,         request.memory_object, observed_hash};
    LoadImageStatus image_status = LoadImageInitialize(
        image, descriptor, request.frame_hooks, request.page_storage, request.page_storage_count,
        request.region_storage, request.region_storage_count, request.plan_storage, request.plan_storage_bytes);
    if (image_status != LoadImageStatus::Ok)
        return Result(ElfLoadImageStatus::LoadImageRejected, elf_status, image_status, bounds.segment_count,
                      bounds.load_base, image_size, entry_point);

    StageContext stage{&request, image, bounds.load_base, LoadImageStatus::Ok};
    (void)core::ElfForEachPtLoad(request.bytes, request.byte_count, &StageSegment, &stage);
    if (stage.failure != LoadImageStatus::Ok)
    {
        LoadImageRelease(image);
        return Result(ElfLoadImageStatus::LoadImageRejected, elf_status, stage.failure, bounds.segment_count,
                      bounds.load_base, image_size, entry_point);
    }

    image_status = LoadImageSeal(image);
    if (image_status != LoadImageStatus::Ok)
    {
        LoadImageRelease(image);
        return Result(ElfLoadImageStatus::LoadImageRejected, elf_status, image_status, bounds.segment_count,
                      bounds.load_base, image_size, entry_point);
    }
    return Result(ElfLoadImageStatus::Ok, elf_status, LoadImageStatus::Ok, bounds.segment_count, bounds.load_base,
                  image_size, entry_point);
}

const char* ElfLoadImageStatusName(ElfLoadImageStatus status)
{
    switch (status)
    {
    case ElfLoadImageStatus::Ok:
        return "ok";
    case ElfLoadImageStatus::InvalidArgument:
        return "invalid-argument";
    case ElfLoadImageStatus::SourceHashMismatch:
        return "source-hash-mismatch";
    case ElfLoadImageStatus::ElfRejected:
        return "elf-rejected";
    case ElfLoadImageStatus::NoLoadSegments:
        return "no-load-segments";
    case ElfLoadImageStatus::TooManySegments:
        return "too-many-segments";
    case ElfLoadImageStatus::InvalidSegment:
        return "invalid-segment";
    case ElfLoadImageStatus::RangeOutOfBounds:
        return "range-out-of-bounds";
    case ElfLoadImageStatus::WritableExecutable:
        return "writable-executable";
    case ElfLoadImageStatus::EntryNotExecutable:
        return "entry-not-executable";
    case ElfLoadImageStatus::LoadImageRejected:
        return "load-image-rejected";
    }
    return "unknown";
}

} // namespace duetos::loader
