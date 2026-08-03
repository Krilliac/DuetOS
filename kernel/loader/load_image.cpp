/*
 * Loader-private staging package. See load_image.h for ownership contracts.
 */

#include "loader/load_image.h"

#include "crypto/sha256.h"

namespace duetos::loader
{

namespace
{

constexpr u32 kHeaderSizeOffset = 0;
constexpr u32 kHeaderVersionOffset = 4;
constexpr u32 kHeaderFormatOffset = 6;
constexpr u32 kHeaderEntryOffset = 8;
constexpr u32 kHeaderPreferredBaseOffset = 16;
constexpr u32 kHeaderRegionCountOffset = 24;
constexpr u32 kHeaderDependencyCountOffset = 28;
constexpr u32 kHeaderSourceHashOffset = 32;

constexpr u32 kRegionVirtualAddressOffset = 0;
constexpr u32 kRegionLengthOffset = 8;
constexpr u32 kRegionMemoryObjectOffset = 16;
constexpr u32 kRegionObjectOffsetOffset = 24;
constexpr u32 kRegionProtectionOffset = 32;
constexpr u32 kRegionContentHashOffset = 36;
constexpr u32 kRegionReservedOffset = 68;

u32 ProtectionBits(VmProtection protection)
{
    return static_cast<u32>(protection);
}

bool ProtectionIsValid(VmProtection protection)
{
    const u32 bits = ProtectionBits(protection);
    return bits != 0 && (bits & ~kVmProtectionMask) == 0;
}

bool ProtectionIsWritableExecutable(VmProtection protection)
{
    const u32 bits = ProtectionBits(protection);
    return (bits & static_cast<u32>(VmProtection::Write)) != 0 && (bits & static_cast<u32>(VmProtection::Execute)) != 0;
}

VmProtection ProtectionUnion(VmProtection lhs, VmProtection rhs)
{
    return static_cast<VmProtection>(ProtectionBits(lhs) | ProtectionBits(rhs));
}

bool HashIsZero(const Hash256& hash)
{
    u8 aggregate = 0;
    for (u32 i = 0; i < sizeof(hash.bytes); ++i)
        aggregate |= hash.bytes[i];
    return aggregate == 0;
}

bool HashEqual(const Hash256& lhs, const Hash256& rhs)
{
    u8 difference = 0;
    for (u32 i = 0; i < sizeof(lhs.bytes); ++i)
        difference |= static_cast<u8>(lhs.bytes[i] ^ rhs.bytes[i]);
    return difference == 0;
}

bool ImageIsCanonicalZero(const LoadImage& image)
{
    return image.state == LoadImageState::Uninitialized && image.descriptor.format == static_cast<ImageFormat>(0) &&
           image.descriptor.load_base == 0 && image.descriptor.preferred_base == 0 &&
           image.descriptor.entry_point == 0 && image.descriptor.image_size == 0 &&
           image.descriptor.memory_object == 0 && HashIsZero(image.descriptor.source_hash) &&
           image.frame_hooks.context == nullptr && image.frame_hooks.allocate_frame == nullptr &&
           image.frame_hooks.release_frame == nullptr && image.pages == nullptr && image.page_count == 0 &&
           image.page_capacity == 0 && image.regions == nullptr && image.region_count == 0 &&
           image.region_capacity == 0 && image.plan_storage == nullptr && image.plan_size == 0 &&
           image.plan_capacity == 0;
}

bool FormatIsSupported(ImageFormat format)
{
    return format == ImageFormat::Pe32Plus || format == ImageFormat::Pe32 || format == ImageFormat::Elf64;
}

bool IsPageAligned(u64 value)
{
    return (value & (kLoadPlanPageSize - 1u)) == 0;
}

bool CheckedAdd(u64 lhs, u64 rhs, u64* out)
{
    if (out == nullptr || rhs > static_cast<u64>(-1) - lhs)
        return false;
    *out = lhs + rhs;
    return true;
}

bool RangeInImage(const LoadImage& image, u64 rva, u64 length)
{
    return rva <= image.descriptor.image_size && length <= image.descriptor.image_size - rva;
}

bool StateAllowsRead(LoadImageState state)
{
    return state == LoadImageState::Mutable || state == LoadImageState::Sealed;
}

bool IntegerWidthIsValid(u32 width)
{
    return width == 1 || width == 2 || width == 4 || width == 8;
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
    WriteLe32(bytes, static_cast<u32>(value & 0xFFFFFFFFULL));
    WriteLe32(bytes + 4, static_cast<u32>(value >> 32u));
}

void WriteHash(u8* bytes, const Hash256& hash)
{
    for (u32 i = 0; i < sizeof(hash.bytes); ++i)
        bytes[i] = hash.bytes[i];
}

void ClearPage(LoadImagePage* page)
{
    page->frame = kLoadImageInvalidFrame;
    page->writable_page = nullptr;
    page->protection = VmProtection::None;
    page->state = LoadImagePageState::Empty;
    for (u32 i = 0; i < sizeof(page->reserved); ++i)
        page->reserved[i] = 0;
}

void ReleaseOwnedFrames(LoadImage* image)
{
    if (image == nullptr || image->pages == nullptr || image->frame_hooks.release_frame == nullptr)
        return;
    for (u32 index = 0; index < image->page_count; ++index)
    {
        LoadImagePage& page = image->pages[index];
        if (page.state != LoadImagePageState::PackageOwned)
            continue;
        image->frame_hooks.release_frame(image->frame_hooks.context, page.frame);
        page.frame = kLoadImageInvalidFrame;
        page.writable_page = nullptr;
        page.state = LoadImagePageState::Released;
    }
}

bool RangeIsPresent(const LoadImage& image, u64 rva, u64 length)
{
    if (!RangeInImage(image, rva, length))
        return false;
    if (length == 0)
        return true;
    const u64 end = rva + length;
    const u32 first_page = static_cast<u32>(rva / kLoadPlanPageSize);
    const u32 final_page = static_cast<u32>((end - 1u) / kLoadPlanPageSize);
    for (u32 index = first_page; index <= final_page; ++index)
    {
        const LoadImagePageState state = image.pages[index].state;
        if (state != LoadImagePageState::PackageOwned)
            return false;
    }
    return true;
}

void HashRegionPages(const LoadImage& image, u32 first_page, u32 page_count, Hash256* hash_out)
{
    crypto::Sha256Ctx hash{};
    crypto::Sha256Init(hash);
    for (u32 page = 0; page < page_count; ++page)
    {
        const LoadImagePage& row = image.pages[first_page + page];
        crypto::Sha256Update(hash, row.writable_page, static_cast<u32>(kLoadPlanPageSize));
    }
    crypto::Sha256Final(hash, hash_out->bytes);
}

bool RegionSliceHash(const LoadImage& image, const LoadImageRegionAuthority& region, Hash256* hash_out)
{
    if (!IsPageAligned(region.object_offset) || !IsPageAligned(region.length) || region.length == 0)
        return false;
    const u64 first_page_u64 = region.object_offset / kLoadPlanPageSize;
    const u64 page_count_u64 = region.length / kLoadPlanPageSize;
    if (first_page_u64 >= image.page_count || page_count_u64 > image.page_count - first_page_u64)
        return false;
    const u32 first_page = static_cast<u32>(first_page_u64);
    const u32 page_count = static_cast<u32>(page_count_u64);
    for (u32 page = 0; page < page_count; ++page)
    {
        const LoadImagePage& row = image.pages[first_page + page];
        if (row.state != LoadImagePageState::PackageOwned || row.writable_page == nullptr ||
            row.protection != region.protection)
            return false;
    }
    HashRegionPages(image, first_page, page_count, hash_out);
    return true;
}

bool PlanMatchesAuthority(const LoadImage& image, const LoadPlanViewV1& view)
{
    if (view.header.format != image.descriptor.format || view.header.entry_point != image.descriptor.entry_point ||
        view.header.preferred_base != image.descriptor.preferred_base ||
        view.header.region_count != image.region_count ||
        !HashEqual(view.header.source_hash, image.descriptor.source_hash))
        return false;

    for (u32 index = 0; index < image.region_count; ++index)
    {
        LoadRegionV1 plan_region{};
        if (!LoadPlanRegionAt(view, index, &plan_region))
            return false;
        const LoadImageRegionAuthority& authority = image.regions[index];
        if (plan_region.virtual_address != image.descriptor.load_base + authority.object_offset ||
            plan_region.length != authority.length || plan_region.memory_object != image.descriptor.memory_object ||
            plan_region.object_offset != authority.object_offset || plan_region.protection != authority.protection ||
            !HashEqual(plan_region.content_hash, authority.sealed_hash))
            return false;
    }
    return true;
}

void RollBackMappedFrames(LoadImage* image, const LoadImageMapHooks& map_hooks, LoadImageMapResult* result)
{
    for (u32 reverse = image->page_count; reverse > 0; --reverse)
    {
        const u32 index = reverse - 1u;
        LoadImagePage& page = image->pages[index];
        if (page.state != LoadImagePageState::TargetOwned)
            continue;
        const u64 virtual_address = image->descriptor.load_base + static_cast<u64>(index) * kLoadPlanPageSize;
        if (map_hooks.unmap_and_release_frame(map_hooks.context, virtual_address, page.frame))
        {
            page.frame = kLoadImageInvalidFrame;
            page.writable_page = nullptr;
            page.state = LoadImagePageState::Released;
            ++result->pages_rolled_back;
        }
        else
        {
            ++result->rollback_failures;
        }
    }
    ReleaseOwnedFrames(image);
    image->state = LoadImageState::Failed;
    if (result->rollback_failures != 0)
        result->status = LoadImageStatus::RollbackFailed;
}

} // namespace

LoadImageStatus LoadImageInitialize(LoadImage* image, const LoadImageDescriptor& descriptor,
                                    const LoadImageFrameHooks& frame_hooks, LoadImagePage* page_storage,
                                    u32 page_storage_count, LoadImageRegionAuthority* region_storage,
                                    u32 region_storage_count, void* plan_storage, u32 plan_storage_bytes)
{
    if (image == nullptr || page_storage == nullptr || region_storage == nullptr || plan_storage == nullptr ||
        frame_hooks.allocate_frame == nullptr || frame_hooks.release_frame == nullptr || descriptor.image_size == 0 ||
        descriptor.memory_object == 0 || !FormatIsSupported(descriptor.format) || HashIsZero(descriptor.source_hash) ||
        !IsPageAligned(descriptor.load_base) || descriptor.load_base < kLoadPlanUserMin ||
        (descriptor.preferred_base != 0 &&
         (!IsPageAligned(descriptor.preferred_base) || descriptor.preferred_base < kLoadPlanUserMin ||
          descriptor.preferred_base > kLoadPlanUserMax)) ||
        region_storage_count == 0 || plan_storage_bytes < kLoadPlanV1HeaderBytes)
    {
        return LoadImageStatus::InvalidArgument;
    }
    if (image->state != LoadImageState::Uninitialized)
        return LoadImageStatus::InvalidState;
    if (!ImageIsCanonicalZero(*image))
        return LoadImageStatus::CorruptState;

    u64 rounded_size = 0;
    if (!CheckedAdd(descriptor.image_size, kLoadPlanPageSize - 1u, &rounded_size))
        return LoadImageStatus::TooManyPages;
    rounded_size &= ~(kLoadPlanPageSize - 1u);
    const u64 page_count_u64 = rounded_size / kLoadPlanPageSize;
    if (page_count_u64 == 0 || page_count_u64 > kLoadPlanMaxMappedPages)
        return LoadImageStatus::TooManyPages;
    if (page_count_u64 > page_storage_count)
        return LoadImageStatus::PageStorageTooSmall;
    if (descriptor.load_base > kLoadPlanUserMax || rounded_size - 1u > kLoadPlanUserMax - descriptor.load_base)
        return LoadImageStatus::RangeOutOfBounds;
    if (descriptor.entry_point < descriptor.load_base ||
        descriptor.entry_point - descriptor.load_base >= descriptor.image_size)
        return LoadImageStatus::RangeOutOfBounds;

    const u32 page_count = static_cast<u32>(page_count_u64);
    for (u32 index = 0; index < page_count; ++index)
        ClearPage(&page_storage[index]);

    image->descriptor = descriptor;
    image->frame_hooks = frame_hooks;
    image->pages = page_storage;
    image->page_count = page_count;
    image->page_capacity = page_storage_count;
    image->regions = region_storage;
    image->region_count = 0;
    image->region_capacity = region_storage_count;
    image->plan_storage = static_cast<u8*>(plan_storage);
    image->plan_size = 0;
    image->plan_capacity = plan_storage_bytes;
    image->state = LoadImageState::Mutable;
    return LoadImageStatus::Ok;
}

void LoadImageRelease(LoadImage* image)
{
    if (image == nullptr || image->state == LoadImageState::Uninitialized || image->state == LoadImageState::Released)
        return;
    ReleaseOwnedFrames(image);
    bool target_owned = false;
    for (u32 index = 0; image->pages != nullptr && index < image->page_count; ++index)
    {
        if (image->pages[index].state == LoadImagePageState::TargetOwned)
        {
            target_owned = true;
            break;
        }
    }
    if (!target_owned)
        image->state = LoadImageState::Released;
}

LoadImageStatus LoadImageCanResetQuiescent(const LoadImage* image)
{
    if (image == nullptr)
        return LoadImageStatus::InvalidArgument;
    if (image->state == LoadImageState::Uninitialized)
        return ImageIsCanonicalZero(*image) ? LoadImageStatus::Ok : LoadImageStatus::CorruptState;
    if (image->state != LoadImageState::Released && image->state != LoadImageState::Transferred &&
        image->state != LoadImageState::Failed)
    {
        return LoadImageStatus::InvalidState;
    }
    if (image->pages == nullptr || image->page_count == 0 || image->page_count > image->page_capacity ||
        image->page_capacity > kLoadPlanMaxMappedPages || image->regions == nullptr ||
        image->region_count > image->region_capacity || image->region_capacity > kLoadPlanMaxRegions ||
        image->plan_storage == nullptr || image->plan_size > image->plan_capacity ||
        image->plan_capacity < kLoadPlanV1HeaderBytes)
    {
        return LoadImageStatus::CorruptState;
    }

    for (u32 index = 0; index < image->page_count; ++index)
    {
        const LoadImagePage& page = image->pages[index];
        switch (page.state)
        {
        case LoadImagePageState::Empty:
        case LoadImagePageState::Released:
            if (page.frame != kLoadImageInvalidFrame || page.writable_page != nullptr)
                return LoadImageStatus::CorruptState;
            break;
        case LoadImagePageState::PackageOwned:
            return LoadImageStatus::OwnershipOutstanding;
        case LoadImagePageState::TargetOwned:
            if (image->state == LoadImageState::Released || page.frame == kLoadImageInvalidFrame ||
                page.writable_page != nullptr)
            {
                return LoadImageStatus::CorruptState;
            }
            break;
        default:
            return LoadImageStatus::CorruptState;
        }
    }

    return LoadImageStatus::Ok;
}

LoadImageStatus LoadImageResetQuiescent(LoadImage* image)
{
    const LoadImageStatus validation = LoadImageCanResetQuiescent(image);
    if (validation != LoadImageStatus::Ok)
        return validation;
    if (image->state == LoadImageState::Uninitialized)
        return LoadImageStatus::Ok;

    LoadImagePage* const pages = image->pages;
    const u32 page_capacity = image->page_capacity;
    LoadImageRegionAuthority* const regions = image->regions;
    const u32 region_capacity = image->region_capacity;
    u8* const plan_storage = image->plan_storage;
    const u32 plan_capacity = image->plan_capacity;

    for (u32 index = 0; index < page_capacity; ++index)
        ClearPage(&pages[index]);
    for (u32 index = 0; index < region_capacity; ++index)
        regions[index] = LoadImageRegionAuthority{};
    const u32 clear_plan_bytes = plan_capacity < kLoadImageMaxPlanBytes ? plan_capacity : kLoadImageMaxPlanBytes;
    for (u32 index = 0; index < clear_plan_bytes; ++index)
        plan_storage[index] = 0;

    image->descriptor = LoadImageDescriptor{};
    image->frame_hooks = LoadImageFrameHooks{};
    image->pages = nullptr;
    image->page_count = 0;
    image->page_capacity = 0;
    image->regions = nullptr;
    image->region_count = 0;
    image->region_capacity = 0;
    image->plan_storage = nullptr;
    image->plan_size = 0;
    image->plan_capacity = 0;
    image->state = LoadImageState::Uninitialized;
    return LoadImageStatus::Ok;
}

LoadImageStatus LoadImageClaimRange(LoadImage* image, u64 rva, u64 length, VmProtection protection)
{
    if (image == nullptr || length == 0)
        return LoadImageStatus::InvalidArgument;
    if (image->state != LoadImageState::Mutable)
        return image->state == LoadImageState::Sealed ? LoadImageStatus::WriteAfterSeal : LoadImageStatus::InvalidState;
    if (!RangeInImage(*image, rva, length))
        return LoadImageStatus::RangeOutOfBounds;
    if (!ProtectionIsValid(protection))
        return LoadImageStatus::InvalidProtection;
    if (ProtectionIsWritableExecutable(protection))
        return LoadImageStatus::WritableExecutableConflict;

    const u64 end = rva + length;
    const u32 first_page = static_cast<u32>(rva / kLoadPlanPageSize);
    const u32 final_page = static_cast<u32>((end - 1u) / kLoadPlanPageSize);

    // Conflict preflight is deliberately separate: a rejected shared-page
    // claim cannot partially widen earlier pages before the bad page is seen.
    for (u32 index = first_page; index <= final_page; ++index)
    {
        const LoadImagePage& page = image->pages[index];
        if (page.state != LoadImagePageState::Empty && page.state != LoadImagePageState::PackageOwned)
            return LoadImageStatus::CorruptState;
        const VmProtection combined = ProtectionUnion(page.protection, protection);
        if (ProtectionIsWritableExecutable(combined))
            return LoadImageStatus::WritableExecutableConflict;
    }

    for (u32 index = first_page; index <= final_page; ++index)
    {
        LoadImagePage& page = image->pages[index];
        if (page.state == LoadImagePageState::PackageOwned)
            continue;
        LoadImageFrame frame = kLoadImageInvalidFrame;
        u8* writable_page = nullptr;
        const bool allocated = image->frame_hooks.allocate_frame(image->frame_hooks.context, &frame, &writable_page);
        if (!allocated)
        {
            // False publishes no ownership by contract. Output values are
            // unspecified and may be stale sentinels; never release them.
            ReleaseOwnedFrames(image);
            image->state = LoadImageState::Failed;
            return LoadImageStatus::FrameAllocationFailed;
        }
        if (frame == kLoadImageInvalidFrame || writable_page == nullptr)
        {
            // True transferred one frame. Even a malformed alias result must
            // consume that ownership exactly once before failing terminally.
            if (frame != kLoadImageInvalidFrame)
                image->frame_hooks.release_frame(image->frame_hooks.context, frame);
            ReleaseOwnedFrames(image);
            image->state = LoadImageState::Failed;
            return LoadImageStatus::FrameAllocationFailed;
        }
        for (u32 offset = 0; offset < kLoadPlanPageSize; ++offset)
            writable_page[offset] = 0;
        page.frame = frame;
        page.writable_page = writable_page;
        page.state = LoadImagePageState::PackageOwned;
    }

    for (u32 index = first_page; index <= final_page; ++index)
        image->pages[index].protection = ProtectionUnion(image->pages[index].protection, protection);
    return LoadImageStatus::Ok;
}

LoadImageStatus LoadImageCopyIn(LoadImage* image, u64 rva, const void* source, u64 length)
{
    if (image == nullptr || (source == nullptr && length != 0))
        return LoadImageStatus::InvalidArgument;
    if (image->state != LoadImageState::Mutable)
        return image->state == LoadImageState::Sealed ? LoadImageStatus::WriteAfterSeal : LoadImageStatus::InvalidState;
    if (!RangeInImage(*image, rva, length))
        return LoadImageStatus::RangeOutOfBounds;
    if (!RangeIsPresent(*image, rva, length))
        return LoadImageStatus::UnmappedRange;

    const auto* input = static_cast<const u8*>(source);
    u64 copied = 0;
    while (copied < length)
    {
        const u64 current_rva = rva + copied;
        const u32 page_index = static_cast<u32>(current_rva / kLoadPlanPageSize);
        const u32 page_offset = static_cast<u32>(current_rva & (kLoadPlanPageSize - 1u));
        const u64 available = kLoadPlanPageSize - page_offset;
        const u64 chunk = (length - copied < available) ? (length - copied) : available;
        u8* output = image->pages[page_index].writable_page + page_offset;
        for (u64 index = 0; index < chunk; ++index)
            output[index] = input[copied + index];
        copied += chunk;
    }
    return LoadImageStatus::Ok;
}

LoadImageStatus LoadImageCopyOut(const LoadImage* image, u64 rva, void* destination, u64 length)
{
    if (image == nullptr || (destination == nullptr && length != 0))
        return LoadImageStatus::InvalidArgument;
    if (!StateAllowsRead(image->state))
        return LoadImageStatus::InvalidState;
    if (!RangeInImage(*image, rva, length))
        return LoadImageStatus::RangeOutOfBounds;
    if (!RangeIsPresent(*image, rva, length))
        return LoadImageStatus::UnmappedRange;

    auto* output = static_cast<u8*>(destination);
    u64 copied = 0;
    while (copied < length)
    {
        const u64 current_rva = rva + copied;
        const u32 page_index = static_cast<u32>(current_rva / kLoadPlanPageSize);
        const u32 page_offset = static_cast<u32>(current_rva & (kLoadPlanPageSize - 1u));
        const u64 available = kLoadPlanPageSize - page_offset;
        const u64 chunk = (length - copied < available) ? (length - copied) : available;
        const u8* input = image->pages[page_index].writable_page + page_offset;
        for (u64 index = 0; index < chunk; ++index)
            output[copied + index] = input[index];
        copied += chunk;
    }
    return LoadImageStatus::Ok;
}

LoadImageStatus LoadImageReadLe(const LoadImage* image, u64 rva, u32 width, u64* value_out)
{
    if (value_out == nullptr)
        return LoadImageStatus::InvalidArgument;
    if (!IntegerWidthIsValid(width))
        return LoadImageStatus::InvalidIntegerWidth;
    u8 bytes[8]{};
    const LoadImageStatus status = LoadImageCopyOut(image, rva, bytes, width);
    if (status != LoadImageStatus::Ok)
        return status;
    u64 value = 0;
    for (u32 index = 0; index < width; ++index)
        value |= static_cast<u64>(bytes[index]) << (index * 8u);
    *value_out = value;
    return LoadImageStatus::Ok;
}

LoadImageStatus LoadImageWriteLe(LoadImage* image, u64 rva, u32 width, u64 value)
{
    if (!IntegerWidthIsValid(width))
        return LoadImageStatus::InvalidIntegerWidth;
    u8 bytes[8]{};
    for (u32 index = 0; index < width; ++index)
        bytes[index] = static_cast<u8>((value >> (index * 8u)) & 0xFFu);
    return LoadImageCopyIn(image, rva, bytes, width);
}

LoadImageStatus LoadImageSeal(LoadImage* image)
{
    if (image == nullptr)
        return LoadImageStatus::InvalidArgument;
    if (image->state == LoadImageState::Sealed)
        return LoadImageStatus::AlreadySealed;
    if (image->state != LoadImageState::Mutable)
        return LoadImageStatus::InvalidState;

    u32 present_pages = 0;
    u32 region_count = 0;
    for (u32 index = 0; index < image->page_count;)
    {
        const LoadImagePage& page = image->pages[index];
        if (page.state == LoadImagePageState::Empty)
        {
            ++index;
            continue;
        }
        if (page.state != LoadImagePageState::PackageOwned || page.writable_page == nullptr ||
            page.frame == kLoadImageInvalidFrame || !ProtectionIsValid(page.protection) ||
            ProtectionIsWritableExecutable(page.protection))
            return LoadImageStatus::CorruptState;

        const VmProtection protection = page.protection;
        u32 end = index + 1u;
        while (end < image->page_count && image->pages[end].state == LoadImagePageState::PackageOwned &&
               image->pages[end].writable_page != nullptr && image->pages[end].frame != kLoadImageInvalidFrame &&
               image->pages[end].protection == protection)
            ++end;
        present_pages += end - index;
        ++region_count;
        index = end;
    }
    if (present_pages == 0)
        return LoadImageStatus::UnmappedRange;
    if (region_count > kLoadPlanMaxRegions)
        return LoadImageStatus::TooManyRegions;
    if (region_count > image->region_capacity)
        return LoadImageStatus::RegionStorageTooSmall;
    const u32 plan_size = kLoadPlanV1HeaderBytes + region_count * kLoadRegionV1Bytes;
    if (plan_size > image->plan_capacity)
        return LoadImageStatus::PlanStorageTooSmall;

    const u64 entry_rva = image->descriptor.entry_point - image->descriptor.load_base;
    const u32 entry_page = static_cast<u32>(entry_rva / kLoadPlanPageSize);
    if (entry_page >= image->page_count || image->pages[entry_page].state != LoadImagePageState::PackageOwned ||
        (ProtectionBits(image->pages[entry_page].protection) & static_cast<u32>(VmProtection::Execute)) == 0)
        return LoadImageStatus::UnmappedRange;

    u32 authority_index = 0;
    for (u32 index = 0; index < image->page_count;)
    {
        if (image->pages[index].state == LoadImagePageState::Empty)
        {
            ++index;
            continue;
        }
        const VmProtection protection = image->pages[index].protection;
        u32 end = index + 1u;
        while (end < image->page_count && image->pages[end].state == LoadImagePageState::PackageOwned &&
               image->pages[end].protection == protection)
            ++end;

        LoadImageRegionAuthority& authority = image->regions[authority_index];
        authority.object_offset = static_cast<u64>(index) * kLoadPlanPageSize;
        authority.length = static_cast<u64>(end - index) * kLoadPlanPageSize;
        authority.protection = protection;
        HashRegionPages(*image, index, end - index, &authority.sealed_hash);
        ++authority_index;
        index = end;
    }

    u8* plan = image->plan_storage;
    WriteLe32(plan + kHeaderSizeOffset, plan_size);
    WriteLe16(plan + kHeaderVersionOffset, kLoadPlanVersion1);
    WriteLe16(plan + kHeaderFormatOffset, static_cast<u16>(image->descriptor.format));
    WriteLe64(plan + kHeaderEntryOffset, image->descriptor.entry_point);
    WriteLe64(plan + kHeaderPreferredBaseOffset, image->descriptor.preferred_base);
    WriteLe32(plan + kHeaderRegionCountOffset, region_count);
    WriteLe32(plan + kHeaderDependencyCountOffset, 0);
    WriteHash(plan + kHeaderSourceHashOffset, image->descriptor.source_hash);

    for (u32 index = 0; index < region_count; ++index)
    {
        const LoadImageRegionAuthority& authority = image->regions[index];
        u8* region = plan + kLoadPlanV1HeaderBytes + index * kLoadRegionV1Bytes;
        WriteLe64(region + kRegionVirtualAddressOffset, image->descriptor.load_base + authority.object_offset);
        WriteLe64(region + kRegionLengthOffset, authority.length);
        WriteLe64(region + kRegionMemoryObjectOffset, image->descriptor.memory_object);
        WriteLe64(region + kRegionObjectOffsetOffset, authority.object_offset);
        WriteLe32(region + kRegionProtectionOffset, ProtectionBits(authority.protection));
        WriteHash(region + kRegionContentHashOffset, authority.sealed_hash);
        WriteLe32(region + kRegionReservedOffset, 0);
    }

    image->region_count = region_count;
    image->plan_size = plan_size;
    image->state = LoadImageState::Sealed;
    return LoadImageStatus::Ok;
}

bool LoadImagePlanBytes(const LoadImage* image, const u8** bytes_out, u32* size_out)
{
    if (image == nullptr || bytes_out == nullptr || size_out == nullptr || image->plan_size == 0 ||
        image->state == LoadImageState::Uninitialized || image->state == LoadImageState::Mutable ||
        image->state == LoadImageState::Released)
        return false;
    *bytes_out = image->plan_storage;
    *size_out = image->plan_size;
    return true;
}

bool LoadImageBackingQuery(ObjectHandle memory_object, u64 object_offset, u64 length, LoadBackingInfoV1* out_info,
                           void* context)
{
    if (context == nullptr || out_info == nullptr)
        return false;
    auto* image = static_cast<LoadImage*>(context);
    if (image->state != LoadImageState::Sealed || memory_object != image->descriptor.memory_object)
        return false;
    for (u32 index = 0; index < image->region_count; ++index)
    {
        const LoadImageRegionAuthority& region = image->regions[index];
        if (region.object_offset != object_offset || region.length != length)
            continue;
        Hash256 live_hash{};
        if (!RegionSliceHash(*image, region, &live_hash))
            return false;
        LoadBackingInfoV1 info{};
        info.object_size = static_cast<u64>(image->page_count) * kLoadPlanPageSize;
        info.sealed = 1;
        info.slice_hash = live_hash;
        *out_info = info;
        return true;
    }
    return false;
}

LoadImageMapResult LoadImageMapInto(LoadImage* image, const LoadImageMapHooks& map_hooks)
{
    LoadImageMapResult result{LoadImageStatus::InvalidArgument, LoadPlanValidationError::Ok, 0, 0, 0};
    if (image == nullptr || map_hooks.map_owned_frame == nullptr || map_hooks.unmap_and_release_frame == nullptr)
        return result;
    if (image->state != LoadImageState::Sealed)
    {
        result.status = LoadImageStatus::NotSealed;
        return result;
    }

    LoadPlanViewV1 view{};
    result.validation_error = LoadPlanValidateV1(image->plan_storage, image->plan_size, &image->descriptor.source_hash,
                                                 &LoadImageBackingQuery, image, &view);
    if (result.validation_error != LoadPlanValidationError::Ok)
    {
        result.status = LoadImageStatus::PlanRejected;
        ReleaseOwnedFrames(image);
        image->state = LoadImageState::Failed;
        return result;
    }
    if (!PlanMatchesAuthority(*image, view))
    {
        result.status = LoadImageStatus::PlanAuthorityMismatch;
        ReleaseOwnedFrames(image);
        image->state = LoadImageState::Failed;
        return result;
    }

    for (u32 index = 0; index < image->page_count; ++index)
    {
        const LoadImagePage& page = image->pages[index];
        if (page.state != LoadImagePageState::Empty && page.state != LoadImagePageState::PackageOwned)
        {
            result.status = LoadImageStatus::CorruptState;
            ReleaseOwnedFrames(image);
            image->state = LoadImageState::Failed;
            return result;
        }
    }

    image->state = LoadImageState::Mapping;
    result.status = LoadImageStatus::Ok;
    for (u32 region_index = 0; region_index < view.header.region_count; ++region_index)
    {
        LoadRegionV1 region{};
        if (!LoadPlanRegionAt(view, region_index, &region))
        {
            result.status = LoadImageStatus::CorruptState;
            RollBackMappedFrames(image, map_hooks, &result);
            return result;
        }
        const u64 first_page_u64 = region.object_offset / kLoadPlanPageSize;
        const u64 region_pages_u64 = region.length / kLoadPlanPageSize;
        if (first_page_u64 >= image->page_count || region_pages_u64 > image->page_count - first_page_u64)
        {
            result.status = LoadImageStatus::CorruptState;
            RollBackMappedFrames(image, map_hooks, &result);
            return result;
        }
        const u32 first_page = static_cast<u32>(first_page_u64);
        const u32 region_pages = static_cast<u32>(region_pages_u64);
        for (u32 offset = 0; offset < region_pages; ++offset)
        {
            const u32 page_index = first_page + offset;
            LoadImagePage& page = image->pages[page_index];
            if (page.state != LoadImagePageState::PackageOwned || page.frame == kLoadImageInvalidFrame ||
                page.protection != region.protection)
            {
                result.status = LoadImageStatus::CorruptState;
                RollBackMappedFrames(image, map_hooks, &result);
                return result;
            }
            const u64 virtual_address = region.virtual_address + static_cast<u64>(offset) * kLoadPlanPageSize;
            if (!map_hooks.map_owned_frame(map_hooks.context, virtual_address, page.frame, region.protection))
            {
                result.status = LoadImageStatus::MapFailed;
                RollBackMappedFrames(image, map_hooks, &result);
                return result;
            }
            page.state = LoadImagePageState::TargetOwned;
            page.writable_page = nullptr;
            ++result.pages_mapped;
        }
    }

    for (u32 index = 0; index < image->page_count; ++index)
    {
        if (image->pages[index].state == LoadImagePageState::PackageOwned)
        {
            result.status = LoadImageStatus::CorruptState;
            RollBackMappedFrames(image, map_hooks, &result);
            return result;
        }
    }

    image->state = LoadImageState::Transferred;
    return result;
}

LoadImageStatus LoadImageInspect(const LoadImage* image, LoadImageSnapshot* snapshot_out)
{
    if (image == nullptr || snapshot_out == nullptr)
        return LoadImageStatus::InvalidArgument;
    LoadImageSnapshot snapshot{};
    snapshot.state = image->state;
    snapshot.page_count = image->page_count;
    snapshot.region_count = image->region_count;
    snapshot.plan_size = image->plan_size;
    for (u32 index = 0; image->pages != nullptr && index < image->page_count; ++index)
    {
        switch (image->pages[index].state)
        {
        case LoadImagePageState::Empty:
            break;
        case LoadImagePageState::PackageOwned:
            ++snapshot.present_pages;
            ++snapshot.package_owned_pages;
            break;
        case LoadImagePageState::TargetOwned:
            ++snapshot.present_pages;
            ++snapshot.target_owned_pages;
            break;
        case LoadImagePageState::Released:
            ++snapshot.released_pages;
            break;
        }
    }
    *snapshot_out = snapshot;
    return LoadImageStatus::Ok;
}

const char* LoadImageStatusName(LoadImageStatus status)
{
    switch (status)
    {
    case LoadImageStatus::Ok:
        return "ok";
    case LoadImageStatus::InvalidArgument:
        return "invalid-argument";
    case LoadImageStatus::InvalidState:
        return "invalid-state";
    case LoadImageStatus::RangeOutOfBounds:
        return "range-out-of-bounds";
    case LoadImageStatus::InvalidProtection:
        return "invalid-protection";
    case LoadImageStatus::WritableExecutableConflict:
        return "writable-executable-conflict";
    case LoadImageStatus::PageStorageTooSmall:
        return "page-storage-too-small";
    case LoadImageStatus::RegionStorageTooSmall:
        return "region-storage-too-small";
    case LoadImageStatus::PlanStorageTooSmall:
        return "plan-storage-too-small";
    case LoadImageStatus::TooManyPages:
        return "too-many-pages";
    case LoadImageStatus::TooManyRegions:
        return "too-many-regions";
    case LoadImageStatus::FrameAllocationFailed:
        return "frame-allocation-failed";
    case LoadImageStatus::UnmappedRange:
        return "unmapped-range";
    case LoadImageStatus::InvalidIntegerWidth:
        return "invalid-integer-width";
    case LoadImageStatus::WriteAfterSeal:
        return "write-after-seal";
    case LoadImageStatus::AlreadySealed:
        return "already-sealed";
    case LoadImageStatus::NotSealed:
        return "not-sealed";
    case LoadImageStatus::PlanRejected:
        return "plan-rejected";
    case LoadImageStatus::PlanAuthorityMismatch:
        return "plan-authority-mismatch";
    case LoadImageStatus::MapFailed:
        return "map-failed";
    case LoadImageStatus::RollbackFailed:
        return "rollback-failed";
    case LoadImageStatus::CorruptState:
        return "corrupt-state";
    case LoadImageStatus::OwnershipOutstanding:
        return "ownership-outstanding";
    }
    return "unknown";
}

} // namespace duetos::loader
