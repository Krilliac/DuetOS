/*
 * DuetOS immutable executable load plan, v1 validator.
 *
 * Deliberately self-contained: this translation unit has no allocator, VM,
 * process, or object-manager dependency. The eventual syscall/admission layer
 * supplies the narrow backing query that resolves and pins memory objects.
 */

#include "loader/load_plan.h"

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

void ReadHash(const u8* bytes, Hash256* out)
{
    for (u32 i = 0; i < 32; ++i)
        out->bytes[i] = bytes[i];
}

bool HashIsZero(const Hash256& hash)
{
    u8 aggregate = 0;
    for (u32 i = 0; i < 32; ++i)
        aggregate |= hash.bytes[i];
    return aggregate == 0;
}

bool HashEqual(const Hash256& lhs, const Hash256& rhs)
{
    // Accumulate every byte rather than returning on the first mismatch.
    // The hashes are public integrity metadata, but a fixed comparison shape
    // also keeps the helper suitable if a later policy authenticates them.
    u8 difference = 0;
    for (u32 i = 0; i < 32; ++i)
        difference |= static_cast<u8>(lhs.bytes[i] ^ rhs.bytes[i]);
    return difference == 0;
}

bool CheckedAdd(u64 lhs, u64 rhs, u64* out)
{
    if (out == nullptr || rhs > static_cast<u64>(-1) - lhs)
        return false;
    *out = lhs + rhs;
    return true;
}

bool IsPageAligned(u64 value)
{
    return (value & (kLoadPlanPageSize - 1u)) == 0;
}

bool IsSupportedFormat(ImageFormat format)
{
    return format == ImageFormat::Pe32Plus || format == ImageFormat::Pe32 || format == ImageFormat::Elf64;
}

void DecodeHeader(const u8* bytes, LoadPlanV1* out)
{
    *out = LoadPlanV1{};
    out->size = ReadLe32(bytes + kHeaderSizeOffset);
    out->version = ReadLe16(bytes + kHeaderVersionOffset);
    out->format = static_cast<ImageFormat>(ReadLe16(bytes + kHeaderFormatOffset));
    out->entry_point = ReadLe64(bytes + kHeaderEntryOffset);
    out->preferred_base = ReadLe64(bytes + kHeaderPreferredBaseOffset);
    out->region_count = ReadLe32(bytes + kHeaderRegionCountOffset);
    out->dependency_count = ReadLe32(bytes + kHeaderDependencyCountOffset);
    ReadHash(bytes + kHeaderSourceHashOffset, &out->source_hash);
}

void DecodeRegion(const u8* bytes, LoadRegionV1* out)
{
    *out = LoadRegionV1{};
    out->virtual_address = ReadLe64(bytes + kRegionVirtualAddressOffset);
    out->length = ReadLe64(bytes + kRegionLengthOffset);
    out->memory_object = ReadLe64(bytes + kRegionMemoryObjectOffset);
    out->object_offset = ReadLe64(bytes + kRegionObjectOffsetOffset);
    out->protection = static_cast<VmProtection>(ReadLe32(bytes + kRegionProtectionOffset));
    ReadHash(bytes + kRegionContentHashOffset, &out->content_hash);
    out->reserved = ReadLe32(bytes + kRegionReservedOffset);
}

void ClearView(LoadPlanViewV1* view)
{
    if (view != nullptr)
        *view = LoadPlanViewV1{};
}

} // namespace

const char* LoadPlanValidationErrorName(LoadPlanValidationError error)
{
    switch (error)
    {
    case LoadPlanValidationError::Ok:
        return "ok";
    case LoadPlanValidationError::NullBuffer:
        return "null-buffer";
    case LoadPlanValidationError::HeaderTruncated:
        return "header-truncated";
    case LoadPlanValidationError::SizeOverflow:
        return "size-overflow";
    case LoadPlanValidationError::SizeMismatch:
        return "size-mismatch";
    case LoadPlanValidationError::UnsupportedVersion:
        return "unsupported-version";
    case LoadPlanValidationError::UnsupportedFormat:
        return "unsupported-format";
    case LoadPlanValidationError::DependenciesUnsupported:
        return "dependencies-unsupported";
    case LoadPlanValidationError::NoRegions:
        return "no-regions";
    case LoadPlanValidationError::TooManyRegions:
        return "too-many-regions";
    case LoadPlanValidationError::MissingSourceHash:
        return "missing-source-hash";
    case LoadPlanValidationError::SourceHashAuthorityRequired:
        return "source-hash-authority-required";
    case LoadPlanValidationError::SourceHashMismatch:
        return "source-hash-mismatch";
    case LoadPlanValidationError::InvalidPreferredBase:
        return "invalid-preferred-base";
    case LoadPlanValidationError::ReservedNonZero:
        return "reserved-nonzero";
    case LoadPlanValidationError::InvalidProtection:
        return "invalid-protection";
    case LoadPlanValidationError::EmptyRegion:
        return "empty-region";
    case LoadPlanValidationError::UnalignedRegion:
        return "unaligned-region";
    case LoadPlanValidationError::MappedBytesOverflow:
        return "mapped-bytes-overflow";
    case LoadPlanValidationError::TooManyMappedBytes:
        return "too-many-mapped-bytes";
    case LoadPlanValidationError::AddressOverflow:
        return "address-overflow";
    case LoadPlanValidationError::AddressOutOfRange:
        return "address-out-of-range";
    case LoadPlanValidationError::NullMemoryObject:
        return "null-memory-object";
    case LoadPlanValidationError::BackingOffsetOverflow:
        return "backing-offset-overflow";
    case LoadPlanValidationError::MissingContentHash:
        return "missing-content-hash";
    case LoadPlanValidationError::WritableExecutable:
        return "writable-executable";
    case LoadPlanValidationError::RegionOverlap:
        return "region-overlap";
    case LoadPlanValidationError::BackingQueryRequired:
        return "backing-query-required";
    case LoadPlanValidationError::BackingNotFound:
        return "backing-not-found";
    case LoadPlanValidationError::BackingRangeOutOfBounds:
        return "backing-range-out-of-bounds";
    case LoadPlanValidationError::ContentHashMismatch:
        return "content-hash-mismatch";
    case LoadPlanValidationError::MutableExecutableBacking:
        return "mutable-executable-backing";
    case LoadPlanValidationError::EntryOutsideExecutableRegion:
        return "entry-outside-executable-region";
    case LoadPlanValidationError::MultipleMemoryObjects:
        return "multiple-memory-objects";
    case LoadPlanValidationError::BackingRegionOverlap:
        return "backing-region-overlap";
    case LoadPlanValidationError::InvalidBackingAuthority:
        return "invalid-backing-authority";
    }
    return "unknown";
}

bool LoadPlanRegionAt(const LoadPlanViewV1& view, u32 index, LoadRegionV1* out_region)
{
    if (out_region == nullptr || view.bytes == nullptr || view.header.version != kLoadPlanVersion1 ||
        view.header.region_count == 0 || view.header.region_count > kLoadPlanMaxRegions ||
        view.header.region_count > (0xFFFFFFFFu - kLoadPlanV1HeaderBytes) / kLoadRegionV1Bytes)
        return false;

    const u32 expected_size = kLoadPlanV1HeaderBytes + static_cast<u32>(view.header.region_count * kLoadRegionV1Bytes);
    if (view.header.size != expected_size || view.size != expected_size || index >= view.header.region_count)
        return false;

    const u64 offset = static_cast<u64>(kLoadPlanV1HeaderBytes) + static_cast<u64>(index) * kLoadRegionV1Bytes;
    u64 end = 0;
    if (!CheckedAdd(offset, kLoadRegionV1Bytes, &end) || end > view.size)
        return false;
    DecodeRegion(view.bytes + offset, out_region);
    return true;
}

LoadPlanValidationError LoadPlanValidateV1(const void* bytes_void, u64 byte_count, const Hash256* expected_source_hash,
                                           LoadBackingQueryV1 query_backing, void* query_context,
                                           LoadPlanViewV1* out_view)
{
    ClearView(out_view);
    if (bytes_void == nullptr)
        return LoadPlanValidationError::NullBuffer;
    if (byte_count < kLoadPlanV1HeaderBytes)
        return LoadPlanValidationError::HeaderTruncated;
    if (byte_count > 0xFFFFFFFFULL)
        return LoadPlanValidationError::SizeOverflow;

    const auto* bytes = static_cast<const u8*>(bytes_void);
    LoadPlanV1 header{};
    DecodeHeader(bytes, &header);

    if (header.version != kLoadPlanVersion1)
        return LoadPlanValidationError::UnsupportedVersion;
    if (!IsSupportedFormat(header.format))
        return LoadPlanValidationError::UnsupportedFormat;
    if (header.dependency_count != 0)
        return LoadPlanValidationError::DependenciesUnsupported;
    if (header.region_count == 0)
        return LoadPlanValidationError::NoRegions;

    constexpr u32 kMaxRegionCountForU32Size = (0xFFFFFFFFu - kLoadPlanV1HeaderBytes) / kLoadRegionV1Bytes;
    if (header.region_count > kMaxRegionCountForU32Size)
        return LoadPlanValidationError::SizeOverflow;
    const u32 expected_size = kLoadPlanV1HeaderBytes + static_cast<u32>(header.region_count * kLoadRegionV1Bytes);
    if (header.size != expected_size || byte_count != expected_size)
        return LoadPlanValidationError::SizeMismatch;
    if (header.region_count > kLoadPlanMaxRegions)
        return LoadPlanValidationError::TooManyRegions;
    if (HashIsZero(header.source_hash))
        return LoadPlanValidationError::MissingSourceHash;
    if (expected_source_hash == nullptr)
        return LoadPlanValidationError::SourceHashAuthorityRequired;
    if (!HashEqual(header.source_hash, *expected_source_hash))
        return LoadPlanValidationError::SourceHashMismatch;
    if (header.preferred_base != 0 &&
        (!IsPageAligned(header.preferred_base) || header.preferred_base < kLoadPlanUserMin ||
         header.preferred_base > kLoadPlanUserMax ||
         (header.format == ImageFormat::Pe32 && header.preferred_base > kLoadPlanPe32UserMax)))
        return LoadPlanValidationError::InvalidPreferredBase;

    // Structural pass 1: validate every record's local shape and compute the
    // aggregate work bound before consulting any backing authority. Delaying
    // the ceiling comparison until after the checked sum makes arithmetic
    // overflow independently observable instead of hiding it behind the cap.
    u64 total_mapped_bytes = 0;
    ObjectHandle primary_memory_object = 0;
    for (u32 index = 0; index < header.region_count; ++index)
    {
        LoadRegionV1 region{};
        const u64 region_offset =
            static_cast<u64>(kLoadPlanV1HeaderBytes) + static_cast<u64>(index) * kLoadRegionV1Bytes;
        DecodeRegion(bytes + region_offset, &region);

        if (region.reserved != 0)
            return LoadPlanValidationError::ReservedNonZero;

        const u32 protection = static_cast<u32>(region.protection);
        if (protection == 0 || (protection & ~kVmProtectionMask) != 0)
            return LoadPlanValidationError::InvalidProtection;
        if (region.length == 0)
            return LoadPlanValidationError::EmptyRegion;
        if (!IsPageAligned(region.virtual_address) || !IsPageAligned(region.length) ||
            !IsPageAligned(region.object_offset))
            return LoadPlanValidationError::UnalignedRegion;

        if (region.memory_object == 0)
            return LoadPlanValidationError::NullMemoryObject;
        if (index == 0)
            primary_memory_object = region.memory_object;
        else if (region.memory_object != primary_memory_object)
            return LoadPlanValidationError::MultipleMemoryObjects;
        u64 object_end = 0;
        if (!CheckedAdd(region.object_offset, region.length, &object_end))
            return LoadPlanValidationError::BackingOffsetOverflow;
        if (HashIsZero(region.content_hash))
            return LoadPlanValidationError::MissingContentHash;

        const bool writable = (protection & static_cast<u32>(VmProtection::Write)) != 0;
        const bool executable = (protection & static_cast<u32>(VmProtection::Execute)) != 0;
        if (writable && executable)
            return LoadPlanValidationError::WritableExecutable;

        u64 next_total = 0;
        if (!CheckedAdd(total_mapped_bytes, region.length, &next_total))
            return LoadPlanValidationError::MappedBytesOverflow;
        total_mapped_bytes = next_total;
    }
    if (total_mapped_bytes > kLoadPlanMaxMappedBytes ||
        total_mapped_bytes / kLoadPlanPageSize > kLoadPlanMaxMappedPages)
        return LoadPlanValidationError::TooManyMappedBytes;

    // Structural pass 2: validate address arithmetic, all pairwise virtual and
    // backing overlap, and executable-entry membership for the complete record
    // set. No object lookup or hashing may occur until every hostile structural
    // field passes.
    bool entry_is_executable = false;
    for (u32 index = 0; index < header.region_count; ++index)
    {
        LoadRegionV1 region{};
        const u64 region_offset =
            static_cast<u64>(kLoadPlanV1HeaderBytes) + static_cast<u64>(index) * kLoadRegionV1Bytes;
        DecodeRegion(bytes + region_offset, &region);

        u64 virtual_end = 0;
        if (!CheckedAdd(region.virtual_address, region.length, &virtual_end))
            return LoadPlanValidationError::AddressOverflow;
        const u64 format_user_max = header.format == ImageFormat::Pe32 ? kLoadPlanPe32UserMax : kLoadPlanUserMax;
        if (region.virtual_address < kLoadPlanUserMin || virtual_end == 0 || virtual_end - 1u > format_user_max)
            return LoadPlanValidationError::AddressOutOfRange;
        const u64 object_end = region.object_offset + region.length;

        // Pairwise half-open interval check. The hard region cap bounds this
        // allocation-free O(n^2) walk to 32,640 comparisons while allowing
        // parsers to preserve their native section/program-header order.
        for (u32 previous_index = 0; previous_index < index; ++previous_index)
        {
            LoadRegionV1 previous{};
            const u64 previous_offset =
                static_cast<u64>(kLoadPlanV1HeaderBytes) + static_cast<u64>(previous_index) * kLoadRegionV1Bytes;
            DecodeRegion(bytes + previous_offset, &previous);
            const u64 previous_end = previous.virtual_address + previous.length;
            if (region.virtual_address < previous_end && previous.virtual_address < virtual_end)
                return LoadPlanValidationError::RegionOverlap;
            const u64 previous_object_end = previous.object_offset + previous.length;
            if (region.object_offset < previous_object_end && previous.object_offset < object_end)
                return LoadPlanValidationError::BackingRegionOverlap;
        }

        const u32 protection = static_cast<u32>(region.protection);
        const bool executable = (protection & static_cast<u32>(VmProtection::Execute)) != 0;
        if (executable && header.entry_point >= region.virtual_address && header.entry_point < virtual_end)
            entry_is_executable = true;
    }

    if (!entry_is_executable)
        return LoadPlanValidationError::EntryOutsideExecutableRegion;
    if (query_backing == nullptr)
        return LoadPlanValidationError::BackingQueryRequired;

    // Authority pass: only a completely valid, bounded structural plan may
    // resolve objects or request exact-slice hashes. Re-decode from the frozen
    // snapshot so no allocation or attacker-authored pointer is retained.
    for (u32 index = 0; index < header.region_count; ++index)
    {
        LoadRegionV1 region{};
        const u64 region_offset =
            static_cast<u64>(kLoadPlanV1HeaderBytes) + static_cast<u64>(index) * kLoadRegionV1Bytes;
        DecodeRegion(bytes + region_offset, &region);

        // The structural pass already proved this addition cannot wrap.
        const u64 object_end = region.object_offset + region.length;
        const u32 protection = static_cast<u32>(region.protection);
        const bool executable = (protection & static_cast<u32>(VmProtection::Execute)) != 0;
        LoadBackingInfoV1 backing{};
        if (!query_backing(region.memory_object, region.object_offset, region.length, &backing, query_context))
            return LoadPlanValidationError::BackingNotFound;
        u8 reserved_aggregate = 0;
        for (u32 reserved_index = 0; reserved_index < sizeof(backing.reserved); ++reserved_index)
            reserved_aggregate |= backing.reserved[reserved_index];
        if (backing.sealed > 1 || reserved_aggregate != 0)
            return LoadPlanValidationError::InvalidBackingAuthority;
        if (object_end > backing.object_size)
            return LoadPlanValidationError::BackingRangeOutOfBounds;
        if (executable && backing.sealed == 0)
            return LoadPlanValidationError::MutableExecutableBacking;
        if (!HashEqual(region.content_hash, backing.slice_hash))
            return LoadPlanValidationError::ContentHashMismatch;
    }

    if (out_view != nullptr)
    {
        out_view->bytes = bytes;
        out_view->size = expected_size;
        out_view->header = header;
    }
    return LoadPlanValidationError::Ok;
}

} // namespace duetos::loader
