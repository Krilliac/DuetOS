// Hosted hostile-boundary coverage for loader/load_plan.{h,cpp}.
//
// The input is the future execd -> kernel trust boundary. Tests build the
// little-endian blob byte-by-byte (including an unaligned transport case) so
// native compiler layout can never accidentally make a malformed plan pass.

#include "host_test_helper.h"
#include "loader/load_plan.h"

#include <array>
#include <vector>

namespace
{

using duetos::u16;
using duetos::u32;
using duetos::u64;
using duetos::u8;
using namespace duetos::loader;

constexpr u32 kHeaderBytes = kLoadPlanV1HeaderBytes;
constexpr u32 kRegionBytes = kLoadRegionV1Bytes;
constexpr u32 kValidRegionCount = 2;
constexpr u32 kValidPlanBytes = kHeaderBytes + kValidRegionCount * kRegionBytes;

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
    for (u32 i = 0; i < 32; ++i)
        hash.bytes[i] = static_cast<u8>(seed + i);
    return hash;
}

void WriteHash(u8* bytes, const Hash256& hash)
{
    for (u32 i = 0; i < 32; ++i)
        bytes[i] = hash.bytes[i];
}

u8* RegionBytes(ValidBlob& blob, u32 index)
{
    return blob.data() + kHeaderBytes + index * kRegionBytes;
}

void WriteRegion(ValidBlob& blob, u32 index, u64 va, u64 length, ObjectHandle object, u64 object_offset, u32 protection,
                 const Hash256& hash)
{
    u8* region = RegionBytes(blob, index);
    WriteLe64(region + kRegionVirtualAddress, va);
    WriteLe64(region + kRegionLength, length);
    WriteLe64(region + kRegionMemoryObject, object);
    WriteLe64(region + kRegionObjectOffset, object_offset);
    WriteLe32(region + kRegionProtection, protection);
    WriteHash(region + kRegionContentHash, hash);
    WriteLe32(region + kRegionReserved, 0);
}

ValidBlob MakeValidBlob()
{
    ValidBlob blob{};
    WriteLe32(blob.data() + kHeaderSize, kValidPlanBytes);
    WriteLe16(blob.data() + kHeaderVersion, kLoadPlanVersion1);
    WriteLe16(blob.data() + kHeaderFormat, static_cast<u16>(ImageFormat::Pe32Plus));
    WriteLe64(blob.data() + kHeaderEntry, 0x400100);
    WriteLe64(blob.data() + kHeaderPreferredBase, 0x400000);
    WriteLe32(blob.data() + kHeaderRegionCount, kValidRegionCount);
    WriteLe32(blob.data() + kHeaderDependencyCount, 0);
    WriteHash(blob.data() + kHeaderSourceHash, MakeHash(0x10));

    WriteRegion(blob, 0, 0x400000, 0x2000, 0x101, 0,
                static_cast<u32>(VmProtection::Read) | static_cast<u32>(VmProtection::Execute), MakeHash(0x30));
    WriteRegion(blob, 1, 0x500000, 0x1000, 0x101, 0x2000,
                static_cast<u32>(VmProtection::Read) | static_cast<u32>(VmProtection::Write), MakeHash(0x60));
    return blob;
}

struct BackingRecord
{
    ObjectHandle handle;
    u64 offset;
    u64 size;
    u8 sealed;
    Hash256 slice_hash;
};

struct BackingRegistry
{
    BackingRecord records[2];
    Hash256 source_hash;
    u32 query_count;
};

BackingRegistry MakeRegistry()
{
    return BackingRegistry{
        {{0x101, 0, 0x4000, 1, MakeHash(0x30)}, {0x101, 0x2000, 0x4000, 0, MakeHash(0x60)}}, MakeHash(0x10), 0};
}

bool QueryBacking(ObjectHandle handle, u64 offset, u64, LoadBackingInfoV1* out, void* context)
{
    if (out == nullptr || context == nullptr)
        return false;
    auto* registry = static_cast<BackingRegistry*>(context);
    ++registry->query_count;
    const BackingRecord* fallback = nullptr;
    for (const BackingRecord& record : registry->records)
    {
        if (record.handle != handle)
            continue;
        if (fallback == nullptr)
            fallback = &record;
        if (record.offset != offset)
            continue;
        *out = LoadBackingInfoV1{};
        out->object_size = record.size;
        out->sealed = record.sealed;
        out->slice_hash = record.slice_hash;
        return true;
    }
    if (fallback == nullptr)
        return false;
    *out = LoadBackingInfoV1{};
    out->object_size = fallback->size;
    out->sealed = fallback->sealed;
    out->slice_hash = fallback->slice_hash;
    return true;
}

bool QueryBackingWithInvalidSeal(ObjectHandle handle, u64 offset, u64 length, LoadBackingInfoV1* out, void* context)
{
    if (!QueryBacking(handle, offset, length, out, context))
        return false;
    out->sealed = 2;
    return true;
}

bool QueryBackingWithReservedByte(ObjectHandle handle, u64 offset, u64 length, LoadBackingInfoV1* out, void* context)
{
    if (!QueryBacking(handle, offset, length, out, context))
        return false;
    out->reserved[6] = 1;
    return true;
}

LoadPlanValidationError Validate(const ValidBlob& blob, BackingRegistry& registry, LoadPlanViewV1* view = nullptr)
{
    return LoadPlanValidateV1(blob.data(), static_cast<u64>(blob.size()), &registry.source_hash, &QueryBacking,
                              &registry, view);
}

void ExpectRejected(const ValidBlob& blob, BackingRegistry& registry, LoadPlanValidationError expected)
{
    LoadPlanViewV1 view{};
    view.bytes = reinterpret_cast<const u8*>(static_cast<duetos::uptr>(1));
    view.size = 0xFFFFFFFFu;
    view.header.region_count = 0xFFFFFFFFu;
    EXPECT_EQ(Validate(blob, registry, &view), expected);
    EXPECT_EQ(view.bytes, nullptr);
    EXPECT_EQ(view.size, 0u);
    EXPECT_EQ(view.header.region_count, 0u);
}

} // namespace

int main()
{
    static_assert(sizeof(LoadPlanV1) == 64);
    static_assert(sizeof(LoadRegionV1) == 72);
    static_assert(kLoadPlanMaxMappedPages == 262144);
    static_assert(kLoadPlanMaxMappedBytes == 1024ULL * 1024 * 1024);
    static_assert(kLoadPlanPe32UserMax == 0xFFFFFFFFULL);

    // Happy path and immutable decoding view.
    ValidBlob valid = MakeValidBlob();
    BackingRegistry registry = MakeRegistry();
    LoadPlanViewV1 view{};
    EXPECT_EQ(Validate(valid, registry, &view), LoadPlanValidationError::Ok);
    EXPECT_EQ(view.bytes, valid.data());
    EXPECT_EQ(view.size, kValidPlanBytes);
    EXPECT_EQ(view.header.version, kLoadPlanVersion1);
    EXPECT_EQ(view.header.format, ImageFormat::Pe32Plus);
    EXPECT_EQ(view.header.region_count, kValidRegionCount);
    LoadRegionV1 decoded{};
    EXPECT_TRUE(LoadPlanRegionAt(view, 0, &decoded));
    EXPECT_EQ(decoded.virtual_address, 0x400000ULL);
    EXPECT_EQ(decoded.length, 0x2000ULL);
    EXPECT_EQ(decoded.memory_object, 0x101ULL);
    EXPECT_FALSE(LoadPlanRegionAt(view, kValidRegionCount, &decoded));
    EXPECT_FALSE(LoadPlanRegionAt(view, 0, nullptr));
    EXPECT_FALSE(LoadPlanRegionAt(LoadPlanViewV1{}, 0, &decoded));
    {
        LoadPlanViewV1 corrupt_view = view;
        corrupt_view.header.version = 0;
        EXPECT_FALSE(LoadPlanRegionAt(corrupt_view, 0, &decoded));
        corrupt_view = view;
        corrupt_view.header.size -= 1u;
        EXPECT_FALSE(LoadPlanRegionAt(corrupt_view, 0, &decoded));
        corrupt_view = view;
        corrupt_view.header.region_count = kLoadPlanMaxRegions + 1u;
        EXPECT_FALSE(LoadPlanRegionAt(corrupt_view, 0, &decoded));
    }

    // Wire reads must tolerate an unaligned copied-in transport buffer.
    {
        std::array<u8, kValidPlanBytes + 1> storage{};
        for (u32 i = 0; i < kValidPlanBytes; ++i)
            storage[i + 1] = valid[i];
        LoadPlanViewV1 unaligned_view{};
        EXPECT_EQ(LoadPlanValidateV1(storage.data() + 1, kValidPlanBytes, &registry.source_hash, &QueryBacking,
                                     &registry, &unaligned_view),
                  LoadPlanValidationError::Ok);
        EXPECT_TRUE(LoadPlanRegionAt(unaligned_view, 1, &decoded));
        EXPECT_EQ(decoded.virtual_address, 0x500000ULL);
    }

    // Framing, version, format, dependency and count boundaries.
    EXPECT_EQ(LoadPlanValidateV1(nullptr, kValidPlanBytes, &registry.source_hash, &QueryBacking, &registry, nullptr),
              LoadPlanValidationError::NullBuffer);
    EXPECT_EQ(
        LoadPlanValidateV1(valid.data(), kHeaderBytes - 1, &registry.source_hash, &QueryBacking, &registry, nullptr),
        LoadPlanValidationError::HeaderTruncated);
    EXPECT_EQ(
        LoadPlanValidateV1(valid.data(), 0x100000000ULL, &registry.source_hash, &QueryBacking, &registry, nullptr),
        LoadPlanValidationError::SizeOverflow);
    {
        ValidBlob blob = valid;
        WriteLe16(blob.data() + kHeaderVersion, 0);
        ExpectRejected(blob, registry, LoadPlanValidationError::UnsupportedVersion);
        WriteLe16(blob.data() + kHeaderVersion, kLoadPlanVersion1 + 1u);
        ExpectRejected(blob, registry, LoadPlanValidationError::UnsupportedVersion);
    }
    {
        for (u16 format : {static_cast<u16>(0), static_cast<u16>(4), static_cast<u16>(0xFFFF)})
        {
            ValidBlob blob = valid;
            WriteLe16(blob.data() + kHeaderFormat, format);
            ExpectRejected(blob, registry, LoadPlanValidationError::UnsupportedFormat);
        }
        for (ImageFormat format : {ImageFormat::Pe32Plus, ImageFormat::Pe32, ImageFormat::Elf64})
        {
            ValidBlob blob = valid;
            WriteLe16(blob.data() + kHeaderFormat, static_cast<u16>(format));
            EXPECT_EQ(Validate(blob, registry), LoadPlanValidationError::Ok);
        }
    }
    {
        ValidBlob blob = valid;
        WriteLe32(blob.data() + kHeaderDependencyCount, 1);
        ExpectRejected(blob, registry, LoadPlanValidationError::DependenciesUnsupported);
        WriteLe32(blob.data() + kHeaderDependencyCount, 0xFFFFFFFFu);
        ExpectRejected(blob, registry, LoadPlanValidationError::DependenciesUnsupported);
    }
    {
        ValidBlob blob = valid;
        WriteLe32(blob.data() + kHeaderRegionCount, 0);
        ExpectRejected(blob, registry, LoadPlanValidationError::NoRegions);
    }
    {
        constexpr u32 kFirstOverflowingCount = (0xFFFFFFFFu - kHeaderBytes) / kRegionBytes + 1u;
        ValidBlob blob = valid;
        WriteLe32(blob.data() + kHeaderRegionCount, kFirstOverflowingCount);
        ExpectRejected(blob, registry, LoadPlanValidationError::SizeOverflow);
        WriteLe32(blob.data() + kHeaderRegionCount, 0xFFFFFFFFu);
        ExpectRejected(blob, registry, LoadPlanValidationError::SizeOverflow);
    }
    {
        const u32 count = kLoadPlanMaxRegions + 1u;
        const u32 size = kHeaderBytes + count * kRegionBytes;
        std::vector<u8> blob(size, 0);
        WriteLe32(blob.data() + kHeaderSize, size);
        WriteLe16(blob.data() + kHeaderVersion, kLoadPlanVersion1);
        WriteLe16(blob.data() + kHeaderFormat, static_cast<u16>(ImageFormat::Elf64));
        WriteLe32(blob.data() + kHeaderRegionCount, count);
        EXPECT_EQ(
            LoadPlanValidateV1(blob.data(), blob.size(), &registry.source_hash, &QueryBacking, &registry, nullptr),
            LoadPlanValidationError::TooManyRegions);
    }
    {
        ValidBlob blob = valid;
        WriteLe32(blob.data() + kHeaderSize, kValidPlanBytes - 1u);
        ExpectRejected(blob, registry, LoadPlanValidationError::SizeMismatch);
        WriteLe32(blob.data() + kHeaderSize, kValidPlanBytes + 1u);
        ExpectRejected(blob, registry, LoadPlanValidationError::SizeMismatch);
        EXPECT_EQ(LoadPlanValidateV1(valid.data(), kValidPlanBytes - 1u, &registry.source_hash, &QueryBacking,
                                     &registry, nullptr),
                  LoadPlanValidationError::SizeMismatch);
        std::array<u8, kValidPlanBytes + 1> trailing{};
        for (u32 i = 0; i < kValidPlanBytes; ++i)
            trailing[i] = valid[i];
        EXPECT_EQ(LoadPlanValidateV1(trailing.data(), trailing.size(), &registry.source_hash, &QueryBacking, &registry,
                                     nullptr),
                  LoadPlanValidationError::SizeMismatch);
    }

    // Header integrity and preferred-base boundaries.
    {
        ValidBlob blob = valid;
        for (u32 i = 0; i < 32; ++i)
            blob[kHeaderSourceHash + i] = 0;
        ExpectRejected(blob, registry, LoadPlanValidationError::MissingSourceHash);
    }
    {
        const u32 queries_before = registry.query_count;
        EXPECT_EQ(LoadPlanValidateV1(valid.data(), valid.size(), nullptr, &QueryBacking, &registry, nullptr),
                  LoadPlanValidationError::SourceHashAuthorityRequired);
        EXPECT_EQ(registry.query_count, queries_before);

        Hash256 wrong_source_hash = registry.source_hash;
        wrong_source_hash.bytes[31] ^= 0x80;
        EXPECT_EQ(LoadPlanValidateV1(valid.data(), valid.size(), &wrong_source_hash, &QueryBacking, &registry, nullptr),
                  LoadPlanValidationError::SourceHashMismatch);
        EXPECT_EQ(registry.query_count, queries_before);
    }
    {
        ValidBlob blob = valid;
        WriteLe64(blob.data() + kHeaderPreferredBase, 0);
        EXPECT_EQ(Validate(blob, registry), LoadPlanValidationError::Ok);
        WriteLe64(blob.data() + kHeaderPreferredBase, 0x400001);
        ExpectRejected(blob, registry, LoadPlanValidationError::InvalidPreferredBase);
        WriteLe64(blob.data() + kHeaderPreferredBase, 0x0000800000000000ULL);
        ExpectRejected(blob, registry, LoadPlanValidationError::InvalidPreferredBase);
    }
    {
        ValidBlob pe32 = valid;
        WriteLe16(pe32.data() + kHeaderFormat, static_cast<u16>(ImageFormat::Pe32));
        WriteLe64(pe32.data() + kHeaderPreferredBase, 0x100000000ULL);
        ExpectRejected(pe32, registry, LoadPlanValidationError::InvalidPreferredBase);

        pe32 = valid;
        WriteLe16(pe32.data() + kHeaderFormat, static_cast<u16>(ImageFormat::Pe32));
        WriteLe64(RegionBytes(pe32, 0) + kRegionVirtualAddress, 0xFFFFE000ULL);
        WriteLe64(pe32.data() + kHeaderEntry, 0xFFFFE000ULL);
        EXPECT_EQ(Validate(pe32, registry), LoadPlanValidationError::Ok);

        WriteLe64(RegionBytes(pe32, 0) + kRegionVirtualAddress, 0xFFFFF000ULL);
        WriteLe64(pe32.data() + kHeaderEntry, 0xFFFFF000ULL);
        ExpectRejected(pe32, registry, LoadPlanValidationError::AddressOutOfRange);
    }

    // Region structural boundaries.
    {
        ValidBlob blob = valid;
        WriteLe32(RegionBytes(blob, 0) + kRegionReserved, 1);
        ExpectRejected(blob, registry, LoadPlanValidationError::ReservedNonZero);
    }
    {
        // A malformed final record must fail before the valid first record can
        // trigger any object lookup or exact-slice hash work.
        ValidBlob blob = valid;
        WriteLe32(RegionBytes(blob, 1) + kRegionReserved, 1);
        const u32 queries_before = registry.query_count;
        ExpectRejected(blob, registry, LoadPlanValidationError::ReservedNonZero);
        EXPECT_EQ(registry.query_count, queries_before);
    }
    {
        for (u32 protection : {0u, 8u, 0xFFFFFFFFu})
        {
            ValidBlob blob = valid;
            WriteLe32(RegionBytes(blob, 0) + kRegionProtection, protection);
            ExpectRejected(blob, registry, LoadPlanValidationError::InvalidProtection);
        }
    }
    {
        ValidBlob blob = valid;
        WriteLe64(RegionBytes(blob, 0) + kRegionLength, 0);
        ExpectRejected(blob, registry, LoadPlanValidationError::EmptyRegion);
    }
    {
        ValidBlob blob = valid;
        WriteLe64(RegionBytes(blob, 0) + kRegionVirtualAddress, 0x400001);
        ExpectRejected(blob, registry, LoadPlanValidationError::UnalignedRegion);
        blob = valid;
        WriteLe64(RegionBytes(blob, 0) + kRegionLength, 0x2001);
        ExpectRejected(blob, registry, LoadPlanValidationError::UnalignedRegion);
        blob = valid;
        WriteLe64(RegionBytes(blob, 0) + kRegionObjectOffset, 1);
        ExpectRejected(blob, registry, LoadPlanValidationError::UnalignedRegion);
    }
    {
        ValidBlob blob = valid;
        WriteLe64(RegionBytes(blob, 0) + kRegionVirtualAddress, 0xFFFFFFFFFFFFF000ULL);
        WriteLe64(RegionBytes(blob, 0) + kRegionLength, 0x2000);
        ExpectRejected(blob, registry, LoadPlanValidationError::AddressOverflow);
    }
    {
        for (u64 address : {0ULL, 0x0000800000000000ULL, 0xFFFF800000000000ULL})
        {
            ValidBlob blob = valid;
            WriteLe64(RegionBytes(blob, 0) + kRegionVirtualAddress, address);
            ExpectRejected(blob, registry, LoadPlanValidationError::AddressOutOfRange);
        }
        ValidBlob crossing = valid;
        WriteLe64(RegionBytes(crossing, 0) + kRegionVirtualAddress, 0x00007FFFFFFFF000ULL);
        WriteLe64(RegionBytes(crossing, 0) + kRegionLength, 0x2000);
        ExpectRejected(crossing, registry, LoadPlanValidationError::AddressOutOfRange);
    }
    {
        ValidBlob blob = valid;
        WriteLe64(RegionBytes(blob, 0) + kRegionMemoryObject, 0);
        ExpectRejected(blob, registry, LoadPlanValidationError::NullMemoryObject);
    }
    {
        ValidBlob blob = valid;
        WriteLe64(RegionBytes(blob, 0) + kRegionObjectOffset, 0xFFFFFFFFFFFFF000ULL);
        WriteLe64(RegionBytes(blob, 0) + kRegionLength, 0x2000);
        ExpectRejected(blob, registry, LoadPlanValidationError::BackingOffsetOverflow);
    }
    {
        // Exactly 262,144 pages (1 GiB) is the frozen v1 ceiling.
        ValidBlob blob = valid;
        BackingRegistry maximum = registry;
        const u64 first_length = kLoadPlanMaxMappedBytes - kLoadPlanPageSize;
        WriteLe64(RegionBytes(blob, 0) + kRegionLength, first_length);
        WriteLe64(RegionBytes(blob, 1) + kRegionVirtualAddress, 0x50000000ULL);
        WriteLe64(RegionBytes(blob, 1) + kRegionLength, kLoadPlanPageSize);
        WriteLe64(RegionBytes(blob, 1) + kRegionObjectOffset, first_length);
        maximum.records[0].size = kLoadPlanMaxMappedBytes;
        maximum.records[1].offset = first_length;
        maximum.records[1].size = kLoadPlanMaxMappedBytes;
        EXPECT_EQ(Validate(blob, maximum), LoadPlanValidationError::Ok);
    }
    {
        // One page over the ceiling fails before either backing is queried.
        ValidBlob blob = valid;
        WriteLe64(RegionBytes(blob, 0) + kRegionLength, kLoadPlanMaxMappedBytes);
        const u32 queries_before = registry.query_count;
        ExpectRejected(blob, registry, LoadPlanValidationError::TooManyMappedBytes);
        EXPECT_EQ(registry.query_count, queries_before);
    }
    {
        // The checked aggregate addition is independently fail-closed even
        // though each individual aligned length fits in u64.
        ValidBlob blob = valid;
        WriteLe64(RegionBytes(blob, 0) + kRegionLength, 0x8000000000000000ULL);
        WriteLe64(RegionBytes(blob, 1) + kRegionLength, 0x8000000000000000ULL);
        const u32 queries_before = registry.query_count;
        ExpectRejected(blob, registry, LoadPlanValidationError::MappedBytesOverflow);
        EXPECT_EQ(registry.query_count, queries_before);
    }
    {
        ValidBlob blob = valid;
        for (u32 i = 0; i < 32; ++i)
            RegionBytes(blob, 0)[kRegionContentHash + i] = 0;
        ExpectRejected(blob, registry, LoadPlanValidationError::MissingContentHash);
    }
    {
        ValidBlob blob = valid;
        WriteLe32(RegionBytes(blob, 0) + kRegionProtection,
                  static_cast<u32>(VmProtection::Write) | static_cast<u32>(VmProtection::Execute));
        ExpectRejected(blob, registry, LoadPlanValidationError::WritableExecutable);
    }

    // Half-open overlap boundaries: every actual overlap is rejected;
    // touching endpoints and arbitrary non-overlapping order are accepted.
    for (u64 second_va : {0x400000ULL, 0x401000ULL})
    {
        ValidBlob blob = valid;
        WriteLe64(RegionBytes(blob, 1) + kRegionVirtualAddress, second_va);
        const u32 queries_before = registry.query_count;
        ExpectRejected(blob, registry, LoadPlanValidationError::RegionOverlap);
        EXPECT_EQ(registry.query_count, queries_before);
    }
    {
        ValidBlob overlaps_from_below = valid;
        WriteLe64(RegionBytes(overlaps_from_below, 1) + kRegionVirtualAddress, 0x3FF000);
        WriteLe64(RegionBytes(overlaps_from_below, 1) + kRegionLength, 0x2000);
        ExpectRejected(overlaps_from_below, registry, LoadPlanValidationError::RegionOverlap);

        ValidBlob contains = valid;
        WriteLe64(RegionBytes(contains, 1) + kRegionVirtualAddress, 0x3FF000);
        WriteLe64(RegionBytes(contains, 1) + kRegionLength, 0x4000);
        ExpectRejected(contains, registry, LoadPlanValidationError::RegionOverlap);

        ValidBlob touches_before = valid;
        WriteLe64(RegionBytes(touches_before, 1) + kRegionVirtualAddress, 0x3FF000);
        EXPECT_EQ(Validate(touches_before, registry), LoadPlanValidationError::Ok);

        ValidBlob touching = valid;
        WriteLe64(RegionBytes(touching, 1) + kRegionVirtualAddress, 0x402000);
        EXPECT_EQ(Validate(touching, registry), LoadPlanValidationError::Ok);

        ValidBlob unsorted = valid;
        WriteLe64(RegionBytes(unsorted, 0) + kRegionVirtualAddress, 0x500000);
        WriteLe64(RegionBytes(unsorted, 1) + kRegionVirtualAddress, 0x400000);
        WriteLe64(unsorted.data() + kHeaderEntry, 0x500000);
        EXPECT_EQ(Validate(unsorted, registry), LoadPlanValidationError::Ok);
    }

    // The same backing bytes may not be mapped through disjoint VAs, even
    // when each individual region obeys W^X. All failures are structural and
    // therefore occur before the backing authority is queried.
    {
        ValidBlob writable_executable_alias = valid;
        WriteLe64(RegionBytes(writable_executable_alias, 1) + kRegionObjectOffset, 0);
        const u32 queries_before = registry.query_count;
        ExpectRejected(writable_executable_alias, registry, LoadPlanValidationError::BackingRegionOverlap);
        EXPECT_EQ(registry.query_count, queries_before);
    }
    {
        ValidBlob same_protection_alias = valid;
        WriteLe32(RegionBytes(same_protection_alias, 1) + kRegionProtection,
                  static_cast<u32>(VmProtection::Read) | static_cast<u32>(VmProtection::Execute));
        WriteLe64(RegionBytes(same_protection_alias, 1) + kRegionObjectOffset, 0x1000);
        const u32 queries_before = registry.query_count;
        ExpectRejected(same_protection_alias, registry, LoadPlanValidationError::BackingRegionOverlap);
        EXPECT_EQ(registry.query_count, queries_before);
    }
    {
        ValidBlob multiple_objects = valid;
        WriteLe64(RegionBytes(multiple_objects, 1) + kRegionMemoryObject, 0x202);
        const u32 queries_before = registry.query_count;
        ExpectRejected(multiple_objects, registry, LoadPlanValidationError::MultipleMemoryObjects);
        EXPECT_EQ(registry.query_count, queries_before);
    }
    {
        const u32 queries_before = registry.query_count;
        EXPECT_EQ(Validate(valid, registry), LoadPlanValidationError::Ok);
        EXPECT_EQ(registry.query_count, queries_before + kValidRegionCount);
    }

    // Trusted backing authority: existence, extent, sealing and hash are
    // all out-of-band facts, never accepted from the untrusted blob.
    EXPECT_EQ(LoadPlanValidateV1(valid.data(), valid.size(), &registry.source_hash, nullptr, nullptr, nullptr),
              LoadPlanValidationError::BackingQueryRequired);
    {
        ValidBlob blob = valid;
        WriteLe64(RegionBytes(blob, 0) + kRegionMemoryObject, 0x999);
        WriteLe64(RegionBytes(blob, 1) + kRegionMemoryObject, 0x999);
        ExpectRejected(blob, registry, LoadPlanValidationError::BackingNotFound);
    }
    {
        BackingRegistry short_backing = registry;
        short_backing.records[0].size = 0x1000;
        ExpectRejected(valid, short_backing, LoadPlanValidationError::BackingRangeOutOfBounds);
    }
    {
        ValidBlob exact_end = valid;
        BackingRegistry exact_registry = registry;
        WriteLe64(RegionBytes(exact_end, 0) + kRegionLength, 0x1000);
        WriteLe64(RegionBytes(exact_end, 0) + kRegionObjectOffset, 0x3000);
        exact_registry.records[0].offset = 0x3000;
        EXPECT_EQ(Validate(exact_end, exact_registry), LoadPlanValidationError::Ok);

        ValidBlob one_page_past = valid;
        WriteLe64(RegionBytes(one_page_past, 0) + kRegionObjectOffset, 0x3000);
        ExpectRejected(one_page_past, registry, LoadPlanValidationError::BackingRangeOutOfBounds);
    }
    {
        BackingRegistry mutable_code = registry;
        mutable_code.records[0].sealed = 0;
        ExpectRejected(valid, mutable_code, LoadPlanValidationError::MutableExecutableBacking);
    }
    {
        // Writable/NX data is allowed to remain mutable.
        BackingRegistry mutable_data = registry;
        mutable_data.records[1].sealed = 0;
        EXPECT_EQ(Validate(valid, mutable_data), LoadPlanValidationError::Ok);
    }
    {
        BackingRegistry wrong_hash = registry;
        wrong_hash.records[0].slice_hash.bytes[31] ^= 0x80;
        ExpectRejected(valid, wrong_hash, LoadPlanValidationError::ContentHashMismatch);
    }
    {
        BackingRegistry malformed_authority = registry;
        EXPECT_EQ(LoadPlanValidateV1(valid.data(), valid.size(), &malformed_authority.source_hash,
                                     &QueryBackingWithInvalidSeal, &malformed_authority, nullptr),
                  LoadPlanValidationError::InvalidBackingAuthority);
        malformed_authority = registry;
        EXPECT_EQ(LoadPlanValidateV1(valid.data(), valid.size(), &malformed_authority.source_hash,
                                     &QueryBackingWithReservedByte, &malformed_authority, nullptr),
                  LoadPlanValidationError::InvalidBackingAuthority);
    }

    // Entry-point half-open boundaries and execute-only membership.
    struct EntryCase
    {
        u64 entry;
        bool accepted;
    };
    for (const EntryCase& entry_case :
         {EntryCase{0x3FFFFFULL, false}, EntryCase{0x400000ULL, true}, EntryCase{0x400001ULL, true},
          EntryCase{0x401FFFULL, true}, EntryCase{0x402000ULL, false}, EntryCase{0x500000ULL, false}})
    {
        ValidBlob blob = valid;
        WriteLe64(blob.data() + kHeaderEntry, entry_case.entry);
        const LoadPlanValidationError result = Validate(blob, registry);
        if (entry_case.accepted)
            EXPECT_EQ(result, LoadPlanValidationError::Ok);
        else
            EXPECT_EQ(result, LoadPlanValidationError::EntryOutsideExecutableRegion);
    }

    EXPECT_STREQ(LoadPlanValidationErrorName(LoadPlanValidationError::Ok), "ok");
    EXPECT_STREQ(LoadPlanValidationErrorName(LoadPlanValidationError::RegionOverlap), "region-overlap");
    EXPECT_STREQ(LoadPlanValidationErrorName(LoadPlanValidationError::SourceHashMismatch), "source-hash-mismatch");
    EXPECT_STREQ(LoadPlanValidationErrorName(LoadPlanValidationError::MappedBytesOverflow), "mapped-bytes-overflow");
    EXPECT_STREQ(LoadPlanValidationErrorName(LoadPlanValidationError::TooManyMappedBytes), "too-many-mapped-bytes");
    EXPECT_STREQ(LoadPlanValidationErrorName(LoadPlanValidationError::MultipleMemoryObjects),
                 "multiple-memory-objects");
    EXPECT_STREQ(LoadPlanValidationErrorName(LoadPlanValidationError::BackingRegionOverlap), "backing-region-overlap");
    EXPECT_STREQ(LoadPlanValidationErrorName(LoadPlanValidationError::MutableExecutableBacking),
                 "mutable-executable-backing");
    EXPECT_STREQ(LoadPlanValidationErrorName(LoadPlanValidationError::InvalidBackingAuthority),
                 "invalid-backing-authority");
    EXPECT_STREQ(LoadPlanValidationErrorName(static_cast<LoadPlanValidationError>(0xFF)), "unknown");

    return duetos_host_test::finish_main("test_load_plan");
}
