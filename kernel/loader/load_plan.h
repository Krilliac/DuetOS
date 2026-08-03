#pragma once

#include "util/types.h"

/*
 * DuetOS immutable executable load plan, v1.
 *
 * This is the strangler seam between hostile PE/ELF parsing and the
 * privileged mapper. Today an in-kernel parser can emit this compact blob;
 * later execd can emit the same bytes from an isolated address space without
 * changing process-creation semantics. The validator never allocates, never
 * mutates the blob, owns no global state, and does not trust plan-authored
 * claims about memory-object immutability or content.
 *
 * Wire format (little endian):
 *
 *     LoadPlanV1                 64 bytes
 *     LoadRegionV1[region_count] 72 bytes each
 *
 * `LoadPlanV1::size` is the exact total blob size, not just the header size.
 * V1 deliberately rejects dependency_count != 0 because the architecture
 * decision did not freeze a dependency-record schema. A future version must
 * define that record before accepting dependency payloads.
 *
 * V1 is also deliberately a single-object format: every region must name the
 * same memory-object handle, and its object-offset interval must be disjoint
 * from every other region. This prevents writable and executable virtual
 * aliases of the same backing bytes. A future multi-object version needs an
 * authority-level object-identity rule before relaxing this restriction.
 */

namespace duetos::loader
{

using ObjectHandle = u64;

struct Hash256
{
    u8 bytes[32];
};

enum class ImageFormat : u16
{
    Invalid = 0,
    Pe32Plus = 1,
    Pe32 = 2,
    Elf64 = 3,
};

enum class VmProtection : u32
{
    None = 0,
    Read = 1u << 0,
    Write = 1u << 1,
    Execute = 1u << 2,
};

inline constexpr u32 kVmProtectionMask = static_cast<u32>(VmProtection::Read) | static_cast<u32>(VmProtection::Write) |
                                         static_cast<u32>(VmProtection::Execute);

inline constexpr u16 kLoadPlanVersion1 = 1;
inline constexpr u32 kLoadPlanV1HeaderBytes = 64;
inline constexpr u32 kLoadRegionV1Bytes = 72;
inline constexpr u32 kLoadPlanMaxRegions = 256;
inline constexpr u64 kLoadPlanPageSize = 4096;
inline constexpr u64 kLoadPlanMaxMappedPages = 262144;
inline constexpr u64 kLoadPlanMaxMappedBytes = kLoadPlanMaxMappedPages * kLoadPlanPageSize;
inline constexpr u64 kLoadPlanUserMin = kLoadPlanPageSize;
inline constexpr u64 kLoadPlanUserMax = 0x00007FFFFFFFFFFFULL;
inline constexpr u64 kLoadPlanPe32UserMax = 0x00000000FFFFFFFFULL;
static_assert(kLoadPlanMaxMappedBytes == 1024ULL * 1024 * 1024, "LoadPlan v1 map ceiling changed");

// Native mirror of the frozen 64-byte wire header. Consumers must still use
// LoadPlanValidateV1/LoadPlanRegionAt for untrusted or unaligned input.
struct LoadPlanV1
{
    u32 size;
    u16 version;
    ImageFormat format;
    u64 entry_point;
    u64 preferred_base;
    u32 region_count;
    u32 dependency_count;
    Hash256 source_hash;
};
static_assert(sizeof(LoadPlanV1) == kLoadPlanV1HeaderBytes, "LoadPlanV1 wire size changed");

// Native mirror of the frozen 72-byte region record. `reserved` names the
// four bytes of tail padding implied by the original schema so canonical
// serialized plans can require them to be zero.
struct LoadRegionV1
{
    u64 virtual_address;
    u64 length;
    ObjectHandle memory_object;
    u64 object_offset;
    VmProtection protection;
    Hash256 content_hash;
    u32 reserved;
};
static_assert(sizeof(LoadRegionV1) == kLoadRegionV1Bytes, "LoadRegionV1 wire size changed");

// Trusted information returned by the kernel's memory-object authority for
// exactly the requested [object_offset, object_offset + length) slice.
// `sealed` is canonical boolean metadata (0 or 1) and `reserved` must be zero.
// `slice_hash` is compared with LoadRegionV1::content_hash; the plan cannot
// attest to its own backing bytes or sealing state.
struct LoadBackingInfoV1
{
    u64 object_size;
    u8 sealed;
    u8 reserved[7];
    Hash256 slice_hash;
};

// [any thread; caller serializes its object registry]
// Returns false when `memory_object` is invalid, stale, wrong-typed, or not
// inspectable. The callback must describe the exact requested slice.
using LoadBackingQueryV1 = bool (*)(ObjectHandle memory_object, u64 object_offset, u64 length,
                                    LoadBackingInfoV1* out_info, void* context);

enum class LoadPlanValidationError : u8
{
    Ok = 0,
    NullBuffer,
    HeaderTruncated,
    SizeOverflow,
    SizeMismatch,
    UnsupportedVersion,
    UnsupportedFormat,
    DependenciesUnsupported,
    NoRegions,
    TooManyRegions,
    MissingSourceHash,
    SourceHashAuthorityRequired,
    SourceHashMismatch,
    InvalidPreferredBase,
    ReservedNonZero,
    InvalidProtection,
    EmptyRegion,
    UnalignedRegion,
    MappedBytesOverflow,
    TooManyMappedBytes,
    AddressOverflow,
    AddressOutOfRange,
    NullMemoryObject,
    BackingOffsetOverflow,
    MissingContentHash,
    WritableExecutable,
    RegionOverlap,
    BackingQueryRequired,
    BackingNotFound,
    BackingRangeOutOfBounds,
    ContentHashMismatch,
    MutableExecutableBacking,
    EntryOutsideExecutableRegion,
    MultipleMemoryObjects,
    BackingRegionOverlap,
    InvalidBackingAuthority,
};

const char* LoadPlanValidationErrorName(LoadPlanValidationError error);

// A validated, immutable view. It borrows `bytes`; the caller must keep the
// kernel-resident snapshot alive and unchanged for the view's lifetime. No
// pointer to an unaligned wire struct escapes: the sanitized header is copied
// here and regions are decoded into caller storage by LoadPlanRegionAt.
struct LoadPlanViewV1
{
    const u8* bytes;
    u32 size;
    LoadPlanV1 header;
};

// [any thread; re-entrant except for the caller-supplied backing authority]
// Validate exact framing, version/format, hashes, page/range arithmetic,
// virtual/backing overlap, single-object identity, W^X, backing extent and
// seal state, and executable entry.
// `expected_source_hash` is trusted admission metadata computed independently
// from the source image; a plan may not attest to its own source identity.
//
// SECURITY PRECONDITION: `bytes` must be a stable kernel-resident snapshot for
// this call, every backing callback, and the lifetime of any returned view. It
// must never point directly at mutable user memory. A syscall/execd ingress
// must copy the complete framed blob into kernel-owned storage and freeze that
// snapshot before invoking this validator. The pure validator cannot prove
// address provenance without depending on VM internals, so violating this
// precondition is an admission-layer bug, not a supported input mode.
//
// `out_view` is optional and is cleared before every failure return.
LoadPlanValidationError LoadPlanValidateV1(const void* bytes, u64 byte_count, const Hash256* expected_source_hash,
                                           LoadBackingQueryV1 query_backing, void* query_context,
                                           LoadPlanViewV1* out_view);

// [any thread; pure]
// Decode one region from an already-validated immutable view. Returns false
// for null output or an index outside header.region_count.
bool LoadPlanRegionAt(const LoadPlanViewV1& view, u32 index, LoadRegionV1* out_region);

} // namespace duetos::loader
