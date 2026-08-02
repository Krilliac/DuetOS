#pragma once

#include "loader/elf_loader.h"
#include "loader/load_image.h"

namespace duetos::loader
{

inline constexpr u64 kElfLoadImageMaximumSourceBytes = 256ULL * 1024ULL * 1024ULL;
inline constexpr u64 kElfLoadImageMaximumSegmentSpanBytes = 256ULL * 1024ULL * 1024ULL;

enum class ElfLoadImageStatus : u8
{
    Ok = 0,
    InvalidArgument,
    SourceHashMismatch,
    ElfRejected,
    NoLoadSegments,
    TooManySegments,
    InvalidSegment,
    RangeOutOfBounds,
    WritableExecutable,
    EntryNotExecutable,
    LoadImageRejected,
};

// Caller-owned storage and immutable source authority for one staging
// transaction. `bytes` must remain stable for the duration of Prepare; it is
// never retained. `expected_source_hash` comes from a separately authenticated
// package/transfer object, not from the ELF itself.
struct ElfLoadImageRequest
{
    const u8* bytes;
    u64 byte_count;
    Hash256 expected_source_hash;
    ObjectHandle memory_object;
    LoadImageFrameHooks frame_hooks;
    LoadImagePage* page_storage;
    u32 page_storage_count;
    LoadImageRegionAuthority* region_storage;
    u32 region_storage_count;
    void* plan_storage;
    u32 plan_storage_bytes;
};

struct ElfLoadImageResult
{
    ElfLoadImageStatus status;
    core::ElfStatus elf_status;
    LoadImageStatus load_image_status;
    u32 segment_count;
    u64 load_base;
    u64 image_size;
    u64 entry_point;
};

// Parse with the production ELF validator/walker, stage every PT_LOAD into
// caller-owned LoadImage frames, and seal an immutable LoadPlan. This function
// does not map a target AddressSpace, publish a Process, consume an
// ExecAdmission token, or retain the source bytes. On failure it releases every
// frame acquired during this call and leaves `image` terminal/released.
ElfLoadImageResult ElfLoadImagePrepare(const ElfLoadImageRequest& request, LoadImage* image);

const char* ElfLoadImageStatusName(ElfLoadImageStatus status);

} // namespace duetos::loader
