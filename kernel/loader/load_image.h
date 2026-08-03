#pragma once

/*
 * Loader-private mutable image staging and sealed LoadPlan backing.
 *
 * This package is the ownership seam between an image parser and the
 * privileged address-space mapper. It deliberately knows nothing about PE,
 * ELF, the frame allocator, or AddressSpace: callers inject frame allocation,
 * release, map, and exact rollback operations. Metadata and wire-plan storage
 * are also caller-owned, so hosted tests can exercise the real state machine
 * without kernel allocator or VM dependencies.
 *
 * Lifetime and ownership:
 *   - Initialize borrows all metadata/plan buffers and the frame hooks.
 *   - ClaimRange allocates frames; the LoadImage exclusively owns them.
 *   - Seal hashes the final page bytes, emits one immutable LoadPlan, and
 *     rejects every later write through this API.
 *   - MapInto is consuming. A successful map callback transfers one frame to
 *     the unpublished target. If a later map fails, successful earlier maps
 *     are exact-unmapped in reverse order and all still-package-owned frames
 *     are released immediately.
 *   - Release is idempotent and releases package-owned frames only. It never
 *     guesses that a target-owned frame can be freed.
 *
 * The object is unpublished and single-thread-affine through MapInto. There
 * are no internal locks and no callback is invoked while any lock is held.
 */

#include "loader/load_plan.h"
#include "util/types.h"

namespace duetos::loader
{

using LoadImageFrame = u64;
inline constexpr LoadImageFrame kLoadImageInvalidFrame = 0;
inline constexpr u32 kLoadImageMaxPlanBytes = kLoadPlanV1HeaderBytes + kLoadPlanMaxRegions * kLoadRegionV1Bytes;

enum class LoadImageState : u8
{
    Uninitialized = 0,
    Mutable,
    Sealed,
    Mapping,
    Transferred,
    Failed,
    Released,
};

enum class LoadImagePageState : u8
{
    Empty = 0,
    PackageOwned,
    TargetOwned,
    Released,
};

enum class LoadImageStatus : u8
{
    Ok = 0,
    InvalidArgument,
    InvalidState,
    RangeOutOfBounds,
    InvalidProtection,
    WritableExecutableConflict,
    PageStorageTooSmall,
    RegionStorageTooSmall,
    PlanStorageTooSmall,
    TooManyPages,
    TooManyRegions,
    FrameAllocationFailed,
    UnmappedRange,
    InvalidIntegerWidth,
    WriteAfterSeal,
    AlreadySealed,
    NotSealed,
    PlanRejected,
    PlanAuthorityMismatch,
    MapFailed,
    RollbackFailed,
    CorruptState,
    OwnershipOutstanding,
};

struct LoadImageDescriptor
{
    ImageFormat format;
    u64 load_base;
    u64 preferred_base;
    u64 entry_point;
    u64 image_size;
    ObjectHandle memory_object;
    Hash256 source_hash;
};

// On true, allocate_frame publishes one nonzero frame plus a writable,
// page-sized kernel alias and transfers ownership to the LoadImage. On false,
// it publishes no ownership. release_frame consumes exactly one frame still
// owned by the package.
using LoadImageAllocateFrameFn = bool (*)(void* context, LoadImageFrame* frame_out, u8** writable_page_out);
using LoadImageReleaseFrameFn = void (*)(void* context, LoadImageFrame frame);

struct LoadImageFrameHooks
{
    void* context;
    LoadImageAllocateFrameFn allocate_frame;
    LoadImageReleaseFrameFn release_frame;
};

// map_owned_frame(true) consumes package ownership and installs the exact
// frame in an unpublished target. false consumes nothing. If a later mapping
// fails, unmap_and_release_frame is called in exact reverse order; true means
// it removed the expected mapping and consumed/freed target ownership. false
// must leave target ownership intact so target teardown can recover it.
using LoadImageMapOwnedFrameFn = bool (*)(void* context, u64 virtual_address, LoadImageFrame frame,
                                          VmProtection protection);
using LoadImageUnmapAndReleaseFrameFn = bool (*)(void* context, u64 virtual_address, LoadImageFrame expected_frame);

struct LoadImageMapHooks
{
    void* context;
    LoadImageMapOwnedFrameFn map_owned_frame;
    LoadImageUnmapAndReleaseFrameFn unmap_and_release_frame;
};

// Caller-provided dense metadata, one row per page in the declared image
// extent. Fields are implementation state and must not be modified directly.
struct LoadImagePage
{
    LoadImageFrame frame;
    u8* writable_page;
    VmProtection protection;
    LoadImagePageState state;
    u8 reserved[3];
};

// Authoritative canonical region metadata lives separately from the plan
// bytes. The backing callback matches an exact slice here, then re-hashes the
// live frames; it never accepts the plan's hash as its own authority.
struct LoadImageRegionAuthority
{
    u64 object_offset;
    u64 length;
    VmProtection protection;
    Hash256 sealed_hash;
};

// Exposed only so callers can allocate/embody the package without another
// allocator. The object MUST be value/zero-initialized (`LoadImage image{}`)
// before its first LoadImageInitialize call; Initialize reads the state field
// to reject reinitializing a live owner. Treat every field as opaque after
// initialization.
struct LoadImage
{
    LoadImageState state;
    LoadImageDescriptor descriptor;
    LoadImageFrameHooks frame_hooks;
    LoadImagePage* pages;
    u32 page_count;
    u32 page_capacity;
    LoadImageRegionAuthority* regions;
    u32 region_count;
    u32 region_capacity;
    u8* plan_storage;
    u32 plan_size;
    u32 plan_capacity;
};

struct LoadImageMapResult
{
    LoadImageStatus status;
    LoadPlanValidationError validation_error;
    u32 pages_mapped;
    u32 pages_rolled_back;
    u32 rollback_failures;
};

struct LoadImageSnapshot
{
    LoadImageState state;
    u32 page_count;
    u32 present_pages;
    u32 package_owned_pages;
    u32 target_owned_pages;
    u32 released_pages;
    u32 region_count;
    u32 plan_size;
};

// Initialize a zero-initialized, unpublished package over caller-owned
// metadata and plan storage. page_storage_count must cover
// ceil(image_size / 4096); region and plan capacity may be smaller than their
// v1 maxima, but Seal then reports an explicit capacity error if the canonical
// image needs more.
LoadImageStatus LoadImageInitialize(LoadImage* image, const LoadImageDescriptor& descriptor,
                                    const LoadImageFrameHooks& frame_hooks, LoadImagePage* page_storage,
                                    u32 page_storage_count, LoadImageRegionAuthority* region_storage,
                                    u32 region_storage_count, void* plan_storage, u32 plan_storage_bytes);

// Idempotently release every frame still package-owned. Target-owned frames
// are never touched. After a rollback failure, the caller must destroy the
// unpublished target to consume those residual target references.
void LoadImageRelease(LoadImage* image);

// [unpublished owner, quiescent]
// Validate, without mutation, that a retired fixed bank can be reset. Released
// images are accepted only with no live frame ownership. Transferred/Failed
// images are accepted only after every package-owned frame has left the image;
// target-owned frames already belong exclusively to the target's independent
// mapping ledger and are deliberately neither freed nor made reusable here.
// Clearing their observer identities cannot affect a live target mapping or
// its later teardown. Mutable, Sealed, and Mapping images must first
// complete/release their owning transaction.
LoadImageStatus LoadImageCanResetQuiescent(const LoadImage* image);

// Apply the same proof, then return the bank to canonical Uninitialized form
// without invoking frame hooks. On failure no image or metadata byte changes.
LoadImageStatus LoadImageResetQuiescent(LoadImage* image);

// Claim every page touched by [rva, rva + length), zeroing newly allocated
// frames. Protection is canonicalized per page by union. Any direct or shared
// page W+X combination is rejected before this call changes page state.
LoadImageStatus LoadImageClaimRange(LoadImage* image, u64 rva, u64 length, VmProtection protection);

// Bounded byte transfer against already-claimed pages. CopyIn is mutable-only;
// CopyOut remains available after sealing for diagnostics. Both preflight the
// complete range, so an error never performs a partial copy.
LoadImageStatus LoadImageCopyIn(LoadImage* image, u64 rva, const void* source, u64 length);
LoadImageStatus LoadImageCopyOut(const LoadImage* image, u64 rva, void* destination, u64 length);

// Page-straddle-safe little-endian access for 1, 2, 4, or 8-byte patch sites.
// Read leaves value_out untouched on failure; Write is rejected after Seal.
LoadImageStatus LoadImageReadLe(const LoadImage* image, u64 rva, u32 width, u64* value_out);
LoadImageStatus LoadImageWriteLe(LoadImage* image, u64 rva, u32 width, u64 value);

// Seal exactly once. Canonical contiguous pages with identical protection are
// emitted as one LoadRegionV1. Region hashes cover whole page-rounded slices,
// including zero padding. Successful Seal permanently rejects writes.
LoadImageStatus LoadImageSeal(LoadImage* image);

// Borrow the frozen wire plan. Valid while the package metadata/plan storage
// remains alive. Returns false before successful Seal.
bool LoadImagePlanBytes(const LoadImage* image, const u8** bytes_out, u32* size_out);

// Sole LoadPlan backing authority for this package. It accepts only the exact
// package object and exact canonical sealed slices, and computes the live
// SHA-256 from backing pages so post-seal corruption is caught before map.
bool LoadImageBackingQuery(ObjectHandle memory_object, u64 object_offset, u64 length, LoadBackingInfoV1* out_info,
                           void* context);

// Consuming validated map transaction. Invalid hook arguments are retryable
// and do not consume the package. Once validation/mapping begins, success
// transfers every frame; any failure releases all remaining package ownership
// and leaves the package terminal. See LoadImageMapHooks for rollback rules.
LoadImageMapResult LoadImageMapInto(LoadImage* image, const LoadImageMapHooks& map_hooks);

LoadImageStatus LoadImageInspect(const LoadImage* image, LoadImageSnapshot* snapshot_out);
const char* LoadImageStatusName(LoadImageStatus status);

} // namespace duetos::loader
