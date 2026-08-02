#pragma once

// Shared loader image-patch primitives.
//
// The PE and DLL loaders both apply relocations and import-address-
// table fixups by writing into the guest's mapped image through the
// kernel direct map (PhysToVirt). The direct map is always writable,
// so an `AddressSpaceLookupUserFrame() != kNullFrame` check is NOT a
// sufficient guard: a relocation `page_rva`/`offset` or an import
// `FirstThunk` comes straight from the (untrusted) image and, if
// used unbounded as a write target, would let a crafted PE/DLL
// rewrite any mapped page of the guest AS — its stack, TEB,
// proc-env, or its own R-X .text — bypassing the PTE writable bit
// and the loader's W^X-for-image guarantee.
//
// A frame returned by AddressSpaceLookupUserFrame is only a snapshot.
// Every direct-map access below therefore holds the address-space mutation
// transaction from lookup through the final byte access. This excludes
// unmap/remap/release without weakening the user PTE's W^X permissions.
// Callers must not already hold `as->mutation_lock`.
//
// These checks/loops were duplicated three times (pe_loader reloc,
// pe_loader IAT, dll_loader reloc). Three copies of one security
// invariant is the exact "sentinel divergence" drift hazard the
// project's audit rules call out: bump one and the others silently
// disagree. This header is the single source of truth. It is
// header-only `inline` so it adds no new TU and keeps both loaders
// standalone (no cross-TU link coupling — only an include), which
// is why it overrides the usual "duplicate tiny helpers" convention
// for THIS case: it is a security invariant, not a 5-line nicety.

#include "mm/address_space.h"
#include "mm/frame_allocator.h"
#include "mm/page.h"
#include "util/types.h"

namespace duetos::loader
{

namespace detail
{

inline constexpr u64 kImagePatchUserMax = 0x00007FFFFFFFFFFFULL;

class ImagePatchMutationGuard final
{
  public:
    explicit ImagePatchMutationGuard(const mm::AddressSpace& as) : m_lock(as.mutation_lock)
    {
        sched::MutexLock(&m_lock);
    }

    ~ImagePatchMutationGuard() { sched::MutexUnlock(&m_lock); }

    ImagePatchMutationGuard(const ImagePatchMutationGuard&) = delete;
    ImagePatchMutationGuard& operator=(const ImagePatchMutationGuard&) = delete;

  private:
    sched::Mutex& m_lock;
};

inline bool ImagePatchRangeValid(const mm::AddressSpace* as, u64 va, u64 len)
{
    return as != nullptr && len != 0 && va <= kImagePatchUserMax && len - 1 <= kImagePatchUserMax - va;
}

} // namespace detail

/// True iff the byte range [off, off+span) lies wholly within an
/// image of `image_size` bytes. `off` is an RVA / image-relative
/// offset, `span` the patch width. Overflow-safe: the subtraction
/// is only evaluated when `off <= image_size`, so it never wraps
/// even if a caller passes an unbounded `off`.
inline bool ImageRangeInBounds(u64 off, u64 span, u64 image_size)
{
    return off <= image_size && span <= image_size - off;
}

/// Copy trusted kernel bytes into an already-mapped image range through the
/// kernel direct map. The complete span is preflighted before the first byte
/// is changed, so a page-straddling missing mapping cannot leave a torn
/// patch. The AS mutation transaction pins every resolved frame through the
/// copy. This deliberately bypasses the user PTE writable bit for loader
/// relocations; the caller MUST first prove the target lies within its image
/// and MUST own either an exact live loader reservation or exclusive access
/// to an unpublished address space.
inline bool ImageDirectWriteBytes(mm::AddressSpace* as, u64 va, const u8* src, u64 len)
{
    if (src == nullptr || !detail::ImagePatchRangeValid(as, va, len))
    {
        return false;
    }

    detail::ImagePatchMutationGuard mutation(*as);

    // Failure-atomic preflight: no direct-map byte is touched until every
    // covered page has a stable owned-frame receipt under mutation_lock.
    u64 cursor = va;
    u64 remaining = len;
    while (remaining != 0)
    {
        const mm::PhysAddr frame = mm::AddressSpaceLookupUserFrame(as, cursor & ~(mm::kPageSize - 1));
        if (frame == mm::kNullFrame)
        {
            return false;
        }
        const u64 page_remaining = mm::kPageSize - (cursor & (mm::kPageSize - 1));
        const u64 chunk = remaining < page_remaining ? remaining : page_remaining;
        cursor += chunk;
        remaining -= chunk;
    }

    cursor = va;
    remaining = len;
    u64 source_offset = 0;
    while (remaining != 0)
    {
        const u64 page_offset = cursor & (mm::kPageSize - 1);
        const mm::PhysAddr frame = mm::AddressSpaceLookupUserFrame(as, cursor - page_offset);
        const u64 page_remaining = mm::kPageSize - page_offset;
        const u64 chunk = remaining < page_remaining ? remaining : page_remaining;
        auto* direct = static_cast<u8*>(mm::PhysToVirt(frame)) + page_offset;
        for (u64 i = 0; i < chunk; ++i)
        {
            direct[i] = src[source_offset + i];
        }
        cursor += chunk;
        source_offset += chunk;
        remaining -= chunk;
    }
    return true;
}

/// Little-endian read of `n` (1..8) bytes at guest VA `va` in `as`,
/// through the kernel direct map, resolving each byte's frame
/// independently so a read that straddles a page boundary is
/// handled correctly. Returns false (and leaves `out` untouched)
/// if any covered page is unmapped.
inline bool ImageDirectReadLe(const mm::AddressSpace* as, u64 va, u64 n, u64& out)
{
    if (n == 0 || n > sizeof(u64) || !detail::ImagePatchRangeValid(as, va, n))
    {
        return false;
    }

    detail::ImagePatchMutationGuard mutation(*as);
    u64 value = 0;
    for (u64 b = 0; b < n; ++b)
    {
        const u64 byte_va = va + b;
        const mm::PhysAddr frame = mm::AddressSpaceLookupUserFrame(as, byte_va & ~(mm::kPageSize - 1));
        if (frame == mm::kNullFrame)
        {
            return false;
        }
        const auto* direct = static_cast<const u8*>(mm::PhysToVirt(frame));
        value |= static_cast<u64>(direct[byte_va & (mm::kPageSize - 1)]) << (b * 8);
    }
    out = value;
    return true;
}

/// Little-endian write of the low `n` (1..8) bytes of `val` at
/// guest VA `va` in `as`, through the direct map, resolving each
/// byte's frame independently (page-straddle safe). Returns false
/// if any covered page is unmapped. The caller MUST have validated
/// the target with ImageRangeInBounds first — this function only
/// guards mapped-ness, not the image-extent invariant.
inline bool ImageDirectWriteLe(mm::AddressSpace* as, u64 va, u64 n, u64 val)
{
    if (n == 0 || n > sizeof(u64))
    {
        return false;
    }

    u8 bytes[sizeof(u64)]{};
    for (u64 b = 0; b < n; ++b)
    {
        bytes[b] = static_cast<u8>((val >> (b * 8)) & 0xFF);
    }
    return ImageDirectWriteBytes(as, va, bytes, n);
}

} // namespace duetos::loader
