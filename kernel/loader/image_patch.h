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

/// True iff the byte range [off, off+span) lies wholly within an
/// image of `image_size` bytes. `off` is an RVA / image-relative
/// offset, `span` the patch width. Overflow-safe: the subtraction
/// is only evaluated when `off <= image_size`, so it never wraps
/// even if a caller passes an unbounded `off`.
inline bool ImageRangeInBounds(u64 off, u64 span, u64 image_size)
{
    return off <= image_size && span <= image_size - off;
}

/// Little-endian read of `n` (1..8) bytes at guest VA `va` in `as`,
/// through the kernel direct map, resolving each byte's frame
/// independently so a read that straddles a page boundary is
/// handled correctly. Returns false (and leaves `out` untouched)
/// if any covered page is unmapped.
inline bool ImageDirectReadLe(const mm::AddressSpace* as, u64 va, u64 n, u64& out)
{
    u64 value = 0;
    for (u64 b = 0; b < n; ++b)
    {
        const u64 byte_va = va + b;
        const mm::PhysAddr frame = mm::AddressSpaceLookupUserFrame(as, byte_va & ~0xFFFULL);
        if (frame == mm::kNullFrame)
        {
            return false;
        }
        const auto* direct = static_cast<const u8*>(mm::PhysToVirt(frame));
        value |= static_cast<u64>(direct[byte_va & 0xFFFULL]) << (b * 8);
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
    for (u64 b = 0; b < n; ++b)
    {
        const u64 byte_va = va + b;
        const mm::PhysAddr frame = mm::AddressSpaceLookupUserFrame(as, byte_va & ~0xFFFULL);
        if (frame == mm::kNullFrame)
        {
            return false;
        }
        auto* direct = static_cast<u8*>(mm::PhysToVirt(frame));
        direct[byte_va & 0xFFFULL] = static_cast<u8>((val >> (b * 8)) & 0xFF);
    }
    return true;
}

} // namespace duetos::loader
