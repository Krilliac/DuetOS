#pragma once

/*
 * Win32 section objects — kernel-resident pools of physical
 * frames that can be mapped into one or more process address
 * spaces via NtMapViewOfSection. Backs Windows shared memory
 * + (eventually) memory-mapped files.
 *
 * v0 SCOPE:
 *   - Anonymous (pagefile-backed) sections only. NtCreateSection
 *     with FileHandle != 0 returns STATUS_NOT_IMPLEMENTED.
 *   - Sections are RAM-resident from creation; no demand-zero,
 *     no swap, no SEC_RESERVE-then-commit phasing.
 *   - Cap: 8 live sections, each up to kSectionMaxBytes bytes.
 *     The pool is global; NtCreateSection picks the first free
 *     slot.
 *   - Cross-process map cap-gated on kCapDebug — same threat
 *     class as cross-process VM read/write.
 *   - View granularity: whole pages. Caller-supplied
 *     SectionOffset must be page-aligned and 0 in v0; non-zero
 *     returns STATUS_INVALID_PARAMETER.
 *
 * Refcount semantics:
 *   - Section.refcount == open-handles + active-mappings.
 *   - NtCreateSection bumps it to 1 (the new handle).
 *   - NtMapViewOfSection bumps it once per view.
 *   - NtClose / NtUnmapViewOfSection drop one each.
 *   - When refcount hits 0, frames are returned to the
 *     physical allocator and the slot goes back to free.
 */

#include "mm/frame_allocator.h"
#include "util/types.h"

namespace duetos::core
{
struct Process;
}
namespace duetos::mm
{
struct AddressSpace;
}

namespace duetos::subsystems::win32::section
{

// Hard upper bound on a single section: 4 MiB. Catches a
// caller that accidentally passes garbage in MaximumSize and
// keeps the per-section frame pointer table small (1024
// entries × 8 bytes = 8 KiB / section).
constexpr u64 kSectionMaxBytes = 4 * 1024 * 1024;
constexpr u32 kSectionPoolCap = 8;

struct Section
{
    bool in_use;
    u32 num_pages;
    u32 refcount;
    u32 page_protect;     // Win32 PAGE_* on creation
    mm::PhysAddr* frames; // owned, length = num_pages, 0 entries are unallocated
};

// Returns the index of a freshly-created section, or -1 on
// any failure (size==0, size>kSectionMaxBytes, pool full,
// frame allocator out). The caller (SYS_SECTION_CREATE) is
// responsible for installing the resulting index into a
// Win32SectionHandle slot in the calling Process. Sections
// start with refcount = 1 (the new handle).
i32 SectionCreate(u64 size_bytes, u32 page_protect);

// Decrements refcount on the section at pool index `idx`.
// Frees frames + pool slot when refcount hits 0. No-op on
// already-free / out-of-range index.
void SectionRelease(u32 idx);

// Increments refcount on the section at pool index `idx`.
// Used when a new mapping is installed.
void SectionRetain(u32 idx);

// Map a section's entire frame set into `target_as` starting at
// `base_va`. `base_va` must be 4 KiB-aligned. Each page gets
// its own PTE installed via AddressSpaceMapBorrowedPage (the
// AS does NOT take ownership — the section pool owns the frames).
// Returns true on success; false if any PTE install conflicts
// with an existing mapping (caller should pick a different
// base_va). The section's refcount is NOT touched here — the
// caller (SYS_SECTION_MAP) handles the SectionRetain.
bool SectionMap(u32 idx, mm::AddressSpace* target_as, u64 base_va, u32 view_protect);

// Unmap a section view. Walks `num_pages` consecutive pages
// starting at `base_va` and clears each PTE via
// AddressSpaceUnmapBorrowedPage. Returns true if every page
// was actually mapped (i.e. the unmap matches a prior
// SectionMap); false if any page was already unmapped — that
// case still clears the rest, so the AS isn't left half-mapped.
bool SectionUnmap(u32 idx, mm::AddressSpace* target_as, u64 base_va);

// Returns the size in bytes of a section's full view (page-
// rounded). 0 on out-of-range / not-in-use index.
u64 SectionViewSize(u32 idx);

// Walk every live pool entry; for each, probe the leaf PTE
// at `base_va` in `target_as` and check whether it points at
// the section's frames[0]. If so, unmap that section's view
// and return its pool index. Returns -1 if no section's
// first frame lives at `base_va` in `target_as` (i.e. the
// caller passed a base_va that doesn't correspond to any
// active section view).
i32 SectionUnmapAtVa(mm::AddressSpace* target_as, u64 base_va);

// Resolve a Win32 section handle on `caller` to its pool
// index. Returns -1 on out-of-range / not-in-use handles.
i32 LookupSectionHandle(core::Process* caller, u64 handle);

} // namespace duetos::subsystems::win32::section
