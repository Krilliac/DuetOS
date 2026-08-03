#pragma once

/*
 * Win32 anonymous section objects.
 *
 * A section owns a bounded vector of physical frames that may be installed as
 * borrowed mappings in one or more process address spaces. File-backed,
 * demand-zero, swap, and non-zero SectionOffset views remain out of scope.
 *
 * Lifetime model:
 *   - Every reference names a non-wrapping `{slot, generation}` key.
 *   - A slot moves Free -> Constructing -> Live -> Retiring -> Free.
 *   - The live refcount is open handles + active views + temporary operation
 *     pins. Exactly the 1 -> 0 transition owns retirement.
 *   - Allocation, address-space mutation, TLB waits, and frame release never
 *     run under the global section-pool spinlock.
 *   - Each slot has a persistent sleepable map mutex. It serializes sticky
 *     W^X history with map/unmap and is never reinitialized between reuse.
 *
 * Lock graph (no reverse edges):
 *   process section-row lock -> global section-pool lock
 *   section map mutex -> global section-pool lock (brief snapshot/publish)
 *   section map mutex -> address-space mutation lock -> regions lock
 */

#include "mm/frame_allocator.h"
#include "proc/resource_domain.h"
#include "util/types.h"

namespace duetos::mm
{
struct AddressSpace;
}

namespace duetos::subsystems::win32::section
{

constexpr u64 kSectionMaxBytes = 4 * 1024 * 1024;
constexpr u32 kSectionPoolCap = 8;
static_assert(kSectionPoolCap == core::kResourceSectionPoolCapacity,
              "Section pool and resource-charge capacity must stay identical");
// Keep identities positive and exactly representable through the PE32 ABI:
// generations occupy public-handle bits 12..30.
constexpr u32 kSectionMaxGeneration = 0x7FFFF;

struct SectionKey
{
    u32 slot;
    u32 generation;
};

constexpr SectionKey kInvalidSectionKey{kSectionPoolCap, 0};

constexpr bool SectionKeyIsValid(SectionKey key)
{
    return key.slot < kSectionPoolCap && key.generation != 0 && key.generation <= kSectionMaxGeneration;
}

constexpr bool operator==(SectionKey lhs, SectionKey rhs)
{
    return lhs.slot == rhs.slot && lhs.generation == rhs.generation;
}

// Transactional create API. On success, key_out owns the initial handle
// reference. The caller must publish that key into a handle row or release it.
// page_protect is the section's immutable maximum access: only exact,
// representable PAGE_READONLY/READWRITE/EXECUTE/EXECUTE_READ values are
// accepted. Copy-on-write and writable+executable protections are refused.
bool SectionCreate(core::ResourceDomainKey domain, u64 size_bytes, u32 page_protect, SectionKey* key_out);

// Generation-exact reference operations. Retain refuses stale, constructing,
// retiring, and saturated objects. Release performs final frame teardown only
// for the exact live generation.
bool SectionRetain(SectionKey key);
void SectionRelease(SectionKey key);

// Snapshot whether an exact view protection is supported and is a subset of
// the immutable maximum stored by SectionCreate. Callers may use this to
// return an ingress error before reserving process/view state; the map API
// repeats the check transactionally and remains authoritative.
bool SectionViewProtectionIsCompatible(SectionKey key, u32 view_protect);

// Atomically map the full frame vector and adopt one view reference on
// success. Failure leaves neither PTEs nor a reference behind. Unknown,
// copy-on-write, writable+executable, and maximum-exceeding protections fail.
bool SectionMapAndRetainView(SectionKey key, mm::AddressSpace* target_as, u64 base_va, u32 view_protect);

// Atomically unmap the exact expected frame vector and release the view
// reference on success. A stale key or PTE mismatch leaves both intact.
bool SectionUnmapAndReleaseView(SectionKey key, mm::AddressSpace* target_as, u64 base_va);

// Page-rounded size of the exact live generation, or zero for a stale key.
u64 SectionViewSize(SectionKey key);

// Boot-time generation, ref-balance, and transactional-view regression.
void SectionLifetimeSelfTest();

} // namespace duetos::subsystems::win32::section
