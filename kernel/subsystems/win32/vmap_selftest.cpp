/*
 * Boot self-test for Win32 VirtualAlloc region tracking
 * (T5-01 partial).
 *
 * Mirrors the algorithmic path the production handlers
 * (DoVirtualAlloc / DoVirtualFree / DoVirtualProtect) take:
 * find-free-slot, set commit bits, clear commit bits, release
 * slot. Runs against a stand-in process region table — we don't
 * touch the AS / page-table layer because the test runs before
 * any real PE has spawned and we'd need an AS to map into.
 *
 * What the production code adds on top: AllocateFrame +
 * AddressSpaceMapUserPage / AddressSpaceProtectUserPage /
 * AddressSpaceUnmapUserPage. The mapping/protect/unmap layer
 * has its own boot self-test in mm/; here we only verify the
 * region-table state-machine.
 */

#include "subsystems/win32/vmap_selftest.h"

#include "arch/x86_64/serial.h"
#include "proc/process.h"

namespace duetos::subsystems::win32
{

namespace
{

using ::duetos::core::Process;

// Reset every region in `p` to the default-empty state.
void ResetRegions(Process& p)
{
    for (u64 i = 0; i < Process::kWin32VmapRegionCap; ++i)
    {
        p.vmap_regions[i].in_use = false;
        p.vmap_regions[i].base_va = 0;
        p.vmap_regions[i].pages = 0;
        p.vmap_regions[i].committed_bits = 0;
        p.vmap_regions[i].protection = 0;
    }
    p.vmap_base = Process::kWin32VmapBase;
    p.vmap_pages_used = 0;
}

// Find the first free region slot — same algorithm as the
// production helper FindFreeRegionSlot.
u64 FreeSlot(const Process& p)
{
    for (u64 i = 0; i < Process::kWin32VmapRegionCap; ++i)
        if (!p.vmap_regions[i].in_use)
            return i;
    return Process::kWin32VmapRegionCap;
}

// Mini-Reserve: claim a fresh slot at the bump cursor.
u64 MiniReserve(Process& p, u32 pages)
{
    if (pages == 0 || pages > Process::kWin32VmapRegionPagesMax)
        return 0;
    if (p.vmap_pages_used + pages > Process::kWin32VmapCapPages)
        return 0;
    const u64 slot = FreeSlot(p);
    if (slot == Process::kWin32VmapRegionCap)
        return 0;
    auto& r = p.vmap_regions[slot];
    r.in_use = true;
    r.base_va = p.vmap_base + p.vmap_pages_used * 4096ULL;
    r.pages = pages;
    r.committed_bits = 0;
    r.protection = 0x04; // PAGE_READWRITE
    p.vmap_pages_used += pages;
    return r.base_va;
}

// Mini-Commit: set the bits for [first, first+count) inside the
// region whose base_va == base. Returns true on success.
bool MiniCommit(Process& p, u64 base, u64 first, u64 count)
{
    for (u64 i = 0; i < Process::kWin32VmapRegionCap; ++i)
    {
        auto& r = p.vmap_regions[i];
        if (!r.in_use || r.base_va != base)
            continue;
        if (first + count > r.pages)
            return false;
        for (u64 j = first; j < first + count; ++j)
            r.committed_bits |= (1u << j);
        return true;
    }
    return false;
}

// Mini-Decommit: clear the bits for [first, first+count) inside
// the region whose base_va == base.
bool MiniDecommit(Process& p, u64 base, u64 first, u64 count)
{
    for (u64 i = 0; i < Process::kWin32VmapRegionCap; ++i)
    {
        auto& r = p.vmap_regions[i];
        if (!r.in_use || r.base_va != base)
            continue;
        for (u64 j = first; j < first + count; ++j)
            r.committed_bits &= ~(1u << j);
        return true;
    }
    return false;
}

// Mini-Release: clear the slot whose base_va == base.
bool MiniRelease(Process& p, u64 base)
{
    for (u64 i = 0; i < Process::kWin32VmapRegionCap; ++i)
    {
        auto& r = p.vmap_regions[i];
        if (!r.in_use || r.base_va != base)
            continue;
        r.in_use = false;
        r.base_va = 0;
        r.pages = 0;
        r.committed_bits = 0;
        r.protection = 0;
        return true;
    }
    return false;
}

} // namespace

void Win32VmapSelfTest()
{
    // File-scope static keeps the boot stack small — Process is
    // ~20 KiB.
    static Process p;
    for (u8* b = reinterpret_cast<u8*>(&p); b < reinterpret_cast<u8*>(&p) + sizeof(Process); ++b)
        *b = 0;
    ResetRegions(p);

    // 1. Reserve a 4-page region. Verify bump-cursor advances and
    //    the slot's committed bitmap is empty.
    const u64 r0 = MiniReserve(p, 4);
    if (r0 == 0)
    {
        arch::SerialWrite("[selftest:vmap] FAIL initial reserve\n");
        return;
    }
    {
        u64 slot = ~u64(0);
        for (u64 i = 0; i < Process::kWin32VmapRegionCap; ++i)
            if (p.vmap_regions[i].in_use && p.vmap_regions[i].base_va == r0)
                slot = i;
        if (slot == ~u64(0) || p.vmap_regions[slot].pages != 4 || p.vmap_regions[slot].committed_bits != 0)
        {
            arch::SerialWrite("[selftest:vmap] FAIL reserve-only state\n");
            return;
        }
    }

    // 2. Commit pages 1..3 of the reservation. Verify only those
    //    bits flip.
    if (!MiniCommit(p, r0, 1, 2))
    {
        arch::SerialWrite("[selftest:vmap] FAIL partial commit\n");
        return;
    }
    {
        u64 slot = ~u64(0);
        for (u64 i = 0; i < Process::kWin32VmapRegionCap; ++i)
            if (p.vmap_regions[i].in_use && p.vmap_regions[i].base_va == r0)
                slot = i;
        if (p.vmap_regions[slot].committed_bits != 0x6) // bits 1+2
        {
            arch::SerialWrite("[selftest:vmap] FAIL committed-bits drift\n");
            return;
        }
    }

    // 3. Decommit page 1. Verify bit 1 clears, bit 2 still set.
    if (!MiniDecommit(p, r0, 1, 1))
    {
        arch::SerialWrite("[selftest:vmap] FAIL decommit\n");
        return;
    }
    {
        u64 slot = ~u64(0);
        for (u64 i = 0; i < Process::kWin32VmapRegionCap; ++i)
            if (p.vmap_regions[i].in_use && p.vmap_regions[i].base_va == r0)
                slot = i;
        if (p.vmap_regions[slot].committed_bits != 0x4) // bit 2 only
        {
            arch::SerialWrite("[selftest:vmap] FAIL decommit-bits drift\n");
            return;
        }
    }

    // 4. Release. Verify the slot clears + a fresh reserve picks
    //    a free slot (the same one or any free one).
    if (!MiniRelease(p, r0))
    {
        arch::SerialWrite("[selftest:vmap] FAIL release\n");
        return;
    }
    {
        for (u64 i = 0; i < Process::kWin32VmapRegionCap; ++i)
            if (p.vmap_regions[i].in_use && p.vmap_regions[i].base_va == r0)
            {
                arch::SerialWrite("[selftest:vmap] FAIL post-release stale slot\n");
                return;
            }
    }

    // 5. Capacity check — fill every region slot, verify the
    //    next reserve fails.
    ResetRegions(p);
    for (u64 i = 0; i < Process::kWin32VmapRegionCap; ++i)
    {
        if (MiniReserve(p, 1) == 0)
        {
            arch::SerialWrite("[selftest:vmap] FAIL fill reserve\n");
            return;
        }
    }
    if (MiniReserve(p, 1) != 0)
    {
        arch::SerialWrite("[selftest:vmap] FAIL overcapacity reserve accepted\n");
        return;
    }

    // 6. Bump-cursor cap — reset, then attempt a too-big reserve.
    ResetRegions(p);
    if (MiniReserve(p, Process::kWin32VmapRegionPagesMax + 1) != 0)
    {
        arch::SerialWrite("[selftest:vmap] FAIL oversized reserve accepted\n");
        return;
    }

    arch::SerialWrite("[selftest:vmap] ok; reserve+commit+decommit+release+caps\n");
}

} // namespace duetos::subsystems::win32
