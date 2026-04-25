/*
 * DuetOS — physical frame allocator: implementation.
 *
 * Companion to frame_allocator.h — see there for the public API
 * (`AllocateFrame`, `FreeFrame`, `kNullFrame`) and the bitmap-
 * over-Multiboot2-map design.
 *
 * WHAT
 *   Owns the physical-memory bitmap. One bit per 4 KiB frame
 *   (1=free, 0=in-use). The bitmap itself lives in low physical
 *   memory at a frame chosen by the boot path; entries up to
 *   the kernel image's end and through reserved Multiboot2
 *   ranges are marked in-use at init time.
 *
 * HOW
 *   `Init` walks the Multiboot2 memory map, sizes the bitmap,
 *   and marks every (E820 RESERVED | LOADER_CODE | bitmap
 *   itself | kernel image) range as in-use. Allocation is a
 *   first-fit linear scan; free is a single bit clear. The
 *   scan is O(N) on the bitmap which is negligible until we
 *   start carving out user pages in the megabytes — at which
 *   point a buddy-allocator overlay will replace the linear
 *   path for the user-half range.
 *
 *   Diagnostic: `FrameAllocatorDump` walks the bitmap and emits
 *   a free/used summary used by the `mem` shell command.
 */

#include "frame_allocator.h"

#include "multiboot2.h"
#include "page.h"

#include "../arch/x86_64/cpu.h"
#include "../arch/x86_64/serial.h"
#include "../core/klog.h"
#include "../core/panic.h"

// Linker-script symbols. Both are PHYSICAL addresses: the kernel image is
// loaded contiguously starting at 1 MiB and the bitmap reservation needs
// physical frame numbers. The higher-half virtual aliases are irrelevant to
// the allocator — we never dereference these; only take their addresses.
extern "C" char _kernel_start_phys[];
extern "C" char _kernel_end_phys[];

namespace duetos::mm
{

namespace
{

using arch::Halt;
using arch::SerialWrite;
using arch::SerialWriteHex;

// ---------------------------------------------------------------------------
// Bitmap state. The backing store is a byte array placed dynamically in a
// "Multiboot available" region; only g_bitmap / g_bitmap_frames matter for
// allocation. Bit N == 1 means frame N is in use. Default is "all used" so
// unknown / reserved memory stays allocated.
// ---------------------------------------------------------------------------
constinit u8* g_bitmap = nullptr;
constinit u64 g_bitmap_frames = 0; // number of frames covered
constinit u64 g_bitmap_bytes = 0;
constinit u64 g_next_hint = 0; // search hint for AllocateFrame
constinit u64 g_free_count = 0;
constinit u64 g_total_frames = 0;

// Local alias keeps call sites tidy; delegates to the central core::Panic
// so the output format matches every other subsystem.
[[noreturn]] void PanicFrame(const char* message)
{
    core::Panic("mm/frame_allocator", message);
}

// ---------------------------------------------------------------------------
// Bitmap primitives.
// ---------------------------------------------------------------------------
inline void BitmapMarkUsed(u64 frame)
{
    if (frame >= g_bitmap_frames)
    {
        return; // out-of-range frames stay "used" by default; nothing to do.
    }
    u8& byte = g_bitmap[frame >> 3];
    const u8 mask = static_cast<u8>(1u << (frame & 7));
    if ((byte & mask) == 0)
    {
        byte = static_cast<u8>(byte | mask);
        --g_free_count;
    }
}

inline void BitmapMarkFree(u64 frame)
{
    if (frame >= g_bitmap_frames)
    {
        return;
    }
    u8& byte = g_bitmap[frame >> 3];
    const u8 mask = static_cast<u8>(1u << (frame & 7));
    if ((byte & mask) != 0)
    {
        byte = static_cast<u8>(byte & ~mask);
        ++g_free_count;
    }
}

inline bool BitmapIsUsed(u64 frame)
{
    if (frame >= g_bitmap_frames)
    {
        return true;
    }
    return (g_bitmap[frame >> 3] & (1u << (frame & 7))) != 0;
}

inline void ReserveRange(u64 start_phys, u64 end_phys)
{
    const u64 first = start_phys >> kPageSizeLog2;
    const u64 last = (end_phys + kPageSize - 1) >> kPageSizeLog2;
    for (u64 f = first; f < last; ++f)
    {
        BitmapMarkUsed(f);
    }
}

// ---------------------------------------------------------------------------
// Multiboot2 tag iteration. The total_size field in the info header bounds
// the walk; each tag's size field advances to the next (8-byte aligned).
// ---------------------------------------------------------------------------
template <typename Callback> void ForEachMmapEntry(uptr info_phys, Callback&& cb)
{
    const auto* info = reinterpret_cast<const MultibootInfoHeader*>(info_phys);
    uptr cursor = info_phys + sizeof(MultibootInfoHeader);
    const uptr end = info_phys + info->total_size;

    while (cursor < end)
    {
        const auto* tag = reinterpret_cast<const MultibootTagHeader*>(cursor);
        if (tag->type == kMultibootTagEnd)
        {
            break;
        }

        if (tag->type == kMultibootTagMmap)
        {
            const auto* mmap = reinterpret_cast<const MultibootMmapTag*>(tag);
            uptr entry_addr = cursor + sizeof(MultibootMmapTag);
            const uptr mmap_end = cursor + mmap->size;
            while (entry_addr + sizeof(MultibootMmapEntry) <= mmap_end)
            {
                const auto* entry = reinterpret_cast<const MultibootMmapEntry*>(entry_addr);
                cb(*entry);
                entry_addr += mmap->entry_size;
            }
        }

        cursor += (tag->size + 7u) & ~uptr{7};
    }
}

// ---------------------------------------------------------------------------
// Find the highest physical address the memory map describes. Used to size
// the bitmap. Reserved / bad RAM regions count — we need bits for them so
// their frames can be marked "used" persistently.
// ---------------------------------------------------------------------------
// Only consider regions we might allocate out of — reserved MMIO windows
// near the top of the physical address space (QEMU parks some at 1 TiB)
// should not force a multi-megabyte bitmap.
u64 ComputeHighestUsableAddr(uptr info_phys)
{
    u64 highest = 0;
    ForEachMmapEntry(info_phys,
                     [&](const MultibootMmapEntry& entry)
                     {
                         if (entry.type != kMmapTypeAvailable && entry.type != kMmapTypeAcpiReclaimable)
                         {
                             return;
                         }
                         const u64 top = entry.base_addr + entry.length;
                         if (top > highest)
                         {
                             highest = top;
                         }
                     });
    return highest;
}

// ---------------------------------------------------------------------------
// Find a "type == available" region large enough for the bitmap, above both
// the kernel image AND the Multiboot2 info struct, within the identity-
// mapped 1 GiB. Returns 0 on failure.
//
// GRUB places the info struct in low RAM just past the kernel — a naïve
// "above _kernel_end" search will pick an address that overwrites it.
// ---------------------------------------------------------------------------
u64 FindBitmapHome(uptr info_phys, u64 info_size, u64 bitmap_bytes)
{
    const u64 kernel_end_phys = reinterpret_cast<u64>(_kernel_end_phys);
    const u64 info_end_phys = info_phys + info_size;
    u64 floor = kernel_end_phys > info_end_phys ? kernel_end_phys : info_end_phys;
    const u64 identity_limit = 1ULL * 1024 * 1024 * 1024; // 1 GiB

    u64 chosen = 0;
    ForEachMmapEntry(info_phys,
                     [&](const MultibootMmapEntry& entry)
                     {
                         if (chosen != 0 || entry.type != kMmapTypeAvailable)
                         {
                             return;
                         }

                         u64 start = entry.base_addr;
                         u64 end = entry.base_addr + entry.length;

                         // Must start after the kernel image AND the Multiboot2 info struct.
                         if (start < floor)
                         {
                             start = floor;
                         }
                         // Align to page boundary.
                         start = (start + kPageSize - 1) & ~(kPageSize - 1);

                         // Clamp to identity-mapped range — we can't write the bitmap at an
                         // address we haven't mapped. Extending the map is a separate commit.
                         if (end > identity_limit)
                         {
                             end = identity_limit;
                         }

                         if (end > start && end - start >= bitmap_bytes)
                         {
                             chosen = start;
                         }
                     });
    return chosen;
}

} // namespace

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
void FrameAllocatorInit(uptr multiboot_info_phys)
{
    KLOG_TRACE_SCOPE("mm/frame", "FrameAllocatorInit");
    if (multiboot_info_phys == 0)
    {
        PanicFrame("null Multiboot2 info pointer");
    }

    // Summarise the memory map for boot diagnostics. This output is small
    // (typical QEMU runs produce <10 entries), readable on any serial
    // console, and the single fastest way to identify "the firmware handed
    // us something weird" bugs.
    SerialWrite("[mm] Multiboot2 memory map:\n");
    ForEachMmapEntry(multiboot_info_phys,
                     [&](const MultibootMmapEntry& entry)
                     {
                         SerialWrite("  base=");
                         SerialWriteHex(entry.base_addr);
                         SerialWrite(" len=");
                         SerialWriteHex(entry.length);
                         SerialWrite(" type=");
                         switch (entry.type)
                         {
                         case kMmapTypeAvailable:
                             SerialWrite("available");
                             break;
                         case kMmapTypeReserved:
                             SerialWrite("reserved");
                             break;
                         case kMmapTypeAcpiReclaimable:
                             SerialWrite("acpi-reclaimable");
                             break;
                         case kMmapTypeAcpiNvs:
                             SerialWrite("acpi-nvs");
                             break;
                         case kMmapTypeBadRam:
                             SerialWrite("bad-ram");
                             break;
                         default:
                             SerialWrite("unknown");
                             break;
                         }
                         SerialWrite("\n");
                     });

    const u64 highest = ComputeHighestUsableAddr(multiboot_info_phys);
    if (highest == 0)
    {
        PanicFrame("Multiboot2 info has no memory map");
    }

    g_bitmap_frames = (highest + kPageSize - 1) >> kPageSizeLog2;
    g_bitmap_bytes = (g_bitmap_frames + 7) >> 3;

    const auto* info = reinterpret_cast<const MultibootInfoHeader*>(multiboot_info_phys);
    const u64 info_size = info->total_size;

    const u64 home = FindBitmapHome(multiboot_info_phys, info_size, g_bitmap_bytes);
    if (home == 0)
    {
        PanicFrame("no available region large enough for the bitmap");
    }

    // Store the bitmap as a KERNEL-HALF VA, not the raw phys address.
    // Reason: at boot the kernel runs on the boot PML4 which identity-
    // maps the first 1 GiB, so `home` (a low phys addr) is a valid VA
    // there. But per-process ASes (AddressSpaceCreate) zero PML4[0];
    // the identity map disappears, and any kernel code running on a
    // task's AS that dereferences g_bitmap would #PF. Routing through
    // PhysToVirt puts the pointer in PML4[511] (the direct map) which
    // IS copied into every AS, so AllocateFrame remains reachable from
    // syscall context no matter which task is on-CPU. Triggered by
    // the Linux sys_mmap path, which is the first kernel consumer to
    // call AllocateFrame on an active user AS.
    g_bitmap = static_cast<u8*>(PhysToVirt(home));

    // Default every bit to "used". Only explicit "available" regions flip
    // back to "free" below — anything the bootloader didn't describe stays
    // reserved by construction.
    for (u64 i = 0; i < g_bitmap_bytes; ++i)
    {
        g_bitmap[i] = 0xFF;
    }
    g_total_frames = g_bitmap_frames;
    g_free_count = 0;

    ForEachMmapEntry(multiboot_info_phys,
                     [&](const MultibootMmapEntry& entry)
                     {
                         if (entry.type != kMmapTypeAvailable)
                         {
                             return;
                         }

                         const u64 first = (entry.base_addr + kPageSize - 1) >> kPageSizeLog2;
                         const u64 last = (entry.base_addr + entry.length) >> kPageSizeLog2;
                         for (u64 f = first; f < last; ++f)
                         {
                             BitmapMarkFree(f);
                         }
                     });

    // Low 1 MiB hosts BIOS structures, video memory, and real-mode IVT.
    // Even if Multiboot2 claimed it's "available", we never allocate from
    // there — too much legacy hardware still pokes around down here.
    ReserveRange(0, 0x100000);

    // Kernel image.
    ReserveRange(reinterpret_cast<u64>(_kernel_start_phys), reinterpret_cast<u64>(_kernel_end_phys));

    // The bitmap itself.
    ReserveRange(home, home + g_bitmap_bytes);

    // Multiboot2 info structure — we still need to read it past Init, and
    // downstream code may parse more tags. Pin its whole page range. Use
    // info_size captured before any bitmap writes: FindBitmapHome already
    // placed the bitmap past this range, so it's safe — but keeping the
    // captured value is defensive.
    ReserveRange(multiboot_info_phys, multiboot_info_phys + info_size);

    // Frame 0 is never handed out — it aliases kNullFrame, used as the
    // "no memory" sentinel. Defense in depth over the 1 MiB reserve above.
    BitmapMarkUsed(0);

    g_next_hint = 0;
}

PhysAddr AllocateFrame()
{
    for (u64 i = 0; i < g_bitmap_frames; ++i)
    {
        const u64 frame = g_next_hint + i;
        if (frame >= g_bitmap_frames)
        {
            // Wrap the hint and try from 0.
            g_next_hint = 0;
            return AllocateFrame();
        }

        if (!BitmapIsUsed(frame))
        {
            BitmapMarkUsed(frame);
            g_next_hint = frame + 1;
            const PhysAddr phys = frame << kPageSizeLog2;
            // Zero the frame before handing it out. Prevents any
            // stale content (a reaper'd task struct, freed kheap
            // chunk, previous user process's page) from leaking
            // into the new owner. Hardens against info-leak
            // primitives in future user-visible allocation paths
            // (SYS_MMAP etc.): a malicious process that allocates
            // a fresh page and reads it sees only zeros.
            //
            // Only frames inside the 1 GiB direct map are
            // reachable for zeroing today. A frame above the
            // direct-map window has no virtual alias we can
            // safely touch without spilling the allocator into
            // MapMmio during bring-up. Until a dynamic-direct-map
            // or MapMmio-based zeroing helper lands, halt loud
            // rather than quietly hand out un-zeroed memory —
            // that would be an info-leak primitive as soon as a
            // user-visible allocator (SYS_MMAP, page-cache) gets
            // a consumer with >1 GiB of RAM. Bitmap initialisation
            // already reserves memory past the direct-map window
            // as used, so this branch should be unreachable today;
            // the panic is defence-in-depth against a future
            // caller accidentally freeing or coloring a high
            // frame back into the pool.
            //
            // Cost: 4 KiB memset per allocation. Boot does hundreds
            // of these (~ms total). If this ever shows up in a
            // profile, a GFP_ZERO / GFP_NOZERO split is the fix.
            if (phys >= kDirectMapBytes)
            {
                PanicFrame("AllocateFrame: frame past direct map, cannot zero");
            }
            auto* virt = static_cast<u8*>(PhysToVirt(phys));
            for (u64 b = 0; b < kPageSize; ++b)
            {
                virt[b] = 0;
            }
            return phys;
        }
    }
    // Physical memory exhausted. Warn once per boot — repeat spam
    // during a sustained OOM storm helps nobody. Callers get the
    // kNullFrame return value to react to.
    KLOG_ONCE_WARN("mm/frame", "out of physical frames (AllocateFrame)");
    return kNullFrame;
}

void FreeFrame(PhysAddr frame)
{
    if (frame == kNullFrame)
    {
        return; // Freeing a null pointer is a no-op, matches convention.
    }
    const u64 index = frame >> kPageSizeLog2;

    // Double-free detection (Class A in runtime-recovery-strategy.md).
    // Silently marking an already-free frame "free" would let the bit
    // stay set for a real allocation that happened after the first
    // free, corrupting the bitmap's view of reality. Halt loudly so
    // the guilty caller is visible in the panic banner rather than
    // manifesting later as a surprise double-allocation.
    //
    // Out-of-range indices already return "used" from BitmapIsUsed
    // by default, so they bypass this check — reserved memory past
    // the bitmap coverage is never actually freed.
    if (index < g_bitmap_frames && !BitmapIsUsed(index))
    {
        core::PanicWithValue("mm/frame_allocator", "FreeFrame on already-free frame (double-free?)", frame);
    }

    BitmapMarkFree(index);
    if (index < g_next_hint)
    {
        g_next_hint = index;
    }
}

PhysAddr AllocateContiguousFrames(u64 count)
{
    if (count == 0 || count > g_bitmap_frames)
    {
        return kNullFrame;
    }
    if (count == 1)
    {
        return AllocateFrame();
    }

    // Linear scan for a run of `count` consecutive free frames. v0: O(n).
    // Replace with a freelist of contiguous runs when allocation patterns
    // demand it (i.e., when we see the cost in profiles, not before).
    u64 run_start = 0;
    u64 run_len = 0;
    for (u64 frame = 0; frame < g_bitmap_frames; ++frame)
    {
        if (BitmapIsUsed(frame))
        {
            run_len = 0;
            continue;
        }
        if (run_len == 0)
        {
            run_start = frame;
        }
        ++run_len;
        if (run_len == count)
        {
            for (u64 f = run_start; f < run_start + count; ++f)
            {
                BitmapMarkUsed(f);
            }
            // Don't advance g_next_hint — single-frame allocations may still
            // find earlier free slots that this scan skipped over.
            return run_start << kPageSizeLog2;
        }
    }
    KLOG_WARN_V("mm/frame", "no contiguous run available; requested frames", count);
    return kNullFrame;
}

void FreeContiguousFrames(PhysAddr base, u64 count)
{
    if (base == kNullFrame || count == 0)
    {
        return;
    }
    const u64 first = base >> kPageSizeLog2;
    for (u64 i = 0; i < count; ++i)
    {
        const u64 idx = first + i;
        if (idx < g_bitmap_frames && !BitmapIsUsed(idx))
        {
            // Same double-free logic as FreeFrame. A run is treated
            // as "in use" iff every frame in it is in use; freeing a
            // run where any frame is already free means someone else
            // released part of it already — bitmap state is no longer
            // consistent with what the caller thought it owned.
            core::PanicWithValue("mm/frame_allocator", "FreeContiguousFrames: frame already free in run",
                                 idx << kPageSizeLog2);
        }
        BitmapMarkFree(idx);
    }
    if (first < g_next_hint)
    {
        g_next_hint = first;
    }
}

u64 TotalFrames()
{
    return g_total_frames;
}

u64 FreeFramesCount()
{
    return g_free_count;
}

void FrameAllocatorSelfTest()
{
    KLOG_TRACE_SCOPE("mm/frame", "FrameAllocatorSelfTest");
    SerialWrite("[mm] frame allocator self-test\n");

    const u64 free_before = g_free_count;

    const PhysAddr a = AllocateFrame();
    const PhysAddr b = AllocateFrame();
    const PhysAddr c = AllocateFrame();

    if (a == kNullFrame || b == kNullFrame || c == kNullFrame)
    {
        PanicFrame("self-test: initial allocation returned null");
    }
    if (a == b || b == c || a == c)
    {
        PanicFrame("self-test: duplicate frames handed out");
    }

    SerialWrite("  alloc A    : ");
    SerialWriteHex(a);
    SerialWrite("\n");
    SerialWrite("  alloc B    : ");
    SerialWriteHex(b);
    SerialWrite("\n");
    SerialWrite("  alloc C    : ");
    SerialWriteHex(c);
    SerialWrite("\n");

    FreeFrame(a);
    FreeFrame(b);
    FreeFrame(c);

    if (g_free_count != free_before)
    {
        PanicFrame("self-test: free count did not return to baseline");
    }

    // The hint was rewound to min(a,b,c) by the first Free, so the next
    // allocation should reuse the lowest freed frame.
    const PhysAddr reuse = AllocateFrame();
    if (reuse != a && reuse != b && reuse != c)
    {
        PanicFrame("self-test: realloc did not reuse freed frame");
    }
    SerialWrite("  realloc    : ");
    SerialWriteHex(reuse);
    SerialWrite(" (reused A/B/C)\n");
    FreeFrame(reuse);

    // Contiguous-run allocation. The kernel heap depends on this returning
    // a base whose successor frames are also reserved — verify by probing
    // each frame index inside the run.
    constexpr u64 kRun = 8;
    const PhysAddr run_base = AllocateContiguousFrames(kRun);
    if (run_base == kNullFrame)
    {
        PanicFrame("self-test: contiguous allocation returned null");
    }
    if ((run_base & (kPageSize - 1)) != 0)
    {
        PanicFrame("self-test: contiguous base not page-aligned");
    }
    for (u64 i = 0; i < kRun; ++i)
    {
        const u64 frame_index = (run_base >> kPageSizeLog2) + i;
        if (!BitmapIsUsed(frame_index))
        {
            PanicFrame("self-test: contiguous run has free frames inside it");
        }
    }
    SerialWrite("  contig x");
    SerialWriteHex(kRun);
    SerialWrite(" : ");
    SerialWriteHex(run_base);
    SerialWrite("\n");
    FreeContiguousFrames(run_base, kRun);

    SerialWrite("[mm] frame allocator self-test OK\n");
}

} // namespace duetos::mm
