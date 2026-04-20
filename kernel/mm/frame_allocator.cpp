#include "frame_allocator.h"

#include "multiboot2.h"

#include "../arch/x86_64/cpu.h"
#include "../arch/x86_64/serial.h"

extern "C" char _kernel_start[];
extern "C" char _kernel_end[];

namespace customos::mm
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
constinit u8*  g_bitmap          = nullptr;
constinit u64  g_bitmap_frames   = 0;        // number of frames covered
constinit u64  g_bitmap_bytes    = 0;
constinit u64  g_next_hint       = 0;        // search hint for AllocateFrame
constinit u64  g_free_count      = 0;
constinit u64  g_total_frames    = 0;

// ---------------------------------------------------------------------------
// Panic helper — a frame-allocator failure during boot is unrecoverable.
// Print context and halt; no attempt to recover.
// ---------------------------------------------------------------------------
[[noreturn]] void PanicFrame(const char* message)
{
    SerialWrite("\n[panic] mm/frame_allocator: ");
    SerialWrite(message);
    SerialWrite("\n");
    Halt();
}

// ---------------------------------------------------------------------------
// Bitmap primitives.
// ---------------------------------------------------------------------------
inline void BitmapMarkUsed(u64 frame)
{
    if (frame >= g_bitmap_frames)
    {
        return;  // out-of-range frames stay "used" by default; nothing to do.
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
    const u64 last  = (end_phys + kPageSize - 1) >> kPageSizeLog2;
    for (u64 f = first; f < last; ++f)
    {
        BitmapMarkUsed(f);
    }
}

// ---------------------------------------------------------------------------
// Multiboot2 tag iteration. The total_size field in the info header bounds
// the walk; each tag's size field advances to the next (8-byte aligned).
// ---------------------------------------------------------------------------
template <typename Callback>
void ForEachMmapEntry(uptr info_phys, Callback&& cb)
{
    const auto* info = reinterpret_cast<const MultibootInfoHeader*>(info_phys);
    uptr cursor      = info_phys + sizeof(MultibootInfoHeader);
    const uptr end   = info_phys + info->total_size;

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
            uptr entry_addr  = cursor + sizeof(MultibootMmapTag);
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
    ForEachMmapEntry(info_phys, [&](const MultibootMmapEntry& entry) {
        if (entry.type != kMmapTypeAvailable &&
            entry.type != kMmapTypeAcpiReclaimable)
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
// Find a "type == available" region large enough for the bitmap, above the
// kernel image, within the identity-mapped 1 GiB. Returns 0 on failure.
// ---------------------------------------------------------------------------
u64 FindBitmapHome(uptr info_phys, u64 bitmap_bytes)
{
    const u64 kernel_end_phys = reinterpret_cast<u64>(_kernel_end);
    const u64 identity_limit  = 1ULL * 1024 * 1024 * 1024;  // 1 GiB

    u64 chosen = 0;
    ForEachMmapEntry(info_phys, [&](const MultibootMmapEntry& entry) {
        if (chosen != 0 || entry.type != kMmapTypeAvailable)
        {
            return;
        }

        u64 start = entry.base_addr;
        u64 end   = entry.base_addr + entry.length;

        // Must start after the kernel image. If the region overlaps, bump up.
        if (start < kernel_end_phys)
        {
            start = kernel_end_phys;
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
    if (multiboot_info_phys == 0)
    {
        PanicFrame("null Multiboot2 info pointer");
    }

    // Summarise the memory map for boot diagnostics. This output is small
    // (typical QEMU runs produce <10 entries), readable on any serial
    // console, and the single fastest way to identify "the firmware handed
    // us something weird" bugs.
    SerialWrite("[mm] Multiboot2 memory map:\n");
    ForEachMmapEntry(multiboot_info_phys, [&](const MultibootMmapEntry& entry) {
        SerialWrite("  base="); SerialWriteHex(entry.base_addr);
        SerialWrite(" len="); SerialWriteHex(entry.length);
        SerialWrite(" type=");
        switch (entry.type)
        {
            case kMmapTypeAvailable:       SerialWrite("available");        break;
            case kMmapTypeReserved:        SerialWrite("reserved");         break;
            case kMmapTypeAcpiReclaimable: SerialWrite("acpi-reclaimable"); break;
            case kMmapTypeAcpiNvs:         SerialWrite("acpi-nvs");         break;
            case kMmapTypeBadRam:          SerialWrite("bad-ram");          break;
            default:                       SerialWrite("unknown");          break;
        }
        SerialWrite("\n");
    });

    const u64 highest = ComputeHighestUsableAddr(multiboot_info_phys);
    if (highest == 0)
    {
        PanicFrame("Multiboot2 info has no memory map");
    }

    g_bitmap_frames = (highest + kPageSize - 1) >> kPageSizeLog2;
    g_bitmap_bytes  = (g_bitmap_frames + 7) >> 3;

    const u64 home = FindBitmapHome(multiboot_info_phys, g_bitmap_bytes);
    if (home == 0)
    {
        PanicFrame("no available region large enough for the bitmap");
    }

    g_bitmap = reinterpret_cast<u8*>(home);

    // Default every bit to "used". Only explicit "available" regions flip
    // back to "free" below — anything the bootloader didn't describe stays
    // reserved by construction.
    for (u64 i = 0; i < g_bitmap_bytes; ++i)
    {
        g_bitmap[i] = 0xFF;
    }
    g_total_frames = g_bitmap_frames;
    g_free_count   = 0;

    ForEachMmapEntry(multiboot_info_phys, [&](const MultibootMmapEntry& entry) {
        if (entry.type != kMmapTypeAvailable)
        {
            return;
        }

        const u64 first = (entry.base_addr + kPageSize - 1) >> kPageSizeLog2;
        const u64 last  = (entry.base_addr + entry.length) >> kPageSizeLog2;
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
    ReserveRange(reinterpret_cast<u64>(_kernel_start),
                 reinterpret_cast<u64>(_kernel_end));

    // The bitmap itself.
    ReserveRange(home, home + g_bitmap_bytes);

    // Multiboot2 info structure — we still need to read it past Init, and
    // downstream code may parse more tags. Pin its whole page range.
    {
        const auto* info = reinterpret_cast<const MultibootInfoHeader*>(multiboot_info_phys);
        ReserveRange(multiboot_info_phys, multiboot_info_phys + info->total_size);
    }

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
            return frame << kPageSizeLog2;
        }
    }
    return kNullFrame;
}

void FreeFrame(PhysAddr frame)
{
    if (frame == kNullFrame)
    {
        return;  // Freeing a null pointer is a no-op, matches convention.
    }
    const u64 index = frame >> kPageSizeLog2;
    BitmapMarkFree(index);
    if (index < g_next_hint)
    {
        g_next_hint = index;
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

    SerialWrite("  alloc A    : "); SerialWriteHex(a); SerialWrite("\n");
    SerialWrite("  alloc B    : "); SerialWriteHex(b); SerialWrite("\n");
    SerialWrite("  alloc C    : "); SerialWriteHex(c); SerialWrite("\n");

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
    SerialWrite("  realloc    : "); SerialWriteHex(reuse);
    SerialWrite(" (reused A/B/C)\n");
    FreeFrame(reuse);

    SerialWrite("[mm] frame allocator self-test OK\n");
}

} // namespace customos::mm
