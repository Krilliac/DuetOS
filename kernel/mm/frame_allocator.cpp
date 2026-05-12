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

#include "mm/frame_allocator.h"

#include "mm/multiboot2.h"
#include "mm/page.h"
#include "mm/poison.h"
#include "multiboot2_rust.h"

#include "acpi/acpi.h"
#include "acpi/srat.h"
#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "cpu/percpu.h"
#include "cpu/topology.h"
#include "debug/probes.h"
#include "diag/fix_journal.h"
#include "diag/kdbg.h"
#include "log/klog.h"
#include "core/panic.h"
#include "util/debug_assert.h"
#include "util/saturating.h"

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
constinit u64 g_peak_used_frames = 0;

// NUMA bias state. Built from SRAT memory-affinity records during
// FrameAllocatorInit (or, if SRAT was parsed AFTER init, lazily on
// first NUMA-aware allocate). Each node carries the union span of
// its memory-affinity records as [start_frame, end_frame_exclusive)
// — the bitmap stays a single global array; only the search start
// position is biased toward locality. Per-node hints round-robin
// inside the span so concurrent CPUs on the same node don't all
// hammer the same bit.
//
// `g_numa_node_count` mirrors `acpi::srat::SratNodeCount()` once
// `FrameAllocatorBuildNumaRanges` has run; zero means "no SRAT
// records, every alloc takes the global linear-scan path"
// (UMA-equivalent behaviour, byte-for-byte the pre-NUMA path).
constinit u64 g_node_start_frame[acpi::srat::kMaxNumaNodes] = {};
constinit u64 g_node_end_frame[acpi::srat::kMaxNumaNodes] = {};
constinit u64 g_node_hint[acpi::srat::kMaxNumaNodes] = {};
constinit u8 g_numa_node_count = 0;

// Test-only OOM injection. Set via FrameAllocatorSetFailAfter; each
// successful Allocate* path decrements. When zero is reached the
// next Allocate* returns kNullFrame and the counter stays at 0
// (further injection requires another SetFailAfter call). 0 disables.
constinit u64 g_fail_after = 0;

// Per-CPU warm pool. Each CPU caches up to kFramePoolDepth recently-
// freed frames. AllocateFrame's fast path pops from the running CPU's
// pool, skipping the bitmap scan entirely; FreeFrame's fast path
// pushes onto the pool, skipping BitmapMarkFree. Pool entries stay
// bitmap=USED for their entire pool lifetime so a peer CPU walking
// the bitmap can never hand the same frame out twice.
//
// Trade: a fixed memory cap (kFramePoolDepth * acpi::kMaxCpus * 8 B
// = 2 KiB worst case for 32-CPU box) plus up to 8 frames per CPU
// of "cached" memory that doesn't show up in FreeFramesCount() in
// exchange for O(1) alloc/free on the size class that dominates
// kheap and slab churn. The pool can be drained explicitly via
// FrameAllocatorDrainPools when the bitmap-accurate count matters
// (boot self-test, memory-pressure responses).
inline constexpr u32 kFramePoolDepth = 8;

struct FramePool
{
    u32 count;
    u32 _pad;
    PhysAddr frames[kFramePoolDepth];
};

constinit FramePool g_frame_pools[acpi::kMaxCpus] = {};
// Frame-pool hit counters — saturating per class BB (wrap → defense
// gap in long-running boots). Read by inspect / shell health command;
// never used for arithmetic that depends on modular wrap.
constinit util::SatU64 g_pool_alloc_hits = 0;
constinit util::SatU64 g_pool_free_hits = 0;

constexpr u64 kFrameRflagsIfBit = 1ULL << 9;

inline u64 FrameReadRflags()
{
    u64 f;
    asm volatile("pushfq; pop %0" : "=r"(f)::"memory");
    return f;
}

// IRQ-off scope guard for pool fast paths. Disabling interrupts on
// the running CPU pins us there (no migration mid-access) and keeps
// any IRQ handler that itself allocates frames from observing a
// half-updated pool.
struct FramePoolIrqOff
{
    u64 saved_rflags;
    FramePoolIrqOff() : saved_rflags(FrameReadRflags()) { arch::Cli(); }
    ~FramePoolIrqOff()
    {
        if ((saved_rflags & kFrameRflagsIfBit) != 0)
        {
            arch::Sti();
        }
    }
    FramePoolIrqOff(const FramePoolIrqOff&) = delete;
    FramePoolIrqOff& operator=(const FramePoolIrqOff&) = delete;
};

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
        const u64 used = g_total_frames - g_free_count;
        if (used > g_peak_used_frames)
        {
            g_peak_used_frames = used;
        }
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
// Multiboot2 tag iteration. The info structure is bootloader-controlled, so
// every cursor advance + mmap entry decode goes through the Rust walker in
// kernel/mm/multiboot2_rust/. This C++ shim turns the kernel-side
// `MultibootMmapEntry` callback contract into FFI calls.
// ---------------------------------------------------------------------------

// Upper bound on the byte slice the Rust walker is willing to
// trust. We don't know the bootloader's claimed `total_size`
// until we've parsed the header, so we pass an upper-bound here
// that's:
//   (a) larger than any plausible real info block (GRUB ships
//       ~1 KiB; we cap at 64 MiB inside the Rust crate too),
//   (b) reachable from `info_phys` via the kernel's identity
//       direct map (PagingInit maps the first 1 GiB physical →
//       higher-half, and the info struct always lives in low
//       memory because GRUB places it right after the kernel
//       image).
// The Rust parser cross-checks that the bootloader's claimed
// `total_size` doesn't exceed this bound AND doesn't exceed its
// own 64 MiB hard cap.
constexpr usize kMultibootProbeUpperBoundBytes = 64u * 1024u * 1024u;

template <typename Callback> void ForEachMmapEntry(uptr info_phys, Callback&& cb)
{
    using namespace ::duetos::mm::multiboot2_rust;
    const u8* info = reinterpret_cast<const u8*>(info_phys);

    DuetosMultibootInfoHeader hdr = {};
    if (!duetos_multiboot2_parse_header(info, kMultibootProbeUpperBoundBytes, &hdr))
    {
        return;
    }
    const usize info_len = static_cast<usize>(hdr.total_size);

    u32 cursor = static_cast<u32>(sizeof(MultibootInfoHeader));
    for (u32 hops = 0; hops < MULTIBOOT_TAG_HOP_CAP; ++hops)
    {
        DuetosMultibootTag tag = {};
        if (!duetos_multiboot2_next_tag(info, info_len, cursor, &tag))
        {
            break;
        }
        if (tag.tag_type == MULTIBOOT_TAG_END)
        {
            break;
        }

        if (tag.tag_type == MULTIBOOT_TAG_MMAP)
        {
            DuetosMultibootMmap mmap = {};
            if (duetos_multiboot2_parse_mmap(info, info_len, tag.offset, tag.size, &mmap))
            {
                u32 entry_off = mmap.entries_offset;
                const u32 entries_end = mmap.entries_offset + mmap.entries_byte_len;
                while (entry_off + mmap.entry_size <= entries_end)
                {
                    DuetosMultibootMmapEntry e = {};
                    if (!duetos_multiboot2_parse_mmap_entry(info, info_len, entry_off, &e))
                    {
                        break;
                    }
                    // Translate to the kernel-side C++ shape that
                    // the existing callbacks expect.
                    MultibootMmapEntry kernel_entry{};
                    kernel_entry.base_addr = e.base_addr;
                    kernel_entry.length = e.length;
                    kernel_entry.type = e.entry_type;
                    kernel_entry.reserved = e.reserved;
                    cb(kernel_entry);
                    entry_off += mmap.entry_size;
                }
            }
        }

        cursor = tag.next_offset;
        if (cursor >= info_len)
        {
            break;
        }
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

    // Firmware MMIO windows. On a well-behaved BIOS / UEFI these are
    // already marked "reserved" in the Multiboot2 mmap (so the
    // "available" pass above never flipped their bits free in the
    // first place). On a real-hardware box where firmware lied and
    // reported these as available — or where the mmap simply stops
    // below 0xFEE00000 and our `highest` extended the bitmap past it
    // (any machine with > 4 GiB RAM crosses this threshold) — the
    // bitmap would happily hand the LAPIC's MMIO page to a kernel
    // allocator, and the next LapicWrite would scribble onto random
    // kheap memory. Belt-and-braces: reserve the canonical xAPIC
    // windows at every boot.
    //
    //   0xFEC00000  IOAPIC base (one 4 KiB window; multi-IOAPIC
    //               firmware may use additional pages — covered by
    //               the BIOS' "reserved" mmap entry for the wider
    //               range).
    //   0xFED00000  HPET base (one 4 KiB window).
    //   0xFEE00000  LAPIC base (one 4 KiB window).
    //
    // The actual LAPIC base is read from IA32_APIC_BASE later, so a
    // relocated LAPIC won't be covered here — but the default
    // address is what 99%+ of real hardware uses, and the firmware
    // mmap should cover any relocated case.
    ReserveRange(0xFEC00000ull, 0xFEC00000ull + 0x1000);
    ReserveRange(0xFED00000ull, 0xFED00000ull + 0x1000);
    ReserveRange(0xFEE00000ull, 0xFEE00000ull + 0x1000);

    // SMP AP trampoline frame at 0x8000 — used by ap_trampoline.S
    // when the BSP brings APs up via INIT/SIPI/SIPI. It's already
    // covered by the broad 0..1MiB reserve above, but a future
    // change that tightens the low reserve (e.g. for ISA DMA
    // bounce buffers) would silently re-enable allocation from
    // 0x8000 and corrupt the in-flight AP image during bring-up.
    // Mark it explicitly so the dependency is greppable.
    BitmapMarkUsed(0x8000 >> kPageSizeLog2);

    // Frame 0 is never handed out — it aliases kNullFrame, used as the
    // "no memory" sentinel. Defense in depth over the 1 MiB reserve above.
    BitmapMarkUsed(0);

    g_peak_used_frames = g_total_frames - g_free_count;
    g_next_hint = 0;
}

// Inner search shared by `AllocateFrame` and `AllocateFrameInRange`.
// `max_frames` clamps the highest frame index considered (exclusive).
// Returns the bitmap index on success or `g_bitmap_frames` (a
// sentinel one past the end) on failure.
namespace
{

// Walk [lo, hi) byte-wise looking for any 0 bit. Returns the frame
// index of the first free bit found, or g_bitmap_frames on miss.
// Whole-byte stride lets a fully-used 8-frame region be rejected
// in a single load + compare instead of 8 bit tests, which is the
// dominant cost on a large mostly-used bitmap.
u64 BitmapFindFreeLinear(u64 lo, u64 hi)
{
    if (lo >= hi)
        return g_bitmap_frames;
    // Handle the (possibly partial) first byte explicitly so the
    // bulk loop below can assume byte-aligned input.
    u64 byte_idx = lo >> 3;
    const u32 head_bit = static_cast<u32>(lo & 7u);
    if (head_bit != 0)
    {
        u8 byte = g_bitmap[byte_idx];
        // Mask off bits below lo so we don't return a stale free
        // bit that came before our search window.
        const u8 head_mask = static_cast<u8>((1u << head_bit) - 1u);
        const u8 cand = static_cast<u8>((~byte) & static_cast<u8>(~head_mask));
        if (cand != 0)
        {
            const u32 bit = static_cast<u32>(__builtin_ctz(cand));
            const u64 frame = (byte_idx << 3) + bit;
            if (frame < hi)
                return frame;
            return g_bitmap_frames;
        }
        ++byte_idx;
    }
    // Bulk: byte at a time. Stop at the byte containing hi-1.
    const u64 end_byte = hi >> 3; // exclusive upper for full-byte loop
    while (byte_idx < end_byte)
    {
        const u8 byte = g_bitmap[byte_idx];
        if (byte != 0xFFu)
        {
            const u32 bit = static_cast<u32>(__builtin_ctz(static_cast<u8>(~byte)));
            return (byte_idx << 3) + bit;
        }
        ++byte_idx;
    }
    // Final (possibly partial) tail byte if hi is not byte-aligned.
    const u32 tail_bit = static_cast<u32>(hi & 7u);
    if (tail_bit != 0)
    {
        const u8 byte = g_bitmap[byte_idx];
        const u8 tail_mask = static_cast<u8>((1u << tail_bit) - 1u);
        const u8 cand = static_cast<u8>((~byte) & tail_mask);
        if (cand != 0)
        {
            const u32 bit = static_cast<u32>(__builtin_ctz(cand));
            return (byte_idx << 3) + bit;
        }
    }
    return g_bitmap_frames;
}

u64 BitmapFindFreeBelow(u64 max_frames)
{
    if (max_frames > g_bitmap_frames)
        max_frames = g_bitmap_frames;
    if (max_frames == 0)
        return g_bitmap_frames;
    const u64 start = (g_next_hint < max_frames) ? g_next_hint : 0;
    // Linearize the wrap: scan [start, max_frames) first, then
    // [0, start). Each half drives the byte-stride scan helper.
    const u64 first = BitmapFindFreeLinear(start, max_frames);
    if (first < g_bitmap_frames)
        return first;
    if (start > 0)
    {
        const u64 second = BitmapFindFreeLinear(0, start);
        if (second < g_bitmap_frames)
            return second;
    }
    return g_bitmap_frames;
}

// Search a [lo, hi) bitmap subrange starting at `hint` and wrapping
// inside the subrange. Returns g_bitmap_frames on miss. Used by the
// NUMA-biased path so the calling CPU's local node gets first dibs.
u64 BitmapFindFreeInRange(u64 lo, u64 hi, u64 hint)
{
    if (lo >= g_bitmap_frames)
        return g_bitmap_frames;
    if (hi > g_bitmap_frames)
        hi = g_bitmap_frames;
    if (hi <= lo)
        return g_bitmap_frames;
    if (hint < lo || hint >= hi)
        hint = lo;
    // Linearize the wrap and let the byte-stride scanner do both
    // halves; identical structure to BitmapFindFreeBelow above.
    const u64 first = BitmapFindFreeLinear(hint, hi);
    if (first < g_bitmap_frames)
        return first;
    if (hint > lo)
    {
        const u64 second = BitmapFindFreeLinear(lo, hint);
        if (second < g_bitmap_frames)
            return second;
    }
    return g_bitmap_frames;
}

// Map an APIC-derived NUMA node index to the [start, end) bitmap
// span recorded for it. Returns false when the node has no recorded
// memory-affinity range (degrades to the global path).
bool NumaNodeRange(u8 node, u64* lo, u64* hi, u64* hint)
{
    if (g_numa_node_count == 0 || node >= acpi::srat::kMaxNumaNodes)
        return false;
    const u64 start = g_node_start_frame[node];
    const u64 end = g_node_end_frame[node];
    if (end <= start)
        return false;
    if (lo)
        *lo = start;
    if (hi)
        *hi = end;
    if (hint)
        *hint = g_node_hint[node];
    return true;
}

// Look up the calling CPU's NUMA node. Returns kTopologyUnknownNode
// when the topology table isn't ready, the SRAT didn't register a
// node for this APIC, or the BSP path predates `TopologyInitBsp`.
// Cheap: one PerCpu fetch + one indexed read.
u8 CurrentCpuNumaNode()
{
    using ::duetos::cpu::CurrentCpuIdOrBsp;
    using ::duetos::cpu::kTopologyUnknownNode;
    using ::duetos::cpu::TopologyForCpu;
    const u32 cpu_id = CurrentCpuIdOrBsp();
    const auto* row = TopologyForCpu(cpu_id);
    if (row == nullptr)
        return kTopologyUnknownNode;
    return row->numa_node;
}

PhysAddr AllocateFrameAtIndex(u64 frame)
{
    BitmapMarkUsed(frame);
    g_next_hint = frame + 1;
    const PhysAddr phys = frame << kPageSizeLog2;
    // Same direct-map zero policy as AllocateFrame — we cannot zero
    // a frame past the direct map without spilling into MapMmio,
    // and handing back un-zeroed memory is an info-leak primitive.
    if (phys >= kDirectMapBytes)
        PanicFrame("AllocateFrameAtIndex: frame past direct map, cannot zero");
    auto* virt = static_cast<u8*>(PhysToVirt(phys));
    for (u64 b = 0; b < kPageSize; ++b)
        virt[b] = 0;
    return phys;
}

} // namespace

void FrameAllocatorNumaSelfTest()
{
    arch::SerialWrite("[mm/frame] numa self-test\n");

    // Path 1 — UMA fallback. AllocateFrameNode with a sentinel node
    // (or with the node table empty) routes through the global
    // linear-scan path. Always covered: even on a NUMA boot, a node
    // index past the recorded count is treated as "no range" and
    // falls through.
    const PhysAddr fallback = AllocateFrameNode(acpi::srat::kNoNode);
    if (fallback == kNullFrame)
    {
        core::Panic("mm/frame", "numa self-test: UMA fallback alloc failed");
    }
    FreeFrame(fallback);

    // Path 2 — node-biased. Only meaningful when SRAT registered
    // a memory-affinity record; otherwise the test degrades to the
    // same global-path coverage above. SKIP cleanly so QEMU boots
    // without an SRAT see [SKIP] not panic.
    if (g_numa_node_count == 0)
    {
        arch::SerialWrite("[mm/frame] numa self-test SKIP (no SRAT memory records — UMA boot)\n");
        return;
    }

    // Find the first node with a non-empty range.
    u8 test_node = acpi::srat::kNoNode;
    for (u8 i = 0; i < g_numa_node_count; ++i)
    {
        if (g_node_end_frame[i] > g_node_start_frame[i])
        {
            test_node = i;
            break;
        }
    }
    if (test_node == acpi::srat::kNoNode)
    {
        arch::SerialWrite("[mm/frame] numa self-test SKIP (every node range collapsed to empty)\n");
        return;
    }
    const PhysAddr local = AllocateFrameNode(test_node);
    if (local == kNullFrame)
    {
        core::Panic("mm/frame", "numa self-test: AllocateFrameNode(local) failed");
    }
    const u64 local_frame = local >> kPageSizeLog2;
    if (local_frame < g_node_start_frame[test_node] || local_frame >= g_node_end_frame[test_node])
    {
        // Allowed: the local node was full at boot and the path
        // fell through to the global pool. Log the surprise but
        // don't panic — it's correct behaviour.
        arch::SerialWrite("[mm/frame] numa self-test: node-local exhausted, fell back to global (frame ");
        arch::SerialWriteHex(local_frame);
        arch::SerialWrite(")\n");
    }
    else
    {
        arch::SerialWrite("[mm/frame] numa self-test OK (node-local frame=");
        arch::SerialWriteHex(local_frame);
        arch::SerialWrite(")\n");
    }
    FreeFrame(local);
}

void FrameAllocatorBuildNumaRanges()
{
    KLOG_TRACE_SCOPE("mm/frame", "FrameAllocatorBuildNumaRanges");
    // Reset the per-node table. Idempotent across re-init paths
    // (the slab self-test re-runs SRAT parsing).
    for (u8 i = 0; i < acpi::srat::kMaxNumaNodes; ++i)
    {
        g_node_start_frame[i] = 0;
        g_node_end_frame[i] = 0;
        g_node_hint[i] = 0;
    }
    g_numa_node_count = 0;

    const u8 mem_count = acpi::srat::SratMemoryRangeCount();
    if (mem_count == 0)
    {
        // UMA boot — no SRAT memory-affinity records. AllocateFrame
        // takes the global linear-scan path verbatim.
        KLOG_INFO("mm/frame", "NUMA: no SRAT memory ranges, UMA path active");
        return;
    }

    // Walk every memory-affinity record and update the per-node
    // span union. Multi-range nodes (rare — usually a single 0..N
    // range per node) get the union span.
    for (u8 i = 0; i < mem_count; ++i)
    {
        acpi::srat::MemoryRange r{};
        if (!acpi::srat::SratMemoryRange(i, &r))
            continue;
        if (!r.enabled || r.length == 0)
            continue;
        if (r.node >= acpi::srat::kMaxNumaNodes)
            continue;
        const u64 lo = r.base >> kPageSizeLog2;
        const u64 hi = (r.base + r.length + kPageSize - 1) >> kPageSizeLog2;
        u64& cur_lo = g_node_start_frame[r.node];
        u64& cur_hi = g_node_end_frame[r.node];
        if (cur_hi == 0)
        {
            cur_lo = lo;
            cur_hi = hi;
            g_node_hint[r.node] = lo;
        }
        else
        {
            if (lo < cur_lo)
                cur_lo = lo;
            if (hi > cur_hi)
                cur_hi = hi;
        }
        if (r.node + 1 > g_numa_node_count)
            g_numa_node_count = static_cast<u8>(r.node + 1);
    }

    // Clip every node's span to the bitmap. Some firmware reports
    // memory-affinity records covering MMIO holes or memory above
    // the physical pool we're tracking; clipping keeps the bitmap
    // index in-bounds.
    for (u8 i = 0; i < g_numa_node_count; ++i)
    {
        if (g_node_end_frame[i] > g_bitmap_frames)
            g_node_end_frame[i] = g_bitmap_frames;
        if (g_node_start_frame[i] >= g_bitmap_frames)
        {
            g_node_start_frame[i] = 0;
            g_node_end_frame[i] = 0;
        }
        if (g_node_hint[i] < g_node_start_frame[i] || g_node_hint[i] >= g_node_end_frame[i])
            g_node_hint[i] = g_node_start_frame[i];
    }

    arch::SerialWrite("[mm/frame] NUMA ranges: nodes=");
    arch::SerialWriteHex(g_numa_node_count);
    arch::SerialWrite("\n");
    for (u8 i = 0; i < g_numa_node_count; ++i)
    {
        if (g_node_end_frame[i] == 0)
            continue;
        arch::SerialWrite("[mm/frame]   node ");
        arch::SerialWriteHex(i);
        arch::SerialWrite(": frames [");
        arch::SerialWriteHex(g_node_start_frame[i]);
        arch::SerialWrite(", ");
        arch::SerialWriteHex(g_node_end_frame[i]);
        arch::SerialWrite(") = ");
        arch::SerialWriteHex(g_node_end_frame[i] - g_node_start_frame[i]);
        arch::SerialWrite(" frames\n");
    }
}

PhysAddr AllocateFrameInRange(PhysAddr max_phys)
{
    u64 max_frames = g_bitmap_frames;
    if (max_phys != 0)
    {
        // Round DOWN to a frame index — the constraint is "physical
        // address strictly less than max_phys".
        max_frames = max_phys >> kPageSizeLog2;
    }
    const u64 frame = BitmapFindFreeBelow(max_frames);
    if (frame >= g_bitmap_frames)
    {
        KLOG_ONCE_WARN("mm/frame", "AllocateFrameInRange: no free frame in range");
        return kNullFrame;
    }
    return AllocateFrameAtIndex(frame);
}

namespace
{

// Finalise a successful frame pick — common tail shared by the
// global linear scan and the NUMA-biased path. Performs the kernel-
// PT registry guard, marks the bitmap, advances hints, zeros the
// page, and returns its physical address. `node` is the dense
// NUMA index when the frame came out of a NUMA-biased path
// (so g_node_hint[node] gets its round-robin update), or
// `acpi::srat::kNoNode` for the global path (only g_next_hint
// advances).
PhysAddr ProcessAndReturnFrame(u64 frame, u8 node)
{
    const PhysAddr phys = frame << kPageSizeLog2;
    if (FrameAllocatorIsRegisteredKernelPt(phys))
    {
        core::PanicWithValue("mm/frame_allocator",
                             "AllocateFrame returning a registered kernel-PT frame (stale free upstream)", phys);
    }
    BitmapMarkUsed(frame);
    g_next_hint = frame + 1;
    if (node != acpi::srat::kNoNode && node < acpi::srat::kMaxNumaNodes)
    {
        g_node_hint[node] = frame + 1;
    }
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

} // namespace

PhysAddr AllocateFrameNode(u8 node)
{
    if (g_fail_after != 0)
    {
        if (g_fail_after == 1)
        {
            g_fail_after = 0;
            return kNullFrame;
        }
        --g_fail_after;
    }
    u64 lo = 0;
    u64 hi = 0;
    u64 hint = 0;
    if (NumaNodeRange(node, &lo, &hi, &hint))
    {
        const u64 frame = BitmapFindFreeInRange(lo, hi, hint);
        if (frame < g_bitmap_frames)
        {
            return ProcessAndReturnFrame(frame, node);
        }
        // Local node exhausted — fall through to the global path.
        // Same-node OOM is rare on a healthy NUMA box; when it
        // happens we'd rather have a remote frame than fail the
        // allocation.
    }
    // Global linear scan (UMA fallback). Identical semantics to the
    // pre-NUMA AllocateFrame loop.
    for (u64 i = 0; i < g_bitmap_frames; ++i)
    {
        u64 frame = g_next_hint + i;
        if (frame >= g_bitmap_frames)
            frame -= g_bitmap_frames;
        if (!BitmapIsUsed(frame))
        {
            return ProcessAndReturnFrame(frame, /*node=*/acpi::srat::kNoNode);
        }
    }
    KLOG_ONCE_WARN("mm/frame", "out of physical frames (AllocateFrameNode)");
    KLOG_CRITICAL_A(::duetos::core::LogArea::Memory, "mm/frame", "AllocateFrameNode: physical OOM");
    KDBG(Mm, "mm/frame", "AllocateFrameNode OOM");
    KBP_PROBE(::duetos::debug::ProbeId::kPhysAllocFail);
    // Journal the OOM as a SoftFaultRecov: the caller's null-handling
    // is the workaround that's now load-bearing. Pin = "mm/frame-alloc"
    // so dedup groups every physical OOM under a single record (the
    // journal must not amplify pressure under sustained allocation
    // failures). ctx_a is the frames-free-at-fail count so the off-line
    // tooling can see whether the request was just outsized vs. the
    // bitmap was actually exhausted.
    (void)::duetos::diag::FixJournalRecordSev(
        ::duetos::diag::FixDetector::SoftFaultRecov, "mm/frame-alloc",
        "physical OOM: AllocateFrameNode returned kNullFrame; investigate caller's null-handling and frame budget",
        FreeFramesCount(), /*ctx_b=*/0, /*severity=*/2);
    return kNullFrame;
}

PhysAddr AllocateFrame()
{
    // ---- Per-CPU warm pool fast path ------------------------------
    // Skip when OOM injection is active so the test counter still
    // drives the failing leg the slow path is meant to exercise.
    if (g_fail_after == 0)
    {
        PhysAddr from_pool = kNullFrame;
        {
            FramePoolIrqOff guard;
            const u32 cpu = cpu::CurrentCpuIdOrBsp();
            if (cpu < acpi::kMaxCpus)
            {
                FramePool& p = g_frame_pools[cpu];
                if (p.count > 0)
                {
                    from_pool = p.frames[--p.count];
                    ++g_pool_alloc_hits;
                }
            }
        }
        if (from_pool != kNullFrame)
        {
            // Frame is bitmap=USED already (it came from FreeFrame's
            // pool push, which keeps the bitmap bit set). Zero before
            // returning to satisfy the same info-leak invariant as
            // the slow path: any prior content (including the 0xDE
            // poison stamped on free) is wiped before a new caller
            // can read it.
            if (from_pool >= kDirectMapBytes)
            {
                PanicFrame("AllocateFrame: pool frame past direct map, cannot zero");
            }
            auto* virt = static_cast<u8*>(PhysToVirt(from_pool));
            for (u64 b = 0; b < kPageSize; ++b)
            {
                virt[b] = 0;
            }
            return from_pool;
        }
    }

    // Hot path with NUMA bias. When SRAT memory-affinity records
    // were registered, route through `AllocateFrameNode` with the
    // current CPU's local node (for free on UMA — kNoNode falls
    // straight through to the global scan). The OOM-injection
    // counter is consumed inside `AllocateFrameNode` so the
    // per-test scaffolding still drives the same OOM ladder.
    if (g_numa_node_count > 0)
    {
        return AllocateFrameNode(CurrentCpuNumaNode());
    }

    // UMA / pre-NUMA path — identical behaviour to the original
    // hot loop. Kept verbatim so SRAT-less boots see no regression.
    if (g_fail_after != 0)
    {
        if (g_fail_after == 1)
        {
            g_fail_after = 0;
            return kNullFrame;
        }
        --g_fail_after;
    }
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
            const PhysAddr phys = frame << kPageSizeLog2;
            // Symmetric check to FreeFrame's PT-registry guard:
            // if AllocateFrame is about to return a frame that's
            // currently registered as a live kernel page table,
            // SOMEONE freed it earlier without unregistering. Panic
            // with the offending physical address so the bad caller
            // surfaces in the boot log instead of the kernel
            // silently triple-faulting later when the new owner
            // overwrites the PT.
            if (FrameAllocatorIsRegisteredKernelPt(phys))
            {
                core::PanicWithValue("mm/frame_allocator",
                                     "AllocateFrame returning a registered kernel-PT frame (stale free upstream)",
                                     phys);
            }
            BitmapMarkUsed(frame);
            g_next_hint = frame + 1;
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
    // kNullFrame return value to react to. Critical-level too:
    // an OOM is a degraded-but-running event and should pop above
    // any per-area Warn-and-below filters operators set.
    KLOG_ONCE_WARN("mm/frame", "out of physical frames (AllocateFrame)");
    KLOG_CRITICAL_A(::duetos::core::LogArea::Memory, "mm/frame", "AllocateFrame: physical OOM");
    KDBG(Mm, "mm/frame", "AllocateFrame OOM");
    KBP_PROBE(::duetos::debug::ProbeId::kPhysAllocFail);
    return kNullFrame;
}

void FreeFrame(PhysAddr frame)
{
    if (frame == kNullFrame)
    {
        return; // Freeing a null pointer is a no-op, matches convention.
    }
    // A non-page-aligned frame address means the caller computed it
    // wrong — masking the low bits would silently free an unrelated
    // adjacent frame. Halt loudly so the corruption stops here.
    if ((frame & (kPageSize - 1)) != 0)
    {
        core::PanicWithValue("mm/frame_allocator", "FreeFrame called with non-page-aligned address", frame);
    }
    // Guard against any caller freeing a frame that backs the kernel
    // image (.text / .rodata / .data / .bss / boot tables). Those
    // frames are reserved at FrameAllocatorInit and never legitimately
    // handed out, so a FreeFrame call inside that range is always a
    // caller bug.
    const u64 kimg_start = reinterpret_cast<u64>(_kernel_start_phys);
    const u64 kimg_end = reinterpret_cast<u64>(_kernel_end_phys);
    if (frame >= kimg_start && frame < kimg_end)
    {
        core::PanicWithValue("mm/frame_allocator", "FreeFrame attempts to free a kernel-image frame (bug in caller)",
                             frame);
    }
    // Guard against freeing a frame that's currently in use as a
    // kernel page table. SplitPsPage allocates new PT frames during
    // ProtectKernelImage; any FreeFrame on one of those is a bug
    // that would corrupt kernel-half page tables and triple-fault.
    if (FrameAllocatorIsRegisteredKernelPt(frame))
    {
        core::PanicWithValue("mm/frame_allocator",
                             "FreeFrame attempts to free a kernel page-table frame (bug in caller)", frame);
    }
    const u64 index = frame >> kPageSizeLog2;
    // Documentation-of-invariant: by this point we've already checked
    // alignment, so `index` is the unique frame number for this
    // physical address. The bit we touch in the bitmap below is a
    // function of `index`, not `frame` directly; the assert pins the
    // expectation that the conversion is well-formed.
    DEBUG_ASSERT(frame == (index << kPageSizeLog2), "mm/frame_allocator", "frame⇄index round-trip mismatch");

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

    // Freed-page poison (plan C2). Stamp 0xDE across the whole 4 KiB
    // page just before returning it to the bitmap. A use-after-free
    // reader sees an obviously stale pattern instead of plausible
    // stale data; the next AllocateFrame caller is expected to
    // initialise the page before reading. Cheap (one 4 KiB store
    // per free), unconditional. The page is reachable through the
    // higher-half direct map.
    PoisonFreedPage(PhysToVirt(frame), kPageSize);

    // ---- Per-CPU warm pool fast path ------------------------------
    // Park the freed frame on the running CPU's pool instead of
    // marking the bitmap bit clear. The bitmap bit stays set so a
    // peer CPU's slow-path scan can never hand the same frame out
    // twice. AllocateFrame's matching fast path will pop it back
    // (after re-zeroing) without a bitmap walk.
    {
        FramePoolIrqOff guard;
        const u32 cpu = cpu::CurrentCpuIdOrBsp();
        if (cpu < acpi::kMaxCpus)
        {
            FramePool& p = g_frame_pools[cpu];
            if (p.count < kFramePoolDepth)
            {
                p.frames[p.count++] = frame;
                ++g_pool_free_hits;
                return;
            }
        }
    }

    BitmapMarkFree(index);
    if (index < g_next_hint)
    {
        g_next_hint = index;
    }
}

void FrameAllocatorDrainPools()
{
    // Push every per-CPU pool entry back onto the bitmap. Visit each
    // pool in turn — the frame allocator is single-threaded today, so
    // walking peer pools without IPI/lock is fine. Once SMP makes
    // FreeFrame concurrent, this becomes "drain MY pool" + a broadcast
    // IPI that asks each peer to drain its own.
    for (u32 cpu = 0; cpu < acpi::kMaxCpus; ++cpu)
    {
        FramePool& p = g_frame_pools[cpu];
        while (p.count > 0)
        {
            const PhysAddr frame = p.frames[--p.count];
            const u64 index = frame >> kPageSizeLog2;
            BitmapMarkFree(index);
            if (index < g_next_hint)
            {
                g_next_hint = index;
            }
        }
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
    // Pool frames are bitmap=USED, so a multi-frame run that's
    // partially in some CPU's pool would be invisible to the
    // contiguous scan and produce a spurious OOM. Drain pools
    // before scanning so every parked frame is once again
    // reachable through the bitmap.
    FrameAllocatorDrainPools();
    // Test-only OOM injection mirrors the AllocateFrame path so multi-
    // frame allocations also exercise the failing leg.
    if (g_fail_after != 0)
    {
        if (g_fail_after == 1)
        {
            g_fail_after = 0;
            return kNullFrame;
        }
        --g_fail_after;
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

PhysAddr AllocateContiguousFramesInRange(u64 count, PhysAddr max_phys)
{
    if (count == 0 || count > g_bitmap_frames)
    {
        return kNullFrame;
    }
    // max_phys == 0 == no upper bound, matching AllocateFrameInRange.
    u64 max_frames = g_bitmap_frames;
    if (max_phys != 0)
    {
        max_frames = max_phys >> kPageSizeLog2;
        if (max_frames > g_bitmap_frames)
            max_frames = g_bitmap_frames;
    }
    if (count > max_frames)
        return kNullFrame;

    // Same linear scan as AllocateContiguousFrames, clamped at
    // max_frames so the WHOLE run sits strictly below max_phys (the
    // last frame in the run is at index max_frames-1, whose physical
    // base is (max_frames-1) << 12 — guaranteed < max_phys because
    // max_frames was rounded down).
    u64 run_start = 0;
    u64 run_len = 0;
    for (u64 frame = 0; frame < max_frames; ++frame)
    {
        if (BitmapIsUsed(frame))
        {
            run_len = 0;
            continue;
        }
        if (run_len == 0)
            run_start = frame;
        ++run_len;
        if (run_len == count)
        {
            for (u64 f = run_start; f < run_start + count; ++f)
                BitmapMarkUsed(f);
            return run_start << kPageSizeLog2;
        }
    }
    KLOG_WARN_V("mm/frame", "no in-range contiguous run available; requested frames", count);
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
        // Freed-page poison (plan C2) — see FreeFrame for rationale.
        PoisonFreedPage(PhysToVirt(idx << kPageSizeLog2), kPageSize);
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

u64 PeakUsedFrames()
{
    return g_peak_used_frames;
}

void FrameAllocatorSetFailAfter(u64 n_remaining)
{
    g_fail_after = n_remaining;
}

u64 FrameAllocatorGetFailAfter()
{
    return g_fail_after;
}

void FrameAllocatorOomInjectionSelfTest()
{
    // Sanity: injection must be disabled at entry.
    if (g_fail_after != 0)
    {
        PanicFrame("FrameAllocatorOomInjectionSelfTest: injection counter non-zero at entry");
    }
    // Inject OOM after exactly two successful allocations. The first
    // two AllocateFrame calls below succeed; the third returns
    // kNullFrame and the counter resets to 0.
    FrameAllocatorSetFailAfter(3);
    const PhysAddr a = AllocateFrame();
    if (a == kNullFrame)
        PanicFrame("FrameAllocatorOomInjectionSelfTest: first AllocateFrame returned null");
    const PhysAddr b = AllocateFrame();
    if (b == kNullFrame)
        PanicFrame("FrameAllocatorOomInjectionSelfTest: second AllocateFrame returned null");
    const PhysAddr c = AllocateFrame();
    if (c != kNullFrame)
        PanicFrame("FrameAllocatorOomInjectionSelfTest: third AllocateFrame should have failed");
    if (g_fail_after != 0)
        PanicFrame("FrameAllocatorOomInjectionSelfTest: counter not consumed");

    // Subsequent allocations succeed (injection is disabled again).
    const PhysAddr d = AllocateFrame();
    if (d == kNullFrame)
        PanicFrame("FrameAllocatorOomInjectionSelfTest: post-injection alloc failed");

    FreeFrame(a);
    FreeFrame(b);
    FreeFrame(d);

    arch::SerialWrite("[frame-test] OOM injection PASS\n");
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

    // Pool frames stay bitmap=USED, so a fast-path absorption of the
    // three frees would leave g_free_count three short of baseline.
    // Drain pools before the check so the assertion reflects total
    // allocator state, not just the fraction in the bitmap.
    FrameAllocatorDrainPools();

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

    // Freed-page poison (plan C2). Allocate a frame, scribble it
    // with a non-poison pattern, free it, then read the page back
    // through its direct-map alias and confirm every byte is
    // kFreedPagePoison. The verification has to happen BEFORE any
    // subsequent AllocateFrame: that path zeros the page before
    // returning it (info-leak hardening), which would wipe the
    // poison we are trying to observe. Reading freed memory via the
    // higher-half direct map is safe in this self-test scope — the
    // bitmap slot is free but the physical page hasn't been handed
    // out, and the direct map keeps the VA mapped.
    const PhysAddr poison_probe = AllocateFrame();
    if (poison_probe == kNullFrame)
    {
        PanicFrame("self-test: poison-probe alloc failed");
    }
    auto* poison_va = static_cast<u8*>(PhysToVirt(poison_probe));
    for (u64 i = 0; i < kPageSize; ++i)
    {
        poison_va[i] = 0xAA;
    }
    FreeFrame(poison_probe);
    const auto* reread = static_cast<const u8*>(PhysToVirt(poison_probe));
    for (u64 i = 0; i < kPageSize; ++i)
    {
        if (reread[i] != kFreedPagePoison)
        {
            PanicFrame("self-test: freed-page poison not applied");
        }
    }
    SerialWrite("  page poison: verified 0xDE across 4 KiB freed page\n");

    SerialWrite("[mm] frame allocator self-test OK\n");
}

// ----------------------------------------------------------------------
// Kernel page-table frame registry
// ----------------------------------------------------------------------
// SplitPsPage allocates new 4 KiB PT frames during ProtectKernelImage
// and never frees them — they're live for the kernel's lifetime. A
// stale-pointer FreeFrame on one of those frames would zero / poison
// the PT, un-mapping every 4 KiB page it covers. The kernel-image
// guard above catches frees inside [_kernel_start_phys,
// _kernel_end_phys), but kernel PT frames live OUTSIDE that range
// (allocated by AllocateFrame post-init). Track them explicitly so
// FreeFrame can panic on any attempt to free one.
//
// 256 slots × 8 bytes = 2 KiB. A typical x86_64 kernel image with
// W^X protection split across .text/.rodata/.data/.bss takes ~10-20
// PTs (one per 2 MiB region the protection flags need to subdivide).
// 256 leaves headroom for future kernel-half mappings (per-CPU areas,
// MMIO arenas) without forcing a dynamic-grow path.
constexpr u32 kMaxKernelPtFrames = 256;
constinit PhysAddr g_kernel_pt_frames[kMaxKernelPtFrames] = {};
constinit u32 g_kernel_pt_count = 0;

void FrameAllocatorRegisterKernelPt(PhysAddr frame)
{
    if (frame == kNullFrame)
        return;
    if (g_kernel_pt_count >= kMaxKernelPtFrames)
    {
        // Best-effort: log once and continue. Late-registered tables
        // aren't covered by the FreeFrame guard, but the kernel still
        // runs — the guard is a defensive net, not a correctness gate.
        KLOG_ONCE_WARN("mm/frame_allocator", "kernel PT registry full — late tables unguarded");
        return;
    }
    g_kernel_pt_frames[g_kernel_pt_count++] = frame;
}

bool FrameAllocatorIsRegisteredKernelPt(PhysAddr frame)
{
    if (frame == kNullFrame)
        return false;
    for (u32 i = 0; i < g_kernel_pt_count; ++i)
    {
        if (g_kernel_pt_frames[i] == frame)
            return true;
    }
    return false;
}

} // namespace duetos::mm
