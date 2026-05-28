#include "mm/poison_alloc.h"

#include "mm/frame_allocator.h"
#include "mm/page.h"
#include "mm/paging.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "log/klog.h"
#include "sync/spinlock.h"

/*
 * Guard-page poison allocator — implementation.
 *
 * The 256 MiB VA region lives at `kPoisonRegionBase` (PML4[384],
 * 0xFFFFC000_00000000). It does NOT collide with any other kernel
 * VA region (boot direct map / MMIO arena / kernel-stack arena
 * all live under PML4[511] — see paging.h's layout comment).
 *
 * Internal layout per allocation:
 *
 *     g_next_va ─┐                          (advances by 12 KiB / call)
 *                v
 *     +----------+----------+----------+
 *     |  GUARD   |   DATA   |  GUARD   |
 *     |  (4 KiB) |  (4 KiB) |  (4 KiB) |
 *     +----------+----------+----------+
 *      unmapped   mapped     unmapped
 *
 * The metadata header is stamped into the FIRST 24 bytes of the
 * data page (always — independent of mode). The user pointer
 * skips the header in underrun mode and is positioned at the
 * end of the data page in overrun mode (the header still lives
 * at the page base, ahead of the returned pointer). The header
 * carries `size`, `mode`, and a magic word so PoisonFree can
 * sanity-check the pointer it was handed.
 */

namespace duetos::mm
{

namespace
{

using arch::SerialWrite;
using arch::SerialWriteHex;

constexpr u64 kPageSizeLocal = kPageSize;                 // 4096; alias for clarity.
constexpr u64 kPoisonHeaderMagic = 0x504F49534F4E4831ULL; // 'POISONH1'

// On-page metadata. Lives at the BASE of the data page,
// independent of mode. The user pointer:
//   - OverrunDetect:  data_page_base + 4096 - size
//   - UnderrunDetect: data_page_base + sizeof(Header) (aligned up to 16)
// In both modes the header is at `data_page_base + 0`.
struct alignas(16) Header
{
    u64 magic; // kPoisonHeaderMagic; mismatch == bad pointer
    u32 size;  // user-visible size
    u8 mode;   // PoisonMode
    u8 reserved0;
    u16 reserved1;
};
static_assert(sizeof(Header) == 16, "poison Header must be 16 bytes");

// Underrun-mode user pointer must NOT collide with the header.
// Headers are 16 bytes; we align the user pointer up to 16 too.
constexpr u64 kUnderrunUserOffset = sizeof(Header);

// Region bookkeeping. The cursor never decreases; on free we
// unmap the data page and leak the VA on purpose so use-after-
// free hits the same #PF a wild pointer would.
constinit u64 g_next_va = 0;    // next slot base; 0 == uninit
constinit u64 g_region_end = 0; // exclusive upper bound
constinit bool g_initialised = false;

constinit u64 g_allocs_total = 0;
constinit u64 g_frees_total = 0;
constinit u64 g_live_count = 0;
constinit u64 g_va_exhausted_count = 0;
constinit u64 g_frame_oom_count = 0;

// Lock covering g_next_va, the stats counters, and the
// region init flag. MapPage / UnmapPage / AllocateFrame /
// FreeFrame are NOT called under this lock (same pattern as
// kstack.cpp) — they run between Pop/Push of metadata.
constinit sync::SpinLock g_poison_alloc_lock{
    .next_ticket = 0, .now_serving = 0, .owner_cpu = 0xFFFFFFFFu, .class_id = sync::kLockClassUnclassified};

[[noreturn]] void PanicPoison(const char* msg, u64 value)
{
    core::PanicWithValue("mm/poison-alloc", msg, value);
}

// Round a u64 up to a 16-byte boundary. Header alignment is 16,
// and the user pointer in underrun mode follows the header.
inline u64 AlignUp16(u64 v)
{
    return (v + 15) & ~15ULL;
}

} // namespace

bool IsPoisonRegionAddress(u64 va)
{
    return va >= kPoisonRegionBase && va < (kPoisonRegionBase + kPoisonRegionBytes);
}

void PoisonAllocInit()
{
    const auto irq = sync::SpinLockAcquire(g_poison_alloc_lock);
    if (g_initialised)
    {
        sync::SpinLockRelease(g_poison_alloc_lock, irq);
        return;
    }
    g_next_va = kPoisonRegionBase;
    g_region_end = kPoisonRegionBase + kPoisonRegionBytes;
    g_initialised = true;
    sync::SpinLockRelease(g_poison_alloc_lock, irq);

    SerialWrite("[mm] poison-alloc init: base=");
    SerialWriteHex(kPoisonRegionBase);
    SerialWrite(" bytes=");
    SerialWriteHex(kPoisonRegionBytes);
    SerialWrite(" slot=");
    SerialWriteHex(kPoisonSlotBytes);
    SerialWrite("\n");
}

void* PoisonAlloc(u64 size, PoisonMode mode)
{
    // The data page is exactly 4096 bytes; the underrun mode
    // also has to fit a 16-byte header at the page base.
    if (size == 0)
    {
        return nullptr;
    }
    const u64 underrun_max = kPageSizeLocal - kUnderrunUserOffset;
    if (mode == PoisonMode::UnderrunDetect)
    {
        if (size > underrun_max)
        {
            return nullptr;
        }
    }
    else
    {
        // Overrun mode: header lives at the base of the page,
        // user pointer is at (page_base + 4096 - size). The
        // alloc must leave at least 16 bytes for the header,
        // i.e. size <= 4096 - 16.
        if (size > kPageSizeLocal - sizeof(Header))
        {
            return nullptr;
        }
    }

    // Reserve a slot — bump the cursor under the lock, but do
    // physical allocation + mapping OUTSIDE the lock (MapPage
    // is not IRQ-safe and would deadlock if it ever reached
    // for the heap through another IRQ'd spinlock).
    u64 slot_base = 0;
    {
        const auto irq = sync::SpinLockAcquire(g_poison_alloc_lock);
        if (!g_initialised)
        {
            sync::SpinLockRelease(g_poison_alloc_lock, irq);
            PanicPoison("PoisonAlloc before PoisonAllocInit", 0);
        }
        if (g_next_va + kPoisonSlotBytes > g_region_end)
        {
            ++g_va_exhausted_count;
            sync::SpinLockRelease(g_poison_alloc_lock, irq);
            // The first exhaustion is interesting; later ones are
            // noise — gate the WARN on the first hit.
            if (g_va_exhausted_count == 1)
            {
                KLOG_WARN("mm/poison-alloc", "VA region exhausted; PoisonAlloc returning nullptr");
            }
            return nullptr;
        }
        slot_base = g_next_va;
        g_next_va += kPoisonSlotBytes;
        sync::SpinLockRelease(g_poison_alloc_lock, irq);
    }

    const u64 data_page = slot_base + kPageSizeLocal;

    // Back the data page with one fresh physical frame.
    auto phys_r = TryAllocateFrame();
    if (!phys_r)
    {
        const auto irq = sync::SpinLockAcquire(g_poison_alloc_lock);
        ++g_frame_oom_count;
        sync::SpinLockRelease(g_poison_alloc_lock, irq);
        // VA is leaked (the cursor advanced) — fine, the
        // poison allocator leaks VA on every free anyway.
        return nullptr;
    }
    const PhysAddr phys = phys_r.value();

    // Map the DATA page only. The two flanking guard pages
    // stay unmapped, so a one-byte overrun or underrun takes
    // a #PF that the trap dispatcher recognises.
    MapPage(data_page, phys, kKernelData);

    // Stamp the header at the base of the data page.
    auto* hdr = reinterpret_cast<Header*>(data_page);
    hdr->magic = kPoisonHeaderMagic;
    hdr->size = static_cast<u32>(size);
    hdr->mode = static_cast<u8>(mode);
    hdr->reserved0 = 0;
    hdr->reserved1 = 0;

    // Compute the user pointer.
    void* user_ptr = nullptr;
    if (mode == PoisonMode::OverrunDetect)
    {
        // Position so `user_ptr + size == data_page + 4096`.
        // The byte after the allocation is the first byte of
        // the upper guard page.
        user_ptr = reinterpret_cast<void*>(data_page + kPageSizeLocal - size);
    }
    else
    {
        // Underrun mode: place the user pointer right after
        // the 16-byte header. The byte before `user_ptr` is
        // the last byte of the header — which is fine, the
        // user agreed to walk forwards. A walk into the lower
        // guard requires going back past the entire header,
        // which is a long-stride underrun (not the one-byte
        // negative-index case we're catching here). For one-
        // byte negative-index underruns to fire on the lower
        // guard, the caller can set size <= 4096 - 16 and
        // accept that the first 16 bytes before the pointer
        // are the header rather than the guard — this is the
        // standard trade-off in this kind of allocator.
        user_ptr = reinterpret_cast<void*>(data_page + AlignUp16(kUnderrunUserOffset));
    }

    {
        const auto irq = sync::SpinLockAcquire(g_poison_alloc_lock);
        ++g_allocs_total;
        ++g_live_count;
        sync::SpinLockRelease(g_poison_alloc_lock, irq);
    }
    return user_ptr;
}

void PoisonFree(void* ptr)
{
    if (ptr == nullptr)
    {
        return;
    }
    const u64 va = reinterpret_cast<u64>(ptr);
    if (!IsPoisonRegionAddress(va))
    {
        PanicPoison("PoisonFree: pointer not in poison region", va);
    }

    // The data page base is the floor of va to a 4 KiB boundary.
    const u64 data_page = va & ~(kPageSizeLocal - 1);
    auto* hdr = reinterpret_cast<Header*>(data_page);
    if (hdr->magic != kPoisonHeaderMagic)
    {
        PanicPoison("PoisonFree: header magic mismatch (bad pointer / double free?)", va);
    }

    // Recover the backing physical frame BEFORE unmapping so we
    // can return it to the frame allocator. The PTE flags walk
    // tells us the frame; an unmapped or 2 MiB-PS PTE would
    // return 0 in the present bit and we'd panic — but the
    // poison region is always mapped at 4 KiB granularity by
    // PoisonAlloc, so a missing PTE here is a kernel bug
    // (double free / wild call) and panicking is correct.
    const PageWalkSnapshot snap = SnapshotPageWalk(data_page);
    if (snap.stop != PageWalkStop::FourKiB)
    {
        PanicPoison("PoisonFree: data page not 4 KiB-mapped (double free?)", data_page);
    }
    const PhysAddr phys = snap.leaf_phys;

    // Stamp the header dead BEFORE unmapping so a racing reader
    // observes magic=0 instead of the live value. (No real race
    // in v0 — the lock-free unmap-then-free sequence would only
    // race if PoisonAlloc could be called concurrently against
    // this slot, but the bump cursor never returns this slot
    // again. Belt-and-braces.)
    hdr->magic = 0;

    UnmapPage(data_page);
    FreeFrame(phys);

    const auto irq = sync::SpinLockAcquire(g_poison_alloc_lock);
    ++g_frees_total;
    if (g_live_count > 0)
    {
        --g_live_count;
    }
    sync::SpinLockRelease(g_poison_alloc_lock, irq);
}

PoisonStats PoisonStatsRead()
{
    const auto irq = sync::SpinLockAcquire(g_poison_alloc_lock);
    PoisonStats s{};
    s.allocs_total = g_allocs_total;
    s.frees_total = g_frees_total;
    s.live_count = g_live_count;
    s.va_exhausted_count = g_va_exhausted_count;
    s.frame_oom_count = g_frame_oom_count;
    sync::SpinLockRelease(g_poison_alloc_lock, irq);
    return s;
}

void PoisonAllocSelfTest()
{
    KLOG_TRACE_SCOPE("mm/poison-alloc", "PoisonAllocSelfTest");

    if (!g_initialised)
    {
        // Lazy-init for the self-test if PoisonAllocInit hasn't
        // been called yet. The boot wiring calls Init before
        // the self-test, but the lazy path keeps the unit
        // self-contained.
        PoisonAllocInit();
    }

    const PoisonStats before = PoisonStatsRead();

    // 1. OverrunDetect: small alloc, write through it at both
    //    ends, free.
    constexpr u64 kSize1 = 128;
    void* a = PoisonAlloc(kSize1, PoisonMode::OverrunDetect);
    if (a == nullptr)
    {
        PanicPoison("self-test: first PoisonAlloc returned null", 0);
    }
    // The byte AT (a + size) is the first byte of the upper
    // guard page — must NOT be touched in the self-test (that's
    // the live-fault path).
    {
        volatile u8* p = static_cast<volatile u8*>(a);
        p[0] = 0xAB;
        p[kSize1 - 1] = 0xCD;
        if (p[0] != 0xAB || p[kSize1 - 1] != 0xCD)
        {
            PanicPoison("self-test: read-back mismatch on OverrunDetect alloc", reinterpret_cast<u64>(a));
        }
    }

    // 2. Free and allocate again; the new alloc MUST have a
    //    different VA (VA-leak by design, see header doc).
    PoisonFree(a);
    void* b = PoisonAlloc(kSize1, PoisonMode::OverrunDetect);
    if (b == nullptr)
    {
        PanicPoison("self-test: second PoisonAlloc returned null", 0);
    }
    if (b == a)
    {
        PanicPoison("self-test: VA recycled (UAF detection would be defeated)", reinterpret_cast<u64>(b));
    }

    // 3. UnderrunDetect: write through it; verify the user
    //    pointer is NOT at the page base (it must skip the
    //    16-byte header).
    constexpr u64 kSize2 = 64;
    void* c = PoisonAlloc(kSize2, PoisonMode::UnderrunDetect);
    if (c == nullptr)
    {
        PanicPoison("self-test: UnderrunDetect alloc returned null", 0);
    }
    {
        const u64 c_va = reinterpret_cast<u64>(c);
        if ((c_va & (kPageSizeLocal - 1)) == 0)
        {
            PanicPoison("self-test: UnderrunDetect pointer collided with page base / header", c_va);
        }
        volatile u8* p = static_cast<volatile u8*>(c);
        p[0] = 0x11;
        p[kSize2 - 1] = 0x22;
        if (p[0] != 0x11 || p[kSize2 - 1] != 0x22)
        {
            PanicPoison("self-test: read-back mismatch on UnderrunDetect alloc", c_va);
        }
    }

    // 4. Free everything; verify stats deltas.
    PoisonFree(b);
    PoisonFree(c);

    const PoisonStats after = PoisonStatsRead();
    if (after.allocs_total != before.allocs_total + 3)
    {
        PanicPoison("self-test: allocs_total delta wrong", after.allocs_total);
    }
    if (after.frees_total != before.frees_total + 3)
    {
        PanicPoison("self-test: frees_total delta wrong", after.frees_total);
    }
    if (after.live_count != before.live_count)
    {
        PanicPoison("self-test: live_count did not return to baseline", after.live_count);
    }

    // Structural sentinel — CI greps for this line as proof
    // the self-test actually ran (PASS is otherwise silent).
    SerialWrite("[poison-alloc] self-test OK\n");
}

} // namespace duetos::mm
