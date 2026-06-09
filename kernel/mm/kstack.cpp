#include "mm/kstack.h"

#include "mm/frame_allocator.h"
#include "mm/paging.h"

#include "arch/x86_64/serial.h"
#include "arch/x86_64/smp.h"
#include "core/panic.h"
#include "debug/probes.h"
#include "log/klog.h"
#include "sync/spinlock.h"

namespace duetos::mm
{

namespace
{

using arch::SerialWrite;
using arch::SerialWriteHex;

// Arena bookkeeping. All state is zero-init at .bss time so no
// explicit init call is required; the first AllocateKernelStack
// call finds next_unseen = 0, free_count = 0, bumps the cursor,
// and proceeds.
//
// Slot indices are u32 even though 512 would fit in u16 — u32
// matches the native word width for compare-and-store and keeps
// the stats struct u64-aligned without padding.
constinit u32 g_next_unseen_slot = 0;
constinit u32 g_free_count = 0;
constinit u32 g_free_stack[kKernelStackMaxSlots] = {};

// Shadow table: per-slot record of which physical frame backs
// each stack page. 512 * 4 * 8 = 16 KiB of .bss — cheap for the
// value, which is that FreeKernelStack doesn't have to read the
// PTE back to recover the frame address (VirtToPhys only works
// on direct-map VAs; the stack arena lives outside it). Zero-
// initialised; a zero entry means "no frame installed".
constinit PhysAddr g_slot_frames[kKernelStackMaxSlots][kKernelStackPages] = {};

constinit u64 g_slots_in_use = 0;
constinit u64 g_slots_ever_allocated = 0;
constinit u64 g_slots_freed = 0;
constinit u64 g_high_water_slots = 0;

// Per-thread deep-usage canary (the "tripwire"). A sentinel word written at
// the 75%-used line on allocation; downward stack growth that reaches it
// overwrites it, so a single read at free time (or via the live accessor)
// tells us the thread consumed >= 75% of its 128 KiB slot — an early warning
// it is approaching the guard page (e.g. the deep TLS->x509->ASN.1->RSA/EC
// tower run on a worker thread). O(1): one word written at alloc, one read
// to check — no per-page scan, and re-armed on every alloc so slot reuse is
// safe. Offset is from the USABLE base (just above the guard); rsp dropping
// below it means (usable - offset) bytes used.
constexpr u64 kStackTripwireWord = 0x574952454B435453ULL;         // "STCKWIRE" sentinel
constexpr u64 kStackTripwireOffset = kKernelStackUsableBytes / 4; // 32 KiB -> trips at 75% (96 KiB) used

inline volatile u64* TripwireSlot(uptr usable_base)
{
    return reinterpret_cast<volatile u64*>(usable_base + kStackTripwireOffset);
}

// Dedicated lock for the arena. Covers g_next_unseen_slot,
// g_free_count, g_free_stack, and the stats counters. Does NOT
// cover MapPage / UnmapPage / AllocateFrame / FreeFrame — those
// run outside this lock and inherit the "paging is single-
// threaded in v0" contract from paging.h. SMP bring-up will
// fix the paging layer uniformly; no point bolting a second
// lock on here first.
// Tagged with `kLockClassKStack` for lockdep — see sync/lockdep.h
// for the canonical order convention.
constinit sync::SpinLock g_kstack_lock{
    .next_ticket = 0, .now_serving = 0, .owner_cpu = 0xFFFFFFFFu, .class_id = sync::kLockClassKStack};

[[noreturn]] void PanicKstack(const char* message, u64 value)
{
    core::PanicWithValue("mm/kstack", message, value);
}

inline uptr SlotBase(u32 slot_index)
{
    return kKernelStackArenaBase + static_cast<u64>(slot_index) * kKernelStackSlotBytes;
}

inline uptr UsableBaseFromSlot(u32 slot_index)
{
    return SlotBase(slot_index) + kKernelStackGuardPages * kPageSize;
}

// Map the kKernelStackPages frames that back slot `slot_index`.
// Backing frames do NOT need to be physically contiguous — each
// page is its own AllocateFrame call. If any frame allocation or
// map fails, unwind whatever we had already installed before
// returning false so a failed allocate doesn't leak frames.
//
// Runs OUTSIDE g_kstack_lock — MapPage is not IRQ-safe and would
// deadlock if it ever reached for a kernel-heap allocation
// through an IRQ'd spinlock we already hold. All arena metadata
// is updated by the caller after this returns.
bool InstallStackPages(u32 slot_index)
{
    const uptr base = UsableBaseFromSlot(slot_index);
    u64 installed = 0;
    for (u64 i = 0; i < kKernelStackPages; ++i)
    {
        auto phys_r = AllocateFrame();
        if (!phys_r)
        {
            // Unwind: free every frame we installed so far so we
            // don't leak on an OOM that may yet be recoverable.
            for (u64 j = 0; j < installed; ++j)
            {
                const uptr va = base + j * kPageSize;
                UnmapPage(va);
                FreeFrame(g_slot_frames[slot_index][j]);
                g_slot_frames[slot_index][j] = kNullFrame;
            }
            return false;
        }
        const PhysAddr phys = phys_r.value();
        MapPage(base + i * kPageSize, phys, kKernelData);
        g_slot_frames[slot_index][i] = phys;
        ++installed;
    }
    return true;
}

// Symmetric teardown. Uses the per-slot shadow table populated
// by InstallStackPages to recover each frame address — the
// alternative (reading the PTE back) would need a new public
// PTE-walker primitive in paging.h, which has zero callers
// beyond this one site.
//
// Runs OUTSIDE g_kstack_lock for the same reason InstallStackPages
// does.
void TearDownStackPages(u32 slot_index)
{
    const uptr base = UsableBaseFromSlot(slot_index);
    for (u64 i = 0; i < kKernelStackPages; ++i)
    {
        const PhysAddr phys = g_slot_frames[slot_index][i];
        if (phys == kNullFrame)
        {
            PanicKstack("TearDownStackPages: slot page has no recorded frame",
                        (static_cast<u64>(slot_index) << 16) | i);
        }
        UnmapPage(base + i * kPageSize);
        FreeFrame(phys);
        g_slot_frames[slot_index][i] = kNullFrame;
    }
    // Cross-CPU TLB shootdown. UnmapPage above invalidates only the
    // CPU running this code; peer CPUs that ran the previous owner
    // of this slot still have TLB entries pointing at the freed
    // physical frames. Without this broadcast, the bug shape was:
    //
    //   1. Task X runs on AP7, populates AP7's TLB for slot N's VAs.
    //   2. Task X exits; reaper on BSP calls FreeKernelStack. BSP's
    //      TLB is invalidated for slot N; AP7's TLB stays stale.
    //   3. SchedCreate allocates slot N to a NEW task and plants
    //      `&SchedTaskTrampoline` at slot_top - 8 (via BSP's fresh
    //      TLB → new physical page).
    //   4. Scheduler dispatches the new task on AP7. AP7's
    //      ContextSwitch reads slot N's VAs through stale TLB → old
    //      physical page → garbage (the OLD task's leftover data).
    //   5. The pop sequence loads garbage into r15..rbx, ret jumps
    //      to whatever value was at the trampoline-RA slot of the
    //      OLD task's stack (often a syscall-entry's SS=0x33 push
    //      for ring-3 tasks, or trampoline tail addrs for kernel-
    //      only tasks).
    //   6. CPU lands at the wild value → #UD / #PF NX_VIOLATION /
    //      self-deadlock — the canary13 boot-tail wild-RIP shape
    //      with all six in-tree validators silent.
    //
    // The kstack-arena VAs are kernel-owned (PML4 high half), so
    // `as=nullptr` does a full broadcast — every online peer's TLB
    // gets the targeted slot invalidated.
    arch::SmpTlbShootdownRange(nullptr, base, kKernelStackPages * kPageSize);
}

// Pop a slot index from the freelist. Caller holds g_kstack_lock.
// Returns false if the freelist is empty.
bool FreelistPop(u32* out_slot)
{
    // Documented-but-unenforced precondition (comment above). A
    // missed g_kstack_lock races a concurrent Pop/Push and hands
    // the SAME slot to two callers — two threads sharing one kernel
    // stack, silent and catastrophic. Same kind/severity as the
    // sched runqueue-funnel guards: debug-panic / release-warn.
    sync::SpinLockAssertHeld(g_kstack_lock);
    if (g_free_count == 0)
    {
        return false;
    }
    --g_free_count;
    *out_slot = g_free_stack[g_free_count];
    // Freelist storage corruption (wild store) would let `*out_slot`
    // come back larger than the arena. Two callers later hand the
    // same slot to two tasks, or InstallStackPages maps frames
    // outside the arena. KASSERT, not DEBUG_ASSERT: a sliced kernel
    // stack is the canonical "wild RIP at 2 a.m." footprint and we
    // want every flavour to catch the corruption at the source.
    KASSERT_WITH_VALUE(*out_slot < kKernelStackMaxSlots, "mm/kstack", "freelist popped oob slot",
                       static_cast<u64>(*out_slot));
    return true;
}

// Push a slot index onto the freelist. Caller holds g_kstack_lock.
void FreelistPush(u32 slot_index)
{
    // Same g_kstack_lock precondition as FreelistPop — an unlocked
    // push races a concurrent pop and corrupts g_free_count.
    sync::SpinLockAssertHeld(g_kstack_lock);
    // Architectural precondition: a caller-supplied oob slot would
    // poison the freelist for every later pop. `SlotIndexFromBase`
    // panics on misalignment but the kstack-self-test sites bypass
    // it; pin the invariant at the storage site so EVERY push is
    // bounded.
    KASSERT_WITH_VALUE(slot_index < kKernelStackMaxSlots, "mm/kstack", "freelist push oob slot",
                       static_cast<u64>(slot_index));
    if (g_free_count >= kKernelStackMaxSlots)
    {
        PanicKstack("freelist overflow (double-free?)", g_free_count);
    }
    g_free_stack[g_free_count] = slot_index;
    ++g_free_count;
}

// Translate a returned `base` pointer back to its slot index.
// Validates that `base` is the usable base (slot_base + guard)
// of some slot; mis-sized or misaligned frees surface as a panic
// rather than corrupting the allocator.
u32 SlotIndexFromBase(void* base)
{
    const uptr va = reinterpret_cast<uptr>(base);
    if (va < kKernelStackArenaBase)
    {
        PanicKstack("FreeKernelStack: base below arena", va);
    }
    const u64 offset = va - kKernelStackArenaBase;
    if (offset >= kKernelStackArenaBytes)
    {
        PanicKstack("FreeKernelStack: base above arena", va);
    }
    const u64 slot_offset = offset % kKernelStackSlotBytes;
    if (slot_offset != kKernelStackGuardPages * kPageSize)
    {
        // Either `base` isn't a usable-base pointer at all, or it
        // points mid-stack — either way, caller is confused.
        PanicKstack("FreeKernelStack: base is not a slot usable-base", va);
    }
    return static_cast<u32>(offset / kKernelStackSlotBytes);
}

} // namespace

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
void* AllocateKernelStack(u64 stack_bytes)
{
    if (stack_bytes != kKernelStackUsableBytes)
    {
        PanicKstack("AllocateKernelStack: stack_bytes must equal kKernelStackUsableBytes", stack_bytes);
    }

    u32 slot_index = 0;
    {
        sync::SpinLockGuard guard(g_kstack_lock);
        if (!FreelistPop(&slot_index))
        {
            if (g_next_unseen_slot >= kKernelStackMaxSlots)
            {
                // Arena full. Return nullptr — SchedCreate already
                // panics on a nullptr stack, preserving the prior
                // KMalloc contract.
                return nullptr;
            }
            slot_index = g_next_unseen_slot++;
        }
    }

    // Install backing pages outside the lock. If InstallStackPages
    // fails (frame allocator OOM), push the slot back on the freelist
    // so a later caller can re-try — the VA was never published to
    // the user.
    if (!InstallStackPages(slot_index))
    {
        sync::SpinLockGuard guard(g_kstack_lock);
        FreelistPush(slot_index);
        return nullptr;
    }

    // Publish stats after pages are installed so a reader never sees
    // slots_in_use > 0 for a slot whose backing frames aren't up yet.
    {
        sync::SpinLockGuard guard(g_kstack_lock);
        ++g_slots_in_use;
        ++g_slots_ever_allocated;
        // Accounting invariant: slots_in_use can never exceed the
        // arena. If it does, a free path missed its decrement; left
        // unchecked the next allocator pass would think the arena
        // is full forever (FreelistPop empty AND g_next_unseen_slot
        // saturated) — silent denial-of-service on every later
        // SchedCreate.
        KASSERT_WITH_VALUE(g_slots_in_use <= kKernelStackMaxSlots, "mm/kstack", "slots_in_use exceeds arena cap",
                           g_slots_in_use);
        if (g_slots_in_use > g_high_water_slots)
        {
            g_high_water_slots = g_slots_in_use;
        }
    }

    const uptr usable_base = UsableBaseFromSlot(slot_index);
    // Arm the deep-usage tripwire at the 75%-used line. The pages are mapped
    // and zeroed; this single word sits in untouched stack until the thread
    // (if ever) grows down past it.
    *TripwireSlot(usable_base) = kStackTripwireWord;
    return reinterpret_cast<void*>(usable_base);
}

bool KernelStackTripwireTripped(void* base)
{
    if (base == nullptr)
    {
        return false;
    }
    return *TripwireSlot(reinterpret_cast<uptr>(base)) != kStackTripwireWord;
}

void FreeKernelStack(void* base, u64 stack_bytes)
{
    if (base == nullptr)
    {
        return;
    }
    if (stack_bytes != kKernelStackUsableBytes)
    {
        PanicKstack("FreeKernelStack: stack_bytes must equal kKernelStackUsableBytes", stack_bytes);
    }

    const u32 slot_index = SlotIndexFromBase(base);

    // Deep-usage canary — read the tripwire BEFORE TearDownStackPages unmaps
    // the slot. If the sentinel was overwritten, this thread's stack crossed
    // the 96 KiB (75%) line on its way toward the guard page.
    if (KernelStackTripwireTripped(base))
    {
        const u64 peak_floor = kKernelStackUsableBytes - kStackTripwireOffset; // >= 96 KiB used
        KBP_PROBE_V(::duetos::debug::ProbeId::kKernelStackDeepUsage, peak_floor);
        KLOG_WARN_V("mm/kstack", "thread freed after using >=75% of its 128 KiB kernel stack; peak >= bytes",
                    peak_floor);
    }

    // Tear down pages outside the lock.
    TearDownStackPages(slot_index);

    sync::SpinLockGuard guard(g_kstack_lock);
    FreelistPush(slot_index);
    if (g_slots_in_use == 0)
    {
        PanicKstack("FreeKernelStack: slots_in_use underflow", slot_index);
    }
    --g_slots_in_use;
    ++g_slots_freed;
}

KernelStackStats KernelStackStatsRead()
{
    sync::SpinLockGuard guard(g_kstack_lock);
    return KernelStackStats{
        .slots_in_use = g_slots_in_use,
        .slots_ever_allocated = g_slots_ever_allocated,
        .slots_freed = g_slots_freed,
        .high_water_slots = g_high_water_slots,
        .next_unseen_slot = g_next_unseen_slot,
        .freelist_depth = g_free_count,
    };
}

void KernelStackSelfTest()
{
    KLOG_TRACE_SCOPE("mm/kstack", "KernelStackSelfTest");
    SerialWrite("[mm] kstack self-test\n");

    const KernelStackStats before = KernelStackStatsRead();

    // 1. Allocate a slot.
    void* a = AllocateKernelStack(kKernelStackUsableBytes);
    if (a == nullptr)
    {
        PanicKstack("self-test: first AllocateKernelStack returned null", 0);
    }

    // 2. Write / read at both ends of the usable range. Proves
    //    every stack page is mapped + writable. If the guard
    //    page were mistakenly mapped we wouldn't catch it here,
    //    but a write into the guard is what the trap-handler
    //    branch is for — that path is verified live.
    volatile u8* p = static_cast<volatile u8*>(a);
    p[0] = 0xA5;
    p[kKernelStackUsableBytes - 1] = 0x5A;
    if (p[0] != 0xA5 || p[kKernelStackUsableBytes - 1] != 0x5A)
    {
        PanicKstack("self-test: stack read-back mismatch", reinterpret_cast<u64>(a));
    }

    // 3. Free, then re-allocate. LIFO freelist must hand back the
    //    same VA — confirms the freelist push/pop is sound and
    //    that teardown didn't corrupt the slot metadata.
    FreeKernelStack(a, kKernelStackUsableBytes);
    void* b = AllocateKernelStack(kKernelStackUsableBytes);
    if (b != a)
    {
        PanicKstack("self-test: freelist did not recycle slot", reinterpret_cast<u64>(b));
    }

    // 4. Touch the recycled stack too — catches a bug where
    //    InstallStackPages only works on fresh slots.
    p = static_cast<volatile u8*>(b);
    p[0] = 0x33;
    if (p[0] != 0x33)
    {
        PanicKstack("self-test: recycled stack write failed", reinterpret_cast<u64>(b));
    }

    FreeKernelStack(b, kKernelStackUsableBytes);

    // 5. Stats must land back where they started for slots_in_use;
    //    lifetime counters must have advanced by exactly two.
    const KernelStackStats after = KernelStackStatsRead();
    if (after.slots_in_use != before.slots_in_use)
    {
        PanicKstack("self-test: slots_in_use drifted", after.slots_in_use);
    }
    if (after.slots_ever_allocated != before.slots_ever_allocated + 2)
    {
        PanicKstack("self-test: slots_ever_allocated mismatch", after.slots_ever_allocated);
    }
    if (after.slots_freed != before.slots_freed + 2)
    {
        PanicKstack("self-test: slots_freed mismatch", after.slots_freed);
    }

    SerialWrite("[mm] kstack self-test ok: arena_base=");
    SerialWriteHex(kKernelStackArenaBase);
    SerialWrite(" slot_bytes=");
    SerialWriteHex(kKernelStackSlotBytes);
    SerialWrite(" max_slots=");
    SerialWriteHex(kKernelStackMaxSlots);
    SerialWrite("\n");
}

} // namespace duetos::mm
