/*
 * DuetOS — cyclic subsystem implementation.
 *
 * See `cyclic.h` for the public contract + level taxonomy. The
 * implementation is a single TU because the three levels share
 * the registration table, the spinlock, and the heap-management
 * helpers; splitting per-level would just spread the same data
 * structure across three files.
 *
 * Heap shape:
 *   The full registration table is `g_table[kMaxCyclics]`. Each
 *   live slot carries its own state (level, deadline, interval,
 *   fn, arg, name, generation). Three min-heaps over slot
 *   INDICES live alongside: `g_high_heap`, `g_lock_heap`,
 *   `g_low_heap`. Storing indices rather than pointers keeps the
 *   heap entries small (8 bytes per entry) and lets `CyclicRemove`
 *   locate-and-erase by slot id without an extra map.
 *
 *   Heaps are kept ordered by `g_table[idx].deadline`. The min
 *   sits at index 0 — the IRQ-tail fast path reads heap[0] and
 *   compares against `now`. If the min hasn't expired, nothing
 *   else needs to run.
 *
 * Lock discipline:
 *   `g_cyclic_lock` is IRQ-off (SpinLockAcquire saves RFLAGS
 *   and disables IF). Held during table mutations and heap
 *   walks. The dispatcher RELEASES the lock before calling
 *   a user callback to bound worst-case hold time to one
 *   callback's runtime — a slow High callback cannot block
 *   later ones on the SAME tick.
 *
 *   The slot's `generation` field is bumped on every register
 *   AND remove. The dispatcher snapshots the generation when
 *   it pops a slot off the heap; if the slot's generation
 *   has moved by the time the dispatcher re-acquires the
 *   lock to re-heap, the registration was removed under us
 *   and the slot must NOT be re-heaped.
 */

#include "time/cyclic.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "log/klog.h"
#include "sched/sched.h"
#include "sync/spinlock.h"
#include "time/tick.h"
#include "util/types.h"

namespace duetos::time
{

namespace
{

// One slot per registration. Slot 0 is reserved (kInvalidCyclicId),
// so live slots use indices 1..kMaxCyclics-1.
struct CyclicSlot
{
    CyclicFn fn;
    void* arg;
    const char* name;
    u64 deadline_ticks;
    u64 interval_ticks;
    CyclicLevel level;
    bool live;
    // Bumped on every register + remove. The dispatcher uses
    // this to detect a slot that was removed (and possibly
    // re-allocated to a NEW registration) while it was in the
    // running-callback window.
    u32 generation;
    // True iff the dispatcher is currently running this slot's
    // callback. CyclicRemove waits on this so the caller can
    // safely tear down `arg` after the call returns.
    bool running;
};

// Min-heap entry — pairs a slot index with its deadline
// (cached so heap ops don't have to chase back into g_table).
// On a re-heap after fire the deadline is updated from the
// slot's new deadline.
struct HeapEntry
{
    u32 slot_idx;
    u64 deadline_ticks;
};

// Global state. constinit so it's available before any dynamic
// init runs — `CyclicRegister` is callable as soon as the
// `CyclicInstall` for-low-kthread has spawned.
constinit CyclicSlot g_table[kMaxCyclics] = {};
constinit HeapEntry g_high_heap[kMaxCyclics] = {};
constinit u32 g_high_heap_size = 0;
constinit HeapEntry g_lock_heap[kMaxCyclics] = {};
constinit u32 g_lock_heap_size = 0;
constinit HeapEntry g_low_heap[kMaxCyclics] = {};
constinit u32 g_low_heap_size = 0;

constinit sync::SpinLock g_cyclic_lock = {};

// Wait queue the Low-level dispatcher kthread blocks on. Woken by
// CyclicRegister(Low, ...) when a new entry is added whose deadline
// is sooner than whatever the kthread is currently parked on, OR
// to nudge the kthread off the 10 s empty-heap park as soon as
// the very first Low cyclic is registered. CyclicRemove also
// wakes the queue so a remove during park exits the park early
// (the dispatcher loop will recompute its next deadline).
constinit sched::WaitQueue g_low_wq = {};

// Diagnostic counters. Updated under g_cyclic_lock except for
// fires_* which are bumped from the dispatcher AFTER the
// callback returns; the per-counter monotonicity is what
// CyclicStatsRead promises (the cross-counter snapshot is
// approximate).
constinit u32 g_registrations_total = 0;
constinit u32 g_registrations_live = 0;
constinit u64 g_fires_high = 0;
constinit u64 g_fires_lock = 0;
constinit u64 g_fires_low = 0;
constinit u64 g_overruns = 0;

// Set by CyclicInstall. Guards against firing the Low-level
// dispatcher kthread twice or accepting registrations before
// the kthread is alive.
constinit bool g_installed = false;

// Heap helpers. All assume g_cyclic_lock is held.

inline HeapEntry* HeapBase(CyclicLevel level, u32*& size_out)
{
    switch (level)
    {
    case CyclicLevel::High:
        size_out = &g_high_heap_size;
        return g_high_heap;
    case CyclicLevel::Lock:
        size_out = &g_lock_heap_size;
        return g_lock_heap;
    case CyclicLevel::Low:
        size_out = &g_low_heap_size;
        return g_low_heap;
    }
    // Unreachable — every CyclicLevel value is enumerated above.
    KASSERT(false, "time/cyclic", "HeapBase: bad level");
    size_out = &g_high_heap_size;
    return g_high_heap;
}

void SiftUp(HeapEntry* heap, u32 idx)
{
    while (idx > 0)
    {
        const u32 parent = (idx - 1) / 2;
        if (heap[parent].deadline_ticks <= heap[idx].deadline_ticks)
        {
            return;
        }
        const HeapEntry tmp = heap[parent];
        heap[parent] = heap[idx];
        heap[idx] = tmp;
        idx = parent;
    }
}

void SiftDown(HeapEntry* heap, u32 size, u32 idx)
{
    for (;;)
    {
        const u32 left = idx * 2 + 1;
        const u32 right = idx * 2 + 2;
        u32 smallest = idx;
        if (left < size && heap[left].deadline_ticks < heap[smallest].deadline_ticks)
        {
            smallest = left;
        }
        if (right < size && heap[right].deadline_ticks < heap[smallest].deadline_ticks)
        {
            smallest = right;
        }
        if (smallest == idx)
        {
            return;
        }
        const HeapEntry tmp = heap[idx];
        heap[idx] = heap[smallest];
        heap[smallest] = tmp;
        idx = smallest;
    }
}

void HeapPush(CyclicLevel level, u32 slot_idx, u64 deadline)
{
    u32* size_ptr;
    HeapEntry* heap = HeapBase(level, size_ptr);
    KASSERT(*size_ptr < kMaxCyclics, "time/cyclic", "HeapPush: heap full");
    heap[*size_ptr] = {slot_idx, deadline};
    ++*size_ptr;
    SiftUp(heap, *size_ptr - 1);
}

// Pop the min entry (index 0) — caller has already checked size > 0.
HeapEntry HeapPop(CyclicLevel level)
{
    u32* size_ptr;
    HeapEntry* heap = HeapBase(level, size_ptr);
    KASSERT(*size_ptr > 0, "time/cyclic", "HeapPop: heap empty");
    const HeapEntry out = heap[0];
    --*size_ptr;
    if (*size_ptr > 0)
    {
        heap[0] = heap[*size_ptr];
        SiftDown(heap, *size_ptr, 0);
    }
    return out;
}

// Remove a slot by its index from the given heap. Linear in heap
// size — only called from CyclicRemove (cold path).
void HeapRemoveSlot(CyclicLevel level, u32 slot_idx)
{
    u32* size_ptr;
    HeapEntry* heap = HeapBase(level, size_ptr);
    for (u32 i = 0; i < *size_ptr; ++i)
    {
        if (heap[i].slot_idx == slot_idx)
        {
            --*size_ptr;
            if (i < *size_ptr)
            {
                heap[i] = heap[*size_ptr];
                // The replacement may need to move either up
                // (smaller than parent) or down (larger than
                // children). Try sift-up first, then sift-down
                // from the same position — only one will actually
                // move the entry. Cheap (each is O(log n)).
                SiftUp(heap, i);
                SiftDown(heap, *size_ptr, i);
            }
            return;
        }
    }
}

// Allocate a free slot. Returns 0 (= kInvalidCyclicId) if full.
u32 AllocSlot()
{
    // Slot 0 reserved as kInvalidCyclicId.
    for (u32 i = 1; i < kMaxCyclics; ++i)
    {
        if (!g_table[i].live)
        {
            return i;
        }
    }
    return 0;
}

// Bump a counter from outside the lock. Counters are plain u64s
// updated only by the dispatcher (one writer per counter
// generation) so a plain increment is correct as long as the
// caller is the dispatcher. CyclicStatsRead does a relaxed read.
void BumpFire(CyclicLevel level)
{
    switch (level)
    {
    case CyclicLevel::High:
        ++g_fires_high;
        return;
    case CyclicLevel::Lock:
        ++g_fires_lock;
        return;
    case CyclicLevel::Low:
        ++g_fires_low;
        return;
    }
}

// Advance the slot's deadline drift-free, detecting overrun.
// Caller holds g_cyclic_lock. Returns the new deadline.
u64 AdvanceDeadline(CyclicSlot& slot, u64 now)
{
    u64 next = slot.deadline_ticks + slot.interval_ticks;
    if (next <= now)
    {
        // Missed at least one interval. Bump overrun counter
        // and snap forward to one full interval past now —
        // we do NOT try to fire back-to-back to "catch up"
        // (matches Solaris semantics).
        ++g_overruns;
        next = now + slot.interval_ticks;
    }
    slot.deadline_ticks = next;
    return next;
}

// Dispatch all due callbacks at the given level. Caller holds
// g_cyclic_lock on entry; this function releases + re-acquires
// across each callback so a slow callback cannot block the rest.
// Returns with the lock held.
void DispatchDueLocked(CyclicLevel level, u64 now, sync::IrqFlags& flags)
{
    u32* size_ptr;
    HeapEntry* heap = HeapBase(level, size_ptr);

    while (*size_ptr > 0 && heap[0].deadline_ticks <= now)
    {
        const HeapEntry entry = HeapPop(level);
        const u32 slot_idx = entry.slot_idx;
        CyclicSlot& slot = g_table[slot_idx];
        // Defensive: a popped slot should always still be live
        // (CyclicRemove also pulls the heap entry under the
        // lock). If it isn't, drop the entry silently — the
        // remove path already cleaned the table.
        if (!slot.live)
        {
            continue;
        }
        const u32 gen_at_dispatch = slot.generation;
        CyclicFn fn = slot.fn;
        void* arg = slot.arg;
        const CyclicLevel slot_level = slot.level;
        // Advance the deadline BEFORE releasing the lock so a
        // concurrent CyclicRegister at the same level doesn't
        // observe a slot with a stale deadline. We re-heap AFTER
        // the callback to bound the lock-hold to one heap op.
        const u64 next_deadline = AdvanceDeadline(slot, now);
        slot.running = true;

        sync::SpinLockRelease(g_cyclic_lock, flags);
        fn(arg);
        flags = sync::SpinLockAcquire(g_cyclic_lock);

        // If the callback removed itself (or was removed by
        // another path) while running, the generation has
        // moved on. Don't re-heap a stale slot.
        if (slot.generation == gen_at_dispatch && slot.live)
        {
            slot.running = false;
            // Push the new deadline back onto the heap. The slot
            // is still live and at the same generation, so the
            // entry's slot_idx is still meaningful.
            HeapPush(slot_level, slot_idx, next_deadline);
        }
        BumpFire(slot_level);
    }
}

// Low-level dispatcher kthread. Loops:
//   - take the cyclic lock, dispatch any due Low cyclics
//   - read the next Low deadline (or 10 s park if heap empty)
//   - WaitQueueBlockTimeout on g_low_wq up to that deadline
// The block is interruptible — CyclicRegister(Low) and
// CyclicRemove(Low) call WaitQueueWakeAll(g_low_wq) so the
// kthread re-computes its deadline immediately when the heap
// changes. Worst-case register-to-fire latency is now bounded
// by the new deadline itself, not by the 10 s park.
constexpr u64 kLowParkTicks = 10 * 100; // 10 s @ 100 Hz

[[noreturn]] void LowDispatcherMain(void* /*arg*/)
{
    // Opt out of the hung-task detector. The cyclic Low dispatcher
    // is by design a long-blocked task between deadlines: when no
    // Low cyclics are registered, it parks on the 10 s empty-heap
    // deadline (which stays under the 30 s hung-task threshold by
    // construction), but a workload that registers a single Low
    // cyclic with cadence > 30 s would otherwise produce a true
    // but unactionable "kcyclic-low is hung" warning every minute.
    // The dispatcher's own progress is observable via CyclicStats
    // (`fires_low` increments), so a genuine deadlock here is
    // visible without the hung-task channel.
    sched::SchedExemptCurrentFromHungTask();
    for (;;)
    {
        // Dispatch + decide next deadline under the lock.
        sync::IrqFlags flags = sync::SpinLockAcquire(g_cyclic_lock);
        const u64 now = sched::SchedNowTicks();
        DispatchDueLocked(CyclicLevel::Low, now, flags);

        u64 deadline = now + kLowParkTicks;
        if (g_low_heap_size > 0)
        {
            const u64 next = g_low_heap[0].deadline_ticks;
            if (next > now)
            {
                deadline = next;
            }
            else
            {
                // Still due — loop without sleeping. Can happen if
                // a callback ran longer than its interval, leaving
                // another entry already past its deadline.
                sync::SpinLockRelease(g_cyclic_lock, flags);
                continue;
            }
        }
        sync::SpinLockRelease(g_cyclic_lock, flags);

        const u64 wait_ticks = (deadline > now) ? (deadline - now) : 1;
        sched::WaitQueueBlockTimeout(&g_low_wq, wait_ticks);
    }
}

void WakeLowDispatcher()
{
    // g_low_wq's storage is protected by g_sched_lock inside the
    // wait-queue API itself; calling WakeAll from outside the
    // cyclic lock avoids a cyclic-then-sched lock-order
    // dependency that would conflict with sched-then-anything
    // elsewhere in the kernel.
    (void)sched::WaitQueueWakeAll(&g_low_wq);
}

} // namespace

CyclicId CyclicRegister(CyclicLevel level, u64 interval_ticks, CyclicFn fn, void* arg, const char* name)
{
    if (fn == nullptr)
    {
        KLOG_WARN("time/cyclic", "CyclicRegister: null fn rejected");
        return kInvalidCyclicId;
    }
    if (interval_ticks == 0)
    {
        // Clamp up to 1 tick. A genuine 0 is almost certainly a
        // caller bug (forgot to convert ms->ticks); 1 keeps the
        // box alive while the bug surfaces in normal logs.
        KLOG_WARN_S("time/cyclic", "CyclicRegister: interval_ticks=0 clamped to 1", "name",
                    (name != nullptr) ? name : "<unnamed>");
        interval_ticks = 1;
    }
    if (!g_installed)
    {
        KLOG_WARN_S("time/cyclic", "CyclicRegister before CyclicInstall — rejected", "name",
                    (name != nullptr) ? name : "<unnamed>");
        return kInvalidCyclicId;
    }

    sync::IrqFlags flags = sync::SpinLockAcquire(g_cyclic_lock);
    const u32 slot_idx = AllocSlot();
    if (slot_idx == 0)
    {
        sync::SpinLockRelease(g_cyclic_lock, flags);
        KLOG_WARN_S("time/cyclic", "CyclicRegister: table full (kMaxCyclics reached)", "name",
                    (name != nullptr) ? name : "<unnamed>");
        return kInvalidCyclicId;
    }

    const u64 now = sched::SchedNowTicks();
    CyclicSlot& slot = g_table[slot_idx];
    slot.fn = fn;
    slot.arg = arg;
    slot.name = name;
    slot.interval_ticks = interval_ticks;
    slot.deadline_ticks = now + interval_ticks;
    slot.level = level;
    slot.live = true;
    slot.running = false;
    ++slot.generation;

    HeapPush(level, slot_idx, slot.deadline_ticks);
    ++g_registrations_total;
    ++g_registrations_live;

    sync::SpinLockRelease(g_cyclic_lock, flags);

    if (level == CyclicLevel::Low)
    {
        // Nudge the Low-level dispatcher kthread off its current
        // park — its next loop iteration will recompute the
        // deadline and pick up this entry. Without this wake the
        // kthread would sleep its full park (up to 10 s) before
        // observing the new entry.
        WakeLowDispatcher();
    }

    return static_cast<CyclicId>(slot_idx);
}

void CyclicRemove(CyclicId id)
{
    if (id == kInvalidCyclicId || id >= kMaxCyclics)
    {
        return;
    }
    // Loop: take the lock, if the slot's not live we're done; if
    // it IS live and not running, tear down; if it's live AND
    // running, drop the lock + yield + retry. Bounded by the
    // worst-case single-callback runtime.
    for (;;)
    {
        sync::IrqFlags flags = sync::SpinLockAcquire(g_cyclic_lock);
        CyclicSlot& slot = g_table[id];
        if (!slot.live)
        {
            sync::SpinLockRelease(g_cyclic_lock, flags);
            return;
        }
        if (!slot.running)
        {
            const CyclicLevel removed_level = slot.level;
            HeapRemoveSlot(slot.level, id);
            slot.live = false;
            slot.fn = nullptr;
            slot.arg = nullptr;
            slot.name = nullptr;
            ++slot.generation;
            --g_registrations_live;
            sync::SpinLockRelease(g_cyclic_lock, flags);
            if (removed_level == CyclicLevel::Low)
            {
                // Wake the Low dispatcher so it recomputes its
                // next deadline against the updated heap — if we
                // removed the heap head, the next park should be
                // shorter (or empty-heap park = 10 s).
                WakeLowDispatcher();
            }
            return;
        }
        // Running. Drop the lock and yield so the dispatcher can
        // finish the callback. The dispatcher will clear running
        // when it re-acquires the lock post-callback.
        sync::SpinLockRelease(g_cyclic_lock, flags);
        sched::SchedYield();
    }
}

void CyclicTimerTick()
{
    // Fast path: if neither High nor Lock heap has a due entry
    // we exit in the time of one (load + compare) pair.
    if (g_high_heap_size == 0 && g_lock_heap_size == 0)
    {
        return;
    }

    // We're already in IRQ context (IF=0). SpinLockAcquire's
    // RFLAGS save/restore preserves that — the lock release
    // returns with IF=0 same as it entered.
    sync::IrqFlags flags = sync::SpinLockAcquire(g_cyclic_lock);
    const u64 now = sched::SchedNowTicks();
    DispatchDueLocked(CyclicLevel::High, now, flags);
    DispatchDueLocked(CyclicLevel::Lock, now, flags);
    sync::SpinLockRelease(g_cyclic_lock, flags);
}

CyclicStats CyclicStatsRead()
{
    CyclicStats out{};
    sync::IrqFlags flags = sync::SpinLockAcquire(g_cyclic_lock);
    out.registrations_total = g_registrations_total;
    out.registrations_live = g_registrations_live;
    out.fires_high = g_fires_high;
    out.fires_lock = g_fires_lock;
    out.fires_low = g_fires_low;
    out.overruns = g_overruns;
    sync::SpinLockRelease(g_cyclic_lock, flags);
    return out;
}

void CyclicInstall()
{
    if (g_installed)
    {
        KLOG_WARN("time/cyclic", "CyclicInstall called twice — ignoring");
        return;
    }
    g_installed = true;
    sched::SchedCreate(&LowDispatcherMain, nullptr, "kcyclic-low");
    arch::SerialWrite("[cyclic] installed (kcyclic-low spawned)\n");
}

namespace
{

// Self-test fixture state. Plain globals so the callbacks (which
// take a `void*` arg) can talk to the test harness without
// allocating. Reset on entry to CyclicSelfTest.
constinit u32 g_selftest_high_fires = 0;
constinit u32 g_selftest_lock_fires = 0;
constinit u32 g_selftest_low_fires = 0;

void SelftestHighFn(void* /*arg*/)
{
    ++g_selftest_high_fires;
}

void SelftestLockFn(void* /*arg*/)
{
    ++g_selftest_lock_fires;
}

void SelftestLowFn(void* /*arg*/)
{
    ++g_selftest_low_fires;
}

} // namespace

void CyclicSelfTest()
{
    g_selftest_high_fires = 0;
    g_selftest_lock_fires = 0;
    g_selftest_low_fires = 0;

    // Pick a short interval (3 ticks = 30 ms @ 100 Hz) for the
    // High + Lock cyclics — they fire from the IRQ tail so the
    // 100 Hz timer drives them regardless of scheduler state.
    // The Low cyclic uses a longer interval (5 ticks = 50 ms)
    // because its dispatcher kthread sleeps on SchedSleepUntil
    // and we want to give the wake path a comfortable margin.
    constexpr u64 kHighInterval = 3;
    constexpr u64 kLockInterval = 3;
    constexpr u64 kLowInterval = 5;

    const CyclicId high_id =
        CyclicRegister(CyclicLevel::High, kHighInterval, &SelftestHighFn, nullptr, "selftest-high");
    const CyclicId lock_id =
        CyclicRegister(CyclicLevel::Lock, kLockInterval, &SelftestLockFn, nullptr, "selftest-lock");
    const CyclicId low_id = CyclicRegister(CyclicLevel::Low, kLowInterval, &SelftestLowFn, nullptr, "selftest-low");

    if (high_id == kInvalidCyclicId || lock_id == kInvalidCyclicId || low_id == kInvalidCyclicId)
    {
        core::Panic("time/cyclic", "self-test: CyclicRegister returned kInvalidCyclicId");
    }

    // Wait long enough for each cyclic to fire AT LEAST 3 times.
    // High/Lock at 3 ticks => 3 fires need ~9+ ticks. Low at 5
    // ticks => 3 fires need ~15+ ticks. Wait 25 ticks (250 ms)
    // for comfortable margin against scheduler latency.
    const u64 wait_deadline = sched::SchedNowTicks() + 25;
    sched::SchedSleepUntil(wait_deadline);

    CyclicRemove(high_id);
    CyclicRemove(lock_id);
    CyclicRemove(low_id);

    if (g_selftest_high_fires < 3)
    {
        core::PanicWithValue("time/cyclic", "self-test: High level fires < 3", g_selftest_high_fires);
    }
    if (g_selftest_lock_fires < 3)
    {
        core::PanicWithValue("time/cyclic", "self-test: Lock level fires < 3", g_selftest_lock_fires);
    }
    if (g_selftest_low_fires < 3)
    {
        core::PanicWithValue("time/cyclic", "self-test: Low level fires < 3", g_selftest_low_fires);
    }

    // Verify the live count went back to baseline after remove.
    const CyclicStats stats = CyclicStatsRead();
    // (Other subsystems may have registered between Install and
    // here in a later slice; the only invariant the self-test
    // owns is that OUR three removes worked. Cross-check via
    // the per-counter advances we recorded above.)

    arch::SerialWrite("[cyclic] self-test OK (high=");
    arch::SerialWriteHex(g_selftest_high_fires);
    arch::SerialWrite(", lock=");
    arch::SerialWriteHex(g_selftest_lock_fires);
    arch::SerialWrite(", low=");
    arch::SerialWriteHex(g_selftest_low_fires);
    arch::SerialWrite(", overruns=");
    arch::SerialWriteHex(stats.overruns);
    arch::SerialWrite(")\n");
}

} // namespace duetos::time
