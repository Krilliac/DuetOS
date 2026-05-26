/*
 * DuetOS — quiescent-state RCU.
 *
 * See `rcu.h` for the public contract. Per-CPU callback queues:
 * each CPU pushes onto its own ring; reclamation walks every queue
 * (`RcuReclaim`) or only the caller's (`RcuReclaimLocal`). Each
 * queue has its own ticket spinlock — the local-CPU fast path
 * sees uncontended acquires while a cross-CPU `RcuReclaim` walks
 * peer queues without racing the peer's own `RcuCall`.
 *
 * Grace-period rule: a callback enqueued at tick T is reclaimable
 * once `g_ticks > T`. The tick counter is a single global atomic
 * advanced by every CPU's `RcuTick` call, so a callback enqueued
 * on any CPU sees a quiescent state as soon as any CPU completes
 * a scheduler tick. Once SMP demands strict per-CPU QS proof,
 * the rule generalises to "every CPU's local tick > T" — the
 * queue layout already supports it.
 */

#include "sync/rcu.h"

#include "acpi/acpi.h"
#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "cpu/percpu.h"
#include "debug/probes.h"
#include "log/klog.h"
#include "sync/spinlock.h"
#include "util/saturating.h"
#include "util/types.h"

// Linker-emitted bounds of the kernel `.text` section. Used by
// DrainQueue's sanity check below to refuse dispatch of a callback
// whose `cb.fn` fell outside executable kernel code.
extern "C" duetos::u8 _text_start[];
extern "C" duetos::u8 _text_end[];

namespace duetos::sync
{

namespace
{

constexpr u32 kRcuPerCpuQueueDepth = 64;

struct PendingCb
{
    RcuCallback fn;
    void* arg;
    u64 enqueue_tick;
};

struct RcuPerCpuQueue
{
    // Per-queue spinlock. Uncontended for the local-only path
    // (RcuCall + RcuReclaimLocal both run on the queue's owning
    // CPU). Contended only when a cross-CPU caller invokes
    // RcuReclaim — the lock prevents the peer's concurrent
    // RcuCall from racing with the drain's index updates.
    SpinLock lock;
    PendingCb slots[kRcuPerCpuQueueDepth];
    u32 head;  ///< Next slot to write.
    u32 tail;  ///< Next slot to reclaim.
    u32 count; ///< Live callbacks.
};

constinit RcuPerCpuQueue g_per_cpu[acpi::kMaxCpus] = {};
constinit u64 g_ticks = 0; ///< Monotonic tick count fed by RcuTick.
constinit u64 g_calls_queued = 0;
constinit u64 g_calls_completed = 0;
constinit u64 g_calls_dropped = 0;

// Drain `q` of every callback whose enqueue tick is now in the past.
// Pops one callback per loop iteration under the queue's spinlock,
// releases the lock BEFORE invoking the callback (which may free
// memory and is not safe to run with IRQs disabled), and counts the
// invocation. Returns total invocations.
u32 DrainQueue(RcuPerCpuQueue& q)
{
    u32 invoked = 0;
    while (true)
    {
        PendingCb cb{};
        bool got = false;
        {
            SpinLockGuard guard(q.lock);
            if (q.count > 0)
            {
                // Ring-buffer integrity invariants. `tail` indexes
                // `q.slots[]` below; `count` bounds the loop's
                // termination condition. Either corruption shape
                // (wild store, slab class collision, etc.) would
                // surface here as either an OOB read of q.slots or
                // an underflow on `--q.count`. The wild-callback
                // check below catches the eventual dispatched-bytes
                // shape; catching the index corruption here pins
                // the offender to RCU's own state instead of the
                // generic "callback fn outside text" path.
                KASSERT_WITH_VALUE(q.tail < kRcuPerCpuQueueDepth, "sync/rcu", "drain: tail oob",
                                   static_cast<u64>(q.tail));
                KASSERT_WITH_VALUE(q.count <= kRcuPerCpuQueueDepth, "sync/rcu", "drain: count > depth",
                                   static_cast<u64>(q.count));
                const u64 now = __atomic_load_n(&g_ticks, __ATOMIC_RELAXED);
                const PendingCb& head = q.slots[q.tail];
                if (now > head.enqueue_tick)
                {
                    cb = head;
                    q.tail = (q.tail + 1) % kRcuPerCpuQueueDepth;
                    --q.count;
                    got = true;
                }
            }
        }
        if (!got)
        {
            break;
        }
        // Run the callback OUTSIDE the spinlock + IRQ-off scope.
        // Callbacks may KFree, take other locks, or do bounded
        // work that's not safe under arch::Cli. The grace contract
        // already guarantees no reader is mid-walk.
        //
        // Sanity-check `cb.fn` before the retpoline call: a queue
        // slot whose fn fell out of kernel TEXT range is a confirmed
        // queue corruption (uninitialised slot dispatched while
        // q.count was non-zero, slab class collision with another
        // structure, etc). The retpoline transparently jumps to
        // whatever value r11 carries, so a wild fn lands at a
        // low-id-map / .bss / heap byte and faults either as
        // `#UD Invalid opcode` (low identity-map bytes decoding as
        // an invalid opcode) or `#PF NX_VIOLATION` (higher-half
        // .bss page, NX-set) — in BOTH cases the trap's RIP is the
        // wild address, not the call site, so the dump banner never
        // names RCU. Catching here names the offender (CPU, fn,
        // arg) and halts with a real banner. Observed 2026-05-22:
        // ~1/15 SMP=8 boots hit one of those shapes on a fresh AP
        // idle's first RcuReclaimLocal dispatch.
        //
        // Bound: kernel `.text` is `[_text_start, _text_end)`.
        // Anything outside that range as a function pointer is a
        // confirmed corruption — never a valid callback target.
        const u64 fn_addr = reinterpret_cast<u64>(cb.fn);
        const u64 text_lo = reinterpret_cast<u64>(::_text_start);
        const u64 text_hi = reinterpret_cast<u64>(::_text_end);
        if (fn_addr < text_lo || fn_addr >= text_hi)
        {
            KBP_PROBE_V(::duetos::debug::ProbeId::kRcuWildCallback, fn_addr);
            arch::SerialWrite("[rcu] WILD callback fn — refusing dispatch  cpu=");
            arch::SerialWriteHex(cpu::CurrentCpuIdOrBsp());
            arch::SerialWrite("  fn=");
            arch::SerialWriteHex(fn_addr);
            arch::SerialWrite("  arg=");
            arch::SerialWriteHex(reinterpret_cast<u64>(cb.arg));
            arch::SerialWrite("  enqueue_tick=");
            arch::SerialWriteHex(cb.enqueue_tick);
            arch::SerialWrite("  text_range=[");
            arch::SerialWriteHex(text_lo);
            arch::SerialWrite("..");
            arch::SerialWriteHex(text_hi);
            arch::SerialWrite(")\n");
            core::PanicWithValue("sync/rcu", "callback fn out of kernel text range", fn_addr);
        }
        cb.fn(cb.arg);
        ++invoked;
        __atomic_add_fetch(&g_calls_completed, 1, __ATOMIC_RELAXED);
    }
    return invoked;
}

} // namespace

bool RcuCall(RcuCallback cb, void* arg)
{
    if (cb == nullptr)
    {
        KLOG_WARN("sync/rcu", "RcuCall: null callback rejected");
        return false;
    }

    // Reading CurrentCpuId before the lock is fine: a migration
    // before SpinLockAcquire would just route us to a peer's queue
    // (which still gets the callback enqueued correctly). After
    // the lock is held, IRQs are disabled and we cannot migrate.
    const u32 cpu = cpu::CurrentCpuIdOrBsp();
    if (cpu >= acpi::kMaxCpus)
    {
        util::SatAtomicAdd<u64>(&g_calls_dropped, 1);
        return false;
    }
    RcuPerCpuQueue& q = g_per_cpu[cpu];

    SpinLockGuard guard(q.lock);
    if (q.count >= kRcuPerCpuQueueDepth)
    {
        // This CPU's queue is saturated. Falling through to a peer
        // would race with cross-CPU drains, so fail cleanly. The
        // caller treats a false return as a memory leak — same
        // contract as the pre-per-CPU queue.
        util::SatAtomicAdd<u64>(&g_calls_dropped, 1);
        KLOG_ONCE_WARN("sync/rcu", "RcuCall: per-CPU queue full — callback DROPPED, will leak");
        return false;
    }
    // `head` indexes `q.slots[]`; a wild-store regression would let
    // the slot write below corrupt adjacent per-CPU structures.
    KASSERT_WITH_VALUE(q.head < kRcuPerCpuQueueDepth, "sync/rcu", "RcuCall: head oob", static_cast<u64>(q.head));
    q.slots[q.head] = {cb, arg, __atomic_load_n(&g_ticks, __ATOMIC_RELAXED)};
    q.head = (q.head + 1) % kRcuPerCpuQueueDepth;
    ++q.count;
    __atomic_add_fetch(&g_calls_queued, 1, __ATOMIC_RELAXED);
    return true;
}

void RcuTick()
{
    // Single store; safe from IRQ context. Advanced by any CPU,
    // observed by every CPU as the grace-period clock.
    __atomic_add_fetch(&g_ticks, 1, __ATOMIC_RELAXED);
}

u32 RcuReclaim()
{
    u32 reclaimed = 0;
    for (u32 cpu = 0; cpu < acpi::kMaxCpus; ++cpu)
    {
        reclaimed += DrainQueue(g_per_cpu[cpu]);
    }
    return reclaimed;
}

u32 RcuReclaimLocal()
{
    // Reading CurrentCpuId without an IRQ-off guard is fine: a
    // migration before DrainQueue starts at most points us at a
    // peer's queue, and DrainQueue is correct on any queue (the
    // per-callback grace check is global, not local). The idle-
    // thread caller pins us to a specific CPU anyway — idle tasks
    // aren't migrated by the scheduler.
    const u32 cpu = cpu::CurrentCpuIdOrBsp();
    if (cpu >= acpi::kMaxCpus)
    {
        // CurrentCpuIdOrBsp returned a corrupted / unconfigured CPU
        // id past the max-CPU array bound. Means PerCpu state was
        // never set up on this CPU; reclaim is a no-op AND the
        // queued callbacks leak. Once-warn so the first occurrence
        // surfaces — the leak side is permanent for this CPU's
        // lifetime, so spamming wouldn't help.
        KLOG_ONCE_WARN_V("sync/rcu", "RcuReclaimLocal: CPU id past kMaxCpus — callbacks will leak", cpu);
        return 0;
    }
    return DrainQueue(g_per_cpu[cpu]);
}

u64 RcuCallsQueued()
{
    return __atomic_load_n(&g_calls_queued, __ATOMIC_RELAXED);
}

u64 RcuCallsCompleted()
{
    return __atomic_load_n(&g_calls_completed, __ATOMIC_RELAXED);
}

namespace
{

constinit u32 g_test_counter = 0;
void TestCb(void* arg)
{
    auto* p = static_cast<u32*>(arg);
    ++(*p);
}

} // namespace

void RcuSelfTest()
{
    KLOG_TRACE_SCOPE("sync/rcu", "RcuSelfTest");
    KLOG_INFO("sync/rcu", "self-test: queue + reclaim cycle");

    g_test_counter = 0;
    const u64 baseline_q = RcuCallsQueued();
    const u64 baseline_c = RcuCallsCompleted();

    // The scheduler tick ISR drives RcuTick() asynchronously, so a
    // timer fire between enqueue and the "no QS yet" assertion would
    // advance g_ticks and reclaim our callback prematurely. Disable
    // interrupts across the deterministic assertions; only the
    // post-tick reclaim count is intrinsically tied to a known
    // g_ticks delta.
    arch::Cli();

    if (!RcuCall(&TestCb, &g_test_counter))
    {
        arch::Sti();
        core::Panic("sync/rcu", "self-test: enqueue failed on empty queue");
    }
    if (RcuCallsQueued() != baseline_q + 1)
    {
        arch::Sti();
        core::Panic("sync/rcu", "self-test: queued counter didn't advance");
    }

    // BEFORE any tick: reclaim must NOT fire — the callback's
    // enqueue-tick equals g_ticks.
    if (RcuReclaim() != 0)
    {
        arch::Sti();
        core::Panic("sync/rcu", "self-test: reclaim fired without QS");
    }
    if (g_test_counter != 0)
    {
        arch::Sti();
        core::Panic("sync/rcu", "self-test: callback ran prematurely");
    }

    // Drive one tick and reclaim. Callback should fire once.
    RcuTick();
    const u32 reclaimed = RcuReclaim();
    if (reclaimed != 1)
    {
        arch::Sti();
        core::Panic("sync/rcu", "self-test: reclaim count != 1");
    }
    if (g_test_counter != 1)
    {
        arch::Sti();
        core::Panic("sync/rcu", "self-test: callback did not run");
    }
    if (RcuCallsCompleted() != baseline_c + 1)
    {
        arch::Sti();
        core::Panic("sync/rcu", "self-test: completed counter didn't advance");
    }

    // Re-reclaim with empty queue is a no-op.
    if (RcuReclaim() != 0)
    {
        arch::Sti();
        core::Panic("sync/rcu", "self-test: reclaim on empty queue non-zero");
    }

    // Local reclaim path is a separate codepath — verify it also
    // observes the same emptiness.
    if (RcuReclaimLocal() != 0)
    {
        arch::Sti();
        core::Panic("sync/rcu", "self-test: local reclaim on empty queue non-zero");
    }

    arch::Sti();

    KLOG_INFO("sync/rcu", "self-test OK (enqueue + grace + reclaim verified)");
}

} // namespace duetos::sync
