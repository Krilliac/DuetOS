/*
 * DuetOS — quiescent-state RCU, v0 (plan B1.4).
 *
 * See `rcu.h` for the public contract. v0 is a single-CPU
 * formulation: a callback enqueued at tick T is reclaimable
 * once `g_ticks > T` (any subsequent tick is a quiescent
 * state). Once SMP lands and per-CPU counters exist, the
 * grace-period rule generalises to "every CPU has ticked at
 * least once since enqueue".
 */

#include "sync/rcu.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "util/types.h"

namespace duetos::sync
{

namespace
{

constexpr u32 kRcuQueueDepth = 256;

struct PendingCb
{
    RcuCallback fn;
    void* arg;
    u64 enqueue_tick;
};

constinit PendingCb g_queue[kRcuQueueDepth] = {};
constinit u32 g_head = 0;  ///< Next slot to write.
constinit u32 g_tail = 0;  ///< Next slot to reclaim.
constinit u32 g_count = 0; ///< Live callbacks.
constinit u64 g_ticks = 0; ///< Monotonic tick count fed by RcuTick.
constinit u64 g_calls_queued = 0;
constinit u64 g_calls_completed = 0;

} // namespace

bool RcuCall(RcuCallback cb, void* arg)
{
    if (cb == nullptr)
    {
        return false;
    }
    arch::Cli();
    if (g_count >= kRcuQueueDepth)
    {
        arch::Sti();
        return false;
    }
    g_queue[g_head] = {cb, arg, g_ticks};
    g_head = (g_head + 1) % kRcuQueueDepth;
    ++g_count;
    ++g_calls_queued;
    arch::Sti();
    return true;
}

void RcuTick()
{
    // Single store; safe from IRQ context.
    __atomic_add_fetch(&g_ticks, 1, __ATOMIC_RELAXED);
}

u32 RcuReclaim()
{
    u32 reclaimed = 0;
    while (true)
    {
        arch::Cli();
        if (g_count == 0)
        {
            arch::Sti();
            break;
        }
        const u64 now = __atomic_load_n(&g_ticks, __ATOMIC_RELAXED);
        const PendingCb& head = g_queue[g_tail];
        // v0 grace rule: any tick AFTER enqueue suffices.
        // Generalises to per-CPU once SMP lands.
        if (now <= head.enqueue_tick)
        {
            arch::Sti();
            break;
        }
        const PendingCb cb = head;
        g_tail = (g_tail + 1) % kRcuQueueDepth;
        --g_count;
        ++g_calls_completed;
        arch::Sti();

        cb.fn(cb.arg);
        ++reclaimed;
    }
    return reclaimed;
}

u64 RcuCallsQueued()
{
    return g_calls_queued;
}

u64 RcuCallsCompleted()
{
    return g_calls_completed;
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
    arch::SerialWrite("[sync] rcu self-test: queue + reclaim cycle\n");

    g_test_counter = 0;
    const u64 baseline_q = g_calls_queued;
    const u64 baseline_c = g_calls_completed;

    if (!RcuCall(&TestCb, &g_test_counter))
    {
        core::Panic("sync/rcu", "self-test: enqueue failed on empty queue");
    }
    if (g_calls_queued != baseline_q + 1)
    {
        core::Panic("sync/rcu", "self-test: queued counter didn't advance");
    }

    // BEFORE any tick: reclaim must NOT fire — the callback's
    // enqueue-tick equals g_ticks.
    if (RcuReclaim() != 0)
    {
        core::Panic("sync/rcu", "self-test: reclaim fired without QS");
    }
    if (g_test_counter != 0)
    {
        core::Panic("sync/rcu", "self-test: callback ran prematurely");
    }

    // Drive one tick and reclaim. Callback should fire once.
    RcuTick();
    const u32 reclaimed = RcuReclaim();
    if (reclaimed != 1)
    {
        core::Panic("sync/rcu", "self-test: reclaim count != 1");
    }
    if (g_test_counter != 1)
    {
        core::Panic("sync/rcu", "self-test: callback did not run");
    }
    if (g_calls_completed != baseline_c + 1)
    {
        core::Panic("sync/rcu", "self-test: completed counter didn't advance");
    }

    // Re-reclaim with empty queue is a no-op.
    if (RcuReclaim() != 0)
    {
        core::Panic("sync/rcu", "self-test: reclaim on empty queue non-zero");
    }

    arch::SerialWrite("[sync] rcu self-test OK (enqueue + grace + reclaim verified).\n");
}

} // namespace duetos::sync
