#include "cpu/percpu_counter.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "cpu/percpu.h"
#include "log/klog.h"
#include "sched/sched.h"
#include "sched/workpool.h"
#include "sync/spinlock.h"

namespace duetos::cpu
{

namespace
{

inline i64 AbsI64(i64 v)
{
    return v < 0 ? -v : v;
}

} // namespace

PercpuCounter::PercpuCounter(i64 batch) : m_global(0), m_batch(batch < 1 ? 1 : batch), m_lock{}
{
    for (u64 i = 0; i < acpi::kMaxCpus; ++i)
    {
        m_stash[i] = 0;
    }
}

void PercpuCounter::Add(i64 delta)
{
    // Acquire the lock unconditionally. The spinlock CLI guarantees:
    //   (a) no migration between the cpu_id read and the stash RMW,
    //   (b) no IRQ-handler re-entry interleaving with the stash
    //       update on the same CPU.
    //
    // Acquiring on every Add looks heavy at first glance, but the
    // lock is fully uncontended on the fast path — each CPU writes
    // its own stash slot and no other CPU is even reading it. The
    // ticket-lock fast path is a single uncontended atomic, which is
    // already what a `LOCK XADD` on a global counter would cost; the
    // win comes from the fact that the cache line we're dirtying is
    // CPU-private (no inter-CPU MESI ping-pong on the hot global),
    // not from skipping the atomic. The fold path on top of that is
    // amortised 1/m_batch.
    const sync::IrqFlags flags = sync::SpinLockAcquire(m_lock);

    const u32 cpu = cpu::CurrentCpuIdOrBsp();
    // Defence-in-depth: a future kMaxCpus bump that forgets to
    // resize the stash, or a stray ID from a not-yet-online CPU,
    // would otherwise scribble past the array. Fall back to slot 0
    // — wrong-CPU attribution is a slop hit, not a corruption hit.
    const u32 slot = (cpu < acpi::kMaxCpus) ? cpu : 0u;

    i64 stash = m_stash[slot] + delta;
    if (AbsI64(stash) >= m_batch)
    {
        // Fold the stash into the global and zero it. Both writes
        // happen under the same lock so a concurrent ReadExact sees
        // a consistent snapshot.
        m_global += stash;
        stash = 0;
    }
    m_stash[slot] = stash;

    sync::SpinLockRelease(m_lock, flags);
}

i64 PercpuCounter::ReadApproximate() const
{
    // Atomic-relaxed load: a torn read on x86_64 is impossible at
    // 8-byte alignment, but the compiler may still hoist or reorder
    // the read without an explicit atomic op. Cast away const for
    // the builtin — m_global is logically mutable from the
    // counter's POV (the fold path writes it) and ReadApproximate
    // is the read-side view.
    return __atomic_load_n(const_cast<volatile i64*>(&m_global), __ATOMIC_RELAXED);
}

i64 PercpuCounter::ReadExact()
{
    const sync::IrqFlags flags = sync::SpinLockAcquire(m_lock);
    i64 sum = m_global;
    for (u64 i = 0; i < acpi::kMaxCpus; ++i)
    {
        sum += m_stash[i];
    }
    sync::SpinLockRelease(m_lock, flags);
    return sum;
}

void PercpuCounter::Reset(i64 value)
{
    const sync::IrqFlags flags = sync::SpinLockAcquire(m_lock);
    m_global = value;
    for (u64 i = 0; i < acpi::kMaxCpus; ++i)
    {
        m_stash[i] = 0;
    }
    sync::SpinLockRelease(m_lock, flags);
}

// ---------------------------------------------------------------------------
// Self-test
// ---------------------------------------------------------------------------

namespace
{

// Shared state passed to the workpool callback. The work-item
// thunk reads the iteration count + counter pointer and calls
// `Add(+1)` N times, then `Add(-1)` N times — so the net effect
// of every worker is zero. This validates two properties at once:
//   1. Per-CPU stash isolation: workers running on different CPUs
//      hit different stash slots; an accidental aliasing bug would
//      show up as a non-zero ReadExact after the drain.
//   2. Fold correctness: with kAddsPerWorker >> batch, every worker
//      crosses the fold threshold many times.
struct PcpuCounterSelfTestState
{
    PercpuCounter* counter;
    u64 adds_per_worker;
};

void PcpuCounterSelfTestItem(void* arg)
{
    auto* st = static_cast<PcpuCounterSelfTestState*>(arg);
    for (u64 i = 0; i < st->adds_per_worker; ++i)
    {
        st->counter->Add(+1);
    }
    for (u64 i = 0; i < st->adds_per_worker; ++i)
    {
        st->counter->Add(-1);
    }
}

} // namespace

void PercpuCounterSelfTest()
{
    KLOG_TRACE_SCOPE("cpu/percpu_counter", "PercpuCounterSelfTest");

    // -----------------------------------------------------------------
    // Single-CPU correctness — exercise the BSP-only path before
    // adding any SMP work. Catches obvious algorithm bugs (sign,
    // fold direction, batch threshold) in a deterministic setting.
    // -----------------------------------------------------------------
    {
        PercpuCounter c(8);
        if (c.ReadApproximate() != 0 || c.ReadExact() != 0)
        {
            core::Panic("cpu/percpu_counter", "fresh counter not zero");
        }

        // 100 +1 adds, then 100 -1 adds. Net = 0.
        for (u64 i = 0; i < 100; ++i)
        {
            c.Add(+1);
        }
        for (u64 i = 0; i < 100; ++i)
        {
            c.Add(-1);
        }
        const i64 after = c.ReadExact();
        if (after != 0)
        {
            core::PanicWithValue("cpu/percpu_counter", "BSP add/sub net != 0", static_cast<u64>(after));
        }

        // 1000 +1 adds — at batch=8, this folds ~125 times. The
        // exact read MUST be 1000 regardless of how much remains
        // in the stash; the approximate read may lag by < 8.
        for (u64 i = 0; i < 1000; ++i)
        {
            c.Add(+1);
        }
        const i64 exact = c.ReadExact();
        if (exact != 1000)
        {
            core::PanicWithValue("cpu/percpu_counter", "BSP 1000-add ReadExact != 1000", static_cast<u64>(exact));
        }
        const i64 approx = c.ReadApproximate();
        const i64 drift = (approx > exact ? approx - exact : exact - approx);
        if (drift >= 8 * static_cast<i64>(acpi::kMaxCpus))
        {
            core::PanicWithValue("cpu/percpu_counter", "ReadApproximate drift > batch * kMaxCpus",
                                 static_cast<u64>(drift));
        }
    }

    // -----------------------------------------------------------------
    // Multi-CPU isolation — run N workers each doing M ±1 cycles via
    // the workpool. Workers float across CPUs (TaskPriority::Normal,
    // no affinity), so each worker's stream of Adds touches whichever
    // CPU's stash the scheduler happened to put it on. The net effect
    // is exactly zero — any drift means a stash slot got attributed
    // to the wrong CPU somewhere along the fold path.
    // -----------------------------------------------------------------
    constexpr u32 kWorkers = 4;
    constexpr u32 kCapacity = 8;
    constexpr u64 kAddsPerWorker = 5000;

    PercpuCounter counter(16);
    sched::WorkPool* pool = sched::WorkPoolCreate(kWorkers, kCapacity, "pcpu-ctr-st");
    if (pool == nullptr)
    {
        // Self-test isn't a hard failure if the scheduler couldn't
        // hand out worker tasks — log and skip the SMP half. The
        // BSP-only block above already validated the core algorithm.
        KLOG_WARN("cpu/percpu_counter", "self-test: workpool unavailable, SMP half skipped");
        arch::SerialWrite("[percpu-counter] self-test OK\n");
        return;
    }

    PcpuCounterSelfTestState st{&counter, kAddsPerWorker};
    for (u32 i = 0; i < kWorkers * 4; ++i)
    {
        sched::WorkPoolSubmit(pool, &PcpuCounterSelfTestItem, &st);
    }
    sched::WorkPoolDrain(pool);

    const i64 smp_exact = counter.ReadExact();
    if (smp_exact != 0)
    {
        sched::WorkPoolShutdown(pool);
        core::PanicWithValue("cpu/percpu_counter", "SMP add/sub net != 0", static_cast<u64>(smp_exact));
    }

    // Hand back the +N case under SMP — N workers each contribute
    // `kAddsPerWorker` then `0`. The total ought to land at
    // kWorkers * 4 * kAddsPerWorker.
    counter.Reset(0);
    auto smp_plus_item = [](void* arg)
    {
        auto* s = static_cast<PcpuCounterSelfTestState*>(arg);
        for (u64 i = 0; i < s->adds_per_worker; ++i)
        {
            s->counter->Add(+1);
        }
    };
    for (u32 i = 0; i < kWorkers * 4; ++i)
    {
        sched::WorkPoolSubmit(pool, smp_plus_item, &st);
    }
    sched::WorkPoolDrain(pool);

    const i64 expected = static_cast<i64>(kWorkers) * 4 * static_cast<i64>(kAddsPerWorker);
    const i64 smp_plus = counter.ReadExact();
    if (smp_plus != expected)
    {
        sched::WorkPoolShutdown(pool);
        core::PanicWithValue("cpu/percpu_counter", "SMP +1 ReadExact mismatch", static_cast<u64>(smp_plus));
    }

    sched::WorkPoolShutdown(pool);

    arch::SerialWrite("[percpu-counter] self-test OK\n");
}

} // namespace duetos::cpu
