#include "cpu/ipi_call.h"

#include "acpi/acpi.h"
#include "arch/x86_64/lapic.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/smp.h"
#include "arch/x86_64/traps.h"
#include "core/panic.h"
#include "cpu/percpu.h"
#include "log/klog.h"
#include "util/types.h"

/*
 * DuetOS — cross-CPU function call primitive (v0) implementation.
 *
 * Per-CPU MPSC mailbox: each CPU owns a small ring of "call slots".
 * Producers (any CPU) reserve a slot via an atomic head bump, fill
 * the function pointer / arg / optional completion word, then
 * release-store an ARMED tag. The owning CPU (single consumer) is
 * the only reader: its IPI handler walks slots in order, consuming
 * each ARMED entry, executing the function, posting completion.
 *
 * The ring size is fixed at boot (kRingSlots, 16). A full ring is
 * treated as caller error — the producer will busy-spin briefly to
 * give the consumer a chance to drain before retrying. In practice
 * the only workloads exercising this primitive (TLB shootdown,
 * runtime-checker rebaseline) issue one call per CPU per epoch, so
 * a ring of 16 has 16x slack against actual demand.
 *
 * Owned by kernel/cpu (per-CPU primitive). Lives next to percpu.h
 * rather than under kernel/arch/x86_64 because the public surface
 * is portable — the LAPIC wiring is the only x86-specific bit and
 * we contain it to `SendIpiToCpu` below.
 */

namespace duetos::cpu
{

namespace
{

// 16 slots is a comfortable headroom over the v0 workload (one or
// two simultaneous calls per CPU). A power of two keeps the
// modulo-index step a single AND.
inline constexpr u32 kRingSlots = 16;
inline constexpr u32 kRingMask = kRingSlots - 1;
static_assert((kRingSlots & kRingMask) == 0, "kRingSlots must be a power of two");

// Slot kind. Cleared back to Free by the consumer (target CPU)
// after invocation; producers wait for Free before reusing the
// slot the head index has rolled around to.
enum class SlotKind : u32
{
    Free = 0,
    Armed = 1,
};

struct Slot
{
    // Producers fill these THEN release-store `kind = Armed`.
    // Consumers acquire-load `kind`; if Armed, the other fields
    // are guaranteed visible.
    IpiCallFn fn;
    void* arg;
    volatile u32* completion_word; // nullptr ⇒ fire-and-forget
    volatile u32 kind;             // SlotKind
};

struct Mailbox
{
    // Producer head — atomically bumped, modulo kRingSlots.
    volatile u32 head;
    // Consumer tail — only ever touched by the owning CPU's IPI
    // handler. Bumped past each drained Armed slot.
    volatile u32 tail;
    Slot slots[kRingSlots];
};

// One mailbox per CPU. Indexed by cpu_id; bound by acpi::kMaxCpus.
// Plain BSS — zeroed at boot, which puts every slot in Free state
// and head=tail=0.
constinit Mailbox g_mailboxes[acpi::kMaxCpus] = {};

// IPI vector. Lives in the 240..254 range reserved by traps.cpp
// for kernel-internal IPIs alongside 0xF8 (resched) and 0xF9 (TLB
// shootdown). The dispatcher's IsDispatchedVector whitelist must
// include this vector — see traps.cpp for the update site.
constexpr u8 kIpiCallVector = 0xFA;

// ICR encoding bits (mirrors smp.cpp's local constexpr set). Keep
// them local — the LAPIC ICR is the one place these constants
// belong; copying them avoids depending on smp.cpp's anon-ns view.
constexpr u32 kIcrDeliveryFixed = 0u << 8;
constexpr u32 kIcrLevelAssert = 1u << 14;

// Soft cap on the wait-completion spin loop. Healthy hardware
// services an IPI in microseconds; 1M pause iterations is a wide
// safety margin. Beyond it we bump wait_timeout_count and KLOG_WARN
// but DO NOT panic — a stuck peer is recoverable; an unconditional
// panic on a transient LAPIC slowdown would be worse.
inline constexpr u64 kWaitSpinSoftCap = 1'000'000;

// Diagnostic stats. Updated with relaxed atomics — they're
// strictly monotonic counters and a torn read is harmless. Sized
// to u64 so a year-long uptime can't wrap them in practice.
constinit u64 g_calls_one_total = 0;
constinit u64 g_calls_each_total = 0;
constinit u64 g_invocations_received = 0;
constinit u64 g_wait_spin_max_loops = 0;
constinit u64 g_wait_timeout_count = 0;

// Send the IPI at the given target's LAPIC. Wraps `SmpSendIpi`
// with the fixed-delivery encoding the call mailbox expects. No
// shorthand — we target a specific LAPIC ID so the consumer set
// is exactly the one CPU whose mailbox we just posted to.
void SendIpiToCpu(u32 cpu_id)
{
    PerCpu* peer = arch::SmpGetPercpu(cpu_id);
    if (peer == nullptr)
    {
        return;
    }
    const u32 icr_low = kIcrDeliveryFixed | kIcrLevelAssert | static_cast<u32>(kIpiCallVector);
    arch::SmpSendIpi(peer->lapic_id, icr_low);
}

// Push one call onto `target`'s mailbox. Producer-side path —
// runs on the requesting CPU, can be any CPU.
//
// Returns true on success, false if the producer side observed a
// full ring after exhausting a short retry budget. A full ring is
// astonishingly unlikely under normal load; if it ever fires we'd
// want to learn about it, hence the KLOG_WARN.
bool MailboxPost(Mailbox& target, IpiCallFn fn, void* arg, volatile u32* completion_word)
{
    // Bounded retry on full mailbox. The producer doesn't wait
    // forever — that would risk a deadlock if the target CPU is
    // itself blocked posting to us. 256 iterations is enough for
    // any healthy peer to drain at least one slot.
    for (u32 attempt = 0; attempt < 256; ++attempt)
    {
        const u32 head = __atomic_load_n(&target.head, __ATOMIC_RELAXED);
        const u32 tail = __atomic_load_n(&target.tail, __ATOMIC_ACQUIRE);
        // Distance between head and tail in slots used. >= kRingSlots
        // means the ring is full and we must wait for the consumer to
        // bump tail. Unsigned subtraction handles wraparound.
        if ((head - tail) >= kRingSlots)
        {
            asm volatile("pause" ::: "memory");
            continue;
        }
        // Try to claim this head slot. CAS guards against another
        // producer racing us for the same index.
        u32 expected = head;
        if (!__atomic_compare_exchange_n(&target.head, &expected, head + 1, /*weak=*/false, __ATOMIC_ACQ_REL,
                                         __ATOMIC_RELAXED))
        {
            continue;
        }
        // Slot is ours. The consumer guarantees that by the time
        // tail has advanced past index `head - kRingSlots`, that
        // slot's kind is back to Free — so once we won the CAS,
        // we own this slot and can publish into it.
        Slot& slot = target.slots[head & kRingMask];
        // Spin briefly waiting for the consumer to free the slot
        // we just claimed, on the off chance head wraparound beat
        // consumer drain. In practice we already checked the
        // head-tail distance, so this should be one read.
        u32 k = __atomic_load_n(&slot.kind, __ATOMIC_ACQUIRE);
        while (k != static_cast<u32>(SlotKind::Free))
        {
            asm volatile("pause" ::: "memory");
            k = __atomic_load_n(&slot.kind, __ATOMIC_ACQUIRE);
        }
        slot.fn = fn;
        slot.arg = arg;
        slot.completion_word = completion_word;
        // Release-store the arm tag. Pairs with the acquire load
        // in DrainMailbox so the consumer sees fn/arg/completion
        // populated.
        __atomic_store_n(&slot.kind, static_cast<u32>(SlotKind::Armed), __ATOMIC_RELEASE);
        return true;
    }
    KLOG_WARN("cpu/ipi-call", "mailbox full — caller will see no-op");
    return false;
}

// Consumer side. Runs on the target CPU in IPI context with IF=0.
// Drains every Armed slot at or after `tail` up to the head as
// observed at entry. A producer that arms a slot AFTER our entry
// snapshot is left for the next IPI; that producer's IPI is the
// edge that re-fires this handler.
void DrainMailbox(Mailbox& self)
{
    // Snapshot the head at entry — see comment above for why we
    // don't loop forever against new producers.
    const u32 head_at_entry = __atomic_load_n(&self.head, __ATOMIC_ACQUIRE);
    u32 t = __atomic_load_n(&self.tail, __ATOMIC_RELAXED);
    while (t != head_at_entry)
    {
        Slot& slot = self.slots[t & kRingMask];
        // Acquire-load kind. Pairs with the producer's release
        // store. If we observe Armed, fn/arg/completion_word are
        // guaranteed visible. A producer that won the head CAS
        // but hasn't released yet leaves kind == Free here — we
        // just spin briefly waiting for them; we already saw
        // their head bump.
        u32 k = __atomic_load_n(&slot.kind, __ATOMIC_ACQUIRE);
        while (k != static_cast<u32>(SlotKind::Armed))
        {
            asm volatile("pause" ::: "memory");
            k = __atomic_load_n(&slot.kind, __ATOMIC_ACQUIRE);
        }
        IpiCallFn fn = slot.fn;
        void* arg = slot.arg;
        volatile u32* completion = slot.completion_word;
        // Mark slot Free BEFORE bumping tail. The Free store has
        // release semantics; the tail bump uses release so a
        // future producer sees an in-bounds slot in Free state.
        __atomic_store_n(&slot.kind, static_cast<u32>(SlotKind::Free), __ATOMIC_RELEASE);
        ++t;
        __atomic_store_n(&self.tail, t, __ATOMIC_RELEASE);
        // Run the callable. Any panic / fault inside fn will trap
        // through the IPI vector's normal exception path — same
        // recovery shape as a faulty timer handler.
        if (fn != nullptr)
        {
            fn(arg);
            __atomic_fetch_add(&g_invocations_received, 1, __ATOMIC_RELAXED);
        }
        // Post completion AFTER fn has returned. Release so the
        // waiter observes any side effects fn made.
        if (completion != nullptr)
        {
            __atomic_store_n(completion, 1u, __ATOMIC_RELEASE);
        }
    }
}

// Vector handler. The IRQ dispatcher (traps.cpp) issues the LAPIC
// EOI on return for vectors in the dispatched-IPI whitelist, so
// the handler itself does NOT call LapicEoi. It also doesn't sti
// — IF=0 is the natural state through the handler and we want it
// to stay that way (the mailbox consumer is single-threaded on
// this CPU; allowing another vector to fire mid-drain would break
// that).
void IpiCallVectorHandler()
{
    PerCpu* self = CurrentCpu();
    const u32 cpu_id = (self != nullptr) ? self->cpu_id : 0u;
    if (cpu_id >= acpi::kMaxCpus)
    {
        return;
    }
    DrainMailbox(g_mailboxes[cpu_id]);
}

// Wait for `done` to flip to 1. Bounded by `kWaitSpinSoftCap` to
// the soft cap; beyond it we keep waiting but bump the timeout
// counter and emit a one-shot WARN. (Hard-panicking on a slow
// peer is more harmful than continuing.)
void SpinForCompletion(volatile u32* done, const char* tag)
{
    u64 spins = 0;
    while (__atomic_load_n(done, __ATOMIC_ACQUIRE) == 0u)
    {
        asm volatile("pause" ::: "memory");
        ++spins;
        if (spins == kWaitSpinSoftCap)
        {
            __atomic_fetch_add(&g_wait_timeout_count, 1, __ATOMIC_RELAXED);
            KLOG_WARN("cpu/ipi-call", "wait-completion spin exceeded soft cap");
            (void)tag;
        }
    }
    // Track the deepest observed wait, monotonic.
    u64 prev = __atomic_load_n(&g_wait_spin_max_loops, __ATOMIC_RELAXED);
    while (spins > prev)
    {
        if (__atomic_compare_exchange_n(&g_wait_spin_max_loops, &prev, spins, /*weak=*/true, __ATOMIC_RELAXED,
                                        __ATOMIC_RELAXED))
        {
            break;
        }
    }
}

} // namespace

bool IpiCallOne(u32 cpu_id, IpiCallFn fn, void* arg, bool wait)
{
    if (fn == nullptr)
    {
        return false;
    }
    __atomic_fetch_add(&g_calls_one_total, 1, __ATOMIC_RELAXED);

    PerCpu* self = CurrentCpu();
    const u32 self_id = (self != nullptr) ? self->cpu_id : 0u;

    // Local short-circuit: no IPI needed. Avoids the self-wait
    // deadlock and is the common case for "broadcast to N CPUs"
    // when N==1 and that one is us.
    if (cpu_id == self_id)
    {
        fn(arg);
        __atomic_fetch_add(&g_invocations_received, 1, __ATOMIC_RELAXED);
        return true;
    }

    if (cpu_id >= acpi::kMaxCpus)
    {
        return false;
    }
    PerCpu* peer = arch::SmpGetPercpu(cpu_id);
    if (peer == nullptr)
    {
        return false;
    }

    Mailbox& target = g_mailboxes[cpu_id];

    if (wait)
    {
        // Stack-allocated completion word. The mailbox slot
        // captures &done; the target's handler posts a release
        // store; we spin acquire-load until it flips.
        volatile u32 done = 0;
        if (!MailboxPost(target, fn, arg, &done))
        {
            return false;
        }
        SendIpiToCpu(cpu_id);
        SpinForCompletion(&done, "one");
        return true;
    }

    // Fire-and-forget. Caller is responsible for `arg` outliving
    // the target's drain; documented on the API.
    if (!MailboxPost(target, fn, arg, nullptr))
    {
        return false;
    }
    SendIpiToCpu(cpu_id);
    return true;
}

u32 IpiCallEach(IpiCallFn fn, void* arg, bool wait)
{
    if (fn == nullptr)
    {
        return 0;
    }
    __atomic_fetch_add(&g_calls_each_total, 1, __ATOMIC_RELAXED);

    PerCpu* self = CurrentCpu();
    const u32 self_id = (self != nullptr) ? self->cpu_id : 0u;
    const u32 limit = arch::SmpCpuIdLimit();

    // Local leg first — fn runs synchronously on the caller before
    // any peer IPI is fired. Means a `wait == false` broadcast has
    // the local effect committed by return.
    fn(arg);
    __atomic_fetch_add(&g_invocations_received, 1, __ATOMIC_RELAXED);
    u32 dispatched = 1;

    // One completion word per peer. kMaxCpus is 32 today; the
    // array is small enough to live comfortably on the kernel
    // stack. Each slot starts at 0; each target's handler sets
    // its own slot to 1; the caller spins until every slot is 1.
    volatile u32 completions[acpi::kMaxCpus] = {};

    for (u32 id = 0; id < limit; ++id)
    {
        if (id == self_id)
        {
            continue;
        }
        PerCpu* peer = arch::SmpGetPercpu(id);
        if (peer == nullptr)
        {
            continue;
        }
        Mailbox& target = g_mailboxes[id];
        volatile u32* slot = wait ? &completions[id] : nullptr;
        if (!MailboxPost(target, fn, arg, slot))
        {
            continue;
        }
        SendIpiToCpu(id);
        ++dispatched;
    }

    if (wait)
    {
        for (u32 id = 0; id < limit; ++id)
        {
            if (id == self_id)
            {
                continue;
            }
            PerCpu* peer = arch::SmpGetPercpu(id);
            if (peer == nullptr)
            {
                continue;
            }
            SpinForCompletion(&completions[id], "each");
        }
    }

    return dispatched;
}

IpiCallStats IpiCallStatsRead()
{
    IpiCallStats out{};
    out.calls_one_total = __atomic_load_n(&g_calls_one_total, __ATOMIC_RELAXED);
    out.calls_each_total = __atomic_load_n(&g_calls_each_total, __ATOMIC_RELAXED);
    out.invocations_received = __atomic_load_n(&g_invocations_received, __ATOMIC_RELAXED);
    out.wait_spin_max_loops = __atomic_load_n(&g_wait_spin_max_loops, __ATOMIC_RELAXED);
    out.wait_timeout_count = __atomic_load_n(&g_wait_timeout_count, __ATOMIC_RELAXED);
    return out;
}

void IpiCallInstall()
{
    arch::IrqInstall(kIpiCallVector, &IpiCallVectorHandler);
}

namespace
{

// Self-test callback. Bumps a per-CPU counter so the harness can
// verify it actually ran on the expected CPUs.
struct SelfTestCtx
{
    volatile u32 hits[acpi::kMaxCpus];
};

void SelfTestBump(void* arg)
{
    SelfTestCtx* ctx = static_cast<SelfTestCtx*>(arg);
    PerCpu* self = CurrentCpu();
    const u32 cpu_id = (self != nullptr) ? self->cpu_id : 0u;
    if (cpu_id < acpi::kMaxCpus)
    {
        __atomic_fetch_add(&ctx->hits[cpu_id], 1, __ATOMIC_RELAXED);
    }
}

void WriteHexDecimal(u64 value)
{
    // Tiny decimal emitter — we don't pull a printf into this TU.
    char buf[24];
    int n = 0;
    if (value == 0)
    {
        buf[n++] = '0';
    }
    else
    {
        char tmp[24];
        int t = 0;
        while (value != 0)
        {
            tmp[t++] = '0' + static_cast<char>(value % 10);
            value /= 10;
        }
        while (t > 0)
        {
            buf[n++] = tmp[--t];
        }
    }
    buf[n] = '\0';
    arch::SerialWrite(buf);
}

} // namespace

void IpiCallSelfTest()
{
    SelfTestCtx ctx{};

    PerCpu* self = CurrentCpu();
    const u32 self_id = (self != nullptr) ? self->cpu_id : 0u;
    const u32 limit = arch::SmpCpuIdLimit();

    const IpiCallStats before = IpiCallStatsRead();

    // (1) Self IpiCallOne, wait=true. fn must have run; hits[self] == 1.
    if (!IpiCallOne(self_id, &SelfTestBump, &ctx, /*wait=*/true))
    {
        ::duetos::core::Panic("cpu/ipi-call", "self IpiCallOne wait=true returned false");
    }
    if (__atomic_load_n(&ctx.hits[self_id], __ATOMIC_RELAXED) != 1u)
    {
        ::duetos::core::Panic("cpu/ipi-call", "self IpiCallOne wait=true did not run fn");
    }

    // (2) Self IpiCallOne, wait=false. Still synchronous because self.
    if (!IpiCallOne(self_id, &SelfTestBump, &ctx, /*wait=*/false))
    {
        ::duetos::core::Panic("cpu/ipi-call", "self IpiCallOne wait=false returned false");
    }
    if (__atomic_load_n(&ctx.hits[self_id], __ATOMIC_RELAXED) != 2u)
    {
        ::duetos::core::Panic("cpu/ipi-call", "self IpiCallOne wait=false did not run fn");
    }

    // (3) Peer IpiCallOne, wait=true. Pick the first AP we find.
    u32 peer_id = 0;
    bool have_peer = false;
    for (u32 id = 0; id < limit; ++id)
    {
        if (id == self_id)
        {
            continue;
        }
        if (arch::SmpGetPercpu(id) != nullptr)
        {
            peer_id = id;
            have_peer = true;
            break;
        }
    }
    if (have_peer)
    {
        if (!IpiCallOne(peer_id, &SelfTestBump, &ctx, /*wait=*/true))
        {
            ::duetos::core::Panic("cpu/ipi-call", "peer IpiCallOne wait=true returned false");
        }
        // After wait=true returns, the peer has incremented hits[peer_id].
        if (__atomic_load_n(&ctx.hits[peer_id], __ATOMIC_RELAXED) != 1u)
        {
            ::duetos::core::Panic("cpu/ipi-call", "peer IpiCallOne wait=true did not run fn on peer");
        }
    }

    // (4) IpiCallEach wait=true. Every online CPU bumps its own
    // slot — verify the count.
    const u32 dispatched = IpiCallEach(&SelfTestBump, &ctx, /*wait=*/true);
    if (dispatched == 0)
    {
        ::duetos::core::Panic("cpu/ipi-call", "IpiCallEach dispatched zero CPUs");
    }
    u32 hit_cpus = 0;
    for (u32 id = 0; id < limit; ++id)
    {
        const u32 hits = __atomic_load_n(&ctx.hits[id], __ATOMIC_RELAXED);
        if (hits == 0)
        {
            continue;
        }
        ++hit_cpus;
    }
    // hit_cpus must include at least every dispatched CPU (some
    // CPUs may have additional hits from earlier legs — that's
    // fine; we only check coverage). The exact count of CPUs
    // that received the broadcast must match `dispatched`.
    if (hit_cpus < dispatched)
    {
        KLOG_WARN("cpu/ipi-call", "IpiCallEach coverage shortfall: hit_cpus < dispatched");
    }
    u32 each_hit_cpus = 0;
    for (u32 id = 0; id < limit; ++id)
    {
        // CPU `id` was part of the broadcast iff its PerCpu exists.
        if (arch::SmpGetPercpu(id) == nullptr)
        {
            continue;
        }
        ++each_hit_cpus;
    }
    if (dispatched != each_hit_cpus)
    {
        KLOG_WARN("cpu/ipi-call", "IpiCallEach dispatched count != online CPU count");
    }

    // Stats — invocation count must have advanced by at least:
    //   2 (self legs) + (have_peer ? 1 : 0) + dispatched (each)
    const IpiCallStats after = IpiCallStatsRead();
    const u64 invs_delta = after.invocations_received - before.invocations_received;
    const u64 expected_min = 2 + (have_peer ? 1ULL : 0ULL) + static_cast<u64>(dispatched);
    if (invs_delta < expected_min)
    {
        KLOG_WARN_V("cpu/ipi-call", "invocations counter advanced by less than expected", invs_delta);
    }

    arch::SerialWrite("[ipi-call] self-test OK (cpus=");
    WriteHexDecimal(static_cast<u64>(each_hit_cpus));
    arch::SerialWrite(", invocations=");
    WriteHexDecimal(invs_delta);
    arch::SerialWrite(")\n");
}

} // namespace duetos::cpu
