#include "subsystems/win32/waitaddr_syscall.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/traps.h"
#include "mm/paging.h"
#include "sched/sched.h"

namespace duetos::subsystems::win32
{

namespace
{

constexpr u64 kInfiniteMs = 0xFFFFFFFFu;
constexpr u64 kMsPerTick = 10; // scheduler 100 Hz, mirrors event_syscall
constexpr u32 kBuckets = 256;  // power of two; wide enough that distinct
                               // addresses rarely share a queue

// Address-hashed wait queues. Zero-init = empty (WaitQueue needs no
// explicit init). A bucket collision means an unrelated waiter may
// be woken; it re-checks its own word and re-waits, so correctness
// holds — only a lost wakeup would be a bug, and waking the whole
// bucket on every wake prevents that.
constinit sched::WaitQueue g_futex_bucket[kBuckets] = {};
// Stable publication sequence for each bucket. A waker advances it before
// touching the scheduler queue; a waiter samples it before reading the user
// word and lets the scheduler recheck it while publishing the block.
constinit u64 g_futex_sequence[kBuckets] = {};

constexpr u64 kSaturatedSequence = ~u64(0);

u64 SequenceSnapshot(u32 bucket)
{
    return __atomic_load_n(&g_futex_sequence[bucket], __ATOMIC_ACQUIRE);
}

void PublishBucketEvent(u32 bucket)
{
    u64 observed = __atomic_load_n(&g_futex_sequence[bucket], __ATOMIC_RELAXED);
    while (observed != kSaturatedSequence)
    {
        if (__atomic_compare_exchange_n(&g_futex_sequence[bucket], &observed, observed + 1, false, __ATOMIC_RELEASE,
                                        __ATOMIC_RELAXED))
        {
            return;
        }
    }
}

u32 BucketOf(u64 va)
{
    // Mix a couple of address bits; futex words are usually 4/8-byte
    // aligned so the low bits are poor entropy on their own.
    const u64 h = (va >> 3) ^ (va >> 11) ^ (va >> 19);
    return static_cast<u32>(h & (kBuckets - 1));
}

u64 SizeMask(u64 size)
{
    if (size >= 8)
    {
        return ~0ULL;
    }
    if (size == 0)
    {
        return 0;
    }
    return (1ULL << (size * 8)) - 1ULL;
}

} // namespace

void DoWaitOnAddress(arch::TrapFrame* frame)
{
    const u64 user_va = frame->rdi;
    const u64 expected = frame->rsi;
    const u64 size = frame->rdx;
    const u64 timeout_ms = frame->r10 & 0xFFFFFFFFu;

    if (user_va == 0 || (size != 1 && size != 2 && size != 4 && size != 8))
    {
        // Bad shape — return "woken" so the caller re-checks and
        // doesn't spin in the kernel on a malformed request.
        frame->rax = 1;
        return;
    }

    const u64 mask = SizeMask(size);
    const u32 bucket = BucketOf(user_va);
    const u64 observed_sequence = SequenceSnapshot(bucket);

    // Snapshot before probing the hostile word. Wake publication and the
    // scheduler's sequence-recheck/enqueue transaction close both sides of
    // the compare-versus-block window without disabling interrupts around a
    // potentially faulting user copy.
    u64 cur = 0;
    if (!mm::CopyFromUser(&cur, reinterpret_cast<const void*>(user_va), size))
    {
        frame->rax = 1;
        return;
    }
    if ((cur & mask) != (expected & mask))
    {
        // Value already differs — Win32 WaitOnAddress returns
        // immediately TRUE in this case.
        frame->rax = 1;
        return;
    }

    if (observed_sequence == kSaturatedSequence)
    {
        const u64 requested_ticks = timeout_ms == kInfiniteMs ? ~u64(0) : (timeout_ms + (kMsPerTick - 1)) / kMsPerTick;
        const u64 fallback_ticks = requested_ticks == 0 ? 0 : 1;
        const sched::WaitQueueBlockResult fallback =
            sched::WaitQueueBlockTimeoutCancellable(&g_futex_bucket[bucket], fallback_ticks);
        if (fallback == sched::WaitQueueBlockResult::Cancelled)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        if (fallback == sched::WaitQueueBlockResult::TimedOut && requested_ticks <= 1)
        {
            frame->rax = 0;
            return;
        }
        frame->rax = 1;
        return;
    }

    if (timeout_ms == kInfiniteMs)
    {
        const sched::WaitQueueBlockResult wait_result = sched::WaitQueueBlockIfSequenceUnchangedCancellable(
            &g_futex_bucket[bucket], &g_futex_sequence[bucket], observed_sequence);
        if (wait_result == sched::WaitQueueBlockResult::Cancelled)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        frame->rax = 1; // woken (possibly spurious — caller re-checks)
        return;
    }

    const u64 ticks = (timeout_ms + (kMsPerTick - 1)) / kMsPerTick;
    const sched::WaitQueueBlockResult wait_result = sched::WaitQueueBlockIfSequenceUnchangedTimeoutCancellable(
        &g_futex_bucket[bucket], &g_futex_sequence[bucket], observed_sequence, ticks);
    if (wait_result == sched::WaitQueueBlockResult::Cancelled)
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }
    const bool woken = wait_result != sched::WaitQueueBlockResult::TimedOut;
    frame->rax = woken ? 1 : 0; // 0 == timed out
}

void DoWakeByAddress(arch::TrapFrame* frame)
{
    const u64 user_va = frame->rdi;
    if (user_va == 0)
    {
        frame->rax = 0;
        return;
    }
    const u32 bucket = BucketOf(user_va);
    PublishBucketEvent(bucket);
    // Wake the whole bucket regardless of single/all. Single is
    // best-effort: with a bucket shared by a colliding address,
    // waking only the queue head could leave the intended waiter
    // asleep (lost wakeup). Waking all and letting each re-check
    // its own word is the correct, simple v0 — extra wakeups are
    // spurious, which the Win32 contract explicitly permits.
    arch::Cli();
    sched::WaitQueueWakeAll(&g_futex_bucket[bucket]);
    arch::Sti();
    frame->rax = 0;
}

} // namespace duetos::subsystems::win32
