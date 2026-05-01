/*
 * DuetOS — sequence lock implementation, v0 (plan B1.3).
 *
 * See `seqlock.h` for the public contract. This TU owns the
 * sequence-counter state machine + writer-side spinlock wiring +
 * boot self-test.
 *
 * Memory ordering notes:
 *   - The writer's "bump to odd" must precede the protected mutation
 *     and the "bump to even" must follow it, both in program AND
 *     compiler order. We use `volatile` on `sequence` for the read
 *     side and a compiler barrier (`asm volatile("" ::: "memory")`)
 *     after each store on the write side. On x86, regular stores are
 *     already sequentially consistent with other stores, so no
 *     explicit `mfence` is needed here — the compiler barrier alone
 *     prevents the optimizer from reordering the protected payload's
 *     stores around the sequence stores.
 *   - The reader's "sample → read payload → re-sample" is similarly
 *     fenced via `volatile` reads + a compiler barrier between the
 *     payload load and the second sequence load. If the payload is
 *     read in compiler-reordered order, EndRead can falsely succeed
 *     on torn data; the barrier prevents that.
 *
 * No atomic RMW on the sequence counter — only plain stores from the
 * writer (which holds the inner SpinLock so it's the sole writer).
 * Readers do plain volatile loads; they never write to `sequence`.
 */

#include "sync/seqlock.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "sched/sched.h"
#include "sync/spinlock.h"
#include "util/types.h"

namespace duetos::sync
{

namespace
{

[[noreturn]] void PanicSeq(const char* what)
{
    core::Panic("sync/seqlock", what);
}

inline void CompilerBarrier()
{
    asm volatile("" ::: "memory");
}

} // namespace

IrqFlags SeqLockBeginWrite(SeqLock& lock)
{
    // Inner spinlock first — only one writer at a time may bump
    // `sequence`. The spinlock also disables IRQs on this CPU, so
    // an IRQ handler that tries to acquire the same writer side
    // can't deadlock against us (it would just retry once we've
    // re-enabled IRQs in EndWrite).
    const IrqFlags flags = SpinLockAcquire(lock.writer);

    // Even → odd. After this store, any concurrent reader's EndRead
    // is guaranteed to fail until the matching EndWrite bumps back
    // to even. The compiler barrier prevents the protected payload's
    // mutations (which the caller is about to perform) from leaking
    // *upwards* past this store in compiled order.
    u32 cur = lock.sequence;
    if ((cur & 1u) != 0)
    {
        // Caught odd sequence at the start of a write — a previous
        // writer must have aborted without releasing, or the lock
        // was used uninitialised after an `EndWrite` panic.
        // Debug: panic and surface the leak. Release: log it, then
        // force the sequence forward to the next even value so the
        // recovery write below can proceed; in-flight readers will
        // retry on their EndRead and re-snapshot.
        core::DebugPanicOrWarn("sync/seqlock", "BeginWrite found sequence already odd (writer leak?)");
        lock.sequence = cur + 1u; // even
        cur = lock.sequence;
    }
    lock.sequence = cur + 1u;
    CompilerBarrier();

    return flags;
}

void SeqLockEndWrite(SeqLock& lock, IrqFlags flags)
{
    // Compiler barrier first — ensures the caller's payload writes
    // are committed to memory before we publish the even sequence
    // that signals "stable" to readers.
    CompilerBarrier();
    const u32 cur = lock.sequence;
    if ((cur & 1u) == 0)
    {
        // Even at EndWrite — somebody else released the sequence
        // (impossible while we held the inner spinlock) or it was
        // never bumped. Debug: panic. Release: log it, skip the
        // bump (sequence is already at a stable parity), and
        // release the writer spinlock. The compiler barrier
        // above already published the payload writes.
        core::DebugPanicOrWarn("sync/seqlock", "EndWrite found sequence already even");
        SpinLockRelease(lock.writer, flags);
        return;
    }
    lock.sequence = cur + 1u;

    SpinLockRelease(lock.writer, flags);
}

u32 SeqLockBeginRead(const SeqLock& lock)
{
    // Plain volatile load. Readers don't synchronise with each
    // other and don't need an atomic primitive — they only need to
    // see SOME recent value of `sequence` and re-validate at the
    // end of the read. The compiler barrier prevents the caller's
    // about-to-happen payload reads from leaking *upwards* past
    // this load.
    const u32 s = lock.sequence;
    CompilerBarrier();
    return s;
}

bool SeqLockEndRead(const SeqLock& lock, u32 snapshot)
{
    // Re-sample after the caller's payload reads (the compiler
    // barrier here mirrors the one in BeginRead — together they
    // sandwich the payload reads between two `sequence` loads).
    // The read is good iff:
    //   1. snapshot was even at BeginRead time (no writer was
    //      mid-update when we started), AND
    //   2. sequence is still exactly snapshot now (no writer
    //      slipped a complete update in between).
    CompilerBarrier();
    const u32 now = lock.sequence;
    if ((snapshot & 1u) != 0)
    {
        return false;
    }
    return now == snapshot;
}

void SeqLockSelfTest()
{
    arch::SerialWrite("[sync] seqlock self-test: sequence parity + reader retry paths\n");

    SeqLock lock{};

    // (1) Fresh lock — sequence is 0 (even). Reader sees stable.
    if (lock.sequence != 0)
    {
        PanicSeq("fresh lock not zero-initialised");
    }
    {
        const u32 seq = SeqLockBeginRead(lock);
        if (seq != 0)
        {
            PanicSeq("BeginRead on fresh lock did not return 0");
        }
        if (!SeqLockEndRead(lock, seq))
        {
            PanicSeq("EndRead failed on quiet lock");
        }
    }

    // (2) Begin/EndWrite bumps sequence by 2 (even → odd → even).
    // Inside the writer window the sequence is odd; outside it's
    // even.
    {
        const IrqFlags f = SeqLockBeginWrite(lock);
        if (lock.sequence != 1u)
        {
            SpinLockRelease(lock.writer, f);
            PanicSeq("BeginWrite did not bump sequence to 1");
        }
        if ((lock.sequence & 1u) == 0)
        {
            SpinLockRelease(lock.writer, f);
            PanicSeq("BeginWrite did not flip parity to odd");
        }
        SeqLockEndWrite(lock, f);
        if (lock.sequence != 2u)
        {
            PanicSeq("EndWrite did not bump sequence to 2");
        }
        if ((lock.sequence & 1u) != 0)
        {
            PanicSeq("EndWrite did not return parity to even");
        }
    }

    // (3) Reader pattern across a clean writer cycle. The retry
    // loop must converge — sequence stable, EndRead returns true,
    // we exit with a coherent snapshot.
    {
        u32 snap = 0xDEADBEEF;
        u32 seq;
        u32 iters = 0;
        do
        {
            ++iters;
            seq = SeqLockBeginRead(lock);
            // No actual payload here; the test is the loop's
            // convergence on a quiet lock.
            snap = seq; // pretend the payload mirrors the seq
        } while (!SeqLockEndRead(lock, seq));
        if (iters != 1)
        {
            PanicSeq("reader retried on quiet lock");
        }
        if (snap != 2u)
        {
            PanicSeq("reader snapshot did not match expected sequence");
        }
    }

    // (4) Reader detects "writer in progress" (odd snapshot)
    // without spinning. We synthesise the odd state by acquiring
    // the writer side and releasing only after the EndRead check.
    {
        const IrqFlags f = SeqLockBeginWrite(lock);
        // Sequence is now 3 (odd). A reader that samples here
        // MUST see EndRead return false regardless of whether the
        // sequence changes between Begin and End.
        const u32 seq = SeqLockBeginRead(lock);
        if ((seq & 1u) == 0)
        {
            SpinLockRelease(lock.writer, f);
            PanicSeq("BeginRead returned even sequence while writer holds the lock");
        }
        if (SeqLockEndRead(lock, seq))
        {
            SpinLockRelease(lock.writer, f);
            PanicSeq("EndRead returned true on odd snapshot (writer in progress)");
        }
        SeqLockEndWrite(lock, f);
    }

    // (5) Reader detects "writer completed mid-read" — sample with
    // an even sequence, then race a writer in BEFORE EndRead, and
    // EndRead must report failure even though the parity is even
    // again.
    {
        const u32 seq = SeqLockBeginRead(lock);
        if ((seq & 1u) != 0)
        {
            PanicSeq("BeginRead returned odd on quiet lock at start of step 5");
        }
        // Synthesise a complete writer cycle while the reader
        // "thinks" it's holding the snapshot.
        {
            const IrqFlags f = SeqLockBeginWrite(lock);
            SeqLockEndWrite(lock, f);
        }
        if (SeqLockEndRead(lock, seq))
        {
            PanicSeq("EndRead returned true after a complete writer cycle bumped the sequence");
        }
    }

    // (6) After all the above, sequence is 6 (3 complete writer
    // cycles × 2). A fresh BeginRead/EndRead pair must succeed
    // again — we're back to a quiet, even state.
    if (lock.sequence != 6u)
    {
        PanicSeq("sequence at end of self-test not 6");
    }
    {
        const u32 seq = SeqLockBeginRead(lock);
        if (!SeqLockEndRead(lock, seq))
        {
            PanicSeq("EndRead failed on quiet lock after all writer cycles");
        }
    }

    // (7) RAII guard exercises the same Begin/End under a scope
    // exit. Sequence must climb by 2 across the guard.
    {
        const u32 before = lock.sequence;
        {
            SeqLockWriteGuard g(lock);
            if (lock.sequence != before + 1u)
            {
                PanicSeq("write guard did not bump sequence to odd");
            }
        }
        if (lock.sequence != before + 2u)
        {
            PanicSeq("write guard did not bump sequence to even on scope exit");
        }
    }

    arch::SerialWrite("[sync] seqlock self-test OK (parity + retry + guard verified).\n");
}

namespace
{

constexpr u32 kSeqContentionWriterCycles = 200;

struct SeqContentionShared
{
    SeqLock lock;
    u32 payload_lo; ///< Two halves the writer keeps consistent. The reader's
    u32 payload_hi; ///< invariant is `payload_hi == payload_lo + 1`.
    u32 writer_done;
    u32 reader_retries; ///< Number of retry-loop iterations beyond the first.
};

SeqContentionShared g_seq_shared{};

void SeqWriterTask(void* arg)
{
    auto* s = static_cast<SeqContentionShared*>(arg);
    for (u32 i = 0; i < kSeqContentionWriterCycles; ++i)
    {
        SeqLockWriteGuard g(s->lock);
        // Mutate the two halves so a torn read is observable —
        // hi must always equal lo+1. The reader checks this
        // invariant; if EndRead returns true on a torn snapshot,
        // the invariant breaks and the test panics.
        s->payload_lo = i;
        s->payload_hi = i + 1u;
        // Yield sometimes so the reader gets a chance to retry
        // mid-cycle. Without this, on a single CPU the reader
        // would run between writer cycles only and never see a
        // torn snapshot.
        if ((i & 7u) == 0)
        {
            sched::SchedYield();
        }
    }
    __atomic_store_n(&s->writer_done, 1, __ATOMIC_SEQ_CST);
}

} // namespace

void SeqLockContentionSelfTest()
{
    arch::SerialWrite("[sync] seqlock contention self-test: concurrent writer + reader\n");

    // Reset shared state. Reader runs in the calling thread;
    // writer is a kernel-spawned thread. Seed the payload so the
    // `hi == lo + 1` invariant the reader checks holds BEFORE the
    // writer's first cycle — without seeding, the reader's first
    // EndRead succeeds against the all-zero default state and the
    // invariant fires `0 != 0 + 1` before the writer has run.
    g_seq_shared = SeqContentionShared{};
    g_seq_shared.payload_hi = g_seq_shared.payload_lo + 1u;

    sched::SchedCreate(SeqWriterTask, &g_seq_shared, "seq-writer");

    // Reader loop — keep reading until the writer's "done" flag
    // is set, then do one final read to confirm the post-state.
    // Each individual read uses the canonical retry pattern.
    u32 last_lo = 0;
    u32 last_hi = 0;
    constexpr u32 kReaderTimeoutTicks = 200; // ~2 s
    u32 ticks_waited = 0;
    while (__atomic_load_n(&g_seq_shared.writer_done, __ATOMIC_SEQ_CST) == 0)
    {
        u32 seq;
        u32 lo = 0;
        u32 hi = 0;
        u32 iters = 0;
        bool ok = false;
        do
        {
            ++iters;
            seq = SeqLockBeginRead(g_seq_shared.lock);
            // Read the two halves with a compiler barrier between
            // them so the optimizer can't fuse / reorder.
            lo = g_seq_shared.payload_lo;
            asm volatile("" ::: "memory");
            hi = g_seq_shared.payload_hi;
            // If the writer is in-progress (odd seq) OR completed
            // mid-read (seq bumped), EndRead returns false and we
            // retry. The retry MUST eventually converge — the
            // writer is bounded.
            if (iters > 10000u)
            {
                core::Panic("sync/seqlock", "contention test: reader retry loop did not converge");
            }
            ok = SeqLockEndRead(g_seq_shared.lock, seq);
            // Single-CPU cooperative kernel: the writer may have
            // yielded mid-write while still holding `lock.writer`
            // (sequence stays odd until it wakes and runs to
            // EndWrite). Spinning here without yielding starves
            // the writer and the inner loop never converges, so
            // give the scheduler a turn between retries.
            if (!ok)
            {
                sched::SchedYield();
            }
        } while (!ok);

        // After a successful EndRead, the invariant `hi == lo + 1`
        // MUST hold — that's the whole point of seqlock. If a
        // torn snapshot got through the retry, this fires.
        if (hi != lo + 1u)
        {
            core::Panic("sync/seqlock", "contention test: torn snapshot escaped retry");
        }
        last_lo = lo;
        last_hi = hi;
        if (iters > 1)
        {
            __atomic_add_fetch(&g_seq_shared.reader_retries, iters - 1, __ATOMIC_SEQ_CST);
        }

        // Yield so the writer gets to run. Without this the
        // reader could otherwise spin indefinitely on a quiet
        // lock and starve the writer.
        sched::SchedYield();

        if (++ticks_waited > kReaderTimeoutTicks)
        {
            core::Panic("sync/seqlock", "contention test: writer did not finish in time");
        }
    }

    // Final read after writer completion. Sequence should be even
    // (writer ended its last cycle), and the payload should match
    // the writer's final write.
    if ((g_seq_shared.lock.sequence & 1u) != 0)
    {
        core::Panic("sync/seqlock", "contention test: lock sequence odd at end (writer mid-cycle)");
    }
    if (last_hi != last_lo + 1u)
    {
        core::Panic("sync/seqlock", "contention test: final payload invariant broken");
    }

    // The reader MUST have observed at least one retry — if not,
    // the test isn't actually testing contention; the writer ran
    // entirely between two reader checks. With 200 writer cycles
    // and SchedYield in both paths, this should be statistically
    // certain on a cooperative scheduler.
    const u32 retries = __atomic_load_n(&g_seq_shared.reader_retries, __ATOMIC_SEQ_CST);
    if (retries == 0)
    {
        core::Panic("sync/seqlock", "contention test: reader never retried (no observed contention)");
    }

    arch::SerialWrite("[sync] seqlock contention self-test OK (writer cycles done, reader observed ");
    arch::SerialWriteHex(retries);
    arch::SerialWrite(" retries).\n");
}

} // namespace duetos::sync
