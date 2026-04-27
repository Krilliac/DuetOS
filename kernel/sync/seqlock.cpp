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
    const u32 cur = lock.sequence;
    if ((cur & 1u) != 0)
    {
        // Caught odd sequence at the start of a write — a previous
        // writer must have aborted without releasing, or the lock
        // was used uninitialised after an `EndWrite` panic. Either
        // way, the invariant is broken; surface immediately.
        SpinLockRelease(lock.writer, flags);
        PanicSeq("BeginWrite found sequence already odd (writer leak?)");
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
        // never bumped. Bug.
        SpinLockRelease(lock.writer, flags);
        PanicSeq("EndWrite found sequence already even");
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

} // namespace duetos::sync
