#include "ipc/iocp.h"

#include "core/panic.h"
#include "log/klog.h"
#include "mm/kheap.h"

namespace duetos::ipc
{

namespace
{

constexpr u64 kMaxRelativeWaitTicks = (~u64{0}) >> 1;

u64 RelativeDeadlineFromNow(u64 now, u64 ticks)
{
    const u64 bounded_ticks = ticks > kMaxRelativeWaitTicks ? kMaxRelativeWaitTicks : ticks;
    return bounded_ticks > (~u64{0} - now) ? ~u64{0} : now + bounded_ticks;
}

bool TickDeadlineReached(u64 now, u64 deadline)
{
    return static_cast<i64>(now - deadline) >= 0;
}

void Zero(IocpCompletion* c)
{
    c->overlapped_user_va = 0;
    c->completion_key = 0;
    c->bytes_transferred = 0;
    c->ntstatus = 0;
    for (u32 i = 0; i < sizeof(c->_pad); ++i)
        c->_pad[i] = 0;
}

} // namespace

void IocpInit(IocpPort* port)
{
    if (port == nullptr)
        return;
    // The lock fields MUST be zeroed here, not assumed
    // value-initialised. Callers legitimately pass a bare
    // stack-local `IocpPort port;` (the boot self-test does) —
    // without an explicit `{}` the embedded `sched::Mutex` has
    // an indeterminate `owner`, and the first MutexLock would
    // mistake the garbage for "held by someone else" and block
    // forever on a garbage wait queue. Zero IS the valid empty
    // state for both primitives: Mutex → owner=nullptr +
    // no waiters, Condvar → no waiters (see the zero-init
    // contract documented on `sched::Condvar`). Neither holds
    // dynamic resources, so zeroing an in-use lock here would
    // only be wrong if a caller re-init'd a contended port —
    // which `IocpClose` (the only re-init path) never does
    // while waiters are parked.
    port->inner = sched::Mutex{};
    port->not_empty = sched::Condvar{};
    for (u32 i = 0; i < IocpPort::kCapacity; ++i)
        Zero(&port->slots[i]);
    port->head = 0;
    port->tail = 0;
    port->count = 0;
    port->association_count = 0;
    port->closed = false;
}

bool IocpTryPost(IocpPort* port, const IocpCompletion& c)
{
    if (port == nullptr)
        return false;
    sched::MutexLock(&port->inner);
    if (port->closed || port->count >= IocpPort::kCapacity)
    {
        sched::MutexUnlock(&port->inner);
        return false;
    }
    // Ring-buffer index invariant. `head < kCapacity` should hold by
    // the modulo-update below, but a wild store between cycles would
    // let `slots[head]` write past the slot array. KASSERT catches
    // the corruption at the source rather than letting a torn IOCP
    // completion poison every GetQueuedCompletionStatus caller after.
    KASSERT_WITH_VALUE(port->head < IocpPort::kCapacity, "ipc/iocp", "try-post: head oob",
                       static_cast<u64>(port->head));
    port->slots[port->head] = c;
    port->head = (port->head + 1) % IocpPort::kCapacity;
    ++port->count;
    sched::CondvarSignal(&port->not_empty);
    sched::MutexUnlock(&port->inner);
    return true;
}

bool IocpTryPop(IocpPort* port, IocpCompletion* out)
{
    if (port == nullptr || out == nullptr)
        return false;
    sched::MutexLock(&port->inner);
    if (port->count == 0)
    {
        sched::MutexUnlock(&port->inner);
        return false;
    }
    KASSERT_WITH_VALUE(port->tail < IocpPort::kCapacity, "ipc/iocp", "try-pop: tail oob", static_cast<u64>(port->tail));
    KASSERT_WITH_VALUE(port->count <= IocpPort::kCapacity, "ipc/iocp", "try-pop: count > capacity",
                       static_cast<u64>(port->count));
    *out = port->slots[port->tail];
    Zero(&port->slots[port->tail]);
    port->tail = (port->tail + 1) % IocpPort::kCapacity;
    --port->count;
    sched::MutexUnlock(&port->inner);
    return true;
}

IocpWaitResult IocpWait(IocpPort* port, IocpCompletion* out, u64 timeout_ticks)
{
    if (port == nullptr || out == nullptr)
        return IocpWaitResult::Failed;
    sched::MutexLock(&port->inner);
    if (port->closed)
    {
        sched::MutexUnlock(&port->inner);
        return IocpWaitResult::Closed;
    }
    if (port->count == 0 && timeout_ticks == 0)
    {
        // Probe-and-return: same observable as IocpTryPop on an
        // empty port, with the lock already taken.
        sched::MutexUnlock(&port->inner);
        return IocpWaitResult::TimedOut;
    }
    if (timeout_ticks == kIocpTimeoutInfinite)
    {
        while (port->count == 0 && !port->closed)
        {
            if (sched::CondvarWaitCancellable(&port->not_empty, &port->inner) == sched::WaitQueueBlockResult::Cancelled)
            {
                sched::MutexUnlock(&port->inner);
                return IocpWaitResult::Cancelled;
            }
        }
    }
    else if (port->count == 0)
    {
        // One absolute deadline: spurious wakes and a completion
        // consumed by another waiter never re-arm the caller's budget.
        const u64 deadline = RelativeDeadlineFromNow(sched::SchedNowTicks(), timeout_ticks);
        while (port->count == 0 && !port->closed)
        {
            const u64 now = sched::SchedNowTicks();
            if (TickDeadlineReached(now, deadline))
            {
                sched::MutexUnlock(&port->inner);
                return IocpWaitResult::TimedOut;
            }
            const sched::WaitQueueBlockResult wait_result =
                sched::CondvarWaitTimeoutCancellable(&port->not_empty, &port->inner, deadline - now);
            if (wait_result == sched::WaitQueueBlockResult::Cancelled)
            {
                sched::MutexUnlock(&port->inner);
                return IocpWaitResult::Cancelled;
            }
            if (wait_result == sched::WaitQueueBlockResult::TimedOut && port->count == 0 && !port->closed)
            {
                sched::MutexUnlock(&port->inner);
                return IocpWaitResult::TimedOut;
            }
        }
    }
    if (port->closed)
    {
        sched::MutexUnlock(&port->inner);
        return IocpWaitResult::Closed;
    }
    KASSERT(port->count > 0, "ipc/iocp", "wait: missing completion after wake");
    KASSERT_WITH_VALUE(port->tail < IocpPort::kCapacity, "ipc/iocp", "wait: tail oob", static_cast<u64>(port->tail));
    *out = port->slots[port->tail];
    Zero(&port->slots[port->tail]);
    port->tail = (port->tail + 1) % IocpPort::kCapacity;
    --port->count;
    sched::MutexUnlock(&port->inner);
    return IocpWaitResult::Dequeued;
}

void IocpClose(IocpPort* port)
{
    if (port == nullptr)
        return;
    sched::MutexLock(&port->inner);
    port->closed = true;
    // Wake every blocked consumer so they observe `closed` and
    // return false. Broadcast (not Signal) — multiple callers
    // may be parked.
    sched::CondvarBroadcast(&port->not_empty);
    for (u32 i = 0; i < IocpPort::kCapacity; ++i)
        Zero(&port->slots[i]);
    port->head = 0;
    port->tail = 0;
    port->count = 0;
    port->association_count = 0;
    sched::MutexUnlock(&port->inner);
}

namespace
{
void IocpDestroy(KObject* obj)
{
    if (obj == nullptr)
        return;
    // KObject is the first member of IocpPort — the cast is the
    // standard handle-table round-trip shape (see kobject.h).
    auto* port = reinterpret_cast<IocpPort*>(obj);
    IocpClose(port);
    ::duetos::mm::KFree(port);
}
} // namespace

::duetos::core::Result<IocpPort*> IocpCreate()
{
    auto* port = static_cast<IocpPort*>(::duetos::mm::KMalloc(sizeof(IocpPort)));
    if (port == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::OutOfMemory};
    // Value-init zeroes both the KObject base and the ring fields;
    // `KObjectInit` then sets the type tag + destroy callback +
    // refcount = 1. The ring stays empty until the first
    // `IocpTryPost`.
    *port = IocpPort{};
    KObjectInit(&port->base, KObjectType::Iocp, &IocpDestroy);
    return port;
}

void IocpSelfTest()
{
    IocpPort port;
    IocpInit(&port);

    // Empty port: try-pop returns false.
    IocpCompletion got = {};
    if (IocpTryPop(&port, &got))
        ::duetos::core::Panic("ipc/iocp", "self-test: try-pop on empty returned true");

    // Post N completions, drain them, verify FIFO order.
    constexpr u32 kN = 8;
    for (u32 i = 0; i < kN; ++i)
    {
        IocpCompletion c = {};
        c.overlapped_user_va = 0x4000ULL + i;
        c.completion_key = 0x10 + i;
        c.bytes_transferred = 100 + i;
        c.ntstatus = 0;
        if (!IocpTryPost(&port, c))
            ::duetos::core::Panic("ipc/iocp", "self-test: try-post failed under capacity");
    }
    if (port.count != kN)
        ::duetos::core::Panic("ipc/iocp", "self-test: count != N after posts");

    for (u32 i = 0; i < kN; ++i)
    {
        IocpCompletion c = {};
        if (!IocpTryPop(&port, &c))
            ::duetos::core::Panic("ipc/iocp", "self-test: try-pop failed mid-drain");
        if (c.overlapped_user_va != (0x4000ULL + i) || c.completion_key != (0x10ULL + i) ||
            c.bytes_transferred != (100ULL + i))
            ::duetos::core::Panic("ipc/iocp", "self-test: FIFO order broken");
    }
    if (port.count != 0)
        ::duetos::core::Panic("ipc/iocp", "self-test: count != 0 after drain");

    // Fill to capacity, verify overflow returns false.
    for (u32 i = 0; i < IocpPort::kCapacity; ++i)
    {
        IocpCompletion c = {};
        c.completion_key = i;
        if (!IocpTryPost(&port, c))
            ::duetos::core::Panic("ipc/iocp", "self-test: try-post failed before capacity");
    }
    IocpCompletion overflow = {};
    if (IocpTryPost(&port, overflow))
        ::duetos::core::Panic("ipc/iocp", "self-test: try-post accepted past capacity");

    // Close drains.
    IocpClose(&port);
    if (port.count != 0)
        ::duetos::core::Panic("ipc/iocp", "self-test: Close didn't drain");
    if (!port.closed)
        ::duetos::core::Panic("ipc/iocp", "self-test: Close didn't set closed flag");

    // Closed port refuses subsequent posts.
    IocpCompletion after_close = {};
    if (IocpTryPost(&port, after_close))
        ::duetos::core::Panic("ipc/iocp", "self-test: try-post accepted on closed port");

    // Blocking wait — reset to a fresh state for the next batch
    // of checks. IocpInit clears `closed` back to false.
    IocpInit(&port);

    // IocpWait with timeout_ticks == 0 behaves like IocpTryPop:
    // empty queue reports timeout without parking the caller.
    IocpCompletion drained = {};
    drained.overlapped_user_va = 0x1111;
    drained.completion_key = 0x2222;
    drained.bytes_transferred = 0x3333;
    drained.ntstatus = 0x4444;
    if (IocpWait(nullptr, &drained, /*timeout_ticks=*/0) != IocpWaitResult::Failed ||
        IocpWait(&port, nullptr, /*timeout_ticks=*/0) != IocpWaitResult::Failed)
    {
        ::duetos::core::Panic("ipc/iocp", "self-test: invalid wait arguments did not fail");
    }
    if (IocpWait(&port, &drained, /*timeout_ticks=*/0) != IocpWaitResult::TimedOut)
        ::duetos::core::Panic("ipc/iocp", "self-test: IocpWait(timeout=0) did not report timeout");
    if (drained.overlapped_user_va != 0x1111 || drained.completion_key != 0x2222 ||
        drained.bytes_transferred != 0x3333 || drained.ntstatus != 0x4444)
    {
        ::duetos::core::Panic("ipc/iocp", "self-test: timed-out wait modified output");
    }

    // IocpWait drains a posted completion (single-threaded — the
    // post happens before the wait, so no parking is required to
    // make progress).
    IocpCompletion fresh = {};
    fresh.overlapped_user_va = 0xC0DEULL;
    fresh.completion_key = 0xAA55;
    fresh.bytes_transferred = 7;
    if (!IocpTryPost(&port, fresh))
        ::duetos::core::Panic("ipc/iocp", "self-test: try-post failed before IocpWait");
    if (IocpWait(&port, &drained, /*timeout_ticks=*/1) != IocpWaitResult::Dequeued)
        ::duetos::core::Panic("ipc/iocp", "self-test: IocpWait failed to drain a queued completion");
    if (drained.overlapped_user_va != 0xC0DEULL || drained.completion_key != 0xAA55 || drained.bytes_transferred != 7)
        ::duetos::core::Panic("ipc/iocp", "self-test: IocpWait returned the wrong completion");

    // NOTE: the genuinely-parking path (IocpWait on an empty port
    // with a finite or infinite timeout) is deliberately NOT
    // exercised here. This self-test runs from the boot task
    // inside RunPhase(Phase::Sched); parking it on a
    // CondvarWaitTimeout with no producer to signal relies on
    // timer-driven sleep-queue wakeup of the boot task, which is
    // not a guarantee this early in bring-up (it hung the boot in
    // testing). The blocking primitive is the verbatim
    // KMailbox Mutex+Condvar pattern, whose contended wake/timeout
    // paths are covered by `KMailboxContentionSelfTest` (spawned
    // producer/consumer tasks) in the same phase. Here we only
    // assert the non-parking branches: probe (timeout=0),
    // drain-when-ready (count>0), and the closed-port
    // short-circuit below.

    // Closed port short-circuits IocpWait without parking — even
    // a timeout=0 probe must report Closed once `closed` is set.
    // This is the production path real GetQueuedCompletionStatus
    // callers hit when the port is destroyed underneath them
    // (the infinite-wait wake-on-close broadcast is exercised by
    // real workloads, not the boot self-test).
    IocpClose(&port);
    const IocpCompletion before_closed_wait = drained;
    if (IocpWait(&port, &drained, /*timeout_ticks=*/0) != IocpWaitResult::Closed)
        ::duetos::core::Panic("ipc/iocp", "self-test: IocpWait did not report closed port");
    if (drained.overlapped_user_va != before_closed_wait.overlapped_user_va ||
        drained.completion_key != before_closed_wait.completion_key ||
        drained.bytes_transferred != before_closed_wait.bytes_transferred ||
        drained.ntstatus != before_closed_wait.ntstatus)
    {
        ::duetos::core::Panic("ipc/iocp", "self-test: closed wait modified output");
    }

    // Re-init to leave the port in a clean state for any
    // subsequent self-test extensions.
    IocpInit(&port);

    // KObject promotion path: IocpCreate / KObjectRelease must
    // produce a well-formed KObjectType::Iocp + free the storage
    // on last release. The destroy callback is registered on the
    // type and fires from KObjectRelease — we have no way to
    // sense the free directly, so we rely on the kheap's
    // double-free / use-after-free guards to surface a regression
    // if the destroy path is wrong. The type-tag + refcount
    // checks below catch the most common KObjectInit regressions
    // (forgot to register the destroy callback, wrong type tag).
    auto create_r = IocpCreate();
    if (!create_r.has_value())
        ::duetos::core::Panic("ipc/iocp", "self-test: IocpCreate failed (kheap OOM?)");
    IocpPort* heap = create_r.value();
    if (heap->base.type != KObjectType::Iocp)
        ::duetos::core::Panic("ipc/iocp", "self-test: IocpCreate wrong type tag");
    if (heap->base.refcount != 1)
        ::duetos::core::Panic("ipc/iocp", "self-test: IocpCreate refcount != 1");
    if (heap->base.destroy == nullptr)
        ::duetos::core::Panic("ipc/iocp", "self-test: IocpCreate destroy callback null");
    // Exercise the ring through the heap-allocated port too so
    // the KObject base offset is correct (a misaligned base
    // would corrupt the ring's first slot on the post below).
    // The post is Win32-shaped — the exact completion SYS_IOCP_POST
    // (PostQueuedCompletionStatus) fabricates: caller-picked
    // key / bytes / OVERLAPPED*, ntstatus = STATUS_SUCCESS — and
    // the drain goes through IocpWait, the SYS_IOCP_REMOVE path.
    IocpCompletion c2 = {};
    c2.overlapped_user_va = 0xBEEFULL;
    c2.completion_key = 0xCAFE;
    c2.bytes_transferred = 42;
    c2.ntstatus = 0;
    if (!IocpTryPost(heap, c2))
        ::duetos::core::Panic("ipc/iocp", "self-test: heap port try-post failed");
    IocpCompletion posted = {};
    if (IocpWait(heap, &posted, /*timeout_ticks=*/1) != IocpWaitResult::Dequeued)
        ::duetos::core::Panic("ipc/iocp", "self-test: heap port IocpWait failed to drain the post");
    if (posted.overlapped_user_va != 0xBEEFULL || posted.completion_key != 0xCAFE || posted.bytes_transferred != 42 ||
        posted.ntstatus != 0)
        ::duetos::core::Panic("ipc/iocp", "self-test: heap port post/wait round-trip corrupted the completion");
    KObjectRelease(&heap->base);
    // heap is now freed — must not be touched again.

    KLOG_INFO("ipc/iocp", "self-test PASS");
}

} // namespace duetos::ipc
