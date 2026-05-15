#include "ipc/iocp.h"

#include "core/panic.h"
#include "log/klog.h"
#include "mm/kheap.h"

namespace duetos::ipc
{

namespace
{

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
    for (u32 i = 0; i < IocpPort::kCapacity; ++i)
        Zero(&port->slots[i]);
    port->head = 0;
    port->tail = 0;
    port->count = 0;
    port->association_count = 0;
    port->closed = false;
    // sched::Mutex and sched::Condvar are correct in the zero
    // state — owner=nullptr, no waiters. The caller may have
    // value-initialised the whole IocpPort via `*port = {}`;
    // if not (the legacy IocpInit path on a reused stack-local),
    // we still leave the lock fields alone — neither holds
    // dynamic resources that need teardown.
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
    *out = port->slots[port->tail];
    Zero(&port->slots[port->tail]);
    port->tail = (port->tail + 1) % IocpPort::kCapacity;
    --port->count;
    sched::MutexUnlock(&port->inner);
    return true;
}

bool IocpWait(IocpPort* port, IocpCompletion* out, u64 timeout_ticks)
{
    if (port == nullptr || out == nullptr)
        return false;
    sched::MutexLock(&port->inner);
    if (port->count == 0 && !port->closed)
    {
        if (timeout_ticks == 0)
        {
            // Probe-and-return — same observable as IocpTryPop
            // on an empty port, with the lock already taken.
            sched::MutexUnlock(&port->inner);
            return false;
        }
        if (timeout_ticks == kIocpTimeoutInfinite)
        {
            // Win32 `INFINITE` — loop until either a producer
            // signals not_empty or `IocpClose` broadcasts.
            while (port->count == 0 && !port->closed)
                sched::CondvarWait(&port->not_empty, &port->inner);
        }
        else
        {
            // Finite timeout — single CondvarWaitTimeout pass.
            // Win32 GetQueuedCompletionStatus's timeout is a
            // best-effort budget; spurious wakes are rare in
            // this codebase and the caller can re-issue if it
            // needs sharper granularity.
            (void)sched::CondvarWaitTimeout(&port->not_empty, &port->inner, timeout_ticks);
        }
    }
    if (port->count == 0)
    {
        // Either timed out or the port was closed underneath us.
        sched::MutexUnlock(&port->inner);
        return false;
    }
    *out = port->slots[port->tail];
    Zero(&port->slots[port->tail]);
    port->tail = (port->tail + 1) % IocpPort::kCapacity;
    --port->count;
    sched::MutexUnlock(&port->inner);
    return true;
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
    // empty queue returns false without parking the caller.
    IocpCompletion drained = {};
    if (IocpWait(&port, &drained, /*timeout_ticks=*/0))
        ::duetos::core::Panic("ipc/iocp", "self-test: IocpWait(timeout=0) returned true on empty");

    // IocpWait drains a posted completion (single-threaded — the
    // post happens before the wait, so no parking is required to
    // make progress).
    IocpCompletion fresh = {};
    fresh.overlapped_user_va = 0xC0DEULL;
    fresh.completion_key = 0xAA55;
    fresh.bytes_transferred = 7;
    if (!IocpTryPost(&port, fresh))
        ::duetos::core::Panic("ipc/iocp", "self-test: try-post failed before IocpWait");
    if (!IocpWait(&port, &drained, /*timeout_ticks=*/1))
        ::duetos::core::Panic("ipc/iocp", "self-test: IocpWait failed to drain a queued completion");
    if (drained.overlapped_user_va != 0xC0DEULL || drained.completion_key != 0xAA55 || drained.bytes_transferred != 7)
        ::duetos::core::Panic("ipc/iocp", "self-test: IocpWait returned the wrong completion");

    // IocpWait on empty with a finite (1 tick) timeout: no
    // producer will signal not_empty, so CondvarWaitTimeout has
    // to fire after the budget elapses and the function must
    // return false. Verifies the finite-timeout path completes
    // (does not park indefinitely) on no producer.
    if (IocpWait(&port, &drained, /*timeout_ticks=*/1))
        ::duetos::core::Panic("ipc/iocp", "self-test: IocpWait(timeout=1) on empty returned true");

    // Closed port short-circuits IocpWait — even with INFINITE
    // timeout the broadcast fires from IocpClose and the wait
    // returns false. We pre-close, then wait with timeout=0
    // (which never parks anyway) so the boot test stays
    // deterministic; the infinite-wait wake-on-close is the
    // production path that real GetQueuedCompletionStatus calls
    // hit when the port is destroyed underneath them.
    IocpClose(&port);
    if (IocpWait(&port, &drained, /*timeout_ticks=*/0))
        ::duetos::core::Panic("ipc/iocp", "self-test: IocpWait returned true on closed port");

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
    IocpCompletion c2 = {};
    c2.completion_key = 0xCAFE;
    if (!IocpTryPost(heap, c2))
        ::duetos::core::Panic("ipc/iocp", "self-test: heap port try-post failed");
    KObjectRelease(&heap->base);
    // heap is now freed — must not be touched again.

    KLOG_INFO("ipc/iocp", "self-test PASS");
}

} // namespace duetos::ipc
