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
}

bool IocpTryPost(IocpPort* port, const IocpCompletion& c)
{
    if (port == nullptr)
        return false;
    if (port->count >= IocpPort::kCapacity)
        return false;
    port->slots[port->head] = c;
    port->head = (port->head + 1) % IocpPort::kCapacity;
    ++port->count;
    return true;
}

bool IocpTryPop(IocpPort* port, IocpCompletion* out)
{
    if (port == nullptr || out == nullptr)
        return false;
    if (port->count == 0)
        return false;
    *out = port->slots[port->tail];
    Zero(&port->slots[port->tail]);
    port->tail = (port->tail + 1) % IocpPort::kCapacity;
    --port->count;
    return true;
}

void IocpClose(IocpPort* port)
{
    if (port == nullptr)
        return;
    IocpInit(port);
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
