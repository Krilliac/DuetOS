#include "ipc/kmessage_port.h"

#include "ipc/handle_table.h"
#include "ipc/kobject.h"
#include "ipc/message_ring.h"

#if defined(DUETOS_HOST_TEST)
#include <new>
#else
#include "mm/kheap.h"
#include "sched/sched.h"
#endif

#include <stddef.h>

namespace duetos::ipc
{

static_assert(__builtin_offsetof(KMessagePort, base) == 0, "KObject must be the first member of KMessagePort");
static_assert(sizeof(KMessagePort) <= static_cast<uptr>(~static_cast<u32>(0)), "MessagePort size must fit u32");

namespace
{

enum class PortWaitResult : u8
{
    Woken,
    Cancelled,
};

class PortGuard
{
  public:
#if defined(DUETOS_HOST_TEST)
    explicit PortGuard(KMessagePort& port) : m_port(port), m_lock(port.inner) {}
#else
    explicit PortGuard(KMessagePort& port) : m_port(port), m_locked(true) { sched::MutexLock(&m_port.inner); }
#endif

    ~PortGuard()
    {
#if !defined(DUETOS_HOST_TEST)
        if (m_locked)
            sched::MutexUnlock(&m_port.inner);
#endif
    }

    PortGuard(const PortGuard&) = delete;
    PortGuard& operator=(const PortGuard&) = delete;

    PortWaitResult Wait()
    {
#if defined(DUETOS_HOST_TEST)
        m_port.readable.wait(m_lock);
        return PortWaitResult::Woken;
#else
        return sched::CondvarWaitCancellable(&m_port.readable, &m_port.inner) == sched::WaitQueueBlockResult::Cancelled
                   ? PortWaitResult::Cancelled
                   : PortWaitResult::Woken;
#endif
    }

    void Broadcast()
    {
#if defined(DUETOS_HOST_TEST)
        m_port.readable.notify_all();
#else
        (void)sched::CondvarBroadcast(&m_port.readable);
#endif
    }

    void Unlock()
    {
#if defined(DUETOS_HOST_TEST)
        m_lock.unlock();
#else
        if (m_locked)
        {
            sched::MutexUnlock(&m_port.inner);
            m_locked = false;
        }
#endif
    }

    void Lock()
    {
#if defined(DUETOS_HOST_TEST)
        m_lock.lock();
#else
        if (!m_locked)
        {
            sched::MutexLock(&m_port.inner);
            m_locked = true;
        }
#endif
    }

  private:
    KMessagePort& m_port;
#if defined(DUETOS_HOST_TEST)
    std::unique_lock<std::mutex> m_lock;
#else
    bool m_locked;
#endif
};

bool PointerRangeIsValid(const void* pointer, u32 bytes)
{
    if (pointer == nullptr)
        return false;
    const uptr begin = reinterpret_cast<uptr>(pointer);
    return static_cast<uptr>(bytes) <= ~static_cast<uptr>(0) - begin;
}

bool PointerRangesOverlap(const void* left, u32 left_bytes, const void* right, u32 right_bytes)
{
    const uptr left_begin = reinterpret_cast<uptr>(left);
    const uptr right_begin = reinterpret_cast<uptr>(right);
    const uptr left_end = left_begin + static_cast<uptr>(left_bytes);
    const uptr right_end = right_begin + static_cast<uptr>(right_bytes);
    return left_begin < right_end && right_begin < left_end;
}

bool BufferAliasesPort(const KMessagePort& port, const void* buffer, u32 bytes)
{
    return PointerRangesOverlap(&port, static_cast<u32>(sizeof(KMessagePort)), buffer, bytes);
}

MessageRingEnqueueResult EmptyEnqueueResult(MessageRingStatus status)
{
    return MessageRingEnqueueResult{status, 0, 0, MessageValidationError::Ok, PayloadValidationError::Ok};
}

KMessagePortSendResult SendFailure(KMessagePortStatus status, MessageRingStatus ring_status)
{
    return KMessagePortSendResult{status, EmptyEnqueueResult(ring_status)};
}

KMessagePortReceiveResult ReceiveFailure(KMessagePortStatus status, MessageRingStatus ring_status, u64 sequence = 0,
                                         u32 frame_size = 0)
{
    return KMessagePortReceiveResult{status, ring_status, sequence, frame_size, 0};
}

void CopyBytes(u8* destination, const u8* source, u32 bytes)
{
    for (u32 index = 0; index < bytes; ++index)
        destination[index] = source[index];
}

void CloseInternal(KMessagePort& port)
{
    PortGuard guard(port);
    if (port.closed)
        return;
    port.closed = true;
    guard.Broadcast();
}

void KMessagePortDestroy(KObject* object)
{
    auto* port = reinterpret_cast<KMessagePort*>(object);
    CloseInternal(*port);
#if defined(DUETOS_HOST_TEST)
    delete port;
#else
    duetos::mm::KFree(port);
#endif
}

KMessagePort* ResolvePort(HandleTable& table, Handle handle, u64 required_rights)
{
    KObject* object = HandleTableLookupRef(table, handle, KObjectType::MessagePort, required_rights);
    return object == nullptr ? nullptr : reinterpret_cast<KMessagePort*>(object);
}

} // namespace

::duetos::core::Result<KMessagePort*> KMessagePortCreate()
{
#if defined(DUETOS_HOST_TEST)
    auto* port = new (std::nothrow) KMessagePort{};
#else
    auto* port = static_cast<KMessagePort*>(duetos::mm::KMalloc(sizeof(KMessagePort)));
    if (port != nullptr)
        *port = KMessagePort{};
#endif
    if (port == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::OutOfMemory};

    KObjectInit(&port->base, KObjectType::MessagePort, &KMessagePortDestroy);
    const MessageRingStatus initialized =
        MessageRingInitialize(&port->ring, port->storage, static_cast<u32>(sizeof(port->storage)));
    if (initialized != MessageRingStatus::Ok)
    {
#if defined(DUETOS_HOST_TEST)
        delete port;
#else
        duetos::mm::KFree(port);
#endif
        return ::duetos::core::Err{::duetos::core::ErrorCode::BadState};
    }
    return port;
}

#if defined(DUETOS_HOST_TEST)
void KMessagePortHostArmCopyWindowHook(KMessagePort* port, KMessagePortHostCopyWindowHook hook, void* context)
{
    if (port == nullptr)
        return;
    PortGuard guard(*port);
    port->host_copy_window_hook = hook;
    port->host_copy_window_context = context;
}
#endif

KMessagePortSendResult KMessagePortSend(KMessagePort* port, const void* frame, u32 frame_bytes,
                                        const PayloadVersionRule* payload_rules, u32 payload_rule_count)
{
    if (port == nullptr || !PointerRangeIsValid(frame, frame_bytes) || frame_bytes == 0)
        return SendFailure(KMessagePortStatus::InvalidArgument, MessageRingStatus::InvalidArgument);
    if (BufferAliasesPort(*port, frame, frame_bytes))
        return SendFailure(KMessagePortStatus::InvalidArgument, MessageRingStatus::AliasedBuffer);
    if (payload_rules != nullptr && payload_rule_count <= kVersionedPayloadMaxRules)
    {
        const u32 rule_bytes = payload_rule_count * static_cast<u32>(sizeof(PayloadVersionRule));
        if (!PointerRangeIsValid(payload_rules, rule_bytes))
            return SendFailure(KMessagePortStatus::InvalidArgument, MessageRingStatus::InvalidPayloadContract);
        if (BufferAliasesPort(*port, payload_rules, rule_bytes))
            return SendFailure(KMessagePortStatus::InvalidArgument, MessageRingStatus::AliasedBuffer);
    }

    // Reject calls that begin after close before spending time validating.
    {
        PortGuard guard(*port);
        if (port->closed)
            return SendFailure(KMessagePortStatus::Closed, MessageRingStatus::ProducerAborted);
    }

    // Message/payload validation, reservation, and bounded copy occur without
    // the port mutex. MessageRing itself runs validators before its leaf lock.
    MessageRingEnqueueResult prepared =
        MessageRingPrepareEnqueue(&port->ring, frame, frame_bytes, payload_rules, payload_rule_count);
    if (prepared.status != MessageRingStatus::Ok)
        return KMessagePortSendResult{KMessagePortStatus::RingFailure, prepared};

    PortGuard guard(*port);
    if (port->closed)
    {
        (void)MessageRingAbortEnqueue(&port->ring, prepared.reservation_id);
        prepared.status = MessageRingStatus::ProducerAborted;
        prepared.reservation_id = 0;
        return KMessagePortSendResult{KMessagePortStatus::Closed, prepared};
    }

    u64 sequence = 0;
    prepared.status = MessageRingPublishEnqueue(&port->ring, prepared.reservation_id, &sequence);
    if (prepared.status != MessageRingStatus::Ok)
    {
        (void)MessageRingAbortEnqueue(&port->ring, prepared.reservation_id);
        return KMessagePortSendResult{KMessagePortStatus::RingFailure, prepared};
    }
    prepared.sequence = sequence;
    prepared.reservation_id = 0;

    // The predicate became true while the companion mutex is held. CondvarWait
    // atomically releases-and-blocks, so no waiter can miss this publication.
    guard.Broadcast();
    return KMessagePortSendResult{KMessagePortStatus::Ok, prepared};
}

KMessagePortReceiveResult KMessagePortTryReceive(KMessagePort* port, void* destination, u32 destination_bytes)
{
    if (port == nullptr || !PointerRangeIsValid(destination, destination_bytes))
        return ReceiveFailure(KMessagePortStatus::InvalidArgument, MessageRingStatus::InvalidArgument);
    if (BufferAliasesPort(*port, destination, destination_bytes))
        return ReceiveFailure(KMessagePortStatus::InvalidArgument, MessageRingStatus::AliasedBuffer);

    PortGuard guard(*port);
    if (port->closed)
        return ReceiveFailure(KMessagePortStatus::Closed, MessageRingStatus::Empty);

    MessageRingPeekView view{};
    MessageRingStatus ring_status = MessageRingPeek(&port->ring, &view);
    if (ring_status != MessageRingStatus::Ok)
        return ReceiveFailure(KMessagePortStatus::RingFailure, ring_status);
    if (destination_bytes < view.frame_size)
    {
        (void)MessageRingCancelReceive(&port->ring, view.sequence, view.receive_lease_id);
        return ReceiveFailure(KMessagePortStatus::RingFailure, MessageRingStatus::BufferTooSmall, view.sequence,
                              view.frame_size);
    }

    MessageRingCopySpans spans{};
    ring_status = MessageRingBeginCopyOut(&port->ring, view.sequence, view.receive_lease_id, &spans);
    if (ring_status != MessageRingStatus::Ok)
    {
        (void)MessageRingCancelReceive(&port->ring, view.sequence, view.receive_lease_id);
        return ReceiveFailure(KMessagePortStatus::RingFailure, ring_status, view.sequence, view.frame_size);
    }

#if defined(DUETOS_HOST_TEST)
    const KMessagePortHostCopyWindowHook host_copy_window_hook = port->host_copy_window_hook;
    void* const host_copy_window_context = port->host_copy_window_context;
    port->host_copy_window_hook = nullptr;
    port->host_copy_window_context = nullptr;
#endif

    // The ring pins these spans until EndCopyOut. No port or ring lock is held
    // while the destination bytes are touched.
    guard.Unlock();
    auto* bytes = static_cast<u8*>(destination);
    CopyBytes(bytes, spans.first, spans.first_size);
    if (spans.second_size != 0)
        CopyBytes(bytes + spans.first_size, spans.second, spans.second_size);
#if defined(DUETOS_HOST_TEST)
    if (host_copy_window_hook != nullptr)
        host_copy_window_hook(host_copy_window_context);
#endif
    guard.Lock();

    if (port->closed)
    {
        (void)MessageRingEndCopyOut(&port->ring, view.sequence, view.receive_lease_id, spans.copy_id, false);
        (void)MessageRingCancelReceive(&port->ring, view.sequence, view.receive_lease_id);
        return ReceiveFailure(KMessagePortStatus::Closed, MessageRingStatus::ProducerAborted, view.sequence,
                              view.frame_size);
    }

    ring_status = MessageRingEndCopyOut(&port->ring, view.sequence, view.receive_lease_id, spans.copy_id, true);
    if (ring_status != MessageRingStatus::Ok)
    {
        (void)MessageRingCancelReceive(&port->ring, view.sequence, view.receive_lease_id);
        return ReceiveFailure(KMessagePortStatus::RingFailure, ring_status, view.sequence, view.frame_size);
    }
    ring_status = MessageRingCommit(&port->ring, view.sequence, view.receive_lease_id);
    if (ring_status != MessageRingStatus::Ok)
    {
        (void)MessageRingCancelReceive(&port->ring, view.sequence, view.receive_lease_id);
        return ReceiveFailure(KMessagePortStatus::RingFailure, ring_status, view.sequence, view.frame_size);
    }
    return KMessagePortReceiveResult{KMessagePortStatus::Ok, MessageRingStatus::Ok, view.sequence, view.frame_size,
                                     view.frame_size};
}

KMessagePortStatus KMessagePortWaitReadable(KMessagePort* port)
{
    if (port == nullptr)
        return KMessagePortStatus::InvalidArgument;

    PortGuard guard(*port);
    for (;;)
    {
        if (port->closed)
            return KMessagePortStatus::Closed;
        MessageRingSnapshot snapshot{};
        if (MessageRingInspect(&port->ring, &snapshot) != MessageRingStatus::Ok)
            return KMessagePortStatus::RingFailure;
        if (snapshot.queued_frames != 0)
            return KMessagePortStatus::Ok;
        if (guard.Wait() == PortWaitResult::Cancelled)
            return KMessagePortStatus::Cancelled;
    }
}

void KMessagePortClose(KMessagePort* port)
{
    if (port != nullptr)
        CloseInternal(*port);
}

KMessagePortStatus KMessagePortInspect(KMessagePort* port, KMessagePortSnapshot* snapshot_out)
{
    if (snapshot_out != nullptr && !PointerRangeIsValid(snapshot_out, static_cast<u32>(sizeof(*snapshot_out))))
        return KMessagePortStatus::InvalidArgument;
    if (port != nullptr && snapshot_out != nullptr &&
        BufferAliasesPort(*port, snapshot_out, static_cast<u32>(sizeof(*snapshot_out))))
    {
        return KMessagePortStatus::InvalidArgument;
    }
    if (port == nullptr || snapshot_out == nullptr)
    {
        if (snapshot_out != nullptr)
            *snapshot_out = {};
        return KMessagePortStatus::InvalidArgument;
    }
    *snapshot_out = {};

    PortGuard guard(*port);
    snapshot_out->closed = port->closed;
    if (MessageRingInspect(&port->ring, &snapshot_out->ring) != MessageRingStatus::Ok)
    {
        *snapshot_out = {};
        return KMessagePortStatus::RingFailure;
    }
    return KMessagePortStatus::Ok;
}

KMessagePortSendResult KMessagePortSendHandle(HandleTable& table, Handle handle, const void* frame, u32 frame_bytes,
                                              const PayloadVersionRule* payload_rules, u32 payload_rule_count)
{
    KMessagePort* port = ResolvePort(table, handle, kHandleRightWrite);
    if (port == nullptr)
        return SendFailure(KMessagePortStatus::InvalidHandleOrRights, MessageRingStatus::InvalidArgument);
    KMessagePortSendResult result = KMessagePortSend(port, frame, frame_bytes, payload_rules, payload_rule_count);
    KObjectRelease(&port->base);
    return result;
}

KMessagePortReceiveResult KMessagePortTryReceiveHandle(HandleTable& table, Handle handle, void* destination,
                                                       u32 destination_bytes)
{
    KMessagePort* port = ResolvePort(table, handle, kHandleRightRead);
    if (port == nullptr)
        return ReceiveFailure(KMessagePortStatus::InvalidHandleOrRights, MessageRingStatus::InvalidArgument);
    KMessagePortReceiveResult result = KMessagePortTryReceive(port, destination, destination_bytes);
    KObjectRelease(&port->base);
    return result;
}

KMessagePortStatus KMessagePortWaitReadableHandle(HandleTable& table, Handle handle)
{
    KMessagePort* port = ResolvePort(table, handle, kHandleRightWait);
    if (port == nullptr)
        return KMessagePortStatus::InvalidHandleOrRights;
    const KMessagePortStatus status = KMessagePortWaitReadable(port);
    KObjectRelease(&port->base);
    return status;
}

KMessagePortStatus KMessagePortCloseHandle(HandleTable& table, Handle handle)
{
    auto detached = HandleTableDetach(table, handle, KObjectType::MessagePort, kHandleRightDestroy);
    if (!detached.has_value())
        return KMessagePortStatus::InvalidHandleOrRights;
    auto* port = reinterpret_cast<KMessagePort*>(detached.value());
    KMessagePortClose(port);
    KObjectRelease(&port->base);
    return KMessagePortStatus::Ok;
}

const char* KMessagePortStatusName(KMessagePortStatus status)
{
    switch (status)
    {
    case KMessagePortStatus::Ok:
        return "ok";
    case KMessagePortStatus::InvalidArgument:
        return "invalid-argument";
    case KMessagePortStatus::InvalidHandleOrRights:
        return "invalid-handle-or-rights";
    case KMessagePortStatus::Closed:
        return "closed";
    case KMessagePortStatus::Cancelled:
        return "cancelled";
    case KMessagePortStatus::RingFailure:
        return "ring-failure";
    }
    return "unknown";
}

} // namespace duetos::ipc
