#pragma once

/*
 * Waitable, generation-safe message-port KObject.
 *
 * A MessagePort owns one fixed-size MessageRing and its byte storage in the
 * same allocation.  Frames and payloads are validated by MessageRing before
 * its leaf spinlock is acquired.  The outer mutex protects only the terminal
 * close state and the committed-message wait predicate; it is never held
 * while frame bytes are validated or copied.
 *
 * Lock/lifetime order:
 *   HandleTable retained lookup -> KObject operation reference
 *     -> MessagePort mutex -> MessageRing leaf lock.
 *
 * No KObject retain/release, HandleTable operation, validation, or byte copy
 * occurs while the MessagePort mutex or MessageRing lock is held.  A public
 * close detaches the exact Destroy-authorized handle first, marks the object
 * closed and wakes every waiter, then releases the detached reference.
 */

#include "ipc/handle_table.h"
#include "ipc/kobject.h"
#include "ipc/message_ring.h"
#include "util/result.h"
#include "util/types.h"

#if defined(DUETOS_HOST_TEST)
#include <condition_variable>
#include <mutex>
#else
#include "sched/sched.h"
#endif

namespace duetos::ipc
{

inline constexpr u32 kMessagePortStorageBytes = 4096;

enum class KMessagePortStatus : u8
{
    Ok = 0,
    InvalidArgument,
    InvalidHandleOrRights,
    Closed,
    Cancelled,
    RingFailure,
};

struct KMessagePortSendResult
{
    KMessagePortStatus status;
    MessageRingEnqueueResult ring;
};

struct KMessagePortReceiveResult
{
    KMessagePortStatus status;
    MessageRingStatus ring_status;
    u64 sequence;
    u32 frame_size;
    u32 copied_bytes;
};

struct KMessagePortSnapshot
{
    bool closed;
    MessageRingSnapshot ring;
};

#if defined(DUETOS_HOST_TEST)
using KMessagePortHostCopyWindowHook = void (*)(void* context);
#endif

struct KMessagePort
{
    // MUST be first: HandleTable resolves the object as KObject*.
    KObject base;

#if defined(DUETOS_HOST_TEST)
    std::mutex inner;
    std::condition_variable readable;
    KMessagePortHostCopyWindowHook host_copy_window_hook;
    void* host_copy_window_context;
#else
    sched::Mutex inner;
    sched::Condvar readable;
#endif

    bool closed;
    MessageRing ring;
    alignas(16) u8 storage[kMessagePortStorageBytes];
};

/// Allocate one port object.  Message bytes use the embedded bounded storage;
/// no per-message or secondary queue allocation occurs.
::duetos::core::Result<KMessagePort*> KMessagePortCreate();

/// Validate/reserve/copy outside the port mutex, then publish under it.  If a
/// close wins before publication, the exact reservation is aborted and never
/// becomes visible.  Caller must own a KObject reference for the whole call.
KMessagePortSendResult KMessagePortSend(KMessagePort* port, const void* frame, u32 frame_bytes,
                                        const PayloadVersionRule* payload_rules = nullptr, u32 payload_rule_count = 0);

/// Claim the exact committed head, expose stable spans only for an unlocked
/// bounded copy, then commit on success.  Every pre-copy failure cancels the
/// claim; close during copy ends and cancels it rather than consuming it.
KMessagePortReceiveResult KMessagePortTryReceive(KMessagePort* port, void* destination, u32 destination_bytes);

#if defined(DUETOS_HOST_TEST)
/// Arm a one-shot hosted-test hook after copy-out and before the port mutex is
/// reacquired. The hook and its fields do not exist in a production build.
void KMessagePortHostArmCopyWindowHook(KMessagePort* port, KMessagePortHostCopyWindowHook hook, void* context);
#endif

/// Level-triggered wait: Ok means at least one message was committed while
/// the predicate was checked. Close wins over readiness and wakes all waiters.
/// Cooperative cancellation returns Cancelled after the predicate mutex is
/// reacquired and unwound; hosted tests retain std::condition_variable waits
/// and therefore produce only Ok, Closed, or failure statuses. Caller must own
/// a KObject reference for the full call.
KMessagePortStatus KMessagePortWaitReadable(KMessagePort* port);

/// Terminal and idempotent.  Wakes all waiters and rejects every later send,
/// receive, and wait operation.
void KMessagePortClose(KMessagePort* port);

/// Return a lock-consistent snapshot. The writable output must be disjoint from
/// the complete port allocation; alias/range failures leave all storage intact.
KMessagePortStatus KMessagePortInspect(KMessagePort* port, KMessagePortSnapshot* snapshot_out);

/// Rights-checked HandleTable entry points.  Each retained lookup spans the
/// complete operation (including a blocking wait) and is released afterward.
KMessagePortSendResult KMessagePortSendHandle(HandleTable& table, Handle handle, const void* frame, u32 frame_bytes,
                                              const PayloadVersionRule* payload_rules = nullptr,
                                              u32 payload_rule_count = 0);
KMessagePortReceiveResult KMessagePortTryReceiveHandle(HandleTable& table, Handle handle, void* destination,
                                                       u32 destination_bytes);
KMessagePortStatus KMessagePortWaitReadableHandle(HandleTable& table, Handle handle);
KMessagePortStatus KMessagePortCloseHandle(HandleTable& table, Handle handle);

const char* KMessagePortStatusName(KMessagePortStatus status);

} // namespace duetos::ipc
