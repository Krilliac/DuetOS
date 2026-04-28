#pragma once

#include "ipc/kobject.h"
#include "sched/sched.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — concrete `KMailbox` kernel object, v0 (plan A3-followup).
 *
 * WHAT
 *   Fourth concrete `KObject` subclass (after KMutex / KEvent /
 *   KSemaphore). A bounded-FIFO message queue: producers post
 *   fixed-size messages, consumers receive them in order.
 *
 * MAPS TO
 *   - Win32 `PostThreadMessage` / `GetMessage` / message queues
 *   - POSIX message queues (`mq_open` / `mq_send` / `mq_receive`)
 *   - The classic producer/consumer + bounded buffer textbook
 *     primitive — building block for in-kernel work queues,
 *     async I/O completion routing, and inter-task signaling.
 *
 * WHY
 *   KMutex / KEvent / KSemaphore cover lock + signal + count
 *   patterns. KMailbox covers the "send some data along with
 *   the wakeup" pattern that any non-trivial IPC uses. Without
 *   it, callers either smuggle data through a side-channel
 *   (mutex-protected struct + Event) or invent ad-hoc lockfree
 *   queues per call-site — both tax sandbox auditing.
 *
 * MESSAGE SHAPE
 *   Fixed 32-byte struct (`KMailboxMessage`) with a u64 `type`
 *   tag + 24 bytes of payload. Out-of-band data (longer payloads)
 *   stays the caller's problem — typical usage is a `type` tag
 *   + a handle / pointer / small primitive for routing.
 *
 * CAPACITY
 *   Set at create time. Storage is a `KMalloc`'d circular buffer
 *   sized as `capacity * sizeof(KMailboxMessage)`. Full queue
 *   blocks the producer (`Post`); empty queue blocks the
 *   consumer (`Receive`).
 *
 * THREADING
 *   `Post` / `Receive` serialise through the embedded
 *   `sched::Mutex`. Two condvars (`not_full` / `not_empty`)
 *   handle the two waiting directions independently — a
 *   blocked producer and a blocked consumer never collide on a
 *   single condvar.
 */

namespace duetos::ipc
{

struct KMailboxMessage
{
    u64 type;     ///< Caller-defined tag.
    u64 payload0; ///< 24 bytes of inline payload — most callers
    u64 payload1; ///< pack a (handle, value) pair into the first
    u64 payload2; ///< two; payload2 is the tail.
};

struct KMailbox
{
    /// MUST be first — `KObject*` ↔ `KMailbox*` cast shape.
    KObject base;

    sched::Mutex inner;
    sched::Condvar not_full;  ///< Producers wait here when the queue is full.
    sched::Condvar not_empty; ///< Consumers wait here when the queue is empty.

    KMailboxMessage* slots; ///< Heap-allocated circular buffer.
    u32 capacity;
    u32 count;
    u32 head; ///< Next slot a Post will write to.
    u32 tail; ///< Next slot a Receive will read from.
};

/// Allocate + zero-init + KObjectInit a fresh KMailbox with a
/// `capacity`-slot circular buffer. Returns
/// `Err{ErrorCode::InvalidArgument}` for capacity == 0, or
/// `Err{ErrorCode::OutOfMemory}` on either allocation failing.
::duetos::core::Result<KMailbox*> KMailboxCreate(u32 capacity);

/// Block until a slot is available, then enqueue `msg`. Wakes a
/// blocked consumer if the queue was empty.
void KMailboxPost(KMailbox* mb, const KMailboxMessage& msg);

/// Non-blocking variant. Returns true on success, false if the
/// queue is full. Useful for caller-decides-overflow patterns.
bool KMailboxTryPost(KMailbox* mb, const KMailboxMessage& msg);

/// Block until a message is available, then dequeue into `out`.
/// Wakes a blocked producer if the queue was full.
void KMailboxReceive(KMailbox* mb, KMailboxMessage* out);

/// Non-blocking variant. Returns true on success, false if the
/// queue is empty. `out` is unchanged on false.
bool KMailboxTryReceive(KMailbox* mb, KMailboxMessage* out);

/// Read-only accessor for diagnostics. Racy under SMP.
u32 KMailboxCount(const KMailbox* mb);

/// Boot-time self-test. Allocates a KMailbox with capacity 4,
/// inserts into a HandleTable, exercises:
///   - try-receive on empty queue returns false,
///   - post one + receive one round-trip preserves the message,
///   - fill to capacity (4 posts) + try-post returns false,
///   - drain to empty (4 receives) + try-receive returns false,
///   - removes from table; destroy frees both the slots buffer
///     and the mailbox itself.
/// Panics on any mismatch. Real producer/consumer contention is
/// out of scope (no spawned tasks); the v0 test verifies the
/// state machine on the fast path.
void KMailboxSelfTest();

} // namespace duetos::ipc
