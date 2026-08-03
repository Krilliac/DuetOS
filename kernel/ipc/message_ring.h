#pragma once

/*
 * Fixed-storage validated IPC message ring.
 *
 * The caller owns the byte storage and the MessageRing object for the ring's
 * entire lifetime.  No operation allocates, blocks on a wait queue, invokes a
 * callback, or accepts a user pointer.  A future waitable KObject wrapper is
 * responsible for user copies, sleep/wake policy, endpoint authority, and
 * lifetime pinning.
 *
 * Lock order and copy rules:
 *   - The ring lock is a leaf metadata lock.  Callers must not acquire another
 *     lock from a ring operation, and a wrapper must release it before any
 *     wait-queue, scheduler, user-copy, or notification operation.
 *   - MessageValidate and PayloadValidate always run before producer
 *     reservation and therefore outside the ring lock.
 *   - A producer copies one already-validated, immutable kernel frame into a
 *     reserved free range without the lock, then explicitly publishes or
 *     aborts that reservation.  Sequence numbers are assigned only at publish.
 *   - Receive is transactional: Peek reserves the head; BeginCopyOut pins two
 *     stable storage spans; EndCopyOut records copy success; Commit retires
 *     only that exact message sequence.  CopyOut is a kernel-buffer convenience
 *     that performs its byte copy between Begin/End, never under the lock.
 *   - Initialization is a one-shot atomic state transition on a zero-initialized
 *     object.  Reinitialization never resets a live lock or recycles scalar
 *     reservation/sequence authority.  The retained outer owner must quiesce
 *     every operation before destroying the ring or its storage.
 *   - Input frames, trusted rule tables, caller-owned storage, the ring object,
 *     and writable outputs are disjoint.  Alias/range preflight completes
 *     before an output is cleared or any transactional state is changed.
 *     An operation that observes Uninitialized/Initializing leaves outputs
 *     untouched because the backing-storage identity is not yet readable.
 */

#include "ipc/message_abi.h"
#include "ipc/versioned_payload.h"
#include "util/types.h"

#if !defined(DUETOS_HOST_TEST)
#include "sync/spinlock.h"
#endif

namespace duetos::ipc
{

inline constexpr u32 kMessageRingRecordHeaderBytes = 16;
inline constexpr u32 kMessageRingMinimumStorageBytes = kMessageRingRecordHeaderBytes + kMessageAbiHeaderV1Bytes;

enum class MessageRingStatus : u8
{
    Ok = 0,
    InvalidArgument,
    NotInitialized,
    AliasedBuffer,
    MalformedMessage,
    InvalidPayloadContract,
    MissingPayloadContract,
    MalformedPayload,
    Full,
    Busy,
    Empty,
    BufferTooSmall,
    CopyRequired,
    CopyNotActive,
    StaleSequence,
    StaleReservation,
    ProducerAborted,
    SequenceExhausted,
    ReservationExhausted,
    CorruptState,
    AlreadyInitialized,
    StaleReceiveLease,
    StaleCopyAttempt,
    ReceiveLeaseExhausted,
    CopyIdExhausted,
};

struct MessageRingEnqueueResult
{
    MessageRingStatus status;
    u64 reservation_id;
    u64 sequence;
    MessageValidationError message_error;
    PayloadValidationError payload_error;
};

struct MessageRingPeekView
{
    u64 sequence;
    u64 receive_lease_id;
    u32 frame_size;
};

// Valid only between successful BeginCopyOut and the matching EndCopyOut.
// A wrapped frame has two spans; otherwise second is null/zero.
struct MessageRingCopySpans
{
    const u8* first;
    u32 first_size;
    const u8* second;
    u32 second_size;
    u64 copy_id;
};

struct MessageRingSnapshot
{
    u32 capacity_bytes;
    u32 used_bytes;
    u32 free_bytes;
    u32 queued_frames;
    u64 next_sequence;
    u64 producer_reservation_id;
    u64 receive_sequence;
    bool producer_copy_active;
    bool producer_abort_requested;
    bool receive_copy_active;
    bool receive_copy_succeeded;
    bool sequence_exhausted;
    bool reservation_exhausted;
    bool receive_lease_exhausted;
    bool copy_id_exhausted;
};

#if defined(DUETOS_HOST_TEST)
struct MessageRingHostLock
{
    u32 next_ticket;
    u32 now_serving;
};
#endif

// Implementation state is exposed only so the ring can be embedded without an
// allocator.  Callers must treat every field as opaque after initialization.
struct MessageRing
{
#if defined(DUETOS_HOST_TEST)
    MessageRingHostLock lock;
#else
    sync::SpinLock lock;
#endif
    u8* storage;
    u32 capacity_bytes;
    u32 head_offset;
    u32 tail_offset;
    u32 used_bytes;
    u32 queued_frames;
    u32 initialized;

    u64 next_sequence;
    u32 sequence_exhausted;

    u64 next_reservation_id;
    u32 reservation_exhausted;
    u64 producer_reservation_id;
    u32 producer_tail_offset;
    u32 producer_record_bytes;
    u32 producer_frame_size;
    u32 producer_copy_active;
    u32 producer_abort_requested;

    u64 next_receive_lease_id;
    u32 receive_lease_exhausted;
    u64 receive_sequence;
    u64 receive_lease_id;
    u32 receive_frame_size;

    u64 next_copy_id;
    u32 copy_id_exhausted;
    u64 receive_copy_id;
    u64 receive_copy_succeeded_id;
};

/// Atomically initialize a zero-initialized, unpublished ring over caller-owned
/// storage exactly once.  A failed argument preflight leaves it retryable;
/// concurrent or later initialization returns AlreadyInitialized without
/// touching live state.  A nonzero first sequence is required; UINT64_MAX is
/// accepted for exhaustion testing and permits exactly one published frame.
MessageRingStatus MessageRingInitialize(MessageRing* ring, void* storage, u32 storage_bytes, u64 first_sequence = 1);

/// Validate, reserve, and copy one immutable kernel frame, but do not publish
/// it.  A successful result owns `reservation_id`; it must be passed to either
/// PublishEnqueue or AbortEnqueue.  Nonempty payloads require a nonempty rule
/// table and are validated against it before the ring lock is acquired.
/// The immutable frame and trusted rule table must be disjoint from each other,
/// the ring object, and its backing storage.
MessageRingEnqueueResult MessageRingPrepareEnqueue(MessageRing* ring, const void* frame, u32 frame_bytes,
                                                   const PayloadVersionRule* payload_rules = nullptr,
                                                   u32 payload_rule_count = 0);

/// Atomically publish an exact prepared reservation and assign its monotonic
/// sequence.  No sequence is consumed by an aborted preparation.  An optional
/// output must not alias the ring or storage; alias failures leave it and the
/// reservation unchanged.
MessageRingStatus MessageRingPublishEnqueue(MessageRing* ring, u64 reservation_id, u64* sequence_out);

/// Cancel an exact unpublished reservation.  If its bounded byte copy is in
/// progress, this records an abort request; the copy owner observes it before
/// publication and releases the reservation.  A stale reservation never
/// affects the current producer.
MessageRingStatus MessageRingAbortEnqueue(MessageRing* ring, u64 reservation_id);

/// Synchronous convenience: Prepare followed by Publish.  Full and Busy are
/// explicit backpressure results; the function never waits for storage.
MessageRingEnqueueResult MessageRingEnqueue(MessageRing* ring, const void* frame, u32 frame_bytes,
                                            const PayloadVersionRule* payload_rules = nullptr,
                                            u32 payload_rule_count = 0);

/// Reserve the current head for one receiver transaction and return a unique,
/// non-reused receive lease.  Writable outputs must not alias the ring or
/// backing storage; alias failures leave all state and caller storage unchanged.
MessageRingStatus MessageRingPeek(MessageRing* ring, MessageRingPeekView* view_out);

/// Pin stable storage spans for unlocked copy-out of the exact peeked sequence
/// and lease.  Every successful begin returns a distinct copy-attempt ID.
MessageRingStatus MessageRingBeginCopyOut(MessageRing* ring, u64 sequence, u64 receive_lease_id,
                                          MessageRingCopySpans* spans_out);

/// End an active copy phase.  `succeeded=false` leaves Commit disabled so the
/// same message may be retried or its receive lease canceled.  A delayed or
/// duplicate completion cannot terminate a newer copy attempt.
MessageRingStatus MessageRingEndCopyOut(MessageRing* ring, u64 sequence, u64 receive_lease_id, u64 copy_id,
                                        bool succeeded);

/// Copy into a non-user kernel buffer outside the ring lock and mark the copy
/// successful.  The destination, optional count output, ring, and backing
/// storage must be pairwise disjoint.  BufferTooSmall, alias, and copy failures
/// leave the queue unchanged.
MessageRingStatus MessageRingCopyOut(MessageRing* ring, u64 sequence, u64 receive_lease_id, void* destination,
                                     u32 destination_bytes, u32* copied_bytes_out = nullptr);

/// Retire the head only after successful copy-out and only for the exact
/// sequence returned by Peek.
MessageRingStatus MessageRingCommit(MessageRing* ring, u64 sequence, u64 receive_lease_id);

/// Release an exact receive lease without consuming the frame.
MessageRingStatus MessageRingCancelReceive(MessageRing* ring, u64 sequence, u64 receive_lease_id);

/// Return a lock-consistent scalar snapshot for backpressure and diagnostics.
/// The output must not alias the ring or its backing storage.
MessageRingStatus MessageRingInspect(MessageRing* ring, MessageRingSnapshot* snapshot_out);

const char* MessageRingStatusName(MessageRingStatus status);

} // namespace duetos::ipc
