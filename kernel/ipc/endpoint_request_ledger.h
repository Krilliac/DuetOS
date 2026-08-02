#pragma once

/*
 * Exact-epoch service-endpoint request lifecycle ledger.
 *
 * The ledger is a pure state machine embedded in a future ServiceEndpoint.
 * It owns no lock, allocation, timer, callback, waiter, payload, or KObject.
 * The endpoint owner serializes every call with its endpoint lock and performs
 * all policy invocation, reply publication, wakeup, and destruction after
 * releasing that lock.
 *
 * One ledger belongs to one immutable direction at a time.  Its identity is
 * the pair {nonzero endpoint epoch, canonical direction}, so completion
 * authority minted for one direction cannot complete an equal request ID in
 * the opposite direction. The endpoint owner must allocate epochs from one
 * boot-global nonwrapping source. An epoch may be shared only by the paired
 * directions of one ChannelCore and must never be reused by another live or
 * future channel generation.
 * Request IDs are accepted in exact increasing order.
 * Successful Reserve advances the sequence; a rejected validation/reservation
 * does not. Once UINT64_MAX is reserved, the sequence retires instead of
 * wrapping. Completed and cancelled IDs therefore remain replay-rejected
 * without an unbounded tombstone set.
 *
 * Commit is the one-shot policy-invocation boundary. Only its first success
 * returns a CompletionAuthority, and Complete accepts only that trusted type.
 * Cancel racing Complete wins or loses under the caller's lock; never both.
 * Drain invalidates every outstanding request and rejects new work until an
 * explicit strictly-newer identity reset.
 */

#include "util/types.h"

namespace duetos::ipc
{

inline constexpr u64 kEndpointRequestEpochInvalid = 0;
inline constexpr u64 kEndpointRequestEpochMaximum = ~0ULL;
inline constexpr u64 kEndpointRequestIdInvalid = 0;
inline constexpr u64 kEndpointRequestIdMaximum = ~0ULL;
inline constexpr u32 kEndpointRequestLedgerCapacity = 32;

enum class EndpointRequestDirection : u64
{
    Invalid = 0,
    InitiatorToAcceptor = 1,
    AcceptorToInitiator = 2,
};

struct EndpointRequestLedgerIdentity
{
    u64 endpoint_epoch;
    EndpointRequestDirection direction;
};

inline constexpr EndpointRequestLedgerIdentity kInvalidEndpointRequestLedgerIdentity{
    kEndpointRequestEpochInvalid,
    EndpointRequestDirection::Invalid,
};

inline constexpr bool EndpointRequestDirectionIsValid(EndpointRequestDirection direction)
{
    return direction == EndpointRequestDirection::InitiatorToAcceptor ||
           direction == EndpointRequestDirection::AcceptorToInitiator;
}

inline constexpr bool EndpointRequestLedgerIdentityIsValid(EndpointRequestLedgerIdentity identity)
{
    return identity.endpoint_epoch != kEndpointRequestEpochInvalid &&
           EndpointRequestDirectionIsValid(identity.direction);
}

inline constexpr bool operator==(EndpointRequestLedgerIdentity lhs, EndpointRequestLedgerIdentity rhs)
{
    return lhs.endpoint_epoch == rhs.endpoint_epoch && lhs.direction == rhs.direction;
}

struct EndpointRequestKey
{
    EndpointRequestLedgerIdentity ledger_identity;
    u64 request_id;
};

inline constexpr EndpointRequestKey kInvalidEndpointRequestKey{kInvalidEndpointRequestLedgerIdentity,
                                                               kEndpointRequestIdInvalid};

inline constexpr bool EndpointRequestKeyIsValid(EndpointRequestKey key)
{
    return EndpointRequestLedgerIdentityIsValid(key.ledger_identity) && key.request_id != kEndpointRequestIdInvalid;
}

inline constexpr bool operator==(EndpointRequestKey lhs, EndpointRequestKey rhs)
{
    return lhs.ledger_identity == rhs.ledger_identity && lhs.request_id == rhs.request_id;
}

struct EndpointRequestLedger;
enum class EndpointRequestLedgerStatus : u8;
class EndpointRequestCompletionAuthority;
struct [[nodiscard]] EndpointRequestCommitResult;

EndpointRequestCommitResult EndpointRequestLedgerCommit(EndpointRequestLedger* ledger, EndpointRequestKey key);

// Trusted kernel authority minted only by the first successful Commit. Its
// key-bearing constructor is private, so a decoded sender key cannot be
// passed to Complete by accident. Copying a minted value does not duplicate
// authority: the exact live row can be completed or cancelled only once.
class EndpointRequestCompletionAuthority
{
  public:
    constexpr EndpointRequestCompletionAuthority() = default;

    constexpr EndpointRequestKey request_key() const { return key_; }

  private:
    constexpr explicit EndpointRequestCompletionAuthority(EndpointRequestKey key) : key_(key) {}

    EndpointRequestKey key_ = kInvalidEndpointRequestKey;

    friend EndpointRequestCommitResult EndpointRequestLedgerCommit(EndpointRequestLedger* ledger,
                                                                   EndpointRequestKey key);
};

inline constexpr EndpointRequestCompletionAuthority kInvalidEndpointRequestCompletionAuthority{};

inline constexpr bool EndpointRequestCompletionAuthorityIsValid(EndpointRequestCompletionAuthority authority)
{
    return EndpointRequestKeyIsValid(authority.request_key());
}

enum class EndpointRequestSlotState : u8
{
    Free = 0,
    Reserved,
    Committed,
};

enum class EndpointRequestLedgerState : u8
{
    Uninitialized = 0,
    Open,
    SequenceRetired,
    Draining,
};

enum class EndpointRequestLedgerStatus : u8
{
    Ok = 0,
    InvalidArgument,
    NotInitialized,
    AlreadyInitialized,
    ResetNotDrained,
    IdentityExhausted,
    CorruptState,
    Draining,
    SequenceExhausted,
    Full,
    StaleIdentity,
    OutOfOrder,
    ReplayRejected,
    NotFound,
    NotCommitted,
};

struct [[nodiscard]] EndpointRequestCommitResult
{
    EndpointRequestLedgerStatus status;
    EndpointRequestCompletionAuthority completion_authority;
};

struct [[nodiscard]] EndpointRequestDrainResult
{
    EndpointRequestLedgerStatus status;
    u32 detached_count;
    EndpointRequestKey detached_keys[kEndpointRequestLedgerCapacity];
};

// Public only for fixed-size embedding and host invariant tests. Treat these
// fields as opaque after initialization.
struct EndpointRequestSlot
{
    EndpointRequestKey key;
    EndpointRequestSlotState state;
};

struct EndpointRequestLedger
{
    EndpointRequestSlot slots[kEndpointRequestLedgerCapacity];
    EndpointRequestLedgerIdentity identity;
    // Zero means the nonwrapping request sequence has retired or the ledger is
    // draining/uninitialized. It is never interpreted as a request ID.
    u64 next_request_id;
    u32 active_count;
    u32 next_free_hint;
    EndpointRequestLedgerState state;
};

// [unpublished, never-before-initialized endpoint]
// One-shot construction accepts only the canonical zero-initialized state.
// `first_request_id` exists for deterministic restoration and terminal-value
// tests. Failure leaves the ledger unchanged.
EndpointRequestLedgerStatus EndpointRequestLedgerInitialize(EndpointRequestLedger* ledger,
                                                            EndpointRequestLedgerIdentity identity,
                                                            u64 first_request_id = 1);

// [caller holds endpoint lock; drained endpoint is otherwise quiescent]
// Reuse is explicit and accepts only a canonical Draining ledger with no live
// rows. Direction is immutable and endpoint_epoch must increase without wrap.
// Failure leaves the drained ledger unchanged.
EndpointRequestLedgerStatus EndpointRequestLedgerReset(EndpointRequestLedger* ledger,
                                                       EndpointRequestLedgerIdentity next_identity,
                                                       u64 first_request_id = 1);

// [caller holds endpoint lock; pure, allocation-free, callback-free]
bool EndpointRequestLedgerIsCanonical(const EndpointRequestLedger& ledger);

// Accept exactly `next_request_id` for this identity and reserve one bounded row.
// Full, stale, replayed, and out-of-order failures leave every field unchanged.
EndpointRequestLedgerStatus EndpointRequestLedgerReserve(EndpointRequestLedger* ledger, EndpointRequestKey key);

// Linearize one validated request for policy invocation. Returning the result
// by value removes caller-controlled output aliases. A duplicate Commit never
// returns authority. The endpoint must retain/pin the exact request context
// across unlocked policy work; this ledger suppresses stale reply publication
// but cannot protect endpoint-owned payload/context from concurrent cleanup.
EndpointRequestCommitResult EndpointRequestLedgerCommit(EndpointRequestLedger* ledger, EndpointRequestKey key);

// Cancel either a Reserved or Committed request. Success consumes the row, so
// a later Commit, Cancel, or Complete for the same key is replay-rejected.
EndpointRequestLedgerStatus EndpointRequestLedgerCancel(EndpointRequestLedger* ledger, EndpointRequestKey key);

// Consume the one trusted completion authority. Only a currently Committed
// row succeeds; a copied/replayed authority cannot publish a second reply.
EndpointRequestLedgerStatus EndpointRequestLedgerComplete(EndpointRequestLedger* ledger,
                                                          EndpointRequestCompletionAuthority completion_authority);

// Terminally drain this identity and return an exact bounded snapshot of every
// detached Reserved/Committed key. Returning by value removes output aliases;
// the endpoint uses the keys for cleanup after dropping its lock. Repeated
// drain is idempotent and reports zero. The caller must consume every detached
// key and release its corresponding pinned context. No callback or release
// occurs here.
EndpointRequestDrainResult EndpointRequestLedgerDrain(EndpointRequestLedger* ledger);

const char* EndpointRequestLedgerStatusName(EndpointRequestLedgerStatus status);

} // namespace duetos::ipc
