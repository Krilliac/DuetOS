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
 * One ledger belongs to one immutable, nonzero endpoint epoch and one message
 * direction. Request IDs are accepted in exact increasing order. Successful
 * Reserve advances the sequence; a rejected validation/reservation does not.
 * Once UINT64_MAX is reserved, the sequence retires instead of wrapping.
 * Completed and cancelled IDs therefore remain replay-rejected without an
 * unbounded tombstone set.
 *
 * Commit is the one-shot policy-invocation boundary. Only its first success
 * returns a CompletionAuthority, and Complete accepts only that trusted type.
 * Cancel racing Complete wins or loses under the caller's lock; never both.
 * Drain invalidates every outstanding request and permanently rejects new
 * work for this epoch.
 */

#include "util/types.h"

namespace duetos::ipc
{

inline constexpr u64 kEndpointRequestEpochInvalid = 0;
inline constexpr u64 kEndpointRequestIdInvalid = 0;
inline constexpr u64 kEndpointRequestIdMaximum = ~0ULL;
inline constexpr u32 kEndpointRequestLedgerCapacity = 32;

struct EndpointRequestKey
{
    u64 endpoint_epoch;
    u64 request_id;
};

inline constexpr EndpointRequestKey kInvalidEndpointRequestKey{kEndpointRequestEpochInvalid, kEndpointRequestIdInvalid};

inline constexpr bool EndpointRequestKeyIsValid(EndpointRequestKey key)
{
    return key.endpoint_epoch != kEndpointRequestEpochInvalid && key.request_id != kEndpointRequestIdInvalid;
}

inline constexpr bool operator==(EndpointRequestKey lhs, EndpointRequestKey rhs)
{
    return lhs.endpoint_epoch == rhs.endpoint_epoch && lhs.request_id == rhs.request_id;
}

struct EndpointRequestLedger;
enum class EndpointRequestLedgerStatus : u8;
class EndpointRequestCompletionAuthority;

EndpointRequestLedgerStatus EndpointRequestLedgerCommit(EndpointRequestLedger* ledger, EndpointRequestKey key,
                                                        EndpointRequestCompletionAuthority* completion_authority_out);

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

    friend EndpointRequestLedgerStatus EndpointRequestLedgerCommit(
        EndpointRequestLedger* ledger, EndpointRequestKey key,
        EndpointRequestCompletionAuthority* completion_authority_out);
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
    CorruptState,
    Draining,
    SequenceExhausted,
    Full,
    StaleEpoch,
    OutOfOrder,
    ReplayRejected,
    NotFound,
    NotCommitted,
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
    u64 endpoint_epoch;
    // Zero means the nonwrapping request sequence has retired or the ledger is
    // draining/uninitialized. It is never interpreted as a request ID.
    u64 next_request_id;
    u32 active_count;
    u32 next_free_hint;
    EndpointRequestLedgerState state;
};

// [unpublished/quiescent endpoint]
// `first_request_id` exists for deterministic restoration and terminal-value
// tests. Production endpoints normally use the default. Failure clears the
// output to the canonical Uninitialized state.
EndpointRequestLedgerStatus EndpointRequestLedgerInitialize(EndpointRequestLedger* ledger, u64 endpoint_epoch,
                                                            u64 first_request_id = 1);

// [caller holds endpoint lock; pure, allocation-free, callback-free]
bool EndpointRequestLedgerIsCanonical(const EndpointRequestLedger& ledger);

// Accept exactly `next_request_id` for this epoch and reserve one bounded row.
// Full, stale, replayed, and out-of-order failures leave every field unchanged.
EndpointRequestLedgerStatus EndpointRequestLedgerReserve(EndpointRequestLedger* ledger, EndpointRequestKey key);

// Linearize one validated request for policy invocation. The output authority
// is always cleared first. A duplicate Commit never returns authority.
EndpointRequestLedgerStatus EndpointRequestLedgerCommit(EndpointRequestLedger* ledger, EndpointRequestKey key,
                                                        EndpointRequestCompletionAuthority* completion_authority_out);

// Cancel either a Reserved or Committed request. Success consumes the row, so
// a later Commit, Cancel, or Complete for the same key is replay-rejected.
EndpointRequestLedgerStatus EndpointRequestLedgerCancel(EndpointRequestLedger* ledger, EndpointRequestKey key);

// Consume the one trusted completion authority. Only a currently Committed
// row succeeds; a copied/replayed authority cannot publish a second reply.
EndpointRequestLedgerStatus EndpointRequestLedgerComplete(EndpointRequestLedger* ledger,
                                                          EndpointRequestCompletionAuthority completion_authority);

// Terminally drain this epoch. The output is cleared first and reports how many
// Reserved/Committed rows were cancelled. Repeated drain is idempotent and
// reports zero. No callback or release occurs inside this primitive.
EndpointRequestLedgerStatus EndpointRequestLedgerDrain(EndpointRequestLedger* ledger, u32* cancelled_request_count_out);

const char* EndpointRequestLedgerStatusName(EndpointRequestLedgerStatus status);

} // namespace duetos::ipc
