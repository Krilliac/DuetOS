#pragma once

/*
 * Internal owner for one authenticated bidirectional channel generation.
 *
 * ChannelCore is deliberately not a wire object or public KObject. A future
 * ServiceEndpoint retains the caller-owned ChannelCore storage and translates
 * user operations into bounded kernel-buffer MessagePort calls. One core owns
 * two MessagePorts, two ObjectTransferTables, paired directional request
 * ledgers, and exactly one ResourceDomain channel charge.
 *
 * Lifetime and locking:
 *   - Initialize is a one-shot transition from canonical zero storage. Reset
 *     is a separate transition permitted only after exact drain detachment.
 *   - One shared core lock serializes both directional ledgers, epoch changes,
 *     operation pins, and ownership detachment. MessagePort, transfer-table,
 *     KObject, allocator, and ResourceDomain calls never occur under it.
 *   - Every borrowed direction resource requires an exact operation pin. Once
 *     Draining is published no new pin is issued and no new request may be
 *     reserved. Drain closes both ports outside the lock to wake blocked
 *     operations, then returns Busy until all pins quiesce. Already-issued pins
 *     may still commit, cancel, or complete their exact reserved work while the
 *     request ledgers remain live. The ledgers are drained only after the last
 *     pin releases; storage cannot be reclaimed before final detachment.
 *   - Drain returns cancelled request keys and detached owned resources by
 *     value. The caller consumes request cleanup and releases the detached
 *     bundle after the core lock is absent. No caller-provided byte buffer or
 *     user pointer is accepted by this primitive.
 *   - Channel epochs come only from one boot-global, nonwrapping authority.
 *     UINT64_MAX is issued once; exhaustion is permanent and fail closed.
 */

#include "ipc/endpoint_request_ledger.h"
#include "ipc/kmessage_port.h"
#include "ipc/object_transfer.h"
#include "proc/resource_domain.h"
#include "util/types.h"

#if !defined(DUETOS_HOST_TEST)
#include "sync/spinlock.h"
#endif

namespace duetos::ipc
{

using ChannelEpoch = u64;
inline constexpr ChannelEpoch kChannelEpochInvalid = 0;
inline constexpr ChannelEpoch kChannelEpochMaximum = ~0ULL;
inline constexpr u32 kChannelCoreDirectionCount = 2;
inline constexpr u32 kChannelCoreOperationCapacity = 32;
inline constexpr u32 kChannelCoreOperationGenerationMaximum = ~0U;
inline constexpr u64 kChannelCoreQueuedBufferBytes =
    static_cast<u64>(kChannelCoreDirectionCount) * kMessagePortStorageBytes;

enum class ChannelCoreDirection : u8
{
    InitiatorToAcceptor = 0,
    AcceptorToInitiator = 1,
};

inline constexpr bool ChannelCoreDirectionIsValid(ChannelCoreDirection direction)
{
    return direction == ChannelCoreDirection::InitiatorToAcceptor ||
           direction == ChannelCoreDirection::AcceptorToInitiator;
}

inline constexpr u32 ChannelCoreDirectionIndex(ChannelCoreDirection direction)
{
    return direction == ChannelCoreDirection::InitiatorToAcceptor ? 0U : 1U;
}

inline constexpr EndpointRequestDirection ChannelCoreLedgerDirection(ChannelCoreDirection direction)
{
    return direction == ChannelCoreDirection::InitiatorToAcceptor ? EndpointRequestDirection::InitiatorToAcceptor
                                                                  : EndpointRequestDirection::AcceptorToInitiator;
}

enum class ChannelCoreState : u8
{
    Uninitialized = 0,
    Open,
    Draining,
    Drained,
};

enum class ChannelCoreStatus : u8
{
    Ok = 0,
    InvalidArgument,
    NotInitialized,
    AlreadyInitialized,
    CorruptState,
    ResourceChargeFailed,
    AllocationFailed,
    EpochExhausted,
    Draining,
    Drained,
    ResetNotDrained,
    Busy,
    OperationIdentityExhausted,
    StaleOperation,
    StaleEpoch,
    LedgerFailure,
    TransferCloseFailed,
    InvalidCleanup,
    ResourceReleaseFailed,
};

enum class ChannelCoreOperationSlotState : u8
{
    Free = 0,
    Live,
    Retired,
};

using ChannelCoreOperationBinding = u64;
inline constexpr ChannelCoreOperationBinding kInvalidChannelCoreOperationBinding = 0;

inline constexpr bool ChannelCoreOperationBindingIsValid(ChannelCoreOperationBinding binding)
{
    return binding != kInvalidChannelCoreOperationBinding;
}

struct ChannelCoreOperationPin
{
    ChannelEpoch channel_epoch;
    u32 slot;
    u32 generation;
    ChannelCoreOperationBinding binding;
};

inline constexpr ChannelCoreOperationPin kInvalidChannelCoreOperationPin{
    kChannelEpochInvalid,
    kChannelCoreOperationCapacity,
    0,
    kInvalidChannelCoreOperationBinding,
};

inline constexpr bool ChannelCoreOperationPinIsValid(ChannelCoreOperationPin pin)
{
    return pin.channel_epoch != kChannelEpochInvalid && pin.slot < kChannelCoreOperationCapacity &&
           pin.generation != 0 && ChannelCoreOperationBindingIsValid(pin.binding);
}

inline constexpr bool operator==(ChannelCoreOperationPin lhs, ChannelCoreOperationPin rhs)
{
    return lhs.channel_epoch == rhs.channel_epoch && lhs.slot == rhs.slot && lhs.generation == rhs.generation &&
           lhs.binding == rhs.binding;
}

struct [[nodiscard]] ChannelCoreOpenResult
{
    ChannelCoreStatus status;
    ChannelEpoch channel_epoch;
};

struct [[nodiscard]] ChannelCorePinResult
{
    ChannelCoreStatus status;
    ChannelCoreOperationPin pin;
};

// Borrowed only while `pin` remains live. These are kernel addresses and must
// never be copied into a message or returned to user mode.
struct [[nodiscard]] ChannelCoreDirectionLease
{
    ChannelCoreStatus status;
    KMessagePort* port;
    ObjectTransferTable* transfer_table;
    EndpointRequestLedgerIdentity request_identity;
};

struct [[nodiscard]] ChannelCoreRequestReserveResult
{
    ChannelCoreStatus status;
    EndpointRequestLedgerStatus ledger_status;
    EndpointRequestKey request_key;
};

struct [[nodiscard]] ChannelCoreRequestCommitResult
{
    ChannelCoreStatus status;
    EndpointRequestLedgerStatus ledger_status;
    EndpointRequestCompletionAuthority completion_authority;
};

struct [[nodiscard]] ChannelCoreRequestTransitionResult
{
    ChannelCoreStatus status;
    EndpointRequestLedgerStatus ledger_status;
};

struct ChannelCoreDetachedCleanup
{
    ChannelEpoch channel_epoch;
    KMessagePort* ports[kChannelCoreDirectionCount];
    ObjectTransferTable* transfer_tables[kChannelCoreDirectionCount];
    ::duetos::core::ResourceChannelChargeKey resource_charge;
};

inline constexpr bool ChannelCoreDetachedCleanupIsEmpty(const ChannelCoreDetachedCleanup& cleanup)
{
    return cleanup.channel_epoch == kChannelEpochInvalid && cleanup.ports[0] == nullptr &&
           cleanup.ports[1] == nullptr && cleanup.transfer_tables[0] == nullptr &&
           cleanup.transfer_tables[1] == nullptr &&
           !::duetos::core::ResourceChannelChargeKeyIsValid(cleanup.resource_charge);
}

struct [[nodiscard]] ChannelCoreDrainResult
{
    ChannelCoreStatus status;
    ChannelEpoch channel_epoch;
    EndpointRequestDrainResult request_cleanup[kChannelCoreDirectionCount];
    ChannelCoreDetachedCleanup detached;
};

struct ChannelCoreSnapshot
{
    ChannelCoreState state;
    ChannelEpoch channel_epoch;
    u32 active_operations;
    u32 active_requests[kChannelCoreDirectionCount];
    EndpointRequestLedgerIdentity request_identities[kChannelCoreDirectionCount];
    bool resources_attached;
    bool ports_close_notified;
    bool request_ledgers_drained;
};

struct [[nodiscard]] ChannelCoreInspectResult
{
    ChannelCoreStatus status;
    ChannelCoreSnapshot snapshot;
};

#if defined(DUETOS_HOST_TEST)
struct ChannelCoreHostLock
{
    u32 next_ticket;
    u32 now_serving;
};
#endif

struct ChannelCoreOperationSlot
{
    u32 generation;
    ChannelCoreOperationSlotState state;
    ChannelCoreOperationBinding binding;
};

// Public only for allocation-free outer-owner embedding and hosted invariant
// tests. Treat every field as opaque after Initialize.
struct ChannelCore
{
#if defined(DUETOS_HOST_TEST)
    ChannelCoreHostLock lock;
#else
    sync::SpinLock lock;
#endif
    EndpointRequestLedger request_ledgers[kChannelCoreDirectionCount];
    KMessagePort* ports[kChannelCoreDirectionCount];
    ObjectTransferTable* transfer_tables[kChannelCoreDirectionCount];
    ::duetos::core::ResourceChannelChargeKey resource_charge;
    ChannelCoreOperationSlot operation_slots[kChannelCoreOperationCapacity];
    ChannelEpoch channel_epoch;
    u32 active_operations;
    u32 next_operation_hint;
    u32 initialized;
    u32 drain_driver_active;
    u32 ports_close_notified;
    u32 request_ledgers_drained;
    ChannelCoreState state;
};

// [unpublished canonical-zero storage]
// Prepare the complete private resource graph outside the core lock, allocate
// one boot-global epoch, then publish both directions together. Every failure
// rolls back the ResourceDomain charge and owned allocations. Invalid argument
// and exhaustion failures leave the core bytes unchanged and retryable.
ChannelCoreOpenResult ChannelCoreInitialize(ChannelCore* core, ::duetos::core::ResourceDomainKey resource_domain);

// [Drained core; previous detached cleanup is owned by the caller]
// Prepare a replacement resource graph, allocate a strictly newer global
// epoch, reset both Draining ledgers on private copies, then publish the pair in
// one core-lock critical section. A losing/concurrent reset rolls back exactly.
ChannelCoreOpenResult ChannelCoreReset(ChannelCore* core, ::duetos::core::ResourceDomainKey resource_domain);

// Acquire/release exact endpoint-operation authority. A pin keeps the core and
// every borrowed direction resource alive. Copied/stale pins cannot decrement
// another operation; terminal per-slot generations are permanently retired.
ChannelCorePinResult ChannelCoreAcquireOperation(ChannelCore* core, ChannelEpoch expected_epoch,
                                                 ChannelCoreOperationBinding binding);
ChannelCoreStatus ChannelCoreReleaseOperation(ChannelCore* core, ChannelCoreOperationPin pin);

// Return one borrowed direction bundle after exact pin validation. The caller
// may use only internal kernel buffers and must release the operation pin after
// all MessagePort/ObjectTransfer calls return.
ChannelCoreDirectionLease ChannelCoreBorrowDirection(ChannelCore* core, ChannelCoreOperationPin pin,
                                                     ChannelCoreDirection direction);

// Reserve one exact request ID under the shared core lock. The trusted key is
// returned by value and may later be handled by the directional ledger owner.
ChannelCoreRequestReserveResult ChannelCoreReserveRequest(ChannelCore* core, ChannelCoreOperationPin pin,
                                                          ChannelCoreDirection direction, u64 request_id);

// Commit, cancel, and complete one request while the same exact operation pin
// keeps the ChannelCore generation and its embedded ledgers alive. These exact
// settlement transitions remain available after Draining is published, until
// the pin is released; BorrowDirection and Reserve are blocked immediately.
// The caller supplies the semantic direction; the ledger identity then
// independently rejects keys or completion authority minted for the peer
// direction or an old channel epoch. No request transition invokes callbacks
// or drops the core lock around a mutable ledger row.
ChannelCoreRequestCommitResult ChannelCoreCommitRequest(ChannelCore* core, ChannelCoreOperationPin pin,
                                                        ChannelCoreDirection direction, EndpointRequestKey key);
ChannelCoreRequestTransitionResult ChannelCoreCancelRequest(ChannelCore* core, ChannelCoreOperationPin pin,
                                                            ChannelCoreDirection direction, EndpointRequestKey key);
ChannelCoreRequestTransitionResult ChannelCoreCompleteRequest(ChannelCore* core, ChannelCoreOperationPin pin,
                                                              ChannelCoreDirection direction,
                                                              EndpointRequestCompletionAuthority completion_authority);

// Begin terminal drain for the current epoch. The first call publishes
// Draining, blocks new pins/reservations, and closes both ports outside the core
// lock to wake pinned waiters. While pins remain, it returns Busy with no
// request cleanup. A retry after pins quiesce closes transfer tables outside
// the lock; only after both closes succeed does it atomically drain both
// ledgers and return request cleanup plus the complete detached ownership
// bundle exactly once.
ChannelCoreDrainResult ChannelCoreDrain(ChannelCore* core);

// Begin terminal drain only if `expected_epoch` still names the core's current
// generation. The comparison is serialized by the core lock and happens before
// any lifecycle/resource mutation, so a stale outer-owner copy cannot drain a
// reset generation. Existing trusted callers that intentionally target the
// current generation may continue using ChannelCoreDrain.
ChannelCoreDrainResult ChannelCoreDrainExpected(ChannelCore* core, ChannelEpoch expected_epoch);

// Consume a detached bundle after ChannelCoreDrain returned it. The bundle is
// invalidated before KObject destruction callbacks run. Transfer tables are
// already Closed; this function frees their storage, releases both port refs,
// and only then releases the exact ResourceDomain charge. A fail-closed charge
// release leaves a charge-only token in `cleanup` for a bounded retry.
// Serialized trusted callers must not replay copied cleanup values.
ChannelCoreStatus ChannelCoreReleaseDetachedCleanup(ChannelCoreDetachedCleanup* cleanup);

ChannelCoreInspectResult ChannelCoreInspect(ChannelCore* core);
const char* ChannelCoreStatusName(ChannelCoreStatus status);

#if defined(DUETOS_HOST_TEST)
using ChannelCoreHostInitializePreClaimHook = void (*)(void* context);

// Arm a one-shot hook after argument preflight but before construction
// ownership CAS.  Hosted tests use it to delay one initializer while another
// wins the CAS; it has no production layout or code-path footprint.
void ChannelCoreHostArmInitializePreClaimHookForTest(ChannelCoreHostInitializePreClaimHook hook, void* context);

// Deterministic terminal-authority seam. Call only with no concurrent
// ChannelCore construction. Zero means permanently exhausted.
void ChannelCoreHostSetNextEpochForTest(ChannelEpoch next_epoch);
#endif

} // namespace duetos::ipc
