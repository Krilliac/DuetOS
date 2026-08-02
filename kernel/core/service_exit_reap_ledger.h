#pragma once

/*
 * Fixed-capacity, allocation-free reap ledger for managed-service exit events.
 *
 * The ledger sits between four parties and owns the durable multi-step reap of
 * one exit event per row:
 *
 *   1. ServiceExitObserver — the exact event source.  Acquire dequeues one
 *      receipt exactly once; the receipt is requeued only by an explicit
 *      pre-commit rollback and acknowledged only after lifecycle and directory
 *      teardown are settled.
 *   2. ServiceLifecycleBrokerObserveExit — the irreversible lifecycle commit.
 *      Once the broker settles the exact instance token (commit or exact
 *      terminal refusal), the ledger never calls ObserveExit for that row
 *      again and never requeues its observer receipt.
 *   3. ServiceDirectoryOwnerCrashed — directory teardown for the exact crashed
 *      owner.  Busy retains the full row identity for bounded, rotating pump
 *      retries; there is no second queue and no drop-on-retry.
 *   4. A later SYS_SERVICE_CONTROL delivery plane — dequeues ready events for
 *      userland serviced and acknowledges them with a separate, global,
 *      non-wrapping public delivery token.  The ledger event sequence is an
 *      exact factual join key, never acknowledgement authority by itself.
 *
 * This module performs no allocation, logging, callback, wait, sleep,
 * scheduler call, or wall-clock read (timestamps enter as caller arguments).
 * Its lock is never held across any observer, broker, or directory call:
 * every external step snapshots under the lock, drops it, performs exactly
 * one external operation, then reacquires the lock to apply the outcome.
 *
 * Locking:
 *   - Every operation after Initialize is [any task/CPU, thread-safe].
 *   - A per-row in-flight guard serializes external progress per row, so
 *     concurrent pump callers never double-drive one row.
 *   - Pump is nonblocking and batch-bounded; it is safe to drive from
 *     scheduler maintenance context with no scheduler/Process lock held.
 */

#include "core/service_directory.h"
#include "core/service_exit_observer.h"
#include "core/service_lifecycle_broker.h"
#include "sync/spinlock.h"
#include "util/types.h"

namespace duetos::core
{

// Every observer slot holds at most one undelivered exit event, but the ledger
// retains an event after the observer receipt is acknowledged (teardown done,
// public delivery still pending) while the freed observer slot re-registers a
// restarted incarnation that may crash again before userland acknowledges the
// first event.  Two ledger rows per observer slot bound that overlap window:
// one event awaiting the serviced ACK plus one successor crash.
inline constexpr u32 kServiceExitReapRowsPerObserverSlot = 2;
inline constexpr u32 kServiceExitReapLedgerCapacity =
    kServiceExitObserverCapacity * kServiceExitReapRowsPerObserverSlot;
static_assert(kServiceExitReapLedgerCapacity >= kServiceExitObserverCapacity,
              "reap ledger must absorb every simultaneously pending observer event");
static_assert(kServiceExitReapLedgerCapacity == kServiceExitObserverCapacity * kServiceExitReapRowsPerObserverSlot,
              "ledger capacity is tied to the observer: delivery-pending row plus successor crash per slot");

inline constexpr u32 kServiceExitReapInvalidRow = kServiceExitReapLedgerCapacity;
inline constexpr u64 kServiceExitReapInvalidDeliveryToken = 0;
inline constexpr u64 kServiceExitReapInvalidAdmission = 0;
inline constexpr u64 kServiceExitReapInvalidEventSequence = 0;

enum class ServiceExitReapLedgerState : u8
{
    Uninitialized = 0,
    Open,
    Closed,
};

// Durable row stages.  Forward-only, with exactly one sanctioned reversal:
// Delivered -> ReadyForDelivery when the exact delivery owner exits before
// acknowledging (the public token is retained, never re-minted).  A row is
// freed only by an exact public-token acknowledgement or by an explicit
// pre-commit rollback of an Acquired row.
enum class ServiceExitReapRowStage : u8
{
    Free = 0,
    // Observer receipt held; lifecycle commit not yet settled.  This is the
    // only stage from which the receipt may be requeued to the observer.
    Acquired,
    // ServiceLifecycleBrokerObserveExit settled the exact instance token
    // (committed, or an exact terminal refusal recorded verbatim).  From here
    // on ObserveExit is never re-called and the receipt is never requeued.
    LifecycleCommitted,
    // ServiceDirectoryOwnerCrashed reported Busy.  The exact ServiceKey and
    // owner instance token stay in the row for bounded pump retries.
    DirectoryDraining,
    // Directory processing reached a recorded terminal disposition: committed,
    // exact settled-absent, terminal refusal, or explicitly unbound.  Only the
    // first two authorize restage.  The observer receipt is acknowledged and
    // the public delivery token minted on the transition out of this stage.
    DirectoryCommitted,
    // Observer slot released and public token minted.  Restage still depends
    // on the row's exact lifecycle and directory dispositions.
    ReadyForDelivery,
    // Dequeued by an exact delivery owner; awaiting its exact-token ACK.
    Delivered,
};

// Recorded facts about each settlement.  The ledger never fabricates a
// missing outcome: a refusal keeps the exact peer status, and an unbound
// directory stage is reported as Unbound rather than as a committed close.
enum class ServiceExitReapLifecycleDisposition : u8
{
    None = 0,
    Committed,
    RefusedTerminal,
};

enum class ServiceExitReapDirectoryDisposition : u8
{
    None = 0,
    Committed,
    // The exact directory key is stale, proving that this incarnation no
    // longer owns a directory row.  Unlike a generic refusal, this is an
    // authoritative teardown settlement for restage.
    SettledAbsent,
    RefusedTerminal,
    // The acquirer declared no directory binding (explicitly unknown), so
    // ServiceDirectoryOwnerCrashed was never called for this row.
    Unbound,
};

enum class ServiceExitReapObserverAckDisposition : u8
{
    None = 0,
    Acknowledged,
    Refused,
};

enum class ServiceExitReapStatus : u8
{
    Ok = 0,
    NullArgument,
    InvalidBinding,
    InvalidProcessKey,
    InvalidEventKey,
    AlreadyInitialized,
    NotInitialized,
    Closed,
    CorruptState,
    CapacityExhausted,
    SequenceExhausted,
    TokenSpaceExhausted,
    NoEvent,
    ObserverRefused,
    NotFound,
    Busy,
    RowsLive,
    WrongStage,
    StaleTicket,
    StaleToken,
    StaleEvent,
    ForeignAcknowledger,
    RollbackRefused,
};

// Kernel-internal row authority handed back by Acquire.  The admission value
// is minted from a global non-wrapping sequence, so a ticket from an earlier
// ledger incarnation can never alias a row of a later one.  It authorizes
// only the explicit pre-commit rollback; it is never exposed to userland.
struct ServiceExitReapRowTicket
{
    u32 row;
    u64 admission;
};

inline constexpr ServiceExitReapRowTicket kInvalidServiceExitReapRowTicket{
    kServiceExitReapInvalidRow,
    kServiceExitReapInvalidAdmission,
};

inline constexpr bool ServiceExitReapRowTicketIsValid(ServiceExitReapRowTicket ticket)
{
    return ticket.row < kServiceExitReapLedgerCapacity && ticket.admission != kServiceExitReapInvalidAdmission;
}

inline constexpr bool operator==(ServiceExitReapRowTicket lhs, ServiceExitReapRowTicket rhs)
{
    return lhs.row == rhs.row && lhs.admission == rhs.admission;
}

// Exact factual identity of one ledger-owned exit event.  event_sequence is a
// global, non-wrapping ledger sequence and is not acknowledgement authority;
// the independently minted delivery token remains required for an ACK.
struct ServiceExitReapEventKey
{
    u64 broker_epoch;
    u64 service_identity;
    u64 transition_generation;
    ProcessKey process;
    u64 event_sequence;
};

inline constexpr ServiceExitReapEventKey kInvalidServiceExitReapEventKey{
    kServiceLifecycleInvalidBrokerEpoch,  kInvalidServiceTransitionIdentity, 0, kInvalidProcessKey,
    kServiceExitReapInvalidEventSequence,
};

inline constexpr bool ServiceExitReapEventKeyIsValid(ServiceExitReapEventKey key)
{
    return key.broker_epoch != kServiceLifecycleInvalidBrokerEpoch &&
           key.service_identity != kInvalidServiceTransitionIdentity && key.transition_generation != 0 &&
           ProcessKeyIsValid(key.process) && key.event_sequence != kServiceExitReapInvalidEventSequence;
}

inline constexpr bool operator==(ServiceExitReapEventKey lhs, ServiceExitReapEventKey rhs)
{
    return lhs.broker_epoch == rhs.broker_epoch && lhs.service_identity == rhs.service_identity &&
           lhs.transition_generation == rhs.transition_generation && lhs.process == rhs.process &&
           lhs.event_sequence == rhs.event_sequence;
}

// Directory binding supplied by the acquirer.  The exit event does not carry
// the directory ServiceKey (registration authority stays with whoever drove
// publication), so the caller either supplies the exact key or explicitly
// declares it unknown.  The ledger never invents a key and never resolves one
// by name, and an unbound row reports ServiceExitReapDirectoryDisposition::
// Unbound instead of a fabricated teardown.
struct ServiceExitReapDirectoryBinding
{
    u8 bound;
    ServiceKey service;
};

inline constexpr ServiceExitReapDirectoryBinding kServiceExitReapNoDirectoryBinding{0, kInvalidServiceKey};

inline constexpr ServiceExitReapDirectoryBinding ServiceExitReapDirectoryBindingFor(ServiceKey service)
{
    return ServiceExitReapDirectoryBinding{1, service};
}

// One durable reap row.  Public only for fixed-capacity boot-global embedding
// and hostile host tests; treat every field as opaque after Initialize.
struct ServiceExitReapRow
{
    ServiceExitReapRowStage stage;
    u8 pump_inflight;
    ServiceExitReapLifecycleDisposition lifecycle_disposition;
    ServiceExitReapDirectoryDisposition directory_disposition;
    ServiceExitReapObserverAckDisposition observer_ack_disposition;
    u8 directory_bound;
    u8 reserved8[2];
    u64 admission;
    u64 event_sequence;
    ServiceExitEvent event;
    ServiceKey directory_service;
    ServiceInstanceToken directory_owner;
    ServiceLifecycleStatus lifecycle_status;
    ServiceDirectoryStatus directory_status;
    ServiceEndpointStatus directory_endpoint_status;
    ServiceExitObserverStatus observer_ack_status;
    u32 directory_drained_channels;
    u64 delivery_token;
    ProcessKey delivery_owner;
    u32 delivery_count;
    u32 reserved32;
};

// Public only so the boot owner can provide fixed, allocation-free storage.
// Treat all fields as opaque after Initialize succeeds.
struct ServiceExitReapLedger
{
    sync::SpinLock lock;
    ServiceExitReapLedgerState state;
    u8 initialized;
    u16 reserved16;
    u32 live_rows;
    u32 pump_cursor;
    // Free rows reserved across ServiceExitObserverDequeue.  Exact restage
    // queries return Busy while this is nonzero because the dequeued service
    // identity is not yet visible in a durable row.
    u32 acquisitions_inflight;
    ServiceExitReapRow rows[kServiceExitReapLedgerCapacity];

    ServiceExitReapLedger();
    ServiceExitReapLedger(const ServiceExitReapLedger&) = delete;
    ServiceExitReapLedger& operator=(const ServiceExitReapLedger&) = delete;
    ServiceExitReapLedger(ServiceExitReapLedger&&) = delete;
    ServiceExitReapLedger& operator=(ServiceExitReapLedger&&) = delete;
};

struct [[nodiscard]] ServiceExitReapAcquireResult
{
    ServiceExitReapStatus status;
    ServiceExitObserverStatus observer_status;
    ServiceExitReapRowTicket ticket;
};

struct [[nodiscard]] ServiceExitReapRollbackResult
{
    ServiceExitReapStatus status;
    ServiceExitObserverStatus observer_status;
};

struct [[nodiscard]] ServiceExitReapPumpResult
{
    ServiceExitReapStatus status;
    u32 steps_attempted;
    u32 lifecycle_committed;
    u32 lifecycle_refused;
    u32 directory_committed;
    u32 directory_busy;
    u32 directory_refused;
    u32 ready_transitions;
    u32 rows_pending;
};

// Scalar delivery record for the SYS_SERVICE_CONTROL plane.  Everything is an
// exact recorded fact from the observer event and the settlement statuses; no
// pointer and no broker/directory authority.  event_sequence is factual
// identity only and must be paired with delivery_token for acknowledgement.
struct ServiceExitReapDeliveryRecord
{
    u64 delivery_token;
    u64 service_identity;
    u64 generation;
    u64 broker_epoch;
    u64 event_sequence;
    ServiceInstanceKey instance;
    ProcessKey process;
    u32 exit_code;
    u8 failed;
    ServiceExitReapLifecycleDisposition lifecycle_disposition;
    ServiceExitReapDirectoryDisposition directory_disposition;
    ServiceExitReapObserverAckDisposition observer_ack_disposition;
    ServiceLifecycleStatus lifecycle_status;
    ServiceDirectoryStatus directory_status;
    ServiceExitObserverStatus observer_ack_status;
    u8 reserved8;
    u32 directory_drained_channels;
    u32 delivery_count;
};

struct [[nodiscard]] ServiceExitReapDeliveryResult
{
    ServiceExitReapStatus status;
    ServiceExitReapDeliveryRecord record;
};

struct [[nodiscard]] ServiceExitReapOwnerExitResult
{
    ServiceExitReapStatus status;
    u32 reverted_rows;
};

struct [[nodiscard]] ServiceExitReapRestageResult
{
    ServiceExitReapStatus status;
    u8 eligible;
    u32 live_rows;
    u32 blocking_rows;
};

struct ServiceExitReapRowSnapshot
{
    ServiceExitReapRowStage stage;
    ServiceExitReapLifecycleDisposition lifecycle_disposition;
    ServiceExitReapDirectoryDisposition directory_disposition;
    ServiceExitReapObserverAckDisposition observer_ack_disposition;
    u64 admission;
    u64 event_sequence;
    u64 broker_epoch;
    u64 service_identity;
    u64 generation;
    ProcessKey process;
    u64 delivery_token;
    ProcessKey delivery_owner;
    u32 delivery_count;
    u32 directory_drained_channels;
};

struct [[nodiscard]] ServiceExitReapRowInspectResult
{
    ServiceExitReapStatus status;
    ServiceExitReapRowSnapshot snapshot;
};

struct ServiceExitReapLedgerSnapshot
{
    ServiceExitReapLedgerState state;
    u32 live_rows;
    u32 stage_counts[7];
};

/// Initialize caller-owned canonical storage.  Reinitialization is legal only
/// after a successful Close; an Open ledger refuses a second Initialize.
/// [boot/task context; not concurrent with itself]
ServiceExitReapStatus ServiceExitReapLedgerInitialize(ServiceExitReapLedger* ledger);

/// Close only when no row is live.  RowsLive leaves the ledger Open with every
/// durable row intact; close never silently discards an undelivered event.
/// [any task/CPU, thread-safe]
ServiceExitReapStatus ServiceExitReapLedgerClose(ServiceExitReapLedger* ledger);

/// Dequeue exactly one pending observer exit event into a Free row.  A full
/// ledger refuses with CapacityExhausted BEFORE touching the observer, so the
/// event stays queued there and nothing is dropped.  The caller supplies the
/// directory binding (exact ServiceKey or explicitly unbound); the exact
/// directory owner token is derived from the event's instance token, exactly
/// as the lifecycle broker derives it.
/// [any task/CPU, thread-safe; no ledger lock held across the observer call]
ServiceExitReapAcquireResult ServiceExitReapLedgerAcquireFromObserver(ServiceExitReapLedger* ledger,
                                                                      ServiceExitObserver* observer,
                                                                      ServiceExitReapDirectoryBinding binding);

/// Explicit pre-commit rollback: requeue the exact observer receipt and free
/// the row.  Legal only while the row is Acquired; after the lifecycle commit
/// settles, rollback refuses with WrongStage.  A refused requeue keeps the
/// row Acquired and reports the exact observer status (fail closed, no drop).
/// [any task/CPU, thread-safe; no ledger lock held across the observer call]
ServiceExitReapRollbackResult ServiceExitReapLedgerRollbackAcquired(ServiceExitReapLedger* ledger,
                                                                    ServiceExitObserver* observer,
                                                                    ServiceExitReapRowTicket ticket);

/// Drive at most max_steps external settlement steps across all rows needing
/// progress, starting from a rotating cursor so a perpetually-Busy row cannot
/// starve later rows.  Each step performs exactly one external call
/// (ObserveExit, OwnerCrashed, or observer Acknowledge) with no ledger lock
/// held across it.  Nonblocking; safe from scheduler maintenance context.
/// now_ns must be monotonic per the lifecycle broker's timestamp contract.
/// [task context, any task/CPU, thread-safe]
ServiceExitReapPumpResult ServiceExitReapLedgerPump(ServiceExitReapLedger* ledger, ServiceLifecycleBroker* broker,
                                                    ServiceDirectory* directory, ServiceExitObserver* observer,
                                                    u64 now_ns, u32 max_steps);

/// Dequeue the oldest ReadyForDelivery event for an exact delivery owner.
/// The public token was minted at the ReadyForDelivery transition and is
/// stable across redeliveries; dequeue never mints.  The row moves to
/// Delivered leased to delivery_owner until its exact ACK or its exit.
/// [any task/CPU, thread-safe]
ServiceExitReapDeliveryResult ServiceExitReapLedgerDequeueForDelivery(ServiceExitReapLedger* ledger,
                                                                      ProcessKey delivery_owner);

/// Exact-event, exact-token acknowledgement.  Fails closed without mutating
/// any row unless the token names a Delivered row whose full factual event key
/// and lease owner both match.  Validation and row release occur in one locked
/// transaction, so a lookup-then-ACK TOCTOU cannot exist.
/// [any task/CPU, thread-safe]
ServiceExitReapStatus ServiceExitReapLedgerAcknowledgeDelivery(ServiceExitReapLedger* ledger,
                                                               ServiceExitReapEventKey event, u64 delivery_token,
                                                               ProcessKey delivery_owner);

/// Delivery-owner crash path: every Delivered row leased to exactly
/// delivery_owner reverts to ReadyForDelivery with its token and record
/// intact, so the next exact serviced incarnation can redeliver and ACK.
/// Idempotent; an unknown owner reverts nothing and reports Ok.
/// [any task/CPU, thread-safe]
ServiceExitReapOwnerExitResult ServiceExitReapLedgerNotifyDeliveryOwnerExit(ServiceExitReapLedger* ledger,
                                                                            ProcessKey delivery_owner);

/// Restage eligibility for one exact exit event.  The exact row must have a
/// committed lifecycle outcome and authoritative directory settlement
/// (Committed or SettledAbsent).  Delivery-token minting and userland ACK are
/// deliberately irrelevant.  Two outstanding rows for the same service apply
/// backpressure so a third incarnation cannot exceed the advertised overlap
/// bound.  NotFound means the ledger holds no row for this exact key.
/// [any task/CPU, thread-safe]
ServiceExitReapRestageResult ServiceExitReapLedgerQueryRestageExact(ServiceExitReapLedger* ledger,
                                                                    ServiceExitReapEventKey event);

/// Scalar snapshots for tests and diagnostics.  No authority is returned.
/// [any task/CPU, thread-safe]
ServiceExitReapStatus ServiceExitReapLedgerInspect(ServiceExitReapLedger* ledger,
                                                   ServiceExitReapLedgerSnapshot* snapshot_out);
ServiceExitReapRowInspectResult ServiceExitReapLedgerInspectRow(ServiceExitReapLedger* ledger, u32 row);

const char* ServiceExitReapStatusName(ServiceExitReapStatus status);

#if defined(DUETOS_HOST_TEST)
enum class ServiceExitReapLedgerHostHookPoint : u8
{
    AcquireReservedBeforeObserverDequeue = 0,
    ObserverDequeueReturnedBeforeLedgerApply,
    RollbackReservedBeforeObserverRequeue,
    PumpSelectedBeforeExternalCall,
    ObserverAckReturnedBeforeLedgerApply,
};

struct ServiceExitReapLedgerHostHookEvent
{
    ServiceExitReapLedgerHostHookPoint point;
    u32 row;
    u64 admission;
    ServiceExitReapRowStage stage;
};

using ServiceExitReapLedgerHostHook = void (*)(const ServiceExitReapLedgerHostHookEvent& event, void* context);

// Deterministic concurrency seam.  The callback always runs without the
// ledger lock and must not re-enter the ledger or call a function while
// holding another core lock.  Install and clear only while callbacks are
// quiescent; passing nullptr clears the hook.
void ServiceExitReapLedgerHostSetHook(ServiceExitReapLedgerHostHook hook, void* context);

// Host-only exhaustion seam for the global public delivery-token space.
// Returns the previous next-token value so a test can restore it.
u64 ServiceExitReapLedgerHostSetNextDeliveryTokenForTest(u64 next_token);
#endif

} // namespace duetos::core
