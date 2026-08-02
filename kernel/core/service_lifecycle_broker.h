#pragma once

/*
 * Fixed-capacity managed-service lifecycle broker.
 *
 * This is the kernel-resident lifecycle half of the future serviced split. It
 * consumes a fully validated ServiceManifestPlanV1 and owns only stable row
 * identity, exact ServiceTransition state, lifecycle telemetry, builder pins,
 * and drain state. Restart policy remains in serviced, outside this TCB.
 * It does not parse executables, choose policy, allocate, call the scheduler,
 * publish endpoints, wait, log, or release external objects.
 * All pointers are trusted kernel-resident storage. A syscall/IPC adapter must
 * copy and validate hostile wire data before entering this module; numeric
 * pointer-range checks here are overflow/alias guards, not user-copy probes.
 *
 * Locking:
 *   - Every operation after Initialize is [any task/CPU, thread-safe].
 *   - The scheduler publication path acquires scheduler publication lock,
 *     then calls CommitPublication, which acquires this broker lock.
 *   - No caller may enter the scheduler, loader, allocator, KObject release,
 *     or arbitrary callback while holding this broker's lock.
 *   - Stop and BeginDrain return exact tokens.  Scheduler kill/proof-of-exit
 *     happens after this lock is released and is committed with ObserveExit.
 */

#include "core/service_manifest.h"
#include "core/service_transition.h"
#include "sync/spinlock.h"
#include "util/types.h"

namespace duetos::core
{

struct ServiceDirectory;
struct ServiceKey;
struct ServiceRegistrationReservation;
enum class ServiceDirectoryStatus : u8;

inline constexpr u32 kServiceLifecycleCapacity = kServiceManifestMaximumServices;
inline constexpr u64 kServiceLifecycleInvalidBrokerEpoch = 0;
static_assert(kServiceLifecycleCapacity <= 64, "service lifecycle dependency mask width exceeded");

enum class ServiceLifecycleStatus : u8;
struct ServiceLifecycleBroker;

/// One-shot authority for a kernel-wide, non-recycled broker incarnation.
/// Only ServiceLifecycleBrokerMintEpoch can construct a valid token, and a
/// successful broker initialization consumes it.  This makes accidental epoch
/// reuse a compile-time error instead of a caller convention.  Exhaustion is
/// fail-closed and returns an invalid token; epochs restart only with a kernel
/// reboot, when no old broker authority remains live.
class ServiceLifecycleBrokerEpoch
{
  public:
    constexpr ServiceLifecycleBrokerEpoch() = default;
    ~ServiceLifecycleBrokerEpoch() = default;
    ServiceLifecycleBrokerEpoch(const ServiceLifecycleBrokerEpoch&) = delete;
    ServiceLifecycleBrokerEpoch& operator=(const ServiceLifecycleBrokerEpoch&) = delete;
    ServiceLifecycleBrokerEpoch(ServiceLifecycleBrokerEpoch&&) = delete;
    ServiceLifecycleBrokerEpoch& operator=(ServiceLifecycleBrokerEpoch&&) = delete;

    [[nodiscard]] constexpr bool IsValid() const { return m_value != kServiceLifecycleInvalidBrokerEpoch; }

  private:
    explicit constexpr ServiceLifecycleBrokerEpoch(u64 value) : m_value(value) {}

    u64 m_value = kServiceLifecycleInvalidBrokerEpoch;

    friend ServiceLifecycleBrokerEpoch ServiceLifecycleBrokerMintEpoch();
    friend ServiceLifecycleStatus ServiceLifecycleBrokerInitialize(ServiceLifecycleBroker*,
                                                                   const ServiceManifestPlanV1*,
                                                                   const ServiceManifestAuthoritySnapshotV1*,
                                                                   ServiceLifecycleBrokerEpoch*);
};

/// Mint one process-wide broker epoch.  This is allocation-free, thread-safe,
/// and callable only from kernel trust-domain code.  An invalid token means the
/// monotonic u64 space was exhausted and broker creation must fail closed.
ServiceLifecycleBrokerEpoch ServiceLifecycleBrokerMintEpoch();

struct ServiceLifecycleStartTicket
{
    // Non-recycled kernel-minted broker incarnation.  The embedded transition
    // ticket is deliberately insufficient on its own: two broker instances may
    // contain the same service identity and generation.
    u64 broker_epoch;
    ServiceStartTicket transition;
};

constexpr ServiceLifecycleStartTicket kInvalidServiceLifecycleStartTicket{kServiceLifecycleInvalidBrokerEpoch,
                                                                          kInvalidServiceStartTicket};

constexpr bool ServiceLifecycleStartTicketIsValid(ServiceLifecycleStartTicket ticket)
{
    return ticket.broker_epoch != kServiceLifecycleInvalidBrokerEpoch && ServiceStartTicketIsValid(ticket.transition);
}

constexpr bool operator==(ServiceLifecycleStartTicket lhs, ServiceLifecycleStartTicket rhs)
{
    return lhs.broker_epoch == rhs.broker_epoch && lhs.transition == rhs.transition;
}

struct ServiceLifecycleInstanceToken
{
    ServiceLifecycleStartTicket start;
    ServiceInstanceKey process;
};

constexpr ServiceLifecycleInstanceToken kInvalidServiceLifecycleInstanceToken{kInvalidServiceLifecycleStartTicket,
                                                                              kInvalidServiceInstanceKey};

constexpr bool ServiceLifecycleInstanceTokenIsValid(ServiceLifecycleInstanceToken token)
{
    return ServiceLifecycleStartTicketIsValid(token.start) && ServiceInstanceKeyIsValid(token.process);
}

constexpr bool operator==(ServiceLifecycleInstanceToken lhs, ServiceLifecycleInstanceToken rhs)
{
    return lhs.start == rhs.start && lhs.process == rhs.process;
}

enum class ServiceLifecycleBrokerState : u8
{
    Uninitialized = 0,
    Open,
    Draining,
    Closed,
};

enum class ServiceLifecycleStatus : u8
{
    Ok = 0,
    NullArgument,
    AliasedOutput,
    InvalidManifestPlan,
    InvalidBrokerEpoch,
    AlreadyInitialized,
    NotInitialized,
    Closed,
    Draining,
    CorruptState,
    NotFound,
    StaleGeneration,
    StaleBrokerEpoch,
    InvalidTimestamp,
    AlreadyRequested,
    StopInProgress,
    GenerationExhausted,
    TransitionRejected,
    AlreadyStopped,
    StartCancelled,
    KillRequired,
    AlreadyStopping,
    StartRetirementPending,
    DependencyNotReady,
    Busy,
};

enum class ServiceLifecycleBuilderState : u8
{
    None = 0,
    Constructing,
    CancelledAwaitingRetirement,
};

struct ServiceLifecycleRow
{
    ServiceTransitionState transition;
    u64 dependency_mask;
    u64 last_transition_ns;
    u32 successful_publications;
    u32 spawn_failures;
    u32 observed_exits;
    u32 failed_exits;
    ServiceLifecycleBuilderState builder_state;
    bool ready;
    u8 reserved8;
    u16 reserved16;
    u32 reserved32;
};

struct ServiceLifecycleBroker
{
    sync::SpinLock lock;
    ServiceLifecycleBrokerState state;
    u8 initialized;
    u16 service_count;
    u16 dependency_count;
    u16 reserved16;
    u64 broker_epoch;
    u64 manifest_identity;
    u64 manifest_authority_identity;
    loader::Hash256 manifest_object_hash;
    u64 manifest_object_extent;
    ServiceLifecycleRow rows[kServiceLifecycleCapacity];

    ServiceLifecycleBroker();
    ServiceLifecycleBroker(const ServiceLifecycleBroker&) = delete;
    ServiceLifecycleBroker& operator=(const ServiceLifecycleBroker&) = delete;
    ServiceLifecycleBroker(ServiceLifecycleBroker&&) = delete;
    ServiceLifecycleBroker& operator=(ServiceLifecycleBroker&&) = delete;
};

struct ServiceLifecycleSnapshot
{
    u64 service_identity;
    ServiceTransitionPhase phase;
    u64 transition_generation;
    ServiceInstanceKey instance;
    u64 dependency_mask;
    u64 last_transition_ns;
    u32 successful_publications;
    u32 spawn_failures;
    u32 observed_exits;
    u32 failed_exits;
    ServiceLifecycleBuilderState builder_state;
    bool ready;
};

struct ServiceLifecycleBrokerSnapshot
{
    ServiceLifecycleBrokerState state;
    u16 service_count;
    u16 dependency_count;
    u64 broker_epoch;
    u64 manifest_identity;
    u64 manifest_authority_identity;
    loader::Hash256 manifest_object_hash;
    u64 manifest_object_extent;
};

struct ServiceLifecycleStartResult
{
    ServiceLifecycleStatus status;
    ServiceLifecycleStartTicket ticket;
};

struct ServiceLifecyclePublicationResult
{
    ServiceLifecycleStatus status;
    ServiceLifecycleInstanceToken instance;
};

// Joint first-Task publication result.  The directory status is meaningful
// only when lifecycle_status is Ok.  A non-Ok directory status guarantees
// that the exact lifecycle commit was rolled back to its prior Starting
// builder state before the lifecycle lock was released.
struct ServiceLifecycleDirectoryPublicationResult
{
    ServiceLifecycleStatus lifecycle_status;
    ServiceDirectoryStatus directory_status;
    ServiceLifecycleInstanceToken instance;
};

// Joint service-readiness result. directory_status is meaningful only when
// lifecycle_status is Ok. A non-Ok directory status guarantees neither half
// was changed by this invocation.
struct ServiceLifecycleDirectoryReadyResult
{
    ServiceLifecycleStatus lifecycle_status;
    ServiceDirectoryStatus directory_status;
};

struct ServiceLifecycleStopResult
{
    ServiceLifecycleStatus status;
    ServiceLifecycleInstanceToken instance_to_kill;
    ServiceLifecycleStartTicket start_to_cancel;
};

struct ServiceLifecycleInspectResult
{
    ServiceLifecycleStatus status;
    ServiceLifecycleSnapshot snapshot;
};

struct ServiceLifecycleBrokerInspectResult
{
    ServiceLifecycleStatus status;
    ServiceLifecycleBrokerSnapshot snapshot;
};

struct ServiceLifecycleDrainPlan
{
    u16 kill_count;
    u16 cancel_count;
    u32 reserved32;
    ServiceLifecycleInstanceToken instances[kServiceLifecycleCapacity];
    ServiceLifecycleStartTicket cancelled_starts[kServiceLifecycleCapacity];
};

/// Initialize an unpublished broker from an exact validated manifest plan, its
/// separately retained trusted authority snapshot, and a one-shot
/// kernel-minted broker incarnation. The function independently checks the
/// native document/topology, binds every plan identity/hash/extent back to the
/// authority snapshot, replays every authority ceiling, and recomputes the
/// canonical document hash, rejecting post-validation mutation. The caller
/// owns or pins the plan and authority as immutable for the full call. Inputs,
/// epoch, and output must not overlap. Successful initialization consumes the
/// epoch; failures leave it valid for retry. The broker is intentionally
/// non-copyable and rejects every attempt to initialize it twice.
/// [boot/task context; not concurrent]
ServiceLifecycleStatus ServiceLifecycleBrokerInitialize(ServiceLifecycleBroker* broker,
                                                        const ServiceManifestPlanV1* plan,
                                                        const ServiceManifestAuthoritySnapshotV1* authority,
                                                        ServiceLifecycleBrokerEpoch* broker_epoch);

/// Reserve a start only when expected_generation exactly matches the current
/// row.  Returning broker-scoped start authority is represented by status Ok.
/// No scheduler or loader operation occurs here.
/// [any task/CPU, thread-safe]
ServiceLifecycleStartResult ServiceLifecycleBrokerReserveStart(ServiceLifecycleBroker* broker, u64 service_identity,
                                                               u64 expected_generation, u64 now_ns);

/// Dependency-aware reserve for the authenticated bootstrap builder. Under one
/// broker-lock critical section, validate the exact selected row and require
/// every identity in its manifest-derived dependency mask to be Running with a
/// valid published instance whose joint ready transaction committed, then
/// reserve the start. DependencyNotReady makes
/// no mutation. This is the only supported bootstrap dependency-admission
/// primitive; callers must not synthesize it from unlocked Inspect snapshots.
/// [any task/CPU, thread-safe]
ServiceLifecycleStartResult ServiceLifecycleBrokerReserveStartWithDependencies(ServiceLifecycleBroker* broker,
                                                                               u64 service_identity,
                                                                               u64 expected_generation, u64 now_ns);

/// Commit private-construction failure for one exact start ticket.  The
/// timestamp must be monotonic for this row. Restart decisions belong to
/// serviced; this operation records only the exact transition and telemetry.
/// [any task/CPU, thread-safe]
ServiceLifecycleStatus ServiceLifecycleBrokerRecordSpawnFailure(ServiceLifecycleBroker* broker,
                                                                ServiceLifecycleStartTicket ticket, u64 now_ns);

/// Retire one exact private builder after cancellation.  The caller must first
/// destroy every unpublished Process/Task/resource graph owned by the ticket;
/// this acknowledgement then releases the broker's lifetime pin.  A cancelled
/// generation cannot restart and drain cannot finish until this succeeds.
/// This is a kernel builder operation and is never exposed as serviced-owned
/// proof that teardown happened.
/// [any task/CPU, thread-safe]
ServiceLifecycleStatus ServiceLifecycleBrokerAcknowledgeCancelledStart(ServiceLifecycleBroker* broker,
                                                                       ServiceLifecycleStartTicket ticket, u64 now_ns);

/// Scheduler publication gate.  Call while holding the scheduler publication
/// lock; this function takes the lower-ranked broker lock and commits the exact
/// non-recycled process identity/PID pair.  Publish the private Task before
/// releasing the scheduler lock iff status is Ok.
/// This is a kernel scheduler-publication operation, not a public broker verb.
/// [scheduler publication lock held; nonblocking]
ServiceLifecyclePublicationResult ServiceLifecycleBrokerCommitPublication(ServiceLifecycleBroker* broker,
                                                                          ServiceLifecycleStartTicket ticket,
                                                                          ServiceInstanceKey instance, u64 now_ns);

/// Authenticated bootstrap publication join.  Call only from the first-Task
/// scheduler publication gate after the exact exit-observer row is Bound.
/// This operation holds the lifecycle lock continuously while it commits the
/// exact ticket/ProcessKey and takes the lower-ranked directory lock to publish
/// the already-private registration.  Directory publication is the last
/// fallible visibility step.  On directory refusal, a private exact rollback
/// token restores the lifecycle row to the same Starting builder transaction
/// before either lock is released; no Running-without-directory interval can
/// escape to stop/drain callers.
///
/// No endpoint, HandleTable operation, allocation, callback, destructor,
/// logging, scheduler call, or wait is permitted in this lock chain.
/// [scheduler publication lock held; nonblocking]
ServiceLifecycleDirectoryPublicationResult ServiceLifecycleBrokerCommitDirectoryPublication(
    ServiceLifecycleBroker* broker, ServiceLifecycleStartTicket ticket, ServiceInstanceKey instance, u64 now_ns,
    ServiceDirectory* directory, ServiceRegistrationReservation* reservation);

/// Atomically admit one exact published instance for dependency starts and new
/// directory Connect calls. This operation holds the lifecycle lock, validates
/// the exact current Running instance, then takes the lower-ranked directory
/// lock to validate the exact Active ServiceKey/owner. Only after all fallible
/// checks pass does it write directory.ready followed by lifecycle.ready; no
/// fallible operation remains after the first write. Exact replay is
/// idempotent. Owner Lookup and Accept do not depend on this admission bit.
/// [any task/CPU, thread-safe; nonblocking]
ServiceLifecycleDirectoryReadyResult ServiceLifecycleBrokerMarkReady(ServiceLifecycleBroker* broker,
                                                                     ServiceLifecycleInstanceToken instance,
                                                                     ServiceDirectory* directory, ServiceKey service);

/// Request stop for an exact observed generation.  KillRequired returns the
/// sole scheduler-kill token; StartCancelled returns the exact builder ticket
/// that must be signalled and later acknowledged; duplicate calls emit neither.
/// [any task/CPU, thread-safe]
ServiceLifecycleStopResult ServiceLifecycleBrokerRequestStop(ServiceLifecycleBroker* broker, u64 service_identity,
                                                             u64 expected_generation, u64 now_ns);

/// Commit proof that the exact published process is no longer scheduler
/// visible.  `failed` is telemetry only and grants no authority.
/// This is a kernel scheduler/reaper operation, not serviced-supplied proof.
/// [any task/CPU, thread-safe]
ServiceLifecycleStatus ServiceLifecycleBrokerObserveExit(ServiceLifecycleBroker* broker,
                                                         ServiceLifecycleInstanceToken instance, u64 now_ns,
                                                         bool failed);

/// Enter terminal drain transactionally.  Starts become forbidden, every
/// Starting row is cancelled and contributes one exact builder ticket, and
/// each newly-stopped Running row contributes one exact kill token.
/// Already-Stopping/cancelled rows emit no duplicate authority.
/// [any task/CPU, thread-safe]
ServiceLifecycleStatus ServiceLifecycleBrokerBeginDrain(ServiceLifecycleBroker* broker, u64 now_ns,
                                                        ServiceLifecycleDrainPlan* plan_out);

/// Close only after every Starting/Running/Stopping row and cancelled private
/// builder pin is gone. Busy leaves the broker Draining so callers can finish
/// exact scheduler/private-graph teardown.
/// [any task/CPU, thread-safe]
ServiceLifecycleStatus ServiceLifecycleBrokerFinishDrain(ServiceLifecycleBroker* broker);

/// Stable identity lookup and sorted-index enumeration.  Returned data is a
/// scalar snapshot and carries no Process/Task pointer or retained authority.
/// [any task/CPU, thread-safe]
ServiceLifecycleBrokerInspectResult ServiceLifecycleBrokerDescribe(ServiceLifecycleBroker* broker);
ServiceLifecycleInspectResult ServiceLifecycleBrokerInspect(ServiceLifecycleBroker* broker, u64 service_identity);
ServiceLifecycleInspectResult ServiceLifecycleBrokerInspectAt(ServiceLifecycleBroker* broker, u32 index);

const char* ServiceLifecycleStatusName(ServiceLifecycleStatus status);

} // namespace duetos::core
