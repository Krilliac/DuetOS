#pragma once

/*
 * Exact-generation service publication state machine.
 *
 * This module deliberately owns no lock, Task, Process, scheduler pointer,
 * loader callback, allocation, or logging.  A service-manager row embeds one
 * ServiceTransitionState and serializes every operation with its own lock.
 *
 * The publication rule is the important part:
 *
 *   1. ReserveStart under the service lock.
 *   2. Construct the Process and Task privately with no service lock held.
 *   3. Acquire the scheduler publication lock.
 *   4. While still holding it, acquire the lower-ranked service lock and call
 *      CommitAtSchedulerPublication for the exact ticket and PID.
 *   5. If accepted, link the Task into the scheduler registry/runqueue before
 *      releasing the scheduler lock.  If rejected, destroy it unpublished.
 *
 * Stop never calls the scheduler while holding the service lock.  It either
 * cancels an unpublished start or moves a published instance to Stopping while
 * retaining its exact process identity and PID.  The caller kills that exact
 * instance only after dropping the service lock, then commits proof of exit.
 * A new start cannot be reserved while Stopping, so there is no
 * runnable-but-unrecorded or overlapping service interval.
 */

#include "util/types.h"

namespace duetos::core
{

constexpr u64 kInvalidServiceTransitionIdentity = 0;
constexpr u64 kServiceTransitionGenerationMaximum = ~0ULL;

struct ServiceStartTicket
{
    u64 service_identity;
    u64 generation;
};

constexpr ServiceStartTicket kInvalidServiceStartTicket{kInvalidServiceTransitionIdentity, 0};

constexpr bool ServiceStartTicketIsValid(ServiceStartTicket ticket)
{
    return ticket.service_identity != kInvalidServiceTransitionIdentity && ticket.generation != 0;
}

constexpr bool operator==(ServiceStartTicket lhs, ServiceStartTicket rhs)
{
    return lhs.service_identity == rhs.service_identity && lhs.generation == rhs.generation;
}

struct ServiceInstanceKey
{
    // process_identity is a non-recycled ProcessKey/incarnation, not a PID.
    // pid is retained for the current scheduler lookup and diagnostics only.
    u64 process_identity;
    u64 pid;
};

constexpr ServiceInstanceKey kInvalidServiceInstanceKey{0, 0};

constexpr bool ServiceInstanceKeyIsValid(ServiceInstanceKey key)
{
    return key.process_identity != 0 && key.pid != 0;
}

constexpr bool operator==(ServiceInstanceKey lhs, ServiceInstanceKey rhs)
{
    return lhs.process_identity == rhs.process_identity && lhs.pid == rhs.pid;
}

// Complete exact authority for one published service instance.  The service
// generation and non-recycled process identity travel together so an unlocked
// scheduler operation cannot accidentally combine facts from two lifetimes.
struct ServiceInstanceToken
{
    ServiceStartTicket start;
    ServiceInstanceKey process;
};

constexpr ServiceInstanceToken kInvalidServiceInstanceToken{kInvalidServiceStartTicket, kInvalidServiceInstanceKey};

constexpr bool ServiceInstanceTokenIsValid(ServiceInstanceToken token)
{
    return ServiceStartTicketIsValid(token.start) && ServiceInstanceKeyIsValid(token.process);
}

constexpr bool operator==(ServiceInstanceToken lhs, ServiceInstanceToken rhs)
{
    return lhs.start == rhs.start && lhs.process == rhs.process;
}

enum class ServiceTransitionPhase : u8
{
    Stopped = 0,
    Starting,
    Running,
    Exited,
    Failed,
    GenerationExhausted,
    Stopping,
};

struct ServiceTransitionState
{
    // Stable manifest identity.  Tickets are bound to it so a ticket minted
    // for one service cannot authorize another service at the same generation.
    u64 service_identity;
    ServiceTransitionPhase phase;
    u64 generation;
    ServiceInstanceKey instance;
    bool desired_running;
    bool start_in_flight;
};

enum class ServiceStartReserveResult : u8
{
    Rejected = 0,
    Reserved,
    AlreadyRequested,
    StopInProgress,
    GenerationExhausted,
};

enum class ServicePublicationResult : u8
{
    Rejected = 0,
    Published,
};

enum class ServiceSpawnFailureResult : u8
{
    Rejected = 0,
    Applied,
};

enum class ServiceStopResult : u8
{
    Rejected = 0,
    AlreadyStopped,
    StartCancelled,
    KillRequired,
    AlreadyStopping,
};

enum class ServiceExitResult : u8
{
    Rejected = 0,
    Applied,
};

/// Initialize a caller-owned row for one stable manifest identity.  Failure
/// clears the output to an invalid, non-canonical value.
bool ServiceTransitionInitialize(u64 service_identity, ServiceTransitionState* out_state);

/// Return whether every phase/flag/PID/generation invariant is canonical.
/// The mutation functions reject a non-canonical input without repairing it.
bool ServiceTransitionIsCanonical(const ServiceTransitionState& state);

/// Reserve one exact non-wrapping start generation.  The output ticket is
/// always cleared first.  AlreadyRequested is idempotent success for callers
/// that only need the service to be desired; it intentionally returns no
/// authority ticket.
ServiceStartReserveResult ServiceTransitionReserveStart(ServiceTransitionState* state, ServiceStartTicket* out_ticket);

/// Test the exact Starting authority without mutation.  This is suitable for
/// early aborts during private construction, but is not the publication gate.
bool ServiceTransitionIsCurrentStart(const ServiceTransitionState& state, ServiceStartTicket ticket);

/// Record that private Process/Task construction failed before publication.
/// Stale, cross-service, malformed, and replayed tickets are rejected.
ServiceSpawnFailureResult ServiceTransitionRecordSpawnFailure(ServiceTransitionState* state, ServiceStartTicket ticket);

/// Commit the exact non-recycled process identity and current PID at the
/// scheduler publication boundary.  Call only in the scheduler-lock ->
/// service-lock critical section described above, and publish the private Task
/// before releasing the scheduler lock iff Published is returned.
ServicePublicationResult ServiceTransitionCommitAtSchedulerPublication(ServiceTransitionState* state,
                                                                       ServiceStartTicket ticket,
                                                                       ServiceInstanceKey instance);

/// Cancel Starting authority, or move a Running instance to Stopping and
/// return its exact service/process token for an unlocked scheduler kill.
/// Repeated calls while Stopping return no second kill token.  The caller must
/// retain the first token and keep the row Stopping until ObserveExit commits
/// proof that this exact instance is absent.
ServiceStopResult ServiceTransitionStop(ServiceTransitionState* state, ServiceInstanceToken* out_instance_to_kill);

/// Commit an unlocked scheduler liveness observation only for the exact
/// running/stopping generation and process key.  A stale PID, recycled PID, or
/// ticket cannot retire a newer instance.  Stopping becomes Stopped (or
/// GenerationExhausted); a natural Running exit becomes Exited.  Restart
/// policy is intentionally outside this primitive.
ServiceExitResult ServiceTransitionObserveExit(ServiceTransitionState* state, ServiceInstanceToken instance);

/// Exact read-only check used to revalidate unlocked liveness observations.
bool ServiceTransitionIsCurrentRunning(const ServiceTransitionState& state, ServiceInstanceToken instance);

/// Exact read-only check for either the Running or Stopping instance.
bool ServiceTransitionIsCurrentInstance(const ServiceTransitionState& state, ServiceInstanceToken instance);

} // namespace duetos::core
