#pragma once

/*
 * Protocol-neutral process Job service.
 *
 * The core owns the bounded pool, opaque non-wrapping generation keys,
 * handle-reference count, exact ProcessKey membership records, accounting
 * snapshots, publication/termination operation pins, and owner-exit drain. ABI adapters
 * own public handle encoding, status values, user-buffer layouts, capability
 * policy, and the actual process-kill request.
 *
 * A Job never retains or borrows a Process pointer. Membership is a small
 * record keyed by the immutable ProcessKey. The scheduler is the outer
 * lifetime boundary for publication, explicit assignment, and termination;
 * Job operations only mutate the pointer-free record beneath that lock. This deliberately breaks the
 * Job -> Process -> handle -> Job lifetime cycle.
 *
 * Locking contract: no Process operation, scheduler operation, allocator,
 * logger, or other external subsystem call runs while the Job pool lock is
 * held.
 */

#include "proc/process.h"
#include "util/types.h"

namespace duetos::core
{

constexpr u32 kJobPoolCapacity = 8;
constexpr u32 kJobMemberCapacity = 32;

// Opaque keys use a fixed 51-bit generation domain. Exhausted rows are
// permanently retired instead of wrapping.
constexpr u64 kJobGenerationMaximum = (1ULL << 51) - 1;

struct JobKey
{
    u32 slot;
    u64 generation;
};

enum class JobState : u8
{
    Retired = 0,
    Reserved,
    Live,
    Terminating,
    Tombstone,
};

struct JobSnapshot
{
    // Current externally visible membership. `process_id_count` is kept
    // separate so a future bounded/partial PID-list query cannot confuse the
    // number assigned with the number that fit in the caller's buffer.
    u32 member_count;
    u32 process_id_count;
    u32 total_processes;
    u32 total_terminated_processes;
    u64 member_pids[kJobMemberCapacity];
};

struct JobLifecycleSnapshot
{
    JobState state;
    u64 generation;
    ProcessKey owner;
    u32 references;
    u32 operation_pins;
    u32 member_count;
    u32 pending_member_count;
    bool retire_pending;
};

enum class JobAssignResult : u8
{
    Assigned = 0,
    AlreadyMember,
    MembershipConflict,
    InvalidJob,
    Terminated,
    Capacity,
    NotLive,
};

enum class JobTerminateResult : u8
{
    Begun = 0,
    AlreadyTerminated,
    InvalidJob,
};

// Exact member incarnations copied from completion records.  No Process
// lifetime is carried by this object.  Do not copy or reuse an active intent.
struct JobTerminationIntent
{
    JobTerminationIntent() = default;
    JobTerminationIntent(const JobTerminationIntent&) = delete;
    JobTerminationIntent& operator=(const JobTerminationIntent&) = delete;

    JobKey key{};
    u64 ticket = 0;
    u32 member_count = 0;
    u32 exit_code = 0;
    bool active = false;
    ProcessKey members[kJobMemberCapacity]{};
};

enum class JobPublishPrepareResult : u8
{
    NoParentJob = 0,
    Prepared,
    MembershipConflict,
    Terminated,
    Capacity,
    Invalid,
};

// One hidden child-membership reservation. The nonce is minted under the Job
// lock and bound to the exact row generation, member slot, and ProcessKey.
// Tickets are synchronous scheduler-publication capabilities: they cannot be
// copied, and commit/abort consumes the matching nonce exactly once.
struct JobPublicationTicket
{
    JobPublicationTicket() = default;
    JobPublicationTicket(const JobPublicationTicket&) = delete;
    JobPublicationTicket& operator=(const JobPublicationTicket&) = delete;

    JobKey key{};
    ProcessKey process{};
    u64 ticket = 0;
    u32 member_slot = 0;
    bool active = false;
};

/// Reserve, initialize, and publish one Job with one open reference.
bool JobCreate(ProcessKey owner, JobKey* out_key);

/// Publish an exact Process incarnation as an active Job member. The Job never
/// retains ProcessCore. The scheduler wrapper must hold its lifetime lock,
/// prove the Process is Published/Open with a non-Dead Task, and keep that lock
/// through this mutation; the same transaction owns JobOnProcessExit at the
/// exact last-Task unlink.
JobAssignResult JobAssign(JobKey key, ProcessKey owner, ProcessKey member);

/// Reserve default child membership while the scheduler holds its lifetime
/// lock. Pending membership is invisible to queries/accounting but pins the
/// Job row against close/owner-drain reuse. A parent in a terminating Job
/// rejects publication rather than allowing the child to escape.
JobPublishPrepareResult JobPrepareInheritedMember(ProcessKey parent, ProcessKey child,
                                                  JobPublicationTicket* out_ticket);

/// Publish or discard one exact pending child membership. The scheduler keeps
/// its lifetime lock across prepare, the external Process publication gate,
/// and this terminal operation; no Job lock is held while that gate runs.
bool JobCommitInheritedMember(JobPublicationTicket* ticket);
bool JobAbortInheritedMember(JobPublicationTicket* ticket);

/// Test membership in one owner-authorized Job.
bool JobContainsOwned(JobKey key, ProcessKey owner, ProcessKey member, bool* out_contains);

/// Test membership in any externally visible Job.
bool JobContainsAny(ProcessKey member);

/// Snapshot one owner-authorized Job into a protocol-neutral structure.
bool JobSnapshotOwned(JobKey key, ProcessKey owner, JobSnapshot* out_snapshot);

/// Snapshot the first externally visible Job containing `member`.
bool JobSnapshotContaining(ProcessKey member, JobSnapshot* out_snapshot);

/// Transition Live -> Terminating and copy every active exact member key into
/// a one-shot intent while pinning the Job row against generation reuse.
JobTerminateResult JobBeginTermination(JobKey key, ProcessKey owner, u32 exit_code, JobTerminationIntent* out_intent);

/// Consume the authentic dispatch ticket and drop its operation pin. The Job
/// remains Terminating while any member is active; the last exact Process-exit
/// notification owns the Terminating -> Tombstone transition.
bool JobFinishTermination(JobTerminationIntent* intent);

/// Notify the service that an exact Process incarnation has no live tasks.
/// Logical active membership is removed exactly once and the slot becomes
/// reusable. Explicit assignment is scheduler-linearized with live Process
/// state, so a stale retained Process header cannot republish the dead key.
/// Thread-safe and callable from any CPU; does not invoke the scheduler.
void JobOnProcessExit(ProcessKey process);

/// Drop one open reference.  Returns false for stale, foreign, or double close.
bool JobClose(JobKey key, ProcessKey owner);

/// Tombstone and retire every Job created by the exact owner.  Idempotent.
void JobDrainOwned(ProcessKey owner);

/// Kernel diagnostic/self-test view.  Unlike public operations, this can
/// inspect an exact retired generation until that row is reused.
bool JobInspectLifecycle(JobKey key, JobLifecycleSnapshot* out_snapshot);

} // namespace duetos::core
