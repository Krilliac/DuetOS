#pragma once

/*
 * Protocol-neutral process Job service.
 *
 * The core owns the bounded pool, opaque non-wrapping generation keys,
 * handle-reference count, member Process references, accounting snapshots,
 * termination operation pins, and owner-exit drain.  ABI adapters own public
 * handle encoding, status values, user-buffer layouts, capability policy, and
 * the actual process-kill request.
 *
 * Locking contract: no Process retain/release, scheduler operation, allocator,
 * logger, or other external subsystem call runs while the Job pool lock is
 * held.  Assignment transfers a reference acquired by the caller.  A
 * JobTerminationIntent borrows member pointers while an internal operation pin
 * prevents close/drain from detaching their owning references.
 */

#include "util/types.h"

namespace duetos::core
{

struct Process;

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
    u32 member_count;
    u32 total_processes;
    u32 total_terminated_processes;
    u64 member_pids[kJobMemberCapacity];
};

struct JobLifecycleSnapshot
{
    JobState state;
    u64 generation;
    u64 owner_pid;
    u32 references;
    u32 operation_pins;
    u32 member_count;
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
};

enum class JobTerminateResult : u8
{
    Begun = 0,
    AlreadyTerminated,
    InvalidJob,
};

// Member pointers are borrowed, not newly retained.  They remain live until
// JobFinishTermination consumes this intent.  Do not copy or reuse an intent.
struct JobTerminationIntent
{
    JobKey key;
    u32 member_count;
    bool active;
    Process* members[kJobMemberCapacity];
};

/// Reserve, initialize, and publish one Job with one open reference.
bool JobCreate(u64 owner_pid, JobKey* out_key);

/// Attempt to add `member`, for which the caller already owns one Process
/// reference.  Assigned transfers that reference to the Job.  Every other
/// result leaves the reference with the caller.
JobAssignResult JobAssignRetained(JobKey key, u64 owner_pid, Process* member);

/// Test membership in one owner-authorized Job.
bool JobContainsOwned(JobKey key, u64 owner_pid, const Process* member, bool* out_contains);

/// Test membership in any externally visible Job.
bool JobContainsAny(const Process* member);

/// Snapshot one owner-authorized Job into a protocol-neutral structure.
bool JobSnapshotOwned(JobKey key, u64 owner_pid, JobSnapshot* out_snapshot);

/// Snapshot the first externally visible Job containing `member`.
bool JobSnapshotContaining(const Process* member, JobSnapshot* out_snapshot);

/// Transition Live -> Terminating and pin all borrowed member pointers.
JobTerminateResult JobBeginTermination(JobKey key, u64 owner_pid, JobTerminationIntent* out_intent);

/// Consume an active intent, transition Terminating -> Tombstone, and retire
/// after the last reference when appropriate.  Member releases occur only
/// after the pool lock is dropped.
bool JobFinishTermination(JobTerminationIntent* intent);

/// Drop one open reference.  Returns false for stale, foreign, or double close.
bool JobClose(JobKey key, u64 owner_pid);

/// Tombstone and retire every Job created by owner_pid.  Idempotent.
void JobDrainOwned(u64 owner_pid);

/// Kernel diagnostic/self-test view.  Unlike public operations, this can
/// inspect an exact retired generation until that row is reused.
bool JobInspectLifecycle(JobKey key, JobLifecycleSnapshot* out_snapshot);

} // namespace duetos::core
