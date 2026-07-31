/*
 * Protocol-neutral process Job service.
 *
 * State machine (under g_job_lock):
 *
 *   Retired -> Reserved -> Live -> Terminating -> Tombstone -> Retired
 *                            \--------------------^            ^
 *                             close / owner drain --------------/
 *
 * Reserved is never externally visible.  Terminating owns an operation pin,
 * so a concurrent last-close or owner drain records retire_pending but cannot
 * detach membership references until JobFinishTermination.  Tombstones remain
 * queryable while an open reference exists and reject new assignments.
 */

#include "proc/job.h"

#include "proc/process.h"
#include "sync/spinlock.h"

namespace duetos::core
{

namespace
{

struct JobMember
{
    Process* process;
};

struct JobRow
{
    JobState state;
    u64 generation;
    u64 owner_pid;
    u64 active_process_limit;
    u64 cpu_seconds_limit;
    u32 references;
    u32 operation_pins;
    u32 member_count;
    u32 total_processes;
    u32 total_terminated_processes;
    bool retire_pending;
    JobMember members[kJobMemberCapacity];
};

JobRow g_job_pool[kJobPoolCapacity]{};
sync::SpinLock g_job_lock{};

bool KeyHasValidShape(JobKey key)
{
    return key.slot < kJobPoolCapacity && key.generation != 0 && key.generation <= kJobGenerationMaximum;
}

bool IsExternallyVisibleState(JobState state)
{
    return state == JobState::Live || state == JobState::Terminating || state == JobState::Tombstone;
}

JobRow* ResolveExactLocked(JobKey key)
{
    if (!KeyHasValidShape(key))
        return nullptr;
    JobRow& row = g_job_pool[key.slot];
    return row.generation == key.generation ? &row : nullptr;
}

JobRow* ResolveOwnedLocked(JobKey key, u64 owner_pid)
{
    JobRow* row = ResolveExactLocked(key);
    if (row == nullptr || row->references == 0 || !IsExternallyVisibleState(row->state) || row->owner_pid != owner_pid)
    {
        return nullptr;
    }
    return row;
}

bool ContainsLocked(const JobRow& row, const Process* member)
{
    for (u32 index = 0; index < kJobMemberCapacity; ++index)
    {
        if (row.members[index].process == member)
            return true;
    }
    return false;
}

void SnapshotLocked(const JobRow& row, JobSnapshot& snapshot)
{
    snapshot.total_processes = row.total_processes;
    snapshot.total_terminated_processes = row.total_terminated_processes;
    for (u32 index = 0; index < kJobMemberCapacity; ++index)
    {
        const Process* member = row.members[index].process;
        if (member != nullptr)
            snapshot.member_pids[snapshot.member_count++] = member->pid;
    }
}

// Detach one row while preserving its generation.  Every returned pointer is
// one membership-owned Process reference.  The caller releases them only after
// g_job_lock is dropped.
u32 DetachMembersLocked(JobRow& row, Process** detached)
{
    u32 detached_count = 0;
    for (u32 index = 0; index < kJobMemberCapacity; ++index)
    {
        Process*& member = row.members[index].process;
        if (member != nullptr)
            detached[detached_count++] = member;
        member = nullptr;
    }
    row.member_count = 0;
    return detached_count;
}

u32 RetireLocked(JobRow& row, Process** detached)
{
    // A terminating row cannot retire until its operation pin is consumed.
    if (row.state == JobState::Terminating || row.operation_pins != 0)
        return 0;

    if (row.state == JobState::Live)
        row.state = JobState::Tombstone;

    const u32 detached_count = DetachMembersLocked(row, detached);
    row.owner_pid = 0;
    row.active_process_limit = 0;
    row.cpu_seconds_limit = 0;
    row.references = 0;
    row.operation_pins = 0;
    row.total_processes = 0;
    row.total_terminated_processes = 0;
    row.retire_pending = false;
    row.state = JobState::Retired;
    return detached_count;
}

void ReleaseDetached(Process** detached, u32 detached_count)
{
    for (u32 index = 0; index < detached_count; ++index)
        ProcessRelease(detached[index]);
}

} // namespace

bool JobCreate(u64 owner_pid, JobKey* out_key)
{
    if (out_key == nullptr)
        return false;
    *out_key = {};

    sync::SpinLockGuard guard(g_job_lock);
    for (u32 index = 0; index < kJobPoolCapacity; ++index)
    {
        JobRow& row = g_job_pool[index];
        if (row.state != JobState::Retired || row.generation >= kJobGenerationMaximum)
            continue;

        // Reservation and publication are deliberately separate transitions,
        // even though both occur beneath one lock and cannot be observed by a
        // resolver.
        row.state = JobState::Reserved;
        ++row.generation;
        row.owner_pid = owner_pid;
        row.active_process_limit = 0;
        row.cpu_seconds_limit = 0;
        row.references = 1;
        row.operation_pins = 0;
        row.member_count = 0;
        row.total_processes = 0;
        row.total_terminated_processes = 0;
        row.retire_pending = false;
        for (u32 member = 0; member < kJobMemberCapacity; ++member)
            row.members[member].process = nullptr;
        row.state = JobState::Live;

        out_key->slot = index;
        out_key->generation = row.generation;
        return true;
    }
    return false;
}

JobAssignResult JobAssignRetained(JobKey key, u64 owner_pid, Process* member)
{
    if (member == nullptr)
        return JobAssignResult::InvalidJob;

    sync::SpinLockGuard guard(g_job_lock);
    JobRow* row = ResolveOwnedLocked(key, owner_pid);
    if (row == nullptr)
        return JobAssignResult::InvalidJob;
    if (row->state != JobState::Live)
        return JobAssignResult::Terminated;

    if (ContainsLocked(*row, member))
        return JobAssignResult::AlreadyMember;

    // Membership is globally exclusive until the owning row retires. Keep
    // zero-reference Terminating rows in this scan: their operation pin still
    // owns the member reference, and admitting the same Process elsewhere
    // would make null-handle queries and termination ownership ambiguous.
    for (u32 index = 0; index < kJobPoolCapacity; ++index)
    {
        const JobRow& other = g_job_pool[index];
        if (&other != row && IsExternallyVisibleState(other.state) && ContainsLocked(other, member))
            return JobAssignResult::MembershipConflict;
    }

    if (row->active_process_limit != 0 && row->member_count >= row->active_process_limit)
        return JobAssignResult::Capacity;

    for (u32 index = 0; index < kJobMemberCapacity; ++index)
    {
        if (row->members[index].process == nullptr)
        {
            row->members[index].process = member; // adopts caller's retained reference
            ++row->member_count;
            ++row->total_processes;
            return JobAssignResult::Assigned;
        }
    }
    return JobAssignResult::Capacity;
}

bool JobContainsOwned(JobKey key, u64 owner_pid, const Process* member, bool* out_contains)
{
    if (member == nullptr || out_contains == nullptr)
        return false;
    *out_contains = false;

    sync::SpinLockGuard guard(g_job_lock);
    JobRow* row = ResolveOwnedLocked(key, owner_pid);
    if (row == nullptr)
        return false;
    *out_contains = ContainsLocked(*row, member);
    return true;
}

bool JobContainsAny(const Process* member)
{
    if (member == nullptr)
        return false;

    sync::SpinLockGuard guard(g_job_lock);
    for (u32 index = 0; index < kJobPoolCapacity; ++index)
    {
        const JobRow& row = g_job_pool[index];
        // Membership remains authoritative while a zero-reference
        // Terminating row is held alive by its operation pin.  Requiring a
        // public handle here would let null-handle membership queries deny
        // the same ownership that JobAssignRetained correctly treats as an
        // exclusive cross-Job conflict.
        if (IsExternallyVisibleState(row.state) && ContainsLocked(row, member))
            return true;
    }
    return false;
}

bool JobSnapshotOwned(JobKey key, u64 owner_pid, JobSnapshot* out_snapshot)
{
    if (out_snapshot == nullptr)
        return false;
    *out_snapshot = {};

    sync::SpinLockGuard guard(g_job_lock);
    JobRow* row = ResolveOwnedLocked(key, owner_pid);
    if (row == nullptr)
        return false;
    SnapshotLocked(*row, *out_snapshot);
    return true;
}

bool JobSnapshotContaining(const Process* member, JobSnapshot* out_snapshot)
{
    if (member == nullptr || out_snapshot == nullptr)
        return false;
    *out_snapshot = {};

    sync::SpinLockGuard guard(g_job_lock);
    for (u32 index = 0; index < kJobPoolCapacity; ++index)
    {
        const JobRow& row = g_job_pool[index];
        if (IsExternallyVisibleState(row.state) && ContainsLocked(row, member))
        {
            SnapshotLocked(row, *out_snapshot);
            return true;
        }
    }
    return false;
}

JobTerminateResult JobBeginTermination(JobKey key, u64 owner_pid, JobTerminationIntent* out_intent)
{
    if (out_intent == nullptr)
        return JobTerminateResult::InvalidJob;
    *out_intent = {};

    sync::SpinLockGuard guard(g_job_lock);
    JobRow* row = ResolveOwnedLocked(key, owner_pid);
    if (row == nullptr)
        return JobTerminateResult::InvalidJob;
    if (row->state == JobState::Terminating || row->state == JobState::Tombstone)
        return JobTerminateResult::AlreadyTerminated;

    row->state = JobState::Terminating;
    ++row->operation_pins;
    out_intent->key = key;
    for (u32 index = 0; index < kJobMemberCapacity; ++index)
    {
        Process* member = row->members[index].process;
        if (member != nullptr)
            out_intent->members[out_intent->member_count++] = member;
    }
    row->total_terminated_processes += out_intent->member_count;
    out_intent->active = true;
    return JobTerminateResult::Begun;
}

bool JobFinishTermination(JobTerminationIntent* intent)
{
    if (intent == nullptr || !intent->active)
        return false;

    Process* detached[kJobMemberCapacity]{};
    u32 detached_count = 0;
    {
        sync::SpinLockGuard guard(g_job_lock);
        JobRow* row = ResolveExactLocked(intent->key);
        if (row == nullptr || row->state != JobState::Terminating || row->operation_pins == 0)
            return false;

        row->state = JobState::Tombstone;
        --row->operation_pins;
        if (row->references == 0 || row->retire_pending)
            detached_count = RetireLocked(*row, detached);
    }

    intent->active = false;
    intent->member_count = 0;
    for (u32 index = 0; index < kJobMemberCapacity; ++index)
        intent->members[index] = nullptr;
    ReleaseDetached(detached, detached_count);
    return true;
}

bool JobClose(JobKey key, u64 owner_pid)
{
    Process* detached[kJobMemberCapacity]{};
    u32 detached_count = 0;
    bool found = false;
    {
        sync::SpinLockGuard guard(g_job_lock);
        JobRow* row = ResolveOwnedLocked(key, owner_pid);
        if (row != nullptr)
        {
            found = true;
            --row->references;
            if (row->references == 0)
            {
                row->retire_pending = true;
                if (row->state != JobState::Terminating && row->operation_pins == 0)
                {
                    if (row->state == JobState::Live)
                        row->state = JobState::Tombstone;
                    detached_count = RetireLocked(*row, detached);
                }
            }
        }
    }
    ReleaseDetached(detached, detached_count);
    return found;
}

void JobDrainOwned(u64 owner_pid)
{
    Process* detached[kJobPoolCapacity * kJobMemberCapacity]{};
    u32 detached_count = 0;
    {
        sync::SpinLockGuard guard(g_job_lock);
        for (u32 index = 0; index < kJobPoolCapacity; ++index)
        {
            JobRow& row = g_job_pool[index];
            if (!IsExternallyVisibleState(row.state) || row.owner_pid != owner_pid)
                continue;

            row.references = 0;
            row.retire_pending = true;
            if (row.state == JobState::Terminating || row.operation_pins != 0)
                continue;
            if (row.state == JobState::Live)
                row.state = JobState::Tombstone;
            detached_count += RetireLocked(row, &detached[detached_count]);
        }
    }
    ReleaseDetached(detached, detached_count);
}

bool JobInspectLifecycle(JobKey key, JobLifecycleSnapshot* out_snapshot)
{
    if (out_snapshot == nullptr)
        return false;
    *out_snapshot = {};

    sync::SpinLockGuard guard(g_job_lock);
    JobRow* row = ResolveExactLocked(key);
    if (row == nullptr)
        return false;
    out_snapshot->state = row->state;
    out_snapshot->generation = row->generation;
    out_snapshot->owner_pid = row->owner_pid;
    out_snapshot->references = row->references;
    out_snapshot->operation_pins = row->operation_pins;
    out_snapshot->member_count = row->member_count;
    out_snapshot->retire_pending = row->retire_pending;
    return true;
}

} // namespace duetos::core
