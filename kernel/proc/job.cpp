/*
 * Protocol-neutral process Job service.
 *
 * State machine (under g_job_lock):
 *
 *   Retired -> Reserved -> Live -> Terminating -> Tombstone -> Retired
 *                            \--------------------^            ^
 *                             close / owner drain --------------/
 *
 * Reserved and pending child members are never externally visible.
 * Publication and termination tickets own operation pins, so a concurrent
 * last-close or owner drain cannot recycle the row. Termination dispatch only
 * consumes its pin: the last member exit owns the Tombstone transition.
 * Member rows never retain ProcessCore.
 */

#include "proc/job.h"

#include "core/panic.h"
#include "proc/process.h"
#include "sync/spinlock.h"

namespace duetos::core
{

namespace
{

enum class JobMemberState : u8
{
    Empty = 0,
    PendingPublication,
    Active,
};

struct JobMember
{
    ProcessKey process;
    JobMemberState state;
    u64 publication_ticket;
};

struct JobRow
{
    JobState state;
    u64 generation;
    ProcessKey owner;
    u64 active_process_limit;
    u64 cpu_seconds_limit;
    u32 references;
    u32 operation_pins;
    u32 member_count;
    u32 pending_member_count;
    u32 total_processes;
    u32 total_terminated_processes;
    u64 termination_ticket;
    bool retire_pending;
    JobMember members[kJobMemberCapacity];
};

JobRow g_job_pool[kJobPoolCapacity]{};
sync::SpinLock g_job_lock{};
u64 g_next_job_ticket = 1;

u64 MintTicketLocked()
{
    if (g_next_job_ticket == 0 || g_next_job_ticket == ~u64{0})
        return 0;
    return g_next_job_ticket++;
}

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

JobRow* ResolveOwnedLocked(JobKey key, ProcessKey owner)
{
    JobRow* row = ResolveExactLocked(key);
    if (row == nullptr || row->references == 0 || !IsExternallyVisibleState(row->state) || !(row->owner == owner))
    {
        return nullptr;
    }
    return row;
}

bool ContainsActiveLocked(const JobRow& row, ProcessKey member)
{
    for (u32 index = 0; index < kJobMemberCapacity; ++index)
    {
        if (row.members[index].process == member && row.members[index].state == JobMemberState::Active)
            return true;
    }
    return false;
}

bool ContainsHeldLocked(const JobRow& row, ProcessKey member)
{
    for (u32 index = 0; index < kJobMemberCapacity; ++index)
    {
        if (row.members[index].process == member && row.members[index].state != JobMemberState::Empty)
            return true;
    }
    return false;
}

void ClearMember(JobMember& member)
{
    member.process = kInvalidProcessKey;
    member.state = JobMemberState::Empty;
    member.publication_ticket = 0;
}

void SnapshotLocked(const JobRow& row, JobSnapshot& snapshot)
{
    snapshot.member_count = row.member_count;
    snapshot.process_id_count = 0;
    snapshot.total_processes = row.total_processes;
    snapshot.total_terminated_processes = row.total_terminated_processes;
    for (u32 index = 0; index < kJobMemberCapacity; ++index)
    {
        const JobMember& entry = row.members[index];
        if (ProcessKeyIsValid(entry.process) && entry.state == JobMemberState::Active)
            snapshot.member_pids[snapshot.process_id_count++] = entry.process.pid;
    }
}

void ClearMembersLocked(JobRow& row)
{
    for (u32 index = 0; index < kJobMemberCapacity; ++index)
        ClearMember(row.members[index]);
    row.member_count = 0;
    row.pending_member_count = 0;
}

void RetireLocked(JobRow& row)
{
    KASSERT(row.state != JobState::Terminating && row.operation_pins == 0 && row.member_count == 0 &&
                row.pending_member_count == 0,
            "core/job", "retired Job still owns membership or an operation pin");

    ClearMembersLocked(row);
    row.owner = kInvalidProcessKey;
    row.active_process_limit = 0;
    row.cpu_seconds_limit = 0;
    row.references = 0;
    row.operation_pins = 0;
    row.termination_ticket = 0;
    row.total_processes = 0;
    row.total_terminated_processes = 0;
    row.retire_pending = false;
    row.state = JobState::Retired;
}

void MaybeCompleteAndRetireLocked(JobRow& row)
{
    if (row.state == JobState::Terminating && row.member_count == 0 && row.pending_member_count == 0 &&
        row.operation_pins == 0)
    {
        row.state = JobState::Tombstone;
    }

    if (row.references != 0 || row.operation_pins != 0 || row.member_count != 0 || row.pending_member_count != 0)
        return;

    if (row.state == JobState::Live)
        row.state = JobState::Tombstone;
    if (row.state == JobState::Tombstone)
        RetireLocked(row);
}

void ResetPublicationTicket(JobPublicationTicket& ticket)
{
    ticket.key = {};
    ticket.process = kInvalidProcessKey;
    ticket.ticket = 0;
    ticket.member_slot = 0;
    ticket.active = false;
}

void ResetTerminationIntent(JobTerminationIntent& intent)
{
    intent.key = {};
    intent.ticket = 0;
    intent.member_count = 0;
    intent.exit_code = 0;
    intent.active = false;
    for (u32 index = 0; index < kJobMemberCapacity; ++index)
        intent.members[index] = kInvalidProcessKey;
}

} // namespace

bool JobCreate(ProcessKey owner, JobKey* out_key)
{
    if (out_key == nullptr || !ProcessKeyIsValid(owner))
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
        row.owner = owner;
        row.active_process_limit = 0;
        row.cpu_seconds_limit = 0;
        row.references = 1;
        row.operation_pins = 0;
        row.member_count = 0;
        row.pending_member_count = 0;
        row.total_processes = 0;
        row.total_terminated_processes = 0;
        row.termination_ticket = 0;
        row.retire_pending = false;
        for (u32 member = 0; member < kJobMemberCapacity; ++member)
            ClearMember(row.members[member]);
        row.state = JobState::Live;

        out_key->slot = index;
        out_key->generation = row.generation;
        return true;
    }
    return false;
}

JobAssignResult JobAssign(JobKey key, ProcessKey owner, ProcessKey member)
{
    if (!ProcessKeyIsValid(owner) || !ProcessKeyIsValid(member))
        return JobAssignResult::InvalidJob;

    sync::SpinLockGuard guard(g_job_lock);
    JobRow* row = ResolveOwnedLocked(key, owner);
    if (row == nullptr)
        return JobAssignResult::InvalidJob;
    if (row->state != JobState::Live)
        return JobAssignResult::Terminated;

    if (ContainsActiveLocked(*row, member))
        return JobAssignResult::AlreadyMember;
    if (ContainsHeldLocked(*row, member))
        return JobAssignResult::MembershipConflict;

    // Membership is globally exclusive for one exact Process incarnation.
    // Keep zero-reference Terminating rows in this scan: their operation pin
    // still owns a copied termination intent and admitting the same identity
    // elsewhere would make policy ownership ambiguous.
    for (u32 index = 0; index < kJobPoolCapacity; ++index)
    {
        const JobRow& other = g_job_pool[index];
        if (&other != row && IsExternallyVisibleState(other.state) && ContainsHeldLocked(other, member))
            return JobAssignResult::MembershipConflict;
    }

    if (row->active_process_limit != 0 && row->member_count + row->pending_member_count >= row->active_process_limit)
        return JobAssignResult::Capacity;

    for (u32 index = 0; index < kJobMemberCapacity; ++index)
    {
        if (row->members[index].state == JobMemberState::Empty)
        {
            row->members[index].process = member;
            row->members[index].state = JobMemberState::Active;
            row->members[index].publication_ticket = 0;
            ++row->member_count;
            ++row->total_processes;
            return JobAssignResult::Assigned;
        }
    }
    return JobAssignResult::Capacity;
}

JobPublishPrepareResult JobPrepareInheritedMember(ProcessKey parent, ProcessKey child,
                                                  JobPublicationTicket* out_ticket)
{
    if (out_ticket == nullptr)
        return JobPublishPrepareResult::Invalid;
    ResetPublicationTicket(*out_ticket);
    if (!ProcessKeyIsValid(parent) || !ProcessKeyIsValid(child) || parent == child)
        return JobPublishPrepareResult::Invalid;

    sync::SpinLockGuard guard(g_job_lock);
    JobRow* parent_row = nullptr;
    u32 parent_slot = 0;
    for (u32 index = 0; index < kJobPoolCapacity; ++index)
    {
        JobRow& row = g_job_pool[index];
        if (IsExternallyVisibleState(row.state) && ContainsActiveLocked(row, parent))
        {
            parent_row = &row;
            parent_slot = index;
            break;
        }
    }
    if (parent_row == nullptr)
        return JobPublishPrepareResult::NoParentJob;
    if (parent_row->state != JobState::Live)
        return JobPublishPrepareResult::Terminated;

    // Active and hidden-pending identities are globally exclusive. Exited
    // identities are cleared at the scheduler-linearized last-task boundary,
    // so stale retained Process headers cannot consume a slot here.
    for (u32 index = 0; index < kJobPoolCapacity; ++index)
    {
        if (IsExternallyVisibleState(g_job_pool[index].state) && ContainsHeldLocked(g_job_pool[index], child))
            return JobPublishPrepareResult::MembershipConflict;
    }

    if (parent_row->active_process_limit != 0 &&
        parent_row->member_count + parent_row->pending_member_count >= parent_row->active_process_limit)
    {
        return JobPublishPrepareResult::Capacity;
    }

    u32 member_slot = kJobMemberCapacity;
    for (u32 index = 0; index < kJobMemberCapacity; ++index)
    {
        if (parent_row->members[index].state == JobMemberState::Empty)
        {
            member_slot = index;
            break;
        }
    }
    if (member_slot == kJobMemberCapacity)
        return JobPublishPrepareResult::Capacity;

    const u64 ticket = MintTicketLocked();
    if (ticket == 0)
        return JobPublishPrepareResult::Capacity;

    JobMember& pending = parent_row->members[member_slot];
    pending.process = child;
    pending.state = JobMemberState::PendingPublication;
    pending.publication_ticket = ticket;
    ++parent_row->pending_member_count;
    ++parent_row->operation_pins;

    out_ticket->key = JobKey{parent_slot, parent_row->generation};
    out_ticket->process = child;
    out_ticket->ticket = ticket;
    out_ticket->member_slot = member_slot;
    out_ticket->active = true;
    return JobPublishPrepareResult::Prepared;
}

bool JobCommitInheritedMember(JobPublicationTicket* ticket)
{
    if (ticket == nullptr || !ticket->active || ticket->member_slot >= kJobMemberCapacity ||
        ticket->ticket == 0 || !ProcessKeyIsValid(ticket->process))
    {
        return false;
    }

    {
        sync::SpinLockGuard guard(g_job_lock);
        JobRow* row = ResolveExactLocked(ticket->key);
        if (row == nullptr || row->state != JobState::Live || row->operation_pins == 0 ||
            row->pending_member_count == 0)
        {
            return false;
        }
        JobMember& pending = row->members[ticket->member_slot];
        if (pending.state != JobMemberState::PendingPublication || !(pending.process == ticket->process) ||
            pending.publication_ticket != ticket->ticket)
        {
            return false;
        }

        pending.state = JobMemberState::Active;
        pending.publication_ticket = 0;
        --row->pending_member_count;
        --row->operation_pins;
        ++row->member_count;
        ++row->total_processes;
        MaybeCompleteAndRetireLocked(*row);
    }

    ResetPublicationTicket(*ticket);
    return true;
}

bool JobAbortInheritedMember(JobPublicationTicket* ticket)
{
    if (ticket == nullptr || !ticket->active || ticket->member_slot >= kJobMemberCapacity ||
        ticket->ticket == 0 || !ProcessKeyIsValid(ticket->process))
    {
        return false;
    }

    {
        sync::SpinLockGuard guard(g_job_lock);
        JobRow* row = ResolveExactLocked(ticket->key);
        if (row == nullptr || row->operation_pins == 0 || row->pending_member_count == 0)
            return false;
        JobMember& pending = row->members[ticket->member_slot];
        if (pending.state != JobMemberState::PendingPublication || !(pending.process == ticket->process) ||
            pending.publication_ticket != ticket->ticket)
        {
            return false;
        }

        ClearMember(pending);
        --row->pending_member_count;
        --row->operation_pins;
        MaybeCompleteAndRetireLocked(*row);
    }

    ResetPublicationTicket(*ticket);
    return true;
}

bool JobContainsOwned(JobKey key, ProcessKey owner, ProcessKey member, bool* out_contains)
{
    if (!ProcessKeyIsValid(owner) || !ProcessKeyIsValid(member) || out_contains == nullptr)
        return false;
    *out_contains = false;

    sync::SpinLockGuard guard(g_job_lock);
    JobRow* row = ResolveOwnedLocked(key, owner);
    if (row == nullptr)
        return false;
    *out_contains = ContainsActiveLocked(*row, member);
    return true;
}

bool JobContainsAny(ProcessKey member)
{
    if (!ProcessKeyIsValid(member))
        return false;

    sync::SpinLockGuard guard(g_job_lock);
    for (u32 index = 0; index < kJobPoolCapacity; ++index)
    {
        const JobRow& row = g_job_pool[index];
        // Membership remains authoritative while a zero-reference
        // Terminating row is held alive by its operation pin. Requiring a
        // public handle here would disagree with JobAssign's exclusive
        // cross-Job policy.
        if (IsExternallyVisibleState(row.state) && ContainsActiveLocked(row, member))
            return true;
    }
    return false;
}

bool JobSnapshotOwned(JobKey key, ProcessKey owner, JobSnapshot* out_snapshot)
{
    if (!ProcessKeyIsValid(owner) || out_snapshot == nullptr)
        return false;
    *out_snapshot = {};

    sync::SpinLockGuard guard(g_job_lock);
    JobRow* row = ResolveOwnedLocked(key, owner);
    if (row == nullptr)
        return false;
    SnapshotLocked(*row, *out_snapshot);
    return true;
}

bool JobSnapshotContaining(ProcessKey member, JobSnapshot* out_snapshot)
{
    if (!ProcessKeyIsValid(member) || out_snapshot == nullptr)
        return false;
    *out_snapshot = {};

    sync::SpinLockGuard guard(g_job_lock);
    for (u32 index = 0; index < kJobPoolCapacity; ++index)
    {
        const JobRow& row = g_job_pool[index];
        if (IsExternallyVisibleState(row.state) && ContainsActiveLocked(row, member))
        {
            SnapshotLocked(row, *out_snapshot);
            return true;
        }
    }
    return false;
}

JobTerminateResult JobBeginTermination(JobKey key, ProcessKey owner, u32 exit_code,
                                       JobTerminationIntent* out_intent)
{
    if (!ProcessKeyIsValid(owner) || out_intent == nullptr)
        return JobTerminateResult::InvalidJob;
    ResetTerminationIntent(*out_intent);

    sync::SpinLockGuard guard(g_job_lock);
    JobRow* row = ResolveOwnedLocked(key, owner);
    if (row == nullptr)
        return JobTerminateResult::InvalidJob;
    if (row->state == JobState::Terminating || row->state == JobState::Tombstone)
        return JobTerminateResult::AlreadyTerminated;

    // Scheduler publication holds the outer lifetime lock, so a legitimate
    // termination cannot meet a hidden member transaction. Refuse rather than
    // turning a private child into an escape from a terminating Job.
    if (row->pending_member_count != 0 || row->operation_pins != 0)
        return JobTerminateResult::InvalidJob;

    const u64 ticket = MintTicketLocked();
    if (ticket == 0)
        return JobTerminateResult::InvalidJob;

    row->state = JobState::Terminating;
    ++row->operation_pins;
    row->termination_ticket = ticket;
    out_intent->key = key;
    out_intent->ticket = ticket;
    out_intent->exit_code = exit_code;
    for (u32 index = 0; index < kJobMemberCapacity; ++index)
    {
        const JobMember& entry = row->members[index];
        if (ProcessKeyIsValid(entry.process) && entry.state == JobMemberState::Active)
            out_intent->members[out_intent->member_count++] = entry.process;
    }
    // JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::TotalTerminatedProcesses is
    // reserved for future limit/policy enforcement. An explicit
    // TerminateJobObject request does not increment it.
    out_intent->active = true;
    return JobTerminateResult::Begun;
}

bool JobFinishTermination(JobTerminationIntent* intent)
{
    if (intent == nullptr || !intent->active)
        return false;

    {
        sync::SpinLockGuard guard(g_job_lock);
        JobRow* row = ResolveExactLocked(intent->key);
        if (row == nullptr || row->state != JobState::Terminating || row->operation_pins == 0 ||
            row->termination_ticket == 0 || row->termination_ticket != intent->ticket)
            return false;

        row->termination_ticket = 0;
        --row->operation_pins;
        MaybeCompleteAndRetireLocked(*row);
    }

    ResetTerminationIntent(*intent);
    return true;
}

void JobOnProcessExit(ProcessKey process)
{
    if (!ProcessKeyIsValid(process))
        return;

    sync::SpinLockGuard guard(g_job_lock);
    for (u32 row_index = 0; row_index < kJobPoolCapacity; ++row_index)
    {
        JobRow& row = g_job_pool[row_index];
        if (!IsExternallyVisibleState(row.state))
            continue;

        for (u32 member_index = 0; member_index < kJobMemberCapacity; ++member_index)
        {
            JobMember& entry = row.members[member_index];
            if (!(entry.process == process) || entry.state != JobMemberState::Active)
                continue;

            ClearMember(entry);
            --row.member_count;
            MaybeCompleteAndRetireLocked(row);
            // Exact ProcessKeys are globally exclusive, so at most one row
            // can consume the notification.
            return;
        }
    }
}

bool JobClose(JobKey key, ProcessKey owner)
{
    if (!ProcessKeyIsValid(owner))
        return false;

    bool found = false;
    {
        sync::SpinLockGuard guard(g_job_lock);
        JobRow* row = ResolveOwnedLocked(key, owner);
        if (row != nullptr)
        {
            found = true;
            --row->references;
            if (row->references == 0)
            {
                row->retire_pending = true;
                MaybeCompleteAndRetireLocked(*row);
            }
        }
    }
    return found;
}

void JobDrainOwned(ProcessKey owner)
{
    if (!ProcessKeyIsValid(owner))
        return;

    sync::SpinLockGuard guard(g_job_lock);
    for (u32 index = 0; index < kJobPoolCapacity; ++index)
    {
        JobRow& row = g_job_pool[index];
        if (!IsExternallyVisibleState(row.state) || !(row.owner == owner))
            continue;

        row.references = 0;
        row.retire_pending = true;
        MaybeCompleteAndRetireLocked(row);
    }
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
    out_snapshot->owner = row->owner;
    out_snapshot->references = row->references;
    out_snapshot->operation_pins = row->operation_pins;
    out_snapshot->member_count = row->member_count;
    out_snapshot->pending_member_count = row->pending_member_count;
    out_snapshot->retire_pending = row->retire_pending;
    return true;
}

} // namespace duetos::core
