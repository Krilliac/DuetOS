#include "drivers/video/gui_send_transaction.h"

namespace duetos::drivers::video
{

namespace
{

bool ReservedBytesAreZero(const u8* bytes, u32 count)
{
    if (bytes == nullptr)
        return false;
    for (u32 index = 0; index < count; ++index)
    {
        if (bytes[index] != 0)
            return false;
    }
    return true;
}

bool PrincipalMatches(const GuiSendPrincipalSnapshot& lhs, const GuiSendPrincipalSnapshot& rhs)
{
    return lhs.endpoint_identity == rhs.endpoint_identity && lhs.process_identity == rhs.process_identity &&
           lhs.task_identity == rhs.task_identity;
}

bool TaskMatches(u64 process_identity, u64 task_identity, const GuiSendTaskIdentity& task)
{
    return process_identity == task.process_identity && task_identity == task.task_identity;
}

bool SameTask(u64 lhs_process, u64 lhs_task, u64 rhs_process, u64 rhs_task)
{
    return lhs_process == rhs_process && lhs_task == rhs_task;
}

bool PhaseIsActive(GuiSendTransactionPhase phase)
{
    switch (phase)
    {
    case GuiSendTransactionPhase::Pending:
    case GuiSendTransactionPhase::Dispatching:
    case GuiSendTransactionPhase::ReplyReady:
    case GuiSendTransactionPhase::Cancelled:
    case GuiSendTransactionPhase::TimedOut:
        return true;
    case GuiSendTransactionPhase::Vacant:
    case GuiSendTransactionPhase::Retired:
    case GuiSendTransactionPhase::GenerationExhausted:
        return false;
    }
    return false;
}

bool PhaseIsMutable(GuiSendTransactionPhase phase)
{
    return phase == GuiSendTransactionPhase::Pending || phase == GuiSendTransactionPhase::Dispatching;
}

bool PhaseIsTerminal(GuiSendTransactionPhase phase)
{
    return phase == GuiSendTransactionPhase::ReplyReady || phase == GuiSendTransactionPhase::Cancelled ||
           phase == GuiSendTransactionPhase::TimedOut;
}

bool InvalidIdentityIsCanonical(GuiSendCallIdentity identity)
{
    return identity == kInvalidGuiSendCallIdentity;
}

GuiSendCallIdentity IdentityFor(u32 slot, u64 generation)
{
    return GuiSendCallIdentity{slot, 0, generation};
}

} // namespace

bool GuiSendPrincipalSnapshotIsCanonical(const GuiSendPrincipalSnapshot& principal)
{
    return principal.endpoint_identity != 0 && principal.process_identity != 0 && principal.task_identity != 0 &&
           ReservedBytesAreZero(principal.reserved, 8);
}

bool GuiSendTaskIdentityIsCanonical(const GuiSendTaskIdentity& task)
{
    return task.process_identity != 0 && task.task_identity != 0;
}

bool GuiSendFrozenCallShapeIsCanonical(const GuiSendFrozenCall& call)
{
    if (call.sender_endpoint_identity == 0 || call.sender_process_identity == 0 || call.sender_task_identity == 0 ||
        call.target_process_identity == 0 || call.target_task_identity == 0 || call.target_window_identity == 0 ||
        call.policy_authority_identity == 0 || call.request_sequence == 0 || call.absolute_deadline == 0 ||
        call.message > 0xFFFFU || call.reentrancy_depth > kGuiSendMaximumReentrancyDepth ||
        !ReservedBytesAreZero(call.reserved, 3))
    {
        return false;
    }
    if (call.sender_task_identity == call.target_task_identity &&
        call.sender_process_identity != call.target_process_identity)
    {
        return false;
    }
    if (call.reentrancy_depth == 0)
        return InvalidIdentityIsCanonical(call.parent_call);
    return GuiSendCallIdentityIsValid(call.parent_call);
}

bool GuiSendDispatchTokenIsCanonical(const GuiSendDispatchToken& token)
{
    return GuiSendCallIdentityIsValid(token.call) && GuiSendPrincipalSnapshotIsCanonical(token.dispatcher) &&
           token.request_sequence != 0 && token.valid == 1 && ReservedBytesAreZero(token.reserved, 7);
}

GuiSendTransactionTable::Row* GuiSendTransactionTable::FindExactLocked(GuiSendCallIdentity identity)
{
    sync::SpinLockAssertHeld(m_lock);
    if (!GuiSendCallIdentityIsValid(identity))
        return nullptr;
    Row& row = m_rows[identity.slot];
    if (row.generation != identity.generation || row.phase == GuiSendTransactionPhase::Vacant ||
        row.phase == GuiSendTransactionPhase::GenerationExhausted)
    {
        return nullptr;
    }
    return &row;
}

const GuiSendTransactionTable::Row* GuiSendTransactionTable::FindExactLocked(GuiSendCallIdentity identity) const
{
    sync::SpinLockAssertHeld(m_lock);
    if (!GuiSendCallIdentityIsValid(identity))
        return nullptr;
    const Row& row = m_rows[identity.slot];
    if (row.generation != identity.generation || row.phase == GuiSendTransactionPhase::Vacant ||
        row.phase == GuiSendTransactionPhase::GenerationExhausted)
    {
        return nullptr;
    }
    return &row;
}

bool GuiSendTransactionTable::HasActiveChildLocked(GuiSendCallIdentity identity) const
{
    sync::SpinLockAssertHeld(m_lock);
    for (u32 slot = 0; slot < kGuiSendTransactionCapacity; ++slot)
    {
        const Row& row = m_rows[slot];
        if (PhaseIsActive(row.phase) && row.call.reentrancy_depth != 0 && row.call.parent_call == identity)
            return true;
    }
    return false;
}

bool GuiSendTransactionTable::ParentChainIsAvailableLocked(const GuiSendFrozenCall& call,
                                                           GuiSendBeginResult* out_error) const
{
    sync::SpinLockAssertHeld(m_lock);
    if (out_error == nullptr)
        return false;
    *out_error = GuiSendBeginResult::ParentUnavailable;
    if (call.reentrancy_depth == 0)
        return true;

    GuiSendCallIdentity current = call.parent_call;
    u8 expected_depth = static_cast<u8>(call.reentrancy_depth - 1U);
    const u32 call_depth = static_cast<u32>(call.reentrancy_depth);
    for (u32 level = 0; level < call_depth; ++level)
    {
        const Row* parent = FindExactLocked(current);
        if (parent == nullptr || parent->phase != GuiSendTransactionPhase::Dispatching)
            return false;
        if (parent->call.reentrancy_depth != expected_depth)
        {
            *out_error = GuiSendBeginResult::DepthMismatch;
            return false;
        }
        if (call.absolute_deadline > parent->call.absolute_deadline)
            return false;
        if (SameTask(call.target_process_identity, call.target_task_identity, parent->call.sender_process_identity,
                     parent->call.sender_task_identity) ||
            SameTask(call.target_process_identity, call.target_task_identity, parent->call.target_process_identity,
                     parent->call.target_task_identity))
        {
            *out_error = GuiSendBeginResult::Cycle;
            return false;
        }

        if (level == 0)
        {
            const GuiSendPrincipalSnapshot child_sender{
                call.sender_endpoint_identity, call.sender_process_identity, call.sender_task_identity, {}};
            if (!PrincipalMatches(parent->dispatcher, child_sender) || HasActiveChildLocked(current))
                return false;
        }

        if (expected_depth == 0)
        {
            if (!InvalidIdentityIsCanonical(parent->call.parent_call) || level + 1U != call_depth)
            {
                *out_error = GuiSendBeginResult::DepthMismatch;
                return false;
            }
            return true;
        }
        current = parent->call.parent_call;
        --expected_depth;
    }

    *out_error = GuiSendBeginResult::DepthMismatch;
    return false;
}

u32 GuiSendTransactionTable::CancelWithDescendantsLocked(GuiSendCallIdentity identity,
                                                         GuiSendTransactionPhase root_phase)
{
    sync::SpinLockAssertHeld(m_lock);
    if (root_phase != GuiSendTransactionPhase::Cancelled && root_phase != GuiSendTransactionPhase::TimedOut)
        return 0;

    Row* root = FindExactLocked(identity);
    if (root == nullptr || !PhaseIsMutable(root->phase))
        return 0;

    GuiSendCallIdentity frontier[kGuiSendTransactionCapacity]{};
    u32 frontier_count = 1;
    frontier[0] = identity;
    root->phase = root_phase;
    u32 transitioned = 1;

    for (u32 frontier_index = 0; frontier_index < frontier_count; ++frontier_index)
    {
        const GuiSendCallIdentity parent = frontier[frontier_index];
        for (u32 slot = 0; slot < kGuiSendTransactionCapacity; ++slot)
        {
            Row& row = m_rows[slot];
            if (!PhaseIsMutable(row.phase) || row.call.reentrancy_depth == 0 || row.call.parent_call != parent)
                continue;
            row.phase = GuiSendTransactionPhase::Cancelled;
            if (frontier_count < kGuiSendTransactionCapacity)
                frontier[frontier_count++] = IdentityFor(slot, row.generation);
            ++transitioned;
        }
    }
    return transitioned;
}

void GuiSendTransactionTable::RetireLocked(Row& row)
{
    sync::SpinLockAssertHeld(m_lock);
    const u64 generation = row.generation;
    row.call = {};
    row.dispatcher = {};
    row.reply_value = 0;
    row.generation = generation;
    row.phase = GuiSendTransactionPhase::Retired;
}

GuiSendBeginResult GuiSendTransactionTable::Begin(const GuiSendFrozenCall& call, u64 now,
                                                  GuiSendCallIdentity* out_identity)
{
    if (out_identity != nullptr)
        *out_identity = kInvalidGuiSendCallIdentity;
    if (out_identity == nullptr)
        return GuiSendBeginResult::Rejected;
    if (call.reentrancy_depth > kGuiSendMaximumReentrancyDepth ||
        (call.reentrancy_depth == 0 && !InvalidIdentityIsCanonical(call.parent_call)) ||
        (call.reentrancy_depth != 0 && !GuiSendCallIdentityIsValid(call.parent_call)))
    {
        return GuiSendBeginResult::DepthMismatch;
    }
    if (!GuiSendFrozenCallShapeIsCanonical(call))
        return GuiSendBeginResult::Rejected;
    if (now >= call.absolute_deadline)
        return GuiSendBeginResult::DeadlineElapsed;

    sync::SpinLockGuard guard(m_lock);
    GuiSendBeginResult parent_error = GuiSendBeginResult::ParentUnavailable;
    if (!ParentChainIsAvailableLocked(call, &parent_error))
        return parent_error;

    bool any_active = false;
    for (u32 slot = 0; slot < kGuiSendTransactionCapacity; ++slot)
    {
        const Row& row = m_rows[slot];
        if (!PhaseIsActive(row.phase))
            continue;
        any_active = true;
        if (row.call.sender_endpoint_identity == call.sender_endpoint_identity &&
            row.call.request_sequence == call.request_sequence)
        {
            return GuiSendBeginResult::DuplicateRequest;
        }
    }

    for (u32 slot = 0; slot < kGuiSendTransactionCapacity; ++slot)
    {
        Row& row = m_rows[slot];
        if (row.phase != GuiSendTransactionPhase::Vacant && row.phase != GuiSendTransactionPhase::Retired)
            continue;
        if (row.generation == kGuiSendGenerationMaximum)
        {
            row.phase = GuiSendTransactionPhase::GenerationExhausted;
            continue;
        }

        ++row.generation;
        row.call = call;
        row.dispatcher = {};
        row.reply_value = 0;
        row.phase = GuiSendTransactionPhase::Pending;
        *out_identity = IdentityFor(slot, row.generation);
        return GuiSendBeginResult::Created;
    }

    return any_active ? GuiSendBeginResult::TableFull : GuiSendBeginResult::GenerationExhausted;
}

GuiSendDispatchResult GuiSendTransactionTable::ClaimDispatch(GuiSendCallIdentity identity,
                                                             const GuiSendPrincipalSnapshot& dispatcher, u64 now,
                                                             GuiSendDispatchClaim* out_claim)
{
    if (out_claim != nullptr)
        *out_claim = {};
    if (out_claim == nullptr || !GuiSendCallIdentityIsValid(identity) ||
        !GuiSendPrincipalSnapshotIsCanonical(dispatcher))
    {
        return GuiSendDispatchResult::Rejected;
    }

    sync::SpinLockGuard guard(m_lock);
    Row* row = FindExactLocked(identity);
    if (row == nullptr || row->phase == GuiSendTransactionPhase::Retired)
        return GuiSendDispatchResult::Stale;
    if (row->call.target_process_identity != dispatcher.process_identity ||
        row->call.target_task_identity != dispatcher.task_identity)
    {
        return GuiSendDispatchResult::WrongPrincipal;
    }
    if (row->phase != GuiSendTransactionPhase::Pending)
        return GuiSendDispatchResult::NotPending;
    if (now >= row->call.absolute_deadline)
    {
        (void)CancelWithDescendantsLocked(identity, GuiSendTransactionPhase::TimedOut);
        return GuiSendDispatchResult::TimedOut;
    }

    row->dispatcher = dispatcher;
    row->phase = GuiSendTransactionPhase::Dispatching;
    out_claim->call = row->call;
    out_claim->token.call = identity;
    out_claim->token.dispatcher = dispatcher;
    out_claim->token.request_sequence = row->call.request_sequence;
    out_claim->token.valid = 1;
    return GuiSendDispatchResult::Claimed;
}

GuiSendReplyResult GuiSendTransactionTable::CommitReply(const GuiSendDispatchToken& token,
                                                        const GuiSendPrincipalSnapshot& dispatcher, u64 completed_at,
                                                        u64 reply_value)
{
    if (!GuiSendDispatchTokenIsCanonical(token) || !GuiSendPrincipalSnapshotIsCanonical(dispatcher))
        return GuiSendReplyResult::Rejected;

    sync::SpinLockGuard guard(m_lock);
    Row* row = FindExactLocked(token.call);
    if (row == nullptr || row->phase == GuiSendTransactionPhase::Retired)
        return GuiSendReplyResult::Stale;
    if (row->phase == GuiSendTransactionPhase::Pending)
        return GuiSendReplyResult::WrongClaim;
    if (!GuiSendPrincipalSnapshotIsCanonical(row->dispatcher))
        return GuiSendReplyResult::Terminal;
    if (!PrincipalMatches(row->dispatcher, dispatcher))
        return GuiSendReplyResult::WrongPrincipal;
    if (!PrincipalMatches(row->dispatcher, token.dispatcher) || row->call.request_sequence != token.request_sequence)
    {
        return GuiSendReplyResult::WrongClaim;
    }
    if (row->phase != GuiSendTransactionPhase::Dispatching)
        return GuiSendReplyResult::Terminal;
    if (completed_at >= row->call.absolute_deadline)
    {
        (void)CancelWithDescendantsLocked(token.call, GuiSendTransactionPhase::TimedOut);
        return GuiSendReplyResult::TimedOut;
    }
    if (HasActiveChildLocked(token.call))
        return GuiSendReplyResult::ActiveChild;

    row->reply_value = reply_value;
    row->phase = GuiSendTransactionPhase::ReplyReady;
    return GuiSendReplyResult::Committed;
}

GuiSendCancelResult GuiSendTransactionTable::CancelByCaller(GuiSendCallIdentity identity,
                                                            const GuiSendPrincipalSnapshot& caller)
{
    if (!GuiSendCallIdentityIsValid(identity) || !GuiSendPrincipalSnapshotIsCanonical(caller))
        return GuiSendCancelResult::Rejected;

    sync::SpinLockGuard guard(m_lock);
    Row* row = FindExactLocked(identity);
    if (row == nullptr || row->phase == GuiSendTransactionPhase::Retired)
        return GuiSendCancelResult::Stale;
    const GuiSendPrincipalSnapshot frozen_sender{
        row->call.sender_endpoint_identity, row->call.sender_process_identity, row->call.sender_task_identity, {}};
    if (!PrincipalMatches(frozen_sender, caller))
        return GuiSendCancelResult::WrongPrincipal;
    if (!PhaseIsMutable(row->phase))
        return GuiSendCancelResult::TooLate;
    (void)CancelWithDescendantsLocked(identity, GuiSendTransactionPhase::Cancelled);
    return GuiSendCancelResult::Cancelled;
}

GuiSendTimeoutResult GuiSendTransactionTable::TimeoutAt(GuiSendCallIdentity identity, u64 now)
{
    if (!GuiSendCallIdentityIsValid(identity))
        return GuiSendTimeoutResult::Rejected;

    sync::SpinLockGuard guard(m_lock);
    Row* row = FindExactLocked(identity);
    if (row == nullptr || row->phase == GuiSendTransactionPhase::Retired)
        return GuiSendTimeoutResult::Stale;
    if (!PhaseIsMutable(row->phase))
        return GuiSendTimeoutResult::TooLate;
    if (now < row->call.absolute_deadline)
        return GuiSendTimeoutResult::NotDue;
    (void)CancelWithDescendantsLocked(identity, GuiSendTransactionPhase::TimedOut);
    return GuiSendTimeoutResult::TimedOut;
}

u32 GuiSendTransactionTable::CancelCallerDeath(const GuiSendPrincipalSnapshot& caller)
{
    if (!GuiSendPrincipalSnapshotIsCanonical(caller))
        return 0;

    sync::SpinLockGuard guard(m_lock);
    u32 transitioned = 0;
    for (u32 slot = 0; slot < kGuiSendTransactionCapacity; ++slot)
    {
        Row& row = m_rows[slot];
        if (!PhaseIsMutable(row.phase) || row.call.sender_endpoint_identity != caller.endpoint_identity ||
            row.call.sender_process_identity != caller.process_identity ||
            row.call.sender_task_identity != caller.task_identity)
        {
            continue;
        }
        transitioned +=
            CancelWithDescendantsLocked(IdentityFor(slot, row.generation), GuiSendTransactionPhase::Cancelled);
    }
    return transitioned;
}

u32 GuiSendTransactionTable::CancelTargetDeath(const GuiSendTaskIdentity& target)
{
    if (!GuiSendTaskIdentityIsCanonical(target))
        return 0;

    sync::SpinLockGuard guard(m_lock);
    u32 transitioned = 0;
    for (u32 slot = 0; slot < kGuiSendTransactionCapacity; ++slot)
    {
        Row& row = m_rows[slot];
        if (!PhaseIsMutable(row.phase) ||
            !TaskMatches(row.call.target_process_identity, row.call.target_task_identity, target))
        {
            continue;
        }
        transitioned +=
            CancelWithDescendantsLocked(IdentityFor(slot, row.generation), GuiSendTransactionPhase::Cancelled);
    }
    return transitioned;
}

GuiSendConsumeResult GuiSendTransactionTable::Consume(GuiSendCallIdentity identity,
                                                      const GuiSendPrincipalSnapshot& caller,
                                                      GuiSendCompletion* out_completion)
{
    if (out_completion != nullptr)
        *out_completion = {};
    if (out_completion == nullptr || !GuiSendCallIdentityIsValid(identity) ||
        !GuiSendPrincipalSnapshotIsCanonical(caller))
    {
        return GuiSendConsumeResult::Rejected;
    }

    sync::SpinLockGuard guard(m_lock);
    Row* row = FindExactLocked(identity);
    if (row == nullptr || row->phase == GuiSendTransactionPhase::Retired)
        return GuiSendConsumeResult::Stale;
    const GuiSendPrincipalSnapshot frozen_sender{
        row->call.sender_endpoint_identity, row->call.sender_process_identity, row->call.sender_task_identity, {}};
    if (!PrincipalMatches(frozen_sender, caller))
        return GuiSendConsumeResult::WrongPrincipal;
    if (!PhaseIsTerminal(row->phase))
        return GuiSendConsumeResult::NotReady;

    out_completion->call = identity;
    out_completion->phase = row->phase;
    out_completion->valid = 1;
    out_completion->request_sequence = row->call.request_sequence;
    out_completion->reply_value = row->phase == GuiSendTransactionPhase::ReplyReady ? row->reply_value : 0;
    RetireLocked(*row);
    return GuiSendConsumeResult::Consumed;
}

GuiSendRetireResult GuiSendTransactionTable::RetireAbandoned(GuiSendCallIdentity identity)
{
    if (!GuiSendCallIdentityIsValid(identity))
        return GuiSendRetireResult::Rejected;

    sync::SpinLockGuard guard(m_lock);
    Row* row = FindExactLocked(identity);
    if (row == nullptr || row->phase == GuiSendTransactionPhase::Retired)
        return GuiSendRetireResult::Stale;
    if (!PhaseIsTerminal(row->phase))
        return GuiSendRetireResult::NotTerminal;
    RetireLocked(*row);
    return GuiSendRetireResult::Retired;
}

bool GuiSendTransactionTable::Inspect(GuiSendCallIdentity identity, GuiSendTransactionSnapshot* out_snapshot)
{
    if (out_snapshot != nullptr)
        *out_snapshot = {};
    if (out_snapshot == nullptr || !GuiSendCallIdentityIsValid(identity))
        return false;

    sync::SpinLockGuard guard(m_lock);
    const Row* row = FindExactLocked(identity);
    if (row == nullptr)
        return false;
    out_snapshot->identity = identity;
    out_snapshot->phase = row->phase;
    out_snapshot->valid = 1;
    out_snapshot->call = row->call;
    out_snapshot->dispatcher = row->dispatcher;
    out_snapshot->reply_value = row->reply_value;
    return true;
}

u32 GuiSendTransactionTable::ActiveCount()
{
    sync::SpinLockGuard guard(m_lock);
    u32 active = 0;
    for (u32 slot = 0; slot < kGuiSendTransactionCapacity; ++slot)
    {
        if (PhaseIsActive(m_rows[slot].phase))
            ++active;
    }
    return active;
}

#if defined(DUETOS_HOST_TEST)
bool GuiSendTransactionTable::HostPositionInactiveGeneration(u32 slot, u64 generation)
{
    if (slot >= kGuiSendTransactionCapacity)
        return false;
    sync::SpinLockGuard guard(m_lock);
    Row& row = m_rows[slot];
    if (PhaseIsActive(row.phase))
        return false;
    row = {};
    row.generation = generation;
    row.phase = generation == 0 ? GuiSendTransactionPhase::Vacant : GuiSendTransactionPhase::Retired;
    return true;
}

sync::LockClass GuiSendTransactionTable::HostTransactionLockClass() const
{
    return m_lock.class_id;
}
#endif

} // namespace duetos::drivers::video
