#include "drivers/video/gui_send_service.h"

#if defined(DUETOS_HOST_TEST)
#include <atomic>
#endif

namespace duetos::drivers::video
{

namespace
{

constexpr u64 kU64Maximum = static_cast<u64>(-1);
u64 g_next_gui_send_service_incarnation = 1;

u64 AtomicLoadServiceIncarnation(u64* value)
{
#if defined(DUETOS_HOST_TEST)
    return std::atomic_ref<u64>(*value).load(std::memory_order_relaxed);
#else
    return __atomic_load_n(value, __ATOMIC_RELAXED);
#endif
}

bool AtomicCompareExchangeServiceIncarnation(u64* value, u64* expected, u64 desired)
{
#if defined(DUETOS_HOST_TEST)
    return std::atomic_ref<u64>(*value).compare_exchange_weak(*expected, desired, std::memory_order_relaxed,
                                                              std::memory_order_relaxed);
#else
    return __atomic_compare_exchange_n(value, expected, desired, true, __ATOMIC_RELAXED, __ATOMIC_RELAXED);
#endif
}

u64 MintServiceIncarnation()
{
    u64 current = AtomicLoadServiceIncarnation(&g_next_gui_send_service_incarnation);
    while (current != kU64Maximum)
    {
        u64 expected = current;
        if (AtomicCompareExchangeServiceIncarnation(&g_next_gui_send_service_incarnation, &expected, current + 1))
            return current;
        current = expected;
    }
    return 0;
}

bool ServiceReservedBytesAreZero(const u8* bytes, u32 count)
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

bool ServicePhaseIsMutable(GuiSendTransactionPhase phase)
{
    return phase == GuiSendTransactionPhase::Pending || phase == GuiSendTransactionPhase::Dispatching;
}

bool ServicePrincipalsEqual(const GuiSendPrincipalSnapshot& lhs, const GuiSendPrincipalSnapshot& rhs)
{
    return lhs.endpoint_identity == rhs.endpoint_identity && lhs.process_identity == rhs.process_identity &&
           lhs.task_identity == rhs.task_identity;
}

bool ServiceDispatchTokensEqual(const GuiSendServiceDispatchToken& lhs, const GuiSendServiceDispatchToken& rhs)
{
    return lhs.service_incarnation == rhs.service_incarnation && lhs.transaction.call == rhs.transaction.call &&
           ServicePrincipalsEqual(lhs.transaction.dispatcher, rhs.transaction.dispatcher) &&
           lhs.transaction.request_sequence == rhs.transaction.request_sequence &&
           lhs.transaction.valid == rhs.transaction.valid;
}

} // namespace

GuiSendService::GuiSendService() : m_service_incarnation(MintServiceIncarnation()) {}

GuiSendService::EndpointRow* GuiSendService::ResolveEndpointLocked(GuiSendTaskEndpointIdentity endpoint)
{
    sync::SpinLockAssertHeld(m_lock);
    if (endpoint.service_incarnation != m_service_incarnation)
        return nullptr;
    const u32 slot = GuiSendTaskEndpointSlot(endpoint);
    if (slot >= kGuiSendServiceEndpointCapacity)
        return nullptr;
    EndpointRow& row = m_endpoints[slot];
    if (!row.active || row.retired || row.generation != GuiSendTaskEndpointGeneration(endpoint))
        return nullptr;
    return &row;
}

const GuiSendService::EndpointRow* GuiSendService::ResolveEndpointLocked(GuiSendTaskEndpointIdentity endpoint) const
{
    sync::SpinLockAssertHeld(m_lock);
    if (endpoint.service_incarnation != m_service_incarnation)
        return nullptr;
    const u32 slot = GuiSendTaskEndpointSlot(endpoint);
    if (slot >= kGuiSendServiceEndpointCapacity)
        return nullptr;
    const EndpointRow& row = m_endpoints[slot];
    if (!row.active || row.retired || row.generation != GuiSendTaskEndpointGeneration(endpoint))
        return nullptr;
    return &row;
}

GuiSendService::CallRow* GuiSendService::ResolveCallLocked(GuiSendServiceCallIdentity call)
{
    sync::SpinLockAssertHeld(m_lock);
    if (!GuiSendServiceCallIdentityIsCanonical(call) || call.service_incarnation != m_service_incarnation)
        return nullptr;
    CallRow& row = m_calls[call.slot];
    if (!row.active || row.call != call)
        return nullptr;
    return &row;
}

const GuiSendService::CallRow* GuiSendService::ResolveCallLocked(GuiSendServiceCallIdentity call) const
{
    sync::SpinLockAssertHeld(m_lock);
    if (!GuiSendServiceCallIdentityIsCanonical(call) || call.service_incarnation != m_service_incarnation)
        return nullptr;
    const CallRow& row = m_calls[call.slot];
    if (!row.active || row.call != call)
        return nullptr;
    return &row;
}

GuiSendPrincipalSnapshot GuiSendService::PrincipalLocked(GuiSendTaskEndpointIdentity endpoint,
                                                         const EndpointRow& row) const
{
    sync::SpinLockAssertHeld(m_lock);
    GuiSendPrincipalSnapshot principal{};
    principal.endpoint_identity = endpoint.value;
    principal.process_identity = row.process_identity;
    principal.task_identity = row.task_identity;
    return principal;
}

GuiSendTaskEndpointIdentity GuiSendService::IdentityForEndpointLocked(u32 slot, const EndpointRow& row) const
{
    sync::SpinLockAssertHeld(m_lock);
    if (slot >= kGuiSendServiceEndpointCapacity || row.generation == 0 ||
        row.generation > kGuiSendEndpointGenerationMaximum)
    {
        return kInvalidGuiSendTaskEndpoint;
    }
    return GuiSendTaskEndpointIdentity{m_service_incarnation,
                                       (row.generation << kGuiSendEndpointSlotBits) | (static_cast<u64>(slot) + 1ULL)};
}

bool GuiSendService::AllocateFifoTicketLocked(u64* out_ticket)
{
    sync::SpinLockAssertHeld(m_lock);
    if (out_ticket == nullptr)
        return false;
    *out_ticket = 0;

    if (m_next_fifo_ticket == 0)
    {
        for (u32 slot = 0; slot < kGuiSendTransactionCapacity; ++slot)
        {
            const CallRow& row = m_calls[slot];
            if (row.active &&
                (row.state == GuiSendServiceCallState::Queued || row.state == GuiSendServiceCallState::Dispatching))
            {
                return false;
            }
        }
        m_next_fifo_ticket = 1;
    }

    *out_ticket = m_next_fifo_ticket;
    m_next_fifo_ticket = m_next_fifo_ticket == kU64Maximum ? 0 : m_next_fifo_ticket + 1;
    return true;
}

u32 GuiSendService::CallerActiveCallCountLocked(GuiSendTaskEndpointIdentity endpoint) const
{
    sync::SpinLockAssertHeld(m_lock);
    u32 active = 0;
    for (u32 slot = 0; slot < kGuiSendTransactionCapacity; ++slot)
    {
        const CallRow& row = m_calls[slot];
        if (row.active && row.caller_endpoint == endpoint)
            ++active;
    }
    return active;
}

GuiSendService::DispatchFrame* GuiSendService::TopDispatchFrameLocked(GuiSendTaskEndpointIdentity endpoint,
                                                                      EndpointRow& row)
{
    sync::SpinLockAssertHeld(m_lock);
    if (row.top_dispatch_frame_biased == 0)
        return nullptr;
    const u32 slot = row.top_dispatch_frame_biased - 1U;
    if (slot >= kGuiSendServiceDispatchFrameCapacity)
        return nullptr;
    DispatchFrame& frame = m_dispatch_frames[slot];
    if (!frame.active || frame.endpoint != endpoint || !GuiSendServiceDispatchTokenIsCanonical(frame.token) ||
        frame.token.service_incarnation != m_service_incarnation ||
        frame.token.transaction.dispatcher.endpoint_identity != endpoint.value ||
        frame.token.transaction.dispatcher.process_identity != row.process_identity ||
        frame.token.transaction.dispatcher.task_identity != row.task_identity)
    {
        return nullptr;
    }
    return &frame;
}

const GuiSendService::DispatchFrame* GuiSendService::TopDispatchFrameLocked(GuiSendTaskEndpointIdentity endpoint,
                                                                            const EndpointRow& row) const
{
    sync::SpinLockAssertHeld(m_lock);
    if (row.top_dispatch_frame_biased == 0)
        return nullptr;
    const u32 slot = row.top_dispatch_frame_biased - 1U;
    if (slot >= kGuiSendServiceDispatchFrameCapacity)
        return nullptr;
    const DispatchFrame& frame = m_dispatch_frames[slot];
    if (!frame.active || frame.endpoint != endpoint || !GuiSendServiceDispatchTokenIsCanonical(frame.token) ||
        frame.token.service_incarnation != m_service_incarnation ||
        frame.token.transaction.dispatcher.endpoint_identity != endpoint.value ||
        frame.token.transaction.dispatcher.process_identity != row.process_identity ||
        frame.token.transaction.dispatcher.task_identity != row.task_identity)
    {
        return nullptr;
    }
    return &frame;
}

GuiSendService::DispatchFrame* GuiSendService::FindVacantDispatchFrameLocked()
{
    sync::SpinLockAssertHeld(m_lock);
    for (u32 slot = 0; slot < kGuiSendServiceDispatchFrameCapacity; ++slot)
    {
        if (!m_dispatch_frames[slot].active)
            return &m_dispatch_frames[slot];
    }
    return nullptr;
}

bool GuiSendService::PushDispatchFrameLocked(GuiSendTaskEndpointIdentity endpoint, EndpointRow& row,
                                             const GuiSendServiceDispatchToken& token)
{
    sync::SpinLockAssertHeld(m_lock);
    if (!GuiSendTaskEndpointIdentityIsCanonical(endpoint) || !GuiSendServiceDispatchTokenIsCanonical(token) ||
        token.service_incarnation != m_service_incarnation ||
        token.transaction.dispatcher.endpoint_identity != endpoint.value ||
        token.transaction.dispatcher.process_identity != row.process_identity ||
        token.transaction.dispatcher.task_identity != row.task_identity)
    {
        return false;
    }
    if (row.top_dispatch_frame_biased != 0 && TopDispatchFrameLocked(endpoint, row) == nullptr)
        return false;

    DispatchFrame* frame = FindVacantDispatchFrameLocked();
    if (frame == nullptr)
        return false;
    const u32 slot = static_cast<u32>(frame - m_dispatch_frames);
    if (slot >= kGuiSendServiceDispatchFrameCapacity)
        return false;

    *frame = {};
    frame->token = token;
    frame->endpoint = endpoint;
    frame->previous_frame_biased = row.top_dispatch_frame_biased;
    frame->active = true;
    row.top_dispatch_frame_biased = slot + 1U;
    return true;
}

void GuiSendService::PopDispatchFrameLocked(EndpointRow& row, DispatchFrame& frame)
{
    sync::SpinLockAssertHeld(m_lock);
    const u32 slot = static_cast<u32>(&frame - m_dispatch_frames);
    if (!frame.active || slot >= kGuiSendServiceDispatchFrameCapacity || row.top_dispatch_frame_biased != slot + 1U)
    {
        return;
    }
    row.top_dispatch_frame_biased = frame.previous_frame_biased;
    frame = {};
}

void GuiSendService::ClearDispatchFramesLocked(GuiSendTaskEndpointIdentity endpoint, EndpointRow& row)
{
    sync::SpinLockAssertHeld(m_lock);
    for (u32 slot = 0; slot < kGuiSendServiceDispatchFrameCapacity; ++slot)
    {
        DispatchFrame& frame = m_dispatch_frames[slot];
        if (frame.active && frame.endpoint == endpoint)
            frame = {};
    }
    row.top_dispatch_frame_biased = 0;
}

void GuiSendService::ReconcileTerminalLocked(GuiSendServiceCompletionReason cancelled_reason)
{
    sync::SpinLockAssertHeld(m_lock);
    if (cancelled_reason == GuiSendServiceCompletionReason::Invalid)
        cancelled_reason = GuiSendServiceCompletionReason::AncestorCancelled;

    for (u32 slot = 0; slot < kGuiSendTransactionCapacity; ++slot)
    {
        CallRow& row = m_calls[slot];
        if (!row.active)
            continue;

        GuiSendTransactionSnapshot snapshot{};
        if (!m_transactions.Inspect(GuiSendTransactionIdentity(row.call), &snapshot))
        {
            // The service is the sole transaction-table owner. Losing the
            // backing row without retiring this mirror is an invariant break,
            // not a stale call: keep a terminal poison row so the caller gets
            // InvariantViolation instead of a false successful retirement.
            row.state = GuiSendServiceCallState::Terminal;
            row.reason = GuiSendServiceCompletionReason::Invalid;
            continue;
        }

        switch (snapshot.phase)
        {
        case GuiSendTransactionPhase::Pending:
            row.state = GuiSendServiceCallState::Queued;
            break;
        case GuiSendTransactionPhase::Dispatching:
            row.state = GuiSendServiceCallState::Dispatching;
            break;
        case GuiSendTransactionPhase::ReplyReady:
            row.state = GuiSendServiceCallState::Terminal;
            if (row.reason == GuiSendServiceCompletionReason::Invalid)
                row.reason = GuiSendServiceCompletionReason::Reply;
            break;
        case GuiSendTransactionPhase::Cancelled:
            row.state = GuiSendServiceCallState::Terminal;
            if (row.reason == GuiSendServiceCompletionReason::Invalid)
                row.reason = cancelled_reason;
            break;
        case GuiSendTransactionPhase::TimedOut:
            row.state = GuiSendServiceCallState::Terminal;
            if (row.reason == GuiSendServiceCompletionReason::Invalid)
                row.reason = GuiSendServiceCompletionReason::DeadlineExpired;
            break;
        case GuiSendTransactionPhase::Retired:
        case GuiSendTransactionPhase::Vacant:
        case GuiSendTransactionPhase::GenerationExhausted:
            ClearCallLocked(row);
            break;
        }
    }
}

void GuiSendService::PublishWakeLocked(GuiSendServiceWakeAction* out_wake)
{
    sync::SpinLockAssertHeld(m_lock);
    if (out_wake == nullptr)
        return;
    *out_wake = {};

    if (!m_mutation_epoch_saturated)
    {
        if (m_mutation_epoch == kU64Maximum)
            m_mutation_epoch_saturated = true;
        else
            ++m_mutation_epoch;
    }
    out_wake->mutation_epoch = m_mutation_epoch;
    out_wake->wake_all = 1;
}

GuiSendServiceBeginResult GuiSendService::MapBeginResultLocked(GuiSendBeginResult result) const
{
    sync::SpinLockAssertHeld(m_lock);
    switch (result)
    {
    case GuiSendBeginResult::Created:
        return GuiSendServiceBeginResult::Created;
    case GuiSendBeginResult::DeadlineElapsed:
        return GuiSendServiceBeginResult::DeadlineElapsed;
    case GuiSendBeginResult::ParentUnavailable:
        return GuiSendServiceBeginResult::ParentUnavailable;
    case GuiSendBeginResult::DuplicateRequest:
        // Request sequences are allocated under the service lock, so a
        // duplicate can only be an internal service/transaction divergence.
        return GuiSendServiceBeginResult::InvariantViolation;
    case GuiSendBeginResult::DepthMismatch:
        return GuiSendServiceBeginResult::DepthLimit;
    case GuiSendBeginResult::Cycle:
        return GuiSendServiceBeginResult::Cycle;
    case GuiSendBeginResult::TableFull:
        return GuiSendServiceBeginResult::TableFull;
    case GuiSendBeginResult::GenerationExhausted:
        return GuiSendServiceBeginResult::GenerationExhausted;
    case GuiSendBeginResult::Rejected:
        return GuiSendServiceBeginResult::Rejected;
    }
    return GuiSendServiceBeginResult::InvariantViolation;
}

void GuiSendService::ClearCallLocked(CallRow& row)
{
    sync::SpinLockAssertHeld(m_lock);
    row = {};
}

GuiSendEndpointResult GuiSendService::EnsureTaskEndpoint(u64 process_identity, u64 task_identity,
                                                         GuiSendTaskEndpointIdentity* out_endpoint)
{
    if (out_endpoint != nullptr)
        *out_endpoint = kInvalidGuiSendTaskEndpoint;
    if (out_endpoint == nullptr || process_identity == 0 || task_identity == 0 || task_identity == kU64Maximum)
        return GuiSendEndpointResult::Rejected;
    if (m_service_incarnation == 0)
        return GuiSendEndpointResult::GenerationExhausted;

    sync::SpinLockGuard guard(m_lock);
    for (u32 slot = 0; slot < kGuiSendServiceEndpointCapacity; ++slot)
    {
        const EndpointRow& row = m_endpoints[slot];
        if (!row.active)
            continue;
        if (row.task_identity == task_identity && row.process_identity != process_identity)
            return GuiSendEndpointResult::Rejected;
        if (row.process_identity == process_identity && row.task_identity == task_identity)
        {
            *out_endpoint = IdentityForEndpointLocked(slot, row);
            return GuiSendEndpointResult::Existing;
        }
    }

    bool saw_exhausted = false;
    bool saw_active = false;
    for (u32 slot = 0; slot < kGuiSendServiceEndpointCapacity; ++slot)
    {
        EndpointRow& row = m_endpoints[slot];
        if (row.active)
        {
            saw_active = true;
            continue;
        }
        if (row.retired || row.generation == kGuiSendEndpointGenerationMaximum)
        {
            row.retired = true;
            saw_exhausted = true;
            continue;
        }

        ++row.generation;
        row.process_identity = process_identity;
        row.task_identity = task_identity;
        row.next_request_sequence = 1;
        row.active = true;
        row.retired = false;
        *out_endpoint = IdentityForEndpointLocked(slot, row);
        return GuiSendEndpointResult::Created;
    }

    return !saw_active && saw_exhausted ? GuiSendEndpointResult::GenerationExhausted : GuiSendEndpointResult::TableFull;
}

GuiSendEndpointCloseResult GuiSendService::CloseTaskEndpoint(GuiSendTaskEndpointIdentity endpoint,
                                                             GuiSendEndpointCloseSummary* out_summary)
{
    if (out_summary != nullptr)
        *out_summary = {};
    if (out_summary == nullptr || !GuiSendTaskEndpointIdentityIsCanonical(endpoint))
        return GuiSendEndpointCloseResult::Rejected;

    sync::SpinLockGuard guard(m_lock);
    EndpointRow* endpoint_row = ResolveEndpointLocked(endpoint);
    if (endpoint_row == nullptr)
        return GuiSendEndpointCloseResult::Stale;

    const GuiSendPrincipalSnapshot principal = PrincipalLocked(endpoint, *endpoint_row);
    const GuiSendTaskIdentity task{endpoint_row->process_identity, endpoint_row->task_identity};

    for (u32 slot = 0; slot < kGuiSendTransactionCapacity; ++slot)
    {
        CallRow& row = m_calls[slot];
        if (row.active && row.target_endpoint == endpoint &&
            (row.state == GuiSendServiceCallState::Queued || row.state == GuiSendServiceCallState::Dispatching))
        {
            row.reason = GuiSendServiceCompletionReason::TargetTaskExited;
        }
    }

    out_summary->caller_transitions = m_transactions.CancelCallerDeath(principal);
    out_summary->target_transitions = m_transactions.CancelTargetDeath(task);
    ReconcileTerminalLocked(GuiSendServiceCompletionReason::AncestorCancelled);

    for (u32 slot = 0; slot < kGuiSendTransactionCapacity; ++slot)
    {
        CallRow& row = m_calls[slot];
        if (!row.active || row.caller_endpoint != endpoint)
            continue;
        if (m_transactions.RetireAbandoned(GuiSendTransactionIdentity(row.call)) == GuiSendRetireResult::Retired)
            ++out_summary->caller_rows_retired;
        ClearCallLocked(row);
    }

    ClearDispatchFramesLocked(endpoint, *endpoint_row);
    endpoint_row->process_identity = 0;
    endpoint_row->task_identity = 0;
    endpoint_row->next_request_sequence = 1;
    endpoint_row->active = false;
    if (endpoint_row->generation == kGuiSendEndpointGenerationMaximum)
        endpoint_row->retired = true;

    PublishWakeLocked(&out_summary->wake);
    return GuiSendEndpointCloseResult::Closed;
}

GuiSendServiceBeginResult GuiSendService::Begin(const GuiSendServiceBeginRequest& request, u64 now,
                                                GuiSendServiceBeginOutput* out)
{
    if (out != nullptr)
    {
        *out = {};
        out->call = kInvalidGuiSendServiceCallIdentity;
    }
    const bool root_send = GuiSendServiceDispatchTokenIsInvalidCanonical(request.parent_dispatch);
    if (out == nullptr || request.reserved != 0 || !GuiSendTaskEndpointIdentityIsCanonical(request.caller_endpoint) ||
        !GuiSendTaskEndpointIdentityIsCanonical(request.target_endpoint) ||
        (!root_send && !GuiSendServiceDispatchTokenIsCanonical(request.parent_dispatch)))
    {
        return GuiSendServiceBeginResult::Rejected;
    }
    if (request.target_window_identity == 0)
        return GuiSendServiceBeginResult::InvalidTargetWindow;
    if (request.message > 0xFFFFU)
        return GuiSendServiceBeginResult::InvalidMessage;
    if (request.absolute_deadline == 0 || now >= request.absolute_deadline)
        return GuiSendServiceBeginResult::DeadlineElapsed;

    sync::SpinLockGuard guard(m_lock);
    EndpointRow* caller = ResolveEndpointLocked(request.caller_endpoint);
    if (caller == nullptr)
        return GuiSendServiceBeginResult::CallerEndpointStale;
    const EndpointRow* target = ResolveEndpointLocked(request.target_endpoint);
    if (target == nullptr)
        return GuiSendServiceBeginResult::TargetEndpointStale;
    if (caller->process_identity != target->process_identity)
        return GuiSendServiceBeginResult::CrossProcessDenied;
    if (caller->task_identity == target->task_identity)
        return GuiSendServiceBeginResult::SameTaskDirectRequired;
    if (caller->next_request_sequence == 0)
        return GuiSendServiceBeginResult::SequenceExhausted;
    u8 depth = 0;
    GuiSendCallIdentity parent_identity = kInvalidGuiSendCallIdentity;
    DispatchFrame* current_dispatch = TopDispatchFrameLocked(request.caller_endpoint, *caller);
    if (caller->top_dispatch_frame_biased != 0 && current_dispatch == nullptr)
        return GuiSendServiceBeginResult::InvariantViolation;
    if (!root_send)
    {
        if (request.parent_dispatch.service_incarnation != m_service_incarnation)
            return GuiSendServiceBeginResult::ParentUnavailable;
        if (current_dispatch == nullptr ||
            !ServiceDispatchTokensEqual(current_dispatch->token, request.parent_dispatch))
        {
            return GuiSendServiceBeginResult::ParentUnavailable;
        }

        const GuiSendServiceCallIdentity parent_service_identity = GuiSendServiceIdentity(
            request.parent_dispatch.service_incarnation, request.parent_dispatch.transaction.call);
        const CallRow* parent_row = ResolveCallLocked(parent_service_identity);
        GuiSendTransactionSnapshot parent{};
        if (parent_row == nullptr || parent_row->state != GuiSendServiceCallState::Dispatching ||
            parent_row->target_endpoint != request.caller_endpoint ||
            !m_transactions.Inspect(request.parent_dispatch.transaction.call, &parent) ||
            parent.phase != GuiSendTransactionPhase::Dispatching)
        {
            return GuiSendServiceBeginResult::ParentUnavailable;
        }
        const GuiSendPrincipalSnapshot caller_principal = PrincipalLocked(request.caller_endpoint, *caller);
        if (!ServicePrincipalsEqual(parent.dispatcher, caller_principal) ||
            !ServicePrincipalsEqual(parent.dispatcher, request.parent_dispatch.transaction.dispatcher) ||
            request.parent_dispatch.transaction.request_sequence != parent.call.request_sequence)
        {
            return GuiSendServiceBeginResult::ParentUnavailable;
        }
        if (parent.call.reentrancy_depth >= kGuiSendMaximumReentrancyDepth)
            return GuiSendServiceBeginResult::DepthLimit;
        depth = static_cast<u8>(parent.call.reentrancy_depth + 1U);
        parent_identity = request.parent_dispatch.transaction.call;
    }
    else if (current_dispatch != nullptr)
    {
        // An adapter running inside a WndProc must preserve the exact private
        // dispatch token. Treating the nested send as a new root would erase
        // ancestry, cycle checks, depth limits, and cancellation propagation.
        return GuiSendServiceBeginResult::ParentRequired;
    }
    if (CallerActiveCallCountLocked(request.caller_endpoint) >= kGuiSendServicePerCallerCallLimit)
        return GuiSendServiceBeginResult::CallerQuotaExceeded;

    GuiSendFrozenCall frozen{};
    frozen.parent_call = parent_identity;
    frozen.sender_endpoint_identity = request.caller_endpoint.value;
    frozen.sender_process_identity = caller->process_identity;
    frozen.sender_task_identity = caller->task_identity;
    frozen.target_process_identity = target->process_identity;
    frozen.target_task_identity = target->task_identity;
    frozen.target_window_identity = request.target_window_identity;
    frozen.policy_authority_identity = kGuiSendSameProcessScalarAuthority;
    frozen.request_sequence = caller->next_request_sequence;
    frozen.wparam = request.wparam;
    frozen.lparam = request.lparam;
    frozen.absolute_deadline = request.absolute_deadline;
    frozen.message = request.message;
    frozen.reentrancy_depth = depth;

    GuiSendCallIdentity transaction_identity = kInvalidGuiSendCallIdentity;
    const GuiSendBeginResult transaction_result = m_transactions.Begin(frozen, now, &transaction_identity);
    if (transaction_result != GuiSendBeginResult::Created)
        return MapBeginResultLocked(transaction_result);
    if (!GuiSendCallIdentityIsValid(transaction_identity) || transaction_identity.slot >= kGuiSendTransactionCapacity ||
        m_calls[transaction_identity.slot].active)
    {
        const GuiSendPrincipalSnapshot principal = PrincipalLocked(request.caller_endpoint, *caller);
        (void)m_transactions.CancelByCaller(transaction_identity, principal);
        (void)m_transactions.RetireAbandoned(transaction_identity);
        return GuiSendServiceBeginResult::InvariantViolation;
    }

    u64 fifo_ticket = 0;
    if (!AllocateFifoTicketLocked(&fifo_ticket))
    {
        // Do not burn FIFO space on a failed transaction begin. Conversely,
        // if ticket rollover is blocked by older ordered work, unwind this
        // just-created transaction before exposing it to any caller.
        const GuiSendPrincipalSnapshot principal = PrincipalLocked(request.caller_endpoint, *caller);
        (void)m_transactions.CancelByCaller(transaction_identity, principal);
        (void)m_transactions.RetireAbandoned(transaction_identity);
        return GuiSendServiceBeginResult::TableFull;
    }

    const GuiSendServiceCallIdentity service_identity =
        GuiSendServiceIdentity(m_service_incarnation, transaction_identity);
    CallRow& call_row = m_calls[transaction_identity.slot];
    call_row.call = service_identity;
    call_row.caller_endpoint = request.caller_endpoint;
    call_row.target_endpoint = request.target_endpoint;
    call_row.target_window_identity = request.target_window_identity;
    call_row.fifo_ticket = fifo_ticket;
    call_row.state = GuiSendServiceCallState::Queued;
    call_row.reason = GuiSendServiceCompletionReason::Invalid;
    call_row.active = true;

    out->call = service_identity;
    out->request_sequence = frozen.request_sequence;
    caller->next_request_sequence =
        caller->next_request_sequence == kU64Maximum ? 0 : caller->next_request_sequence + 1;
    PublishWakeLocked(&out->wake);
    return GuiSendServiceBeginResult::Created;
}

GuiSendServicePumpResult GuiSendService::Pump(GuiSendTaskEndpointIdentity endpoint,
                                              GuiSendServiceCallIdentity waiting_call, u64 now,
                                              GuiSendServicePumpOutput* out)
{
    if (out != nullptr)
    {
        *out = {};
        out->dispatch.reply_token = kInvalidGuiSendServiceDispatchToken;
        out->completion.call = kInvalidGuiSendServiceCallIdentity;
    }
    if (out == nullptr || !GuiSendTaskEndpointIdentityIsCanonical(endpoint) ||
        (!GuiSendServiceCallIdentityIsInvalidCanonical(waiting_call) &&
         !GuiSendServiceCallIdentityIsCanonical(waiting_call)))
    {
        return GuiSendServicePumpResult::Rejected;
    }

    sync::SpinLockGuard guard(m_lock);
    EndpointRow* endpoint_row = ResolveEndpointLocked(endpoint);
    if (endpoint_row == nullptr)
        return GuiSendServicePumpResult::EndpointStale;

    if (GuiSendServiceCallIdentityIsCanonical(waiting_call))
    {
        const CallRow* waiting = ResolveCallLocked(waiting_call);
        if (waiting == nullptr)
            return GuiSendServicePumpResult::WaitingCallStale;
        if (waiting->caller_endpoint != endpoint)
            return GuiSendServicePumpResult::WrongCaller;
    }

    bool wake_changed = false;
    const GuiSendPrincipalSnapshot dispatcher = PrincipalLocked(endpoint, *endpoint_row);
    for (u32 attempt = 0; attempt < kGuiSendTransactionCapacity; ++attempt)
    {
        CallRow* candidate = nullptr;
        for (u32 slot = 0; slot < kGuiSendTransactionCapacity; ++slot)
        {
            CallRow& row = m_calls[slot];
            if (!row.active || row.state != GuiSendServiceCallState::Queued || row.target_endpoint != endpoint)
                continue;
            if (candidate == nullptr || row.fifo_ticket < candidate->fifo_ticket)
                candidate = &row;
        }
        if (candidate == nullptr)
            break;
        if (endpoint_row->top_dispatch_frame_biased != 0 && TopDispatchFrameLocked(endpoint, *endpoint_row) == nullptr)
            return GuiSendServicePumpResult::InvariantViolation;
        if (FindVacantDispatchFrameLocked() == nullptr)
            return GuiSendServicePumpResult::DispatchContextFull;

        GuiSendDispatchClaim claim{};
        const GuiSendDispatchResult result =
            m_transactions.ClaimDispatch(GuiSendTransactionIdentity(candidate->call), dispatcher, now, &claim);
        if (result == GuiSendDispatchResult::Claimed)
        {
            const GuiSendServiceDispatchToken service_token{m_service_incarnation, claim.token};
            if (!PushDispatchFrameLocked(endpoint, *endpoint_row, service_token))
            {
                const GuiSendPrincipalSnapshot caller{claim.call.sender_endpoint_identity,
                                                      claim.call.sender_process_identity,
                                                      claim.call.sender_task_identity,
                                                      {}};
                (void)m_transactions.CancelByCaller(claim.token.call, caller);
                ReconcileTerminalLocked(GuiSendServiceCompletionReason::AncestorCancelled);
                PublishWakeLocked(&out->wake);
                return GuiSendServicePumpResult::InvariantViolation;
            }
            candidate->state = GuiSendServiceCallState::Dispatching;
            out->kind = GuiSendServicePumpKind::Dispatch;
            out->dispatch.reply_token = service_token;
            out->dispatch.target_endpoint = endpoint;
            out->dispatch.target_window_identity = claim.call.target_window_identity;
            out->dispatch.request_sequence = claim.call.request_sequence;
            out->dispatch.wparam = claim.call.wparam;
            out->dispatch.lparam = claim.call.lparam;
            out->dispatch.absolute_deadline = claim.call.absolute_deadline;
            out->dispatch.message = claim.call.message;
            out->dispatch.reentrancy_depth = claim.call.reentrancy_depth;
            if (wake_changed)
                PublishWakeLocked(&out->wake);
            return GuiSendServicePumpResult::Pumped;
        }
        if (result == GuiSendDispatchResult::TimedOut)
        {
            candidate->state = GuiSendServiceCallState::Terminal;
            candidate->reason = GuiSendServiceCompletionReason::DeadlineExpired;
            ReconcileTerminalLocked(GuiSendServiceCompletionReason::AncestorCancelled);
            wake_changed = true;
            continue;
        }
        if (result == GuiSendDispatchResult::NotPending)
        {
            ReconcileTerminalLocked(GuiSendServiceCompletionReason::AncestorCancelled);
            if (candidate->active && candidate->state == GuiSendServiceCallState::Terminal)
                continue;
        }
        return GuiSendServicePumpResult::InvariantViolation;
    }

    if (GuiSendServiceCallIdentityIsCanonical(waiting_call))
    {
        CallRow* waiting = ResolveCallLocked(waiting_call);
        if (waiting == nullptr)
            return GuiSendServicePumpResult::WaitingCallStale;

        if (waiting->state == GuiSendServiceCallState::Queued || waiting->state == GuiSendServiceCallState::Dispatching)
        {
            const GuiSendTimeoutResult timeout =
                m_transactions.TimeoutAt(GuiSendTransactionIdentity(waiting_call), now);
            if (timeout == GuiSendTimeoutResult::TimedOut)
            {
                waiting->state = GuiSendServiceCallState::Terminal;
                waiting->reason = GuiSendServiceCompletionReason::DeadlineExpired;
                ReconcileTerminalLocked(GuiSendServiceCompletionReason::AncestorCancelled);
                wake_changed = true;
            }
            else if (timeout != GuiSendTimeoutResult::NotDue && timeout != GuiSendTimeoutResult::TooLate)
            {
                return GuiSendServicePumpResult::InvariantViolation;
            }
        }

        waiting = ResolveCallLocked(waiting_call);
        if (waiting == nullptr)
            return GuiSendServicePumpResult::WaitingCallStale;
        if (waiting->state == GuiSendServiceCallState::Terminal)
        {
            const GuiSendServiceCompletionReason reason = waiting->reason;
            const GuiSendPrincipalSnapshot caller = PrincipalLocked(endpoint, *endpoint_row);
            GuiSendCompletion completion{};
            const GuiSendConsumeResult consumed =
                m_transactions.Consume(GuiSendTransactionIdentity(waiting_call), caller, &completion);
            if (consumed != GuiSendConsumeResult::Consumed)
                return GuiSendServicePumpResult::InvariantViolation;

            out->kind = GuiSendServicePumpKind::Completion;
            out->completion.call = waiting_call;
            out->completion.reason = reason;
            out->completion.transaction_phase = completion.phase;
            out->completion.valid = 1;
            out->completion.request_sequence = completion.request_sequence;
            out->completion.reply_value = completion.reply_value;
            ClearCallLocked(*waiting);
            if (wake_changed)
                PublishWakeLocked(&out->wake);
            return GuiSendServicePumpResult::Pumped;
        }
    }

    if (wake_changed)
        PublishWakeLocked(&out->wake);
    out->kind = GuiSendServicePumpKind::Idle;
    out->wait_token.endpoint = endpoint;
    out->wait_token.mutation_epoch = m_mutation_epoch;
    out->wait_token.valid = m_mutation_epoch_saturated ? 0 : 1;
    return GuiSendServicePumpResult::Pumped;
}

GuiSendServiceReplyResult GuiSendService::CommitReply(GuiSendTaskEndpointIdentity dispatcher_endpoint,
                                                      const GuiSendServiceDispatchToken& token, u64 completed_at,
                                                      u64 reply_value, GuiSendServiceWakeAction* out_wake)
{
    if (out_wake != nullptr)
        *out_wake = {};
    if (out_wake == nullptr || !GuiSendTaskEndpointIdentityIsCanonical(dispatcher_endpoint) ||
        !GuiSendServiceDispatchTokenIsCanonical(token))
    {
        return GuiSendServiceReplyResult::Rejected;
    }

    sync::SpinLockGuard guard(m_lock);
    EndpointRow* endpoint = ResolveEndpointLocked(dispatcher_endpoint);
    if (endpoint == nullptr)
        return GuiSendServiceReplyResult::EndpointStale;

    DispatchFrame* current_dispatch = TopDispatchFrameLocked(dispatcher_endpoint, *endpoint);
    if (endpoint->top_dispatch_frame_biased != 0 && current_dispatch == nullptr)
        return GuiSendServiceReplyResult::InvariantViolation;
    const bool current_token =
        current_dispatch != nullptr && ServiceDispatchTokensEqual(current_dispatch->token, token);
    if (token.service_incarnation != m_service_incarnation)
        return GuiSendServiceReplyResult::Stale;
    const GuiSendServiceCallIdentity service_call =
        GuiSendServiceIdentity(token.service_incarnation, token.transaction.call);
    CallRow* row = ResolveCallLocked(service_call);
    if (row != nullptr && row->target_endpoint != dispatcher_endpoint)
        return GuiSendServiceReplyResult::WrongDispatcher;
    if (!current_token)
    {
        // A retired transaction can still have an executing WndProc frame.
        // If another frame is above it, Stale would incorrectly tell the
        // adapter that the buried return boundary had completed. Preserve the
        // frame and require exact LIFO unwind even after the CallRow is gone.
        return current_dispatch != nullptr || row != nullptr ? GuiSendServiceReplyResult::WrongClaim
                                                             : GuiSendServiceReplyResult::Stale;
    }

    const GuiSendPrincipalSnapshot principal = PrincipalLocked(dispatcher_endpoint, *endpoint);
    const GuiSendReplyResult result =
        m_transactions.CommitReply(token.transaction, principal, completed_at, reply_value);
    switch (result)
    {
    case GuiSendReplyResult::Committed:
        if (row == nullptr)
        {
            PopDispatchFrameLocked(*endpoint, *current_dispatch);
            PublishWakeLocked(out_wake);
            return GuiSendServiceReplyResult::InvariantViolation;
        }
        row->state = GuiSendServiceCallState::Terminal;
        row->reason = GuiSendServiceCompletionReason::Reply;
        ReconcileTerminalLocked(GuiSendServiceCompletionReason::AncestorCancelled);
        PopDispatchFrameLocked(*endpoint, *current_dispatch);
        PublishWakeLocked(out_wake);
        return GuiSendServiceReplyResult::Committed;
    case GuiSendReplyResult::TimedOut:
        if (row == nullptr)
        {
            PopDispatchFrameLocked(*endpoint, *current_dispatch);
            PublishWakeLocked(out_wake);
            return GuiSendServiceReplyResult::InvariantViolation;
        }
        row->state = GuiSendServiceCallState::Terminal;
        row->reason = GuiSendServiceCompletionReason::DeadlineExpired;
        ReconcileTerminalLocked(GuiSendServiceCompletionReason::AncestorCancelled);
        PopDispatchFrameLocked(*endpoint, *current_dispatch);
        PublishWakeLocked(out_wake);
        return GuiSendServiceReplyResult::DeadlineExpired;
    case GuiSendReplyResult::WrongPrincipal:
        return GuiSendServiceReplyResult::WrongDispatcher;
    case GuiSendReplyResult::WrongClaim:
        return GuiSendServiceReplyResult::WrongClaim;
    case GuiSendReplyResult::ActiveChild:
        return GuiSendServiceReplyResult::ActiveChild;
    case GuiSendReplyResult::Terminal:
        ReconcileTerminalLocked(GuiSendServiceCompletionReason::AncestorCancelled);
        PopDispatchFrameLocked(*endpoint, *current_dispatch);
        PublishWakeLocked(out_wake);
        return GuiSendServiceReplyResult::Terminal;
    case GuiSendReplyResult::Stale:
        PopDispatchFrameLocked(*endpoint, *current_dispatch);
        PublishWakeLocked(out_wake);
        return GuiSendServiceReplyResult::Stale;
    case GuiSendReplyResult::Rejected:
        return GuiSendServiceReplyResult::Rejected;
    }
    return GuiSendServiceReplyResult::InvariantViolation;
}

GuiSendServiceCancelResult GuiSendService::Cancel(GuiSendTaskEndpointIdentity caller_endpoint,
                                                  GuiSendServiceCallIdentity call, GuiSendServiceWakeAction* out_wake)
{
    if (out_wake != nullptr)
        *out_wake = {};
    if (out_wake == nullptr || !GuiSendTaskEndpointIdentityIsCanonical(caller_endpoint) ||
        !GuiSendServiceCallIdentityIsCanonical(call))
    {
        return GuiSendServiceCancelResult::Rejected;
    }

    sync::SpinLockGuard guard(m_lock);
    EndpointRow* endpoint = ResolveEndpointLocked(caller_endpoint);
    if (endpoint == nullptr)
        return GuiSendServiceCancelResult::EndpointStale;
    CallRow* row = ResolveCallLocked(call);
    if (row == nullptr)
        return GuiSendServiceCancelResult::Stale;
    if (row->caller_endpoint != caller_endpoint)
        return GuiSendServiceCancelResult::WrongCaller;

    const GuiSendPrincipalSnapshot principal = PrincipalLocked(caller_endpoint, *endpoint);
    const GuiSendCancelResult result = m_transactions.CancelByCaller(GuiSendTransactionIdentity(call), principal);
    switch (result)
    {
    case GuiSendCancelResult::Cancelled:
        row->state = GuiSendServiceCallState::Terminal;
        row->reason = GuiSendServiceCompletionReason::CallerCancelled;
        ReconcileTerminalLocked(GuiSendServiceCompletionReason::AncestorCancelled);
        PublishWakeLocked(out_wake);
        return GuiSendServiceCancelResult::Cancelled;
    case GuiSendCancelResult::WrongPrincipal:
        return GuiSendServiceCancelResult::WrongCaller;
    case GuiSendCancelResult::TooLate:
        ReconcileTerminalLocked(GuiSendServiceCompletionReason::AncestorCancelled);
        return GuiSendServiceCancelResult::TooLate;
    case GuiSendCancelResult::Stale:
        return GuiSendServiceCancelResult::Stale;
    case GuiSendCancelResult::Rejected:
        return GuiSendServiceCancelResult::Rejected;
    }
    return GuiSendServiceCancelResult::InvariantViolation;
}

u32 GuiSendService::CancelTargetWindow(GuiSendTaskEndpointIdentity target_endpoint, u64 target_window_identity,
                                       GuiSendServiceWakeAction* out_wake)
{
    if (out_wake != nullptr)
        *out_wake = {};
    if (out_wake == nullptr || !GuiSendTaskEndpointIdentityIsCanonical(target_endpoint) || target_window_identity == 0)
    {
        return 0;
    }

    sync::SpinLockGuard guard(m_lock);
    if (ResolveEndpointLocked(target_endpoint) == nullptr)
        return 0;

    u32 cancelled = 0;
    for (u32 slot = 0; slot < kGuiSendTransactionCapacity; ++slot)
    {
        CallRow& row = m_calls[slot];
        if (!row.active || row.target_endpoint != target_endpoint ||
            row.target_window_identity != target_window_identity ||
            (row.state != GuiSendServiceCallState::Queued && row.state != GuiSendServiceCallState::Dispatching))
        {
            continue;
        }

        GuiSendTransactionSnapshot snapshot{};
        const GuiSendCallIdentity transaction_call = GuiSendTransactionIdentity(row.call);
        if (!m_transactions.Inspect(transaction_call, &snapshot) || !ServicePhaseIsMutable(snapshot.phase))
            continue;
        const GuiSendPrincipalSnapshot caller{snapshot.call.sender_endpoint_identity,
                                              snapshot.call.sender_process_identity,
                                              snapshot.call.sender_task_identity,
                                              {}};
        if (m_transactions.CancelByCaller(transaction_call, caller) == GuiSendCancelResult::Cancelled)
        {
            row.state = GuiSendServiceCallState::Terminal;
            row.reason = GuiSendServiceCompletionReason::TargetWindowClosed;
            ++cancelled;
        }
    }

    if (cancelled != 0)
    {
        ReconcileTerminalLocked(GuiSendServiceCompletionReason::AncestorCancelled);
        PublishWakeLocked(out_wake);
    }
    return cancelled;
}

u32 GuiSendService::ExpireDeadlines(u64 now, GuiSendServiceWakeAction* out_wake)
{
    if (out_wake != nullptr)
        *out_wake = {};
    if (out_wake == nullptr)
        return 0;

    sync::SpinLockGuard guard(m_lock);
    u32 expired = 0;
    for (u32 slot = 0; slot < kGuiSendTransactionCapacity; ++slot)
    {
        CallRow& row = m_calls[slot];
        if (!row.active ||
            (row.state != GuiSendServiceCallState::Queued && row.state != GuiSendServiceCallState::Dispatching))
        {
            continue;
        }
        if (m_transactions.TimeoutAt(GuiSendTransactionIdentity(row.call), now) == GuiSendTimeoutResult::TimedOut)
        {
            row.state = GuiSendServiceCallState::Terminal;
            row.reason = GuiSendServiceCompletionReason::DeadlineExpired;
            ++expired;
        }
    }

    if (expired != 0)
    {
        ReconcileTerminalLocked(GuiSendServiceCompletionReason::AncestorCancelled);
        PublishWakeLocked(out_wake);
    }
    return expired;
}

bool GuiSendService::WaitTokenCurrent(const GuiSendServiceWaitToken& token)
{
    if (token.valid != 1 || !ServiceReservedBytesAreZero(token.reserved, 7) ||
        !GuiSendTaskEndpointIdentityIsCanonical(token.endpoint) || token.mutation_epoch == 0)
    {
        return false;
    }

    sync::SpinLockGuard guard(m_lock);
    return !m_mutation_epoch_saturated && ResolveEndpointLocked(token.endpoint) != nullptr &&
           token.mutation_epoch == m_mutation_epoch;
}

bool GuiSendService::InspectCall(GuiSendServiceCallIdentity call, GuiSendServiceCallSnapshot* out_snapshot)
{
    if (out_snapshot != nullptr)
    {
        *out_snapshot = {};
        out_snapshot->call = kInvalidGuiSendServiceCallIdentity;
    }
    if (out_snapshot == nullptr || !GuiSendServiceCallIdentityIsCanonical(call))
        return false;

    sync::SpinLockGuard guard(m_lock);
    const CallRow* row = ResolveCallLocked(call);
    if (row == nullptr)
        return false;
    GuiSendTransactionSnapshot transaction{};
    if (!m_transactions.Inspect(GuiSendTransactionIdentity(call), &transaction))
        return false;

    out_snapshot->call = row->call;
    out_snapshot->caller_endpoint = row->caller_endpoint;
    out_snapshot->target_endpoint = row->target_endpoint;
    out_snapshot->target_window_identity = row->target_window_identity;
    out_snapshot->fifo_ticket = row->fifo_ticket;
    out_snapshot->state = row->state;
    out_snapshot->reason = row->reason;
    out_snapshot->valid = 1;
    out_snapshot->transaction = transaction;
    return true;
}

u32 GuiSendService::ActiveEndpointCount()
{
    sync::SpinLockGuard guard(m_lock);
    u32 active = 0;
    for (u32 slot = 0; slot < kGuiSendServiceEndpointCapacity; ++slot)
    {
        if (m_endpoints[slot].active)
            ++active;
    }
    return active;
}

u32 GuiSendService::ActiveCallCount()
{
    sync::SpinLockGuard guard(m_lock);
    u32 active = 0;
    for (u32 slot = 0; slot < kGuiSendTransactionCapacity; ++slot)
    {
        if (m_calls[slot].active)
            ++active;
    }
    return active;
}

u32 GuiSendService::ActiveDispatchFrameCount()
{
    sync::SpinLockGuard guard(m_lock);
    u32 active = 0;
    for (u32 slot = 0; slot < kGuiSendServiceDispatchFrameCapacity; ++slot)
    {
        if (m_dispatch_frames[slot].active)
            ++active;
    }
    return active;
}

#if defined(DUETOS_HOST_TEST)
bool GuiSendService::HostPositionEndpointGeneration(u32 slot, u64 generation)
{
    if (slot >= kGuiSendServiceEndpointCapacity || generation > kGuiSendEndpointGenerationMaximum)
        return false;
    sync::SpinLockGuard guard(m_lock);
    EndpointRow& row = m_endpoints[slot];
    if (row.active || generation < row.generation)
        return false;
    row = {};
    row.generation = generation;
    row.next_request_sequence = 1;
    row.retired = generation == kGuiSendEndpointGenerationMaximum;
    return true;
}

bool GuiSendService::HostPositionNextFifoTicket(u64 ticket)
{
    if (ticket == 0)
        return false;
    sync::SpinLockGuard guard(m_lock);
    for (u32 slot = 0; slot < kGuiSendTransactionCapacity; ++slot)
    {
        const CallRow& row = m_calls[slot];
        if (row.active &&
            (row.state == GuiSendServiceCallState::Queued || row.state == GuiSendServiceCallState::Dispatching))
        {
            return false;
        }
    }
    m_next_fifo_ticket = ticket;
    return true;
}

sync::LockClass GuiSendService::HostServiceLockClass() const
{
    return m_lock.class_id;
}
#endif

} // namespace duetos::drivers::video
