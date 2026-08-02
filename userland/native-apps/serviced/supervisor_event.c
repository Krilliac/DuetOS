#include "supervisor_internal.h"

static uint64_t FingerprintMix(uint64_t hash, uint64_t value)
{
    uint32_t index;
    for (index = 0; index < 8; ++index)
    {
        hash ^= (uint8_t)(value >> (index * 8U));
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static uint64_t EventFingerprint(const ServicedSupervisorLifecycleEvent* event)
{
    uint64_t hash = UINT64_C(1469598103934665603);
    hash = FingerprintMix(hash, event->event_sequence);
    hash = FingerprintMix(hash, event->now_ns);
    hash = FingerprintMix(hash, event->service_identity);
    hash = FingerprintMix(hash, event->instance_generation);
    hash = FingerprintMix(hash, event->service_slot);
    hash = FingerprintMix(hash, event->exit_code);
    hash = FingerprintMix(hash, event->type);
    hash = FingerprintMix(hash, event->failed);
    hash = FingerprintMix(hash, event->observed.service_slot);
    hash = FingerprintMix(hash, event->observed.instance_generation);
    hash = FingerprintMix(hash, event->observed.process.identity);
    hash = FingerprintMix(hash, event->observed.process.pid);
    hash = FingerprintMix(hash, event->observed.endpoint_epoch);
    return hash != 0 ? hash : UINT64_C(1);
}

static uint8_t EventShapeIsCanonical(const ServicedSupervisorLifecycleEvent* event)
{
    const uint8_t observed_valid = ServicedSupervisorObservedIdentityIsCanonical(&event->observed);
    const uint8_t observed_zero = ServicedSupervisorInternalObservedIsZero(&event->observed);
    if (event->event_sequence == 0 || event->service_identity == 0 ||
        event->service_slot >= SERVICED_SUPERVISOR_MAX_SERVICES || event->instance_generation == 0 ||
        event->failed > 1 || event->reserved16 != 0 || event->reserved32 != 0)
        return 0;
    switch (event->type)
    {
    case SERVICED_EVENT_PUBLISHED:
    case SERVICED_EVENT_ENDPOINT_READY:
    case SERVICED_EVENT_ENDPOINT_CLOSED:
        return (uint8_t)(observed_valid && event->observed.service_slot == event->service_slot &&
                         event->observed.instance_generation == event->instance_generation && event->exit_code == 0 &&
                         event->failed == 0);
    case SERVICED_EVENT_EXITED:
        return (uint8_t)(observed_valid && event->observed.service_slot == event->service_slot &&
                         event->observed.instance_generation == event->instance_generation);
    case SERVICED_EVENT_START_FAILED:
        return (uint8_t)(observed_zero && event->failed == 1);
    case SERVICED_EVENT_START_CANCELLED:
        return (uint8_t)(observed_zero && event->failed == 0 && event->exit_code == 0);
    default:
        return 0;
    }
}

static ServicedSupervisorStatus ValidateEventForRow(const ServicedSupervisorRow* row,
                                                    const ServicedSupervisorLifecycleEvent* event)
{
    if (row->service_slot != event->service_slot)
        return SERVICED_SUPERVISOR_NOT_FOUND;
    if (row->transition_generation != event->instance_generation)
        return SERVICED_SUPERVISOR_STALE_GENERATION;
    switch (event->type)
    {
    case SERVICED_EVENT_PUBLISHED:
        return row->phase == SERVICED_PHASE_STARTING ? SERVICED_SUPERVISOR_OK : SERVICED_SUPERVISOR_INVALID_EVENT;
    case SERVICED_EVENT_ENDPOINT_READY:
        if (row->phase != SERVICED_PHASE_RUNNING)
            return SERVICED_SUPERVISOR_INVALID_EVENT;
        break;
    case SERVICED_EVENT_ENDPOINT_CLOSED:
    case SERVICED_EVENT_EXITED:
        if (row->phase != SERVICED_PHASE_RUNNING && row->phase != SERVICED_PHASE_READY &&
            row->phase != SERVICED_PHASE_STOPPING)
            return SERVICED_SUPERVISOR_INVALID_EVENT;
        break;
    case SERVICED_EVENT_START_FAILED:
        return row->phase == SERVICED_PHASE_STARTING ? SERVICED_SUPERVISOR_OK : SERVICED_SUPERVISOR_INVALID_EVENT;
    case SERVICED_EVENT_START_CANCELLED:
        return row->phase == SERVICED_PHASE_STOPPING && ServicedSupervisorInternalObservedIsZero(&row->observed)
                   ? SERVICED_SUPERVISOR_OK
                   : SERVICED_SUPERVISOR_INVALID_EVENT;
    default:
        return SERVICED_SUPERVISOR_INVALID_EVENT;
    }
    return ServicedSupervisorInternalObservedEqual(&row->observed, &event->observed)
               ? SERVICED_SUPERVISOR_OK
               : SERVICED_SUPERVISOR_WRONG_INSTANCE;
}

static void EnterCrashLoop(ServicedSupervisorRow* row)
{
    row->phase = SERVICED_PHASE_CRASH_LOOP;
    row->desired_state = SERVICED_DESIRED_STOPPED;
    row->restart_requested = 0;
    row->terminal_after_stop = 0;
    row->start_reason = SERVICED_ACTION_REASON_NONE;
    row->adopted = 0;
    ServicedSupervisorInternalClearObserved(&row->observed);
}

static void ApplyNaturalExitPolicy(ServicedSupervisorRow* row, uint8_t failed, uint64_t now_ns)
{
    const uint8_t should_restart = (uint8_t)(row->restart_policy == SERVICED_RESTART_ALWAYS ||
                                             (row->restart_policy == SERVICED_RESTART_ON_FAILURE && failed != 0));
    row->phase = failed != 0 ? SERVICED_PHASE_FAILED : SERVICED_PHASE_EXITED;
    row->adopted = 0;
    ServicedSupervisorInternalClearObserved(&row->observed);
    row->restart_requested = 0;
    if (!should_restart)
    {
        row->desired_state = SERVICED_DESIRED_STOPPED;
        row->start_reason = SERVICED_ACTION_REASON_NONE;
    }
    else if (!ServicedSupervisorPolicyArmAutomaticRestart(row, now_ns))
        EnterCrashLoop(row);
}

static ServicedSupervisorStatus ApplyEventMutation(ServicedSupervisorImpl* supervisor, ServicedSupervisorRow* row,
                                                   const ServicedSupervisorLifecycleEvent* event,
                                                   ServicedSupervisorActionBatch* actions)
{
    switch (event->type)
    {
    case SERVICED_EVENT_PUBLISHED:
        row->observed = event->observed;
        row->phase = SERVICED_PHASE_RUNNING;
        row->adopted = 1;
        break;
    case SERVICED_EVENT_ENDPOINT_READY:
        row->phase = SERVICED_PHASE_READY;
        row->adopted = 1;
        break;
    case SERVICED_EVENT_ENDPOINT_CLOSED:
        if (row->phase != SERVICED_PHASE_STOPPING)
        {
            const uint8_t restartable = (uint8_t)(row->restart_policy == SERVICED_RESTART_ALWAYS ||
                                                  row->restart_policy == SERVICED_RESTART_ON_FAILURE);
            if (restartable && ServicedSupervisorPolicyArmAutomaticRestart(row, event->now_ns))
            {
                row->restart_requested = 1;
                row->start_reason = SERVICED_ACTION_REASON_ENDPOINT_LOST;
            }
            else
            {
                row->desired_state = SERVICED_DESIRED_STOPPED;
                row->terminal_after_stop = restartable;
                row->start_reason = SERVICED_ACTION_REASON_ENDPOINT_LOST;
            }
        }
        break;
    case SERVICED_EVENT_EXITED:
    {
        const uint8_t was_stopping = (uint8_t)(row->phase == SERVICED_PHASE_STOPPING);
        row->last_exit_ns = event->now_ns;
        row->last_exit_code = event->exit_code;
        row->adopted = 0;
        ServicedSupervisorInternalClearObserved(&row->observed);
        if (was_stopping)
        {
            if (row->terminal_after_stop != 0)
                EnterCrashLoop(row);
            else if (row->transition_generation == UINT64_MAX)
            {
                row->phase = SERVICED_PHASE_GENERATION_EXHAUSTED;
                row->desired_state = SERVICED_DESIRED_STOPPED;
                row->restart_requested = 0;
            }
            else
            {
                row->phase = SERVICED_PHASE_STOPPED;
                row->restart_requested = 0;
            }
        }
        else
            ApplyNaturalExitPolicy(row, event->failed, event->now_ns);
        break;
    }
    case SERVICED_EVENT_START_FAILED:
        row->last_exit_ns = event->now_ns;
        row->last_exit_code = event->exit_code;
        ApplyNaturalExitPolicy(row, 1, event->now_ns);
        break;
    case SERVICED_EVENT_START_CANCELLED:
        row->adopted = 0;
        ServicedSupervisorInternalClearObserved(&row->observed);
        if (row->terminal_after_stop != 0)
            EnterCrashLoop(row);
        else if (row->transition_generation == UINT64_MAX)
        {
            row->phase = SERVICED_PHASE_GENERATION_EXHAUSTED;
            row->desired_state = SERVICED_DESIRED_STOPPED;
            row->restart_requested = 0;
        }
        else
        {
            row->phase = SERVICED_PHASE_STOPPED;
            row->restart_requested = 0;
        }
        break;
    default:
        return SERVICED_SUPERVISOR_INVALID_EVENT;
    }
    return ServicedSupervisorPolicyReconcileDesired(supervisor, event->now_ns, actions);
}

static uint8_t ReceiptMatches(const ServicedSupervisorImpl* supervisor, const ServicedSupervisorEventReceipt* receipt)
{
    return (uint8_t)(supervisor->has_pending_acknowledgement != 0 &&
                     receipt->manifest_identity == supervisor->pending_receipt.manifest_identity &&
                     receipt->manifest_generation == supervisor->pending_receipt.manifest_generation &&
                     receipt->event_sequence == supervisor->pending_receipt.event_sequence &&
                     receipt->event_fingerprint == supervisor->pending_receipt.event_fingerprint);
}

ServicedSupervisorStatus ServicedSupervisorApplyLifecycleEvent(ServicedSupervisor* supervisor,
                                                               const ServicedSupervisorLifecycleEvent* event,
                                                               ServicedSupervisorEventResult* result_out)
{
    ServicedSupervisorLifecycleEvent event_snapshot;
    ServicedSupervisorImpl* implementation;
    ServicedSupervisorRow* row;
    ServicedSupervisorStatus status;
    if (supervisor == (ServicedSupervisor*)0 || event == (const ServicedSupervisorLifecycleEvent*)0 ||
        result_out == (ServicedSupervisorEventResult*)0)
        return SERVICED_SUPERVISOR_NULL_ARGUMENT;
    if (ServicedSupervisorInternalRangesOverlap(supervisor, sizeof(*supervisor), event, sizeof(*event)) ||
        ServicedSupervisorInternalRangesOverlap(supervisor, sizeof(*supervisor), result_out, sizeof(*result_out)) ||
        ServicedSupervisorInternalRangesOverlap(event, sizeof(*event), result_out, sizeof(*result_out)))
        return SERVICED_SUPERVISOR_ALIASED_STORAGE;
    event_snapshot = *event;
    ServicedSupervisorInternalClear(result_out, (uint32_t)sizeof(*result_out));
    implementation = ServicedSupervisorInternalMutable(supervisor);
    status = ServicedSupervisorPolicyReady(implementation);
    if (status != SERVICED_SUPERVISOR_OK)
    {
        result_out->status = status;
        return status;
    }
    if (implementation->reconciled == 0)
    {
        result_out->status = SERVICED_SUPERVISOR_RECONCILE_REJECTED;
        return result_out->status;
    }
    if (implementation->has_pending_acknowledgement != 0)
    {
        result_out->status = SERVICED_SUPERVISOR_PENDING_ACKNOWLEDGEMENT;
        return result_out->status;
    }
    if (event_snapshot.event_sequence <= implementation->last_acknowledged_event_sequence)
    {
        result_out->status = SERVICED_SUPERVISOR_REPLAYED_EVENT;
        return result_out->status;
    }
    if (implementation->last_acknowledged_event_sequence == UINT64_MAX ||
        event_snapshot.event_sequence != implementation->last_acknowledged_event_sequence + UINT64_C(1))
    {
        result_out->status = SERVICED_SUPERVISOR_OUT_OF_ORDER_EVENT;
        return result_out->status;
    }
    if (!EventShapeIsCanonical(&event_snapshot))
    {
        result_out->status = SERVICED_SUPERVISOR_INVALID_EVENT;
        return result_out->status;
    }
    row = ServicedSupervisorInternalFind(implementation, event_snapshot.service_identity);
    if (row == (ServicedSupervisorRow*)0)
    {
        result_out->status = SERVICED_SUPERVISOR_NOT_FOUND;
        return result_out->status;
    }
    status = ValidateEventForRow(row, &event_snapshot);
    if (status != SERVICED_SUPERVISOR_OK)
    {
        result_out->status = status;
        return status;
    }
    if (event_snapshot.now_ns < implementation->last_now_ns)
    {
        result_out->status = SERVICED_SUPERVISOR_INVALID_TIMESTAMP;
        return result_out->status;
    }

    ServicedSupervisorPolicyAcceptTimestamp(implementation, event_snapshot.now_ns);
    status = ApplyEventMutation(implementation, row, &event_snapshot, &result_out->actions);
    if (status != SERVICED_SUPERVISOR_OK)
    {
        result_out->status = status;
        return status;
    }
    result_out->receipt.manifest_identity = implementation->manifest_identity;
    result_out->receipt.manifest_generation = implementation->manifest_generation;
    result_out->receipt.event_sequence = event_snapshot.event_sequence;
    result_out->receipt.event_fingerprint = EventFingerprint(&event_snapshot);
    implementation->pending_receipt = result_out->receipt;
    implementation->pending_actions = result_out->actions;
    implementation->last_applied_event_sequence = event_snapshot.event_sequence;
    implementation->has_pending_acknowledgement = 1;
    result_out->status = ServicedSupervisorPolicyReady(implementation);
    return result_out->status;
}

ServicedSupervisorStatus ServicedSupervisorGetPendingEventActions(const ServicedSupervisor* supervisor,
                                                                  const ServicedSupervisorEventReceipt* receipt,
                                                                  ServicedSupervisorActionBatch* actions_out)
{
    const ServicedSupervisorImpl* implementation;
    ServicedSupervisorStatus status;
    if (supervisor == (const ServicedSupervisor*)0 || receipt == (const ServicedSupervisorEventReceipt*)0 ||
        actions_out == (ServicedSupervisorActionBatch*)0)
        return SERVICED_SUPERVISOR_NULL_ARGUMENT;
    if (ServicedSupervisorInternalRangesOverlap(supervisor, sizeof(*supervisor), receipt, sizeof(*receipt)) ||
        ServicedSupervisorInternalRangesOverlap(supervisor, sizeof(*supervisor), actions_out, sizeof(*actions_out)) ||
        ServicedSupervisorInternalRangesOverlap(receipt, sizeof(*receipt), actions_out, sizeof(*actions_out)))
        return SERVICED_SUPERVISOR_ALIASED_STORAGE;
    ServicedSupervisorInternalClearBatch(actions_out);
    implementation = ServicedSupervisorInternalReadOnly(supervisor);
    status = ServicedSupervisorInternalValidate(implementation);
    if (status != SERVICED_SUPERVISOR_OK)
        return status;
    if (!ReceiptMatches(implementation, receipt))
        return SERVICED_SUPERVISOR_INVALID_ACKNOWLEDGEMENT;
    *actions_out = implementation->pending_actions;
    return SERVICED_SUPERVISOR_OK;
}

ServicedSupervisorStatus ServicedSupervisorBuildEventAcknowledgement(const ServicedSupervisor* supervisor,
                                                                     const ServicedSupervisorEventReceipt* receipt,
                                                                     ServicedSupervisorAction* action_out)
{
    const ServicedSupervisorImpl* implementation;
    ServicedSupervisorStatus status;
    if (supervisor == (const ServicedSupervisor*)0 || receipt == (const ServicedSupervisorEventReceipt*)0 ||
        action_out == (ServicedSupervisorAction*)0)
        return SERVICED_SUPERVISOR_NULL_ARGUMENT;
    if (ServicedSupervisorInternalRangesOverlap(supervisor, sizeof(*supervisor), receipt, sizeof(*receipt)) ||
        ServicedSupervisorInternalRangesOverlap(supervisor, sizeof(*supervisor), action_out, sizeof(*action_out)) ||
        ServicedSupervisorInternalRangesOverlap(receipt, sizeof(*receipt), action_out, sizeof(*action_out)))
        return SERVICED_SUPERVISOR_ALIASED_STORAGE;
    ServicedSupervisorInternalClear(action_out, (uint32_t)sizeof(*action_out));
    implementation = ServicedSupervisorInternalReadOnly(supervisor);
    status = ServicedSupervisorInternalValidate(implementation);
    if (status != SERVICED_SUPERVISOR_OK)
        return status;
    if (!ReceiptMatches(implementation, receipt))
        return SERVICED_SUPERVISOR_INVALID_ACKNOWLEDGEMENT;
    action_out->type = SERVICED_ACTION_ACKNOWLEDGE_EVENT;
    action_out->event_sequence = receipt->event_sequence;
    return SERVICED_SUPERVISOR_OK;
}

ServicedSupervisorStatus ServicedSupervisorCommitEventAcknowledgement(ServicedSupervisor* supervisor,
                                                                      const ServicedSupervisorEventReceipt* receipt)
{
    ServicedSupervisorImpl* implementation;
    ServicedSupervisorStatus status;
    if (supervisor == (ServicedSupervisor*)0 || receipt == (const ServicedSupervisorEventReceipt*)0)
        return SERVICED_SUPERVISOR_NULL_ARGUMENT;
    if (ServicedSupervisorInternalRangesOverlap(supervisor, sizeof(*supervisor), receipt, sizeof(*receipt)))
        return SERVICED_SUPERVISOR_ALIASED_STORAGE;
    implementation = ServicedSupervisorInternalMutable(supervisor);
    status = ServicedSupervisorPolicyReady(implementation);
    if (status != SERVICED_SUPERVISOR_OK)
        return status;
    if (!ReceiptMatches(implementation, receipt))
        return SERVICED_SUPERVISOR_INVALID_ACKNOWLEDGEMENT;
    implementation->last_acknowledged_event_sequence = receipt->event_sequence;
    implementation->last_applied_event_sequence = receipt->event_sequence;
    implementation->has_pending_acknowledgement = 0;
    ServicedSupervisorInternalClear(&implementation->pending_receipt,
                                    (uint32_t)sizeof(implementation->pending_receipt));
    ServicedSupervisorInternalClearBatch(&implementation->pending_actions);
    return ServicedSupervisorPolicyReady(implementation);
}
