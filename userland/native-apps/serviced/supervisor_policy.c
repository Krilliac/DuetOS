#include "supervisor_internal.h"

ServicedSupervisorStatus ServicedSupervisorPolicyReady(ServicedSupervisorImpl* supervisor)
{
    return ServicedSupervisorInternalValidate(supervisor);
}

uint8_t ServicedSupervisorPolicyPhaseCanStart(uint8_t phase)
{
    return (uint8_t)(phase == SERVICED_PHASE_STOPPED || phase == SERVICED_PHASE_EXITED ||
                     phase == SERVICED_PHASE_FAILED);
}

uint8_t ServicedSupervisorPolicyPhaseCanStop(uint8_t phase)
{
    return (uint8_t)(phase == SERVICED_PHASE_STARTING || phase == SERVICED_PHASE_RUNNING ||
                     phase == SERVICED_PHASE_READY);
}

uint8_t ServicedSupervisorPolicyDependenciesReady(const ServicedSupervisorImpl* supervisor,
                                                  const ServicedSupervisorRow* row)
{
    uint64_t dependencies = row->dependency_mask;
    while (dependencies != 0)
    {
        uint32_t slot;
        uint64_t bit = UINT64_C(1);
        for (slot = 0; slot < SERVICED_SUPERVISOR_MAX_SERVICES; ++slot, bit <<= 1U)
        {
            if ((dependencies & bit) != 0)
            {
                const ServicedSupervisorRow* dependency = &supervisor->rows[slot];
                if (dependency->phase != SERVICED_PHASE_READY ||
                    dependency->desired_state != SERVICED_DESIRED_RUNNING || dependency->restart_requested != 0)
                    return 0;
                dependencies &= ~bit;
                break;
            }
        }
    }
    return 1;
}

static ServicedSupervisorStatus AppendAction(ServicedSupervisorActionBatch* batch,
                                             const ServicedSupervisorAction* action)
{
    if (batch->count >= SERVICED_SUPERVISOR_ACTION_CAPACITY)
        return SERVICED_SUPERVISOR_ACTION_OVERFLOW;
    batch->actions[batch->count] = *action;
    ++batch->count;
    return SERVICED_SUPERVISOR_OK;
}

static ServicedSupervisorStatus ScheduleStart(ServicedSupervisorRow* row, uint64_t now_ns,
                                              ServicedSupervisorActionBatch* actions)
{
    ServicedSupervisorAction action;
    uint64_t expected_generation;
    if (!ServicedSupervisorPolicyPhaseCanStart(row->phase) || row->desired_state != SERVICED_DESIRED_RUNNING)
        return SERVICED_SUPERVISOR_CORRUPT_STATE;
    if (row->transition_generation == UINT64_MAX)
    {
        row->phase = SERVICED_PHASE_GENERATION_EXHAUSTED;
        row->desired_state = SERVICED_DESIRED_STOPPED;
        row->restart_requested = 0;
        row->terminal_after_stop = 0;
        row->start_reason = SERVICED_ACTION_REASON_NONE;
        ServicedSupervisorInternalClearObserved(&row->observed);
        return SERVICED_SUPERVISOR_GENERATION_EXHAUSTED;
    }

    expected_generation = row->transition_generation;
    ServicedSupervisorInternalClear(&action, (uint32_t)sizeof(action));
    action.type = SERVICED_ACTION_START;
    action.reason =
        row->start_reason != SERVICED_ACTION_REASON_NONE ? row->start_reason : SERVICED_ACTION_REASON_MANIFEST_DESIRED;
    action.service_slot = row->service_slot;
    action.service_identity = row->service_identity;
    action.expected_transition_generation = expected_generation;
    action.target_instance_generation = expected_generation + UINT64_C(1);
    if (AppendAction(actions, &action) != SERVICED_SUPERVISOR_OK)
        return SERVICED_SUPERVISOR_ACTION_OVERFLOW;

    row->transition_generation = action.target_instance_generation;
    row->phase = SERVICED_PHASE_STARTING;
    row->adopted = 0;
    row->restart_requested = 0;
    row->terminal_after_stop = 0;
    row->start_reason = SERVICED_ACTION_REASON_NONE;
    row->last_start_ns = now_ns;
    ServicedSupervisorInternalClearObserved(&row->observed);
    if (expected_generation != 0 && row->lifetime_restarts != UINT32_MAX)
        ++row->lifetime_restarts;
    return SERVICED_SUPERVISOR_OK;
}

ServicedSupervisorStatus ServicedSupervisorPolicyScheduleStop(ServicedSupervisorRow* row, uint8_t reason,
                                                              ServicedSupervisorActionBatch* actions)
{
    ServicedSupervisorAction action;
    if (!ServicedSupervisorPolicyPhaseCanStop(row->phase))
        return SERVICED_SUPERVISOR_OK;
    ServicedSupervisorInternalClear(&action, (uint32_t)sizeof(action));
    action.reason = reason;
    action.service_slot = row->service_slot;
    action.service_identity = row->service_identity;
    action.expected_transition_generation = row->transition_generation;
    action.target_instance_generation = row->transition_generation;
    if (row->phase == SERVICED_PHASE_STARTING)
        action.type = SERVICED_ACTION_CANCEL_START;
    else
    {
        if (!ServicedSupervisorObservedIdentityIsCanonical(&row->observed))
            return SERVICED_SUPERVISOR_CORRUPT_STATE;
        action.type = SERVICED_ACTION_STOP_INSTANCE;
        action.observed = row->observed;
    }
    if (AppendAction(actions, &action) != SERVICED_SUPERVISOR_OK)
        return SERVICED_SUPERVISOR_ACTION_OVERFLOW;
    row->phase = SERVICED_PHASE_STOPPING;
    return SERVICED_SUPERVISOR_OK;
}

ServicedSupervisorStatus ServicedSupervisorPolicyReconcileDesired(ServicedSupervisorImpl* supervisor, uint64_t now_ns,
                                                                  ServicedSupervisorActionBatch* actions)
{
    uint32_t ordinal;
    for (ordinal = supervisor->service_count; ordinal != 0; --ordinal)
    {
        const uint32_t slot = supervisor->topological_order[ordinal - 1U];
        ServicedSupervisorRow* row = &supervisor->rows[slot];
        uint8_t reason = SERVICED_ACTION_REASON_NONE;
        if (!ServicedSupervisorPolicyPhaseCanStop(row->phase))
            continue;
        if (row->desired_state == SERVICED_DESIRED_STOPPED)
            reason = (row->start_reason == SERVICED_ACTION_REASON_ENDPOINT_LOST ||
                      row->start_reason == SERVICED_ACTION_REASON_RECONCILE_MISMATCH)
                         ? row->start_reason
                         : SERVICED_ACTION_REASON_OPERATOR;
        else if (row->restart_requested != 0)
            reason = (row->start_reason == SERVICED_ACTION_REASON_ENDPOINT_LOST ||
                      row->start_reason == SERVICED_ACTION_REASON_RECONCILE_MISMATCH)
                         ? row->start_reason
                         : SERVICED_ACTION_REASON_OPERATOR;
        else if (!ServicedSupervisorPolicyDependenciesReady(supervisor, row))
        {
            reason = SERVICED_ACTION_REASON_DEPENDENCY_LOST;
            row->start_reason = SERVICED_ACTION_REASON_DEPENDENCY_LOST;
        }
        if (reason != SERVICED_ACTION_REASON_NONE)
        {
            const ServicedSupervisorStatus status = ServicedSupervisorPolicyScheduleStop(row, reason, actions);
            if (status != SERVICED_SUPERVISOR_OK)
                return status;
        }
    }

    for (ordinal = 0; ordinal < supervisor->service_count; ++ordinal)
    {
        const uint32_t slot = supervisor->topological_order[ordinal];
        ServicedSupervisorRow* row = &supervisor->rows[slot];
        if (row->desired_state == SERVICED_DESIRED_RUNNING && row->restart_requested == 0 &&
            ServicedSupervisorPolicyPhaseCanStart(row->phase) &&
            ServicedSupervisorPolicyDependenciesReady(supervisor, row))
        {
            const ServicedSupervisorStatus status = ScheduleStart(row, now_ns, actions);
            if (status != SERVICED_SUPERVISOR_OK && status != SERVICED_SUPERVISOR_GENERATION_EXHAUSTED)
                return status;
        }
    }
    return SERVICED_SUPERVISOR_OK;
}

static void PruneRestartWindow(ServicedSupervisorRow* row, uint64_t now_ns)
{
    if (row->restart_limit == 0 || row->restart_window_ns == 0)
        return;
    while (row->restart_count != 0)
    {
        const uint64_t oldest = row->restart_times[row->restart_head];
        if (now_ns < oldest || now_ns - oldest < row->restart_window_ns)
            break;
        row->restart_times[row->restart_head] = 0;
        row->restart_head = (uint8_t)((row->restart_head + 1U) % SERVICED_SUPERVISOR_MAX_RESTARTS);
        --row->restart_count;
    }
    if (row->restart_count == 0)
        row->restart_head = 0;
}

uint8_t ServicedSupervisorPolicyArmAutomaticRestart(ServicedSupervisorRow* row, uint64_t now_ns)
{
    uint32_t insertion;
    if (row->restart_policy == SERVICED_RESTART_NEVER || row->restart_limit == 0)
        return 0;
    PruneRestartWindow(row, now_ns);
    if (row->restart_count >= row->restart_limit)
        return 0;
    insertion = ((uint32_t)row->restart_head + row->restart_count) % SERVICED_SUPERVISOR_MAX_RESTARTS;
    row->restart_times[insertion] = now_ns;
    ++row->restart_count;
    row->desired_state = SERVICED_DESIRED_RUNNING;
    row->start_reason = SERVICED_ACTION_REASON_RESTART_POLICY;
    return 1;
}

uint8_t ServicedSupervisorPolicyClearCrashLoopAfterWindow(ServicedSupervisorRow* row, uint64_t now_ns)
{
    if (row->phase != SERVICED_PHASE_CRASH_LOOP)
        return 1;
    PruneRestartWindow(row, now_ns);
    if (row->restart_count >= row->restart_limit)
        return 0;
    row->phase = SERVICED_PHASE_STOPPED;
    row->terminal_after_stop = 0;
    return 1;
}

uint8_t ServicedSupervisorPolicyAcceptTimestamp(ServicedSupervisorImpl* supervisor, uint64_t now_ns)
{
    if (now_ns < supervisor->last_now_ns)
        return 0;
    supervisor->last_now_ns = now_ns;
    return 1;
}
