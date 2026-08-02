#include "supervisor_internal.h"

static uint8_t ReconcileRowIsCanonical(const ServicedSupervisorImpl* supervisor,
                                       const ServicedSupervisorReconcileRow* row)
{
    const ServicedSupervisorRow* definition;
    const uint8_t lifecycle_zero = ServicedSupervisorInternalObservedIsZero(&row->lifecycle_identity);
    const uint8_t directory_zero = ServicedSupervisorInternalObservedIsZero(&row->directory_identity);
    const uint8_t lifecycle_valid = ServicedSupervisorObservedIdentityIsCanonical(&row->lifecycle_identity);
    const uint8_t directory_valid = ServicedSupervisorObservedIdentityIsCanonical(&row->directory_identity);
    if (row->service_identity == 0 || row->service_slot >= SERVICED_SUPERVISOR_MAX_SERVICES || row->reserved16 != 0 ||
        row->endpoint_ready > 1)
        return 0;
    definition = ServicedSupervisorInternalFindConst(supervisor, row->service_identity);
    if (definition == (const ServicedSupervisorRow*)0 || definition->service_slot != row->service_slot)
        return 0;

    switch (row->phase)
    {
    case SERVICED_PHASE_STOPPED:
    case SERVICED_PHASE_EXITED:
    case SERVICED_PHASE_FAILED:
        return (uint8_t)(row->transition_generation != UINT64_MAX && lifecycle_zero && directory_zero &&
                         row->endpoint_ready == 0);
    case SERVICED_PHASE_GENERATION_EXHAUSTED:
        return (uint8_t)(row->transition_generation == UINT64_MAX && lifecycle_zero && directory_zero &&
                         row->endpoint_ready == 0);
    case SERVICED_PHASE_STARTING:
        return (uint8_t)(row->transition_generation != 0 && lifecycle_zero && directory_zero &&
                         row->endpoint_ready == 0);
    case SERVICED_PHASE_RUNNING:
    case SERVICED_PHASE_READY:
    case SERVICED_PHASE_STOPPING:
        if (row->transition_generation == 0 || !lifecycle_valid ||
            row->lifecycle_identity.service_slot != row->service_slot ||
            row->lifecycle_identity.instance_generation != row->transition_generation)
            return 0;
        if (!directory_zero && !directory_valid)
            return 0;
        if (directory_valid && (row->directory_identity.service_slot != row->service_slot ||
                                row->directory_identity.instance_generation != row->transition_generation))
            return 0;
        return (uint8_t)(row->endpoint_ready == 0 || directory_valid);
    default:
        return 0;
    }
}

static uint8_t ReconcileSnapshotIsCanonical(const ServicedSupervisorImpl* supervisor,
                                            const ServicedSupervisorReconcileSnapshot* snapshot)
{
    uint64_t seen = 0;
    uint32_t index;
    uint32_t other;
    if (snapshot->manifest_identity != supervisor->manifest_identity ||
        snapshot->manifest_generation != supervisor->manifest_generation ||
        snapshot->row_count != supervisor->service_count || snapshot->reserved32 != 0 ||
        snapshot->acknowledged_event_sequence < supervisor->last_acknowledged_event_sequence)
        return 0;
    for (index = 0; index < snapshot->row_count; ++index)
    {
        const ServicedSupervisorReconcileRow* row = &snapshot->rows[index];
        const uint64_t bit =
            row->service_slot < SERVICED_SUPERVISOR_MAX_SERVICES ? (UINT64_C(1) << row->service_slot) : 0;
        if (bit == 0 || (seen & bit) != 0 || !ReconcileRowIsCanonical(supervisor, row))
            return 0;
        seen |= bit;
        if (ServicedSupervisorObservedIdentityIsCanonical(&row->lifecycle_identity))
        {
            for (other = 0; other < index; ++other)
            {
                const ServicedSupervisorReconcileRow* prior = &snapshot->rows[other];
                if (ServicedSupervisorObservedIdentityIsCanonical(&prior->lifecycle_identity) &&
                    (prior->lifecycle_identity.process.identity == row->lifecycle_identity.process.identity ||
                     prior->lifecycle_identity.endpoint_epoch == row->lifecycle_identity.endpoint_epoch))
                    return 0;
            }
        }
    }
    return (uint8_t)(seen == supervisor->present_mask);
}

static void ResetRuntimeRow(ServicedSupervisorRow* row)
{
    row->transition_generation = 0;
    row->last_start_ns = 0;
    row->last_exit_ns = 0;
    ServicedSupervisorInternalClear(row->restart_times, (uint32_t)sizeof(row->restart_times));
    ServicedSupervisorInternalClearObserved(&row->observed);
    row->lifetime_restarts = 0;
    row->last_exit_code = 0;
    row->desired_state = row->autostart != 0 ? SERVICED_DESIRED_RUNNING : SERVICED_DESIRED_STOPPED;
    row->phase = SERVICED_PHASE_STOPPED;
    row->adopted = 0;
    row->restart_head = 0;
    row->restart_count = 0;
    row->restart_requested = 0;
    row->terminal_after_stop = 0;
    row->start_reason = row->autostart != 0 ? SERVICED_ACTION_REASON_MANIFEST_DESIRED : SERVICED_ACTION_REASON_NONE;
}

ServicedSupervisorStatus ServicedSupervisorReconcile(ServicedSupervisor* supervisor,
                                                     const ServicedSupervisorReconcileSnapshot* snapshot,
                                                     ServicedSupervisorActionBatch* actions_out)
{
    ServicedSupervisorImpl* implementation;
    ServicedSupervisorStatus status;
    uint32_t slot;
    uint32_t index;
    if (supervisor == (ServicedSupervisor*)0 || snapshot == (const ServicedSupervisorReconcileSnapshot*)0 ||
        actions_out == (ServicedSupervisorActionBatch*)0)
        return SERVICED_SUPERVISOR_NULL_ARGUMENT;
    if (ServicedSupervisorInternalRangesOverlap(supervisor, sizeof(*supervisor), snapshot, sizeof(*snapshot)) ||
        ServicedSupervisorInternalRangesOverlap(supervisor, sizeof(*supervisor), actions_out, sizeof(*actions_out)) ||
        ServicedSupervisorInternalRangesOverlap(snapshot, sizeof(*snapshot), actions_out, sizeof(*actions_out)))
        return SERVICED_SUPERVISOR_ALIASED_STORAGE;
    ServicedSupervisorInternalClearBatch(actions_out);
    implementation = ServicedSupervisorInternalMutable(supervisor);
    status = ServicedSupervisorPolicyReady(implementation);
    if (status != SERVICED_SUPERVISOR_OK)
        return status;
    if (implementation->reconciled != 0 || implementation->has_pending_acknowledgement != 0)
        return SERVICED_SUPERVISOR_RECONCILE_REJECTED;
    if (snapshot->now_ns < implementation->last_now_ns || !ReconcileSnapshotIsCanonical(implementation, snapshot))
        return snapshot->now_ns < implementation->last_now_ns ? SERVICED_SUPERVISOR_INVALID_TIMESTAMP
                                                              : SERVICED_SUPERVISOR_RECONCILE_REJECTED;

    for (slot = 0; slot < SERVICED_SUPERVISOR_MAX_SERVICES; ++slot)
    {
        if ((implementation->present_mask & (UINT64_C(1) << slot)) != 0)
            ResetRuntimeRow(&implementation->rows[slot]);
    }
    implementation->last_acknowledged_event_sequence = snapshot->acknowledged_event_sequence;
    implementation->last_applied_event_sequence = snapshot->acknowledged_event_sequence;
    implementation->last_now_ns = snapshot->now_ns;

    for (index = 0; index < snapshot->row_count; ++index)
    {
        const ServicedSupervisorReconcileRow* source = &snapshot->rows[index];
        ServicedSupervisorRow* row = &implementation->rows[source->service_slot];
        const uint8_t directory_matches =
            (uint8_t)(ServicedSupervisorObservedIdentityIsCanonical(&source->directory_identity) &&
                      ServicedSupervisorInternalObservedEqual(&source->lifecycle_identity,
                                                              &source->directory_identity));
        row->transition_generation = source->transition_generation;
        switch (source->phase)
        {
        case SERVICED_PHASE_STOPPED:
        case SERVICED_PHASE_EXITED:
        case SERVICED_PHASE_FAILED:
        case SERVICED_PHASE_GENERATION_EXHAUSTED:
            row->phase = source->phase;
            if (source->phase == SERVICED_PHASE_GENERATION_EXHAUSTED)
                row->desired_state = SERVICED_DESIRED_STOPPED;
            break;
        case SERVICED_PHASE_STARTING:
            row->phase = SERVICED_PHASE_STARTING;
            row->desired_state = SERVICED_DESIRED_RUNNING;
            row->restart_requested = 1;
            row->start_reason = SERVICED_ACTION_REASON_RECONCILE_MISMATCH;
            break;
        case SERVICED_PHASE_RUNNING:
        case SERVICED_PHASE_READY:
        case SERVICED_PHASE_STOPPING:
            row->observed = source->lifecycle_identity;
            if (source->phase != SERVICED_PHASE_STOPPING)
                row->desired_state = SERVICED_DESIRED_RUNNING;
            if (directory_matches)
            {
                row->adopted = 1;
                row->phase = source->phase == SERVICED_PHASE_STOPPING
                                 ? SERVICED_PHASE_STOPPING
                                 : (source->endpoint_ready != 0 ? SERVICED_PHASE_READY : SERVICED_PHASE_RUNNING);
            }
            else
            {
                row->adopted = 0;
                row->phase = SERVICED_PHASE_RUNNING;
                row->start_reason = SERVICED_ACTION_REASON_RECONCILE_MISMATCH;
                row->restart_requested = (uint8_t)(row->desired_state == SERVICED_DESIRED_RUNNING);
            }
            break;
        default:
            return SERVICED_SUPERVISOR_CORRUPT_STATE;
        }
    }

    implementation->reconciled = 1;
    status = ServicedSupervisorPolicyReconcileDesired(implementation, snapshot->now_ns, actions_out);
    if (status != SERVICED_SUPERVISOR_OK)
        return status;
    return ServicedSupervisorPolicyReady(implementation);
}
