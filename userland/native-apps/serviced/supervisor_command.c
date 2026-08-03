#include "supervisor_internal.h"

static uint8_t CommandShapeIsCanonical(const ServicedSupervisorCommand* command)
{
    uint32_t index;
    if (command->client_identity == 0 || command->request_id == 0 || command->service_identity == 0 ||
        (command->type != SERVICED_COMMAND_START && command->type != SERVICED_COMMAND_STOP &&
         command->type != SERVICED_COMMAND_RESTART))
        return 0;
    for (index = 0; index < 7; ++index)
    {
        if (command->reserved8[index] != 0)
            return 0;
    }
    return 1;
}

static ServicedSupervisorClientLedger* FindClient(ServicedSupervisorImpl* supervisor, uint64_t client_identity)
{
    uint32_t index;
    for (index = 0; index < SERVICED_SUPERVISOR_MAX_CLIENTS; ++index)
    {
        if (supervisor->clients[index].in_use != 0 && supervisor->clients[index].client_identity == client_identity)
            return &supervisor->clients[index];
    }
    return (ServicedSupervisorClientLedger*)0;
}

static ServicedSupervisorClientLedger* AllocateClient(ServicedSupervisorImpl* supervisor)
{
    uint32_t index;
    for (index = 0; index < SERVICED_SUPERVISOR_MAX_CLIENTS; ++index)
    {
        if (supervisor->clients[index].in_use == 0)
            return &supervisor->clients[index];
    }
    return (ServicedSupervisorClientLedger*)0;
}

static ServicedSupervisorStatus ApplyCommandMutation(ServicedSupervisorImpl* supervisor, ServicedSupervisorRow* row,
                                                     const ServicedSupervisorCommand* command,
                                                     ServicedSupervisorActionBatch* actions)
{
    ServicedSupervisorStatus status;
    if (row->phase == SERVICED_PHASE_GENERATION_EXHAUSTED)
        return SERVICED_SUPERVISOR_GENERATION_EXHAUSTED;
    if ((command->type == SERVICED_COMMAND_START || command->type == SERVICED_COMMAND_RESTART) &&
        !ServicedSupervisorPolicyClearCrashLoopAfterWindow(row, command->now_ns))
        return SERVICED_SUPERVISOR_CRASH_LOOP;

    switch (command->type)
    {
    case SERVICED_COMMAND_START:
        row->desired_state = SERVICED_DESIRED_RUNNING;
        row->start_reason = SERVICED_ACTION_REASON_OPERATOR;
        break;
    case SERVICED_COMMAND_STOP:
        row->desired_state = SERVICED_DESIRED_STOPPED;
        row->restart_requested = 0;
        row->terminal_after_stop = 0;
        row->start_reason = SERVICED_ACTION_REASON_NONE;
        break;
    case SERVICED_COMMAND_RESTART:
        row->desired_state = SERVICED_DESIRED_RUNNING;
        row->start_reason = SERVICED_ACTION_REASON_OPERATOR;
        if (ServicedSupervisorPolicyPhaseCanStop(row->phase) || row->phase == SERVICED_PHASE_STOPPING)
            row->restart_requested = 1;
        else
            row->restart_requested = 0;
        break;
    default:
        return SERVICED_SUPERVISOR_INVALID_COMMAND;
    }

    status = ServicedSupervisorPolicyReconcileDesired(supervisor, command->now_ns, actions);
    if (status != SERVICED_SUPERVISOR_OK)
        return status;
    if ((command->type == SERVICED_COMMAND_START || command->type == SERVICED_COMMAND_RESTART) &&
        row->desired_state == SERVICED_DESIRED_RUNNING && ServicedSupervisorPolicyPhaseCanStart(row->phase) &&
        !ServicedSupervisorPolicyDependenciesReady(supervisor, row))
        return SERVICED_SUPERVISOR_DEPENDENCY_NOT_READY;
    if (row->phase == SERVICED_PHASE_GENERATION_EXHAUSTED)
        return SERVICED_SUPERVISOR_GENERATION_EXHAUSTED;
    return SERVICED_SUPERVISOR_OK;
}

static void CacheCommand(ServicedSupervisorClientLedger* client, const ServicedSupervisorCommand* command,
                         const ServicedSupervisorCommandResult* result)
{
    client->client_identity = command->client_identity;
    client->request_id = command->request_id;
    client->service_identity = command->service_identity;
    client->expected_transition_generation = command->expected_transition_generation;
    client->now_ns = command->now_ns;
    client->status = result->status;
    client->command_type = command->type;
    client->actions = result->actions;
    client->in_use = 1;
}

ServicedSupervisorStatus ServicedSupervisorApplyCommand(ServicedSupervisor* supervisor,
                                                        const ServicedSupervisorCommand* command,
                                                        ServicedSupervisorCommandResult* result_out)
{
    ServicedSupervisorCommand command_snapshot;
    ServicedSupervisorImpl* implementation;
    ServicedSupervisorClientLedger* client;
    ServicedSupervisorRow* row;
    ServicedSupervisorStatus status;
    uint8_t new_client = 0;
    if (supervisor == (ServicedSupervisor*)0 || command == (const ServicedSupervisorCommand*)0 ||
        result_out == (ServicedSupervisorCommandResult*)0)
        return SERVICED_SUPERVISOR_NULL_ARGUMENT;
    if (ServicedSupervisorInternalRangesOverlap(supervisor, sizeof(*supervisor), command, sizeof(*command)) ||
        ServicedSupervisorInternalRangesOverlap(supervisor, sizeof(*supervisor), result_out, sizeof(*result_out)) ||
        ServicedSupervisorInternalRangesOverlap(command, sizeof(*command), result_out, sizeof(*result_out)))
        return SERVICED_SUPERVISOR_ALIASED_STORAGE;
    command_snapshot = *command;
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
    if (!CommandShapeIsCanonical(&command_snapshot))
    {
        result_out->status = SERVICED_SUPERVISOR_INVALID_COMMAND;
        return result_out->status;
    }

    client = FindClient(implementation, command_snapshot.client_identity);
    if (client != (ServicedSupervisorClientLedger*)0)
    {
        if (command_snapshot.request_id < client->request_id)
        {
            result_out->status = SERVICED_SUPERVISOR_REPLAYED_REQUEST;
            return result_out->status;
        }
        if (command_snapshot.request_id == client->request_id)
        {
            if (command_snapshot.type != client->command_type ||
                command_snapshot.service_identity != client->service_identity ||
                command_snapshot.expected_transition_generation != client->expected_transition_generation ||
                command_snapshot.now_ns != client->now_ns)
            {
                result_out->status = SERVICED_SUPERVISOR_REQUEST_ID_CONFLICT;
                return result_out->status;
            }
            result_out->status = client->status;
            result_out->duplicate = 1;
            result_out->actions = client->actions;
            return result_out->status;
        }
    }
    else
    {
        client = AllocateClient(implementation);
        if (client == (ServicedSupervisorClientLedger*)0)
        {
            result_out->status = SERVICED_SUPERVISOR_CLIENT_CAPACITY;
            return result_out->status;
        }
        new_client = 1;
    }
    row = ServicedSupervisorInternalFind(implementation, command_snapshot.service_identity);
    if (row == (ServicedSupervisorRow*)0)
        result_out->status = SERVICED_SUPERVISOR_NOT_FOUND;
    else if (row->transition_generation != command_snapshot.expected_transition_generation)
        result_out->status = SERVICED_SUPERVISOR_STALE_GENERATION;
    else if (!ServicedSupervisorPolicyAcceptTimestamp(implementation, command_snapshot.now_ns))
    {
        result_out->status = SERVICED_SUPERVISOR_INVALID_TIMESTAMP;
        return result_out->status;
    }
    else
        result_out->status = ApplyCommandMutation(implementation, row, &command_snapshot, &result_out->actions);

    if (new_client != 0)
        ++implementation->client_count;
    CacheCommand(client, &command_snapshot, result_out);
    status = ServicedSupervisorPolicyReady(implementation);
    if (status != SERVICED_SUPERVISOR_OK)
    {
        result_out->status = status;
        return status;
    }
    return result_out->status;
}
