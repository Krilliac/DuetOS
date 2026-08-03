#include "supervisor_internal.h"

static uint32_t CountBits(uint64_t value)
{
    uint32_t count = 0;
    while (value != 0)
    {
        value &= value - UINT64_C(1);
        ++count;
    }
    return count;
}

void ServicedSupervisorInternalClear(void* storage, uint32_t bytes)
{
    uint8_t* output = (uint8_t*)storage;
    uint32_t index;
    if (output == (uint8_t*)0)
        return;
    for (index = 0; index < bytes; ++index)
        output[index] = 0;
}

void ServicedSupervisorInternalClearBatch(ServicedSupervisorActionBatch* batch)
{
    if (batch != (ServicedSupervisorActionBatch*)0)
        ServicedSupervisorInternalClear(batch, (uint32_t)sizeof(*batch));
}

void ServicedSupervisorInternalClearObserved(ServicedSupervisorObservedIdentity* identity)
{
    if (identity != (ServicedSupervisorObservedIdentity*)0)
        ServicedSupervisorInternalClear(identity, (uint32_t)sizeof(*identity));
}

ServicedSupervisorImpl* ServicedSupervisorInternalMutable(ServicedSupervisor* supervisor)
{
    return (ServicedSupervisorImpl*)(void*)supervisor;
}

const ServicedSupervisorImpl* ServicedSupervisorInternalReadOnly(const ServicedSupervisor* supervisor)
{
    return (const ServicedSupervisorImpl*)(const void*)supervisor;
}

uint8_t ServicedSupervisorInternalRangesOverlap(const void* left, uint64_t left_bytes, const void* right,
                                                uint64_t right_bytes)
{
    uintptr_t left_start;
    uintptr_t right_start;
    if (left == (const void*)0 || right == (const void*)0 || left_bytes == 0 || right_bytes == 0)
        return 0;
    left_start = (uintptr_t)left;
    right_start = (uintptr_t)right;
    if (left_bytes > (uint64_t)UINTPTR_MAX - (uint64_t)left_start ||
        right_bytes > (uint64_t)UINTPTR_MAX - (uint64_t)right_start)
        return 1;
    return (uint8_t)(left_start < right_start + (uintptr_t)right_bytes &&
                     right_start < left_start + (uintptr_t)left_bytes);
}

uint8_t ServicedSupervisorObservedIdentityIsCanonical(const ServicedSupervisorObservedIdentity* identity)
{
    if (identity == (const ServicedSupervisorObservedIdentity*)0)
        return 0;
    return (uint8_t)(identity->service_slot < SERVICED_SUPERVISOR_MAX_SERVICES && identity->reserved32 == 0 &&
                     identity->instance_generation != 0 && identity->process.identity != 0 &&
                     identity->process.pid != 0 && identity->endpoint_epoch != 0);
}

uint8_t ServicedSupervisorInternalObservedIsZero(const ServicedSupervisorObservedIdentity* identity)
{
    const uint8_t* bytes = (const uint8_t*)(const void*)identity;
    uint32_t index;
    if (identity == (const ServicedSupervisorObservedIdentity*)0)
        return 0;
    for (index = 0; index < (uint32_t)sizeof(*identity); ++index)
    {
        if (bytes[index] != 0)
            return 0;
    }
    return 1;
}

uint8_t ServicedSupervisorInternalObservedEqual(const ServicedSupervisorObservedIdentity* left,
                                                const ServicedSupervisorObservedIdentity* right)
{
    if (left == (const ServicedSupervisorObservedIdentity*)0 || right == (const ServicedSupervisorObservedIdentity*)0)
        return 0;
    return (uint8_t)(left->service_slot == right->service_slot && left->reserved32 == right->reserved32 &&
                     left->instance_generation == right->instance_generation &&
                     left->process.identity == right->process.identity && left->process.pid == right->process.pid &&
                     left->endpoint_epoch == right->endpoint_epoch);
}

ServicedSupervisorRow* ServicedSupervisorInternalFind(ServicedSupervisorImpl* supervisor, uint64_t service_identity)
{
    uint32_t slot;
    if (supervisor == (ServicedSupervisorImpl*)0 || service_identity == 0)
        return (ServicedSupervisorRow*)0;
    for (slot = 0; slot < SERVICED_SUPERVISOR_MAX_SERVICES; ++slot)
    {
        if ((supervisor->present_mask & (UINT64_C(1) << slot)) != 0 &&
            supervisor->rows[slot].service_identity == service_identity)
            return &supervisor->rows[slot];
    }
    return (ServicedSupervisorRow*)0;
}

const ServicedSupervisorRow* ServicedSupervisorInternalFindConst(const ServicedSupervisorImpl* supervisor,
                                                                 uint64_t service_identity)
{
    uint32_t slot;
    if (supervisor == (const ServicedSupervisorImpl*)0 || service_identity == 0)
        return (const ServicedSupervisorRow*)0;
    for (slot = 0; slot < SERVICED_SUPERVISOR_MAX_SERVICES; ++slot)
    {
        if ((supervisor->present_mask & (UINT64_C(1) << slot)) != 0 &&
            supervisor->rows[slot].service_identity == service_identity)
            return &supervisor->rows[slot];
    }
    return (const ServicedSupervisorRow*)0;
}

static uint8_t RestartPolicyIsCanonical(const ServicedSupervisorManifestService* service)
{
    if (service->restart_policy == SERVICED_RESTART_NEVER)
        return (uint8_t)(service->restart_limit == 0 && service->restart_window_ns == 0);
    if (service->restart_policy != SERVICED_RESTART_ALWAYS && service->restart_policy != SERVICED_RESTART_ON_FAILURE)
        return 0;
    return (uint8_t)(service->restart_limit != 0 && service->restart_limit <= SERVICED_SUPERVISOR_MAX_RESTARTS &&
                     service->restart_window_ns != 0);
}

static uint8_t ManifestIsCanonical(const ServicedSupervisorManifest* manifest, uint64_t* present_out,
                                   uint8_t topological_order[SERVICED_SUPERVISOR_MAX_SERVICES])
{
    uint64_t dependencies[SERVICED_SUPERVISOR_MAX_SERVICES];
    uint64_t present = 0;
    uint64_t remaining;
    uint32_t index;
    uint32_t other;
    uint32_t ordinal;

    if (manifest == (const ServicedSupervisorManifest*)0 || present_out == (uint64_t*)0 ||
        topological_order == (uint8_t*)0 || manifest->manifest_identity == 0 || manifest->manifest_generation == 0 ||
        manifest->service_count == 0 || manifest->service_count > SERVICED_SUPERVISOR_MAX_SERVICES ||
        manifest->reserved32 != 0)
        return 0;
    ServicedSupervisorInternalClear(dependencies, (uint32_t)sizeof(dependencies));
    ServicedSupervisorInternalClear(topological_order, SERVICED_SUPERVISOR_MAX_SERVICES);

    for (index = 0; index < manifest->service_count; ++index)
    {
        const ServicedSupervisorManifestService* service = &manifest->services[index];
        const uint64_t bit =
            service->service_slot < SERVICED_SUPERVISOR_MAX_SERVICES ? (UINT64_C(1) << service->service_slot) : 0;
        if (service->service_identity == 0 || service->service_identity == UINT64_MAX || bit == 0 ||
            (present & bit) != 0 || service->autostart > 1 || service->reserved8 != 0 ||
            !RestartPolicyIsCanonical(service))
            return 0;
        for (other = 0; other < index; ++other)
        {
            if (manifest->services[other].service_identity == service->service_identity)
                return 0;
        }
        present |= bit;
        dependencies[service->service_slot] = service->dependency_mask;
    }

    for (index = 0; index < manifest->service_count; ++index)
    {
        const ServicedSupervisorManifestService* service = &manifest->services[index];
        const uint64_t self = UINT64_C(1) << service->service_slot;
        if ((service->dependency_mask & ~present) != 0 || (service->dependency_mask & self) != 0)
            return 0;
    }

    remaining = present;
    for (ordinal = 0; ordinal < manifest->service_count; ++ordinal)
    {
        uint32_t selected = SERVICED_SUPERVISOR_MAX_SERVICES;
        for (index = 0; index < SERVICED_SUPERVISOR_MAX_SERVICES; ++index)
        {
            const uint64_t bit = UINT64_C(1) << index;
            if ((remaining & bit) != 0 && (dependencies[index] & remaining) == 0)
            {
                selected = index;
                break;
            }
        }
        if (selected == SERVICED_SUPERVISOR_MAX_SERVICES)
            return 0;
        topological_order[ordinal] = (uint8_t)selected;
        remaining &= ~(UINT64_C(1) << selected);
    }
    *present_out = present;
    return (uint8_t)(remaining == 0);
}

ServicedSupervisorStatus ServicedSupervisorInitialize(ServicedSupervisor* supervisor,
                                                      const ServicedSupervisorManifest* manifest)
{
    uint8_t topological_order[SERVICED_SUPERVISOR_MAX_SERVICES];
    uint64_t present = 0;
    uint32_t index;
    ServicedSupervisorImpl* implementation;

    if (supervisor == (ServicedSupervisor*)0 || manifest == (const ServicedSupervisorManifest*)0)
        return SERVICED_SUPERVISOR_NULL_ARGUMENT;
    if (ServicedSupervisorInternalRangesOverlap(supervisor, sizeof(*supervisor), manifest, sizeof(*manifest)))
        return SERVICED_SUPERVISOR_ALIASED_STORAGE;
    implementation = ServicedSupervisorInternalMutable(supervisor);
    if (implementation->magic == SERVICED_SUPERVISOR_MAGIC)
        return SERVICED_SUPERVISOR_ALREADY_INITIALIZED;
    if (!ManifestIsCanonical(manifest, &present, topological_order))
        return SERVICED_SUPERVISOR_INVALID_MANIFEST;

    ServicedSupervisorInternalClear(supervisor, SERVICED_SUPERVISOR_STORAGE_BYTES);
    implementation->manifest_identity = manifest->manifest_identity;
    implementation->manifest_generation = manifest->manifest_generation;
    implementation->present_mask = present;
    implementation->service_count = manifest->service_count;
    for (index = 0; index < manifest->service_count; ++index)
    {
        const ServicedSupervisorManifestService* service = &manifest->services[index];
        ServicedSupervisorRow* row = &implementation->rows[service->service_slot];
        row->service_identity = service->service_identity;
        row->dependency_mask = service->dependency_mask;
        row->restart_window_ns = service->restart_window_ns;
        row->service_slot = service->service_slot;
        row->restart_policy = service->restart_policy;
        row->autostart = service->autostart;
        row->restart_limit = service->restart_limit;
        row->desired_state = service->autostart != 0 ? SERVICED_DESIRED_RUNNING : SERVICED_DESIRED_STOPPED;
        row->phase = SERVICED_PHASE_STOPPED;
        row->start_reason =
            service->autostart != 0 ? SERVICED_ACTION_REASON_MANIFEST_DESIRED : SERVICED_ACTION_REASON_NONE;
    }
    for (index = 0; index < manifest->service_count; ++index)
        implementation->topological_order[index] = topological_order[index];
    implementation->magic = SERVICED_SUPERVISOR_MAGIC;
    return ServicedSupervisorInternalValidate(implementation);
}

static uint8_t RowIsCanonical(const ServicedSupervisorImpl* supervisor, const ServicedSupervisorRow* row)
{
    const uint8_t observed_canonical = ServicedSupervisorObservedIdentityIsCanonical(&row->observed);
    const uint8_t observed_zero = ServicedSupervisorInternalObservedIsZero(&row->observed);
    if (row->service_identity == 0 || row->service_slot >= SERVICED_SUPERVISOR_MAX_SERVICES ||
        (supervisor->present_mask & (UINT64_C(1) << row->service_slot)) == 0 ||
        (row->dependency_mask & ~supervisor->present_mask) != 0 ||
        (row->dependency_mask & (UINT64_C(1) << row->service_slot)) != 0 || row->autostart > 1 ||
        row->desired_state > SERVICED_DESIRED_RUNNING || row->adopted > 1 || row->restart_count > row->restart_limit ||
        row->restart_count > SERVICED_SUPERVISOR_MAX_RESTARTS ||
        row->restart_head >= SERVICED_SUPERVISOR_MAX_RESTARTS || row->restart_requested > 1 ||
        row->terminal_after_stop > 1)
        return 0;
    if (row->restart_policy == SERVICED_RESTART_NEVER)
    {
        if (row->restart_limit != 0 || row->restart_window_ns != 0)
            return 0;
    }
    else if ((row->restart_policy != SERVICED_RESTART_ALWAYS && row->restart_policy != SERVICED_RESTART_ON_FAILURE) ||
             row->restart_limit == 0 || row->restart_limit > SERVICED_SUPERVISOR_MAX_RESTARTS ||
             row->restart_window_ns == 0)
        return 0;

    if (observed_canonical && (row->observed.service_slot != row->service_slot ||
                               row->observed.instance_generation != row->transition_generation))
        return 0;
    switch (row->phase)
    {
    case SERVICED_PHASE_STOPPED:
    case SERVICED_PHASE_EXITED:
    case SERVICED_PHASE_FAILED:
        return (uint8_t)(observed_zero && row->transition_generation != UINT64_MAX);
    case SERVICED_PHASE_STARTING:
        return (uint8_t)(observed_zero && row->transition_generation != 0 && row->transition_generation != UINT64_MAX &&
                         row->desired_state == SERVICED_DESIRED_RUNNING);
    case SERVICED_PHASE_RUNNING:
    case SERVICED_PHASE_READY:
        return (uint8_t)(observed_canonical && row->desired_state == SERVICED_DESIRED_RUNNING);
    case SERVICED_PHASE_STOPPING:
        return (uint8_t)(row->transition_generation != 0 && (observed_zero || observed_canonical));
    case SERVICED_PHASE_CRASH_LOOP:
        return (uint8_t)(observed_zero && row->desired_state == SERVICED_DESIRED_STOPPED);
    case SERVICED_PHASE_GENERATION_EXHAUSTED:
        return (uint8_t)(observed_zero && row->transition_generation == UINT64_MAX &&
                         row->desired_state == SERVICED_DESIRED_STOPPED);
    default:
        return 0;
    }
}

ServicedSupervisorStatus ServicedSupervisorInternalValidate(const ServicedSupervisorImpl* supervisor)
{
    uint64_t seen = 0;
    uint64_t dependency_ready = 0;
    uint32_t ordinal;
    uint32_t clients = 0;
    if (supervisor == (const ServicedSupervisorImpl*)0)
        return SERVICED_SUPERVISOR_NULL_ARGUMENT;
    if (supervisor->magic != SERVICED_SUPERVISOR_MAGIC)
        return SERVICED_SUPERVISOR_NOT_INITIALIZED;
    if (supervisor->manifest_identity == 0 || supervisor->manifest_generation == 0 || supervisor->service_count == 0 ||
        supervisor->service_count > SERVICED_SUPERVISOR_MAX_SERVICES ||
        CountBits(supervisor->present_mask) != supervisor->service_count || supervisor->reconciled > 1 ||
        supervisor->has_pending_acknowledgement > 1)
        return SERVICED_SUPERVISOR_CORRUPT_STATE;

    for (ordinal = 0; ordinal < supervisor->service_count; ++ordinal)
    {
        const uint32_t slot = supervisor->topological_order[ordinal];
        const uint64_t bit = slot < SERVICED_SUPERVISOR_MAX_SERVICES ? (UINT64_C(1) << slot) : 0;
        const ServicedSupervisorRow* row;
        if (bit == 0 || (supervisor->present_mask & bit) == 0 || (seen & bit) != 0)
            return SERVICED_SUPERVISOR_CORRUPT_STATE;
        row = &supervisor->rows[slot];
        if (!RowIsCanonical(supervisor, row) || (row->dependency_mask & ~dependency_ready) != 0)
            return SERVICED_SUPERVISOR_CORRUPT_STATE;
        seen |= bit;
        dependency_ready |= bit;
    }
    if (seen != supervisor->present_mask)
        return SERVICED_SUPERVISOR_CORRUPT_STATE;

    for (ordinal = 0; ordinal < SERVICED_SUPERVISOR_MAX_CLIENTS; ++ordinal)
    {
        const ServicedSupervisorClientLedger* client = &supervisor->clients[ordinal];
        if (client->in_use > 1)
            return SERVICED_SUPERVISOR_CORRUPT_STATE;
        if (client->in_use != 0)
        {
            if (client->client_identity == 0 || client->request_id == 0 ||
                client->actions.count > SERVICED_SUPERVISOR_ACTION_CAPACITY)
                return SERVICED_SUPERVISOR_CORRUPT_STATE;
            ++clients;
        }
    }
    if (clients != supervisor->client_count)
        return SERVICED_SUPERVISOR_CORRUPT_STATE;

    if (supervisor->has_pending_acknowledgement != 0)
    {
        if (supervisor->pending_receipt.manifest_identity != supervisor->manifest_identity ||
            supervisor->pending_receipt.manifest_generation != supervisor->manifest_generation ||
            supervisor->pending_receipt.event_sequence == 0 ||
            supervisor->pending_receipt.event_sequence != supervisor->last_applied_event_sequence ||
            supervisor->last_applied_event_sequence <= supervisor->last_acknowledged_event_sequence ||
            supervisor->pending_actions.count > SERVICED_SUPERVISOR_ACTION_CAPACITY)
            return SERVICED_SUPERVISOR_CORRUPT_STATE;
    }
    else if (supervisor->last_applied_event_sequence != supervisor->last_acknowledged_event_sequence)
        return SERVICED_SUPERVISOR_CORRUPT_STATE;
    return SERVICED_SUPERVISOR_OK;
}

static void SnapshotRow(const ServicedSupervisorRow* row, ServicedSupervisorServiceSnapshot* snapshot)
{
    ServicedSupervisorInternalClear(snapshot, (uint32_t)sizeof(*snapshot));
    snapshot->service_identity = row->service_identity;
    snapshot->dependency_mask = row->dependency_mask;
    snapshot->transition_generation = row->transition_generation;
    snapshot->last_start_ns = row->last_start_ns;
    snapshot->last_exit_ns = row->last_exit_ns;
    snapshot->observed = row->observed;
    snapshot->service_slot = row->service_slot;
    snapshot->lifetime_restarts = row->lifetime_restarts;
    snapshot->restarts_in_window = row->restart_count;
    snapshot->last_exit_code = row->last_exit_code;
    snapshot->restart_policy = row->restart_policy;
    snapshot->desired_state = row->desired_state;
    snapshot->phase = row->phase;
    snapshot->adopted = row->adopted;
}

ServicedSupervisorStatus ServicedSupervisorDescribe(const ServicedSupervisor* supervisor,
                                                    ServicedSupervisorSnapshot* snapshot_out)
{
    const ServicedSupervisorImpl* implementation;
    ServicedSupervisorStatus status;
    if (supervisor == (const ServicedSupervisor*)0 || snapshot_out == (ServicedSupervisorSnapshot*)0)
        return SERVICED_SUPERVISOR_NULL_ARGUMENT;
    if (ServicedSupervisorInternalRangesOverlap(supervisor, sizeof(*supervisor), snapshot_out, sizeof(*snapshot_out)))
        return SERVICED_SUPERVISOR_ALIASED_STORAGE;
    ServicedSupervisorInternalClear(snapshot_out, (uint32_t)sizeof(*snapshot_out));
    implementation = ServicedSupervisorInternalReadOnly(supervisor);
    status = ServicedSupervisorInternalValidate(implementation);
    if (status != SERVICED_SUPERVISOR_OK)
        return status;
    snapshot_out->manifest_identity = implementation->manifest_identity;
    snapshot_out->manifest_generation = implementation->manifest_generation;
    snapshot_out->last_acknowledged_event_sequence = implementation->last_acknowledged_event_sequence;
    snapshot_out->last_applied_event_sequence = implementation->last_applied_event_sequence;
    snapshot_out->last_now_ns = implementation->last_now_ns;
    snapshot_out->service_count = implementation->service_count;
    snapshot_out->client_count = implementation->client_count;
    snapshot_out->has_pending_acknowledgement = implementation->has_pending_acknowledgement;
    snapshot_out->reconciled = implementation->reconciled;
    return SERVICED_SUPERVISOR_OK;
}

ServicedSupervisorStatus ServicedSupervisorInspect(const ServicedSupervisor* supervisor, uint64_t service_identity,
                                                   ServicedSupervisorServiceSnapshot* snapshot_out)
{
    const ServicedSupervisorImpl* implementation;
    const ServicedSupervisorRow* row;
    ServicedSupervisorStatus status;
    if (supervisor == (const ServicedSupervisor*)0 || snapshot_out == (ServicedSupervisorServiceSnapshot*)0)
        return SERVICED_SUPERVISOR_NULL_ARGUMENT;
    if (ServicedSupervisorInternalRangesOverlap(supervisor, sizeof(*supervisor), snapshot_out, sizeof(*snapshot_out)))
        return SERVICED_SUPERVISOR_ALIASED_STORAGE;
    ServicedSupervisorInternalClear(snapshot_out, (uint32_t)sizeof(*snapshot_out));
    implementation = ServicedSupervisorInternalReadOnly(supervisor);
    status = ServicedSupervisorInternalValidate(implementation);
    if (status != SERVICED_SUPERVISOR_OK)
        return status;
    row = ServicedSupervisorInternalFindConst(implementation, service_identity);
    if (row == (const ServicedSupervisorRow*)0)
        return SERVICED_SUPERVISOR_NOT_FOUND;
    SnapshotRow(row, snapshot_out);
    return SERVICED_SUPERVISOR_OK;
}

ServicedSupervisorStatus ServicedSupervisorInspectAt(const ServicedSupervisor* supervisor, uint32_t ordinal,
                                                     ServicedSupervisorServiceSnapshot* snapshot_out)
{
    const ServicedSupervisorImpl* implementation;
    ServicedSupervisorStatus status;
    uint32_t slot;
    if (supervisor == (const ServicedSupervisor*)0 || snapshot_out == (ServicedSupervisorServiceSnapshot*)0)
        return SERVICED_SUPERVISOR_NULL_ARGUMENT;
    if (ServicedSupervisorInternalRangesOverlap(supervisor, sizeof(*supervisor), snapshot_out, sizeof(*snapshot_out)))
        return SERVICED_SUPERVISOR_ALIASED_STORAGE;
    ServicedSupervisorInternalClear(snapshot_out, (uint32_t)sizeof(*snapshot_out));
    implementation = ServicedSupervisorInternalReadOnly(supervisor);
    status = ServicedSupervisorInternalValidate(implementation);
    if (status != SERVICED_SUPERVISOR_OK)
        return status;
    if (ordinal >= implementation->service_count)
        return SERVICED_SUPERVISOR_NOT_FOUND;
    slot = implementation->topological_order[ordinal];
    SnapshotRow(&implementation->rows[slot], snapshot_out);
    return SERVICED_SUPERVISOR_OK;
}

const char* ServicedSupervisorStatusName(ServicedSupervisorStatus status)
{
    switch (status)
    {
    case SERVICED_SUPERVISOR_OK:
        return "ok";
    case SERVICED_SUPERVISOR_NULL_ARGUMENT:
        return "null_argument";
    case SERVICED_SUPERVISOR_ALIASED_STORAGE:
        return "aliased_storage";
    case SERVICED_SUPERVISOR_INVALID_MANIFEST:
        return "invalid_manifest";
    case SERVICED_SUPERVISOR_ALREADY_INITIALIZED:
        return "already_initialized";
    case SERVICED_SUPERVISOR_NOT_INITIALIZED:
        return "not_initialized";
    case SERVICED_SUPERVISOR_CORRUPT_STATE:
        return "corrupt_state";
    case SERVICED_SUPERVISOR_NOT_FOUND:
        return "not_found";
    case SERVICED_SUPERVISOR_INVALID_TIMESTAMP:
        return "invalid_timestamp";
    case SERVICED_SUPERVISOR_STALE_GENERATION:
        return "stale_generation";
    case SERVICED_SUPERVISOR_GENERATION_EXHAUSTED:
        return "generation_exhausted";
    case SERVICED_SUPERVISOR_DEPENDENCY_NOT_READY:
        return "dependency_not_ready";
    case SERVICED_SUPERVISOR_CRASH_LOOP:
        return "crash_loop";
    case SERVICED_SUPERVISOR_INVALID_EVENT:
        return "invalid_event";
    case SERVICED_SUPERVISOR_REPLAYED_EVENT:
        return "replayed_event";
    case SERVICED_SUPERVISOR_OUT_OF_ORDER_EVENT:
        return "out_of_order_event";
    case SERVICED_SUPERVISOR_WRONG_INSTANCE:
        return "wrong_instance";
    case SERVICED_SUPERVISOR_PENDING_ACKNOWLEDGEMENT:
        return "pending_acknowledgement";
    case SERVICED_SUPERVISOR_INVALID_ACKNOWLEDGEMENT:
        return "invalid_acknowledgement";
    case SERVICED_SUPERVISOR_INVALID_COMMAND:
        return "invalid_command";
    case SERVICED_SUPERVISOR_REPLAYED_REQUEST:
        return "replayed_request";
    case SERVICED_SUPERVISOR_REQUEST_ID_CONFLICT:
        return "request_id_conflict";
    case SERVICED_SUPERVISOR_CLIENT_CAPACITY:
        return "client_capacity";
    case SERVICED_SUPERVISOR_ACTION_OVERFLOW:
        return "action_overflow";
    case SERVICED_SUPERVISOR_RECONCILE_REJECTED:
        return "reconcile_rejected";
    default:
        return "unknown";
    }
}
