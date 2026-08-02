#include "worker_internal.h"

static uint8_t FormatHintIsValid(uint16_t format_hint)
{
    return format_hint == EXECD_WORKER_FORMAT_AUTO || format_hint == EXECD_WORKER_FORMAT_PE32_PLUS ||
           format_hint == EXECD_WORKER_FORMAT_PE32 || format_hint == EXECD_WORKER_FORMAT_ELF64;
}

static uint8_t ParseRequestIsCanonical(const ExecdWorkerParseRequest* request)
{
    return request != 0 && request->request_id != 0 && ExecdWorkerInternalSourceIsCanonical(&request->source) &&
           request->flags == 0 && request->dependency_count == 0 && FormatHintIsValid(request->format_hint) &&
           request->reserved16 == 0 && request->reserved32 == 0;
}

static uint8_t CleanupHasWork(const ExecdWorkerCleanupRecord* cleanup)
{
    return cleanup != 0 && (cleanup->release_source_import || cleanup->plan_disposition != EXECD_WORKER_PLAN_NONE);
}

static void DetachSource(ExecdWorkerImpl* worker, uint32_t request_slot, ExecdWorkerCleanupRecord* cleanup)
{
    ExecdWorkerRequestRow* request = &worker->requests[request_slot];

    if (!request->source_retained)
        return;
    cleanup->request = ExecdWorkerInternalMakeRequestReceipt(worker, request_slot);
    cleanup->release_source_import = 1;
    cleanup->source_transfer_reference = request->request.source.transfer_reference;
    cleanup->source_object_identity = request->request.source.object_identity;
    request->source_retained = 0;
}

static void DetachPlan(ExecdWorkerImpl* worker, uint32_t request_slot, ExecdWorkerPlanDisposition disposition,
                       ExecdWorkerCleanupRecord* cleanup)
{
    ExecdWorkerRequestRow* request = &worker->requests[request_slot];

    if (!request->plan_retained)
        return;
    cleanup->request = ExecdWorkerInternalMakeRequestReceipt(worker, request_slot);
    cleanup->plan_disposition = (uint8_t)disposition;
    cleanup->plan_transfer_reference = request->plan.transfer_reference;
    cleanup->plan_object_identity = request->plan.object_identity;
    request->plan_retained = 0;
    ExecdWorkerInternalClear(&request->plan, (uint32_t)sizeof(request->plan));
}

static ExecdWorkerStatus ValidateOpen(ExecdWorkerImpl* worker)
{
    ExecdWorkerStatus status = ExecdWorkerInternalValidate(worker);

    if (status != EXECD_WORKER_OK)
        return status;
    if (worker->state == EXECD_WORKER_STATE_DRAINING)
        return EXECD_WORKER_DRAINING;
    if (worker->state == EXECD_WORKER_STATE_CLOSED)
        return EXECD_WORKER_CLOSED;
    return EXECD_WORKER_OK;
}

ExecdWorkerStatus ExecdWorkerSubmit(ExecdWorker* worker, const ExecdWorkerPeerReceipt* peer,
                                    const ExecdWorkerParseRequest* request, ExecdWorkerRequestReceipt* receipt_out)
{
    ExecdWorkerPeerReceipt peer_snapshot;
    ExecdWorkerParseRequest request_snapshot;
    ExecdWorkerImpl* implementation;
    ExecdWorkerPeerRow* peer_row = 0;
    uint32_t offset;
    uint32_t free_slot = EXECD_WORKER_MAX_REQUESTS;
    uint8_t retired_seen = 0;
    ExecdWorkerStatus status;

    if (worker == 0 || peer == 0 || request == 0 || receipt_out == 0)
        return EXECD_WORKER_NULL_ARGUMENT;
    if (ExecdWorkerInternalRangesOverlap(worker, sizeof(*worker), peer, sizeof(*peer)) ||
        ExecdWorkerInternalRangesOverlap(worker, sizeof(*worker), request, sizeof(*request)) ||
        ExecdWorkerInternalRangesOverlap(worker, sizeof(*worker), receipt_out, sizeof(*receipt_out)))
        return EXECD_WORKER_ALIASED_STORAGE;
    peer_snapshot = *peer;
    request_snapshot = *request;
    ExecdWorkerInternalClearRequestReceipt(receipt_out);
    implementation = ExecdWorkerInternalMutable(worker);
    status = ValidateOpen(implementation);
    if (status != EXECD_WORKER_OK)
        return status;
    status = ExecdWorkerInternalResolvePeer(implementation, &peer_snapshot, 0, &peer_row);
    if (status != EXECD_WORKER_OK)
        return status;
    if (!ParseRequestIsCanonical(&request_snapshot))
        return EXECD_WORKER_INVALID_ARGUMENT;
    if (peer_row->next_request_id == 0)
        return EXECD_WORKER_SEQUENCE_EXHAUSTED;
    if (request_snapshot.request_id < peer_row->next_request_id)
        return EXECD_WORKER_REPLAYED_REQUEST;
    if (request_snapshot.request_id > peer_row->next_request_id)
        return EXECD_WORKER_OUT_OF_ORDER_REQUEST;

    for (offset = 0; offset < EXECD_WORKER_MAX_REQUESTS; ++offset)
    {
        const uint32_t index = (implementation->next_request_hint + offset) % EXECD_WORKER_MAX_REQUESTS;
        const ExecdWorkerRequestRow* row = &implementation->requests[index];
        if (row->state == EXECD_WORKER_SLOT_RETIRED)
            retired_seen = 1;
        else if (row->state == EXECD_WORKER_SLOT_FREE && free_slot == EXECD_WORKER_MAX_REQUESTS)
            free_slot = index;
    }
    if (free_slot == EXECD_WORKER_MAX_REQUESTS)
        return retired_seen && implementation->request_count < EXECD_WORKER_MAX_REQUESTS
                   ? EXECD_WORKER_GENERATION_EXHAUSTED
                   : EXECD_WORKER_REQUEST_CAPACITY;

    {
        ExecdWorkerRequestRow* row = &implementation->requests[free_slot];
        const uint64_t generation = row->generation;
        ExecdWorkerInternalClear(row, (uint32_t)sizeof(*row));
        row->request = request_snapshot;
        row->generation = generation;
        row->peer_generation = peer_snapshot.peer_generation;
        row->request_id = request_snapshot.request_id;
        row->peer_slot = peer_snapshot.peer_slot;
        row->state = EXECD_WORKER_SLOT_QUEUED;
        row->source_retained = 1;
    }
    peer_row->next_request_id =
        request_snapshot.request_id == UINT64_MAX ? 0 : request_snapshot.request_id + UINT64_C(1);
    ++peer_row->active_requests;
    ++implementation->request_count;
    implementation->next_request_hint = (free_slot + 1U) % EXECD_WORKER_MAX_REQUESTS;
    *receipt_out = ExecdWorkerInternalMakeRequestReceipt(implementation, free_slot);
    return ExecdWorkerInternalValidate(implementation);
}

ExecdWorkerStatus ExecdWorkerClaimNext(ExecdWorker* worker, ExecdWorkerWorkItem* work_out)
{
    ExecdWorkerImpl* implementation;
    ExecdWorkerWorkItem work;
    uint32_t offset;
    ExecdWorkerStatus status;

    if (worker == 0 || work_out == 0)
        return EXECD_WORKER_NULL_ARGUMENT;
    if (ExecdWorkerInternalRangesOverlap(worker, sizeof(*worker), work_out, sizeof(*work_out)))
        return EXECD_WORKER_ALIASED_STORAGE;
    ExecdWorkerInternalClear(&work, (uint32_t)sizeof(work));
    ExecdWorkerInternalClear(work_out, (uint32_t)sizeof(*work_out));
    implementation = ExecdWorkerInternalMutable(worker);
    status = ValidateOpen(implementation);
    if (status != EXECD_WORKER_OK)
        return status;
    for (offset = 0; offset < EXECD_WORKER_MAX_REQUESTS; ++offset)
    {
        const uint32_t index = (implementation->next_work_hint + offset) % EXECD_WORKER_MAX_REQUESTS;
        ExecdWorkerRequestRow* request = &implementation->requests[index];
        if (request->state != EXECD_WORKER_SLOT_QUEUED)
            continue;
        if (implementation->peers[request->peer_slot].state != EXECD_WORKER_PEER_STATE_OPEN)
            return EXECD_WORKER_CORRUPT_STATE;
        request->state = EXECD_WORKER_SLOT_RUNNING;
        work.lease.request = ExecdWorkerInternalMakeRequestReceipt(implementation, index);
        work.request = request->request;
        implementation->next_work_hint = (index + 1U) % EXECD_WORKER_MAX_REQUESTS;
        *work_out = work;
        return ExecdWorkerInternalValidate(implementation);
    }
    return EXECD_WORKER_NO_WORK;
}

ExecdWorkerStatus ExecdWorkerCheckCancellation(const ExecdWorker* worker, const ExecdWorkerWorkLease* lease,
                                               uint8_t* cancellation_out)
{
    const ExecdWorkerImpl* implementation;
    const ExecdWorkerRequestRow* request = 0;
    const ExecdWorkerPeerRow* peer;
    ExecdWorkerWorkLease lease_snapshot;
    ExecdWorkerStatus status;

    if (worker == 0 || lease == 0 || cancellation_out == 0)
        return EXECD_WORKER_NULL_ARGUMENT;
    if (ExecdWorkerInternalRangesOverlap(worker, sizeof(*worker), lease, sizeof(*lease)) ||
        ExecdWorkerInternalRangesOverlap(worker, sizeof(*worker), cancellation_out, sizeof(*cancellation_out)))
        return EXECD_WORKER_ALIASED_STORAGE;
    lease_snapshot = *lease;
    *cancellation_out = 0;
    implementation = ExecdWorkerInternalReadOnly(worker);
    status = ExecdWorkerInternalValidate(implementation);
    if (status != EXECD_WORKER_OK)
        return status;
    status = ExecdWorkerInternalResolveRequestConst(implementation, &lease_snapshot.request, &request);
    if (status != EXECD_WORKER_OK || request->state != EXECD_WORKER_SLOT_RUNNING)
        return EXECD_WORKER_STALE_WORK;
    peer = &implementation->peers[request->peer_slot];
    *cancellation_out = request->cancel_requested || peer->state == EXECD_WORKER_PEER_STATE_CLOSING ||
                        implementation->state == EXECD_WORKER_STATE_DRAINING;
    return EXECD_WORKER_OK;
}

ExecdWorkerCancelResult ExecdWorkerCancel(ExecdWorker* worker, const ExecdWorkerPeerReceipt* peer, uint64_t request_id)
{
    ExecdWorkerCancelResult result;
    ExecdWorkerPeerReceipt peer_snapshot;
    ExecdWorkerImpl* implementation;
    ExecdWorkerPeerRow* peer_row = 0;
    ExecdWorkerRequestRow* request;
    int32_t request_slot;
    ExecdWorkerStatus status;

    ExecdWorkerInternalClearCancelResult(&result);
    if (worker == 0 || peer == 0)
    {
        result.status = EXECD_WORKER_NULL_ARGUMENT;
        return result;
    }
    if (ExecdWorkerInternalRangesOverlap(worker, sizeof(*worker), peer, sizeof(*peer)))
    {
        result.status = EXECD_WORKER_ALIASED_STORAGE;
        return result;
    }
    peer_snapshot = *peer;
    implementation = ExecdWorkerInternalMutable(worker);
    status = ValidateOpen(implementation);
    if (status != EXECD_WORKER_OK)
    {
        result.status = status;
        return result;
    }
    status = ExecdWorkerInternalResolvePeer(implementation, &peer_snapshot, 0, &peer_row);
    if (status != EXECD_WORKER_OK)
    {
        result.status = status;
        return result;
    }
    if (request_id == 0)
    {
        result.status = EXECD_WORKER_INVALID_ARGUMENT;
        return result;
    }
    request_slot = ExecdWorkerInternalFindRequest(implementation, peer_snapshot.peer_slot,
                                                  peer_snapshot.peer_generation, request_id);
    if (request_slot < 0)
    {
        if (peer_row->next_request_id == 0 || request_id < peer_row->next_request_id)
            result.status = EXECD_WORKER_REPLAYED_REQUEST;
        else if (request_id > peer_row->next_request_id)
            result.status = EXECD_WORKER_OUT_OF_ORDER_REQUEST;
        else
            result.status = EXECD_WORKER_REQUEST_NOT_FOUND;
        return result;
    }

    request = &implementation->requests[(uint32_t)request_slot];
    switch (request->state)
    {
    case EXECD_WORKER_SLOT_QUEUED:
        ExecdWorkerInternalMakeFailureReply(request, EXECD_WORKER_REPLY_CANCELLED);
        request->state = EXECD_WORKER_SLOT_REPLY_READY;
        DetachSource(implementation, (uint32_t)request_slot, &result.cleanup);
        result.cancellation_requested = 1;
        result.reply_ready = 1;
        break;
    case EXECD_WORKER_SLOT_RUNNING:
        if (request->cancel_requested)
        {
            result.status = EXECD_WORKER_REPLAYED_REQUEST;
            return result;
        }
        request->cancel_requested = 1;
        result.cancellation_requested = 1;
        break;
    case EXECD_WORKER_SLOT_REPLY_READY:
        if (request->reply.status == EXECD_WORKER_REPLY_CANCELLED)
        {
            result.status = EXECD_WORKER_REPLAYED_REQUEST;
            return result;
        }
        DetachPlan(implementation, (uint32_t)request_slot, EXECD_WORKER_PLAN_DISCARD, &result.cleanup);
        ExecdWorkerInternalMakeFailureReply(request, EXECD_WORKER_REPLY_CANCELLED);
        result.cancellation_requested = 1;
        result.reply_ready = 1;
        break;
    case EXECD_WORKER_SLOT_REPLY_PUBLISHING:
        result.status = EXECD_WORKER_CANCEL_TOO_LATE;
        return result;
    default:
        result.status = EXECD_WORKER_CORRUPT_STATE;
        return result;
    }
    result.status = ExecdWorkerInternalValidate(implementation);
    return result;
}

ExecdWorkerCompleteResult ExecdWorkerComplete(ExecdWorker* worker, const ExecdWorkerWorkLease* lease,
                                              const ExecdWorkerCompletion* completion)
{
    ExecdWorkerCompleteResult result;
    ExecdWorkerWorkLease lease_snapshot;
    ExecdWorkerCompletion completion_snapshot;
    ExecdWorkerImpl* implementation;
    ExecdWorkerRequestRow* request = 0;
    ExecdWorkerPeerRow* peer;
    ExecdWorkerStatus status;
    uint32_t request_slot;

    ExecdWorkerInternalClearCompleteResult(&result);
    if (worker == 0 || lease == 0 || completion == 0)
    {
        result.status = EXECD_WORKER_NULL_ARGUMENT;
        return result;
    }
    if (ExecdWorkerInternalRangesOverlap(worker, sizeof(*worker), lease, sizeof(*lease)) ||
        ExecdWorkerInternalRangesOverlap(worker, sizeof(*worker), completion, sizeof(*completion)))
    {
        result.status = EXECD_WORKER_ALIASED_STORAGE;
        return result;
    }
    lease_snapshot = *lease;
    completion_snapshot = *completion;
    implementation = ExecdWorkerInternalMutable(worker);
    status = ExecdWorkerInternalValidate(implementation);
    if (status != EXECD_WORKER_OK)
    {
        result.status = status;
        return result;
    }
    status = ExecdWorkerInternalResolveRequest(implementation, &lease_snapshot.request, &request);
    if (status != EXECD_WORKER_OK || request->state != EXECD_WORKER_SLOT_RUNNING)
    {
        result.status = EXECD_WORKER_STALE_WORK;
        return result;
    }
    if (!ExecdWorkerInternalCompletionIsCanonical(request, &completion_snapshot))
    {
        result.status = EXECD_WORKER_INVALID_COMPLETION;
        return result;
    }
    request_slot = lease_snapshot.request.request_slot;
    peer = &implementation->peers[request->peer_slot];
    if (completion_snapshot.reply_status == EXECD_WORKER_REPLY_SUCCESS)
    {
        request->plan = completion_snapshot.plan;
        request->plan_retained = 1;
    }

    if (peer->state == EXECD_WORKER_PEER_STATE_CLOSING || implementation->state == EXECD_WORKER_STATE_DRAINING)
    {
        const ExecdWorkerPlanDisposition disposition =
            request->plan_retained ? EXECD_WORKER_PLAN_DISCARD : EXECD_WORKER_PLAN_NONE;
        status = ExecdWorkerInternalRetireRequest(implementation, request_slot, disposition, &result.cleanup);
        result.status = status == EXECD_WORKER_OK ? ExecdWorkerInternalValidate(implementation) : status;
        result.request_discarded = result.status == EXECD_WORKER_OK;
        return result;
    }

    DetachSource(implementation, request_slot, &result.cleanup);
    if (request->cancel_requested || completion_snapshot.reply_status == EXECD_WORKER_REPLY_CANCELLED)
    {
        DetachPlan(implementation, request_slot, EXECD_WORKER_PLAN_DISCARD, &result.cleanup);
        ExecdWorkerInternalMakeFailureReply(request, EXECD_WORKER_REPLY_CANCELLED);
    }
    else if (completion_snapshot.reply_status == EXECD_WORKER_REPLY_SUCCESS)
    {
        uint32_t index;
        request->reply.request_id = request->request_id;
        request->reply.status = EXECD_WORKER_REPLY_SUCCESS;
        request->reply.immutable_policy_id = EXECD_WORKER_LOAD_PLAN_POLICY_V1;
        request->reply.load_plan_object_ref = request->plan.transfer_reference;
        for (index = 0; index < 32U; ++index)
            request->reply.source_hash[index] = request->request.source.source_hash[index];
    }
    else
        ExecdWorkerInternalMakeFailureReply(request, (ExecdWorkerReplyStatus)completion_snapshot.reply_status);
    request->cancel_requested = 0;
    request->state = EXECD_WORKER_SLOT_REPLY_READY;
    result.reply_ready = 1;
    result.status = ExecdWorkerInternalValidate(implementation);
    return result;
}

ExecdWorkerStatus ExecdWorkerGetNextReply(ExecdWorker* worker, ExecdWorkerReplyPublication* reply_out)
{
    ExecdWorkerImpl* implementation;
    ExecdWorkerReplyPublication reply;
    uint32_t index;
    uint32_t offset;
    ExecdWorkerStatus status;

    if (worker == 0 || reply_out == 0)
        return EXECD_WORKER_NULL_ARGUMENT;
    if (ExecdWorkerInternalRangesOverlap(worker, sizeof(*worker), reply_out, sizeof(*reply_out)))
        return EXECD_WORKER_ALIASED_STORAGE;
    ExecdWorkerInternalClearReplyPublication(&reply);
    ExecdWorkerInternalClearReplyPublication(reply_out);
    implementation = ExecdWorkerInternalMutable(worker);
    status = ValidateOpen(implementation);
    if (status != EXECD_WORKER_OK)
        return status;
    for (index = 0; index < EXECD_WORKER_MAX_REQUESTS; ++index)
    {
        if (implementation->requests[index].state == EXECD_WORKER_SLOT_REPLY_PUBLISHING)
            return EXECD_WORKER_REPLY_IN_FLIGHT;
    }
    for (offset = 0; offset < EXECD_WORKER_MAX_REQUESTS; ++offset)
    {
        const uint32_t request_index = (implementation->next_reply_hint + offset) % EXECD_WORKER_MAX_REQUESTS;
        ExecdWorkerRequestRow* request = &implementation->requests[request_index];
        if (request->state != EXECD_WORKER_SLOT_REPLY_READY)
            continue;
        if (implementation->peers[request->peer_slot].state != EXECD_WORKER_PEER_STATE_OPEN)
            return EXECD_WORKER_CORRUPT_STATE;
        request->state = EXECD_WORKER_SLOT_REPLY_PUBLISHING;
        reply.lease.request = ExecdWorkerInternalMakeRequestReceipt(implementation, request_index);
        reply.reply = request->reply;
        reply.plan = request->plan;
        implementation->next_reply_hint = (request_index + 1U) % EXECD_WORKER_MAX_REQUESTS;
        *reply_out = reply;
        return ExecdWorkerInternalValidate(implementation);
    }
    return EXECD_WORKER_NO_REPLY;
}

ExecdWorkerStatus ExecdWorkerCommitReply(ExecdWorker* worker, const ExecdWorkerReplyLease* lease,
                                         ExecdWorkerCleanupRecord* cleanup_out)
{
    ExecdWorkerReplyLease lease_snapshot;
    ExecdWorkerImpl* implementation;
    ExecdWorkerRequestRow* request = 0;
    ExecdWorkerStatus status;
    ExecdWorkerPlanDisposition disposition;

    if (worker == 0 || lease == 0 || cleanup_out == 0)
        return EXECD_WORKER_NULL_ARGUMENT;
    if (ExecdWorkerInternalRangesOverlap(worker, sizeof(*worker), lease, sizeof(*lease)) ||
        ExecdWorkerInternalRangesOverlap(worker, sizeof(*worker), cleanup_out, sizeof(*cleanup_out)))
        return EXECD_WORKER_ALIASED_STORAGE;
    lease_snapshot = *lease;
    ExecdWorkerInternalClearCleanup(cleanup_out);
    implementation = ExecdWorkerInternalMutable(worker);
    status = ExecdWorkerInternalValidate(implementation);
    if (status != EXECD_WORKER_OK)
        return status;
    status = ExecdWorkerInternalResolveRequest(implementation, &lease_snapshot.request, &request);
    if (status != EXECD_WORKER_OK || request->state != EXECD_WORKER_SLOT_REPLY_PUBLISHING)
        return EXECD_WORKER_STALE_REPLY;
    disposition = request->plan_retained ? EXECD_WORKER_PLAN_PUBLISHED : EXECD_WORKER_PLAN_NONE;
    status =
        ExecdWorkerInternalRetireRequest(implementation, lease_snapshot.request.request_slot, disposition, cleanup_out);
    return status == EXECD_WORKER_OK ? ExecdWorkerInternalValidate(implementation) : status;
}

ExecdWorkerStatus ExecdWorkerAbortReply(ExecdWorker* worker, const ExecdWorkerReplyLease* lease)
{
    ExecdWorkerReplyLease lease_snapshot;
    ExecdWorkerImpl* implementation;
    ExecdWorkerRequestRow* request = 0;
    ExecdWorkerStatus status;

    if (worker == 0 || lease == 0)
        return EXECD_WORKER_NULL_ARGUMENT;
    if (ExecdWorkerInternalRangesOverlap(worker, sizeof(*worker), lease, sizeof(*lease)))
        return EXECD_WORKER_ALIASED_STORAGE;
    lease_snapshot = *lease;
    implementation = ExecdWorkerInternalMutable(worker);
    status = ValidateOpen(implementation);
    if (status != EXECD_WORKER_OK)
        return status;
    status = ExecdWorkerInternalResolveRequest(implementation, &lease_snapshot.request, &request);
    if (status != EXECD_WORKER_OK || request->state != EXECD_WORKER_SLOT_REPLY_PUBLISHING)
        return EXECD_WORKER_STALE_REPLY;
    request->state = EXECD_WORKER_SLOT_REPLY_READY;
    return ExecdWorkerInternalValidate(implementation);
}

ExecdWorkerStatus ExecdWorkerClosePeer(ExecdWorker* worker, const ExecdWorkerPeerReceipt* receipt,
                                       ExecdWorkerCleanupBatch* cleanup_out)
{
    ExecdWorkerPeerReceipt receipt_snapshot;
    ExecdWorkerImpl* implementation;
    ExecdWorkerPeerRow* peer = 0;
    uint32_t index;
    ExecdWorkerStatus status;

    if (worker == 0 || receipt == 0 || cleanup_out == 0)
        return EXECD_WORKER_NULL_ARGUMENT;
    if (ExecdWorkerInternalRangesOverlap(worker, sizeof(*worker), receipt, sizeof(*receipt)) ||
        ExecdWorkerInternalRangesOverlap(worker, sizeof(*worker), cleanup_out, sizeof(*cleanup_out)))
        return EXECD_WORKER_ALIASED_STORAGE;
    receipt_snapshot = *receipt;
    ExecdWorkerInternalClearCleanupBatch(cleanup_out);
    implementation = ExecdWorkerInternalMutable(worker);
    status = ExecdWorkerInternalValidate(implementation);
    if (status != EXECD_WORKER_OK)
        return status;
    if (implementation->state == EXECD_WORKER_STATE_CLOSED)
        return EXECD_WORKER_CLOSED;
    status = ExecdWorkerInternalResolvePeer(implementation, &receipt_snapshot, 1, &peer);
    if (status != EXECD_WORKER_OK)
        return status;
    if (peer->state == EXECD_WORKER_PEER_STATE_CLOSING)
        return EXECD_WORKER_PEER_CLOSING;
    peer->state = EXECD_WORKER_PEER_STATE_CLOSING;

    for (index = 0; index < EXECD_WORKER_MAX_REQUESTS; ++index)
    {
        ExecdWorkerRequestRow* request = &implementation->requests[index];
        ExecdWorkerCleanupRecord cleanup;
        ExecdWorkerPlanDisposition disposition;

        if (request->state == EXECD_WORKER_SLOT_FREE || request->state == EXECD_WORKER_SLOT_RETIRED ||
            request->peer_slot != receipt_snapshot.peer_slot ||
            request->peer_generation != receipt_snapshot.peer_generation)
            continue;
        if (request->state == EXECD_WORKER_SLOT_RUNNING)
        {
            request->cancel_requested = 1;
            continue;
        }
        disposition = request->plan_retained ? EXECD_WORKER_PLAN_DISCARD : EXECD_WORKER_PLAN_NONE;
        status = ExecdWorkerInternalRetireRequest(implementation, index, disposition, &cleanup);
        if (status != EXECD_WORKER_OK)
            return status;
        if (CleanupHasWork(&cleanup))
        {
            status = ExecdWorkerInternalAppendCleanup(cleanup_out, &cleanup);
            if (status != EXECD_WORKER_OK)
                return status;
        }
    }
    ExecdWorkerInternalMaybeFinalizePeer(implementation, receipt_snapshot.peer_slot);
    return ExecdWorkerInternalValidate(implementation);
}

ExecdWorkerStatus ExecdWorkerBeginDrain(ExecdWorker* worker, ExecdWorkerCleanupBatch* cleanup_out)
{
    ExecdWorkerImpl* implementation;
    uint32_t index;
    ExecdWorkerStatus status;

    if (worker == 0 || cleanup_out == 0)
        return EXECD_WORKER_NULL_ARGUMENT;
    if (ExecdWorkerInternalRangesOverlap(worker, sizeof(*worker), cleanup_out, sizeof(*cleanup_out)))
        return EXECD_WORKER_ALIASED_STORAGE;
    ExecdWorkerInternalClearCleanupBatch(cleanup_out);
    implementation = ExecdWorkerInternalMutable(worker);
    status = ExecdWorkerInternalValidate(implementation);
    if (status != EXECD_WORKER_OK)
        return status;
    if (implementation->state == EXECD_WORKER_STATE_CLOSED)
        return EXECD_WORKER_CLOSED;
    if (implementation->state == EXECD_WORKER_STATE_DRAINING)
        return EXECD_WORKER_OK;
    implementation->state = EXECD_WORKER_STATE_DRAINING;
    for (index = 0; index < EXECD_WORKER_MAX_PEERS; ++index)
    {
        if (implementation->peers[index].state == EXECD_WORKER_PEER_STATE_OPEN)
            implementation->peers[index].state = EXECD_WORKER_PEER_STATE_CLOSING;
    }

    for (index = 0; index < EXECD_WORKER_MAX_REQUESTS; ++index)
    {
        ExecdWorkerRequestRow* request = &implementation->requests[index];
        ExecdWorkerCleanupRecord cleanup;
        ExecdWorkerPlanDisposition disposition;

        if (request->state == EXECD_WORKER_SLOT_FREE || request->state == EXECD_WORKER_SLOT_RETIRED)
            continue;
        if (request->state == EXECD_WORKER_SLOT_RUNNING)
        {
            request->cancel_requested = 1;
            continue;
        }
        disposition = request->plan_retained ? EXECD_WORKER_PLAN_DISCARD : EXECD_WORKER_PLAN_NONE;
        status = ExecdWorkerInternalRetireRequest(implementation, index, disposition, &cleanup);
        if (status != EXECD_WORKER_OK)
            return status;
        if (CleanupHasWork(&cleanup))
        {
            status = ExecdWorkerInternalAppendCleanup(cleanup_out, &cleanup);
            if (status != EXECD_WORKER_OK)
                return status;
        }
    }
    for (index = 0; index < EXECD_WORKER_MAX_PEERS; ++index)
        ExecdWorkerInternalMaybeFinalizePeer(implementation, index);
    return ExecdWorkerInternalValidate(implementation);
}

ExecdWorkerStatus ExecdWorkerFinishDrain(ExecdWorker* worker)
{
    ExecdWorkerImpl* implementation;
    ExecdWorkerStatus status;

    if (worker == 0)
        return EXECD_WORKER_NULL_ARGUMENT;
    implementation = ExecdWorkerInternalMutable(worker);
    status = ExecdWorkerInternalValidate(implementation);
    if (status != EXECD_WORKER_OK)
        return status;
    if (implementation->state == EXECD_WORKER_STATE_CLOSED)
        return EXECD_WORKER_CLOSED;
    if (implementation->state != EXECD_WORKER_STATE_DRAINING)
        return EXECD_WORKER_INVALID_ARGUMENT;
    if (implementation->peer_count != 0 || implementation->request_count != 0)
        return EXECD_WORKER_BUSY;
    implementation->state = EXECD_WORKER_STATE_CLOSED;
    return ExecdWorkerInternalValidate(implementation);
}
