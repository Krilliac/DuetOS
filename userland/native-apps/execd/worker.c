#include "worker_internal.h"

static uint8_t ProcessKeyIsCanonical(const ExecdWorkerProcessKey* key)
{
    return key != 0 && key->identity != 0 && key->pid != 0;
}

static uint8_t CredentialKeyIsCanonical(const ExecdWorkerCredentialKey* key)
{
    return key != 0 && key->reserved32 == 0 && key->generation != 0;
}

static uint8_t BytesAreZero(const void* storage, uint32_t bytes)
{
    const uint8_t* cursor = (const uint8_t*)storage;
    uint32_t index;

    if (storage == 0)
        return 0;
    for (index = 0; index < bytes; ++index)
    {
        if (cursor[index] != 0)
            return 0;
    }
    return 1;
}

ExecdWorkerImpl* ExecdWorkerInternalMutable(ExecdWorker* worker)
{
    return worker == 0 ? 0 : (ExecdWorkerImpl*)(void*)worker->bytes;
}

const ExecdWorkerImpl* ExecdWorkerInternalReadOnly(const ExecdWorker* worker)
{
    return worker == 0 ? 0 : (const ExecdWorkerImpl*)(const void*)worker->bytes;
}

void ExecdWorkerInternalClear(void* storage, uint32_t bytes)
{
    uint8_t* cursor = (uint8_t*)storage;
    uint32_t index;

    if (storage == 0)
        return;
    for (index = 0; index < bytes; ++index)
        cursor[index] = 0;
}

uint8_t ExecdWorkerInternalStorageIsZero(const void* storage, uint32_t bytes)
{
    return BytesAreZero(storage, bytes);
}

uint8_t ExecdWorkerInternalRangesOverlap(const void* left, uint64_t left_bytes, const void* right, uint64_t right_bytes)
{
    const uintptr_t left_begin = (uintptr_t)left;
    const uintptr_t right_begin = (uintptr_t)right;
    uintptr_t left_end;
    uintptr_t right_end;

    if (left == 0 || right == 0 || left_bytes == 0 || right_bytes == 0)
        return 0;
    if (left_bytes > (uint64_t)UINTPTR_MAX || right_bytes > (uint64_t)UINTPTR_MAX)
        return 1;
    if (left_begin > UINTPTR_MAX - (uintptr_t)left_bytes || right_begin > UINTPTR_MAX - (uintptr_t)right_bytes)
        return 1;
    left_end = left_begin + (uintptr_t)left_bytes;
    right_end = right_begin + (uintptr_t)right_bytes;
    return left_begin < right_end && right_begin < left_end;
}

uint8_t ExecdWorkerInternalHashIsNonzero(const uint8_t hash[32])
{
    uint32_t index;
    uint8_t value = 0;

    if (hash == 0)
        return 0;
    for (index = 0; index < 32U; ++index)
        value = (uint8_t)(value | hash[index]);
    return value != 0;
}

uint8_t ExecdWorkerInternalHashEqual(const uint8_t left[32], const uint8_t right[32])
{
    uint32_t index;
    uint8_t difference = 0;

    if (left == 0 || right == 0)
        return 0;
    for (index = 0; index < 32U; ++index)
        difference = (uint8_t)(difference | (uint8_t)(left[index] ^ right[index]));
    return difference == 0;
}

uint8_t ExecdWorkerInstanceIdentityIsCanonical(const ExecdWorkerInstanceIdentity* identity)
{
    return identity != 0 && identity->service_identity != 0 && identity->instance_generation != 0 &&
           ProcessKeyIsCanonical(&identity->process) && identity->published_endpoint_epoch != 0 &&
           identity->reserved32 == 0;
}

uint8_t ExecdWorkerPeerIdentityIsCanonical(const ExecdWorkerPeerIdentity* identity)
{
    return identity != 0 && ProcessKeyIsCanonical(&identity->process) &&
           CredentialKeyIsCanonical(&identity->credential) && identity->channel_epoch != 0;
}

uint8_t ExecdWorkerInternalPeerEqual(const ExecdWorkerPeerIdentity* left, const ExecdWorkerPeerIdentity* right)
{
    return left != 0 && right != 0 && left->process.identity == right->process.identity &&
           left->process.pid == right->process.pid && left->credential.slot == right->credential.slot &&
           left->credential.reserved32 == right->credential.reserved32 &&
           left->credential.generation == right->credential.generation && left->channel_epoch == right->channel_epoch;
}

uint8_t ExecdWorkerInternalInstanceEqual(const ExecdWorkerInstanceIdentity* left,
                                         const ExecdWorkerInstanceIdentity* right)
{
    return left != 0 && right != 0 && left->service_identity == right->service_identity &&
           left->instance_generation == right->instance_generation &&
           left->process.identity == right->process.identity && left->process.pid == right->process.pid &&
           left->published_endpoint_epoch == right->published_endpoint_epoch &&
           left->service_slot == right->service_slot && left->reserved32 == right->reserved32;
}

uint8_t ExecdWorkerInternalSourceIsCanonical(const ExecdWorkerSourceAuthority* source)
{
    return source != 0 && source->transfer_reference != 0 &&
           source->transfer_reference <= EXECD_WORKER_TRANSFER_REF_MAX && source->object_identity != 0 &&
           source->object_bytes != 0 && source->object_bytes <= EXECD_WORKER_SOURCE_MAX_BYTES &&
           source->immutable_policy_id == EXECD_WORKER_SOURCE_POLICY_V1 && source->sealed == 1 &&
           source->read_only == 1 && source->reserved8[0] == 0 && source->reserved8[1] == 0 &&
           ExecdWorkerInternalHashIsNonzero(source->source_hash);
}

uint8_t ExecdWorkerInternalPlanIsCanonical(const ExecdWorkerPlanAuthority* plan)
{
    return plan != 0 && plan->transfer_reference != 0 && plan->transfer_reference <= EXECD_WORKER_TRANSFER_REF_MAX &&
           plan->object_identity != 0 && plan->object_bytes >= EXECD_WORKER_LOAD_PLAN_MIN_BYTES &&
           plan->object_bytes <= EXECD_WORKER_LOAD_PLAN_MAX_BYTES &&
           plan->immutable_policy_id == EXECD_WORKER_LOAD_PLAN_POLICY_V1 && plan->sealed == 1 && plan->read_only == 1 &&
           plan->reserved8[0] == 0 && plan->reserved8[1] == 0 && ExecdWorkerInternalHashIsNonzero(plan->object_hash) &&
           ExecdWorkerInternalHashIsNonzero(plan->source_hash);
}

void ExecdWorkerInternalClearPeerReceipt(ExecdWorkerPeerReceipt* receipt)
{
    ExecdWorkerInternalClear(receipt, (uint32_t)sizeof(*receipt));
}

void ExecdWorkerInternalClearRequestReceipt(ExecdWorkerRequestReceipt* receipt)
{
    ExecdWorkerInternalClear(receipt, (uint32_t)sizeof(*receipt));
}

void ExecdWorkerInternalClearCleanup(ExecdWorkerCleanupRecord* cleanup)
{
    ExecdWorkerInternalClear(cleanup, (uint32_t)sizeof(*cleanup));
}

void ExecdWorkerInternalClearCleanupBatch(ExecdWorkerCleanupBatch* cleanup)
{
    ExecdWorkerInternalClear(cleanup, (uint32_t)sizeof(*cleanup));
}

void ExecdWorkerInternalClearReplyPublication(ExecdWorkerReplyPublication* reply)
{
    ExecdWorkerInternalClear(reply, (uint32_t)sizeof(*reply));
}

void ExecdWorkerInternalClearCompleteResult(ExecdWorkerCompleteResult* result)
{
    ExecdWorkerInternalClear(result, (uint32_t)sizeof(*result));
}

void ExecdWorkerInternalClearCancelResult(ExecdWorkerCancelResult* result)
{
    ExecdWorkerInternalClear(result, (uint32_t)sizeof(*result));
}

ExecdWorkerPeerReceipt ExecdWorkerInternalMakePeerReceipt(const ExecdWorkerImpl* worker, uint32_t peer_slot)
{
    ExecdWorkerPeerReceipt receipt;

    ExecdWorkerInternalClearPeerReceipt(&receipt);
    if (worker == 0 || peer_slot >= EXECD_WORKER_MAX_PEERS)
        return receipt;
    receipt.instance = worker->instance;
    receipt.peer = worker->peers[peer_slot].identity;
    receipt.peer_generation = worker->peers[peer_slot].generation;
    receipt.peer_slot = peer_slot;
    return receipt;
}

ExecdWorkerRequestReceipt ExecdWorkerInternalMakeRequestReceipt(const ExecdWorkerImpl* worker, uint32_t request_slot)
{
    ExecdWorkerRequestReceipt receipt;
    const ExecdWorkerRequestRow* request;

    ExecdWorkerInternalClearRequestReceipt(&receipt);
    if (worker == 0 || request_slot >= EXECD_WORKER_MAX_REQUESTS)
        return receipt;
    request = &worker->requests[request_slot];
    receipt.peer = ExecdWorkerInternalMakePeerReceipt(worker, request->peer_slot);
    receipt.request_generation = request->generation;
    receipt.request_id = request->request_id;
    receipt.request_slot = request_slot;
    return receipt;
}

ExecdWorkerStatus ExecdWorkerInternalResolvePeer(ExecdWorkerImpl* worker, const ExecdWorkerPeerReceipt* receipt,
                                                 uint8_t allow_closing, ExecdWorkerPeerRow** peer_out)
{
    ExecdWorkerPeerRow* peer;

    if (peer_out != 0)
        *peer_out = 0;
    if (worker == 0 || receipt == 0 || peer_out == 0)
        return EXECD_WORKER_NULL_ARGUMENT;
    if (receipt->reserved32 != 0 || receipt->peer_slot >= EXECD_WORKER_MAX_PEERS || receipt->peer_generation == 0 ||
        !ExecdWorkerInstanceIdentityIsCanonical(&receipt->instance) ||
        !ExecdWorkerPeerIdentityIsCanonical(&receipt->peer))
        return EXECD_WORKER_STALE_PEER;
    if (!ExecdWorkerInternalInstanceEqual(&worker->instance, &receipt->instance))
        return EXECD_WORKER_STALE_PEER;
    peer = &worker->peers[receipt->peer_slot];
    if (peer->state == EXECD_WORKER_PEER_STATE_FREE || peer->state == EXECD_WORKER_PEER_STATE_RETIRED ||
        peer->generation != receipt->peer_generation || !ExecdWorkerInternalPeerEqual(&peer->identity, &receipt->peer))
        return EXECD_WORKER_STALE_PEER;
    if (peer->state == EXECD_WORKER_PEER_STATE_CLOSING && !allow_closing)
        return EXECD_WORKER_PEER_CLOSING;
    *peer_out = peer;
    return EXECD_WORKER_OK;
}

ExecdWorkerStatus ExecdWorkerInternalResolvePeerConst(const ExecdWorkerImpl* worker,
                                                      const ExecdWorkerPeerReceipt* receipt, uint8_t allow_closing,
                                                      const ExecdWorkerPeerRow** peer_out)
{
    if (peer_out != 0)
        *peer_out = 0;
    if (worker == 0 || receipt == 0 || peer_out == 0)
        return EXECD_WORKER_NULL_ARGUMENT;
    if (receipt->reserved32 != 0 || receipt->peer_slot >= EXECD_WORKER_MAX_PEERS || receipt->peer_generation == 0 ||
        !ExecdWorkerInstanceIdentityIsCanonical(&receipt->instance) ||
        !ExecdWorkerPeerIdentityIsCanonical(&receipt->peer))
        return EXECD_WORKER_STALE_PEER;
    if (!ExecdWorkerInternalInstanceEqual(&worker->instance, &receipt->instance))
        return EXECD_WORKER_STALE_PEER;

    {
        const ExecdWorkerPeerRow* peer = &worker->peers[receipt->peer_slot];
        if (peer->state == EXECD_WORKER_PEER_STATE_FREE || peer->state == EXECD_WORKER_PEER_STATE_RETIRED ||
            peer->generation != receipt->peer_generation ||
            !ExecdWorkerInternalPeerEqual(&peer->identity, &receipt->peer))
            return EXECD_WORKER_STALE_PEER;
        if (peer->state == EXECD_WORKER_PEER_STATE_CLOSING && !allow_closing)
            return EXECD_WORKER_PEER_CLOSING;
        *peer_out = peer;
    }
    return EXECD_WORKER_OK;
}

ExecdWorkerStatus ExecdWorkerInternalResolveRequest(ExecdWorkerImpl* worker, const ExecdWorkerRequestReceipt* receipt,
                                                    ExecdWorkerRequestRow** request_out)
{
    ExecdWorkerRequestRow* request;
    ExecdWorkerPeerRow* peer = 0;
    ExecdWorkerStatus peer_status;

    if (request_out != 0)
        *request_out = 0;
    if (worker == 0 || receipt == 0 || request_out == 0)
        return EXECD_WORKER_NULL_ARGUMENT;
    if (receipt->reserved32 != 0 || receipt->request_slot >= EXECD_WORKER_MAX_REQUESTS ||
        receipt->request_generation == 0 || receipt->request_id == 0)
        return EXECD_WORKER_STALE_WORK;
    peer_status = ExecdWorkerInternalResolvePeer(worker, &receipt->peer, 1, &peer);
    if (peer_status != EXECD_WORKER_OK)
        return EXECD_WORKER_STALE_WORK;
    request = &worker->requests[receipt->request_slot];
    if (request->state == EXECD_WORKER_SLOT_FREE || request->state == EXECD_WORKER_SLOT_RETIRED ||
        request->generation != receipt->request_generation || request->request_id != receipt->request_id ||
        request->peer_slot != receipt->peer.peer_slot || request->peer_generation != receipt->peer.peer_generation)
        return EXECD_WORKER_STALE_WORK;
    (void)peer;
    *request_out = request;
    return EXECD_WORKER_OK;
}

ExecdWorkerStatus ExecdWorkerInternalResolveRequestConst(const ExecdWorkerImpl* worker,
                                                         const ExecdWorkerRequestReceipt* receipt,
                                                         const ExecdWorkerRequestRow** request_out)
{
    if (request_out != 0)
        *request_out = 0;
    if (worker == 0 || receipt == 0 || request_out == 0)
        return EXECD_WORKER_NULL_ARGUMENT;
    if (receipt->reserved32 != 0 || receipt->request_slot >= EXECD_WORKER_MAX_REQUESTS ||
        receipt->request_generation == 0 || receipt->request_id == 0)
        return EXECD_WORKER_STALE_WORK;

    {
        const ExecdWorkerPeerRow* peer = 0;
        const ExecdWorkerRequestRow* request;
        if (ExecdWorkerInternalResolvePeerConst(worker, &receipt->peer, 1, &peer) != EXECD_WORKER_OK)
            return EXECD_WORKER_STALE_WORK;
        request = &worker->requests[receipt->request_slot];
        if (request->state == EXECD_WORKER_SLOT_FREE || request->state == EXECD_WORKER_SLOT_RETIRED ||
            request->generation != receipt->request_generation || request->request_id != receipt->request_id ||
            request->peer_slot != receipt->peer.peer_slot || request->peer_generation != receipt->peer.peer_generation)
            return EXECD_WORKER_STALE_WORK;
        (void)peer;
        *request_out = request;
    }
    return EXECD_WORKER_OK;
}

int32_t ExecdWorkerInternalFindRequest(const ExecdWorkerImpl* worker, uint32_t peer_slot, uint64_t peer_generation,
                                       uint64_t request_id)
{
    uint32_t index;

    if (worker == 0)
        return -1;
    for (index = 0; index < EXECD_WORKER_MAX_REQUESTS; ++index)
    {
        const ExecdWorkerRequestRow* request = &worker->requests[index];
        if (request->state != EXECD_WORKER_SLOT_FREE && request->state != EXECD_WORKER_SLOT_RETIRED &&
            request->peer_slot == peer_slot && request->peer_generation == peer_generation &&
            request->request_id == request_id)
            return (int32_t)index;
    }
    return -1;
}

static uint8_t FormatHintIsValid(uint16_t format_hint)
{
    return format_hint == EXECD_WORKER_FORMAT_AUTO || format_hint == EXECD_WORKER_FORMAT_PE32_PLUS ||
           format_hint == EXECD_WORKER_FORMAT_PE32 || format_hint == EXECD_WORKER_FORMAT_ELF64;
}

static uint8_t RequestInputIsCanonical(const ExecdWorkerParseRequest* request)
{
    return request != 0 && request->request_id != 0 && ExecdWorkerInternalSourceIsCanonical(&request->source) &&
           request->flags == 0 && request->dependency_count == 0 && FormatHintIsValid(request->format_hint) &&
           request->reserved16 == 0 && request->reserved32 == 0;
}

static uint8_t PlanIsZero(const ExecdWorkerPlanAuthority* plan)
{
    return plan != 0 && BytesAreZero(plan, (uint32_t)sizeof(*plan));
}

static uint8_t ReplyRowIsCanonical(const ExecdWorkerRequestRow* request)
{
    if (request->reply.request_id != request->request_id)
        return 0;
    if (request->reply.status == EXECD_WORKER_REPLY_SUCCESS)
    {
        return request->reply.immutable_policy_id == EXECD_WORKER_LOAD_PLAN_POLICY_V1 &&
               request->reply.load_plan_object_ref == request->plan.transfer_reference && request->plan_retained == 1 &&
               ExecdWorkerInternalPlanIsCanonical(&request->plan) &&
               ExecdWorkerInternalHashEqual(request->reply.source_hash, request->request.source.source_hash) &&
               ExecdWorkerInternalHashEqual(request->plan.source_hash, request->request.source.source_hash);
    }
    if (request->reply.status < EXECD_WORKER_REPLY_INVALID_IMAGE ||
        request->reply.status > EXECD_WORKER_REPLY_SERVICE_FAILURE)
        return 0;
    return request->reply.immutable_policy_id == 0 && request->reply.load_plan_object_ref == 0 &&
           !ExecdWorkerInternalHashIsNonzero(request->reply.source_hash) && request->plan_retained == 0 &&
           PlanIsZero(&request->plan);
}

ExecdWorkerStatus ExecdWorkerInternalValidate(const ExecdWorkerImpl* worker)
{
    uint32_t peer_count = 0;
    uint32_t request_count = 0;
    uint32_t peer_index;
    uint32_t request_index;

    if (worker == 0)
        return EXECD_WORKER_NULL_ARGUMENT;
    if (worker->magic == 0)
        return EXECD_WORKER_NOT_INITIALIZED;
    if (worker->magic != EXECD_WORKER_MAGIC || !ExecdWorkerInstanceIdentityIsCanonical(&worker->instance) ||
        worker->first_slot_generation == 0 || worker->state < EXECD_WORKER_STATE_OPEN ||
        worker->state > EXECD_WORKER_STATE_CLOSED || worker->next_peer_hint >= EXECD_WORKER_MAX_PEERS ||
        worker->next_request_hint >= EXECD_WORKER_MAX_REQUESTS || worker->next_work_hint >= EXECD_WORKER_MAX_REQUESTS ||
        worker->next_reply_hint >= EXECD_WORKER_MAX_REQUESTS)
        return EXECD_WORKER_CORRUPT_STATE;

    for (peer_index = 0; peer_index < EXECD_WORKER_MAX_PEERS; ++peer_index)
    {
        const ExecdWorkerPeerRow* peer = &worker->peers[peer_index];
        uint32_t observed_requests = 0;

        if (peer->generation == 0 || peer->reserved8[0] != 0 || peer->reserved8[1] != 0 || peer->reserved8[2] != 0 ||
            peer->state > EXECD_WORKER_PEER_STATE_RETIRED)
            return EXECD_WORKER_CORRUPT_STATE;
        if (peer->state == EXECD_WORKER_PEER_STATE_FREE || peer->state == EXECD_WORKER_PEER_STATE_RETIRED)
        {
            if (!BytesAreZero(&peer->identity, (uint32_t)sizeof(peer->identity)) || peer->next_request_id != 0 ||
                peer->active_requests != 0 ||
                (peer->state == EXECD_WORKER_PEER_STATE_RETIRED && peer->generation != UINT64_MAX))
                return EXECD_WORKER_CORRUPT_STATE;
            continue;
        }
        if (!ExecdWorkerPeerIdentityIsCanonical(&peer->identity))
            return EXECD_WORKER_CORRUPT_STATE;
        ++peer_count;
        for (request_index = 0; request_index < EXECD_WORKER_MAX_REQUESTS; ++request_index)
        {
            const ExecdWorkerRequestRow* request = &worker->requests[request_index];
            if (request->state != EXECD_WORKER_SLOT_FREE && request->state != EXECD_WORKER_SLOT_RETIRED &&
                request->peer_slot == peer_index && request->peer_generation == peer->generation)
                ++observed_requests;
        }
        if (observed_requests != peer->active_requests)
            return EXECD_WORKER_CORRUPT_STATE;
    }

    for (request_index = 0; request_index < EXECD_WORKER_MAX_REQUESTS; ++request_index)
    {
        const ExecdWorkerRequestRow* request = &worker->requests[request_index];
        const ExecdWorkerPeerRow* peer;

        if (request->generation == 0 || request->state > EXECD_WORKER_SLOT_RETIRED || request->cancel_requested > 1 ||
            request->source_retained > 1 || request->plan_retained > 1)
            return EXECD_WORKER_CORRUPT_STATE;
        if (request->state == EXECD_WORKER_SLOT_FREE || request->state == EXECD_WORKER_SLOT_RETIRED)
        {
            if (request->request_id != 0 || request->peer_generation != 0 || request->peer_slot != 0 ||
                request->cancel_requested != 0 || request->source_retained != 0 || request->plan_retained != 0 ||
                !BytesAreZero(&request->request, (uint32_t)sizeof(request->request)) ||
                !BytesAreZero(&request->plan, (uint32_t)sizeof(request->plan)) ||
                !BytesAreZero(&request->reply, (uint32_t)sizeof(request->reply)) ||
                (request->state == EXECD_WORKER_SLOT_RETIRED && request->generation != UINT64_MAX))
                return EXECD_WORKER_CORRUPT_STATE;
            continue;
        }
        if (!RequestInputIsCanonical(&request->request) || request->request_id != request->request.request_id ||
            request->peer_slot >= EXECD_WORKER_MAX_PEERS || request->peer_generation == 0)
            return EXECD_WORKER_CORRUPT_STATE;
        peer = &worker->peers[request->peer_slot];
        if ((peer->state != EXECD_WORKER_PEER_STATE_OPEN && peer->state != EXECD_WORKER_PEER_STATE_CLOSING) ||
            peer->generation != request->peer_generation)
            return EXECD_WORKER_CORRUPT_STATE;
        if (request->state == EXECD_WORKER_SLOT_QUEUED || request->state == EXECD_WORKER_SLOT_RUNNING)
        {
            if (request->source_retained != 1 || request->plan_retained != 0 ||
                !BytesAreZero(&request->plan, (uint32_t)sizeof(request->plan)) ||
                !BytesAreZero(&request->reply, (uint32_t)sizeof(request->reply)) ||
                (request->state == EXECD_WORKER_SLOT_QUEUED && request->cancel_requested != 0))
                return EXECD_WORKER_CORRUPT_STATE;
        }
        else if (request->state == EXECD_WORKER_SLOT_REPLY_READY ||
                 request->state == EXECD_WORKER_SLOT_REPLY_PUBLISHING)
        {
            if (request->source_retained != 0 || request->cancel_requested != 0 || !ReplyRowIsCanonical(request))
                return EXECD_WORKER_CORRUPT_STATE;
        }
        else
            return EXECD_WORKER_CORRUPT_STATE;
        ++request_count;
    }

    if (peer_count != worker->peer_count || request_count != worker->request_count)
        return EXECD_WORKER_CORRUPT_STATE;
    if (worker->state == EXECD_WORKER_STATE_CLOSED && (peer_count != 0 || request_count != 0))
        return EXECD_WORKER_CORRUPT_STATE;
    return EXECD_WORKER_OK;
}

uint8_t ExecdWorkerInternalCompletionIsCanonical(const ExecdWorkerRequestRow* request,
                                                 const ExecdWorkerCompletion* completion)
{
    if (request == 0 || completion == 0 || completion->reserved32 != 0)
        return 0;
    if (completion->reply_status == EXECD_WORKER_REPLY_SUCCESS)
    {
        return ExecdWorkerInternalPlanIsCanonical(&completion->plan) &&
               ExecdWorkerInternalHashEqual(completion->plan.source_hash, request->request.source.source_hash);
    }
    if (completion->reply_status == EXECD_WORKER_REPLY_CANCELLED)
        return request->cancel_requested != 0 && PlanIsZero(&completion->plan);
    if (completion->reply_status < EXECD_WORKER_REPLY_INVALID_IMAGE ||
        completion->reply_status > EXECD_WORKER_REPLY_SERVICE_FAILURE)
        return 0;
    return PlanIsZero(&completion->plan);
}

void ExecdWorkerInternalMakeFailureReply(ExecdWorkerRequestRow* request, ExecdWorkerReplyStatus status)
{
    ExecdWorkerInternalClear(&request->reply, (uint32_t)sizeof(request->reply));
    request->reply.request_id = request->request_id;
    request->reply.status = (uint32_t)status;
}

void ExecdWorkerInternalMaybeFinalizePeer(ExecdWorkerImpl* worker, uint32_t peer_slot)
{
    ExecdWorkerPeerRow* peer;
    uint64_t generation;

    if (worker == 0 || peer_slot >= EXECD_WORKER_MAX_PEERS)
        return;
    peer = &worker->peers[peer_slot];
    if (peer->state != EXECD_WORKER_PEER_STATE_CLOSING || peer->active_requests != 0)
        return;
    generation = peer->generation;
    ExecdWorkerInternalClear(peer, (uint32_t)sizeof(*peer));
    if (generation == UINT64_MAX)
    {
        peer->generation = UINT64_MAX;
        peer->state = EXECD_WORKER_PEER_STATE_RETIRED;
    }
    else
    {
        peer->generation = generation + UINT64_C(1);
        peer->state = EXECD_WORKER_PEER_STATE_FREE;
    }
    if (worker->peer_count != 0)
        --worker->peer_count;
}

ExecdWorkerStatus ExecdWorkerInternalRetireRequest(ExecdWorkerImpl* worker, uint32_t request_slot,
                                                   ExecdWorkerPlanDisposition plan_disposition,
                                                   ExecdWorkerCleanupRecord* cleanup_out)
{
    ExecdWorkerRequestRow* request;
    ExecdWorkerPeerRow* peer;
    ExecdWorkerRequestReceipt receipt;
    uint64_t generation;
    uint32_t peer_slot;

    if (worker == 0 || cleanup_out == 0 || request_slot >= EXECD_WORKER_MAX_REQUESTS)
        return EXECD_WORKER_NULL_ARGUMENT;
    ExecdWorkerInternalClearCleanup(cleanup_out);
    request = &worker->requests[request_slot];
    if (request->state == EXECD_WORKER_SLOT_FREE || request->state == EXECD_WORKER_SLOT_RETIRED)
        return EXECD_WORKER_STALE_WORK;
    if (request->plan_retained && plan_disposition == EXECD_WORKER_PLAN_NONE)
        return EXECD_WORKER_CORRUPT_STATE;
    receipt = ExecdWorkerInternalMakeRequestReceipt(worker, request_slot);
    cleanup_out->request = receipt;
    if (request->source_retained)
    {
        cleanup_out->release_source_import = 1;
        cleanup_out->source_transfer_reference = request->request.source.transfer_reference;
        cleanup_out->source_object_identity = request->request.source.object_identity;
    }
    if (request->plan_retained)
    {
        cleanup_out->plan_disposition = (uint8_t)plan_disposition;
        cleanup_out->plan_transfer_reference = request->plan.transfer_reference;
        cleanup_out->plan_object_identity = request->plan.object_identity;
    }

    peer_slot = request->peer_slot;
    peer = &worker->peers[peer_slot];
    generation = request->generation;
    ExecdWorkerInternalClear(request, (uint32_t)sizeof(*request));
    if (generation == UINT64_MAX)
    {
        request->generation = UINT64_MAX;
        request->state = EXECD_WORKER_SLOT_RETIRED;
    }
    else
    {
        request->generation = generation + UINT64_C(1);
        request->state = EXECD_WORKER_SLOT_FREE;
    }
    if (worker->request_count != 0)
        --worker->request_count;
    if (peer->active_requests != 0)
        --peer->active_requests;
    ExecdWorkerInternalMaybeFinalizePeer(worker, peer_slot);
    return EXECD_WORKER_OK;
}

ExecdWorkerStatus ExecdWorkerInternalAppendCleanup(ExecdWorkerCleanupBatch* batch,
                                                   const ExecdWorkerCleanupRecord* cleanup)
{
    if (batch == 0 || cleanup == 0)
        return EXECD_WORKER_NULL_ARGUMENT;
    if (!cleanup->release_source_import && cleanup->plan_disposition == EXECD_WORKER_PLAN_NONE)
        return EXECD_WORKER_OK;
    if (batch->count >= EXECD_WORKER_CLEANUP_CAPACITY)
        return EXECD_WORKER_CORRUPT_STATE;
    batch->records[batch->count++] = *cleanup;
    return EXECD_WORKER_OK;
}

ExecdWorkerStatus ExecdWorkerInitialize(ExecdWorker* worker, const ExecdWorkerInstanceIdentity* instance,
                                        uint64_t first_slot_generation)
{
    ExecdWorkerInstanceIdentity instance_snapshot;
    ExecdWorkerImpl* implementation;
    uint32_t index;
    ExecdWorkerStatus validation;

    if (worker == 0 || instance == 0)
        return EXECD_WORKER_NULL_ARGUMENT;
    if (ExecdWorkerInternalRangesOverlap(worker, sizeof(*worker), instance, sizeof(*instance)))
        return EXECD_WORKER_ALIASED_STORAGE;
    instance_snapshot = *instance;
    if (!ExecdWorkerInstanceIdentityIsCanonical(&instance_snapshot) || first_slot_generation == 0)
        return EXECD_WORKER_INVALID_IDENTITY;
    implementation = ExecdWorkerInternalMutable(worker);
    if (!ExecdWorkerInternalStorageIsZero(worker, (uint32_t)sizeof(*worker)))
    {
        if (implementation->magic == EXECD_WORKER_MAGIC)
            return EXECD_WORKER_ALREADY_INITIALIZED;
        return EXECD_WORKER_NONZERO_STORAGE;
    }

    implementation->instance = instance_snapshot;
    implementation->first_slot_generation = first_slot_generation;
    implementation->state = EXECD_WORKER_STATE_OPEN;
    for (index = 0; index < EXECD_WORKER_MAX_PEERS; ++index)
        implementation->peers[index].generation = first_slot_generation;
    for (index = 0; index < EXECD_WORKER_MAX_REQUESTS; ++index)
        implementation->requests[index].generation = first_slot_generation;
    implementation->magic = EXECD_WORKER_MAGIC;
    validation = ExecdWorkerInternalValidate(implementation);
    if (validation != EXECD_WORKER_OK)
    {
        ExecdWorkerInternalClear(worker, (uint32_t)sizeof(*worker));
        return validation;
    }
    return EXECD_WORKER_OK;
}

ExecdWorkerStatus ExecdWorkerOpenPeer(ExecdWorker* worker, const ExecdWorkerPeerIdentity* peer,
                                      uint64_t first_request_id, ExecdWorkerPeerReceipt* receipt_out)
{
    ExecdWorkerPeerIdentity peer_snapshot;
    ExecdWorkerImpl* implementation;
    uint32_t offset;
    uint32_t free_slot = EXECD_WORKER_MAX_PEERS;
    uint8_t retired_seen = 0;
    ExecdWorkerStatus validation;

    if (worker == 0 || peer == 0 || receipt_out == 0)
        return EXECD_WORKER_NULL_ARGUMENT;
    if (ExecdWorkerInternalRangesOverlap(worker, sizeof(*worker), peer, sizeof(*peer)) ||
        ExecdWorkerInternalRangesOverlap(worker, sizeof(*worker), receipt_out, sizeof(*receipt_out)))
        return EXECD_WORKER_ALIASED_STORAGE;
    peer_snapshot = *peer;
    ExecdWorkerInternalClearPeerReceipt(receipt_out);
    implementation = ExecdWorkerInternalMutable(worker);
    validation = ExecdWorkerInternalValidate(implementation);
    if (validation != EXECD_WORKER_OK)
        return validation;
    if (implementation->state == EXECD_WORKER_STATE_DRAINING)
        return EXECD_WORKER_DRAINING;
    if (implementation->state == EXECD_WORKER_STATE_CLOSED)
        return EXECD_WORKER_CLOSED;
    if (!ExecdWorkerPeerIdentityIsCanonical(&peer_snapshot) || first_request_id == 0)
        return EXECD_WORKER_INVALID_IDENTITY;

    for (offset = 0; offset < EXECD_WORKER_MAX_PEERS; ++offset)
    {
        const uint32_t index = (implementation->next_peer_hint + offset) % EXECD_WORKER_MAX_PEERS;
        ExecdWorkerPeerRow* row = &implementation->peers[index];
        if ((row->state == EXECD_WORKER_PEER_STATE_OPEN || row->state == EXECD_WORKER_PEER_STATE_CLOSING) &&
            ExecdWorkerInternalPeerEqual(&row->identity, &peer_snapshot))
            return EXECD_WORKER_PEER_EXISTS;
        if (row->state == EXECD_WORKER_PEER_STATE_RETIRED)
            retired_seen = 1;
        else if (row->state == EXECD_WORKER_PEER_STATE_FREE && free_slot == EXECD_WORKER_MAX_PEERS)
            free_slot = index;
    }
    if (free_slot == EXECD_WORKER_MAX_PEERS)
        return retired_seen ? EXECD_WORKER_GENERATION_EXHAUSTED : EXECD_WORKER_PEER_CAPACITY;

    implementation->peers[free_slot].identity = peer_snapshot;
    implementation->peers[free_slot].next_request_id = first_request_id;
    implementation->peers[free_slot].state = EXECD_WORKER_PEER_STATE_OPEN;
    ++implementation->peer_count;
    implementation->next_peer_hint = (free_slot + 1U) % EXECD_WORKER_MAX_PEERS;
    *receipt_out = ExecdWorkerInternalMakePeerReceipt(implementation, free_slot);
    return ExecdWorkerInternalValidate(implementation);
}

ExecdWorkerStatus ExecdWorkerDescribe(const ExecdWorker* worker, ExecdWorkerSnapshot* snapshot_out)
{
    const ExecdWorkerImpl* implementation;
    ExecdWorkerSnapshot snapshot;
    uint32_t index;
    ExecdWorkerStatus validation;

    if (worker == 0 || snapshot_out == 0)
        return EXECD_WORKER_NULL_ARGUMENT;
    if (ExecdWorkerInternalRangesOverlap(worker, sizeof(*worker), snapshot_out, sizeof(*snapshot_out)))
        return EXECD_WORKER_ALIASED_STORAGE;
    ExecdWorkerInternalClear(&snapshot, (uint32_t)sizeof(snapshot));
    ExecdWorkerInternalClear(snapshot_out, (uint32_t)sizeof(*snapshot_out));
    implementation = ExecdWorkerInternalReadOnly(worker);
    validation = ExecdWorkerInternalValidate(implementation);
    if (validation != EXECD_WORKER_OK)
        return validation;
    snapshot.instance = implementation->instance;
    snapshot.state = implementation->state;
    snapshot.peer_count = implementation->peer_count;
    snapshot.request_count = implementation->request_count;
    for (index = 0; index < EXECD_WORKER_MAX_PEERS; ++index)
    {
        if (implementation->peers[index].state == EXECD_WORKER_PEER_STATE_RETIRED)
            ++snapshot.retired_peer_slots;
    }
    for (index = 0; index < EXECD_WORKER_MAX_REQUESTS; ++index)
    {
        switch (implementation->requests[index].state)
        {
        case EXECD_WORKER_SLOT_QUEUED:
            ++snapshot.queued_count;
            break;
        case EXECD_WORKER_SLOT_RUNNING:
            ++snapshot.running_count;
            break;
        case EXECD_WORKER_SLOT_REPLY_READY:
        case EXECD_WORKER_SLOT_REPLY_PUBLISHING:
            ++snapshot.reply_count;
            break;
        case EXECD_WORKER_SLOT_RETIRED:
            ++snapshot.retired_request_slots;
            break;
        default:
            break;
        }
    }
    *snapshot_out = snapshot;
    return EXECD_WORKER_OK;
}

ExecdWorkerStatus ExecdWorkerInspectRequest(const ExecdWorker* worker, const ExecdWorkerRequestReceipt* receipt,
                                            ExecdWorkerRequestSnapshot* snapshot_out)
{
    const ExecdWorkerImpl* implementation;
    const ExecdWorkerRequestRow* request = 0;
    ExecdWorkerRequestReceipt receipt_snapshot;
    ExecdWorkerStatus status;

    if (worker == 0 || receipt == 0 || snapshot_out == 0)
        return EXECD_WORKER_NULL_ARGUMENT;
    if (ExecdWorkerInternalRangesOverlap(worker, sizeof(*worker), receipt, sizeof(*receipt)) ||
        ExecdWorkerInternalRangesOverlap(worker, sizeof(*worker), snapshot_out, sizeof(*snapshot_out)))
        return EXECD_WORKER_ALIASED_STORAGE;
    receipt_snapshot = *receipt;
    ExecdWorkerInternalClear(snapshot_out, (uint32_t)sizeof(*snapshot_out));
    implementation = ExecdWorkerInternalReadOnly(worker);
    status = ExecdWorkerInternalValidate(implementation);
    if (status != EXECD_WORKER_OK)
        return status;
    status = ExecdWorkerInternalResolveRequestConst(implementation, &receipt_snapshot, &request);
    if (status != EXECD_WORKER_OK)
        return status;
    snapshot_out->receipt = receipt_snapshot;
    snapshot_out->phase = request->state;
    snapshot_out->cancel_requested = request->cancel_requested;
    snapshot_out->source_retained = request->source_retained;
    snapshot_out->plan_retained = request->plan_retained;
    return EXECD_WORKER_OK;
}

const char* ExecdWorkerStatusName(ExecdWorkerStatus status)
{
    switch (status)
    {
    case EXECD_WORKER_OK:
        return "ok";
    case EXECD_WORKER_NULL_ARGUMENT:
        return "null-argument";
    case EXECD_WORKER_ALIASED_STORAGE:
        return "aliased-storage";
    case EXECD_WORKER_NONZERO_STORAGE:
        return "nonzero-storage";
    case EXECD_WORKER_ALREADY_INITIALIZED:
        return "already-initialized";
    case EXECD_WORKER_NOT_INITIALIZED:
        return "not-initialized";
    case EXECD_WORKER_CORRUPT_STATE:
        return "corrupt-state";
    case EXECD_WORKER_INVALID_IDENTITY:
        return "invalid-identity";
    case EXECD_WORKER_INVALID_ARGUMENT:
        return "invalid-argument";
    case EXECD_WORKER_CLOSED:
        return "closed";
    case EXECD_WORKER_DRAINING:
        return "draining";
    case EXECD_WORKER_BUSY:
        return "busy";
    case EXECD_WORKER_PEER_CAPACITY:
        return "peer-capacity";
    case EXECD_WORKER_REQUEST_CAPACITY:
        return "request-capacity";
    case EXECD_WORKER_GENERATION_EXHAUSTED:
        return "generation-exhausted";
    case EXECD_WORKER_SEQUENCE_EXHAUSTED:
        return "sequence-exhausted";
    case EXECD_WORKER_PEER_EXISTS:
        return "peer-exists";
    case EXECD_WORKER_PEER_NOT_FOUND:
        return "peer-not-found";
    case EXECD_WORKER_STALE_PEER:
        return "stale-peer";
    case EXECD_WORKER_PEER_CLOSING:
        return "peer-closing";
    case EXECD_WORKER_REPLAYED_REQUEST:
        return "replayed-request";
    case EXECD_WORKER_OUT_OF_ORDER_REQUEST:
        return "out-of-order-request";
    case EXECD_WORKER_REQUEST_NOT_FOUND:
        return "request-not-found";
    case EXECD_WORKER_NO_WORK:
        return "no-work";
    case EXECD_WORKER_STALE_WORK:
        return "stale-work";
    case EXECD_WORKER_INVALID_COMPLETION:
        return "invalid-completion";
    case EXECD_WORKER_NO_REPLY:
        return "no-reply";
    case EXECD_WORKER_STALE_REPLY:
        return "stale-reply";
    case EXECD_WORKER_REPLY_IN_FLIGHT:
        return "reply-in-flight";
    case EXECD_WORKER_CANCEL_TOO_LATE:
        return "cancel-too-late";
    default:
        return "unknown";
    }
}
