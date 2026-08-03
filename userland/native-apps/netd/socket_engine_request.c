#include "socket_engine_internal.h"

static NetdSocketEngineStatus ResolveEngine(NetdSocketEngine* engine, NetdSocketEngineImpl** implementation_out)
{
    NetdSocketEngineImpl* implementation;
    if (engine == 0 || implementation_out == 0)
        return NETD_SOCKET_ENGINE_NULL_ARGUMENT;
    implementation = NetdSocketEngineInternalMutable(engine);
    if (implementation->magic != NETD_SOCKET_ENGINE_MAGIC)
        return NETD_SOCKET_ENGINE_NOT_INITIALIZED;
    if (!NetdSocketEngineInternalValidate(implementation))
        return NETD_SOCKET_ENGINE_CORRUPT_STATE;
    *implementation_out = implementation;
    return NETD_SOCKET_ENGINE_OK;
}

static NetdSocketEngineStatus ResolveSubmissionPeer(NetdSocketEngineImpl* implementation,
                                                    const NetdSocketEnginePeerReceipt* receipt, uint64_t method,
                                                    NetdSocketEnginePeerRow** row_out)
{
    NetdSocketEngineStatus status;
    if (NetdSocketEngineInternalHasPublishingReply(implementation))
        return NETD_SOCKET_ENGINE_REPLY_IN_FLIGHT;
    if (implementation->state == NETD_SOCKET_ENGINE_STATE_AWAITING_TRANSPORT)
        return NETD_SOCKET_ENGINE_TRANSPORT_UNAVAILABLE;
    if (implementation->state == NETD_SOCKET_ENGINE_STATE_DRAINING)
        return NETD_SOCKET_ENGINE_DRAINING;
    if (implementation->state == NETD_SOCKET_ENGINE_STATE_CLOSED)
        return NETD_SOCKET_ENGINE_CLOSED;
    status = NetdSocketEngineInternalResolvePeer(implementation, receipt, row_out);
    if (status != NETD_SOCKET_ENGINE_OK)
        return status;
    if ((*row_out)->state == NETD_SOCKET_ENGINE_PEER_STATE_CLOSING)
        return NETD_SOCKET_ENGINE_PEER_CLOSING;
    if (((*row_out)->authority.allowed_methods & method) == 0)
        return NETD_SOCKET_ENGINE_UNAUTHORIZED;
    return NETD_SOCKET_ENGINE_OK;
}

static NetdSocketEngineStatus CheckRequestSequence(const NetdSocketEnginePeerRow* peer, uint64_t request_id)
{
    if (request_id == 0)
        return NETD_SOCKET_ENGINE_INVALID_ARGUMENT;
    if (peer->next_request_id == 0)
        return NETD_SOCKET_ENGINE_SEQUENCE_EXHAUSTED;
    if (request_id < peer->next_request_id)
        return NETD_SOCKET_ENGINE_REPLAYED_REQUEST;
    if (request_id > peer->next_request_id)
        return NETD_SOCKET_ENGINE_OUT_OF_ORDER_REQUEST;
    return NETD_SOCKET_ENGINE_OK;
}

static void AdvanceRequestSequence(NetdSocketEnginePeerRow* peer, uint64_t request_id)
{
    peer->next_request_id = request_id == UINT64_MAX ? 0 : request_id + UINT64_C(1);
}

static uint32_t FindRequestSlot(NetdSocketEngineImpl* implementation)
{
    uint32_t offset;
    for (offset = 0; offset < NETD_SOCKET_ENGINE_MAX_REQUESTS; ++offset)
    {
        const uint32_t slot = (implementation->next_request_hint + offset) % NETD_SOCKET_ENGINE_MAX_REQUESTS;
        if (implementation->requests[slot].state == NETD_SOCKET_ENGINE_REQUEST_FREE)
            return slot;
    }
    return NETD_SOCKET_ENGINE_INVALID_SLOT;
}

static uint32_t FindSocketSlot(NetdSocketEngineImpl* implementation)
{
    uint32_t offset;
    for (offset = 0; offset < NETD_SOCKET_ENGINE_MAX_SOCKETS; ++offset)
    {
        const uint32_t slot = (implementation->next_socket_hint + offset) % NETD_SOCKET_ENGINE_MAX_SOCKETS;
        if (implementation->sockets[slot].state == NETD_SOCKET_ENGINE_SOCKET_FREE)
            return slot;
    }
    return NETD_SOCKET_ENGINE_INVALID_SLOT;
}

static uint8_t SocketHasActiveRequest(const NetdSocketEngineImpl* implementation, uint32_t socket_slot,
                                      uint64_t socket_generation)
{
    uint32_t index;
    for (index = 0; index < NETD_SOCKET_ENGINE_MAX_REQUESTS; ++index)
    {
        const NetdSocketEngineRequestRow* request = &implementation->requests[index];
        if (request->state != NETD_SOCKET_ENGINE_REQUEST_FREE && request->state != NETD_SOCKET_ENGINE_REQUEST_RETIRED &&
            request->socket_slot == socket_slot && request->socket_generation == socket_generation)
            return 1;
    }
    return 0;
}

static void PrepareRequestRow(NetdSocketEngineImpl* implementation, uint32_t request_slot, uint32_t peer_slot,
                              uint32_t socket_slot, uint64_t request_id, uint32_t operation)
{
    NetdSocketEngineRequestRow* request = &implementation->requests[request_slot];
    const uint64_t generation = request->generation;
    NetdSocketEngineInternalClear(request, (uint32_t)sizeof(*request));
    request->generation = generation;
    request->peer_slot = peer_slot;
    request->peer_generation = implementation->peers[peer_slot].generation;
    request->socket_slot = socket_slot;
    request->socket_generation = implementation->sockets[socket_slot].generation;
    request->request.socket = NetdSocketEngineInternalSocketRef(implementation, socket_slot);
    request->request.request_id = request_id;
    request->request.operation = operation;
    request->state = NETD_SOCKET_ENGINE_REQUEST_QUEUED_INTERNAL;
    ++implementation->request_count;
    ++implementation->peers[peer_slot].active_requests;
    implementation->next_request_hint = (request_slot + 1U) % NETD_SOCKET_ENGINE_MAX_REQUESTS;
}

static NetdSocketEngineStatus RequestCapacityStatus(const NetdSocketEngineImpl* implementation)
{
    return implementation->request_count == NETD_SOCKET_ENGINE_MAX_REQUESTS ? NETD_SOCKET_ENGINE_REQUEST_CAPACITY
                                                                            : NETD_SOCKET_ENGINE_GENERATION_EXHAUSTED;
}

static NetdSocketEngineStatus SocketCapacityStatus(const NetdSocketEngineImpl* implementation)
{
    return implementation->socket_count == NETD_SOCKET_ENGINE_MAX_SOCKETS ? NETD_SOCKET_ENGINE_SOCKET_CAPACITY
                                                                          : NETD_SOCKET_ENGINE_GENERATION_EXHAUSTED;
}

NetdSocketEngineStatus NetdSocketEngineSubmitOpen(NetdSocketEngine* engine, const NetdSocketEnginePeerReceipt* peer,
                                                  uint64_t request_id, uint16_t domain, uint16_t type,
                                                  uint16_t protocol, uint32_t flags,
                                                  NetdSocketEngineRequestReceipt* receipt_out)
{
    NetdSocketEngineImpl* implementation;
    NetdSocketEnginePeerRow* peer_row;
    NetdSocketEngineSocketRow* socket_row;
    NetdSocketEngineStatus status;
    uint32_t request_slot;
    uint32_t socket_slot;
    uint64_t socket_generation;
    if (engine == 0 || peer == 0 || receipt_out == 0)
        return NETD_SOCKET_ENGINE_NULL_ARGUMENT;
    if (NetdSocketEngineInternalRangesOverlap(engine, sizeof(*engine), peer, sizeof(*peer)) ||
        NetdSocketEngineInternalRangesOverlap(engine, sizeof(*engine), receipt_out, sizeof(*receipt_out)) ||
        NetdSocketEngineInternalRangesOverlap(peer, sizeof(*peer), receipt_out, sizeof(*receipt_out)))
        return NETD_SOCKET_ENGINE_ALIASED_STORAGE;
    NetdSocketEngineInternalClear(receipt_out, (uint32_t)sizeof(*receipt_out));
    status = ResolveEngine(engine, &implementation);
    if (status != NETD_SOCKET_ENGINE_OK)
        return status;
    status = ResolveSubmissionPeer(implementation, peer, NETD_SOCKET_ENGINE_METHOD_OPEN, &peer_row);
    if (status != NETD_SOCKET_ENGINE_OK)
        return status;
    if (!NetdSocketEngineInternalSocketParametersAreCanonical(domain, type, protocol) || flags != 0)
        return NETD_SOCKET_ENGINE_INVALID_ARGUMENT;
    status = CheckRequestSequence(peer_row, request_id);
    if (status != NETD_SOCKET_ENGINE_OK)
        return status;
    if (peer_row->active_requests >= peer_row->authority.request_limit)
        return NETD_SOCKET_ENGINE_REQUEST_CAPACITY;
    if (peer_row->active_sockets >= peer_row->authority.socket_limit)
        return NETD_SOCKET_ENGINE_SOCKET_CAPACITY;
    request_slot = FindRequestSlot(implementation);
    if (request_slot == NETD_SOCKET_ENGINE_INVALID_SLOT)
        return RequestCapacityStatus(implementation);
    socket_slot = FindSocketSlot(implementation);
    if (socket_slot == NETD_SOCKET_ENGINE_INVALID_SLOT)
        return SocketCapacityStatus(implementation);

    socket_row = &implementation->sockets[socket_slot];
    socket_generation = socket_row->generation;
    NetdSocketEngineInternalClear(socket_row, (uint32_t)sizeof(*socket_row));
    socket_row->generation = socket_generation;
    socket_row->owner_peer_slot = peer->peer_slot;
    socket_row->owner_peer_generation = peer_row->generation;
    socket_row->domain = domain;
    socket_row->type = type;
    socket_row->protocol = protocol;
    socket_row->state = NETD_SOCKET_ENGINE_SOCKET_RESERVED;
    ++implementation->socket_count;
    ++peer_row->active_sockets;
    implementation->next_socket_hint = (socket_slot + 1U) % NETD_SOCKET_ENGINE_MAX_SOCKETS;

    PrepareRequestRow(implementation, request_slot, peer->peer_slot, socket_slot, request_id,
                      NETD_SOCKET_ENGINE_OPERATION_OPEN);
    implementation->requests[request_slot].request.domain = domain;
    implementation->requests[request_slot].request.type = type;
    implementation->requests[request_slot].request.protocol = protocol;
    AdvanceRequestSequence(peer_row, request_id);
    *receipt_out = NetdSocketEngineInternalRequestReceipt(implementation, request_slot);
    return NETD_SOCKET_ENGINE_OK;
}

NetdSocketEngineStatus NetdSocketEngineSubmitClose(NetdSocketEngine* engine, const NetdSocketEnginePeerReceipt* peer,
                                                   uint64_t request_id, const NetdSocketEngineSocketRef* socket,
                                                   NetdSocketEngineRequestReceipt* receipt_out)
{
    NetdSocketEngineImpl* implementation;
    NetdSocketEnginePeerRow* peer_row;
    NetdSocketEngineSocketRow* socket_row;
    NetdSocketEngineStatus status;
    uint32_t request_slot;
    if (engine == 0 || peer == 0 || socket == 0 || receipt_out == 0)
        return NETD_SOCKET_ENGINE_NULL_ARGUMENT;
    if (NetdSocketEngineInternalRangesOverlap(engine, sizeof(*engine), peer, sizeof(*peer)) ||
        NetdSocketEngineInternalRangesOverlap(engine, sizeof(*engine), socket, sizeof(*socket)) ||
        NetdSocketEngineInternalRangesOverlap(engine, sizeof(*engine), receipt_out, sizeof(*receipt_out)) ||
        NetdSocketEngineInternalRangesOverlap(peer, sizeof(*peer), receipt_out, sizeof(*receipt_out)) ||
        NetdSocketEngineInternalRangesOverlap(socket, sizeof(*socket), receipt_out, sizeof(*receipt_out)))
        return NETD_SOCKET_ENGINE_ALIASED_STORAGE;
    NetdSocketEngineInternalClear(receipt_out, (uint32_t)sizeof(*receipt_out));
    status = ResolveEngine(engine, &implementation);
    if (status != NETD_SOCKET_ENGINE_OK)
        return status;
    status = ResolveSubmissionPeer(implementation, peer, NETD_SOCKET_ENGINE_METHOD_CLOSE, &peer_row);
    if (status != NETD_SOCKET_ENGINE_OK)
        return status;
    status = CheckRequestSequence(peer_row, request_id);
    if (status != NETD_SOCKET_ENGINE_OK)
        return status;
    status = NetdSocketEngineInternalResolveSocket(implementation, peer_row, peer->peer_slot, socket, &socket_row);
    if (status != NETD_SOCKET_ENGINE_OK)
        return status;
    if (socket_row->state != NETD_SOCKET_ENGINE_SOCKET_OPEN)
        return NETD_SOCKET_ENGINE_SOCKET_BUSY;
    if (SocketHasActiveRequest(implementation, socket->slot, socket->generation))
        return NETD_SOCKET_ENGINE_SOCKET_BUSY;
    if (peer_row->active_requests >= peer_row->authority.request_limit)
        return NETD_SOCKET_ENGINE_REQUEST_CAPACITY;
    request_slot = FindRequestSlot(implementation);
    if (request_slot == NETD_SOCKET_ENGINE_INVALID_SLOT)
        return RequestCapacityStatus(implementation);

    PrepareRequestRow(implementation, request_slot, peer->peer_slot, socket->slot, request_id,
                      NETD_SOCKET_ENGINE_OPERATION_CLOSE);
    socket_row->state = NETD_SOCKET_ENGINE_SOCKET_CLOSING;
    AdvanceRequestSequence(peer_row, request_id);
    *receipt_out = NetdSocketEngineInternalRequestReceipt(implementation, request_slot);
    return NETD_SOCKET_ENGINE_OK;
}

NetdSocketEngineStatus NetdSocketEngineClaimNext(NetdSocketEngine* engine, NetdSocketEngineWorkItem* work_out)
{
    NetdSocketEngineImpl* implementation;
    NetdSocketEngineStatus status;
    uint32_t offset;
    if (engine == 0 || work_out == 0)
        return NETD_SOCKET_ENGINE_NULL_ARGUMENT;
    if (NetdSocketEngineInternalRangesOverlap(engine, sizeof(*engine), work_out, sizeof(*work_out)))
        return NETD_SOCKET_ENGINE_ALIASED_STORAGE;
    NetdSocketEngineInternalClear(work_out, (uint32_t)sizeof(*work_out));
    status = ResolveEngine(engine, &implementation);
    if (status != NETD_SOCKET_ENGINE_OK)
        return status;
    if (NetdSocketEngineInternalHasPublishingReply(implementation))
        return NETD_SOCKET_ENGINE_REPLY_IN_FLIGHT;
    if (implementation->state == NETD_SOCKET_ENGINE_STATE_AWAITING_TRANSPORT)
        return NETD_SOCKET_ENGINE_TRANSPORT_UNAVAILABLE;
    if (implementation->state == NETD_SOCKET_ENGINE_STATE_DRAINING)
        return NETD_SOCKET_ENGINE_DRAINING;
    if (implementation->state == NETD_SOCKET_ENGINE_STATE_CLOSED)
        return NETD_SOCKET_ENGINE_CLOSED;
    for (offset = 0; offset < NETD_SOCKET_ENGINE_MAX_REQUESTS; ++offset)
    {
        const uint32_t slot = (implementation->next_work_hint + offset) % NETD_SOCKET_ENGINE_MAX_REQUESTS;
        NetdSocketEngineRequestRow* request = &implementation->requests[slot];
        if (request->state != NETD_SOCKET_ENGINE_REQUEST_QUEUED_INTERNAL)
            continue;
        request->state = NETD_SOCKET_ENGINE_REQUEST_RUNNING_INTERNAL;
        work_out->lease.request = NetdSocketEngineInternalRequestReceipt(implementation, slot);
        work_out->request = request->request;
        if (request->request.operation == NETD_SOCKET_ENGINE_OPERATION_CLOSE)
            work_out->backend = implementation->sockets[request->socket_slot].backend;
        implementation->next_work_hint = (slot + 1U) % NETD_SOCKET_ENGINE_MAX_REQUESTS;
        return NETD_SOCKET_ENGINE_OK;
    }
    return NETD_SOCKET_ENGINE_NO_WORK;
}

NetdSocketEngineStatus NetdSocketEngineCheckCancellation(const NetdSocketEngine* engine,
                                                         const NetdSocketEngineWorkLease* lease,
                                                         uint8_t* cancellation_out)
{
    NetdSocketEngineImpl* implementation;
    NetdSocketEngineRequestRow* request;
    NetdSocketEngineStatus status;
    if (engine == 0 || lease == 0 || cancellation_out == 0)
        return NETD_SOCKET_ENGINE_NULL_ARGUMENT;
    if (NetdSocketEngineInternalRangesOverlap(engine, sizeof(*engine), lease, sizeof(*lease)) ||
        NetdSocketEngineInternalRangesOverlap(engine, sizeof(*engine), cancellation_out, sizeof(*cancellation_out)) ||
        NetdSocketEngineInternalRangesOverlap(lease, sizeof(*lease), cancellation_out, sizeof(*cancellation_out)))
        return NETD_SOCKET_ENGINE_ALIASED_STORAGE;
    *cancellation_out = 0;
    implementation = (NetdSocketEngineImpl*)(void*)engine;
    if (implementation->magic != NETD_SOCKET_ENGINE_MAGIC)
        return NETD_SOCKET_ENGINE_NOT_INITIALIZED;
    if (!NetdSocketEngineInternalValidate(implementation))
        return NETD_SOCKET_ENGINE_CORRUPT_STATE;
    status = NetdSocketEngineInternalResolveRequest(implementation, &lease->request, &request);
    if (status != NETD_SOCKET_ENGINE_OK)
        return status;
    if (request->state != NETD_SOCKET_ENGINE_REQUEST_RUNNING_INTERNAL)
        return NETD_SOCKET_ENGINE_STALE_WORK;
    *cancellation_out = request->cancel_requested;
    return NETD_SOCKET_ENGINE_OK;
}

static uint8_t CompletionStatusIsCanonical(uint32_t status)
{
    return (uint8_t)(status <= NETD_SOCKET_ENGINE_REPLY_BACKEND_FAILURE &&
                     status != NETD_SOCKET_ENGINE_REPLY_CANCELLED);
}

static uint8_t BackendIdentityIsUnique(const NetdSocketEngineImpl* implementation,
                                       const NetdSocketEngineBackendSocketIdentity* backend,
                                       uint32_t except_socket_slot)
{
    uint32_t index;
    for (index = 0; index < NETD_SOCKET_ENGINE_MAX_SOCKETS; ++index)
    {
        const NetdSocketEngineSocketRow* socket = &implementation->sockets[index];
        if (index != except_socket_slot &&
            (socket->state == NETD_SOCKET_ENGINE_SOCKET_OPEN || socket->state == NETD_SOCKET_ENGINE_SOCKET_CLOSING) &&
            NetdSocketEngineInternalBackendEqual(&socket->backend, backend))
            return 0;
    }
    return 1;
}

static void PrepareReply(NetdSocketEngineRequestRow* request, uint32_t status)
{
    NetdSocketEngineInternalClear(&request->reply, (uint32_t)sizeof(request->reply));
    request->reply.request_id = request->request.request_id;
    request->reply.operation = request->request.operation;
    request->reply.status = status;
    if (request->request.operation == NETD_SOCKET_ENGINE_OPERATION_CLOSE || status == NETD_SOCKET_ENGINE_REPLY_SUCCESS)
        request->reply.socket = request->request.socket;
    request->state = NETD_SOCKET_ENGINE_REQUEST_REPLY_READY_INTERNAL;
}

static void RetireRequestAndMaybePeer(NetdSocketEngineImpl* implementation, uint32_t request_slot, uint32_t peer_slot)
{
    NetdSocketEngineInternalRetireRequest(implementation, request_slot);
    NetdSocketEngineInternalMaybeFinalizePeer(implementation, peer_slot);
}

NetdSocketEngineCompleteResult NetdSocketEngineComplete(NetdSocketEngine* engine,
                                                        const NetdSocketEngineWorkLease* lease,
                                                        const NetdSocketEngineCompletion* completion)
{
    NetdSocketEngineCompleteResult result;
    NetdSocketEngineImpl* implementation;
    NetdSocketEngineRequestRow* request;
    NetdSocketEngineSocketRow* socket;
    NetdSocketEnginePeerRow* peer;
    NetdSocketEngineStatus status;
    uint32_t request_slot;
    uint32_t peer_slot;
    uint32_t socket_slot;
    uint8_t abandoning;
    NetdSocketEngineInternalClear(&result, (uint32_t)sizeof(result));
    if (engine == 0 || lease == 0 || completion == 0)
    {
        result.status = NETD_SOCKET_ENGINE_NULL_ARGUMENT;
        return result;
    }
    if (NetdSocketEngineInternalRangesOverlap(engine, sizeof(*engine), lease, sizeof(*lease)) ||
        NetdSocketEngineInternalRangesOverlap(engine, sizeof(*engine), completion, sizeof(*completion)))
    {
        result.status = NETD_SOCKET_ENGINE_ALIASED_STORAGE;
        return result;
    }
    status = ResolveEngine(engine, &implementation);
    if (status != NETD_SOCKET_ENGINE_OK)
    {
        result.status = status;
        return result;
    }
    if (NetdSocketEngineInternalHasPublishingReply(implementation))
    {
        result.status = NETD_SOCKET_ENGINE_REPLY_IN_FLIGHT;
        return result;
    }
    status = NetdSocketEngineInternalResolveRequest(implementation, &lease->request, &request);
    if (status != NETD_SOCKET_ENGINE_OK || request->state != NETD_SOCKET_ENGINE_REQUEST_RUNNING_INTERNAL)
    {
        result.status = status != NETD_SOCKET_ENGINE_OK ? status : NETD_SOCKET_ENGINE_STALE_WORK;
        return result;
    }
    if (!CompletionStatusIsCanonical(completion->reply_status) || completion->reserved32 != 0)
    {
        result.status = NETD_SOCKET_ENGINE_INVALID_COMPLETION;
        return result;
    }

    request_slot = lease->request.request_slot;
    peer_slot = request->peer_slot;
    socket_slot = request->socket_slot;
    peer = &implementation->peers[peer_slot];
    socket = &implementation->sockets[socket_slot];
    abandoning = (uint8_t)(implementation->state == NETD_SOCKET_ENGINE_STATE_DRAINING ||
                           peer->state == NETD_SOCKET_ENGINE_PEER_STATE_CLOSING);

    if (request->request.operation == NETD_SOCKET_ENGINE_OPERATION_OPEN)
    {
        if (completion->reply_status == NETD_SOCKET_ENGINE_REPLY_SUCCESS)
        {
            if (!NetdSocketEngineInternalBackendIsCanonical(&completion->backend) ||
                !NetdSocketEngineInternalTransportEqual(&completion->backend.transport, &implementation->transport) ||
                !BackendIdentityIsUnique(implementation, &completion->backend, socket_slot))
            {
                result.status = NETD_SOCKET_ENGINE_INVALID_COMPLETION;
                return result;
            }
            socket->backend = completion->backend;
            socket->state = NETD_SOCKET_ENGINE_SOCKET_OPEN;
        }
        else if (!NetdSocketEngineInternalBackendIsZero(&completion->backend))
        {
            result.status = NETD_SOCKET_ENGINE_INVALID_COMPLETION;
            return result;
        }

        if (request->cancel_requested || abandoning)
        {
            if (completion->reply_status == NETD_SOCKET_ENGINE_REPLY_SUCCESS)
            {
                result.cleanup = NetdSocketEngineInternalCleanupRecord(implementation, socket_slot,
                                                                       request->abandon_cleanup_reason != 0
                                                                           ? request->abandon_cleanup_reason
                                                                           : NETD_SOCKET_ENGINE_CLEANUP_CANCELLED_OPEN);
                result.cleanup_valid = 1;
            }
            NetdSocketEngineInternalRetireSocket(implementation, socket_slot);
            request->socket_slot = NETD_SOCKET_ENGINE_INVALID_SLOT;
            if (!abandoning)
            {
                PrepareReply(request, NETD_SOCKET_ENGINE_REPLY_CANCELLED);
                result.reply_ready = 1;
            }
            else
            {
                RetireRequestAndMaybePeer(implementation, request_slot, peer_slot);
                result.request_retired = 1;
            }
            result.status = NETD_SOCKET_ENGINE_OK;
            return result;
        }

        if (completion->reply_status != NETD_SOCKET_ENGINE_REPLY_SUCCESS)
        {
            NetdSocketEngineInternalRetireSocket(implementation, socket_slot);
            request->socket_slot = NETD_SOCKET_ENGINE_INVALID_SLOT;
        }
        PrepareReply(request, completion->reply_status);
        result.reply_ready = 1;
        result.status = NETD_SOCKET_ENGINE_OK;
        return result;
    }

    if (!NetdSocketEngineInternalBackendIsZero(&completion->backend))
    {
        result.status = NETD_SOCKET_ENGINE_INVALID_COMPLETION;
        return result;
    }
    if (completion->reply_status == NETD_SOCKET_ENGINE_REPLY_SUCCESS)
    {
        NetdSocketEngineInternalRetireSocket(implementation, socket_slot);
        request->socket_slot = NETD_SOCKET_ENGINE_INVALID_SLOT;
    }
    else if (abandoning)
    {
        result.cleanup =
            NetdSocketEngineInternalCleanupRecord(implementation, socket_slot, NETD_SOCKET_ENGINE_CLEANUP_FAILED_CLOSE);
        result.cleanup_valid = 1;
        NetdSocketEngineInternalRetireSocket(implementation, socket_slot);
        request->socket_slot = NETD_SOCKET_ENGINE_INVALID_SLOT;
    }
    else
        socket->state = NETD_SOCKET_ENGINE_SOCKET_OPEN;

    if (abandoning)
    {
        RetireRequestAndMaybePeer(implementation, request_slot, peer_slot);
        result.request_retired = 1;
    }
    else
    {
        PrepareReply(request, completion->reply_status);
        result.reply_ready = 1;
    }
    result.status = NETD_SOCKET_ENGINE_OK;
    return result;
}
