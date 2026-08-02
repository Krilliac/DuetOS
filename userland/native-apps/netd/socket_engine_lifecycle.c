#include "socket_engine_internal.h"

static NetdSocketEngineStatus ResolveLifecycleEngine(NetdSocketEngine* engine,
                                                     NetdSocketEngineImpl** implementation_out)
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

static void PrepareCancelledReply(NetdSocketEngineRequestRow* request)
{
    NetdSocketEngineInternalClear(&request->reply, (uint32_t)sizeof(request->reply));
    request->reply.request_id = request->request.request_id;
    request->reply.operation = request->request.operation;
    request->reply.status = NETD_SOCKET_ENGINE_REPLY_CANCELLED;
    if (request->request.operation == NETD_SOCKET_ENGINE_OPERATION_CLOSE)
        request->reply.socket = request->request.socket;
    request->state = NETD_SOCKET_ENGINE_REQUEST_REPLY_READY_INTERNAL;
}

static NetdSocketEngineRequestRow* FindPeerRequest(NetdSocketEngineImpl* implementation, uint32_t peer_slot,
                                                   uint64_t peer_generation, uint64_t request_id, uint32_t* slot_out)
{
    uint32_t index;
    for (index = 0; index < NETD_SOCKET_ENGINE_MAX_REQUESTS; ++index)
    {
        NetdSocketEngineRequestRow* request = &implementation->requests[index];
        if (request->state != NETD_SOCKET_ENGINE_REQUEST_FREE && request->state != NETD_SOCKET_ENGINE_REQUEST_RETIRED &&
            request->peer_slot == peer_slot && request->peer_generation == peer_generation &&
            request->request.request_id == request_id)
        {
            *slot_out = index;
            return request;
        }
    }
    return 0;
}

static uint8_t SocketHasRunningRequest(const NetdSocketEngineImpl* implementation, uint32_t socket_slot)
{
    uint32_t index;
    for (index = 0; index < NETD_SOCKET_ENGINE_MAX_REQUESTS; ++index)
    {
        const NetdSocketEngineRequestRow* request = &implementation->requests[index];
        if (request->state == NETD_SOCKET_ENGINE_REQUEST_RUNNING_INTERNAL && request->socket_slot == socket_slot)
            return 1;
    }
    return 0;
}

static NetdSocketEngineStatus AppendSocketCleanup(NetdSocketEngineImpl* implementation, uint32_t socket_slot,
                                                  uint32_t reason, NetdSocketEngineCleanupBatch* cleanup)
{
    const NetdSocketEngineCleanupRecord record =
        NetdSocketEngineInternalCleanupRecord(implementation, socket_slot, reason);
    return NetdSocketEngineInternalAppendCleanup(cleanup, &record);
}

static NetdSocketEngineStatus AbandonPeer(NetdSocketEngineImpl* implementation, uint32_t peer_slot, uint32_t reason,
                                          NetdSocketEngineCleanupBatch* cleanup)
{
    NetdSocketEnginePeerRow* peer = &implementation->peers[peer_slot];
    uint32_t index;
    peer->state = NETD_SOCKET_ENGINE_PEER_STATE_CLOSING;

    for (index = 0; index < NETD_SOCKET_ENGINE_MAX_REQUESTS; ++index)
    {
        NetdSocketEngineRequestRow* request = &implementation->requests[index];
        uint32_t socket_slot;
        if (request->state == NETD_SOCKET_ENGINE_REQUEST_FREE || request->state == NETD_SOCKET_ENGINE_REQUEST_RETIRED ||
            request->peer_slot != peer_slot || request->peer_generation != peer->generation)
            continue;
        socket_slot = request->socket_slot;
        if (request->state == NETD_SOCKET_ENGINE_REQUEST_RUNNING_INTERNAL)
        {
            if (request->request.operation == NETD_SOCKET_ENGINE_OPERATION_OPEN)
            {
                request->cancel_requested = 1;
                request->abandon_cleanup_reason = (uint8_t)reason;
            }
            continue;
        }
        if (request->state == NETD_SOCKET_ENGINE_REQUEST_REPLY_PUBLISHING_INTERNAL)
            return NETD_SOCKET_ENGINE_REPLY_IN_FLIGHT;
        if (socket_slot != NETD_SOCKET_ENGINE_INVALID_SLOT)
        {
            NetdSocketEngineSocketRow* socket = &implementation->sockets[socket_slot];
            if (NetdSocketEngineInternalBackendIsCanonical(&socket->backend))
            {
                NetdSocketEngineStatus status = AppendSocketCleanup(implementation, socket_slot, reason, cleanup);
                if (status != NETD_SOCKET_ENGINE_OK)
                    return status;
            }
            NetdSocketEngineInternalRetireSocket(implementation, socket_slot);
            request->socket_slot = NETD_SOCKET_ENGINE_INVALID_SLOT;
        }
        NetdSocketEngineInternalRetireRequest(implementation, index);
    }

    for (index = 0; index < NETD_SOCKET_ENGINE_MAX_SOCKETS; ++index)
    {
        NetdSocketEngineSocketRow* socket = &implementation->sockets[index];
        NetdSocketEngineStatus status;
        if ((socket->state == NETD_SOCKET_ENGINE_SOCKET_FREE || socket->state == NETD_SOCKET_ENGINE_SOCKET_RETIRED) ||
            socket->owner_peer_slot != peer_slot || socket->owner_peer_generation != peer->generation ||
            SocketHasRunningRequest(implementation, index))
            continue;
        if (!NetdSocketEngineInternalBackendIsCanonical(&socket->backend))
            return NETD_SOCKET_ENGINE_CORRUPT_STATE;
        status = AppendSocketCleanup(implementation, index, reason, cleanup);
        if (status != NETD_SOCKET_ENGINE_OK)
            return status;
        NetdSocketEngineInternalRetireSocket(implementation, index);
    }
    NetdSocketEngineInternalMaybeFinalizePeer(implementation, peer_slot);
    return NETD_SOCKET_ENGINE_OK;
}

NetdSocketEngineCancelResult NetdSocketEngineCancel(NetdSocketEngine* engine, const NetdSocketEnginePeerReceipt* peer,
                                                    uint64_t request_id)
{
    NetdSocketEngineCancelResult result;
    NetdSocketEngineImpl* implementation;
    NetdSocketEnginePeerRow* peer_row;
    NetdSocketEngineRequestRow* request;
    NetdSocketEngineStatus status;
    uint32_t request_slot = NETD_SOCKET_ENGINE_INVALID_SLOT;
    NetdSocketEngineInternalClear(&result, (uint32_t)sizeof(result));
    if (engine == 0 || peer == 0)
    {
        result.status = NETD_SOCKET_ENGINE_NULL_ARGUMENT;
        return result;
    }
    if (NetdSocketEngineInternalRangesOverlap(engine, sizeof(*engine), peer, sizeof(*peer)))
    {
        result.status = NETD_SOCKET_ENGINE_ALIASED_STORAGE;
        return result;
    }
    status = ResolveLifecycleEngine(engine, &implementation);
    if (status != NETD_SOCKET_ENGINE_OK)
    {
        result.status = status;
        return result;
    }
    if (implementation->state == NETD_SOCKET_ENGINE_STATE_AWAITING_TRANSPORT)
    {
        result.status = NETD_SOCKET_ENGINE_TRANSPORT_UNAVAILABLE;
        return result;
    }
    if (implementation->state == NETD_SOCKET_ENGINE_STATE_DRAINING)
    {
        result.status = NETD_SOCKET_ENGINE_DRAINING;
        return result;
    }
    if (implementation->state == NETD_SOCKET_ENGINE_STATE_CLOSED)
    {
        result.status = NETD_SOCKET_ENGINE_CLOSED;
        return result;
    }
    status = NetdSocketEngineInternalResolvePeer(implementation, peer, &peer_row);
    if (status != NETD_SOCKET_ENGINE_OK || peer_row->state == NETD_SOCKET_ENGINE_PEER_STATE_CLOSING)
    {
        result.status = status != NETD_SOCKET_ENGINE_OK ? status : NETD_SOCKET_ENGINE_PEER_CLOSING;
        return result;
    }
    request = FindPeerRequest(implementation, peer->peer_slot, peer->peer_generation, request_id, &request_slot);
    if (request == 0)
    {
        result.status = request_id == 0 ? NETD_SOCKET_ENGINE_INVALID_ARGUMENT
                                        : ((peer_row->next_request_id == 0 || request_id < peer_row->next_request_id)
                                               ? NETD_SOCKET_ENGINE_REPLAYED_REQUEST
                                               : NETD_SOCKET_ENGINE_REQUEST_NOT_FOUND);
        return result;
    }
    if (NetdSocketEngineInternalHasPublishingReply(implementation))
    {
        result.status = request->state == NETD_SOCKET_ENGINE_REQUEST_REPLY_PUBLISHING_INTERNAL
                            ? NETD_SOCKET_ENGINE_CANCEL_TOO_LATE
                            : NETD_SOCKET_ENGINE_REPLY_IN_FLIGHT;
        return result;
    }

    if (request->state == NETD_SOCKET_ENGINE_REQUEST_QUEUED_INTERNAL)
    {
        NetdSocketEngineSocketRow* socket = &implementation->sockets[request->socket_slot];
        if (request->request.operation == NETD_SOCKET_ENGINE_OPERATION_OPEN)
        {
            NetdSocketEngineInternalRetireSocket(implementation, request->socket_slot);
            request->socket_slot = NETD_SOCKET_ENGINE_INVALID_SLOT;
        }
        else
            socket->state = NETD_SOCKET_ENGINE_SOCKET_OPEN;
        request->cancel_requested = 1;
        PrepareCancelledReply(request);
        result.cancellation_requested = 1;
        result.reply_ready = 1;
        result.status = NETD_SOCKET_ENGINE_OK;
        return result;
    }
    if (request->state == NETD_SOCKET_ENGINE_REQUEST_RUNNING_INTERNAL)
    {
        if (request->request.operation == NETD_SOCKET_ENGINE_OPERATION_CLOSE)
        {
            result.status = NETD_SOCKET_ENGINE_CANCEL_TOO_LATE;
            return result;
        }
        request->cancel_requested = 1;
        result.cancellation_requested = 1;
        result.status = NETD_SOCKET_ENGINE_OK;
        return result;
    }
    if (request->state == NETD_SOCKET_ENGINE_REQUEST_REPLY_READY_INTERNAL &&
        request->request.operation == NETD_SOCKET_ENGINE_OPERATION_OPEN)
    {
        if (request->reply.status == NETD_SOCKET_ENGINE_REPLY_SUCCESS)
        {
            result.cleanup = NetdSocketEngineInternalCleanupRecord(implementation, request->socket_slot,
                                                                   NETD_SOCKET_ENGINE_CLEANUP_CANCELLED_OPEN);
            result.cleanup_valid = 1;
            NetdSocketEngineInternalRetireSocket(implementation, request->socket_slot);
            request->socket_slot = NETD_SOCKET_ENGINE_INVALID_SLOT;
        }
        request->cancel_requested = 1;
        PrepareCancelledReply(request);
        result.cancellation_requested = 1;
        result.reply_ready = 1;
        result.status = NETD_SOCKET_ENGINE_OK;
        return result;
    }
    result.status = NETD_SOCKET_ENGINE_CANCEL_TOO_LATE;
    return result;
}

NetdSocketEngineStatus NetdSocketEngineClosePeer(NetdSocketEngine* engine, const NetdSocketEnginePeerReceipt* receipt,
                                                 NetdSocketEngineCleanupBatch* cleanup_out)
{
    NetdSocketEngineImpl* implementation;
    NetdSocketEnginePeerRow* peer;
    NetdSocketEngineStatus status;
    if (engine == 0 || receipt == 0 || cleanup_out == 0)
        return NETD_SOCKET_ENGINE_NULL_ARGUMENT;
    if (NetdSocketEngineInternalRangesOverlap(engine, sizeof(*engine), receipt, sizeof(*receipt)) ||
        NetdSocketEngineInternalRangesOverlap(engine, sizeof(*engine), cleanup_out, sizeof(*cleanup_out)) ||
        NetdSocketEngineInternalRangesOverlap(receipt, sizeof(*receipt), cleanup_out, sizeof(*cleanup_out)))
        return NETD_SOCKET_ENGINE_ALIASED_STORAGE;
    NetdSocketEngineInternalClear(cleanup_out, (uint32_t)sizeof(*cleanup_out));
    status = ResolveLifecycleEngine(engine, &implementation);
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
    status = NetdSocketEngineInternalResolvePeer(implementation, receipt, &peer);
    if (status != NETD_SOCKET_ENGINE_OK)
        return status;
    if (peer->state == NETD_SOCKET_ENGINE_PEER_STATE_CLOSING)
        return NETD_SOCKET_ENGINE_PEER_CLOSING;
    return AbandonPeer(implementation, receipt->peer_slot, NETD_SOCKET_ENGINE_CLEANUP_PEER_CLOSED, cleanup_out);
}

NetdSocketEngineStatus NetdSocketEngineGetNextReply(NetdSocketEngine* engine,
                                                    NetdSocketEngineReplyPublication* reply_out)
{
    NetdSocketEngineImpl* implementation;
    NetdSocketEngineStatus status;
    uint32_t offset;
    if (engine == 0 || reply_out == 0)
        return NETD_SOCKET_ENGINE_NULL_ARGUMENT;
    if (NetdSocketEngineInternalRangesOverlap(engine, sizeof(*engine), reply_out, sizeof(*reply_out)))
        return NETD_SOCKET_ENGINE_ALIASED_STORAGE;
    NetdSocketEngineInternalClear(reply_out, (uint32_t)sizeof(*reply_out));
    status = ResolveLifecycleEngine(engine, &implementation);
    if (status != NETD_SOCKET_ENGINE_OK)
        return status;
    if (NetdSocketEngineInternalHasPublishingReply(implementation))
        return NETD_SOCKET_ENGINE_REPLY_IN_FLIGHT;
    if (implementation->state == NETD_SOCKET_ENGINE_STATE_DRAINING)
        return NETD_SOCKET_ENGINE_DRAINING;
    if (implementation->state == NETD_SOCKET_ENGINE_STATE_CLOSED)
        return NETD_SOCKET_ENGINE_CLOSED;
    if (implementation->state == NETD_SOCKET_ENGINE_STATE_AWAITING_TRANSPORT)
        return NETD_SOCKET_ENGINE_TRANSPORT_UNAVAILABLE;
    for (offset = 0; offset < NETD_SOCKET_ENGINE_MAX_REQUESTS; ++offset)
    {
        const uint32_t slot = (implementation->next_reply_hint + offset) % NETD_SOCKET_ENGINE_MAX_REQUESTS;
        NetdSocketEngineRequestRow* request = &implementation->requests[slot];
        if (request->state != NETD_SOCKET_ENGINE_REQUEST_REPLY_READY_INTERNAL)
            continue;
        request->state = NETD_SOCKET_ENGINE_REQUEST_REPLY_PUBLISHING_INTERNAL;
        reply_out->lease.request = NetdSocketEngineInternalRequestReceipt(implementation, slot);
        reply_out->reply = request->reply;
        implementation->next_reply_hint = (slot + 1U) % NETD_SOCKET_ENGINE_MAX_REQUESTS;
        return NETD_SOCKET_ENGINE_OK;
    }
    return NETD_SOCKET_ENGINE_NO_REPLY;
}

NetdSocketEngineStatus NetdSocketEngineCommitReply(NetdSocketEngine* engine, const NetdSocketEngineReplyLease* lease)
{
    NetdSocketEngineImpl* implementation;
    NetdSocketEngineRequestRow* request;
    NetdSocketEngineStatus status;
    uint32_t peer_slot;
    if (engine == 0 || lease == 0)
        return NETD_SOCKET_ENGINE_NULL_ARGUMENT;
    if (NetdSocketEngineInternalRangesOverlap(engine, sizeof(*engine), lease, sizeof(*lease)))
        return NETD_SOCKET_ENGINE_ALIASED_STORAGE;
    status = ResolveLifecycleEngine(engine, &implementation);
    if (status != NETD_SOCKET_ENGINE_OK)
        return status;
    status = NetdSocketEngineInternalResolveRequest(implementation, &lease->request, &request);
    if (status != NETD_SOCKET_ENGINE_OK)
        return status;
    if (request->state != NETD_SOCKET_ENGINE_REQUEST_REPLY_PUBLISHING_INTERNAL)
        return NETD_SOCKET_ENGINE_STALE_REPLY;
    peer_slot = request->peer_slot;
    NetdSocketEngineInternalRetireRequest(implementation, lease->request.request_slot);
    NetdSocketEngineInternalMaybeFinalizePeer(implementation, peer_slot);
    return NETD_SOCKET_ENGINE_OK;
}

NetdSocketEngineStatus NetdSocketEngineAbortReply(NetdSocketEngine* engine, const NetdSocketEngineReplyLease* lease)
{
    NetdSocketEngineImpl* implementation;
    NetdSocketEngineRequestRow* request;
    NetdSocketEngineStatus status;
    if (engine == 0 || lease == 0)
        return NETD_SOCKET_ENGINE_NULL_ARGUMENT;
    if (NetdSocketEngineInternalRangesOverlap(engine, sizeof(*engine), lease, sizeof(*lease)))
        return NETD_SOCKET_ENGINE_ALIASED_STORAGE;
    status = ResolveLifecycleEngine(engine, &implementation);
    if (status != NETD_SOCKET_ENGINE_OK)
        return status;
    status = NetdSocketEngineInternalResolveRequest(implementation, &lease->request, &request);
    if (status != NETD_SOCKET_ENGINE_OK)
        return status;
    if (request->state != NETD_SOCKET_ENGINE_REQUEST_REPLY_PUBLISHING_INTERNAL)
        return NETD_SOCKET_ENGINE_STALE_REPLY;
    request->state = NETD_SOCKET_ENGINE_REQUEST_REPLY_READY_INTERNAL;
    return NETD_SOCKET_ENGINE_OK;
}

NetdSocketEngineStatus NetdSocketEngineBeginDrain(NetdSocketEngine* engine,
                                                  const NetdSocketEngineTransportReceipt* transport,
                                                  NetdSocketEngineCleanupBatch* cleanup_out)
{
    NetdSocketEngineImpl* implementation;
    NetdSocketEngineStatus status;
    uint32_t index;
    if (engine == 0 || cleanup_out == 0)
        return NETD_SOCKET_ENGINE_NULL_ARGUMENT;
    if ((transport != 0 &&
         NetdSocketEngineInternalRangesOverlap(engine, sizeof(*engine), transport, sizeof(*transport))) ||
        NetdSocketEngineInternalRangesOverlap(engine, sizeof(*engine), cleanup_out, sizeof(*cleanup_out)) ||
        (transport != 0 &&
         NetdSocketEngineInternalRangesOverlap(transport, sizeof(*transport), cleanup_out, sizeof(*cleanup_out))))
        return NETD_SOCKET_ENGINE_ALIASED_STORAGE;
    NetdSocketEngineInternalClear(cleanup_out, (uint32_t)sizeof(*cleanup_out));
    status = ResolveLifecycleEngine(engine, &implementation);
    if (status != NETD_SOCKET_ENGINE_OK)
        return status;
    if (NetdSocketEngineInternalHasPublishingReply(implementation))
        return NETD_SOCKET_ENGINE_REPLY_IN_FLIGHT;
    if (implementation->state == NETD_SOCKET_ENGINE_STATE_CLOSED)
        return NETD_SOCKET_ENGINE_CLOSED;
    if (implementation->state == NETD_SOCKET_ENGINE_STATE_DRAINING)
        return NETD_SOCKET_ENGINE_DRAINING;
    if (implementation->state == NETD_SOCKET_ENGINE_STATE_AWAITING_TRANSPORT)
    {
        if (transport != 0)
            return NETD_SOCKET_ENGINE_STALE_TRANSPORT;
    }
    else
    {
        if (transport == 0 || !NetdSocketEngineInstanceIdentityIsCanonical(&transport->instance) ||
            !NetdSocketEngineTransportIdentityIsCanonical(&transport->transport) ||
            !NetdSocketEngineInternalInstanceEqual(&implementation->instance, &transport->instance) ||
            !NetdSocketEngineInternalTransportEqual(&implementation->transport, &transport->transport))
            return NETD_SOCKET_ENGINE_STALE_TRANSPORT;
    }

    implementation->state = NETD_SOCKET_ENGINE_STATE_DRAINING;
    for (index = 0; index < NETD_SOCKET_ENGINE_MAX_PEERS; ++index)
    {
        if (implementation->peers[index].state != NETD_SOCKET_ENGINE_PEER_STATE_OPEN &&
            implementation->peers[index].state != NETD_SOCKET_ENGINE_PEER_STATE_CLOSING)
            continue;
        status = AbandonPeer(implementation, index, NETD_SOCKET_ENGINE_CLEANUP_TRANSPORT_DRAIN, cleanup_out);
        if (status != NETD_SOCKET_ENGINE_OK)
            return status;
    }
    return NETD_SOCKET_ENGINE_OK;
}

NetdSocketEngineStatus NetdSocketEngineFinishDrain(NetdSocketEngine* engine)
{
    NetdSocketEngineImpl* implementation;
    NetdSocketEngineStatus status = ResolveLifecycleEngine(engine, &implementation);
    if (status != NETD_SOCKET_ENGINE_OK)
        return status;
    if (implementation->state == NETD_SOCKET_ENGINE_STATE_CLOSED)
        return NETD_SOCKET_ENGINE_CLOSED;
    if (implementation->state != NETD_SOCKET_ENGINE_STATE_DRAINING)
        return NETD_SOCKET_ENGINE_INVALID_ARGUMENT;
    if (implementation->peer_count != 0 || implementation->socket_count != 0 || implementation->request_count != 0)
        return NETD_SOCKET_ENGINE_BUSY;
    NetdSocketEngineInternalClear(&implementation->transport, (uint32_t)sizeof(implementation->transport));
    implementation->state = NETD_SOCKET_ENGINE_STATE_CLOSED;
    return NetdSocketEngineInternalValidate(implementation) ? NETD_SOCKET_ENGINE_OK : NETD_SOCKET_ENGINE_CORRUPT_STATE;
}

const char* NetdSocketEngineStatusName(NetdSocketEngineStatus status)
{
    switch (status)
    {
    case NETD_SOCKET_ENGINE_OK:
        return "ok";
    case NETD_SOCKET_ENGINE_NULL_ARGUMENT:
        return "null-argument";
    case NETD_SOCKET_ENGINE_ALIASED_STORAGE:
        return "aliased-storage";
    case NETD_SOCKET_ENGINE_NONZERO_STORAGE:
        return "nonzero-storage";
    case NETD_SOCKET_ENGINE_ALREADY_INITIALIZED:
        return "already-initialized";
    case NETD_SOCKET_ENGINE_NOT_INITIALIZED:
        return "not-initialized";
    case NETD_SOCKET_ENGINE_CORRUPT_STATE:
        return "corrupt-state";
    case NETD_SOCKET_ENGINE_INVALID_IDENTITY:
        return "invalid-identity";
    case NETD_SOCKET_ENGINE_INVALID_ARGUMENT:
        return "invalid-argument";
    case NETD_SOCKET_ENGINE_CLOSED:
        return "closed";
    case NETD_SOCKET_ENGINE_DRAINING:
        return "draining";
    case NETD_SOCKET_ENGINE_TRANSPORT_UNAVAILABLE:
        return "transport-unavailable";
    case NETD_SOCKET_ENGINE_TRANSPORT_ALREADY_ATTACHED:
        return "transport-already-attached";
    case NETD_SOCKET_ENGINE_STALE_TRANSPORT:
        return "stale-transport";
    case NETD_SOCKET_ENGINE_UNAUTHORIZED:
        return "unauthorized";
    case NETD_SOCKET_ENGINE_PEER_CAPACITY:
        return "peer-capacity";
    case NETD_SOCKET_ENGINE_SOCKET_CAPACITY:
        return "socket-capacity";
    case NETD_SOCKET_ENGINE_REQUEST_CAPACITY:
        return "request-capacity";
    case NETD_SOCKET_ENGINE_GENERATION_EXHAUSTED:
        return "generation-exhausted";
    case NETD_SOCKET_ENGINE_SEQUENCE_EXHAUSTED:
        return "sequence-exhausted";
    case NETD_SOCKET_ENGINE_PEER_EXISTS:
        return "peer-exists";
    case NETD_SOCKET_ENGINE_PEER_NOT_FOUND:
        return "peer-not-found";
    case NETD_SOCKET_ENGINE_STALE_PEER:
        return "stale-peer";
    case NETD_SOCKET_ENGINE_PEER_CLOSING:
        return "peer-closing";
    case NETD_SOCKET_ENGINE_SOCKET_NOT_FOUND:
        return "socket-not-found";
    case NETD_SOCKET_ENGINE_STALE_SOCKET:
        return "stale-socket";
    case NETD_SOCKET_ENGINE_SOCKET_BUSY:
        return "socket-busy";
    case NETD_SOCKET_ENGINE_REPLAYED_REQUEST:
        return "replayed-request";
    case NETD_SOCKET_ENGINE_OUT_OF_ORDER_REQUEST:
        return "out-of-order-request";
    case NETD_SOCKET_ENGINE_REQUEST_NOT_FOUND:
        return "request-not-found";
    case NETD_SOCKET_ENGINE_NO_WORK:
        return "no-work";
    case NETD_SOCKET_ENGINE_STALE_WORK:
        return "stale-work";
    case NETD_SOCKET_ENGINE_INVALID_COMPLETION:
        return "invalid-completion";
    case NETD_SOCKET_ENGINE_NO_REPLY:
        return "no-reply";
    case NETD_SOCKET_ENGINE_STALE_REPLY:
        return "stale-reply";
    case NETD_SOCKET_ENGINE_REPLY_IN_FLIGHT:
        return "reply-in-flight";
    case NETD_SOCKET_ENGINE_CANCEL_TOO_LATE:
        return "cancel-too-late";
    case NETD_SOCKET_ENGINE_BUSY:
        return "busy";
    default:
        return "unknown";
    }
}
