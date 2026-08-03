#include "socket_engine_internal.h"

NetdSocketEnginePeerReceipt NetdSocketEngineInternalPeerReceipt(const NetdSocketEngineImpl* implementation,
                                                                uint32_t slot)
{
    NetdSocketEnginePeerReceipt receipt;
    const NetdSocketEnginePeerRow* row = &implementation->peers[slot];
    NetdSocketEngineInternalClear(&receipt, (uint32_t)sizeof(receipt));
    receipt.instance = implementation->instance;
    receipt.peer = row->identity;
    receipt.authority = row->authority;
    receipt.peer_generation = row->generation;
    receipt.peer_slot = slot;
    return receipt;
}

NetdSocketEngineSocketRef NetdSocketEngineInternalSocketRef(const NetdSocketEngineImpl* implementation, uint32_t slot)
{
    NetdSocketEngineSocketRef socket;
    NetdSocketEngineInternalClear(&socket, (uint32_t)sizeof(socket));
    socket.instance_generation = implementation->instance.instance_generation;
    socket.transport_generation = implementation->transport.generation;
    socket.generation = implementation->sockets[slot].generation;
    socket.slot = slot;
    return socket;
}

NetdSocketEngineRequestReceipt NetdSocketEngineInternalRequestReceipt(const NetdSocketEngineImpl* implementation,
                                                                      uint32_t slot)
{
    NetdSocketEngineRequestReceipt receipt;
    const NetdSocketEngineRequestRow* row = &implementation->requests[slot];
    NetdSocketEngineInternalClear(&receipt, (uint32_t)sizeof(receipt));
    receipt.peer = NetdSocketEngineInternalPeerReceipt(implementation, row->peer_slot);
    receipt.request_generation = row->generation;
    receipt.request_id = row->request.request_id;
    receipt.request_slot = slot;
    return receipt;
}

NetdSocketEngineCleanupRecord NetdSocketEngineInternalCleanupRecord(const NetdSocketEngineImpl* implementation,
                                                                    uint32_t socket_slot, uint32_t reason)
{
    NetdSocketEngineCleanupRecord record;
    NetdSocketEngineInternalClear(&record, (uint32_t)sizeof(record));
    record.socket = NetdSocketEngineInternalSocketRef(implementation, socket_slot);
    record.backend = implementation->sockets[socket_slot].backend;
    record.reason = reason;
    return record;
}

NetdSocketEngineStatus NetdSocketEngineInternalAppendCleanup(NetdSocketEngineCleanupBatch* batch,
                                                             const NetdSocketEngineCleanupRecord* record)
{
    if (batch->count >= NETD_SOCKET_ENGINE_CLEANUP_CAPACITY)
        return NETD_SOCKET_ENGINE_CORRUPT_STATE;
    batch->records[batch->count++] = *record;
    return NETD_SOCKET_ENGINE_OK;
}

NetdSocketEngineStatus NetdSocketEngineInternalResolvePeer(NetdSocketEngineImpl* implementation,
                                                           const NetdSocketEnginePeerReceipt* receipt,
                                                           NetdSocketEnginePeerRow** row_out)
{
    NetdSocketEnginePeerRow* row;
    if (receipt == 0 || row_out == 0 || !NetdSocketEngineInstanceIdentityIsCanonical(&receipt->instance) ||
        !NetdSocketEnginePeerIdentityIsCanonical(&receipt->peer) ||
        !NetdSocketEnginePeerAuthorityIsCanonical(&receipt->authority) || receipt->peer_generation == 0 ||
        receipt->peer_slot >= NETD_SOCKET_ENGINE_MAX_PEERS || receipt->reserved32 != 0)
        return NETD_SOCKET_ENGINE_INVALID_IDENTITY;
    if (!NetdSocketEngineInternalInstanceEqual(&implementation->instance, &receipt->instance))
        return NETD_SOCKET_ENGINE_STALE_PEER;
    row = &implementation->peers[receipt->peer_slot];
    if (row->generation != receipt->peer_generation || row->state == NETD_SOCKET_ENGINE_PEER_STATE_FREE ||
        row->state == NETD_SOCKET_ENGINE_PEER_STATE_RETIRED ||
        !NetdSocketEngineInternalPeerEqual(&row->identity, &receipt->peer) ||
        !NetdSocketEngineInternalAuthorityEqual(&row->authority, &receipt->authority))
        return NETD_SOCKET_ENGINE_STALE_PEER;
    *row_out = row;
    return NETD_SOCKET_ENGINE_OK;
}

NetdSocketEngineStatus NetdSocketEngineInternalResolveRequest(NetdSocketEngineImpl* implementation,
                                                              const NetdSocketEngineRequestReceipt* receipt,
                                                              NetdSocketEngineRequestRow** row_out)
{
    NetdSocketEnginePeerRow* peer;
    NetdSocketEngineRequestRow* row;
    NetdSocketEngineStatus status;
    if (receipt == 0 || row_out == 0 || receipt->request_generation == 0 || receipt->request_id == 0 ||
        receipt->request_slot >= NETD_SOCKET_ENGINE_MAX_REQUESTS || receipt->reserved32 != 0)
        return NETD_SOCKET_ENGINE_INVALID_IDENTITY;
    status = NetdSocketEngineInternalResolvePeer(implementation, &receipt->peer, &peer);
    if (status != NETD_SOCKET_ENGINE_OK)
        return status;
    row = &implementation->requests[receipt->request_slot];
    if (row->generation != receipt->request_generation || row->request.request_id != receipt->request_id ||
        row->peer_slot != receipt->peer.peer_slot || row->peer_generation != receipt->peer.peer_generation ||
        row->state == NETD_SOCKET_ENGINE_REQUEST_FREE || row->state == NETD_SOCKET_ENGINE_REQUEST_RETIRED)
        return NETD_SOCKET_ENGINE_STALE_WORK;
    *row_out = row;
    return NETD_SOCKET_ENGINE_OK;
}

NetdSocketEngineStatus NetdSocketEngineInternalResolveSocket(NetdSocketEngineImpl* implementation,
                                                             const NetdSocketEnginePeerRow* owner, uint32_t owner_slot,
                                                             const NetdSocketEngineSocketRef* socket,
                                                             NetdSocketEngineSocketRow** row_out)
{
    NetdSocketEngineSocketRow* row;
    if (socket == 0 || row_out == 0 || owner == 0 || owner_slot >= NETD_SOCKET_ENGINE_MAX_PEERS ||
        !NetdSocketEngineInternalSocketRefIsCanonical(implementation, socket))
        return NETD_SOCKET_ENGINE_INVALID_IDENTITY;
    row = &implementation->sockets[socket->slot];
    if (row->generation != socket->generation)
        return NETD_SOCKET_ENGINE_STALE_SOCKET;
    if (row->state == NETD_SOCKET_ENGINE_SOCKET_FREE || row->state == NETD_SOCKET_ENGINE_SOCKET_RETIRED)
        return NETD_SOCKET_ENGINE_SOCKET_NOT_FOUND;
    if (row->owner_peer_slot != owner_slot || row->owner_peer_generation != owner->generation)
        return NETD_SOCKET_ENGINE_STALE_SOCKET;
    *row_out = row;
    return NETD_SOCKET_ENGINE_OK;
}

void NetdSocketEngineInternalRetireRequest(NetdSocketEngineImpl* implementation, uint32_t slot)
{
    NetdSocketEngineRequestRow* row = &implementation->requests[slot];
    const uint64_t generation = row->generation;
    const uint32_t peer_slot = row->peer_slot;
    NetdSocketEngineInternalClear(row, (uint32_t)sizeof(*row));
    row->generation = generation;
    if (generation == UINT64_MAX)
        row->state = NETD_SOCKET_ENGINE_REQUEST_RETIRED;
    else
    {
        row->generation = generation + UINT64_C(1);
        row->state = NETD_SOCKET_ENGINE_REQUEST_FREE;
    }
    --implementation->request_count;
    --implementation->peers[peer_slot].active_requests;
}

void NetdSocketEngineInternalRetireSocket(NetdSocketEngineImpl* implementation, uint32_t slot)
{
    NetdSocketEngineSocketRow* row = &implementation->sockets[slot];
    const uint64_t generation = row->generation;
    const uint32_t peer_slot = row->owner_peer_slot;
    NetdSocketEngineInternalClear(row, (uint32_t)sizeof(*row));
    row->generation = generation;
    if (generation == UINT64_MAX)
        row->state = NETD_SOCKET_ENGINE_SOCKET_RETIRED;
    else
    {
        row->generation = generation + UINT64_C(1);
        row->state = NETD_SOCKET_ENGINE_SOCKET_FREE;
    }
    --implementation->socket_count;
    --implementation->peers[peer_slot].active_sockets;
}

void NetdSocketEngineInternalMaybeFinalizePeer(NetdSocketEngineImpl* implementation, uint32_t slot)
{
    NetdSocketEnginePeerRow* row = &implementation->peers[slot];
    uint64_t generation;
    if (row->state != NETD_SOCKET_ENGINE_PEER_STATE_CLOSING || row->active_sockets != 0 || row->active_requests != 0)
        return;
    generation = row->generation;
    NetdSocketEngineInternalClear(row, (uint32_t)sizeof(*row));
    row->generation = generation;
    if (generation == UINT64_MAX)
        row->state = NETD_SOCKET_ENGINE_PEER_STATE_RETIRED;
    else
    {
        row->generation = generation + UINT64_C(1);
        row->state = NETD_SOCKET_ENGINE_PEER_STATE_FREE;
    }
    --implementation->peer_count;
}

static uint8_t ChannelEqual(const NetdSocketEngineChannelIdentity* left, const NetdSocketEngineChannelIdentity* right)
{
    return (uint8_t)(left->slot == right->slot && left->role == right->role && left->generation == right->generation &&
                     left->epoch == right->epoch);
}

NetdSocketEngineStatus NetdSocketEngineInitialize(NetdSocketEngine* engine,
                                                  const NetdSocketEngineInstanceIdentity* instance,
                                                  uint64_t first_slot_generation)
{
    NetdSocketEngineImpl* implementation;
    uint32_t index;
    if (engine == 0 || instance == 0)
        return NETD_SOCKET_ENGINE_NULL_ARGUMENT;
    if (NetdSocketEngineInternalRangesOverlap(engine, sizeof(*engine), instance, sizeof(*instance)))
        return NETD_SOCKET_ENGINE_ALIASED_STORAGE;
    if (!NetdSocketEngineInternalStorageIsZero(engine, (uint32_t)sizeof(*engine)))
        return NetdSocketEngineInternalReadOnly(engine)->magic == NETD_SOCKET_ENGINE_MAGIC
                   ? NETD_SOCKET_ENGINE_ALREADY_INITIALIZED
                   : NETD_SOCKET_ENGINE_NONZERO_STORAGE;
    if (!NetdSocketEngineInstanceIdentityIsCanonical(instance) || first_slot_generation == 0)
        return NETD_SOCKET_ENGINE_INVALID_IDENTITY;

    implementation = NetdSocketEngineInternalMutable(engine);
    implementation->magic = NETD_SOCKET_ENGINE_MAGIC;
    implementation->instance = *instance;
    implementation->first_slot_generation = first_slot_generation;
    implementation->state = NETD_SOCKET_ENGINE_STATE_AWAITING_TRANSPORT;
    for (index = 0; index < NETD_SOCKET_ENGINE_MAX_PEERS; ++index)
        implementation->peers[index].generation = first_slot_generation;
    for (index = 0; index < NETD_SOCKET_ENGINE_MAX_SOCKETS; ++index)
        implementation->sockets[index].generation = first_slot_generation;
    for (index = 0; index < NETD_SOCKET_ENGINE_MAX_REQUESTS; ++index)
        implementation->requests[index].generation = first_slot_generation;
    return NetdSocketEngineInternalValidate(implementation) ? NETD_SOCKET_ENGINE_OK : NETD_SOCKET_ENGINE_CORRUPT_STATE;
}

NetdSocketEngineStatus NetdSocketEngineAttachTransport(NetdSocketEngine* engine,
                                                       const NetdSocketEngineTransportIdentity* transport,
                                                       NetdSocketEngineTransportReceipt* receipt_out)
{
    NetdSocketEngineImpl* implementation;
    if (engine == 0 || transport == 0 || receipt_out == 0)
        return NETD_SOCKET_ENGINE_NULL_ARGUMENT;
    if (NetdSocketEngineInternalRangesOverlap(engine, sizeof(*engine), transport, sizeof(*transport)) ||
        NetdSocketEngineInternalRangesOverlap(engine, sizeof(*engine), receipt_out, sizeof(*receipt_out)) ||
        NetdSocketEngineInternalRangesOverlap(transport, sizeof(*transport), receipt_out, sizeof(*receipt_out)))
        return NETD_SOCKET_ENGINE_ALIASED_STORAGE;
    NetdSocketEngineInternalClear(receipt_out, (uint32_t)sizeof(*receipt_out));
    implementation = NetdSocketEngineInternalMutable(engine);
    if (implementation->magic != NETD_SOCKET_ENGINE_MAGIC)
        return NETD_SOCKET_ENGINE_NOT_INITIALIZED;
    if (!NetdSocketEngineInternalValidate(implementation))
        return NETD_SOCKET_ENGINE_CORRUPT_STATE;
    if (!NetdSocketEngineTransportIdentityIsCanonical(transport))
        return NETD_SOCKET_ENGINE_INVALID_IDENTITY;
    if (implementation->state == NETD_SOCKET_ENGINE_STATE_OPEN)
        return NETD_SOCKET_ENGINE_TRANSPORT_ALREADY_ATTACHED;
    if (implementation->state == NETD_SOCKET_ENGINE_STATE_DRAINING)
        return NETD_SOCKET_ENGINE_DRAINING;
    if (implementation->state == NETD_SOCKET_ENGINE_STATE_CLOSED)
        return NETD_SOCKET_ENGINE_CLOSED;
    implementation->transport = *transport;
    implementation->state = NETD_SOCKET_ENGINE_STATE_OPEN;
    receipt_out->instance = implementation->instance;
    receipt_out->transport = implementation->transport;
    return NETD_SOCKET_ENGINE_OK;
}

NetdSocketEngineStatus NetdSocketEngineOpenPeer(NetdSocketEngine* engine, const NetdSocketEnginePeerIdentity* peer,
                                                const NetdSocketEnginePeerAuthority* authority,
                                                uint64_t first_request_id, NetdSocketEnginePeerReceipt* receipt_out)
{
    NetdSocketEngineImpl* implementation;
    uint32_t selected = NETD_SOCKET_ENGINE_INVALID_SLOT;
    uint32_t offset;
    if (engine == 0 || peer == 0 || authority == 0 || receipt_out == 0)
        return NETD_SOCKET_ENGINE_NULL_ARGUMENT;
    if (NetdSocketEngineInternalRangesOverlap(engine, sizeof(*engine), peer, sizeof(*peer)) ||
        NetdSocketEngineInternalRangesOverlap(engine, sizeof(*engine), authority, sizeof(*authority)) ||
        NetdSocketEngineInternalRangesOverlap(engine, sizeof(*engine), receipt_out, sizeof(*receipt_out)) ||
        NetdSocketEngineInternalRangesOverlap(peer, sizeof(*peer), receipt_out, sizeof(*receipt_out)) ||
        NetdSocketEngineInternalRangesOverlap(authority, sizeof(*authority), receipt_out, sizeof(*receipt_out)))
        return NETD_SOCKET_ENGINE_ALIASED_STORAGE;
    NetdSocketEngineInternalClear(receipt_out, (uint32_t)sizeof(*receipt_out));
    implementation = NetdSocketEngineInternalMutable(engine);
    if (implementation->magic != NETD_SOCKET_ENGINE_MAGIC)
        return NETD_SOCKET_ENGINE_NOT_INITIALIZED;
    if (!NetdSocketEngineInternalValidate(implementation))
        return NETD_SOCKET_ENGINE_CORRUPT_STATE;
    if (NetdSocketEngineInternalHasPublishingReply(implementation))
        return NETD_SOCKET_ENGINE_REPLY_IN_FLIGHT;
    if (implementation->state == NETD_SOCKET_ENGINE_STATE_AWAITING_TRANSPORT)
        return NETD_SOCKET_ENGINE_TRANSPORT_UNAVAILABLE;
    if (implementation->state == NETD_SOCKET_ENGINE_STATE_DRAINING)
        return NETD_SOCKET_ENGINE_DRAINING;
    if (implementation->state == NETD_SOCKET_ENGINE_STATE_CLOSED)
        return NETD_SOCKET_ENGINE_CLOSED;
    if (!NetdSocketEnginePeerIdentityIsCanonical(peer) || !NetdSocketEnginePeerAuthorityIsCanonical(authority) ||
        first_request_id == 0)
        return NETD_SOCKET_ENGINE_INVALID_IDENTITY;

    for (offset = 0; offset < NETD_SOCKET_ENGINE_MAX_PEERS; ++offset)
    {
        const uint32_t slot = (implementation->next_peer_hint + offset) % NETD_SOCKET_ENGINE_MAX_PEERS;
        NetdSocketEnginePeerRow* row = &implementation->peers[slot];
        if (row->state == NETD_SOCKET_ENGINE_PEER_STATE_OPEN || row->state == NETD_SOCKET_ENGINE_PEER_STATE_CLOSING)
        {
            if (ChannelEqual(&row->identity.channel, &peer->channel))
                return NetdSocketEngineInternalPeerEqual(&row->identity, peer) ? NETD_SOCKET_ENGINE_PEER_EXISTS
                                                                               : NETD_SOCKET_ENGINE_INVALID_IDENTITY;
        }
        else if (selected == NETD_SOCKET_ENGINE_INVALID_SLOT && row->state == NETD_SOCKET_ENGINE_PEER_STATE_FREE)
            selected = slot;
    }
    if (selected == NETD_SOCKET_ENGINE_INVALID_SLOT)
        return implementation->peer_count == NETD_SOCKET_ENGINE_MAX_PEERS ? NETD_SOCKET_ENGINE_PEER_CAPACITY
                                                                          : NETD_SOCKET_ENGINE_GENERATION_EXHAUSTED;

    implementation->peers[selected].identity = *peer;
    implementation->peers[selected].authority = *authority;
    implementation->peers[selected].next_request_id = first_request_id;
    implementation->peers[selected].state = NETD_SOCKET_ENGINE_PEER_STATE_OPEN;
    ++implementation->peer_count;
    implementation->next_peer_hint = (selected + 1U) % NETD_SOCKET_ENGINE_MAX_PEERS;
    *receipt_out = NetdSocketEngineInternalPeerReceipt(implementation, selected);
    return NETD_SOCKET_ENGINE_OK;
}

NetdSocketEngineStatus NetdSocketEngineDescribe(const NetdSocketEngine* engine, NetdSocketEngineSnapshot* snapshot_out)
{
    const NetdSocketEngineImpl* implementation;
    uint32_t index;
    if (engine == 0 || snapshot_out == 0)
        return NETD_SOCKET_ENGINE_NULL_ARGUMENT;
    if (NetdSocketEngineInternalRangesOverlap(engine, sizeof(*engine), snapshot_out, sizeof(*snapshot_out)))
        return NETD_SOCKET_ENGINE_ALIASED_STORAGE;
    NetdSocketEngineInternalClear(snapshot_out, (uint32_t)sizeof(*snapshot_out));
    implementation = NetdSocketEngineInternalReadOnly(engine);
    if (implementation->magic != NETD_SOCKET_ENGINE_MAGIC)
        return NETD_SOCKET_ENGINE_NOT_INITIALIZED;
    if (!NetdSocketEngineInternalValidate(implementation))
        return NETD_SOCKET_ENGINE_CORRUPT_STATE;
    snapshot_out->instance = implementation->instance;
    snapshot_out->transport = implementation->transport;
    snapshot_out->state = implementation->state;
    snapshot_out->peer_count = implementation->peer_count;
    snapshot_out->socket_count = implementation->socket_count;
    snapshot_out->request_count = implementation->request_count;
    for (index = 0; index < NETD_SOCKET_ENGINE_MAX_PEERS; ++index)
    {
        if (implementation->peers[index].state == NETD_SOCKET_ENGINE_PEER_STATE_RETIRED)
            ++snapshot_out->retired_peer_slots;
    }
    for (index = 0; index < NETD_SOCKET_ENGINE_MAX_SOCKETS; ++index)
    {
        if (implementation->sockets[index].state == NETD_SOCKET_ENGINE_SOCKET_RETIRED)
            ++snapshot_out->retired_socket_slots;
    }
    for (index = 0; index < NETD_SOCKET_ENGINE_MAX_REQUESTS; ++index)
    {
        const uint8_t state = implementation->requests[index].state;
        if (state == NETD_SOCKET_ENGINE_REQUEST_QUEUED_INTERNAL)
            ++snapshot_out->queued_count;
        else if (state == NETD_SOCKET_ENGINE_REQUEST_RUNNING_INTERNAL)
            ++snapshot_out->running_count;
        else if (state == NETD_SOCKET_ENGINE_REQUEST_REPLY_READY_INTERNAL ||
                 state == NETD_SOCKET_ENGINE_REQUEST_REPLY_PUBLISHING_INTERNAL)
            ++snapshot_out->reply_count;
        else if (state == NETD_SOCKET_ENGINE_REQUEST_RETIRED)
            ++snapshot_out->retired_request_slots;
    }
    return NETD_SOCKET_ENGINE_OK;
}

NetdSocketEngineStatus NetdSocketEngineInspectSocket(const NetdSocketEngine* engine,
                                                     const NetdSocketEnginePeerReceipt* peer,
                                                     const NetdSocketEngineSocketRef* socket,
                                                     NetdSocketEngineSocketSnapshot* snapshot_out)
{
    NetdSocketEngineImpl* implementation;
    NetdSocketEnginePeerRow* peer_row;
    NetdSocketEngineSocketRow* socket_row;
    NetdSocketEngineStatus status;
    if (engine == 0 || peer == 0 || socket == 0 || snapshot_out == 0)
        return NETD_SOCKET_ENGINE_NULL_ARGUMENT;
    if (NetdSocketEngineInternalRangesOverlap(engine, sizeof(*engine), peer, sizeof(*peer)) ||
        NetdSocketEngineInternalRangesOverlap(engine, sizeof(*engine), socket, sizeof(*socket)) ||
        NetdSocketEngineInternalRangesOverlap(engine, sizeof(*engine), snapshot_out, sizeof(*snapshot_out)) ||
        NetdSocketEngineInternalRangesOverlap(peer, sizeof(*peer), snapshot_out, sizeof(*snapshot_out)) ||
        NetdSocketEngineInternalRangesOverlap(socket, sizeof(*socket), snapshot_out, sizeof(*snapshot_out)))
        return NETD_SOCKET_ENGINE_ALIASED_STORAGE;
    NetdSocketEngineInternalClear(snapshot_out, (uint32_t)sizeof(*snapshot_out));
    implementation = (NetdSocketEngineImpl*)(void*)engine;
    if (implementation->magic != NETD_SOCKET_ENGINE_MAGIC)
        return NETD_SOCKET_ENGINE_NOT_INITIALIZED;
    if (!NetdSocketEngineInternalValidate(implementation))
        return NETD_SOCKET_ENGINE_CORRUPT_STATE;
    status = NetdSocketEngineInternalResolvePeer(implementation, peer, &peer_row);
    if (status != NETD_SOCKET_ENGINE_OK)
        return status;
    status = NetdSocketEngineInternalResolveSocket(implementation, peer_row, peer->peer_slot, socket, &socket_row);
    if (status != NETD_SOCKET_ENGINE_OK)
        return status;
    snapshot_out->socket = *socket;
    snapshot_out->owner = *peer;
    snapshot_out->backend = socket_row->backend;
    snapshot_out->domain = socket_row->domain;
    snapshot_out->type = socket_row->type;
    snapshot_out->protocol = socket_row->protocol;
    snapshot_out->phase =
        socket_row->state == NETD_SOCKET_ENGINE_SOCKET_RESERVED
            ? NETD_SOCKET_ENGINE_SOCKET_RESERVED_OPEN
            : (socket_row->state == NETD_SOCKET_ENGINE_SOCKET_OPEN ? NETD_SOCKET_ENGINE_SOCKET_LIVE
                                                                   : NETD_SOCKET_ENGINE_SOCKET_BUSY_CLOSE);
    return NETD_SOCKET_ENGINE_OK;
}

NetdSocketEngineStatus NetdSocketEngineInspectRequest(const NetdSocketEngine* engine,
                                                      const NetdSocketEngineRequestReceipt* receipt,
                                                      NetdSocketEngineRequestSnapshot* snapshot_out)
{
    NetdSocketEngineImpl* implementation;
    NetdSocketEngineRequestRow* request;
    NetdSocketEngineStatus status;
    if (engine == 0 || receipt == 0 || snapshot_out == 0)
        return NETD_SOCKET_ENGINE_NULL_ARGUMENT;
    if (NetdSocketEngineInternalRangesOverlap(engine, sizeof(*engine), receipt, sizeof(*receipt)) ||
        NetdSocketEngineInternalRangesOverlap(engine, sizeof(*engine), snapshot_out, sizeof(*snapshot_out)) ||
        NetdSocketEngineInternalRangesOverlap(receipt, sizeof(*receipt), snapshot_out, sizeof(*snapshot_out)))
        return NETD_SOCKET_ENGINE_ALIASED_STORAGE;
    NetdSocketEngineInternalClear(snapshot_out, (uint32_t)sizeof(*snapshot_out));
    implementation = (NetdSocketEngineImpl*)(void*)engine;
    if (implementation->magic != NETD_SOCKET_ENGINE_MAGIC)
        return NETD_SOCKET_ENGINE_NOT_INITIALIZED;
    if (!NetdSocketEngineInternalValidate(implementation))
        return NETD_SOCKET_ENGINE_CORRUPT_STATE;
    status = NetdSocketEngineInternalResolveRequest(implementation, receipt, &request);
    if (status != NETD_SOCKET_ENGINE_OK)
        return status;
    snapshot_out->receipt = *receipt;
    snapshot_out->request = request->request;
    snapshot_out->cancel_requested = request->cancel_requested;
    if (request->state == NETD_SOCKET_ENGINE_REQUEST_QUEUED_INTERNAL)
        snapshot_out->phase = NETD_SOCKET_ENGINE_REQUEST_QUEUED;
    else if (request->state == NETD_SOCKET_ENGINE_REQUEST_RUNNING_INTERNAL)
        snapshot_out->phase = NETD_SOCKET_ENGINE_REQUEST_RUNNING;
    else if (request->state == NETD_SOCKET_ENGINE_REQUEST_REPLY_READY_INTERNAL)
        snapshot_out->phase = NETD_SOCKET_ENGINE_REQUEST_REPLY_READY;
    else
        snapshot_out->phase = NETD_SOCKET_ENGINE_REQUEST_REPLY_PUBLISHING;
    return NETD_SOCKET_ENGINE_OK;
}
