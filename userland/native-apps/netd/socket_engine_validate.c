#include "socket_engine_internal.h"

static uint8_t ProcessKeyIsCanonical(const NetdSocketEngineProcessKey* key)
{
    return (uint8_t)(key != 0 && key->identity != 0 && key->pid != 0);
}

static uint8_t CredentialKeyIsCanonical(const NetdSocketEngineCredentialKey* key)
{
    return (uint8_t)(key != 0 && key->slot < NETD_SOCKET_ENGINE_CREDENTIAL_CAPACITY && key->reserved32 == 0 &&
                     key->generation != 0 && key->generation <= NETD_SOCKET_ENGINE_IDENTITY_GENERATION_MAX);
}

static uint8_t ChannelIdentityIsCanonical(const NetdSocketEngineChannelIdentity* identity)
{
    return (uint8_t)(identity != 0 && identity->slot < NETD_SOCKET_ENGINE_CHANNEL_CAPACITY &&
                     identity->role == NETD_SOCKET_ENGINE_CHANNEL_ACCEPTOR && identity->reserved8[0] == 0 &&
                     identity->reserved8[1] == 0 && identity->reserved8[2] == 0 && identity->generation != 0 &&
                     identity->generation <= NETD_SOCKET_ENGINE_IDENTITY_GENERATION_MAX && identity->epoch != 0);
}

static uint8_t TransportIsZero(const NetdSocketEngineTransportIdentity* transport)
{
    return (uint8_t)(transport->identity == 0 && transport->generation == 0);
}

NetdSocketEngineImpl* NetdSocketEngineInternalMutable(NetdSocketEngine* engine)
{
    return (NetdSocketEngineImpl*)(void*)engine;
}

const NetdSocketEngineImpl* NetdSocketEngineInternalReadOnly(const NetdSocketEngine* engine)
{
    return (const NetdSocketEngineImpl*)(const void*)engine;
}

void NetdSocketEngineInternalClear(void* storage, uint32_t bytes)
{
    uint8_t* output = (uint8_t*)storage;
    uint32_t index;
    for (index = 0; index < bytes; ++index)
        output[index] = 0;
}

uint8_t NetdSocketEngineInternalStorageIsZero(const void* storage, uint32_t bytes)
{
    const uint8_t* input = (const uint8_t*)storage;
    uint32_t index;
    for (index = 0; index < bytes; ++index)
    {
        if (input[index] != 0)
            return 0;
    }
    return 1;
}

uint8_t NetdSocketEngineInternalRangesOverlap(const void* left, uint64_t left_bytes, const void* right,
                                              uint64_t right_bytes)
{
    const uintptr_t left_start = (uintptr_t)left;
    const uintptr_t right_start = (uintptr_t)right;
    uintptr_t left_end;
    uintptr_t right_end;

    if (left == 0 || right == 0 || left_bytes == 0 || right_bytes == 0)
        return 0;
    if (left_bytes > (uint64_t)(UINTPTR_MAX - left_start) || right_bytes > (uint64_t)(UINTPTR_MAX - right_start))
        return 1;
    left_end = left_start + (uintptr_t)left_bytes;
    right_end = right_start + (uintptr_t)right_bytes;
    return (uint8_t)(left_start < right_end && right_start < left_end);
}

uint8_t NetdSocketEngineInstanceIdentityIsCanonical(const NetdSocketEngineInstanceIdentity* identity)
{
    return (uint8_t)(identity != 0 && identity->service_identity != 0 && identity->instance_generation != 0 &&
                     ProcessKeyIsCanonical(&identity->process) && identity->published_endpoint_epoch != 0 &&
                     identity->service_slot < NETD_SOCKET_ENGINE_SERVICE_CAPACITY && identity->reserved32 == 0);
}

uint8_t NetdSocketEnginePeerIdentityIsCanonical(const NetdSocketEnginePeerIdentity* identity)
{
    return (uint8_t)(identity != 0 && ProcessKeyIsCanonical(&identity->process) &&
                     CredentialKeyIsCanonical(&identity->credential) && ChannelIdentityIsCanonical(&identity->channel));
}

uint8_t NetdSocketEnginePeerAuthorityIsCanonical(const NetdSocketEnginePeerAuthority* authority)
{
    return (uint8_t)(authority != 0 && authority->authority_identity != 0 &&
                     authority->network_namespace_identity != 0 && authority->allowed_methods != 0 &&
                     (authority->allowed_methods & ~NETD_SOCKET_ENGINE_METHOD_KNOWN_MASK) == 0 &&
                     authority->socket_limit != 0 && authority->socket_limit <= NETD_SOCKET_ENGINE_MAX_SOCKETS &&
                     authority->request_limit != 0 && authority->request_limit <= NETD_SOCKET_ENGINE_MAX_REQUESTS &&
                     authority->reserved == 0);
}

uint8_t NetdSocketEngineTransportIdentityIsCanonical(const NetdSocketEngineTransportIdentity* transport)
{
    return (uint8_t)(transport != 0 && transport->identity != 0 && transport->generation != 0);
}

uint8_t NetdSocketEngineInternalInstanceEqual(const NetdSocketEngineInstanceIdentity* left,
                                              const NetdSocketEngineInstanceIdentity* right)
{
    return (uint8_t)(left->service_identity == right->service_identity &&
                     left->instance_generation == right->instance_generation &&
                     left->process.identity == right->process.identity && left->process.pid == right->process.pid &&
                     left->published_endpoint_epoch == right->published_endpoint_epoch &&
                     left->service_slot == right->service_slot && left->reserved32 == right->reserved32);
}

uint8_t NetdSocketEngineInternalPeerEqual(const NetdSocketEnginePeerIdentity* left,
                                          const NetdSocketEnginePeerIdentity* right)
{
    return (uint8_t)(left->process.identity == right->process.identity && left->process.pid == right->process.pid &&
                     left->credential.slot == right->credential.slot &&
                     left->credential.reserved32 == right->credential.reserved32 &&
                     left->credential.generation == right->credential.generation &&
                     left->channel.slot == right->channel.slot && left->channel.role == right->channel.role &&
                     left->channel.reserved8[0] == right->channel.reserved8[0] &&
                     left->channel.reserved8[1] == right->channel.reserved8[1] &&
                     left->channel.reserved8[2] == right->channel.reserved8[2] &&
                     left->channel.generation == right->channel.generation &&
                     left->channel.epoch == right->channel.epoch);
}

uint8_t NetdSocketEngineInternalAuthorityEqual(const NetdSocketEnginePeerAuthority* left,
                                               const NetdSocketEnginePeerAuthority* right)
{
    return (uint8_t)(left->authority_identity == right->authority_identity &&
                     left->network_namespace_identity == right->network_namespace_identity &&
                     left->allowed_methods == right->allowed_methods && left->socket_limit == right->socket_limit &&
                     left->request_limit == right->request_limit && left->reserved == right->reserved);
}

uint8_t NetdSocketEngineInternalTransportEqual(const NetdSocketEngineTransportIdentity* left,
                                               const NetdSocketEngineTransportIdentity* right)
{
    return (uint8_t)(left->identity == right->identity && left->generation == right->generation);
}

uint8_t NetdSocketEngineInternalBackendIsCanonical(const NetdSocketEngineBackendSocketIdentity* backend)
{
    return (uint8_t)(backend != 0 && NetdSocketEngineTransportIdentityIsCanonical(&backend->transport) &&
                     backend->identity != 0);
}

uint8_t NetdSocketEngineInternalBackendEqual(const NetdSocketEngineBackendSocketIdentity* left,
                                             const NetdSocketEngineBackendSocketIdentity* right)
{
    return (uint8_t)(NetdSocketEngineInternalTransportEqual(&left->transport, &right->transport) &&
                     left->identity == right->identity);
}

uint8_t NetdSocketEngineInternalBackendIsZero(const NetdSocketEngineBackendSocketIdentity* backend)
{
    return (uint8_t)(TransportIsZero(&backend->transport) && backend->identity == 0);
}

uint8_t NetdSocketEngineInternalSocketParametersAreCanonical(uint16_t domain, uint16_t type, uint16_t protocol)
{
    if (domain != NETD_SOCKET_ENGINE_DOMAIN_IPV4 && domain != NETD_SOCKET_ENGINE_DOMAIN_IPV6)
        return 0;
    if (type == NETD_SOCKET_ENGINE_TYPE_STREAM)
        return (uint8_t)(protocol == NETD_SOCKET_ENGINE_PROTOCOL_DEFAULT ||
                         protocol == NETD_SOCKET_ENGINE_PROTOCOL_TCP);
    if (type == NETD_SOCKET_ENGINE_TYPE_DATAGRAM)
        return (uint8_t)(protocol == NETD_SOCKET_ENGINE_PROTOCOL_DEFAULT ||
                         protocol == NETD_SOCKET_ENGINE_PROTOCOL_UDP);
    return 0;
}

uint8_t NetdSocketEngineInternalSocketRefEqual(const NetdSocketEngineSocketRef* left,
                                               const NetdSocketEngineSocketRef* right)
{
    return (uint8_t)(left->instance_generation == right->instance_generation &&
                     left->transport_generation == right->transport_generation &&
                     left->generation == right->generation && left->slot == right->slot &&
                     left->reserved32 == right->reserved32);
}

uint8_t NetdSocketEngineInternalSocketRefIsZero(const NetdSocketEngineSocketRef* socket)
{
    return (uint8_t)(socket->instance_generation == 0 && socket->transport_generation == 0 && socket->generation == 0 &&
                     socket->slot == 0 && socket->reserved32 == 0);
}

uint8_t NetdSocketEngineInternalSocketRefIsCanonical(const NetdSocketEngineImpl* implementation,
                                                     const NetdSocketEngineSocketRef* socket)
{
    return (uint8_t)(implementation != 0 && socket != 0 &&
                     socket->instance_generation == implementation->instance.instance_generation &&
                     socket->transport_generation == implementation->transport.generation && socket->generation != 0 &&
                     socket->slot < NETD_SOCKET_ENGINE_MAX_SOCKETS && socket->reserved32 == 0);
}

uint8_t NetdSocketEngineInternalHasPublishingReply(const NetdSocketEngineImpl* implementation)
{
    uint32_t index;
    for (index = 0; index < NETD_SOCKET_ENGINE_MAX_REQUESTS; ++index)
    {
        if (implementation->requests[index].state == NETD_SOCKET_ENGINE_REQUEST_REPLY_PUBLISHING_INTERNAL)
            return 1;
    }
    return 0;
}

uint8_t NetdSocketEngineInternalValidate(const NetdSocketEngineImpl* implementation)
{
    uint32_t sockets_by_peer[NETD_SOCKET_ENGINE_MAX_PEERS] = {0};
    uint32_t requests_by_peer[NETD_SOCKET_ENGINE_MAX_PEERS] = {0};
    uint8_t requests_by_socket[NETD_SOCKET_ENGINE_MAX_SOCKETS] = {0};
    uint32_t peer_count = 0;
    uint32_t socket_count = 0;
    uint32_t request_count = 0;
    uint32_t publishing_count = 0;
    uint32_t index;

    if (implementation == 0 || implementation->magic != NETD_SOCKET_ENGINE_MAGIC ||
        !NetdSocketEngineInstanceIdentityIsCanonical(&implementation->instance) ||
        implementation->first_slot_generation == 0 ||
        implementation->state < NETD_SOCKET_ENGINE_STATE_AWAITING_TRANSPORT ||
        implementation->state > NETD_SOCKET_ENGINE_STATE_CLOSED ||
        implementation->next_peer_hint >= NETD_SOCKET_ENGINE_MAX_PEERS ||
        implementation->next_socket_hint >= NETD_SOCKET_ENGINE_MAX_SOCKETS ||
        implementation->next_request_hint >= NETD_SOCKET_ENGINE_MAX_REQUESTS ||
        implementation->next_work_hint >= NETD_SOCKET_ENGINE_MAX_REQUESTS ||
        implementation->next_reply_hint >= NETD_SOCKET_ENGINE_MAX_REQUESTS)
        return 0;
    if ((implementation->state == NETD_SOCKET_ENGINE_STATE_AWAITING_TRANSPORT ||
         implementation->state == NETD_SOCKET_ENGINE_STATE_CLOSED) &&
        !TransportIsZero(&implementation->transport))
        return 0;
    if ((implementation->state == NETD_SOCKET_ENGINE_STATE_OPEN ||
         (implementation->state == NETD_SOCKET_ENGINE_STATE_DRAINING &&
          !TransportIsZero(&implementation->transport))) &&
        !NetdSocketEngineTransportIdentityIsCanonical(&implementation->transport))
        return 0;

    for (index = 0; index < NETD_SOCKET_ENGINE_MAX_PEERS; ++index)
    {
        const NetdSocketEnginePeerRow* peer = &implementation->peers[index];
        if (peer->generation < implementation->first_slot_generation)
            return 0;
        if (peer->state == NETD_SOCKET_ENGINE_PEER_STATE_FREE || peer->state == NETD_SOCKET_ENGINE_PEER_STATE_RETIRED)
        {
            if ((peer->state == NETD_SOCKET_ENGINE_PEER_STATE_RETIRED && peer->generation != UINT64_MAX) ||
                !NetdSocketEngineInternalStorageIsZero(&peer->identity, (uint32_t)sizeof(peer->identity)) ||
                !NetdSocketEngineInternalStorageIsZero(&peer->authority, (uint32_t)sizeof(peer->authority)) ||
                peer->next_request_id != 0 || peer->active_sockets != 0 || peer->active_requests != 0 ||
                !NetdSocketEngineInternalStorageIsZero(peer->reserved8, (uint32_t)sizeof(peer->reserved8)))
                return 0;
            continue;
        }
        if ((peer->state != NETD_SOCKET_ENGINE_PEER_STATE_OPEN &&
             peer->state != NETD_SOCKET_ENGINE_PEER_STATE_CLOSING) ||
            !NetdSocketEnginePeerIdentityIsCanonical(&peer->identity) ||
            !NetdSocketEnginePeerAuthorityIsCanonical(&peer->authority) ||
            !NetdSocketEngineInternalStorageIsZero(peer->reserved8, (uint32_t)sizeof(peer->reserved8)) ||
            (peer->state == NETD_SOCKET_ENGINE_PEER_STATE_CLOSING && peer->active_requests == 0) ||
            (implementation->state == NETD_SOCKET_ENGINE_STATE_DRAINING &&
             peer->state != NETD_SOCKET_ENGINE_PEER_STATE_CLOSING))
            return 0;
        ++peer_count;
    }

    for (index = 0; index < NETD_SOCKET_ENGINE_MAX_SOCKETS; ++index)
    {
        const NetdSocketEngineSocketRow* socket = &implementation->sockets[index];
        uint32_t prior;
        if (socket->generation < implementation->first_slot_generation)
            return 0;
        if (socket->state == NETD_SOCKET_ENGINE_SOCKET_FREE || socket->state == NETD_SOCKET_ENGINE_SOCKET_RETIRED)
        {
            if ((socket->state == NETD_SOCKET_ENGINE_SOCKET_RETIRED && socket->generation != UINT64_MAX) ||
                !NetdSocketEngineInternalBackendIsZero(&socket->backend) || socket->owner_peer_generation != 0 ||
                socket->owner_peer_slot != 0 || socket->reserved8 != 0 || socket->domain != 0 || socket->type != 0 ||
                socket->protocol != 0 || socket->reserved32 != 0)
                return 0;
            continue;
        }
        if (socket->owner_peer_slot >= NETD_SOCKET_ENGINE_MAX_PEERS ||
            implementation->peers[socket->owner_peer_slot].generation != socket->owner_peer_generation ||
            (implementation->peers[socket->owner_peer_slot].state != NETD_SOCKET_ENGINE_PEER_STATE_OPEN &&
             implementation->peers[socket->owner_peer_slot].state != NETD_SOCKET_ENGINE_PEER_STATE_CLOSING) ||
            !NetdSocketEngineInternalSocketParametersAreCanonical(socket->domain, socket->type, socket->protocol) ||
            socket->reserved8 != 0 || socket->reserved32 != 0)
            return 0;
        if (socket->state == NETD_SOCKET_ENGINE_SOCKET_RESERVED)
        {
            if (!NetdSocketEngineInternalBackendIsZero(&socket->backend))
                return 0;
        }
        else if ((socket->state != NETD_SOCKET_ENGINE_SOCKET_OPEN &&
                  socket->state != NETD_SOCKET_ENGINE_SOCKET_CLOSING) ||
                 !NetdSocketEngineInternalBackendIsCanonical(&socket->backend) ||
                 !NetdSocketEngineInternalTransportEqual(&socket->backend.transport, &implementation->transport))
            return 0;
        for (prior = 0; prior < index; ++prior)
        {
            const NetdSocketEngineSocketRow* other = &implementation->sockets[prior];
            if ((socket->state == NETD_SOCKET_ENGINE_SOCKET_OPEN ||
                 socket->state == NETD_SOCKET_ENGINE_SOCKET_CLOSING) &&
                (other->state == NETD_SOCKET_ENGINE_SOCKET_OPEN || other->state == NETD_SOCKET_ENGINE_SOCKET_CLOSING) &&
                NetdSocketEngineInternalBackendEqual(&socket->backend, &other->backend))
                return 0;
        }
        ++sockets_by_peer[socket->owner_peer_slot];
        ++socket_count;
    }

    for (index = 0; index < NETD_SOCKET_ENGINE_MAX_REQUESTS; ++index)
    {
        const NetdSocketEngineRequestRow* request = &implementation->requests[index];
        const NetdSocketEnginePeerRow* peer;
        const NetdSocketEngineSocketRow* socket = 0;
        if (request->generation < implementation->first_slot_generation)
            return 0;
        if (request->state == NETD_SOCKET_ENGINE_REQUEST_FREE || request->state == NETD_SOCKET_ENGINE_REQUEST_RETIRED)
        {
            if ((request->state == NETD_SOCKET_ENGINE_REQUEST_RETIRED && request->generation != UINT64_MAX) ||
                !NetdSocketEngineInternalStorageIsZero(&request->request, (uint32_t)sizeof(request->request)) ||
                !NetdSocketEngineInternalStorageIsZero(&request->reply, (uint32_t)sizeof(request->reply)) ||
                request->peer_generation != 0 || request->peer_slot != 0 || request->socket_slot != 0 ||
                request->socket_generation != 0 || request->cancel_requested != 0 ||
                request->abandon_cleanup_reason != 0 ||
                !NetdSocketEngineInternalStorageIsZero(request->reserved8, (uint32_t)sizeof(request->reserved8)))
                return 0;
            continue;
        }
        if (request->state < NETD_SOCKET_ENGINE_REQUEST_QUEUED_INTERNAL ||
            request->state > NETD_SOCKET_ENGINE_REQUEST_REPLY_PUBLISHING_INTERNAL ||
            request->peer_slot >= NETD_SOCKET_ENGINE_MAX_PEERS)
            return 0;
        peer = &implementation->peers[request->peer_slot];
        if (peer->generation != request->peer_generation ||
            (peer->state != NETD_SOCKET_ENGINE_PEER_STATE_OPEN &&
             peer->state != NETD_SOCKET_ENGINE_PEER_STATE_CLOSING) ||
            request->request.request_id == 0 ||
            (request->request.operation != NETD_SOCKET_ENGINE_OPERATION_OPEN &&
             request->request.operation != NETD_SOCKET_ENGINE_OPERATION_CLOSE) ||
            !NetdSocketEngineInternalSocketRefIsCanonical(implementation, &request->request.socket) ||
            request->socket_generation != request->request.socket.generation || request->request.reserved16 != 0 ||
            request->request.flags != 0 ||
            !NetdSocketEngineInternalStorageIsZero(request->reserved8, (uint32_t)sizeof(request->reserved8)))
            return 0;
        if ((peer->next_request_id != 0 && request->request.request_id >= peer->next_request_id) ||
            (peer->state == NETD_SOCKET_ENGINE_PEER_STATE_CLOSING &&
             request->state != NETD_SOCKET_ENGINE_REQUEST_RUNNING_INTERNAL))
            return 0;
        if ((request->request.operation == NETD_SOCKET_ENGINE_OPERATION_OPEN &&
             !NetdSocketEngineInternalSocketParametersAreCanonical(request->request.domain, request->request.type,
                                                                   request->request.protocol)) ||
            (request->request.operation == NETD_SOCKET_ENGINE_OPERATION_CLOSE &&
             (request->request.domain != 0 || request->request.type != 0 || request->request.protocol != 0)))
            return 0;
        if (request->cancel_requested > 1 ||
            (request->abandon_cleanup_reason != 0 &&
             (request->state != NETD_SOCKET_ENGINE_REQUEST_RUNNING_INTERNAL ||
              request->request.operation != NETD_SOCKET_ENGINE_OPERATION_OPEN || request->cancel_requested == 0 ||
              peer->state != NETD_SOCKET_ENGINE_PEER_STATE_CLOSING ||
              (request->abandon_cleanup_reason != NETD_SOCKET_ENGINE_CLEANUP_PEER_CLOSED &&
               request->abandon_cleanup_reason != NETD_SOCKET_ENGINE_CLEANUP_TRANSPORT_DRAIN))))
            return 0;
        if (request->socket_slot != NETD_SOCKET_ENGINE_INVALID_SLOT)
        {
            NetdSocketEngineSocketRef expected_socket;
            if (request->socket_slot >= NETD_SOCKET_ENGINE_MAX_SOCKETS)
                return 0;
            socket = &implementation->sockets[request->socket_slot];
            expected_socket = NetdSocketEngineInternalSocketRef(implementation, request->socket_slot);
            if (socket->generation != request->socket_generation || socket->owner_peer_slot != request->peer_slot ||
                socket->owner_peer_generation != request->peer_generation ||
                socket->state == NETD_SOCKET_ENGINE_SOCKET_FREE || socket->state == NETD_SOCKET_ENGINE_SOCKET_RETIRED ||
                !NetdSocketEngineInternalSocketRefEqual(&request->request.socket, &expected_socket))
                return 0;
            if (requests_by_socket[request->socket_slot] != 0)
                return 0;
            requests_by_socket[request->socket_slot] = 1;
        }
        else if (request->state < NETD_SOCKET_ENGINE_REQUEST_REPLY_READY_INTERNAL)
            return 0;
        if (request->state == NETD_SOCKET_ENGINE_REQUEST_QUEUED_INTERNAL ||
            request->state == NETD_SOCKET_ENGINE_REQUEST_RUNNING_INTERNAL)
        {
            if (!NetdSocketEngineInternalStorageIsZero(&request->reply, (uint32_t)sizeof(request->reply)) ||
                (request->request.operation == NETD_SOCKET_ENGINE_OPERATION_OPEN &&
                 socket->state != NETD_SOCKET_ENGINE_SOCKET_RESERVED) ||
                (request->request.operation == NETD_SOCKET_ENGINE_OPERATION_CLOSE &&
                 socket->state != NETD_SOCKET_ENGINE_SOCKET_CLOSING) ||
                (request->state == NETD_SOCKET_ENGINE_REQUEST_QUEUED_INTERNAL && request->cancel_requested != 0) ||
                (request->request.operation == NETD_SOCKET_ENGINE_OPERATION_CLOSE && request->cancel_requested != 0))
                return 0;
        }
        else
        {
            if (request->reply.request_id != request->request.request_id ||
                request->reply.operation != request->request.operation ||
                request->reply.status > NETD_SOCKET_ENGINE_REPLY_BACKEND_FAILURE)
                return 0;
            if (request->request.operation == NETD_SOCKET_ENGINE_OPERATION_OPEN &&
                request->reply.status != NETD_SOCKET_ENGINE_REPLY_SUCCESS &&
                !NetdSocketEngineInternalSocketRefIsZero(&request->reply.socket))
                return 0;
            if ((request->request.operation == NETD_SOCKET_ENGINE_OPERATION_CLOSE ||
                 request->reply.status == NETD_SOCKET_ENGINE_REPLY_SUCCESS) &&
                !NetdSocketEngineInternalSocketRefEqual(&request->reply.socket, &request->request.socket))
                return 0;
            if ((request->reply.status == NETD_SOCKET_ENGINE_REPLY_CANCELLED) != (request->cancel_requested != 0))
                return 0;
            if (request->request.operation == NETD_SOCKET_ENGINE_OPERATION_OPEN)
            {
                if ((request->reply.status == NETD_SOCKET_ENGINE_REPLY_SUCCESS &&
                     (socket == 0 || socket->state != NETD_SOCKET_ENGINE_SOCKET_OPEN)) ||
                    (request->reply.status != NETD_SOCKET_ENGINE_REPLY_SUCCESS && socket != 0))
                    return 0;
            }
            else if ((request->reply.status == NETD_SOCKET_ENGINE_REPLY_SUCCESS && socket != 0) ||
                     (request->reply.status != NETD_SOCKET_ENGINE_REPLY_SUCCESS &&
                      (socket == 0 || socket->state != NETD_SOCKET_ENGINE_SOCKET_OPEN)))
                return 0;
            if (request->state == NETD_SOCKET_ENGINE_REQUEST_REPLY_PUBLISHING_INTERNAL)
                ++publishing_count;
        }
        ++requests_by_peer[request->peer_slot];
        ++request_count;
    }

    for (index = 0; index < NETD_SOCKET_ENGINE_MAX_PEERS; ++index)
    {
        const NetdSocketEnginePeerRow* peer = &implementation->peers[index];
        if ((peer->state == NETD_SOCKET_ENGINE_PEER_STATE_OPEN ||
             peer->state == NETD_SOCKET_ENGINE_PEER_STATE_CLOSING) &&
            (peer->active_sockets != sockets_by_peer[index] || peer->active_requests != requests_by_peer[index] ||
             peer->active_sockets > peer->authority.socket_limit ||
             peer->active_requests > peer->authority.request_limit))
            return 0;
    }
    for (index = 0; index < NETD_SOCKET_ENGINE_MAX_SOCKETS; ++index)
    {
        const NetdSocketEngineSocketRow* socket = &implementation->sockets[index];
        if ((socket->state == NETD_SOCKET_ENGINE_SOCKET_RESERVED ||
             socket->state == NETD_SOCKET_ENGINE_SOCKET_CLOSING ||
             ((socket->state == NETD_SOCKET_ENGINE_SOCKET_OPEN) &&
              implementation->peers[socket->owner_peer_slot].state == NETD_SOCKET_ENGINE_PEER_STATE_CLOSING)) &&
            requests_by_socket[index] != 1)
            return 0;
    }
    if (publishing_count > 1 || (implementation->state != NETD_SOCKET_ENGINE_STATE_OPEN && publishing_count != 0) ||
        ((implementation->state == NETD_SOCKET_ENGINE_STATE_AWAITING_TRANSPORT ||
          implementation->state == NETD_SOCKET_ENGINE_STATE_CLOSED ||
          (implementation->state == NETD_SOCKET_ENGINE_STATE_DRAINING &&
           TransportIsZero(&implementation->transport))) &&
         (peer_count != 0 || socket_count != 0 || request_count != 0)))
        return 0;
    return (uint8_t)(implementation->peer_count == peer_count && implementation->socket_count == socket_count &&
                     implementation->request_count == request_count &&
                     implementation->peer_count <= NETD_SOCKET_ENGINE_MAX_PEERS &&
                     implementation->socket_count <= NETD_SOCKET_ENGINE_MAX_SOCKETS &&
                     implementation->request_count <= NETD_SOCKET_ENGINE_MAX_REQUESTS);
}
