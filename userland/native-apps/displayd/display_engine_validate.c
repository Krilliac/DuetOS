#include "display_engine_internal.h"

#include <stdint.h>

uint8_t DisplaydInternalInstanceEqual(const DisplaydEngineInstanceIdentity* left,
                                      const DisplaydEngineInstanceIdentity* right)
{
    return (uint8_t)(left != 0 && right != 0 && left->service_identity == right->service_identity &&
                     left->instance_generation == right->instance_generation &&
                     left->process.identity == right->process.identity && left->process.pid == right->process.pid &&
                     left->published_endpoint_epoch == right->published_endpoint_epoch &&
                     left->service_slot == right->service_slot && left->reserved32 == right->reserved32);
}

uint8_t DisplaydInternalPeerEqual(const DisplaydPeerIdentity* left, const DisplaydPeerIdentity* right)
{
    uint32_t index;

    if (left == 0 || right == 0 || left->process.identity != right->process.identity ||
        left->process.pid != right->process.pid || left->credential.slot != right->credential.slot ||
        left->credential.reserved32 != right->credential.reserved32 ||
        left->credential.generation != right->credential.generation || left->channel.slot != right->channel.slot ||
        left->channel.role != right->channel.role || left->channel.generation != right->channel.generation ||
        left->channel.epoch != right->channel.epoch || left->integrity != right->integrity)
        return 0;
    for (index = 0; index < 3; ++index)
    {
        if (left->channel.reserved8[index] != right->channel.reserved8[index])
            return 0;
    }
    for (index = 0; index < 7; ++index)
    {
        if (left->reserved8[index] != right->reserved8[index])
            return 0;
    }
    return 1;
}

uint8_t DisplaydInternalSurfaceEqual(const DisplaydSurfaceIdentity* left, const DisplaydSurfaceIdentity* right)
{
    return (uint8_t)(left != 0 && right != 0 && DisplaydInternalInstanceEqual(&left->instance, &right->instance) &&
                     left->generation == right->generation && left->slot == right->slot &&
                     left->reserved32 == right->reserved32);
}

uint8_t DisplaydInternalSurfaceIsZero(const DisplaydSurfaceIdentity* surface)
{
    DisplaydSurfaceIdentity zero;

    if (surface == 0)
        return 0;
    DisplaydInternalClear(&zero, (uint32_t)sizeof(zero));
    return DisplaydInternalSurfaceEqual(surface, &zero);
}

uint8_t DisplaydInternalRectIsZero(const DisplaydRect* bounds)
{
    return (uint8_t)(bounds != 0 && bounds->x == 0 && bounds->y == 0 && bounds->width == 0 && bounds->height == 0);
}

uint8_t DisplaydInternalRectIsValid(const DisplaydEngineImpl* engine, const DisplaydRect* bounds)
{
    uint32_t x;
    uint32_t y;

    if (engine == 0 || bounds == 0 || bounds->x < 0 || bounds->y < 0 || bounds->width == 0 || bounds->height == 0)
        return 0;
    x = (uint32_t)bounds->x;
    y = (uint32_t)bounds->y;
    return (uint8_t)(x <= engine->display_width && y <= engine->display_height &&
                     bounds->width <= engine->display_width - x && bounds->height <= engine->display_height - y);
}

uint8_t DisplaydEngineInstanceIdentityIsCanonical(const DisplaydEngineInstanceIdentity* identity)
{
    return (uint8_t)(identity != 0 && identity->service_identity == DISPLAYD_ENGINE_SERVICE_IDENTITY &&
                     identity->instance_generation != 0 && identity->process.identity != 0 &&
                     identity->process.pid != 0 && identity->published_endpoint_epoch != 0 &&
                     identity->service_slot < DISPLAYD_ENGINE_SERVICE_CAPACITY && identity->reserved32 == 0);
}

uint8_t DisplaydPeerIdentityIsCanonical(const DisplaydPeerIdentity* identity)
{
    uint32_t index;

    if (identity == 0 || identity->process.identity == 0 || identity->process.pid == 0 ||
        identity->credential.slot >= 64U || identity->credential.reserved32 != 0 ||
        identity->credential.generation == 0 ||
        identity->credential.generation > DISPLAYD_ENGINE_CREDENTIAL_GENERATION_MAX ||
        identity->channel.slot >= DISPLAYD_ENGINE_CHANNEL_SLOT_CAPACITY ||
        (identity->channel.role != DISPLAYD_CHANNEL_ROLE_INITIATOR &&
         identity->channel.role != DISPLAYD_CHANNEL_ROLE_ACCEPTOR) ||
        identity->channel.generation == 0 || identity->channel.generation > DISPLAYD_ENGINE_CHANNEL_GENERATION_MAX ||
        identity->channel.epoch == 0 || identity->integrity < 1 || identity->integrity > 5)
        return 0;
    for (index = 0; index < 3; ++index)
    {
        if (identity->channel.reserved8[index] != 0)
            return 0;
    }
    for (index = 0; index < 7; ++index)
    {
        if (identity->reserved8[index] != 0)
            return 0;
    }
    return 1;
}

uint8_t DisplaydPeerReceiptIsCanonical(const DisplaydPeerReceipt* receipt)
{
    return (uint8_t)(receipt != 0 && DisplaydEngineInstanceIdentityIsCanonical(&receipt->instance) &&
                     DisplaydPeerIdentityIsCanonical(&receipt->peer) && receipt->generation != 0 &&
                     receipt->slot < DISPLAYD_ENGINE_MAX_PEERS && receipt->reserved32 == 0);
}

uint8_t DisplaydSurfaceIdentityIsCanonical(const DisplaydSurfaceIdentity* identity)
{
    return (uint8_t)(identity != 0 && DisplaydEngineInstanceIdentityIsCanonical(&identity->instance) &&
                     identity->generation != 0 && identity->slot < DISPLAYD_ENGINE_MAX_SURFACES &&
                     identity->reserved32 == 0);
}

DisplaydEngineStatus DisplaydInternalResolvePeer(DisplaydEngineImpl* engine, const DisplaydPeerReceipt* receipt,
                                                 DisplaydPeerRow** peer_out)
{
    DisplaydPeerRow* row;

    if (peer_out != 0)
        *peer_out = 0;
    if (engine == 0 || receipt == 0 || peer_out == 0 || !DisplaydPeerReceiptIsCanonical(receipt))
        return DISPLAYD_ENGINE_INVALID_IDENTITY;
    if (!DisplaydInternalInstanceEqual(&engine->instance, &receipt->instance))
        return DISPLAYD_ENGINE_STALE_PEER;
    row = &engine->peers[receipt->slot];
    if (row->state != DISPLAYD_PEER_OPEN || row->generation != receipt->generation ||
        !DisplaydInternalPeerEqual(&row->identity, &receipt->peer))
        return DISPLAYD_ENGINE_STALE_PEER;
    *peer_out = row;
    return DISPLAYD_ENGINE_OK;
}

DisplaydEngineStatus DisplaydInternalResolvePeerConst(const DisplaydEngineImpl* engine,
                                                      const DisplaydPeerReceipt* receipt,
                                                      const DisplaydPeerRow** peer_out)
{
    const DisplaydPeerRow* row;

    if (peer_out != 0)
        *peer_out = 0;
    if (engine == 0 || receipt == 0 || peer_out == 0 || !DisplaydPeerReceiptIsCanonical(receipt))
        return DISPLAYD_ENGINE_INVALID_IDENTITY;
    if (!DisplaydInternalInstanceEqual(&engine->instance, &receipt->instance))
        return DISPLAYD_ENGINE_STALE_PEER;
    row = &engine->peers[receipt->slot];
    if (row->state != DISPLAYD_PEER_OPEN || row->generation != receipt->generation ||
        !DisplaydInternalPeerEqual(&row->identity, &receipt->peer))
        return DISPLAYD_ENGINE_STALE_PEER;
    *peer_out = row;
    return DISPLAYD_ENGINE_OK;
}

DisplaydEngineStatus DisplaydInternalResolveSurface(DisplaydEngineImpl* engine, const DisplaydSurfaceIdentity* identity,
                                                    DisplaydSurfaceRow** surface_out)
{
    DisplaydSurfaceRow* row;

    if (surface_out != 0)
        *surface_out = 0;
    if (engine == 0 || identity == 0 || surface_out == 0 || !DisplaydSurfaceIdentityIsCanonical(identity))
        return DISPLAYD_ENGINE_INVALID_IDENTITY;
    if (!DisplaydInternalInstanceEqual(&engine->instance, &identity->instance))
        return DISPLAYD_ENGINE_STALE_SURFACE;
    row = &engine->surfaces[identity->slot];
    if (row->state != DISPLAYD_SURFACE_LIVE)
        return DISPLAYD_ENGINE_SURFACE_NOT_FOUND;
    if (row->generation != identity->generation)
        return DISPLAYD_ENGINE_STALE_SURFACE;
    *surface_out = row;
    return DISPLAYD_ENGINE_OK;
}

DisplaydEngineStatus DisplaydInternalResolveSurfaceConst(const DisplaydEngineImpl* engine,
                                                         const DisplaydSurfaceIdentity* identity,
                                                         const DisplaydSurfaceRow** surface_out)
{
    const DisplaydSurfaceRow* row;

    if (surface_out != 0)
        *surface_out = 0;
    if (engine == 0 || identity == 0 || surface_out == 0 || !DisplaydSurfaceIdentityIsCanonical(identity))
        return DISPLAYD_ENGINE_INVALID_IDENTITY;
    if (!DisplaydInternalInstanceEqual(&engine->instance, &identity->instance))
        return DISPLAYD_ENGINE_STALE_SURFACE;
    row = &engine->surfaces[identity->slot];
    if (row->state != DISPLAYD_SURFACE_LIVE)
        return DISPLAYD_ENGINE_SURFACE_NOT_FOUND;
    if (row->generation != identity->generation)
        return DISPLAYD_ENGINE_STALE_SURFACE;
    *surface_out = row;
    return DISPLAYD_ENGINE_OK;
}

DisplaydEngineStatus DisplaydInternalResolveRequest(DisplaydEngineImpl* engine, const DisplaydRequestReceipt* receipt,
                                                    DisplaydRequestRow** request_out)
{
    DisplaydRequestRow* row;

    if (request_out != 0)
        *request_out = 0;
    if (engine == 0 || receipt == 0 || request_out == 0 || receipt->request_slot >= DISPLAYD_ENGINE_MAX_REQUESTS ||
        receipt->peer_slot >= DISPLAYD_ENGINE_MAX_PEERS || receipt->peer_generation == 0 ||
        receipt->request_generation == 0 || receipt->request_id == 0 ||
        !DisplaydEngineInstanceIdentityIsCanonical(&receipt->instance))
        return DISPLAYD_ENGINE_INVALID_IDENTITY;
    if (!DisplaydInternalInstanceEqual(&engine->instance, &receipt->instance))
        return DISPLAYD_ENGINE_STALE_REPLY;
    row = &engine->requests[receipt->request_slot];
    if (row->state == DISPLAYD_REQUEST_FREE || row->state == DISPLAYD_REQUEST_RETIRED ||
        row->generation != receipt->request_generation || row->peer_slot != receipt->peer_slot ||
        row->peer_generation != receipt->peer_generation || row->request.request_id != receipt->request_id)
        return DISPLAYD_ENGINE_STALE_REPLY;
    *request_out = row;
    return DISPLAYD_ENGINE_OK;
}

DisplaydEngineStatus DisplaydInternalResolveRequestConst(const DisplaydEngineImpl* engine,
                                                         const DisplaydRequestReceipt* receipt,
                                                         const DisplaydRequestRow** request_out)
{
    if (request_out != 0)
        *request_out = 0;
    if (engine == 0 || receipt == 0 || request_out == 0 || receipt->request_slot >= DISPLAYD_ENGINE_MAX_REQUESTS ||
        receipt->peer_slot >= DISPLAYD_ENGINE_MAX_PEERS || receipt->peer_generation == 0 ||
        receipt->request_generation == 0 || receipt->request_id == 0 ||
        !DisplaydEngineInstanceIdentityIsCanonical(&receipt->instance))
        return DISPLAYD_ENGINE_INVALID_IDENTITY;
    if (!DisplaydInternalInstanceEqual(&engine->instance, &receipt->instance))
        return DISPLAYD_ENGINE_STALE_REPLY;
    {
        const DisplaydRequestRow* row = &engine->requests[receipt->request_slot];
        if (row->state == DISPLAYD_REQUEST_FREE || row->state == DISPLAYD_REQUEST_RETIRED ||
            row->generation != receipt->request_generation || row->peer_slot != receipt->peer_slot ||
            row->peer_generation != receipt->peer_generation || row->request.request_id != receipt->request_id)
            return DISPLAYD_ENGINE_STALE_REPLY;
        *request_out = row;
    }
    return DISPLAYD_ENGINE_OK;
}

int32_t DisplaydInternalFindRequest(const DisplaydEngineImpl* engine, uint32_t peer_slot, uint64_t peer_generation,
                                    uint64_t request_id)
{
    uint32_t index;

    if (engine == 0)
        return -1;
    for (index = 0; index < DISPLAYD_ENGINE_MAX_REQUESTS; ++index)
    {
        const DisplaydRequestRow* row = &engine->requests[index];
        if (row->state != DISPLAYD_REQUEST_FREE && row->state != DISPLAYD_REQUEST_RETIRED &&
            row->peer_slot == peer_slot && row->peer_generation == peer_generation &&
            row->request.request_id == request_id)
            return (int32_t)index;
    }
    return -1;
}

DisplaydEngineStatus DisplaydInternalValidate(const DisplaydEngineImpl* engine)
{
    uint32_t peer_surfaces[DISPLAYD_ENGINE_MAX_PEERS];
    uint32_t peer_requests[DISPLAYD_ENGINE_MAX_PEERS];
    uint32_t peer_events[DISPLAYD_ENGINE_MAX_PEERS];
    uint32_t peer_count = 0;
    uint32_t surface_count = 0;
    uint32_t request_count = 0;
    uint32_t event_count = 0;
    uint32_t index;

    if (engine == 0 || engine->magic != DISPLAYD_ENGINE_MAGIC)
        return DISPLAYD_ENGINE_NOT_INITIALIZED;
    if (!DisplaydEngineInstanceIdentityIsCanonical(&engine->instance) || engine->first_slot_generation == 0 ||
        engine->display_width == 0 || engine->display_height == 0 || engine->state_epoch == 0 ||
        engine->next_request_fifo_ticket == 0 || engine->next_event_fifo_ticket == 0 ||
        (engine->state != DISPLAYD_ENGINE_STATE_OPEN && engine->state != DISPLAYD_ENGINE_STATE_DRAINING &&
         engine->state != DISPLAYD_ENGINE_STATE_CLOSED) ||
        engine->peer_count > DISPLAYD_ENGINE_MAX_PEERS || engine->surface_count > DISPLAYD_ENGINE_MAX_SURFACES ||
        engine->request_count > DISPLAYD_ENGINE_MAX_REQUESTS || engine->event_count > DISPLAYD_ENGINE_MAX_EVENTS ||
        engine->z_count > DISPLAYD_ENGINE_MAX_SURFACES || engine->state_epoch_exhausted > 1 ||
        engine->request_fifo_exhausted > 1 || engine->event_fifo_exhausted > 1 ||
        (engine->state_epoch_exhausted && engine->state_epoch != UINT64_MAX) ||
        (engine->request_fifo_exhausted && engine->next_request_fifo_ticket != UINT64_MAX) ||
        (engine->event_fifo_exhausted && engine->next_event_fifo_ticket != UINT64_MAX))
        return DISPLAYD_ENGINE_CORRUPT_STATE;
    DisplaydInternalClear(peer_surfaces, (uint32_t)sizeof(peer_surfaces));
    DisplaydInternalClear(peer_requests, (uint32_t)sizeof(peer_requests));
    DisplaydInternalClear(peer_events, (uint32_t)sizeof(peer_events));
    for (index = 0; index < DISPLAYD_ENGINE_MAX_PEERS; ++index)
    {
        const DisplaydPeerRow* row = &engine->peers[index];
        if (row->state == DISPLAYD_PEER_OPEN)
        {
            if (!DisplaydPeerIdentityIsCanonical(&row->identity) || row->generation == 0 || row->next_request_id == 0 ||
                row->next_event_sequence == 0 || row->surface_count > DISPLAYD_ENGINE_MAX_SURFACES ||
                row->request_count > DISPLAYD_ENGINE_MAX_REQUESTS ||
                row->event_count > DISPLAYD_ENGINE_MAX_EVENTS_PER_PEER || row->request_sequence_exhausted > 1 ||
                row->event_sequence_exhausted > 1 ||
                (row->request_sequence_exhausted && row->next_request_id != UINT64_MAX) ||
                (row->event_sequence_exhausted && row->next_event_sequence != UINT64_MAX))
                return DISPLAYD_ENGINE_CORRUPT_STATE;
            ++peer_count;
        }
        else if (row->state != DISPLAYD_PEER_FREE && row->state != DISPLAYD_PEER_RETIRED)
            return DISPLAYD_ENGINE_CORRUPT_STATE;
    }
    for (index = 0; index < DISPLAYD_ENGINE_MAX_SURFACES; ++index)
    {
        const DisplaydSurfaceRow* row = &engine->surfaces[index];
        if (row->state == DISPLAYD_SURFACE_LIVE)
        {
            if (row->generation == 0 || row->peer_slot >= DISPLAYD_ENGINE_MAX_PEERS || row->visible > 1 ||
                !DisplaydInternalRectIsValid(engine, &row->bounds) ||
                engine->peers[row->peer_slot].state != DISPLAYD_PEER_OPEN ||
                engine->peers[row->peer_slot].generation != row->peer_generation)
                return DISPLAYD_ENGINE_CORRUPT_STATE;
            ++surface_count;
            ++peer_surfaces[row->peer_slot];
        }
        else if (row->state != DISPLAYD_SURFACE_FREE && row->state != DISPLAYD_SURFACE_RETIRED)
            return DISPLAYD_ENGINE_CORRUPT_STATE;
    }
    for (index = 0; index < DISPLAYD_ENGINE_MAX_REQUESTS; ++index)
    {
        const DisplaydRequestRow* row = &engine->requests[index];
        if (row->state != DISPLAYD_REQUEST_FREE && row->state != DISPLAYD_REQUEST_RETIRED)
        {
            if (row->state < DISPLAYD_REQUEST_QUEUED_INTERNAL ||
                row->state > DISPLAYD_REQUEST_REPLY_PUBLISHING_INTERNAL || row->generation == 0 ||
                row->peer_slot >= DISPLAYD_ENGINE_MAX_PEERS || row->peer_generation == 0 ||
                row->request.request_id == 0 || row->fifo_ticket == 0 ||
                engine->peers[row->peer_slot].state != DISPLAYD_PEER_OPEN ||
                engine->peers[row->peer_slot].generation != row->peer_generation)
                return DISPLAYD_ENGINE_CORRUPT_STATE;
            ++request_count;
            ++peer_requests[row->peer_slot];
        }
    }
    for (index = 0; index < DISPLAYD_ENGINE_MAX_EVENTS; ++index)
    {
        const DisplaydEventRow* row = &engine->events[index];
        if (row->state != DISPLAYD_EVENT_FREE && row->state != DISPLAYD_EVENT_RETIRED)
        {
            if ((row->state != DISPLAYD_EVENT_READY_INTERNAL && row->state != DISPLAYD_EVENT_PUBLISHING_INTERNAL) ||
                row->generation == 0 || row->peer_slot >= DISPLAYD_ENGINE_MAX_PEERS || row->peer_generation == 0 ||
                row->fifo_ticket == 0 || row->event.sequence == 0 || row->event.state_epoch == 0 ||
                row->event.type <= DISPLAYD_EVENT_INVALID || row->event.type > DISPLAYD_EVENT_FOCUS_LOST ||
                !DisplaydSurfaceIdentityIsCanonical(&row->event.surface) ||
                engine->peers[row->peer_slot].state != DISPLAYD_PEER_OPEN ||
                engine->peers[row->peer_slot].generation != row->peer_generation)
                return DISPLAYD_ENGINE_CORRUPT_STATE;
            ++event_count;
            ++peer_events[row->peer_slot];
        }
    }
    if (peer_count != engine->peer_count || surface_count != engine->surface_count ||
        request_count != engine->request_count || event_count != engine->event_count ||
        engine->z_count != engine->surface_count)
        return DISPLAYD_ENGINE_CORRUPT_STATE;
    for (index = 0; index < DISPLAYD_ENGINE_MAX_PEERS; ++index)
    {
        if (engine->peers[index].state == DISPLAYD_PEER_OPEN &&
            (engine->peers[index].surface_count != peer_surfaces[index] ||
             engine->peers[index].request_count != peer_requests[index] ||
             engine->peers[index].event_count != peer_events[index]))
            return DISPLAYD_ENGINE_CORRUPT_STATE;
    }
    for (index = 0; index < engine->z_count; ++index)
    {
        const DisplaydSurfaceRow* row;
        uint32_t other;
        if (DisplaydInternalResolveSurfaceConst(engine, &engine->z_order[index], &row) != DISPLAYD_ENGINE_OK)
            return DISPLAYD_ENGINE_CORRUPT_STATE;
        for (other = index + 1; other < engine->z_count; ++other)
        {
            if (DisplaydInternalSurfaceEqual(&engine->z_order[index], &engine->z_order[other]))
                return DISPLAYD_ENGINE_CORRUPT_STATE;
        }
    }
    if (!DisplaydInternalSurfaceIsZero(&engine->focused_surface))
    {
        const DisplaydSurfaceRow* focused;
        if (DisplaydInternalResolveSurfaceConst(engine, &engine->focused_surface, &focused) != DISPLAYD_ENGINE_OK ||
            !focused->visible)
            return DISPLAYD_ENGINE_CORRUPT_STATE;
    }
    if ((engine->state == DISPLAYD_ENGINE_STATE_DRAINING || engine->state == DISPLAYD_ENGINE_STATE_CLOSED) &&
        (engine->peer_count != 0 || engine->surface_count != 0 || engine->request_count != 0 ||
         engine->event_count != 0 || engine->z_count != 0 || !DisplaydInternalSurfaceIsZero(&engine->focused_surface)))
        return DISPLAYD_ENGINE_CORRUPT_STATE;
    return DISPLAYD_ENGINE_OK;
}

DisplaydEngineStatus DisplaydEngineDescribe(const DisplaydEngine* engine, DisplaydEngineSnapshot* snapshot_out)
{
    const DisplaydEngineImpl* impl;
    DisplaydEngineStatus status;
    uint32_t index;

    if (engine == 0 || snapshot_out == 0)
        return DISPLAYD_ENGINE_NULL_ARGUMENT;
    if (DisplaydInternalRangesOverlap(engine, sizeof(*engine), snapshot_out, sizeof(*snapshot_out)))
        return DISPLAYD_ENGINE_ALIASED_STORAGE;
    DisplaydInternalClear(snapshot_out, (uint32_t)sizeof(*snapshot_out));
    impl = DisplaydInternalReadOnly(engine);
    status = DisplaydInternalValidate(impl);
    if (status != DISPLAYD_ENGINE_OK)
        return status;
    snapshot_out->instance = impl->instance;
    snapshot_out->focused_surface = impl->focused_surface;
    snapshot_out->state_epoch = impl->state_epoch;
    snapshot_out->state = impl->state;
    snapshot_out->display_width = impl->display_width;
    snapshot_out->display_height = impl->display_height;
    snapshot_out->peer_count = impl->peer_count;
    snapshot_out->surface_count = impl->surface_count;
    snapshot_out->request_count = impl->request_count;
    snapshot_out->event_count = impl->event_count;
    snapshot_out->z_count = impl->z_count;
    for (index = 0; index < DISPLAYD_ENGINE_MAX_PEERS; ++index)
        snapshot_out->retired_peer_slots += (uint32_t)(impl->peers[index].state == DISPLAYD_PEER_RETIRED);
    for (index = 0; index < DISPLAYD_ENGINE_MAX_SURFACES; ++index)
        snapshot_out->retired_surface_slots += (uint32_t)(impl->surfaces[index].state == DISPLAYD_SURFACE_RETIRED);
    for (index = 0; index < DISPLAYD_ENGINE_MAX_REQUESTS; ++index)
        snapshot_out->retired_request_slots += (uint32_t)(impl->requests[index].state == DISPLAYD_REQUEST_RETIRED);
    for (index = 0; index < DISPLAYD_ENGINE_MAX_EVENTS; ++index)
        snapshot_out->retired_event_slots += (uint32_t)(impl->events[index].state == DISPLAYD_EVENT_RETIRED);
    return DISPLAYD_ENGINE_OK;
}

DisplaydEngineStatus DisplaydEngineInspectPeer(const DisplaydEngine* engine, const DisplaydPeerReceipt* peer,
                                               DisplaydPeerSnapshot* snapshot_out)
{
    const DisplaydEngineImpl* impl;
    const DisplaydPeerRow* row;
    DisplaydEngineStatus status;

    if (engine == 0 || peer == 0 || snapshot_out == 0)
        return DISPLAYD_ENGINE_NULL_ARGUMENT;
    if (DisplaydInternalRangesOverlap(engine, sizeof(*engine), peer, sizeof(*peer)) ||
        DisplaydInternalRangesOverlap(engine, sizeof(*engine), snapshot_out, sizeof(*snapshot_out)) ||
        DisplaydInternalRangesOverlap(peer, sizeof(*peer), snapshot_out, sizeof(*snapshot_out)))
        return DISPLAYD_ENGINE_ALIASED_STORAGE;
    DisplaydInternalClear(snapshot_out, (uint32_t)sizeof(*snapshot_out));
    impl = DisplaydInternalReadOnly(engine);
    status = DisplaydInternalValidate(impl);
    if (status != DISPLAYD_ENGINE_OK)
        return status;
    status = DisplaydInternalResolvePeerConst(impl, peer, &row);
    if (status != DISPLAYD_ENGINE_OK)
        return status;
    snapshot_out->receipt = *peer;
    snapshot_out->next_request_id = row->next_request_id;
    snapshot_out->next_event_sequence = row->next_event_sequence;
    snapshot_out->surface_count = row->surface_count;
    snapshot_out->request_count = row->request_count;
    snapshot_out->event_count = row->event_count;
    snapshot_out->open = 1;
    return DISPLAYD_ENGINE_OK;
}

DisplaydEngineStatus DisplaydEngineInspectSurface(const DisplaydEngine* engine, const DisplaydSurfaceIdentity* surface,
                                                  DisplaydSurfaceSnapshot* snapshot_out)
{
    const DisplaydEngineImpl* impl;
    const DisplaydSurfaceRow* row;
    DisplaydEngineStatus status;
    int32_t rank;

    if (engine == 0 || surface == 0 || snapshot_out == 0)
        return DISPLAYD_ENGINE_NULL_ARGUMENT;
    if (DisplaydInternalRangesOverlap(engine, sizeof(*engine), surface, sizeof(*surface)) ||
        DisplaydInternalRangesOverlap(engine, sizeof(*engine), snapshot_out, sizeof(*snapshot_out)) ||
        DisplaydInternalRangesOverlap(surface, sizeof(*surface), snapshot_out, sizeof(*snapshot_out)))
        return DISPLAYD_ENGINE_ALIASED_STORAGE;
    DisplaydInternalClear(snapshot_out, (uint32_t)sizeof(*snapshot_out));
    impl = DisplaydInternalReadOnly(engine);
    status = DisplaydInternalValidate(impl);
    if (status != DISPLAYD_ENGINE_OK)
        return status;
    status = DisplaydInternalResolveSurfaceConst(impl, surface, &row);
    if (status != DISPLAYD_ENGINE_OK)
        return status;
    rank = DisplaydInternalZRank(impl, surface);
    if (rank < 0)
        return DISPLAYD_ENGINE_CORRUPT_STATE;
    snapshot_out->identity = *surface;
    snapshot_out->owner = DisplaydInternalMakePeerReceipt(impl, row->peer_slot);
    snapshot_out->bounds = row->bounds;
    snapshot_out->z_rank = (uint32_t)rank;
    snapshot_out->visible = row->visible;
    snapshot_out->focused = DisplaydInternalSurfaceEqual(&impl->focused_surface, surface);
    return DISPLAYD_ENGINE_OK;
}

DisplaydEngineStatus DisplaydEngineInspectRequest(const DisplaydEngine* engine, const DisplaydRequestReceipt* request,
                                                  DisplaydRequestSnapshot* snapshot_out)
{
    const DisplaydEngineImpl* impl;
    const DisplaydRequestRow* row;
    DisplaydEngineStatus status;

    if (engine == 0 || request == 0 || snapshot_out == 0)
        return DISPLAYD_ENGINE_NULL_ARGUMENT;
    if (DisplaydInternalRangesOverlap(engine, sizeof(*engine), request, sizeof(*request)) ||
        DisplaydInternalRangesOverlap(engine, sizeof(*engine), snapshot_out, sizeof(*snapshot_out)) ||
        DisplaydInternalRangesOverlap(request, sizeof(*request), snapshot_out, sizeof(*snapshot_out)))
        return DISPLAYD_ENGINE_ALIASED_STORAGE;
    DisplaydInternalClear(snapshot_out, (uint32_t)sizeof(*snapshot_out));
    impl = DisplaydInternalReadOnly(engine);
    status = DisplaydInternalValidate(impl);
    if (status != DISPLAYD_ENGINE_OK)
        return status;
    status = DisplaydInternalResolveRequestConst(impl, request, &row);
    if (status != DISPLAYD_ENGINE_OK)
        return status;
    snapshot_out->receipt = *request;
    snapshot_out->request = row->request;
    snapshot_out->reply = row->reply;
    snapshot_out->fifo_ticket = row->fifo_ticket;
    if (row->state == DISPLAYD_REQUEST_QUEUED_INTERNAL)
        snapshot_out->phase = DISPLAYD_REQUEST_QUEUED;
    else if (row->state == DISPLAYD_REQUEST_REPLY_READY_INTERNAL)
        snapshot_out->phase = DISPLAYD_REQUEST_REPLY_READY;
    else if (row->state == DISPLAYD_REQUEST_REPLY_PUBLISHING_INTERNAL)
        snapshot_out->phase = DISPLAYD_REQUEST_REPLY_PUBLISHING;
    else
        return DISPLAYD_ENGINE_CORRUPT_STATE;
    return DISPLAYD_ENGINE_OK;
}
