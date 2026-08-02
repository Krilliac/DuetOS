#include "display_engine_internal.h"

#include <stdint.h>

static uint8_t ReservedBytesAreZero(const uint8_t* bytes, uint32_t count)
{
    uint32_t index;

    for (index = 0; index < count; ++index)
    {
        if (bytes[index] != 0)
            return 0;
    }
    return 1;
}

static uint8_t RequestIsCanonical(const DisplaydEngineImpl* engine, const DisplaydRequest* request)
{
    if (engine == 0 || request == 0 || request->request_id == 0 || request->command <= DISPLAYD_COMMAND_INVALID ||
        request->command > DISPLAYD_COMMAND_FOCUS || request->visible > 1 ||
        !ReservedBytesAreZero(request->reserved8, 6))
        return 0;
    switch ((DisplaydCommandType)request->command)
    {
    case DISPLAYD_COMMAND_CREATE_SURFACE:
        return (uint8_t)(DisplaydInternalSurfaceIsZero(&request->surface) &&
                         DisplaydInternalRectIsValid(engine, &request->bounds));
    case DISPLAYD_COMMAND_DESTROY_SURFACE:
    case DISPLAYD_COMMAND_RAISE:
    case DISPLAYD_COMMAND_FOCUS:
        return (uint8_t)(DisplaydSurfaceIdentityIsCanonical(&request->surface) &&
                         DisplaydInternalRectIsZero(&request->bounds) && request->visible == 0);
    case DISPLAYD_COMMAND_SET_BOUNDS:
        return (uint8_t)(DisplaydSurfaceIdentityIsCanonical(&request->surface) &&
                         DisplaydInternalRectIsValid(engine, &request->bounds) && request->visible == 0);
    case DISPLAYD_COMMAND_SET_VISIBLE:
        return (uint8_t)(DisplaydSurfaceIdentityIsCanonical(&request->surface) &&
                         DisplaydInternalRectIsZero(&request->bounds));
    default:
        return 0;
    }
}

static void MakeReply(DisplaydRequestRow* row, DisplaydReplyCode code, uint64_t state_epoch,
                      const DisplaydSurfaceIdentity* surface)
{
    DisplaydInternalClearReply(&row->reply);
    row->reply.request_id = row->request.request_id;
    row->reply.state_epoch = state_epoch;
    if (surface != 0)
        row->reply.surface = *surface;
    row->reply.code = (uint32_t)code;
}

DisplaydEngineStatus DisplaydEngineSubmit(DisplaydEngine* engine, const DisplaydPeerReceipt* peer,
                                          const DisplaydRequest* request, DisplaydRequestReceipt* receipt_out)
{
    DisplaydEngineImpl* impl;
    DisplaydPeerRow* peer_row;
    DisplaydRequestRow* row;
    DisplaydEngineStatus status;
    int32_t slot;
    uint64_t generation;
    uint64_t fifo_ticket;

    if (engine == 0 || peer == 0 || request == 0 || receipt_out == 0)
        return DISPLAYD_ENGINE_NULL_ARGUMENT;
    if (DisplaydInternalRangesOverlap(engine, sizeof(*engine), peer, sizeof(*peer)) ||
        DisplaydInternalRangesOverlap(engine, sizeof(*engine), request, sizeof(*request)) ||
        DisplaydInternalRangesOverlap(engine, sizeof(*engine), receipt_out, sizeof(*receipt_out)) ||
        DisplaydInternalRangesOverlap(peer, sizeof(*peer), receipt_out, sizeof(*receipt_out)) ||
        DisplaydInternalRangesOverlap(request, sizeof(*request), receipt_out, sizeof(*receipt_out)))
        return DISPLAYD_ENGINE_ALIASED_STORAGE;
    DisplaydInternalClearRequestReceipt(receipt_out);
    impl = DisplaydInternalMutable(engine);
    status = DisplaydInternalValidate(impl);
    if (status != DISPLAYD_ENGINE_OK)
        return status;
    if (impl->state == DISPLAYD_ENGINE_STATE_DRAINING)
        return DISPLAYD_ENGINE_DRAINING;
    if (impl->state == DISPLAYD_ENGINE_STATE_CLOSED)
        return DISPLAYD_ENGINE_CLOSED;
    status = DisplaydInternalResolvePeer(impl, peer, &peer_row);
    if (status != DISPLAYD_ENGINE_OK)
        return status;
    if (!RequestIsCanonical(impl, request))
        return DISPLAYD_ENGINE_INVALID_COMMAND;
    if (peer_row->request_sequence_exhausted)
        return DISPLAYD_ENGINE_SEQUENCE_EXHAUSTED;
    if (request->request_id < peer_row->next_request_id)
        return DISPLAYD_ENGINE_REPLAYED_REQUEST;
    if (request->request_id > peer_row->next_request_id)
        return DISPLAYD_ENGINE_OUT_OF_ORDER_REQUEST;
    if (impl->request_count >= DISPLAYD_ENGINE_MAX_REQUESTS)
        return DISPLAYD_ENGINE_REQUEST_CAPACITY;
    slot = DisplaydInternalFindReusableRequest(impl);
    if (slot < 0)
        return DISPLAYD_ENGINE_GENERATION_EXHAUSTED;
    generation = DisplaydInternalNextGeneration(impl, impl->requests[(uint32_t)slot].generation);
    if (generation == 0)
        return DISPLAYD_ENGINE_GENERATION_EXHAUSTED;
    if (!DisplaydInternalAllocateRequestTicket(impl, &fifo_ticket))
        return DISPLAYD_ENGINE_SEQUENCE_EXHAUSTED;
    row = &impl->requests[(uint32_t)slot];
    DisplaydInternalClear(row, (uint32_t)sizeof(*row));
    row->request = *request;
    row->generation = generation;
    row->peer_generation = peer->generation;
    row->fifo_ticket = fifo_ticket;
    row->peer_slot = peer->slot;
    row->state = DISPLAYD_REQUEST_QUEUED_INTERNAL;
    ++peer_row->request_count;
    ++impl->request_count;
    if (peer_row->next_request_id == UINT64_MAX)
        peer_row->request_sequence_exhausted = 1;
    else
        ++peer_row->next_request_id;
    *receipt_out = DisplaydInternalMakeRequestReceipt(impl, (uint32_t)slot);
    return DisplaydInternalValidate(impl);
}

DisplaydEngineStatus DisplaydEngineCancel(DisplaydEngine* engine, const DisplaydPeerReceipt* peer, uint64_t request_id,
                                          DisplaydRequestReceipt* receipt_out)
{
    DisplaydEngineImpl* impl;
    DisplaydPeerRow* ignored_peer;
    DisplaydRequestRow* row;
    DisplaydEngineStatus status;
    int32_t slot;

    if (engine == 0 || peer == 0 || receipt_out == 0)
        return DISPLAYD_ENGINE_NULL_ARGUMENT;
    if (DisplaydInternalRangesOverlap(engine, sizeof(*engine), peer, sizeof(*peer)) ||
        DisplaydInternalRangesOverlap(engine, sizeof(*engine), receipt_out, sizeof(*receipt_out)) ||
        DisplaydInternalRangesOverlap(peer, sizeof(*peer), receipt_out, sizeof(*receipt_out)))
        return DISPLAYD_ENGINE_ALIASED_STORAGE;
    DisplaydInternalClearRequestReceipt(receipt_out);
    if (request_id == 0)
        return DISPLAYD_ENGINE_INVALID_ARGUMENT;
    impl = DisplaydInternalMutable(engine);
    status = DisplaydInternalValidate(impl);
    if (status != DISPLAYD_ENGINE_OK)
        return status;
    status = DisplaydInternalResolvePeer(impl, peer, &ignored_peer);
    if (status != DISPLAYD_ENGINE_OK)
        return status;
    slot = DisplaydInternalFindRequest(impl, peer->slot, peer->generation, request_id);
    if (slot < 0)
        return DISPLAYD_ENGINE_REQUEST_NOT_FOUND;
    row = &impl->requests[(uint32_t)slot];
    if (row->state != DISPLAYD_REQUEST_QUEUED_INTERNAL)
        return DISPLAYD_ENGINE_CANCEL_TOO_LATE;
    MakeReply(row, DISPLAYD_REPLY_CANCELLED, impl->state_epoch,
              DisplaydInternalSurfaceIsZero(&row->request.surface) ? 0 : &row->request.surface);
    row->state = DISPLAYD_REQUEST_REPLY_READY_INTERNAL;
    *receipt_out = DisplaydInternalMakeRequestReceipt(impl, (uint32_t)slot);
    return DisplaydInternalValidate(impl);
}

static uint8_t RectEqual(const DisplaydRect* left, const DisplaydRect* right)
{
    return (uint8_t)(left->x == right->x && left->y == right->y && left->width == right->width &&
                     left->height == right->height);
}

static void PrepareEvent(DisplaydEventDraft* draft, uint32_t peer_slot, uint64_t peer_generation,
                         DisplaydEventType type, const DisplaydSurfaceIdentity* surface, const DisplaydRect* bounds,
                         uint8_t visible, uint32_t z_rank, uint64_t state_epoch)
{
    DisplaydInternalClear(draft, (uint32_t)sizeof(*draft));
    draft->peer_slot = peer_slot;
    draft->peer_generation = peer_generation;
    draft->event.state_epoch = state_epoch;
    draft->event.surface = *surface;
    draft->event.bounds = *bounds;
    draft->event.z_rank = z_rank;
    draft->event.type = (uint8_t)type;
    draft->event.visible = visible;
}

static DisplaydEngineStatus ReserveMutationEvents(const DisplaydEngineImpl* engine, DisplaydEventDraft* drafts,
                                                  uint32_t count, DisplaydEventReservation* reservation,
                                                  uint64_t* next_epoch)
{
    uint32_t index;

    if (next_epoch != 0)
        *next_epoch = 0;
    if (engine == 0 || reservation == 0 || next_epoch == 0)
        return DISPLAYD_ENGINE_INVALID_ARGUMENT;
    if (engine->state_epoch_exhausted || engine->state_epoch == UINT64_MAX)
        return DISPLAYD_ENGINE_STATE_EPOCH_EXHAUSTED;
    *next_epoch = engine->state_epoch + 1U;
    for (index = 0; index < count; ++index)
        drafts[index].event.state_epoch = *next_epoch;
    return DisplaydInternalReserveEvents(engine, drafts, count, reservation);
}

static DisplaydReplyCode EventFailureReply(DisplaydEngineStatus status)
{
    if (status == DISPLAYD_ENGINE_GENERATION_EXHAUSTED)
        return DISPLAYD_REPLY_GENERATION_EXHAUSTED;
    if (status == DISPLAYD_ENGINE_EVENT_CAPACITY)
        return DISPLAYD_REPLY_EVENT_QUEUE_FULL;
    if (status == DISPLAYD_ENGINE_STATE_EPOCH_EXHAUSTED)
        return DISPLAYD_REPLY_STATE_EPOCH_EXHAUSTED;
    if (status == DISPLAYD_ENGINE_EVENT_SEQUENCE_EXHAUSTED)
        return DISPLAYD_REPLY_EVENT_SEQUENCE_EXHAUSTED;
    return DISPLAYD_REPLY_INTERNAL_FAILURE;
}

static DisplaydReplyCode ResolveOwnedSurface(DisplaydEngineImpl* engine, const DisplaydRequestRow* request_row,
                                             DisplaydSurfaceRow** surface_out)
{
    DisplaydEngineStatus status = DisplaydInternalResolveSurface(engine, &request_row->request.surface, surface_out);

    if (status != DISPLAYD_ENGINE_OK)
        return DISPLAYD_REPLY_INVALID_SURFACE;
    if ((*surface_out)->peer_slot != request_row->peer_slot ||
        (*surface_out)->peer_generation != request_row->peer_generation)
    {
        *surface_out = 0;
        return DISPLAYD_REPLY_WRONG_OWNER;
    }
    return DISPLAYD_REPLY_SUCCESS;
}

static uint8_t PrepareExistingEvent(const DisplaydEngineImpl* engine, DisplaydEventDraft* draft, DisplaydEventType type,
                                    const DisplaydSurfaceIdentity* identity, const DisplaydRect* bounds_override,
                                    int32_t visible_override, int32_t z_rank_override)
{
    const DisplaydSurfaceRow* row;
    const DisplaydRect* bounds;
    int32_t rank;
    uint8_t visible;

    if (DisplaydInternalResolveSurfaceConst(engine, identity, &row) != DISPLAYD_ENGINE_OK)
        return 0;
    rank = z_rank_override >= 0 ? z_rank_override : DisplaydInternalZRank(engine, identity);
    if (rank < 0)
        return 0;
    bounds = bounds_override != 0 ? bounds_override : &row->bounds;
    visible = visible_override >= 0 ? (uint8_t)visible_override : row->visible;
    PrepareEvent(draft, row->peer_slot, row->peer_generation, type, identity, bounds, visible, (uint32_t)rank, 0);
    return 1;
}

static DisplaydReplyCode ApplyCreate(DisplaydEngineImpl* engine, DisplaydRequestRow* request_row,
                                     DisplaydSurfaceIdentity* surface_out)
{
    DisplaydEventDraft drafts[DISPLAYD_ENGINE_MAX_EVENTS_PER_MUTATION];
    DisplaydEventReservation reservation;
    DisplaydSurfaceIdentity identity;
    DisplaydSurfaceRow* surface;
    DisplaydEngineStatus status;
    uint64_t generation;
    uint64_t epoch;
    uint32_t draft_count = 1;
    int32_t slot;

    if (engine->surface_count >= DISPLAYD_ENGINE_MAX_SURFACES)
        return DISPLAYD_REPLY_SURFACE_CAPACITY;
    slot = DisplaydInternalFindReusableSurface(engine);
    if (slot < 0)
        return DISPLAYD_REPLY_GENERATION_EXHAUSTED;
    generation = DisplaydInternalNextGeneration(engine, engine->surfaces[(uint32_t)slot].generation);
    if (generation == 0)
        return DISPLAYD_REPLY_GENERATION_EXHAUSTED;
    DisplaydInternalClearSurfaceIdentity(&identity);
    identity.instance = engine->instance;
    identity.generation = generation;
    identity.slot = (uint32_t)slot;
    PrepareEvent(&drafts[0], request_row->peer_slot, request_row->peer_generation, DISPLAYD_EVENT_SURFACE_CREATED,
                 &identity, &request_row->request.bounds, request_row->request.visible, engine->z_count, 0);
    if (request_row->request.visible && DisplaydInternalSurfaceIsZero(&engine->focused_surface))
    {
        PrepareEvent(&drafts[draft_count++], request_row->peer_slot, request_row->peer_generation,
                     DISPLAYD_EVENT_FOCUS_GAINED, &identity, &request_row->request.bounds, 1, engine->z_count, 0);
    }
    status = ReserveMutationEvents(engine, drafts, draft_count, &reservation, &epoch);
    if (status != DISPLAYD_ENGINE_OK)
        return EventFailureReply(status);
    if (!DisplaydInternalAdvanceStateEpoch(engine, &epoch))
        return DISPLAYD_REPLY_STATE_EPOCH_EXHAUSTED;
    surface = &engine->surfaces[(uint32_t)slot];
    DisplaydInternalClear(surface, (uint32_t)sizeof(*surface));
    surface->bounds = request_row->request.bounds;
    surface->generation = generation;
    surface->peer_generation = request_row->peer_generation;
    surface->peer_slot = request_row->peer_slot;
    surface->state = DISPLAYD_SURFACE_LIVE;
    surface->visible = request_row->request.visible;
    engine->z_order[engine->z_count++] = identity;
    ++engine->surface_count;
    ++engine->peers[request_row->peer_slot].surface_count;
    if (request_row->request.visible && DisplaydInternalSurfaceIsZero(&engine->focused_surface))
        engine->focused_surface = identity;
    DisplaydInternalPublishEvents(engine, drafts, &reservation);
    *surface_out = identity;
    return DISPLAYD_REPLY_SUCCESS;
}

static DisplaydReplyCode ApplyDestroy(DisplaydEngineImpl* engine, DisplaydRequestRow* request_row,
                                      DisplaydSurfaceIdentity* surface_out)
{
    DisplaydEventDraft drafts[DISPLAYD_ENGINE_MAX_EVENTS_PER_MUTATION];
    DisplaydEventReservation reservation;
    DisplaydSurfaceIdentity fallback;
    DisplaydSurfaceRow* surface;
    DisplaydReplyCode resolved;
    DisplaydEngineStatus status;
    uint64_t epoch;
    uint32_t draft_count = 0;
    int32_t destroyed_rank;
    uint8_t was_focused;

    resolved = ResolveOwnedSurface(engine, request_row, &surface);
    if (resolved != DISPLAYD_REPLY_SUCCESS)
        return resolved;
    destroyed_rank = DisplaydInternalZRank(engine, &request_row->request.surface);
    if (destroyed_rank < 0)
        return DISPLAYD_REPLY_INTERNAL_FAILURE;
    was_focused = DisplaydInternalSurfaceEqual(&engine->focused_surface, &request_row->request.surface);
    DisplaydInternalClearSurfaceIdentity(&fallback);
    if (was_focused)
    {
        if (!PrepareExistingEvent(engine, &drafts[draft_count++], DISPLAYD_EVENT_FOCUS_LOST,
                                  &request_row->request.surface, 0, -1, destroyed_rank))
            return DISPLAYD_REPLY_INTERNAL_FAILURE;
        fallback = DisplaydInternalTopVisibleExcept(engine, &request_row->request.surface);
    }
    if (!PrepareExistingEvent(engine, &drafts[draft_count++], DISPLAYD_EVENT_SURFACE_DESTROYED,
                              &request_row->request.surface, 0, -1, destroyed_rank))
        return DISPLAYD_REPLY_INTERNAL_FAILURE;
    if (!DisplaydInternalSurfaceIsZero(&fallback))
    {
        int32_t fallback_rank = DisplaydInternalZRank(engine, &fallback);
        if (fallback_rank < 0)
            return DISPLAYD_REPLY_INTERNAL_FAILURE;
        if (fallback_rank > destroyed_rank)
            --fallback_rank;
        if (!PrepareExistingEvent(engine, &drafts[draft_count++], DISPLAYD_EVENT_FOCUS_GAINED, &fallback, 0, -1,
                                  fallback_rank))
            return DISPLAYD_REPLY_INTERNAL_FAILURE;
    }
    status = ReserveMutationEvents(engine, drafts, draft_count, &reservation, &epoch);
    if (status != DISPLAYD_ENGINE_OK)
        return EventFailureReply(status);
    if (!DisplaydInternalAdvanceStateEpoch(engine, &epoch))
        return DISPLAYD_REPLY_STATE_EPOCH_EXHAUSTED;
    DisplaydInternalRetireSurface(engine, request_row->request.surface.slot);
    if (was_focused)
        engine->focused_surface = fallback;
    DisplaydInternalPublishEvents(engine, drafts, &reservation);
    *surface_out = request_row->request.surface;
    return DISPLAYD_REPLY_SUCCESS;
}

static DisplaydReplyCode ApplyBounds(DisplaydEngineImpl* engine, DisplaydRequestRow* request_row,
                                     DisplaydSurfaceIdentity* surface_out)
{
    DisplaydEventDraft draft;
    DisplaydEventReservation reservation;
    DisplaydSurfaceRow* surface;
    DisplaydReplyCode resolved;
    DisplaydEngineStatus status;
    uint64_t epoch;

    resolved = ResolveOwnedSurface(engine, request_row, &surface);
    if (resolved != DISPLAYD_REPLY_SUCCESS)
        return resolved;
    *surface_out = request_row->request.surface;
    if (RectEqual(&surface->bounds, &request_row->request.bounds))
        return DISPLAYD_REPLY_SUCCESS;
    if (!PrepareExistingEvent(engine, &draft, DISPLAYD_EVENT_BOUNDS_CHANGED, &request_row->request.surface,
                              &request_row->request.bounds, -1, -1))
        return DISPLAYD_REPLY_INTERNAL_FAILURE;
    status = ReserveMutationEvents(engine, &draft, 1, &reservation, &epoch);
    if (status != DISPLAYD_ENGINE_OK)
        return EventFailureReply(status);
    if (!DisplaydInternalAdvanceStateEpoch(engine, &epoch))
        return DISPLAYD_REPLY_STATE_EPOCH_EXHAUSTED;
    surface->bounds = request_row->request.bounds;
    DisplaydInternalPublishEvents(engine, &draft, &reservation);
    return DISPLAYD_REPLY_SUCCESS;
}

static DisplaydReplyCode ApplyVisibility(DisplaydEngineImpl* engine, DisplaydRequestRow* request_row,
                                         DisplaydSurfaceIdentity* surface_out)
{
    DisplaydEventDraft drafts[DISPLAYD_ENGINE_MAX_EVENTS_PER_MUTATION];
    DisplaydEventReservation reservation;
    DisplaydSurfaceIdentity fallback;
    DisplaydSurfaceRow* surface;
    DisplaydReplyCode resolved;
    DisplaydEngineStatus status;
    uint64_t epoch;
    uint32_t draft_count = 0;
    uint8_t was_focused;

    resolved = ResolveOwnedSurface(engine, request_row, &surface);
    if (resolved != DISPLAYD_REPLY_SUCCESS)
        return resolved;
    *surface_out = request_row->request.surface;
    if (surface->visible == request_row->request.visible)
        return DISPLAYD_REPLY_SUCCESS;
    was_focused = DisplaydInternalSurfaceEqual(&engine->focused_surface, &request_row->request.surface);
    DisplaydInternalClearSurfaceIdentity(&fallback);
    if (was_focused && !request_row->request.visible)
    {
        if (!PrepareExistingEvent(engine, &drafts[draft_count++], DISPLAYD_EVENT_FOCUS_LOST,
                                  &request_row->request.surface, 0, 0, -1))
            return DISPLAYD_REPLY_INTERNAL_FAILURE;
        fallback = DisplaydInternalTopVisibleExcept(engine, &request_row->request.surface);
    }
    if (!PrepareExistingEvent(engine, &drafts[draft_count++], DISPLAYD_EVENT_VISIBILITY_CHANGED,
                              &request_row->request.surface, 0, request_row->request.visible, -1))
        return DISPLAYD_REPLY_INTERNAL_FAILURE;
    if (!DisplaydInternalSurfaceIsZero(&fallback))
    {
        if (!PrepareExistingEvent(engine, &drafts[draft_count++], DISPLAYD_EVENT_FOCUS_GAINED, &fallback, 0, -1, -1))
            return DISPLAYD_REPLY_INTERNAL_FAILURE;
    }
    else if (request_row->request.visible && DisplaydInternalSurfaceIsZero(&engine->focused_surface))
    {
        if (!PrepareExistingEvent(engine, &drafts[draft_count++], DISPLAYD_EVENT_FOCUS_GAINED,
                                  &request_row->request.surface, 0, 1, -1))
            return DISPLAYD_REPLY_INTERNAL_FAILURE;
    }
    status = ReserveMutationEvents(engine, drafts, draft_count, &reservation, &epoch);
    if (status != DISPLAYD_ENGINE_OK)
        return EventFailureReply(status);
    if (!DisplaydInternalAdvanceStateEpoch(engine, &epoch))
        return DISPLAYD_REPLY_STATE_EPOCH_EXHAUSTED;
    surface->visible = request_row->request.visible;
    if (was_focused && !surface->visible)
        engine->focused_surface = fallback;
    else if (surface->visible && DisplaydInternalSurfaceIsZero(&engine->focused_surface))
        engine->focused_surface = request_row->request.surface;
    DisplaydInternalPublishEvents(engine, drafts, &reservation);
    return DISPLAYD_REPLY_SUCCESS;
}

static DisplaydReplyCode ApplyRaise(DisplaydEngineImpl* engine, DisplaydRequestRow* request_row,
                                    DisplaydSurfaceIdentity* surface_out)
{
    DisplaydEventDraft draft;
    DisplaydEventReservation reservation;
    DisplaydSurfaceRow* surface;
    DisplaydReplyCode resolved;
    DisplaydEngineStatus status;
    uint64_t epoch;
    int32_t rank;

    resolved = ResolveOwnedSurface(engine, request_row, &surface);
    if (resolved != DISPLAYD_REPLY_SUCCESS)
        return resolved;
    (void)surface;
    *surface_out = request_row->request.surface;
    rank = DisplaydInternalZRank(engine, &request_row->request.surface);
    if (rank < 0)
        return DISPLAYD_REPLY_INTERNAL_FAILURE;
    if ((uint32_t)rank + 1U == engine->z_count)
        return DISPLAYD_REPLY_SUCCESS;
    if (!PrepareExistingEvent(engine, &draft, DISPLAYD_EVENT_Z_ORDER_CHANGED, &request_row->request.surface, 0, -1,
                              (int32_t)(engine->z_count - 1U)))
        return DISPLAYD_REPLY_INTERNAL_FAILURE;
    status = ReserveMutationEvents(engine, &draft, 1, &reservation, &epoch);
    if (status != DISPLAYD_ENGINE_OK)
        return EventFailureReply(status);
    if (!DisplaydInternalAdvanceStateEpoch(engine, &epoch))
        return DISPLAYD_REPLY_STATE_EPOCH_EXHAUSTED;
    DisplaydInternalZRaise(engine, &request_row->request.surface);
    DisplaydInternalPublishEvents(engine, &draft, &reservation);
    return DISPLAYD_REPLY_SUCCESS;
}

static DisplaydReplyCode ApplyFocus(DisplaydEngineImpl* engine, DisplaydRequestRow* request_row,
                                    DisplaydSurfaceIdentity* surface_out)
{
    DisplaydEventDraft drafts[DISPLAYD_ENGINE_MAX_EVENTS_PER_MUTATION];
    DisplaydEventReservation reservation;
    DisplaydSurfaceRow* surface;
    DisplaydReplyCode resolved;
    DisplaydEngineStatus status;
    uint64_t epoch;
    uint32_t draft_count = 0;
    int32_t rank;
    uint8_t focus_change;
    uint8_t needs_raise;

    resolved = ResolveOwnedSurface(engine, request_row, &surface);
    if (resolved != DISPLAYD_REPLY_SUCCESS)
        return resolved;
    *surface_out = request_row->request.surface;
    if (!surface->visible)
        return DISPLAYD_REPLY_NOT_VISIBLE;
    rank = DisplaydInternalZRank(engine, &request_row->request.surface);
    if (rank < 0)
        return DISPLAYD_REPLY_INTERNAL_FAILURE;
    focus_change = (uint8_t)!DisplaydInternalSurfaceEqual(&engine->focused_surface, &request_row->request.surface);
    needs_raise = (uint8_t)((uint32_t)rank + 1U != engine->z_count);
    if (!focus_change && !needs_raise)
        return DISPLAYD_REPLY_SUCCESS;
    if (focus_change && !DisplaydInternalSurfaceIsZero(&engine->focused_surface))
    {
        if (!PrepareExistingEvent(engine, &drafts[draft_count++], DISPLAYD_EVENT_FOCUS_LOST, &engine->focused_surface,
                                  0, -1, -1))
            return DISPLAYD_REPLY_INTERNAL_FAILURE;
    }
    if (needs_raise)
    {
        if (!PrepareExistingEvent(engine, &drafts[draft_count++], DISPLAYD_EVENT_Z_ORDER_CHANGED,
                                  &request_row->request.surface, 0, -1, (int32_t)(engine->z_count - 1U)))
            return DISPLAYD_REPLY_INTERNAL_FAILURE;
    }
    if (focus_change)
    {
        if (!PrepareExistingEvent(engine, &drafts[draft_count++], DISPLAYD_EVENT_FOCUS_GAINED,
                                  &request_row->request.surface, 0, -1, (int32_t)(engine->z_count - 1U)))
            return DISPLAYD_REPLY_INTERNAL_FAILURE;
    }
    status = ReserveMutationEvents(engine, drafts, draft_count, &reservation, &epoch);
    if (status != DISPLAYD_ENGINE_OK)
        return EventFailureReply(status);
    if (!DisplaydInternalAdvanceStateEpoch(engine, &epoch))
        return DISPLAYD_REPLY_STATE_EPOCH_EXHAUSTED;
    if (needs_raise)
        DisplaydInternalZRaise(engine, &request_row->request.surface);
    if (focus_change)
        engine->focused_surface = request_row->request.surface;
    DisplaydInternalPublishEvents(engine, drafts, &reservation);
    return DISPLAYD_REPLY_SUCCESS;
}

static DisplaydReplyCode ApplyCommand(DisplaydEngineImpl* engine, DisplaydRequestRow* request_row,
                                      DisplaydSurfaceIdentity* surface_out)
{
    DisplaydInternalClearSurfaceIdentity(surface_out);
    switch ((DisplaydCommandType)request_row->request.command)
    {
    case DISPLAYD_COMMAND_CREATE_SURFACE:
        return ApplyCreate(engine, request_row, surface_out);
    case DISPLAYD_COMMAND_DESTROY_SURFACE:
        return ApplyDestroy(engine, request_row, surface_out);
    case DISPLAYD_COMMAND_SET_BOUNDS:
        return ApplyBounds(engine, request_row, surface_out);
    case DISPLAYD_COMMAND_SET_VISIBLE:
        return ApplyVisibility(engine, request_row, surface_out);
    case DISPLAYD_COMMAND_RAISE:
        return ApplyRaise(engine, request_row, surface_out);
    case DISPLAYD_COMMAND_FOCUS:
        return ApplyFocus(engine, request_row, surface_out);
    default:
        return DISPLAYD_REPLY_INTERNAL_FAILURE;
    }
}

DisplaydEngineStatus DisplaydEngineApplyNext(DisplaydEngine* engine, DisplaydApplyResult* result_out)
{
    DisplaydEngineImpl* impl;
    DisplaydRequestRow* row;
    DisplaydSurfaceIdentity surface;
    DisplaydReplyCode reply_code;
    DisplaydEngineStatus status;
    uint64_t best_ticket = UINT64_MAX;
    uint32_t best_slot = DISPLAYD_ENGINE_MAX_REQUESTS;
    uint32_t index;

    if (engine == 0 || result_out == 0)
        return DISPLAYD_ENGINE_NULL_ARGUMENT;
    if (DisplaydInternalRangesOverlap(engine, sizeof(*engine), result_out, sizeof(*result_out)))
        return DISPLAYD_ENGINE_ALIASED_STORAGE;
    DisplaydInternalClearApplyResult(result_out);
    impl = DisplaydInternalMutable(engine);
    status = DisplaydInternalValidate(impl);
    if (status != DISPLAYD_ENGINE_OK)
        return status;
    if (impl->state == DISPLAYD_ENGINE_STATE_CLOSED)
        return DISPLAYD_ENGINE_CLOSED;
    for (index = 0; index < DISPLAYD_ENGINE_MAX_REQUESTS; ++index)
    {
        if (impl->requests[index].state == DISPLAYD_REQUEST_QUEUED_INTERNAL &&
            impl->requests[index].fifo_ticket < best_ticket)
        {
            best_ticket = impl->requests[index].fifo_ticket;
            best_slot = index;
        }
    }
    if (best_slot == DISPLAYD_ENGINE_MAX_REQUESTS)
        return DISPLAYD_ENGINE_NO_REQUEST;
    row = &impl->requests[best_slot];
    reply_code = ApplyCommand(impl, row, &surface);
    MakeReply(row, reply_code, impl->state_epoch, DisplaydInternalSurfaceIsZero(&surface) ? 0 : &surface);
    row->state = DISPLAYD_REQUEST_REPLY_READY_INTERNAL;
    result_out->receipt = DisplaydInternalMakeRequestReceipt(impl, best_slot);
    result_out->reply = row->reply;
    return DisplaydInternalValidate(impl);
}

DisplaydEngineStatus DisplaydEngineGetNextReply(DisplaydEngine* engine, const DisplaydPeerReceipt* peer,
                                                DisplaydReplyPublication* publication_out)
{
    DisplaydEngineImpl* impl;
    DisplaydPeerRow* ignored_peer;
    DisplaydEngineStatus status;
    uint64_t best_ticket = UINT64_MAX;
    uint32_t best_slot = DISPLAYD_ENGINE_MAX_REQUESTS;
    uint32_t index;

    if (engine == 0 || peer == 0 || publication_out == 0)
        return DISPLAYD_ENGINE_NULL_ARGUMENT;
    if (DisplaydInternalRangesOverlap(engine, sizeof(*engine), peer, sizeof(*peer)) ||
        DisplaydInternalRangesOverlap(engine, sizeof(*engine), publication_out, sizeof(*publication_out)) ||
        DisplaydInternalRangesOverlap(peer, sizeof(*peer), publication_out, sizeof(*publication_out)))
        return DISPLAYD_ENGINE_ALIASED_STORAGE;
    DisplaydInternalClearReplyPublication(publication_out);
    impl = DisplaydInternalMutable(engine);
    status = DisplaydInternalValidate(impl);
    if (status != DISPLAYD_ENGINE_OK)
        return status;
    status = DisplaydInternalResolvePeer(impl, peer, &ignored_peer);
    if (status != DISPLAYD_ENGINE_OK)
        return status;
    for (index = 0; index < DISPLAYD_ENGINE_MAX_REQUESTS; ++index)
    {
        DisplaydRequestRow* row = &impl->requests[index];
        if (row->peer_slot != peer->slot || row->peer_generation != peer->generation)
            continue;
        if (row->state == DISPLAYD_REQUEST_REPLY_PUBLISHING_INTERNAL)
            return DISPLAYD_ENGINE_REPLY_IN_FLIGHT;
        if (row->state == DISPLAYD_REQUEST_REPLY_READY_INTERNAL && row->fifo_ticket < best_ticket)
        {
            best_ticket = row->fifo_ticket;
            best_slot = index;
        }
    }
    if (best_slot == DISPLAYD_ENGINE_MAX_REQUESTS)
        return DISPLAYD_ENGINE_NO_REPLY;
    impl->requests[best_slot].state = DISPLAYD_REQUEST_REPLY_PUBLISHING_INTERNAL;
    publication_out->lease.request = DisplaydInternalMakeRequestReceipt(impl, best_slot);
    publication_out->reply = impl->requests[best_slot].reply;
    return DisplaydInternalValidate(impl);
}

DisplaydEngineStatus DisplaydEngineCommitReply(DisplaydEngine* engine, const DisplaydReplyLease* lease)
{
    DisplaydEngineImpl* impl;
    DisplaydRequestRow* row;
    DisplaydEngineStatus status;
    uint32_t request_slot;

    if (engine == 0 || lease == 0)
        return DISPLAYD_ENGINE_NULL_ARGUMENT;
    if (DisplaydInternalRangesOverlap(engine, sizeof(*engine), lease, sizeof(*lease)))
        return DISPLAYD_ENGINE_ALIASED_STORAGE;
    impl = DisplaydInternalMutable(engine);
    status = DisplaydInternalValidate(impl);
    if (status != DISPLAYD_ENGINE_OK)
        return status;
    status = DisplaydInternalResolveRequest(impl, &lease->request, &row);
    if (status != DISPLAYD_ENGINE_OK)
        return status;
    if (row->state != DISPLAYD_REQUEST_REPLY_PUBLISHING_INTERNAL)
        return DISPLAYD_ENGINE_STALE_REPLY;
    request_slot = lease->request.request_slot;
    DisplaydInternalRetireRequest(impl, request_slot);
    return DisplaydInternalValidate(impl);
}

DisplaydEngineStatus DisplaydEngineAbortReply(DisplaydEngine* engine, const DisplaydReplyLease* lease)
{
    DisplaydEngineImpl* impl;
    DisplaydRequestRow* row;
    DisplaydEngineStatus status;

    if (engine == 0 || lease == 0)
        return DISPLAYD_ENGINE_NULL_ARGUMENT;
    if (DisplaydInternalRangesOverlap(engine, sizeof(*engine), lease, sizeof(*lease)))
        return DISPLAYD_ENGINE_ALIASED_STORAGE;
    impl = DisplaydInternalMutable(engine);
    status = DisplaydInternalValidate(impl);
    if (status != DISPLAYD_ENGINE_OK)
        return status;
    status = DisplaydInternalResolveRequest(impl, &lease->request, &row);
    if (status != DISPLAYD_ENGINE_OK)
        return status;
    if (row->state != DISPLAYD_REQUEST_REPLY_PUBLISHING_INTERNAL)
        return DISPLAYD_ENGINE_STALE_REPLY;
    row->state = DISPLAYD_REQUEST_REPLY_READY_INTERNAL;
    return DisplaydInternalValidate(impl);
}
