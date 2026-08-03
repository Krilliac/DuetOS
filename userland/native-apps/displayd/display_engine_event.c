#include "display_engine_internal.h"

#include <stdint.h>

int32_t DisplaydInternalZRank(const DisplaydEngineImpl* engine, const DisplaydSurfaceIdentity* surface)
{
    uint32_t index;

    if (engine == 0 || surface == 0)
        return -1;
    for (index = 0; index < engine->z_count; ++index)
    {
        if (DisplaydInternalSurfaceEqual(&engine->z_order[index], surface))
            return (int32_t)index;
    }
    return -1;
}

void DisplaydInternalZRemove(DisplaydEngineImpl* engine, const DisplaydSurfaceIdentity* surface)
{
    int32_t rank;
    uint32_t index;

    if (engine == 0 || surface == 0)
        return;
    rank = DisplaydInternalZRank(engine, surface);
    if (rank < 0)
        return;
    for (index = (uint32_t)rank; index + 1 < engine->z_count; ++index)
        engine->z_order[index] = engine->z_order[index + 1];
    --engine->z_count;
    DisplaydInternalClearSurfaceIdentity(&engine->z_order[engine->z_count]);
}

void DisplaydInternalZRaise(DisplaydEngineImpl* engine, const DisplaydSurfaceIdentity* surface)
{
    if (engine == 0 || surface == 0 || engine->z_count == 0)
        return;
    if (DisplaydInternalZRank(engine, surface) == (int32_t)(engine->z_count - 1U))
        return;
    DisplaydInternalZRemove(engine, surface);
    if (engine->z_count < DISPLAYD_ENGINE_MAX_SURFACES)
        engine->z_order[engine->z_count++] = *surface;
}

DisplaydSurfaceIdentity DisplaydInternalTopVisibleExcept(const DisplaydEngineImpl* engine,
                                                         const DisplaydSurfaceIdentity* excluded)
{
    DisplaydSurfaceIdentity none;
    uint32_t ordinal;

    DisplaydInternalClearSurfaceIdentity(&none);
    if (engine == 0)
        return none;
    for (ordinal = engine->z_count; ordinal > 0; --ordinal)
    {
        const DisplaydSurfaceIdentity* candidate = &engine->z_order[ordinal - 1U];
        const DisplaydSurfaceRow* row;
        if (excluded != 0 && DisplaydInternalSurfaceEqual(candidate, excluded))
            continue;
        if (DisplaydInternalResolveSurfaceConst(engine, candidate, &row) == DISPLAYD_ENGINE_OK && row->visible)
            return *candidate;
    }
    return none;
}

DisplaydEngineStatus DisplaydInternalReserveEvents(const DisplaydEngineImpl* engine, const DisplaydEventDraft* drafts,
                                                   uint32_t count, DisplaydEventReservation* reservation_out)
{
    uint32_t needed[DISPLAYD_ENGINE_MAX_PEERS];
    uint32_t draft_index;
    uint32_t event_index;

    if (reservation_out != 0)
        DisplaydInternalClear(reservation_out, (uint32_t)sizeof(*reservation_out));
    if (engine == 0 || reservation_out == 0 || count > DISPLAYD_ENGINE_MAX_EVENTS_PER_MUTATION ||
        (count != 0 && drafts == 0))
        return DISPLAYD_ENGINE_INVALID_ARGUMENT;
    if (count == 0)
        return DISPLAYD_ENGINE_OK;
    if (engine->event_fifo_exhausted || engine->next_event_fifo_ticket == 0 ||
        UINT64_MAX - engine->next_event_fifo_ticket + 1U < count)
        return DISPLAYD_ENGINE_EVENT_SEQUENCE_EXHAUSTED;
    if (engine->event_count > DISPLAYD_ENGINE_MAX_EVENTS - count)
        return DISPLAYD_ENGINE_EVENT_CAPACITY;
    DisplaydInternalClear(needed, (uint32_t)sizeof(needed));
    for (draft_index = 0; draft_index < count; ++draft_index)
    {
        const DisplaydEventDraft* draft = &drafts[draft_index];
        const DisplaydPeerRow* peer;
        if (draft->peer_slot >= DISPLAYD_ENGINE_MAX_PEERS)
            return DISPLAYD_ENGINE_CORRUPT_STATE;
        peer = &engine->peers[draft->peer_slot];
        if (peer->state != DISPLAYD_PEER_OPEN || peer->generation != draft->peer_generation ||
            draft->event.type <= DISPLAYD_EVENT_INVALID || draft->event.type > DISPLAYD_EVENT_FOCUS_LOST ||
            draft->event.sequence != 0 || draft->event.state_epoch == 0 ||
            !DisplaydSurfaceIdentityIsCanonical(&draft->event.surface))
            return DISPLAYD_ENGINE_CORRUPT_STATE;
        ++needed[draft->peer_slot];
    }
    for (draft_index = 0; draft_index < DISPLAYD_ENGINE_MAX_PEERS; ++draft_index)
    {
        const DisplaydPeerRow* peer = &engine->peers[draft_index];
        if (needed[draft_index] == 0)
            continue;
        if (peer->event_sequence_exhausted || peer->next_event_sequence == 0 ||
            UINT64_MAX - peer->next_event_sequence + 1U < needed[draft_index])
            return DISPLAYD_ENGINE_EVENT_SEQUENCE_EXHAUSTED;
        if (peer->event_count > DISPLAYD_ENGINE_MAX_EVENTS_PER_PEER - needed[draft_index])
            return DISPLAYD_ENGINE_EVENT_CAPACITY;
    }
    for (event_index = 0; event_index < DISPLAYD_ENGINE_MAX_EVENTS && reservation_out->count < count; ++event_index)
    {
        const DisplaydEventRow* row = &engine->events[event_index];
        const uint64_t generation = DisplaydInternalNextGeneration(engine, row->generation);
        if ((row->state == DISPLAYD_EVENT_FREE || row->state == DISPLAYD_EVENT_RETIRED) && generation != 0)
        {
            const uint32_t at = reservation_out->count++;
            reservation_out->slots[at] = event_index;
            reservation_out->generations[at] = generation;
        }
    }
    if (reservation_out->count != count)
    {
        DisplaydInternalClear(reservation_out, (uint32_t)sizeof(*reservation_out));
        return DISPLAYD_ENGINE_GENERATION_EXHAUSTED;
    }
    return DISPLAYD_ENGINE_OK;
}

void DisplaydInternalPublishEvents(DisplaydEngineImpl* engine, const DisplaydEventDraft* drafts,
                                   const DisplaydEventReservation* reservation)
{
    uint32_t index;

    if (engine == 0 || drafts == 0 || reservation == 0)
        return;
    for (index = 0; index < reservation->count; ++index)
    {
        const DisplaydEventDraft* draft = &drafts[index];
        DisplaydPeerRow* peer = &engine->peers[draft->peer_slot];
        DisplaydEventRow* row = &engine->events[reservation->slots[index]];
        DisplaydInternalClear(row, (uint32_t)sizeof(*row));
        row->event = draft->event;
        row->event.sequence = peer->next_event_sequence;
        row->generation = reservation->generations[index];
        row->peer_generation = draft->peer_generation;
        row->fifo_ticket = engine->next_event_fifo_ticket;
        row->peer_slot = draft->peer_slot;
        row->state = DISPLAYD_EVENT_READY_INTERNAL;
        ++peer->event_count;
        ++engine->event_count;
        if (peer->next_event_sequence == UINT64_MAX)
            peer->event_sequence_exhausted = 1;
        else
            ++peer->next_event_sequence;
        if (engine->next_event_fifo_ticket == UINT64_MAX)
            engine->event_fifo_exhausted = 1;
        else
            ++engine->next_event_fifo_ticket;
    }
}

void DisplaydInternalRetireEvent(DisplaydEngineImpl* engine, uint32_t event_slot)
{
    DisplaydEventRow* row;
    uint64_t generation;

    if (engine == 0 || event_slot >= DISPLAYD_ENGINE_MAX_EVENTS)
        return;
    row = &engine->events[event_slot];
    if (row->state != DISPLAYD_EVENT_READY_INTERNAL && row->state != DISPLAYD_EVENT_PUBLISHING_INTERNAL)
        return;
    if (row->peer_slot < DISPLAYD_ENGINE_MAX_PEERS)
    {
        DisplaydPeerRow* peer = &engine->peers[row->peer_slot];
        if (peer->state == DISPLAYD_PEER_OPEN && peer->generation == row->peer_generation && peer->event_count > 0)
            --peer->event_count;
    }
    if (engine->event_count > 0)
        --engine->event_count;
    generation = row->generation;
    DisplaydInternalClear(row, (uint32_t)sizeof(*row));
    row->generation = generation;
    row->state = DISPLAYD_EVENT_RETIRED;
}

DisplaydEngineStatus DisplaydEngineGetNextEvent(DisplaydEngine* engine, const DisplaydPeerReceipt* peer,
                                                DisplaydEventPublication* publication_out)
{
    DisplaydEngineImpl* impl;
    DisplaydPeerRow* ignored_peer;
    DisplaydEngineStatus status;
    uint64_t best_ticket = UINT64_MAX;
    uint32_t best_slot = DISPLAYD_ENGINE_MAX_EVENTS;
    uint32_t index;

    if (engine == 0 || peer == 0 || publication_out == 0)
        return DISPLAYD_ENGINE_NULL_ARGUMENT;
    if (DisplaydInternalRangesOverlap(engine, sizeof(*engine), peer, sizeof(*peer)) ||
        DisplaydInternalRangesOverlap(engine, sizeof(*engine), publication_out, sizeof(*publication_out)) ||
        DisplaydInternalRangesOverlap(peer, sizeof(*peer), publication_out, sizeof(*publication_out)))
        return DISPLAYD_ENGINE_ALIASED_STORAGE;
    DisplaydInternalClearEventPublication(publication_out);
    impl = DisplaydInternalMutable(engine);
    status = DisplaydInternalValidate(impl);
    if (status != DISPLAYD_ENGINE_OK)
        return status;
    status = DisplaydInternalResolvePeer(impl, peer, &ignored_peer);
    if (status != DISPLAYD_ENGINE_OK)
        return status;
    for (index = 0; index < DISPLAYD_ENGINE_MAX_EVENTS; ++index)
    {
        DisplaydEventRow* row = &impl->events[index];
        if (row->peer_slot != peer->slot || row->peer_generation != peer->generation)
            continue;
        if (row->state == DISPLAYD_EVENT_PUBLISHING_INTERNAL)
            return DISPLAYD_ENGINE_EVENT_IN_FLIGHT;
        if (row->state == DISPLAYD_EVENT_READY_INTERNAL && row->fifo_ticket < best_ticket)
        {
            best_ticket = row->fifo_ticket;
            best_slot = index;
        }
    }
    if (best_slot == DISPLAYD_ENGINE_MAX_EVENTS)
        return DISPLAYD_ENGINE_NO_EVENT;
    impl->events[best_slot].state = DISPLAYD_EVENT_PUBLISHING_INTERNAL;
    publication_out->lease = DisplaydInternalMakeEventLease(impl, best_slot);
    publication_out->event = impl->events[best_slot].event;
    return DisplaydInternalValidate(impl);
}

static DisplaydEngineStatus ResolveEventLease(DisplaydEngineImpl* engine, const DisplaydEventLease* lease,
                                              DisplaydEventRow** row_out)
{
    DisplaydEventRow* row;

    if (row_out != 0)
        *row_out = 0;
    if (engine == 0 || lease == 0 || row_out == 0 || lease->peer_slot >= DISPLAYD_ENGINE_MAX_PEERS ||
        lease->event_slot >= DISPLAYD_ENGINE_MAX_EVENTS || lease->peer_generation == 0 ||
        lease->event_generation == 0 || lease->event_sequence == 0 ||
        !DisplaydEngineInstanceIdentityIsCanonical(&lease->instance))
        return DISPLAYD_ENGINE_INVALID_IDENTITY;
    if (!DisplaydInternalInstanceEqual(&engine->instance, &lease->instance))
        return DISPLAYD_ENGINE_STALE_EVENT;
    row = &engine->events[lease->event_slot];
    if (row->state == DISPLAYD_EVENT_FREE || row->state == DISPLAYD_EVENT_RETIRED ||
        row->peer_slot != lease->peer_slot || row->peer_generation != lease->peer_generation ||
        row->generation != lease->event_generation || row->event.sequence != lease->event_sequence)
        return DISPLAYD_ENGINE_STALE_EVENT;
    *row_out = row;
    return DISPLAYD_ENGINE_OK;
}

DisplaydEngineStatus DisplaydEngineCommitEvent(DisplaydEngine* engine, const DisplaydEventLease* lease)
{
    DisplaydEngineImpl* impl;
    DisplaydEventRow* row;
    DisplaydEngineStatus status;
    uint32_t event_slot;

    if (engine == 0 || lease == 0)
        return DISPLAYD_ENGINE_NULL_ARGUMENT;
    if (DisplaydInternalRangesOverlap(engine, sizeof(*engine), lease, sizeof(*lease)))
        return DISPLAYD_ENGINE_ALIASED_STORAGE;
    impl = DisplaydInternalMutable(engine);
    status = DisplaydInternalValidate(impl);
    if (status != DISPLAYD_ENGINE_OK)
        return status;
    status = ResolveEventLease(impl, lease, &row);
    if (status != DISPLAYD_ENGINE_OK)
        return status;
    if (row->state != DISPLAYD_EVENT_PUBLISHING_INTERNAL)
        return DISPLAYD_ENGINE_STALE_EVENT;
    event_slot = lease->event_slot;
    DisplaydInternalRetireEvent(impl, event_slot);
    return DisplaydInternalValidate(impl);
}

DisplaydEngineStatus DisplaydEngineAbortEvent(DisplaydEngine* engine, const DisplaydEventLease* lease)
{
    DisplaydEngineImpl* impl;
    DisplaydEventRow* row;
    DisplaydEngineStatus status;

    if (engine == 0 || lease == 0)
        return DISPLAYD_ENGINE_NULL_ARGUMENT;
    if (DisplaydInternalRangesOverlap(engine, sizeof(*engine), lease, sizeof(*lease)))
        return DISPLAYD_ENGINE_ALIASED_STORAGE;
    impl = DisplaydInternalMutable(engine);
    status = DisplaydInternalValidate(impl);
    if (status != DISPLAYD_ENGINE_OK)
        return status;
    status = ResolveEventLease(impl, lease, &row);
    if (status != DISPLAYD_ENGINE_OK)
        return status;
    if (row->state != DISPLAYD_EVENT_PUBLISHING_INTERNAL)
        return DISPLAYD_ENGINE_STALE_EVENT;
    row->state = DISPLAYD_EVENT_READY_INTERNAL;
    return DisplaydInternalValidate(impl);
}
