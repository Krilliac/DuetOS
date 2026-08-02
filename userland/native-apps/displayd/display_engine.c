#include "display_engine_internal.h"

#include <stdint.h>

DisplaydEngineImpl* DisplaydInternalMutable(DisplaydEngine* engine)
{
    return (DisplaydEngineImpl*)(void*)engine;
}

const DisplaydEngineImpl* DisplaydInternalReadOnly(const DisplaydEngine* engine)
{
    return (const DisplaydEngineImpl*)(const void*)engine;
}

void DisplaydInternalClear(void* storage, uint32_t bytes)
{
    uint8_t* cursor = (uint8_t*)storage;
    uint32_t index;

    if (cursor == 0)
        return;
    for (index = 0; index < bytes; ++index)
        cursor[index] = 0;
}

uint8_t DisplaydInternalStorageIsZero(const void* storage, uint32_t bytes)
{
    const uint8_t* cursor = (const uint8_t*)storage;
    uint32_t index;

    if (cursor == 0)
        return 0;
    for (index = 0; index < bytes; ++index)
    {
        if (cursor[index] != 0)
            return 0;
    }
    return 1;
}

uint8_t DisplaydInternalRangesOverlap(const void* left, uint64_t left_bytes, const void* right, uint64_t right_bytes)
{
    const uintptr_t left_begin = (uintptr_t)left;
    const uintptr_t right_begin = (uintptr_t)right;
    uintptr_t left_end;
    uintptr_t right_end;

    if (left == 0 || right == 0 || left_bytes == 0 || right_bytes == 0)
        return 0;
    if (left_bytes > (uint64_t)(UINTPTR_MAX - left_begin) || right_bytes > (uint64_t)(UINTPTR_MAX - right_begin))
        return 1;
    left_end = left_begin + (uintptr_t)left_bytes;
    right_end = right_begin + (uintptr_t)right_bytes;
    return (uint8_t)(left_begin < right_end && right_begin < left_end);
}

void DisplaydInternalClearPeerReceipt(DisplaydPeerReceipt* receipt)
{
    DisplaydInternalClear(receipt, receipt != 0 ? (uint32_t)sizeof(*receipt) : 0);
}

void DisplaydInternalClearSurfaceIdentity(DisplaydSurfaceIdentity* identity)
{
    DisplaydInternalClear(identity, identity != 0 ? (uint32_t)sizeof(*identity) : 0);
}

void DisplaydInternalClearRequestReceipt(DisplaydRequestReceipt* receipt)
{
    DisplaydInternalClear(receipt, receipt != 0 ? (uint32_t)sizeof(*receipt) : 0);
}

void DisplaydInternalClearReply(DisplaydReply* reply)
{
    DisplaydInternalClear(reply, reply != 0 ? (uint32_t)sizeof(*reply) : 0);
}

void DisplaydInternalClearApplyResult(DisplaydApplyResult* result)
{
    DisplaydInternalClear(result, result != 0 ? (uint32_t)sizeof(*result) : 0);
}

void DisplaydInternalClearReplyPublication(DisplaydReplyPublication* publication)
{
    DisplaydInternalClear(publication, publication != 0 ? (uint32_t)sizeof(*publication) : 0);
}

void DisplaydInternalClearEventPublication(DisplaydEventPublication* publication)
{
    DisplaydInternalClear(publication, publication != 0 ? (uint32_t)sizeof(*publication) : 0);
}

void DisplaydInternalClearDrainSummary(DisplaydPeerDrainSummary* summary)
{
    DisplaydInternalClear(summary, summary != 0 ? (uint32_t)sizeof(*summary) : 0);
}

const char* DisplaydEngineStatusName(DisplaydEngineStatus status)
{
    static const char* const names[] = {
        "ok",
        "null-argument",
        "aliased-storage",
        "nonzero-storage",
        "already-initialized",
        "not-initialized",
        "corrupt-state",
        "invalid-instance",
        "invalid-identity",
        "invalid-argument",
        "draining",
        "closed",
        "peer-capacity",
        "surface-capacity",
        "request-capacity",
        "event-capacity",
        "generation-exhausted",
        "sequence-exhausted",
        "state-epoch-exhausted",
        "event-sequence-exhausted",
        "peer-exists",
        "peer-not-found",
        "stale-peer",
        "replayed-request",
        "out-of-order-request",
        "request-not-found",
        "no-request",
        "cancel-too-late",
        "invalid-command",
        "surface-not-found",
        "stale-surface",
        "wrong-owner",
        "no-reply",
        "stale-reply",
        "reply-in-flight",
        "no-event",
        "stale-event",
        "event-in-flight",
        "not-drained",
    };
    const uint32_t index = (uint32_t)status;

    if (index >= (uint32_t)(sizeof(names) / sizeof(names[0])))
        return "unknown";
    return names[index];
}

DisplaydPeerReceipt DisplaydInternalMakePeerReceipt(const DisplaydEngineImpl* engine, uint32_t peer_slot)
{
    DisplaydPeerReceipt receipt;

    DisplaydInternalClearPeerReceipt(&receipt);
    if (engine == 0 || peer_slot >= DISPLAYD_ENGINE_MAX_PEERS || engine->peers[peer_slot].state != DISPLAYD_PEER_OPEN)
        return receipt;
    receipt.instance = engine->instance;
    receipt.peer = engine->peers[peer_slot].identity;
    receipt.generation = engine->peers[peer_slot].generation;
    receipt.slot = peer_slot;
    return receipt;
}

DisplaydSurfaceIdentity DisplaydInternalMakeSurfaceIdentity(const DisplaydEngineImpl* engine, uint32_t surface_slot)
{
    DisplaydSurfaceIdentity identity;

    DisplaydInternalClearSurfaceIdentity(&identity);
    if (engine == 0 || surface_slot >= DISPLAYD_ENGINE_MAX_SURFACES ||
        engine->surfaces[surface_slot].state != DISPLAYD_SURFACE_LIVE)
        return identity;
    identity.instance = engine->instance;
    identity.generation = engine->surfaces[surface_slot].generation;
    identity.slot = surface_slot;
    return identity;
}

DisplaydRequestReceipt DisplaydInternalMakeRequestReceipt(const DisplaydEngineImpl* engine, uint32_t request_slot)
{
    DisplaydRequestReceipt receipt;
    const DisplaydRequestRow* row;

    DisplaydInternalClearRequestReceipt(&receipt);
    if (engine == 0 || request_slot >= DISPLAYD_ENGINE_MAX_REQUESTS)
        return receipt;
    row = &engine->requests[request_slot];
    if (row->state == DISPLAYD_REQUEST_FREE || row->state == DISPLAYD_REQUEST_RETIRED)
        return receipt;
    receipt.instance = engine->instance;
    receipt.peer_generation = row->peer_generation;
    receipt.request_generation = row->generation;
    receipt.request_id = row->request.request_id;
    receipt.peer_slot = row->peer_slot;
    receipt.request_slot = request_slot;
    return receipt;
}

DisplaydEventLease DisplaydInternalMakeEventLease(const DisplaydEngineImpl* engine, uint32_t event_slot)
{
    DisplaydEventLease lease;
    const DisplaydEventRow* row;

    DisplaydInternalClear(&lease, (uint32_t)sizeof(lease));
    if (engine == 0 || event_slot >= DISPLAYD_ENGINE_MAX_EVENTS)
        return lease;
    row = &engine->events[event_slot];
    if (row->state != DISPLAYD_EVENT_READY_INTERNAL && row->state != DISPLAYD_EVENT_PUBLISHING_INTERNAL)
        return lease;
    lease.instance = engine->instance;
    lease.peer_generation = row->peer_generation;
    lease.event_generation = row->generation;
    lease.event_sequence = row->event.sequence;
    lease.peer_slot = row->peer_slot;
    lease.event_slot = event_slot;
    return lease;
}

uint64_t DisplaydInternalNextGeneration(const DisplaydEngineImpl* engine, uint64_t generation)
{
    if (engine == 0 || engine->first_slot_generation == 0)
        return 0;
    if (generation == 0)
        return engine->first_slot_generation;
    if (generation == UINT64_MAX)
        return 0;
    return generation + 1;
}

static int32_t FindReusableGeneration(const DisplaydEngineImpl* engine, const uint8_t* states,
                                      const uint64_t* generations, uint32_t stride, uint32_t count, uint8_t free_state,
                                      uint8_t retired_state)
{
    uint32_t index;

    for (index = 0; index < count; ++index)
    {
        const uint8_t state = *(const uint8_t*)((const uint8_t*)states + (uint64_t)index * stride);
        const uint64_t generation = *(const uint64_t*)((const uint8_t*)generations + (uint64_t)index * stride);
        if ((state == free_state || state == retired_state) && DisplaydInternalNextGeneration(engine, generation) != 0)
            return (int32_t)index;
    }
    return -1;
}

int32_t DisplaydInternalFindReusablePeer(const DisplaydEngineImpl* engine)
{
    return FindReusableGeneration(engine, &engine->peers[0].state, &engine->peers[0].generation,
                                  (uint32_t)sizeof(engine->peers[0]), DISPLAYD_ENGINE_MAX_PEERS, DISPLAYD_PEER_FREE,
                                  DISPLAYD_PEER_RETIRED);
}

int32_t DisplaydInternalFindReusableSurface(const DisplaydEngineImpl* engine)
{
    return FindReusableGeneration(engine, &engine->surfaces[0].state, &engine->surfaces[0].generation,
                                  (uint32_t)sizeof(engine->surfaces[0]), DISPLAYD_ENGINE_MAX_SURFACES,
                                  DISPLAYD_SURFACE_FREE, DISPLAYD_SURFACE_RETIRED);
}

int32_t DisplaydInternalFindReusableRequest(const DisplaydEngineImpl* engine)
{
    return FindReusableGeneration(engine, &engine->requests[0].state, &engine->requests[0].generation,
                                  (uint32_t)sizeof(engine->requests[0]), DISPLAYD_ENGINE_MAX_REQUESTS,
                                  DISPLAYD_REQUEST_FREE, DISPLAYD_REQUEST_RETIRED);
}

uint8_t DisplaydInternalAdvanceStateEpoch(DisplaydEngineImpl* engine, uint64_t* epoch_out)
{
    if (epoch_out != 0)
        *epoch_out = 0;
    if (engine == 0 || epoch_out == 0 || engine->state_epoch_exhausted)
        return 0;
    if (engine->state_epoch == UINT64_MAX)
    {
        engine->state_epoch_exhausted = 1;
        return 0;
    }
    ++engine->state_epoch;
    *epoch_out = engine->state_epoch;
    if (engine->state_epoch == UINT64_MAX)
        engine->state_epoch_exhausted = 1;
    return 1;
}

uint8_t DisplaydInternalAllocateRequestTicket(DisplaydEngineImpl* engine, uint64_t* ticket_out)
{
    if (ticket_out != 0)
        *ticket_out = 0;
    if (engine == 0 || ticket_out == 0 || engine->request_fifo_exhausted || engine->next_request_fifo_ticket == 0)
        return 0;
    *ticket_out = engine->next_request_fifo_ticket;
    if (engine->next_request_fifo_ticket == UINT64_MAX)
        engine->request_fifo_exhausted = 1;
    else
        ++engine->next_request_fifo_ticket;
    return 1;
}

void DisplaydInternalRetireRequest(DisplaydEngineImpl* engine, uint32_t request_slot)
{
    DisplaydRequestRow* row;
    uint64_t generation;

    if (engine == 0 || request_slot >= DISPLAYD_ENGINE_MAX_REQUESTS)
        return;
    row = &engine->requests[request_slot];
    if (row->state == DISPLAYD_REQUEST_FREE || row->state == DISPLAYD_REQUEST_RETIRED)
        return;
    if (row->peer_slot < DISPLAYD_ENGINE_MAX_PEERS)
    {
        DisplaydPeerRow* peer = &engine->peers[row->peer_slot];
        if (peer->state == DISPLAYD_PEER_OPEN && peer->generation == row->peer_generation && peer->request_count > 0)
            --peer->request_count;
    }
    if (engine->request_count > 0)
        --engine->request_count;
    generation = row->generation;
    DisplaydInternalClear(row, (uint32_t)sizeof(*row));
    row->generation = generation;
    row->state = DISPLAYD_REQUEST_RETIRED;
}

void DisplaydInternalRetireSurface(DisplaydEngineImpl* engine, uint32_t surface_slot)
{
    DisplaydSurfaceRow* row;
    DisplaydSurfaceIdentity identity;
    uint64_t generation;

    if (engine == 0 || surface_slot >= DISPLAYD_ENGINE_MAX_SURFACES)
        return;
    row = &engine->surfaces[surface_slot];
    if (row->state != DISPLAYD_SURFACE_LIVE)
        return;
    identity = DisplaydInternalMakeSurfaceIdentity(engine, surface_slot);
    DisplaydInternalZRemove(engine, &identity);
    if (DisplaydInternalSurfaceEqual(&engine->focused_surface, &identity))
        DisplaydInternalClearSurfaceIdentity(&engine->focused_surface);
    if (row->peer_slot < DISPLAYD_ENGINE_MAX_PEERS)
    {
        DisplaydPeerRow* peer = &engine->peers[row->peer_slot];
        if (peer->state == DISPLAYD_PEER_OPEN && peer->generation == row->peer_generation && peer->surface_count > 0)
            --peer->surface_count;
    }
    if (engine->surface_count > 0)
        --engine->surface_count;
    generation = row->generation;
    DisplaydInternalClear(row, (uint32_t)sizeof(*row));
    row->generation = generation;
    row->state = DISPLAYD_SURFACE_RETIRED;
}

DisplaydEngineStatus DisplaydEngineInitialize(DisplaydEngine* engine, const DisplaydEngineInstanceIdentity* instance,
                                              uint64_t first_slot_generation, uint32_t display_width,
                                              uint32_t display_height)
{
    DisplaydEngineImpl* impl;

    if (engine == 0 || instance == 0)
        return DISPLAYD_ENGINE_NULL_ARGUMENT;
    if (DisplaydInternalRangesOverlap(engine, sizeof(*engine), instance, sizeof(*instance)))
        return DISPLAYD_ENGINE_ALIASED_STORAGE;
    impl = DisplaydInternalMutable(engine);
    if (impl->magic == DISPLAYD_ENGINE_MAGIC)
        return DISPLAYD_ENGINE_ALREADY_INITIALIZED;
    if (!DisplaydInternalStorageIsZero(engine, (uint32_t)sizeof(*engine)))
        return DISPLAYD_ENGINE_NONZERO_STORAGE;
    if (!DisplaydEngineInstanceIdentityIsCanonical(instance) || first_slot_generation == 0 || display_width == 0 ||
        display_height == 0 || display_width > INT32_MAX || display_height > INT32_MAX)
        return DISPLAYD_ENGINE_INVALID_INSTANCE;
    impl->magic = DISPLAYD_ENGINE_MAGIC;
    impl->instance = *instance;
    impl->first_slot_generation = first_slot_generation;
    impl->state_epoch = 1;
    impl->next_request_fifo_ticket = 1;
    impl->next_event_fifo_ticket = 1;
    impl->state = DISPLAYD_ENGINE_STATE_OPEN;
    impl->display_width = display_width;
    impl->display_height = display_height;
    return DisplaydInternalValidate(impl);
}

DisplaydEngineStatus DisplaydEngineOpenPeer(DisplaydEngine* engine, const DisplaydPeerIdentity* peer,
                                            uint64_t first_request_id, DisplaydPeerReceipt* receipt_out)
{
    DisplaydEngineImpl* impl;
    DisplaydEngineStatus status;
    int32_t slot;
    uint32_t index;
    uint64_t generation;

    if (engine == 0 || peer == 0 || receipt_out == 0)
        return DISPLAYD_ENGINE_NULL_ARGUMENT;
    if (DisplaydInternalRangesOverlap(engine, sizeof(*engine), peer, sizeof(*peer)) ||
        DisplaydInternalRangesOverlap(engine, sizeof(*engine), receipt_out, sizeof(*receipt_out)) ||
        DisplaydInternalRangesOverlap(peer, sizeof(*peer), receipt_out, sizeof(*receipt_out)))
        return DISPLAYD_ENGINE_ALIASED_STORAGE;
    DisplaydInternalClearPeerReceipt(receipt_out);
    impl = DisplaydInternalMutable(engine);
    status = DisplaydInternalValidate(impl);
    if (status != DISPLAYD_ENGINE_OK)
        return status;
    if (impl->state == DISPLAYD_ENGINE_STATE_DRAINING)
        return DISPLAYD_ENGINE_DRAINING;
    if (impl->state == DISPLAYD_ENGINE_STATE_CLOSED)
        return DISPLAYD_ENGINE_CLOSED;
    if (!DisplaydPeerIdentityIsCanonical(peer) || first_request_id == 0)
        return DISPLAYD_ENGINE_INVALID_IDENTITY;
    for (index = 0; index < DISPLAYD_ENGINE_MAX_PEERS; ++index)
    {
        if (impl->peers[index].state == DISPLAYD_PEER_OPEN &&
            DisplaydInternalPeerEqual(&impl->peers[index].identity, peer))
            return DISPLAYD_ENGINE_PEER_EXISTS;
    }
    if (impl->peer_count >= DISPLAYD_ENGINE_MAX_PEERS)
        return DISPLAYD_ENGINE_PEER_CAPACITY;
    slot = DisplaydInternalFindReusablePeer(impl);
    if (slot < 0)
        return DISPLAYD_ENGINE_GENERATION_EXHAUSTED;
    generation = DisplaydInternalNextGeneration(impl, impl->peers[(uint32_t)slot].generation);
    if (generation == 0)
        return DISPLAYD_ENGINE_GENERATION_EXHAUSTED;
    DisplaydInternalClear(&impl->peers[(uint32_t)slot], (uint32_t)sizeof(impl->peers[0]));
    impl->peers[(uint32_t)slot].identity = *peer;
    impl->peers[(uint32_t)slot].generation = generation;
    impl->peers[(uint32_t)slot].next_request_id = first_request_id;
    impl->peers[(uint32_t)slot].next_event_sequence = 1;
    impl->peers[(uint32_t)slot].state = DISPLAYD_PEER_OPEN;
    ++impl->peer_count;
    *receipt_out = DisplaydInternalMakePeerReceipt(impl, (uint32_t)slot);
    return DisplaydInternalValidate(impl);
}

static void AdvanceTeardownEpoch(DisplaydEngineImpl* engine)
{
    if (engine->state_epoch_exhausted)
        return;
    if (engine->state_epoch == UINT64_MAX)
    {
        engine->state_epoch_exhausted = 1;
        return;
    }
    ++engine->state_epoch;
    if (engine->state_epoch == UINT64_MAX)
        engine->state_epoch_exhausted = 1;
}

DisplaydEngineStatus DisplaydEngineClosePeer(DisplaydEngine* engine, const DisplaydPeerReceipt* peer,
                                             DisplaydPeerDrainSummary* summary_out)
{
    DisplaydEngineImpl* impl;
    DisplaydPeerRow* peer_row;
    DisplaydEngineStatus status;
    uint32_t index;
    uint64_t generation;

    if (engine == 0 || peer == 0 || summary_out == 0)
        return DISPLAYD_ENGINE_NULL_ARGUMENT;
    if (DisplaydInternalRangesOverlap(engine, sizeof(*engine), peer, sizeof(*peer)) ||
        DisplaydInternalRangesOverlap(engine, sizeof(*engine), summary_out, sizeof(*summary_out)) ||
        DisplaydInternalRangesOverlap(peer, sizeof(*peer), summary_out, sizeof(*summary_out)))
        return DISPLAYD_ENGINE_ALIASED_STORAGE;
    DisplaydInternalClearDrainSummary(summary_out);
    impl = DisplaydInternalMutable(engine);
    status = DisplaydInternalValidate(impl);
    if (status != DISPLAYD_ENGINE_OK)
        return status;
    if (impl->state == DISPLAYD_ENGINE_STATE_CLOSED)
        return DISPLAYD_ENGINE_CLOSED;
    status = DisplaydInternalResolvePeer(impl, peer, &peer_row);
    if (status != DISPLAYD_ENGINE_OK)
        return status;
    if (!DisplaydInternalSurfaceIsZero(&impl->focused_surface))
    {
        const DisplaydSurfaceRow* focused;
        if (DisplaydInternalResolveSurfaceConst(impl, &impl->focused_surface, &focused) == DISPLAYD_ENGINE_OK &&
            focused->peer_slot == peer->slot && focused->peer_generation == peer->generation)
            summary_out->focus_cleared = 1;
    }
    for (index = 0; index < DISPLAYD_ENGINE_MAX_EVENTS; ++index)
    {
        if (impl->events[index].state != DISPLAYD_EVENT_FREE && impl->events[index].state != DISPLAYD_EVENT_RETIRED &&
            impl->events[index].peer_slot == peer->slot && impl->events[index].peer_generation == peer->generation)
        {
            DisplaydInternalRetireEvent(impl, index);
            ++summary_out->events_retired;
        }
    }
    for (index = 0; index < DISPLAYD_ENGINE_MAX_REQUESTS; ++index)
    {
        if (impl->requests[index].state != DISPLAYD_REQUEST_FREE &&
            impl->requests[index].state != DISPLAYD_REQUEST_RETIRED && impl->requests[index].peer_slot == peer->slot &&
            impl->requests[index].peer_generation == peer->generation)
        {
            DisplaydInternalRetireRequest(impl, index);
            ++summary_out->requests_retired;
        }
    }
    for (index = 0; index < DISPLAYD_ENGINE_MAX_SURFACES; ++index)
    {
        if (impl->surfaces[index].state == DISPLAYD_SURFACE_LIVE && impl->surfaces[index].peer_slot == peer->slot &&
            impl->surfaces[index].peer_generation == peer->generation)
        {
            DisplaydInternalRetireSurface(impl, index);
            ++summary_out->surfaces_destroyed;
        }
    }
    if (summary_out->surfaces_destroyed != 0 || summary_out->focus_cleared)
        AdvanceTeardownEpoch(impl);
    generation = peer_row->generation;
    DisplaydInternalClear(peer_row, (uint32_t)sizeof(*peer_row));
    peer_row->generation = generation;
    peer_row->state = DISPLAYD_PEER_RETIRED;
    if (impl->peer_count > 0)
        --impl->peer_count;
    summary_out->final_state_epoch = impl->state_epoch;
    return DisplaydInternalValidate(impl);
}

DisplaydEngineStatus DisplaydEngineBeginDrain(DisplaydEngine* engine)
{
    DisplaydEngineImpl* impl;
    DisplaydEngineStatus status;
    uint32_t index;

    if (engine == 0)
        return DISPLAYD_ENGINE_NULL_ARGUMENT;
    impl = DisplaydInternalMutable(engine);
    status = DisplaydInternalValidate(impl);
    if (status != DISPLAYD_ENGINE_OK)
        return status;
    if (impl->state == DISPLAYD_ENGINE_STATE_CLOSED || impl->state == DISPLAYD_ENGINE_STATE_DRAINING)
        return DISPLAYD_ENGINE_OK;
    for (index = 0; index < DISPLAYD_ENGINE_MAX_PEERS; ++index)
    {
        if (impl->peers[index].state == DISPLAYD_PEER_OPEN)
        {
            DisplaydPeerReceipt receipt = DisplaydInternalMakePeerReceipt(impl, index);
            DisplaydPeerDrainSummary summary;
            status = DisplaydEngineClosePeer(engine, &receipt, &summary);
            if (status != DISPLAYD_ENGINE_OK)
                return status;
        }
    }
    impl->state = DISPLAYD_ENGINE_STATE_DRAINING;
    return DisplaydInternalValidate(impl);
}

DisplaydEngineStatus DisplaydEngineFinishDrain(DisplaydEngine* engine)
{
    DisplaydEngineImpl* impl;
    DisplaydEngineStatus status;

    if (engine == 0)
        return DISPLAYD_ENGINE_NULL_ARGUMENT;
    impl = DisplaydInternalMutable(engine);
    status = DisplaydInternalValidate(impl);
    if (status != DISPLAYD_ENGINE_OK)
        return status;
    if (impl->state == DISPLAYD_ENGINE_STATE_CLOSED)
        return DISPLAYD_ENGINE_OK;
    if (impl->state != DISPLAYD_ENGINE_STATE_DRAINING)
        return DISPLAYD_ENGINE_NOT_DRAINED;
    impl->state = DISPLAYD_ENGINE_STATE_CLOSED;
    return DisplaydInternalValidate(impl);
}
