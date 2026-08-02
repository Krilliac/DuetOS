#ifndef DUETOS_DISPLAYD_DISPLAY_ENGINE_INTERNAL_H
#define DUETOS_DISPLAYD_DISPLAY_ENGINE_INTERNAL_H

#include "display_engine.h"

#define DISPLAYD_ENGINE_MAGIC UINT64_C(0x4453504c59454e31)
#define DISPLAYD_ENGINE_MAX_EVENTS_PER_MUTATION 4U

typedef enum DisplaydPeerStateInternal
{
    DISPLAYD_PEER_FREE = 0,
    DISPLAYD_PEER_OPEN,
    DISPLAYD_PEER_RETIRED
} DisplaydPeerStateInternal;

typedef enum DisplaydSurfaceStateInternal
{
    DISPLAYD_SURFACE_FREE = 0,
    DISPLAYD_SURFACE_LIVE,
    DISPLAYD_SURFACE_RETIRED
} DisplaydSurfaceStateInternal;

typedef enum DisplaydRequestStateInternal
{
    DISPLAYD_REQUEST_FREE = 0,
    DISPLAYD_REQUEST_QUEUED_INTERNAL,
    DISPLAYD_REQUEST_REPLY_READY_INTERNAL,
    DISPLAYD_REQUEST_REPLY_PUBLISHING_INTERNAL,
    DISPLAYD_REQUEST_RETIRED
} DisplaydRequestStateInternal;

typedef enum DisplaydEventStateInternal
{
    DISPLAYD_EVENT_FREE = 0,
    DISPLAYD_EVENT_READY_INTERNAL,
    DISPLAYD_EVENT_PUBLISHING_INTERNAL,
    DISPLAYD_EVENT_RETIRED
} DisplaydEventStateInternal;

typedef struct DisplaydPeerRow
{
    DisplaydPeerIdentity identity;
    uint64_t generation;
    uint64_t next_request_id;
    uint64_t next_event_sequence;
    uint32_t surface_count;
    uint32_t request_count;
    uint32_t event_count;
    uint8_t state;
    uint8_t request_sequence_exhausted;
    uint8_t event_sequence_exhausted;
    uint8_t reserved8;
} DisplaydPeerRow;

typedef struct DisplaydSurfaceRow
{
    DisplaydRect bounds;
    uint64_t generation;
    uint64_t peer_generation;
    uint32_t peer_slot;
    uint8_t state;
    uint8_t visible;
    uint8_t reserved8[2];
} DisplaydSurfaceRow;

typedef struct DisplaydRequestRow
{
    DisplaydRequest request;
    DisplaydReply reply;
    uint64_t generation;
    uint64_t peer_generation;
    uint64_t fifo_ticket;
    uint32_t peer_slot;
    uint8_t state;
    uint8_t reserved8[3];
} DisplaydRequestRow;

typedef struct DisplaydEventRow
{
    DisplaydEvent event;
    uint64_t generation;
    uint64_t peer_generation;
    uint64_t fifo_ticket;
    uint32_t peer_slot;
    uint8_t state;
    uint8_t reserved8[3];
} DisplaydEventRow;

typedef struct DisplaydEngineImpl
{
    uint64_t magic;
    DisplaydEngineInstanceIdentity instance;
    DisplaydSurfaceIdentity focused_surface;
    uint64_t first_slot_generation;
    uint64_t state_epoch;
    uint64_t next_request_fifo_ticket;
    uint64_t next_event_fifo_ticket;
    uint32_t state;
    uint32_t display_width;
    uint32_t display_height;
    uint32_t peer_count;
    uint32_t surface_count;
    uint32_t request_count;
    uint32_t event_count;
    uint32_t z_count;
    uint8_t state_epoch_exhausted;
    uint8_t request_fifo_exhausted;
    uint8_t event_fifo_exhausted;
    uint8_t reserved8;
    DisplaydPeerRow peers[DISPLAYD_ENGINE_MAX_PEERS];
    DisplaydSurfaceRow surfaces[DISPLAYD_ENGINE_MAX_SURFACES];
    DisplaydRequestRow requests[DISPLAYD_ENGINE_MAX_REQUESTS];
    DisplaydEventRow events[DISPLAYD_ENGINE_MAX_EVENTS];
    DisplaydSurfaceIdentity z_order[DISPLAYD_ENGINE_MAX_SURFACES];
} DisplaydEngineImpl;

#if defined(__cplusplus)
static_assert(sizeof(DisplaydEngineImpl) <= DISPLAYD_ENGINE_STORAGE_BYTES,
              "displayd engine fixed storage is too small");
#else
_Static_assert(sizeof(DisplaydEngineImpl) <= DISPLAYD_ENGINE_STORAGE_BYTES,
               "displayd engine fixed storage is too small");
#endif

typedef struct DisplaydEventDraft
{
    uint32_t peer_slot;
    uint64_t peer_generation;
    DisplaydEvent event;
} DisplaydEventDraft;

typedef struct DisplaydEventReservation
{
    uint32_t count;
    uint32_t slots[DISPLAYD_ENGINE_MAX_EVENTS_PER_MUTATION];
    uint64_t generations[DISPLAYD_ENGINE_MAX_EVENTS_PER_MUTATION];
} DisplaydEventReservation;

#ifdef __cplusplus
extern "C"
{
#endif

    DisplaydEngineImpl* DisplaydInternalMutable(DisplaydEngine* engine);
    const DisplaydEngineImpl* DisplaydInternalReadOnly(const DisplaydEngine* engine);
    void DisplaydInternalClear(void* storage, uint32_t bytes);
    uint8_t DisplaydInternalStorageIsZero(const void* storage, uint32_t bytes);
    uint8_t DisplaydInternalRangesOverlap(const void* left, uint64_t left_bytes, const void* right,
                                          uint64_t right_bytes);
    uint8_t DisplaydInternalInstanceEqual(const DisplaydEngineInstanceIdentity* left,
                                          const DisplaydEngineInstanceIdentity* right);
    uint8_t DisplaydInternalPeerEqual(const DisplaydPeerIdentity* left, const DisplaydPeerIdentity* right);
    uint8_t DisplaydInternalSurfaceEqual(const DisplaydSurfaceIdentity* left, const DisplaydSurfaceIdentity* right);
    uint8_t DisplaydInternalSurfaceIsZero(const DisplaydSurfaceIdentity* surface);
    uint8_t DisplaydInternalRectIsZero(const DisplaydRect* bounds);
    uint8_t DisplaydInternalRectIsValid(const DisplaydEngineImpl* engine, const DisplaydRect* bounds);
    DisplaydEngineStatus DisplaydInternalValidate(const DisplaydEngineImpl* engine);

    void DisplaydInternalClearPeerReceipt(DisplaydPeerReceipt* receipt);
    void DisplaydInternalClearSurfaceIdentity(DisplaydSurfaceIdentity* identity);
    void DisplaydInternalClearRequestReceipt(DisplaydRequestReceipt* receipt);
    void DisplaydInternalClearReply(DisplaydReply* reply);
    void DisplaydInternalClearApplyResult(DisplaydApplyResult* result);
    void DisplaydInternalClearReplyPublication(DisplaydReplyPublication* publication);
    void DisplaydInternalClearEventPublication(DisplaydEventPublication* publication);
    void DisplaydInternalClearDrainSummary(DisplaydPeerDrainSummary* summary);

    DisplaydPeerReceipt DisplaydInternalMakePeerReceipt(const DisplaydEngineImpl* engine, uint32_t peer_slot);
    DisplaydSurfaceIdentity DisplaydInternalMakeSurfaceIdentity(const DisplaydEngineImpl* engine,
                                                                uint32_t surface_slot);
    DisplaydRequestReceipt DisplaydInternalMakeRequestReceipt(const DisplaydEngineImpl* engine, uint32_t request_slot);
    DisplaydEventLease DisplaydInternalMakeEventLease(const DisplaydEngineImpl* engine, uint32_t event_slot);

    DisplaydEngineStatus DisplaydInternalResolvePeer(DisplaydEngineImpl* engine, const DisplaydPeerReceipt* receipt,
                                                     DisplaydPeerRow** peer_out);
    DisplaydEngineStatus DisplaydInternalResolvePeerConst(const DisplaydEngineImpl* engine,
                                                          const DisplaydPeerReceipt* receipt,
                                                          const DisplaydPeerRow** peer_out);
    DisplaydEngineStatus DisplaydInternalResolveSurface(DisplaydEngineImpl* engine,
                                                        const DisplaydSurfaceIdentity* identity,
                                                        DisplaydSurfaceRow** surface_out);
    DisplaydEngineStatus DisplaydInternalResolveSurfaceConst(const DisplaydEngineImpl* engine,
                                                             const DisplaydSurfaceIdentity* identity,
                                                             const DisplaydSurfaceRow** surface_out);
    DisplaydEngineStatus DisplaydInternalResolveRequest(DisplaydEngineImpl* engine,
                                                        const DisplaydRequestReceipt* receipt,
                                                        DisplaydRequestRow** request_out);
    DisplaydEngineStatus DisplaydInternalResolveRequestConst(const DisplaydEngineImpl* engine,
                                                             const DisplaydRequestReceipt* receipt,
                                                             const DisplaydRequestRow** request_out);
    int32_t DisplaydInternalFindRequest(const DisplaydEngineImpl* engine, uint32_t peer_slot, uint64_t peer_generation,
                                        uint64_t request_id);

    int32_t DisplaydInternalFindReusablePeer(const DisplaydEngineImpl* engine);
    int32_t DisplaydInternalFindReusableSurface(const DisplaydEngineImpl* engine);
    int32_t DisplaydInternalFindReusableRequest(const DisplaydEngineImpl* engine);
    uint64_t DisplaydInternalNextGeneration(const DisplaydEngineImpl* engine, uint64_t generation);
    uint8_t DisplaydInternalAdvanceStateEpoch(DisplaydEngineImpl* engine, uint64_t* epoch_out);
    uint8_t DisplaydInternalAllocateRequestTicket(DisplaydEngineImpl* engine, uint64_t* ticket_out);

    int32_t DisplaydInternalZRank(const DisplaydEngineImpl* engine, const DisplaydSurfaceIdentity* surface);
    void DisplaydInternalZRemove(DisplaydEngineImpl* engine, const DisplaydSurfaceIdentity* surface);
    void DisplaydInternalZRaise(DisplaydEngineImpl* engine, const DisplaydSurfaceIdentity* surface);
    DisplaydSurfaceIdentity DisplaydInternalTopVisibleExcept(const DisplaydEngineImpl* engine,
                                                             const DisplaydSurfaceIdentity* excluded);

    DisplaydEngineStatus DisplaydInternalReserveEvents(const DisplaydEngineImpl* engine,
                                                       const DisplaydEventDraft* drafts, uint32_t count,
                                                       DisplaydEventReservation* reservation_out);
    void DisplaydInternalPublishEvents(DisplaydEngineImpl* engine, const DisplaydEventDraft* drafts,
                                       const DisplaydEventReservation* reservation);
    void DisplaydInternalRetireEvent(DisplaydEngineImpl* engine, uint32_t event_slot);
    void DisplaydInternalRetireRequest(DisplaydEngineImpl* engine, uint32_t request_slot);
    void DisplaydInternalRetireSurface(DisplaydEngineImpl* engine, uint32_t surface_slot);

#ifdef __cplusplus
}
#endif

#endif
