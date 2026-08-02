#ifndef DUETOS_DISPLAYD_DISPLAY_ENGINE_H
#define DUETOS_DISPLAYD_DISPLAY_ENGINE_H

/*
 * Allocation-free displayd compositor/broker policy engine.
 *
 * This C11 interface contains no kernel headers, syscalls, handles, callbacks,
 * or wire decoder.  A future service-endpoint adapter must authenticate an
 * exact ProcessKey, CredentialKey, integrity level, and ServiceEndpoint
 * channel generation before opening a peer.  This engine copies those scalar
 * snapshots and never treats request bytes as authority.
 *
 * One displayd event-loop thread owns every call.  The engine is deliberately
 * transport- and framebuffer-independent: it manages bounded surface, focus,
 * z-order, request, reply, and event state without claiming that displayd has
 * acquired DisplayMaster or that the dormant displayd binary is live.
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define DISPLAYD_ENGINE_SERVICE_IDENTITY UINT64_C(0x300)
#define DISPLAYD_ENGINE_MAX_PEERS 16U
#define DISPLAYD_ENGINE_MAX_SURFACES 64U
#define DISPLAYD_ENGINE_MAX_REQUESTS 64U
#define DISPLAYD_ENGINE_MAX_EVENTS 128U
#define DISPLAYD_ENGINE_MAX_EVENTS_PER_PEER 16U
#define DISPLAYD_ENGINE_SERVICE_CAPACITY 64U
#define DISPLAYD_ENGINE_CREDENTIAL_GENERATION_MAX ((UINT64_C(1) << 51U) - 1U)
#define DISPLAYD_ENGINE_CHANNEL_SLOT_CAPACITY 32U
#define DISPLAYD_ENGINE_CHANNEL_GENERATION_MAX ((UINT64_C(1) << 51U) - 1U)
#define DISPLAYD_ENGINE_STORAGE_BYTES 131072U

    typedef enum DisplaydEngineStatus
    {
        DISPLAYD_ENGINE_OK = 0,
        DISPLAYD_ENGINE_NULL_ARGUMENT,
        DISPLAYD_ENGINE_ALIASED_STORAGE,
        DISPLAYD_ENGINE_NONZERO_STORAGE,
        DISPLAYD_ENGINE_ALREADY_INITIALIZED,
        DISPLAYD_ENGINE_NOT_INITIALIZED,
        DISPLAYD_ENGINE_CORRUPT_STATE,
        DISPLAYD_ENGINE_INVALID_INSTANCE,
        DISPLAYD_ENGINE_INVALID_IDENTITY,
        DISPLAYD_ENGINE_INVALID_ARGUMENT,
        DISPLAYD_ENGINE_DRAINING,
        DISPLAYD_ENGINE_CLOSED,
        DISPLAYD_ENGINE_PEER_CAPACITY,
        DISPLAYD_ENGINE_SURFACE_CAPACITY,
        DISPLAYD_ENGINE_REQUEST_CAPACITY,
        DISPLAYD_ENGINE_EVENT_CAPACITY,
        DISPLAYD_ENGINE_GENERATION_EXHAUSTED,
        DISPLAYD_ENGINE_SEQUENCE_EXHAUSTED,
        DISPLAYD_ENGINE_STATE_EPOCH_EXHAUSTED,
        DISPLAYD_ENGINE_EVENT_SEQUENCE_EXHAUSTED,
        DISPLAYD_ENGINE_PEER_EXISTS,
        DISPLAYD_ENGINE_PEER_NOT_FOUND,
        DISPLAYD_ENGINE_STALE_PEER,
        DISPLAYD_ENGINE_REPLAYED_REQUEST,
        DISPLAYD_ENGINE_OUT_OF_ORDER_REQUEST,
        DISPLAYD_ENGINE_REQUEST_NOT_FOUND,
        DISPLAYD_ENGINE_NO_REQUEST,
        DISPLAYD_ENGINE_CANCEL_TOO_LATE,
        DISPLAYD_ENGINE_INVALID_COMMAND,
        DISPLAYD_ENGINE_SURFACE_NOT_FOUND,
        DISPLAYD_ENGINE_STALE_SURFACE,
        DISPLAYD_ENGINE_WRONG_OWNER,
        DISPLAYD_ENGINE_NO_REPLY,
        DISPLAYD_ENGINE_STALE_REPLY,
        DISPLAYD_ENGINE_REPLY_IN_FLIGHT,
        DISPLAYD_ENGINE_NO_EVENT,
        DISPLAYD_ENGINE_STALE_EVENT,
        DISPLAYD_ENGINE_EVENT_IN_FLIGHT,
        DISPLAYD_ENGINE_NOT_DRAINED
    } DisplaydEngineStatus;

    typedef enum DisplaydEngineState
    {
        DISPLAYD_ENGINE_STATE_UNINITIALIZED = 0,
        DISPLAYD_ENGINE_STATE_OPEN,
        DISPLAYD_ENGINE_STATE_DRAINING,
        DISPLAYD_ENGINE_STATE_CLOSED
    } DisplaydEngineState;

    typedef enum DisplaydChannelRole
    {
        DISPLAYD_CHANNEL_ROLE_INITIATOR = 0,
        DISPLAYD_CHANNEL_ROLE_ACCEPTOR = 1,
        DISPLAYD_CHANNEL_ROLE_INVALID = 0xff
    } DisplaydChannelRole;

    typedef struct DisplaydProcessKey
    {
        uint64_t identity;
        uint64_t pid;
    } DisplaydProcessKey;

    typedef struct DisplaydCredentialKey
    {
        uint32_t slot;
        uint32_t reserved32;
        uint64_t generation;
    } DisplaydCredentialKey;

    typedef struct DisplaydChannelIdentity
    {
        uint32_t slot;
        uint8_t role;
        uint8_t reserved8[3];
        uint64_t generation;
        uint64_t epoch;
    } DisplaydChannelIdentity;

    typedef struct DisplaydEngineInstanceIdentity
    {
        uint64_t service_identity;
        uint64_t instance_generation;
        DisplaydProcessKey process;
        uint64_t published_endpoint_epoch;
        uint32_t service_slot;
        uint32_t reserved32;
    } DisplaydEngineInstanceIdentity;

    typedef struct DisplaydPeerIdentity
    {
        DisplaydProcessKey process;
        DisplaydCredentialKey credential;
        DisplaydChannelIdentity channel;
        uint8_t integrity;
        uint8_t reserved8[7];
    } DisplaydPeerIdentity;

    typedef struct DisplaydPeerReceipt
    {
        DisplaydEngineInstanceIdentity instance;
        DisplaydPeerIdentity peer;
        uint64_t generation;
        uint32_t slot;
        uint32_t reserved32;
    } DisplaydPeerReceipt;

    typedef struct DisplaydSurfaceIdentity
    {
        DisplaydEngineInstanceIdentity instance;
        uint64_t generation;
        uint32_t slot;
        uint32_t reserved32;
    } DisplaydSurfaceIdentity;

    typedef struct DisplaydRect
    {
        int32_t x;
        int32_t y;
        uint32_t width;
        uint32_t height;
    } DisplaydRect;

    typedef enum DisplaydCommandType
    {
        DISPLAYD_COMMAND_INVALID = 0,
        DISPLAYD_COMMAND_CREATE_SURFACE,
        DISPLAYD_COMMAND_DESTROY_SURFACE,
        DISPLAYD_COMMAND_SET_BOUNDS,
        DISPLAYD_COMMAND_SET_VISIBLE,
        DISPLAYD_COMMAND_RAISE,
        DISPLAYD_COMMAND_FOCUS
    } DisplaydCommandType;

    /*
     * Unused fields must be zero.  CREATE uses bounds+visible and requires an
     * invalid (all-zero) surface.  SET_BOUNDS uses surface+bounds;
     * SET_VISIBLE uses surface+visible; the remaining commands use surface.
     */
    typedef struct DisplaydRequest
    {
        uint64_t request_id;
        DisplaydSurfaceIdentity surface;
        DisplaydRect bounds;
        uint8_t command;
        uint8_t visible;
        uint8_t reserved8[6];
    } DisplaydRequest;

    typedef struct DisplaydRequestReceipt
    {
        DisplaydEngineInstanceIdentity instance;
        uint64_t peer_generation;
        uint64_t request_generation;
        uint64_t request_id;
        uint32_t peer_slot;
        uint32_t request_slot;
    } DisplaydRequestReceipt;

    typedef enum DisplaydReplyCode
    {
        DISPLAYD_REPLY_SUCCESS = 0,
        DISPLAYD_REPLY_CANCELLED,
        DISPLAYD_REPLY_INVALID_SURFACE,
        DISPLAYD_REPLY_WRONG_OWNER,
        DISPLAYD_REPLY_INVALID_BOUNDS,
        DISPLAYD_REPLY_SURFACE_CAPACITY,
        DISPLAYD_REPLY_EVENT_QUEUE_FULL,
        DISPLAYD_REPLY_NOT_VISIBLE,
        DISPLAYD_REPLY_GENERATION_EXHAUSTED,
        DISPLAYD_REPLY_STATE_EPOCH_EXHAUSTED,
        DISPLAYD_REPLY_EVENT_SEQUENCE_EXHAUSTED,
        DISPLAYD_REPLY_SERVICE_DRAINING,
        DISPLAYD_REPLY_INTERNAL_FAILURE
    } DisplaydReplyCode;

    typedef struct DisplaydReply
    {
        uint64_t request_id;
        uint64_t state_epoch;
        DisplaydSurfaceIdentity surface;
        uint32_t code;
        uint32_t reserved32;
    } DisplaydReply;

    typedef struct DisplaydApplyResult
    {
        DisplaydRequestReceipt receipt;
        DisplaydReply reply;
    } DisplaydApplyResult;

    typedef struct DisplaydReplyLease
    {
        DisplaydRequestReceipt request;
    } DisplaydReplyLease;

    typedef struct DisplaydReplyPublication
    {
        DisplaydReplyLease lease;
        DisplaydReply reply;
    } DisplaydReplyPublication;

    typedef enum DisplaydEventType
    {
        DISPLAYD_EVENT_INVALID = 0,
        DISPLAYD_EVENT_SURFACE_CREATED,
        DISPLAYD_EVENT_SURFACE_DESTROYED,
        DISPLAYD_EVENT_BOUNDS_CHANGED,
        DISPLAYD_EVENT_VISIBILITY_CHANGED,
        DISPLAYD_EVENT_Z_ORDER_CHANGED,
        DISPLAYD_EVENT_FOCUS_GAINED,
        DISPLAYD_EVENT_FOCUS_LOST
    } DisplaydEventType;

    typedef struct DisplaydEvent
    {
        uint64_t sequence;
        uint64_t state_epoch;
        DisplaydSurfaceIdentity surface;
        DisplaydRect bounds;
        uint32_t z_rank;
        uint8_t type;
        uint8_t visible;
        uint8_t reserved8[2];
    } DisplaydEvent;

    typedef struct DisplaydEventLease
    {
        DisplaydEngineInstanceIdentity instance;
        uint64_t peer_generation;
        uint64_t event_generation;
        uint64_t event_sequence;
        uint32_t peer_slot;
        uint32_t event_slot;
    } DisplaydEventLease;

    typedef struct DisplaydEventPublication
    {
        DisplaydEventLease lease;
        DisplaydEvent event;
    } DisplaydEventPublication;

    typedef struct DisplaydPeerDrainSummary
    {
        uint32_t surfaces_destroyed;
        uint32_t requests_retired;
        uint32_t events_retired;
        uint8_t focus_cleared;
        uint8_t reserved8[3];
        uint64_t final_state_epoch;
    } DisplaydPeerDrainSummary;

    typedef enum DisplaydRequestPhase
    {
        DISPLAYD_REQUEST_QUEUED = 1,
        DISPLAYD_REQUEST_REPLY_READY,
        DISPLAYD_REQUEST_REPLY_PUBLISHING
    } DisplaydRequestPhase;

    typedef struct DisplaydEngineSnapshot
    {
        DisplaydEngineInstanceIdentity instance;
        DisplaydSurfaceIdentity focused_surface;
        uint64_t state_epoch;
        uint32_t state;
        uint32_t display_width;
        uint32_t display_height;
        uint32_t peer_count;
        uint32_t surface_count;
        uint32_t request_count;
        uint32_t event_count;
        uint32_t z_count;
        uint32_t retired_peer_slots;
        uint32_t retired_surface_slots;
        uint32_t retired_request_slots;
        uint32_t retired_event_slots;
    } DisplaydEngineSnapshot;

    typedef struct DisplaydPeerSnapshot
    {
        DisplaydPeerReceipt receipt;
        uint64_t next_request_id;
        uint64_t next_event_sequence;
        uint32_t surface_count;
        uint32_t request_count;
        uint32_t event_count;
        uint8_t open;
        uint8_t reserved8[3];
    } DisplaydPeerSnapshot;

    typedef struct DisplaydSurfaceSnapshot
    {
        DisplaydSurfaceIdentity identity;
        DisplaydPeerReceipt owner;
        DisplaydRect bounds;
        uint32_t z_rank;
        uint8_t visible;
        uint8_t focused;
        uint8_t reserved8[2];
    } DisplaydSurfaceSnapshot;

    typedef struct DisplaydRequestSnapshot
    {
        DisplaydRequestReceipt receipt;
        DisplaydRequest request;
        DisplaydReply reply;
        uint64_t fifo_ticket;
        uint8_t phase;
        uint8_t reserved8[7];
    } DisplaydRequestSnapshot;

    /* Opaque, caller-owned fixed storage. Static/BSS allocation is required. */
    typedef union DisplaydEngine
    {
        uint64_t alignment;
        uint8_t bytes[DISPLAYD_ENGINE_STORAGE_BYTES];
    } DisplaydEngine;

    /* [displayd event-loop thread; one-shot, allocation/callback/wait free] */
    DisplaydEngineStatus DisplaydEngineInitialize(DisplaydEngine* engine,
                                                  const DisplaydEngineInstanceIdentity* instance,
                                                  uint64_t first_slot_generation, uint32_t display_width,
                                                  uint32_t display_height);

    /*
     * OpenPeer is called only after the future endpoint adapter authenticates
     * and snapshots every peer field.  The engine neither resolves nor retains
     * a kernel object.  first_request_id must be nonzero.
     */
    DisplaydEngineStatus DisplaydEngineOpenPeer(DisplaydEngine* engine, const DisplaydPeerIdentity* peer,
                                                uint64_t first_request_id, DisplaydPeerReceipt* receipt_out);
    DisplaydEngineStatus DisplaydEngineClosePeer(DisplaydEngine* engine, const DisplaydPeerReceipt* peer,
                                                 DisplaydPeerDrainSummary* summary_out);

    /*
     * Request ownership transfers only when Submit returns OK.  Output
     * storage must not overlap the engine or any input object; detected
     * overlap returns ALIASED_STORAGE before either object is modified.
     */
    DisplaydEngineStatus DisplaydEngineSubmit(DisplaydEngine* engine, const DisplaydPeerReceipt* peer,
                                              const DisplaydRequest* request, DisplaydRequestReceipt* receipt_out);
    DisplaydEngineStatus DisplaydEngineCancel(DisplaydEngine* engine, const DisplaydPeerReceipt* peer,
                                              uint64_t request_id, DisplaydRequestReceipt* receipt_out);
    DisplaydEngineStatus DisplaydEngineApplyNext(DisplaydEngine* engine, DisplaydApplyResult* result_out);

    /* Reply/event publication is reserve -> external enqueue -> commit/abort. */
    DisplaydEngineStatus DisplaydEngineGetNextReply(DisplaydEngine* engine, const DisplaydPeerReceipt* peer,
                                                    DisplaydReplyPublication* publication_out);
    DisplaydEngineStatus DisplaydEngineCommitReply(DisplaydEngine* engine, const DisplaydReplyLease* lease);
    DisplaydEngineStatus DisplaydEngineAbortReply(DisplaydEngine* engine, const DisplaydReplyLease* lease);
    DisplaydEngineStatus DisplaydEngineGetNextEvent(DisplaydEngine* engine, const DisplaydPeerReceipt* peer,
                                                    DisplaydEventPublication* publication_out);
    DisplaydEngineStatus DisplaydEngineCommitEvent(DisplaydEngine* engine, const DisplaydEventLease* lease);
    DisplaydEngineStatus DisplaydEngineAbortEvent(DisplaydEngine* engine, const DisplaydEventLease* lease);

    /* Terminal and idempotent drain. No peer can be reopened afterward. */
    DisplaydEngineStatus DisplaydEngineBeginDrain(DisplaydEngine* engine);
    DisplaydEngineStatus DisplaydEngineFinishDrain(DisplaydEngine* engine);

    /* [displayd event-loop thread or externally serialized diagnostics] */
    DisplaydEngineStatus DisplaydEngineDescribe(const DisplaydEngine* engine, DisplaydEngineSnapshot* snapshot_out);
    DisplaydEngineStatus DisplaydEngineInspectPeer(const DisplaydEngine* engine, const DisplaydPeerReceipt* peer,
                                                   DisplaydPeerSnapshot* snapshot_out);
    DisplaydEngineStatus DisplaydEngineInspectSurface(const DisplaydEngine* engine,
                                                      const DisplaydSurfaceIdentity* surface,
                                                      DisplaydSurfaceSnapshot* snapshot_out);
    DisplaydEngineStatus DisplaydEngineInspectRequest(const DisplaydEngine* engine,
                                                      const DisplaydRequestReceipt* request,
                                                      DisplaydRequestSnapshot* snapshot_out);

    uint8_t DisplaydEngineInstanceIdentityIsCanonical(const DisplaydEngineInstanceIdentity* identity);
    uint8_t DisplaydPeerIdentityIsCanonical(const DisplaydPeerIdentity* identity);
    uint8_t DisplaydPeerReceiptIsCanonical(const DisplaydPeerReceipt* receipt);
    uint8_t DisplaydSurfaceIdentityIsCanonical(const DisplaydSurfaceIdentity* identity);
    const char* DisplaydEngineStatusName(DisplaydEngineStatus status);

#ifdef __cplusplus
}
#endif

#endif
