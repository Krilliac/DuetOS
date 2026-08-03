#ifndef DUETOS_EXECD_WORKER_H
#define DUETOS_EXECD_WORKER_H

/*
 * Allocation-free execd request coordinator.
 *
 * This C11 interface contains no kernel headers, handles, callbacks, or
 * authority-bearing pointers.  The service endpoint adapter authenticates
 * peers, validates ExecdProtocol v1, commits the endpoint request ledger, and
 * retains imported/exported objects before passing trusted scalar snapshots
 * here.  The engine schedules immutable work and returns explicit cleanup
 * records; the adapter performs releases only after this call returns.
 *
 * One execd dispatcher thread owns every mutating call. Parse workers may keep
 * the immutable ExecdWorkerWorkItem by value and return it to that dispatcher.
 * This object is non-hot-reloadable: restart requires fresh zeroed storage and
 * a strictly new supervised service-instance identity.
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define EXECD_WORKER_MAX_PEERS 16U
#define EXECD_WORKER_MAX_REQUESTS 32U
#define EXECD_WORKER_CLEANUP_CAPACITY EXECD_WORKER_MAX_REQUESTS
#define EXECD_WORKER_STORAGE_BYTES 32768U
#define EXECD_WORKER_SOURCE_POLICY_V1 1U
#define EXECD_WORKER_LOAD_PLAN_POLICY_V1 2U
#define EXECD_WORKER_TRANSFER_REF_MAX UINT64_C(0x7fffffff)
#define EXECD_WORKER_SOURCE_MAX_BYTES (UINT64_C(1024) * 1024U * 1024U)
#define EXECD_WORKER_LOAD_PLAN_MIN_BYTES 64U
#define EXECD_WORKER_LOAD_PLAN_MAX_BYTES 18496U

    typedef enum ExecdWorkerStatus
    {
        EXECD_WORKER_OK = 0,
        EXECD_WORKER_NULL_ARGUMENT,
        EXECD_WORKER_ALIASED_STORAGE,
        EXECD_WORKER_NONZERO_STORAGE,
        EXECD_WORKER_ALREADY_INITIALIZED,
        EXECD_WORKER_NOT_INITIALIZED,
        EXECD_WORKER_CORRUPT_STATE,
        EXECD_WORKER_INVALID_IDENTITY,
        EXECD_WORKER_INVALID_ARGUMENT,
        EXECD_WORKER_CLOSED,
        EXECD_WORKER_DRAINING,
        EXECD_WORKER_BUSY,
        EXECD_WORKER_PEER_CAPACITY,
        EXECD_WORKER_REQUEST_CAPACITY,
        EXECD_WORKER_GENERATION_EXHAUSTED,
        EXECD_WORKER_SEQUENCE_EXHAUSTED,
        EXECD_WORKER_PEER_EXISTS,
        EXECD_WORKER_PEER_NOT_FOUND,
        EXECD_WORKER_STALE_PEER,
        EXECD_WORKER_PEER_CLOSING,
        EXECD_WORKER_REPLAYED_REQUEST,
        EXECD_WORKER_OUT_OF_ORDER_REQUEST,
        EXECD_WORKER_REQUEST_NOT_FOUND,
        EXECD_WORKER_NO_WORK,
        EXECD_WORKER_STALE_WORK,
        EXECD_WORKER_INVALID_COMPLETION,
        EXECD_WORKER_NO_REPLY,
        EXECD_WORKER_STALE_REPLY,
        EXECD_WORKER_REPLY_IN_FLIGHT,
        EXECD_WORKER_CANCEL_TOO_LATE
    } ExecdWorkerStatus;

    typedef enum ExecdWorkerState
    {
        EXECD_WORKER_STATE_UNINITIALIZED = 0,
        EXECD_WORKER_STATE_OPEN,
        EXECD_WORKER_STATE_DRAINING,
        EXECD_WORKER_STATE_CLOSED
    } ExecdWorkerState;

    typedef enum ExecdWorkerFormatHint
    {
        EXECD_WORKER_FORMAT_AUTO = 0,
        EXECD_WORKER_FORMAT_PE32_PLUS = 1,
        EXECD_WORKER_FORMAT_PE32 = 2,
        EXECD_WORKER_FORMAT_ELF64 = 3
    } ExecdWorkerFormatHint;

    typedef enum ExecdWorkerReplyStatus
    {
        EXECD_WORKER_REPLY_SUCCESS = 0,
        EXECD_WORKER_REPLY_INVALID_IMAGE = 1,
        EXECD_WORKER_REPLY_UNSUPPORTED_FORMAT = 2,
        EXECD_WORKER_REPLY_POLICY_REJECTED = 3,
        EXECD_WORKER_REPLY_CANCELLED = 4,
        EXECD_WORKER_REPLY_SERVICE_FAILURE = 5
    } ExecdWorkerReplyStatus;

    typedef enum ExecdWorkerPlanDisposition
    {
        EXECD_WORKER_PLAN_NONE = 0,
        EXECD_WORKER_PLAN_PUBLISHED,
        EXECD_WORKER_PLAN_DISCARD
    } ExecdWorkerPlanDisposition;

    typedef struct ExecdWorkerProcessKey
    {
        uint64_t identity;
        uint64_t pid;
    } ExecdWorkerProcessKey;

    typedef struct ExecdWorkerCredentialKey
    {
        uint32_t slot;
        uint32_t reserved32;
        uint64_t generation;
    } ExecdWorkerCredentialKey;

    typedef struct ExecdWorkerInstanceIdentity
    {
        uint64_t service_identity;
        uint64_t instance_generation;
        ExecdWorkerProcessKey process;
        uint64_t published_endpoint_epoch;
        uint32_t service_slot;
        uint32_t reserved32;
    } ExecdWorkerInstanceIdentity;

    typedef struct ExecdWorkerPeerIdentity
    {
        ExecdWorkerProcessKey process;
        ExecdWorkerCredentialKey credential;
        uint64_t channel_epoch;
    } ExecdWorkerPeerIdentity;

    typedef struct ExecdWorkerPeerReceipt
    {
        ExecdWorkerInstanceIdentity instance;
        ExecdWorkerPeerIdentity peer;
        uint64_t peer_generation;
        uint32_t peer_slot;
        uint32_t reserved32;
    } ExecdWorkerPeerReceipt;

    typedef struct ExecdWorkerSourceAuthority
    {
        uint64_t transfer_reference;
        uint64_t object_identity;
        uint64_t object_bytes;
        uint32_t immutable_policy_id;
        uint8_t sealed;
        uint8_t read_only;
        uint8_t reserved8[2];
        uint8_t source_hash[32];
    } ExecdWorkerSourceAuthority;

    typedef struct ExecdWorkerPlanAuthority
    {
        uint64_t transfer_reference;
        uint64_t object_identity;
        uint64_t object_bytes;
        uint32_t immutable_policy_id;
        uint8_t sealed;
        uint8_t read_only;
        uint8_t reserved8[2];
        uint8_t object_hash[32];
        uint8_t source_hash[32];
    } ExecdWorkerPlanAuthority;

    typedef struct ExecdWorkerParseRequest
    {
        uint64_t request_id;
        ExecdWorkerSourceAuthority source;
        uint32_t flags;
        uint32_t dependency_count;
        uint16_t format_hint;
        uint16_t reserved16;
        uint32_t reserved32;
    } ExecdWorkerParseRequest;

    typedef struct ExecdWorkerRequestReceipt
    {
        ExecdWorkerPeerReceipt peer;
        uint64_t request_generation;
        uint64_t request_id;
        uint32_t request_slot;
        uint32_t reserved32;
    } ExecdWorkerRequestReceipt;

    typedef struct ExecdWorkerWorkLease
    {
        ExecdWorkerRequestReceipt request;
    } ExecdWorkerWorkLease;

    typedef struct ExecdWorkerWorkItem
    {
        ExecdWorkerWorkLease lease;
        ExecdWorkerParseRequest request;
    } ExecdWorkerWorkItem;

    typedef struct ExecdWorkerCompletion
    {
        uint32_t reply_status;
        uint32_t reserved32;
        ExecdWorkerPlanAuthority plan;
    } ExecdWorkerCompletion;

    typedef struct ExecdWorkerReply
    {
        uint64_t request_id;
        uint32_t status;
        uint32_t immutable_policy_id;
        uint64_t load_plan_object_ref;
        uint8_t source_hash[32];
    } ExecdWorkerReply;

    typedef struct ExecdWorkerReplyLease
    {
        ExecdWorkerRequestReceipt request;
    } ExecdWorkerReplyLease;

    typedef struct ExecdWorkerReplyPublication
    {
        ExecdWorkerReplyLease lease;
        ExecdWorkerReply reply;
        ExecdWorkerPlanAuthority plan;
    } ExecdWorkerReplyPublication;

    /*
     * release_source_import drops the request-local imported SourceImage.
     * plan_disposition=PUBLISHED drops only request-local producer ownership;
     * the endpoint transfer table keeps its own reference. DISCARD requires
     * revoking/unpublishing the plan export before dropping producer ownership.
     */
    typedef struct ExecdWorkerCleanupRecord
    {
        ExecdWorkerRequestReceipt request;
        uint64_t source_transfer_reference;
        uint64_t source_object_identity;
        uint64_t plan_transfer_reference;
        uint64_t plan_object_identity;
        uint8_t release_source_import;
        uint8_t plan_disposition;
        uint8_t reserved8[6];
    } ExecdWorkerCleanupRecord;

    typedef struct ExecdWorkerCleanupBatch
    {
        uint32_t count;
        uint32_t reserved32;
        ExecdWorkerCleanupRecord records[EXECD_WORKER_CLEANUP_CAPACITY];
    } ExecdWorkerCleanupBatch;

    typedef struct ExecdWorkerCancelResult
    {
        ExecdWorkerStatus status;
        uint8_t cancellation_requested;
        uint8_t reply_ready;
        uint8_t reserved8[2];
        ExecdWorkerCleanupRecord cleanup;
    } ExecdWorkerCancelResult;

    typedef struct ExecdWorkerCompleteResult
    {
        ExecdWorkerStatus status;
        uint8_t reply_ready;
        uint8_t request_discarded;
        uint8_t reserved8[2];
        ExecdWorkerCleanupRecord cleanup;
    } ExecdWorkerCompleteResult;

    typedef enum ExecdWorkerRequestPhase
    {
        EXECD_WORKER_REQUEST_QUEUED = 1,
        EXECD_WORKER_REQUEST_RUNNING,
        EXECD_WORKER_REQUEST_REPLY_READY,
        EXECD_WORKER_REQUEST_REPLY_PUBLISHING
    } ExecdWorkerRequestPhase;

    typedef struct ExecdWorkerSnapshot
    {
        ExecdWorkerInstanceIdentity instance;
        uint32_t state;
        uint32_t peer_count;
        uint32_t request_count;
        uint32_t queued_count;
        uint32_t running_count;
        uint32_t reply_count;
        uint32_t retired_peer_slots;
        uint32_t retired_request_slots;
    } ExecdWorkerSnapshot;

    typedef struct ExecdWorkerRequestSnapshot
    {
        ExecdWorkerRequestReceipt receipt;
        uint32_t phase;
        uint8_t cancel_requested;
        uint8_t source_retained;
        uint8_t plan_retained;
        uint8_t reserved8;
    } ExecdWorkerRequestSnapshot;

    /* Opaque, caller-owned fixed storage. Static/BSS allocation is recommended. */
    typedef union ExecdWorker
    {
        uint64_t alignment;
        uint8_t bytes[EXECD_WORKER_STORAGE_BYTES];
    } ExecdWorker;

    /* [execd dispatcher thread; one-shot, allocation/callback/wait free] */
    ExecdWorkerStatus ExecdWorkerInitialize(ExecdWorker* worker, const ExecdWorkerInstanceIdentity* instance,
                                            uint64_t first_slot_generation);

    /*
     * [execd dispatcher thread]
     * The adapter calls OpenPeer only after accepting an authenticated endpoint
     * and snapshots its exact ProcessKey, CredentialKey, and ChannelEpoch.
     */
    ExecdWorkerStatus ExecdWorkerOpenPeer(ExecdWorker* worker, const ExecdWorkerPeerIdentity* peer,
                                          uint64_t first_request_id, ExecdWorkerPeerReceipt* receipt_out);
    ExecdWorkerStatus ExecdWorkerClosePeer(ExecdWorker* worker, const ExecdWorkerPeerReceipt* receipt,
                                           ExecdWorkerCleanupBatch* cleanup_out);

    /*
     * [execd dispatcher thread]
     * Submit is valid only after ExecdProtocol and ObjectTransfer validation
     * and the endpoint's exact incoming request Commit have succeeded.
     * EXECD_WORKER_OK transfers the request-local imported SourceImage release
     * duty to this engine. Every other result leaves that duty with the caller.
     */
    ExecdWorkerStatus ExecdWorkerSubmit(ExecdWorker* worker, const ExecdWorkerPeerReceipt* peer,
                                        const ExecdWorkerParseRequest* request, ExecdWorkerRequestReceipt* receipt_out);
    ExecdWorkerStatus ExecdWorkerClaimNext(ExecdWorker* worker, ExecdWorkerWorkItem* work_out);
    ExecdWorkerStatus ExecdWorkerCheckCancellation(const ExecdWorker* worker, const ExecdWorkerWorkLease* lease,
                                                   uint8_t* cancellation_out);
    ExecdWorkerCancelResult ExecdWorkerCancel(ExecdWorker* worker, const ExecdWorkerPeerReceipt* peer,
                                              uint64_t request_id);
    /*
     * A successful completion transfers producer ownership of its LoadPlan to
     * this engine only when Complete returns EXECD_WORKER_OK. On every rejected
     * completion the caller still owns the supplied plan. Cleanup records never
     * execute releases; the adapter applies them after this call returns.
     */
    ExecdWorkerCompleteResult ExecdWorkerComplete(ExecdWorker* worker, const ExecdWorkerWorkLease* lease,
                                                  const ExecdWorkerCompletion* completion);

    /*
     * [execd dispatcher thread]
     * GetNextReply reserves one reply publication. Commit follows successful
     * transport enqueue. Abort returns an unsent reply to the ready queue. The
     * trusted adapter must resolve the returned lease before any other engine
     * mutation, so external enqueue and plan-ownership transfer are one
     * serialized transaction.
     */
    ExecdWorkerStatus ExecdWorkerGetNextReply(ExecdWorker* worker, ExecdWorkerReplyPublication* reply_out);
    ExecdWorkerStatus ExecdWorkerCommitReply(ExecdWorker* worker, const ExecdWorkerReplyLease* lease,
                                             ExecdWorkerCleanupRecord* cleanup_out);
    ExecdWorkerStatus ExecdWorkerAbortReply(ExecdWorker* worker, const ExecdWorkerReplyLease* lease);

    /* [execd dispatcher thread; terminal, idempotent BeginDrain] */
    ExecdWorkerStatus ExecdWorkerBeginDrain(ExecdWorker* worker, ExecdWorkerCleanupBatch* cleanup_out);
    ExecdWorkerStatus ExecdWorkerFinishDrain(ExecdWorker* worker);

    /* [execd dispatcher thread or externally serialized diagnostic reader] */
    ExecdWorkerStatus ExecdWorkerDescribe(const ExecdWorker* worker, ExecdWorkerSnapshot* snapshot_out);
    ExecdWorkerStatus ExecdWorkerInspectRequest(const ExecdWorker* worker, const ExecdWorkerRequestReceipt* receipt,
                                                ExecdWorkerRequestSnapshot* snapshot_out);

    uint8_t ExecdWorkerInstanceIdentityIsCanonical(const ExecdWorkerInstanceIdentity* identity);
    uint8_t ExecdWorkerPeerIdentityIsCanonical(const ExecdWorkerPeerIdentity* identity);
    const char* ExecdWorkerStatusName(ExecdWorkerStatus status);

#ifdef __cplusplus
}
#endif

#endif
