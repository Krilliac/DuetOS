#ifndef DUETOS_EXECD_WORKER_INTERNAL_H
#define DUETOS_EXECD_WORKER_INTERNAL_H

#include "worker.h"

#define EXECD_WORKER_MAGIC UINT64_C(0x4558454357524b31)

typedef enum ExecdWorkerPeerStateInternal
{
    EXECD_WORKER_PEER_STATE_FREE = 0,
    EXECD_WORKER_PEER_STATE_OPEN,
    EXECD_WORKER_PEER_STATE_CLOSING,
    EXECD_WORKER_PEER_STATE_RETIRED
} ExecdWorkerPeerStateInternal;

typedef enum ExecdWorkerRequestStateInternal
{
    EXECD_WORKER_SLOT_FREE = 0,
    EXECD_WORKER_SLOT_QUEUED,
    EXECD_WORKER_SLOT_RUNNING,
    EXECD_WORKER_SLOT_REPLY_READY,
    EXECD_WORKER_SLOT_REPLY_PUBLISHING,
    EXECD_WORKER_SLOT_RETIRED
} ExecdWorkerRequestStateInternal;

typedef struct ExecdWorkerPeerRow
{
    ExecdWorkerPeerIdentity identity;
    uint64_t generation;
    uint64_t next_request_id;
    uint32_t active_requests;
    uint8_t state;
    uint8_t reserved8[3];
} ExecdWorkerPeerRow;

typedef struct ExecdWorkerRequestRow
{
    ExecdWorkerParseRequest request;
    ExecdWorkerPlanAuthority plan;
    ExecdWorkerReply reply;
    uint64_t generation;
    uint64_t peer_generation;
    uint64_t request_id;
    uint32_t peer_slot;
    uint8_t state;
    uint8_t cancel_requested;
    uint8_t source_retained;
    uint8_t plan_retained;
} ExecdWorkerRequestRow;

typedef struct ExecdWorkerImpl
{
    uint64_t magic;
    ExecdWorkerInstanceIdentity instance;
    uint64_t first_slot_generation;
    uint32_t state;
    uint32_t peer_count;
    uint32_t request_count;
    uint32_t next_peer_hint;
    uint32_t next_request_hint;
    uint32_t next_work_hint;
    uint32_t next_reply_hint;
    ExecdWorkerPeerRow peers[EXECD_WORKER_MAX_PEERS];
    ExecdWorkerRequestRow requests[EXECD_WORKER_MAX_REQUESTS];
} ExecdWorkerImpl;

#if defined(__cplusplus)
static_assert(sizeof(ExecdWorkerImpl) <= EXECD_WORKER_STORAGE_BYTES, "execd worker fixed storage is too small");
#else
_Static_assert(sizeof(ExecdWorkerImpl) <= EXECD_WORKER_STORAGE_BYTES, "execd worker fixed storage is too small");
#endif

ExecdWorkerImpl* ExecdWorkerInternalMutable(ExecdWorker* worker);
const ExecdWorkerImpl* ExecdWorkerInternalReadOnly(const ExecdWorker* worker);
void ExecdWorkerInternalClear(void* storage, uint32_t bytes);
uint8_t ExecdWorkerInternalStorageIsZero(const void* storage, uint32_t bytes);
uint8_t ExecdWorkerInternalRangesOverlap(const void* left, uint64_t left_bytes, const void* right,
                                         uint64_t right_bytes);
uint8_t ExecdWorkerInternalHashIsNonzero(const uint8_t hash[32]);
uint8_t ExecdWorkerInternalHashEqual(const uint8_t left[32], const uint8_t right[32]);
uint8_t ExecdWorkerInternalPeerEqual(const ExecdWorkerPeerIdentity* left, const ExecdWorkerPeerIdentity* right);
uint8_t ExecdWorkerInternalInstanceEqual(const ExecdWorkerInstanceIdentity* left,
                                         const ExecdWorkerInstanceIdentity* right);
uint8_t ExecdWorkerInternalSourceIsCanonical(const ExecdWorkerSourceAuthority* source);
uint8_t ExecdWorkerInternalPlanIsCanonical(const ExecdWorkerPlanAuthority* plan);
ExecdWorkerStatus ExecdWorkerInternalValidate(const ExecdWorkerImpl* worker);

void ExecdWorkerInternalClearPeerReceipt(ExecdWorkerPeerReceipt* receipt);
void ExecdWorkerInternalClearRequestReceipt(ExecdWorkerRequestReceipt* receipt);
void ExecdWorkerInternalClearCleanup(ExecdWorkerCleanupRecord* cleanup);
void ExecdWorkerInternalClearCleanupBatch(ExecdWorkerCleanupBatch* cleanup);
void ExecdWorkerInternalClearReplyPublication(ExecdWorkerReplyPublication* reply);
void ExecdWorkerInternalClearCompleteResult(ExecdWorkerCompleteResult* result);
void ExecdWorkerInternalClearCancelResult(ExecdWorkerCancelResult* result);

ExecdWorkerPeerReceipt ExecdWorkerInternalMakePeerReceipt(const ExecdWorkerImpl* worker, uint32_t peer_slot);
ExecdWorkerRequestReceipt ExecdWorkerInternalMakeRequestReceipt(const ExecdWorkerImpl* worker, uint32_t request_slot);
ExecdWorkerStatus ExecdWorkerInternalResolvePeer(ExecdWorkerImpl* worker, const ExecdWorkerPeerReceipt* receipt,
                                                 uint8_t allow_closing, ExecdWorkerPeerRow** peer_out);
ExecdWorkerStatus ExecdWorkerInternalResolvePeerConst(const ExecdWorkerImpl* worker,
                                                      const ExecdWorkerPeerReceipt* receipt, uint8_t allow_closing,
                                                      const ExecdWorkerPeerRow** peer_out);
ExecdWorkerStatus ExecdWorkerInternalResolveRequest(ExecdWorkerImpl* worker, const ExecdWorkerRequestReceipt* receipt,
                                                    ExecdWorkerRequestRow** request_out);
ExecdWorkerStatus ExecdWorkerInternalResolveRequestConst(const ExecdWorkerImpl* worker,
                                                         const ExecdWorkerRequestReceipt* receipt,
                                                         const ExecdWorkerRequestRow** request_out);
int32_t ExecdWorkerInternalFindRequest(const ExecdWorkerImpl* worker, uint32_t peer_slot, uint64_t peer_generation,
                                       uint64_t request_id);

void ExecdWorkerInternalMaybeFinalizePeer(ExecdWorkerImpl* worker, uint32_t peer_slot);
ExecdWorkerStatus ExecdWorkerInternalRetireRequest(ExecdWorkerImpl* worker, uint32_t request_slot,
                                                   ExecdWorkerPlanDisposition plan_disposition,
                                                   ExecdWorkerCleanupRecord* cleanup_out);
ExecdWorkerStatus ExecdWorkerInternalAppendCleanup(ExecdWorkerCleanupBatch* batch,
                                                   const ExecdWorkerCleanupRecord* cleanup);
uint8_t ExecdWorkerInternalCompletionIsCanonical(const ExecdWorkerRequestRow* request,
                                                 const ExecdWorkerCompletion* completion);
void ExecdWorkerInternalMakeFailureReply(ExecdWorkerRequestRow* request, ExecdWorkerReplyStatus status);

#endif
