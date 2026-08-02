#ifndef DUETOS_NETD_SOCKET_ENGINE_H
#define DUETOS_NETD_SOCKET_ENGINE_H

/*
 * Allocation-free netd socket authority and request coordinator.
 *
 * This C11 interface is a service-local state machine, not a network stack.
 * It never calls the current kernel BSD socket ABI, touches packets, or claims
 * that NetworkMaster/PacketRing transport is live.  A trusted endpoint adapter
 * authenticates a peer, commits the incoming endpoint request ledger, and
 * snapshots scalar authority before calling this API.  A separate backend may
 * execute returned work only after an exact transport attachment exists.
 *
 * One netd control actor owns every mutating call.  Backend workers may retain
 * work items by value and return exact leases to that actor, but do not inspect
 * this storage concurrently; CheckCancellation is an actor-side snapshot.
 * No callback, allocation, wait, handle, kernel pointer, or authority-bearing
 * wire field is stored here.  Restart requires fresh zeroed storage and a
 * strictly new supervised service-instance identity.
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define NETD_SOCKET_ENGINE_MAX_PEERS 16U
#define NETD_SOCKET_ENGINE_MAX_SOCKETS 64U
#define NETD_SOCKET_ENGINE_MAX_REQUESTS 64U
#define NETD_SOCKET_ENGINE_CLEANUP_CAPACITY NETD_SOCKET_ENGINE_MAX_SOCKETS
#define NETD_SOCKET_ENGINE_STORAGE_BYTES 65536U
#define NETD_SOCKET_ENGINE_SERVICE_CAPACITY 64U
#define NETD_SOCKET_ENGINE_CREDENTIAL_CAPACITY 64U
#define NETD_SOCKET_ENGINE_CHANNEL_CAPACITY 32U
#define NETD_SOCKET_ENGINE_IDENTITY_GENERATION_MAX UINT64_C(0x7ffffffffffff)

#define NETD_SOCKET_ENGINE_METHOD_OPEN UINT64_C(0x1)
#define NETD_SOCKET_ENGINE_METHOD_CLOSE UINT64_C(0x2)
#define NETD_SOCKET_ENGINE_METHOD_KNOWN_MASK (NETD_SOCKET_ENGINE_METHOD_OPEN | NETD_SOCKET_ENGINE_METHOD_CLOSE)

    typedef enum NetdSocketEngineStatus
    {
        NETD_SOCKET_ENGINE_OK = 0,
        NETD_SOCKET_ENGINE_NULL_ARGUMENT,
        NETD_SOCKET_ENGINE_ALIASED_STORAGE,
        NETD_SOCKET_ENGINE_NONZERO_STORAGE,
        NETD_SOCKET_ENGINE_ALREADY_INITIALIZED,
        NETD_SOCKET_ENGINE_NOT_INITIALIZED,
        NETD_SOCKET_ENGINE_CORRUPT_STATE,
        NETD_SOCKET_ENGINE_INVALID_IDENTITY,
        NETD_SOCKET_ENGINE_INVALID_ARGUMENT,
        NETD_SOCKET_ENGINE_CLOSED,
        NETD_SOCKET_ENGINE_DRAINING,
        NETD_SOCKET_ENGINE_TRANSPORT_UNAVAILABLE,
        NETD_SOCKET_ENGINE_TRANSPORT_ALREADY_ATTACHED,
        NETD_SOCKET_ENGINE_STALE_TRANSPORT,
        NETD_SOCKET_ENGINE_UNAUTHORIZED,
        NETD_SOCKET_ENGINE_PEER_CAPACITY,
        NETD_SOCKET_ENGINE_SOCKET_CAPACITY,
        NETD_SOCKET_ENGINE_REQUEST_CAPACITY,
        NETD_SOCKET_ENGINE_GENERATION_EXHAUSTED,
        NETD_SOCKET_ENGINE_SEQUENCE_EXHAUSTED,
        NETD_SOCKET_ENGINE_PEER_EXISTS,
        NETD_SOCKET_ENGINE_PEER_NOT_FOUND,
        NETD_SOCKET_ENGINE_STALE_PEER,
        NETD_SOCKET_ENGINE_PEER_CLOSING,
        NETD_SOCKET_ENGINE_SOCKET_NOT_FOUND,
        NETD_SOCKET_ENGINE_STALE_SOCKET,
        NETD_SOCKET_ENGINE_SOCKET_BUSY,
        NETD_SOCKET_ENGINE_REPLAYED_REQUEST,
        NETD_SOCKET_ENGINE_OUT_OF_ORDER_REQUEST,
        NETD_SOCKET_ENGINE_REQUEST_NOT_FOUND,
        NETD_SOCKET_ENGINE_NO_WORK,
        NETD_SOCKET_ENGINE_STALE_WORK,
        NETD_SOCKET_ENGINE_INVALID_COMPLETION,
        NETD_SOCKET_ENGINE_NO_REPLY,
        NETD_SOCKET_ENGINE_STALE_REPLY,
        NETD_SOCKET_ENGINE_REPLY_IN_FLIGHT,
        NETD_SOCKET_ENGINE_CANCEL_TOO_LATE,
        NETD_SOCKET_ENGINE_BUSY
    } NetdSocketEngineStatus;

    typedef enum NetdSocketEngineState
    {
        NETD_SOCKET_ENGINE_STATE_UNINITIALIZED = 0,
        NETD_SOCKET_ENGINE_STATE_AWAITING_TRANSPORT,
        NETD_SOCKET_ENGINE_STATE_OPEN,
        NETD_SOCKET_ENGINE_STATE_DRAINING,
        NETD_SOCKET_ENGINE_STATE_CLOSED
    } NetdSocketEngineState;

    typedef enum NetdSocketEngineChannelRole
    {
        NETD_SOCKET_ENGINE_CHANNEL_INITIATOR = 0,
        NETD_SOCKET_ENGINE_CHANNEL_ACCEPTOR = 1
    } NetdSocketEngineChannelRole;

    typedef enum NetdSocketEngineOperation
    {
        NETD_SOCKET_ENGINE_OPERATION_OPEN = 1,
        NETD_SOCKET_ENGINE_OPERATION_CLOSE = 2
    } NetdSocketEngineOperation;

    typedef enum NetdSocketEngineDomain
    {
        NETD_SOCKET_ENGINE_DOMAIN_IPV4 = 1,
        NETD_SOCKET_ENGINE_DOMAIN_IPV6 = 2
    } NetdSocketEngineDomain;

    typedef enum NetdSocketEngineType
    {
        NETD_SOCKET_ENGINE_TYPE_STREAM = 1,
        NETD_SOCKET_ENGINE_TYPE_DATAGRAM = 2
    } NetdSocketEngineType;

    typedef enum NetdSocketEngineProtocol
    {
        NETD_SOCKET_ENGINE_PROTOCOL_DEFAULT = 0,
        NETD_SOCKET_ENGINE_PROTOCOL_TCP = 6,
        NETD_SOCKET_ENGINE_PROTOCOL_UDP = 17
    } NetdSocketEngineProtocol;

    typedef enum NetdSocketEngineReplyStatus
    {
        NETD_SOCKET_ENGINE_REPLY_SUCCESS = 0,
        NETD_SOCKET_ENGINE_REPLY_INVALID_ARGUMENT,
        NETD_SOCKET_ENGINE_REPLY_POLICY_REJECTED,
        NETD_SOCKET_ENGINE_REPLY_TRANSPORT_UNAVAILABLE,
        NETD_SOCKET_ENGINE_REPLY_CANCELLED,
        NETD_SOCKET_ENGINE_REPLY_BACKEND_FAILURE
    } NetdSocketEngineReplyStatus;

    typedef enum NetdSocketEngineCleanupReason
    {
        NETD_SOCKET_ENGINE_CLEANUP_CANCELLED_OPEN = 1,
        NETD_SOCKET_ENGINE_CLEANUP_PEER_CLOSED,
        NETD_SOCKET_ENGINE_CLEANUP_TRANSPORT_DRAIN,
        NETD_SOCKET_ENGINE_CLEANUP_FAILED_CLOSE
    } NetdSocketEngineCleanupReason;

    typedef struct NetdSocketEngineProcessKey
    {
        uint64_t identity;
        uint64_t pid;
    } NetdSocketEngineProcessKey;

    typedef struct NetdSocketEngineCredentialKey
    {
        uint32_t slot;
        uint32_t reserved32;
        uint64_t generation;
    } NetdSocketEngineCredentialKey;

    /* Exact accepted ServiceEndpoint identity; role must be Acceptor. */
    typedef struct NetdSocketEngineChannelIdentity
    {
        uint32_t slot;
        uint8_t role;
        uint8_t reserved8[3];
        uint64_t generation;
        uint64_t epoch;
    } NetdSocketEngineChannelIdentity;

    typedef struct NetdSocketEngineInstanceIdentity
    {
        uint64_t service_identity;
        uint64_t instance_generation;
        NetdSocketEngineProcessKey process;
        uint64_t published_endpoint_epoch;
        uint32_t service_slot;
        uint32_t reserved32;
    } NetdSocketEngineInstanceIdentity;

    typedef struct NetdSocketEnginePeerIdentity
    {
        NetdSocketEngineProcessKey process;
        NetdSocketEngineCredentialKey credential;
        NetdSocketEngineChannelIdentity channel;
    } NetdSocketEnginePeerIdentity;

    /* Trusted endpoint-policy snapshot. Never populate this from message bytes. */
    typedef struct NetdSocketEnginePeerAuthority
    {
        uint64_t authority_identity;
        uint64_t network_namespace_identity;
        uint64_t allowed_methods;
        uint32_t socket_limit;
        uint32_t request_limit;
        uint64_t reserved;
    } NetdSocketEnginePeerAuthority;

    /*
     * A value-only proof that the adapter has a real, revocable backend.
     * This is not itself NetworkMaster or a PacketRing capability.  The adapter
     * may attach it only after those kernel-owned objects are live and retained.
     */
    typedef struct NetdSocketEngineTransportIdentity
    {
        uint64_t identity;
        uint64_t generation;
    } NetdSocketEngineTransportIdentity;

    typedef struct NetdSocketEngineTransportReceipt
    {
        NetdSocketEngineInstanceIdentity instance;
        NetdSocketEngineTransportIdentity transport;
    } NetdSocketEngineTransportReceipt;

    typedef struct NetdSocketEnginePeerReceipt
    {
        NetdSocketEngineInstanceIdentity instance;
        NetdSocketEnginePeerIdentity peer;
        NetdSocketEnginePeerAuthority authority;
        uint64_t peer_generation;
        uint32_t peer_slot;
        uint32_t reserved32;
    } NetdSocketEnginePeerReceipt;

    /* Service-local opaque reference; stale after restart, drain, or reuse. */
    typedef struct NetdSocketEngineSocketRef
    {
        uint64_t instance_generation;
        uint64_t transport_generation;
        uint64_t generation;
        uint32_t slot;
        uint32_t reserved32;
    } NetdSocketEngineSocketRef;

    typedef struct NetdSocketEngineBackendSocketIdentity
    {
        NetdSocketEngineTransportIdentity transport;
        uint64_t identity;
    } NetdSocketEngineBackendSocketIdentity;

    typedef struct NetdSocketEngineRequest
    {
        NetdSocketEngineSocketRef socket;
        uint64_t request_id;
        uint32_t operation;
        uint16_t domain;
        uint16_t type;
        uint16_t protocol;
        uint16_t reserved16;
        uint32_t flags;
    } NetdSocketEngineRequest;

    typedef struct NetdSocketEngineRequestReceipt
    {
        NetdSocketEnginePeerReceipt peer;
        uint64_t request_generation;
        uint64_t request_id;
        uint32_t request_slot;
        uint32_t reserved32;
    } NetdSocketEngineRequestReceipt;

    typedef struct NetdSocketEngineWorkLease
    {
        NetdSocketEngineRequestReceipt request;
    } NetdSocketEngineWorkLease;

    typedef struct NetdSocketEngineWorkItem
    {
        NetdSocketEngineWorkLease lease;
        NetdSocketEngineRequest request;
        NetdSocketEngineBackendSocketIdentity backend;
    } NetdSocketEngineWorkItem;

    typedef struct NetdSocketEngineCompletion
    {
        NetdSocketEngineBackendSocketIdentity backend;
        uint32_t reply_status;
        uint32_t reserved32;
    } NetdSocketEngineCompletion;

    typedef struct NetdSocketEngineReply
    {
        NetdSocketEngineSocketRef socket;
        uint64_t request_id;
        uint32_t operation;
        uint32_t status;
    } NetdSocketEngineReply;

    typedef struct NetdSocketEngineReplyLease
    {
        NetdSocketEngineRequestReceipt request;
    } NetdSocketEngineReplyLease;

    typedef struct NetdSocketEngineReplyPublication
    {
        NetdSocketEngineReplyLease lease;
        NetdSocketEngineReply reply;
    } NetdSocketEngineReplyPublication;

    /* The adapter executes cleanup only after the mutating call returns. */
    typedef struct NetdSocketEngineCleanupRecord
    {
        NetdSocketEngineSocketRef socket;
        NetdSocketEngineBackendSocketIdentity backend;
        uint32_t reason;
        uint32_t reserved32;
    } NetdSocketEngineCleanupRecord;

    typedef struct NetdSocketEngineCleanupBatch
    {
        uint32_t count;
        uint32_t reserved32;
        NetdSocketEngineCleanupRecord records[NETD_SOCKET_ENGINE_CLEANUP_CAPACITY];
    } NetdSocketEngineCleanupBatch;

    typedef struct NetdSocketEngineCancelResult
    {
        NetdSocketEngineStatus status;
        uint8_t cancellation_requested;
        uint8_t reply_ready;
        uint8_t cleanup_valid;
        uint8_t reserved8;
        NetdSocketEngineCleanupRecord cleanup;
    } NetdSocketEngineCancelResult;

    typedef struct NetdSocketEngineCompleteResult
    {
        NetdSocketEngineStatus status;
        uint8_t reply_ready;
        uint8_t request_retired;
        uint8_t cleanup_valid;
        uint8_t reserved8;
        NetdSocketEngineCleanupRecord cleanup;
    } NetdSocketEngineCompleteResult;

    typedef enum NetdSocketEngineRequestPhase
    {
        NETD_SOCKET_ENGINE_REQUEST_QUEUED = 1,
        NETD_SOCKET_ENGINE_REQUEST_RUNNING,
        NETD_SOCKET_ENGINE_REQUEST_REPLY_READY,
        NETD_SOCKET_ENGINE_REQUEST_REPLY_PUBLISHING
    } NetdSocketEngineRequestPhase;

    typedef enum NetdSocketEngineSocketPhase
    {
        NETD_SOCKET_ENGINE_SOCKET_RESERVED_OPEN = 1,
        NETD_SOCKET_ENGINE_SOCKET_LIVE,
        NETD_SOCKET_ENGINE_SOCKET_BUSY_CLOSE
    } NetdSocketEngineSocketPhase;

    typedef struct NetdSocketEngineSnapshot
    {
        NetdSocketEngineInstanceIdentity instance;
        NetdSocketEngineTransportIdentity transport;
        uint32_t state;
        uint32_t peer_count;
        uint32_t socket_count;
        uint32_t request_count;
        uint32_t queued_count;
        uint32_t running_count;
        uint32_t reply_count;
        uint32_t retired_peer_slots;
        uint32_t retired_socket_slots;
        uint32_t retired_request_slots;
    } NetdSocketEngineSnapshot;

    typedef struct NetdSocketEngineSocketSnapshot
    {
        NetdSocketEngineSocketRef socket;
        NetdSocketEnginePeerReceipt owner;
        NetdSocketEngineBackendSocketIdentity backend;
        uint32_t phase;
        uint16_t domain;
        uint16_t type;
        uint16_t protocol;
        uint16_t reserved16;
    } NetdSocketEngineSocketSnapshot;

    typedef struct NetdSocketEngineRequestSnapshot
    {
        NetdSocketEngineRequestReceipt receipt;
        NetdSocketEngineRequest request;
        uint32_t phase;
        uint8_t cancel_requested;
        uint8_t reserved8[3];
    } NetdSocketEngineRequestSnapshot;

    /* Opaque, caller-owned fixed storage. Static/BSS allocation is recommended. */
    typedef union NetdSocketEngine
    {
        uint64_t alignment;
        uint8_t bytes[NETD_SOCKET_ENGINE_STORAGE_BYTES];
    } NetdSocketEngine;

    /* [netd control actor; one-shot, allocation/callback/wait free] */
    NetdSocketEngineStatus NetdSocketEngineInitialize(NetdSocketEngine* engine,
                                                      const NetdSocketEngineInstanceIdentity* instance,
                                                      uint64_t first_slot_generation);

    /*
     * Attach succeeds exactly once. The adapter retains the real transport
     * authority for the lifetime of the returned receipt. Before this call,
     * peer admission and every socket request fail closed.
     */
    NetdSocketEngineStatus NetdSocketEngineAttachTransport(NetdSocketEngine* engine,
                                                           const NetdSocketEngineTransportIdentity* transport,
                                                           NetdSocketEngineTransportReceipt* receipt_out);

    /* [netd control actor; identity and authority are trusted endpoint facts] */
    NetdSocketEngineStatus NetdSocketEngineOpenPeer(NetdSocketEngine* engine, const NetdSocketEnginePeerIdentity* peer,
                                                    const NetdSocketEnginePeerAuthority* authority,
                                                    uint64_t first_request_id,
                                                    NetdSocketEnginePeerReceipt* receipt_out);
    NetdSocketEngineStatus NetdSocketEngineClosePeer(NetdSocketEngine* engine,
                                                     const NetdSocketEnginePeerReceipt* receipt,
                                                     NetdSocketEngineCleanupBatch* cleanup_out);

    /*
     * The endpoint adapter calls Submit only after canonical protocol decoding
     * and successful CommitReceivedRequest for this exact request ID. Capacity,
     * rights, quota, socket identity, and transport checks occur before the
     * engine advances its own monotonic per-peer sequence. A socket stays
     * request-pinned until its reply is committed; guessed or pipelined reuse
     * of the reference fails with SOCKET_BUSY without consuming the sequence.
     */
    NetdSocketEngineStatus NetdSocketEngineSubmitOpen(NetdSocketEngine* engine, const NetdSocketEnginePeerReceipt* peer,
                                                      uint64_t request_id, uint16_t domain, uint16_t type,
                                                      uint16_t protocol, uint32_t flags,
                                                      NetdSocketEngineRequestReceipt* receipt_out);
    NetdSocketEngineStatus NetdSocketEngineSubmitClose(NetdSocketEngine* engine,
                                                       const NetdSocketEnginePeerReceipt* peer, uint64_t request_id,
                                                       const NetdSocketEngineSocketRef* socket,
                                                       NetdSocketEngineRequestReceipt* receipt_out);

    /* [control actor/backend handoff; work is immutable and the lease is one exact pin] */
    NetdSocketEngineStatus NetdSocketEngineClaimNext(NetdSocketEngine* engine, NetdSocketEngineWorkItem* work_out);
    NetdSocketEngineStatus NetdSocketEngineCheckCancellation(const NetdSocketEngine* engine,
                                                             const NetdSocketEngineWorkLease* lease,
                                                             uint8_t* cancellation_out);
    NetdSocketEngineCancelResult NetdSocketEngineCancel(NetdSocketEngine* engine,
                                                        const NetdSocketEnginePeerReceipt* peer, uint64_t request_id);
    NetdSocketEngineCompleteResult NetdSocketEngineComplete(NetdSocketEngine* engine,
                                                            const NetdSocketEngineWorkLease* lease,
                                                            const NetdSocketEngineCompletion* completion);

    /*
     * Reply publication is two-phase. The actor must resolve the lease with
     * Commit or Abort before any other mutation, including close or drain.
     */
    NetdSocketEngineStatus NetdSocketEngineGetNextReply(NetdSocketEngine* engine,
                                                        NetdSocketEngineReplyPublication* reply_out);
    NetdSocketEngineStatus NetdSocketEngineCommitReply(NetdSocketEngine* engine,
                                                       const NetdSocketEngineReplyLease* lease);
    NetdSocketEngineStatus NetdSocketEngineAbortReply(NetdSocketEngine* engine,
                                                      const NetdSocketEngineReplyLease* lease);

    /*
     * Terminal drain. OPEN requires the exact transport receipt; awaiting-
     * transport initialization requires NULL. Running backend work remains
     * pinned and FinishDrain returns BUSY until each exact lease completes.
     */
    NetdSocketEngineStatus NetdSocketEngineBeginDrain(NetdSocketEngine* engine,
                                                      const NetdSocketEngineTransportReceipt* transport,
                                                      NetdSocketEngineCleanupBatch* cleanup_out);
    NetdSocketEngineStatus NetdSocketEngineFinishDrain(NetdSocketEngine* engine);

    /* [actor thread or externally serialized diagnostic reader] */
    NetdSocketEngineStatus NetdSocketEngineDescribe(const NetdSocketEngine* engine,
                                                    NetdSocketEngineSnapshot* snapshot_out);
    NetdSocketEngineStatus NetdSocketEngineInspectSocket(const NetdSocketEngine* engine,
                                                         const NetdSocketEnginePeerReceipt* peer,
                                                         const NetdSocketEngineSocketRef* socket,
                                                         NetdSocketEngineSocketSnapshot* snapshot_out);
    NetdSocketEngineStatus NetdSocketEngineInspectRequest(const NetdSocketEngine* engine,
                                                          const NetdSocketEngineRequestReceipt* receipt,
                                                          NetdSocketEngineRequestSnapshot* snapshot_out);

    uint8_t NetdSocketEngineInstanceIdentityIsCanonical(const NetdSocketEngineInstanceIdentity* identity);
    uint8_t NetdSocketEnginePeerIdentityIsCanonical(const NetdSocketEnginePeerIdentity* identity);
    uint8_t NetdSocketEnginePeerAuthorityIsCanonical(const NetdSocketEnginePeerAuthority* authority);
    uint8_t NetdSocketEngineTransportIdentityIsCanonical(const NetdSocketEngineTransportIdentity* transport);
    const char* NetdSocketEngineStatusName(NetdSocketEngineStatus status);

#ifdef __cplusplus
}
#endif

#endif
