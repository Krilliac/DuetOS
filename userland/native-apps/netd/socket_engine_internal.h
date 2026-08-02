#ifndef DUETOS_NETD_SOCKET_ENGINE_INTERNAL_H
#define DUETOS_NETD_SOCKET_ENGINE_INTERNAL_H

#include "socket_engine.h"

#define NETD_SOCKET_ENGINE_MAGIC UINT64_C(0x4e455444534f4331)
#define NETD_SOCKET_ENGINE_INVALID_SLOT UINT32_MAX

typedef enum NetdSocketEnginePeerStateInternal
{
    NETD_SOCKET_ENGINE_PEER_STATE_FREE = 0,
    NETD_SOCKET_ENGINE_PEER_STATE_OPEN,
    NETD_SOCKET_ENGINE_PEER_STATE_CLOSING,
    NETD_SOCKET_ENGINE_PEER_STATE_RETIRED
} NetdSocketEnginePeerStateInternal;

typedef enum NetdSocketEngineSocketStateInternal
{
    NETD_SOCKET_ENGINE_SOCKET_FREE = 0,
    NETD_SOCKET_ENGINE_SOCKET_RESERVED,
    NETD_SOCKET_ENGINE_SOCKET_OPEN,
    NETD_SOCKET_ENGINE_SOCKET_CLOSING,
    NETD_SOCKET_ENGINE_SOCKET_RETIRED
} NetdSocketEngineSocketStateInternal;

typedef enum NetdSocketEngineRequestStateInternal
{
    NETD_SOCKET_ENGINE_REQUEST_FREE = 0,
    NETD_SOCKET_ENGINE_REQUEST_QUEUED_INTERNAL,
    NETD_SOCKET_ENGINE_REQUEST_RUNNING_INTERNAL,
    NETD_SOCKET_ENGINE_REQUEST_REPLY_READY_INTERNAL,
    NETD_SOCKET_ENGINE_REQUEST_REPLY_PUBLISHING_INTERNAL,
    NETD_SOCKET_ENGINE_REQUEST_RETIRED
} NetdSocketEngineRequestStateInternal;

typedef struct NetdSocketEnginePeerRow
{
    NetdSocketEnginePeerIdentity identity;
    NetdSocketEnginePeerAuthority authority;
    uint64_t generation;
    uint64_t next_request_id;
    uint32_t active_sockets;
    uint32_t active_requests;
    uint8_t state;
    uint8_t reserved8[7];
} NetdSocketEnginePeerRow;

typedef struct NetdSocketEngineSocketRow
{
    NetdSocketEngineBackendSocketIdentity backend;
    uint64_t generation;
    uint64_t owner_peer_generation;
    uint32_t owner_peer_slot;
    uint8_t state;
    uint8_t reserved8;
    uint16_t domain;
    uint16_t type;
    uint16_t protocol;
    uint32_t reserved32;
} NetdSocketEngineSocketRow;

typedef struct NetdSocketEngineRequestRow
{
    NetdSocketEngineRequest request;
    NetdSocketEngineReply reply;
    uint64_t generation;
    uint64_t peer_generation;
    uint32_t peer_slot;
    uint32_t socket_slot;
    uint64_t socket_generation;
    uint8_t state;
    uint8_t cancel_requested;
    uint8_t abandon_cleanup_reason;
    uint8_t reserved8[5];
} NetdSocketEngineRequestRow;

typedef struct NetdSocketEngineImpl
{
    uint64_t magic;
    NetdSocketEngineInstanceIdentity instance;
    NetdSocketEngineTransportIdentity transport;
    uint64_t first_slot_generation;
    uint32_t state;
    uint32_t peer_count;
    uint32_t socket_count;
    uint32_t request_count;
    uint32_t next_peer_hint;
    uint32_t next_socket_hint;
    uint32_t next_request_hint;
    uint32_t next_work_hint;
    uint32_t next_reply_hint;
    NetdSocketEnginePeerRow peers[NETD_SOCKET_ENGINE_MAX_PEERS];
    NetdSocketEngineSocketRow sockets[NETD_SOCKET_ENGINE_MAX_SOCKETS];
    NetdSocketEngineRequestRow requests[NETD_SOCKET_ENGINE_MAX_REQUESTS];
} NetdSocketEngineImpl;

#if defined(__cplusplus)
static_assert(sizeof(NetdSocketEngineImpl) <= NETD_SOCKET_ENGINE_STORAGE_BYTES,
              "netd socket engine fixed storage is too small");
#else
_Static_assert(sizeof(NetdSocketEngineImpl) <= NETD_SOCKET_ENGINE_STORAGE_BYTES,
               "netd socket engine fixed storage is too small");
#endif

NetdSocketEngineImpl* NetdSocketEngineInternalMutable(NetdSocketEngine* engine);
const NetdSocketEngineImpl* NetdSocketEngineInternalReadOnly(const NetdSocketEngine* engine);
void NetdSocketEngineInternalClear(void* storage, uint32_t bytes);
uint8_t NetdSocketEngineInternalStorageIsZero(const void* storage, uint32_t bytes);
uint8_t NetdSocketEngineInternalRangesOverlap(const void* left, uint64_t left_bytes, const void* right,
                                              uint64_t right_bytes);

uint8_t NetdSocketEngineInternalInstanceEqual(const NetdSocketEngineInstanceIdentity* left,
                                              const NetdSocketEngineInstanceIdentity* right);
uint8_t NetdSocketEngineInternalPeerEqual(const NetdSocketEnginePeerIdentity* left,
                                          const NetdSocketEnginePeerIdentity* right);
uint8_t NetdSocketEngineInternalAuthorityEqual(const NetdSocketEnginePeerAuthority* left,
                                               const NetdSocketEnginePeerAuthority* right);
uint8_t NetdSocketEngineInternalTransportEqual(const NetdSocketEngineTransportIdentity* left,
                                               const NetdSocketEngineTransportIdentity* right);
uint8_t NetdSocketEngineInternalBackendIsCanonical(const NetdSocketEngineBackendSocketIdentity* backend);
uint8_t NetdSocketEngineInternalBackendEqual(const NetdSocketEngineBackendSocketIdentity* left,
                                             const NetdSocketEngineBackendSocketIdentity* right);
uint8_t NetdSocketEngineInternalBackendIsZero(const NetdSocketEngineBackendSocketIdentity* backend);
uint8_t NetdSocketEngineInternalSocketParametersAreCanonical(uint16_t domain, uint16_t type, uint16_t protocol);
uint8_t NetdSocketEngineInternalSocketRefEqual(const NetdSocketEngineSocketRef* left,
                                               const NetdSocketEngineSocketRef* right);
uint8_t NetdSocketEngineInternalSocketRefIsZero(const NetdSocketEngineSocketRef* socket);
uint8_t NetdSocketEngineInternalSocketRefIsCanonical(const NetdSocketEngineImpl* implementation,
                                                     const NetdSocketEngineSocketRef* socket);
uint8_t NetdSocketEngineInternalValidate(const NetdSocketEngineImpl* implementation);
uint8_t NetdSocketEngineInternalHasPublishingReply(const NetdSocketEngineImpl* implementation);

NetdSocketEngineStatus NetdSocketEngineInternalResolvePeer(NetdSocketEngineImpl* implementation,
                                                           const NetdSocketEnginePeerReceipt* receipt,
                                                           NetdSocketEnginePeerRow** row_out);
NetdSocketEngineStatus NetdSocketEngineInternalResolveRequest(NetdSocketEngineImpl* implementation,
                                                              const NetdSocketEngineRequestReceipt* receipt,
                                                              NetdSocketEngineRequestRow** row_out);
NetdSocketEngineStatus NetdSocketEngineInternalResolveSocket(NetdSocketEngineImpl* implementation,
                                                             const NetdSocketEnginePeerRow* owner, uint32_t owner_slot,
                                                             const NetdSocketEngineSocketRef* socket,
                                                             NetdSocketEngineSocketRow** row_out);

NetdSocketEnginePeerReceipt NetdSocketEngineInternalPeerReceipt(const NetdSocketEngineImpl* implementation,
                                                                uint32_t slot);
NetdSocketEngineRequestReceipt NetdSocketEngineInternalRequestReceipt(const NetdSocketEngineImpl* implementation,
                                                                      uint32_t slot);
NetdSocketEngineSocketRef NetdSocketEngineInternalSocketRef(const NetdSocketEngineImpl* implementation, uint32_t slot);
NetdSocketEngineCleanupRecord NetdSocketEngineInternalCleanupRecord(const NetdSocketEngineImpl* implementation,
                                                                    uint32_t socket_slot, uint32_t reason);
NetdSocketEngineStatus NetdSocketEngineInternalAppendCleanup(NetdSocketEngineCleanupBatch* batch,
                                                             const NetdSocketEngineCleanupRecord* record);

void NetdSocketEngineInternalRetireRequest(NetdSocketEngineImpl* implementation, uint32_t slot);
void NetdSocketEngineInternalRetireSocket(NetdSocketEngineImpl* implementation, uint32_t slot);
void NetdSocketEngineInternalMaybeFinalizePeer(NetdSocketEngineImpl* implementation, uint32_t slot);

#endif
