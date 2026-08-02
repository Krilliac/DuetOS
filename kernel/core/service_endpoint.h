#pragma once

/*
 * Authenticated, generation-safe ownership for one paired service channel.
 *
 * A ServiceEndpointOwner is fixed-capacity storage supplied by its boot-global
 * parent.  Each live row embeds one ChannelCore and the paired initiator and
 * acceptor KObjects.  Endpoint KObjects carry only an exact owner identity;
 * callers can borrow a ChannelCore direction only through an operation receipt
 * that owns both a KObject reference and an exact ChannelCore operation pin.
 *
 * No KObject operation, ChannelCore operation, request-cleanup callback,
 * allocation, HandleTable operation, or logging occurs while the owner lock is
 * held.  The first endpoint close or outer-owner release starts one guarded
 * drain. A contender that releases the last ChannelCore pin while that driver
 * is active publishes a durable retry request; the active driver consumes that
 * handoff before retiring. Storage is not recycled until the outer ownership
 * receipt is consumed, both endpoint KObject lifetimes end, request/detached
 * cleanup is complete, and ChannelCore pins have quiesced.
 */

#include "ipc/channel_core.h"
#include "ipc/kobject.h"
#include "proc/credentials.h"
#include "proc/process.h"
#include "proc/resource_domain.h"
#include "util/types.h"

#if !defined(DUETOS_HOST_TEST)
#include "sync/spinlock.h"
#endif

namespace duetos::core
{

inline constexpr u32 kServiceEndpointOwnerCapacity = 32;
inline constexpr u64 kServiceEndpointGenerationMaximum = (1ULL << 51) - 1;

enum class ServiceEndpointRole : u8
{
    Initiator = 0,
    Acceptor,
};

inline constexpr bool ServiceEndpointRoleIsValid(ServiceEndpointRole role)
{
    return role == ServiceEndpointRole::Initiator || role == ServiceEndpointRole::Acceptor;
}

inline constexpr u32 ServiceEndpointRoleIndex(ServiceEndpointRole role)
{
    return role == ServiceEndpointRole::Initiator ? 0U : 1U;
}

struct ServiceEndpointChannelKey
{
    u32 slot;
    u64 generation;
    ipc::ChannelEpoch channel_epoch;
};

inline constexpr ServiceEndpointChannelKey kInvalidServiceEndpointChannelKey{
    kServiceEndpointOwnerCapacity,
    0,
    ipc::kChannelEpochInvalid,
};

inline constexpr bool ServiceEndpointChannelKeyIsValid(ServiceEndpointChannelKey key)
{
    return key.slot < kServiceEndpointOwnerCapacity && key.generation != 0 &&
           key.generation <= kServiceEndpointGenerationMaximum && key.channel_epoch != ipc::kChannelEpochInvalid;
}

inline constexpr bool operator==(ServiceEndpointChannelKey lhs, ServiceEndpointChannelKey rhs)
{
    return lhs.slot == rhs.slot && lhs.generation == rhs.generation && lhs.channel_epoch == rhs.channel_epoch;
}

struct ServiceEndpointIdentity
{
    ServiceEndpointChannelKey channel;
    ServiceEndpointRole role;
};

inline constexpr ServiceEndpointIdentity kInvalidServiceEndpointIdentity{
    kInvalidServiceEndpointChannelKey,
    ServiceEndpointRole::Initiator,
};

inline constexpr bool ServiceEndpointIdentityIsValid(ServiceEndpointIdentity identity)
{
    return ServiceEndpointChannelKeyIsValid(identity.channel) && ServiceEndpointRoleIsValid(identity.role);
}

inline constexpr bool operator==(ServiceEndpointIdentity lhs, ServiceEndpointIdentity rhs)
{
    return lhs.channel == rhs.channel && lhs.role == rhs.role;
}

// Trusted kernel transport authority. No manifest or wire field may populate
// this structure. `service_identity` binds it to one stable manifest service,
// while `wire_service_id` selects that service's protocol-local MessageAbi
// route. Method ids 1..64 map to bit (method_id - 1) in allowed_methods and
// never imply generic HandleTable rights.
struct ServiceEndpointProtocolAuthority
{
    u64 authority_identity;
    u64 protocol_identity;
    u64 service_identity;
    u64 allowed_methods;
    u32 protocol_version;
    u32 flags;
    u32 wire_service_id;
    u32 reserved32;
};

inline constexpr u32 kServiceEndpointProtocolVersionMaximum = 0xFFFFU;

static_assert(sizeof(ServiceEndpointProtocolAuthority) == 48, "service endpoint protocol authority size changed");
static_assert(__builtin_offsetof(ServiceEndpointProtocolAuthority, wire_service_id) == 40,
              "service endpoint wire route offset changed");
static_assert(__builtin_offsetof(ServiceEndpointProtocolAuthority, reserved32) == 44,
              "service endpoint protocol reserved offset changed");

bool ServiceEndpointProtocolAuthorityIsCanonical(const ServiceEndpointProtocolAuthority& authority);
bool ServiceEndpointProtocolAuthorityAllowsRoute(const ServiceEndpointProtocolAuthority& authority, u32 wire_service_id,
                                                 u32 method_id);

struct ServiceEndpointCredentialSnapshot
{
    CredentialKey key;
    CredentialSecurityContext security;
};

bool ServiceEndpointCredentialSnapshotIsCanonical(const ServiceEndpointCredentialSnapshot& snapshot);
bool operator==(const ServiceEndpointCredentialSnapshot& lhs, const ServiceEndpointCredentialSnapshot& rhs);

struct ServiceEndpointPeerSnapshot
{
    ProcessKey process;
    ServiceEndpointCredentialSnapshot credential;
};

bool ServiceEndpointPeerSnapshotIsCanonical(const ServiceEndpointPeerSnapshot& snapshot);
bool operator==(const ServiceEndpointPeerSnapshot& lhs, const ServiceEndpointPeerSnapshot& rhs);

using ServiceEndpointRequestCleanupFn = void (*)(void* context, ipc::EndpointRequestKey request_key);

struct ServiceEndpointRequestCleanupSink
{
    ServiceEndpointRequestCleanupFn consume;
    void* context;
};

inline constexpr ServiceEndpointRequestCleanupSink kInvalidServiceEndpointRequestCleanupSink{nullptr, nullptr};

inline constexpr bool ServiceEndpointRequestCleanupSinkIsValid(const ServiceEndpointRequestCleanupSink* sink)
{
    return sink != nullptr && sink->consume != nullptr;
}

enum class ServiceEndpointOwnerState : u8
{
    Uninitialized = 0,
    Open,
};

enum class ServiceEndpointSlotState : u8
{
    Empty = 0,
    Constructing,
    Private,
    Open,
    Draining,
    Drained,
    Retired,
};

enum class ServiceEndpointStatus : u8
{
    Ok = 0,
    InvalidArgument,
    NotInitialized,
    AlreadyInitialized,
    CorruptState,
    CapacityExhausted,
    GenerationExhausted,
    ChannelCreateFailed,
    NotPublished,
    AlreadyPublished,
    Closing,
    Drained,
    StaleIdentity,
    StaleActivation,
    StaleOwner,
    Busy,
    InvalidCleanup,
    ResourceReleaseFailed,
    RequestRejected,
};

struct ServiceEndpointOwner;

// First member is KObject so the stable ServiceEndpoint type tag may be
// resolved back to this concrete object after a checked HandleTable lookup.
struct ServiceEndpointObject
{
    ipc::KObject base;
    ServiceEndpointOwner* owner;
    ServiceEndpointIdentity identity;
    ServiceEndpointProtocolAuthority protocol;
    ServiceEndpointPeerSnapshot peer;
};

struct ServiceEndpointOwnerReceipt
{
    ServiceEndpointOwner* owner;
    ServiceEndpointChannelKey channel;
};

inline constexpr ServiceEndpointOwnerReceipt kInvalidServiceEndpointOwnerReceipt{
    nullptr,
    kInvalidServiceEndpointChannelKey,
};

inline constexpr bool ServiceEndpointOwnerReceiptIsValid(ServiceEndpointOwnerReceipt receipt)
{
    return receipt.owner != nullptr && ServiceEndpointChannelKeyIsValid(receipt.channel);
}

struct ServiceEndpointActivationTicket
{
    ServiceEndpointOwner* owner;
    ServiceEndpointChannelKey channel;
    u64 nonce;
};

inline constexpr ServiceEndpointActivationTicket kInvalidServiceEndpointActivationTicket{
    nullptr,
    kInvalidServiceEndpointChannelKey,
    0,
};

inline constexpr bool ServiceEndpointActivationTicketIsValid(ServiceEndpointActivationTicket ticket)
{
    return ticket.owner != nullptr && ServiceEndpointChannelKeyIsValid(ticket.channel) && ticket.nonce != 0;
}

struct ServiceEndpointPair
{
    ServiceEndpointOwnerReceipt owner;
    ServiceEndpointActivationTicket activation;
    ipc::KObject* initiator;
    ipc::KObject* acceptor;
    ServiceEndpointIdentity initiator_identity;
    ServiceEndpointIdentity acceptor_identity;
};

inline constexpr bool ServiceEndpointPairIsEmpty(const ServiceEndpointPair& pair)
{
    return !ServiceEndpointOwnerReceiptIsValid(pair.owner) &&
           !ServiceEndpointActivationTicketIsValid(pair.activation) && pair.initiator == nullptr &&
           pair.acceptor == nullptr && !ServiceEndpointIdentityIsValid(pair.initiator_identity) &&
           !ServiceEndpointIdentityIsValid(pair.acceptor_identity);
}

#if defined(DUETOS_HOST_TEST)
struct ServiceEndpointHostLock
{
    u32 next_ticket;
    u32 now_serving;
};
#endif

struct ServiceEndpointOwnerSlot
{
    ipc::ChannelCore core;
    ServiceEndpointObject endpoints[ipc::kChannelCoreDirectionCount];
    ipc::ChannelCoreDetachedCleanup detached_cleanup;
    ServiceEndpointRequestCleanupSink request_cleanup;
    ServiceEndpointChannelKey key;
    u64 activation_nonce;
    bool endpoint_reference_live[ipc::kChannelCoreDirectionCount];
    bool outer_owner_live;
    bool drain_driver_active;
    // Protected by the owner lock. A contender sets this before returning Busy
    // so the active driver cannot miss a last-pin release during unlocked drain
    // work. The driver clears it only while either retaining or relinquishing
    // drain authority under the same lock.
    bool drain_retry_requested;
    // Sticky quarantine: a detached request snapshot failed validation or
    // delivery and must never be forgotten by a later drain retry.
    bool request_cleanup_failed;
    ServiceEndpointSlotState state;
};

// Public only for fixed-capacity boot-global embedding and hostile host tests.
// Treat fields as opaque after ServiceEndpointOwnerInitialize.
struct ServiceEndpointOwner
{
    u32 initialized;
#if defined(DUETOS_HOST_TEST)
    ServiceEndpointHostLock lock;
#else
    sync::SpinLock lock;
#endif
    ServiceEndpointOwnerState state;
    ServiceEndpointOwnerSlot slots[kServiceEndpointOwnerCapacity];
};

struct [[nodiscard]] ServiceEndpointPairCreateResult
{
    ServiceEndpointStatus status;
    ipc::ChannelCoreStatus channel_status;
    ServiceEndpointPair pair;
};

enum class ServiceEndpointTrafficDirection : u8
{
    Send = 0,
    Receive,
};

inline constexpr bool ServiceEndpointTrafficDirectionIsValid(ServiceEndpointTrafficDirection direction)
{
    return direction == ServiceEndpointTrafficDirection::Send || direction == ServiceEndpointTrafficDirection::Receive;
}

inline constexpr ipc::ChannelCoreOperationBinding ServiceEndpointOperationBinding(ServiceEndpointRole role)
{
    return ServiceEndpointRoleIsValid(role)
               ? static_cast<ipc::ChannelCoreOperationBinding>(ServiceEndpointRoleIndex(role) + 1U)
               : ipc::kInvalidChannelCoreOperationBinding;
}

// Owns one endpoint KObject reference and one exact ChannelCore operation pin.
// The borrowed direction lease below is valid only until this receipt is
// consumed by ServiceEndpointReleaseOperation.
struct ServiceEndpointOperation
{
    ServiceEndpointObject* endpoint;
    ServiceEndpointIdentity identity;
    ipc::ChannelCoreOperationPin core_pin;
};

inline constexpr ServiceEndpointOperation kInvalidServiceEndpointOperation{
    nullptr,
    kInvalidServiceEndpointIdentity,
    ipc::kInvalidChannelCoreOperationPin,
};

inline constexpr bool ServiceEndpointOperationIsValid(const ServiceEndpointOperation& operation)
{
    return operation.endpoint != nullptr && ServiceEndpointIdentityIsValid(operation.identity) &&
           ipc::ChannelCoreOperationPinIsValid(operation.core_pin) &&
           operation.core_pin.binding == ServiceEndpointOperationBinding(operation.identity.role);
}

struct [[nodiscard]] ServiceEndpointOperationResult
{
    ServiceEndpointStatus status;
    ipc::ChannelCoreStatus channel_status;
    ServiceEndpointOperation operation;
};

struct [[nodiscard]] ServiceEndpointDirectionResult
{
    ServiceEndpointStatus status;
    ipc::ChannelCoreStatus channel_status;
    ipc::ChannelCoreDirectionLease lease;
};

struct [[nodiscard]] ServiceEndpointRequestReserveResult
{
    ServiceEndpointStatus status;
    ipc::ChannelCoreStatus channel_status;
    ipc::EndpointRequestLedgerStatus ledger_status;
    ipc::EndpointRequestKey request_key;
};

struct [[nodiscard]] ServiceEndpointRequestCommitResult
{
    ServiceEndpointStatus status;
    ipc::ChannelCoreStatus channel_status;
    ipc::EndpointRequestLedgerStatus ledger_status;
    ipc::EndpointRequestCompletionAuthority completion_authority;
};

struct [[nodiscard]] ServiceEndpointRequestTransitionResult
{
    ServiceEndpointStatus status;
    ipc::ChannelCoreStatus channel_status;
    ipc::EndpointRequestLedgerStatus ledger_status;
};

struct ServiceEndpointSnapshot
{
    ServiceEndpointChannelKey channel;
    ServiceEndpointSlotState state;
    bool outer_owner_live;
    bool endpoint_reference_live[ipc::kChannelCoreDirectionCount];
    bool drain_driver_active;
    bool drain_retry_requested;
    bool detached_cleanup_live;
    bool request_cleanup_failed;
};

struct [[nodiscard]] ServiceEndpointInspectResult
{
    ServiceEndpointStatus status;
    ServiceEndpointSnapshot snapshot;
};

ServiceEndpointStatus ServiceEndpointOwnerInitialize(ServiceEndpointOwner* owner);
bool ServiceEndpointOwnerIsReady(const ServiceEndpointOwner* owner);

// Construct a complete pair in private owner storage. Success returns exactly
// one reference for each endpoint KObject, one outer-owner receipt, and one
// activation ticket. The caller must transfer or release every component. The
// cleanup sink is copied by value, but its context is borrowed and must remain
// valid and callable until the pair has drained completely.
ServiceEndpointPairCreateResult ServiceEndpointCreatePair(ServiceEndpointOwner* owner,
                                                          ResourceDomainKey resource_domain,
                                                          const ServiceEndpointProtocolAuthority* protocol,
                                                          const ServiceEndpointPeerSnapshot* initiator,
                                                          const ServiceEndpointPeerSnapshot* acceptor,
                                                          const ServiceEndpointRequestCleanupSink* cleanup_sink);

// Consume the one-shot private activation ticket after the initiator handle is
// published and the acceptor reference is retained by a directory queue.
ServiceEndpointStatus ServiceEndpointActivate(ServiceEndpointActivationTicket* ticket);

// Request terminal drain and consume the exact outer-owner receipt only after
// request cleanup, detached resource release, and core pins have quiesced.
// Busy retains the receipt for a bounded retry.
ServiceEndpointStatus ServiceEndpointReleaseOwner(ServiceEndpointOwnerReceipt* receipt);

// Abort an unescaped private pair. Busy/cleanup failure preserves the remaining
// exact components in `pair`; success releases both KObject refs and clears it.
ServiceEndpointStatus ServiceEndpointAbortPair(ServiceEndpointPair* pair);

// `retained_object` must be a live ServiceEndpoint KObject reference. Acquire
// adds its own reference so callers may release the lookup result immediately.
ServiceEndpointOperationResult ServiceEndpointAcquireOperation(ipc::KObject* retained_object);
ServiceEndpointDirectionResult ServiceEndpointBorrowDirection(const ServiceEndpointOperation* operation,
                                                              ServiceEndpointTrafficDirection direction);

// Request lifecycle operations are role-constrained rather than accepting a
// caller-selected traffic direction. A sender may reserve or cancel only its
// outgoing requests. The peer may commit and complete only requests received
// through its incoming ledger. Keys and completion authority are additionally
// bound to the exact channel epoch and direction by ChannelCore.
ServiceEndpointRequestReserveResult ServiceEndpointReserveRequest(const ServiceEndpointOperation* operation,
                                                                  u64 request_id);
// Compatibility overload for existing transport callers. Receive is rejected;
// successful reservation is always bound to the caller's Send direction.
ServiceEndpointRequestReserveResult ServiceEndpointReserveRequest(const ServiceEndpointOperation* operation,
                                                                  ServiceEndpointTrafficDirection direction,
                                                                  u64 request_id);
ServiceEndpointRequestCommitResult ServiceEndpointCommitReceivedRequest(const ServiceEndpointOperation* operation,
                                                                        ipc::EndpointRequestKey request_key);
// Consume an invalid request from the caller's exact Receive ledger. The key
// is invalidated only after the cancellation succeeds, so failure retains the
// caller's precise settlement authority for terminal handling.
ServiceEndpointRequestTransitionResult ServiceEndpointRejectReceivedRequest(const ServiceEndpointOperation* operation,
                                                                            ipc::EndpointRequestKey* request_key);
ServiceEndpointRequestTransitionResult ServiceEndpointCancelSentRequest(const ServiceEndpointOperation* operation,
                                                                        ipc::EndpointRequestKey* request_key);
ServiceEndpointRequestTransitionResult ServiceEndpointCompleteReceivedRequest(
    const ServiceEndpointOperation* operation, ipc::EndpointRequestCompletionAuthority* completion_authority);
ServiceEndpointStatus ServiceEndpointReleaseOperation(ServiceEndpointOperation* operation);

// Value-only metadata inspection from a retained KObject; no owner/core pointer
// or borrowed lifetime escapes.
ServiceEndpointStatus ServiceEndpointInspectObject(ipc::KObject* retained_object, ServiceEndpointIdentity* identity,
                                                   ServiceEndpointProtocolAuthority* protocol,
                                                   ServiceEndpointPeerSnapshot* peer);
ServiceEndpointInspectResult ServiceEndpointInspectExact(ServiceEndpointOwner* owner,
                                                         ServiceEndpointChannelKey channel);
const char* ServiceEndpointStatusName(ServiceEndpointStatus status);

#if defined(DUETOS_HOST_TEST)
// Set a boot-global last-issued slot generation. Maximum permanently exhausts
// that slot. Call only with no concurrent endpoint construction.
bool ServiceEndpointHostSetLastGenerationForTest(u32 slot, u64 last_generation);
#endif

} // namespace duetos::core
