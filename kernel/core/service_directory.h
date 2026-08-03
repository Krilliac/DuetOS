#pragma once

/*
 * Fixed-capacity authenticated service registration and endpoint directory.
 *
 * Registrations, operation pins, queued connections, accepted ownership, and
 * publication drivers are exact generation-bearing records. Connect and Accept
 * reserve HandleTable rows invisibly and never call HandleTable, KObject,
 * ServiceEndpoint, cleanup callbacks, allocation, wait, or logging while the
 * directory lock is held.
 *
 * A queued record owns the unpublished acceptor KObject reference plus the one
 * ServiceEndpoint outer-owner receipt. Accept transfers the KObject reference
 * to an exact server handle while retaining the outer receipt in an accepted
 * tracker. Normal close consumes that tracker through
 * ServiceDirectoryReleaseAcceptedChannel; unregister/owner crash detach and
 * revoke both queued and accepted trackers, so accepted channels cannot escape
 * owner-crash cleanup. A row recycles only after operation/reservation pins,
 * queued/accepted/closing ownership, and external publication drivers all
 * quiesce.
 */

#include "core/service_endpoint.h"
#include "core/service_manifest.h"
#include "core/service_transition.h"
#include "ipc/handle_table.h"
#include "util/types.h"

#if !defined(DUETOS_HOST_TEST)
#include "sync/spinlock.h"
#endif

namespace duetos::core
{

inline constexpr u32 kServiceDirectoryCapacity = kServiceManifestMaximumServices;
inline constexpr u32 kServiceDirectoryNameCapacity = kServiceManifestServiceNameCapacity;
inline constexpr u32 kServiceDirectoryAcceptCapacity = 8;
inline constexpr u32 kServiceDirectoryAcceptedCapacity = 8;
inline constexpr u32 kServiceDirectoryProcessTeardownBatchCapacity = 4;
inline constexpr u32 kServiceDirectoryDeferredAcceptedCapacity =
    kServiceDirectoryCapacity * kServiceDirectoryAcceptedCapacity;
inline constexpr u32 kServiceDirectoryCloseBatchCapacity =
    kServiceDirectoryAcceptCapacity + kServiceDirectoryAcceptedCapacity;
inline constexpr u32 kServiceDirectoryOperationCapacity = 8;
inline constexpr u64 kServiceKeyGenerationMaximum = (1ULL << 51) - 1;
inline constexpr u32 kServiceDirectoryOperationGenerationMaximum = ~0U;
inline constexpr u32 kServiceDirectoryAcceptedGenerationMaximum = ~0U;

struct ServiceDirectoryName
{
    u8 length;
    u8 bytes[kServiceDirectoryNameCapacity];
};

bool ServiceDirectoryNameIsCanonical(const ServiceDirectoryName& name);

struct ServiceKey
{
    u32 slot;
    u64 generation;
};

inline constexpr ServiceKey kInvalidServiceKey{kServiceDirectoryCapacity, 0};

inline constexpr bool ServiceKeyIsValid(ServiceKey key)
{
    return key.slot < kServiceDirectoryCapacity && key.generation != 0 &&
           key.generation <= kServiceKeyGenerationMaximum;
}

inline constexpr bool operator==(ServiceKey lhs, ServiceKey rhs)
{
    return lhs.slot == rhs.slot && lhs.generation == rhs.generation;
}

struct ServiceRegistrationReservation
{
    ServiceKey service;
    u64 authority_generation;
};

inline constexpr ServiceRegistrationReservation kInvalidServiceRegistrationReservation{kInvalidServiceKey, 0};

inline constexpr bool ServiceRegistrationReservationIsValid(ServiceRegistrationReservation reservation)
{
    return ServiceKeyIsValid(reservation.service) && reservation.authority_generation != 0 &&
           reservation.authority_generation == reservation.service.generation;
}

struct ServiceDirectoryOperationPin
{
    ServiceKey service;
    u32 slot;
    u32 generation;
};

inline constexpr ServiceDirectoryOperationPin kInvalidServiceDirectoryOperationPin{
    kInvalidServiceKey,
    kServiceDirectoryOperationCapacity,
    0,
};

inline constexpr bool ServiceDirectoryOperationPinIsValid(ServiceDirectoryOperationPin pin)
{
    return ServiceKeyIsValid(pin.service) && pin.slot < kServiceDirectoryOperationCapacity && pin.generation != 0;
}

enum class ServiceDirectoryState : u8
{
    Uninitialized = 0,
    Open,
};

enum class ServiceDirectoryEntryState : u8
{
    Empty = 0,
    Reserved,
    Active,
    Closing,
    Retired,
};

enum class ServiceDirectoryCloseReason : u8
{
    None = 0,
    RegistrationAbort,
    Unregister,
    OwnerCrash,
};

enum class ServiceDirectoryStatus : u8
{
    Ok = 0,
    InvalidArgument,
    NotInitialized,
    AlreadyInitialized,
    CorruptState,
    NameConflict,
    ServiceConflict,
    CapacityExhausted,
    GenerationExhausted,
    NotFound,
    StaleKey,
    OwnerMismatch,
    CredentialMismatch,
    ProtocolMismatch,
    NotReady,
    Closing,
    ReservationConsumed,
    Busy,
    OperationIdentityExhausted,
    StaleOperation,
    QueueFull,
    QueueEmpty,
    AcceptedCapacityExhausted,
    StaleAcceptedChannel,
    EndpointCreateFailed,
    EndpointActivationFailed,
    EndpointReleaseFailed,
    HandleReserveFailed,
    HandlePublishFailed,
    HandleRollbackFailed,
};

enum class ServiceDirectoryOperationSlotState : u8
{
    Free = 0,
    Live,
    Retired,
};

struct ServiceDirectoryOperationSlot
{
    u32 generation;
    ServiceDirectoryOperationSlotState state;
};

using ServiceDirectoryRequestCleanupFn = ServiceEndpointRequestCleanupFn;
using ServiceDirectoryRequestCleanupSink = ServiceEndpointRequestCleanupSink;
inline constexpr ServiceDirectoryRequestCleanupSink kInvalidServiceDirectoryRequestCleanupSink =
    kInvalidServiceEndpointRequestCleanupSink;

inline constexpr bool ServiceDirectoryRequestCleanupSinkIsValid(const ServiceDirectoryRequestCleanupSink* sink)
{
    return ServiceEndpointRequestCleanupSinkIsValid(sink);
}

// Exact detached ownership driven only after every directory lock is absent.
// `unpublished_acceptor` is an owned KObject reference when non-null.
struct ServiceDirectoryOwnedChannel
{
    ServiceEndpointOwnerReceipt owner;
    ipc::KObject* unpublished_acceptor;
    bool release_driver_active;
};

inline constexpr bool ServiceDirectoryOwnedChannelIsEmpty(const ServiceDirectoryOwnedChannel& channel)
{
    return !ServiceEndpointOwnerReceiptIsValid(channel.owner) && channel.unpublished_acceptor == nullptr &&
           !channel.release_driver_active;
}

enum class ServiceDirectoryQueuedChannelState : u8
{
    Empty = 0,
    PendingClientPublish,
    Ready,
};

struct ServiceDirectoryQueuedChannel
{
    ServiceDirectoryOwnedChannel owned;
    ServiceEndpointChannelKey channel;
    ServiceDirectoryQueuedChannelState state;
};

struct ServiceDirectoryAcceptedChannelKey
{
    ServiceKey service;
    u32 slot;
    u32 generation;
    ServiceEndpointChannelKey channel;
};

inline constexpr ServiceDirectoryAcceptedChannelKey kInvalidServiceDirectoryAcceptedChannelKey{
    kInvalidServiceKey,
    kServiceDirectoryAcceptedCapacity,
    0,
    kInvalidServiceEndpointChannelKey,
};

inline constexpr bool ServiceDirectoryAcceptedChannelKeyIsValid(ServiceDirectoryAcceptedChannelKey key)
{
    return ServiceKeyIsValid(key.service) && key.slot < kServiceDirectoryAcceptedCapacity && key.generation != 0 &&
           ServiceEndpointChannelKeyIsValid(key.channel);
}

inline constexpr bool operator==(ServiceDirectoryAcceptedChannelKey lhs, ServiceDirectoryAcceptedChannelKey rhs)
{
    return lhs.service == rhs.service && lhs.slot == rhs.slot && lhs.generation == rhs.generation &&
           lhs.channel == rhs.channel;
}

enum class ServiceDirectoryAcceptedChannelState : u8
{
    Free = 0,
    Publishing,
    Published,
    Releasing,
    Retired,
};

struct ServiceDirectoryAcceptedChannel
{
    ServiceDirectoryAcceptedChannelKey key;
    ServiceEndpointOwnerReceipt owner;
    ProcessKey server_process;
    ipc::Handle server_handle;
    bool process_teardown_deferred;
    bool release_driver_active;
    ServiceDirectoryAcceptedChannelState state;
};

struct ServiceDirectoryCloseBatch
{
    ServiceDirectoryOwnedChannel channels[kServiceDirectoryCloseBatchCapacity];
    u32 count;
};

struct ServiceDirectoryRow
{
    ServiceDirectoryName name;
    ServiceInstanceToken owner;
    ServiceEndpointCredentialSnapshot owner_credential;
    ServiceKey key;
    u64 reservation_authority;
    u32 manifest_slot;
    u32 active_operations;
    u32 next_operation_hint;
    ServiceDirectoryOperationSlot operation_slots[kServiceDirectoryOperationCapacity];
    ServiceDirectoryQueuedChannel accept_queue[kServiceDirectoryAcceptCapacity];
    u32 accept_head;
    u32 accept_count;
    ServiceDirectoryAcceptedChannel accepted_channels[kServiceDirectoryAcceptedCapacity];
    u32 accepted_count;
    u32 next_accepted_hint;
    u32 external_publishers;
    ServiceDirectoryOwnedChannel closing_channels[kServiceDirectoryCloseBatchCapacity];
    u32 closing_count;
    u32 close_batch_outstanding;
    u32 close_driver_active;
    bool ready;
    ServiceDirectoryEntryState state;
    ServiceDirectoryCloseReason close_reason;
};

#if defined(DUETOS_HOST_TEST)
struct ServiceDirectoryHostLock
{
    u32 next_ticket;
    u32 now_serving;
};
#endif

// Public only for fixed-capacity boot-global embedding and hostile host tests.
// Treat every field as opaque after Initialize.
struct ServiceDirectory
{
    u32 initialized;
#if defined(DUETOS_HOST_TEST)
    ServiceDirectoryHostLock lock;
#else
    sync::SpinLock lock;
#endif
    ServiceDirectoryState state;
    ServiceEndpointOwner* endpoint_owner;
    u32 deferred_scan_hint;
    ServiceDirectoryRow rows[kServiceDirectoryCapacity];
};

struct [[nodiscard]] ServiceDirectoryReserveResult
{
    ServiceDirectoryStatus status;
    ServiceRegistrationReservation reservation;
};

struct [[nodiscard]] ServiceDirectoryLookupResult
{
    ServiceDirectoryStatus status;
    ServiceDirectoryOperationPin pin;
};

struct [[nodiscard]] ServiceDirectoryConnectResult
{
    ServiceDirectoryStatus status;
    ServiceEndpointStatus endpoint_status;
    ErrorCode handle_status;
    ipc::Handle client_handle;
    ServiceEndpointIdentity endpoint;
    // Non-empty only when an endpoint cleanup driver reported Busy/failure.
    // Caller serializes and retries ServiceDirectoryDrainOwnedChannel.
    ServiceDirectoryOwnedChannel rollback;
};

struct [[nodiscard]] ServiceDirectoryAcceptResult
{
    ServiceDirectoryStatus status;
    ServiceEndpointStatus endpoint_status;
    ErrorCode handle_status;
    ipc::Handle server_handle;
    ServiceEndpointIdentity endpoint;
    ServiceDirectoryAcceptedChannelKey accepted;
};

struct [[nodiscard]] ServiceDirectoryReleaseAcceptedResult
{
    ServiceDirectoryStatus status;
    ServiceEndpointStatus endpoint_status;
};

// Exact Process teardown ownership transfer. Every matching accepted row is
// marked in place under the directory lock, so this operation is idempotent
// and cannot encounter a second capacity limit. The retained owner receipt is
// the durable authority that permits generic Process handle teardown to
// continue before a peer operation pin drains.
struct [[nodiscard]] ServiceDirectoryDeferAcceptedProcessResult
{
    ServiceDirectoryStatus status;
    u32 newly_deferred_channels;
    u32 deferred_channels;
};

// One fair, bounded maintenance pass over all deferred accepted rows.
// `pending_channels` is an exact final rescan rather than attempt arithmetic.
struct [[nodiscard]] ServiceDirectoryDriveDeferredAcceptedResult
{
    ServiceDirectoryStatus status;
    ServiceEndpointStatus endpoint_status;
    u32 released_channels;
    u32 pending_channels;
};

struct [[nodiscard]] ServiceDirectoryCloseResult
{
    ServiceDirectoryStatus status;
    ServiceEndpointStatus endpoint_status;
    u32 drained_channels;
};

struct ServiceDirectoryEntrySnapshot
{
    ServiceKey key;
    ServiceDirectoryName name;
    ServiceInstanceToken owner;
    ServiceEndpointCredentialSnapshot owner_credential;
    u32 manifest_slot;
    u32 active_operations;
    u32 queued_channels;
    u32 accepted_channels;
    u32 closing_channels;
    u32 external_publishers;
    bool reservation_live;
    bool ready;
    ServiceDirectoryEntryState state;
    ServiceDirectoryCloseReason close_reason;
};

struct [[nodiscard]] ServiceDirectoryInspectResult
{
    ServiceDirectoryStatus status;
    ServiceDirectoryEntrySnapshot snapshot;
};

ServiceDirectoryStatus ServiceDirectoryInitialize(ServiceDirectory* directory, ServiceEndpointOwner* endpoint_owner);

// Runtime-owner coherence probe. It acquires only the directory lock and
// verifies canonical Open state plus the exact embedded endpoint-owner
// identity. It performs no endpoint operation, allocation, callback, wait,
// logging, or external release.
ServiceDirectoryStatus ServiceDirectoryValidateRuntimeOwner(ServiceDirectory* directory,
                                                            const ServiceEndpointOwner* expected_endpoint_owner);

ServiceDirectoryReserveResult ServiceDirectoryReserveRegistration(
    ServiceDirectory* directory, const ServiceDirectoryName* name, u32 manifest_slot, ServiceInstanceToken owner,
    const ServiceEndpointCredentialSnapshot* owner_credential);
// Safe as the final nested operation in scheduler -> lifecycle -> directory
// publication. It mutates only the exact Reserved row and performs no
// endpoint, HandleTable, allocation, callback, destructor, logging, or wait.
ServiceDirectoryStatus ServiceDirectoryPublishRegistration(ServiceDirectory* directory,
                                                           ServiceRegistrationReservation* reservation,
                                                           ServiceInstanceToken owner);

// Kernel-internal, single-callsite readiness commit leaf for
// ServiceLifecycleBrokerMarkReady; it is not independent directory authority
// and no other production caller may invoke it. The caller holds the higher-
// ranked lifecycle-broker lock continuously and supplies its prevalidated
// exact row's borrowed ready bit. This operation takes the directory lock,
// prevalidates the exact Active row and owner, then writes directory readiness
// followed by lifecycle readiness before releasing either lock. No fallible
// operation remains after the first write, and exact replay is idempotent. No
// endpoint, HandleTable, allocation, callback, destructor, logging, scheduler
// call, or wait occurs here.
// [lifecycle-broker lock held; nonblocking]
ServiceDirectoryStatus ServiceDirectoryCommitJointReady(ServiceDirectory* directory, ServiceKey service,
                                                        ServiceInstanceToken owner, bool* lifecycle_ready);
ServiceDirectoryStatus ServiceDirectoryAbortRegistration(ServiceDirectory* directory,
                                                         ServiceRegistrationReservation* reservation,
                                                         ServiceInstanceToken owner);

ServiceDirectoryLookupResult ServiceDirectoryLookup(ServiceDirectory* directory, const ServiceDirectoryName* name);
ServiceDirectoryStatus ServiceDirectoryReleaseOperation(ServiceDirectory* directory, ServiceDirectoryOperationPin* pin);

// Reserve the client handle invisibly, construct the complete private pair,
// enqueue an acceptor record that Accept cannot yet see, publish and activate
// the initiator outside the directory lock, then make the queue entry Ready.
// The cleanup sink context is borrowed through terminal channel drain.
ServiceDirectoryConnectResult ServiceDirectoryConnect(ServiceDirectory* directory, ServiceDirectoryOperationPin pin,
                                                      ResourceDomainKey resource_domain,
                                                      ipc::HandleTable* client_handles, ProcessKey client_process,
                                                      const ServiceEndpointCredentialSnapshot* client_credential,
                                                      const ServiceEndpointProtocolAuthority* protocol,
                                                      u64 client_handle_rights,
                                                      const ServiceDirectoryRequestCleanupSink* cleanup_sink);

// Reserve the server handle before claiming a Ready entry. The accepted owner
// record is installed under the directory lock; KObject publication happens
// outside it and either commits the exact accepted token or restores/revokes
// the record without exposing an unowned server endpoint.
ServiceDirectoryAcceptResult ServiceDirectoryAccept(ServiceDirectory* directory, ServiceKey service,
                                                    ServiceInstanceToken owner, ipc::HandleTable* server_handles,
                                                    ProcessKey server_process,
                                                    const ServiceEndpointCredentialSnapshot* server_credential,
                                                    u64 server_handle_rights);

// Normal accepted-handle teardown releases the retained directory owner. The
// exact key is consumed only after endpoint drain completes. Re-entry while the
// external cleanup driver is active reports Busy and leaves the token live.
ServiceDirectoryReleaseAcceptedResult ServiceDirectoryReleaseAcceptedChannel(
    ServiceDirectory* directory, ServiceDirectoryAcceptedChannelKey* accepted);

// Close adapter for a published server endpoint handle. The caller must invoke
// this before removing the exact handle from the server HandleTable. Resolution
// uses the full ProcessKey plus generation-bearing handle, snapshots the exact
// accepted key under the directory lock, then delegates the potentially
// re-entrant endpoint drain after dropping that lock. A client endpoint or a
// stale/replayed server handle returns NotFound and releases no ownership.
ServiceDirectoryReleaseAcceptedResult ServiceDirectoryReleaseAcceptedHandle(ServiceDirectory* directory,
                                                                            ProcessKey server_process,
                                                                            ipc::Handle server_handle);

// Process teardown adapter. Marks every exact ProcessKey row as deferred in
// place while holding only the directory lock. No endpoint/KObject operation
// occurs and no new row is allocated. Once this succeeds, the Process may
// drain its raw HandleTable: the accepted row still retains the boot-global
// endpoint owner until maintenance completes it. Stale ProcessKeys are
// idempotent no-ops.
// [task context, any task/CPU, thread-safe]
ServiceDirectoryDeferAcceptedProcessResult ServiceDirectoryDeferAcceptedProcess(ServiceDirectory* directory,
                                                                                ProcessKey server_process);

// Fair global maintenance adapter. A rotating flattened scan snapshots at
// most one fixed-size batch of exact accepted keys under the directory lock,
// invokes every owner release only after dropping that lock, then exactly
// rescans all deferred rows. Busy preserves the row and its strong receipt.
// [task context, no scheduler/Process/directory lock held]
ServiceDirectoryDriveDeferredAcceptedResult ServiceDirectoryDriveDeferredAccepted(ServiceDirectory* directory);

// Caller-serialized detached rollback/close ownership. KObject release and
// request cleanup occur only after all directory and endpoint-owner locks are
// absent. Busy retains the exact receipt for retry.
ServiceEndpointStatus ServiceDirectoryDrainOwnedChannel(ServiceDirectoryOwnedChannel* channel);

ServiceDirectoryCloseResult ServiceDirectoryUnregister(ServiceDirectory* directory, ServiceKey service,
                                                       ServiceInstanceToken owner);
ServiceDirectoryCloseResult ServiceDirectoryOwnerCrashed(ServiceDirectory* directory, ServiceKey service,
                                                         ServiceInstanceToken owner);

ServiceDirectoryInspectResult ServiceDirectoryInspectExact(ServiceDirectory* directory, ServiceKey service);
const char* ServiceDirectoryStatusName(ServiceDirectoryStatus status);

#if defined(DUETOS_HOST_TEST)
using ServiceDirectoryHostPublicationHook = void (*)(void* context);

// One-shot deterministic seams immediately after directory ownership is
// installed and before client/server HandleTable publication. Hooks run with no
// directory, endpoint-owner, ChannelCore, or HandleTable lock held.
void ServiceDirectoryHostArmConnectPublicationHookForTest(ServiceDirectoryHostPublicationHook hook, void* context);
void ServiceDirectoryHostArmAcceptPublicationHookForTest(ServiceDirectoryHostPublicationHook hook, void* context);

// One-shot, allocation-free failure at the final registration-publication
// rung. No callback runs while the directory (or outer lifecycle) lock is held.
void ServiceDirectoryHostFailNextRegistrationPublicationForTest();

bool ServiceDirectoryHostSetLastGenerationForTest(u32 slot, u64 last_generation);
#endif

} // namespace duetos::core
