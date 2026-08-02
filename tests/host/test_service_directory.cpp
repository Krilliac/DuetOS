// Hosted hostile registration, failure-atomic handle publication, accepted
// ownership, owner-crash, ABA, queue/full-table, and close-race coverage.

#include "host_test_helper.h"
#include "core/service_directory.h"

#include <array>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <latch>
#include <mutex>
#include <new>
#include <thread>

// Exercise real ResourceDomain channel accounting.
#include "proc/resource_domain.cpp"

namespace
{

std::mutex g_host_spinlock;
std::mutex g_object_lock;
std::atomic<duetos::u32> g_port_create_calls{0};
std::atomic<duetos::u32> g_port_destroy_calls{0};

} // namespace

namespace duetos::core
{

[[noreturn]] void Panic(const char* subsystem, const char* message)
{
    (void)subsystem;
    (void)message;
    std::abort();
}

[[noreturn]] void PanicWithValue(const char* subsystem, const char* message, u64 value)
{
    (void)subsystem;
    (void)message;
    (void)value;
    std::abort();
}

} // namespace duetos::core

namespace duetos::sync
{

IrqFlags SpinLockAcquire(SpinLock&)
{
    g_host_spinlock.lock();
    return IrqFlags{0};
}

void SpinLockRelease(SpinLock&, IrqFlags)
{
    g_host_spinlock.unlock();
}

} // namespace duetos::sync

namespace duetos::ipc
{

namespace
{

void DestroyHostedPort(KObject* object)
{
    g_port_destroy_calls.fetch_add(1, std::memory_order_relaxed);
    delete reinterpret_cast<KMessagePort*>(object);
}

} // namespace

void KObjectInit(KObject* object, KObjectType type, KObjectDestroyFn destroy)
{
    object->type = type;
    object->refcount = 1;
    object->destroy = destroy;
}

bool KObjectAcquire(KObject* object)
{
    if (object == nullptr)
        return false;
    std::lock_guard<std::mutex> guard(g_object_lock);
    if (object->refcount == 0 || object->refcount == static_cast<u32>(-1))
        return false;
    ++object->refcount;
    return true;
}

void KObjectRelease(KObject* object)
{
    if (object == nullptr)
        return;
    KObjectDestroyFn destroy = nullptr;
    {
        std::lock_guard<std::mutex> guard(g_object_lock);
        if (object->refcount == 0)
            return;
        --object->refcount;
        if (object->refcount == 0)
            destroy = object->destroy;
    }
    if (destroy != nullptr)
        destroy(object);
}

u32 KObjectRefcount(const KObject* object)
{
    if (object == nullptr)
        return 0;
    std::lock_guard<std::mutex> guard(g_object_lock);
    return object->refcount;
}

::duetos::core::Result<KMessagePort*> KMessagePortCreate()
{
    auto* port = new (std::nothrow) KMessagePort{};
    if (port == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::OutOfMemory};
    KObjectInit(&port->base, KObjectType::MessagePort, &DestroyHostedPort);
    g_port_create_calls.fetch_add(1, std::memory_order_relaxed);
    return port;
}

void KMessagePortClose(KMessagePort* port)
{
    if (port == nullptr)
        return;
    std::lock_guard<std::mutex> guard(port->inner);
    port->closed = true;
}

ObjectTransferStatus ObjectTransferTableInitialize(ObjectTransferTable* table, u32 first_generation)
{
    if (table == nullptr || first_generation == 0 || first_generation > kObjectTransferGenerationMax)
        return ObjectTransferStatus::InvalidArgument;
    if (table->initialized != 0)
        return ObjectTransferStatus::AlreadyInitialized;
    table->initialized = 1;
    table->state = ObjectTransferTableState::Open;
    return ObjectTransferStatus::Ok;
}

ObjectTransferStatus ObjectTransferTableClose(ObjectTransferTable* table)
{
    if (table == nullptr)
        return ObjectTransferStatus::InvalidArgument;
    if (table->initialized != 1)
        return ObjectTransferStatus::NotInitialized;
    table->state = ObjectTransferTableState::Closed;
    return ObjectTransferStatus::Ok;
}

} // namespace duetos::ipc

namespace
{

using duetos::u32;
using duetos::u64;
using namespace duetos::core;
using namespace duetos::ipc;

inline constexpr u64 kEndpointRights = kHandleRightRead | kHandleRightWrite | kHandleRightWait | kHandleRightDestroy;

struct CleanupCollector
{
    std::array<EndpointRequestKey, 64> keys{};
    std::atomic<u32> count{0};
    std::atomic<bool> reentered{false};
    ServiceDirectory* reenter_directory = nullptr;
    ServiceDirectoryAcceptedChannelKey* reenter_accepted = nullptr;
    std::atomic<ServiceDirectoryStatus> reenter_status{ServiceDirectoryStatus::Ok};
    std::atomic<ServiceEndpointStatus> reenter_endpoint_status{ServiceEndpointStatus::Ok};
};

void CollectCleanup(void* context, EndpointRequestKey key)
{
    auto& collector = *static_cast<CleanupCollector*>(context);
    const u32 index = collector.count.fetch_add(1, std::memory_order_acq_rel);
    if (index < collector.keys.size())
        collector.keys[index] = key;
    bool expected = false;
    if (collector.reenter_directory != nullptr && collector.reenter_accepted != nullptr &&
        collector.reentered.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
    {
        const ServiceDirectoryReleaseAcceptedResult result =
            ServiceDirectoryReleaseAcceptedChannel(collector.reenter_directory, collector.reenter_accepted);
        collector.reenter_status.store(result.status, std::memory_order_release);
        collector.reenter_endpoint_status.store(result.endpoint_status, std::memory_order_release);
    }
}

CredentialSecurityContext Security(u32 uid)
{
    CredentialSecurityContext security{};
    security.real_uid = uid;
    security.effective_uid = uid;
    security.saved_uid = uid;
    security.fs_uid = uid;
    security.real_gid = uid;
    security.effective_gid = uid;
    security.saved_gid = uid;
    security.fs_gid = uid;
    security.win32_integrity = Win32IntegrityLevel::Low;
    EXPECT_TRUE(CredentialSecurityContextIsCanonical(security));
    return security;
}

ServiceEndpointCredentialSnapshot Credential(u32 slot, u64 generation, u32 uid)
{
    return ServiceEndpointCredentialSnapshot{CredentialKey{slot, generation}, Security(uid)};
}

ServiceDirectoryName Name(const char* text)
{
    ServiceDirectoryName name{};
    const size_t length = std::strlen(text);
    EXPECT_TRUE(length <= kServiceDirectoryNameCapacity);
    name.length = static_cast<duetos::u8>(length);
    for (u32 index = 0; index < name.length; ++index)
        name.bytes[index] = static_cast<duetos::u8>(text[index]);
    return name;
}

ServiceInstanceToken Owner(u64 service_identity, u64 start_generation, u64 process_identity, u64 pid)
{
    return ServiceInstanceToken{ServiceStartTicket{service_identity, start_generation},
                                ServiceInstanceKey{process_identity, pid}};
}

ProcessKey ProcessOf(ServiceInstanceToken owner)
{
    return ProcessKey{owner.process.process_identity, owner.process.pid};
}

ServiceEndpointProtocolAuthority Protocol(u64 service_identity)
{
    return ServiceEndpointProtocolAuthority{0xA110U, 0x5010U, service_identity, 0x3FU, 1, 0, 0x51U, 0};
}

ResourceDomainKey CreateDomain()
{
    ResourceDomainKey domain = kInvalidResourceDomainKey;
    EXPECT_TRUE(ResourceDomainCreateAuthenticatedService(&domain));
    return domain;
}

ServiceKey Register(ServiceDirectory& directory, const ServiceDirectoryName& name, u32 manifest_slot,
                    ServiceInstanceToken owner, const ServiceEndpointCredentialSnapshot& credential)
{
    ServiceDirectoryReserveResult reserved =
        ServiceDirectoryReserveRegistration(&directory, &name, manifest_slot, owner, &credential);
    EXPECT_EQ(reserved.status, ServiceDirectoryStatus::Ok);
    const ServiceKey key = reserved.reservation.service;
    EXPECT_EQ(ServiceDirectoryPublishRegistration(&directory, &reserved.reservation, owner),
              ServiceDirectoryStatus::Ok);
    bool lifecycle_ready = false;
    EXPECT_EQ(ServiceDirectoryCommitJointReady(&directory, key, owner, &lifecycle_ready), ServiceDirectoryStatus::Ok);
    EXPECT_TRUE(lifecycle_ready);
    return key;
}

ServiceDirectoryOperationPin Lookup(ServiceDirectory& directory, const ServiceDirectoryName& name)
{
    const ServiceDirectoryLookupResult lookup = ServiceDirectoryLookup(&directory, &name);
    EXPECT_EQ(lookup.status, ServiceDirectoryStatus::Ok);
    return lookup.pin;
}

ServiceDirectoryConnectResult Connect(ServiceDirectory& directory, ServiceDirectoryOperationPin pin,
                                      ResourceDomainKey domain, HandleTable& client_handles, ProcessKey client,
                                      const ServiceEndpointCredentialSnapshot& credential,
                                      const ServiceEndpointProtocolAuthority& protocol, CleanupCollector& collector)
{
    const ServiceDirectoryRequestCleanupSink sink{&CollectCleanup, &collector};
    return ServiceDirectoryConnect(&directory, pin, domain, &client_handles, client, &credential, &protocol,
                                   kEndpointRights, &sink);
}

ServiceDirectoryAcceptResult Accept(ServiceDirectory& directory, ServiceKey service, ServiceInstanceToken owner,
                                    HandleTable& server_handles,
                                    const ServiceEndpointCredentialSnapshot& server_credential)
{
    return ServiceDirectoryAccept(&directory, service, owner, &server_handles, ProcessOf(owner), &server_credential,
                                  kEndpointRights);
}

ServiceDirectoryEntrySnapshot Inspect(ServiceDirectory& directory, ServiceKey service)
{
    const ServiceDirectoryInspectResult inspected = ServiceDirectoryInspectExact(&directory, service);
    EXPECT_EQ(inspected.status, ServiceDirectoryStatus::Ok);
    return inspected.snapshot;
}

void CloseHandle(HandleTable& table, Handle handle)
{
    const Result<void> removed = HandleTableRemove(table, handle);
    EXPECT_TRUE(removed.has_value());
}

struct PublicationGate
{
    std::latch entered{1};
    std::latch release{1};
};

void BlockPublication(void* context)
{
    auto& gate = *static_cast<PublicationGate*>(context);
    gate.entered.count_down();
    gate.release.wait();
}

u32 FillReservations(HandleTable& table, std::array<HandleTableReservation, kHandleTableCapacity - 1U>& reservations)
{
    u32 count = 0;
    while (count < reservations.size())
    {
        Result<HandleTableReservation> reserved =
            HandleTableReserve(table, KObjectType::ServiceEndpoint, kEndpointRights);
        if (!reserved.has_value())
            break;
        reservations[count++] = reserved.value();
    }
    return count;
}

void AbortReservations(HandleTable& table,
                       const std::array<HandleTableReservation, kHandleTableCapacity - 1U>& reservations, u32 count)
{
    for (u32 index = 0; index < count; ++index)
        EXPECT_TRUE(HandleTableAbort(table, reservations[index]).has_value());
}

} // namespace

int main()
{
    using namespace duetos::core;
    using namespace duetos::ipc;

    static ServiceEndpointOwner uninitialized_endpoint_owner{};
    static ServiceDirectory rejected_directory{};
    EXPECT_EQ(ServiceDirectoryInitialize(&rejected_directory, &uninitialized_endpoint_owner),
              ServiceDirectoryStatus::NotInitialized);

    static ServiceEndpointOwner endpoint_owner{};
    static ServiceDirectory directory{};
    EXPECT_EQ(ServiceEndpointOwnerInitialize(&endpoint_owner), ServiceEndpointStatus::Ok);
    EXPECT_EQ(ServiceDirectoryInitialize(&directory, &endpoint_owner), ServiceDirectoryStatus::Ok);

    ResourceDomainKey domain = CreateDomain();
    const ServiceEndpointCredentialSnapshot server_credential = Credential(1, 1, 2001);
    const ServiceEndpointCredentialSnapshot client_credential = Credential(2, 1, 1001);
    const ProcessKey client_process{0x1001U, 101};

    // Registration reservation and lookup receipts remain exact and replay-safe.
    const ServiceDirectoryName alpha_name = Name("alpha.service");
    const ServiceInstanceToken alpha_owner = Owner(0xA1U, 1, 0x2001U, 201);
    ServiceDirectoryReserveResult alpha_reserved =
        ServiceDirectoryReserveRegistration(&directory, &alpha_name, 0, alpha_owner, &server_credential);
    EXPECT_EQ(alpha_reserved.status, ServiceDirectoryStatus::Ok);
    const ServiceRegistrationReservation alpha_replay = alpha_reserved.reservation;
    const ServiceKey alpha = alpha_reserved.reservation.service;
    EXPECT_EQ(ServiceDirectoryLookup(&directory, &alpha_name).status, ServiceDirectoryStatus::NotReady);
    EXPECT_EQ(ServiceDirectoryPublishRegistration(&directory, &alpha_reserved.reservation, alpha_owner),
              ServiceDirectoryStatus::Ok);
    ServiceRegistrationReservation stale_registration = alpha_replay;
    EXPECT_EQ(ServiceDirectoryPublishRegistration(&directory, &stale_registration, alpha_owner),
              ServiceDirectoryStatus::ReservationConsumed);

    ServiceDirectoryOperationPin alpha_pin = Lookup(directory, alpha_name);
    const ServiceDirectoryOperationPin alpha_pin_replay = alpha_pin;
    HandleTable client_handles{};
    HandleTable server_handles{};
    CleanupCollector alpha_cleanup{};
    const ServiceEndpointProtocolAuthority alpha_protocol = Protocol(alpha_owner.start.service_identity);

    // Publication makes the service discoverable, but CONNECT remains closed
    // until the exact lifecycle owner commits readiness. The lookup pin is
    // reusable after this fail-closed observation.
    EXPECT_EQ(Connect(directory, alpha_pin, domain, client_handles, client_process, client_credential, alpha_protocol,
                      alpha_cleanup)
                  .status,
              ServiceDirectoryStatus::NotReady);
    EXPECT_EQ(HandleTableLiveCount(client_handles), 0U);
    bool alpha_lifecycle_ready = false;
    EXPECT_EQ(ServiceDirectoryCommitJointReady(&directory, alpha, alpha_owner, &alpha_lifecycle_ready),
              ServiceDirectoryStatus::Ok);
    EXPECT_TRUE(alpha_lifecycle_ready);

    ServiceEndpointProtocolAuthority wrong_protocol = alpha_protocol;
    ++wrong_protocol.service_identity;
    EXPECT_EQ(Connect(directory, alpha_pin, domain, client_handles, client_process, client_credential, wrong_protocol,
                      alpha_cleanup)
                  .status,
              ServiceDirectoryStatus::ProtocolMismatch);
    EXPECT_EQ(HandleTableLiveCount(client_handles), 0U);

    ServiceDirectoryConnectResult connected = Connect(directory, alpha_pin, domain, client_handles, client_process,
                                                      client_credential, alpha_protocol, alpha_cleanup);
    EXPECT_EQ(connected.status, ServiceDirectoryStatus::Ok);
    EXPECT_NE(connected.client_handle, kHandleInvalid);
    EXPECT_TRUE(ServiceDirectoryOwnedChannelIsEmpty(connected.rollback));
    EXPECT_EQ(HandleTableLiveCount(client_handles), 1U);
    EXPECT_EQ(Inspect(directory, alpha).queued_channels, 1U);

    ServiceEndpointCredentialSnapshot wrong_server_credential = server_credential;
    ++wrong_server_credential.key.generation;
    EXPECT_EQ(Accept(directory, alpha, alpha_owner, server_handles, wrong_server_credential).status,
              ServiceDirectoryStatus::CredentialMismatch);
    EXPECT_EQ(Inspect(directory, alpha).queued_channels, 1U);

    ServiceDirectoryAcceptResult accepted = Accept(directory, alpha, alpha_owner, server_handles, server_credential);
    EXPECT_EQ(accepted.status, ServiceDirectoryStatus::Ok);
    EXPECT_NE(accepted.server_handle, kHandleInvalid);
    EXPECT_EQ(HandleTableLiveCount(server_handles), 1U);
    EXPECT_EQ(Inspect(directory, alpha).queued_channels, 0U);
    EXPECT_EQ(Inspect(directory, alpha).accepted_channels, 1U);

    // The accepted tracker is an exact generation-bearing owner. A callback
    // from request cleanup may re-enter its release hook but cannot double-drive
    // the active ownership receipt.
    KObject* client_endpoint =
        HandleTableLookupRef(client_handles, connected.client_handle, KObjectType::ServiceEndpoint, kHandleRightWrite);
    ASSERT_TRUE(client_endpoint != nullptr);
    ServiceEndpointOperationResult request_operation = ServiceEndpointAcquireOperation(client_endpoint);
    KObjectRelease(client_endpoint);
    EXPECT_EQ(request_operation.status, ServiceEndpointStatus::Ok);
    const ServiceEndpointRequestReserveResult pending_request =
        ServiceEndpointReserveRequest(&request_operation.operation, ServiceEndpointTrafficDirection::Send, 1);
    EXPECT_EQ(pending_request.status, ServiceEndpointStatus::Ok);
    EXPECT_EQ(ServiceEndpointReleaseOperation(&request_operation.operation), ServiceEndpointStatus::Ok);

    const ServiceDirectoryAcceptedChannelKey accepted_replay = accepted.accepted;
    alpha_cleanup.reenter_directory = &directory;
    alpha_cleanup.reenter_accepted = &accepted.accepted;
    const ServiceDirectoryReleaseAcceptedResult released_accepted =
        ServiceDirectoryReleaseAcceptedChannel(&directory, &accepted.accepted);
    EXPECT_EQ(released_accepted.status, ServiceDirectoryStatus::Ok);
    EXPECT_EQ(alpha_cleanup.count.load(std::memory_order_acquire), 1U);
    EXPECT_EQ(alpha_cleanup.keys[0], pending_request.request_key);
    EXPECT_EQ(alpha_cleanup.reenter_status.load(std::memory_order_acquire), ServiceDirectoryStatus::Busy);
    EXPECT_EQ(alpha_cleanup.reenter_endpoint_status.load(std::memory_order_acquire), ServiceEndpointStatus::Busy);
    ServiceDirectoryAcceptedChannelKey stale_accepted = accepted_replay;
    EXPECT_EQ(ServiceDirectoryReleaseAcceptedChannel(&directory, &stale_accepted).status,
              ServiceDirectoryStatus::StaleAcceptedChannel);

    CloseHandle(client_handles, connected.client_handle);
    CloseHandle(server_handles, accepted.server_handle);
    EXPECT_EQ(Inspect(directory, alpha).accepted_channels, 0U);

    // Normal server-handle close resolves the exact accepted ownership by the
    // full server ProcessKey plus generation-bearing handle. Wrong owners,
    // malformed handles, and replayed closes cannot release a newer channel.
    ServiceDirectoryConnectResult close_connected = Connect(
        directory, alpha_pin, domain, client_handles, client_process, client_credential, alpha_protocol, alpha_cleanup);
    EXPECT_EQ(close_connected.status, ServiceDirectoryStatus::Ok);
    ServiceDirectoryAcceptResult close_accepted =
        Accept(directory, alpha, alpha_owner, server_handles, server_credential);
    EXPECT_EQ(close_accepted.status, ServiceDirectoryStatus::Ok);
    EXPECT_EQ(Inspect(directory, alpha).accepted_channels, 1U);
    ProcessKey wrong_server_process = ProcessOf(alpha_owner);
    ++wrong_server_process.identity;
    EXPECT_EQ(
        ServiceDirectoryReleaseAcceptedHandle(&directory, wrong_server_process, close_accepted.server_handle).status,
        ServiceDirectoryStatus::NotFound);
    EXPECT_EQ(ServiceDirectoryReleaseAcceptedHandle(&directory, ProcessOf(alpha_owner), kHandleInvalid).status,
              ServiceDirectoryStatus::InvalidArgument);
    EXPECT_EQ(
        ServiceDirectoryReleaseAcceptedHandle(&directory, ProcessOf(alpha_owner), close_accepted.server_handle).status,
        ServiceDirectoryStatus::Ok);
    EXPECT_EQ(Inspect(directory, alpha).accepted_channels, 0U);
    EXPECT_EQ(
        ServiceDirectoryReleaseAcceptedHandle(&directory, ProcessOf(alpha_owner), close_accepted.server_handle).status,
        ServiceDirectoryStatus::NotFound);
    ServiceDirectoryAcceptedChannelKey close_stale_key = close_accepted.accepted;
    EXPECT_EQ(ServiceDirectoryReleaseAcceptedChannel(&directory, &close_stale_key).status,
              ServiceDirectoryStatus::StaleAcceptedChannel);
    CloseHandle(client_handles, close_connected.client_handle);
    CloseHandle(server_handles, close_accepted.server_handle);
    EXPECT_EQ(ServiceDirectoryReleaseOperation(&directory, &alpha_pin), ServiceDirectoryStatus::Ok);
    ServiceDirectoryOperationPin copied_pin = alpha_pin_replay;
    EXPECT_EQ(ServiceDirectoryReleaseOperation(&directory, &copied_pin), ServiceDirectoryStatus::StaleOperation);
    EXPECT_EQ(ServiceDirectoryUnregister(&directory, alpha, alpha_owner).status, ServiceDirectoryStatus::Ok);

    // A full client table fails before endpoint construction and leaves the
    // listener queue unchanged. Reserved handle rows remain invisible.
    const ServiceDirectoryName full_name = Name("full.service");
    const ServiceInstanceToken full_owner = Owner(0xB1U, 1, 0x3001U, 301);
    const ServiceEndpointCredentialSnapshot full_server_credential = Credential(3, 1, 3001);
    const ServiceKey full_service = Register(directory, full_name, 1, full_owner, full_server_credential);
    ServiceDirectoryOperationPin full_pin = Lookup(directory, full_name);
    HandleTable full_client_table{};
    std::array<HandleTableReservation, kHandleTableCapacity - 1U> full_reservations{};
    const u32 full_count = FillReservations(full_client_table, full_reservations);
    EXPECT_EQ(full_count, kHandleTableCapacity - 1U);
    EXPECT_EQ(HandleTableLiveCount(full_client_table), 0U);
    CleanupCollector full_cleanup{};
    EXPECT_EQ(Connect(directory, full_pin, domain, full_client_table, client_process, client_credential,
                      Protocol(full_owner.start.service_identity), full_cleanup)
                  .status,
              ServiceDirectoryStatus::HandleReserveFailed);
    EXPECT_EQ(Inspect(directory, full_service).queued_channels, 0U);
    AbortReservations(full_client_table, full_reservations, full_count);

    // Fill the bounded listener queue. The ninth connect rolls back its private
    // pair and invisible reservation without publishing a client handle.
    HandleTable queue_clients{};
    std::array<Handle, kServiceDirectoryAcceptCapacity> queued_handles{};
    for (u32 index = 0; index < kServiceDirectoryAcceptCapacity; ++index)
    {
        ServiceDirectoryConnectResult queued =
            Connect(directory, full_pin, domain, queue_clients, client_process, client_credential,
                    Protocol(full_owner.start.service_identity), full_cleanup);
        EXPECT_EQ(queued.status, ServiceDirectoryStatus::Ok);
        queued_handles[index] = queued.client_handle;
    }
    HandleTable overflow_client{};
    ServiceDirectoryConnectResult overflow =
        Connect(directory, full_pin, domain, overflow_client, client_process, client_credential,
                Protocol(full_owner.start.service_identity), full_cleanup);
    EXPECT_EQ(overflow.status, ServiceDirectoryStatus::QueueFull);
    EXPECT_EQ(HandleTableLiveCount(overflow_client), 0U);
    EXPECT_TRUE(ServiceDirectoryOwnedChannelIsEmpty(overflow.rollback));
    EXPECT_EQ(Inspect(directory, full_service).queued_channels, kServiceDirectoryAcceptCapacity);

    ServiceDirectoryCloseResult full_crash = ServiceDirectoryOwnerCrashed(&directory, full_service, full_owner);
    EXPECT_EQ(full_crash.status, ServiceDirectoryStatus::Busy);
    EXPECT_EQ(full_crash.drained_channels, kServiceDirectoryAcceptCapacity);
    for (Handle handle : queued_handles)
        CloseHandle(queue_clients, handle);
    EXPECT_EQ(ServiceDirectoryReleaseOperation(&directory, &full_pin), ServiceDirectoryStatus::Ok);
    EXPECT_EQ(ServiceDirectoryOwnerCrashed(&directory, full_service, full_owner).status,
              ServiceDirectoryStatus::StaleKey);

    // Accept handle exhaustion leaves the exact Ready queue entry available for
    // retry. Once capacity returns, publication succeeds normally.
    const ServiceDirectoryName accept_full_name = Name("accept-full.service");
    const ServiceInstanceToken accept_full_owner = Owner(0xC1U, 1, 0x4001U, 401);
    const ServiceEndpointCredentialSnapshot accept_full_credential = Credential(4, 1, 4001);
    const ServiceKey accept_full_service =
        Register(directory, accept_full_name, 2, accept_full_owner, accept_full_credential);
    ServiceDirectoryOperationPin accept_full_pin = Lookup(directory, accept_full_name);
    HandleTable accept_full_client{};
    CleanupCollector accept_full_cleanup{};
    const ServiceDirectoryConnectResult accept_full_connected =
        Connect(directory, accept_full_pin, domain, accept_full_client, client_process, client_credential,
                Protocol(accept_full_owner.start.service_identity), accept_full_cleanup);
    EXPECT_EQ(accept_full_connected.status, ServiceDirectoryStatus::Ok);
    HandleTable full_server_table{};
    std::array<HandleTableReservation, kHandleTableCapacity - 1U> server_reservations{};
    const u32 server_full_count = FillReservations(full_server_table, server_reservations);
    EXPECT_EQ(
        Accept(directory, accept_full_service, accept_full_owner, full_server_table, accept_full_credential).status,
        ServiceDirectoryStatus::HandleReserveFailed);
    EXPECT_EQ(Inspect(directory, accept_full_service).queued_channels, 1U);
    AbortReservations(full_server_table, server_reservations, server_full_count);
    ServiceDirectoryAcceptResult accept_full_accepted =
        Accept(directory, accept_full_service, accept_full_owner, full_server_table, accept_full_credential);
    EXPECT_EQ(accept_full_accepted.status, ServiceDirectoryStatus::Ok);
    CloseHandle(accept_full_client, accept_full_connected.client_handle);
    CloseHandle(full_server_table, accept_full_accepted.server_handle);
    EXPECT_EQ(ServiceDirectoryReleaseAcceptedChannel(&directory, &accept_full_accepted.accepted).status,
              ServiceDirectoryStatus::Ok);
    EXPECT_EQ(ServiceDirectoryReleaseOperation(&directory, &accept_full_pin), ServiceDirectoryStatus::Ok);
    EXPECT_EQ(ServiceDirectoryUnregister(&directory, accept_full_service, accept_full_owner).status,
              ServiceDirectoryStatus::Ok);

    // Deterministic close-vs-connect: owner crash detaches the Pending entry
    // while the client handle is still invisible. The publisher may complete
    // only to detach that exact handle; no side escapes.
    const ServiceDirectoryName race_name = Name("race.service");
    const ServiceInstanceToken race_owner = Owner(0xD1U, 1, 0x5001U, 501);
    const ServiceEndpointCredentialSnapshot race_credential = Credential(5, 1, 5001);
    const ServiceKey race_service = Register(directory, race_name, 3, race_owner, race_credential);
    ServiceDirectoryOperationPin race_pin = Lookup(directory, race_name);
    HandleTable race_client{};
    CleanupCollector race_cleanup{};
    PublicationGate connect_gate{};
    ServiceDirectoryHostArmConnectPublicationHookForTest(&BlockPublication, &connect_gate);
    ServiceDirectoryConnectResult raced_connect{ServiceDirectoryStatus::CorruptState,
                                                ServiceEndpointStatus::CorruptState,
                                                ErrorCode::Corrupt,
                                                kHandleInvalid,
                                                kInvalidServiceEndpointIdentity,
                                                {}};
    std::thread connect_thread(
        [&]
        {
            raced_connect = Connect(directory, race_pin, domain, race_client, client_process, client_credential,
                                    Protocol(race_owner.start.service_identity), race_cleanup);
        });
    connect_gate.entered.wait();
    EXPECT_EQ(Inspect(directory, race_service).external_publishers, 1U);
    EXPECT_EQ(ServiceDirectoryOwnerCrashed(&directory, race_service, race_owner).status, ServiceDirectoryStatus::Busy);
    connect_gate.release.count_down();
    connect_thread.join();
    EXPECT_EQ(raced_connect.status, ServiceDirectoryStatus::Closing);
    EXPECT_EQ(HandleTableLiveCount(race_client), 0U);
    EXPECT_EQ(ServiceDirectoryReleaseOperation(&directory, &race_pin), ServiceDirectoryStatus::Ok);
    EXPECT_EQ(ServiceDirectoryOwnerCrashed(&directory, race_service, race_owner).status,
              ServiceDirectoryStatus::StaleKey);

    // Deterministic owner-crash-vs-accept closes the prior blind spot. The
    // accepted tracker is detached before server publication and the publisher
    // rolls its exact handle back after observing Closing.
    const ServiceDirectoryName accept_race_name = Name("accept-race.service");
    const ServiceInstanceToken accept_race_owner = Owner(0xE1U, 1, 0x6001U, 601);
    const ServiceEndpointCredentialSnapshot accept_race_credential = Credential(6, 1, 6001);
    const ServiceKey accept_race_service =
        Register(directory, accept_race_name, 4, accept_race_owner, accept_race_credential);
    ServiceDirectoryOperationPin accept_race_pin = Lookup(directory, accept_race_name);
    HandleTable accept_race_client{};
    HandleTable accept_race_server{};
    CleanupCollector accept_race_cleanup{};
    ServiceDirectoryConnectResult accept_race_connected =
        Connect(directory, accept_race_pin, domain, accept_race_client, client_process, client_credential,
                Protocol(accept_race_owner.start.service_identity), accept_race_cleanup);
    EXPECT_EQ(accept_race_connected.status, ServiceDirectoryStatus::Ok);
    PublicationGate accept_gate{};
    ServiceDirectoryHostArmAcceptPublicationHookForTest(&BlockPublication, &accept_gate);
    ServiceDirectoryAcceptResult raced_accept{ServiceDirectoryStatus::CorruptState,
                                              ServiceEndpointStatus::CorruptState,
                                              ErrorCode::Corrupt,
                                              kHandleInvalid,
                                              kInvalidServiceEndpointIdentity,
                                              kInvalidServiceDirectoryAcceptedChannelKey};
    std::thread accept_thread(
        [&]
        {
            raced_accept =
                Accept(directory, accept_race_service, accept_race_owner, accept_race_server, accept_race_credential);
        });
    accept_gate.entered.wait();
    EXPECT_EQ(Inspect(directory, accept_race_service).accepted_channels, 1U);
    EXPECT_EQ(ServiceDirectoryOwnerCrashed(&directory, accept_race_service, accept_race_owner).status,
              ServiceDirectoryStatus::Busy);
    accept_gate.release.count_down();
    accept_thread.join();
    EXPECT_EQ(raced_accept.status, ServiceDirectoryStatus::Closing);
    EXPECT_EQ(HandleTableLiveCount(accept_race_server), 0U);
    EXPECT_EQ(Inspect(directory, accept_race_service).accepted_channels, 0U);
    CloseHandle(accept_race_client, accept_race_connected.client_handle);
    EXPECT_EQ(ServiceDirectoryReleaseOperation(&directory, &accept_race_pin), ServiceDirectoryStatus::Ok);
    EXPECT_EQ(ServiceDirectoryOwnerCrashed(&directory, accept_race_service, accept_race_owner).status,
              ServiceDirectoryStatus::StaleKey);

    EXPECT_EQ(g_port_create_calls.load(std::memory_order_relaxed),
              g_port_destroy_calls.load(std::memory_order_relaxed));
    EXPECT_TRUE(ResourceDomainRelease(domain));
    return duetos_host_test::finish_main("test_service_directory");
}
