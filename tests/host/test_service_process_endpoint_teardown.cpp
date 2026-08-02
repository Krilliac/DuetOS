// Hostile ProcessKey-aware accepted ServiceEndpoint teardown coverage.
// Directory/endpoint ownership is real; only kernel allocation and locks use
// the standard hosted leaf doubles.

#include "host_test_helper.h"

#include "core/service_directory.h"

#include <array>
#include <atomic>
#include <barrier>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <new>
#include <thread>

// Exercise real authenticated-service channel accounting.
#include "proc/resource_domain.cpp"

namespace
{

std::mutex g_host_spinlock;
std::mutex g_host_object_lock;

} // namespace

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

namespace duetos::core
{

[[noreturn]] void Panic(const char*, const char*)
{
    std::abort();
}

[[noreturn]] void PanicWithValue(const char*, const char*, u64)
{
    std::abort();
}

} // namespace duetos::core

namespace duetos::ipc
{

namespace
{

void DestroyHostedPort(KObject* object)
{
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
    std::lock_guard<std::mutex> guard(g_host_object_lock);
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
        std::lock_guard<std::mutex> guard(g_host_object_lock);
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
    std::lock_guard<std::mutex> guard(g_host_object_lock);
    return object->refcount;
}

::duetos::core::Result<KMessagePort*> KMessagePortCreate()
{
    auto* port = new (std::nothrow) KMessagePort{};
    if (port == nullptr)
        return ::duetos::core::Err{::duetos::core::ErrorCode::OutOfMemory};
    KObjectInit(&port->base, KObjectType::MessagePort, &DestroyHostedPort);
    return port;
}

void KMessagePortClose(KMessagePort* port)
{
    if (port == nullptr)
        return;
    {
        std::lock_guard<std::mutex> guard(port->inner);
        port->closed = true;
    }
    port->readable.notify_all();
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

void IgnoreCleanup(void*, EndpointRequestKey) {}

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

ServiceEndpointCredentialSnapshot Credential(u32 slot, u32 uid)
{
    return ServiceEndpointCredentialSnapshot{CredentialKey{slot, 1}, Security(uid)};
}

ServiceDirectoryName Name()
{
    ServiceDirectoryName name{};
    constexpr char kName[] = "serviced";
    name.length = static_cast<duetos::u8>(sizeof(kName) - 1U);
    for (u32 index = 0; index < name.length; ++index)
        name.bytes[index] = static_cast<duetos::u8>(kName[index]);
    return name;
}

struct AcceptedPair
{
    Handle client;
    Handle server;
    ServiceDirectoryAcceptedChannelKey accepted;
};

struct Fixture
{
    ServiceEndpointOwner endpoint_owner{};
    ServiceDirectory directory{};
    HandleTable client_handles{};
    HandleTable server_handles{};
    ResourceDomainKey domain = kInvalidResourceDomainKey;
    ServiceEndpointCredentialSnapshot server_credential = Credential(1, 2001);
    ServiceEndpointCredentialSnapshot client_credential = Credential(2, 1001);
    ProcessKey server_process{0x2001, 201};
    ProcessKey client_process{0x1001, 101};
    ServiceInstanceToken owner{ServiceStartTicket{0xA1, 1},
                               ServiceInstanceKey{server_process.identity, server_process.pid}};
    ServiceDirectoryName name = Name();
    ServiceKey service = kInvalidServiceKey;
    ServiceDirectoryOperationPin pin = kInvalidServiceDirectoryOperationPin;
    ServiceEndpointProtocolAuthority protocol{0xA110, 0x5010, owner.start.service_identity, 0x3F, 1, 0, 0x51U, 0};
    ServiceDirectoryRequestCleanupSink cleanup{&IgnoreCleanup, nullptr};

    Fixture()
    {
        EXPECT_EQ(ServiceEndpointOwnerInitialize(&endpoint_owner), ServiceEndpointStatus::Ok);
        EXPECT_EQ(ServiceDirectoryInitialize(&directory, &endpoint_owner), ServiceDirectoryStatus::Ok);
        EXPECT_TRUE(ResourceDomainCreateAuthenticatedService(&domain));
        ServiceDirectoryReserveResult reserved =
            ServiceDirectoryReserveRegistration(&directory, &name, 0, owner, &server_credential);
        EXPECT_EQ(reserved.status, ServiceDirectoryStatus::Ok);
        service = reserved.reservation.service;
        EXPECT_EQ(ServiceDirectoryPublishRegistration(&directory, &reserved.reservation, owner),
                  ServiceDirectoryStatus::Ok);
        bool lifecycle_ready = false;
        EXPECT_EQ(ServiceDirectoryCommitJointReady(&directory, service, owner, &lifecycle_ready),
                  ServiceDirectoryStatus::Ok);
        EXPECT_TRUE(lifecycle_ready);
        const ServiceDirectoryLookupResult looked_up = ServiceDirectoryLookup(&directory, &name);
        EXPECT_EQ(looked_up.status, ServiceDirectoryStatus::Ok);
        pin = looked_up.pin;
    }

    AcceptedPair AcceptOne(u64 request_identity)
    {
        const ProcessKey client{client_process.identity + request_identity, client_process.pid + request_identity};
        const ServiceDirectoryConnectResult connected = ServiceDirectoryConnect(
            &directory, pin, domain, &client_handles, client, &client_credential, &protocol, kEndpointRights, &cleanup);
        EXPECT_EQ(connected.status, ServiceDirectoryStatus::Ok);
        const ServiceDirectoryAcceptResult accepted = ServiceDirectoryAccept(
            &directory, service, owner, &server_handles, server_process, &server_credential, kEndpointRights);
        EXPECT_EQ(accepted.status, ServiceDirectoryStatus::Ok);
        return AcceptedPair{connected.client_handle, accepted.server_handle, accepted.accepted};
    }

    ServiceDirectoryEntrySnapshot Inspect()
    {
        const ServiceDirectoryInspectResult inspected = ServiceDirectoryInspectExact(&directory, service);
        EXPECT_EQ(inspected.status, ServiceDirectoryStatus::Ok);
        return inspected.snapshot;
    }

    void Cleanup()
    {
        HandleTableDrain(server_handles);
        HandleTableDrain(client_handles);
        if (ServiceDirectoryOperationPinIsValid(pin))
            EXPECT_EQ(ServiceDirectoryReleaseOperation(&directory, &pin), ServiceDirectoryStatus::Ok);
        const ServiceDirectoryCloseResult closed = ServiceDirectoryUnregister(&directory, service, owner);
        EXPECT_EQ(closed.status, ServiceDirectoryStatus::Ok);
        EXPECT_TRUE(ResourceDomainRelease(domain));
        domain = kInvalidResourceDomainKey;
    }
};

} // namespace

int main()
{
    // A stale ProcessKey is an idempotent no-op. Exact teardown transfers the
    // retained owner in place without touching the still-live server handle,
    // and duplicate transfer cannot create a second deferred row.
    {
        auto fixture = std::make_unique<Fixture>();
        const AcceptedPair accepted = fixture->AcceptOne(1);
        ProcessKey stale = fixture->server_process;
        ++stale.identity;
        const ServiceDirectoryDeferAcceptedProcessResult stale_result =
            ServiceDirectoryDeferAcceptedProcess(&fixture->directory, stale);
        EXPECT_EQ(stale_result.status, ServiceDirectoryStatus::Ok);
        EXPECT_EQ(stale_result.newly_deferred_channels, 0U);
        EXPECT_EQ(stale_result.deferred_channels, 0U);
        EXPECT_EQ(fixture->Inspect().accepted_channels, 1U);

        const ServiceDirectoryDeferAcceptedProcessResult deferred =
            ServiceDirectoryDeferAcceptedProcess(&fixture->directory, fixture->server_process);
        EXPECT_EQ(deferred.status, ServiceDirectoryStatus::Ok);
        EXPECT_EQ(deferred.newly_deferred_channels, 1U);
        EXPECT_EQ(deferred.deferred_channels, 1U);
        EXPECT_EQ(fixture->Inspect().accepted_channels, 1U);
        EXPECT_EQ(HandleTableLiveCount(fixture->server_handles), 1U);

        const ServiceDirectoryDeferAcceptedProcessResult duplicate =
            ServiceDirectoryDeferAcceptedProcess(&fixture->directory, fixture->server_process);
        EXPECT_EQ(duplicate.status, ServiceDirectoryStatus::Ok);
        EXPECT_EQ(duplicate.newly_deferred_channels, 0U);
        EXPECT_EQ(duplicate.deferred_channels, 1U);

        // This is the Process teardown ordering boundary: raw KObject release
        // is legal only after the exact in-directory ownership transfer.
        HandleTableDrain(fixture->server_handles);
        EXPECT_EQ(HandleTableLiveCount(fixture->server_handles), 0U);
        const ServiceDirectoryDriveDeferredAcceptedResult driven =
            ServiceDirectoryDriveDeferredAccepted(&fixture->directory);
        EXPECT_EQ(driven.status, ServiceDirectoryStatus::Ok);
        EXPECT_EQ(driven.released_channels, 1U);
        EXPECT_EQ(driven.pending_channels, 0U);
        EXPECT_EQ(fixture->Inspect().accepted_channels, 0U);
        const ServiceDirectoryDriveDeferredAcceptedResult empty =
            ServiceDirectoryDriveDeferredAccepted(&fixture->directory);
        EXPECT_EQ(empty.status, ServiceDirectoryStatus::Ok);
        EXPECT_EQ(empty.released_channels, 0U);
        EXPECT_NE(accepted.server, kHandleInvalid);
        fixture->Cleanup();
    }

    // Once Process teardown marks a row, concurrent service close cannot move
    // that receipt into an anonymous close batch or clear its exact identity.
    // Closing stays Busy until scheduler maintenance releases the owner.
    {
        auto fixture = std::make_unique<Fixture>();
        fixture->AcceptOne(2);
        const ServiceDirectoryDeferAcceptedProcessResult deferred =
            ServiceDirectoryDeferAcceptedProcess(&fixture->directory, fixture->server_process);
        EXPECT_EQ(deferred.status, ServiceDirectoryStatus::Ok);
        EXPECT_EQ(deferred.newly_deferred_channels, 1U);
        EXPECT_EQ(ServiceDirectoryReleaseOperation(&fixture->directory, &fixture->pin), ServiceDirectoryStatus::Ok);

        const ServiceDirectoryCloseResult closing =
            ServiceDirectoryUnregister(&fixture->directory, fixture->service, fixture->owner);
        EXPECT_EQ(closing.status, ServiceDirectoryStatus::Busy);
        EXPECT_EQ(closing.drained_channels, 0U);
        EXPECT_EQ(fixture->Inspect().accepted_channels, 1U);

        HandleTableDrain(fixture->server_handles);
        const ServiceDirectoryDriveDeferredAcceptedResult completed =
            ServiceDirectoryDriveDeferredAccepted(&fixture->directory);
        EXPECT_EQ(completed.status, ServiceDirectoryStatus::Ok);
        EXPECT_EQ(completed.released_channels, 1U);
        EXPECT_EQ(completed.pending_channels, 0U);

        HandleTableDrain(fixture->client_handles);
        EXPECT_TRUE(ResourceDomainRelease(fixture->domain));
        fixture->domain = kInvalidResourceDomainKey;
    }

    // A peer can be blocked in Receive and then NT-suspended after terminal
    // close wakes it, retaining its endpoint operation pin indefinitely. The
    // Process still transfers ownership and drains its raw server handle. A
    // bounded maintenance pass reports durable Busy rather than wedging the
    // sole Process reaper; unsuspend lets a later pass consume the exact row.
    {
        auto fixture = std::make_unique<Fixture>();
        const AcceptedPair accepted = fixture->AcceptOne(3);
        KObject* retained = HandleTableLookupRef(fixture->client_handles, accepted.client, KObjectType::ServiceEndpoint,
                                                 kHandleRightRead);
        ASSERT_TRUE(retained != nullptr);
        ServiceEndpointOperationResult peer_operation = ServiceEndpointAcquireOperation(retained);
        KObjectRelease(retained);
        EXPECT_EQ(peer_operation.status, ServiceEndpointStatus::Ok);
        const ServiceEndpointDirectionResult peer_receive =
            ServiceEndpointBorrowDirection(&peer_operation.operation, ServiceEndpointTrafficDirection::Receive);
        EXPECT_EQ(peer_receive.status, ServiceEndpointStatus::Ok);
        ASSERT_TRUE(peer_receive.lease.port != nullptr);

        std::barrier peer_waiting{2};
        std::mutex progress_lock;
        std::condition_variable progress_changed;
        bool peer_woken = false;
        bool resume_peer = false;
        bool peer_released = false;
        ServiceEndpointStatus peer_release_status = ServiceEndpointStatus::Busy;
        std::thread peer(
            [&]
            {
                {
                    std::unique_lock<std::mutex> port_lock(peer_receive.lease.port->inner);
                    peer_waiting.arrive_and_wait();
                    peer_receive.lease.port->readable.wait(port_lock, [&] { return peer_receive.lease.port->closed; });
                }
                {
                    std::unique_lock<std::mutex> guard(progress_lock);
                    peer_woken = true;
                    progress_changed.notify_all();
                    progress_changed.wait(guard, [&] { return resume_peer; });
                }
                const ServiceEndpointStatus released = ServiceEndpointReleaseOperation(&peer_operation.operation);
                {
                    std::lock_guard<std::mutex> guard(progress_lock);
                    peer_release_status = released;
                    peer_released = true;
                }
                progress_changed.notify_all();
            });
        peer_waiting.arrive_and_wait();

        const ServiceDirectoryDeferAcceptedProcessResult deferred =
            ServiceDirectoryDeferAcceptedProcess(&fixture->directory, fixture->server_process);
        EXPECT_EQ(deferred.status, ServiceDirectoryStatus::Ok);
        EXPECT_EQ(deferred.newly_deferred_channels, 1U);
        EXPECT_EQ(deferred.deferred_channels, 1U);
        HandleTableDrain(fixture->server_handles);
        EXPECT_EQ(HandleTableLiveCount(fixture->server_handles), 0U);

        bool woken_in_time = false;
        {
            std::unique_lock<std::mutex> guard(progress_lock);
            woken_in_time = progress_changed.wait_for(guard, std::chrono::seconds(2), [&] { return peer_woken; });
        }
        // Keep a failing test joinable without hiding a missed terminal wake.
        if (!woken_in_time)
        {
            {
                std::lock_guard<std::mutex> guard(peer_receive.lease.port->inner);
                peer_receive.lease.port->closed = true;
            }
            peer_receive.lease.port->readable.notify_all();
        }
        EXPECT_TRUE(woken_in_time);

        const ServiceDirectoryDriveDeferredAcceptedResult busy =
            ServiceDirectoryDriveDeferredAccepted(&fixture->directory);
        EXPECT_EQ(busy.status, ServiceDirectoryStatus::Busy);
        EXPECT_EQ(busy.endpoint_status, ServiceEndpointStatus::Busy);
        EXPECT_EQ(busy.released_channels, 0U);
        EXPECT_EQ(busy.pending_channels, 1U);
        EXPECT_EQ(fixture->Inspect().accepted_channels, 1U);
        EXPECT_EQ(HandleTableLiveCount(fixture->client_handles), 1U);

        {
            std::lock_guard<std::mutex> guard(progress_lock);
            resume_peer = true;
        }
        progress_changed.notify_all();
        peer.join();
        EXPECT_TRUE(peer_released);
        EXPECT_EQ(peer_release_status, ServiceEndpointStatus::Ok);

        const ServiceDirectoryDriveDeferredAcceptedResult completed =
            ServiceDirectoryDriveDeferredAccepted(&fixture->directory);
        EXPECT_EQ(completed.status, ServiceDirectoryStatus::Ok);
        EXPECT_EQ(completed.released_channels, 1U);
        EXPECT_EQ(completed.pending_channels, 0U);
        EXPECT_EQ(fixture->Inspect().accepted_channels, 0U);
        EXPECT_EQ(HandleTableLiveCount(fixture->server_handles), 0U);
        EXPECT_EQ(HandleTableLiveCount(fixture->client_handles), 1U);
        fixture->Cleanup();
    }

    // Fairness is global rather than first-row biased. Five exact owners are
    // deferred in place with no second capacity boundary. The first slot stays
    // Busy, but the rotating flattened hint lets later quiescent rows drain in
    // bounded batches before that peer operation is released.
    {
        auto fixture = std::make_unique<Fixture>();
        std::array<AcceptedPair, kServiceDirectoryProcessTeardownBatchCapacity + 1U> accepted{};
        for (u32 index = 0; index < accepted.size(); ++index)
            accepted[index] = fixture->AcceptOne(10 + index);
        EXPECT_EQ(fixture->service.slot, 0U);
        EXPECT_EQ(accepted[0].accepted.slot, 0U);

        KObject* retained = HandleTableLookupRef(fixture->client_handles, accepted[0].client,
                                                 KObjectType::ServiceEndpoint, kHandleRightRead);
        ASSERT_TRUE(retained != nullptr);
        ServiceEndpointOperationResult pinned = ServiceEndpointAcquireOperation(retained);
        KObjectRelease(retained);
        EXPECT_EQ(pinned.status, ServiceEndpointStatus::Ok);

        const ServiceDirectoryDeferAcceptedProcessResult deferred =
            ServiceDirectoryDeferAcceptedProcess(&fixture->directory, fixture->server_process);
        EXPECT_EQ(deferred.status, ServiceDirectoryStatus::Ok);
        EXPECT_EQ(deferred.newly_deferred_channels, accepted.size());
        EXPECT_EQ(deferred.deferred_channels, accepted.size());
        EXPECT_EQ(fixture->Inspect().accepted_channels, accepted.size());
        HandleTableDrain(fixture->server_handles);

        const ServiceDirectoryDriveDeferredAcceptedResult first =
            ServiceDirectoryDriveDeferredAccepted(&fixture->directory);
        EXPECT_EQ(first.status, ServiceDirectoryStatus::Busy);
        EXPECT_EQ(first.released_channels, kServiceDirectoryProcessTeardownBatchCapacity - 1U);
        EXPECT_EQ(first.pending_channels, 2U);

        const ServiceDirectoryDriveDeferredAcceptedResult second =
            ServiceDirectoryDriveDeferredAccepted(&fixture->directory);
        EXPECT_EQ(second.status, ServiceDirectoryStatus::Busy);
        EXPECT_EQ(second.released_channels, 1U);
        EXPECT_EQ(second.pending_channels, 1U);
        EXPECT_EQ(fixture->Inspect().accepted_channels, 1U);

        EXPECT_EQ(ServiceEndpointReleaseOperation(&pinned.operation), ServiceEndpointStatus::Ok);
        const ServiceDirectoryDriveDeferredAcceptedResult completed =
            ServiceDirectoryDriveDeferredAccepted(&fixture->directory);
        EXPECT_EQ(completed.status, ServiceDirectoryStatus::Ok);
        EXPECT_EQ(completed.released_channels, 1U);
        EXPECT_EQ(completed.pending_channels, 0U);
        fixture->Cleanup();
    }

    // Concurrent duplicate transfers serialize under the directory lock. One
    // call marks the existing row and the other observes it; no duplicate row,
    // owner receipt, or capacity claim is created.
    {
        auto fixture = std::make_unique<Fixture>();
        fixture->AcceptOne(20);
        std::barrier start{3};
        ServiceDirectoryDeferAcceptedProcessResult left{ServiceDirectoryStatus::InvalidArgument, 0, 0};
        ServiceDirectoryDeferAcceptedProcessResult right = left;
        std::thread first(
            [&]
            {
                start.arrive_and_wait();
                left = ServiceDirectoryDeferAcceptedProcess(&fixture->directory, fixture->server_process);
            });
        std::thread second(
            [&]
            {
                start.arrive_and_wait();
                right = ServiceDirectoryDeferAcceptedProcess(&fixture->directory, fixture->server_process);
            });
        start.arrive_and_wait();
        first.join();
        second.join();

        EXPECT_EQ(left.status, ServiceDirectoryStatus::Ok);
        EXPECT_EQ(right.status, ServiceDirectoryStatus::Ok);
        EXPECT_EQ(left.newly_deferred_channels + right.newly_deferred_channels, 1U);
        EXPECT_EQ(left.deferred_channels, 1U);
        EXPECT_EQ(right.deferred_channels, 1U);
        EXPECT_EQ(fixture->Inspect().accepted_channels, 1U);

        HandleTableDrain(fixture->server_handles);
        const ServiceDirectoryDriveDeferredAcceptedResult completed =
            ServiceDirectoryDriveDeferredAccepted(&fixture->directory);
        EXPECT_EQ(completed.status, ServiceDirectoryStatus::Ok);
        EXPECT_EQ(completed.released_channels, 1U);
        EXPECT_EQ(completed.pending_channels, 0U);
        fixture->Cleanup();
    }

    return duetos_host_test::finish_main("test_service_process_endpoint_teardown");
}
