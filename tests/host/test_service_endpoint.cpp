// Hosted hostile ownership, pin, cleanup, ABA, and close-race coverage for
// authenticated ServiceEndpoint pairs.

#include "host_test_helper.h"
#include "core/service_endpoint.h"

#include <array>
#include <atomic>
#include <latch>
#include <mutex>
#include <new>
#include <thread>
#include <vector>

// Exercise the authoritative channel charge rather than a permissive fake.
#include "proc/resource_domain.cpp"

namespace
{

std::mutex g_host_spinlock;
std::mutex g_object_lock;
std::atomic<duetos::u32> g_port_create_calls{0};
std::atomic<duetos::u32> g_port_destroy_calls{0};

struct PortCloseBarrier
{
    std::latch close_entered{1};
    std::latch allow_close{1};
};

std::atomic<PortCloseBarrier*> g_port_close_barrier{nullptr};

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
    PortCloseBarrier* barrier = g_port_close_barrier.exchange(nullptr, std::memory_order_acq_rel);
    if (barrier != nullptr)
    {
        barrier->close_entered.count_down();
        barrier->allow_close.wait();
    }
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

struct CleanupCollector
{
    std::array<EndpointRequestKey, 8> keys{};
    u32 count = 0;
    ServiceEndpointOwnerReceipt* reenter_owner = nullptr;
    ServiceEndpointStatus reenter_status = ServiceEndpointStatus::Ok;
    bool reentered = false;
};

void CollectCleanup(void* context, EndpointRequestKey key)
{
    auto& collector = *static_cast<CleanupCollector*>(context);
    if (collector.count < collector.keys.size())
        collector.keys[collector.count] = key;
    ++collector.count;
    if (!collector.reentered && collector.reenter_owner != nullptr)
    {
        collector.reentered = true;
        collector.reenter_status = ServiceEndpointReleaseOwner(collector.reenter_owner);
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

ServiceEndpointPeerSnapshot Peer(u32 credential_slot, u64 credential_generation, u64 process_identity, u64 pid, u32 uid)
{
    return ServiceEndpointPeerSnapshot{
        ProcessKey{process_identity, pid},
        ServiceEndpointCredentialSnapshot{CredentialKey{credential_slot, credential_generation}, Security(uid)},
    };
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

ServiceEndpointPair CreatePair(ServiceEndpointOwner& owner, ResourceDomainKey domain, CleanupCollector& collector,
                               u64 service_identity = 0x51U)
{
    const ServiceEndpointPeerSnapshot initiator = Peer(1, 1, 0x1001U, 101, 1001);
    const ServiceEndpointPeerSnapshot acceptor = Peer(2, 1, 0x2001U, 201, 2001);
    const ServiceEndpointProtocolAuthority protocol = Protocol(service_identity);
    const ServiceEndpointRequestCleanupSink sink{&CollectCleanup, &collector};
    const ServiceEndpointPairCreateResult created =
        ServiceEndpointCreatePair(&owner, domain, &protocol, &initiator, &acceptor, &sink);
    EXPECT_EQ(created.status, ServiceEndpointStatus::Ok);
    EXPECT_EQ(created.channel_status, ChannelCoreStatus::Ok);
    return created.pair;
}

void ReleasePairObjects(ServiceEndpointPair& pair)
{
    KObject* initiator = pair.initiator;
    KObject* acceptor = pair.acceptor;
    pair.initiator = nullptr;
    pair.acceptor = nullptr;
    if (initiator != nullptr)
        KObjectRelease(initiator);
    if (acceptor != nullptr)
        KObjectRelease(acceptor);
}

} // namespace

int main()
{
    using namespace duetos::core;
    using namespace duetos::ipc;

    static ServiceEndpointOwner owner{};
    EXPECT_EQ(ServiceEndpointOwnerInitialize(&owner), ServiceEndpointStatus::Ok);
    EXPECT_EQ(ServiceEndpointOwnerInitialize(&owner), ServiceEndpointStatus::AlreadyInitialized);

    ResourceDomainKey domain = CreateDomain();
    CleanupCollector collector{};
    ServiceEndpointPair pair = CreatePair(owner, domain, collector);
    const ServiceEndpointChannelKey first_channel = pair.owner.channel;
    const ServiceEndpointActivationTicket activation_replay = pair.activation;
    const ServiceEndpointOwnerReceipt owner_replay = pair.owner;

    // Both objects bind the common protocol and the exact opposite peer by
    // value. Hostile output aliasing is refused without corrupting the object.
    ServiceEndpointIdentity initiator_identity{};
    ServiceEndpointProtocolAuthority initiator_protocol{};
    ServiceEndpointPeerSnapshot initiator_peer{};
    EXPECT_EQ(ServiceEndpointInspectObject(pair.initiator, &initiator_identity, &initiator_protocol, &initiator_peer),
              ServiceEndpointStatus::Ok);
    EXPECT_EQ(initiator_identity, pair.initiator_identity);
    EXPECT_EQ(initiator_protocol.service_identity, 0x51ULL);
    EXPECT_EQ(initiator_protocol.wire_service_id, 0x51U);
    EXPECT_TRUE(ServiceEndpointProtocolAuthorityAllowsRoute(initiator_protocol, 0x51U, 1));
    EXPECT_TRUE(ServiceEndpointProtocolAuthorityAllowsRoute(initiator_protocol, 0x51U, 6));
    EXPECT_FALSE(ServiceEndpointProtocolAuthorityAllowsRoute(initiator_protocol, 0x51U, 7));
    EXPECT_FALSE(ServiceEndpointProtocolAuthorityAllowsRoute(initiator_protocol, 0x51U, 0));
    EXPECT_FALSE(ServiceEndpointProtocolAuthorityAllowsRoute(initiator_protocol, 0x51U, 65));
    EXPECT_FALSE(ServiceEndpointProtocolAuthorityAllowsRoute(initiator_protocol, 0x52U, 1));
    ServiceEndpointProtocolAuthority invalid_protocol = initiator_protocol;
    invalid_protocol.protocol_version = kServiceEndpointProtocolVersionMaximum + 1U;
    EXPECT_FALSE(ServiceEndpointProtocolAuthorityIsCanonical(invalid_protocol));
    invalid_protocol = initiator_protocol;
    invalid_protocol.wire_service_id = 0;
    EXPECT_FALSE(ServiceEndpointProtocolAuthorityIsCanonical(invalid_protocol));
    invalid_protocol = initiator_protocol;
    invalid_protocol.reserved32 = 1;
    EXPECT_FALSE(ServiceEndpointProtocolAuthorityIsCanonical(invalid_protocol));
    EXPECT_EQ(initiator_peer.process, (ProcessKey{0x2001U, 201}));
    auto* alias = reinterpret_cast<ServiceEndpointObject*>(pair.initiator);
    EXPECT_EQ(ServiceEndpointInspectObject(pair.initiator, &alias->identity, &initiator_protocol, &initiator_peer),
              ServiceEndpointStatus::InvalidArgument);
    EXPECT_EQ(alias->identity, pair.initiator_identity);

    // Private endpoints cannot be operated. A forged activation ticket is
    // harmless; the exact ticket activates once and copied replay fails.
    EXPECT_EQ(ServiceEndpointAcquireOperation(pair.initiator).status, ServiceEndpointStatus::NotPublished);
    ServiceEndpointActivationTicket forged_activation = pair.activation;
    ++forged_activation.nonce;
    EXPECT_EQ(ServiceEndpointActivate(&forged_activation), ServiceEndpointStatus::StaleActivation);
    EXPECT_EQ(ServiceEndpointActivate(&pair.activation), ServiceEndpointStatus::Ok);
    ServiceEndpointActivationTicket activation_copy = activation_replay;
    EXPECT_EQ(ServiceEndpointActivate(&activation_copy), ServiceEndpointStatus::AlreadyPublished);

    ServiceEndpointOperationResult initiator_operation = ServiceEndpointAcquireOperation(pair.initiator);
    ServiceEndpointOperationResult acceptor_operation = ServiceEndpointAcquireOperation(pair.acceptor);
    EXPECT_EQ(initiator_operation.status, ServiceEndpointStatus::Ok);
    EXPECT_EQ(acceptor_operation.status, ServiceEndpointStatus::Ok);

    // Releasing a normal operation only drops its exact core/object pins; it
    // must not be mistaken for an endpoint-close request.
    EXPECT_EQ(ServiceEndpointReleaseOperation(&initiator_operation.operation), ServiceEndpointStatus::Ok);
    EXPECT_EQ(ServiceEndpointInspectExact(&owner, first_channel).snapshot.state, ServiceEndpointSlotState::Open);
    initiator_operation = ServiceEndpointAcquireOperation(pair.initiator);
    EXPECT_EQ(initiator_operation.status, ServiceEndpointStatus::Ok);

    // A ChannelCore pin is bound to the endpoint role that acquired it. A
    // public receipt tuple cannot be spliced with its peer's same-core pin.
    ServiceEndpointOperation spliced_operation = initiator_operation.operation;
    spliced_operation.core_pin = acceptor_operation.operation.core_pin;
    EXPECT_FALSE(ServiceEndpointOperationIsValid(spliced_operation));
    EXPECT_EQ(ServiceEndpointReserveRequest(&spliced_operation, 1).status, ServiceEndpointStatus::InvalidArgument);

    // Bounded operation saturation is ordinary backpressure, not evidence of
    // corrupt owner state. The failed acquire also rolls back its KObject ref.
    std::array<ServiceEndpointOperation, kChannelCoreOperationCapacity - 2U> saturated_operations{};
    for (ServiceEndpointOperation& operation : saturated_operations)
    {
        ServiceEndpointOperationResult acquired = ServiceEndpointAcquireOperation(pair.initiator);
        EXPECT_EQ(acquired.status, ServiceEndpointStatus::Ok);
        operation = acquired.operation;
    }
    const ServiceEndpointOperationResult saturated = ServiceEndpointAcquireOperation(pair.initiator);
    EXPECT_EQ(saturated.status, ServiceEndpointStatus::Busy);
    EXPECT_EQ(saturated.channel_status, ChannelCoreStatus::Busy);
    for (ServiceEndpointOperation& operation : saturated_operations)
        EXPECT_EQ(ServiceEndpointReleaseOperation(&operation), ServiceEndpointStatus::Ok);

    const ServiceEndpointDirectionResult initiator_send =
        ServiceEndpointBorrowDirection(&initiator_operation.operation, ServiceEndpointTrafficDirection::Send);
    const ServiceEndpointDirectionResult initiator_receive =
        ServiceEndpointBorrowDirection(&initiator_operation.operation, ServiceEndpointTrafficDirection::Receive);
    const ServiceEndpointDirectionResult acceptor_send =
        ServiceEndpointBorrowDirection(&acceptor_operation.operation, ServiceEndpointTrafficDirection::Send);
    EXPECT_EQ(initiator_send.status, ServiceEndpointStatus::Ok);
    EXPECT_EQ(initiator_send.lease.request_identity.direction, EndpointRequestDirection::InitiatorToAcceptor);
    EXPECT_EQ(initiator_receive.lease.request_identity.direction, EndpointRequestDirection::AcceptorToInitiator);
    EXPECT_EQ(acceptor_send.lease.request_identity.direction, EndpointRequestDirection::AcceptorToInitiator);

    EXPECT_EQ(ServiceEndpointReserveRequest(&initiator_operation.operation, ServiceEndpointTrafficDirection::Receive, 1)
                  .status,
              ServiceEndpointStatus::InvalidArgument);
    const ServiceEndpointRequestReserveResult request_one =
        ServiceEndpointReserveRequest(&initiator_operation.operation, 1);
    EXPECT_EQ(request_one.status, ServiceEndpointStatus::Ok);

    // The sender cannot commit its own outgoing request. Only the peer's
    // receive role can mint completion authority, which is then consumed once
    // and invalidated. Copied authority remains a replay, not a second reply.
    const ServiceEndpointRequestCommitResult wrong_sender_commit =
        ServiceEndpointCommitReceivedRequest(&initiator_operation.operation, request_one.request_key);
    EXPECT_EQ(wrong_sender_commit.status, ServiceEndpointStatus::RequestRejected);
    EXPECT_EQ(wrong_sender_commit.ledger_status, EndpointRequestLedgerStatus::StaleIdentity);
    ServiceEndpointRequestCommitResult committed =
        ServiceEndpointCommitReceivedRequest(&acceptor_operation.operation, request_one.request_key);
    EXPECT_EQ(committed.status, ServiceEndpointStatus::Ok);
    EXPECT_TRUE(EndpointRequestCompletionAuthorityIsValid(committed.completion_authority));
    const ServiceEndpointRequestCommitResult duplicate_commit =
        ServiceEndpointCommitReceivedRequest(&acceptor_operation.operation, request_one.request_key);
    EXPECT_EQ(duplicate_commit.status, ServiceEndpointStatus::RequestRejected);
    EXPECT_EQ(duplicate_commit.ledger_status, EndpointRequestLedgerStatus::ReplayRejected);
    EndpointRequestCompletionAuthority completion_replay = committed.completion_authority;
    const ServiceEndpointRequestTransitionResult wrong_receiver_complete =
        ServiceEndpointCompleteReceivedRequest(&initiator_operation.operation, &completion_replay);
    EXPECT_EQ(wrong_receiver_complete.status, ServiceEndpointStatus::RequestRejected);
    EXPECT_EQ(wrong_receiver_complete.ledger_status, EndpointRequestLedgerStatus::StaleIdentity);
    EXPECT_TRUE(EndpointRequestCompletionAuthorityIsValid(completion_replay));
    EXPECT_EQ(
        ServiceEndpointCompleteReceivedRequest(&acceptor_operation.operation, &committed.completion_authority).status,
        ServiceEndpointStatus::Ok);
    EXPECT_FALSE(EndpointRequestCompletionAuthorityIsValid(committed.completion_authority));
    EXPECT_EQ(ServiceEndpointCompleteReceivedRequest(&acceptor_operation.operation, &completion_replay).ledger_status,
              EndpointRequestLedgerStatus::ReplayRejected);

    ServiceEndpointRequestReserveResult rejected_request =
        ServiceEndpointReserveRequest(&initiator_operation.operation, 2);
    EXPECT_EQ(rejected_request.status, ServiceEndpointStatus::Ok);
    EndpointRequestKey rejection_replay = rejected_request.request_key;
    EndpointRequestKey wrong_receiver_reject_key = rejected_request.request_key;
    const ServiceEndpointRequestTransitionResult wrong_receiver_reject =
        ServiceEndpointRejectReceivedRequest(&initiator_operation.operation, &wrong_receiver_reject_key);
    EXPECT_EQ(wrong_receiver_reject.status, ServiceEndpointStatus::RequestRejected);
    EXPECT_EQ(wrong_receiver_reject.ledger_status, EndpointRequestLedgerStatus::StaleIdentity);
    EXPECT_TRUE(EndpointRequestKeyIsValid(wrong_receiver_reject_key));
    EXPECT_EQ(ServiceEndpointRejectReceivedRequest(&acceptor_operation.operation, &rejected_request.request_key).status,
              ServiceEndpointStatus::Ok);
    EXPECT_FALSE(EndpointRequestKeyIsValid(rejected_request.request_key));
    EXPECT_EQ(ServiceEndpointRejectReceivedRequest(&acceptor_operation.operation, &rejection_replay).ledger_status,
              EndpointRequestLedgerStatus::ReplayRejected);

    ServiceEndpointRequestReserveResult request_three =
        ServiceEndpointReserveRequest(&initiator_operation.operation, 3);
    EXPECT_EQ(request_three.status, ServiceEndpointStatus::Ok);
    EndpointRequestKey cancellation_replay = request_three.request_key;
    const ServiceEndpointRequestTransitionResult wrong_sender_cancel =
        ServiceEndpointCancelSentRequest(&acceptor_operation.operation, &cancellation_replay);
    EXPECT_EQ(wrong_sender_cancel.status, ServiceEndpointStatus::RequestRejected);
    EXPECT_EQ(wrong_sender_cancel.ledger_status, EndpointRequestLedgerStatus::StaleIdentity);
    EXPECT_TRUE(EndpointRequestKeyIsValid(cancellation_replay));
    EXPECT_EQ(ServiceEndpointCancelSentRequest(&initiator_operation.operation, &request_three.request_key).status,
              ServiceEndpointStatus::Ok);
    EXPECT_FALSE(EndpointRequestKeyIsValid(request_three.request_key));
    EXPECT_EQ(ServiceEndpointCancelSentRequest(&initiator_operation.operation, &cancellation_replay).ledger_status,
              EndpointRequestLedgerStatus::ReplayRejected);

    // Exercise the asymmetric peer direction through the same typed API:
    // Acceptor sends, Initiator receives/commits, and Initiator completes.
    const ServiceEndpointRequestReserveResult reverse_request =
        ServiceEndpointReserveRequest(&acceptor_operation.operation, 1);
    EXPECT_EQ(reverse_request.status, ServiceEndpointStatus::Ok);
    ServiceEndpointRequestCommitResult reverse_commit =
        ServiceEndpointCommitReceivedRequest(&initiator_operation.operation, reverse_request.request_key);
    EXPECT_EQ(reverse_commit.status, ServiceEndpointStatus::Ok);
    EXPECT_EQ(
        ServiceEndpointCompleteReceivedRequest(&initiator_operation.operation, &reverse_commit.completion_authority)
            .status,
        ServiceEndpointStatus::Ok);
    EXPECT_FALSE(EndpointRequestCompletionAuthorityIsValid(reverse_commit.completion_authority));

    const ServiceEndpointRequestReserveResult request =
        ServiceEndpointReserveRequest(&initiator_operation.operation, 4);
    EXPECT_EQ(request.status, ServiceEndpointStatus::Ok);
    ServiceEndpointOperation stale_operation = initiator_operation.operation;
    EXPECT_TRUE(stale_operation.core_pin.generation > 1U);
    --stale_operation.core_pin.generation;
    EndpointRequestKey stale_attempt = request.request_key;
    EXPECT_EQ(ServiceEndpointCancelSentRequest(&stale_operation, &stale_attempt).status,
              ServiceEndpointStatus::StaleIdentity);
    EXPECT_TRUE(EndpointRequestKeyIsValid(stale_attempt));

    // Drain cannot outrun either exact operation pin. The first close only
    // blocks new work and wakes port waiters; request cleanup is deferred until
    // the final issued operation settles. It is then delivered once outside
    // the owner/core locks, where callback re-entry sees the active driver
    // rather than double-cleaning the receipt.
    collector.reenter_owner = &pair.owner;
    EXPECT_EQ(ServiceEndpointReleaseOwner(&pair.owner), ServiceEndpointStatus::Busy);
    EXPECT_EQ(collector.count, 0U);
    EXPECT_FALSE(collector.reentered);
    EXPECT_TRUE(ServiceEndpointOwnerReceiptIsValid(pair.owner));
    EXPECT_EQ(
        ServiceEndpointBorrowDirection(&initiator_operation.operation, ServiceEndpointTrafficDirection::Send).status,
        ServiceEndpointStatus::Closing);

    EXPECT_EQ(ServiceEndpointReleaseOperation(&initiator_operation.operation), ServiceEndpointStatus::Ok);
    EXPECT_EQ(collector.count, 0U);
    EXPECT_EQ(ServiceEndpointReleaseOperation(&acceptor_operation.operation), ServiceEndpointStatus::Ok);
    EXPECT_EQ(collector.count, 1U);
    EXPECT_EQ(collector.keys[0], request.request_key);
    EXPECT_EQ(collector.reenter_status, ServiceEndpointStatus::Busy);
    EXPECT_EQ(ServiceEndpointReleaseOwner(&pair.owner), ServiceEndpointStatus::Ok);
    EXPECT_EQ(collector.count, 1U);

    ServiceEndpointOwnerReceipt copied_owner = owner_replay;
    EXPECT_EQ(ServiceEndpointReleaseOwner(&copied_owner), ServiceEndpointStatus::StaleOwner);
    KObjectRelease(pair.initiator);
    pair.initiator = nullptr;
    ServiceEndpointInspectResult half_closed = ServiceEndpointInspectExact(&owner, first_channel);
    EXPECT_EQ(half_closed.status, ServiceEndpointStatus::Ok);
    EXPECT_FALSE(half_closed.snapshot.endpoint_reference_live[0]);
    EXPECT_TRUE(half_closed.snapshot.endpoint_reference_live[1]);
    KObjectRelease(pair.acceptor);
    pair.acceptor = nullptr;
    EXPECT_EQ(ServiceEndpointInspectExact(&owner, first_channel).status, ServiceEndpointStatus::StaleIdentity);

    // Lost-wakeup barrier: pause the outer drain after it snapshots one live
    // ChannelCore pin and drops both owner/core locks to close a port. Releasing
    // that final operation must publish a durable retry request. When resumed,
    // the existing driver consumes the handoff and completes cleanup itself;
    // no unrelated owner/object lifecycle call is needed to make progress.
    CleanupCollector handoff_collector{};
    ServiceEndpointPair handoff = CreatePair(owner, domain, handoff_collector, 0x5151U);
    const ServiceEndpointChannelKey handoff_channel = handoff.owner.channel;
    EXPECT_EQ(ServiceEndpointActivate(&handoff.activation), ServiceEndpointStatus::Ok);
    ServiceEndpointOperationResult handoff_operation = ServiceEndpointAcquireOperation(handoff.initiator);
    EXPECT_EQ(handoff_operation.status, ServiceEndpointStatus::Ok);
    const ServiceEndpointRequestReserveResult handoff_request =
        ServiceEndpointReserveRequest(&handoff_operation.operation, 1);
    EXPECT_EQ(handoff_request.status, ServiceEndpointStatus::Ok);

    PortCloseBarrier close_barrier;
    g_port_close_barrier.store(&close_barrier, std::memory_order_release);
    ServiceEndpointStatus handoff_release_status = ServiceEndpointStatus::CorruptState;
    std::thread outer_drain([&] { handoff_release_status = ServiceEndpointReleaseOwner(&handoff.owner); });
    close_barrier.close_entered.wait();

    EXPECT_EQ(ServiceEndpointReleaseOperation(&handoff_operation.operation), ServiceEndpointStatus::Ok);
    ServiceEndpointInspectResult pending_handoff = ServiceEndpointInspectExact(&owner, handoff_channel);
    EXPECT_EQ(pending_handoff.status, ServiceEndpointStatus::Ok);
    EXPECT_EQ(pending_handoff.snapshot.state, ServiceEndpointSlotState::Draining);
    EXPECT_TRUE(pending_handoff.snapshot.drain_driver_active);
    EXPECT_TRUE(pending_handoff.snapshot.drain_retry_requested);

    close_barrier.allow_close.count_down();
    outer_drain.join();
    EXPECT_EQ(handoff_release_status, ServiceEndpointStatus::Ok);
    EXPECT_FALSE(ServiceEndpointOwnerReceiptIsValid(handoff.owner));
    EXPECT_EQ(handoff_collector.count, 1U);
    EXPECT_EQ(handoff_collector.keys[0], handoff_request.request_key);
    const ServiceEndpointInspectResult completed_handoff = ServiceEndpointInspectExact(&owner, handoff_channel);
    EXPECT_EQ(completed_handoff.status, ServiceEndpointStatus::Ok);
    EXPECT_EQ(completed_handoff.snapshot.state, ServiceEndpointSlotState::Drained);
    EXPECT_FALSE(completed_handoff.snapshot.drain_driver_active);
    EXPECT_FALSE(completed_handoff.snapshot.drain_retry_requested);
    ReleasePairObjects(handoff);
    EXPECT_EQ(ServiceEndpointInspectExact(&owner, handoff_channel).status, ServiceEndpointStatus::StaleIdentity);

    // Reuse cannot recreate the retired identity. Closing one endpoint starts
    // the one shared drain while the peer object remains independently alive.
    CleanupCollector second_collector{};
    ServiceEndpointPair second = CreatePair(owner, domain, second_collector, 0x52U);
    EXPECT_TRUE(!(second.owner.channel == first_channel));
    EXPECT_TRUE(second.owner.channel.generation > first_channel.generation ||
                second.owner.channel.slot != first_channel.slot);
    EXPECT_EQ(ServiceEndpointActivate(&second.activation), ServiceEndpointStatus::Ok);
    KObjectRelease(second.initiator);
    second.initiator = nullptr;
    const ServiceEndpointStatus peer_after_close = ServiceEndpointAcquireOperation(second.acceptor).status;
    EXPECT_TRUE(peer_after_close == ServiceEndpointStatus::Closing ||
                peer_after_close == ServiceEndpointStatus::Drained);
    EXPECT_EQ(ServiceEndpointReleaseOwner(&second.owner), ServiceEndpointStatus::Ok);
    KObjectRelease(second.acceptor);
    second.acceptor = nullptr;

    // Sanitizer-friendly close-vs-acquire stress. The initial endpoint refs keep
    // object storage stable while worker-owned operation refs race terminal
    // outer-owner release. Only exact successful pins are released.
    CleanupCollector stress_collector{};
    ServiceEndpointPair stress = CreatePair(owner, domain, stress_collector, 0x53U);
    EXPECT_EQ(ServiceEndpointActivate(&stress.activation), ServiceEndpointStatus::Ok);
    std::atomic<bool> start{false};
    std::atomic<bool> stop{false};
    std::atomic<u32> successful_operations{0};
    std::vector<std::thread> workers;
    for (u32 worker = 0; worker < 4; ++worker)
    {
        workers.emplace_back(
            [&]
            {
                while (!start.load(std::memory_order_acquire))
                    std::this_thread::yield();
                while (!stop.load(std::memory_order_acquire))
                {
                    ServiceEndpointOperationResult acquired = ServiceEndpointAcquireOperation(stress.initiator);
                    if (acquired.status != ServiceEndpointStatus::Ok)
                        continue;
                    successful_operations.fetch_add(1, std::memory_order_relaxed);
                    EXPECT_EQ(ServiceEndpointReleaseOperation(&acquired.operation), ServiceEndpointStatus::Ok);
                }
            });
    }
    start.store(true, std::memory_order_release);
    for (u32 spin = 0; successful_operations.load(std::memory_order_acquire) == 0 && spin < 100000; ++spin)
        std::this_thread::yield();
    ServiceEndpointStatus stress_release = ServiceEndpointReleaseOwner(&stress.owner);
    stop.store(true, std::memory_order_release);
    for (auto& worker : workers)
        worker.join();
    for (u32 retry = 0; stress_release == ServiceEndpointStatus::Busy && retry < 16; ++retry)
        stress_release = ServiceEndpointReleaseOwner(&stress.owner);
    EXPECT_EQ(stress_release, ServiceEndpointStatus::Ok);
    EXPECT_TRUE(successful_operations.load(std::memory_order_relaxed) != 0);
    ReleasePairObjects(stress);

    // Corrupting the immutable cleanup sink after publication simulates the
    // fail-closed validation path. The request context stays quarantined, but
    // the already-detached ports/tables/charge must still be released exactly
    // once rather than becoming unreachable behind a Drained ChannelCore.
    CleanupCollector invalid_cleanup_collector{};
    ServiceEndpointPair invalid_cleanup = CreatePair(owner, domain, invalid_cleanup_collector, 0x54U);
    EXPECT_EQ(ServiceEndpointActivate(&invalid_cleanup.activation), ServiceEndpointStatus::Ok);
    ServiceEndpointOperationResult invalid_cleanup_operation =
        ServiceEndpointAcquireOperation(invalid_cleanup.initiator);
    EXPECT_EQ(invalid_cleanup_operation.status, ServiceEndpointStatus::Ok);
    EXPECT_EQ(ServiceEndpointReserveRequest(&invalid_cleanup_operation.operation, 1).status, ServiceEndpointStatus::Ok);
    owner.slots[invalid_cleanup.owner.channel.slot].request_cleanup = kInvalidServiceEndpointRequestCleanupSink;
    const u32 destroys_before_invalid_cleanup = g_port_destroy_calls.load(std::memory_order_relaxed);
    EXPECT_EQ(ServiceEndpointReleaseOwner(&invalid_cleanup.owner), ServiceEndpointStatus::Busy);
    EXPECT_EQ(g_port_destroy_calls.load(std::memory_order_relaxed), destroys_before_invalid_cleanup);
    ServiceEndpointInspectResult quarantined = ServiceEndpointInspectExact(&owner, invalid_cleanup.owner.channel);
    EXPECT_EQ(quarantined.status, ServiceEndpointStatus::Ok);
    EXPECT_EQ(quarantined.snapshot.state, ServiceEndpointSlotState::Draining);
    EXPECT_FALSE(quarantined.snapshot.request_cleanup_failed);
    EXPECT_FALSE(quarantined.snapshot.detached_cleanup_live);
    EXPECT_EQ(ServiceEndpointReleaseOperation(&invalid_cleanup_operation.operation), ServiceEndpointStatus::Ok);
    EXPECT_EQ(g_port_destroy_calls.load(std::memory_order_relaxed), destroys_before_invalid_cleanup + 2U);
    quarantined = ServiceEndpointInspectExact(&owner, invalid_cleanup.owner.channel);
    EXPECT_EQ(quarantined.status, ServiceEndpointStatus::Ok);
    EXPECT_EQ(quarantined.snapshot.state, ServiceEndpointSlotState::Draining);
    EXPECT_FALSE(quarantined.snapshot.detached_cleanup_live);
    EXPECT_TRUE(quarantined.snapshot.request_cleanup_failed);
    EXPECT_TRUE(ServiceEndpointOwnerReceiptIsValid(invalid_cleanup.owner));
    EXPECT_EQ(ServiceEndpointReleaseOwner(&invalid_cleanup.owner), ServiceEndpointStatus::InvalidCleanup);
    ReleasePairObjects(invalid_cleanup);

    EXPECT_EQ(g_port_create_calls.load(std::memory_order_relaxed),
              g_port_destroy_calls.load(std::memory_order_relaxed));
    EXPECT_TRUE(ResourceDomainRelease(domain));

    return duetos_host_test::finish_main("test_service_endpoint");
}
