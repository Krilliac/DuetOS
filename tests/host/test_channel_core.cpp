// Hosted lifecycle, exact-pin, paired-reset, cleanup, and exhaustion coverage
// for the dormant internal ChannelCore owner primitive.

#include "host_test_helper.h"
#include "ipc/channel_core.h"

#include <array>
#include <atomic>
#include <cstring>
#include <latch>
#include <mutex>
#include <new>
#include <thread>
#include <type_traits>

// Use the production ResourceDomain implementation so charge acquisition,
// rollback, Closing pinning, and final release are part of this test.
#include "proc/resource_domain.cpp"

namespace
{

std::mutex g_host_spinlock;
std::mutex g_object_lock;
std::atomic<duetos::u32> g_port_create_calls{0};
std::atomic<duetos::u32> g_port_destroy_calls{0};
std::atomic<duetos::u32> g_port_close_calls{0};
std::atomic<duetos::u32> g_transfer_close_calls{0};
std::atomic<duetos::u32> g_transfer_close_busy_once{0};
std::atomic<duetos::u32> g_fail_port_create_call{0};
std::atomic<duetos::ipc::ChannelCore*> g_close_reentry_core{nullptr};
std::atomic<duetos::ipc::ChannelCoreStatus> g_close_reentry_status{duetos::ipc::ChannelCoreStatus::Ok};

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
    const u32 call = g_port_create_calls.fetch_add(1, std::memory_order_relaxed) + 1U;
    if (call == g_fail_port_create_call.load(std::memory_order_relaxed))
        return ::duetos::core::Err{::duetos::core::ErrorCode::OutOfMemory};
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
    g_port_close_calls.fetch_add(1, std::memory_order_relaxed);
    ChannelCore* reenter = g_close_reentry_core.exchange(nullptr, std::memory_order_acq_rel);
    if (reenter != nullptr)
        g_close_reentry_status.store(ChannelCoreDrain(reenter).status, std::memory_order_release);
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
    g_transfer_close_calls.fetch_add(1, std::memory_order_relaxed);
    if (table->state == ObjectTransferTableState::Closed)
        return ObjectTransferStatus::Ok;
    if (g_transfer_close_busy_once.exchange(0, std::memory_order_acq_rel) != 0)
    {
        table->state = ObjectTransferTableState::Draining;
        return ObjectTransferStatus::Busy;
    }
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

ResourceDomainSnapshot InspectDomain(ResourceDomainKey key)
{
    ResourceDomainSnapshot snapshot{};
    EXPECT_TRUE(ResourceDomainInspectExact(key, &snapshot));
    return snapshot;
}

ChannelCoreSnapshot InspectCore(ChannelCore& core)
{
    const ChannelCoreInspectResult inspected = ChannelCoreInspect(&core);
    EXPECT_EQ(inspected.status, ChannelCoreStatus::Ok);
    return inspected.snapshot;
}

template <typename T> std::array<unsigned char, sizeof(T)> BytesOf(const T& value)
{
    std::array<unsigned char, sizeof(T)> bytes{};
    std::memcpy(bytes.data(), &value, sizeof(T));
    return bytes;
}

void ExpectPairedIdentities(const ChannelCoreSnapshot& snapshot, u64 epoch)
{
    EXPECT_EQ(snapshot.request_identities[0].endpoint_epoch, epoch);
    EXPECT_EQ(snapshot.request_identities[1].endpoint_epoch, epoch);
    EXPECT_EQ(snapshot.request_identities[0].direction, EndpointRequestDirection::InitiatorToAcceptor);
    EXPECT_EQ(snapshot.request_identities[1].direction, EndpointRequestDirection::AcceptorToInitiator);
}

struct InitializeRaceGate
{
    std::latch preclaim_reached{1};
    std::latch allow_claim{1};
};

void PauseBeforeInitializeClaim(void* context)
{
    auto& gate = *static_cast<InitializeRaceGate*>(context);
    gate.preclaim_reached.count_down();
    gate.allow_claim.wait();
}

} // namespace

int main()
{
    static_assert(std::is_same_v<decltype(ChannelCoreDrain(nullptr)), ChannelCoreDrainResult>);
    static_assert(
        std::is_same_v<decltype(ChannelCoreDrainExpected(nullptr, kChannelEpochInvalid)), ChannelCoreDrainResult>);
    static_assert(
        std::is_same_v<decltype(ChannelCoreInitialize(nullptr, kInvalidResourceDomainKey)), ChannelCoreOpenResult>);
    static_assert(kChannelCoreQueuedBufferBytes == 2ULL * kMessagePortStorageBytes);
    ChannelCoreHostSetNextEpochForTest(1);

    // Invalid preflight and failed allocation leave canonical caller storage
    // byte-for-byte unchanged and roll back every ResourceDomain charge.
    ChannelCore untouched{};
    const auto untouched_bytes = BytesOf(untouched);
    EXPECT_EQ(ChannelCoreInitialize(nullptr, kInvalidResourceDomainKey).status, ChannelCoreStatus::InvalidArgument);
    EXPECT_EQ(ChannelCoreInitialize(&untouched, kInvalidResourceDomainKey).status, ChannelCoreStatus::InvalidArgument);
    EXPECT_TRUE(BytesOf(untouched) == untouched_bytes);

    ResourceDomainKey domain = kInvalidResourceDomainKey;
    EXPECT_TRUE(ResourceDomainCreateTrusted(&domain));
    const u32 create_before_failure = g_port_create_calls.load(std::memory_order_relaxed);
    const u32 destroy_before_failure = g_port_destroy_calls.load(std::memory_order_relaxed);
    g_fail_port_create_call.store(create_before_failure + 2U, std::memory_order_relaxed);
    ChannelCore allocation_failure{};
    const auto allocation_failure_bytes = BytesOf(allocation_failure);
    EXPECT_EQ(ChannelCoreInitialize(&allocation_failure, domain).status, ChannelCoreStatus::AllocationFailed);
    EXPECT_TRUE(BytesOf(allocation_failure) == allocation_failure_bytes);
    EXPECT_EQ(InspectDomain(domain).channel_objects, 0U);
    EXPECT_EQ(InspectDomain(domain).channel_bytes, 0ULL);
    EXPECT_EQ(g_port_create_calls.load(std::memory_order_relaxed), create_before_failure + 2U);
    EXPECT_EQ(g_port_destroy_calls.load(std::memory_order_relaxed), destroy_before_failure + 1U);
    g_fail_port_create_call.store(0, std::memory_order_relaxed);

    ChannelCore core{};
    const ChannelCoreOpenResult opened = ChannelCoreInitialize(&core, domain);
    EXPECT_EQ(opened.status, ChannelCoreStatus::Ok);
    EXPECT_EQ(opened.channel_epoch, 1ULL);
    auto snapshot = InspectCore(core);
    EXPECT_EQ(snapshot.state, ChannelCoreState::Open);
    EXPECT_TRUE(snapshot.resources_attached);
    EXPECT_FALSE(snapshot.request_ledgers_drained);
    ExpectPairedIdentities(snapshot, opened.channel_epoch);
    EXPECT_EQ(InspectDomain(domain).channel_objects, 1U);
    EXPECT_EQ(InspectDomain(domain).channel_bytes, kChannelCoreQueuedBufferBytes);
    EXPECT_EQ(ChannelCoreInitialize(&core, domain).status, ChannelCoreStatus::AlreadyInitialized);

    // Pin slots advance on reuse. A copied old token cannot release the newer
    // pin even though it occupies the same physical slot in the same epoch.
    const ChannelCorePinResult aba_first = ChannelCoreAcquireOperation(&core, opened.channel_epoch, 0xA1U);
    EXPECT_EQ(aba_first.status, ChannelCoreStatus::Ok);
    EXPECT_EQ(ChannelCoreReleaseOperation(&core, aba_first.pin), ChannelCoreStatus::Ok);
    const ChannelCorePinResult aba_second = ChannelCoreAcquireOperation(&core, opened.channel_epoch, 0xA1U);
    EXPECT_EQ(aba_second.status, ChannelCoreStatus::Ok);
    EXPECT_EQ(aba_second.pin.slot, aba_first.pin.slot);
    EXPECT_TRUE(aba_second.pin.generation > aba_first.pin.generation);
    EXPECT_EQ(ChannelCoreReleaseOperation(&core, aba_first.pin), ChannelCoreStatus::StaleOperation);
    EXPECT_EQ(ChannelCoreReleaseOperation(&core, aba_second.pin), ChannelCoreStatus::Ok);

    const ChannelCorePinResult pin = ChannelCoreAcquireOperation(&core, opened.channel_epoch, 0xC0DEU);
    EXPECT_EQ(pin.status, ChannelCoreStatus::Ok);
    EXPECT_EQ(ChannelCoreAcquireOperation(&core, opened.channel_epoch, kInvalidChannelCoreOperationBinding).status,
              ChannelCoreStatus::InvalidArgument);
    EXPECT_EQ(ChannelCoreAcquireOperation(&core, opened.channel_epoch + 1U, 0xC0DEU).status,
              ChannelCoreStatus::StaleEpoch);
    const ChannelCoreDirectionLease forward =
        ChannelCoreBorrowDirection(&core, pin.pin, ChannelCoreDirection::InitiatorToAcceptor);
    const ChannelCoreDirectionLease reverse =
        ChannelCoreBorrowDirection(&core, pin.pin, ChannelCoreDirection::AcceptorToInitiator);
    EXPECT_EQ(forward.status, ChannelCoreStatus::Ok);
    EXPECT_EQ(reverse.status, ChannelCoreStatus::Ok);
    EXPECT_TRUE(forward.port != nullptr && reverse.port != nullptr && forward.port != reverse.port);
    EXPECT_TRUE(forward.transfer_table != nullptr && reverse.transfer_table != nullptr &&
                forward.transfer_table != reverse.transfer_table);

    const ChannelCoreRequestReserveResult forward_request_one =
        ChannelCoreReserveRequest(&core, pin.pin, ChannelCoreDirection::InitiatorToAcceptor, 1);
    const ChannelCoreRequestReserveResult reverse_request =
        ChannelCoreReserveRequest(&core, pin.pin, ChannelCoreDirection::AcceptorToInitiator, 1);
    EXPECT_EQ(forward_request_one.status, ChannelCoreStatus::Ok);
    EXPECT_EQ(reverse_request.status, ChannelCoreStatus::Ok);
    EXPECT_FALSE(forward_request_one.request_key == reverse_request.request_key);

    // A request crosses the directional ledger only through the exact live
    // operation pin. The receiving side commits once, receives unforgeable
    // completion authority, and consumes it once. Direction swaps, copied
    // authority, and duplicate transitions fail without consuming the row.
    EXPECT_EQ(ChannelCoreCommitRequest(&core, pin.pin, ChannelCoreDirection::AcceptorToInitiator,
                                       forward_request_one.request_key)
                  .ledger_status,
              EndpointRequestLedgerStatus::StaleIdentity);
    const ChannelCoreRequestCommitResult committed = ChannelCoreCommitRequest(
        &core, pin.pin, ChannelCoreDirection::InitiatorToAcceptor, forward_request_one.request_key);
    EXPECT_EQ(committed.status, ChannelCoreStatus::Ok);
    EXPECT_TRUE(EndpointRequestCompletionAuthorityIsValid(committed.completion_authority));
    EXPECT_EQ(ChannelCoreCommitRequest(&core, pin.pin, ChannelCoreDirection::InitiatorToAcceptor,
                                       forward_request_one.request_key)
                  .ledger_status,
              EndpointRequestLedgerStatus::ReplayRejected);
    EXPECT_EQ(ChannelCoreCompleteRequest(&core, pin.pin, ChannelCoreDirection::AcceptorToInitiator,
                                         committed.completion_authority)
                  .ledger_status,
              EndpointRequestLedgerStatus::StaleIdentity);
    EXPECT_EQ(ChannelCoreCompleteRequest(&core, pin.pin, ChannelCoreDirection::InitiatorToAcceptor,
                                         committed.completion_authority)
                  .status,
              ChannelCoreStatus::Ok);
    EXPECT_EQ(ChannelCoreCompleteRequest(&core, pin.pin, ChannelCoreDirection::InitiatorToAcceptor,
                                         committed.completion_authority)
                  .ledger_status,
              EndpointRequestLedgerStatus::ReplayRejected);

    const ChannelCoreRequestReserveResult forward_request_two =
        ChannelCoreReserveRequest(&core, pin.pin, ChannelCoreDirection::InitiatorToAcceptor, 2);
    EXPECT_EQ(forward_request_two.status, ChannelCoreStatus::Ok);
    EXPECT_EQ(ChannelCoreCancelRequest(&core, pin.pin, ChannelCoreDirection::InitiatorToAcceptor,
                                       forward_request_two.request_key)
                  .status,
              ChannelCoreStatus::Ok);
    EXPECT_EQ(ChannelCoreCancelRequest(&core, pin.pin, ChannelCoreDirection::InitiatorToAcceptor,
                                       forward_request_two.request_key)
                  .ledger_status,
              EndpointRequestLedgerStatus::ReplayRejected);

    const ChannelCoreRequestReserveResult forward_request =
        ChannelCoreReserveRequest(&core, pin.pin, ChannelCoreDirection::InitiatorToAcceptor, 3);
    EXPECT_EQ(forward_request.status, ChannelCoreStatus::Ok);
    ChannelCoreOperationPin wrong_binding = pin.pin;
    ++wrong_binding.binding;
    EXPECT_EQ(ChannelCoreCommitRequest(&core, wrong_binding, ChannelCoreDirection::InitiatorToAcceptor,
                                       forward_request.request_key)
                  .status,
              ChannelCoreStatus::StaleOperation);
    EXPECT_EQ(ChannelCoreCommitRequest(&core, aba_first.pin, ChannelCoreDirection::InitiatorToAcceptor,
                                       forward_request.request_key)
                  .status,
              ChannelCoreStatus::StaleOperation);
    EXPECT_EQ(
        ChannelCoreCancelRequest(&core, pin.pin, ChannelCoreDirection::AcceptorToInitiator, forward_request.request_key)
            .ledger_status,
        EndpointRequestLedgerStatus::StaleIdentity);
    EXPECT_EQ(
        ChannelCoreCommitRequest(&core, pin.pin, ChannelCoreDirection::InitiatorToAcceptor, kInvalidEndpointRequestKey)
            .status,
        ChannelCoreStatus::InvalidArgument);

    // send-close-complete barrier: model a reply that has already been
    // published by committing its exact request before close linearizes. Its
    // completion authority must remain usable by the issued pin while the core
    // is Draining.
    const ChannelCoreRequestReserveResult reply_request =
        ChannelCoreReserveRequest(&core, pin.pin, ChannelCoreDirection::InitiatorToAcceptor, 4);
    EXPECT_EQ(reply_request.status, ChannelCoreStatus::Ok);
    const ChannelCoreRequestCommitResult reply_commit =
        ChannelCoreCommitRequest(&core, pin.pin, ChannelCoreDirection::InitiatorToAcceptor, reply_request.request_key);
    EXPECT_EQ(reply_commit.status, ChannelCoreStatus::Ok);

    // Drain must not wait for a live pin. It publishes Draining and closes the
    // ports outside the core lock (the close hook re-enters), but it preserves
    // both ledgers until every exact pin has settled its already-issued work.
    g_close_reentry_core.store(&core, std::memory_order_release);
    const ChannelCoreDrainResult busy_drain = ChannelCoreDrainExpected(&core, opened.channel_epoch);
    EXPECT_EQ(busy_drain.status, ChannelCoreStatus::Busy);
    EXPECT_EQ(g_close_reentry_status.load(std::memory_order_acquire), ChannelCoreStatus::Busy);
    EXPECT_EQ(busy_drain.request_cleanup[0].detached_count, 0U);
    EXPECT_EQ(busy_drain.request_cleanup[1].detached_count, 0U);
    EXPECT_TRUE(ChannelCoreDetachedCleanupIsEmpty(busy_drain.detached));
    snapshot = InspectCore(core);
    EXPECT_EQ(snapshot.state, ChannelCoreState::Draining);
    EXPECT_EQ(snapshot.active_operations, 1U);
    EXPECT_EQ(snapshot.active_requests[0], 2U);
    EXPECT_EQ(snapshot.active_requests[1], 1U);
    EXPECT_TRUE(snapshot.ports_close_notified);
    EXPECT_FALSE(snapshot.request_ledgers_drained);
    EXPECT_EQ(ChannelCoreAcquireOperation(&core, opened.channel_epoch, 0xC0DEU).status, ChannelCoreStatus::Draining);
    EXPECT_EQ(ChannelCoreBorrowDirection(&core, pin.pin, ChannelCoreDirection::InitiatorToAcceptor).status,
              ChannelCoreStatus::Draining);
    EXPECT_EQ(ChannelCoreReserveRequest(&core, pin.pin, ChannelCoreDirection::InitiatorToAcceptor, 5).status,
              ChannelCoreStatus::Draining);

    EXPECT_EQ(ChannelCoreCompleteRequest(&core, pin.pin, ChannelCoreDirection::InitiatorToAcceptor,
                                         reply_commit.completion_authority)
                  .status,
              ChannelCoreStatus::Ok);

    // dequeue-close-commit barrier: the peer has already dequeued this request
    // under the same operation pin. Close must not revoke the exact Commit that
    // records that accepted work.
    const ChannelCoreRequestCommitResult committed_after_close = ChannelCoreCommitRequest(
        &core, pin.pin, ChannelCoreDirection::InitiatorToAcceptor, forward_request.request_key);
    EXPECT_EQ(committed_after_close.status, ChannelCoreStatus::Ok);

    // reserve-close-cancel barrier: a sender whose publication did not finish
    // may consume its exact reservation after close instead of leaking it into
    // terminal cleanup.
    EXPECT_EQ(
        ChannelCoreCancelRequest(&core, pin.pin, ChannelCoreDirection::AcceptorToInitiator, reverse_request.request_key)
            .status,
        ChannelCoreStatus::Ok);
    snapshot = InspectCore(core);
    EXPECT_EQ(snapshot.active_requests[0], 1U);
    EXPECT_EQ(snapshot.active_requests[1], 0U);
    EXPECT_FALSE(snapshot.request_ledgers_drained);

    const ChannelCoreDrainResult repeated_busy = ChannelCoreDrainExpected(&core, opened.channel_epoch);
    EXPECT_EQ(repeated_busy.status, ChannelCoreStatus::Busy);
    EXPECT_EQ(repeated_busy.request_cleanup[0].detached_count, 0U);
    EXPECT_EQ(repeated_busy.request_cleanup[1].detached_count, 0U);
    EXPECT_EQ(ChannelCoreReleaseOperation(&core, pin.pin), ChannelCoreStatus::Ok);
    EXPECT_EQ(ChannelCoreReleaseOperation(&core, pin.pin), ChannelCoreStatus::StaleOperation);

    // Transfer-table close can be transiently Busy even after outer operation
    // pins quiesce. Request cleanup must remain ledger-owned on that non-success
    // result so the successful retry returns cleanup and detached ownership
    // together exactly once.
    g_transfer_close_busy_once.store(1, std::memory_order_release);
    const ChannelCoreDrainResult transfer_busy = ChannelCoreDrainExpected(&core, opened.channel_epoch);
    EXPECT_EQ(transfer_busy.status, ChannelCoreStatus::Busy);
    EXPECT_EQ(transfer_busy.request_cleanup[0].detached_count, 0U);
    EXPECT_EQ(transfer_busy.request_cleanup[1].detached_count, 0U);
    EXPECT_TRUE(ChannelCoreDetachedCleanupIsEmpty(transfer_busy.detached));
    snapshot = InspectCore(core);
    EXPECT_EQ(snapshot.state, ChannelCoreState::Draining);
    EXPECT_EQ(snapshot.active_operations, 0U);
    EXPECT_EQ(snapshot.active_requests[0], 1U);
    EXPECT_EQ(snapshot.active_requests[1], 0U);
    EXPECT_FALSE(snapshot.request_ledgers_drained);

    ChannelCoreDrainResult drained = ChannelCoreDrainExpected(&core, opened.channel_epoch);
    EXPECT_EQ(drained.status, ChannelCoreStatus::Ok);
    EXPECT_EQ(drained.request_cleanup[0].detached_count, 1U);
    EXPECT_EQ(drained.request_cleanup[1].detached_count, 0U);
    EXPECT_TRUE(drained.request_cleanup[0].detached_keys[0] == forward_request.request_key);
    EXPECT_FALSE(ChannelCoreDetachedCleanupIsEmpty(drained.detached));
    EXPECT_EQ(drained.detached.channel_epoch, opened.channel_epoch);
    snapshot = InspectCore(core);
    EXPECT_EQ(snapshot.state, ChannelCoreState::Drained);
    EXPECT_FALSE(snapshot.resources_attached);
    EXPECT_TRUE(snapshot.request_ledgers_drained);
    EXPECT_EQ(InspectDomain(domain).channel_objects, 1U);
    EXPECT_EQ(InspectDomain(domain).channel_bytes, kChannelCoreQueuedBufferBytes);

    const ChannelCoreDrainResult drained_replay = ChannelCoreDrainExpected(&core, opened.channel_epoch);
    EXPECT_EQ(drained_replay.status, ChannelCoreStatus::Ok);
    EXPECT_EQ(drained_replay.request_cleanup[0].detached_count, 0U);
    EXPECT_EQ(drained_replay.request_cleanup[1].detached_count, 0U);
    EXPECT_TRUE(ChannelCoreDetachedCleanupIsEmpty(drained_replay.detached));

    EXPECT_EQ(ChannelCoreReleaseDetachedCleanup(&drained.detached), ChannelCoreStatus::Ok);
    EXPECT_TRUE(ChannelCoreDetachedCleanupIsEmpty(drained.detached));
    EXPECT_EQ(ChannelCoreReleaseDetachedCleanup(&drained.detached), ChannelCoreStatus::InvalidCleanup);
    EXPECT_EQ(InspectDomain(domain).channel_objects, 0U);
    EXPECT_EQ(InspectDomain(domain).channel_bytes, 0ULL);

    // Reset prepares a new charged resource graph, then changes both ledger
    // identities together under the shared lock. Old-epoch tokens remain stale.
    const ChannelCoreOpenResult reset = ChannelCoreReset(&core, domain);
    EXPECT_EQ(reset.status, ChannelCoreStatus::Ok);
    EXPECT_TRUE(reset.channel_epoch > opened.channel_epoch);
    snapshot = InspectCore(core);
    EXPECT_EQ(snapshot.state, ChannelCoreState::Open);
    EXPECT_FALSE(snapshot.request_ledgers_drained);
    ExpectPairedIdentities(snapshot, reset.channel_epoch);
    EXPECT_EQ(ChannelCoreReleaseOperation(&core, pin.pin), ChannelCoreStatus::StaleEpoch);
    EXPECT_EQ(InspectDomain(domain).channel_objects, 1U);
    EXPECT_EQ(InspectDomain(domain).channel_bytes, kChannelCoreQueuedBufferBytes);

    const ChannelCorePinResult reset_pin = ChannelCoreAcquireOperation(&core, reset.channel_epoch, 0xBEEFU);
    EXPECT_EQ(reset_pin.status, ChannelCoreStatus::Ok);
    const ChannelCoreRequestReserveResult reset_request =
        ChannelCoreReserveRequest(&core, reset_pin.pin, ChannelCoreDirection::AcceptorToInitiator, 1);
    EXPECT_EQ(reset_request.status, ChannelCoreStatus::Ok);
    EXPECT_EQ(ChannelCoreReset(&core, domain).status, ChannelCoreStatus::ResetNotDrained);

    // A stale outer owner from the first generation must fail under the core
    // lock before it can transition the reset generation, detach its live
    // request, or close any newly-created resource.
    const u32 port_closes_before_stale_drain = g_port_close_calls.load(std::memory_order_relaxed);
    const u32 transfer_closes_before_stale_drain = g_transfer_close_calls.load(std::memory_order_relaxed);
    EXPECT_EQ(ChannelCoreDrainExpected(&core, kChannelEpochInvalid).status, ChannelCoreStatus::InvalidArgument);
    EXPECT_EQ(ChannelCoreDrainExpected(&core, opened.channel_epoch).status, ChannelCoreStatus::StaleEpoch);
    snapshot = InspectCore(core);
    EXPECT_EQ(snapshot.state, ChannelCoreState::Open);
    EXPECT_EQ(snapshot.channel_epoch, reset.channel_epoch);
    EXPECT_EQ(snapshot.active_operations, 1U);
    EXPECT_EQ(snapshot.active_requests[1], 1U);
    EXPECT_TRUE(snapshot.resources_attached);
    EXPECT_EQ(g_port_close_calls.load(std::memory_order_relaxed), port_closes_before_stale_drain);
    EXPECT_EQ(g_transfer_close_calls.load(std::memory_order_relaxed), transfer_closes_before_stale_drain);
    EXPECT_EQ(InspectDomain(domain).channel_objects, 1U);
    EXPECT_EQ(InspectDomain(domain).channel_bytes, kChannelCoreQueuedBufferBytes);

    EXPECT_EQ(ChannelCoreReleaseOperation(&core, reset_pin.pin), ChannelCoreStatus::Ok);
    drained = ChannelCoreDrainExpected(&core, reset.channel_epoch);
    EXPECT_EQ(drained.status, ChannelCoreStatus::Ok);
    EXPECT_EQ(drained.request_cleanup[0].detached_count, 0U);
    EXPECT_EQ(drained.request_cleanup[1].detached_count, 1U);
    EXPECT_TRUE(drained.request_cleanup[1].detached_keys[0] == reset_request.request_key);
    EXPECT_EQ(ChannelCoreReleaseDetachedCleanup(&drained.detached), ChannelCoreStatus::Ok);
    EXPECT_EQ(InspectDomain(domain).channel_objects, 0U);
    EXPECT_EQ(InspectDomain(domain).channel_bytes, 0ULL);
    EXPECT_TRUE(ResourceDomainRelease(domain));

    // A delayed initializer stops after argument preflight but before claiming
    // construction. The competing logical CPU wins the CAS and publishes the
    // body; when released, the loser performs only the CAS, observes Ready,
    // and never races a non-atomic canonical-body scan against publication.
    ResourceDomainKey initialize_race_domain = kInvalidResourceDomainKey;
    EXPECT_TRUE(ResourceDomainCreateTrusted(&initialize_race_domain));
    ChannelCore initialize_race{};
    InitializeRaceGate initialize_gate;
    ChannelCoreOpenResult delayed_result{};
    ChannelCoreHostArmInitializePreClaimHookForTest(&PauseBeforeInitializeClaim, &initialize_gate);
    std::thread delayed_initializer(
        [&] { delayed_result = ChannelCoreInitialize(&initialize_race, initialize_race_domain); });
    initialize_gate.preclaim_reached.wait();
    const ChannelCoreOpenResult winning_result = ChannelCoreInitialize(&initialize_race, initialize_race_domain);
    EXPECT_EQ(winning_result.status, ChannelCoreStatus::Ok);
    initialize_gate.allow_claim.count_down();
    delayed_initializer.join();
    EXPECT_EQ(delayed_result.status, ChannelCoreStatus::AlreadyInitialized);
    EXPECT_EQ(InspectDomain(initialize_race_domain).channel_objects, 1U);
    EXPECT_EQ(InspectDomain(initialize_race_domain).channel_bytes, kChannelCoreQueuedBufferBytes);
    ChannelCoreDrainResult initialize_race_drain = ChannelCoreDrain(&initialize_race);
    EXPECT_EQ(initialize_race_drain.status, ChannelCoreStatus::Ok);
    EXPECT_EQ(ChannelCoreReleaseDetachedCleanup(&initialize_race_drain.detached), ChannelCoreStatus::Ok);
    EXPECT_EQ(InspectDomain(initialize_race_domain).channel_objects, 0U);
    EXPECT_EQ(InspectDomain(initialize_race_domain).channel_bytes, 0ULL);
    EXPECT_TRUE(ResourceDomainRelease(initialize_race_domain));

    // UINT64_MAX is issued once. The following construction performs a full
    // charge/allocation preparation and then proves exhaustion rollback leaves
    // both caller bytes and ResourceDomain accounting unchanged.
    ResourceDomainKey terminal_domain = kInvalidResourceDomainKey;
    EXPECT_TRUE(ResourceDomainCreateTrusted(&terminal_domain));
    ChannelCoreHostSetNextEpochForTest(kChannelEpochMaximum);
    ChannelCore terminal{};
    const ChannelCoreOpenResult terminal_open = ChannelCoreInitialize(&terminal, terminal_domain);
    EXPECT_EQ(terminal_open.status, ChannelCoreStatus::Ok);
    EXPECT_EQ(terminal_open.channel_epoch, kChannelEpochMaximum);
    ChannelCoreDrainResult terminal_drain = ChannelCoreDrain(&terminal);
    EXPECT_EQ(terminal_drain.status, ChannelCoreStatus::Ok);
    EXPECT_EQ(ChannelCoreReleaseDetachedCleanup(&terminal_drain.detached), ChannelCoreStatus::Ok);
    EXPECT_EQ(InspectDomain(terminal_domain).channel_objects, 0U);
    EXPECT_EQ(InspectDomain(terminal_domain).channel_bytes, 0ULL);

    ChannelCore exhausted{};
    const auto exhausted_bytes = BytesOf(exhausted);
    const u32 created_before_exhaustion = g_port_create_calls.load(std::memory_order_relaxed);
    const u32 destroyed_before_exhaustion = g_port_destroy_calls.load(std::memory_order_relaxed);
    EXPECT_EQ(ChannelCoreInitialize(&exhausted, terminal_domain).status, ChannelCoreStatus::EpochExhausted);
    EXPECT_TRUE(BytesOf(exhausted) == exhausted_bytes);
    EXPECT_EQ(InspectDomain(terminal_domain).channel_objects, 0U);
    EXPECT_EQ(InspectDomain(terminal_domain).channel_bytes, 0ULL);
    EXPECT_EQ(g_port_create_calls.load(std::memory_order_relaxed), created_before_exhaustion + 2U);
    EXPECT_EQ(g_port_destroy_calls.load(std::memory_order_relaxed), destroyed_before_exhaustion + 2U);
    EXPECT_TRUE(ResourceDomainRelease(terminal_domain));

    EXPECT_EQ(g_port_create_calls.load(std::memory_order_relaxed) - 1U,
              g_port_destroy_calls.load(std::memory_order_relaxed));
    // One failed creation increments the call counter without creating an
    // object; every successfully-created port was destroyed exactly once.
    EXPECT_TRUE(g_transfer_close_calls.load(std::memory_order_relaxed) >= 6U);

    return duetos_host_test::finish_main("test_channel_core");
}
