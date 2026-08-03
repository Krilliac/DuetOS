// Hosted hostile coverage for core/service_exit_reap_ledger.{h,cpp}: the
// durable reap pipeline between the exact exit observer, the lifecycle
// broker's ObserveExit commit, ServiceDirectoryOwnerCrashed teardown, and the
// public delivery/ACK plane a later SYS_SERVICE_CONTROL surface will drive.

#include "crypto_host_shims.h"
#include "host_test_helper.h"

#include "core/service_exit_reap_ledger.h"
#include "crypto/sha256.h"

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <new>
#include <thread>
#include <type_traits>
#include <vector>

namespace
{

std::mutex g_host_object_lock;

} // namespace

namespace duetos::sync
{

IrqFlags SpinLockAcquire(SpinLock& lock)
{
    std::atomic_ref<u32> next_ticket(*const_cast<u32*>(&lock.next_ticket));
    const u32 ticket = next_ticket.fetch_add(1, std::memory_order_relaxed);
    std::atomic_ref<u32> now_serving(*const_cast<u32*>(&lock.now_serving));
    while (now_serving.load(std::memory_order_acquire) != ticket)
        std::this_thread::yield();
    return IrqFlags{0};
}

void SpinLockRelease(SpinLock& lock, IrqFlags)
{
    std::atomic_ref<u32> now_serving(*const_cast<u32*>(&lock.now_serving));
    now_serving.fetch_add(1, std::memory_order_release);
}

} // namespace duetos::sync

// The reap pipeline never opens an endpoint.  Supply the standard hosted
// ChannelCore leaf doubles so this binary drives the real endpoint-owner and
// directory state machines without the scheduler or kernel allocator.
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

using namespace duetos::core;
using duetos::u16;
using duetos::u32;
using duetos::u64;
using duetos::u8;

static_assert(kServiceExitReapLedgerCapacity == kServiceExitObserverCapacity * kServiceExitReapRowsPerObserverSlot);
static_assert(kServiceExitReapLedgerCapacity >= kServiceExitObserverCapacity);
static_assert(!std::is_copy_constructible_v<ServiceExitReapLedger>);
static_assert(!std::is_copy_assignable_v<ServiceExitReapLedger>);

// The durable stage ladder is forward-only; the underlying values encode the
// irreversible ordering the pump relies on.
static_assert(static_cast<u8>(ServiceExitReapRowStage::Acquired) <
              static_cast<u8>(ServiceExitReapRowStage::LifecycleCommitted));
static_assert(static_cast<u8>(ServiceExitReapRowStage::LifecycleCommitted) <
              static_cast<u8>(ServiceExitReapRowStage::DirectoryDraining));
static_assert(static_cast<u8>(ServiceExitReapRowStage::DirectoryDraining) <
              static_cast<u8>(ServiceExitReapRowStage::DirectoryCommitted));
static_assert(static_cast<u8>(ServiceExitReapRowStage::DirectoryCommitted) <
              static_cast<u8>(ServiceExitReapRowStage::ReadyForDelivery));
static_assert(static_cast<u8>(ServiceExitReapRowStage::ReadyForDelivery) <
              static_cast<u8>(ServiceExitReapRowStage::Delivered));

constexpr u64 kServicedIdentity = 100;
constexpr u64 kExecdIdentity = 200;

struct HostPause
{
    explicit HostPause(ServiceExitReapLedgerHostHookPoint wanted_point) : wanted(wanted_point) {}

    ServiceExitReapLedgerHostHookPoint wanted;
    std::mutex mutex;
    std::condition_variable changed;
    ServiceExitReapLedgerHostHookEvent event{};
    bool entered = false;
    bool released = false;
};

void PauseAtHostHook(const ServiceExitReapLedgerHostHookEvent& event, void* context)
{
    auto* pause = static_cast<HostPause*>(context);
    if (pause == nullptr || event.point != pause->wanted)
        return;
    std::unique_lock<std::mutex> guard(pause->mutex);
    pause->event = event;
    pause->entered = true;
    pause->changed.notify_all();
    pause->changed.wait(guard, [&] { return pause->released; });
}

bool WaitForHostPause(HostPause& pause)
{
    std::unique_lock<std::mutex> guard(pause.mutex);
    const bool entered = pause.changed.wait_for(guard, std::chrono::seconds(5), [&] { return pause.entered; });
    EXPECT_TRUE(entered);
    return entered;
}

void ReleaseHostPause(HostPause& pause)
{
    std::lock_guard<std::mutex> guard(pause.mutex);
    pause.released = true;
    pause.changed.notify_all();
}

duetos::loader::Hash256 Hash(u8 seed)
{
    duetos::loader::Hash256 hash{};
    for (u32 index = 0; index < sizeof(hash.bytes); ++index)
        hash.bytes[index] = static_cast<u8>(seed + index);
    return hash;
}

void SetText(u8* destination, u32 capacity, u8* length_out, const char* text)
{
    const u32 length = static_cast<u32>(std::strlen(text));
    EXPECT_TRUE(length <= capacity);
    for (u32 index = 0; index < capacity; ++index)
        destination[index] = index < length ? static_cast<u8>(text[index]) : 0;
    *length_out = static_cast<u8>(length);
}

void FillService(ServiceManifestServiceV1& service, u64 identity, u32 transfer_ref, u8 hash_seed, const char* name,
                 const char* path)
{
    service.service_identity = identity;
    service.executable_transfer_ref = transfer_ref;
    service.immutable_policy_selector = 1;
    service.executable_content_hash = Hash(hash_seed);
    service.requested_capability_ceiling = 1ULL << 2;
    service.requested_frame_budget_pages = 32;
    service.requested_tick_budget = 1000;
    service.requested_section_objects = 2;
    service.requested_section_pages = 16;
    service.kind = ServiceManifestKind::Native;
    service.restart_policy = ServiceManifestRestartPolicy::OnFailure;
    service.autostart = 1;
    service.resource_profile = ServiceManifestResourceProfile::AuthenticatedService;
    SetText(service.name, kServiceManifestServiceNameCapacity, &service.name_length, name);
    SetText(service.executable_path, kServiceManifestExecutablePathCapacity, &service.executable_path_length, path);
}

ServiceManifestDocumentV1 Document()
{
    ServiceManifestDocumentV1 document{};
    document.manifest_identity = 0xA001;
    document.signer_identity = 0xB001;
    document.profile_identity = 0xC001;
    document.service_count = 2;
    FillService(document.services[0], kServicedIdentity, 1, 0x10, "serviced", "/system/serviced");
    FillService(document.services[1], kExecdIdentity, 2, 0x40, "execd", "/system/execd");
    return document;
}

ServiceManifestAuthoritySnapshotV1 Authority(const ServiceManifestDocumentV1& document, const u8* bytes, u32 byte_count)
{
    ServiceManifestAuthoritySnapshotV1 authority{};
    authority.authority_identity = 0xD001;
    authority.manifest_identity = document.manifest_identity;
    authority.signer_identity = document.signer_identity;
    authority.profile_identity = document.profile_identity;
    duetos::crypto::Sha256Hash(bytes, byte_count, authority.sealed_object_hash.bytes);
    authority.sealed_object_extent = byte_count;
    authority.allowed_capabilities = kServiceManifestCapabilityMaskV1;
    authority.allowed_immutable_policies = 1ULL << 1;
    authority.maximum_frame_budget_pages = kServiceManifestFrameBudgetMaximum;
    authority.maximum_tick_budget = kServiceManifestTickBudgetMaximum;
    authority.allowed_service_kinds = kServiceManifestKnownKindMask;
    authority.allowed_resource_profiles = kServiceManifestKnownResourceProfileMask;
    authority.maximum_section_objects = kServiceManifestSectionObjectMaximum;
    authority.maximum_section_pages = kServiceManifestSectionPageMaximum;
    authority.maximum_services = static_cast<u16>(kServiceManifestMaximumServices);
    authority.maximum_dependencies = static_cast<u16>(kServiceManifestMaximumDependencies);
    authority.flags = kServiceManifestAuthoritySealed;
    return authority;
}

ServiceDirectoryName DirectoryName(const char* text)
{
    ServiceDirectoryName name{};
    const u32 length = static_cast<u32>(std::strlen(text));
    name.length = static_cast<u8>(length);
    for (u32 index = 0; index < length; ++index)
        name.bytes[index] = static_cast<u8>(text[index]);
    EXPECT_TRUE(ServiceDirectoryNameIsCanonical(name));
    return name;
}

ServiceEndpointCredentialSnapshot Credential()
{
    CredentialSecurityContext security{};
    security.real_uid = 100;
    security.effective_uid = 100;
    security.saved_uid = 100;
    security.fs_uid = 100;
    security.real_gid = 100;
    security.effective_gid = 100;
    security.saved_gid = 100;
    security.fs_gid = 100;
    security.win32_integrity = Win32IntegrityLevel::Low;
    EXPECT_TRUE(CredentialSecurityContextIsCanonical(security));
    return ServiceEndpointCredentialSnapshot{CredentialKey{1, 1}, security};
}

ProcessKey Key(u64 identity)
{
    return ProcessKey{identity, identity + 1000};
}

struct Fixture
{
    ServiceManifestAuthoritySnapshotV1 authority{};
    ServiceManifestPlanV1 plan{};
    ServiceLifecycleBroker broker{};
    ServiceEndpointOwner endpoint_owner{};
    ServiceDirectory directory{};
    ServiceExitObserver observer{};
    ServiceExitReapLedger ledger{};
    u64 next_now = 100;
    u64 next_process_identity = 0x5000;

    Fixture()
    {
        const ServiceManifestDocumentV1 document = Document();
        std::array<u8, kServiceManifestMaximumBytes> bytes{};
        const ServiceManifestEncodeResult encoded = ServiceManifestEncodeV1(bytes.data(), bytes.size(), document);
        EXPECT_EQ(encoded.error, ServiceManifestError::Ok);
        authority = Authority(document, bytes.data(), encoded.bytes_written);
        EXPECT_EQ(ServiceManifestValidateV1(bytes.data(), encoded.bytes_written, &authority, &plan),
                  ServiceManifestError::Ok);

        ServiceLifecycleBrokerEpoch epoch = ServiceLifecycleBrokerMintEpoch();
        EXPECT_TRUE(epoch.IsValid());
        EXPECT_EQ(ServiceLifecycleBrokerInitialize(&broker, &plan, &authority, &epoch), ServiceLifecycleStatus::Ok);
        EXPECT_EQ(ServiceEndpointOwnerInitialize(&endpoint_owner), ServiceEndpointStatus::Ok);
        EXPECT_EQ(ServiceDirectoryInitialize(&directory, &endpoint_owner), ServiceDirectoryStatus::Ok);

        ServiceExitObserverEpoch observer_epoch = ServiceExitObserverMintEpoch();
        EXPECT_TRUE(observer_epoch.IsValid());
        EXPECT_EQ(ServiceExitObserverInitialize(&observer, &observer_epoch), ServiceExitObserverStatus::Ok);
        EXPECT_EQ(ServiceExitReapLedgerInitialize(&ledger), ServiceExitReapStatus::Ok);
    }

    u64 Now() { return next_now++; }
};

struct ServiceSpec
{
    u64 identity;
    const char* name;
    u32 manifest_slot;
};

constexpr ServiceSpec kServicedSpec{kServicedIdentity, "serviced", 0};
constexpr ServiceSpec kExecdSpec{kExecdIdentity, "execd", 1};

struct PublishedService
{
    ServiceLifecycleStartTicket start;
    ServiceLifecycleInstanceToken instance;
    ServiceInstanceToken directory_owner;
    ServiceKey directory_key;
    ProcessKey process;
};

ServiceExitReapEventKey EventKey(const PublishedService& published, ServiceExitReapRowTicket ticket)
{
    return ServiceExitReapEventKey{
        published.start.broker_epoch,
        published.start.transition.service_identity,
        published.start.transition.generation,
        published.process,
        ticket.admission,
    };
}

ServiceExitReapEventKey EventKey(const ServiceExitReapDeliveryRecord& record)
{
    return ServiceExitReapEventKey{
        record.broker_epoch, record.service_identity, record.generation, record.process, record.event_sequence,
    };
}

u64 CurrentGeneration(Fixture& fixture, u64 identity)
{
    const ServiceLifecycleInspectResult inspected = ServiceLifecycleBrokerInspect(&fixture.broker, identity);
    EXPECT_EQ(inspected.status, ServiceLifecycleStatus::Ok);
    return inspected.snapshot.transition_generation;
}

ServiceLifecycleSnapshot InspectLifecycle(Fixture& fixture, u64 identity)
{
    const ServiceLifecycleInspectResult inspected = ServiceLifecycleBrokerInspect(&fixture.broker, identity);
    EXPECT_EQ(inspected.status, ServiceLifecycleStatus::Ok);
    return inspected.snapshot;
}

ServiceExitObserverSnapshot InspectObserver(Fixture& fixture)
{
    ServiceExitObserverSnapshot snapshot{};
    EXPECT_EQ(ServiceExitObserverInspect(&fixture.observer, &snapshot), ServiceExitObserverStatus::Ok);
    return snapshot;
}

// The exact publication path a managed service takes: lifecycle reserve,
// observer reserve, invisible directory reservation, observer bind at the
// (simulated) scheduler publication gate, then the joint lifecycle+directory
// publication commit.
PublishedService PublishService(Fixture& fixture, const ServiceSpec& spec)
{
    const u64 expected_generation = CurrentGeneration(fixture, spec.identity);
    const ServiceLifecycleStartResult start =
        ServiceLifecycleBrokerReserveStart(&fixture.broker, spec.identity, expected_generation, fixture.Now());
    EXPECT_EQ(start.status, ServiceLifecycleStatus::Ok);

    const ServiceExitReservationResult reservation = ServiceExitObserverReserve(&fixture.observer, start.ticket);
    EXPECT_EQ(reservation.status, ServiceExitObserverStatus::Ok);

    const u64 identity = fixture.next_process_identity++;
    const ProcessKey process = Key(identity);
    const ServiceInstanceKey instance_key{process.identity, process.pid};
    const ServiceInstanceToken owner{start.ticket.transition, instance_key};
    const ServiceDirectoryName name = DirectoryName(spec.name);
    const ServiceEndpointCredentialSnapshot credential = Credential();
    ServiceDirectoryReserveResult directory =
        ServiceDirectoryReserveRegistration(&fixture.directory, &name, spec.manifest_slot, owner, &credential);
    EXPECT_EQ(directory.status, ServiceDirectoryStatus::Ok);

    EXPECT_EQ(ServiceExitObserverBindAtSchedulerPublication(&fixture.observer, reservation.registration, process,
                                                            directory.reservation),
              ServiceExitObserverStatus::Ok);

    // The joint commit consumes the reservation, so snapshot the durable
    // directory ServiceKey first — it is the exact teardown authority the
    // observer captures from that same reservation before it is consumed.
    const ServiceKey directory_key = directory.reservation.service;
    const ServiceLifecycleDirectoryPublicationResult joined = ServiceLifecycleBrokerCommitDirectoryPublication(
        &fixture.broker, start.ticket, instance_key, fixture.Now(), &fixture.directory, &directory.reservation);
    EXPECT_EQ(joined.lifecycle_status, ServiceLifecycleStatus::Ok);
    EXPECT_EQ(joined.directory_status, ServiceDirectoryStatus::Ok);
    EXPECT_TRUE(ServiceLifecycleInstanceTokenIsValid(joined.instance));

    return PublishedService{start.ticket, joined.instance, owner, directory_key, process};
}

void CrashService(Fixture& fixture, const PublishedService& published, u32 exit_code)
{
    EXPECT_EQ(ServiceExitObserverPublishExit(&fixture.observer, published.process, exit_code),
              ServiceExitObserverStatus::Ok);
}

ServiceExitReapRowSnapshot InspectRow(Fixture& fixture, u32 row)
{
    const ServiceExitReapRowInspectResult inspected = ServiceExitReapLedgerInspectRow(&fixture.ledger, row);
    EXPECT_EQ(inspected.status, ServiceExitReapStatus::Ok);
    return inspected.snapshot;
}

// Publish + crash + acquire + pump-to-ready in one call; returns the public
// delivery token of the resulting ReadyForDelivery row.
struct ReadyEvent
{
    PublishedService published;
    ServiceExitReapRowTicket ticket;
    u64 token;
    ServiceExitReapEventKey event;
};

ReadyEvent StageReadyEvent(Fixture& fixture, const ServiceSpec& spec, u32 exit_code)
{
    const PublishedService published = PublishService(fixture, spec);
    CrashService(fixture, published, exit_code);
    const ServiceExitReapAcquireResult acquired =
        ServiceExitReapLedgerAcquireFromObserver(&fixture.ledger, &fixture.observer);
    EXPECT_EQ(acquired.status, ServiceExitReapStatus::Ok);
    const ServiceExitReapPumpResult pumped = ServiceExitReapLedgerPump(
        &fixture.ledger, &fixture.broker, &fixture.directory, &fixture.observer, fixture.Now(), 8);
    EXPECT_EQ(pumped.status, ServiceExitReapStatus::Ok);
    const ServiceExitReapRowSnapshot row = InspectRow(fixture, acquired.ticket.row);
    EXPECT_EQ(row.stage, ServiceExitReapRowStage::ReadyForDelivery);
    EXPECT_NE(row.delivery_token, kServiceExitReapInvalidDeliveryToken);
    return ReadyEvent{published, acquired.ticket, row.delivery_token, EventKey(published, acquired.ticket)};
}

} // namespace

int main()
{
    // Null/misuse and canonical init -> close -> reinit before any traffic.
    {
        EXPECT_EQ(ServiceExitReapLedgerInitialize(nullptr), ServiceExitReapStatus::NullArgument);
        ServiceExitReapLedger ledger{};
        ServiceExitObserver observer{};
        EXPECT_EQ(ServiceExitReapLedgerAcquireFromObserver(nullptr, &observer).status,
                  ServiceExitReapStatus::NullArgument);
        EXPECT_EQ(ServiceExitReapLedgerAcquireFromObserver(&ledger, nullptr).status,
                  ServiceExitReapStatus::NullArgument);
        EXPECT_EQ(ServiceExitReapLedgerAcquireFromObserver(&ledger, &observer).status,
                  ServiceExitReapStatus::NotInitialized);
        EXPECT_EQ(ServiceExitReapLedgerClose(&ledger), ServiceExitReapStatus::NotInitialized);
        ServiceLifecycleBroker broker{};
        ServiceDirectory directory{};
        EXPECT_EQ(ServiceExitReapLedgerPump(&ledger, &broker, &directory, &observer, 0, 0).status,
                  ServiceExitReapStatus::NotInitialized);
        EXPECT_EQ(ServiceExitReapLedgerInitialize(&ledger), ServiceExitReapStatus::Ok);
        EXPECT_EQ(ServiceExitReapLedgerInitialize(&ledger), ServiceExitReapStatus::AlreadyInitialized);
        EXPECT_EQ(ServiceExitReapLedgerPump(&ledger, &broker, &directory, &observer, 0, 0).status,
                  ServiceExitReapStatus::Ok);
        const ServiceExitReapEventKey valid_event{1, 1, 1, Key(1), 1};
        EXPECT_EQ(ServiceExitReapLedgerAcknowledgeDelivery(&ledger, kInvalidServiceExitReapEventKey, 77, Key(1)),
                  ServiceExitReapStatus::InvalidEventKey);
        EXPECT_EQ(ServiceExitReapLedgerAcknowledgeDelivery(&ledger, valid_event, 0, Key(1)),
                  ServiceExitReapStatus::StaleToken);
        EXPECT_EQ(ServiceExitReapLedgerAcknowledgeDelivery(&ledger, valid_event, 77, kInvalidProcessKey),
                  ServiceExitReapStatus::InvalidProcessKey);
        EXPECT_EQ(ServiceExitReapLedgerDequeueForDelivery(&ledger, kInvalidProcessKey).status,
                  ServiceExitReapStatus::InvalidProcessKey);
        ledger.state = static_cast<ServiceExitReapLedgerState>(0xFF);
        ServiceExitReapLedgerSnapshot corrupt_snapshot{};
        EXPECT_EQ(ServiceExitReapLedgerInspect(&ledger, &corrupt_snapshot), ServiceExitReapStatus::CorruptState);
        EXPECT_EQ(ServiceExitReapLedgerPump(&ledger, &broker, &directory, &observer, 0, 0).status,
                  ServiceExitReapStatus::CorruptState);
        ledger.state = ServiceExitReapLedgerState::Open;
        EXPECT_EQ(ServiceExitReapLedgerClose(&ledger), ServiceExitReapStatus::Ok);
        EXPECT_EQ(ServiceExitReapLedgerPump(&ledger, &broker, &directory, &observer, 0, 0).status,
                  ServiceExitReapStatus::Closed);
        EXPECT_EQ(ServiceExitReapLedgerAcquireFromObserver(&ledger, &observer).status, ServiceExitReapStatus::Closed);
        EXPECT_EQ(ServiceExitReapLedgerInitialize(&ledger), ServiceExitReapStatus::Ok);
        EXPECT_EQ(ServiceExitReapLedgerClose(&ledger), ServiceExitReapStatus::Ok);

        ServiceExitReapLedger corrupt_storage{};
        corrupt_storage.reserved16 = 1;
        EXPECT_EQ(ServiceExitReapLedgerInitialize(&corrupt_storage), ServiceExitReapStatus::CorruptState);
    }

    // Normal exactly-once pipeline: one crash flows Acquired ->
    // LifecycleCommitted -> DirectoryCommitted -> ReadyForDelivery ->
    // Delivered -> freed by the exact ACK, with wrong/foreign/replayed ACKs
    // failing closed against a second in-flight row.
    {
        Fixture fixture;
        const PublishedService published = PublishService(fixture, kServicedSpec);
        CrashService(fixture, published, 7);
        EXPECT_EQ(InspectObserver(fixture).pending_count, 1U);

        const ServiceExitReapAcquireResult acquired =
            ServiceExitReapLedgerAcquireFromObserver(&fixture.ledger, &fixture.observer);
        EXPECT_EQ(acquired.status, ServiceExitReapStatus::Ok);
        EXPECT_TRUE(ServiceExitReapRowTicketIsValid(acquired.ticket));
        EXPECT_EQ(InspectObserver(fixture).pending_count, 0U);

        // The observer receipt was dequeued exactly once; there is no second
        // event to acquire and the observer sees no further pending work.
        EXPECT_EQ(ServiceExitReapLedgerAcquireFromObserver(&fixture.ledger, &fixture.observer).status,
                  ServiceExitReapStatus::NoEvent);

        // Teardown is not yet settled, so the service cannot restage.
        const ServiceExitReapEventKey exact_event = EventKey(published, acquired.ticket);
        const ServiceExitReapRestageResult blocked =
            ServiceExitReapLedgerQueryRestageExact(&fixture.ledger, exact_event);
        EXPECT_EQ(blocked.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(blocked.eligible, 0U);
        EXPECT_EQ(blocked.blocking_rows, 1U);
        ServiceExitReapEventKey wrong_generation = exact_event;
        ++wrong_generation.transition_generation;
        EXPECT_EQ(ServiceExitReapLedgerQueryRestageExact(&fixture.ledger, wrong_generation).status,
                  ServiceExitReapStatus::NotFound);

        const ServiceExitReapPumpResult pumped = ServiceExitReapLedgerPump(
            &fixture.ledger, &fixture.broker, &fixture.directory, &fixture.observer, fixture.Now(), 8);
        EXPECT_EQ(pumped.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(pumped.lifecycle_committed, 1U);
        EXPECT_EQ(pumped.directory_committed, 1U);
        EXPECT_EQ(pumped.ready_transitions, 1U);
        EXPECT_EQ(pumped.rows_pending, 0U);

        const ServiceLifecycleSnapshot lifecycle = InspectLifecycle(fixture, kServicedIdentity);
        EXPECT_EQ(lifecycle.phase, ServiceTransitionPhase::Exited);
        EXPECT_EQ(lifecycle.observed_exits, 1U);
        EXPECT_EQ(lifecycle.failed_exits, 1U);
        EXPECT_EQ(ServiceDirectoryInspectExact(&fixture.directory, published.directory_key).status,
                  ServiceDirectoryStatus::StaleKey);
        const ServiceExitObserverSnapshot observer_after = InspectObserver(fixture);
        EXPECT_EQ(observer_after.active_count, 0U);
        EXPECT_EQ(observer_after.pending_count, 0U);

        // Settled teardown makes restage eligible without any userland ACK.
        const ServiceExitReapRestageResult eligible =
            ServiceExitReapLedgerQueryRestageExact(&fixture.ledger, exact_event);
        EXPECT_EQ(eligible.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(eligible.eligible, 1U);
        EXPECT_EQ(eligible.blocking_rows, 0U);

        // Stage a second in-flight event (execd) to prove ACK isolation
        // cannot mutate a neighbouring row.
        const ReadyEvent other = StageReadyEvent(fixture, kExecdSpec, 9);
        const ProcessKey serviced_owner = Key(9001);
        const ProcessKey execd_owner = Key(9002);

        const ServiceExitReapDeliveryResult delivered =
            ServiceExitReapLedgerDequeueForDelivery(&fixture.ledger, serviced_owner);
        EXPECT_EQ(delivered.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(delivered.record.service_identity, kServicedIdentity);
        EXPECT_EQ(delivered.record.generation, 1ULL);
        EXPECT_NE(delivered.record.delivery_token, kServiceExitReapInvalidDeliveryToken);
        EXPECT_EQ(delivered.record.exit_code, 7U);
        EXPECT_EQ(delivered.record.failed, 1U);
        EXPECT_EQ(delivered.record.lifecycle_disposition, ServiceExitReapLifecycleDisposition::Committed);
        EXPECT_EQ(delivered.record.directory_disposition, ServiceExitReapDirectoryDisposition::Committed);
        EXPECT_EQ(delivered.record.observer_ack_disposition, ServiceExitReapObserverAckDisposition::Acknowledged);
        EXPECT_EQ(delivered.record.delivery_count, 1U);
        EXPECT_EQ(delivered.record.process, published.process);

        const ServiceExitReapDeliveryResult other_delivered =
            ServiceExitReapLedgerDequeueForDelivery(&fixture.ledger, execd_owner);
        EXPECT_EQ(other_delivered.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(other_delivered.record.service_identity, kExecdIdentity);

        // Wrong token, foreign acknowledger, and cross-row ACKs all fail
        // closed without touching either row.
        EXPECT_EQ(ServiceExitReapLedgerAcknowledgeDelivery(&fixture.ledger, EventKey(delivered.record),
                                                           delivered.record.delivery_token + 12345, serviced_owner),
                  ServiceExitReapStatus::StaleToken);
        EXPECT_EQ(ServiceExitReapLedgerAcknowledgeDelivery(&fixture.ledger, EventKey(delivered.record),
                                                           delivered.record.delivery_token, execd_owner),
                  ServiceExitReapStatus::ForeignAcknowledger);
        ServiceExitReapEventKey mismatched_event = EventKey(delivered.record);
        ++mismatched_event.event_sequence;
        EXPECT_EQ(ServiceExitReapLedgerAcknowledgeDelivery(&fixture.ledger, mismatched_event,
                                                           delivered.record.delivery_token, serviced_owner),
                  ServiceExitReapStatus::StaleEvent);
        EXPECT_EQ(ServiceExitReapLedgerAcknowledgeDelivery(&fixture.ledger, EventKey(other_delivered.record),
                                                           other_delivered.record.delivery_token, serviced_owner),
                  ServiceExitReapStatus::ForeignAcknowledger);
        EXPECT_EQ(InspectRow(fixture, acquired.ticket.row).stage, ServiceExitReapRowStage::Delivered);
        EXPECT_EQ(InspectRow(fixture, other.ticket.row).stage, ServiceExitReapRowStage::Delivered);

        EXPECT_EQ(ServiceExitReapLedgerAcknowledgeDelivery(&fixture.ledger, EventKey(delivered.record),
                                                           delivered.record.delivery_token, serviced_owner),
                  ServiceExitReapStatus::Ok);
        EXPECT_EQ(ServiceExitReapLedgerAcknowledgeDelivery(&fixture.ledger, EventKey(delivered.record),
                                                           delivered.record.delivery_token, serviced_owner),
                  ServiceExitReapStatus::StaleToken);
        EXPECT_EQ(ServiceExitReapLedgerAcknowledgeDelivery(&fixture.ledger, EventKey(other_delivered.record),
                                                           other_delivered.record.delivery_token, execd_owner),
                  ServiceExitReapStatus::Ok);

        ServiceExitReapLedgerSnapshot snapshot{};
        EXPECT_EQ(ServiceExitReapLedgerInspect(&fixture.ledger, &snapshot), ServiceExitReapStatus::Ok);
        EXPECT_EQ(snapshot.live_rows, 0U);
        EXPECT_EQ(ServiceExitReapLedgerQueryRestageExact(&fixture.ledger, exact_event).status,
                  ServiceExitReapStatus::NotFound);
    }

    // Pre-commit rollback requeues the exact receipt; after the lifecycle
    // commit settles, rollback refuses and the receipt can never re-enter the
    // observer queue.
    {
        Fixture fixture;
        const PublishedService published = PublishService(fixture, kServicedSpec);
        CrashService(fixture, published, 0);
        const ServiceExitReapAcquireResult acquired =
            ServiceExitReapLedgerAcquireFromObserver(&fixture.ledger, &fixture.observer);
        EXPECT_EQ(acquired.status, ServiceExitReapStatus::Ok);

        ServiceExitReapRowTicket stale = acquired.ticket;
        stale.admission += 1;
        EXPECT_EQ(ServiceExitReapLedgerRollbackAcquired(&fixture.ledger, &fixture.observer, stale).status,
                  ServiceExitReapStatus::StaleTicket);

        const ServiceExitReapRollbackResult rolled_back =
            ServiceExitReapLedgerRollbackAcquired(&fixture.ledger, &fixture.observer, acquired.ticket);
        EXPECT_EQ(rolled_back.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(rolled_back.observer_status, ServiceExitObserverStatus::Ok);
        EXPECT_EQ(InspectObserver(fixture).pending_count, 1U);
        ServiceExitReapLedgerSnapshot snapshot{};
        EXPECT_EQ(ServiceExitReapLedgerInspect(&fixture.ledger, &snapshot), ServiceExitReapStatus::Ok);
        EXPECT_EQ(snapshot.live_rows, 0U);

        // The requeued event is replay-safe: the exact receipt is acquired
        // again and this time committed.
        const ServiceExitReapAcquireResult reacquired =
            ServiceExitReapLedgerAcquireFromObserver(&fixture.ledger, &fixture.observer);
        EXPECT_EQ(reacquired.status, ServiceExitReapStatus::Ok);
        const ServiceExitReapPumpResult pumped = ServiceExitReapLedgerPump(
            &fixture.ledger, &fixture.broker, &fixture.directory, &fixture.observer, fixture.Now(), 1);
        EXPECT_EQ(pumped.lifecycle_committed, 1U);
        EXPECT_EQ(InspectRow(fixture, reacquired.ticket.row).stage, ServiceExitReapRowStage::LifecycleCommitted);

        EXPECT_EQ(ServiceExitReapLedgerRollbackAcquired(&fixture.ledger, &fixture.observer, reacquired.ticket).status,
                  ServiceExitReapStatus::WrongStage);
        EXPECT_EQ(InspectObserver(fixture).pending_count, 0U);
        EXPECT_EQ(InspectLifecycle(fixture, kServicedIdentity).observed_exits, 1U);
    }

    // Hostile row corruption is detected before rollback, restage, delivery,
    // or owner-exit mutation can consume authority.
    {
        Fixture fixture;
        const PublishedService published = PublishService(fixture, kServicedSpec);
        CrashService(fixture, published, 2);
        const ServiceExitReapAcquireResult acquired =
            ServiceExitReapLedgerAcquireFromObserver(&fixture.ledger, &fixture.observer);
        EXPECT_EQ(acquired.status, ServiceExitReapStatus::Ok);
        fixture.ledger.rows[acquired.ticket.row].reserved8[0] = 1;
        EXPECT_EQ(ServiceExitReapLedgerQueryRestageExact(&fixture.ledger, EventKey(published, acquired.ticket)).status,
                  ServiceExitReapStatus::CorruptState);
        EXPECT_EQ(ServiceExitReapLedgerRollbackAcquired(&fixture.ledger, &fixture.observer, acquired.ticket).status,
                  ServiceExitReapStatus::CorruptState);
        EXPECT_EQ(ServiceExitReapLedgerNotifyDeliveryOwnerExit(&fixture.ledger, Key(42)).status,
                  ServiceExitReapStatus::CorruptState);
        fixture.ledger.rows[acquired.ticket.row].reserved8[0] = 0;
        EXPECT_EQ(ServiceExitReapLedgerRollbackAcquired(&fixture.ledger, &fixture.observer, acquired.ticket).status,
                  ServiceExitReapStatus::Ok);
    }

    // Dispositions are evidence only when paired with the exact status that
    // produced them.  A one-byte status/disposition corruption must not turn a
    // terminal refusal into restage authority or expose a noncanonical row.
    {
        Fixture fixture;
        const ReadyEvent ready = StageReadyEvent(fixture, kServicedSpec, 3);
        ServiceExitReapRow& row = fixture.ledger.rows[ready.ticket.row];

        row.lifecycle_status = ServiceLifecycleStatus::StaleGeneration;
        EXPECT_EQ(ServiceExitReapLedgerQueryRestageExact(&fixture.ledger, ready.event).status,
                  ServiceExitReapStatus::CorruptState);
        row.lifecycle_status = ServiceLifecycleStatus::Ok;

        row.lifecycle_disposition = ServiceExitReapLifecycleDisposition::RefusedTerminal;
        EXPECT_EQ(ServiceExitReapLedgerInspectRow(&fixture.ledger, ready.ticket.row).status,
                  ServiceExitReapStatus::CorruptState);
        row.lifecycle_disposition = ServiceExitReapLifecycleDisposition::Committed;

        row.directory_status = ServiceDirectoryStatus::OwnerMismatch;
        EXPECT_EQ(ServiceExitReapLedgerQueryRestageExact(&fixture.ledger, ready.event).status,
                  ServiceExitReapStatus::CorruptState);
        row.directory_status = ServiceDirectoryStatus::Ok;

        row.directory_disposition = ServiceExitReapDirectoryDisposition::SettledAbsent;
        EXPECT_EQ(ServiceExitReapLedgerInspectRow(&fixture.ledger, ready.ticket.row).status,
                  ServiceExitReapStatus::CorruptState);
        row.directory_disposition = ServiceExitReapDirectoryDisposition::Committed;

        row.directory_disposition = ServiceExitReapDirectoryDisposition::RefusedTerminal;
        row.directory_status = ServiceDirectoryStatus::EndpointReleaseFailed;
        row.directory_endpoint_status = ServiceEndpointStatus::Busy;
        EXPECT_EQ(ServiceExitReapLedgerInspectRow(&fixture.ledger, ready.ticket.row).status,
                  ServiceExitReapStatus::CorruptState);
        row.directory_disposition = ServiceExitReapDirectoryDisposition::Committed;
        row.directory_status = ServiceDirectoryStatus::Ok;
        row.directory_endpoint_status = ServiceEndpointStatus::Ok;

        row.observer_ack_status = ServiceExitObserverStatus::Busy;
        EXPECT_EQ(ServiceExitReapLedgerInspectRow(&fixture.ledger, ready.ticket.row).status,
                  ServiceExitReapStatus::CorruptState);
        row.observer_ack_status = ServiceExitObserverStatus::Ok;
        EXPECT_EQ(ServiceExitReapLedgerInspectRow(&fixture.ledger, ready.ticket.row).status, ServiceExitReapStatus::Ok);
    }

    // ServiceDirectoryOwnerCrashed Busy retains the exact row for later pump
    // progress; retries never re-run ObserveExit and never requeue the
    // observer receipt, and the row is never dropped.
    {
        Fixture fixture;
        const PublishedService published = PublishService(fixture, kServicedSpec);
        CrashService(fixture, published, 3);
        const ServiceExitReapAcquireResult acquired =
            ServiceExitReapLedgerAcquireFromObserver(&fixture.ledger, &fixture.observer);
        EXPECT_EQ(acquired.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(ServiceExitReapLedgerPump(&fixture.ledger, &fixture.broker, &fixture.directory, &fixture.observer,
                                            fixture.Now(), 1)
                      .lifecycle_committed,
                  1U);
        EXPECT_EQ(InspectLifecycle(fixture, kServicedIdentity).observed_exits, 1U);

        // A live lookup operation pin keeps the directory row from recycling,
        // so OwnerCrashed reports Busy and the row parks in DirectoryDraining.
        const ServiceDirectoryName name = DirectoryName("serviced");
        const ServiceDirectoryLookupResult looked_up = ServiceDirectoryLookup(&fixture.directory, &name);
        EXPECT_EQ(looked_up.status, ServiceDirectoryStatus::Ok);

        const ServiceExitReapPumpResult busy_pass = ServiceExitReapLedgerPump(
            &fixture.ledger, &fixture.broker, &fixture.directory, &fixture.observer, fixture.Now(), 4);
        EXPECT_EQ(busy_pass.status, ServiceExitReapStatus::Ok);
        EXPECT_TRUE(busy_pass.directory_busy >= 1U);
        EXPECT_EQ(busy_pass.ready_transitions, 0U);
        EXPECT_EQ(InspectRow(fixture, acquired.ticket.row).stage, ServiceExitReapRowStage::DirectoryDraining);

        // Retrying while still Busy: exactly zero additional ObserveExit
        // calls, zero requeues, and the observer slot is still held (the
        // receipt is acknowledged only at the ReadyForDelivery transition).
        const ServiceExitReapPumpResult busy_again = ServiceExitReapLedgerPump(
            &fixture.ledger, &fixture.broker, &fixture.directory, &fixture.observer, fixture.Now(), 4);
        EXPECT_TRUE(busy_again.directory_busy >= 1U);
        EXPECT_EQ(InspectLifecycle(fixture, kServicedIdentity).observed_exits, 1U);
        const ServiceExitObserverSnapshot held = InspectObserver(fixture);
        EXPECT_EQ(held.pending_count, 0U);
        EXPECT_EQ(held.active_count, 1U);
        const ServiceExitReapRestageResult blocked =
            ServiceExitReapLedgerQueryRestageExact(&fixture.ledger, EventKey(published, acquired.ticket));
        EXPECT_EQ(blocked.eligible, 0U);

        // Releasing the last operation pin completes the pin-blocked close in
        // the directory itself (every release path calls the recycler), so
        // the pump's bounded retry observes the exact settled-elsewhere
        // result: StaleKey.  The ledger records it as exact settled-absent
        // evidence, and the event still reaches
        // delivery — with zero additional ObserveExit calls and zero
        // requeues across the whole Busy interval.
        ServiceDirectoryOperationPin pin = looked_up.pin;
        EXPECT_EQ(ServiceDirectoryReleaseOperation(&fixture.directory, &pin), ServiceDirectoryStatus::Ok);
        EXPECT_EQ(ServiceDirectoryInspectExact(&fixture.directory, published.directory_key).status,
                  ServiceDirectoryStatus::StaleKey);
        const ServiceExitReapPumpResult drained = ServiceExitReapLedgerPump(
            &fixture.ledger, &fixture.broker, &fixture.directory, &fixture.observer, fixture.Now(), 4);
        EXPECT_EQ(drained.directory_committed, 1U);
        EXPECT_EQ(drained.ready_transitions, 1U);
        EXPECT_EQ(InspectRow(fixture, acquired.ticket.row).directory_disposition,
                  ServiceExitReapDirectoryDisposition::SettledAbsent);
        EXPECT_EQ(InspectLifecycle(fixture, kServicedIdentity).observed_exits, 1U);
        EXPECT_EQ(InspectObserver(fixture).active_count, 0U);

        const ProcessKey owner = Key(9100);
        const ServiceExitReapDeliveryResult delivered = ServiceExitReapLedgerDequeueForDelivery(&fixture.ledger, owner);
        EXPECT_EQ(delivered.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(delivered.record.directory_status, ServiceDirectoryStatus::StaleKey);
        EXPECT_EQ(ServiceExitReapLedgerAcknowledgeDelivery(&fixture.ledger, EventKey(delivered.record),
                                                           delivered.record.delivery_token, owner),
                  ServiceExitReapStatus::Ok);
    }

    // Two outstanding events for the same service coexist: the first reaches
    // ReadyForDelivery (making restage eligible before any userland ACK), the
    // service restarts and crashes again, and delivery drains FIFO.
    {
        Fixture fixture;
        const ReadyEvent first = StageReadyEvent(fixture, kServicedSpec, 11);
        const ServiceExitReapRestageResult eligible =
            ServiceExitReapLedgerQueryRestageExact(&fixture.ledger, first.event);
        EXPECT_EQ(eligible.eligible, 1U);

        const ReadyEvent second = StageReadyEvent(fixture, kServicedSpec, 12);
        EXPECT_NE(first.token, second.token);
        EXPECT_TRUE(second.token > first.token);
        ServiceExitReapLedgerSnapshot snapshot{};
        EXPECT_EQ(ServiceExitReapLedgerInspect(&fixture.ledger, &snapshot), ServiceExitReapStatus::Ok);
        EXPECT_EQ(snapshot.live_rows, 2U);
        const ServiceExitReapRestageResult backlog =
            ServiceExitReapLedgerQueryRestageExact(&fixture.ledger, second.event);
        EXPECT_EQ(backlog.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(backlog.eligible, 0U);
        EXPECT_EQ(backlog.live_rows, 2U);

        const ProcessKey owner = Key(9200);
        const ServiceExitReapDeliveryResult oldest = ServiceExitReapLedgerDequeueForDelivery(&fixture.ledger, owner);
        EXPECT_EQ(oldest.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(oldest.record.delivery_token, first.token);
        EXPECT_EQ(oldest.record.generation, 1ULL);
        EXPECT_EQ(oldest.record.exit_code, 11U);
        const ServiceExitReapDeliveryResult newest = ServiceExitReapLedgerDequeueForDelivery(&fixture.ledger, owner);
        EXPECT_EQ(newest.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(newest.record.delivery_token, second.token);
        EXPECT_EQ(newest.record.generation, 2ULL);
        EXPECT_EQ(newest.record.exit_code, 12U);
        EXPECT_EQ(ServiceExitReapLedgerAcknowledgeDelivery(&fixture.ledger, first.event, first.token, owner),
                  ServiceExitReapStatus::Ok);
        EXPECT_EQ(ServiceExitReapLedgerAcknowledgeDelivery(&fixture.ledger, second.event, second.token, owner),
                  ServiceExitReapStatus::Ok);
    }

    // A delivery-owner crash after dequeue but before ACK leaves the event
    // redeliverable to the next exact serviced incarnation under the SAME
    // public token; the dead lease's replayed ACK fails closed.
    {
        Fixture fixture;
        const ReadyEvent staged = StageReadyEvent(fixture, kServicedSpec, 5);
        const ProcessKey first_serviced = Key(9300);
        const ProcessKey second_serviced = Key(9301);

        const ServiceExitReapDeliveryResult first_delivery =
            ServiceExitReapLedgerDequeueForDelivery(&fixture.ledger, first_serviced);
        EXPECT_EQ(first_delivery.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(first_delivery.record.delivery_token, staged.token);
        EXPECT_EQ(first_delivery.record.delivery_count, 1U);

        const ServiceExitReapOwnerExitResult reverted =
            ServiceExitReapLedgerNotifyDeliveryOwnerExit(&fixture.ledger, first_serviced);
        EXPECT_EQ(reverted.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(reverted.reverted_rows, 1U);
        const ServiceExitReapRowSnapshot reverted_row = InspectRow(fixture, staged.ticket.row);
        EXPECT_EQ(reverted_row.stage, ServiceExitReapRowStage::ReadyForDelivery);
        EXPECT_EQ(reverted_row.delivery_token, staged.token);
        EXPECT_FALSE(ProcessKeyIsValid(reverted_row.delivery_owner));

        // Replayed ACK from the dead lease: the row is no longer Delivered.
        EXPECT_EQ(ServiceExitReapLedgerAcknowledgeDelivery(&fixture.ledger, staged.event, staged.token, first_serviced),
                  ServiceExitReapStatus::WrongStage);

        const ServiceExitReapDeliveryResult second_delivery =
            ServiceExitReapLedgerDequeueForDelivery(&fixture.ledger, second_serviced);
        EXPECT_EQ(second_delivery.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(second_delivery.record.delivery_token, staged.token);
        EXPECT_EQ(second_delivery.record.delivery_count, 2U);

        // The dead owner remains foreign to the re-leased row.
        EXPECT_EQ(ServiceExitReapLedgerAcknowledgeDelivery(&fixture.ledger, staged.event, staged.token, first_serviced),
                  ServiceExitReapStatus::ForeignAcknowledger);
        EXPECT_EQ(
            ServiceExitReapLedgerAcknowledgeDelivery(&fixture.ledger, staged.event, staged.token, second_serviced),
            ServiceExitReapStatus::Ok);
        const ServiceExitReapOwnerExitResult idempotent =
            ServiceExitReapLedgerNotifyDeliveryOwnerExit(&fixture.ledger, first_serviced);
        EXPECT_EQ(idempotent.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(idempotent.reverted_rows, 0U);
    }

    // The event carries the exact directory generation captured at publication.
    // If that slot is recycled before the reap pump reaches directory teardown,
    // the stale event settles absent without touching the replacement row.
    {
        Fixture fixture;
        const PublishedService first = PublishService(fixture, kServicedSpec);
        CrashService(fixture, first, 21);
        const ServiceExitReapAcquireResult acquired =
            ServiceExitReapLedgerAcquireFromObserver(&fixture.ledger, &fixture.observer);
        EXPECT_EQ(acquired.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(fixture.ledger.rows[acquired.ticket.row].directory_service, first.directory_key);

        EXPECT_EQ(ServiceDirectoryOwnerCrashed(&fixture.directory, first.directory_key, first.directory_owner).status,
                  ServiceDirectoryStatus::Ok);
        EXPECT_EQ(ServiceDirectoryInspectExact(&fixture.directory, first.directory_key).status,
                  ServiceDirectoryStatus::StaleKey);

        const PublishedService replacement = PublishService(fixture, kExecdSpec);
        EXPECT_EQ(replacement.directory_key.slot, first.directory_key.slot);
        EXPECT_NE(replacement.directory_key.generation, first.directory_key.generation);

        const ServiceExitReapPumpResult pumped = ServiceExitReapLedgerPump(
            &fixture.ledger, &fixture.broker, &fixture.directory, &fixture.observer, fixture.Now(), 8);
        EXPECT_EQ(pumped.ready_transitions, 1U);
        EXPECT_EQ(InspectRow(fixture, acquired.ticket.row).directory_disposition,
                  ServiceExitReapDirectoryDisposition::SettledAbsent);
        EXPECT_EQ(fixture.ledger.rows[acquired.ticket.row].directory_status, ServiceDirectoryStatus::StaleKey);
        const ServiceDirectoryInspectResult replacement_row =
            ServiceDirectoryInspectExact(&fixture.directory, replacement.directory_key);
        EXPECT_EQ(replacement_row.status, ServiceDirectoryStatus::Ok);
        EXPECT_EQ(replacement_row.snapshot.state, ServiceDirectoryEntryState::Active);

        const ProcessKey owner = Key(9400);
        const ServiceExitReapDeliveryResult delivered = ServiceExitReapLedgerDequeueForDelivery(&fixture.ledger, owner);
        EXPECT_EQ(delivered.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(delivered.record.directory_disposition, ServiceExitReapDirectoryDisposition::SettledAbsent);
        EXPECT_EQ(ServiceExitReapLedgerAcknowledgeDelivery(&fixture.ledger, EventKey(delivered.record),
                                                           delivered.record.delivery_token, owner),
                  ServiceExitReapStatus::Ok);
    }

    // Global rotating fairness: the lowest row perpetually Busy in
    // DirectoryDraining must not starve a later row, which commits and
    // becomes deliverable while the Busy row keeps its exact retry state.
    {
        Fixture fixture;
        const PublishedService serviced = PublishService(fixture, kServicedSpec);
        CrashService(fixture, serviced, 1);
        const ServiceExitReapAcquireResult serviced_acquired =
            ServiceExitReapLedgerAcquireFromObserver(&fixture.ledger, &fixture.observer);
        EXPECT_EQ(serviced_acquired.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(ServiceExitReapLedgerPump(&fixture.ledger, &fixture.broker, &fixture.directory, &fixture.observer,
                                            fixture.Now(), 1)
                      .lifecycle_committed,
                  1U);
        const ServiceDirectoryName serviced_name = DirectoryName("serviced");
        const ServiceDirectoryLookupResult pin = ServiceDirectoryLookup(&fixture.directory, &serviced_name);
        EXPECT_EQ(pin.status, ServiceDirectoryStatus::Ok);

        const PublishedService execd = PublishService(fixture, kExecdSpec);
        CrashService(fixture, execd, 2);
        const ServiceExitReapAcquireResult execd_acquired =
            ServiceExitReapLedgerAcquireFromObserver(&fixture.ledger, &fixture.observer);
        EXPECT_EQ(execd_acquired.status, ServiceExitReapStatus::Ok);

        const ServiceExitReapPumpResult pumped = ServiceExitReapLedgerPump(
            &fixture.ledger, &fixture.broker, &fixture.directory, &fixture.observer, fixture.Now(), 8);
        EXPECT_TRUE(pumped.directory_busy >= 1U);
        EXPECT_EQ(InspectRow(fixture, serviced_acquired.ticket.row).stage, ServiceExitReapRowStage::DirectoryDraining);
        EXPECT_EQ(InspectRow(fixture, execd_acquired.ticket.row).stage, ServiceExitReapRowStage::ReadyForDelivery);

        // The later row delivers while the earlier row is still draining.
        const ProcessKey owner = Key(9500);
        const ServiceExitReapDeliveryResult execd_delivered =
            ServiceExitReapLedgerDequeueForDelivery(&fixture.ledger, owner);
        EXPECT_EQ(execd_delivered.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(execd_delivered.record.service_identity, kExecdIdentity);
        EXPECT_EQ(ServiceExitReapLedgerAcknowledgeDelivery(&fixture.ledger, EventKey(execd_delivered.record),
                                                           execd_delivered.record.delivery_token, owner),
                  ServiceExitReapStatus::Ok);

        // Pin release completes the close inside the directory (see the Busy
        // block above); the retry records the exact settled-absent result
        // and the starved row still reaches delivery.
        ServiceDirectoryOperationPin release = pin.pin;
        EXPECT_EQ(ServiceDirectoryReleaseOperation(&fixture.directory, &release), ServiceDirectoryStatus::Ok);
        const ServiceExitReapPumpResult drained = ServiceExitReapLedgerPump(
            &fixture.ledger, &fixture.broker, &fixture.directory, &fixture.observer, fixture.Now(), 8);
        EXPECT_EQ(drained.directory_committed, 1U);
        EXPECT_EQ(drained.ready_transitions, 1U);
        const ServiceExitReapDeliveryResult serviced_delivered =
            ServiceExitReapLedgerDequeueForDelivery(&fixture.ledger, owner);
        EXPECT_EQ(serviced_delivered.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(serviced_delivered.record.service_identity, kServicedIdentity);
        EXPECT_EQ(ServiceExitReapLedgerAcknowledgeDelivery(&fixture.ledger, EventKey(serviced_delivered.record),
                                                           serviced_delivered.record.delivery_token, owner),
                  ServiceExitReapStatus::Ok);
    }

    // Directory settlement is sufficient for exact restage even before token
    // mint/observer ACK.  A refused observer ACK retains the row and its
    // pre-reserved token; it must never fabricate ReadyForDelivery.
    {
        Fixture fixture;
        const PublishedService published = PublishService(fixture, kServicedSpec);
        CrashService(fixture, published, 6);
        const ServiceExitReapAcquireResult acquired =
            ServiceExitReapLedgerAcquireFromObserver(&fixture.ledger, &fixture.observer);
        EXPECT_EQ(acquired.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(ServiceExitReapLedgerPump(&fixture.ledger, &fixture.broker, &fixture.directory, &fixture.observer,
                                            fixture.Now(), 2)
                      .directory_committed,
                  1U);
        EXPECT_EQ(InspectRow(fixture, acquired.ticket.row).stage, ServiceExitReapRowStage::DirectoryCommitted);
        const ServiceExitReapRestageResult settled =
            ServiceExitReapLedgerQueryRestageExact(&fixture.ledger, EventKey(published, acquired.ticket));
        EXPECT_EQ(settled.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(settled.eligible, 1U);

        fixture.observer.initialized = 0;
        const ServiceExitReapPumpResult refused = ServiceExitReapLedgerPump(
            &fixture.ledger, &fixture.broker, &fixture.directory, &fixture.observer, fixture.Now(), 1);
        EXPECT_EQ(refused.status, ServiceExitReapStatus::ObserverRefused);
        const ServiceExitReapRowSnapshot parked = InspectRow(fixture, acquired.ticket.row);
        EXPECT_EQ(parked.stage, ServiceExitReapRowStage::DirectoryCommitted);
        EXPECT_EQ(parked.observer_ack_disposition, ServiceExitReapObserverAckDisposition::Refused);
        EXPECT_NE(parked.delivery_token, kServiceExitReapInvalidDeliveryToken);
        EXPECT_EQ(fixture.observer.active_count, 1U);

        fixture.observer.initialized = 1;
        const ServiceExitReapPumpResult retried = ServiceExitReapLedgerPump(
            &fixture.ledger, &fixture.broker, &fixture.directory, &fixture.observer, fixture.Now(), 1);
        EXPECT_EQ(retried.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(retried.ready_transitions, 1U);
        EXPECT_EQ(InspectRow(fixture, acquired.ticket.row).delivery_token, parked.delivery_token);
        EXPECT_EQ(InspectObserver(fixture).active_count, 0U);

        const ProcessKey owner = Key(9550);
        const ServiceExitReapDeliveryResult delivered = ServiceExitReapLedgerDequeueForDelivery(&fixture.ledger, owner);
        EXPECT_EQ(delivered.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(ServiceExitReapLedgerAcknowledgeDelivery(&fixture.ledger, EventKey(delivered.record),
                                                           delivered.record.delivery_token, owner),
                  ServiceExitReapStatus::Ok);
    }

    // A permanently stale observer receipt is forensic state, not rotating
    // pump work.  It never fabricates delivery, but exact teardown settlement
    // remains sufficient for restage.
    {
        Fixture fixture;
        const PublishedService published = PublishService(fixture, kServicedSpec);
        CrashService(fixture, published, 61);
        const ServiceExitReapAcquireResult acquired =
            ServiceExitReapLedgerAcquireFromObserver(&fixture.ledger, &fixture.observer);
        EXPECT_EQ(acquired.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(ServiceExitReapLedgerPump(&fixture.ledger, &fixture.broker, &fixture.directory, &fixture.observer,
                                            fixture.Now(), 2)
                      .directory_committed,
                  1U);

        ServiceExitEventReceipt consumed = fixture.ledger.rows[acquired.ticket.row].event.receipt;
        EXPECT_EQ(ServiceExitObserverAcknowledge(&fixture.observer, &consumed), ServiceExitObserverStatus::Ok);
        const ServiceExitReapPumpResult refused = ServiceExitReapLedgerPump(
            &fixture.ledger, &fixture.broker, &fixture.directory, &fixture.observer, fixture.Now(), 1);
        EXPECT_EQ(refused.status, ServiceExitReapStatus::ObserverRefused);
        EXPECT_EQ(refused.rows_pending, 0U);
        const ServiceExitReapRowSnapshot parked = InspectRow(fixture, acquired.ticket.row);
        EXPECT_EQ(parked.stage, ServiceExitReapRowStage::DirectoryCommitted);
        EXPECT_EQ(parked.observer_ack_disposition, ServiceExitReapObserverAckDisposition::Refused);
        EXPECT_EQ(fixture.ledger.rows[acquired.ticket.row].observer_ack_status,
                  ServiceExitObserverStatus::InvalidEventReceipt);
        EXPECT_NE(parked.delivery_token, kServiceExitReapInvalidDeliveryToken);

        const ServiceExitReapPumpResult no_spin = ServiceExitReapLedgerPump(
            &fixture.ledger, &fixture.broker, &fixture.directory, &fixture.observer, fixture.Now(), 8);
        EXPECT_EQ(no_spin.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(no_spin.steps_attempted, 0U);
        EXPECT_EQ(no_spin.rows_pending, 0U);
        const ServiceExitReapRestageResult restage =
            ServiceExitReapLedgerQueryRestageExact(&fixture.ledger, EventKey(published, acquired.ticket));
        EXPECT_EQ(restage.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(restage.eligible, 1U);
        EXPECT_EQ(ServiceExitReapLedgerDequeueForDelivery(&fixture.ledger, Key(9560)).status,
                  ServiceExitReapStatus::NoEvent);
    }

    // Capacity: a full ledger refuses admission BEFORE the observer dequeue,
    // so the event stays durably queued in the observer; freeing one row by
    // exact ACK reopens admission and the retained event is acquired intact.
    {
        Fixture fixture;
        std::vector<u64> tokens;
        std::vector<ServiceExitReapEventKey> events;
        for (u32 index = 0; index < kServiceExitReapLedgerCapacity; ++index)
        {
            const ReadyEvent staged = StageReadyEvent(fixture, kServicedSpec, index);
            tokens.push_back(staged.token);
            events.push_back(staged.event);
        }
        ServiceExitReapLedgerSnapshot snapshot{};
        EXPECT_EQ(ServiceExitReapLedgerInspect(&fixture.ledger, &snapshot), ServiceExitReapStatus::Ok);
        EXPECT_EQ(snapshot.live_rows, kServiceExitReapLedgerCapacity);

        const PublishedService overflow = PublishService(fixture, kServicedSpec);
        CrashService(fixture, overflow, 99);
        const ServiceExitReapAcquireResult refused =
            ServiceExitReapLedgerAcquireFromObserver(&fixture.ledger, &fixture.observer);
        EXPECT_EQ(refused.status, ServiceExitReapStatus::CapacityExhausted);
        EXPECT_EQ(InspectObserver(fixture).pending_count, 1U);

        const ProcessKey owner = Key(9600);
        const ServiceExitReapDeliveryResult delivered = ServiceExitReapLedgerDequeueForDelivery(&fixture.ledger, owner);
        EXPECT_EQ(delivered.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(delivered.record.delivery_token, tokens[0]);
        EXPECT_EQ(ServiceExitReapLedgerAcknowledgeDelivery(&fixture.ledger, events[0], tokens[0], owner),
                  ServiceExitReapStatus::Ok);

        const ServiceExitReapAcquireResult admitted =
            ServiceExitReapLedgerAcquireFromObserver(&fixture.ledger, &fixture.observer);
        EXPECT_EQ(admitted.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(InspectObserver(fixture).pending_count, 0U);
        const ServiceExitReapPumpResult pumped = ServiceExitReapLedgerPump(
            &fixture.ledger, &fixture.broker, &fixture.directory, &fixture.observer, fixture.Now(), 8);
        EXPECT_EQ(pumped.ready_transitions, 1U);

        for (u32 index = 1; index < kServiceExitReapLedgerCapacity; ++index)
        {
            const ServiceExitReapDeliveryResult next = ServiceExitReapLedgerDequeueForDelivery(&fixture.ledger, owner);
            EXPECT_EQ(next.status, ServiceExitReapStatus::Ok);
            EXPECT_EQ(next.record.delivery_token, tokens[index]);
            EXPECT_EQ(ServiceExitReapLedgerAcknowledgeDelivery(&fixture.ledger, events[index], tokens[index], owner),
                      ServiceExitReapStatus::Ok);
        }
        const ServiceExitReapDeliveryResult last = ServiceExitReapLedgerDequeueForDelivery(&fixture.ledger, owner);
        EXPECT_EQ(last.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(ServiceExitReapLedgerAcknowledgeDelivery(&fixture.ledger, EventKey(last.record),
                                                           last.record.delivery_token, owner),
                  ServiceExitReapStatus::Ok);
        EXPECT_EQ(ServiceExitReapLedgerInspect(&fixture.ledger, &snapshot), ServiceExitReapStatus::Ok);
        EXPECT_EQ(snapshot.live_rows, 0U);
    }

    // The public delivery-token space never wraps: at the ceiling the pump
    // fails closed BEFORE consuming the observer receipt, the row parks at
    // DirectoryCommitted, and restoring the space resumes exactly once.
    {
        Fixture fixture;
        const PublishedService published = PublishService(fixture, kServicedSpec);
        CrashService(fixture, published, 13);
        const ServiceExitReapAcquireResult acquired =
            ServiceExitReapLedgerAcquireFromObserver(&fixture.ledger, &fixture.observer);
        EXPECT_EQ(acquired.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(ServiceExitReapLedgerPump(&fixture.ledger, &fixture.broker, &fixture.directory, &fixture.observer,
                                            fixture.Now(), 2)
                      .directory_committed,
                  1U);
        EXPECT_EQ(InspectRow(fixture, acquired.ticket.row).stage, ServiceExitReapRowStage::DirectoryCommitted);

        const u64 previous_next_token = ServiceExitReapLedgerHostSetNextDeliveryTokenForTest(~static_cast<u64>(0));
        const ServiceExitReapPumpResult exhausted = ServiceExitReapLedgerPump(
            &fixture.ledger, &fixture.broker, &fixture.directory, &fixture.observer, fixture.Now(), 2);
        EXPECT_EQ(exhausted.status, ServiceExitReapStatus::TokenSpaceExhausted);
        EXPECT_EQ(exhausted.ready_transitions, 0U);
        EXPECT_EQ(InspectRow(fixture, acquired.ticket.row).stage, ServiceExitReapRowStage::DirectoryCommitted);
        // The refusal happened before the observer acknowledgement, so the
        // receipt/slot is still held and nothing was consumed or dropped.
        EXPECT_EQ(InspectObserver(fixture).active_count, 1U);

        ServiceExitReapLedgerHostSetNextDeliveryTokenForTest(previous_next_token);
        const ServiceExitReapPumpResult resumed = ServiceExitReapLedgerPump(
            &fixture.ledger, &fixture.broker, &fixture.directory, &fixture.observer, fixture.Now(), 2);
        EXPECT_EQ(resumed.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(resumed.ready_transitions, 1U);
        EXPECT_EQ(InspectObserver(fixture).active_count, 0U);

        const ProcessKey owner = Key(9700);
        const ServiceExitReapDeliveryResult delivered = ServiceExitReapLedgerDequeueForDelivery(&fixture.ledger, owner);
        EXPECT_EQ(delivered.status, ServiceExitReapStatus::Ok);
        EXPECT_NE(delivered.record.delivery_token, kServiceExitReapInvalidDeliveryToken);
        EXPECT_EQ(ServiceExitReapLedgerAcknowledgeDelivery(&fixture.ledger, EventKey(delivered.record),
                                                           delivered.record.delivery_token, owner),
                  ServiceExitReapStatus::Ok);
    }

    // Two rows racing at the final token can release at most one observer
    // slot.  Token reservation is durably committed before either ACK.
    {
        Fixture fixture;
        const PublishedService serviced = PublishService(fixture, kServicedSpec);
        const PublishedService execd = PublishService(fixture, kExecdSpec);
        CrashService(fixture, serviced, 31);
        CrashService(fixture, execd, 32);
        const ServiceExitReapAcquireResult serviced_acquired =
            ServiceExitReapLedgerAcquireFromObserver(&fixture.ledger, &fixture.observer);
        const ServiceExitReapAcquireResult execd_acquired =
            ServiceExitReapLedgerAcquireFromObserver(&fixture.ledger, &fixture.observer);
        EXPECT_EQ(serviced_acquired.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(execd_acquired.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(ServiceExitReapLedgerPump(&fixture.ledger, &fixture.broker, &fixture.directory, &fixture.observer,
                                            fixture.Now(), 4)
                      .directory_committed,
                  2U);

        const u64 previous_next_token = ServiceExitReapLedgerHostSetNextDeliveryTokenForTest(~static_cast<u64>(0) - 1);
        std::array<ServiceExitReapPumpResult, 2> results{};
        const u64 first_now = fixture.Now();
        const u64 second_now = fixture.Now();
        std::thread first(
            [&]
            {
                results[0] = ServiceExitReapLedgerPump(&fixture.ledger, &fixture.broker, &fixture.directory,
                                                       &fixture.observer, first_now, 1);
            });
        std::thread second(
            [&]
            {
                results[1] = ServiceExitReapLedgerPump(&fixture.ledger, &fixture.broker, &fixture.directory,
                                                       &fixture.observer, second_now, 1);
            });
        first.join();
        second.join();
        const u32 exhausted = static_cast<u32>(results[0].status == ServiceExitReapStatus::TokenSpaceExhausted) +
                              static_cast<u32>(results[1].status == ServiceExitReapStatus::TokenSpaceExhausted);
        EXPECT_EQ(exhausted, 1U);
        const ServiceExitReapRowSnapshot serviced_row = InspectRow(fixture, serviced_acquired.ticket.row);
        const ServiceExitReapRowSnapshot execd_row = InspectRow(fixture, execd_acquired.ticket.row);
        const u32 ready = static_cast<u32>(serviced_row.stage == ServiceExitReapRowStage::ReadyForDelivery) +
                          static_cast<u32>(execd_row.stage == ServiceExitReapRowStage::ReadyForDelivery);
        EXPECT_EQ(ready, 1U);
        EXPECT_EQ(InspectObserver(fixture).active_count, 1U);

        ServiceExitReapLedgerHostSetNextDeliveryTokenForTest(previous_next_token);
        EXPECT_EQ(ServiceExitReapLedgerPump(&fixture.ledger, &fixture.broker, &fixture.directory, &fixture.observer,
                                            fixture.Now(), 2)
                      .ready_transitions,
                  1U);
        EXPECT_EQ(InspectObserver(fixture).active_count, 0U);
        const ProcessKey owner = Key(9750);
        for (u32 index = 0; index < 2; ++index)
        {
            const ServiceExitReapDeliveryResult delivered =
                ServiceExitReapLedgerDequeueForDelivery(&fixture.ledger, owner);
            EXPECT_EQ(delivered.status, ServiceExitReapStatus::Ok);
            EXPECT_EQ(ServiceExitReapLedgerAcknowledgeDelivery(&fixture.ledger, EventKey(delivered.record),
                                                               delivered.record.delivery_token, owner),
                      ServiceExitReapStatus::Ok);
        }
    }

    // Deterministic acquisition window: the observer has dequeued the event,
    // but its identity is not yet visible in the reserved ledger row.  Close
    // refuses the in-flight acquisition and exact-restage refuses to attest
    // any event until publication completes.
    {
        Fixture fixture;
        const PublishedService published = PublishService(fixture, kServicedSpec);
        CrashService(fixture, published, 71);
        HostPause pause(ServiceExitReapLedgerHostHookPoint::ObserverDequeueReturnedBeforeLedgerApply);
        ServiceExitReapLedgerHostSetHook(&PauseAtHostHook, &pause);
        ServiceExitReapAcquireResult acquired{};
        std::thread acquirer(
            [&] { acquired = ServiceExitReapLedgerAcquireFromObserver(&fixture.ledger, &fixture.observer); });
        (void)WaitForHostPause(pause);
        EXPECT_TRUE(pause.event.row < kServiceExitReapLedgerCapacity);
        EXPECT_NE(pause.event.admission, kServiceExitReapInvalidAdmission);
        EXPECT_EQ(pause.event.stage, ServiceExitReapRowStage::Free);
        EXPECT_EQ(ServiceExitReapLedgerClose(&fixture.ledger), ServiceExitReapStatus::RowsLive);
        const ServiceExitReapEventKey hidden_event{
            published.start.broker_epoch,
            published.start.transition.service_identity,
            published.start.transition.generation,
            published.process,
            pause.event.admission,
        };
        EXPECT_EQ(ServiceExitReapLedgerQueryRestageExact(&fixture.ledger, hidden_event).status,
                  ServiceExitReapStatus::Busy);
        EXPECT_EQ(InspectObserver(fixture).pending_count, 0U);
        ReleaseHostPause(pause);
        acquirer.join();
        ServiceExitReapLedgerHostSetHook(nullptr, nullptr);
        EXPECT_EQ(acquired.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(acquired.ticket.row, pause.event.row);
        EXPECT_EQ(acquired.ticket.admission, pause.event.admission);
        EXPECT_EQ(ServiceExitReapLedgerRollbackAcquired(&fixture.ledger, &fixture.observer, acquired.ticket).status,
                  ServiceExitReapStatus::Ok);
    }

    // Deterministic pump-vs-pump and pump-vs-rollback handoff.  The selected
    // row is pinned before the external lifecycle call, so no competing driver
    // or rollback can consume it.
    {
        Fixture fixture;
        const PublishedService published = PublishService(fixture, kServicedSpec);
        CrashService(fixture, published, 72);
        const ServiceExitReapAcquireResult acquired =
            ServiceExitReapLedgerAcquireFromObserver(&fixture.ledger, &fixture.observer);
        EXPECT_EQ(acquired.status, ServiceExitReapStatus::Ok);

        HostPause pause(ServiceExitReapLedgerHostHookPoint::PumpSelectedBeforeExternalCall);
        ServiceExitReapLedgerHostSetHook(&PauseAtHostHook, &pause);
        ServiceExitReapPumpResult first{};
        std::thread pumper(
            [&]
            {
                first = ServiceExitReapLedgerPump(&fixture.ledger, &fixture.broker, &fixture.directory,
                                                  &fixture.observer, fixture.Now(), 1);
            });
        (void)WaitForHostPause(pause);
        EXPECT_EQ(pause.event.row, acquired.ticket.row);
        EXPECT_EQ(pause.event.admission, acquired.ticket.admission);
        EXPECT_EQ(pause.event.stage, ServiceExitReapRowStage::Acquired);
        const ServiceExitReapPumpResult competing = ServiceExitReapLedgerPump(
            &fixture.ledger, &fixture.broker, &fixture.directory, &fixture.observer, fixture.Now(), 1);
        EXPECT_EQ(competing.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(competing.steps_attempted, 0U);
        EXPECT_EQ(ServiceExitReapLedgerRollbackAcquired(&fixture.ledger, &fixture.observer, acquired.ticket).status,
                  ServiceExitReapStatus::Busy);
        ReleaseHostPause(pause);
        pumper.join();
        ServiceExitReapLedgerHostSetHook(nullptr, nullptr);
        EXPECT_EQ(first.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(first.lifecycle_committed, 1U);
        EXPECT_EQ(ServiceExitReapLedgerPump(&fixture.ledger, &fixture.broker, &fixture.directory, &fixture.observer,
                                            fixture.Now(), 8)
                      .ready_transitions,
                  1U);
    }

    // The rollback side has the same one-driver guarantee: once it pins an
    // Acquired row, neither a pump nor a duplicate rollback may race the
    // observer requeue.
    {
        Fixture fixture;
        const PublishedService published = PublishService(fixture, kServicedSpec);
        CrashService(fixture, published, 73);
        const ServiceExitReapAcquireResult acquired =
            ServiceExitReapLedgerAcquireFromObserver(&fixture.ledger, &fixture.observer);
        EXPECT_EQ(acquired.status, ServiceExitReapStatus::Ok);

        HostPause pause(ServiceExitReapLedgerHostHookPoint::RollbackReservedBeforeObserverRequeue);
        ServiceExitReapLedgerHostSetHook(&PauseAtHostHook, &pause);
        ServiceExitReapRollbackResult first{};
        std::thread rollback(
            [&]
            { first = ServiceExitReapLedgerRollbackAcquired(&fixture.ledger, &fixture.observer, acquired.ticket); });
        (void)WaitForHostPause(pause);
        EXPECT_EQ(pause.event.row, acquired.ticket.row);
        EXPECT_EQ(pause.event.admission, acquired.ticket.admission);
        EXPECT_EQ(ServiceExitReapLedgerPump(&fixture.ledger, &fixture.broker, &fixture.directory, &fixture.observer,
                                            fixture.Now(), 1)
                      .steps_attempted,
                  0U);
        EXPECT_EQ(ServiceExitReapLedgerRollbackAcquired(&fixture.ledger, &fixture.observer, acquired.ticket).status,
                  ServiceExitReapStatus::Busy);
        ReleaseHostPause(pause);
        rollback.join();
        ServiceExitReapLedgerHostSetHook(nullptr, nullptr);
        EXPECT_EQ(first.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(InspectObserver(fixture).pending_count, 1U);
    }

    // Observer ACK is irreversible before the ledger applies its result.  In
    // that window the reserved public token and exact settlement remain
    // canonical, another pumper cannot select the row, and restage can rely on
    // lifecycle+directory facts without pretending delivery is ready.
    {
        Fixture fixture;
        const PublishedService published = PublishService(fixture, kServicedSpec);
        CrashService(fixture, published, 74);
        const ServiceExitReapAcquireResult acquired =
            ServiceExitReapLedgerAcquireFromObserver(&fixture.ledger, &fixture.observer);
        EXPECT_EQ(acquired.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(ServiceExitReapLedgerPump(&fixture.ledger, &fixture.broker, &fixture.directory, &fixture.observer,
                                            fixture.Now(), 2)
                      .directory_committed,
                  1U);

        HostPause pause(ServiceExitReapLedgerHostHookPoint::ObserverAckReturnedBeforeLedgerApply);
        ServiceExitReapLedgerHostSetHook(&PauseAtHostHook, &pause);
        ServiceExitReapPumpResult ack_pass{};
        std::thread acker(
            [&]
            {
                ack_pass = ServiceExitReapLedgerPump(&fixture.ledger, &fixture.broker, &fixture.directory,
                                                     &fixture.observer, fixture.Now(), 1);
            });
        (void)WaitForHostPause(pause);
        EXPECT_EQ(pause.event.row, acquired.ticket.row);
        EXPECT_EQ(pause.event.admission, acquired.ticket.admission);
        EXPECT_EQ(pause.event.stage, ServiceExitReapRowStage::DirectoryCommitted);
        const ServiceExitReapRowSnapshot before_apply = InspectRow(fixture, acquired.ticket.row);
        EXPECT_EQ(before_apply.stage, ServiceExitReapRowStage::DirectoryCommitted);
        EXPECT_EQ(before_apply.observer_ack_disposition, ServiceExitReapObserverAckDisposition::None);
        EXPECT_NE(before_apply.delivery_token, kServiceExitReapInvalidDeliveryToken);
        EXPECT_EQ(InspectObserver(fixture).active_count, 0U);
        EXPECT_EQ(ServiceExitReapLedgerPump(&fixture.ledger, &fixture.broker, &fixture.directory, &fixture.observer,
                                            fixture.Now(), 1)
                      .steps_attempted,
                  0U);
        const ServiceExitReapRestageResult settled =
            ServiceExitReapLedgerQueryRestageExact(&fixture.ledger, EventKey(published, acquired.ticket));
        EXPECT_EQ(settled.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(settled.eligible, 1U);
        ReleaseHostPause(pause);
        acker.join();
        ServiceExitReapLedgerHostSetHook(nullptr, nullptr);
        EXPECT_EQ(ack_pass.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(ack_pass.ready_transitions, 1U);
        EXPECT_EQ(InspectRow(fixture, acquired.ticket.row).stage, ServiceExitReapRowStage::ReadyForDelivery);
    }

    // Close fails closed while any durable row is live (never discarding an
    // undelivered event), reinitialization is canonical, and the global token
    // space keeps old acknowledgement authority dead across incarnations.
    {
        Fixture fixture;
        const PublishedService published = PublishService(fixture, kServicedSpec);
        CrashService(fixture, published, 17);
        const ServiceExitReapAcquireResult acquired =
            ServiceExitReapLedgerAcquireFromObserver(&fixture.ledger, &fixture.observer);
        EXPECT_EQ(acquired.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(ServiceExitReapLedgerClose(&fixture.ledger), ServiceExitReapStatus::RowsLive);
        EXPECT_EQ(ServiceExitReapLedgerInitialize(&fixture.ledger), ServiceExitReapStatus::AlreadyInitialized);

        const ServiceExitReapPumpResult pumped = ServiceExitReapLedgerPump(
            &fixture.ledger, &fixture.broker, &fixture.directory, &fixture.observer, fixture.Now(), 8);
        EXPECT_EQ(pumped.ready_transitions, 1U);
        EXPECT_EQ(ServiceExitReapLedgerClose(&fixture.ledger), ServiceExitReapStatus::RowsLive);
        const ProcessKey owner = Key(9800);
        const ServiceExitReapDeliveryResult delivered = ServiceExitReapLedgerDequeueForDelivery(&fixture.ledger, owner);
        EXPECT_EQ(delivered.status, ServiceExitReapStatus::Ok);
        const u64 old_token = delivered.record.delivery_token;
        const ServiceExitReapEventKey old_event = EventKey(delivered.record);
        EXPECT_EQ(ServiceExitReapLedgerAcknowledgeDelivery(&fixture.ledger, old_event, old_token, owner),
                  ServiceExitReapStatus::Ok);

        EXPECT_EQ(ServiceExitReapLedgerClose(&fixture.ledger), ServiceExitReapStatus::Ok);
        EXPECT_EQ(ServiceExitReapLedgerPump(&fixture.ledger, &fixture.broker, &fixture.directory, &fixture.observer,
                                            fixture.Now(), 1)
                      .status,
                  ServiceExitReapStatus::Closed);
        EXPECT_EQ(ServiceExitReapLedgerInitialize(&fixture.ledger), ServiceExitReapStatus::Ok);

        // The reinitialized incarnation mints strictly newer tokens, so the
        // consumed ticket/event/token can never alias a fresh row's authority.
        const ReadyEvent fresh = StageReadyEvent(fixture, kServicedSpec, 18);
        EXPECT_TRUE(fresh.token > old_token);
        EXPECT_TRUE(fresh.ticket.admission > acquired.ticket.admission);
        EXPECT_EQ(ServiceExitReapLedgerQueryRestageExact(&fixture.ledger, old_event).status,
                  ServiceExitReapStatus::NotFound);
        EXPECT_EQ(ServiceExitReapLedgerRollbackAcquired(&fixture.ledger, &fixture.observer, acquired.ticket).status,
                  ServiceExitReapStatus::StaleTicket);
        EXPECT_EQ(ServiceExitReapLedgerAcknowledgeDelivery(&fixture.ledger, old_event, old_token, owner),
                  ServiceExitReapStatus::StaleToken);
        const ServiceExitReapDeliveryResult redelivered =
            ServiceExitReapLedgerDequeueForDelivery(&fixture.ledger, owner);
        EXPECT_EQ(redelivered.status, ServiceExitReapStatus::Ok);
        EXPECT_EQ(ServiceExitReapLedgerAcknowledgeDelivery(&fixture.ledger, old_event, fresh.token, owner),
                  ServiceExitReapStatus::StaleEvent);
        EXPECT_EQ(ServiceExitReapLedgerAcknowledgeDelivery(&fixture.ledger, fresh.event, fresh.token, owner),
                  ServiceExitReapStatus::Ok);
    }

    // Concurrency: two pump drivers, a delivery/ACK consumer, and an
    // inspector race over the same ledger; every event settles exactly once
    // and each public token is delivered/acknowledged by exactly one path.
    {
        Fixture fixture;
        const PublishedService serviced = PublishService(fixture, kServicedSpec);
        CrashService(fixture, serviced, 1);
        const ServiceExitReapAcquireResult serviced_acquired =
            ServiceExitReapLedgerAcquireFromObserver(&fixture.ledger, &fixture.observer);
        EXPECT_EQ(serviced_acquired.status, ServiceExitReapStatus::Ok);
        const PublishedService execd = PublishService(fixture, kExecdSpec);
        CrashService(fixture, execd, 2);
        const ServiceExitReapAcquireResult execd_acquired =
            ServiceExitReapLedgerAcquireFromObserver(&fixture.ledger, &fixture.observer);
        EXPECT_EQ(execd_acquired.status, ServiceExitReapStatus::Ok);

        std::atomic<u64> now{100000};
        std::atomic<bool> stop{false};
        std::atomic<u32> acked{0};
        std::mutex token_lock;
        std::vector<u64> delivered_tokens;
        const ProcessKey owner = Key(9900);

        auto pump_loop = [&]
        {
            for (u32 iteration = 0; iteration < 10000 && !stop.load(); ++iteration)
            {
                const ServiceExitReapPumpResult pumped = ServiceExitReapLedgerPump(
                    &fixture.ledger, &fixture.broker, &fixture.directory, &fixture.observer, now.fetch_add(1), 2);
                if (pumped.status != ServiceExitReapStatus::Ok)
                    break;
            }
        };
        std::thread pumper_a(pump_loop);
        std::thread pumper_b(pump_loop);
        std::thread consumer(
            [&]
            {
                for (u32 iteration = 0; iteration < 1000000 && acked.load() < 2; ++iteration)
                {
                    const ServiceExitReapDeliveryResult delivered =
                        ServiceExitReapLedgerDequeueForDelivery(&fixture.ledger, owner);
                    if (delivered.status != ServiceExitReapStatus::Ok)
                        continue;
                    {
                        std::lock_guard<std::mutex> guard(token_lock);
                        delivered_tokens.push_back(delivered.record.delivery_token);
                    }
                    if (ServiceExitReapLedgerAcknowledgeDelivery(&fixture.ledger, EventKey(delivered.record),
                                                                 delivered.record.delivery_token,
                                                                 owner) == ServiceExitReapStatus::Ok)
                        acked.fetch_add(1);
                }
                stop.store(true);
            });
        std::thread inspector(
            [&]
            {
                while (!stop.load())
                {
                    ServiceExitReapLedgerSnapshot snapshot{};
                    (void)ServiceExitReapLedgerInspect(&fixture.ledger, &snapshot);
                    (void)ServiceExitReapLedgerQueryRestageExact(&fixture.ledger,
                                                                 EventKey(serviced, serviced_acquired.ticket));
                }
            });
        pumper_a.join();
        pumper_b.join();
        consumer.join();
        inspector.join();
        // The threaded pumps advanced the broker rows' monotonic timestamps
        // past the fixture clock; fast-forward it before publishing again.
        fixture.next_now = now.load() + 10;

        EXPECT_EQ(acked.load(), 2U);
        EXPECT_EQ(delivered_tokens.size(), static_cast<size_t>(2));
        EXPECT_TRUE(delivered_tokens[0] != delivered_tokens[1]);
        ServiceExitReapLedgerSnapshot final_snapshot{};
        EXPECT_EQ(ServiceExitReapLedgerInspect(&fixture.ledger, &final_snapshot), ServiceExitReapStatus::Ok);
        EXPECT_EQ(final_snapshot.live_rows, 0U);
        EXPECT_EQ(InspectLifecycle(fixture, kServicedIdentity).observed_exits, 1U);
        EXPECT_EQ(InspectLifecycle(fixture, kExecdIdentity).observed_exits, 1U);

        // Duplicate-ACK race on one token: exactly one winner.
        const ReadyEvent staged = StageReadyEvent(fixture, kServicedSpec, 30);
        const ServiceExitReapDeliveryResult delivered = ServiceExitReapLedgerDequeueForDelivery(&fixture.ledger, owner);
        EXPECT_EQ(delivered.status, ServiceExitReapStatus::Ok);
        std::atomic<u32> ok_count{0};
        std::atomic<u32> stale_count{0};
        auto ack_once = [&]
        {
            const ServiceExitReapStatus status =
                ServiceExitReapLedgerAcknowledgeDelivery(&fixture.ledger, staged.event, staged.token, owner);
            if (status == ServiceExitReapStatus::Ok)
                ok_count.fetch_add(1);
            else if (status == ServiceExitReapStatus::StaleToken)
                stale_count.fetch_add(1);
        };
        std::thread acker_a(ack_once);
        std::thread acker_b(ack_once);
        acker_a.join();
        acker_b.join();
        EXPECT_EQ(ok_count.load(), 1U);
        EXPECT_EQ(stale_count.load(), 1U);
    }

    return duetos_host_test::finish_main("test_service_exit_reap_ledger");
}
