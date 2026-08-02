// Hosted hostile coverage for the lifecycle -> ServiceDirectory join used by
// the dormant first-Task service publication gate.

#include "crypto_host_shims.h"
#include "host_test_helper.h"

#include "core/service_directory.h"
#include "core/service_lifecycle_broker.h"
#include "crypto/sha256.h"

#include <array>
#include <barrier>
#include <cstring>
#include <mutex>
#include <new>
#include <thread>

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

// The join does not open an endpoint.  Supply the standard hosted ChannelCore
// leaf doubles so this binary tests the real endpoint-owner and directory
// state machines without pulling in the scheduler and kernel allocator.
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

ServiceManifestDocumentV1 Document()
{
    ServiceManifestDocumentV1 document{};
    document.manifest_identity = 0xA001;
    document.signer_identity = 0xB001;
    document.profile_identity = 0xC001;
    document.service_count = 1;
    ServiceManifestServiceV1& service = document.services[0];
    service.service_identity = 100;
    service.executable_transfer_ref = 1;
    service.immutable_policy_selector = 1;
    service.executable_content_hash = Hash(0x10);
    service.requested_capability_ceiling = 1ULL << 2;
    service.requested_frame_budget_pages = 32;
    service.requested_tick_budget = 1000;
    service.requested_section_objects = 2;
    service.requested_section_pages = 16;
    service.kind = ServiceManifestKind::Native;
    service.restart_policy = ServiceManifestRestartPolicy::OnFailure;
    service.autostart = 1;
    service.resource_profile = ServiceManifestResourceProfile::AuthenticatedService;
    SetText(service.name, kServiceManifestServiceNameCapacity, &service.name_length, "serviced");
    SetText(service.executable_path, kServiceManifestExecutablePathCapacity, &service.executable_path_length,
            "/system/serviced");
    return document;
}

ServiceManifestDocumentV1 DependencyDocument()
{
    ServiceManifestDocumentV1 document = Document();
    document.service_count = 2;
    document.dependency_count = 1;
    ServiceManifestServiceV1& dependent = document.services[1];
    dependent = document.services[0];
    dependent.service_identity = 200;
    dependent.executable_transfer_ref = 2;
    dependent.executable_content_hash = Hash(0x30);
    dependent.dependency_first = 0;
    dependent.dependency_count = 1;
    SetText(dependent.name, kServiceManifestServiceNameCapacity, &dependent.name_length, "clientd");
    SetText(dependent.executable_path, kServiceManifestExecutablePathCapacity, &dependent.executable_path_length,
            "/system/clientd");
    document.dependencies[0] = ServiceManifestDependencyV1{200, 100};
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

ServiceDirectoryName DirectoryName()
{
    ServiceDirectoryName name{};
    constexpr char kName[] = "serviced";
    name.length = static_cast<u8>(sizeof(kName) - 1U);
    for (u32 index = 0; index < name.length; ++index)
        name.bytes[index] = static_cast<u8>(kName[index]);
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

ServiceEndpointProtocolAuthority Protocol(u64 service_identity)
{
    return ServiceEndpointProtocolAuthority{0xA110U, 0x5010U, service_identity, 0x3FU, 1, 0, 0x51U, 0};
}

void IgnoreCleanup(void*, duetos::ipc::EndpointRequestKey) {}

struct Fixture
{
    ServiceManifestAuthoritySnapshotV1 authority{};
    ServiceManifestPlanV1 plan{};
    ServiceLifecycleBroker broker{};
    ServiceEndpointOwner endpoint_owner{};
    ServiceDirectory directory{};

    explicit Fixture(const ServiceManifestDocumentV1& document = Document())
    {
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
        EXPECT_EQ(ServiceDirectoryValidateRuntimeOwner(&directory, &endpoint_owner), ServiceDirectoryStatus::Ok);
    }
};

struct ReservedPublication
{
    ServiceLifecycleStartTicket start;
    ServiceInstanceKey process;
    ServiceInstanceToken directory_owner;
    ServiceRegistrationReservation directory;
};

ReservedPublication Reserve(Fixture& fixture, u64 expected_generation, u64 now_ns, u64 process_identity, u64 pid)
{
    const ServiceLifecycleStartResult start =
        ServiceLifecycleBrokerReserveStart(&fixture.broker, 100, expected_generation, now_ns);
    EXPECT_EQ(start.status, ServiceLifecycleStatus::Ok);
    const ServiceInstanceKey process{process_identity, pid};
    const ServiceInstanceToken owner{start.ticket.transition, process};
    const ServiceDirectoryName name = DirectoryName();
    const ServiceEndpointCredentialSnapshot credential = Credential();
    const ServiceDirectoryReserveResult directory =
        ServiceDirectoryReserveRegistration(&fixture.directory, &name, 0, owner, &credential);
    EXPECT_EQ(directory.status, ServiceDirectoryStatus::Ok);
    return ReservedPublication{start.ticket, process, owner, directory.reservation};
}

ServiceLifecycleSnapshot InspectLifecycle(Fixture& fixture)
{
    const ServiceLifecycleInspectResult inspected = ServiceLifecycleBrokerInspect(&fixture.broker, 100);
    EXPECT_EQ(inspected.status, ServiceLifecycleStatus::Ok);
    return inspected.snapshot;
}

} // namespace

int main()
{
    // Final directory refusal rolls the exact lifecycle row back to Starting;
    // the private builder then records ordinary spawn failure and aborts the
    // invisible reservation without ever creating an Active row.
    {
        Fixture fixture;
        ReservedPublication publication = Reserve(fixture, 0, 10, 0xAA01, 101);
        const ServiceKey directory_key = publication.directory.service;
        ServiceDirectoryHostFailNextRegistrationPublicationForTest();
        const ServiceLifecycleDirectoryPublicationResult joined = ServiceLifecycleBrokerCommitDirectoryPublication(
            &fixture.broker, publication.start, publication.process, 11, &fixture.directory, &publication.directory);
        EXPECT_EQ(joined.lifecycle_status, ServiceLifecycleStatus::Ok);
        EXPECT_EQ(joined.directory_status, ServiceDirectoryStatus::Busy);
        EXPECT_FALSE(ServiceLifecycleInstanceTokenIsValid(joined.instance));
        EXPECT_TRUE(ServiceRegistrationReservationIsValid(publication.directory));

        const ServiceLifecycleSnapshot rolled_back = InspectLifecycle(fixture);
        EXPECT_EQ(rolled_back.phase, ServiceTransitionPhase::Starting);
        EXPECT_EQ(rolled_back.builder_state, ServiceLifecycleBuilderState::Constructing);
        EXPECT_EQ(rolled_back.successful_publications, 0U);
        const ServiceDirectoryInspectResult reserved = ServiceDirectoryInspectExact(&fixture.directory, directory_key);
        EXPECT_EQ(reserved.status, ServiceDirectoryStatus::Ok);
        EXPECT_EQ(reserved.snapshot.state, ServiceDirectoryEntryState::Reserved);

        EXPECT_EQ(ServiceLifecycleBrokerRecordSpawnFailure(&fixture.broker, publication.start, 12),
                  ServiceLifecycleStatus::Ok);
        EXPECT_EQ(
            ServiceDirectoryAbortRegistration(&fixture.directory, &publication.directory, publication.directory_owner),
            ServiceDirectoryStatus::Ok);
        EXPECT_EQ(ServiceDirectoryInspectExact(&fixture.directory, directory_key).status,
                  ServiceDirectoryStatus::StaleKey);
        EXPECT_EQ(InspectLifecycle(fixture).phase, ServiceTransitionPhase::Failed);
    }

    // The directory reservation is bound to the same immutable ProcessKey as
    // the lifecycle commit. A mismatched scheduler key fails directory owner
    // validation, and the exact in-lock rollback restores Starting.
    {
        Fixture fixture;
        ReservedPublication publication = Reserve(fixture, 0, 20, 0xBB01, 201);
        const ServiceKey directory_key = publication.directory.service;
        const ServiceInstanceKey wrong_process{publication.process.process_identity + 1, publication.process.pid};
        const ServiceLifecycleDirectoryPublicationResult joined = ServiceLifecycleBrokerCommitDirectoryPublication(
            &fixture.broker, publication.start, wrong_process, 21, &fixture.directory, &publication.directory);
        EXPECT_EQ(joined.lifecycle_status, ServiceLifecycleStatus::Ok);
        EXPECT_EQ(joined.directory_status, ServiceDirectoryStatus::OwnerMismatch);
        EXPECT_EQ(InspectLifecycle(fixture).phase, ServiceTransitionPhase::Starting);
        EXPECT_EQ(ServiceDirectoryInspectExact(&fixture.directory, directory_key).snapshot.state,
                  ServiceDirectoryEntryState::Reserved);
        EXPECT_EQ(ServiceLifecycleBrokerRecordSpawnFailure(&fixture.broker, publication.start, 22),
                  ServiceLifecycleStatus::Ok);
        EXPECT_EQ(
            ServiceDirectoryAbortRegistration(&fixture.directory, &publication.directory, publication.directory_owner),
            ServiceDirectoryStatus::Ok);
    }

    // First-Task publication exposes one coherent but not-yet-ready identity.
    // Owner Lookup and Accept remain usable, while Connect alone is denied.
    // MarkReady validates both exact identities before directory-ready then
    // broker-ready commits with no fallible mutation remaining.
    {
        Fixture fixture{DependencyDocument()};
        ReservedPublication publication = Reserve(fixture, 0, 30, 0xCC01, 301);
        const ServiceKey directory_key = publication.directory.service;
        const ServiceLifecycleDirectoryPublicationResult joined = ServiceLifecycleBrokerCommitDirectoryPublication(
            &fixture.broker, publication.start, publication.process, 31, &fixture.directory, &publication.directory);
        EXPECT_EQ(joined.lifecycle_status, ServiceLifecycleStatus::Ok);
        EXPECT_EQ(joined.directory_status, ServiceDirectoryStatus::Ok);
        EXPECT_TRUE(ServiceLifecycleInstanceTokenIsValid(joined.instance));
        EXPECT_FALSE(ServiceRegistrationReservationIsValid(publication.directory));
        ServiceLifecycleSnapshot lifecycle = InspectLifecycle(fixture);
        ServiceDirectoryInspectResult directory = ServiceDirectoryInspectExact(&fixture.directory, directory_key);
        EXPECT_EQ(lifecycle.phase, ServiceTransitionPhase::Running);
        EXPECT_FALSE(lifecycle.ready);
        EXPECT_EQ(directory.status, ServiceDirectoryStatus::Ok);
        EXPECT_EQ(directory.snapshot.state, ServiceDirectoryEntryState::Active);
        EXPECT_FALSE(directory.snapshot.ready);
        EXPECT_EQ(directory.snapshot.owner.start, joined.instance.start.transition);
        EXPECT_EQ(directory.snapshot.owner.process, joined.instance.process);
        EXPECT_EQ(ServiceLifecycleBrokerReserveStartWithDependencies(&fixture.broker, 200, 0, 32).status,
                  ServiceLifecycleStatus::DependencyNotReady);

        const ServiceDirectoryName name = DirectoryName();
        ServiceDirectoryLookupResult lookup = ServiceDirectoryLookup(&fixture.directory, &name);
        EXPECT_EQ(lookup.status, ServiceDirectoryStatus::Ok);
        const ServiceEndpointCredentialSnapshot client_credential = Credential();
        const ServiceEndpointProtocolAuthority protocol = Protocol(100);
        const ServiceDirectoryRequestCleanupSink cleanup{&IgnoreCleanup, nullptr};
        duetos::ipc::HandleTable client_handles{};
        const ServiceDirectoryConnectResult denied = ServiceDirectoryConnect(
            &fixture.directory, lookup.pin, ResourceDomainKey{0, 1}, &client_handles, ProcessKey{0xCC02, 302},
            &client_credential, &protocol, duetos::ipc::kHandleRightRead | duetos::ipc::kHandleRightWrite, &cleanup);
        EXPECT_EQ(denied.status, ServiceDirectoryStatus::NotReady);
        EXPECT_EQ(denied.client_handle, duetos::ipc::kHandleInvalid);

        duetos::ipc::HandleTable server_handles{};
        const ServiceDirectoryAcceptResult owner_accept = ServiceDirectoryAccept(
            &fixture.directory, directory_key, directory.snapshot.owner, &server_handles,
            ProcessKey{joined.instance.process.process_identity, joined.instance.process.pid},
            &directory.snapshot.owner_credential, duetos::ipc::kHandleRightRead | duetos::ipc::kHandleRightWrite);
        EXPECT_EQ(owner_accept.status, ServiceDirectoryStatus::QueueEmpty);
        EXPECT_EQ(ServiceDirectoryReleaseOperation(&fixture.directory, &lookup.pin), ServiceDirectoryStatus::Ok);

        ServiceLifecycleInstanceToken stale_instance = joined.instance;
        ++stale_instance.process.pid;
        const ServiceLifecycleDirectoryReadyResult stale_broker =
            ServiceLifecycleBrokerMarkReady(&fixture.broker, stale_instance, &fixture.directory, directory_key);
        EXPECT_EQ(stale_broker.lifecycle_status, ServiceLifecycleStatus::TransitionRejected);
        EXPECT_FALSE(InspectLifecycle(fixture).ready);
        EXPECT_FALSE(ServiceDirectoryInspectExact(&fixture.directory, directory_key).snapshot.ready);

        const ServiceKey stale_directory{directory_key.slot, directory_key.generation + 1U};
        const ServiceLifecycleDirectoryReadyResult stale_row =
            ServiceLifecycleBrokerMarkReady(&fixture.broker, joined.instance, &fixture.directory, stale_directory);
        EXPECT_EQ(stale_row.lifecycle_status, ServiceLifecycleStatus::Ok);
        EXPECT_EQ(stale_row.directory_status, ServiceDirectoryStatus::StaleKey);
        EXPECT_FALSE(InspectLifecycle(fixture).ready);
        EXPECT_FALSE(ServiceDirectoryInspectExact(&fixture.directory, directory_key).snapshot.ready);

        const ServiceLifecycleDirectoryReadyResult marked =
            ServiceLifecycleBrokerMarkReady(&fixture.broker, joined.instance, &fixture.directory, directory_key);
        EXPECT_EQ(marked.lifecycle_status, ServiceLifecycleStatus::Ok);
        EXPECT_EQ(marked.directory_status, ServiceDirectoryStatus::Ok);
        const ServiceLifecycleDirectoryReadyResult replay =
            ServiceLifecycleBrokerMarkReady(&fixture.broker, joined.instance, &fixture.directory, directory_key);
        EXPECT_EQ(replay.lifecycle_status, ServiceLifecycleStatus::Ok);
        EXPECT_EQ(replay.directory_status, ServiceDirectoryStatus::Ok);
        lifecycle = InspectLifecycle(fixture);
        directory = ServiceDirectoryInspectExact(&fixture.directory, directory_key);
        EXPECT_TRUE(lifecycle.ready);
        EXPECT_TRUE(directory.snapshot.ready);
        const ServiceLifecycleStartResult dependent =
            ServiceLifecycleBrokerReserveStartWithDependencies(&fixture.broker, 200, 0, 33);
        EXPECT_EQ(dependent.status, ServiceLifecycleStatus::Ok);
        EXPECT_EQ(ServiceLifecycleBrokerRecordSpawnFailure(&fixture.broker, dependent.ticket, 34),
                  ServiceLifecycleStatus::Ok);

        EXPECT_EQ(ServiceDirectoryUnregister(&fixture.directory, directory_key, directory.snapshot.owner).status,
                  ServiceDirectoryStatus::Ok);
        const ServiceLifecycleStopResult stop =
            ServiceLifecycleBrokerRequestStop(&fixture.broker, 100, joined.instance.start.transition.generation, 35);
        EXPECT_EQ(stop.status, ServiceLifecycleStatus::KillRequired);
        EXPECT_FALSE(InspectLifecycle(fixture).ready);
        EXPECT_EQ(ServiceLifecycleBrokerObserveExit(&fixture.broker, joined.instance, 36, false),
                  ServiceLifecycleStatus::Ok);
    }

    // A hostile stop racing an injected final-directory failure must serialize
    // on the lifecycle lock. Whether stop wins before the joint call or after
    // its exact rollback, no observer can end with Running and no directory row
    // can become Active.
    {
        Fixture fixture;
        ReservedPublication publication = Reserve(fixture, 0, 40, 0xDD01, 401);
        const ServiceKey directory_key = publication.directory.service;
        ServiceDirectoryHostFailNextRegistrationPublicationForTest();
        std::barrier start{3};
        ServiceLifecycleDirectoryPublicationResult joined{ServiceLifecycleStatus::Busy, ServiceDirectoryStatus::Ok,
                                                          kInvalidServiceLifecycleInstanceToken};
        ServiceLifecycleStopResult stopped{ServiceLifecycleStatus::Busy, kInvalidServiceLifecycleInstanceToken,
                                           kInvalidServiceLifecycleStartTicket};
        std::thread publisher(
            [&]
            {
                start.arrive_and_wait();
                joined = ServiceLifecycleBrokerCommitDirectoryPublication(&fixture.broker, publication.start,
                                                                          publication.process, 41, &fixture.directory,
                                                                          &publication.directory);
            });
        std::thread stopper(
            [&]
            {
                start.arrive_and_wait();
                stopped = ServiceLifecycleBrokerRequestStop(&fixture.broker, 100, 1, 41);
            });
        start.arrive_and_wait();
        publisher.join();
        stopper.join();

        EXPECT_EQ(stopped.status, ServiceLifecycleStatus::StartCancelled);
        EXPECT_TRUE(joined.lifecycle_status == ServiceLifecycleStatus::Ok ||
                    joined.lifecycle_status == ServiceLifecycleStatus::TransitionRejected);
        if (joined.lifecycle_status == ServiceLifecycleStatus::Ok)
            EXPECT_EQ(joined.directory_status, ServiceDirectoryStatus::Busy);
        const ServiceLifecycleSnapshot lifecycle = InspectLifecycle(fixture);
        EXPECT_TRUE(lifecycle.phase != ServiceTransitionPhase::Running);
        EXPECT_EQ(lifecycle.builder_state, ServiceLifecycleBuilderState::CancelledAwaitingRetirement);
        const ServiceDirectoryInspectResult directory = ServiceDirectoryInspectExact(&fixture.directory, directory_key);
        EXPECT_EQ(directory.status, ServiceDirectoryStatus::Ok);
        EXPECT_EQ(directory.snapshot.state, ServiceDirectoryEntryState::Reserved);

        EXPECT_EQ(ServiceLifecycleBrokerAcknowledgeCancelledStart(&fixture.broker, stopped.start_to_cancel, 42),
                  ServiceLifecycleStatus::Ok);
        EXPECT_EQ(
            ServiceDirectoryAbortRegistration(&fixture.directory, &publication.directory, publication.directory_owner),
            ServiceDirectoryStatus::Ok);
    }

    return duetos_host_test::finish_main("test_service_publication_directory");
}
