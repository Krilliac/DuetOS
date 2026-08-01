// Hosted manifest, identity, publication, stop, drain, and concurrency
// properties for core/service_lifecycle_broker.{h,cpp}.

#include "crypto_host_shims.h"
#include "host_test_helper.h"
#include "core/service_lifecycle_broker.h"
#include "crypto/sha256.h"

#include <array>
#include <atomic>
#include <barrier>
#include <cstring>
#include <mutex>
#include <thread>
#include <type_traits>

namespace
{

std::mutex g_host_spinlock;

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

namespace
{

using namespace duetos::core;
using duetos::u16;
using duetos::u32;
using duetos::u64;
using duetos::u8;

static_assert(!std::is_copy_constructible_v<ServiceLifecycleBroker>);
static_assert(!std::is_copy_assignable_v<ServiceLifecycleBroker>);
static_assert(!std::is_copy_constructible_v<ServiceLifecycleBrokerEpoch>);
static_assert(!std::is_copy_assignable_v<ServiceLifecycleBrokerEpoch>);
static_assert(!std::is_move_constructible_v<ServiceLifecycleBrokerEpoch>);
static_assert(!std::is_move_assignable_v<ServiceLifecycleBrokerEpoch>);

duetos::loader::Hash256 Hash(u8 seed)
{
    duetos::loader::Hash256 hash{};
    for (u32 index = 0; index < static_cast<u32>(sizeof(hash.bytes)); ++index)
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

ServiceManifestServiceV1 Service(u64 identity, u32 transfer_ref, const char* name, const char* path, u8 seed,
                                 ServiceManifestRestartPolicy restart)
{
    ServiceManifestServiceV1 service{};
    service.service_identity = identity;
    service.executable_transfer_ref = transfer_ref;
    service.immutable_policy_selector = 1;
    service.executable_content_hash = Hash(seed);
    service.requested_capability_ceiling = 1ULL << 2;
    service.requested_frame_budget_pages = 128;
    service.requested_tick_budget = 10000;
    service.requested_section_objects = 2;
    service.requested_section_pages = 64;
    service.kind = ServiceManifestKind::Native;
    service.restart_policy = restart;
    service.autostart = 1;
    service.resource_profile = ServiceManifestResourceProfile::AuthenticatedService;
    SetText(service.name, kServiceManifestServiceNameCapacity, &service.name_length, name);
    SetText(service.executable_path, kServiceManifestExecutablePathCapacity, &service.executable_path_length, path);
    return service;
}

ServiceManifestDocumentV1 Document()
{
    ServiceManifestDocumentV1 document{};
    document.manifest_identity = 0xA001;
    document.signer_identity = 0xB001;
    document.profile_identity = 0xC001;
    document.service_count = 3;
    document.dependency_count = 3;
    document.services[0] = Service(100, 0x101, "execd", "/system/execd", 0x10, ServiceManifestRestartPolicy::OnFailure);
    document.services[1] =
        Service(200, 0x102, "displayd", "/system/displayd", 0x30, ServiceManifestRestartPolicy::Always);
    document.services[2] = Service(300, 0x103, "netd", "/system/netd", 0x50, ServiceManifestRestartPolicy::Never);
    document.services[0].dependency_first = 0;
    document.services[0].dependency_count = 0;
    document.services[1].dependency_first = 0;
    document.services[1].dependency_count = 1;
    document.services[2].dependency_first = 1;
    document.services[2].dependency_count = 2;
    document.dependencies[0] = ServiceManifestDependencyV1{200, 100};
    document.dependencies[1] = ServiceManifestDependencyV1{300, 100};
    document.dependencies[2] = ServiceManifestDependencyV1{300, 200};
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

ServiceManifestPlanV1 Plan(ServiceManifestAuthoritySnapshotV1* authority_out)
{
    EXPECT_TRUE(authority_out != nullptr);
    const ServiceManifestDocumentV1 document = Document();
    std::array<u8, kServiceManifestMaximumBytes> bytes{};
    const ServiceManifestEncodeResult encoded = ServiceManifestEncodeV1(bytes.data(), bytes.size(), document);
    EXPECT_EQ(encoded.error, ServiceManifestError::Ok);
    const ServiceManifestAuthoritySnapshotV1 authority = Authority(document, bytes.data(), encoded.bytes_written);
    ServiceManifestPlanV1 plan{};
    EXPECT_EQ(ServiceManifestValidateV1(bytes.data(), encoded.bytes_written, &authority, &plan),
              ServiceManifestError::Ok);
    *authority_out = authority;
    return plan;
}

u64 InitializeBroker(ServiceLifecycleBroker* broker, const ServiceManifestPlanV1& plan,
                     const ServiceManifestAuthoritySnapshotV1& authority)
{
    ServiceLifecycleBrokerEpoch epoch = ServiceLifecycleBrokerMintEpoch();
    EXPECT_TRUE(epoch.IsValid());
    EXPECT_EQ(ServiceLifecycleBrokerInitialize(broker, &plan, &authority, &epoch), ServiceLifecycleStatus::Ok);
    EXPECT_TRUE(!epoch.IsValid());
    const ServiceLifecycleBrokerInspectResult described = ServiceLifecycleBrokerDescribe(broker);
    EXPECT_EQ(described.status, ServiceLifecycleStatus::Ok);
    return described.snapshot.broker_epoch;
}

ServiceInstanceKey Process(u64 pid)
{
    return ServiceInstanceKey{0x8000000000000000ULL | pid, pid};
}

ServiceLifecycleStartResult Start(ServiceLifecycleBroker& broker, u64 identity, u64 generation, u64 now_ns)
{
    const ServiceLifecycleStartResult result =
        ServiceLifecycleBrokerReserveStart(&broker, identity, generation, now_ns);
    EXPECT_EQ(result.status, ServiceLifecycleStatus::Ok);
    EXPECT_TRUE(ServiceLifecycleStartTicketIsValid(result.ticket));
    return result;
}

ServiceLifecycleInstanceToken Publish(ServiceLifecycleBroker& broker, ServiceLifecycleStartTicket ticket, u64 pid,
                                      u64 now_ns)
{
    const ServiceInstanceKey process = Process(pid);
    const ServiceLifecyclePublicationResult result =
        ServiceLifecycleBrokerCommitPublication(&broker, ticket, process, now_ns);
    EXPECT_EQ(result.status, ServiceLifecycleStatus::Ok);
    const ServiceLifecycleInstanceToken expected{ticket, process};
    EXPECT_TRUE(result.instance == expected);
    return result.instance;
}

} // namespace

int main()
{
    ServiceManifestAuthoritySnapshotV1 authority{};
    ServiceManifestPlanV1 plan = Plan(&authority);

    // The process-wide epoch dispenser must remain unique under concurrent
    // broker construction; no caller supplies or recycles raw integers.
    {
        constexpr u32 kEpochWorkers = 8;
        std::array<u64, kEpochWorkers> epochs{};
        std::array<ServiceLifecycleStatus, kEpochWorkers> statuses{};
        std::array<std::thread, kEpochWorkers> workers{};
        for (u32 index = 0; index < kEpochWorkers; ++index)
        {
            workers[index] = std::thread(
                [&, index]
                {
                    ServiceLifecycleBroker concurrent_broker{};
                    ServiceLifecycleBrokerEpoch epoch = ServiceLifecycleBrokerMintEpoch();
                    statuses[index] = epoch.IsValid() ? ServiceLifecycleBrokerInitialize(&concurrent_broker, &plan,
                                                                                         &authority, &epoch)
                                                      : ServiceLifecycleStatus::InvalidBrokerEpoch;
                    if (statuses[index] == ServiceLifecycleStatus::Ok)
                        epochs[index] = ServiceLifecycleBrokerDescribe(&concurrent_broker).snapshot.broker_epoch;
                });
        }
        for (std::thread& worker : workers)
            worker.join();
        for (u32 left = 0; left < kEpochWorkers; ++left)
        {
            EXPECT_EQ(statuses[left], ServiceLifecycleStatus::Ok);
            EXPECT_TRUE(epochs[left] != kServiceLifecycleInvalidBrokerEpoch);
            for (u32 right = 0; right < left; ++right)
                EXPECT_TRUE(epochs[left] != epochs[right]);
        }
    }

    ServiceLifecycleBroker broker{};
    ServiceLifecycleBrokerEpoch init_epoch = ServiceLifecycleBrokerMintEpoch();
    EXPECT_TRUE(init_epoch.IsValid());
    EXPECT_EQ(ServiceLifecycleBrokerInitialize(nullptr, &plan, &authority, &init_epoch),
              ServiceLifecycleStatus::NullArgument);
    EXPECT_EQ(ServiceLifecycleBrokerInitialize(&broker, nullptr, &authority, &init_epoch),
              ServiceLifecycleStatus::NullArgument);
    EXPECT_EQ(ServiceLifecycleBrokerInitialize(&broker, &plan, nullptr, &init_epoch),
              ServiceLifecycleStatus::NullArgument);
    EXPECT_EQ(ServiceLifecycleBrokerInitialize(&broker, &plan, &authority, nullptr),
              ServiceLifecycleStatus::NullArgument);
    EXPECT_EQ(ServiceLifecycleBrokerInitialize(&broker, reinterpret_cast<const ServiceManifestPlanV1*>(&broker),
                                               &authority, &init_epoch),
              ServiceLifecycleStatus::AliasedOutput);
    EXPECT_EQ(ServiceLifecycleBrokerInitialize(
                  &broker, &plan, reinterpret_cast<const ServiceManifestAuthoritySnapshotV1*>(&broker), &init_epoch),
              ServiceLifecycleStatus::AliasedOutput);
    EXPECT_EQ(ServiceLifecycleBrokerInitialize(
                  &broker, &plan, reinterpret_cast<const ServiceManifestAuthoritySnapshotV1*>(&plan), &init_epoch),
              ServiceLifecycleStatus::InvalidManifestPlan);
    EXPECT_EQ(ServiceLifecycleBrokerInitialize(&broker, &plan, &authority,
                                               reinterpret_cast<ServiceLifecycleBrokerEpoch*>(&broker)),
              ServiceLifecycleStatus::AliasedOutput);
    ServiceLifecycleBrokerEpoch invalid_epoch{};
    EXPECT_EQ(ServiceLifecycleBrokerInitialize(&broker, &plan, &authority, &invalid_epoch),
              ServiceLifecycleStatus::InvalidBrokerEpoch);

    ServiceManifestPlanV1 bad_plan = plan;
    bad_plan.topological_identities[0] = 200;
    bad_plan.topological_identities[1] = 100;
    EXPECT_EQ(ServiceLifecycleBrokerInitialize(&broker, &bad_plan, &authority, &init_epoch),
              ServiceLifecycleStatus::InvalidManifestPlan);
    EXPECT_EQ(broker.state, ServiceLifecycleBrokerState::Uninitialized);
    bad_plan = plan;
    bad_plan.topological_identities[2] = 200;
    EXPECT_EQ(ServiceLifecycleBrokerInitialize(&broker, &bad_plan, &authority, &init_epoch),
              ServiceLifecycleStatus::InvalidManifestPlan);
    bad_plan = plan;
    bad_plan.sealed_object_hash = {};
    EXPECT_EQ(ServiceLifecycleBrokerInitialize(&broker, &bad_plan, &authority, &init_epoch),
              ServiceLifecycleStatus::InvalidManifestPlan);
    bad_plan = plan;
    bad_plan.document.services[0].restart_policy = ServiceManifestRestartPolicy::Always;
    EXPECT_EQ(ServiceLifecycleBrokerInitialize(&broker, &bad_plan, &authority, &init_epoch),
              ServiceLifecycleStatus::InvalidManifestPlan);

    bad_plan = plan;
    ++bad_plan.authority_identity;
    EXPECT_EQ(ServiceLifecycleBrokerInitialize(&broker, &bad_plan, &authority, &init_epoch),
              ServiceLifecycleStatus::InvalidManifestPlan);
    ServiceManifestAuthoritySnapshotV1 bad_authority = authority;
    ++bad_authority.authority_identity;
    EXPECT_EQ(ServiceLifecycleBrokerInitialize(&broker, &plan, &bad_authority, &init_epoch),
              ServiceLifecycleStatus::InvalidManifestPlan);

    bad_authority = authority;
    bad_authority.allowed_capabilities = 0;
    EXPECT_TRUE(ServiceManifestAuthoritySnapshotIsCanonicalV1(bad_authority));
    EXPECT_EQ(ServiceLifecycleBrokerInitialize(&broker, &plan, &bad_authority, &init_epoch),
              ServiceLifecycleStatus::InvalidManifestPlan);

    EXPECT_EQ(ServiceLifecycleBrokerInitialize(&broker, &plan, &authority, &init_epoch), ServiceLifecycleStatus::Ok);
    EXPECT_TRUE(!init_epoch.IsValid());
    ServiceLifecycleBroker duplicate_epoch_broker{};
    EXPECT_EQ(ServiceLifecycleBrokerInitialize(&duplicate_epoch_broker, &plan, &authority, &init_epoch),
              ServiceLifecycleStatus::InvalidBrokerEpoch);
    EXPECT_EQ(broker.state, ServiceLifecycleBrokerState::Open);
    EXPECT_EQ(broker.service_count, 3U);
    ServiceLifecycleBrokerInspectResult described = ServiceLifecycleBrokerDescribe(&broker);
    EXPECT_EQ(described.status, ServiceLifecycleStatus::Ok);
    EXPECT_TRUE(described.snapshot.broker_epoch != kServiceLifecycleInvalidBrokerEpoch);
    EXPECT_EQ(described.snapshot.manifest_identity, plan.document.manifest_identity);
    EXPECT_EQ(described.snapshot.manifest_authority_identity, authority.authority_identity);
    EXPECT_EQ(described.snapshot.service_count, plan.document.service_count);
    EXPECT_EQ(described.snapshot.dependency_count, plan.document.dependency_count);
    EXPECT_EQ(described.snapshot.manifest_object_extent, plan.sealed_object_extent);
    EXPECT_TRUE(std::memcmp(described.snapshot.manifest_object_hash.bytes, plan.sealed_object_hash.bytes,
                            sizeof(plan.sealed_object_hash.bytes)) == 0);
    ServiceLifecycleBrokerEpoch reinitialize_epoch = ServiceLifecycleBrokerMintEpoch();
    EXPECT_TRUE(reinitialize_epoch.IsValid());
    EXPECT_EQ(ServiceLifecycleBrokerInitialize(&broker, &plan, &authority, &reinitialize_epoch),
              ServiceLifecycleStatus::AlreadyInitialized);
    EXPECT_TRUE(reinitialize_epoch.IsValid());
    ServiceLifecycleInspectResult inspected = ServiceLifecycleBrokerInspectAt(&broker, 0);
    EXPECT_EQ(inspected.status, ServiceLifecycleStatus::Ok);
    EXPECT_EQ(inspected.snapshot.service_identity, 100ULL);
    EXPECT_EQ(inspected.snapshot.dependency_mask, 0ULL);
    inspected = ServiceLifecycleBrokerInspect(&broker, 200);
    EXPECT_EQ(inspected.status, ServiceLifecycleStatus::Ok);
    EXPECT_EQ(inspected.snapshot.dependency_mask, 1ULL << 0);
    inspected = ServiceLifecycleBrokerInspect(&broker, 300);
    EXPECT_EQ(inspected.status, ServiceLifecycleStatus::Ok);
    EXPECT_EQ(inspected.snapshot.dependency_mask, (1ULL << 0) | (1ULL << 1));
    EXPECT_EQ(ServiceLifecycleBrokerInspect(&broker, 999).status, ServiceLifecycleStatus::NotFound);
    EXPECT_EQ(ServiceLifecycleBrokerInspectAt(&broker, 3).status, ServiceLifecycleStatus::NotFound);

    EXPECT_EQ(ServiceLifecycleBrokerReserveStart(&broker, 999, 0, 1).status, ServiceLifecycleStatus::NotFound);
    EXPECT_EQ(ServiceLifecycleBrokerReserveStart(&broker, 100, 1, 1).status, ServiceLifecycleStatus::StaleGeneration);
    ServiceLifecycleStartResult start = Start(broker, 100, 0, 10);
    EXPECT_EQ(ServiceLifecycleBrokerReserveStart(&broker, 100, 1, 11).status, ServiceLifecycleStatus::AlreadyRequested);

    ServiceLifecycleBroker other_broker{};
    InitializeBroker(&other_broker, plan, authority);
    const ServiceLifecycleStartResult other_start = Start(other_broker, 100, 0, 10);
    EXPECT_EQ(other_start.ticket.transition, start.ticket.transition);
    EXPECT_TRUE(other_start.ticket.broker_epoch != start.ticket.broker_epoch);
    EXPECT_EQ(ServiceLifecycleBrokerCommitPublication(&other_broker, start.ticket, Process(699), 12).status,
              ServiceLifecycleStatus::StaleBrokerEpoch);
    EXPECT_EQ(ServiceLifecycleBrokerRecordSpawnFailure(&other_broker, other_start.ticket, 13),
              ServiceLifecycleStatus::Ok);

    EXPECT_EQ(ServiceLifecycleBrokerCommitPublication(&broker, start.ticket, kInvalidServiceInstanceKey, 12).status,
              ServiceLifecycleStatus::TransitionRejected);
    const ServiceLifecycleInstanceToken first = Publish(broker, start.ticket, 700, 20);
    EXPECT_EQ(ServiceLifecycleBrokerCommitPublication(&broker, start.ticket, first.process, 21).status,
              ServiceLifecycleStatus::TransitionRejected);
    EXPECT_EQ(ServiceLifecycleBrokerRequestStop(&broker, 100, 0, 22).status, ServiceLifecycleStatus::StaleGeneration);
    EXPECT_EQ(ServiceLifecycleBrokerRequestStop(&broker, 100, 1, 19).status, ServiceLifecycleStatus::InvalidTimestamp);
    ServiceLifecycleStopResult stop = ServiceLifecycleBrokerRequestStop(&broker, 100, 1, 30);
    EXPECT_EQ(stop.status, ServiceLifecycleStatus::KillRequired);
    EXPECT_TRUE(stop.instance_to_kill == first);
    EXPECT_EQ(ServiceLifecycleBrokerReserveStart(&broker, 100, 1, 31).status, ServiceLifecycleStatus::StopInProgress);
    stop = ServiceLifecycleBrokerRequestStop(&broker, 100, 1, 31);
    EXPECT_EQ(stop.status, ServiceLifecycleStatus::AlreadyStopping);
    EXPECT_TRUE(stop.instance_to_kill == kInvalidServiceLifecycleInstanceToken);
    ServiceLifecycleInstanceToken wrong = first;
    ++wrong.process.process_identity;
    EXPECT_EQ(ServiceLifecycleBrokerObserveExit(&broker, wrong, 40, false), ServiceLifecycleStatus::TransitionRejected);
    EXPECT_EQ(ServiceLifecycleBrokerObserveExit(&broker, first, 40, false), ServiceLifecycleStatus::Ok);

    inspected = ServiceLifecycleBrokerInspect(&broker, 100);
    EXPECT_EQ(inspected.snapshot.phase, ServiceTransitionPhase::Stopped);
    EXPECT_EQ(inspected.snapshot.successful_publications, 1U);
    EXPECT_EQ(inspected.snapshot.observed_exits, 1U);
    EXPECT_EQ(inspected.snapshot.failed_exits, 0U);

    start = Start(broker, 100, 1, 50);
    const ServiceLifecycleInstanceToken second = Publish(broker, start.ticket, 701, 60);
    EXPECT_EQ(ServiceLifecycleBrokerObserveExit(&broker, second, 70, true), ServiceLifecycleStatus::Ok);
    EXPECT_EQ(ServiceLifecycleBrokerObserveExit(&broker, second, 71, true), ServiceLifecycleStatus::TransitionRejected);
    inspected = ServiceLifecycleBrokerInspect(&broker, 100);
    EXPECT_EQ(inspected.snapshot.phase, ServiceTransitionPhase::Exited);
    EXPECT_EQ(inspected.snapshot.successful_publications, 2U);
    EXPECT_EQ(inspected.snapshot.observed_exits, 2U);
    EXPECT_EQ(inspected.snapshot.failed_exits, 1U);

    ServiceLifecycleStartResult failed_start = Start(broker, 200, 0, 80);
    EXPECT_EQ(ServiceLifecycleBrokerRecordSpawnFailure(&broker, failed_start.ticket, 90), ServiceLifecycleStatus::Ok);
    EXPECT_EQ(ServiceLifecycleBrokerRecordSpawnFailure(&broker, failed_start.ticket, 91),
              ServiceLifecycleStatus::TransitionRejected);
    inspected = ServiceLifecycleBrokerInspect(&broker, 200);
    EXPECT_EQ(inspected.snapshot.spawn_failures, 1U);
    EXPECT_EQ(inspected.snapshot.phase, ServiceTransitionPhase::Failed);

    ServiceLifecycleStartResult cancelled = Start(broker, 300, 0, 100);
    stop = ServiceLifecycleBrokerRequestStop(&broker, 300, 1, 110);
    EXPECT_EQ(stop.status, ServiceLifecycleStatus::StartCancelled);
    EXPECT_TRUE(stop.instance_to_kill == kInvalidServiceLifecycleInstanceToken);
    EXPECT_TRUE(stop.start_to_cancel == cancelled.ticket);
    EXPECT_EQ(ServiceLifecycleBrokerReserveStart(&broker, 300, 1, 111).status,
              ServiceLifecycleStatus::StartRetirementPending);
    EXPECT_EQ(ServiceLifecycleBrokerCommitPublication(&broker, cancelled.ticket, Process(900), 120).status,
              ServiceLifecycleStatus::TransitionRejected);
    EXPECT_EQ(ServiceLifecycleBrokerAcknowledgeCancelledStart(&broker, cancelled.ticket, 120),
              ServiceLifecycleStatus::Ok);
    EXPECT_EQ(ServiceLifecycleBrokerAcknowledgeCancelledStart(&broker, cancelled.ticket, 121),
              ServiceLifecycleStatus::TransitionRejected);

    // Drain is transactional with respect to clock validation and emits one
    // exact kill token per newly-Stopping Running row.
    ServiceLifecycleBroker draining{};
    InitializeBroker(&draining, plan, authority);
    const ServiceLifecycleStartResult running_start = Start(draining, 100, 0, 10);
    const ServiceLifecycleInstanceToken running = Publish(draining, running_start.ticket, 1000, 20);
    (void)Start(draining, 200, 0, 30);
    ServiceLifecycleDrainPlan drain_plan{};
    EXPECT_EQ(ServiceLifecycleBrokerBeginDrain(&draining, 19, &drain_plan), ServiceLifecycleStatus::InvalidTimestamp);
    EXPECT_EQ(draining.state, ServiceLifecycleBrokerState::Open);
    EXPECT_EQ(ServiceLifecycleBrokerBeginDrain(&draining, 40, reinterpret_cast<ServiceLifecycleDrainPlan*>(&draining)),
              ServiceLifecycleStatus::AliasedOutput);
    EXPECT_EQ(ServiceLifecycleBrokerBeginDrain(&draining, 40, &drain_plan), ServiceLifecycleStatus::Ok);
    EXPECT_EQ(drain_plan.kill_count, 1U);
    EXPECT_EQ(drain_plan.cancel_count, 1U);
    EXPECT_TRUE(drain_plan.instances[0] == running);
    EXPECT_EQ(draining.state, ServiceLifecycleBrokerState::Draining);
    EXPECT_EQ(ServiceLifecycleBrokerReserveStart(&draining, 300, 0, 41).status, ServiceLifecycleStatus::Draining);
    ServiceLifecycleDrainPlan duplicate_plan{};
    EXPECT_EQ(ServiceLifecycleBrokerBeginDrain(&draining, 41, &duplicate_plan), ServiceLifecycleStatus::Draining);
    EXPECT_EQ(duplicate_plan.kill_count, 0U);
    EXPECT_EQ(duplicate_plan.cancel_count, 0U);
    EXPECT_EQ(ServiceLifecycleBrokerFinishDrain(&draining), ServiceLifecycleStatus::Busy);
    EXPECT_EQ(ServiceLifecycleBrokerObserveExit(&draining, running, 50, true), ServiceLifecycleStatus::Ok);
    EXPECT_EQ(ServiceLifecycleBrokerFinishDrain(&draining), ServiceLifecycleStatus::Busy);
    EXPECT_EQ(ServiceLifecycleBrokerAcknowledgeCancelledStart(&draining, drain_plan.cancelled_starts[0], 50),
              ServiceLifecycleStatus::Ok);
    EXPECT_EQ(ServiceLifecycleBrokerFinishDrain(&draining), ServiceLifecycleStatus::Ok);
    EXPECT_EQ(draining.state, ServiceLifecycleBrokerState::Closed);
    EXPECT_EQ(ServiceLifecycleBrokerFinishDrain(&draining), ServiceLifecycleStatus::Closed);
    EXPECT_EQ(ServiceLifecycleBrokerReserveStart(&draining, 100, 1, 60).status, ServiceLifecycleStatus::Closed);
    EXPECT_EQ(ServiceLifecycleBrokerInspect(&draining, 100).status, ServiceLifecycleStatus::Ok);

    // Cancelling Starting authority does not make its private graph vanish.
    // Close remains Busy until the exact builder destroys that graph and acks.
    ServiceLifecycleBroker paused_builder{};
    InitializeBroker(&paused_builder, plan, authority);
    const ServiceLifecycleStartResult paused_start = Start(paused_builder, 100, 0, 10);
    ServiceLifecycleDrainPlan paused_plan{};
    std::barrier builder_started(2);
    std::barrier allow_retirement(2);
    std::atomic<u32> retirement_status{static_cast<u32>(ServiceLifecycleStatus::CorruptState)};
    std::thread builder(
        [&]
        {
            builder_started.arrive_and_wait();
            allow_retirement.arrive_and_wait();
            retirement_status.store(static_cast<u32>(ServiceLifecycleBrokerAcknowledgeCancelledStart(
                                        &paused_builder, paused_start.ticket, 30)),
                                    std::memory_order_relaxed);
        });
    builder_started.arrive_and_wait();
    EXPECT_EQ(ServiceLifecycleBrokerBeginDrain(&paused_builder, 20, &paused_plan), ServiceLifecycleStatus::Ok);
    EXPECT_EQ(paused_plan.cancel_count, 1U);
    EXPECT_TRUE(paused_plan.cancelled_starts[0] == paused_start.ticket);
    EXPECT_EQ(ServiceLifecycleBrokerFinishDrain(&paused_builder), ServiceLifecycleStatus::Busy);
    allow_retirement.arrive_and_wait();
    builder.join();
    EXPECT_EQ(retirement_status.load(std::memory_order_relaxed), static_cast<u32>(ServiceLifecycleStatus::Ok));
    EXPECT_EQ(ServiceLifecycleBrokerFinishDrain(&paused_builder), ServiceLifecycleStatus::Ok);

    // The final usable generation stays exact through Stopping and retires
    // only after scheduler invisibility is proven.
    ServiceLifecycleBroker terminal{};
    InitializeBroker(&terminal, plan, authority);
    terminal.rows[0].transition.generation = kServiceTransitionGenerationMaximum - 1;
    ServiceLifecycleStartResult terminal_start = Start(terminal, 100, kServiceTransitionGenerationMaximum - 1, 1);
    EXPECT_EQ(terminal_start.ticket.transition.generation, kServiceTransitionGenerationMaximum);
    const ServiceLifecycleInstanceToken terminal_instance = Publish(terminal, terminal_start.ticket, 0x777, 2);
    stop = ServiceLifecycleBrokerRequestStop(&terminal, 100, kServiceTransitionGenerationMaximum, 3);
    EXPECT_EQ(stop.status, ServiceLifecycleStatus::KillRequired);
    EXPECT_TRUE(stop.instance_to_kill == terminal_instance);
    EXPECT_EQ(ServiceLifecycleBrokerObserveExit(&terminal, terminal_instance, 4, false), ServiceLifecycleStatus::Ok);
    EXPECT_EQ(ServiceLifecycleBrokerReserveStart(&terminal, 100, kServiceTransitionGenerationMaximum, 5).status,
              ServiceLifecycleStatus::GenerationExhausted);

    ServiceLifecycleBroker terminal_natural{};
    InitializeBroker(&terminal_natural, plan, authority);
    terminal_natural.rows[0].transition.generation = kServiceTransitionGenerationMaximum - 1;
    terminal_start = Start(terminal_natural, 100, kServiceTransitionGenerationMaximum - 1, 10);
    const ServiceLifecycleInstanceToken terminal_natural_instance =
        Publish(terminal_natural, terminal_start.ticket, 0x778, 20);
    EXPECT_EQ(ServiceLifecycleBrokerObserveExit(&terminal_natural, terminal_natural_instance, 30, true),
              ServiceLifecycleStatus::Ok);
    EXPECT_EQ(
        ServiceLifecycleBrokerReserveStart(&terminal_natural, 100, kServiceTransitionGenerationMaximum, 40).status,
        ServiceLifecycleStatus::GenerationExhausted);
    inspected = ServiceLifecycleBrokerInspect(&terminal_natural, 100);
    EXPECT_EQ(inspected.snapshot.phase, ServiceTransitionPhase::GenerationExhausted);
    EXPECT_EQ(inspected.snapshot.last_transition_ns, 40ULL);

    ServiceLifecycleBroker terminal_failure{};
    InitializeBroker(&terminal_failure, plan, authority);
    terminal_failure.rows[0].transition.generation = kServiceTransitionGenerationMaximum - 1;
    terminal_start = Start(terminal_failure, 100, kServiceTransitionGenerationMaximum - 1, 10);
    EXPECT_EQ(ServiceLifecycleBrokerRecordSpawnFailure(&terminal_failure, terminal_start.ticket, 20),
              ServiceLifecycleStatus::Ok);
    EXPECT_EQ(
        ServiceLifecycleBrokerReserveStart(&terminal_failure, 100, kServiceTransitionGenerationMaximum, 30).status,
        ServiceLifecycleStatus::GenerationExhausted);
    inspected = ServiceLifecycleBrokerInspect(&terminal_failure, 100);
    EXPECT_EQ(inspected.snapshot.phase, ServiceTransitionPhase::GenerationExhausted);
    EXPECT_EQ(inspected.snapshot.last_transition_ns, 30ULL);

    // Publication and global drain have only two legal linearization orders.
    for (u32 iteration = 0; iteration < 512; ++iteration)
    {
        ServiceLifecycleBroker raced{};
        InitializeBroker(&raced, plan, authority);
        const ServiceLifecycleStartResult raced_start = Start(raced, 100, 0, 1);
        const ServiceInstanceKey raced_process = Process(0x10000ULL + iteration);
        std::barrier line(3);
        std::atomic<u32> publish_status{static_cast<u32>(ServiceLifecycleStatus::CorruptState)};
        std::atomic<u32> drain_status{static_cast<u32>(ServiceLifecycleStatus::CorruptState)};
        ServiceLifecycleDrainPlan raced_plan{};

        std::thread publisher(
            [&]
            {
                line.arrive_and_wait();
                publish_status.store(
                    static_cast<u32>(
                        ServiceLifecycleBrokerCommitPublication(&raced, raced_start.ticket, raced_process, 2).status),
                    std::memory_order_relaxed);
            });
        std::thread drainer(
            [&]
            {
                line.arrive_and_wait();
                drain_status.store(static_cast<u32>(ServiceLifecycleBrokerBeginDrain(&raced, 3, &raced_plan)),
                                   std::memory_order_relaxed);
            });
        line.arrive_and_wait();
        publisher.join();
        drainer.join();

        EXPECT_EQ(drain_status.load(std::memory_order_relaxed), static_cast<u32>(ServiceLifecycleStatus::Ok));
        if (publish_status.load(std::memory_order_relaxed) == static_cast<u32>(ServiceLifecycleStatus::Ok))
        {
            EXPECT_EQ(raced_plan.kill_count, 1U);
            EXPECT_EQ(raced_plan.cancel_count, 0U);
            EXPECT_EQ(ServiceLifecycleBrokerObserveExit(&raced, raced_plan.instances[0], 4, false),
                      ServiceLifecycleStatus::Ok);
        }
        else
        {
            EXPECT_EQ(publish_status.load(std::memory_order_relaxed),
                      static_cast<u32>(ServiceLifecycleStatus::Draining));
            EXPECT_EQ(raced_plan.kill_count, 0U);
            EXPECT_EQ(raced_plan.cancel_count, 1U);
            EXPECT_EQ(ServiceLifecycleBrokerAcknowledgeCancelledStart(&raced, raced_plan.cancelled_starts[0], 4),
                      ServiceLifecycleStatus::Ok);
        }
        EXPECT_EQ(ServiceLifecycleBrokerFinishDrain(&raced), ServiceLifecycleStatus::Ok);
    }

    ServiceLifecycleBroker corrupt{};
    InitializeBroker(&corrupt, plan, authority);
    corrupt.rows[0].dependency_mask = 1;
    EXPECT_EQ(ServiceLifecycleBrokerInspect(&corrupt, 100).status, ServiceLifecycleStatus::CorruptState);
    ServiceLifecycleBroker corrupt_telemetry{};
    InitializeBroker(&corrupt_telemetry, plan, authority);
    corrupt_telemetry.rows[0].observed_exits = 1;
    EXPECT_EQ(ServiceLifecycleBrokerInspect(&corrupt_telemetry, 100).status, ServiceLifecycleStatus::CorruptState);

    ServiceLifecycleBroker corrupt_draining{};
    InitializeBroker(&corrupt_draining, plan, authority);
    const ServiceLifecycleInstanceToken corrupt_running =
        Publish(corrupt_draining, Start(corrupt_draining, 100, 0, 1).ticket, 0xF001, 2);
    EXPECT_TRUE(ServiceLifecycleInstanceTokenIsValid(corrupt_running));
    corrupt_draining.state = ServiceLifecycleBrokerState::Draining;
    EXPECT_EQ(ServiceLifecycleBrokerInspect(&corrupt_draining, 100).status, ServiceLifecycleStatus::CorruptState);

    ServiceLifecycleBroker corrupt_closed{};
    InitializeBroker(&corrupt_closed, plan, authority);
    const ServiceLifecycleStartTicket corrupt_builder = Start(corrupt_closed, 100, 0, 1).ticket;
    EXPECT_EQ(ServiceLifecycleBrokerRequestStop(&corrupt_closed, 100, 1, 2).status,
              ServiceLifecycleStatus::StartCancelled);
    corrupt_closed.state = ServiceLifecycleBrokerState::Closed;
    EXPECT_EQ(ServiceLifecycleBrokerAcknowledgeCancelledStart(&corrupt_closed, corrupt_builder, 3),
              ServiceLifecycleStatus::CorruptState);
    EXPECT_TRUE(std::strcmp(ServiceLifecycleStatusName(ServiceLifecycleStatus::KillRequired), "kill-required") == 0);

    return duetos_host_test::finish_main("service_lifecycle_broker");
}
