#include "core/service_control_platform.h"

#include <atomic>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <thread>
#include <vector>

using namespace duetos;
using namespace duetos::core;

namespace
{

int g_failures = 0;

#define EXPECT_TRUE(expr)                                                                                              \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(expr))                                                                                                   \
        {                                                                                                              \
            std::cerr << __FILE__ << ':' << __LINE__ << ": EXPECT_TRUE(" #expr ") failed\n";                           \
            ++g_failures;                                                                                              \
        }                                                                                                              \
    } while (false)

#define EXPECT_EQ(actual, expected)                                                                                    \
    do                                                                                                                 \
    {                                                                                                                  \
        const auto actual_value = (actual);                                                                            \
        const auto expected_value = (expected);                                                                        \
        if (!(actual_value == expected_value))                                                                         \
        {                                                                                                              \
            std::cerr << __FILE__ << ':' << __LINE__ << ": EXPECT_EQ(" #actual ", " #expected ") failed\n";            \
            ++g_failures;                                                                                              \
        }                                                                                                              \
    } while (false)

constexpr u64 kBrokerEpoch = 0xB001;
constexpr u64 kServiceIdentity = 0x300;
constexpr u64 kManifestIdentity = 0xA001;
constexpr u64 kManifestAuthorityIdentity = 0xA002;
constexpr u64 kStageRegistryIdentity = 0xA003;
constexpr ProcessKey kSupervisorOne{0x51001, 501};
constexpr ProcessKey kSupervisorTwo{0x52002, 502};
constexpr ProcessKey kServiceProcess{0x33003, 303};

template <typename T> T* Sentinel(std::uintptr_t value)
{
    return reinterpret_cast<T*>(value);
}

struct Fixture
{
    ServiceRuntimeV1* runtime = Sentinel<ServiceRuntimeV1>(0x10000);
    ServiceExitReapLedger* ledger = Sentinel<ServiceExitReapLedger>(0x20000);
    ServiceRuntimeStatusV1 runtime_inspect_status = ServiceRuntimeStatusV1::Ok;
    ServiceRuntimeStatusV1 bind_status = ServiceRuntimeStatusV1::Ok;
    ServiceLifecycleStatus broker_status = ServiceLifecycleStatus::Ok;
    ServiceLifecycleStatus lifecycle_status = ServiceLifecycleStatus::Ok;
    ServiceBootstrapActivationStatusV1 activation_status = ServiceBootstrapActivationStatusV1::Ok;
    ServiceLifecycleStatus stop_status = ServiceLifecycleStatus::KillRequired;
    ServiceControlPlatformKillExactResultV1 kill_status = ServiceControlPlatformKillExactResultV1::Visited;
    ServiceBootstrapStageStatus stage_status = ServiceBootstrapStageStatus::Ok;
    ServiceBootstrapLiveStatusV1 live_status = ServiceBootstrapLiveStatusV1::CompatibilityRequired;
    ServiceBootstrapLiveRestageStatusV1 live_restage_status = ServiceBootstrapLiveRestageStatusV1::Ok;
    ServiceBootstrapStageStatus live_restage_stage_status = ServiceBootstrapStageStatus::Ok;
    u8 live_restage_previous_bank = 0;
    u8 live_restage_active_bank = 1;
    ServiceExitReapStatus ledger_status = ServiceExitReapStatus::Ok;
    ServiceExitReapStatus dequeue_status = ServiceExitReapStatus::Ok;
    ServiceExitReapStatus restage_query_status = ServiceExitReapStatus::Ok;
    ServiceExitReapStatus acknowledge_status = ServiceExitReapStatus::Ok;
    ServiceControlIngressStatus install_status = ServiceControlIngressStatus::Ok;
    u64 now_ns = 100;

    ServiceRuntimeSnapshotV1 runtime_snapshot{};
    ServiceRuntimeActivationAuthorityV1 authority{};
    ServiceLifecycleBrokerSnapshot broker_snapshot{};
    ServiceLifecycleSnapshot lifecycle_snapshot{};
    ServiceBootstrapServiceSnapshotV1 staged_snapshot{};
    ServiceBootstrapLiveSnapshotV1 live_snapshot{};
    ServiceExitReapLedgerSnapshot ledger_snapshot{};
    ServiceExitReapDeliveryRecord delivery_record{};
    ServiceExitReapRestageResult restage_result{};

    std::atomic<u32> runtime_inspect_calls{0};
    std::atomic<u32> bind_calls{0};
    std::atomic<u32> broker_calls{0};
    std::atomic<u32> lifecycle_calls{0};
    std::atomic<u32> activation_calls{0};
    std::atomic<u32> stop_calls{0};
    std::atomic<u32> kill_calls{0};
    std::atomic<u32> stage_calls{0};
    std::atomic<u32> live_inspect_calls{0};
    std::atomic<u32> live_restage_calls{0};
    std::atomic<u32> ledger_inspect_calls{0};
    std::atomic<u32> dequeue_calls{0};
    std::atomic<u32> restage_query_calls{0};
    std::atomic<u32> acknowledge_calls{0};
    std::atomic<u32> install_calls{0};

    ServiceControlIngressPlatformV1 installed{};
    ProcessKey last_kill = kInvalidProcessKey;
    std::atomic<u64> last_delivery_owner_identity{0};
    std::atomic<u64> last_delivery_owner_pid{0};
    ProcessKey last_ack_owner = kInvalidProcessKey;
    ServiceExitReapEventKey last_restage_event = kInvalidServiceExitReapEventKey;
    ServiceExitReapEventKey last_ack_event = kInvalidServiceExitReapEventKey;
    u64 last_ack_token = 0;
    u64 last_stage_generation = 0;
    ServiceBootstrapLiveRetiredTargetTeardownV1 last_teardown =
        ServiceBootstrapLiveRetiredTargetTeardownV1::NotConfirmed;

    Fixture()
    {
        for (u32 index = 0; index < sizeof(authority.manifest_object_hash.bytes); ++index)
            authority.manifest_object_hash.bytes[index] = static_cast<u8>(index + 1);
        authority.stage = Sentinel<ServiceBootstrapStageRuntimeV1>(0x30000);
        authority.lifecycle = Sentinel<ServiceLifecycleBroker>(0x40000);
        authority.exit_observer = Sentinel<ServiceExitObserver>(0x50000);
        authority.directory = Sentinel<ServiceDirectory>(0x60000);
        authority.manifest_identity = kManifestIdentity;
        authority.manifest_authority_identity = kManifestAuthorityIdentity;
        authority.manifest_object_extent = 4096;
        authority.stage_registry_identity = kStageRegistryIdentity;

        runtime_snapshot.state = ServiceRuntimeStateV1::Open;
        runtime_snapshot.version = kServiceRuntimeVersion1;
        runtime_snapshot.service_count = 5;
        runtime_snapshot.manifest_identity = authority.manifest_identity;
        runtime_snapshot.manifest_authority_identity = authority.manifest_authority_identity;
        runtime_snapshot.broker_epoch = kBrokerEpoch;
        runtime_snapshot.observer_epoch = 7;
        runtime_snapshot.observer_event_sequence = 1;
        runtime_snapshot.stage_registry_identity = authority.stage_registry_identity;

        broker_snapshot.state = ServiceLifecycleBrokerState::Open;
        broker_snapshot.service_count = static_cast<u16>(runtime_snapshot.service_count);
        broker_snapshot.broker_epoch = kBrokerEpoch;
        broker_snapshot.manifest_identity = authority.manifest_identity;
        broker_snapshot.manifest_authority_identity = authority.manifest_authority_identity;
        broker_snapshot.manifest_object_hash = authority.manifest_object_hash;
        broker_snapshot.manifest_object_extent = authority.manifest_object_extent;

        lifecycle_snapshot.service_identity = kServiceIdentity;
        lifecycle_snapshot.phase = ServiceTransitionPhase::Stopped;
        lifecycle_snapshot.transition_generation = 0;
        lifecycle_snapshot.instance = kInvalidServiceInstanceKey;

        staged_snapshot.service_identity = kServiceIdentity;
        staged_snapshot.manifest_index = 2;
        staged_snapshot.activation_state = ServiceBootstrapActivationStateV1::TransferredPublished;
        staged_snapshot.activation_generation = 9;

        live_snapshot.state = ServiceBootstrapLiveStateV1::RuntimeOpenCompatibilityRequired;
        live_snapshot.status = ServiceBootstrapLiveStatusV1::CompatibilityRequired;
        live_snapshot.version = kServiceBootstrapLiveVersion1;
        live_snapshot.fixed_service_capacity = kServiceBootstrapLiveServiceCapacityV1;
        live_snapshot.generated_service_count = runtime_snapshot.service_count;
        live_snapshot.staged_service_count = runtime_snapshot.service_count;
        live_snapshot.stage_registry_identity = authority.stage_registry_identity;
        live_snapshot.compatibility_required = 1;

        ledger_snapshot.state = ServiceExitReapLedgerState::Open;

        delivery_record.delivery_token = 0xAC01;
        delivery_record.service_identity = kServiceIdentity;
        delivery_record.generation = 4;
        delivery_record.broker_epoch = kBrokerEpoch;
        delivery_record.event_sequence = 0xEE01;
        delivery_record.instance = ServiceInstanceKey{kServiceProcess.identity, kServiceProcess.pid};
        delivery_record.process = kServiceProcess;
        delivery_record.exit_code = 0xC0000005U;
        delivery_record.failed = 1;
        delivery_record.lifecycle_disposition = ServiceExitReapLifecycleDisposition::Committed;
        delivery_record.directory_disposition = ServiceExitReapDirectoryDisposition::Committed;
        delivery_record.observer_ack_disposition = ServiceExitReapObserverAckDisposition::Acknowledged;
        delivery_record.lifecycle_status = ServiceLifecycleStatus::Ok;
        delivery_record.directory_status = ServiceDirectoryStatus::Ok;
        delivery_record.observer_ack_status = ServiceExitObserverStatus::Ok;
        delivery_record.delivery_count = 1;

        restage_result.status = ServiceExitReapStatus::Ok;
        restage_result.eligible = 1;
        restage_result.live_rows = 1;
        restage_result.blocking_rows = 0;
    }
};

u64 MonotonicNs(void* context)
{
    return static_cast<Fixture*>(context)->now_ns;
}

ServiceRuntimeStatusV1 RuntimeInspect(void* context, const ServiceRuntimeV1*, ServiceRuntimeSnapshotV1* out)
{
    auto& fixture = *static_cast<Fixture*>(context);
    ++fixture.runtime_inspect_calls;
    if (fixture.runtime_inspect_status == ServiceRuntimeStatusV1::Ok && out != nullptr)
        *out = fixture.runtime_snapshot;
    return fixture.runtime_inspect_status;
}

ServiceRuntimeStatusV1 BindAuthority(void* context, ServiceRuntimeV1*, ServiceRuntimeActivationAuthorityV1* out)
{
    auto& fixture = *static_cast<Fixture*>(context);
    ++fixture.bind_calls;
    if (fixture.bind_status == ServiceRuntimeStatusV1::Ok && out != nullptr)
        *out = fixture.authority;
    return fixture.bind_status;
}

ServiceLifecycleBrokerInspectResult BrokerDescribe(void* context, ServiceLifecycleBroker*)
{
    auto& fixture = *static_cast<Fixture*>(context);
    ++fixture.broker_calls;
    return ServiceLifecycleBrokerInspectResult{fixture.broker_status, fixture.broker_snapshot};
}

ServiceLifecycleInspectResult LifecycleInspect(void* context, ServiceLifecycleBroker*, u64 service_identity)
{
    auto& fixture = *static_cast<Fixture*>(context);
    ++fixture.lifecycle_calls;
    if (service_identity != fixture.lifecycle_snapshot.service_identity)
        return ServiceLifecycleInspectResult{ServiceLifecycleStatus::NotFound, {}};
    return ServiceLifecycleInspectResult{fixture.lifecycle_status, fixture.lifecycle_snapshot};
}

ServiceBootstrapActivationResultV1 Activate(void* context, const ServiceBootstrapActivationRequestV1& request)
{
    auto& fixture = *static_cast<Fixture*>(context);
    ++fixture.activation_calls;
    ServiceBootstrapActivationResultV1 result{};
    result.status = fixture.activation_status;
    result.runtime_status = ServiceRuntimeStatusV1::Ok;
    result.stage_status = ServiceBootstrapStageStatus::Ok;
    result.lifecycle_status = ServiceLifecycleStatus::Ok;
    result.lifecycle_cleanup_status = ServiceLifecycleStatus::Ok;
    if (result.status == ServiceBootstrapActivationStatusV1::Ok)
    {
        result.instance = ServiceLifecycleInstanceToken{
            ServiceLifecycleStartTicket{
                kBrokerEpoch, ServiceStartTicket{request.service_identity, request.expected_transition_generation + 1}},
            ServiceInstanceKey{kServiceProcess.identity, kServiceProcess.pid},
        };
    }
    return result;
}

ServiceLifecycleStopResult RequestStop(void* context, ServiceLifecycleBroker*, u64 service_identity,
                                       u64 expected_generation, u64)
{
    auto& fixture = *static_cast<Fixture*>(context);
    ++fixture.stop_calls;
    ServiceLifecycleStopResult result{fixture.stop_status, kInvalidServiceLifecycleInstanceToken,
                                      kInvalidServiceLifecycleStartTicket};
    if (fixture.stop_status == ServiceLifecycleStatus::KillRequired)
    {
        result.instance_to_kill = ServiceLifecycleInstanceToken{
            ServiceLifecycleStartTicket{kBrokerEpoch, ServiceStartTicket{service_identity, expected_generation}},
            ServiceInstanceKey{kServiceProcess.identity, kServiceProcess.pid},
        };
    }
    if (fixture.stop_status == ServiceLifecycleStatus::StartCancelled)
    {
        result.start_to_cancel =
            ServiceLifecycleStartTicket{kBrokerEpoch, ServiceStartTicket{service_identity, expected_generation}};
    }
    return result;
}

ServiceControlPlatformKillExactResultV1 KillExact(void* context, ProcessKey process)
{
    auto& fixture = *static_cast<Fixture*>(context);
    ++fixture.kill_calls;
    fixture.last_kill = process;
    return fixture.kill_status;
}

ServiceBootstrapStageStatus StageFind(void* context, const ServiceBootstrapStageRuntimeV1*, u64 service_identity,
                                      ServiceBootstrapServiceSnapshotV1* out)
{
    auto& fixture = *static_cast<Fixture*>(context);
    ++fixture.stage_calls;
    if (fixture.stage_status == ServiceBootstrapStageStatus::Ok && out != nullptr &&
        service_identity == fixture.staged_snapshot.service_identity)
    {
        *out = fixture.staged_snapshot;
    }
    return fixture.stage_status;
}

ServiceBootstrapLiveStatusV1 LiveInspect(void* context, ServiceBootstrapLiveSnapshotV1* out)
{
    auto& fixture = *static_cast<Fixture*>(context);
    ++fixture.live_inspect_calls;
    if (out != nullptr)
        *out = fixture.live_snapshot;
    return fixture.live_status;
}

ServiceBootstrapLiveRestageResultV1 LiveRestage(void* context, u64, u64 expected_generation,
                                                ServiceBootstrapLiveRetiredTargetTeardownV1 teardown)
{
    auto& fixture = *static_cast<Fixture*>(context);
    ++fixture.live_restage_calls;
    fixture.last_stage_generation = expected_generation;
    fixture.last_teardown = teardown;
    ServiceBootstrapLiveRestageResultV1 result{};
    result.status = fixture.live_restage_status;
    result.previous_active_bank = fixture.live_restage_previous_bank;
    result.active_bank = fixture.live_restage_active_bank;
    result.service_index = fixture.staged_snapshot.manifest_index;
    result.stage.status = fixture.live_restage_stage_status;
    result.stage.service_index = fixture.staged_snapshot.manifest_index;
    result.retired_image_status = loader::LoadImageStatus::Ok;
    result.retired_admission_status = loader::ExecAdmissionStatus::Ok;
    return result;
}

ServiceExitReapStatus LedgerInspect(void* context, ServiceExitReapLedger*, ServiceExitReapLedgerSnapshot* out)
{
    auto& fixture = *static_cast<Fixture*>(context);
    ++fixture.ledger_inspect_calls;
    if (fixture.ledger_status == ServiceExitReapStatus::Ok && out != nullptr)
        *out = fixture.ledger_snapshot;
    return fixture.ledger_status;
}

ServiceExitReapDeliveryResult ExitDequeue(void* context, ServiceExitReapLedger*, ProcessKey owner)
{
    auto& fixture = *static_cast<Fixture*>(context);
    ++fixture.dequeue_calls;
    fixture.last_delivery_owner_identity.store(owner.identity, std::memory_order_relaxed);
    fixture.last_delivery_owner_pid.store(owner.pid, std::memory_order_relaxed);
    return ServiceExitReapDeliveryResult{fixture.dequeue_status, fixture.delivery_record};
}

ServiceExitReapRestageResult RestageQueryExact(void* context, ServiceExitReapLedger*, ServiceExitReapEventKey event)
{
    auto& fixture = *static_cast<Fixture*>(context);
    ++fixture.restage_query_calls;
    fixture.last_restage_event = event;
    ServiceExitReapRestageResult result = fixture.restage_result;
    result.status = fixture.restage_query_status;
    return result;
}

ServiceExitReapStatus AcknowledgeExact(void* context, ServiceExitReapLedger*, ServiceExitReapEventKey event, u64 token,
                                       ProcessKey owner)
{
    auto& fixture = *static_cast<Fixture*>(context);
    ++fixture.acknowledge_calls;
    fixture.last_ack_event = event;
    fixture.last_ack_token = token;
    fixture.last_ack_owner = owner;
    return fixture.acknowledge_status;
}

ServiceControlIngressStatus InstallIngress(void* context, const ServiceControlIngressPlatformV1* platform)
{
    auto& fixture = *static_cast<Fixture*>(context);
    ++fixture.install_calls;
    if (platform != nullptr)
        fixture.installed = *platform;
    return fixture.install_status;
}

ServiceControlPlatformOperationsV1 Operations(Fixture& fixture)
{
    return ServiceControlPlatformOperationsV1{
        sizeof(ServiceControlPlatformOperationsV1),
        kServiceControlPlatformOperationsVersion1,
        &fixture,
        &MonotonicNs,
        &RuntimeInspect,
        &BindAuthority,
        &BrokerDescribe,
        &LifecycleInspect,
        &Activate,
        &RequestStop,
        &KillExact,
        &StageFind,
        &LiveInspect,
        &LiveRestage,
        &LedgerInspect,
        &ExitDequeue,
        &RestageQueryExact,
        &AcknowledgeExact,
        &InstallIngress,
        {0, 0},
    };
}

ServiceControlPlatformInitializeResultV1 Initialize(Fixture& fixture, ServiceControlPlatformAdapterV1& platform)
{
    const ServiceControlPlatformOperationsV1 operations = Operations(fixture);
    return ServiceControlPlatformInitializeForTestV1(&platform, fixture.runtime, fixture.ledger, &operations);
}

ServiceControlPlatformTargetV1 Target(u64 generation, ProcessKey process = kInvalidProcessKey, u64 sequence = 0)
{
    return ServiceControlPlatformTargetV1{kBrokerEpoch, kServiceIdentity, generation, process, sequence};
}

void ExpectCompleteTable(const Fixture& fixture)
{
    EXPECT_EQ(fixture.installed.struct_size, sizeof(ServiceControlIngressPlatformV1));
    EXPECT_EQ(fixture.installed.version, kServiceControlPlatformVersion1);
    EXPECT_TRUE(fixture.installed.context != nullptr);
    EXPECT_TRUE(fixture.installed.activate != nullptr);
    EXPECT_TRUE(fixture.installed.stop != nullptr);
    EXPECT_TRUE(fixture.installed.restage != nullptr);
    EXPECT_TRUE(fixture.installed.exit_dequeue != nullptr);
    EXPECT_TRUE(fixture.installed.exit_ack != nullptr);
    EXPECT_EQ(fixture.installed.reserved[0], 0ULL);
    EXPECT_EQ(fixture.installed.reserved[1], 0ULL);
}

void TestFailClosedInitialization()
{
    EXPECT_EQ(ServiceControlPlatformInitializeForTestV1(nullptr, nullptr, nullptr, nullptr).status,
              ServiceControlPlatformAdapterStatusV1::NullArgument);

    {
        Fixture fixture;
        ServiceControlPlatformAdapterV1 platform;
        auto operations = Operations(fixture);
        operations.exit_acknowledge_exact = nullptr;
        EXPECT_EQ(
            ServiceControlPlatformInitializeForTestV1(&platform, fixture.runtime, fixture.ledger, &operations).status,
            ServiceControlPlatformAdapterStatusV1::InvalidOperations);
        EXPECT_EQ(fixture.install_calls.load(), 0U);
        EXPECT_EQ(ServiceControlPlatformStateV1(&platform), ServiceControlPlatformAdapterStateV1::Failed);
    }
    {
        Fixture fixture;
        ServiceControlPlatformAdapterV1 platform;
        fixture.runtime_inspect_status = ServiceRuntimeStatusV1::NotInitialized;
        EXPECT_EQ(Initialize(fixture, platform).status, ServiceControlPlatformAdapterStatusV1::RuntimeNotReady);
        EXPECT_EQ(fixture.install_calls.load(), 0U);
    }
    {
        Fixture fixture;
        ServiceControlPlatformAdapterV1 platform;
        fixture.broker_snapshot.state = ServiceLifecycleBrokerState::Closed;
        EXPECT_EQ(Initialize(fixture, platform).status, ServiceControlPlatformAdapterStatusV1::BrokerNotReady);
        EXPECT_EQ(fixture.install_calls.load(), 0U);
    }
    {
        Fixture fixture;
        ServiceControlPlatformAdapterV1 platform;
        fixture.ledger_snapshot.state = ServiceExitReapLedgerState::Closed;
        EXPECT_EQ(Initialize(fixture, platform).status, ServiceControlPlatformAdapterStatusV1::LedgerNotReady);
        EXPECT_EQ(fixture.install_calls.load(), 0U);
    }
    {
        Fixture fixture;
        ServiceControlPlatformAdapterV1 platform;
        fixture.live_snapshot.activation_ready = 1;
        EXPECT_EQ(Initialize(fixture, platform).status, ServiceControlPlatformAdapterStatusV1::LiveBootstrapNotReady);
        EXPECT_EQ(fixture.install_calls.load(), 0U);
    }
    {
        Fixture fixture;
        ServiceControlPlatformAdapterV1 platform;
        fixture.install_status = ServiceControlIngressStatus::PlatformAlreadyInstalled;
        EXPECT_EQ(Initialize(fixture, platform).status, ServiceControlPlatformAdapterStatusV1::InstallRejected);
        EXPECT_EQ(ServiceControlPlatformStateV1(&platform), ServiceControlPlatformAdapterStateV1::Failed);
        ExpectCompleteTable(fixture);
        ServiceControlPlatformExitEventV1 event{};
        EXPECT_EQ(fixture.installed.exit_dequeue(fixture.installed.context, &fixture.authority, kSupervisorOne, &event),
                  ServiceControlPlatformStatusV1::NotReady);
        EXPECT_EQ(fixture.dequeue_calls.load(), 0U);
    }
    {
        Fixture fixture;
        ServiceControlPlatformAdapterV1 platform;
        EXPECT_EQ(Initialize(fixture, platform).status, ServiceControlPlatformAdapterStatusV1::Ok);
        ExpectCompleteTable(fixture);
        EXPECT_EQ(ServiceControlPlatformStateV1(&platform), ServiceControlPlatformAdapterStateV1::Open);
        EXPECT_EQ(fixture.activation_calls.load(), 0U);
        EXPECT_EQ(fixture.stop_calls.load(), 0U);
        EXPECT_EQ(fixture.live_restage_calls.load(), 0U);
        EXPECT_EQ(fixture.dequeue_calls.load(), 0U);
        EXPECT_EQ(fixture.acknowledge_calls.load(), 0U);
        EXPECT_EQ(Initialize(fixture, platform).status, ServiceControlPlatformAdapterStatusV1::AlreadyAttempted);
        EXPECT_EQ(fixture.install_calls.load(), 1U);
    }
}

void TestActivationAndStopAuthority()
{
    Fixture fixture;
    ServiceControlPlatformAdapterV1 platform;
    EXPECT_EQ(Initialize(fixture, platform).status, ServiceControlPlatformAdapterStatusV1::Ok);

    ServiceControlPlatformTargetV1 activate = Target(0);
    EXPECT_EQ(fixture.installed.activate(fixture.installed.context, &fixture.authority, kSupervisorOne, activate),
              ServiceControlPlatformStatusV1::Ok);
    EXPECT_EQ(fixture.activation_calls.load(), 1U);

    activate.broker_epoch++;
    EXPECT_EQ(fixture.installed.activate(fixture.installed.context, &fixture.authority, kSupervisorOne, activate),
              ServiceControlPlatformStatusV1::Stale);
    EXPECT_EQ(fixture.activation_calls.load(), 1U);

    fixture.lifecycle_snapshot.phase = ServiceTransitionPhase::Running;
    fixture.lifecycle_snapshot.transition_generation = 4;
    fixture.lifecycle_snapshot.instance = ServiceInstanceKey{kServiceProcess.identity, kServiceProcess.pid};
    ServiceControlPlatformTargetV1 stop = Target(4, kServiceProcess);
    EXPECT_EQ(fixture.installed.stop(fixture.installed.context, &fixture.authority, kSupervisorOne, stop),
              ServiceControlPlatformStatusV1::Ok);
    EXPECT_EQ(fixture.stop_calls.load(), 1U);
    EXPECT_EQ(fixture.kill_calls.load(), 1U);
    EXPECT_TRUE(fixture.last_kill == kServiceProcess);

    stop.process.pid++;
    EXPECT_EQ(fixture.installed.stop(fixture.installed.context, &fixture.authority, kSupervisorOne, stop),
              ServiceControlPlatformStatusV1::Stale);
    EXPECT_EQ(fixture.stop_calls.load(), 1U);

    fixture.lifecycle_snapshot.phase = ServiceTransitionPhase::Starting;
    fixture.lifecycle_snapshot.instance = kInvalidServiceInstanceKey;
    fixture.stop_status = ServiceLifecycleStatus::StartCancelled;
    stop = Target(4);
    EXPECT_EQ(fixture.installed.stop(fixture.installed.context, &fixture.authority, kSupervisorOne, stop),
              ServiceControlPlatformStatusV1::Ok);
    EXPECT_EQ(fixture.kill_calls.load(), 1U);
}

void TestMalformedBackendResultsFailClosed()
{
    Fixture fixture;
    ServiceControlPlatformAdapterV1 platform;
    EXPECT_EQ(Initialize(fixture, platform).status, ServiceControlPlatformAdapterStatusV1::Ok);

    const ServiceControlPlatformTargetV1 activate = Target(0);
    fixture.activation_status = ServiceBootstrapActivationStatusV1::RuntimeRejected;
    EXPECT_EQ(fixture.installed.activate(fixture.installed.context, &fixture.authority, kSupervisorOne, activate),
              ServiceControlPlatformStatusV1::CorruptState);
    fixture.activation_status = ServiceBootstrapActivationStatusV1::StageRejected;
    EXPECT_EQ(fixture.installed.activate(fixture.installed.context, &fixture.authority, kSupervisorOne, activate),
              ServiceControlPlatformStatusV1::CorruptState);
    fixture.activation_status = ServiceBootstrapActivationStatusV1::LifecyclePublicationRollbackFailed;
    EXPECT_EQ(fixture.installed.activate(fixture.installed.context, &fixture.authority, kSupervisorOne, activate),
              ServiceControlPlatformStatusV1::CorruptState);

    fixture.lifecycle_snapshot.phase = ServiceTransitionPhase::Running;
    fixture.lifecycle_snapshot.transition_generation = 4;
    fixture.lifecycle_snapshot.instance = ServiceInstanceKey{kServiceProcess.identity, kServiceProcess.pid};
    fixture.stop_status = ServiceLifecycleStatus::Ok;
    const ServiceControlPlatformTargetV1 stop = Target(4, kServiceProcess);
    EXPECT_EQ(fixture.installed.stop(fixture.installed.context, &fixture.authority, kSupervisorOne, stop),
              ServiceControlPlatformStatusV1::CorruptState);
    EXPECT_EQ(fixture.kill_calls.load(), 0U);

    fixture.lifecycle_snapshot.phase = ServiceTransitionPhase::Exited;
    const ServiceControlPlatformTargetV1 restage = Target(4, kServiceProcess, fixture.delivery_record.event_sequence);
    fixture.live_restage_status = ServiceBootstrapLiveRestageStatusV1::StageRejected;
    fixture.live_restage_stage_status = ServiceBootstrapStageStatus::Ok;
    EXPECT_EQ(fixture.installed.restage(fixture.installed.context, &fixture.authority, kSupervisorOne, restage),
              ServiceControlPlatformStatusV1::CorruptState);
    fixture.live_restage_status = ServiceBootstrapLiveRestageStatusV1::Ok;
    fixture.live_restage_active_bank = fixture.live_restage_previous_bank;
    EXPECT_EQ(fixture.installed.restage(fixture.installed.context, &fixture.authority, kSupervisorOne, restage),
              ServiceControlPlatformStatusV1::CorruptState);
}

void TestExactRestageGate()
{
    Fixture fixture;
    fixture.lifecycle_snapshot.phase = ServiceTransitionPhase::Exited;
    fixture.lifecycle_snapshot.transition_generation = 4;
    ServiceControlPlatformAdapterV1 platform;
    EXPECT_EQ(Initialize(fixture, platform).status, ServiceControlPlatformAdapterStatusV1::Ok);

    const ServiceControlPlatformTargetV1 target = Target(4, kServiceProcess, fixture.delivery_record.event_sequence);
    EXPECT_EQ(fixture.installed.restage(fixture.installed.context, &fixture.authority, kSupervisorOne, target),
              ServiceControlPlatformStatusV1::Ok);
    const ServiceExitReapEventKey expected_event{kBrokerEpoch, kServiceIdentity, 4, kServiceProcess,
                                                 fixture.delivery_record.event_sequence};
    EXPECT_TRUE(fixture.last_restage_event == expected_event);
    EXPECT_EQ(fixture.last_stage_generation, fixture.staged_snapshot.activation_generation);
    EXPECT_EQ(fixture.last_teardown, ServiceBootstrapLiveRetiredTargetTeardownV1::TeardownComplete);

    fixture.restage_query_status = ServiceExitReapStatus::StaleEvent;
    ServiceControlPlatformTargetV1 stale = target;
    stale.event_sequence++;
    EXPECT_EQ(fixture.installed.restage(fixture.installed.context, &fixture.authority, kSupervisorOne, stale),
              ServiceControlPlatformStatusV1::ReplayRejected);
    EXPECT_EQ(fixture.live_restage_calls.load(), 1U);

    fixture.restage_query_status = ServiceExitReapStatus::Ok;
    fixture.restage_result.eligible = 0;
    fixture.restage_result.blocking_rows = 1;
    EXPECT_EQ(fixture.installed.restage(fixture.installed.context, &fixture.authority, kSupervisorOne, target),
              ServiceControlPlatformStatusV1::Busy);
    EXPECT_EQ(fixture.live_restage_calls.load(), 1U);
}

void TestExitDeliveryAckAndRedelivery()
{
    Fixture fixture;
    ServiceControlPlatformAdapterV1 platform;
    EXPECT_EQ(Initialize(fixture, platform).status, ServiceControlPlatformAdapterStatusV1::Ok);

    ServiceControlPlatformExitEventV1 event{};
    EXPECT_EQ(fixture.installed.exit_dequeue(fixture.installed.context, &fixture.authority, kSupervisorOne, &event),
              ServiceControlPlatformStatusV1::Ok);
    EXPECT_EQ(event.instance.start.broker_epoch, fixture.delivery_record.broker_epoch);
    EXPECT_EQ(event.instance.start.transition.service_identity, fixture.delivery_record.service_identity);
    EXPECT_EQ(event.instance.start.transition.generation, fixture.delivery_record.generation);
    EXPECT_EQ(event.event_sequence, fixture.delivery_record.event_sequence);
    EXPECT_EQ(event.acknowledgement_token, fixture.delivery_record.delivery_token);
    EXPECT_EQ(event.exit_status, static_cast<i64>(fixture.delivery_record.exit_code));
    EXPECT_TRUE(event.failed);
    EXPECT_EQ(fixture.last_delivery_owner_identity.load(std::memory_order_relaxed), kSupervisorOne.identity);
    EXPECT_EQ(fixture.last_delivery_owner_pid.load(std::memory_order_relaxed), kSupervisorOne.pid);

    // Simulate owner-exit requeue in the ledger: redelivery keeps the exact
    // event sequence and public token while leasing to a new serviced Process.
    ServiceControlPlatformExitEventV1 redelivered{};
    EXPECT_EQ(
        fixture.installed.exit_dequeue(fixture.installed.context, &fixture.authority, kSupervisorTwo, &redelivered),
        ServiceControlPlatformStatusV1::Ok);
    EXPECT_EQ(redelivered.event_sequence, event.event_sequence);
    EXPECT_EQ(redelivered.acknowledgement_token, event.acknowledgement_token);

    ServiceControlPlatformTargetV1 ack_target = Target(
        fixture.delivery_record.generation, fixture.delivery_record.process, fixture.delivery_record.event_sequence);
    fixture.acknowledge_status = ServiceExitReapStatus::ForeignAcknowledger;
    EXPECT_EQ(fixture.installed.exit_ack(fixture.installed.context, &fixture.authority, kSupervisorOne, ack_target,
                                         fixture.delivery_record.delivery_token),
              ServiceControlPlatformStatusV1::ReplayRejected);
    fixture.acknowledge_status = ServiceExitReapStatus::Ok;
    EXPECT_EQ(fixture.installed.exit_ack(fixture.installed.context, &fixture.authority, kSupervisorTwo, ack_target,
                                         fixture.delivery_record.delivery_token),
              ServiceControlPlatformStatusV1::Ok);
    const ServiceExitReapEventKey expected_event{kBrokerEpoch, kServiceIdentity, 4, kServiceProcess,
                                                 fixture.delivery_record.event_sequence};
    EXPECT_TRUE(fixture.last_ack_event == expected_event);
    EXPECT_EQ(fixture.last_ack_token, fixture.delivery_record.delivery_token);
    EXPECT_TRUE(fixture.last_ack_owner == kSupervisorTwo);

    fixture.dequeue_status = ServiceExitReapStatus::NoEvent;
    EXPECT_EQ(fixture.installed.exit_dequeue(fixture.installed.context, &fixture.authority, kSupervisorTwo, &event),
              ServiceControlPlatformStatusV1::WouldBlock);
}

void TestConcurrentCallbacksAndFreshAuthority()
{
    Fixture fixture;
    ServiceControlPlatformAdapterV1 platform;
    EXPECT_EQ(Initialize(fixture, platform).status, ServiceControlPlatformAdapterStatusV1::Ok);

    constexpr u32 kThreads = 8;
    std::atomic<u32> successes{0};
    std::vector<std::thread> workers;
    workers.reserve(kThreads);
    for (u32 index = 0; index < kThreads; ++index)
    {
        workers.emplace_back(
            [&]
            {
                ServiceControlPlatformExitEventV1 event{};
                if (fixture.installed.exit_dequeue(fixture.installed.context, &fixture.authority, kSupervisorOne,
                                                   &event) == ServiceControlPlatformStatusV1::Ok &&
                    event.event_sequence == fixture.delivery_record.event_sequence)
                {
                    ++successes;
                }
            });
    }
    for (auto& worker : workers)
        worker.join();
    EXPECT_EQ(successes.load(), kThreads);
    EXPECT_EQ(fixture.dequeue_calls.load(), kThreads);

    ServiceRuntimeActivationAuthorityV1 forged = fixture.authority;
    forged.stage_registry_identity++;
    ServiceControlPlatformExitEventV1 event{};
    EXPECT_EQ(fixture.installed.exit_dequeue(fixture.installed.context, &forged, kSupervisorOne, &event),
              ServiceControlPlatformStatusV1::CorruptState);
    EXPECT_EQ(fixture.dequeue_calls.load(), kThreads);
}

} // namespace

int main()
{
    TestFailClosedInitialization();
    TestActivationAndStopAuthority();
    TestMalformedBackendResultsFailClosed();
    TestExactRestageGate();
    TestExitDeliveryAckAndRedelivery();
    TestConcurrentCallbacksAndFreshAuthority();

    EXPECT_TRUE(
        std::strcmp(ServiceControlPlatformAdapterStatusNameV1(ServiceControlPlatformAdapterStatusV1::Ok), "ok") == 0);
    if (g_failures != 0)
    {
        std::cerr << "service-control platform tests failed: " << g_failures << '\n';
        return 1;
    }
    std::cout << "service-control platform tests passed\n";
    return 0;
}
