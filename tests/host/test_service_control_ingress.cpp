#include "syscall/service_control_ingress.h"

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>

using namespace duetos;
using namespace duetos::core;

namespace
{

[[noreturn]] void Fail(const char* expression, int line)
{
    std::fprintf(stderr, "FAIL line %d: %s\n", line, expression);
    std::exit(1);
}

#define EXPECT_TRUE(expr)                                                                                              \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(expr))                                                                                                   \
            Fail(#expr, __LINE__);                                                                                     \
    } while (0)
#define EXPECT_EQ(lhs, rhs) EXPECT_TRUE((lhs) == (rhs))

alignas(ServiceRuntimeV1) unsigned char g_runtime_storage[sizeof(ServiceRuntimeV1)]{};
alignas(ServiceLifecycleBroker) unsigned char g_broker_storage[sizeof(ServiceLifecycleBroker)]{};
alignas(ServiceDirectory) unsigned char g_directory_storage[sizeof(ServiceDirectory)]{};
ServiceBootstrapStageRuntimeV1 g_stage{};

ServiceRuntimeV1* Runtime()
{
    return reinterpret_cast<ServiceRuntimeV1*>(g_runtime_storage);
}

ServiceLifecycleBroker* Broker()
{
    return reinterpret_cast<ServiceLifecycleBroker*>(g_broker_storage);
}

ServiceDirectory* Directory()
{
    return reinterpret_cast<ServiceDirectory*>(g_directory_storage);
}

struct Model
{
    static constexpr u32 kRows = 3;
    u64 broker_epoch = 0xA11CE;
    ServiceLifecycleSnapshot rows[kRows]{};
    u32 mark_ready_calls = 0;
    u32 directory_lookup_calls = 0;
    u32 directory_release_calls = 0;
    u32 activate_calls = 0;
    u32 stop_calls = 0;
    u32 restage_calls = 0;
    u32 dequeue_calls = 0;
    u32 ack_calls = 0;
    bool callback_saw_unlocked_ingress = false;
    bool emit_corrupt_event = false;
    ServiceControlIngressState* ingress = nullptr;
    ServiceControlPlatformTargetV1 last_target{};
    ProcessKey last_supervisor{};
} g_model;

void ResetModel()
{
    g_model = {};
    g_model.broker_epoch = 0xA11CE;
    g_model.rows[0] = ServiceLifecycleSnapshot{
        0x100, ServiceTransitionPhase::Running,    3,     ServiceInstanceKey{0x10001, 101}, 0, 10, 1, 0, 0,
        0,     ServiceLifecycleBuilderState::None, false,
    };
    g_model.rows[1] = ServiceLifecycleSnapshot{
        0x200, ServiceTransitionPhase::Stopped,    0,     kInvalidServiceInstanceKey, 1, 20, 0, 0, 0,
        0,     ServiceLifecycleBuilderState::None, false,
    };
    g_model.rows[2] = ServiceLifecycleSnapshot{
        0x300, ServiceTransitionPhase::Exited,     4,     kInvalidServiceInstanceKey, 2, 30, 1, 0, 1,
        1,     ServiceLifecycleBuilderState::None, false,
    };

    g_stage.package.manifest_plan.document.service_count = Model::kRows;
    static constexpr const char* kNames[Model::kRows] = {"serviced", "execd", "displayd"};
    for (u32 index = 0; index < Model::kRows; ++index)
    {
        auto& service = g_stage.package.manifest_plan.document.services[index];
        service = {};
        service.service_identity = g_model.rows[index].service_identity;
        service.name_length = static_cast<u8>(std::strlen(kNames[index]));
        std::memcpy(service.name, kNames[index], service.name_length);
    }
}

duet_service_control_request_v1 Request(u16 operation)
{
    duet_service_control_request_v1 request{};
    request.struct_size = sizeof(request);
    request.version = DUET_SERVICE_CONTROL_ABI_VERSION;
    request.operation = operation;
    return request;
}

ServiceControlIngressCaller Caller(ProcessKey process, bool supervisor)
{
    CapSet capabilities = CapSetEmpty();
    if (supervisor)
        CapSetAdd(capabilities, kCapServiceControl);
    return ServiceControlIngressCaller{process, capabilities, Runtime()};
}

void BindRequestToRow(duet_service_control_request_v1* request, u32 index, ProcessKey process)
{
    request->broker_epoch = g_model.broker_epoch;
    request->service_identity = g_model.rows[index].service_identity;
    request->transition_generation = g_model.rows[index].transition_generation;
    request->process_identity = process.identity;
    request->pid = process.pid;
}

ServiceControlIngressPlatformV1 Platform();

} // namespace

namespace duetos::core
{

ServiceRuntimeStatusV1 ServiceRuntimeBindActivationAuthorityV1(ServiceRuntimeV1* runtime,
                                                               ServiceRuntimeActivationAuthorityV1* authority_out)
{
    if (runtime != Runtime() || authority_out == nullptr)
        return ServiceRuntimeStatusV1::NullArgument;
    *authority_out = {};
    authority_out->stage = &g_stage;
    authority_out->lifecycle = Broker();
    authority_out->directory = Directory();
    authority_out->manifest_identity = 0xD00D;
    authority_out->manifest_authority_identity = 0xA07;
    authority_out->stage_registry_identity = 0x5157;
    return ServiceRuntimeStatusV1::Ok;
}

ServiceLifecycleBrokerInspectResult ServiceLifecycleBrokerDescribe(ServiceLifecycleBroker* broker)
{
    if (broker != Broker())
        return {ServiceLifecycleStatus::NullArgument, {}};
    ServiceLifecycleBrokerSnapshot snapshot{};
    snapshot.state = ServiceLifecycleBrokerState::Open;
    snapshot.service_count = Model::kRows;
    snapshot.broker_epoch = g_model.broker_epoch;
    return {ServiceLifecycleStatus::Ok, snapshot};
}

ServiceLifecycleInspectResult ServiceLifecycleBrokerInspectAt(ServiceLifecycleBroker* broker, u32 index)
{
    if (broker != Broker())
        return {ServiceLifecycleStatus::NullArgument, {}};
    if (index >= Model::kRows)
        return {ServiceLifecycleStatus::NotFound, {}};
    return {ServiceLifecycleStatus::Ok, g_model.rows[index]};
}

bool ServiceDirectoryNameIsCanonical(const ServiceDirectoryName& name)
{
    return name.length != 0 && name.length <= kServiceDirectoryNameCapacity;
}

ServiceDirectoryLookupResult ServiceDirectoryLookup(ServiceDirectory* directory, const ServiceDirectoryName* name)
{
    ++g_model.directory_lookup_calls;
    if (directory != Directory() || name == nullptr || !ServiceDirectoryNameIsCanonical(*name))
        return {ServiceDirectoryStatus::InvalidArgument, kInvalidServiceDirectoryOperationPin};
    return {ServiceDirectoryStatus::Ok, ServiceDirectoryOperationPin{ServiceKey{0, 9}, 0, 1}};
}

ServiceDirectoryStatus ServiceDirectoryReleaseOperation(ServiceDirectory* directory, ServiceDirectoryOperationPin* pin)
{
    ++g_model.directory_release_calls;
    if (directory != Directory() || pin == nullptr || !ServiceDirectoryOperationPinIsValid(*pin))
        return ServiceDirectoryStatus::InvalidArgument;
    *pin = kInvalidServiceDirectoryOperationPin;
    return ServiceDirectoryStatus::Ok;
}

ServiceLifecycleDirectoryReadyResult ServiceLifecycleBrokerMarkReady(ServiceLifecycleBroker* broker,
                                                                     ServiceLifecycleInstanceToken instance,
                                                                     ServiceDirectory* directory, ServiceKey service)
{
    ++g_model.mark_ready_calls;
    if (broker != Broker() || directory != Directory() || !ServiceKeyIsValid(service) ||
        instance.start.broker_epoch != g_model.broker_epoch ||
        instance.start.transition.service_identity != g_model.rows[0].service_identity ||
        instance.start.transition.generation != g_model.rows[0].transition_generation ||
        instance.process != g_model.rows[0].instance)
    {
        return {ServiceLifecycleStatus::StaleGeneration, ServiceDirectoryStatus::StaleKey};
    }
    g_model.rows[0].ready = true;
    return {ServiceLifecycleStatus::Ok, ServiceDirectoryStatus::Ok};
}

} // namespace duetos::core

namespace
{

ServiceControlPlatformStatusV1 Activate(void*, const ServiceRuntimeActivationAuthorityV1* authority,
                                        ProcessKey supervisor, ServiceControlPlatformTargetV1 target)
{
    ++g_model.activate_calls;
    g_model.last_target = target;
    g_model.last_supervisor = supervisor;
    if (authority == nullptr || authority->lifecycle != Broker())
        return ServiceControlPlatformStatusV1::CorruptState;
    if (g_model.ingress != nullptr && g_model.ingress->lock.try_lock())
    {
        g_model.callback_saw_unlocked_ingress = true;
        g_model.ingress->lock.unlock();
    }
    g_model.rows[1].phase = ServiceTransitionPhase::Starting;
    g_model.rows[1].transition_generation = 1;
    return ServiceControlPlatformStatusV1::Ok;
}

ServiceControlPlatformStatusV1 Stop(void*, const ServiceRuntimeActivationAuthorityV1*, ProcessKey supervisor,
                                    ServiceControlPlatformTargetV1 target)
{
    ++g_model.stop_calls;
    g_model.last_target = target;
    g_model.last_supervisor = supervisor;
    g_model.rows[0].phase = ServiceTransitionPhase::Stopping;
    return ServiceControlPlatformStatusV1::Ok;
}

ServiceControlPlatformStatusV1 Restage(void*, const ServiceRuntimeActivationAuthorityV1*, ProcessKey supervisor,
                                       ServiceControlPlatformTargetV1 target)
{
    ++g_model.restage_calls;
    g_model.last_target = target;
    g_model.last_supervisor = supervisor;
    return g_model.restage_calls == 1 ? ServiceControlPlatformStatusV1::Busy : ServiceControlPlatformStatusV1::Ok;
}

ServiceControlPlatformStatusV1 ExitDequeue(void*, const ServiceRuntimeActivationAuthorityV1*, ProcessKey,
                                           ServiceControlPlatformExitEventV1* event_out)
{
    ++g_model.dequeue_calls;
    if (g_model.dequeue_calls == 1)
        return ServiceControlPlatformStatusV1::WouldBlock;
    *event_out = {};
    event_out->instance = ServiceLifecycleInstanceToken{
        ServiceLifecycleStartTicket{g_model.broker_epoch, ServiceStartTicket{0x300, 4}},
        ServiceInstanceKey{0x30003, 303},
    };
    event_out->event_sequence = 0xEE01;
    event_out->acknowledgement_token = 0xAC01;
    event_out->exit_status = -7;
    event_out->failed = true;
    if (g_model.emit_corrupt_event)
        event_out->reserved[2] = 1;
    return ServiceControlPlatformStatusV1::Ok;
}

ServiceControlPlatformStatusV1 ExitAck(void*, const ServiceRuntimeActivationAuthorityV1*, ProcessKey supervisor,
                                       ServiceControlPlatformTargetV1 target, u64 token)
{
    ++g_model.ack_calls;
    g_model.last_target = target;
    g_model.last_supervisor = supervisor;
    if (token != 0xAC01)
        return ServiceControlPlatformStatusV1::Stale;
    if (g_model.ack_calls == 1)
        return ServiceControlPlatformStatusV1::Busy;
    if (g_model.ack_calls == 2)
        return ServiceControlPlatformStatusV1::Ok;
    return ServiceControlPlatformStatusV1::ReplayRejected;
}

ServiceControlIngressPlatformV1 Platform()
{
    ServiceControlIngressPlatformV1 platform{};
    platform.struct_size = sizeof(platform);
    platform.version = kServiceControlPlatformVersion1;
    platform.activate = Activate;
    platform.stop = Stop;
    platform.restage = Restage;
    platform.exit_dequeue = ExitDequeue;
    platform.exit_ack = ExitAck;
    return platform;
}

void ExpectStructured(ServiceControlIngressState& state, const ServiceControlIngressCaller& caller,
                      const duet_service_control_request_v1& request, i32 expected)
{
    duet_service_control_result_v1 result{};
    EXPECT_EQ(ServiceControlIngressExecute(&state, &caller, &request, &result), ServiceControlIngressStatus::Ok);
    EXPECT_EQ(result.struct_size, sizeof(result));
    EXPECT_EQ(result.version, DUET_SERVICE_CONTROL_ABI_VERSION);
    EXPECT_EQ(result.operation, request.operation);
    EXPECT_EQ(result.status, expected);
    EXPECT_EQ(result.reserved8, 0);
    EXPECT_EQ(result.reserved32, 0U);
    EXPECT_EQ(result.reserved[0], 0ULL);
    EXPECT_EQ(result.reserved[1], 0ULL);
}

void TestValidationAndAuthorization()
{
    ResetModel();
    ServiceControlIngressState state{};
    EXPECT_EQ(ServiceControlIngressInitialize(&state), ServiceControlIngressStatus::Ok);
    EXPECT_EQ(ServiceControlIngressInitialize(&state), ServiceControlIngressStatus::AlreadyInitialized);

    const ServiceControlIngressCaller self = Caller(ProcessKey{0x10001, 101}, false);
    const ServiceControlIngressCaller outsider = Caller(ProcessKey{0x99999, 999}, false);
    const ServiceControlIngressCaller supervisor = Caller(ProcessKey{0x51000, 51}, true);
    duet_service_control_request_v1 request = Request(DUET_SERVICE_CONTROL_OP_DESCRIBE_SELF);
    duet_service_control_result_v1 result{};
    EXPECT_EQ(ServiceControlIngressExecute(&state, &self, &request, &result), ServiceControlIngressStatus::Ok);
    EXPECT_EQ(result.status, DUET_SERVICE_CONTROL_STATUS_OK);
    EXPECT_EQ(result.service_identity, 0x100ULL);
    EXPECT_EQ(result.process_identity, self.process.identity);
    EXPECT_EQ(result.flags, DUET_SERVICE_CONTROL_RESULT_HAS_SERVICE);

    ExpectStructured(state, outsider, request, DUET_SERVICE_CONTROL_STATUS_ACCESS_DENIED);

    request.version = 99;
    ExpectStructured(state, self, request, DUET_SERVICE_CONTROL_STATUS_BAD_VERSION);
    request = Request(DUET_SERVICE_CONTROL_OP_DESCRIBE_SELF);
    request.struct_size = sizeof(request) - 1;
    ExpectStructured(state, self, request, DUET_SERVICE_CONTROL_STATUS_INVALID_ARGUMENT);
    request = Request(DUET_SERVICE_CONTROL_OP_DESCRIBE_SELF);
    request.flags = 1;
    ExpectStructured(state, self, request, DUET_SERVICE_CONTROL_STATUS_INVALID_ARGUMENT);
    request = Request(DUET_SERVICE_CONTROL_OP_DESCRIBE_SELF);
    request.reserved[0] = 1;
    ExpectStructured(state, self, request, DUET_SERVICE_CONTROL_STATUS_INVALID_ARGUMENT);
    request = Request(DUET_SERVICE_CONTROL_OP_DESCRIBE_SELF);
    request.reserved[1] = 1;
    ExpectStructured(state, self, request, DUET_SERVICE_CONTROL_STATUS_INVALID_ARGUMENT);
    request = Request(99);
    ExpectStructured(state, self, request, DUET_SERVICE_CONTROL_STATUS_UNSUPPORTED);

    request = Request(DUET_SERVICE_CONTROL_OP_ENUMERATE);
    ExpectStructured(state, self, request, DUET_SERVICE_CONTROL_STATUS_ACCESS_DENIED);
    request.flags = 1U << static_cast<u32>(kCapServiceControl);
    ExpectStructured(state, self, request, DUET_SERVICE_CONTROL_STATUS_INVALID_ARGUMENT);
    request = Request(DUET_SERVICE_CONTROL_OP_ENUMERATE);
    ExpectStructured(state, supervisor, request, DUET_SERVICE_CONTROL_STATUS_OK);
    request.broker_epoch = g_model.broker_epoch + 1;
    ExpectStructured(state, supervisor, request, DUET_SERVICE_CONTROL_STATUS_STALE);
    request = Request(DUET_SERVICE_CONTROL_OP_ENUMERATE);
    request.service_index = Model::kRows;
    ExpectStructured(state, supervisor, request, DUET_SERVICE_CONTROL_STATUS_NOT_FOUND);

    request = Request(DUET_SERVICE_CONTROL_OP_ACTIVATE);
    BindRequestToRow(&request, 1, kInvalidProcessKey);
    ExpectStructured(state, supervisor, request, DUET_SERVICE_CONTROL_STATUS_NOT_READY);
}

void TestAliasAndAtomicReady()
{
    ResetModel();
    ServiceControlIngressState state{};
    EXPECT_EQ(ServiceControlIngressInitialize(&state), ServiceControlIngressStatus::Ok);
    const ServiceControlIngressCaller self = Caller(ProcessKey{0x10001, 101}, false);

    union Alias
    {
        duet_service_control_request_v1 request;
        duet_service_control_result_v1 result;
    } alias{};
    alias.request = Request(DUET_SERVICE_CONTROL_OP_DESCRIBE_SELF);
    EXPECT_EQ(ServiceControlIngressExecute(&state, &self, &alias.request, &alias.result),
              ServiceControlIngressStatus::Ok);
    EXPECT_EQ(alias.result.status, DUET_SERVICE_CONTROL_STATUS_OK);
    EXPECT_EQ(alias.result.service_identity, 0x100ULL);

    duet_service_control_request_v1 ready = Request(DUET_SERVICE_CONTROL_OP_MARK_READY);
    BindRequestToRow(&ready, 0, self.process);
    duet_service_control_result_v1 result{};
    EXPECT_EQ(ServiceControlIngressExecute(&state, &self, &ready, &result), ServiceControlIngressStatus::Ok);
    EXPECT_EQ(result.status, DUET_SERVICE_CONTROL_STATUS_OK);
    EXPECT_EQ(g_model.mark_ready_calls, 1U);
    EXPECT_EQ(g_model.directory_lookup_calls, 1U);
    EXPECT_EQ(g_model.directory_release_calls, 1U);
    EXPECT_EQ(result.ready, 1U);
    EXPECT_TRUE((result.flags & DUET_SERVICE_CONTROL_RESULT_SERVICE_READY) != 0);

    ready.transition_generation--;
    ExpectStructured(state, self, ready, DUET_SERVICE_CONTROL_STATUS_STALE);
    EXPECT_EQ(g_model.mark_ready_calls, 1U);
    ready.transition_generation++;
    ready.process_identity++;
    ExpectStructured(state, self, ready, DUET_SERVICE_CONTROL_STATUS_STALE);
    EXPECT_EQ(g_model.mark_ready_calls, 1U);
}

void TestPlatformAndExactMutations()
{
    ResetModel();
    ServiceControlIngressState state{};
    EXPECT_EQ(ServiceControlIngressInitialize(&state), ServiceControlIngressStatus::Ok);
    g_model.ingress = &state;
    ServiceControlIngressPlatformV1 platform = Platform();
    EXPECT_EQ(ServiceControlIngressInstallPlatformV1(&state, &platform), ServiceControlIngressStatus::Ok);
    EXPECT_EQ(ServiceControlIngressInstallPlatformV1(&state, &platform),
              ServiceControlIngressStatus::PlatformAlreadyInstalled);
    const ServiceControlIngressCaller supervisor = Caller(ProcessKey{0x51000, 51}, true);

    duet_service_control_request_v1 activate = Request(DUET_SERVICE_CONTROL_OP_ACTIVATE);
    BindRequestToRow(&activate, 1, kInvalidProcessKey);
    duet_service_control_result_v1 result{};
    EXPECT_EQ(ServiceControlIngressExecute(&state, &supervisor, &activate, &result), ServiceControlIngressStatus::Ok);
    EXPECT_EQ(result.status, DUET_SERVICE_CONTROL_STATUS_OK);
    EXPECT_EQ(g_model.activate_calls, 1U);
    EXPECT_TRUE(g_model.callback_saw_unlocked_ingress);
    EXPECT_EQ(g_model.last_target.transition_generation, 0ULL);
    EXPECT_EQ(result.transition_generation, 1ULL);

    g_model.rows[1].phase = ServiceTransitionPhase::Stopped;
    g_model.rows[1].transition_generation = kServiceTransitionGenerationMaximum;
    activate.transition_generation = kServiceTransitionGenerationMaximum;
    ExpectStructured(state, supervisor, activate, DUET_SERVICE_CONTROL_STATUS_GENERATION_EXHAUSTED);
    EXPECT_EQ(g_model.activate_calls, 1U);

    duet_service_control_request_v1 stop = Request(DUET_SERVICE_CONTROL_OP_STOP);
    BindRequestToRow(&stop, 0, ProcessKey{0x10001, 101});
    stop.process_identity++;
    ExpectStructured(state, supervisor, stop, DUET_SERVICE_CONTROL_STATUS_STALE);
    EXPECT_EQ(g_model.stop_calls, 0U);
    stop.process_identity--;
    EXPECT_EQ(ServiceControlIngressExecute(&state, &supervisor, &stop, &result), ServiceControlIngressStatus::Ok);
    EXPECT_EQ(result.status, DUET_SERVICE_CONTROL_STATUS_OK);
    EXPECT_EQ(g_model.stop_calls, 1U);
    EXPECT_EQ(g_model.last_target.process.identity, 0x10001ULL);

    duet_service_control_request_v1 restage = Request(DUET_SERVICE_CONTROL_OP_RESTAGE);
    BindRequestToRow(&restage, 2, ProcessKey{0x30003, 303});
    restage.operation_token = 0xEE01;
    EXPECT_EQ(ServiceControlIngressExecute(&state, &supervisor, &restage, &result), ServiceControlIngressStatus::Ok);
    EXPECT_EQ(result.status, DUET_SERVICE_CONTROL_STATUS_BUSY);
    EXPECT_EQ(g_model.last_target.event_sequence, 0xEE01ULL);
    EXPECT_EQ(ServiceControlIngressExecute(&state, &supervisor, &restage, &result), ServiceControlIngressStatus::Ok);
    EXPECT_EQ(result.status, DUET_SERVICE_CONTROL_STATUS_OK);
    EXPECT_EQ(g_model.restage_calls, 2U);
}

void TestExitDeliveryAndAckReplay()
{
    ResetModel();
    ServiceControlIngressState state{};
    EXPECT_EQ(ServiceControlIngressInitialize(&state), ServiceControlIngressStatus::Ok);
    ServiceControlIngressPlatformV1 platform = Platform();
    EXPECT_EQ(ServiceControlIngressInstallPlatformV1(&state, &platform), ServiceControlIngressStatus::Ok);
    const ServiceControlIngressCaller supervisor = Caller(ProcessKey{0x51000, 51}, true);

    duet_service_control_request_v1 dequeue = Request(DUET_SERVICE_CONTROL_OP_EXIT_DEQUEUE);
    duet_service_control_result_v1 result{};
    EXPECT_EQ(ServiceControlIngressExecute(&state, &supervisor, &dequeue, &result), ServiceControlIngressStatus::Ok);
    EXPECT_EQ(result.status, DUET_SERVICE_CONTROL_STATUS_WOULD_BLOCK);
    EXPECT_EQ(ServiceControlIngressExecute(&state, &supervisor, &dequeue, &result), ServiceControlIngressStatus::Ok);
    EXPECT_EQ(result.status, DUET_SERVICE_CONTROL_STATUS_OK);
    EXPECT_EQ(result.service_identity, 0x300ULL);
    EXPECT_EQ(result.transition_generation, 4ULL);
    EXPECT_EQ(result.process_identity, 0x30003ULL);
    EXPECT_EQ(result.event_sequence, 0xEE01ULL);
    EXPECT_EQ(result.operation_token, 0xAC01ULL);
    EXPECT_EQ(result.exit_status, -7);
    EXPECT_TRUE((result.flags & DUET_SERVICE_CONTROL_RESULT_HAS_EXIT_EVENT) != 0);
    EXPECT_TRUE((result.flags & DUET_SERVICE_CONTROL_RESULT_EXIT_FAILED) != 0);

    duet_service_control_request_v1 ack = Request(DUET_SERVICE_CONTROL_OP_EXIT_ACK);
    ack.broker_epoch = result.broker_epoch;
    ack.service_identity = result.service_identity;
    ack.transition_generation = result.transition_generation;
    ack.process_identity = result.process_identity;
    ack.pid = result.pid;
    ack.operation_token = result.operation_token;
    ExpectStructured(state, supervisor, ack, DUET_SERVICE_CONTROL_STATUS_BUSY);
    ExpectStructured(state, supervisor, ack, DUET_SERVICE_CONTROL_STATUS_OK);
    ExpectStructured(state, supervisor, ack, DUET_SERVICE_CONTROL_STATUS_REPLAY_REJECTED);
    EXPECT_EQ(g_model.ack_calls, 3U);

    ack.pid++;
    ExpectStructured(state, supervisor, ack, DUET_SERVICE_CONTROL_STATUS_REPLAY_REJECTED);

    g_model.emit_corrupt_event = true;
    EXPECT_EQ(ServiceControlIngressExecute(&state, &supervisor, &dequeue, &result), ServiceControlIngressStatus::Ok);
    EXPECT_EQ(result.status, DUET_SERVICE_CONTROL_STATUS_CORRUPT_STATE);
}

} // namespace

int main()
{
    TestValidationAndAuthorization();
    TestAliasAndAtomicReady();
    TestPlatformAndExactMutations();
    TestExitDeliveryAndAckReplay();
    std::puts("service-control ingress: PASS");
    return 0;
}
