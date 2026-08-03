// Hosted hostile-input, process-binding, replay, reply, and typed-handle
// transfer coverage for syscall/service_endpoint_ingress.{h,cpp}.

#include "host_test_helper.h"

#include "core/service_protocol_policy.h"
#include "core/serviced_protocol.h"
#include "ipc/kmessage_port.h"
#include "ipc/message_abi.h"
#include "ipc/versioned_payload.h"
#include "syscall/service_endpoint_ingress.h"

#include <array>
#include <cstdlib>
#include <mutex>
#include <new>

// Exercise the authoritative ChannelCore resource charge in this focused host
// target without adding a production source-file dependency to the kernel.
#include "proc/resource_domain.cpp"

namespace
{

std::mutex g_host_spinlock;
std::mutex g_object_lock;

} // namespace

namespace duetos::core
{

bool g_runtime_bind_enabled = false;
u32 g_directory_lookup_calls = 0;
u32 g_directory_connect_calls = 0;
u32 g_directory_drain_calls = 0;
u32 g_directory_drain_busy_remaining = 0;
ServiceDirectoryLookupResult g_directory_lookup_result{ServiceDirectoryStatus::NotFound,
                                                       kInvalidServiceDirectoryOperationPin};
ServiceDirectoryInspectResult g_directory_inspect_result{ServiceDirectoryStatus::NotFound, {}};
ServiceDirectoryConnectResult g_directory_connect_result{
    ServiceDirectoryStatus::NotInitialized, ServiceEndpointStatus::Ok, ErrorCode::Ok, ipc::kHandleInvalid, {}, {}};
ServiceEndpointProtocolAuthority g_last_connect_protocol{};
ServiceDirectory* g_last_connect_directory = nullptr;

ServiceLifecycleBroker::ServiceLifecycleBroker() {}
ServiceExitObserver::ServiceExitObserver() {}
ServiceExitReapLedger::ServiceExitReapLedger() {}

[[noreturn]] void Panic(const char*, const char*)
{
    std::abort();
}

[[noreturn]] void PanicWithValue(const char*, const char*, u64)
{
    std::abort();
}

// Accept and directory-owned close are deliberately outside this focused
// fixture. These exact-signature stubs satisfy the host link while all tested
// operations execute the production endpoint/channel/transfer path.
ServiceRuntimeStatusV1 ServiceRuntimeInspectV1(const ServiceRuntimeV1*, ServiceRuntimeSnapshotV1*)
{
    return ServiceRuntimeStatusV1::NotInitialized;
}

ServiceRuntimeStatusV1 ServiceRuntimeBindActivationAuthorityV1(ServiceRuntimeV1* runtime,
                                                               ServiceRuntimeActivationAuthorityV1* authority)
{
    if (!g_runtime_bind_enabled || runtime == nullptr || runtime->stage == nullptr || authority == nullptr)
        return ServiceRuntimeStatusV1::NotInitialized;
    *authority = {};
    authority->stage = runtime->stage;
    authority->directory = &runtime->directory;
    return ServiceRuntimeStatusV1::Ok;
}

ServiceLifecycleBrokerInspectResult ServiceLifecycleBrokerDescribe(ServiceLifecycleBroker*)
{
    return {};
}

ServiceLifecycleInspectResult ServiceLifecycleBrokerInspectAt(ServiceLifecycleBroker*, u32)
{
    return {};
}

bool ServiceDirectoryNameIsCanonical(const ServiceDirectoryName& name)
{
    return name.length != 0 && name.length <= kServiceDirectoryNameCapacity && name.bytes[0] != 0;
}

ServiceDirectoryLookupResult ServiceDirectoryLookup(ServiceDirectory*, const ServiceDirectoryName*)
{
    ++g_directory_lookup_calls;
    return g_directory_lookup_result;
}

ServiceDirectoryStatus ServiceDirectoryReleaseOperation(ServiceDirectory*, ServiceDirectoryOperationPin* pin)
{
    if (pin == nullptr || !ServiceDirectoryOperationPinIsValid(*pin))
        return ServiceDirectoryStatus::InvalidArgument;
    *pin = kInvalidServiceDirectoryOperationPin;
    return ServiceDirectoryStatus::Ok;
}

ServiceDirectoryInspectResult ServiceDirectoryInspectExact(ServiceDirectory*, ServiceKey)
{
    return g_directory_inspect_result;
}

ServiceDirectoryConnectResult ServiceDirectoryConnect(ServiceDirectory* directory, ServiceDirectoryOperationPin,
                                                      ResourceDomainKey, ipc::HandleTable*, ProcessKey,
                                                      const ServiceEndpointCredentialSnapshot*,
                                                      const ServiceEndpointProtocolAuthority* protocol, u64,
                                                      const ServiceDirectoryRequestCleanupSink*)
{
    ++g_directory_connect_calls;
    g_last_connect_directory = directory;
    g_last_connect_protocol = protocol == nullptr ? ServiceEndpointProtocolAuthority{} : *protocol;
    ServiceDirectoryConnectResult result = g_directory_connect_result;
    g_directory_connect_result.rollback = {};
    return result;
}

ServiceEndpointStatus ServiceDirectoryDrainOwnedChannel(ServiceDirectoryOwnedChannel* channel)
{
    ++g_directory_drain_calls;
    if (channel == nullptr || ServiceDirectoryOwnedChannelIsEmpty(*channel))
        return ServiceEndpointStatus::InvalidArgument;
    if (g_directory_drain_busy_remaining != 0)
    {
        --g_directory_drain_busy_remaining;
        return ServiceEndpointStatus::Busy;
    }
    *channel = {};
    return ServiceEndpointStatus::Ok;
}

ServiceDirectoryAcceptResult ServiceDirectoryAccept(ServiceDirectory*, ServiceKey, ServiceInstanceToken,
                                                    ipc::HandleTable*, ProcessKey,
                                                    const ServiceEndpointCredentialSnapshot*, u64)
{
    return {};
}

ServiceDirectoryReleaseAcceptedResult ServiceDirectoryReleaseAcceptedHandle(ServiceDirectory*, ProcessKey, ipc::Handle)
{
    return {ServiceDirectoryStatus::NotFound, ServiceEndpointStatus::Ok};
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

} // namespace duetos::ipc

namespace
{

using duetos::u16;
using duetos::u32;
using duetos::u64;
using duetos::u8;
using namespace duetos::core;
using namespace duetos::ipc;

inline constexpr u64 kEndpointRights = kHandleRightRead | kHandleRightWrite | kHandleRightWait | kHandleRightDestroy;

ServiceBootstrapStageRuntimeV1 g_target_stage{};
ServiceRuntimeV1 g_target_runtime{};

void ConfigureTargetService(u64 identity, const char* name, u32 selector = kServiceProtocolImmutablePolicyV1)
{
    g_target_stage.package.manifest_plan.document = {};
    auto& document = g_target_stage.package.manifest_plan.document;
    document.service_count = 1;
    auto& service = document.services[0];
    service.service_identity = identity;
    service.immutable_policy_selector = selector;
    while (service.name_length < kServiceManifestServiceNameCapacity && name[service.name_length] != 0)
    {
        service.name[service.name_length] = static_cast<u8>(name[service.name_length]);
        ++service.name_length;
    }
    g_target_runtime.stage = &g_target_stage;
}

void ResetDirectoryDoubles()
{
    g_directory_lookup_calls = 0;
    g_directory_connect_calls = 0;
    g_directory_drain_calls = 0;
    g_directory_drain_busy_remaining = 0;
    g_directory_lookup_result = {ServiceDirectoryStatus::NotFound, kInvalidServiceDirectoryOperationPin};
    g_directory_inspect_result = {ServiceDirectoryStatus::NotFound, {}};
    g_directory_connect_result = {
        ServiceDirectoryStatus::NotInitialized, ServiceEndpointStatus::Ok, ErrorCode::Ok, kHandleInvalid, {}, {}};
    g_last_connect_protocol = {};
    g_last_connect_directory = nullptr;
}

bool ConnectRollbacksAreFree(const ServiceEndpointIngressState& state)
{
    for (const auto& row : state.connect_rollbacks)
    {
        if (row.state != ServiceEndpointIngressConnectRollbackState::Free || row.directory != nullptr ||
            !ServiceDirectoryOwnedChannelIsEmpty(row.channel))
        {
            return false;
        }
    }
    return true;
}

void InitializeHandleTable(HandleTable* table)
{
    *table = HandleTable{};
    table->state = HandleTableState::Open;
    table->slots[0].state = HandleSlotState::Retired;
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

ServiceEndpointPeerSnapshot Peer(u32 credential_slot, u64 process_identity, u64 pid, u32 uid)
{
    return ServiceEndpointPeerSnapshot{
        ProcessKey{process_identity, pid},
        ServiceEndpointCredentialSnapshot{CredentialKey{credential_slot, 1}, Security(uid)},
    };
}

ServiceEndpointProtocolAuthority Protocol()
{
    return ServiceEndpointProtocolAuthority{0xA110U, 0x5010U, 0x51U, 0x3FU, 1, 0, 0x51U, 0};
}

void IgnoreCleanup(void*, EndpointRequestKey) {}

std::array<u8, kMessageAbiHeaderV1Bytes + kVersionedPayloadHeaderBytes> Frame(MessageKind kind, u64 request_id,
                                                                              u32 service_id = 0x51U, u32 method_id = 1,
                                                                              u16 payload_version = 1)
{
    std::array<u8, kMessageAbiHeaderV1Bytes + kVersionedPayloadHeaderBytes> frame{};
    const PayloadVersionRule payload_rule{payload_version, 0, kVersionedPayloadHeaderBytes,
                                          kVersionedPayloadHeaderBytes};
    EXPECT_EQ(PayloadEncodeHeader(frame.data() + kMessageAbiHeaderV1Bytes, kVersionedPayloadHeaderBytes,
                                  payload_version, 0, &payload_rule, 1),
              PayloadValidationError::Ok);
    const MessageHeaderV1 header{kind, 0, service_id, method_id, request_id};
    EXPECT_EQ(MessageEncodeHeaderV1(frame.data(), static_cast<u32>(frame.size()), header), MessageValidationError::Ok);
    return frame;
}

duet_service_endpoint_request_v1 Request(u16 operation)
{
    duet_service_endpoint_request_v1 request{};
    request.struct_size = sizeof(request);
    request.version = DUET_SERVICE_ENDPOINT_ABI_VERSION;
    request.operation = operation;
    return request;
}

struct Fixture
{
    ServiceEndpointIngressState ingress{};
    ServiceEndpointOwner endpoint_owner{};
    HandleTable client_handles{};
    HandleTable server_handles{};
    ResourceDomainKey domain = kInvalidResourceDomainKey;
    ServiceEndpointOwnerReceipt owner_receipt{};
    Handle client_endpoint = kHandleInvalid;
    Handle server_endpoint = kHandleInvalid;
    ProcessKey client_process{0x1001U, 101};
    ProcessKey server_process{0x2001U, 201};
    CredentialKey client_credential{1, 1};
    CredentialKey server_credential{2, 1};
    CredentialSecurityContext client_security = Security(1001);
    CredentialSecurityContext server_security = Security(2001);

    bool Initialize()
    {
        InitializeHandleTable(&client_handles);
        InitializeHandleTable(&server_handles);
        if (ServiceEndpointIngressInitialize(&ingress) != ServiceEndpointIngressStatus::Ok ||
            ServiceEndpointOwnerInitialize(&endpoint_owner) != ServiceEndpointStatus::Ok ||
            !ResourceDomainCreateAuthenticatedService(&domain))
        {
            return false;
        }

        const ServiceEndpointPeerSnapshot client = Peer(1, client_process.identity, client_process.pid, 1001);
        const ServiceEndpointPeerSnapshot server = Peer(2, server_process.identity, server_process.pid, 2001);
        const ServiceEndpointProtocolAuthority protocol = Protocol();
        const ServiceEndpointRequestCleanupSink cleanup{&IgnoreCleanup, nullptr};
        ServiceEndpointPairCreateResult created =
            ServiceEndpointCreatePair(&endpoint_owner, domain, &protocol, &client, &server, &cleanup);
        if (created.status != ServiceEndpointStatus::Ok)
            return false;

        auto client_inserted = HandleTableInsert(client_handles, created.pair.initiator, kEndpointRights);
        if (!client_inserted.has_value())
        {
            (void)ServiceEndpointAbortPair(&created.pair);
            return false;
        }
        client_endpoint = client_inserted.value();
        created.pair.initiator = nullptr;

        auto server_inserted = HandleTableInsert(server_handles, created.pair.acceptor, kEndpointRights);
        if (!server_inserted.has_value())
        {
            HandleTableDrain(client_handles);
            (void)ServiceEndpointAbortPair(&created.pair);
            return false;
        }
        server_endpoint = server_inserted.value();
        created.pair.acceptor = nullptr;
        owner_receipt = created.pair.owner;
        created.pair.owner = {};
        return ServiceEndpointActivate(&created.pair.activation) == ServiceEndpointStatus::Ok;
    }

    ServiceEndpointIngressCaller Client() const
    {
        return ServiceEndpointIngressCaller{client_process,
                                            const_cast<HandleTable*>(&client_handles),
                                            client_credential,
                                            client_security,
                                            CapSetEmpty(),
                                            domain,
                                            nullptr};
    }

    ServiceEndpointIngressCaller Server() const
    {
        return ServiceEndpointIngressCaller{server_process,
                                            const_cast<HandleTable*>(&server_handles),
                                            server_credential,
                                            server_security,
                                            CapSetEmpty(),
                                            domain,
                                            nullptr};
    }

    void Cleanup()
    {
        if (ServiceEndpointOwnerReceiptIsValid(owner_receipt))
            EXPECT_EQ(ServiceEndpointReleaseOwner(&owner_receipt), ServiceEndpointStatus::Ok);
        HandleTableDrain(client_handles);
        HandleTableDrain(server_handles);
        if (ResourceDomainKeyIsValid(domain))
            EXPECT_TRUE(ResourceDomainRelease(domain));
    }
};

bool SendRequest(Fixture& fixture, u64 request_id, u32 service_id = 0x51U, u32 method_id = 1, u16 payload_version = 1)
{
    KObject* retained = HandleTableLookupRef(fixture.client_handles, fixture.client_endpoint,
                                             KObjectType::ServiceEndpoint, kHandleRightWrite);
    if (retained == nullptr)
        return false;
    ServiceEndpointOperationResult acquired = ServiceEndpointAcquireOperation(retained);
    KObjectRelease(retained);
    if (acquired.status != ServiceEndpointStatus::Ok)
        return false;
    const ServiceEndpointRequestReserveResult reserved = ServiceEndpointReserveRequest(&acquired.operation, request_id);
    const ServiceEndpointDirectionResult direction =
        ServiceEndpointBorrowDirection(&acquired.operation, ServiceEndpointTrafficDirection::Send);
    const auto frame = Frame(MessageKind::Request, request_id, service_id, method_id, payload_version);
    const PayloadVersionRule payload_rule{payload_version, 0, kVersionedPayloadHeaderBytes,
                                          kVersionedPayloadHeaderBytes};
    const KMessagePortSendResult sent =
        direction.status == ServiceEndpointStatus::Ok
            ? KMessagePortSend(direction.lease.port, frame.data(), static_cast<u32>(frame.size()), &payload_rule, 1)
            : KMessagePortSendResult{};
    EXPECT_EQ(ServiceEndpointReleaseOperation(&acquired.operation), ServiceEndpointStatus::Ok);
    return reserved.status == ServiceEndpointStatus::Ok && direction.status == ServiceEndpointStatus::Ok &&
           sent.status == KMessagePortStatus::Ok;
}

bool ReceiveReply(Fixture& fixture, u64 request_id)
{
    KObject* retained = HandleTableLookupRef(fixture.client_handles, fixture.client_endpoint,
                                             KObjectType::ServiceEndpoint, kHandleRightRead | kHandleRightWait);
    if (retained == nullptr)
        return false;
    ServiceEndpointOperationResult acquired = ServiceEndpointAcquireOperation(retained);
    KObjectRelease(retained);
    if (acquired.status != ServiceEndpointStatus::Ok)
        return false;
    const ServiceEndpointDirectionResult direction =
        ServiceEndpointBorrowDirection(&acquired.operation, ServiceEndpointTrafficDirection::Receive);
    std::array<u8, DUET_SERVICE_ENDPOINT_MAX_FRAME_BYTES> frame{};
    const KMessagePortReceiveResult received =
        direction.status == ServiceEndpointStatus::Ok
            ? KMessagePortTryReceive(direction.lease.port, frame.data(), static_cast<u32>(frame.size()))
            : KMessagePortReceiveResult{};
    MessageView view{};
    const bool valid = received.status == KMessagePortStatus::Ok &&
                       MessageValidate(frame.data(), received.copied_bytes, &view) == MessageValidationError::Ok &&
                       view.kind == MessageKind::Reply && view.request_id == request_id;
    EXPECT_EQ(ServiceEndpointReleaseOperation(&acquired.operation), ServiceEndpointStatus::Ok);
    return valid;
}

duet_service_endpoint_result_v1 Execute(ServiceEndpointIngressState& state, const ServiceEndpointIngressCaller& caller,
                                        const duet_service_endpoint_request_v1& request, const u8* request_frame,
                                        u8* result_frame, u32 result_frame_capacity)
{
    duet_service_endpoint_result_v1 result{};
    EXPECT_EQ(ServiceEndpointIngressExecute(&state, &caller, &request, request_frame, &result, result_frame,
                                            result_frame_capacity),
              ServiceEndpointIngressStatus::Ok);
    return result;
}

} // namespace

int main()
{
    using namespace duetos::core;
    using namespace duetos::ipc;

    Fixture fixture{};
    ASSERT_TRUE(fixture.Initialize());
    const ServiceEndpointIngressCaller client = fixture.Client();
    const ServiceEndpointIngressCaller server = fixture.Server();

    // Bad versions and non-canonical operation fields are rejected before any
    // endpoint lookup or receipt mutation.
    duet_service_endpoint_request_v1 malformed = Request(DUET_SERVICE_ENDPOINT_OP_RECEIVE);
    malformed.version = 2;
    malformed.endpoint_handle = fixture.server_endpoint;
    duet_service_endpoint_result_v1 malformed_result = Execute(fixture.ingress, server, malformed, nullptr, nullptr, 0);
    EXPECT_EQ(malformed_result.status, DUET_SERVICE_ENDPOINT_STATUS_BAD_VERSION);

    // CONNECT accepts only a stable manifest selector. Missing capability,
    // missing policy, and malformed names return before directory/HandleTable
    // mutation and before consuming the non-wrapping authority counter or a
    // durable cleanup slot.
    g_runtime_bind_enabled = true;
    ServiceEndpointIngressCaller connecting = client;
    connecting.runtime = &g_target_runtime;
    duet_service_endpoint_request_v1 connect = Request(DUET_SERVICE_ENDPOINT_OP_CONNECT);

    ConfigureTargetService(kExecdManifestServiceIdentityV1, "execd");
    connect.target_service_identity = kExecdManifestServiceIdentityV1;
    ResetDirectoryDoubles();
    duet_service_endpoint_result_v1 no_parse_cap = Execute(fixture.ingress, connecting, connect, nullptr, nullptr, 0);
    EXPECT_EQ(no_parse_cap.status, DUET_SERVICE_ENDPOINT_STATUS_ACCESS_DENIED);
    EXPECT_EQ(g_directory_lookup_calls, 0U);
    EXPECT_EQ(g_directory_connect_calls, 0U);
    EXPECT_EQ(fixture.ingress.next_protocol_authority_identity, 1ULL);
    EXPECT_TRUE(ConnectRollbacksAreFree(fixture.ingress));

    ConfigureTargetService(kRegistrydManifestServiceIdentityV1, "registryd");
    connect.target_service_identity = kRegistrydManifestServiceIdentityV1;
    ResetDirectoryDoubles();
    duet_service_endpoint_result_v1 missing_policy = Execute(fixture.ingress, connecting, connect, nullptr, nullptr, 0);
    EXPECT_EQ(missing_policy.status, DUET_SERVICE_ENDPOINT_STATUS_UNSUPPORTED);
    EXPECT_EQ(g_directory_lookup_calls, 0U);
    EXPECT_EQ(g_directory_connect_calls, 0U);
    EXPECT_EQ(fixture.ingress.next_protocol_authority_identity, 1ULL);
    EXPECT_TRUE(ConnectRollbacksAreFree(fixture.ingress));

    ConfigureTargetService(kServicedManifestServiceIdentityV1, "");
    connect.target_service_identity = kServicedManifestServiceIdentityV1;
    ResetDirectoryDoubles();
    duet_service_endpoint_result_v1 invalid_name = Execute(fixture.ingress, connecting, connect, nullptr, nullptr, 0);
    EXPECT_EQ(invalid_name.status, DUET_SERVICE_ENDPOINT_STATUS_CORRUPT_STATE);
    EXPECT_EQ(g_directory_lookup_calls, 0U);
    EXPECT_EQ(fixture.ingress.next_protocol_authority_identity, 1ULL);
    EXPECT_TRUE(ConnectRollbacksAreFree(fixture.ingress));

    ConfigureTargetService(kServicedManifestServiceIdentityV1, "serviced");
    ResetDirectoryDoubles();
    g_directory_lookup_result = {ServiceDirectoryStatus::Ok, ServiceDirectoryOperationPin{ServiceKey{0, 1}, 0, 1}};
    g_directory_inspect_result.status = ServiceDirectoryStatus::Ok;
    g_directory_inspect_result.snapshot.manifest_slot = 0;
    g_directory_inspect_result.snapshot.owner =
        ServiceInstanceToken{ServiceStartTicket{0x999, 1}, ServiceInstanceKey{0x9001, 901}};
    duet_service_endpoint_result_v1 owner_mismatch = Execute(fixture.ingress, connecting, connect, nullptr, nullptr, 0);
    EXPECT_EQ(owner_mismatch.status, DUET_SERVICE_ENDPOINT_STATUS_ACCESS_DENIED);
    EXPECT_EQ(g_directory_lookup_calls, 1U);
    EXPECT_EQ(g_directory_connect_calls, 0U);
    EXPECT_EQ(fixture.ingress.next_protocol_authority_identity, 1ULL);
    EXPECT_TRUE(ConnectRollbacksAreFree(fixture.ingress));

    // A Busy directory rollback is moved from the syscall stack into one exact
    // durable row. A second CONNECT still has independent rollback capacity;
    // later driving consumes the authority once and replay-driving is inert.
    ResetDirectoryDoubles();
    g_directory_lookup_result = {ServiceDirectoryStatus::Ok, ServiceDirectoryOperationPin{ServiceKey{0, 1}, 0, 1}};
    g_directory_inspect_result.status = ServiceDirectoryStatus::Ok;
    g_directory_inspect_result.snapshot.manifest_slot = 0;
    g_directory_inspect_result.snapshot.owner = ServiceInstanceToken{
        ServiceStartTicket{kServicedManifestServiceIdentityV1, 1}, ServiceInstanceKey{0x9001, 901}};
    g_directory_inspect_result.snapshot.owner_credential = Peer(9, 0x9001, 901, 9).credential;
    const ServiceEndpointChannelKey rollback_channel{0, 1, 0xBEEFULL};
    g_directory_connect_result = {
        ServiceDirectoryStatus::EndpointReleaseFailed,
        ServiceEndpointStatus::Busy,
        ErrorCode::Ok,
        kHandleInvalid,
        {},
        ServiceDirectoryOwnedChannel{ServiceEndpointOwnerReceipt{&fixture.endpoint_owner, rollback_channel}, nullptr,
                                     false}};
    g_directory_drain_busy_remaining = 1;
    duet_service_endpoint_result_v1 busy_connect = Execute(fixture.ingress, connecting, connect, nullptr, nullptr, 0);
    EXPECT_EQ(busy_connect.status, DUET_SERVICE_ENDPOINT_STATUS_BUSY);
    EXPECT_EQ(g_directory_connect_calls, 1U);
    EXPECT_TRUE(g_last_connect_directory == &g_target_runtime.directory);
    EXPECT_EQ(g_last_connect_protocol.authority_identity, 1ULL);
    EXPECT_EQ(g_last_connect_protocol.service_identity, kServicedManifestServiceIdentityV1);
    EXPECT_EQ(g_last_connect_protocol.allowed_methods, 0x3ULL);
    EXPECT_EQ(g_last_connect_protocol.wire_service_id, kServicedServiceId);
    EXPECT_EQ(fixture.ingress.next_protocol_authority_identity, 2ULL);
    u32 live_rollbacks = 0;
    for (const auto& row : fixture.ingress.connect_rollbacks)
    {
        if (row.state == ServiceEndpointIngressConnectRollbackState::Live)
        {
            ++live_rollbacks;
            EXPECT_TRUE(row.directory == &g_target_runtime.directory);
            EXPECT_TRUE(row.channel.owner.owner == &fixture.endpoint_owner);
            EXPECT_TRUE(row.channel.owner.channel == rollback_channel);
        }
    }
    EXPECT_EQ(live_rollbacks, 1U);

    g_directory_lookup_result = {ServiceDirectoryStatus::NotFound, kInvalidServiceDirectoryOperationPin};
    duet_service_endpoint_result_v1 parallel_connect =
        Execute(fixture.ingress, connecting, connect, nullptr, nullptr, 0);
    EXPECT_EQ(parallel_connect.status, DUET_SERVICE_ENDPOINT_STATUS_NOT_READY);
    EXPECT_EQ(fixture.ingress.next_protocol_authority_identity, 2ULL);
    const u32 drains_before_settlement = g_directory_drain_calls;
    ServiceEndpointIngressDriveConnectRollbacks(&fixture.ingress);
    EXPECT_TRUE(ConnectRollbacksAreFree(fixture.ingress));
    EXPECT_EQ(g_directory_drain_calls, drains_before_settlement + 1U);
    ServiceEndpointIngressDriveConnectRollbacks(&fixture.ingress);
    EXPECT_EQ(g_directory_drain_calls, drains_before_settlement + 1U);
    g_runtime_bind_enabled = false;
    ResetDirectoryDoubles();

    // SEND_REQUEST rejects foreign routes and payload versions before the
    // request ledger mutates. The same request id therefore remains usable by
    // the first exact authorized frame, and its replay is rejected afterward.
    duet_service_endpoint_request_v1 send = Request(DUET_SERVICE_ENDPOINT_OP_SEND_REQUEST);
    send.endpoint_handle = fixture.client_endpoint;
    const auto wrong_route_request = Frame(MessageKind::Request, 1, 0x52U);
    send.frame_bytes = static_cast<u32>(wrong_route_request.size());
    EXPECT_EQ(Execute(fixture.ingress, client, send, wrong_route_request.data(), nullptr, 0).status,
              DUET_SERVICE_ENDPOINT_STATUS_MALFORMED_MESSAGE);
    const auto wrong_version_request = Frame(MessageKind::Request, 1, 0x51U, 1, 2);
    EXPECT_EQ(Execute(fixture.ingress, client, send, wrong_version_request.data(), nullptr, 0).status,
              DUET_SERVICE_ENDPOINT_STATUS_MALFORMED_MESSAGE);
    const auto request_one = Frame(MessageKind::Request, 1);
    duet_service_endpoint_result_v1 sent_one = Execute(fixture.ingress, client, send, request_one.data(), nullptr, 0);
    EXPECT_EQ(sent_one.status, DUET_SERVICE_ENDPOINT_STATUS_OK);
    EXPECT_NE(sent_one.message_sequence, 0ULL);
    EXPECT_EQ(Execute(fixture.ingress, client, send, request_one.data(), nullptr, 0).status,
              DUET_SERVICE_ENDPOINT_STATUS_REPLAY_REJECTED);
    duet_service_endpoint_request_v1 receive = Request(DUET_SERVICE_ENDPOINT_OP_RECEIVE);
    receive.flags = DUET_SERVICE_ENDPOINT_REQUEST_NONBLOCK;
    receive.endpoint_handle = fixture.server_endpoint;
    std::array<u8, DUET_SERVICE_ENDPOINT_MAX_FRAME_BYTES> receive_frame{};

    // A short output does not consume the queued request or strand a Pending
    // receipt. A full retry receives the same frame and obtains exact reply
    // authority bound to the current process and endpoint generation.
    duet_service_endpoint_result_v1 short_receive =
        Execute(fixture.ingress, server, receive, nullptr, receive_frame.data(), 1);
    EXPECT_EQ(short_receive.status, DUET_SERVICE_ENDPOINT_STATUS_BUFFER_TOO_SMALL);
    EXPECT_EQ(short_receive.required_frame_bytes, kMessageAbiHeaderV1Bytes + kVersionedPayloadHeaderBytes);

    duet_service_endpoint_result_v1 received = Execute(fixture.ingress, server, receive, nullptr, receive_frame.data(),
                                                       static_cast<u32>(receive_frame.size()));
    EXPECT_EQ(received.status, DUET_SERVICE_ENDPOINT_STATUS_OK);
    EXPECT_TRUE((received.flags & DUET_SERVICE_ENDPOINT_RESULT_HAS_FRAME) != 0);
    EXPECT_TRUE((received.flags & DUET_SERVICE_ENDPOINT_RESULT_HAS_COMPLETION_RECEIPT) != 0);
    EXPECT_TRUE((received.flags & DUET_SERVICE_ENDPOINT_RESULT_PEER_TASK_UNAVAILABLE) != 0);
    EXPECT_EQ(received.peer_task_identity, 0ULL);
    EXPECT_EQ(received.peer_process.identity, fixture.client_process.identity);
    EXPECT_EQ(received.peer_process.pid, fixture.client_process.pid);
    EXPECT_EQ(received.peer_credential.slot, fixture.client_credential.slot);
    EXPECT_EQ(received.last_committed_request_sequence, 0ULL);
    EXPECT_NE(received.completion_receipt, 0ULL);

    auto wrong_reply_frame = Frame(MessageKind::Reply, 2);
    duet_service_endpoint_request_v1 reply = Request(DUET_SERVICE_ENDPOINT_OP_REPLY_ACK);
    reply.endpoint_handle = fixture.server_endpoint;
    reply.completion_receipt = received.completion_receipt;
    reply.frame_bytes = static_cast<u32>(wrong_reply_frame.size());

    // Route and payload authority are checked before ClaimReceipt, so hostile
    // replies cannot transiently consume or reveal the live receipt.
    const auto wrong_route_reply = Frame(MessageKind::Reply, 1, 0x52U);
    EXPECT_EQ(Execute(fixture.ingress, server, reply, wrong_route_reply.data(), nullptr, 0).status,
              DUET_SERVICE_ENDPOINT_STATUS_MALFORMED_MESSAGE);
    const auto wrong_version_reply = Frame(MessageKind::Reply, 1, 0x51U, 1, 2);
    EXPECT_EQ(Execute(fixture.ingress, server, reply, wrong_version_reply.data(), nullptr, 0).status,
              DUET_SERVICE_ENDPOINT_STATUS_MALFORMED_MESSAGE);

    // The exact live token is no more informative to a foreign ProcessKey than
    // the same row after retirement: both are replay-rejected, so probing the
    // bounded receipt space cannot disclose which slots are occupied.
    ServiceEndpointIngressCaller impostor = server;
    impostor.process = ProcessKey{fixture.server_process.identity + 1U, fixture.server_process.pid};
    duet_service_endpoint_result_v1 denied =
        Execute(fixture.ingress, impostor, reply, wrong_reply_frame.data(), nullptr, 0);
    EXPECT_EQ(denied.status, DUET_SERVICE_ENDPOINT_STATUS_REPLAY_REJECTED);

    // Request-ID mismatch restores the live receipt. The exact reply then
    // consumes it, and a copied receipt cannot publish a duplicate response.
    duet_service_endpoint_result_v1 mismatch =
        Execute(fixture.ingress, server, reply, wrong_reply_frame.data(), nullptr, 0);
    EXPECT_EQ(mismatch.status, DUET_SERVICE_ENDPOINT_STATUS_REPLAY_REJECTED);
    const auto reply_frame = Frame(MessageKind::Reply, 1);
    reply.frame_bytes = static_cast<u32>(reply_frame.size());
    duet_service_endpoint_result_v1 replied = Execute(fixture.ingress, server, reply, reply_frame.data(), nullptr, 0);
    EXPECT_EQ(replied.status, DUET_SERVICE_ENDPOINT_STATUS_OK);
    duet_service_endpoint_result_v1 replayed = Execute(fixture.ingress, server, reply, reply_frame.data(), nullptr, 0);
    EXPECT_EQ(replayed.status, DUET_SERVICE_ENDPOINT_STATUS_REPLAY_REJECTED);
    EXPECT_TRUE(ReceiveReply(fixture, 1));

    // Export and import preserve exact type/rights metadata. Endpoint objects
    // are explicitly not transferable until directory ownership migration is
    // designed, and a revoked generation cannot be replayed.
    auto transferable_port = KMessagePortCreate();
    ASSERT_TRUE(transferable_port.has_value());
    constexpr u64 source_rights = kHandleRightDuplicate | kHandleRightTransfer | kHandleRightRead | kHandleRightWrite |
                                  kHandleRightWait | kHandleRightDestroy;
    auto installed_port = HandleTableInsert(fixture.server_handles, &transferable_port.value()->base, source_rights);
    ASSERT_TRUE(installed_port.has_value());

    duet_service_endpoint_request_v1 export_request = Request(DUET_SERVICE_ENDPOINT_OP_EXPORT);
    export_request.endpoint_handle = fixture.server_endpoint;
    export_request.object_handle = installed_port.value();
    export_request.object_type = DUET_KOBJECT_MESSAGE_PORT;
    export_request.requested_rights = DUET_HANDLE_RIGHT_READ | DUET_HANDLE_RIGHT_WAIT;
    duet_service_endpoint_result_v1 exported = Execute(fixture.ingress, server, export_request, nullptr, nullptr, 0);
    EXPECT_EQ(exported.status, DUET_SERVICE_ENDPOINT_STATUS_OK);
    EXPECT_TRUE((exported.flags & DUET_SERVICE_ENDPOINT_RESULT_HAS_TRANSFER) != 0);
    EXPECT_EQ(exported.object_type, DUET_KOBJECT_MESSAGE_PORT);
    EXPECT_EQ(exported.object_rights, export_request.requested_rights);
    EXPECT_NE(exported.object_metadata.identity, 0ULL);

    duet_service_endpoint_request_v1 forbidden_export = export_request;
    forbidden_export.object_handle = fixture.server_endpoint;
    forbidden_export.object_type = DUET_KOBJECT_SERVICE_ENDPOINT;
    duet_service_endpoint_result_v1 forbidden = Execute(fixture.ingress, server, forbidden_export, nullptr, nullptr, 0);
    EXPECT_EQ(forbidden.status, DUET_SERVICE_ENDPOINT_STATUS_UNSUPPORTED);

    duet_service_endpoint_request_v1 overbroad_export = export_request;
    overbroad_export.requested_rights = DUET_HANDLE_RIGHT_SIGNAL;
    duet_service_endpoint_result_v1 overbroad = Execute(fixture.ingress, server, overbroad_export, nullptr, nullptr, 0);
    EXPECT_EQ(overbroad.status, DUET_SERVICE_ENDPOINT_STATUS_RIGHTS_DENIED);

    duet_service_endpoint_request_v1 import_request = Request(DUET_SERVICE_ENDPOINT_OP_IMPORT);
    import_request.endpoint_handle = fixture.client_endpoint;
    import_request.transfer_reference = exported.transfer_reference;
    import_request.object_type = exported.object_type;
    import_request.requested_rights = exported.object_rights;
    duet_service_endpoint_result_v1 imported = Execute(fixture.ingress, client, import_request, nullptr, nullptr, 0);
    EXPECT_EQ(imported.status, DUET_SERVICE_ENDPOINT_STATUS_OK);
    EXPECT_NE(imported.object_handle, 0ULL);
    EXPECT_EQ(imported.object_metadata.identity, exported.object_metadata.identity);

    duet_service_endpoint_request_v1 revoke = Request(DUET_SERVICE_ENDPOINT_OP_REVOKE_EXPORT);
    revoke.endpoint_handle = fixture.server_endpoint;
    revoke.transfer_reference = exported.transfer_reference;
    duet_service_endpoint_result_v1 revoked = Execute(fixture.ingress, server, revoke, nullptr, nullptr, 0);
    EXPECT_EQ(revoked.status, DUET_SERVICE_ENDPOINT_STATUS_OK);
    duet_service_endpoint_result_v1 stale_import =
        Execute(fixture.ingress, client, import_request, nullptr, nullptr, 0);
    EXPECT_EQ(stale_import.status, DUET_SERVICE_ENDPOINT_STATUS_REPLAY_REJECTED);

    // A hostile peer can bypass syscall send validation only in kernel test
    // scaffolding. Receive still rejects its exact reserved ledger row before
    // any bytes or completion receipt are exposed. Rejected route/version IDs
    // remain replayed, while the next exact request is accepted normally.
    ASSERT_TRUE(SendRequest(fixture, 2, 0x52U));
    duet_service_endpoint_result_v1 rejected_route = Execute(
        fixture.ingress, server, receive, nullptr, receive_frame.data(), static_cast<u32>(receive_frame.size()));
    EXPECT_EQ(rejected_route.status, DUET_SERVICE_ENDPOINT_STATUS_MALFORMED_MESSAGE);
    EXPECT_EQ(rejected_route.frame_bytes, 0U);
    EXPECT_EQ(rejected_route.flags &
                  (DUET_SERVICE_ENDPOINT_RESULT_HAS_FRAME | DUET_SERVICE_ENDPOINT_RESULT_HAS_COMPLETION_RECEIPT),
              0U);
    const auto exact_two = Frame(MessageKind::Request, 2);
    send.frame_bytes = static_cast<u32>(exact_two.size());
    EXPECT_EQ(Execute(fixture.ingress, client, send, exact_two.data(), nullptr, 0).status,
              DUET_SERVICE_ENDPOINT_STATUS_REPLAY_REJECTED);

    ASSERT_TRUE(SendRequest(fixture, 3, 0x51U, 1, 2));
    duet_service_endpoint_result_v1 rejected_version = Execute(
        fixture.ingress, server, receive, nullptr, receive_frame.data(), static_cast<u32>(receive_frame.size()));
    EXPECT_EQ(rejected_version.status, DUET_SERVICE_ENDPOINT_STATUS_MALFORMED_MESSAGE);
    EXPECT_EQ(rejected_version.frame_bytes, 0U);
    EXPECT_EQ(rejected_version.flags &
                  (DUET_SERVICE_ENDPOINT_RESULT_HAS_FRAME | DUET_SERVICE_ENDPOINT_RESULT_HAS_COMPLETION_RECEIPT),
              0U);
    const auto exact_three = Frame(MessageKind::Request, 3);
    EXPECT_EQ(Execute(fixture.ingress, client, send, exact_three.data(), nullptr, 0).status,
              DUET_SERVICE_ENDPOINT_STATUS_REPLAY_REJECTED);

    const auto exact_four = Frame(MessageKind::Request, 4);
    EXPECT_EQ(Execute(fixture.ingress, client, send, exact_four.data(), nullptr, 0).status,
              DUET_SERVICE_ENDPOINT_STATUS_OK);
    duet_service_endpoint_result_v1 second = Execute(fixture.ingress, server, receive, nullptr, receive_frame.data(),
                                                     static_cast<u32>(receive_frame.size()));
    EXPECT_EQ(second.status, DUET_SERVICE_ENDPOINT_STATUS_OK);
    EXPECT_EQ(second.last_committed_request_sequence, 1ULL);
    ServiceEndpointIngressCancelProcess(&fixture.ingress, fixture.server_process);
    const auto second_reply_frame = Frame(MessageKind::Reply, 4);
    reply.completion_receipt = second.completion_receipt;
    reply.frame_bytes = static_cast<u32>(second_reply_frame.size());
    duet_service_endpoint_result_v1 cancelled =
        Execute(fixture.ingress, server, reply, second_reply_frame.data(), nullptr, 0);
    EXPECT_EQ(cancelled.status, DUET_SERVICE_ENDPOINT_STATUS_REPLAY_REJECTED);

    fixture.Cleanup();
    return duetos_host_test::finish_main("test_service_endpoint_ingress");
}
