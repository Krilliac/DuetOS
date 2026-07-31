// Hosted hostile-frame and authority-binding properties for serviced v1.

#include "core/serviced_protocol.h"
#include "host_test_helper.h"

#include <array>

namespace
{

using namespace duetos;
using namespace duetos::core;
using duetos::ipc::MessageKind;

using RequestFrame = std::array<u8, kServicedRequestV1MessageBytes>;
using ReplyFrame = std::array<u8, kServicedReplyV1MessageBytes>;

constexpr u32 kEnvelopeKindOffset = 12;
constexpr u32 kEnvelopeServiceOffset = 16;
constexpr u32 kPayloadOffset = ipc::kMessageAbiHeaderV1Bytes;
constexpr u32 kRequestPayloadMethodOffset = kPayloadOffset + 8;
constexpr u32 kRequestPayloadReservedOffset = kPayloadOffset + 12;
constexpr u32 kRequestPayloadCursorOffset = kPayloadOffset + 16;
constexpr u32 kRequestPayloadReserved2Offset = kPayloadOffset + 20;
constexpr u32 kRequestPayloadIdentityOffset = kPayloadOffset + 24;
constexpr u32 kRequestPayloadGenerationOffset = kPayloadOffset + 32;
constexpr u32 kReplyPayloadMethodOffset = kPayloadOffset + 8;
constexpr u32 kReplyPayloadStatusOffset = kPayloadOffset + 12;
constexpr u32 kReplyPayloadSequenceOffset = kPayloadOffset + 16;
constexpr u32 kReplyPayloadServiceIdentityOffset = kPayloadOffset + 24;
constexpr u32 kReplyPayloadPidOffset = kPayloadOffset + 48;
constexpr u32 kReplyPayloadPhaseOffset = kPayloadOffset + 80;
constexpr u32 kReplyPayloadPolicyOffset = kPayloadOffset + 81;
constexpr u32 kReplyPayloadReservedOffset = kPayloadOffset + 83;
constexpr u32 kReplyPayloadNameOffset = kPayloadOffset + 88;

void WriteLe16(u8* bytes, u16 value)
{
    bytes[0] = static_cast<u8>(value);
    bytes[1] = static_cast<u8>(value >> 8U);
}

void WriteLe32(u8* bytes, u32 value)
{
    bytes[0] = static_cast<u8>(value);
    bytes[1] = static_cast<u8>(value >> 8U);
    bytes[2] = static_cast<u8>(value >> 16U);
    bytes[3] = static_cast<u8>(value >> 24U);
}

void WriteLe64(u8* bytes, u64 value)
{
    WriteLe32(bytes, static_cast<u32>(value));
    WriteLe32(bytes + 4, static_cast<u32>(value >> 32U));
}

ServicedEndpointSnapshotV1 Endpoint(u64 floor = 0)
{
    return ServicedEndpointSnapshotV1{0x1001, 0x2002, 0x3003, floor, 0};
}

constexpr u64 ServiceIdentity(u32 slot)
{
    return 0x5356430000000000ULL | static_cast<u64>(slot + 1U);
}

ServicedControlAuthoritySnapshotV1 Authority(u64 scope = kServicedAllServicesScope, u32 rights = kServicedKnownRights)
{
    return ServicedControlAuthoritySnapshotV1{0x4004, 0x1001, scope, rights, 0};
}

ServicedRequestV1 Request(ServicedMethod method, u64 request_id = 50, u32 slot = 7, u64 generation = 0)
{
    return ServicedRequestV1{
        request_id, method, method == ServicedMethod::Enumerate ? slot : 0,
        method == ServicedMethod::Enumerate ? kServicedInvalidServiceIdentity : ServiceIdentity(slot), generation};
}

RequestFrame EncodeRequest(const ServicedRequestV1& request)
{
    RequestFrame frame{};
    EXPECT_EQ(ServicedEncodeRequestV1(frame.data(), static_cast<u32>(frame.size()), request).error,
              ServicedProtocolError::Ok);
    return frame;
}

ServicedStatusRowV1 Row(u32 slot = 7, ServicedInstancePhase phase = ServicedInstancePhase::Running, u64 generation = 9,
                        u64 pid = 700)
{
    ServicedStatusRowV1 row{};
    row.service_identity = ServiceIdentity(slot);
    row.service_slot = slot;
    row.transition_generation = generation;
    row.pid = pid;
    row.lifetime_restarts = 4;
    row.restarts_in_window = 2;
    row.last_spawn_ns = 1000;
    row.last_exit_ns = 900;
    row.phase = phase;
    row.restart_policy = ServicedRestartPolicy::Always;
    row.autostart = 1;
    constexpr char name[] = "example-service";
    row.name_length = static_cast<u8>(sizeof(name) - 1);
    for (u32 index = 0; index < row.name_length; ++index)
        row.name[index] = static_cast<u8>(name[index]);
    return row;
}

ServicedReplyV1 SuccessReply(ServicedMethod method, u64 request_id = 50)
{
    ServicedReplyV1 reply{};
    reply.request_id = request_id;
    reply.method = method;
    reply.status = ServicedReplyStatus::Success;
    reply.next_cursor = method == ServicedMethod::Enumerate ? kServicedEnumerationEnd : 0;
    reply.service = Row();
    return reply;
}

ReplyFrame EncodeReply(const ServicedReplyV1& reply)
{
    ReplyFrame frame{};
    EXPECT_EQ(ServicedEncodeReplyV1(frame.data(), static_cast<u32>(frame.size()), reply).error,
              ServicedProtocolError::Ok);
    return frame;
}

void Poison(ServicedValidatedRequestV1* output)
{
    output->request = ServicedRequestV1{~0ULL, static_cast<ServicedMethod>(~0U), ~0U, ~0ULL, ~0ULL};
    output->sender_endpoint_identity = ~0ULL;
    output->sender_process_identity = ~0ULL;
    output->sender_task_identity = ~0ULL;
    output->authority_identity = ~0ULL;
    output->authority_rights = ~0U;
    output->authority_scope = ~0U;
}

void ExpectCleared(const ServicedValidatedRequestV1& output)
{
    EXPECT_EQ(output.request.request_id, 0ULL);
    EXPECT_EQ(output.request.enumeration_cursor, 0U);
    EXPECT_EQ(output.request.service_identity, 0ULL);
    EXPECT_EQ(output.request.expected_transition_generation, 0ULL);
    EXPECT_EQ(output.sender_endpoint_identity, 0ULL);
    EXPECT_EQ(output.sender_process_identity, 0ULL);
    EXPECT_EQ(output.sender_task_identity, 0ULL);
    EXPECT_EQ(output.authority_identity, 0ULL);
    EXPECT_EQ(output.authority_rights, 0U);
    EXPECT_EQ(output.authority_scope, 0U);
}

void ExpectRequestFailure(const RequestFrame& frame, const ServicedEndpointSnapshotV1* endpoint,
                          const ServicedControlAuthoritySnapshotV1* authority, ServicedProtocolError error)
{
    ServicedValidatedRequestV1 output{};
    Poison(&output);
    EXPECT_EQ(
        ServicedValidateRequestV1(frame.data(), static_cast<u32>(frame.size()), endpoint, authority, &output).error,
        error);
    ExpectCleared(output);
}

u64 NextRandom(u64& state)
{
    state ^= state << 13U;
    state ^= state >> 7U;
    state ^= state << 17U;
    return state;
}

} // namespace

int main()
{
    static_assert(kServicedRequestV1MessageBytes == 72);
    static_assert(kServicedReplyV1MessageBytes == 152);
    static_assert(kServicedReplyV1MessageBytes < 4096);

    ServicedEndpointSnapshotV1 endpoint = Endpoint();
    ServicedControlAuthoritySnapshotV1 all_authority = Authority();
    EXPECT_TRUE(ServicedEndpointSnapshotIsCanonicalV1(endpoint));
    EXPECT_TRUE(ServicedControlAuthoritySnapshotIsCanonicalV1(all_authority));
    ServicedEndpointSnapshotV1 malformed_endpoint = endpoint;
    malformed_endpoint.reserved = 1;
    EXPECT_FALSE(ServicedEndpointSnapshotIsCanonicalV1(malformed_endpoint));
    ServicedControlAuthoritySnapshotV1 malformed_authority = all_authority;
    malformed_authority.rights |= 0x80000000U;
    EXPECT_FALSE(ServicedControlAuthoritySnapshotIsCanonicalV1(malformed_authority));
    malformed_authority = all_authority;
    malformed_authority.service_identity_scope = kServicedInvalidServiceIdentity;
    EXPECT_FALSE(ServicedControlAuthoritySnapshotIsCanonicalV1(malformed_authority));

    // All methods round-trip, but trusted endpoint/capability facts come only
    // from retained snapshots and are copied alongside the wire selectors.
    constexpr ServicedMethod methods[] = {ServicedMethod::Enumerate, ServicedMethod::Query, ServicedMethod::Start,
                                          ServicedMethod::Stop, ServicedMethod::Restart};
    for (ServicedMethod method : methods)
    {
        const u64 generation =
            method == ServicedMethod::Enumerate || method == ServicedMethod::Query ? 0 : 0x123456789ABCULL;
        const ServicedRequestV1 request = Request(method, 50 + static_cast<u32>(method), 7, generation);
        const RequestFrame frame = EncodeRequest(request);
        ServicedValidatedRequestV1 decoded{};
        EXPECT_EQ(
            ServicedValidateRequestV1(frame.data(), static_cast<u32>(frame.size()), &endpoint, &all_authority, &decoded)
                .error,
            ServicedProtocolError::Ok);
        EXPECT_EQ(decoded.request.request_id, request.request_id);
        EXPECT_EQ(decoded.request.method, method);
        EXPECT_EQ(decoded.request.enumeration_cursor, method == ServicedMethod::Enumerate ? 7U : 0U);
        EXPECT_EQ(decoded.request.service_identity,
                  method == ServicedMethod::Enumerate ? kServicedInvalidServiceIdentity : ServiceIdentity(7));
        EXPECT_EQ(decoded.request.expected_transition_generation, generation);
        EXPECT_EQ(decoded.sender_endpoint_identity, endpoint.endpoint_identity);
        EXPECT_EQ(decoded.sender_process_identity, endpoint.process_identity);
        EXPECT_EQ(decoded.sender_task_identity, endpoint.task_identity);
        EXPECT_EQ(decoded.authority_identity, all_authority.authority_identity);
    }

    // Inspect/control and service scope are independent retained authorities.
    const RequestFrame query_frame = EncodeRequest(Request(ServicedMethod::Query));
    ServicedControlAuthoritySnapshotV1 exact_inspect = Authority(ServiceIdentity(7), kServicedRightInspect);
    ServicedValidatedRequestV1 decoded{};
    EXPECT_EQ(ServicedValidateRequestV1(query_frame.data(), static_cast<u32>(query_frame.size()), &endpoint,
                                        &exact_inspect, &decoded)
                  .error,
              ServicedProtocolError::Ok);
    const RequestFrame start_frame = EncodeRequest(Request(ServicedMethod::Start, 60, 7, 9));
    ExpectRequestFailure(start_frame, &endpoint, &exact_inspect, ServicedProtocolError::PermissionDenied);
    ServicedControlAuthoritySnapshotV1 exact_control = Authority(ServiceIdentity(7), kServicedRightControl);
    EXPECT_EQ(ServicedValidateRequestV1(start_frame.data(), static_cast<u32>(start_frame.size()), &endpoint,
                                        &exact_control, &decoded)
                  .error,
              ServicedProtocolError::Ok);
    ExpectRequestFailure(query_frame, &endpoint, &exact_control, ServicedProtocolError::PermissionDenied);
    ServicedControlAuthoritySnapshotV1 wrong_scope = Authority(ServiceIdentity(8), kServicedRightInspect);
    ExpectRequestFailure(query_frame, &endpoint, &wrong_scope, ServicedProtocolError::AuthorityScopeMismatch);
    const RequestFrame enumerate_frame = EncodeRequest(Request(ServicedMethod::Enumerate, 61, 7));
    ExpectRequestFailure(enumerate_frame, &endpoint, &exact_inspect, ServicedProtocolError::AuthorityScopeMismatch);

    // Endpoint identity and replay state cannot be forged by payload bytes.
    ServicedControlAuthoritySnapshotV1 wrong_holder = all_authority;
    wrong_holder.holder_endpoint_identity++;
    ExpectRequestFailure(query_frame, &endpoint, &wrong_holder, ServicedProtocolError::AuthorityEndpointMismatch);
    endpoint.last_committed_request_sequence = 50;
    ExpectRequestFailure(query_frame, &endpoint, &all_authority, ServicedProtocolError::ReplayedRequest);
    endpoint = Endpoint(49);
    EXPECT_EQ(ServicedValidateRequestV1(query_frame.data(), static_cast<u32>(query_frame.size()), &endpoint,
                                        &all_authority, &decoded)
                  .error,
              ServicedProtocolError::Ok);
    ExpectRequestFailure(query_frame, &endpoint, nullptr, ServicedProtocolError::AuthorityRequired);

    // Malformed encodes are transactional.
    RequestFrame untouched{};
    untouched.fill(0xA5);
    const RequestFrame before = untouched;
    EXPECT_EQ(ServicedEncodeRequestV1(untouched.data(), static_cast<u32>(untouched.size()),
                                      Request(static_cast<ServicedMethod>(99)))
                  .error,
              ServicedProtocolError::WrongMethod);
    EXPECT_TRUE(untouched == before);
    EXPECT_EQ(ServicedEncodeRequestV1(untouched.data(), static_cast<u32>(untouched.size()),
                                      Request(ServicedMethod::Enumerate, 50, kServicedMaximumServices))
                  .error,
              ServicedProtocolError::InvalidServiceSlot);
    EXPECT_TRUE(untouched == before);
    EXPECT_EQ(ServicedEncodeRequestV1(untouched.data(), static_cast<u32>(untouched.size()),
                                      Request(ServicedMethod::Query, 50, 7, 1))
                  .error,
              ServicedProtocolError::InvalidRequestShape);
    EXPECT_TRUE(untouched == before);

    // Route, kind, duplicate method tag, reserved bytes, and selector bounds
    // are independent confusion boundaries.
    {
        RequestFrame bad = query_frame;
        WriteLe32(bad.data() + kEnvelopeServiceOffset, kServicedServiceId + 1);
        ExpectRequestFailure(bad, &endpoint, &all_authority, ServicedProtocolError::WrongService);
        bad = query_frame;
        WriteLe16(bad.data() + kEnvelopeKindOffset, static_cast<u16>(MessageKind::Reply));
        ExpectRequestFailure(bad, &endpoint, &all_authority, ServicedProtocolError::WrongKind);
        bad = query_frame;
        WriteLe32(bad.data() + kRequestPayloadMethodOffset, static_cast<u32>(ServicedMethod::Start));
        ExpectRequestFailure(bad, &endpoint, &all_authority, ServicedProtocolError::PayloadMethodMismatch);
        bad = query_frame;
        WriteLe32(bad.data() + kRequestPayloadReservedOffset, 1);
        ExpectRequestFailure(bad, &endpoint, &all_authority, ServicedProtocolError::ReservedNonZero);
        bad = query_frame;
        WriteLe32(bad.data() + kRequestPayloadReserved2Offset, 1);
        ExpectRequestFailure(bad, &endpoint, &all_authority, ServicedProtocolError::ReservedNonZero);
        bad = query_frame;
        WriteLe32(bad.data() + kRequestPayloadCursorOffset, kServicedMaximumServices);
        ExpectRequestFailure(bad, &endpoint, &all_authority, ServicedProtocolError::InvalidServiceSlot);
        bad = query_frame;
        WriteLe64(bad.data() + kRequestPayloadIdentityOffset, kServicedInvalidServiceIdentity);
        ExpectRequestFailure(bad, &endpoint, &all_authority, ServicedProtocolError::InvalidRequestShape);
        bad = query_frame;
        WriteLe64(bad.data() + kRequestPayloadGenerationOffset, 1);
        ExpectRequestFailure(bad, &endpoint, &all_authority, ServicedProtocolError::InvalidRequestShape);
    }

    // Aliases are rejected before any output or snapshot mutation. In
    // particular, casting hostile bytes to an authority snapshot cannot work.
    {
        RequestFrame frame = query_frame;
        auto* aliased_output = reinterpret_cast<ServicedValidatedRequestV1*>(frame.data());
        EXPECT_EQ(ServicedValidateRequestV1(frame.data(), static_cast<u32>(frame.size()), &endpoint, &all_authority,
                                            aliased_output)
                      .error,
                  ServicedProtocolError::AliasedOutput);
        ServicedValidatedRequestV1 output{};
        Poison(&output);
        auto* hostile_endpoint = reinterpret_cast<const ServicedEndpointSnapshotV1*>(frame.data());
        EXPECT_EQ(ServicedValidateRequestV1(frame.data(), static_cast<u32>(frame.size()), hostile_endpoint,
                                            &all_authority, &output)
                      .error,
                  ServicedProtocolError::SnapshotAliasesMessage);
        EXPECT_EQ(output.authority_identity, ~0ULL);
        Poison(&output);
        auto* hostile_authority = reinterpret_cast<const ServicedControlAuthoritySnapshotV1*>(frame.data());
        EXPECT_EQ(ServicedValidateRequestV1(frame.data(), static_cast<u32>(frame.size()), &endpoint, hostile_authority,
                                            &output)
                      .error,
                  ServicedProtocolError::SnapshotAliasesMessage);
        EXPECT_EQ(output.authority_identity, ~0ULL);
    }

    // Status rows have exact phase/PID/generation, restart, and bounded-name
    // representation. No Process pointer or authoritative PID appears in a
    // request; the PID below is serviced-authored reply state only.
    ServicedStatusRowV1 row = Row();
    EXPECT_TRUE(ServicedStatusRowIsCanonicalV1(row));
    EXPECT_TRUE(ServicedStatusRowIsCanonicalV1(Row(7, ServicedInstancePhase::Stopping, 9, 700)));
    EXPECT_TRUE(ServicedStatusRowIsCanonicalV1(Row(7, ServicedInstancePhase::Starting, 9, 0)));
    EXPECT_TRUE(ServicedStatusRowIsCanonicalV1(Row(7, ServicedInstancePhase::Exited, 9, 0)));
    EXPECT_TRUE(ServicedStatusRowIsCanonicalV1(Row(7, ServicedInstancePhase::Failed, 9, 0)));
    EXPECT_TRUE(ServicedStatusRowIsCanonicalV1(Row(7, ServicedInstancePhase::GenerationExhausted, ~0ULL, 0)));
    ServicedStatusRowV1 bad_row = row;
    bad_row.pid = 0;
    EXPECT_FALSE(ServicedStatusRowIsCanonicalV1(bad_row));
    bad_row = row;
    bad_row.name[bad_row.name_length] = 'x';
    EXPECT_FALSE(ServicedStatusRowIsCanonicalV1(bad_row));
    bad_row = row;
    bad_row.name[0] = '/';
    EXPECT_FALSE(ServicedStatusRowIsCanonicalV1(bad_row));
    bad_row = row;
    bad_row.restarts_in_window = bad_row.lifetime_restarts + 1;
    EXPECT_FALSE(ServicedStatusRowIsCanonicalV1(bad_row));
    bad_row = Row(7, ServicedInstancePhase::Stopping, 9, 0);
    EXPECT_FALSE(ServicedStatusRowIsCanonicalV1(bad_row));

    for (ServicedMethod method : methods)
    {
        const ServicedReplyV1 reply = SuccessReply(method, 80 + static_cast<u32>(method));
        const ReplyFrame frame = EncodeReply(reply);
        ServicedReplyV1 decoded_reply{};
        const ServicedRequestV1 expected = Request(method, reply.request_id);
        EXPECT_EQ(ServicedValidateReplyV1(frame.data(), static_cast<u32>(frame.size()), expected, &decoded_reply).error,
                  ServicedProtocolError::Ok);
        EXPECT_EQ(decoded_reply.request_id, reply.request_id);
        EXPECT_EQ(decoded_reply.method, method);
        EXPECT_EQ(decoded_reply.status, ServicedReplyStatus::Success);
        EXPECT_EQ(decoded_reply.service.service_identity, reply.service.service_identity);
        EXPECT_EQ(decoded_reply.service.service_slot, reply.service.service_slot);
        EXPECT_EQ(decoded_reply.service.pid, reply.service.pid);
        EXPECT_EQ(decoded_reply.service.name_length, reply.service.name_length);
    }

    // End-of-list and failure replies carry no stale service state.
    ServicedReplyV1 end{};
    end.request_id = 100;
    end.method = ServicedMethod::Enumerate;
    end.status = ServicedReplyStatus::EndOfEnumeration;
    end.next_cursor = kServicedEnumerationEnd;
    ReplyFrame end_frame = EncodeReply(end);
    ServicedReplyV1 decoded_reply{};
    EXPECT_EQ(ServicedValidateReplyV1(end_frame.data(), static_cast<u32>(end_frame.size()),
                                      Request(end.method, end.request_id, 0), &decoded_reply)
                  .error,
              ServicedProtocolError::Ok);
    EXPECT_EQ(decoded_reply.status, ServicedReplyStatus::EndOfEnumeration);
    ServicedReplyV1 failure{};
    failure.request_id = 101;
    failure.method = ServicedMethod::Start;
    failure.status = ServicedReplyStatus::StaleGeneration;
    ReplyFrame failure_frame = EncodeReply(failure);
    EXPECT_EQ(ServicedValidateReplyV1(failure_frame.data(), static_cast<u32>(failure_frame.size()),
                                      Request(failure.method, failure.request_id), &decoded_reply)
                  .error,
              ServicedProtocolError::Ok);

    // Hostile reply fields cannot change route, request association, status
    // shape, reserved bytes, phase, PID, or name canonicality.
    {
        const ServicedReplyV1 reply = SuccessReply(ServicedMethod::Query, 120);
        const ServicedRequestV1 expected = Request(reply.method, reply.request_id);
        ReplyFrame bad = EncodeReply(reply);
        WriteLe64(bad.data() + kReplyPayloadSequenceOffset, reply.request_id + 1);
        EXPECT_EQ(ServicedValidateReplyV1(bad.data(), static_cast<u32>(bad.size()), expected, &decoded_reply).error,
                  ServicedProtocolError::RequestIdMismatch);
        bad = EncodeReply(reply);
        WriteLe32(bad.data() + kReplyPayloadMethodOffset, static_cast<u32>(ServicedMethod::Stop));
        EXPECT_EQ(ServicedValidateReplyV1(bad.data(), static_cast<u32>(bad.size()), expected, &decoded_reply).error,
                  ServicedProtocolError::PayloadMethodMismatch);
        bad = EncodeReply(reply);
        WriteLe32(bad.data() + kReplyPayloadStatusOffset, 99);
        EXPECT_EQ(ServicedValidateReplyV1(bad.data(), static_cast<u32>(bad.size()), expected, &decoded_reply).error,
                  ServicedProtocolError::InvalidReplyStatus);
        bad = EncodeReply(reply);
        bad[kReplyPayloadReservedOffset] = 1;
        EXPECT_EQ(ServicedValidateReplyV1(bad.data(), static_cast<u32>(bad.size()), expected, &decoded_reply).error,
                  ServicedProtocolError::ReservedNonZero);
        bad = EncodeReply(reply);
        bad[kReplyPayloadPhaseOffset] = static_cast<u8>(ServicedInstancePhase::Running);
        WriteLe64(bad.data() + kReplyPayloadPidOffset, 0);
        EXPECT_EQ(ServicedValidateReplyV1(bad.data(), static_cast<u32>(bad.size()), expected, &decoded_reply).error,
                  ServicedProtocolError::MalformedStatusRow);
        bad = EncodeReply(reply);
        bad[kReplyPayloadPolicyOffset] = 0xFF;
        EXPECT_EQ(ServicedValidateReplyV1(bad.data(), static_cast<u32>(bad.size()), expected, &decoded_reply).error,
                  ServicedProtocolError::InvalidRestartPolicy);
        bad = EncodeReply(reply);
        bad[kReplyPayloadNameOffset] = '/';
        EXPECT_EQ(ServicedValidateReplyV1(bad.data(), static_cast<u32>(bad.size()), expected, &decoded_reply).error,
                  ServicedProtocolError::InvalidServiceName);
        bad = EncodeReply(reply);
        EXPECT_EQ(ServicedValidateReplyV1(bad.data(), static_cast<u32>(bad.size()),
                                          Request(reply.method, reply.request_id, 8), &decoded_reply)
                      .error,
                  ServicedProtocolError::ReplyTargetMismatch);
        bad = failure_frame;
        WriteLe64(bad.data() + kReplyPayloadServiceIdentityOffset, ServiceIdentity(7));
        EXPECT_EQ(ServicedValidateReplyV1(bad.data(), static_cast<u32>(bad.size()),
                                          Request(failure.method, failure.request_id), &decoded_reply)
                      .error,
                  ServicedProtocolError::MalformedReplyCombination);

        const ServicedReplyV1 enumeration = SuccessReply(ServicedMethod::Enumerate, 121);
        bad = EncodeReply(enumeration);
        EXPECT_EQ(ServicedValidateReplyV1(bad.data(), static_cast<u32>(bad.size()),
                                          Request(ServicedMethod::Enumerate, 121, 8), &decoded_reply)
                      .error,
                  ServicedProtocolError::ReplyTargetMismatch);
    }

    // Unaligned frames and deterministic randomized scalar round trips.
    {
        std::array<u8, kServicedRequestV1MessageBytes + 1> storage{};
        const ServicedRequestV1 request = Request(ServicedMethod::Restart, 150, 2, ~0ULL);
        EXPECT_EQ(ServicedEncodeRequestV1(storage.data() + 1, kServicedRequestV1MessageBytes, request).error,
                  ServicedProtocolError::Ok);
        endpoint = Endpoint(149);
        EXPECT_EQ(ServicedValidateRequestV1(storage.data() + 1, kServicedRequestV1MessageBytes, &endpoint,
                                            &all_authority, &decoded)
                      .error,
                  ServicedProtocolError::Ok);
    }

    u64 random = 0x5e7b1cedc0ffeeULL;
    for (u32 iteration = 0; iteration < 2048; ++iteration)
    {
        const ServicedMethod method = methods[NextRandom(random) % 5];
        const u64 request_id = NextRandom(random) | 1ULL;
        const u32 slot = static_cast<u32>(NextRandom(random) % kServicedMaximumServices);
        const u64 generation =
            method == ServicedMethod::Enumerate || method == ServicedMethod::Query ? 0 : NextRandom(random);
        const ServicedRequestV1 request = Request(method, request_id, slot, generation);
        const RequestFrame frame = EncodeRequest(request);
        endpoint = Endpoint(request_id - 1);
        EXPECT_EQ(
            ServicedValidateRequestV1(frame.data(), static_cast<u32>(frame.size()), &endpoint, &all_authority, &decoded)
                .error,
            ServicedProtocolError::Ok);

        ServicedReplyV1 reply = SuccessReply(method, request_id);
        reply.service.service_slot = slot;
        reply.service.service_identity = ServiceIdentity(slot);
        reply.service.transition_generation = NextRandom(random) | 1ULL;
        reply.service.pid = NextRandom(random) | 1ULL;
        reply.service.lifetime_restarts = static_cast<u32>(NextRandom(random));
        reply.service.restarts_in_window =
            reply.service.lifetime_restarts == 0
                ? 0
                : static_cast<u32>(NextRandom(random) % (static_cast<u64>(reply.service.lifetime_restarts) + 1ULL));
        const ReplyFrame reply_frame = EncodeReply(reply);
        EXPECT_EQ(
            ServicedValidateReplyV1(reply_frame.data(), static_cast<u32>(reply_frame.size()), request, &decoded_reply)
                .error,
            ServicedProtocolError::Ok);
        EXPECT_EQ(decoded_reply.service.service_slot, slot);
        EXPECT_EQ(decoded_reply.service.service_identity, ServiceIdentity(slot));
        EXPECT_EQ(decoded_reply.service.transition_generation, reply.service.transition_generation);
    }

    EXPECT_STREQ(ServicedProtocolErrorName(ServicedProtocolError::PermissionDenied), "permission-denied");
    EXPECT_STREQ(ServicedProtocolErrorName(static_cast<ServicedProtocolError>(0xFF)), "unknown");
    return duetos_host_test::finish_main("serviced_protocol");
}
