#include "core/serviced_protocol.h"

namespace duetos::core
{

namespace
{

constexpr u32 kRequestMethodOffset = 8;
constexpr u32 kRequestReservedOffset = 12;
constexpr u32 kRequestCursorOffset = 16;
constexpr u32 kRequestReserved2Offset = 20;
constexpr u32 kRequestServiceIdentityOffset = 24;
constexpr u32 kRequestExpectedGenerationOffset = 32;

constexpr u32 kReplyMethodOffset = 8;
constexpr u32 kReplyStatusOffset = 12;
constexpr u32 kReplyRequestSequenceOffset = 16;
constexpr u32 kReplyServiceIdentityOffset = 24;
constexpr u32 kReplyServiceSlotOffset = 32;
constexpr u32 kReplyNextCursorOffset = 36;
constexpr u32 kReplyTransitionGenerationOffset = 40;
constexpr u32 kReplyPidOffset = 48;
constexpr u32 kReplyLifetimeRestartsOffset = 56;
constexpr u32 kReplyWindowRestartsOffset = 60;
constexpr u32 kReplyLastSpawnOffset = 64;
constexpr u32 kReplyLastExitOffset = 72;
constexpr u32 kReplyPhaseOffset = 80;
constexpr u32 kReplyRestartPolicyOffset = 81;
constexpr u32 kReplyAutostartOffset = 82;
constexpr u32 kReplyReservedOffset = 83;
constexpr u32 kReplyNameLengthOffset = 84;
constexpr u32 kReplyReserved2Offset = 85;
constexpr u32 kReplyNameOffset = 88;

constexpr ipc::PayloadVersionRule kRequestRules[] = {
    {kServicedProtocolVersion1, kServicedPayloadV1KnownFlags, kServicedRequestV1PayloadBytes,
     kServicedRequestV1PayloadBytes},
};
constexpr ipc::PayloadVersionRule kReplyRules[] = {
    {kServicedProtocolVersion1, kServicedPayloadV1KnownFlags, kServicedReplyV1PayloadBytes,
     kServicedReplyV1PayloadBytes},
};

u32 ReadLe32(const u8* bytes)
{
    return static_cast<u32>(bytes[0]) | (static_cast<u32>(bytes[1]) << 8U) | (static_cast<u32>(bytes[2]) << 16U) |
           (static_cast<u32>(bytes[3]) << 24U);
}

u64 ReadLe64(const u8* bytes)
{
    return static_cast<u64>(ReadLe32(bytes)) | (static_cast<u64>(ReadLe32(bytes + 4)) << 32U);
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

void CopyBytes(u8* destination, const u8* source, u32 count)
{
    for (u32 index = 0; index < count; ++index)
        destination[index] = source[index];
}

bool RangeIsValid(const void* pointer, u64 bytes)
{
    if (pointer == nullptr || bytes == 0)
        return false;
    const uptr begin = reinterpret_cast<uptr>(pointer);
    return static_cast<uptr>(bytes) <= ~static_cast<uptr>(0) - begin;
}

bool RangesOverlap(const void* left, u64 left_bytes, const void* right, u64 right_bytes)
{
    const uptr left_begin = reinterpret_cast<uptr>(left);
    const uptr right_begin = reinterpret_cast<uptr>(right);
    return left_begin < right_begin + static_cast<uptr>(right_bytes) &&
           right_begin < left_begin + static_cast<uptr>(left_bytes);
}

bool MethodIsValid(ServicedMethod method)
{
    switch (method)
    {
    case ServicedMethod::Enumerate:
    case ServicedMethod::Query:
    case ServicedMethod::Start:
    case ServicedMethod::Stop:
    case ServicedMethod::Restart:
        return true;
    }
    return false;
}

bool MethodIsControl(ServicedMethod method)
{
    return method == ServicedMethod::Start || method == ServicedMethod::Stop || method == ServicedMethod::Restart;
}

bool ReplyStatusIsValid(ServicedReplyStatus status)
{
    switch (status)
    {
    case ServicedReplyStatus::Success:
    case ServicedReplyStatus::EndOfEnumeration:
    case ServicedReplyStatus::NotFound:
    case ServicedReplyStatus::StaleGeneration:
    case ServicedReplyStatus::Denied:
    case ServicedReplyStatus::Busy:
    case ServicedReplyStatus::GenerationExhausted:
    case ServicedReplyStatus::ServiceFailure:
        return true;
    }
    return false;
}

bool PhaseIsValid(ServicedInstancePhase phase)
{
    switch (phase)
    {
    case ServicedInstancePhase::Stopped:
    case ServicedInstancePhase::Starting:
    case ServicedInstancePhase::Running:
    case ServicedInstancePhase::Exited:
    case ServicedInstancePhase::Failed:
    case ServicedInstancePhase::GenerationExhausted:
    case ServicedInstancePhase::Stopping:
        return true;
    }
    return false;
}

bool RestartPolicyIsValid(ServicedRestartPolicy policy)
{
    switch (policy)
    {
    case ServicedRestartPolicy::Never:
    case ServicedRestartPolicy::Always:
    case ServicedRestartPolicy::OnFailure:
        return true;
    }
    return false;
}

bool ServiceNameByteIsValid(u8 byte)
{
    return (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') || (byte >= '0' && byte <= '9') ||
           byte == '_' || byte == '-' || byte == '.';
}

bool ServiceNameIsCanonical(const ServicedStatusRowV1& row)
{
    if (row.name_length == 0 || row.name_length > kServicedServiceNameCapacity)
        return false;
    for (u32 index = 0; index < row.name_length; ++index)
    {
        if (!ServiceNameByteIsValid(row.name[index]))
            return false;
    }
    for (u32 index = row.name_length; index < kServicedServiceNameCapacity; ++index)
    {
        if (row.name[index] != 0)
            return false;
    }
    return true;
}

bool StatusRowIsZero(const ServicedStatusRowV1& row)
{
    if (row.service_identity != 0 || row.service_slot != 0 || row.transition_generation != 0 || row.pid != 0 ||
        row.lifetime_restarts != 0 || row.restarts_in_window != 0 || row.last_spawn_ns != 0 || row.last_exit_ns != 0 ||
        static_cast<u8>(row.phase) != 0 || static_cast<u8>(row.restart_policy) != 0 || row.autostart != 0 ||
        row.name_length != 0)
    {
        return false;
    }
    for (u32 index = 0; index < kServicedServiceNameCapacity; ++index)
    {
        if (row.name[index] != 0)
            return false;
    }
    return true;
}

ServicedProtocolResult Result(ServicedProtocolError error,
                              ipc::MessageValidationError envelope_error = ipc::MessageValidationError::Ok,
                              ipc::PayloadValidationError payload_error = ipc::PayloadValidationError::Ok)
{
    return ServicedProtocolResult{error, envelope_error, payload_error};
}

ServicedProtocolError ValidateRequestShape(const ServicedRequestV1& request)
{
    if (request.request_id == 0)
        return ServicedProtocolError::RequestIdMismatch;
    if (!MethodIsValid(request.method))
        return ServicedProtocolError::WrongMethod;
    if (request.enumeration_cursor >= kServicedMaximumServices)
        return ServicedProtocolError::InvalidServiceSlot;
    const bool exact_identity = request.service_identity != kServicedInvalidServiceIdentity &&
                                request.service_identity != kServicedAllServicesScope;
    if (request.method == ServicedMethod::Enumerate)
    {
        if (request.service_identity != kServicedInvalidServiceIdentity || request.expected_transition_generation != 0)
        {
            return ServicedProtocolError::InvalidRequestShape;
        }
    }
    else if (request.enumeration_cursor != 0 || !exact_identity ||
             (request.method == ServicedMethod::Query && request.expected_transition_generation != 0))
    {
        return ServicedProtocolError::InvalidRequestShape;
    }
    return ServicedProtocolError::Ok;
}

ServicedProtocolError ValidateReplyShape(const ServicedReplyV1& reply)
{
    if (reply.request_id == 0)
        return ServicedProtocolError::RequestIdMismatch;
    if (!MethodIsValid(reply.method))
        return ServicedProtocolError::WrongMethod;
    if (!ReplyStatusIsValid(reply.status))
        return ServicedProtocolError::InvalidReplyStatus;

    if (reply.status == ServicedReplyStatus::Success)
    {
        if (!ServicedStatusRowIsCanonicalV1(reply.service))
            return !PhaseIsValid(reply.service.phase)
                       ? ServicedProtocolError::InvalidPhase
                       : (!RestartPolicyIsValid(reply.service.restart_policy)
                              ? ServicedProtocolError::InvalidRestartPolicy
                              : (!ServiceNameIsCanonical(reply.service) ? ServicedProtocolError::InvalidServiceName
                                                                        : ServicedProtocolError::MalformedStatusRow));
        if (reply.method == ServicedMethod::Enumerate)
        {
            if (reply.next_cursor != kServicedEnumerationEnd &&
                (reply.next_cursor >= kServicedMaximumServices || reply.next_cursor <= reply.service.service_slot))
            {
                return ServicedProtocolError::MalformedReplyCombination;
            }
        }
        else if (reply.next_cursor != 0)
        {
            return ServicedProtocolError::MalformedReplyCombination;
        }
        return ServicedProtocolError::Ok;
    }

    if (!StatusRowIsZero(reply.service))
        return ServicedProtocolError::MalformedReplyCombination;
    if (reply.status == ServicedReplyStatus::EndOfEnumeration)
    {
        if (reply.method != ServicedMethod::Enumerate || reply.next_cursor != kServicedEnumerationEnd)
            return ServicedProtocolError::MalformedReplyCombination;
    }
    else if (reply.next_cursor != 0)
    {
        return ServicedProtocolError::MalformedReplyCombination;
    }
    return ServicedProtocolError::Ok;
}

ServicedProtocolResult EncodePayloadPrefix(u8* payload, u32 payload_bytes, const ipc::PayloadVersionRule* rules)
{
    const ipc::PayloadValidationError error = ipc::PayloadEncodeHeader(
        payload, payload_bytes, kServicedProtocolVersion1, kServicedPayloadV1KnownFlags, rules, 1);
    return error == ipc::PayloadValidationError::Ok
               ? Result(ServicedProtocolError::Ok)
               : Result(ServicedProtocolError::PayloadRejected, ipc::MessageValidationError::Ok, error);
}

ServicedProtocolResult ValidateEnvelopeAndPayload(const void* message, u32 message_bytes, u32 exact_message_bytes,
                                                  ipc::MessageKind kind, ServicedMethod expected_method,
                                                  u64 expected_request_id, const ipc::PayloadVersionRule* rules,
                                                  ipc::MessageView* view_out)
{
    ipc::MessageView view{};
    const ipc::MessageValidationError envelope_error = ipc::MessageValidate(message, message_bytes, &view);
    if (envelope_error != ipc::MessageValidationError::Ok)
        return Result(ServicedProtocolError::EnvelopeRejected, envelope_error);
    if (view.total_size != exact_message_bytes)
        return Result(ServicedProtocolError::WrongMessageSize);
    if (view.service_id != kServicedServiceId)
        return Result(ServicedProtocolError::WrongService);
    if (view.method_id != static_cast<u32>(expected_method))
        return Result(ServicedProtocolError::WrongMethod);
    if (view.kind != kind)
        return Result(ServicedProtocolError::WrongKind);
    if (expected_request_id != 0 && view.request_id != expected_request_id)
        return Result(ServicedProtocolError::RequestIdMismatch);

    const u8* payload = static_cast<const u8*>(message) + view.payload_offset;
    ipc::VersionedPayloadView payload_view{};
    const ipc::PayloadValidationError payload_error =
        ipc::PayloadValidate(payload, view.payload_size, rules, 1, &payload_view);
    if (payload_error != ipc::PayloadValidationError::Ok)
        return Result(ServicedProtocolError::PayloadRejected, ipc::MessageValidationError::Ok, payload_error);
    *view_out = view;
    return Result(ServicedProtocolError::Ok);
}

void DecodeStatusRow(const u8* payload, ServicedStatusRowV1* row)
{
    row->service_identity = ReadLe64(payload + kReplyServiceIdentityOffset);
    row->service_slot = ReadLe32(payload + kReplyServiceSlotOffset);
    row->transition_generation = ReadLe64(payload + kReplyTransitionGenerationOffset);
    row->pid = ReadLe64(payload + kReplyPidOffset);
    row->lifetime_restarts = ReadLe32(payload + kReplyLifetimeRestartsOffset);
    row->restarts_in_window = ReadLe32(payload + kReplyWindowRestartsOffset);
    row->last_spawn_ns = ReadLe64(payload + kReplyLastSpawnOffset);
    row->last_exit_ns = ReadLe64(payload + kReplyLastExitOffset);
    row->phase = static_cast<ServicedInstancePhase>(payload[kReplyPhaseOffset]);
    row->restart_policy = static_cast<ServicedRestartPolicy>(payload[kReplyRestartPolicyOffset]);
    row->autostart = payload[kReplyAutostartOffset];
    row->name_length = payload[kReplyNameLengthOffset];
    CopyBytes(row->name, payload + kReplyNameOffset, kServicedServiceNameCapacity);
}

void EncodeStatusRow(u8* payload, const ServicedStatusRowV1& row)
{
    WriteLe64(payload + kReplyServiceIdentityOffset, row.service_identity);
    WriteLe32(payload + kReplyServiceSlotOffset, row.service_slot);
    WriteLe64(payload + kReplyTransitionGenerationOffset, row.transition_generation);
    WriteLe64(payload + kReplyPidOffset, row.pid);
    WriteLe32(payload + kReplyLifetimeRestartsOffset, row.lifetime_restarts);
    WriteLe32(payload + kReplyWindowRestartsOffset, row.restarts_in_window);
    WriteLe64(payload + kReplyLastSpawnOffset, row.last_spawn_ns);
    WriteLe64(payload + kReplyLastExitOffset, row.last_exit_ns);
    payload[kReplyPhaseOffset] = static_cast<u8>(row.phase);
    payload[kReplyRestartPolicyOffset] = static_cast<u8>(row.restart_policy);
    payload[kReplyAutostartOffset] = row.autostart;
    payload[kReplyNameLengthOffset] = row.name_length;
    CopyBytes(payload + kReplyNameOffset, row.name, kServicedServiceNameCapacity);
}

} // namespace

bool ServicedEndpointSnapshotIsCanonicalV1(const ServicedEndpointSnapshotV1& snapshot)
{
    return snapshot.endpoint_identity != 0 && snapshot.process_identity != 0 && snapshot.task_identity != 0 &&
           snapshot.reserved == 0;
}

bool ServicedControlAuthoritySnapshotIsCanonicalV1(const ServicedControlAuthoritySnapshotV1& snapshot)
{
    const bool scope_valid = snapshot.service_identity_scope != kServicedInvalidServiceIdentity;
    return snapshot.authority_identity != 0 && snapshot.holder_endpoint_identity != 0 && scope_valid &&
           snapshot.rights != 0 && (snapshot.rights & ~kServicedKnownRights) == 0 && snapshot.reserved == 0;
}

bool ServicedStatusRowIsCanonicalV1(const ServicedStatusRowV1& row)
{
    if (row.service_identity == kServicedInvalidServiceIdentity || row.service_identity == kServicedAllServicesScope ||
        row.service_slot >= kServicedMaximumServices || !PhaseIsValid(row.phase) ||
        !RestartPolicyIsValid(row.restart_policy) || row.autostart > 1 ||
        row.restarts_in_window > row.lifetime_restarts || !ServiceNameIsCanonical(row))
    {
        return false;
    }

    switch (row.phase)
    {
    case ServicedInstancePhase::Stopped:
        return row.pid == 0;
    case ServicedInstancePhase::Starting:
    case ServicedInstancePhase::Exited:
    case ServicedInstancePhase::Failed:
        return row.transition_generation != 0 && row.pid == 0;
    case ServicedInstancePhase::Running:
    case ServicedInstancePhase::Stopping:
        return row.transition_generation != 0 && row.pid != 0;
    case ServicedInstancePhase::GenerationExhausted:
        return row.transition_generation == ~0ULL && row.pid == 0;
    }
    return false;
}

ServicedProtocolResult ServicedEncodeRequestV1(void* message, u32 message_bytes, const ServicedRequestV1& request)
{
    if (message == nullptr)
        return Result(ServicedProtocolError::NullArgument);
    if (message_bytes != kServicedRequestV1MessageBytes)
        return Result(ServicedProtocolError::WrongMessageSize);
    const ServicedRequestV1 snapshot = request;
    const ServicedProtocolError shape_error = ValidateRequestShape(snapshot);
    if (shape_error != ServicedProtocolError::Ok)
        return Result(shape_error);

    u8 encoded[kServicedRequestV1MessageBytes]{};
    ipc::MessageHeaderV1 header{ipc::MessageKind::Request, 0, kServicedServiceId, static_cast<u32>(snapshot.method),
                                snapshot.request_id};
    const ipc::MessageValidationError envelope_error =
        ipc::MessageEncodeHeaderV1(encoded, kServicedRequestV1MessageBytes, header);
    if (envelope_error != ipc::MessageValidationError::Ok)
        return Result(ServicedProtocolError::EnvelopeRejected, envelope_error);
    ServicedProtocolResult prefix =
        EncodePayloadPrefix(encoded + ipc::kMessageAbiHeaderV1Bytes, kServicedRequestV1PayloadBytes, kRequestRules);
    if (prefix.error != ServicedProtocolError::Ok)
        return prefix;
    u8* payload = encoded + ipc::kMessageAbiHeaderV1Bytes;
    WriteLe32(payload + kRequestMethodOffset, static_cast<u32>(snapshot.method));
    WriteLe32(payload + kRequestCursorOffset, snapshot.enumeration_cursor);
    WriteLe64(payload + kRequestServiceIdentityOffset, snapshot.service_identity);
    WriteLe64(payload + kRequestExpectedGenerationOffset, snapshot.expected_transition_generation);
    CopyBytes(static_cast<u8*>(message), encoded, kServicedRequestV1MessageBytes);
    return Result(ServicedProtocolError::Ok);
}

ServicedProtocolResult ServicedEncodeReplyV1(void* message, u32 message_bytes, const ServicedReplyV1& reply)
{
    if (message == nullptr)
        return Result(ServicedProtocolError::NullArgument);
    if (message_bytes != kServicedReplyV1MessageBytes)
        return Result(ServicedProtocolError::WrongMessageSize);
    const ServicedReplyV1 snapshot = reply;
    const ServicedProtocolError shape_error = ValidateReplyShape(snapshot);
    if (shape_error != ServicedProtocolError::Ok)
        return Result(shape_error);

    u8 encoded[kServicedReplyV1MessageBytes]{};
    ipc::MessageHeaderV1 header{ipc::MessageKind::Reply, 0, kServicedServiceId, static_cast<u32>(snapshot.method),
                                snapshot.request_id};
    const ipc::MessageValidationError envelope_error =
        ipc::MessageEncodeHeaderV1(encoded, kServicedReplyV1MessageBytes, header);
    if (envelope_error != ipc::MessageValidationError::Ok)
        return Result(ServicedProtocolError::EnvelopeRejected, envelope_error);
    ServicedProtocolResult prefix =
        EncodePayloadPrefix(encoded + ipc::kMessageAbiHeaderV1Bytes, kServicedReplyV1PayloadBytes, kReplyRules);
    if (prefix.error != ServicedProtocolError::Ok)
        return prefix;
    u8* payload = encoded + ipc::kMessageAbiHeaderV1Bytes;
    WriteLe32(payload + kReplyMethodOffset, static_cast<u32>(snapshot.method));
    WriteLe32(payload + kReplyStatusOffset, static_cast<u32>(snapshot.status));
    WriteLe64(payload + kReplyRequestSequenceOffset, snapshot.request_id);
    WriteLe32(payload + kReplyNextCursorOffset, snapshot.next_cursor);
    if (snapshot.status == ServicedReplyStatus::Success)
        EncodeStatusRow(payload, snapshot.service);
    CopyBytes(static_cast<u8*>(message), encoded, kServicedReplyV1MessageBytes);
    return Result(ServicedProtocolError::Ok);
}

ServicedProtocolResult ServicedValidateRequestV1(const void* message, u32 message_bytes,
                                                 const ServicedEndpointSnapshotV1* endpoint,
                                                 const ServicedControlAuthoritySnapshotV1* authority,
                                                 ServicedValidatedRequestV1* request_out)
{
    if (request_out == nullptr || !RangeIsValid(request_out, sizeof(*request_out)))
        return Result(ServicedProtocolError::NullArgument);
    if (message == nullptr || !RangeIsValid(message, message_bytes))
    {
        *request_out = ServicedValidatedRequestV1{};
        return Result(ServicedProtocolError::NullArgument);
    }
    if (RangesOverlap(message, message_bytes, request_out, sizeof(*request_out)))
        return Result(ServicedProtocolError::AliasedOutput);
    if (endpoint == nullptr)
    {
        *request_out = ServicedValidatedRequestV1{};
        return Result(ServicedProtocolError::NullArgument);
    }
    if (authority == nullptr)
    {
        *request_out = ServicedValidatedRequestV1{};
        return Result(ServicedProtocolError::AuthorityRequired);
    }
    if (!RangeIsValid(endpoint, sizeof(*endpoint)) || !RangeIsValid(authority, sizeof(*authority)))
    {
        *request_out = ServicedValidatedRequestV1{};
        return Result(ServicedProtocolError::NullArgument);
    }
    if (RangesOverlap(message, message_bytes, endpoint, sizeof(*endpoint)) ||
        RangesOverlap(message, message_bytes, authority, sizeof(*authority)))
    {
        return Result(ServicedProtocolError::SnapshotAliasesMessage);
    }
    if (RangesOverlap(request_out, sizeof(*request_out), endpoint, sizeof(*endpoint)) ||
        RangesOverlap(request_out, sizeof(*request_out), authority, sizeof(*authority)))
    {
        return Result(ServicedProtocolError::AliasedOutput);
    }

    const ServicedEndpointSnapshotV1 endpoint_snapshot = *endpoint;
    const ServicedControlAuthoritySnapshotV1 authority_snapshot = *authority;
    *request_out = ServicedValidatedRequestV1{};
    if (!ServicedEndpointSnapshotIsCanonicalV1(endpoint_snapshot))
        return Result(ServicedProtocolError::MalformedEndpoint);
    if (!ServicedControlAuthoritySnapshotIsCanonicalV1(authority_snapshot))
        return Result(ServicedProtocolError::MalformedAuthority);
    if (authority_snapshot.holder_endpoint_identity != endpoint_snapshot.endpoint_identity)
        return Result(ServicedProtocolError::AuthorityEndpointMismatch);

    ipc::MessageView view{};
    ipc::MessageView route{};
    const ipc::MessageValidationError envelope_error = ipc::MessageValidate(message, message_bytes, &route);
    if (envelope_error != ipc::MessageValidationError::Ok)
        return Result(ServicedProtocolError::EnvelopeRejected, envelope_error);
    const ServicedMethod method = static_cast<ServicedMethod>(route.method_id);
    if (!MethodIsValid(method))
        return Result(ServicedProtocolError::WrongMethod);
    ServicedProtocolResult frame =
        ValidateEnvelopeAndPayload(message, message_bytes, kServicedRequestV1MessageBytes, ipc::MessageKind::Request,
                                   method, 0, kRequestRules, &view);
    if (frame.error != ServicedProtocolError::Ok)
        return frame;
    const u8* payload = static_cast<const u8*>(message) + view.payload_offset;
    if (ReadLe32(payload + kRequestMethodOffset) != static_cast<u32>(method))
        return Result(ServicedProtocolError::PayloadMethodMismatch);
    if (ReadLe32(payload + kRequestReservedOffset) != 0 || ReadLe32(payload + kRequestReserved2Offset) != 0)
        return Result(ServicedProtocolError::ReservedNonZero);

    ServicedRequestV1 decoded{view.request_id, method, ReadLe32(payload + kRequestCursorOffset),
                              ReadLe64(payload + kRequestServiceIdentityOffset),
                              ReadLe64(payload + kRequestExpectedGenerationOffset)};
    const ServicedProtocolError shape_error = ValidateRequestShape(decoded);
    if (shape_error != ServicedProtocolError::Ok)
        return Result(shape_error);
    if (decoded.request_id <= endpoint_snapshot.last_committed_request_sequence)
        return Result(ServicedProtocolError::ReplayedRequest);

    const u32 required_right = MethodIsControl(method) ? kServicedRightControl : kServicedRightInspect;
    if ((authority_snapshot.rights & required_right) == 0)
        return Result(ServicedProtocolError::PermissionDenied);
    if (method == ServicedMethod::Enumerate)
    {
        if (authority_snapshot.service_identity_scope != kServicedAllServicesScope)
            return Result(ServicedProtocolError::AuthorityScopeMismatch);
    }
    else if (authority_snapshot.service_identity_scope != kServicedAllServicesScope &&
             authority_snapshot.service_identity_scope != decoded.service_identity)
    {
        return Result(ServicedProtocolError::AuthorityScopeMismatch);
    }

    request_out->request = decoded;
    request_out->sender_endpoint_identity = endpoint_snapshot.endpoint_identity;
    request_out->sender_process_identity = endpoint_snapshot.process_identity;
    request_out->sender_task_identity = endpoint_snapshot.task_identity;
    request_out->authority_identity = authority_snapshot.authority_identity;
    request_out->authority_rights = authority_snapshot.rights;
    request_out->authority_scope = authority_snapshot.service_identity_scope;
    return Result(ServicedProtocolError::Ok);
}

ServicedProtocolResult ServicedValidateReplyV1(const void* message, u32 message_bytes,
                                               ServicedRequestV1 expected_request, ServicedReplyV1* reply_out)
{
    if (reply_out == nullptr || !RangeIsValid(reply_out, sizeof(*reply_out)))
        return Result(ServicedProtocolError::NullArgument);
    if (message == nullptr || !RangeIsValid(message, message_bytes))
    {
        *reply_out = ServicedReplyV1{};
        return Result(ServicedProtocolError::NullArgument);
    }
    if (RangesOverlap(message, message_bytes, reply_out, sizeof(*reply_out)))
        return Result(ServicedProtocolError::AliasedOutput);
    *reply_out = ServicedReplyV1{};
    const ServicedProtocolError expected_error = ValidateRequestShape(expected_request);
    if (expected_error != ServicedProtocolError::Ok)
        return Result(expected_error);

    ipc::MessageView view{};
    ServicedProtocolResult frame =
        ValidateEnvelopeAndPayload(message, message_bytes, kServicedReplyV1MessageBytes, ipc::MessageKind::Reply,
                                   expected_request.method, expected_request.request_id, kReplyRules, &view);
    if (frame.error != ServicedProtocolError::Ok)
        return frame;
    const u8* payload = static_cast<const u8*>(message) + view.payload_offset;
    if (ReadLe32(payload + kReplyMethodOffset) != static_cast<u32>(expected_request.method))
        return Result(ServicedProtocolError::PayloadMethodMismatch);
    if (ReadLe64(payload + kReplyRequestSequenceOffset) != expected_request.request_id)
        return Result(ServicedProtocolError::RequestIdMismatch);
    if (payload[kReplyReservedOffset] != 0 || payload[kReplyReserved2Offset] != 0 ||
        payload[kReplyReserved2Offset + 1] != 0 || payload[kReplyReserved2Offset + 2] != 0)
    {
        return Result(ServicedProtocolError::ReservedNonZero);
    }

    ServicedReplyV1 decoded{};
    decoded.request_id = view.request_id;
    decoded.method = expected_request.method;
    decoded.status = static_cast<ServicedReplyStatus>(ReadLe32(payload + kReplyStatusOffset));
    decoded.next_cursor = ReadLe32(payload + kReplyNextCursorOffset);
    DecodeStatusRow(payload, &decoded.service);
    const ServicedProtocolError shape_error = ValidateReplyShape(decoded);
    if (shape_error != ServicedProtocolError::Ok)
        return Result(shape_error);
    if (decoded.status == ServicedReplyStatus::Success)
    {
        if (expected_request.method == ServicedMethod::Enumerate)
        {
            if (decoded.service.service_slot < expected_request.enumeration_cursor)
                return Result(ServicedProtocolError::ReplyTargetMismatch);
        }
        else if (decoded.service.service_identity != expected_request.service_identity)
        {
            return Result(ServicedProtocolError::ReplyTargetMismatch);
        }
    }
    *reply_out = decoded;
    return Result(ServicedProtocolError::Ok);
}

const char* ServicedProtocolErrorName(ServicedProtocolError error)
{
    switch (error)
    {
    case ServicedProtocolError::Ok:
        return "ok";
    case ServicedProtocolError::NullArgument:
        return "null-argument";
    case ServicedProtocolError::AliasedOutput:
        return "aliased-output";
    case ServicedProtocolError::SnapshotAliasesMessage:
        return "snapshot-aliases-message";
    case ServicedProtocolError::WrongMessageSize:
        return "wrong-message-size";
    case ServicedProtocolError::EnvelopeRejected:
        return "envelope-rejected";
    case ServicedProtocolError::PayloadRejected:
        return "payload-rejected";
    case ServicedProtocolError::WrongService:
        return "wrong-service";
    case ServicedProtocolError::WrongMethod:
        return "wrong-method";
    case ServicedProtocolError::WrongKind:
        return "wrong-kind";
    case ServicedProtocolError::RequestIdMismatch:
        return "request-id-mismatch";
    case ServicedProtocolError::PayloadMethodMismatch:
        return "payload-method-mismatch";
    case ServicedProtocolError::ReservedNonZero:
        return "reserved-nonzero";
    case ServicedProtocolError::InvalidServiceSlot:
        return "invalid-service-slot";
    case ServicedProtocolError::InvalidRequestShape:
        return "invalid-request-shape";
    case ServicedProtocolError::ReplayedRequest:
        return "replayed-request";
    case ServicedProtocolError::MalformedEndpoint:
        return "malformed-endpoint";
    case ServicedProtocolError::AuthorityRequired:
        return "authority-required";
    case ServicedProtocolError::MalformedAuthority:
        return "malformed-authority";
    case ServicedProtocolError::AuthorityEndpointMismatch:
        return "authority-endpoint-mismatch";
    case ServicedProtocolError::AuthorityScopeMismatch:
        return "authority-scope-mismatch";
    case ServicedProtocolError::PermissionDenied:
        return "permission-denied";
    case ServicedProtocolError::InvalidReplyStatus:
        return "invalid-reply-status";
    case ServicedProtocolError::MalformedReplyCombination:
        return "malformed-reply-combination";
    case ServicedProtocolError::ReplyTargetMismatch:
        return "reply-target-mismatch";
    case ServicedProtocolError::MalformedStatusRow:
        return "malformed-status-row";
    case ServicedProtocolError::InvalidPhase:
        return "invalid-phase";
    case ServicedProtocolError::InvalidRestartPolicy:
        return "invalid-restart-policy";
    case ServicedProtocolError::InvalidServiceName:
        return "invalid-service-name";
    }
    return "unknown";
}

} // namespace duetos::core
