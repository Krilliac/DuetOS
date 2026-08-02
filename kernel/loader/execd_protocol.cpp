#include "loader/execd_protocol.h"

namespace duetos::loader
{

namespace
{

constexpr u32 kRequestSourceObjectRefOffset = 8;
constexpr u32 kRequestImmutablePolicyOffset = 16;
constexpr u32 kRequestFormatHintOffset = 20;
constexpr u32 kRequestReserved16Offset = 22;
constexpr u32 kRequestFlagsOffset = 24;
constexpr u32 kRequestDependencyCountOffset = 28;
constexpr u32 kRequestReserved64Offset = 32;

constexpr u32 kReplyStatusOffset = 8;
constexpr u32 kReplyReserved32AOffset = 12;
constexpr u32 kReplyLoadPlanObjectRefOffset = 16;
constexpr u32 kReplyImmutablePolicyOffset = 24;
constexpr u32 kReplyReserved32BOffset = 28;
constexpr u32 kReplySourceHashOffset = 32;

constexpr ipc::PayloadVersionRule kRequestPayloadRules[] = {
    {kExecdProtocolVersion1, kExecdPayloadV1KnownFlags, kExecdParseRequestV1PayloadBytes,
     kExecdParseRequestV1PayloadBytes},
};
constexpr ipc::PayloadVersionRule kReplyPayloadRules[] = {
    {kExecdProtocolVersion1, kExecdPayloadV1KnownFlags, kExecdParseReplyV1PayloadBytes, kExecdParseReplyV1PayloadBytes},
};

u16 ReadLe16(const u8* bytes)
{
    return static_cast<u16>(static_cast<u16>(bytes[0]) | (static_cast<u16>(bytes[1]) << 8U));
}

u32 ReadLe32(const u8* bytes)
{
    return static_cast<u32>(bytes[0]) | (static_cast<u32>(bytes[1]) << 8U) | (static_cast<u32>(bytes[2]) << 16U) |
           (static_cast<u32>(bytes[3]) << 24U);
}

u64 ReadLe64(const u8* bytes)
{
    return static_cast<u64>(ReadLe32(bytes)) | (static_cast<u64>(ReadLe32(bytes + 4)) << 32U);
}

void WriteLe16(u8* bytes, u16 value)
{
    bytes[0] = static_cast<u8>(value & 0xFFU);
    bytes[1] = static_cast<u8>((value >> 8U) & 0xFFU);
}

void WriteLe32(u8* bytes, u32 value)
{
    bytes[0] = static_cast<u8>(value & 0xFFU);
    bytes[1] = static_cast<u8>((value >> 8U) & 0xFFU);
    bytes[2] = static_cast<u8>((value >> 16U) & 0xFFU);
    bytes[3] = static_cast<u8>((value >> 24U) & 0xFFU);
}

void WriteLe64(u8* bytes, u64 value)
{
    WriteLe32(bytes, static_cast<u32>(value & 0xFFFFFFFFULL));
    WriteLe32(bytes + 4, static_cast<u32>(value >> 32U));
}

void CopyBytes(u8* destination, const u8* source, u32 bytes)
{
    for (u32 index = 0; index < bytes; ++index)
        destination[index] = source[index];
}

void ReadHash(const u8* bytes, Hash256* hash_out)
{
    for (u32 index = 0; index < 32; ++index)
        hash_out->bytes[index] = bytes[index];
}

void WriteHash(u8* bytes, const Hash256& hash)
{
    for (u32 index = 0; index < 32; ++index)
        bytes[index] = hash.bytes[index];
}

bool HashIsZero(const Hash256& hash)
{
    u8 aggregate = 0;
    for (u32 index = 0; index < 32; ++index)
        aggregate = static_cast<u8>(aggregate | hash.bytes[index]);
    return aggregate == 0;
}

bool HashEquals(const Hash256& left, const Hash256& right)
{
    u8 difference = 0;
    for (u32 index = 0; index < 32; ++index)
        difference = static_cast<u8>(difference | static_cast<u8>(left.bytes[index] ^ right.bytes[index]));
    return difference == 0;
}

bool PointerRangeIsValid(const void* pointer, u64 bytes)
{
    if (pointer == nullptr || bytes == 0)
        return false;
    const uptr begin = reinterpret_cast<uptr>(pointer);
    return static_cast<uptr>(bytes) <= ~static_cast<uptr>(0) - begin;
}

bool PointerRangesOverlap(const void* left, u64 left_bytes, const void* right, u64 right_bytes)
{
    const uptr left_begin = reinterpret_cast<uptr>(left);
    const uptr right_begin = reinterpret_cast<uptr>(right);
    const uptr left_end = left_begin + static_cast<uptr>(left_bytes);
    const uptr right_end = right_begin + static_cast<uptr>(right_bytes);
    return left_begin < right_end && right_begin < left_end;
}

bool ObjectReferenceIsValid(ExecdTransportObjectRef reference)
{
    return reference != 0 && reference <= kExecdTransportObjectRefMax;
}

bool FormatHintIsValid(ExecdFormatHint hint)
{
    switch (hint)
    {
    case ExecdFormatHint::AutoDetect:
    case ExecdFormatHint::Pe32Plus:
    case ExecdFormatHint::Pe32:
    case ExecdFormatHint::Elf64:
        return true;
    }
    return false;
}

bool ReplyStatusIsValid(ExecdReplyStatus status)
{
    switch (status)
    {
    case ExecdReplyStatus::Success:
    case ExecdReplyStatus::InvalidImage:
    case ExecdReplyStatus::UnsupportedFormat:
    case ExecdReplyStatus::PolicyRejected:
    case ExecdReplyStatus::Cancelled:
    case ExecdReplyStatus::ServiceFailure:
        return true;
    }
    return false;
}

ExecdProtocolResult Result(ExecdProtocolError error,
                           ipc::MessageValidationError envelope_error = ipc::MessageValidationError::Ok,
                           ipc::PayloadValidationError payload_error = ipc::PayloadValidationError::Ok)
{
    return ExecdProtocolResult{error, envelope_error, payload_error};
}

ExecdProtocolError ValidateRequestScalars(const ExecdParseRequestV1& request)
{
    if (request.request_id == 0)
        return ExecdProtocolError::RequestIdMismatch;
    if (!ObjectReferenceIsValid(request.source_object_ref))
        return ExecdProtocolError::InvalidObjectReference;
    if (request.immutable_policy_id != kExecdSourceImmutablePolicyV1)
        return ExecdProtocolError::UnsupportedImmutablePolicy;
    if (!FormatHintIsValid(request.format_hint))
        return ExecdProtocolError::UnsupportedFormatHint;
    if ((request.flags & ~kExecdParseV1KnownFlags) != 0)
        return ExecdProtocolError::UnsupportedFlags;
    if (request.dependency_count != 0)
        return ExecdProtocolError::DependenciesUnsupported;
    return ExecdProtocolError::Ok;
}

ExecdProtocolError ValidateReplyScalars(const ExecdParseReplyV1& reply)
{
    if (reply.request_id == 0)
        return ExecdProtocolError::RequestIdMismatch;
    if (!ReplyStatusIsValid(reply.status))
        return ExecdProtocolError::InvalidReplyStatus;

    if (reply.status == ExecdReplyStatus::Success)
    {
        if (!ObjectReferenceIsValid(reply.load_plan_object_ref))
            return ExecdProtocolError::InvalidObjectReference;
        if (reply.immutable_policy_id != kExecdLoadPlanImmutablePolicyV1)
            return ExecdProtocolError::UnsupportedImmutablePolicy;
        if (HashIsZero(reply.source_hash))
            return ExecdProtocolError::MissingSourceHash;
        return ExecdProtocolError::Ok;
    }

    if (reply.load_plan_object_ref != 0 || reply.immutable_policy_id != 0 || !HashIsZero(reply.source_hash))
        return ExecdProtocolError::MalformedStatusCombination;
    return ExecdProtocolError::Ok;
}

ExecdProtocolError ValidateSourceAuthority(const ExecdObjectTransferAuthorityV1& authority,
                                           ExecdTransportObjectRef expected_reference, u32 expected_policy)
{
    if (!ObjectReferenceIsValid(authority.transport_object_ref))
        return ExecdProtocolError::InvalidObjectReference;
    if (expected_reference != 0 && authority.transport_object_ref != expected_reference)
        return ExecdProtocolError::AuthorityReferenceMismatch;
    if (authority.object_kind != ExecdTransferredObjectKind::SourceImage)
        return ExecdProtocolError::AuthorityKindMismatch;
    if (authority.sealed != 1)
        return ExecdProtocolError::AuthorityNotSealed;
    if (authority.immutable_policy_id != kExecdSourceImmutablePolicyV1 ||
        authority.immutable_policy_id != expected_policy)
    {
        return ExecdProtocolError::AuthorityPolicyMismatch;
    }
    if (authority.object_bytes == 0 || authority.object_bytes > kExecdSourceObjectMaxBytes)
        return ExecdProtocolError::AuthoritySizeInvalid;
    if (HashIsZero(authority.object_hash))
        return ExecdProtocolError::MissingSourceHash;
    return ExecdProtocolError::Ok;
}

ExecdProtocolError ValidateLoadPlanAuthority(const ExecdObjectTransferAuthorityV1& authority,
                                             ExecdTransportObjectRef expected_reference, u32 expected_policy)
{
    if (!ObjectReferenceIsValid(authority.transport_object_ref))
        return ExecdProtocolError::InvalidObjectReference;
    if (authority.transport_object_ref != expected_reference)
        return ExecdProtocolError::AuthorityReferenceMismatch;
    if (authority.object_kind != ExecdTransferredObjectKind::LoadPlan)
        return ExecdProtocolError::AuthorityKindMismatch;
    if (authority.sealed != 1)
        return ExecdProtocolError::AuthorityNotSealed;
    if (authority.immutable_policy_id != kExecdLoadPlanImmutablePolicyV1 ||
        authority.immutable_policy_id != expected_policy)
    {
        return ExecdProtocolError::AuthorityPolicyMismatch;
    }
    if (authority.object_bytes < kExecdLoadPlanObjectMinBytes ||
        authority.object_bytes > kExecdLoadPlanObjectMaxBytes ||
        (authority.object_bytes - kLoadPlanV1HeaderBytes) % kLoadRegionV1Bytes != 0)
        return ExecdProtocolError::AuthoritySizeInvalid;
    return ExecdProtocolError::Ok;
}

ExecdProtocolResult ValidateEnvelope(const void* message, u32 message_bytes, u32 exact_message_bytes,
                                     ipc::MessageKind expected_kind, u32 expected_method, u64 expected_request_id,
                                     ipc::MessageView* view_out)
{
    ipc::MessageView view{};
    const ipc::MessageValidationError envelope_error = ipc::MessageValidate(message, message_bytes, &view);
    if (envelope_error != ipc::MessageValidationError::Ok)
        return Result(ExecdProtocolError::EnvelopeRejected, envelope_error);
    if (view.total_size != exact_message_bytes)
        return Result(ExecdProtocolError::WrongMessageSize);
    if (view.service_id != kExecdServiceId)
        return Result(ExecdProtocolError::WrongService);
    if (view.method_id != expected_method)
        return Result(ExecdProtocolError::WrongMethod);
    if (view.kind != expected_kind)
        return Result(ExecdProtocolError::WrongKind);
    if (expected_request_id != 0 && view.request_id != expected_request_id)
        return Result(ExecdProtocolError::RequestIdMismatch);
    *view_out = view;
    return Result(ExecdProtocolError::Ok);
}

ExecdProtocolResult ValidatePayload(const u8* payload, u32 payload_bytes, const ipc::PayloadVersionRule* rules,
                                    u32 rule_count)
{
    ipc::VersionedPayloadView payload_view{};
    const ipc::PayloadValidationError payload_error =
        ipc::PayloadValidate(payload, payload_bytes, rules, rule_count, &payload_view);
    if (payload_error != ipc::PayloadValidationError::Ok)
        return Result(ExecdProtocolError::PayloadRejected, ipc::MessageValidationError::Ok, payload_error);
    return Result(ExecdProtocolError::Ok);
}

template <typename T>
ExecdProtocolResult ValidateMessageAndOutputRanges(const void* message, u32 message_bytes, T* output)
{
    if (output == nullptr || !PointerRangeIsValid(output, sizeof(T)))
        return Result(ExecdProtocolError::NullArgument);
    if (message == nullptr || !PointerRangeIsValid(message, message_bytes))
    {
        *output = T{};
        return Result(ExecdProtocolError::NullArgument);
    }
    if (PointerRangesOverlap(message, message_bytes, output, sizeof(T)))
        return Result(ExecdProtocolError::AliasedOutput);
    return Result(ExecdProtocolError::Ok);
}

template <typename T>
ExecdProtocolResult SnapshotAuthority(const void* message, u32 message_bytes, const T* authority, T* authority_snapshot)
{
    if (authority == nullptr)
        return Result(ExecdProtocolError::AuthorityRequired);
    if (!PointerRangeIsValid(authority, sizeof(T)))
        return Result(ExecdProtocolError::NullArgument);
    if (PointerRangesOverlap(message, message_bytes, authority, sizeof(T)))
        return Result(ExecdProtocolError::AuthorityAliasesMessage);
    *authority_snapshot = *authority;
    return Result(ExecdProtocolError::Ok);
}

} // namespace

ExecdProtocolResult ExecdEncodeParseRequestV1(void* message, u32 message_bytes, const ExecdParseRequestV1& request)
{
    if (message == nullptr)
        return Result(ExecdProtocolError::NullArgument);
    if (message_bytes != kExecdParseRequestV1MessageBytes)
        return Result(ExecdProtocolError::WrongMessageSize);
    if (!PointerRangeIsValid(message, message_bytes))
        return Result(ExecdProtocolError::NullArgument);

    const ExecdParseRequestV1 canonical = request;
    const ExecdProtocolError semantic_error = ValidateRequestScalars(canonical);
    if (semantic_error != ExecdProtocolError::Ok)
        return Result(semantic_error);

    u8 staged[kExecdParseRequestV1MessageBytes]{};
    const ipc::MessageHeaderV1 envelope{ipc::MessageKind::Request, 0, kExecdServiceId, kExecdParseMethodId,
                                        canonical.request_id};
    const ipc::MessageValidationError envelope_error =
        ipc::MessageEncodeHeaderV1(staged, kExecdParseRequestV1MessageBytes, envelope);
    if (envelope_error != ipc::MessageValidationError::Ok)
        return Result(ExecdProtocolError::EnvelopeRejected, envelope_error);

    u8* payload = staged + ipc::kMessageAbiHeaderV1Bytes;
    const ipc::PayloadValidationError payload_error = ipc::PayloadEncodeHeader(
        payload, kExecdParseRequestV1PayloadBytes, kExecdProtocolVersion1, 0, kRequestPayloadRules, 1);
    if (payload_error != ipc::PayloadValidationError::Ok)
        return Result(ExecdProtocolError::PayloadRejected, ipc::MessageValidationError::Ok, payload_error);

    WriteLe64(payload + kRequestSourceObjectRefOffset, canonical.source_object_ref);
    WriteLe32(payload + kRequestImmutablePolicyOffset, canonical.immutable_policy_id);
    WriteLe16(payload + kRequestFormatHintOffset, static_cast<u16>(canonical.format_hint));
    WriteLe32(payload + kRequestFlagsOffset, canonical.flags);
    WriteLe32(payload + kRequestDependencyCountOffset, canonical.dependency_count);
    CopyBytes(static_cast<u8*>(message), staged, kExecdParseRequestV1MessageBytes);
    return Result(ExecdProtocolError::Ok);
}

ExecdProtocolResult ExecdEncodeParseReplyV1(void* message, u32 message_bytes, const ExecdParseReplyV1& reply)
{
    if (message == nullptr)
        return Result(ExecdProtocolError::NullArgument);
    if (message_bytes != kExecdParseReplyV1MessageBytes)
        return Result(ExecdProtocolError::WrongMessageSize);
    if (!PointerRangeIsValid(message, message_bytes))
        return Result(ExecdProtocolError::NullArgument);

    const ExecdParseReplyV1 canonical = reply;
    const ExecdProtocolError semantic_error = ValidateReplyScalars(canonical);
    if (semantic_error != ExecdProtocolError::Ok)
        return Result(semantic_error);

    u8 staged[kExecdParseReplyV1MessageBytes]{};
    const ipc::MessageHeaderV1 envelope{ipc::MessageKind::Reply, 0, kExecdServiceId, kExecdParseMethodId,
                                        canonical.request_id};
    const ipc::MessageValidationError envelope_error =
        ipc::MessageEncodeHeaderV1(staged, kExecdParseReplyV1MessageBytes, envelope);
    if (envelope_error != ipc::MessageValidationError::Ok)
        return Result(ExecdProtocolError::EnvelopeRejected, envelope_error);

    u8* payload = staged + ipc::kMessageAbiHeaderV1Bytes;
    const ipc::PayloadValidationError payload_error = ipc::PayloadEncodeHeader(
        payload, kExecdParseReplyV1PayloadBytes, kExecdProtocolVersion1, 0, kReplyPayloadRules, 1);
    if (payload_error != ipc::PayloadValidationError::Ok)
        return Result(ExecdProtocolError::PayloadRejected, ipc::MessageValidationError::Ok, payload_error);

    WriteLe32(payload + kReplyStatusOffset, static_cast<u32>(canonical.status));
    WriteLe64(payload + kReplyLoadPlanObjectRefOffset, canonical.load_plan_object_ref);
    WriteLe32(payload + kReplyImmutablePolicyOffset, canonical.immutable_policy_id);
    WriteHash(payload + kReplySourceHashOffset, canonical.source_hash);
    CopyBytes(static_cast<u8*>(message), staged, kExecdParseReplyV1MessageBytes);
    return Result(ExecdProtocolError::Ok);
}

ExecdProtocolResult ExecdEncodeCancelV1(void* message, u32 message_bytes, u64 request_id)
{
    if (message == nullptr)
        return Result(ExecdProtocolError::NullArgument);
    if (message_bytes != kExecdCancelV1MessageBytes)
        return Result(ExecdProtocolError::WrongMessageSize);
    if (!PointerRangeIsValid(message, message_bytes))
        return Result(ExecdProtocolError::NullArgument);
    if (request_id == 0)
        return Result(ExecdProtocolError::RequestIdMismatch);

    u8 staged[kExecdCancelV1MessageBytes]{};
    const ipc::MessageHeaderV1 envelope{ipc::MessageKind::Cancel, 0, kExecdServiceId, kExecdCancelMethodId, request_id};
    const ipc::MessageValidationError envelope_error =
        ipc::MessageEncodeHeaderV1(staged, kExecdCancelV1MessageBytes, envelope);
    if (envelope_error != ipc::MessageValidationError::Ok)
        return Result(ExecdProtocolError::EnvelopeRejected, envelope_error);
    CopyBytes(static_cast<u8*>(message), staged, kExecdCancelV1MessageBytes);
    return Result(ExecdProtocolError::Ok);
}

ExecdProtocolResult ExecdValidateParseRequestV1(const void* message, u32 message_bytes,
                                                const ExecdObjectTransferAuthorityV1* source_authority,
                                                ExecdParseRequestV1* request_out)
{
    const ExecdProtocolResult range_result = ValidateMessageAndOutputRanges(message, message_bytes, request_out);
    if (range_result.error != ExecdProtocolError::Ok)
        return range_result;

    ExecdObjectTransferAuthorityV1 authority{};
    const ExecdProtocolResult authority_result =
        SnapshotAuthority(message, message_bytes, source_authority, &authority);
    *request_out = ExecdParseRequestV1{};
    if (authority_result.error != ExecdProtocolError::Ok)
        return authority_result;

    ipc::MessageView envelope{};
    const ExecdProtocolResult envelope_result =
        ValidateEnvelope(message, message_bytes, kExecdParseRequestV1MessageBytes, ipc::MessageKind::Request,
                         kExecdParseMethodId, 0, &envelope);
    if (envelope_result.error != ExecdProtocolError::Ok)
        return envelope_result;

    const auto* payload = static_cast<const u8*>(message) + envelope.payload_offset;
    const ExecdProtocolResult payload_result = ValidatePayload(payload, envelope.payload_size, kRequestPayloadRules, 1);
    if (payload_result.error != ExecdProtocolError::Ok)
        return payload_result;

    if (ReadLe16(payload + kRequestReserved16Offset) != 0 || ReadLe64(payload + kRequestReserved64Offset) != 0)
        return Result(ExecdProtocolError::ReservedNonZero);

    ExecdParseRequestV1 decoded{envelope.request_id,
                                ReadLe64(payload + kRequestSourceObjectRefOffset),
                                ReadLe32(payload + kRequestImmutablePolicyOffset),
                                static_cast<ExecdFormatHint>(ReadLe16(payload + kRequestFormatHintOffset)),
                                ReadLe32(payload + kRequestFlagsOffset),
                                ReadLe32(payload + kRequestDependencyCountOffset)};
    const ExecdProtocolError semantic_error = ValidateRequestScalars(decoded);
    if (semantic_error != ExecdProtocolError::Ok)
        return Result(semantic_error);

    const ExecdProtocolError trusted_error =
        ValidateSourceAuthority(authority, decoded.source_object_ref, decoded.immutable_policy_id);
    if (trusted_error != ExecdProtocolError::Ok)
        return Result(trusted_error);

    *request_out = decoded;
    return Result(ExecdProtocolError::Ok);
}

ExecdProtocolResult ExecdValidateParseReplyV1(const void* message, u32 message_bytes, u64 expected_request_id,
                                              ExecdTransportObjectRef expected_source_object_ref,
                                              const ExecdObjectTransferAuthorityV1* retained_source_authority,
                                              const ExecdObjectTransferAuthorityV1* load_plan_authority,
                                              ExecdParseReplyV1* reply_out)
{
    const ExecdProtocolResult range_result = ValidateMessageAndOutputRanges(message, message_bytes, reply_out);
    if (range_result.error != ExecdProtocolError::Ok)
        return range_result;

    ExecdObjectTransferAuthorityV1 source_authority{};
    const ExecdProtocolResult source_result =
        SnapshotAuthority(message, message_bytes, retained_source_authority, &source_authority);
    ExecdObjectTransferAuthorityV1 plan_authority{};
    ExecdProtocolResult plan_result = Result(ExecdProtocolError::Ok);
    if (load_plan_authority != nullptr)
        plan_result = SnapshotAuthority(message, message_bytes, load_plan_authority, &plan_authority);

    *reply_out = ExecdParseReplyV1{};
    if (expected_request_id == 0)
        return Result(ExecdProtocolError::RequestIdMismatch);
    if (!ObjectReferenceIsValid(expected_source_object_ref))
        return Result(ExecdProtocolError::InvalidObjectReference);
    if (source_result.error != ExecdProtocolError::Ok)
        return source_result;
    if (plan_result.error != ExecdProtocolError::Ok)
        return plan_result;

    ipc::MessageView envelope{};
    const ExecdProtocolResult envelope_result =
        ValidateEnvelope(message, message_bytes, kExecdParseReplyV1MessageBytes, ipc::MessageKind::Reply,
                         kExecdParseMethodId, expected_request_id, &envelope);
    if (envelope_result.error != ExecdProtocolError::Ok)
        return envelope_result;

    const auto* payload = static_cast<const u8*>(message) + envelope.payload_offset;
    const ExecdProtocolResult payload_result = ValidatePayload(payload, envelope.payload_size, kReplyPayloadRules, 1);
    if (payload_result.error != ExecdProtocolError::Ok)
        return payload_result;
    if (ReadLe32(payload + kReplyReserved32AOffset) != 0 || ReadLe32(payload + kReplyReserved32BOffset) != 0)
        return Result(ExecdProtocolError::ReservedNonZero);

    ExecdParseReplyV1 decoded{};
    decoded.request_id = envelope.request_id;
    decoded.status = static_cast<ExecdReplyStatus>(ReadLe32(payload + kReplyStatusOffset));
    decoded.load_plan_object_ref = ReadLe64(payload + kReplyLoadPlanObjectRefOffset);
    decoded.immutable_policy_id = ReadLe32(payload + kReplyImmutablePolicyOffset);
    ReadHash(payload + kReplySourceHashOffset, &decoded.source_hash);

    const ExecdProtocolError semantic_error = ValidateReplyScalars(decoded);
    if (semantic_error != ExecdProtocolError::Ok)
        return Result(semantic_error);
    const ExecdProtocolError source_authority_error =
        ValidateSourceAuthority(source_authority, expected_source_object_ref, kExecdSourceImmutablePolicyV1);
    if (source_authority_error != ExecdProtocolError::Ok)
        return Result(source_authority_error);

    if (decoded.status == ExecdReplyStatus::Success)
    {
        if (load_plan_authority == nullptr)
            return Result(ExecdProtocolError::AuthorityRequired);
        if (decoded.load_plan_object_ref == expected_source_object_ref)
            return Result(ExecdProtocolError::ObjectReferenceCollision);
        const ExecdProtocolError plan_authority_error =
            ValidateLoadPlanAuthority(plan_authority, decoded.load_plan_object_ref, decoded.immutable_policy_id);
        if (plan_authority_error != ExecdProtocolError::Ok)
            return Result(plan_authority_error);
        if (!HashEquals(decoded.source_hash, source_authority.object_hash))
            return Result(ExecdProtocolError::SourceHashMismatch);
    }
    else if (load_plan_authority != nullptr)
    {
        return Result(ExecdProtocolError::UnexpectedAuthority);
    }

    *reply_out = decoded;
    return Result(ExecdProtocolError::Ok);
}

ExecdProtocolResult ExecdValidateCancelV1(const void* message, u32 message_bytes, u64 expected_request_id,
                                          ExecdCancelV1* cancel_out)
{
    const ExecdProtocolResult range_result = ValidateMessageAndOutputRanges(message, message_bytes, cancel_out);
    if (range_result.error != ExecdProtocolError::Ok)
        return range_result;
    *cancel_out = ExecdCancelV1{};
    if (expected_request_id == 0)
        return Result(ExecdProtocolError::RequestIdMismatch);

    ipc::MessageView envelope{};
    const ExecdProtocolResult envelope_result =
        ValidateEnvelope(message, message_bytes, kExecdCancelV1MessageBytes, ipc::MessageKind::Cancel,
                         kExecdCancelMethodId, expected_request_id, &envelope);
    if (envelope_result.error != ExecdProtocolError::Ok)
        return envelope_result;

    *cancel_out = ExecdCancelV1{envelope.request_id};
    return Result(ExecdProtocolError::Ok);
}

const char* ExecdProtocolErrorName(ExecdProtocolError error)
{
    switch (error)
    {
    case ExecdProtocolError::Ok:
        return "ok";
    case ExecdProtocolError::NullArgument:
        return "null-argument";
    case ExecdProtocolError::AliasedOutput:
        return "aliased-output";
    case ExecdProtocolError::AuthorityAliasesMessage:
        return "authority-aliases-message";
    case ExecdProtocolError::WrongMessageSize:
        return "wrong-message-size";
    case ExecdProtocolError::EnvelopeRejected:
        return "envelope-rejected";
    case ExecdProtocolError::PayloadRejected:
        return "payload-rejected";
    case ExecdProtocolError::WrongService:
        return "wrong-service";
    case ExecdProtocolError::WrongMethod:
        return "wrong-method";
    case ExecdProtocolError::WrongKind:
        return "wrong-kind";
    case ExecdProtocolError::RequestIdMismatch:
        return "request-id-mismatch";
    case ExecdProtocolError::InvalidObjectReference:
        return "invalid-object-reference";
    case ExecdProtocolError::UnsupportedImmutablePolicy:
        return "unsupported-immutable-policy";
    case ExecdProtocolError::UnsupportedFormatHint:
        return "unsupported-format-hint";
    case ExecdProtocolError::UnsupportedFlags:
        return "unsupported-flags";
    case ExecdProtocolError::DependenciesUnsupported:
        return "dependencies-unsupported";
    case ExecdProtocolError::ReservedNonZero:
        return "reserved-nonzero";
    case ExecdProtocolError::InvalidReplyStatus:
        return "invalid-reply-status";
    case ExecdProtocolError::MalformedStatusCombination:
        return "malformed-status-combination";
    case ExecdProtocolError::AuthorityRequired:
        return "authority-required";
    case ExecdProtocolError::UnexpectedAuthority:
        return "unexpected-authority";
    case ExecdProtocolError::AuthorityReferenceMismatch:
        return "authority-reference-mismatch";
    case ExecdProtocolError::AuthorityKindMismatch:
        return "authority-kind-mismatch";
    case ExecdProtocolError::AuthorityPolicyMismatch:
        return "authority-policy-mismatch";
    case ExecdProtocolError::AuthorityNotSealed:
        return "authority-not-sealed";
    case ExecdProtocolError::AuthoritySizeInvalid:
        return "authority-size-invalid";
    case ExecdProtocolError::MissingSourceHash:
        return "missing-source-hash";
    case ExecdProtocolError::SourceHashMismatch:
        return "source-hash-mismatch";
    case ExecdProtocolError::ObjectReferenceCollision:
        return "object-reference-collision";
    }
    return "unknown";
}

} // namespace duetos::loader
