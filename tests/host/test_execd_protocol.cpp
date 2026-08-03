// Hosted hostile-input coverage for loader/execd_protocol.{h,cpp}.
//
// Exercises canonical unaligned wire encoding, exact MessageAbi and
// VersionedPayload framing, transfer-authority binding, cross-kind confusion,
// failure canonicalization, and deterministic stack-only round trips.

#include "host_test_helper.h"
#include "loader/execd_protocol.h"

#include <array>

namespace
{

using duetos::u16;
using duetos::u32;
using duetos::u64;
using duetos::u8;
using namespace duetos::ipc;
using namespace duetos::loader;

using RequestMessage = std::array<u8, kExecdParseRequestV1MessageBytes>;
using ReplyMessage = std::array<u8, kExecdParseReplyV1MessageBytes>;
using CancelMessage = std::array<u8, kExecdCancelV1MessageBytes>;

constexpr u32 kEnvelopeTotalSizeOffset = 4;
constexpr u32 kEnvelopeVersionOffset = 8;
constexpr u32 kEnvelopeKindOffset = 12;
constexpr u32 kEnvelopeFlagsOffset = 14;
constexpr u32 kEnvelopeServiceOffset = 16;
constexpr u32 kEnvelopeMethodOffset = 20;
constexpr u32 kEnvelopeRequestIdOffset = 24;
constexpr u32 kPayloadOffset = kMessageAbiHeaderV1Bytes;
constexpr u32 kPayloadSizeOffset = kPayloadOffset;
constexpr u32 kPayloadVersionOffset = kPayloadOffset + 4;
constexpr u32 kPayloadFlagsOffset = kPayloadOffset + 6;

constexpr u32 kRequestSourceObjectRefOffset = kPayloadOffset + 8;
constexpr u32 kRequestImmutablePolicyOffset = kPayloadOffset + 16;
constexpr u32 kRequestFormatHintOffset = kPayloadOffset + 20;
constexpr u32 kRequestReserved16Offset = kPayloadOffset + 22;
constexpr u32 kRequestFlagsOffset = kPayloadOffset + 24;
constexpr u32 kRequestDependencyCountOffset = kPayloadOffset + 28;
constexpr u32 kRequestReserved64Offset = kPayloadOffset + 32;

constexpr u32 kReplyStatusOffset = kPayloadOffset + 8;
constexpr u32 kReplyReserved32AOffset = kPayloadOffset + 12;
constexpr u32 kReplyLoadPlanObjectRefOffset = kPayloadOffset + 16;
constexpr u32 kReplyImmutablePolicyOffset = kPayloadOffset + 24;
constexpr u32 kReplyReserved32BOffset = kPayloadOffset + 28;
constexpr u32 kReplySourceHashOffset = kPayloadOffset + 32;

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

Hash256 MakeHash(u8 seed)
{
    Hash256 hash{};
    for (u32 index = 0; index < 32; ++index)
        hash.bytes[index] = static_cast<u8>(seed + index * 3U);
    return hash;
}

bool HashEquals(const Hash256& left, const Hash256& right)
{
    for (u32 index = 0; index < 32; ++index)
    {
        if (left.bytes[index] != right.bytes[index])
            return false;
    }
    return true;
}

ExecdObjectTransferAuthorityV1 MakeSourceAuthority(ExecdTransportObjectRef reference, const Hash256& hash)
{
    return ExecdObjectTransferAuthorityV1{
        reference, ExecdTransferredObjectKind::SourceImage, 1, kExecdSourceImmutablePolicyV1, 0x9000, hash};
}

ExecdObjectTransferAuthorityV1 MakePlanAuthority(ExecdTransportObjectRef reference)
{
    return ExecdObjectTransferAuthorityV1{reference,
                                          ExecdTransferredObjectKind::LoadPlan,
                                          1,
                                          kExecdLoadPlanImmutablePolicyV1,
                                          kExecdLoadPlanObjectMinBytes,
                                          MakeHash(0xA0)};
}

ExecdParseRequestV1 MakeRequest(u64 request_id = 0x1020304050607080ULL,
                                ExecdTransportObjectRef source_reference = 0x112233)
{
    return ExecdParseRequestV1{
        request_id, source_reference, kExecdSourceImmutablePolicyV1, ExecdFormatHint::Pe32Plus, 0, 0};
}

ExecdParseReplyV1 MakeSuccessReply(u64 request_id, ExecdTransportObjectRef plan_reference, const Hash256& source_hash)
{
    return ExecdParseReplyV1{request_id, ExecdReplyStatus::Success, plan_reference, kExecdLoadPlanImmutablePolicyV1,
                             source_hash};
}

ExecdParseReplyV1 MakeFailureReply(u64 request_id, ExecdReplyStatus status)
{
    return ExecdParseReplyV1{request_id, status, 0, 0, Hash256{}};
}

RequestMessage EncodeRequest(const ExecdParseRequestV1& request)
{
    RequestMessage message{};
    EXPECT_EQ(ExecdEncodeParseRequestV1(message.data(), static_cast<u32>(message.size()), request).error,
              ExecdProtocolError::Ok);
    return message;
}

ReplyMessage EncodeReply(const ExecdParseReplyV1& reply)
{
    ReplyMessage message{};
    EXPECT_EQ(ExecdEncodeParseReplyV1(message.data(), static_cast<u32>(message.size()), reply).error,
              ExecdProtocolError::Ok);
    return message;
}

CancelMessage EncodeCancel(u64 request_id)
{
    CancelMessage message{};
    EXPECT_EQ(ExecdEncodeCancelV1(message.data(), static_cast<u32>(message.size()), request_id).error,
              ExecdProtocolError::Ok);
    return message;
}

void PoisonRequest(ExecdParseRequestV1* request)
{
    *request = ExecdParseRequestV1{~0ULL, ~0ULL, ~0U, static_cast<ExecdFormatHint>(0xFFFF), ~0U, ~0U};
}

void ExpectNoRequest(const ExecdParseRequestV1& request)
{
    EXPECT_EQ(request.request_id, 0ULL);
    EXPECT_EQ(request.source_object_ref, 0ULL);
    EXPECT_EQ(request.immutable_policy_id, 0U);
    EXPECT_EQ(request.flags, 0U);
    EXPECT_EQ(request.dependency_count, 0U);
}

void PoisonReply(ExecdParseReplyV1* reply)
{
    *reply = ExecdParseReplyV1{~0ULL, static_cast<ExecdReplyStatus>(~0U), ~0ULL, ~0U, MakeHash(0xE0)};
}

void ExpectNoReply(const ExecdParseReplyV1& reply)
{
    EXPECT_EQ(reply.request_id, 0ULL);
    EXPECT_EQ(reply.load_plan_object_ref, 0ULL);
    EXPECT_EQ(reply.immutable_policy_id, 0U);
    EXPECT_TRUE(HashEquals(reply.source_hash, Hash256{}));
}

void ExpectRequestFailure(const RequestMessage& message, const ExecdObjectTransferAuthorityV1* authority,
                          ExecdProtocolError expected)
{
    ExecdParseRequestV1 output{};
    PoisonRequest(&output);
    const ExecdProtocolResult result =
        ExecdValidateParseRequestV1(message.data(), static_cast<u32>(message.size()), authority, &output);
    EXPECT_EQ(result.error, expected);
    ExpectNoRequest(output);
}

void ExpectReplyFailure(const ReplyMessage& message, u64 expected_request_id,
                        const ExecdObjectTransferAuthorityV1* source_authority,
                        const ExecdObjectTransferAuthorityV1* plan_authority, ExecdProtocolError expected)
{
    ExecdParseReplyV1 output{};
    PoisonReply(&output);
    const ExecdProtocolResult result =
        ExecdValidateParseReplyV1(message.data(), static_cast<u32>(message.size()), expected_request_id,
                                  source_authority != nullptr ? source_authority->transport_object_ref : 1,
                                  source_authority, plan_authority, &output);
    EXPECT_EQ(result.error, expected);
    ExpectNoReply(output);
}

u64 NextRandom(u64* state)
{
    u64 value = *state;
    value ^= value << 13U;
    value ^= value >> 7U;
    value ^= value << 17U;
    *state = value;
    return value;
}

Hash256 NextHash(u64* state)
{
    Hash256 hash{};
    for (u32 index = 0; index < 32; ++index)
        hash.bytes[index] = static_cast<u8>(NextRandom(state) >> 56U);
    hash.bytes[0] = static_cast<u8>(hash.bytes[0] | 1U);
    return hash;
}

} // namespace

int main()
{
    static_assert(kExecdParseRequestV1MessageBytes == 72);
    static_assert(kExecdParseReplyV1MessageBytes == 96);
    static_assert(kExecdCancelV1MessageBytes == 32);
    static_assert(kExecdParseReplyV1MessageBytes < 4096);
    static_assert(kExecdSourceObjectMaxBytes == 1024ULL * 1024 * 1024);
    static_assert(kExecdLoadPlanObjectMinBytes == 136);
    static_assert(kExecdLoadPlanObjectMaxBytes == 18496);

    const Hash256 source_hash = MakeHash(0x20);
    const ExecdParseRequestV1 request = MakeRequest();
    const ExecdObjectTransferAuthorityV1 source_authority = MakeSourceAuthority(request.source_object_ref, source_hash);

    // Canonical request round trip and exact transfer-authority binding.
    RequestMessage request_message = EncodeRequest(request);
    ExecdParseRequestV1 decoded_request{};
    EXPECT_EQ(ExecdValidateParseRequestV1(request_message.data(), static_cast<u32>(request_message.size()),
                                          &source_authority, &decoded_request)
                  .error,
              ExecdProtocolError::Ok);
    EXPECT_EQ(decoded_request.request_id, request.request_id);
    EXPECT_EQ(decoded_request.source_object_ref, request.source_object_ref);
    EXPECT_EQ(decoded_request.immutable_policy_id, kExecdSourceImmutablePolicyV1);
    EXPECT_EQ(decoded_request.format_hint, ExecdFormatHint::Pe32Plus);
    EXPECT_EQ(decoded_request.flags, 0U);
    EXPECT_EQ(decoded_request.dependency_count, 0U);

    // No native alignment is required at either wire boundary.
    {
        std::array<u8, kExecdParseRequestV1MessageBytes + 1> storage{};
        u8* unaligned = storage.data() + 1;
        EXPECT_EQ(ExecdEncodeParseRequestV1(unaligned, kExecdParseRequestV1MessageBytes, request).error,
                  ExecdProtocolError::Ok);
        EXPECT_EQ(ExecdValidateParseRequestV1(unaligned, kExecdParseRequestV1MessageBytes, &source_authority,
                                              &decoded_request)
                      .error,
                  ExecdProtocolError::Ok);
    }

    // Rejected encodes are transactional and v1 cannot express dependencies.
    {
        RequestMessage untouched{};
        untouched.fill(0xA5);
        const RequestMessage before = untouched;
        ExecdParseRequestV1 invalid = request;
        invalid.dependency_count = 1;
        EXPECT_EQ(ExecdEncodeParseRequestV1(untouched.data(), static_cast<u32>(untouched.size()), invalid).error,
                  ExecdProtocolError::DependenciesUnsupported);
        EXPECT_TRUE(untouched == before);
        EXPECT_EQ(ExecdEncodeParseRequestV1(untouched.data(), static_cast<u32>(untouched.size()) - 1U, request).error,
                  ExecdProtocolError::WrongMessageSize);
        EXPECT_TRUE(untouched == before);
    }
    {
        const auto overflowing_address = ~static_cast<duetos::uptr>(0) - kExecdParseRequestV1MessageBytes + 2U;
        void* const overflowing_output = reinterpret_cast<void*>(overflowing_address);
        EXPECT_EQ(ExecdEncodeParseRequestV1(overflowing_output, kExecdParseRequestV1MessageBytes, request).error,
                  ExecdProtocolError::NullArgument);
    }

    // Exact framing composes the envelope and typed-payload validators.
    {
        ExecdParseRequestV1 output{};
        PoisonRequest(&output);
        ExecdProtocolResult result = ExecdValidateParseRequestV1(
            request_message.data(), static_cast<u32>(request_message.size()) - 1U, &source_authority, &output);
        EXPECT_EQ(result.error, ExecdProtocolError::EnvelopeRejected);
        EXPECT_EQ(result.envelope_error, MessageValidationError::SizeMismatch);
        ExpectNoRequest(output);
    }
    {
        RequestMessage malformed = request_message;
        WriteLe32(malformed.data() + kEnvelopeTotalSizeOffset, static_cast<u32>(malformed.size()) - 1U);
        ExecdParseRequestV1 output{};
        ExecdProtocolResult result = ExecdValidateParseRequestV1(malformed.data(), static_cast<u32>(malformed.size()),
                                                                 &source_authority, &output);
        EXPECT_EQ(result.error, ExecdProtocolError::EnvelopeRejected);
        EXPECT_EQ(result.envelope_error, MessageValidationError::SizeMismatch);
    }
    {
        RequestMessage malformed = request_message;
        WriteLe32(malformed.data() + kPayloadSizeOffset, kExecdParseRequestV1PayloadBytes - 1U);
        ExecdParseRequestV1 output{};
        const ExecdProtocolResult result = ExecdValidateParseRequestV1(
            malformed.data(), static_cast<u32>(malformed.size()), &source_authority, &output);
        EXPECT_EQ(result.error, ExecdProtocolError::PayloadRejected);
        EXPECT_EQ(result.payload_error, PayloadValidationError::SizeMismatch);
    }
    {
        RequestMessage malformed = request_message;
        WriteLe16(malformed.data() + kPayloadVersionOffset, kExecdProtocolVersion1 + 1U);
        ExecdParseRequestV1 output{};
        const ExecdProtocolResult result = ExecdValidateParseRequestV1(
            malformed.data(), static_cast<u32>(malformed.size()), &source_authority, &output);
        EXPECT_EQ(result.error, ExecdProtocolError::PayloadRejected);
        EXPECT_EQ(result.payload_error, PayloadValidationError::UnsupportedVersion);
    }
    {
        RequestMessage malformed = request_message;
        WriteLe16(malformed.data() + kPayloadFlagsOffset, 1);
        ExecdParseRequestV1 output{};
        const ExecdProtocolResult result = ExecdValidateParseRequestV1(
            malformed.data(), static_cast<u32>(malformed.size()), &source_authority, &output);
        EXPECT_EQ(result.error, ExecdProtocolError::PayloadRejected);
        EXPECT_EQ(result.payload_error, PayloadValidationError::UnsupportedFlags);
    }
    {
        RequestMessage malformed = request_message;
        WriteLe16(malformed.data() + kEnvelopeVersionOffset, kMessageAbiVersion1 + 1U);
        ExecdParseRequestV1 output{};
        ExecdProtocolResult result = ExecdValidateParseRequestV1(malformed.data(), static_cast<u32>(malformed.size()),
                                                                 &source_authority, &output);
        EXPECT_EQ(result.error, ExecdProtocolError::EnvelopeRejected);
        EXPECT_EQ(result.envelope_error, MessageValidationError::UnsupportedVersion);
        malformed = request_message;
        WriteLe16(malformed.data() + kEnvelopeFlagsOffset, 1);
        result = ExecdValidateParseRequestV1(malformed.data(), static_cast<u32>(malformed.size()), &source_authority,
                                             &output);
        EXPECT_EQ(result.error, ExecdProtocolError::EnvelopeRejected);
        EXPECT_EQ(result.envelope_error, MessageValidationError::UnsupportedFlags);
    }
    {
        std::array<u8, kExecdParseRequestV1MessageBytes + 1> oversized{};
        for (u32 index = 0; index < kExecdParseRequestV1MessageBytes; ++index)
            oversized[index] = request_message[index];
        WriteLe32(oversized.data() + kEnvelopeTotalSizeOffset, static_cast<u32>(oversized.size()));
        WriteLe32(oversized.data() + kPayloadSizeOffset, kExecdParseRequestV1PayloadBytes + 1U);
        ExecdParseRequestV1 output{};
        EXPECT_EQ(ExecdValidateParseRequestV1(oversized.data(), static_cast<u32>(oversized.size()), &source_authority,
                                              &output)
                      .error,
                  ExecdProtocolError::WrongMessageSize);
        ExpectNoRequest(output);
    }

    // Route, kind, and method are independent confusion boundaries.
    {
        RequestMessage malformed = request_message;
        WriteLe32(malformed.data() + kEnvelopeServiceOffset, kExecdServiceId + 1U);
        ExpectRequestFailure(malformed, &source_authority, ExecdProtocolError::WrongService);
        malformed = request_message;
        WriteLe32(malformed.data() + kEnvelopeMethodOffset, kExecdCancelMethodId);
        ExpectRequestFailure(malformed, &source_authority, ExecdProtocolError::WrongMethod);
        malformed = request_message;
        WriteLe16(malformed.data() + kEnvelopeKindOffset, static_cast<u16>(MessageKind::Reply));
        ExpectRequestFailure(malformed, &source_authority, ExecdProtocolError::WrongKind);
        malformed = request_message;
        WriteLe64(malformed.data() + kEnvelopeRequestIdOffset, 0);
        ExecdParseRequestV1 output{};
        const ExecdProtocolResult result = ExecdValidateParseRequestV1(
            malformed.data(), static_cast<u32>(malformed.size()), &source_authority, &output);
        EXPECT_EQ(result.error, ExecdProtocolError::EnvelopeRejected);
        EXPECT_EQ(result.envelope_error, MessageValidationError::InvalidRequestId);
    }

    // Hostile request scalar and reserved-field vectors fail closed.
    {
        RequestMessage malformed = request_message;
        WriteLe64(malformed.data() + kRequestSourceObjectRefOffset, 0);
        ExpectRequestFailure(malformed, &source_authority, ExecdProtocolError::InvalidObjectReference);
        malformed = request_message;
        WriteLe64(malformed.data() + kRequestSourceObjectRefOffset, kExecdTransportObjectRefMax + 1ULL);
        ExpectRequestFailure(malformed, &source_authority, ExecdProtocolError::InvalidObjectReference);
        malformed = request_message;
        WriteLe32(malformed.data() + kRequestImmutablePolicyOffset, 0);
        ExpectRequestFailure(malformed, &source_authority, ExecdProtocolError::UnsupportedImmutablePolicy);
        malformed = request_message;
        WriteLe16(malformed.data() + kRequestFormatHintOffset, 0xFFFF);
        ExpectRequestFailure(malformed, &source_authority, ExecdProtocolError::UnsupportedFormatHint);
        malformed = request_message;
        WriteLe32(malformed.data() + kRequestFlagsOffset, 1);
        ExpectRequestFailure(malformed, &source_authority, ExecdProtocolError::UnsupportedFlags);
        malformed = request_message;
        WriteLe32(malformed.data() + kRequestDependencyCountOffset, 1);
        ExpectRequestFailure(malformed, &source_authority, ExecdProtocolError::DependenciesUnsupported);
        malformed = request_message;
        WriteLe16(malformed.data() + kRequestReserved16Offset, 1);
        ExpectRequestFailure(malformed, &source_authority, ExecdProtocolError::ReservedNonZero);
        malformed = request_message;
        WriteLe64(malformed.data() + kRequestReserved64Offset, 1);
        ExpectRequestFailure(malformed, &source_authority, ExecdProtocolError::ReservedNonZero);
    }

    // Sender bytes cannot self-authorize. Every retained source fact must bind
    // exactly and the authority record itself cannot reside in the message.
    ExpectRequestFailure(request_message, nullptr, ExecdProtocolError::AuthorityRequired);
    {
        ExecdObjectTransferAuthorityV1 authority = source_authority;
        ++authority.transport_object_ref;
        ExpectRequestFailure(request_message, &authority, ExecdProtocolError::AuthorityReferenceMismatch);
        authority = source_authority;
        authority.object_kind = ExecdTransferredObjectKind::LoadPlan;
        ExpectRequestFailure(request_message, &authority, ExecdProtocolError::AuthorityKindMismatch);
        authority = source_authority;
        authority.sealed = 0;
        ExpectRequestFailure(request_message, &authority, ExecdProtocolError::AuthorityNotSealed);
        authority = source_authority;
        authority.immutable_policy_id = kExecdLoadPlanImmutablePolicyV1;
        ExpectRequestFailure(request_message, &authority, ExecdProtocolError::AuthorityPolicyMismatch);
        authority = source_authority;
        authority.object_bytes = 0;
        ExpectRequestFailure(request_message, &authority, ExecdProtocolError::AuthoritySizeInvalid);
        authority = source_authority;
        authority.object_bytes = kExecdSourceObjectMaxBytes;
        ExecdParseRequestV1 maximum_source{};
        EXPECT_EQ(ExecdValidateParseRequestV1(request_message.data(), static_cast<u32>(request_message.size()),
                                              &authority, &maximum_source)
                      .error,
                  ExecdProtocolError::Ok);
        authority.object_bytes = kExecdSourceObjectMaxBytes + 1ULL;
        ExpectRequestFailure(request_message, &authority, ExecdProtocolError::AuthoritySizeInvalid);
        authority = source_authority;
        authority.object_hash = Hash256{};
        ExpectRequestFailure(request_message, &authority, ExecdProtocolError::MissingSourceHash);
    }
    {
        const auto* sender_authored = reinterpret_cast<const ExecdObjectTransferAuthorityV1*>(request_message.data());
        ExpectRequestFailure(request_message, sender_authored, ExecdProtocolError::AuthorityAliasesMessage);
    }
    {
        RequestMessage alias_message = request_message;
        const RequestMessage before = alias_message;
        auto* aliased_output = reinterpret_cast<ExecdParseRequestV1*>(alias_message.data());
        EXPECT_EQ(ExecdValidateParseRequestV1(alias_message.data(), static_cast<u32>(alias_message.size()),
                                              &source_authority, aliased_output)
                      .error,
                  ExecdProtocolError::AliasedOutput);
        EXPECT_TRUE(alias_message == before);
    }

    // Success reply binds the exact request, source hash, and retained sealed
    // LoadPlan transfer object without placing plan bytes in the message.
    constexpr ExecdTransportObjectRef kPlanReference = 0x445566;
    const ExecdParseReplyV1 success_reply = MakeSuccessReply(request.request_id, kPlanReference, source_hash);
    const ExecdObjectTransferAuthorityV1 plan_authority = MakePlanAuthority(kPlanReference);
    ReplyMessage reply_message = EncodeReply(success_reply);
    ExecdParseReplyV1 decoded_reply{};
    EXPECT_EQ(ExecdValidateParseReplyV1(reply_message.data(), static_cast<u32>(reply_message.size()),
                                        request.request_id, request.source_object_ref, &source_authority,
                                        &plan_authority, &decoded_reply)
                  .error,
              ExecdProtocolError::Ok);
    EXPECT_EQ(decoded_reply.request_id, request.request_id);
    EXPECT_EQ(decoded_reply.status, ExecdReplyStatus::Success);
    EXPECT_EQ(decoded_reply.load_plan_object_ref, kPlanReference);
    EXPECT_TRUE(HashEquals(decoded_reply.source_hash, source_hash));
    {
        ReplyMessage malformed = reply_message;
        WriteLe32(malformed.data() + kPayloadSizeOffset, kExecdParseReplyV1PayloadBytes - 1U);
        ExecdParseReplyV1 output{};
        PoisonReply(&output);
        const ExecdProtocolResult result =
            ExecdValidateParseReplyV1(malformed.data(), static_cast<u32>(malformed.size()), request.request_id,
                                      request.source_object_ref, &source_authority, &plan_authority, &output);
        EXPECT_EQ(result.error, ExecdProtocolError::PayloadRejected);
        EXPECT_EQ(result.payload_error, PayloadValidationError::SizeMismatch);
        ExpectNoReply(output);

        malformed = reply_message;
        WriteLe16(malformed.data() + kPayloadVersionOffset, kExecdProtocolVersion1 + 1U);
        PoisonReply(&output);
        const ExecdProtocolResult version_result =
            ExecdValidateParseReplyV1(malformed.data(), static_cast<u32>(malformed.size()), request.request_id,
                                      request.source_object_ref, &source_authority, &plan_authority, &output);
        EXPECT_EQ(version_result.error, ExecdProtocolError::PayloadRejected);
        EXPECT_EQ(version_result.payload_error, PayloadValidationError::UnsupportedVersion);
        ExpectNoReply(output);
    }
    ExpectReplyFailure(reply_message, request.request_id + 1ULL, &source_authority, &plan_authority,
                       ExecdProtocolError::RequestIdMismatch);
    {
        ExecdParseReplyV1 replay_output{};
        PoisonReply(&replay_output);
        EXPECT_EQ(ExecdValidateParseReplyV1(reply_message.data(), static_cast<u32>(reply_message.size()),
                                            request.request_id, request.source_object_ref + 1ULL, &source_authority,
                                            &plan_authority, &replay_output)
                      .error,
                  ExecdProtocolError::AuthorityReferenceMismatch);
        ExpectNoReply(replay_output);

        ExecdObjectTransferAuthorityV1 replayed_source = source_authority;
        ++replayed_source.transport_object_ref;
        PoisonReply(&replay_output);
        EXPECT_EQ(ExecdValidateParseReplyV1(reply_message.data(), static_cast<u32>(reply_message.size()),
                                            request.request_id, request.source_object_ref, &replayed_source,
                                            &plan_authority, &replay_output)
                      .error,
                  ExecdProtocolError::AuthorityReferenceMismatch);
        ExpectNoReply(replay_output);
        PoisonReply(&replay_output);
        EXPECT_EQ(ExecdValidateParseReplyV1(reply_message.data(), static_cast<u32>(reply_message.size()),
                                            request.request_id, 0, &source_authority, &plan_authority, &replay_output)
                      .error,
                  ExecdProtocolError::InvalidObjectReference);
        ExpectNoReply(replay_output);
        PoisonReply(&replay_output);
        EXPECT_EQ(ExecdValidateParseReplyV1(reply_message.data(), static_cast<u32>(reply_message.size()),
                                            request.request_id, kExecdTransportObjectRefMax + 1ULL, &source_authority,
                                            &plan_authority, &replay_output)
                      .error,
                  ExecdProtocolError::InvalidObjectReference);
        ExpectNoReply(replay_output);
    }

    // Reply cross-kind/method/route confusion remains distinct from framing.
    {
        ReplyMessage malformed = reply_message;
        WriteLe32(malformed.data() + kEnvelopeServiceOffset, kExecdServiceId + 1U);
        ExpectReplyFailure(malformed, request.request_id, &source_authority, &plan_authority,
                           ExecdProtocolError::WrongService);
        malformed = reply_message;
        WriteLe32(malformed.data() + kEnvelopeMethodOffset, kExecdCancelMethodId);
        ExpectReplyFailure(malformed, request.request_id, &source_authority, &plan_authority,
                           ExecdProtocolError::WrongMethod);
        malformed = reply_message;
        WriteLe16(malformed.data() + kEnvelopeKindOffset, static_cast<u16>(MessageKind::Request));
        ExpectReplyFailure(malformed, request.request_id, &source_authority, &plan_authority,
                           ExecdProtocolError::WrongKind);
    }

    // Successful reply authority and source identity must match exactly.
    ExpectReplyFailure(reply_message, request.request_id, &source_authority, nullptr,
                       ExecdProtocolError::AuthorityRequired);
    {
        ExecdObjectTransferAuthorityV1 authority = plan_authority;
        ++authority.transport_object_ref;
        ExpectReplyFailure(reply_message, request.request_id, &source_authority, &authority,
                           ExecdProtocolError::AuthorityReferenceMismatch);
        authority = plan_authority;
        authority.object_kind = ExecdTransferredObjectKind::SourceImage;
        ExpectReplyFailure(reply_message, request.request_id, &source_authority, &authority,
                           ExecdProtocolError::AuthorityKindMismatch);
        authority = plan_authority;
        authority.sealed = 0;
        ExpectReplyFailure(reply_message, request.request_id, &source_authority, &authority,
                           ExecdProtocolError::AuthorityNotSealed);
        authority = plan_authority;
        authority.immutable_policy_id = kExecdSourceImmutablePolicyV1;
        ExpectReplyFailure(reply_message, request.request_id, &source_authority, &authority,
                           ExecdProtocolError::AuthorityPolicyMismatch);
        authority = plan_authority;
        authority.object_bytes = kLoadPlanV1HeaderBytes;
        ExpectReplyFailure(reply_message, request.request_id, &source_authority, &authority,
                           ExecdProtocolError::AuthoritySizeInvalid);
        authority = plan_authority;
        authority.object_bytes = kExecdLoadPlanObjectMinBytes - 1U;
        ExpectReplyFailure(reply_message, request.request_id, &source_authority, &authority,
                           ExecdProtocolError::AuthoritySizeInvalid);
        authority = plan_authority;
        authority.object_bytes = kExecdLoadPlanObjectMinBytes + 1U;
        ExpectReplyFailure(reply_message, request.request_id, &source_authority, &authority,
                           ExecdProtocolError::AuthoritySizeInvalid);
        authority = plan_authority;
        authority.object_bytes = kExecdLoadPlanObjectMaxBytes;
        ExecdParseReplyV1 maximum_plan{};
        EXPECT_EQ(ExecdValidateParseReplyV1(reply_message.data(), static_cast<u32>(reply_message.size()),
                                            request.request_id, request.source_object_ref, &source_authority,
                                            &authority, &maximum_plan)
                      .error,
                  ExecdProtocolError::Ok);
        authority.object_bytes = kExecdLoadPlanObjectMaxBytes - 1U;
        ExpectReplyFailure(reply_message, request.request_id, &source_authority, &authority,
                           ExecdProtocolError::AuthoritySizeInvalid);
        authority = plan_authority;
        authority.object_bytes = static_cast<u64>(kExecdLoadPlanObjectMaxBytes) + 1ULL;
        ExpectReplyFailure(reply_message, request.request_id, &source_authority, &authority,
                           ExecdProtocolError::AuthoritySizeInvalid);
    }
    {
        const ExecdParseReplyV1 collision_reply =
            MakeSuccessReply(request.request_id, request.source_object_ref, source_hash);
        const ReplyMessage collision_message = EncodeReply(collision_reply);
        const ExecdObjectTransferAuthorityV1 collision_plan = MakePlanAuthority(request.source_object_ref);
        ExpectReplyFailure(collision_message, request.request_id, &source_authority, &collision_plan,
                           ExecdProtocolError::ObjectReferenceCollision);
    }
    {
        ExecdObjectTransferAuthorityV1 wrong_source = source_authority;
        wrong_source.object_hash.bytes[0] ^= 0x80U;
        ExpectReplyFailure(reply_message, request.request_id, &wrong_source, &plan_authority,
                           ExecdProtocolError::SourceHashMismatch);
    }

    // Unknown statuses and success/failure field mixtures are never accepted.
    {
        ReplyMessage malformed = reply_message;
        WriteLe32(malformed.data() + kReplyStatusOffset, 0xFFFFFFFFU);
        ExpectReplyFailure(malformed, request.request_id, &source_authority, &plan_authority,
                           ExecdProtocolError::InvalidReplyStatus);
        malformed = reply_message;
        WriteLe64(malformed.data() + kReplyLoadPlanObjectRefOffset, 0);
        ExpectReplyFailure(malformed, request.request_id, &source_authority, &plan_authority,
                           ExecdProtocolError::InvalidObjectReference);
        malformed = reply_message;
        WriteLe64(malformed.data() + kReplyLoadPlanObjectRefOffset, kExecdTransportObjectRefMax + 1ULL);
        ExpectReplyFailure(malformed, request.request_id, &source_authority, &plan_authority,
                           ExecdProtocolError::InvalidObjectReference);
        malformed = reply_message;
        WriteLe32(malformed.data() + kReplyImmutablePolicyOffset, 0);
        ExpectReplyFailure(malformed, request.request_id, &source_authority, &plan_authority,
                           ExecdProtocolError::UnsupportedImmutablePolicy);
        malformed = reply_message;
        for (u32 index = 0; index < 32; ++index)
            malformed[kReplySourceHashOffset + index] = 0;
        ExpectReplyFailure(malformed, request.request_id, &source_authority, &plan_authority,
                           ExecdProtocolError::MissingSourceHash);
        malformed = reply_message;
        WriteLe32(malformed.data() + kReplyReserved32AOffset, 1);
        ExpectReplyFailure(malformed, request.request_id, &source_authority, &plan_authority,
                           ExecdProtocolError::ReservedNonZero);
        malformed = reply_message;
        WriteLe32(malformed.data() + kReplyReserved32BOffset, 1);
        ExpectReplyFailure(malformed, request.request_id, &source_authority, &plan_authority,
                           ExecdProtocolError::ReservedNonZero);
    }
    {
        ExecdParseReplyV1 invalid = MakeFailureReply(request.request_id, ExecdReplyStatus::InvalidImage);
        invalid.load_plan_object_ref = kPlanReference;
        ReplyMessage untouched{};
        untouched.fill(0x5A);
        const ReplyMessage before = untouched;
        EXPECT_EQ(ExecdEncodeParseReplyV1(untouched.data(), static_cast<u32>(untouched.size()), invalid).error,
                  ExecdProtocolError::MalformedStatusCombination);
        EXPECT_TRUE(untouched == before);

        ReplyMessage malformed = EncodeReply(MakeFailureReply(request.request_id, ExecdReplyStatus::InvalidImage));
        WriteLe64(malformed.data() + kReplyLoadPlanObjectRefOffset, kPlanReference);
        ExpectReplyFailure(malformed, request.request_id, &source_authority, nullptr,
                           ExecdProtocolError::MalformedStatusCombination);
    }

    // Every defined failure status has one canonical zero-object shape and
    // rejects an attached transfer authority.
    for (ExecdReplyStatus status :
         {ExecdReplyStatus::InvalidImage, ExecdReplyStatus::UnsupportedFormat, ExecdReplyStatus::PolicyRejected,
          ExecdReplyStatus::Cancelled, ExecdReplyStatus::ServiceFailure})
    {
        const ReplyMessage failure_message = EncodeReply(MakeFailureReply(request.request_id, status));
        ExecdParseReplyV1 failure{};
        EXPECT_EQ(ExecdValidateParseReplyV1(failure_message.data(), static_cast<u32>(failure_message.size()),
                                            request.request_id, request.source_object_ref, &source_authority, nullptr,
                                            &failure)
                      .error,
                  ExecdProtocolError::Ok);
        EXPECT_EQ(failure.status, status);
        ExpectReplyFailure(failure_message, request.request_id, &source_authority, &plan_authority,
                           ExecdProtocolError::UnexpectedAuthority);
    }

    // Cancellation is a distinct, payload-free method and exact correlation.
    CancelMessage cancel_message = EncodeCancel(request.request_id);
    ExecdCancelV1 cancel{};
    EXPECT_EQ(ExecdValidateCancelV1(cancel_message.data(), static_cast<u32>(cancel_message.size()), request.request_id,
                                    &cancel)
                  .error,
              ExecdProtocolError::Ok);
    EXPECT_EQ(cancel.request_id, request.request_id);
    EXPECT_EQ(ExecdValidateCancelV1(cancel_message.data(), static_cast<u32>(cancel_message.size()),
                                    request.request_id + 1ULL, &cancel)
                  .error,
              ExecdProtocolError::RequestIdMismatch);
    {
        CancelMessage malformed = cancel_message;
        WriteLe32(malformed.data() + kEnvelopeMethodOffset, kExecdParseMethodId);
        EXPECT_EQ(
            ExecdValidateCancelV1(malformed.data(), static_cast<u32>(malformed.size()), request.request_id, &cancel)
                .error,
            ExecdProtocolError::WrongMethod);
        malformed = cancel_message;
        WriteLe16(malformed.data() + kEnvelopeKindOffset, static_cast<u16>(MessageKind::Request));
        EXPECT_EQ(
            ExecdValidateCancelV1(malformed.data(), static_cast<u32>(malformed.size()), request.request_id, &cancel)
                .error,
            ExecdProtocolError::WrongKind);
    }
    {
        std::array<u8, kExecdCancelV1MessageBytes + 1> malformed{};
        for (u32 index = 0; index < kExecdCancelV1MessageBytes; ++index)
            malformed[index] = cancel_message[index];
        WriteLe32(malformed.data() + kEnvelopeTotalSizeOffset, static_cast<u32>(malformed.size()));
        EXPECT_EQ(
            ExecdValidateCancelV1(malformed.data(), static_cast<u32>(malformed.size()), request.request_id, &cancel)
                .error,
            ExecdProtocolError::EnvelopeRejected);
    }

    // Deterministic randomized scalar round trips use fixed stack buffers and
    // no callbacks. This also supplies broad sanitizer coverage of every hint,
    // success/failure shape, and correlation path.
    u64 random_state = 0xD1CEB00C5EED1234ULL;
    constexpr u32 kRoundTripIterations = 1024;
    for (u32 iteration = 0; iteration < kRoundTripIterations; ++iteration)
    {
        const u64 request_id = NextRandom(&random_state) | 1ULL;
        const ExecdTransportObjectRef source_ref = (NextRandom(&random_state) % kExecdTransportObjectRefMax) + 1ULL;
        const Hash256 random_hash = NextHash(&random_state);
        ExecdParseRequestV1 random_request{request_id,
                                           source_ref,
                                           kExecdSourceImmutablePolicyV1,
                                           static_cast<ExecdFormatHint>(NextRandom(&random_state) % 4ULL),
                                           0,
                                           0};
        const ExecdObjectTransferAuthorityV1 random_source = MakeSourceAuthority(source_ref, random_hash);
        const RequestMessage random_request_message = EncodeRequest(random_request);
        ExecdParseRequestV1 request_copy{};
        EXPECT_EQ(ExecdValidateParseRequestV1(random_request_message.data(),
                                              static_cast<u32>(random_request_message.size()), &random_source,
                                              &request_copy)
                      .error,
                  ExecdProtocolError::Ok);
        EXPECT_EQ(request_copy.request_id, random_request.request_id);
        EXPECT_EQ(request_copy.source_object_ref, random_request.source_object_ref);
        EXPECT_EQ(request_copy.format_hint, random_request.format_hint);

        const bool success = (NextRandom(&random_state) & 1ULL) != 0;
        ExecdParseReplyV1 random_reply{};
        ExecdObjectTransferAuthorityV1 random_plan{};
        const ExecdObjectTransferAuthorityV1* random_plan_ptr = nullptr;
        if (success)
        {
            const ExecdTransportObjectRef plan_ref = (NextRandom(&random_state) % kExecdTransportObjectRefMax) + 1ULL;
            random_reply = MakeSuccessReply(request_id, plan_ref, random_hash);
            random_plan = MakePlanAuthority(plan_ref);
            const u64 region_count = (NextRandom(&random_state) % kLoadPlanMaxRegions) + 1ULL;
            random_plan.object_bytes = kLoadPlanV1HeaderBytes + region_count * kLoadRegionV1Bytes;
            random_plan_ptr = &random_plan;
        }
        else
        {
            const u32 status_value = 1U + static_cast<u32>(NextRandom(&random_state) % 5ULL);
            random_reply = MakeFailureReply(request_id, static_cast<ExecdReplyStatus>(status_value));
        }
        const ReplyMessage random_reply_message = EncodeReply(random_reply);
        ExecdParseReplyV1 reply_copy{};
        EXPECT_EQ(ExecdValidateParseReplyV1(random_reply_message.data(), static_cast<u32>(random_reply_message.size()),
                                            request_id, source_ref, &random_source, random_plan_ptr, &reply_copy)
                      .error,
                  ExecdProtocolError::Ok);
        EXPECT_EQ(reply_copy.request_id, request_id);
        EXPECT_EQ(reply_copy.status, random_reply.status);

        const CancelMessage random_cancel = EncodeCancel(request_id);
        ExecdCancelV1 cancel_copy{};
        EXPECT_EQ(ExecdValidateCancelV1(random_cancel.data(), static_cast<u32>(random_cancel.size()), request_id,
                                        &cancel_copy)
                      .error,
                  ExecdProtocolError::Ok);
        EXPECT_EQ(cancel_copy.request_id, request_id);
    }

    EXPECT_STREQ(ExecdProtocolErrorName(ExecdProtocolError::Ok), "ok");
    EXPECT_STREQ(ExecdProtocolErrorName(ExecdProtocolError::AuthorityAliasesMessage), "authority-aliases-message");
    EXPECT_STREQ(ExecdProtocolErrorName(ExecdProtocolError::ObjectReferenceCollision), "object-reference-collision");
    EXPECT_STREQ(ExecdProtocolErrorName(static_cast<ExecdProtocolError>(0xFF)), "unknown");

    return duetos_host_test::finish_main("test_execd_protocol");
}
