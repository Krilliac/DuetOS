// Hosted canonical-wire, authority-separation, hostile-input, and replay
// coverage for drivers/video/gui_broker_protocol.{h,cpp}.

#include "host_test_helper.h"
#include "drivers/video/gui_broker_protocol.h"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstring>
#include <thread>

namespace
{

using duetos::u16;
using duetos::u32;
using duetos::u64;
using duetos::u8;
using duetos::core::Win32IntegrityLevel;
using duetos::ipc::MessageEncodeHeaderV1;
using duetos::ipc::MessageHeaderV1;
using duetos::ipc::MessageKind;
using duetos::ipc::MessageValidationError;
using duetos::ipc::PayloadEncodeHeader;
using duetos::ipc::PayloadValidationError;
using namespace duetos::drivers::video;

constexpr u32 kEnvelopeKindOffset = 12;
constexpr u32 kEnvelopeServiceOffset = 16;
constexpr u32 kEnvelopeMethodOffset = 20;
constexpr u32 kEnvelopeRequestIdOffset = 24;

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

u32 ReadLe32(const u8* bytes)
{
    return static_cast<u32>(bytes[0]) | (static_cast<u32>(bytes[1]) << 8U) | (static_cast<u32>(bytes[2]) << 16U) |
           (static_cast<u32>(bytes[3]) << 24U);
}

u64 NextRandom(u64& state)
{
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    return state;
}

template <u32 PayloadBytes>
std::array<u8, duetos::ipc::kMessageAbiHeaderV1Bytes + PayloadBytes> MakeTypedFrame(MessageKind kind,
                                                                                    GuiBrokerMethod method,
                                                                                    u64 request_id)
{
    std::array<u8, duetos::ipc::kMessageAbiHeaderV1Bytes + PayloadBytes> frame{};
    const MessageHeaderV1 header{kind, 0, kGuiBrokerServiceId, static_cast<u32>(method), request_id};
    EXPECT_EQ(MessageEncodeHeaderV1(frame.data(), static_cast<u32>(frame.size()), header), MessageValidationError::Ok);
    if constexpr (PayloadBytes != 0)
    {
        EXPECT_EQ(PayloadEncodeHeader(frame.data() + duetos::ipc::kMessageAbiHeaderV1Bytes, PayloadBytes,
                                      kGuiBrokerPayloadVersion1, 0, kGuiBrokerPayloadRules, kGuiBrokerPayloadRuleCount),
                  PayloadValidationError::Ok);
        WriteLe32(frame.data() + duetos::ipc::kMessageAbiHeaderV1Bytes + kGuiBrokerPayloadMethodOffset,
                  static_cast<u32>(method));
    }
    return frame;
}

std::array<u8, kGuiBrokerRegisterRequestFrameBytes> MakeRegisterRequest(u64 request_id, u64 target_reference,
                                                                        u64 principal_reference, u32 message,
                                                                        u64 wparam_mask, u64 lparam_mask)
{
    auto frame = MakeTypedFrame<kGuiBrokerRegisterRequestPayloadBytes>(MessageKind::Request,
                                                                       GuiBrokerMethod::RegisterRule, request_id);
    u8* payload = frame.data() + duetos::ipc::kMessageAbiHeaderV1Bytes;
    WriteLe64(payload + kGuiBrokerPayloadTargetReferenceOffset, target_reference);
    WriteLe64(payload + kGuiBrokerRegisterPrincipalReferenceOffset, principal_reference);
    WriteLe64(payload + kGuiBrokerRegisterSequenceOffset, request_id);
    WriteLe32(payload + kGuiBrokerRegisterMessageOffset, message);
    WriteLe64(payload + kGuiBrokerRegisterScalar0Offset, wparam_mask);
    WriteLe64(payload + kGuiBrokerRegisterScalar1Offset, lparam_mask);
    return frame;
}

std::array<u8, kGuiBrokerRevokeRequestFrameBytes> MakeRevokeRequest(u64 request_id, u64 target_reference,
                                                                    u64 rule_sequence, u32 message, u64 wparam_mask,
                                                                    u64 lparam_mask)
{
    auto frame = MakeTypedFrame<kGuiBrokerRevokeRequestPayloadBytes>(MessageKind::Request, GuiBrokerMethod::RevokeRule,
                                                                     request_id);
    u8* payload = frame.data() + duetos::ipc::kMessageAbiHeaderV1Bytes;
    WriteLe64(payload + kGuiBrokerPayloadTargetReferenceOffset, target_reference);
    WriteLe64(payload + kGuiBrokerPayloadSequenceOffset, rule_sequence);
    WriteLe32(payload + kGuiBrokerPayloadMessageOffset, message);
    WriteLe64(payload + kGuiBrokerPayloadScalar0Offset, wparam_mask);
    WriteLe64(payload + kGuiBrokerPayloadScalar1Offset, lparam_mask);
    return frame;
}

std::array<u8, kGuiBrokerPostRequestFrameBytes> MakePostRequest(u64 request_id, u64 target_reference, u32 message,
                                                                u64 wparam, u64 lparam)
{
    auto frame =
        MakeTypedFrame<kGuiBrokerPostRequestPayloadBytes>(MessageKind::Request, GuiBrokerMethod::Post, request_id);
    u8* payload = frame.data() + duetos::ipc::kMessageAbiHeaderV1Bytes;
    WriteLe64(payload + kGuiBrokerPayloadTargetReferenceOffset, target_reference);
    WriteLe64(payload + kGuiBrokerPayloadSequenceOffset, request_id);
    WriteLe32(payload + kGuiBrokerPayloadMessageOffset, message);
    WriteLe64(payload + kGuiBrokerPayloadScalar0Offset, wparam);
    WriteLe64(payload + kGuiBrokerPayloadScalar1Offset, lparam);
    return frame;
}

std::array<u8, kGuiBrokerReplyFrameBytes> MakeReply(GuiBrokerMethod method, u64 request_id, GuiBrokerReplyStatus status)
{
    auto frame = MakeTypedFrame<kGuiBrokerReplyPayloadBytes>(MessageKind::Reply, method, request_id);
    u8* payload = frame.data() + duetos::ipc::kMessageAbiHeaderV1Bytes;
    WriteLe64(payload + kGuiBrokerReplySequenceOffset, request_id);
    WriteLe32(payload + kGuiBrokerReplyStatusOffset, static_cast<u32>(status));
    return frame;
}

std::array<u8, kGuiBrokerCancelFrameBytes> MakeCancel(u64 request_id)
{
    return MakeTypedFrame<0>(MessageKind::Cancel, GuiBrokerMethod::Post, request_id);
}

GuiBrokerEndpointCredentialsSnapshot Endpoint(u64 endpoint, u64 process, u64 task, Win32IntegrityLevel integrity,
                                              u64 committed_floor = 0)
{
    GuiBrokerEndpointCredentialsSnapshot snapshot{};
    snapshot.endpoint_identity = endpoint;
    snapshot.process_identity = process;
    snapshot.task_identity = task;
    snapshot.last_committed_request_sequence = committed_floor;
    snapshot.integrity = integrity;
    return snapshot;
}

GuiBrokerTargetAuthoritySnapshot Target(const GuiBrokerEndpointCredentialsSnapshot& holder,
                                        const GuiBrokerEndpointCredentialsSnapshot& owner, u64 authority,
                                        u64 transfer_reference, u32 rights,
                                        GuiBrokerTargetObjectKind kind = GuiBrokerTargetObjectKind::Window)
{
    GuiBrokerTargetAuthoritySnapshot snapshot{};
    snapshot.authority_identity = authority;
    snapshot.transfer_reference = transfer_reference;
    snapshot.holder_endpoint_identity = holder.endpoint_identity;
    snapshot.owner_endpoint_identity = owner.endpoint_identity;
    snapshot.target_process_identity = owner.process_identity;
    snapshot.target_task_identity = owner.task_identity;
    snapshot.target_object_identity =
        kind == GuiBrokerTargetObjectKind::Task ? owner.task_identity : 0xABCDEF0100000042ULL;
    snapshot.target_integrity = owner.integrity;
    snapshot.object_kind = kind;
    snapshot.rights = rights;
    return snapshot;
}

GuiBrokerPrincipalAuthoritySnapshot Principal(const GuiBrokerEndpointCredentialsSnapshot& holder,
                                              const GuiBrokerEndpointCredentialsSnapshot& principal, u64 authority,
                                              u64 transfer_reference)
{
    GuiBrokerPrincipalAuthoritySnapshot snapshot{};
    snapshot.authority_identity = authority;
    snapshot.transfer_reference = transfer_reference;
    snapshot.holder_endpoint_identity = holder.endpoint_identity;
    snapshot.principal_endpoint_identity = principal.endpoint_identity;
    snapshot.principal_process_identity = principal.process_identity;
    snapshot.principal_task_identity = principal.task_identity;
    snapshot.principal_integrity = principal.integrity;
    return snapshot;
}

GuiBrokerRuleAuthoritySnapshot Rule(const GuiBrokerTargetAuthoritySnapshot& target,
                                    const GuiBrokerPrincipalAuthoritySnapshot& principal, u64 authority,
                                    u64 rule_sequence, u32 message, u64 wparam_mask, u64 lparam_mask)
{
    GuiBrokerRuleAuthoritySnapshot snapshot{};
    snapshot.authority_identity = authority;
    snapshot.sender_endpoint_identity = principal.principal_endpoint_identity;
    snapshot.sender_process_identity = principal.principal_process_identity;
    snapshot.sender_task_identity = principal.principal_task_identity;
    snapshot.target_owner_endpoint_identity = target.owner_endpoint_identity;
    snapshot.target_process_identity = target.target_process_identity;
    snapshot.target_task_identity = target.target_task_identity;
    snapshot.target_object_identity = target.target_object_identity;
    snapshot.rule_sequence = rule_sequence;
    snapshot.wparam_allowed_bits = wparam_mask;
    snapshot.lparam_allowed_bits = lparam_mask;
    snapshot.message = message;
    snapshot.target_object_kind = target.object_kind;
    snapshot.sender_integrity = principal.principal_integrity;
    snapshot.target_integrity = target.target_integrity;
    snapshot.live = true;
    return snapshot;
}

GuiBrokerPendingAuthoritySnapshot Pending(const GuiBrokerEndpointCredentialsSnapshot& requester,
                                          const GuiBrokerEndpointCredentialsSnapshot& broker, u64 authority,
                                          u64 request_id, GuiBrokerMethod method,
                                          GuiBrokerPendingState state = GuiBrokerPendingState::Pending)
{
    GuiBrokerPendingAuthoritySnapshot snapshot{};
    snapshot.authority_identity = authority;
    snapshot.requester_endpoint_identity = requester.endpoint_identity;
    snapshot.broker_endpoint_identity = broker.endpoint_identity;
    snapshot.request_id = request_id;
    snapshot.method = method;
    snapshot.state = state;
    return snapshot;
}

template <std::size_t N>
GuiBrokerProtocolValidation Validate(const std::array<u8, N>& frame,
                                     const GuiBrokerEndpointCredentialsSnapshot& endpoint,
                                     const GuiBrokerTargetAuthoritySnapshot* target = nullptr,
                                     const GuiBrokerRuleAuthoritySnapshot* rule = nullptr,
                                     const GuiBrokerPendingAuthoritySnapshot* pending = nullptr)
{
    return GuiBrokerProtocolValidate(frame.data(), static_cast<u32>(frame.size()), &endpoint, target, nullptr, rule,
                                     pending);
}

template <std::size_t N>
GuiBrokerProtocolValidation ValidateRegister(const std::array<u8, N>& frame,
                                             const GuiBrokerEndpointCredentialsSnapshot& endpoint,
                                             const GuiBrokerTargetAuthoritySnapshot* target,
                                             const GuiBrokerPrincipalAuthoritySnapshot* principal)
{
    return GuiBrokerProtocolValidate(frame.data(), static_cast<u32>(frame.size()), &endpoint, target, principal,
                                     nullptr, nullptr);
}

template <std::size_t N>
void ExpectRegisterError(const std::array<u8, N>& frame, const GuiBrokerEndpointCredentialsSnapshot& endpoint,
                         const GuiBrokerTargetAuthoritySnapshot* target,
                         const GuiBrokerPrincipalAuthoritySnapshot* principal, GuiBrokerProtocolError error)
{
    const GuiBrokerProtocolValidation result = ValidateRegister(frame, endpoint, target, principal);
    EXPECT_EQ(result.error, error);
    EXPECT_EQ(result.message.operation, GuiBrokerValidatedOperation::Invalid);
    EXPECT_EQ(result.message.request_id, 0ULL);
    EXPECT_EQ(result.message.principal_authority_identity, 0ULL);
}

template <std::size_t N>
void ExpectError(const std::array<u8, N>& frame, const GuiBrokerEndpointCredentialsSnapshot& endpoint,
                 const GuiBrokerTargetAuthoritySnapshot* target, const GuiBrokerRuleAuthoritySnapshot* rule,
                 const GuiBrokerPendingAuthoritySnapshot* pending, GuiBrokerProtocolError error)
{
    const GuiBrokerProtocolValidation result = Validate(frame, endpoint, target, rule, pending);
    EXPECT_EQ(result.error, error);
    EXPECT_EQ(result.message.operation, GuiBrokerValidatedOperation::Invalid);
    EXPECT_EQ(result.message.request_id, 0ULL);
    EXPECT_EQ(result.message.sender_endpoint_identity, 0ULL);
    EXPECT_EQ(result.message.target_object_identity, 0ULL);
    EXPECT_EQ(result.message.rule_authority_identity, 0ULL);
    EXPECT_EQ(result.message.pending_authority_identity, 0ULL);
}

void ExpectAuthorityAliasError(const GuiBrokerProtocolValidation& result)
{
    EXPECT_EQ(result.error, GuiBrokerProtocolError::AuthorityAliasesMessage);
    EXPECT_EQ(result.message.operation, GuiBrokerValidatedOperation::Invalid);
    EXPECT_EQ(result.message.request_id, 0ULL);
    EXPECT_EQ(result.message.sender_endpoint_identity, 0ULL);
    EXPECT_EQ(result.message.target_authority_identity, 0ULL);
    EXPECT_EQ(result.message.principal_authority_identity, 0ULL);
    EXPECT_EQ(result.message.rule_authority_identity, 0ULL);
    EXPECT_EQ(result.message.pending_authority_identity, 0ULL);
}

} // namespace

int main()
{
    static_assert(kGuiBrokerRegisterRequestFrameBytes == 96);
    static_assert(kGuiBrokerRevokeRequestFrameBytes == 88);
    static_assert(kGuiBrokerPostRequestFrameBytes == 88);
    static_assert(kGuiBrokerReplyFrameBytes == 64);
    static_assert(kGuiBrokerCancelFrameBytes == 32);
    static_assert(kGuiBrokerPayloadMethodOffset == 8);
    static_assert(kGuiBrokerPayloadTargetReferenceOffset == 16);
    static_assert(kGuiBrokerPayloadSequenceOffset == 24);
    static_assert(kGuiBrokerPayloadMessageOffset == 32);
    static_assert(kGuiBrokerPayloadScalar0Offset == 40);
    static_assert(kGuiBrokerPayloadScalar1Offset == 48);
    static_assert(kGuiBrokerRegisterPrincipalReferenceOffset == 24);
    static_assert(kGuiBrokerRegisterSequenceOffset == 32);
    static_assert(kGuiBrokerRegisterMessageOffset == 40);
    static_assert(kGuiBrokerRegisterScalar0Offset == 48);
    static_assert(kGuiBrokerRegisterScalar1Offset == 56);
    static_assert(kGuiBrokerReplySequenceOffset == 16);

    const GuiBrokerEndpointCredentialsSnapshot owner =
        Endpoint(0xA001, 0xA101, 0xA201, Win32IntegrityLevel::Medium, 10);
    const GuiBrokerEndpointCredentialsSnapshot poster =
        Endpoint(0xB001, 0xB101, 0xB201, Win32IntegrityLevel::High, 100);
    const GuiBrokerEndpointCredentialsSnapshot broker =
        Endpoint(0xC001, 0xC101, 0xC201, Win32IntegrityLevel::System, 0);
    const GuiBrokerTargetAuthoritySnapshot owner_target =
        Target(owner, owner, 0xD001, 0xD101, kGuiBrokerTargetRightManageRules);
    const GuiBrokerTargetAuthoritySnapshot poster_target =
        Target(poster, owner, 0xD002, 0xD102, kGuiBrokerTargetRightReceivePosts);
    const GuiBrokerPrincipalAuthoritySnapshot sender_principal = Principal(owner, poster, 0xD201, 0xD301);
    constexpr u32 kMessage = 0x8123;
    constexpr u64 kWparamMask = 0xFF;
    constexpr u64 kLparamMask = 0xFFF;
    const GuiBrokerRuleAuthoritySnapshot rule =
        Rule(owner_target, sender_principal, 0xE001, 11, kMessage, kWparamMask, kLparamMask);

    // Kernel snapshots have one canonical representation. Transport transfer
    // authority is endpoint-local; rule authority instead binds the stable
    // owner/process/task/object generation tuple.
    EXPECT_TRUE(GuiBrokerEndpointCredentialsAreCanonical(owner));
    EXPECT_TRUE(GuiBrokerTargetAuthorityIsCanonical(owner_target));
    EXPECT_TRUE(GuiBrokerTargetAuthorityIsCanonical(poster_target));
    EXPECT_TRUE(GuiBrokerPrincipalAuthorityIsCanonical(sender_principal));
    EXPECT_TRUE(GuiBrokerRuleAuthorityIsCanonical(rule));
    GuiBrokerEndpointCredentialsSnapshot bad_endpoint = owner;
    bad_endpoint.endpoint_identity = 0;
    EXPECT_FALSE(GuiBrokerEndpointCredentialsAreCanonical(bad_endpoint));
    bad_endpoint = owner;
    bad_endpoint.integrity = Win32IntegrityLevel::Invalid;
    EXPECT_FALSE(GuiBrokerEndpointCredentialsAreCanonical(bad_endpoint));
    bad_endpoint = owner;
    bad_endpoint.reserved[6] = 1;
    EXPECT_FALSE(GuiBrokerEndpointCredentialsAreCanonical(bad_endpoint));

    GuiBrokerTargetAuthoritySnapshot bad_target = owner_target;
    bad_target.holder_endpoint_identity = 0;
    EXPECT_FALSE(GuiBrokerTargetAuthorityIsCanonical(bad_target));
    bad_target = owner_target;
    bad_target.rights = 0;
    EXPECT_FALSE(GuiBrokerTargetAuthorityIsCanonical(bad_target));
    bad_target = owner_target;
    bad_target.rights |= 0x80000000U;
    EXPECT_FALSE(GuiBrokerTargetAuthorityIsCanonical(bad_target));
    bad_target = owner_target;
    bad_target.object_kind = GuiBrokerTargetObjectKind::Invalid;
    EXPECT_FALSE(GuiBrokerTargetAuthorityIsCanonical(bad_target));
    bad_target =
        Target(owner, owner, 0xD003, 0xD103, kGuiBrokerTargetRightManageRules, GuiBrokerTargetObjectKind::Task);
    EXPECT_TRUE(GuiBrokerTargetAuthorityIsCanonical(bad_target));
    ++bad_target.target_object_identity;
    EXPECT_FALSE(GuiBrokerTargetAuthorityIsCanonical(bad_target));
    bad_target = owner_target;
    bad_target.reserved2 = 1;
    EXPECT_FALSE(GuiBrokerTargetAuthorityIsCanonical(bad_target));

    GuiBrokerPrincipalAuthoritySnapshot bad_principal = sender_principal;
    bad_principal.transfer_reference = 0;
    EXPECT_FALSE(GuiBrokerPrincipalAuthorityIsCanonical(bad_principal));
    bad_principal = sender_principal;
    bad_principal.principal_endpoint_identity = 0;
    EXPECT_FALSE(GuiBrokerPrincipalAuthorityIsCanonical(bad_principal));
    bad_principal = sender_principal;
    bad_principal.principal_integrity = Win32IntegrityLevel::Invalid;
    EXPECT_FALSE(GuiBrokerPrincipalAuthorityIsCanonical(bad_principal));
    bad_principal = sender_principal;
    bad_principal.reserved[5] = 1;
    EXPECT_FALSE(GuiBrokerPrincipalAuthorityIsCanonical(bad_principal));

    GuiBrokerRuleAuthoritySnapshot bad_rule = rule;
    bad_rule.live = false;
    EXPECT_FALSE(GuiBrokerRuleAuthorityIsCanonical(bad_rule));
    bad_rule = rule;
    bad_rule.live = 2;
    EXPECT_FALSE(GuiBrokerRuleAuthorityIsCanonical(bad_rule));
    bad_rule = rule;
    bad_rule.message = 0x0400;
    EXPECT_FALSE(GuiBrokerRuleAuthorityIsCanonical(bad_rule));
    bad_rule = rule;
    bad_rule.target_object_kind = GuiBrokerTargetObjectKind::Task;
    EXPECT_FALSE(GuiBrokerRuleAuthorityIsCanonical(bad_rule));
    bad_rule = rule;
    bad_rule.sender_endpoint_identity = bad_rule.target_owner_endpoint_identity;
    EXPECT_FALSE(GuiBrokerRuleAuthorityIsCanonical(bad_rule));
    bad_rule = rule;
    bad_rule.sender_process_identity = bad_rule.target_process_identity;
    EXPECT_FALSE(GuiBrokerRuleAuthorityIsCanonical(bad_rule));
    bad_rule = rule;
    bad_rule.sender_integrity = Win32IntegrityLevel::Low;
    EXPECT_FALSE(GuiBrokerRuleAuthorityIsCanonical(bad_rule));
    bad_rule = rule;
    bad_rule.reserved = 1;
    EXPECT_FALSE(GuiBrokerRuleAuthorityIsCanonical(bad_rule));

    const auto register_frame = MakeRegisterRequest(
        11, owner_target.transfer_reference, sender_principal.transfer_reference, kMessage, kWparamMask, kLparamMask);
    EXPECT_EQ(ReadLe32(register_frame.data() + duetos::ipc::kMessageAbiHeaderV1Bytes + kGuiBrokerRegisterMessageOffset),
              kMessage);
    const GuiBrokerProtocolValidation registered =
        ValidateRegister(register_frame, owner, &owner_target, &sender_principal);
    EXPECT_EQ(registered.error, GuiBrokerProtocolError::Ok);
    EXPECT_EQ(registered.message.operation, GuiBrokerValidatedOperation::RegisterRuleRequest);
    EXPECT_EQ(registered.message.request_id, 11ULL);
    EXPECT_EQ(registered.message.request_sequence, 11ULL);
    EXPECT_EQ(registered.message.rule_sequence, 11ULL);
    EXPECT_EQ(registered.message.sender_process_identity, owner.process_identity);
    EXPECT_EQ(registered.message.target_object_identity, owner_target.target_object_identity);
    EXPECT_EQ(registered.message.target_owner_endpoint_identity, owner.endpoint_identity);
    EXPECT_EQ(registered.message.principal_authority_identity, sender_principal.authority_identity);
    EXPECT_EQ(registered.message.principal_transfer_reference, sender_principal.transfer_reference);
    EXPECT_EQ(registered.message.rule_sender_endpoint_identity, poster.endpoint_identity);
    EXPECT_EQ(registered.message.rule_sender_process_identity, poster.process_identity);
    EXPECT_EQ(registered.message.rule_sender_task_identity, poster.task_identity);
    EXPECT_EQ(registered.message.rule_sender_integrity, poster.integrity);
    EXPECT_EQ(registered.message.message, kMessage);
    EXPECT_EQ(registered.message.wparam_allowed_bits, kWparamMask);
    EXPECT_EQ(registered.message.lparam_allowed_bits, kLparamMask);

    // Revoke names the exact registered rule schema and uses a newer request
    // id. A same-shaped rule attached to another target cannot be substituted.
    const auto revoke_frame =
        MakeRevokeRequest(12, owner_target.transfer_reference, 11, kMessage, kWparamMask, kLparamMask);
    const GuiBrokerProtocolValidation revoked = Validate(revoke_frame, owner, &owner_target, &rule);
    EXPECT_EQ(revoked.error, GuiBrokerProtocolError::Ok);
    EXPECT_EQ(revoked.message.operation, GuiBrokerValidatedOperation::RevokeRuleRequest);
    EXPECT_EQ(revoked.message.request_id, 12ULL);
    EXPECT_EQ(revoked.message.request_sequence, 12ULL);
    EXPECT_EQ(revoked.message.rule_sequence, 11ULL);
    EXPECT_EQ(revoked.message.rule_authority_identity, rule.authority_identity);

    // A poster resolves its own endpoint-local reference to the same stable
    // target object. Only scalars copied from trusted snapshots and the fixed
    // wire fields leave validation.
    const auto post_frame = MakePostRequest(101, poster_target.transfer_reference, kMessage, 0x34, 0x500);
    const GuiBrokerProtocolValidation posted = Validate(post_frame, poster, &poster_target, &rule);
    EXPECT_EQ(posted.error, GuiBrokerProtocolError::Ok);
    EXPECT_EQ(posted.message.operation, GuiBrokerValidatedOperation::PostRequest);
    EXPECT_EQ(posted.message.request_id, 101ULL);
    EXPECT_EQ(posted.message.request_sequence, 101ULL);
    EXPECT_EQ(posted.message.rule_sequence, 11ULL);
    EXPECT_EQ(posted.message.sender_endpoint_identity, poster.endpoint_identity);
    EXPECT_EQ(posted.message.sender_process_identity, poster.process_identity);
    EXPECT_EQ(posted.message.sender_task_identity, poster.task_identity);
    EXPECT_EQ(posted.message.sender_integrity, poster.integrity);
    EXPECT_EQ(posted.message.rule_sender_endpoint_identity, poster.endpoint_identity);
    EXPECT_EQ(posted.message.rule_sender_process_identity, poster.process_identity);
    EXPECT_EQ(posted.message.rule_sender_task_identity, poster.task_identity);
    EXPECT_EQ(posted.message.rule_sender_integrity, poster.integrity);
    EXPECT_EQ(posted.message.target_authority_identity, poster_target.authority_identity);
    EXPECT_EQ(posted.message.target_owner_endpoint_identity, owner.endpoint_identity);
    EXPECT_EQ(posted.message.target_process_identity, owner.process_identity);
    EXPECT_EQ(posted.message.target_task_identity, owner.task_identity);
    EXPECT_EQ(posted.message.target_object_identity, owner_target.target_object_identity);
    EXPECT_EQ(posted.message.rule_authority_identity, rule.authority_identity);
    EXPECT_EQ(posted.message.wparam, 0x34ULL);
    EXPECT_EQ(posted.message.lparam, 0x500ULL);

    // The validated scalars reduce directly to the existing exact trusted-
    // broker policy shape. No sender-authored identity or right is consulted.
    GuiMessageRequestSnapshot policy_request{};
    policy_request.sender.process_identity = posted.message.sender_process_identity;
    policy_request.sender.task_identity = posted.message.sender_task_identity;
    policy_request.sender.integrity = posted.message.sender_integrity;
    policy_request.target.process_identity = posted.message.target_process_identity;
    policy_request.target.task_identity = posted.message.target_task_identity;
    policy_request.target.integrity = posted.message.target_integrity;
    policy_request.target_window_identity = posted.message.target_object_identity;
    policy_request.message = posted.message.message;
    policy_request.wparam = posted.message.wparam;
    policy_request.lparam = posted.message.lparam;
    GuiMessageTrustedBrokerSnapshot policy_grant{};
    policy_grant.authority_identity = posted.message.rule_authority_identity;
    policy_grant.principal_process_identity = posted.message.rule_sender_process_identity;
    policy_grant.principal_task_identity = posted.message.rule_sender_task_identity;
    policy_grant.target_process_identity = posted.message.target_process_identity;
    policy_grant.target_task_identity = posted.message.target_task_identity;
    policy_grant.target_window_identity = posted.message.target_object_identity;
    policy_grant.wparam_allowed_bits = posted.message.wparam_allowed_bits;
    policy_grant.lparam_allowed_bits = posted.message.lparam_allowed_bits;
    policy_grant.message = posted.message.message;
    policy_grant.rights = kGuiBrokerRightPostApplicationScalar;
    EXPECT_EQ(GuiMessagePolicyEvaluate(policy_request, nullptr, &policy_grant),
              GuiMessagePolicyDecision::AllowTrustedBroker);

    // Task targets still use a nonzero transport-object reference and exact
    // task generation. Only the policy adapter maps that validated kind to
    // the HWND-less zero used by GuiMessageRequestSnapshot.
    const GuiBrokerTargetAuthoritySnapshot owner_task_target =
        Target(owner, owner, 0xD011, 0xD111, kGuiBrokerTargetRightManageRules, GuiBrokerTargetObjectKind::Task);
    const GuiBrokerTargetAuthoritySnapshot poster_task_target =
        Target(poster, owner, 0xD012, 0xD112, kGuiBrokerTargetRightReceivePosts, GuiBrokerTargetObjectKind::Task);
    const auto task_register_frame =
        MakeRegisterRequest(13, owner_task_target.transfer_reference, sender_principal.transfer_reference, kMessage,
                            kWparamMask, kLparamMask);
    EXPECT_EQ(ValidateRegister(task_register_frame, owner, &owner_task_target, &sender_principal).error,
              GuiBrokerProtocolError::Ok);
    const GuiBrokerRuleAuthoritySnapshot task_rule =
        Rule(owner_task_target, sender_principal, 0xE011, 13, kMessage, kWparamMask, kLparamMask);
    const auto task_post_frame = MakePostRequest(102, poster_task_target.transfer_reference, kMessage, 0x12, 0x345);
    const GuiBrokerProtocolValidation task_posted = Validate(task_post_frame, poster, &poster_task_target, &task_rule);
    EXPECT_EQ(task_posted.error, GuiBrokerProtocolError::Ok);
    EXPECT_EQ(task_posted.message.target_object_kind, GuiBrokerTargetObjectKind::Task);
    EXPECT_EQ(task_posted.message.target_object_identity, owner.task_identity);
    GuiMessageRequestSnapshot task_policy_request = policy_request;
    task_policy_request.target_window_identity = 0;
    task_policy_request.wparam = task_posted.message.wparam;
    task_policy_request.lparam = task_posted.message.lparam;
    GuiMessageTrustedBrokerSnapshot task_policy_grant = policy_grant;
    task_policy_grant.authority_identity = task_posted.message.rule_authority_identity;
    task_policy_grant.target_window_identity = 0;
    EXPECT_EQ(GuiMessagePolicyEvaluate(task_policy_request, nullptr, &task_policy_grant),
              GuiMessagePolicyDecision::AllowTrustedBroker);

    // Replies and cancellation correlate only through separately retained
    // pending authority. Validation itself does not consume that state.
    const GuiBrokerPendingAuthoritySnapshot post_pending = Pending(poster, broker, 0xF001, 101, GuiBrokerMethod::Post);
    EXPECT_TRUE(GuiBrokerPendingAuthorityIsCanonical(post_pending));
    for (u32 status_value = static_cast<u32>(GuiBrokerReplyStatus::Ok);
         status_value <= static_cast<u32>(GuiBrokerReplyStatus::InternalFailure); ++status_value)
    {
        const auto reply_frame = MakeReply(GuiBrokerMethod::Post, 101, static_cast<GuiBrokerReplyStatus>(status_value));
        const GuiBrokerProtocolValidation replied = Validate(reply_frame, broker, nullptr, nullptr, &post_pending);
        EXPECT_EQ(replied.error, GuiBrokerProtocolError::Ok);
        EXPECT_EQ(replied.message.operation, GuiBrokerValidatedOperation::PostReply);
        EXPECT_EQ(replied.message.reply_status, static_cast<GuiBrokerReplyStatus>(status_value));
        EXPECT_EQ(replied.message.pending_authority_identity, post_pending.authority_identity);
    }
    const auto cancel_frame = MakeCancel(101);
    const GuiBrokerProtocolValidation cancelled = Validate(cancel_frame, poster, nullptr, nullptr, &post_pending);
    EXPECT_EQ(cancelled.error, GuiBrokerProtocolError::Ok);
    EXPECT_EQ(cancelled.message.operation, GuiBrokerValidatedOperation::CancelPost);
    EXPECT_EQ(cancelled.message.pending_authority_identity, post_pending.authority_identity);

    const GuiBrokerPendingAuthoritySnapshot register_pending =
        Pending(owner, broker, 0xF002, 11, GuiBrokerMethod::RegisterRule);
    const auto register_reply = MakeReply(GuiBrokerMethod::RegisterRule, 11, GuiBrokerReplyStatus::Ok);
    EXPECT_EQ(Validate(register_reply, broker, nullptr, nullptr, &register_pending).message.operation,
              GuiBrokerValidatedOperation::RegisterRuleReply);
    const GuiBrokerPendingAuthoritySnapshot revoke_pending =
        Pending(owner, broker, 0xF003, 12, GuiBrokerMethod::RevokeRule);
    const auto revoke_reply = MakeReply(GuiBrokerMethod::RevokeRule, 12, GuiBrokerReplyStatus::Ok);
    EXPECT_EQ(Validate(revoke_reply, broker, nullptr, nullptr, &revoke_pending).message.operation,
              GuiBrokerValidatedOperation::RevokeRuleReply);

    GuiBrokerPendingAuthoritySnapshot bad_pending = post_pending;
    bad_pending.requester_endpoint_identity = bad_pending.broker_endpoint_identity;
    EXPECT_FALSE(GuiBrokerPendingAuthorityIsCanonical(bad_pending));
    bad_pending = post_pending;
    bad_pending.state = GuiBrokerPendingState::Invalid;
    EXPECT_FALSE(GuiBrokerPendingAuthorityIsCanonical(bad_pending));
    bad_pending = post_pending;
    bad_pending.reserved2 = 1;
    EXPECT_FALSE(GuiBrokerPendingAuthorityIsCanonical(bad_pending));

    // Envelope and payload canonicality fail before any scalar output. The
    // fixed shape leaves no wire slots for PID/TID/integrity/broker rights.
    {
        const GuiBrokerProtocolValidation result = GuiBrokerProtocolValidate(
            nullptr, kGuiBrokerPostRequestFrameBytes, &poster, &poster_target, nullptr, &rule, nullptr);
        EXPECT_EQ(result.error, GuiBrokerProtocolError::MalformedMessageEnvelope);
        EXPECT_EQ(result.message_error, MessageValidationError::NullBuffer);
        EXPECT_EQ(result.message.operation, GuiBrokerValidatedOperation::Invalid);
    }
    {
        auto hostile = post_frame;
        hostile[0] ^= 1;
        const GuiBrokerProtocolValidation result = Validate(hostile, poster, &poster_target, &rule);
        EXPECT_EQ(result.error, GuiBrokerProtocolError::MalformedMessageEnvelope);
        EXPECT_EQ(result.message_error, MessageValidationError::BadMagic);
    }
    {
        auto hostile = post_frame;
        WriteLe32(hostile.data() + kEnvelopeServiceOffset, kGuiBrokerServiceId ^ 1U);
        ExpectError(hostile, poster, &poster_target, &rule, nullptr, GuiBrokerProtocolError::WrongService);
    }
    {
        auto hostile = register_frame;
        WriteLe32(hostile.data() + duetos::ipc::kMessageAbiHeaderV1Bytes + kGuiBrokerRegisterReserved2Offset, 1);
        ExpectRegisterError(hostile, owner, &owner_target, &sender_principal,
                            GuiBrokerProtocolError::NonCanonicalPayload);
    }
    {
        auto wrong_size = MakeTypedFrame<kGuiBrokerRevokeRequestPayloadBytes>(MessageKind::Request,
                                                                              GuiBrokerMethod::RegisterRule, 11);
        ExpectRegisterError(wrong_size, owner, &owner_target, &sender_principal,
                            GuiBrokerProtocolError::WrongPayloadSize);
    }
    {
        auto hostile = post_frame;
        WriteLe32(hostile.data() + kEnvelopeMethodOffset, 0xFFFFFFFFU);
        ExpectError(hostile, poster, &poster_target, &rule, nullptr, GuiBrokerProtocolError::UnknownMethod);
    }
    {
        auto hostile = post_frame;
        WriteLe32(hostile.data() + duetos::ipc::kMessageAbiHeaderV1Bytes + kGuiBrokerPayloadMethodOffset,
                  static_cast<u32>(GuiBrokerMethod::RevokeRule));
        ExpectError(hostile, poster, &poster_target, &rule, nullptr, GuiBrokerProtocolError::PayloadMethodMismatch);
    }
    {
        auto hostile = post_frame;
        WriteLe16(hostile.data() + duetos::ipc::kMessageAbiHeaderV1Bytes + 6, 1);
        const GuiBrokerProtocolValidation result = Validate(hostile, poster, &poster_target, &rule);
        EXPECT_EQ(result.error, GuiBrokerProtocolError::MalformedPayloadEnvelope);
        EXPECT_EQ(result.payload_error, PayloadValidationError::UnsupportedFlags);
    }
    {
        auto hostile = post_frame;
        WriteLe32(hostile.data() + duetos::ipc::kMessageAbiHeaderV1Bytes + kGuiBrokerPayloadReservedOffset, 1);
        ExpectError(hostile, poster, &poster_target, &rule, nullptr, GuiBrokerProtocolError::NonCanonicalPayload);
    }
    {
        auto hostile = post_frame;
        WriteLe32(hostile.data() + duetos::ipc::kMessageAbiHeaderV1Bytes + kGuiBrokerPayloadReserved2Offset, 1);
        ExpectError(hostile, poster, &poster_target, &rule, nullptr, GuiBrokerProtocolError::NonCanonicalPayload);
    }
    {
        auto wrong_size = MakeTypedFrame<40>(MessageKind::Request, GuiBrokerMethod::Post, 101);
        ExpectError(wrong_size, poster, &poster_target, &rule, nullptr, GuiBrokerProtocolError::WrongPayloadSize);
    }
    {
        const auto no_payload = MakeTypedFrame<0>(MessageKind::Request, GuiBrokerMethod::Post, 101);
        ExpectError(no_payload, poster, &poster_target, &rule, nullptr, GuiBrokerProtocolError::MissingPayload);
    }
    {
        std::array<u8, kGuiBrokerPostRequestFrameBytes + 1> storage{};
        for (std::size_t index = 0; index < post_frame.size(); ++index)
            storage[index + 1] = post_frame[index];
        const GuiBrokerProtocolValidation result = GuiBrokerProtocolValidate(
            storage.data() + 1, static_cast<u32>(post_frame.size()), &poster, &poster_target, nullptr, &rule, nullptr);
        EXPECT_EQ(result.error, GuiBrokerProtocolError::Ok);
        EXPECT_EQ(result.message.wparam, 0x34ULL);
    }

    // Reject address ranges that would wrap before reading even one byte or
    // snapshot field. These synthetic addresses are never dereferenced.
    {
        const duetos::uptr maximum = ~static_cast<duetos::uptr>(0);
        const auto* wrapping_frame = reinterpret_cast<const u8*>(maximum - 15U);
        const GuiBrokerProtocolValidation result = GuiBrokerProtocolValidate(
            wrapping_frame, duetos::ipc::kMessageAbiHeaderV1Bytes, &poster, &poster_target, nullptr, &rule, nullptr);
        EXPECT_EQ(result.error, GuiBrokerProtocolError::MalformedMessageEnvelope);
        EXPECT_EQ(result.message_error, MessageValidationError::MessageTooLarge);
        EXPECT_EQ(result.message.operation, GuiBrokerValidatedOperation::Invalid);
    }
    {
        const duetos::uptr maximum = ~static_cast<duetos::uptr>(0);
        const auto* wrapping_endpoint = reinterpret_cast<const GuiBrokerEndpointCredentialsSnapshot*>(
            maximum - static_cast<duetos::uptr>(sizeof(GuiBrokerEndpointCredentialsSnapshot)) + 1U);
        const GuiBrokerProtocolValidation result =
            GuiBrokerProtocolValidate(post_frame.data(), static_cast<u32>(post_frame.size()), wrapping_endpoint,
                                      &poster_target, nullptr, &rule, nullptr);
        EXPECT_EQ(result.error, GuiBrokerProtocolError::MalformedEndpointCredentials);
        EXPECT_EQ(result.message.operation, GuiBrokerValidatedOperation::Invalid);
    }
    {
        const duetos::uptr maximum = ~static_cast<duetos::uptr>(0);
        const auto* wrapping_target = reinterpret_cast<const GuiBrokerTargetAuthoritySnapshot*>(
            maximum - static_cast<duetos::uptr>(sizeof(GuiBrokerTargetAuthoritySnapshot)) + 1U);
        const GuiBrokerProtocolValidation result = GuiBrokerProtocolValidate(
            post_frame.data(), static_cast<u32>(post_frame.size()), &poster, wrapping_target, nullptr, &rule, nullptr);
        EXPECT_EQ(result.error, GuiBrokerProtocolError::UnexpectedAuthority);
        EXPECT_EQ(result.message.operation, GuiBrokerValidatedOperation::Invalid);
    }

    // Trusted snapshots must never alias attacker-controlled frame storage.
    // The overlap gate precedes both message parsing and every snapshot read,
    // so carving any snapshot kind into even a now-corrupted frame is fatal.
    constexpr std::size_t kCarvedSnapshotOffset = 32;
    static_assert(kCarvedSnapshotOffset % alignof(GuiBrokerEndpointCredentialsSnapshot) == 0);
    static_assert(kCarvedSnapshotOffset % alignof(GuiBrokerTargetAuthoritySnapshot) == 0);
    static_assert(kCarvedSnapshotOffset % alignof(GuiBrokerPrincipalAuthoritySnapshot) == 0);
    static_assert(kCarvedSnapshotOffset % alignof(GuiBrokerRuleAuthoritySnapshot) == 0);
    static_assert(kCarvedSnapshotOffset % alignof(GuiBrokerPendingAuthoritySnapshot) == 0);
    static_assert(kCarvedSnapshotOffset + sizeof(GuiBrokerEndpointCredentialsSnapshot) <= 256);
    static_assert(kCarvedSnapshotOffset + sizeof(GuiBrokerTargetAuthoritySnapshot) <= 256);
    static_assert(kCarvedSnapshotOffset + sizeof(GuiBrokerPrincipalAuthoritySnapshot) <= 256);
    static_assert(kCarvedSnapshotOffset + sizeof(GuiBrokerRuleAuthoritySnapshot) <= 256);
    static_assert(kCarvedSnapshotOffset + sizeof(GuiBrokerPendingAuthoritySnapshot) <= 256);
    {
        alignas(GuiBrokerEndpointCredentialsSnapshot) std::array<u8, 256> storage{};
        std::memcpy(storage.data(), post_frame.data(), post_frame.size());
        std::memcpy(storage.data() + kCarvedSnapshotOffset, &poster, sizeof(poster));
        const auto* carved_endpoint =
            reinterpret_cast<const GuiBrokerEndpointCredentialsSnapshot*>(storage.data() + kCarvedSnapshotOffset);
        ExpectAuthorityAliasError(GuiBrokerProtocolValidate(storage.data(), static_cast<u32>(post_frame.size()),
                                                            carved_endpoint, &poster_target, nullptr, &rule, nullptr));
    }
    {
        alignas(GuiBrokerTargetAuthoritySnapshot) std::array<u8, 256> storage{};
        std::memcpy(storage.data(), post_frame.data(), post_frame.size());
        std::memcpy(storage.data() + kCarvedSnapshotOffset, &poster_target, sizeof(poster_target));
        const auto* carved_target =
            reinterpret_cast<const GuiBrokerTargetAuthoritySnapshot*>(storage.data() + kCarvedSnapshotOffset);
        ExpectAuthorityAliasError(GuiBrokerProtocolValidate(storage.data(), static_cast<u32>(post_frame.size()),
                                                            &poster, carved_target, nullptr, &rule, nullptr));
    }
    {
        alignas(GuiBrokerPrincipalAuthoritySnapshot) std::array<u8, 256> storage{};
        std::memcpy(storage.data(), register_frame.data(), register_frame.size());
        std::memcpy(storage.data() + kCarvedSnapshotOffset, &sender_principal, sizeof(sender_principal));
        const auto* carved_principal =
            reinterpret_cast<const GuiBrokerPrincipalAuthoritySnapshot*>(storage.data() + kCarvedSnapshotOffset);
        ExpectAuthorityAliasError(GuiBrokerProtocolValidate(storage.data(), static_cast<u32>(register_frame.size()),
                                                            &owner, &owner_target, carved_principal, nullptr, nullptr));
    }
    {
        alignas(GuiBrokerRuleAuthoritySnapshot) std::array<u8, 256> storage{};
        std::memcpy(storage.data(), post_frame.data(), post_frame.size());
        std::memcpy(storage.data() + kCarvedSnapshotOffset, &rule, sizeof(rule));
        const auto* carved_rule =
            reinterpret_cast<const GuiBrokerRuleAuthoritySnapshot*>(storage.data() + kCarvedSnapshotOffset);
        ExpectAuthorityAliasError(GuiBrokerProtocolValidate(storage.data(), static_cast<u32>(post_frame.size()),
                                                            &poster, &poster_target, nullptr, carved_rule, nullptr));
    }
    {
        alignas(GuiBrokerPendingAuthoritySnapshot) std::array<u8, 256> storage{};
        std::memcpy(storage.data(), register_reply.data(), register_reply.size());
        std::memcpy(storage.data() + kCarvedSnapshotOffset, &register_pending, sizeof(register_pending));
        const auto* carved_pending =
            reinterpret_cast<const GuiBrokerPendingAuthoritySnapshot*>(storage.data() + kCarvedSnapshotOffset);
        ExpectAuthorityAliasError(GuiBrokerProtocolValidate(storage.data(), static_cast<u32>(register_reply.size()),
                                                            &broker, nullptr, nullptr, nullptr, carved_pending));
    }
    EXPECT_EQ(GuiBrokerProtocolValidate(post_frame.data(), static_cast<u32>(post_frame.size()), nullptr, &poster_target,
                                        nullptr, &rule, nullptr)
                  .error,
              GuiBrokerProtocolError::MalformedEndpointCredentials);

    // Cross-kind and cross-method reinterpretation never reuses a payload.
    {
        auto hostile = post_frame;
        WriteLe16(hostile.data() + kEnvelopeKindOffset, static_cast<u16>(MessageKind::Reply));
        ExpectError(hostile, broker, nullptr, nullptr, &post_pending, GuiBrokerProtocolError::WrongPayloadSize);
    }
    {
        auto hostile = post_frame;
        WriteLe16(hostile.data() + kEnvelopeKindOffset, static_cast<u16>(MessageKind::Notification));
        WriteLe64(hostile.data() + kEnvelopeRequestIdOffset, 0);
        ExpectError(hostile, poster, &poster_target, &rule, nullptr, GuiBrokerProtocolError::UnexpectedKind);
    }
    {
        auto hostile = revoke_frame;
        WriteLe32(hostile.data() + kEnvelopeMethodOffset, static_cast<u32>(GuiBrokerMethod::Post));
        ExpectError(hostile, owner, &owner_target, &rule, nullptr, GuiBrokerProtocolError::PayloadMethodMismatch);
    }
    {
        const auto cancel_wrong_method = MakeTypedFrame<0>(MessageKind::Cancel, GuiBrokerMethod::RevokeRule, 101);
        ExpectError(cancel_wrong_method, poster, nullptr, nullptr, &post_pending,
                    GuiBrokerProtocolError::UnexpectedKind);
    }
    EXPECT_EQ(GuiBrokerProtocolValidate(post_frame.data(), static_cast<u32>(post_frame.size()), &poster, &poster_target,
                                        &sender_principal, &rule, nullptr)
                  .error,
              GuiBrokerProtocolError::UnexpectedAuthority);
    EXPECT_EQ(GuiBrokerProtocolValidate(register_frame.data(), static_cast<u32>(register_frame.size()), &owner,
                                        &owner_target, &sender_principal, &rule, nullptr)
                  .error,
              GuiBrokerProtocolError::UnexpectedAuthority);
    EXPECT_EQ(GuiBrokerProtocolValidate(register_reply.data(), static_cast<u32>(register_reply.size()), &broker,
                                        &owner_target, nullptr, nullptr, &register_pending)
                  .error,
              GuiBrokerProtocolError::UnexpectedAuthority);

    // Replay is checked against authenticated endpoint state, never a sender
    // claim. Payload and envelope sequence values must also be identical.
    {
        auto replay = poster;
        replay.last_committed_request_sequence = 101;
        ExpectError(post_frame, replay, &poster_target, &rule, nullptr, GuiBrokerProtocolError::ReplayedRequest);
    }
    {
        auto replay = poster;
        replay.last_committed_request_sequence = 102;
        ExpectError(post_frame, replay, &poster_target, &rule, nullptr, GuiBrokerProtocolError::ReplayedRequest);
    }
    {
        auto hostile = post_frame;
        WriteLe64(hostile.data() + duetos::ipc::kMessageAbiHeaderV1Bytes + kGuiBrokerPayloadSequenceOffset, 102);
        ExpectError(hostile, poster, &poster_target, &rule, nullptr, GuiBrokerProtocolError::InvalidRequestSequence);
    }
    {
        auto hostile = register_frame;
        WriteLe64(hostile.data() + duetos::ipc::kMessageAbiHeaderV1Bytes + kGuiBrokerRegisterSequenceOffset, 12);
        ExpectRegisterError(hostile, owner, &owner_target, &sender_principal,
                            GuiBrokerProtocolError::InvalidRequestSequence);
    }
    {
        auto hostile = revoke_frame;
        WriteLe64(hostile.data() + duetos::ipc::kMessageAbiHeaderV1Bytes + kGuiBrokerPayloadSequenceOffset, 12);
        ExpectError(hostile, owner, &owner_target, &rule, nullptr, GuiBrokerProtocolError::InvalidRequestSequence);
    }

    // Confused-deputy and authority-alias attempts fail against the retained
    // endpoint namespace and stable target generation, even when raw transfer
    // numbers or rule masks happen to collide.
    {
        GuiBrokerTargetAuthoritySnapshot stolen = poster_target;
        stolen.holder_endpoint_identity = owner.endpoint_identity;
        ExpectError(post_frame, poster, &stolen, &rule, nullptr, GuiBrokerProtocolError::TargetAuthorityMismatch);
    }
    {
        GuiBrokerTargetAuthoritySnapshot foreign_owner = owner_target;
        foreign_owner.owner_endpoint_identity = poster.endpoint_identity;
        ExpectRegisterError(register_frame, owner, &foreign_owner, &sender_principal,
                            GuiBrokerProtocolError::EndpointDoesNotOwnTarget);
    }
    {
        GuiBrokerTargetAuthoritySnapshot aliased = poster_target;
        ++aliased.target_object_identity;
        ExpectError(post_frame, poster, &aliased, &rule, nullptr, GuiBrokerProtocolError::RuleAuthorityMismatch);
    }
    {
        GuiBrokerRuleAuthoritySnapshot aliased = rule;
        ++aliased.target_owner_endpoint_identity;
        ExpectError(post_frame, poster, &poster_target, &aliased, nullptr,
                    GuiBrokerProtocolError::RuleAuthorityMismatch);
    }
    {
        auto hostile = post_frame;
        WriteLe64(hostile.data() + duetos::ipc::kMessageAbiHeaderV1Bytes + kGuiBrokerPayloadTargetReferenceOffset,
                  owner_target.transfer_reference);
        ExpectError(hostile, poster, &poster_target, &rule, nullptr, GuiBrokerProtocolError::TargetReferenceMismatch);
    }
    {
        GuiBrokerTargetAuthoritySnapshot equivalent_transfer = poster_target;
        equivalent_transfer.authority_identity ^= 0x55;
        EXPECT_EQ(Validate(post_frame, poster, &equivalent_transfer, &rule).error, GuiBrokerProtocolError::Ok);
    }

    // RegisterRule resolves an opaque sender-principal transfer in the target
    // owner's endpoint namespace. The wire reference cannot substitute for
    // the separately authenticated endpoint/process/task/integrity snapshot.
    ExpectRegisterError(register_frame, owner, &owner_target, nullptr,
                        GuiBrokerProtocolError::MissingPrincipalAuthority);
    {
        GuiBrokerPrincipalAuthoritySnapshot malformed = sender_principal;
        malformed.reserved[0] = 1;
        ExpectRegisterError(register_frame, owner, &owner_target, &malformed,
                            GuiBrokerProtocolError::MalformedPrincipalAuthority);
    }
    {
        GuiBrokerPrincipalAuthoritySnapshot stolen = sender_principal;
        stolen.holder_endpoint_identity = poster.endpoint_identity;
        ExpectRegisterError(register_frame, owner, &owner_target, &stolen,
                            GuiBrokerProtocolError::PrincipalAuthorityMismatch);
    }
    {
        auto hostile = register_frame;
        WriteLe64(hostile.data() + duetos::ipc::kMessageAbiHeaderV1Bytes + kGuiBrokerRegisterPrincipalReferenceOffset,
                  sender_principal.transfer_reference ^ 1ULL);
        ExpectRegisterError(hostile, owner, &owner_target, &sender_principal,
                            GuiBrokerProtocolError::PrincipalReferenceMismatch);
    }
    {
        GuiBrokerPrincipalAuthoritySnapshot cross_kind_alias = sender_principal;
        cross_kind_alias.transfer_reference = owner_target.transfer_reference;
        auto hostile = register_frame;
        WriteLe64(hostile.data() + duetos::ipc::kMessageAbiHeaderV1Bytes + kGuiBrokerRegisterPrincipalReferenceOffset,
                  owner_target.transfer_reference);
        ExpectRegisterError(hostile, owner, &owner_target, &cross_kind_alias,
                            GuiBrokerProtocolError::PrincipalReferenceMismatch);
    }
    {
        GuiBrokerPrincipalAuthoritySnapshot same_process = sender_principal;
        same_process.principal_endpoint_identity ^= 0x10;
        same_process.principal_process_identity = owner.process_identity;
        same_process.principal_task_identity ^= 0x20;
        same_process.principal_integrity = owner.integrity;
        ExpectRegisterError(register_frame, owner, &owner_target, &same_process,
                            GuiBrokerProtocolError::SameProcessPost);
    }
    {
        GuiBrokerPrincipalAuthoritySnapshot same_task_lookalike = sender_principal;
        same_task_lookalike.principal_endpoint_identity ^= 0x11;
        same_task_lookalike.principal_process_identity ^= 0x21;
        same_task_lookalike.principal_task_identity = owner.task_identity;
        ExpectRegisterError(register_frame, owner, &owner_target, &same_task_lookalike,
                            GuiBrokerProtocolError::SameProcessPost);
    }
    {
        GuiBrokerPrincipalAuthoritySnapshot low_principal = sender_principal;
        low_principal.principal_integrity = Win32IntegrityLevel::Low;
        ExpectRegisterError(register_frame, owner, &owner_target, &low_principal,
                            GuiBrokerProtocolError::LowToHighIntegrity);
    }

    // The stored rule is exact to the authenticated endpoint generation as
    // well as process/task/integrity. Reconnects and lookalike principals do
    // not inherit a prior endpoint's grant.
    {
        GuiBrokerEndpointCredentialsSnapshot reconnect = poster;
        reconnect.endpoint_identity ^= 0x100;
        GuiBrokerTargetAuthoritySnapshot reconnect_target = poster_target;
        reconnect_target.holder_endpoint_identity = reconnect.endpoint_identity;
        ExpectError(post_frame, reconnect, &reconnect_target, &rule, nullptr,
                    GuiBrokerProtocolError::RulePrincipalMismatch);
    }
    {
        GuiBrokerEndpointCredentialsSnapshot cross_sender = poster;
        cross_sender.endpoint_identity ^= 0x200;
        cross_sender.process_identity ^= 0x200;
        cross_sender.task_identity ^= 0x200;
        GuiBrokerTargetAuthoritySnapshot cross_target = poster_target;
        cross_target.holder_endpoint_identity = cross_sender.endpoint_identity;
        ExpectError(post_frame, cross_sender, &cross_target, &rule, nullptr,
                    GuiBrokerProtocolError::RulePrincipalMismatch);
    }
    {
        GuiBrokerEndpointCredentialsSnapshot mutated = poster;
        mutated.process_identity ^= 1;
        ExpectError(post_frame, mutated, &poster_target, &rule, nullptr, GuiBrokerProtocolError::RulePrincipalMismatch);
        mutated = poster;
        mutated.task_identity ^= 1;
        ExpectError(post_frame, mutated, &poster_target, &rule, nullptr, GuiBrokerProtocolError::RulePrincipalMismatch);
        mutated = poster;
        mutated.integrity = Win32IntegrityLevel::System;
        ExpectError(post_frame, mutated, &poster_target, &rule, nullptr, GuiBrokerProtocolError::RulePrincipalMismatch);
    }
    {
        GuiBrokerRuleAuthoritySnapshot mutated = rule;
        mutated.sender_endpoint_identity ^= 0x400;
        ExpectError(post_frame, poster, &poster_target, &mutated, nullptr,
                    GuiBrokerProtocolError::RulePrincipalMismatch);
        mutated = rule;
        mutated.sender_process_identity ^= 0x400;
        ExpectError(post_frame, poster, &poster_target, &mutated, nullptr,
                    GuiBrokerProtocolError::RulePrincipalMismatch);
        mutated = rule;
        mutated.sender_task_identity ^= 0x400;
        ExpectError(post_frame, poster, &poster_target, &mutated, nullptr,
                    GuiBrokerProtocolError::RulePrincipalMismatch);
        mutated = rule;
        mutated.sender_integrity = Win32IntegrityLevel::System;
        ExpectError(post_frame, poster, &poster_target, &mutated, nullptr,
                    GuiBrokerProtocolError::RulePrincipalMismatch);
    }

    {
        GuiBrokerTargetAuthoritySnapshot missing_right = owner_target;
        missing_right.rights = kGuiBrokerTargetRightReceivePosts;
        ExpectRegisterError(register_frame, owner, &missing_right, &sender_principal,
                            GuiBrokerProtocolError::MissingTargetRight);
    }
    {
        GuiBrokerTargetAuthoritySnapshot missing_right = poster_target;
        missing_right.rights = kGuiBrokerTargetRightManageRules;
        ExpectError(post_frame, poster, &missing_right, &rule, nullptr, GuiBrokerProtocolError::MissingTargetRight);
    }
    {
        GuiBrokerEndpointCredentialsSnapshot low = poster;
        low.integrity = Win32IntegrityLevel::Low;
        ExpectError(post_frame, low, &poster_target, &rule, nullptr, GuiBrokerProtocolError::RulePrincipalMismatch);
    }
    {
        auto payload_escape = post_frame;
        WriteLe64(payload_escape.data() + duetos::ipc::kMessageAbiHeaderV1Bytes + kGuiBrokerPayloadScalar0Offset,
                  kWparamMask + 1);
        ExpectError(payload_escape, poster, &poster_target, &rule, nullptr, GuiBrokerProtocolError::PayloadOutsideRule);
    }

    // Pending state is exact and replay-safe only when the caller atomically
    // commits the returned transition. Completed/cancelled aliases, wrong
    // endpoints, request ids, and methods are all refused here.
    {
        GuiBrokerPendingAuthoritySnapshot completed = post_pending;
        completed.state = GuiBrokerPendingState::Completed;
        ExpectError(cancel_frame, poster, nullptr, nullptr, &completed,
                    GuiBrokerProtocolError::PendingAuthorityMismatch);
    }
    {
        GuiBrokerPendingAuthoritySnapshot wrong_endpoint = post_pending;
        ++wrong_endpoint.requester_endpoint_identity;
        ExpectError(cancel_frame, poster, nullptr, nullptr, &wrong_endpoint,
                    GuiBrokerProtocolError::PendingAuthorityMismatch);
    }
    {
        GuiBrokerPendingAuthoritySnapshot wrong_method = post_pending;
        wrong_method.method = GuiBrokerMethod::RevokeRule;
        const auto reply_frame = MakeReply(GuiBrokerMethod::Post, 101, GuiBrokerReplyStatus::Ok);
        ExpectError(reply_frame, broker, nullptr, nullptr, &wrong_method,
                    GuiBrokerProtocolError::PendingAuthorityMismatch);
    }
    {
        GuiBrokerPendingAuthoritySnapshot wrong_broker = post_pending;
        ++wrong_broker.broker_endpoint_identity;
        const auto reply_frame = MakeReply(GuiBrokerMethod::Post, 101, GuiBrokerReplyStatus::Ok);
        ExpectError(reply_frame, broker, nullptr, nullptr, &wrong_broker,
                    GuiBrokerProtocolError::PendingAuthorityMismatch);
    }
    {
        auto reply_frame = MakeReply(GuiBrokerMethod::Post, 101, static_cast<GuiBrokerReplyStatus>(9));
        ExpectError(reply_frame, broker, nullptr, nullptr, &post_pending, GuiBrokerProtocolError::UnknownReplyStatus);
    }
    {
        auto reply_frame = MakeReply(GuiBrokerMethod::Post, 101, GuiBrokerReplyStatus::Ok);
        WriteLe64(reply_frame.data() + duetos::ipc::kMessageAbiHeaderV1Bytes + kGuiBrokerReplySequenceOffset, 102);
        ExpectError(reply_frame, broker, nullptr, nullptr, &post_pending,
                    GuiBrokerProtocolError::InvalidRequestSequence);
    }

    // Exhaust the entire Win32 16-bit message namespace. The broker contract
    // admits exactly WM_APP..0xBFFF; every other system/private/registered
    // identifier fails before it can be paired with a grant.
    for (u32 message = 0; message <= kGuiMessageMaximum; ++message)
    {
        const auto frame = MakePostRequest(101, poster_target.transfer_reference, message, 0, 0);
        const GuiBrokerRuleAuthoritySnapshot exact_rule =
            Rule(owner_target, sender_principal, 0xE100, 11, message, 0, 0);
        const GuiBrokerProtocolValidation result = Validate(frame, poster, &poster_target, &exact_rule);
        const bool expected = message >= kGuiMessageApplicationFirst && message <= kGuiMessageApplicationLast;
        EXPECT_EQ(result.error == GuiBrokerProtocolError::Ok, expected);
        if (expected)
            EXPECT_EQ(result.message.message, message);
        else
            EXPECT_EQ(result.error, GuiBrokerProtocolError::InvalidMessage);
    }

    // Deterministic structured fuzz pins scalar masks and sequence replay.
    u64 random = 0x8C0FFEE5A17E1234ULL;
    for (u32 iteration = 0; iteration < 100000; ++iteration)
    {
        const u64 wparam_mask = NextRandom(random);
        const u64 lparam_mask = NextRandom(random);
        u64 wparam = NextRandom(random);
        u64 lparam = NextRandom(random);
        if ((iteration & 1U) == 0)
        {
            wparam &= wparam_mask;
            lparam &= lparam_mask;
        }
        const u64 request_id = 101 + (NextRandom(random) & 0xFFFFULL);
        const auto frame = MakePostRequest(request_id, poster_target.transfer_reference, kMessage, wparam, lparam);
        const GuiBrokerRuleAuthoritySnapshot fuzz_rule =
            Rule(owner_target, sender_principal, 0xE200, 11, kMessage, wparam_mask, lparam_mask);
        GuiBrokerEndpointCredentialsSnapshot fuzz_endpoint = poster;
        fuzz_endpoint.last_committed_request_sequence = NextRandom(random) & 0x1FFFFULL;
        const GuiBrokerProtocolValidation result = Validate(frame, fuzz_endpoint, &poster_target, &fuzz_rule);
        const bool fresh = request_id > fuzz_endpoint.last_committed_request_sequence;
        const bool payload_fits = (wparam & ~wparam_mask) == 0 && (lparam & ~lparam_mask) == 0;
        EXPECT_EQ(result.error == GuiBrokerProtocolError::Ok, fresh && payload_fits);
        if (result.error == GuiBrokerProtocolError::Ok)
        {
            EXPECT_EQ(result.message.sender_process_identity, poster.process_identity);
            EXPECT_EQ(result.message.target_object_identity, poster_target.target_object_identity);
            EXPECT_EQ(result.message.request_id, request_id);
        }
    }

    // Byte-mutation fuzz may still succeed when it changes only an allowed
    // scalar. Any success must preserve every authority-derived field and all
    // protocol invariants regardless of hostile byte contents.
    const GuiBrokerRuleAuthoritySnapshot wide_rule =
        Rule(owner_target, sender_principal, 0xE300, 11, kMessage, ~u64(0), ~u64(0));
    for (u32 iteration = 0; iteration < 50000; ++iteration)
    {
        auto mutated = post_frame;
        const u64 draw = NextRandom(random);
        const std::size_t index = static_cast<std::size_t>(draw % mutated.size());
        mutated[index] ^= static_cast<u8>(1U << ((draw >> 8U) & 7U));
        const GuiBrokerProtocolValidation result = Validate(mutated, poster, &poster_target, &wide_rule);
        if (result.error == GuiBrokerProtocolError::Ok)
        {
            EXPECT_EQ(result.message.operation, GuiBrokerValidatedOperation::PostRequest);
            EXPECT_TRUE(result.message.request_id > poster.last_committed_request_sequence);
            EXPECT_EQ(result.message.request_id, result.message.request_sequence);
            EXPECT_TRUE(result.message.message >= kGuiMessageApplicationFirst);
            EXPECT_TRUE(result.message.message <= kGuiMessageApplicationLast);
            EXPECT_EQ(result.message.sender_endpoint_identity, poster.endpoint_identity);
            EXPECT_EQ(result.message.sender_process_identity, poster.process_identity);
            EXPECT_EQ(result.message.sender_task_identity, poster.task_identity);
            EXPECT_EQ(result.message.sender_integrity, poster.integrity);
            EXPECT_EQ(result.message.target_owner_endpoint_identity, owner.endpoint_identity);
            EXPECT_EQ(result.message.target_process_identity, owner.process_identity);
            EXPECT_EQ(result.message.target_task_identity, owner.task_identity);
            EXPECT_EQ(result.message.target_object_identity, poster_target.target_object_identity);
            EXPECT_EQ(result.message.rule_authority_identity, wide_rule.authority_identity);
        }
    }

    // Immutable frames and retained snapshots may be validated concurrently.
    // Workers do not publish through the host-test macros; they report only a
    // scalar failure count after joining so this is also a meaningful TSan
    // exercise of the documented any-thread/pure contract.
    std::atomic<u32> concurrent_failures{0};
    const auto validate_concurrently = [&]()
    {
        for (u32 iteration = 0; iteration < 10000; ++iteration)
        {
            const GuiBrokerProtocolValidation result = Validate(post_frame, poster, &poster_target, &rule);
            if (result.error != GuiBrokerProtocolError::Ok ||
                result.message.operation != GuiBrokerValidatedOperation::PostRequest ||
                result.message.request_id != 101 || result.message.target_authority_identity != 0xD002 ||
                result.message.rule_authority_identity != 0xE001)
            {
                concurrent_failures.fetch_add(1, std::memory_order_relaxed);
            }
        }
    };
    std::thread first_validator(validate_concurrently);
    std::thread second_validator(validate_concurrently);
    first_validator.join();
    second_validator.join();
    EXPECT_EQ(concurrent_failures.load(std::memory_order_relaxed), 0U);

    EXPECT_STREQ(GuiBrokerProtocolErrorName(GuiBrokerProtocolError::TargetAuthorityMismatch),
                 "target-authority-mismatch");
    EXPECT_STREQ(GuiBrokerProtocolErrorName(GuiBrokerProtocolError::AuthorityAliasesMessage),
                 "authority-aliases-message");
    EXPECT_STREQ(GuiBrokerProtocolErrorName(static_cast<GuiBrokerProtocolError>(0xFF)), "unknown");
    return duetos_host_test::finish_main("test_gui_broker_protocol");
}
