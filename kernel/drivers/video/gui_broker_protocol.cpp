#include "drivers/video/gui_broker_protocol.h"

namespace duetos::drivers::video
{

namespace
{

static_assert(sizeof(uptr) >= sizeof(u64));

u32 ReadLe32(const u8* bytes)
{
    return static_cast<u32>(bytes[0]) | (static_cast<u32>(bytes[1]) << 8U) | (static_cast<u32>(bytes[2]) << 16U) |
           (static_cast<u32>(bytes[3]) << 24U);
}

u64 ReadLe64(const u8* bytes)
{
    return static_cast<u64>(ReadLe32(bytes)) | (static_cast<u64>(ReadLe32(bytes + 4)) << 32U);
}

bool ReservedBytesAreZero(const u8* bytes, u32 count)
{
    if (bytes == nullptr)
        return false;
    for (u32 index = 0; index < count; ++index)
    {
        if (bytes[index] != 0)
            return false;
    }
    return true;
}

bool PointerRangeIsValid(const void* pointer, u64 bytes)
{
    if (pointer == nullptr)
        return false;
    const uptr begin = reinterpret_cast<uptr>(pointer);
    const uptr maximum = ~static_cast<uptr>(0);
    return static_cast<uptr>(bytes) <= maximum - begin;
}

bool PointerRangesOverlap(const void* left, u64 left_bytes, const void* right, u64 right_bytes)
{
    if (left_bytes == 0 || right_bytes == 0)
        return false;
    const uptr left_begin = reinterpret_cast<uptr>(left);
    const uptr right_begin = reinterpret_cast<uptr>(right);
    const uptr left_end = left_begin + static_cast<uptr>(left_bytes);
    const uptr right_end = right_begin + static_cast<uptr>(right_bytes);
    return left_begin < right_end && right_begin < left_end;
}

bool IntegrityIsValid(core::Win32IntegrityLevel integrity)
{
    return integrity >= core::Win32IntegrityLevel::Untrusted && integrity <= core::Win32IntegrityLevel::System;
}

bool MethodIsValid(GuiBrokerMethod method)
{
    switch (method)
    {
    case GuiBrokerMethod::RegisterRule:
    case GuiBrokerMethod::RevokeRule:
    case GuiBrokerMethod::Post:
        return true;
    }
    return false;
}

bool PendingStateIsValid(GuiBrokerPendingState state)
{
    switch (state)
    {
    case GuiBrokerPendingState::Pending:
    case GuiBrokerPendingState::Completed:
    case GuiBrokerPendingState::Cancelled:
        return true;
    case GuiBrokerPendingState::Invalid:
        return false;
    }
    return false;
}

bool ReplyStatusIsValid(GuiBrokerReplyStatus status)
{
    switch (status)
    {
    case GuiBrokerReplyStatus::Ok:
    case GuiBrokerReplyStatus::Denied:
    case GuiBrokerReplyStatus::InvalidTarget:
    case GuiBrokerReplyStatus::InvalidRule:
    case GuiBrokerReplyStatus::StaleSequence:
    case GuiBrokerReplyStatus::QueueFull:
    case GuiBrokerReplyStatus::Cancelled:
    case GuiBrokerReplyStatus::NotFound:
    case GuiBrokerReplyStatus::InternalFailure:
        return true;
    }
    return false;
}

bool IsApplicationScalarMessage(u32 message)
{
    return GuiMessageClassifySecurity(message) == GuiMessageSecurityClass::ApplicationScalar;
}

GuiBrokerProtocolValidation Failure(GuiBrokerProtocolError error,
                                    ipc::MessageValidationError message_error = ipc::MessageValidationError::Ok,
                                    ipc::PayloadValidationError payload_error = ipc::PayloadValidationError::Ok)
{
    GuiBrokerProtocolValidation result{};
    result.error = error;
    result.message_error = message_error;
    result.payload_error = payload_error;
    return result;
}

void CopyEndpoint(GuiBrokerValidatedMessage& out, const GuiBrokerEndpointCredentialsSnapshot& endpoint)
{
    out.sender_endpoint_identity = endpoint.endpoint_identity;
    out.sender_process_identity = endpoint.process_identity;
    out.sender_task_identity = endpoint.task_identity;
    out.sender_integrity = endpoint.integrity;
}

void CopyTarget(GuiBrokerValidatedMessage& out, const GuiBrokerTargetAuthoritySnapshot& target)
{
    out.target_transfer_reference = target.transfer_reference;
    out.target_authority_identity = target.authority_identity;
    out.target_owner_endpoint_identity = target.owner_endpoint_identity;
    out.target_process_identity = target.target_process_identity;
    out.target_task_identity = target.target_task_identity;
    out.target_object_identity = target.target_object_identity;
    out.target_integrity = target.target_integrity;
    out.target_object_kind = target.object_kind;
}

void CopyRuleSender(GuiBrokerValidatedMessage& out, u64 principal_authority_identity, u64 principal_reference,
                    u64 endpoint_identity, u64 process_identity, u64 task_identity, core::Win32IntegrityLevel integrity)
{
    out.principal_authority_identity = principal_authority_identity;
    out.principal_transfer_reference = principal_reference;
    out.rule_sender_endpoint_identity = endpoint_identity;
    out.rule_sender_process_identity = process_identity;
    out.rule_sender_task_identity = task_identity;
    out.rule_sender_integrity = integrity;
}

GuiBrokerValidatedOperation ReplyOperation(GuiBrokerMethod method)
{
    switch (method)
    {
    case GuiBrokerMethod::RegisterRule:
        return GuiBrokerValidatedOperation::RegisterRuleReply;
    case GuiBrokerMethod::RevokeRule:
        return GuiBrokerValidatedOperation::RevokeRuleReply;
    case GuiBrokerMethod::Post:
        return GuiBrokerValidatedOperation::PostReply;
    }
    return GuiBrokerValidatedOperation::Invalid;
}

} // namespace

bool GuiBrokerEndpointCredentialsAreCanonical(const GuiBrokerEndpointCredentialsSnapshot& snapshot)
{
    return snapshot.endpoint_identity != 0 && snapshot.process_identity != 0 && snapshot.task_identity != 0 &&
           IntegrityIsValid(snapshot.integrity) && ReservedBytesAreZero(snapshot.reserved, 7);
}

bool GuiBrokerTargetAuthorityIsCanonical(const GuiBrokerTargetAuthoritySnapshot& snapshot)
{
    if (snapshot.authority_identity == 0 || snapshot.transfer_reference == 0 ||
        snapshot.holder_endpoint_identity == 0 || snapshot.owner_endpoint_identity == 0 ||
        snapshot.target_process_identity == 0 || snapshot.target_task_identity == 0 ||
        snapshot.target_object_identity == 0 || !IntegrityIsValid(snapshot.target_integrity) ||
        !ReservedBytesAreZero(snapshot.reserved, 6) || snapshot.reserved2 != 0 || snapshot.rights == 0 ||
        (snapshot.rights & ~kGuiBrokerTargetKnownRights) != 0)
    {
        return false;
    }

    switch (snapshot.object_kind)
    {
    case GuiBrokerTargetObjectKind::Window:
        return true;
    case GuiBrokerTargetObjectKind::Task:
        return snapshot.target_object_identity == snapshot.target_task_identity;
    case GuiBrokerTargetObjectKind::Invalid:
        return false;
    }
    return false;
}

bool GuiBrokerPrincipalAuthorityIsCanonical(const GuiBrokerPrincipalAuthoritySnapshot& snapshot)
{
    return snapshot.authority_identity != 0 && snapshot.transfer_reference != 0 &&
           snapshot.holder_endpoint_identity != 0 && snapshot.principal_endpoint_identity != 0 &&
           snapshot.principal_process_identity != 0 && snapshot.principal_task_identity != 0 &&
           IntegrityIsValid(snapshot.principal_integrity) && ReservedBytesAreZero(snapshot.reserved, 7);
}

bool GuiBrokerRuleAuthorityIsCanonical(const GuiBrokerRuleAuthoritySnapshot& snapshot)
{
    if (snapshot.authority_identity == 0 || snapshot.sender_endpoint_identity == 0 ||
        snapshot.sender_process_identity == 0 || snapshot.sender_task_identity == 0 ||
        snapshot.target_owner_endpoint_identity == 0 || snapshot.target_process_identity == 0 ||
        snapshot.target_task_identity == 0 || snapshot.target_object_identity == 0 || snapshot.rule_sequence == 0 ||
        !IsApplicationScalarMessage(snapshot.message) || !IntegrityIsValid(snapshot.sender_integrity) ||
        !IntegrityIsValid(snapshot.target_integrity) || snapshot.live != 1 || snapshot.reserved != 0 ||
        snapshot.sender_endpoint_identity == snapshot.target_owner_endpoint_identity ||
        snapshot.sender_process_identity == snapshot.target_process_identity ||
        snapshot.sender_task_identity == snapshot.target_task_identity ||
        snapshot.sender_integrity < snapshot.target_integrity)
    {
        return false;
    }
    switch (snapshot.target_object_kind)
    {
    case GuiBrokerTargetObjectKind::Window:
        return true;
    case GuiBrokerTargetObjectKind::Task:
        return snapshot.target_object_identity == snapshot.target_task_identity;
    case GuiBrokerTargetObjectKind::Invalid:
        return false;
    }
    return false;
}

bool GuiBrokerPendingAuthorityIsCanonical(const GuiBrokerPendingAuthoritySnapshot& snapshot)
{
    return snapshot.authority_identity != 0 && snapshot.requester_endpoint_identity != 0 &&
           snapshot.broker_endpoint_identity != 0 &&
           snapshot.requester_endpoint_identity != snapshot.broker_endpoint_identity && snapshot.request_id != 0 &&
           MethodIsValid(snapshot.method) && PendingStateIsValid(snapshot.state) &&
           ReservedBytesAreZero(snapshot.reserved, 3) && snapshot.reserved2 == 0;
}

GuiBrokerProtocolValidation GuiBrokerProtocolValidate(
    const void* frame, u32 frame_bytes, const GuiBrokerEndpointCredentialsSnapshot* endpoint_input,
    const GuiBrokerTargetAuthoritySnapshot* target_authority_input,
    const GuiBrokerPrincipalAuthoritySnapshot* principal_authority_input,
    const GuiBrokerRuleAuthoritySnapshot* rule_authority_input,
    const GuiBrokerPendingAuthoritySnapshot* pending_authority_input)
{
    if (frame == nullptr)
        return Failure(GuiBrokerProtocolError::MalformedMessageEnvelope, ipc::MessageValidationError::NullBuffer);
    if (!PointerRangeIsValid(frame, frame_bytes))
        return Failure(GuiBrokerProtocolError::MalformedMessageEnvelope, ipc::MessageValidationError::MessageTooLarge);
    if (endpoint_input == nullptr || !PointerRangeIsValid(endpoint_input, static_cast<u64>(sizeof(*endpoint_input))))
    {
        return Failure(GuiBrokerProtocolError::MalformedEndpointCredentials);
    }
    if ((target_authority_input != nullptr &&
         !PointerRangeIsValid(target_authority_input, static_cast<u64>(sizeof(*target_authority_input)))) ||
        (principal_authority_input != nullptr &&
         !PointerRangeIsValid(principal_authority_input, static_cast<u64>(sizeof(*principal_authority_input)))) ||
        (rule_authority_input != nullptr &&
         !PointerRangeIsValid(rule_authority_input, static_cast<u64>(sizeof(*rule_authority_input)))) ||
        (pending_authority_input != nullptr &&
         !PointerRangeIsValid(pending_authority_input, static_cast<u64>(sizeof(*pending_authority_input)))))
    {
        return Failure(GuiBrokerProtocolError::UnexpectedAuthority);
    }
    if (PointerRangesOverlap(frame, frame_bytes, endpoint_input, static_cast<u64>(sizeof(*endpoint_input))) ||
        (target_authority_input != nullptr &&
         PointerRangesOverlap(frame, frame_bytes, target_authority_input,
                              static_cast<u64>(sizeof(*target_authority_input)))) ||
        (principal_authority_input != nullptr &&
         PointerRangesOverlap(frame, frame_bytes, principal_authority_input,
                              static_cast<u64>(sizeof(*principal_authority_input)))) ||
        (rule_authority_input != nullptr && PointerRangesOverlap(frame, frame_bytes, rule_authority_input,
                                                                 static_cast<u64>(sizeof(*rule_authority_input)))) ||
        (pending_authority_input != nullptr &&
         PointerRangesOverlap(frame, frame_bytes, pending_authority_input,
                              static_cast<u64>(sizeof(*pending_authority_input)))))
    {
        return Failure(GuiBrokerProtocolError::AuthorityAliasesMessage);
    }

    const GuiBrokerEndpointCredentialsSnapshot endpoint = *endpoint_input;
    GuiBrokerTargetAuthoritySnapshot target_authority_storage{};
    GuiBrokerPrincipalAuthoritySnapshot principal_authority_storage{};
    GuiBrokerRuleAuthoritySnapshot rule_authority_storage{};
    GuiBrokerPendingAuthoritySnapshot pending_authority_storage{};
    const GuiBrokerTargetAuthoritySnapshot* target_authority = nullptr;
    const GuiBrokerPrincipalAuthoritySnapshot* principal_authority = nullptr;
    const GuiBrokerRuleAuthoritySnapshot* rule_authority = nullptr;
    const GuiBrokerPendingAuthoritySnapshot* pending_authority = nullptr;
    if (target_authority_input != nullptr)
    {
        target_authority_storage = *target_authority_input;
        target_authority = &target_authority_storage;
    }
    if (principal_authority_input != nullptr)
    {
        principal_authority_storage = *principal_authority_input;
        principal_authority = &principal_authority_storage;
    }
    if (rule_authority_input != nullptr)
    {
        rule_authority_storage = *rule_authority_input;
        rule_authority = &rule_authority_storage;
    }
    if (pending_authority_input != nullptr)
    {
        pending_authority_storage = *pending_authority_input;
        pending_authority = &pending_authority_storage;
    }

    ipc::MessageView envelope{};
    const ipc::MessageValidationError message_error = ipc::MessageValidate(frame, frame_bytes, &envelope);
    if (message_error != ipc::MessageValidationError::Ok)
        return Failure(GuiBrokerProtocolError::MalformedMessageEnvelope, message_error);

    if (envelope.service_id != kGuiBrokerServiceId)
        return Failure(GuiBrokerProtocolError::WrongService);

    const GuiBrokerMethod method = static_cast<GuiBrokerMethod>(envelope.method_id);
    if (!MethodIsValid(method))
        return Failure(GuiBrokerProtocolError::UnknownMethod);
    if (!GuiBrokerEndpointCredentialsAreCanonical(endpoint))
        return Failure(GuiBrokerProtocolError::MalformedEndpointCredentials);

    if (envelope.kind == ipc::MessageKind::Notification)
        return Failure(GuiBrokerProtocolError::UnexpectedKind);

    if (envelope.kind == ipc::MessageKind::Cancel)
    {
        if (method != GuiBrokerMethod::Post)
            return Failure(GuiBrokerProtocolError::UnexpectedKind);
        if (target_authority != nullptr || principal_authority != nullptr || rule_authority != nullptr)
            return Failure(GuiBrokerProtocolError::UnexpectedAuthority);
        if (pending_authority == nullptr)
            return Failure(GuiBrokerProtocolError::MissingPendingAuthority);
        if (!GuiBrokerPendingAuthorityIsCanonical(*pending_authority))
            return Failure(GuiBrokerProtocolError::MalformedPendingAuthority);
        if (pending_authority->state != GuiBrokerPendingState::Pending ||
            pending_authority->method != GuiBrokerMethod::Post ||
            pending_authority->request_id != envelope.request_id ||
            pending_authority->requester_endpoint_identity != endpoint.endpoint_identity)
        {
            return Failure(GuiBrokerProtocolError::PendingAuthorityMismatch);
        }

        GuiBrokerProtocolValidation result{};
        result.error = GuiBrokerProtocolError::Ok;
        result.message.operation = GuiBrokerValidatedOperation::CancelPost;
        result.message.request_id = envelope.request_id;
        result.message.request_sequence = envelope.request_id;
        result.message.pending_authority_identity = pending_authority->authority_identity;
        CopyEndpoint(result.message, endpoint);
        return result;
    }

    if (envelope.kind != ipc::MessageKind::Request && envelope.kind != ipc::MessageKind::Reply)
        return Failure(GuiBrokerProtocolError::UnexpectedKind);
    if (envelope.payload_size == 0)
        return Failure(GuiBrokerProtocolError::MissingPayload);

    const auto* frame_bytes_view = static_cast<const u8*>(frame);
    const u8* payload = frame_bytes_view + envelope.payload_offset;
    const ipc::PayloadValidationError payload_error = ipc::PayloadValidate(
        payload, envelope.payload_size, kGuiBrokerPayloadRules, kGuiBrokerPayloadRuleCount, nullptr);
    if (payload_error != ipc::PayloadValidationError::Ok)
        return Failure(GuiBrokerProtocolError::MalformedPayloadEnvelope, ipc::MessageValidationError::Ok,
                       payload_error);

    const u32 expected_payload_size =
        envelope.kind == ipc::MessageKind::Reply
            ? kGuiBrokerReplyPayloadBytes
            : (method == GuiBrokerMethod::RegisterRule ? kGuiBrokerRegisterRequestPayloadBytes
               : method == GuiBrokerMethod::RevokeRule ? kGuiBrokerRevokeRequestPayloadBytes
                                                       : kGuiBrokerPostRequestPayloadBytes);
    if (envelope.payload_size != expected_payload_size)
        return Failure(GuiBrokerProtocolError::WrongPayloadSize);
    if (ReadLe32(payload + kGuiBrokerPayloadMethodOffset) != envelope.method_id)
        return Failure(GuiBrokerProtocolError::PayloadMethodMismatch);
    if (ReadLe32(payload + kGuiBrokerPayloadReservedOffset) != 0)
        return Failure(GuiBrokerProtocolError::NonCanonicalPayload);

    if (envelope.kind == ipc::MessageKind::Reply)
    {
        if (target_authority != nullptr || principal_authority != nullptr || rule_authority != nullptr)
            return Failure(GuiBrokerProtocolError::UnexpectedAuthority);
        if (pending_authority == nullptr)
            return Failure(GuiBrokerProtocolError::MissingPendingAuthority);
        if (!GuiBrokerPendingAuthorityIsCanonical(*pending_authority))
            return Failure(GuiBrokerProtocolError::MalformedPendingAuthority);
        if (ReadLe32(payload + kGuiBrokerReplyReserved2Offset) != 0)
            return Failure(GuiBrokerProtocolError::NonCanonicalPayload);

        const u64 request_sequence = ReadLe64(payload + kGuiBrokerReplySequenceOffset);
        if (request_sequence != envelope.request_id)
            return Failure(GuiBrokerProtocolError::InvalidRequestSequence);
        if (pending_authority->state != GuiBrokerPendingState::Pending || pending_authority->method != method ||
            pending_authority->request_id != envelope.request_id ||
            pending_authority->broker_endpoint_identity != endpoint.endpoint_identity)
        {
            return Failure(GuiBrokerProtocolError::PendingAuthorityMismatch);
        }

        const GuiBrokerReplyStatus status =
            static_cast<GuiBrokerReplyStatus>(ReadLe32(payload + kGuiBrokerReplyStatusOffset));
        if (!ReplyStatusIsValid(status))
            return Failure(GuiBrokerProtocolError::UnknownReplyStatus);

        GuiBrokerProtocolValidation result{};
        result.error = GuiBrokerProtocolError::Ok;
        result.message.operation = ReplyOperation(method);
        result.message.reply_status = status;
        result.message.request_id = envelope.request_id;
        result.message.request_sequence = request_sequence;
        result.message.pending_authority_identity = pending_authority->authority_identity;
        CopyEndpoint(result.message, endpoint);
        return result;
    }

    if (envelope.request_id <= endpoint.last_committed_request_sequence)
        return Failure(GuiBrokerProtocolError::ReplayedRequest);
    if (pending_authority != nullptr)
        return Failure(GuiBrokerProtocolError::UnexpectedAuthority);
    if (target_authority == nullptr)
        return Failure(GuiBrokerProtocolError::MissingTargetAuthority);
    if (!GuiBrokerTargetAuthorityIsCanonical(*target_authority))
        return Failure(GuiBrokerProtocolError::MalformedTargetAuthority);
    if (target_authority->holder_endpoint_identity != endpoint.endpoint_identity)
        return Failure(GuiBrokerProtocolError::TargetAuthorityMismatch);

    const u64 target_reference = ReadLe64(payload + kGuiBrokerPayloadTargetReferenceOffset);
    if (target_reference == 0 || target_reference != target_authority->transfer_reference)
        return Failure(GuiBrokerProtocolError::TargetReferenceMismatch);

    if (method == GuiBrokerMethod::RegisterRule)
    {
        if (rule_authority != nullptr)
            return Failure(GuiBrokerProtocolError::UnexpectedAuthority);
        if (principal_authority == nullptr)
            return Failure(GuiBrokerProtocolError::MissingPrincipalAuthority);
        if (!GuiBrokerPrincipalAuthorityIsCanonical(*principal_authority))
            return Failure(GuiBrokerProtocolError::MalformedPrincipalAuthority);
        if ((target_authority->rights & kGuiBrokerTargetRightManageRules) == 0)
            return Failure(GuiBrokerProtocolError::MissingTargetRight);
        if (target_authority->owner_endpoint_identity != endpoint.endpoint_identity ||
            target_authority->target_process_identity != endpoint.process_identity ||
            target_authority->target_task_identity != endpoint.task_identity ||
            target_authority->target_integrity != endpoint.integrity)
        {
            return Failure(GuiBrokerProtocolError::EndpointDoesNotOwnTarget);
        }
        if (principal_authority->holder_endpoint_identity != endpoint.endpoint_identity)
            return Failure(GuiBrokerProtocolError::PrincipalAuthorityMismatch);

        const u64 principal_reference = ReadLe64(payload + kGuiBrokerRegisterPrincipalReferenceOffset);
        const u64 sequence = ReadLe64(payload + kGuiBrokerRegisterSequenceOffset);
        const u32 message = ReadLe32(payload + kGuiBrokerRegisterMessageOffset);
        if (ReadLe32(payload + kGuiBrokerRegisterReserved2Offset) != 0)
            return Failure(GuiBrokerProtocolError::NonCanonicalPayload);
        if (principal_reference == 0 || principal_reference == target_reference ||
            principal_reference != principal_authority->transfer_reference)
            return Failure(GuiBrokerProtocolError::PrincipalReferenceMismatch);
        if (principal_authority->principal_endpoint_identity == endpoint.endpoint_identity ||
            principal_authority->principal_process_identity == target_authority->target_process_identity ||
            principal_authority->principal_task_identity == target_authority->target_task_identity)
        {
            return Failure(GuiBrokerProtocolError::SameProcessPost);
        }
        if (principal_authority->principal_integrity < target_authority->target_integrity)
            return Failure(GuiBrokerProtocolError::LowToHighIntegrity);
        if (sequence != envelope.request_id)
            return Failure(GuiBrokerProtocolError::InvalidRequestSequence);
        if (!IsApplicationScalarMessage(message))
            return Failure(GuiBrokerProtocolError::InvalidMessage);

        GuiBrokerProtocolValidation result{};
        result.error = GuiBrokerProtocolError::Ok;
        result.message.operation = GuiBrokerValidatedOperation::RegisterRuleRequest;
        result.message.request_id = envelope.request_id;
        result.message.request_sequence = sequence;
        result.message.rule_sequence = sequence;
        result.message.message = message;
        result.message.wparam_allowed_bits = ReadLe64(payload + kGuiBrokerRegisterScalar0Offset);
        result.message.lparam_allowed_bits = ReadLe64(payload + kGuiBrokerRegisterScalar1Offset);
        CopyEndpoint(result.message, endpoint);
        CopyTarget(result.message, *target_authority);
        CopyRuleSender(result.message, principal_authority->authority_identity, principal_reference,
                       principal_authority->principal_endpoint_identity,
                       principal_authority->principal_process_identity, principal_authority->principal_task_identity,
                       principal_authority->principal_integrity);
        return result;
    }

    if (principal_authority != nullptr)
        return Failure(GuiBrokerProtocolError::UnexpectedAuthority);
    const u64 sequence = ReadLe64(payload + kGuiBrokerPayloadSequenceOffset);
    const u32 message = ReadLe32(payload + kGuiBrokerPayloadMessageOffset);
    if (ReadLe32(payload + kGuiBrokerPayloadReserved2Offset) != 0)
        return Failure(GuiBrokerProtocolError::NonCanonicalPayload);
    if (!IsApplicationScalarMessage(message))
        return Failure(GuiBrokerProtocolError::InvalidMessage);
    if (rule_authority == nullptr)
        return Failure(GuiBrokerProtocolError::MissingRuleAuthority);
    if (!GuiBrokerRuleAuthorityIsCanonical(*rule_authority))
        return Failure(GuiBrokerProtocolError::MalformedRuleAuthority);
    if (rule_authority->target_owner_endpoint_identity != target_authority->owner_endpoint_identity ||
        rule_authority->target_process_identity != target_authority->target_process_identity ||
        rule_authority->target_task_identity != target_authority->target_task_identity ||
        rule_authority->target_object_identity != target_authority->target_object_identity ||
        rule_authority->target_object_kind != target_authority->object_kind ||
        rule_authority->target_integrity != target_authority->target_integrity || rule_authority->message != message)
    {
        return Failure(GuiBrokerProtocolError::RuleAuthorityMismatch);
    }

    if (method == GuiBrokerMethod::RevokeRule)
    {
        if ((target_authority->rights & kGuiBrokerTargetRightManageRules) == 0)
            return Failure(GuiBrokerProtocolError::MissingTargetRight);
        if (target_authority->owner_endpoint_identity != endpoint.endpoint_identity ||
            target_authority->target_process_identity != endpoint.process_identity ||
            target_authority->target_task_identity != endpoint.task_identity ||
            target_authority->target_integrity != endpoint.integrity)
        {
            return Failure(GuiBrokerProtocolError::EndpointDoesNotOwnTarget);
        }
        if (sequence == 0 || sequence >= envelope.request_id)
            return Failure(GuiBrokerProtocolError::InvalidRequestSequence);
        const u64 wparam_mask = ReadLe64(payload + kGuiBrokerPayloadScalar0Offset);
        const u64 lparam_mask = ReadLe64(payload + kGuiBrokerPayloadScalar1Offset);
        if (sequence != rule_authority->rule_sequence || wparam_mask != rule_authority->wparam_allowed_bits ||
            lparam_mask != rule_authority->lparam_allowed_bits)
        {
            return Failure(GuiBrokerProtocolError::RuleAuthorityMismatch);
        }

        GuiBrokerProtocolValidation result{};
        result.error = GuiBrokerProtocolError::Ok;
        result.message.operation = GuiBrokerValidatedOperation::RevokeRuleRequest;
        result.message.request_id = envelope.request_id;
        result.message.request_sequence = envelope.request_id;
        result.message.rule_sequence = sequence;
        result.message.message = message;
        result.message.wparam_allowed_bits = wparam_mask;
        result.message.lparam_allowed_bits = lparam_mask;
        result.message.rule_authority_identity = rule_authority->authority_identity;
        CopyEndpoint(result.message, endpoint);
        CopyTarget(result.message, *target_authority);
        CopyRuleSender(result.message, 0, 0, rule_authority->sender_endpoint_identity,
                       rule_authority->sender_process_identity, rule_authority->sender_task_identity,
                       rule_authority->sender_integrity);
        return result;
    }

    if (method != GuiBrokerMethod::Post)
        return Failure(GuiBrokerProtocolError::UnknownMethod);
    if ((target_authority->rights & kGuiBrokerTargetRightReceivePosts) == 0)
        return Failure(GuiBrokerProtocolError::MissingTargetRight);
    if (target_authority->owner_endpoint_identity == endpoint.endpoint_identity ||
        target_authority->target_process_identity == endpoint.process_identity ||
        target_authority->target_task_identity == endpoint.task_identity)
    {
        return Failure(GuiBrokerProtocolError::SameProcessPost);
    }
    if (rule_authority->sender_endpoint_identity != endpoint.endpoint_identity ||
        rule_authority->sender_process_identity != endpoint.process_identity ||
        rule_authority->sender_task_identity != endpoint.task_identity ||
        rule_authority->sender_integrity != endpoint.integrity)
    {
        return Failure(GuiBrokerProtocolError::RulePrincipalMismatch);
    }
    if (endpoint.integrity < target_authority->target_integrity)
        return Failure(GuiBrokerProtocolError::LowToHighIntegrity);
    if (sequence != envelope.request_id)
        return Failure(GuiBrokerProtocolError::InvalidRequestSequence);

    const u64 wparam = ReadLe64(payload + kGuiBrokerPayloadScalar0Offset);
    const u64 lparam = ReadLe64(payload + kGuiBrokerPayloadScalar1Offset);
    if ((wparam & ~rule_authority->wparam_allowed_bits) != 0 || (lparam & ~rule_authority->lparam_allowed_bits) != 0)
    {
        return Failure(GuiBrokerProtocolError::PayloadOutsideRule);
    }

    GuiBrokerProtocolValidation result{};
    result.error = GuiBrokerProtocolError::Ok;
    result.message.operation = GuiBrokerValidatedOperation::PostRequest;
    result.message.request_id = envelope.request_id;
    result.message.request_sequence = sequence;
    result.message.rule_sequence = rule_authority->rule_sequence;
    result.message.message = message;
    result.message.wparam = wparam;
    result.message.lparam = lparam;
    result.message.wparam_allowed_bits = rule_authority->wparam_allowed_bits;
    result.message.lparam_allowed_bits = rule_authority->lparam_allowed_bits;
    result.message.rule_authority_identity = rule_authority->authority_identity;
    CopyEndpoint(result.message, endpoint);
    CopyTarget(result.message, *target_authority);
    CopyRuleSender(result.message, 0, 0, rule_authority->sender_endpoint_identity,
                   rule_authority->sender_process_identity, rule_authority->sender_task_identity,
                   rule_authority->sender_integrity);
    return result;
}

const char* GuiBrokerProtocolErrorName(GuiBrokerProtocolError error)
{
    switch (error)
    {
    case GuiBrokerProtocolError::Ok:
        return "ok";
    case GuiBrokerProtocolError::MalformedMessageEnvelope:
        return "malformed-message-envelope";
    case GuiBrokerProtocolError::WrongService:
        return "wrong-service";
    case GuiBrokerProtocolError::UnknownMethod:
        return "unknown-method";
    case GuiBrokerProtocolError::UnexpectedKind:
        return "unexpected-kind";
    case GuiBrokerProtocolError::MissingPayload:
        return "missing-payload";
    case GuiBrokerProtocolError::MalformedPayloadEnvelope:
        return "malformed-payload-envelope";
    case GuiBrokerProtocolError::WrongPayloadSize:
        return "wrong-payload-size";
    case GuiBrokerProtocolError::PayloadMethodMismatch:
        return "payload-method-mismatch";
    case GuiBrokerProtocolError::NonCanonicalPayload:
        return "non-canonical-payload";
    case GuiBrokerProtocolError::InvalidMessage:
        return "invalid-message";
    case GuiBrokerProtocolError::InvalidRequestSequence:
        return "invalid-request-sequence";
    case GuiBrokerProtocolError::ReplayedRequest:
        return "replayed-request";
    case GuiBrokerProtocolError::MalformedEndpointCredentials:
        return "malformed-endpoint-credentials";
    case GuiBrokerProtocolError::AuthorityAliasesMessage:
        return "authority-aliases-message";
    case GuiBrokerProtocolError::MissingTargetAuthority:
        return "missing-target-authority";
    case GuiBrokerProtocolError::MalformedTargetAuthority:
        return "malformed-target-authority";
    case GuiBrokerProtocolError::UnexpectedAuthority:
        return "unexpected-authority";
    case GuiBrokerProtocolError::TargetReferenceMismatch:
        return "target-reference-mismatch";
    case GuiBrokerProtocolError::TargetAuthorityMismatch:
        return "target-authority-mismatch";
    case GuiBrokerProtocolError::EndpointDoesNotOwnTarget:
        return "endpoint-does-not-own-target";
    case GuiBrokerProtocolError::MissingTargetRight:
        return "missing-target-right";
    case GuiBrokerProtocolError::SameProcessPost:
        return "same-process-post";
    case GuiBrokerProtocolError::LowToHighIntegrity:
        return "low-to-high-integrity";
    case GuiBrokerProtocolError::MissingPrincipalAuthority:
        return "missing-principal-authority";
    case GuiBrokerProtocolError::MalformedPrincipalAuthority:
        return "malformed-principal-authority";
    case GuiBrokerProtocolError::PrincipalReferenceMismatch:
        return "principal-reference-mismatch";
    case GuiBrokerProtocolError::PrincipalAuthorityMismatch:
        return "principal-authority-mismatch";
    case GuiBrokerProtocolError::MissingRuleAuthority:
        return "missing-rule-authority";
    case GuiBrokerProtocolError::MalformedRuleAuthority:
        return "malformed-rule-authority";
    case GuiBrokerProtocolError::RuleAuthorityMismatch:
        return "rule-authority-mismatch";
    case GuiBrokerProtocolError::RulePrincipalMismatch:
        return "rule-principal-mismatch";
    case GuiBrokerProtocolError::PayloadOutsideRule:
        return "payload-outside-rule";
    case GuiBrokerProtocolError::MissingPendingAuthority:
        return "missing-pending-authority";
    case GuiBrokerProtocolError::MalformedPendingAuthority:
        return "malformed-pending-authority";
    case GuiBrokerProtocolError::PendingAuthorityMismatch:
        return "pending-authority-mismatch";
    case GuiBrokerProtocolError::UnknownReplyStatus:
        return "unknown-reply-status";
    }
    return "unknown";
}

} // namespace duetos::drivers::video
