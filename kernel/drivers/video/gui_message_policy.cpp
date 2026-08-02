#include "drivers/video/gui_message_policy.h"

namespace duetos::drivers::video
{

namespace
{

bool ReservedBytesAreZero(const u8* bytes, u32 count)
{
    if (bytes == nullptr)
    {
        return false;
    }
    for (u32 index = 0; index < count; ++index)
    {
        if (bytes[index] != 0)
        {
            return false;
        }
    }
    return true;
}

bool IntegrityIsValid(core::Win32IntegrityLevel integrity)
{
    return integrity >= core::Win32IntegrityLevel::Untrusted && integrity <= core::Win32IntegrityLevel::System;
}

bool PrincipalIsCanonical(const GuiMessagePrincipalSnapshot& principal)
{
    return principal.process_identity != 0 && principal.task_identity != 0 && IntegrityIsValid(principal.integrity) &&
           ReservedBytesAreZero(principal.reserved, 7);
}

bool RuleIsZero(const GuiMessageTargetRule& rule)
{
    return rule.sender_process_identity == 0 && rule.sender_task_identity == 0 && rule.message == 0 &&
           rule.flags == 0 && rule.wparam_allowed_bits == 0 && rule.lparam_allowed_bits == 0;
}

bool RuleKeyLess(const GuiMessageTargetRule& lhs, const GuiMessageTargetRule& rhs)
{
    if (lhs.sender_process_identity != rhs.sender_process_identity)
    {
        return lhs.sender_process_identity < rhs.sender_process_identity;
    }
    if (lhs.sender_task_identity != rhs.sender_task_identity)
    {
        return lhs.sender_task_identity < rhs.sender_task_identity;
    }
    return lhs.message < rhs.message;
}

bool IsLifecycleMessage(u32 message)
{
    switch (message)
    {
    case 0x0001: // WM_CREATE
    case 0x0002: // WM_DESTROY
    case 0x0010: // WM_CLOSE
    case 0x0011: // WM_QUERYENDSESSION
    case 0x0016: // WM_ENDSESSION
    case 0x0081: // WM_NCCREATE
    case 0x0082: // WM_NCDESTROY
        return true;
    default:
        return false;
    }
}

bool IsFocusActivationMessage(u32 message)
{
    switch (message)
    {
    case 0x0006: // WM_ACTIVATE
    case 0x0007: // WM_SETFOCUS
    case 0x0008: // WM_KILLFOCUS
    case 0x001C: // WM_ACTIVATEAPP
    case 0x001F: // WM_CANCELMODE
    case 0x0021: // WM_MOUSEACTIVATE
    case 0x0086: // WM_NCACTIVATE
        return true;
    default:
        return false;
    }
}

bool IsInputMessage(u32 message)
{
    if ((message >= 0x0100 && message <= 0x010F) || // keyboard + IME composition
        (message >= 0x0200 && message <= 0x020E) || // mouse
        (message >= 0x0240 && message <= 0x024F))   // touch + pointer
    {
        return true;
    }
    switch (message)
    {
    case 0x00FE: // WM_INPUT_DEVICE_CHANGE
    case 0x00FF: // WM_INPUT
    case 0x0119: // WM_GESTURE
    case 0x011A: // WM_GESTURENOTIFY
    case 0x0312: // WM_HOTKEY
    case 0x0319: // WM_APPCOMMAND
        return true;
    default:
        return false;
    }
}

bool IsSystemCommandMessage(u32 message)
{
    switch (message)
    {
    case 0x004E: // WM_NOTIFY
    case 0x0111: // WM_COMMAND
    case 0x0112: // WM_SYSCOMMAND
    case 0x0113: // WM_TIMER
    case 0x0114: // WM_HSCROLL
    case 0x0115: // WM_VSCROLL
    case 0x0116: // WM_INITMENU
    case 0x0117: // WM_INITMENUPOPUP
    case 0x011F: // WM_MENUSELECT
    case 0x0120: // WM_MENUCHAR
    case 0x0218: // WM_POWERBROADCAST
    case 0x0219: // WM_DEVICECHANGE
        return true;
    default:
        return false;
    }
}

bool RuleMatchesRequest(const GuiMessageTargetRule& rule, const GuiMessageRequestSnapshot& request)
{
    return rule.sender_process_identity == request.sender.process_identity &&
           rule.sender_task_identity == request.sender.task_identity && rule.message == request.message;
}

bool PayloadFitsRule(const GuiMessageTargetRule& rule, const GuiMessageRequestSnapshot& request)
{
    return (request.wparam & ~rule.wparam_allowed_bits) == 0 && (request.lparam & ~rule.lparam_allowed_bits) == 0;
}

} // namespace

GuiMessageEndpointRelation GuiMessageClassifyRelation(const GuiMessagePrincipalSnapshot& sender,
                                                      const GuiMessagePrincipalSnapshot& target)
{
    if (!PrincipalIsCanonical(sender) || !PrincipalIsCanonical(target))
    {
        return GuiMessageEndpointRelation::Invalid;
    }
    if (sender.task_identity == target.task_identity)
    {
        return (sender.process_identity == target.process_identity && sender.integrity == target.integrity)
                   ? GuiMessageEndpointRelation::SameTask
                   : GuiMessageEndpointRelation::Invalid;
    }
    if (sender.process_identity == target.process_identity)
    {
        return (sender.integrity == target.integrity) ? GuiMessageEndpointRelation::SameProcess
                                                      : GuiMessageEndpointRelation::Invalid;
    }
    return GuiMessageEndpointRelation::CrossProcess;
}

GuiMessageSecurityClass GuiMessageClassifySecurity(u32 message)
{
    if (message > kGuiMessageMaximum)
    {
        return GuiMessageSecurityClass::Invalid;
    }
    if (message == 0x0012) // WM_QUIT
    {
        return GuiMessageSecurityClass::Quit;
    }
    if (IsLifecycleMessage(message))
    {
        return GuiMessageSecurityClass::Lifecycle;
    }
    if (IsFocusActivationMessage(message))
    {
        return GuiMessageSecurityClass::FocusActivation;
    }
    if (message == 0x0215) // WM_CAPTURECHANGED
    {
        return GuiMessageSecurityClass::Capture;
    }
    if (IsInputMessage(message))
    {
        return GuiMessageSecurityClass::Input;
    }
    if (IsSystemCommandMessage(message))
    {
        return GuiMessageSecurityClass::SystemCommand;
    }
    if (message <= 0x03FF)
    {
        return GuiMessageSecurityClass::OtherSystem;
    }
    if (message < kGuiMessageApplicationFirst)
    {
        return GuiMessageSecurityClass::PrivateUnsafe;
    }
    if (message <= kGuiMessageApplicationLast)
    {
        return GuiMessageSecurityClass::ApplicationScalar;
    }
    return GuiMessageSecurityClass::RegisteredUnknown;
}

bool GuiMessageTargetOptInIsCanonical(const GuiMessageTargetOptInSnapshot& snapshot)
{
    if (snapshot.target_process_identity == 0 || snapshot.target_task_identity == 0 || snapshot.reserved != 0 ||
        snapshot.rule_count > kGuiMessageTargetRuleCapacity)
    {
        return false;
    }

    for (u32 index = 0; index < snapshot.rule_count; ++index)
    {
        const GuiMessageTargetRule& rule = snapshot.rules[index];
        if (rule.sender_process_identity == 0 || rule.sender_task_identity == 0 ||
            rule.sender_process_identity == snapshot.target_process_identity ||
            rule.sender_task_identity == snapshot.target_task_identity || rule.flags != kGuiMessageRuleScalarPayload ||
            GuiMessageClassifySecurity(rule.message) != GuiMessageSecurityClass::ApplicationScalar)
        {
            return false;
        }
        if (index != 0 && !RuleKeyLess(snapshot.rules[index - 1], rule))
        {
            // Equal keys overlap even when their payload masks differ.
            return false;
        }
    }
    for (u32 index = snapshot.rule_count; index < kGuiMessageTargetRuleCapacity; ++index)
    {
        if (!RuleIsZero(snapshot.rules[index]))
        {
            return false;
        }
    }
    return true;
}

bool GuiMessageTrustedBrokerIsCanonical(const GuiMessageTrustedBrokerSnapshot& snapshot)
{
    return snapshot.authority_identity != 0 && snapshot.principal_process_identity != 0 &&
           snapshot.principal_task_identity != 0 && snapshot.target_process_identity != 0 &&
           snapshot.target_task_identity != 0 &&
           snapshot.principal_process_identity != snapshot.target_process_identity &&
           snapshot.principal_task_identity != snapshot.target_task_identity &&
           GuiMessageClassifySecurity(snapshot.message) == GuiMessageSecurityClass::ApplicationScalar &&
           snapshot.rights == kGuiBrokerRightPostApplicationScalar && snapshot.reserved == 0 && snapshot.reserved2 == 0;
}

GuiMessagePolicyDecision GuiMessagePolicyEvaluate(const GuiMessageRequestSnapshot& request,
                                                  const GuiMessageTargetOptInSnapshot* target_opt_in,
                                                  const GuiMessageTrustedBrokerSnapshot* broker)
{
    if (request.reserved != 0)
    {
        return GuiMessagePolicyDecision::DenyMalformedRequest;
    }
    const GuiMessageEndpointRelation relation = GuiMessageClassifyRelation(request.sender, request.target);
    if (relation == GuiMessageEndpointRelation::Invalid)
    {
        return GuiMessagePolicyDecision::DenyMalformedRequest;
    }
    const GuiMessageSecurityClass security_class = GuiMessageClassifySecurity(request.message);
    if (security_class == GuiMessageSecurityClass::Invalid)
    {
        return GuiMessagePolicyDecision::DenyUnknownMessage;
    }
    if (relation == GuiMessageEndpointRelation::SameTask)
    {
        return GuiMessagePolicyDecision::AllowSameTask;
    }
    if (relation == GuiMessageEndpointRelation::SameProcess)
    {
        return GuiMessagePolicyDecision::AllowSameProcess;
    }

    // Cross-process authority is strictly monotonic. Neither target consent
    // nor a broker right can turn a lower-integrity sender into a higher-
    // integrity writer.
    if (request.sender.integrity < request.target.integrity)
    {
        return GuiMessagePolicyDecision::DenyLowToHighIntegrity;
    }
    if (security_class != GuiMessageSecurityClass::ApplicationScalar)
    {
        return (security_class == GuiMessageSecurityClass::PrivateUnsafe ||
                security_class == GuiMessageSecurityClass::RegisteredUnknown)
                   ? GuiMessagePolicyDecision::DenyUnknownMessage
                   : GuiMessagePolicyDecision::DenyAbsoluteMessage;
    }

    if (target_opt_in != nullptr)
    {
        if (!GuiMessageTargetOptInIsCanonical(*target_opt_in))
        {
            return GuiMessagePolicyDecision::DenyMalformedTargetRules;
        }
        if (target_opt_in->target_process_identity != request.target.process_identity ||
            target_opt_in->target_task_identity != request.target.task_identity ||
            target_opt_in->target_window_identity != request.target_window_identity)
        {
            return GuiMessagePolicyDecision::DenyTargetSnapshotMismatch;
        }
    }
    if (broker != nullptr)
    {
        if (!GuiMessageTrustedBrokerIsCanonical(*broker))
        {
            return GuiMessagePolicyDecision::DenyMalformedBrokerAuthority;
        }
        if (broker->principal_process_identity != request.sender.process_identity ||
            broker->principal_task_identity != request.sender.task_identity)
        {
            return GuiMessagePolicyDecision::DenyBrokerPrincipalMismatch;
        }
        if (broker->target_process_identity != request.target.process_identity ||
            broker->target_task_identity != request.target.task_identity ||
            broker->target_window_identity != request.target_window_identity || broker->message != request.message)
        {
            return GuiMessagePolicyDecision::DenyBrokerGrantMismatch;
        }
        if ((broker->rights & kGuiBrokerRightPostApplicationScalar) != 0)
        {
            if ((request.wparam & ~broker->wparam_allowed_bits) != 0 ||
                (request.lparam & ~broker->lparam_allowed_bits) != 0)
            {
                return GuiMessagePolicyDecision::DenyPayloadOutsideBrokerGrant;
            }
            return GuiMessagePolicyDecision::AllowTrustedBroker;
        }
    }

    if (target_opt_in == nullptr)
    {
        return GuiMessagePolicyDecision::DenyNoAuthorization;
    }
    for (u32 index = 0; index < target_opt_in->rule_count; ++index)
    {
        const GuiMessageTargetRule& rule = target_opt_in->rules[index];
        if (!RuleMatchesRequest(rule, request))
        {
            continue;
        }
        return PayloadFitsRule(rule, request) ? GuiMessagePolicyDecision::AllowTargetOptIn
                                              : GuiMessagePolicyDecision::DenyPayloadOutsideRule;
    }
    return GuiMessagePolicyDecision::DenyNoAuthorization;
}

} // namespace duetos::drivers::video
