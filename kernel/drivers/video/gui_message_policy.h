#pragma once

#include "proc/credentials.h"
#include "util/types.h"

/*
 * DuetOS -- pure cross-process GUI message authorization policy.
 *
 * This module is the allocation-free decision seam for a future trusted GUI
 * broker. It owns no registry and retains no pointers. Callers freeze process,
 * task, HWND, integrity, target opt-in, and broker-capability state into the
 * immutable snapshots below, evaluate once, then revalidate the live opaque
 * identities before enqueueing. PID/TID/HWND values are equality-only opaque
 * scalars here; this policy never decodes or truncates their generations.
 *
 * Trust boundaries:
 *   - `request` is built from kernel-resolved caller and target state.
 *   - `target_opt_in` is a kernel-resident snapshot previously registered by
 *     the exact target task/window, never raw bytes from the sender.
 *   - `broker` is a separately authenticated kernel capability snapshot. A
 *     sender-authored flag or serialized lookalike must never populate it.
 *
 * The policy is pure and thread-safe: all inputs are borrowed read-only for
 * the duration of the call, there are no globals, callbacks, locks, logging,
 * allocation, user copies, or scheduler operations. It is linked into the
 * non-hot-reloadable kernel image and owns no shutdown state.
 */

namespace duetos::drivers::video
{

inline constexpr u32 kGuiMessageMaximum = 0xFFFFu;
inline constexpr u32 kGuiMessageApplicationFirst = 0x8000u; // WM_APP
inline constexpr u32 kGuiMessageApplicationLast = 0xBFFFu;
inline constexpr u32 kGuiMessageTargetRuleCapacity = 16;

enum class GuiMessageEndpointRelation : u8
{
    Invalid = 0,
    SameTask,
    SameProcess,
    CrossProcess,
};

enum class GuiMessageSecurityClass : u8
{
    Invalid = 0,
    Lifecycle,
    Quit,
    FocusActivation,
    Capture,
    Input,
    SystemCommand,
    OtherSystem,
    PrivateUnsafe,
    ApplicationScalar,
    RegisteredUnknown,
};

enum class GuiMessagePolicyDecision : u8
{
    DenyMalformedRequest = 0,
    DenyUnknownMessage,
    DenyAbsoluteMessage,
    DenyLowToHighIntegrity,
    DenyMalformedTargetRules,
    DenyTargetSnapshotMismatch,
    DenyMalformedBrokerAuthority,
    DenyBrokerPrincipalMismatch,
    DenyBrokerGrantMismatch,
    DenyPayloadOutsideBrokerGrant,
    DenyPayloadOutsideRule,
    DenyNoAuthorization,
    AllowSameTask,
    AllowSameProcess,
    AllowTargetOptIn,
    AllowTrustedBroker,
};

struct GuiMessagePrincipalSnapshot
{
    u64 process_identity;
    u64 task_identity;
    core::Win32IntegrityLevel integrity;
    u8 reserved[7];
};

struct GuiMessageRequestSnapshot
{
    GuiMessagePrincipalSnapshot sender;
    GuiMessagePrincipalSnapshot target;
    u64 target_window_identity; // 0 is an HWND-less task message
    u32 message;
    u32 reserved;
    u64 wparam;
    u64 lparam;
};

inline constexpr u32 kGuiMessageRuleScalarPayload = 1u << 0;
inline constexpr u32 kGuiMessageRuleKnownFlags = kGuiMessageRuleScalarPayload;

struct GuiMessageTargetRule
{
    u64 sender_process_identity;
    u64 sender_task_identity;
    u32 message;
    u32 flags;
    u64 wparam_allowed_bits;
    u64 lparam_allowed_bits;
};

struct GuiMessageTargetOptInSnapshot
{
    u64 target_process_identity;
    u64 target_task_identity;
    u64 target_window_identity;
    u32 rule_count;
    u32 reserved;
    GuiMessageTargetRule rules[kGuiMessageTargetRuleCapacity];
};

inline constexpr u32 kGuiBrokerRightPostApplicationScalar = 1u << 0;
inline constexpr u32 kGuiBrokerKnownRights = kGuiBrokerRightPostApplicationScalar;

struct GuiMessageTrustedBrokerSnapshot
{
    u64 authority_identity; // opaque, non-zero kernel capability generation
    u64 principal_process_identity;
    u64 principal_task_identity;
    u64 target_process_identity;
    u64 target_task_identity;
    u64 target_window_identity;
    u64 wparam_allowed_bits;
    u64 lparam_allowed_bits;
    u32 message;
    u32 rights;
    u32 reserved;
    u32 reserved2;
};

/// Classify two immutable principals. Same-task with different process ids or
/// same-process with different integrity snapshots is malformed.
/// [any thread, pure, allocation-free]
GuiMessageEndpointRelation GuiMessageClassifyRelation(const GuiMessagePrincipalSnapshot& sender,
                                                      const GuiMessagePrincipalSnapshot& target);

/// Classify the complete 32-bit input. Values above the Win32 16-bit message
/// domain are Invalid. Only WM_APP..0xBFFF is eligible for cross-process scalar
/// opt-in; WM_USER/control-private and registered/unknown ranges fail closed.
/// [any thread, pure, allocation-free]
GuiMessageSecurityClass GuiMessageClassifySecurity(u32 message);

/// Exact canonicality check. Rules are strictly sorted by
/// {sender_process_identity, sender_task_identity, message}; duplicate keys
/// overlap and are rejected. Sender and target identities must be distinct;
/// every unused row and reserved field must be zero.
/// [any thread, pure, allocation-free]
bool GuiMessageTargetOptInIsCanonical(const GuiMessageTargetOptInSnapshot& snapshot);

/// Canonicality check for a separately authenticated broker capability. A
/// grant is least-privilege: one sender principal, one target task/window, one
/// exact WM_APP message, and explicit scalar payload masks. This validates
/// representation only; it does not authenticate sender bytes.
/// [any thread, pure, allocation-free]
bool GuiMessageTrustedBrokerIsCanonical(const GuiMessageTrustedBrokerSnapshot& snapshot);

/// Evaluate one frozen request. Same-task/same-process traffic is classified
/// and allowed inside its existing trust boundary. Cross-process traffic is
/// default-deny, never flows from lower to higher integrity, and can carry
/// only exact WM_APP scalar messages authorized by a canonical target rule or
/// a separately authenticated broker right. Neither path can override an
/// absolute lifecycle/quit/focus/capture/input/system denial.
/// [any thread, pure, allocation-free]
GuiMessagePolicyDecision GuiMessagePolicyEvaluate(const GuiMessageRequestSnapshot& request,
                                                  const GuiMessageTargetOptInSnapshot* target_opt_in,
                                                  const GuiMessageTrustedBrokerSnapshot* broker);

constexpr bool GuiMessagePolicyAllowed(GuiMessagePolicyDecision decision)
{
    return decision == GuiMessagePolicyDecision::AllowSameTask ||
           decision == GuiMessagePolicyDecision::AllowSameProcess ||
           decision == GuiMessagePolicyDecision::AllowTargetOptIn ||
           decision == GuiMessagePolicyDecision::AllowTrustedBroker;
}

} // namespace duetos::drivers::video
