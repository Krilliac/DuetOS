#pragma once

#include "drivers/video/gui_message_policy.h"
#include "ipc/message_abi.h"
#include "ipc/versioned_payload.h"
#include "proc/credentials.h"
#include "util/types.h"

/*
 * DuetOS -- GUI broker wire protocol v1.
 *
 * This is a transport-independent, allocation-free decoder layered on the
 * generic MessageAbi envelope and VersionedPayload prefix. It defines wire
 * shapes only; it does not own a port, rule table, replay ledger, handle table,
 * process, or window. The non-hot-reloadable kernel service borrows immutable
 * retained authority snapshots for one validation call and returns scalar
 * copies, never views into hostile storage.
 *
 * Trust boundaries are intentionally separate:
 *
 *   hostile frame bytes
 *     -> target transfer reference + WM_APP scalar fields only
 *   authenticated transport endpoint credentials
 *     -> sender process/task/integrity + committed request-sequence floor
 *   retained target/principal/rule/pending authority snapshots
 *     -> target ownership, exact sender principal, opaque HWND/task identity,
 *        rights, exact masks, and request lifecycle
 *
 * Sender bytes never carry authoritative PID, TID, integrity, target HWND,
 * broker rights, raw pointers, or inline kernel handles. The u64 target field
 * is only an opaque transport-object reference. A caller must resolve and
 * retain that exact generation through its transport/handle layer, freeze the
 * separate authority snapshot, and keep the retain alive through validation
 * and enqueue. The same lifetime rule applies to every non-null principal,
 * rule, and pending snapshot through its corresponding atomic commit; scalar
 * identities returned here are not owner references. This module performs no
 * global lookup and does not authenticate transfers or endpoints. Those
 * integration steps remain unresolved until the broker is wired to a concrete
 * message-port/handle transport.
 *
 * Frame storage must not overlap the endpoint or any optional authority
 * record. Validation rejects such aliasing by address range before reading an
 * authority field, then copies every accepted record once into call-local
 * storage. This preserves the separate-authority boundary even when a caller
 * accidentally passes a typed view carved from hostile message bytes.
 *
 * Replay checks are snapshot-based. Request validation requires a sequence
 * above the endpoint's committed floor; the transport must atomically reserve
 * and advance that floor after success. Likewise, reply/cancel validation
 * consumes no pending state: the caller must atomically transition the exact
 * retained pending request so two concurrent validations cannot both commit.
 */

namespace duetos::drivers::video
{

// "GUIB" in little-endian byte order.
inline constexpr u32 kGuiBrokerServiceId = 0x42495547u;
inline constexpr u16 kGuiBrokerPayloadVersion1 = 1;
inline constexpr u16 kGuiBrokerPayloadV1KnownFlags = 0;

enum class GuiBrokerMethod : u32
{
    RegisterRule = 1,
    RevokeRule = 2,
    Post = 3,
};

enum class GuiBrokerTargetObjectKind : u8
{
    Invalid = 0,
    Window,
    Task,
};

enum class GuiBrokerPendingState : u8
{
    Invalid = 0,
    Pending,
    Completed,
    Cancelled,
};

enum class GuiBrokerReplyStatus : u32
{
    Ok = 0,
    Denied = 1,
    InvalidTarget = 2,
    InvalidRule = 3,
    StaleSequence = 4,
    QueueFull = 5,
    Cancelled = 6,
    NotFound = 7,
    InternalFailure = 8,
};

enum class GuiBrokerValidatedOperation : u8
{
    Invalid = 0,
    RegisterRuleRequest,
    RegisterRuleReply,
    RevokeRuleRequest,
    RevokeRuleReply,
    PostRequest,
    PostReply,
    CancelPost,
};

enum class GuiBrokerProtocolError : u8
{
    Ok = 0,
    MalformedMessageEnvelope,
    WrongService,
    UnknownMethod,
    UnexpectedKind,
    MissingPayload,
    MalformedPayloadEnvelope,
    WrongPayloadSize,
    PayloadMethodMismatch,
    NonCanonicalPayload,
    InvalidMessage,
    InvalidRequestSequence,
    ReplayedRequest,
    MalformedEndpointCredentials,
    MissingTargetAuthority,
    MalformedTargetAuthority,
    UnexpectedAuthority,
    TargetReferenceMismatch,
    TargetAuthorityMismatch,
    EndpointDoesNotOwnTarget,
    MissingTargetRight,
    SameProcessPost,
    LowToHighIntegrity,
    MissingPrincipalAuthority,
    MalformedPrincipalAuthority,
    PrincipalReferenceMismatch,
    PrincipalAuthorityMismatch,
    MissingRuleAuthority,
    MalformedRuleAuthority,
    RuleAuthorityMismatch,
    RulePrincipalMismatch,
    PayloadOutsideRule,
    MissingPendingAuthority,
    MalformedPendingAuthority,
    PendingAuthorityMismatch,
    UnknownReplyStatus,
    AuthorityAliasesMessage,
};

inline constexpr u32 kGuiBrokerTargetRightManageRules = 1u << 0;
inline constexpr u32 kGuiBrokerTargetRightReceivePosts = 1u << 1;
inline constexpr u32 kGuiBrokerTargetKnownRights = kGuiBrokerTargetRightManageRules | kGuiBrokerTargetRightReceivePosts;

// Trusted transport snapshot. No field in a wire payload can populate this.
struct GuiBrokerEndpointCredentialsSnapshot
{
    u64 endpoint_identity;
    u64 process_identity;
    u64 task_identity;
    u64 last_committed_request_sequence;
    core::Win32IntegrityLevel integrity;
    u8 reserved[7];
};

// Retained endpoint-local translation from one opaque transfer reference to
// an exact target generation. `holder_endpoint_identity` is the endpoint
// namespace in which the reference was resolved; it must match the currently
// authenticated endpoint even when the target is owned elsewhere.
// `target_object_identity` is an HWND for Window and must equal
// target_task_identity for Task. It is never decoded by this protocol; a
// gui_message_policy adapter maps Task to its HWND-less zero only after this
// exact object-kind validation.
struct GuiBrokerTargetAuthoritySnapshot
{
    u64 authority_identity;
    u64 transfer_reference;
    u64 holder_endpoint_identity;
    u64 owner_endpoint_identity;
    u64 target_process_identity;
    u64 target_task_identity;
    u64 target_object_identity;
    core::Win32IntegrityLevel target_integrity;
    GuiBrokerTargetObjectKind object_kind;
    u8 reserved[6];
    u32 rights;
    u32 reserved2;
};

// Retained endpoint-local translation of the target owner's opaque sender-
// principal reference. RegisterRule is the only operation that consumes it.
// The target transport authenticates this snapshot; hostile bytes never
// provide the endpoint/process/task/integrity values stored here.
struct GuiBrokerPrincipalAuthoritySnapshot
{
    u64 authority_identity;
    u64 transfer_reference;
    u64 holder_endpoint_identity;
    u64 principal_endpoint_identity;
    u64 principal_process_identity;
    u64 principal_task_identity;
    core::Win32IntegrityLevel principal_integrity;
    u8 reserved[7];
};

// Retained target-owned exact schema produced only after a successful rule
// registration. It binds the stable target-owner/object generation tuple, not
// an endpoint-local transfer slot, so a separately authenticated transfer in
// another endpoint can name the same exact target without aliasing the rule.
// A post is accepted only when its authenticated endpoint/process/task/
// integrity equals this bound sender and its payload fits the grant. The
// returned scalars therefore reduce directly to gui_message_policy's exact
// principal/target/message/mask shape; no wildcard binding to the current
// caller and no broker-right bit exists on the wire.
struct GuiBrokerRuleAuthoritySnapshot
{
    u64 authority_identity;
    u64 sender_endpoint_identity;
    u64 sender_process_identity;
    u64 sender_task_identity;
    u64 target_owner_endpoint_identity;
    u64 target_process_identity;
    u64 target_task_identity;
    u64 target_object_identity;
    u64 rule_sequence;
    u64 wparam_allowed_bits;
    u64 lparam_allowed_bits;
    u32 message;
    GuiBrokerTargetObjectKind target_object_kind;
    core::Win32IntegrityLevel sender_integrity;
    core::Win32IntegrityLevel target_integrity;
    u8 live;
    u32 reserved;
};

// Retained request-lifecycle authority. Replies come from broker_endpoint;
// cancellation comes from requester_endpoint. The wire request id merely
// selects this already-retained object and grants no cancellation right.
struct GuiBrokerPendingAuthoritySnapshot
{
    u64 authority_identity;
    u64 requester_endpoint_identity;
    u64 broker_endpoint_identity;
    u64 request_id;
    GuiBrokerMethod method;
    GuiBrokerPendingState state;
    u8 reserved[3];
    u32 reserved2;
};

// Every non-cancel payload begins with the standard eight-byte
// VersionedPayload prefix, followed by one of these exact little-endian forms:
//
// Rule register request (64 bytes):
//   +08 u32 method tag        +12 u32 reserved=0
//   +16 u64 target transfer   +24 u64 sender-principal transfer
//   +32 u64 rule sequence     +40 u32 WM_APP message
//   +44 u32 reserved=0        +48 u64 wParam bit mask
//   +56 u64 lParam bit mask
//
// Rule revoke request (56 bytes):
//   +08 u32 method tag        +12 u32 reserved=0
//   +16 u64 target transfer   +24 u64 rule sequence
//   +32 u32 WM_APP message    +36 u32 reserved=0
//   +40 u64 wParam bit mask   +48 u64 lParam bit mask
//
// Post request (56 bytes):
//   +08 u32 method tag=Post   +12 u32 reserved=0
//   +16 u64 target transfer   +24 u64 request sequence
//   +32 u32 WM_APP message    +36 u32 reserved=0
//   +40 u64 wParam            +48 u64 lParam
//
// Reply (32 bytes):
//   +08 u32 method tag        +12 u32 reserved=0
//   +16 u64 request sequence  +24 u32 GuiBrokerReplyStatus
//   +28 u32 reserved=0
//
// CancelPost is the MessageAbi envelope only (32 bytes), kind=Cancel,
// method=Post, request_id naming the exact retained pending request.
inline constexpr u32 kGuiBrokerRegisterRequestPayloadBytes = 64;
inline constexpr u32 kGuiBrokerRevokeRequestPayloadBytes = 56;
inline constexpr u32 kGuiBrokerPostRequestPayloadBytes = 56;
inline constexpr u32 kGuiBrokerReplyPayloadBytes = 32;
inline constexpr u32 kGuiBrokerRegisterRequestFrameBytes =
    ipc::kMessageAbiHeaderV1Bytes + kGuiBrokerRegisterRequestPayloadBytes;
inline constexpr u32 kGuiBrokerRevokeRequestFrameBytes =
    ipc::kMessageAbiHeaderV1Bytes + kGuiBrokerRevokeRequestPayloadBytes;
inline constexpr u32 kGuiBrokerPostRequestFrameBytes =
    ipc::kMessageAbiHeaderV1Bytes + kGuiBrokerPostRequestPayloadBytes;
inline constexpr u32 kGuiBrokerReplyFrameBytes = ipc::kMessageAbiHeaderV1Bytes + kGuiBrokerReplyPayloadBytes;
inline constexpr u32 kGuiBrokerCancelFrameBytes = ipc::kMessageAbiHeaderV1Bytes;

inline constexpr u32 kGuiBrokerPayloadMethodOffset = 8;
inline constexpr u32 kGuiBrokerPayloadReservedOffset = 12;
inline constexpr u32 kGuiBrokerPayloadTargetReferenceOffset = 16;
inline constexpr u32 kGuiBrokerPayloadSequenceOffset = 24;
inline constexpr u32 kGuiBrokerPayloadMessageOffset = 32;
inline constexpr u32 kGuiBrokerPayloadReserved2Offset = 36;
inline constexpr u32 kGuiBrokerPayloadScalar0Offset = 40;
inline constexpr u32 kGuiBrokerPayloadScalar1Offset = 48;
inline constexpr u32 kGuiBrokerRegisterPrincipalReferenceOffset = 24;
inline constexpr u32 kGuiBrokerRegisterSequenceOffset = 32;
inline constexpr u32 kGuiBrokerRegisterMessageOffset = 40;
inline constexpr u32 kGuiBrokerRegisterReserved2Offset = 44;
inline constexpr u32 kGuiBrokerRegisterScalar0Offset = 48;
inline constexpr u32 kGuiBrokerRegisterScalar1Offset = 56;
inline constexpr u32 kGuiBrokerReplySequenceOffset = 16;
inline constexpr u32 kGuiBrokerReplyStatusOffset = 24;
inline constexpr u32 kGuiBrokerReplyReserved2Offset = 28;
static_assert(kGuiBrokerReplySequenceOffset + sizeof(u64) == kGuiBrokerReplyStatusOffset);

// Broad transport rule. The service validator below narrows kind/method to an
// exact 32-, 56-, or 64-byte payload. Cancellation has no payload and needs no
// rule.
inline constexpr ipc::PayloadVersionRule kGuiBrokerPayloadRules[] = {
    {kGuiBrokerPayloadVersion1, kGuiBrokerPayloadV1KnownFlags, kGuiBrokerReplyPayloadBytes,
     kGuiBrokerRegisterRequestPayloadBytes},
};
inline constexpr u32 kGuiBrokerPayloadRuleCount = 1;

struct GuiBrokerValidatedMessage
{
    GuiBrokerValidatedOperation operation;
    GuiBrokerReplyStatus reply_status;
    GuiBrokerTargetObjectKind target_object_kind;
    core::Win32IntegrityLevel sender_integrity;
    core::Win32IntegrityLevel target_integrity;
    core::Win32IntegrityLevel rule_sender_integrity;
    u8 reserved[2];

    u64 request_id;
    u64 request_sequence;
    u64 rule_sequence;
    u64 target_transfer_reference;
    u64 principal_transfer_reference;
    u64 wparam;
    u64 lparam;
    u64 wparam_allowed_bits;
    u64 lparam_allowed_bits;
    u64 sender_endpoint_identity;
    u64 sender_process_identity;
    u64 sender_task_identity;
    u64 principal_authority_identity;
    u64 rule_sender_endpoint_identity;
    u64 rule_sender_process_identity;
    u64 rule_sender_task_identity;
    u64 target_authority_identity;
    u64 target_owner_endpoint_identity;
    u64 target_process_identity;
    u64 target_task_identity;
    u64 target_object_identity;
    u64 rule_authority_identity;
    u64 pending_authority_identity;
    u32 message;
    u32 reserved2;
};

struct GuiBrokerProtocolValidation
{
    GuiBrokerProtocolError error;
    ipc::MessageValidationError message_error;
    ipc::PayloadValidationError payload_error;
    GuiBrokerValidatedMessage message;
};

/// Pure representation checks for separately retained kernel snapshots.
/// [any thread, pure, allocation-free]
bool GuiBrokerEndpointCredentialsAreCanonical(const GuiBrokerEndpointCredentialsSnapshot& snapshot);
bool GuiBrokerTargetAuthorityIsCanonical(const GuiBrokerTargetAuthoritySnapshot& snapshot);
bool GuiBrokerPrincipalAuthorityIsCanonical(const GuiBrokerPrincipalAuthoritySnapshot& snapshot);
bool GuiBrokerRuleAuthorityIsCanonical(const GuiBrokerRuleAuthoritySnapshot& snapshot);
bool GuiBrokerPendingAuthorityIsCanonical(const GuiBrokerPendingAuthoritySnapshot& snapshot);

/// Validate one complete immutable frame and required non-null endpoint, then
/// copy every accepted scalar into the result. Irrelevant authority arguments
/// must be null: request register
/// uses target+principal, revoke/post use target+rule, reply/cancel use pending.
/// Failure returns a zero `message`. No retain, lookup, mutation, allocation,
/// callback, user copy, logging, lock, or scheduler operation occurs.
/// [any thread, pure, allocation-free]
GuiBrokerProtocolValidation GuiBrokerProtocolValidate(
    const void* frame, u32 frame_bytes, const GuiBrokerEndpointCredentialsSnapshot* endpoint,
    const GuiBrokerTargetAuthoritySnapshot* target_authority = nullptr,
    const GuiBrokerPrincipalAuthoritySnapshot* principal_authority = nullptr,
    const GuiBrokerRuleAuthoritySnapshot* rule_authority = nullptr,
    const GuiBrokerPendingAuthoritySnapshot* pending_authority = nullptr);

const char* GuiBrokerProtocolErrorName(GuiBrokerProtocolError error);

} // namespace duetos::drivers::video
