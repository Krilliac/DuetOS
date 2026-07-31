#pragma once

/*
 * Transport-independent serviced control protocol, v1.
 *
 * serviced is the future userland owner of manifests and restart policy.  The
 * kernel keeps final scheduling, address-space, object-right, interrupt, and
 * device authority.  This boundary therefore carries service selectors and
 * optimistic transition generations, never Process/Task pointers, raw kernel
 * handles, capability bits, or authoritative PID/TID values from sender bytes.
 *
 * Every frame is a canonical MessageAbi envelope plus a fixed VersionedPayload
 * record.  Integers are little-endian and decoded bytewise.  The validator is
 * pure and allocation-free.  Authority comes from a separately retained
 * endpoint capability snapshot: the request's stable service identity and
 * expected generation select state, but cannot grant permission.
 *
 * Request sequence validation is snapshot-based.  After a successful decode,
 * the transport must atomically reserve/commit that exact request_id against
 * the endpoint replay ledger before invoking serviced.  Replies must arrive on
 * the retained serviced endpoint and are additionally bound here to the exact
 * original request, including identity or enumeration cursor.
 */

#include "ipc/message_abi.h"
#include "ipc/versioned_payload.h"
#include "util/types.h"

namespace duetos::core
{

// "SVCD" in little-endian byte order.
inline constexpr u32 kServicedServiceId = 0x44435653U;
inline constexpr u16 kServicedProtocolVersion1 = 1;
inline constexpr u16 kServicedPayloadV1KnownFlags = 0;

inline constexpr u32 kServicedMaximumServices = 4096;
inline constexpr u64 kServicedInvalidServiceIdentity = 0;
inline constexpr u64 kServicedAllServicesScope = ~0ULL;
inline constexpr u32 kServicedEnumerationEnd = ~0U;
inline constexpr u32 kServicedServiceNameCapacity = 32;

inline constexpr u32 kServicedRequestV1PayloadBytes = 40;
inline constexpr u32 kServicedReplyV1PayloadBytes = 120;
inline constexpr u32 kServicedRequestV1MessageBytes = ipc::kMessageAbiHeaderV1Bytes + kServicedRequestV1PayloadBytes;
inline constexpr u32 kServicedReplyV1MessageBytes = ipc::kMessageAbiHeaderV1Bytes + kServicedReplyV1PayloadBytes;

enum class ServicedMethod : u32
{
    Enumerate = 1,
    Query = 2,
    Start = 3,
    Stop = 4,
    Restart = 5,
};

enum class ServicedReplyStatus : u32
{
    Success = 0,
    EndOfEnumeration = 1,
    NotFound = 2,
    StaleGeneration = 3,
    Denied = 4,
    Busy = 5,
    GenerationExhausted = 6,
    ServiceFailure = 7,
};

enum class ServicedInstancePhase : u8
{
    Stopped = 0,
    Starting = 1,
    Running = 2,
    Exited = 3,
    Failed = 4,
    GenerationExhausted = 5,
    Stopping = 6,
};

enum class ServicedRestartPolicy : u8
{
    Never = 0,
    Always = 1,
    OnFailure = 2,
};

inline constexpr u32 kServicedRightInspect = 1U << 0;
inline constexpr u32 kServicedRightControl = 1U << 1;
inline constexpr u32 kServicedKnownRights = kServicedRightInspect | kServicedRightControl;

// Trusted transport facts.  No wire field can populate these structures.
struct ServicedEndpointSnapshotV1
{
    u64 endpoint_identity;
    u64 process_identity;
    u64 task_identity;
    u64 last_committed_request_sequence;
    u64 reserved;
};

// A scope is either one exact stable service identity or
// kServicedAllServicesScope. Manifest array indices are deliberately not
// authority: after a manifest change, a stale slot must not name a different
// service. Control does not imply Inspect and vice versa.
struct ServicedControlAuthoritySnapshotV1
{
    u64 authority_identity;
    u64 holder_endpoint_identity;
    u64 service_identity_scope;
    u32 rights;
    u32 reserved;
};

struct ServicedRequestV1
{
    u64 request_id;
    ServicedMethod method;
    u32 enumeration_cursor;
    u64 service_identity;
    u64 expected_transition_generation;
};

// Result of request validation.  The trusted bindings are copied beside the
// wire selectors so downstream code need not re-read borrowed snapshots.
struct ServicedValidatedRequestV1
{
    ServicedRequestV1 request;
    u64 sender_endpoint_identity;
    u64 sender_process_identity;
    u64 sender_task_identity;
    u64 authority_identity;
    u32 authority_rights;
    u64 authority_scope;
};

struct ServicedStatusRowV1
{
    // Opaque stable manifest/service-registry generation. Clients use this for
    // Query/control. service_slot is enumeration metadata only.
    u64 service_identity;
    u32 service_slot;
    u64 transition_generation;
    u64 pid;
    u32 lifetime_restarts;
    u32 restarts_in_window;
    u64 last_spawn_ns;
    u64 last_exit_ns;
    ServicedInstancePhase phase;
    ServicedRestartPolicy restart_policy;
    u8 autostart;
    u8 name_length;
    u8 name[kServicedServiceNameCapacity];
};

struct ServicedReplyV1
{
    u64 request_id;
    ServicedMethod method;
    ServicedReplyStatus status;
    u32 next_cursor;
    ServicedStatusRowV1 service;
};

enum class ServicedProtocolError : u8
{
    Ok = 0,
    NullArgument,
    AliasedOutput,
    SnapshotAliasesMessage,
    WrongMessageSize,
    EnvelopeRejected,
    PayloadRejected,
    WrongService,
    WrongMethod,
    WrongKind,
    RequestIdMismatch,
    PayloadMethodMismatch,
    ReservedNonZero,
    InvalidServiceSlot,
    InvalidRequestShape,
    ReplayedRequest,
    MalformedEndpoint,
    AuthorityRequired,
    MalformedAuthority,
    AuthorityEndpointMismatch,
    AuthorityScopeMismatch,
    PermissionDenied,
    InvalidReplyStatus,
    MalformedReplyCombination,
    ReplyTargetMismatch,
    MalformedStatusRow,
    InvalidPhase,
    InvalidRestartPolicy,
    InvalidServiceName,
};

struct ServicedProtocolResult
{
    ServicedProtocolError error;
    ipc::MessageValidationError envelope_error;
    ipc::PayloadValidationError payload_error;
};

/// Representation-only checks for retained trusted snapshots and decoded rows.
/// [any thread; pure, allocation-free, callback-free]
bool ServicedEndpointSnapshotIsCanonicalV1(const ServicedEndpointSnapshotV1& snapshot);
bool ServicedControlAuthoritySnapshotIsCanonicalV1(const ServicedControlAuthoritySnapshotV1& snapshot);
bool ServicedStatusRowIsCanonicalV1(const ServicedStatusRowV1& row);

/// Encode exact canonical frames transactionally.  Logical inputs are
/// snapshotted before output writes, so they may share caller scratch storage.
/// [any thread; pure, allocation-free, callback-free]
ServicedProtocolResult ServicedEncodeRequestV1(void* message, u32 message_bytes, const ServicedRequestV1& request);
ServicedProtocolResult ServicedEncodeReplyV1(void* message, u32 message_bytes, const ServicedReplyV1& reply);

/// Validate one request plus separately retained endpoint/control authority.
/// Outputs may not overlap the hostile frame or trusted snapshots.  Alias
/// failures perform no write; every other failure clears the output.
/// [any thread; pure, allocation-free, callback-free]
ServicedProtocolResult ServicedValidateRequestV1(const void* message, u32 message_bytes,
                                                 const ServicedEndpointSnapshotV1* endpoint,
                                                 const ServicedControlAuthoritySnapshotV1* authority,
                                                 ServicedValidatedRequestV1* request_out);

/// Validate a reply arriving on an already-authenticated serviced endpoint.
/// The exact original request is passed by value and binds request id, method,
/// enumeration cursor, and stable service identity; a same-method reply for a
/// different service cannot be substituted.
/// [any thread; pure, allocation-free, callback-free]
ServicedProtocolResult ServicedValidateReplyV1(const void* message, u32 message_bytes,
                                               ServicedRequestV1 expected_request, ServicedReplyV1* reply_out);

const char* ServicedProtocolErrorName(ServicedProtocolError error);

} // namespace duetos::core
