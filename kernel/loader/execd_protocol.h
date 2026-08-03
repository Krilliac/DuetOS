#pragma once

/*
 * Transport-independent execd protocol, v1.
 *
 * Every message is a canonical MessageAbi v1 envelope. Parse request/reply
 * bodies are fixed-size VersionedPayload v1 records; cancellation is the
 * envelope-only control shape required by MessageAbi. All wire integers are
 * little-endian and hostile bytes are decoded bytewise, never through a native
 * struct cast. Successful validation returns scalar copies only.
 *
 * Object references in sender bytes are NOT capabilities by themselves. They
 * are opaque indices into one retained endpoint transfer record and are never
 * looked up in a global HandleTable. The caller must supply trusted scalar
 * facts produced while that record retains the object: exact reference, type,
 * immutable policy, seal state, extent, and (for a source image) content hash.
 * A transfer authority object may not live inside the hostile message.
 *
 * The endpoint/object-transfer mechanism does not exist as a frozen contract
 * yet. Consequently this layer does not claim to authenticate an endpoint,
 * mint a transfer reference, prove a seal, or retain an object. Integration
 * must do those things before calling a validator and keep the transfer record
 * alive through its use of the returned scalars.
 *
 * Peer identity and replay authority never come from this wire format. Before
 * validation, the endpoint adapter must resolve an authenticated peer receipt
 * carrying the exact immutable ProcessKey, credential generation, and channel
 * epoch. After validation it must commit `request_id` once in that exact peer's
 * monotonic request ledger before dispatch. A request ID is correlation only;
 * it is not a process identity, channel generation, or replay capability.
 *
 * Parse replies never inline a LoadPlan. A v1 plan may occupy 18,496 bytes;
 * success instead names one sealed, typed LoadPlan transfer object whose bytes
 * are admitted separately by ExecAdmission.
 */

#include "ipc/message_abi.h"
#include "ipc/versioned_payload.h"
#include "loader/load_plan.h"
#include "util/types.h"

namespace duetos::loader
{

// "EXED" in little-endian byte order.
inline constexpr u32 kExecdServiceId = 0x44455845U;
inline constexpr u32 kExecdParseMethodId = 1;
inline constexpr u32 kExecdCancelMethodId = 2;

inline constexpr u16 kExecdProtocolVersion1 = 1;
inline constexpr u16 kExecdPayloadV1KnownFlags = 0;
inline constexpr u32 kExecdParseRequestV1PayloadBytes = 40;
inline constexpr u32 kExecdParseReplyV1PayloadBytes = 64;
inline constexpr u32 kExecdParseRequestV1MessageBytes =
    ipc::kMessageAbiHeaderV1Bytes + kExecdParseRequestV1PayloadBytes;
inline constexpr u32 kExecdParseReplyV1MessageBytes = ipc::kMessageAbiHeaderV1Bytes + kExecdParseReplyV1PayloadBytes;
inline constexpr u32 kExecdCancelV1MessageBytes = ipc::kMessageAbiHeaderV1Bytes;

// The future transfer layer may use a narrower representation, but v1 never
// accepts a sender value outside the existing positive Handle domain.
using ExecdTransportObjectRef = u64;
inline constexpr ExecdTransportObjectRef kExecdTransportObjectRefMax = 0x7FFFFFFFULL;

inline constexpr u32 kExecdSourceImmutablePolicyV1 = 1;
inline constexpr u32 kExecdLoadPlanImmutablePolicyV1 = 2;
inline constexpr u32 kExecdParseV1KnownFlags = 0;
inline constexpr u64 kExecdSourceObjectMaxBytes = kLoadPlanMaxMappedBytes;
inline constexpr u32 kExecdLoadPlanObjectMinBytes = kLoadPlanV1HeaderBytes + kLoadRegionV1Bytes;
inline constexpr u32 kExecdLoadPlanObjectMaxBytes = kLoadPlanV1HeaderBytes + kLoadPlanMaxRegions * kLoadRegionV1Bytes;
static_assert(kExecdSourceObjectMaxBytes == 1024ULL * 1024 * 1024, "execd v1 source ceiling changed");
static_assert(kExecdLoadPlanObjectMinBytes == 136, "execd v1 LoadPlan minimum changed");
static_assert(kExecdLoadPlanObjectMaxBytes == 18496, "execd v1 LoadPlan ceiling changed");

enum class ExecdFormatHint : u16
{
    AutoDetect = 0,
    Pe32Plus = 1,
    Pe32 = 2,
    Elf64 = 3,
};

enum class ExecdReplyStatus : u32
{
    Success = 0,
    InvalidImage = 1,
    UnsupportedFormat = 2,
    PolicyRejected = 3,
    Cancelled = 4,
    ServiceFailure = 5,
};

enum class ExecdTransferredObjectKind : u8
{
    SourceImage = 1,
    LoadPlan = 2,
};

// Trusted native facts, never a wire structure. The endpoint transfer layer
// owns and retains the referenced object; this value is only a call-local copy
// of the facts against which sender bytes are compared.
struct ExecdObjectTransferAuthorityV1
{
    ExecdTransportObjectRef transport_object_ref;
    ExecdTransferredObjectKind object_kind;
    u8 sealed;
    u32 immutable_policy_id;
    u64 object_bytes;
    Hash256 object_hash;
};

struct ExecdParseRequestV1
{
    u64 request_id;
    ExecdTransportObjectRef source_object_ref;
    u32 immutable_policy_id;
    ExecdFormatHint format_hint;
    u32 flags;
    u32 dependency_count;
};

struct ExecdParseReplyV1
{
    u64 request_id;
    ExecdReplyStatus status;
    ExecdTransportObjectRef load_plan_object_ref;
    u32 immutable_policy_id;
    Hash256 source_hash;
};

struct ExecdCancelV1
{
    u64 request_id;
};

enum class ExecdProtocolError : u8
{
    Ok = 0,
    NullArgument,
    AliasedOutput,
    AuthorityAliasesMessage,
    WrongMessageSize,
    EnvelopeRejected,
    PayloadRejected,
    WrongService,
    WrongMethod,
    WrongKind,
    RequestIdMismatch,
    InvalidObjectReference,
    UnsupportedImmutablePolicy,
    UnsupportedFormatHint,
    UnsupportedFlags,
    DependenciesUnsupported,
    ReservedNonZero,
    InvalidReplyStatus,
    MalformedStatusCombination,
    AuthorityRequired,
    UnexpectedAuthority,
    AuthorityReferenceMismatch,
    AuthorityKindMismatch,
    AuthorityPolicyMismatch,
    AuthorityNotSealed,
    AuthoritySizeInvalid,
    MissingSourceHash,
    SourceHashMismatch,
    ObjectReferenceCollision,
};

// Nested errors preserve the exact MessageAbi or VersionedPayload rejection
// without inflating the stable protocol error namespace.
struct ExecdProtocolResult
{
    ExecdProtocolError error;
    ipc::MessageValidationError envelope_error;
    ipc::PayloadValidationError payload_error;
};

// [any thread; pure, allocation-free, callback-free]
// Encode exact canonical frames. The logical input is snapshotted before any
// output write, so it may share caller scratch storage with `message`.
ExecdProtocolResult ExecdEncodeParseRequestV1(void* message, u32 message_bytes, const ExecdParseRequestV1& request);
ExecdProtocolResult ExecdEncodeParseReplyV1(void* message, u32 message_bytes, const ExecdParseReplyV1& reply);
ExecdProtocolResult ExecdEncodeCancelV1(void* message, u32 message_bytes, u64 request_id);

// [any thread; pure, allocation-free, callback-free]
// Validate exact frames plus trusted transfer facts. Outputs must be writable
// and may not overlap the hostile message; an alias is rejected without a
// write because clearing it would corrupt the input. Every other failure
// clears the scalar output. Authority records are snapshotted and rejected if
// their storage overlaps sender bytes. Reply validation requires both the
// original request ID and its exact validated source-object reference, so a
// same-hash authority record from another request cannot be substituted.
// These pure validators do not replace the endpoint peer receipt or its replay
// ledger; callers must retain that exact ProcessKey/generation authority across
// validation, ledger commit, worker submission, reply, and cancellation.
ExecdProtocolResult ExecdValidateParseRequestV1(const void* message, u32 message_bytes,
                                                const ExecdObjectTransferAuthorityV1* source_authority,
                                                ExecdParseRequestV1* request_out);
ExecdProtocolResult ExecdValidateParseReplyV1(const void* message, u32 message_bytes, u64 expected_request_id,
                                              ExecdTransportObjectRef expected_source_object_ref,
                                              const ExecdObjectTransferAuthorityV1* retained_source_authority,
                                              const ExecdObjectTransferAuthorityV1* load_plan_authority,
                                              ExecdParseReplyV1* reply_out);
ExecdProtocolResult ExecdValidateCancelV1(const void* message, u32 message_bytes, u64 expected_request_id,
                                          ExecdCancelV1* cancel_out);

const char* ExecdProtocolErrorName(ExecdProtocolError error);

} // namespace duetos::loader
