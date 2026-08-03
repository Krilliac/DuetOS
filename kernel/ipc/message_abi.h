#pragma once

/*
 * Versioned byte-level IPC message envelope.
 *
 * This is the stable boundary between generated service/IDL payloads and a
 * future waitable message-port transport. The transport first copies hostile
 * bytes into a kernel-owned snapshot and keeps that snapshot immutable through
 * validation and every later payload read. Validation borrows the snapshot
 * only for the duration of the call and returns scalar offsets/lengths, never
 * a pointer into caller storage. A MessageView is not a lifetime pin: callers
 * must retain the same immutable snapshot while using its offsets.
 *
 * Wire values are little-endian and may be unaligned.  Callers must not cast a
 * hostile buffer to a C++ struct.  Authorization is deliberately absent from
 * the envelope: service identity, credentials, and rights come from the
 * retained channel/handle used to deliver the message, never sender bytes.
 */

#include "util/types.h"

namespace duetos::ipc
{

// "DIPC" in little-endian byte order.
inline constexpr u32 kMessageAbiMagic = 0x43504944U;
inline constexpr u16 kMessageAbiVersion1 = 1;
inline constexpr u16 kMessageAbiHeaderV1Bytes = 32;
inline constexpr u32 kMessageAbiMaxBytes = 64U * 1024U;

enum class MessageKind : u16
{
    Request = 1,
    Reply = 2,
    Notification = 3,
    Cancel = 4,
};

// v1 defines no optional flag bits.  Keeping the field in the fixed header
// lets a later version add negotiated behavior without changing field offsets.
inline constexpr u16 kMessageAbiV1KnownFlags = 0;

enum class MessageValidationError : u8
{
    Ok = 0,
    NullBuffer,
    TruncatedHeader,
    BadMagic,
    UnsupportedVersion,
    UnsupportedHeaderSize,
    MessageTooSmall,
    MessageTooLarge,
    SizeMismatch,
    UnsupportedFlags,
    InvalidKind,
    InvalidRoute,
    InvalidRequestId,
    UnexpectedPayload,
    OutputAliasesInput,
};

// Logical fields accepted by the v1 encoder.  Version, header size, magic, and
// total size are fixed/canonical and are therefore not caller-controlled.
struct MessageHeaderV1
{
    MessageKind kind;
    u16 flags;
    u32 service_id;
    u32 method_id;
    u64 request_id;
};

// Canonical scalar view produced after successful validation.  payload_offset
// and payload_size may be used only against the same immutable snapshot; this
// object intentionally does not extend that snapshot's lifetime.
struct MessageView
{
    u32 total_size;
    u16 version;
    u16 header_size;
    MessageKind kind;
    u16 flags;
    u32 service_id;
    u32 method_id;
    u64 request_id;
    u32 payload_offset;
    u32 payload_size;
};

/// Encode a canonical v1 header into `buffer` without touching payload bytes.
/// `buffer_bytes` becomes the exact total-size field.  Semantic failure leaves
/// the entire buffer unchanged.  The buffer may be unaligned. `header` may
/// overlap the output; it is snapshotted before the first store.
MessageValidationError MessageEncodeHeaderV1(void* buffer, u32 buffer_bytes, const MessageHeaderV1& header);

/// Validate one complete framed message.  The available byte count must match
/// the encoded total exactly; concatenated or truncated frames are refused.
/// `view_out` is optional and must not overlap any available input byte. An
/// alias failure leaves both ranges untouched; every other failure clears a
/// valid non-aliased output. The input is a kernel-owned immutable snapshot,
/// not a user pointer, and must remain immutable while returned offsets are in
/// use. No allocation, blocking, locking, logging, or external callback occurs.
MessageValidationError MessageValidate(const void* buffer, u32 available_bytes, MessageView* view_out);

/// Stable diagnostic spelling for validation results.
const char* MessageValidationErrorName(MessageValidationError error);

} // namespace duetos::ipc
