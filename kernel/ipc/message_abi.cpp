#include "ipc/message_abi.h"

namespace duetos::ipc
{

namespace
{

constexpr u32 kMagicOffset = 0;
constexpr u32 kTotalSizeOffset = 4;
constexpr u32 kVersionOffset = 8;
constexpr u32 kHeaderSizeOffset = 10;
constexpr u32 kKindOffset = 12;
constexpr u32 kFlagsOffset = 14;
constexpr u32 kServiceIdOffset = 16;
constexpr u32 kMethodIdOffset = 20;
constexpr u32 kRequestIdOffset = 24;

bool RangesOverlap(const void* left, u32 left_bytes, const void* right, u32 right_bytes)
{
    if (left == nullptr || right == nullptr || left_bytes == 0 || right_bytes == 0)
        return false;
    const uptr left_begin = reinterpret_cast<uptr>(left);
    const uptr right_begin = reinterpret_cast<uptr>(right);
    return left_begin <= right_begin ? right_begin - left_begin < left_bytes : left_begin - right_begin < right_bytes;
}

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

bool MessageKindIsValid(MessageKind kind)
{
    switch (kind)
    {
    case MessageKind::Request:
    case MessageKind::Reply:
    case MessageKind::Notification:
    case MessageKind::Cancel:
        return true;
    }
    return false;
}

MessageValidationError ValidateSemantics(MessageKind kind, u16 flags, u32 service_id, u32 method_id, u64 request_id,
                                         u32 payload_size)
{
    if ((flags & static_cast<u16>(~kMessageAbiV1KnownFlags)) != 0)
        return MessageValidationError::UnsupportedFlags;
    if (!MessageKindIsValid(kind))
        return MessageValidationError::InvalidKind;
    if (service_id == 0 || method_id == 0)
        return MessageValidationError::InvalidRoute;

    if (kind == MessageKind::Notification)
    {
        if (request_id != 0)
            return MessageValidationError::InvalidRequestId;
    }
    else if (request_id == 0)
    {
        return MessageValidationError::InvalidRequestId;
    }

    // Cancellation is an envelope-only control message.  The exact request to
    // cancel is named by request_id; accepting arbitrary payload here would
    // create a second, underspecified cancellation protocol.
    if (kind == MessageKind::Cancel && payload_size != 0)
        return MessageValidationError::UnexpectedPayload;
    return MessageValidationError::Ok;
}

} // namespace

MessageValidationError MessageEncodeHeaderV1(void* buffer, u32 buffer_bytes, const MessageHeaderV1& header)
{
    if (buffer == nullptr)
        return MessageValidationError::NullBuffer;
    if (buffer_bytes < kMessageAbiHeaderV1Bytes)
        return MessageValidationError::MessageTooSmall;
    if (buffer_bytes > kMessageAbiMaxBytes)
        return MessageValidationError::MessageTooLarge;

    // Snapshot before any store so callers may build a logical header in the
    // same scratch buffer without later field reads observing our wire writes.
    const MessageHeaderV1 canonical = header;
    const u32 payload_size = buffer_bytes - kMessageAbiHeaderV1Bytes;
    const MessageValidationError semantic_error = ValidateSemantics(
        canonical.kind, canonical.flags, canonical.service_id, canonical.method_id, canonical.request_id, payload_size);
    if (semantic_error != MessageValidationError::Ok)
        return semantic_error;

    // Validate everything above before the first store so a rejected encode is
    // transactional from the caller's perspective.
    auto* bytes = static_cast<u8*>(buffer);
    WriteLe32(bytes + kMagicOffset, kMessageAbiMagic);
    WriteLe32(bytes + kTotalSizeOffset, buffer_bytes);
    WriteLe16(bytes + kVersionOffset, kMessageAbiVersion1);
    WriteLe16(bytes + kHeaderSizeOffset, kMessageAbiHeaderV1Bytes);
    WriteLe16(bytes + kKindOffset, static_cast<u16>(canonical.kind));
    WriteLe16(bytes + kFlagsOffset, canonical.flags);
    WriteLe32(bytes + kServiceIdOffset, canonical.service_id);
    WriteLe32(bytes + kMethodIdOffset, canonical.method_id);
    WriteLe64(bytes + kRequestIdOffset, canonical.request_id);
    return MessageValidationError::Ok;
}

MessageValidationError MessageValidate(const void* buffer, u32 available_bytes, MessageView* view_out)
{
    if (RangesOverlap(buffer, available_bytes, view_out, static_cast<u32>(sizeof(*view_out))))
        return MessageValidationError::OutputAliasesInput;
    if (view_out != nullptr)
        *view_out = {};
    if (buffer == nullptr)
        return MessageValidationError::NullBuffer;
    if (available_bytes < kMessageAbiHeaderV1Bytes)
        return MessageValidationError::TruncatedHeader;

    const auto* bytes = static_cast<const u8*>(buffer);
    if (ReadLe32(bytes + kMagicOffset) != kMessageAbiMagic)
        return MessageValidationError::BadMagic;

    const u16 version = ReadLe16(bytes + kVersionOffset);
    if (version != kMessageAbiVersion1)
        return MessageValidationError::UnsupportedVersion;

    const u16 header_size = ReadLe16(bytes + kHeaderSizeOffset);
    if (header_size != kMessageAbiHeaderV1Bytes)
        return MessageValidationError::UnsupportedHeaderSize;

    const u32 total_size = ReadLe32(bytes + kTotalSizeOffset);
    if (total_size < header_size)
        return MessageValidationError::MessageTooSmall;
    if (total_size > kMessageAbiMaxBytes)
        return MessageValidationError::MessageTooLarge;
    if (total_size != available_bytes)
        return MessageValidationError::SizeMismatch;

    const MessageKind kind = static_cast<MessageKind>(ReadLe16(bytes + kKindOffset));
    const u16 flags = ReadLe16(bytes + kFlagsOffset);
    const u32 service_id = ReadLe32(bytes + kServiceIdOffset);
    const u32 method_id = ReadLe32(bytes + kMethodIdOffset);
    const u64 request_id = ReadLe64(bytes + kRequestIdOffset);
    const u32 payload_size = total_size - header_size;
    const MessageValidationError semantic_error =
        ValidateSemantics(kind, flags, service_id, method_id, request_id, payload_size);
    if (semantic_error != MessageValidationError::Ok)
        return semantic_error;

    if (view_out != nullptr)
    {
        *view_out = MessageView{total_size,  version,    header_size,
                                kind,        flags,      service_id,
                                method_id,   request_id, payload_size == 0 ? 0U : header_size,
                                payload_size};
    }
    return MessageValidationError::Ok;
}

const char* MessageValidationErrorName(MessageValidationError error)
{
    switch (error)
    {
    case MessageValidationError::Ok:
        return "ok";
    case MessageValidationError::NullBuffer:
        return "null-buffer";
    case MessageValidationError::OutputAliasesInput:
        return "output-aliases-input";
    case MessageValidationError::TruncatedHeader:
        return "truncated-header";
    case MessageValidationError::BadMagic:
        return "bad-magic";
    case MessageValidationError::UnsupportedVersion:
        return "unsupported-version";
    case MessageValidationError::UnsupportedHeaderSize:
        return "unsupported-header-size";
    case MessageValidationError::MessageTooSmall:
        return "message-too-small";
    case MessageValidationError::MessageTooLarge:
        return "message-too-large";
    case MessageValidationError::SizeMismatch:
        return "size-mismatch";
    case MessageValidationError::UnsupportedFlags:
        return "unsupported-flags";
    case MessageValidationError::InvalidKind:
        return "invalid-kind";
    case MessageValidationError::InvalidRoute:
        return "invalid-route";
    case MessageValidationError::InvalidRequestId:
        return "invalid-request-id";
    case MessageValidationError::UnexpectedPayload:
        return "unexpected-payload";
    }
    return "unknown";
}

} // namespace duetos::ipc
