// tests/host/test_message_abi.cpp
//
// Hosted hostile-input coverage for kernel/ipc/message_abi.{h,cpp}.
// Pins the unaligned little-endian wire contract, exact framing, semantic
// request-id rules, cancellation shape, and transactional encoder failures.

#include "host_test_helper.h"
#include "ipc/message_abi.h"

#include <array>
#include <cstddef>
#include <vector>

namespace
{

using duetos::u16;
using duetos::u32;
using duetos::u64;
using duetos::u8;
using duetos::ipc::kMessageAbiHeaderV1Bytes;
using duetos::ipc::kMessageAbiMagic;
using duetos::ipc::kMessageAbiMaxBytes;
using duetos::ipc::kMessageAbiVersion1;
using duetos::ipc::MessageEncodeHeaderV1;
using duetos::ipc::MessageHeaderV1;
using duetos::ipc::MessageKind;
using duetos::ipc::MessageValidate;
using duetos::ipc::MessageValidationError;
using duetos::ipc::MessageValidationErrorName;
using duetos::ipc::MessageView;

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

template <std::size_t N> std::array<u8, N> MakeRequest(u32 service_id = 7, u32 method_id = 11, u64 request_id = 13)
{
    static_assert(N >= kMessageAbiHeaderV1Bytes);
    std::array<u8, N> bytes{};
    const MessageHeaderV1 header{MessageKind::Request, 0, service_id, method_id, request_id};
    EXPECT_EQ(MessageEncodeHeaderV1(bytes.data(), static_cast<u32>(bytes.size()), header), MessageValidationError::Ok);
    return bytes;
}

void ExpectFailure(const u8* bytes, u32 size, MessageValidationError expected)
{
    MessageView view{};
    view.total_size = 0xFFFFFFFFU;
    view.request_id = 0xFFFFFFFFFFFFFFFFULL;
    EXPECT_EQ(MessageValidate(bytes, size, &view), expected);
    EXPECT_EQ(view.total_size, 0U);
    EXPECT_EQ(view.request_id, 0ULL);
}

} // namespace

int main()
{
    constexpr u32 kPayloadBytes = 9;
    auto request = MakeRequest<kMessageAbiHeaderV1Bytes + kPayloadBytes>();
    for (u32 index = 0; index < kPayloadBytes; ++index)
        request[kMessageAbiHeaderV1Bytes + index] = static_cast<u8>(0xA0U + index);

    MessageView view{};

    // Independent byte-exact v1 oracle. This must not be produced by the
    // encoder under test, so a paired offset/endian defect cannot self-agree.
    constexpr std::array<u8, kMessageAbiHeaderV1Bytes> kGoldenRequest{
        0x44, 0x49, 0x50, 0x43, 0x20, 0x00, 0x00, 0x00, 0x01, 0x00, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x04, 0x03, 0x02, 0x01, 0xD4, 0xC3, 0xB2, 0xA1, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01};
    EXPECT_EQ(MessageValidate(kGoldenRequest.data(), static_cast<u32>(kGoldenRequest.size()), &view),
              MessageValidationError::Ok);
    EXPECT_EQ(view.service_id, 0x01020304U);
    EXPECT_EQ(view.method_id, 0xA1B2C3D4U);
    EXPECT_EQ(view.request_id, 0x0102030405060708ULL);
    std::array<u8, kMessageAbiHeaderV1Bytes> encoded_golden{};
    const MessageHeaderV1 golden_header{MessageKind::Request, 0, 0x01020304U, 0xA1B2C3D4U, 0x0102030405060708ULL};
    EXPECT_EQ(MessageEncodeHeaderV1(encoded_golden.data(), static_cast<u32>(encoded_golden.size()), golden_header),
              MessageValidationError::Ok);
    EXPECT_TRUE(encoded_golden == kGoldenRequest);

    EXPECT_EQ(MessageValidate(request.data(), static_cast<u32>(request.size()), &view), MessageValidationError::Ok);
    EXPECT_EQ(view.total_size, static_cast<u32>(request.size()));
    EXPECT_EQ(view.version, kMessageAbiVersion1);
    EXPECT_EQ(view.header_size, kMessageAbiHeaderV1Bytes);
    EXPECT_EQ(view.kind, MessageKind::Request);
    EXPECT_EQ(view.flags, 0U);
    EXPECT_EQ(view.service_id, 7U);
    EXPECT_EQ(view.method_id, 11U);
    EXPECT_EQ(view.request_id, 13ULL);
    EXPECT_EQ(view.payload_offset, static_cast<u32>(kMessageAbiHeaderV1Bytes));
    EXPECT_EQ(view.payload_size, kPayloadBytes);

    // Both APIs must tolerate an unaligned transport buffer.
    std::array<u8, kMessageAbiHeaderV1Bytes + 2> unaligned_storage{};
    u8* unaligned = unaligned_storage.data() + 1;
    const MessageHeaderV1 notification{MessageKind::Notification, 0, 3, 5, 0};
    EXPECT_EQ(MessageEncodeHeaderV1(unaligned, kMessageAbiHeaderV1Bytes + 1, notification), MessageValidationError::Ok);
    EXPECT_EQ(MessageValidate(unaligned, kMessageAbiHeaderV1Bytes + 1, &view), MessageValidationError::Ok);
    EXPECT_EQ(view.kind, MessageKind::Notification);
    EXPECT_EQ(view.payload_size, 1U);

    // The logical header may live in the same output object. The encoder must
    // snapshot it before publishing any wire byte.
    struct HeaderAliasStorage
    {
        MessageHeaderV1 header;
        std::array<u8, kMessageAbiHeaderV1Bytes - sizeof(MessageHeaderV1)> tail;
    };
    static_assert(sizeof(HeaderAliasStorage) == kMessageAbiHeaderV1Bytes);
    HeaderAliasStorage header_alias{{MessageKind::Request, 0, 17, 19, 23}, {}};
    EXPECT_EQ(MessageEncodeHeaderV1(&header_alias, static_cast<u32>(sizeof(header_alias)), header_alias.header),
              MessageValidationError::Ok);
    EXPECT_EQ(MessageValidate(&header_alias, static_cast<u32>(sizeof(header_alias)), &view),
              MessageValidationError::Ok);
    EXPECT_EQ(view.service_id, 17U);
    EXPECT_EQ(view.method_id, 19U);
    EXPECT_EQ(view.request_id, 23ULL);

    // Validation output is trusted state and may never overlap the immutable
    // transport snapshot, including payload-only overlap. Alias rejection is
    // transactional and therefore leaves both ranges byte-identical.
    alignas(MessageView) std::array<u8, kMessageAbiHeaderV1Bytes + sizeof(MessageView)> alias_input{};
    const MessageHeaderV1 alias_header{MessageKind::Request, 0, 29, 31, 37};
    EXPECT_EQ(MessageEncodeHeaderV1(alias_input.data(), static_cast<u32>(alias_input.size()), alias_header),
              MessageValidationError::Ok);
    for (u32 index = kMessageAbiHeaderV1Bytes; index < alias_input.size(); ++index)
        alias_input[index] = static_cast<u8>(0x40U + index);
    const auto alias_before = alias_input;
    EXPECT_EQ(MessageValidate(alias_input.data(), static_cast<u32>(alias_input.size()),
                              reinterpret_cast<MessageView*>(alias_input.data())),
              MessageValidationError::OutputAliasesInput);
    EXPECT_TRUE(alias_input == alias_before);
    EXPECT_EQ(MessageValidate(alias_input.data(), static_cast<u32>(alias_input.size()),
                              reinterpret_cast<MessageView*>(alias_input.data() + kMessageAbiHeaderV1Bytes)),
              MessageValidationError::OutputAliasesInput);
    EXPECT_TRUE(alias_input == alias_before);

    ExpectFailure(nullptr, kMessageAbiHeaderV1Bytes, MessageValidationError::NullBuffer);
    ExpectFailure(request.data(), kMessageAbiHeaderV1Bytes - 1, MessageValidationError::TruncatedHeader);

    {
        auto bytes = request;
        WriteLe32(bytes.data(), kMessageAbiMagic ^ 1U);
        ExpectFailure(bytes.data(), static_cast<u32>(bytes.size()), MessageValidationError::BadMagic);
    }
    {
        auto bytes = request;
        WriteLe16(bytes.data() + 8, kMessageAbiVersion1 + 1U);
        ExpectFailure(bytes.data(), static_cast<u32>(bytes.size()), MessageValidationError::UnsupportedVersion);
    }
    {
        auto bytes = request;
        WriteLe16(bytes.data() + 10, kMessageAbiHeaderV1Bytes - 8U);
        ExpectFailure(bytes.data(), static_cast<u32>(bytes.size()), MessageValidationError::UnsupportedHeaderSize);
    }
    {
        auto bytes = request;
        WriteLe32(bytes.data() + 4, kMessageAbiHeaderV1Bytes - 1U);
        ExpectFailure(bytes.data(), static_cast<u32>(bytes.size()), MessageValidationError::MessageTooSmall);
    }
    {
        auto bytes = request;
        WriteLe32(bytes.data() + 4, kMessageAbiMaxBytes + 1U);
        ExpectFailure(bytes.data(), static_cast<u32>(bytes.size()), MessageValidationError::MessageTooLarge);
    }
    {
        auto bytes = request;
        WriteLe32(bytes.data() + 4, static_cast<u32>(bytes.size()) - 1U);
        ExpectFailure(bytes.data(), static_cast<u32>(bytes.size()), MessageValidationError::SizeMismatch);
    }
    {
        auto bytes = request;
        WriteLe16(bytes.data() + 14, 1);
        ExpectFailure(bytes.data(), static_cast<u32>(bytes.size()), MessageValidationError::UnsupportedFlags);
    }
    {
        auto bytes = request;
        WriteLe16(bytes.data() + 12, 0);
        ExpectFailure(bytes.data(), static_cast<u32>(bytes.size()), MessageValidationError::InvalidKind);
    }
    {
        auto bytes = request;
        WriteLe32(bytes.data() + 16, 0);
        ExpectFailure(bytes.data(), static_cast<u32>(bytes.size()), MessageValidationError::InvalidRoute);
    }
    {
        auto bytes = request;
        WriteLe32(bytes.data() + 20, 0);
        ExpectFailure(bytes.data(), static_cast<u32>(bytes.size()), MessageValidationError::InvalidRoute);
    }
    {
        auto bytes = request;
        WriteLe64(bytes.data() + 24, 0);
        ExpectFailure(bytes.data(), static_cast<u32>(bytes.size()), MessageValidationError::InvalidRequestId);
    }
    {
        auto bytes = request;
        WriteLe16(bytes.data() + 12, static_cast<u16>(MessageKind::Notification));
        ExpectFailure(bytes.data(), static_cast<u32>(bytes.size()), MessageValidationError::InvalidRequestId);
    }

    // Reply IDs correlate to requests; notifications deliberately have none.
    auto reply = MakeRequest<kMessageAbiHeaderV1Bytes>();
    WriteLe16(reply.data() + 12, static_cast<u16>(MessageKind::Reply));
    EXPECT_EQ(MessageValidate(reply.data(), static_cast<u32>(reply.size()), &view), MessageValidationError::Ok);
    auto note = MakeRequest<kMessageAbiHeaderV1Bytes>();
    WriteLe16(note.data() + 12, static_cast<u16>(MessageKind::Notification));
    WriteLe64(note.data() + 24, 0);
    EXPECT_EQ(MessageValidate(note.data(), static_cast<u32>(note.size()), &view), MessageValidationError::Ok);
    EXPECT_EQ(view.payload_offset, 0U);

    // Cancel is intentionally envelope-only.
    std::array<u8, kMessageAbiHeaderV1Bytes> cancel{};
    const MessageHeaderV1 cancel_header{MessageKind::Cancel, 0, 9, 2, 0x1234};
    EXPECT_EQ(MessageEncodeHeaderV1(cancel.data(), static_cast<u32>(cancel.size()), cancel_header),
              MessageValidationError::Ok);
    EXPECT_EQ(MessageValidate(cancel.data(), static_cast<u32>(cancel.size()), &view), MessageValidationError::Ok);
    std::array<u8, kMessageAbiHeaderV1Bytes + 1> cancel_with_payload{};
    EXPECT_EQ(
        MessageEncodeHeaderV1(cancel_with_payload.data(), static_cast<u32>(cancel_with_payload.size()), cancel_header),
        MessageValidationError::UnexpectedPayload);

    // A rejected encode performs no partial header publication.
    std::array<u8, kMessageAbiHeaderV1Bytes> untouched{};
    untouched.fill(0xA5);
    const auto before = untouched;
    const MessageHeaderV1 invalid_request{MessageKind::Request, 0, 1, 1, 0};
    EXPECT_EQ(MessageEncodeHeaderV1(untouched.data(), static_cast<u32>(untouched.size()), invalid_request),
              MessageValidationError::InvalidRequestId);
    EXPECT_TRUE(untouched == before);

    std::vector<u8> maximum(kMessageAbiMaxBytes);
    const MessageHeaderV1 maximum_header{MessageKind::Request, 0, 1, 1, 1};
    EXPECT_EQ(MessageEncodeHeaderV1(maximum.data(), static_cast<u32>(maximum.size()), maximum_header),
              MessageValidationError::Ok);
    EXPECT_EQ(MessageValidate(maximum.data(), static_cast<u32>(maximum.size()), nullptr), MessageValidationError::Ok);
    std::vector<u8> oversized(static_cast<std::size_t>(kMessageAbiMaxBytes) + 1U);
    EXPECT_EQ(MessageEncodeHeaderV1(oversized.data(), static_cast<u32>(oversized.size()), maximum_header),
              MessageValidationError::MessageTooLarge);

    EXPECT_STREQ(MessageValidationErrorName(MessageValidationError::SizeMismatch), "size-mismatch");
    EXPECT_STREQ(MessageValidationErrorName(MessageValidationError::OutputAliasesInput), "output-aliases-input");
    EXPECT_STREQ(MessageValidationErrorName(static_cast<MessageValidationError>(0xFF)), "unknown");

    return duetos_host_test::finish_main("test_message_abi");
}
