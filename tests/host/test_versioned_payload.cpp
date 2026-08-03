// tests/host/test_versioned_payload.cpp
//
// Hosted hostile-input coverage for kernel/ipc/versioned_payload.{h,cpp}.
// Pins exact framing, unaligned little-endian input, fail-closed generated
// metadata, version-specific flags/sizes, and transactional alias-safe encode.

#include "host_test_helper.h"
#include "ipc/versioned_payload.h"

#include <array>
#include <cstddef>
#include <new>
#include <vector>

namespace
{

using duetos::u16;
using duetos::u32;
using duetos::u8;
using duetos::ipc::kVersionedPayloadHeaderBytes;
using duetos::ipc::kVersionedPayloadMaxBytes;
using duetos::ipc::kVersionedPayloadMaxRules;
using duetos::ipc::PayloadEncodeHeader;
using duetos::ipc::PayloadValidate;
using duetos::ipc::PayloadValidationError;
using duetos::ipc::PayloadValidationErrorName;
using duetos::ipc::PayloadVersionRule;
using duetos::ipc::VersionedPayloadView;

constexpr std::array<PayloadVersionRule, 3> kRules{{
    {1, 0, kVersionedPayloadHeaderBytes, kVersionedPayloadHeaderBytes},
    {2, 0x0003, 12, 24},
    {7, 0, 16, kVersionedPayloadMaxBytes},
}};

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

template <std::size_t N> std::array<u8, N> MakePayload(u16 version, u16 flags = 0)
{
    static_assert(N >= kVersionedPayloadHeaderBytes);
    std::array<u8, N> bytes{};
    EXPECT_EQ(PayloadEncodeHeader(bytes.data(), static_cast<u32>(bytes.size()), version, flags, kRules.data(),
                                  static_cast<u32>(kRules.size())),
              PayloadValidationError::Ok);
    return bytes;
}

void ExpectFailure(const u8* bytes, u32 size, const PayloadVersionRule* rules, u32 rule_count,
                   PayloadValidationError expected)
{
    VersionedPayloadView view{};
    view.total_size = 0xFFFFFFFFU;
    view.version = 0xFFFFU;
    view.flags = 0xFFFFU;
    EXPECT_EQ(PayloadValidate(bytes, size, rules, rule_count, &view), expected);
    EXPECT_EQ(view.total_size, 0U);
    EXPECT_EQ(view.version, 0U);
    EXPECT_EQ(view.flags, 0U);
}

} // namespace

int main()
{
    // Independent literal oracle: this is not produced by the encoder under
    // test and therefore pins every v1 prefix byte and its little-endian order.
    constexpr std::array<u8, 8> golden_v1_header{{0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}};
    VersionedPayloadView golden_view{};
    EXPECT_EQ(PayloadValidate(golden_v1_header.data(), static_cast<u32>(golden_v1_header.size()), kRules.data(),
                              static_cast<u32>(kRules.size()), &golden_view),
              PayloadValidationError::Ok);
    EXPECT_EQ(golden_view.total_size, 8U);
    EXPECT_EQ(golden_view.version, 1U);
    EXPECT_EQ(golden_view.flags, 0U);
    std::array<u8, 8> encoded_golden{};
    EXPECT_EQ(PayloadEncodeHeader(encoded_golden.data(), static_cast<u32>(encoded_golden.size()), 1, 0, kRules.data(),
                                  static_cast<u32>(kRules.size())),
              PayloadValidationError::Ok);
    EXPECT_TRUE(encoded_golden == golden_v1_header);

    auto payload = MakePayload<16>(2, 0x0001);
    VersionedPayloadView view{};
    EXPECT_EQ(PayloadValidate(payload.data(), static_cast<u32>(payload.size()), kRules.data(),
                              static_cast<u32>(kRules.size()), &view),
              PayloadValidationError::Ok);
    EXPECT_EQ(view.total_size, 16U);
    EXPECT_EQ(view.version, 2U);
    EXPECT_EQ(view.flags, 1U);

    // Successful encoding writes exactly the prefix and leaves the typed body
    // under the generated encoder's ownership.
    std::array<u8, 16> body_canary{};
    body_canary.fill(0xA5);
    EXPECT_EQ(PayloadEncodeHeader(body_canary.data(), static_cast<u32>(body_canary.size()), 2, 1, kRules.data(),
                                  static_cast<u32>(kRules.size())),
              PayloadValidationError::Ok);
    constexpr std::array<u8, 8> encoded_v2_header{{0x10, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00}};
    for (std::size_t index = 0; index < encoded_v2_header.size(); ++index)
        EXPECT_EQ(body_canary[index], encoded_v2_header[index]);
    for (std::size_t index = kVersionedPayloadHeaderBytes; index < body_canary.size(); ++index)
        EXPECT_EQ(body_canary[index], 0xA5U);

    // Both APIs accept a byte buffer with no natural integer alignment.
    std::array<u8, 18> unaligned_storage{};
    u8* unaligned = unaligned_storage.data() + 1;
    EXPECT_EQ(PayloadEncodeHeader(unaligned, 16, 2, 0x0002, kRules.data(), static_cast<u32>(kRules.size())),
              PayloadValidationError::Ok);
    EXPECT_EQ(PayloadValidate(unaligned, 16, kRules.data(), static_cast<u32>(kRules.size()), &view),
              PayloadValidationError::Ok);
    EXPECT_EQ(view.flags, 2U);

    ExpectFailure(nullptr, kVersionedPayloadHeaderBytes, kRules.data(), static_cast<u32>(kRules.size()),
                  PayloadValidationError::NullBuffer);
    ExpectFailure(payload.data(), kVersionedPayloadHeaderBytes - 1, kRules.data(), static_cast<u32>(kRules.size()),
                  PayloadValidationError::TruncatedHeader);

    {
        auto bytes = payload;
        WriteLe32(bytes.data(), kVersionedPayloadHeaderBytes - 1U);
        ExpectFailure(bytes.data(), static_cast<u32>(bytes.size()), kRules.data(), static_cast<u32>(kRules.size()),
                      PayloadValidationError::PayloadTooSmall);
    }
    {
        auto bytes = payload;
        WriteLe32(bytes.data(), kVersionedPayloadMaxBytes + 1U);
        ExpectFailure(bytes.data(), static_cast<u32>(bytes.size()), kRules.data(), static_cast<u32>(kRules.size()),
                      PayloadValidationError::PayloadTooLarge);
    }
    {
        auto bytes = payload;
        WriteLe32(bytes.data(), static_cast<u32>(bytes.size()) - 1U);
        ExpectFailure(bytes.data(), static_cast<u32>(bytes.size()), kRules.data(), static_cast<u32>(kRules.size()),
                      PayloadValidationError::SizeMismatch);
    }
    {
        auto bytes = payload;
        WriteLe16(bytes.data() + 4, 3);
        ExpectFailure(bytes.data(), static_cast<u32>(bytes.size()), kRules.data(), static_cast<u32>(kRules.size()),
                      PayloadValidationError::UnsupportedVersion);
    }
    {
        auto bytes = payload;
        WriteLe16(bytes.data() + 6, 0x0004);
        ExpectFailure(bytes.data(), static_cast<u32>(bytes.size()), kRules.data(), static_cast<u32>(kRules.size()),
                      PayloadValidationError::UnsupportedFlags);
    }
    {
        auto bytes = MakePayload<kVersionedPayloadHeaderBytes>(1);
        WriteLe16(bytes.data() + 4, 2);
        ExpectFailure(bytes.data(), static_cast<u32>(bytes.size()), kRules.data(), static_cast<u32>(kRules.size()),
                      PayloadValidationError::SizeOutsideVersionRange);
    }
    {
        std::array<u8, 25> bytes{};
        WriteLe32(bytes.data(), static_cast<u32>(bytes.size()));
        WriteLe16(bytes.data() + 4, 2);
        ExpectFailure(bytes.data(), static_cast<u32>(bytes.size()), kRules.data(), static_cast<u32>(kRules.size()),
                      PayloadValidationError::SizeOutsideVersionRange);
    }

    // Every malformed generated rule-table shape is refused before use.
    ExpectFailure(payload.data(), static_cast<u32>(payload.size()), nullptr, 0,
                  PayloadValidationError::InvalidRuleTable);
    VersionedPayloadView oversized_count_view{0xFFFFFFFFU, 0xFFFFU, 0xFFFFU};
    EXPECT_EQ(PayloadValidate(payload.data(), static_cast<u32>(payload.size()),
                              reinterpret_cast<const PayloadVersionRule*>(&oversized_count_view),
                              kVersionedPayloadMaxRules + 1U, &oversized_count_view),
              PayloadValidationError::InvalidRuleTable);
    EXPECT_EQ(oversized_count_view.total_size, 0xFFFFFFFFU);
    EXPECT_EQ(oversized_count_view.version, 0xFFFFU);
    EXPECT_EQ(oversized_count_view.flags, 0xFFFFU);
    {
        constexpr std::array<PayloadVersionRule, 1> rules{{{0, 0, 8, 8}}};
        ExpectFailure(payload.data(), static_cast<u32>(payload.size()), rules.data(), static_cast<u32>(rules.size()),
                      PayloadValidationError::InvalidRuleTable);
    }
    {
        constexpr std::array<PayloadVersionRule, 2> rules{{{2, 0, 8, 16}, {2, 0, 8, 16}}};
        ExpectFailure(payload.data(), static_cast<u32>(payload.size()), rules.data(), static_cast<u32>(rules.size()),
                      PayloadValidationError::InvalidRuleTable);
    }
    {
        constexpr std::array<PayloadVersionRule, 2> rules{{{2, 0, 8, 16}, {1, 0, 8, 16}}};
        ExpectFailure(payload.data(), static_cast<u32>(payload.size()), rules.data(), static_cast<u32>(rules.size()),
                      PayloadValidationError::InvalidRuleTable);
    }
    {
        constexpr std::array<PayloadVersionRule, 1> rules{{{1, 0, 7, 8}}};
        ExpectFailure(payload.data(), static_cast<u32>(payload.size()), rules.data(), static_cast<u32>(rules.size()),
                      PayloadValidationError::InvalidRuleTable);
    }
    {
        constexpr std::array<PayloadVersionRule, 1> rules{{{1, 0, 12, 11}}};
        ExpectFailure(payload.data(), static_cast<u32>(payload.size()), rules.data(), static_cast<u32>(rules.size()),
                      PayloadValidationError::InvalidRuleTable);
    }
    {
        constexpr std::array<PayloadVersionRule, 1> rules{{{1, 0, 8, kVersionedPayloadMaxBytes + 1U}}};
        ExpectFailure(payload.data(), static_cast<u32>(payload.size()), rules.data(), static_cast<u32>(rules.size()),
                      PayloadValidationError::InvalidRuleTable);
    }

    // Encoder failures are transactional, including malformed metadata.
    std::array<u8, 16> untouched{};
    untouched.fill(0xA5);
    const auto before = untouched;
    EXPECT_EQ(PayloadEncodeHeader(untouched.data(), static_cast<u32>(untouched.size()), 3, 0, kRules.data(),
                                  static_cast<u32>(kRules.size())),
              PayloadValidationError::UnsupportedVersion);
    EXPECT_TRUE(untouched == before);
    EXPECT_EQ(PayloadEncodeHeader(untouched.data(), static_cast<u32>(untouched.size()), 2, 0x0004, kRules.data(),
                                  static_cast<u32>(kRules.size())),
              PayloadValidationError::UnsupportedFlags);
    EXPECT_TRUE(untouched == before);
    EXPECT_EQ(PayloadEncodeHeader(untouched.data(), static_cast<u32>(untouched.size()), 2, 0, nullptr, 0),
              PayloadValidationError::InvalidRuleTable);
    EXPECT_TRUE(untouched == before);

    // The rule table may occupy the same scratch bytes as the encoded prefix.
    // This catches implementations that retain a pointer and read it after the
    // first header store has overwritten the rule's object representation.
    alignas(PayloadVersionRule) u8 aliased_storage[sizeof(PayloadVersionRule)]{};
    auto* aliased_rule = ::new (static_cast<void*>(aliased_storage))
        PayloadVersionRule{5, 0, kVersionedPayloadHeaderBytes, static_cast<u32>(sizeof(aliased_storage))};
    EXPECT_EQ(PayloadEncodeHeader(aliased_storage, static_cast<u32>(sizeof(aliased_storage)), 5, 0, aliased_rule, 1),
              PayloadValidationError::Ok);
    constexpr std::array<PayloadVersionRule, 1> alias_validation_rules{{
        {5, 0, kVersionedPayloadHeaderBytes, static_cast<u32>(sizeof(PayloadVersionRule))},
    }};
    EXPECT_EQ(PayloadValidate(aliased_storage, static_cast<u32>(sizeof(aliased_storage)), alias_validation_rules.data(),
                              static_cast<u32>(alias_validation_rules.size()), &view),
              PayloadValidationError::Ok);
    EXPECT_EQ(view.version, 5U);

    // Validation is intentionally stricter than encoding: policy metadata,
    // hostile bytes, and output storage are three separate trust domains.
    alignas(VersionedPayloadView) std::array<u8, 16> validation_storage = payload;
    const auto validation_before = validation_storage;
    auto* header_alias = reinterpret_cast<VersionedPayloadView*>(validation_storage.data());
    EXPECT_EQ(PayloadValidate(validation_storage.data(), static_cast<u32>(validation_storage.size()), kRules.data(),
                              static_cast<u32>(kRules.size()), header_alias),
              PayloadValidationError::OutputAliasesInput);
    EXPECT_TRUE(validation_storage == validation_before);
    auto* body_alias = reinterpret_cast<VersionedPayloadView*>(validation_storage.data() + 8);
    EXPECT_EQ(PayloadValidate(validation_storage.data(), static_cast<u32>(validation_storage.size()), kRules.data(),
                              static_cast<u32>(kRules.size()), body_alias),
              PayloadValidationError::OutputAliasesInput);
    EXPECT_TRUE(validation_storage == validation_before);

    auto mutable_rules = kRules;
    const auto rules_before = mutable_rules;
    auto* rule_alias = reinterpret_cast<VersionedPayloadView*>(mutable_rules.data());
    EXPECT_EQ(PayloadValidate(payload.data(), static_cast<u32>(payload.size()), mutable_rules.data(),
                              static_cast<u32>(mutable_rules.size()), rule_alias),
              PayloadValidationError::OutputAliasesInput);
    for (std::size_t index = 0; index < mutable_rules.size(); ++index)
    {
        EXPECT_EQ(mutable_rules[index].version, rules_before[index].version);
        EXPECT_EQ(mutable_rules[index].known_flags, rules_before[index].known_flags);
        EXPECT_EQ(mutable_rules[index].minimum_size, rules_before[index].minimum_size);
        EXPECT_EQ(mutable_rules[index].maximum_size, rules_before[index].maximum_size);
    }

    alignas(PayloadVersionRule) std::array<u8, sizeof(PayloadVersionRule)> overlapping_inputs{};
    overlapping_inputs.fill(0x5A);
    VersionedPayloadView untouched_view{0xFFFFFFFFU, 0xFFFFU, 0xFFFFU};
    EXPECT_EQ(PayloadValidate(overlapping_inputs.data(), kVersionedPayloadHeaderBytes,
                              reinterpret_cast<const PayloadVersionRule*>(overlapping_inputs.data()), 1,
                              &untouched_view),
              PayloadValidationError::InputsOverlap);
    EXPECT_EQ(untouched_view.total_size, 0xFFFFFFFFU);
    EXPECT_EQ(untouched_view.version, 0xFFFFU);
    EXPECT_EQ(untouched_view.flags, 0xFFFFU);
    for (u8 byte : overlapping_inputs)
        EXPECT_EQ(byte, 0x5AU);

    // Pin the half-open overlap boundaries in both pointer orderings.  Exact
    // adjacency is safe; a one-byte intersection is not.
    alignas(VersionedPayloadView) std::array<u8, 32> adjacent_after_storage{};
    for (std::size_t index = 0; index < payload.size(); ++index)
        adjacent_after_storage[index] = payload[index];
    auto* adjacent_after = ::new (static_cast<void*>(adjacent_after_storage.data() + payload.size()))
        VersionedPayloadView{0xFFFFFFFFU, 0xFFFFU, 0xFFFFU};
    EXPECT_EQ(PayloadValidate(adjacent_after_storage.data(), static_cast<u32>(payload.size()), kRules.data(),
                              static_cast<u32>(kRules.size()), adjacent_after),
              PayloadValidationError::Ok);
    EXPECT_EQ(adjacent_after->total_size, 16U);
    EXPECT_EQ(adjacent_after->version, 2U);
    EXPECT_EQ(adjacent_after->flags, 1U);

    alignas(VersionedPayloadView) std::array<u8, 32> adjacent_before_storage{};
    auto* adjacent_before =
        ::new (static_cast<void*>(adjacent_before_storage.data())) VersionedPayloadView{0xFFFFFFFFU, 0xFFFFU, 0xFFFFU};
    EXPECT_EQ(PayloadValidate(adjacent_before_storage.data() + sizeof(VersionedPayloadView),
                              static_cast<u32>(payload.size()), kRules.data(), static_cast<u32>(kRules.size()),
                              adjacent_before),
              PayloadValidationError::PayloadTooSmall);
    EXPECT_EQ(adjacent_before->total_size, 0U);
    EXPECT_EQ(adjacent_before->version, 0U);
    EXPECT_EQ(adjacent_before->flags, 0U);

    alignas(VersionedPayloadView) std::array<u8, 32> range_storage{};
    range_storage.fill(0xC3);
    auto* overlap_after = reinterpret_cast<VersionedPayloadView*>(range_storage.data() + payload.size());
    EXPECT_EQ(PayloadValidate(range_storage.data(), static_cast<u32>(payload.size() + 1U), kRules.data(),
                              static_cast<u32>(kRules.size()), overlap_after),
              PayloadValidationError::OutputAliasesInput);
    for (u8 byte : range_storage)
        EXPECT_EQ(byte, 0xC3U);

    range_storage.fill(0xD4);
    auto* overlap_before = reinterpret_cast<VersionedPayloadView*>(range_storage.data());
    EXPECT_EQ(PayloadValidate(range_storage.data() + sizeof(VersionedPayloadView) - 1U,
                              static_cast<u32>(payload.size()), kRules.data(), static_cast<u32>(kRules.size()),
                              overlap_before),
              PayloadValidationError::OutputAliasesInput);
    for (u8 byte : range_storage)
        EXPECT_EQ(byte, 0xD4U);

    std::vector<u8> maximum(kVersionedPayloadMaxBytes);
    EXPECT_EQ(PayloadEncodeHeader(maximum.data(), static_cast<u32>(maximum.size()), 7, 0, kRules.data(),
                                  static_cast<u32>(kRules.size())),
              PayloadValidationError::Ok);
    EXPECT_EQ(PayloadValidate(maximum.data(), static_cast<u32>(maximum.size()), kRules.data(),
                              static_cast<u32>(kRules.size()), nullptr),
              PayloadValidationError::Ok);
    std::vector<u8> oversized(static_cast<std::size_t>(kVersionedPayloadMaxBytes) + 1U);
    EXPECT_EQ(PayloadEncodeHeader(oversized.data(), static_cast<u32>(oversized.size()), 7, 0, kRules.data(),
                                  static_cast<u32>(kRules.size())),
              PayloadValidationError::PayloadTooLarge);

    EXPECT_STREQ(PayloadValidationErrorName(PayloadValidationError::InvalidRuleTable), "invalid-rule-table");
    EXPECT_STREQ(PayloadValidationErrorName(PayloadValidationError::OutputAliasesInput), "output-aliases-input");
    EXPECT_STREQ(PayloadValidationErrorName(PayloadValidationError::InputsOverlap), "inputs-overlap");
    static_assert(static_cast<u8>(PayloadValidationError::Ok) == 0);
    static_assert(static_cast<u8>(PayloadValidationError::SizeOutsideVersionRange) == 9);
    static_assert(static_cast<u8>(PayloadValidationError::OutputAliasesInput) == 10);
    static_assert(static_cast<u8>(PayloadValidationError::InputsOverlap) == 11);
    EXPECT_STREQ(PayloadValidationErrorName(static_cast<PayloadValidationError>(0xFF)), "unknown");

    return duetos_host_test::finish_main("test_versioned_payload");
}
