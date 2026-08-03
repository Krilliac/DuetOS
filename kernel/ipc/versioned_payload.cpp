#include "ipc/versioned_payload.h"

namespace duetos::ipc
{

namespace
{

constexpr u32 kTotalSizeOffset = 0;
constexpr u32 kVersionOffset = 4;
constexpr u32 kFlagsOffset = 6;

bool PointerRangesOverlap(const void* left, u32 left_bytes, const void* right, u32 right_bytes)
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

bool RuleTableIsValid(const PayloadVersionRule* rules, u32 rule_count)
{
    if (rules == nullptr || rule_count == 0 || rule_count > kVersionedPayloadMaxRules)
        return false;

    u16 previous_version = 0;
    for (u32 index = 0; index < rule_count; ++index)
    {
        const PayloadVersionRule& rule = rules[index];
        if (rule.version == 0 || rule.version <= previous_version)
            return false;
        if (rule.minimum_size < kVersionedPayloadHeaderBytes || rule.maximum_size < rule.minimum_size ||
            rule.maximum_size > kVersionedPayloadMaxBytes)
        {
            return false;
        }
        previous_version = rule.version;
    }
    return true;
}

const PayloadVersionRule* FindRule(const PayloadVersionRule* rules, u32 rule_count, u16 version)
{
    // Generated tables are sorted, so lookup cost remains logarithmic even at
    // the defensive maximum table size.
    u32 first = 0;
    u32 count = rule_count;
    while (count != 0)
    {
        const u32 step = count / 2;
        const u32 index = first + step;
        if (rules[index].version < version)
        {
            first = index + 1;
            count -= step + 1;
        }
        else
        {
            count = step;
        }
    }

    if (first < rule_count && rules[first].version == version)
        return &rules[first];
    return nullptr;
}

PayloadValidationError ValidateAgainstRule(u32 total_size, u16 flags, const PayloadVersionRule& rule)
{
    if ((flags & static_cast<u16>(~rule.known_flags)) != 0)
        return PayloadValidationError::UnsupportedFlags;
    if (total_size < rule.minimum_size || total_size > rule.maximum_size)
        return PayloadValidationError::SizeOutsideVersionRange;
    return PayloadValidationError::Ok;
}

} // namespace

PayloadValidationError PayloadEncodeHeader(void* buffer, u32 buffer_bytes, u16 version, u16 flags,
                                           const PayloadVersionRule* rules, u32 rule_count)
{
    if (buffer == nullptr)
        return PayloadValidationError::NullBuffer;
    if (buffer_bytes < kVersionedPayloadHeaderBytes)
        return PayloadValidationError::PayloadTooSmall;
    if (buffer_bytes > kVersionedPayloadMaxBytes)
        return PayloadValidationError::PayloadTooLarge;
    if (!RuleTableIsValid(rules, rule_count))
        return PayloadValidationError::InvalidRuleTable;

    const PayloadVersionRule* matched_rule = FindRule(rules, rule_count, version);
    if (matched_rule == nullptr)
        return PayloadValidationError::UnsupportedVersion;

    // Copy the rule before any store.  Generated encoders normally keep rules
    // in read-only memory, but permitting overlap makes scratch-buffer usage
    // deterministic and prevents a subtle post-validation alias hazard.
    const PayloadVersionRule canonical_rule = *matched_rule;
    const PayloadValidationError semantic_error = ValidateAgainstRule(buffer_bytes, flags, canonical_rule);
    if (semantic_error != PayloadValidationError::Ok)
        return semantic_error;

    auto* bytes = static_cast<u8*>(buffer);
    WriteLe32(bytes + kTotalSizeOffset, buffer_bytes);
    WriteLe16(bytes + kVersionOffset, version);
    WriteLe16(bytes + kFlagsOffset, flags);
    return PayloadValidationError::Ok;
}

PayloadValidationError PayloadValidate(const void* buffer, u32 available_bytes, const PayloadVersionRule* rules,
                                       u32 rule_count, VersionedPayloadView* view_out)
{
    // An excessive count cannot establish a trustworthy input extent.  Reject
    // it before writing view_out rather than guessing a range and potentially
    // clobbering aliased policy metadata on this error path.
    if (rule_count > kVersionedPayloadMaxRules)
        return PayloadValidationError::InvalidRuleTable;

    const u32 rule_bytes = rule_count * static_cast<u32>(sizeof(PayloadVersionRule));
    if (PointerRangesOverlap(buffer, available_bytes, view_out, static_cast<u32>(sizeof(*view_out))) ||
        PointerRangesOverlap(rules, rule_bytes, view_out, static_cast<u32>(sizeof(*view_out))))
    {
        return PayloadValidationError::OutputAliasesInput;
    }
    if (PointerRangesOverlap(buffer, available_bytes, rules, rule_bytes))
        return PayloadValidationError::InputsOverlap;

    if (view_out != nullptr)
        *view_out = {};
    if (buffer == nullptr)
        return PayloadValidationError::NullBuffer;
    if (available_bytes < kVersionedPayloadHeaderBytes)
        return PayloadValidationError::TruncatedHeader;
    if (available_bytes > kVersionedPayloadMaxBytes)
        return PayloadValidationError::PayloadTooLarge;
    if (!RuleTableIsValid(rules, rule_count))
        return PayloadValidationError::InvalidRuleTable;

    const auto* bytes = static_cast<const u8*>(buffer);
    const u32 total_size = ReadLe32(bytes + kTotalSizeOffset);
    if (total_size < kVersionedPayloadHeaderBytes)
        return PayloadValidationError::PayloadTooSmall;
    if (total_size > kVersionedPayloadMaxBytes)
        return PayloadValidationError::PayloadTooLarge;
    if (total_size != available_bytes)
        return PayloadValidationError::SizeMismatch;

    const u16 version = ReadLe16(bytes + kVersionOffset);
    const PayloadVersionRule* matched_rule = FindRule(rules, rule_count, version);
    if (matched_rule == nullptr)
        return PayloadValidationError::UnsupportedVersion;

    const u16 flags = ReadLe16(bytes + kFlagsOffset);
    const PayloadValidationError semantic_error = ValidateAgainstRule(total_size, flags, *matched_rule);
    if (semantic_error != PayloadValidationError::Ok)
        return semantic_error;

    if (view_out != nullptr)
        *view_out = VersionedPayloadView{total_size, version, flags};
    return PayloadValidationError::Ok;
}

const char* PayloadValidationErrorName(PayloadValidationError error)
{
    switch (error)
    {
    case PayloadValidationError::Ok:
        return "ok";
    case PayloadValidationError::NullBuffer:
        return "null-buffer";
    case PayloadValidationError::InvalidRuleTable:
        return "invalid-rule-table";
    case PayloadValidationError::TruncatedHeader:
        return "truncated-header";
    case PayloadValidationError::PayloadTooSmall:
        return "payload-too-small";
    case PayloadValidationError::PayloadTooLarge:
        return "payload-too-large";
    case PayloadValidationError::SizeMismatch:
        return "size-mismatch";
    case PayloadValidationError::UnsupportedVersion:
        return "unsupported-version";
    case PayloadValidationError::UnsupportedFlags:
        return "unsupported-flags";
    case PayloadValidationError::SizeOutsideVersionRange:
        return "size-outside-version-range";
    case PayloadValidationError::OutputAliasesInput:
        return "output-aliases-input";
    case PayloadValidationError::InputsOverlap:
        return "inputs-overlap";
    }
    return "unknown";
}

} // namespace duetos::ipc
