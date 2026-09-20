#pragma once

#include "net/stack.h"

namespace duetos::net
{

inline bool ParseIpv4Range(const char* begin, const char* end, Ipv4Address* out)
{
    if (begin == nullptr || end == nullptr || out == nullptr || begin >= end)
        return false;

    Ipv4Address parsed{};
    u32 octet_index = 0;
    u32 value = 0;
    bool had_digit = false;
    for (const char* cursor = begin; cursor != end; ++cursor)
    {
        const char c = *cursor;
        if (c == '.')
        {
            if (!had_digit || octet_index >= 3)
                return false;
            parsed.octets[octet_index++] = static_cast<u8>(value);
            value = 0;
            had_digit = false;
            continue;
        }
        if (c < '0' || c > '9')
            return false;
        value = value * 10 + static_cast<u32>(c - '0');
        if (value > 255)
            return false;
        had_digit = true;
    }
    if (!had_digit || octet_index != 3)
        return false;
    parsed.octets[3] = static_cast<u8>(value);
    *out = parsed;
    return true;
}

inline bool ParseIpv4Exact(const char* text, Ipv4Address* out)
{
    if (text == nullptr)
        return false;
    const char* end = text;
    while (*end != '\0')
        ++end;
    return ParseIpv4Range(text, end, out);
}

constexpr u32 Ipv4AddressValue(Ipv4Address address)
{
    return (static_cast<u32>(address.octets[0]) << 24) | (static_cast<u32>(address.octets[1]) << 16) |
           (static_cast<u32>(address.octets[2]) << 8) | static_cast<u32>(address.octets[3]);
}

constexpr bool Ipv4AddressEqual(Ipv4Address left, Ipv4Address right)
{
    return Ipv4AddressValue(left) == Ipv4AddressValue(right);
}

constexpr bool Ipv4AddressIsZero(Ipv4Address address)
{
    return Ipv4AddressValue(address) == 0;
}

constexpr bool Ipv4AddressIsUsableUnicast(Ipv4Address address)
{
    const u8 first = address.octets[0];
    return first != 0 && first != 127 && first < 224;
}

constexpr u32 Ipv4PrefixMask(u8 prefix_length)
{
    return prefix_length == 0 || prefix_length > 32 ? 0 : 0xFFFFFFFFu << (32 - prefix_length);
}

constexpr bool Ipv4AddressSameSubnet(Ipv4Address left, Ipv4Address right, u8 prefix_length)
{
    if (prefix_length > 32)
        return false;
    const u32 mask = Ipv4PrefixMask(prefix_length);
    return (Ipv4AddressValue(left) & mask) == (Ipv4AddressValue(right) & mask);
}

constexpr bool Ipv4AddressIsUsableHost(Ipv4Address address, u8 prefix_length)
{
    if (!Ipv4AddressIsUsableUnicast(address) || prefix_length == 0 || prefix_length > 32)
        return false;
    if (prefix_length >= 31)
        return true;
    const u32 host_mask = ~Ipv4PrefixMask(prefix_length);
    const u32 host = Ipv4AddressValue(address) & host_mask;
    return host != 0 && host != host_mask;
}

inline bool Ipv4PrefixLengthFromMask(Ipv4Address mask, u8* out_prefix_length)
{
    if (out_prefix_length == nullptr)
        return false;
    const u32 value = Ipv4AddressValue(mask);
    bool saw_zero = false;
    u8 prefix_length = 0;
    for (u32 bit_index = 0; bit_index < 32; ++bit_index)
    {
        const bool set = (value & (u32{1} << (31 - bit_index))) != 0;
        if (set)
        {
            if (saw_zero)
                return false;
            ++prefix_length;
        }
        else
        {
            saw_zero = true;
        }
    }
    *out_prefix_length = prefix_length;
    return true;
}

} // namespace duetos::net
