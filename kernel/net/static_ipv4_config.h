#pragma once

#include "net/ipv4_parse.h"

namespace duetos::net
{

enum class StaticIpv4ParseStatus : u8
{
    Absent,
    Valid,
    Invalid,
};

struct StaticIpv4Config
{
    u32 iface_index = 0;
    Ipv4Address address{};
    u8 prefix_length = 0;
    Ipv4Address gateway{};
    Ipv4Address dns{};
    bool gateway_set = false;
    bool dns_set = false;
};

struct StaticIpv4ParseResult
{
    StaticIpv4ParseStatus status = StaticIpv4ParseStatus::Absent;
    StaticIpv4Config config{};
};

namespace static_ipv4_detail
{

inline bool TokenValue(const char* begin, const char* end, const char* key, const char** out_value)
{
    const char* cursor = begin;
    const char* key_cursor = key;
    while (*key_cursor != '\0' && cursor != end && *cursor == *key_cursor)
    {
        ++cursor;
        ++key_cursor;
    }
    if (*key_cursor != '\0' || cursor == end || *cursor != '=')
        return false;
    *out_value = cursor + 1;
    return true;
}

inline bool ParsePrefix(const char* begin, const char* end, u8* out_prefix)
{
    if (begin == end || out_prefix == nullptr)
        return false;
    u32 value = 0;
    for (const char* cursor = begin; cursor != end; ++cursor)
    {
        if (*cursor < '0' || *cursor > '9')
            return false;
        value = value * 10 + static_cast<u32>(*cursor - '0');
        if (value > 32)
            return false;
    }
    if (value == 0)
        return false;
    *out_prefix = static_cast<u8>(value);
    return true;
}

inline bool ParseInterfaceIndex(const char* begin, const char* end, u32* out_index)
{
    if (begin == end || out_index == nullptr)
        return false;
    u32 value = 0;
    for (const char* cursor = begin; cursor != end; ++cursor)
    {
        if (*cursor < '0' || *cursor > '9')
            return false;
        value = value * 10 + static_cast<u32>(*cursor - '0');
        if (value >= kMaxNetInterfaces)
            return false;
    }
    *out_index = value;
    return true;
}

inline bool ParseAddressAndPrefix(const char* begin, const char* end, Ipv4Address* out_address, u8* out_prefix)
{
    const char* slash = nullptr;
    for (const char* cursor = begin; cursor != end; ++cursor)
    {
        if (*cursor != '/')
            continue;
        if (slash != nullptr)
            return false;
        slash = cursor;
    }
    if (slash == nullptr || slash == begin || slash + 1 == end || !ParseIpv4Range(begin, slash, out_address) ||
        !ParsePrefix(slash + 1, end, out_prefix))
        return false;
    return Ipv4AddressIsUsableHost(*out_address, *out_prefix);
}

} // namespace static_ipv4_detail

inline StaticIpv4ParseResult ParseStaticIpv4Config(const char* cmdline)
{
    if (cmdline == nullptr || *cmdline == '\0')
        return {};

    StaticIpv4Config config{};
    bool static_seen = false;
    bool iface_seen = false;
    bool gateway_seen = false;
    bool dns_seen = false;
    const char* cursor = cmdline;
    while (*cursor != '\0')
    {
        while (*cursor == ' ' || *cursor == '\t')
            ++cursor;
        if (*cursor == '\0')
            break;
        const char* begin = cursor;
        while (*cursor != '\0' && *cursor != ' ' && *cursor != '\t')
            ++cursor;
        const char* end = cursor;
        const char* value = nullptr;
        if (static_ipv4_detail::TokenValue(begin, end, "net.static", &value))
        {
            if (static_seen ||
                !static_ipv4_detail::ParseAddressAndPrefix(value, end, &config.address, &config.prefix_length))
                return {StaticIpv4ParseStatus::Invalid, {}};
            static_seen = true;
        }
        else if (static_ipv4_detail::TokenValue(begin, end, "net.static-iface", &value))
        {
            if (iface_seen || !static_ipv4_detail::ParseInterfaceIndex(value, end, &config.iface_index))
                return {StaticIpv4ParseStatus::Invalid, {}};
            iface_seen = true;
        }
        else if (static_ipv4_detail::TokenValue(begin, end, "net.gateway", &value))
        {
            if (gateway_seen || !ParseIpv4Range(value, end, &config.gateway) ||
                !Ipv4AddressIsUsableUnicast(config.gateway))
                return {StaticIpv4ParseStatus::Invalid, {}};
            gateway_seen = true;
            config.gateway_set = true;
        }
        else if (static_ipv4_detail::TokenValue(begin, end, "net.dns", &value))
        {
            if (dns_seen || !ParseIpv4Range(value, end, &config.dns) || !Ipv4AddressIsUsableUnicast(config.dns))
                return {StaticIpv4ParseStatus::Invalid, {}};
            dns_seen = true;
            config.dns_set = true;
        }
    }

    if (!static_seen)
        return iface_seen || gateway_seen || dns_seen ? StaticIpv4ParseResult{StaticIpv4ParseStatus::Invalid, {}}
                                                      : StaticIpv4ParseResult{};
    if (gateway_seen && (!Ipv4AddressSameSubnet(config.address, config.gateway, config.prefix_length) ||
                         !Ipv4AddressIsUsableHost(config.gateway, config.prefix_length) ||
                         Ipv4AddressEqual(config.address, config.gateway)))
        return {StaticIpv4ParseStatus::Invalid, {}};
    return {StaticIpv4ParseStatus::Valid, config};
}

} // namespace duetos::net
