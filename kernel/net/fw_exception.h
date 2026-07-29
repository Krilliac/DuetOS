#pragma once

#include "util/types.h"

/*
 * DuetOS firewall exceptions — textual spec parsing.
 *
 * Header-only and freestanding for the same reason as
 * `security/exception_id.h`: this is the part that decides which
 * traffic an operator vouched for, so it is worth testing directly
 * (`tests/host/test_fw_exception.cpp`) rather than only by booting.
 *
 * Spec grammar (one exception per spec, ':'-separated):
 *
 *     <dir> ':' <proto> ':' <addr> '/' <mask_bits> ':' <port>
 *
 *     dir    "in" | "out"
 *     proto  "any" | "icmp" | "tcp" | "udp"
 *     addr   dotted quad, e.g. 10.0.2.2
 *     mask   0..32; 0 matches any address
 *     port   decimal 0..65535, or "*" for any port
 *
 * Examples:
 *     in:tcp:10.0.2.2/32:8080     accept inbound TCP to local port 8080 from that host
 *     out:udp:0.0.0.0/0:53        permit outbound DNS to anywhere
 *     in:icmp:192.168.1.0/24:*    accept inbound ping from the LAN
 *
 * `addr` is the PEER: the source for an ingress exception, the
 * destination for an egress one. `port` is the destination port in
 * both directions, which is the field that identifies the service
 * being reached — the ephemeral source port is not something an
 * operator can usefully pin.
 *
 * The parser is strict. A malformed spec is rejected outright rather
 * than partially applied: a half-understood firewall exception is a
 * hole of unknown shape, which is worse than no exception at all.
 *
 * Context: any. Pure function over a caller-supplied buffer.
 */

namespace duetos::net::firewall
{

/// Wire-independent parsed form. Deliberately not `Rule` — this
/// header stays freestanding, and `firewall.h` pulls in the network
/// stack. `firewall.cpp` translates a spec into a `Rule`.
struct ExceptionSpec
{
    bool egress;   // false = ingress
    u8 proto;      // 0 any, 1 icmp, 6 tcp, 17 udp (matches Proto)
    u8 addr[4];    // peer address, network order (addr[0] = first octet)
    u8 mask_bits;  // 0..32
    bool any_port; // true => port field was "*"
    u16 port;      // destination port when !any_port
};

namespace detail
{

/// Parse a decimal number from `[s, s+len)`. The whole field must be
/// digits; an empty field, a non-digit, or a value above `max` all
/// fail. No overflow: the running value is bounded against `max`
/// before each multiply.
constexpr bool ParseDecimal(const char* s, u32 len, u32 max, u32* out)
{
    if (s == nullptr || len == 0 || len > 5)
        return false;
    u32 v = 0;
    for (u32 i = 0; i < len; ++i)
    {
        if (s[i] < '0' || s[i] > '9')
            return false;
        v = v * 10 + static_cast<u32>(s[i] - '0');
        if (v > max)
            return false;
    }
    *out = v;
    return true;
}

/// Compare `[s, s+len)` against a NUL-terminated literal.
constexpr bool FieldEquals(const char* s, u32 len, const char* lit)
{
    u32 i = 0;
    for (; i < len; ++i)
    {
        if (lit[i] == '\0' || s[i] != lit[i])
            return false;
    }
    return lit[i] == '\0';
}

/// Split `[s, s+len)` on ':' and return field `index`.
constexpr bool ColonField(const char* s, u32 len, u32 index, const char** out, u32* out_len)
{
    u32 field = 0;
    u32 start = 0;
    for (u32 i = 0; i <= len; ++i)
    {
        if (i != len && s[i] != ':')
            continue;
        if (field == index)
        {
            *out = s + start;
            *out_len = i - start;
            return true;
        }
        ++field;
        start = i + 1;
    }
    return false;
}

constexpr u32 ColonFieldCount(const char* s, u32 len)
{
    u32 n = 1;
    for (u32 i = 0; i < len; ++i)
    {
        if (s[i] == ':')
            ++n;
    }
    return n;
}

/// Parse "A.B.C.D/bits" into four octets plus a mask width.
constexpr bool ParseCidr(const char* s, u32 len, u8 addr[4], u8* mask_bits)
{
    // Locate the '/'. Exactly one is required.
    u32 slash = len;
    for (u32 i = 0; i < len; ++i)
    {
        if (s[i] != '/')
            continue;
        if (slash != len)
            return false; // second slash
        slash = i;
    }
    if (slash == len)
        return false;

    u32 mask = 0;
    if (!ParseDecimal(s + slash + 1, len - slash - 1, 32, &mask))
        return false;

    // Four dot-separated octets in the region before the slash.
    u32 octet = 0;
    u32 start = 0;
    for (u32 i = 0; i <= slash; ++i)
    {
        if (i != slash && s[i] != '.')
            continue;
        if (octet >= 4)
            return false;
        u32 v = 0;
        if (!ParseDecimal(s + start, i - start, 255, &v))
            return false;
        addr[octet++] = static_cast<u8>(v);
        start = i + 1;
    }
    if (octet != 4)
        return false;

    *mask_bits = static_cast<u8>(mask);
    return true;
}

} // namespace detail

/// Parse one exception spec. Returns false and leaves `*out`
/// untouched on any malformed input.
constexpr bool ParseExceptionSpec(const char* s, u32 len, ExceptionSpec* out)
{
    if (s == nullptr || out == nullptr || len == 0)
        return false;
    if (detail::ColonFieldCount(s, len) != 4)
        return false;

    const char* f = nullptr;
    u32 flen = 0;
    ExceptionSpec spec{};

    // dir
    if (!detail::ColonField(s, len, 0, &f, &flen))
        return false;
    if (detail::FieldEquals(f, flen, "in"))
        spec.egress = false;
    else if (detail::FieldEquals(f, flen, "out"))
        spec.egress = true;
    else
        return false;

    // proto
    if (!detail::ColonField(s, len, 1, &f, &flen))
        return false;
    if (detail::FieldEquals(f, flen, "any"))
        spec.proto = 0;
    else if (detail::FieldEquals(f, flen, "icmp"))
        spec.proto = 1;
    else if (detail::FieldEquals(f, flen, "tcp"))
        spec.proto = 6;
    else if (detail::FieldEquals(f, flen, "udp"))
        spec.proto = 17;
    else
        return false;

    // addr/mask
    if (!detail::ColonField(s, len, 2, &f, &flen))
        return false;
    if (!detail::ParseCidr(f, flen, spec.addr, &spec.mask_bits))
        return false;

    // port
    if (!detail::ColonField(s, len, 3, &f, &flen))
        return false;
    if (detail::FieldEquals(f, flen, "*"))
    {
        spec.any_port = true;
        spec.port = 0;
    }
    else
    {
        u32 p = 0;
        if (!detail::ParseDecimal(f, flen, 65535, &p))
            return false;
        spec.any_port = false;
        spec.port = static_cast<u16>(p);
    }

    // ICMP has no ports; an explicit port on an ICMP spec is a
    // misunderstanding the parser should surface rather than
    // silently drop.
    if (spec.proto == 1 && !spec.any_port)
        return false;

    *out = spec;
    return true;
}

} // namespace duetos::net::firewall
