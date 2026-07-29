#pragma once

#include "util/types.h"

/*
 * DuetOS security exceptions — identity encoding + boot-token parsing.
 *
 * Header-only and freestanding on purpose: this is the logic that
 * decides WHICH image an operator vouched for, so it is the part
 * worth testing directly rather than by booting a kernel. The
 * hosted tests in `tests/host/test_exception_id.cpp` include this
 * file unmodified.
 *
 * Identity model
 * --------------
 * An exception is scoped to the SHA-256 digest of the image bytes,
 * never to its path. A path is a label, not an identity: dropping a
 * different `UNITYPLA.DLL` at the same path must NOT inherit the
 * previous file's exception. The digest is what the guard already
 * computes in `Gate()`, so scoping to it costs nothing extra and
 * closes the file-substitution hole a path-keyed list would open.
 *
 * Boot tokens
 * -----------
 * `CmdlineFindNthValue` extracts the value of the n-th occurrence of
 * a whitespace-delimited `key=value` token. The kernel's existing
 * `core::CmdlineMatches` answers only "does key equal want", which
 * cannot express "seed these three digests" — hence the separate,
 * repeatable scanner here. It is deliberately generic: the guard
 * uses it for `guard-allow=`, the firewall for `fw-allow=`.
 *
 * Context: any. Pure functions over caller-supplied buffers — no
 * allocation, no globals, no kernel state. Safe from IRQ context.
 */

namespace duetos::security
{

inline constexpr u32 kImageDigestBytes = 32;
inline constexpr u32 kImageDigestHexChars = kImageDigestBytes * 2;

/// One hex digit -> 0..15, or -1 for any non-hex character.
/// Accepts both cases.
constexpr i32 HexNibble(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/// Parse exactly `kImageDigestHexChars` hex characters from the
/// front of `s` into a 32-byte digest.
///
/// Requires `len >= kImageDigestHexChars` and rejects a longer run
/// of hex — a 65-hex-character field is a typo, not a digest with a
/// trailing character, and silently truncating it would let a
/// mistyped token vouch for an image the operator never saw. Any
/// non-hex byte at position 64 (line feed, comma, NUL, space) is
/// the normal terminator and is accepted.
///
/// Returns false without touching `out` on any malformed input.
constexpr bool ParseHexDigest(const char* s, u64 len, u8 out[kImageDigestBytes])
{
    if (s == nullptr || len < kImageDigestHexChars)
        return false;

    // Reject an over-long hex run before writing anything.
    if (len > kImageDigestHexChars && HexNibble(s[kImageDigestHexChars]) >= 0)
        return false;

    u8 staging[kImageDigestBytes] = {};
    for (u32 i = 0; i < kImageDigestBytes; ++i)
    {
        const i32 hi = HexNibble(s[2 * i]);
        const i32 lo = HexNibble(s[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return false;
        staging[i] = static_cast<u8>((hi << 4) | lo);
    }
    for (u32 i = 0; i < kImageDigestBytes; ++i)
        out[i] = staging[i];
    return true;
}

/// Render a digest as `kImageDigestHexChars` lowercase hex
/// characters. Does NOT NUL-terminate — callers that want a C
/// string size the buffer at kImageDigestHexChars + 1 and set the
/// terminator themselves.
constexpr void FormatHexDigest(const u8 in[kImageDigestBytes], char out[kImageDigestHexChars])
{
    for (u32 i = 0; i < kImageDigestBytes; ++i)
    {
        const u8 hi = static_cast<u8>(in[i] >> 4);
        const u8 lo = static_cast<u8>(in[i] & 0xF);
        out[2 * i] = static_cast<char>(hi < 10 ? '0' + hi : 'a' + hi - 10);
        out[2 * i + 1] = static_cast<char>(lo < 10 ? '0' + lo : 'a' + lo - 10);
    }
}

/// Constant-length digest compare. Not constant-time, and it does
/// not need to be: an allowlist is public configuration, not a
/// secret, so there is no digest to recover by timing the miss.
constexpr bool DigestEqual(const u8 a[kImageDigestBytes], const u8 b[kImageDigestBytes])
{
    for (u32 i = 0; i < kImageDigestBytes; ++i)
    {
        if (a[i] != b[i])
            return false;
    }
    return true;
}

namespace detail
{

constexpr bool IsCmdlineSpace(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

constexpr u64 TokenLen(const char* s)
{
    u64 n = 0;
    while (s[n] != '\0')
        ++n;
    return n;
}

} // namespace detail

/// Find the value of the `n`-th (0-based) whitespace-delimited
/// `key=value` token in `cmdline`.
///
/// On success writes a pointer to the first character after the '='
/// and the value's length (up to the next whitespace or the string
/// end) and returns true. `key` must not contain '=' or whitespace.
///
/// A `key=` token with an empty value matches with `*len_out == 0`;
/// callers treat that as "operator wrote the token but gave nothing"
/// and should warn rather than silently ignoring it.
///
/// A nullptr cmdline or a key that never appears returns false.
constexpr bool CmdlineFindNthValue(const char* cmdline, const char* key, u32 n, const char** val_out, u32* len_out)
{
    if (cmdline == nullptr || key == nullptr || key[0] == '\0')
        return false;
    const u64 klen = detail::TokenLen(key);

    u32 seen = 0;
    u64 i = 0;
    while (cmdline[i] != '\0')
    {
        // Skip separators, then measure this token.
        while (cmdline[i] != '\0' && detail::IsCmdlineSpace(cmdline[i]))
            ++i;
        if (cmdline[i] == '\0')
            break;
        const u64 tok_start = i;
        while (cmdline[i] != '\0' && !detail::IsCmdlineSpace(cmdline[i]))
            ++i;
        const u64 tok_len = i - tok_start;

        // Token must be exactly `key` followed by '='.
        if (tok_len <= klen || cmdline[tok_start + klen] != '=')
            continue;
        bool key_matches = true;
        for (u64 k = 0; k < klen; ++k)
        {
            if (cmdline[tok_start + k] != key[k])
            {
                key_matches = false;
                break;
            }
        }
        if (!key_matches)
            continue;

        if (seen == n)
        {
            if (val_out != nullptr)
                *val_out = cmdline + tok_start + klen + 1;
            if (len_out != nullptr)
                *len_out = static_cast<u32>(tok_len - klen - 1);
            return true;
        }
        ++seen;
    }
    return false;
}

/// Number of `key=` tokens present in `cmdline`.
constexpr u32 CmdlineCountKey(const char* cmdline, const char* key)
{
    u32 n = 0;
    while (CmdlineFindNthValue(cmdline, key, n, nullptr, nullptr))
        ++n;
    return n;
}

/// Split `[s, s+len)` on ',' and hand back field `index`.
/// Empty fields are preserved (so "a,,b" has three fields) — the
/// caller decides whether an empty field is an error.
constexpr bool CsvField(const char* s, u32 len, u32 index, const char** field_out, u32* field_len_out)
{
    if (s == nullptr)
        return false;
    u32 field = 0;
    u32 start = 0;
    for (u32 i = 0; i <= len; ++i)
    {
        const bool at_end = (i == len);
        if (!at_end && s[i] != ',')
            continue;
        if (field == index)
        {
            if (field_out != nullptr)
                *field_out = s + start;
            if (field_len_out != nullptr)
                *field_len_out = i - start;
            return true;
        }
        ++field;
        start = i + 1;
    }
    return false;
}

/// Number of comma-separated fields in `[s, s+len)`. Zero-length
/// input has zero fields; every other input has at least one.
constexpr u32 CsvFieldCount(const char* s, u32 len)
{
    if (s == nullptr || len == 0)
        return 0;
    u32 n = 1;
    for (u32 i = 0; i < len; ++i)
    {
        if (s[i] == ',')
            ++n;
    }
    return n;
}

} // namespace duetos::security
