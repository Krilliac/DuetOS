#pragma once

#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — Base64 encode + decode per RFC 4648.
 *
 * Standard alphabet (A-Z a-z 0-9 + /), '=' padding. The URL-safe
 * alphabet (- and _) and the no-padding variant aren't supported
 * in v0; add them if a consumer asks.
 *
 * Decode is strict: any non-alphabet byte that isn't whitespace
 * or a trailing '=' fails the call. Whitespace (space, tab,
 * \r, \n) is silently skipped to make MIME-encoded inputs
 * tolerable.
 *
 * Eventual consumers:
 *   - HTTP Basic auth (`Authorization: Basic <b64>`).
 *   - MIME / RFC 2045 transport.
 *   - Win32 API `CryptStringToBinary` / `CryptBinaryToString`.
 *   - sshd `authorized_keys` parsing if/when an SSH server lands.
 *
 * Buffer-size helpers exist as constexpr so callers can
 * stack-allocate output buffers from the input length without
 * an extra runtime measurement pass.
 */

namespace duetos::util
{

/// Maximum encoded length for an input of `n` bytes (no newlines
/// added — pure base64 with '=' padding). Output is rounded up
/// to the nearest 4 bytes.
constexpr u32 Base64EncodedLen(u32 input_len)
{
    return ((input_len + 2u) / 3u) * 4u;
}

/// Maximum decoded length for an encoded input of `n` characters.
/// Real decoded length is at most this; trailing padding subtracts
/// 1 or 2 from the real value.
constexpr u32 Base64DecodedMaxLen(u32 encoded_len)
{
    return (encoded_len / 4u) * 3u;
}

/// Encode `len` raw bytes into the output buffer. Caller must
/// ensure `out` has `Base64EncodedLen(len)` bytes of capacity.
/// Returns the number of output bytes actually written (always
/// equal to `Base64EncodedLen(len)` on success).
u32 Base64Encode(const u8* in, u32 len, char* out);

/// Decode a base64-encoded string into raw bytes. On success the
/// returned `Result<u32>` carries the decoded length (the number
/// of bytes actually written into `out`). Errors:
///   - `ErrorCode::InvalidArgument` — null `in` or `out`.
///   - `ErrorCode::Corrupt` — invalid character, bad padding
///     configuration, or truncated (non-4-aligned) input.
///   - `ErrorCode::BufferTooSmall` — `out_capacity` is too small
///     for the decoded data.
/// Whitespace inside `in` is silently skipped (MIME tolerance).
::duetos::core::Result<u32> Base64Decode(const char* in, u32 in_len, u8* out, u32 out_capacity);

void Base64SelfTest();

} // namespace duetos::util
