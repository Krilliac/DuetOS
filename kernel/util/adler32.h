#pragma once

#include "util/types.h"

/*
 * DuetOS — Adler-32 checksum (RFC 1950 §9, clean room).
 *
 * Adler-32 is the corruption-detection checksum used by every
 * zlib-wrapped DEFLATE stream. It's faster than CRC-32 to
 * compute and detects single-byte corruption with the same
 * worst-case ratio for the lengths zlib actually carries
 * (≤ 64 KB chunks). zlib stream readers refuse to accept any
 * payload whose Adler-32 doesn't match, so a clean-room zlib
 * implementation needs this primitive.
 *
 * Algorithm:
 *
 *   a = 1
 *   b = 0
 *   for each byte v:
 *     a = (a + v) mod 65521
 *     b = (b + a) mod 65521
 *   return (b << 16) | a
 *
 * 65521 is the largest prime ≤ 2^16. Modular reduction can be
 * deferred for ~5552 bytes before a + b overflows 32 bits — we
 * use that block-amortized form for speed.
 */

namespace duetos::util
{

inline constexpr u32 kAdler32Base = 65521u;
inline constexpr u32 kAdler32MaxRunBytes = 5552u;

/// Compute Adler-32 over `data` (`len` bytes). Returns the
/// 32-bit checksum (high 16 bits = b, low 16 bits = a).
u32 Adler32(const u8* data, u32 len);

/// Streaming flavour: combine a partial checksum with the
/// continuation of the same stream. `prev` is the result of
/// `Adler32` over the prior bytes; this call extends it with
/// `len` more.
u32 Adler32Update(u32 prev, const u8* data, u32 len);

void Adler32SelfTest();

} // namespace duetos::util
