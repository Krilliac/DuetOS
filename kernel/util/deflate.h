#pragma once

#include "util/types.h"

/*
 * DuetOS — DEFLATE inflater (RFC 1951, clean room).
 *
 * Decompresses a raw DEFLATE bit stream — type-0 stored, type-1
 * fixed Huffman, type-2 dynamic Huffman — into a caller-provided
 * output buffer. Encoder is deliberately not provided in v0; the
 * project doesn't have a compression consumer that needs to
 * produce DEFLATE bits.
 *
 * Reference implementations consulted *as algorithms only*: Mark
 * Adler's `puff.c` (public domain) and the RFC 1951 prose. No
 * source code copied.
 *
 * Eventual consumers:
 *   - GZIP container (RFC 1952) wraps a DEFLATE bit stream with a
 *     header + CRC32 + uncompressed-length tail.
 *   - zlib container (RFC 1950) wraps a DEFLATE bit stream with a
 *     2-byte header + Adler-32 tail.
 *   - PNG decoder pulls IDAT chunks through a zlib wrapper.
 *
 * Out of scope (deliberate):
 *   - Compression / encoder.
 *   - Streaming over multiple output buffers (the inflater
 *     consumes the full input in one shot).
 *
 * Limits:
 *   - LZ77 window is the full output buffer up to 32 KiB before
 *     the current output position (RFC 1951 §3.2.5 — distance
 *     codes 1..32768).
 *   - Maximum Huffman-code length is 15 bits.
 *
 * No allocation, no global state — every routine works on
 * caller-provided buffers and a fixed-size internal scratch
 * struct (~3 KiB) for Huffman tables.
 */

namespace duetos::util
{

/// Decompress a raw DEFLATE bit stream. `src` is `src_len` bytes
/// of compressed input. `dst` has `dst_cap` bytes available for
/// the decompressed output. On success returns the decompressed
/// byte count. On any malformed input or `dst` overflow returns 0.
u32 DeflateInflate(const u8* src, u32 src_len, u8* dst, u32 dst_cap);

void DeflateSelfTest();

} // namespace duetos::util
