#pragma once

#include "util/types.h"

/*
 * DuetOS — LZ4 raw-block decoder (clean room).
 *
 * Spec: LZ4 block format specification (lz4.org, public domain).
 * This implementation covers the *raw block* layout — each
 * sequence is a token byte followed by optional length-extension
 * bytes, optional literals, optional 2-byte LE offset, optional
 * length extension. The minimum match length is 4 bytes; matches
 * may overlap (copy is byte-by-byte by construction).
 *
 * Out of scope (deliberate v0):
 *   - LZ4 frame format (RFC-style wrapper with magic 0x184D2204
 *     + frame descriptor + block checksums + content checksum).
 *     Frame format is its own porting-candidates row; the raw
 *     block decoder lands first because every existing LZ4
 *     consumer can be plumbed via the block API.
 *   - LZ4HC (high-compression encoder). We are decoder-only in v0.
 *   - LZ4 dictionary mode.
 *
 * Eventual consumers:
 *   - Future kernel image self-decompression (smaller boot image
 *     than gzip's DEFLATE for similar ratios).
 *   - CPIO / TAR archive layers compressed with .lz4.
 *
 * No allocation, no global state.
 */

namespace duetos::util
{

/// Decompress an LZ4 raw block. `src` is `src_len` bytes;
/// `dst` has `dst_cap` bytes available. On success returns the
/// number of bytes written to `dst`. On any malformed input or
/// `dst` overflow returns 0.
u32 Lz4DecompressBlock(const u8* src, u32 src_len, u8* dst, u32 dst_cap);

void Lz4SelfTest();

} // namespace duetos::util
