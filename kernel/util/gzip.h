#pragma once

#include "util/types.h"

/*
 * DuetOS — GZIP (RFC 1952) + zlib (RFC 1950) stream wrappers
 * over the existing DEFLATE inflater (clean room).
 *
 * Both formats wrap a raw DEFLATE bit stream with header bytes
 * + a checksum tail. The DEFLATE inflater is reused verbatim;
 * this TU is just header parse + checksum verify.
 *
 * Eventual consumers:
 *   - kernel-image self-decompression (GZIP-compressed initramfs).
 *   - PNG decoder (zlib-wrapped DEFLATE inside IDAT chunks).
 *   - HTTP `Content-Encoding: gzip` payloads in a future user-mode
 *     HTTP client.
 */

namespace duetos::util
{

/// Decompress a GZIP-wrapped DEFLATE payload. Verifies CRC-32 and
/// uncompressed-size on success. Returns 0 on any malformed
/// header / payload / checksum mismatch / `dst` overflow.
u32 GzipInflate(const u8* src, u32 src_len, u8* dst, u32 dst_cap);

/// Decompress a zlib-wrapped DEFLATE payload. Verifies the
/// trailing big-endian Adler-32 against the recomputed checksum.
u32 ZlibInflate(const u8* src, u32 src_len, u8* dst, u32 dst_cap);

void GzipZlibSelfTest();

} // namespace duetos::util
