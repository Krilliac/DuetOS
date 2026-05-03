#pragma once

#include "util/types.h"

/*
 * DuetOS — PNG decoder (RFC 2083 / W3C PNG 2nd Ed., clean room).
 *
 * Decodes the colour-types DuetOS actually consumes:
 *   - colour-type 2 (truecolour, RGB) at bit_depth 8.
 *   - colour-type 6 (truecolour + alpha, RGBA) at bit_depth 8.
 *
 * The decoder is built on the existing kernel utilities:
 *   - util/crc32 — every chunk carries a CRC32 trailer (validated).
 *   - util/gzip::ZlibInflate — every IDAT bitstream is wrapped in
 *     zlib (Adler-32-validated DEFLATE).
 *   - util/deflate — invoked indirectly via ZlibInflate.
 *
 * Eventual consumer: kernel/apps/imageview now dispatches `.PNG`
 * alongside the existing `.BMP` and `.TGA` paths. This is the
 * consumer that finally justifies util/deflate, util/gzip, and
 * util/adler32 living in the tree at all.
 *
 * Out of scope (deliberate v0):
 *   - Other colour types: 0 (grayscale), 3 (palette/PLTE),
 *     4 (grayscale+alpha). Add only if a target file lands.
 *   - Bit depths other than 8.
 *   - Interlaced PNGs (Adam7 — historical, basically unused
 *     since the 2010s).
 *   - tRNS / gAMA / sRGB / iCCP and other ancillary chunks
 *     beyond IHDR / IDAT / IEND. Walked past tolerantly.
 *
 * No allocation, no global state — caller provides a scratch
 * buffer for the concatenated IDAT bytes and the decompressed
 * filtered scanlines.
 */

namespace duetos::util
{

inline constexpr u32 kPngSignatureBytes = 8;

struct PngInfo
{
    u32 width;
    u32 height;
    u8 bit_depth;
    u8 color_type;
    bool ok;
};

/// Parse the 8-byte signature + IHDR chunk at `src` (`src_len`
/// bytes). Returns `info.ok = false` on any of: short buffer,
/// bad signature, missing IHDR, IHDR CRC mismatch, or an
/// unsupported subformat (anything other than 8-bit RGB / RGBA,
/// non-interlaced).
PngInfo PngParseHeader(const u8* src, u32 src_len);

/// Decode a PNG file in `src` (`src_len` bytes). On success
/// writes `info.width × info.height` BGRA8888 u32 elements to
/// `out_pixels` (caller must size for `width × height` u32).
///
/// `scratch` is used for two intermediate buffers — concatenated
/// IDAT bytes and the decompressed filtered scanlines. The
/// caller-supplied capacity must hold both:
///     `scratch_cap >= sum(IDAT chunk lengths) +
///                     (width * bytes_per_pixel + 1) * height`
/// where `bytes_per_pixel` is 3 (RGB) or 4 (RGBA). A simple
/// upper bound: `scratch_cap >= src_len + (width * 4 + 1) * height`.
///
/// Returns true on success. Returns false on chunk-CRC mismatch,
/// zlib failure, scratch overflow, or any malformed input.
bool PngDecode(const u8* src, u32 src_len, const PngInfo& info, u8* scratch, u32 scratch_cap, u32* out_pixels);

void PngSelfTest();

} // namespace duetos::util
