#pragma once

#include "util/types.h"

/*
 * DuetOS — JPEG / JFIF / EXIF header validator.
 *
 * Spec: ISO/IEC 10918-1 (JPEG baseline) + the JFIF / EXIF
 * application-segment conventions.
 *
 * Scope (v0):
 *   - Validate the SOI marker (FFD8) and walk segments until the
 *     first Start-of-Frame (SOF) is found.
 *   - Return dimensions + precision + component count from the
 *     SOF body.
 *
 * Out of scope (deliberate, future slices):
 *   - JPEG decoder. The actual zig-zag / Huffman / DCT /
 *     dequantise / IDCT / colour-space passes are several
 *     thousand lines and we'd want a real consumer (image
 *     viewer, thumbnail cache, wallpaper format extension)
 *     before paying that cost. The header validator that lands
 *     here is the foundation any of those consumers will sit on.
 *   - EXIF tag walking (orientation, GPS, etc.). The validator
 *     hops past APP1 (FFE1) without reading its body.
 *   - JPEG-2000 / JPEG-XL / arithmetic-coded JPEG.
 *
 * Risk surface: a JPEG file may come from disk, network, or a
 * user-mode app. The fixed-size SOI + segment headers are the
 * widest validation surface and the easiest place for a hostile
 * file to inject mis-sized length fields, out-of-range component
 * counts, oversize dimensions, or an SOS-before-SOF ordering
 * confusion. The validation is delegated to the
 * `duetos_img_meta` Rust crate (see
 * `kernel/util/img_meta_rust/src/lib.rs::parse_jpeg_header`).
 *
 * Context: kernel. No allocation, IRQ-safe.
 */

namespace duetos::util
{

/// Parsed result of `JpegParseHeader`. `ok` is false on any
/// rejection (bad SOI, malformed segment length, SOS-before-SOF,
/// unsupported precision / component count, oversize dimensions).
/// `sof_marker` is the actual SOF marker byte the walker matched
/// (0xC0 = baseline DCT, 0xC2 = progressive DCT, etc.) so a
/// future decoder can route by frame type.
struct JpegInfo
{
    u32 width;
    u32 height;
    u8 precision;  // 8 | 12 | 16
    u8 components; // 1 | 3 | 4
    u8 sof_marker; // 0xC0..0xCF excluding 0xC4 / 0xC8 / 0xCC
    bool ok;
};

/// Parse a JPEG-shaped buffer's SOI + first SOF segment. Returns
/// `{ ok=false, ... }` on any malformed input; otherwise fills
/// the dimensions + precision + component count from the SOF
/// body. Reads at most the bytes between offset 0 and the first
/// SOF segment — does not walk past it into the entropy-coded
/// scan data.
JpegInfo JpegParseHeader(const u8* src, u32 src_len);

} // namespace duetos::util
