#pragma once

#include "util/types.h"

/*
 * DuetOS — JPEG / JFIF / EXIF header validator + Baseline decoder.
 *
 * Spec: ISO/IEC 10918-1 (JPEG baseline) + the JFIF / EXIF
 * application-segment conventions.
 *
 * Scope:
 *   - Validate the SOI marker (FFD8) and walk segments until the
 *     first Start-of-Frame (SOF) is found. (`JpegParseHeader`)
 *   - Decode Baseline-DCT (SOF0) JPEGs into a packed 32-bit
 *     pixel buffer. (`JpegDecode`)
 *
 * Out of scope (deliberate, future slices):
 *   - Progressive JPEGs (SOF2). Detected by JpegParseHeader's
 *     `sof_marker` field; JpegDecode rejects them.
 *   - Arithmetic-coded JPEGs (SOF9–SOFE). Same rejection path.
 *   - JPEG-2000 / JPEG-XL.
 *   - EXIF tag walking (orientation, GPS, etc.).
 *   - 12-bit / 16-bit precision. Caller-side dimension cap +
 *     decoder rejects precision != 8.
 *
 * Risk surface: a JPEG file may come from disk, network, or a
 * user-mode app. Both the header walker (via Rust img_meta) and
 * the decoder validate every length field, run-length, and
 * coefficient index before dereferencing. The decoder also runs
 * with hard scratch / pixel-buffer caps so a hostile file can't
 * exhaust memory.
 *
 * Studied ISO/IEC 10918-1 + the standard JFIF specification for
 * the marker grammar, Huffman-table layout, MCU iteration shape,
 * and IDCT formula. No code copied from any prior implementation.
 *
 * Context: kernel. No heap allocation inside the decoder —
 * caller provides scratch sized via JpegEstimateScratch. IRQ-safe
 * (no locks, no syscalls).
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

// ---------------------------------------------------------------
// Baseline (SOF0) decoder.
// ---------------------------------------------------------------

/// Maximum image dimension the decoder will accept. Anything
/// larger fails fast; the cap exists so a hostile file can't
/// drive a giant scratch allocation. 8192 × 8192 × 4 bytes =
/// 256 MiB pixel output, which is already extreme for a kernel
/// decoder.
inline constexpr u32 kJpegMaxDimension = 8192;

/// Compute scratch buffer size needed by `JpegDecode`. The
/// scratch holds Huffman + quantisation tables, per-component
/// pixel planes, and intermediate work. Returns 0 if `info` is
/// invalid (header parse failed, dimensions exceed cap, etc.).
///
/// The pixel output buffer is NOT included in scratch — that's
/// caller-supplied separately (`out_pixels` in `JpegDecode`)
/// with `width * height * 4` bytes.
u64 JpegEstimateScratch(const JpegInfo& info);

/// Decode a Baseline-DCT JPEG into a packed 32-bit ARGB pixel
/// buffer (alpha = 0xFF, pixel layout 0x00RRGGBB matching the
/// rest of the kernel's framebuffer primitives).
///
/// `src` / `src_len` — full file bytes including SOI..EOI.
/// `info`            — output of JpegParseHeader.
/// `scratch`         — caller-allocated working buffer of size
///                     `JpegEstimateScratch(info)`. The decoder
///                     does no heap allocation.
/// `out_pixels`      — caller-allocated `info.width * info.height`
///                     u32 array, written in row-major order
///                     (pixel (x, y) at `out_pixels[y * width + x]`).
///
/// Returns true on success. Returns false on:
///   - Wrong SOF marker (not 0xC0 → not Baseline)
///   - Precision != 8
///   - Unsupported component count (must be 1 or 3)
///   - Component subsampling ratios outside {1, 2}
///   - Malformed Huffman or quantisation tables
///   - Bit-stream truncation
///   - Coefficient run/length out of range
///   - Restart-marker misalignment
u64 JpegDecode(const u8* src, u32 src_len, const JpegInfo& info, u8* scratch, u64 scratch_len, u32* out_pixels);

/// Boot self-test. Decodes an embedded 8x8 Y'CbCr Baseline JPEG
/// and asserts the output matches a known reference. Pure
/// compute; no I/O side effects beyond serial on failure.
void JpegDecoderSelfTest();

} // namespace duetos::util
