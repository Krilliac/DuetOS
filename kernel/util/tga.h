#pragma once

#include "util/types.h"

/*
 * DuetOS — Truevision TGA 2.0 image decoder (clean room).
 *
 * Spec: Truevision TGA 2.0 (1989), supplemented by the public
 * "TGA File Format Specification" sheet that's been freely
 * mirrored since the late 1990s. No code from stb_image, libtga,
 * or libga used as input.
 *
 * Scope (v0):
 *   - Image type 2 (uncompressed True-color, 24/32 bpp).
 *   - Top-down + bottom-up origin (descriptor bit 5).
 *   - Optional 1-byte image-id field skipped before pixel data.
 *
 * Out of scope (deliberate, future slices):
 *   - Type 10 RLE-encoded True-color — separate slice; the
 *     ImageView consumer can land without it (TGA wallpapers
 *     are typically uncompressed).
 *   - Type 1 / 9 colormapped images — needs palette plumbing.
 *   - Type 3 / 11 black-and-white — niche; defer.
 *   - 16 bpp (1-5-5-5).
 *   - Optional TGA 2.0 footer + extension area — informational
 *     only, ignored on decode.
 *
 * Eventual consumer: `kernel/apps/imageview.cpp`. TGA is a
 * common wallpaper / icon format and its uncompressed 32-bpp
 * BGRA layout matches the framebuffer's native format byte-for-
 * byte, so the decode path is just header-parse + pixel-copy +
 * row-flip-on-bottom-up.
 *
 * No allocation, no global state — every routine operates on
 * caller-provided buffers.
 */

namespace duetos::util
{

/// Fixed-size TGA file header (per spec §3, "Field Reference Table").
inline constexpr u32 kTgaHeaderBytes = 18;

/// Maximum dimension we accept on either axis. Above this is
/// treated as malformed input — a 16384×16384 32-bpp image is
/// already 1 GiB, well past any realistic wallpaper size.
inline constexpr u32 kTgaMaxDim = 16384;

/// Parsed result of `TgaParseHeader`. `ok` is false on any
/// rejection (unsupported type, zero dimension, oversize, etc).
/// `pixel_offset` is the byte offset of the first pixel byte in
/// the source image stream, accounting for image-id skip and
/// (when supported) colour-map skip.
struct TgaInfo
{
    u32 width;
    u32 height;
    u32 bpp;          // 24 or 32; rejected otherwise in v0
    u32 image_type;   // 2 (uncompressed) supported in v0
    u32 pixel_offset; // byte offset within the source where pixels start
    bool top_down;    // image-descriptor bit 5
    bool right_to_left;
    bool ok;
};

/// Parse the 18-byte header at `hdr` plus enough of the source
/// to know where the pixel data starts. Caller must have at
/// least `kTgaHeaderBytes + id_length` bytes available before
/// the pixel data; this function only reads the header.
TgaInfo TgaParseHeader(const u8* hdr);

/// Decode an uncompressed 24/32-bpp TGA image from a contiguous
/// byte buffer. `src` points at the first byte of the file
/// (header, then the pixel area at `info.pixel_offset`), and
/// `src_len` is the total bytes available — the routine does
/// not overrun. Output is BGRA8888 packed as u32 in little-endian
/// memory order (B in low byte, A in high byte) — matches the
/// framebuffer's native format. Output capacity is
/// `info.width * info.height` u32 elements.
///
/// Bottom-up source is automatically row-flipped during decode
/// so the output is always top-down.
///
/// Returns true on success. Returns false on truncated `src`,
/// malformed dimensions, or any unsupported subformat the parser
/// would have flagged via `info.ok = false` already.
bool TgaDecodeUncompressed(const u8* src, u32 src_len, const TgaInfo& info, u32* out_pixels);

/// Write the canonical 18-byte uncompressed 32-bpp top-down TGA
/// header into `out`. `out` must hold at least `kTgaHeaderBytes`.
/// Returns true on success; false if dimensions are out of range.
/// Streaming consumers (e.g. the Screenshot writer) emit this
/// header first, then append BGRA-row bytes verbatim.
bool TgaWriteHeader32(u8 out[kTgaHeaderBytes], u32 width, u32 height);

/// Encode a 32-bpp uncompressed top-down TGA image. `pixels` is
/// `width × height` BGRA8888 u32 elements (same format
/// `TgaDecodeUncompressed` produces). `out` must hold at least
/// `kTgaHeaderBytes + width × height × 4` bytes. Returns the
/// total bytes written, or 0 if `out_cap` is insufficient or
/// dimensions are out of range.
u32 TgaEncode32(const u32* pixels, u32 width, u32 height, u8* out, u32 out_cap);

void TgaSelfTest();

} // namespace duetos::util
