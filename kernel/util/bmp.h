#pragma once

#include "util/types.h"

/*
 * DuetOS — BMP (Microsoft BITMAPFILEHEADER + BITMAPINFOHEADER)
 * encoder + parser, clean room.
 *
 * Spec: Microsoft BITMAPINFOHEADER documentation (publicly
 * mirrored since the early 1990s). 32-bpp uncompressed BI_RGB
 * with top-down (negative-height) DIB orientation is the only
 * subformat the project produces, since it matches the
 * framebuffer's BGRA8888 native layout byte-for-byte.
 *
 * Consumers in DuetOS today:
 *   - kernel/apps/screenshot.cpp — writes `SHOTNNNN.BMP` files
 *     for every Ctrl+Alt+P capture; previously carried its own
 *     `WriteBmpHeader` and constants.
 *   - kernel/apps/imageview.cpp — reads `SHOTNNNN.BMP` (and
 *     other BMPs in the FAT32 root); previously carried its own
 *     `ParseBmpHeader` and `BmpInfo`.
 *
 * Out of scope (deliberate):
 *   - 24/16-bpp / palettes / RLE compression. The streaming
 *     ImageView decoder rejects everything except 32-bpp BI_RGB;
 *     this util mirrors the same support window.
 *   - BITMAPV4 / V5 headers. Tolerated on parse (any DIB size
 *     ≥ 40 bytes is accepted, with `pixel_offset` read from the
 *     file header's bf_off field), but never emitted.
 */

namespace duetos::util
{

/// Sizes per the Microsoft spec. `kBmpHeaderBytes` is the canonical
/// 54-byte composite (FILEHEADER + 40-byte INFOHEADER).
inline constexpr u64 kBmpFileHeaderBytes = 14;
inline constexpr u64 kBmpInfoHeaderBytes = 40;
inline constexpr u64 kBmpHeaderBytes = kBmpFileHeaderBytes + kBmpInfoHeaderBytes;

/// Parsed result of `BmpParseHeader`. `ok` is false on bad
/// signature, malformed dimensions, or DIB size < 40.
struct BmpInfo
{
    u32 width;
    u32 height;
    u32 bpp;          // 1/4/8/16/24/32 — caller decides what's supported
    u32 compression;  // 0 = BI_RGB, 1 = BI_RLE8, 2 = BI_RLE4, 3 = BI_BITFIELDS
    u32 pixel_offset; // bytes from file start to first pixel byte
    bool top_down;    // true when DIB height was negative
    bool ok;
};

/// Write a 54-byte 32-bpp BI_RGB header into `out`. `out` must
/// have at least `kBmpHeaderBytes` bytes available. The image is
/// laid out as top-down (negative DIB height) when `top_down`
/// is true; this matches the framebuffer's screen order so the
/// pixel array can be copied verbatim from a row-major BGRA
/// scratch buffer.
void BmpWriteHeader32(u8 out[kBmpHeaderBytes], u32 width, u32 height, bool top_down);

/// Parse the 54-byte canonical BMP header at `hdr`. Tolerant of
/// BITMAPV4 / V5 extensions (any DIB size ≥ 40 is accepted; the
/// extra fields shift the pixel area, which the parser surfaces
/// via `info.pixel_offset` from the FILEHEADER's bf_off field).
BmpInfo BmpParseHeader(const u8* hdr);

void BmpSelfTest();

} // namespace duetos::util
