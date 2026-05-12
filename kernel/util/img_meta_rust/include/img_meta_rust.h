// DuetOS image-metadata C FFI — hand-written. Mirrors
// kernel/util/img_meta_rust/src/lib.rs.
//
// Both parsers consume an attacker-controlled image-file header
// and emit a validated dimensions/format struct. The heavy
// decoding (zlib, scanline filter, pixel copy) stays in C++.

#pragma once

#include "util/types.h"

namespace duetos::util::img_meta
{

// Out-structs are intentionally distinct types from C++
// PngInfo / BmpInfo — the C++ wrappers do field-by-field copy on
// the way out so layout drift between Rust and C++ can't silently
// break callers. The `_pad` fields are explicit padding to keep
// the layout stable across compilers.

struct DuetosPngInfo
{
    u32 width;
    u32 height;
    u8 bit_depth;
    u8 color_type;
    u8 ok;
    u8 _pad;
};

struct DuetosBmpInfo
{
    u32 width;
    u32 height;
    u32 bpp;
    u32 compression;
    u32 pixel_offset;
    u8 top_down;
    u8 ok;
    u8 _pad[2];
};

struct DuetosTgaInfo
{
    u32 width;
    u32 height;
    u32 bpp;
    u32 image_type;
    u32 pixel_offset;
    u8 top_down;
    u8 right_to_left;
    u8 ok;
    u8 _pad;
};

extern "C"
{
    /// Validate a PNG header: 8-byte signature, IHDR length / tag /
    /// CRC, dimensions, bit-depth, colour-type. Returns true with
    /// `out->ok = 1` only if every field passes.
    ///
    /// Supported colour types in v0: RGB (2) and RGBA (6) at
    /// bit-depth 8, no interlace, default compress/filter methods.
    bool duetos_img_meta_parse_png(const u8* buf, usize len, DuetosPngInfo* out);

    /// Validate a BMP header: "BM" signature, DIB size ≥ 40,
    /// dimensions within the 16384 × 16384 cap. Returns true with
    /// `out->ok = 1` only if every field passes; `out->top_down`
    /// is 1 when the DIB height was negative (origin upper-left).
    bool duetos_img_meta_parse_bmp(const u8* buf, usize len, DuetosBmpInfo* out);

    /// Validate a TGA 18-byte header. Returns true with
    /// `out->ok = 1` only if the image type is 2 (uncompressed
    /// true-colour), the pixel depth is 24 or 32, and dimensions
    /// fit in the 16384 × 16384 cap. `out->pixel_offset` accounts
    /// for the optional image-id field and (tolerantly) any
    /// trailing colormap bytes some encoders leave dangling.
    bool duetos_img_meta_parse_tga(const u8* buf, usize len, DuetosTgaInfo* out);
}

} // namespace duetos::util::img_meta
