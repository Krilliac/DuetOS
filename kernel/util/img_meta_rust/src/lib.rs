//! DuetOS image-metadata header walkers (PNG + BMP).
//!
//! Both decoders consume bytes that came from disk / network / a
//! user-mode app — i.e. attacker-controlled. The header is the
//! widest validation surface (signatures, magic numbers, claimed
//! dimensions, bit depth, compression). Bounds-checked slice
//! traversal in Rust replaces the equivalent hand-rolled C++
//! header walkers in `kernel/util/png.cpp` and
//! `kernel/util/bmp.cpp`; the C++ side keeps the heavy lifting
//! (zlib inflate, scanline filter unwind, pixel copy).

#![no_std]

use core::{ptr, slice};

// ---------- C-ABI out-structs (mirror png.h / bmp.h) ----------

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosPngInfo {
    pub width: u32,
    pub height: u32,
    pub bit_depth: u8,
    pub color_type: u8,
    pub ok: u8,
    pub _pad: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosBmpInfo {
    pub width: u32,
    pub height: u32,
    pub bpp: u32,
    pub compression: u32,
    pub pixel_offset: u32,
    pub top_down: u8,
    pub ok: u8,
    pub _pad: [u8; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosTgaInfo {
    pub width: u32,
    pub height: u32,
    pub bpp: u32,
    pub image_type: u32,
    pub pixel_offset: u32,
    pub top_down: u8,
    pub right_to_left: u8,
    pub ok: u8,
    pub _pad: u8,
}

/// JPEG header decode result. `width` / `height` come from the
/// first Start-of-Frame (SOF) marker the walker finds; `precision`
/// is the bits-per-sample byte from the same SOF; `components` is
/// the number of channels (1 = grayscale, 3 = YCbCr, 4 = CMYK).
/// `sof_marker` is the actual marker byte (`0xC0..=0xCF` excluding
/// `0xC4` / `0xC8` / `0xCC` which are tables, not frames) so the
/// caller can tell baseline (`0xC0`) from progressive (`0xC2`).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosJpegInfo {
    pub width: u32,
    pub height: u32,
    pub precision: u8,
    pub components: u8,
    pub sof_marker: u8,
    pub ok: u8,
    pub _pad: u32,
}

// ---------- helpers ----------
//
// Every raw-pointer dereference is concentrated in helpers so the
// `pub extern "C"` entry points are clippy-clean. New crates ship
// with `// SAFETY:` comments on every unsafe block.

fn slice_from_raw<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: caller's FFI contract is that `ptr` is valid for `len`
    // bytes when non-null. The lifetime is bound to the call frame.
    Some(unsafe { slice::from_raw_parts(ptr, len) })
}

fn out_init<'a, T: Default + Copy>(out: *mut T) -> Option<&'a mut T> {
    if out.is_null() {
        return None;
    }
    // SAFETY: FFI contract pins `out` as a writable T-sized region;
    // we never retain the pointer past the call.
    unsafe {
        ptr::write(out, T::default());
        Some(&mut *out)
    }
}

#[inline]
fn load_u16_le(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

#[inline]
fn load_u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

#[inline]
fn load_u32_be(buf: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

// ---------- CRC32 (used by PNG IHDR check) ----------
//
// Standard PNG / Ethernet polynomial 0xEDB88320, computed on the
// (4 byte type-tag + 13 byte IHDR data) region. A 256-entry lookup
// table inflates the binary by ~1 KiB but the IHDR check runs
// once per file, so we prefer the simple bit-walk implementation.
fn crc32(buf: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in buf {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = if (crc & 1) != 0 { 0xEDB8_8320 } else { 0 };
            crc = (crc >> 1) ^ mask;
        }
    }
    !crc
}

// ---------- PNG ----------

const PNG_SIGNATURE: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
const PNG_COLOR_TYPE_RGB: u8 = 2;
const PNG_COLOR_TYPE_RGBA: u8 = 6;

/// Maximum width / height the parser will accept. Larger images
/// can saturate the in-kernel scratch buffer in `PngDecode`; the
/// header walker enforces the cap so the decoder never sees a
/// dimension it can't handle.
const PNG_MAX_DIM: u32 = 16384;

fn parse_png_header(buf: &[u8], out: &mut DuetosPngInfo) -> bool {
    // Signature (8) + length (4) + type (4) + IHDR data (13) + CRC (4).
    if buf.len() < PNG_SIGNATURE.len() + 4 + 4 + 13 + 4 {
        return false;
    }
    if buf[..8] != PNG_SIGNATURE {
        return false;
    }
    let ihdr_len = load_u32_be(buf, 8);
    if ihdr_len != 13 {
        return false;
    }
    // The IHDR tag MUST be "IHDR".
    if &buf[12..16] != b"IHDR" {
        return false;
    }
    // The CRC covers the type tag + the 13-byte IHDR data: bytes [12..29).
    let stored_crc = load_u32_be(buf, 12 + 4 + 13);
    if crc32(&buf[12..12 + 4 + 13]) != stored_crc {
        return false;
    }
    let width = load_u32_be(buf, 16);
    let height = load_u32_be(buf, 20);
    let bit_depth = buf[24];
    let color_type = buf[25];
    let compress = buf[26];
    let filter = buf[27];
    let interlace = buf[28];
    if width == 0 || height == 0 || width > PNG_MAX_DIM || height > PNG_MAX_DIM {
        return false;
    }
    if bit_depth != 8 {
        return false;
    }
    if color_type != PNG_COLOR_TYPE_RGB && color_type != PNG_COLOR_TYPE_RGBA {
        return false;
    }
    if compress != 0 || filter != 0 || interlace != 0 {
        return false;
    }
    out.width = width;
    out.height = height;
    out.bit_depth = bit_depth;
    out.color_type = color_type;
    out.ok = 1;
    true
}

#[no_mangle]
pub extern "C" fn duetos_img_meta_parse_png(buf: *const u8, len: usize, out: *mut DuetosPngInfo) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_png_header(slice, dst)
}

// ---------- BMP ----------

const BMP_FILE_HEADER_BYTES: usize = 14;
const BMP_INFO_HEADER_MIN: usize = 40;
const BMP_HEADER_TOTAL: usize = BMP_FILE_HEADER_BYTES + BMP_INFO_HEADER_MIN;
const BMP_MAX_DIM: u32 = 16384;

fn parse_bmp_header(buf: &[u8], out: &mut DuetosBmpInfo) -> bool {
    if buf.len() < BMP_HEADER_TOTAL {
        return false;
    }
    if buf[0] != b'B' || buf[1] != b'M' {
        return false;
    }
    out.pixel_offset = load_u32_le(buf, 10);
    let dib_size = load_u32_le(buf, 14);
    if dib_size < 40 {
        return false;
    }
    out.width = load_u32_le(buf, 18);
    // BMP's DIB-height field is a signed 32-bit integer: negative
    // means "top-down" (origin at upper-left), positive means
    // bottom-up.
    let signed_height = load_u32_le(buf, 22) as i32;
    if signed_height < 0 {
        out.height = signed_height.unsigned_abs();
        out.top_down = 1;
    } else {
        out.height = signed_height as u32;
        out.top_down = 0;
    }
    out.bpp = load_u16_le(buf, 28) as u32;
    out.compression = load_u32_le(buf, 30);
    if out.width == 0 || out.height == 0 || out.width > BMP_MAX_DIM || out.height > BMP_MAX_DIM {
        return false;
    }
    out.ok = 1;
    true
}

#[no_mangle]
pub extern "C" fn duetos_img_meta_parse_bmp(buf: *const u8, len: usize, out: *mut DuetosBmpInfo) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_bmp_header(slice, dst)
}

// ---------- TGA ----------

const TGA_HEADER_BYTES: usize = 18;
const TGA_MAX_DIM: u32 = 16384;
/// Truevision image-type 2: uncompressed true-colour. The other
/// types (RLE, colormapped, grayscale) are deferred to a future
/// slice — the v0 C++ decoder rejects them too.
const TGA_IMAGE_TYPE_UNCOMPRESSED_TRUECOLOR: u32 = 2;
/// Image-descriptor byte bits.
const TGA_DESCRIPTOR_ORIGIN_TOP: u8 = 0x20;
const TGA_DESCRIPTOR_ORIGIN_RIGHT: u8 = 0x10;

fn parse_tga_header(buf: &[u8], out: &mut DuetosTgaInfo) -> bool {
    if buf.len() < TGA_HEADER_BYTES {
        return false;
    }
    let id_length = buf[0] as u32;
    let colormap_type = buf[1];
    let image_type = buf[2] as u32;
    // Colormap spec: 5 bytes at offset 3 (origin, length, entry-size).
    let colormap_length = load_u16_le(buf, 5) as u32;
    let colormap_entry_size = buf[7];
    let width = load_u16_le(buf, 12) as u32;
    let height = load_u16_le(buf, 14) as u32;
    let pixel_depth = buf[16];
    let descriptor = buf[17];

    if image_type != TGA_IMAGE_TYPE_UNCOMPRESSED_TRUECOLOR {
        return false;
    }
    // True-colour rejects an attached colormap (per TGA spec).
    if colormap_type != 0 {
        return false;
    }
    if pixel_depth != 24 && pixel_depth != 32 {
        return false;
    }
    if width == 0 || height == 0 || width > TGA_MAX_DIM || height > TGA_MAX_DIM {
        return false;
    }

    // For TYPE-2 the colormap fields should be zero; tolerant
    // decoders skip a non-zero colormap if present. Compute the
    // byte length so pixel_offset moves past it.
    let mut colormap_bytes: u32 = 0;
    if colormap_length != 0 {
        // bits → bytes, rounded up.
        let entry_bytes = (colormap_entry_size as u32).saturating_add(7) / 8;
        colormap_bytes = colormap_length.saturating_mul(entry_bytes);
    }
    // pixel_offset = header + id_length + colormap_bytes, saturating.
    let pixel_offset = (TGA_HEADER_BYTES as u32)
        .saturating_add(id_length)
        .saturating_add(colormap_bytes);

    out.width = width;
    out.height = height;
    out.bpp = pixel_depth as u32;
    out.image_type = image_type;
    out.pixel_offset = pixel_offset;
    out.top_down = if (descriptor & TGA_DESCRIPTOR_ORIGIN_TOP) != 0 {
        1
    } else {
        0
    };
    out.right_to_left = if (descriptor & TGA_DESCRIPTOR_ORIGIN_RIGHT) != 0 {
        1
    } else {
        0
    };
    out.ok = 1;
    true
}

#[no_mangle]
pub extern "C" fn duetos_img_meta_parse_tga(buf: *const u8, len: usize, out: *mut DuetosTgaInfo) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_tga_header(slice, dst)
}

// ---------- JPEG ----------
//
// JPEG / JFIF / EXIF byte layout: every file starts with the
// Start-of-Image marker (FFD8). After that, segments are
// introduced by a marker byte FFxx; most segments carry a u16
// big-endian length (length-inclusive) followed by their body.
// The header walker hops segment-to-segment looking for the
// first Start-of-Frame marker (`FFC0..=FFCF` excluding `FFC4`
// DHT / `FFC8` JPG / `FFCC` DAC). When it finds one, the SOF
// body shape is fixed: precision (u8), height (u16 BE), width
// (u16 BE), components (u8), then per-component info.
//
// What this is NOT: a decoder. We extract dimensions + precision
// + component count so a future viewer (or stat() / file-type
// probe / thumbnail cache) can validate the header before
// committing to a decode pass. Quantisation tables, Huffman
// tables, entropy-coded data: all stay invisible to this
// walker.

const JPEG_MARKER_PREFIX: u8 = 0xFF;
const JPEG_MARKER_SOI: u8 = 0xD8;
const JPEG_MARKER_EOI: u8 = 0xD9;
const JPEG_MARKER_SOS: u8 = 0xDA; // Start-of-Scan — entropy-coded payload follows
const JPEG_MARKER_RST_BASE: u8 = 0xD0;
const JPEG_MARKER_RST_LAST: u8 = 0xD7;
const JPEG_MARKER_TEM: u8 = 0x01;
const JPEG_MARKER_SOF0: u8 = 0xC0;
const JPEG_MARKER_SOF15: u8 = 0xCF;
const JPEG_MARKER_DHT: u8 = 0xC4; // not a SOF
const JPEG_MARKER_JPG: u8 = 0xC8; // reserved, not a SOF
const JPEG_MARKER_DAC: u8 = 0xCC; // not a SOF

/// Hop cap on segment iteration. Real JPEGs have <100 markers
/// before SOS; a hostile file padding with empty segments could
/// otherwise spin the walker.
const JPEG_SEGMENT_HOP_CAP: usize = 4096;

/// Dimension cap mirrors the PNG / BMP / TGA ones above.
const JPEG_MAX_DIM: u32 = 16384;

#[inline]
fn load_u16_be(buf: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([buf[off], buf[off + 1]])
}

/// True for any 0xC0..0xCF marker that introduces a Start-of-Frame
/// segment (i.e. carries the dimension + component info). Excludes
/// the three byte values in that range that are NOT frames per
/// ISO/IEC 10918-1 Annex B.
fn marker_is_sof(m: u8) -> bool {
    (JPEG_MARKER_SOF0..=JPEG_MARKER_SOF15).contains(&m)
        && m != JPEG_MARKER_DHT
        && m != JPEG_MARKER_JPG
        && m != JPEG_MARKER_DAC
}

/// True for the stand-alone markers that DON'T carry a length
/// field (SOI, EOI, TEM, RSTn). Other markers all carry a u16-BE
/// length immediately after the marker byte.
fn marker_is_standalone(m: u8) -> bool {
    m == JPEG_MARKER_SOI
        || m == JPEG_MARKER_EOI
        || m == JPEG_MARKER_TEM
        || (JPEG_MARKER_RST_BASE..=JPEG_MARKER_RST_LAST).contains(&m)
}

fn parse_jpeg_header(buf: &[u8], out: &mut DuetosJpegInfo) -> bool {
    // Need at least SOI (2) + one segment marker (2) + length (2).
    if buf.len() < 6 {
        return false;
    }
    // SOI: 0xFF 0xD8.
    if buf[0] != JPEG_MARKER_PREFIX || buf[1] != JPEG_MARKER_SOI {
        return false;
    }
    let mut cursor = 2usize;
    for _ in 0..JPEG_SEGMENT_HOP_CAP {
        // Marker bytes are FFxx. There can be FILL bytes (0xFF)
        // before the real marker per Annex B.1.1.2 — skip them.
        while cursor < buf.len() && buf[cursor] == JPEG_MARKER_PREFIX {
            cursor += 1;
        }
        if cursor >= buf.len() {
            return false;
        }
        let marker = buf[cursor];
        cursor += 1;
        // Reserved 0x00 after a 0xFF is "this is just an 0xFF in
        // entropy-coded data, not a marker" — but we haven't
        // entered SOS yet, so a 0x00 here is malformed.
        if marker == 0x00 {
            return false;
        }
        if marker_is_standalone(marker) {
            // SOI inside the body, EOI before any SOF, or a stray
            // restart marker — all malformed for v0.
            if marker == JPEG_MARKER_EOI {
                return false;
            }
            // SOI / TEM / RST stand-alone: just advance and keep
            // searching for a SOF.
            continue;
        }
        // Length-bearing segment: u16 BE length (length-inclusive).
        if cursor + 2 > buf.len() {
            return false;
        }
        let seg_len = load_u16_be(buf, cursor) as usize;
        // Spec: length is at least 2 (the length field itself).
        if seg_len < 2 {
            return false;
        }
        if cursor + seg_len > buf.len() {
            return false;
        }
        if marker_is_sof(marker) {
            // SOF body shape (length-inclusive == seg_len):
            //   length (u16 BE)
            //   precision (u8)
            //   height (u16 BE)
            //   width (u16 BE)
            //   components (u8)
            // = 8 bytes minimum.
            if seg_len < 8 {
                return false;
            }
            let precision = buf[cursor + 2];
            let height = load_u16_be(buf, cursor + 3) as u32;
            let width = load_u16_be(buf, cursor + 5) as u32;
            let components = buf[cursor + 7];
            // Spec: precision is 8 or 12 for baseline; 8/12/16 for
            // extended sequential / progressive. Reject other
            // values.
            if precision != 8 && precision != 12 && precision != 16 {
                return false;
            }
            // Components: 1 (grayscale), 3 (YCbCr / RGB), 4 (CMYK /
            // YCCK). Anything else is rejected.
            if components != 1 && components != 3 && components != 4 {
                return false;
            }
            if width == 0 || height == 0 || width > JPEG_MAX_DIM || height > JPEG_MAX_DIM {
                return false;
            }
            out.width = width;
            out.height = height;
            out.precision = precision;
            out.components = components;
            out.sof_marker = marker;
            out.ok = 1;
            return true;
        }
        if marker == JPEG_MARKER_SOS {
            // SOS introduces entropy-coded data. If we reach SOS
            // without seeing a SOF first, the file is malformed.
            return false;
        }
        cursor += seg_len;
    }
    false
}

#[no_mangle]
pub extern "C" fn duetos_img_meta_parse_jpeg(buf: *const u8, len: usize, out: *mut DuetosJpegInfo) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_jpeg_header(slice, dst)
}

// ---------- hosted tests ----------

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;

    fn make_png_ihdr(width: u32, height: u32, color_type: u8) -> [u8; 33] {
        let mut buf = [0u8; 33];
        buf[..8].copy_from_slice(&PNG_SIGNATURE);
        buf[8..12].copy_from_slice(&13u32.to_be_bytes());
        buf[12..16].copy_from_slice(b"IHDR");
        buf[16..20].copy_from_slice(&width.to_be_bytes());
        buf[20..24].copy_from_slice(&height.to_be_bytes());
        buf[24] = 8; // bit depth
        buf[25] = color_type;
        // compress=0, filter=0, interlace=0 already from zero-init.
        let crc = crc32(&buf[12..29]);
        buf[29..33].copy_from_slice(&crc.to_be_bytes());
        buf
    }

    fn make_bmp_header(width: u32, height_signed: i32, bpp: u16, compression: u32) -> [u8; 54] {
        let mut buf = [0u8; 54];
        buf[0] = b'B';
        buf[1] = b'M';
        // Pixel-data offset.
        buf[10..14].copy_from_slice(&54u32.to_le_bytes());
        // DIB size.
        buf[14..18].copy_from_slice(&40u32.to_le_bytes());
        buf[18..22].copy_from_slice(&width.to_le_bytes());
        buf[22..26].copy_from_slice(&(height_signed as u32).to_le_bytes());
        buf[28..30].copy_from_slice(&bpp.to_le_bytes());
        buf[30..34].copy_from_slice(&compression.to_le_bytes());
        buf
    }

    // --- PNG ---

    #[test]
    fn png_valid_rgba_parses() {
        let buf = make_png_ihdr(320, 200, PNG_COLOR_TYPE_RGBA);
        let mut out = DuetosPngInfo::default();
        assert!(parse_png_header(&buf, &mut out));
        assert_eq!(out.width, 320);
        assert_eq!(out.height, 200);
        assert_eq!(out.bit_depth, 8);
        assert_eq!(out.color_type, PNG_COLOR_TYPE_RGBA);
        assert_eq!(out.ok, 1);
    }

    #[test]
    fn png_valid_rgb_parses() {
        let buf = make_png_ihdr(1, 1, PNG_COLOR_TYPE_RGB);
        let mut out = DuetosPngInfo::default();
        assert!(parse_png_header(&buf, &mut out));
        assert_eq!(out.color_type, PNG_COLOR_TYPE_RGB);
    }

    #[test]
    fn png_bad_signature_rejects() {
        let mut buf = make_png_ihdr(8, 8, PNG_COLOR_TYPE_RGBA);
        buf[0] ^= 0xff;
        let mut out = DuetosPngInfo::default();
        assert!(!parse_png_header(&buf, &mut out));
    }

    #[test]
    fn png_bad_crc_rejects() {
        let mut buf = make_png_ihdr(8, 8, PNG_COLOR_TYPE_RGBA);
        // Flip a byte INSIDE the IHDR data (after the CRC field
        // would have been computed). The stored CRC no longer
        // matches.
        buf[28] ^= 0xff;
        let mut out = DuetosPngInfo::default();
        assert!(!parse_png_header(&buf, &mut out));
    }

    #[test]
    fn png_overlong_dim_rejects() {
        let buf = make_png_ihdr(PNG_MAX_DIM + 1, 1, PNG_COLOR_TYPE_RGBA);
        let mut out = DuetosPngInfo::default();
        assert!(!parse_png_header(&buf, &mut out));
    }

    #[test]
    fn png_zero_dim_rejects() {
        let buf = make_png_ihdr(0, 1, PNG_COLOR_TYPE_RGBA);
        let mut out = DuetosPngInfo::default();
        assert!(!parse_png_header(&buf, &mut out));
    }

    #[test]
    fn png_unsupported_color_type_rejects() {
        // Type 3 (palette) — not supported in v0.
        let mut buf = make_png_ihdr(8, 8, 3);
        // Recompute CRC since we changed the IHDR data.
        let crc = crc32(&buf[12..29]);
        buf[29..33].copy_from_slice(&crc.to_be_bytes());
        let mut out = DuetosPngInfo::default();
        assert!(!parse_png_header(&buf, &mut out));
    }

    #[test]
    fn png_too_short_rejects() {
        let buf = [0u8; 10];
        let mut out = DuetosPngInfo::default();
        assert!(!parse_png_header(&buf, &mut out));
    }

    // --- BMP ---

    #[test]
    fn bmp_top_down_32bpp_parses() {
        let buf = make_bmp_header(320, -200, 32, 0);
        let mut out = DuetosBmpInfo::default();
        assert!(parse_bmp_header(&buf, &mut out));
        assert_eq!(out.width, 320);
        assert_eq!(out.height, 200);
        assert_eq!(out.top_down, 1);
        assert_eq!(out.bpp, 32);
        assert_eq!(out.compression, 0);
        assert_eq!(out.pixel_offset, 54);
        assert_eq!(out.ok, 1);
    }

    #[test]
    fn bmp_bottom_up_24bpp_parses() {
        let buf = make_bmp_header(640, 480, 24, 0);
        let mut out = DuetosBmpInfo::default();
        assert!(parse_bmp_header(&buf, &mut out));
        assert_eq!(out.width, 640);
        assert_eq!(out.height, 480);
        assert_eq!(out.top_down, 0);
        assert_eq!(out.bpp, 24);
    }

    #[test]
    fn bmp_bad_signature_rejects() {
        let mut buf = make_bmp_header(8, 8, 32, 0);
        buf[0] = b'X';
        let mut out = DuetosBmpInfo::default();
        assert!(!parse_bmp_header(&buf, &mut out));
    }

    #[test]
    fn bmp_short_dib_rejects() {
        let mut buf = make_bmp_header(8, 8, 32, 0);
        // Force DIB-size = 12 (BITMAPCOREHEADER) — pre-V1, we
        // reject for simplicity.
        buf[14..18].copy_from_slice(&12u32.to_le_bytes());
        let mut out = DuetosBmpInfo::default();
        assert!(!parse_bmp_header(&buf, &mut out));
    }

    #[test]
    fn bmp_overlong_dim_rejects() {
        let buf = make_bmp_header(BMP_MAX_DIM + 1, 1, 32, 0);
        let mut out = DuetosBmpInfo::default();
        assert!(!parse_bmp_header(&buf, &mut out));
    }

    #[test]
    fn bmp_zero_dim_rejects() {
        let buf = make_bmp_header(0, 1, 32, 0);
        let mut out = DuetosBmpInfo::default();
        assert!(!parse_bmp_header(&buf, &mut out));
    }

    #[test]
    fn bmp_too_short_rejects() {
        let buf = [0u8; 10];
        let mut out = DuetosBmpInfo::default();
        assert!(!parse_bmp_header(&buf, &mut out));
    }

    // --- TGA ---

    fn make_tga_header(width: u16, height: u16, depth: u8, descriptor: u8, image_type: u8) -> [u8; 18] {
        let mut buf = [0u8; 18];
        buf[2] = image_type;
        buf[12..14].copy_from_slice(&width.to_le_bytes());
        buf[14..16].copy_from_slice(&height.to_le_bytes());
        buf[16] = depth;
        buf[17] = descriptor;
        buf
    }

    #[test]
    fn tga_top_down_32bpp_parses() {
        let buf = make_tga_header(320, 200, 32, TGA_DESCRIPTOR_ORIGIN_TOP, 2);
        let mut out = DuetosTgaInfo::default();
        assert!(parse_tga_header(&buf, &mut out));
        assert_eq!(out.width, 320);
        assert_eq!(out.height, 200);
        assert_eq!(out.bpp, 32);
        assert_eq!(out.image_type, 2);
        assert_eq!(out.pixel_offset, 18);
        assert_eq!(out.top_down, 1);
        assert_eq!(out.right_to_left, 0);
        assert_eq!(out.ok, 1);
    }

    #[test]
    fn tga_bottom_up_24bpp_parses() {
        let buf = make_tga_header(8, 8, 24, 0, 2);
        let mut out = DuetosTgaInfo::default();
        assert!(parse_tga_header(&buf, &mut out));
        assert_eq!(out.bpp, 24);
        assert_eq!(out.top_down, 0);
    }

    #[test]
    fn tga_rle_rejects() {
        // image_type 10 = RLE true-colour — not supported in v0.
        let buf = make_tga_header(8, 8, 32, 0, 10);
        let mut out = DuetosTgaInfo::default();
        assert!(!parse_tga_header(&buf, &mut out));
    }

    #[test]
    fn tga_colormapped_rejects() {
        // image_type 1 = uncompressed colour-mapped — not supported.
        let mut buf = make_tga_header(8, 8, 32, 0, 1);
        buf[1] = 1; // colormap_type set
        let mut out = DuetosTgaInfo::default();
        assert!(!parse_tga_header(&buf, &mut out));
    }

    #[test]
    fn tga_8bpp_rejects() {
        let buf = make_tga_header(8, 8, 8, 0, 2);
        let mut out = DuetosTgaInfo::default();
        assert!(!parse_tga_header(&buf, &mut out));
    }

    #[test]
    fn tga_overlong_dim_rejects() {
        // width=20000 doesn't fit u16, so a hostile encoder could
        // wrap. We test the documented cap (16384) via a u16 value
        // that's > 16384.
        let buf = make_tga_header(16385, 8, 32, 0, 2);
        let mut out = DuetosTgaInfo::default();
        assert!(!parse_tga_header(&buf, &mut out));
    }

    #[test]
    fn tga_zero_dim_rejects() {
        let buf = make_tga_header(0, 8, 32, 0, 2);
        let mut out = DuetosTgaInfo::default();
        assert!(!parse_tga_header(&buf, &mut out));
    }

    #[test]
    fn tga_too_short_rejects() {
        let buf = [0u8; 10];
        let mut out = DuetosTgaInfo::default();
        assert!(!parse_tga_header(&buf, &mut out));
    }

    #[test]
    fn tga_id_length_shifts_pixel_offset() {
        // id_length = 5 → pixel_offset = 18 + 5.
        let mut buf = make_tga_header(8, 8, 32, 0, 2);
        buf[0] = 5;
        let mut out = DuetosTgaInfo::default();
        assert!(parse_tga_header(&buf, &mut out));
        assert_eq!(out.pixel_offset, 23);
    }

    #[test]
    fn tga_right_to_left_flag_round_trips() {
        let buf = make_tga_header(8, 8, 32, TGA_DESCRIPTOR_ORIGIN_RIGHT, 2);
        let mut out = DuetosTgaInfo::default();
        assert!(parse_tga_header(&buf, &mut out));
        assert_eq!(out.right_to_left, 1);
    }

    // --- JPEG ---

    /// Build a minimal JPEG-shaped buffer: SOI + optional APP0 +
    /// SOF0 + EOI. `app0_len` controls a JFIF APP0 segment to
    /// exercise the segment hop; pass 0 to skip it.
    fn make_jpeg_with_sof(
        width: u16,
        height: u16,
        components: u8,
        sof_marker: u8,
        app0_len: u16,
    ) -> alloc::vec::Vec<u8> {
        use alloc::vec::Vec;
        let mut buf: Vec<u8> = Vec::new();
        // SOI
        buf.push(0xFF);
        buf.push(JPEG_MARKER_SOI);
        // Optional APP0 (FFE0) segment to ensure the walker hops over it.
        if app0_len > 0 {
            buf.push(0xFF);
            buf.push(0xE0);
            buf.extend_from_slice(&app0_len.to_be_bytes());
            for _ in 0..(app0_len as usize - 2) {
                buf.push(0);
            }
        }
        // SOF segment. Body shape (length-inclusive 8 bytes minimum):
        //   length(2) precision(1) height(2) width(2) components(1)
        let body_len: u16 = 8 + (components as u16) * 3; // each component descriptor is 3 bytes
        buf.push(0xFF);
        buf.push(sof_marker);
        buf.extend_from_slice(&body_len.to_be_bytes());
        buf.push(8); // precision
        buf.extend_from_slice(&height.to_be_bytes());
        buf.extend_from_slice(&width.to_be_bytes());
        buf.push(components);
        for _ in 0..components {
            buf.push(1); // component id
            buf.push(0x11); // sampling factors
            buf.push(0); // quant table
        }
        // EOI
        buf.push(0xFF);
        buf.push(JPEG_MARKER_EOI);
        buf
    }

    #[test]
    fn jpeg_baseline_sof0_round_trip() {
        let buf = make_jpeg_with_sof(320, 200, 3, JPEG_MARKER_SOF0, 16);
        let mut out = DuetosJpegInfo::default();
        assert!(parse_jpeg_header(&buf, &mut out));
        assert_eq!(out.width, 320);
        assert_eq!(out.height, 200);
        assert_eq!(out.precision, 8);
        assert_eq!(out.components, 3);
        assert_eq!(out.sof_marker, JPEG_MARKER_SOF0);
        assert_eq!(out.ok, 1);
    }

    #[test]
    fn jpeg_progressive_sof2_round_trip() {
        let buf = make_jpeg_with_sof(640, 480, 3, 0xC2, 0);
        let mut out = DuetosJpegInfo::default();
        assert!(parse_jpeg_header(&buf, &mut out));
        assert_eq!(out.sof_marker, 0xC2);
    }

    #[test]
    fn jpeg_grayscale_1_component() {
        let buf = make_jpeg_with_sof(64, 64, 1, JPEG_MARKER_SOF0, 0);
        let mut out = DuetosJpegInfo::default();
        assert!(parse_jpeg_header(&buf, &mut out));
        assert_eq!(out.components, 1);
    }

    #[test]
    fn jpeg_bad_soi_rejects() {
        let mut buf = make_jpeg_with_sof(8, 8, 3, JPEG_MARKER_SOF0, 0);
        buf[0] = 0xAB;
        let mut out = DuetosJpegInfo::default();
        assert!(!parse_jpeg_header(&buf, &mut out));
    }

    #[test]
    fn jpeg_too_short_rejects() {
        let buf = [0xFF, 0xD8];
        let mut out = DuetosJpegInfo::default();
        assert!(!parse_jpeg_header(&buf, &mut out));
    }

    #[test]
    fn jpeg_zero_dim_rejects() {
        let buf = make_jpeg_with_sof(0, 8, 3, JPEG_MARKER_SOF0, 0);
        let mut out = DuetosJpegInfo::default();
        assert!(!parse_jpeg_header(&buf, &mut out));
    }

    #[test]
    fn jpeg_overlong_dim_rejects() {
        let buf = make_jpeg_with_sof(JPEG_MAX_DIM as u16, 8, 3, JPEG_MARKER_SOF0, 0);
        // Exactly the cap is fine (16384); +1 fails. u16 caps at 65535,
        // and 16385 fits — make sure the parser rejects it.
        let buf2 = make_jpeg_with_sof((JPEG_MAX_DIM + 1) as u16, 8, 3, JPEG_MARKER_SOF0, 0);
        let mut out1 = DuetosJpegInfo::default();
        let mut out2 = DuetosJpegInfo::default();
        assert!(parse_jpeg_header(&buf, &mut out1));
        assert!(!parse_jpeg_header(&buf2, &mut out2));
    }

    #[test]
    fn jpeg_bad_components_rejects() {
        // 2 components — not a valid value per ISO/IEC 10918-1.
        let buf = make_jpeg_with_sof(8, 8, 2, JPEG_MARKER_SOF0, 0);
        let mut out = DuetosJpegInfo::default();
        assert!(!parse_jpeg_header(&buf, &mut out));
    }

    #[test]
    fn jpeg_dht_in_sof_range_is_not_a_frame() {
        // FFC4 (DHT) sits in the 0xC0..0xCF range but is NOT a SOF;
        // the walker must hop past it and keep searching.
        use alloc::vec::Vec;
        let mut buf: Vec<u8> = Vec::new();
        buf.push(0xFF);
        buf.push(JPEG_MARKER_SOI);
        // DHT segment (FFC4) — length 4 (length-inclusive), 2 bytes of body.
        buf.push(0xFF);
        buf.push(0xC4);
        buf.extend_from_slice(&4u16.to_be_bytes());
        buf.push(0);
        buf.push(0);
        // Real SOF0.
        buf.push(0xFF);
        buf.push(JPEG_MARKER_SOF0);
        buf.extend_from_slice(&11u16.to_be_bytes()); // 8 + 3*1
        buf.push(8); // precision
        buf.extend_from_slice(&100u16.to_be_bytes()); // height
        buf.extend_from_slice(&200u16.to_be_bytes()); // width
        buf.push(1); // components
        buf.push(1);
        buf.push(0x11);
        buf.push(0);
        let mut out = DuetosJpegInfo::default();
        assert!(parse_jpeg_header(&buf, &mut out));
        assert_eq!(out.width, 200);
        assert_eq!(out.height, 100);
    }

    #[test]
    fn jpeg_segment_length_overflows_buffer_rejects() {
        // SOI + SOF0 with claimed length far past the buffer's end.
        let buf: [u8; 6] = [0xFF, 0xD8, 0xFF, 0xC0, 0xFF, 0xFF];
        let mut out = DuetosJpegInfo::default();
        assert!(!parse_jpeg_header(&buf, &mut out));
    }

    #[test]
    fn jpeg_sos_before_sof_rejects() {
        // SOI then SOS — entropy-coded scan without a frame defined
        // is malformed.
        let mut buf: alloc::vec::Vec<u8> = alloc::vec![0xFF, 0xD8, 0xFF, 0xDA];
        buf.extend_from_slice(&3u16.to_be_bytes());
        buf.push(0);
        let mut out = DuetosJpegInfo::default();
        assert!(!parse_jpeg_header(&buf, &mut out));
    }

    #[test]
    fn jpeg_fill_byte_padding_tolerated() {
        // Spec allows any number of 0xFF "fill bytes" between
        // markers. Insert a handful before the SOF marker.
        use alloc::vec::Vec;
        let mut buf: Vec<u8> = Vec::new();
        buf.push(0xFF);
        buf.push(JPEG_MARKER_SOI);
        // Padding 0xFF bytes.
        for _ in 0..5 {
            buf.push(0xFF);
        }
        buf.push(JPEG_MARKER_SOF0);
        buf.extend_from_slice(&11u16.to_be_bytes());
        buf.push(8);
        buf.extend_from_slice(&50u16.to_be_bytes());
        buf.extend_from_slice(&80u16.to_be_bytes());
        buf.push(1);
        buf.push(1);
        buf.push(0x11);
        buf.push(0);
        let mut out = DuetosJpegInfo::default();
        assert!(parse_jpeg_header(&buf, &mut out));
        assert_eq!(out.width, 80);
        assert_eq!(out.height, 50);
    }

    #[test]
    fn jpeg_segment_length_below_two_rejects() {
        let buf: [u8; 6] = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x01]; // APP0 with bogus length=1
        let mut out = DuetosJpegInfo::default();
        assert!(!parse_jpeg_header(&buf, &mut out));
    }
}
