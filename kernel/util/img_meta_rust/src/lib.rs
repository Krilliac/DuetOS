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

// ---------- hosted tests ----------

#[cfg(test)]
mod tests {
    use super::*;

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
}
