//! DuetOS AMD GFX9+ microcode-image parser.
//!
//! Port of the C++ parser in kernel/drivers/gpu/amd_gfx_fw.cpp.
//! The 32-byte common_firmware_header + optional 12-byte
//! gfx_firmware_header_v1_0 tail + jump-table + ucode payload
//! all come from an attacker-controllable disk blob. Rust port
//! confines `unsafe` to the FFI wall + uses checked arithmetic
//! for every length comparison.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

use core::{ptr, slice};

const AMD_COMMON_FW_HEADER_BYTES: u32 = 32;
const AMD_GFX_FW_HEADER_V1_BYTES: u32 = 44;
const AMD_MAX_FW_SIZE_BYTES: u32 = 4 * 1024 * 1024;

const REJECT_BLOB_TOO_SHORT: u32 = 1 << 0;
const REJECT_HEADER_SHORT: u32 = 1 << 1;
const REJECT_HEADER_INCONSISTENT: u32 = 1 << 2;
const REJECT_UCODE_OVERFLOW: u32 = 1 << 3;
const REJECT_JT_OVERFLOW: u32 = 1 << 4;
const REJECT_OVERSIZE: u32 = 1 << 5;

const RESULT_OK: i32 = 0;
const RESULT_INVALID_ARG: i32 = 1;
const RESULT_CORRUPT: i32 = 2;

#[repr(C)]
pub struct DuetosAmdGfxFwParsed {
    pub valid: bool,
    pub is_v1_gfx_header: bool,
    pub _pad0: [u8; 2],
    pub size_bytes: u32,
    pub header_size_bytes: u32,
    pub header_version_major: u16,
    pub header_version_minor: u16,
    pub ip_version_major: u16,
    pub ip_version_minor: u16,
    pub ucode_version: u32,
    pub ucode_size_bytes: u32,
    pub ucode_array_offset: u32,
    pub crc32: u32,
    pub ucode_feature_version: u32,
    pub jt_offset_dwords: u32,
    pub jt_size_dwords: u32,
    pub ucode: *const u32,
    pub ucode_dword_count: u32,
    pub reject_reason: u32,
}

fn read_u16_le(buf: &[u8], offset: usize) -> u16 {
    u16::from(buf[offset]) | (u16::from(buf[offset + 1]) << 8)
}

fn read_u32_le(buf: &[u8], offset: usize) -> u32 {
    u32::from(buf[offset])
        | (u32::from(buf[offset + 1]) << 8)
        | (u32::from(buf[offset + 2]) << 16)
        | (u32::from(buf[offset + 3]) << 24)
}

fn parse_inner(blob: &[u8], blob_ptr: *const u8, parsed: &mut DuetosAmdGfxFwParsed) -> i32 {
    if (blob.len() as u32) < AMD_COMMON_FW_HEADER_BYTES {
        parsed.reject_reason |= REJECT_BLOB_TOO_SHORT;
        return RESULT_INVALID_ARG;
    }

    parsed.size_bytes = read_u32_le(blob, 0x00);
    parsed.header_size_bytes = read_u32_le(blob, 0x04);
    parsed.header_version_major = read_u16_le(blob, 0x08);
    parsed.header_version_minor = read_u16_le(blob, 0x0A);
    parsed.ip_version_major = read_u16_le(blob, 0x0C);
    parsed.ip_version_minor = read_u16_le(blob, 0x0E);
    parsed.ucode_version = read_u32_le(blob, 0x10);
    parsed.ucode_size_bytes = read_u32_le(blob, 0x14);
    parsed.ucode_array_offset = read_u32_le(blob, 0x18);
    parsed.crc32 = read_u32_le(blob, 0x1C);

    if parsed.size_bytes > AMD_MAX_FW_SIZE_BYTES || parsed.ucode_size_bytes > AMD_MAX_FW_SIZE_BYTES {
        parsed.reject_reason |= REJECT_OVERSIZE;
        return RESULT_CORRUPT;
    }
    if parsed.header_size_bytes < AMD_COMMON_FW_HEADER_BYTES || parsed.header_size_bytes as usize > blob.len() {
        parsed.reject_reason |= REJECT_HEADER_SHORT;
        return RESULT_CORRUPT;
    }
    if parsed.size_bytes < parsed.header_size_bytes {
        parsed.reject_reason |= REJECT_HEADER_INCONSISTENT;
        return RESULT_CORRUPT;
    }
    // Payload bound.
    if (parsed.ucode_array_offset as usize) >= blob.len()
        || parsed.ucode_size_bytes == 0
        || (parsed.ucode_size_bytes & 0x3) != 0
    {
        parsed.reject_reason |= REJECT_UCODE_OVERFLOW;
        return RESULT_CORRUPT;
    }
    let payload_end = match (parsed.ucode_array_offset as u64).checked_add(parsed.ucode_size_bytes as u64) {
        Some(v) => v,
        None => {
            parsed.reject_reason |= REJECT_UCODE_OVERFLOW;
            return RESULT_CORRUPT;
        }
    };
    if payload_end > blob.len() as u64 {
        parsed.reject_reason |= REJECT_UCODE_OVERFLOW;
        return RESULT_CORRUPT;
    }

    // SAFETY: ucode_array_offset .. + ucode_size_bytes is within
    // blob[..]; the pointer references back into the caller's
    // buffer.
    parsed.ucode = unsafe { blob_ptr.add(parsed.ucode_array_offset as usize) as *const u32 };
    parsed.ucode_dword_count = parsed.ucode_size_bytes / 4;

    // v1 gfx-header fields when header_size_bytes >= 44.
    if parsed.header_size_bytes >= AMD_GFX_FW_HEADER_V1_BYTES {
        parsed.is_v1_gfx_header = true;
        parsed.ucode_feature_version = read_u32_le(blob, 0x20);
        parsed.jt_offset_dwords = read_u32_le(blob, 0x24);
        parsed.jt_size_dwords = read_u32_le(blob, 0x28);

        let jt_end = match (parsed.jt_offset_dwords as u64).checked_add(parsed.jt_size_dwords as u64) {
            Some(v) => v,
            None => {
                parsed.reject_reason |= REJECT_JT_OVERFLOW;
                parsed.ucode = core::ptr::null();
                parsed.ucode_dword_count = 0;
                return RESULT_CORRUPT;
            }
        };
        if jt_end > parsed.ucode_dword_count as u64 {
            parsed.reject_reason |= REJECT_JT_OVERFLOW;
            parsed.ucode = core::ptr::null();
            parsed.ucode_dword_count = 0;
            return RESULT_CORRUPT;
        }
    }

    parsed.valid = true;
    RESULT_OK
}

/// Parse an AMD GFX microcode image. Behaviour mirrors the C++
/// `AmdGfxFwParse` 1:1.
///
/// # Safety
/// `blob` must point to at least `blob_size` readable bytes (or
/// be null); `parsed` must point to a writable
/// `DuetosAmdGfxFwParsed`.
#[no_mangle]
pub unsafe extern "C" fn duetos_amd_gfx_fw_parse(
    blob: *const u8,
    blob_size: u32,
    parsed: *mut DuetosAmdGfxFwParsed,
) -> i32 {
    if parsed.is_null() {
        return RESULT_INVALID_ARG;
    }
    // SAFETY: caller's contract; zero the struct including the
    // ucode pointer.
    unsafe {
        ptr::write_bytes(parsed, 0, 1);
    }
    let parsed_ref = unsafe { &mut *parsed };

    if blob.is_null() {
        parsed_ref.reject_reason |= REJECT_BLOB_TOO_SHORT;
        return RESULT_INVALID_ARG;
    }
    if blob_size < AMD_COMMON_FW_HEADER_BYTES {
        parsed_ref.reject_reason |= REJECT_BLOB_TOO_SHORT;
        return RESULT_INVALID_ARG;
    }
    // SAFETY: caller's contract that `blob` is valid for blob_size
    // bytes when non-null.
    let s = unsafe { slice::from_raw_parts(blob, blob_size as usize) };
    parse_inner(s, blob, parsed_ref)
}

// ---------------------------------------------------------------------------
// Host-only unit tests.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::vec::Vec;

    fn build_image(header_size: u32, ucode_size: u32, jt_offset_dwords: u32, jt_size_dwords: u32) -> Vec<u8> {
        assert!(ucode_size % 4 == 0);
        let ucode_offset = header_size;
        let size_bytes = header_size + ucode_size;
        let mut buf = Vec::with_capacity(size_bytes as usize);
        // common_firmware_header (32 bytes).
        buf.extend_from_slice(&size_bytes.to_le_bytes()); // 0x00
        buf.extend_from_slice(&header_size.to_le_bytes()); // 0x04
        buf.extend_from_slice(&1u16.to_le_bytes()); // 0x08 hv_major
        buf.extend_from_slice(&0u16.to_le_bytes()); // 0x0A hv_minor
        buf.extend_from_slice(&9u16.to_le_bytes()); // 0x0C ip_major
        buf.extend_from_slice(&0u16.to_le_bytes()); // 0x0E ip_minor
        buf.extend_from_slice(&0x01020304u32.to_le_bytes()); // 0x10
        buf.extend_from_slice(&ucode_size.to_le_bytes()); // 0x14
        buf.extend_from_slice(&ucode_offset.to_le_bytes()); // 0x18
        buf.extend_from_slice(&0xDEADBEEFu32.to_le_bytes()); // 0x1C
        if header_size >= AMD_GFX_FW_HEADER_V1_BYTES {
            buf.extend_from_slice(&1u32.to_le_bytes()); // 0x20 feature_version
            buf.extend_from_slice(&jt_offset_dwords.to_le_bytes()); // 0x24
            buf.extend_from_slice(&jt_size_dwords.to_le_bytes()); // 0x28
        }
        assert_eq!(buf.len(), header_size as usize);
        // Payload — dword pattern.
        for i in 0..(ucode_size / 4) {
            buf.extend_from_slice(&(0xCAFE0000u32 | i).to_le_bytes());
        }
        buf
    }

    fn parse(buf: &[u8]) -> (i32, DuetosAmdGfxFwParsed) {
        let mut p = unsafe { core::mem::zeroed::<DuetosAmdGfxFwParsed>() };
        let r = unsafe { duetos_amd_gfx_fw_parse(buf.as_ptr(), buf.len() as u32, &mut p) };
        (r, p)
    }

    #[test]
    fn v1_gfx_header_happy_path() {
        let img = build_image(AMD_GFX_FW_HEADER_V1_BYTES, 256, 4, 4);
        let (r, p) = parse(&img);
        assert_eq!(r, RESULT_OK);
        assert!(p.valid);
        assert!(p.is_v1_gfx_header);
        assert_eq!(p.ucode_dword_count, 64);
        assert_eq!(p.jt_offset_dwords, 4);
        assert_eq!(p.jt_size_dwords, 4);
    }

    #[test]
    fn common_only_happy_path() {
        let img = build_image(AMD_COMMON_FW_HEADER_BYTES, 128, 0, 0);
        let (r, p) = parse(&img);
        assert_eq!(r, RESULT_OK);
        assert!(p.valid);
        assert!(!p.is_v1_gfx_header);
    }

    #[test]
    fn short_blob_rejects() {
        let buf = [0u8; 16];
        let (r, p) = parse(&buf);
        assert_eq!(r, RESULT_INVALID_ARG);
        assert_ne!(p.reject_reason & REJECT_BLOB_TOO_SHORT, 0);
    }

    #[test]
    fn oversize_rejects() {
        let mut img = build_image(AMD_GFX_FW_HEADER_V1_BYTES, 256, 0, 0);
        let oversize = AMD_MAX_FW_SIZE_BYTES + 1;
        img[0x14..0x18].copy_from_slice(&oversize.to_le_bytes());
        let (r, p) = parse(&img);
        assert_eq!(r, RESULT_CORRUPT);
        assert_ne!(p.reject_reason & REJECT_OVERSIZE, 0);
    }

    #[test]
    fn header_short_rejects() {
        let mut img = build_image(AMD_GFX_FW_HEADER_V1_BYTES, 256, 0, 0);
        // header_size_bytes < 32
        img[0x04..0x08].copy_from_slice(&8u32.to_le_bytes());
        let (r, p) = parse(&img);
        assert_eq!(r, RESULT_CORRUPT);
        assert_ne!(p.reject_reason & REJECT_HEADER_SHORT, 0);
    }

    #[test]
    fn header_inconsistent_rejects() {
        let mut img = build_image(AMD_GFX_FW_HEADER_V1_BYTES, 256, 0, 0);
        // size_bytes < header_size_bytes
        img[0x00..0x04].copy_from_slice(&8u32.to_le_bytes());
        let (r, p) = parse(&img);
        assert_eq!(r, RESULT_CORRUPT);
        assert_ne!(p.reject_reason & REJECT_HEADER_INCONSISTENT, 0);
    }

    #[test]
    fn ucode_overflow_rejects() {
        let mut img = build_image(AMD_GFX_FW_HEADER_V1_BYTES, 256, 0, 0);
        // Claim ucode_size 0x10000 but only 256 bytes follow.
        img[0x14..0x18].copy_from_slice(&0x10000u32.to_le_bytes());
        let (r, p) = parse(&img);
        assert_eq!(r, RESULT_CORRUPT);
        assert_ne!(p.reject_reason & REJECT_UCODE_OVERFLOW, 0);
    }

    #[test]
    fn ucode_not_multiple_of_4_rejects() {
        let img = build_image(AMD_GFX_FW_HEADER_V1_BYTES, 256, 0, 0);
        let mut img = img;
        // 255 is not a multiple of 4.
        img[0x14..0x18].copy_from_slice(&255u32.to_le_bytes());
        let (r, p) = parse(&img);
        assert_eq!(r, RESULT_CORRUPT);
        assert_ne!(p.reject_reason & REJECT_UCODE_OVERFLOW, 0);
    }

    #[test]
    fn jt_overflow_rejects() {
        // jt extends past ucode_dword_count.
        let img = build_image(AMD_GFX_FW_HEADER_V1_BYTES, 64, 30, 50);
        let (r, p) = parse(&img);
        assert_eq!(r, RESULT_CORRUPT);
        assert_ne!(p.reject_reason & REJECT_JT_OVERFLOW, 0);
        // ucode view cleared on JT overflow.
        assert!(p.ucode.is_null());
        assert_eq!(p.ucode_dword_count, 0);
    }
}
