//! DuetOS NVIDIA GSP firmware-image (nvfw_bin_hdr) parser.
//!
//! Port of the C++ parser in kernel/drivers/gpu/nvidia_gsp_fw.cpp.
//! The 24-byte outer header + per-arch inner descriptor + ELF64
//! RISC-V payload all come from an on-disk firmware blob the
//! attacker can shape if they control the install media or
//! staging path. The Rust port:
//!   - reads every field through bounds-checked indexing,
//!   - uses checked_add for every offset+size pair so a hostile
//!     `data_size` close to u32::MAX can't wrap to a smaller
//!     value that "fits the buffer",
//!   - confines `unsafe` to the FFI wall (raw ptr -> slice +
//!     the payload pointer compute at the very end).
//!
//! Behaviour MUST match the prior C++ implementation 1:1 — the
//! existing `fuzz_nvidia_gsp_fw` harness pins the contract and
//! the C++ `NvidiaGspFwSelfTest` boot sentinel exercises the
//! crate through the same FFI.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

use core::{ptr, slice};

// Protocol constants — mirror kernel/drivers/gpu/nvidia_gsp_fw.h.
const NVIDIA_BIN_HDR_MAGIC: u32 = 0x10DE;
const NVIDIA_BIN_HDR_VER_EXPECTED: u32 = 1;
const NVIDIA_BIN_HDR_BYTES: u32 = 24;
const NVIDIA_DESC_BYTES_TURING_GA100: u32 = 76;
const NVIDIA_DESC_BYTES_GA102_PLUS: u32 = 84;
const NVIDIA_MAX_GSP_IMAGE_BYTES: u32 = 64 * 1024 * 1024;

// reject_reason bit codes.
const REJECT_BLOB_TOO_SHORT: u32 = 1 << 0;
const REJECT_BAD_MAGIC: u32 = 1 << 1;
const REJECT_BAD_VERSION: u32 = 1 << 2;
const REJECT_HEADER_OFFSET: u32 = 1 << 3;
const REJECT_DATA_BOUNDS: u32 = 1 << 4;
const REJECT_DESC_TOO_SMALL: u32 = 1 << 5;
const REJECT_OVERSIZE: u32 = 1 << 6;

// arch_class enum values.
const ARCH_UNKNOWN: u8 = 0;
const ARCH_TURING_GA100: u8 = 1;
const ARCH_GA102_PLUS: u8 = 2;

// Result codes returned by the FFI parse entry point.
const RESULT_OK: i32 = 0;
const RESULT_INVALID_ARG: i32 = 1;
const RESULT_CORRUPT: i32 = 2;

#[repr(C)]
pub struct DuetosNvidiaGspFwParsed {
    pub valid: bool,
    pub bin_magic: u32,
    pub bin_ver: u32,
    pub bin_size: u32,
    pub header_offset: u32,
    pub data_offset: u32,
    pub data_size: u32,
    pub descriptor_offset: u32,
    pub descriptor_size: u32,
    pub arch_class: u8,
    pub _pad0: [u8; 3],
    pub payload: *const u8,
    pub payload_size: u32,
    pub payload_looks_elf: bool,
    pub _pad1: [u8; 3],
    pub reject_reason: u32,
}

fn read_u32_le(buf: &[u8], offset: usize) -> u32 {
    u32::from(buf[offset])
        | (u32::from(buf[offset + 1]) << 8)
        | (u32::from(buf[offset + 2]) << 16)
        | (u32::from(buf[offset + 3]) << 24)
}

fn classify_descriptor(size: u32) -> u8 {
    if size == NVIDIA_DESC_BYTES_TURING_GA100 {
        ARCH_TURING_GA100
    } else if size == NVIDIA_DESC_BYTES_GA102_PLUS {
        ARCH_GA102_PLUS
    } else {
        ARCH_UNKNOWN
    }
}

fn parse_inner(blob: &[u8], blob_ptr: *const u8, parsed: &mut DuetosNvidiaGspFwParsed) -> i32 {
    // Defaults — all fields zeroed by the caller's `*parsed = {}`.
    if (blob.len() as u32) < NVIDIA_BIN_HDR_BYTES {
        parsed.reject_reason |= REJECT_BLOB_TOO_SHORT;
        return RESULT_INVALID_ARG;
    }

    parsed.bin_magic = read_u32_le(blob, 0x00);
    parsed.bin_ver = read_u32_le(blob, 0x04);
    parsed.bin_size = read_u32_le(blob, 0x08);
    parsed.header_offset = read_u32_le(blob, 0x0C);
    parsed.data_offset = read_u32_le(blob, 0x10);
    parsed.data_size = read_u32_le(blob, 0x14);

    if parsed.bin_magic != NVIDIA_BIN_HDR_MAGIC {
        parsed.reject_reason |= REJECT_BAD_MAGIC;
        return RESULT_CORRUPT;
    }
    if parsed.bin_ver != NVIDIA_BIN_HDR_VER_EXPECTED {
        parsed.reject_reason |= REJECT_BAD_VERSION;
        return RESULT_CORRUPT;
    }
    if parsed.data_size > NVIDIA_MAX_GSP_IMAGE_BYTES {
        parsed.reject_reason |= REJECT_OVERSIZE;
        return RESULT_CORRUPT;
    }
    if parsed.header_offset != NVIDIA_BIN_HDR_BYTES {
        parsed.reject_reason |= REJECT_HEADER_OFFSET;
        return RESULT_CORRUPT;
    }
    // `header_offset + 76` must fit in u32 (checked) and
    // `data_offset` must be at least that.
    let min_data_offset = match parsed.header_offset.checked_add(NVIDIA_DESC_BYTES_TURING_GA100) {
        Some(v) => v,
        None => {
            parsed.reject_reason |= REJECT_DESC_TOO_SMALL;
            return RESULT_CORRUPT;
        }
    };
    if parsed.data_offset < min_data_offset {
        parsed.reject_reason |= REJECT_DESC_TOO_SMALL;
        return RESULT_CORRUPT;
    }
    // Bound the payload via checked arithmetic.
    let data_end = match (parsed.data_offset as u64).checked_add(parsed.data_size as u64) {
        Some(v) => v,
        None => {
            parsed.reject_reason |= REJECT_DATA_BOUNDS;
            return RESULT_CORRUPT;
        }
    };
    if (parsed.data_offset as usize) >= blob.len() || data_end > blob.len() as u64 {
        parsed.reject_reason |= REJECT_DATA_BOUNDS;
        return RESULT_CORRUPT;
    }

    parsed.descriptor_offset = parsed.header_offset;
    parsed.descriptor_size = parsed.data_offset - parsed.header_offset;
    parsed.arch_class = classify_descriptor(parsed.descriptor_size);

    // SAFETY: data_offset .. data_offset + data_size are within
    // blob[0..blob.len()] per the bounds check just above. The
    // caller's contract is that `blob_ptr` is valid for blob.len()
    // bytes; this pointer references back into that same range.
    parsed.payload = unsafe { blob_ptr.add(parsed.data_offset as usize) };
    parsed.payload_size = parsed.data_size;

    // Advisory ELF magic check on the first 4 payload bytes. Safe
    // — we know payload_size >= 0; check both.
    let off = parsed.data_offset as usize;
    parsed.payload_looks_elf = parsed.data_size >= 4
        && blob[off] == 0x7F
        && blob[off + 1] == b'E'
        && blob[off + 2] == b'L'
        && blob[off + 3] == b'F';

    parsed.valid = true;
    RESULT_OK
}

/// Parse an NVIDIA GSP firmware container. Behaviour mirrors the
/// C++ `NvidiaGspFwParse` 1:1.
///
/// # Safety
/// `blob` must point to at least `blob_size` readable bytes (or
/// be null); `parsed` must point to a writable
/// `DuetosNvidiaGspFwParsed`.
#[no_mangle]
pub unsafe extern "C" fn duetos_nvidia_gsp_fw_parse(
    blob: *const u8,
    blob_size: u32,
    parsed: *mut DuetosNvidiaGspFwParsed,
) -> i32 {
    if parsed.is_null() {
        return RESULT_INVALID_ARG;
    }
    // SAFETY: caller's contract; ptr::write_bytes zeroes the
    // struct including the `payload` pointer.
    unsafe {
        ptr::write_bytes(parsed, 0, 1);
    }
    let parsed_ref = unsafe { &mut *parsed };

    if blob.is_null() {
        parsed_ref.reject_reason |= REJECT_BLOB_TOO_SHORT;
        return RESULT_INVALID_ARG;
    }
    if blob_size < NVIDIA_BIN_HDR_BYTES {
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

    fn build_image(desc_bytes: u32, payload_size: u32, elf_magic: bool) -> Vec<u8> {
        let header_offset = NVIDIA_BIN_HDR_BYTES;
        let data_offset = header_offset + desc_bytes;
        let total = data_offset + payload_size;
        let mut buf = Vec::with_capacity(total as usize);
        // Header.
        buf.extend_from_slice(&NVIDIA_BIN_HDR_MAGIC.to_le_bytes());
        buf.extend_from_slice(&NVIDIA_BIN_HDR_VER_EXPECTED.to_le_bytes());
        buf.extend_from_slice(&total.to_le_bytes());
        buf.extend_from_slice(&header_offset.to_le_bytes());
        buf.extend_from_slice(&data_offset.to_le_bytes());
        buf.extend_from_slice(&payload_size.to_le_bytes());
        // Descriptor.
        buf.resize((header_offset + desc_bytes) as usize, 0xA5);
        // Payload.
        if elf_magic && payload_size >= 4 {
            buf.extend_from_slice(b"\x7fELF");
            for i in 4..payload_size {
                buf.push((i & 0xFF) as u8);
            }
        } else {
            for i in 0..payload_size {
                buf.push((i & 0xFF) as u8);
            }
        }
        buf
    }

    fn parse(buf: &[u8]) -> (i32, DuetosNvidiaGspFwParsed) {
        let mut p = unsafe { core::mem::zeroed::<DuetosNvidiaGspFwParsed>() };
        let r = unsafe { duetos_nvidia_gsp_fw_parse(buf.as_ptr(), buf.len() as u32, &mut p) };
        (r, p)
    }

    #[test]
    fn turing_ga100_happy_path() {
        let img = build_image(NVIDIA_DESC_BYTES_TURING_GA100, 512, true);
        let (r, p) = parse(&img);
        assert_eq!(r, RESULT_OK);
        assert!(p.valid);
        assert_eq!(p.arch_class, ARCH_TURING_GA100);
        assert_eq!(p.descriptor_size, NVIDIA_DESC_BYTES_TURING_GA100);
        assert_eq!(p.payload_size, 512);
        assert!(p.payload_looks_elf);
    }

    #[test]
    fn ga102_plus_happy_path() {
        let img = build_image(NVIDIA_DESC_BYTES_GA102_PLUS, 1024, false);
        let (r, p) = parse(&img);
        assert_eq!(r, RESULT_OK);
        assert_eq!(p.arch_class, ARCH_GA102_PLUS);
        assert!(!p.payload_looks_elf);
    }

    #[test]
    fn short_blob_rejects() {
        let buf = [0u8; 10];
        let (r, p) = parse(&buf);
        assert_eq!(r, RESULT_INVALID_ARG);
        assert_ne!(p.reject_reason & REJECT_BLOB_TOO_SHORT, 0);
    }

    #[test]
    fn bad_magic_rejects() {
        let mut img = build_image(NVIDIA_DESC_BYTES_TURING_GA100, 256, false);
        img[0..4].copy_from_slice(&0xDEAD0000u32.to_le_bytes());
        let (r, p) = parse(&img);
        assert_eq!(r, RESULT_CORRUPT);
        assert_ne!(p.reject_reason & REJECT_BAD_MAGIC, 0);
    }

    #[test]
    fn bad_version_rejects() {
        let mut img = build_image(NVIDIA_DESC_BYTES_TURING_GA100, 256, false);
        img[4..8].copy_from_slice(&99u32.to_le_bytes());
        let (r, p) = parse(&img);
        assert_eq!(r, RESULT_CORRUPT);
        assert_ne!(p.reject_reason & REJECT_BAD_VERSION, 0);
    }

    #[test]
    fn bad_header_offset_rejects() {
        let mut img = build_image(NVIDIA_DESC_BYTES_TURING_GA100, 256, false);
        img[0x0C..0x10].copy_from_slice(&32u32.to_le_bytes());
        let (r, p) = parse(&img);
        assert_eq!(r, RESULT_CORRUPT);
        assert_ne!(p.reject_reason & REJECT_HEADER_OFFSET, 0);
    }

    #[test]
    fn desc_too_small_rejects() {
        // Manually craft an image with 32-byte descriptor span.
        let desc = 32u32;
        let payload = 128u32;
        let data_off = NVIDIA_BIN_HDR_BYTES + desc;
        let total = data_off + payload;
        let mut img = Vec::with_capacity(total as usize);
        img.extend_from_slice(&NVIDIA_BIN_HDR_MAGIC.to_le_bytes());
        img.extend_from_slice(&NVIDIA_BIN_HDR_VER_EXPECTED.to_le_bytes());
        img.extend_from_slice(&total.to_le_bytes());
        img.extend_from_slice(&NVIDIA_BIN_HDR_BYTES.to_le_bytes());
        img.extend_from_slice(&data_off.to_le_bytes());
        img.extend_from_slice(&payload.to_le_bytes());
        img.resize(total as usize, 0);
        let (r, p) = parse(&img);
        assert_eq!(r, RESULT_CORRUPT);
        assert_ne!(p.reject_reason & REJECT_DESC_TOO_SMALL, 0);
    }

    #[test]
    fn data_bounds_overflow_rejects() {
        let mut img = build_image(NVIDIA_DESC_BYTES_TURING_GA100, 256, false);
        // Claim 64 KiB payload but only 256 B follow.
        img[0x14..0x18].copy_from_slice(&0x10000u32.to_le_bytes());
        let (r, p) = parse(&img);
        assert_eq!(r, RESULT_CORRUPT);
        assert_ne!(p.reject_reason & REJECT_DATA_BOUNDS, 0);
    }

    #[test]
    fn oversize_rejects() {
        let mut img = build_image(NVIDIA_DESC_BYTES_TURING_GA100, 256, false);
        let oversize = NVIDIA_MAX_GSP_IMAGE_BYTES + 1;
        img[0x14..0x18].copy_from_slice(&oversize.to_le_bytes());
        let (r, p) = parse(&img);
        assert_eq!(r, RESULT_CORRUPT);
        assert_ne!(p.reject_reason & REJECT_OVERSIZE, 0);
    }

    #[test]
    fn null_parsed_rejects() {
        let img = build_image(NVIDIA_DESC_BYTES_TURING_GA100, 256, false);
        let r = unsafe { duetos_nvidia_gsp_fw_parse(img.as_ptr(), img.len() as u32, core::ptr::null_mut()) };
        assert_eq!(r, RESULT_INVALID_ARG);
    }

    #[test]
    fn null_blob_rejects() {
        let mut p = unsafe { core::mem::zeroed::<DuetosNvidiaGspFwParsed>() };
        let r = unsafe { duetos_nvidia_gsp_fw_parse(core::ptr::null(), 1024, &mut p) };
        assert_eq!(r, RESULT_INVALID_ARG);
        assert_ne!(p.reject_reason & REJECT_BLOB_TOO_SHORT, 0);
    }

    #[test]
    fn data_size_u32_max_overflow_rejects() {
        // Craft a header where data_offset + data_size would
        // overflow u64 (impossible because both are u32, but
        // u32+u32 can still overflow u32 in the wrong arithmetic).
        // checked_add on u64 catches both.
        let mut img = build_image(NVIDIA_DESC_BYTES_TURING_GA100, 256, false);
        img[0x10..0x14].copy_from_slice(&0xFFFFFF00u32.to_le_bytes()); // data_offset huge
        img[0x14..0x18].copy_from_slice(&0xFFu32.to_le_bytes());       // data_size small
        // data_offset >= blob.len() triggers REJECT_DATA_BOUNDS.
        let (r, p) = parse(&img);
        assert_eq!(r, RESULT_CORRUPT);
        assert_ne!(p.reject_reason & REJECT_DATA_BOUNDS, 0);
    }
}
