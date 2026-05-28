//! DuetOS Realtek rtlwifi firmware-header parser.
//!
//! Port of kernel/drivers/net/rtl88xx_fw.cpp.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

use core::{ptr, slice};

const HEADER_BYTES: u32 = 32;

const SIG_8192C: u16 = 0x88C0;
const SIG_8192D: u16 = 0x92D0;
const SIG_8723B: u16 = 0x5300;
const SIG_8821: u16 = 0x8821;
const SIG_8812: u16 = 0x8812;
const SIG_8814: u16 = 0x8814;
const SIG_8822B: u16 = 0x88B0;
const SIG_8852A: u16 = 0x8852;
const SIG_8723D: u16 = 0x53D0;

const GEN_UNKNOWN: u8 = 0;
const GEN_RTLWIFI: u8 = 1;
const GEN_RTW88: u8 = 2;
const GEN_RTW89: u8 = 3;

const RESULT_OK: i32 = 0;
const RESULT_INVALID_ARG: i32 = 1;
const RESULT_CORRUPT: i32 = 2;

#[repr(C)]
pub struct DuetosRtlFirmwareParsed {
    pub valid: bool,
    pub generation: u8,
    pub _pad0: [u8; 2],
    pub signature: u16,
    pub category: u8,
    pub function: u8,
    pub version: u16,
    pub subversion: u8,
    pub subsubversion: u8,
    pub date_month: u8,
    pub date_day: u8,
    pub date_hour: u8,
    pub date_minute: u8,
    pub ramcode_size: u16,
    pub _pad1: u16,
    pub svn_index: u32,
    pub payload: *const u8,
    pub payload_size: u32,
    pub size_mismatch: bool,
    pub _pad2: [u8; 3],
}

fn read_le16(buf: &[u8], off: usize) -> u16 {
    u16::from(buf[off]) | (u16::from(buf[off + 1]) << 8)
}

fn read_le32(buf: &[u8], off: usize) -> u32 {
    u32::from(buf[off])
        | (u32::from(buf[off + 1]) << 8)
        | (u32::from(buf[off + 2]) << 16)
        | (u32::from(buf[off + 3]) << 24)
}

fn classify_signature(sig: u16) -> u8 {
    if sig == SIG_8852A {
        GEN_RTW89
    } else if sig == SIG_8822B {
        GEN_RTW88
    } else if matches!(
        sig,
        SIG_8192C | SIG_8192D | SIG_8723B | SIG_8723D | SIG_8821 | SIG_8812 | SIG_8814
    ) {
        GEN_RTLWIFI
    } else {
        GEN_UNKNOWN
    }
}

fn parse_inner(blob: &[u8], blob_ptr: *const u8, parsed: &mut DuetosRtlFirmwareParsed) -> i32 {
    if (blob.len() as u32) < HEADER_BYTES {
        return RESULT_INVALID_ARG;
    }

    parsed.signature = read_le16(blob, 0x00);
    parsed.generation = classify_signature(parsed.signature);
    if parsed.generation == GEN_UNKNOWN {
        return RESULT_CORRUPT;
    }

    parsed.category = blob[0x02];
    parsed.function = blob[0x03];
    parsed.version = read_le16(blob, 0x04);
    parsed.subversion = blob[0x06];
    parsed.subsubversion = blob[0x07];
    parsed.date_month = blob[0x08];
    parsed.date_day = blob[0x09];
    parsed.date_hour = blob[0x0A];
    parsed.date_minute = blob[0x0B];
    parsed.ramcode_size = read_le16(blob, 0x0C);
    parsed.svn_index = read_le32(blob, 0x10);

    // SAFETY: blob[HEADER_BYTES..] is in bounds (we checked
    // blob.len() >= HEADER_BYTES above); pointer points back into
    // the caller's blob.
    parsed.payload = unsafe { blob_ptr.add(HEADER_BYTES as usize) };
    parsed.payload_size = (blob.len() as u32) - HEADER_BYTES;

    // Size sanity (mirrors C++): accept declared size as bytes OR
    // kbytes within a 4 KiB tolerance.
    let declared = u32::from(parsed.ramcode_size);
    let declared_scaled = declared.saturating_mul(1024);
    let tol: u32 = 4096;
    let mut agrees = declared == 0;
    if parsed.payload_size >= declared && parsed.payload_size - declared <= tol {
        agrees = true;
    }
    if parsed.payload_size >= declared_scaled && parsed.payload_size - declared_scaled <= tol {
        agrees = true;
    }
    parsed.size_mismatch = !agrees;
    parsed.valid = true;
    RESULT_OK
}

/// # Safety
/// `blob` valid for `blob_size` bytes or null; `parsed` writable.
#[no_mangle]
pub unsafe extern "C" fn duetos_rtl88xx_fw_parse(
    blob: *const u8,
    blob_size: u32,
    parsed: *mut DuetosRtlFirmwareParsed,
) -> i32 {
    if parsed.is_null() {
        return RESULT_INVALID_ARG;
    }
    // SAFETY: caller-provided pointer.
    unsafe {
        ptr::write_bytes(parsed, 0, 1);
    }
    let parsed_ref = unsafe { &mut *parsed };
    if blob.is_null() {
        return RESULT_INVALID_ARG;
    }
    if blob_size < HEADER_BYTES {
        return RESULT_INVALID_ARG;
    }
    // SAFETY: caller's contract.
    let s = unsafe { slice::from_raw_parts(blob, blob_size as usize) };
    parse_inner(s, blob, parsed_ref)
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::vec::Vec;

    use super::*;

    fn build_image(sig: u16, payload_size: usize) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_BYTES as usize + payload_size);
        buf.extend_from_slice(&sig.to_le_bytes()); // 0x00
        buf.push(1); // category
        buf.push(2); // function
        buf.extend_from_slice(&0x4321u16.to_le_bytes()); // version
        buf.push(0x12); // subversion
        buf.push(0x34); // subsubversion
        buf.push(0x05); // month
        buf.push(0x01); // day
        buf.push(0x12); // hour
        buf.push(0x30); // minute
        buf.extend_from_slice(&(payload_size as u16).to_le_bytes()); // 0x0C ramcode_size
        buf.extend_from_slice(&[0u8; 2]); // 0x0E reserved
        buf.extend_from_slice(&0xCAFEBABEu32.to_le_bytes()); // 0x10
        buf.extend_from_slice(&[0u8; 12]); // 0x14..0x20 reserved
        assert_eq!(buf.len(), HEADER_BYTES as usize);
        for i in 0..payload_size {
            buf.push((i & 0xFF) as u8);
        }
        buf
    }

    fn parse(buf: &[u8]) -> (i32, DuetosRtlFirmwareParsed) {
        let mut p = unsafe { core::mem::zeroed::<DuetosRtlFirmwareParsed>() };
        let r = unsafe { duetos_rtl88xx_fw_parse(buf.as_ptr(), buf.len() as u32, &mut p) };
        (r, p)
    }

    #[test]
    fn rtlwifi_happy_path() {
        let img = build_image(SIG_8821, 256);
        let (r, p) = parse(&img);
        assert_eq!(r, RESULT_OK);
        assert!(p.valid);
        assert_eq!(p.generation, GEN_RTLWIFI);
        assert_eq!(p.signature, SIG_8821);
        assert_eq!(p.version, 0x4321);
        assert_eq!(p.svn_index, 0xCAFEBABE);
        assert_eq!(p.payload_size, 256);
        assert!(!p.size_mismatch);
    }

    #[test]
    fn rtw89_happy_path() {
        let img = build_image(SIG_8852A, 256);
        let (r, p) = parse(&img);
        assert_eq!(r, RESULT_OK);
        assert_eq!(p.generation, GEN_RTW89);
    }

    #[test]
    fn rtw88_happy_path() {
        let img = build_image(SIG_8822B, 256);
        let (r, p) = parse(&img);
        assert_eq!(r, RESULT_OK);
        assert_eq!(p.generation, GEN_RTW88);
    }

    #[test]
    fn bad_sig_rejects() {
        let img = build_image(0xDEAD, 256);
        let (r, _) = parse(&img);
        assert_eq!(r, RESULT_CORRUPT);
    }

    #[test]
    fn short_header_rejects() {
        let buf = [0u8; 16];
        let (r, _) = parse(&buf);
        assert_eq!(r, RESULT_INVALID_ARG);
    }
}
