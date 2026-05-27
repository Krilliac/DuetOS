//! DuetOS Broadcom b43 / brcm firmware parser.
//!
//! Port of kernel/drivers/net/bcm43xx_fw.cpp. Walks the b43
//! 8-byte-big-endian-record format. Untrusted firmware bytes
//! from disk — Rust-Subsystems P1.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

use core::{ptr, slice};

const RECORD_HEADER_BYTES: u32 = 8;
const TYPE_UCODE: u8 = 0x75;
const TYPE_PCM: u8 = 0x70;
const TYPE_IV: u8 = 0x69;
const MAX_RECORDS: usize = 8;
const INDEX_NONE: u32 = u32::MAX;

const RESULT_OK: i32 = 0;
const RESULT_INVALID_ARG: i32 = 1;
const RESULT_CORRUPT: i32 = 2;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosBcmFwRecord {
    pub r#type: u8,
    pub version: u8,
    pub _pad: [u8; 2],
    pub size: u32,
    pub payload: *const u8,
}

#[repr(C)]
pub struct DuetosBcmFirmwareParsed {
    pub valid: bool,
    pub truncated: bool,
    pub _pad0: [u8; 2],
    pub records: [DuetosBcmFwRecord; MAX_RECORDS],
    pub record_count: u32,
    pub ucode_index: u32,
    pub pcm_index: u32,
    pub iv_index: u32,
    pub walked_bytes: u32,
    pub dropped_records: u32,
}

fn read_be32(buf: &[u8], off: usize) -> u32 {
    (u32::from(buf[off]) << 24)
        | (u32::from(buf[off + 1]) << 16)
        | (u32::from(buf[off + 2]) << 8)
        | u32::from(buf[off + 3])
}

fn recognised_record_type(t: u8) -> bool {
    t == TYPE_UCODE || t == TYPE_PCM || t == TYPE_IV
}

fn parse_inner(blob: &[u8], blob_ptr: *const u8, parsed: &mut DuetosBcmFirmwareParsed) -> i32 {
    if (blob.len() as u32) < RECORD_HEADER_BYTES {
        return RESULT_INVALID_ARG;
    }
    // First byte must be a recognised record type — the cleanest
    // "this isn't a b43 blob" signal.
    if !recognised_record_type(blob[0]) {
        return RESULT_CORRUPT;
    }

    let mut off: u32 = 0;
    while off as usize + RECORD_HEADER_BYTES as usize <= blob.len() {
        let off_u = off as usize;
        let r_type = blob[off_u];
        let r_version = blob[off_u + 1];
        // bytes [off+2..off+4] reserved.
        let size = read_be32(blob, off_u + 4);
        let payload_off = match off.checked_add(RECORD_HEADER_BYTES) {
            Some(v) => v,
            None => {
                parsed.truncated = true;
                break;
            }
        };

        // Bound check via checked_add.
        let record_end = match (payload_off as u64).checked_add(size as u64) {
            Some(v) => v,
            None => {
                parsed.truncated = true;
                break;
            }
        };
        if size as usize > blob.len() || record_end > blob.len() as u64 {
            parsed.truncated = true;
            break;
        }
        if !recognised_record_type(r_type) {
            // Unrecognised type mid-stream is a stop signal.
            parsed.truncated = true;
            break;
        }

        if (parsed.record_count as usize) < MAX_RECORDS {
            let i = parsed.record_count as usize;
            // SAFETY: payload_off in bounds checked above; the
            // pointer references back into the caller's blob.
            let pp = unsafe { blob_ptr.add(payload_off as usize) };
            parsed.records[i] = DuetosBcmFwRecord {
                r#type: r_type,
                version: r_version,
                _pad: [0, 0],
                size,
                payload: pp,
            };
            parsed.record_count += 1;
        } else {
            parsed.dropped_records += 1;
        }

        off = record_end as u32;
    }

    parsed.walked_bytes = off;

    // Convenience indices: first occurrence of each type.
    parsed.ucode_index = INDEX_NONE;
    parsed.pcm_index = INDEX_NONE;
    parsed.iv_index = INDEX_NONE;
    for i in 0..parsed.record_count as usize {
        let t = parsed.records[i].r#type;
        let idx = i as u32;
        if t == TYPE_UCODE && parsed.ucode_index == INDEX_NONE {
            parsed.ucode_index = idx;
        } else if t == TYPE_PCM && parsed.pcm_index == INDEX_NONE {
            parsed.pcm_index = idx;
        } else if t == TYPE_IV && parsed.iv_index == INDEX_NONE {
            parsed.iv_index = idx;
        }
    }

    parsed.valid = parsed.record_count > 0;
    if !parsed.valid {
        return RESULT_CORRUPT;
    }
    RESULT_OK
}

/// # Safety
/// `blob` must point to at least `blob_size` readable bytes (or
/// be null); `parsed` must point to a writable struct.
#[no_mangle]
pub unsafe extern "C" fn duetos_bcm43xx_fw_parse(
    blob: *const u8,
    blob_size: u32,
    parsed: *mut DuetosBcmFirmwareParsed,
) -> i32 {
    if parsed.is_null() {
        return RESULT_INVALID_ARG;
    }
    // SAFETY: caller-provided pointer; zero the whole struct.
    unsafe {
        ptr::write_bytes(parsed, 0, 1);
    }
    let parsed_ref = unsafe { &mut *parsed };
    parsed_ref.ucode_index = INDEX_NONE;
    parsed_ref.pcm_index = INDEX_NONE;
    parsed_ref.iv_index = INDEX_NONE;

    if blob.is_null() {
        return RESULT_INVALID_ARG;
    }
    if blob_size < RECORD_HEADER_BYTES {
        return RESULT_INVALID_ARG;
    }
    // SAFETY: caller's contract that `blob` is valid for blob_size bytes.
    let s = unsafe { slice::from_raw_parts(blob, blob_size as usize) };
    parse_inner(s, blob, parsed_ref)
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::vec::Vec;

    fn write_record(buf: &mut Vec<u8>, type_b: u8, version: u8, payload: &[u8]) {
        buf.push(type_b);
        buf.push(version);
        buf.push(0);
        buf.push(0);
        buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(payload);
    }

    fn parse(buf: &[u8]) -> (i32, DuetosBcmFirmwareParsed) {
        let mut p = unsafe { core::mem::zeroed::<DuetosBcmFirmwareParsed>() };
        let r = unsafe { duetos_bcm43xx_fw_parse(buf.as_ptr(), buf.len() as u32, &mut p) };
        (r, p)
    }

    #[test]
    fn three_records_happy_path() {
        let mut buf = Vec::new();
        write_record(&mut buf, TYPE_UCODE, 1, &[0xAA; 32]);
        write_record(&mut buf, TYPE_PCM, 1, &[0xBB; 16]);
        write_record(&mut buf, TYPE_IV, 1, &[0xCC; 8]);
        let (r, p) = parse(&buf);
        assert_eq!(r, RESULT_OK);
        assert!(p.valid);
        assert_eq!(p.record_count, 3);
        assert_eq!(p.ucode_index, 0);
        assert_eq!(p.pcm_index, 1);
        assert_eq!(p.iv_index, 2);
        assert!(!p.truncated);
    }

    #[test]
    fn bad_first_type_rejects() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0xDE, 0, 0, 0, 0, 0, 0, 16]);
        buf.extend_from_slice(&[0u8; 16]);
        let (r, _) = parse(&buf);
        assert_eq!(r, RESULT_CORRUPT);
    }

    #[test]
    fn short_header_rejects() {
        let buf = [0u8; 4];
        let (r, _) = parse(&buf);
        assert_eq!(r, RESULT_INVALID_ARG);
    }

    #[test]
    fn oversize_truncates_after_first() {
        // First record valid, second declares giant size.
        let mut buf = Vec::new();
        write_record(&mut buf, TYPE_UCODE, 1, &[0; 8]);
        // Manually append a record with huge size claim.
        buf.push(TYPE_PCM);
        buf.push(1);
        buf.push(0);
        buf.push(0);
        buf.extend_from_slice(&0xFFFFFF00u32.to_be_bytes());
        let (r, p) = parse(&buf);
        // first record OK, second truncates the walk.
        assert_eq!(r, RESULT_OK);
        assert!(p.truncated);
        assert_eq!(p.record_count, 1);
    }

    #[test]
    fn drops_records_past_cap() {
        let mut buf = Vec::new();
        // Write 10 records — cap is 8.
        for _ in 0..10 {
            write_record(&mut buf, TYPE_UCODE, 1, &[0; 4]);
        }
        let (r, p) = parse(&buf);
        assert_eq!(r, RESULT_OK);
        assert_eq!(p.record_count, MAX_RECORDS as u32);
        assert_eq!(p.dropped_records, 2);
    }

    #[test]
    fn null_blob_invalid() {
        let mut p = unsafe { core::mem::zeroed::<DuetosBcmFirmwareParsed>() };
        let r = unsafe { duetos_bcm43xx_fw_parse(core::ptr::null(), 64, &mut p) };
        assert_eq!(r, RESULT_INVALID_ARG);
    }
}
