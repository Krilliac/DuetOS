//! DuetOS Intel iwlwifi firmware TLV parser.
//!
//! Port of kernel/drivers/net/iwlwifi_fw.cpp. 88-byte preamble
//! (zero + magic + 64-byte name + ver + build + 8 ignored)
//! followed by a stream of (u32 type, u32 length, payload, pad)
//! TLV records. Attacker-controllable firmware bytes.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

use core::{ptr, slice};

const MAGIC: u32 = 0x0A4C5749; // "IWL\n" LE
const HEADER_BYTES: u32 = 88;
const HUMAN_READABLE_LEN: usize = 64;

// TLV identifiers (subset).
const TLV_INST: u32 = 1;
const TLV_DATA: u32 = 2;
const TLV_INIT: u32 = 3;
const TLV_INIT_DATA: u32 = 4;
const TLV_FLAGS: u32 = 18;
const TLV_SEC_RT: u32 = 19;
const TLV_SECURE_SEC_RT: u32 = 24;
const TLV_NUM_OF_CPU: u32 = 27;
const TLV_FW_VERSION: u32 = 36;
const TLV_PHY_SKU: u32 = 23;
const TLV_HW_TYPE: u32 = 58;

const RESULT_OK: i32 = 0;
const RESULT_INVALID_ARG: i32 = 1;
const RESULT_CORRUPT: i32 = 2;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosIwlFwSection {
    pub data: *const u8,
    pub size: u32,
    pub _pad: u32,
}

#[repr(C)]
pub struct DuetosIwlFirmwareParsed {
    pub valid: bool,
    pub _pad0: [u8; 3],
    pub human_readable: [u8; HUMAN_READABLE_LEN + 1],
    pub _pad1: [u8; 3],
    pub ver_packed: u32,
    pub build: u32,
    pub inst: DuetosIwlFwSection,
    pub data: DuetosIwlFwSection,
    pub init: DuetosIwlFwSection,
    pub init_data: DuetosIwlFwSection,
    pub sec_rt_first: DuetosIwlFwSection,
    pub sec_rt_count: u32,
    pub flags: u32,
    pub num_of_cpu: u32,
    pub fw_version: u32,
    pub phy_sku: u32,
    pub hw_type: u32,
    pub total_records: u32,
    pub unknown_records: u32,
    pub walked_bytes: u32,
    pub invalid_records: u32,
}

fn read_le32(buf: &[u8], off: usize) -> u32 {
    u32::from(buf[off])
        | (u32::from(buf[off + 1]) << 8)
        | (u32::from(buf[off + 2]) << 16)
        | (u32::from(buf[off + 3]) << 24)
}

fn round_up_4(v: u32) -> u32 {
    (v + 3) & !3u32
}

fn copy_human_readable(dst: &mut [u8; HUMAN_READABLE_LEN + 1], src: &[u8]) {
    let n = src.len().min(HUMAN_READABLE_LEN);
    dst[..n].copy_from_slice(&src[..n]);
    // NUL-terminate.
    dst[HUMAN_READABLE_LEN] = 0;
    // Also NUL after the first NUL byte, mirroring the C++ side
    // (which copies up to 64 then writes a NUL at [64]).
}

fn parse_inner(blob: &[u8], blob_ptr: *const u8, parsed: &mut DuetosIwlFirmwareParsed) -> i32 {
    if (blob.len() as u32) < HEADER_BYTES {
        return RESULT_INVALID_ARG;
    }

    let zero_word = read_le32(blob, 0);
    let magic = read_le32(blob, 4);
    if zero_word != 0 || magic != MAGIC {
        return RESULT_CORRUPT;
    }

    copy_human_readable(&mut parsed.human_readable, &blob[8..8 + HUMAN_READABLE_LEN]);
    parsed.ver_packed = read_le32(blob, 8 + HUMAN_READABLE_LEN);
    parsed.build = read_le32(blob, 8 + HUMAN_READABLE_LEN + 4);

    let mut off: u32 = HEADER_BYTES;
    while (off as u64 + 8) <= (blob.len() as u64) {
        let off_u = off as usize;
        let r_type = read_le32(blob, off_u);
        let length = read_le32(blob, off_u + 4);
        let payload_off = match off.checked_add(8) {
            Some(v) => v,
            None => {
                parsed.invalid_records += 1;
                return RESULT_CORRUPT;
            }
        };

        // Bound check via checked arithmetic.
        let end = match (payload_off as u64).checked_add(length as u64) {
            Some(v) => v,
            None => {
                parsed.invalid_records += 1;
                return RESULT_CORRUPT;
            }
        };
        if length as u64 > blob.len() as u64 || end > blob.len() as u64 {
            parsed.invalid_records += 1;
            return RESULT_CORRUPT;
        }

        parsed.total_records += 1;
        // SAFETY: payload_off in bounds (checked above).
        let payload_ptr = unsafe { blob_ptr.add(payload_off as usize) };
        let payload_off_u = payload_off as usize;

        match r_type {
            TLV_INST => {
                parsed.inst = DuetosIwlFwSection {
                    data: payload_ptr,
                    size: length,
                    _pad: 0,
                };
            }
            TLV_DATA => {
                parsed.data = DuetosIwlFwSection {
                    data: payload_ptr,
                    size: length,
                    _pad: 0,
                };
            }
            TLV_INIT => {
                parsed.init = DuetosIwlFwSection {
                    data: payload_ptr,
                    size: length,
                    _pad: 0,
                };
            }
            TLV_INIT_DATA => {
                parsed.init_data = DuetosIwlFwSection {
                    data: payload_ptr,
                    size: length,
                    _pad: 0,
                };
            }
            TLV_SEC_RT | TLV_SECURE_SEC_RT => {
                if parsed.sec_rt_count == 0 {
                    parsed.sec_rt_first = DuetosIwlFwSection {
                        data: payload_ptr,
                        size: length,
                        _pad: 0,
                    };
                }
                parsed.sec_rt_count += 1;
            }
            TLV_FLAGS => {
                if length >= 4 {
                    parsed.flags = read_le32(blob, payload_off_u);
                }
            }
            TLV_NUM_OF_CPU => {
                if length >= 4 {
                    parsed.num_of_cpu = read_le32(blob, payload_off_u);
                }
            }
            TLV_FW_VERSION => {
                if length >= 4 {
                    parsed.fw_version = read_le32(blob, payload_off_u);
                }
            }
            TLV_PHY_SKU => {
                if length >= 4 {
                    parsed.phy_sku = read_le32(blob, payload_off_u);
                }
            }
            TLV_HW_TYPE => {
                if length >= 4 {
                    parsed.hw_type = read_le32(blob, payload_off_u);
                }
            }
            _ => {
                parsed.unknown_records += 1;
            }
        }

        // Advance past payload, then up to dword boundary.
        let advance = match 8u32.checked_add(round_up_4(length)) {
            Some(v) => v,
            None => {
                parsed.invalid_records += 1;
                return RESULT_CORRUPT;
            }
        };
        off = match off.checked_add(advance) {
            Some(v) => v,
            None => {
                parsed.invalid_records += 1;
                return RESULT_CORRUPT;
            }
        };
    }

    parsed.walked_bytes = off;
    parsed.valid = parsed.total_records > 0;
    RESULT_OK
}

/// # Safety
/// `blob` valid for `blob_size` bytes or null; `parsed` writable.
#[no_mangle]
pub unsafe extern "C" fn duetos_iwlwifi_fw_parse(
    blob: *const u8,
    blob_size: u32,
    parsed: *mut DuetosIwlFirmwareParsed,
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
    use alloc::boxed::Box;
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;

    fn build_blob(records: &[(u32, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_le_bytes()); // zero
        buf.extend_from_slice(&MAGIC.to_le_bytes()); // magic
        let mut name = [0u8; HUMAN_READABLE_LEN];
        for (i, b) in b"test-firmware".iter().enumerate() {
            name[i] = *b;
        }
        buf.extend_from_slice(&name);
        buf.extend_from_slice(&0x12345678u32.to_le_bytes()); // ver
        buf.extend_from_slice(&0xABCDu32.to_le_bytes()); // build
        buf.extend_from_slice(&[0u8; 8]); // 8-byte ignore
        assert_eq!(buf.len(), HEADER_BYTES as usize);
        for (t, payload) in records {
            buf.extend_from_slice(&t.to_le_bytes());
            buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            buf.extend_from_slice(payload);
            // Pad to dword boundary.
            while buf.len() % 4 != 0 {
                buf.push(0);
            }
        }
        buf
    }

    fn parse(buf: &[u8]) -> (i32, Box<DuetosIwlFirmwareParsed>) {
        let mut p: Box<DuetosIwlFirmwareParsed> = unsafe { Box::new(core::mem::zeroed::<DuetosIwlFirmwareParsed>()) };
        let r = unsafe { duetos_iwlwifi_fw_parse(buf.as_ptr(), buf.len() as u32, p.as_mut() as *mut _) };
        (r, p)
    }

    #[test]
    fn multi_record_happy_path() {
        let inst_data = vec![0xAAu8; 32];
        let data_data = vec![0xBBu8; 16];
        let buf = build_blob(&[
            (TLV_INST, &inst_data),
            (TLV_DATA, &data_data),
            (TLV_FW_VERSION, &0xCAFEBABEu32.to_le_bytes()),
            (TLV_NUM_OF_CPU, &2u32.to_le_bytes()),
        ]);
        let (r, p) = parse(&buf);
        assert_eq!(r, RESULT_OK);
        assert!(p.valid);
        assert_eq!(p.total_records, 4);
        assert_eq!(p.inst.size, 32);
        assert_eq!(p.data.size, 16);
        assert_eq!(p.fw_version, 0xCAFEBABE);
        assert_eq!(p.num_of_cpu, 2);
        assert_eq!(p.ver_packed, 0x12345678);
        // human_readable should contain "test-firmware".
        let name_bytes = &p.human_readable[..13];
        assert_eq!(name_bytes, b"test-firmware");
    }

    #[test]
    fn bad_magic_rejects() {
        let mut buf = build_blob(&[(TLV_INST, &[0; 16])]);
        buf[4..8].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        let (r, _) = parse(&buf);
        assert_eq!(r, RESULT_CORRUPT);
    }

    #[test]
    fn nonzero_first_word_rejects() {
        let mut buf = build_blob(&[(TLV_INST, &[0; 16])]);
        buf[0] = 0xFF;
        let (r, _) = parse(&buf);
        assert_eq!(r, RESULT_CORRUPT);
    }

    #[test]
    fn short_header_rejects() {
        let buf = [0u8; 16];
        let (r, _) = parse(&buf);
        assert_eq!(r, RESULT_INVALID_ARG);
    }

    #[test]
    fn tlv_length_overflow_rejects() {
        // Build a valid header then a TLV with declared length > blob.
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&MAGIC.to_le_bytes());
        buf.extend_from_slice(&[0u8; HUMAN_READABLE_LEN]);
        buf.extend_from_slice(&[0u8; 4 + 4 + 8]);
        // TLV with massive declared length.
        buf.extend_from_slice(&TLV_INST.to_le_bytes());
        buf.extend_from_slice(&0xFFFFFF00u32.to_le_bytes());
        let (r, p) = parse(&buf);
        assert_eq!(r, RESULT_CORRUPT);
        assert!(p.invalid_records >= 1);
    }

    #[test]
    fn unknown_tlv_counted_not_rejected() {
        let buf = build_blob(&[(0x9999, &[0u8; 8])]);
        let (r, p) = parse(&buf);
        assert_eq!(r, RESULT_OK);
        assert_eq!(p.unknown_records, 1);
    }

    #[test]
    fn sec_rt_multi_records() {
        let buf = build_blob(&[
            (TLV_SEC_RT, &[1u8; 16]),
            (TLV_SEC_RT, &[2u8; 32]),
            (TLV_SECURE_SEC_RT, &[3u8; 8]),
        ]);
        let (r, p) = parse(&buf);
        assert_eq!(r, RESULT_OK);
        assert_eq!(p.sec_rt_count, 3);
        assert_eq!(p.sec_rt_first.size, 16); // first one wins
    }
}
