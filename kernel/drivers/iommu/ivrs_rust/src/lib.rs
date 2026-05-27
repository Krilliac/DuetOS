//! DuetOS AMD-Vi IVRS (I/O Virtualization Reporting Structure)
//! ACPI-table parser.
//!
//! AMD's analogue of Intel's DMAR. Layout (AMD IOMMU spec §5.2):
//!
//!   bytes 0..35    : standard 36-byte ACPI SDT header (signature
//!                    "IVRS" + length + checksum + ...)
//!   bytes 36..39   : IVinfo — capability flags (PASmax / PA size /
//!                    VA size / EFR support / HtAtsResv)
//!   bytes 40..47   : reserved
//!   bytes 48..     : array of variable-length IVHD / IVMD blocks.
//!
//! Each block starts with a 4-byte common header:
//!   bytes 0..0  : type (0x10=IVHD-fixed, 0x11=IVHD-extended,
//!                       0x40=IVHD-full, 0x20/0x21/0x22=IVMD)
//!   bytes 1..1  : flags
//!   bytes 2..3  : length (LE16, includes the 4-byte header)
//!
//! IVHD (type 0x10) fixed layout:
//!   bytes 0..3   : common header (type=0x10)
//!   bytes 4..5   : device_id (BDF) of IOMMU
//!   bytes 6..7   : capability_offset (LE16)
//!   bytes 8..15  : iommu_base_address (LE64)
//!   bytes 16..17 : pci_segment (LE16)
//!   bytes 18..19 : iommu_info (LE16; MSI MSINum etc.)
//!   bytes 20..23 : feature_information (LE32)
//!   bytes 24..   : device entries (variable; we skip in v0)
//!
//! IVHD type 0x11 / 0x40 extend with attributes (LE32 at offset 20),
//! efr_register_image (LE64 at offset 24), reserved (LE64 at offset
//! 32), then device entries at offset 40. We parse the common
//! prefix (base_address, pci_segment, flags) for all three types
//! and capture the extended IVHD's EFR image when present so the
//! enable slice can avoid an MMIO round-trip to read the same bits.
//!
//! IVMD layout (types 0x20/0x21/0x22):
//!   bytes 0..3   : common header
//!   bytes 4..5   : device_id range (for 0x21=single, 0x22=range)
//!   bytes 6..7   : aux_data (LE16)
//!   bytes 8..15  : reserved
//!   bytes 16..23 : start_address (LE64) — region base
//!   bytes 24..31 : memory_length (LE64) — bytes covered
//!
//! Sentinels emitted on parse failure:
//!   - `parse_ivrs` returns `ok=false` on bad signature, table-
//!     length mismatch, or header that doesn't fit. Caller MUST
//!     check `ok` before consuming any of the returned fields.
//!   - Per-entry overflow inside the structure loop terminates
//!     the loop and returns `ok=true` with whatever entries were
//!     decoded — partial data is better than none.

#![no_std]

#[cfg(test)]
extern crate alloc;

use core::ptr;
use core::slice;

pub const IVRS_TYPE_IVHD_FIXED: u8 = 0x10;
pub const IVRS_TYPE_IVHD_EXTENDED: u8 = 0x11;
pub const IVRS_TYPE_IVHD_FULL: u8 = 0x40;
pub const IVRS_TYPE_IVMD_ALL: u8 = 0x20;
pub const IVRS_TYPE_IVMD_SINGLE: u8 = 0x21;
pub const IVRS_TYPE_IVMD_RANGE: u8 = 0x22;

pub const IVRS_MAX_IVHDS: usize = 8;
pub const IVRS_MAX_IVMDS: usize = 8;

const IVRS_SDT_HEADER_BYTES: usize = 36;
const IVRS_HEADER_AFTER_SDT_BYTES: usize = 12; // IVinfo + reserved
const IVRS_BLOCK_COMMON_HEADER_BYTES: usize = 4;
const IVRS_IVHD_FIXED_BYTES: usize = 24;
const IVRS_IVHD_EXTENDED_BYTES: usize = 40;
const IVRS_IVMD_BYTES: usize = 32;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosIvrsIvhd {
    pub block_type: u8, // 0x10, 0x11, or 0x40
    pub flags: u8,
    pub device_id: u16,
    pub capability_offset: u16,
    pub pci_segment: u16,
    pub _pad0: u32,
    pub iommu_base_address: u64,
    pub iommu_info: u16,
    pub _pad1: [u8; 6],
    pub feature_information: u32, // type 0x10's last fixed field
    pub _pad2: u32,
    pub efr_register_image: u64, // valid for type 0x11/0x40; 0 for 0x10
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosIvrsIvmd {
    pub block_type: u8, // 0x20/0x21/0x22
    pub flags: u8,
    pub device_id_start: u16,
    pub aux_data: u16,
    pub _pad: [u8; 6],
    pub start_address: u64,
    pub memory_length: u64,
}

#[repr(C)]
pub struct DuetosIvrs {
    pub iv_info: u32,
    pub _pad0: u32,
    pub n_ivhds: u32,
    pub n_ivmds: u32,
    pub ivhds: [DuetosIvrsIvhd; IVRS_MAX_IVHDS],
    pub ivmds: [DuetosIvrsIvmd; IVRS_MAX_IVMDS],
    pub ok: u8,
    pub _pad1: [u8; 7],
}

impl Default for DuetosIvrs {
    fn default() -> Self {
        Self {
            iv_info: 0,
            _pad0: 0,
            n_ivhds: 0,
            n_ivmds: 0,
            ivhds: [DuetosIvrsIvhd::default(); IVRS_MAX_IVHDS],
            ivmds: [DuetosIvrsIvmd::default(); IVRS_MAX_IVMDS],
            ok: 0,
            _pad1: [0; 8 - 1],
        }
    }
}

#[inline]
fn read_u16_le(buf: &[u8], off: usize) -> u16 {
    (buf[off] as u16) | ((buf[off + 1] as u16) << 8)
}

#[inline]
fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    (buf[off] as u32)
        | ((buf[off + 1] as u32) << 8)
        | ((buf[off + 2] as u32) << 16)
        | ((buf[off + 3] as u32) << 24)
}

#[inline]
fn read_u64_le(buf: &[u8], off: usize) -> u64 {
    let mut v: u64 = 0;
    for i in 0..8 {
        v |= (buf[off + i] as u64) << (i * 8);
    }
    v
}

pub fn parse_ivrs(buf: &[u8], out: &mut DuetosIvrs) -> bool {
    *out = DuetosIvrs::default();
    if buf.len() < IVRS_SDT_HEADER_BYTES + IVRS_HEADER_AFTER_SDT_BYTES {
        return false;
    }
    if &buf[0..4] != b"IVRS" {
        return false;
    }

    let table_len = read_u32_le(buf, 4);
    if (table_len as usize) > buf.len() {
        return false;
    }
    let walk_end = table_len as usize;

    out.iv_info = read_u32_le(buf, IVRS_SDT_HEADER_BYTES);

    let mut off = IVRS_SDT_HEADER_BYTES + IVRS_HEADER_AFTER_SDT_BYTES;

    let mut iter_cap = 256usize;
    while off + IVRS_BLOCK_COMMON_HEADER_BYTES <= walk_end && iter_cap > 0 {
        iter_cap -= 1;

        let ty = buf[off];
        let flags = buf[off + 1];
        let len = read_u16_le(buf, off + 2) as usize;
        if len < IVRS_BLOCK_COMMON_HEADER_BYTES || off + len > walk_end {
            break;
        }

        match ty {
            IVRS_TYPE_IVHD_FIXED | IVRS_TYPE_IVHD_EXTENDED | IVRS_TYPE_IVHD_FULL => {
                if len >= IVRS_IVHD_FIXED_BYTES && (out.n_ivhds as usize) < IVRS_MAX_IVHDS {
                    let i = out.n_ivhds as usize;
                    out.ivhds[i] = DuetosIvrsIvhd::default();
                    out.ivhds[i].block_type = ty;
                    out.ivhds[i].flags = flags;
                    out.ivhds[i].device_id = read_u16_le(buf, off + 4);
                    out.ivhds[i].capability_offset = read_u16_le(buf, off + 6);
                    out.ivhds[i].iommu_base_address = read_u64_le(buf, off + 8);
                    out.ivhds[i].pci_segment = read_u16_le(buf, off + 16);
                    out.ivhds[i].iommu_info = read_u16_le(buf, off + 18);
                    // Type 0x10 ends at +24 with feature_information at +20.
                    // Type 0x11/0x40 has attributes at +20, EFR at +24,
                    // reserved at +32, device entries at +40.
                    if ty == IVRS_TYPE_IVHD_FIXED {
                        out.ivhds[i].feature_information = read_u32_le(buf, off + 20);
                    } else if len >= IVRS_IVHD_EXTENDED_BYTES {
                        out.ivhds[i].feature_information = read_u32_le(buf, off + 20);
                        out.ivhds[i].efr_register_image = read_u64_le(buf, off + 24);
                    }
                    out.n_ivhds += 1;
                }
            }
            IVRS_TYPE_IVMD_ALL | IVRS_TYPE_IVMD_SINGLE | IVRS_TYPE_IVMD_RANGE => {
                if len >= IVRS_IVMD_BYTES && (out.n_ivmds as usize) < IVRS_MAX_IVMDS {
                    let i = out.n_ivmds as usize;
                    out.ivmds[i] = DuetosIvrsIvmd::default();
                    out.ivmds[i].block_type = ty;
                    out.ivmds[i].flags = flags;
                    out.ivmds[i].device_id_start = read_u16_le(buf, off + 4);
                    out.ivmds[i].aux_data = read_u16_le(buf, off + 6);
                    out.ivmds[i].start_address = read_u64_le(buf, off + 16);
                    out.ivmds[i].memory_length = read_u64_le(buf, off + 24);
                    out.n_ivmds += 1;
                }
            }
            _ => {
                // Unknown / device-specific block — skip without
                // parse-failing the table.
            }
        }

        off += len;
    }

    out.ok = 1;
    true
}

/// # Safety
///
/// `buf` must point to at least `len` readable bytes of an ACPI
/// table image. `out` must point to a writable `DuetosIvrs`.
#[no_mangle]
pub unsafe extern "C" fn duetos_ivrs_parse(buf: *const u8, len: usize, out: *mut DuetosIvrs) -> bool {
    if buf.is_null() || out.is_null() || len == 0 {
        return false;
    }
    // SAFETY: caller-supplied buf is valid for `len` readable
    // bytes; out is a writable DuetosIvrs.
    let slice_ref = unsafe { slice::from_raw_parts(buf, len) };
    let out_ref = unsafe { &mut *out };
    parse_ivrs(slice_ref, out_ref)
}

/// # Safety
///
/// `out` must point to a writable `DuetosIvrs`.
#[no_mangle]
pub unsafe extern "C" fn duetos_ivrs_zero(out: *mut DuetosIvrs) {
    if out.is_null() {
        return;
    }
    // SAFETY: caller-supplied out is a writable DuetosIvrs; the
    // struct has no drop glue (all fields are POD).
    unsafe { ptr::write(out, DuetosIvrs::default()) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    fn make_header() -> Vec<u8> {
        let mut h = vec![0u8; IVRS_SDT_HEADER_BYTES + IVRS_HEADER_AFTER_SDT_BYTES];
        h[0..4].copy_from_slice(b"IVRS");
        // IVinfo = 0x00010002 — distinct, non-trivial value
        h[IVRS_SDT_HEADER_BYTES..IVRS_SDT_HEADER_BYTES + 4].copy_from_slice(&0x00010002u32.to_le_bytes());
        h
    }

    fn push_ivhd_fixed(buf: &mut Vec<u8>, flags: u8, base: u64, segment: u16) {
        let start = buf.len();
        buf.resize(start + IVRS_IVHD_FIXED_BYTES, 0);
        buf[start] = IVRS_TYPE_IVHD_FIXED;
        buf[start + 1] = flags;
        buf[start + 2..start + 4].copy_from_slice(&(IVRS_IVHD_FIXED_BYTES as u16).to_le_bytes());
        // device_id, capability_offset stay 0
        buf[start + 8..start + 16].copy_from_slice(&base.to_le_bytes());
        buf[start + 16..start + 18].copy_from_slice(&segment.to_le_bytes());
    }

    fn push_ivhd_extended(buf: &mut Vec<u8>, flags: u8, base: u64, efr: u64) {
        let start = buf.len();
        buf.resize(start + IVRS_IVHD_EXTENDED_BYTES, 0);
        buf[start] = IVRS_TYPE_IVHD_EXTENDED;
        buf[start + 1] = flags;
        buf[start + 2..start + 4].copy_from_slice(&(IVRS_IVHD_EXTENDED_BYTES as u16).to_le_bytes());
        buf[start + 8..start + 16].copy_from_slice(&base.to_le_bytes());
        // attributes at +20, EFR at +24
        buf[start + 24..start + 32].copy_from_slice(&efr.to_le_bytes());
    }

    fn push_ivmd(buf: &mut Vec<u8>, base: u64, length: u64) {
        let start = buf.len();
        buf.resize(start + IVRS_IVMD_BYTES, 0);
        buf[start] = IVRS_TYPE_IVMD_ALL;
        buf[start + 2..start + 4].copy_from_slice(&(IVRS_IVMD_BYTES as u16).to_le_bytes());
        buf[start + 16..start + 24].copy_from_slice(&base.to_le_bytes());
        buf[start + 24..start + 32].copy_from_slice(&length.to_le_bytes());
    }

    fn patch_len(buf: &mut Vec<u8>) {
        let total = buf.len() as u32;
        buf[4..8].copy_from_slice(&total.to_le_bytes());
    }

    #[test]
    fn empty_ivrs_parses() {
        let mut buf = make_header();
        patch_len(&mut buf);
        let mut out = DuetosIvrs::default();
        assert!(parse_ivrs(&buf, &mut out));
        assert_eq!(out.iv_info, 0x00010002);
        assert_eq!(out.n_ivhds, 0);
        assert_eq!(out.n_ivmds, 0);
    }

    #[test]
    fn single_fixed_ivhd_captured() {
        let mut buf = make_header();
        push_ivhd_fixed(&mut buf, 0x01, 0xFEB80000, 0);
        patch_len(&mut buf);
        let mut out = DuetosIvrs::default();
        assert!(parse_ivrs(&buf, &mut out));
        assert_eq!(out.n_ivhds, 1);
        assert_eq!(out.ivhds[0].block_type, IVRS_TYPE_IVHD_FIXED);
        assert_eq!(out.ivhds[0].flags, 0x01);
        assert_eq!(out.ivhds[0].iommu_base_address, 0xFEB80000);
        assert_eq!(out.ivhds[0].pci_segment, 0);
        assert_eq!(out.ivhds[0].efr_register_image, 0); // type 0x10 has no EFR
    }

    #[test]
    fn extended_ivhd_captures_efr() {
        let mut buf = make_header();
        push_ivhd_extended(&mut buf, 0x02, 0xFEB80000, 0x123456789ABCDEFu64);
        patch_len(&mut buf);
        let mut out = DuetosIvrs::default();
        assert!(parse_ivrs(&buf, &mut out));
        assert_eq!(out.n_ivhds, 1);
        assert_eq!(out.ivhds[0].block_type, IVRS_TYPE_IVHD_EXTENDED);
        assert_eq!(out.ivhds[0].efr_register_image, 0x123456789ABCDEFu64);
    }

    #[test]
    fn ivhd_and_ivmd_together() {
        let mut buf = make_header();
        push_ivhd_fixed(&mut buf, 0, 0xFEB80000, 0);
        push_ivmd(&mut buf, 0xC0000, 0x10000);
        patch_len(&mut buf);
        let mut out = DuetosIvrs::default();
        assert!(parse_ivrs(&buf, &mut out));
        assert_eq!(out.n_ivhds, 1);
        assert_eq!(out.n_ivmds, 1);
        assert_eq!(out.ivmds[0].start_address, 0xC0000);
        assert_eq!(out.ivmds[0].memory_length, 0x10000);
    }

    #[test]
    fn bad_signature_rejected() {
        let mut buf = make_header();
        buf[0] = b'X';
        patch_len(&mut buf);
        let mut out = DuetosIvrs::default();
        assert!(!parse_ivrs(&buf, &mut out));
    }

    #[test]
    fn truncated_table_length_rejected() {
        let mut buf = make_header();
        push_ivhd_fixed(&mut buf, 0, 0xFEB80000, 0);
        let lying_len = (buf.len() + 64) as u32;
        buf[4..8].copy_from_slice(&lying_len.to_le_bytes());
        let mut out = DuetosIvrs::default();
        assert!(!parse_ivrs(&buf, &mut out));
    }

    #[test]
    fn zero_length_block_terminates_loop() {
        let mut buf = make_header();
        let start = buf.len();
        buf.resize(start + 8, 0);
        buf[start] = IVRS_TYPE_IVHD_FIXED;
        // length = 0 — would infinite-loop if we didn't break
        patch_len(&mut buf);
        let mut out = DuetosIvrs::default();
        assert!(parse_ivrs(&buf, &mut out));
        assert_eq!(out.n_ivhds, 0);
    }

    #[test]
    fn unknown_type_skipped() {
        let mut buf = make_header();
        let start = buf.len();
        buf.resize(start + 8, 0);
        buf[start] = 0x55; // unknown
        buf[start + 2..start + 4].copy_from_slice(&8u16.to_le_bytes());
        push_ivhd_fixed(&mut buf, 0, 0xFEB80000, 0);
        patch_len(&mut buf);
        let mut out = DuetosIvrs::default();
        assert!(parse_ivrs(&buf, &mut out));
        assert_eq!(out.n_ivhds, 1);
        assert_eq!(out.ivhds[0].iommu_base_address, 0xFEB80000);
    }

    #[test]
    fn ivhd_overflow_caps_at_max() {
        let mut buf = make_header();
        for i in 0..(IVRS_MAX_IVHDS + 4) {
            push_ivhd_fixed(&mut buf, 0, 0xFEB80000 + (i as u64) * 0x1000, 0);
        }
        patch_len(&mut buf);
        let mut out = DuetosIvrs::default();
        assert!(parse_ivrs(&buf, &mut out));
        assert_eq!(out.n_ivhds as usize, IVRS_MAX_IVHDS);
    }

    #[test]
    fn null_inputs_rejected() {
        let mut out = DuetosIvrs::default();
        unsafe {
            assert!(!duetos_ivrs_parse(core::ptr::null(), 64, &mut out));
            assert!(!duetos_ivrs_parse(b"IVRS".as_ptr(), 0, &mut out));
            assert!(!duetos_ivrs_parse(b"IVRS".as_ptr(), 64, core::ptr::null_mut()));
        }
    }
}
