//! DuetOS Intel VT-d DMAR (DMA Remapping Reporting) ACPI-table parser.
//!
//! The DMAR table is the firmware's description of every IOMMU in
//! the system + the reserved memory regions that must be identity-
//! mapped through them. Layout (Intel VT-d spec §8.1):
//!
//!   bytes 0..35    : standard 36-byte ACPI SDT header (signature
//!                    "DMAR" + length + checksum + ...)
//!   byte  36       : Host Address Width (HAW) — physical-address
//!                    width supported by the IOMMU on this platform.
//!                    `HAW + 1` is the number of bits the IOMMU
//!                    contexts must cover (39 = 40-bit / 1 TB,
//!                    48 = 49-bit / 512 TB, etc.).
//!   byte  37       : flags — bit 0 INTR_REMAP, bit 1 X2APIC_OPT_OUT,
//!                    bit 2 DMA_CTRL_PLATFORM_OPT_IN.
//!   bytes 38..47   : reserved.
//!   bytes 48..     : array of variable-length remapping structures.
//!
//! Each remapping structure starts with a 4-byte common header:
//!   bytes 0..1 : type (LE16)  — 0=DRHD, 1=RMRR, 2=ATSR, 3=RHSA,
//!                                4=ANDD, 5=SATC.
//!   bytes 2..3 : length (LE16, includes the 4-byte header).
//!
//! DRHD (DMA Remapping Hardware Unit Definition):
//!   bytes 0..3   : common header (type=0)
//!   byte  4      : flags — bit 0 INCLUDE_PCI_ALL (this IOMMU
//!                          owns every PCI device in the segment
//!                          NOT explicitly listed under another
//!                          DRHD), bit 1 ATS_REQUIRED.
//!   byte  5      : reserved
//!   bytes 6..7   : PCI segment number (LE16)
//!   bytes 8..15  : register base address (LE64) — the IOMMU MMIO base
//!   bytes 16..   : Device Scope structures (variable; we skip)
//!
//! RMRR (Reserved Memory Region Reporting):
//!   bytes 0..3   : common header (type=1)
//!   bytes 4..5   : reserved
//!   bytes 6..7   : PCI segment number (LE16)
//!   bytes 8..15  : base address (LE64) — start of reserved region
//!   bytes 16..23 : limit address (LE64) — end of reserved region
//!                  (inclusive — VT-d spec §8.4 is explicit)
//!   bytes 24..   : Device Scope structures (variable; we skip)
//!
//! Sentinels emitted on parse failure:
//!   - `parse_dmar` returns `ok=false` (an out-of-band failure
//!     signal — distinct from a successfully parsed but empty
//!     table). The caller must check this BEFORE consuming any
//!     of the returned fields.
//!   - Per-entry overflow inside the structure loop terminates
//!     the loop and returns `ok=true` with whatever entries were
//!     decoded up to that point — partial data is better than
//!     none, and a malformed late entry shouldn't poison the
//!     parsed prefix.

#![no_std]

#[cfg(test)]
extern crate alloc;

use core::ptr;
use core::slice;

pub const DMAR_TYPE_DRHD: u16 = 0;
pub const DMAR_TYPE_RMRR: u16 = 1;
pub const DMAR_TYPE_ATSR: u16 = 2;
pub const DMAR_TYPE_RHSA: u16 = 3;
pub const DMAR_TYPE_ANDD: u16 = 4;
pub const DMAR_TYPE_SATC: u16 = 5;

pub const DMAR_DRHD_FLAG_INCLUDE_PCI_ALL: u8 = 1 << 0;
pub const DMAR_DRHD_FLAG_ATS_REQUIRED: u8 = 1 << 1;

pub const DMAR_HEADER_FLAG_INTR_REMAP: u8 = 1 << 0;
pub const DMAR_HEADER_FLAG_X2APIC_OPT_OUT: u8 = 1 << 1;
pub const DMAR_HEADER_FLAG_DMA_CTRL_PLATFORM_OPT_IN: u8 = 1 << 2;

pub const DMAR_MAX_DRHDS: usize = 16;
pub const DMAR_MAX_RMRRS: usize = 16;

const DMAR_SDT_HEADER_BYTES: usize = 36;
const DMAR_HEADER_AFTER_SDT_BYTES: usize = 12; // HAW + flags + reserved
const DMAR_REMAP_COMMON_HEADER_BYTES: usize = 4;
const DMAR_DRHD_FIXED_BYTES: usize = 16;
const DMAR_RMRR_FIXED_BYTES: usize = 24;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosDmarDrhd {
    pub flags: u8,
    pub _pad0: u8,
    pub segment: u16,
    pub _pad1: u32,
    pub register_base: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosDmarRmrr {
    pub segment: u16,
    pub _pad: [u8; 6],
    pub base_address: u64,
    pub limit_address: u64,
}

#[repr(C)]
pub struct DuetosDmar {
    pub host_address_width: u8,
    pub flags: u8,
    pub _pad0: [u8; 2],
    pub n_drhds: u32,
    pub n_rmrrs: u32,
    pub drhds: [DuetosDmarDrhd; DMAR_MAX_DRHDS],
    pub rmrrs: [DuetosDmarRmrr; DMAR_MAX_RMRRS],
    pub ok: u8,
    pub _pad1: [u8; 7],
}

impl Default for DuetosDmar {
    fn default() -> Self {
        Self {
            host_address_width: 0,
            flags: 0,
            _pad0: [0; 2],
            n_drhds: 0,
            n_rmrrs: 0,
            drhds: [DuetosDmarDrhd::default(); DMAR_MAX_DRHDS],
            rmrrs: [DuetosDmarRmrr::default(); DMAR_MAX_RMRRS],
            ok: 0,
            _pad1: [0; 7],
        }
    }
}

#[inline]
fn read_u16_le(buf: &[u8], off: usize) -> u16 {
    (buf[off] as u16) | ((buf[off + 1] as u16) << 8)
}

#[inline]
fn read_u64_le(buf: &[u8], off: usize) -> u64 {
    let mut v: u64 = 0;
    for i in 0..8 {
        v |= (buf[off + i] as u64) << (i * 8);
    }
    v
}

pub fn parse_dmar(buf: &[u8], out: &mut DuetosDmar) -> bool {
    *out = DuetosDmar::default();
    if buf.len() < DMAR_SDT_HEADER_BYTES + DMAR_HEADER_AFTER_SDT_BYTES {
        return false;
    }
    if &buf[0..4] != b"DMAR" {
        return false;
    }

    // ACPI table `length` field at offset 4 must agree with the
    // buffer length the caller handed us. A firmware that lies
    // about its own table length is producing attacker-controlled
    // bounds; refuse rather than walk past the buffer end.
    let table_len = (buf[4] as u32) | ((buf[5] as u32) << 8) | ((buf[6] as u32) << 16) | ((buf[7] as u32) << 24);
    if (table_len as usize) > buf.len() {
        return false;
    }
    let walk_end = table_len as usize;

    out.host_address_width = buf[DMAR_SDT_HEADER_BYTES];
    out.flags = buf[DMAR_SDT_HEADER_BYTES + 1];

    let mut off = DMAR_SDT_HEADER_BYTES + DMAR_HEADER_AFTER_SDT_BYTES;

    // Each iteration consumes one remapping structure. Bounded by
    // the table length and a hard iteration cap so a circular /
    // malformed length field cannot spin the loop forever.
    let mut iter_cap = 256usize;
    while off + DMAR_REMAP_COMMON_HEADER_BYTES <= walk_end && iter_cap > 0 {
        iter_cap -= 1;

        let ty = read_u16_le(buf, off);
        let len = read_u16_le(buf, off + 2) as usize;
        // Length must be at least the common header and must not
        // walk us past the end of the table. A zero-length entry
        // would also infinitely loop — refuse it.
        if len < DMAR_REMAP_COMMON_HEADER_BYTES || off + len > walk_end {
            break;
        }

        match ty {
            DMAR_TYPE_DRHD => {
                if len >= DMAR_DRHD_FIXED_BYTES && (out.n_drhds as usize) < DMAR_MAX_DRHDS {
                    let i = out.n_drhds as usize;
                    out.drhds[i].flags = buf[off + 4];
                    out.drhds[i].segment = read_u16_le(buf, off + 6);
                    out.drhds[i].register_base = read_u64_le(buf, off + 8);
                    out.n_drhds += 1;
                }
            }
            DMAR_TYPE_RMRR => {
                if len >= DMAR_RMRR_FIXED_BYTES && (out.n_rmrrs as usize) < DMAR_MAX_RMRRS {
                    let i = out.n_rmrrs as usize;
                    out.rmrrs[i].segment = read_u16_le(buf, off + 6);
                    out.rmrrs[i].base_address = read_u64_le(buf, off + 8);
                    out.rmrrs[i].limit_address = read_u64_le(buf, off + 16);
                    out.n_rmrrs += 1;
                }
            }
            // ATSR, RHSA, ANDD, SATC: recognised but not parsed
            // by v0. Forward-compat — Intel may add more types in
            // a future spec rev; an unknown type is skipped, not
            // rejected.
            _ => {}
        }

        off += len;
    }

    out.ok = 1;
    true
}

/// # Safety
///
/// `buf` must point to at least `len` readable bytes of an ACPI
/// table image. `out` must point to a writable `DuetosDmar`.
#[no_mangle]
pub unsafe extern "C" fn duetos_dmar_parse(buf: *const u8, len: usize, out: *mut DuetosDmar) -> bool {
    if buf.is_null() || out.is_null() || len == 0 {
        return false;
    }
    // SAFETY: the function precondition guarantees `buf` is valid
    // for `len` readable bytes, and `out` is a writable
    // DuetosDmar. The two regions don't overlap (caller passes a
    // distinct out struct).
    let slice_ref = unsafe { slice::from_raw_parts(buf, len) };
    let out_ref = unsafe { &mut *out };
    parse_dmar(slice_ref, out_ref)
}

/// # Safety
///
/// `out` must point to a writable `DuetosDmar`.
#[no_mangle]
pub unsafe extern "C" fn duetos_dmar_zero(out: *mut DuetosDmar) {
    if out.is_null() {
        return;
    }
    // SAFETY: caller-supplied `out` is a writable DuetosDmar (see
    // function precondition). DuetosDmar has no drop glue (all
    // fields are POD), so overwriting via `ptr::write` is safe.
    unsafe { ptr::write(out, DuetosDmar::default()) };
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;

    fn make_header(table_len: u32) -> Vec<u8> {
        let mut h = vec![0u8; DMAR_SDT_HEADER_BYTES + DMAR_HEADER_AFTER_SDT_BYTES];
        h[0..4].copy_from_slice(b"DMAR");
        h[4..8].copy_from_slice(&table_len.to_le_bytes());
        h[DMAR_SDT_HEADER_BYTES] = 39; // HAW
        h[DMAR_SDT_HEADER_BYTES + 1] = DMAR_HEADER_FLAG_INTR_REMAP;
        h
    }

    fn push_drhd(buf: &mut Vec<u8>, flags: u8, segment: u16, base: u64) {
        let start = buf.len();
        buf.resize(start + DMAR_DRHD_FIXED_BYTES, 0);
        buf[start..start + 2].copy_from_slice(&DMAR_TYPE_DRHD.to_le_bytes());
        buf[start + 2..start + 4].copy_from_slice(&(DMAR_DRHD_FIXED_BYTES as u16).to_le_bytes());
        buf[start + 4] = flags;
        buf[start + 6..start + 8].copy_from_slice(&segment.to_le_bytes());
        buf[start + 8..start + 16].copy_from_slice(&base.to_le_bytes());
    }

    fn push_rmrr(buf: &mut Vec<u8>, segment: u16, base: u64, limit: u64) {
        let start = buf.len();
        buf.resize(start + DMAR_RMRR_FIXED_BYTES, 0);
        buf[start..start + 2].copy_from_slice(&DMAR_TYPE_RMRR.to_le_bytes());
        buf[start + 2..start + 4].copy_from_slice(&(DMAR_RMRR_FIXED_BYTES as u16).to_le_bytes());
        buf[start + 6..start + 8].copy_from_slice(&segment.to_le_bytes());
        buf[start + 8..start + 16].copy_from_slice(&base.to_le_bytes());
        buf[start + 16..start + 24].copy_from_slice(&limit.to_le_bytes());
    }

    #[test]
    fn empty_dmar_parses_no_entries() {
        let mut buf = make_header(0);
        let total = buf.len() as u32;
        buf[4..8].copy_from_slice(&total.to_le_bytes());
        let mut out = DuetosDmar::default();
        assert!(parse_dmar(&buf, &mut out));
        assert_eq!(out.host_address_width, 39);
        assert_eq!(out.flags, DMAR_HEADER_FLAG_INTR_REMAP);
        assert_eq!(out.n_drhds, 0);
        assert_eq!(out.n_rmrrs, 0);
    }

    #[test]
    fn single_drhd_captured() {
        let mut buf = make_header(0);
        push_drhd(&mut buf, DMAR_DRHD_FLAG_INCLUDE_PCI_ALL, 0, 0xFED90000);
        let total = buf.len() as u32;
        buf[4..8].copy_from_slice(&total.to_le_bytes());
        let mut out = DuetosDmar::default();
        assert!(parse_dmar(&buf, &mut out));
        assert_eq!(out.n_drhds, 1);
        assert_eq!(out.drhds[0].flags, DMAR_DRHD_FLAG_INCLUDE_PCI_ALL);
        assert_eq!(out.drhds[0].segment, 0);
        assert_eq!(out.drhds[0].register_base, 0xFED90000);
    }

    #[test]
    fn drhd_and_rmrr_in_order() {
        let mut buf = make_header(0);
        push_drhd(&mut buf, 0, 0, 0xFED90000);
        push_rmrr(&mut buf, 0, 0x000A0000, 0x000BFFFF);
        push_drhd(&mut buf, DMAR_DRHD_FLAG_INCLUDE_PCI_ALL, 0, 0xFED91000);
        let total = buf.len() as u32;
        buf[4..8].copy_from_slice(&total.to_le_bytes());
        let mut out = DuetosDmar::default();
        assert!(parse_dmar(&buf, &mut out));
        assert_eq!(out.n_drhds, 2);
        assert_eq!(out.drhds[1].flags, DMAR_DRHD_FLAG_INCLUDE_PCI_ALL);
        assert_eq!(out.drhds[1].register_base, 0xFED91000);
        assert_eq!(out.n_rmrrs, 1);
        assert_eq!(out.rmrrs[0].base_address, 0x000A0000);
        assert_eq!(out.rmrrs[0].limit_address, 0x000BFFFF);
    }

    #[test]
    fn bad_signature_rejected() {
        let mut buf = make_header(0);
        buf[0] = b'X';
        let total = buf.len() as u32;
        buf[4..8].copy_from_slice(&total.to_le_bytes());
        let mut out = DuetosDmar::default();
        assert!(!parse_dmar(&buf, &mut out));
    }

    #[test]
    fn truncated_table_length_rejected() {
        let mut buf = make_header(0);
        push_drhd(&mut buf, 0, 0, 0xFED90000);
        // Claim a table length larger than the actual buffer.
        let lying_len = (buf.len() + 64) as u32;
        buf[4..8].copy_from_slice(&lying_len.to_le_bytes());
        let mut out = DuetosDmar::default();
        assert!(!parse_dmar(&buf, &mut out));
    }

    #[test]
    fn zero_length_entry_terminates_loop() {
        let mut buf = make_header(0);
        // Hand-craft a zero-length remapping structure.
        let start = buf.len();
        buf.resize(start + 8, 0);
        buf[start..start + 2].copy_from_slice(&DMAR_TYPE_DRHD.to_le_bytes());
        // length = 0
        let total = buf.len() as u32;
        buf[4..8].copy_from_slice(&total.to_le_bytes());
        let mut out = DuetosDmar::default();
        assert!(parse_dmar(&buf, &mut out));
        assert_eq!(out.n_drhds, 0);
    }

    #[test]
    fn unknown_type_skipped_not_rejected() {
        let mut buf = make_header(0);
        let start = buf.len();
        buf.resize(start + 8, 0);
        buf[start..start + 2].copy_from_slice(&99u16.to_le_bytes()); // unknown type
        buf[start + 2..start + 4].copy_from_slice(&8u16.to_le_bytes()); // 8 bytes total
                                                                        // Now follow with a real DRHD.
        push_drhd(&mut buf, 0, 0, 0xFED90000);
        let total = buf.len() as u32;
        buf[4..8].copy_from_slice(&total.to_le_bytes());
        let mut out = DuetosDmar::default();
        assert!(parse_dmar(&buf, &mut out));
        assert_eq!(out.n_drhds, 1);
        assert_eq!(out.drhds[0].register_base, 0xFED90000);
    }

    #[test]
    fn drhd_overflow_caps_at_max() {
        let mut buf = make_header(0);
        for i in 0..(DMAR_MAX_DRHDS + 4) {
            push_drhd(&mut buf, 0, 0, 0xFED90000 + (i as u64) * 0x1000);
        }
        let total = buf.len() as u32;
        buf[4..8].copy_from_slice(&total.to_le_bytes());
        let mut out = DuetosDmar::default();
        assert!(parse_dmar(&buf, &mut out));
        assert_eq!(out.n_drhds as usize, DMAR_MAX_DRHDS);
    }

    #[test]
    fn null_inputs_rejected() {
        let mut out = DuetosDmar::default();
        unsafe {
            assert!(!duetos_dmar_parse(core::ptr::null(), 64, &mut out));
            assert!(!duetos_dmar_parse(b"DMAR".as_ptr(), 0, &mut out));
            assert!(!duetos_dmar_parse(b"DMAR".as_ptr(), 64, core::ptr::null_mut()));
        }
    }
}
