//! DuetOS ACPI table walker — **skeleton**.
//!
//! Foundation for future ACPI parsing. v0 covers two safe gates
//! that any ACPI consumer needs first: (1) the RSDP (Root System
//! Description Pointer) v1/v2 signature + checksum, and (2) the
//! generic 36-byte ACPI table header (signature + length +
//! checksum). FADT, MADT, SRAT, MCFG, and the AML interpreter
//! stay in C++ pending follow-up slices.
//!
//! No current C++ caller. The C++ side
//! (`kernel/acpi/acpi.cpp`) keeps its existing parsers.

#![no_std]

use core::{ptr, slice};

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosAcpiRsdp {
    pub revision: u8, // 0 = ACPI 1.0 RSDP (20 bytes), 2 = ACPI 2.0+ (36 bytes)
    pub _pad0: [u8; 3],
    pub rsdt_address: u32, // ACPI 1.0
    pub xsdt_address: u64, // ACPI 2.0+
    pub oem_id: [u8; 6],
    pub ok: u8,
    pub _pad1: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosAcpiTableHeader {
    pub signature: [u8; 4],
    pub length: u32,
    pub revision: u8,
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub oem_table_id: [u8; 8],
    pub oem_revision: u32,
    pub creator_id: [u8; 4],
    pub creator_revision: u32,
    pub ok: u8,
    pub _pad: [u8; 3],
}

const RSDP_SIGNATURE: &[u8; 8] = b"RSD PTR ";
const RSDP_V1_SIZE: usize = 20;
const RSDP_V2_SIZE: usize = 36;
const ACPI_TABLE_HEADER_SIZE: usize = 36;

fn slice_from_raw<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: FFI contract pins `ptr` as valid for `len` bytes.
    Some(unsafe { slice::from_raw_parts(ptr, len) })
}

fn out_init<'a, T: Default + Copy>(out: *mut T) -> Option<&'a mut T> {
    if out.is_null() {
        return None;
    }
    // SAFETY: FFI contract pins `out` as a writable T-sized region.
    unsafe {
        ptr::write(out, T::default());
        Some(&mut *out)
    }
}

/// Compute the ACPI 8-bit additive checksum: a valid table sums
/// to 0 mod 256.
fn checksum(buf: &[u8]) -> u8 {
    let mut acc: u8 = 0;
    for &b in buf {
        acc = acc.wrapping_add(b);
    }
    acc
}

#[inline]
fn load_u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

#[inline]
fn load_u64_le(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
}

fn parse_rsdp(buf: &[u8], out: &mut DuetosAcpiRsdp) -> bool {
    if buf.len() < RSDP_V1_SIZE {
        return false;
    }
    if &buf[..8] != RSDP_SIGNATURE {
        return false;
    }
    // ACPI 1.0 RSDP: 20 bytes, summed to zero mod 256.
    if checksum(&buf[..RSDP_V1_SIZE]) != 0 {
        return false;
    }
    out.oem_id.copy_from_slice(&buf[9..15]);
    out.revision = buf[15];
    out.rsdt_address = load_u32_le(buf, 16);
    if out.revision >= 2 {
        // ACPI 2.0+: extended structure, summed to zero across all 36 bytes.
        if buf.len() < RSDP_V2_SIZE {
            return false;
        }
        if checksum(&buf[..RSDP_V2_SIZE]) != 0 {
            return false;
        }
        out.xsdt_address = load_u64_le(buf, 24);
    }
    out.ok = 1;
    true
}

fn parse_table_header(buf: &[u8], out: &mut DuetosAcpiTableHeader) -> bool {
    if buf.len() < ACPI_TABLE_HEADER_SIZE {
        return false;
    }
    out.signature.copy_from_slice(&buf[0..4]);
    out.length = load_u32_le(buf, 4);
    out.revision = buf[8];
    out.checksum = buf[9];
    out.oem_id.copy_from_slice(&buf[10..16]);
    out.oem_table_id.copy_from_slice(&buf[16..24]);
    out.oem_revision = load_u32_le(buf, 24);
    out.creator_id.copy_from_slice(&buf[28..32]);
    out.creator_revision = load_u32_le(buf, 32);
    // length must be at least the header size and fit in `buf`.
    if (out.length as usize) < ACPI_TABLE_HEADER_SIZE {
        return false;
    }
    if (out.length as usize) > buf.len() {
        return false;
    }
    // Whole-table checksum sums to 0 mod 256.
    if checksum(&buf[..out.length as usize]) != 0 {
        return false;
    }
    out.ok = 1;
    true
}

#[no_mangle]
pub extern "C" fn duetos_acpi_parse_rsdp(buf: *const u8, len: usize, out: *mut DuetosAcpiRsdp) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_rsdp(slice, dst)
}

#[no_mangle]
pub extern "C" fn duetos_acpi_parse_table_header(buf: *const u8, len: usize, out: *mut DuetosAcpiTableHeader) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_table_header(slice, dst)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rsdp_v1() -> [u8; 20] {
        let mut buf = [0u8; 20];
        buf[..8].copy_from_slice(RSDP_SIGNATURE);
        buf[9..15].copy_from_slice(b"DUETOS");
        buf[15] = 0; // revision
        buf[16..20].copy_from_slice(&0xCAFE_BABEu32.to_le_bytes()); // RSDT
                                                                    // Set checksum byte (offset 8) so the sum is zero.
        let cs = checksum(&buf);
        buf[8] = (256u16 - cs as u16) as u8;
        buf
    }

    fn make_rsdp_v2() -> [u8; 36] {
        let mut buf = [0u8; 36];
        buf[..8].copy_from_slice(RSDP_SIGNATURE);
        buf[9..15].copy_from_slice(b"DUETOS");
        buf[15] = 2; // revision
        buf[16..20].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        // Length field at offset 20.
        buf[20..24].copy_from_slice(&36u32.to_le_bytes());
        buf[24..32].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes()); // XSDT
                                                                              // First, fix the v1 portion checksum (offset 8 covers 0..20).
        let cs1 = checksum(&buf[..20]);
        buf[8] = (256u16 - cs1 as u16) as u8;
        // Then the full v2 checksum lives at offset 32.
        let cs2 = checksum(&buf);
        buf[32] = (256u16 - cs2 as u16) as u8;
        buf
    }

    #[test]
    fn rsdp_v1_passes() {
        let buf = make_rsdp_v1();
        let mut out = DuetosAcpiRsdp::default();
        assert!(parse_rsdp(&buf, &mut out));
        assert_eq!(out.revision, 0);
        assert_eq!(out.rsdt_address, 0xCAFE_BABE);
        assert_eq!(out.ok, 1);
    }

    #[test]
    fn rsdp_v2_passes() {
        let buf = make_rsdp_v2();
        let mut out = DuetosAcpiRsdp::default();
        assert!(parse_rsdp(&buf, &mut out));
        assert_eq!(out.revision, 2);
        assert_eq!(out.xsdt_address, 0x1122_3344_5566_7788);
    }

    #[test]
    fn rsdp_bad_signature_rejects() {
        let mut buf = make_rsdp_v1();
        buf[0] = b'X';
        let mut out = DuetosAcpiRsdp::default();
        assert!(!parse_rsdp(&buf, &mut out));
    }

    #[test]
    fn rsdp_bad_checksum_rejects() {
        let mut buf = make_rsdp_v1();
        buf[19] ^= 0xff;
        let mut out = DuetosAcpiRsdp::default();
        assert!(!parse_rsdp(&buf, &mut out));
    }

    fn make_table_header(sig: &[u8; 4], length: u32) -> alloc::vec::Vec<u8> {
        let mut buf = alloc::vec![0u8; length as usize];
        buf[0..4].copy_from_slice(sig);
        buf[4..8].copy_from_slice(&length.to_le_bytes());
        buf[8] = 1; // revision
        buf[10..16].copy_from_slice(b"DUETOS");
        buf[16..24].copy_from_slice(b"DUETTBL1");
        buf[24..28].copy_from_slice(&1u32.to_le_bytes());
        buf[28..32].copy_from_slice(b"DUET");
        buf[32..36].copy_from_slice(&1u32.to_le_bytes());
        // Fix checksum (byte 9) so the whole table sums to 0.
        let cs = checksum(&buf);
        buf[9] = (256u16 - cs as u16) as u8;
        buf
    }

    extern crate alloc;

    #[test]
    fn table_header_passes() {
        let buf = make_table_header(b"FACP", 64);
        let mut out = DuetosAcpiTableHeader::default();
        assert!(parse_table_header(&buf, &mut out));
        assert_eq!(&out.signature, b"FACP");
        assert_eq!(out.length, 64);
        assert_eq!(out.revision, 1);
        assert_eq!(out.ok, 1);
    }

    #[test]
    fn table_header_short_length_rejects() {
        let mut buf = make_table_header(b"FACP", 64);
        // Force length below header size.
        buf[4..8].copy_from_slice(&30u32.to_le_bytes());
        let mut out = DuetosAcpiTableHeader::default();
        assert!(!parse_table_header(&buf, &mut out));
    }

    #[test]
    fn table_header_bad_checksum_rejects() {
        let mut buf = make_table_header(b"FACP", 64);
        buf[40] ^= 0xff;
        let mut out = DuetosAcpiTableHeader::default();
        assert!(!parse_table_header(&buf, &mut out));
    }

    #[test]
    fn table_header_too_short_rejects() {
        let buf = [0u8; 30];
        let mut out = DuetosAcpiTableHeader::default();
        assert!(!parse_table_header(&buf, &mut out));
    }
}
