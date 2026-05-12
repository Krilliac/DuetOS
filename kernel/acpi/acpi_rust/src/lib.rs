//! DuetOS ACPI table walker.
//!
//! Production crate. Covers:
//!   - RSDP v1 / v2 signature + checksum.
//!   - 36-byte ACPI table header validation.
//!   - MADT entry header walker (type + length).
//!   - FADT body decoder (SCI vector, reset reg, PM1 control, DSDT).
//!   - MCFG entry decoder (segment, bus range, ECAM base).
//!   - HPET descriptor table decoder.
//!   - SRAT memory-affinity entry decoder.
//!
//! The C++ wrapper at `kernel/acpi/acpi.cpp` delegates byte parsing
//! to this crate. AML execution + table lookup walks (XSDT/RSDT)
//! stay in C++.

#![no_std]

use core::{ptr, slice};

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosAcpiRsdp {
    pub revision: u8,
    pub _pad0: [u8; 3],
    pub rsdt_address: u32,
    pub xsdt_address: u64,
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

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosAcpiMadtEntryHeader {
    pub entry_type: u8,
    pub length: u8,
    pub _pad: u16,
    pub ok: u8,
    pub _pad1: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosAcpiFadt {
    pub firmware_ctrl: u32,
    pub dsdt: u32,
    pub sci_int: u16,
    pub _pad0: u16,
    pub smi_cmd: u32,
    pub pm1a_evt_blk: u32,
    pub pm1a_cnt_blk: u32,
    pub pm1b_cnt_blk: u32,
    pub pm_tmr_blk: u32,
    pub pm1_cnt_len: u8,
    pub _pad1: [u8; 3],
    pub flags: u32,
    pub reset_supported: u8,
    pub reset_address_space_id: u8,
    pub _pad2: [u8; 2],
    pub reset_address: u64,
    pub reset_value: u8,
    pub _pad3: [u8; 3],
    pub ok: u8,
    pub _pad4: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosAcpiMcfgEntry {
    pub base_address: u64,
    pub segment_group: u16,
    pub start_bus: u8,
    pub end_bus: u8,
    pub _pad: u32,
    pub ok: u8,
    pub _pad2: [u8; 7],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosAcpiHpet {
    pub event_timer_block_id: u32,
    pub base_address_space_id: u8,
    pub _pad0: [u8; 3],
    pub base_address: u64,
    pub hpet_number: u8,
    pub _pad1: u8,
    pub main_counter_minimum: u16,
    pub page_protection_oem: u8,
    pub _pad2: [u8; 3],
    pub timer_count: u8,
    pub counter_width: u8,
    pub _pad3: [u8; 2],
    pub ok: u8,
    pub _pad4: [u8; 7],
}

/// SRAT Memory Affinity structure (subtable type 1).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosAcpiSratMemoryAffinity {
    pub proximity_domain: u32,
    pub _pad0: u32,
    pub base_address: u64,
    pub length: u64,
    pub flags: u32,
    pub enabled: u8,
    pub hot_pluggable: u8,
    pub non_volatile: u8,
    pub _pad1: u8,
    pub ok: u8,
    pub _pad2: [u8; 7],
}

const RSDP_SIGNATURE: &[u8; 8] = b"RSD PTR ";
const RSDP_V1_SIZE: usize = 20;
const RSDP_V2_SIZE: usize = 36;
const ACPI_TABLE_HEADER_SIZE: usize = 36;

pub const ACPI_MADT_TYPE_LAPIC: u8 = 0;
pub const ACPI_MADT_TYPE_IOAPIC: u8 = 1;
pub const ACPI_MADT_TYPE_INT_SOURCE_OVERRIDE: u8 = 2;
pub const ACPI_MADT_TYPE_LAPIC_ADDR_OVERRIDE: u8 = 5;

const ACPI_FADT_FLAG_RESET_REG_SUP: u32 = 1 << 10;
/// Generic Address Structure: system memory (MMIO). Currently
/// referenced from tests; kept public so consumers don't
/// hard-code the magic number.
pub const ACPI_GENERIC_ADDR_SPACE_MEMORY: u8 = 0;

pub const ACPI_SRAT_TYPE_MEMORY_AFFINITY: u8 = 1;

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

fn checksum(buf: &[u8]) -> u8 {
    let mut acc: u8 = 0;
    for &b in buf {
        acc = acc.wrapping_add(b);
    }
    acc
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
    if checksum(&buf[..RSDP_V1_SIZE]) != 0 {
        return false;
    }
    out.oem_id.copy_from_slice(&buf[9..15]);
    out.revision = buf[15];
    out.rsdt_address = load_u32_le(buf, 16);
    if out.revision >= 2 {
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
    if (out.length as usize) < ACPI_TABLE_HEADER_SIZE {
        return false;
    }
    if (out.length as usize) > buf.len() {
        return false;
    }
    if checksum(&buf[..out.length as usize]) != 0 {
        return false;
    }
    out.ok = 1;
    true
}

fn parse_madt_entry_header(buf: &[u8], off: usize, out: &mut DuetosAcpiMadtEntryHeader) -> bool {
    if off + 2 > buf.len() {
        return false;
    }
    let entry_type = buf[off];
    let length = buf[off + 1];
    if length < 2 {
        return false;
    }
    if off + length as usize > buf.len() {
        return false;
    }
    out.entry_type = entry_type;
    out.length = length;
    out.ok = 1;
    true
}

fn parse_fadt(buf: &[u8], out: &mut DuetosAcpiFadt) -> bool {
    // FADT is at least 116 bytes through the reset register block.
    // Earlier FADTs (ACPI 1.0) are 116 bytes; we read reset_reg
    // (offset 116) + reset_value (offset 128) defensively.
    // We treat anything < 116 as a malformed table.
    if buf.len() < ACPI_TABLE_HEADER_SIZE + 80 {
        return false;
    }
    // Body starts after the 36-byte ACPI table header.
    let body = &buf[ACPI_TABLE_HEADER_SIZE..];
    out.firmware_ctrl = load_u32_le(body, 0);
    out.dsdt = load_u32_le(body, 4);
    // body[8] reserved, body[9] preferred_pm_profile.
    out.sci_int = load_u16_le(body, 10);
    out.smi_cmd = load_u32_le(body, 12);
    out.pm1a_evt_blk = load_u32_le(body, 20);
    out.pm1a_cnt_blk = load_u32_le(body, 28);
    out.pm1b_cnt_blk = load_u32_le(body, 32);
    out.pm_tmr_blk = load_u32_le(body, 40);
    out.pm1_cnt_len = body[57];
    out.flags = load_u32_le(body, 76);
    if (out.flags & ACPI_FADT_FLAG_RESET_REG_SUP) != 0 {
        // Reset reg is a 12-byte GenericAddress at body offset 80.
        if body.len() > 80 + 12 {
            out.reset_supported = 1;
            out.reset_address_space_id = body[80];
            out.reset_address = load_u64_le(body, 80 + 4);
            out.reset_value = body[80 + 12];
        }
    }
    out.ok = 1;
    true
}

fn parse_mcfg_entry(buf: &[u8], idx: u32, out: &mut DuetosAcpiMcfgEntry) -> bool {
    // MCFG table body: 8-byte reserved + N×16-byte entries.
    // `buf` is the entire MCFG table including the 36-byte header.
    let entries_start = ACPI_TABLE_HEADER_SIZE + 8;
    if buf.len() < entries_start {
        return false;
    }
    let off = entries_start + (idx as usize) * 16;
    if off + 16 > buf.len() {
        return false;
    }
    out.base_address = load_u64_le(buf, off);
    out.segment_group = load_u16_le(buf, off + 8);
    out.start_bus = buf[off + 10];
    out.end_bus = buf[off + 11];
    out.ok = 1;
    true
}

fn parse_hpet(buf: &[u8], out: &mut DuetosAcpiHpet) -> bool {
    // HPET table body starts after 36-byte header:
    //   [+0]   u32 event_timer_block_id
    //   [+4]   GenericAddress (12 bytes)
    //   [+16]  u8 hpet_number
    //   [+17]  u16 main_counter_minimum
    //   [+19]  u8 page_protection_oem
    if buf.len() < ACPI_TABLE_HEADER_SIZE + 20 {
        return false;
    }
    let body = &buf[ACPI_TABLE_HEADER_SIZE..];
    out.event_timer_block_id = load_u32_le(body, 0);
    out.base_address_space_id = body[4];
    out.base_address = load_u64_le(body, 4 + 4);
    out.hpet_number = body[16];
    out.main_counter_minimum = load_u16_le(body, 17);
    out.page_protection_oem = body[19];
    // Derived: timer count = (block_id[12:8] + 1).
    let num = (out.event_timer_block_id & 0x1F00) >> 8;
    out.timer_count = (num + 1) as u8;
    out.counter_width = if (out.event_timer_block_id & (1 << 13)) != 0 {
        64
    } else {
        32
    };
    out.ok = 1;
    true
}

fn parse_srat_memory_affinity(buf: &[u8], off: usize, out: &mut DuetosAcpiSratMemoryAffinity) -> bool {
    // SRAT Memory Affinity structure (type 1) is 40 bytes.
    if off + 40 > buf.len() {
        return false;
    }
    let entry_type = buf[off];
    let length = buf[off + 1];
    if entry_type != ACPI_SRAT_TYPE_MEMORY_AFFINITY || length != 40 {
        return false;
    }
    out.proximity_domain = load_u32_le(buf, off + 2);
    // bytes 6..8 reserved
    out.base_address = load_u64_le(buf, off + 8);
    out.length = load_u64_le(buf, off + 16);
    // bytes 24..28 reserved
    out.flags = load_u32_le(buf, off + 28);
    // bytes 32..40 reserved
    out.enabled = if (out.flags & 0x1) != 0 { 1 } else { 0 };
    out.hot_pluggable = if (out.flags & 0x2) != 0 { 1 } else { 0 };
    out.non_volatile = if (out.flags & 0x4) != 0 { 1 } else { 0 };
    out.ok = 1;
    true
}

// ---------- FFI ----------

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

#[no_mangle]
pub extern "C" fn duetos_acpi_parse_madt_entry_header(
    buf: *const u8,
    len: usize,
    off: usize,
    out: *mut DuetosAcpiMadtEntryHeader,
) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_madt_entry_header(slice, off, dst)
}

#[no_mangle]
pub extern "C" fn duetos_acpi_parse_fadt(buf: *const u8, len: usize, out: *mut DuetosAcpiFadt) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_fadt(slice, dst)
}

#[no_mangle]
pub extern "C" fn duetos_acpi_parse_mcfg_entry(
    buf: *const u8,
    len: usize,
    idx: u32,
    out: *mut DuetosAcpiMcfgEntry,
) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_mcfg_entry(slice, idx, dst)
}

#[no_mangle]
pub extern "C" fn duetos_acpi_parse_hpet(buf: *const u8, len: usize, out: *mut DuetosAcpiHpet) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_hpet(slice, dst)
}

#[no_mangle]
pub extern "C" fn duetos_acpi_parse_srat_memory_affinity(
    buf: *const u8,
    len: usize,
    off: usize,
    out: *mut DuetosAcpiSratMemoryAffinity,
) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_srat_memory_affinity(slice, off, dst)
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;

    fn make_rsdp_v1() -> [u8; 20] {
        let mut buf = [0u8; 20];
        buf[..8].copy_from_slice(RSDP_SIGNATURE);
        buf[9..15].copy_from_slice(b"DUETOS");
        buf[15] = 0;
        buf[16..20].copy_from_slice(&0xCAFE_BABEu32.to_le_bytes());
        let cs = checksum(&buf);
        buf[8] = (256u16 - cs as u16) as u8;
        buf
    }

    fn make_rsdp_v2() -> [u8; 36] {
        let mut buf = [0u8; 36];
        buf[..8].copy_from_slice(RSDP_SIGNATURE);
        buf[9..15].copy_from_slice(b"DUETOS");
        buf[15] = 2;
        buf[16..20].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        buf[20..24].copy_from_slice(&36u32.to_le_bytes());
        buf[24..32].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
        let cs1 = checksum(&buf[..20]);
        buf[8] = (256u16 - cs1 as u16) as u8;
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
        buf[8] = 1;
        buf[10..16].copy_from_slice(b"DUETOS");
        buf[16..24].copy_from_slice(b"DUETTBL1");
        buf[24..28].copy_from_slice(&1u32.to_le_bytes());
        buf[28..32].copy_from_slice(b"DUET");
        buf[32..36].copy_from_slice(&1u32.to_le_bytes());
        let cs = checksum(&buf);
        buf[9] = (256u16 - cs as u16) as u8;
        buf
    }

    #[test]
    fn table_header_passes() {
        let buf = make_table_header(b"FACP", 64);
        let mut out = DuetosAcpiTableHeader::default();
        assert!(parse_table_header(&buf, &mut out));
        assert_eq!(&out.signature, b"FACP");
        assert_eq!(out.length, 64);
        assert_eq!(out.ok, 1);
    }

    #[test]
    fn table_header_short_length_rejects() {
        let mut buf = make_table_header(b"FACP", 64);
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

    // ---- MADT walker ----

    #[test]
    fn madt_entry_header_decodes() {
        let buf = [0x00u8, 0x08, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00];
        let mut out = DuetosAcpiMadtEntryHeader::default();
        assert!(parse_madt_entry_header(&buf, 0, &mut out));
        assert_eq!(out.entry_type, 0);
        assert_eq!(out.length, 8);
        assert_eq!(out.ok, 1);
    }

    #[test]
    fn madt_entry_zero_length_rejects() {
        let buf = [0x00u8, 0x00];
        let mut out = DuetosAcpiMadtEntryHeader::default();
        assert!(!parse_madt_entry_header(&buf, 0, &mut out));
    }

    #[test]
    fn madt_entry_oob_length_rejects() {
        let buf = [0x00u8, 0x40]; // claims 64 bytes but only 2
        let mut out = DuetosAcpiMadtEntryHeader::default();
        assert!(!parse_madt_entry_header(&buf, 0, &mut out));
    }

    #[test]
    fn madt_walker_can_iterate() {
        // Synthetic MADT body: two LAPIC entries, each 8 bytes.
        let buf = [0u8, 8, 1, 0, 1, 0, 0, 0, 0, 8, 2, 1, 1, 0, 0, 0];
        let mut off = 0;
        let mut count = 0;
        while off < buf.len() {
            let mut h = DuetosAcpiMadtEntryHeader::default();
            if !parse_madt_entry_header(&buf, off, &mut h) {
                break;
            }
            count += 1;
            off += h.length as usize;
        }
        assert_eq!(count, 2);
    }

    // ---- FADT ----

    fn make_fadt(length: u32) -> alloc::vec::Vec<u8> {
        let mut buf = make_table_header(b"FACP", length);
        // body offset 0..: firmware_ctrl, dsdt, ...
        let body_off = ACPI_TABLE_HEADER_SIZE;
        buf[body_off..body_off + 4].copy_from_slice(&0x1000u32.to_le_bytes()); // firmware_ctrl
        buf[body_off + 4..body_off + 8].copy_from_slice(&0x2000u32.to_le_bytes()); // dsdt
        buf[body_off + 10..body_off + 12].copy_from_slice(&9u16.to_le_bytes()); // sci_int
        buf[body_off + 28..body_off + 32].copy_from_slice(&0x3004u32.to_le_bytes()); // pm1a_cnt_blk
        buf[body_off + 76..body_off + 80].copy_from_slice(&ACPI_FADT_FLAG_RESET_REG_SUP.to_le_bytes()); // flags
                                                                                                        // Reset reg at body+80: address_space_id, bit_width, bit_offset, access_size, address
        buf[body_off + 80] = ACPI_GENERIC_ADDR_SPACE_MEMORY;
        buf[body_off + 84..body_off + 92].copy_from_slice(&0xCF9u64.to_le_bytes());
        buf[body_off + 92] = 0x06;
        // Re-fix checksum after edits.
        buf[9] = 0;
        let cs = checksum(&buf);
        buf[9] = (256u16 - cs as u16) as u8;
        buf
    }

    #[test]
    fn fadt_basic_decodes() {
        // 36-byte header + body up through reset_value at body+92 = total 129.
        let buf = make_fadt(144);
        let mut out = DuetosAcpiFadt::default();
        assert!(parse_fadt(&buf, &mut out));
        assert_eq!(out.firmware_ctrl, 0x1000);
        assert_eq!(out.dsdt, 0x2000);
        assert_eq!(out.sci_int, 9);
        assert_eq!(out.pm1a_cnt_blk, 0x3004);
        assert_eq!(out.reset_supported, 1);
        assert_eq!(out.reset_address, 0xCF9);
        assert_eq!(out.reset_value, 0x06);
        assert_eq!(out.ok, 1);
    }

    #[test]
    fn fadt_too_short_rejects() {
        let buf = [0u8; 50];
        let mut out = DuetosAcpiFadt::default();
        assert!(!parse_fadt(&buf, &mut out));
    }

    // ---- MCFG ----

    fn make_mcfg(seg: u16) -> alloc::vec::Vec<u8> {
        // 36-byte header + 8-byte reserved + 16-byte entry.
        let mut buf = make_table_header(b"MCFG", 60);
        let entry_off = ACPI_TABLE_HEADER_SIZE + 8;
        buf[entry_off..entry_off + 8].copy_from_slice(&0xE000_0000u64.to_le_bytes());
        buf[entry_off + 8..entry_off + 10].copy_from_slice(&seg.to_le_bytes());
        buf[entry_off + 10] = 0;
        buf[entry_off + 11] = 0xFF;
        // Fix checksum.
        buf[9] = 0;
        let cs = checksum(&buf);
        buf[9] = (256u16 - cs as u16) as u8;
        buf
    }

    #[test]
    fn mcfg_entry_decodes() {
        let buf = make_mcfg(0);
        let mut out = DuetosAcpiMcfgEntry::default();
        assert!(parse_mcfg_entry(&buf, 0, &mut out));
        assert_eq!(out.base_address, 0xE000_0000);
        assert_eq!(out.segment_group, 0);
        assert_eq!(out.start_bus, 0);
        assert_eq!(out.end_bus, 0xFF);
        assert_eq!(out.ok, 1);
    }

    #[test]
    fn mcfg_entry_oob_rejects() {
        let buf = make_mcfg(0);
        let mut out = DuetosAcpiMcfgEntry::default();
        assert!(!parse_mcfg_entry(&buf, 5, &mut out));
    }

    // ---- HPET ----

    fn make_hpet() -> alloc::vec::Vec<u8> {
        let mut buf = make_table_header(b"HPET", 56);
        let body_off = ACPI_TABLE_HEADER_SIZE;
        // event_timer_block_id: 4 timers (num=3) + 64-bit (bit 13).
        let block_id: u32 = (3u32 << 8) | (1 << 13);
        buf[body_off..body_off + 4].copy_from_slice(&block_id.to_le_bytes());
        buf[body_off + 4] = ACPI_GENERIC_ADDR_SPACE_MEMORY;
        buf[body_off + 8..body_off + 16].copy_from_slice(&0xFED00000u64.to_le_bytes());
        buf[body_off + 16] = 0;
        buf[body_off + 17..body_off + 19].copy_from_slice(&0u16.to_le_bytes());
        buf[body_off + 19] = 0;
        buf[9] = 0;
        let cs = checksum(&buf);
        buf[9] = (256u16 - cs as u16) as u8;
        buf
    }

    #[test]
    fn hpet_decodes() {
        let buf = make_hpet();
        let mut out = DuetosAcpiHpet::default();
        assert!(parse_hpet(&buf, &mut out));
        assert_eq!(out.base_address, 0xFED00000);
        assert_eq!(out.base_address_space_id, 0);
        assert_eq!(out.timer_count, 4);
        assert_eq!(out.counter_width, 64);
    }

    // ---- SRAT memory affinity ----

    #[test]
    fn srat_memory_affinity_decodes() {
        let mut buf = [0u8; 40];
        buf[0] = ACPI_SRAT_TYPE_MEMORY_AFFINITY;
        buf[1] = 40;
        buf[2..6].copy_from_slice(&7u32.to_le_bytes()); // proximity domain
        buf[8..16].copy_from_slice(&0x10000_0000u64.to_le_bytes()); // base
        buf[16..24].copy_from_slice(&0x1000_0000u64.to_le_bytes()); // length
        buf[28..32].copy_from_slice(&0x3u32.to_le_bytes()); // enabled | hot_pluggable
        let mut out = DuetosAcpiSratMemoryAffinity::default();
        assert!(parse_srat_memory_affinity(&buf, 0, &mut out));
        assert_eq!(out.proximity_domain, 7);
        assert_eq!(out.base_address, 0x10000_0000);
        assert_eq!(out.length, 0x1000_0000);
        assert_eq!(out.enabled, 1);
        assert_eq!(out.hot_pluggable, 1);
        assert_eq!(out.non_volatile, 0);
    }

    #[test]
    fn srat_wrong_type_rejects() {
        let mut buf = [0u8; 40];
        buf[0] = 0; // type 0 = CPU affinity, not memory
        buf[1] = 40;
        let mut out = DuetosAcpiSratMemoryAffinity::default();
        assert!(!parse_srat_memory_affinity(&buf, 0, &mut out));
    }
}
