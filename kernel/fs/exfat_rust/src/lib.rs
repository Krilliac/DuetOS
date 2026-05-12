//! DuetOS exFAT metadata walker — **skeleton**.
//!
//! Foundation for a future read-only exFAT driver. v0 covers only
//! the VBR signature + main layout fields a mount path needs to
//! say "this is exFAT, here's the FAT and the cluster heap." The
//! FAT chain walker, dirent decoder (file / stream-extension /
//! filename entries), and up-case table are next-slice work,
//! tracked in `wiki/filesystem/exFAT.md`.
//!
//! No current C++ caller.

#![no_std]

use core::{ptr, slice};

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosExfatBootSector {
    pub partition_offset: u64,    // sectors from disk start
    pub volume_length: u64,       // sectors
    pub fat_offset: u32,          // sectors from VBR
    pub fat_length: u32,          // sectors
    pub cluster_heap_offset: u32, // sectors from VBR
    pub cluster_count: u32,
    pub root_dir_first_cluster: u32,
    pub volume_serial: u32,
    pub bytes_per_sector_shift: u8,    // log2(bytes_per_sector)
    pub sectors_per_cluster_shift: u8, // log2(sectors_per_cluster)
    pub number_of_fats: u8,
    pub ok: u8,
    pub _pad: u32,
}

const EXFAT_OEM_ID: &[u8; 8] = b"EXFAT   ";

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

fn parse_boot_sector(buf: &[u8], out: &mut DuetosExfatBootSector) -> bool {
    // exFAT VBR is 512 bytes; touches up through offset 0x70 + MBR
    // signature at end.
    if buf.len() < 512 {
        return false;
    }
    if &buf[3..11] != EXFAT_OEM_ID {
        return false;
    }
    if buf[510] != 0x55 || buf[511] != 0xAA {
        return false;
    }
    out.partition_offset = load_u64_le(buf, 0x40);
    out.volume_length = load_u64_le(buf, 0x48);
    out.fat_offset = load_u32_le(buf, 0x50);
    out.fat_length = load_u32_le(buf, 0x54);
    out.cluster_heap_offset = load_u32_le(buf, 0x58);
    out.cluster_count = load_u32_le(buf, 0x5C);
    out.root_dir_first_cluster = load_u32_le(buf, 0x60);
    out.volume_serial = load_u32_le(buf, 0x64);
    out.bytes_per_sector_shift = buf[0x6C];
    out.sectors_per_cluster_shift = buf[0x6D];
    out.number_of_fats = buf[0x6E];
    // Spec §3.1.13 / §3.1.14: shift fields cap at 12 / 25
    // respectively, and number_of_fats is 1 or 2.
    if out.bytes_per_sector_shift < 9 || out.bytes_per_sector_shift > 12 {
        return false;
    }
    if out.sectors_per_cluster_shift > 25 - out.bytes_per_sector_shift {
        return false;
    }
    if out.number_of_fats != 1 && out.number_of_fats != 2 {
        return false;
    }
    out.ok = 1;
    true
}

#[no_mangle]
pub extern "C" fn duetos_exfat_parse_boot_sector(buf: *const u8, len: usize, out: *mut DuetosExfatBootSector) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_boot_sector(slice, dst)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_exfat_vbr() -> [u8; 512] {
        let mut buf = [0u8; 512];
        buf[3..11].copy_from_slice(EXFAT_OEM_ID);
        buf[0x40..0x48].copy_from_slice(&0u64.to_le_bytes()); // partition_offset
        buf[0x48..0x50].copy_from_slice(&0x10_0000u64.to_le_bytes()); // volume_length
        buf[0x50..0x54].copy_from_slice(&0x800u32.to_le_bytes()); // fat_offset
        buf[0x54..0x58].copy_from_slice(&0x100u32.to_le_bytes()); // fat_length
        buf[0x58..0x5C].copy_from_slice(&0x1000u32.to_le_bytes()); // cluster_heap_offset
        buf[0x5C..0x60].copy_from_slice(&0xFFFu32.to_le_bytes()); // cluster_count
        buf[0x60..0x64].copy_from_slice(&5u32.to_le_bytes()); // root_dir_first_cluster
        buf[0x64..0x68].copy_from_slice(&0xCAFE_BABEu32.to_le_bytes()); // volume_serial
        buf[0x6C] = 9; // bytes_per_sector_shift = 512
        buf[0x6D] = 8; // sectors_per_cluster_shift = 256 → cluster=128KiB
        buf[0x6E] = 1;
        buf[510] = 0x55;
        buf[511] = 0xAA;
        buf
    }

    #[test]
    fn exfat_valid_vbr_parses() {
        let buf = make_exfat_vbr();
        let mut out = DuetosExfatBootSector::default();
        assert!(parse_boot_sector(&buf, &mut out));
        assert_eq!(out.volume_length, 0x10_0000);
        assert_eq!(out.fat_offset, 0x800);
        assert_eq!(out.cluster_heap_offset, 0x1000);
        assert_eq!(out.bytes_per_sector_shift, 9);
        assert_eq!(out.sectors_per_cluster_shift, 8);
        assert_eq!(out.number_of_fats, 1);
        assert_eq!(out.volume_serial, 0xCAFE_BABE);
        assert_eq!(out.ok, 1);
    }

    #[test]
    fn exfat_bad_oem_rejects() {
        let mut buf = make_exfat_vbr();
        buf[3] = b'F';
        let mut out = DuetosExfatBootSector::default();
        assert!(!parse_boot_sector(&buf, &mut out));
    }

    #[test]
    fn exfat_bad_sector_shift_rejects() {
        let mut buf = make_exfat_vbr();
        buf[0x6C] = 13;
        let mut out = DuetosExfatBootSector::default();
        assert!(!parse_boot_sector(&buf, &mut out));
    }

    #[test]
    fn exfat_bad_cluster_shift_rejects() {
        let mut buf = make_exfat_vbr();
        buf[0x6C] = 9; // BPS = 512
        buf[0x6D] = 25; // 9+25 = 34 > 25 → reject
        let mut out = DuetosExfatBootSector::default();
        assert!(!parse_boot_sector(&buf, &mut out));
    }

    #[test]
    fn exfat_bad_number_of_fats_rejects() {
        let mut buf = make_exfat_vbr();
        buf[0x6E] = 3;
        let mut out = DuetosExfatBootSector::default();
        assert!(!parse_boot_sector(&buf, &mut out));
    }

    #[test]
    fn exfat_too_short_rejects() {
        let buf = [0u8; 100];
        let mut out = DuetosExfatBootSector::default();
        assert!(!parse_boot_sector(&buf, &mut out));
    }
}
