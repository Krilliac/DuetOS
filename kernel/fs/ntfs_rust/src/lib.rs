//! DuetOS NTFS metadata walker — **skeleton**.
//!
//! Foundation for a future read-only NTFS driver. v0 covers only
//! the boot-sector signature + cluster / sector layout fields a
//! mount path needs to decide "this is NTFS, here's the MFT
//! location." The MFT walker, attribute decoder, runlist parser,
//! and INDX entry walker are all left as next-slice work, tracked
//! in `wiki/filesystem/NTFS.md`.
//!
//! No current C++ caller — keep until a read-only NTFS driver
//! lands at `kernel/fs/ntfs.cpp`. The `wiki/reference/Roadmap.md`
//! "Skeleton crates" table records the trigger that flips this to
//! production status.

#![no_std]

use core::{ptr, slice};

/// Decoded NTFS boot-sector ("BIOS Parameter Block" + NTFS-specific
/// extension). Mirrors the on-disk layout the C++ caller will eventually
/// hand to a mount path.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosNtfsBootSector {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub _pad0: u8,
    pub total_sectors: u64,
    pub mft_lcn: u64,        // logical cluster number of $MFT
    pub mft_mirror_lcn: u64, // logical cluster number of $MFTMirr
    pub clusters_per_mft_record: i8,
    pub clusters_per_index_block: i8,
    pub _pad1: [u8; 2],
    pub volume_serial: u64,
    pub ok: u8,
    pub _pad2: [u8; 7],
}

const NTFS_OEM_ID: &[u8; 8] = b"NTFS    ";

fn slice_from_raw<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: FFI contract pins `ptr` as valid for `len` bytes
    // when non-null.
    Some(unsafe { slice::from_raw_parts(ptr, len) })
}

fn out_init<'a, T: Default + Copy>(out: *mut T) -> Option<&'a mut T> {
    if out.is_null() {
        return None;
    }
    // SAFETY: FFI contract pins `out` as a writable T-sized region;
    // we never retain the pointer past the call.
    unsafe {
        ptr::write(out, T::default());
        Some(&mut *out)
    }
}

#[inline]
fn load_u16_le(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
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

fn parse_boot_sector(buf: &[u8], out: &mut DuetosNtfsBootSector) -> bool {
    // NTFS boot sector is 512 bytes; we touch up through offset 0x50
    // + signature at the end. Require the full 512 bytes to make
    // future expansion (e.g. backup-boot-sector check) cheap.
    if buf.len() < 512 {
        return false;
    }
    // OEM ID at offset 3..11 must be "NTFS    " (4 trailing spaces).
    if &buf[3..11] != NTFS_OEM_ID {
        return false;
    }
    // Every NTFS volume's last two bytes of the boot sector are
    // 0x55 0xAA (the standard MBR boot-sector signature).
    if buf[510] != 0x55 || buf[511] != 0xAA {
        return false;
    }
    out.bytes_per_sector = load_u16_le(buf, 11);
    out.sectors_per_cluster = buf[13];
    out.total_sectors = load_u64_le(buf, 0x28);
    out.mft_lcn = load_u64_le(buf, 0x30);
    out.mft_mirror_lcn = load_u64_le(buf, 0x38);
    out.clusters_per_mft_record = buf[0x40] as i8;
    out.clusters_per_index_block = buf[0x44] as i8;
    out.volume_serial = load_u64_le(buf, 0x48);
    // Sanity: bytes_per_sector must be a power-of-2 in [256, 4096]
    // (NTFS spec §3.1) and sectors_per_cluster must be 1, 2, 4,
    // 8, 16, 32, 64, or 128.
    if !matches!(out.bytes_per_sector, 256 | 512 | 1024 | 2048 | 4096) {
        return false;
    }
    if !matches!(out.sectors_per_cluster, 1 | 2 | 4 | 8 | 16 | 32 | 64 | 128) {
        return false;
    }
    out.ok = 1;
    true
}

/// FFI: probe + parse an NTFS boot sector. Returns true with
/// `out->ok = 1` only if the OEM ID, MBR signature, and basic
/// layout fields are well-formed.
#[no_mangle]
pub extern "C" fn duetos_ntfs_parse_boot_sector(buf: *const u8, len: usize, out: *mut DuetosNtfsBootSector) -> bool {
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

    fn make_ntfs_boot_sector(bps: u16, spc: u8) -> [u8; 512] {
        let mut buf = [0u8; 512];
        // OEM ID at offset 3..11.
        buf[3..11].copy_from_slice(NTFS_OEM_ID);
        // BPB.
        buf[11..13].copy_from_slice(&bps.to_le_bytes());
        buf[13] = spc;
        buf[0x28..0x30].copy_from_slice(&0x0010_0000u64.to_le_bytes()); // total_sectors
        buf[0x30..0x38].copy_from_slice(&0x4u64.to_le_bytes()); // mft_lcn
        buf[0x38..0x40].copy_from_slice(&0x8u64.to_le_bytes()); // mft_mirror_lcn
        buf[0x40] = 0xF6_u8 as i8 as u8; // clusters_per_mft_record (signed -10 → 1024 bytes)
        buf[0x44] = 0x01; // clusters_per_index_block
        buf[0x48..0x50].copy_from_slice(&0xDEAD_BEEF_CAFE_BABEu64.to_le_bytes());
        // MBR signature.
        buf[510] = 0x55;
        buf[511] = 0xAA;
        buf
    }

    #[test]
    fn ntfs_valid_boot_sector_parses() {
        let buf = make_ntfs_boot_sector(512, 8);
        let mut out = DuetosNtfsBootSector::default();
        assert!(parse_boot_sector(&buf, &mut out));
        assert_eq!(out.bytes_per_sector, 512);
        assert_eq!(out.sectors_per_cluster, 8);
        assert_eq!(out.total_sectors, 0x0010_0000);
        assert_eq!(out.mft_lcn, 4);
        assert_eq!(out.volume_serial, 0xDEAD_BEEF_CAFE_BABE);
        assert_eq!(out.ok, 1);
    }

    #[test]
    fn ntfs_bad_oem_rejects() {
        let mut buf = make_ntfs_boot_sector(512, 8);
        buf[3] = b'X';
        let mut out = DuetosNtfsBootSector::default();
        assert!(!parse_boot_sector(&buf, &mut out));
    }

    #[test]
    fn ntfs_missing_mbr_signature_rejects() {
        let mut buf = make_ntfs_boot_sector(512, 8);
        buf[510] = 0;
        let mut out = DuetosNtfsBootSector::default();
        assert!(!parse_boot_sector(&buf, &mut out));
    }

    #[test]
    fn ntfs_bad_sector_size_rejects() {
        let buf = make_ntfs_boot_sector(123, 8);
        let mut out = DuetosNtfsBootSector::default();
        assert!(!parse_boot_sector(&buf, &mut out));
    }

    #[test]
    fn ntfs_bad_sectors_per_cluster_rejects() {
        let buf = make_ntfs_boot_sector(512, 7);
        let mut out = DuetosNtfsBootSector::default();
        assert!(!parse_boot_sector(&buf, &mut out));
    }

    #[test]
    fn ntfs_too_short_rejects() {
        let buf = [0u8; 100];
        let mut out = DuetosNtfsBootSector::default();
        assert!(!parse_boot_sector(&buf, &mut out));
    }
}
