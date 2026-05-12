//! DuetOS exFAT metadata walker.
//!
//! Production crate. Boot-sector probe + FAT chain walker + dirent
//! decoder (File 0x85 + Stream-Extension 0xC0 + FileName 0xC1
//! tuples). The C++ wrapper at `kernel/fs/exfat.cpp` delegates the
//! boot-sector parse, dirent-set walk, and FAT chain advance to
//! this crate; the UTF-16 → ASCII glyph filter stays in C++ because
//! it draws on `util::Utf16CpToSafeAscii`.

#![no_std]

use core::{ptr, slice};

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosExfatBootSector {
    pub partition_offset: u64,
    pub volume_length: u64,
    pub fat_offset: u32,
    pub fat_length: u32,
    pub cluster_heap_offset: u32,
    pub cluster_count: u32,
    pub root_dir_first_cluster: u32,
    pub volume_serial: u32,
    pub bytes_per_sector_shift: u8,
    pub sectors_per_cluster_shift: u8,
    pub number_of_fats: u8,
    pub ok: u8,
    pub _pad: u32,
}

/// Layout numbers derived from the boot sector (so the C++ caller
/// doesn't have to re-do the shift arithmetic). Returned by
/// `duetos_exfat_derive_geometry`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosExfatGeometry {
    pub bytes_per_sector: u32,
    pub sectors_per_cluster: u32,
    pub cluster_bytes: u64,
    pub ok: u8,
    pub _pad: [u8; 7],
}

/// One decoded dirent set (File + StreamExt + N FileName entries).
/// The C++ caller copies the fields verbatim into its `DirEntry`
/// struct; UTF-16 → ASCII translation is done on the host side
/// using `(name_offset, name_units)` because the project owns the
/// glyph-filter table.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosExfatDirEntry {
    pub attributes: u8,
    pub _pad0: u8,
    pub _pad1: u16,
    pub first_cluster: u32,
    pub size_bytes: u64,
    pub valid_data_len: u64,
    /// Byte offset (within the buffer) where the first FileName
    /// entry's UTF-16 bytes begin.
    pub name_offset: u32,
    /// Total UTF-16 code units (across all FileName entries).
    pub name_units: u8,
    pub _pad2: [u8; 3],
    /// Number of 32-byte slots consumed (1 + secondary_count). The
    /// caller advances its cursor by this many slots.
    pub slots_consumed: u8,
    pub _pad3: [u8; 3],
    pub ok: u8,
    pub _pad4: [u8; 7],
}

const EXFAT_OEM_ID: &[u8; 8] = b"EXFAT   ";

pub const EXFAT_DIRENT_END_OF_DIR: u8 = 0x00;
pub const EXFAT_DIRENT_FILE: u8 = 0x85;
pub const EXFAT_DIRENT_STREAM_EXT: u8 = 0xC0;
pub const EXFAT_DIRENT_FILE_NAME: u8 = 0xC1;

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

fn derive_geometry(bs: &DuetosExfatBootSector, out: &mut DuetosExfatGeometry) -> bool {
    if bs.ok == 0 {
        return false;
    }
    if bs.bytes_per_sector_shift < 9 || bs.bytes_per_sector_shift > 12 {
        return false;
    }
    if bs.sectors_per_cluster_shift > 25 - bs.bytes_per_sector_shift {
        return false;
    }
    out.bytes_per_sector = 1u32 << bs.bytes_per_sector_shift;
    out.sectors_per_cluster = 1u32 << bs.sectors_per_cluster_shift;
    out.cluster_bytes = u64::from(out.bytes_per_sector) * u64::from(out.sectors_per_cluster);
    out.ok = 1;
    true
}

/// Decode one dirent set starting at `start_idx` within `buf`.
/// `buf_entries` is the total entry count in the buffer. Returns
/// false on a malformed primary entry; returns true with
/// `slots_consumed == 1` and `ok == 0` for a non-File primary so
/// the caller can skip individual entries.
fn parse_file_dirent_set(buf: &[u8], start_idx: u32, buf_entries: u32, out: &mut DuetosExfatDirEntry) -> bool {
    if start_idx >= buf_entries {
        return false;
    }
    let file_off = (start_idx as usize) * 32;
    if file_off + 32 > buf.len() {
        return false;
    }
    let primary = &buf[file_off..file_off + 32];
    // Deleted entries have bit 7 clear; we still consume the slot.
    if (primary[0] & 0x7F) != (EXFAT_DIRENT_FILE & 0x7F) {
        out.slots_consumed = 1;
        return true;
    }
    if (primary[0] & 0x80) == 0 {
        out.slots_consumed = 1;
        return true;
    }
    let secondary_count = primary[1];
    if secondary_count < 2 {
        // Need at least StreamExt + 1 FileName.
        out.slots_consumed = 1;
        return true;
    }
    let total_slots = u32::from(secondary_count) + 1;
    if start_idx + total_slots > buf_entries {
        out.slots_consumed = 1;
        return true;
    }
    let stream_off = file_off + 32;
    let stream = &buf[stream_off..stream_off + 32];
    if (stream[0] & 0x7F) != (EXFAT_DIRENT_STREAM_EXT & 0x7F) {
        out.slots_consumed = total_slots as u8;
        return true;
    }

    out.attributes = primary[4];
    out.valid_data_len = load_u64_le(stream, 0x08);
    out.first_cluster = load_u32_le(stream, 0x14);
    out.size_bytes = load_u64_le(stream, 0x18);
    let name_length = stream[0x03];

    // Find the first FileName slot. The spec orders them at slots
    // 2 .. (total_slots - 1).
    let mut name_off: u32 = 0;
    let mut total_name_units: u8 = 0;
    let mut found_name_start = false;
    let mut remaining = name_length;
    for k in 2..total_slots {
        let ent_off = file_off + (k as usize) * 32;
        if ent_off + 32 > buf.len() {
            break;
        }
        let ent = &buf[ent_off..ent_off + 32];
        if (ent[0] & 0x7F) != (EXFAT_DIRENT_FILE_NAME & 0x7F) {
            continue;
        }
        if !found_name_start {
            name_off = (ent_off + 2) as u32;
            found_name_start = true;
        }
        let take = if remaining > 15 { 15 } else { remaining };
        total_name_units = total_name_units.saturating_add(take);
        remaining = remaining.saturating_sub(take);
        if remaining == 0 {
            break;
        }
    }
    if !found_name_start {
        out.slots_consumed = total_slots as u8;
        return true;
    }
    out.name_offset = name_off;
    out.name_units = total_name_units;
    out.slots_consumed = total_slots as u8;
    out.ok = 1;
    true
}

/// Walk one entry of the exFAT FAT (4-byte LE per cluster) and
/// return the next cluster. Returns 0xFFFFFFFF on the
/// end-of-chain marker (>= 0xFFFFFFF8 per spec) and 0 on an
/// out-of-bounds index.
fn fat_chain_next(fat: &[u8], cluster: u32) -> u32 {
    // First two FAT entries are reserved (media descriptor + dirty
    // bit), so a valid cluster index is >= 2.
    if cluster < 2 {
        return 0;
    }
    let off = (cluster as usize) * 4;
    if off + 4 > fat.len() {
        return 0;
    }
    let next = load_u32_le(fat, off);
    // EOC range per exFAT spec.
    if next >= 0xFFFF_FFF8 {
        return 0xFFFF_FFFF;
    }
    next
}

// ---------- FFI ----------

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

/// SAFETY: caller's FFI contract is that `bs` is non-null and
/// points to a readable `DuetosExfatBootSector`. We copy the
/// struct out once and never retain the pointer.
fn read_boot_sector_by_ptr(bs: *const DuetosExfatBootSector) -> Option<DuetosExfatBootSector> {
    if bs.is_null() {
        return None;
    }
    // SAFETY: pointer non-null, FFI contract pins layout.
    Some(unsafe { ptr::read(bs) })
}

#[no_mangle]
pub extern "C" fn duetos_exfat_derive_geometry(
    bs: *const DuetosExfatBootSector,
    out: *mut DuetosExfatGeometry,
) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(bs_val) = read_boot_sector_by_ptr(bs) else {
        return false;
    };
    derive_geometry(&bs_val, dst)
}

/// Parse one dirent set. `buf_entries` is the number of 32-byte
/// slots in `buf` (call site passes bytes_to_read / 32).
#[no_mangle]
pub extern "C" fn duetos_exfat_parse_dirent_set(
    buf: *const u8,
    len: usize,
    start_idx: u32,
    buf_entries: u32,
    out: *mut DuetosExfatDirEntry,
) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_file_dirent_set(slice, start_idx, buf_entries, dst)
}

#[no_mangle]
pub extern "C" fn duetos_exfat_fat_chain_next(fat: *const u8, fat_len: usize, cluster: u32) -> u32 {
    let Some(slice) = slice_from_raw(fat, fat_len) else {
        return 0;
    };
    fat_chain_next(slice, cluster)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_exfat_vbr() -> [u8; 512] {
        let mut buf = [0u8; 512];
        buf[3..11].copy_from_slice(EXFAT_OEM_ID);
        buf[0x40..0x48].copy_from_slice(&0u64.to_le_bytes());
        buf[0x48..0x50].copy_from_slice(&0x10_0000u64.to_le_bytes());
        buf[0x50..0x54].copy_from_slice(&0x800u32.to_le_bytes());
        buf[0x54..0x58].copy_from_slice(&0x100u32.to_le_bytes());
        buf[0x58..0x5C].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[0x5C..0x60].copy_from_slice(&0xFFFu32.to_le_bytes());
        buf[0x60..0x64].copy_from_slice(&5u32.to_le_bytes());
        buf[0x64..0x68].copy_from_slice(&0xCAFE_BABEu32.to_le_bytes());
        buf[0x6C] = 9;
        buf[0x6D] = 8;
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
        buf[0x6C] = 9;
        buf[0x6D] = 25;
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

    // ---- Geometry ----

    #[test]
    fn geometry_basic() {
        let buf = make_exfat_vbr();
        let mut bs = DuetosExfatBootSector::default();
        assert!(parse_boot_sector(&buf, &mut bs));
        let mut g = DuetosExfatGeometry::default();
        assert!(derive_geometry(&bs, &mut g));
        assert_eq!(g.bytes_per_sector, 512);
        assert_eq!(g.sectors_per_cluster, 256);
        assert_eq!(g.cluster_bytes, 512 * 256);
        assert_eq!(g.ok, 1);
    }

    #[test]
    fn geometry_rejects_invalid_bs() {
        let bs = DuetosExfatBootSector::default(); // ok = 0
        let mut g = DuetosExfatGeometry::default();
        assert!(!derive_geometry(&bs, &mut g));
    }

    // ---- Dirent set walker ----

    /// Build a dirent buffer with one File + Stream + 1 FileName
    /// entry encoding `name` (max 15 UTF-16 units).
    fn make_dirent_set_short(name: &str, attrs: u8, first_cluster: u32, size: u64) -> [u8; 32 * 3] {
        let mut buf = [0u8; 32 * 3];
        // File entry.
        buf[0] = EXFAT_DIRENT_FILE;
        buf[1] = 2; // secondary_count = 2 (StreamExt + 1 FileName)
        buf[4] = attrs;
        // Stream-Extension entry.
        buf[32] = EXFAT_DIRENT_STREAM_EXT;
        // Name length at offset 3.
        buf[32 + 3] = name.encode_utf16().count() as u8;
        // valid_data_len + data_length.
        buf[32 + 0x08..32 + 0x10].copy_from_slice(&size.to_le_bytes());
        buf[32 + 0x14..32 + 0x18].copy_from_slice(&first_cluster.to_le_bytes());
        buf[32 + 0x18..32 + 0x20].copy_from_slice(&size.to_le_bytes());
        // FileName entry.
        buf[64] = EXFAT_DIRENT_FILE_NAME;
        for (i, u) in name.encode_utf16().take(15).enumerate() {
            buf[64 + 2 + i * 2..64 + 2 + i * 2 + 2].copy_from_slice(&u.to_le_bytes());
        }
        buf
    }

    #[test]
    fn dirent_set_simple_parses() {
        let buf = make_dirent_set_short("README.MD", 0x20, 5, 1234);
        let mut e = DuetosExfatDirEntry::default();
        assert!(parse_file_dirent_set(&buf, 0, 3, &mut e));
        assert_eq!(e.ok, 1);
        assert_eq!(e.attributes, 0x20);
        assert_eq!(e.first_cluster, 5);
        assert_eq!(e.size_bytes, 1234);
        assert_eq!(e.valid_data_len, 1234);
        assert_eq!(e.name_units, 9);
        assert_eq!(e.name_offset, 64 + 2);
        assert_eq!(e.slots_consumed, 3);
    }

    #[test]
    fn dirent_set_deleted_skipped() {
        let mut buf = make_dirent_set_short("X", 0, 0, 0);
        // Clear bit 7 of the primary type.
        buf[0] &= 0x7F;
        let mut e = DuetosExfatDirEntry::default();
        assert!(parse_file_dirent_set(&buf, 0, 3, &mut e));
        assert_eq!(e.ok, 0);
        assert_eq!(e.slots_consumed, 1);
    }

    #[test]
    fn dirent_set_long_name_spans_two_filename_entries() {
        let name = "ABCDEFGHIJKLMNOP"; // 16 UTF-16 units
        let mut buf = [0u8; 32 * 4];
        buf[0] = EXFAT_DIRENT_FILE;
        buf[1] = 3; // StreamExt + 2 FileName
        buf[32] = EXFAT_DIRENT_STREAM_EXT;
        buf[32 + 3] = 16;
        // FileName 1
        buf[64] = EXFAT_DIRENT_FILE_NAME;
        for (i, u) in name.encode_utf16().take(15).enumerate() {
            buf[64 + 2 + i * 2..64 + 2 + i * 2 + 2].copy_from_slice(&u.to_le_bytes());
        }
        // FileName 2
        buf[96] = EXFAT_DIRENT_FILE_NAME;
        let u = name.encode_utf16().nth(15).unwrap();
        buf[96 + 2..96 + 4].copy_from_slice(&u.to_le_bytes());

        let mut e = DuetosExfatDirEntry::default();
        assert!(parse_file_dirent_set(&buf, 0, 4, &mut e));
        assert_eq!(e.ok, 1);
        assert_eq!(e.name_units, 16);
        assert_eq!(e.slots_consumed, 4);
    }

    #[test]
    fn dirent_set_short_secondary_count_skips() {
        let mut buf = [0u8; 32];
        buf[0] = EXFAT_DIRENT_FILE;
        buf[1] = 0; // need at least 2
        let mut e = DuetosExfatDirEntry::default();
        assert!(parse_file_dirent_set(&buf, 0, 1, &mut e));
        assert_eq!(e.ok, 0);
        assert_eq!(e.slots_consumed, 1);
    }

    // ---- FAT chain walker ----

    #[test]
    fn fat_chain_next_basic() {
        let mut fat = [0u8; 64];
        // Cluster 2 → 3, Cluster 3 → 4, Cluster 4 → EOC.
        fat[8..12].copy_from_slice(&3u32.to_le_bytes());
        fat[12..16].copy_from_slice(&4u32.to_le_bytes());
        fat[16..20].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        assert_eq!(fat_chain_next(&fat, 2), 3);
        assert_eq!(fat_chain_next(&fat, 3), 4);
        assert_eq!(fat_chain_next(&fat, 4), 0xFFFF_FFFF);
    }

    #[test]
    fn fat_chain_next_reserved_cluster_rejects() {
        let fat = [0u8; 16];
        assert_eq!(fat_chain_next(&fat, 0), 0);
        assert_eq!(fat_chain_next(&fat, 1), 0);
    }

    #[test]
    fn fat_chain_next_out_of_bounds_rejects() {
        let fat = [0u8; 8];
        assert_eq!(fat_chain_next(&fat, 100), 0);
    }

    #[test]
    fn fat_chain_next_eoc_range() {
        let mut fat = [0u8; 16];
        fat[8..12].copy_from_slice(&0xFFFF_FFF8u32.to_le_bytes());
        assert_eq!(fat_chain_next(&fat, 2), 0xFFFF_FFFF);
    }
}
