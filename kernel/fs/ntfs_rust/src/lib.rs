//! DuetOS NTFS metadata walker.
//!
//! Production crate. Covers the boot-sector probe, the MFT
//! record header decode, the resident `$FILE_NAME` attribute walk,
//! and the runlist (mapping-pairs) decode for non-resident
//! attributes, all in safe Rust slice traversal. The C++ wrapper
//! in `kernel/fs/ntfs.cpp` delegates the boot-sector parse, the
//! MFT record header decode, and the filename extraction to this
//! crate; the UTF-16 to ASCII glyph filter still lives in C++
//! because it draws on `util::Utf16CpToSafeAscii`.
//!
//! Layer ownership:
//! - Rust: byte parsing, magic / signature / length sanity,
//!   runlist decode, mapping-pairs arithmetic.
//! - C++: block I/O, scratch buffers, per-volume registry,
//!   mount table, logging, UTF-16 → ASCII filter.

#![no_std]

use core::{ptr, slice};

/// Decoded NTFS boot-sector ("BIOS Parameter Block" + NTFS-specific
/// extension). Mirrors the on-disk layout the C++ caller hands to a
/// mount path.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosNtfsBootSector {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub _pad0: u8,
    pub total_sectors: u64,
    pub mft_lcn: u64,
    pub mft_mirror_lcn: u64,
    pub clusters_per_mft_record: i8,
    pub clusters_per_index_block: i8,
    pub _pad1: [u8; 2],
    pub volume_serial: u64,
    pub ok: u8,
    pub _pad2: [u8; 7],
}

/// MFT record header summary (the fixed prefix every "FILE" record
/// carries, plus the offset of the first attribute and the in-use /
/// directory flag bits the caller wants for enumeration).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosNtfsMftRecordHeader {
    /// Offset (bytes from record start) of the first attribute.
    pub first_attribute_offset: u16,
    /// MFT-flag bits: bit 0 = in_use, bit 1 = is_directory.
    pub flags: u16,
    pub in_use: u8,
    pub is_directory: u8,
    pub _pad: [u8; 4],
    pub ok: u8,
    pub _pad2: [u8; 7],
}

/// A resident $FILE_NAME attribute's name slot. The C++ caller does
/// the UTF-16 → ASCII glyph filter itself (it owns the project's
/// `util::Utf16CpToSafeAscii`), so we hand back the UTF-16 byte
/// span as `(offset, length_in_code_units)` rather than copying.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosNtfsFileNameSpan {
    /// Offset (bytes from record start) where the UTF-16 name begins.
    pub utf16_offset: u32,
    /// Length, in UTF-16 code units (not bytes).
    pub utf16_units: u8,
    pub _pad: [u8; 3],
    pub ok: u8,
    pub _pad2: [u8; 7],
}

/// A decoded runlist data run (LCN extent). The runlist on disk is
/// a sequence of "mapping pairs" of variable byte width; the C++
/// caller asks Rust to decode one entry at a time so the loop state
/// stays simple.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosNtfsRunlistEntry {
    /// Length of this run, in clusters.
    pub length_clusters: u64,
    /// Logical cluster number of the first cluster, or 0 for a
    /// sparse run.
    pub lcn: u64,
    /// 1 if this run is sparse (no LCN field on disk).
    pub is_sparse: u8,
    pub _pad: [u8; 7],
    /// Bytes consumed by this run header on disk (so the caller
    /// can advance its cursor).
    pub bytes_consumed: u32,
    /// 1 on success, 0 on the end-of-runlist sentinel or a parse
    /// error.
    pub ok: u8,
    pub _pad2: [u8; 3],
}

const NTFS_OEM_ID: &[u8; 8] = b"NTFS    ";
const NTFS_FILE_RECORD_MAGIC: &[u8; 4] = b"FILE";
/// $FILE_NAME attribute type code.
pub const NTFS_ATTR_TYPE_FILE_NAME: u32 = 0x30;
/// Attribute list terminator.
pub const NTFS_ATTR_TYPE_END: u32 = 0xFFFF_FFFF;

fn slice_from_raw<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: FFI contract pins `ptr` as valid for `len` bytes
    // when non-null. The lifetime is bound to the FFI call frame —
    // we never store the slice past the call.
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

fn parse_boot_sector(buf: &[u8], out: &mut DuetosNtfsBootSector) -> bool {
    // NTFS boot sector is 512 bytes; we touch up through offset 0x50
    // + signature at the end. Require the full 512 bytes to make
    // future expansion (e.g. backup-boot-sector check) cheap.
    if buf.len() < 512 {
        return false;
    }
    if &buf[3..11] != NTFS_OEM_ID {
        return false;
    }
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
    if !matches!(out.bytes_per_sector, 256 | 512 | 1024 | 2048 | 4096) {
        return false;
    }
    if !matches!(out.sectors_per_cluster, 1 | 2 | 4 | 8 | 16 | 32 | 64 | 128) {
        return false;
    }
    out.ok = 1;
    true
}

/// Decode the BPB-field `clusters_per_mft_record` into a byte size.
/// Positive: that many clusters per record. Negative N: record size
/// = 2^(-N). Returns 0 on out-of-range shift counts so the caller
/// can reject the layout.
pub fn decode_mft_record_size(raw: i8, bytes_per_cluster: u32) -> u32 {
    if raw == 0 {
        // 0 clusters per record is invalid — let the caller reject.
        return 0;
    }
    if raw > 0 {
        return (raw as u32).saturating_mul(bytes_per_cluster);
    }
    let shift = ((-(raw as i32)) as u32) & 0x3F;
    if shift >= 32 {
        return 0;
    }
    1u32 << shift
}

fn parse_mft_record_header(rec: &[u8], rec_size: usize, out: &mut DuetosNtfsMftRecordHeader) -> bool {
    // MFT record layout (NTFS on-disk format):
    //   [0..4]   "FILE" signature
    //   [0x14]   u16 first-attribute offset
    //   [0x16]   u16 flags (bit 0 in_use, bit 1 is_directory)
    if rec.len() < 0x18 || rec.len() < rec_size {
        return false;
    }
    if &rec[0..4] != NTFS_FILE_RECORD_MAGIC {
        return false;
    }
    let first_attr_off = load_u16_le(rec, 0x14);
    if first_attr_off as usize >= rec_size {
        return false;
    }
    let flags = load_u16_le(rec, 0x16);
    out.first_attribute_offset = first_attr_off;
    out.flags = flags;
    out.in_use = if flags & 0x1 != 0 { 1 } else { 0 };
    out.is_directory = if flags & 0x2 != 0 { 1 } else { 0 };
    out.ok = 1;
    true
}

/// Walk the attribute list in an MFT record and return the byte
/// span of the first resident $FILE_NAME attribute's UTF-16 name.
/// Returns `false` if no resident $FILE_NAME is present or the
/// attribute list is malformed.
fn find_resident_file_name(rec: &[u8], rec_size: usize, out: &mut DuetosNtfsFileNameSpan) -> bool {
    if rec.len() < rec_size || rec_size < 0x18 {
        return false;
    }
    let first_attr_off = load_u16_le(rec, 0x14) as usize;
    if first_attr_off >= rec_size {
        return false;
    }
    let mut off = first_attr_off;
    // Attribute header layout (NTFS spec):
    //   +0  u32 type
    //   +4  u32 length (total bytes including header)
    //   +8  u8  non_resident (0 = resident, 1 = non-resident)
    //   +16 u32 resident value length
    //   +20 u16 resident value offset (from attribute start)
    while off + 8 <= rec_size {
        let ty = load_u32_le(rec, off);
        if ty == NTFS_ATTR_TYPE_END {
            return false;
        }
        let len = load_u32_le(rec, off + 4) as usize;
        if len == 0 || off.saturating_add(len) > rec_size {
            return false;
        }
        if ty == NTFS_ATTR_TYPE_FILE_NAME && rec[off + 8] == 0 {
            let val_len = load_u32_le(rec, off + 0x10) as usize;
            let val_off = load_u16_le(rec, off + 0x14) as usize;
            // $FILE_NAME value layout has a 0x42-byte fixed prefix
            // before the UTF-16 name bytes. The name length field
            // (UTF-16 code units, u8) lives at +0x40 of the value.
            if val_len >= 0x42 && val_off + val_len <= len {
                let value_start = off + val_off;
                let units = rec[value_start + 0x40];
                let utf16_off = value_start + 0x42;
                let utf16_bytes = (units as usize) * 2;
                if utf16_off.saturating_add(utf16_bytes) <= rec_size {
                    out.utf16_offset = utf16_off as u32;
                    out.utf16_units = units;
                    out.ok = 1;
                    return true;
                }
            }
        }
        off += len;
    }
    false
}

/// Decode one mapping-pair runlist entry starting at `cursor`.
/// `prev_lcn` is the running absolute LCN — pass 0 for the first
/// entry. Returns `bytes_consumed = 1` and `ok = 0` on the
/// end-of-runlist terminator byte (the lone 0x00) so the caller
/// can detect it.
fn parse_runlist_entry(buf: &[u8], prev_lcn: u64, out: &mut DuetosNtfsRunlistEntry) -> bool {
    if buf.is_empty() {
        return false;
    }
    let header = buf[0];
    if header == 0 {
        // End-of-runlist terminator.
        out.bytes_consumed = 1;
        out.ok = 0;
        return true;
    }
    // Low nibble = byte width of the length field; high nibble =
    // byte width of the (signed) LCN delta.
    let len_bytes = (header & 0x0F) as usize;
    let lcn_bytes = ((header >> 4) & 0x0F) as usize;
    if len_bytes == 0 || len_bytes > 8 || lcn_bytes > 8 {
        return false;
    }
    let total = 1 + len_bytes + lcn_bytes;
    if buf.len() < total {
        return false;
    }
    // Length is an unsigned little-endian integer.
    let mut length: u64 = 0;
    for i in 0..len_bytes {
        length |= (buf[1 + i] as u64) << (i * 8);
    }
    // LCN delta is a signed little-endian integer (two's complement).
    // lcn_bytes == 0 indicates a sparse run (no LCN field on disk).
    let (lcn, is_sparse) = if lcn_bytes == 0 {
        (0u64, true)
    } else {
        let mut delta: i64 = 0;
        for i in 0..lcn_bytes {
            delta |= (buf[1 + len_bytes + i] as i64) << (i * 8);
        }
        // Sign-extend from `lcn_bytes` bytes.
        let sign_bit = 1i64 << (lcn_bytes * 8 - 1);
        if delta & sign_bit != 0 {
            delta |= !((1i64 << (lcn_bytes * 8)) - 1);
        }
        let new_lcn = (prev_lcn as i64).wrapping_add(delta) as u64;
        (new_lcn, false)
    };
    out.length_clusters = length;
    out.lcn = lcn;
    out.is_sparse = if is_sparse { 1 } else { 0 };
    out.bytes_consumed = total as u32;
    out.ok = 1;
    true
}

// ---------- FFI ----------

/// FFI: probe + parse an NTFS boot sector.
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

/// FFI: decode `clusters_per_mft_record` into a byte size.
#[no_mangle]
pub extern "C" fn duetos_ntfs_decode_mft_record_size(raw: i8, bytes_per_cluster: u32) -> u32 {
    decode_mft_record_size(raw, bytes_per_cluster)
}

/// FFI: parse an MFT record header. `rec_size` is the on-disk
/// record size (typically 1024) so partial reads with trailing
/// scratch are bounded correctly.
#[no_mangle]
pub extern "C" fn duetos_ntfs_parse_mft_record_header(
    rec: *const u8,
    rec_len: usize,
    rec_size: usize,
    out: *mut DuetosNtfsMftRecordHeader,
) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(rec, rec_len) else {
        return false;
    };
    parse_mft_record_header(slice, rec_size, dst)
}

/// FFI: locate the first resident $FILE_NAME attribute and report
/// the (offset, units) byte span of its UTF-16 name. The caller
/// does the UTF-16 → ASCII translation in its own code (in DuetOS,
/// `util::Utf16CpToSafeAscii`).
#[no_mangle]
pub extern "C" fn duetos_ntfs_find_resident_file_name(
    rec: *const u8,
    rec_len: usize,
    rec_size: usize,
    out: *mut DuetosNtfsFileNameSpan,
) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(rec, rec_len) else {
        return false;
    };
    find_resident_file_name(slice, rec_size, dst)
}

/// FFI: decode one mapping-pair runlist entry. `prev_lcn` is the
/// running absolute LCN; pass 0 for the first call. On the
/// end-of-runlist terminator byte returns `bytes_consumed = 1`
/// and `ok = 0`; on a hard parse error returns `false`.
#[no_mangle]
pub extern "C" fn duetos_ntfs_parse_runlist_entry(
    buf: *const u8,
    len: usize,
    prev_lcn: u64,
    out: *mut DuetosNtfsRunlistEntry,
) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_runlist_entry(slice, prev_lcn, dst)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ntfs_boot_sector(bps: u16, spc: u8) -> [u8; 512] {
        let mut buf = [0u8; 512];
        buf[3..11].copy_from_slice(NTFS_OEM_ID);
        buf[11..13].copy_from_slice(&bps.to_le_bytes());
        buf[13] = spc;
        buf[0x28..0x30].copy_from_slice(&0x0010_0000u64.to_le_bytes());
        buf[0x30..0x38].copy_from_slice(&0x4u64.to_le_bytes());
        buf[0x38..0x40].copy_from_slice(&0x8u64.to_le_bytes());
        buf[0x40] = 0xF6_u8 as i8 as u8; // -10 → record size = 1024
        buf[0x44] = 0x01;
        buf[0x48..0x50].copy_from_slice(&0xDEAD_BEEF_CAFE_BABEu64.to_le_bytes());
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

    // ---- MFT record size decoder ----

    #[test]
    fn mft_record_size_negative_is_power_of_two() {
        // -10 → 2^10 = 1024 (the typical NTFS value).
        assert_eq!(decode_mft_record_size(-10, 4096), 1024);
        // -12 → 4096.
        assert_eq!(decode_mft_record_size(-12, 4096), 4096);
    }

    #[test]
    fn mft_record_size_positive_is_cluster_multiple() {
        // Positive 2 with 4 KiB clusters → 8 KiB record.
        assert_eq!(decode_mft_record_size(2, 4096), 8192);
        assert_eq!(decode_mft_record_size(1, 1024), 1024);
    }

    #[test]
    fn mft_record_size_zero_returns_zero() {
        // 0 is technically "0 clusters per record" — kernel rejects.
        assert_eq!(decode_mft_record_size(0, 4096), 0);
    }

    // ---- MFT record header parser ----

    fn make_mft_record(in_use: bool, is_dir: bool) -> [u8; 1024] {
        let mut rec = [0u8; 1024];
        rec[0..4].copy_from_slice(NTFS_FILE_RECORD_MAGIC);
        // Update Sequence Array placeholder.
        rec[4..6].copy_from_slice(&0x002Au16.to_le_bytes()); // USA offset
        rec[6..8].copy_from_slice(&0x0003u16.to_le_bytes()); // USA size
                                                             // First-attribute offset.
        rec[0x14..0x16].copy_from_slice(&0x0038u16.to_le_bytes());
        // Flags.
        let mut flags: u16 = 0;
        if in_use {
            flags |= 0x1;
        }
        if is_dir {
            flags |= 0x2;
        }
        rec[0x16..0x18].copy_from_slice(&flags.to_le_bytes());
        // Place a $FILE_NAME attribute at offset 0x38.
        let attr_off = 0x38;
        // type = 0x30
        rec[attr_off..attr_off + 4].copy_from_slice(&NTFS_ATTR_TYPE_FILE_NAME.to_le_bytes());
        // Attribute length: must cover val_off (24) + val_len
        // ($FN fixed prefix 0x42 + 5 UTF-16 units = 76) = 100.
        let attr_len: u32 = 104;
        rec[attr_off + 4..attr_off + 8].copy_from_slice(&attr_len.to_le_bytes());
        rec[attr_off + 8] = 0; // resident
                               // Value length (resident).
        let val_len: u32 = 0x42 + 10;
        rec[attr_off + 0x10..attr_off + 0x14].copy_from_slice(&val_len.to_le_bytes());
        // Value offset (from attribute start) — put it right after the
        // resident header at 24 bytes in.
        let val_off: u16 = 24;
        rec[attr_off + 0x14..attr_off + 0x16].copy_from_slice(&val_off.to_le_bytes());
        // $FILE_NAME body — name_length at +0x40.
        let body = attr_off + val_off as usize;
        rec[body + 0x40] = 5; // 5 UTF-16 code units
                              // UTF-16: "DUETS"
        let name = "DUETS";
        for (i, ch) in name.chars().enumerate() {
            let u = ch as u16;
            rec[body + 0x42 + i * 2..body + 0x42 + i * 2 + 2].copy_from_slice(&u.to_le_bytes());
        }
        // Attribute list terminator.
        let term_off = attr_off + attr_len as usize;
        rec[term_off..term_off + 4].copy_from_slice(&NTFS_ATTR_TYPE_END.to_le_bytes());
        rec
    }

    #[test]
    fn mft_record_header_parses() {
        let rec = make_mft_record(true, false);
        let mut hdr = DuetosNtfsMftRecordHeader::default();
        assert!(parse_mft_record_header(&rec, 1024, &mut hdr));
        assert_eq!(hdr.first_attribute_offset, 0x38);
        assert_eq!(hdr.in_use, 1);
        assert_eq!(hdr.is_directory, 0);
        assert_eq!(hdr.ok, 1);
    }

    #[test]
    fn mft_record_header_dir_flag() {
        let rec = make_mft_record(true, true);
        let mut hdr = DuetosNtfsMftRecordHeader::default();
        assert!(parse_mft_record_header(&rec, 1024, &mut hdr));
        assert_eq!(hdr.is_directory, 1);
    }

    #[test]
    fn mft_record_header_bad_magic_rejects() {
        let mut rec = make_mft_record(true, false);
        rec[0] = b'X';
        let mut hdr = DuetosNtfsMftRecordHeader::default();
        assert!(!parse_mft_record_header(&rec, 1024, &mut hdr));
    }

    #[test]
    fn mft_record_header_truncated_rejects() {
        let rec = [0u8; 8];
        let mut hdr = DuetosNtfsMftRecordHeader::default();
        assert!(!parse_mft_record_header(&rec, 1024, &mut hdr));
    }

    // ---- Resident $FILE_NAME walker ----

    #[test]
    fn file_name_walker_finds_name() {
        let rec = make_mft_record(true, false);
        let mut span = DuetosNtfsFileNameSpan::default();
        assert!(find_resident_file_name(&rec, 1024, &mut span));
        assert_eq!(span.utf16_units, 5);
        // Verify the UTF-16 bytes match "DUETS".
        let off = span.utf16_offset as usize;
        let units = span.utf16_units as usize;
        let mut decoded = [0u16; 5];
        for i in 0..units {
            decoded[i] = load_u16_le(&rec, off + i * 2);
        }
        assert_eq!(
            decoded,
            [b'D' as u16, b'U' as u16, b'E' as u16, b'T' as u16, b'S' as u16]
        );
    }

    #[test]
    fn file_name_walker_skips_other_attrs() {
        let mut rec = make_mft_record(true, false);
        // Put a fake $STANDARD_INFORMATION attribute (type 0x10) at
        // offset 0x38 instead, pushing $FILE_NAME to 0x60.
        let attr_off = 0x38;
        rec[attr_off..attr_off + 4].copy_from_slice(&0x10u32.to_le_bytes());
        let attr_len: u32 = 40;
        rec[attr_off + 4..attr_off + 8].copy_from_slice(&attr_len.to_le_bytes());
        rec[attr_off + 8] = 0; // resident
                               // Now place $FILE_NAME at 0x60.
        let fn_off = 0x60;
        rec[fn_off..fn_off + 4].copy_from_slice(&NTFS_ATTR_TYPE_FILE_NAME.to_le_bytes());
        // val_off (24) + $FN fixed prefix 0x42 + 3 UTF-16 units (6)
        // = 96; round up to 104 for headroom.
        let fn_len: u32 = 104;
        rec[fn_off + 4..fn_off + 8].copy_from_slice(&fn_len.to_le_bytes());
        rec[fn_off + 8] = 0;
        let fn_val_len: u32 = 0x42 + 6;
        rec[fn_off + 0x10..fn_off + 0x14].copy_from_slice(&fn_val_len.to_le_bytes());
        let fn_val_off: u16 = 24;
        rec[fn_off + 0x14..fn_off + 0x16].copy_from_slice(&fn_val_off.to_le_bytes());
        let body = fn_off + fn_val_off as usize;
        rec[body + 0x40] = 3;
        for (i, ch) in "AB.".chars().enumerate() {
            let u = ch as u16;
            rec[body + 0x42 + i * 2..body + 0x42 + i * 2 + 2].copy_from_slice(&u.to_le_bytes());
        }
        // Terminator.
        let term_off = fn_off + fn_len as usize;
        rec[term_off..term_off + 4].copy_from_slice(&NTFS_ATTR_TYPE_END.to_le_bytes());

        let mut span = DuetosNtfsFileNameSpan::default();
        assert!(find_resident_file_name(&rec, 1024, &mut span));
        assert_eq!(span.utf16_units, 3);
    }

    #[test]
    fn file_name_walker_returns_false_when_absent() {
        let mut rec = [0u8; 1024];
        rec[0..4].copy_from_slice(NTFS_FILE_RECORD_MAGIC);
        rec[0x14..0x16].copy_from_slice(&0x0038u16.to_le_bytes());
        // Single attribute, type END.
        let attr_off = 0x38;
        rec[attr_off..attr_off + 4].copy_from_slice(&NTFS_ATTR_TYPE_END.to_le_bytes());
        let mut span = DuetosNtfsFileNameSpan::default();
        assert!(!find_resident_file_name(&rec, 1024, &mut span));
    }

    // ---- Runlist parser ----

    #[test]
    fn runlist_single_run() {
        // header 0x21: 1-byte length, 2-byte LCN delta.
        // length = 0x10 (16 clusters), LCN delta = 0x0014 = 20.
        let buf = [0x21u8, 0x10, 0x14, 0x00];
        let mut e = DuetosNtfsRunlistEntry::default();
        assert!(parse_runlist_entry(&buf, 0, &mut e));
        assert_eq!(e.length_clusters, 16);
        assert_eq!(e.lcn, 20);
        assert_eq!(e.is_sparse, 0);
        assert_eq!(e.bytes_consumed, 4);
        assert_eq!(e.ok, 1);
    }

    #[test]
    fn runlist_sparse_run() {
        // Sparse: lcn_bytes = 0 (high nibble 0); length = 0x05.
        let buf = [0x01u8, 0x05];
        let mut e = DuetosNtfsRunlistEntry::default();
        assert!(parse_runlist_entry(&buf, 100, &mut e));
        assert_eq!(e.length_clusters, 5);
        assert_eq!(e.is_sparse, 1);
        assert_eq!(e.bytes_consumed, 2);
    }

    #[test]
    fn runlist_negative_delta() {
        // header 0x11: 1-byte length, 1-byte signed LCN delta.
        // length = 0x05, delta = 0xFF = -1.
        let buf = [0x11u8, 0x05, 0xFF];
        let mut e = DuetosNtfsRunlistEntry::default();
        assert!(parse_runlist_entry(&buf, 100, &mut e));
        assert_eq!(e.length_clusters, 5);
        // 100 + (-1) = 99.
        assert_eq!(e.lcn, 99);
        assert_eq!(e.bytes_consumed, 3);
    }

    #[test]
    fn runlist_end_terminator() {
        let buf = [0u8];
        let mut e = DuetosNtfsRunlistEntry::default();
        assert!(parse_runlist_entry(&buf, 0, &mut e));
        assert_eq!(e.bytes_consumed, 1);
        assert_eq!(e.ok, 0);
    }

    #[test]
    fn runlist_truncated_rejects() {
        // Claims 4-byte length but only 2 bytes follow.
        let buf = [0x04u8, 0x01, 0x02];
        let mut e = DuetosNtfsRunlistEntry::default();
        assert!(!parse_runlist_entry(&buf, 0, &mut e));
    }

    #[test]
    fn runlist_oversized_field_rejects() {
        // header 0x99: 9-byte length, 9-byte LCN — both > 8.
        let buf = [0x99u8, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut e = DuetosNtfsRunlistEntry::default();
        assert!(!parse_runlist_entry(&buf, 0, &mut e));
    }
}
