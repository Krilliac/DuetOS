//! DuetOS SMBIOS table walker.
//!
//! Firmware-controlled bytes in, validated offsets/slices out. The
//! C++ caller at `kernel/arch/x86_64/smbios.cpp` maps the BIOS scan
//! window and the structure table via the direct map, then hands
//! borrowed slices to this crate. Rust owns the anchor checksum,
//! the structure-table walk, and the trailing-strings list parse.
//!
//! What we do NOT do here: dereference physical pointers (the C++
//! side resolves `PhysToVirt`) and decode per-structure bodies
//! (the C++ side reads at known byte offsets within the bounded
//! slice the walker returns).

#![no_std]

use core::{ptr, slice};

// ---------- C-ABI out-structs ----------

/// Anchor location output. Whichever of `_SM_` (2.x) or `_SM3_`
/// (3.x) the firmware publishes is decoded into the same shape.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosSmbiosEntryPoint {
    /// 2 = "_SM_" anchor (32-bit table phys), 3 = "_SM3_" anchor
    /// (64-bit table phys). 0 when `ok` is 0.
    pub anchor_revision: u8,
    /// SMBIOS spec major version from the anchor.
    pub major_version: u8,
    /// SMBIOS spec minor version from the anchor.
    pub minor_version: u8,
    pub _pad0: u8,
    /// Physical address of the start of the structure table.
    pub table_phys: u64,
    /// Length of the structure table in bytes.
    pub table_length: u32,
    /// 1 on validated decode; 0 on any failure (in which case all
    /// other fields are zero).
    pub ok: u8,
    pub _pad1: [u8; 3],
}

/// One structure's framing data: type, formatted-area length,
/// handle, and the byte offsets that bound (a) the formatted area
/// and (b) the trailing strings region.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosSmbiosStructure {
    pub struct_type: u8,
    /// Formatted-area length in bytes, header inclusive (i.e. the
    /// `Length` byte from the structure header). Always >= 4 on
    /// success (header is 4 bytes).
    pub formatted_length: u8,
    pub _pad0: u16,
    pub handle: u16,
    pub _pad1: u16,
    /// Start offset within the structure-table slice of the
    /// formatted area (this is the same as the input offset on
    /// success).
    pub formatted_offset: u32,
    /// Start offset within the structure-table slice of the
    /// trailing strings region (= formatted_offset + formatted_length).
    pub strings_offset: u32,
    /// One-past-end offset of the trailing strings region (i.e.
    /// the start of the next structure). For an end-of-table
    /// (type 127) record this is `table_len`.
    pub end_offset: u32,
    pub ok: u8,
    pub _pad2: [u8; 3],
}

/// A bounded string slice returned by `read_structure_string`.
/// Lifetime of `data` matches the slice the caller passed into
/// `duetos_smbios_read_string` — the FFI never allocates.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosSmbiosString {
    /// Offset within the structure-table slice where the string
    /// begins (i.e. the first byte of the chosen NUL-terminated
    /// entry).
    pub offset: u32,
    /// Length of the string in bytes, NUL exclusive.
    pub length: u32,
    /// 1 on found + bounded, 0 on miss / overflow / unterminated.
    pub ok: u8,
    pub _pad: [u8; 3],
}

// ---------- constants ----------

const ANCHOR_2X: &[u8; 4] = b"_SM_";
const ANCHOR_2X_DMI: &[u8; 5] = b"_DMI_";
const ANCHOR_3X: &[u8; 5] = b"_SM3_";

/// 2.x anchor: total entry-point length is fixed at 31 bytes per
/// SMBIOS 2.x §2.1.1.
const SMBIOS_2X_EP_LENGTH: usize = 31;
/// 3.x anchor: total entry-point length is fixed at 24 bytes per
/// SMBIOS 3.x §5.2.
const SMBIOS_3X_EP_LENGTH: usize = 24;

/// Per the spec, the legacy 2.x anchor caps structure-table length
/// at 0xFFFF (16-bit field). The 3.x anchor caps at 0xFFFFFFFF.
/// We cap further at 1 MiB so a buggy firmware can't make us walk
/// for half a second on every boot — real tables are 1-50 KiB.
const SMBIOS_TABLE_LENGTH_CAP: u32 = 1 << 20;

/// Per-string cap. SMBIOS §6.1.3 documents 64 KiB as the spec
/// maximum but real strings are <= 128 bytes; the C++ summary
/// cache uses 64-byte fields. The cap protects the walker against
/// firmware that omits a NUL terminator inside the table.
const SMBIOS_STRING_LENGTH_CAP: usize = 1024;

// ---------- helpers ----------

fn slice_from_raw<'a>(p: *const u8, len: usize) -> Option<&'a [u8]> {
    if p.is_null() {
        return None;
    }
    // SAFETY: FFI contract pins `p` as valid for `len` bytes.
    Some(unsafe { slice::from_raw_parts(p, len) })
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

/// 8-bit additive checksum: every byte of the entry point sums to
/// zero (mod 256). Used by both 2.x and 3.x anchors over their own
/// declared entry-point length.
fn checksum(buf: &[u8]) -> u8 {
    let mut acc: u8 = 0;
    for &b in buf {
        acc = acc.wrapping_add(b);
    }
    acc
}

// ---------- entry-point parser ----------

fn parse_entry_point(buf: &[u8], out: &mut DuetosSmbiosEntryPoint) -> bool {
    // Prefer 3.x if both signatures appear at offset 0 — the 3.x
    // anchor exposes a 64-bit table physical address, which a
    // firmware would only publish when the table sits above 4 GiB.
    if buf.len() >= SMBIOS_3X_EP_LENGTH && &buf[0..5] == ANCHOR_3X {
        return parse_3x_anchor(buf, out);
    }
    if buf.len() >= SMBIOS_2X_EP_LENGTH && &buf[0..4] == ANCHOR_2X {
        return parse_2x_anchor(buf, out);
    }
    false
}

fn parse_2x_anchor(buf: &[u8], out: &mut DuetosSmbiosEntryPoint) -> bool {
    // 2.x entry point layout (offsets, sizes in bytes):
    //   0:  "_SM_"            (4)
    //   4:  entry-point checksum (u8)
    //   5:  entry-point length (u8) — must be 31
    //   6:  major             (u8)
    //   7:  minor             (u8)
    //   8:  max struct size   (u16)
    //   10: entry-point rev   (u8)
    //   11: formatted area    (5)
    //   16: "_DMI_"           (5)
    //   21: intermediate cksum(u8)
    //   22: table length      (u16)
    //   24: table phys addr   (u32)
    //   28: number of structs (u16)
    //   30: BCD revision      (u8)
    let ep_len = buf[5] as usize;
    if ep_len != SMBIOS_2X_EP_LENGTH || buf.len() < ep_len {
        return false;
    }
    if checksum(&buf[..ep_len]) != 0 {
        return false;
    }
    if &buf[16..21] != ANCHOR_2X_DMI {
        return false;
    }
    // Intermediate-anchor checksum covers bytes 16..31 of the
    // entry point (the second 15-byte half). Some real BIOSes
    // mis-compute this field; tolerate a mismatch and let the
    // table walk catch a malformed body.
    let table_length_u16 = load_u16_le(buf, 22);
    let table_length = u32::from(table_length_u16);
    if table_length == 0 || table_length > SMBIOS_TABLE_LENGTH_CAP {
        return false;
    }
    let table_phys = u64::from(load_u32_le(buf, 24));
    out.anchor_revision = 2;
    out.major_version = buf[6];
    out.minor_version = buf[7];
    out.table_phys = table_phys;
    out.table_length = table_length;
    out.ok = 1;
    true
}

fn parse_3x_anchor(buf: &[u8], out: &mut DuetosSmbiosEntryPoint) -> bool {
    // 3.x entry point layout:
    //   0:  "_SM3_"           (5)
    //   5:  checksum          (u8)
    //   6:  entry-point length(u8) — must be 24
    //   7:  major             (u8)
    //   8:  minor             (u8)
    //   9:  docrev            (u8)
    //   10: ep revision       (u8)
    //   11: reserved          (u8)
    //   12: structure max size(u32)
    //   16: table phys addr   (u64)
    let ep_len = buf[6] as usize;
    if ep_len != SMBIOS_3X_EP_LENGTH || buf.len() < ep_len {
        return false;
    }
    if checksum(&buf[..ep_len]) != 0 {
        return false;
    }
    let table_length = load_u32_le(buf, 12);
    if table_length == 0 || table_length > SMBIOS_TABLE_LENGTH_CAP {
        return false;
    }
    let table_phys = load_u64_le(buf, 16);
    out.anchor_revision = 3;
    out.major_version = buf[7];
    out.minor_version = buf[8];
    out.table_phys = table_phys;
    out.table_length = table_length;
    out.ok = 1;
    true
}

// ---------- structure-table walker ----------

/// Decode the structure header at `off` and find the end of the
/// trailing-strings region by walking forward to the double-NUL
/// terminator. All offsets are clamped to `buf`.
fn parse_structure(buf: &[u8], off: usize, out: &mut DuetosSmbiosStructure) -> bool {
    // Structure header layout (per SMBIOS §6.1):
    //   0: type   (u8)
    //   1: length (u8) — covers the formatted area only
    //   2: handle (u16)
    //
    // Formatted area sits at `[off..off + length)`. The trailing
    // strings region starts immediately after and is a sequence
    // of NUL-terminated entries ended by an empty (zero-length)
    // entry — i.e. a double-NUL.
    if off >= buf.len() || off.saturating_add(4) > buf.len() {
        return false;
    }
    let struct_type = buf[off];
    let length = buf[off + 1];
    if (length as usize) < 4 {
        return false;
    }
    let handle = load_u16_le(buf, off + 2);
    let formatted_end = match off.checked_add(length as usize) {
        Some(v) if v <= buf.len() => v,
        _ => return false,
    };

    // Walk the strings region. If `formatted_end == buf.len()`
    // there is no room for even the mandatory double-NUL — only
    // valid when the spec lets the FINAL record drop the second
    // NUL (it never does formally, but we tolerate it for the
    // end-of-table sentinel type 127). For type != 127 the
    // double-NUL is required.
    let mut p = formatted_end;
    let end_offset;
    if buf.len() < formatted_end + 2 {
        if struct_type == 127 {
            // End-of-table record with the trailer cropped off the
            // table slice. Treat as terminating; end_offset is the
            // slice length.
            end_offset = buf.len() as u32;
        } else {
            return false;
        }
    } else if buf[p] == 0 && buf[p + 1] == 0 {
        // No strings at all — common.
        end_offset = (p + 2) as u32;
    } else {
        // Walk NUL-terminated entries. Each entry's NUL marks its
        // end; the WHOLE list ends with a second NUL right after
        // the last entry's NUL. We bound the scan by the slice
        // length and by `SMBIOS_STRING_LENGTH_CAP` per entry.
        loop {
            // Find the next NUL within the slice.
            let entry_start = p;
            let mut scan_off = p;
            let mut found_nul = false;
            while scan_off < buf.len() && scan_off - entry_start < SMBIOS_STRING_LENGTH_CAP {
                if buf[scan_off] == 0 {
                    found_nul = true;
                    break;
                }
                scan_off += 1;
            }
            if !found_nul {
                // Either ran past `SMBIOS_STRING_LENGTH_CAP` without
                // a NUL (overlong string) or off the end of the
                // slice. Either is malformed.
                return false;
            }
            // `scan_off` points at the NUL byte. The list terminator
            // is a second NUL immediately after.
            if scan_off + 1 >= buf.len() {
                return false;
            }
            if buf[scan_off + 1] == 0 {
                end_offset = (scan_off + 2) as u32;
                break;
            }
            // Otherwise, more strings follow. Advance to the next
            // entry's first byte.
            p = scan_off + 1;
        }
    }

    out.struct_type = struct_type;
    out.formatted_length = length;
    out.handle = handle;
    out.formatted_offset = off as u32;
    out.strings_offset = formatted_end as u32;
    out.end_offset = end_offset;
    out.ok = 1;
    true
}

/// Look up the 1-based string `index` inside the strings region
/// that runs from `strings_off` (the value `parse_structure` wrote
/// to `strings_offset`) up to `end_off` (the value it wrote to
/// `end_offset`). Returns the string's offset + length on hit; on
/// miss leaves `ok = 0` and zero-length.
fn read_string(buf: &[u8], strings_off: usize, end_off: usize, index: u8, out: &mut DuetosSmbiosString) -> bool {
    if index == 0 {
        return false;
    }
    if strings_off >= end_off || end_off > buf.len() {
        return false;
    }
    // The terminator is a NUL at end_off - 1 (preceded by another
    // NUL OR by the end of a string + NUL). Iterate entries and
    // count up to `index`.
    let mut p = strings_off;
    let mut cur: u8 = 1;
    while p < end_off {
        // Find this entry's NUL within `[p, end_off)`. Cap each
        // entry at SMBIOS_STRING_LENGTH_CAP.
        let entry_start = p;
        let mut scan_off = p;
        while scan_off < end_off && scan_off - entry_start < SMBIOS_STRING_LENGTH_CAP {
            if buf[scan_off] == 0 {
                break;
            }
            scan_off += 1;
        }
        if scan_off >= end_off {
            return false;
        }
        if buf[scan_off] != 0 {
            // Overlong string with no NUL inside the cap — reject.
            return false;
        }
        let entry_len = scan_off - entry_start;
        if entry_len == 0 {
            // Empty entry = trailing terminator NUL. We've walked
            // past the last real string without finding the
            // requested index.
            return false;
        }
        if cur == index {
            out.offset = entry_start as u32;
            out.length = entry_len as u32;
            out.ok = 1;
            return true;
        }
        cur = cur.wrapping_add(1);
        p = scan_off + 1;
    }
    false
}

// ---------- FFI entry points ----------

/// Decode an SMBIOS entry-point structure. `buf` is a slice of at
/// least 24 bytes (the 3.x entry-point length); 31 bytes lets a
/// 2.x anchor decode. The bytes typically come from the legacy
/// BIOS scan window (0xF0000..0x100000) mapped via the direct
/// map, or from a UEFI configuration table value.
///
/// On success, writes the resolved (anchor_revision, major,
/// minor, table_phys, table_length) into `*out` and sets `ok=1`.
/// On any failure (signature miss, checksum, oversize table
/// length, malformed entry-point) returns false with `out`
/// zero-initialised.
#[no_mangle]
pub extern "C" fn duetos_smbios_parse_entry_point(
    buf: *const u8,
    len: usize,
    out: *mut DuetosSmbiosEntryPoint,
) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_entry_point(slice, dst)
}

/// Decode one structure within the SMBIOS structure table. `buf`
/// is the entire structure-table slice (validated by the caller
/// to be `table_length` bytes long). `off` is the byte offset
/// where the structure starts.
///
/// On success, `out->{type, formatted_length, handle,
/// formatted_offset, strings_offset, end_offset}` are populated
/// and `ok=1`. The caller advances by passing `out->end_offset`
/// back in as `off` on the next call until either `type == 127`
/// (end-of-table sentinel) or `end_offset == buf.len()`.
#[no_mangle]
pub extern "C" fn duetos_smbios_parse_structure(
    buf: *const u8,
    len: usize,
    off: usize,
    out: *mut DuetosSmbiosStructure,
) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_structure(slice, off, dst)
}

/// Resolve a 1-based string index inside a structure's trailing
/// strings region. `strings_off` and `end_off` must be the values
/// `duetos_smbios_parse_structure` wrote into `strings_offset` /
/// `end_offset`; passing any other values is a programmer bug.
///
/// On success, `out->offset` is the byte offset of the chosen
/// string's first character (relative to `buf`), `out->length` is
/// its length in bytes (NUL exclusive), and `ok=1`. The caller can
/// then read `[buf+offset .. buf+offset+length]` as the string
/// contents.
#[no_mangle]
pub extern "C" fn duetos_smbios_read_string(
    buf: *const u8,
    len: usize,
    strings_off: usize,
    end_off: usize,
    index: u8,
    out: *mut DuetosSmbiosString,
) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    read_string(slice, strings_off, end_off, index, dst)
}

// ---------- hosted tests ----------

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;

    // ----- entry-point builders -----

    fn build_2x_anchor(major: u8, minor: u8, table_len: u16, table_phys: u32) -> [u8; 31] {
        let mut buf = [0u8; 31];
        buf[..4].copy_from_slice(ANCHOR_2X);
        buf[5] = 31; // entry-point length
        buf[6] = major;
        buf[7] = minor;
        buf[16..21].copy_from_slice(ANCHOR_2X_DMI);
        buf[22..24].copy_from_slice(&table_len.to_le_bytes());
        buf[24..28].copy_from_slice(&table_phys.to_le_bytes());
        // Compute checksum so byte sum is zero (mod 256).
        let s = checksum(&buf);
        buf[4] = (0u8).wrapping_sub(s);
        // Intermediate checksum (bytes 16..31) — set so the sub-sum
        // is zero too; tolerated even when wrong, but make it valid
        // by default.
        let sub = checksum(&buf[16..31]);
        buf[21] = (0u8).wrapping_sub(sub);
        // Re-fix the full-EP checksum after writing the
        // intermediate (above mutation might disturb the sum).
        buf[4] = 0;
        let s2 = checksum(&buf);
        buf[4] = (0u8).wrapping_sub(s2);
        buf
    }

    fn build_3x_anchor(major: u8, minor: u8, table_len: u32, table_phys: u64) -> [u8; 24] {
        let mut buf = [0u8; 24];
        buf[..5].copy_from_slice(ANCHOR_3X);
        buf[6] = 24; // entry-point length
        buf[7] = major;
        buf[8] = minor;
        buf[12..16].copy_from_slice(&table_len.to_le_bytes());
        buf[16..24].copy_from_slice(&table_phys.to_le_bytes());
        let s = checksum(&buf);
        buf[5] = (0u8).wrapping_sub(s);
        buf
    }

    #[test]
    fn ep_2x_round_trip() {
        let buf = build_2x_anchor(2, 8, 0x1234, 0xCAFEBABE);
        let mut out = DuetosSmbiosEntryPoint::default();
        assert!(parse_entry_point(&buf, &mut out));
        assert_eq!(out.anchor_revision, 2);
        assert_eq!(out.major_version, 2);
        assert_eq!(out.minor_version, 8);
        assert_eq!(out.table_length, 0x1234);
        assert_eq!(out.table_phys, 0xCAFE_BABE);
        assert_eq!(out.ok, 1);
    }

    #[test]
    fn ep_3x_round_trip() {
        let buf = build_3x_anchor(3, 5, 0x1_0000, 0x1_FFFF_0000_u64);
        let mut out = DuetosSmbiosEntryPoint::default();
        assert!(parse_entry_point(&buf, &mut out));
        assert_eq!(out.anchor_revision, 3);
        assert_eq!(out.major_version, 3);
        assert_eq!(out.minor_version, 5);
        assert_eq!(out.table_length, 0x1_0000);
        assert_eq!(out.table_phys, 0x1_FFFF_0000_u64);
        assert_eq!(out.ok, 1);
    }

    #[test]
    fn ep_bad_signature_rejects() {
        let mut buf = build_2x_anchor(2, 8, 0x10, 0x1000);
        buf[0] = b'X';
        let mut out = DuetosSmbiosEntryPoint::default();
        assert!(!parse_entry_point(&buf, &mut out));
        assert_eq!(out.ok, 0);
    }

    #[test]
    fn ep_bad_checksum_rejects() {
        let mut buf = build_2x_anchor(2, 8, 0x10, 0x1000);
        buf[4] = buf[4].wrapping_add(1);
        let mut out = DuetosSmbiosEntryPoint::default();
        assert!(!parse_entry_point(&buf, &mut out));
    }

    #[test]
    fn ep_2x_missing_dmi_rejects() {
        let mut buf = build_2x_anchor(2, 8, 0x10, 0x1000);
        buf[16] = b'X'; // corrupt "_DMI_" → "XDMI_"
                        // Fix the checksum so we don't reject on that path first.
        buf[4] = 0;
        let s = checksum(&buf);
        buf[4] = (0u8).wrapping_sub(s);
        let mut out = DuetosSmbiosEntryPoint::default();
        assert!(!parse_entry_point(&buf, &mut out));
    }

    #[test]
    fn ep_oversize_table_length_rejects() {
        // 2.x cap is u16 — saturating value is 0xFFFF, comfortably
        // under our 1 MiB cap; 3.x lets us exceed the cap.
        let buf = build_3x_anchor(3, 5, SMBIOS_TABLE_LENGTH_CAP + 1, 0x1000);
        let mut out = DuetosSmbiosEntryPoint::default();
        assert!(!parse_entry_point(&buf, &mut out));
    }

    #[test]
    fn ep_zero_table_length_rejects() {
        let buf = build_2x_anchor(2, 8, 0, 0x1000);
        let mut out = DuetosSmbiosEntryPoint::default();
        assert!(!parse_entry_point(&buf, &mut out));
    }

    #[test]
    fn ep_prefers_3x_when_both_present() {
        // Lay a 3.x anchor at offset 0; the parser dispatches on
        // first-prefix match so 2.x doesn't get a turn.
        let buf = build_3x_anchor(3, 5, 0x100, 0x1234_0000_5678_0000_u64);
        let mut out = DuetosSmbiosEntryPoint::default();
        assert!(parse_entry_point(&buf, &mut out));
        assert_eq!(out.anchor_revision, 3);
    }

    #[test]
    fn ep_short_buffer_rejects() {
        let buf = [0u8; 4];
        let mut out = DuetosSmbiosEntryPoint::default();
        assert!(!parse_entry_point(&buf, &mut out));
    }

    // ----- structure-table builders -----

    /// Build a structure-table slice with one type=0 BIOS record,
    /// two strings ("ACME BIOS", "1.0"), then a type=127 sentinel.
    fn build_minimal_table() -> alloc::vec::Vec<u8> {
        use alloc::vec::Vec;
        let mut t = Vec::new();
        // Structure 1 — type=0, formatted length=18 (BIOS info v2.0+).
        t.push(0); // type
        t.push(18); // length
        t.push(0x00);
        t.push(0x00); // handle = 0
                      // Padding bytes 4..18 of the formatted area; vendor=string-idx 1,
                      // version=string-idx 2.
        t.push(1); // vendor (string index 1)
        t.push(2); // version (string index 2)
        for _ in 6..18 {
            t.push(0);
        }
        // Strings region.
        t.extend_from_slice(b"ACME BIOS\0");
        t.extend_from_slice(b"1.0\0");
        t.push(0); // list terminator
                   // Structure 2 — end-of-table (type=127, length=4, no strings).
        t.push(127);
        t.push(4);
        t.push(0x01);
        t.push(0x00);
        t.push(0); // formatted-area is empty; trailing double-NUL.
        t.push(0);
        t
    }

    #[test]
    fn walk_minimal_table() {
        let t = build_minimal_table();
        let mut hdr = DuetosSmbiosStructure::default();
        assert!(parse_structure(&t, 0, &mut hdr));
        assert_eq!(hdr.struct_type, 0);
        assert_eq!(hdr.formatted_length, 18);
        assert_eq!(hdr.formatted_offset, 0);
        assert_eq!(hdr.strings_offset, 18);
        assert!(hdr.end_offset as usize > 18);

        let mut s1 = DuetosSmbiosString::default();
        assert!(read_string(
            &t,
            hdr.strings_offset as usize,
            hdr.end_offset as usize,
            1,
            &mut s1
        ));
        assert_eq!(
            &t[s1.offset as usize..s1.offset as usize + s1.length as usize],
            b"ACME BIOS"
        );

        let mut s2 = DuetosSmbiosString::default();
        assert!(read_string(
            &t,
            hdr.strings_offset as usize,
            hdr.end_offset as usize,
            2,
            &mut s2
        ));
        assert_eq!(&t[s2.offset as usize..s2.offset as usize + s2.length as usize], b"1.0");

        // Step to the next structure.
        let mut eot = DuetosSmbiosStructure::default();
        assert!(parse_structure(&t, hdr.end_offset as usize, &mut eot));
        assert_eq!(eot.struct_type, 127);
        assert_eq!(eot.formatted_length, 4);
    }

    #[test]
    fn structure_with_no_strings() {
        // type=4 (CPU), length=4 (header-only), trailing double-NUL.
        let t: [u8; 6] = [4, 4, 0, 0, 0, 0];
        let mut hdr = DuetosSmbiosStructure::default();
        assert!(parse_structure(&t, 0, &mut hdr));
        assert_eq!(hdr.strings_offset, 4);
        assert_eq!(hdr.end_offset, 6);
    }

    #[test]
    fn structure_short_length_rejects() {
        // length=3 is < 4 (the size of the mandatory header).
        let t: [u8; 6] = [1, 3, 0, 0, 0, 0];
        let mut hdr = DuetosSmbiosStructure::default();
        assert!(!parse_structure(&t, 0, &mut hdr));
    }

    #[test]
    fn structure_length_overflows_table_rejects() {
        // length=10 but only 6 bytes of slice.
        let t: [u8; 6] = [1, 10, 0, 0, 0, 0];
        let mut hdr = DuetosSmbiosStructure::default();
        assert!(!parse_structure(&t, 0, &mut hdr));
    }

    #[test]
    fn structure_no_double_nul_rejects() {
        // Formatted area present, then a single string with no
        // double-NUL — strictly malformed.
        let mut t = alloc::vec::Vec::<u8>::new();
        t.push(1);
        t.push(4);
        t.push(0);
        t.push(0);
        t.extend_from_slice(b"unterminated"); // no NUL at all
        let mut hdr = DuetosSmbiosStructure::default();
        assert!(!parse_structure(&t, 0, &mut hdr));
    }

    #[test]
    fn structure_overlong_string_rejects() {
        // A "string" longer than SMBIOS_STRING_LENGTH_CAP without a
        // NUL is malformed; bounded scan must reject it.
        let mut t = alloc::vec::Vec::<u8>::new();
        t.push(1);
        t.push(4);
        t.push(0);
        t.push(0);
        // SMBIOS_STRING_LENGTH_CAP + 32 bytes of 'A', no NUL.
        for _ in 0..(SMBIOS_STRING_LENGTH_CAP + 32) {
            t.push(b'A');
        }
        t.push(0);
        t.push(0);
        let mut hdr = DuetosSmbiosStructure::default();
        assert!(!parse_structure(&t, 0, &mut hdr));
    }

    #[test]
    fn read_string_index_out_of_range_returns_false() {
        let t = build_minimal_table();
        let mut hdr = DuetosSmbiosStructure::default();
        assert!(parse_structure(&t, 0, &mut hdr));
        let mut s = DuetosSmbiosString::default();
        // The minimal table only has 2 strings; index 3 misses.
        assert!(!read_string(
            &t,
            hdr.strings_offset as usize,
            hdr.end_offset as usize,
            3,
            &mut s
        ));
        assert_eq!(s.ok, 0);
    }

    #[test]
    fn read_string_index_zero_rejects() {
        let t = build_minimal_table();
        let mut hdr = DuetosSmbiosStructure::default();
        assert!(parse_structure(&t, 0, &mut hdr));
        let mut s = DuetosSmbiosString::default();
        // Index 0 means "no string" per SMBIOS spec — should not
        // resolve to a real string.
        assert!(!read_string(
            &t,
            hdr.strings_offset as usize,
            hdr.end_offset as usize,
            0,
            &mut s
        ));
    }

    #[test]
    fn walker_end_of_table_with_cropped_trailer() {
        // Type-127 sentinel at the very end of the slice with no
        // room for the trailing strings region — accepted because
        // it's the end-of-table.
        let t: [u8; 4] = [127, 4, 0, 0];
        let mut hdr = DuetosSmbiosStructure::default();
        assert!(parse_structure(&t, 0, &mut hdr));
        assert_eq!(hdr.struct_type, 127);
        assert_eq!(hdr.end_offset as usize, t.len());
    }

    #[test]
    fn non_127_at_eof_without_trailer_rejects() {
        // Same shape as above but type=1 — strictly malformed
        // because the double-NUL is missing.
        let t: [u8; 4] = [1, 4, 0, 0];
        let mut hdr = DuetosSmbiosStructure::default();
        assert!(!parse_structure(&t, 0, &mut hdr));
    }
}
