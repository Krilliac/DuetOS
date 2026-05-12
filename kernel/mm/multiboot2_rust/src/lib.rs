//! DuetOS Multiboot2 info-structure walker.
//!
//! The bootloader hands the kernel a physical pointer to the
//! info structure. C++ at `kernel/mm/frame_allocator.cpp` reads
//! tags out of it to size the frame bitmap and find a home for it.
//! This crate owns every offset arithmetic step over those
//! bootloader-controlled bytes.

#![no_std]

use core::{ptr, slice};

// ---------- C-ABI out-structs ----------

/// Info-header decode result: total size of the info block and
/// the reserved word (echoed for debug). Caller validates the
/// underlying slice is at least `total_size` bytes.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosMultibootInfoHeader {
    pub total_size: u32,
    pub reserved: u32,
    pub ok: u8,
    pub _pad: [u8; 7],
}

/// One tag header. `payload_offset` is the byte offset (within the
/// info slice) where the tag's body begins — header is fixed 8
/// bytes, payload sits at `tag_offset + 8`. `next_offset` is
/// already 8-byte aligned and bounded.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosMultibootTag {
    pub tag_type: u32,
    /// Tag size (header inclusive). Always >= 8 on success.
    pub size: u32,
    /// Offset of this tag's first byte within the info slice
    /// (= cursor passed in).
    pub offset: u32,
    /// Offset of the next tag's first byte (= offset + size
    /// rounded up to 8). Equal to the slice length when the END
    /// tag is reached.
    pub next_offset: u32,
    pub ok: u8,
    pub _pad: [u8; 7],
}

/// Decoded mmap-tag header (the 8-byte fixed prefix after the tag
/// header). `entries_offset` is the byte offset where the variable-
/// length entry array begins within the info slice;
/// `entries_byte_len` bounds how far the caller can iterate.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosMultibootMmap {
    /// Bytes per entry (Multiboot2 spec: typically 24).
    pub entry_size: u32,
    /// 0 today; the spec reserves future versions.
    pub entry_version: u32,
    pub entries_offset: u32,
    pub entries_byte_len: u32,
    pub ok: u8,
    pub _pad: [u8; 7],
}

/// One mmap entry (24 bytes on the wire today).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosMultibootMmapEntry {
    pub base_addr: u64,
    pub length: u64,
    pub entry_type: u32,
    pub reserved: u32,
    pub ok: u8,
    pub _pad: [u8; 7],
}

// ---------- constants ----------

pub const MULTIBOOT_TAG_END: u32 = 0;
pub const MULTIBOOT_TAG_CMDLINE: u32 = 1;
pub const MULTIBOOT_TAG_MMAP: u32 = 6;
pub const MULTIBOOT_TAG_FRAMEBUFFER: u32 = 8;
pub const MULTIBOOT_TAG_ACPI_OLD: u32 = 14;
pub const MULTIBOOT_TAG_ACPI_NEW: u32 = 15;

const MULTIBOOT_INFO_HEADER_SIZE: usize = 8;
const MULTIBOOT_TAG_HEADER_SIZE: usize = 8;
const MULTIBOOT_MMAP_FIXED_PREFIX: usize = 16; // tag (8) + entry_size + entry_version
/// Hard cap on the info block. Real GRUB blocks are 1-10 KiB; a
/// 64 MiB ceiling lets exotic configurations through while still
/// shielding the kernel from a hostile bootloader that claims an
/// 8 EiB total_size.
const MULTIBOOT_TOTAL_SIZE_CAP: u32 = 64 * 1024 * 1024;
/// Hop cap on the tag walk. Real boots have ~10 tags; the C++
/// caller stops at this many iterations to bound pathological
/// producers. Exposed in the FFI for the C++ side to match.
pub const MULTIBOOT_TAG_HOP_CAP: u32 = 256;
/// Per the spec mmap entry layout: u64 base + u64 length + u32 type
/// + u32 reserved = 24 bytes. Anything else is malformed.
const MULTIBOOT_MMAP_ENTRY_SIZE_MIN: u32 = 24;
const MULTIBOOT_MMAP_ENTRY_SIZE_MAX: u32 = 256;

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

#[inline]
fn align8(n: u32) -> u32 {
    (n + 7) & !7
}

// ---------- parsers ----------

fn parse_header(buf: &[u8], out: &mut DuetosMultibootInfoHeader) -> bool {
    if buf.len() < MULTIBOOT_INFO_HEADER_SIZE {
        return false;
    }
    let total_size = load_u32_le(buf, 0);
    let reserved = load_u32_le(buf, 4);
    if (total_size as usize) < MULTIBOOT_INFO_HEADER_SIZE {
        return false;
    }
    if total_size > MULTIBOOT_TOTAL_SIZE_CAP {
        return false;
    }
    if (total_size as usize) > buf.len() {
        return false;
    }
    out.total_size = total_size;
    out.reserved = reserved;
    out.ok = 1;
    true
}

fn next_tag(buf: &[u8], off: usize, out: &mut DuetosMultibootTag) -> bool {
    // The tag at `off` has an 8-byte header. We accept the END
    // tag (size = 8) and any well-shaped non-end tag whose total
    // size fits in the remaining slice.
    if off < MULTIBOOT_INFO_HEADER_SIZE || off >= buf.len() {
        return false;
    }
    if off + MULTIBOOT_TAG_HEADER_SIZE > buf.len() {
        return false;
    }
    let tag_type = load_u32_le(buf, off);
    let size = load_u32_le(buf, off + 4);
    if (size as usize) < MULTIBOOT_TAG_HEADER_SIZE {
        return false;
    }
    let end_offset = match (off as u32).checked_add(size) {
        Some(v) if (v as usize) <= buf.len() => v as usize,
        _ => return false,
    };
    let next = align8(end_offset as u32) as usize;
    // The next-tag offset can equal the slice length only after the
    // END tag — that's a clean termination signal for the caller.
    if next > buf.len() {
        return false;
    }
    out.tag_type = tag_type;
    out.size = size;
    out.offset = off as u32;
    out.next_offset = next as u32;
    out.ok = 1;
    true
}

fn parse_mmap_tag(buf: &[u8], off: usize, tag_size: u32, out: &mut DuetosMultibootMmap) -> bool {
    // tag layout: (type, size, entry_size, entry_version, entries[])
    if (tag_size as usize) < MULTIBOOT_MMAP_FIXED_PREFIX {
        return false;
    }
    if off + MULTIBOOT_MMAP_FIXED_PREFIX > buf.len() {
        return false;
    }
    let entry_size = load_u32_le(buf, off + 8);
    let entry_version = load_u32_le(buf, off + 12);
    if !(MULTIBOOT_MMAP_ENTRY_SIZE_MIN..=MULTIBOOT_MMAP_ENTRY_SIZE_MAX).contains(&entry_size) {
        return false;
    }
    if entry_version != 0 {
        // A future version with a wider entry shape would need a
        // matching decoder; refuse until then so we don't silently
        // truncate fields.
        return false;
    }
    let entries_offset = off + MULTIBOOT_MMAP_FIXED_PREFIX;
    let payload_len = (tag_size as usize) - MULTIBOOT_MMAP_FIXED_PREFIX;
    if entries_offset + payload_len > buf.len() {
        return false;
    }
    out.entry_size = entry_size;
    out.entry_version = entry_version;
    out.entries_offset = entries_offset as u32;
    out.entries_byte_len = payload_len as u32;
    out.ok = 1;
    true
}

fn parse_mmap_entry(buf: &[u8], off: usize, out: &mut DuetosMultibootMmapEntry) -> bool {
    if off + (MULTIBOOT_MMAP_ENTRY_SIZE_MIN as usize) > buf.len() {
        return false;
    }
    let base_addr = load_u64_le(buf, off);
    let length = load_u64_le(buf, off + 8);
    let entry_type = load_u32_le(buf, off + 16);
    let reserved = load_u32_le(buf, off + 20);
    // A length of 0 is allowed by the spec (zero-byte region) and
    // we don't filter it here; the C++ caller decides what to do
    // with it. We DO reject base+length overflow because that
    // value would otherwise feed into `top = base + length` and
    // wrap around — a classic frame-allocator confuser.
    if base_addr.checked_add(length).is_none() {
        return false;
    }
    out.base_addr = base_addr;
    out.length = length;
    out.entry_type = entry_type;
    out.reserved = reserved;
    out.ok = 1;
    true
}

// ---------- FFI entry points ----------

/// Validate the Multiboot2 info header. On success `out->total_size`
/// gives the byte length of the entire info block (header
/// inclusive); the caller can then iterate tags inside
/// `[buf, buf + total_size)`.
#[no_mangle]
pub extern "C" fn duetos_multiboot2_parse_header(
    buf: *const u8,
    len: usize,
    out: *mut DuetosMultibootInfoHeader,
) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_header(slice, dst)
}

/// Decode one tag header at `off`. On success populates
/// `out->{tag_type, size, offset, next_offset}` and returns true.
/// The caller advances by passing `out->next_offset` back in as
/// `off` until it sees `tag_type == MULTIBOOT_TAG_END` (0) or
/// runs out of slice. Caller is responsible for capping iteration
/// at some hop count (`MULTIBOOT_TAG_HOP_CAP` is recommended).
#[no_mangle]
pub extern "C" fn duetos_multiboot2_next_tag(
    buf: *const u8,
    len: usize,
    off: usize,
    out: *mut DuetosMultibootTag,
) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    next_tag(slice, off, dst)
}

/// Decode the mmap-tag fixed prefix (entry_size + entry_version)
/// and return the bounded byte range that holds the entries.
/// `off` should be the offset of the mmap tag's first byte (i.e.
/// the value `next_tag` wrote to `offset` for a mmap-typed tag);
/// `tag_size` is the value it wrote to `size`.
#[no_mangle]
pub extern "C" fn duetos_multiboot2_parse_mmap(
    buf: *const u8,
    len: usize,
    off: usize,
    tag_size: u32,
    out: *mut DuetosMultibootMmap,
) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_mmap_tag(slice, off, tag_size, dst)
}

/// Decode one mmap entry at `off`. Returns the {base, length, type}
/// triple after rejecting base+length overflow.
#[no_mangle]
pub extern "C" fn duetos_multiboot2_parse_mmap_entry(
    buf: *const u8,
    len: usize,
    off: usize,
    out: *mut DuetosMultibootMmapEntry,
) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_mmap_entry(slice, off, dst)
}

// ---------- hosted tests ----------

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec::Vec;

    fn push_u32(buf: &mut Vec<u8>, v: u32) {
        buf.extend_from_slice(&v.to_le_bytes());
    }
    fn push_u64(buf: &mut Vec<u8>, v: u64) {
        buf.extend_from_slice(&v.to_le_bytes());
    }

    fn build_minimal_info() -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        // Header: total_size placeholder + reserved.
        push_u32(&mut buf, 0);
        push_u32(&mut buf, 0);
        // Mmap tag at offset 8.
        push_u32(&mut buf, MULTIBOOT_TAG_MMAP); // type
        let mmap_size_offset = buf.len();
        push_u32(&mut buf, 0); // size placeholder
        push_u32(&mut buf, 24); // entry_size
        push_u32(&mut buf, 0); // entry_version
                               // Two mmap entries.
        for (base, len, ty) in &[(0u64, 0x1_0000u64, 1u32), (0x10_0000u64, 0x40_0000u64, 1u32)] {
            push_u64(&mut buf, *base);
            push_u64(&mut buf, *len);
            push_u32(&mut buf, *ty);
            push_u32(&mut buf, 0); // reserved
        }
        let mmap_size = (buf.len() - 8) as u32; // 8 + 8 + 2*24 = 64 - 8 header offset
        buf[mmap_size_offset..mmap_size_offset + 4].copy_from_slice(&mmap_size.to_le_bytes());
        // Pad to 8-byte align.
        while buf.len() % 8 != 0 {
            buf.push(0);
        }
        // End tag.
        let end_offset = buf.len();
        push_u32(&mut buf, MULTIBOOT_TAG_END);
        push_u32(&mut buf, 8);
        // Pad to 8-byte align.
        while buf.len() % 8 != 0 {
            buf.push(0);
        }
        let total = buf.len() as u32;
        buf[0..4].copy_from_slice(&total.to_le_bytes());
        let _ = end_offset; // silence
        buf
    }

    #[test]
    fn header_round_trip() {
        let info = build_minimal_info();
        let mut hdr = DuetosMultibootInfoHeader::default();
        assert!(parse_header(&info, &mut hdr));
        assert_eq!(hdr.total_size as usize, info.len());
        assert_eq!(hdr.ok, 1);
    }

    #[test]
    fn header_oversize_rejects() {
        let mut info: Vec<u8> = alloc::vec![0u8; 16];
        info[0..4].copy_from_slice(&(MULTIBOOT_TOTAL_SIZE_CAP + 1).to_le_bytes());
        let mut hdr = DuetosMultibootInfoHeader::default();
        assert!(!parse_header(&info, &mut hdr));
    }

    #[test]
    fn header_short_buffer_rejects() {
        let info: Vec<u8> = alloc::vec![0u8; 4];
        let mut hdr = DuetosMultibootInfoHeader::default();
        assert!(!parse_header(&info, &mut hdr));
    }

    #[test]
    fn header_zero_size_rejects() {
        let mut info: Vec<u8> = alloc::vec![0u8; 16];
        info[0..4].copy_from_slice(&0u32.to_le_bytes());
        let mut hdr = DuetosMultibootInfoHeader::default();
        assert!(!parse_header(&info, &mut hdr));
    }

    #[test]
    fn header_size_exceeds_slice_rejects() {
        let mut info: Vec<u8> = alloc::vec![0u8; 16];
        info[0..4].copy_from_slice(&64u32.to_le_bytes());
        let mut hdr = DuetosMultibootInfoHeader::default();
        assert!(!parse_header(&info, &mut hdr));
    }

    #[test]
    fn walk_minimal_info_finds_mmap_then_end() {
        let info = build_minimal_info();
        let mut hdr = DuetosMultibootInfoHeader::default();
        assert!(parse_header(&info, &mut hdr));

        let mut tag = DuetosMultibootTag::default();
        assert!(next_tag(&info, MULTIBOOT_INFO_HEADER_SIZE, &mut tag));
        assert_eq!(tag.tag_type, MULTIBOOT_TAG_MMAP);

        let mut mmap = DuetosMultibootMmap::default();
        assert!(parse_mmap_tag(&info, tag.offset as usize, tag.size, &mut mmap));
        assert_eq!(mmap.entry_size, 24);

        // Walk both entries.
        let mut e = DuetosMultibootMmapEntry::default();
        assert!(parse_mmap_entry(&info, mmap.entries_offset as usize, &mut e));
        assert_eq!(e.base_addr, 0);
        assert_eq!(e.length, 0x1_0000);

        let mut e2 = DuetosMultibootMmapEntry::default();
        assert!(parse_mmap_entry(
            &info,
            mmap.entries_offset as usize + mmap.entry_size as usize,
            &mut e2
        ));
        assert_eq!(e2.base_addr, 0x10_0000);

        // Next tag is END.
        let mut tag_end = DuetosMultibootTag::default();
        assert!(next_tag(&info, tag.next_offset as usize, &mut tag_end));
        assert_eq!(tag_end.tag_type, MULTIBOOT_TAG_END);
    }

    #[test]
    fn next_tag_short_size_rejects() {
        // Tag with size < 8 (header inclusive) is malformed.
        let mut info: Vec<u8> = Vec::new();
        push_u32(&mut info, 16); // total_size
        push_u32(&mut info, 0); // reserved
        push_u32(&mut info, 5); // type
        push_u32(&mut info, 4); // bad size
        let mut tag = DuetosMultibootTag::default();
        assert!(!next_tag(&info, 8, &mut tag));
    }

    #[test]
    fn next_tag_overruns_slice_rejects() {
        let mut info: Vec<u8> = Vec::new();
        push_u32(&mut info, 16); // total_size
        push_u32(&mut info, 0);
        push_u32(&mut info, MULTIBOOT_TAG_CMDLINE);
        push_u32(&mut info, 100); // huge size, doesn't fit
        let mut tag = DuetosMultibootTag::default();
        assert!(!next_tag(&info, 8, &mut tag));
    }

    #[test]
    fn next_tag_low_offset_rejects() {
        let info = build_minimal_info();
        let mut tag = DuetosMultibootTag::default();
        // 0 is inside the header — never a valid tag start.
        assert!(!next_tag(&info, 0, &mut tag));
        // 4 likewise.
        assert!(!next_tag(&info, 4, &mut tag));
    }

    #[test]
    fn parse_mmap_with_unsupported_version_rejects() {
        let mut info: Vec<u8> = Vec::new();
        push_u32(&mut info, 32); // total_size
        push_u32(&mut info, 0);
        // Mmap tag at offset 8.
        push_u32(&mut info, MULTIBOOT_TAG_MMAP);
        push_u32(&mut info, 16); // size: header (8) + entry_size + entry_version
        push_u32(&mut info, 24);
        push_u32(&mut info, 1); // unsupported version
        let mut mmap = DuetosMultibootMmap::default();
        assert!(!parse_mmap_tag(&info, 8, 16, &mut mmap));
    }

    #[test]
    fn parse_mmap_with_bad_entry_size_rejects() {
        let mut info: Vec<u8> = Vec::new();
        push_u32(&mut info, 32);
        push_u32(&mut info, 0);
        push_u32(&mut info, MULTIBOOT_TAG_MMAP);
        push_u32(&mut info, 16);
        push_u32(&mut info, 8); // entry_size < 24 — bad
        push_u32(&mut info, 0);
        let mut mmap = DuetosMultibootMmap::default();
        assert!(!parse_mmap_tag(&info, 8, 16, &mut mmap));
    }

    #[test]
    fn parse_mmap_entry_base_plus_length_overflow_rejects() {
        // Adversarial entry: base = u64::MAX, length = 1 wraps.
        let mut buf: Vec<u8> = Vec::new();
        push_u64(&mut buf, u64::MAX);
        push_u64(&mut buf, 1);
        push_u32(&mut buf, 1); // type
        push_u32(&mut buf, 0);
        let mut e = DuetosMultibootMmapEntry::default();
        assert!(!parse_mmap_entry(&buf, 0, &mut e));
    }

    #[test]
    fn parse_mmap_entry_short_buffer_rejects() {
        let buf: Vec<u8> = alloc::vec![0u8; 16]; // < 24
        let mut e = DuetosMultibootMmapEntry::default();
        assert!(!parse_mmap_entry(&buf, 0, &mut e));
    }

    #[test]
    fn parse_mmap_entry_zero_length_accepted() {
        let mut buf: Vec<u8> = Vec::new();
        push_u64(&mut buf, 0x1000);
        push_u64(&mut buf, 0);
        push_u32(&mut buf, 1);
        push_u32(&mut buf, 0);
        let mut e = DuetosMultibootMmapEntry::default();
        assert!(parse_mmap_entry(&buf, 0, &mut e));
        assert_eq!(e.length, 0);
    }

    #[test]
    fn tag_alignment_padding_observed() {
        // Tag size 9 (non-aligned). next_offset should be aligned to 16.
        let mut info: Vec<u8> = Vec::new();
        push_u32(&mut info, 32); // total_size
        push_u32(&mut info, 0);
        push_u32(&mut info, MULTIBOOT_TAG_CMDLINE);
        push_u32(&mut info, 9);
        info.push(b'a'); // one byte body
        while info.len() < 32 {
            info.push(0);
        }
        let mut tag = DuetosMultibootTag::default();
        assert!(next_tag(&info, 8, &mut tag));
        // tag end = 8 + 9 = 17; aligned up = 24.
        assert_eq!(tag.next_offset, 24);
    }
}
