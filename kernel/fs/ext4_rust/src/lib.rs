//! DuetOS ext4 metadata walker.
//!
//! Production crate. Covers the superblock probe, the
//! group-descriptor decoder, the inode-record decoder, the
//! extent-header decoder, and the linux_dirent walker. The C++
//! wrapper at `kernel/fs/ext4.cpp` delegates the byte parsing
//! to this crate; block I/O, scratch management, the per-volume
//! registry, and logging stay in C++.

#![no_std]

use core::{ptr, slice};

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosExt4Superblock {
    pub inodes_count: u32,
    pub blocks_count_lo: u32,
    pub free_blocks_count_lo: u32,
    pub free_inodes_count: u32,
    pub first_data_block: u32,
    pub log_block_size: u32,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub magic: u16,
    pub state: u16,
    pub rev_level: u32,
    pub feature_compat: u32,
    pub feature_incompat: u32,
    pub feature_ro_compat: u32,
    pub uuid: [u8; 16],
    pub inode_size: u16,
    pub _pad0: u16,
    pub volume_name: [u8; 16],
    pub ok: u8,
    pub _pad: [u8; 7],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosExt4GroupDesc {
    pub block_bitmap_block: u32,
    pub inode_bitmap_block: u32,
    pub inode_table_block: u32,
    pub free_blocks_count: u16,
    pub free_inodes_count: u16,
    pub used_dirs_count: u16,
    pub _pad0: u16,
    pub ok: u8,
    pub _pad1: [u8; 7],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DuetosExt4Inode {
    pub mode: u16,
    pub uid: u16,
    pub size_bytes: u64,
    pub atime: u32,
    pub ctime: u32,
    pub mtime: u32,
    pub gid: u16,
    pub links_count: u16,
    pub blocks_lo: u32,
    pub flags: u32,
    pub uses_extents: u8,
    pub _pad0: u8,
    pub block0_magic: u16,
    pub i_block: [u8; 60],
    pub ok: u8,
    pub _pad1: [u8; 7],
}

// [u8; 60] doesn't auto-implement Default on the workspace's
// nightly toolchain (the std impl only covers arrays through 32),
// so the derive expansion fails. Hand-roll a zero-init; the
// clippy::derivable_impls lint exemption is local to this one
// instance because the derive really can't replace it.
#[allow(clippy::derivable_impls)]
impl Default for DuetosExt4Inode {
    fn default() -> Self {
        Self {
            mode: 0,
            uid: 0,
            size_bytes: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            gid: 0,
            links_count: 0,
            blocks_lo: 0,
            flags: 0,
            uses_extents: 0,
            _pad0: 0,
            block0_magic: 0,
            i_block: [0u8; 60],
            ok: 0,
            _pad1: [0u8; 7],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosExt4ExtentHeader {
    pub magic: u16,
    pub entries: u16,
    pub max: u16,
    pub depth: u16,
    pub generation: u32,
    pub ok: u8,
    pub _pad: [u8; 7],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosExt4Extent {
    pub logical_block: u32,
    pub length_blocks: u16,
    pub _pad0: u16,
    pub physical_block: u64,
    pub ok: u8,
    pub _pad1: [u8; 7],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosExt4ExtentIndex {
    pub logical_block: u32,
    pub leaf_block: u64,
    pub ok: u8,
    pub _pad: [u8; 7],
}

/// One decoded linux_dirent record. The name lives in the caller's
/// scratch buffer at `name_offset..name_offset+name_len`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosExt4DirEntry {
    pub inode: u32,
    pub rec_len: u16,
    pub name_len: u8,
    pub file_type: u8,
    pub name_offset: u32,
    pub ok: u8,
    pub _pad: [u8; 3],
}

pub const EXT4_MAGIC: u16 = 0xEF53;
const EXT4_SB_OFFSET: usize = 1024;
const EXT4_LOG_BLOCK_SIZE_MAX: u32 = 6;
pub const EXT4_EXTENT_HEADER_MAGIC: u16 = 0xF30A;
pub const EXT4_INODE_FLAG_EXTENTS: u32 = 0x80000;
pub const EXT4_FEATURE_RO_COMPAT_LARGE_FILE: u32 = 0x02;

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
fn load_u16_le(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

#[inline]
fn load_u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn parse_superblock(buf: &[u8], out: &mut DuetosExt4Superblock) -> bool {
    if buf.len() < EXT4_SB_OFFSET + 1024 {
        return false;
    }
    let sb = &buf[EXT4_SB_OFFSET..EXT4_SB_OFFSET + 1024];
    let magic = load_u16_le(sb, 0x38);
    if magic != EXT4_MAGIC {
        return false;
    }
    out.inodes_count = load_u32_le(sb, 0x00);
    out.blocks_count_lo = load_u32_le(sb, 0x04);
    out.free_blocks_count_lo = load_u32_le(sb, 0x0C);
    out.free_inodes_count = load_u32_le(sb, 0x10);
    out.first_data_block = load_u32_le(sb, 0x14);
    out.log_block_size = load_u32_le(sb, 0x18);
    out.blocks_per_group = load_u32_le(sb, 0x20);
    out.inodes_per_group = load_u32_le(sb, 0x28);
    out.magic = magic;
    out.state = load_u16_le(sb, 0x3A);
    out.rev_level = load_u32_le(sb, 0x4C);
    out.feature_compat = load_u32_le(sb, 0x5C);
    out.feature_incompat = load_u32_le(sb, 0x60);
    out.feature_ro_compat = load_u32_le(sb, 0x64);
    out.uuid.copy_from_slice(&sb[0x68..0x78]);
    out.inode_size = if out.rev_level >= 1 { load_u16_le(sb, 0x58) } else { 128 };
    if out.inode_size == 0 {
        out.inode_size = 128;
    }
    out.volume_name.copy_from_slice(&sb[0x78..0x88]);
    if out.log_block_size > EXT4_LOG_BLOCK_SIZE_MAX {
        return false;
    }
    if out.blocks_per_group == 0 || out.inodes_per_group == 0 {
        return false;
    }
    let block_size: u32 = 1024u32 << out.log_block_size;
    if u32::from(out.inode_size) > block_size {
        return false;
    }
    out.ok = 1;
    true
}

fn parse_group_desc0(buf: &[u8], out: &mut DuetosExt4GroupDesc) -> bool {
    if buf.len() < 32 {
        return false;
    }
    out.block_bitmap_block = load_u32_le(buf, 0x00);
    out.inode_bitmap_block = load_u32_le(buf, 0x04);
    out.inode_table_block = load_u32_le(buf, 0x08);
    out.free_blocks_count = load_u16_le(buf, 0x0C);
    out.free_inodes_count = load_u16_le(buf, 0x0E);
    out.used_dirs_count = load_u16_le(buf, 0x10);
    if out.inode_table_block == 0 {
        return false;
    }
    out.ok = 1;
    true
}

fn parse_inode(buf: &[u8], ino_size: u16, feature_ro_compat: u32, out: &mut DuetosExt4Inode) -> bool {
    if ino_size < 0x80 || (buf.len() as u16) < ino_size {
        return false;
    }
    out.mode = load_u16_le(buf, 0x00);
    out.uid = load_u16_le(buf, 0x02);
    let size_lo = load_u32_le(buf, 0x04);
    let mut size = u64::from(size_lo);
    if (feature_ro_compat & EXT4_FEATURE_RO_COMPAT_LARGE_FILE) != 0 && ino_size >= 0x70 {
        size |= u64::from(load_u32_le(buf, 0x6C)) << 32;
    }
    out.size_bytes = size;
    out.atime = load_u32_le(buf, 0x08);
    out.ctime = load_u32_le(buf, 0x0C);
    out.mtime = load_u32_le(buf, 0x10);
    out.gid = load_u16_le(buf, 0x18);
    out.links_count = load_u16_le(buf, 0x1A);
    out.blocks_lo = load_u32_le(buf, 0x1C);
    out.flags = load_u32_le(buf, 0x20);
    out.uses_extents = if (out.flags & EXT4_INODE_FLAG_EXTENTS) != 0 {
        1
    } else {
        0
    };
    out.block0_magic = load_u16_le(buf, 0x28);
    out.i_block.copy_from_slice(&buf[0x28..0x28 + 60]);
    out.ok = 1;
    true
}

fn parse_extent_header(buf: &[u8], out: &mut DuetosExt4ExtentHeader) -> bool {
    if buf.len() < 12 {
        return false;
    }
    let magic = load_u16_le(buf, 0);
    if magic != EXT4_EXTENT_HEADER_MAGIC {
        return false;
    }
    out.magic = magic;
    out.entries = load_u16_le(buf, 2);
    out.max = load_u16_le(buf, 4);
    out.depth = load_u16_le(buf, 6);
    out.generation = load_u32_le(buf, 8);
    if out.entries > out.max {
        return false;
    }
    out.ok = 1;
    true
}

fn parse_extent_leaf(buf: &[u8], idx: u16, out: &mut DuetosExt4Extent) -> bool {
    // Each extent record is 12 bytes; index 0 begins after the 12-
    // byte header.
    let off = 12 + (idx as usize) * 12;
    if off + 12 > buf.len() {
        return false;
    }
    out.logical_block = load_u32_le(buf, off);
    out.length_blocks = load_u16_le(buf, off + 4);
    let phys_hi = load_u16_le(buf, off + 6);
    let phys_lo = load_u32_le(buf, off + 8);
    out.physical_block = (u64::from(phys_hi) << 32) | u64::from(phys_lo);
    out.ok = 1;
    true
}

fn parse_extent_index(buf: &[u8], idx: u16, out: &mut DuetosExt4ExtentIndex) -> bool {
    let off = 12 + (idx as usize) * 12;
    if off + 12 > buf.len() {
        return false;
    }
    out.logical_block = load_u32_le(buf, off);
    let leaf_lo = load_u32_le(buf, off + 4);
    let leaf_hi = load_u16_le(buf, off + 8);
    out.leaf_block = (u64::from(leaf_hi) << 32) | u64::from(leaf_lo);
    out.ok = 1;
    true
}

/// Parse one linux_dirent record starting at `byte_off`. Returns
/// the bytes consumed (rec_len) on success, 0 on a hard error.
fn parse_dirent(block: &[u8], byte_off: u32, out: &mut DuetosExt4DirEntry) -> u32 {
    let off = byte_off as usize;
    if off + 8 > block.len() {
        return 0;
    }
    let inode = load_u32_le(block, off);
    let rec_len = load_u16_le(block, off + 4);
    let name_len = block[off + 6];
    let file_type = block[off + 7];
    if rec_len < 8 {
        return 0;
    }
    if (rec_len as usize) + off > block.len() {
        return 0;
    }
    if (rec_len & 0x3) != 0 {
        return 0;
    }
    // The name must fit inside this record. Without this, a crafted
    // image (e.g. rec_len=8 at the last 8 bytes of the block, but
    // name_len=255) makes the C++ caller copy `name_len` bytes from
    // `name_offset = off + 8`, reading past the directory block into
    // adjacent kernel heap and leaking it to the guest via readdir.
    // `rec_len + off <= block.len()` is already enforced above, so
    // bounding the name by `rec_len` bounds it by the block.
    if 8usize + (name_len as usize) > rec_len as usize {
        return 0;
    }
    out.inode = inode;
    out.rec_len = rec_len;
    out.name_len = name_len;
    out.file_type = file_type;
    out.name_offset = byte_off + 8;
    out.ok = if inode != 0 && name_len > 0 { 1 } else { 0 };
    rec_len as u32
}

// ---------- FFI ----------

#[no_mangle]
pub extern "C" fn duetos_ext4_parse_superblock(buf: *const u8, len: usize, out: *mut DuetosExt4Superblock) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_superblock(slice, dst)
}

#[no_mangle]
pub extern "C" fn duetos_ext4_parse_group_desc0(buf: *const u8, len: usize, out: *mut DuetosExt4GroupDesc) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_group_desc0(slice, dst)
}

#[no_mangle]
pub extern "C" fn duetos_ext4_parse_inode(
    buf: *const u8,
    len: usize,
    ino_size: u16,
    feature_ro_compat: u32,
    out: *mut DuetosExt4Inode,
) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_inode(slice, ino_size, feature_ro_compat, dst)
}

#[no_mangle]
pub extern "C" fn duetos_ext4_parse_extent_header(
    buf: *const u8,
    len: usize,
    out: *mut DuetosExt4ExtentHeader,
) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_extent_header(slice, dst)
}

#[no_mangle]
pub extern "C" fn duetos_ext4_parse_extent_leaf(
    buf: *const u8,
    len: usize,
    idx: u16,
    out: *mut DuetosExt4Extent,
) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_extent_leaf(slice, idx, dst)
}

#[no_mangle]
pub extern "C" fn duetos_ext4_parse_extent_index(
    buf: *const u8,
    len: usize,
    idx: u16,
    out: *mut DuetosExt4ExtentIndex,
) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    parse_extent_index(slice, idx, dst)
}

/// Parse one linux_dirent record. Returns the bytes consumed
/// (rec_len) on success, 0 on a hard error. `out->ok == 1` means
/// the record is a real entry (non-zero inode + name_len > 0);
/// `out->ok == 0` means "valid placeholder slot — advance past it".
#[no_mangle]
pub extern "C" fn duetos_ext4_parse_dirent(
    block: *const u8,
    block_len: usize,
    byte_off: u32,
    out: *mut DuetosExt4DirEntry,
) -> u32 {
    let Some(dst) = out_init(out) else {
        return 0;
    };
    let Some(slice) = slice_from_raw(block, block_len) else {
        return 0;
    };
    parse_dirent(slice, byte_off, dst)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ext4_disk() -> [u8; 2048] {
        let mut buf = [0u8; 2048];
        let sb = &mut buf[EXT4_SB_OFFSET..EXT4_SB_OFFSET + 1024];
        sb[0x00..0x04].copy_from_slice(&8192u32.to_le_bytes());
        sb[0x04..0x08].copy_from_slice(&65536u32.to_le_bytes());
        sb[0x18..0x1C].copy_from_slice(&2u32.to_le_bytes()); // 4 KiB blocks
        sb[0x20..0x24].copy_from_slice(&8192u32.to_le_bytes());
        sb[0x28..0x2C].copy_from_slice(&1024u32.to_le_bytes());
        sb[0x38..0x3A].copy_from_slice(&EXT4_MAGIC.to_le_bytes());
        sb[0x3A..0x3C].copy_from_slice(&1u16.to_le_bytes());
        sb[0x4C..0x50].copy_from_slice(&1u32.to_le_bytes()); // rev_level=1
        sb[0x58..0x5A].copy_from_slice(&256u16.to_le_bytes()); // inode_size=256
        buf
    }

    #[test]
    fn ext4_valid_superblock_parses() {
        let buf = make_ext4_disk();
        let mut out = DuetosExt4Superblock::default();
        assert!(parse_superblock(&buf, &mut out));
        assert_eq!(out.magic, EXT4_MAGIC);
        assert_eq!(out.inodes_count, 8192);
        assert_eq!(out.blocks_count_lo, 65536);
        assert_eq!(out.log_block_size, 2);
        assert_eq!(out.blocks_per_group, 8192);
        assert_eq!(out.inodes_per_group, 1024);
        assert_eq!(out.inode_size, 256);
        assert_eq!(out.ok, 1);
    }

    #[test]
    fn ext4_bad_magic_rejects() {
        let mut buf = make_ext4_disk();
        buf[EXT4_SB_OFFSET + 0x38] = 0;
        let mut out = DuetosExt4Superblock::default();
        assert!(!parse_superblock(&buf, &mut out));
    }

    #[test]
    fn ext4_overlong_log_block_size_rejects() {
        let mut buf = make_ext4_disk();
        buf[EXT4_SB_OFFSET + 0x18..EXT4_SB_OFFSET + 0x1C].copy_from_slice(&7u32.to_le_bytes());
        let mut out = DuetosExt4Superblock::default();
        assert!(!parse_superblock(&buf, &mut out));
    }

    #[test]
    fn ext4_zero_blocks_per_group_rejects() {
        let mut buf = make_ext4_disk();
        buf[EXT4_SB_OFFSET + 0x20..EXT4_SB_OFFSET + 0x24].copy_from_slice(&0u32.to_le_bytes());
        let mut out = DuetosExt4Superblock::default();
        assert!(!parse_superblock(&buf, &mut out));
    }

    #[test]
    fn ext4_inode_size_exceeding_block_rejects() {
        let mut buf = make_ext4_disk();
        // s_log_block_size = 0 ⇒ 1 KiB blocks; inode_size 2048
        // doesn't fit.
        buf[EXT4_SB_OFFSET + 0x18..EXT4_SB_OFFSET + 0x1C].copy_from_slice(&0u32.to_le_bytes());
        buf[EXT4_SB_OFFSET + 0x58..EXT4_SB_OFFSET + 0x5A].copy_from_slice(&2048u16.to_le_bytes());
        let mut out = DuetosExt4Superblock::default();
        assert!(!parse_superblock(&buf, &mut out));
    }

    #[test]
    fn ext4_too_short_rejects() {
        let buf = [0u8; 1024];
        let mut out = DuetosExt4Superblock::default();
        assert!(!parse_superblock(&buf, &mut out));
    }

    // ---- Group descriptor ----

    #[test]
    fn group_desc_parses() {
        let mut buf = [0u8; 32];
        buf[0x00..0x04].copy_from_slice(&100u32.to_le_bytes());
        buf[0x04..0x08].copy_from_slice(&101u32.to_le_bytes());
        buf[0x08..0x0C].copy_from_slice(&102u32.to_le_bytes());
        buf[0x0C..0x0E].copy_from_slice(&500u16.to_le_bytes());
        buf[0x0E..0x10].copy_from_slice(&600u16.to_le_bytes());
        buf[0x10..0x12].copy_from_slice(&5u16.to_le_bytes());
        let mut out = DuetosExt4GroupDesc::default();
        assert!(parse_group_desc0(&buf, &mut out));
        assert_eq!(out.block_bitmap_block, 100);
        assert_eq!(out.inode_table_block, 102);
        assert_eq!(out.used_dirs_count, 5);
        assert_eq!(out.ok, 1);
    }

    #[test]
    fn group_desc_zero_inode_table_rejects() {
        let buf = [0u8; 32];
        let mut out = DuetosExt4GroupDesc::default();
        assert!(!parse_group_desc0(&buf, &mut out));
    }

    // ---- Inode ----

    fn make_inode_buf() -> [u8; 256] {
        let mut buf = [0u8; 256];
        buf[0x00..0x02].copy_from_slice(&0x41EDu16.to_le_bytes()); // dir + 0755
        buf[0x04..0x08].copy_from_slice(&4096u32.to_le_bytes()); // size_lo
        buf[0x1A..0x1C].copy_from_slice(&2u16.to_le_bytes()); // links_count = 2
        buf[0x20..0x24].copy_from_slice(&EXT4_INODE_FLAG_EXTENTS.to_le_bytes());
        buf[0x28..0x2A].copy_from_slice(&EXT4_EXTENT_HEADER_MAGIC.to_le_bytes());
        buf
    }

    #[test]
    fn inode_decoder_passes() {
        let buf = make_inode_buf();
        let mut out = DuetosExt4Inode::default();
        assert!(parse_inode(&buf, 256, 0, &mut out));
        assert_eq!(out.mode, 0x41ED);
        assert_eq!(out.size_bytes, 4096);
        assert_eq!(out.uses_extents, 1);
        assert_eq!(out.block0_magic, EXT4_EXTENT_HEADER_MAGIC);
        assert_eq!(out.ok, 1);
    }

    #[test]
    fn inode_decoder_handles_large_file_size_hi() {
        let mut buf = make_inode_buf();
        buf[0x6C..0x70].copy_from_slice(&1u32.to_le_bytes()); // size_hi = 1
        let mut out = DuetosExt4Inode::default();
        assert!(parse_inode(&buf, 256, EXT4_FEATURE_RO_COMPAT_LARGE_FILE, &mut out));
        // 4096 + (1 << 32).
        assert_eq!(out.size_bytes, 4096u64 + (1u64 << 32));
    }

    #[test]
    fn inode_decoder_short_ino_size_rejects() {
        let buf = make_inode_buf();
        let mut out = DuetosExt4Inode::default();
        assert!(!parse_inode(&buf, 0x70, 0, &mut out));
    }

    // ---- Extent header / leaf / index ----

    #[test]
    fn extent_header_passes() {
        let mut buf = [0u8; 24];
        buf[0..2].copy_from_slice(&EXT4_EXTENT_HEADER_MAGIC.to_le_bytes());
        buf[2..4].copy_from_slice(&1u16.to_le_bytes()); // entries
        buf[4..6].copy_from_slice(&4u16.to_le_bytes()); // max
        buf[6..8].copy_from_slice(&0u16.to_le_bytes()); // depth = 0
        let mut out = DuetosExt4ExtentHeader::default();
        assert!(parse_extent_header(&buf, &mut out));
        assert_eq!(out.entries, 1);
        assert_eq!(out.max, 4);
        assert_eq!(out.depth, 0);
    }

    #[test]
    fn extent_header_bad_magic_rejects() {
        let mut buf = [0u8; 12];
        buf[0..2].copy_from_slice(&0u16.to_le_bytes());
        let mut out = DuetosExt4ExtentHeader::default();
        assert!(!parse_extent_header(&buf, &mut out));
    }

    #[test]
    fn extent_header_entries_exceed_max_rejects() {
        let mut buf = [0u8; 12];
        buf[0..2].copy_from_slice(&EXT4_EXTENT_HEADER_MAGIC.to_le_bytes());
        buf[2..4].copy_from_slice(&10u16.to_le_bytes());
        buf[4..6].copy_from_slice(&4u16.to_le_bytes());
        let mut out = DuetosExt4ExtentHeader::default();
        assert!(!parse_extent_header(&buf, &mut out));
    }

    #[test]
    fn extent_leaf_decodes() {
        let mut buf = [0u8; 24];
        buf[0..2].copy_from_slice(&EXT4_EXTENT_HEADER_MAGIC.to_le_bytes());
        buf[2..4].copy_from_slice(&1u16.to_le_bytes());
        buf[4..6].copy_from_slice(&4u16.to_le_bytes());
        // Extent record at offset 12.
        buf[12..16].copy_from_slice(&100u32.to_le_bytes()); // logical
        buf[16..18].copy_from_slice(&5u16.to_le_bytes()); // length
        buf[18..20].copy_from_slice(&0u16.to_le_bytes()); // phys_hi
        buf[20..24].copy_from_slice(&12345u32.to_le_bytes()); // phys_lo
        let mut e = DuetosExt4Extent::default();
        assert!(parse_extent_leaf(&buf, 0, &mut e));
        assert_eq!(e.logical_block, 100);
        assert_eq!(e.length_blocks, 5);
        assert_eq!(e.physical_block, 12345);
    }

    #[test]
    fn extent_index_decodes() {
        let mut buf = [0u8; 24];
        buf[0..2].copy_from_slice(&EXT4_EXTENT_HEADER_MAGIC.to_le_bytes());
        // Index record at offset 12.
        buf[12..16].copy_from_slice(&100u32.to_le_bytes());
        buf[16..20].copy_from_slice(&54321u32.to_le_bytes()); // leaf_lo
        buf[20..22].copy_from_slice(&1u16.to_le_bytes()); // leaf_hi
        let mut e = DuetosExt4ExtentIndex::default();
        assert!(parse_extent_index(&buf, 0, &mut e));
        assert_eq!(e.logical_block, 100);
        assert_eq!(e.leaf_block, (1u64 << 32) | 54321);
    }

    // ---- Dirent walker ----

    #[test]
    fn dirent_parses_simple() {
        // inode=2, rec_len=12, name_len=1, file_type=2, name=".".
        let mut buf = [0u8; 12];
        buf[0..4].copy_from_slice(&2u32.to_le_bytes());
        buf[4..6].copy_from_slice(&12u16.to_le_bytes());
        buf[6] = 1;
        buf[7] = 2; // file_type DIR
        buf[8] = b'.';
        let mut e = DuetosExt4DirEntry::default();
        let consumed = parse_dirent(&buf, 0, &mut e);
        assert_eq!(consumed, 12);
        assert_eq!(e.inode, 2);
        assert_eq!(e.name_len, 1);
        assert_eq!(e.name_offset, 8);
        assert_eq!(e.ok, 1);
    }

    #[test]
    fn dirent_rejects_misaligned_rec_len() {
        let mut buf = [0u8; 16];
        buf[0..4].copy_from_slice(&1u32.to_le_bytes());
        buf[4..6].copy_from_slice(&15u16.to_le_bytes()); // not 4-byte aligned
        buf[6] = 1;
        buf[7] = 1;
        buf[8] = b'a';
        let mut e = DuetosExt4DirEntry::default();
        let consumed = parse_dirent(&buf, 0, &mut e);
        assert_eq!(consumed, 0);
    }

    #[test]
    fn dirent_unused_slot_ok_false() {
        // inode=0, rec_len=8, name_len=0 — placeholder slot.
        let mut buf = [0u8; 8];
        buf[0..4].copy_from_slice(&0u32.to_le_bytes());
        buf[4..6].copy_from_slice(&8u16.to_le_bytes());
        let mut e = DuetosExt4DirEntry::default();
        let consumed = parse_dirent(&buf, 0, &mut e);
        assert_eq!(consumed, 8);
        assert_eq!(e.ok, 0);
    }

    #[test]
    fn dirent_truncated_rejects() {
        let buf = [0u8; 4];
        let mut e = DuetosExt4DirEntry::default();
        let consumed = parse_dirent(&buf, 0, &mut e);
        assert_eq!(consumed, 0);
    }

    #[test]
    fn dirent_rec_len_too_short_rejects() {
        let mut buf = [0u8; 16];
        buf[0..4].copy_from_slice(&1u32.to_le_bytes());
        buf[4..6].copy_from_slice(&4u16.to_le_bytes()); // < 8 → invalid
        let mut e = DuetosExt4DirEntry::default();
        let consumed = parse_dirent(&buf, 0, &mut e);
        assert_eq!(consumed, 0);
    }
}
