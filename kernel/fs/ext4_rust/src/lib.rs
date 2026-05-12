//! DuetOS ext4 metadata walker — **skeleton**.
//!
//! Foundation for a future read-only ext4 driver. v0 covers only
//! the superblock magic + headline layout fields a mount path
//! needs. Inode table, dirent walker, extent tree, HTREE indexes
//! are next-slice work tracked in `wiki/filesystem/ext4.md`.
//!
//! No current C++ caller.

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
    pub log_block_size: u32, // log2(block_size) - 10
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub magic: u16, // always 0xEF53 on success
    pub state: u16,
    pub rev_level: u32,
    pub feature_compat: u32,
    pub feature_incompat: u32,
    pub feature_ro_compat: u32,
    pub uuid: [u8; 16],
    pub ok: u8,
    pub _pad: [u8; 7],
}

/// ext2/3/4 superblock magic.
const EXT4_MAGIC: u16 = 0xEF53;
/// Superblock lives at offset 1024 in any ext2/3/4 volume.
const EXT4_SB_OFFSET: usize = 1024;
/// Spec: log_block_size <= 6 (block size = 1024 << log = 64 KiB max).
const EXT4_LOG_BLOCK_SIZE_MAX: u32 = 6;

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
    // Caller passes the disk image starting at offset 0; the
    // superblock lives at offset 1024 and is 1024 bytes itself.
    if buf.len() < EXT4_SB_OFFSET + 1024 {
        return false;
    }
    let sb = &buf[EXT4_SB_OFFSET..EXT4_SB_OFFSET + 1024];
    // Magic at offset 0x38 within the superblock.
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
    if out.log_block_size > EXT4_LOG_BLOCK_SIZE_MAX {
        return false;
    }
    if out.blocks_per_group == 0 || out.inodes_per_group == 0 {
        return false;
    }
    out.ok = 1;
    true
}

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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ext4_disk() -> [u8; 2048] {
        let mut buf = [0u8; 2048];
        let sb = &mut buf[EXT4_SB_OFFSET..EXT4_SB_OFFSET + 1024];
        sb[0x00..0x04].copy_from_slice(&8192u32.to_le_bytes()); // inodes_count
        sb[0x04..0x08].copy_from_slice(&65536u32.to_le_bytes()); // blocks_count_lo
        sb[0x18..0x1C].copy_from_slice(&2u32.to_le_bytes()); // log_block_size = 4096
        sb[0x20..0x24].copy_from_slice(&8192u32.to_le_bytes()); // blocks_per_group
        sb[0x28..0x2C].copy_from_slice(&1024u32.to_le_bytes()); // inodes_per_group
        sb[0x38..0x3A].copy_from_slice(&EXT4_MAGIC.to_le_bytes()); // magic
        sb[0x3A..0x3C].copy_from_slice(&1u16.to_le_bytes()); // state = clean
                                                             // Feature flags + uuid stay zero — fine for v0 sanity.
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
    fn ext4_too_short_rejects() {
        let buf = [0u8; 1024];
        let mut out = DuetosExt4Superblock::default();
        assert!(!parse_superblock(&buf, &mut out));
    }
}
