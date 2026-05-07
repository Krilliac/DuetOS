// DuetFS v2 on-disk format.
//
//   block 0          Superblock (struct Superblock, padded to BLOCK_SIZE)
//   block 1          Free-block bitmap (1 bit per block; bit set = in use)
//   block 2..=5      Node table (NODES_PER_BLOCK × Node per block, 4 blocks = 64 nodes)
//   block 6..        Data blocks (file extents, dir-children blocks)
//
// All multi-byte integers are little-endian.
//
// v2 changes vs v1:
//   - Node carries up to MAX_INLINE_EXTENTS (8) inline extents
//     instead of a single contiguous extent. Read / write walk
//     the extent list; grow_file appends a new extent rather than
//     realloc-and-copy when possible.
//   - Superblock carries a CRC32 (sb_crc32) covering the SB with
//     that field zeroed. Computed at mkfs / mutation time and
//     verified at every Fs::open. A mismatch fails open() with
//     FsError::Invalid — fsck (kernel/fs/duetfs/src/fsck.rs)
//     can rebuild the SB from the node table.
//
// Lineage: clean-room, inspired by RedoxFS. CoW / journal /
// encryption / compression / B-tree are tracked in
// wiki/reference/Roadmap.md and land in their own slices.

pub const BLOCK_SIZE: usize = 4096;
pub const NODE_SIZE: usize = 256;
pub const NODES_PER_BLOCK: usize = BLOCK_SIZE / NODE_SIZE; // 16
pub const NAME_MAX: usize = 64;
pub const MAX_INLINE_EXTENTS: usize = 8;

// Layout constants. Fixed in v2; parameterized in a later slice.
pub const SUPERBLOCK_LBA: u32 = 0;
pub const BITMAP_LBA: u32 = 1;
pub const NODE_TABLE_LBA: u32 = 2;
pub const NODE_TABLE_BLOCKS: u32 = 4;
pub const NODE_COUNT: u32 = NODE_TABLE_BLOCKS * (NODES_PER_BLOCK as u32); // 64
pub const DATA_LBA: u32 = NODE_TABLE_LBA + NODE_TABLE_BLOCKS; // 6
pub const MIN_TOTAL_BLOCKS: u32 = DATA_LBA + 1;               // 7

// Bitmap: 1 block = 4096 B = 32768 bits. Covers up to 32768-block
// (128 MiB) volumes — more than enough for v2.
pub const BITMAP_BITS: u32 = (BLOCK_SIZE as u32) * 8;
pub const MAX_TOTAL_BLOCKS: u32 = BITMAP_BITS;

// "DuetFS01" little-endian (byte 0 = 'D' = 0x44, byte 7 = '1' = 0x31).
// Magic stayed; only the version field bumps for v2.
pub const MAGIC: u64 = u64::from_le_bytes(*b"DuetFS01");
pub const VERSION: u32 = 3;

pub const NODE_KIND_UNUSED: u32 = 0;
pub const NODE_KIND_FILE: u32 = 1;
pub const NODE_KIND_DIR: u32 = 2;

pub const ROOT_NODE_ID: u32 = 0;
pub const INVALID_NODE_ID: u32 = 0xFFFFFFFFu32;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Extent
{
    pub block: u32,
    pub blocks: u32,
}

const _: () = assert!(core::mem::size_of::<Extent>() == 8);

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Superblock
{
    pub magic: u64,
    pub version: u32,
    pub block_size: u32,
    pub total_blocks: u32,
    pub node_count: u32,
    pub root_node: u32,
    pub bitmap_lba: u32,
    pub node_table_lba: u32,
    pub node_table_blocks: u32,
    pub data_lba: u32,
    pub free_blocks: u32,
    pub sb_crc32: u32, // CRC32 of SB with this field zeroed
    pub reserved: [u32; 4],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Node
{
    pub kind: u32,
    pub size_bytes: u32,
    pub extent_count: u32, // 0..=MAX_INLINE_EXTENTS
    pub child_count: u32,
    pub name_len: u32,
    pub parent_id: u32,
    pub reserved: [u32; 2],
    pub name: [u8; NAME_MAX],
    pub extents: [Extent; MAX_INLINE_EXTENTS], // 8 × 8 B = 64 B
    pub pad: [u8; NODE_SIZE - 32 - NAME_MAX - 8 * MAX_INLINE_EXTENTS],
}

const _: () = assert!(core::mem::size_of::<Node>() == NODE_SIZE);
const _: () = assert!(core::mem::size_of::<Superblock>() <= BLOCK_SIZE);

impl Node
{
    pub const fn unused() -> Self
    {
        Self {
            kind: NODE_KIND_UNUSED,
            size_bytes: 0,
            extent_count: 0,
            child_count: 0,
            name_len: 0,
            parent_id: INVALID_NODE_ID,
            reserved: [0; 2],
            name: [0u8; NAME_MAX],
            extents: [Extent { block: 0, blocks: 0 }; MAX_INLINE_EXTENTS],
            pad: [0u8; NODE_SIZE - 32 - NAME_MAX - 8 * MAX_INLINE_EXTENTS],
        }
    }

    pub fn name_bytes(&self) -> &[u8]
    {
        let n = (self.name_len as usize).min(NAME_MAX);
        &self.name[..n]
    }

    pub fn set_name(&mut self, name: &[u8]) -> bool
    {
        if name.len() > NAME_MAX
        {
            return false;
        }
        self.name = [0u8; NAME_MAX];
        self.name[..name.len()].copy_from_slice(name);
        self.name_len = name.len() as u32;
        true
    }

    /// Total blocks reserved across all valid extents.
    pub fn total_blocks(&self) -> u32
    {
        let mut t: u32 = 0;
        for i in 0..(self.extent_count as usize).min(MAX_INLINE_EXTENTS)
        {
            t = t.saturating_add(self.extents[i].blocks);
        }
        t
    }
}

/// Compute the number of blocks needed to hold `bytes`.
pub const fn blocks_for_bytes(bytes: u32) -> u32
{
    (bytes as usize).div_ceil(BLOCK_SIZE) as u32
}
