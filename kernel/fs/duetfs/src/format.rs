// DuetFS v1 on-disk format.
//
//   block 0          Superblock (struct Superblock, padded to BLOCK_SIZE)
//   block 1          Free-block bitmap (1 bit per block; bit set = in use)
//   block 2..=5      Node table (NODES_PER_BLOCK × Node per block, 4 blocks = 64 nodes)
//   block 6..        Data blocks (file extents, dir-children blocks)
//
// All multi-byte integers are little-endian. Strings are NUL-padded
// inside their fixed-size buffers; name_len carries the active
// length so callers don't have to strlen.
//
// Lineage: clean-room, inspired by RedoxFS. v1 adds the persistence
// shape (free bitmap) and a write path. CoW / journal / checksums /
// encryption / compression / B-tree are tracked in
// wiki/reference/Roadmap.md and land in their own slices.

pub const BLOCK_SIZE: usize = 4096;
pub const NODE_SIZE: usize = 256;
pub const NODES_PER_BLOCK: usize = BLOCK_SIZE / NODE_SIZE; // 16
pub const NAME_MAX: usize = 64;

// Layout constants. Fixed in v1; parameterized in a later slice.
pub const SUPERBLOCK_LBA: u32 = 0;
pub const BITMAP_LBA: u32 = 1;
pub const NODE_TABLE_LBA: u32 = 2;
pub const NODE_TABLE_BLOCKS: u32 = 4;
pub const NODE_COUNT: u32 = NODE_TABLE_BLOCKS * (NODES_PER_BLOCK as u32); // 64
pub const DATA_LBA: u32 = NODE_TABLE_LBA + NODE_TABLE_BLOCKS; // 6
pub const MIN_TOTAL_BLOCKS: u32 = DATA_LBA + 1;               // 7

// Bitmap: 1 block = 4096 B = 32768 bits. Covers up to 32768-block
// (128 MiB) volumes — more than enough for v1.
pub const BITMAP_BITS: u32 = (BLOCK_SIZE as u32) * 8;
pub const MAX_TOTAL_BLOCKS: u32 = BITMAP_BITS;

// "DuetFS01" little-endian (byte 0 = 'D' = 0x44, byte 7 = '1' = 0x31).
pub const MAGIC: u64 = u64::from_le_bytes(*b"DuetFS01");
pub const VERSION: u32 = 2;

pub const NODE_KIND_UNUSED: u32 = 0;
pub const NODE_KIND_FILE: u32 = 1;
pub const NODE_KIND_DIR: u32 = 2;

pub const ROOT_NODE_ID: u32 = 0;
pub const INVALID_NODE_ID: u32 = 0xFFFFFFFFu32;

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
    pub free_blocks: u32, // accounting; rederivable from the bitmap
    pub reserved: [u32; 5],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Node
{
    pub kind: u32,        // NODE_KIND_*
    pub size_bytes: u32,  // file: byte length; dir: child_count × 4
    pub first_block: u32, // first data block of the file/dir's extent
    pub ext_blocks: u32,  // number of blocks reserved for the extent
    pub child_count: u32, // dir only; 0 for files
    pub name_len: u32,    // active length of `name` (≤ NAME_MAX)
    pub parent_id: u32,   // parent node id (root → ROOT_NODE_ID)
    pub reserved: u32,
    pub name: [u8; NAME_MAX],
    pub pad: [u8; NODE_SIZE - 32 - NAME_MAX], // = 160 bytes
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
            first_block: 0,
            ext_blocks: 0,
            child_count: 0,
            name_len: 0,
            parent_id: INVALID_NODE_ID,
            reserved: 0,
            name: [0u8; NAME_MAX],
            pad: [0u8; NODE_SIZE - 32 - NAME_MAX],
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
}

/// Compute the number of blocks needed to hold `bytes`.
pub const fn blocks_for_bytes(bytes: u32) -> u32
{
    (bytes as usize).div_ceil(BLOCK_SIZE) as u32
}
