// DuetFS v0 on-disk format.
//
//   block 0          superblock (struct Superblock, padded to BLOCK_SIZE)
//   block 1..=N      node table (NODES_PER_BLOCK × Node per block)
//   block N+1..      data blocks (file extents + dir-child arrays)
//
// All multi-byte integers are little-endian. Strings are NUL-padded
// inside their fixed-size buffers; name_len carries the active
// length so callers don't have to strlen.
//
// Format choices were made to keep the v0 mkfs (a Rust function that
// writes a constinit byte array at compile time on the C++ side, see
// kernel/fs/duetfs/duetfs_image.cpp) trivially expressible. RedoxFS
// uses a B-tree; v0 uses a flat node table because lookup walks
// names linearly and v0's ceiling on entries is the test image, not
// production.

pub const BLOCK_SIZE: usize = 4096;
pub const NODE_SIZE: usize = 256;
pub const NODES_PER_BLOCK: usize = BLOCK_SIZE / NODE_SIZE; // 16
pub const NAME_MAX: usize = 64;

// "DuetFS00" little-endian → [0x44 0x75 0x65 0x74 0x46 0x53 0x30 0x30]
pub const MAGIC: u64 = u64::from_le_bytes(*b"DuetFS00");
pub const VERSION: u32 = 1;

pub const NODE_KIND_UNUSED: u32 = 0;
pub const NODE_KIND_FILE: u32 = 1;
pub const NODE_KIND_DIR: u32 = 2;

pub const ROOT_NODE_ID: u32 = 0;

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
    pub node_table_start: u32, // first block of the node table; v0 = 1
    pub data_start: u32,       // first block after the node table
    pub reserved: [u32; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Node
{
    pub kind: u32,        // NODE_KIND_*
    pub size_bytes: u32,  // file size; for dirs = child_count × 4
    pub first_block: u32, // file: first data block; dir: child-id-array block
    pub child_count: u32, // dir only; 0 for files
    pub name_len: u32,    // active length of `name` (≤ NAME_MAX)
    pub reserved: u32,
    pub name: [u8; NAME_MAX],
    pub pad: [u8; NODE_SIZE - 24 - NAME_MAX], // = 168 bytes
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
            child_count: 0,
            name_len: 0,
            reserved: 0,
            name: [0u8; NAME_MAX],
            pad: [0u8; NODE_SIZE - 24 - NAME_MAX],
        }
    }

    pub fn name_bytes(&self) -> &[u8]
    {
        let n = (self.name_len as usize).min(NAME_MAX);
        &self.name[..n]
    }
}
