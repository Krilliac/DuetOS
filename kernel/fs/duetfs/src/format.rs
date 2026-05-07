// DuetFS v5 on-disk format.
//
//   block 0          Superblock (struct Superblock, padded to BLOCK_SIZE)
//   block 1          Free-block bitmap (1 bit per block; bit set = in use)
//   block 2          CRC table (1024 × u32, one per FS block; v3 caps
//                    images at 1024 blocks = 4 MiB)
//   block 3..=6      Node table (NODES_PER_BLOCK × Node per block, 4 blocks = 64 nodes)
//   block 7..=14     Journal (1 descriptor + 7 payload slots, v5)
//   block 15..       Data blocks (file extents, dir-children blocks)
//
// All multi-byte integers are little-endian.
//
// v5 changes vs v3 (v3 → v4 was a fix-only bump that didn't ship a
// public format; v5 is the first format-extending bump):
//   - Journal at JOURNAL_LBA covers atomic metadata writes (every
//     write_node + bitmap-flush + crc-table-flush path). On mount
//     Fs::open replays any committed-but-unfinished txn, so a
//     torn write of a multi-block metadata mutation either fully
//     persists or fully reverts. See src/journal.rs.
//   - Superblock gains journal_lba + journal_blocks (consume the
//     two pre-existing reserved u32 fields).
//   - DATA_LBA shifts from 7 to 15.
//
// v3 changes vs v2:
//   - Per-block CRCs stored in a CRC table at LBA 2.
//   - Node carries `link_count`; NODE_KIND_SYMLINK is a new kind.

pub const BLOCK_SIZE: usize = 4096;
pub const NODE_SIZE: usize = 256;
pub const NODES_PER_BLOCK: usize = BLOCK_SIZE / NODE_SIZE; // 16
pub const NAME_MAX: usize = 64;
pub const MAX_INLINE_EXTENTS: usize = 8;

// Layout constants (v3). Fixed; parameterized in a later slice.
pub const SUPERBLOCK_LBA: u32 = 0;
pub const BITMAP_LBA: u32 = 1;
pub const CRC_TABLE_LBA: u32 = 2;
pub const CRC_TABLE_BLOCKS: u32 = 1;
pub const NODE_TABLE_LBA: u32 = CRC_TABLE_LBA + CRC_TABLE_BLOCKS; // 3
pub const NODE_TABLE_BLOCKS: u32 = 4;
pub const NODE_COUNT: u32 = NODE_TABLE_BLOCKS * (NODES_PER_BLOCK as u32); // 64

// Journal — v5. 1 descriptor block + 7 payload slots. Sized so an
// internal mutation that touches at most one metadata block (the
// dominant case: write_node updates a single node-table block) plus
// up to six co-affected blocks (bitmap, crc-table, dir-child block,
// truncate's freed-extent zeros, …) commits in a single txn. Larger
// batches must split into multiple txns and accept loss of cross-txn
// atomicity — a follow-up grows the journal once a real workload
// shows the contention.
pub const JOURNAL_LBA: u32 = NODE_TABLE_LBA + NODE_TABLE_BLOCKS; // 7
pub const JOURNAL_BLOCKS: u32 = 8;
pub const MAX_JOURNAL_OPS: usize = (JOURNAL_BLOCKS - 1) as usize; // 7

pub const JOURNAL_DESCRIPTOR_MAGIC: u32 = u32::from_le_bytes(*b"DJRN");
pub const JOURNAL_STATE_EMPTY: u32 = 0;
pub const JOURNAL_STATE_COMMITTED: u32 = 1;

pub const DATA_LBA: u32 = JOURNAL_LBA + JOURNAL_BLOCKS; // 15
pub const MIN_TOTAL_BLOCKS: u32 = DATA_LBA + 1; // 16

// CRC table: one block = 1024 × u32 entries. v3 cap = 1024 blocks.
pub const CRC_TABLE_ENTRIES: u32 = (BLOCK_SIZE / 4) as u32;
pub const MAX_TOTAL_BLOCKS: u32 = CRC_TABLE_ENTRIES;

// Bitmap unchanged from v2 (still single block, more capacity than CRC table).
pub const BITMAP_BITS: u32 = (BLOCK_SIZE as u32) * 8;

pub const MAGIC: u64 = u64::from_le_bytes(*b"DuetFS01");
pub const VERSION: u32 = 6;

// Encryption — v6. The volume is either fully encrypted or fully
// unencrypted; per-file encryption isn't on the roadmap. Block 0
// (SB) stays plaintext so a mounter can read these fields before
// it has the key. Every other block is AES-256-XTS-encrypted with
// sector index = LBA.
pub const ENCRYPTED_NO: u32 = 0;
pub const ENCRYPTED_AES_XTS_256: u32 = 1;
pub const SALT_BYTES: usize = 16;

pub const NODE_KIND_UNUSED: u32 = 0;
pub const NODE_KIND_FILE: u32 = 1;
pub const NODE_KIND_DIR: u32 = 2;
pub const NODE_KIND_SYMLINK: u32 = 3;

pub const ROOT_NODE_ID: u32 = 0;
pub const INVALID_NODE_ID: u32 = 0xFFFFFFFFu32;

/// Maximum symlink target length. Stored inline in the symlink
/// node's first extent's first block; bounded so a target fits
/// without ever needing a multi-block read on resolve.
pub const SYMLINK_TARGET_MAX: u32 = 1024;

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
    pub crc_table_lba: u32,
    pub crc_table_blocks: u32,
    pub node_table_lba: u32,
    pub node_table_blocks: u32,
    pub data_lba: u32,
    pub free_blocks: u32,
    pub sb_crc32: u32, // CRC32 of SB with this field zeroed
    // v5 — journal pinning. Cross-validated against the compile-time
    // JOURNAL_LBA / JOURNAL_BLOCKS constants by Fs::open.
    pub journal_lba: u32,
    pub journal_blocks: u32,
    // v6 — encryption metadata. `encrypted` is one of the
    // ENCRYPTED_* constants above; ENCRYPTED_NO leaves every block
    // plaintext and the rest of these fields are zero. For an
    // ENCRYPTED_AES_XTS_256 volume the salt + KDF costs let a
    // mounter reconstruct the key from a password without storing
    // anything secret in plain on disk.
    pub encrypted: u32,
    pub kdf_m_cost_kib: u32,
    pub kdf_t_cost: u32,
    pub kdf_p_cost: u32,
    pub kdf_salt: [u8; SALT_BYTES],
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
    pub link_count: u32, // hard-link refcount (1 at create; 0 unlinked)
    pub reserved: u32,
    pub name: [u8; NAME_MAX],
    pub extents: [Extent; MAX_INLINE_EXTENTS],
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
            link_count: 0,
            reserved: 0,
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

pub const fn blocks_for_bytes(bytes: u32) -> u32
{
    (bytes as usize).div_ceil(BLOCK_SIZE) as u32
}
