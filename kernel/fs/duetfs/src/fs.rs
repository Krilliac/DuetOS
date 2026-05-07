// DuetFS open-filesystem state.
//
// `Fs<'d, D>` borrows a block device and caches the superblock +
// free-block bitmap. Path / directory / file ops live in ops.rs;
// this file holds the foundations: open, sync, node-table I/O,
// extent allocation/free, superblock CRC verification.
//
// Nothing here allocates dynamically — every buffer is on the stack.

use crate::alloc_bitmap::BitmapAllocator;
use crate::block_dev::BlockDevice;
use crate::crc32::crc32;
use crate::format::{
    Node, Superblock, BITMAP_LBA, BLOCK_SIZE, DATA_LBA, MAGIC, MAX_INLINE_EXTENTS, NAME_MAX,
    NODE_COUNT, NODE_KIND_UNUSED, NODE_SIZE, NODE_TABLE_BLOCKS, NODE_TABLE_LBA,
    NODES_PER_BLOCK, ROOT_NODE_ID, SUPERBLOCK_LBA, VERSION,
};

#[derive(Clone, Copy)]
pub enum FsError
{
    Io,
    NotFound,
    NotADir,
    NotAFile,
    NameTooLong,
    NameExists,
    DirNotEmpty,
    NoSpaceData,
    NoSpaceNodes,
    NoSpaceExtents,
    Invalid,
    ReadOnly,
    Corrupt,
}

pub type FsResult<T> = Result<T, FsError>;

pub struct Fs<'d, D: BlockDevice + ?Sized + 'd>
{
    pub(crate) dev: &'d mut D,
    pub(crate) sb: Superblock,
    pub(crate) bitmap: BitmapAllocator,
}

impl<'d, D: BlockDevice + ?Sized> Fs<'d, D>
{
    pub fn open(dev: &'d mut D) -> FsResult<Self>
    {
        let mut block = [0u8; BLOCK_SIZE];
        dev.read_block(SUPERBLOCK_LBA, &mut block).map_err(|_| FsError::Io)?;
        let sb = read_superblock(&block);
        if sb.magic != MAGIC
            || sb.version != VERSION
            || sb.block_size as usize != BLOCK_SIZE
            || sb.bitmap_lba != BITMAP_LBA
            || sb.node_table_lba != NODE_TABLE_LBA
            || sb.node_table_blocks != NODE_TABLE_BLOCKS
            || sb.node_count != NODE_COUNT
            || sb.data_lba != DATA_LBA
            || sb.total_blocks > dev.block_count()
        {
            return Err(FsError::Invalid);
        }
        // Verify CRC. We zero out the sb_crc32 field in the
        // computed image and recompute over the same span.
        let want = sb.sb_crc32;
        let got = compute_sb_crc(&sb);
        if want != got
        {
            return Err(FsError::Corrupt);
        }
        let bitmap = BitmapAllocator::load(dev, sb.total_blocks).map_err(|_| FsError::Io)?;
        Ok(Self { dev, sb, bitmap })
    }

    #[allow(dead_code)]
    pub fn superblock(&self) -> &Superblock
    {
        &self.sb
    }

    #[allow(dead_code)]
    pub fn free_blocks(&self) -> u32
    {
        self.bitmap.free_count()
    }

    #[allow(dead_code)]
    pub fn sync(&mut self) -> FsResult<()>
    {
        self.bitmap.flush(self.dev).map_err(|_| FsError::Io)?;
        Ok(())
    }

    // -------- Node table I/O --------

    pub(crate) fn read_node(&self, id: u32) -> FsResult<Node>
    {
        if id >= self.sb.node_count
        {
            return Err(FsError::NotFound);
        }
        let lba = self.sb.node_table_lba + id / (NODES_PER_BLOCK as u32);
        let off = (id as usize % NODES_PER_BLOCK) * NODE_SIZE;
        let mut block = [0u8; BLOCK_SIZE];
        self.dev.read_block(lba, &mut block).map_err(|_| FsError::Io)?;
        let mut node = Node::unused();
        unsafe {
            core::slice::from_raw_parts_mut((&mut node) as *mut Node as *mut u8, NODE_SIZE)
        }
        .copy_from_slice(&block[off..off + NODE_SIZE]);
        Ok(node)
    }

    pub(crate) fn write_node(&mut self, id: u32, node: &Node) -> FsResult<()>
    {
        if id >= self.sb.node_count
        {
            return Err(FsError::Invalid);
        }
        let lba = self.sb.node_table_lba + id / (NODES_PER_BLOCK as u32);
        let off = (id as usize % NODES_PER_BLOCK) * NODE_SIZE;
        let mut block = [0u8; BLOCK_SIZE];
        self.dev.read_block(lba, &mut block).map_err(|_| FsError::Io)?;
        block[off..off + NODE_SIZE].copy_from_slice(unsafe {
            core::slice::from_raw_parts((node as *const Node) as *const u8, NODE_SIZE)
        });
        self.dev.write_block(lba, &block).map_err(|_| FsError::Io)?;
        Ok(())
    }

    pub(crate) fn alloc_node(&mut self) -> FsResult<u32>
    {
        for id in 0..self.sb.node_count
        {
            if self.read_node(id)?.kind == NODE_KIND_UNUSED
            {
                return Ok(id);
            }
        }
        Err(FsError::NoSpaceNodes)
    }

    // -------- Block allocation --------

    pub(crate) fn alloc_run(&mut self, n: u32) -> FsResult<u32>
    {
        let lba = self.bitmap.alloc_run(n).ok_or(FsError::NoSpaceData)?;
        self.bitmap.flush(self.dev).map_err(|_| FsError::Io)?;
        let zero = [0u8; BLOCK_SIZE];
        for i in 0..n
        {
            self.dev.write_block(lba + i, &zero).map_err(|_| FsError::Io)?;
        }
        Ok(lba)
    }

    pub(crate) fn free_run(&mut self, lba: u32, n: u32) -> FsResult<()>
    {
        self.bitmap.free_run(lba, n);
        self.bitmap.flush(self.dev).map_err(|_| FsError::Io)?;
        Ok(())
    }

    pub(crate) fn free_node_extents(&mut self, node: &Node) -> FsResult<()>
    {
        let n = (node.extent_count as usize).min(MAX_INLINE_EXTENTS);
        for i in 0..n
        {
            let e = node.extents[i];
            if e.blocks > 0 && e.block != 0
            {
                self.free_run(e.block, e.blocks)?;
            }
        }
        Ok(())
    }

    pub(crate) fn validate_name(&self, name: &[u8]) -> FsResult<()>
    {
        if name.is_empty() || name.len() > NAME_MAX
        {
            return Err(FsError::NameTooLong);
        }
        for &b in name
        {
            if b == 0 || b == b'/' || b == b':'
            {
                return Err(FsError::Invalid);
            }
        }
        Ok(())
    }
}

fn read_superblock(block: &[u8]) -> Superblock
{
    let mut sb = Superblock {
        magic: 0,
        version: 0,
        block_size: 0,
        total_blocks: 0,
        node_count: 0,
        root_node: ROOT_NODE_ID,
        bitmap_lba: 0,
        node_table_lba: 0,
        node_table_blocks: 0,
        data_lba: 0,
        free_blocks: 0,
        sb_crc32: 0,
        reserved: [0; 4],
    };
    let raw = unsafe {
        core::slice::from_raw_parts_mut(
            (&mut sb) as *mut Superblock as *mut u8,
            core::mem::size_of::<Superblock>(),
        )
    };
    raw.copy_from_slice(&block[..core::mem::size_of::<Superblock>()]);
    sb
}

/// Compute the CRC32 over a superblock as it should be persisted —
/// i.e. with the `sb_crc32` field zeroed. Both write_superblock
/// (mkfs.rs) and Fs::open use this so the algorithm is in lockstep.
pub(crate) fn compute_sb_crc(sb: &Superblock) -> u32
{
    let mut copy = *sb;
    copy.sb_crc32 = 0;
    let raw = unsafe {
        core::slice::from_raw_parts(
            (&copy as *const Superblock) as *const u8,
            core::mem::size_of::<Superblock>(),
        )
    };
    crc32(raw)
}
