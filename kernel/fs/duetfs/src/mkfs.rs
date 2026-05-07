// DuetFS mkfs — format a fresh image (v3).
//
// Writes a v3 superblock + zeroed bitmap + CRC table + zeroed
// node table, then creates the root directory (node 0) with one
// inline extent. Initializes the CRC table to cover every
// metadata + data block.

use crate::alloc_bitmap::BitmapAllocator;
use crate::block_dev::BlockDevice;
use crate::crc32::crc32;
use crate::crc_table::CrcTable;
use crate::format::{
    Extent, Node, Superblock, BITMAP_LBA, BLOCK_SIZE, CRC_TABLE_BLOCKS, CRC_TABLE_LBA,
    DATA_LBA, MAGIC, MIN_TOTAL_BLOCKS, NODE_COUNT, NODE_KIND_DIR, NODE_SIZE,
    NODE_TABLE_BLOCKS, NODE_TABLE_LBA, NODES_PER_BLOCK, ROOT_NODE_ID, SUPERBLOCK_LBA,
    VERSION,
};
use crate::fs::{compute_sb_crc, FsError, FsResult};

pub fn format<D: BlockDevice + ?Sized>(dev: &mut D) -> FsResult<()>
{
    let total_blocks = dev.block_count();
    if total_blocks < MIN_TOTAL_BLOCKS
    {
        return Err(FsError::NoSpaceData);
    }
    if dev.is_read_only()
    {
        return Err(FsError::ReadOnly);
    }

    // 1. Bitmap: mark every metadata region + root-dir extent as used.
    let mut bitmap = BitmapAllocator::fresh(total_blocks);
    bitmap.mark_used(SUPERBLOCK_LBA);
    bitmap.mark_used(BITMAP_LBA);
    for i in 0..CRC_TABLE_BLOCKS
    {
        bitmap.mark_used(CRC_TABLE_LBA + i);
    }
    for i in 0..NODE_TABLE_BLOCKS
    {
        bitmap.mark_used(NODE_TABLE_LBA + i);
    }
    let root_extent = DATA_LBA;
    bitmap.mark_used(root_extent);

    // 2. Zero the node table + root dir's child-id block.
    let zero = [0u8; BLOCK_SIZE];
    for i in 0..NODE_TABLE_BLOCKS
    {
        dev.write_block(NODE_TABLE_LBA + i, &zero).map_err(|_| FsError::Io)?;
    }
    dev.write_block(root_extent, &zero).map_err(|_| FsError::Io)?;

    // 3. Write the root node — one extent, no children, link_count=1
    //    (a directory's "link" is its self-reference).
    let mut root = Node::unused();
    root.kind = NODE_KIND_DIR;
    root.extents[0] = Extent { block: root_extent, blocks: 1 };
    root.extent_count = 1;
    root.parent_id = ROOT_NODE_ID;
    root.link_count = 1;
    write_node_to_table(dev, ROOT_NODE_ID, &root)?;

    // 4. Flush bitmap.
    bitmap.flush(dev).map_err(|_| FsError::Io)?;

    // 5. Build the CRC table covering every metadata + data block.
    //    Read each block back and CRC it; the CRC table's own entry
    //    stays 0 (sentinel — fsck flags non-zero as suspicious).
    let mut crc_table = CrcTable::fresh();
    let mut buf = [0u8; BLOCK_SIZE];
    // SB will be CRC'd after we write it, below.
    dev.read_block(BITMAP_LBA, &mut buf).map_err(|_| FsError::Io)?;
    crc_table.set(BITMAP_LBA, crc32(&buf));
    crc_table.set(CRC_TABLE_LBA, 0);
    for i in 0..NODE_TABLE_BLOCKS
    {
        dev.read_block(NODE_TABLE_LBA + i, &mut buf).map_err(|_| FsError::Io)?;
        crc_table.set(NODE_TABLE_LBA + i, crc32(&buf));
    }
    crc_table.set(root_extent, crc32(&zero));

    // 6. Build superblock with CRC.
    let mut sb = Superblock {
        magic: MAGIC,
        version: VERSION,
        block_size: BLOCK_SIZE as u32,
        total_blocks,
        node_count: NODE_COUNT,
        root_node: ROOT_NODE_ID,
        bitmap_lba: BITMAP_LBA,
        crc_table_lba: CRC_TABLE_LBA,
        crc_table_blocks: CRC_TABLE_BLOCKS,
        node_table_lba: NODE_TABLE_LBA,
        node_table_blocks: NODE_TABLE_BLOCKS,
        data_lba: DATA_LBA,
        free_blocks: bitmap.free_count(),
        sb_crc32: 0,
        reserved: [0; 2],
    };
    sb.sb_crc32 = compute_sb_crc(&sb);

    // 7. CRC the SB block as it'll appear on disk + flush table.
    let mut sb_block = [0u8; BLOCK_SIZE];
    let raw = unsafe {
        core::slice::from_raw_parts(
            (&sb as *const Superblock) as *const u8,
            core::mem::size_of::<Superblock>(),
        )
    };
    sb_block[..raw.len()].copy_from_slice(raw);
    crc_table.set(SUPERBLOCK_LBA, crc32(&sb_block));
    crc_table.flush(dev).map_err(|_| FsError::Io)?;

    // 8. Write the SB last so a half-finished mkfs leaves a clean
    //    rejection rather than a partly-mutated FS.
    dev.write_block(SUPERBLOCK_LBA, &sb_block).map_err(|_| FsError::Io)?;
    Ok(())
}

fn write_node_to_table<D: BlockDevice + ?Sized>(
    dev: &mut D, id: u32, node: &Node,
) -> FsResult<()>
{
    let lba = NODE_TABLE_LBA + id / (NODES_PER_BLOCK as u32);
    let off = (id as usize % NODES_PER_BLOCK) * NODE_SIZE;
    let mut block = [0u8; BLOCK_SIZE];
    dev.read_block(lba, &mut block).map_err(|_| FsError::Io)?;
    let raw = unsafe {
        core::slice::from_raw_parts((node as *const Node) as *const u8, NODE_SIZE)
    };
    block[off..off + NODE_SIZE].copy_from_slice(raw);
    dev.write_block(lba, &block).map_err(|_| FsError::Io)
}

/// Rewrite the on-disk superblock from `sb`. Caller is responsible
/// for setting `sb.sb_crc32` to the correct CRC. Used by fsck after
/// repair.
pub(crate) fn rewrite_superblock<D: BlockDevice + ?Sized>(
    dev: &mut D, sb: &Superblock,
) -> FsResult<()>
{
    let mut block = [0u8; BLOCK_SIZE];
    let raw = unsafe {
        core::slice::from_raw_parts(
            (sb as *const Superblock) as *const u8,
            core::mem::size_of::<Superblock>(),
        )
    };
    block[..raw.len()].copy_from_slice(raw);
    dev.write_block(SUPERBLOCK_LBA, &block).map_err(|_| FsError::Io)
}
