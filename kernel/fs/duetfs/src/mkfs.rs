// DuetFS mkfs — format a fresh image (v2).
//
// Writes a v2 superblock (with CRC32) + zeroed bitmap + zeroed
// node table, then creates the root directory (node 0) with one
// inline extent. After mkfs, `Fs::open(dev)` succeeds and
// `Fs::lookup_path("/")` returns the root.

use crate::alloc_bitmap::BitmapAllocator;
use crate::block_dev::BlockDevice;
use crate::format::{
    Extent, Node, Superblock, BITMAP_LBA, BLOCK_SIZE, DATA_LBA, MAGIC, MIN_TOTAL_BLOCKS,
    NODE_COUNT, NODE_KIND_DIR, NODE_KIND_UNUSED, NODE_SIZE, NODE_TABLE_BLOCKS,
    NODE_TABLE_LBA, NODES_PER_BLOCK, ROOT_NODE_ID, SUPERBLOCK_LBA, VERSION,
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

    // 1. Bitmap. Mark superblock + bitmap + node-table + root-dir
    //    extent as in use; everything else is free.
    let mut bitmap = BitmapAllocator::fresh(total_blocks);
    bitmap.mark_used(SUPERBLOCK_LBA);
    bitmap.mark_used(BITMAP_LBA);
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

    // 3. Write the root node — one extent, no children, self-loop parent.
    let mut root = Node::unused();
    root.kind = NODE_KIND_DIR;
    root.extents[0] = Extent { block: root_extent, blocks: 1 };
    root.extent_count = 1;
    root.parent_id = ROOT_NODE_ID;
    write_node_to_table(dev, ROOT_NODE_ID, &root)?;

    let _ = NODE_KIND_UNUSED;

    // 4. Flush bitmap.
    bitmap.flush(dev).map_err(|_| FsError::Io)?;

    // 5. Build superblock with CRC, write last so a half-finished
    //    mkfs leaves a clean rejection rather than a partly-mutated FS.
    let mut sb = Superblock {
        magic: MAGIC,
        version: VERSION,
        block_size: BLOCK_SIZE as u32,
        total_blocks,
        node_count: NODE_COUNT,
        root_node: ROOT_NODE_ID,
        bitmap_lba: BITMAP_LBA,
        node_table_lba: NODE_TABLE_LBA,
        node_table_blocks: NODE_TABLE_BLOCKS,
        data_lba: DATA_LBA,
        free_blocks: bitmap.free_count(),
        sb_crc32: 0,
        reserved: [0; 4],
    };
    sb.sb_crc32 = compute_sb_crc(&sb);
    write_superblock(dev, &sb)?;
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

fn write_superblock<D: BlockDevice + ?Sized>(dev: &mut D, sb: &Superblock) -> FsResult<()>
{
    rewrite_superblock(dev, sb)
}

/// Rewrite the on-disk superblock from `sb`. Caller is responsible
/// for setting `sb.sb_crc32` to the correct CRC before calling
/// (compute_sb_crc lives in fs.rs). Used by fsck after repair to
/// commit the recomputed `free_blocks` + fresh CRC.
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
