// DuetFS mkfs — format a fresh image.
//
// Writes a v1 superblock + zeroed bitmap + zeroed node table, then
// creates the root directory (node 0). After mkfs, `Fs::open(dev)`
// succeeds and `Fs::lookup_path("/")` returns the root.
//
// `format` requires the device to expose at least MIN_TOTAL_BLOCKS
// (= DATA_LBA + 1) blocks. The first data block is allocated to
// the root dir's child-id list.

use crate::alloc_bitmap::BitmapAllocator;
use crate::block_dev::BlockDevice;
use crate::format::{
    Node, Superblock, BITMAP_LBA, BLOCK_SIZE, DATA_LBA, MAGIC, MIN_TOTAL_BLOCKS, NODE_COUNT,
    NODE_KIND_DIR, NODE_KIND_UNUSED, NODE_SIZE, NODE_TABLE_BLOCKS, NODE_TABLE_LBA,
    NODES_PER_BLOCK, ROOT_NODE_ID, SUPERBLOCK_LBA, VERSION,
};
use crate::fs::{FsError, FsResult};

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

    // 2. Zero out the node table.
    let zero = [0u8; BLOCK_SIZE];
    for i in 0..NODE_TABLE_BLOCKS
    {
        dev.write_block(NODE_TABLE_LBA + i, &zero).map_err(|_| FsError::Io)?;
    }

    // 3. Zero out the root dir's child-id block.
    dev.write_block(root_extent, &zero).map_err(|_| FsError::Io)?;

    // 4. Write the root node. Root has no name and no parent.
    let mut root = Node::unused();
    root.kind = NODE_KIND_DIR;
    root.first_block = root_extent;
    root.ext_blocks = 1;
    root.parent_id = ROOT_NODE_ID; // self-loop is the convention
    write_node_to_table(dev, ROOT_NODE_ID, &root)?;

    // 5. Write remaining nodes as unused (they are already zeroed,
    //    which is exactly NODE_KIND_UNUSED — but be explicit so any
    //    future Node-layout drift is caught).
    let _ = NODE_KIND_UNUSED;

    // 6. Flush bitmap to disk.
    bitmap.flush(dev).map_err(|_| FsError::Io)?;

    // 7. Write the superblock last — until step 7 the image is
    //    invalid, so a half-finished mkfs leaves a clean rejection
    //    rather than a partly-mutated FS.
    let sb = Superblock {
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
        reserved: [0; 5],
    };
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
