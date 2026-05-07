// DuetFS image accessor — read-only view over a flat byte slice.
//
// The kernel hands the crate an `&[u8]` (today: a constinit
// synthesized image baked at compile time on the C++ side; later: a
// block-device-mapped buffer). We never write through this view.
//
// All accessors return Option / explicit errors — a corrupt or
// truncated image must not panic. The crate's only contract with
// the kernel is "best effort, never crash"; a None propagates back
// as a lookup miss.

use crate::format::{Node, Superblock, BLOCK_SIZE, MAGIC, NODES_PER_BLOCK, NODE_SIZE,
                    VERSION};

pub struct Image<'a>
{
    bytes: &'a [u8],
    superblock: Superblock,
}

impl<'a> Image<'a>
{
    pub fn parse(bytes: &'a [u8]) -> Option<Self>
    {
        if bytes.len() < BLOCK_SIZE
        {
            return None;
        }
        let sb = read_superblock(bytes)?;
        if sb.magic != MAGIC
            || sb.version != VERSION
            || sb.block_size as usize != BLOCK_SIZE
            || (sb.total_blocks as usize) * BLOCK_SIZE > bytes.len()
            || sb.node_table_start == 0
            || sb.data_start <= sb.node_table_start
        {
            return None;
        }
        Some(Self { bytes, superblock: sb })
    }

    #[allow(dead_code)] // exposed for future slices (stat / df / fsck)
    pub fn superblock(&self) -> &Superblock
    {
        &self.superblock
    }

    pub fn block(&self, lba: u32) -> Option<&'a [u8]>
    {
        let start = (lba as usize).checked_mul(BLOCK_SIZE)?;
        let end = start.checked_add(BLOCK_SIZE)?;
        self.bytes.get(start..end)
    }

    pub fn node(&self, node_id: u32) -> Option<Node>
    {
        if node_id >= self.superblock.node_count
        {
            return None;
        }
        let block_idx =
            self.superblock.node_table_start + (node_id / NODES_PER_BLOCK as u32);
        let in_block = (node_id as usize) % NODES_PER_BLOCK;
        let block: &[u8] = self.block(block_idx)?;
        let off = in_block * NODE_SIZE;
        let raw = block.get(off..off + NODE_SIZE)?;
        Some(read_node(raw))
    }

    pub fn dir_children(&self, dir: &Node) -> Option<&'a [u8]>
    {
        let block = self.block(dir.first_block)?;
        let n_bytes = (dir.child_count as usize).checked_mul(4)?;
        block.get(..n_bytes)
    }

    pub fn file_bytes(&self, file: &Node) -> Option<&'a [u8]>
    {
        let size = file.size_bytes as usize;
        if size == 0
        {
            return Some(&[]);
        }
        let start = (file.first_block as usize).checked_mul(BLOCK_SIZE)?;
        let end = start.checked_add(size)?;
        self.bytes.get(start..end)
    }
}

fn read_superblock(bytes: &[u8]) -> Option<Superblock>
{
    let raw = bytes.get(..core::mem::size_of::<Superblock>())?;
    // Safe: Superblock is repr(C), no padding requires alignment beyond
    // what we control, and we copy out by-value.
    let mut sb = Superblock {
        magic: 0,
        version: 0,
        block_size: 0,
        total_blocks: 0,
        node_count: 0,
        root_node: 0,
        node_table_start: 0,
        data_start: 0,
        reserved: [0; 8],
    };
    let dst = unsafe {
        core::slice::from_raw_parts_mut(
            (&mut sb) as *mut Superblock as *mut u8,
            core::mem::size_of::<Superblock>(),
        )
    };
    dst.copy_from_slice(raw);
    Some(sb)
}

fn read_node(raw: &[u8]) -> Node
{
    let mut node = Node::unused();
    let dst = unsafe {
        core::slice::from_raw_parts_mut(
            (&mut node) as *mut Node as *mut u8,
            NODE_SIZE,
        )
    };
    dst.copy_from_slice(raw);
    node
}
