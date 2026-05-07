// DuetFS — directory + file extent helpers shared by ops.rs.
//
// Directory storage in v1: each dir owns ONE child-id-array block
// (allocated at create time). Child IDs pack as little-endian u32 at
// the head of the block — `child_count × 4` bytes are valid; the
// rest is junk. v1 caps directories at BLOCK_SIZE / 4 = 1024 children;
// adding multi-block dirs is a future slice.

use crate::block_dev::BlockDevice;
use crate::format::{
    blocks_for_bytes, Node, BLOCK_SIZE, INVALID_NODE_ID, NODE_KIND_DIR, NODE_KIND_FILE,
    NODE_KIND_UNUSED, ROOT_NODE_ID,
};
use crate::fs::{Fs, FsError, FsResult};
use crate::ops::Resolved;

pub(crate) const DIR_MAX_CHILDREN: u32 = (BLOCK_SIZE / 4) as u32;

impl<'d, D: BlockDevice + ?Sized> Fs<'d, D>
{
    pub(crate) fn find_in_dir(&self, dir: &Node, name: &[u8]) -> FsResult<Resolved>
    {
        if dir.kind != NODE_KIND_DIR || dir.child_count == 0
        {
            return Err(FsError::NotFound);
        }
        let mut block = [0u8; BLOCK_SIZE];
        self.dev.read_block(dir.first_block, &mut block).map_err(|_| FsError::Io)?;
        for i in 0..dir.child_count
        {
            let off = (i as usize) * 4;
            let id = u32::from_le_bytes([
                block[off], block[off + 1], block[off + 2], block[off + 3],
            ]);
            let child = self.read_node(id)?;
            if child.kind != NODE_KIND_UNUSED && child.name_bytes() == name
            {
                return Ok(Resolved { node_id: id, node: child });
            }
        }
        Err(FsError::NotFound)
    }

    pub(crate) fn dir_add_child(&mut self, dir_id: u32, child_id: u32) -> FsResult<()>
    {
        let mut dir = self.read_node(dir_id)?;
        if dir.kind != NODE_KIND_DIR
        {
            return Err(FsError::NotADir);
        }
        if dir.child_count >= DIR_MAX_CHILDREN
        {
            return Err(FsError::NoSpaceData);
        }
        let mut block = [0u8; BLOCK_SIZE];
        self.dev.read_block(dir.first_block, &mut block).map_err(|_| FsError::Io)?;
        let off = (dir.child_count as usize) * 4;
        block[off..off + 4].copy_from_slice(&child_id.to_le_bytes());
        self.dev.write_block(dir.first_block, &block).map_err(|_| FsError::Io)?;
        dir.child_count += 1;
        dir.size_bytes = dir.child_count * 4;
        self.write_node(dir_id, &dir)?;
        Ok(())
    }

    pub(crate) fn dir_remove_child(&mut self, dir_id: u32, child_id: u32) -> FsResult<()>
    {
        let mut dir = self.read_node(dir_id)?;
        let mut block = [0u8; BLOCK_SIZE];
        self.dev.read_block(dir.first_block, &mut block).map_err(|_| FsError::Io)?;
        let mut found_at: Option<usize> = None;
        for i in 0..dir.child_count
        {
            let off = (i as usize) * 4;
            let id = u32::from_le_bytes([
                block[off], block[off + 1], block[off + 2], block[off + 3],
            ]);
            if id == child_id
            {
                found_at = Some(i as usize);
                break;
            }
        }
        let idx = found_at.ok_or(FsError::NotFound)?;
        // Move the last child into the hole.
        let last = (dir.child_count - 1) as usize;
        if idx != last
        {
            let last_off = last * 4;
            let last_bytes = [
                block[last_off], block[last_off + 1], block[last_off + 2], block[last_off + 3],
            ];
            let dst_off = idx * 4;
            block[dst_off..dst_off + 4].copy_from_slice(&last_bytes);
        }
        self.dev.write_block(dir.first_block, &block).map_err(|_| FsError::Io)?;
        dir.child_count -= 1;
        dir.size_bytes = dir.child_count * 4;
        self.write_node(dir_id, &dir)?;
        Ok(())
    }

    pub(crate) fn create_child(
        &mut self, parent_id: u32, name: &[u8], kind: u32,
    ) -> FsResult<u32>
    {
        if self.dev.is_read_only()
        {
            return Err(FsError::ReadOnly);
        }
        self.validate_name(name)?;
        let parent = self.read_node(parent_id)?;
        if parent.kind != NODE_KIND_DIR
        {
            return Err(FsError::NotADir);
        }
        if self.find_in_dir(&parent, name).is_ok()
        {
            return Err(FsError::NameExists);
        }
        let new_id = self.alloc_node()?;
        let mut node = Node::unused();
        node.kind = kind;
        node.parent_id = parent_id;
        node.set_name(name);
        if kind == NODE_KIND_DIR
        {
            // Allocate one block to hold the child-id list.
            node.first_block = self.alloc_run(1)?;
            node.ext_blocks = 1;
        }
        else if kind == NODE_KIND_FILE
        {
            // Allocate one block of headroom — write_at grows on demand.
            node.first_block = self.alloc_run(1)?;
            node.ext_blocks = 1;
        }
        self.write_node(new_id, &node)?;
        if let Err(e) = self.dir_add_child(parent_id, new_id)
        {
            // Roll back the allocations we made for the new node.
            if node.ext_blocks > 0
            {
                let _ = self.free_run(node.first_block, node.ext_blocks);
            }
            let _ = self.write_node(new_id, &Node::unused());
            return Err(e);
        }
        Ok(new_id)
    }

    pub(crate) fn grow_file(&mut self, node: &mut Node, need_blocks: u32) -> FsResult<()>
    {
        let new_blocks = need_blocks.max(node.ext_blocks.saturating_mul(2)).max(1);
        let new_lba = self.alloc_run(new_blocks)?;
        // Copy old extent into the new one (size_bytes worth).
        let copy_blocks = blocks_for_bytes(node.size_bytes).min(node.ext_blocks);
        let mut buf = [0u8; BLOCK_SIZE];
        for i in 0..copy_blocks
        {
            self.dev.read_block(node.first_block + i, &mut buf).map_err(|_| FsError::Io)?;
            self.dev.write_block(new_lba + i, &buf).map_err(|_| FsError::Io)?;
        }
        if node.ext_blocks > 0 && node.first_block != 0
        {
            self.free_run(node.first_block, node.ext_blocks)?;
        }
        node.first_block = new_lba;
        node.ext_blocks = new_blocks;
        // Caller updates parent_id / size_bytes as appropriate.
        let _ = (ROOT_NODE_ID, INVALID_NODE_ID); // suppress unused-import noise
        Ok(())
    }
}
