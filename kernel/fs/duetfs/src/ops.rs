// DuetFS path / dir / file operations.
//
// Builds on `Fs` from fs.rs. Same path-shape rules as kernel/fs/vfs.h:
//   - leading '/' tolerated
//   - "." accepted and skipped
//   - ".." rejected (no parent climb)
//   - empty components ("//") tolerated
//   - trailing slash tolerated
//
// File extents are single-contiguous in v1. Writes that exceed
// `ext_blocks * BLOCK_SIZE` trigger a realloc-and-copy grow with a
// double-and-grow strategy for amortized cost.

use crate::block_dev::BlockDevice;
use crate::format::{
    blocks_for_bytes, Node, BLOCK_SIZE, NODE_KIND_DIR, NODE_KIND_FILE, ROOT_NODE_ID,
};
use crate::fs::{Fs, FsError, FsResult};
use crate::path::PathIter;

#[derive(Clone, Copy)]
pub struct Resolved
{
    pub node_id: u32,
    pub node: Node,
}

impl<'d, D: BlockDevice + ?Sized> Fs<'d, D>
{
    pub fn lookup_path(&self, path: &[u8]) -> FsResult<Resolved>
    {
        let root = self.read_node(ROOT_NODE_ID)?;
        let mut current = Resolved { node_id: ROOT_NODE_ID, node: root };
        let mut iter = PathIter::new(path);
        while let Some(comp) = iter.next()
        {
            let comp = comp.ok_or(FsError::Invalid)?;
            if current.node.kind != NODE_KIND_DIR
            {
                return Err(FsError::NotADir);
            }
            current = self.find_in_dir(&current.node, comp)?;
        }
        Ok(current)
    }

    pub fn read_at(&self, node_id: u32, offset: u32, dst: &mut [u8]) -> FsResult<u32>
    {
        let node = self.read_node(node_id)?;
        if node.kind != NODE_KIND_FILE
        {
            return Err(FsError::NotAFile);
        }
        if offset >= node.size_bytes
        {
            return Ok(0);
        }
        let avail = node.size_bytes - offset;
        let n = (dst.len() as u32).min(avail);
        let mut copied: u32 = 0;
        let mut block_buf = [0u8; BLOCK_SIZE];
        while copied < n
        {
            let cur = offset + copied;
            let lba = node.first_block + cur / (BLOCK_SIZE as u32);
            let in_block = (cur as usize) % BLOCK_SIZE;
            self.dev.read_block(lba, &mut block_buf).map_err(|_| FsError::Io)?;
            let chunk = ((BLOCK_SIZE - in_block) as u32).min(n - copied);
            let dst_off = copied as usize;
            dst[dst_off..dst_off + chunk as usize]
                .copy_from_slice(&block_buf[in_block..in_block + chunk as usize]);
            copied += chunk;
        }
        Ok(copied)
    }

    pub fn write_at(&mut self, node_id: u32, offset: u32, src: &[u8]) -> FsResult<u32>
    {
        if self.dev.is_read_only()
        {
            return Err(FsError::ReadOnly);
        }
        let mut node = self.read_node(node_id)?;
        if node.kind != NODE_KIND_FILE
        {
            return Err(FsError::NotAFile);
        }
        let need_size = offset.saturating_add(src.len() as u32);
        let need_blocks = blocks_for_bytes(need_size);
        if need_blocks > node.ext_blocks
        {
            self.grow_file(&mut node, need_blocks)?;
        }
        // Block-by-block write, read-modify-write at partial-block edges.
        let mut written: u32 = 0;
        let mut block_buf = [0u8; BLOCK_SIZE];
        while written < src.len() as u32
        {
            let cur = offset + written;
            let lba = node.first_block + cur / (BLOCK_SIZE as u32);
            let in_block = (cur as usize) % BLOCK_SIZE;
            let chunk = ((BLOCK_SIZE - in_block) as u32).min(src.len() as u32 - written);
            if in_block != 0 || chunk != BLOCK_SIZE as u32
            {
                self.dev.read_block(lba, &mut block_buf).map_err(|_| FsError::Io)?;
            }
            let s = written as usize;
            block_buf[in_block..in_block + chunk as usize]
                .copy_from_slice(&src[s..s + chunk as usize]);
            self.dev.write_block(lba, &block_buf).map_err(|_| FsError::Io)?;
            written += chunk;
        }
        if need_size > node.size_bytes
        {
            node.size_bytes = need_size;
        }
        self.write_node(node_id, &node)?;
        Ok(written)
    }

    pub fn create_file(&mut self, parent_id: u32, name: &[u8]) -> FsResult<u32>
    {
        self.create_child(parent_id, name, NODE_KIND_FILE)
    }

    pub fn create_dir(&mut self, parent_id: u32, name: &[u8]) -> FsResult<u32>
    {
        self.create_child(parent_id, name, NODE_KIND_DIR)
    }

    pub fn unlink(&mut self, parent_id: u32, name: &[u8]) -> FsResult<()>
    {
        if self.dev.is_read_only()
        {
            return Err(FsError::ReadOnly);
        }
        let parent = self.read_node(parent_id)?;
        if parent.kind != NODE_KIND_DIR
        {
            return Err(FsError::NotADir);
        }
        let target = self.find_in_dir(&parent, name)?;
        if target.node.kind == NODE_KIND_DIR && target.node.child_count > 0
        {
            return Err(FsError::DirNotEmpty);
        }
        // Free the node's data extent + dir-children block.
        if target.node.ext_blocks > 0 && target.node.first_block != 0
        {
            self.free_run(target.node.first_block, target.node.ext_blocks)?;
        }
        // Remove the child id from the parent's child list and decrement count.
        self.dir_remove_child(parent_id, target.node_id)?;
        // Mark the node unused.
        let mut zero = Node::unused();
        zero.parent_id = crate::format::INVALID_NODE_ID;
        self.write_node(target.node_id, &zero)?;
        Ok(())
    }

    pub fn truncate(&mut self, node_id: u32, new_size: u32) -> FsResult<()>
    {
        if self.dev.is_read_only()
        {
            return Err(FsError::ReadOnly);
        }
        let mut node = self.read_node(node_id)?;
        if node.kind != NODE_KIND_FILE
        {
            return Err(FsError::NotAFile);
        }
        let need_blocks = blocks_for_bytes(new_size);
        if need_blocks > node.ext_blocks
        {
            self.grow_file(&mut node, need_blocks)?;
        }
        node.size_bytes = new_size;
        self.write_node(node_id, &node)?;
        Ok(())
    }
}
