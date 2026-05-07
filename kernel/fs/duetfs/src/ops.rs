// DuetFS path / dir / file operations.
//
// Builds on `Fs` from fs.rs. Same path-shape rules as kernel/fs/vfs.h.
//
// File data is held in up to MAX_INLINE_EXTENTS extents. Read /
// write walk the extent list to find which extent contains the
// byte at a given offset; grow_file (in ops_dir.rs) appends a new
// extent when the current set is full.

use crate::block_dev::BlockDevice;
use crate::format::{
    blocks_for_bytes, Node, BLOCK_SIZE, MAX_INLINE_EXTENTS, NODE_KIND_DIR, NODE_KIND_FILE,
    ROOT_NODE_ID,
};
use crate::fs::{Fs, FsError, FsResult};
use crate::path::PathIter;

#[derive(Clone, Copy)]
pub struct Resolved
{
    pub node_id: u32,
    pub node: Node,
}

/// Resolve a byte offset to (extent_index, in_extent_byte_offset).
/// Returns None if the offset is past the end of the last extent.
fn locate(node: &Node, offset: u32) -> Option<(usize, u32)>
{
    let mut walked: u32 = 0;
    let n = (node.extent_count as usize).min(MAX_INLINE_EXTENTS);
    for i in 0..n
    {
        let ext_size = node.extents[i].blocks.saturating_mul(BLOCK_SIZE as u32);
        if offset < walked.saturating_add(ext_size)
        {
            return Some((i, offset - walked));
        }
        walked = walked.saturating_add(ext_size);
    }
    None
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
        let want = (dst.len() as u32).min(avail);
        let mut copied: u32 = 0;
        let mut block_buf = [0u8; BLOCK_SIZE];
        while copied < want
        {
            let cur = offset + copied;
            let (ext_idx, in_ext) = locate(&node, cur).ok_or(FsError::Corrupt)?;
            let lba = node.extents[ext_idx].block + in_ext / (BLOCK_SIZE as u32);
            let in_block = (in_ext as usize) % BLOCK_SIZE;
            self.dev.read_block(lba, &mut block_buf).map_err(|_| FsError::Io)?;
            let chunk = ((BLOCK_SIZE - in_block) as u32).min(want - copied);
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
        if need_blocks > node.total_blocks()
        {
            self.grow_file(&mut node, need_blocks)?;
        }
        let mut written: u32 = 0;
        let mut block_buf = [0u8; BLOCK_SIZE];
        while written < src.len() as u32
        {
            let cur = offset + written;
            let (ext_idx, in_ext) = locate(&node, cur).ok_or(FsError::Corrupt)?;
            let lba = node.extents[ext_idx].block + in_ext / (BLOCK_SIZE as u32);
            let in_block = (in_ext as usize) % BLOCK_SIZE;
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
        self.free_node_extents(&target.node)?;
        self.dir_remove_child(parent_id, target.node_id)?;
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
        if need_blocks > node.total_blocks()
        {
            self.grow_file(&mut node, need_blocks)?;
        }
        node.size_bytes = new_size;
        self.write_node(node_id, &node)?;
        Ok(())
    }
}
