// DuetFS path / dir / file operations.
//
// Builds on `Fs` from fs.rs. Same path-shape rules as kernel/fs/vfs.h.
//
// File data is held in up to MAX_INLINE_EXTENTS extents. Read /
// write walk the extent list to find which extent contains the
// byte at a given offset; grow_file (in ops_dir.rs) appends a new
// extent when the current set is full.
//
// v3: every block write to the data region goes through
// `write_data_block` (fs.rs) so the per-block CRC table updates in
// lockstep.

use crate::block_dev::BlockDevice;
use crate::format::{
    blocks_for_bytes, Node, BLOCK_SIZE, INVALID_NODE_ID, MAX_INLINE_EXTENTS, NODE_KIND_DIR,
    NODE_KIND_FILE, NODE_KIND_SYMLINK, ROOT_NODE_ID, SYMLINK_TARGET_MAX,
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

fn last_extent_count(node: &Node) -> u32
{
    let mut n: u32 = 0;
    for i in 0..MAX_INLINE_EXTENTS
    {
        if node.extents[i].blocks != 0
        {
            n = (i as u32) + 1;
        }
    }
    n
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
        if node.kind != NODE_KIND_FILE && node.kind != NODE_KIND_SYMLINK
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
            self.read_data_block(lba, &mut block_buf)?;
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
                self.read_data_block(lba, &mut block_buf)?;
            }
            let s = written as usize;
            block_buf[in_block..in_block + chunk as usize]
                .copy_from_slice(&src[s..s + chunk as usize]);
            self.write_data_block(lba, &block_buf)?;
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

    /// Create a symbolic link at parent/name pointing at `target`.
    /// The target is stored as bytes inside the symlink node's
    /// first extent (one block, capped at SYMLINK_TARGET_MAX).
    pub fn create_symlink(&mut self, parent_id: u32, name: &[u8], target: &[u8])
        -> FsResult<u32>
    {
        if target.is_empty() || target.len() as u32 > SYMLINK_TARGET_MAX
        {
            return Err(FsError::Invalid);
        }
        let id = self.create_child(parent_id, name, NODE_KIND_SYMLINK)?;
        // create_child set up one block of headroom; write the target in place.
        let mut node = self.read_node(id)?;
        let lba = node.extents[0].block;
        let mut buf = [0u8; BLOCK_SIZE];
        buf[..target.len()].copy_from_slice(target);
        self.write_data_block(lba, &buf)?;
        node.size_bytes = target.len() as u32;
        self.write_node(id, &node)?;
        Ok(id)
    }

    /// Read the target of a symlink into `dst`. Returns bytes copied.
    pub fn readlink(&self, node_id: u32, dst: &mut [u8]) -> FsResult<u32>
    {
        let node = self.read_node(node_id)?;
        if node.kind != NODE_KIND_SYMLINK
        {
            return Err(FsError::NotASymlink);
        }
        // read_at handles SYMLINK kind alongside FILE.
        self.read_at(node_id, 0, dst)
    }

    /// Add a hard link at parent/new_name to an existing file. The
    /// target must be a file (not a dir — directory hard-links would
    /// allow cycles). Increments link_count; the node is not freed
    /// until link_count reaches 0.
    pub fn link(&mut self, target_id: u32, parent_id: u32, new_name: &[u8])
        -> FsResult<()>
    {
        if self.dev.is_read_only()
        {
            return Err(FsError::ReadOnly);
        }
        self.validate_name(new_name)?;
        let parent = self.read_node(parent_id)?;
        if parent.kind != NODE_KIND_DIR
        {
            return Err(FsError::NotADir);
        }
        if self.find_in_dir(&parent, new_name).is_ok()
        {
            return Err(FsError::NameExists);
        }
        let mut target = self.read_node(target_id)?;
        if target.kind != NODE_KIND_FILE && target.kind != NODE_KIND_SYMLINK
        {
            return Err(FsError::Invalid);
        }
        target.link_count += 1;
        self.write_node(target_id, &target)?;
        // Append the same node id to the parent's child list — but
        // we need the directory entry to use a *different* visible
        // name. v3's dir-entry shape is just a u32 child id; the
        // child's `name` field holds its name. So a "hard link"
        // here means `target_id` appears more than once in the
        // dir-children block, and the most recent name wins for
        // lookup. That matches POSIX where link(2) creates a new
        // dirent pointing at the same inode but doesn't rename
        // the inode itself.
        //
        // To avoid the name collision we record the new name in a
        // copy of the target — but storing two names per node
        // doesn't fit in a fixed Node. v3's compromise: hard links
        // share both the inode AND the name. Renaming via link(2)
        // is therefore not supported; the name passed in must
        // equal target's existing name. Future slice: dirent table.
        if new_name != target.name_bytes()
        {
            target.link_count -= 1;
            self.write_node(target_id, &target)?;
            return Err(FsError::Invalid);
        }
        self.dir_add_child(parent_id, target_id)?;
        Ok(())
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
        self.dir_remove_child(parent_id, target.node_id)?;
        let mut node = target.node;
        if node.link_count > 1
        {
            node.link_count -= 1;
            self.write_node(target.node_id, &node)?;
        }
        else
        {
            self.free_node_extents(&node)?;
            let mut zero = Node::unused();
            zero.parent_id = INVALID_NODE_ID;
            self.write_node(target.node_id, &zero)?;
        }
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

        let old_size = node.size_bytes;
        let need_blocks = blocks_for_bytes(new_size);
        if need_blocks > node.total_blocks()
        {
            self.grow_file(&mut node, need_blocks)?;
        }

        // POSIX-style truncate semantics: bytes exposed by a later
        // grow must read as zero, not as stale contents from before
        // a shrink. Zero the affected retained blocks before freeing
        // any whole-block tail extents. Newly allocated grow blocks
        // are already zeroed by alloc_run / try_extend_extent, but
        // this also fixes growth inside previously retained capacity.
        if new_size < old_size
        {
            let zero_end = old_size.min(need_blocks.saturating_mul(BLOCK_SIZE as u32));
            self.zero_file_range(&node, new_size, zero_end)?;
            self.shrink_file_extents(&mut node, need_blocks)?;
        }
        else if new_size > old_size
        {
            self.zero_file_range(&node, old_size, new_size)?;
        }

        node.size_bytes = new_size;
        self.write_node(node_id, &node)?;
        Ok(())
    }

    fn zero_file_range(&mut self, node: &Node, start: u32, end: u32) -> FsResult<()>
    {
        if start >= end
        {
            return Ok(());
        }
        let mut cur = start;
        let mut block_buf = [0u8; BLOCK_SIZE];
        while cur < end
        {
            let (ext_idx, in_ext) = locate(node, cur).ok_or(FsError::Corrupt)?;
            let lba = node.extents[ext_idx].block + in_ext / (BLOCK_SIZE as u32);
            let in_block = (in_ext as usize) % BLOCK_SIZE;
            let chunk = ((BLOCK_SIZE - in_block) as u32).min(end - cur);
            self.read_data_block(lba, &mut block_buf)?;
            block_buf[in_block..in_block + chunk as usize].fill(0);
            self.write_data_block(lba, &block_buf)?;
            cur += chunk;
        }
        Ok(())
    }

    fn shrink_file_extents(&mut self, node: &mut Node, keep_blocks: u32) -> FsResult<()>
    {
        let mut walked: u32 = 0;
        let n = (node.extent_count as usize).min(MAX_INLINE_EXTENTS);
        for i in 0..n
        {
            let ext = node.extents[i];
            if ext.blocks == 0
            {
                continue;
            }

            if walked >= keep_blocks
            {
                self.free_run(ext.block, ext.blocks)?;
                node.extents[i].block = 0;
                node.extents[i].blocks = 0;
            }
            else if walked + ext.blocks > keep_blocks
            {
                let keep_in_extent = keep_blocks - walked;
                let free_blocks = ext.blocks - keep_in_extent;
                self.free_run(ext.block + keep_in_extent, free_blocks)?;
                node.extents[i].blocks = keep_in_extent;
            }
            walked = walked.saturating_add(ext.blocks);
        }
        node.extent_count = last_extent_count(node);
        Ok(())
    }
}
