// DuetFS — directory + file extent helpers shared by ops.rs.
//
// Directory storage in v2: still ONE child-id-array block per
// directory (allocated at create time), capped at 1024 children.
// Multi-block dirs land in a future slice.
//
// File extents in v2: up to MAX_INLINE_EXTENTS extents inline on
// the Node. grow_file appends a new extent when capacity is needed,
// and only realloc-and-copies when the inline extent slots are
// full (NoSpaceExtents otherwise).

use crate::block_dev::BlockDevice;
use crate::crc32::crc32;
use crate::format::{
    Extent, Node, BITMAP_LBA, BLOCK_SIZE, INVALID_NODE_ID, MAX_INLINE_EXTENTS, NODE_KIND_DIR, NODE_KIND_UNUSED,
    ROOT_NODE_ID,
};
use crate::fs::{Fs, FsError, FsResult};
use crate::ops::Resolved;

pub(crate) const DIR_MAX_CHILDREN: u32 = (BLOCK_SIZE / 4) as u32;

impl<'d, D: BlockDevice + ?Sized> Fs<'d, D> {
    pub(crate) fn dir_block(&self, dir: &Node) -> FsResult<u32> {
        if dir.extent_count == 0 || dir.extents[0].blocks == 0 {
            return Err(FsError::Corrupt);
        }
        Ok(dir.extents[0].block)
    }

    pub(crate) fn find_in_dir(&self, dir: &Node, name: &[u8]) -> FsResult<Resolved> {
        if dir.kind != NODE_KIND_DIR || dir.child_count == 0 {
            return Err(FsError::NotFound);
        }
        let lba = self.dir_block(dir)?;
        let mut block = [0u8; BLOCK_SIZE];
        self.read_data_block(lba, &mut block)?;
        for i in 0..dir.child_count {
            let off = (i as usize) * 4;
            let id = u32::from_le_bytes([block[off], block[off + 1], block[off + 2], block[off + 3]]);
            let child = self.read_node(id)?;
            if child.kind != NODE_KIND_UNUSED && child.name_bytes() == name {
                return Ok(Resolved {
                    node_id: id,
                    node: child,
                });
            }
        }
        Err(FsError::NotFound)
    }

    pub(crate) fn dir_add_child(&mut self, dir_id: u32, child_id: u32) -> FsResult<()> {
        let mut dir = self.read_node(dir_id)?;
        if dir.kind != NODE_KIND_DIR {
            return Err(FsError::NotADir);
        }
        if dir.child_count >= DIR_MAX_CHILDREN {
            return Err(FsError::NoSpaceData);
        }
        let lba = self.dir_block(&dir)?;
        let mut block = [0u8; BLOCK_SIZE];
        self.read_data_block(lba, &mut block)?;
        let off = (dir.child_count as usize) * 4;
        block[off..off + 4].copy_from_slice(&child_id.to_le_bytes());
        self.write_data_block(lba, &block)?;
        dir.child_count += 1;
        dir.size_bytes = dir.child_count * 4;
        self.write_node(dir_id, &dir)?;
        Ok(())
    }

    pub(crate) fn dir_remove_child(&mut self, dir_id: u32, child_id: u32) -> FsResult<()> {
        let mut dir = self.read_node(dir_id)?;
        let lba = self.dir_block(&dir)?;
        let mut block = [0u8; BLOCK_SIZE];
        self.read_data_block(lba, &mut block)?;
        let mut found_at: Option<usize> = None;
        for i in 0..dir.child_count {
            let off = (i as usize) * 4;
            let id = u32::from_le_bytes([block[off], block[off + 1], block[off + 2], block[off + 3]]);
            if id == child_id {
                found_at = Some(i as usize);
                break;
            }
        }
        let idx = found_at.ok_or(FsError::NotFound)?;
        let last = (dir.child_count - 1) as usize;
        if idx != last {
            let last_off = last * 4;
            let last_bytes = [
                block[last_off],
                block[last_off + 1],
                block[last_off + 2],
                block[last_off + 3],
            ];
            let dst_off = idx * 4;
            block[dst_off..dst_off + 4].copy_from_slice(&last_bytes);
        }
        self.write_data_block(lba, &block)?;
        dir.child_count -= 1;
        dir.size_bytes = dir.child_count * 4;
        self.write_node(dir_id, &dir)?;
        Ok(())
    }

    pub(crate) fn create_child(&mut self, parent_id: u32, name: &[u8], kind: u32) -> FsResult<u32> {
        if self.dev.is_read_only() {
            return Err(FsError::ReadOnly);
        }
        self.validate_name(name)?;
        let parent = self.read_node(parent_id)?;
        if parent.kind != NODE_KIND_DIR {
            return Err(FsError::NotADir);
        }
        if self.find_in_dir(&parent, name).is_ok() {
            return Err(FsError::NameExists);
        }
        let new_id = self.alloc_node()?;
        let mut node = Node::unused();
        node.kind = kind;
        node.parent_id = parent_id;
        node.link_count = 1;
        node.set_name(name);
        // Allocate one block of headroom — files (write_at grows
        // as needed), dirs (cap at DIR_MAX_CHILDREN), symlinks
        // (target stored in this block).
        let lba = self.alloc_run(1)?;
        node.extents[0] = Extent { block: lba, blocks: 1 };
        node.extent_count = 1;
        self.write_node(new_id, &node)?;
        if let Err(e) = self.dir_add_child(parent_id, new_id) {
            let _ = self.free_run(lba, 1);
            let _ = self.write_node(new_id, &Node::unused());
            return Err(e);
        }
        Ok(new_id)
    }

    /// Append capacity until the file holds at least `need_blocks`
    /// blocks across all extents. Tries to extend the last extent
    /// in place (cheap); falls back to appending a new extent
    /// (needs an open extent slot); falls back to NoSpaceExtents
    /// if all 8 slots are full.
    pub(crate) fn grow_file(&mut self, node: &mut Node, need_blocks: u32) -> FsResult<()> {
        while node.total_blocks() < need_blocks {
            let want = need_blocks - node.total_blocks();
            // Try to extend the last extent in place.
            let n = node.extent_count as usize;
            if n > 0 {
                let last = node.extents[n - 1];
                let next_lba = last.block + last.blocks;
                // Would the next consecutive blocks fit?
                let take = want.min(self.bitmap.free_count());
                if take > 0 && self.try_extend_extent(next_lba, take)? {
                    node.extents[n - 1].blocks += take;
                    continue;
                }
            }
            // Otherwise, append a new extent if a slot is free.
            if (node.extent_count as usize) >= MAX_INLINE_EXTENTS {
                return Err(FsError::NoSpaceExtents);
            }
            // Allocate as much as we can in one shot, but cap so
            // we don't request more than the bitmap can fit.
            let try_one = want.min(self.bitmap.free_count()).max(1);
            let lba = self.alloc_run(try_one)?;
            let slot = node.extent_count as usize;
            node.extents[slot] = Extent {
                block: lba,
                blocks: try_one,
            };
            node.extent_count += 1;
        }
        let _ = (ROOT_NODE_ID, INVALID_NODE_ID); // suppress unused-import noise
        Ok(())
    }

    /// True if the run [start, start+n) is fully free in the bitmap.
    /// Marks the run as used + flushes on success.
    fn try_extend_extent(&mut self, start: u32, n: u32) -> FsResult<bool> {
        if n == 0 || start.checked_add(n).is_none() {
            return Ok(false);
        }
        for i in 0..n {
            if self.bitmap.is_set(start + i) || (start + i) >= self.sb.total_blocks {
                return Ok(false);
            }
        }
        for i in 0..n {
            self.bitmap.mark_used(start + i);
        }
        self.bitmap.flush(self.dev).map_err(|_| FsError::Io)?;
        // Update bitmap's CRC entry to match the new on-disk content,
        // and seed each freshly-allocated block's CRC with the
        // zero-fill we're about to write. Without this, fsck reports
        // a CRC mismatch for the bitmap (its bits changed) and for
        // every extended block (table still says 0).
        let mut bm = [0u8; BLOCK_SIZE];
        self.dev.read_block(BITMAP_LBA, &mut bm).map_err(|_| FsError::Io)?;
        self.crc_table.set(BITMAP_LBA, crc32(&bm));
        let zero = [0u8; BLOCK_SIZE];
        let zero_crc = crc32(&zero);
        for i in 0..n {
            self.dev.write_block(start + i, &zero).map_err(|_| FsError::Io)?;
            self.crc_table.set(start + i, zero_crc);
        }
        self.crc_table.flush(self.dev).map_err(|_| FsError::Io)?;
        Ok(true)
    }
}
