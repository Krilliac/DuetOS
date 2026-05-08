// DuetFS fsck — consistency check + repair (v3).
//
// What it does (v3):
//   1. Walk every reachable node; rebuild the should-be bitmap;
//      diff against the on-disk bitmap.
//   2. Re-derive the per-node link_count from the dir-children
//      tables; flag mismatches.
//   3. Read every metadata + data block back, recompute its CRC,
//      and compare to the stored CRC table entry.
//   4. Optionally repair (rewrite the bitmap + CRC table + SB).

use crate::alloc_bitmap::BitmapAllocator;
use crate::block_dev::BlockDevice;
use crate::crc32::crc32;
use crate::format::{
    BITMAP_LBA, BLOCK_SIZE, CRC_TABLE_LBA, JOURNAL_BLOCKS, JOURNAL_LBA, MAX_INLINE_EXTENTS,
    NODE_COUNT, NODE_KIND_DIR, NODE_KIND_FILE, NODE_KIND_SYMLINK, NODE_TABLE_BLOCKS,
    NODE_TABLE_LBA, SNAPSHOT_BLOCKS, SNAPSHOT_LBA, SUPERBLOCK_LBA,
};
use crate::fs::{compute_sb_crc, Fs, FsError, FsResult};
use crate::mkfs;
use crate::ops_dir::DIR_MAX_CHILDREN;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FsckReport
{
    pub leaked_blocks: u32,
    pub missing_blocks: u32,
    pub orphan_nodes: u32,
    pub bad_extents: u32,
    pub repaired: u32,
    pub sb_crc_mismatch: u32,
    pub block_crc_mismatch: u32,
    pub link_count_mismatch: u32,
}

impl<'d, D: BlockDevice + ?Sized> Fs<'d, D>
{
    pub fn fsck(&mut self, repair: bool) -> FsResult<FsckReport>
    {
        let mut report = FsckReport::default();
        let mut want = BitmapAllocator::fresh(self.sb.total_blocks);

        // Mark fixed regions.
        want.mark_used(SUPERBLOCK_LBA);
        want.mark_used(BITMAP_LBA);
        want.mark_used(CRC_TABLE_LBA);
        for i in 0..NODE_TABLE_BLOCKS
        {
            want.mark_used(NODE_TABLE_LBA + i);
        }
        for i in 0..JOURNAL_BLOCKS
        {
            want.mark_used(JOURNAL_LBA + i);
        }
        for i in 0..SNAPSHOT_BLOCKS
        {
            want.mark_used(SNAPSHOT_LBA + i);
        }

        // Reachability from the root dir. This is intentionally
        // separate from the bitmap rebuild below: repair does not
        // recycle orphan nodes yet, so the allocator still treats
        // their extents as pinned. The signal is explicit in
        // report.orphan_nodes until a future repair slice can clear
        // those nodes safely.
        let mut reachable = [false; NODE_COUNT as usize];
        let mut stack = [0u32; NODE_COUNT as usize];
        let mut top: usize = 0;
        if self.sb.root_node < self.sb.node_count && (self.sb.root_node as usize) < reachable.len()
        {
            reachable[self.sb.root_node as usize] = true;
            stack[top] = self.sb.root_node;
            top += 1;
        }
        while top > 0
        {
            top -= 1;
            let id = stack[top];
            let node = self.read_node(id)?;
            if node.kind != NODE_KIND_DIR || node.child_count == 0
            {
                continue;
            }
            if node.child_count > DIR_MAX_CHILDREN
            {
                report.bad_extents += 1;
            }
            if node.extent_count == 0
                || node.extents[0].blocks == 0
                || node.extents[0].block < self.sb.data_lba
                || node.extents[0].block >= self.sb.total_blocks
            {
                report.bad_extents += 1;
                continue;
            }
            let lba = node.extents[0].block;
            let mut block = [0u8; BLOCK_SIZE];
            self.dev.read_block(lba, &mut block).map_err(|_| FsError::Io)?;
            let child_count = node.child_count.min(DIR_MAX_CHILDREN);
            for i in 0..child_count
            {
                let off = (i as usize) * 4;
                let cid = u32::from_le_bytes([
                    block[off], block[off + 1], block[off + 2], block[off + 3],
                ]);
                if cid >= self.sb.node_count || (cid as usize) >= reachable.len()
                {
                    report.bad_extents += 1;
                    continue;
                }
                let child = self.read_node(cid)?;
                if child.kind != NODE_KIND_FILE
                    && child.kind != NODE_KIND_DIR
                    && child.kind != NODE_KIND_SYMLINK
                {
                    continue;
                }
                if !reachable[cid as usize]
                {
                    reachable[cid as usize] = true;
                    if top < stack.len()
                    {
                        stack[top] = cid;
                        top += 1;
                    }
                }
            }
        }

        // Per-node refcount derived from dir entries (so we can
        // catch link_count drift).
        let mut ref_count = [0u32; NODE_COUNT as usize];

        for id in 0..self.sb.node_count
        {
            let node = self.read_node(id)?;
            if node.kind == 0
            {
                continue;
            }
            if node.kind != NODE_KIND_FILE
                && node.kind != NODE_KIND_DIR
                && node.kind != NODE_KIND_SYMLINK
            {
                report.orphan_nodes += 1;
                continue;
            }
            let n_ext = (node.extent_count as usize).min(MAX_INLINE_EXTENTS);
            for i in 0..n_ext
            {
                let e = node.extents[i];
                if e.blocks == 0
                {
                    continue;
                }
                if e.block < self.sb.data_lba
                    || e.block.checked_add(e.blocks).is_none()
                    || e.block + e.blocks > self.sb.total_blocks
                {
                    report.bad_extents += 1;
                    continue;
                }
                for k in 0..e.blocks
                {
                    let b = e.block + k;
                    if want.is_set(b)
                    {
                        // Hard links share extents — if the same
                        // block is reachable from multiple nodes
                        // that's fine for symlinks/files, only
                        // problematic for unrelated nodes. v3 fsck
                        // doesn't dedupe shares; counts as leaked.
                        report.leaked_blocks += 1;
                    }
                    else
                    {
                        want.mark_used(b);
                    }
                }
            }

            // For dirs, walk the child list and bump the children's
            // ref counters.
            if node.kind == NODE_KIND_DIR && node.child_count > 0
            {
                if node.child_count > DIR_MAX_CHILDREN
                {
                    report.bad_extents += 1;
                }
                if node.extent_count == 0
                    || node.extents[0].blocks == 0
                    || node.extents[0].block < self.sb.data_lba
                    || node.extents[0].block >= self.sb.total_blocks
                {
                    report.bad_extents += 1;
                    continue;
                }
                let lba = node.extents[0].block;
                let mut block = [0u8; BLOCK_SIZE];
                self.dev.read_block(lba, &mut block).map_err(|_| FsError::Io)?;
                let child_count = node.child_count.min(DIR_MAX_CHILDREN);
                for i in 0..child_count
                {
                    let off = (i as usize) * 4;
                    let cid = u32::from_le_bytes([
                        block[off], block[off + 1], block[off + 2], block[off + 3],
                    ]);
                    if (cid as usize) < ref_count.len()
                    {
                        ref_count[cid as usize] += 1;
                    }
                }
            }
        }

        // Re-walk: compare derived ref_count to each node's
        // link_count and flag nodes that are either unreachable from
        // root or whose parent_id chain never reaches root (cycle,
        // invalid parent, or non-dir parent). The root dir has
        // link_count=1 (self-loop), not derived from any parent's
        // child list, so skip it.
        for id in 0..self.sb.node_count
        {
            let node = self.read_node(id)?;
            if node.kind == 0 || id == self.sb.root_node
            {
                continue;
            }
            if node.kind != NODE_KIND_FILE
                && node.kind != NODE_KIND_DIR
                && node.kind != NODE_KIND_SYMLINK
            {
                continue;
            }
            let derived = ref_count[id as usize];
            if derived != node.link_count
            {
                report.link_count_mismatch += 1;
            }

            let mut parent_ok = false;
            let mut seen = [false; NODE_COUNT as usize];
            let mut cur = node.parent_id;
            for _ in 0..self.sb.node_count
            {
                if cur == self.sb.root_node
                {
                    parent_ok = true;
                    break;
                }
                if cur >= self.sb.node_count || (cur as usize) >= seen.len() || seen[cur as usize]
                {
                    break;
                }
                seen[cur as usize] = true;
                let parent = self.read_node(cur)?;
                if parent.kind != NODE_KIND_DIR
                {
                    break;
                }
                cur = parent.parent_id;
            }
            if !reachable[id as usize] || !parent_ok
            {
                report.orphan_nodes += 1;
            }
        }

        // Diff bitmap.
        for b in 0..self.sb.total_blocks
        {
            let on_disk = self.bitmap.is_set(b);
            let should = want.is_set(b);
            if on_disk && !should
            {
                report.leaked_blocks += 1;
            }
            else if !on_disk && should
            {
                report.missing_blocks += 1;
            }
        }

        // Per-block CRC verification. Only checks blocks the
        // metadata thinks are in use — unallocated blocks have no
        // CRC entry (table defaults to 0) but their on-disk bytes
        // are arbitrary, so verifying them produces false mismatches.
        // Journal blocks are mutated by every metadata commit (and
        // the descriptor itself by every open via replay's clear) —
        // their CRC entries can't track those updates without
        // doubling the I/O on every write. The journal's own
        // descriptor CRC + payload CRCs cover its integrity instead,
        // so skip the journal range here.
        let mut buf = [0u8; BLOCK_SIZE];
        for b in 0..self.sb.total_blocks
        {
            if b == CRC_TABLE_LBA
            {
                continue;
            }
            if (JOURNAL_LBA..JOURNAL_LBA + JOURNAL_BLOCKS).contains(&b)
            {
                continue;
            }
            // Snapshot blocks change on snapshot_create / restore;
            // their CRC is implicit in the snapshot SB copy at
            // SNAPSHOT_LBA, not the live crc_table entry.
            if (SNAPSHOT_LBA..SNAPSHOT_LBA + SNAPSHOT_BLOCKS).contains(&b)
            {
                continue;
            }
            if !want.is_set(b)
            {
                continue;
            }
            self.dev.read_block(b, &mut buf).map_err(|_| FsError::Io)?;
            let want_crc = self.crc_table.get(b).unwrap_or(0);
            let got_crc = crc32(&buf);
            if want_crc != got_crc
            {
                report.block_crc_mismatch += 1;
            }
        }

        if repair
        {
            self.bitmap = want;
            self.bitmap.flush(self.dev).map_err(|_| FsError::Io)?;
            self.sb.free_blocks = self.bitmap.free_count();
            self.sb.sb_crc32 = compute_sb_crc(&self.sb);
            // Rewrite the SB BEFORE we hash it for the CRC table —
            // otherwise the entry captures the pre-repair contents
            // and the next clean pass reports a CRC mismatch.
            mkfs::rewrite_superblock(self.dev, &self.sb)?;
            // Rebuild every CRC entry by reading + hashing. The
            // journal range tracks its own CRC inside the descriptor
            // — leave its crc_table entries pointing at whatever the
            // current bytes hash to, but the verifier above skips
            // them so the entry's value doesn't matter.
            for b in 0..self.sb.total_blocks
            {
                if b == CRC_TABLE_LBA
                {
                    self.crc_table.set(b, 0);
                    continue;
                }
                self.dev.read_block(b, &mut buf).map_err(|_| FsError::Io)?;
                self.crc_table.set(b, crc32(&buf));
            }
            self.crc_table.flush(self.dev).map_err(|_| FsError::Io)?;
            report.repaired = 1;
        }

        Ok(report)
    }
}
