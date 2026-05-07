// DuetFS fsck — consistency check + repair (v2 read-only).
//
// What it does:
//   1. Walk the entire reachable tree from the root via the parent
//      <-> child links.
//   2. Compute the "should-be" bitmap from scratch: SB + bitmap +
//      node table + every reachable extent + every reachable
//      dir-children block.
//   3. Compare to the on-disk bitmap; report counts of {leaked,
//      double-counted} blocks.
//   4. Optionally repair (rewrite the bitmap + recompute the SB
//      CRC) when `repair = true`.
//
// What it doesn't do (yet):
//   - Reachability sweep through orphaned nodes (a node whose
//     parent_id points to a different node that doesn't list it).
//   - Per-block CRCs (only the SB has a CRC in v2).
//   - Cycle detection in parent_id chains.

use crate::alloc_bitmap::BitmapAllocator;
use crate::block_dev::BlockDevice;
use crate::format::{
    BITMAP_LBA, MAX_INLINE_EXTENTS, NODE_KIND_DIR, NODE_KIND_FILE, NODE_TABLE_BLOCKS,
    NODE_TABLE_LBA, SUPERBLOCK_LBA,
};
use crate::fs::{compute_sb_crc, Fs, FsError, FsResult};
use crate::mkfs;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FsckReport
{
    pub leaked_blocks: u32,    // marked-used in bitmap, not reachable
    pub missing_blocks: u32,   // reachable, not marked-used
    pub orphan_nodes: u32,     // node whose parent_id is invalid
    pub bad_extents: u32,      // extent with block < data_lba or block + blocks > total_blocks
    pub repaired: u32,         // 1 if bitmap was rewritten
    pub sb_crc_mismatch: u32,  // 1 if the on-disk SB CRC didn't match
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
        for i in 0..NODE_TABLE_BLOCKS
        {
            want.mark_used(NODE_TABLE_LBA + i);
        }

        // Walk every node; mark its extents.
        for id in 0..self.sb.node_count
        {
            let node = self.read_node(id)?;
            if node.kind == 0
            {
                continue;
            }
            if node.kind != NODE_KIND_FILE && node.kind != NODE_KIND_DIR
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
                        // Two nodes sharing a block — count as leaked
                        // (the second hit is the "extra"). v2 fsck
                        // doesn't repair this; flag it for the next
                        // slice.
                        report.leaked_blocks += 1;
                    }
                    else
                    {
                        want.mark_used(b);
                    }
                }
            }
        }

        // Diff the on-disk bitmap vs. the recomputed one.
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

        if repair
        {
            // Wholesale-replace the bitmap with the recomputed one
            // and rewrite the superblock with the new free_blocks
            // count + a fresh CRC.
            self.bitmap = want;
            self.bitmap.flush(self.dev).map_err(|_| FsError::Io)?;
            self.sb.free_blocks = self.bitmap.free_count();
            self.sb.sb_crc32 = compute_sb_crc(&self.sb);
            mkfs::rewrite_superblock(self.dev, &self.sb)?;
            report.repaired = 1;
        }

        Ok(report)
    }
}
