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
    NODE_KIND_DIR, NODE_KIND_FILE, NODE_KIND_SYMLINK, NODE_TABLE_BLOCKS, NODE_TABLE_LBA,
    SNAPSHOT_BLOCKS, SNAPSHOT_LBA, SUPERBLOCK_LBA,
};
use crate::fs::{compute_sb_crc, Fs, FsError, FsResult};
use crate::mkfs;

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

        // Per-node refcount derived from dir entries (so we can
        // catch link_count drift).
        let mut ref_count = [0u32; 64]; // NODE_COUNT in v3

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
                let lba = node.extents[0].block;
                let mut block = [0u8; BLOCK_SIZE];
                self.dev.read_block(lba, &mut block).map_err(|_| FsError::Io)?;
                for i in 0..node.child_count
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
        // link_count. The root dir has link_count=1 (self-loop),
        // not derived from any parent's child list, so skip it.
        for id in 0..self.sb.node_count
        {
            let node = self.read_node(id)?;
            if node.kind == 0 || id == self.sb.root_node
            {
                continue;
            }
            let derived = ref_count[id as usize];
            if derived != node.link_count
            {
                report.link_count_mismatch += 1;
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
            if b >= JOURNAL_LBA && b < JOURNAL_LBA + JOURNAL_BLOCKS
            {
                continue;
            }
            // Snapshot blocks change on snapshot_create / restore;
            // their CRC is implicit in the snapshot SB copy at
            // SNAPSHOT_LBA, not the live crc_table entry.
            if b >= SNAPSHOT_LBA && b < SNAPSHOT_LBA + SNAPSHOT_BLOCKS
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
