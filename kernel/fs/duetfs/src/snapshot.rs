// DuetFS snapshot — v7. Single-slot save / restore + CoW pinning.
//
// Layout (relative to SNAPSHOT_LBA):
//   +0          snapshot SB copy
//   +1          snapshot bitmap copy (used as the pin bitmap while
//               SB.snapshot_present == 1)
//   +2          snapshot CRC-table copy
//   +3..6       snapshot node-table copy
//
// State machine:
//   PRESENT_NO  — slot is dormant; the live FS allocates freely.
//   PRESENT_YES — slot holds a frozen copy. The live FS may still
//                 mutate, but `alloc_run` consults the snapshot
//                 bitmap and refuses to reuse any block the
//                 snapshot pins. Restore copies the slot back on
//                 top of the live metadata; create-then-restore is
//                 idempotent (no harm in restoring a never-mutated
//                 snapshot).
//
// The snapshot blocks are NOT covered by the live CRC table — fsck
// skips the range — because they're written exactly twice per
// snapshot lifecycle (once at create, once at restore) and their
// integrity is established by the SB copy's own sb_crc32 + a CRC
// over each metadata block stored in the live crc_table copy.
//
// Multi-snapshot timeline lands in a follow-up. v7 only has to
// prove the single-slot save / pin / restore round-trip works.

use crate::block_dev::BlockDevice;
use crate::format::{
    BLOCK_SIZE, BITMAP_LBA, CRC_TABLE_LBA, NODE_TABLE_BLOCKS, NODE_TABLE_LBA, SNAPSHOT_LBA,
    SNAPSHOT_BITMAP_OFFSET, SNAPSHOT_CRC_OFFSET, SNAPSHOT_NODE_TABLE_OFFSET, SNAPSHOT_SB_OFFSET,
    SUPERBLOCK_LBA,
};
use crate::fs::{FsError, FsResult};

/// Take a snapshot of the live metadata. Reads SB / bitmap /
/// crc_table / node_table blocks and writes them into the snapshot
/// slot. After this call the live SB has `snapshot_present == 1`.
pub fn create<D: BlockDevice + ?Sized>(dev: &mut D, ts_ns: u64) -> FsResult<()>
{
    if dev.is_read_only()
    {
        return Err(FsError::ReadOnly);
    }
    let mut buf = [0u8; BLOCK_SIZE];

    // 1. Copy each live metadata block into the corresponding
    //    snapshot slot. SB goes last so a partially-written
    //    snapshot doesn't claim PRESENT_YES.
    dev.read_block(BITMAP_LBA, &mut buf).map_err(|_| FsError::Io)?;
    dev.write_block(SNAPSHOT_LBA + SNAPSHOT_BITMAP_OFFSET, &buf).map_err(|_| FsError::Io)?;
    dev.read_block(CRC_TABLE_LBA, &mut buf).map_err(|_| FsError::Io)?;
    dev.write_block(SNAPSHOT_LBA + SNAPSHOT_CRC_OFFSET, &buf).map_err(|_| FsError::Io)?;
    for i in 0..NODE_TABLE_BLOCKS
    {
        dev.read_block(NODE_TABLE_LBA + i, &mut buf).map_err(|_| FsError::Io)?;
        dev.write_block(SNAPSHOT_LBA + SNAPSHOT_NODE_TABLE_OFFSET + i, &buf)
            .map_err(|_| FsError::Io)?;
    }

    // 2. Read the live SB, swap in `snapshot_present = YES` + the
    //    timestamp, recompute the SB CRC, write the SB to BOTH the
    //    live slot AND the snapshot slot. The SB write is the
    //    commit barrier: after it, replay / mount sees a present
    //    snapshot.
    let mut sb_block = [0u8; BLOCK_SIZE];
    dev.read_block(SUPERBLOCK_LBA, &mut sb_block).map_err(|_| FsError::Io)?;
    let mut sb = unsafe {
        core::ptr::read_unaligned(sb_block.as_ptr() as *const crate::format::Superblock)
    };
    sb.snapshot_present = crate::format::SNAPSHOT_PRESENT_YES;
    sb.snapshot_timestamp_ns = ts_ns;
    sb.sb_crc32 = 0;
    sb.sb_crc32 = crate::fs::compute_sb_crc(&sb);
    let mut new_sb_block = [0u8; BLOCK_SIZE];
    let raw = unsafe {
        core::slice::from_raw_parts(
            (&sb as *const crate::format::Superblock) as *const u8,
            core::mem::size_of::<crate::format::Superblock>(),
        )
    };
    new_sb_block[..raw.len()].copy_from_slice(raw);
    dev.write_block(SNAPSHOT_LBA + SNAPSHOT_SB_OFFSET, &new_sb_block)
        .map_err(|_| FsError::Io)?;
    dev.write_block(SUPERBLOCK_LBA, &new_sb_block).map_err(|_| FsError::Io)?;
    Ok(())
}

/// Restore the snapshot slot on top of the live metadata. After
/// this the live FS exactly matches the state captured by `create`.
/// The snapshot slot stays populated — a subsequent restore is a
/// no-op idempotent re-apply.
pub fn restore<D: BlockDevice + ?Sized>(dev: &mut D) -> FsResult<()>
{
    if dev.is_read_only()
    {
        return Err(FsError::ReadOnly);
    }
    // 1. Verify the snapshot slot is populated. Read the snapshot
    //    SB; if its magic / version don't match, the slot is empty
    //    or corrupt.
    let mut snap_sb_block = [0u8; BLOCK_SIZE];
    dev.read_block(SNAPSHOT_LBA + SNAPSHOT_SB_OFFSET, &mut snap_sb_block)
        .map_err(|_| FsError::Io)?;
    let snap_sb = unsafe {
        core::ptr::read_unaligned(snap_sb_block.as_ptr() as *const crate::format::Superblock)
    };
    if snap_sb.magic != crate::format::MAGIC || snap_sb.version != crate::format::VERSION
    {
        return Err(FsError::NotFound);
    }
    let mut buf = [0u8; BLOCK_SIZE];

    // 2. Copy each snapshot metadata block back to its live slot.
    dev.read_block(SNAPSHOT_LBA + SNAPSHOT_BITMAP_OFFSET, &mut buf).map_err(|_| FsError::Io)?;
    dev.write_block(BITMAP_LBA, &buf).map_err(|_| FsError::Io)?;
    dev.read_block(SNAPSHOT_LBA + SNAPSHOT_CRC_OFFSET, &mut buf).map_err(|_| FsError::Io)?;
    dev.write_block(CRC_TABLE_LBA, &buf).map_err(|_| FsError::Io)?;
    for i in 0..NODE_TABLE_BLOCKS
    {
        dev.read_block(SNAPSHOT_LBA + SNAPSHOT_NODE_TABLE_OFFSET + i, &mut buf)
            .map_err(|_| FsError::Io)?;
        dev.write_block(NODE_TABLE_LBA + i, &buf).map_err(|_| FsError::Io)?;
    }

    // 3. Restore the live SB last — the commit barrier (a torn
    //    write before this point leaves snapshot_present == YES,
    //    so a re-mount + retry restore picks up where we left off).
    //    Carry over the snapshot_present flag from the snapshot SB
    //    itself (it stays YES — the slot remains populated).
    dev.write_block(SUPERBLOCK_LBA, &snap_sb_block).map_err(|_| FsError::Io)?;
    Ok(())
}

/// Read the snapshot bitmap (only meaningful when SB
/// `snapshot_present == YES`). Returned bytes are LE-packed bits;
/// `bit set = block pinned by snapshot, allocator must skip`.
pub fn read_pinned_bitmap<D: BlockDevice + ?Sized>(dev: &D) -> FsResult<[u8; BLOCK_SIZE]>
{
    let mut buf = [0u8; BLOCK_SIZE];
    dev.read_block(SNAPSHOT_LBA + SNAPSHOT_BITMAP_OFFSET, &mut buf)
        .map_err(|_| FsError::Io)?;
    Ok(buf)
}
