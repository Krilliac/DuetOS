// Free-block bitmap allocator.
//
// One bit per filesystem block, packed LSB-first within each byte.
// `bit set = block in use`. The bitmap lives at LBA 1 (BITMAP_LBA),
// occupying one block. Total addressable image size is therefore
// capped at BITMAP_BITS (32768 blocks = 128 MiB) in v1.
//
// The allocator caches the bitmap in RAM for the lifetime of an
// open `Fs` (see fs.rs) and writes it back through the block
// device on every mutation. v1 does not journal; a crash mid-
// operation will leave a node and a bitmap entry that disagree,
// which `fsck` will reconcile in a future slice.

use crate::block_dev::{BlockDevice, BlockResult};
use crate::format::{BITMAP_BITS, BITMAP_LBA, BLOCK_SIZE, MAX_TOTAL_BLOCKS};

pub struct BitmapAllocator
{
    bits: [u8; BLOCK_SIZE],
    total_blocks: u32,
    free_count: u32,
    dirty: bool,
}

impl BitmapAllocator
{
    pub fn load<D: BlockDevice + ?Sized>(dev: &D, total_blocks: u32) -> BlockResult<Self>
    {
        let mut bits = [0u8; BLOCK_SIZE];
        dev.read_block(BITMAP_LBA, &mut bits)?;
        let mut free_count: u32 = 0;
        for b in 0..total_blocks.min(MAX_TOTAL_BLOCKS)
        {
            if !bit_get(&bits, b)
            {
                free_count += 1;
            }
        }
        Ok(Self { bits, total_blocks, free_count, dirty: false })
    }

    pub fn fresh(total_blocks: u32) -> Self
    {
        Self {
            bits: [0u8; BLOCK_SIZE],
            total_blocks: total_blocks.min(MAX_TOTAL_BLOCKS),
            free_count: total_blocks.min(MAX_TOTAL_BLOCKS),
            dirty: true,
        }
    }

    pub fn free_count(&self) -> u32
    {
        self.free_count
    }

    #[allow(dead_code)] // exposed for future fsck / df callers
    pub fn is_set(&self, block: u32) -> bool
    {
        block < self.total_blocks && bit_get(&self.bits, block)
    }

    /// Mark block as in use. No-op if already set.
    pub fn mark_used(&mut self, block: u32)
    {
        if block >= self.total_blocks
        {
            return;
        }
        if !bit_get(&self.bits, block)
        {
            bit_set(&mut self.bits, block, true);
            self.free_count -= 1;
            self.dirty = true;
        }
    }

    /// Mark block as free. No-op if already free.
    pub fn mark_free(&mut self, block: u32)
    {
        if block >= self.total_blocks
        {
            return;
        }
        if bit_get(&self.bits, block)
        {
            bit_set(&mut self.bits, block, false);
            self.free_count += 1;
            self.dirty = true;
        }
    }

    /// Find a contiguous run of `n` free blocks. First-fit linear
    /// scan — adequate for v1 workloads (small images, modest churn).
    /// Returns the LBA of the first block on success.
    pub fn find_run(&self, n: u32) -> Option<u32>
    {
        self.find_run_with_pinned(n, None)
    }

    /// Same as `find_run` but treats blocks set in `pinned` as also-
    /// in-use. Used by the snapshot-aware allocator when a snapshot
    /// is present at SNAPSHOT_LBA — its bitmap copy is the pin set.
    pub fn find_run_with_pinned(
        &self, n: u32, pinned: Option<&[u8; BLOCK_SIZE]>,
    ) -> Option<u32>
    {
        if n == 0 || n > self.total_blocks
        {
            return None;
        }
        let mut run_start: Option<u32> = None;
        let mut run_len: u32 = 0;
        for b in 0..self.total_blocks
        {
            let pinned_set = match pinned
            {
                Some(bs) => bit_get(bs, b),
                None => false,
            };
            if bit_get(&self.bits, b) || pinned_set
            {
                run_start = None;
                run_len = 0;
                continue;
            }
            if run_start.is_none()
            {
                run_start = Some(b);
                run_len = 0;
            }
            run_len += 1;
            if run_len == n
            {
                return run_start;
            }
        }
        None
    }

    /// Allocate a contiguous run. Convenience for find_run +
    /// mark_used range. Returns the first LBA on success.
    pub fn alloc_run(&mut self, n: u32) -> Option<u32>
    {
        let start = self.find_run(n)?;
        for i in 0..n
        {
            self.mark_used(start + i);
        }
        Some(start)
    }

    /// Snapshot-aware variant — skips blocks set in `pinned`.
    pub fn alloc_run_with_pinned(
        &mut self, n: u32, pinned: Option<&[u8; BLOCK_SIZE]>,
    ) -> Option<u32>
    {
        let start = self.find_run_with_pinned(n, pinned)?;
        for i in 0..n
        {
            self.mark_used(start + i);
        }
        Some(start)
    }

    pub fn free_run(&mut self, start: u32, n: u32)
    {
        for i in 0..n
        {
            self.mark_free(start + i);
        }
    }

    pub fn flush<D: BlockDevice + ?Sized>(&mut self, dev: &mut D) -> BlockResult<()>
    {
        if self.dirty
        {
            dev.write_block(BITMAP_LBA, &self.bits)?;
            self.dirty = false;
        }
        Ok(())
    }
}

fn bit_get(bits: &[u8; BLOCK_SIZE], idx: u32) -> bool
{
    if idx >= BITMAP_BITS
    {
        return false;
    }
    let byte = (idx / 8) as usize;
    let mask = 1u8 << (idx % 8);
    (bits[byte] & mask) != 0
}

fn bit_set(bits: &mut [u8; BLOCK_SIZE], idx: u32, v: bool)
{
    if idx >= BITMAP_BITS
    {
        return;
    }
    let byte = (idx / 8) as usize;
    let mask = 1u8 << (idx % 8);
    if v
    {
        bits[byte] |= mask;
    }
    else
    {
        bits[byte] &= !mask;
    }
}
