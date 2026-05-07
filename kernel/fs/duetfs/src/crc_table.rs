// Per-block CRC table.
//
// Stored in one block at LBA CRC_TABLE_LBA. Layout: 1024 little-
// endian u32 entries, indexed by FS block LBA. Entry [SUPERBLOCK_LBA]
// mirrors the SB's own sb_crc32 (the SB has a self-contained CRC,
// duplicated here so a uniform fsck pass works).
//
// Updates: every write through Fs::write_block_checked recomputes
// the entry for the written LBA. Reads do NOT verify CRCs in v3 —
// fsck does. That keeps the read hot-path free.
//
// The CRC table itself isn't covered by its own CRC entry (would
// be circular); fsck flags a CRC table whose stored CRC for its
// own LBA is non-zero as suspicious.

use crate::block_dev::{BlockDevice, BlockResult};
use crate::crc32::crc32;
use crate::format::{BLOCK_SIZE, CRC_TABLE_ENTRIES, CRC_TABLE_LBA};

pub struct CrcTable
{
    bytes: [u8; BLOCK_SIZE],
    dirty: bool,
}

impl CrcTable
{
    pub fn load<D: BlockDevice + ?Sized>(dev: &D) -> BlockResult<Self>
    {
        let mut bytes = [0u8; BLOCK_SIZE];
        dev.read_block(CRC_TABLE_LBA, &mut bytes)?;
        Ok(Self { bytes, dirty: false })
    }

    pub fn fresh() -> Self
    {
        Self { bytes: [0u8; BLOCK_SIZE], dirty: true }
    }

    pub fn get(&self, lba: u32) -> Option<u32>
    {
        if lba >= CRC_TABLE_ENTRIES
        {
            return None;
        }
        let off = (lba as usize) * 4;
        Some(u32::from_le_bytes([
            self.bytes[off], self.bytes[off + 1], self.bytes[off + 2], self.bytes[off + 3],
        ]))
    }

    /// Set the CRC entry for `lba` to `crc`. No-op if `lba` is
    /// out of range — caller's responsibility to bound.
    pub fn set(&mut self, lba: u32, crc: u32)
    {
        if lba >= CRC_TABLE_ENTRIES
        {
            return;
        }
        let off = (lba as usize) * 4;
        let bytes = crc.to_le_bytes();
        self.bytes[off..off + 4].copy_from_slice(&bytes);
        self.dirty = true;
    }

    /// Compute the CRC for the contents of a block.
    #[allow(dead_code)] // exposed for callers that want to peek without writing
    pub fn compute(block: &[u8]) -> u32
    {
        crc32(block)
    }

    pub fn flush<D: BlockDevice + ?Sized>(&mut self, dev: &mut D) -> BlockResult<()>
    {
        if self.dirty
        {
            dev.write_block(CRC_TABLE_LBA, &self.bytes)?;
            self.dirty = false;
        }
        Ok(())
    }
}
