// DuetFS open-filesystem state.
//
// `Fs<'d, D>` borrows a block device and caches the superblock,
// the free-block bitmap, and the per-block CRC table. v3 added
// the CRC table; data-block writes go through write_data_block
// so the CRC entry is updated in lockstep.
//
// Nothing here allocates dynamically — every buffer is on the stack.

use crate::alloc_bitmap::BitmapAllocator;
use crate::block_dev::BlockDevice;
use crate::crc32::crc32;
use crate::crc_table::CrcTable;
use crate::format::{
    Extent, Node, Superblock, BITMAP_LBA, BLOCK_SIZE, CRC_TABLE_BLOCKS, CRC_TABLE_LBA, DATA_LBA, DIR_MAX_CHILDREN,
    INVALID_NODE_ID, JOURNAL_BLOCKS, JOURNAL_LBA, MAGIC, MAX_INLINE_EXTENTS, NAME_MAX, NODES_PER_BLOCK, NODE_COUNT,
    NODE_KIND_DIR, NODE_KIND_FILE, NODE_KIND_SYMLINK, NODE_KIND_UNUSED, NODE_SIZE, NODE_TABLE_BLOCKS, NODE_TABLE_LBA,
    ROOT_NODE_ID, SNAPSHOT_BLOCKS, SNAPSHOT_LBA, SUPERBLOCK_LBA, SYMLINK_TARGET_MAX, VERSION,
};
use crate::journal;

#[derive(Clone, Copy)]
pub enum FsError {
    Io,
    NotFound,
    NotADir,
    NotAFile,
    NameTooLong,
    NameExists,
    DirNotEmpty,
    NoSpaceData,
    NoSpaceNodes,
    NoSpaceExtents,
    Invalid,
    ReadOnly,
    Corrupt,
    NotASymlink,
    #[allow(dead_code)] // reserved for cross-volume link rejection (future slice)
    XdevLink,
    /// A symbolic-link chain exceeded MAX_SYMLINK_HOPS or the
    /// rewritten path exceeded the scratch buffer. Surfaced from
    /// lookup_path-style resolvers that follow symlinks.
    SymlinkLoop,
}

pub type FsResult<T> = Result<T, FsError>;

pub struct Fs<'d, D: BlockDevice + ?Sized + 'd> {
    pub(crate) dev: &'d mut D,
    pub(crate) sb: Superblock,
    pub(crate) bitmap: BitmapAllocator,
    pub(crate) crc_table: CrcTable,
    /// Next txn id to issue when wrapping a metadata write through
    /// `journal::apply`. Persisted only implicitly — on mount the
    /// replay path picks `last_committed_txn + 1` from the on-disk
    /// descriptor; an empty journal seeds it to 1. Wraparound is
    /// not a correctness concern (txn ids are advisory; the state
    /// machine runs off the descriptor's `state` field), so a
    /// saturating increment is fine.
    pub(crate) next_txn_id: u32,
}

fn extent_is_valid(extent: Extent, data_lba: u32, total_blocks: u32) -> bool {
    extent.blocks != 0
        && extent.block >= data_lba
        && extent
            .block
            .checked_add(extent.blocks)
            .is_some_and(|end| end <= total_blocks)
}

fn node_semantics_are_valid(
    id: u32,
    node: &Node,
    root_node: u32,
    node_count: u32,
    data_lba: u32,
    total_blocks: u32,
) -> bool {
    if node.extent_count as usize > MAX_INLINE_EXTENTS
        || node.child_count > DIR_MAX_CHILDREN
        || node.name_len as usize > NAME_MAX
    {
        return false;
    }

    if node.kind == NODE_KIND_UNUSED {
        return id != root_node
            && node.size_bytes == 0
            && node.extent_count == 0
            && node.child_count == 0
            && node.name_len == 0
            && node.link_count == 0
            && (node.parent_id == 0 || node.parent_id == INVALID_NODE_ID)
            && node
                .extents
                .iter()
                .all(|extent| extent.block == 0 && extent.blocks == 0)
            && node.xattr_extent.block == 0
            && node.xattr_extent.blocks == 0;
    }

    if !matches!(node.kind, NODE_KIND_FILE | NODE_KIND_DIR | NODE_KIND_SYMLINK)
        || node.parent_id >= node_count
        || node.link_count == 0
        || (id == root_node && node.kind != NODE_KIND_DIR)
        || (id != root_node && node.name_len == 0)
        || (node.kind != NODE_KIND_DIR && node.child_count != 0)
    {
        return false;
    }

    let name = &node.name[..node.name_len as usize];
    if name.iter().any(|byte| *byte == 0 || *byte == b'/' || *byte == b':') {
        return false;
    }

    let mut capacity_bytes = 0u64;
    for extent in &node.extents[..node.extent_count as usize] {
        if !extent_is_valid(*extent, data_lba, total_blocks) {
            return false;
        }
        capacity_bytes = match capacity_bytes.checked_add((extent.blocks as u64) * (BLOCK_SIZE as u64)) {
            Some(capacity) => capacity,
            None => return false,
        };
    }
    if node.size_bytes as u64 > capacity_bytes {
        return false;
    }

    if node.kind == NODE_KIND_DIR
        && (node.extent_count == 0 || node.size_bytes != node.child_count * core::mem::size_of::<u32>() as u32)
    {
        return false;
    }
    if node.kind == NODE_KIND_SYMLINK && node.size_bytes > SYMLINK_TARGET_MAX {
        return false;
    }

    if node.xattr_extent.blocks == 0 {
        node.xattr_extent.block == 0
    } else {
        node.xattr_extent.blocks == 1 && extent_is_valid(node.xattr_extent, data_lba, total_blocks)
    }
}

impl<'d, D: BlockDevice + ?Sized> Fs<'d, D> {
    pub fn open(dev: &'d mut D) -> FsResult<Self> {
        let mut block = [0u8; BLOCK_SIZE];
        dev.read_block(SUPERBLOCK_LBA, &mut block).map_err(|_| FsError::Io)?;
        let sb = read_superblock(&block);
        if sb.magic != MAGIC
            || sb.version != VERSION
            || sb.block_size as usize != BLOCK_SIZE
            || sb.bitmap_lba != BITMAP_LBA
            || sb.crc_table_lba != CRC_TABLE_LBA
            || sb.crc_table_blocks != CRC_TABLE_BLOCKS
            || sb.node_table_lba != NODE_TABLE_LBA
            || sb.node_table_blocks != NODE_TABLE_BLOCKS
            || sb.node_count != NODE_COUNT
            || sb.journal_lba != JOURNAL_LBA
            || sb.journal_blocks != JOURNAL_BLOCKS
            || sb.snapshot_lba != SNAPSHOT_LBA
            || sb.snapshot_blocks != SNAPSHOT_BLOCKS
            || sb.data_lba != DATA_LBA
            || sb.total_blocks > dev.block_count()
        {
            return Err(FsError::Invalid);
        }
        let want_crc = sb.sb_crc32;
        let got_crc = compute_sb_crc(&sb);
        if want_crc != got_crc {
            return Err(FsError::Corrupt);
        }
        // Replay any committed-but-unfinished journal txn. Must run
        // BEFORE we load the bitmap / crc_table so a torn write to
        // either of those structures gets rolled forward first. On a
        // read-only mount the journal can still hold a committed txn;
        // skip replay (the dev refuses writes anyway) and accept that
        // structural integrity matches whatever's on disk.
        let next_txn_id = if dev.is_read_only() {
            1
        } else {
            journal::replay(dev, JOURNAL_LBA)?
        };
        let bitmap = BitmapAllocator::load(dev, sb.total_blocks).map_err(|_| FsError::Io)?;
        let crc_table = CrcTable::load(dev).map_err(|_| FsError::Io)?;
        Ok(Self {
            dev,
            sb,
            bitmap,
            crc_table,
            next_txn_id,
        })
    }

    #[allow(dead_code)]
    pub fn superblock(&self) -> &Superblock {
        &self.sb
    }

    #[allow(dead_code)]
    pub fn free_blocks(&self) -> u32 {
        self.bitmap.free_count()
    }

    #[allow(dead_code)]
    pub fn sync(&mut self) -> FsResult<()> {
        self.bitmap.flush(self.dev).map_err(|_| FsError::Io)?;
        self.crc_table.flush(self.dev).map_err(|_| FsError::Io)?;
        Ok(())
    }

    // -------- Node table I/O --------

    pub(crate) fn read_node_raw(&self, id: u32) -> FsResult<Node> {
        if id >= self.sb.node_count {
            return Err(FsError::NotFound);
        }
        let lba = self.sb.node_table_lba + id / (NODES_PER_BLOCK as u32);
        let off = (id as usize % NODES_PER_BLOCK) * NODE_SIZE;
        let mut block = [0u8; BLOCK_SIZE];
        self.dev.read_block(lba, &mut block).map_err(|_| FsError::Io)?;
        let mut node = Node::unused();
        unsafe { core::slice::from_raw_parts_mut((&mut node) as *mut Node as *mut u8, NODE_SIZE) }
            .copy_from_slice(&block[off..off + NODE_SIZE]);
        Ok(node)
    }

    pub(crate) fn read_node(&self, id: u32) -> FsResult<Node> {
        let node = self.read_node_raw(id)?;
        if !node_semantics_are_valid(
            id,
            &node,
            self.sb.root_node,
            self.sb.node_count,
            self.sb.data_lba,
            self.sb.total_blocks,
        ) {
            return Err(FsError::Corrupt);
        }
        Ok(node)
    }

    pub(crate) fn write_node(&mut self, id: u32, node: &Node) -> FsResult<()> {
        if id >= self.sb.node_count {
            return Err(FsError::Invalid);
        }
        if !node_semantics_are_valid(
            id,
            node,
            self.sb.root_node,
            self.sb.node_count,
            self.sb.data_lba,
            self.sb.total_blocks,
        ) {
            return Err(FsError::Invalid);
        }
        let lba = self.sb.node_table_lba + id / (NODES_PER_BLOCK as u32);
        let off = (id as usize % NODES_PER_BLOCK) * NODE_SIZE;
        let mut block = [0u8; BLOCK_SIZE];
        self.dev.read_block(lba, &mut block).map_err(|_| FsError::Io)?;
        block[off..off + NODE_SIZE]
            .copy_from_slice(unsafe { core::slice::from_raw_parts((node as *const Node) as *const u8, NODE_SIZE) });
        // Atomic via the journal: the node-table block + the matching
        // CRC-table block move together. Without this, a torn write
        // between the two leaves the on-disk node valid but its CRC
        // entry stale (or vice versa) — fsck would flag it as
        // corruption when the FS is actually self-consistent.
        let crc = crc32(&block);
        self.crc_table.set(lba, crc);
        let crc_block = self.crc_table.materialise();
        let txn_id = self.next_txn_id;
        self.next_txn_id = txn_id.saturating_add(1).max(1);
        journal::apply(
            self.dev,
            JOURNAL_LBA,
            txn_id,
            &[(lba, &block), (CRC_TABLE_LBA, &crc_block)],
        )?;
        Ok(())
    }

    pub(crate) fn alloc_node(&mut self) -> FsResult<u32> {
        for id in 0..self.sb.node_count {
            if self.read_node(id)?.kind == NODE_KIND_UNUSED {
                return Ok(id);
            }
        }
        Err(FsError::NoSpaceNodes)
    }

    // -------- Block allocation --------

    pub(crate) fn alloc_run(&mut self, n: u32) -> FsResult<u32> {
        // When a snapshot is present, its bitmap copy pins every
        // block the snapshot references. The live allocator skips
        // those blocks so a future restore retains every byte the
        // snapshot captured. The read happens once per alloc — the
        // snapshot bitmap doesn't change during normal FS operation,
        // only on snapshot_create / restore.
        let pinned_buf: Option<[u8; BLOCK_SIZE]> = if self.sb.snapshot_present == crate::format::SNAPSHOT_PRESENT_YES {
            Some(crate::snapshot::read_pinned_bitmap(self.dev)?)
        } else {
            None
        };
        let lba = match pinned_buf.as_ref() {
            Some(pinned) => self.bitmap.alloc_run_with_pinned(n, Some(pinned)),
            None => self.bitmap.alloc_run(n),
        }
        .ok_or(FsError::NoSpaceData)?;
        self.bitmap.flush(self.dev).map_err(|_| FsError::Io)?;
        // Update bitmap's own CRC entry.
        let mut bm = [0u8; BLOCK_SIZE];
        self.dev.read_block(BITMAP_LBA, &mut bm).map_err(|_| FsError::Io)?;
        self.crc_table.set(BITMAP_LBA, crc32(&bm));
        // Zero each newly-allocated data block + checksum.
        let zero = [0u8; BLOCK_SIZE];
        for i in 0..n {
            self.dev.write_block(lba + i, &zero).map_err(|_| FsError::Io)?;
            self.crc_table.set(lba + i, crc32(&zero));
        }
        self.crc_table.flush(self.dev).map_err(|_| FsError::Io)?;
        Ok(lba)
    }

    pub(crate) fn free_run(&mut self, lba: u32, n: u32) -> FsResult<()> {
        self.bitmap.free_run(lba, n);
        self.bitmap.flush(self.dev).map_err(|_| FsError::Io)?;
        let mut bm = [0u8; BLOCK_SIZE];
        self.dev.read_block(BITMAP_LBA, &mut bm).map_err(|_| FsError::Io)?;
        self.crc_table.set(BITMAP_LBA, crc32(&bm));
        // Don't bother clearing the freed blocks' CRC entries; the
        // next alloc that takes them will overwrite. Saves one I/O.
        self.crc_table.flush(self.dev).map_err(|_| FsError::Io)?;
        Ok(())
    }

    pub(crate) fn free_node_extents(&mut self, node: &Node) -> FsResult<()> {
        let n = (node.extent_count as usize).min(MAX_INLINE_EXTENTS);
        for i in 0..n {
            let e = node.extents[i];
            if e.blocks > 0 && e.block != 0 {
                self.free_run(e.block, e.blocks)?;
            }
        }
        // v8 — also free the per-node xattr block. The unlink path
        // already calls this before recycling the node, so a node
        // with xattrs released cleanly never leaks the block.
        if node.xattr_extent.blocks > 0 && node.xattr_extent.block != 0 {
            self.free_run(node.xattr_extent.block, node.xattr_extent.blocks)?;
        }
        Ok(())
    }

    /// Read a *data* block (LBA >= data_lba) and verify its
    /// per-block CRC before handing bytes to callers. fsck still
    /// uses raw block reads so it can report and repair corruption
    /// instead of being blocked by the first mismatch.
    pub(crate) fn read_data_block(&self, lba: u32, dst: &mut [u8]) -> FsResult<()> {
        if lba < self.sb.data_lba || lba >= self.sb.total_blocks || dst.len() != BLOCK_SIZE {
            return Err(FsError::Invalid);
        }
        self.dev.read_block(lba, dst).map_err(|_| FsError::Io)?;
        let want_crc = self.crc_table.get(lba).ok_or(FsError::Corrupt)?;
        let got_crc = crc32(dst);
        if want_crc != got_crc {
            return Err(FsError::Corrupt);
        }
        Ok(())
    }

    /// Write a *data* block (LBA >= data_lba). Updates the CRC
    /// table in lockstep. Use this for every file/dir-children
    /// block write so fsck can verify integrity later.
    pub(crate) fn write_data_block(&mut self, lba: u32, src: &[u8]) -> FsResult<()> {
        if lba < self.sb.data_lba || src.len() != BLOCK_SIZE {
            return Err(FsError::Invalid);
        }
        self.dev.write_block(lba, src).map_err(|_| FsError::Io)?;
        self.crc_table.set(lba, crc32(src));
        self.crc_table.flush(self.dev).map_err(|_| FsError::Io)?;
        Ok(())
    }

    pub(crate) fn validate_name(&self, name: &[u8]) -> FsResult<()> {
        if name.is_empty() || name.len() > NAME_MAX {
            return Err(FsError::NameTooLong);
        }
        for &b in name {
            if b == 0 || b == b'/' || b == b':' {
                return Err(FsError::Invalid);
            }
        }
        Ok(())
    }
}

fn read_superblock(block: &[u8]) -> Superblock {
    let mut sb = Superblock {
        magic: 0,
        version: 0,
        block_size: 0,
        total_blocks: 0,
        node_count: 0,
        root_node: ROOT_NODE_ID,
        bitmap_lba: 0,
        crc_table_lba: 0,
        crc_table_blocks: 0,
        node_table_lba: 0,
        node_table_blocks: 0,
        data_lba: 0,
        free_blocks: 0,
        sb_crc32: 0,
        journal_lba: 0,
        journal_blocks: 0,
        encrypted: crate::format::ENCRYPTED_NO,
        kdf_m_cost_kib: 0,
        kdf_t_cost: 0,
        kdf_p_cost: 0,
        kdf_salt: [0; crate::format::SALT_BYTES],
        snapshot_lba: 0,
        snapshot_blocks: 0,
        snapshot_present: crate::format::SNAPSHOT_PRESENT_NO,
        snapshot_reserved: 0,
        snapshot_timestamp_ns: 0,
    };
    let raw = unsafe {
        core::slice::from_raw_parts_mut(
            (&mut sb) as *mut Superblock as *mut u8,
            core::mem::size_of::<Superblock>(),
        )
    };
    raw.copy_from_slice(&block[..core::mem::size_of::<Superblock>()]);
    sb
}

pub(crate) fn compute_sb_crc(sb: &Superblock) -> u32 {
    let mut copy = *sb;
    copy.sb_crc32 = 0;
    let raw = unsafe {
        core::slice::from_raw_parts(
            (&copy as *const Superblock) as *const u8,
            core::mem::size_of::<Superblock>(),
        )
    };
    crc32(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crafted_directory_child_count_is_rejected_before_indexing() {
        let mut node = Node::unused();
        node.kind = NODE_KIND_DIR;
        node.parent_id = ROOT_NODE_ID;
        node.link_count = 1;
        assert!(node.set_name(b"dir"));
        node.extents[0] = Extent {
            block: DATA_LBA,
            blocks: 1,
        };
        node.extent_count = 1;

        let mut encoded = [0u8; NODE_SIZE];
        encoded.copy_from_slice(unsafe { core::slice::from_raw_parts((&node as *const Node).cast::<u8>(), NODE_SIZE) });
        let child_count_offset = 3 * core::mem::size_of::<u32>();
        encoded[child_count_offset..child_count_offset + 4].copy_from_slice(&(DIR_MAX_CHILDREN + 1).to_le_bytes());
        let crafted = unsafe { core::ptr::read_unaligned(encoded.as_ptr().cast::<Node>()) };

        assert!(!node_semantics_are_valid(
            1,
            &crafted,
            ROOT_NODE_ID,
            NODE_COUNT,
            DATA_LBA,
            DATA_LBA + 8,
        ));
    }
}
