// xattr — v8. Per-node extended-attribute store.
//
// Storage shape: one optional 4 KiB xattr block per node. The block
// holds a stream of records:
//
//   record := name_len: u16-le, value_len: u16-le,
//             name_bytes (name_len), value_bytes (value_len)
//
// Terminator: a record with name_len == 0. The FFI rejects empty
// names so the terminator can never collide with a real entry.
//
// `xattr_extent.blocks == 0` on the Node means "no xattrs" — the
// first set call allocates one block, every subsequent set / remove
// rewrites the block in place. Unsetting the last xattr frees the
// block.
//
// One block of total xattr storage gives ~4080 bytes after the
// header overhead, plenty for typical (system.posix_acl_access,
// security.selinux, user.tag) sets. Multi-block xattr lands in a
// follow-up once a real workload stresses this path.

use crate::block_dev::BlockDevice;
use crate::format::{
    Extent, BLOCK_SIZE, XATTR_NAME_MAX, XATTR_VALUE_MAX,
};
use crate::fs::{Fs, FsError, FsResult};

/// Look up `name` in the xattr block of node `node_id`. On hit
/// writes up to `dst.len()` bytes of the value to `dst` and the
/// full value length to `*out_len`. On miss returns
/// FsError::NotFound. `dst` may be shorter than the value — callers
/// detect this by `*out_len > dst.len()` and re-call with a bigger
/// buffer.
impl<'d, D: BlockDevice + ?Sized> Fs<'d, D>
{
    pub fn xattr_get(
        &self, node_id: u32, name: &[u8], dst: &mut [u8],
    ) -> FsResult<usize>
    {
        if name.is_empty() || name.len() > XATTR_NAME_MAX
        {
            return Err(FsError::Invalid);
        }
        let node = self.read_node(node_id)?;
        if node.xattr_extent.blocks == 0
        {
            return Err(FsError::NotFound);
        }
        let lba = node.xattr_extent.block;
        let mut block = [0u8; BLOCK_SIZE];
        self.dev.read_block(lba, &mut block).map_err(|_| FsError::Io)?;
        match find_record(&block, name)
        {
            Some((value_off, value_len)) => {
                let take = dst.len().min(value_len);
                dst[..take].copy_from_slice(&block[value_off..value_off + take]);
                Ok(value_len)
            }
            None => Err(FsError::NotFound),
        }
    }

    /// List xattr names. Writes a stream of NUL-separated names to
    /// `dst`. Returns the total byte count actually needed (which
    /// may exceed `dst.len()` — caller re-calls with a bigger
    /// buffer). Names without xattrs return 0.
    pub fn xattr_list(&self, node_id: u32, dst: &mut [u8]) -> FsResult<usize>
    {
        let node = self.read_node(node_id)?;
        if node.xattr_extent.blocks == 0
        {
            return Ok(0);
        }
        let lba = node.xattr_extent.block;
        let mut block = [0u8; BLOCK_SIZE];
        self.dev.read_block(lba, &mut block).map_err(|_| FsError::Io)?;
        let mut needed: usize = 0;
        let mut written: usize = 0;
        for_each_record(&block, |name_off, name_len, _value_off, _value_len| {
            if needed + name_len + 1 <= dst.len()
            {
                dst[written..written + name_len]
                    .copy_from_slice(&block[name_off..name_off + name_len]);
                dst[written + name_len] = 0;
                written += name_len + 1;
            }
            needed += name_len + 1;
        });
        Ok(needed)
    }

    /// Set / replace `name`'s value. Allocates the xattr block on
    /// first set; rewrites in place on subsequent calls. Returns
    /// FsError::NoSpaceData if the resulting block would exceed
    /// BLOCK_SIZE.
    pub fn xattr_set(
        &mut self, node_id: u32, name: &[u8], value: &[u8],
    ) -> FsResult<()>
    {
        if self.dev.is_read_only()
        {
            return Err(FsError::ReadOnly);
        }
        if name.is_empty() || name.len() > XATTR_NAME_MAX
        {
            return Err(FsError::Invalid);
        }
        if value.len() > XATTR_VALUE_MAX
        {
            return Err(FsError::Invalid);
        }
        let mut node = self.read_node(node_id)?;
        let mut block = [0u8; BLOCK_SIZE];
        if node.xattr_extent.blocks == 0
        {
            // No prior xattrs — allocate the block.
            let lba = self.alloc_run(1)?;
            node.xattr_extent = Extent { block: lba, blocks: 1 };
        }
        else
        {
            self.dev.read_block(node.xattr_extent.block, &mut block).map_err(|_| FsError::Io)?;
        }
        // Strip the existing entry (if any), then append the new
        // record before the terminator.
        let new_block = rewrite_with_set(&block, name, value).ok_or(FsError::NoSpaceData)?;
        self.write_data_block(node.xattr_extent.block, &new_block)?;
        self.write_node(node_id, &node)?;
        Ok(())
    }

    /// Remove `name`'s entry. If the block becomes empty, frees it
    /// and clears `node.xattr_extent`. FsError::NotFound when the
    /// name isn't present.
    pub fn xattr_remove(&mut self, node_id: u32, name: &[u8]) -> FsResult<()>
    {
        if self.dev.is_read_only()
        {
            return Err(FsError::ReadOnly);
        }
        if name.is_empty() || name.len() > XATTR_NAME_MAX
        {
            return Err(FsError::Invalid);
        }
        let mut node = self.read_node(node_id)?;
        if node.xattr_extent.blocks == 0
        {
            return Err(FsError::NotFound);
        }
        let lba = node.xattr_extent.block;
        let mut block = [0u8; BLOCK_SIZE];
        self.dev.read_block(lba, &mut block).map_err(|_| FsError::Io)?;
        let (new_block, found) = rewrite_with_remove(&block, name);
        if !found
        {
            return Err(FsError::NotFound);
        }
        // Detect "block now empty" — a fresh block holds only the
        // 4-byte zero terminator.
        let now_empty = new_block[0] == 0 && new_block[1] == 0 && new_block[2] == 0 && new_block[3] == 0;
        if now_empty
        {
            self.free_run(lba, 1)?;
            node.xattr_extent = Extent { block: 0, blocks: 0 };
        }
        else
        {
            self.write_data_block(lba, &new_block)?;
        }
        self.write_node(node_id, &node)?;
        Ok(())
    }
}

/// Walk the xattr block. Calls `cb(name_off, name_len, value_off,
/// value_len)` for each entry. Terminator: name_len == 0.
fn for_each_record<F>(block: &[u8; BLOCK_SIZE], mut cb: F)
where
    F: FnMut(usize, usize, usize, usize),
{
    let mut off: usize = 0;
    while off + 4 <= BLOCK_SIZE
    {
        let name_len = u16::from_le_bytes([block[off], block[off + 1]]) as usize;
        if name_len == 0
        {
            return;
        }
        let value_len = u16::from_le_bytes([block[off + 2], block[off + 3]]) as usize;
        if off + 4 + name_len + value_len > BLOCK_SIZE
        {
            return;
        }
        cb(off + 4, name_len, off + 4 + name_len, value_len);
        off += 4 + name_len + value_len;
    }
}

/// Find `name`'s record. Returns (value_off, value_len) on hit.
fn find_record(block: &[u8; BLOCK_SIZE], name: &[u8]) -> Option<(usize, usize)>
{
    let mut hit: Option<(usize, usize)> = None;
    for_each_record(block, |name_off, name_len, value_off, value_len| {
        if hit.is_none() && name_len == name.len() && &block[name_off..name_off + name_len] == name
        {
            hit = Some((value_off, value_len));
        }
    });
    hit
}

/// Rebuild the block with `name → value` set (replacing or appending).
/// Returns None if the resulting record stream wouldn't fit.
fn rewrite_with_set(
    block: &[u8; BLOCK_SIZE], name: &[u8], value: &[u8],
) -> Option<[u8; BLOCK_SIZE]>
{
    let mut out = [0u8; BLOCK_SIZE];
    let mut cursor: usize = 0;
    // Copy existing records, skipping any whose name matches.
    for_each_record(block, |name_off, name_len, value_off, value_len| {
        if name_len == name.len() && &block[name_off..name_off + name_len] == name
        {
            return; // dropped; will be replaced
        }
        let need = 4 + name_len + value_len;
        if cursor + need <= BLOCK_SIZE - (4 + name.len() + value.len()) - 4
        {
            out[cursor..cursor + 2].copy_from_slice(&(name_len as u16).to_le_bytes());
            out[cursor + 2..cursor + 4].copy_from_slice(&(value_len as u16).to_le_bytes());
            out[cursor + 4..cursor + 4 + name_len]
                .copy_from_slice(&block[name_off..name_off + name_len]);
            out[cursor + 4 + name_len..cursor + 4 + name_len + value_len]
                .copy_from_slice(&block[value_off..value_off + value_len]);
            cursor += need;
        }
    });
    // Append the new record.
    let new_record_size = 4 + name.len() + value.len();
    if cursor + new_record_size + 4 > BLOCK_SIZE
    {
        return None;
    }
    out[cursor..cursor + 2].copy_from_slice(&(name.len() as u16).to_le_bytes());
    out[cursor + 2..cursor + 4].copy_from_slice(&(value.len() as u16).to_le_bytes());
    out[cursor + 4..cursor + 4 + name.len()].copy_from_slice(name);
    out[cursor + 4 + name.len()..cursor + new_record_size].copy_from_slice(value);
    cursor += new_record_size;
    // Zero terminator (already zeroed but explicit for clarity).
    out[cursor] = 0;
    out[cursor + 1] = 0;
    out[cursor + 2] = 0;
    out[cursor + 3] = 0;
    Some(out)
}

/// Rebuild the block with `name`'s record removed. Returns the new
/// block + a "found" flag.
fn rewrite_with_remove(block: &[u8; BLOCK_SIZE], name: &[u8]) -> ([u8; BLOCK_SIZE], bool)
{
    let mut out = [0u8; BLOCK_SIZE];
    let mut cursor: usize = 0;
    let mut found = false;
    for_each_record(block, |name_off, name_len, value_off, value_len| {
        if name_len == name.len() && &block[name_off..name_off + name_len] == name
        {
            found = true;
            return;
        }
        let need = 4 + name_len + value_len;
        if cursor + need + 4 <= BLOCK_SIZE
        {
            out[cursor..cursor + 2].copy_from_slice(&(name_len as u16).to_le_bytes());
            out[cursor + 2..cursor + 4].copy_from_slice(&(value_len as u16).to_le_bytes());
            out[cursor + 4..cursor + 4 + name_len]
                .copy_from_slice(&block[name_off..name_off + name_len]);
            out[cursor + 4 + name_len..cursor + 4 + name_len + value_len]
                .copy_from_slice(&block[value_off..value_off + value_len]);
            cursor += need;
        }
    });
    (out, found)
}
