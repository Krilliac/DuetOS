// BlockDevice abstraction.
//
// The DuetFS write path doesn't speak directly to a disk — it goes
// through this trait. v1 ships two impls:
//
//   - `MemoryBlockDevice` — borrows a kernel-owned mutable buffer
//     (no Rust allocations). Used by the boot self-test and any
//     in-Rust testing.
//   - `ExternBlockDevice` — wraps a kernel-side block-handle via
//     two extern "C" callbacks. The C++ adapter
//     (kernel/fs/duetfs_kernel_block_dev.cpp) builds one of these
//     from a `BlockDeviceRead/Write(handle, …)` pair.
//
// All I/O is fixed at BLOCK_SIZE (4 KiB) per call. Sector-translation
// (when the underlying device's sector_size != BLOCK_SIZE) lives in
// the C++ adapter — Rust always sees 4 KiB blocks.

use core::ffi::c_void;

use crate::format::BLOCK_SIZE;

#[derive(Clone, Copy)]
pub enum BlockError {
    OutOfRange,
    Io,
    ReadOnly,
}

pub type BlockResult<T> = Result<T, BlockError>;

pub trait BlockDevice {
    fn block_count(&self) -> u32;
    fn is_read_only(&self) -> bool;
    fn read_block(&self, lba: u32, dst: &mut [u8]) -> BlockResult<()>;
    fn write_block(&mut self, lba: u32, src: &[u8]) -> BlockResult<()>;
}

/// In-memory backend over a borrowed byte buffer. The crate never
/// allocates; storage stays on the C++ side. Today the C++ adapter
/// goes through `ExternBlockDevice` even for memory-backed images,
/// so this impl is kept for future in-Rust testing scaffolds.
#[allow(dead_code)]
pub struct MemoryBlockDevice {
    bytes: *mut u8,
    len: usize,
    read_only: bool,
}

#[allow(dead_code)]
impl MemoryBlockDevice {
    /// SAFETY: `bytes[..len]` must remain valid and non-aliased for
    /// the lifetime of the returned device. `len` must be a multiple
    /// of `BLOCK_SIZE`.
    pub unsafe fn new(bytes: *mut u8, len: usize, read_only: bool) -> Self {
        Self { bytes, len, read_only }
    }
}

impl BlockDevice for MemoryBlockDevice {
    fn block_count(&self) -> u32 {
        (self.len / BLOCK_SIZE) as u32
    }

    fn is_read_only(&self) -> bool {
        self.read_only
    }

    fn read_block(&self, lba: u32, dst: &mut [u8]) -> BlockResult<()> {
        if dst.len() != BLOCK_SIZE {
            return Err(BlockError::Io);
        }
        let start = (lba as usize).checked_mul(BLOCK_SIZE).ok_or(BlockError::OutOfRange)?;
        let end = start.checked_add(BLOCK_SIZE).ok_or(BlockError::OutOfRange)?;
        if end > self.len {
            return Err(BlockError::OutOfRange);
        }
        unsafe {
            let src = core::slice::from_raw_parts(self.bytes.add(start), BLOCK_SIZE);
            dst.copy_from_slice(src);
        }
        Ok(())
    }

    fn write_block(&mut self, lba: u32, src: &[u8]) -> BlockResult<()> {
        if self.read_only {
            return Err(BlockError::ReadOnly);
        }
        if src.len() != BLOCK_SIZE {
            return Err(BlockError::Io);
        }
        let start = (lba as usize).checked_mul(BLOCK_SIZE).ok_or(BlockError::OutOfRange)?;
        let end = start.checked_add(BLOCK_SIZE).ok_or(BlockError::OutOfRange)?;
        if end > self.len {
            return Err(BlockError::OutOfRange);
        }
        unsafe {
            let dst = core::slice::from_raw_parts_mut(self.bytes.add(start), BLOCK_SIZE);
            dst.copy_from_slice(src);
        }
        Ok(())
    }
}

/// Kernel-handle backend. Wraps two extern "C" callbacks that the
/// C++ side fills with `BlockDeviceRead` / `BlockDeviceWrite`. The
/// crate calls through; sector translation is the adapter's
/// responsibility.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExternBlockDeviceOps {
    pub read: Option<unsafe extern "C" fn(cookie: *mut c_void, lba: u32, dst: *mut u8) -> i32>,
    pub write: Option<unsafe extern "C" fn(cookie: *mut c_void, lba: u32, src: *const u8) -> i32>,
}

pub struct ExternBlockDevice {
    pub cookie: *mut c_void,
    pub block_count: u32,
    pub ops: ExternBlockDeviceOps,
    pub read_only: bool,
}

impl BlockDevice for ExternBlockDevice {
    fn block_count(&self) -> u32 {
        self.block_count
    }

    fn is_read_only(&self) -> bool {
        self.read_only
    }

    fn read_block(&self, lba: u32, dst: &mut [u8]) -> BlockResult<()> {
        if dst.len() != BLOCK_SIZE || lba >= self.block_count {
            return Err(BlockError::OutOfRange);
        }
        let f = self.ops.read.ok_or(BlockError::Io)?;
        let rc = unsafe { f(self.cookie, lba, dst.as_mut_ptr()) };
        if rc != 0 {
            Err(BlockError::Io)
        } else {
            Ok(())
        }
    }

    fn write_block(&mut self, lba: u32, src: &[u8]) -> BlockResult<()> {
        if self.read_only {
            return Err(BlockError::ReadOnly);
        }
        if src.len() != BLOCK_SIZE || lba >= self.block_count {
            return Err(BlockError::OutOfRange);
        }
        let f = self.ops.write.ok_or(BlockError::ReadOnly)?;
        let rc = unsafe { f(self.cookie, lba, src.as_ptr()) };
        if rc != 0 {
            Err(BlockError::Io)
        } else {
            Ok(())
        }
    }
}
