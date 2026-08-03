// DuetFS C FFI — narrow surface, hand-mirrored in include/duetfs.h.
//
// One descriptor (`DuetFsDevice`) covers both memory- and kernel-
// block-handle backends; the C++ side fills in the read/write
// callbacks and DuetFS doesn't have to know which is which.
//
// Every call constructs a fresh `Fs` from the descriptor, performs
// the op, and lets the `Fs` drop. The bitmap auto-flushes inside
// each mutation, so a successful return leaves the device
// consistent. A panic inside the crate routes through
// `duetos_rust_panic` (panic.rs) — never UB on the C++ side.

// Pointer/length pairs cross one checked-slice funnel. Pure byte
// outputs are initialized with raw writes before Rust constructs a
// mutable slice; initialized in/out buffers use a separate helper.
// Writable regions are validated as disjoint from descriptors and
// inputs.

use core::ffi::{c_uchar, c_uint, c_void};
use core::mem::{align_of, size_of};

use crate::block_dev::{BlockDevice, ExternBlockDevice, ExternBlockDeviceOps};
use crate::compress;
use crate::crypto;
use crate::format::{
    BLOCK_SIZE, ENCRYPTED_AES_XTS_256, ENCRYPTED_NO, JOURNAL_LBA, MAX_TOTAL_BLOCKS, NAME_MAX, NODE_KIND_DIR,
    NODE_KIND_FILE, NODE_KIND_UNUSED, ROOT_NODE_ID, SALT_BYTES, SUPERBLOCK_LBA, SYMLINK_TARGET_MAX, XATTR_NAME_MAX,
    XATTR_VALUE_MAX,
};
use crate::fs::{Fs, FsError};
use crate::journal;
use crate::mkfs;
use crate::path::split_parent_and_name;
use crate::snapshot;

// Status codes returned by FFI fns. 0 = success, anything else = an
// FsError variant. Kept in lockstep with kKindMiss / kStatus* in
// include/duetfs.h.
const STATUS_OK: u32 = 0;
const STATUS_INVALID: u32 = 1;
const STATUS_NOT_FOUND: u32 = 2;
const STATUS_NOT_A_DIR: u32 = 3;
const STATUS_NOT_A_FILE: u32 = 4;
const STATUS_NAME_TOO_LONG: u32 = 5;
const STATUS_NAME_EXISTS: u32 = 6;
const STATUS_DIR_NOT_EMPTY: u32 = 7;
const STATUS_NO_SPACE_DATA: u32 = 8;
const STATUS_NO_SPACE_NODES: u32 = 9;
const STATUS_IO: u32 = 10;
const STATUS_READ_ONLY: u32 = 11;
const STATUS_NO_SPACE_EXTENTS: u32 = 12;
const STATUS_CORRUPT: u32 = 13;
const STATUS_NOT_A_SYMLINK: u32 = 14;
const STATUS_XDEV_LINK: u32 = 15;
const STATUS_SYMLINK_LOOP: u32 = 16;

// Keep native lengths from expanding into unbounded slice validity or
// work requirements. Path resolution has a matching 4-KiB scratch cap,
// and a v8 image cannot address more than MAX_TOTAL_BLOCKS blocks.
const FFI_PATH_CSTRING_MAX: usize = 4096 + 1;
const FFI_MAX_IO_BYTES: usize = (MAX_TOTAL_BLOCKS as usize) * BLOCK_SIZE;

#[repr(C)]
pub struct DuetFsDevice {
    pub cookie: *mut c_void,
    pub block_count: u32,
    pub read_only: u32,
    pub read: Option<unsafe extern "C" fn(cookie: *mut c_void, lba: u32, dst: *mut u8) -> i32>,
    pub write: Option<unsafe extern "C" fn(cookie: *mut c_void, lba: u32, src: *const u8) -> i32>,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DuetFsLookupResult {
    pub kind: u32,
    pub node_id: u32,
    pub size_bytes: u32,
    pub child_count: u32,
}

const KIND_MISS: u32 = u32::MAX;

fn err_to_status(e: FsError) -> u32 {
    match e {
        FsError::Invalid => STATUS_INVALID,
        FsError::NotFound => STATUS_NOT_FOUND,
        FsError::NotADir => STATUS_NOT_A_DIR,
        FsError::NotAFile => STATUS_NOT_A_FILE,
        FsError::NameTooLong => STATUS_NAME_TOO_LONG,
        FsError::NameExists => STATUS_NAME_EXISTS,
        FsError::DirNotEmpty => STATUS_DIR_NOT_EMPTY,
        FsError::NoSpaceData => STATUS_NO_SPACE_DATA,
        FsError::NoSpaceNodes => STATUS_NO_SPACE_NODES,
        FsError::Io => STATUS_IO,
        FsError::ReadOnly => STATUS_READ_ONLY,
        FsError::NoSpaceExtents => STATUS_NO_SPACE_EXTENTS,
        FsError::Corrupt => STATUS_CORRUPT,
        FsError::NotASymlink => STATUS_NOT_A_SYMLINK,
        FsError::XdevLink => STATUS_XDEV_LINK,
        FsError::SymlinkLoop => STATUS_SYMLINK_LOOP,
    }
}

fn ffi_range<T>(ptr: *const T, len: usize) -> Option<(usize, usize)> {
    if len == 0 {
        let address = ptr as usize;
        return Some((address, address));
    }
    if ptr.is_null() || !(ptr as usize).is_multiple_of(align_of::<T>()) {
        return None;
    }
    let bytes = len.checked_mul(size_of::<T>())?;
    if bytes > isize::MAX as usize {
        return None;
    }
    let start = ptr as usize;
    let end = start.checked_add(bytes)?;
    Some((start, end))
}

unsafe fn ffi_slice<T>(ptr: *const T, len: usize, _scope: &()) -> Option<&[T]> {
    if len == 0 {
        return Some(&[]);
    }
    ffi_range(ptr, len)?;
    // SAFETY: the FFI contract supplies readable storage. The gate
    // above rejects null, misaligned, overflowing, and over-isize
    // ranges before Rust constructs a slice, and the scope token
    // prevents the returned borrow from escaping this call.
    Some(unsafe { core::slice::from_raw_parts(ptr, len) })
}

unsafe fn ffi_inout_slice_mut<T>(ptr: *mut T, len: usize, _scope: &mut ()) -> Option<&mut [T]> {
    if len == 0 {
        return Some(&mut []);
    }
    ffi_range(ptr, len)?;
    // SAFETY: the FFI contract supplies initialized, exclusively
    // borrowed in/out storage. Numeric range and alignment checks
    // were completed above.
    Some(unsafe { core::slice::from_raw_parts_mut(ptr, len) })
}

unsafe fn ffi_output_bytes(ptr: *mut u8, len: usize, scope: &mut ()) -> Option<&mut [u8]> {
    if len == 0 {
        return Some(&mut []);
    }
    ffi_range(ptr, len)?;
    // SAFETY: the FFI contract supplies exclusive writable storage.
    // Raw zero-initialization makes every byte valid before the
    // initialized in/out helper constructs a Rust reference.
    unsafe { core::ptr::write_bytes(ptr, 0, len) };
    unsafe { ffi_inout_slice_mut(ptr, len, scope) }
}

fn ffi_ranges_overlap<L, R>(left: *const L, left_len: usize, right: *const R, right_len: usize) -> Option<bool> {
    let (left_start, left_end) = ffi_range(left, left_len)?;
    let (right_start, right_end) = ffi_range(right, right_len)?;
    if left_start == left_end || right_start == right_end {
        return Some(false);
    }
    Some(left_start < right_end && right_start < left_end)
}

fn ffi_optional_range<T>(ptr: *const T, len: usize) -> Option<(usize, usize)> {
    if ptr.is_null() {
        Some((0, 0))
    } else {
        ffi_range(ptr, len)
    }
}

fn ffi_optional_range_valid<T>(ptr: *const T, len: usize) -> bool {
    ffi_optional_range(ptr, len).is_some()
}

fn ffi_output_ranges_disjoint(ranges: &[Option<(usize, usize)>]) -> bool {
    for (index, left) in ranges.iter().enumerate() {
        let Some((left_start, left_end)) = left else {
            return false;
        };
        if left_start == left_end {
            continue;
        }
        for right in &ranges[index + 1..] {
            let Some((right_start, right_end)) = right else {
                return false;
            };
            if right_start != right_end && left_start < right_end && right_start < left_end {
                return false;
            }
        }
    }
    true
}

unsafe fn ffi_write_optional<T: Copy>(out: *mut T, value: T) -> bool {
    if out.is_null() {
        return true;
    }
    if ffi_range(out, 1).is_none() {
        return false;
    }
    // SAFETY: the caller supplies writable storage and the range gate
    // above verifies alignment and arithmetic before the write.
    unsafe { core::ptr::write(out, value) };
    true
}

// SAFETY: caller guarantees `desc` is valid + readable, that callback-
// reachable backing storage is stable and disjoint from all FFI ranges,
// and that every callback operates correctly on its cookie for the
// lifetime of this call. No retention across calls.
unsafe fn make_dev(desc: *const DuetFsDevice) -> Option<ExternBlockDevice> {
    ffi_range(desc, 1)?;
    let d = unsafe { &*desc };
    Some(ExternBlockDevice {
        cookie: d.cookie,
        block_count: d.block_count,
        ops: ExternBlockDeviceOps {
            read: d.read,
            write: d.write,
        },
        read_only: d.read_only != 0,
    })
}

unsafe fn cstr_to_slice(p: *const c_uchar, max: usize, _scope: &()) -> Option<&[u8]> {
    if max == 0 || max > FFI_PATH_CSTRING_MAX {
        return None;
    }
    let bytes = unsafe { ffi_slice(p, max, _scope) }?;
    let n = bytes.iter().position(|&b| b == 0).unwrap_or(max);
    Some(&bytes[..n])
}

/// # Safety
/// Raw pointer arguments must satisfy the C ABI contract in `include/duetfs.h`
/// for the duration of the call; DuetFS never retains them after returning.
#[no_mangle]
pub unsafe extern "C" fn duetfs_probe(desc: *const DuetFsDevice) -> c_uint {
    let Some(mut dev) = (unsafe { make_dev(desc) }) else {
        return 0;
    };
    Fs::open(&mut dev).is_ok() as c_uint
}

/// # Safety
/// Raw pointer arguments must satisfy the C ABI contract in `include/duetfs.h`
/// for the duration of the call; DuetFS never retains them after returning.
#[no_mangle]
pub unsafe extern "C" fn duetfs_mkfs(desc: *const DuetFsDevice) -> c_uint {
    let Some(mut dev) = (unsafe { make_dev(desc) }) else {
        return STATUS_INVALID;
    };
    match mkfs::format(&mut dev) {
        Ok(()) => STATUS_OK,
        Err(e) => err_to_status(e),
    }
}

/// # Safety
/// Raw pointer arguments must satisfy the C ABI contract in `include/duetfs.h`
/// for the duration of the call; DuetFS never retains them after returning.
#[no_mangle]
pub unsafe extern "C" fn duetfs_lookup(
    desc: *const DuetFsDevice,
    path: *const c_uchar,
    path_max: usize,
    out: *mut DuetFsLookupResult,
) -> c_uint {
    if !ffi_output_ranges_disjoint(&[ffi_range(desc, 1), ffi_optional_range(out, 1)])
        || (!out.is_null() && ffi_ranges_overlap(path, path_max, out, 1) != Some(false))
    {
        return STATUS_INVALID;
    }
    let miss = DuetFsLookupResult {
        kind: KIND_MISS,
        node_id: 0,
        size_bytes: 0,
        child_count: 0,
    };
    if !unsafe { ffi_write_optional(out, miss) } {
        return STATUS_INVALID;
    }
    let Some(mut dev) = (unsafe { make_dev(desc) }) else {
        return STATUS_INVALID;
    };
    let path_scope = ();
    let Some(path_bytes) = (unsafe { cstr_to_slice(path, path_max, &path_scope) }) else {
        return STATUS_INVALID;
    };
    let fs = match Fs::open(&mut dev) {
        Ok(f) => f,
        Err(e) => return err_to_status(e),
    };
    match fs.lookup_path(path_bytes) {
        Ok(r) => {
            let result = DuetFsLookupResult {
                kind: r.node.kind,
                node_id: r.node_id,
                size_bytes: r.node.size_bytes,
                child_count: r.node.child_count,
            };
            if !unsafe { ffi_write_optional(out, result) } {
                return STATUS_INVALID;
            }
            STATUS_OK
        }
        Err(e) => err_to_status(e),
    }
}

/// Like `duetfs_lookup` but follows the final component too.
/// POSIX-`stat`-style: a path landing on a symlink returns the
/// symlink's resolved target rather than the symlink node itself.
/// Returns `kStatusSymlinkLoop` on chains deeper than the
/// `MAX_SYMLINK_HOPS` floor (8 hops).
///
/// # Safety
/// Raw pointer arguments must satisfy the C ABI contract in `include/duetfs.h`
/// for the duration of the call; DuetFS never retains them after returning.
#[no_mangle]
pub unsafe extern "C" fn duetfs_lookup_follow(
    desc: *const DuetFsDevice,
    path: *const c_uchar,
    path_max: usize,
    out: *mut DuetFsLookupResult,
) -> c_uint {
    if !ffi_output_ranges_disjoint(&[ffi_range(desc, 1), ffi_optional_range(out, 1)])
        || (!out.is_null() && ffi_ranges_overlap(path, path_max, out, 1) != Some(false))
    {
        return STATUS_INVALID;
    }
    let miss = DuetFsLookupResult {
        kind: KIND_MISS,
        node_id: 0,
        size_bytes: 0,
        child_count: 0,
    };
    if !unsafe { ffi_write_optional(out, miss) } {
        return STATUS_INVALID;
    }
    let Some(mut dev) = (unsafe { make_dev(desc) }) else {
        return STATUS_INVALID;
    };
    let path_scope = ();
    let Some(path_bytes) = (unsafe { cstr_to_slice(path, path_max, &path_scope) }) else {
        return STATUS_INVALID;
    };
    let fs = match Fs::open(&mut dev) {
        Ok(f) => f,
        Err(e) => return err_to_status(e),
    };
    match fs.lookup_path_follow(path_bytes) {
        Ok(r) => {
            let result = DuetFsLookupResult {
                kind: r.node.kind,
                node_id: r.node_id,
                size_bytes: r.node.size_bytes,
                child_count: r.node.child_count,
            };
            if !unsafe { ffi_write_optional(out, result) } {
                return STATUS_INVALID;
            }
            STATUS_OK
        }
        Err(e) => err_to_status(e),
    }
}

/// # Safety
/// Raw pointer arguments must satisfy the C ABI contract in `include/duetfs.h`
/// for the duration of the call; DuetFS never retains them after returning.
#[no_mangle]
pub unsafe extern "C" fn duetfs_read_file(
    desc: *const DuetFsDevice,
    node_id: u32,
    offset: u32,
    dst: *mut c_void,
    dst_max: usize,
    out_copied: *mut usize,
) -> c_uint {
    if dst.is_null() || dst_max == 0 {
        return STATUS_INVALID;
    }
    let bounded_dst_max = core::cmp::min(dst_max, FFI_MAX_IO_BYTES);
    if !ffi_output_ranges_disjoint(&[
        ffi_range(desc, 1),
        ffi_range(dst as *const u8, bounded_dst_max),
        ffi_optional_range(out_copied, 1),
    ]) || !unsafe { ffi_write_optional(out_copied, 0) }
    {
        return STATUS_INVALID;
    }
    let Some(mut dev) = (unsafe { make_dev(desc) }) else {
        return STATUS_INVALID;
    };
    let fs = match Fs::open(&mut dev) {
        Ok(f) => f,
        Err(e) => return err_to_status(e),
    };
    let mut dst_scope = ();
    let Some(buf) = (unsafe { ffi_output_bytes(dst as *mut u8, bounded_dst_max, &mut dst_scope) }) else {
        return STATUS_INVALID;
    };
    match fs.read_at(node_id, offset, buf) {
        Ok(n) => {
            if !unsafe { ffi_write_optional(out_copied, n as usize) } {
                return STATUS_INVALID;
            }
            STATUS_OK
        }
        Err(e) => err_to_status(e),
    }
}

/// One directory child, surfaced to the C++ side by `duetfs_readdir`.
/// `name` is NUL-padded; `name_len` is the valid byte count.
#[repr(C)]
pub struct DuetFsDirEntry {
    pub node_id: u32,
    pub kind: u32,
    pub size_bytes: u32,
    pub name_len: u32,
    pub name: [u8; NAME_MAX],
}

/// Enumerate the children of directory `dir_node_id`, starting at
/// child slot `start_index`, filling up to `out_max` entries. Writes
/// the number produced to `*out_count` (0 once `start_index` reaches
/// `child_count`). The caller pages by advancing `start_index` by the
/// returned count until it gets 0. Child slots [0, child_count) are
/// dense — `dir_remove_child` swaps the tail down — so no UNUSED
/// filtering is needed here.
///
/// # Safety
/// Raw pointer arguments must satisfy the C ABI contract in `include/duetfs.h`
/// for the duration of the call; DuetFS never retains them after returning.
#[no_mangle]
pub unsafe extern "C" fn duetfs_readdir(
    desc: *const DuetFsDevice,
    dir_node_id: u32,
    start_index: u32,
    out: *mut DuetFsDirEntry,
    out_max: usize,
    out_count: *mut usize,
) -> c_uint {
    if out.is_null() || out_max == 0 {
        return STATUS_INVALID;
    }
    let bounded_out_max = core::cmp::min(out_max, BLOCK_SIZE / size_of::<u32>());
    if !ffi_output_ranges_disjoint(&[
        ffi_range(desc, 1),
        ffi_range(out, bounded_out_max),
        ffi_optional_range(out_count, 1),
    ]) || !unsafe { ffi_write_optional(out_count, 0) }
    {
        return STATUS_INVALID;
    }
    let Some(mut dev) = (unsafe { make_dev(desc) }) else {
        return STATUS_INVALID;
    };
    let fs = match Fs::open(&mut dev) {
        Ok(f) => f,
        Err(e) => return err_to_status(e),
    };
    let dir = match fs.read_node(dir_node_id) {
        Ok(n) => n,
        Err(e) => return err_to_status(e),
    };
    if dir.kind != NODE_KIND_DIR {
        return STATUS_NOT_A_DIR;
    }
    if start_index >= dir.child_count {
        return STATUS_OK; // past the end — count stays 0
    }
    let lba = match fs.dir_block(&dir) {
        Ok(l) => l,
        Err(e) => return err_to_status(e),
    };
    let mut block = [0u8; BLOCK_SIZE];
    if let Err(e) = fs.read_data_block(lba, &mut block) {
        return err_to_status(e);
    }
    let available = (dir.child_count - start_index) as usize;
    let produce = core::cmp::min(available, bounded_out_max);
    if ffi_range(out, produce).is_none() {
        return STATUS_INVALID;
    }
    let mut written = 0usize;
    for relative in 0..produce {
        let i = start_index + relative as u32;
        let off = (i as usize) * 4;
        let id = u32::from_le_bytes([block[off], block[off + 1], block[off + 2], block[off + 3]]);
        let child = match fs.read_node(id) {
            Ok(n) => n,
            Err(e) => return err_to_status(e),
        };
        let nb = child.name_bytes();
        let mut name = [0u8; NAME_MAX];
        name[..nb.len()].copy_from_slice(nb);
        let entry = DuetFsDirEntry {
            node_id: id,
            kind: child.kind,
            size_bytes: child.size_bytes,
            name_len: nb.len() as u32,
            name,
        };
        // SAFETY: the complete output range was validated above and
        // `written < produce`; raw construction permits C callers to
        // provide uninitialized DirEntry storage.
        unsafe { core::ptr::write(out.add(written), entry) };
        written += 1;
    }
    if !unsafe { ffi_write_optional(out_count, written) } {
        return STATUS_INVALID;
    }
    STATUS_OK
}

/// # Safety
/// Raw pointer arguments must satisfy the C ABI contract in `include/duetfs.h`
/// for the duration of the call; DuetFS never retains them after returning.
#[no_mangle]
pub unsafe extern "C" fn duetfs_write_at(
    desc: *const DuetFsDevice,
    node_id: u32,
    offset: u32,
    src: *const c_void,
    src_max: usize,
    out_written: *mut usize,
) -> c_uint {
    let Some(write_end) = (offset as usize).checked_add(src_max) else {
        return STATUS_INVALID;
    };
    if (src.is_null() && src_max != 0) || src_max > FFI_MAX_IO_BYTES || write_end > FFI_MAX_IO_BYTES {
        return STATUS_INVALID;
    }
    if !ffi_output_ranges_disjoint(&[ffi_range(desc, 1), ffi_optional_range(out_written, 1)])
        || (!out_written.is_null() && ffi_ranges_overlap(src as *const u8, src_max, out_written, 1) != Some(false))
        || !unsafe { ffi_write_optional(out_written, 0) }
    {
        return STATUS_INVALID;
    }
    let Some(mut dev) = (unsafe { make_dev(desc) }) else {
        return STATUS_INVALID;
    };
    let mut fs = match Fs::open(&mut dev) {
        Ok(f) => f,
        Err(e) => return err_to_status(e),
    };
    let src_scope = ();
    let Some(buf) = (unsafe { ffi_slice(src as *const u8, src_max, &src_scope) }) else {
        return STATUS_INVALID;
    };
    match fs.write_at(node_id, offset, buf) {
        Ok(n) => {
            if !unsafe { ffi_write_optional(out_written, n as usize) } {
                return STATUS_INVALID;
            }
            STATUS_OK
        }
        Err(e) => err_to_status(e),
    }
}

/// # Safety
/// Raw pointer arguments must satisfy the C ABI contract in `include/duetfs.h`
/// for the duration of the call; DuetFS never retains them after returning.
#[no_mangle]
pub unsafe extern "C" fn duetfs_create_path(
    desc: *const DuetFsDevice,
    path: *const c_uchar,
    path_max: usize,
    kind: u32,
    out_node_id: *mut u32,
) -> c_uint {
    if !ffi_output_ranges_disjoint(&[ffi_range(desc, 1), ffi_optional_range(out_node_id, 1)])
        || (!out_node_id.is_null() && ffi_ranges_overlap(path, path_max, out_node_id, 1) != Some(false))
    {
        return STATUS_INVALID;
    }
    if !unsafe { ffi_write_optional(out_node_id, 0) } {
        return STATUS_INVALID;
    }
    if kind != NODE_KIND_FILE && kind != NODE_KIND_DIR {
        return STATUS_INVALID;
    }
    let Some(mut dev) = (unsafe { make_dev(desc) }) else {
        return STATUS_INVALID;
    };
    let path_scope = ();
    let Some(path_bytes) = (unsafe { cstr_to_slice(path, path_max, &path_scope) }) else {
        return STATUS_INVALID;
    };
    let Some((parent_path, name)) = split_parent_and_name(path_bytes) else {
        return STATUS_INVALID;
    };
    let mut fs = match Fs::open(&mut dev) {
        Ok(f) => f,
        Err(e) => return err_to_status(e),
    };
    let parent = match fs.lookup_path(parent_path) {
        Ok(r) => r,
        Err(e) => return err_to_status(e),
    };
    let res = if kind == NODE_KIND_FILE {
        fs.create_file(parent.node_id, name)
    } else {
        fs.create_dir(parent.node_id, name)
    };
    match res {
        Ok(id) => {
            if !unsafe { ffi_write_optional(out_node_id, id) } {
                return STATUS_INVALID;
            }
            STATUS_OK
        }
        Err(e) => err_to_status(e),
    }
}

/// # Safety
/// Raw pointer arguments must satisfy the C ABI contract in `include/duetfs.h`
/// for the duration of the call; DuetFS never retains them after returning.
#[no_mangle]
pub unsafe extern "C" fn duetfs_unlink_path(
    desc: *const DuetFsDevice,
    path: *const c_uchar,
    path_max: usize,
) -> c_uint {
    let Some(mut dev) = (unsafe { make_dev(desc) }) else {
        return STATUS_INVALID;
    };
    let path_scope = ();
    let Some(path_bytes) = (unsafe { cstr_to_slice(path, path_max, &path_scope) }) else {
        return STATUS_INVALID;
    };
    let Some((parent_path, name)) = split_parent_and_name(path_bytes) else {
        return STATUS_INVALID;
    };
    let mut fs = match Fs::open(&mut dev) {
        Ok(f) => f,
        Err(e) => return err_to_status(e),
    };
    let parent = match fs.lookup_path(parent_path) {
        Ok(r) => r,
        Err(e) => return err_to_status(e),
    };
    match fs.unlink(parent.node_id, name) {
        Ok(()) => STATUS_OK,
        Err(e) => err_to_status(e),
    }
}

/// # Safety
/// Raw pointer arguments must satisfy the C ABI contract in `include/duetfs.h`
/// for the duration of the call; DuetFS never retains them after returning.
#[no_mangle]
pub unsafe extern "C" fn duetfs_truncate(desc: *const DuetFsDevice, node_id: u32, new_size: u32) -> c_uint {
    let Some(mut dev) = (unsafe { make_dev(desc) }) else {
        return STATUS_INVALID;
    };
    let mut fs = match Fs::open(&mut dev) {
        Ok(f) => f,
        Err(e) => return err_to_status(e),
    };
    match fs.truncate(node_id, new_size) {
        Ok(()) => STATUS_OK,
        Err(e) => err_to_status(e),
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetFsFsckReport {
    pub leaked_blocks: u32,
    pub missing_blocks: u32,
    pub orphan_nodes: u32,
    pub bad_extents: u32,
    pub repaired: u32,
    pub sb_crc_mismatch: u32,
    pub block_crc_mismatch: u32,
    pub link_count_mismatch: u32,
}

const _: () = {
    assert!(size_of::<DuetFsDevice>() == 32);
    assert!(align_of::<DuetFsDevice>() == 8);
    assert!(size_of::<DuetFsLookupResult>() == 16);
    assert!(align_of::<DuetFsLookupResult>() == 4);
    assert!(size_of::<DuetFsDirEntry>() == 80);
    assert!(align_of::<DuetFsDirEntry>() == 4);
    assert!(size_of::<DuetFsFsckReport>() == 32);
    assert!(align_of::<DuetFsFsckReport>() == 4);
};

/// # Safety
/// Raw pointer arguments must satisfy the C ABI contract in `include/duetfs.h`
/// for the duration of the call; DuetFS never retains them after returning.
#[no_mangle]
pub unsafe extern "C" fn duetfs_fsck(desc: *const DuetFsDevice, repair: u32, out: *mut DuetFsFsckReport) -> c_uint {
    if !ffi_output_ranges_disjoint(&[ffi_range(desc, 1), ffi_optional_range(out, 1)])
        || !unsafe { ffi_write_optional(out, DuetFsFsckReport::default()) }
    {
        return STATUS_INVALID;
    }
    let Some(mut dev) = (unsafe { make_dev(desc) }) else {
        return STATUS_INVALID;
    };
    let mut fs = match Fs::open(&mut dev) {
        Ok(f) => f,
        Err(e) => return err_to_status(e),
    };
    match fs.fsck(repair != 0) {
        Ok(r) => {
            let report = DuetFsFsckReport {
                leaked_blocks: r.leaked_blocks,
                missing_blocks: r.missing_blocks,
                orphan_nodes: r.orphan_nodes,
                bad_extents: r.bad_extents,
                repaired: r.repaired,
                sb_crc_mismatch: r.sb_crc_mismatch,
                block_crc_mismatch: r.block_crc_mismatch,
                link_count_mismatch: r.link_count_mismatch,
            };
            if !unsafe { ffi_write_optional(out, report) } {
                return STATUS_INVALID;
            }
            STATUS_OK
        }
        Err(e) => err_to_status(e),
    }
}

/// Create a symbolic link at `path` pointing at `target`. Both
/// strings are NUL-terminated kernel buffers.
/// # Safety
/// Raw pointer arguments must satisfy the C ABI contract in `include/duetfs.h`
/// for the duration of the call; DuetFS never retains them after returning.
#[no_mangle]
pub unsafe extern "C" fn duetfs_create_symlink(
    desc: *const DuetFsDevice,
    path: *const c_uchar,
    path_max: usize,
    target: *const c_uchar,
    target_max: usize,
    out_node_id: *mut u32,
) -> c_uint {
    if !ffi_output_ranges_disjoint(&[ffi_range(desc, 1), ffi_optional_range(out_node_id, 1)])
        || (!out_node_id.is_null()
            && (ffi_ranges_overlap(path, path_max, out_node_id, 1) != Some(false)
                || ffi_ranges_overlap(target, target_max, out_node_id, 1) != Some(false)))
    {
        return STATUS_INVALID;
    }
    if !unsafe { ffi_write_optional(out_node_id, 0) } {
        return STATUS_INVALID;
    }
    let Some(mut dev) = (unsafe { make_dev(desc) }) else {
        return STATUS_INVALID;
    };
    let path_scope = ();
    let Some(path_bytes) = (unsafe { cstr_to_slice(path, path_max, &path_scope) }) else {
        return STATUS_INVALID;
    };
    let target_scope = ();
    let Some(target_bytes) = (unsafe { cstr_to_slice(target, target_max, &target_scope) }) else {
        return STATUS_INVALID;
    };
    let Some((parent_path, name)) = split_parent_and_name(path_bytes) else {
        return STATUS_INVALID;
    };
    let mut fs = match Fs::open(&mut dev) {
        Ok(f) => f,
        Err(e) => return err_to_status(e),
    };
    let parent = match fs.lookup_path(parent_path) {
        Ok(r) => r,
        Err(e) => return err_to_status(e),
    };
    match fs.create_symlink(parent.node_id, name, target_bytes) {
        Ok(id) => {
            if !unsafe { ffi_write_optional(out_node_id, id) } {
                return STATUS_INVALID;
            }
            STATUS_OK
        }
        Err(e) => err_to_status(e),
    }
}

/// Read a symlink's target into `dst`. Returns kStatusOk + bytes
/// copied via `*out_copied`. Same shape as duetfs_read_file but
/// requires the node to be a symlink.
/// # Safety
/// Raw pointer arguments must satisfy the C ABI contract in `include/duetfs.h`
/// for the duration of the call; DuetFS never retains them after returning.
#[no_mangle]
pub unsafe extern "C" fn duetfs_readlink(
    desc: *const DuetFsDevice,
    node_id: u32,
    dst: *mut c_void,
    dst_max: usize,
    out_copied: *mut usize,
) -> c_uint {
    if dst.is_null() || dst_max == 0 {
        return STATUS_INVALID;
    }
    let bounded_dst_max = core::cmp::min(dst_max, SYMLINK_TARGET_MAX as usize);
    if !ffi_output_ranges_disjoint(&[
        ffi_range(desc, 1),
        ffi_range(dst as *const u8, bounded_dst_max),
        ffi_optional_range(out_copied, 1),
    ]) || !unsafe { ffi_write_optional(out_copied, 0) }
    {
        return STATUS_INVALID;
    }
    let Some(mut dev) = (unsafe { make_dev(desc) }) else {
        return STATUS_INVALID;
    };
    let fs = match Fs::open(&mut dev) {
        Ok(f) => f,
        Err(e) => return err_to_status(e),
    };
    let mut dst_scope = ();
    let Some(buf) = (unsafe { ffi_output_bytes(dst as *mut u8, bounded_dst_max, &mut dst_scope) }) else {
        return STATUS_INVALID;
    };
    match fs.readlink(node_id, buf) {
        Ok(n) => {
            if !unsafe { ffi_write_optional(out_copied, n as usize) } {
                return STATUS_INVALID;
            }
            STATUS_OK
        }
        Err(e) => err_to_status(e),
    }
}

/// Create a hard link at `new_path` pointing at the same inode as
/// `existing_path`. v3 caveat: the new dirent shares the target's
/// existing name; passing a `new_path` whose last component
/// differs from the target's name returns STATUS_INVALID until a
/// future slice introduces a separate dirent table.
/// # Safety
/// Raw pointer arguments must satisfy the C ABI contract in `include/duetfs.h`
/// for the duration of the call; DuetFS never retains them after returning.
#[no_mangle]
pub unsafe extern "C" fn duetfs_link(
    desc: *const DuetFsDevice,
    existing_path: *const c_uchar,
    existing_max: usize,
    new_path: *const c_uchar,
    new_max: usize,
) -> c_uint {
    let Some(mut dev) = (unsafe { make_dev(desc) }) else {
        return STATUS_INVALID;
    };
    let existing_path_scope = ();
    let Some(existing_bytes) = (unsafe { cstr_to_slice(existing_path, existing_max, &existing_path_scope) }) else {
        return STATUS_INVALID;
    };
    let new_path_scope = ();
    let Some(new_bytes) = (unsafe { cstr_to_slice(new_path, new_max, &new_path_scope) }) else {
        return STATUS_INVALID;
    };
    let Some((parent_path, name)) = split_parent_and_name(new_bytes) else {
        return STATUS_INVALID;
    };
    let mut fs = match Fs::open(&mut dev) {
        Ok(f) => f,
        Err(e) => return err_to_status(e),
    };
    let target = match fs.lookup_path(existing_bytes) {
        Ok(r) => r,
        Err(e) => return err_to_status(e),
    };
    let parent = match fs.lookup_path(parent_path) {
        Ok(r) => r,
        Err(e) => return err_to_status(e),
    };
    match fs.link(target.node_id, parent.node_id, name) {
        Ok(()) => STATUS_OK,
        Err(e) => err_to_status(e),
    }
}

// Constants kept linked so the header's enums stay greppable.
#[no_mangle]
pub static DUETFS_KIND_UNUSED: u32 = NODE_KIND_UNUSED;
#[no_mangle]
pub static DUETFS_KIND_FILE: u32 = NODE_KIND_FILE;
#[no_mangle]
pub static DUETFS_KIND_DIR: u32 = NODE_KIND_DIR;
#[no_mangle]
pub static DUETFS_ROOT_NODE_ID: u32 = ROOT_NODE_ID;

// ----------------------------------------------------------------
// Journal FFI — diagnostic + self-test helpers.
// ----------------------------------------------------------------

/// Read a raw block at `lba` into `dst`. Bypasses the FS — useful
/// for the journal self-test which inspects on-disk state directly.
/// Returns kStatusOk on success.
/// # Safety
/// Raw pointer arguments must satisfy the C ABI contract in `include/duetfs.h`
/// for the duration of the call; DuetFS never retains them after returning.
#[no_mangle]
pub unsafe extern "C" fn duetfs_block_read(desc: *const DuetFsDevice, lba: u32, dst: *mut u8) -> c_uint {
    if !ffi_output_ranges_disjoint(&[ffi_range(desc, 1), ffi_range(dst, BLOCK_SIZE)]) {
        return STATUS_INVALID;
    }
    let Some(dev) = (unsafe { make_dev(desc) }) else {
        return STATUS_INVALID;
    };
    if lba >= dev.block_count() {
        return STATUS_INVALID;
    }
    let mut dst_scope = ();
    let Some(buf) = (unsafe { ffi_output_bytes(dst, BLOCK_SIZE, &mut dst_scope) }) else {
        return STATUS_INVALID;
    };
    match dev.read_block(lba, buf) {
        Ok(()) => STATUS_OK,
        Err(_) => STATUS_IO,
    }
}

/// Apply a single (target_lba, payload) write through the journal.
/// Atomic against torn writes — either the new payload reaches the
/// target or the FS is left exactly as it was. `payload` MUST point
/// at a kernel-space buffer of at least kBlockSize bytes.
/// # Safety
/// Raw pointer arguments must satisfy the C ABI contract in `include/duetfs.h`
/// for the duration of the call; DuetFS never retains them after returning.
#[no_mangle]
pub unsafe extern "C" fn duetfs_journal_apply(
    desc: *const DuetFsDevice,
    target_lba: u32,
    payload: *const u8,
) -> c_uint {
    let Some(mut dev) = (unsafe { make_dev(desc) }) else {
        return STATUS_INVALID;
    };
    let payload_scope = ();
    let Some(buf) = (unsafe { ffi_slice(payload, BLOCK_SIZE, &payload_scope) }) else {
        return STATUS_INVALID;
    };
    // txn_id of 1 is fine for the standalone helper — Fs::open's
    // replay path doesn't depend on monotonicity (it only reads the
    // descriptor's `state`).
    match journal::apply(&mut dev, JOURNAL_LBA, 1, &[(target_lba, buf)]) {
        Ok(()) => STATUS_OK,
        Err(e) => err_to_status(e),
    }
}

/// Test-only: stage a single (target_lba, payload) write through
/// the journal AND mark it COMMITTED, but skip the apply step.
/// Simulates a torn write between "journal fsync'd" and "apply
/// finished" — the next call to a function that opens the FS
/// (probe / lookup / mkfs aren't probe-only — only FFIs that go
/// through Fs::open) will replay it. Used exclusively by the boot
/// self-test in kernel/fs/duetfs.cpp.
/// # Safety
/// Raw pointer arguments must satisfy the C ABI contract in `include/duetfs.h`
/// for the duration of the call; DuetFS never retains them after returning.
#[no_mangle]
pub unsafe extern "C" fn duetfs_journal_inject_for_test(
    desc: *const DuetFsDevice,
    target_lba: u32,
    payload: *const u8,
) -> c_uint {
    let Some(mut dev) = (unsafe { make_dev(desc) }) else {
        return STATUS_INVALID;
    };
    let payload_scope = ();
    let Some(buf) = (unsafe { ffi_slice(payload, BLOCK_SIZE, &payload_scope) }) else {
        return STATUS_INVALID;
    };
    match journal::inject_committed_for_test(&mut dev, JOURNAL_LBA, 1, &[(target_lba, buf)]) {
        Ok(()) => STATUS_OK,
        Err(e) => err_to_status(e),
    }
}

/// Read the journal descriptor's `state` field. 0 = empty, 1 =
/// committed (replay pending). Other values reflect a corrupt
/// descriptor and are reported verbatim. Diagnostic — never fails
/// the FS-open path (Fs::open replays first), so a clean mount
/// always reports state == 0.
/// # Safety
/// Raw pointer arguments must satisfy the C ABI contract in `include/duetfs.h`
/// for the duration of the call; DuetFS never retains them after returning.
#[no_mangle]
pub unsafe extern "C" fn duetfs_journal_state(desc: *const DuetFsDevice) -> c_uint {
    let Some(mut dev) = (unsafe { make_dev(desc) }) else {
        return c_uint::MAX;
    };
    match journal::peek_descriptor(&mut dev, JOURNAL_LBA) {
        Ok(d) => d.state,
        Err(_) => c_uint::MAX,
    }
}

// ----------------------------------------------------------------
// Crypto FFI — v6. AES-256-XTS block primitives + Argon2id KDF.
// Designed so the kernel C++ side composes them into an
// "encrypted Device" wrapper: it holds the derived 64-byte key in
// kernel memory, intercepts every read/write callback, and calls
// duetfs_xts_encrypt_block / duetfs_xts_decrypt_block on the
// payload before forwarding to the underlying storage.
// ----------------------------------------------------------------

/// Argon2id KDF. Derives a 64-byte XTS key from a password + salt
/// and (m_cost_kib, t_cost, p_cost). Returns kStatusOk on success
/// or kStatusInvalid for parameter / null-pointer / output-size
/// problems.
///
/// `out_key` MUST point at a 64-byte buffer. The first 32 bytes
/// become the AES-256-XTS data-cipher key; the remaining 32 bytes
/// the tweak-cipher key. Both are randomly distinguishable from
/// each other by the KDF — Argon2id's output stream is uniform.
/// # Safety
/// Raw pointer arguments must satisfy the C ABI contract in `include/duetfs.h`
/// for the duration of the call; DuetFS never retains them after returning.
#[no_mangle]
pub unsafe extern "C" fn duetfs_kdf_argon2id(
    password: *const u8,
    password_len: usize,
    salt: *const u8,
    salt_len: usize,
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
    out_key: *mut u8,
) -> c_uint {
    if password_len == 0
        || password_len > crypto::ARGON2_MAX_PASSWORD_BYTES
        || salt_len == 0
        || salt_len > crypto::ARGON2_MAX_SALT_BYTES
        || !crypto::argon2id_params_valid(m_cost_kib, t_cost, p_cost)
    {
        return STATUS_INVALID;
    }
    let Some(password_overlap) = ffi_ranges_overlap(password, password_len, out_key, crypto::XTS_KEY_BYTES) else {
        return STATUS_INVALID;
    };
    let Some(salt_overlap) = ffi_ranges_overlap(salt, salt_len, out_key, crypto::XTS_KEY_BYTES) else {
        return STATUS_INVALID;
    };
    if password_overlap || salt_overlap {
        return STATUS_INVALID;
    }
    let password_scope = ();
    let Some(pw) = (unsafe { ffi_slice(password, password_len, &password_scope) }) else {
        return STATUS_INVALID;
    };
    let salt_scope = ();
    let Some(s) = (unsafe { ffi_slice(salt, salt_len, &salt_scope) }) else {
        return STATUS_INVALID;
    };
    let mut key = [0u8; crypto::XTS_KEY_BYTES];
    if !crypto::argon2id_kdf(pw, s, m_cost_kib, t_cost, p_cost, &mut key) {
        return STATUS_INVALID;
    }
    let mut output_scope = ();
    let Some(dst) = (unsafe { ffi_output_bytes(out_key, crypto::XTS_KEY_BYTES, &mut output_scope) }) else {
        return STATUS_INVALID;
    };
    dst.copy_from_slice(&key);
    STATUS_OK
}

/// Encrypt a 4096-byte block in place using AES-256-XTS. `key`
/// points at a 64-byte key (data || tweak). `sector` is the LBA —
/// the XTS tweak is derived from it so the same plaintext at
/// different LBAs produces different ciphertext.
/// # Safety
/// Raw pointer arguments must satisfy the C ABI contract in `include/duetfs.h`
/// for the duration of the call; DuetFS never retains them after returning.
#[no_mangle]
pub unsafe extern "C" fn duetfs_xts_encrypt_block(key: *const u8, sector: u64, buf: *mut u8) -> c_uint {
    let Some(overlap) = ffi_ranges_overlap(key, crypto::XTS_KEY_BYTES, buf, crypto::SECTOR_BYTES) else {
        return STATUS_INVALID;
    };
    if overlap {
        return STATUS_INVALID;
    }
    let mut k = [0u8; crypto::XTS_KEY_BYTES];
    let key_scope = ();
    let Some(raw_key) = (unsafe { ffi_slice(key, crypto::XTS_KEY_BYTES, &key_scope) }) else {
        return STATUS_INVALID;
    };
    k.copy_from_slice(raw_key);
    let mut payload_scope = ();
    let Some(payload) = (unsafe { ffi_inout_slice_mut(buf, crypto::SECTOR_BYTES, &mut payload_scope) }) else {
        return STATUS_INVALID;
    };
    crypto::xts_encrypt_in_place(&k, sector, payload);
    STATUS_OK
}

/// Decrypt a 4096-byte block in place. Inverse of
/// `duetfs_xts_encrypt_block`.
/// # Safety
/// Raw pointer arguments must satisfy the C ABI contract in `include/duetfs.h`
/// for the duration of the call; DuetFS never retains them after returning.
#[no_mangle]
pub unsafe extern "C" fn duetfs_xts_decrypt_block(key: *const u8, sector: u64, buf: *mut u8) -> c_uint {
    let Some(overlap) = ffi_ranges_overlap(key, crypto::XTS_KEY_BYTES, buf, crypto::SECTOR_BYTES) else {
        return STATUS_INVALID;
    };
    if overlap {
        return STATUS_INVALID;
    }
    let mut k = [0u8; crypto::XTS_KEY_BYTES];
    let key_scope = ();
    let Some(raw_key) = (unsafe { ffi_slice(key, crypto::XTS_KEY_BYTES, &key_scope) }) else {
        return STATUS_INVALID;
    };
    k.copy_from_slice(raw_key);
    let mut payload_scope = ();
    let Some(payload) = (unsafe { ffi_inout_slice_mut(buf, crypto::SECTOR_BYTES, &mut payload_scope) }) else {
        return STATUS_INVALID;
    };
    crypto::xts_decrypt_in_place(&k, sector, payload);
    STATUS_OK
}

/// Format an encrypted volume. `dev` MUST already wrap the underlying
/// storage in the C++ AES-XTS encrypt/decrypt callbacks (the kernel
/// builds that wrapper after deriving the key with
/// duetfs_kdf_argon2id). `salt` (16 bytes) and the (m_cost_kib,
/// t_cost, p_cost) triple get persisted in the SB so a future
/// mounter can re-derive the key from the same password.
/// # Safety
/// Raw pointer arguments must satisfy the C ABI contract in `include/duetfs.h`
/// for the duration of the call; DuetFS never retains them after returning.
#[no_mangle]
pub unsafe extern "C" fn duetfs_mkfs_encrypted(
    desc: *const DuetFsDevice,
    salt: *const u8,
    salt_len: usize,
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> c_uint {
    if salt_len != SALT_BYTES || !crypto::argon2id_params_valid(m_cost_kib, t_cost, p_cost) {
        return STATUS_INVALID;
    }
    let Some(mut dev) = (unsafe { make_dev(desc) }) else {
        return STATUS_INVALID;
    };
    let mut salt_arr = [0u8; SALT_BYTES];
    let salt_scope = ();
    let Some(raw) = (unsafe { ffi_slice(salt, SALT_BYTES, &salt_scope) }) else {
        return STATUS_INVALID;
    };
    salt_arr.copy_from_slice(raw);
    match mkfs::format_encrypted(&mut dev, &salt_arr, m_cost_kib, t_cost, p_cost) {
        Ok(()) => STATUS_OK,
        Err(e) => err_to_status(e),
    }
}

// ----------------------------------------------------------------
// LZ4 compression FFI — v7. Block-format primitives that operate on
// kernel-staged buffers. The on-disk shape is the standard
// "size-prefixed LZ4 frame" — a u32-le uncompressed-length header
// followed by the LZ4 bytes — so external tooling decompresses the
// raw payload as-is.
// ----------------------------------------------------------------

/// Compress `src_len` bytes from `src` into `dst`. The output is a
/// size-prefixed LZ4 frame (u32-le uncompressed length header +
/// LZ4 bytes). On success writes the byte count to `*out_len` and
/// returns kStatusOk; on dst-too-small returns kStatusInvalid (caller
/// queried the worst-case bound from `duetfs_lz4_compress_bound`).
/// # Safety
/// Raw pointer arguments must satisfy the C ABI contract in `include/duetfs.h`
/// for the duration of the call; DuetFS never retains them after returning.
#[no_mangle]
pub unsafe extern "C" fn duetfs_lz4_compress(
    src: *const u8,
    src_len: usize,
    dst: *mut u8,
    dst_max: usize,
    out_len: *mut usize,
) -> c_uint {
    if !ffi_optional_range_valid(out_len, 1) {
        return STATUS_INVALID;
    }
    let dst_extent = core::cmp::min(dst_max, compress::compress_bound(src_len));
    if !out_len.is_null()
        && (ffi_ranges_overlap(src, src_len, out_len as *const u8, size_of::<usize>()) != Some(false)
            || ffi_ranges_overlap(dst, dst_extent, out_len as *const u8, size_of::<usize>()) != Some(false))
    {
        return STATUS_INVALID;
    }
    if !unsafe { ffi_write_optional(out_len, 0) } {
        return STATUS_INVALID;
    }
    let Some(overlap) = ffi_ranges_overlap(src, src_len, dst, dst_extent) else {
        return STATUS_INVALID;
    };
    if overlap || src_len == 0 || src_len > compress::MAX_INPUT_BYTES {
        return STATUS_INVALID;
    }
    let source_scope = ();
    let Some(s) = (unsafe { ffi_slice(src, src_len, &source_scope) }) else {
        return STATUS_INVALID;
    };
    let mut destination_scope = ();
    let Some(d) = (unsafe { ffi_output_bytes(dst, dst_extent, &mut destination_scope) }) else {
        return STATUS_INVALID;
    };
    let n = compress::compress_prepend_size(s, d);
    if n == 0 && src_len != 0 {
        return STATUS_INVALID;
    }
    if !unsafe { ffi_write_optional(out_len, n) } {
        return STATUS_INVALID;
    }
    STATUS_OK
}

/// Decompress a size-prefixed LZ4 frame from `src` into `dst`. On
/// success writes the byte count to `*out_len` and returns
/// kStatusOk; on any error (truncated input, bad header, dst short)
/// returns kStatusInvalid.
/// # Safety
/// Raw pointer arguments must satisfy the C ABI contract in `include/duetfs.h`
/// for the duration of the call; DuetFS never retains them after returning.
#[no_mangle]
pub unsafe extern "C" fn duetfs_lz4_decompress(
    src: *const u8,
    src_len: usize,
    dst: *mut u8,
    dst_max: usize,
    out_len: *mut usize,
) -> c_uint {
    if !ffi_optional_range_valid(out_len, 1) {
        return STATUS_INVALID;
    }
    let max_frame_bytes = compress::compress_bound(compress::MAX_INPUT_BYTES);
    if src_len < 4 || src_len > max_frame_bytes {
        return STATUS_INVALID;
    }
    let bounded_dst_extent = core::cmp::min(dst_max, compress::MAX_INPUT_BYTES);
    if !out_len.is_null()
        && (ffi_ranges_overlap(src, src_len, out_len as *const u8, size_of::<usize>()) != Some(false)
            || ffi_ranges_overlap(dst, bounded_dst_extent, out_len as *const u8, size_of::<usize>()) != Some(false))
    {
        return STATUS_INVALID;
    }
    if !unsafe { ffi_write_optional(out_len, 0) } {
        return STATUS_INVALID;
    }
    let source_scope = ();
    let Some(s) = (unsafe { ffi_slice(src, src_len, &source_scope) }) else {
        return STATUS_INVALID;
    };
    let expected = u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as usize;
    if expected == 0 || expected > compress::MAX_INPUT_BYTES || expected > dst_max {
        return STATUS_INVALID;
    }
    let Some(overlap) = ffi_ranges_overlap(src, src_len, dst, expected) else {
        return STATUS_INVALID;
    };
    if overlap {
        return STATUS_INVALID;
    }
    let mut destination_scope = ();
    let Some(d) = (unsafe { ffi_output_bytes(dst, expected, &mut destination_scope) }) else {
        return STATUS_INVALID;
    };
    let n = compress::decompress_size_prepended(s, d);
    if n == 0 {
        return STATUS_INVALID;
    }
    if !unsafe { ffi_write_optional(out_len, n) } {
        return STATUS_INVALID;
    }
    STATUS_OK
}

/// Worst-case output size for `duetfs_lz4_compress` on an input of
/// `n` bytes — caller sizes the dst buffer to this. Includes the
/// 4-byte size header. Cheap (no I/O).
/// # Safety
/// Raw pointer arguments must satisfy the C ABI contract in `include/duetfs.h`
/// for the duration of the call; DuetFS never retains them after returning.
#[no_mangle]
pub unsafe extern "C" fn duetfs_lz4_compress_bound(n: usize) -> usize {
    compress::compress_bound(n)
}

// ----------------------------------------------------------------
// Snapshot FFI — v7. Single-slot save / restore + CoW pinning. The
// pinning is applied transparently inside Fs::alloc_run; FFI only
// surfaces create / restore / status to the C++ side.
// ----------------------------------------------------------------

/// Take a snapshot of the live FS metadata. Persists SB + bitmap +
/// CRC table + node table into the snapshot slot. After this call
/// every block the live allocator considers in-use is pinned —
/// alloc_run treats it as unavailable until snapshot_restore.
///
/// `ts_ns` is opaque to the FS — typically the kernel monotonic
/// clock at snapshot time. Stored verbatim in the SB so the C++
/// side can render "snapshot taken N seconds ago".
/// # Safety
/// Raw pointer arguments must satisfy the C ABI contract in `include/duetfs.h`
/// for the duration of the call; DuetFS never retains them after returning.
#[no_mangle]
pub unsafe extern "C" fn duetfs_snapshot_create(desc: *const DuetFsDevice, ts_ns: u64) -> c_uint {
    let Some(mut dev) = (unsafe { make_dev(desc) }) else {
        return STATUS_INVALID;
    };
    match snapshot::create(&mut dev, ts_ns) {
        Ok(()) => STATUS_OK,
        Err(e) => err_to_status(e),
    }
}

/// Restore the snapshot slot back to the live metadata. The FS
/// returns to exactly the state captured by the most recent
/// `duetfs_snapshot_create`. Idempotent — restoring an already-
/// restored snapshot is a no-op re-apply.
/// # Safety
/// Raw pointer arguments must satisfy the C ABI contract in `include/duetfs.h`
/// for the duration of the call; DuetFS never retains them after returning.
#[no_mangle]
pub unsafe extern "C" fn duetfs_snapshot_restore(desc: *const DuetFsDevice) -> c_uint {
    let Some(mut dev) = (unsafe { make_dev(desc) }) else {
        return STATUS_INVALID;
    };
    match snapshot::restore(&mut dev) {
        Ok(()) => STATUS_OK,
        Err(e) => err_to_status(e),
    }
}

// ----------------------------------------------------------------
// xattr FFI — v8. Per-node extended attributes. Path-addressed; the
// kernel C++ side sees the same FFI shape as setxattr(2) / getxattr
// / listxattr / removexattr.
// ----------------------------------------------------------------

/// Set / replace `name`'s value on the node at `path`. Allocates
/// the per-node xattr block on first set; rewrites in place after.
/// # Safety
/// Raw pointer arguments must satisfy the C ABI contract in `include/duetfs.h`
/// for the duration of the call; DuetFS never retains them after returning.
#[no_mangle]
pub unsafe extern "C" fn duetfs_xattr_set(
    desc: *const DuetFsDevice,
    path: *const c_uchar,
    path_max: usize,
    name: *const c_uchar,
    name_len: usize,
    value: *const u8,
    value_len: usize,
) -> c_uint {
    if name_len == 0 || name_len > XATTR_NAME_MAX || value_len > XATTR_VALUE_MAX {
        return STATUS_INVALID;
    }
    if value.is_null() && value_len != 0 {
        return STATUS_INVALID;
    }
    let Some(mut dev) = (unsafe { make_dev(desc) }) else {
        return STATUS_INVALID;
    };
    let path_scope = ();
    let Some(path_bytes) = (unsafe { cstr_to_slice(path, path_max, &path_scope) }) else {
        return STATUS_INVALID;
    };
    let mut fs = match Fs::open(&mut dev) {
        Ok(f) => f,
        Err(e) => return err_to_status(e),
    };
    let target = match fs.lookup_path(path_bytes) {
        Ok(r) => r,
        Err(e) => return err_to_status(e),
    };
    let name_scope = ();
    let Some(name_bytes) = (unsafe { ffi_slice(name, name_len, &name_scope) }) else {
        return STATUS_INVALID;
    };
    let value_scope = ();
    let Some(value_bytes) = (unsafe { ffi_slice(value, value_len, &value_scope) }) else {
        return STATUS_INVALID;
    };
    match fs.xattr_set(target.node_id, name_bytes, value_bytes) {
        Ok(()) => STATUS_OK,
        Err(e) => err_to_status(e),
    }
}

/// Read `name`'s value on the node at `path` into `dst`. Writes the
/// full value length (which may exceed `dst_max`) to `*out_len`.
/// Caller treats `*out_len > dst_max` as "buffer too small".
/// Returns kStatusOk on hit, kStatusNotFound on no such xattr.
/// # Safety
/// Raw pointer arguments must satisfy the C ABI contract in `include/duetfs.h`
/// for the duration of the call; DuetFS never retains them after returning.
#[no_mangle]
pub unsafe extern "C" fn duetfs_xattr_get(
    desc: *const DuetFsDevice,
    path: *const c_uchar,
    path_max: usize,
    name: *const c_uchar,
    name_len: usize,
    dst: *mut u8,
    dst_max: usize,
    out_len: *mut usize,
) -> c_uint {
    if name_len == 0 || name_len > XATTR_NAME_MAX {
        return STATUS_INVALID;
    }
    let dst_extent = core::cmp::min(dst_max, XATTR_VALUE_MAX);
    if !ffi_output_ranges_disjoint(&[
        ffi_range(desc, 1),
        ffi_range(dst, dst_extent),
        ffi_optional_range(out_len, 1),
    ]) || ffi_ranges_overlap(path, path_max, dst, dst_extent) != Some(false)
        || ffi_ranges_overlap(name, name_len, dst, dst_extent) != Some(false)
        || (!out_len.is_null()
            && (ffi_ranges_overlap(path, path_max, out_len, 1) != Some(false)
                || ffi_ranges_overlap(name, name_len, out_len, 1) != Some(false)))
        || !unsafe { ffi_write_optional(out_len, 0) }
    {
        return STATUS_INVALID;
    }
    let Some(mut dev) = (unsafe { make_dev(desc) }) else {
        return STATUS_INVALID;
    };
    let path_scope = ();
    let Some(path_bytes) = (unsafe { cstr_to_slice(path, path_max, &path_scope) }) else {
        return STATUS_INVALID;
    };
    let fs = match Fs::open(&mut dev) {
        Ok(f) => f,
        Err(e) => return err_to_status(e),
    };
    let target = match fs.lookup_path(path_bytes) {
        Ok(r) => r,
        Err(e) => return err_to_status(e),
    };
    let name_scope = ();
    let Some(name_bytes) = (unsafe { ffi_slice(name, name_len, &name_scope) }) else {
        return STATUS_INVALID;
    };
    // dst can be empty for a probe call ("how big is the buffer I need?").
    let mut dst_scope = ();
    let Some(dst_slice) = (unsafe { ffi_output_bytes(dst, dst_extent, &mut dst_scope) }) else {
        return STATUS_INVALID;
    };
    match fs.xattr_get(target.node_id, name_bytes, dst_slice) {
        Ok(n) => {
            if !unsafe { ffi_write_optional(out_len, n) } {
                return STATUS_INVALID;
            }
            STATUS_OK
        }
        Err(e) => err_to_status(e),
    }
}

/// List xattr names on the node at `path` as a NUL-separated stream
/// in `dst`. Writes the total bytes-needed to `*out_len`. Caller
/// treats `*out_len > dst_max` as "buffer too small".
/// # Safety
/// Raw pointer arguments must satisfy the C ABI contract in `include/duetfs.h`
/// for the duration of the call; DuetFS never retains them after returning.
#[no_mangle]
pub unsafe extern "C" fn duetfs_xattr_list(
    desc: *const DuetFsDevice,
    path: *const c_uchar,
    path_max: usize,
    dst: *mut u8,
    dst_max: usize,
    out_len: *mut usize,
) -> c_uint {
    let dst_extent = core::cmp::min(dst_max, BLOCK_SIZE);
    if !ffi_output_ranges_disjoint(&[
        ffi_range(desc, 1),
        ffi_range(dst, dst_extent),
        ffi_optional_range(out_len, 1),
    ]) || ffi_ranges_overlap(path, path_max, dst, dst_extent) != Some(false)
        || (!out_len.is_null() && ffi_ranges_overlap(path, path_max, out_len, 1) != Some(false))
        || !unsafe { ffi_write_optional(out_len, 0) }
    {
        return STATUS_INVALID;
    }
    let Some(mut dev) = (unsafe { make_dev(desc) }) else {
        return STATUS_INVALID;
    };
    let path_scope = ();
    let Some(path_bytes) = (unsafe { cstr_to_slice(path, path_max, &path_scope) }) else {
        return STATUS_INVALID;
    };
    let fs = match Fs::open(&mut dev) {
        Ok(f) => f,
        Err(e) => return err_to_status(e),
    };
    let target = match fs.lookup_path(path_bytes) {
        Ok(r) => r,
        Err(e) => return err_to_status(e),
    };
    let mut dst_scope = ();
    let Some(dst_slice) = (unsafe { ffi_output_bytes(dst, dst_extent, &mut dst_scope) }) else {
        return STATUS_INVALID;
    };
    match fs.xattr_list(target.node_id, dst_slice) {
        Ok(n) => {
            if !unsafe { ffi_write_optional(out_len, n) } {
                return STATUS_INVALID;
            }
            STATUS_OK
        }
        Err(e) => err_to_status(e),
    }
}

/// Remove `name`'s entry on the node at `path`. Frees the xattr
/// block if the last entry is removed. Returns kStatusNotFound when
/// no such xattr exists.
/// # Safety
/// Raw pointer arguments must satisfy the C ABI contract in `include/duetfs.h`
/// for the duration of the call; DuetFS never retains them after returning.
#[no_mangle]
pub unsafe extern "C" fn duetfs_xattr_remove(
    desc: *const DuetFsDevice,
    path: *const c_uchar,
    path_max: usize,
    name: *const c_uchar,
    name_len: usize,
) -> c_uint {
    if name_len == 0 || name_len > XATTR_NAME_MAX {
        return STATUS_INVALID;
    }
    let Some(mut dev) = (unsafe { make_dev(desc) }) else {
        return STATUS_INVALID;
    };
    let path_scope = ();
    let Some(path_bytes) = (unsafe { cstr_to_slice(path, path_max, &path_scope) }) else {
        return STATUS_INVALID;
    };
    let mut fs = match Fs::open(&mut dev) {
        Ok(f) => f,
        Err(e) => return err_to_status(e),
    };
    let target = match fs.lookup_path(path_bytes) {
        Ok(r) => r,
        Err(e) => return err_to_status(e),
    };
    let name_scope = ();
    let Some(name_bytes) = (unsafe { ffi_slice(name, name_len, &name_scope) }) else {
        return STATUS_INVALID;
    };
    match fs.xattr_remove(target.node_id, name_bytes) {
        Ok(()) => STATUS_OK,
        Err(e) => err_to_status(e),
    }
}

/// Snapshot presence. 0 = absent, 1 = present, 0xFFFFFFFFu = read
/// error / corrupt SB.
/// # Safety
/// Raw pointer arguments must satisfy the C ABI contract in `include/duetfs.h`
/// for the duration of the call; DuetFS never retains them after returning.
#[no_mangle]
pub unsafe extern "C" fn duetfs_snapshot_present(desc: *const DuetFsDevice) -> c_uint {
    let Some(dev) = (unsafe { make_dev(desc) }) else {
        return c_uint::MAX;
    };
    let mut block = [0u8; BLOCK_SIZE];
    if dev.read_block(SUPERBLOCK_LBA, &mut block).is_err() {
        return c_uint::MAX;
    }
    let sb = unsafe { core::ptr::read_unaligned(block.as_ptr() as *const crate::format::Superblock) };
    if sb.magic != crate::format::MAGIC || sb.version != crate::format::VERSION {
        return c_uint::MAX;
    }
    sb.snapshot_present
}

/// Read the SB's encryption metadata without mounting the FS.
/// Lets the C++ side discover salt + cost params for a previously-
/// formatted encrypted volume so it can prompt for a password,
/// derive the key, and build the encrypted-Device wrapper before
/// any other duetfs FFI call. `dev` here is the RAW device, NOT a
/// crypto wrapper — the SB lives at LBA 0 plaintext.
/// # Safety
/// Raw pointer arguments must satisfy the C ABI contract in `include/duetfs.h`
/// for the duration of the call; DuetFS never retains them after returning.
#[no_mangle]
pub unsafe extern "C" fn duetfs_read_encryption_meta(
    desc: *const DuetFsDevice,
    out_encrypted: *mut u32,
    out_m_cost: *mut u32,
    out_t_cost: *mut u32,
    out_p_cost: *mut u32,
    out_salt: *mut u8,
    salt_buf_len: usize,
) -> c_uint {
    if !ffi_output_ranges_disjoint(&[
        ffi_range(desc, 1),
        ffi_optional_range(out_encrypted, 1),
        ffi_optional_range(out_m_cost, 1),
        ffi_optional_range(out_t_cost, 1),
        ffi_optional_range(out_p_cost, 1),
        ffi_optional_range(out_salt, SALT_BYTES),
    ]) {
        return STATUS_INVALID;
    }
    let Some(dev) = (unsafe { make_dev(desc) }) else {
        return STATUS_INVALID;
    };
    if salt_buf_len < SALT_BYTES {
        return STATUS_INVALID;
    }
    let mut block = [0u8; BLOCK_SIZE];
    if dev.read_block(0, &mut block).is_err() {
        return STATUS_IO;
    }
    let sb = unsafe { core::ptr::read_unaligned(block.as_ptr() as *const crate::format::Superblock) };
    if sb.magic != crate::format::MAGIC || sb.version != crate::format::VERSION {
        return STATUS_INVALID;
    }
    if sb.encrypted != ENCRYPTED_NO && sb.encrypted != ENCRYPTED_AES_XTS_256 {
        return STATUS_CORRUPT;
    }
    if sb.encrypted == ENCRYPTED_AES_XTS_256
        && !crypto::argon2id_params_valid(sb.kdf_m_cost_kib, sb.kdf_t_cost, sb.kdf_p_cost)
    {
        return STATUS_CORRUPT;
    }
    if !unsafe { ffi_write_optional(out_encrypted, sb.encrypted) }
        || !unsafe { ffi_write_optional(out_m_cost, sb.kdf_m_cost_kib) }
        || !unsafe { ffi_write_optional(out_t_cost, sb.kdf_t_cost) }
        || !unsafe { ffi_write_optional(out_p_cost, sb.kdf_p_cost) }
    {
        return STATUS_INVALID;
    }
    if !out_salt.is_null() {
        let mut salt_scope = ();
        let Some(dst) = (unsafe { ffi_output_bytes(out_salt, SALT_BYTES, &mut salt_scope) }) else {
            return STATUS_INVALID;
        };
        dst.copy_from_slice(&sb.kdf_salt);
    }
    STATUS_OK
}
