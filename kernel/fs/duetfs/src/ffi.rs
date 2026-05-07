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

use core::ffi::{c_uchar, c_uint, c_void};

use crate::block_dev::{ExternBlockDevice, ExternBlockDeviceOps};
use crate::format::{
    NODE_KIND_DIR, NODE_KIND_FILE, NODE_KIND_UNUSED, ROOT_NODE_ID,
};
use crate::fs::{Fs, FsError};
use crate::mkfs;
use crate::path::split_parent_and_name;

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

#[repr(C)]
pub struct DuetFsDevice
{
    pub cookie: *mut c_void,
    pub block_count: u32,
    pub read_only: u32,
    pub read: Option<unsafe extern "C" fn(cookie: *mut c_void, lba: u32, dst: *mut u8) -> i32>,
    pub write: Option<unsafe extern "C" fn(cookie: *mut c_void, lba: u32, src: *const u8) -> i32>,
}

#[repr(C)]
pub struct DuetFsLookupResult
{
    pub kind: u32,
    pub node_id: u32,
    pub size_bytes: u32,
    pub child_count: u32,
}

const KIND_MISS: u32 = u32::MAX;

fn err_to_status(e: FsError) -> u32
{
    match e
    {
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
    }
}

// SAFETY: caller guarantees `desc` is valid + readable, and that
// every callback operates correctly on its cookie for the lifetime
// of this call. No retention across calls.
unsafe fn make_dev(desc: *const DuetFsDevice) -> Option<ExternBlockDevice>
{
    if desc.is_null()
    {
        return None;
    }
    let d = unsafe { &*desc };
    Some(ExternBlockDevice {
        cookie: d.cookie,
        block_count: d.block_count,
        ops: ExternBlockDeviceOps { read: d.read, write: d.write },
        read_only: d.read_only != 0,
    })
}

unsafe fn cstr_to_slice<'a>(p: *const c_uchar, max: usize) -> Option<&'a [u8]>
{
    if p.is_null() || max == 0
    {
        return None;
    }
    let bytes = unsafe { core::slice::from_raw_parts(p, max) };
    let n = bytes.iter().position(|&b| b == 0).unwrap_or(max);
    Some(&bytes[..n])
}

#[no_mangle]
pub unsafe extern "C" fn duetfs_probe(desc: *const DuetFsDevice) -> c_uint
{
    let Some(mut dev) = (unsafe { make_dev(desc) }) else { return 0 };
    Fs::open(&mut dev).is_ok() as c_uint
}

#[no_mangle]
pub unsafe extern "C" fn duetfs_mkfs(desc: *const DuetFsDevice) -> c_uint
{
    let Some(mut dev) = (unsafe { make_dev(desc) }) else { return STATUS_INVALID };
    match mkfs::format(&mut dev)
    {
        Ok(()) => STATUS_OK,
        Err(e) => err_to_status(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn duetfs_lookup(
    desc: *const DuetFsDevice, path: *const c_uchar, path_max: usize,
    out: *mut DuetFsLookupResult,
) -> c_uint
{
    if !out.is_null()
    {
        unsafe {
            (*out).kind = KIND_MISS;
            (*out).node_id = 0;
            (*out).size_bytes = 0;
            (*out).child_count = 0;
        }
    }
    let Some(mut dev) = (unsafe { make_dev(desc) }) else { return STATUS_INVALID };
    let Some(path_bytes) = (unsafe { cstr_to_slice(path, path_max) }) else { return STATUS_INVALID };
    let fs = match Fs::open(&mut dev) { Ok(f) => f, Err(e) => return err_to_status(e) };
    match fs.lookup_path(path_bytes)
    {
        Ok(r) => {
            if !out.is_null()
            {
                unsafe {
                    (*out).kind = r.node.kind;
                    (*out).node_id = r.node_id;
                    (*out).size_bytes = r.node.size_bytes;
                    (*out).child_count = r.node.child_count;
                }
            }
            STATUS_OK
        }
        Err(e) => err_to_status(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn duetfs_read_file(
    desc: *const DuetFsDevice, node_id: u32, offset: u32, dst: *mut c_void, dst_max: usize,
    out_copied: *mut usize,
) -> c_uint
{
    if !out_copied.is_null()
    {
        unsafe { *out_copied = 0 };
    }
    if dst.is_null() || dst_max == 0
    {
        return STATUS_INVALID;
    }
    let Some(mut dev) = (unsafe { make_dev(desc) }) else { return STATUS_INVALID };
    let fs = match Fs::open(&mut dev) { Ok(f) => f, Err(e) => return err_to_status(e) };
    let buf = unsafe { core::slice::from_raw_parts_mut(dst as *mut u8, dst_max) };
    match fs.read_at(node_id, offset, buf)
    {
        Ok(n) => {
            if !out_copied.is_null()
            {
                unsafe { *out_copied = n as usize };
            }
            STATUS_OK
        }
        Err(e) => err_to_status(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn duetfs_write_at(
    desc: *const DuetFsDevice, node_id: u32, offset: u32, src: *const c_void, src_max: usize,
    out_written: *mut usize,
) -> c_uint
{
    if !out_written.is_null()
    {
        unsafe { *out_written = 0 };
    }
    if src.is_null() && src_max != 0
    {
        return STATUS_INVALID;
    }
    let Some(mut dev) = (unsafe { make_dev(desc) }) else { return STATUS_INVALID };
    let mut fs = match Fs::open(&mut dev) { Ok(f) => f, Err(e) => return err_to_status(e) };
    let buf = if src.is_null() { &[] as &[u8] } else {
        unsafe { core::slice::from_raw_parts(src as *const u8, src_max) }
    };
    match fs.write_at(node_id, offset, buf)
    {
        Ok(n) => {
            if !out_written.is_null()
            {
                unsafe { *out_written = n as usize };
            }
            STATUS_OK
        }
        Err(e) => err_to_status(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn duetfs_create_path(
    desc: *const DuetFsDevice, path: *const c_uchar, path_max: usize, kind: u32,
    out_node_id: *mut u32,
) -> c_uint
{
    if !out_node_id.is_null()
    {
        unsafe { *out_node_id = 0 };
    }
    if kind != NODE_KIND_FILE && kind != NODE_KIND_DIR
    {
        return STATUS_INVALID;
    }
    let Some(mut dev) = (unsafe { make_dev(desc) }) else { return STATUS_INVALID };
    let Some(path_bytes) = (unsafe { cstr_to_slice(path, path_max) }) else { return STATUS_INVALID };
    let Some((parent_path, name)) = split_parent_and_name(path_bytes) else { return STATUS_INVALID };
    let mut fs = match Fs::open(&mut dev) { Ok(f) => f, Err(e) => return err_to_status(e) };
    let parent = match fs.lookup_path(parent_path) { Ok(r) => r, Err(e) => return err_to_status(e) };
    let res = if kind == NODE_KIND_FILE
    {
        fs.create_file(parent.node_id, name)
    }
    else
    {
        fs.create_dir(parent.node_id, name)
    };
    match res
    {
        Ok(id) => {
            if !out_node_id.is_null()
            {
                unsafe { *out_node_id = id };
            }
            STATUS_OK
        }
        Err(e) => err_to_status(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn duetfs_unlink_path(
    desc: *const DuetFsDevice, path: *const c_uchar, path_max: usize,
) -> c_uint
{
    let Some(mut dev) = (unsafe { make_dev(desc) }) else { return STATUS_INVALID };
    let Some(path_bytes) = (unsafe { cstr_to_slice(path, path_max) }) else { return STATUS_INVALID };
    let Some((parent_path, name)) = split_parent_and_name(path_bytes) else { return STATUS_INVALID };
    let mut fs = match Fs::open(&mut dev) { Ok(f) => f, Err(e) => return err_to_status(e) };
    let parent = match fs.lookup_path(parent_path) { Ok(r) => r, Err(e) => return err_to_status(e) };
    match fs.unlink(parent.node_id, name)
    {
        Ok(()) => STATUS_OK,
        Err(e) => err_to_status(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn duetfs_truncate(
    desc: *const DuetFsDevice, node_id: u32, new_size: u32,
) -> c_uint
{
    let Some(mut dev) = (unsafe { make_dev(desc) }) else { return STATUS_INVALID };
    let mut fs = match Fs::open(&mut dev) { Ok(f) => f, Err(e) => return err_to_status(e) };
    match fs.truncate(node_id, new_size)
    {
        Ok(()) => STATUS_OK,
        Err(e) => err_to_status(e),
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetFsFsckReport
{
    pub leaked_blocks: u32,
    pub missing_blocks: u32,
    pub orphan_nodes: u32,
    pub bad_extents: u32,
    pub repaired: u32,
    pub sb_crc_mismatch: u32,
}

#[no_mangle]
pub unsafe extern "C" fn duetfs_fsck(
    desc: *const DuetFsDevice, repair: u32, out: *mut DuetFsFsckReport,
) -> c_uint
{
    if !out.is_null()
    {
        unsafe { *out = DuetFsFsckReport::default() };
    }
    let Some(mut dev) = (unsafe { make_dev(desc) }) else { return STATUS_INVALID };
    let mut fs = match Fs::open(&mut dev) { Ok(f) => f, Err(e) => return err_to_status(e) };
    match fs.fsck(repair != 0)
    {
        Ok(r) => {
            if !out.is_null()
            {
                unsafe {
                    (*out).leaked_blocks = r.leaked_blocks;
                    (*out).missing_blocks = r.missing_blocks;
                    (*out).orphan_nodes = r.orphan_nodes;
                    (*out).bad_extents = r.bad_extents;
                    (*out).repaired = r.repaired;
                    (*out).sb_crc_mismatch = r.sb_crc_mismatch;
                }
            }
            STATUS_OK
        }
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
