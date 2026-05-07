// DuetFS C FFI — narrow surface, hand-mirrored in include/duetfs.h.
//
// Bindgen is forbidden by project policy (the contract should be
// readable from the header alone). Every change here MUST update
// the header in lockstep, and the C++ adapter
// (kernel/fs/duetfs.cpp) re-checks the layout via static_assert at
// compile time.
//
// Lifetime discipline: the kernel hands the crate raw image bytes
// + length on every call. The crate never retains them across
// calls. No global state, no allocations in the hot path.

use core::ffi::{c_uchar, c_uint, c_void};

use crate::format::{NODE_KIND_DIR, NODE_KIND_FILE, NODE_KIND_UNUSED};
use crate::image::Image;
use crate::lookup;

#[repr(C)]
pub struct DuetFsLookupResult
{
    pub kind: u32,        // NODE_KIND_*
    pub node_id: u32,
    pub size_bytes: u32,
    pub child_count: u32,
}

const KIND_MISS: u32 = u32::MAX;

/// Probe a buffer to confirm it's a DuetFS image. Returns 1 if valid,
/// 0 otherwise. Cheap — only inspects the superblock.
///
/// SAFETY: caller guarantees `image[..len]` is a readable byte range
/// for the duration of the call, or `image == NULL` / `len == 0`.
#[no_mangle]
pub unsafe extern "C" fn duetfs_probe(image: *const c_uchar, len: usize) -> c_uint
{
    let Some(bytes) = (unsafe { slice_from_raw(image, len) }) else { return 0 };
    Image::parse(bytes).map_or(0, |_| 1)
}

/// Resolve `path` (NUL-terminated, kernel buffer) against `image`.
/// On success, fills `*out` and returns 1. On miss / corruption / bad
/// args returns 0; `*out` is left with `kind = u32::MAX`.
///
/// SAFETY: caller guarantees `image[..len]` and `path` (until NUL,
/// bounded by `path_max`) are readable for the call. `out` is
/// writable for `sizeof(DuetFsLookupResult)` bytes.
#[no_mangle]
pub unsafe extern "C" fn duetfs_lookup(
    image: *const c_uchar,
    len: usize,
    path: *const c_uchar,
    path_max: usize,
    out: *mut DuetFsLookupResult,
) -> c_uint
{
    if out.is_null()
    {
        return 0;
    }
    unsafe {
        (*out).kind = KIND_MISS;
        (*out).node_id = 0;
        (*out).size_bytes = 0;
        (*out).child_count = 0;
    }
    let Some(bytes) = (unsafe { slice_from_raw(image, len) }) else { return 0 };
    let Some(path_bytes) = (unsafe { cstr_to_slice(path, path_max) }) else { return 0 };
    let Some(img) = Image::parse(bytes) else { return 0 };
    let Some(res) = lookup::resolve(&img, path_bytes) else { return 0 };
    unsafe {
        (*out).kind = res.node.kind;
        (*out).node_id = res.node_id;
        (*out).size_bytes = res.node.size_bytes;
        (*out).child_count = res.node.child_count;
    }
    1
}

/// Copy up to `dst_max` bytes of `node_id`'s file contents into `dst`,
/// starting at `offset`. Returns the number of bytes copied (0 on
/// miss / non-file / out-of-range — same shape as a short read).
#[no_mangle]
pub unsafe extern "C" fn duetfs_read_file(
    image: *const c_uchar,
    len: usize,
    node_id: u32,
    offset: u32,
    dst: *mut c_void,
    dst_max: usize,
) -> usize
{
    if dst.is_null() || dst_max == 0
    {
        return 0;
    }
    let Some(bytes) = (unsafe { slice_from_raw(image, len) }) else { return 0 };
    let Some(img) = Image::parse(bytes) else { return 0 };
    let Some(node) = img.node(node_id) else { return 0 };
    if node.kind != NODE_KIND_FILE
    {
        return 0;
    }
    let Some(file_bytes) = img.file_bytes(&node) else { return 0 };
    let off = offset as usize;
    if off >= file_bytes.len()
    {
        return 0;
    }
    let avail = file_bytes.len() - off;
    let n = avail.min(dst_max);
    unsafe {
        core::ptr::copy_nonoverlapping(
            file_bytes.as_ptr().add(off),
            dst as *mut u8,
            n,
        );
    }
    n
}

// Keep the kind constants linked into the staticlib so the header's
// values stay greppable. Without this they'd be optimized away.
#[no_mangle]
pub static DUETFS_KIND_UNUSED: u32 = NODE_KIND_UNUSED;
#[no_mangle]
pub static DUETFS_KIND_FILE: u32 = NODE_KIND_FILE;
#[no_mangle]
pub static DUETFS_KIND_DIR: u32 = NODE_KIND_DIR;

unsafe fn slice_from_raw<'a>(p: *const c_uchar, len: usize) -> Option<&'a [u8]>
{
    if p.is_null() || len == 0
    {
        return None;
    }
    Some(unsafe { core::slice::from_raw_parts(p, len) })
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
