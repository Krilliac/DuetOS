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

use crate::block_dev::{BlockDevice, ExternBlockDevice, ExternBlockDeviceOps};
use crate::compress;
use crate::crypto;
use crate::format::{
    BLOCK_SIZE, JOURNAL_LBA, NODE_KIND_DIR, NODE_KIND_FILE, NODE_KIND_UNUSED, ROOT_NODE_ID,
    SALT_BYTES,
};
use crate::fs::{Fs, FsError};
use crate::journal;
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
const STATUS_NOT_A_SYMLINK: u32 = 14;
const STATUS_XDEV_LINK: u32 = 15;

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
        FsError::NotASymlink => STATUS_NOT_A_SYMLINK,
        FsError::XdevLink => STATUS_XDEV_LINK,
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
    pub block_crc_mismatch: u32,
    pub link_count_mismatch: u32,
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
                    (*out).block_crc_mismatch = r.block_crc_mismatch;
                    (*out).link_count_mismatch = r.link_count_mismatch;
                }
            }
            STATUS_OK
        }
        Err(e) => err_to_status(e),
    }
}

/// Create a symbolic link at `path` pointing at `target`. Both
/// strings are NUL-terminated kernel buffers.
#[no_mangle]
pub unsafe extern "C" fn duetfs_create_symlink(
    desc: *const DuetFsDevice, path: *const c_uchar, path_max: usize,
    target: *const c_uchar, target_max: usize, out_node_id: *mut u32,
) -> c_uint
{
    if !out_node_id.is_null()
    {
        unsafe { *out_node_id = 0 };
    }
    let Some(mut dev) = (unsafe { make_dev(desc) }) else { return STATUS_INVALID };
    let Some(path_bytes) = (unsafe { cstr_to_slice(path, path_max) }) else { return STATUS_INVALID };
    let Some(target_bytes) = (unsafe { cstr_to_slice(target, target_max) }) else { return STATUS_INVALID };
    let Some((parent_path, name)) = split_parent_and_name(path_bytes) else { return STATUS_INVALID };
    let mut fs = match Fs::open(&mut dev) { Ok(f) => f, Err(e) => return err_to_status(e) };
    let parent = match fs.lookup_path(parent_path) { Ok(r) => r, Err(e) => return err_to_status(e) };
    match fs.create_symlink(parent.node_id, name, target_bytes)
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

/// Read a symlink's target into `dst`. Returns kStatusOk + bytes
/// copied via `*out_copied`. Same shape as duetfs_read_file but
/// requires the node to be a symlink.
#[no_mangle]
pub unsafe extern "C" fn duetfs_readlink(
    desc: *const DuetFsDevice, node_id: u32, dst: *mut c_void, dst_max: usize,
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
    match fs.readlink(node_id, buf)
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

/// Create a hard link at `new_path` pointing at the same inode as
/// `existing_path`. v3 caveat: the new dirent shares the target's
/// existing name; passing a `new_path` whose last component
/// differs from the target's name returns STATUS_INVALID until a
/// future slice introduces a separate dirent table.
#[no_mangle]
pub unsafe extern "C" fn duetfs_link(
    desc: *const DuetFsDevice, existing_path: *const c_uchar, existing_max: usize,
    new_path: *const c_uchar, new_max: usize,
) -> c_uint
{
    let Some(mut dev) = (unsafe { make_dev(desc) }) else { return STATUS_INVALID };
    let Some(existing_bytes) = (unsafe { cstr_to_slice(existing_path, existing_max) }) else {
        return STATUS_INVALID;
    };
    let Some(new_bytes) = (unsafe { cstr_to_slice(new_path, new_max) }) else { return STATUS_INVALID };
    let Some((parent_path, name)) = split_parent_and_name(new_bytes) else { return STATUS_INVALID };
    let mut fs = match Fs::open(&mut dev) { Ok(f) => f, Err(e) => return err_to_status(e) };
    let target = match fs.lookup_path(existing_bytes) { Ok(r) => r, Err(e) => return err_to_status(e) };
    let parent = match fs.lookup_path(parent_path) { Ok(r) => r, Err(e) => return err_to_status(e) };
    match fs.link(target.node_id, parent.node_id, name)
    {
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
#[no_mangle]
pub unsafe extern "C" fn duetfs_block_read(
    desc: *const DuetFsDevice, lba: u32, dst: *mut u8,
) -> c_uint
{
    if dst.is_null()
    {
        return STATUS_INVALID;
    }
    let Some(dev) = (unsafe { make_dev(desc) }) else { return STATUS_INVALID };
    if lba >= dev.block_count()
    {
        return STATUS_INVALID;
    }
    let buf = unsafe { core::slice::from_raw_parts_mut(dst, BLOCK_SIZE) };
    match dev.read_block(lba, buf)
    {
        Ok(()) => STATUS_OK,
        Err(_) => STATUS_IO,
    }
}

/// Apply a single (target_lba, payload) write through the journal.
/// Atomic against torn writes — either the new payload reaches the
/// target or the FS is left exactly as it was. `payload` MUST point
/// at a kernel-space buffer of at least kBlockSize bytes.
#[no_mangle]
pub unsafe extern "C" fn duetfs_journal_apply(
    desc: *const DuetFsDevice, target_lba: u32, payload: *const u8,
) -> c_uint
{
    if payload.is_null()
    {
        return STATUS_INVALID;
    }
    let Some(mut dev) = (unsafe { make_dev(desc) }) else { return STATUS_INVALID };
    let buf = unsafe { core::slice::from_raw_parts(payload, BLOCK_SIZE) };
    // txn_id of 1 is fine for the standalone helper — Fs::open's
    // replay path doesn't depend on monotonicity (it only reads the
    // descriptor's `state`).
    match journal::apply(&mut dev, JOURNAL_LBA, 1, &[(target_lba, buf)])
    {
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
#[no_mangle]
pub unsafe extern "C" fn duetfs_journal_inject_for_test(
    desc: *const DuetFsDevice, target_lba: u32, payload: *const u8,
) -> c_uint
{
    if payload.is_null()
    {
        return STATUS_INVALID;
    }
    let Some(mut dev) = (unsafe { make_dev(desc) }) else { return STATUS_INVALID };
    let buf = unsafe { core::slice::from_raw_parts(payload, BLOCK_SIZE) };
    match journal::inject_committed_for_test(&mut dev, JOURNAL_LBA, 1, &[(target_lba, buf)])
    {
        Ok(()) => STATUS_OK,
        Err(e) => err_to_status(e),
    }
}

/// Read the journal descriptor's `state` field. 0 = empty, 1 =
/// committed (replay pending). Other values reflect a corrupt
/// descriptor and are reported verbatim. Diagnostic — never fails
/// the FS-open path (Fs::open replays first), so a clean mount
/// always reports state == 0.
#[no_mangle]
pub unsafe extern "C" fn duetfs_journal_state(desc: *const DuetFsDevice) -> c_uint
{
    let Some(mut dev) = (unsafe { make_dev(desc) }) else { return c_uint::MAX };
    match journal::peek_descriptor(&mut dev, JOURNAL_LBA)
    {
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
#[no_mangle]
pub unsafe extern "C" fn duetfs_kdf_argon2id(
    password: *const u8, password_len: usize, salt: *const u8, salt_len: usize, m_cost_kib: u32,
    t_cost: u32, p_cost: u32, out_key: *mut u8,
) -> c_uint
{
    if password.is_null() || salt.is_null() || out_key.is_null() || password_len == 0 || salt_len == 0
    {
        return STATUS_INVALID;
    }
    let pw = unsafe { core::slice::from_raw_parts(password, password_len) };
    let s = unsafe { core::slice::from_raw_parts(salt, salt_len) };
    let mut key = [0u8; crypto::XTS_KEY_BYTES];
    if !crypto::argon2id_kdf(pw, s, m_cost_kib, t_cost, p_cost, &mut key)
    {
        return STATUS_INVALID;
    }
    let dst = unsafe { core::slice::from_raw_parts_mut(out_key, crypto::XTS_KEY_BYTES) };
    dst.copy_from_slice(&key);
    STATUS_OK
}

/// Encrypt a 4096-byte block in place using AES-256-XTS. `key`
/// points at a 64-byte key (data || tweak). `sector` is the LBA —
/// the XTS tweak is derived from it so the same plaintext at
/// different LBAs produces different ciphertext.
#[no_mangle]
pub unsafe extern "C" fn duetfs_xts_encrypt_block(
    key: *const u8, sector: u64, buf: *mut u8,
) -> c_uint
{
    if key.is_null() || buf.is_null()
    {
        return STATUS_INVALID;
    }
    let mut k = [0u8; crypto::XTS_KEY_BYTES];
    let raw_key = unsafe { core::slice::from_raw_parts(key, crypto::XTS_KEY_BYTES) };
    k.copy_from_slice(raw_key);
    let payload = unsafe { core::slice::from_raw_parts_mut(buf, crypto::SECTOR_BYTES) };
    crypto::xts_encrypt_in_place(&k, sector, payload);
    STATUS_OK
}

/// Decrypt a 4096-byte block in place. Inverse of
/// `duetfs_xts_encrypt_block`.
#[no_mangle]
pub unsafe extern "C" fn duetfs_xts_decrypt_block(
    key: *const u8, sector: u64, buf: *mut u8,
) -> c_uint
{
    if key.is_null() || buf.is_null()
    {
        return STATUS_INVALID;
    }
    let mut k = [0u8; crypto::XTS_KEY_BYTES];
    let raw_key = unsafe { core::slice::from_raw_parts(key, crypto::XTS_KEY_BYTES) };
    k.copy_from_slice(raw_key);
    let payload = unsafe { core::slice::from_raw_parts_mut(buf, crypto::SECTOR_BYTES) };
    crypto::xts_decrypt_in_place(&k, sector, payload);
    STATUS_OK
}

/// Format an encrypted volume. `dev` MUST already wrap the underlying
/// storage in the C++ AES-XTS encrypt/decrypt callbacks (the kernel
/// builds that wrapper after deriving the key with
/// duetfs_kdf_argon2id). `salt` (16 bytes) and the (m_cost_kib,
/// t_cost, p_cost) triple get persisted in the SB so a future
/// mounter can re-derive the key from the same password.
#[no_mangle]
pub unsafe extern "C" fn duetfs_mkfs_encrypted(
    desc: *const DuetFsDevice, salt: *const u8, salt_len: usize, m_cost_kib: u32, t_cost: u32,
    p_cost: u32,
) -> c_uint
{
    if salt.is_null() || salt_len != SALT_BYTES
    {
        return STATUS_INVALID;
    }
    let Some(mut dev) = (unsafe { make_dev(desc) }) else { return STATUS_INVALID };
    let mut salt_arr = [0u8; SALT_BYTES];
    let raw = unsafe { core::slice::from_raw_parts(salt, SALT_BYTES) };
    salt_arr.copy_from_slice(raw);
    match mkfs::format_encrypted(&mut dev, &salt_arr, m_cost_kib, t_cost, p_cost)
    {
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
#[no_mangle]
pub unsafe extern "C" fn duetfs_lz4_compress(
    src: *const u8, src_len: usize, dst: *mut u8, dst_max: usize, out_len: *mut usize,
) -> c_uint
{
    if !out_len.is_null()
    {
        unsafe { *out_len = 0 };
    }
    if src.is_null() || dst.is_null()
    {
        return STATUS_INVALID;
    }
    let s = unsafe { core::slice::from_raw_parts(src, src_len) };
    let d = unsafe { core::slice::from_raw_parts_mut(dst, dst_max) };
    let n = compress::compress_prepend_size(s, d);
    if n == 0 && src_len != 0
    {
        return STATUS_INVALID;
    }
    if !out_len.is_null()
    {
        unsafe { *out_len = n };
    }
    STATUS_OK
}

/// Decompress a size-prefixed LZ4 frame from `src` into `dst`. On
/// success writes the byte count to `*out_len` and returns
/// kStatusOk; on any error (truncated input, bad header, dst short)
/// returns kStatusInvalid.
#[no_mangle]
pub unsafe extern "C" fn duetfs_lz4_decompress(
    src: *const u8, src_len: usize, dst: *mut u8, dst_max: usize, out_len: *mut usize,
) -> c_uint
{
    if !out_len.is_null()
    {
        unsafe { *out_len = 0 };
    }
    if src.is_null() || dst.is_null() || src_len == 0
    {
        return STATUS_INVALID;
    }
    let s = unsafe { core::slice::from_raw_parts(src, src_len) };
    let d = unsafe { core::slice::from_raw_parts_mut(dst, dst_max) };
    let n = compress::decompress_size_prepended(s, d);
    if n == 0
    {
        return STATUS_INVALID;
    }
    if !out_len.is_null()
    {
        unsafe { *out_len = n };
    }
    STATUS_OK
}

/// Worst-case output size for `duetfs_lz4_compress` on an input of
/// `n` bytes — caller sizes the dst buffer to this. Includes the
/// 4-byte size header. Cheap (no I/O).
#[no_mangle]
pub unsafe extern "C" fn duetfs_lz4_compress_bound(n: usize) -> usize
{
    compress::compress_bound(n)
}

/// Read the SB's encryption metadata without mounting the FS.
/// Lets the C++ side discover salt + cost params for a previously-
/// formatted encrypted volume so it can prompt for a password,
/// derive the key, and build the encrypted-Device wrapper before
/// any other duetfs FFI call. `dev` here is the RAW device, NOT a
/// crypto wrapper — the SB lives at LBA 0 plaintext.
#[no_mangle]
pub unsafe extern "C" fn duetfs_read_encryption_meta(
    desc: *const DuetFsDevice, out_encrypted: *mut u32, out_m_cost: *mut u32, out_t_cost: *mut u32,
    out_p_cost: *mut u32, out_salt: *mut u8, salt_buf_len: usize,
) -> c_uint
{
    let Some(dev) = (unsafe { make_dev(desc) }) else { return STATUS_INVALID };
    if salt_buf_len < SALT_BYTES
    {
        return STATUS_INVALID;
    }
    let mut block = [0u8; BLOCK_SIZE];
    if dev.read_block(0, &mut block).is_err()
    {
        return STATUS_IO;
    }
    let sb = unsafe {
        core::ptr::read_unaligned(block.as_ptr() as *const crate::format::Superblock)
    };
    if sb.magic != crate::format::MAGIC || sb.version != crate::format::VERSION
    {
        return STATUS_INVALID;
    }
    if !out_encrypted.is_null()
    {
        unsafe { *out_encrypted = sb.encrypted };
    }
    if !out_m_cost.is_null()
    {
        unsafe { *out_m_cost = sb.kdf_m_cost_kib };
    }
    if !out_t_cost.is_null()
    {
        unsafe { *out_t_cost = sb.kdf_t_cost };
    }
    if !out_p_cost.is_null()
    {
        unsafe { *out_p_cost = sb.kdf_p_cost };
    }
    if !out_salt.is_null()
    {
        let dst = unsafe { core::slice::from_raw_parts_mut(out_salt, SALT_BYTES) };
        dst.copy_from_slice(&sb.kdf_salt);
    }
    STATUS_OK
}
