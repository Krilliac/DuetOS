#include "fs/mount.h"

#include "core/panic.h"
#include "fs/duetfs.h"
#include "fs/ext4.h"
#include "fs/fat32.h"
#include "fs/ntfs.h"
#include "fs/tmpfs.h"
#include "fs/vfs.h"
#include "log/klog.h"
#include "util/string.h"

namespace duetos::fs
{

namespace
{

constinit MountEntry g_mounts[kMaxMounts] = {};
constinit u32 g_mount_count = 0;
constinit u32 g_mount_seq = 1;

using duetos::core::StrEqual;
using duetos::core::StrLen;

void StrCopyCapped(char* dst, u32 dst_max, const char* src)
{
    if (dst == nullptr || dst_max == 0)
    {
        return;
    }
    u32 i = 0;
    if (src != nullptr)
    {
        for (; src[i] && i + 1 < dst_max; ++i)
        {
            dst[i] = src[i];
        }
    }
    dst[i] = 0;
}

bool ValidMountPoint(const char* p)
{
    if (p == nullptr)
    {
        return false;
    }
    if (p[0] != '/')
    {
        return false;
    }
    const u32 n = StrLen(p);
    if (n < 2 || n >= sizeof(g_mounts[0].mount_point))
    {
        return false;
    }
    return true;
}

} // namespace

const char* FsTypeName(FsType t)
{
    switch (t)
    {
    case FsType::Ramfs:
        return "ramfs";
    case FsType::Fat32:
        return "fat32";
    case FsType::Ext4:
        return "ext4";
    case FsType::Ntfs:
        return "ntfs";
    case FsType::DuetFs:
        return "duetfs";
    case FsType::RamVol:
        return "ramvol";
    }
    return "unknown";
}

MountId VfsMount(const char* mount_point, FsType fs_type, u32 block_handle)
{
    if (!ValidMountPoint(mount_point))
    {
        return kInvalidMountId;
    }
    // ramfs and ramvol are in-tree synth backends — block_handle
    // must be 0 for them; every other backend must have a real
    // block handle.
    if (fs_type == FsType::Ramfs || fs_type == FsType::RamVol)
    {
        if (block_handle != 0)
        {
            return kInvalidMountId;
        }
    }
    else
    {
        if (block_handle == 0)
        {
            return kInvalidMountId;
        }
    }
    // Reject duplicate mount points. Caller must VfsUmount first if
    // they want to swap the backing for an existing path.
    for (u32 i = 0; i < kMaxMounts; ++i)
    {
        if (g_mounts[i].in_use && StrEqual(g_mounts[i].mount_point, mount_point))
        {
            return kInvalidMountId;
        }
    }
    // Find a free slot.
    for (u32 i = 0; i < kMaxMounts; ++i)
    {
        if (!g_mounts[i].in_use)
        {
            StrCopyCapped(g_mounts[i].mount_point, sizeof(g_mounts[i].mount_point), mount_point);
            g_mounts[i].fs_type = fs_type;
            g_mounts[i].block_handle = block_handle;
            g_mounts[i].mount_seq = g_mount_seq++;
            g_mounts[i].in_use = true;
            ++g_mount_count;
            KLOG_INFO_S("fs/mount", "registered", "mount_point", mount_point);
            return i;
        }
    }
    return kInvalidMountId;
}

bool VfsUmount(MountId id)
{
    if (id >= kMaxMounts || !g_mounts[id].in_use)
    {
        return false;
    }
    KLOG_INFO_S("fs/mount", "unregistered", "mount_point", g_mounts[id].mount_point);
    g_mounts[id] = MountEntry{};
    --g_mount_count;
    return true;
}

u32 VfsMountCount()
{
    return g_mount_count;
}

void VfsMountEnumerate(VfsMountEnumCb cb, void* cookie)
{
    if (cb == nullptr)
    {
        return;
    }
    for (u32 i = 0; i < kMaxMounts; ++i)
    {
        if (!g_mounts[i].in_use)
        {
            continue;
        }
        if (!cb(g_mounts[i], i, cookie))
        {
            break;
        }
    }
}

const MountEntry* VfsMountFind(const char* mount_point)
{
    if (mount_point == nullptr)
    {
        return nullptr;
    }
    for (u32 i = 0; i < kMaxMounts; ++i)
    {
        if (!g_mounts[i].in_use)
        {
            continue;
        }
        if (StrEqual(g_mounts[i].mount_point, mount_point))
        {
            return &g_mounts[i];
        }
    }
    return nullptr;
}

const MountEntry* VfsMountResolve(const char* path, const char** out_subpath)
{
    if (path == nullptr || path[0] != '/')
    {
        if (out_subpath != nullptr)
        {
            *out_subpath = nullptr;
        }
        return nullptr;
    }
    const u32 path_len = StrLen(path);
    const MountEntry* best = nullptr;
    u32 best_len = 0;
    for (u32 i = 0; i < kMaxMounts; ++i)
    {
        if (!g_mounts[i].in_use)
        {
            continue;
        }
        const char* mp = g_mounts[i].mount_point;
        const u32 mp_len = StrLen(mp);
        if (mp_len == 0 || mp_len > path_len)
        {
            continue;
        }
        // Byte-for-byte prefix match on [0..mp_len).
        bool prefix_ok = true;
        for (u32 k = 0; k < mp_len; ++k)
        {
            if (path[k] != mp[k])
            {
                prefix_ok = false;
                break;
            }
        }
        if (!prefix_ok)
        {
            continue;
        }
        // Component boundary: either path ends here, or the next
        // byte is '/'. Otherwise "/disk/0" would falsely match
        // "/disk/01/foo".
        if (path[mp_len] != '\0' && path[mp_len] != '/')
        {
            continue;
        }
        if (mp_len > best_len)
        {
            best = &g_mounts[i];
            best_len = mp_len;
        }
    }
    if (best == nullptr)
    {
        if (out_subpath != nullptr)
        {
            *out_subpath = nullptr;
        }
        return nullptr;
    }
    if (out_subpath != nullptr)
    {
        // The remainder begins where the mount point ended. If the
        // path equals the mount point exactly we hand back "/" so
        // the caller doesn't have to distinguish "" from "/".
        const char* tail = path + best_len;
        *out_subpath = (tail[0] == '\0') ? "/" : tail;
    }
    return best;
}

// =====================================================
// Per-FsType lookup vtable (Stage 6 second slice).
// =====================================================

namespace
{

bool Fat32Lookup(u32 block_handle, const char* subpath, void* out_node)
{
    if (subpath == nullptr || out_node == nullptr)
    {
        return false;
    }
    const auto* v = fat32::Fat32Volume(block_handle);
    if (v == nullptr)
    {
        return false;
    }
    fat32::DirEntry entry{};
    if (!fat32::Fat32LookupPath(v, subpath, &entry))
    {
        return false;
    }
    auto* out = static_cast<VfsNode*>(out_node);
    out->backend = VfsBackend::Fat32;
    out->ramfs = nullptr;
    out->fat32_volume_idx = block_handle;
    out->fat32_entry = entry;
    return true;
}

constinit VfsBackendOps g_fat32_ops = {&Fat32Lookup};

bool DuetFsLookup(u32 block_handle, const char* subpath, void* out_node)
{
    if (subpath == nullptr || out_node == nullptr)
    {
        return false;
    }
    const auto dev = duetos::fs::duetfs::DeviceForMountHandle(block_handle);
    if (dev.read == nullptr)
    {
        return false;
    }
    duetos::fs::duetfs::LookupResult res{};
    // strlen-bounded path buffer is OK here: subpath comes from
    // mount.cpp's resolver which already trims to a kernel-owned
    // string; the FFI walks until NUL or path_max, whichever first.
    usize n = 0;
    while (subpath[n] != '\0')
    {
        ++n;
    }
    const u32 status = duetfs_lookup(&dev, reinterpret_cast<const u8*>(subpath), n + 1, &res);
    if (status != duetos::fs::duetfs::kStatusOk)
    {
        return false;
    }
    auto* out = static_cast<VfsNode*>(out_node);
    out->backend = VfsBackend::DuetFs;
    out->ramfs = nullptr;
    out->fat32_volume_idx = 0;
    out->duetfs_block_handle = block_handle;
    out->duetfs_node_id = res.node_id;
    out->duetfs_kind = res.kind;
    out->duetfs_size_bytes = res.size_bytes;
    out->duetfs_child_count = res.child_count;
    return true;
}

constinit VfsBackendOps g_duetfs_ops = {&DuetFsLookup};

// RamVol is path-addressed and mounted at the fixed point /run
// (GAP: single fixed mount point — the lookup vtable receives only
// the in-mount subpath, so the "/run" prefix is reconstructed here;
// generalising needs the resolver to pass the mount point through).
// The absolute path IS the stable handle (RamVol node structs are
// module-private); reads re-resolve via fs::RamVolRead/Stat.
bool RamVolLookup(u32 block_handle, const char* subpath, void* out_node)
{
    (void)block_handle; // synth backend — no block device
    if (subpath == nullptr || out_node == nullptr)
    {
        return false;
    }
    char abspath[192];
    const char pfx[] = "/run";
    u32 w = 0;
    for (; pfx[w] != '\0'; ++w)
    {
        abspath[w] = pfx[w];
    }
    // subpath always starts with '/' (or is exactly "/"); appending
    // it after "/run" yields "/run", "/run/foo", ... A lone "/"
    // becomes "/run/" which RamWalk treats as the /run dir.
    u32 s = 0;
    while (subpath[s] != '\0' && w < sizeof(abspath) - 1)
    {
        abspath[w++] = subpath[s++];
    }
    abspath[w] = '\0';
    if (subpath[s] != '\0')
    {
        return false; // path longer than the snapshot buffer
    }
    if (!duetos::fs::RamVolStat(abspath, nullptr, nullptr, nullptr))
    {
        return false;
    }
    auto* out = static_cast<VfsNode*>(out_node);
    out->backend = VfsBackend::RamVol;
    out->ramfs = nullptr;
    out->fat32_volume_idx = 0;
    for (u32 i = 0; i <= w; ++i)
    {
        out->ramvol_path[i] = abspath[i];
    }
    return true;
}

constinit VfsBackendOps g_ramvol_ops = {&RamVolLookup};

// ext4 read backend. Resolves a (possibly multi-component) path under
// the ext4 root by walking one directory at a time: read the root
// inode, find the next component in it, descend into the child inode
// if it is a directory, repeat. The read path each component routes
// through (probe → inode → extent-walked dir data → linux_dirent
// scan) lives in fs/ext4.cpp. `subpath` arrives volume-relative with a
// leading '/'. A successful resolve leaves an `Ext4`-tagged VfsNode
// carrying the mount block_handle + on-disk inode number (a stable
// handle) plus a size / is-dir snapshot; reads re-derive the InodeInfo
// via Ext4ReadInode then stream through Ext4ReadFile (see
// shell_fsio.cpp).
//
// GAP: htree (hashed) directories are not walked (same limit as
//   Ext4FindInDir); path components longer than 127 chars cannot
//   match and symlinks are not followed.
bool Ext4Lookup(u32 block_handle, const char* subpath, void* out_node)
{
    if (subpath == nullptr || out_node == nullptr)
    {
        return false;
    }
    const ext4::Volume* v = ext4::Ext4VolumeByHandle(block_handle);
    if (v == nullptr)
    {
        return false;
    }
    auto* out = static_cast<VfsNode*>(out_node);

    const char* p = subpath;
    while (*p == '/')
    {
        ++p;
    }
    if (*p == '\0')
    {
        // Bare mount point — the volume's root directory (inode 2,
        // EXT4_ROOT_INO). Directories carry size 0 at the VFS layer.
        out->backend = VfsBackend::Ext4;
        out->ext4_block_handle = block_handle;
        out->ext4_inode = 2;
        out->ext4_size_bytes = 0;
        out->ext4_is_dir = true;
        return true;
    }

    // Walk components from the root directory inode.
    ext4::InodeInfo dir{};
    if (!ext4::Ext4ReadInode(*v, 2, &dir))
    {
        return false;
    }
    ext4::Ext4DirEntry entry{};
    while (*p != '\0')
    {
        char comp[128];
        u32 ci = 0;
        while (*p != '\0' && *p != '/' && ci + 1 < sizeof(comp))
        {
            comp[ci++] = *p++;
        }
        comp[ci] = '\0';
        // A component that overrun the buffer (next char neither '/'
        // nor end) is longer than any storable dir-entry name — miss.
        if (*p != '\0' && *p != '/')
        {
            return false;
        }
        while (*p == '/')
        {
            ++p;
        }
        if (ci == 0)
        {
            continue; // collapse "//" / trailing slash
        }
        if (!ext4::Ext4FindInDir(*v, dir, comp, &entry))
        {
            return false;
        }
        if (*p != '\0')
        {
            // More components follow — `entry` must be a directory to
            // descend into.
            if (entry.file_type != 2) // EXT4_FT_DIR
            {
                return false;
            }
            if (!ext4::Ext4ReadInode(*v, entry.inode, &dir))
            {
                return false;
            }
        }
    }

    // `entry` is now the final path component.
    const bool is_dir = (entry.file_type == 2); // EXT4_FT_DIR
    u64 size = 0;
    if (!is_dir)
    {
        // Size comes from the inode; a read failure here leaves size 0
        // (the node still resolves — the read path reports the error).
        ext4::InodeInfo info{};
        if (ext4::Ext4ReadInode(*v, entry.inode, &info))
        {
            size = info.size_bytes;
        }
    }
    out->backend = VfsBackend::Ext4;
    out->ext4_block_handle = block_handle;
    out->ext4_inode = entry.inode;
    out->ext4_size_bytes = size;
    out->ext4_is_dir = is_dir;
    return true;
}

constinit VfsBackendOps g_ext4_ops = {&Ext4Lookup};

// NTFS read backend. Resolves a (possibly multi-component) path under
// the NTFS root by walking one directory at a time: start at the root
// MFT record (5), find the next component's $I30 entry in it, descend
// into the child MFT record if it is a directory, repeat. The read
// path each component routes through (probe → MFT record + USA fixup →
// $I30 INDEX_ROOT enumerate → NtfsFindInDir → resolve $DATA →
// NtfsReadFile) lives in fs/ntfs.cpp. `subpath` arrives volume-relative
// with a leading '/'. A successful resolve leaves an `Ntfs`-tagged
// VfsNode carrying the mount block_handle + MFT record reference (a
// stable handle) plus a size / is-dir snapshot; reads re-read the
// record + resolve $DATA, then stream NtfsReadFile (see shell_fsio.cpp).
//
// GAP: resident $INDEX_ROOT only — a directory whose $I30 index spilled
//   into a non-resident $INDEX_ALLOCATION b-tree is only enumerated for
//   the resident slice (same limit as NtfsFindInDir, at every level);
//   path components longer than 127 chars cannot match.
bool NtfsLookup(u32 block_handle, const char* subpath, void* out_node)
{
    if (subpath == nullptr || out_node == nullptr)
    {
        return false;
    }
    const ntfs::Volume* v = ntfs::NtfsVolumeByHandle(block_handle);
    if (v == nullptr)
    {
        return false;
    }
    auto* out = static_cast<VfsNode*>(out_node);

    const char* p = subpath;
    while (*p == '/')
    {
        ++p;
    }
    if (*p == '\0')
    {
        // Bare mount point — the volume's root directory (MFT record 5).
        out->backend = VfsBackend::Ntfs;
        out->ntfs_block_handle = block_handle;
        out->ntfs_mft_reference = 5;
        out->ntfs_size_bytes = 0;
        out->ntfs_is_dir = true;
        return true;
    }

    // Walk components from the root directory MFT record (record 5).
    u64 dir_record = 5;
    ntfs::DirEntry entry{};
    while (*p != '\0')
    {
        char comp[128];
        u32 ci = 0;
        while (*p != '\0' && *p != '/' && ci + 1 < sizeof(comp))
        {
            comp[ci++] = *p++;
        }
        comp[ci] = '\0';
        // A component that overran the buffer (next char neither '/'
        // nor end) is longer than any storable dir-entry name — miss.
        if (*p != '\0' && *p != '/')
        {
            return false;
        }
        while (*p == '/')
        {
            ++p;
        }
        if (ci == 0)
        {
            continue; // collapse "//" / trailing slash
        }
        if (!ntfs::NtfsFindInDir(*v, dir_record, comp, &entry))
        {
            return false;
        }
        if (*p != '\0')
        {
            // More components follow — `entry` must be a directory to
            // descend into. NtfsFindInDir reads the record itself, so no
            // separate record-read step is needed here.
            if (!entry.is_directory)
            {
                return false;
            }
            dir_record = entry.mft_reference;
        }
    }

    // `entry` is now the final path component.
    u64 size = 0;
    if (!entry.is_directory)
    {
        // Size comes from the resolved $DATA location: read the target
        // MFT record, apply the USA fixup, decode $DATA. A failure here
        // leaves size 0 (the node still resolves — the read path
        // reports the error).
        u8 rec[ntfs::kMaxMftRecordSize];
        if (v->mft_record_size <= sizeof(rec) && ntfs::NtfsReadMftRecord(*v, entry.mft_reference, rec))
        {
            ntfs::DataLocation data{};
            if (ntfs::NtfsResolveData(*v, rec, &data) && data.valid)
            {
                size = data.size_bytes;
            }
        }
    }
    out->backend = VfsBackend::Ntfs;
    out->ntfs_block_handle = block_handle;
    out->ntfs_mft_reference = entry.mft_reference;
    out->ntfs_size_bytes = size;
    out->ntfs_is_dir = entry.is_directory;
    return true;
}

constinit VfsBackendOps g_ntfs_ops = {&NtfsLookup};

} // namespace

const VfsBackendOps* VfsBackendForFsType(FsType t)
{
    switch (t)
    {
    case FsType::Fat32:
        return &g_fat32_ops;
    case FsType::DuetFs:
        return &g_duetfs_ops;
    case FsType::RamVol:
        return &g_ramvol_ops;
    case FsType::Ext4:
        // Read backend registered; dispatch reaches Ext4Lookup. The
        // lookup performs real root-dir resolution but cannot yet
        // surface a tagged VfsNode (vfs.h owns the tag — see the STUB
        // on Ext4Lookup). The read path proper is exercised by
        // Ext4SelfTest on every boot.
        return &g_ext4_ops;
    case FsType::Ntfs:
        // Read backend registered; dispatch reaches NtfsLookup. The
        // lookup performs real root-dir resolution but cannot yet
        // surface a tagged VfsNode (vfs.h owns the tag — see the STUB
        // on NtfsLookup). The read path proper is exercised by
        // NtfsSelfTest on every boot.
        return &g_ntfs_ops;
    case FsType::Ramfs:
    default:
        // GAP: exFAT — the read lookup + the file-mutation API
        // (ExfatWriteInPlace / ExfatAppendInRoot / ExfatCreateInRoot /
        // ExfatTruncateInRoot in fs/exfat.cpp) are live and reachable
        // through the exfat:: registry, but exFAT has no `FsType`
        // member yet, so it cannot be VfsMount'd / dispatched here.
        // Revisit when an `FsType::Exfat` lands in fs/mount.h: add the
        // enum member + an `ExfatLookup` arm beside g_fat32_ops, the
        // same way FAT32 routes its VfsNode through the volume index.
        return nullptr;
    }
}

void VfsMountSelfTest()
{
    const u32 baseline = g_mount_count;
    // Round-trip: register, find, enumerate, unmount.
    const MountId a = VfsMount("/mnt/selftest-a", FsType::Fat32, 7);
    if (a == kInvalidMountId)
    {
        core::Panic("fs/mount", "self-test: register a failed");
    }
    if (g_mount_count != baseline + 1)
    {
        core::Panic("fs/mount", "self-test: count didn't advance after add");
    }
    const MountEntry* hit = VfsMountFind("/mnt/selftest-a");
    if (hit == nullptr || hit->fs_type != FsType::Fat32 || hit->block_handle != 7)
    {
        core::Panic("fs/mount", "self-test: find returned wrong entry");
    }
    // Reject duplicates.
    if (VfsMount("/mnt/selftest-a", FsType::Ext4, 9) != kInvalidMountId)
    {
        core::Panic("fs/mount", "self-test: duplicate mount accepted");
    }
    // Reject ramfs with a non-zero block handle.
    if (VfsMount("/mnt/selftest-bad", FsType::Ramfs, 1) != kInvalidMountId)
    {
        core::Panic("fs/mount", "self-test: ramfs+block_handle accepted");
    }
    // Reject non-ramfs without a block handle.
    if (VfsMount("/mnt/selftest-bad2", FsType::Fat32, 0) != kInvalidMountId)
    {
        core::Panic("fs/mount", "self-test: non-ramfs zero block_handle accepted");
    }
    // Reject malformed mount points.
    if (VfsMount("not-absolute", FsType::Fat32, 1) != kInvalidMountId)
    {
        core::Panic("fs/mount", "self-test: relative mount point accepted");
    }
    if (VfsMount("/", FsType::Fat32, 1) != kInvalidMountId)
    {
        core::Panic("fs/mount", "self-test: root single-slash mount point accepted");
    }
    // Longest-prefix resolution. Mount "/disk/0" + "/disk/0/SUB"
    // and verify a path under each routes to the correct one.
    const MountId rd0 = VfsMount("/disk/0", FsType::Fat32, 11);
    const MountId rd1 = VfsMount("/disk/0/SUB", FsType::Fat32, 12);
    if (rd0 == kInvalidMountId || rd1 == kInvalidMountId)
    {
        core::Panic("fs/mount", "self-test: resolver mounts failed");
    }
    const char* sub = nullptr;
    const MountEntry* r1 = VfsMountResolve("/disk/0/HELLO.TXT", &sub);
    if (r1 == nullptr || r1->block_handle != 11 || sub == nullptr || sub[0] != '/' || sub[1] != 'H')
    {
        core::Panic("fs/mount", "self-test: resolve /disk/0/HELLO.TXT");
    }
    const MountEntry* r2 = VfsMountResolve("/disk/0/SUB/INNER.TXT", &sub);
    if (r2 == nullptr || r2->block_handle != 12 || sub == nullptr || sub[0] != '/' || sub[1] != 'I')
    {
        core::Panic("fs/mount", "self-test: resolve longer-prefix /disk/0/SUB/...");
    }
    const MountEntry* vr = VfsMountResolveVisible(RamfsTrustedRoot(), "/disk/0/SUB/INNER.TXT", 64, &sub);
    if (vr == nullptr || vr->block_handle != 12 || sub == nullptr || sub[0] != '/' || sub[1] != 'I')
    {
        core::Panic("fs/mount", "self-test: visible resolver trusted longer-prefix");
    }
    if (VfsMountResolveVisible(RamfsSandboxRoot(), "/disk/0/SUB/INNER.TXT", 64, &sub) != nullptr || sub != nullptr)
    {
        core::Panic("fs/mount", "self-test: visible resolver exposed hidden mount");
    }
    // Component boundary: "/disk/01" must NOT match "/disk/0".
    if (VfsMountResolve("/disk/01/foo", &sub) != nullptr)
    {
        core::Panic("fs/mount", "self-test: resolver crossed component boundary");
    }
    // Exact-match: "/disk/0" should resolve, sub == "/".
    const MountEntry* r3 = VfsMountResolve("/disk/0", &sub);
    if (r3 == nullptr || sub == nullptr || sub[0] != '/' || sub[1] != '\0')
    {
        core::Panic("fs/mount", "self-test: exact-match resolve");
    }
    if (!VfsUmount(rd0) || !VfsUmount(rd1))
    {
        core::Panic("fs/mount", "self-test: resolver unmounts failed");
    }

    // Unmount + verify.
    if (!VfsUmount(a))
    {
        core::Panic("fs/mount", "self-test: unmount failed");
    }
    if (g_mount_count != baseline)
    {
        core::Panic("fs/mount", "self-test: count didn't decrement after umount");
    }
    if (VfsMountFind("/mnt/selftest-a") != nullptr)
    {
        core::Panic("fs/mount", "self-test: find returned stale entry post-umount");
    }
    if (VfsUmount(a))
    {
        core::Panic("fs/mount", "self-test: double unmount accepted");
    }
}

} // namespace duetos::fs
