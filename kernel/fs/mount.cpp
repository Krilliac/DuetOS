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

// ext4 read backend. Resolves a name directly under the ext4 root
// directory; the read path it routes through (probe → group-desc →
// inode → root-dir enumerate → Ext4FindInRoot) lives in fs/ext4.cpp.
// `subpath` arrives volume-relative with a leading '/'.
//
// STUB: a successful resolve cannot yet surface a usable VfsNode.
//   vfs.h owns the `VfsBackend` enum + the `VfsNode` field set and is
//   outside this slice's file scope, so there is no `VfsBackend::Ext4`
//   tag nor an ext4 volume-idx/inode pair to populate. VfsResolve's
//   contract is "a `true` return leaves a backend-tagged node"; an
//   ext4 hit can't honour that, so this lookup always reports miss.
//   The real read path IS reachable and exercised on every boot via
//   Ext4SelfTest (probe → enumerate → Ext4ReadFile). To finish the
//   VFS wiring: add `VfsBackend::Ext4` + an `ext4_volume_idx` /
//   `ext4_dir_entry` pair to VfsNode in vfs.h, then fill out_node here
//   the way Fat32Lookup does and extend to multi-component path walks
//   via repeated Ext4ReadInode + dir enumerate.
bool Ext4Lookup(u32 block_handle, const char* subpath, void* out_node)
{
    (void)out_node;
    if (subpath == nullptr)
    {
        return false;
    }
    const ext4::Volume* v = ext4::Ext4VolumeByHandle(block_handle);
    if (v == nullptr)
    {
        return false;
    }
    // Strip leading slash(es). A bare "/" addresses the root dir; a
    // name addresses a direct child of root. We perform the real
    // resolution (it exercises the parsed root-dir snapshot) but, per
    // the STUB above, cannot surface a tagged VfsNode, so the result
    // is discarded and we always report miss until vfs.h grows an
    // ext4 backend tag.
    const char* name = subpath;
    while (*name == '/')
    {
        ++name;
    }
    if (*name != '\0')
    {
        ext4::Ext4DirEntry entry{};
        (void)ext4::Ext4FindInRoot(*v, name, &entry);
    }
    return false;
}

constinit VfsBackendOps g_ext4_ops = {&Ext4Lookup};

// NTFS read backend. Resolves a name directly under the NTFS root
// directory; the read path it routes through (probe → MFT record +
// USA fixup → $I30 INDEX_ROOT enumerate → NtfsFindInRoot → resolve
// $DATA → NtfsReadFile) lives in fs/ntfs.cpp. `subpath` arrives
// volume-relative with a leading '/'.
//
// STUB: identical limitation to Ext4Lookup — vfs.h owns the
//   `VfsBackend` enum + the `VfsNode` field set and is outside this
//   slice's file scope, so there is no `VfsBackend::Ntfs` tag nor an
//   NTFS volume-idx / MFT-reference pair to populate. VfsResolve's
//   contract is "a `true` return leaves a backend-tagged node"; an
//   NTFS hit can't honour that, so this lookup always reports miss.
//   The real read path IS reachable and exercised on every boot via
//   NtfsSelfTest (probe → enumerate → NtfsReadFile). To finish the
//   VFS wiring: add `VfsBackend::Ntfs` + an `ntfs_volume_idx` /
//   `ntfs_mft_reference` pair to VfsNode in vfs.h, then fill out_node
//   here the way Fat32Lookup does and extend to multi-component path
//   walks via repeated MFT-record read + $I30 enumerate.
bool NtfsLookup(u32 block_handle, const char* subpath, void* out_node)
{
    (void)out_node;
    if (subpath == nullptr)
    {
        return false;
    }
    const ntfs::Volume* v = ntfs::NtfsVolumeByHandle(block_handle);
    if (v == nullptr)
    {
        return false;
    }
    // Strip leading slash(es); a name addresses a direct child of the
    // root dir. We perform the real resolution (it exercises the
    // resident $I30 index walk) but, per the STUB above, cannot
    // surface a tagged VfsNode, so the result is discarded and we
    // report miss until vfs.h grows an NTFS backend tag.
    const char* name = subpath;
    while (*name == '/')
    {
        ++name;
    }
    if (*name != '\0')
    {
        ntfs::DirEntry entry{};
        (void)ntfs::NtfsFindInRoot(*v, name, &entry);
    }
    return false;
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
