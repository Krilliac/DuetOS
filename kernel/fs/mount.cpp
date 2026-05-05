#include "fs/mount.h"

#include "core/panic.h"
#include "log/klog.h"

namespace duetos::fs
{

namespace
{

constinit MountEntry g_mounts[kMaxMounts] = {};
constinit u32 g_mount_count = 0;
constinit u32 g_mount_seq = 1;

bool StrEq(const char* a, const char* b)
{
    if (a == nullptr || b == nullptr)
    {
        return false;
    }
    while (*a && *b)
    {
        if (*a != *b)
        {
            return false;
        }
        ++a;
        ++b;
    }
    return *a == *b;
}

u32 StrLen(const char* s)
{
    u32 n = 0;
    if (s != nullptr)
    {
        while (s[n])
        {
            ++n;
        }
    }
    return n;
}

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
    }
    return "unknown";
}

MountId VfsMount(const char* mount_point, FsType fs_type, u32 block_handle)
{
    if (!ValidMountPoint(mount_point))
    {
        return kInvalidMountId;
    }
    // ramfs is the in-tree synth backend — block_handle must be 0
    // for it; every other backend must have a real block handle.
    if (fs_type == FsType::Ramfs)
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
        if (g_mounts[i].in_use && StrEq(g_mounts[i].mount_point, mount_point))
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
        if (StrEq(g_mounts[i].mount_point, mount_point))
        {
            return &g_mounts[i];
        }
    }
    return nullptr;
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
