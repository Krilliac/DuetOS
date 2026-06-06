/*
 * DuetOS — kernel shell: filesystem I/O helpers.
 *
 * Sibling TU of shell.cpp. Houses the read-only file-to-buffer
 * + line-slicing helpers shared by every command that processes
 * file content (cat, sort, uniq, head, tail, wc, hexdump, stat,
 * tac, nl, checksum, source, exec, readelf, ...).
 *
 * Hoisted out of shell.cpp so the next round of command bucket
 * extractions has a public surface to share.
 */

#include "shell/shell_internal.h"

#include "fs/duetfs.h"
#include "fs/ext4.h"
#include "fs/fat32.h"
#include "fs/ntfs.h"
#include "fs/ramfs.h"
#include "fs/tmpfs.h"
#include "fs/vfs.h"

namespace duetos::core::shell::internal
{

// Read a tmpfs/ramfs file into a stack scratch buffer. Resolves
// either tmpfs (/tmp/<leaf>) or the read-only ramfs. Returns
// the number of bytes copied (up to `cap`) or u32 max on miss.
// Never dereferences a nullptr out buffer.
u32 ReadFileToBuf(const char* path, char* buf, u32 cap)
{
    if (path == nullptr || buf == nullptr || cap == 0)
    {
        return static_cast<u32>(-1);
    }
    if (const char* tmp_leaf = TmpLeaf(path); tmp_leaf != nullptr && *tmp_leaf != '\0')
    {
        const char* bytes = nullptr;
        u32 len = 0;
        if (!duetos::fs::TmpFsRead(tmp_leaf, &bytes, &len))
        {
            return static_cast<u32>(-1);
        }
        const u32 n = (len > cap) ? cap : len;
        for (u32 i = 0; i < n; ++i)
        {
            buf[i] = bytes[i];
        }
        return n;
    }
    // Everything else resolves through the one cross-mount path so
    // the line-processing commands (head/tail/grep/wc/sort/uniq/
    // stat/...) reach the same volumes `cat` does — ramfs, FAT32
    // disks at /disk/<idx> (and the /fat alias), and DuetFS.
    char alias_buf[256];
    const char* rpath = DiskAliasPath(path, alias_buf, sizeof(alias_buf));
    const duetos::fs::VfsNode v = duetos::fs::VfsResolve(duetos::fs::RamfsTrustedRoot(), rpath, sizeof(alias_buf));
    if (!duetos::fs::VfsNodeIsValid(v) || !duetos::fs::VfsNodeIsFile(v))
    {
        return static_cast<u32>(-1);
    }
    using duetos::fs::VfsBackend;
    if (v.backend == VfsBackend::Ramfs)
    {
        const u32 n = (v.ramfs->file_size > cap) ? cap : static_cast<u32>(v.ramfs->file_size);
        for (u32 i = 0; i < n; ++i)
        {
            buf[i] = static_cast<char>(v.ramfs->file_bytes[i]);
        }
        return n;
    }
    if (v.backend == VfsBackend::Fat32)
    {
        namespace fat = duetos::fs::fat32;
        const fat::Volume* vol = fat::Fat32Volume(v.fat32_volume_idx);
        if (vol == nullptr)
        {
            return static_cast<u32>(-1);
        }
        struct Ctx
        {
            char* buf;
            u32 cap;
            u32 used;
        };
        Ctx ctx{buf, cap, 0};
        const bool ok = fat::Fat32ReadFileStream(
            vol, &v.fat32_entry,
            [](const duetos::u8* data, duetos::u64 len, void* cx) -> bool
            {
                auto* c = static_cast<Ctx*>(cx);
                for (duetos::u64 i = 0; i < len && c->used < c->cap; ++i)
                {
                    c->buf[c->used++] = static_cast<char>(data[i]);
                }
                return c->used < c->cap; // stop streaming once full
            },
            &ctx);
        if (!ok && ctx.used == 0)
        {
            return static_cast<u32>(-1);
        }
        return ctx.used;
    }
    if (v.backend == VfsBackend::Ext4)
    {
        // ext4 read-only: re-derive the inode from its number (a stable
        // handle the VfsNode snapshotted), then stream the extent-mapped
        // body into `buf` clamped to `cap`.
        namespace ext4 = duetos::fs::ext4;
        const ext4::Volume* vol = ext4::Ext4VolumeByHandle(v.ext4_block_handle);
        if (vol == nullptr)
        {
            return static_cast<u32>(-1);
        }
        ext4::InodeInfo info{};
        if (!ext4::Ext4ReadInode(*vol, v.ext4_inode, &info))
        {
            return static_cast<u32>(-1);
        }
        duetos::u64 got = 0;
        if (!ext4::Ext4ReadFile(*vol, info, 0, buf, cap, &got))
        {
            return static_cast<u32>(-1);
        }
        return static_cast<u32>(got);
    }
    if (v.backend == VfsBackend::Ntfs)
    {
        // NTFS read-only: re-read the MFT record for the snapshotted
        // reference, apply the USA fixup, resolve $DATA, then stream the
        // body into `buf` clamped to `cap`.
        namespace ntfs = duetos::fs::ntfs;
        const ntfs::Volume* vol = ntfs::NtfsVolumeByHandle(v.ntfs_block_handle);
        if (vol == nullptr || vol->mft_record_size > ntfs::kMaxMftRecordSize)
        {
            return static_cast<u32>(-1);
        }
        duetos::u8 rec[ntfs::kMaxMftRecordSize];
        if (!ntfs::NtfsReadMftRecord(*vol, v.ntfs_mft_reference, rec))
        {
            return static_cast<u32>(-1);
        }
        ntfs::DataLocation data{};
        if (!ntfs::NtfsResolveData(*vol, rec, &data) || !data.valid)
        {
            return static_cast<u32>(-1);
        }
        duetos::u64 got = 0;
        if (!ntfs::NtfsReadFile(*vol, rec, data, 0, buf, cap, &got))
        {
            return static_cast<u32>(-1);
        }
        return static_cast<u32>(got);
    }
    if (v.backend != VfsBackend::DuetFs)
    {
        // RamVol / unknown backends have no streaming read path here.
        return static_cast<u32>(-1);
    }
    // DuetFS — read sequential chunks until the buffer is full or
    // the file ends.
    namespace df = duetos::fs::duetfs;
    const df::Device dev = df::DeviceForMountHandle(v.duetfs_block_handle);
    u32 used = 0;
    while (used < cap)
    {
        duetos::usize got = 0;
        const u32 st = df::duetfs_read_file(&dev, v.duetfs_node_id, used, buf + used, cap - used, &got);
        if (st != df::kStatusOk)
        {
            return used > 0 ? used : static_cast<u32>(-1);
        }
        if (got == 0)
        {
            break;
        }
        used += static_cast<u32>(got);
    }
    return used;
}

// Walk `scratch[0..n)` and populate `offs`/`lens` with one
// entry per line (excluding the terminating '\n'). Unterminated
// final line is counted. Returns number of lines written (capped).
u32 SliceLines(const char* scratch, u32 n, u32* offs, u32* lens, u32 cap)
{
    u32 count = 0;
    u32 start = 0;
    for (u32 i = 0; i <= n && count < cap; ++i)
    {
        const bool at_end = (i == n);
        if (at_end || scratch[i] == '\n')
        {
            offs[count] = start;
            lens[count] = i - start;
            ++count;
            start = i + 1;
        }
    }
    return count;
}

} // namespace duetos::core::shell::internal
