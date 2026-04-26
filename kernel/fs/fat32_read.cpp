/*
 * DuetOS — FAT32 filesystem driver: file-content read APIs.
 *
 * Sibling to fat32.cpp (probe / dir / lookup) and fat32_write.cpp
 * (mutators). Houses the three read-side public entry points that
 * pull file bytes off disk via the cluster chain:
 *
 *   Fat32ReadFile        — bulk read from byte 0, capped at file size
 *   Fat32ReadAt          — offset-aware read for syscall cursors
 *   Fat32ReadFileStream  — cluster-by-cluster callback streaming
 *
 * All three consume the cross-TU primitives (g_scratch, Fat32Guard,
 * ReadFatEntry) declared in fat32_internal.h. Public fat32.h API
 * is unchanged — split is source-only.
 */

#include "fat32.h"

#include "../drivers/storage/block.h"
#include "fat32_internal.h"

namespace duetos::fs::fat32
{

using namespace internal;

i64 Fat32ReadFile(const Volume* v, const DirEntry* e, void* out, u64 max)
{
    Fat32Guard guard;
    if (v == nullptr || e == nullptr || out == nullptr)
        return -1;
    if (max == 0 || e->size_bytes == 0 || e->first_cluster < 2)
        return 0;

    // Cap the copy at the file's declared size — overruns would
    // bleed cluster slack (zero-padding or the next file's data)
    // into the caller's buffer, which callers never want.
    const u64 want = (e->size_bytes < max) ? u64(e->size_bytes) : max;
    const u64 cluster_bytes = u64(v->sectors_per_cluster) * u64(v->bytes_per_sector);
    u8* dst = static_cast<u8*>(out);
    u64 written = 0;
    u32 cluster = e->first_cluster;

    for (u32 step = 0; step < 65536; ++step)
    {
        if (cluster < 2 || cluster >= 0x0FFFFFF8u)
            break;
        const u64 lba = u64(v->data_start_sector) + u64(cluster - 2) * u64(v->sectors_per_cluster);
        const u64 need = want - written;
        if (need == 0)
            break;

        if (need >= cluster_bytes)
        {
            // Full-cluster transfer direct into caller's buffer —
            // no staging copy. Block-layer bounds-checks lba+count
            // against the partition's sector_count before dispatch.
            if (drivers::storage::BlockDeviceRead(v->block_handle, lba, v->sectors_per_cluster, dst + written) != 0)
            {
                return -1;
            }
            written += cluster_bytes;
        }
        else
        {
            // Partial last cluster — read into the shared scratch
            // page, then copy exactly `need` bytes out so the
            // caller's buffer is never over-filled.
            if (drivers::storage::BlockDeviceRead(v->block_handle, lba, v->sectors_per_cluster, g_scratch) != 0)
            {
                return -1;
            }
            for (u64 i = 0; i < need; ++i)
                dst[written + i] = g_scratch[i];
            written += need;
            break;
        }
        cluster = ReadFatEntry(*v, cluster);
    }
    return static_cast<i64>(written);
}

i64 Fat32ReadAt(const Volume* v, const DirEntry* e, u64 offset, void* out, u64 len)
{
    Fat32Guard guard;
    if (v == nullptr || e == nullptr || out == nullptr)
        return -1;
    if (len == 0)
        return 0;
    if (offset >= e->size_bytes || e->first_cluster < 2)
        return 0;

    const u64 max_readable = u64(e->size_bytes) - offset;
    const u64 want = (max_readable < len) ? max_readable : len;
    const u64 cluster_bytes = u64(v->sectors_per_cluster) * u64(v->bytes_per_sector);
    if (cluster_bytes == 0 || v->sectors_per_cluster > sizeof(g_scratch) / 512)
        return -1;

    // Walk the FAT chain forward to the cluster containing `offset`.
    // The skip loop is bounded by the same 65536 ceiling the bulk
    // read uses — a corrupt self-loop can't spin forever.
    const u64 skip_clusters = offset / cluster_bytes;
    u32 cluster = e->first_cluster;
    for (u64 i = 0; i < skip_clusters; ++i)
    {
        if (cluster < 2 || cluster >= 0x0FFFFFF8u)
            return -1;
        cluster = ReadFatEntry(*v, cluster);
    }

    auto* dst = static_cast<u8*>(out);
    u64 written = 0;
    u64 in_cluster_off = offset % cluster_bytes;

    for (u32 step = 0; step < 65536 && written < want; ++step)
    {
        if (cluster < 2 || cluster >= 0x0FFFFFF8u)
            break;
        const u64 lba = u64(v->data_start_sector) + u64(cluster - 2) * u64(v->sectors_per_cluster);
        if (drivers::storage::BlockDeviceRead(v->block_handle, lba, v->sectors_per_cluster, g_scratch) != 0)
            return -1;
        const u64 avail_in_cluster = cluster_bytes - in_cluster_off;
        const u64 need = want - written;
        const u64 take = (avail_in_cluster < need) ? avail_in_cluster : need;
        for (u64 i = 0; i < take; ++i)
            dst[written + i] = g_scratch[in_cluster_off + i];
        written += take;
        in_cluster_off = 0;
        cluster = ReadFatEntry(*v, cluster);
    }
    return static_cast<i64>(written);
}

bool Fat32ReadFileStream(const Volume* v, const DirEntry* e, ReadChunkCb cb, void* ctx)
{
    Fat32Guard guard;
    if (v == nullptr || e == nullptr || cb == nullptr)
        return false;
    if (e->size_bytes == 0 || e->first_cluster < 2)
        return true;

    const u64 cluster_bytes = u64(v->sectors_per_cluster) * u64(v->bytes_per_sector);
    u64 remaining = e->size_bytes;
    u32 cluster = e->first_cluster;

    for (u32 step = 0; step < 65536; ++step)
    {
        if (cluster < 2 || cluster >= 0x0FFFFFF8u)
            break;
        if (remaining == 0)
            break;
        if (v->sectors_per_cluster > sizeof(g_scratch) / 512)
            return false; // cluster bigger than our scratch page

        const u64 lba = u64(v->data_start_sector) + u64(cluster - 2) * u64(v->sectors_per_cluster);
        if (drivers::storage::BlockDeviceRead(v->block_handle, lba, v->sectors_per_cluster, g_scratch) != 0)
        {
            return false;
        }
        const u64 chunk = (remaining < cluster_bytes) ? remaining : cluster_bytes;
        if (!cb(g_scratch, chunk, ctx))
            return true; // caller asked us to stop — not an error
        remaining -= chunk;
        if (remaining == 0)
            break;
        // ReadFatEntry clobbers g_scratch; cb returned already so
        // the just-streamed bytes are safe to overwrite.
        cluster = ReadFatEntry(*v, cluster);
    }
    return true;
}

} // namespace duetos::fs::fat32
