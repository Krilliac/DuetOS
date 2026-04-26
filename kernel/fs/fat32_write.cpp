/*
 * DuetOS — FAT32 filesystem driver: file-content mutation path.
 *
 * Sibling to fat32_create.cpp (directory-mutation path) and the
 * read-side TUs (fat32.cpp / fat32_dir.cpp / fat32_lookup.cpp /
 * fat32_read.cpp). Houses the public Fat32* entries that mutate
 * existing files in place — write/append/truncate — plus the
 * private workers behind them.
 *
 * Cross-TU helpers shared with fat32_create.cpp (FAT-table
 * mutators, on-disk dir walker, free-slot finder, path resolver)
 * live below in `namespace duetos::fs::fat32::internal_write` and
 * are declared in fat32_write_internal.h. Read-side primitives
 * (g_scratch, Fat32Guard, ReadFatEntry, WalkDirChain, ...) come
 * from fat32_internal.h.
 */

#include "fs/fat32.h"

#include "diag/kdbg.h"
#include "log/klog.h"
#include "diag/log_names.h"
#include "drivers/storage/block.h"
#include "fs/fat32_internal.h"
#include "fs/fat32_write_internal.h"

namespace duetos::fs::fat32
{

using namespace internal;

namespace internal_write
{

// Write a FAT32 entry, preserving the top 4 reserved bits from
// whatever was there. Mirrors the update to BOTH FAT copies so
// the on-disk mirror stays in sync. Returns true on success.
bool WriteFatEntry(const Volume& v, u32 cluster, u32 value)
{
    const u32 byte_off = cluster * 4;
    const u32 sec_off = byte_off / v.bytes_per_sector;
    const u32 byte_in_sec = byte_off % v.bytes_per_sector;
    for (u32 copy = 0; copy < v.num_fats; ++copy)
    {
        const u64 lba = u64(v.reserved_sectors) + u64(copy) * u64(v.fat_size_sectors) + sec_off;
        if (drivers::storage::BlockDeviceRead(v.block_handle, lba, 1, g_scratch) != 0)
            return false;
        const u32 existing = LeU32(g_scratch + byte_in_sec);
        const u32 merged = (existing & 0xF0000000u) | (value & 0x0FFFFFFFu);
        g_scratch[byte_in_sec + 0] = static_cast<u8>(merged & 0xFF);
        g_scratch[byte_in_sec + 1] = static_cast<u8>((merged >> 8) & 0xFF);
        g_scratch[byte_in_sec + 2] = static_cast<u8>((merged >> 16) & 0xFF);
        g_scratch[byte_in_sec + 3] = static_cast<u8>((merged >> 24) & 0xFF);
        if (drivers::storage::BlockDeviceWrite(v.block_handle, lba, 1, g_scratch) != 0)
            return false;
    }
    return true;
}

// Find the lowest-numbered free cluster (FAT entry == 0), mark it
// as EOC in BOTH FAT copies, and return its number. Returns 0 on
// full-disk or I/O error. Capped at 1,000,000 clusters scanned so
// a pathological volume can't spin forever.
u32 AllocateFreeCluster(const Volume& v)
{
    const u32 entries_per_sector = v.bytes_per_sector / 4;
    const u32 max_fat_entries = v.fat_size_sectors * entries_per_sector;
    const u32 hard_cap = max_fat_entries < 1000000u ? max_fat_entries : 1000000u;
    for (u32 cluster = 2; cluster < hard_cap; ++cluster)
    {
        const u32 byte_off = cluster * 4;
        const u32 sec_off = byte_off / v.bytes_per_sector;
        const u32 byte_in_sec = byte_off % v.bytes_per_sector;
        const u64 lba = u64(v.reserved_sectors) + sec_off;
        if (drivers::storage::BlockDeviceRead(v.block_handle, lba, 1, g_scratch) != 0)
            return 0;
        const u32 entry = LeU32(g_scratch + byte_in_sec) & 0x0FFFFFFFu;
        if (entry == 0)
        {
            if (!WriteFatEntry(v, cluster, 0x0FFFFFFFu))
                return 0;
            return cluster;
        }
    }
    return 0;
}

// Overwrite a cluster's data sectors with zeros — called on newly
// allocated clusters so slack bytes beyond the caller-written
// region don't leak whatever was left on disk.
bool ZeroCluster(const Volume& v, u32 cluster)
{
    if (cluster < 2)
        return false;
    const u64 lba = u64(v.data_start_sector) + u64(cluster - 2) * u64(v.sectors_per_cluster);
    if (v.sectors_per_cluster > sizeof(g_scratch) / 512)
        return false;
    VZero(g_scratch, u64(v.sectors_per_cluster) * 512);
    return drivers::storage::BlockDeviceWrite(v.block_handle, lba, v.sectors_per_cluster, g_scratch) == 0;
}

// Walk every in-use SFN slot in the root and invoke `visit`.
// `visit` receives the absolute sector LBA, the 32-byte offset
// inside that sector, and a decoded DirEntry. Returning false
// stops the walk. LFN fragments, deleted, volume-id and dot
// entries are skipped. Used by find-by-name and find-free-slot.
// Separate from WalkDirChain because it exposes the on-disk
// address, which WalkDirChain intentionally hides.
using OnDiskSfnVisitor = bool (*)(u64 sector_lba, u32 off_in_sec, const u8* raw, const DirEntry& e, void* ctx);

bool WalkDirOnDisk(const Volume& v, u32 first_cluster, OnDiskSfnVisitor visit, void* ctx)
{
    // LFN accumulator — mirrors WalkDirChain so visitors see the
    // long name in DirEntry.name when one is present. Without
    // this, delete/truncate that target a long-named file would
    // compare against the SFN fallback (e.g. "MIXEDC~1.MD") and
    // never match the caller's long-form name.
    char pending_long[260];
    bool pending_any = false;
    VZero(pending_long, sizeof(pending_long));

    u32 cluster = first_cluster;
    for (u32 step = 0; step < 64; ++step)
    {
        if (cluster < 2 || cluster >= 0x0FFFFFF8u)
            return true;
        for (u32 sec = 0; sec < v.sectors_per_cluster; ++sec)
        {
            const u64 lba = u64(v.data_start_sector) + u64(cluster - 2) * u64(v.sectors_per_cluster) + sec;
            if (drivers::storage::BlockDeviceRead(v.block_handle, lba, 1, g_scratch) != 0)
                return false;
            for (u32 off = 0; off + 32 <= v.bytes_per_sector; off += 32)
            {
                const u8* e = g_scratch + off;
                if (e[0] == 0x00)
                    return true;
                if (e[0] == 0xE5)
                {
                    pending_any = false;
                    continue;
                }
                const u8 attr = e[11];
                if ((attr & kAttrLongName) == kAttrLongName)
                {
                    const u8 ord = static_cast<u8>(e[0] & 0x3F);
                    if (ord == 0 || ord > 20)
                    {
                        pending_any = false;
                        continue;
                    }
                    char chars[13];
                    for (u32 i = 0; i < 13; ++i)
                        chars[i] = 0;
                    bool terminated = false;
                    DecodeLfnChars(e, chars, &terminated);
                    const u32 base = u32(ord - 1) * 13;
                    for (u32 i = 0; i < 13; ++i)
                        pending_long[base + i] = chars[i];
                    pending_any = true;
                    continue;
                }
                if (attr & kAttrVolumeId)
                {
                    pending_any = false;
                    continue;
                }
                DirEntry decoded;
                DecodeEntry(e, decoded);
                if (IsDotEntry(decoded.name))
                {
                    pending_any = false;
                    continue;
                }
                if (pending_any)
                {
                    u32 n = 0;
                    while (n + 1 < sizeof(decoded.name) && pending_long[n] != 0)
                    {
                        decoded.name[n] = pending_long[n];
                        ++n;
                    }
                    decoded.name[n] = 0;
                }
                pending_any = false;
                VZero(pending_long, sizeof(pending_long));
                if (!visit(lba, off, e, decoded, ctx))
                    return true;
            }
        }
        cluster = ReadFatEntry(v, cluster);
    }
    return true;
}

// Find any slot suitable for a new SFN record. Preference:
//   (1) first 0xE5 (deleted) slot — reuses dir space.
//   (2) the 0x00 end-of-dir slot — extends the dir one entry.
// Returns true + fills sector/off when a slot is found.
bool FindFreeSlotInDir(const Volume& v, u32 first_cluster, u64* out_lba, u32* out_off)
{
    u32 cluster = first_cluster;
    for (u32 step = 0; step < 64; ++step)
    {
        if (cluster < 2 || cluster >= 0x0FFFFFF8u)
            return false;
        for (u32 sec = 0; sec < v.sectors_per_cluster; ++sec)
        {
            const u64 lba = u64(v.data_start_sector) + u64(cluster - 2) * u64(v.sectors_per_cluster) + sec;
            if (drivers::storage::BlockDeviceRead(v.block_handle, lba, 1, g_scratch) != 0)
                return false;
            for (u32 off = 0; off + 32 <= v.bytes_per_sector; off += 32)
            {
                const u8* e = g_scratch + off;
                if (e[0] == 0x00 || e[0] == 0xE5)
                {
                    *out_lba = lba;
                    *out_off = off;
                    return true;
                }
            }
        }
        cluster = ReadFatEntry(v, cluster);
    }
    return false;
}

// Free an entire cluster chain starting at `first_cluster`. Each
// FAT entry is zeroed (in both mirrors). Bounded at 65536
// clusters so a corrupted self-loop can't spin forever.
bool FreeClusterChain(const Volume& v, u32 first_cluster)
{
    u32 cluster = first_cluster;
    for (u32 step = 0; step < 65536; ++step)
    {
        if (cluster < 2 || cluster >= 0x0FFFFFF8u)
            return true;
        const u32 next = ReadFatEntry(v, cluster);
        if (!WriteFatEntry(v, cluster, 0))
            return false;
        cluster = next;
    }
    return true;
}

// Find an entry by name in `dir_cluster`, returning it by value.
// Unlike Fat32FindInRoot (which reads the cached snapshot), this
// walks fresh on-disk — subdirectories have no cache. Uses the
// generic WalkDirChain so LFN names resolve too.
bool FindInDirByName(const Volume& v, u32 dir_cluster, const char* want, DirEntry* out)
{
    struct Ctx
    {
        const char* want;
        DirEntry match;
        bool found;
    };
    Ctx ctx;
    ctx.want = want;
    ctx.found = false;
    VZero(&ctx.match, sizeof(ctx.match));

    WalkDirChain(
        v, dir_cluster,
        [](const DirEntry& e, void* cx) -> bool
        {
            auto* c = static_cast<Ctx*>(cx);
            if (NameIEqual(e.name, c->want))
            {
                CopyEntry(c->match, e);
                c->found = true;
                return false;
            }
            return true;
        },
        &ctx);
    if (!ctx.found)
        return false;
    CopyEntry(*out, ctx.match);
    return true;
}

// Resolve the parent directory for a path. On success fills
// `*out_parent_cluster` and copies the basename into `base_out`.
// Fails when any intermediate component is missing, not a
// directory, or the path is just "/" with no basename.
// Forward decl — SplitPath's body sits below but is called here.
bool SplitPath(const char* path, char* parent_out, u32 parent_cap, char* base_out, u32 base_cap);

bool ResolveParentDir(const Volume& v, const char* path, u32* out_parent_cluster, char* base_out, u32 base_cap)
{
    char parent_path[128];
    if (!SplitPath(path, parent_path, sizeof(parent_path), base_out, base_cap))
        return false;
    DirEntry parent;
    if (!Fat32LookupPath(&v, parent_path, &parent))
        return false;
    if ((parent.attributes & kAttrDirectory) == 0)
        return false;
    // Synthetic root returned by Fat32LookupPath("") has
    // first_cluster already set to v.root_cluster; subdirs carry
    // their on-disk first_cluster. Either way this is the cluster
    // we want for subsequent InDir ops.
    *out_parent_cluster = parent.first_cluster;
    return true;
}

// Split a volume-relative path into (parent_dir_path, basename).
// Both outputs are written into caller-supplied buffers. Examples:
//   "/FILE"          -> parent="",        base="FILE"
//   "FILE"           -> parent="",        base="FILE"
//   "/SUB/FILE"      -> parent="SUB",     base="FILE"
//   "/A/B/FILE"      -> parent="A/B",     base="FILE"
//   "/"              -> returns false (no basename)
// Trailing slashes are stripped.
bool SplitPath(const char* path, char* parent_out, u32 parent_cap, char* base_out, u32 base_cap)
{
    if (path == nullptr || parent_out == nullptr || base_out == nullptr)
        return false;
    // Skip leading slashes.
    while (*path == '/')
        ++path;
    // Length without trailing slashes.
    u32 n = 0;
    while (path[n] != 0)
        ++n;
    while (n > 0 && path[n - 1] == '/')
        --n;
    if (n == 0)
        return false;

    // Find the last slash in [0..n).
    u32 last_slash = 0xFFFFFFFFu;
    for (u32 i = n; i-- > 0;)
    {
        if (path[i] == '/')
        {
            last_slash = i;
            break;
        }
    }

    u32 parent_len = 0;
    u32 base_len = 0;
    if (last_slash == 0xFFFFFFFFu)
    {
        base_len = n;
        parent_len = 0;
    }
    else
    {
        parent_len = last_slash;
        base_len = n - last_slash - 1;
    }
    if (parent_len + 1 > parent_cap || base_len + 1 > base_cap || base_len == 0)
        return false;
    for (u32 i = 0; i < parent_len; ++i)
        parent_out[i] = path[i];
    parent_out[parent_len] = 0;
    for (u32 i = 0; i < base_len; ++i)
        base_out[i] = path[last_slash + 1 + i];
    base_out[base_len] = 0;
    return true;
}

// Find `count` consecutive unused entry slots in `dir_cluster`.
// v0 only looks at the 0x00 end-of-dir marker and its trailing
// 0x00 space; 0xE5 deleted slots in the middle are skipped. For
// a test image with plenty of slack after the seeded entries,
// this is a non-issue. Returns true + fills
// `out_first_lba` / `out_first_off`; `count` slots are known to
// be contiguous starting from that position. Caller is
// responsible for not running off the end of the cluster.
bool FindFreeRunInDir(const Volume& v, u32 dir_cluster, u32 count, u64* out_first_lba, u32* out_first_off)
{
    u32 cluster = dir_cluster;
    for (u32 step = 0; step < 64; ++step)
    {
        if (cluster < 2 || cluster >= 0x0FFFFFF8u)
            return false;
        for (u32 sec = 0; sec < v.sectors_per_cluster; ++sec)
        {
            const u64 lba = u64(v.data_start_sector) + u64(cluster - 2) * u64(v.sectors_per_cluster) + sec;
            if (drivers::storage::BlockDeviceRead(v.block_handle, lba, 1, g_scratch) != 0)
                return false;
            u32 first_zero = 0xFFFFFFFFu;
            for (u32 off = 0; off + 32 <= v.bytes_per_sector; off += 32)
            {
                if (g_scratch[off] != 0x00)
                    continue;
                if (first_zero == 0xFFFFFFFFu)
                    first_zero = off;
                // Require the run to fit inside THIS single sector.
                // PlantDirEntry / CreateInDir RMW one sector per
                // entry install; a run crossing a sector boundary
                // would silently truncate the half past byte 512.
                if (off + count * 32 > v.bytes_per_sector)
                    continue;
                *out_first_lba = lba;
                *out_first_off = off;
                return true;
            }
            // Reached end-of-sector without placing the run, but
            // there WAS a 0x00 slot in this sector. Walker treats
            // 0x00 at first-byte as "no more entries" — orphaning
            // everything we place in later sectors. Convert the
            // 0x00 tail to 0xE5 ("deleted, but valid entries may
            // follow") so the walker continues past. RMW the
            // sector in place.
            if (first_zero != 0xFFFFFFFFu)
            {
                bool dirtied = false;
                for (u32 off = first_zero; off + 32 <= v.bytes_per_sector; off += 32)
                {
                    if (g_scratch[off] == 0x00)
                    {
                        g_scratch[off] = 0xE5;
                        dirtied = true;
                    }
                }
                if (dirtied)
                {
                    if (drivers::storage::BlockDeviceWrite(v.block_handle, lba, 1, g_scratch) != 0)
                        return false;
                }
            }
        }
        cluster = ReadFatEntry(v, cluster);
    }
    return false;
}

// Find-or-grow: if the directory has no contiguous run of
// `count` free slots, allocate a new cluster, chain it to the
// directory's FAT chain, and return a slot at byte 0 of the new
// cluster. Cap: `count` must fit in one cluster — caller checks.
// Used by PlantDirEntry for LFN-sequence reservations; pure-SFN
// path still uses FindFreeSlotInDir (single-slot find never
// overflows).
bool ReserveRunInDir(const Volume& v, u32 dir_cluster, u32 count, u64* out_first_lba, u32* out_first_off)
{
    if (count == 0)
        return false;
    // Single-sector constraint: the write path RMWs one sector,
    // so a run cannot straddle two. Our LFN cap (11 frags + 1 SFN
    // = 12 slots = 384 bytes) fits trivially in a 512 B sector.
    if (count * 32u > v.bytes_per_sector)
        return false;
    if (FindFreeRunInDir(v, dir_cluster, count, out_first_lba, out_first_off))
        return true;

    // Walk to tail cluster, allocate + zero + chain.
    u32 tail = dir_cluster;
    for (u32 step = 0; step < 64; ++step)
    {
        const u32 next = ReadFatEntry(v, tail);
        if (next < 2 || next >= 0x0FFFFFF8u)
            break;
        tail = next;
    }
    const u32 fresh = AllocateFreeCluster(v);
    if (fresh == 0)
        return false;
    if (!ZeroCluster(v, fresh))
        return false;
    if (!WriteFatEntry(v, tail, fresh))
    {
        // Best-effort rollback: mark the fresh cluster free again.
        FreeClusterChain(v, fresh);
        return false;
    }
    *out_first_lba = u64(v.data_start_sector) + u64(fresh - 2) * u64(v.sectors_per_cluster);
    *out_first_off = 0;
    return true;
}

} // namespace internal_write

using namespace internal_write;

namespace
{

// Find a root-directory entry by name and patch its 32-bit size
// field (bytes 28..31) with the new value, then write the
// containing sector back. Returns true on success, false on miss
// or I/O error. Only touches the size field — other fields
// (first_cluster, attrs, times) are preserved.
bool UpdateEntrySizeInDir(const Volume& v, u32 first_cluster, const char* want, u32 new_size)
{
    KDBG_3V(Fat32Walker, "fs/fat32", "UpdateEntrySizeInDir enter", "first_cluster", first_cluster, "want_first_byte",
            want != nullptr ? static_cast<u64>(static_cast<u8>(want[0])) : 0u, "new_size", new_size);
    u32 cluster = first_cluster;
    // Bounded like the other walkers — 64 clusters covers any
    // realistic directory.
    for (u32 step = 0; step < 64; ++step)
    {
        if (cluster < 2 || cluster >= 0x0FFFFFF8u)
        {
            KDBG_2V(Fat32Walker, "fs/fat32", "walk halt", "step", step, "cluster", cluster);
            return false;
        }
        const u32 bytes = v.sectors_per_cluster * v.bytes_per_sector;
        // Read the cluster one sector at a time so we can find the
        // entry, patch it in the scratch copy, and write JUST that
        // sector back. Whole-cluster write would be wasteful and
        // risk clobbering a concurrent writer's scratch staging
        // (though v0 is single-threaded on the shell path).
        for (u32 sec = 0; sec < v.sectors_per_cluster; ++sec)
        {
            const u64 lba = u64(v.data_start_sector) + u64(cluster - 2) * u64(v.sectors_per_cluster) + sec;
            const i32 rd_rc = drivers::storage::BlockDeviceRead(v.block_handle, lba, 1, g_scratch);
            KDBG_4V(Fat32Walker, "fs/fat32", "post-read", "lba", lba, "rd_rc", static_cast<u64>(rd_rc), "g0",
                    static_cast<u64>(g_scratch[0]), "g32", static_cast<u64>(g_scratch[32]));
            if (rd_rc != 0)
                return false;
            const u32 bytes_in_sec = v.bytes_per_sector;
            for (u32 off = 0; off + 32 <= bytes_in_sec; off += 32)
            {
                const u8* e = g_scratch + off;
                KDBG_3V(Fat32Walker, "fs/fat32", "visit", "off", off, "e0", static_cast<u64>(e[0]), "e11",
                        static_cast<u64>(e[11]));
                if (e[0] == 0x00)
                    return false; // end of dir — not found
                if (e[0] == 0xE5)
                    continue;
                const u8 attr = e[11];
                if ((attr & kAttrLongName) == kAttrLongName)
                    continue;
                if (attr & kAttrVolumeId)
                    continue;
                DirEntry decoded;
                DecodeEntry(e, decoded);
                if (IsDotEntry(decoded.name))
                    continue;
                KDBG_S(Fat32Walker, "fs/fat32", "entry", "name", decoded.name);
                // Match on the SFN only — LFN matching would need
                // us to accumulate fragments here too, which v0
                // append doesn't need (HELLO.TXT in the self-test
                // has no LFN). Upgrade when a long-named callee
                // needs resize.
                if (NameIEqual(decoded.name, want))
                {
                    g_scratch[off + 28] = static_cast<u8>(new_size & 0xFF);
                    g_scratch[off + 29] = static_cast<u8>((new_size >> 8) & 0xFF);
                    g_scratch[off + 30] = static_cast<u8>((new_size >> 16) & 0xFF);
                    g_scratch[off + 31] = static_cast<u8>((new_size >> 24) & 0xFF);
                    return drivers::storage::BlockDeviceWrite(v.block_handle, lba, 1, g_scratch) == 0;
                }
            }
            (void)bytes;
        }
        cluster = ReadFatEntry(v, cluster);
    }
    return false;
}

// Find the sector LBA + offset of the root-dir SFN entry whose
// decoded name matches `want` (case-insensitive). Returns false
// if not found or on I/O error.
bool FindEntryLbaInDir(const Volume& v, u32 first_cluster, const char* want, u64* out_lba, u32* out_off)
{
    struct Ctx
    {
        const char* want;
        u64 lba;
        u32 off;
        bool found;
    };
    Ctx ctx{want, 0, 0, false};
    const bool walk_ok = WalkDirOnDisk(
        v, first_cluster,
        [](u64 lba, u32 off, const u8* raw, const DirEntry& e, void* cx) -> bool
        {
            (void)raw;
            auto* c = static_cast<Ctx*>(cx);
            if (NameIEqual(e.name, c->want))
            {
                c->lba = lba;
                c->off = off;
                c->found = true;
                return false;
            }
            return true;
        },
        &ctx);
    if (!walk_ok || !ctx.found)
        return false;
    *out_lba = ctx.lba;
    *out_off = ctx.off;
    return true;
}

// Internal worker used by Fat32AppendInRoot and Fat32AppendAtPath.
// `dir_cluster` names the directory the entry lives in; the caller
// has already resolved it.
i64 AppendInDir(const Volume* v, u32 dir_cluster, const char* name, const void* buf, u64 len)
{
    if (v == nullptr || name == nullptr || buf == nullptr)
        return -1;
    if (len == 0)
        return 0;

    KDBG_2V(Fat32Append, "fs/fat32", "AppendInDir enter", "dir_cluster", dir_cluster, "len", len);
    DirEntry e_val;
    if (!FindInDirByName(*v, dir_cluster, name, &e_val))
    {
        KDBG_S(Fat32Append, "fs/fat32", "AppendInDir target missing", "name", name);
        return -1;
    }
    const DirEntry* e = &e_val;
    if (e->attributes & kAttrDirectory)
        return -1; // append-to-directory is nonsensical
    if (e->first_cluster < 2)
        return -1; // zero-byte files are not supported in v0

    const u64 cluster_bytes = u64(v->sectors_per_cluster) * u64(v->bytes_per_sector);
    if (v->sectors_per_cluster > sizeof(g_scratch) / 512)
        return -1;
    const u32 old_size = e->size_bytes;
    const u64 new_size_u64 = u64(old_size) + len;
    if (new_size_u64 > 0xFFFFFFFFull)
        return -1; // FAT32 size field is 32-bit
    const u32 new_size = static_cast<u32>(new_size_u64);

    // Walk the existing chain to the tail cluster so we know
    // where to append and whether the tail has slack bytes.
    u32 tail = e->first_cluster;
    while (true)
    {
        const u32 next = ReadFatEntry(*v, tail);
        if (next < 2 || next >= 0x0FFFFFF8u)
            break;
        tail = next;
    }
    // Byte offset within the tail cluster where the NEXT byte of
    // file content would land. If the file ends exactly on a
    // cluster boundary, tail_off == 0 and we must allocate a new
    // cluster immediately.
    u64 tail_off = old_size % cluster_bytes;
    if (tail_off == 0 && old_size > 0)
    {
        // File ended on a cluster boundary — the "tail" cluster
        // has no slack; grab a fresh one before the write loop.
        const u32 fresh = AllocateFreeCluster(*v);
        if (fresh == 0)
            return -1;
        if (!ZeroCluster(*v, fresh))
            return -1;
        if (!WriteFatEntry(*v, tail, fresh))
            return -1;
        tail = fresh;
        tail_off = 0;
    }

    const auto* src = static_cast<const u8*>(buf);
    u64 written = 0;
    while (written < len)
    {
        const u64 remain = len - written;
        const u64 avail = cluster_bytes - tail_off;
        const u64 chunk = (remain < avail) ? remain : avail;
        const u64 lba = u64(v->data_start_sector) + u64(tail - 2) * u64(v->sectors_per_cluster);

        if (tail_off == 0 && chunk == cluster_bytes)
        {
            // Full-cluster append, no read-modify-write.
            for (u64 i = 0; i < chunk; ++i)
                g_scratch[i] = src[written + i];
            if (drivers::storage::BlockDeviceWrite(v->block_handle, lba, v->sectors_per_cluster, g_scratch) != 0)
                return -1;
        }
        else
        {
            // Partial append: read cluster, patch tail portion,
            // write back. Covers both the first-cluster-with-slack
            // case and the final-cluster-partial case.
            if (drivers::storage::BlockDeviceRead(v->block_handle, lba, v->sectors_per_cluster, g_scratch) != 0)
                return -1;
            for (u64 i = 0; i < chunk; ++i)
                g_scratch[tail_off + i] = src[written + i];
            if (drivers::storage::BlockDeviceWrite(v->block_handle, lba, v->sectors_per_cluster, g_scratch) != 0)
                return -1;
        }
        written += chunk;
        tail_off += chunk;
        if (written == len)
            break;
        // Need another cluster. Allocate, zero, and chain.
        const u32 fresh = AllocateFreeCluster(*v);
        if (fresh == 0)
            return -1;
        if (!ZeroCluster(*v, fresh))
            return -1;
        if (!WriteFatEntry(*v, tail, fresh))
            return -1;
        tail = fresh;
        tail_off = 0;
    }

    // Patch the on-disk directory entry's size field. Without this
    // the appended bytes exist on disk but readers stop at the old
    // size and never see them. Failure here is dangerous — the
    // file's on-disk cluster chain is longer than its declared
    // size. Log + fail hard; caller should treat the volume as
    // potentially inconsistent (v0 has no journal to roll back).
    if (!UpdateEntrySizeInDir(*v, dir_cluster, name, new_size))
    {
        core::Log(core::LogLevel::Error, "fs/fat32", "append: cluster chain extended but dir entry size update failed");
        // Forensic dump of the dir cluster's first sector — only
        // emitted when Fat32Append channel is on, so the normal
        // boot log isn't polluted on every flake.
        if (KDBG_ON(Fat32Append))
        {
            const u64 lba0 = u64(v->data_start_sector) + u64(dir_cluster - 2) * u64(v->sectors_per_cluster);
            if (drivers::storage::BlockDeviceRead(v->block_handle, lba0, 1, g_scratch) == 0)
            {
                for (u32 slot = 0; slot < 16; ++slot)
                {
                    core::DbgEmit3V(core::DbgChannel::Fat32Append, "fs/fat32", "dump-slot", "off", slot * 32u, "first",
                                    static_cast<u64>(g_scratch[slot * 32]), "attr",
                                    static_cast<u64>(g_scratch[slot * 32 + 11]));
                }
            }
        }
        return -1;
    }

    // Refresh the cached root snapshot when the target IS the root
    // — subdirs don't have a cache, so no-op there.
    if (dir_cluster == v->root_cluster)
    {
        Volume* vm = const_cast<Volume*>(v);
        WalkRootIntoSnapshot(*vm, vm->root_cluster);
    }

    return static_cast<i64>(written);
}

i64 TruncateInDir(const Volume* v, u32 dir_cluster, const char* name, u64 new_size)
{
    if (v == nullptr || name == nullptr)
        return -1;
    if (new_size > 0xFFFFFFFFu)
        return -1;

    DirEntry e_val;
    if (!FindInDirByName(*v, dir_cluster, name, &e_val))
        return -1;
    const DirEntry* e = &e_val;
    if (e->attributes & kAttrDirectory)
        return -1;
    const u64 old_size = e->size_bytes;
    if (new_size == old_size)
        return static_cast<i64>(new_size);

    if (new_size > old_size)
    {
        // Growth: append zero bytes. Simplest, matches spec (FAT32
        // has no sparse semantics, so the tail is materialised).
        const u64 grow = new_size - old_size;
        // Budget our zero buffer at 1 KiB chunks — cluster_bytes
        // is never more than 4 KiB in our test image, fits fine.
        static u8 zeros[1024];
        VZero(zeros, sizeof(zeros));
        u64 remain = grow;
        if (e->first_cluster < 2)
            return -1; // can't grow a truly-empty file in v0
        while (remain > 0)
        {
            const u64 chunk = (remain < sizeof(zeros)) ? remain : sizeof(zeros);
            const i64 a = AppendInDir(v, dir_cluster, name, zeros, chunk);
            if (a != static_cast<i64>(chunk))
                return -1;
            remain -= chunk;
        }
        return static_cast<i64>(new_size);
    }

    // Shrink: walk to the cluster containing byte (new_size - 1),
    // mark it EOC, free the rest. Special case new_size == 0:
    // release first_cluster too and zero it in the dir entry.
    const u64 cluster_bytes = u64(v->sectors_per_cluster) * u64(v->bytes_per_sector);
    if (new_size == 0)
    {
        // Free the whole chain, then patch the dir entry to
        // size=0, first_cluster=0.
        if (e->first_cluster >= 2)
        {
            if (!FreeClusterChain(*v, e->first_cluster))
                return -1;
        }
        u64 flba = 0;
        u32 foff = 0;
        if (!FindEntryLbaInDir(*v, dir_cluster, name, &flba, &foff))
            return -1;
        if (drivers::storage::BlockDeviceRead(v->block_handle, flba, 1, g_scratch) != 0)
            return -1;
        g_scratch[foff + 20] = 0;
        g_scratch[foff + 21] = 0;
        g_scratch[foff + 26] = 0;
        g_scratch[foff + 27] = 0;
        g_scratch[foff + 28] = 0;
        g_scratch[foff + 29] = 0;
        g_scratch[foff + 30] = 0;
        g_scratch[foff + 31] = 0;
        if (drivers::storage::BlockDeviceWrite(v->block_handle, flba, 1, g_scratch) != 0)
            return -1;
        if (dir_cluster == v->root_cluster)
        {
            Volume* vm = const_cast<Volume*>(v);
            WalkRootIntoSnapshot(*vm, vm->root_cluster);
        }
        return 0;
    }

    // Non-zero shrink.
    const u64 keep_clusters = (new_size + cluster_bytes - 1) / cluster_bytes;
    u32 cluster = e->first_cluster;
    for (u64 i = 1; i < keep_clusters; ++i)
    {
        const u32 next = ReadFatEntry(*v, cluster);
        if (next < 2 || next >= 0x0FFFFFF8u)
            return -1;
        cluster = next;
    }
    const u32 first_to_free = ReadFatEntry(*v, cluster);
    if (!WriteFatEntry(*v, cluster, 0x0FFFFFFFu))
        return -1;
    if (first_to_free >= 2 && first_to_free < 0x0FFFFFF8u)
    {
        if (!FreeClusterChain(*v, first_to_free))
            return -1;
    }
    if (!UpdateEntrySizeInDir(*v, dir_cluster, name, static_cast<u32>(new_size)))
        return -1;
    if (dir_cluster == v->root_cluster)
    {
        Volume* vm = const_cast<Volume*>(v);
        WalkRootIntoSnapshot(*vm, vm->root_cluster);
    }
    return static_cast<i64>(new_size);
}

} // namespace

i64 Fat32WriteInPlace(const Volume* v, const DirEntry* e, u64 offset, const void* buf, u64 len)
{
    Fat32Guard guard;
    if (v == nullptr || e == nullptr || buf == nullptr)
        return -1;
    if (len == 0)
        return 0;
    if (offset > e->size_bytes || offset + len > u64(e->size_bytes))
        return -1; // write would extend the file; not supported in v0
    if (e->first_cluster < 2)
        return -1;

    const u64 cluster_bytes = u64(v->sectors_per_cluster) * u64(v->bytes_per_sector);
    if (v->sectors_per_cluster > sizeof(g_scratch) / 512)
        return -1; // cluster wider than scratch page
    const auto* src = static_cast<const u8*>(buf);

    // Phase 1: walk to the cluster containing `offset`.
    u32 cluster = e->first_cluster;
    u64 cluster_idx = offset / cluster_bytes;
    for (u64 i = 0; i < cluster_idx; ++i)
    {
        cluster = ReadFatEntry(*v, cluster);
        if (cluster < 2 || cluster >= 0x0FFFFFF8u)
            return -1; // chain ended early — filesystem corrupt
    }

    u64 written = 0;
    u64 in_cluster_off = offset - cluster_idx * cluster_bytes;

    // Phase 2: write one cluster at a time. Three cases:
    //   (a) full cluster — write without read-modify-write
    //   (b) partial cluster head / tail — read-modify-write via g_scratch
    while (written < len)
    {
        if (cluster < 2 || cluster >= 0x0FFFFFF8u)
            return -1;
        const u64 lba = u64(v->data_start_sector) + u64(cluster - 2) * u64(v->sectors_per_cluster);
        const u64 remain = len - written;
        const u64 avail = cluster_bytes - in_cluster_off;
        const u64 chunk = (remain < avail) ? remain : avail;

        if (in_cluster_off == 0 && chunk == cluster_bytes)
        {
            // Case (a): full-cluster overwrite. Stage through
            // scratch (the caller's buffer may not be contiguous
            // in physical memory — block layer wants a direct-map
            // alias, which g_scratch always is).
            for (u64 i = 0; i < chunk; ++i)
                g_scratch[i] = src[written + i];
            if (drivers::storage::BlockDeviceWrite(v->block_handle, lba, v->sectors_per_cluster, g_scratch) != 0)
                return -1;
        }
        else
        {
            // Case (b): read-modify-write. Read cluster, patch the
            // in-range bytes, write back. Only touches [in_cluster_off,
            // in_cluster_off+chunk) — the rest stays whatever the
            // filesystem already had.
            if (drivers::storage::BlockDeviceRead(v->block_handle, lba, v->sectors_per_cluster, g_scratch) != 0)
                return -1;
            for (u64 i = 0; i < chunk; ++i)
                g_scratch[in_cluster_off + i] = src[written + i];
            if (drivers::storage::BlockDeviceWrite(v->block_handle, lba, v->sectors_per_cluster, g_scratch) != 0)
                return -1;
        }

        written += chunk;
        if (written == len)
            break;
        // Advance to the next cluster. g_scratch gets clobbered by
        // ReadFatEntry, which is fine — we've already issued the
        // write for this cluster.
        cluster = ReadFatEntry(*v, cluster);
        in_cluster_off = 0;
    }

    return static_cast<i64>(written);
}

i64 Fat32AppendInRoot(const Volume* v, const char* name, const void* buf, u64 len)
{
    Fat32Guard guard;
    if (v == nullptr)
        return -1;
    return AppendInDir(v, v->root_cluster, name, buf, len);
}

i64 Fat32AppendAtPath(const Volume* v, const char* path, const void* buf, u64 len)
{
    Fat32Guard guard;
    if (v == nullptr || path == nullptr)
        return -1;
    u32 parent_cluster = 0;
    char basename[64];
    if (!ResolveParentDir(*v, path, &parent_cluster, basename, sizeof(basename)))
        return -1;
    return AppendInDir(v, parent_cluster, basename, buf, len);
}

i64 Fat32TruncateInRoot(const Volume* v, const char* name, u64 new_size)
{
    Fat32Guard guard;
    if (v == nullptr)
        return -1;
    return TruncateInDir(v, v->root_cluster, name, new_size);
}

i64 Fat32TruncateAtPath(const Volume* v, const char* path, u64 new_size)
{
    Fat32Guard guard;
    if (v == nullptr || path == nullptr)
        return -1;
    u32 parent_cluster = 0;
    char basename[64];
    if (!ResolveParentDir(*v, path, &parent_cluster, basename, sizeof(basename)))
        return -1;
    return TruncateInDir(v, parent_cluster, basename, new_size);
}

} // namespace duetos::fs::fat32
