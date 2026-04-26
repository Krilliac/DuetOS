/*
 * DuetOS — FAT32 filesystem driver: mutating path.
 *
 * Companion to fat32.cpp (read side). Houses every public Fat32*
 * entry that changes on-disk state plus the private helpers they
 * depend on — write-FAT-entry, free-cluster scan, on-disk SFN
 * walker, LFN encoder, slot reservation, and the per-operation
 * workers (CreateInDir / DeleteInDir / TruncateInDir / etc.).
 *
 * The TU shares the read-side primitives (g_scratch, Fat32Guard,
 * ReadCluster/ReadFatEntry, WalkDirChain, WalkRootIntoSnapshot)
 * via fat32_internal.h. Public API surface is unchanged — split is
 * source-only.
 *
 * Out of scope: free-cluster bitmap caching, FSInfo updates,
 * journaling, subdirectory growth past one cluster.
 */

#include "fat32.h"

#include "../core/kdbg.h"
#include "../core/klog.h"
#include "../core/log_names.h"
#include "../drivers/storage/block.h"
#include "fat32_internal.h"

namespace duetos::fs::fat32
{

using namespace internal;

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

namespace
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

// Convert user-supplied "NAME.EXT" into the 11-byte space-padded
// uppercase 8.3 form FAT32 stores on disk. Returns true on success
// and fills `out_11`; false if the name is invalid (base > 8 chars,
// ext > 3 chars, reserved initial char 0x00 / 0xE5, or contains a
// disallowed character).
bool MakeSfn(const char* name, u8* out_11)
{
    if (name == nullptr || name[0] == 0)
        return false;
    for (u32 i = 0; i < 11; ++i)
        out_11[i] = ' ';
    // Split at the LAST '.' — FAT doesn't support multiple dots
    // (spec forbids them in SFN), but users may type "a.b.c". We
    // reject multi-dot for now; operator can rename.
    u32 dot_pos = 0xFFFFFFFFu;
    u32 n = 0;
    while (name[n] != 0)
        ++n;
    for (u32 i = 0; i < n; ++i)
    {
        if (name[i] == '.')
        {
            if (dot_pos != 0xFFFFFFFFu)
                return false; // multiple dots
            dot_pos = i;
        }
    }
    const u32 base_len = (dot_pos == 0xFFFFFFFFu) ? n : dot_pos;
    const u32 ext_len = (dot_pos == 0xFFFFFFFFu) ? 0 : (n - dot_pos - 1);
    if (base_len == 0 || base_len > 8 || ext_len > 3)
        return false;

    auto to_sfn_char = [](char c) -> int
    {
        if (c >= 'a' && c <= 'z')
            c = static_cast<char>(c - 32);
        // Permitted: A-Z 0-9 and "!#$%&'()-@^_`{}~" (subset; spec is
        // wider). Space inside a name is not allowed — would confuse
        // the padding.
        if (c >= 'A' && c <= 'Z')
            return static_cast<u8>(c);
        if (c >= '0' && c <= '9')
            return static_cast<u8>(c);
        const char kExtra[] = "!#$%&'()-@^_`{}~";
        for (u32 i = 0; kExtra[i] != 0; ++i)
            if (c == kExtra[i])
                return static_cast<u8>(c);
        return -1;
    };

    for (u32 i = 0; i < base_len; ++i)
    {
        const int ch = to_sfn_char(name[i]);
        if (ch < 0)
            return false;
        out_11[i] = static_cast<u8>(ch);
    }
    for (u32 i = 0; i < ext_len; ++i)
    {
        const int ch = to_sfn_char(name[dot_pos + 1 + i]);
        if (ch < 0)
            return false;
        out_11[8 + i] = static_cast<u8>(ch);
    }
    // Spec forbids 0x00 / 0xE5 as the first byte — 0xE5 collides
    // with the deletion marker; 0x05 is the escape in the SFN
    // record for a legitimate 0xE5 first char. v0 rejects rather
    // than escaping.
    if (out_11[0] == 0x00 || out_11[0] == 0xE5)
        return false;
    return true;
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

} // namespace

namespace
{
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

// Detects whether an input name requires an LFN sequence to
// round-trip losslessly: any lowercase, any multi-dot, any
// length > 8 base or > 3 ext, or any char outside the narrow SFN
// character set. If this returns false, MakeSfn succeeds and the
// input equals its 8.3 form (case-lost but spec-compliant).
bool NeedsLfn(const char* name)
{
    if (name == nullptr || name[0] == 0)
        return false;
    u32 n = 0;
    while (name[n] != 0)
        ++n;
    u32 dot_count = 0;
    for (u32 i = 0; i < n; ++i)
        if (name[i] == '.')
            ++dot_count;
    if (dot_count > 1)
        return true;

    // Any lowercase -> need LFN for case preservation.
    for (u32 i = 0; i < n; ++i)
        if (name[i] >= 'a' && name[i] <= 'z')
            return true;

    // Length check 8.3.
    u32 dot_pos = 0xFFFFFFFFu;
    for (u32 i = 0; i < n; ++i)
        if (name[i] == '.')
        {
            dot_pos = i;
            break;
        }
    const u32 base_len = (dot_pos == 0xFFFFFFFFu) ? n : dot_pos;
    const u32 ext_len = (dot_pos == 0xFFFFFFFFu) ? 0 : (n - dot_pos - 1);
    if (base_len > 8 || ext_len > 3)
        return true;
    return false;
}

// FAT LFN checksum of the 11-byte SFN. Spec algorithm — rotates
// right then adds the byte.
u8 SfnChecksum(const u8* sfn11)
{
    u8 sum = 0;
    for (u32 i = 0; i < 11; ++i)
    {
        sum = static_cast<u8>((((sum & 1) ? 0x80 : 0) + (sum >> 1) + sfn11[i]) & 0xFF);
    }
    return sum;
}

// Generate a unique "BASE~N.EXT" short name for the given long
// name within `dir_cluster`. Picks up to 6 SFN-legal characters
// of the base and up to 3 of the extension, then tries numeric
// tails 1..9. Returns false if no free tail in that range.
bool GenerateUniqueSfn(const Volume& v, u32 dir_cluster, const char* long_name, u8* out_sfn_11)
{
    auto sfn_safe = [](char c) -> int
    {
        if (c >= 'a' && c <= 'z')
            c = static_cast<char>(c - 32);
        if ((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))
            return static_cast<u8>(c);
        const char kExtra[] = "!#$%&'()-@^_`{}~";
        for (u32 i = 0; kExtra[i] != 0; ++i)
            if (c == kExtra[i])
                return static_cast<u8>(c);
        return -1;
    };

    // Split long_name at the LAST '.'.
    u32 n = 0;
    while (long_name[n] != 0)
        ++n;
    u32 last_dot = 0xFFFFFFFFu;
    for (u32 i = n; i-- > 0;)
        if (long_name[i] == '.')
        {
            last_dot = i;
            break;
        }
    const u32 base_end = (last_dot == 0xFFFFFFFFu) ? n : last_dot;

    // Pack first 6 safe chars of base into out_sfn_11[0..5].
    u8 base_chars[6];
    u32 bi = 0;
    for (u32 i = 0; i < base_end && bi < 6; ++i)
    {
        const int c = sfn_safe(long_name[i]);
        if (c < 0)
            continue;
        base_chars[bi++] = static_cast<u8>(c);
    }
    // Ext: first 3 safe chars after last '.'.
    u8 ext_chars[3] = {' ', ' ', ' '};
    u32 ei = 0;
    if (last_dot != 0xFFFFFFFFu)
    {
        for (u32 i = last_dot + 1; i < n && ei < 3; ++i)
        {
            const int c = sfn_safe(long_name[i]);
            if (c < 0)
                continue;
            ext_chars[ei++] = static_cast<u8>(c);
        }
    }
    if (bi == 0 && ei == 0)
        return false; // nothing left after filtering — reject.

    for (u32 tail = 1; tail <= 9; ++tail)
    {
        for (u32 i = 0; i < 11; ++i)
            out_sfn_11[i] = ' ';
        for (u32 i = 0; i < bi; ++i)
            out_sfn_11[i] = base_chars[i];
        out_sfn_11[bi] = '~';
        out_sfn_11[bi + 1] = static_cast<u8>('0' + tail);
        for (u32 i = 0; i < 3; ++i)
            out_sfn_11[8 + i] = ext_chars[i];
        // Check for duplicate. Render to human form for case-insensitive
        // compare — the existing FindInDirByName wants that form.
        char human[13];
        FormatShortName(out_sfn_11, human);
        DirEntry tmp;
        if (!FindInDirByName(v, dir_cluster, human, &tmp))
            return true; // unused tail found
    }
    return false;
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

// Encode one LFN fragment into `out_32`. `chunk` holds up to 13
// ASCII chars; chunks shorter than 13 get a 0x0000 terminator at
// position `chunk_len` and 0xFFFF padding beyond.
void EncodeLfnFragment(const char* chunk, u32 chunk_len, u8 ordinal, bool is_last, u8 checksum, u8* out_32)
{
    VZero(out_32, 32);
    out_32[0] = static_cast<u8>(is_last ? (ordinal | 0x40) : ordinal);
    out_32[11] = 0x0F; // LFN attr
    out_32[12] = 0;
    out_32[13] = checksum;
    out_32[26] = 0; // cluster must be 0
    out_32[27] = 0;
    static constexpr u32 kLfnOffs[13] = {1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30};
    bool past_terminator = false;
    for (u32 i = 0; i < 13; ++i)
    {
        const u32 o = kLfnOffs[i];
        if (i < chunk_len)
        {
            const u8 c = static_cast<u8>(chunk[i]);
            out_32[o] = c;
            out_32[o + 1] = 0;
        }
        else if (!past_terminator && i == chunk_len)
        {
            out_32[o] = 0x00;
            out_32[o + 1] = 0x00;
            past_terminator = true;
        }
        else
        {
            out_32[o] = 0xFF;
            out_32[o + 1] = 0xFF;
        }
    }
}

} // namespace

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

namespace
{
i64 CreateInDir(const Volume* v, u32 dir_cluster, const char* name, const void* buf, u64 len)
{
    if (v == nullptr || name == nullptr)
        return -1;
    if (buf == nullptr && len != 0)
        return -1;
    if (len > 0xFFFFFFFFu)
        return -1;

    const u64 cluster_bytes = u64(v->sectors_per_cluster) * u64(v->bytes_per_sector);
    if (v->sectors_per_cluster > sizeof(g_scratch) / 512)
        return -1;

    // Decide which directory-entry layout to use: plain SFN (fast
    // path for clean 8.3 uppercase names) or LFN sequence + SFN
    // fallback (long, mixed-case, or non-ASCII-safe names).
    const bool use_lfn = NeedsLfn(name);
    u8 sfn[11];
    u32 lfn_frag_count = 0;
    u32 long_len = 0;
    if (!use_lfn)
    {
        if (!MakeSfn(name, sfn))
            return -1;
        char human[13];
        FormatShortName(sfn, human);
        DirEntry tmp;
        if (FindInDirByName(*v, dir_cluster, human, &tmp))
            return -1; // duplicate
    }
    else
    {
        while (name[long_len] != 0)
            ++long_len;
        if (long_len > 127)
            return -1; // exceeds DirEntry::name capacity
        // LFN duplicate check via full-name walk — walker already
        // emits the long name in DirEntry.name.
        DirEntry tmp;
        if (FindInDirByName(*v, dir_cluster, name, &tmp))
            return -1;
        if (!GenerateUniqueSfn(*v, dir_cluster, name, sfn))
            return -1;
        lfn_frag_count = (long_len + 12) / 13;
        if (lfn_frag_count == 0 || lfn_frag_count > 20)
            return -1;
    }

    // Reserve (lfn_frag_count + 1) consecutive slots. For pure
    // SFN path, one slot suffices.
    u64 slot_lba = 0;
    u32 slot_off = 0;
    const u32 slots_needed = lfn_frag_count + 1;
    if (slots_needed == 1)
    {
        if (!FindFreeSlotInDir(*v, dir_cluster, &slot_lba, &slot_off))
            return -1;
    }
    else
    {
        if (!ReserveRunInDir(*v, dir_cluster, slots_needed, &slot_lba, &slot_off))
            return -1;
    }

    // Allocate + populate content clusters.
    u32 first_cluster = 0;
    if (len > 0)
    {
        first_cluster = AllocateFreeCluster(*v);
        if (first_cluster == 0)
            return -1;
        if (!ZeroCluster(*v, first_cluster))
            return -1;
        u32 tail = first_cluster;
        u64 written = 0;
        const auto* src = static_cast<const u8*>(buf);
        while (written < len)
        {
            const u64 remain = len - written;
            const u64 chunk = (remain < cluster_bytes) ? remain : cluster_bytes;
            const u64 lba = u64(v->data_start_sector) + u64(tail - 2) * u64(v->sectors_per_cluster);
            if (chunk == cluster_bytes)
            {
                for (u64 i = 0; i < chunk; ++i)
                    g_scratch[i] = src[written + i];
            }
            else
            {
                VZero(g_scratch, cluster_bytes);
                for (u64 i = 0; i < chunk; ++i)
                    g_scratch[i] = src[written + i];
            }
            if (drivers::storage::BlockDeviceWrite(v->block_handle, lba, v->sectors_per_cluster, g_scratch) != 0)
            {
                FreeClusterChain(*v, first_cluster);
                return -1;
            }
            written += chunk;
            if (written == len)
                break;
            const u32 fresh = AllocateFreeCluster(*v);
            if (fresh == 0 || !ZeroCluster(*v, fresh) || !WriteFatEntry(*v, tail, fresh))
            {
                FreeClusterChain(*v, first_cluster);
                return -1;
            }
            tail = fresh;
        }
    }

    // Write the entry records. For LFN case, write `lfn_frag_count`
    // fragments (highest ordinal first on disk) followed by the
    // SFN; the SFN sits slot_off + lfn_frag_count * 32 bytes in.
    // All records live inside one sector (guaranteed by
    // FindFreeRunInDir for the common v0 case with ≤ 16 slots
    // per sector).
    if (drivers::storage::BlockDeviceRead(v->block_handle, slot_lba, 1, g_scratch) != 0)
    {
        if (first_cluster != 0)
            FreeClusterChain(*v, first_cluster);
        return -1;
    }
    const bool was_eod = (g_scratch[slot_off] == 0x00);
    if (use_lfn)
    {
        const u8 chk = SfnChecksum(sfn);
        // Fragments: ordinal N (highest, is_last=true) on disk first,
        // ordinal 1 last — so on disk we walk from slot 0 to
        // lfn_frag_count-1 placing ord=N, N-1, ..., 1.
        for (u32 i = 0; i < lfn_frag_count; ++i)
        {
            const u32 ord = lfn_frag_count - i;
            const bool is_last_piece = (i == 0); // physical-first = logical-last
            const u32 chunk_start = (ord - 1) * 13;
            u32 chunk_len = 0;
            while (chunk_len < 13 && chunk_start + chunk_len < long_len)
                ++chunk_len;
            u8* rec = g_scratch + slot_off + i * 32;
            EncodeLfnFragment(name + chunk_start, chunk_len, static_cast<u8>(ord), is_last_piece, chk, rec);
        }
    }
    u8* rec = g_scratch + slot_off + lfn_frag_count * 32;
    VZero(rec, 32);
    for (u32 i = 0; i < 11; ++i)
        rec[i] = sfn[i];
    rec[11] = 0x20; // ATTR_ARCHIVE
    rec[26] = static_cast<u8>(first_cluster & 0xFF);
    rec[27] = static_cast<u8>((first_cluster >> 8) & 0xFF);
    rec[20] = static_cast<u8>((first_cluster >> 16) & 0xFF);
    rec[21] = static_cast<u8>((first_cluster >> 24) & 0xFF);
    const u32 size32 = static_cast<u32>(len);
    rec[28] = static_cast<u8>(size32 & 0xFF);
    rec[29] = static_cast<u8>((size32 >> 8) & 0xFF);
    rec[30] = static_cast<u8>((size32 >> 16) & 0xFF);
    rec[31] = static_cast<u8>((size32 >> 24) & 0xFF);
    // If we consumed the end-of-dir slot, the next 32 B (if any)
    // must still read as 0x00 to keep the enumerator honest.
    const u32 past_end = slot_off + slots_needed * 32;
    if (was_eod && past_end + 32 <= v->bytes_per_sector)
    {
        g_scratch[past_end] = 0x00;
    }
    if (drivers::storage::BlockDeviceWrite(v->block_handle, slot_lba, 1, g_scratch) != 0)
    {
        if (first_cluster != 0)
            FreeClusterChain(*v, first_cluster);
        return -1;
    }

    if (dir_cluster == v->root_cluster)
    {
        Volume* vm = const_cast<Volume*>(v);
        WalkRootIntoSnapshot(*vm, vm->root_cluster);
    }
    return static_cast<i64>(len);
}

} // namespace

i64 Fat32CreateInRoot(const Volume* v, const char* name, const void* buf, u64 len)
{
    Fat32Guard guard;
    if (v == nullptr)
        return -1;
    return CreateInDir(v, v->root_cluster, name, buf, len);
}

i64 Fat32CreateAtPath(const Volume* v, const char* path, const void* buf, u64 len)
{
    Fat32Guard guard;
    if (v == nullptr || path == nullptr)
        return -1;
    u32 parent_cluster = 0;
    char basename[64];
    if (!ResolveParentDir(*v, path, &parent_cluster, basename, sizeof(basename)))
        return -1;
    return CreateInDir(v, parent_cluster, basename, buf, len);
}

namespace
{
bool DeleteInDir(const Volume* v, u32 dir_cluster, const char* name)
{
    if (v == nullptr || name == nullptr)
        return false;
    struct FindCtx
    {
        const char* want;
        u64 lba;
        u32 off;
        u32 first_cluster;
        bool found;
    };
    FindCtx fc{name, 0, 0, 0, false};
    WalkDirOnDisk(
        *v, dir_cluster,
        [](u64 lba, u32 off, const u8* raw, const DirEntry& e, void* cx) -> bool
        {
            auto* c = static_cast<FindCtx*>(cx);
            if (NameIEqual(e.name, c->want))
            {
                c->lba = lba;
                c->off = off;
                c->first_cluster = e.first_cluster;
                c->found = true;
                (void)raw;
                return false;
            }
            return true;
        },
        &fc);
    if (!fc.found)
        return false;

    // Free clusters FIRST — if this fails partway, the dir entry
    // still points at a partially-freed chain, which is bad but
    // the deletion was requested; the operator knows. If we
    // marked the entry deleted first and then the cluster chain
    // free failed, we'd leak clusters from a file that's already
    // invisible. Freeing first minimizes leak risk.
    if (fc.first_cluster >= 2)
    {
        if (!FreeClusterChain(*v, fc.first_cluster))
            return false;
    }
    // Patch the SFN entry + any preceding LFN fragments to 0xE5.
    // FAT doesn't require the LFN trail to be cleaned — readers
    // skip orphan fragments anyway — but tidying keeps the
    // directory compact for subsequent FindFreeRunInDir calls
    // and matches what Windows / mkfs.fat do on delete.
    //
    // Strategy: RMW the SFN's sector. Walk BACKWARDS from the
    // SFN offset; for each entry with attr == 0x0F and first
    // byte between 0x01 and 0x7F (ord), stamp 0xE5. Stop at the
    // first non-LFN record. Bounded by 20 slots (FAT LFN max).
    // Doesn't cross sector boundaries in v0 — long-name runs
    // never exceed a single sector's 16-slot capacity for our
    // test image.
    if (drivers::storage::BlockDeviceRead(v->block_handle, fc.lba, 1, g_scratch) != 0)
        return false;
    g_scratch[fc.off] = 0xE5;
    {
        u32 probe = fc.off;
        for (u32 step = 0; step < 20 && probe >= 32; ++step)
        {
            probe -= 32;
            const u8* e = g_scratch + probe;
            if (e[11] != 0x0F)
                break;
            g_scratch[probe] = 0xE5;
        }
    }
    if (drivers::storage::BlockDeviceWrite(v->block_handle, fc.lba, 1, g_scratch) != 0)
        return false;

    if (dir_cluster == v->root_cluster)
    {
        Volume* vm = const_cast<Volume*>(v);
        WalkRootIntoSnapshot(*vm, vm->root_cluster);
    }
    return true;
}

} // namespace

bool Fat32DeleteInRoot(const Volume* v, const char* name)
{
    Fat32Guard guard;
    if (v == nullptr)
        return false;
    return DeleteInDir(v, v->root_cluster, name);
}

bool Fat32DeleteAtPath(const Volume* v, const char* path)
{
    Fat32Guard guard;
    if (v == nullptr || path == nullptr)
        return false;
    u32 parent_cluster = 0;
    char basename[64];
    if (!ResolveParentDir(*v, path, &parent_cluster, basename, sizeof(basename)))
        return false;
    return DeleteInDir(v, parent_cluster, basename);
}

namespace
{

// Plant the "." and ".." synthetic entries at the start of a new
// directory's cluster. Per FAT32 spec:
//   "." entry's first_cluster = the new directory's own cluster
//   ".." entry's first_cluster = the parent directory's cluster,
//        except when the parent is the root, where it must be 0.
bool SeedDotEntries(const Volume& v, u32 new_dir_cluster, u32 parent_cluster)
{
    if (!ZeroCluster(v, new_dir_cluster))
        return false;
    // One sector of the new cluster = first two 32-B records.
    const u64 lba = u64(v.data_start_sector) + u64(new_dir_cluster - 2) * u64(v.sectors_per_cluster);
    VZero(g_scratch, v.bytes_per_sector);

    u8* dot = g_scratch;
    for (u32 i = 0; i < 11; ++i)
        dot[i] = ' ';
    dot[0] = '.';
    dot[11] = 0x10; // ATTR_DIRECTORY
    dot[26] = static_cast<u8>(new_dir_cluster & 0xFF);
    dot[27] = static_cast<u8>((new_dir_cluster >> 8) & 0xFF);
    dot[20] = static_cast<u8>((new_dir_cluster >> 16) & 0xFF);
    dot[21] = static_cast<u8>((new_dir_cluster >> 24) & 0xFF);

    u8* dotdot = g_scratch + 32;
    for (u32 i = 0; i < 11; ++i)
        dotdot[i] = ' ';
    dotdot[0] = '.';
    dotdot[1] = '.';
    dotdot[11] = 0x10;
    // Spec: when parent IS the root, record 0 in ".." — not the
    // root's actual cluster number. Our enumerator already hides
    // dot entries, so the value only matters if tools like
    // chkdsk / fsck inspect the raw record.
    const u32 dotdot_cluster = (parent_cluster == v.root_cluster) ? 0 : parent_cluster;
    dotdot[26] = static_cast<u8>(dotdot_cluster & 0xFF);
    dotdot[27] = static_cast<u8>((dotdot_cluster >> 8) & 0xFF);
    dotdot[20] = static_cast<u8>((dotdot_cluster >> 16) & 0xFF);
    dotdot[21] = static_cast<u8>((dotdot_cluster >> 24) & 0xFF);

    return drivers::storage::BlockDeviceWrite(v.block_handle, lba, 1, g_scratch) == 0;
}

// Write a directory-slot SFN (+ optional LFN fragments) that
// describes an existing new entry (cluster already allocated,
// content already populated). Shared between file-create and
// mkdir, factored out because their only difference is the
// attribute byte.
bool PlantDirEntry(const Volume& v, u32 dir_cluster, const char* name, u32 first_cluster, u32 size, u8 attributes)
{
    const bool use_lfn = NeedsLfn(name);
    u8 sfn[11];
    u32 lfn_frag_count = 0;
    u32 long_len = 0;
    if (!use_lfn)
    {
        if (!MakeSfn(name, sfn))
            return false;
        char human[13];
        FormatShortName(sfn, human);
        DirEntry tmp;
        if (FindInDirByName(v, dir_cluster, human, &tmp))
            return false;
    }
    else
    {
        while (name[long_len] != 0)
            ++long_len;
        if (long_len > 127)
            return false;
        DirEntry tmp;
        if (FindInDirByName(v, dir_cluster, name, &tmp))
            return false;
        if (!GenerateUniqueSfn(v, dir_cluster, name, sfn))
            return false;
        lfn_frag_count = (long_len + 12) / 13;
        if (lfn_frag_count == 0 || lfn_frag_count > 20)
            return false;
    }

    u64 slot_lba = 0;
    u32 slot_off = 0;
    const u32 slots_needed = lfn_frag_count + 1;
    if (slots_needed == 1)
    {
        if (!FindFreeSlotInDir(v, dir_cluster, &slot_lba, &slot_off))
            return false;
    }
    else
    {
        if (!ReserveRunInDir(v, dir_cluster, slots_needed, &slot_lba, &slot_off))
            return false;
    }
    if (drivers::storage::BlockDeviceRead(v.block_handle, slot_lba, 1, g_scratch) != 0)
        return false;
    const bool was_eod = (g_scratch[slot_off] == 0x00);
    if (use_lfn)
    {
        const u8 chk = SfnChecksum(sfn);
        for (u32 i = 0; i < lfn_frag_count; ++i)
        {
            const u32 ord = lfn_frag_count - i;
            const bool is_last_piece = (i == 0);
            const u32 chunk_start = (ord - 1) * 13;
            u32 chunk_len = 0;
            while (chunk_len < 13 && chunk_start + chunk_len < long_len)
                ++chunk_len;
            u8* rec = g_scratch + slot_off + i * 32;
            EncodeLfnFragment(name + chunk_start, chunk_len, static_cast<u8>(ord), is_last_piece, chk, rec);
        }
    }
    u8* rec = g_scratch + slot_off + lfn_frag_count * 32;
    VZero(rec, 32);
    for (u32 i = 0; i < 11; ++i)
        rec[i] = sfn[i];
    rec[11] = attributes;
    rec[26] = static_cast<u8>(first_cluster & 0xFF);
    rec[27] = static_cast<u8>((first_cluster >> 8) & 0xFF);
    rec[20] = static_cast<u8>((first_cluster >> 16) & 0xFF);
    rec[21] = static_cast<u8>((first_cluster >> 24) & 0xFF);
    rec[28] = static_cast<u8>(size & 0xFF);
    rec[29] = static_cast<u8>((size >> 8) & 0xFF);
    rec[30] = static_cast<u8>((size >> 16) & 0xFF);
    rec[31] = static_cast<u8>((size >> 24) & 0xFF);
    const u32 past_end = slot_off + slots_needed * 32;
    if (was_eod && past_end + 32 <= v.bytes_per_sector)
    {
        g_scratch[past_end] = 0x00;
    }
    return drivers::storage::BlockDeviceWrite(v.block_handle, slot_lba, 1, g_scratch) == 0;
}

// True if a directory's cluster chain contains ANY entry beyond
// the "." / ".." synthetic pair. Used by rmdir to enforce the
// "must be empty" precondition.
bool DirHasOnlyDots(const Volume& v, u32 dir_cluster)
{
    struct Ctx
    {
        bool only_dots;
    };
    Ctx ctx{true};
    WalkDirChain(
        v, dir_cluster,
        [](const DirEntry& e, void* cx) -> bool
        {
            (void)e;
            auto* c = static_cast<Ctx*>(cx);
            // Walker already filters dot entries, so any surviving
            // visit is a real entry — directory is not empty.
            c->only_dots = false;
            return false;
        },
        &ctx);
    return ctx.only_dots;
}

} // namespace

bool Fat32MkdirAtPath(const Volume* v, const char* path)
{
    Fat32Guard guard;
    if (v == nullptr || path == nullptr)
        return false;
    u32 parent_cluster = 0;
    char basename[64];
    if (!ResolveParentDir(*v, path, &parent_cluster, basename, sizeof(basename)))
        return false;

    // Allocate a fresh cluster for the new directory's data,
    // seed it with "." and ".." entries.
    const u32 new_cluster = AllocateFreeCluster(*v);
    if (new_cluster == 0)
        return false;
    if (!SeedDotEntries(*v, new_cluster, parent_cluster))
    {
        FreeClusterChain(*v, new_cluster);
        return false;
    }

    // Plant the entry in the parent. On failure, roll back the
    // cluster allocation.
    if (!PlantDirEntry(*v, parent_cluster, basename, new_cluster, 0, /*attrs=*/0x10))
    {
        FreeClusterChain(*v, new_cluster);
        return false;
    }
    if (parent_cluster == v->root_cluster)
    {
        Volume* vm = const_cast<Volume*>(v);
        WalkRootIntoSnapshot(*vm, vm->root_cluster);
    }
    return true;
}

bool Fat32RmdirAtPath(const Volume* v, const char* path)
{
    Fat32Guard guard;
    if (v == nullptr || path == nullptr)
        return false;
    u32 parent_cluster = 0;
    char basename[64];
    if (!ResolveParentDir(*v, path, &parent_cluster, basename, sizeof(basename)))
        return false;
    DirEntry target;
    if (!FindInDirByName(*v, parent_cluster, basename, &target))
        return false;
    if ((target.attributes & 0x10) == 0)
        return false; // not a directory
    if (!DirHasOnlyDots(*v, target.first_cluster))
        return false; // not empty
    // Reuse DeleteInDir — it frees the cluster chain AND clears
    // preceding LFN fragments, which is exactly what we need.
    return DeleteInDir(v, parent_cluster, basename);
}

namespace
{
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
