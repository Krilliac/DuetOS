/*
 * DuetOS — FAT32 filesystem driver: directory-mutation path.
 *
 * Sibling to fat32_write.cpp. Houses the public Fat32* entries
 * that grow / shrink directory contents — file create/delete and
 * dir create/delete (mkdir/rmdir) — plus their private workers
 * (CreateInDir, DeleteInDir, SeedDotEntries, PlantDirEntry,
 * DirHasOnlyDots) and the SFN/LFN encoding helpers (MakeSfn,
 * NeedsLfn, SfnChecksum, GenerateUniqueSfn, EncodeLfnFragment).
 *
 * Cross-TU helpers shared with fat32_write.cpp (FAT-table
 * mutators, on-disk dir walker, free-slot finder, path resolver)
 * come from `namespace internal_write` declared in
 * fat32_write_internal.h. Read-side primitives (g_scratch,
 * Fat32Guard, ReadFatEntry, FormatShortName, ...) come from
 * fat32_internal.h.
 */

#include "fs/fat32.h"

#include "log/klog.h"
#include "drivers/storage/block.h"
#include "fs/fat32_internal.h"
#include "fs/fat32_write_internal.h"

namespace duetos::fs::fat32
{

using namespace internal;
using namespace internal_write;

namespace
{

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

} // namespace duetos::fs::fat32
