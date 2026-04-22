#include "fat32.h"

#include "../arch/x86_64/serial.h"
#include "../core/klog.h"
#include "../drivers/storage/block.h"

namespace customos::fs::fat32
{

namespace
{

// Volume registry. Flat array, handed-out by Fat32Probe, stable
// for the kernel's lifetime. kMaxVolumes == 16 matches the block
// layer's cap.
constinit Volume g_volumes[kMaxVolumes] = {};
constinit u32 g_volume_count = 0;

// FAT attribute byte bits (spec §6.1). Only the ones this v0 code
// consults are defined here; ReadOnly / Hidden / System get added
// back when we grow a user-facing `ls` that wants to render them.
constexpr u8 kAttrVolumeId = 0x08;
constexpr u8 kAttrDirectory = 0x10;
constexpr u8 kAttrLongName = 0x0F; // read_only | hidden | system | volume_id

// Scratch buffer for the BPB sector + any single cluster read.
// v0 assumes 512 B sectors and ≤ 4 KiB clusters — fits in one
// page. A future multi-sector read path (larger clusters, 4 KiB
// native sectors) will need a bigger buffer or a streamed API.
alignas(16) constinit u8 g_scratch[4096] = {};

// Volatile-zero / volatile-copy — same rationale as the guard
// and AHCI drivers: prevent clang from lowering a byte loop into
// libc memset/memcpy, which the freestanding kernel does not link.
void VZero(void* p, u64 n)
{
    auto* b = reinterpret_cast<volatile u8*>(p);
    for (u64 i = 0; i < n; ++i)
        b[i] = 0;
}

// sizeof(DirEntry) is 144 bytes today; the compiler will lower a
// plain struct-assignment at this size to a memcpy call against a
// freestanding kernel with no libc. Route every DirEntry copy
// through this volatile helper to keep link-time honest.
void CopyEntry(DirEntry& dst, const DirEntry& src)
{
    auto* d = reinterpret_cast<volatile u8*>(&dst);
    auto* s = reinterpret_cast<const volatile u8*>(&src);
    for (u64 i = 0; i < sizeof(DirEntry); ++i)
        d[i] = s[i];
}

// Little-endian readers straight off a byte buffer.
u16 LeU16(const u8* p)
{
    return static_cast<u16>(p[0] | (u16(p[1]) << 8));
}
u32 LeU32(const u8* p)
{
    return u32(p[0]) | (u32(p[1]) << 8) | (u32(p[2]) << 16) | (u32(p[3]) << 24);
}

// Populate `out` with "NAME.EXT\0" given an 11-byte FAT 8.3 name.
// `name` is caller-owned; `out` must be at least 13 bytes. Trailing
// spaces in the base or extension are stripped.
void FormatShortName(const u8* name, char* out)
{
    u32 w = 0;
    // Base (bytes 0..7).
    for (u32 i = 0; i < 8; ++i)
    {
        if (name[i] == ' ')
            break;
        out[w++] = static_cast<char>(name[i]);
    }
    // Extension (bytes 8..10). Only emit the '.' if there's an ext.
    bool has_ext = false;
    for (u32 i = 8; i < 11; ++i)
    {
        if (name[i] != ' ')
        {
            has_ext = true;
            break;
        }
    }
    if (has_ext)
    {
        out[w++] = '.';
        for (u32 i = 8; i < 11; ++i)
        {
            if (name[i] == ' ')
                break;
            out[w++] = static_cast<char>(name[i]);
        }
    }
    out[w] = 0;
}

// Read one 512 B sector from the volume's partition block device
// into g_scratch. Returns false on I/O error.
bool ReadSector(u32 handle, u64 lba)
{
    return drivers::storage::BlockDeviceRead(handle, lba, 1, g_scratch) == 0;
}

// Read `sectors_per_cluster` contiguous sectors for a cluster into
// g_scratch. Bounded by sizeof(g_scratch) / 512 = 8, which matches
// our v0 test image's 4 KiB cluster. Larger clusters will need a
// bigger buffer.
bool ReadCluster(const Volume& v, u32 cluster)
{
    if (cluster < 2)
        return false;
    const u64 lba = v.data_start_sector + u64(cluster - 2) * v.sectors_per_cluster;
    if (v.sectors_per_cluster > sizeof(g_scratch) / 512)
        return false;
    return drivers::storage::BlockDeviceRead(v.block_handle, lba, v.sectors_per_cluster, g_scratch) == 0;
}

// Read the FAT entry for `cluster`. Returns 0x0FFFFFFF on I/O error
// (caller treats it as EOC, same semantics as a real EOC — the walk
// terminates cleanly). FAT32 uses 4 bytes per entry, top 4 bits
// reserved.
u32 ReadFatEntry(const Volume& v, u32 cluster)
{
    const u32 byte_off = cluster * 4;
    const u32 sec_off = byte_off / v.bytes_per_sector;
    const u32 byte_in_sec = byte_off % v.bytes_per_sector;
    const u64 lba = v.reserved_sectors + sec_off;
    if (!ReadSector(v.block_handle, lba))
        return 0x0FFFFFFFu;
    return LeU32(g_scratch + byte_in_sec) & 0x0FFFFFFFu;
}

// True if the formatted name is exactly "." or "..". Used by the
// enumerators to suppress the self / parent pseudo-entries that
// every non-root directory carries.
bool IsDotEntry(const char* n)
{
    if (n[0] != '.')
        return false;
    if (n[1] == 0)
        return true;
    if (n[1] == '.' && n[2] == 0)
        return true;
    return false;
}

// Case-insensitive ASCII compare of two NUL-terminated strings.
bool NameIEqual(const char* a, const char* b)
{
    u32 i = 0;
    for (; a[i] != 0 && b[i] != 0; ++i)
    {
        char ca = a[i];
        char cb = b[i];
        if (ca >= 'a' && ca <= 'z')
            ca = static_cast<char>(ca - 32);
        if (cb >= 'a' && cb <= 'z')
            cb = static_cast<char>(cb - 32);
        if (ca != cb)
            return false;
    }
    return a[i] == 0 && b[i] == 0;
}

// Fill one DirEntry from the 32-byte on-disk record.
void DecodeEntry(const u8* e, DirEntry& out)
{
    VZero(&out, sizeof(out));
    FormatShortName(e, out.name);
    out.attributes = e[11];
    const u16 cl_lo = LeU16(e + 26);
    const u16 cl_hi = LeU16(e + 20);
    out.first_cluster = (u32(cl_hi) << 16) | u32(cl_lo);
    out.size_bytes = LeU32(e + 28);
}

// Visitor type for the directory-cluster walker. Return true to
// keep walking, false to short-circuit. `ctx` is caller-opaque.
using DirVisitor = bool (*)(const DirEntry& e, void* ctx);

// Extract the 13 UTF-16 code units from a single LFN entry into
// `out_chars` at offsets [0..12]. Stops writing on the first
// 0x0000 terminator; `*did_terminate` reports whether the NUL was
// hit inside this fragment. Non-ASCII codepoints collapse to '?'
// — v0 is ASCII-friendly only.
void DecodeLfnChars(const u8* e, char* out_chars, bool* did_terminate)
{
    *did_terminate = false;
    // 13 positions: entry bytes (1..10) = 5 chars, (14..25) = 6 chars,
    // (28..31) = 2 chars. Each char is a little-endian u16.
    static constexpr u32 kLfnOffsets[13] = {1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30};
    for (u32 i = 0; i < 13; ++i)
    {
        const u32 o = kLfnOffsets[i];
        const u16 wc = static_cast<u16>(e[o] | (u16(e[o + 1]) << 8));
        if (wc == 0x0000)
        {
            out_chars[i] = 0;
            *did_terminate = true;
            // Don't break — zero out remaining positions explicitly
            // so the caller's concatenator sees a clean tail.
            for (u32 j = i + 1; j < 13; ++j)
                out_chars[j] = 0;
            return;
        }
        if (wc > 0x7F)
            out_chars[i] = '?';
        else
            out_chars[i] = static_cast<char>(wc);
    }
}

// Walk a directory's cluster chain, decode each in-use entry, and
// feed it to `visit`. LFN sequences are assembled into the DirEntry's
// `name` field before the visitor is called on the SFN. Deleted /
// volume-label / dot entries are filtered. Returns true on clean
// completion (end-of-dir or EOC), false on I/O error. A visitor
// returning false also ends the walk (still not an error).
//
// Reuses g_scratch for cluster data; the visitor MUST copy any
// DirEntry fields it wants to keep before returning.
bool WalkDirChain(const Volume& v, u32 first_cluster, DirVisitor visit, void* ctx)
{
    // LFN accumulator. FAT32 spec allows up to 20 LFN fragments ×
    // 13 UTF-16 chars = 260 chars; we truncate to DirEntry::name's
    // 128-byte budget at copy-out time.
    char pending_long[260];
    bool pending_any = false;
    VZero(pending_long, sizeof(pending_long));

    u32 cluster = first_cluster;
    for (u32 step = 0; step < 64; ++step)
    {
        if (cluster < 2 || cluster >= 0x0FFFFFF8u)
            break;
        if (!ReadCluster(v, cluster))
            return false;

        const u32 bytes = v.sectors_per_cluster * v.bytes_per_sector;
        for (u32 off = 0; off + 32 <= bytes; off += 32)
        {
            const u8* e = g_scratch + off;
            if (e[0] == 0x00)
                return true; // end of dir
            if (e[0] == 0xE5)
            {
                pending_any = false;
                continue;
            }
            const u8 attr = e[11];
            if ((attr & kAttrLongName) == kAttrLongName)
            {
                // LFN fragment. Ordinal low 6 bits = 1..20; bit 6
                // set on the LAST (first-in-physical-order) entry.
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
                // Replace the 8.3 name with the assembled LFN.
                // Trust the sequence; v0 doesn't validate the
                // 11-byte SFN checksum at LFN byte 13.
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

            if (!visit(decoded, ctx))
                return true;
        }
        cluster = ReadFatEntry(v, cluster);
    }
    return true;
}

// Probe-time root snapshot filler. Uses the generic walker with a
// cookie that appends into v.root_entries[].
bool WalkRootIntoSnapshot(Volume& v, u32 first_cluster)
{
    v.root_entry_count = 0;
    struct Ctx
    {
        Volume* v;
    };
    Ctx ctx{&v};
    return WalkDirChain(
        v, first_cluster,
        [](const DirEntry& e, void* cx) -> bool
        {
            auto* c = static_cast<Ctx*>(cx);
            if (c->v->root_entry_count >= kMaxDirEntries)
                return false;
            CopyEntry(c->v->root_entries[c->v->root_entry_count++], e);
            return true;
        },
        &ctx);
}

void LogEntry(const DirEntry& e)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    SerialWrite("[fs/fat32]   - ");
    SerialWrite(e.name);
    SerialWrite("  attr=");
    SerialWriteHex(static_cast<u64>(e.attributes));
    SerialWrite("  first_cluster=");
    SerialWriteHex(static_cast<u64>(e.first_cluster));
    SerialWrite("  size=");
    SerialWriteHex(static_cast<u64>(e.size_bytes));
    SerialWrite("\n");
}

} // namespace

bool Fat32Probe(u32 block_handle, u32* out_index)
{
    KLOG_TRACE_SCOPE("fs/fat32", "Fat32Probe");
    using arch::SerialWrite;

    if (g_volume_count >= kMaxVolumes)
    {
        core::Log(core::LogLevel::Error, "fs/fat32", "volume registry full");
        return false;
    }

    // Read LBA 0 of the partition = candidate BPB sector.
    if (!ReadSector(block_handle, 0))
    {
        core::Log(core::LogLevel::Warn, "fs/fat32", "probe: LBA 0 read failed");
        return false;
    }

    // Signature at 510/511.
    if (g_scratch[510] != 0x55 || g_scratch[511] != 0xAA)
    {
        return false;
    }
    // FAT32-class marker: "FAT32   " at bytes 82..89. Accept the
    // substring, not the full 8 bytes, so mkfs.fat variants that
    // pad differently still pass.
    const u8* ft = g_scratch + 82;
    if (ft[0] != 'F' || ft[1] != 'A' || ft[2] != 'T' || ft[3] != '3' || ft[4] != '2')
    {
        return false;
    }

    Volume& v = g_volumes[g_volume_count];
    VZero(&v, sizeof(v));
    v.block_handle = block_handle;
    v.bytes_per_sector = LeU16(g_scratch + 11);
    v.sectors_per_cluster = g_scratch[13];
    v.reserved_sectors = LeU16(g_scratch + 14);
    v.num_fats = g_scratch[16];
    v.fat_size_sectors = LeU32(g_scratch + 36);
    v.total_sectors = LeU32(g_scratch + 32);
    v.root_cluster = LeU32(g_scratch + 44);

    // v0 sanity checks: 512 B sectors, a real cluster size, ≥1 FAT.
    if (v.bytes_per_sector != 512 || v.sectors_per_cluster == 0 || v.num_fats == 0 || v.fat_size_sectors == 0)
    {
        core::Log(core::LogLevel::Warn, "fs/fat32", "BPB has unsupported geometry");
        return false;
    }
    v.data_start_sector = v.reserved_sectors + v.num_fats * v.fat_size_sectors;

    SerialWrite("[fs/fat32] volume:");
    SerialWrite(" handle=");
    arch::SerialWriteHex(static_cast<u64>(block_handle));
    SerialWrite(" bps=");
    arch::SerialWriteHex(static_cast<u64>(v.bytes_per_sector));
    SerialWrite(" spc=");
    arch::SerialWriteHex(static_cast<u64>(v.sectors_per_cluster));
    SerialWrite(" res=");
    arch::SerialWriteHex(static_cast<u64>(v.reserved_sectors));
    SerialWrite(" fat_size=");
    arch::SerialWriteHex(static_cast<u64>(v.fat_size_sectors));
    SerialWrite(" root_cluster=");
    arch::SerialWriteHex(static_cast<u64>(v.root_cluster));
    SerialWrite(" data_start=");
    arch::SerialWriteHex(static_cast<u64>(v.data_start_sector));
    SerialWrite("\n");

    if (!WalkRootIntoSnapshot(v, v.root_cluster))
    {
        core::Log(core::LogLevel::Error, "fs/fat32", "root directory walk failed");
        return false;
    }
    for (u32 i = 0; i < v.root_entry_count; ++i)
    {
        LogEntry(v.root_entries[i]);
    }

    const u32 index = g_volume_count++;
    if (out_index != nullptr)
        *out_index = index;
    return true;
}

u32 Fat32VolumeCount()
{
    return g_volume_count;
}

const Volume* Fat32Volume(u32 index)
{
    if (index >= g_volume_count)
        return nullptr;
    return &g_volumes[index];
}

u32 Fat32ListDirByCluster(const Volume* v, u32 first_cluster, DirEntry* out, u32 cap)
{
    if (v == nullptr || out == nullptr || cap == 0)
        return 0;
    struct Ctx
    {
        DirEntry* out;
        u32 cap;
        u32 n;
    };
    Ctx ctx{out, cap, 0};
    WalkDirChain(
        *v, first_cluster,
        [](const DirEntry& e, void* cx) -> bool
        {
            auto* c = static_cast<Ctx*>(cx);
            if (c->n >= c->cap)
                return false;
            CopyEntry(c->out[c->n++], e);
            return true;
        },
        &ctx);
    return ctx.n;
}

namespace
{
// Path walker context: "looking for `want`; when the visitor sees
// it, stash the entry in `match` and stop."
struct FindCtx
{
    const char* want;
    DirEntry match;
    bool found;
};

bool FindVisitor(const DirEntry& e, void* cx)
{
    auto* c = static_cast<FindCtx*>(cx);
    if (NameIEqual(e.name, c->want))
    {
        CopyEntry(c->match, e);
        c->found = true;
        return false; // stop the walk
    }
    return true;
}
} // namespace

bool Fat32LookupPath(const Volume* v, const char* path, DirEntry* out)
{
    if (v == nullptr || path == nullptr || out == nullptr)
        return false;

    // Synthetic "root" entry: directory at v->root_cluster.
    DirEntry cur;
    VZero(&cur, sizeof(cur));
    cur.name[0] = '/';
    cur.name[1] = 0;
    cur.attributes = kAttrDirectory;
    cur.first_cluster = v->root_cluster;
    cur.size_bytes = 0;

    // Skip leading slashes. An empty/"/" path returns the root entry.
    while (*path == '/')
        ++path;
    if (*path == 0)
    {
        CopyEntry(*out, cur);
        return true;
    }

    // Component-by-component descent. We copy each component into
    // a 13-byte local buffer (8.3 max = "FILENAME.EXT\0" = 13) so
    // we never mutate the caller's path.
    char comp[13];
    while (*path != 0)
    {
        u32 n = 0;
        while (*path != 0 && *path != '/')
        {
            if (n >= sizeof(comp) - 1)
                return false; // component longer than an 8.3 short name
            comp[n++] = *path++;
        }
        comp[n] = 0;
        if (n == 0)
            continue; // consecutive '/'
        while (*path == '/')
            ++path;

        if ((cur.attributes & kAttrDirectory) == 0)
            return false; // walking INTO a regular file

        FindCtx ctx;
        ctx.want = comp;
        ctx.found = false;
        VZero(&ctx.match, sizeof(ctx.match));
        if (!WalkDirChain(*v, cur.first_cluster, &FindVisitor, &ctx))
            return false;
        if (!ctx.found)
            return false;
        CopyEntry(cur, ctx.match);
    }

    CopyEntry(*out, cur);
    return true;
}

const DirEntry* Fat32FindInRoot(const Volume* v, const char* name)
{
    if (v == nullptr || name == nullptr)
        return nullptr;
    for (u32 i = 0; i < v->root_entry_count; ++i)
    {
        const DirEntry& e = v->root_entries[i];
        bool match = true;
        u32 k = 0;
        for (; e.name[k] != 0 && name[k] != 0; ++k)
        {
            // Case-insensitive over ASCII A-Z.
            char a = e.name[k];
            char b = name[k];
            if (a >= 'a' && a <= 'z')
                a = static_cast<char>(a - 32);
            if (b >= 'a' && b <= 'z')
                b = static_cast<char>(b - 32);
            if (a != b)
            {
                match = false;
                break;
            }
        }
        if (match && e.name[k] == 0 && name[k] == 0)
        {
            return &e;
        }
    }
    return nullptr;
}

i64 Fat32ReadFile(const Volume* v, const DirEntry* e, void* out, u64 max)
{
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

i64 Fat32WriteInPlace(const Volume* v, const DirEntry* e, u64 offset, const void* buf, u64 len)
{
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
bool RootUpdateEntrySize(const Volume& v, const char* want, u32 new_size)
{
    u32 cluster = v.root_cluster;
    // Bounded like the other walkers — 64 clusters covers any
    // realistic root directory.
    for (u32 step = 0; step < 64; ++step)
    {
        if (cluster < 2 || cluster >= 0x0FFFFFF8u)
            return false;
        const u32 bytes = v.sectors_per_cluster * v.bytes_per_sector;
        // Read the cluster one sector at a time so we can find the
        // entry, patch it in the scratch copy, and write JUST that
        // sector back. Whole-cluster write would be wasteful and
        // risk clobbering a concurrent writer's scratch staging
        // (though v0 is single-threaded on the shell path).
        for (u32 sec = 0; sec < v.sectors_per_cluster; ++sec)
        {
            const u64 lba = u64(v.data_start_sector) + u64(cluster - 2) * u64(v.sectors_per_cluster) + sec;
            if (drivers::storage::BlockDeviceRead(v.block_handle, lba, 1, g_scratch) != 0)
                return false;
            const u32 bytes_in_sec = v.bytes_per_sector;
            for (u32 off = 0; off + 32 <= bytes_in_sec; off += 32)
            {
                const u8* e = g_scratch + off;
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

} // namespace

i64 Fat32AppendInRoot(const Volume* v, const char* name, const void* buf, u64 len)
{
    if (v == nullptr || name == nullptr || buf == nullptr)
        return -1;
    if (len == 0)
        return 0;

    // Resolve the entry via the cached root snapshot so we can
    // read its current first_cluster / size without a fresh walk.
    const DirEntry* e = Fat32FindInRoot(v, name);
    if (e == nullptr)
        return -1;
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
    if (!RootUpdateEntrySize(*v, name, new_size))
    {
        core::Log(core::LogLevel::Error, "fs/fat32", "append: cluster chain extended but dir entry size update failed");
        return -1;
    }

    // Refresh the cached root snapshot so the next Fat32FindInRoot
    // sees the new size + first_cluster. We just re-walk; the
    // volume registry is non-const but the public handle is const
    // — cast off constness, same as the self-test's write-back path.
    Volume* vm = const_cast<Volume*>(v);
    WalkRootIntoSnapshot(*vm, vm->root_cluster);

    return static_cast<i64>(written);
}

bool Fat32ReadFileStream(const Volume* v, const DirEntry* e, ReadChunkCb cb, void* ctx)
{
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

void Fat32SelfTest()
{
    KLOG_TRACE_SCOPE("fs/fat32", "Fat32SelfTest");
    using arch::SerialWrite;

    const u32 block_count = drivers::storage::BlockDeviceCount();
    for (u32 h = 0; h < block_count; ++h)
    {
        const char* name = drivers::storage::BlockDeviceName(h);
        SerialWrite("[fs/fat32] probing handle=");
        arch::SerialWriteHex(static_cast<u64>(h));
        SerialWrite(" (");
        SerialWrite(name);
        SerialWrite(")\n");
        if (!Fat32Probe(h, nullptr))
        {
            SerialWrite("[fs/fat32]   -> not FAT32 (or unsupported geometry)\n");
        }
    }

    if (g_volume_count == 0)
    {
        SerialWrite("[fs/fat32] self-test: NO VOLUMES FOUND\n");
        return;
    }

    // Success criterion: at least one volume has at least one non-directory
    // entry in its root. Matches what `build_fat32` seeds (HELLO.TXT).
    bool any_file = false;
    for (u32 vi = 0; vi < g_volume_count; ++vi)
    {
        const Volume& v = g_volumes[vi];
        for (u32 ei = 0; ei < v.root_entry_count; ++ei)
        {
            if ((v.root_entries[ei].attributes & kAttrDirectory) == 0)
            {
                any_file = true;
                break;
            }
        }
        if (any_file)
            break;
    }
    if (!any_file)
    {
        SerialWrite("[fs/fat32] self-test WARN: volumes found but no files in any root\n");
        return;
    }

    // Content check: read the seed file from the first volume and
    // compare against the string the image-builder writes.
    //   tools/qemu/make-gpt-image.py : FAT_FILE_BODY = "hello from fat32\n"
    // A mismatch points at either an image-builder change that
    // forgot to update this assertion, or a driver regression in
    // the cluster-chain walk.
    const Volume* v0 = Fat32Volume(0);
    const DirEntry* hello = Fat32FindInRoot(v0, "HELLO.TXT");
    if (hello == nullptr)
    {
        SerialWrite("[fs/fat32] self-test WARN: HELLO.TXT not found in first volume\n");
        return;
    }
    static u8 buf[64];
    VZero(buf, sizeof(buf));
    const i64 n = Fat32ReadFile(v0, hello, buf, sizeof(buf));
    if (n < 0)
    {
        SerialWrite("[fs/fat32] self-test FAILED: read error on HELLO.TXT\n");
        return;
    }
    const char* expect = "hello from fat32\n";
    u32 elen = 0;
    while (expect[elen] != 0)
        ++elen;
    if (static_cast<u64>(n) != elen)
    {
        SerialWrite("[fs/fat32] self-test FAILED: HELLO.TXT wrong size\n");
        return;
    }
    for (u32 i = 0; i < elen; ++i)
    {
        if (buf[i] != static_cast<u8>(expect[i]))
        {
            SerialWrite("[fs/fat32] self-test FAILED: HELLO.TXT content mismatch\n");
            return;
        }
    }
    SerialWrite("[fs/fat32] self-test OK (HELLO.TXT contents verified)\n");

    // Second phase: prove the path walker resolves a nested entry.
    // Image-builder seeds /SUB/INNER.TXT with body "inner file\n".
    DirEntry inner;
    if (!Fat32LookupPath(v0, "/SUB/INNER.TXT", &inner))
    {
        SerialWrite("[fs/fat32] self-test WARN: /SUB/INNER.TXT not found\n");
        return;
    }
    VZero(buf, sizeof(buf));
    const i64 n2 = Fat32ReadFile(v0, &inner, buf, sizeof(buf));
    const char* expect2 = "inner file\n";
    u32 elen2 = 0;
    while (expect2[elen2] != 0)
        ++elen2;
    if (n2 != static_cast<i64>(elen2))
    {
        SerialWrite("[fs/fat32] self-test FAILED: /SUB/INNER.TXT wrong size\n");
        return;
    }
    for (u32 i = 0; i < elen2; ++i)
    {
        if (buf[i] != static_cast<u8>(expect2[i]))
        {
            SerialWrite("[fs/fat32] self-test FAILED: /SUB/INNER.TXT content mismatch\n");
            return;
        }
    }
    SerialWrite("[fs/fat32] self-test OK (/SUB/INNER.TXT path-walked + verified)\n");

    // Third phase: LFN decoding. The image-builder seeds a file
    // whose long name is "LongFile.txt" (SFN fallback LONGFI~1.TXT);
    // the long name must survive the walker's accumulator and be
    // lookup-able via the LFN path.
    DirEntry lng;
    if (!Fat32LookupPath(v0, "/LongFile.txt", &lng))
    {
        SerialWrite("[fs/fat32] self-test WARN: /LongFile.txt not resolved via LFN\n");
        return;
    }
    VZero(buf, sizeof(buf));
    const i64 n3 = Fat32ReadFile(v0, &lng, buf, sizeof(buf));
    const char* expect3 = "long filename file\n";
    u32 elen3 = 0;
    while (expect3[elen3] != 0)
        ++elen3;
    if (n3 != static_cast<i64>(elen3))
    {
        SerialWrite("[fs/fat32] self-test FAILED: LongFile.txt wrong size\n");
        return;
    }
    for (u32 i = 0; i < elen3; ++i)
    {
        if (buf[i] != static_cast<u8>(expect3[i]))
        {
            SerialWrite("[fs/fat32] self-test FAILED: LongFile.txt content mismatch\n");
            return;
        }
    }
    SerialWrite("[fs/fat32] self-test OK (LFN /LongFile.txt decoded + verified)\n");

    // Fourth phase: streamed read across multiple clusters. The
    // image-builder seeds /BIG.TXT as 6000 bytes of a printable-
    // ASCII pattern spanning clusters 7+8.
    DirEntry big;
    if (!Fat32LookupPath(v0, "/BIG.TXT", &big))
    {
        SerialWrite("[fs/fat32] self-test WARN: /BIG.TXT not found\n");
        return;
    }
    struct StreamCtx
    {
        u64 total;
        u8 first_byte;
        u8 last_byte;
        u8 byte_4095;
        u8 byte_4096;
        bool captured_first;
    };
    StreamCtx sc{0, 0, 0, 0, 0, false};
    const bool stream_ok = Fat32ReadFileStream(
        v0, &big,
        [](const u8* data, u64 len, void* ctx) -> bool
        {
            auto* s = static_cast<StreamCtx*>(ctx);
            if (!s->captured_first && len > 0)
            {
                s->first_byte = data[0];
                s->captured_first = true;
            }
            // Boundary bytes. `data` is this cluster's first byte,
            // so the absolute offset of data[i] is `s->total + i`.
            for (u64 i = 0; i < len; ++i)
            {
                const u64 abs = s->total + i;
                if (abs == 4095)
                    s->byte_4095 = data[i];
                if (abs == 4096)
                    s->byte_4096 = data[i];
            }
            s->total += len;
            if (len > 0)
                s->last_byte = data[len - 1];
            return true;
        },
        &sc);
    if (!stream_ok)
    {
        SerialWrite("[fs/fat32] self-test FAILED: /BIG.TXT stream read error\n");
        return;
    }
    // Expected pattern: byte i = 0x20 + (i % 95).
    const u8 exp_first = 0x20 + (0 % 95);
    const u8 exp_4095 = 0x20 + (4095 % 95);
    const u8 exp_4096 = 0x20 + (4096 % 95);
    const u8 exp_last = 0x20 + (5999 % 95);
    if (sc.total != 6000 || sc.first_byte != exp_first || sc.byte_4095 != exp_4095 || sc.byte_4096 != exp_4096 ||
        sc.last_byte != exp_last)
    {
        SerialWrite("[fs/fat32] self-test FAILED: /BIG.TXT pattern mismatch\n");
        return;
    }
    SerialWrite("[fs/fat32] self-test OK (streamed /BIG.TXT 6000 B across clusters)\n");

    // Fifth phase: in-place write. Take HELLO.TXT (body "hello from
    // fat32\n"), overwrite bytes [0..5) from "hello" to "HELLO",
    // read back, then restore. Round-trip verifies the whole chain:
    //   Fat32WriteInPlace -> BlockDeviceWrite -> AHCI/NVMe WRITE_DMA
    //   -> re-read -> byte-compare -> restore.
    // Volume 0 picked because we already verified HELLO.TXT there.
    const DirEntry* hello2 = Fat32FindInRoot(v0, "HELLO.TXT");
    if (hello2 == nullptr)
    {
        SerialWrite("[fs/fat32] self-test WARN: HELLO.TXT missing for write test\n");
        return;
    }
    const u8 upper[] = {'H', 'E', 'L', 'L', 'O'};
    const u8 lower[] = {'h', 'e', 'l', 'l', 'o'};
    if (Fat32WriteInPlace(v0, hello2, 0, upper, 5) != 5)
    {
        SerialWrite("[fs/fat32] self-test FAILED: HELLO.TXT write returned wrong count\n");
        return;
    }
    VZero(buf, sizeof(buf));
    const i64 n4 = Fat32ReadFile(v0, hello2, buf, sizeof(buf));
    if (n4 != 17 || buf[0] != 'H' || buf[1] != 'E' || buf[2] != 'L' || buf[3] != 'L' || buf[4] != 'O' || buf[5] != ' ')
    {
        SerialWrite("[fs/fat32] self-test FAILED: HELLO.TXT read-back after write mismatch\n");
        return;
    }
    // Restore to the original body so subsequent re-runs see a
    // clean fixture. Not strictly necessary (the image is rebuilt
    // every run by make-gpt-image.py) but makes the on-disk state
    // match the image-builder's output at test end.
    if (Fat32WriteInPlace(v0, hello2, 0, lower, 5) != 5)
    {
        SerialWrite("[fs/fat32] self-test FAILED: HELLO.TXT restore write failed\n");
        return;
    }
    SerialWrite("[fs/fat32] self-test OK (HELLO.TXT in-place round-trip verified)\n");

    // Sixth phase: append-and-grow. Take HELLO.TXT (17 B, single
    // cluster) and extend it by 5000 bytes of pattern — forces
    // allocation of a second cluster, FAT chaining, directory
    // entry size update. Read back the whole thing and verify
    // the original 17 B prefix + the 5000 B pattern tail.
    const char* hello_name = "HELLO.TXT";
    const u32 grow_by = 5000;
    static u8 pattern[5000];
    for (u32 i = 0; i < grow_by; ++i)
        pattern[i] = static_cast<u8>(0x41 + (i % 26)); // A..Z repeating
    const i64 appended = Fat32AppendInRoot(v0, hello_name, pattern, grow_by);
    if (appended != static_cast<i64>(grow_by))
    {
        SerialWrite("[fs/fat32] self-test FAILED: append returned wrong count\n");
        return;
    }
    const DirEntry* grown = Fat32FindInRoot(v0, hello_name);
    if (grown == nullptr || grown->size_bytes != 17 + grow_by)
    {
        SerialWrite("[fs/fat32] self-test FAILED: grown HELLO.TXT size wrong\n");
        return;
    }
    // Verify by streamed read — can't fit 5017 B in buf[64].
    struct VerifyCtx
    {
        u64 total;
        bool prefix_ok;
        bool tail_ok;
        bool tail_seen;
    };
    VerifyCtx vc{0, true, true, false};
    Fat32ReadFileStream(
        v0, grown,
        [](const u8* data, u64 len, void* ctx) -> bool
        {
            auto* c = static_cast<VerifyCtx*>(ctx);
            const char* prefix = "hello from fat32\n";
            const u64 prefix_len = 17;
            for (u64 i = 0; i < len; ++i)
            {
                const u64 abs = c->total + i;
                if (abs < prefix_len)
                {
                    if (data[i] != static_cast<u8>(prefix[abs]))
                        c->prefix_ok = false;
                }
                else
                {
                    const u64 off = abs - prefix_len;
                    const u8 expect = static_cast<u8>(0x41 + (off % 26));
                    if (data[i] != expect)
                        c->tail_ok = false;
                    c->tail_seen = true;
                }
            }
            c->total += len;
            return true;
        },
        &vc);
    if (vc.total != 17 + grow_by || !vc.prefix_ok || !vc.tail_seen || !vc.tail_ok)
    {
        SerialWrite("[fs/fat32] self-test FAILED: grown HELLO.TXT read-back mismatch\n");
        return;
    }
    SerialWrite("[fs/fat32] self-test OK (append grew HELLO.TXT 17 -> 5017 B)\n");
}

} // namespace customos::fs::fat32
