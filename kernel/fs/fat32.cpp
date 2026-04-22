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
    // a 128-byte local buffer — matches DirEntry::name capacity
    // since LFN entries can carry names up to 127 chars. Avoids
    // mutating the caller's path.
    char comp[128];
    while (*path != 0)
    {
        u32 n = 0;
        while (*path != 0 && *path != '/')
        {
            if (n >= sizeof(comp) - 1)
                return false; // component exceeds LFN cap
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
bool UpdateEntrySizeInDir(const Volume& v, u32 first_cluster, const char* want, u32 new_size)
{
    u32 cluster = first_cluster;
    // Bounded like the other walkers — 64 clusters covers any
    // realistic directory.
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

    DirEntry e_val;
    if (!FindInDirByName(*v, dir_cluster, name, &e_val))
        return -1;
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
    if (v == nullptr)
        return -1;
    return AppendInDir(v, v->root_cluster, name, buf, len);
}

i64 Fat32AppendAtPath(const Volume* v, const char* path, const void* buf, u64 len)
{
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
    if (v == nullptr)
        return -1;
    return CreateInDir(v, v->root_cluster, name, buf, len);
}

i64 Fat32CreateAtPath(const Volume* v, const char* path, const void* buf, u64 len)
{
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
    if (v == nullptr)
        return false;
    return DeleteInDir(v, v->root_cluster, name);
}

bool Fat32DeleteAtPath(const Volume* v, const char* path)
{
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
    if (v == nullptr)
        return -1;
    return TruncateInDir(v, v->root_cluster, name, new_size);
}

i64 Fat32TruncateAtPath(const Volume* v, const char* path, u64 new_size)
{
    if (v == nullptr || path == nullptr)
        return -1;
    u32 parent_cluster = 0;
    char basename[64];
    if (!ResolveParentDir(*v, path, &parent_cluster, basename, sizeof(basename)))
        return -1;
    return TruncateInDir(v, parent_cluster, basename, new_size);
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

    // Seventh phase: create. New file "NEW.TXT" with content
    // "created at runtime\n" (19 bytes). Must enumerate + read
    // back exactly.
    const u8 create_body[] = "created at runtime\n";
    const u64 create_len = 19;
    if (Fat32CreateInRoot(v0, "NEW.TXT", create_body, create_len) != static_cast<i64>(create_len))
    {
        SerialWrite("[fs/fat32] self-test FAILED: create NEW.TXT\n");
        return;
    }
    const DirEntry* newent = Fat32FindInRoot(v0, "NEW.TXT");
    if (newent == nullptr || newent->size_bytes != create_len)
    {
        SerialWrite("[fs/fat32] self-test FAILED: NEW.TXT not visible / wrong size\n");
        return;
    }
    VZero(buf, sizeof(buf));
    const i64 n5 = Fat32ReadFile(v0, newent, buf, sizeof(buf));
    if (n5 != static_cast<i64>(create_len))
    {
        SerialWrite("[fs/fat32] self-test FAILED: NEW.TXT read-back wrong size\n");
        return;
    }
    for (u32 i = 0; i < create_len; ++i)
    {
        if (buf[i] != create_body[i])
        {
            SerialWrite("[fs/fat32] self-test FAILED: NEW.TXT content mismatch\n");
            return;
        }
    }
    SerialWrite("[fs/fat32] self-test OK (created NEW.TXT 19 B, round-tripped)\n");

    // Eighth phase: truncate. Shrink NEW.TXT from 19 to 7 bytes
    // ("created"), then verify. Cluster is not freed (fits in
    // one cluster either way) but the size field and any future
    // read must stop at 7.
    if (Fat32TruncateInRoot(v0, "NEW.TXT", 7) != 7)
    {
        SerialWrite("[fs/fat32] self-test FAILED: truncate NEW.TXT -> 7\n");
        return;
    }
    const DirEntry* trunc_ent = Fat32FindInRoot(v0, "NEW.TXT");
    if (trunc_ent == nullptr || trunc_ent->size_bytes != 7)
    {
        SerialWrite("[fs/fat32] self-test FAILED: NEW.TXT post-truncate size wrong\n");
        return;
    }
    VZero(buf, sizeof(buf));
    const i64 n6 = Fat32ReadFile(v0, trunc_ent, buf, sizeof(buf));
    if (n6 != 7 || buf[0] != 'c' || buf[6] != 'd')
    {
        SerialWrite("[fs/fat32] self-test FAILED: NEW.TXT post-truncate content\n");
        return;
    }
    SerialWrite("[fs/fat32] self-test OK (truncated NEW.TXT 19 -> 7 B)\n");

    // Ninth phase: delete. Remove NEW.TXT; enumeration must no
    // longer see it.
    if (!Fat32DeleteInRoot(v0, "NEW.TXT"))
    {
        SerialWrite("[fs/fat32] self-test FAILED: delete NEW.TXT\n");
        return;
    }
    if (Fat32FindInRoot(v0, "NEW.TXT") != nullptr)
    {
        SerialWrite("[fs/fat32] self-test FAILED: NEW.TXT still visible after delete\n");
        return;
    }
    SerialWrite("[fs/fat32] self-test OK (deleted NEW.TXT)\n");

    // Tenth phase: create + read + delete a file in /SUB, using
    // the path-based API. Exercises the parent-directory
    // resolution step and the generic InDir primitives.
    const u8 sub_body[] = "sub file\n";
    const u64 sub_len = 9;
    if (Fat32CreateAtPath(v0, "/SUB/CHILD.TXT", sub_body, sub_len) != static_cast<i64>(sub_len))
    {
        SerialWrite("[fs/fat32] self-test FAILED: create /SUB/CHILD.TXT\n");
        return;
    }
    DirEntry child;
    if (!Fat32LookupPath(v0, "/SUB/CHILD.TXT", &child) || child.size_bytes != sub_len)
    {
        SerialWrite("[fs/fat32] self-test FAILED: /SUB/CHILD.TXT not resolvable after create\n");
        return;
    }
    VZero(buf, sizeof(buf));
    const i64 n7 = Fat32ReadFile(v0, &child, buf, sizeof(buf));
    if (n7 != static_cast<i64>(sub_len))
    {
        SerialWrite("[fs/fat32] self-test FAILED: /SUB/CHILD.TXT read-back wrong size\n");
        return;
    }
    for (u32 i = 0; i < sub_len; ++i)
    {
        if (buf[i] != sub_body[i])
        {
            SerialWrite("[fs/fat32] self-test FAILED: /SUB/CHILD.TXT content mismatch\n");
            return;
        }
    }
    if (!Fat32DeleteAtPath(v0, "/SUB/CHILD.TXT"))
    {
        SerialWrite("[fs/fat32] self-test FAILED: delete /SUB/CHILD.TXT\n");
        return;
    }
    DirEntry after_del;
    if (Fat32LookupPath(v0, "/SUB/CHILD.TXT", &after_del))
    {
        SerialWrite("[fs/fat32] self-test FAILED: /SUB/CHILD.TXT still visible after delete\n");
        return;
    }
    SerialWrite("[fs/fat32] self-test OK (subdir CRUD on /SUB/CHILD.TXT)\n");

    // Eleventh phase: LFN emission on create. Name "MixedCase.Report.md"
    // triggers the LFN path (multi-dot, mixed case, > 8 base). The
    // walker reads the long name back via its LFN accumulator; we
    // verify both that the created file is findable by its long
    // name AND that the SFN fallback is findable too.
    const char* long_name = "MixedCase.Report.md";
    const u8 long_body[] = "lfn create smoke\n";
    const u64 long_body_len = 17;
    if (Fat32CreateAtPath(v0, "/MixedCase.Report.md", long_body, long_body_len) != static_cast<i64>(long_body_len))
    {
        SerialWrite("[fs/fat32] self-test FAILED: create MixedCase.Report.md\n");
        return;
    }
    DirEntry lng_create;
    if (!Fat32LookupPath(v0, "/MixedCase.Report.md", &lng_create))
    {
        SerialWrite("[fs/fat32] self-test FAILED: long-name lookup post-create\n");
        return;
    }
    // Exact long-name match in DirEntry.name proves the walker
    // correctly accumulated our emitted LFN fragments.
    for (u32 i = 0; long_name[i] != 0; ++i)
    {
        if (lng_create.name[i] != long_name[i])
        {
            SerialWrite("[fs/fat32] self-test FAILED: long-name round-trip mismatch\n");
            return;
        }
    }
    VZero(buf, sizeof(buf));
    const i64 n8 = Fat32ReadFile(v0, &lng_create, buf, sizeof(buf));
    if (n8 != static_cast<i64>(long_body_len))
    {
        SerialWrite("[fs/fat32] self-test FAILED: long-name body size\n");
        return;
    }
    for (u32 i = 0; i < long_body_len; ++i)
    {
        if (buf[i] != long_body[i])
        {
            SerialWrite("[fs/fat32] self-test FAILED: long-name body mismatch\n");
            return;
        }
    }
    if (!Fat32DeleteAtPath(v0, "/MixedCase.Report.md"))
    {
        SerialWrite("[fs/fat32] self-test FAILED: delete long-name file\n");
        return;
    }
    SerialWrite("[fs/fat32] self-test OK (LFN emitted + read back on create/delete)\n");

    // Twelfth phase: mkdir / rmdir round-trip. Create /NEWDIR,
    // verify it's a directory, create a file inside it, verify
    // rmdir FAILS when non-empty, remove the file, rmdir
    // succeeds, verify the directory is gone.
    if (!Fat32MkdirAtPath(v0, "/NEWDIR"))
    {
        SerialWrite("[fs/fat32] self-test FAILED: mkdir /NEWDIR\n");
        return;
    }
    DirEntry mkd;
    if (!Fat32LookupPath(v0, "/NEWDIR", &mkd) || (mkd.attributes & 0x10) == 0)
    {
        SerialWrite("[fs/fat32] self-test FAILED: /NEWDIR not a directory post-mkdir\n");
        return;
    }
    const u8 inside_body[] = "inside\n";
    if (Fat32CreateAtPath(v0, "/NEWDIR/FILE.TXT", inside_body, 7) != 7)
    {
        SerialWrite("[fs/fat32] self-test FAILED: create /NEWDIR/FILE.TXT\n");
        return;
    }
    if (Fat32RmdirAtPath(v0, "/NEWDIR"))
    {
        SerialWrite("[fs/fat32] self-test FAILED: rmdir on non-empty dir should refuse\n");
        return;
    }
    if (!Fat32DeleteAtPath(v0, "/NEWDIR/FILE.TXT"))
    {
        SerialWrite("[fs/fat32] self-test FAILED: delete /NEWDIR/FILE.TXT\n");
        return;
    }
    if (!Fat32RmdirAtPath(v0, "/NEWDIR"))
    {
        SerialWrite("[fs/fat32] self-test FAILED: rmdir /NEWDIR when empty\n");
        return;
    }
    DirEntry after_rmdir;
    if (Fat32LookupPath(v0, "/NEWDIR", &after_rmdir))
    {
        SerialWrite("[fs/fat32] self-test FAILED: /NEWDIR still visible after rmdir\n");
        return;
    }
    SerialWrite("[fs/fat32] self-test OK (mkdir + rmdir round-trip with empty-check)\n");

    // Thirteenth phase: directory growth. Fill /SUB with enough
    // long-named files to overflow its single 4 KiB cluster (128
    // slots). Each LFN create takes 2 slots (1 frag + 1 SFN);
    // 70 such files = 140 slots. With /SUB's existing "." / ".."
    // + 1 INNER.TXT (3 slots), we need the driver to allocate
    // a second cluster for /SUB and place later entries there.
    //
    // Create 70 LFN files, read back the 70th, delete all 70,
    // verify /SUB looks unchanged afterward. If directory growth
    // is working, this just succeeds; if not, ~62 creates in
    // we run out of slots in the first cluster.
    if (!Fat32MkdirAtPath(v0, "/SUB/GROWTEST"))
    {
        SerialWrite("[fs/fat32] self-test FAILED: mkdir /SUB/GROWTEST\n");
        return;
    }
    const u32 grow_count = 70;
    for (u32 i = 0; i < grow_count; ++i)
    {
        // Name forces LFN path: mixed case + long base.
        char name[64];
        const char* prefix = "/SUB/GROWTEST/LongEntry";
        u32 w = 0;
        while (prefix[w] != 0 && w + 8 < sizeof(name))
        {
            name[w] = prefix[w];
            ++w;
        }
        // Append "NN.txt".
        name[w++] = static_cast<char>('0' + (i / 10) % 10);
        name[w++] = static_cast<char>('0' + i % 10);
        name[w++] = '.';
        name[w++] = 't';
        name[w++] = 'x';
        name[w++] = 't';
        name[w] = 0;
        const u8 body[2] = {'x', '\n'};
        if (Fat32CreateAtPath(v0, name, body, 2) != 2)
        {
            SerialWrite("[fs/fat32] self-test FAILED: growth create at ");
            SerialWrite(name);
            SerialWrite("\n");
            return;
        }
    }
    // Verify the last-written file is readable + has expected body.
    DirEntry last_ent;
    if (!Fat32LookupPath(v0, "/SUB/GROWTEST/LongEntry69.txt", &last_ent) || last_ent.size_bytes != 2)
    {
        SerialWrite("[fs/fat32] self-test FAILED: growth last-entry read-back\n");
        return;
    }
    // Tear down.
    for (u32 i = 0; i < grow_count; ++i)
    {
        char name[64];
        const char* prefix = "/SUB/GROWTEST/LongEntry";
        u32 w = 0;
        while (prefix[w] != 0 && w + 8 < sizeof(name))
        {
            name[w] = prefix[w];
            ++w;
        }
        name[w++] = static_cast<char>('0' + (i / 10) % 10);
        name[w++] = static_cast<char>('0' + i % 10);
        name[w++] = '.';
        name[w++] = 't';
        name[w++] = 'x';
        name[w++] = 't';
        name[w] = 0;
        if (!Fat32DeleteAtPath(v0, name))
        {
            SerialWrite("[fs/fat32] self-test FAILED: growth delete at ");
            SerialWrite(name);
            SerialWrite("\n");
            return;
        }
    }
    if (!Fat32RmdirAtPath(v0, "/SUB/GROWTEST"))
    {
        SerialWrite("[fs/fat32] self-test FAILED: rmdir /SUB/GROWTEST post-teardown\n");
        return;
    }
    SerialWrite("[fs/fat32] self-test OK (dir growth handled 70 LFN entries + teardown)\n");
}

} // namespace customos::fs::fat32
