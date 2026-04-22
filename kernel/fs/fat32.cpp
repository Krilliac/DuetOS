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
}

} // namespace customos::fs::fat32
