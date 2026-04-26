/*
 * DuetOS — FAT32 filesystem driver: implementation.
 *
 * Companion to fat32.h — see there for the public mount/read/
 * write/lookup API and the in-memory mount struct.
 *
 * WHAT
 *   Mounts a FAT32 partition discovered by the GPT parser
 *   (kernel/fs/gpt.cpp), parses the BPB, and exposes
 *   directory walks + file read/write through the VFS
 *   adapter. Supports long file names (LFN, UTF-16) including
 *   the LFN-checksum sidechannel; short-name fallback when LFN
 *   is missing.
 *
 * HOW
 *   FAT itself is a chained-cluster index; lookups walk the
 *   chain by `next = fat[curr]`. We cache the FAT in
 *   per-mount RAM at v0 — small enough on typical FAT32
 *   volumes (<128 MiB FAT for a 32 GiB volume), big enough
 *   that on-demand FAT-block reads will be needed when we
 *   support larger partitions.
 *
 *   Directory entries are 32-byte structs; LFN entries
 *   precede the 8.3 entry and are stitched together by the
 *   walker. Write paths gate through the security guard
 *   (security/guard.cpp) so a sandboxed Win32 PE can't
 *   silently scribble over the boot partition.
 *
 * WHY THIS FILE IS LARGE
 *   FAT32 has a lot of wire-format ceremony (BPB, FAT, LFN
 *   stitching, 8.3 generation, free-cluster scan, cluster-
 *   chain walk). Each is short but they accumulate. Plus the
 *   shell `fat32` command's pretty-printer.
 */

#include "fat32.h"

#include "../arch/x86_64/serial.h"
#include "../core/kdbg.h"
#include "../core/klog.h"
#include "../core/log_names.h"
#include "../drivers/storage/block.h"
#include "../sched/sched.h"
#include "fat32_internal.h"

namespace duetos::fs::fat32
{

namespace internal
{

// Driver-wide mutex protecting the public-API surface. Both fat32.cpp
// and fat32_write.cpp construct Fat32Guard at every entry point;
// concurrent ring-3 tasks that both reach for FAT32 (e.g. the
// windows-side openat smoke + the linux-side write-past-EOF smoke
// racing during boot) would otherwise stomp on the shared g_scratch
// buffer. Recursive: a public entry that calls back into another
// public entry (Fat32CreateAtPath -> Fat32LookupPath, etc.) skips
// re-locking via the owning-task check.
constinit sched::Mutex g_fat32_mutex = {};
constinit u64 g_fat32_recursion = 0;

// Scratch buffer for the BPB sector + any single cluster read.
// v0 assumes 512 B sectors and ≤ 4 KiB clusters — fits in one
// page. A future multi-sector read path (larger clusters, 4 KiB
// native sectors) will need a bigger buffer or a streamed API.
alignas(16) constinit u8 g_scratch[4096] = {};

Fat32Guard::Fat32Guard()
{
    sched::Task* me = sched::CurrentTask();
    if (me != nullptr && g_fat32_mutex.owner == me)
    {
        ++g_fat32_recursion;
        owns_ = false;
        return;
    }
    // CurrentTask() can be nullptr during early boot before the
    // scheduler is online — Fat32Probe runs then. Skip the lock in
    // that case; preemption isn't possible yet, so the race we're
    // guarding against can't fire.
    if (me == nullptr)
    {
        owns_ = false;
        return;
    }
    sched::MutexLock(&g_fat32_mutex);
    owns_ = true;
}

Fat32Guard::~Fat32Guard()
{
    if (!owns_)
    {
        --g_fat32_recursion;
        return;
    }
    sched::MutexUnlock(&g_fat32_mutex);
}

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

// FAT32 short-name checksum, per the spec: rotate-right one bit and
// add each of the 11 SFN bytes. All LFN fragments in a sequence
// carry this checksum at offset 13 — when it mismatches the SFN
// that follows, the LFN is orphaned (typical after a partial
// rename) and we must fall back to the 8.3 name.
u8 ComputeLfnChecksum(const u8* sfn11)
{
    u8 sum = 0;
    for (u32 i = 0; i < 11; ++i)
        sum = static_cast<u8>(((sum & 1) ? 0x80 : 0) + static_cast<u8>(sum >> 1) + sfn11[i]);
    return sum;
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
    u8 pending_checksum = 0;
    bool pending_checksum_set = false;
    bool pending_checksum_consistent = true;
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
                pending_checksum_set = false;
                pending_checksum_consistent = true;
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
                    pending_checksum_set = false;
                    pending_checksum_consistent = true;
                    continue;
                }
                const u8 frag_chk = e[13];
                if (!pending_checksum_set)
                {
                    pending_checksum = frag_chk;
                    pending_checksum_set = true;
                    pending_checksum_consistent = true;
                }
                else if (frag_chk != pending_checksum)
                {
                    pending_checksum_consistent = false;
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
                pending_checksum_set = false;
                pending_checksum_consistent = true;
                continue;
            }

            DirEntry decoded;
            DecodeEntry(e, decoded);
            if (IsDotEntry(decoded.name))
            {
                pending_any = false;
                pending_checksum_set = false;
                pending_checksum_consistent = true;
                continue;
            }
            if (pending_any)
            {
                // Replace the 8.3 name with the assembled LFN, but
                // only if every fragment carried the same checksum
                // AND that checksum matches the trailing SFN's
                // 11-byte computation. Otherwise the LFN is
                // orphaned — fall back to the SFN.
                bool lfn_ok = pending_checksum_set && pending_checksum_consistent;
                if (lfn_ok && ComputeLfnChecksum(e) != pending_checksum)
                    lfn_ok = false;
                if (lfn_ok)
                {
                    u32 n = 0;
                    while (n + 1 < sizeof(decoded.name) && pending_long[n] != 0)
                    {
                        decoded.name[n] = pending_long[n];
                        ++n;
                    }
                    decoded.name[n] = 0;
                }
            }
            pending_any = false;
            pending_checksum_set = false;
            pending_checksum_consistent = true;
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

} // namespace internal

// Hoist the cross-TU primitives into the driver's outer namespace so
// the public Fat32* function bodies (and the anonymous-namespace
// helpers below) can call them unqualified. Internal-only consumers
// outside this TU pick the names up by including fat32_internal.h.
using namespace internal;

namespace
{

// Volume registry. Flat array, handed-out by Fat32Probe, stable
// for the kernel's lifetime. kMaxVolumes == 16 matches the block
// layer's cap. TU-private to fat32.cpp — the write-side TU reaches
// volumes through the public Fat32Volume / Fat32VolumeCount API.
constinit Volume g_volumes[kMaxVolumes] = {};
constinit u32 g_volume_count = 0;

void LogEntry(const DirEntry& e)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    SerialWrite("[fs/fat32]   - ");
    SerialWrite(e.name);
    SerialWrite("  attr=");
    SerialWriteHex(static_cast<u64>(e.attributes));
    ::duetos::core::SerialWriteFatAttr(static_cast<u64>(e.attributes));
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


} // namespace duetos::fs::fat32
