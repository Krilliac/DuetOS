/*
 * DuetOS — exFAT driver, v0 probe + root-directory walk.
 *
 * Byte-parsing lives in Rust (`kernel/fs/exfat_rust`): boot-sector
 * probe, geometry derivation, FAT chain walker, and dirent-set
 * decoder. This C++ TU owns block I/O, scratch buffers, the
 * per-volume registry, logging, and the UTF-16 → ASCII glyph
 * filter.
 */

#include "fs/exfat.h"

#include "arch/x86_64/serial.h"
#include "drivers/storage/block.h"
#include "fs/exfat_rust/include/exfat_rust.h"
#include "log/klog.h"
#include "util/unicode.h"

namespace duetos::fs::exfat
{

namespace
{

constinit Volume g_volumes[kMaxVolumes] = {};
u32 g_volume_count = 0;

// Scratch buffers. 4 KiB covers 8×512-byte sectors or 1×4 KiB
// sector; one cluster at minimum spc_shift=0 still fits 128 dir
// entries.
alignas(16) constinit u8 g_scratch[512] = {};
alignas(16) constinit u8 g_dir_scratch[4096] = {};

void ByteZero(void* dst, u64 n)
{
    auto* d = static_cast<volatile u8*>(dst);
    for (u64 i = 0; i < n; ++i)
        d[i] = 0;
}

// Decode the UTF-16 name span the Rust dirent walker returned into
// the caller's ASCII buffer using the project's safe-glyph filter.
// `buf_len` is the size of `buf`; without it a malformed dirent set
// with a bogus `name_offset` from the Rust parser would let this
// read past `g_dir_scratch`.
void DecodeDirentName(const u8* buf, u64 buf_len, const DuetosExfatDirEntry& src, char* out_name, u64 out_cap)
{
    u64 write_pos = 0;
    for (u8 u = 0; u < src.name_units; ++u)
    {
        const u64 byte_off = static_cast<u64>(src.name_offset) + static_cast<u64>(u) * 2;
        // Each UTF-16 unit is two bytes; reject the unit if either
        // byte would fall outside the dirent buffer. Truncating here
        // is safe — we already drop the trailing NUL below.
        if (byte_off + 1 >= buf_len)
            break;
        const u16 cp = static_cast<u16>(buf[byte_off]) | (static_cast<u16>(buf[byte_off + 1]) << 8);
        const char c = duetos::util::Utf16CpToSafeAscii(u32(cp));
        if (c == '\0')
            break;
        if (write_pos + 1 < out_cap)
            out_name[write_pos++] = c;
    }
    if (out_cap > 0)
        out_name[write_pos] = '\0';
}

void WalkRootDir(Volume& v)
{
    const u32 bps = 1u << v.bytes_per_sector_shift;
    const u32 spc = 1u << v.sectors_per_cluster_shift;
    const u64 cluster_bytes = u64(bps) * spc;
    if (v.first_cluster_of_root < 2)
        return;
    const u64 root_sector = u64(v.cluster_heap_offset_sectors) + u64(v.first_cluster_of_root - 2) * spc;

    u64 bytes_to_read = cluster_bytes;
    if (bytes_to_read > sizeof(g_dir_scratch))
        bytes_to_read = sizeof(g_dir_scratch);
    if (bps == 0)
        return;
    const u32 sectors_to_read = u32(bytes_to_read / bps);
    if (sectors_to_read == 0)
        return;

    const i32 rc = drivers::storage::BlockDeviceRead(v.block_handle, root_sector, sectors_to_read, g_dir_scratch);
    if (rc < 0)
    {
        // BlockDeviceRead returned an error reading the root
        // directory cluster — without it we can't enumerate any
        // files. Surface via klog with the storage rc value so a
        // post-mortem ties the failure back to the storage stack.
        KLOG_ERROR_V("fs/exfat", "root-dir read failed (rc)", static_cast<u64>(rc));
        return;
    }

    const u32 entry_count = u32(bytes_to_read / 32);
    u32 idx = 0;
    while (idx < entry_count)
    {
        const u8 type = g_dir_scratch[idx * 32];
        if (type == kDirEntryEndOfDir)
            break;
        if (v.root_entry_count >= kMaxDirEntries)
            break;

        DuetosExfatDirEntry rust_entry{};
        if (!duetos_exfat_parse_dirent_set(g_dir_scratch, bytes_to_read, idx, entry_count, &rust_entry))
        {
            // Hard parse error — refuse to keep walking; the rest
            // of the buffer is no longer trustworthy.
            break;
        }
        const u8 consumed = rust_entry.slots_consumed == 0 ? 1 : rust_entry.slots_consumed;
        if (rust_entry.ok == 0)
        {
            idx += consumed;
            continue;
        }

        const u32 before = v.root_entry_count;
        DirEntry* slot = &v.root_entries[before];
        ByteZero(slot, sizeof(*slot));
        slot->attributes = rust_entry.attributes;
        slot->valid_data_len = rust_entry.valid_data_len;
        slot->first_cluster = rust_entry.first_cluster;
        slot->size_bytes = rust_entry.size_bytes;
        DecodeDirentName(g_dir_scratch, bytes_to_read, rust_entry, slot->name, sizeof(slot->name));
        v.root_entry_count = before + 1;

        arch::SerialWrite("[exfat]   entry ");
        arch::SerialWrite(slot->name);
        arch::SerialWrite("  attr=");
        arch::SerialWriteHex(slot->attributes);
        arch::SerialWrite(" first_cluster=");
        arch::SerialWriteHex(slot->first_cluster);
        arch::SerialWrite(" size=");
        arch::SerialWriteHex(slot->size_bytes);
        arch::SerialWrite("\n");
        idx += consumed;
    }
    arch::SerialWrite("[exfat]   parsed ");
    arch::SerialWriteHex(v.root_entry_count);
    arch::SerialWrite(" root-dir entries\n");
}

} // namespace

bool ExfatVolumeIsDuetOsOwned(const Volume* v)
{
    if (v == nullptr)
        return false;
    return v->volume_serial == kDuetOsVolumeSerial;
}

::duetos::core::Result<u32> ExfatProbe(u32 block_handle)
{
    using ::duetos::core::Err;
    using ::duetos::core::ErrorCode;
    if (g_volume_count >= kMaxVolumes)
        return Err{ErrorCode::BadState};
    if (block_handle >= drivers::storage::BlockDeviceCount())
        return Err{ErrorCode::InvalidArgument};
    const i32 rc = drivers::storage::BlockDeviceRead(block_handle, kBootSectorLba, 1, g_scratch);
    if (rc < 0)
        return Err{ErrorCode::IoError};

    DuetosExfatBootSector bs{};
    if (!duetos_exfat_parse_boot_sector(g_scratch, sizeof(g_scratch), &bs))
        return Err{ErrorCode::NotFound};
    if (bs.ok == 0)
        return Err{ErrorCode::NotFound};

    DuetosExfatGeometry geom{};
    if (!duetos_exfat_derive_geometry(&bs, &geom) || geom.ok == 0)
        return Err{ErrorCode::Corrupt};

    Volume& v = g_volumes[g_volume_count];
    ByteZero(&v, sizeof(v));
    v.block_handle = block_handle;
    // Field-by-field copy from the Rust struct to the C++ Volume.
    v.partition_offset_bytes = bs.partition_offset;
    v.volume_length_sectors = bs.volume_length;
    v.fat_offset_sectors = bs.fat_offset;
    v.cluster_heap_offset_sectors = bs.cluster_heap_offset;
    v.cluster_count = bs.cluster_count;
    v.first_cluster_of_root = bs.root_dir_first_cluster;
    v.volume_serial = bs.volume_serial;
    v.bytes_per_sector_shift = bs.bytes_per_sector_shift;
    v.sectors_per_cluster_shift = bs.sectors_per_cluster_shift;

    // Adoption gate: DuetOS only registers exFAT volumes it owns. A
    // foreign exFAT volume (a Windows / macOS SD card, a USB stick) is
    // recognised and logged but NOT added to the registry — otherwise
    // its root-dir write paths (ExfatCreateInRoot / ExfatAppendInRoot /
    // ExfatTruncateInRoot) could mutate a partition DuetOS does not own
    // the moment exFAT is wired into the VFS. Inert-by-default: no
    // DuetOS marker -> not adopted. Mirrors the FAT32 adoption gate
    // landed in commit 7bb94062.
    if (!ExfatVolumeIsDuetOsOwned(&v))
    {
        arch::SerialWrite("[exfat] foreign exFAT volume (no DuetOS marker) — not adopting; handle=");
        arch::SerialWriteHex(block_handle);
        arch::SerialWrite(" volume_serial=");
        arch::SerialWriteHex(v.volume_serial);
        arch::SerialWrite("\n");
        // GAP: foreign-exFAT interop READ (mounting a foreign exFAT
        // volume read-only) is a deliberate future opt-in mount path,
        // not a boot auto-adopt — revisit when interop-read lands.
        return Err{ErrorCode::NotFound};
    }

    arch::SerialWrite("[exfat] probe OK handle=");
    arch::SerialWriteHex(block_handle);
    arch::SerialWrite(" bps_shift=");
    arch::SerialWriteHex(v.bytes_per_sector_shift);
    arch::SerialWrite(" spc_shift=");
    arch::SerialWriteHex(v.sectors_per_cluster_shift);
    arch::SerialWrite(" cluster_count=");
    arch::SerialWriteHex(v.cluster_count);
    arch::SerialWrite(" root_cluster=");
    arch::SerialWriteHex(v.first_cluster_of_root);
    arch::SerialWrite("\n");

    WalkRootDir(v);

    return g_volume_count++;
}

u32 ExfatVolumeCount()
{
    return g_volume_count;
}

const Volume* ExfatVolumeByIndex(u32 index)
{
    if (index >= g_volume_count)
        return nullptr;
    return &g_volumes[index];
}

void ExfatScanAll()
{
    KLOG_TRACE_SCOPE("fs/exfat", "ExfatScanAll");
    const u32 n = drivers::storage::BlockDeviceCount();
    for (u32 i = 0; i < n; ++i)
    {
        auto r = ExfatProbe(i);
        if (!r && r.error() != ::duetos::core::ErrorCode::NotFound)
        {
            arch::SerialWrite("[exfat] handle=");
            arch::SerialWriteHex(i);
            arch::SerialWrite(" probe error=");
            arch::SerialWrite(::duetos::core::ErrorCodeName(r.error()));
            arch::SerialWrite("\n");
        }
    }
    core::LogWithValue(core::LogLevel::Info, "fs/exfat", "exFAT volumes found", g_volume_count);
}

// =====================================================================
// Write path. Mirrors the FAT32 write reference (fat32_write.cpp +
// fat32_create.cpp): allocate free clusters, chain them through the
// 4-byte exFAT FAT, flip the allocation-bitmap bits, then plant /
// patch the on-disk dirent set. Block I/O stays in C++ (this TU owns
// the block layer); byte layout is encoded here because the Rust
// crate is a read-only parser and is out of scope for this slice.
// =====================================================================

namespace
{

// exFAT FAT end-of-chain sentinel and "bad cluster" marker.
inline constexpr u32 kExfatEoc = 0xFFFFFFFFu;
inline constexpr u32 kExfatBadCluster = 0xFFFFFFF7u;
// GeneralSecondaryFlags bits in the Stream-Extension entry (offset 1).
inline constexpr u8 kStreamFlagAllocPossible = 0x01;
inline constexpr u8 kStreamFlagNoFatChain = 0x02;
// FAT-style attribute byte for a freshly-created regular file.
inline constexpr u8 kAttrArchive = 0x20;
// Allocation-Bitmap directory entry type (primary, in the root dir).
inline constexpr u8 kDirEntryAllocBitmap = 0x81;
// Hard cap on cluster-chain length so a corrupt self-looping chain
// can't spin forever — matches the FAT32 reference's bound.
inline constexpr u32 kMaxChainClusters = 65536;

// Dedicated 4 KiB write scratch, separate from g_scratch /
// g_dir_scratch so a write that nests inside a snapshot refresh
// can't clobber a buffer the refresh is mid-read on.
alignas(16) constinit u8 g_write_scratch[4096] = {};

inline u32 BytesPerSector(const Volume& v)
{
    return 1u << v.bytes_per_sector_shift;
}

inline u32 SectorsPerCluster(const Volume& v)
{
    return 1u << v.sectors_per_cluster_shift;
}

inline u64 ClusterBytes(const Volume& v)
{
    return u64(BytesPerSector(v)) * SectorsPerCluster(v);
}

// LBA (partition-relative) of the first sector of `cluster` in the
// cluster heap. Clusters 0/1 are reserved, data starts at 2.
inline u64 ClusterToLba(const Volume& v, u32 cluster)
{
    return u64(v.cluster_heap_offset_sectors) + u64(cluster - 2) * SectorsPerCluster(v);
}

inline u32 LoadLe32(const u8* p)
{
    return u32(p[0]) | (u32(p[1]) << 8) | (u32(p[2]) << 16) | (u32(p[3]) << 24);
}

inline void StoreLe32(u8* p, u32 v)
{
    p[0] = u8(v & 0xFF);
    p[1] = u8((v >> 8) & 0xFF);
    p[2] = u8((v >> 16) & 0xFF);
    p[3] = u8((v >> 24) & 0xFF);
}

inline void StoreLe64(u8* p, u64 v)
{
    for (u32 i = 0; i < 8; ++i)
        p[i] = u8((v >> (i * 8)) & 0xFF);
}

inline void StoreLe16(u8* p, u16 v)
{
    p[0] = u8(v & 0xFF);
    p[1] = u8((v >> 8) & 0xFF);
}

// ---- FAT (4-byte LE per cluster) ----

// Read FAT[cluster]. Returns false on I/O error; *out gets the raw
// 32-bit entry (caller interprets EOC / free / data).
bool ReadFatEntry(const Volume& v, u32 cluster, u32* out)
{
    const u32 bps = BytesPerSector(v);
    const u64 byte_off = u64(cluster) * 4;
    const u64 lba = u64(v.fat_offset_sectors) + byte_off / bps;
    const u32 in_sec = u32(byte_off % bps);
    if (drivers::storage::BlockDeviceRead(v.block_handle, lba, 1, g_write_scratch) != 0)
        return false;
    *out = LoadLe32(g_write_scratch + in_sec);
    return true;
}

// Write FAT[cluster] = value. exFAT keeps the data-region FAT chain
// in FAT #1 only; FAT #2 (when NumberOfFats == 2) is TexFAT and is
// not maintained in v0 (see header GAP).
bool WriteFatEntry(const Volume& v, u32 cluster, u32 value)
{
    const u32 bps = BytesPerSector(v);
    const u64 byte_off = u64(cluster) * 4;
    const u64 lba = u64(v.fat_offset_sectors) + byte_off / bps;
    const u32 in_sec = u32(byte_off % bps);
    if (drivers::storage::BlockDeviceRead(v.block_handle, lba, 1, g_write_scratch) != 0)
        return false;
    StoreLe32(g_write_scratch + in_sec, value);
    return drivers::storage::BlockDeviceWrite(v.block_handle, lba, 1, g_write_scratch) == 0;
}

// ---- Allocation bitmap ----
//
// exFAT tracks free clusters in an Allocation-Bitmap special file,
// referenced by a type-0x81 dirent in the root directory. Bit N
// (0-based, LSB-first) covers cluster (N + 2). We must keep it in
// sync with the FAT or chkdsk / Windows will flag the volume dirty.

struct BitmapInfo
{
    u32 first_cluster; // first cluster of the bitmap file (0 == not found)
    u64 length_bytes;  // bitmap file size
};

// Scan the root's first cluster for the Allocation-Bitmap dirent.
// v0 reads only the root's first cluster (consistent with the read-
// side WalkRootDir bound); the bitmap dirent is by spec one of the
// first entries, so this is reliable in practice.
bool FindAllocationBitmap(const Volume& v, BitmapInfo* out)
{
    out->first_cluster = 0;
    out->length_bytes = 0;
    if (v.first_cluster_of_root < 2)
        return false;
    const u32 bps = BytesPerSector(v);
    const u32 spc = SectorsPerCluster(v);
    const u64 base = ClusterToLba(v, v.first_cluster_of_root);
    for (u32 sec = 0; sec < spc; ++sec)
    {
        if (drivers::storage::BlockDeviceRead(v.block_handle, base + sec, 1, g_write_scratch) != 0)
            return false;
        for (u32 off = 0; off + 32 <= bps; off += 32)
        {
            const u8* e = g_write_scratch + off;
            if (e[0] == kDirEntryEndOfDir)
                return false;
            if (e[0] == kDirEntryAllocBitmap)
            {
                // BitmapFlags bit 0 selects FAT #1's bitmap (the only
                // one on a single-FAT volume); we take the first.
                out->first_cluster = LoadLe32(e + 0x14);
                out->length_bytes = 0;
                for (u32 i = 0; i < 8; ++i)
                    out->length_bytes |= u64(e[0x18 + i]) << (i * 8);
                return out->first_cluster >= 2;
            }
        }
    }
    return false;
}

// Set or clear the bitmap bit for `cluster`. Reads the covering
// bitmap sector, flips the bit, writes it back. Returns false on
// I/O error or an out-of-range cluster.
bool SetBitmapBit(const Volume& v, const BitmapInfo& bm, u32 cluster, bool used)
{
    if (cluster < 2 || bm.first_cluster < 2)
        return false;
    const u64 bit_index = u64(cluster - 2);
    if (bit_index / 8 >= bm.length_bytes)
        return false;
    const u32 bps = BytesPerSector(v);
    const u64 byte_off = bit_index / 8;
    // Walk the bitmap file's cluster chain to the cluster holding
    // byte_off, then to the sector within it.
    const u64 cluster_bytes = ClusterBytes(v);
    u64 remaining = byte_off;
    u32 cur = bm.first_cluster;
    while (remaining >= cluster_bytes)
    {
        u32 next = 0;
        if (!ReadFatEntry(v, cur, &next))
            return false;
        if (next < 2 || next >= kExfatBadCluster)
            return false;
        cur = next;
        remaining -= cluster_bytes;
    }
    const u32 sec_in_cluster = u32(remaining / bps);
    const u32 in_sec = u32(remaining % bps);
    const u64 lba = ClusterToLba(v, cur) + sec_in_cluster;
    if (drivers::storage::BlockDeviceRead(v.block_handle, lba, 1, g_write_scratch) != 0)
        return false;
    const u8 mask = u8(1u << (bit_index % 8));
    if (used)
        g_write_scratch[in_sec] |= mask;
    else
        g_write_scratch[in_sec] = u8(g_write_scratch[in_sec] & ~mask);
    return drivers::storage::BlockDeviceWrite(v.block_handle, lba, 1, g_write_scratch) == 0;
}

// Read the bitmap bit for `cluster` into *used. Returns false on I/O
// error or out-of-range cluster. Mirrors SetBitmapBit's chain walk.
bool TestBitmapBit(const Volume& v, const BitmapInfo& bm, u32 cluster, bool* used)
{
    if (cluster < 2 || bm.first_cluster < 2)
        return false;
    const u64 bit_index = u64(cluster - 2);
    if (bit_index / 8 >= bm.length_bytes)
        return false;
    const u32 bps = BytesPerSector(v);
    const u64 byte_off = bit_index / 8;
    const u64 cluster_bytes = ClusterBytes(v);
    u64 remaining = byte_off;
    u32 cur = bm.first_cluster;
    while (remaining >= cluster_bytes)
    {
        u32 next = 0;
        if (!ReadFatEntry(v, cur, &next) || next < 2 || next >= kExfatBadCluster)
            return false;
        cur = next;
        remaining -= cluster_bytes;
    }
    const u32 sec_in_cluster = u32(remaining / bps);
    const u32 in_sec = u32(remaining % bps);
    const u64 lba = ClusterToLba(v, cur) + sec_in_cluster;
    if (drivers::storage::BlockDeviceRead(v.block_handle, lba, 1, g_write_scratch) != 0)
        return false;
    *used = (g_write_scratch[in_sec] & u8(1u << (bit_index % 8))) != 0;
    return true;
}

// ---- Cluster allocation / free ----

// Find a free cluster (allocation-bitmap bit clear — the bitmap, not
// the FAT, is exFAT's authority on free space because contiguous
// NoFatChain files have FAT entry 0 yet are bitmap-used), mark it
// used in the bitmap AND as EOC in the FAT, and return it. Returns 0
// on full-disk / I/O error.
u32 AllocateCluster(const Volume& v, const BitmapInfo& bm)
{
    const u32 hard_cap = v.cluster_count < kMaxChainClusters * 16 ? v.cluster_count : kMaxChainClusters * 16;
    for (u32 cluster = 2; cluster < hard_cap + 2; ++cluster)
    {
        if (cluster == v.first_cluster_of_root)
            continue;
        if (cluster == bm.first_cluster)
            continue;
        bool used = true;
        if (!TestBitmapBit(v, bm, cluster, &used))
            return 0;
        if (used)
            continue;
        if (!SetBitmapBit(v, bm, cluster, true))
            return 0;
        if (!WriteFatEntry(v, cluster, kExfatEoc))
        {
            (void)SetBitmapBit(v, bm, cluster, false); // best-effort rollback
            return 0;
        }
        return cluster;
    }
    return 0;
}

// Zero a freshly-allocated cluster so slack bytes don't leak stale
// on-disk content.
bool ZeroCluster(const Volume& v, u32 cluster)
{
    if (cluster < 2)
        return false;
    const u64 cb = ClusterBytes(v);
    if (cb > sizeof(g_write_scratch))
    {
        // Cluster larger than the scratch buffer — zero it in
        // scratch-sized sector runs.
        const u32 bps = BytesPerSector(v);
        const u32 sectors_per_pass = u32(sizeof(g_write_scratch) / bps);
        for (u32 i = 0; i < sizeof(g_write_scratch); ++i)
            g_write_scratch[i] = 0;
        u32 done = 0;
        const u32 total = SectorsPerCluster(v);
        const u64 base = ClusterToLba(v, cluster);
        while (done < total)
        {
            const u32 run = (total - done) < sectors_per_pass ? (total - done) : sectors_per_pass;
            if (drivers::storage::BlockDeviceWrite(v.block_handle, base + done, run, g_write_scratch) != 0)
                return false;
            done += run;
        }
        return true;
    }
    for (u32 i = 0; i < cb; ++i)
        g_write_scratch[i] = 0;
    return drivers::storage::BlockDeviceWrite(v.block_handle, ClusterToLba(v, cluster), SectorsPerCluster(v),
                                              g_write_scratch) == 0;
}

// Walk the FAT chain from `first` to its last cluster. Returns 0 if
// `first` is not a valid data cluster; otherwise the last cluster
// (whose FAT entry is EOC) via *out_last. Bounded by kMaxChainClusters.
bool ChainLast(const Volume& v, u32 first, u32* out_last)
{
    if (first < 2)
        return false;
    u32 cur = first;
    for (u32 step = 0; step < kMaxChainClusters; ++step)
    {
        u32 next = 0;
        if (!ReadFatEntry(v, cur, &next))
            return false;
        if (next >= kExfatBadCluster)
        {
            *out_last = cur;
            return true;
        }
        if (next < 2)
            return false; // corrupt chain
        cur = next;
    }
    return false; // chain too long / self-loop
}

// Free a cluster chain starting at `first`: clear each FAT entry and
// the matching bitmap bit. Bounded. Best-effort: a mid-chain I/O
// error leaves the volume partially freed (v0 has no journaling).
bool FreeChain(const Volume& v, const BitmapInfo& bm, u32 first)
{
    if (first < 2)
        return true;
    u32 cur = first;
    for (u32 step = 0; step < kMaxChainClusters; ++step)
    {
        u32 next = 0;
        if (!ReadFatEntry(v, cur, &next))
            return false;
        if (!WriteFatEntry(v, cur, 0))
            return false;
        (void)SetBitmapBit(v, bm, cur, false);
        if (next >= kExfatBadCluster)
            return true;
        if (next < 2)
            return true;
        cur = next;
    }
    return false;
}

// Grow a file's chain by `add` clusters, appending to `last` (or
// starting a fresh chain when last == 0). Newly allocated clusters
// are zeroed. Returns the new last cluster via *out_last and the new
// first cluster via *out_first (unchanged when last != 0). False on
// full-disk / I/O error, with already-allocated clusters left
// chained (best-effort; v0 has no rollback journaling).
bool GrowChain(const Volume& v, const BitmapInfo& bm, u32 first, u32 last, u32 add, u32* out_first, u32* out_last)
{
    u32 chain_first = first;
    u32 prev = last;
    for (u32 i = 0; i < add; ++i)
    {
        const u32 c = AllocateCluster(v, bm);
        if (c == 0)
            return false;
        if (!ZeroCluster(v, c))
            return false;
        if (prev == 0)
        {
            chain_first = c;
        }
        else if (!WriteFatEntry(v, prev, c))
        {
            return false;
        }
        prev = c;
    }
    *out_first = chain_first;
    *out_last = prev;
    return true;
}

// ---- Dirent-set encoding ----

// Up-case an ASCII letter (a-z -> A-Z). exFAT's real NameHash uses
// the volume Up-case Table; v0 covers ASCII only (header GAP).
inline u16 UpcaseAscii(u16 cp)
{
    if (cp >= u16('a') && cp <= u16('z'))
        return u16(cp - 32);
    return cp;
}

// Convert a NUL-terminated ASCII name into UTF-16LE code units in
// `out` (each entry is a u16). Returns the unit count, or 0 if the
// name is empty or longer than `cap` units.
u32 NameToUtf16(const char* name, u16* out, u32 cap)
{
    u32 n = 0;
    while (name[n] != '\0')
    {
        if (n >= cap)
            return 0;
        out[n] = u16(u8(name[n]));
        ++n;
    }
    return n;
}

// exFAT NameHash (UTF-16 up-cased, byte-wise rotate-add over the LE
// bytes). Per spec §7.4.1.
u16 ComputeNameHash(const u16* units, u32 count)
{
    u16 hash = 0;
    for (u32 i = 0; i < count; ++i)
    {
        const u16 up = UpcaseAscii(units[i]);
        const u8 lo = u8(up & 0xFF);
        const u8 hi = u8((up >> 8) & 0xFF);
        hash = u16(((hash << 15) | (hash >> 1)) + lo);
        hash = u16(((hash << 15) | (hash >> 1)) + hi);
    }
    return hash;
}

// exFAT SetChecksum over a dirent set of `entry_count` 32-byte
// entries beginning at `entries`. Bytes 2 and 3 of the FIRST entry
// (the checksum field itself) are skipped. Per spec §6.3.3.
u16 ComputeSetChecksum(const u8* entries, u32 entry_count)
{
    u16 checksum = 0;
    const u32 total = entry_count * 32;
    for (u32 i = 0; i < total; ++i)
    {
        if (i == 2 || i == 3)
            continue;
        checksum = u16(((checksum << 15) | (checksum >> 1)) + entries[i]);
    }
    return checksum;
}

// ---- Root-directory slot location ----
//
// The root's first cluster holds the dirent stream. v0 operates on
// that single cluster (header GAP: multi-cluster root). A "slot" is a
// 32-byte entry addressed by (sector LBA, byte offset in sector).

// Case-insensitive ASCII compare of two NUL-terminated names.
bool NameEqualCI(const char* a, const char* b)
{
    u32 i = 0;
    for (;; ++i)
    {
        const char ca = a[i] >= 'a' && a[i] <= 'z' ? char(a[i] - 32) : a[i];
        const char cb = b[i] >= 'a' && b[i] <= 'z' ? char(b[i] - 32) : b[i];
        if (ca != cb)
            return false;
        if (ca == '\0')
            return true;
    }
}

// Locate the on-disk dirent set for `name` in the root's first
// cluster. On a hit fills the File-entry slot address (file_lba /
// file_off), the total slots the set occupies, and the Stream-Ext
// entry address (stream_lba / stream_off) for in-place size patches.
struct SlotLoc
{
    u64 file_lba;
    u32 file_off;
    u64 stream_lba;
    u32 stream_off;
    u8 total_slots;
    u32 first_cluster;
    u64 size_bytes;
};

bool FindDirentSet(const Volume& v, const char* name, SlotLoc* out)
{
    const u32 bps = BytesPerSector(v);
    const u32 spc = SectorsPerCluster(v);
    const u64 base = ClusterToLba(v, v.first_cluster_of_root);
    // Read the whole root cluster into g_dir_scratch (bounded by the
    // read-side WalkRootDir's 4 KiB limit) so we can decode the name
    // via the Rust parser and compare against `name`.
    u64 bytes = u64(spc) * bps;
    if (bytes > sizeof(g_dir_scratch))
        bytes = sizeof(g_dir_scratch);
    const u32 sectors = u32(bytes / bps);
    if (sectors == 0)
        return false;
    if (drivers::storage::BlockDeviceRead(v.block_handle, base, sectors, g_dir_scratch) != 0)
        return false;
    const u32 entry_count = u32(bytes / 32);
    char decoded[128];
    u32 idx = 0;
    while (idx < entry_count)
    {
        const u8 type = g_dir_scratch[idx * 32];
        if (type == kDirEntryEndOfDir)
            return false;
        DuetosExfatDirEntry parsed{};
        if (!duetos_exfat_parse_dirent_set(g_dir_scratch, bytes, idx, entry_count, &parsed))
            return false;
        const u8 consumed = parsed.slots_consumed == 0 ? 1 : parsed.slots_consumed;
        if (parsed.ok == 0)
        {
            idx += consumed;
            continue;
        }
        DecodeDirentName(g_dir_scratch, bytes, parsed, decoded, sizeof(decoded));
        if (NameEqualCI(decoded, name))
        {
            const u32 file_slot = idx;
            const u32 stream_slot = idx + 1;
            out->file_off = (file_slot % (bps / 32)) * 32;
            out->file_lba = base + (u64(file_slot) * 32) / bps;
            out->stream_off = (stream_slot % (bps / 32)) * 32;
            out->stream_lba = base + (u64(stream_slot) * 32) / bps;
            out->total_slots = consumed;
            out->first_cluster = parsed.first_cluster;
            out->size_bytes = parsed.size_bytes;
            return true;
        }
        idx += consumed;
    }
    return false;
}

// Patch a located Stream-Extension entry's ValidDataLength (0x08) and
// DataLength (0x18) to `size`, and FirstCluster (0x14) to
// `first_cluster`, recomputing the set's SetChecksum in the File
// entry. Reads both slots, edits, writes back. Returns false on I/O
// error or when the (rare) File and Stream slots span two sectors
// (v0 keeps every dirent set sector-aligned, so this never trips on
// our own volumes — flagged as a GAP for foreign images).
bool PatchStreamSize(const Volume& v, const SlotLoc& loc, u32 first_cluster, u64 size)
{
    const u32 bps = BytesPerSector(v);
    // File + Stream + name entries all live in the same sector for
    // our writer (a fresh set is planted contiguously). Read the
    // sector holding the File entry; the whole set is within it.
    if (loc.file_lba != loc.stream_lba)
    {
        // GAP: dirent set straddling a sector boundary — not produced
        // by our own create path; refuse rather than corrupt a
        // foreign image's checksum. Revisit with a slot-granular RMW.
        KLOG_WARN("fs/exfat", "dirent set straddles sector boundary; refusing in-place size patch");
        return false;
    }
    if (drivers::storage::BlockDeviceRead(v.block_handle, loc.file_lba, 1, g_write_scratch) != 0)
        return false;
    u8* file = g_write_scratch + loc.file_off;
    u8* stream = g_write_scratch + loc.stream_off;
    StoreLe64(stream + 0x08, size);
    StoreLe32(stream + 0x14, first_cluster);
    StoreLe64(stream + 0x18, size);
    // A zero-length file carries first_cluster 0 and clears the
    // AllocationPossible flag's chain; keep AllocPossible set, clear
    // NoFatChain (we always chain).
    stream[1] = u8((stream[1] | kStreamFlagAllocPossible) & ~kStreamFlagNoFatChain);
    if (size == 0)
        StoreLe32(stream + 0x14, 0);
    // Recompute SetChecksum over the whole set (File first byte gives
    // SecondaryCount; total entries = SecondaryCount + 1).
    const u32 entry_count = u32(file[1]) + 1;
    if (loc.file_off + entry_count * 32 > bps)
    {
        KLOG_WARN("fs/exfat", "dirent set exceeds sector; refusing checksum recompute");
        return false;
    }
    const u16 checksum = ComputeSetChecksum(file, entry_count);
    StoreLe16(file + 0x02, checksum);
    return drivers::storage::BlockDeviceWrite(v.block_handle, loc.file_lba, 1, g_write_scratch) == 0;
}

// Refresh the cached root snapshot after a mutation so a follow-up
// read sees the new state. Re-runs the read-side WalkRootDir (which
// resets the per-volume entry list first).
void RefreshRootSnapshot(Volume& v)
{
    v.root_entry_count = 0;
    WalkRootDir(v);
}

// Find a run of `need` consecutive free 32-byte slots in the root's
// first cluster. A slot is free if its type byte is 0x00 (end-of-dir,
// extends the directory) or has bit 7 clear (deleted / unused). Fills
// the first slot's LBA + offset on success. v0 only places sets that
// fit entirely within one sector (so PatchStreamSize's RMW stays a
// single-sector op); a run crossing a sector boundary is skipped.
bool FindFreeSlots(const Volume& v, u32 need, u64* out_lba, u32* out_off)
{
    const u32 bps = BytesPerSector(v);
    const u32 spc = SectorsPerCluster(v);
    const u64 base = ClusterToLba(v, v.first_cluster_of_root);
    const u32 slots_per_sector = bps / 32;
    if (need > slots_per_sector)
        return false; // GAP: dirent set larger than one sector unsupported
    for (u32 sec = 0; sec < spc; ++sec)
    {
        if (drivers::storage::BlockDeviceRead(v.block_handle, base + sec, 1, g_write_scratch) != 0)
            return false;
        u32 run = 0;
        u32 run_start = 0;
        for (u32 s = 0; s < slots_per_sector; ++s)
        {
            const u8 type = g_write_scratch[s * 32];
            const bool free_slot = (type == kDirEntryEndOfDir) || (type & 0x80) == 0;
            if (free_slot)
            {
                if (run == 0)
                    run_start = s;
                ++run;
                if (run >= need)
                {
                    *out_lba = base + sec;
                    *out_off = run_start * 32;
                    return true;
                }
            }
            else
            {
                run = 0;
            }
        }
    }
    return false;
}

// Plant a fresh File (0x85) + Stream-Extension (0xC0) + FileName
// (0xC1)* dirent set for `name` at (lba, off). `name_units` UTF-16
// code units come from `units`. Sets attr, first_cluster, size,
// NameHash and SetChecksum. The whole set must fit within the sector
// at (lba, off) — FindFreeSlots guarantees that.
bool PlantDirentSet(const Volume& v, u64 lba, u32 off, const u16* units, u32 name_units, u8 attr, u32 first_cluster,
                    u64 size)
{
    const u32 bps = BytesPerSector(v);
    const u32 name_entries = (name_units + 14) / 15; // 15 units per FileName entry
    const u32 secondary = 1 + name_entries;          // StreamExt + FileName entries
    const u32 total = 1 + secondary;
    if (off + total * 32 > bps)
        return false;
    if (drivers::storage::BlockDeviceRead(v.block_handle, lba, 1, g_write_scratch) != 0)
        return false;
    u8* set = g_write_scratch + off;
    for (u32 i = 0; i < total * 32; ++i)
        set[i] = 0;

    // File entry (0x85).
    set[0] = kDirEntryFile;
    set[1] = u8(secondary);
    set[4] = attr; // FileAttributes (FAT-style byte)
    // SetChecksum (set[2..3]) filled last.

    // Stream-Extension entry (0xC0).
    u8* stream = set + 32;
    stream[0] = kDirEntryStreamExt;
    stream[1] = kStreamFlagAllocPossible; // chained (NoFatChain clear)
    stream[3] = u8(name_units);           // NameLength
    StoreLe64(stream + 0x08, size);       // ValidDataLength
    StoreLe32(stream + 0x14, first_cluster);
    StoreLe64(stream + 0x18, size); // DataLength
    if (size == 0)
    {
        stream[1] = 0; // no allocation for a zero-length file
        StoreLe32(stream + 0x14, 0);
    }
    // NameHash (stream[4..5]).
    StoreLe16(stream + 0x04, ComputeNameHash(units, name_units));

    // FileName entries (0xC1).
    u32 written = 0;
    for (u32 e = 0; e < name_entries; ++e)
    {
        u8* fn = set + (2 + e) * 32;
        fn[0] = kDirEntryFileName;
        for (u32 u = 0; u < 15 && written < name_units; ++u, ++written)
            StoreLe16(fn + 2 + u * 2, units[written]);
    }

    // SetChecksum last (over the finished set, skipping File[2..3]).
    StoreLe16(set + 0x02, ComputeSetChecksum(set, total));
    return drivers::storage::BlockDeviceWrite(v.block_handle, lba, 1, g_write_scratch) == 0;
}

} // namespace

// =====================================================================
// Public write API.
// =====================================================================

const DirEntry* ExfatFindInRoot(const Volume* v, const char* name)
{
    if (v == nullptr || name == nullptr)
        return nullptr;
    for (u32 i = 0; i < v->root_entry_count; ++i)
    {
        if (NameEqualCI(v->root_entries[i].name, name))
            return &v->root_entries[i];
    }
    return nullptr;
}

i64 ExfatWriteInPlace(const Volume* v, const DirEntry* e, u64 offset, const void* buf, u64 len)
{
    if (v == nullptr || e == nullptr || buf == nullptr)
        return -1;
    if (len == 0)
        return 0;
    if (!drivers::storage::BlockDeviceIsWritable(v->block_handle))
        return -1;
    if (offset + len > e->size_bytes)
        return -1; // in-place only — no growth
    if (e->first_cluster < 2)
        return -1;

    const u32 bps = BytesPerSector(*v);
    const u64 cb = ClusterBytes(*v);
    if (bps == 0 || bps > sizeof(g_write_scratch) || cb == 0)
        return -1;
    const auto* src = static_cast<const u8*>(buf);

    // Walk to the cluster holding `offset`.
    u32 cluster = e->first_cluster;
    const u64 skip = offset / cb;
    for (u64 i = 0; i < skip; ++i)
    {
        u32 next = 0;
        if (!ReadFatEntry(*v, cluster, &next) || next < 2 || next >= kExfatBadCluster)
            return -1;
        cluster = next;
    }

    // Sector-granular read-modify-write so any cluster size works
    // (a cluster can be far larger than the scratch buffer). Each
    // touched sector is RMW'd to preserve bytes outside the span.
    u64 written = 0;
    u64 pos = offset;
    while (written < len)
    {
        const u64 in_cluster = pos % cb;
        const u32 sec_in_cluster = u32(in_cluster / bps);
        const u32 in_sec = u32(in_cluster % bps);
        const u64 lba = ClusterToLba(*v, cluster) + sec_in_cluster;
        const u64 chunk = (bps - in_sec) < (len - written) ? (bps - in_sec) : (len - written);
        if (drivers::storage::BlockDeviceRead(v->block_handle, lba, 1, g_write_scratch) != 0)
            return -1;
        for (u64 i = 0; i < chunk; ++i)
            g_write_scratch[in_sec + i] = src[written + i];
        if (drivers::storage::BlockDeviceWrite(v->block_handle, lba, 1, g_write_scratch) != 0)
            return -1;
        written += chunk;
        pos += chunk;
        // Advance to the next cluster only when we've consumed this one.
        if (written < len && (pos % cb) == 0)
        {
            u32 next = 0;
            if (!ReadFatEntry(*v, cluster, &next) || next < 2 || next >= kExfatBadCluster)
                return -1;
            cluster = next;
        }
    }
    (void)drivers::storage::BlockDeviceFlush(v->block_handle);
    return i64(written);
}

i64 ExfatAppendInRoot(Volume* v, const char* name, const void* buf, u64 len)
{
    if (v == nullptr || name == nullptr || buf == nullptr)
        return -1;
    if (!drivers::storage::BlockDeviceIsWritable(v->block_handle))
        return -1;
    if (len == 0)
        return 0;

    SlotLoc loc{};
    if (!FindDirentSet(*v, name, &loc))
        return -1;

    BitmapInfo bm{};
    if (!FindAllocationBitmap(*v, &bm))
        return -1;

    const u64 cb = ClusterBytes(*v);
    const u64 old_size = loc.size_bytes;
    const u64 new_size = old_size + len;
    const u64 old_clusters = (old_size + cb - 1) / cb;
    const u64 new_clusters = (new_size + cb - 1) / cb;
    const u64 add = new_clusters - old_clusters;

    u32 first = loc.first_cluster;
    u32 last = 0;
    if (first >= 2)
    {
        if (!ChainLast(*v, first, &last))
            return -1;
    }
    if (add > 0)
    {
        u32 new_first = first;
        u32 new_last = last;
        if (!GrowChain(*v, bm, first, last, u32(add), &new_first, &new_last))
            return -1;
        first = new_first;
    }
    // Bump the on-disk size first so the in-place writer (bounded by
    // size_bytes) accepts the [old_size, new_size) span, then write
    // the appended bytes through the freshly-chained clusters.
    DirEntry tmp{};
    tmp.first_cluster = first;
    tmp.size_bytes = new_size;
    if (!PatchStreamSize(*v, loc, first, new_size))
        return -1;
    const i64 w = ExfatWriteInPlace(v, &tmp, old_size, buf, len);
    if (w < 0 || u64(w) != len)
        return -1;
    (void)drivers::storage::BlockDeviceFlush(v->block_handle);
    RefreshRootSnapshot(*v);
    return i64(len);
}

i64 ExfatCreateInRoot(Volume* v, const char* name, const void* buf, u64 len)
{
    if (v == nullptr || name == nullptr)
        return -1;
    if (!drivers::storage::BlockDeviceIsWritable(v->block_handle))
        return -1;
    if (ExfatFindInRoot(v, name) != nullptr)
        return -1; // duplicate

    u16 units[255];
    const u32 name_units = NameToUtf16(name, units, 255);
    if (name_units == 0)
        return -1;
    const u32 name_entries = (name_units + 14) / 15;
    const u32 total_slots = 2 + name_entries; // File + Stream + N FileName

    u64 slot_lba = 0;
    u32 slot_off = 0;
    if (!FindFreeSlots(*v, total_slots, &slot_lba, &slot_off))
        return -1; // root cluster full or set too big for one sector

    BitmapInfo bm{};
    if (!FindAllocationBitmap(*v, &bm))
        return -1;

    u32 first_cluster = 0;
    if (buf != nullptr && len > 0)
    {
        const u64 cb = ClusterBytes(*v);
        const u32 need = u32((len + cb - 1) / cb);
        u32 gf = 0;
        u32 gl = 0;
        if (!GrowChain(*v, bm, 0, 0, need, &gf, &gl))
            return -1;
        first_cluster = gf;
        // Plant the entry first so size/checksum reflect the content,
        // then write the bytes via the in-place writer.
        if (!PlantDirentSet(*v, slot_lba, slot_off, units, name_units, kAttrArchive, first_cluster, len))
            return -1;
        DirEntry tmp{};
        tmp.first_cluster = first_cluster;
        tmp.size_bytes = len;
        const i64 w = ExfatWriteInPlace(v, &tmp, 0, buf, len);
        if (w < 0 || u64(w) != len)
            return -1;
    }
    else
    {
        if (!PlantDirentSet(*v, slot_lba, slot_off, units, name_units, kAttrArchive, 0, 0))
            return -1;
    }
    (void)drivers::storage::BlockDeviceFlush(v->block_handle);
    RefreshRootSnapshot(*v);
    return i64(len);
}

i64 ExfatTruncateInRoot(Volume* v, const char* name, u64 new_size)
{
    if (v == nullptr || name == nullptr)
        return -1;
    if (!drivers::storage::BlockDeviceIsWritable(v->block_handle))
        return -1;

    SlotLoc loc{};
    if (!FindDirentSet(*v, name, &loc))
        return -1;
    const u64 cur = loc.size_bytes;
    if (new_size == cur)
        return i64(cur);

    if (new_size > cur)
    {
        // Grow with zero-fill. GrowChain zeroes new clusters; the
        // append writer needs a buffer, so grow the chain + bump the
        // size, and the new clusters are already zero.
        BitmapInfo bm{};
        if (!FindAllocationBitmap(*v, &bm))
            return -1;
        const u64 cb = ClusterBytes(*v);
        const u64 old_clusters = (cur + cb - 1) / cb;
        const u64 new_clusters = (new_size + cb - 1) / cb;
        u32 first = loc.first_cluster;
        u32 last = 0;
        if (first >= 2 && !ChainLast(*v, first, &last))
            return -1;
        if (new_clusters > old_clusters)
        {
            u32 nf = first;
            u32 nl = last;
            if (!GrowChain(*v, bm, first, last, u32(new_clusters - old_clusters), &nf, &nl))
                return -1;
            first = nf;
        }
        // Bump the size, then zero-fill the [cur, new_size) gap so the
        // grown region reads back as zero (newly allocated clusters are
        // already zeroed by GrowChain; this covers the slack inside the
        // old partial last cluster). A zero-length-old file (first == 0)
        // has all-new zeroed clusters, so the explicit fill is skipped.
        if (!PatchStreamSize(*v, loc, first, new_size))
            return -1;
        if (cur > 0 && first >= 2)
        {
            DirEntry tmp{};
            tmp.first_cluster = first;
            tmp.size_bytes = new_size;
            const u64 gap = (cb - (cur % cb)) % cb; // slack in the old last cluster
            for (u64 done = 0; done < gap;)
            {
                u8 zeros[64] = {};
                const u64 chunk = (gap - done) < sizeof(zeros) ? (gap - done) : sizeof(zeros);
                if (ExfatWriteInPlace(v, &tmp, cur + done, zeros, chunk) != i64(chunk))
                    return -1;
                done += chunk;
            }
        }
        (void)drivers::storage::BlockDeviceFlush(v->block_handle);
        RefreshRootSnapshot(*v);
        return i64(new_size);
    }

    // Shrink. Walk to the last cluster the new size still needs, mark
    // it EOC, and free everything after it. new_size == 0 releases the
    // whole chain and clears first_cluster.
    BitmapInfo bm{};
    if (!FindAllocationBitmap(*v, &bm))
        return -1;
    const u64 cb = ClusterBytes(*v);
    const u64 keep_clusters = (new_size + cb - 1) / cb;
    u32 new_first = loc.first_cluster;

    if (keep_clusters == 0)
    {
        if (loc.first_cluster >= 2 && !FreeChain(*v, bm, loc.first_cluster))
            return -1;
        new_first = 0;
    }
    else
    {
        u32 cluster = loc.first_cluster;
        for (u64 i = 1; i < keep_clusters; ++i)
        {
            u32 next = 0;
            if (!ReadFatEntry(*v, cluster, &next) || next < 2 || next >= kExfatBadCluster)
                return -1;
            cluster = next;
        }
        u32 tail = 0;
        if (!ReadFatEntry(*v, cluster, &tail))
            return -1;
        if (!WriteFatEntry(*v, cluster, kExfatEoc))
            return -1;
        if (tail >= 2 && tail < kExfatBadCluster)
        {
            if (!FreeChain(*v, bm, tail))
                return -1;
        }
    }
    if (!PatchStreamSize(*v, loc, new_first, new_size))
        return -1;
    (void)drivers::storage::BlockDeviceFlush(v->block_handle);
    RefreshRootSnapshot(*v);
    return i64(new_size);
}

} // namespace duetos::fs::exfat
