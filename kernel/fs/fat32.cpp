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

// Walk the directory cluster chain starting at `first_cluster` and
// fill `v.root_entries[]`. Stops at the first 0x00 entry, at an
// EOC FAT value, or when the entry cap is hit. LFN entries (attr
// == 0x0F) are skipped; so are deleted (byte 0 == 0xE5) and volume
// label (attr & 0x08) entries.
bool WalkDirectory(Volume& v, u32 first_cluster)
{
    v.root_entry_count = 0;
    u32 cluster = first_cluster;
    // Bounded loop: FAT32 chains can be long on real disks, but
    // we're filling a fixed-size snapshot. Cap at 64 clusters so
    // a bogus self-loop in the FAT doesn't spin forever.
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
                continue; // deleted
            const u8 attr = e[11];
            if ((attr & kAttrLongName) == kAttrLongName)
                continue; // LFN fragment
            if (attr & kAttrVolumeId)
                continue; // volume label, not a real file

            if (v.root_entry_count >= kMaxDirEntries)
                return true;
            DirEntry& out = v.root_entries[v.root_entry_count];
            VZero(&out, sizeof(out));
            FormatShortName(e, out.name);
            out.attributes = attr;
            const u16 cl_lo = LeU16(e + 26);
            const u16 cl_hi = LeU16(e + 20);
            out.first_cluster = (u32(cl_hi) << 16) | u32(cl_lo);
            out.size_bytes = LeU32(e + 28);
            ++v.root_entry_count;
        }
        cluster = ReadFatEntry(v, cluster);
    }
    return true;
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

    if (!WalkDirectory(v, v.root_cluster))
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
    if (any_file)
    {
        SerialWrite("[fs/fat32] self-test OK (at least one file in a root)\n");
    }
    else
    {
        SerialWrite("[fs/fat32] self-test WARN: volumes found but no files in any root\n");
    }
}

} // namespace customos::fs::fat32
