#include "fs/fat32.h"

#include "drivers/storage/block.h"
#include "fs/fat32_internal.h"
#include "log/klog.h"
#include "mm/kheap.h"

namespace duetos::fs::fat32
{

namespace
{

constexpr u32 kSectorSize = 512;
constexpr u32 kReservedSectors = 32; // standard for mkfs.fat
constexpr u32 kNumFats = 2;
constexpr u32 kRootCluster = 2;
constexpr u32 kFsInfoLba = 1;
constexpr u32 kBackupBootLba = 6;

// Pick a sectors-per-cluster that keeps the cluster count in the
// FAT32-valid window (>= 65525 per Microsoft's FAT spec). For
// partitions ≤ 260 MiB we use 1 sector/cluster; the floor scales
// with partition size the way mkfs.fat does.
u8 PickSectorsPerCluster(u64 partition_sector_count)
{
    const u64 mib = (partition_sector_count * kSectorSize) / (1024ull * 1024ull);
    if (mib <= 260)
        return 1;
    if (mib <= 8192)
        return 8;
    if (mib <= 16384)
        return 16;
    if (mib <= 32768)
        return 32;
    return 64;
}

// Compute fat_size in sectors per the standard derivation
// (Microsoft FAT spec §3.5): treat each FAT entry as 4 bytes,
// subtract reserved + 32 sectors of slack, divide.
u32 ComputeFatSizeSectors(u64 partition_sector_count, u8 sectors_per_cluster)
{
    const u64 root_dir_sectors = 0; // FAT32 uses a clustered root, not a fixed region
    const u64 tmp_val_1 = partition_sector_count - kReservedSectors - root_dir_sectors;
    const u64 tmp_val_2 = (256ull * sectors_per_cluster) + kNumFats;
    return u32((tmp_val_1 + tmp_val_2 - 1) / tmp_val_2);
}

inline void StoreU16(u8* p, u16 v)
{
    p[0] = u8(v);
    p[1] = u8(v >> 8);
}

inline void StoreU32(u8* p, u32 v)
{
    p[0] = u8(v);
    p[1] = u8(v >> 8);
    p[2] = u8(v >> 16);
    p[3] = u8(v >> 24);
}

void BuildBootSector(u8 sec[kSectorSize], u32 sectors_per_cluster, u32 fat_size_sectors, u64 partition_sector_count)
{
    for (u32 i = 0; i < kSectorSize; ++i)
        sec[i] = 0;
    // Jump instruction (BS_jmpBoot) — eb 58 90: short jump + nop.
    sec[0] = 0xEB;
    sec[1] = 0x58;
    sec[2] = 0x90;
    // BS_OEMName = "MSWIN4.1" — what every interop reader expects.
    sec[3] = 'M';
    sec[4] = 'S';
    sec[5] = 'W';
    sec[6] = 'I';
    sec[7] = 'N';
    sec[8] = '4';
    sec[9] = '.';
    sec[10] = '1';
    // BPB.
    StoreU16(sec + 11, kSectorSize);      // bytes_per_sector
    sec[13] = u8(sectors_per_cluster);    // sectors_per_cluster
    StoreU16(sec + 14, kReservedSectors); // reserved_sector_count
    sec[16] = kNumFats;                   // num_fats
    StoreU16(sec + 17, 0);                // root_entry_count = 0 for FAT32
    StoreU16(sec + 19, 0);                // total_sectors_16 = 0 (use 32-bit)
    sec[21] = 0xF8;                       // media descriptor (fixed disk)
    StoreU16(sec + 22, 0);                // fat_size_16 = 0 (use 32-bit)
    StoreU16(sec + 24, 63);               // sectors_per_track (legacy)
    StoreU16(sec + 26, 255);              // num_heads (legacy)
    StoreU32(sec + 28, 0);                // hidden_sectors
    const u32 total32 = (partition_sector_count > 0xFFFFFFFFull) ? 0xFFFFFFFFu : u32(partition_sector_count);
    StoreU32(sec + 32, total32); // total_sectors_32
    // FAT32 extended BPB.
    StoreU32(sec + 36, fat_size_sectors); // fat_size_32
    StoreU16(sec + 40, 0);                // ext_flags (mirroring on)
    StoreU16(sec + 42, 0);                // fs_version
    StoreU32(sec + 44, kRootCluster);     // root_cluster
    StoreU16(sec + 48, kFsInfoLba);       // fs_info_sector
    StoreU16(sec + 50, kBackupBootLba);   // backup_boot_sector
    // Reserved (12 bytes at 52..63) stays zero.
    sec[64] = 0x80; // drive_number
    sec[65] = 0;    // reserved
    sec[66] = 0x29; // boot_sig (extended)
    // volume_id + label are the DuetOS-ownership markers Fat32Probe
    // checks (see Fat32VolumeIsDuetOsOwned). Stamped from the shared
    // fat32.h constants so the formatter and the adoption gate can't
    // drift; tools/qemu/make-gpt-image.py stamps the same values.
    StoreU32(sec + 67, kDuetOsVolumeId); // volume_id (DuetOS-owned marker)
    // Volume label (11 bytes) = "DUETOS     " (space-padded).
    u32 lbl = 0;
    for (; kDuetOsVolumeLabel[lbl] != '\0' && lbl < 11; ++lbl)
        sec[71 + lbl] = static_cast<u8>(kDuetOsVolumeLabel[lbl]);
    for (; lbl < 11; ++lbl)
        sec[71 + lbl] = ' ';
    // Filesystem-type string "FAT32   " (8 bytes).
    sec[82] = 'F';
    sec[83] = 'A';
    sec[84] = 'T';
    sec[85] = '3';
    sec[86] = '2';
    sec[87] = ' ';
    sec[88] = ' ';
    sec[89] = ' ';
    // Boot signature.
    sec[510] = 0x55;
    sec[511] = 0xAA;
}

void BuildFsInfo(u8 sec[kSectorSize], u32 free_count)
{
    for (u32 i = 0; i < kSectorSize; ++i)
        sec[i] = 0;
    // Lead signature "RRaA" at byte 0.
    StoreU32(sec + 0, 0x41615252u);
    // Struct signature "rrAa" at byte 484.
    StoreU32(sec + 484, 0x61417272u);
    StoreU32(sec + 488, free_count);       // free_count
    StoreU32(sec + 492, kRootCluster + 1); // next_free hint
    // Trail signature 0x000055AA at byte 508.
    sec[508] = 0x00;
    sec[509] = 0x00;
    sec[510] = 0x55;
    sec[511] = 0xAA;
}

} // namespace

bool Fat32Format(u32 block_handle, u64 partition_sector_count)
{
    internal::Fat32InvalidatePathCache(); // every prior path resolution is now void
    if (!drivers::storage::BlockDeviceIsWritable(block_handle))
    {
        core::Log(core::LogLevel::Warn, "fs/fat32", "Fat32Format: handle not writable");
        return false;
    }
    if (partition_sector_count < 65600ull)
    {
        core::Log(core::LogLevel::Warn, "fs/fat32", "Fat32Format: partition < 32 MiB (FAT32 floor)");
        return false;
    }

    const u8 spc = PickSectorsPerCluster(partition_sector_count);
    const u32 fat_size = ComputeFatSizeSectors(partition_sector_count, spc);
    const u32 fats_total_sectors = fat_size * kNumFats;
    const u64 data_sectors_total = partition_sector_count - kReservedSectors - fats_total_sectors;
    if (data_sectors_total < spc)
    {
        core::Log(core::LogLevel::Warn, "fs/fat32", "Fat32Format: no room for data clusters");
        return false;
    }
    const u32 cluster_count = u32(data_sectors_total / spc);
    if (cluster_count < 65525)
    {
        core::Log(core::LogLevel::Warn, "fs/fat32", "Fat32Format: < 65525 clusters (Microsoft FAT32 floor)");
        return false;
    }

    // ---- Boot sector (LBA 0).
    u8 sec[kSectorSize];
    BuildBootSector(sec, spc, fat_size, partition_sector_count);
    if (drivers::storage::BlockDeviceWrite(block_handle, 0, 1, sec) < 0)
    {
        core::Log(core::LogLevel::Error, "fs/fat32", "Fat32Format: boot sector write failed");
        return false;
    }
    // ---- Backup boot sector (LBA 6) — same bytes.
    if (drivers::storage::BlockDeviceWrite(block_handle, kBackupBootLba, 1, sec) < 0)
    {
        core::Log(core::LogLevel::Error, "fs/fat32", "Fat32Format: backup boot write failed");
        return false;
    }

    // ---- FSInfo (LBA 1).
    BuildFsInfo(sec, cluster_count - 1); // root cluster consumes one
    if (drivers::storage::BlockDeviceWrite(block_handle, kFsInfoLba, 1, sec) < 0)
    {
        core::Log(core::LogLevel::Error, "fs/fat32", "Fat32Format: FSInfo write failed");
        return false;
    }

    // ---- Both FATs: zero all sectors first, then patch the leading
    // three entries on FAT #1's first sector.
    for (u32 i = 0; i < kSectorSize; ++i)
        sec[i] = 0;
    for (u32 fat_idx = 0; fat_idx < kNumFats; ++fat_idx)
    {
        const u32 fat_start = kReservedSectors + fat_idx * fat_size;
        for (u32 s = 0; s < fat_size; ++s)
        {
            if (drivers::storage::BlockDeviceWrite(block_handle, fat_start + s, 1, sec) < 0)
            {
                core::Log(core::LogLevel::Error, "fs/fat32", "Fat32Format: FAT zero-fill failed");
                return false;
            }
        }
    }
    // Patch FAT entries: [0]=0x0FFFFFF8 (matches media descriptor),
    // [1]=0x0FFFFFFF (clean shutdown bit set), [2]=0x0FFFFFFF (root
    // cluster end-of-chain).
    StoreU32(sec + 0, 0x0FFFFFF8u);
    StoreU32(sec + 4, 0x0FFFFFFFu);
    StoreU32(sec + 8, 0x0FFFFFFFu);
    for (u32 fat_idx = 0; fat_idx < kNumFats; ++fat_idx)
    {
        const u32 fat_start = kReservedSectors + fat_idx * fat_size;
        if (drivers::storage::BlockDeviceWrite(block_handle, fat_start, 1, sec) < 0)
        {
            core::Log(core::LogLevel::Error, "fs/fat32", "Fat32Format: FAT entry write failed");
            return false;
        }
    }

    // ---- Root cluster: zero `spc` sectors at the data area's first
    // cluster (which is cluster 2).
    for (u32 i = 0; i < kSectorSize; ++i)
        sec[i] = 0;
    const u32 data_start_lba = kReservedSectors + fats_total_sectors;
    for (u32 s = 0; s < spc; ++s)
    {
        if (drivers::storage::BlockDeviceWrite(block_handle, data_start_lba + s, 1, sec) < 0)
        {
            core::Log(core::LogLevel::Error, "fs/fat32", "Fat32Format: root-cluster zero failed");
            return false;
        }
    }

    core::Log(core::LogLevel::Info, "fs/fat32", "Fat32Format: FAT32 layout written");
    return true;
}

} // namespace duetos::fs::fat32
