#include "exfat.h"

#include "../arch/x86_64/serial.h"
#include "../core/klog.h"
#include "../drivers/storage/block.h"

namespace customos::fs::exfat
{

namespace
{

Volume g_volumes[kMaxVolumes] = {};
u32 g_volume_count = 0;

alignas(16) constinit u8 g_scratch[512] = {};

// exFAT boot-sector offsets (per Microsoft's exFAT file system spec).
constexpr u64 kOffFileSystemName = 0x03; // "EXFAT   " (8 bytes)
constexpr u64 kOffPartitionOffset = 0x40;
constexpr u64 kOffVolumeLength = 0x48;
constexpr u64 kOffFatOffset = 0x50;
constexpr u64 kOffFatLength = 0x54;
constexpr u64 kOffClusterHeapOffset = 0x58;
constexpr u64 kOffClusterCount = 0x5C;
constexpr u64 kOffFirstClusterOfRoot = 0x60;
constexpr u64 kOffBytesPerSectorShift = 0x6C;
constexpr u64 kOffSectorsPerClusterShift = 0x6D;
constexpr u64 kOffBootSig = 0x1FE;

inline u32 LeU32(const u8* p)
{
    return u32(p[0]) | (u32(p[1]) << 8) | (u32(p[2]) << 16) | (u32(p[3]) << 24);
}
inline u64 LeU64(const u8* p)
{
    u64 r = 0;
    for (u64 i = 0; i < 8; ++i)
        r |= u64(p[i]) << (i * 8);
    return r;
}

bool MatchesFsName(const u8* sect)
{
    const u8 ref[8] = {'E', 'X', 'F', 'A', 'T', ' ', ' ', ' '};
    for (u64 i = 0; i < 8; ++i)
    {
        if (sect[kOffFileSystemName + i] != ref[i])
            return false;
    }
    return true;
}

} // namespace

bool ExfatProbe(u32 block_handle, u32* out_index)
{
    if (g_volume_count >= kMaxVolumes)
        return false;
    const i32 rc = drivers::storage::BlockDeviceRead(block_handle, kBootSectorLba, 1, g_scratch);
    if (rc < 0)
        return false;
    const u8* sect = g_scratch;
    if (sect[kOffBootSig] != 0x55 || sect[kOffBootSig + 1] != 0xAA)
        return false;
    if (!MatchesFsName(sect))
        return false;

    Volume v = {};
    v.block_handle = block_handle;
    v.partition_offset_bytes = LeU64(sect + kOffPartitionOffset);
    v.volume_length_sectors = LeU64(sect + kOffVolumeLength);
    v.fat_offset_sectors = LeU32(sect + kOffFatOffset);
    v.cluster_heap_offset_sectors = LeU32(sect + kOffClusterHeapOffset);
    v.cluster_count = LeU32(sect + kOffClusterCount);
    v.first_cluster_of_root = LeU32(sect + kOffFirstClusterOfRoot);
    v.bytes_per_sector_shift = sect[kOffBytesPerSectorShift];
    v.sectors_per_cluster_shift = sect[kOffSectorsPerClusterShift];

    g_volumes[g_volume_count] = v;
    if (out_index != nullptr)
        *out_index = g_volume_count;
    ++g_volume_count;

    arch::SerialWrite("[exfat] probe OK handle=");
    arch::SerialWriteHex(block_handle);
    arch::SerialWrite(" bps_shift=");
    arch::SerialWriteHex(v.bytes_per_sector_shift);
    arch::SerialWrite(" spc_shift=");
    arch::SerialWriteHex(v.sectors_per_cluster_shift);
    arch::SerialWrite(" cluster_count=");
    arch::SerialWriteHex(v.cluster_count);
    arch::SerialWrite(" (read-only parse deferred)\n");
    return true;
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
        u32 idx = 0;
        (void)ExfatProbe(i, &idx);
    }
    core::LogWithValue(core::LogLevel::Info, "fs/exfat", "exFAT volumes found", g_volume_count);
}

} // namespace customos::fs::exfat
