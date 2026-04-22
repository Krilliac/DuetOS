#include "ntfs.h"

#include "../arch/x86_64/serial.h"
#include "../core/klog.h"
#include "../drivers/storage/block.h"

namespace customos::fs::ntfs
{

namespace
{

Volume g_volumes[kMaxVolumes] = {};
u32 g_volume_count = 0;

alignas(16) constinit u8 g_scratch[512] = {};

// Boot-sector field offsets (per NTFS on-disk format spec).
constexpr u64 kOffOemId = 0x03;             // "NTFS    " (8 bytes)
constexpr u64 kOffBytesPerSector = 0x0B;    // u16
constexpr u64 kOffSectorsPerCluster = 0x0D; // u8
constexpr u64 kOffTotalSectors = 0x28;      // i64 signed (always positive)
constexpr u64 kOffMftLcn = 0x30;            // u64
constexpr u64 kOffBootSig = 0x1FE;          // 0x55 0xAA

inline u16 LeU16(const u8* p)
{
    return u16(p[0]) | (u16(p[1]) << 8);
}
inline u64 LeU64(const u8* p)
{
    u64 r = 0;
    for (u64 i = 0; i < 8; ++i)
        r |= u64(p[i]) << (i * 8);
    return r;
}

bool MatchesOem(const u8* sect)
{
    // "NTFS    " — exact 8 bytes starting at offset 3.
    const u8 ref[8] = {'N', 'T', 'F', 'S', ' ', ' ', ' ', ' '};
    for (u64 i = 0; i < 8; ++i)
    {
        if (sect[kOffOemId + i] != ref[i])
            return false;
    }
    return true;
}

} // namespace

bool NtfsProbe(u32 block_handle, u32* out_index)
{
    if (g_volume_count >= kMaxVolumes)
        return false;
    const i32 rc = drivers::storage::BlockDeviceRead(block_handle, kBootSectorLba, 1, g_scratch);
    if (rc < 0)
        return false;
    const u8* sect = g_scratch;
    if (sect[kOffBootSig] != 0x55 || sect[kOffBootSig + 1] != 0xAA)
        return false;
    if (!MatchesOem(sect))
        return false;

    Volume v = {};
    v.block_handle = block_handle;
    v.bytes_per_sector = LeU16(sect + kOffBytesPerSector);
    v.sectors_per_cluster = sect[kOffSectorsPerCluster];
    v.total_sectors = LeU64(sect + kOffTotalSectors);
    v.mft_lcn = LeU64(sect + kOffMftLcn);

    g_volumes[g_volume_count] = v;
    if (out_index != nullptr)
        *out_index = g_volume_count;
    ++g_volume_count;

    arch::SerialWrite("[ntfs] probe OK handle=");
    arch::SerialWriteHex(block_handle);
    arch::SerialWrite(" bps=");
    arch::SerialWriteHex(v.bytes_per_sector);
    arch::SerialWrite(" spc=");
    arch::SerialWriteHex(v.sectors_per_cluster);
    arch::SerialWrite(" mft_lcn=");
    arch::SerialWriteHex(v.mft_lcn);
    arch::SerialWrite(" (read-only parse deferred)\n");
    return true;
}

u32 NtfsVolumeCount()
{
    return g_volume_count;
}

const Volume* NtfsVolumeByIndex(u32 index)
{
    if (index >= g_volume_count)
        return nullptr;
    return &g_volumes[index];
}

void NtfsScanAll()
{
    KLOG_TRACE_SCOPE("fs/ntfs", "NtfsScanAll");
    const u32 n = drivers::storage::BlockDeviceCount();
    for (u32 i = 0; i < n; ++i)
    {
        u32 idx = 0;
        (void)NtfsProbe(i, &idx);
    }
    core::LogWithValue(core::LogLevel::Info, "fs/ntfs", "NTFS volumes found", g_volume_count);
}

} // namespace customos::fs::ntfs
