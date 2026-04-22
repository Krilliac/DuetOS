#include "ext4.h"

#include "../arch/x86_64/serial.h"
#include "../core/klog.h"
#include "../drivers/storage/block.h"

namespace customos::fs::ext4
{

namespace
{

Volume g_volumes[kMaxVolumes] = {};
u32 g_volume_count = 0;

// Static scratch buffer — kernel stack isn't in the direct map
// and BlockDeviceRead requires a direct-mapped destination.
// 1024 bytes covers the ext4 superblock; alignas(16) matches
// NVMe / AHCI DMA alignment expectations.
alignas(16) constinit u8 g_scratch[1024] = {};

// Pull a little-endian u16/u32/u64 out of a raw byte buffer.
inline u16 LeU16(const u8* p)
{
    return u16(p[0]) | (u16(p[1]) << 8);
}
inline u32 LeU32(const u8* p)
{
    return u32(p[0]) | (u32(p[1]) << 8) | (u32(p[2]) << 16) | (u32(p[3]) << 24);
}

// Superblock field offsets (relative to the superblock start, NOT
// the LBA start). See include/linux/ext4_fs.h / e2fsprogs.
constexpr u64 kSbOffInodeCount = 0x00;
constexpr u64 kSbOffBlockCountLo = 0x04;
constexpr u64 kSbOffLogBlockSize = 0x18; // block_size = 1024 << this
constexpr u64 kSbOffMagic = 0x38;
constexpr u64 kSbOffVolumeName = 0x78; // 16 bytes

} // namespace

bool Ext4Probe(u32 block_handle, u32* out_index)
{
    if (g_volume_count >= kMaxVolumes)
        return false;
    // Read the 1024-byte superblock. ext4 superblock lives at byte
    // 1024 regardless of block size — LBA 2 on a 512-byte-sector
    // device. We read 2 sectors (1024 bytes) into the static
    // scratch.
    const i32 rc = drivers::storage::BlockDeviceRead(block_handle, kSuperblockLba, 2, g_scratch);
    if (rc < 0)
        return false;
    const u8* sb = g_scratch;

    const u16 magic = LeU16(sb + kSbOffMagic);
    if (magic != kSuperblockMagic)
        return false;

    Volume v = {};
    v.block_handle = block_handle;
    v.block_size = u32(1024) << LeU32(sb + kSbOffLogBlockSize);
    v.block_count = LeU32(sb + kSbOffBlockCountLo);
    v.inode_count = LeU32(sb + kSbOffInodeCount);
    for (u32 i = 0; i < 16; ++i)
        v.label[i] = char(sb[kSbOffVolumeName + i]);
    v.label[16] = '\0';

    g_volumes[g_volume_count] = v;
    if (out_index != nullptr)
        *out_index = g_volume_count;
    ++g_volume_count;

    arch::SerialWrite("[ext4] probe OK handle=");
    arch::SerialWriteHex(block_handle);
    arch::SerialWrite(" block_size=");
    arch::SerialWriteHex(v.block_size);
    arch::SerialWrite(" label=\"");
    arch::SerialWrite(v.label);
    arch::SerialWrite("\" (mount path deferred)\n");
    return true;
}

u32 Ext4VolumeCount()
{
    return g_volume_count;
}

const Volume* Ext4VolumeByIndex(u32 index)
{
    if (index >= g_volume_count)
        return nullptr;
    return &g_volumes[index];
}

void Ext4ScanAll()
{
    KLOG_TRACE_SCOPE("fs/ext4", "Ext4ScanAll");
    const u32 n = drivers::storage::BlockDeviceCount();
    for (u32 i = 0; i < n; ++i)
    {
        u32 idx = 0;
        (void)Ext4Probe(i, &idx);
    }
    core::LogWithValue(core::LogLevel::Info, "fs/ext4", "ext4 volumes found", g_volume_count);
}

} // namespace customos::fs::ext4
