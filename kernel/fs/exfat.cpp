#include "exfat.h"

#include "../arch/x86_64/serial.h"
#include "../core/klog.h"
#include "../drivers/storage/block.h"

namespace duetos::fs::exfat
{

namespace
{

constinit Volume g_volumes[kMaxVolumes] = {};
u32 g_volume_count = 0;

// Scratch buffers. 4 KiB covers 8×512-byte sectors or 1×4 KiB
// sector; one cluster at minimum spc_shift=0 still fits 128 dir
// entries which is plenty for our per-volume cap. BlockDeviceRead
// needs a direct-map destination, so stack buffers won't do.
alignas(16) constinit u8 g_scratch[512] = {};
alignas(16) constinit u8 g_dir_scratch[4096] = {};

// Freestanding kernel — no libc memset. A whole-struct `= {}` on
// Volume (which includes kMaxDirEntries × 144-byte DirEntry array)
// would emit a memset call the link can't resolve. This helper
// keeps every zero-init explicit.
void ByteZero(void* dst, u64 n)
{
    auto* d = static_cast<volatile u8*>(dst);
    for (u64 i = 0; i < n; ++i)
        d[i] = 0;
}

// exFAT boot-sector offsets (per Microsoft's exFAT file system spec).
constexpr u64 kOffFileSystemName = 0x03; // "EXFAT   " (8 bytes)
constexpr u64 kOffPartitionOffset = 0x40;
constexpr u64 kOffVolumeLength = 0x48;
constexpr u64 kOffFatOffset = 0x50;
constexpr u64 kOffClusterHeapOffset = 0x58;
constexpr u64 kOffClusterCount = 0x5C;
constexpr u64 kOffFirstClusterOfRoot = 0x60;
constexpr u64 kOffBytesPerSectorShift = 0x6C;
constexpr u64 kOffSectorsPerClusterShift = 0x6D;
constexpr u64 kOffBootSig = 0x1FE;

// Directory-entry offsets (per the exFAT spec, §7).
constexpr u64 kFileEntryAttributes = 0x04;
constexpr u64 kStreamEntryNameLength = 0x03;
constexpr u64 kStreamEntryValidDataLen = 0x08;
constexpr u64 kStreamEntryFirstCluster = 0x14;
constexpr u64 kStreamEntryDataLength = 0x18;

inline u16 LeU16(const u8* p)
{
    return u16(p[0]) | (u16(p[1]) << 8);
}
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

// Translate a UTF-16LE code unit to a safe ASCII byte. Non-ASCII
// or control characters become '?'. We never emit NUL inside a
// name.
char Utf16ToSafeAscii(u16 cp)
{
    if (cp == 0)
        return '\0';
    if (cp >= 0x20 && cp < 0x7F)
        return char(cp);
    return '?';
}

// Parse one "entry set" starting at `start_idx` within `buf`.
// Returns the number of 32-byte slots consumed (SecondaryCount +
// 1), or 0 if this isn't a usable file entry. `buf_entries` is
// the total entry count in the buffer for bounds checks.
u32 ParseFileEntrySet(const u8* buf, u32 start_idx, u32 buf_entries, DirEntry* out)
{
    const u8* file_ent = buf + u64(start_idx) * 32;
    if ((file_ent[0] & 0x7F) != (kDirEntryFile & 0x7F))
        return 0;
    // Deleted entries have bit 7 of the type clear.
    if ((file_ent[0] & 0x80) == 0)
        return 0;

    const u8 secondary_count = file_ent[1];
    if (secondary_count < 2) // need at least StreamExt + 1 FileName
        return 1;
    const u32 total = u32(secondary_count) + 1;
    if (start_idx + total > buf_entries)
        return 1;

    const u8* stream_ent = file_ent + 32;
    if ((stream_ent[0] & 0x7F) != (kDirEntryStreamExt & 0x7F))
        return total;

    const u8 name_length = stream_ent[kStreamEntryNameLength];

    ByteZero(out, sizeof(*out));
    out->attributes = u8(LeU16(file_ent + kFileEntryAttributes));
    out->valid_data_len = LeU64(stream_ent + kStreamEntryValidDataLen);
    out->first_cluster = LeU32(stream_ent + kStreamEntryFirstCluster);
    out->size_bytes = LeU64(stream_ent + kStreamEntryDataLength);

    // Walk the FileName entries (0xC1), each contributing up to
    // 15 UTF-16 code units. Cap the decoded name at name[128].
    u32 name_pos = 0;
    u32 remaining_units = name_length;
    for (u32 k = 2; k < total; ++k)
    {
        const u8* name_ent = file_ent + u64(k) * 32;
        if ((name_ent[0] & 0x7F) != (kDirEntryFileName & 0x7F))
            continue;
        for (u32 u = 0; u < 15 && remaining_units > 0; ++u, --remaining_units)
        {
            const u16 cp = LeU16(name_ent + 2 + u * 2);
            const char c = Utf16ToSafeAscii(cp);
            if (c == '\0')
                break;
            if (name_pos + 1 < sizeof(out->name))
                out->name[name_pos++] = c;
        }
    }
    out->name[name_pos] = '\0';
    return total;
}

void WalkRootDir(Volume& v)
{
    const u32 bps = 1u << v.bytes_per_sector_shift;
    const u32 spc = 1u << v.sectors_per_cluster_shift;
    const u64 cluster_bytes = u64(bps) * spc;
    // First cluster of root. exFAT clusters are 2-indexed, matching
    // FAT32 convention.
    if (v.first_cluster_of_root < 2)
        return;
    const u64 root_sector = u64(v.cluster_heap_offset_sectors) + u64(v.first_cluster_of_root - 2) * spc;

    // Read up to sizeof(g_dir_scratch) of the root cluster. 4 KiB
    // is 128 entries; v0 cap is kMaxDirEntries=32 so even a very
    // full volume stays within this single read.
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
        arch::SerialWrite("[exfat]   root-dir read failed\n");
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

        // Parse directly into the registry slot so the sizeof
        // DirEntry (144+ bytes with name[128]) never appears on the
        // RHS of a struct copy — the freestanding link has no
        // memcpy.
        const u32 before = v.root_entry_count;
        DirEntry* slot = &v.root_entries[before];
        const u32 consumed = ParseFileEntrySet(g_dir_scratch, idx, entry_count, slot);
        if (consumed == 0)
        {
            ++idx;
            continue;
        }
        if (consumed > 1)
        {
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
        }
        idx += consumed;
    }
    arch::SerialWrite("[exfat]   parsed ");
    arch::SerialWriteHex(v.root_entry_count);
    arch::SerialWrite(" root-dir entries\n");
}

} // namespace

::duetos::core::Result<u32> ExfatProbe(u32 block_handle)
{
    using ::duetos::core::Err;
    using ::duetos::core::ErrorCode;
    if (g_volume_count >= kMaxVolumes)
        return Err{ErrorCode::BadState};
    const i32 rc = drivers::storage::BlockDeviceRead(block_handle, kBootSectorLba, 1, g_scratch);
    if (rc < 0)
        return Err{ErrorCode::IoError};
    const u8* sect = g_scratch;
    if (sect[kOffBootSig] != 0x55 || sect[kOffBootSig + 1] != 0xAA)
        return Err{ErrorCode::NotFound};
    if (!MatchesFsName(sect))
        return Err{ErrorCode::NotFound};

    // Build the volume record directly in its registry slot — avoids
    // a whole-struct copy (kMaxDirEntries × sizeof(DirEntry) would
    // otherwise emit a memcpy call the freestanding kernel can't
    // link).
    Volume& v = g_volumes[g_volume_count];
    ByteZero(&v, sizeof(v));
    v.block_handle = block_handle;
    v.partition_offset_bytes = LeU64(sect + kOffPartitionOffset);
    v.volume_length_sectors = LeU64(sect + kOffVolumeLength);
    v.fat_offset_sectors = LeU32(sect + kOffFatOffset);
    v.cluster_heap_offset_sectors = LeU32(sect + kOffClusterHeapOffset);
    v.cluster_count = LeU32(sect + kOffClusterCount);
    v.first_cluster_of_root = LeU32(sect + kOffFirstClusterOfRoot);
    v.bytes_per_sector_shift = sect[kOffBytesPerSectorShift];
    v.sectors_per_cluster_shift = sect[kOffSectorsPerClusterShift];

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

} // namespace duetos::fs::exfat
