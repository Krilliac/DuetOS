#include "ntfs.h"

#include "../arch/x86_64/serial.h"
#include "../core/klog.h"
#include "../drivers/storage/block.h"

namespace customos::fs::ntfs
{

namespace
{

constinit Volume g_volumes[kMaxVolumes] = {};
u32 g_volume_count = 0;

alignas(16) constinit u8 g_scratch[512] = {};
// MFT records are typically 1024 bytes; give ourselves headroom for
// 4096-byte records (some modern formats).
alignas(16) constinit u8 g_mft_scratch[4096] = {};

// Boot-sector field offsets (per NTFS on-disk format spec).
constexpr u64 kOffOemId = 0x03;                // "NTFS    " (8 bytes)
constexpr u64 kOffBytesPerSector = 0x0B;       // u16
constexpr u64 kOffSectorsPerCluster = 0x0D;    // u8
constexpr u64 kOffTotalSectors = 0x28;         // i64 signed (always positive)
constexpr u64 kOffMftLcn = 0x30;               // u64
constexpr u64 kOffClustersPerMftRecord = 0x40; // i8
constexpr u64 kOffBootSig = 0x1FE;             // 0x55 0xAA

// MFT record header layout.
constexpr u64 kMftRecSig = 0x00;          // u32 = 'FILE'
constexpr u64 kMftRecFirstAttrOff = 0x14; // u16
constexpr u64 kMftRecFlags = 0x16;        // u16: bit 0 in-use, bit 1 dir

// Attribute header common fields.
constexpr u64 kAttrType = 0x00;        // u32
constexpr u64 kAttrLength = 0x04;      // u32 (total bytes including header)
constexpr u64 kAttrNonResident = 0x08; // u8
constexpr u64 kAttrResValueLen = 0x10; // u32 (resident only)
constexpr u64 kAttrResValueOff = 0x14; // u16 (resident only)

constexpr u32 kAttrTypeFileName = 0x30;
constexpr u32 kAttrTypeEnd = 0xFFFFFFFFu;

// $FILE_NAME attribute body offsets. (namespace byte at 0x41 is
// captured in the on-disk layout but unused here — we decode every
// namespace's name identically.)
constexpr u64 kFnNameLength = 0x40; // u8: UTF-16 code units
constexpr u64 kFnNameUtf16 = 0x42;

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

void ByteZero(void* dst, u64 n)
{
    auto* d = static_cast<volatile u8*>(dst);
    for (u64 i = 0; i < n; ++i)
        d[i] = 0;
}

bool MatchesOem(const u8* sect)
{
    const u8 ref[8] = {'N', 'T', 'F', 'S', ' ', ' ', ' ', ' '};
    for (u64 i = 0; i < 8; ++i)
    {
        if (sect[kOffOemId + i] != ref[i])
            return false;
    }
    return true;
}

// Translate UTF-16LE to safe ASCII; non-ASCII or control chars
// become '?'.
char Utf16ToSafeAscii(u16 cp)
{
    if (cp == 0)
        return '\0';
    if (cp >= 0x20 && cp < 0x7F)
        return char(cp);
    return '?';
}

// BPB's clusters_per_mft_record is a signed byte. Positive: that
// many clusters per record. Negative N: record size = 2^(-N).
u32 DecodeMftRecordSize(i8 raw, u32 bytes_per_cluster)
{
    if (raw > 0)
        return u32(raw) * bytes_per_cluster;
    const u32 shift = u32(-i32(raw)) & 0x3F;
    if (shift >= 32)
        return 0;
    return 1u << shift;
}

// Extract the (first) $FILE_NAME attribute from an MFT record and
// decode its UTF-16 name. Returns true on success. `rec` points to
// the start of the MFT record (not the attribute); `rec_size` is
// the total record size in bytes.
bool ExtractFileName(const u8* rec, u32 rec_size, char* out_name, u64 out_cap)
{
    const u16 first_attr_off = LeU16(rec + kMftRecFirstAttrOff);
    if (first_attr_off >= rec_size)
        return false;
    u64 off = first_attr_off;
    while (off + 8 <= rec_size) // at least type+length
    {
        const u32 type = LeU32(rec + off + kAttrType);
        if (type == kAttrTypeEnd)
            return false;
        const u32 len = LeU32(rec + off + kAttrLength);
        if (len == 0 || off + len > rec_size)
            return false;

        if (type == kAttrTypeFileName)
        {
            const u8 non_res = rec[off + kAttrNonResident];
            if (non_res == 0) // only handle resident $FILE_NAME
            {
                const u32 val_len = LeU32(rec + off + kAttrResValueLen);
                const u16 val_off = LeU16(rec + off + kAttrResValueOff);
                if (u64(val_off) + val_len <= len)
                {
                    const u8* fn = rec + off + val_off;
                    // Sanity: $FILE_NAME must carry at least the
                    // fixed header + 1 UTF-16 unit.
                    if (val_len >= kFnNameUtf16 + 2)
                    {
                        const u8 name_len = fn[kFnNameLength];
                        u64 write_pos = 0;
                        for (u32 u = 0; u < name_len; ++u)
                        {
                            const u64 byte_off = kFnNameUtf16 + u64(u) * 2;
                            if (byte_off + 2 > val_len)
                                break;
                            const u16 cp = LeU16(fn + byte_off);
                            const char c = Utf16ToSafeAscii(cp);
                            if (c == '\0')
                                break;
                            if (write_pos + 1 < out_cap)
                                out_name[write_pos++] = c;
                        }
                        out_name[write_pos] = '\0';
                        return write_pos > 0;
                    }
                }
            }
        }
        off += len;
    }
    return false;
}

void WalkSystemRecords(Volume& v)
{
    if (v.mft_record_size == 0 || v.mft_record_size > sizeof(g_mft_scratch))
    {
        arch::SerialWrite("[ntfs]   mft record size out of supported range, skipping walk\n");
        return;
    }
    if (v.bytes_per_sector == 0)
        return;
    const u32 bps = v.bytes_per_sector;
    const u32 sectors_per_record = v.mft_record_size / bps;
    if (sectors_per_record == 0 || (v.mft_record_size % bps) != 0)
        return;
    const u64 mft_start_lba = v.mft_lcn * v.sectors_per_cluster;

    for (u32 i = 0; i < kMaxMftRecords && v.system_record_count < kMaxMftRecords; ++i)
    {
        const u64 rec_lba = mft_start_lba + u64(i) * sectors_per_record;
        const i32 rc = drivers::storage::BlockDeviceRead(v.block_handle, rec_lba, sectors_per_record, g_mft_scratch);
        if (rc < 0)
            break;
        if (LeU32(g_mft_scratch + kMftRecSig) != kFileRecordMagic)
            continue;

        MftEntry& slot = v.system_records[v.system_record_count++];
        ByteZero(&slot, sizeof(slot));
        slot.record_num = i;
        const u16 flags = LeU16(g_mft_scratch + kMftRecFlags);
        slot.in_use = (flags & 0x1) != 0;
        slot.is_directory = (flags & 0x2) != 0;
        const bool got_name = ExtractFileName(g_mft_scratch, v.mft_record_size, slot.name, sizeof(slot.name));
        if (!got_name)
        {
            // Record is valid but has no resident $FILE_NAME (rare
            // for systems files 0..15, but possible for 8: $BadClus
            // which stores its name in a namespace we didn't pick).
            slot.name[0] = '?';
            slot.name[1] = '\0';
        }
        arch::SerialWrite("[ntfs]   mft#");
        arch::SerialWriteHex(i);
        arch::SerialWrite(" name=");
        arch::SerialWrite(slot.name);
        arch::SerialWrite(slot.is_directory ? " (dir)" : " (file)");
        arch::SerialWrite(slot.in_use ? "" : " [deleted]");
        arch::SerialWrite("\n");
    }
    arch::SerialWrite("[ntfs]   parsed ");
    arch::SerialWriteHex(v.system_record_count);
    arch::SerialWrite(" system records\n");
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

    Volume& v = g_volumes[g_volume_count];
    ByteZero(&v, sizeof(v));
    v.block_handle = block_handle;
    v.bytes_per_sector = LeU16(sect + kOffBytesPerSector);
    v.sectors_per_cluster = sect[kOffSectorsPerCluster];
    v.total_sectors = LeU64(sect + kOffTotalSectors);
    v.mft_lcn = LeU64(sect + kOffMftLcn);
    v.clusters_per_mft_record = i8(sect[kOffClustersPerMftRecord]);
    const u32 bytes_per_cluster = u32(v.bytes_per_sector) * u32(v.sectors_per_cluster);
    v.mft_record_size = DecodeMftRecordSize(v.clusters_per_mft_record, bytes_per_cluster);

    arch::SerialWrite("[ntfs] probe OK handle=");
    arch::SerialWriteHex(block_handle);
    arch::SerialWrite(" bps=");
    arch::SerialWriteHex(v.bytes_per_sector);
    arch::SerialWrite(" spc=");
    arch::SerialWriteHex(v.sectors_per_cluster);
    arch::SerialWrite(" mft_lcn=");
    arch::SerialWriteHex(v.mft_lcn);
    arch::SerialWrite(" mft_record_size=");
    arch::SerialWriteHex(v.mft_record_size);
    arch::SerialWrite("\n");

    WalkSystemRecords(v);

    if (out_index != nullptr)
        *out_index = g_volume_count;
    ++g_volume_count;
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
