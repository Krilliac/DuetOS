/*
 * DuetOS — NTFS driver, v0 probe + $MFT system-record walk.
 *
 * The byte-parsing layer lives in Rust (`kernel/fs/ntfs_rust`):
 * boot-sector validation, MFT record header decode, resident
 * $FILE_NAME attribute walk, and mapping-pairs runlist decode.
 * This C++ TU owns block I/O, the per-volume registry, scratch
 * buffers, logging, and the UTF-16 → ASCII glyph filter.
 */

#include "fs/ntfs.h"

#include "arch/x86_64/serial.h"
#include "drivers/storage/block.h"
#include "fs/ntfs_rust/include/ntfs_rust.h"
#include "log/klog.h"
#include "util/unicode.h"

namespace duetos::fs::ntfs
{

namespace
{

constinit Volume g_volumes[kMaxVolumes] = {};
u32 g_volume_count = 0;

alignas(16) constinit u8 g_scratch[512] = {};
// MFT records are typically 1024 bytes; give ourselves headroom for
// 4096-byte records (some modern formats).
alignas(16) constinit u8 g_mft_scratch[4096] = {};

void ByteZero(void* dst, u64 n)
{
    auto* d = static_cast<volatile u8*>(dst);
    for (u64 i = 0; i < n; ++i)
        d[i] = 0;
}

// Decode the resident $FILE_NAME UTF-16 name into the caller's
// ASCII buffer using the project's safe-glyph filter. Returns true
// if at least one code unit decoded into a printable ASCII glyph.
bool DecodeFileName(const u8* rec, u64 rec_len, const DuetosNtfsFileNameSpan& span, char* out_name, u64 out_cap)
{
    if (span.ok == 0 || out_cap == 0)
        return false;
    u64 write_pos = 0;
    for (u32 u = 0; u < span.utf16_units; ++u)
    {
        const u64 byte_off = static_cast<u64>(span.utf16_offset) + static_cast<u64>(u) * 2;
        // Bound the read against the MFT record we were handed. A
        // malformed $FILE_NAME span from the Rust parser would
        // otherwise let this read past the scratch buffer's end.
        if (byte_off + 1 >= rec_len)
            break;
        const u16 cp = static_cast<u16>(rec[byte_off]) | (static_cast<u16>(rec[byte_off + 1]) << 8);
        const char c = duetos::util::Utf16CpToSafeAscii(u32(cp));
        if (c == '\0')
            break;
        if (write_pos + 1 < out_cap)
            out_name[write_pos++] = c;
    }
    out_name[write_pos] = '\0';
    return write_pos > 0;
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

        DuetosNtfsMftRecordHeader hdr{};
        if (!duetos_ntfs_parse_mft_record_header(g_mft_scratch, v.mft_record_size, v.mft_record_size, &hdr))
        {
            // Not a "FILE" record (or truncated) — leave the slot
            // unconsumed and continue.
            continue;
        }

        MftEntry& slot = v.system_records[v.system_record_count++];
        ByteZero(&slot, sizeof(slot));
        slot.record_num = i;
        slot.in_use = hdr.in_use != 0;
        slot.is_directory = hdr.is_directory != 0;

        DuetosNtfsFileNameSpan span{};
        const bool got_name =
            duetos_ntfs_find_resident_file_name(g_mft_scratch, v.mft_record_size, v.mft_record_size, &span) &&
            DecodeFileName(g_mft_scratch, v.mft_record_size, span, slot.name, sizeof(slot.name));
        if (!got_name)
        {
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

::duetos::core::Result<u32> NtfsProbe(u32 block_handle)
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

    DuetosNtfsBootSector bs{};
    if (!duetos_ntfs_parse_boot_sector(g_scratch, sizeof(g_scratch), &bs))
        return Err{ErrorCode::NotFound};
    if (bs.ok == 0)
        return Err{ErrorCode::NotFound};

    Volume& v = g_volumes[g_volume_count];
    ByteZero(&v, sizeof(v));
    v.block_handle = block_handle;
    // Field-by-field copy between the Rust struct and the C++
    // Volume so layout drift can't silently break callers.
    v.bytes_per_sector = bs.bytes_per_sector;
    v.sectors_per_cluster = bs.sectors_per_cluster;
    if (v.bytes_per_sector == 0 || v.bytes_per_sector > 4096 || v.sectors_per_cluster == 0)
        return Err{ErrorCode::Corrupt};
    v.total_sectors = bs.total_sectors;
    v.mft_lcn = bs.mft_lcn;
    v.clusters_per_mft_record = bs.clusters_per_mft_record;
    const u32 bytes_per_cluster = u32(v.bytes_per_sector) * u32(v.sectors_per_cluster);
    v.mft_record_size = duetos_ntfs_decode_mft_record_size(v.clusters_per_mft_record, bytes_per_cluster);
    if (v.mft_record_size == 0)
        return Err{ErrorCode::Corrupt};

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

    return g_volume_count++;
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
        auto r = NtfsProbe(i);
        if (!r && r.error() != ::duetos::core::ErrorCode::NotFound)
        {
            arch::SerialWrite("[ntfs] handle=");
            arch::SerialWriteHex(i);
            arch::SerialWrite(" probe error=");
            arch::SerialWrite(::duetos::core::ErrorCodeName(r.error()));
            arch::SerialWrite("\n");
        }
    }
    core::LogWithValue(core::LogLevel::Info, "fs/ntfs", "NTFS volumes found", g_volume_count);
}

} // namespace duetos::fs::ntfs
