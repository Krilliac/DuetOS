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
    v.bytes_per_sector_shift = bs.bytes_per_sector_shift;
    v.sectors_per_cluster_shift = bs.sectors_per_cluster_shift;

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
