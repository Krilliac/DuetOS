#include "gpt.h"

#include "../arch/x86_64/serial.h"
#include "../core/klog.h"
#include "../drivers/storage/block.h"

namespace customos::fs::gpt
{

namespace
{

// --- CRC32 (IEEE 802.3, reflected, poly 0xEDB88320) -------------------------
//
// One table for both the GPT header CRC and the entry-array CRC. 1 KiB
// of .rodata, built on first use. The compiler could do this at compile
// time with a constexpr loop, but a runtime lazy-init keeps the code
// short and the .rodata hot. No thread-safety concern — the first
// caller runs in task context before anything else touches the table.

constinit u32 g_crc_table[256] = {};
constinit bool g_crc_table_ready = false;

void Crc32TableInit()
{
    if (g_crc_table_ready)
        return;
    for (u32 i = 0; i < 256; ++i)
    {
        u32 c = i;
        for (int j = 0; j < 8; ++j)
        {
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        }
        g_crc_table[i] = c;
    }
    g_crc_table_ready = true;
}

u32 Crc32(const u8* data, u64 len)
{
    Crc32TableInit();
    u32 c = 0xFFFFFFFFu;
    for (u64 i = 0; i < len; ++i)
    {
        c = g_crc_table[(c ^ data[i]) & 0xFFu] ^ (c >> 8);
    }
    return c ^ 0xFFFFFFFFu;
}

// --- GPT on-disk structures -------------------------------------------------

constexpr u64 kGptSignature = 0x5452415020494645ULL; // "EFI PART" LE
constexpr u32 kGptRevision1 = 0x00010000;
constexpr u32 kGptHeaderSize = 92;
constexpr u32 kGptEntryCountStd = 128;
constexpr u32 kGptEntrySizeStd = 128;

struct __attribute__((packed)) GptHeader
{
    u64 signature;
    u32 revision;
    u32 header_size;
    u32 header_crc32;
    u32 reserved;
    u64 my_lba;
    u64 alternate_lba;
    u64 first_usable_lba;
    u64 last_usable_lba;
    u8 disk_guid[16];
    u64 partition_entry_lba;
    u32 num_partition_entries;
    u32 partition_entry_size;
    u32 partition_entries_crc32;
};
static_assert(sizeof(GptHeader) == kGptHeaderSize, "GPT header must be 92 bytes");

struct __attribute__((packed)) GptEntry
{
    u8 type_guid[16];
    u8 unique_guid[16];
    u64 first_lba;
    u64 last_lba;
    u64 attributes;
    u8 name_utf16le[72];
};
static_assert(sizeof(GptEntry) == 128, "GPT entry must be 128 bytes");

// --- Registry ---------------------------------------------------------------

constinit Disk g_disks[kMaxDisks] = {};
constinit u32 g_disk_count = 0;

bool IsZeroGuid(const u8* guid)
{
    for (u32 i = 0; i < kGuidBytes; ++i)
        if (guid[i] != 0)
            return false;
    return true;
}

void CopyBytes(u8* dst, const u8* src, u64 n)
{
    for (u64 i = 0; i < n; ++i)
        dst[i] = src[i];
}

void ZeroBytes(u8* dst, u64 n)
{
    for (u64 i = 0; i < n; ++i)
        dst[i] = 0;
}

// Read `count` sectors starting at `lba` into `buf`, looping through the
// block layer's per-call cap if needed. Returns true on success.
bool ReadSectors(u32 handle, u32 sector_size, u64 lba, u32 count, u8* buf)
{
    const u32 per_call_max = 4096 / sector_size; // NVMe PRP1-only = 4 KiB cap
    u32 remaining = count;
    u64 cur_lba = lba;
    u8* cur_buf = buf;
    while (remaining > 0)
    {
        const u32 n = remaining < per_call_max ? remaining : per_call_max;
        if (drivers::storage::BlockDeviceRead(handle, cur_lba, n, cur_buf) != 0)
        {
            return false;
        }
        remaining -= n;
        cur_lba += n;
        cur_buf += u64(n) * sector_size;
    }
    return true;
}

bool ValidateProtectiveMbr(const u8* sector, u32 sector_size)
{
    if (sector_size < 512)
    {
        return false;
    }
    // 0xAA55 signature at 510..511.
    if (sector[510] != 0x55 || sector[511] != 0xAA)
    {
        core::Log(core::LogLevel::Warn, "fs/gpt", "LBA 0: missing 0x55AA boot signature");
        return false;
    }
    // At least one partition entry with type 0xEE (protective GPT).
    for (u32 i = 0; i < 4; ++i)
    {
        const u32 off = 446 + i * 16;
        if (sector[off + 4] == 0xEE)
        {
            return true;
        }
    }
    core::Log(core::LogLevel::Warn, "fs/gpt", "LBA 0: no 0xEE protective-GPT entry");
    return false;
}

bool ValidateGptHeader(const GptHeader& h, u64 sector_count, u32 sector_size)
{
    if (h.signature != kGptSignature)
    {
        core::Log(core::LogLevel::Warn, "fs/gpt", "LBA 1: header signature != 'EFI PART'");
        return false;
    }
    if (h.revision != kGptRevision1)
    {
        core::LogWithValue(core::LogLevel::Warn, "fs/gpt", "LBA 1: unsupported revision", h.revision);
        return false;
    }
    if (h.header_size < kGptHeaderSize || h.header_size > sector_size)
    {
        core::LogWithValue(core::LogLevel::Warn, "fs/gpt", "LBA 1: bad header_size", h.header_size);
        return false;
    }
    if (h.num_partition_entries != kGptEntryCountStd || h.partition_entry_size != kGptEntrySizeStd)
    {
        core::Log(core::LogLevel::Warn, "fs/gpt", "non-standard entry layout (v0 supports 128 x 128 only)");
        return false;
    }
    if (h.my_lba != 1)
    {
        core::LogWithValue(core::LogLevel::Warn, "fs/gpt", "primary my_lba != 1", h.my_lba);
        return false;
    }
    if (h.first_usable_lba >= sector_count || h.last_usable_lba >= sector_count)
    {
        core::Log(core::LogLevel::Warn, "fs/gpt", "usable LBA range past end of disk");
        return false;
    }
    // Header CRC: compute over the raw bytes with the crc32 field
    // temporarily zeroed. Save + restore so we don't mutate the caller's
    // copy. A naive `GptHeader copy = h` would pull in memcpy which the
    // freestanding kernel doesn't link against.
    auto* bytes = reinterpret_cast<u8*>(const_cast<GptHeader*>(&h));
    const u32 saved = h.header_crc32;
    for (u32 i = 0; i < 4; ++i)
        bytes[16 + i] = 0;
    const u32 computed = Crc32(bytes, h.header_size);
    for (u32 i = 0; i < 4; ++i)
        bytes[16 + i] = static_cast<u8>((saved >> (8 * i)) & 0xFFu);
    if (computed != saved)
    {
        core::LogWithValue(core::LogLevel::Warn, "fs/gpt", "header CRC mismatch; expected", saved);
        core::LogWithValue(core::LogLevel::Warn, "fs/gpt", "header CRC mismatch; computed", computed);
        return false;
    }
    return true;
}

// One hex digit → its ASCII character.
constexpr char kHexDigits[] = "0123456789abcdef";

void WriteByteHex(u8 b)
{
    const char out[3] = {kHexDigits[b >> 4], kHexDigits[b & 0xF], 0};
    arch::SerialWrite(out);
}

// Render a GPT GUID in the canonical mixed-endian form —
// AABBCCDD-EEFF-GGHH-IIJJ-KKLLMMNNOOPP — so the log line matches
// what `blkid` / `gdisk` would print for the same partition.
// Bytes 0..3 little-endian, 4..5 little-endian, 6..7 little-endian,
// 8..9 big-endian, 10..15 big-endian.
void WriteGuid(const u8* g)
{
    const int order[] = {3, 2, 1, 0, -1, 5, 4, -1, 7, 6, -1, 8, 9, -1, 10, 11, 12, 13, 14, 15};
    for (int i : order)
    {
        if (i < 0)
            arch::SerialWrite("-");
        else
            WriteByteHex(g[i]);
    }
}

void LogPartitionLine(const Partition& p, u32 index)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    SerialWrite("[fs/gpt]   part[");
    SerialWriteHex(index);
    SerialWrite("] first=");
    SerialWriteHex(p.first_lba);
    SerialWrite(" last=");
    SerialWriteHex(p.last_lba);
    SerialWrite(" type=");
    WriteGuid(p.type_guid);
    SerialWrite("\n");
}

} // namespace

bool GptProbe(u32 block_handle, u32* out_index)
{
    if (g_disk_count >= kMaxDisks)
    {
        core::Log(core::LogLevel::Warn, "fs/gpt", "disk registry full");
        return false;
    }
    const u32 sector_size = drivers::storage::BlockDeviceSectorSize(block_handle);
    const u64 sector_count = drivers::storage::BlockDeviceSectorCount(block_handle);
    if (sector_size < 512 || sector_count < 34)
    {
        core::Log(core::LogLevel::Warn, "fs/gpt", "disk too small or sector_size < 512");
        return false;
    }

    // Scratch buffers live in .bss (static) rather than on the stack.
    // The partition entry array alone is 16 KiB, and the per-task
    // kernel stack is 16 KiB total — a stack allocation would corrupt
    // the stack and triple-fault. Probing is single-threaded (boot-
    // time only), so static buffers are safe.
    static u8 sector[4096];
    if (sector_size > sizeof(sector))
    {
        core::Log(core::LogLevel::Warn, "fs/gpt", "sector_size exceeds scratch");
        return false;
    }

    // 1) Protective MBR at LBA 0.
    if (!ReadSectors(block_handle, sector_size, 0, 1, sector))
    {
        core::Log(core::LogLevel::Warn, "fs/gpt", "LBA 0 read failed");
        return false;
    }
    if (!ValidateProtectiveMbr(sector, sector_size))
    {
        return false;
    }

    // 2) Primary GPT header at LBA 1.
    if (!ReadSectors(block_handle, sector_size, 1, 1, sector))
    {
        core::Log(core::LogLevel::Warn, "fs/gpt", "LBA 1 read failed");
        return false;
    }
    GptHeader hdr{};
    CopyBytes(reinterpret_cast<u8*>(&hdr), sector, sizeof(hdr));
    if (!ValidateGptHeader(hdr, sector_count, sector_size))
    {
        return false;
    }

    // 3) Partition entry array. 128 * 128 = 16 KiB = 32 × 512-byte sectors
    // or 4 × 4096-byte sectors. Also in .bss — see rationale on `sector`.
    constexpr u64 kEntriesBytes = u64(kGptEntryCountStd) * kGptEntrySizeStd;
    static u8 entries[kEntriesBytes];
    const u64 array_sectors = (kEntriesBytes + sector_size - 1) / sector_size;
    if (hdr.partition_entry_lba + array_sectors > sector_count)
    {
        core::Log(core::LogLevel::Warn, "fs/gpt", "partition entry array past end of disk");
        return false;
    }
    if (!ReadSectors(block_handle, sector_size, hdr.partition_entry_lba, static_cast<u32>(array_sectors), entries))
    {
        core::Log(core::LogLevel::Warn, "fs/gpt", "partition entry array read failed");
        return false;
    }
    const u32 entries_crc = Crc32(entries, kEntriesBytes);
    if (entries_crc != hdr.partition_entries_crc32)
    {
        core::LogWithValue(core::LogLevel::Warn, "fs/gpt", "entry array CRC mismatch; expected",
                           hdr.partition_entries_crc32);
        core::LogWithValue(core::LogLevel::Warn, "fs/gpt", "entry array CRC mismatch; computed", entries_crc);
        return false;
    }

    // 4) Register the disk and collect non-empty partitions.
    Disk& disk = g_disks[g_disk_count];
    ZeroBytes(reinterpret_cast<u8*>(&disk), sizeof(disk));
    disk.block_handle = block_handle;
    disk.disk_sector_count = sector_count;
    disk.sector_size = sector_size;
    CopyBytes(disk.disk_guid, hdr.disk_guid, kGuidBytes);

    u32 found = 0;
    for (u32 i = 0; i < kGptEntryCountStd && found < kMaxPartitionsPerDisk; ++i)
    {
        const auto* e = reinterpret_cast<const GptEntry*>(entries + i * kGptEntrySizeStd);
        if (IsZeroGuid(e->type_guid))
            continue;
        if (e->first_lba > e->last_lba || e->last_lba >= sector_count)
        {
            core::LogWithValue(core::LogLevel::Warn, "fs/gpt", "partition entry out of range; idx", i);
            continue;
        }
        Partition& p = disk.partitions[found];
        p.first_lba = e->first_lba;
        p.last_lba = e->last_lba;
        p.attributes = e->attributes;
        CopyBytes(p.type_guid, e->type_guid, kGuidBytes);
        CopyBytes(p.unique_guid, e->unique_guid, kGuidBytes);
        CopyBytes(p.name_utf16le, e->name_utf16le, sizeof(p.name_utf16le));
        ++found;
    }
    disk.partition_count = found;
    const u32 index = g_disk_count;
    ++g_disk_count;

    arch::SerialWrite("[fs/gpt] disk handle=");
    arch::SerialWriteHex(block_handle);
    arch::SerialWrite(" partitions=");
    arch::SerialWriteHex(found);
    arch::SerialWrite("\n");
    for (u32 i = 0; i < found; ++i)
    {
        LogPartitionLine(disk.partitions[i], i);
    }

    if (out_index != nullptr)
        *out_index = index;
    return true;
}

u32 GptDiskCount()
{
    return g_disk_count;
}

const Disk* GptDisk(u32 index)
{
    if (index >= g_disk_count)
        return nullptr;
    return &g_disks[index];
}

void GptSelfTest()
{
    const u32 block_count = drivers::storage::BlockDeviceCount();
    arch::SerialWrite("[fs/gpt] probing ");
    arch::SerialWriteHex(block_count);
    arch::SerialWrite(" block devices\n");
    for (u32 h = 0; h < block_count; ++h)
    {
        arch::SerialWrite("[fs/gpt]  handle=");
        arch::SerialWriteHex(h);
        arch::SerialWrite(" name=");
        arch::SerialWrite(drivers::storage::BlockDeviceName(h));
        arch::SerialWrite("\n");
        u32 disk_idx = 0;
        if (GptProbe(h, &disk_idx))
        {
            arch::SerialWrite("[fs/gpt]   -> GPT OK, disk_idx=");
            arch::SerialWriteHex(disk_idx);
            arch::SerialWrite("\n");
        }
        else
        {
            arch::SerialWrite("[fs/gpt]   -> not a GPT disk (or parse failed)\n");
        }
    }
}

} // namespace customos::fs::gpt
