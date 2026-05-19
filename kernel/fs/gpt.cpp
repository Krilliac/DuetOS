#include "fs/gpt.h"

#include "arch/x86_64/serial.h"
#include "drivers/storage/block.h"
#include "log/klog.h"
#include "mm/kheap.h"
#include "util/crc32.h"

namespace duetos::fs::gpt
{

namespace
{

using duetos::util::Crc32;

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

// Static storage for generated partition-device names — one name
// per (disk, partition) slot, kept alive for the kernel's lifetime
// so the block-layer registry can hold the pointer. Linux-style
// 1-based naming: "<parent>pN", e.g. "sata0p1", "nvme0n1p2".
constinit char g_part_names[kMaxDisks][kMaxPartitionsPerDisk][20] = {};

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

bool ValidateGptHeader(const GptHeader& h, u64 sector_count)
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
    // header_size must be EXACTLY the canonical 92. The struct is
    // fixed at sizeof(GptHeader)==92 and only 92 bytes are copied
    // out of the sector into `hdr`; the header CRC below runs over
    // `header_size` bytes of that 92-byte buffer. The old bound
    // (>= 92 && <= sector_size) let an attacker-supplied
    // header_size up to the 512-byte sector drive Crc32 ~420 bytes
    // off the end of the stack struct (the GPT fuzzer caught this
    // as a stack-buffer-overflow). UEFI permits a larger header
    // with zeroed reserved tail, but every real mkfs/parted emits
    // exactly 92 and this v0 already rejects all other
    // non-canonical layouts (entry count/size), so pin it here.
    if (h.header_size != kGptHeaderSize)
    {
        core::LogWithValue(core::LogLevel::Warn, "fs/gpt", "LBA 1: non-canonical header_size", h.header_size);
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

// Map a GPT type-GUID to a short name. Returns "" when the GUID
// isn't one we've catalogued — caller falls back to the canonical
// hex rendering. Names follow the conventional `gdisk` short form.
const char* GuidLabel(const u8* g)
{
    struct Known
    {
        u8 bytes[16];
        const char* name;
    };
    static constexpr Known kTable[] = {
        // EFI System Partition: C12A7328-F81F-11D2-BA4B-00A0C93EC93B
        {{0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B},
         "EFI System"},
        // BIOS Boot: 21686148-6449-6E6F-744E-656564454649
        {{0x48, 0x61, 0x68, 0x21, 0x49, 0x64, 0x6F, 0x6E, 0x74, 0x4E, 0x65, 0x65, 0x64, 0x45, 0x46, 0x49}, "BIOS Boot"},
        // Microsoft Reserved: E3C9E316-0B5C-4DB8-817D-F92DF00215AE
        {{0x16, 0xE3, 0xC9, 0xE3, 0x5C, 0x0B, 0xB8, 0x4D, 0x81, 0x7D, 0xF9, 0x2D, 0xF0, 0x02, 0x15, 0xAE},
         "Microsoft Reserved"},
        // Microsoft Basic Data: EBD0A0A2-B9E5-4433-87C0-68B6B72699C7
        {{0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44, 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7},
         "Microsoft Basic Data"},
        // Linux Filesystem: 0FC63DAF-8483-4772-8E79-3D69D8477DE4
        {{0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4},
         "Linux Filesystem"},
        // Linux Swap: 0657FD6D-A4AB-43C4-84E5-0933C84B4F4F
        {{0x6D, 0xFD, 0x57, 0x06, 0xAB, 0xA4, 0xC4, 0x43, 0x84, 0xE5, 0x09, 0x33, 0xC8, 0x4B, 0x4F, 0x4F},
         "Linux Swap"},
        // Linux LVM: E6D6D379-F507-44C2-A23C-238F2A3DF928
        {{0x79, 0xD3, 0xD6, 0xE6, 0x07, 0xF5, 0xC2, 0x44, 0xA2, 0x3C, 0x23, 0x8F, 0x2A, 0x3D, 0xF9, 0x28}, "Linux LVM"},
        // Windows Recovery: DE94BBA4-06D1-4D40-A16A-BFD50179D6AC
        {{0xA4, 0xBB, 0x94, 0xDE, 0xD1, 0x06, 0x40, 0x4D, 0xA1, 0x6A, 0xBF, 0xD5, 0x01, 0x79, 0xD6, 0xAC},
         "Windows Recovery"},
    };
    for (const auto& e : kTable)
    {
        bool match = true;
        for (int i = 0; i < 16; ++i)
        {
            if (e.bytes[i] != g[i])
            {
                match = false;
                break;
            }
        }
        if (match)
        {
            return e.name;
        }
    }
    return "";
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
    const char* label = GuidLabel(p.type_guid);
    if (label[0] != 0)
    {
        SerialWrite(" (");
        SerialWrite(label);
        SerialWrite(")");
    }
    SerialWrite("\n");
}

} // namespace

bool GptProbe(u32 block_handle, u32* out_index)
{
    KLOG_TRACE_SCOPE("fs/gpt", "GptProbe");
    if (g_disk_count >= kMaxDisks)
    {
        core::Log(core::LogLevel::Warn, "fs/gpt", "disk registry full");
        return false;
    }
    if (block_handle >= drivers::storage::BlockDeviceCount())
    {
        core::LogWithValue(core::LogLevel::Warn, "fs/gpt", "invalid block handle", block_handle);
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
    if (!ValidateGptHeader(hdr, sector_count))
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

    // Build and register a partition-block view per entry so
    // higher layers (FAT32 mount, `lsblk`, the GPT self-test) can
    // address a partition as a standalone block device. Name is
    // "<parent>p<N>" (1-based) — matches Linux disk partition
    // conventions and keeps log lines grep-friendly.
    const char* parent_name = drivers::storage::BlockDeviceName(block_handle);
    for (u32 i = 0; i < found; ++i)
    {
        char* out = g_part_names[index][i];
        u32 w = 0;
        for (u32 c = 0; parent_name[c] != 0 && w < sizeof(g_part_names[0][0]) - 4; ++c)
        {
            out[w++] = parent_name[c];
        }
        out[w++] = 'p';
        // Partition numbers are 1-based and max 16 per disk, so two
        // digits is enough. No sprintf in kernel.
        const u32 n = i + 1;
        if (n >= 10)
            out[w++] = static_cast<char>('0' + n / 10);
        out[w++] = static_cast<char>('0' + n % 10);
        out[w] = 0;

        const u32 ph = drivers::storage::PartitionBlockDeviceCreate(out, block_handle, disk.partitions[i].first_lba,
                                                                    disk.partitions[i].last_lba);
        if (ph == drivers::storage::kBlockHandleInvalid)
        {
            core::LogWithValue(core::LogLevel::Error, "fs/gpt", "partition-block register failed idx", i);
        }
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

bool GptFindCrashDumpRegion(u32 block_handle, u64* first_lba_out, u64* sector_count_out)
{
    if (first_lba_out == nullptr || sector_count_out == nullptr)
    {
        return false;
    }
    for (u32 di = 0; di < g_disk_count; ++di)
    {
        const Disk& d = g_disks[di];
        if (d.block_handle != block_handle)
        {
            continue;
        }
        for (u32 pi = 0; pi < d.partition_count; ++pi)
        {
            const Partition& p = d.partitions[pi];
            // Byte-wise compare against our private dump-type GUID.
            // Both buffers are 16 bytes; no early-out micro-opt
            // because the hit count is tiny.
            bool match = true;
            for (u32 i = 0; i < kGuidBytes; ++i)
            {
                if (p.type_guid[i] != kDuetCrashDumpTypeGuid[i])
                {
                    match = false;
                    break;
                }
            }
            if (!match)
            {
                continue;
            }
            if (p.last_lba < p.first_lba)
            {
                continue; // malformed entry — skip
            }
            *first_lba_out = p.first_lba;
            *sector_count_out = (p.last_lba - p.first_lba) + 1;
            return true;
        }
    }
    return false;
}

namespace
{

// Compute header CRC per UEFI 2.10 §5.3.1 — header_crc32 field is
// zeroed for the duration of the calculation.
u32 ComputeHeaderCrc(GptHeader& hdr)
{
    const u32 saved = hdr.header_crc32;
    hdr.header_crc32 = 0;
    const u32 crc = Crc32(reinterpret_cast<const u8*>(&hdr), kGptHeaderSize);
    hdr.header_crc32 = saved;
    return crc;
}

// Minimal Protective MBR (UEFI 2.10 §5.2.3): one MBR partition entry
// of type 0xEE spanning LBA 1..(disk_size_sectors - 1) (clamped to
// 0xFFFFFFFF), boot signature 0x55AA at byte 510. Everything else
// zeroed.
void BuildPmbr(u8 sector[512], u64 disk_sector_count)
{
    for (u32 i = 0; i < 512; ++i)
        sector[i] = 0;
    // Partition entry 0 at byte 446.
    sector[446 + 0] = 0;    // boot indicator (non-bootable)
    sector[446 + 1] = 0x00; // start CHS (head)
    sector[446 + 2] = 0x02; // start CHS (sector|cylinder)
    sector[446 + 3] = 0x00; // start CHS (cylinder)
    sector[446 + 4] = 0xEE; // type = GPT protective
    sector[446 + 5] = 0xFF; // end CHS (head)
    sector[446 + 6] = 0xFF; // end CHS (sector|cylinder)
    sector[446 + 7] = 0xFF; // end CHS (cylinder)
    // First LBA = 1 (LE u32).
    sector[446 + 8] = 1;
    // Sector count = min(disk_size - 1, 0xFFFFFFFF) (LE u32).
    const u64 span = disk_sector_count - 1;
    const u32 span32 = (span > 0xFFFFFFFFull) ? 0xFFFFFFFFu : u32(span);
    sector[446 + 12] = u8(span32);
    sector[446 + 13] = u8(span32 >> 8);
    sector[446 + 14] = u8(span32 >> 16);
    sector[446 + 15] = u8(span32 >> 24);
    // MBR signature.
    sector[510] = 0x55;
    sector[511] = 0xAA;
}

} // namespace

bool GptInitDisk(u32 block_handle, u64 disk_sector_count, const u8 disk_guid[kGuidBytes], const PartitionSpec* parts,
                 u32 part_count)
{
    if (!drivers::storage::BlockDeviceIsWritable(block_handle))
    {
        core::Log(core::LogLevel::Warn, "fs/gpt", "GptInitDisk: handle not writable");
        return false;
    }
    if (disk_sector_count < 67)
    {
        core::Log(core::LogLevel::Warn, "fs/gpt", "GptInitDisk: disk too small (<67 sectors)");
        return false;
    }
    if (part_count > kCanonicalPartitionCount)
    {
        core::Log(core::LogLevel::Warn, "fs/gpt", "GptInitDisk: part_count > 128");
        return false;
    }

    constexpr u32 kSectorSize = 512;
    constexpr u32 kEntriesArrayBytes = kCanonicalPartitionCount * kCanonicalEntryBytes; // 16384
    constexpr u32 kEntriesArraySectors = kEntriesArrayBytes / kSectorSize;              // 32
    const u64 backup_entries_lba = disk_sector_count - 1 - kEntriesArraySectors;
    const u64 backup_header_lba = disk_sector_count - 1;
    const u64 first_usable_lba = 2 + kEntriesArraySectors; // 34
    const u64 last_usable_lba = backup_entries_lba - 1;    // disk_size - 34

    // Validate per-partition LBA ranges before touching the disk.
    for (u32 i = 0; i < part_count; ++i)
    {
        const PartitionSpec& p = parts[i];
        if (p.first_lba < first_usable_lba || p.last_lba > last_usable_lba || p.first_lba > p.last_lba)
        {
            core::Log(core::LogLevel::Warn, "fs/gpt", "GptInitDisk: partition LBA range out of bounds");
            return false;
        }
    }

    // Build entries array on the heap (16 KiB; the kernel kheap satisfies
    // this comfortably, and stack would be too tight).
    u8* entries_buf = static_cast<u8*>(mm::KMalloc(kEntriesArrayBytes));
    if (entries_buf == nullptr)
    {
        core::Log(core::LogLevel::Warn, "fs/gpt", "GptInitDisk: entries-buffer alloc failed");
        return false;
    }
    for (u32 i = 0; i < kEntriesArrayBytes; ++i)
        entries_buf[i] = 0;
    for (u32 i = 0; i < part_count; ++i)
    {
        const PartitionSpec& p = parts[i];
        GptEntry* e = reinterpret_cast<GptEntry*>(entries_buf + u64(i) * kCanonicalEntryBytes);
        for (u32 b = 0; b < kGuidBytes; ++b)
            e->type_guid[b] = p.type_guid[b];
        for (u32 b = 0; b < kGuidBytes; ++b)
            e->unique_guid[b] = p.unique_guid[b];
        e->first_lba = p.first_lba;
        e->last_lba = p.last_lba;
        e->attributes = p.attributes;
        for (u32 b = 0; b < sizeof(e->name_utf16le); ++b)
            e->name_utf16le[b] = (p.name_utf16le != nullptr) ? p.name_utf16le[b] : 0;
    }
    const u32 entries_crc = Crc32(entries_buf, kEntriesArrayBytes);

    // Build primary header.
    GptHeader primary{};
    primary.signature = kGptSignature;
    primary.revision = kGptRevision1;
    primary.header_size = kGptHeaderSize;
    primary.header_crc32 = 0;
    primary.reserved = 0;
    primary.my_lba = 1;
    primary.alternate_lba = backup_header_lba;
    primary.first_usable_lba = first_usable_lba;
    primary.last_usable_lba = last_usable_lba;
    for (u32 b = 0; b < kGuidBytes; ++b)
        primary.disk_guid[b] = disk_guid[b];
    primary.partition_entry_lba = 2;
    primary.num_partition_entries = kCanonicalPartitionCount;
    primary.partition_entry_size = kCanonicalEntryBytes;
    primary.partition_entries_crc32 = entries_crc;
    primary.header_crc32 = ComputeHeaderCrc(primary);

    // Build backup header — same fields swapped for my_lba / alternate_lba
    // / partition_entry_lba.
    GptHeader backup = primary;
    backup.my_lba = backup_header_lba;
    backup.alternate_lba = 1;
    backup.partition_entry_lba = backup_entries_lba;
    backup.header_crc32 = 0;
    backup.header_crc32 = ComputeHeaderCrc(backup);

    // Lay down the four regions. PMBR + headers each fit in one 512-byte
    // sector; entries arrays are 32 sectors.
    u8 sector[kSectorSize];
    BuildPmbr(sector, disk_sector_count);
    if (drivers::storage::BlockDeviceWrite(block_handle, 0, 1, sector) < 0)
    {
        mm::KFree(entries_buf);
        core::Log(core::LogLevel::Error, "fs/gpt", "GptInitDisk: PMBR write failed");
        return false;
    }
    for (u32 i = 0; i < kSectorSize; ++i)
        sector[i] = 0;
    auto write_header = [&](u64 lba, const GptHeader& hdr) -> bool
    {
        for (u32 i = 0; i < kSectorSize; ++i)
            sector[i] = 0;
        for (u32 i = 0; i < kGptHeaderSize; ++i)
            sector[i] = reinterpret_cast<const u8*>(&hdr)[i];
        return drivers::storage::BlockDeviceWrite(block_handle, lba, 1, sector) >= 0;
    };
    if (!write_header(1, primary))
    {
        mm::KFree(entries_buf);
        core::Log(core::LogLevel::Error, "fs/gpt", "GptInitDisk: primary header write failed");
        return false;
    }
    if (drivers::storage::BlockDeviceWrite(block_handle, 2, kEntriesArraySectors, entries_buf) < 0)
    {
        mm::KFree(entries_buf);
        core::Log(core::LogLevel::Error, "fs/gpt", "GptInitDisk: primary entries write failed");
        return false;
    }
    if (drivers::storage::BlockDeviceWrite(block_handle, backup_entries_lba, kEntriesArraySectors, entries_buf) < 0)
    {
        mm::KFree(entries_buf);
        core::Log(core::LogLevel::Error, "fs/gpt", "GptInitDisk: backup entries write failed");
        return false;
    }
    if (!write_header(backup_header_lba, backup))
    {
        mm::KFree(entries_buf);
        core::Log(core::LogLevel::Error, "fs/gpt", "GptInitDisk: backup header write failed");
        return false;
    }
    mm::KFree(entries_buf);
    core::Log(core::LogLevel::Info, "fs/gpt", "GptInitDisk: GPT layout written");
    return true;
}

void GptSelfTest()
{
    KLOG_TRACE_SCOPE("fs/gpt", "GptSelfTest");
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

    // ---- Round-trip GptInitDisk → GptProbe on a fresh RAM disk.
    // The RAM-disk fixture is large enough to host a real GPT (67-
    // sector minimum + a small data area). 256 sectors at 512 b/sec
    // = 128 KiB, comfortably within kheap.
    constexpr u64 kTestSectorCount = 256;
    const u32 ram_h = drivers::storage::RamBlockDeviceCreate("ramgpt", 512, kTestSectorCount);
    if (ram_h == drivers::storage::kBlockHandleInvalid)
    {
        arch::SerialWrite("[fs/gpt]   -> ramdisk create failed; SKIP write self-test\n");
        return;
    }

    // ESP type GUID from UEFI 2.10: C12A7328-F81F-11D2-BA4B-00A0C93EC93B.
    // Stored in the GPT entry "mixed-endian" form (LE u32, LE u16,
    // LE u16, BE u8[2], BE u8[6]).
    const u8 esp_type_guid[16] = {
        0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B,
    };
    const u8 unique_guid[16] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01,
    };
    const u8 disk_guid[16] = {
        0xA1, 0xA2, 0xA3, 0xA4, 0xB1, 0xB2, 0xC1, 0xC2, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8,
    };
    u8 part_name[72] = {};
    // "ESP\0" in UTF-16LE.
    part_name[0] = 'E';
    part_name[2] = 'S';
    part_name[4] = 'P';

    PartitionSpec specs[1];
    specs[0].type_guid = esp_type_guid;
    specs[0].unique_guid = unique_guid;
    specs[0].first_lba = 64;
    specs[0].last_lba = 200;
    specs[0].attributes = 0;
    specs[0].name_utf16le = part_name;

    const bool wrote = GptInitDisk(ram_h, kTestSectorCount, disk_guid, specs, 1);
    if (!wrote)
    {
        arch::SerialWrite("[fs/gpt]   -> GptInitDisk FAILED\n");
        return;
    }
    u32 disk_idx = 0;
    const bool reread = GptProbe(ram_h, &disk_idx);
    if (!reread)
    {
        arch::SerialWrite("[fs/gpt]   -> round-trip GptProbe FAILED\n");
        return;
    }
    const Disk* d = GptDisk(disk_idx);
    if (d == nullptr || d->partition_count != 1 || d->partitions[0].first_lba != 64 || d->partitions[0].last_lba != 200)
    {
        arch::SerialWrite("[fs/gpt]   -> round-trip partition fields wrong\n");
        return;
    }
    arch::SerialWrite("[fs/gpt]   -> GptInitDisk + reparse PASS (1 partition, LBA 64..200)\n");
}

void FormatGuid(const u8 guid[kGuidBytes], char* out_buf, u32 buf_cap)
{
    if (out_buf == nullptr || buf_cap == 0)
        return;
    if (guid == nullptr || buf_cap <= kGuidStringLen)
    {
        out_buf[0] = '\0';
        return;
    }
    // Mixed-endian: bytes 0..3 reversed, 4..5 reversed, 6..7
    // reversed, 8..9 as-is, 10..15 as-is, with hyphens at the
    // 8/4/4/4/12 boundaries.
    static constexpr int kOrder[20] = {3, 2, 1, 0, -1, 5, 4, -1, 7, 6, -1, 8, 9, -1, 10, 11, 12, 13, 14, 15};
    auto hex_nibble = [](u8 n) -> char { return n < 10 ? char('0' + n) : char('A' + n - 10); };
    u32 w = 0;
    for (int k = 0; k < 20 && w + 2 < buf_cap; ++k)
    {
        const int idx = kOrder[k];
        if (idx < 0)
        {
            out_buf[w++] = '-';
        }
        else
        {
            const u8 b = guid[idx];
            out_buf[w++] = hex_nibble(b >> 4);
            out_buf[w++] = hex_nibble(b & 0xF);
        }
    }
    out_buf[w] = '\0';
}

} // namespace duetos::fs::gpt
