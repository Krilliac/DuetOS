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

const Volume* NtfsVolumeByHandle(u32 block_handle)
{
    for (u32 i = 0; i < g_volume_count; ++i)
    {
        if (g_volumes[i].block_handle == block_handle)
            return &g_volumes[i];
    }
    return nullptr;
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

// ---------------------------------------------------------------------------
// Read path: MFT record read + USA fixup, attribute walk, $DATA resolve,
// $INDEX_ROOT enumerate, file read. The byte-level magic / span sanity lives
// in the Rust ntfs_rust crate; the attribute-list walk for $DATA / $INDEX_ROOT
// and the on-disk USA fixup are done here in C++ because they dispatch real
// block I/O against scratch and the crate's FFI surface stops at $FILE_NAME.
// ---------------------------------------------------------------------------

namespace
{

// Root directory's well-known MFT record number.
constexpr u64 kRootDirRecordNum = 5;

inline u16 LoadLe16(const u8* p)
{
    return u16(u16(p[0]) | (u16(p[1]) << 8));
}

inline u32 LoadLe32(const u8* p)
{
    return u32(p[0]) | (u32(p[1]) << 8) | (u32(p[2]) << 16) | (u32(p[3]) << 24);
}

inline u64 LoadLe64(const u8* p)
{
    u64 v = 0;
    for (u32 i = 0; i < 8; ++i)
        v |= u64(p[i]) << (i * 8);
    return v;
}

// Per-volume scratch for a single fixed-up MFT record and for one
// file-data run. Module-private, single-threaded boot/probe context.
alignas(16) constinit u8 g_rec_scratch[kMaxMftRecordSize] = {};
alignas(16) constinit u8 g_data_scratch[kMaxFileReadBytes] = {};

// Apply the NTFS update-sequence-array fixup to a record read into
// `rec` (length `rec_size`). The USA replaces the last 2 bytes of
// every `bytes_per_sector`-sized chunk with a check value; the real
// bytes live in the USA at `usa_off`. Returns false on an
// inconsistent check value (torn write / corruption).
bool ApplyUsaFixup(u8* rec, u32 rec_size, u32 bytes_per_sector)
{
    // MFT record header: usa_offset @ 4 (u16), usa_count @ 6 (u16).
    // usa_count includes the leading update-sequence-number word, so
    // there are (usa_count - 1) protected sectors.
    const u16 usa_off = LoadLe16(rec + 4);
    const u16 usa_count = LoadLe16(rec + 6);
    if (usa_count < 2 || bytes_per_sector == 0)
        return false;
    const u32 sectors = u32(usa_count) - 1;
    // The protected region must exactly cover the record.
    if (u64(sectors) * bytes_per_sector != rec_size)
        return false;
    if (u32(usa_off) + u32(usa_count) * 2 > rec_size)
        return false;
    const u16 usn = LoadLe16(rec + usa_off);
    for (u32 s = 0; s < sectors; ++s)
    {
        const u32 tail = (s + 1) * bytes_per_sector - 2; // last word of sector s
        if (LoadLe16(rec + tail) != usn)
            return false; // torn write — the check word didn't match the USN
        const u32 usa_entry = usa_off + 2 * (s + 1);
        rec[tail] = rec[usa_entry];
        rec[tail + 1] = rec[usa_entry + 1];
    }
    return true;
}

// Decode the resident $FILE_NAME UTF-16 name into the caller's ASCII
// buffer. Mirrors the file-scope DecodeFileName but takes the raw
// value pointer (used by the $INDEX_ROOT entry walk).
void DecodeUtf16Name(const u8* utf16, u32 units, char* out, u32 out_cap)
{
    u32 w = 0;
    for (u32 u = 0; u < units && w + 1 < out_cap; ++u)
    {
        const u16 cp = LoadLe16(utf16 + u * 2);
        const char c = duetos::util::Utf16CpToSafeAscii(u32(cp));
        if (c == '\0')
            break;
        out[w++] = c;
    }
    out[w] = '\0';
}

// Find the first unnamed attribute of type `want_type` in a fixed-up
// MFT record. Returns the byte offset of the attribute header, or 0
// if absent / malformed (offset 0 is never a valid attribute start —
// the record header occupies it).
u32 FindAttribute(const u8* rec, u32 rec_size, u32 want_type)
{
    const u16 first = LoadLe16(rec + 0x14);
    if (first < 0x18 || first >= rec_size)
        return 0;
    u32 off = first;
    while (off + 8 <= rec_size)
    {
        const u32 ty = LoadLe32(rec + off);
        if (ty == kAttrTypeEnd)
            return 0;
        const u32 len = LoadLe32(rec + off + 4);
        if (len < 8 || u64(off) + len > rec_size)
            return 0;
        // name_length @ +9 (u8); 0 ⇒ unnamed (the stream we want).
        const u8 name_len = rec[off + 9];
        if (ty == want_type && name_len == 0)
            return off;
        off += len;
    }
    return 0;
}

} // namespace

::duetos::core::Result<void> NtfsReadMftRecord(const Volume& v, u64 record_num, u8* out)
{
    using ::duetos::core::Err;
    using ::duetos::core::ErrorCode;
    if (out == nullptr)
        return Err{ErrorCode::InvalidArgument};
    if (v.mft_record_size == 0 || v.mft_record_size > kMaxMftRecordSize)
        return Err{ErrorCode::InvalidArgument};
    if (v.bytes_per_sector == 0 || v.sectors_per_cluster == 0)
        return Err{ErrorCode::InvalidArgument};
    const u32 bps = v.bytes_per_sector;
    if ((v.mft_record_size % bps) != 0)
        return Err{ErrorCode::InvalidArgument};
    const u32 sectors_per_record = v.mft_record_size / bps;
    if (sectors_per_record == 0)
        return Err{ErrorCode::InvalidArgument};

    const u64 mft_start_lba = v.mft_lcn * v.sectors_per_cluster;
    const u64 rec_lba = mft_start_lba + record_num * sectors_per_record;
    if (drivers::storage::BlockDeviceRead(v.block_handle, rec_lba, sectors_per_record, out) < 0)
        return Err{ErrorCode::IoError};

    // "FILE" signature check before fixup touches sector tails.
    if (LoadLe32(out) != kFileRecordMagic)
        return Err{ErrorCode::Corrupt};
    if (!ApplyUsaFixup(out, v.mft_record_size, bps))
        return Err{ErrorCode::Corrupt};
    return {};
}

::duetos::core::Result<void> NtfsResolveData(const Volume& v, const u8* rec, DataLocation* out)
{
    using ::duetos::core::Err;
    using ::duetos::core::ErrorCode;
    if (rec == nullptr || out == nullptr)
        return Err{ErrorCode::InvalidArgument};
    *out = DataLocation{};
    const u32 rec_size = v.mft_record_size;
    const u32 off = FindAttribute(rec, rec_size, kAttrTypeData);
    if (off == 0)
        return Err{ErrorCode::NotFound};

    const u32 attr_len = LoadLe32(rec + off + 4);
    const u8 non_resident = rec[off + 8];
    if (non_resident == 0)
    {
        // Resident value: length @ +0x10 (u32), offset @ +0x14 (u16).
        const u32 val_len = LoadLe32(rec + off + 0x10);
        const u16 val_off = LoadLe16(rec + off + 0x14);
        if (u64(val_off) + val_len > attr_len || u64(off) + val_off + val_len > rec_size)
            return Err{ErrorCode::Corrupt};
        out->valid = true;
        out->resident = true;
        out->size_bytes = val_len;
        out->resident_offset = off + val_off;
        return {};
    }

    // Non-resident value: mapping-pairs offset @ +0x20 (u16), real
    // (initialised) size @ +0x38 (u64). We decode only the FIRST run.
    const u16 mp_off = LoadLe16(rec + off + 0x20);
    const u64 real_size = LoadLe64(rec + off + 0x38);
    if (mp_off < 0x40 || u64(off) + mp_off >= u64(off) + attr_len)
        return Err{ErrorCode::Corrupt};
    const u32 run_start = off + mp_off;
    const u32 run_avail = (u64(off) + attr_len <= rec_size) ? (off + attr_len - run_start) : (rec_size - run_start);
    DuetosNtfsRunlistEntry e{};
    if (!duetos_ntfs_parse_runlist_entry(rec + run_start, run_avail, 0, &e) || e.ok == 0 || e.is_sparse != 0)
        return Err{ErrorCode::Corrupt};
    out->valid = true;
    out->resident = false;
    out->size_bytes = real_size;
    out->first_lcn = e.lcn;
    out->run_clusters = e.length_clusters;
    return {};
}

::duetos::core::Result<void> NtfsEnumerateRoot(const Volume& v, DirEntry* out_entries, u32 cap, u32* out_count)
{
    using ::duetos::core::Err;
    using ::duetos::core::ErrorCode;
    if (out_entries == nullptr || out_count == nullptr || cap == 0)
        return Err{ErrorCode::InvalidArgument};
    *out_count = 0;

    RESULT_TRY(NtfsReadMftRecord(v, kRootDirRecordNum, g_rec_scratch));
    const u32 rec_size = v.mft_record_size;
    const u32 ir_off = FindAttribute(g_rec_scratch, rec_size, kAttrTypeIndexRoot);
    if (ir_off == 0)
        return Err{ErrorCode::NotFound};
    // $INDEX_ROOT must be resident (it always is by definition).
    if (g_rec_scratch[ir_off + 8] != 0)
        return Err{ErrorCode::Corrupt};
    const u32 val_len = LoadLe32(g_rec_scratch + ir_off + 0x10);
    const u16 val_off = LoadLe16(g_rec_scratch + ir_off + 0x14);
    const u32 value = ir_off + val_off;
    if (u64(value) + val_len > rec_size || val_len < 0x20)
        return Err{ErrorCode::Corrupt};

    // INDEX_ROOT layout:
    //   +0x00 attribute type indexed (we don't re-check)
    //   +0x10 INDEX_HEADER { entries_offset(u32) @ +0, total_size(u32) @ +4 }
    // The INDEX_HEADER sits at value + 0x10; entry list starts at
    // (value + 0x10 + entries_offset).
    const u32 hdr = value + 0x10;
    if (u64(hdr) + 0x10 > rec_size)
        return Err{ErrorCode::Corrupt};
    const u32 entries_off = LoadLe32(g_rec_scratch + hdr + 0x00);
    const u32 index_used = LoadLe32(g_rec_scratch + hdr + 0x04);
    u32 entry = hdr + entries_off;
    const u32 list_end = hdr + index_used;
    if (list_end > rec_size || entry < hdr)
        return Err{ErrorCode::Corrupt};

    u32 produced = 0;
    // INDEX_ENTRY layout:
    //   +0x00 mft_reference (u64; low 48 bits = record number)
    //   +0x08 entry_length  (u16)
    //   +0x0A key_length    (u16)  ($FILE_NAME size)
    //   +0x0C flags         (u16)  bit 0x02 = last (end) entry
    //   +0x10 key ($FILE_NAME: name_length(u8) @ +0x40, name @ +0x42)
    while (entry + 0x10 <= list_end && produced < cap)
    {
        const u16 entry_len = LoadLe16(g_rec_scratch + entry + 0x08);
        const u16 flags = LoadLe16(g_rec_scratch + entry + 0x0C);
        if (entry_len < 0x10 || u64(entry) + entry_len > rec_size)
            break;
        if (flags & 0x02) // last entry — no key
            break;
        const u64 ref = LoadLe64(g_rec_scratch + entry) & 0x0000FFFFFFFFFFFFull;
        const u32 key = entry + 0x10;
        // $FILE_NAME key: flags @ +0x38 (u64 attr), file_attributes
        // @ +0x38 within the FILE_NAME body actually — we only need
        // name_length @ +0x40 and the UTF-16 name @ +0x42, plus the
        // directory bit in the FILE_NAME file-attribute flags @ +0x38.
        if (u64(key) + 0x42 > rec_size)
            break;
        const u8 name_len = g_rec_scratch[key + 0x40];
        if (u64(key) + 0x42 + u64(name_len) * 2 > rec_size)
            break;
        const u32 fn_attrs = LoadLe32(g_rec_scratch + key + 0x38);
        DirEntry& de = out_entries[produced++];
        de.mft_reference = ref;
        de.is_directory = (fn_attrs & 0x10000000u) != 0; // FILE_ATTR_DIRECTORY (index flag)
        DecodeUtf16Name(g_rec_scratch + key + 0x42, name_len, de.name, sizeof(de.name));
        entry += entry_len;
    }
    *out_count = produced;
    return {};
}

::duetos::core::Result<void> NtfsFindInRoot(const Volume& v, const char* name, DirEntry* out)
{
    using ::duetos::core::Err;
    using ::duetos::core::ErrorCode;
    if (name == nullptr || out == nullptr)
        return Err{ErrorCode::InvalidArgument};
    DirEntry entries[kMaxDirEntries];
    u32 count = 0;
    RESULT_TRY(NtfsEnumerateRoot(v, entries, kMaxDirEntries, &count));
    for (u32 i = 0; i < count; ++i)
    {
        u32 j = 0;
        while (entries[i].name[j] != '\0' && name[j] != '\0' && entries[i].name[j] == name[j])
            ++j;
        if (entries[i].name[j] == '\0' && name[j] == '\0')
        {
            *out = entries[i];
            return {};
        }
    }
    return Err{ErrorCode::NotFound};
}

::duetos::core::Result<void> NtfsReadFile(const Volume& v, const u8* rec, const DataLocation& data, u64 offset,
                                          void* buf, u64 len, u64* out_read)
{
    using ::duetos::core::Err;
    using ::duetos::core::ErrorCode;
    if (buf == nullptr || out_read == nullptr || !data.valid)
        return Err{ErrorCode::InvalidArgument};
    *out_read = 0;
    if (offset >= data.size_bytes)
        return {}; // EOF
    u64 remaining = data.size_bytes - offset;
    if (len < remaining)
        remaining = len;
    auto* dst = static_cast<u8*>(buf);

    if (data.resident)
    {
        if (rec == nullptr)
            return Err{ErrorCode::InvalidArgument};
        const u8* src = rec + data.resident_offset + offset;
        for (u64 i = 0; i < remaining; ++i)
            dst[i] = src[i];
        *out_read = remaining;
        return {};
    }

    // Non-resident single run. Read the run into scratch, then copy.
    const u32 bytes_per_cluster = u32(v.bytes_per_sector) * u32(v.sectors_per_cluster);
    if (bytes_per_cluster == 0)
        return Err{ErrorCode::InvalidArgument};
    const u64 run_bytes = data.run_clusters * bytes_per_cluster;
    if (run_bytes == 0 || run_bytes > sizeof(g_data_scratch))
        return Err{ErrorCode::IoError}; // GAP: run larger than one scratch buffer.
    const u64 run_lba = data.first_lcn * v.sectors_per_cluster;
    const u32 run_sectors = u32(run_bytes / v.bytes_per_sector);
    if (drivers::storage::BlockDeviceRead(v.block_handle, run_lba, run_sectors, g_data_scratch) < 0)
        return Err{ErrorCode::IoError};
    if (offset + remaining > run_bytes)
        return Err{ErrorCode::IoError}; // GAP: read beyond the first run.
    for (u64 i = 0; i < remaining; ++i)
        dst[i] = g_data_scratch[offset + i];
    *out_read = remaining;
    return {};
}

} // namespace duetos::fs::ntfs
