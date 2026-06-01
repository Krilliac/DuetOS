// ntfs_selftest.cpp — NtfsSelfTest: builds a minimal synthetic NTFS
// volume in a fresh RAM block device and drives the read path end to
// end: probe → MFT-record-by-index read (with USA fixup) → root
// directory enumerate ($I30 resident INDEX_ROOT) → find a regular
// file → resolve its resident $DATA → read it back and compare. This
// is the boot wire-in proving the NTFS read code is live, not just
// compiled.
//
// Hand-building a valid minimal NTFS image is the hard part. The key
// invariant the C++ reader enforces is the update-sequence-array
// (USA) fixup: every 512-byte sector of a FILE record has its last
// two bytes replaced by a per-record check word, with the real bytes
// stashed in the USA. PutRecord() below performs that substitution
// when it lays each record down, so NtfsReadMftRecord's fixup pass
// finds matching check words and restores the originals.
//
// Geometry (deliberately minimal):
//   - 512-byte sectors, 1 sector/cluster (bytes_per_cluster = 512).
//   - 1024-byte MFT records (clusters_per_mft_record raw = -10 →
//     2^10 = 1024). One record spans 2 sectors → USA count = 3.
//   - $MFT at LCN kMftLcn. We populate only record 5 ($Root, with a
//     resident $INDEX_ROOT $I30 holding one entry) and record 24
//     (the file, with a resident $DATA). Records the probe walk
//     touches (0..15) that we leave zeroed simply fail the "FILE"
//     check and are skipped — harmless for the read path under test.
//
// GAP: this image exercises the resident-$DATA + resident-INDEX_ROOT
// happy path only. The non-resident single-run $DATA decoder and the
// runlist path are implemented in fs/ntfs.cpp and unit-tested in the
// ntfs_rust crate, but are not driven by this synthetic image (which
// would need a multi-cluster data run to be meaningful). $INDEX_ALLO-
// CATION b-trees, compressed/sparse/encrypted $DATA, ADS, and writes
// are out of scope — see the GAP markers in fs/ntfs.{h,cpp}.

#include "fs/ntfs.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "drivers/storage/block.h"
#include "log/klog.h"

namespace duetos::fs::ntfs
{

namespace
{

constexpr u32 kSectorSize = 512;
constexpr u32 kSectorsPerCluster = 1;
constexpr u32 kBytesPerCluster = kSectorSize * kSectorsPerCluster;
constexpr u32 kRecordSize = 1024; // 2 sectors per record
constexpr u32 kSectorsPerRecord = kRecordSize / kSectorSize;

constexpr u64 kMftLcn = 4;         // $MFT starts at LBA 4
constexpr u64 kRootRecordNum = 5;  // $Root
constexpr u64 kFileRecordNum = 24; // our regular file
constexpr u32 kTotalSectors = 128; // tiny volume

// File body the test plants and reads back.
constexpr char kFileBody[] = "hello from ntfs\n";
constexpr u32 kFileBodyLen = 16; // strlen, excludes the NUL
constexpr char kFileName[] = "hello.txt";
constexpr u8 kFileNameUnits = 9;

inline void StoreLe16(u8* p, u16 v)
{
    p[0] = u8(v & 0xFF);
    p[1] = u8((v >> 8) & 0xFF);
}

inline void StoreLe32(u8* p, u32 v)
{
    p[0] = u8(v & 0xFF);
    p[1] = u8((v >> 8) & 0xFF);
    p[2] = u8((v >> 16) & 0xFF);
    p[3] = u8((v >> 24) & 0xFF);
}

inline void StoreLe64(u8* p, u64 v)
{
    for (u32 i = 0; i < 8; ++i)
        p[i] = u8((v >> (i * 8)) & 0xFF);
}

inline void Zero(void* p, u64 n)
{
    auto* b = static_cast<volatile u8*>(p);
    for (u64 i = 0; i < n; ++i)
        b[i] = 0;
}

// Write `units` UTF-16LE code units of an ASCII name into `dst`.
void PutUtf16Name(u8* dst, const char* name, u8 units)
{
    for (u8 i = 0; i < units; ++i)
        StoreLe16(dst + i * 2, u16(u8(name[i])));
}

// Lay an MFT record into the device with the USA fixup applied.
// `rec` is a fully-built 1024-byte FILE record EXCEPT the sector-tail
// check words, which this routine writes (and stashes the displaced
// originals into the USA) so NtfsReadMftRecord's fixup validates.
bool PutRecord(u32 handle, u64 record_num, u8* rec)
{
    // USA: offset 0x30, count = sectors + 1 = 3. USN = 0x0001.
    constexpr u16 kUsaOff = 0x30;
    constexpr u16 kUsaCount = kSectorsPerRecord + 1;
    constexpr u16 kUsn = 0x0001;
    StoreLe16(rec + 4, kUsaOff);
    StoreLe16(rec + 6, kUsaCount);
    StoreLe16(rec + kUsaOff, kUsn);
    for (u32 s = 0; s < kSectorsPerRecord; ++s)
    {
        const u32 tail = (s + 1) * kSectorSize - 2;
        const u32 usa_entry = kUsaOff + 2 * (s + 1);
        // Stash the real tail bytes into the USA, then write the USN
        // into the sector tail (the on-disk protection word).
        rec[usa_entry] = rec[tail];
        rec[usa_entry + 1] = rec[tail + 1];
        StoreLe16(rec + tail, kUsn);
    }
    const u64 lba = kMftLcn * kSectorsPerCluster + record_num * kSectorsPerRecord;
    return drivers::storage::BlockDeviceWrite(handle, lba, kSectorsPerRecord, rec) == 0;
}

// Build the NTFS boot sector at LBA 0.
bool PutBootSector(u32 handle)
{
    u8 bs[kSectorSize];
    Zero(bs, sizeof(bs));
    const char* oem = "NTFS    ";
    for (u32 i = 0; i < 8; ++i)
        bs[3 + i] = u8(oem[i]);
    StoreLe16(bs + 11, u16(kSectorSize));     // bytes per sector
    bs[13] = u8(kSectorsPerCluster);          // sectors per cluster
    StoreLe64(bs + 0x28, u64(kTotalSectors)); // total sectors
    StoreLe64(bs + 0x30, kMftLcn);            // $MFT LCN
    StoreLe64(bs + 0x38, kMftLcn + 1);        // $MFTMirr LCN
    bs[0x40] = u8(i8(-10));                   // clusters_per_mft_record → 1024
    bs[0x44] = 0x01;                          // clusters_per_index_block
    StoreLe64(bs + 0x48, 0xCAFEBABEull);      // volume serial
    bs[510] = 0x55;
    bs[511] = 0xAA;
    return drivers::storage::BlockDeviceWrite(handle, 0, 1, bs) == 0;
}

// Build $Root (record 5): a FILE record whose only attribute of
// interest is a resident $INDEX_ROOT ($I30) holding a single index
// entry that points to the file record by name.
bool PutRootRecord(u32 handle)
{
    u8 rec[kRecordSize];
    Zero(rec, sizeof(rec));
    StoreLe32(rec + 0, kFileRecordMagic); // "FILE"
    StoreLe16(rec + 0x16, u16(0x0003));   // flags: in_use | is_directory
    constexpr u16 kFirstAttr = 0x38;
    StoreLe16(rec + 0x14, kFirstAttr);

    // ---- $INDEX_ROOT attribute (type 0x90), resident, unnamed.
    // Attribute header (resident, 0x18 bytes) then the value:
    //   value+0x00 INDEX_ROOT prefix (0x10 bytes)
    //   value+0x10 INDEX_HEADER (entries_offset @ +0, index_used @ +4)
    //   value+0x10+entries_offset  first INDEX_ENTRY
    u32 attr = kFirstAttr;
    const u32 value = attr + 0x18;

    // INDEX_HEADER lives at value+0x10. Entry list starts right after
    // the 0x10-byte header (entries_offset = 0x10 relative to header).
    const u32 hdr = value + 0x10;
    const u32 entries_off = 0x10;
    const u32 entry = hdr + entries_off;

    // INDEX_ENTRY (key = $FILE_NAME). Layout we fill:
    //   +0x00 mft_reference (u64; low 48 = record number)
    //   +0x08 entry_length (u16)
    //   +0x0A key_length   (u16)
    //   +0x0C flags        (u16)
    //   +0x10 key: $FILE_NAME — name_length @ +0x40, name @ +0x42,
    //         file_attributes @ +0x38.
    const u32 key = entry + 0x10;
    const u32 key_len = 0x42 + u32(kFileNameUnits) * 2; // FILE_NAME size
    const u32 entry_len = 0x10 + ((key_len + 7) & ~7u); // 8-byte aligned
    StoreLe64(rec + entry + 0x00, kFileRecordNum);
    StoreLe16(rec + entry + 0x08, u16(entry_len));
    StoreLe16(rec + entry + 0x0A, u16(key_len));
    StoreLe16(rec + entry + 0x0C, 0x0000);   // not the last entry
    StoreLe32(rec + key + 0x38, 0x00000000); // file_attributes: not a dir
    rec[key + 0x40] = kFileNameUnits;        // name length (UTF-16 units)
    PutUtf16Name(rec + key + 0x42, kFileName, kFileNameUnits);

    // Trailing "last entry" sentinel (flags bit 0x02, no key).
    const u32 last = entry + entry_len;
    StoreLe16(rec + last + 0x08, 0x10); // entry_length (>= 0x10)
    StoreLe16(rec + last + 0x0C, 0x02); // flags: last entry
    const u32 list_end = last + 0x10;

    // INDEX_HEADER fields.
    StoreLe32(rec + hdr + 0x00, entries_off);    // entries_offset
    StoreLe32(rec + hdr + 0x04, list_end - hdr); // index_used (total size)
    StoreLe32(rec + hdr + 0x08, list_end - hdr); // allocated size
    rec[hdr + 0x0C] = 0;                         // flags: small index

    // INDEX_ROOT prefix (value+0x00 .. +0x10): indexed attr type
    // 0x30 ($FILE_NAME), collation 0x01, index-block size, clusters.
    StoreLe32(rec + value + 0x00, kAttrTypeFileName);
    StoreLe32(rec + value + 0x04, 0x00000001); // collation rule
    StoreLe32(rec + value + 0x08, kBytesPerCluster);
    rec[value + 0x0C] = 1;

    const u32 val_len = (list_end - value);
    const u32 attr_len_aligned = ((0x18 + val_len) + 7) & ~7u;
    StoreLe32(rec + attr + 0x00, kAttrTypeIndexRoot);
    StoreLe32(rec + attr + 0x04, attr_len_aligned); // attribute length
    rec[attr + 0x08] = 0;                           // resident
    rec[attr + 0x09] = 0;                           // name length (unnamed)
    StoreLe32(rec + attr + 0x10, val_len);          // value length
    StoreLe16(rec + attr + 0x14, 0x18);             // value offset

    // Attribute-list terminator after the $INDEX_ROOT.
    StoreLe32(rec + attr + attr_len_aligned, kAttrTypeEnd);

    return PutRecord(handle, kRootRecordNum, rec);
}

// Build the file record (record 24): a FILE record with a resident
// $DATA attribute holding the body.
bool PutFileRecord(u32 handle)
{
    u8 rec[kRecordSize];
    Zero(rec, sizeof(rec));
    StoreLe32(rec + 0, kFileRecordMagic); // "FILE"
    StoreLe16(rec + 0x16, u16(0x0001));   // flags: in_use, not dir
    constexpr u16 kFirstAttr = 0x38;
    StoreLe16(rec + 0x14, kFirstAttr);

    // ---- $DATA attribute (type 0x80), resident, unnamed.
    const u32 attr = kFirstAttr;
    const u32 value = attr + 0x18;
    for (u32 i = 0; i < kFileBodyLen; ++i)
        rec[value + i] = u8(kFileBody[i]);
    const u32 attr_len_aligned = ((0x18 + kFileBodyLen) + 7) & ~7u;
    StoreLe32(rec + attr + 0x00, kAttrTypeData);
    StoreLe32(rec + attr + 0x04, attr_len_aligned);
    rec[attr + 0x08] = 0;                       // resident
    rec[attr + 0x09] = 0;                       // unnamed
    StoreLe32(rec + attr + 0x10, kFileBodyLen); // value length
    StoreLe16(rec + attr + 0x14, 0x18);         // value offset

    StoreLe32(rec + attr + attr_len_aligned, kAttrTypeEnd);
    return PutRecord(handle, kFileRecordNum, rec);
}

bool BuildSyntheticVolume(u32 handle)
{
    return PutBootSector(handle) && PutRootRecord(handle) && PutFileRecord(handle);
}

void Fail(const char* phase)
{
    using arch::SerialWrite;
    SerialWrite("[ntfs-selftest] FAIL (");
    SerialWrite(phase);
    SerialWrite(")\n");
    KBP_PROBE_V(duetos::debug::ProbeId::kBootSelftestFail, 0x47F5u);
}

} // namespace

// Boot self-test: build a synthetic NTFS volume in RAM and drive the
// read path. Emits a single [ntfs-selftest] PASS line on success so
// CI can grep it; a FAIL line + kBootSelftestFail probe on any failed
// assertion. Registered after Ext4SelfTest in boot_bringup.cpp.
void NtfsSelfTest()
{
    KLOG_TRACE_SCOPE("fs/ntfs", "NtfsSelfTest");
    using arch::SerialWrite;

    const u32 handle = drivers::storage::RamBlockDeviceCreate("ramntfs", kSectorSize, kTotalSectors);
    if (handle == drivers::storage::kBlockHandleInvalid)
    {
        Fail("ramdisk-create");
        return;
    }
    if (!BuildSyntheticVolume(handle))
    {
        Fail("build-volume");
        return;
    }

    // ---- Phase 1: probe parses the boot sector + walks system records.
    auto probed = NtfsProbe(handle);
    if (!probed)
    {
        Fail("probe");
        return;
    }
    const Volume* v = NtfsVolumeByIndex(probed.value());
    if (v == nullptr || v->mft_record_size != kRecordSize || v->bytes_per_sector != kSectorSize)
    {
        Fail("geometry");
        return;
    }

    // ---- Phase 2: read the root MFT record directly (exercises USA fixup).
    u8 rootrec[kRecordSize];
    if (!NtfsReadMftRecord(*v, kRootRecordNum, rootrec))
    {
        Fail("read-root-record");
        return;
    }

    // ---- Phase 3: enumerate the root dir; the $I30 index has our file.
    DirEntry entries[kMaxDirEntries];
    u32 count = 0;
    if (!NtfsEnumerateRoot(*v, entries, kMaxDirEntries, &count) || count == 0)
    {
        Fail("enumerate-root");
        return;
    }
    DirEntry found{};
    if (!NtfsFindInRoot(*v, kFileName, &found))
    {
        Fail("find-in-root");
        return;
    }
    if (found.mft_reference != kFileRecordNum)
    {
        Fail("dirent-reference");
        return;
    }

    // ---- Phase 4: read the file's MFT record, resolve resident $DATA.
    u8 filerec[kRecordSize];
    if (!NtfsReadMftRecord(*v, found.mft_reference, filerec))
    {
        Fail("read-file-record");
        return;
    }
    DataLocation data{};
    if (!NtfsResolveData(*v, filerec, &data) || !data.valid || !data.resident)
    {
        Fail("resolve-data");
        return;
    }
    if (data.size_bytes != kFileBodyLen)
    {
        Fail("data-size");
        return;
    }

    // ---- Phase 5: read the body back and compare.
    u8 buf[64];
    u64 nread = 0;
    if (!NtfsReadFile(*v, filerec, data, 0, buf, sizeof(buf), &nread) || nread != kFileBodyLen)
    {
        Fail("read-file");
        return;
    }
    for (u32 i = 0; i < kFileBodyLen; ++i)
    {
        if (buf[i] != u8(kFileBody[i]))
        {
            Fail("content");
            return;
        }
    }

    // ---- Phase 6: a mid-file read (offset 6, len 5) returns "from ".
    u64 nread2 = 0;
    if (!NtfsReadFile(*v, filerec, data, 6, buf, 5, &nread2) || nread2 != 5)
    {
        Fail("partial-read");
        return;
    }
    const char* expect = "from ";
    for (u32 i = 0; i < 5; ++i)
    {
        if (buf[i] != u8(expect[i]))
        {
            Fail("partial-content");
            return;
        }
    }

    SerialWrite(
        "[ntfs-selftest] PASS (synthetic volume: probe+USA-fixup+root-index+resident-data file read verified)\n");
}

} // namespace duetos::fs::ntfs
