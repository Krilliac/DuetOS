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
//   - $MFT at LCN kMftLcn. We populate record 5 ($Root, resident
//     $INDEX_ROOT $I30), 24 ("hello.txt"), 25 ("sub"), 26
//     ("sub/deep.txt"), 27 ("big" — a LARGE directory whose 105
//     entries live in $INDEX_ALLOCATION INDX blocks, $I30-named
//     attributes, $BITMAP-gated) and 28 (the shared big-dir target
//     file). Records the probe walk touches (0..15) that we leave
//     zeroed simply fail the "FILE" check and are skipped — harmless
//     for the read path under test.
//
// GAP: this image exercises resident $DATA only. The non-resident
// single-run $DATA decoder is implemented in fs/ntfs.cpp and
// unit-tested in the ntfs_rust crate, but is not driven by this
// synthetic image (which would need a multi-cluster data run to be
// meaningful). B-tree VCN descent, compressed/sparse/encrypted
// $DATA, ADS, and writes are out of scope — see the GAP markers in
// fs/ntfs.{h,cpp}.

#include "fs/ntfs.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "drivers/storage/block.h"
#include "fs/mount.h"
#include "fs/ramfs.h"
#include "fs/vfs.h"
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

constexpr u64 kMftLcn = 4;             // $MFT starts at LBA 4
constexpr u64 kRootRecordNum = 5;      // $Root
constexpr u64 kFileRecordNum = 24;     // our regular file (direct child of root)
constexpr u64 kSubDirRecordNum = 25;   // "sub" directory (child of root)
constexpr u64 kDeepFileRecordNum = 26; // "deep.txt" file (child of "sub")
constexpr u32 kTotalSectors = 128;     // tiny volume

// File body the test plants and reads back.
constexpr char kFileBody[] = "hello from ntfs\n";
constexpr u32 kFileBodyLen = 16; // strlen, excludes the NUL
constexpr char kFileName[] = "hello.txt";
constexpr u8 kFileNameUnits = 9;

// Nested fixture for the multi-component walk: root → "sub" (a
// directory) → "deep.txt" (a regular file with resident $DATA).
constexpr char kSubDirName[] = "sub";
constexpr u8 kSubDirNameUnits = 3;
constexpr char kDeepFileName[] = "deep.txt";
constexpr u8 kDeepFileNameUnits = 8;
constexpr char kDeepBody[] = "deep ntfs file\n";
constexpr u32 kDeepBodyLen = 15; // strlen, excludes the NUL

// Large-directory fixture: "big" (record 27) keeps an EMPTY resident
// $INDEX_ROOT (large-index flag set) and spills every entry into a
// non-resident $INDEX_ALLOCATION stream of 1 KiB INDX blocks across
// TWO data runs — the $I30 shape the INDX walker exists for. Its
// attributes carry the real "$I30" name (the resident root/sub
// records stay unnamed, so both attribute-name forms are exercised).
// All entries point at one regular file record (28) so any positive
// lookup can resolve + read real data.
constexpr u64 kBigDirRecordNum = 27;  // "big" directory (child of root)
constexpr u64 kBigFileRecordNum = 28; // shared target of every big-dir entry
constexpr char kBigDirName[] = "big";
constexpr u8 kBigDirNameUnits = 3;
constexpr char kBigBody[] = "big dir file\n";
constexpr u32 kBigBodyLen = 13; // strlen, excludes the NUL

constexpr u32 kIndexBlockSize = 1024;                                        // INDX block = 2 sectors
constexpr u32 kIndexBlockSectors = kIndexBlockSize / kSectorSize;            // 2
constexpr u32 kIndxBlockCount = 16;                                          // 15 in-use + 1 bitmap-free ghost
constexpr u32 kIndxEntriesPerBlock = 7;                                      // "fileNNN.txt" entries per block
constexpr u32 kBigEntryCount = (kIndxBlockCount - 1) * kIndxEntriesPerBlock; // 105 files
constexpr u32 kIndxBlocksPerRun = 8;
constexpr u64 kIndxRun1Lcn = 70; // blocks 0..7  (16 clusters @ LBA 70)
constexpr u64 kIndxRun2Lcn = 90; // blocks 8..15 (16 clusters @ LBA 90)

// Ghost fixture: block 15 holds valid INDX bytes on disk but is
// marked FREE in $BITMAP — its sole entry must never be found.
constexpr char kGhostName[] = "ghost.txt";

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

// Stamp the update-sequence array into a record / INDX-block image:
// stash each 512-byte sector's real tail word into the USA at
// `usa_off`, then write the USN check word into the tail — the exact
// inverse of the reader's ApplyUsaFixup, so the fixup pass validates
// and restores the original bytes. FILE records and INDX blocks carry
// the identical usa_offset / usa_count header words.
void StampUsa(u8* buf, u32 bytes, u16 usa_off)
{
    const u16 sectors = u16(bytes / kSectorSize);
    constexpr u16 kUsn = 0x0001;
    StoreLe16(buf + 4, usa_off);
    StoreLe16(buf + 6, u16(sectors + 1)); // usa_count includes the USN word
    StoreLe16(buf + usa_off, kUsn);
    for (u32 s = 0; s < sectors; ++s)
    {
        const u32 tail = (s + 1) * kSectorSize - 2;
        const u32 usa_entry = usa_off + 2 * (s + 1);
        // Stash the real tail bytes into the USA, then write the USN
        // into the sector tail (the on-disk protection word).
        buf[usa_entry] = buf[tail];
        buf[usa_entry + 1] = buf[tail + 1];
        StoreLe16(buf + tail, kUsn);
    }
}

// Lay an MFT record into the device with the USA fixup applied.
// `rec` is a fully-built 1024-byte FILE record EXCEPT the sector-tail
// check words, which StampUsa writes (and stashes the displaced
// originals into the USA) so NtfsReadMftRecord's fixup validates.
bool PutRecord(u32 handle, u64 record_num, u8* rec)
{
    StampUsa(rec, kRecordSize, /*usa_off=*/0x30);
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

// Lay down one resident $INDEX_ROOT ($I30) INDEX_ENTRY at `*cursor`
// and advance `*cursor` past it. Mirrors the byte layout the C++
// reader (NtfsEnumerateDir) decodes:
//   +0x00 mft_reference (u64; low 48 = record number)
//   +0x08 entry_length (u16, 8-byte aligned)
//   +0x0A key_length   (u16)  ($FILE_NAME size)
//   +0x0C flags        (u16)  bit 0x02 = last entry (not set here)
//   +0x10 key: $FILE_NAME — file_attributes @ +0x38 (dir bit
//         0x10000000), name_length @ +0x40 (UTF-16 units), name @ +0x42.
// Used by PutRootRecord, PutSubDirRecord, and PutIndxBlock (the
// INDEX_ENTRY layout is identical in $INDEX_ROOT and INDX blocks) so
// the offset math lives in one place and can't drift between callers.
void PutIndexEntry(u8* rec, u32* cursor, u64 mft_ref, const char* name, u8 units, bool is_dir)
{
    const u32 entry = *cursor;
    const u32 key = entry + 0x10;
    const u32 key_len = 0x42 + u32(units) * 2;          // FILE_NAME size
    const u32 entry_len = 0x10 + ((key_len + 7) & ~7u); // 8-byte aligned
    StoreLe64(rec + entry + 0x00, mft_ref);
    StoreLe16(rec + entry + 0x08, u16(entry_len));
    StoreLe16(rec + entry + 0x0A, u16(key_len));
    StoreLe16(rec + entry + 0x0C, 0x0000);                           // not the last entry
    StoreLe32(rec + key + 0x38, is_dir ? 0x10000000u : 0x00000000u); // FILE_ATTR_DIRECTORY
    rec[key + 0x40] = units;                                         // name length (UTF-16 units)
    PutUtf16Name(rec + key + 0x42, name, units);
    *cursor = entry + entry_len;
}

// Build $Root (record 5): a FILE record whose only attribute of
// interest is a resident $INDEX_ROOT ($I30) holding three index
// entries — the regular file "hello.txt" plus the subdirectories
// "sub" and "big" — each pointing at its MFT record by name.
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

    // Three real INDEX_ENTRYs (collation order: big, hello.txt, sub)
    // then the last-entry sentinel. `cursor` walks past each entry's
    // 8-byte-aligned length so index_used picks up the exact span the
    // entries occupy.
    u32 cursor = hdr + entries_off;
    PutIndexEntry(rec, &cursor, kBigDirRecordNum, kBigDirName, kBigDirNameUnits, /*is_dir=*/true);
    PutIndexEntry(rec, &cursor, kFileRecordNum, kFileName, kFileNameUnits, /*is_dir=*/false);
    PutIndexEntry(rec, &cursor, kSubDirRecordNum, kSubDirName, kSubDirNameUnits, /*is_dir=*/true);

    // Trailing "last entry" sentinel (flags bit 0x02, no key).
    const u32 last = cursor;
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

// Build the "sub" directory record (record 25): a near-clone of
// PutRootRecord whose single $I30 entry points at "deep.txt" (a file).
// Marked in_use | is_directory like the root.
bool PutSubDirRecord(u32 handle)
{
    u8 rec[kRecordSize];
    Zero(rec, sizeof(rec));
    StoreLe32(rec + 0, kFileRecordMagic); // "FILE"
    StoreLe16(rec + 0x16, u16(0x0003));   // flags: in_use | is_directory
    constexpr u16 kFirstAttr = 0x38;
    StoreLe16(rec + 0x14, kFirstAttr);

    const u32 attr = kFirstAttr;
    const u32 value = attr + 0x18;
    const u32 hdr = value + 0x10;
    const u32 entries_off = 0x10;

    // One real INDEX_ENTRY ("deep.txt", a file) then the sentinel.
    u32 cursor = hdr + entries_off;
    PutIndexEntry(rec, &cursor, kDeepFileRecordNum, kDeepFileName, kDeepFileNameUnits, /*is_dir=*/false);

    const u32 last = cursor;
    StoreLe16(rec + last + 0x08, 0x10); // entry_length (>= 0x10)
    StoreLe16(rec + last + 0x0C, 0x02); // flags: last entry
    const u32 list_end = last + 0x10;

    // INDEX_HEADER fields.
    StoreLe32(rec + hdr + 0x00, entries_off);    // entries_offset
    StoreLe32(rec + hdr + 0x04, list_end - hdr); // index_used (total size)
    StoreLe32(rec + hdr + 0x08, list_end - hdr); // allocated size
    rec[hdr + 0x0C] = 0;                         // flags: small index

    // INDEX_ROOT prefix.
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

    StoreLe32(rec + attr + attr_len_aligned, kAttrTypeEnd);

    return PutRecord(handle, kSubDirRecordNum, rec);
}

// Build the nested file record (record 26): a clone of PutFileRecord
// carrying the resident $DATA body for "/sub/deep.txt".
bool PutDeepFileRecord(u32 handle)
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
    for (u32 i = 0; i < kDeepBodyLen; ++i)
        rec[value + i] = u8(kDeepBody[i]);
    const u32 attr_len_aligned = ((0x18 + kDeepBodyLen) + 7) & ~7u;
    StoreLe32(rec + attr + 0x00, kAttrTypeData);
    StoreLe32(rec + attr + 0x04, attr_len_aligned);
    rec[attr + 0x08] = 0;                       // resident
    rec[attr + 0x09] = 0;                       // unnamed
    StoreLe32(rec + attr + 0x10, kDeepBodyLen); // value length
    StoreLe16(rec + attr + 0x14, 0x18);         // value offset

    StoreLe32(rec + attr + attr_len_aligned, kAttrTypeEnd);
    return PutRecord(handle, kDeepFileRecordNum, rec);
}

// Format "fileNNN.txt" (zero-padded) for big-dir entry `n` into
// `out` (at least 12 bytes). Returns the name length in characters.
u8 FormatBigName(u32 n, char* out)
{
    out[0] = 'f';
    out[1] = 'i';
    out[2] = 'l';
    out[3] = 'e';
    out[4] = char('0' + (n / 100) % 10);
    out[5] = char('0' + (n / 10) % 10);
    out[6] = char('0' + n % 10);
    out[7] = '.';
    out[8] = 't';
    out[9] = 'x';
    out[10] = 't';
    out[11] = '\0';
    return 11;
}

// Build the "big" directory record (record 27). Unlike the root / sub
// records its $I30 attributes carry the real "$I30" UTF-16 name:
//   - $INDEX_ROOT (resident): EMPTY entry list — just the last-entry
//     sentinel with the sub-node flag — and the large-index flag set,
//     so every real entry lives in $INDEX_ALLOCATION.
//   - $INDEX_ALLOCATION (non-resident): two data runs of 16 clusters
//     (8 INDX blocks) each, at LCN kIndxRun1Lcn / kIndxRun2Lcn.
//   - $BITMAP (resident, 2 bytes): blocks 0..14 in use, 15 free.
bool PutBigDirRecord(u32 handle)
{
    u8 rec[kRecordSize];
    Zero(rec, sizeof(rec));
    StoreLe32(rec + 0, kFileRecordMagic); // "FILE"
    StoreLe16(rec + 0x16, u16(0x0003));   // flags: in_use | is_directory
    constexpr u16 kFirstAttr = 0x38;
    StoreLe16(rec + 0x14, kFirstAttr);

    // ---- $INDEX_ROOT (type 0x90), resident, named "$I30".
    // Resident header 0x18 bytes, name @ +0x18 (8 bytes), value @ +0x20.
    const u32 ir = kFirstAttr;
    const u32 ir_value = ir + 0x20;
    const u32 ir_hdr = ir_value + 0x10;
    // Lone last-entry sentinel: entry_len 0x18 (0x10 + 8-byte VCN),
    // flags 0x03 = last | has-sub-node, VCN 0 (the walker scans blocks
    // linearly and never dereferences the VCN — but write it real).
    const u32 ir_entry = ir_hdr + 0x10;
    StoreLe16(rec + ir_entry + 0x08, 0x18); // entry_length
    StoreLe16(rec + ir_entry + 0x0C, 0x03); // flags: last | sub-node
    StoreLe64(rec + ir_entry + 0x10, 0);    // sub-node VCN
    const u32 ir_list_end = ir_entry + 0x18;
    StoreLe32(rec + ir_hdr + 0x00, 0x10);                          // entries_offset
    StoreLe32(rec + ir_hdr + 0x04, ir_list_end - ir_hdr);          // index_used
    StoreLe32(rec + ir_hdr + 0x08, ir_list_end - ir_hdr);          // allocated
    rec[ir_hdr + 0x0C] = 1;                                        // flags: LARGE index
    StoreLe32(rec + ir_value + 0x00, kAttrTypeFileName);           // indexed attr type
    StoreLe32(rec + ir_value + 0x04, 0x00000001);                  // collation rule
    StoreLe32(rec + ir_value + 0x08, kIndexBlockSize);             // index block size
    rec[ir_value + 0x0C] = u8(kIndexBlockSize / kBytesPerCluster); // clusters per block

    const u32 ir_val_len = ir_list_end - ir_value;
    const u32 ir_len = ((0x20 + ir_val_len) + 7) & ~7u;
    StoreLe32(rec + ir + 0x00, kAttrTypeIndexRoot);
    StoreLe32(rec + ir + 0x04, ir_len);
    rec[ir + 0x08] = 0;                     // resident
    rec[ir + 0x09] = 4;                     // name length ("$I30")
    StoreLe16(rec + ir + 0x0A, 0x18);       // name offset
    StoreLe32(rec + ir + 0x10, ir_val_len); // value length
    StoreLe16(rec + ir + 0x14, 0x20);       // value offset
    PutUtf16Name(rec + ir + 0x18, "$I30", 4);

    // ---- $INDEX_ALLOCATION (type 0xA0), non-resident, named "$I30".
    // Non-resident header 0x40 bytes, name @ +0x40, mapping pairs @ +0x48.
    const u32 ia = ir + ir_len;
    constexpr u32 kStreamBytes = kIndxBlockCount * kIndexBlockSize;
    constexpr u32 kRunClusters = (kIndxBlocksPerRun * kIndexBlockSize) / kBytesPerCluster;
    StoreLe64(rec + ia + 0x10, 0);                         // lowest VCN
    StoreLe64(rec + ia + 0x18, u64(2 * kRunClusters) - 1); // highest VCN
    StoreLe16(rec + ia + 0x20, 0x48);                      // mapping-pairs offset
    StoreLe64(rec + ia + 0x28, kStreamBytes);              // allocated size
    StoreLe64(rec + ia + 0x30, kStreamBytes);              // data size
    StoreLe64(rec + ia + 0x38, kStreamBytes);              // initialised size
    PutUtf16Name(rec + ia + 0x40, "$I30", 4);
    // Mapping pairs: run 1 (header 0x11: 1-byte length, 1-byte LCN
    // delta), run 2 (delta from run 1's LCN), terminator.
    u32 mp = ia + 0x48;
    rec[mp++] = 0x11;
    rec[mp++] = u8(kRunClusters); // 16 clusters
    rec[mp++] = u8(kIndxRun1Lcn); // LCN 70
    rec[mp++] = 0x11;
    rec[mp++] = u8(kRunClusters);                // 16 clusters
    rec[mp++] = u8(kIndxRun2Lcn - kIndxRun1Lcn); // LCN delta +20 → 90
    rec[mp++] = 0x00;                            // end of runlist
    const u32 ia_len = ((mp - ia) + 7) & ~7u;
    StoreLe32(rec + ia + 0x00, kAttrTypeIndexAlloc);
    StoreLe32(rec + ia + 0x04, ia_len);
    rec[ia + 0x08] = 1;               // non-resident
    rec[ia + 0x09] = 4;               // name length ("$I30")
    StoreLe16(rec + ia + 0x0A, 0x40); // name offset

    // ---- $BITMAP (type 0xB0), resident, named "$I30". Bit b set ⇒
    // INDX block b in use: blocks 0..14 used, block 15 (ghost) free.
    const u32 bm = ia + ia_len;
    const u32 bm_len = ((0x20 + 2) + 7) & ~7u;
    StoreLe32(rec + bm + 0x00, kAttrTypeBitmap);
    StoreLe32(rec + bm + 0x04, bm_len);
    rec[bm + 0x08] = 0;               // resident
    rec[bm + 0x09] = 4;               // name length ("$I30")
    StoreLe16(rec + bm + 0x0A, 0x18); // name offset
    StoreLe32(rec + bm + 0x10, 2);    // value length (2 bytes = 16 bits)
    StoreLe16(rec + bm + 0x14, 0x20); // value offset
    PutUtf16Name(rec + bm + 0x18, "$I30", 4);
    rec[bm + 0x20] = 0xFF; // blocks 0..7 in use
    rec[bm + 0x21] = 0x7F; // blocks 8..14 in use, 15 free

    StoreLe32(rec + bm + bm_len, kAttrTypeEnd);
    return PutRecord(handle, kBigDirRecordNum, rec);
}

// Build the shared big-dir target record (record 28): a clone of
// PutFileRecord carrying the resident $DATA body every "fileNNN.txt"
// entry points at.
bool PutBigFileRecord(u32 handle)
{
    u8 rec[kRecordSize];
    Zero(rec, sizeof(rec));
    StoreLe32(rec + 0, kFileRecordMagic); // "FILE"
    StoreLe16(rec + 0x16, u16(0x0001));   // flags: in_use, not dir
    constexpr u16 kFirstAttr = 0x38;
    StoreLe16(rec + 0x14, kFirstAttr);

    const u32 attr = kFirstAttr;
    const u32 value = attr + 0x18;
    for (u32 i = 0; i < kBigBodyLen; ++i)
        rec[value + i] = u8(kBigBody[i]);
    const u32 attr_len_aligned = ((0x18 + kBigBodyLen) + 7) & ~7u;
    StoreLe32(rec + attr + 0x00, kAttrTypeData);
    StoreLe32(rec + attr + 0x04, attr_len_aligned);
    rec[attr + 0x08] = 0;                      // resident
    rec[attr + 0x09] = 0;                      // unnamed
    StoreLe32(rec + attr + 0x10, kBigBodyLen); // value length
    StoreLe16(rec + attr + 0x14, 0x18);        // value offset

    StoreLe32(rec + attr + attr_len_aligned, kAttrTypeEnd);
    return PutRecord(handle, kBigFileRecordNum, rec);
}

// Device LBA of big-dir INDX block `b` per the two-run layout the
// $INDEX_ALLOCATION runlist in PutBigDirRecord describes.
u64 IndxBlockLba(u32 b)
{
    if (b < kIndxBlocksPerRun)
        return kIndxRun1Lcn * kSectorsPerCluster + u64(b) * kIndexBlockSectors;
    return kIndxRun2Lcn * kSectorsPerCluster + u64(b - kIndxBlocksPerRun) * kIndexBlockSectors;
}

// Lay one 1 KiB INDX block at big-dir block index `b`, holding
// either `count` sequential "fileNNN.txt" entries starting at
// `first` (override_name == nullptr) or a single `override_name`
// entry (the ghost block). Layout mirrors what the C++ reader
// decodes: "INDX" magic, USA @ 0x28 (count 3), VCN @ 0x10,
// INDEX_HEADER @ 0x18 with offsets relative to 0x18, entries from
// 0x30, last-entry sentinel.
bool PutIndxBlock(u32 handle, u32 b, u32 first, u32 count, const char* override_name)
{
    u8 blk[kIndexBlockSize];
    Zero(blk, sizeof(blk));
    StoreLe32(blk + 0, kIndxRecordMagic);                                 // "INDX"
    StoreLe64(blk + 0x10, u64(b) * (kIndexBlockSize / kBytesPerCluster)); // this block's VCN

    constexpr u32 kIhdr = 0x18;
    const u32 entries_start = 0x30; // 8-aligned, past the USA (0x28..0x2D)
    u32 cursor = entries_start;
    if (override_name != nullptr)
    {
        u8 units = 0;
        while (override_name[units] != '\0')
            ++units;
        PutIndexEntry(blk, &cursor, kBigFileRecordNum, override_name, units, /*is_dir=*/false);
    }
    else
    {
        for (u32 i = 0; i < count; ++i)
        {
            char name[12];
            const u8 units = FormatBigName(first + i, name);
            PutIndexEntry(blk, &cursor, kBigFileRecordNum, name, units, /*is_dir=*/false);
        }
    }
    // Last-entry sentinel.
    StoreLe16(blk + cursor + 0x08, 0x10); // entry_length
    StoreLe16(blk + cursor + 0x0C, 0x02); // flags: last entry
    const u32 list_end = cursor + 0x10;

    StoreLe32(blk + kIhdr + 0x00, entries_start - kIhdr);   // entries_offset
    StoreLe32(blk + kIhdr + 0x04, list_end - kIhdr);        // index_used
    StoreLe32(blk + kIhdr + 0x08, kIndexBlockSize - kIhdr); // allocated
    StoreLe32(blk + kIhdr + 0x0C, 0);                       // flags: leaf

    StampUsa(blk, kIndexBlockSize, /*usa_off=*/0x28);
    return drivers::storage::BlockDeviceWrite(handle, IndxBlockLba(b), kIndexBlockSectors, blk) == 0;
}

// Lay every big-dir INDX block: 15 in-use blocks carrying the 105
// "fileNNN.txt" entries, plus the bitmap-free ghost block (15) whose
// "ghost.txt" entry must never surface through the walker.
bool PutBigDirIndexBlocks(u32 handle)
{
    for (u32 b = 0; b + 1 < kIndxBlockCount; ++b)
    {
        if (!PutIndxBlock(handle, b, b * kIndxEntriesPerBlock, kIndxEntriesPerBlock, nullptr))
            return false;
    }
    return PutIndxBlock(handle, kIndxBlockCount - 1, 0, 0, kGhostName);
}

bool BuildSyntheticVolume(u32 handle)
{
    return PutBootSector(handle) && PutRootRecord(handle) && PutFileRecord(handle) && PutSubDirRecord(handle) &&
           PutDeepFileRecord(handle) && PutBigDirRecord(handle) && PutBigFileRecord(handle) &&
           PutBigDirIndexBlocks(handle);
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

    // ---- Phase 7: VFS integration. Mount the synthetic volume and
    // prove VfsResolve surfaces an NTFS-tagged node the predicates +
    // read path agree on — the wire-in that makes a path under an NTFS
    // mount (`cat /mnt/.../hello.txt`) reach this backend.
    const MountId mid = VfsMount("/mnt/ntfs-selftest", FsType::Ntfs, handle);
    if (mid == kInvalidMountId)
    {
        Fail("vfs-mount");
        return;
    }
    const char kVfsPath[] = "/mnt/ntfs-selftest/hello.txt";
    const VfsNode node = VfsResolve(RamfsTrustedRoot(), kVfsPath, 256);
    if (node.backend != VfsBackend::Ntfs || !VfsNodeIsFile(node) || VfsNodeIsDir(node))
    {
        Fail("vfs-resolve");
        return;
    }
    if (VfsNodeSize(node) != kFileBodyLen || node.ntfs_mft_reference != kFileRecordNum)
    {
        Fail("vfs-node-fields");
        return;
    }
    // Read through the node exactly as the shell read path does
    // (NtfsReadMftRecord → NtfsResolveData → NtfsReadFile) and compare.
    const Volume* vvol = NtfsVolumeByHandle(node.ntfs_block_handle);
    u8 vrec[kRecordSize];
    DataLocation vdata{};
    u8 vbuf[64];
    u64 vread = 0;
    if (vvol == nullptr || !NtfsReadMftRecord(*vvol, node.ntfs_mft_reference, vrec) ||
        !NtfsResolveData(*vvol, vrec, &vdata) || !vdata.valid ||
        !NtfsReadFile(*vvol, vrec, vdata, 0, vbuf, sizeof(vbuf), &vread) || vread != kFileBodyLen)
    {
        Fail("vfs-read");
        return;
    }
    for (u32 i = 0; i < kFileBodyLen; ++i)
    {
        if (vbuf[i] != u8(kFileBody[i]))
        {
            Fail("vfs-content");
            return;
        }
    }
    // A path that obviously doesn't exist under the mount must miss.
    const char kMissPath[] = "/mnt/ntfs-selftest/_NOPE_.X";
    const VfsNode miss = VfsResolve(RamfsTrustedRoot(), kMissPath, 256);
    if (VfsNodeIsValid(miss) || miss.backend != VfsBackend::Invalid)
    {
        Fail("vfs-miss");
        return;
    }

    // ---- Phase 8: multi-component resolve. "/sub/deep.txt" walks
    // root → "sub" (a directory) → "deep.txt", exercising the descend-
    // into-subdirectory path (NtfsFindInDir at each level). First the
    // two raw NtfsFindInDir descend steps, then the VFS-level resolve.
    DirEntry sub{};
    if (!NtfsFindInDir(*v, kRootRecordNum, kSubDirName, &sub))
    {
        Fail("find-sub");
        return;
    }
    if (!sub.is_directory || sub.mft_reference != kSubDirRecordNum)
    {
        Fail("sub-fields");
        return;
    }
    DirEntry deep{};
    if (!NtfsFindInDir(*v, kSubDirRecordNum, kDeepFileName, &deep))
    {
        Fail("find-deep");
        return;
    }
    if (deep.mft_reference != kDeepFileRecordNum)
    {
        Fail("deep-reference");
        return;
    }

    // The subdirectory itself must resolve as a directory through the VFS.
    const char kSubPath[] = "/mnt/ntfs-selftest/sub";
    const VfsNode subnode = VfsResolve(RamfsTrustedRoot(), kSubPath, 256);
    if (subnode.backend != VfsBackend::Ntfs || !VfsNodeIsDir(subnode) || VfsNodeIsFile(subnode))
    {
        Fail("vfs-subdir");
        return;
    }

    const char kDeepPath[] = "/mnt/ntfs-selftest/sub/deep.txt";
    const VfsNode dnode = VfsResolve(RamfsTrustedRoot(), kDeepPath, 256);
    if (dnode.backend != VfsBackend::Ntfs || !VfsNodeIsFile(dnode))
    {
        Fail("vfs-deep-resolve");
        return;
    }
    if (VfsNodeSize(dnode) != kDeepBodyLen || dnode.ntfs_mft_reference != kDeepFileRecordNum)
    {
        Fail("vfs-deep-fields");
        return;
    }
    // Read the nested body back exactly as the shell read path does.
    const Volume* dvol = NtfsVolumeByHandle(dnode.ntfs_block_handle);
    u8 drec[kRecordSize];
    DataLocation ddata{};
    u8 dbuf[64];
    u64 dread = 0;
    if (dvol == nullptr || !NtfsReadMftRecord(*dvol, dnode.ntfs_mft_reference, drec) ||
        !NtfsResolveData(*dvol, drec, &ddata) || !ddata.valid ||
        !NtfsReadFile(*dvol, drec, ddata, 0, dbuf, sizeof(dbuf), &dread) || dread != kDeepBodyLen)
    {
        Fail("vfs-deep-read");
        return;
    }
    for (u32 i = 0; i < kDeepBodyLen; ++i)
    {
        if (dbuf[i] != u8(kDeepBody[i]))
        {
            Fail("vfs-deep-content");
            return;
        }
    }

    // ---- Phase 9: large directory ($INDEX_ALLOCATION). "big" keeps an
    // empty resident $INDEX_ROOT and spills 105 entries into 15 in-use
    // INDX blocks across two data runs; block 15 is valid on disk but
    // free in $BITMAP. Exercises: $I30-named attribute lookup, runlist
    // decode (both runs), per-block "INDX" + USA fixup, bitmap gating,
    // and the entry walk shared with the resident slice.
    DirEntry bigde{};
    if (!NtfsFindInDir(*v, kRootRecordNum, kBigDirName, &bigde))
    {
        Fail("find-big");
        return;
    }
    if (!bigde.is_directory || bigde.mft_reference != kBigDirRecordNum)
    {
        Fail("big-fields");
        return;
    }
    // Enumeration must continue past the (empty) resident root into the
    // INDX blocks — with 105 entries on disk the caller's cap fills.
    u32 bigcount = 0;
    if (!NtfsEnumerateDir(*v, kBigDirRecordNum, entries, kMaxDirEntries, &bigcount) || bigcount != kMaxDirEntries)
    {
        Fail("enumerate-big");
        return;
    }
    // First entry (block 0) and last entry (block 14, in the SECOND
    // data run) must both be reachable by name.
    char bigname[12];
    FormatBigName(0, bigname);
    DirEntry bigfile{};
    if (!NtfsFindInDir(*v, kBigDirRecordNum, bigname, &bigfile) || bigfile.mft_reference != kBigFileRecordNum)
    {
        Fail("find-big-first");
        return;
    }
    FormatBigName(kBigEntryCount - 1, bigname);
    if (!NtfsFindInDir(*v, kBigDirRecordNum, bigname, &bigfile) || bigfile.mft_reference != kBigFileRecordNum)
    {
        Fail("find-big-last");
        return;
    }
    // Negative lookups: "ghost.txt" lives only in the bitmap-FREE block
    // (must be skipped); "nope.txt" exists nowhere.
    DirEntry bigmiss{};
    if (NtfsFindInDir(*v, kBigDirRecordNum, kGhostName, &bigmiss))
    {
        Fail("big-ghost-found");
        return;
    }
    if (NtfsFindInDir(*v, kBigDirRecordNum, "nope.txt", &bigmiss))
    {
        Fail("big-nope-found");
        return;
    }

    // VFS-level resolve + read-back through the large directory.
    const char kBigDirPath[] = "/mnt/ntfs-selftest/big";
    const VfsNode bignode = VfsResolve(RamfsTrustedRoot(), kBigDirPath, 256);
    if (bignode.backend != VfsBackend::Ntfs || !VfsNodeIsDir(bignode))
    {
        Fail("vfs-big-dir");
        return;
    }
    const char kBigFilePath[] = "/mnt/ntfs-selftest/big/file099.txt";
    const VfsNode bfnode = VfsResolve(RamfsTrustedRoot(), kBigFilePath, 256);
    if (bfnode.backend != VfsBackend::Ntfs || !VfsNodeIsFile(bfnode) ||
        bfnode.ntfs_mft_reference != kBigFileRecordNum || VfsNodeSize(bfnode) != kBigBodyLen)
    {
        Fail("vfs-big-resolve");
        return;
    }
    const Volume* bvol = NtfsVolumeByHandle(bfnode.ntfs_block_handle);
    u8 brec[kRecordSize];
    DataLocation bdata{};
    u8 bbuf[64];
    u64 bread = 0;
    if (bvol == nullptr || !NtfsReadMftRecord(*bvol, bfnode.ntfs_mft_reference, brec) ||
        !NtfsResolveData(*bvol, brec, &bdata) || !bdata.valid ||
        !NtfsReadFile(*bvol, brec, bdata, 0, bbuf, sizeof(bbuf), &bread) || bread != kBigBodyLen)
    {
        Fail("vfs-big-read");
        return;
    }
    for (u32 i = 0; i < kBigBodyLen; ++i)
    {
        if (bbuf[i] != u8(kBigBody[i]))
        {
            Fail("vfs-big-content");
            return;
        }
    }

    SerialWrite("[ntfs-selftest] PASS (synthetic volume: probe+USA-fixup+root-index+resident-data file read + VFS "
                "resolve (single + multi-component) + INDEX_ALLOCATION large-dir walk (105 entries, 2 runs, "
                "bitmap-gated) verified)\n");
}

} // namespace duetos::fs::ntfs
