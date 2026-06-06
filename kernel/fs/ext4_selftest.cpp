// ext4_selftest.cpp — Ext4SelfTest: builds a minimal synthetic ext4
// volume in a fresh RAM block device and drives the read path end to
// end: probe → block-group-descriptor parse → root-inode read →
// root-dir enumerate → find a regular file → read its data back and
// compare. This is the boot wire-in proving the ext4 read code is
// live, not just compiled.
//
// The synthetic image is deliberately minimal — the smallest feature
// set the Rust parsers + the C++ extent walker accept:
//   - 1 KiB blocks (s_log_block_size = 0), single block group.
//   - rev1 inodes, 128-byte inode records (8 per 1 KiB block).
//   - extents feature on (s_feature_incompat bit 0x40); both the root
//     dir inode and the file inode use a depth-0 inline extent tree
//     (the 0xF30A header + one leaf in the 60-byte i_block area).
//   - no journal (read needs no replay), no htree, no 64bit, no
//     xattrs — see the GAP markers in fs/ext4.{h,cpp}.
//
// Layout (1 KiB blocks; first_data_block = 1):
//   block 0   boot (unused)
//   block 1   superblock (on-disk byte offset 1024)
//   block 2   group descriptor table (one 32-byte classic descriptor)
//   block 3   block bitmap (content irrelevant to read)
//   block 4   inode bitmap (content irrelevant to read)
//   block 5   inode table (inode 2 = root dir, inode 11 = the file)
//   block 6   root directory data (linux_dirent records)
//   block 7   file data ("hello from ext4\n" + padding)
//
// The RAM device uses 512-byte sectors, so one 1 KiB block == 2 LBAs.

#include "fs/ext4.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "drivers/storage/block.h"
#include "fs/mount.h"
#include "fs/ramfs.h"
#include "fs/vfs.h"
#include "log/klog.h"

namespace duetos::fs::ext4
{

namespace
{

constexpr u32 kSectorSize = 512;
constexpr u32 kBlockSize = 1024; // 1 KiB blocks (log_block_size = 0)
constexpr u32 kSectorsPerBlock = kBlockSize / kSectorSize;
constexpr u32 kInodeSize = 128; // rev1 minimum
constexpr u32 kInodesPerGroup = 16;
constexpr u32 kBlocksPerGroup = 8192;
constexpr u32 kBlockCount = 16; // total FS blocks (tiny)
constexpr u64 kSectorCount = u64(kBlockCount) * kSectorsPerBlock;

constexpr u32 kRootIno = 2;
// Inode 3 keeps the file's inode record inside the FIRST inode-table
// block (offset (3-1)*128 = 256 < 1024). Picking a high number like
// 11 would push the record into the second inode-table block (FS
// block 6), which this layout reuses for the root-dir data — a
// lost-slot collision. 16 inodes/group * 128 B = 2 blocks, so only
// inodes 1..8 live in block 5; the file must be one of those.
constexpr u32 kFileIno = 3;
// Subdirectory "sub" (inode 4) and the file it holds, "deep.txt"
// (inode 5). Both records live in the first inode-table block (offsets
// 384 and 512, < 1024) alongside inodes 1..3 — no lost-slot collision.
constexpr u32 kSubDirIno = 4;
constexpr u32 kDeepFileIno = 5;

// Block numbers (FS-relative, 1 KiB units).
constexpr u32 kGdtBlock = 2;
constexpr u32 kBlockBitmapBlock = 3;
constexpr u32 kInodeBitmapBlock = 4;
constexpr u32 kInodeTableBlock = 5;
constexpr u32 kRootDirBlock = 6;
constexpr u32 kFileDataBlock = 7;
constexpr u32 kSubDirBlock = 8;   // "sub" directory data
constexpr u32 kDeepDataBlock = 9; // "deep.txt" file data

constexpr u16 kExtentHeaderMagic = 0xF30A;
constexpr u32 kInodeFlagExtents = 0x80000;
constexpr u32 kFeatureIncompatExtents = 0x40;

// File body the test plants and reads back.
constexpr char kFileBody[] = "hello from ext4\n";
constexpr u32 kFileBodyLen = 16; // strlen, excludes the NUL
// Body of the nested file "/sub/deep.txt" (multi-component walk test).
constexpr char kDeepBody[] = "deep ext4 file\n";
constexpr u32 kDeepBodyLen = 15; // strlen, excludes the NUL

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

inline void Zero(void* p, u64 n)
{
    auto* b = static_cast<volatile u8*>(p);
    for (u64 i = 0; i < n; ++i)
        b[i] = 0;
}

// Write one 1 KiB FS block at FS-block index `block`.
bool PutBlock(u32 handle, u32 block, const u8* buf)
{
    const u64 lba = u64(block) * kSectorsPerBlock;
    return drivers::storage::BlockDeviceWrite(handle, lba, kSectorsPerBlock, buf) == 0;
}

// Fill `i_block` (60 bytes) with a depth-0 inline extent tree that
// maps logical block 0 → physical block `phys_block`, length 1.
void FillInlineExtent(u8* i_block, u32 phys_block)
{
    Zero(i_block, 60);
    // Extent header (12 bytes).
    StoreLe16(i_block + 0, kExtentHeaderMagic); // eh_magic
    StoreLe16(i_block + 2, 1);                  // eh_entries
    StoreLe16(i_block + 4, 4);                  // eh_max (4 fit inline)
    StoreLe16(i_block + 6, 0);                  // eh_depth = 0 (leaf)
    StoreLe32(i_block + 8, 0);                  // eh_generation
    // One leaf extent record (12 bytes) at offset 12.
    StoreLe32(i_block + 12, 0);          // ee_block (logical)
    StoreLe16(i_block + 16, 1);          // ee_len (blocks)
    StoreLe16(i_block + 18, 0);          // ee_start_hi
    StoreLe32(i_block + 20, phys_block); // ee_start_lo (physical)
}

// Write inode `ino` (1-based) into the inode-table block. mode/size
// per args; extent-mapped to `data_block`.
void PutInode(u8* table, u32 ino, u16 mode, u32 size_bytes, u16 links, u32 data_block)
{
    const u32 off = (ino - 1) * kInodeSize;
    u8* p = table + off;
    Zero(p, kInodeSize);
    StoreLe16(p + 0x00, mode);              // i_mode
    StoreLe32(p + 0x04, size_bytes);        // i_size_lo
    StoreLe16(p + 0x1A, links);             // i_links_count
    StoreLe32(p + 0x20, kInodeFlagExtents); // i_flags (EXT4_EXTENTS_FL)
    FillInlineExtent(p + 0x28, data_block); // i_block (extent tree)
}

// Append one linux_dirent record to `block` at `*off`. rec_len is
// 4-byte aligned. file_type: 1=reg, 2=dir.
void PutDirent(u8* block, u32& off, u32 ino, const char* name, u32 name_len, u8 file_type, u16 rec_len)
{
    u8* p = block + off;
    StoreLe32(p + 0, ino);
    StoreLe16(p + 4, rec_len);
    p[6] = u8(name_len);
    p[7] = file_type;
    for (u32 i = 0; i < name_len; ++i)
        p[8 + i] = u8(name[i]);
    off += rec_len;
}

// Lay out the whole minimal ext4 image. Returns false on any block
// write failure.
bool BuildSyntheticVolume(u32 handle)
{
    u8 block[kBlockSize];

    // ---- Superblock (FS block 1 = on-disk byte 1024). The Rust
    // parser reads fields relative to byte 1024, so we place them at
    // the start of block 1.
    Zero(block, sizeof(block));
    StoreLe32(block + 0x00, 32);                      // s_inodes_count (>= kFileIno)
    StoreLe32(block + 0x04, kBlockCount);             // s_blocks_count_lo
    StoreLe32(block + 0x14, 1);                       // s_first_data_block (1 for 1 KiB)
    StoreLe32(block + 0x18, 0);                       // s_log_block_size (0 → 1 KiB)
    StoreLe32(block + 0x20, kBlocksPerGroup);         // s_blocks_per_group
    StoreLe32(block + 0x28, kInodesPerGroup);         // s_inodes_per_group
    StoreLe16(block + 0x38, ext4::kSuperblockMagic);  // s_magic (0xEF53)
    StoreLe16(block + 0x3A, 1);                       // s_state (clean)
    StoreLe32(block + 0x4C, 1);                       // s_rev_level (rev1)
    StoreLe16(block + 0x58, u16(kInodeSize));         // s_inode_size
    StoreLe32(block + 0x60, kFeatureIncompatExtents); // s_feature_incompat
    const char* label = "EXT4SELF";
    for (u32 i = 0; label[i] != '\0'; ++i)
        block[0x78 + i] = u8(label[i]); // s_volume_name
    if (!PutBlock(handle, 1, block))
        return false;

    // ---- Group descriptor table (FS block 2). One 32-byte classic
    // descriptor: block/inode bitmaps + the inode-table block.
    Zero(block, sizeof(block));
    StoreLe32(block + 0x00, kBlockBitmapBlock); // bg_block_bitmap
    StoreLe32(block + 0x04, kInodeBitmapBlock); // bg_inode_bitmap
    StoreLe32(block + 0x08, kInodeTableBlock);  // bg_inode_table
    StoreLe16(block + 0x0C, 100);               // bg_free_blocks_count
    StoreLe16(block + 0x0E, 10);                // bg_free_inodes_count
    StoreLe16(block + 0x10, 1);                 // bg_used_dirs_count
    if (!PutBlock(handle, kGdtBlock, block))
        return false;

    // ---- Block / inode bitmaps (content irrelevant to read-only
    // enumeration). Zero them so the device is deterministic.
    Zero(block, sizeof(block));
    if (!PutBlock(handle, kBlockBitmapBlock, block))
        return false;
    if (!PutBlock(handle, kInodeBitmapBlock, block))
        return false;

    // ---- Inode table (FS block 5). Inode 2 = root dir (extent →
    // root-dir block); inode 11 = the regular file (extent → data
    // block). 0x41ED = dir|0755; 0x81A4 = reg|0644.
    Zero(block, sizeof(block));
    PutInode(block, kRootIno, 0x41ED, kBlockSize, 2, kRootDirBlock);
    PutInode(block, kFileIno, 0x81A4, kFileBodyLen, 1, kFileDataBlock);
    // "sub" directory (one block of dir data) and the nested file.
    PutInode(block, kSubDirIno, 0x41ED, kBlockSize, 2, kSubDirBlock);
    PutInode(block, kDeepFileIno, 0x81A4, kDeepBodyLen, 1, kDeepDataBlock);
    if (!PutBlock(handle, kInodeTableBlock, block))
        return false;

    // ---- Root directory data (FS block 6). Records: ".", "..",
    // "hello.txt" → inode 3, "sub" → inode 4. rec_lens are 4-byte
    // aligned; the last record stretches to the block end.
    Zero(block, sizeof(block));
    u32 off = 0;
    PutDirent(block, off, kRootIno, ".", 1, 2, 12);
    PutDirent(block, off, kRootIno, "..", 2, 2, 12);
    // "hello.txt" = 9 chars → 8 + 9 = 17 → round to 20.
    PutDirent(block, off, kFileIno, "hello.txt", 9, 1, 20);
    // "sub" (file_type 2 = dir) is last → stretch to the block end.
    PutDirent(block, off, kSubDirIno, "sub", 3, 2, u16(kBlockSize - off));
    if (!PutBlock(handle, kRootDirBlock, block))
        return false;

    // ---- File data (FS block 7). The body, zero-padded.
    Zero(block, sizeof(block));
    for (u32 i = 0; i < kFileBodyLen; ++i)
        block[i] = u8(kFileBody[i]);
    if (!PutBlock(handle, kFileDataBlock, block))
        return false;

    // ---- "sub" directory data (FS block 8). Records: ".", "..",
    // "deep.txt" → inode 5 (last record stretches to the block end).
    Zero(block, sizeof(block));
    off = 0;
    PutDirent(block, off, kSubDirIno, ".", 1, 2, 12);
    PutDirent(block, off, kRootIno, "..", 2, 2, 12);
    PutDirent(block, off, kDeepFileIno, "deep.txt", 8, 1, u16(kBlockSize - off));
    if (!PutBlock(handle, kSubDirBlock, block))
        return false;

    // ---- Nested file data (FS block 9).
    Zero(block, sizeof(block));
    for (u32 i = 0; i < kDeepBodyLen; ++i)
        block[i] = u8(kDeepBody[i]);
    if (!PutBlock(handle, kDeepDataBlock, block))
        return false;

    return true;
}

void Fail(const char* phase)
{
    using arch::SerialWrite;
    SerialWrite("[ext4-selftest] FAIL (");
    SerialWrite(phase);
    SerialWrite(")\n");
    KBP_PROBE_V(duetos::debug::ProbeId::kBootSelftestFail, 0xE47Au);
}

} // namespace

// Boot self-test: build a synthetic ext4 volume in RAM and drive the
// read path. Emits a single [ext4-selftest] PASS line on success so
// CI can grep it; a FAIL line + kBootSelftestFail probe on any failed
// assertion. Registered after ExfatSelfTest in boot_bringup.cpp.
void Ext4SelfTest()
{
    KLOG_TRACE_SCOPE("fs/ext4", "Ext4SelfTest");
    using arch::SerialWrite;

    const u32 handle = drivers::storage::RamBlockDeviceCreate("ramext4", kSectorSize, kSectorCount);
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

    // ---- Phase 1: probe. Ext4Probe parses the superblock, the group
    // descriptor, the root inode, and enumerates the root dir.
    auto probed = Ext4Probe(handle);
    if (!probed)
    {
        Fail("probe");
        return;
    }
    const Volume* v = Ext4VolumeByIndex(probed.value());
    if (v == nullptr || !v->group0_valid || !v->root_inode_valid)
    {
        Fail("probe-state");
        return;
    }
    if (v->block_size != kBlockSize || v->inode_size != kInodeSize)
    {
        Fail("geometry");
        return;
    }
    if ((v->feature_incompat & kFeatureIncompatExtents) == 0 || !v->root_inode.uses_extents)
    {
        Fail("extents-flag");
        return;
    }

    // ---- Phase 2: root-dir enumeration found "hello.txt".
    Ext4DirEntry hello{};
    if (!Ext4FindInRoot(*v, "hello.txt", &hello))
    {
        Fail("find-in-root");
        return;
    }
    if (hello.inode != kFileIno || hello.file_type != 1 /*reg*/)
    {
        Fail("dirent-fields");
        return;
    }

    // ---- Phase 3: read the file inode by number, then its data, and
    // compare against the planted body.
    InodeInfo fino{};
    if (!Ext4ReadInode(*v, hello.inode, &fino))
    {
        Fail("read-inode");
        return;
    }
    if (fino.size_bytes != kFileBodyLen || !fino.uses_extents)
    {
        Fail("inode-fields");
        return;
    }

    u8 buf[64];
    u64 nread = 0;
    if (!Ext4ReadFile(*v, fino, 0, buf, sizeof(buf), &nread))
    {
        Fail("read-file");
        return;
    }
    if (nread != kFileBodyLen)
    {
        Fail("read-len");
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

    // ---- Phase 4: a mid-file read (offset 6, len 5) returns "from ".
    u64 nread2 = 0;
    if (!Ext4ReadFile(*v, fino, 6, buf, 5, &nread2) || nread2 != 5)
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

    // ---- Phase 5: VFS integration. Mount the synthetic volume and
    // prove VfsResolve surfaces an ext4-tagged node the predicates +
    // read path agree on. This is the wire-in that makes a path under
    // an ext4 mount (`cat /mnt/.../hello.txt`) reach this backend
    // rather than reporting a phantom miss.
    const MountId mid = VfsMount("/mnt/ext4-selftest", FsType::Ext4, handle);
    if (mid == kInvalidMountId)
    {
        Fail("vfs-mount");
        return;
    }
    const char kVfsPath[] = "/mnt/ext4-selftest/hello.txt";
    const VfsNode node = VfsResolve(RamfsTrustedRoot(), kVfsPath, 256);
    if (node.backend != VfsBackend::Ext4 || !VfsNodeIsFile(node) || VfsNodeIsDir(node))
    {
        Fail("vfs-resolve");
        return;
    }
    if (VfsNodeSize(node) != kFileBodyLen || node.ext4_inode != kFileIno)
    {
        Fail("vfs-node-fields");
        return;
    }
    // Read through the node exactly as the shell read path does
    // (Ext4VolumeByHandle → Ext4ReadInode → Ext4ReadFile) and compare.
    const Volume* vvol = Ext4VolumeByHandle(node.ext4_block_handle);
    InodeInfo vinfo{};
    u8 vbuf[64];
    u64 vread = 0;
    if (vvol == nullptr || !Ext4ReadInode(*vvol, node.ext4_inode, &vinfo) ||
        !Ext4ReadFile(*vvol, vinfo, 0, vbuf, sizeof(vbuf), &vread) || vread != kFileBodyLen)
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
    // A path that obviously doesn't exist under the mount must miss
    // (proves the lookup runs the ext4 backend, not a papered-over hit).
    const char kMissPath[] = "/mnt/ext4-selftest/_NOPE_.X";
    const VfsNode miss = VfsResolve(RamfsTrustedRoot(), kMissPath, 256);
    if (VfsNodeIsValid(miss) || miss.backend != VfsBackend::Invalid)
    {
        Fail("vfs-miss");
        return;
    }

    // ---- Phase 6: multi-component resolve. "/sub/deep.txt" walks
    // root → "sub" (a directory) → "deep.txt", exercising the
    // descend-into-subdirectory path (Ext4FindInDir + Ext4ReadInode).
    // First the subdirectory itself must resolve as a directory.
    const char kSubPath[] = "/mnt/ext4-selftest/sub";
    const VfsNode subnode = VfsResolve(RamfsTrustedRoot(), kSubPath, 256);
    if (subnode.backend != VfsBackend::Ext4 || !VfsNodeIsDir(subnode) || VfsNodeIsFile(subnode))
    {
        Fail("vfs-subdir");
        return;
    }
    const char kDeepPath[] = "/mnt/ext4-selftest/sub/deep.txt";
    const VfsNode dnode = VfsResolve(RamfsTrustedRoot(), kDeepPath, 256);
    if (dnode.backend != VfsBackend::Ext4 || !VfsNodeIsFile(dnode))
    {
        Fail("vfs-deep-resolve");
        return;
    }
    if (VfsNodeSize(dnode) != kDeepBodyLen || dnode.ext4_inode != kDeepFileIno)
    {
        Fail("vfs-deep-fields");
        return;
    }
    const Volume* dvol = Ext4VolumeByHandle(dnode.ext4_block_handle);
    InodeInfo dinfo{};
    u8 dbuf[64];
    u64 dread = 0;
    if (dvol == nullptr || !Ext4ReadInode(*dvol, dnode.ext4_inode, &dinfo) ||
        !Ext4ReadFile(*dvol, dinfo, 0, dbuf, sizeof(dbuf), &dread) || dread != kDeepBodyLen)
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

    SerialWrite("[ext4-selftest] PASS (synthetic volume: probe+gdt+inode+root-dir+extent file read + VFS resolve "
                "(single + multi-component) verified)\n");
}

} // namespace duetos::fs::ext4
