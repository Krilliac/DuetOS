#include "ext4.h"

#include "../arch/x86_64/serial.h"
#include "../core/klog.h"
#include "../drivers/storage/block.h"

namespace duetos::fs::ext4
{

namespace
{

constinit Volume g_volumes[kMaxVolumes] = {};
u32 g_volume_count = 0;

// Static scratch buffer — kernel stack isn't in the direct map
// and BlockDeviceRead requires a direct-mapped destination.
// 1024 bytes covers the ext4 superblock; alignas(16) matches
// NVMe / AHCI DMA alignment expectations.
alignas(16) constinit u8 g_scratch[1024] = {};
// Block scratch — 4 KiB covers the common block size (4 KiB) in one
// read. Used for group descriptor table + inode table reads.
alignas(16) constinit u8 g_block_scratch[4096] = {};

// Pull a little-endian u16/u32/u64 out of a raw byte buffer.
inline u16 LeU16(const u8* p)
{
    return u16(p[0]) | (u16(p[1]) << 8);
}
inline u32 LeU32(const u8* p)
{
    return u32(p[0]) | (u32(p[1]) << 8) | (u32(p[2]) << 16) | (u32(p[3]) << 24);
}

// Superblock field offsets (relative to the superblock start, NOT
// the LBA start). See include/linux/ext4_fs.h / e2fsprogs.
constexpr u64 kSbOffInodeCount = 0x00;
constexpr u64 kSbOffBlockCountLo = 0x04;
constexpr u64 kSbOffFirstDataBlock = 0x14;
constexpr u64 kSbOffLogBlockSize = 0x18; // block_size = 1024 << this
constexpr u64 kSbOffBlocksPerGroup = 0x20;
constexpr u64 kSbOffInodesPerGroup = 0x28;
constexpr u64 kSbOffMagic = 0x38;
constexpr u64 kSbOffRevLevel = 0x4C;
constexpr u64 kSbOffInodeSize = 0x58; // u16; 128 / 256
constexpr u64 kSbOffFeatureCompat = 0x5C;
constexpr u64 kSbOffFeatureIncompat = 0x60;
constexpr u64 kSbOffFeatureRoCompat = 0x64;
constexpr u64 kSbOffVolumeName = 0x78; // 16 bytes

// Group-descriptor offsets (classic 32-byte layout; 64-bit FS also
// has 64-byte entries, which we treat identically for the low 32).
constexpr u64 kGdBlockBitmapLo = 0x00;
constexpr u64 kGdInodeBitmapLo = 0x04;
constexpr u64 kGdInodeTableLo = 0x08;
constexpr u64 kGdFreeBlocksLo = 0x0C;
constexpr u64 kGdFreeInodesLo = 0x0E;
constexpr u64 kGdUsedDirsLo = 0x10;

// Inode field offsets.
constexpr u64 kInoMode = 0x00;       // u16
constexpr u64 kInoUid = 0x02;        // u16
constexpr u64 kInoSizeLo = 0x04;     // u32
constexpr u64 kInoAtime = 0x08;      // u32
constexpr u64 kInoCtime = 0x0C;      // u32
constexpr u64 kInoMtime = 0x10;      // u32
constexpr u64 kInoGid = 0x18;        // u16
constexpr u64 kInoLinksCount = 0x1A; // u16
constexpr u64 kInoBlocksLo = 0x1C;   // u32
constexpr u64 kInoFlags = 0x20;      // u32
constexpr u64 kInoBlock0 = 0x28;     // first of i_block[15] / extent header
constexpr u64 kInoSizeHi = 0x6C;     // u32 (large_file feature)

constexpr u32 kInodeFlagExtents = 0x80000; // EXT4_EXTENTS_FL
constexpr u16 kExtentHeaderMagic = 0xF30A;
constexpr u32 kRootInodeNumber = 2;
constexpr u32 kFeatureRoCompatLargeFile = 0x02;

// Classify a probe result as ext2 / ext3 / ext4 from feature bits.
// FEATURE_INCOMPAT_EXTENTS (0x40) is the ext4 signature;
// FEATURE_COMPAT_HAS_JOURNAL (0x04) upgrades ext2 -> ext3.
constexpr u32 kFeatureIncompatExtents = 0x40;
constexpr u32 kFeatureCompatHasJournal = 0x04;

const char* ClassifyExt(u32 feature_incompat, u32 feature_compat)
{
    if (feature_incompat & kFeatureIncompatExtents)
        return "ext4";
    if (feature_compat & kFeatureCompatHasJournal)
        return "ext3";
    return "ext2";
}

void ByteZero(void* dst, u64 n)
{
    auto* d = static_cast<volatile u8*>(dst);
    for (u64 i = 0; i < n; ++i)
        d[i] = 0;
}

// Read `count` sectors beginning at `lba` into g_block_scratch.
// Returns false on error or if `bytes` exceeds the scratch size.
bool ReadIntoBlockScratch(u32 block_handle, u64 lba, u32 sector_size, u64 bytes)
{
    if (sector_size == 0 || bytes > sizeof(g_block_scratch))
        return false;
    const u32 count = u32(bytes / sector_size);
    if (count == 0 || (bytes % sector_size) != 0)
        return false;
    return drivers::storage::BlockDeviceRead(block_handle, lba, count, g_block_scratch) >= 0;
}

// Decode group descriptor 0 from a scratch buffer where the GDT
// starts. Returns true on success. Only populates the low 32-bit
// fields; 64-bit FS has upper halves at offset +0x20 which we
// ignore (the ext4 probe doesn't need them to locate the inode
// table on < 2^32 volumes, i.e. anything under 16 TiB with 4 KiB
// blocks).
bool DecodeGroupDesc0(const u8* buf, GroupDesc* out)
{
    out->block_bitmap_block = LeU32(buf + kGdBlockBitmapLo);
    out->inode_bitmap_block = LeU32(buf + kGdInodeBitmapLo);
    out->inode_table_block = LeU32(buf + kGdInodeTableLo);
    out->free_blocks_count = LeU16(buf + kGdFreeBlocksLo);
    out->free_inodes_count = LeU16(buf + kGdFreeInodesLo);
    out->used_dirs_count = LeU16(buf + kGdUsedDirsLo);
    return out->inode_table_block != 0;
}

// Decode an inode record from the start of `buf`. `ino_size` is
// the filesystem's on-disk inode size.
bool DecodeInode(const u8* buf, u16 ino_size, u32 feature_ro_compat, InodeInfo* out)
{
    if (ino_size < 0x80)
        return false;
    out->mode = LeU16(buf + kInoMode);
    out->uid = LeU16(buf + kInoUid);
    const u32 size_lo = LeU32(buf + kInoSizeLo);
    u64 size = size_lo;
    if ((feature_ro_compat & kFeatureRoCompatLargeFile) && ino_size >= 0x70)
        size |= u64(LeU32(buf + kInoSizeHi)) << 32;
    out->size_bytes = size;
    out->atime = LeU32(buf + kInoAtime);
    out->ctime = LeU32(buf + kInoCtime);
    out->mtime = LeU32(buf + kInoMtime);
    out->gid = LeU16(buf + kInoGid);
    out->links_count = LeU16(buf + kInoLinksCount);
    out->blocks_lo = LeU32(buf + kInoBlocksLo);
    out->flags = LeU32(buf + kInoFlags);
    out->uses_extents = (out->flags & kInodeFlagExtents) != 0;
    out->block0_magic = LeU16(buf + kInoBlock0);
    // Capture the full 60-byte i_block[15] region so a subsequent
    // directory or inline-data walk doesn't need to re-read the
    // inode from disk.
    for (u32 i = 0; i < 60; ++i)
        out->i_block[i] = buf[kInoBlock0 + i];
    return true;
}

const char* InodeModeType(u16 mode)
{
    const u16 type = mode & 0xF000;
    switch (type)
    {
    case 0x4000:
        return "dir";
    case 0x8000:
        return "reg";
    case 0xA000:
        return "lnk";
    case 0x2000:
        return "chr";
    case 0x6000:
        return "blk";
    case 0x1000:
        return "fifo";
    case 0xC000:
        return "sock";
    default:
        return "?";
    }
}

const char* Ext4FileTypeName(u8 ft)
{
    switch (ft)
    {
    case 1:
        return "reg";
    case 2:
        return "dir";
    case 3:
        return "chr";
    case 4:
        return "blk";
    case 5:
        return "fifo";
    case 6:
        return "sock";
    case 7:
        return "lnk";
    default:
        return "?";
    }
}

// Extent header / entry offsets.
constexpr u64 kEhMagic = 0x00;
constexpr u64 kEhEntries = 0x02;
constexpr u64 kEhMax = 0x04;
constexpr u64 kEhDepth = 0x06;
// Extent-entry fields. (kEeLogical at offset 0 — tracked in the
// comment but we only need length + phys for a single-extent walk.)
constexpr u64 kEeLength = 0x04;
constexpr u64 kEePhysHi = 0x06;
constexpr u64 kEePhysLo = 0x08;

// Parse one directory block's worth of linux_dirent records into
// `out_entries[]`. `block` points to the start of the block;
// `block_size` is its byte length. Returns the number of entries
// appended.
u32 ParseDirBlock(const u8* block, u32 block_size, Ext4DirEntry* out_entries, u32 cap, u32 already)
{
    u32 produced = already;
    u32 off = 0;
    while (off + 8 <= block_size && produced < cap)
    {
        const u32 inode = LeU32(block + off + 0);
        const u16 rec_len = LeU16(block + off + 4);
        const u8 name_len = block[off + 6];
        const u8 file_type = block[off + 7];
        if (rec_len < 8 || rec_len + off > block_size || (rec_len & 0x3) != 0)
            break;
        // inode==0 means "unused slot" — skip its name but honour rec_len.
        if (inode != 0 && name_len > 0)
        {
            Ext4DirEntry& e = out_entries[produced++];
            e.inode = inode;
            e.file_type = file_type;
            const u32 copy = (name_len < sizeof(e.name) - 1) ? name_len : u32(sizeof(e.name) - 1);
            for (u32 i = 0; i < copy; ++i)
                e.name[i] = char(block[off + 8 + i]);
            e.name[copy] = '\0';
        }
        off += rec_len;
    }
    return produced;
}

// Walk the root-directory data blocks. Requires `v.root_inode_valid`
// and that the root inode uses the extent tree (the common ext4
// layout). Handles depth-0 extent trees with multiple extents,
// each spanning one or more contiguous physical blocks — covers
// freshly-formatted volumes whose root has grown past one block.
// Depth>0 (extent tree with intermediate index nodes) still bails;
// the index-node walk would need extra block reads and a small
// recursion budget — landed when a workload demands it.
void WalkRootDir(Volume& v)
{
    if (!v.root_inode_valid || !v.root_inode.uses_extents)
        return;
    const u8* ib = v.root_inode.i_block;
    if (LeU16(ib + kEhMagic) != kExtentHeaderMagic)
    {
        arch::SerialWrite("[ext4]   root-dir extent header magic mismatch\n");
        return;
    }
    const u16 entries = LeU16(ib + kEhEntries);
    const u16 max_entries = LeU16(ib + kEhMax);
    const u16 depth = LeU16(ib + kEhDepth);
    if (entries == 0 || max_entries == 0)
        return;
    if (depth != 0)
    {
        arch::SerialWrite("[ext4]   root-dir extent tree has depth>0 — walk deferred\n");
        return;
    }

    const u32 sector_size = drivers::storage::BlockDeviceSectorSize(v.block_handle);
    if (sector_size == 0)
        return;

    // i_block holds the 12-byte header followed by up to 4 extent
    // records (also 12 bytes each) when depth==0. The on-disk
    // header is at most 4 leaf extents wide for the inline tree.
    constexpr u16 kInlineMaxLeafExtents = 4;
    const u16 leaf_count = entries < kInlineMaxLeafExtents ? entries : kInlineMaxLeafExtents;

    v.root_dir_entry_count = 0;
    u32 produced = 0;
    bool any_block_failed = false;

    for (u16 ei = 0; ei < leaf_count && produced < kMaxRootDirEntries; ++ei)
    {
        const u8* ext = ib + 12 + u64(ei) * 12;
        const u16 len_blocks = LeU16(ext + kEeLength);
        const u64 phys = (u64(LeU16(ext + kEePhysHi)) << 32) | LeU32(ext + kEePhysLo);
        if (len_blocks == 0 || phys == 0)
            continue;

        for (u16 bi = 0; bi < len_blocks && produced < kMaxRootDirEntries; ++bi)
        {
            const u64 block_phys = phys + bi;
            const u64 lba = block_phys * v.block_size / sector_size;
            if (!ReadIntoBlockScratch(v.block_handle, lba, sector_size, v.block_size))
            {
                arch::SerialWrite("[ext4]   root-dir data block read failed (extent=");
                arch::SerialWriteHex(ei);
                arch::SerialWrite(" block=");
                arch::SerialWriteHex(bi);
                arch::SerialWrite(")\n");
                any_block_failed = true;
                break;
            }
            produced = ParseDirBlock(g_block_scratch, v.block_size, v.root_dir_entries, kMaxRootDirEntries, produced);
        }
    }

    v.root_dir_entry_count = produced;

    arch::SerialWrite("[ext4]   root-dir entries: ");
    arch::SerialWriteHex(v.root_dir_entry_count);
    arch::SerialWrite(" (extents=");
    arch::SerialWriteHex(leaf_count);
    if (any_block_failed)
        arch::SerialWrite(" partial");
    arch::SerialWrite(")\n");
    for (u32 i = 0; i < v.root_dir_entry_count; ++i)
    {
        const Ext4DirEntry& e = v.root_dir_entries[i];
        arch::SerialWrite("[ext4]     ");
        arch::SerialWrite(e.name);
        arch::SerialWrite("  inode=");
        arch::SerialWriteHex(e.inode);
        arch::SerialWrite(" type=");
        arch::SerialWrite(Ext4FileTypeName(e.file_type));
        arch::SerialWrite("\n");
    }
}

// Read the group-descriptor table (group 0) + the root inode, fill
// the corresponding fields in `v`. Best-effort: failure here just
// leaves the volume with the probe-only metadata.
void ReadGroup0AndRootInode(Volume& v)
{
    const u32 sector_size = drivers::storage::BlockDeviceSectorSize(v.block_handle);
    if (sector_size == 0 || v.block_size == 0)
        return;

    // GDT sits at block `first_data_block + 1`. For 4 KiB blocks
    // with first_data_block = 0 that's block 1 (LBA 8 on 512-byte
    // devices); for 1 KiB blocks with first_data_block = 1 that's
    // block 2 (LBA 4).
    const u64 gdt_block = u64(v.first_data_block) + 1;
    const u64 gdt_lba = gdt_block * v.block_size / sector_size;
    if (!ReadIntoBlockScratch(v.block_handle, gdt_lba, sector_size, v.block_size))
    {
        arch::SerialWrite("[ext4]   gdt read failed\n");
        return;
    }
    if (!DecodeGroupDesc0(g_block_scratch, &v.group0))
        return;
    v.group0_valid = true;
    arch::SerialWrite("[ext4]   gdt0 block_bitmap=");
    arch::SerialWriteHex(v.group0.block_bitmap_block);
    arch::SerialWrite(" inode_bitmap=");
    arch::SerialWriteHex(v.group0.inode_bitmap_block);
    arch::SerialWrite(" inode_table=");
    arch::SerialWriteHex(v.group0.inode_table_block);
    arch::SerialWrite(" free_blks=");
    arch::SerialWriteHex(v.group0.free_blocks_count);
    arch::SerialWrite(" free_inodes=");
    arch::SerialWriteHex(v.group0.free_inodes_count);
    arch::SerialWrite(" dirs=");
    arch::SerialWriteHex(v.group0.used_dirs_count);
    arch::SerialWrite("\n");

    // Root inode is inode 2 (inodes are 1-based; 1 is reserved for
    // the defective-blocks list). Inodes-per-group tells us which
    // group; for inode 2, that's always group 0.
    if (v.inode_size == 0 || v.inodes_per_group == 0)
        return;
    const u32 index_in_group = (kRootInodeNumber - 1) % v.inodes_per_group;
    const u64 byte_offset_in_table = u64(index_in_group) * v.inode_size;
    const u64 inode_table_lba = u64(v.group0.inode_table_block) * v.block_size / sector_size;
    // Read one block's worth at the inode table start; the root
    // inode is the second record, well within 4 KiB.
    if (!ReadIntoBlockScratch(v.block_handle, inode_table_lba, sector_size, v.block_size))
    {
        arch::SerialWrite("[ext4]   inode-table read failed\n");
        return;
    }
    // Guard: the inode must fit within the scratch.
    if (byte_offset_in_table + v.inode_size > v.block_size)
    {
        arch::SerialWrite("[ext4]   root inode outside first block (inode_size skew)\n");
        return;
    }
    if (!DecodeInode(g_block_scratch + byte_offset_in_table, v.inode_size, v.feature_ro_compat, &v.root_inode))
        return;
    v.root_inode_valid = true;
    arch::SerialWrite("[ext4]   root_inode mode=");
    arch::SerialWriteHex(v.root_inode.mode);
    arch::SerialWrite(" type=");
    arch::SerialWrite(InodeModeType(v.root_inode.mode));
    arch::SerialWrite(" size=");
    arch::SerialWriteHex(v.root_inode.size_bytes);
    arch::SerialWrite(" links=");
    arch::SerialWriteHex(v.root_inode.links_count);
    arch::SerialWrite(" blocks_lo=");
    arch::SerialWriteHex(v.root_inode.blocks_lo);
    arch::SerialWrite(" flags=");
    arch::SerialWriteHex(v.root_inode.flags);
    arch::SerialWrite(v.root_inode.uses_extents ? " EXTENTS" : " LEGACY-BLKS");
    if (v.root_inode.uses_extents)
    {
        arch::SerialWrite(" i_block[0]_magic=");
        arch::SerialWriteHex(v.root_inode.block0_magic);
        arch::SerialWrite(v.root_inode.block0_magic == kExtentHeaderMagic ? " (valid)" : " (unexpected)");
    }
    arch::SerialWrite("\n");

    WalkRootDir(v);
}

} // namespace

::duetos::core::Result<u32> Ext4Probe(u32 block_handle)
{
    using ::duetos::core::Err;
    using ::duetos::core::ErrorCode;
    if (g_volume_count >= kMaxVolumes)
        return Err{ErrorCode::BadState};
    // Read the 1024-byte superblock. ext4 superblock lives at byte
    // 1024 regardless of block size — LBA 2 on a 512-byte-sector
    // device. We read 2 sectors (1024 bytes) into the static
    // scratch.
    const i32 rc = drivers::storage::BlockDeviceRead(block_handle, kSuperblockLba, 2, g_scratch);
    if (rc < 0)
        return Err{ErrorCode::IoError};
    const u8* sb = g_scratch;

    const u16 magic = LeU16(sb + kSbOffMagic);
    if (magic != kSuperblockMagic)
        return Err{ErrorCode::NotFound};

    Volume& v = g_volumes[g_volume_count];
    ByteZero(&v, sizeof(v));
    v.block_handle = block_handle;
    v.block_size = u32(1024) << LeU32(sb + kSbOffLogBlockSize);
    v.block_count = LeU32(sb + kSbOffBlockCountLo);
    v.inode_count = LeU32(sb + kSbOffInodeCount);
    v.first_data_block = LeU32(sb + kSbOffFirstDataBlock);
    v.blocks_per_group = LeU32(sb + kSbOffBlocksPerGroup);
    v.inodes_per_group = LeU32(sb + kSbOffInodesPerGroup);
    v.rev_level = LeU32(sb + kSbOffRevLevel);
    v.feature_compat = LeU32(sb + kSbOffFeatureCompat);
    v.feature_incompat = LeU32(sb + kSbOffFeatureIncompat);
    v.feature_ro_compat = LeU32(sb + kSbOffFeatureRoCompat);
    // s_inode_size only exists in rev_level >= 1. Rev 0 (ext2)
    // inodes are always 128 bytes.
    v.inode_size = (v.rev_level >= 1) ? LeU16(sb + kSbOffInodeSize) : 128;
    if (v.inode_size == 0)
        v.inode_size = 128;
    for (u32 i = 0; i < 16; ++i)
        v.label[i] = char(sb[kSbOffVolumeName + i]);
    v.label[16] = '\0';

    const u32 idx = g_volume_count++;

    const char* variant = ClassifyExt(v.feature_incompat, v.feature_compat);
    arch::SerialWrite("[ext4] probe OK handle=");
    arch::SerialWriteHex(block_handle);
    arch::SerialWrite(" variant=");
    arch::SerialWrite(variant);
    arch::SerialWrite(" block_size=");
    arch::SerialWriteHex(v.block_size);
    arch::SerialWrite(" label=\"");
    arch::SerialWrite(v.label);
    arch::SerialWrite("\"\n");
    arch::SerialWrite("[ext4]   blocks=");
    arch::SerialWriteHex(v.block_count);
    arch::SerialWrite(" inodes=");
    arch::SerialWriteHex(v.inode_count);
    arch::SerialWrite(" blocks/grp=");
    arch::SerialWriteHex(v.blocks_per_group);
    arch::SerialWrite(" inodes/grp=");
    arch::SerialWriteHex(v.inodes_per_group);
    arch::SerialWrite(" first_data=");
    arch::SerialWriteHex(v.first_data_block);
    arch::SerialWrite(" rev=");
    arch::SerialWriteHex(v.rev_level);
    arch::SerialWrite("\n");
    arch::SerialWrite("[ext4]   feat_compat=");
    arch::SerialWriteHex(v.feature_compat);
    arch::SerialWrite(" feat_incompat=");
    arch::SerialWriteHex(v.feature_incompat);
    arch::SerialWrite(" feat_ro_compat=");
    arch::SerialWriteHex(v.feature_ro_compat);
    arch::SerialWrite(" inode_size=");
    arch::SerialWriteHex(v.inode_size);
    arch::SerialWrite("\n");

    ReadGroup0AndRootInode(v);
    return idx;
}

u32 Ext4VolumeCount()
{
    return g_volume_count;
}

const Volume* Ext4VolumeByIndex(u32 index)
{
    if (index >= g_volume_count)
        return nullptr;
    return &g_volumes[index];
}

void Ext4ScanAll()
{
    KLOG_TRACE_SCOPE("fs/ext4", "Ext4ScanAll");
    const u32 n = drivers::storage::BlockDeviceCount();
    for (u32 i = 0; i < n; ++i)
    {
        // Probe every block device. NotFound is the expected "this
        // isn't an ext4 volume" outcome — silent. IoError or
        // BadState (registry full) bubble up as one-line logs so a
        // failing disk or bumped kMaxVolumes ceiling is visible.
        auto r = Ext4Probe(i);
        if (!r && r.error() != ::duetos::core::ErrorCode::NotFound)
        {
            arch::SerialWrite("[ext4] handle=");
            arch::SerialWriteHex(i);
            arch::SerialWrite(" probe error=");
            arch::SerialWrite(::duetos::core::ErrorCodeName(r.error()));
            arch::SerialWrite("\n");
        }
    }
    core::LogWithValue(core::LogLevel::Info, "fs/ext4", "ext4 volumes found", g_volume_count);
}

} // namespace duetos::fs::ext4
