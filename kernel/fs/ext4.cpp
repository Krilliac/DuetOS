/*
 * DuetOS — ext4 read-only filesystem driver: implementation.
 *
 * Byte parsing for the superblock, group descriptor, inode record,
 * extent header / leaf / index, and linux_dirent records lives in
 * Rust (`kernel/fs/ext4_rust`). This C++ TU owns block I/O,
 * scratch buffers, the per-volume registry, the depth>0 extent
 * tree DFS (because it needs to dispatch real block reads against
 * scratch), and logging.
 */

#include "fs/ext4.h"

#include "arch/x86_64/serial.h"
#include "diag/log_names.h"
#include "drivers/storage/block.h"
#include "fs/ext4_rust/include/ext4_rust.h"
#include "log/klog.h"

namespace duetos::fs::ext4
{

namespace
{

using duetos::fs::ext4_rust::DuetosExt4DirEntry;
using duetos::fs::ext4_rust::DuetosExt4Extent;
using duetos::fs::ext4_rust::DuetosExt4ExtentHeader;
using duetos::fs::ext4_rust::DuetosExt4ExtentIndex;
using duetos::fs::ext4_rust::DuetosExt4GroupDesc;
using duetos::fs::ext4_rust::DuetosExt4Inode;
using duetos::fs::ext4_rust::DuetosExt4Superblock;

constinit Volume g_volumes[kMaxVolumes] = {};
u32 g_volume_count = 0;

alignas(16) constinit u8 g_scratch[2048] = {};
alignas(16) constinit u8 g_block_scratch[4096] = {};
alignas(16) constinit u8 g_extent_node_scratch[4096] = {};

constexpr u32 kRootInodeNumber = 2;
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

bool ReadIntoBlockScratch(u32 block_handle, u64 lba, u32 sector_size, u64 bytes)
{
    if (sector_size == 0 || bytes == 0 || bytes > sizeof(g_block_scratch))
        return false;
    const u32 count = u32(bytes / sector_size);
    if (count == 0 || (bytes % sector_size) != 0)
        return false;
    return drivers::storage::BlockDeviceRead(block_handle, lba, count, g_block_scratch) >= 0;
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

// Walk one directory block's linux_dirent records via the Rust
// FFI. Appends entries to `out_entries[]` past `already`.
u32 ParseDirBlock(const u8* block, u32 block_size, Ext4DirEntry* out_entries, u32 cap, u32 already)
{
    u32 produced = already;
    u32 off = 0;
    while (off + 8 <= block_size && produced < cap)
    {
        DuetosExt4DirEntry rec{};
        const u32 consumed = duetos::fs::ext4_rust::duetos_ext4_parse_dirent(block, block_size, off, &rec);
        if (consumed == 0)
            break;
        if (rec.ok != 0)
        {
            Ext4DirEntry& e = out_entries[produced++];
            e.inode = rec.inode;
            e.file_type = rec.file_type;
            const u32 copy = (rec.name_len < sizeof(e.name) - 1) ? u32(rec.name_len) : u32(sizeof(e.name) - 1);
            for (u32 i = 0; i < copy; ++i)
                e.name[i] = char(block[rec.name_offset + i]);
            e.name[copy] = '\0';
        }
        off += consumed;
    }
    return produced;
}

void ProcessLeafExtents(Volume& v, u32 sector_size, const u8* hdr_buf, u32 hdr_buf_len, u16 entries, u32& produced,
                        bool& any_failed)
{
    for (u16 ei = 0; ei < entries && produced < kMaxRootDirEntries; ++ei)
    {
        DuetosExt4Extent ext{};
        if (!duetos::fs::ext4_rust::duetos_ext4_parse_extent_leaf(hdr_buf, hdr_buf_len, ei, &ext))
        {
            any_failed = true;
            break;
        }
        if (ext.length_blocks == 0 || ext.physical_block == 0)
            continue;
        for (u16 bi = 0; bi < ext.length_blocks && produced < kMaxRootDirEntries; ++bi)
        {
            // ext.physical_block is parsed from on-disk data and can lie.
            // Reject any block number that would overflow when scaled to
            // bytes by v.block_size — without this the multiplication
            // wraps u64 and the synthesised lba points somewhere we
            // didn't intend to read from.
            if (v.block_size != 0 && ext.physical_block > (u64(-1) - bi) / v.block_size)
            {
                any_failed = true;
                break;
            }
            const u64 block_phys = ext.physical_block + bi;
            const u64 lba = block_phys * v.block_size / sector_size;
            if (!ReadIntoBlockScratch(v.block_handle, lba, sector_size, v.block_size))
            {
                // Block-layer read of a root-dir data block failed —
                // klog captures the (extent, block-within-extent)
                // pair so a post-mortem can correlate against the
                // storage stack's own diagnostic.
                KLOG_ERROR_2V("fs/ext4", "root-dir data block read failed", "extent", static_cast<u64>(ei), "block",
                              static_cast<u64>(bi));
                any_failed = true;
                break;
            }
            produced = ParseDirBlock(g_block_scratch, v.block_size, v.root_dir_entries, kMaxRootDirEntries, produced);
        }
    }
}

void WalkExtentIndexTree(Volume& v, u32 sector_size, const u8* root_buf, u32 root_buf_len, u16 root_count,
                         u32& produced, u32& leaves_visited, bool& any_failed)
{
    constexpr u32 kMaxExtentNodeVisits = 64;
    u64 stack[kMaxExtentNodeVisits];
    u32 sp = 0;

    auto push = [&](u64 phys) -> bool
    {
        if (phys == 0)
            return true;
        if (sp >= kMaxExtentNodeVisits)
        {
            arch::SerialWrite("[ext4]   extent stack overflow — walk truncated\n");
            any_failed = true;
            return false;
        }
        stack[sp++] = phys;
        return true;
    };

    for (u16 ei = 0; ei < root_count; ++ei)
    {
        DuetosExt4ExtentIndex idx{};
        if (!duetos::fs::ext4_rust::duetos_ext4_parse_extent_index(root_buf, root_buf_len, ei, &idx))
        {
            any_failed = true;
            break;
        }
        if (!push(idx.leaf_block))
            break;
    }

    const u32 count_per_block = u32(v.block_size / sector_size);
    if (count_per_block == 0)
    {
        any_failed = true;
        return;
    }
    const u16 max_records_per_node = u16((v.block_size - 12) / 12);

    u32 visits = 0;
    while (sp > 0 && produced < kMaxRootDirEntries)
    {
        if (visits >= kMaxExtentNodeVisits)
        {
            arch::SerialWrite("[ext4]   extent walk hit visit cap — truncated\n");
            any_failed = true;
            break;
        }
        const u64 phys = stack[--sp];
        ++visits;
        // Same overflow guard as the leaf walker above. `phys` came
        // from a disk-resident extent-index entry — never trust it.
        if (v.block_size != 0 && phys > u64(-1) / v.block_size)
        {
            any_failed = true;
            break;
        }
        const u64 lba = phys * v.block_size / sector_size;
        if (drivers::storage::BlockDeviceRead(v.block_handle, lba, count_per_block, g_extent_node_scratch) < 0)
        {
            arch::SerialWrite("[ext4]   extent node read failed (block=");
            arch::SerialWriteHex(phys);
            arch::SerialWrite(")\n");
            any_failed = true;
            continue;
        }
        DuetosExt4ExtentHeader hdr{};
        if (!duetos::fs::ext4_rust::duetos_ext4_parse_extent_header(g_extent_node_scratch,
                                                                    sizeof(g_extent_node_scratch), &hdr))
        {
            arch::SerialWrite("[ext4]   extent node magic mismatch (block=");
            arch::SerialWriteHex(phys);
            arch::SerialWrite(")\n");
            any_failed = true;
            continue;
        }
        const u16 cap_entries = hdr.entries < max_records_per_node ? hdr.entries : max_records_per_node;

        if (hdr.depth == 0)
        {
            ProcessLeafExtents(v, sector_size, g_extent_node_scratch, sizeof(g_extent_node_scratch), cap_entries,
                               produced, any_failed);
            ++leaves_visited;
        }
        else
        {
            for (u16 ei = 0; ei < cap_entries; ++ei)
            {
                DuetosExt4ExtentIndex idx{};
                if (!duetos::fs::ext4_rust::duetos_ext4_parse_extent_index(g_extent_node_scratch,
                                                                           sizeof(g_extent_node_scratch), ei, &idx))
                {
                    any_failed = true;
                    break;
                }
                if (!push(idx.leaf_block))
                    break;
            }
        }
    }
}

void WalkRootDir(Volume& v)
{
    if (!v.root_inode_valid || !v.root_inode.uses_extents)
        return;
    const u8* ib = v.root_inode.i_block;
    DuetosExt4ExtentHeader hdr{};
    if (!duetos::fs::ext4_rust::duetos_ext4_parse_extent_header(ib, 60, &hdr))
    {
        arch::SerialWrite("[ext4]   root-dir extent header magic mismatch\n");
        return;
    }
    if (hdr.entries == 0 || hdr.max == 0)
        return;

    const u32 sector_size = drivers::storage::BlockDeviceSectorSize(v.block_handle);
    if (sector_size == 0 || v.block_size == 0 || (v.block_size % sector_size) != 0)
        return;

    constexpr u16 kInlineMaxRecords = 4;
    const u16 root_count = hdr.entries < kInlineMaxRecords ? hdr.entries : kInlineMaxRecords;

    v.root_dir_entry_count = 0;
    u32 produced = 0;
    u32 leaves_visited = 0;
    bool any_block_failed = false;

    if (hdr.depth == 0)
    {
        ProcessLeafExtents(v, sector_size, ib, 60, root_count, produced, any_block_failed);
        leaves_visited = root_count;
    }
    else
    {
        WalkExtentIndexTree(v, sector_size, ib, 60, root_count, produced, leaves_visited, any_block_failed);
    }

    v.root_dir_entry_count = produced;

    arch::SerialWrite("[ext4]   root-dir entries: ");
    arch::SerialWriteHex(v.root_dir_entry_count);
    arch::SerialWrite(hdr.depth == 0 ? " (extents=" : " (depth=");
    if (hdr.depth == 0)
        arch::SerialWriteHex(leaves_visited);
    else
    {
        arch::SerialWriteHex(hdr.depth);
        arch::SerialWrite(" leaves=");
        arch::SerialWriteHex(leaves_visited);
    }
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

void ReadGroup0AndRootInode(Volume& v)
{
    const u32 sector_size = drivers::storage::BlockDeviceSectorSize(v.block_handle);
    if (sector_size == 0 || v.block_size == 0)
        return;

    const u64 gdt_block = u64(v.first_data_block) + 1;
    const u64 gdt_lba = gdt_block * v.block_size / sector_size;
    if (!ReadIntoBlockScratch(v.block_handle, gdt_lba, sector_size, v.block_size))
    {
        arch::SerialWrite("[ext4]   gdt read failed\n");
        return;
    }
    DuetosExt4GroupDesc gd{};
    if (!duetos::fs::ext4_rust::duetos_ext4_parse_group_desc0(g_block_scratch, sizeof(g_block_scratch), &gd))
        return;
    v.group0_valid = true;
    v.group0.block_bitmap_block = gd.block_bitmap_block;
    v.group0.inode_bitmap_block = gd.inode_bitmap_block;
    v.group0.inode_table_block = gd.inode_table_block;
    v.group0.free_blocks_count = gd.free_blocks_count;
    v.group0.free_inodes_count = gd.free_inodes_count;
    v.group0.used_dirs_count = gd.used_dirs_count;

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

    if (v.inode_size == 0 || v.inodes_per_group == 0)
        return;
    const u32 index_in_group = (kRootInodeNumber - 1) % v.inodes_per_group;
    const u64 byte_offset_in_table = u64(index_in_group) * v.inode_size;
    const u64 inode_table_lba = u64(v.group0.inode_table_block) * v.block_size / sector_size;
    if (!ReadIntoBlockScratch(v.block_handle, inode_table_lba, sector_size, v.block_size))
    {
        arch::SerialWrite("[ext4]   inode-table read failed\n");
        return;
    }
    if (byte_offset_in_table + v.inode_size > v.block_size)
    {
        arch::SerialWrite("[ext4]   root inode outside first block (inode_size skew)\n");
        return;
    }
    DuetosExt4Inode ino{};
    if (!duetos::fs::ext4_rust::duetos_ext4_parse_inode(g_block_scratch + byte_offset_in_table,
                                                        v.block_size - byte_offset_in_table, v.inode_size,
                                                        v.feature_ro_compat, &ino))
        return;
    v.root_inode_valid = true;
    v.root_inode.mode = ino.mode;
    v.root_inode.uid = ino.uid;
    v.root_inode.size_bytes = ino.size_bytes;
    v.root_inode.atime = ino.atime;
    v.root_inode.ctime = ino.ctime;
    v.root_inode.mtime = ino.mtime;
    v.root_inode.gid = ino.gid;
    v.root_inode.links_count = ino.links_count;
    v.root_inode.blocks_lo = ino.blocks_lo;
    v.root_inode.flags = ino.flags;
    v.root_inode.uses_extents = ino.uses_extents != 0;
    v.root_inode.block0_magic = ino.block0_magic;
    for (u32 i = 0; i < 60; ++i)
        v.root_inode.i_block[i] = ino.i_block[i];

    arch::SerialWrite("[ext4]   root_inode mode=");
    arch::SerialWriteHex(v.root_inode.mode);
    ::duetos::core::SerialWriteInodeMode(v.root_inode.mode);
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
        arch::SerialWrite(v.root_inode.block0_magic == 0xF30A ? " (valid)" : " (unexpected)");
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
    if (block_handle >= drivers::storage::BlockDeviceCount())
        return Err{ErrorCode::InvalidArgument};
    // Read enough to cover offset 1024 + 1024-byte superblock = 2048
    // bytes, which is exactly our scratch.
    const i32 rc = drivers::storage::BlockDeviceRead(block_handle, 0, 4, g_scratch);
    if (rc < 0)
        return Err{ErrorCode::IoError};

    DuetosExt4Superblock sb{};
    if (!duetos::fs::ext4_rust::duetos_ext4_parse_superblock(g_scratch, sizeof(g_scratch), &sb))
        return Err{ErrorCode::NotFound};
    if (sb.ok == 0)
        return Err{ErrorCode::NotFound};

    Volume& v = g_volumes[g_volume_count];
    ByteZero(&v, sizeof(v));
    v.block_handle = block_handle;
    v.block_size = u32(1024) << sb.log_block_size;
    v.block_count = sb.blocks_count_lo;
    v.inode_count = sb.inodes_count;
    v.first_data_block = sb.first_data_block;
    v.blocks_per_group = sb.blocks_per_group;
    v.inodes_per_group = sb.inodes_per_group;
    v.rev_level = sb.rev_level;
    v.feature_compat = sb.feature_compat;
    v.feature_incompat = sb.feature_incompat;
    v.feature_ro_compat = sb.feature_ro_compat;
    v.inode_size = sb.inode_size;
    for (u32 i = 0; i < 16; ++i)
        v.label[i] = char(sb.volume_name[i]);
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

const Volume* Ext4VolumeByHandle(u32 block_handle)
{
    for (u32 i = 0; i < g_volume_count; ++i)
    {
        if (g_volumes[i].block_handle == block_handle)
            return &g_volumes[i];
    }
    return nullptr;
}

namespace
{

// Compare a NUL-terminated `a` against `b` (also NUL-terminated).
bool StrEq(const char* a, const char* b)
{
    u32 i = 0;
    while (a[i] != '\0' && b[i] != '\0')
    {
        if (a[i] != b[i])
            return false;
        ++i;
    }
    return a[i] == b[i];
}

// Copy a parsed Rust inode record into our InodeInfo POD.
void CopyInode(const DuetosExt4Inode& ino, InodeInfo& out)
{
    out.mode = ino.mode;
    out.uid = ino.uid;
    out.size_bytes = ino.size_bytes;
    out.atime = ino.atime;
    out.ctime = ino.ctime;
    out.mtime = ino.mtime;
    out.gid = ino.gid;
    out.links_count = ino.links_count;
    out.blocks_lo = ino.blocks_lo;
    out.flags = ino.flags;
    out.uses_extents = ino.uses_extents != 0;
    out.block0_magic = ino.block0_magic;
    for (u32 i = 0; i < 60; ++i)
        out.i_block[i] = ino.i_block[i];
}

// Translate a file-logical block index to its physical FS block via
// the inode's depth-0 extent tree (the i_block[60] inline header).
// Returns true and sets `*phys` when `logical` falls inside a leaf
// extent; returns false for a hole / out-of-range / depth>0 tree.
bool MapLogicalBlockInline(const InodeInfo& inode, u32 logical, u64& phys)
{
    using namespace duetos::fs::ext4_rust;
    DuetosExt4ExtentHeader hdr{};
    if (!duetos_ext4_parse_extent_header(inode.i_block, 60, &hdr))
        return false;
    if (hdr.depth != 0)
        return false; // GAP: depth>0 file extent tree — see Ext4ReadFile doc.
    constexpr u16 kInlineMaxRecords = 4;
    const u16 count = hdr.entries < kInlineMaxRecords ? hdr.entries : kInlineMaxRecords;
    for (u16 ei = 0; ei < count; ++ei)
    {
        DuetosExt4Extent ext{};
        if (!duetos_ext4_parse_extent_leaf(inode.i_block, 60, ei, &ext))
            return false;
        if (ext.length_blocks == 0)
            continue;
        if (logical >= ext.logical_block && logical < u32(ext.logical_block + ext.length_blocks))
        {
            phys = ext.physical_block + (logical - ext.logical_block);
            return true;
        }
    }
    return false;
}

} // namespace

::duetos::core::Result<void> Ext4ReadInode(const Volume& v, u32 ino_num, InodeInfo* out)
{
    using ::duetos::core::Err;
    using ::duetos::core::ErrorCode;
    if (out == nullptr || ino_num == 0 || ino_num > v.inode_count)
        return Err{ErrorCode::NotFound};
    if (v.inode_size == 0 || v.inodes_per_group == 0 || v.block_size == 0)
        return Err{ErrorCode::InvalidArgument};

    const u32 sector_size = drivers::storage::BlockDeviceSectorSize(v.block_handle);
    if (sector_size == 0 || (v.block_size % sector_size) != 0)
        return Err{ErrorCode::InvalidArgument};

    const u32 group = (ino_num - 1) / v.inodes_per_group;
    const u32 index_in_group = (ino_num - 1) % v.inodes_per_group;

    // Locate the group's inode-table block. Group 0's descriptor is
    // already cached; for other groups, read its 32-byte classic
    // descriptor from the GDT (block first_data_block + 1).
    u32 inode_table_block = 0;
    if (group == 0)
    {
        if (!v.group0_valid)
            return Err{ErrorCode::BadState};
        inode_table_block = v.group0.inode_table_block;
    }
    else
    {
        const u64 gdt_block = u64(v.first_data_block) + 1;
        const u64 gdt_lba = gdt_block * v.block_size / sector_size;
        if (!ReadIntoBlockScratch(v.block_handle, gdt_lba, sector_size, v.block_size))
            return Err{ErrorCode::IoError};
        // Each classic group descriptor is 32 bytes; descriptor N
        // sits at byte 32*N within the GDT block.
        // GAP: 64bit feature (64-byte descriptors / multi-block GDT)
        //   is not handled — single-block, 32-byte descriptors only.
        const u32 desc_off = group * 32;
        if (desc_off + 32 > v.block_size)
            return Err{ErrorCode::InvalidArgument};
        DuetosExt4GroupDesc gd{};
        if (!duetos::fs::ext4_rust::duetos_ext4_parse_group_desc0(g_block_scratch + desc_off, v.block_size - desc_off,
                                                                  &gd))
            return Err{ErrorCode::BadState};
        inode_table_block = gd.inode_table_block;
    }

    const u64 byte_offset_in_table = u64(index_in_group) * v.inode_size;
    const u64 block_within_table = byte_offset_in_table / v.block_size;
    const u32 offset_in_block = u32(byte_offset_in_table % v.block_size);
    // GAP: inode record straddling a block boundary — see header doc.
    if (offset_in_block + v.inode_size > v.block_size)
        return Err{ErrorCode::InvalidArgument};

    const u64 table_block_phys = u64(inode_table_block) + block_within_table;
    const u64 lba = table_block_phys * v.block_size / sector_size;
    if (!ReadIntoBlockScratch(v.block_handle, lba, sector_size, v.block_size))
        return Err{ErrorCode::IoError};

    DuetosExt4Inode ino{};
    if (!duetos::fs::ext4_rust::duetos_ext4_parse_inode(
            g_block_scratch + offset_in_block, v.block_size - offset_in_block, v.inode_size, v.feature_ro_compat, &ino))
        return Err{ErrorCode::BadState};
    CopyInode(ino, *out);
    return {};
}

::duetos::core::Result<void> Ext4FindInRoot(const Volume& v, const char* name, Ext4DirEntry* out)
{
    using ::duetos::core::Err;
    using ::duetos::core::ErrorCode;
    if (name == nullptr || out == nullptr)
        return Err{ErrorCode::InvalidArgument};
    for (u32 i = 0; i < v.root_dir_entry_count; ++i)
    {
        const Ext4DirEntry& e = v.root_dir_entries[i];
        if (StrEq(e.name, name))
        {
            *out = e;
            return {};
        }
    }
    return Err{ErrorCode::NotFound};
}

::duetos::core::Result<void> Ext4ReadFile(const Volume& v, const InodeInfo& inode, u64 offset, void* buf, u64 len,
                                          u64* out_read)
{
    using ::duetos::core::Err;
    using ::duetos::core::ErrorCode;
    if (buf == nullptr || out_read == nullptr)
        return Err{ErrorCode::InvalidArgument};
    *out_read = 0;
    if (!inode.uses_extents)
        return Err{ErrorCode::InvalidArgument}; // GAP: classic block maps — see header doc.
    if (v.block_size == 0)
        return Err{ErrorCode::InvalidArgument};

    const u32 sector_size = drivers::storage::BlockDeviceSectorSize(v.block_handle);
    if (sector_size == 0 || (v.block_size % sector_size) != 0)
        return Err{ErrorCode::InvalidArgument};
    const u32 count_per_block = v.block_size / sector_size;

    if (offset >= inode.size_bytes)
        return {}; // EOF — zero bytes read.
    u64 remaining = inode.size_bytes - offset;
    if (len < remaining)
        remaining = len;

    auto* dst = static_cast<u8*>(buf);
    u64 produced = 0;
    while (produced < remaining)
    {
        const u64 file_pos = offset + produced;
        const u32 logical = u32(file_pos / v.block_size);
        const u32 in_block = u32(file_pos % v.block_size);

        u64 phys = 0;
        if (!MapLogicalBlockInline(inode, logical, phys))
        {
            // Hole or unmapped logical block: ext4 reads holes as
            // zeroes. Fill the rest of this block with zero.
            const u32 chunk_max = v.block_size - in_block;
            u64 chunk = remaining - produced;
            if (chunk > chunk_max)
                chunk = chunk_max;
            for (u64 i = 0; i < chunk; ++i)
                dst[produced + i] = 0;
            produced += chunk;
            continue;
        }
        // Overflow guard: phys came from on-disk extent data.
        if (phys > u64(-1) / v.block_size)
            return Err{ErrorCode::IoError};
        const u64 lba = phys * v.block_size / sector_size;
        if (drivers::storage::BlockDeviceRead(v.block_handle, lba, count_per_block, g_block_scratch) < 0)
            return Err{ErrorCode::IoError};

        const u32 chunk_max = v.block_size - in_block;
        u64 chunk = remaining - produced;
        if (chunk > chunk_max)
            chunk = chunk_max;
        for (u64 i = 0; i < chunk; ++i)
            dst[produced + i] = g_block_scratch[in_block + i];
        produced += chunk;
    }
    *out_read = produced;
    return {};
}

void Ext4ScanAll()
{
    KLOG_TRACE_SCOPE("fs/ext4", "Ext4ScanAll");
    const u32 n = drivers::storage::BlockDeviceCount();
    for (u32 i = 0; i < n; ++i)
    {
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
