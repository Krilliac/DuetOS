#pragma once

#include "../core/types.h"

/*
 * CustomOS — exFAT driver, v0 probe-only shell.
 *
 * exFAT boot sector (sector 0) signature is "EXFAT   " (EXFAT +
 * 3 spaces) at offset 3. Unlike FAT32 and NTFS, exFAT uses a
 * much simpler boot record layout but still shares the 0x55AA
 * boot signature at offset 510.
 *
 * Recognised fields: partition offset (bytes), volume length
 * (sectors), FAT offset + length, cluster heap offset, cluster
 * count, first-cluster of root dir.
 *
 * Scope: signature probe + boot-sector record. No directory
 * traversal, no file reads. Used for removable-storage
 * interoperability (USB flash drives formatted as exFAT).
 *
 * Context: kernel, polling synchronous.
 */

namespace customos::fs::exfat
{

inline constexpr u32 kMaxVolumes = 8;
inline constexpr u64 kBootSectorLba = 0;

struct Volume
{
    u32 block_handle;
    u64 partition_offset_bytes;
    u64 volume_length_sectors;
    u32 fat_offset_sectors;
    u32 cluster_heap_offset_sectors;
    u32 cluster_count;
    u32 first_cluster_of_root;
    u8 bytes_per_sector_shift;    // log2
    u8 sectors_per_cluster_shift; // log2
};

bool ExfatProbe(u32 block_handle, u32* out_index);
u32 ExfatVolumeCount();
const Volume* ExfatVolumeByIndex(u32 index);
void ExfatScanAll();

} // namespace customos::fs::exfat
