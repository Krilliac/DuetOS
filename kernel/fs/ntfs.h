#pragma once

#include "../core/types.h"

/*
 * CustomOS — NTFS driver, v0 probe-only shell.
 *
 * Reads LBA 0 (the boot sector) of a block device and validates
 * the NTFS signature: the ASCII bytes "NTFS    " (NTFS + 4 spaces)
 * at offset 3, and the 0x55AA boot signature at offset 510.
 * Records bytes-per-sector, sectors-per-cluster, and the MFT LCN
 * from the boot sector, then logs the result. No $MFT parse, no
 * file reads.
 *
 * Scope:
 *   - Signature probe + handful of boot-sector fields.
 *
 * Not in scope (future slices):
 *   - $MFT traversal, $INDEX_ROOT parsing, file data attribute read.
 *   - Compressed / sparse / encrypted attribute handling.
 *   - The USN journal / $LogFile.
 *
 * Context: kernel, polling-synchronous block reads only.
 */

namespace customos::fs::ntfs
{

inline constexpr u32 kMaxVolumes = 8;
inline constexpr u64 kBootSectorLba = 0;

struct Volume
{
    u32 block_handle;
    u16 bytes_per_sector;
    u8 sectors_per_cluster;
    u64 total_sectors;
    u64 mft_lcn; // logical cluster number of $MFT
};

bool NtfsProbe(u32 block_handle, u32* out_index);
u32 NtfsVolumeCount();
const Volume* NtfsVolumeByIndex(u32 index);
void NtfsScanAll();

} // namespace customos::fs::ntfs
