#pragma once

#include "util/types.h"

/*
 * fix journal — Tier-2 persistence (FAT32 file).
 *
 * Mirrors the in-RAM `FixRecord` ring to `/KERNEL.FIX` on the FAT32
 * root volume so a reviewer (or a future Claude session) can pull
 * the gaps observed during this boot AND any of the previous N
 * boots from a real filesystem path.
 *
 * The on-disk file is a simple concatenation of `FixRecord`
 * structs in seq order:
 *
 *   [u32 magic 'FIXJ']
 *   [u32 version = 1]
 *   [u32 record_count]
 *   [u32 reserved (must be 0)]
 *   [FixRecord × record_count]
 *
 * Each flush rewrites the file end-to-end (the ring is bounded at
 * `kFixJournalCapacity` records = 128 KiB max, so a full rewrite on
 * the 1 Hz UI tick is well under the FAT32 throughput budget). This
 * keeps repeat_count and audited-bit updates consistent without an
 * append-and-collapse reader.
 *
 * Cross-boot retention: on install, the prior session's KERNEL.FIX
 * ages to KERNEL.F0, the existing archive chain shifts down one
 * slot, and the oldest is dropped (depth = 4). Mid-boot the file
 * never grows past its bound, so no in-session rotation runs.
 *
 * Context: kernel. `FixJournalPersistInstall` MUST run AFTER the
 * FAT32 volume is probed and BEFORE the boot completes.
 */

namespace duetos::diag
{

/// Magic identifying a KERNEL.FIX file. Little-endian 'FIXJ'.
constexpr u32 kFixFileMagic = 0x4A584946;

/// File-format version embedded in the header. Bump when the on-disk
/// FixRecord layout changes (today: v1 == 128-byte stride).
constexpr u32 kFixFileVersion = 1;

/// Path of the live fix-journal file on the FAT32 root.
constexpr const char* kFixJournalPath = "KERNEL.FIX";

/// Number of archived KERNEL.F<i> files retained in addition to
/// the live KERNEL.FIX. Must be <= 9 because the rotation paths
/// only encode a single decimal digit.
constexpr u32 kFixRotationDepth = 4;

/// Install the FAT32 sink. Ages the prior session's KERNEL.FIX into
/// KERNEL.F0 (and shifts the rest of the chain), then writes the
/// current ring to a fresh KERNEL.FIX. Returns true if the sink is
/// live afterwards; false if no FAT32 volume is mounted or the
/// initial write failed. Idempotent — a second call ages the live
/// file again, which is the right behaviour if FAT32 was remounted
/// mid-boot.
bool FixJournalPersistInstall();

/// Rewrite KERNEL.FIX from the current ring snapshot. No-op when
/// the sink isn't installed or the ring is empty. Safe to call on
/// the heartbeat tick.
void FixJournalPersistFlush();

/// True iff the sink is currently installed and pointing at a live
/// FAT32 volume.
bool FixJournalPersistInstalled();

/// Boot self-test: flush, read back, validate header magic and
/// record count match the in-RAM ring. Prints PASS / FAIL / SKIP
/// to COM1. SKIP if no FAT32 mount.
void FixJournalPersistSelfTest();

/// Tier-3: write the live ring to the NVMe fix-journal-reserved
/// LBA region. Safe from panic/trap context — no allocations, no
/// scheduler dependencies, no klog. Same on-disk format as the
/// FAT32 file (16-byte header + FixRecord stream). Cap is 2 MiB
/// (half of the crash-dump reservation); fix-journal payloads are
/// bounded at 128 KiB so this is comfortable.
///
/// Returns true if the write completed; false if NVMe is offline,
/// the reserved region wasn't found, or the chunked write
/// reported a partial completion. The boot log records the
/// outcome via SerialWrite (klog isn't safe at panic).
bool FixJournalPanicWriteToNvme();

} // namespace duetos::diag
