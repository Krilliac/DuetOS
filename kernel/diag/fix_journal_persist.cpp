#include "diag/fix_journal_persist.h"

#include "arch/x86_64/serial.h"
#include "diag/fix_journal.h"
#include "fs/fat32.h"
#include "log/klog.h"

/*
 * fix journal persistence — FAT32 sink implementation.
 *
 * Strategy: full rewrite per flush. The ring is bounded at
 * kFixJournalCapacity (1024) records of 128 bytes each = 128 KiB
 * max, plus a 16-byte header. Writing the whole snapshot is simple
 * and consistent (no need to track which records were dirty since
 * last flush, no append-vs-update split).
 *
 * Rotation runs only on install. Mid-boot the file is overwritten
 * in place — its size is monotonic in the ring's used slots, never
 * decreases mid-boot, and is bounded above. There's no scenario
 * where a "live cap" rotation would help.
 */

namespace duetos::diag
{

namespace
{

constinit bool g_installed = false;

// Snapshot scratch — kFixJournalCapacity * sizeof(FixRecord) = 128 KiB,
// way too large for a kernel stack. Static .bss is fine: the flush
// path is heartbeat-single-threaded, so there is no contention.
FixRecord g_snapshot_scratch[kFixJournalCapacity] = {};

// File header — 16 bytes, prepended once before the FixRecord
// concatenation. Format documented in fix_journal_persist.h.
struct FixFileHeader
{
    u32 magic;   // kFixFileMagic
    u32 version; // kFixFileVersion
    u32 record_count;
    u32 reserved; // must be zero
};
static_assert(sizeof(FixFileHeader) == 16, "FixFileHeader is part of the on-disk format");

// Build "KERNEL.F<digit>" into `out`. Caller-supplied buffer must
// hold at least 11 bytes ("KERNEL.F" + 1 digit + NUL).
void FormatRotPath(char* out, u32 idx)
{
    out[0] = 'K';
    out[1] = 'E';
    out[2] = 'R';
    out[3] = 'N';
    out[4] = 'E';
    out[5] = 'L';
    out[6] = '.';
    out[7] = 'F';
    out[8] = static_cast<char>('0' + (idx % 10));
    out[9] = '\0';
}

// Promote KERNEL.FIX -> KERNEL.F0, KERNEL.F0 -> KERNEL.F1, ...,
// dropping the oldest. Mirrors RotateLogChain in klog_persist.cpp
// but for the fix-journal chain.
void RotateChain(const fs::fat32::Volume* v)
{
    namespace fat = fs::fat32;

    char dst_path[11];
    char src_path[11];

    // Drop the oldest archive so the next rename can land.
    FormatRotPath(dst_path, kFixRotationDepth - 1);
    fat::DirEntry oldest;
    if (fat::Fat32LookupPath(v, dst_path, &oldest))
    {
        fat::Fat32DeleteAtPath(v, dst_path);
    }

    for (u32 i = kFixRotationDepth - 1; i > 0; --i)
    {
        FormatRotPath(src_path, i - 1);
        FormatRotPath(dst_path, i);
        fat::DirEntry src;
        if (fat::Fat32LookupPath(v, src_path, &src))
        {
            if (!fat::Fat32RenameAtPath(v, src_path, dst_path))
            {
                arch::SerialWrite("[fix-journal-persist] rotate (archive promotion) failed\n");
            }
        }
    }

    // Finally, KERNEL.FIX -> KERNEL.F0.
    FormatRotPath(dst_path, 0);
    fat::DirEntry pre;
    if (fat::Fat32LookupPath(v, kFixJournalPath, &pre))
    {
        if (!fat::Fat32RenameAtPath(v, kFixJournalPath, dst_path))
        {
            arch::SerialWrite("[fix-journal-persist] rotate KERNEL.FIX -> KERNEL.F0 failed; dropping\n");
            fat::Fat32DeleteAtPath(v, kFixJournalPath);
        }
    }
}

// Write the current ring to KERNEL.FIX. Returns true on success.
// On failure, leaves whatever partial state Fat32 left and emits a
// warning — the next flush will retry.
bool WriteRingSnapshot(const fs::fat32::Volume* v)
{
    namespace fat = fs::fat32;

    // Snapshot the ring into a stack buffer. kFixJournalCapacity *
    // sizeof(FixRecord) = 128 KiB which is larger than a typical
    // kernel stack — so we walk in chunks. Each chunk fits within
    // 4 KiB.
    constexpr u64 kChunkRecords = 32; // 32 * 128 = 4 KiB
    FixRecord chunk[kChunkRecords];

    // First a header-only create. If a prior flush left the file
    // around (mid-boot rewrite), delete it first so size is exact.
    fat::DirEntry pre;
    if (fat::Fat32LookupPath(v, kFixJournalPath, &pre))
    {
        fat::Fat32DeleteAtPath(v, kFixJournalPath);
    }

    // Snapshot the entire ring into the static scratch up-front so
    // the header's record_count matches what we're about to write.
    // The snapshot is most-recent-first; we want oldest-first on
    // disk so a streaming reader sees records in seq order.
    const u64 n = FixJournalSnapshot(g_snapshot_scratch, kFixJournalCapacity);

    FixFileHeader hdr = {};
    hdr.magic = kFixFileMagic;
    hdr.version = kFixFileVersion;
    hdr.record_count = static_cast<u32>(n);
    hdr.reserved = 0;

    // Create with header bytes; if this fails the file isn't on
    // disk and the next flush will retry.
    if (fat::Fat32CreateAtPath(v, kFixJournalPath, &hdr, sizeof(hdr)) < 0)
    {
        KLOG_WARN("diag/fix-journal-persist", "create KERNEL.FIX failed");
        return false;
    }

    if (n == 0)
    {
        // Header-only is a valid, empty snapshot.
        return true;
    }

    // Append records oldest-first. all[0] is the most recent;
    // walk it in reverse to land oldest first.
    u64 written = 0;
    while (written < n)
    {
        const u64 remaining = n - written;
        const u64 this_chunk = (remaining > kChunkRecords) ? kChunkRecords : remaining;
        for (u64 i = 0; i < this_chunk; ++i)
        {
            // g_snapshot_scratch[] is most-recent-first. Index
            // `n - 1 - (written + i)` gives oldest-first.
            chunk[i] = g_snapshot_scratch[n - 1 - (written + i)];
        }
        if (fat::Fat32AppendAtPath(v, kFixJournalPath, chunk, this_chunk * sizeof(FixRecord)) < 0)
        {
            KLOG_WARN_V("diag/fix-journal-persist", "append failed at record", written);
            return false;
        }
        written += this_chunk;
    }
    return true;
}

} // namespace

bool FixJournalPersistInstall()
{
    namespace fat = fs::fat32;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        arch::SerialWrite("[fix-journal-persist] no FAT32 volume — skipping\n");
        return false;
    }

    // Age the prior session's file into KERNEL.F0 (and shift the
    // existing archive chain back one slot each). Then write a
    // fresh KERNEL.FIX from the current ring.
    RotateChain(v);

    if (!WriteRingSnapshot(v))
    {
        return false;
    }

    g_installed = true;
    KLOG_INFO("diag/fix-journal-persist", "online — fix journal -> KERNEL.FIX");
    return true;
}

void FixJournalPersistFlush()
{
    if (!g_installed)
    {
        return;
    }
    namespace fat = fs::fat32;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        // FAT32 disappeared. Mark uninstalled so we don't keep
        // hammering a missing volume on every tick.
        g_installed = false;
        KLOG_WARN("diag/fix-journal-persist", "FAT32 volume gone — sink offline");
        return;
    }
    (void)WriteRingSnapshot(v);
}

bool FixJournalPersistInstalled()
{
    return g_installed;
}

void FixJournalPersistSelfTest()
{
    namespace fat = fs::fat32;
    using arch::SerialWrite;

    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        SerialWrite("[fix-journal-persist] self-test SKIP: no FAT32 volume\n");
        return;
    }
    if (!g_installed)
    {
        SerialWrite("[fix-journal-persist] self-test SKIP: not installed\n");
        return;
    }

    // Force a flush so the on-disk file is current.
    FixJournalPersistFlush();

    // Look up the file and read the header back.
    fat::DirEntry e;
    if (!fat::Fat32LookupPath(v, kFixJournalPath, &e))
    {
        SerialWrite("[fix-journal-persist] self-test FAILED (no KERNEL.FIX)\n");
        return;
    }

    FixFileHeader hdr = {};
    const i64 n = fat::Fat32ReadAt(v, &e, 0, &hdr, sizeof(hdr));
    if (n < 0 || static_cast<u64>(n) != sizeof(hdr))
    {
        SerialWrite("[fix-journal-persist] self-test FAILED (header read short)\n");
        return;
    }
    if (hdr.magic != kFixFileMagic)
    {
        SerialWrite("[fix-journal-persist] self-test FAILED (bad magic)\n");
        return;
    }
    if (hdr.version != kFixFileVersion)
    {
        SerialWrite("[fix-journal-persist] self-test FAILED (bad version)\n");
        return;
    }

    // Cross-check record_count against ring snapshot.
    FixRecord scratch[8] = {};
    const u64 ring_n = FixJournalSnapshot(scratch, 8);
    // The selftest may run when the ring already holds more than 8
    // records (slice-1 selftest injects 6, plus whatever else has
    // been recorded by then). The header should reflect the ring's
    // total `records_unique`, which is what FixJournalSnapshot
    // returns up to the cap.
    if (hdr.record_count == 0 && ring_n > 0)
    {
        SerialWrite("[fix-journal-persist] self-test FAILED (header count zero, ring not empty)\n");
        return;
    }

    // Validate the file size matches: header + record_count * 128.
    const u64 expected_size = sizeof(FixFileHeader) + static_cast<u64>(hdr.record_count) * sizeof(FixRecord);
    if (e.size_bytes != expected_size)
    {
        KLOG_ERROR_2V("diag/fix-journal-persist", "self-test FAILED: size mismatch", "expected", expected_size, "got",
                      e.size_bytes);
        return;
    }

    KLOG_INFO_V("smoke", "fix_journal_persist=ok records", static_cast<u64>(hdr.record_count));
}

} // namespace duetos::diag
