#include "log/klog_persist.h"

#include "arch/x86_64/serial.h"
#include "fs/fat32.h"
#include "log/klog.h"

/*
 * klog persistence layer — FAT32-backed file sink.
 *
 * Wires duetos::core::SetLogFileSink with a writer that buffers
 * chunks in a 4 KiB scratch and flushes to KERNEL.LOG on the
 * FAT32 root volume. The previous tmpfs-backed sink is replaced
 * (single-slot API); the early-boot lines that already landed in
 * /tmp/boot.log stay there.
 *
 * Re-entrancy: Fat32AppendAtPath internally emits Trace-level log
 * lines via KLOG_TRACE_SCOPE. The default file-sink min-level is
 * Info, so those Trace lines are filtered out before reaching us
 * — but a g_in_flush guard catches anything that does sneak
 * through (Warn / Error from inside the FAT32 path), dropping
 * those lines rather than recursing.
 *
 * Rotation policy (kRotationDepth == 4):
 *   - On install, the prior session's KERNEL.LOG ages to KERNEL.0,
 *     KERNEL.0 → KERNEL.1, ..., KERNEL.<N-2> → KERNEL.<N-1>, oldest
 *     dropped. Gives the user N+1 boots of history (current + N
 *     archived).
 *   - During a boot, if KERNEL.LOG would grow past kLogSizeCap on
 *     the next flush, the same rotation runs mid-boot. Bounds the
 *     on-disk footprint at roughly kLogSizeCap × (N+1).
 *   - With kLogSizeCap = 256 KiB and N = 4 the budget is ~1.25 MiB
 *     of historical klog on the root partition.
 *
 * Context: kernel. KlogPersistInstall MUST run AFTER the FAT32
 * volume is probed and BEFORE the boot completes (otherwise the
 * ring replay loses the early lines).
 */

namespace duetos::core
{

namespace
{

constexpr u64 kBufBytes = 4096;
constexpr const char kLogPath[] = "KERNEL.LOG";

// Rotation depth — number of archived KERNEL.<i> files kept
// alongside the live KERNEL.LOG. Capped at 10 because the path
// templates below assume a single decimal digit (KERNEL.0..9).
constexpr u32 kRotationDepth = 4;

// Size cap before mid-boot rotation kicks in. 256 KiB matches a
// few thousand log lines at the typical ~80-byte format, which
// covers a long-running session without unbounded growth.
constexpr u64 kLogSizeCap = 256 * 1024;

// Live size estimate — bumped after every successful append,
// reset to 0 on rotation. Avoids a Fat32LookupPath on every
// FlushToFat32 call. Seeded from the on-disk size at install
// time so the cap is honoured even on very long boots.
constinit u64 g_log_size = 0;

constinit char g_buf[kBufBytes] = {};
constinit u64 g_used = 0;
constinit bool g_installed = false;

// Re-entrancy guard. Set across the FAT32 append; any log call
// emitted from within that window (typically Warn / Error from
// the FAT32 / block layer) is dropped rather than recursed.
constinit bool g_in_flush = false;

// Build "KERNEL.<digit>" into `out`. Caller-supplied buffer
// must hold at least 10 bytes ("KERNEL." + 1 digit + NUL).
void FormatRotPath(char* out, u32 idx)
{
    out[0] = 'K';
    out[1] = 'E';
    out[2] = 'R';
    out[3] = 'N';
    out[4] = 'E';
    out[5] = 'L';
    out[6] = '.';
    out[7] = static_cast<char>('0' + (idx % 10));
    out[8] = '\0';
}

// Promote KERNEL.LOG -> KERNEL.0, KERNEL.0 -> KERNEL.1, ...,
// dropping the oldest. Leaves no live KERNEL.LOG behind — the
// caller is responsible for creating the next one (with a fresh
// header, since Fat32AppendAtPath refuses zero-size files).
//
// On rename failure the function falls through to the next
// promotion: a stale KERNEL.<i+1> staying in place is harmless,
// and the source file isn't lost — it just doesn't age.
void RotateLogChain(const fs::fat32::Volume* v)
{
    namespace fat = fs::fat32;
    char rot_path[10];
    char src_path[10];

    // Drop the oldest archived file so the next rename can land.
    FormatRotPath(rot_path, kRotationDepth - 1);
    fat::DirEntry oldest;
    if (fat::Fat32LookupPath(v, rot_path, &oldest))
    {
        fat::Fat32DeleteAtPath(v, rot_path);
    }

    // Promote KERNEL.<N-2> -> KERNEL.<N-1>, ..., KERNEL.0 -> KERNEL.1.
    // Walking down so each destination is empty when its source
    // arrives.
    for (u32 i = kRotationDepth - 1; i > 0; --i)
    {
        FormatRotPath(src_path, i - 1);
        FormatRotPath(rot_path, i);
        fat::DirEntry src;
        if (fat::Fat32LookupPath(v, src_path, &src))
        {
            if (!fat::Fat32RenameAtPath(v, src_path, rot_path))
            {
                arch::SerialWrite("[klog-persist] rotate (archive promotion) failed\n");
            }
        }
    }

    // Finally, KERNEL.LOG -> KERNEL.0.
    FormatRotPath(rot_path, 0);
    fat::DirEntry pre;
    if (fat::Fat32LookupPath(v, kLogPath, &pre))
    {
        if (!fat::Fat32RenameAtPath(v, kLogPath, rot_path))
        {
            arch::SerialWrite("[klog-persist] rotate KERNEL.LOG -> KERNEL.0 failed; dropping\n");
            fat::Fat32DeleteAtPath(v, kLogPath);
        }
    }
}

// Create a fresh KERNEL.LOG with a single header line so the
// next append has somewhere to land. Returns the seeded byte
// count for g_log_size. Returns 0 on failure (caller treats as
// "no live log file"; subsequent appends will retry-via-create
// inside Fat32AppendAtPath).
u64 SeedFreshLog(const fs::fat32::Volume* v)
{
    namespace fat = fs::fat32;
    constexpr const char kHeader[] = "[klog-persist] kernel log started\n";
    constexpr u32 kHeaderLen = sizeof(kHeader) - 1;
    if (fat::Fat32CreateAtPath(v, kLogPath, kHeader, kHeaderLen) < 0)
    {
        arch::SerialWrite("[klog-persist] create KERNEL.LOG failed\n");
        return 0;
    }
    return kHeaderLen;
}

void FlushToFat32()
{
    if (g_in_flush || !g_installed || g_used == 0)
    {
        return;
    }
    namespace fat = fs::fat32;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        // FAT32 disappeared (block-device error); drop the
        // accumulated bytes rather than spinning.
        g_used = 0;
        return;
    }
    g_in_flush = true;

    // If this flush would push the live log past its cap, rotate
    // first so the bytes land in a fresh file. Idempotent: a
    // single g_used worth always fits because g_used <= kBufBytes
    // < kLogSizeCap.
    if (g_log_size + g_used > kLogSizeCap)
    {
        RotateLogChain(v);
        g_log_size = SeedFreshLog(v);
    }

    fat::Fat32AppendAtPath(v, kLogPath, g_buf, g_used);
    g_log_size += g_used;
    g_used = 0;
    g_in_flush = false;
}

void FileSink(const char* s)
{
    if (g_in_flush || !g_installed || s == nullptr)
    {
        return;
    }
    while (*s != 0)
    {
        const char c = *s++;
        if (g_used >= kBufBytes)
        {
            FlushToFat32();
            // Flush may bail (no FAT32). If g_used is still at
            // the cap, we have to drop further bytes to keep the
            // buffer well-defined.
            if (g_used >= kBufBytes)
            {
                return;
            }
        }
        g_buf[g_used++] = c;
        // Half-buffer threshold lines flush opportunistically:
        // a steady log stream is flushed in chunks rather than
        // one line per FAT32 op (which would wear the FAT
        // mirror unnecessarily).
        if (c == '\n' && g_used >= kBufBytes / 2)
        {
            FlushToFat32();
        }
    }
}

} // namespace

bool KlogPersistInstall()
{
    namespace fat = fs::fat32;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        arch::SerialWrite("[klog-persist] no FAT32 volume — skipping\n");
        return false;
    }

    // Age the prior session's KERNEL.LOG into KERNEL.0 (and the
    // existing archive chain back one slot each), then create a
    // fresh KERNEL.LOG for the current boot. The rotation is
    // bounded — kRotationDepth back-files are kept; older ones
    // are dropped.
    RotateLogChain(v);
    g_log_size = SeedFreshLog(v);
    if (g_log_size == 0)
    {
        return false;
    }

    g_installed = true;
    g_used = 0;
    SetLogFileSink(FileSink);
    // The SetLogFileSink call above replays the ring through
    // FileSink; flush whatever it accumulated so the on-disk
    // file is current before this function returns.
    FlushToFat32();
    arch::SerialWrite("[klog-persist] online — log -> KERNEL.LOG\n");
    return true;
}

void KlogPersistFlush()
{
    FlushToFat32();
}

bool KlogPersistInstalled()
{
    return g_installed;
}

void KlogPersistSelfTest()
{
    namespace fat = fs::fat32;
    using arch::SerialWrite;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        SerialWrite("[klog-persist] self-test SKIP: no FAT32 volume\n");
        return;
    }
    if (!g_installed)
    {
        SerialWrite("[klog-persist] self-test SKIP: not installed\n");
        return;
    }
    // Emit a known marker, force a flush, read back a window
    // around the expected on-disk position, and confirm the
    // marker bytes are present.
    constexpr const char kMark[] = "[klog-persist] self-test marker\n";
    KLOG_INFO("klog-persist", "self-test marker");
    KlogPersistFlush();
    fat::DirEntry e;
    if (!fat::Fat32LookupPath(v, kLogPath, &e))
    {
        SerialWrite("[klog-persist] self-test FAILED (no KERNEL.LOG)\n");
        return;
    }
    // Read the tail of the file (last 256 bytes) and search
    // for "self-test marker" — the formatted log line carries
    // a timestamp prefix, but the message tail is stable.
    constexpr u64 kTail = 256;
    const u64 size = e.size_bytes;
    const u64 off = (size > kTail) ? (size - kTail) : 0;
    const u64 want = (size > kTail) ? kTail : size;
    char buf[kTail];
    const i64 n = fat::Fat32ReadAt(v, &e, off, buf, want);
    if (n < 0)
    {
        SerialWrite("[klog-persist] self-test FAILED (read error)\n");
        return;
    }
    constexpr const char kNeedle[] = "self-test marker";
    constexpr u64 kNeedleLen = sizeof(kNeedle) - 1;
    bool found = false;
    if (static_cast<u64>(n) >= kNeedleLen)
    {
        for (u64 i = 0; i + kNeedleLen <= static_cast<u64>(n); ++i)
        {
            bool match = true;
            for (u64 k = 0; k < kNeedleLen; ++k)
            {
                if (buf[i + k] != kNeedle[k])
                {
                    match = false;
                    break;
                }
            }
            if (match)
            {
                found = true;
                break;
            }
        }
    }
    if (!found)
    {
        SerialWrite("[klog-persist] self-test FAILED (marker missing)\n");
        (void)kMark;
        return;
    }

    // Rotation sub-check: exercise RotateLogChain in a way that
    // doesn't touch KERNEL.LOG. We seed a small KERNEL.<N-1>
    // file (the slot the chain drops on the next rotation),
    // call the rotation, and assert that file is gone. The live
    // KERNEL.LOG / KERNEL.0..<N-2> are unaffected because each
    // promotion only acts when its source exists. Cleaning up
    // afterwards keeps the test side-effect-free.
    char tail_path[10];
    FormatRotPath(tail_path, kRotationDepth - 1);
    constexpr const char kProbe[] = "klog-rotate-probe\n";
    constexpr u32 kProbeLen = sizeof(kProbe) - 1;
    fat::DirEntry probe_pre;
    const bool tail_pre_existed = fat::Fat32LookupPath(v, tail_path, &probe_pre);
    if (tail_pre_existed)
    {
        // Don't trample whatever the live archive chain holds in
        // its oldest slot.
        SerialWrite("[klog-persist] self-test OK (marker + rotation skipped: tail occupied)\n");
        (void)kMark;
        return;
    }
    if (fat::Fat32CreateAtPath(v, tail_path, kProbe, kProbeLen) < 0)
    {
        SerialWrite("[klog-persist] self-test FAILED (rotation probe create error)\n");
        (void)kMark;
        return;
    }
    RotateLogChain(v);
    fat::DirEntry probe_post;
    const bool tail_dropped = !fat::Fat32LookupPath(v, tail_path, &probe_post);
    // RotateLogChain also moved KERNEL.LOG -> KERNEL.0; restore
    // the live log so the rest of the boot keeps appending where
    // we left off. SeedFreshLog isn't enough on its own — the
    // operator's KERNEL.LOG is now in KERNEL.0, so we age it back
    // by promoting (KERNEL.0 -> KERNEL.LOG) via rename.
    char zero_path[10];
    FormatRotPath(zero_path, 0);
    fat::DirEntry zero_post;
    if (fat::Fat32LookupPath(v, zero_path, &zero_post))
    {
        // Drop the freshly-created KERNEL.LOG (header-only) so the
        // rename below has a free slot, then move KERNEL.0 back.
        fat::DirEntry live_post;
        if (fat::Fat32LookupPath(v, kLogPath, &live_post))
        {
            fat::Fat32DeleteAtPath(v, kLogPath);
        }
        fat::Fat32RenameAtPath(v, zero_path, kLogPath);
    }
    // Re-seed g_log_size from the now-restored KERNEL.LOG.
    fat::DirEntry live_e;
    g_log_size = fat::Fat32LookupPath(v, kLogPath, &live_e) ? live_e.size_bytes : 0;

    SerialWrite(tail_dropped ? "[klog-persist] self-test OK (marker + rotation drops oldest)\n"
                             : "[klog-persist] self-test FAILED (rotation did not drop oldest archive)\n");
    (void)kMark;
}

} // namespace duetos::core
