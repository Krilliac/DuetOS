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
 * Each boot truncates KERNEL.LOG and starts fresh — there is no
 * cross-boot append yet, so the on-disk file always reflects the
 * current uptime. This is documented as a // GAP; rotation is the
 * follow-up slice.
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

constinit char g_buf[kBufBytes] = {};
constinit u64 g_used = 0;
constinit bool g_installed = false;

// Re-entrancy guard. Set across the FAT32 append; any log call
// emitted from within that window (typically Warn / Error from
// the FAT32 / block layer) is dropped rather than recursed.
constinit bool g_in_flush = false;

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
    fat::Fat32AppendAtPath(v, kLogPath, g_buf, g_used);
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

    // Truncate any prior KERNEL.LOG so each boot starts fresh.
    // GAP: no cross-boot rotation. Each reboot wipes the file.
    // Revisit when log-rotation lands (size-cap + KERNEL.0,
    // KERNEL.1 round-robin).
    fat::DirEntry pre;
    if (fat::Fat32LookupPath(v, kLogPath, &pre))
    {
        fat::Fat32DeleteAtPath(v, kLogPath);
    }

    // The first byte must come from a Create — Fat32AppendAtPath
    // refuses zero-size files in v0. Seed with a header so the
    // file is non-empty before the ring replay runs.
    constexpr const char kHeader[] = "[klog-persist] kernel log started\n";
    constexpr u32 kHeaderLen = sizeof(kHeader) - 1;
    if (fat::Fat32CreateAtPath(v, kLogPath, kHeader, kHeaderLen) < 0)
    {
        arch::SerialWrite("[klog-persist] create KERNEL.LOG failed\n");
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
    SerialWrite(found ? "[klog-persist] self-test OK (marker found in KERNEL.LOG)\n"
                      : "[klog-persist] self-test FAILED (marker missing)\n");
    (void)kMark;
}

} // namespace duetos::core
