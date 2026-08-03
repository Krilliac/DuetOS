#include "log/klog_persist.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/timer.h"
#include "fs/fat32.h"
#include "log/klog.h"
#include "time/timekeeper.h"

/*
 * klog persistence layer — per-area FAT32-backed log files.
 *
 * Wires duetos::core::SetLogLineSink with a router that picks the
 * destination file from the line's LogArea: NET.LOG for networking
 * lines, USB.LOG for USB lines, FS.LOG for filesystem lines, etc.
 * The prior single-file design (`KERNEL.LOG`) had every subsystem
 * flooding into one aggregate; this layer fans each subsystem out
 * to its own log so an operator can pull the chatter for a single
 * area without grepping through everything else.
 *
 * `KERNEL.LOG` is kept as the file for `LogArea::General` — lines
 * whose subsystem prefix didn't map to any specific area still
 * land in the legacy aggregate, preserving `dmesg f` semantics and
 * giving us a catch-all bucket.
 *
 * Re-entrancy: Fat32AppendAtPath internally emits Trace-level log
 * lines via KLOG_TRACE_SCOPE. The default line-sink min-level is
 * Info, so those Trace lines are filtered out before reaching us
 * — but a g_in_flush guard catches anything that does sneak
 * through (Warn / Error from inside the FAT32 path), dropping
 * those lines rather than recursing.
 *
 * Rotation policy (kRotationDepth == 4) — applied independently
 * per area:
 *   - On install, the prior session's <AREA>.LOG ages to <AREA>.0,
 *     <AREA>.0 → <AREA>.1, ..., oldest dropped. Gives the user
 *     N+1 boots of history per subsystem (current + N archived).
 *   - During a boot, if a single <AREA>.LOG would grow past
 *     kLogSizeCap on the next flush, the same rotation runs for
 *     that area only. Bounds the on-disk footprint per area at
 *     roughly kLogSizeCap × (N+1).
 *   - With kLogSizeCap = 256 KiB and N = 4 the budget is ~1.25
 *     MiB per area; ~30 areas × ~1.25 MiB ≈ 38 MiB worst-case if
 *     every area maxes out (unlikely — most areas log far less
 *     than the cap per boot).
 *
 * Per-area state is allocated statically (~17 KiB total — 32
 * slots indexed by `LogArea` bit position) and seeded lazily on
 * first line so we don't create empty files for areas that never
 * log this boot.
 *
 * Context: kernel. KlogPersistInstall MUST run AFTER the FAT32
 * volume is probed and BEFORE the boot completes (otherwise the
 * ring replay loses the early lines).
 */

namespace duetos::core
{

namespace
{

// Size cap before per-area mid-boot rotation kicks in. 256 KiB
// matches a few thousand log lines at the typical ~80-byte format
// without unbounded growth.
constexpr u64 kLogSizeCap = 256 * 1024;

// Rotation depth — number of archived <AREA>.<i> files kept
// alongside the live <AREA>.LOG. Capped at 10 because the path
// templates below assume a single decimal digit.
constexpr u32 kRotationDepth = 4;

// Per-area write buffer size. 512 bytes coalesces a few log lines
// before each FAT32 append so we don't pay one cluster-write per
// log line; flushes opportunistically on '\n' once half-full, and
// on the external 1 Hz timer. Long lines (>512B) flush as soon as
// the buffer fills.
// Sized for the async design: the sink only ever buffers (no inline
// filesystem I/O), and the UiTicker flusher drains once per second —
// so each area buffer must absorb a full second of Info+ lines from a
// bursty subsystem. 512 bytes forced mid-line synchronous flushes;
// 4 KiB × 32 areas costs 128 KiB of .bss and rides out real bursts.
constexpr u64 kAreaBufBytes = 4096;

// FAT32 8.3 path: 8-char base + '.' + 3-char extension + NUL = 13.
// Plus one for safety. Each per-area entry stores both the live
// path (`<BASE>.LOG`) and base for rotation suffix construction.
constexpr u32 kPathBytes = 16;

struct AreaFile
{
    const char* base; // e.g. "NET", "USB", "KERNEL"
    char buf[kAreaBufBytes];
    u64 used;
    u64 dropped;      // lines dropped because the buffer was full
    u64 size_on_disk; // estimate, bumped on each successful append
    bool installed;   // live <BASE>.LOG seeded?
};

// Producer/consumer buffer lock. LineSink (any logging context, any
// CPU) appends under it; the flusher snapshots-and-clears under it.
// The critical section is a bounded memcpy — NEVER filesystem I/O —
// so it is safe to take from contexts where a sleeping mutex is not
// (spinlocked regions, critical sections, the idle task). Interrupts
// are disabled while held so an IRQ-context log line on the same CPU
// cannot deadlock against its own interrupted holder; the panic path
// uses a bounded spin and drops the line rather than hanging a dying
// CPU. Hand-rolled CAS instead of sync::SpinLock to keep the hottest
// log path free of lockdep/held-stack bookkeeping.
constinit u32 g_buf_lock = 0;

inline u64 BufLockAcquire()
{
    u64 saved_rflags = 0;
    asm volatile("pushfq; pop %0" : "=r"(saved_rflags)::"memory");
    arch::Cli();
    for (u64 spins = 0;; ++spins)
    {
        u32 expected = 0;
        if (__atomic_compare_exchange_n(&g_buf_lock, &expected, 1u, /*weak=*/false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
        {
            return saved_rflags | 1u; // low bit: "acquired"
        }
        if (spins > 5'000'000u)
        {
            // A holder died with the lock (panic on another CPU).
            // Restore IF and report failure — caller drops the line.
            if ((saved_rflags & 0x200u) != 0)
                arch::Sti();
            return saved_rflags & ~u64{1};
        }
        asm volatile("pause" ::: "memory");
    }
}

inline void BufLockRelease(u64 token)
{
    __atomic_store_n(&g_buf_lock, 0u, __ATOMIC_RELEASE);
    if ((token & 0x200u) != 0)
        arch::Sti();
}

// 32 slots (matches the 32 LogArea bits). Indices that don't have
// an entry in `kAreaBases` below stay with base == nullptr and are
// skipped at routing time (folded into the General slot instead).
constinit AreaFile g_area_files[32] = {};

// Per-bit-index base name. Order matches the LogArea enum bit
// positions in klog.h. Areas without an explicit base name (None,
// or future-added bits) fall through to "KERNEL" (General).
//
// Names are kept short to fit FAT32's 8-char base limit and
// keep `<BASE>.<digit>` rotation slots within 8.3 too.
struct AreaBase
{
    u32 bit_index;
    const char* base;
};

constexpr AreaBase kAreaBases[] = {
    {0, "KERNEL"},    // General (legacy aggregate)
    {1, "BOOT"},      // Boot
    {2, "MM"},        // Memory
    {3, "SCHED"},     // Sched
    {4, "PROC"},      // Process
    {5, "SYSCALL"},   // Syscall
    {6, "LOADER"},    // Loader
    {7, "FS"},        // FS
    {8, "NET"},       // Net
    {9, "STORAGE"},   // Storage
    {10, "USB"},      // USB
    {11, "GPU"},      // GPU
    {12, "INPUT"},    // Input
    {13, "AUDIO"},    // Audio
    {14, "IPC"},      // IPC
    {15, "WIN32"},    // Win32
    {16, "LINUX"},    // Linux
    {17, "TIME"},     // Time
    {18, "POWER"},    // Power
    {19, "SECURITY"}, // Security (8 chars — fits 8.3)
    {20, "DIAG"},     // Diag
    {21, "RING3"},    // Ring3
    {22, "APP"},      // App
    {23, "DRIVER"},   // Driver
    {24, "ACPI"},     // ACPI
    {25, "PCI"},      // PCI
    {26, "WIRELESS"}, // Wireless (8 chars)
    {27, "GRAPHICS"}, // Graphics (8 chars)
    {28, "TEST"},     // Test
    {29, "ARITH"},    // Arith
};

constinit bool g_installed = false;

// Re-entrancy guard. Set across any FAT32 append; any log call
// emitted from within that window (typically Warn / Error from
// the FAT32 / block layer) is dropped rather than recursed.
constinit bool g_in_flush = false;

// --- helpers ---------------------------------------------------

// Build "<BASE>.LOG" into `out`. Caller-supplied buffer must hold
// at least kPathBytes.
void FormatLivePath(char* out, const char* base)
{
    u32 i = 0;
    while (base[i] != '\0' && i + 5 < kPathBytes)
    {
        out[i] = base[i];
        ++i;
    }
    out[i++] = '.';
    out[i++] = 'L';
    out[i++] = 'O';
    out[i++] = 'G';
    out[i] = '\0';
}

// Build "<BASE>.<digit>" into `out`. Caller-supplied buffer must
// hold at least kPathBytes. Single-digit decimal — caller ensures
// `idx < 10`.
void FormatRotPath(char* out, const char* base, u32 idx)
{
    u32 i = 0;
    while (base[i] != '\0' && i + 3 < kPathBytes)
    {
        out[i] = base[i];
        ++i;
    }
    out[i++] = '.';
    out[i++] = static_cast<char>('0' + (idx % 10));
    out[i] = '\0';
}

// Map a LogArea (single-bit value) to its area-file slot, or
// nullptr if the area doesn't have an entry. Multi-bit values
// (LogArea::All, combined masks) and unmapped single-bit values
// fold to General so they still land in KERNEL.LOG.
AreaFile* SlotFor(LogArea area)
{
    const u32 bits = static_cast<u32>(area);
    if (bits == 0)
    {
        return &g_area_files[0]; // General
    }
    // Single-bit area: find the bit index.
    if ((bits & (bits - 1u)) == 0u)
    {
        u32 idx = 0;
        u32 t = bits;
        while ((t & 1u) == 0u && idx < 31)
        {
            t >>= 1;
            ++idx;
        }
        if (idx < 32 && g_area_files[idx].base != nullptr)
        {
            return &g_area_files[idx];
        }
    }
    // Multi-bit or unmapped — fall back to the General (KERNEL.LOG)
    // bucket so the line still lands somewhere queryable.
    return &g_area_files[0];
}

// Rotate one area's file chain: drop the oldest archive, age
// <BASE>.<N-2> → <BASE>.<N-1>, ..., then <BASE>.LOG → <BASE>.0.
// Leaves no live <BASE>.LOG behind — caller is responsible for
// re-seeding the next one (with a fresh header, since
// Fat32AppendAtPath refuses zero-size files).
void RotateAreaChain(const fs::fat32::Volume* v, const char* base)
{
    namespace fat = fs::fat32;
    char rot_path[kPathBytes];
    char src_path[kPathBytes];
    char live_path[kPathBytes];
    FormatLivePath(live_path, base);

    // Drop the oldest archive so the next rename can land.
    FormatRotPath(rot_path, base, kRotationDepth - 1);
    fat::DirEntry oldest;
    if (fat::Fat32LookupPath(v, rot_path, &oldest))
    {
        fat::Fat32DeleteAtPath(v, rot_path);
    }

    // Promote <BASE>.<N-2> -> <BASE>.<N-1>, ..., <BASE>.0 -> <BASE>.1.
    for (u32 i = kRotationDepth - 1; i > 0; --i)
    {
        FormatRotPath(src_path, base, i - 1);
        FormatRotPath(rot_path, base, i);
        fat::DirEntry src;
        if (fat::Fat32LookupPath(v, src_path, &src))
        {
            if (!fat::Fat32RenameAtPath(v, src_path, rot_path))
            {
                // Rotation chain broke mid-promotion — the old
                // archive slot stays in place and we'll keep
                // writing to the live file. Klog so a regression
                // in the FS rename path appears in dmesg + panic
                // dump.
                KLOG_WARN_S("log/klog-persist", "rotate archive promotion failed", "path", src_path);
            }
        }
    }

    // Finally, <BASE>.LOG -> <BASE>.0.
    FormatRotPath(rot_path, base, 0);
    fat::DirEntry pre;
    if (fat::Fat32LookupPath(v, live_path, &pre))
    {
        if (!fat::Fat32RenameAtPath(v, live_path, rot_path))
        {
            // Rename of the live log to the .0 slot failed; we
            // delete the live file as fallback so the next boot
            // doesn't append to a stale tail. Klog the rotation
            // failure separately so the operator sees data loss.
            KLOG_WARN_S("log/klog-persist", "rotate live -> .0 failed; dropping", "path", live_path);
            fat::Fat32DeleteAtPath(v, live_path);
        }
    }
}

// Create a fresh <BASE>.LOG with a single header line so the next
// append has somewhere to land. Returns the seeded byte count or 0
// on failure.
u64 SeedFreshAreaLog(const fs::fat32::Volume* v, const char* base)
{
    namespace fat = fs::fat32;
    char live_path[kPathBytes];
    FormatLivePath(live_path, base);
    // Build a per-area header: "[klog-persist] <BASE>.LOG started\n"
    // keeps the marker greppable while making each file's origin
    // obvious without cross-referencing.
    char header[64];
    constexpr const char kPrefix[] = "[klog-persist] ";
    constexpr const char kSuffix[] = " started\n";
    u32 h = 0;
    for (u32 i = 0; kPrefix[i] != '\0' && h + 1 < sizeof(header); ++i)
    {
        header[h++] = kPrefix[i];
    }
    for (u32 i = 0; base[i] != '\0' && h + 1 < sizeof(header); ++i)
    {
        header[h++] = base[i];
    }
    constexpr const char kDotLog[] = ".LOG";
    for (u32 i = 0; kDotLog[i] != '\0' && h + 1 < sizeof(header); ++i)
    {
        header[h++] = kDotLog[i];
    }
    for (u32 i = 0; kSuffix[i] != '\0' && h + 1 < sizeof(header); ++i)
    {
        header[h++] = kSuffix[i];
    }
    header[h] = '\0';
    if (fat::Fat32CreateAtPath(v, live_path, header, h) < 0)
    {
        // Creating the fresh live-log file failed — likely FAT
        // free-cluster exhaustion or a corrupt dir entry. Klog so
        // a regression in the FS create path appears in dmesg.
        KLOG_WARN_S("log/klog-persist", "create failed", "path", live_path);
        return 0;
    }
    return h;
}

// Flush one area's buffer to its live file. Triggers mid-boot
// rotation if the buffered bytes would push the file past kLogSizeCap.
//
// The producer (LineSink) appends under g_buf_lock with interrupts
// off; this consumer must NOT hold that lock across FAT32 I/O (the
// whole point of the async split — I/O off the log-emitting path). So
// it snapshots the pending bytes into a private staging buffer under a
// brief lock, clears the shared buffer, then does all filesystem work
// on the snapshot. A producer that races in during the I/O simply
// fills the freshly-cleared buffer for the next tick.
//
// CALLER CONTRACT: only the single flusher context (UiTicker /
// KlogPersistFlush) calls this; the FAT32 driver mutex still
// serializes against other filesystem users, but there is exactly one
// klog flusher so no two FlushArea calls overlap.
constinit u8 g_flush_stage[kAreaBufBytes] = {};

void FlushArea(AreaFile* a)
{
    if (a == nullptr || a->base == nullptr)
    {
        return;
    }

    // Snapshot-and-clear under the buffer lock — bounded copy only.
    u64 staged = 0;
    {
        const u64 token = BufLockAcquire();
        if ((token & 1u) == 0)
        {
            return;
        }
        staged = a->used;
        if (staged > sizeof(g_flush_stage))
        {
            staged = sizeof(g_flush_stage);
        }
        for (u64 i = 0; i < staged; ++i)
        {
            g_flush_stage[i] = static_cast<u8>(a->buf[i]);
        }
        a->used = 0;
        BufLockRelease(token);
    }
    if (staged == 0)
    {
        return;
    }

    // Everything below is filesystem I/O on the private snapshot, with
    // the buffer lock released so producers never wait on the disk.
    namespace fat = fs::fat32;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        // FAT32 gone (block-device error); the snapshot is dropped, the
        // shared buffer is already clear.
        return;
    }
    char live_path[kPathBytes];
    FormatLivePath(live_path, a->base);

    // Lazy seed: first flush for this area in this boot.
    if (!a->installed)
    {
        a->size_on_disk = SeedFreshAreaLog(v, a->base);
        if (a->size_on_disk == 0)
        {
            return; // create failed; retry next tick with fresh bytes
        }
        a->installed = true;
    }

    if (a->size_on_disk + staged > kLogSizeCap)
    {
        RotateAreaChain(v, a->base);
        a->size_on_disk = SeedFreshAreaLog(v, a->base);
        if (a->size_on_disk == 0)
        {
            return;
        }
    }

    const i64 wrote = fat::Fat32AppendAtPath(v, live_path, g_flush_stage, staged);
    if (wrote >= 0)
    {
        a->size_on_disk += static_cast<u64>(wrote);
    }
}

// Flush every per-area buffer that has pending bytes.
void FlushAllAreas()
{
    if (g_in_flush || !g_installed)
    {
        return;
    }
    g_in_flush = true;
    for (auto& a : g_area_files)
    {
        if (a.base != nullptr && a.used > 0)
        {
            FlushArea(&a);
        }
    }
    g_in_flush = false;
}

// Line-sink entry point — called once per fully-formatted klog
// line. Routes to the area's file based on the area bit.
// ASYNC CONTRACT (2026-08-02 redesign): this sink NEVER touches the
// filesystem. It copies the line into the area's memory buffer under
// the bounded-spin buffer lock and returns; all FAT32 I/O happens on
// the UiTicker flusher's once-per-second KlogPersistFlush. History
// that forced this shape:
//   - The synchronous sink did block I/O under the global FAT32 mutex
//     on WHATEVER task logged the line, making every Info line a
//     kernel-wide serialization point against the disk. Under the
//     pe-threads/pe-winapi spawn storms the whole system queued behind
//     the filesystem for minutes (2026-08-02) — including the
//     heartbeat, which silenced the hung-task detector.
//   - Six distinct unsafe-context classes accumulated as entry guards
//     (spinlock held, pre-scheduler AP, idle task, FAT32 re-entry on
//     the same task, critical section, mid-flush recursion), each a
//     live kernel wedge or corruption in its day. A memory-only sink
//     retires the whole family instead of enumerating it.
void LineSink(LogLevel level, LogArea area, const char* line, u32 line_len)
{
    if (!g_installed || line == nullptr || line_len == 0)
    {
        return;
    }
    // Persist Info and above only. Debug builds emit a steady stream of
    // [T]/[D] lines; the in-memory klog ring still holds every level
    // for BSOD tails and `inspect log` — only the on-disk copy narrows.
    if (level < LogLevel::Info)
    {
        return;
    }
    AreaFile* a = SlotFor(area);
    if (a == nullptr || a->base == nullptr)
    {
        return;
    }

    const u64 token = BufLockAcquire();
    if ((token & 1u) == 0)
    {
        // Lock unobtainable (holder died mid-panic). Drop rather than
        // hang — the klog ring still has the line.
        return;
    }
    if (a->used + line_len <= sizeof(a->buf))
    {
        // memcpy would pull in a libc symbol the freestanding kernel
        // doesn't link; the bounded byte loop is the house idiom.
        for (u32 i = 0; i < line_len; ++i)
        {
            a->buf[a->used + i] = line[i];
        }
        a->used += line_len;
    }
    else
    {
        // Buffer full for this second. Dropping the on-disk copy is the
        // correct back-pressure: the flusher clears it within a tick,
        // and the in-memory ring retains every line regardless. Count
        // it so a persistently-lossy area is visible rather than silent.
        ++a->dropped;
    }
    BufLockRelease(token);
}

// Populate g_area_files[] from the kAreaBases[] table. Called
// once at install time.
void InitAreaTable()
{
    for (const auto& ab : kAreaBases)
    {
        if (ab.bit_index < 32)
        {
            g_area_files[ab.bit_index].base = ab.base;
            g_area_files[ab.bit_index].used = 0;
            g_area_files[ab.bit_index].size_on_disk = 0;
            g_area_files[ab.bit_index].installed = false;
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

    InitAreaTable();

    // Rotate every per-area chain so the prior session's <BASE>.LOG
    // ages to <BASE>.0 across the board, even for areas that don't
    // log this boot. Live <BASE>.LOG files are seeded lazily on
    // first line — avoids creating empty files for cold areas.
    //
    // Each rotation walks kRotationDepth slots * kFat32LookupPaths and
    // produces a burst of Trace-level fs/fat32 "lookup" lines (negative
    // probes when the slot doesn't exist). Bracket the loop with TSC
    // reads so the install summary reports the visible cost — a 60-area
    // rotation pass on a slow TCG host can take tens of ms and an
    // operator chasing boot-time should see that in dmesg, not
    // re-derive it by counting fat32 trace lines.
    const u64 rotate_start_tsc = arch::TscRead();
    u32 rotated_areas = 0;
    for (const auto& a : g_area_files)
    {
        if (a.base != nullptr)
        {
            RotateAreaChain(v, a.base);
            ++rotated_areas;
        }
    }
    const u64 rotate_end_tsc = arch::TscRead();
    const u64 rotate_ms = time::TscCalibrated() ? time::TscToNanos(rotate_end_tsc - rotate_start_tsc) / 1'000'000 : 0;
    KLOG_INFO_2V("log/klog-persist", "rotation pass", "areas", static_cast<u64>(rotated_areas), "elapsed_ms",
                 rotate_ms);

    g_installed = true;
    SetLogLineSink(LineSink);
    // The SetLogLineSink call above replays the ring through
    // LineSink; flush whatever it accumulated so the on-disk
    // files are current before this function returns.
    FlushAllAreas();
    arch::SerialWrite("[klog-persist] online — per-area logs (KERNEL.LOG + <AREA>.LOG)\n");
    return true;
}

void KlogPersistFlush()
{
    FlushAllAreas();
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
    // Emit a known marker under the "klog-persist" subsystem (which
    // maps to LogArea::Diag → DIAG.LOG via AreaFromSubsystem). After
    // a flush, DIAG.LOG must contain the marker — confirming per-
    // area routing actually placed the line in the diag file rather
    // than the legacy KERNEL.LOG aggregate.
    //
    // WARN, not INFO: the release-default klog runtime level
    // suppresses INFO at the source, so an INFO marker never
    // reached the persistence line-sink and this self-test FAILED
    // ("marker missing from DIAG.LOG") on every release boot. WARN
    // survives the release floor (one line, self-test-gated — the
    // CLAUDE.md-sanctioned level for a must-surface marker).
    constexpr const char kMark[] = "[klog-persist] self-test marker\n";
    KLOG_WARN("klog-persist", "self-test marker");
    KlogPersistFlush();

    char target_path[kPathBytes];
    FormatLivePath(target_path, "DIAG");
    fat::DirEntry e;
    if (!fat::Fat32LookupPath(v, target_path, &e))
    {
        SerialWrite("[klog-persist] self-test FAILED (no ");
        SerialWrite(target_path);
        SerialWrite(")\n");
        return;
    }
    // Read the tail of the file (last 256 bytes) and search for
    // "self-test marker" — the formatted log line carries a
    // timestamp prefix on serial but NOT in the line-sink record,
    // so the message tail is stable.
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
        SerialWrite("[klog-persist] self-test FAILED (marker missing from ");
        SerialWrite(target_path);
        SerialWrite(")\n");
        (void)kMark;
        return;
    }

    // Rotation sub-check: exercise RotateAreaChain in a way that
    // doesn't touch any live <BASE>.LOG. Seed a small TEST.<N-1>
    // (the slot the chain drops on the next rotation), call the
    // rotation for "TEST", and assert that file is gone. The live
    // TEST.LOG / TEST.0..<N-2> are unaffected because each promotion
    // only acts when its source exists. Cleaning up afterwards
    // keeps the test side-effect-free.
    char tail_path[kPathBytes];
    FormatRotPath(tail_path, "TEST", kRotationDepth - 1);
    constexpr const char kProbe[] = "klog-rotate-probe\n";
    constexpr u32 kProbeLen = sizeof(kProbe) - 1;
    fat::DirEntry probe_pre;
    const bool tail_pre_existed = fat::Fat32LookupPath(v, tail_path, &probe_pre);
    if (tail_pre_existed)
    {
        SerialWrite("[klog-persist] self-test OK (marker + rotation skipped: ");
        SerialWrite(tail_path);
        SerialWrite(" occupied)\n");
        (void)kMark;
        return;
    }
    if (fat::Fat32CreateAtPath(v, tail_path, kProbe, kProbeLen) < 0)
    {
        SerialWrite("[klog-persist] self-test FAILED (rotation probe create error)\n");
        (void)kMark;
        return;
    }
    RotateAreaChain(v, "TEST");
    fat::DirEntry probe_post;
    const bool tail_dropped = !fat::Fat32LookupPath(v, tail_path, &probe_post);

    // RotateAreaChain may have moved TEST.LOG -> TEST.0. Roll back
    // so the test leaves no live TEST.* files behind that we didn't
    // already have.
    char live_test[kPathBytes];
    FormatLivePath(live_test, "TEST");
    fat::DirEntry live_post;
    if (fat::Fat32LookupPath(v, live_test, &live_post))
    {
        fat::Fat32DeleteAtPath(v, live_test);
    }
    char zero_test[kPathBytes];
    FormatRotPath(zero_test, "TEST", 0);
    fat::DirEntry zero_post;
    if (fat::Fat32LookupPath(v, zero_test, &zero_post))
    {
        fat::Fat32DeleteAtPath(v, zero_test);
    }
    // Drop the test slot's installed bit so a future call seeds
    // a fresh TEST.LOG if/when a real TEST-area line lands.
    if (g_area_files[28].base != nullptr) // bit 28 == Test
    {
        g_area_files[28].installed = false;
        g_area_files[28].size_on_disk = 0;
    }

    SerialWrite(tail_dropped ? "[klog-persist] self-test OK (marker in DIAG.LOG + rotation drops oldest)\n"
                             : "[klog-persist] self-test FAILED (rotation did not drop oldest archive)\n");
    (void)kMark;
}

} // namespace duetos::core
