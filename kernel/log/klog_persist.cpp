#include "log/klog_persist.h"

#include "arch/x86_64/serial.h"
#include "arch/x86_64/timer.h"
#include "fs/fat32.h"
#include "log/klog.h"
#include "log/klog_pending_ring.h"
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
 * Producers never enter FAT32 or mutate per-area state. They copy a complete
 * record into a bounded sequence-published MPMC ring and return. A periodic
 * process-context consumer drains at most one ring lap, folds records into the
 * per-area buffers, and performs FAT32 I/O behind an atomic single-consumer
 * gate. Warn/Error lines emitted by FAT32 enqueue for the next flush instead
 * of recursively re-entering the filesystem.
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
constexpr u64 kAreaBufBytes = 512;

// FAT32 8.3 path: 8-char base + '.' + 3-char extension + NUL = 13.
// Plus one for safety. Each per-area entry stores both the live
// path (`<BASE>.LOG`) and base for rotation suffix construction.
constexpr u32 kPathBytes = 16;

struct AreaFile
{
    const char* base; // e.g. "NET", "USB", "KERNEL"
    char buf[kAreaBufBytes];
    u64 used;
    u64 size_on_disk; // estimate, bumped on each successful append
    bool installed;   // live <BASE>.LOG seeded?
};

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
constinit klog_pending::Ring g_pending_lines{};
constinit bool g_flush_active = false;
constinit u64 g_pending_drops = 0;
// Consumer-owned: only read/written while g_flush_active is held.
constinit u64 g_reported_pending_drops = 0;

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
// rotation if the buffered bytes would push the file past
// kLogSizeCap.
void FlushArea(AreaFile* a)
{
    if (a == nullptr || a->base == nullptr || a->used == 0)
    {
        return;
    }
    namespace fat = fs::fat32;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        // FAT32 disappeared (block-device error); drop the
        // accumulated bytes rather than spinning.
        a->used = 0;
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
            // Create failed — drop the buffer and try again next time.
            a->used = 0;
            return;
        }
        a->installed = true;
    }

    if (a->size_on_disk + a->used > kLogSizeCap)
    {
        RotateAreaChain(v, a->base);
        a->size_on_disk = SeedFreshAreaLog(v, a->base);
        if (a->size_on_disk == 0)
        {
            a->used = 0;
            return;
        }
    }

    // Check the append return value: on success it's the number of
    // bytes appended (== a->used here); on failure it's -1. If the
    // FAT layer reported failure (e.g. cluster-chain extension OK
    // but dir-entry size patch failed — a v0 hazard with no
    // journal to roll back), don't advance size_on_disk because the
    // on-disk file didn't actually grow. Still clear `used` so the
    // next line has a fresh buffer rather than retrying the same
    // bytes forever.
    const i64 wrote = fat::Fat32AppendAtPath(v, live_path, a->buf, a->used);
    if (wrote >= 0)
    {
        a->size_on_disk += static_cast<u64>(wrote);
    }
    a->used = 0;
}

class FlushGateGuard
{
  public:
    FlushGateGuard() = default;

    bool TryAcquire()
    {
        if (m_owned)
        {
            return true;
        }
        bool expected = false;
        m_owned =
            __atomic_compare_exchange_n(&g_flush_active, &expected, true, false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
        return m_owned;
    }

    ~FlushGateGuard()
    {
        if (m_owned)
        {
            __atomic_store_n(&g_flush_active, false, __ATOMIC_RELEASE);
        }
    }

    FlushGateGuard(const FlushGateGuard&) = delete;
    FlushGateGuard& operator=(const FlushGateGuard&) = delete;

  private:
    bool m_owned = false;
};

// Consumer-only fold from one immutable queue record into its per-area staging
// buffer. FAT32 entry is legal here because the caller owns g_flush_active and
// runs in process context; producers never call this function.
void AppendPendingRecord(const klog_pending::Record& record)
{
    AreaFile* a = SlotFor(static_cast<LogArea>(record.area_bits));
    if (a == nullptr || a->base == nullptr || record.length == 0)
    {
        return;
    }
    for (u32 i = 0; i < record.length; ++i)
    {
        if (a->used >= sizeof(a->buf))
        {
            FlushArea(a);
            if (a->used >= sizeof(a->buf))
            {
                break;
            }
        }
        a->buf[a->used++] = record.bytes[i];
    }
    if (a->used >= sizeof(a->buf) / 2 && record.bytes[record.length - 1] == '\n')
    {
        FlushArea(a);
    }
}

void ReportPendingDrops()
{
    const u64 drops = __atomic_load_n(&g_pending_drops, __ATOMIC_ACQUIRE);
    if (drops == g_reported_pending_drops)
    {
        return;
    }
    g_reported_pending_drops = drops;
    arch::SerialLineGuard guard;
    arch::SerialWrite("[klog-persist] pending queue full; dropped=");
    arch::SerialWriteHex(drops);
    arch::SerialWrite("\n");
}

// Drain at most one complete queue lap. The bound prevents a FAT32 warning
// generated by persistence itself from creating an unbounded consume/log loop;
// such re-entrant records remain queued for the next periodic flush.
void FlushAllAreasOwned()
{
    klog_pending::Record record{};
    u32 drained = 0;
    while (drained < klog_pending::kCapacity && klog_pending::Dequeue(&g_pending_lines, &record))
    {
        AppendPendingRecord(record);
        ++drained;
    }
    for (auto& a : g_area_files)
    {
        if (a.base != nullptr && a.used > 0)
        {
            FlushArea(&a);
        }
    }
    ReportPendingDrops();
}

// Flush every queued record and per-area buffer under one atomic consumer gate.
// False means another process-context consumer owns the flush; callers may
// retry later without blocking.
bool FlushAllAreas()
{
    if (!__atomic_load_n(&g_installed, __ATOMIC_ACQUIRE))
    {
        return true;
    }
    FlushGateGuard guard;
    if (!guard.TryAcquire())
    {
        return false;
    }
    FlushAllAreasOwned();
    return true;
}

// Producer entry point: validate context and copy one complete record into the
// bounded atomic handoff. It never allocates, blocks, mutates per-area buffers,
// or enters FAT32. Queue exhaustion is observable and fail-closed: the in-RAM
// klog/serial record remains authoritative while only this on-disk copy drops.
void LineSink(LogLevel /*level*/, LogArea area, const char* line, u32 line_len)
{
    if (!__atomic_load_n(&g_installed, __ATOMIC_ACQUIRE) || line == nullptr || line_len == 0)
    {
        return;
    }
    if (!klog_pending::Enqueue(&g_pending_lines, static_cast<u32>(area), line, line_len))
    {
        __atomic_fetch_add(&g_pending_drops, 1U, __ATOMIC_RELAXED);
    }
}

// Populate g_area_files[] from the kAreaBases[] table. Called
// once at install time.
void InitAreaTable()
{
    for (auto& area : g_area_files)
    {
        area.base = nullptr;
        area.used = 0;
        area.size_on_disk = 0;
        area.installed = false;
    }
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
    if (__atomic_load_n(&g_installed, __ATOMIC_ACQUIRE))
    {
        return true;
    }
    namespace fat = fs::fat32;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        arch::SerialWrite("[klog-persist] no FAT32 volume — skipping\n");
        return false;
    }

    FlushGateGuard gate;
    if (!gate.TryAcquire())
    {
        arch::SerialWrite("[klog-persist] install deferred — flush already active\n");
        return false;
    }

    // First installation occurs before the callback is published, so resetting
    // the queue cannot race a producer. Later calls are the idempotent no-op
    // above; live queue state is never reset under active writers.
    klog_pending::Initialize(&g_pending_lines);
    __atomic_store_n(&g_pending_drops, 0, __ATOMIC_RELAXED);
    g_reported_pending_drops = 0;

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

    __atomic_store_n(&g_installed, true, __ATOMIC_RELEASE);
    SetLogLineSink(LineSink);
    // The SetLogLineSink call above replays the ring through
    // LineSink; flush whatever it accumulated so the on-disk
    // files are current before this function returns.
    FlushAllAreasOwned();
    arch::SerialWrite("[klog-persist] online — per-area logs (KERNEL.LOG + <AREA>.LOG)\n");
    return true;
}

bool KlogPersistFlush()
{
    return FlushAllAreas();
}

bool KlogPersistInstalled()
{
    return __atomic_load_n(&g_installed, __ATOMIC_ACQUIRE);
}

u64 KlogPersistDroppedLines()
{
    return __atomic_load_n(&g_pending_drops, __ATOMIC_ACQUIRE);
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
    if (!KlogPersistInstalled())
    {
        SerialWrite("[klog-persist] self-test SKIP: not installed\n");
        return;
    }

    // Keep the readback + destructive rotation probe mutually exclusive with
    // the periodic/UI and shell flush callers. This boot-only self-test is
    // process-context, but it still uses one non-blocking attempt so the API
    // never hides an IRQ/critical-context scheduling precondition.
    FlushGateGuard gate;
    if (!gate.TryAcquire())
    {
        SerialWrite("[klog-persist] self-test FAILED (flush gate busy)\n");
        return;
    }
    // Publish a known Diag-area marker through the same pending queue as live
    // logging. After a flush, DIAG.LOG must contain it — confirming the queue,
    // consumer fold, and per-area file routing rather than only FAT32 itself.
    //
    // Drain first so the marker gets an explicit queue result instead of being
    // silently lost behind a full backlog. The record is already in the exact
    // line-sink form and uses the same Diag area selected for "klog-persist".
    FlushAllAreasOwned();
    constexpr const char kMark[] = "[W] klog-persist : self-test marker\n";
    constexpr u32 kMarkLen = sizeof(kMark) - 1;
    if (!klog_pending::Enqueue(&g_pending_lines, static_cast<u32>(LogArea::Diag), kMark, kMarkLen))
    {
        SerialWrite("[klog-persist] self-test FAILED (marker queue full)\n");
        return;
    }
    FlushAllAreasOwned();

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
