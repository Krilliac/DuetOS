/*
 * DuetOS — FAT32 filesystem driver: implementation.
 *
 * Companion to fat32.h — see there for the public mount/read/
 * write/lookup API and the in-memory mount struct.
 *
 * WHAT
 *   Mounts a FAT32 partition discovered by the GPT parser
 *   (kernel/fs/gpt.cpp), parses the BPB, and exposes
 *   directory walks + file read/write through the VFS
 *   adapter. Supports long file names (LFN, UTF-16) including
 *   the LFN-checksum sidechannel; short-name fallback when LFN
 *   is missing.
 *
 * HOW
 *   FAT itself is a chained-cluster index; lookups walk the
 *   chain by `next = fat[curr]`. We cache the FAT in
 *   per-mount RAM at v0 — small enough on typical FAT32
 *   volumes (<128 MiB FAT for a 32 GiB volume), big enough
 *   that on-demand FAT-block reads will be needed when we
 *   support larger partitions.
 *
 *   Directory entries are 32-byte structs; LFN entries
 *   precede the 8.3 entry and are stitched together by the
 *   walker. Write paths gate through the security guard
 *   (security/guard.cpp) so a sandboxed Win32 PE can't
 *   silently scribble over the boot partition.
 *
 * WHY THIS FILE IS LARGE
 *   FAT32 has a lot of wire-format ceremony (BPB, FAT, LFN
 *   stitching, 8.3 generation, free-cluster scan, cluster-
 *   chain walk). Each is short but they accumulate. Plus the
 *   shell `fat32` command's pretty-printer.
 */

#include "fs/fat32.h"

#include "arch/x86_64/serial.h"
#include "core/init.h"
#include "diag/kdbg.h"
#include "diag/log_names.h"
#include "drivers/storage/block.h"
#include "fs/fat32_internal.h"
#include "log/klog.h"
#include "sched/sched.h"
#include "security/driver_domain.h"
#include "util/string.h"

namespace duetos::fs::fat32
{

namespace internal
{

// Driver-wide mutex protecting the public-API surface. Both fat32.cpp
// and fat32_write.cpp construct Fat32Guard at every entry point;
// concurrent ring-3 tasks that both reach for FAT32 (e.g. the
// windows-side openat smoke + the linux-side write-past-EOF smoke
// racing during boot) would otherwise stomp on the shared g_scratch
// buffer. Recursive: a public entry that calls back into another
// public entry (Fat32CreateAtPath -> Fat32LookupPath, etc.) skips
// re-locking via the owning-task check.
// Tagged with `kLockClassFat32` so lockdep records every edge
// `(some other class) -> fat32` that fires during boot. Helps
// surface any path that holds a higher-class lock (e.g. sched,
// kobject) across a FAT32 call — that would invert the
// canonical "filesystem locks below subsystem locks" order.
constinit sched::Mutex g_fat32_mutex = {.owner = nullptr, .waiters = {}, .class_id = duetos::sync::kLockClassFat32};

// Scratch buffer for the BPB sector + any single cluster read.
// v0 assumes 512 B sectors and ≤ 4 KiB clusters — fits in one
// page. A future multi-sector read path (larger clusters, 4 KiB
// native sectors) will need a bigger buffer or a streamed API.
alignas(16) constinit u8 g_scratch[4096] = {};

Fat32Guard::Fat32Guard()
{
    sched::Task* me = sched::CurrentTask();
    if (me != nullptr && g_fat32_mutex.owner == me)
    {
        // Recursive re-entry: the owning task already holds the
        // mutex. Skip re-locking; ~Fat32Guard must NOT unlock
        // (owns_ stays false) so the outermost guard owns the
        // unlock.
        owns_ = false;
        return;
    }
    // CurrentTask() can be nullptr during early boot before the
    // scheduler is online — Fat32Probe runs then. Skip the lock in
    // that case; preemption isn't possible yet, so the race we're
    // guarding against can't fire.
    if (me == nullptr)
    {
        owns_ = false;
        return;
    }
    sched::MutexLock(&g_fat32_mutex);
    owns_ = true;
}

Fat32Guard::~Fat32Guard()
{
    // Only the guard that actually took the lock unlocks it.
    // Recursive-entry and early-boot (pre-scheduler) guards set
    // owns_ = false and have nothing to release.
    if (owns_)
        sched::MutexUnlock(&g_fat32_mutex);
}

// Volatile-zero / volatile-copy — same rationale as the guard
// and AHCI drivers: prevent clang from lowering a byte loop into
// libc memset/memcpy, which the freestanding kernel does not link.
void VZero(void* p, u64 n)
{
    auto* b = reinterpret_cast<volatile u8*>(p);
    for (u64 i = 0; i < n; ++i)
        b[i] = 0;
}

// sizeof(DirEntry) is 144 bytes today; the compiler will lower a
// plain struct-assignment at this size to a memcpy call against a
// freestanding kernel with no libc. Route every DirEntry copy
// through this volatile helper to keep link-time honest.
void CopyEntry(DirEntry& dst, const DirEntry& src)
{
    // 8-byte chunked copy with volatile semantics preserved. The
    // bulk word loop covers all-but-the-last-7 bytes; the byte
    // tail picks up the rest. volatile u64 / u8 read/store keeps
    // the compiler from coalescing or reordering even with LTO.
    constexpr u64 kWords = sizeof(DirEntry) / 8;
    constexpr u64 kTailBytes = sizeof(DirEntry) % 8;
    auto* dw = reinterpret_cast<volatile u64*>(&dst);
    const auto* sw = reinterpret_cast<const volatile u64*>(&src);
    for (u64 i = 0; i < kWords; ++i)
        dw[i] = sw[i];
    if constexpr (kTailBytes != 0)
    {
        auto* db = reinterpret_cast<volatile u8*>(&dst) + kWords * 8;
        const auto* sb = reinterpret_cast<const volatile u8*>(&src) + kWords * 8;
        for (u64 i = 0; i < kTailBytes; ++i)
            db[i] = sb[i];
    }
}

// Little-endian readers straight off a byte buffer.
u16 LeU16(const u8* p)
{
    return static_cast<u16>(p[0] | (u16(p[1]) << 8));
}
u32 LeU32(const u8* p)
{
    return u32(p[0]) | (u32(p[1]) << 8) | (u32(p[2]) << 16) | (u32(p[3]) << 24);
}

// Read one 512 B sector from the volume's partition block device
// into g_scratch. Returns false on I/O error.
bool ReadSector(u32 handle, u64 lba)
{
    return drivers::storage::BlockDeviceRead(handle, lba, 1, g_scratch) == 0;
}

// Read `sectors_per_cluster` contiguous sectors for a cluster into
// g_scratch. Bounded by sizeof(g_scratch) / 512 = 8, which matches
// our v0 test image's 4 KiB cluster. Larger clusters will need a
// bigger buffer.
bool ReadCluster(const Volume& v, u32 cluster)
{
    if (cluster < 2)
        return false;
    const u64 lba = v.data_start_sector + u64(cluster - 2) * v.sectors_per_cluster;
    if (v.sectors_per_cluster > sizeof(g_scratch) / 512)
        return false;
    return drivers::storage::BlockDeviceRead(v.block_handle, lba, v.sectors_per_cluster, g_scratch) == 0;
}

// Single-entry FAT sector cache. A FAT32 sector at 512 B holds
// 128 4-byte entries; at 4096 B it holds 1024 — and a sequential
// cluster-chain walk hits the same sector ~N consecutive times
// before crossing a sector boundary. Caching one sector at a time
// turns the per-entry block-layer round-trip into a per-sector one
// for the dominant case (file reads, directory walks).
//
// The cache is a single slot, not a hash table — adding more
// associativity only pays off for workloads that interleave reads
// against multiple FAT regions. The chain walker is naturally
// sector-local; one slot is enough.
struct FatSectorCache
{
    bool valid;
    u32 block_handle;
    u64 lba;
    u32 sector_bytes;
    u8 data[4096];
};

constinit FatSectorCache g_fat_cache = {};

void Fat32InvalidateFatCache()
{
    g_fat_cache.valid = false;
}

// Read the FAT entry for `cluster`. Returns 0x0FFFFFFF on I/O error
// — caller treats it as EOC and the walk terminates cleanly. The
// I/O failure is surfaced via a WARN log so an operator can tell
// transient disk failures from a normal end-of-chain (the latter
// is silent and frequent). FAT32 uses 4 bytes per entry, top 4
// bits reserved.
u32 ReadFatEntry(const Volume& v, u32 cluster)
{
    const u32 byte_off = cluster * 4;
    const u32 sec_off = byte_off / v.bytes_per_sector;
    const u32 byte_in_sec = byte_off % v.bytes_per_sector;
    const u64 lba = v.reserved_sectors + sec_off;

    // Cache hit — same volume's block handle, same FAT sector LBA,
    // sector size matches what we cached. Returning out of the
    // cached buffer skips the block-layer call entirely.
    if (g_fat_cache.valid && g_fat_cache.block_handle == v.block_handle && g_fat_cache.lba == lba &&
        g_fat_cache.sector_bytes == v.bytes_per_sector)
    {
        return LeU32(g_fat_cache.data + byte_in_sec) & 0x0FFFFFFFu;
    }

    // Cache miss — read the sector and refill. ReadSector lands
    // bytes in g_scratch; copy into g_fat_cache.data so subsequent
    // cluster reads (or unrelated sector consumers) don't clobber
    // the cached bytes.
    if (!ReadSector(v.block_handle, lba))
    {
        KLOG_WARN_V("fs/fat32", "ReadFatEntry sector read failed; treating chain as EOC", static_cast<u64>(lba));
        return 0x0FFFFFFFu;
    }
    const u32 cache_bytes = v.bytes_per_sector <= sizeof(g_fat_cache.data) ? v.bytes_per_sector
                                                                           : static_cast<u32>(sizeof(g_fat_cache.data));
    memcpy(g_fat_cache.data, g_scratch, cache_bytes);
    g_fat_cache.block_handle = v.block_handle;
    g_fat_cache.lba = lba;
    g_fat_cache.sector_bytes = v.bytes_per_sector;
    g_fat_cache.valid = (cache_bytes == v.bytes_per_sector);

    return LeU32(g_scratch + byte_in_sec) & 0x0FFFFFFFu;
}
} // namespace internal

// Hoist the cross-TU primitives into the driver's outer namespace so
// the public Fat32* function bodies (and the anonymous-namespace
// helpers below) can call them unqualified. Internal-only consumers
// outside this TU pick the names up by including fat32_internal.h.
using namespace internal;

namespace
{

// Volume registry. Flat array, handed-out by Fat32Probe, stable
// for the kernel's lifetime. kMaxVolumes == 16 matches the block
// layer's cap. TU-private to fat32.cpp — the write-side TU reaches
// volumes through the public Fat32Volume / Fat32VolumeCount API.
constinit Volume g_volumes[kMaxVolumes] = {};
constinit u32 g_volume_count = 0;

void LogEntry(const DirEntry& e)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    SerialWrite("[fs/fat32]   - ");
    SerialWrite(e.name);
    SerialWrite("  attr=");
    SerialWriteHex(static_cast<u64>(e.attributes));
    ::duetos::core::SerialWriteFatAttr(static_cast<u64>(e.attributes));
    SerialWrite("  first_cluster=");
    SerialWriteHex(static_cast<u64>(e.first_cluster));
    SerialWrite("  size=");
    SerialWriteHex(static_cast<u64>(e.size_bytes));
    SerialWrite("\n");
}

} // namespace

bool Fat32VolumeIsDuetOsOwned(const Volume* v)
{
    if (v == nullptr)
        return false;
    if (v->volume_id != kDuetOsVolumeId)
        return false;
    // The BPB label is space-padded to 11 bytes; match the
    // kDuetOsVolumeLabel prefix ("DUETOS") exactly, then require the
    // remaining characters to be spaces or NUL so a foreign label like
    // "DUETOSX" can't pass on the prefix alone.
    u32 i = 0;
    for (; kDuetOsVolumeLabel[i] != '\0'; ++i)
    {
        if (v->volume_label[i] != kDuetOsVolumeLabel[i])
            return false;
    }
    for (; i < 11; ++i)
    {
        const char c = v->volume_label[i];
        if (c != ' ' && c != '\0')
            return false;
    }
    return true;
}

bool Fat32Probe(u32 block_handle, u32* out_index)
{
    KLOG_TRACE_SCOPE("fs/fat32", "Fat32Probe");
    using arch::SerialWrite;

    if (g_volume_count >= kMaxVolumes)
    {
        core::Log(core::LogLevel::Error, "fs/fat32", "volume registry full");
        return false;
    }

    // Read LBA 0 of the partition = candidate BPB sector.
    if (!ReadSector(block_handle, 0))
    {
        core::Log(core::LogLevel::Warn, "fs/fat32", "probe: LBA 0 read failed");
        return false;
    }

    // Signature at 510/511.
    if (g_scratch[510] != 0x55 || g_scratch[511] != 0xAA)
    {
        return false;
    }
    // FAT32-class marker: "FAT32   " at bytes 82..89. Accept the
    // substring, not the full 8 bytes, so mkfs.fat variants that
    // pad differently still pass.
    const u8* ft = g_scratch + 82;
    if (ft[0] != 'F' || ft[1] != 'A' || ft[2] != 'T' || ft[3] != '3' || ft[4] != '2')
    {
        return false;
    }

    Volume& v = g_volumes[g_volume_count];
    VZero(&v, sizeof(v));
    v.block_handle = block_handle;
    v.bytes_per_sector = LeU16(g_scratch + 11);
    v.sectors_per_cluster = g_scratch[13];
    v.reserved_sectors = LeU16(g_scratch + 14);
    v.num_fats = g_scratch[16];
    v.fat_size_sectors = LeU32(g_scratch + 36);
    v.total_sectors = LeU32(g_scratch + 32);
    v.root_cluster = LeU32(g_scratch + 44);
    // Cluster numbers 0 and 1 are reserved (FAT[0] holds the media
    // descriptor + dirty flag; FAT[1] is unused on FAT32). A BPB
    // claiming root_cluster < 2 would make WalkDirChain bail
    // immediately on the < 2 guard and the volume would look
    // permanently empty without any operator-visible warning.
    if (v.root_cluster < 2)
    {
        core::Log(core::LogLevel::Warn, "fs/fat32", "BPB root_cluster < 2 — refusing volume");
        return false;
    }

    // v0 sanity checks: 512 B sectors, a real cluster size, ≥1 FAT.
    if (v.bytes_per_sector != 512 || v.sectors_per_cluster == 0 || v.num_fats == 0 || v.fat_size_sectors == 0)
    {
        core::Log(core::LogLevel::Warn, "fs/fat32", "BPB has unsupported geometry");
        return false;
    }
    // Compute data-start in 64 bits so a malformed BPB whose
    // `num_fats * fat_size_sectors` overflows u32 doesn't wrap into
    // the low LBAs. Reject if the result wouldn't fit back into the
    // u32 field — a real FAT32 volume tops out around 2 TiB so a
    // value past u32-max means the BPB is lying.
    const u64 fat_extent = static_cast<u64>(v.num_fats) * static_cast<u64>(v.fat_size_sectors);
    const u64 data_start_u64 = static_cast<u64>(v.reserved_sectors) + fat_extent;
    if (data_start_u64 > 0xFFFFFFFFULL)
    {
        core::Log(core::LogLevel::Warn, "fs/fat32", "BPB data_start_sector overflows u32 — refusing volume");
        return false;
    }
    v.data_start_sector = static_cast<u32>(data_start_u64);

    // Capture the DuetOS-ownership markers from the BPB (BS_VolID at
    // offset 67, BS_VolLab at offset 71). These tell a volume DuetOS
    // formatted (Fat32Format / make-gpt-image.py both stamp them) from
    // a foreign one (Windows ESP, real Linux FAT, USB stick).
    v.volume_id = LeU32(g_scratch + 67);
    for (u32 i = 0; i < 11; ++i)
        v.volume_label[i] = static_cast<char>(g_scratch[71 + i]);
    v.volume_label[11] = '\0';

    // Adoption gate: DuetOS only registers volumes it owns as writable
    // system volumes. A foreign FAT volume is recognised and logged but
    // NOT added to the registry — otherwise it could become
    // Fat32Volume(0), which the boot-time persistence sinks
    // (KERNEL.LOG / KERNEL.FIX / KERNEL.KPATH) and ~all of the kernel's
    // FAT-backed storage treat as "the system data volume". Adopting a
    // Windows EFI System Partition there would write DuetOS files into
    // the user's Windows install. Inert-by-default: no DuetOS marker →
    // not adopted.
    if (!Fat32VolumeIsDuetOsOwned(&v))
    {
        SerialWrite("[fs/fat32] foreign FAT volume (no DuetOS marker) — not adopting; handle=");
        arch::SerialWriteHex(static_cast<u64>(block_handle));
        SerialWrite(" volume_id=");
        arch::SerialWriteHex(static_cast<u64>(v.volume_id));
        SerialWrite("\n");
        // GAP: foreign-FAT interop READ (mounting a Windows ESP / Linux
        // FAT / USB stick read-only) is a deliberate future opt-in mount
        // path, not a boot auto-adopt — revisit when interop-read lands.
        return false;
    }

    SerialWrite("[fs/fat32] volume:");
    SerialWrite(" handle=");
    arch::SerialWriteHex(static_cast<u64>(block_handle));
    SerialWrite(" bps=");
    arch::SerialWriteHex(static_cast<u64>(v.bytes_per_sector));
    SerialWrite(" spc=");
    arch::SerialWriteHex(static_cast<u64>(v.sectors_per_cluster));
    SerialWrite(" res=");
    arch::SerialWriteHex(static_cast<u64>(v.reserved_sectors));
    SerialWrite(" fat_size=");
    arch::SerialWriteHex(static_cast<u64>(v.fat_size_sectors));
    SerialWrite(" root_cluster=");
    arch::SerialWriteHex(static_cast<u64>(v.root_cluster));
    SerialWrite(" data_start=");
    arch::SerialWriteHex(static_cast<u64>(v.data_start_sector));
    SerialWrite("\n");

    if (!WalkRootIntoSnapshot(v, v.root_cluster))
    {
        core::Log(core::LogLevel::Error, "fs/fat32", "root directory walk failed");
        return false;
    }
    for (u32 i = 0; i < v.root_entry_count; ++i)
    {
        LogEntry(v.root_entries[i]);
    }

    const u32 index = g_volume_count++;
    if (out_index != nullptr)
        *out_index = index;
    return true;
}

u32 Fat32VolumeCount()
{
    return g_volume_count;
}

const Volume* Fat32Volume(u32 index)
{
    if (index >= g_volume_count)
        return nullptr;
    return &g_volumes[index];
}

bool Fat32ForgetVolume(u32 block_handle)
{
    Fat32Guard guard;
    for (u32 i = 0; i < g_volume_count; ++i)
    {
        if (g_volumes[i].block_handle != block_handle)
        {
            continue;
        }
        // Compact: shift the higher-indexed volumes down one slot.
        // Volume indices are never held across calls (every caller
        // re-resolves via Fat32Volume), so renumbering is safe.
        for (u32 j = i + 1; j < g_volume_count; ++j)
        {
            g_volumes[j - 1] = g_volumes[j];
        }
        --g_volume_count;
        VZero(&g_volumes[g_volume_count], sizeof(g_volumes[g_volume_count]));
        return true;
    }
    return false;
}

::duetos::core::Result<void> Fat32Shutdown()
{
    KLOG_TRACE_SCOPE("fs/fat32", "Fat32Shutdown");
    Fat32Guard guard;
    const u32 dropped = g_volume_count;
    for (u32 i = 0; i < g_volume_count; ++i)
    {
        VZero(&g_volumes[i], sizeof(g_volumes[i]));
    }
    g_volume_count = 0;
    arch::SerialWrite("[fs/fat32] shutdown: dropped ");
    arch::SerialWriteHex(static_cast<u64>(dropped));
    arch::SerialWrite(" volume snapshot(s)\n");
    return {};
}

namespace
{

// Self-register fs/fat32 as a fault domain via KERNEL_INITCALL
// (Phase::Drivers). Init re-probes every block handle (matching
// the boot path's probe step but without a CRUD payload);
// teardown drops the in-memory volume registry so the re-probe
// lands cleanly.
::duetos::core::Result<void> RegisterFat32Module()
{
    ::duetos::security::RegisterDriverDomain(
        "fs/fat32",
        []() -> ::duetos::core::Result<void>
        {
            const ::duetos::u32 handles = ::duetos::drivers::storage::BlockDeviceCount();
            for (::duetos::u32 h = 0; h < handles; ++h)
                (void)::duetos::fs::fat32::Fat32Probe(h, nullptr);
            return {};
        },
        []() -> ::duetos::core::Result<void> { return ::duetos::fs::fat32::Fat32Shutdown(); });
    return {};
}

} // namespace

KERNEL_INITCALL(Drivers, "fs/fat32.module", RegisterFat32Module)

} // namespace duetos::fs::fat32
