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
#include "diag/kdbg.h"
#include "log/klog.h"
#include "diag/log_names.h"
#include "drivers/storage/block.h"
#include "sched/sched.h"
#include "fs/fat32_internal.h"

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
constinit sched::Mutex g_fat32_mutex = {};
constinit u64 g_fat32_recursion = 0;

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
        ++g_fat32_recursion;
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
    if (!owns_)
    {
        --g_fat32_recursion;
        return;
    }
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
    auto* d = reinterpret_cast<volatile u8*>(&dst);
    auto* s = reinterpret_cast<const volatile u8*>(&src);
    for (u64 i = 0; i < sizeof(DirEntry); ++i)
        d[i] = s[i];
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

// Read the FAT entry for `cluster`. Returns 0x0FFFFFFF on I/O error
// (caller treats it as EOC, same semantics as a real EOC — the walk
// terminates cleanly). FAT32 uses 4 bytes per entry, top 4 bits
// reserved.
u32 ReadFatEntry(const Volume& v, u32 cluster)
{
    const u32 byte_off = cluster * 4;
    const u32 sec_off = byte_off / v.bytes_per_sector;
    const u32 byte_in_sec = byte_off % v.bytes_per_sector;
    const u64 lba = v.reserved_sectors + sec_off;
    if (!ReadSector(v.block_handle, lba))
        return 0x0FFFFFFFu;
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

    // v0 sanity checks: 512 B sectors, a real cluster size, ≥1 FAT.
    if (v.bytes_per_sector != 512 || v.sectors_per_cluster == 0 || v.num_fats == 0 || v.fat_size_sectors == 0)
    {
        core::Log(core::LogLevel::Warn, "fs/fat32", "BPB has unsupported geometry");
        return false;
    }
    v.data_start_sector = v.reserved_sectors + v.num_fats * v.fat_size_sectors;

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

} // namespace duetos::fs::fat32
