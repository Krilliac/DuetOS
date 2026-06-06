#include "drivers/storage/block.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "log/klog.h"
#include "mm/kheap.h"
#include "util/saturating.h"

namespace duetos::drivers::storage
{

namespace
{

// Capacity picked to hold every plausible v0 consumer: one RAM
// self-test device + one device per NVMe namespace (typically
// 1) + one device per AHCI SATA port (up to 32) + headroom.
// Flat array, no dynamic resize — bumping is cheap if real
// hardware ever exceeds this.
constexpr u32 kMaxDevices = 16;

struct Registered
{
    BlockDesc desc;
    bool alive;
};

constinit Registered g_devices[kMaxDevices] = {};
constinit u32 g_device_count = 0;
constinit bool g_initialised = false;

bool ValidHandle(u32 handle)
{
    return handle < g_device_count && g_devices[handle].alive;
}

// --- RAM-backed block device ------------------------------------------------

struct RamBlock
{
    u8* bytes; // KMalloc-backed; sector_size * sector_count bytes
    u32 sector_size;
    u64 sector_count;
};

i32 RamBlockRead(void* cookie, u64 lba, u32 count, void* buf)
{
    auto* dev = static_cast<RamBlock*>(cookie);
    const u64 off = lba * dev->sector_size;
    const u64 n = u64(count) * dev->sector_size;
    const u8* src = dev->bytes + off;
    auto* dst = static_cast<u8*>(buf);
    for (u64 i = 0; i < n; ++i)
        dst[i] = src[i];
    return 0;
}

i32 RamBlockWrite(void* cookie, u64 lba, u32 count, const void* buf)
{
    auto* dev = static_cast<RamBlock*>(cookie);
    const u64 off = lba * dev->sector_size;
    const u64 n = u64(count) * dev->sector_size;
    u8* dst = dev->bytes + off;
    const auto* src = static_cast<const u8*>(buf);
    for (u64 i = 0; i < n; ++i)
        dst[i] = src[i];
    return 0;
}

i32 RamBlockDiscard(void* cookie, u64 lba, u32 count)
{
    // RAM disk has no media-aware deallocate concept, but treating
    // discard as "zero the range" makes the hint observable: a
    // hosted unit test can write a pattern, discard, and read
    // zeros back, exercising the FS-layer plumbing without needing
    // a real SSD. This matches NVMe's "may return zeroes" allowance
    // — callers don't depend on it, but a backend that DOES zero
    // makes the hint testable.
    auto* dev = static_cast<RamBlock*>(cookie);
    const u64 off = lba * dev->sector_size;
    const u64 n = u64(count) * dev->sector_size;
    u8* dst = dev->bytes + off;
    for (u64 i = 0; i < n; ++i)
        dst[i] = 0;
    return 0;
}

constinit const BlockOps kRamBlockOps = {
    /*.read = */ &RamBlockRead,
    /*.write = */ &RamBlockWrite,
    /*.flush = */ nullptr, // RAM disk is immediately durable; nothing to flush.
    /*.discard = */ &RamBlockDiscard,
};

// --- Partition-view block device -----------------------------------------
//
// Translates (lba, count) on a child handle into (first_lba + lba, count)
// on a parent handle. No buffering, no caching — every I/O is a pass-through
// plus a pre-check that (lba + count) fits inside the partition span.
//
// The parent handle is resolved once at create time; if the caller passes a
// stale parent (layout we don't do today) results are undefined. Kept tiny
// on purpose: the block layer already validates bounds against the view's
// declared sector_count before dispatch, so the wrapper only has to do the
// LBA shift.

struct PartitionBlock
{
    u32 parent_handle;
    u64 first_lba;
};

i32 PartitionBlockRead(void* cookie, u64 lba, u32 count, void* buf)
{
    auto* dev = static_cast<PartitionBlock*>(cookie);
    return BlockDeviceRead(dev->parent_handle, dev->first_lba + lba, count, buf);
}

i32 PartitionBlockWrite(void* cookie, u64 lba, u32 count, const void* buf)
{
    auto* dev = static_cast<PartitionBlock*>(cookie);
    return BlockDeviceWrite(dev->parent_handle, dev->first_lba + lba, count, buf);
}

i32 PartitionBlockFlush(void* cookie)
{
    auto* dev = static_cast<PartitionBlock*>(cookie);
    // Forward to the parent — the parent owns the on-device cache.
    // A partition's flush is a hint that "any of MY writes" reached
    // media, which only the parent can honour. The block layer
    // already collapses absent-flush-on-parent to no-op-success, so
    // this wrapper inherits that behaviour for free.
    return BlockDeviceFlush(dev->parent_handle);
}

i32 PartitionBlockDiscard(void* cookie, u64 lba, u32 count)
{
    auto* dev = static_cast<PartitionBlock*>(cookie);
    // Translate (lba, count) onto the parent's LBA space — same
    // shape as PartitionBlockRead/Write. The parent's discard hook
    // (or its absence) is what determines whether the hint
    // actually reaches the device.
    return BlockDeviceDiscard(dev->parent_handle, dev->first_lba + lba, count);
}

constinit const BlockOps kPartitionBlockOps = {
    /*.read = */ &PartitionBlockRead,
    /*.write = */ &PartitionBlockWrite,
    /*.flush = */ &PartitionBlockFlush,
    /*.discard = */ &PartitionBlockDiscard,
};

// Read-only variant used when the parent device exposes no write
// op. The block layer checks `BlockOps::write == nullptr` to
// populate `BlockDeviceIsWritable`, so picking the right vtable
// at create time keeps that flag accurate through the wrapper.
constinit const BlockOps kPartitionBlockOpsRO = {
    /*.read = */ &PartitionBlockRead,
    /*.write = */ nullptr,
    /*.flush = */ nullptr,
    /*.discard = */ nullptr,
};

} // namespace

void BlockLayerInit()
{
    KLOG_TRACE_SCOPE("block", "BlockLayerInit");
    if (g_initialised)
        return;
    g_initialised = true;
    g_device_count = 0;
    for (u32 i = 0; i < kMaxDevices; ++i)
        g_devices[i].alive = false;
    core::Log(core::LogLevel::Info, "block", "layer online");
}

u32 BlockDeviceRegister(const BlockDesc& desc)
{
    if (!g_initialised)
        BlockLayerInit();
    if (g_device_count >= kMaxDevices)
    {
        core::Log(core::LogLevel::Error, "block", "registry full; cannot register device");
        return kBlockHandleInvalid;
    }
    if (desc.ops == nullptr || desc.ops->read == nullptr || desc.sector_size == 0 || desc.sector_count == 0)
    {
        core::Log(core::LogLevel::Error, "block", "invalid BlockDesc (null ops or zero dimensions)");
        return kBlockHandleInvalid;
    }
    const u32 h = g_device_count;
    g_devices[h].desc = desc;
    g_devices[h].alive = true;
    ++g_device_count;

    arch::SerialWrite("[block] registered name=");
    arch::SerialWrite(desc.name ? desc.name : "(unnamed)");
    arch::SerialWrite(" handle=");
    arch::SerialWriteHex(h);
    arch::SerialWrite(" sector_size=");
    arch::SerialWriteHex(desc.sector_size);
    arch::SerialWrite(" sector_count=");
    arch::SerialWriteHex(desc.sector_count);
    arch::SerialWrite(" writable=");
    arch::SerialWrite(desc.ops->write != nullptr ? "yes" : "no");
    arch::SerialWrite("\n");
    return h;
}

u32 BlockDeviceCount()
{
    return g_device_count;
}

const char* BlockDeviceName(u32 handle)
{
    if (!ValidHandle(handle))
        return "<invalid>";
    const BlockDesc& d = g_devices[handle].desc;
    return d.name ? d.name : "<unnamed>";
}

u32 BlockDeviceSectorSize(u32 handle)
{
    if (!ValidHandle(handle))
        return 0;
    return g_devices[handle].desc.sector_size;
}

u64 BlockDeviceSectorCount(u32 handle)
{
    if (!ValidHandle(handle))
        return 0;
    return g_devices[handle].desc.sector_count;
}

bool BlockDeviceIsWritable(u32 handle)
{
    if (!ValidHandle(handle))
        return false;
    const BlockOps* ops = g_devices[handle].desc.ops;
    return ops != nullptr && ops->write != nullptr;
}

bool BlockDeviceIsPartition(u32 handle)
{
    if (!ValidHandle(handle))
        return false;
    const BlockOps* ops = g_devices[handle].desc.ops;
    return ops == &kPartitionBlockOps || ops == &kPartitionBlockOpsRO;
}

i32 BlockDeviceRead(u32 handle, u64 lba, u32 count, void* buf)
{
    if (!ValidHandle(handle) || buf == nullptr || count == 0)
        return -1;
    const BlockDesc& d = g_devices[handle].desc;
    // Subtractive bound: `lba + count` wraps u64 if a caller passes
    // lba near u64-max. The backends (AHCI / NVMe) already use this
    // form (fixed in batch 1); harmonise here too so the block layer
    // can't be coerced into issuing an out-of-range LBA to a backend
    // that trusts the layer above.
    if (lba >= d.sector_count || count > d.sector_count - lba)
        return -1;
    return d.ops->read(d.cookie, lba, count, buf);
}

namespace
{

// Write-guard rule storage. Fixed-capacity array; linear scan
// on every write is fine because rule-count is tiny (the health
// subsystem arms LBA 0 + LBA 1 per device = ≤32 rules on a
// 16-device system).
struct WriteRule
{
    u32 handle; // kBlockHandleInvalid = match every device
    u64 first_lba;
    u32 count;
    const char* tag; // string literal — no lifetime concerns
    bool valid;
};

constexpr u64 kMaxWriteRules = 32;
constinit WriteRule g_write_rules[kMaxWriteRules] = {};
constinit u64 g_write_rule_count = 0;
constinit WriteGuardMode g_write_guard_mode = WriteGuardMode::Off;
// Write-guard deny stat — saturating per class BB. A flood of denied
// writes from a misbehaving (or malicious) workload cannot wrap the
// counter to zero and obscure the deny pattern in post-incident audit.
constinit util::SatU64 g_write_guard_deny_count = 0;

// Returns the first rule that covers any byte of [lba, lba+count)
// on the given device, or nullptr if none matches.
const WriteRule* FindMatchingRule(u32 handle, u64 lba, u32 count)
{
    for (u64 i = 0; i < g_write_rule_count; ++i)
    {
        const WriteRule& r = g_write_rules[i];
        if (!r.valid)
            continue;
        if (r.handle != kBlockHandleInvalid && r.handle != handle)
            continue;
        const u64 req_end = lba + count;
        const u64 rule_end = r.first_lba + r.count;
        // Overlap if ranges intersect.
        if (lba < rule_end && r.first_lba < req_end)
            return &r;
    }
    return nullptr;
}

} // namespace

WriteGuardMode BlockWriteGuardMode()
{
    return g_write_guard_mode;
}

void BlockWriteGuardSetMode(WriteGuardMode m)
{
    const WriteGuardMode old = g_write_guard_mode;
    g_write_guard_mode = m;
    const char* names[] = {"Off", "Advisory", "Deny"};
    arch::SerialWrite("[blockguard] mode ");
    arch::SerialWrite(names[u8(old)]);
    arch::SerialWrite(" -> ");
    arch::SerialWrite(names[u8(m)]);
    arch::SerialWrite("\n");
}

void BlockWriteGuardAddRule(u32 handle, u64 first_lba, u32 count, const char* tag)
{
    if (g_write_rule_count >= kMaxWriteRules)
    {
        core::Log(core::LogLevel::Warn, "blockguard", "rule table full — dropping new rule");
        return;
    }
    g_write_rules[g_write_rule_count] = {handle, first_lba, count, (tag != nullptr) ? tag : "(untagged)", true};
    ++g_write_rule_count;
}

u64 BlockWriteGuardDenyCount()
{
    return g_write_guard_deny_count;
}

// ---- Owned-region write chokepoint (allow-list) ----
namespace
{
struct OwnedRegion
{
    u32 handle; // kBlockHandleInvalid = every device
    u64 first_lba;
    u64 count;
    const char* tag;
    bool valid;
};
constexpr u64 kMaxOwnedRegions = 32;
constinit OwnedRegion g_owned_regions[kMaxOwnedRegions] = {};
constinit u64 g_owned_region_count = 0;
constinit WriteGuardMode g_owned_write_mode = WriteGuardMode::Off;
constinit util::SatU64 g_owned_write_deny_count = 0;

// Resolve a partition handle down to its parent disk handle,
// accumulating the LBA offset. A write to a partition device is
// translated to (parent_handle, parent_first_lba + lba) by
// PartitionBlockWrite BEFORE the owned-write chokepoint in
// BlockDeviceWrite runs — so an owned region must be registered in
// parent terms or it will never match. Bounded loop guards against a
// pathological cycle. RAM / whole-disk handles are left unchanged.
void ResolveToParent(u32& handle, u64& first_lba)
{
    for (int depth = 0; depth < 8; ++depth)
    {
        if (!ValidHandle(handle))
            return;
        const BlockDesc& d = g_devices[handle].desc;
        if (d.ops != &kPartitionBlockOps && d.ops != &kPartitionBlockOpsRO)
            return;
        const auto* p = static_cast<const PartitionBlock*>(d.cookie);
        first_lba += p->first_lba;
        handle = p->parent_handle;
    }
}

// Append one owned region verbatim (no resolution). Internal helper.
void AddOneRegion(u32 handle, u64 first_lba, u64 count, const char* tag)
{
    if (g_owned_region_count >= kMaxOwnedRegions)
    {
        core::Log(core::LogLevel::Warn, "blockguard", "owned-region table full — dropping new region");
        return;
    }
    g_owned_regions[g_owned_region_count] = {handle, first_lba, count, (tag != nullptr) ? tag : "(untagged)", true};
    ++g_owned_region_count;
}

// Drop owned regions [to, count) — append-only truncation. Lets the
// self-test append + roll back its own test regions without clobbering
// production registrations that came before it.
void TruncateOwnedRegions(u64 to)
{
    if (to > g_owned_region_count)
        return;
    for (u64 i = to; i < g_owned_region_count; ++i)
        g_owned_regions[i].valid = false;
    g_owned_region_count = to;
}
} // namespace

void BlockOwnedRegionAdd(u32 handle, u64 first_lba, u64 count, const char* tag)
{
    if (count == 0)
        return;
    // The chokepoint runs at BOTH the FS-facing handle and — because
    // PartitionBlockWrite re-enters BlockDeviceWrite on the parent — the
    // parent disk. Own the region in both terms so neither check trips.
    AddOneRegion(handle, first_lba, count, tag);
    u32 parent = handle;
    u64 parent_lba = first_lba;
    ResolveToParent(parent, parent_lba);
    if (parent != handle)
        AddOneRegion(parent, parent_lba, count, tag);
}


bool DiskRegionIsOwned(u32 handle, u64 lba, u32 count)
{
    const u64 end = lba + static_cast<u64>(count);
    for (u64 i = 0; i < g_owned_region_count; ++i)
    {
        const OwnedRegion& r = g_owned_regions[i];
        if (!r.valid)
            continue;
        if (r.handle != kBlockHandleInvalid && r.handle != handle)
            continue;
        const u64 r_end = r.first_lba + r.count;
        if (r.first_lba <= lba && end <= r_end)
            return true; // fully contained in an owned region
    }
    return false;
}

WriteGuardMode BlockOwnedWriteMode()
{
    return g_owned_write_mode;
}

void BlockOwnedWriteSetMode(WriteGuardMode m)
{
    g_owned_write_mode = m;
    const char* names[] = {"Off", "Advisory", "Deny"};
    arch::SerialWrite("[blockguard] owned-write mode -> ");
    arch::SerialWrite(names[u8(m)]);
    arch::SerialWrite("\n");
}

u64 BlockOwnedWriteDenyCount()
{
    return g_owned_write_deny_count;
}

void BlockOwnedRegionSelfTest()
{
    using ::duetos::core::PanicWithValue;
    // Preserve production owned regions registered before this test (RAM
    // auto-owns, the FAT32 system volume): we only append + roll back.
    const u64 snap = g_owned_region_count;

    // --- Predicate logic on a fake handle no real device uses.
    const u32 H = 0xFFFF0001u;
    if (DiskRegionIsOwned(H, 0, 1))
        PanicWithValue("blockguard", "owned with no region for handle", 0);
    BlockOwnedRegionAdd(H, 100, 50, "test"); // owns [100, 150)
    if (!DiskRegionIsOwned(H, 100, 50))
        PanicWithValue("blockguard", "exact region not owned", 1);
    if (!DiskRegionIsOwned(H, 120, 10))
        PanicWithValue("blockguard", "inside region not owned", 2);
    if (DiskRegionIsOwned(H, 90, 20))
        PanicWithValue("blockguard", "low straddle owned", 3);
    if (DiskRegionIsOwned(H, 145, 20))
        PanicWithValue("blockguard", "high straddle owned", 4);
    if (DiskRegionIsOwned(H, 200, 1))
        PanicWithValue("blockguard", "outside region owned", 5);
    if (DiskRegionIsOwned(H + 1, 120, 10))
        PanicWithValue("blockguard", "wrong handle owned", 6);
    BlockOwnedRegionAdd(kBlockHandleInvalid, 0, 1000000, "any"); // wildcard
    if (!DiskRegionIsOwned(H + 1, 500, 1))
        PanicWithValue("blockguard", "wildcard region miss", 7);
    TruncateOwnedRegions(snap); // drop the test + wildcard regions

    // --- Deny-mode write refusal on a fresh RAM disk owning only [0, 4).
    const u32 ram = RamBlockDeviceCreate("ramowntest", 512, 8); // auto-owns [0, 8)
    if (ram == kBlockHandleInvalid)
        PanicWithValue("blockguard", "ram create failed", 8);
    TruncateOwnedRegions(snap); // drop the auto-own so sector 5 is unowned
    BlockOwnedRegionAdd(ram, 0, 4, "owned-half");
    const WriteGuardMode saved_mode = BlockOwnedWriteMode();
    BlockOwnedWriteSetMode(WriteGuardMode::Deny);
    u8 buf[512] = {};
    if (BlockDeviceWrite(ram, 0, 1, buf) < 0)
        PanicWithValue("blockguard", "owned write was denied", 9);
    if (BlockDeviceWrite(ram, 5, 1, buf) >= 0)
        PanicWithValue("blockguard", "unowned write was allowed", 10);
    if (BlockOwnedWriteDenyCount() == 0)
        PanicWithValue("blockguard", "deny counter did not advance", 11);
    // Restore the operator's mode (may be advisory/deny via cmdline) and
    // roll back to exactly the production regions we started with.
    BlockOwnedWriteSetMode(saved_mode);
    TruncateOwnedRegions(snap);

    arch::SerialWrite("[block-owned-selftest] PASS (containment + straddle + wildcard + Deny refusal)\n");
}

i32 BlockDeviceWrite(u32 handle, u64 lba, u32 count, const void* buf)
{
    if (!ValidHandle(handle) || buf == nullptr || count == 0)
        return -1;
    const BlockDesc& d = g_devices[handle].desc;
    if (d.ops->write == nullptr)
        return -1;
    if (lba >= d.sector_count || lba + count > d.sector_count)
        return -1;

    // Write-guard consultation. Runs before dispatch so the
    // backend never sees a denied write.
    if (g_write_guard_mode != WriteGuardMode::Off)
    {
        const WriteRule* r = FindMatchingRule(handle, lba, count);
        if (r != nullptr)
        {
            arch::SerialWrite("[blockguard] write to guarded LBA: dev=");
            arch::SerialWriteHex(handle);
            arch::SerialWrite(" lba=");
            arch::SerialWriteHex(lba);
            arch::SerialWrite(" count=");
            arch::SerialWriteHex(count);
            arch::SerialWrite(" rule=\"");
            arch::SerialWrite(r->tag);
            arch::SerialWrite(g_write_guard_mode == WriteGuardMode::Deny ? "\" DENIED\n" : "\" (advisory)\n");
            if (g_write_guard_mode == WriteGuardMode::Deny)
            {
                ++g_write_guard_deny_count;
                return -1;
            }
        }
    }

    // Owned-region chokepoint (allow-list). When enforcement is on, a
    // write not fully contained in a DuetOS-owned region is refused — the
    // single property that supersedes the per-call-site ownership checks.
    // Default Off, so no behaviour change until a future slice registers
    // every legitimate writer's region and flips the default.
    if (g_owned_write_mode != WriteGuardMode::Off && !DiskRegionIsOwned(handle, lba, count))
    {
        arch::SerialWrite("[blockguard] write outside owned region: dev=");
        arch::SerialWriteHex(handle);
        arch::SerialWrite(" lba=");
        arch::SerialWriteHex(lba);
        arch::SerialWrite(" count=");
        arch::SerialWriteHex(count);
        arch::SerialWrite(g_owned_write_mode == WriteGuardMode::Deny ? " DENIED\n" : " (advisory)\n");
        if (g_owned_write_mode == WriteGuardMode::Deny)
        {
            ++g_owned_write_deny_count;
            return -1;
        }
    }

    return d.ops->write(d.cookie, lba, count, buf);
}

i32 BlockDeviceFlush(u32 handle)
{
    if (!ValidHandle(handle))
        return -1;
    const BlockDesc& d = g_devices[handle].desc;
    // Absent flush = nothing-to-flush success. Filesystem code
    // that commits at every fsync doesn't need to special-case
    // backends without a flush op (RAM disk, read-only mounts).
    //
    // CAUTION (per NVMe + SATA reliability audit, 2026-05-27):
    // a backend that secretly has a volatile write cache but
    // omits the flush hook silently turns this no-op-success
    // path into data loss on power cut. Every backend with
    // possible host-side caching MUST wire its flush hook; the
    // partition wrapper, RAM disk, and read-only mounts are the
    // only legitimate nullptr-flush backends today.
    if (d.ops->flush == nullptr)
        return 0;
    return d.ops->flush(d.cookie);
}

namespace
{

// Counters surfacing the block layer's discard activity since
// boot — saturating so a misbehaving caller cannot wrap them and
// obscure the actual hint volume in post-incident audit. Read
// without atomics: 64-bit aligned scalars on x86_64 are torn-free
// for reads against a single writer at this layer (the write-guard
// counter follows the same pattern at line 249).
constinit util::SatU64 g_discard_issued_count = 0;
constinit util::SatU64 g_discard_sectors_hinted = 0;

} // namespace

i32 BlockDeviceDiscard(u32 handle, u64 lba, u32 count)
{
    if (!ValidHandle(handle) || count == 0)
        return -1;
    const BlockDesc& d = g_devices[handle].desc;
    // Subtractive bound: mirror BlockDeviceRead's overflow guard.
    if (lba >= d.sector_count || count > d.sector_count - lba)
        return -1;

    // Discard is a HINT, not a write — but it modifies on-disk
    // state from the caller's perspective (deallocated bytes
    // become controller-defined zeros or stale data). A bootkit
    // that writes via discard would be just as effective at
    // corrupting LBA 0/1 as one that writes; route the hint
    // through the same write-guard predicate.
    if (g_write_guard_mode != WriteGuardMode::Off)
    {
        const WriteRule* r = FindMatchingRule(handle, lba, count);
        if (r != nullptr)
        {
            arch::SerialWrite("[blockguard] discard of guarded LBA: dev=");
            arch::SerialWriteHex(handle);
            arch::SerialWrite(" lba=");
            arch::SerialWriteHex(lba);
            arch::SerialWrite(" count=");
            arch::SerialWriteHex(count);
            arch::SerialWrite(" rule=\"");
            arch::SerialWrite(r->tag);
            arch::SerialWrite(g_write_guard_mode == WriteGuardMode::Deny ? "\" DENIED\n" : "\" (advisory)\n");
            if (g_write_guard_mode == WriteGuardMode::Deny)
            {
                ++g_write_guard_deny_count;
                return -1;
            }
        }
    }

    // Track every hint we accept, even when the backend will
    // drop it on the floor — the FS layer's batch-trim path
    // wants visibility into "did my fstrim actually try?"
    ++g_discard_issued_count;
    g_discard_sectors_hinted += static_cast<u64>(count);

    if (d.ops->discard == nullptr)
        return 0;
    return d.ops->discard(d.cookie, lba, count);
}

bool BlockDeviceSupportsDiscard(u32 handle)
{
    if (!ValidHandle(handle))
        return false;
    const BlockOps* ops = g_devices[handle].desc.ops;
    return ops != nullptr && ops->discard != nullptr;
}

u64 BlockDiscardIssuedCount()
{
    return g_discard_issued_count;
}

u64 BlockDiscardSectorsHinted()
{
    return g_discard_sectors_hinted;
}

u32 RamBlockDeviceCreate(const char* name, u32 sector_size, u64 sector_count)
{
    if (sector_size == 0 || sector_count == 0)
        return kBlockHandleInvalid;
    const u64 total = sector_size * sector_count;
    auto* bytes = static_cast<u8*>(mm::KMalloc(total));
    if (bytes == nullptr)
    {
        core::Log(core::LogLevel::Error, "block", "RAM device KMalloc failed");
        return kBlockHandleInvalid;
    }
    for (u64 i = 0; i < total; ++i)
        bytes[i] = 0;
    auto* dev = static_cast<RamBlock*>(mm::KMalloc(sizeof(RamBlock)));
    if (dev == nullptr)
    {
        mm::KFree(bytes);
        core::Log(core::LogLevel::Error, "block", "RAM device cookie KMalloc failed");
        return kBlockHandleInvalid;
    }
    dev->bytes = bytes;
    dev->sector_size = sector_size;
    dev->sector_count = sector_count;

    BlockDesc desc{};
    desc.name = name;
    desc.ops = &kRamBlockOps;
    desc.cookie = dev;
    desc.sector_size = sector_size;
    desc.sector_count = sector_count;
    const u32 handle = BlockDeviceRegister(desc);
    // RAM block devices are kernel-owned scratch — register the whole
    // device as a DuetOS-owned region so the owned-write chokepoint
    // permits writes to it when enforcement is enabled.
    if (handle != kBlockHandleInvalid)
        BlockOwnedRegionAdd(handle, 0, sector_count, "ram-scratch");
    return handle;
}

u32 PartitionBlockDeviceCreate(const char* name, u32 parent_handle, u64 first_lba, u64 last_lba)
{
    if (!ValidHandle(parent_handle))
    {
        core::Log(core::LogLevel::Error, "block", "partition create: invalid parent handle");
        return kBlockHandleInvalid;
    }
    if (first_lba > last_lba)
    {
        core::Log(core::LogLevel::Error, "block", "partition create: first_lba > last_lba");
        return kBlockHandleInvalid;
    }
    const BlockDesc& parent = g_devices[parent_handle].desc;
    if (last_lba >= parent.sector_count)
    {
        core::Log(core::LogLevel::Error, "block", "partition create: last_lba past end of parent");
        return kBlockHandleInvalid;
    }
    auto* dev = static_cast<PartitionBlock*>(mm::KMalloc(sizeof(PartitionBlock)));
    if (dev == nullptr)
    {
        core::Log(core::LogLevel::Error, "block", "partition create: cookie KMalloc failed");
        return kBlockHandleInvalid;
    }
    dev->parent_handle = parent_handle;
    dev->first_lba = first_lba;

    BlockDesc desc{};
    desc.name = name;
    desc.ops = (parent.ops->write != nullptr) ? &kPartitionBlockOps : &kPartitionBlockOpsRO;
    desc.cookie = dev;
    desc.sector_size = parent.sector_size;
    desc.sector_count = (last_lba - first_lba) + 1;
    return BlockDeviceRegister(desc);
}

void BlockLayerSelfTest()
{
    KLOG_TRACE_SCOPE("block", "BlockLayerSelfTest");
    using arch::SerialWrite;
    const u32 h = RamBlockDeviceCreate("ramtest0", 512, 64);
    if (h == kBlockHandleInvalid)
    {
        SerialWrite("[block] self-test FAILED: could not create RAM device\n");
        return;
    }
    // Pattern A at LBA 0 (0xA5 alternating with sector-index bytes),
    // Pattern B at LBA 63 (0x5A alternating).
    u8 write_a[512];
    u8 write_b[512];
    for (u32 i = 0; i < 512; ++i)
    {
        write_a[i] = static_cast<u8>(0xA5 ^ (i & 0xFF));
        write_b[i] = static_cast<u8>(0x5A ^ (i & 0xFF));
    }
    if (BlockDeviceWrite(h, 0, 1, write_a) != 0)
    {
        SerialWrite("[block] self-test FAILED: write LBA 0\n");
        return;
    }
    if (BlockDeviceWrite(h, 63, 1, write_b) != 0)
    {
        SerialWrite("[block] self-test FAILED: write LBA 63\n");
        return;
    }
    // Out-of-range write must fail.
    if (BlockDeviceWrite(h, 64, 1, write_a) != -1)
    {
        SerialWrite("[block] self-test FAILED: oob write accepted\n");
        return;
    }
    u8 read_buf[512];
    for (u32 i = 0; i < 512; ++i)
        read_buf[i] = 0;
    if (BlockDeviceRead(h, 0, 1, read_buf) != 0)
    {
        SerialWrite("[block] self-test FAILED: read LBA 0\n");
        return;
    }
    for (u32 i = 0; i < 512; ++i)
    {
        if (read_buf[i] != write_a[i])
        {
            SerialWrite("[block] self-test FAILED: LBA 0 mismatch\n");
            return;
        }
    }
    if (BlockDeviceRead(h, 63, 1, read_buf) != 0)
    {
        SerialWrite("[block] self-test FAILED: read LBA 63\n");
        return;
    }
    for (u32 i = 0; i < 512; ++i)
    {
        if (read_buf[i] != write_b[i])
        {
            SerialWrite("[block] self-test FAILED: LBA 63 mismatch\n");
            return;
        }
    }
    // Out-of-range read must also fail.
    if (BlockDeviceRead(h, 64, 1, read_buf) != -1)
    {
        SerialWrite("[block] self-test FAILED: oob read accepted\n");
        return;
    }

    // Discard end-to-end: the RAM backend implements discard as
    // "zero the range," so we can prove the hint reaches the
    // backend by checking a previously-written sector reads back
    // as all zeros after the call. Also exercises the counter
    // bookkeeping in BlockDeviceDiscard.
    const u64 before_issued = BlockDiscardIssuedCount();
    const u64 before_hinted = BlockDiscardSectorsHinted();
    if (!BlockDeviceSupportsDiscard(h))
    {
        SerialWrite("[block] self-test FAILED: RAM backend missing discard hook\n");
        return;
    }
    if (BlockDeviceDiscard(h, 0, 1) != 0)
    {
        SerialWrite("[block] self-test FAILED: discard LBA 0\n");
        return;
    }
    for (u32 i = 0; i < 512; ++i)
        read_buf[i] = 0xFF;
    if (BlockDeviceRead(h, 0, 1, read_buf) != 0)
    {
        SerialWrite("[block] self-test FAILED: read after discard\n");
        return;
    }
    for (u32 i = 0; i < 512; ++i)
    {
        if (read_buf[i] != 0)
        {
            SerialWrite("[block] self-test FAILED: discard did not zero LBA 0\n");
            return;
        }
    }
    // Out-of-range discard must fail.
    if (BlockDeviceDiscard(h, 64, 1) != -1)
    {
        SerialWrite("[block] self-test FAILED: oob discard accepted\n");
        return;
    }
    // Zero-count discard must fail (caller bug).
    if (BlockDeviceDiscard(h, 0, 0) != -1)
    {
        SerialWrite("[block] self-test FAILED: zero-count discard accepted\n");
        return;
    }
    if (BlockDiscardIssuedCount() != before_issued + 1)
    {
        SerialWrite("[block] self-test FAILED: issued counter did not advance by 1\n");
        return;
    }
    if (BlockDiscardSectorsHinted() != before_hinted + 1)
    {
        SerialWrite("[block] self-test FAILED: sectors-hinted counter did not advance by 1\n");
        return;
    }

    // Flush must succeed on any registered handle — RAM backend
    // has no flush op so this exercises the absent-flush-success
    // path documented in BlockDeviceFlush().
    if (BlockDeviceFlush(h) != 0)
    {
        SerialWrite("[block] self-test FAILED: flush rejected on RAM device\n");
        return;
    }
    // Flush on an invalid handle is a caller bug.
    if (BlockDeviceFlush(kBlockHandleInvalid) != -1)
    {
        SerialWrite("[block] self-test FAILED: flush on invalid handle accepted\n");
        return;
    }

    SerialWrite("[block] self-test OK (RAM device write + read + OOB reject + discard + flush)\n");
}

} // namespace duetos::drivers::storage
