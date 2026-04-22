#include "block.h"

#include "../../arch/x86_64/serial.h"
#include "../../core/klog.h"
#include "../../mm/kheap.h"

namespace customos::drivers::storage
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

constinit const BlockOps kRamBlockOps = {
    /*.read = */ &RamBlockRead,
    /*.write = */ &RamBlockWrite,
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

constinit const BlockOps kPartitionBlockOps = {
    /*.read = */ &PartitionBlockRead,
    /*.write = */ &PartitionBlockWrite,
};

// Read-only variant used when the parent device exposes no write
// op. The block layer checks `BlockOps::write == nullptr` to
// populate `BlockDeviceIsWritable`, so picking the right vtable
// at create time keeps that flag accurate through the wrapper.
constinit const BlockOps kPartitionBlockOpsRO = {
    /*.read = */ &PartitionBlockRead,
    /*.write = */ nullptr,
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

i32 BlockDeviceRead(u32 handle, u64 lba, u32 count, void* buf)
{
    if (!ValidHandle(handle) || buf == nullptr || count == 0)
        return -1;
    const BlockDesc& d = g_devices[handle].desc;
    if (lba >= d.sector_count || lba + count > d.sector_count)
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
constinit u64 g_write_guard_deny_count = 0;

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
    return d.ops->write(d.cookie, lba, count, buf);
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
    return BlockDeviceRegister(desc);
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
    SerialWrite("[block] self-test OK (RAM device write + read + OOB reject)\n");
}

} // namespace customos::drivers::storage
