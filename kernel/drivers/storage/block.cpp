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

i32 BlockDeviceWrite(u32 handle, u64 lba, u32 count, const void* buf)
{
    if (!ValidHandle(handle) || buf == nullptr || count == 0)
        return -1;
    const BlockDesc& d = g_devices[handle].desc;
    if (d.ops->write == nullptr)
        return -1;
    if (lba >= d.sector_count || lba + count > d.sector_count)
        return -1;
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
